/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package record

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/utils/clock"
)

const (
	maxLruCacheEntries = 4096

	// if we see the same event that varies only by message
	// more than 10 times in a 10 minute period, aggregate the event
	defaultAggregateMaxEvents         = 10
	defaultAggregateIntervalInSeconds = 600

	// by default, allow a source to send 25 events about an object
	// but control the refill rate to 1 new event every 5 minutes
	// this helps control the long-tail of events for things that are always
	// unhealthy
	defaultSpamBurst = 25
	defaultSpamQPS   = 1. / 300.
)

// getEventKey builds unique event key based on source, involvedObject, reason, message
func getEventKey(event *v1.Event) string {
	return strings.Join([]string{
		event.Source.Component,
		event.Source.Host,
		event.InvolvedObject.Kind,
		event.InvolvedObject.Namespace,
		event.InvolvedObject.Name,
		event.InvolvedObject.FieldPath,
		string(event.InvolvedObject.UID),
		event.InvolvedObject.APIVersion,
		event.Type,
		event.Reason,
		event.Message,
	},
		"")
}

// getSpamKey builds unique event key based on source, involvedObject
func getSpamKey(event *v1.Event) string {
	return strings.Join([]string{
		event.Source.Component,
		event.Source.Host,
		event.InvolvedObject.Kind,
		event.InvolvedObject.Namespace,
		event.InvolvedObject.Name,
		string(event.InvolvedObject.UID),
		event.InvolvedObject.APIVersion,
	},
		"")
}

// EventSpamKeyFunc is a function that returns unique key based on provided event
type EventSpamKeyFunc func(event *v1.Event) string

// EventFilterFunc is a function that returns true if the event should be skipped
type EventFilterFunc func(event *v1.Event) bool

// EventSourceObjectSpamFilter is responsible for throttling
// the amount of events a source and object can produce.
type EventSourceObjectSpamFilter struct {
	sync.RWMutex

	// the cache that manages last synced state
	cache *lru.Cache

	// burst is the amount of events we allow per source + object
	burst int

	// qps is the refill rate of the token bucket in queries per second
	qps float32

	// clock is used to allow for testing over a time interval
	clock clock.PassiveClock

	// spamKeyFunc is a func used to create a key based on an event, which is later used to filter spam events.
	spamKeyFunc EventSpamKeyFunc
}

// NewEventSourceObjectSpamFilter allows burst events from a source about an object with the specified qps refill.
func NewEventSourceObjectSpamFilter(lruCacheSize, burst int, qps float32, clock clock.PassiveClock, spamKeyFunc EventSpamKeyFunc) *EventSourceObjectSpamFilter {
	return &EventSourceObjectSpamFilter{
		cache:       lru.New(lruCacheSize),
		burst:       burst,
		qps:         qps,
		clock:       clock,
		spamKeyFunc: spamKeyFunc,
	}
}

// spamRecord holds data used to perform spam filtering decisions.
type spamRecord struct {
	// rateLimiter controls the rate of events about this object
	rateLimiter flowcontrol.PassiveRateLimiter
}

// Filter controls that a given source+object are not exceeding the allowed rate.
func (f *EventSourceObjectSpamFilter) Filter(event *v1.Event) bool {
	var record spamRecord

	// controls our cached information about this event
	eventKey := f.spamKeyFunc(event)

	// do we have a record of similar events in our cache?
	f.Lock()
	defer f.Unlock()
	value, found := f.cache.Get(eventKey)
	if found {
		record = value.(spamRecord)
	}

	// verify we have a rate limiter for this record
	if record.rateLimiter == nil {
		record.rateLimiter = flowcontrol.NewTokenBucketPassiveRateLimiterWithClock(f.qps, f.burst, f.clock)
	}

	// ensure we have available rate
	filter := !record.rateLimiter.TryAccept()

	// update the cache
	f.cache.Add(eventKey, record)

	return filter
}

// EventAggregatorKeyFunc is responsible for grouping events for aggregation
// It returns a tuple of the following:
// aggregateKey - key the identifies the aggregate group to bucket this event
// localKey - key that makes this event in the local group
type EventAggregatorKeyFunc func(event *v1.Event) (aggregateKey string, localKey string)

// EventAggregatorByReasonFunc aggregates events by exact match on event.Source, event.InvolvedObject, event.Type,
// event.Reason, event.ReportingController and event.ReportingInstance
func EventAggregatorByReasonFunc(event *v1.Event) (string, string) {
	return strings.Join([]string{
		event.Source.Component,
		event.Source.Host,
		event.InvolvedObject.Kind,
		event.InvolvedObject.Namespace,
		event.InvolvedObject.Name,
		string(event.InvolvedObject.UID),
		event.InvolvedObject.APIVersion,
		event.Type,
		event.Reason,
		event.ReportingController,
		event.ReportingInstance,
	},
		""), event.Message
}

// EventAggregatorMessageFunc is responsible for producing an aggregation message
type EventAggregatorMessageFunc func(event *v1.Event) string

// EventAggregatorByReasonMessageFunc returns an aggregate message by prefixing the incoming message
func EventAggregatorByReasonMessageFunc(event *v1.Event) string {
	return "(combined from similar events): " + event.Message
}

// EventAggregator identifies similar events and aggregates them into a single event
type EventAggregator struct {
	sync.RWMutex

	// The cache that manages aggregation state
	cache *lru.Cache

	// The function that groups events for aggregation
	keyFunc EventAggregatorKeyFunc

	// The function that generates a message for an aggregate event
	messageFunc EventAggregatorMessageFunc

	// The maximum number of events in the specified interval before aggregation occurs
	maxEvents uint

	// The amount of time in seconds that must transpire since the last occurrence of a similar event before it's considered new
	maxIntervalInSeconds uint

	// clock is used to allow for testing over a time interval
	clock clock.PassiveClock
}

// NewEventAggregator returns a new instance of an EventAggregator
func NewEventAggregator(lruCacheSize int, keyFunc EventAggregatorKeyFunc, messageFunc EventAggregatorMessageFunc,
	maxEvents int, maxIntervalInSeconds int, clock clock.PassiveClock) *EventAggregator {
	return &EventAggregator{
		cache:                lru.New(lruCacheSize),
		keyFunc:              keyFunc,
		messageFunc:          messageFunc,
		maxEvents:            uint(maxEvents),
		maxIntervalInSeconds: uint(maxIntervalInSeconds),
		clock:                clock,
	}
}

// aggregateRecord holds data used to perform aggregation decisions
type aggregateRecord struct {
	// we track the number of unique local keys we have seen in the aggregate set to know when to actually aggregate
	// if the size of this set exceeds the max, we know we need to aggregate
	localKeys sets.String
	// The last time at which the aggregate was recorded
	lastTimestamp metav1.Time
}

// EventAggregate checks if a similar event has been seen according to the
// aggregation configuration (max events, max interval, etc) and returns:
//
//   - The (potentially modified) event that should be created
//   - The cache key for the event, for correlation purposes. This will be set to
//     the full key for normal events, and to the result of
//     EventAggregatorMessageFunc for aggregate events.
func (e *EventAggregator) EventAggregate(newEvent *v1.Event) (*v1.Event, string) {
	now := metav1.NewTime(e.clock.Now())
	var record aggregateRecord
	// eventKey is the full cache key for this event
	// dfy: eventKey 为 ns-object-name-uid-type-reason-message-component-controller
	eventKey := getEventKey(newEvent)
	// aggregateKey is for the aggregate event, if one is needed.
	// dfy: 此处对应 EventAggregatorByReasonFunc 函数
	// aggregateKey 为 ns-object-name-uid-type-reason-message-component-controller，作为 lru-cache-1 的 key
	// localKey 为 event 的 message
	aggregateKey, localKey := e.keyFunc(newEvent)

	// Do we have a record of similar events in our cache?
	e.Lock()
	defer e.Unlock()
	// dfy: 查询并获取 lru-cache-1 中的记录 record
	value, found := e.cache.Get(aggregateKey)
	if found {
		record = value.(aggregateRecord)
	}

	// Is the previous record too old? If so, make a fresh one. Note: if we didn't
	// find a similar record, its lastTimestamp will be the zero value, so we
	// create a new one in that case.
	// dfy: 默认是 600 s，10 min
	maxInterval := time.Duration(e.maxIntervalInSeconds) * time.Second
	interval := now.Time.Sub(record.lastTimestamp.Time)
	// dfy: 距离上次插入超过 10 分钟，就清空该 key 对应 event set 列表（列表长度默认为 10 ）
	if interval > maxInterval {
		record = aggregateRecord{localKeys: sets.NewString()}
	}

	// Write the new event into the aggregation record and put it on the cache
	// dfy: 每次插入，更新插入时间
	record.localKeys.Insert(localKey)
	record.lastTimestamp = now
	e.cache.Add(aggregateKey, record)

	// If we are not yet over the threshold for unique events, don't correlate them
	// dfy: 若 key 对应的 set 列表没满，直接返回
	if uint(record.localKeys.Len()) < e.maxEvents {
		return newEvent, eventKey
	}

	// do not grow our local key set any larger than max
	// dfy: 如果 key 对应的 set 列表满了（默认10个为上限），那么随意弹出一个
	record.localKeys.PopAny()

	// create a new aggregate event, and return the aggregateKey as the cache key
	// (so that it can be overwritten.)
	eventCopy := &v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%v.%x", newEvent.InvolvedObject.Name, now.UnixNano()),
			Namespace: newEvent.Namespace,
		},
		Count:          1,
		FirstTimestamp: now,
		InvolvedObject: newEvent.InvolvedObject,
		LastTimestamp:  now,
		// dfy: EventAggregatorByReasonMessageFunc 函数 ——"(combined from similar events): " + event.Message
		Message: e.messageFunc(newEvent),
		Type:    newEvent.Type,
		Reason:  newEvent.Reason,
		Source:  newEvent.Source,
	}
	return eventCopy, aggregateKey
}

// eventLog records data about when an event was observed
type eventLog struct {
	// The number of times the event has occurred since first occurrence.
	count uint

	// The time at which the event was first recorded.
	firstTimestamp metav1.Time

	// The unique name of the first occurrence of this event
	name string

	// Resource version returned from previous interaction with server
	resourceVersion string
}

// eventLogger logs occurrences of an event
type eventLogger struct {
	sync.RWMutex
	cache *lru.Cache
	clock clock.PassiveClock
}

// newEventLogger observes events and counts their frequencies
func newEventLogger(lruCacheEntries int, clock clock.PassiveClock) *eventLogger {
	return &eventLogger{cache: lru.New(lruCacheEntries), clock: clock}
}

// eventObserve records an event, or updates an existing one if key is a cache hit
func (e *eventLogger) eventObserve(newEvent *v1.Event, key string) (*v1.Event, []byte, error) {
	var (
		patch []byte
		err   error
	)
	eventCopy := *newEvent
	event := &eventCopy

	e.Lock()
	defer e.Unlock()

	// Check if there is an existing event we should update
	// dfy: 在 lru 缓存中查询该 key（ key 代表 event 的基础主体信息 如哪个 ns 下的 哪个 pod 什么reson 的 event，是个唯一标识信息）
	// 举例子：一个 pod 可能会毫秒级别产生多个 event ，但是 reason 等信息都一致，就 event id 不一致，因此需要聚合这些重复的 event，只更新计数就好
	// 因此可能会产生这样的 key： testns-testpod-create 表示 test ns 下 testpod 产生的 reason 为 create 的 event
	lastObservation := e.lastEventObservationFromCache(key)

	// If we found a result, prepare a patch
	// dfy:
	// 若在 lru 缓存中找到此 key，同时 count > 0 ，表示需要聚合
	// 聚合会更新 该 event 出现的次数，但目前只能更新本地缓存中，无法更新 apiserver 中该 event 存储的信息
	// 所以会产生个 patch，将该 event 中 count 信息的更新，后续更新到 apiserver
	if lastObservation.count > 0 {
		// update the event based on the last observation so patch will work as desired
		event.Name = lastObservation.name
		event.ResourceVersion = lastObservation.resourceVersion
		// dfy: event 的第一次出现时间，要与 lru 缓存中保持一致
		event.FirstTimestamp = lastObservation.firstTimestamp
		// dfy: 更新 event 的出现次数
		event.Count = int32(lastObservation.count) + 1

		eventCopy2 := *event
		eventCopy2.Count = 0
		eventCopy2.LastTimestamp = metav1.NewTime(time.Unix(0, 0))
		eventCopy2.Message = ""

		newData, _ := json.Marshal(event)
		oldData, _ := json.Marshal(eventCopy2)
		// dfy: 将 event 的首次出现时间，出现次数等，更新到此 event 上，通过该 patch 提交给 apiserver 实现
		patch, err = strategicpatch.CreateTwoWayMergePatch(oldData, newData, event)
	}

	// record our new observation
	// dfy:
	// 将 event 存入到另一个 lru 缓存中
	// 并更新 event 的第一次出现时间和次数
	e.cache.Add(
		key,
		eventLog{
			// dfy: 记录 event 出现的次数
			count: uint(event.Count),
			// dfy: 记录 event 第一次出现的时间
			firstTimestamp: event.FirstTimestamp,
			name:           event.Name,
			// dfy: 此处若是 聚合event，那么应该为空，因为并未创建，所以后续会通过 updateState 来更新此处
			resourceVersion: event.ResourceVersion,
		},
	)
	return event, patch, err
}

// updateState updates its internal tracking information based on latest server state
func (e *eventLogger) updateState(event *v1.Event) {
	key := getEventKey(event)
	e.Lock()
	defer e.Unlock()
	// record our new observation
	e.cache.Add(
		key,
		eventLog{
			count:           uint(event.Count),
			firstTimestamp:  event.FirstTimestamp,
			name:            event.Name,
			resourceVersion: event.ResourceVersion,
		},
	)
}

// lastEventObservationFromCache returns the event from the cache, reads must be protected via external lock
func (e *eventLogger) lastEventObservationFromCache(key string) eventLog {
	value, ok := e.cache.Get(key)
	if ok {
		observationValue, ok := value.(eventLog)
		if ok {
			return observationValue
		}
	}
	return eventLog{}
}

// EventCorrelator processes all incoming events and performs analysis to avoid overwhelming the system.  It can filter all
// incoming events to see if the event should be filtered from further processing.  It can aggregate similar events that occur
// frequently to protect the system from spamming events that are difficult for users to distinguish.  It performs de-duplication
// to ensure events that are observed multiple times are compacted into a single event with increasing counts.
type EventCorrelator struct {
	// the function to filter the event
	filterFunc EventFilterFunc
	// the object that performs event aggregation
	aggregator *EventAggregator
	// the object that observes events as they come through
	logger *eventLogger
}

// EventCorrelateResult is the result of a Correlate
type EventCorrelateResult struct {
	// the event after correlation
	Event *v1.Event
	// if provided, perform a strategic patch when updating the record on the server
	Patch []byte
	// if true, do no further processing of the event
	Skip bool
}

// NewEventCorrelator returns an EventCorrelator configured with default values.
//
// The EventCorrelator is responsible for event filtering, aggregating, and counting
// prior to interacting with the API server to record the event.
//
// The default behavior is as follows:
//   - Aggregation is performed if a similar event is recorded 10 times
//     in a 10 minute rolling interval.  A similar event is an event that varies only by
//     the Event.Message field.  Rather than recording the precise event, aggregation
//     will create a new event whose message reports that it has combined events with
//     the same reason.
//   - Events are incrementally counted if the exact same event is encountered multiple
//     times.
//   - A source may burst 25 events about an object, but has a refill rate budget
//     per object of 1 event every 5 minutes to control long-tail of spam.
func NewEventCorrelator(clock clock.PassiveClock) *EventCorrelator {
	cacheSize := maxLruCacheEntries
	spamFilter := NewEventSourceObjectSpamFilter(cacheSize, defaultSpamBurst, defaultSpamQPS, clock, getSpamKey)
	return &EventCorrelator{
		filterFunc: spamFilter.Filter,
		aggregator: NewEventAggregator(
			cacheSize,
			EventAggregatorByReasonFunc,
			EventAggregatorByReasonMessageFunc,
			defaultAggregateMaxEvents,
			defaultAggregateIntervalInSeconds,
			clock),

		logger: newEventLogger(cacheSize, clock),
	}
}

// dfy: 配置聚合器的参数
func NewEventCorrelatorWithOptions(options CorrelatorOptions) *EventCorrelator {
	// dfy: 若参数为空，配置默认参数
	optionsWithDefaults := populateDefaults(options)
	spamFilter := NewEventSourceObjectSpamFilter(
		optionsWithDefaults.LRUCacheSize,
		optionsWithDefaults.BurstSize,
		optionsWithDefaults.QPS,
		optionsWithDefaults.Clock,
		optionsWithDefaults.SpamKeyFunc)
	// dfy: 创建聚合器
	return &EventCorrelator{
		filterFunc: spamFilter.Filter,
		aggregator: NewEventAggregator(
			optionsWithDefaults.LRUCacheSize,
			optionsWithDefaults.KeyFunc,
			optionsWithDefaults.MessageFunc,
			optionsWithDefaults.MaxEvents,
			optionsWithDefaults.MaxIntervalInSeconds,
			optionsWithDefaults.Clock),
		logger: newEventLogger(optionsWithDefaults.LRUCacheSize, optionsWithDefaults.Clock),
	}
}

// populateDefaults populates the zero value options with defaults
func populateDefaults(options CorrelatorOptions) CorrelatorOptions {
	// dfy: lru 缓存条目最大数量为 4096
	if options.LRUCacheSize == 0 {
		options.LRUCacheSize = maxLruCacheEntries
	}
	if options.BurstSize == 0 {
		options.BurstSize = defaultSpamBurst
	}
	if options.QPS == 0 {
		options.QPS = defaultSpamQPS
	}
	// dfy: 猜测正确，是  EventAggregatorByReasonFunc 函数
	if options.KeyFunc == nil {
		options.KeyFunc = EventAggregatorByReasonFunc
	}
	if options.MessageFunc == nil {
		options.MessageFunc = EventAggregatorByReasonMessageFunc
	}
	// dfy: 看见相同 event 10分钟内变化超过 10 次进行聚合
	if options.MaxEvents == 0 {
		options.MaxEvents = defaultAggregateMaxEvents
	}
	// dfy: 缓存中，event 存在大于此事件 600s，就更新缓存记录
	if options.MaxIntervalInSeconds == 0 {
		options.MaxIntervalInSeconds = defaultAggregateIntervalInSeconds
	}
	if options.Clock == nil {
		options.Clock = clock.RealClock{}
	}
	if options.SpamKeyFunc == nil {
		options.SpamKeyFunc = getSpamKey
	}
	return options
}

// EventCorrelate filters, aggregates, counts, and de-duplicates all incoming events
func (c *EventCorrelator) EventCorrelate(newEvent *v1.Event) (*EventCorrelateResult, error) {
	if newEvent == nil {
		return nil, fmt.Errorf("event is nil")
	}
	// dfy: lRU-Cache-1 存储 event 的最新插入时间，进行 event 的聚合
	aggregateEvent, ckey := c.aggregator.EventAggregate(newEvent)
	// dfy: LRU-Cache-2 存储 event 的最早发生时间，新 event 和最早 event 进行对比，形成 patch，用于更新 count 等
	observedEvent, patch, err := c.logger.eventObserve(aggregateEvent, ckey)
	// dfy: Filter主要时起到了一个限速的作用，通过令牌桶来进行过滤操作。 client-go/tools/record/events_cache.go
	if c.filterFunc(observedEvent) {
		return &EventCorrelateResult{Skip: true}, nil
	}
	return &EventCorrelateResult{Event: observedEvent, Patch: patch}, err
}

// UpdateState based on the latest observed state from server
// dfy: 更新 LRU-Cache-2 的 event 信息，因为聚合 event 第一次产生，未创建之前不具有 ResourceVersion
//
//	因此 Create 创建，需要更新 event.ResourceVersion
func (c *EventCorrelator) UpdateState(event *v1.Event) {
	c.logger.updateState(event)
}
