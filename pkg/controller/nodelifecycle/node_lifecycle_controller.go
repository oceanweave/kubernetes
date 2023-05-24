/*
Copyright 2017 The Kubernetes Authors.

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

// The Controller sets tainted annotations on nodes.
// Tainted nodes should not be used for new work loads and
// some effort should be given to getting existing work
// loads off of tainted nodes.

package nodelifecycle

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	coordv1 "k8s.io/api/coordination/v1"
	v1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	appsv1informers "k8s.io/client-go/informers/apps/v1"
	coordinformers "k8s.io/client-go/informers/coordination/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	coordlisters "k8s.io/client-go/listers/coordination/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/component-base/metrics/prometheus/ratelimiter"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/nodelifecycle/scheduler"
	nodeutil "k8s.io/kubernetes/pkg/controller/util/node"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	kubeletapis "k8s.io/kubernetes/pkg/kubelet/apis"
	utilnode "k8s.io/kubernetes/pkg/util/node"
	taintutils "k8s.io/kubernetes/pkg/util/taints"
)

func init() {
	// Register prometheus metrics
	Register()
}

var (
	// UnreachableTaintTemplate is the taint for when a node becomes unreachable.
	UnreachableTaintTemplate = &v1.Taint{
		Key:    v1.TaintNodeUnreachable,
		Effect: v1.TaintEffectNoExecute,
	}

	// NotReadyTaintTemplate is the taint for when a node is not ready for
	// executing pods
	NotReadyTaintTemplate = &v1.Taint{
		Key:    v1.TaintNodeNotReady,
		Effect: v1.TaintEffectNoExecute,
	}

	// map {NodeConditionType: {ConditionStatus: TaintKey}}
	// represents which NodeConditionType under which ConditionStatus should be
	// tainted with which TaintKey
	// for certain NodeConditionType, there are multiple {ConditionStatus,TaintKey} pairs
	nodeConditionToTaintKeyStatusMap = map[v1.NodeConditionType]map[v1.ConditionStatus]string{
		v1.NodeReady: {
			v1.ConditionFalse:   v1.TaintNodeNotReady,
			v1.ConditionUnknown: v1.TaintNodeUnreachable,
		},
		v1.NodeMemoryPressure: {
			v1.ConditionTrue: v1.TaintNodeMemoryPressure,
		},
		v1.NodeDiskPressure: {
			v1.ConditionTrue: v1.TaintNodeDiskPressure,
		},
		v1.NodeNetworkUnavailable: {
			v1.ConditionTrue: v1.TaintNodeNetworkUnavailable,
		},
		v1.NodePIDPressure: {
			v1.ConditionTrue: v1.TaintNodePIDPressure,
		},
	}

	taintKeyToNodeConditionMap = map[string]v1.NodeConditionType{
		v1.TaintNodeNotReady:           v1.NodeReady,
		v1.TaintNodeUnreachable:        v1.NodeReady,
		v1.TaintNodeNetworkUnavailable: v1.NodeNetworkUnavailable,
		v1.TaintNodeMemoryPressure:     v1.NodeMemoryPressure,
		v1.TaintNodeDiskPressure:       v1.NodeDiskPressure,
		v1.TaintNodePIDPressure:        v1.NodePIDPressure,
	}
)

// ZoneState is the state of a given zone.
type ZoneState string

const (
	stateInitial           = ZoneState("Initial")
	stateNormal            = ZoneState("Normal")
	stateFullDisruption    = ZoneState("FullDisruption")
	statePartialDisruption = ZoneState("PartialDisruption")
)

const (
	// The amount of time the nodecontroller should sleep between retrying node health updates
	retrySleepTime   = 20 * time.Millisecond
	nodeNameKeyIndex = "spec.nodeName"
	// podUpdateWorkerSizes assumes that in most cases pod will be handled by monitorNodeHealth pass.
	// Pod update workers will only handle lagging cache pods. 4 workers should be enough.
	podUpdateWorkerSize = 4
)

// labelReconcileInfo lists Node labels to reconcile, and how to reconcile them.
// primaryKey and secondaryKey are keys of labels to reconcile.
//   - If both keys exist, but their values don't match. Use the value from the
//   primaryKey as the source of truth to reconcile.
//   - If ensureSecondaryExists is true, and the secondaryKey does not
//   exist, secondaryKey will be added with the value of the primaryKey.
var labelReconcileInfo = []struct {
	primaryKey            string
	secondaryKey          string
	ensureSecondaryExists bool
}{
	{
		// Reconcile the beta and the stable OS label using the stable label as the source of truth.
		// TODO(#89477): no earlier than 1.22: drop the beta labels if they differ from the GA labels
		primaryKey:            v1.LabelOSStable,
		secondaryKey:          kubeletapis.LabelOS,
		ensureSecondaryExists: true,
	},
	{
		// Reconcile the beta and the stable arch label using the stable label as the source of truth.
		// TODO(#89477): no earlier than 1.22: drop the beta labels if they differ from the GA labels
		primaryKey:            v1.LabelArchStable,
		secondaryKey:          kubeletapis.LabelArch,
		ensureSecondaryExists: true,
	},
}

type nodeHealthData struct {
	probeTimestamp           metav1.Time
	readyTransitionTimestamp metav1.Time
	status                   *v1.NodeStatus
	lease                    *coordv1.Lease
}

func (n *nodeHealthData) deepCopy() *nodeHealthData {
	if n == nil {
		return nil
	}
	return &nodeHealthData{
		probeTimestamp:           n.probeTimestamp,
		readyTransitionTimestamp: n.readyTransitionTimestamp,
		status:                   n.status.DeepCopy(),
		lease:                    n.lease.DeepCopy(),
	}
}

type nodeHealthMap struct {
	lock        sync.RWMutex
	nodeHealths map[string]*nodeHealthData
}

func newNodeHealthMap() *nodeHealthMap {
	return &nodeHealthMap{
		nodeHealths: make(map[string]*nodeHealthData),
	}
}

// getDeepCopy - returns copy of node health data.
// It prevents data being changed after retrieving it from the map.
func (n *nodeHealthMap) getDeepCopy(name string) *nodeHealthData {
	n.lock.RLock()
	defer n.lock.RUnlock()
	return n.nodeHealths[name].deepCopy()
}

func (n *nodeHealthMap) set(name string, data *nodeHealthData) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.nodeHealths[name] = data
}

type podUpdateItem struct {
	namespace string
	name      string
}

type evictionStatus int

const (
	unmarked = iota
	toBeEvicted
	evicted
)

// nodeEvictionMap stores evictionStatus data for each node.
type nodeEvictionMap struct {
	lock          sync.Mutex
	nodeEvictions map[string]evictionStatus
}

func newNodeEvictionMap() *nodeEvictionMap {
	return &nodeEvictionMap{
		nodeEvictions: make(map[string]evictionStatus),
	}
}

func (n *nodeEvictionMap) registerNode(nodeName string) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.nodeEvictions[nodeName] = unmarked
}

func (n *nodeEvictionMap) unregisterNode(nodeName string) {
	n.lock.Lock()
	defer n.lock.Unlock()
	delete(n.nodeEvictions, nodeName)
}

func (n *nodeEvictionMap) setStatus(nodeName string, status evictionStatus) bool {
	n.lock.Lock()
	defer n.lock.Unlock()
	if _, exists := n.nodeEvictions[nodeName]; !exists {
		return false
	}
	n.nodeEvictions[nodeName] = status
	return true
}

func (n *nodeEvictionMap) getStatus(nodeName string) (evictionStatus, bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if _, exists := n.nodeEvictions[nodeName]; !exists {
		return unmarked, false
	}
	return n.nodeEvictions[nodeName], true
}

// Controller is the controller that manages node's life cycle.
type Controller struct {
	taintManager *scheduler.NoExecuteTaintManager

	podLister         corelisters.PodLister
	podInformerSynced cache.InformerSynced
	kubeClient        clientset.Interface

	// This timestamp is to be used instead of LastProbeTime stored in Condition. We do this
	// to avoid the problem with time skew across the cluster.
	now func() metav1.Time

	enterPartialDisruptionFunc func(nodeNum int) float32
	enterFullDisruptionFunc    func(nodeNum int) float32
	computeZoneStateFunc       func(nodeConditions []*v1.NodeCondition) (int, ZoneState)

	knownNodeSet map[string]*v1.Node
	// per Node map storing last observed health together with a local time when it was observed.
	nodeHealthMap *nodeHealthMap

	// evictorLock protects zonePodEvictor and zoneNoExecuteTainter.
	// TODO(#83954): API calls shouldn't be executed under the lock.
	evictorLock     sync.Mutex
	nodeEvictionMap *nodeEvictionMap
	// workers that evicts pods from unresponsive nodes.
	zonePodEvictor map[string]*scheduler.RateLimitedTimedQueue
	// workers that are responsible for tainting nodes.
	zoneNoExecuteTainter map[string]*scheduler.RateLimitedTimedQueue

	nodesToRetry sync.Map

	zoneStates map[string]ZoneState

	daemonSetStore          appsv1listers.DaemonSetLister
	daemonSetInformerSynced cache.InformerSynced

	leaseLister         coordlisters.LeaseLister
	leaseInformerSynced cache.InformerSynced
	nodeLister          corelisters.NodeLister
	nodeInformerSynced  cache.InformerSynced

	getPodsAssignedToNode func(nodeName string) ([]*v1.Pod, error)

	recorder record.EventRecorder

	// Value controlling Controller monitoring period, i.e. how often does Controller
	// check node health signal posted from kubelet. This value should be lower than
	// nodeMonitorGracePeriod.
	// TODO: Change node health monitor to watch based.
	nodeMonitorPeriod time.Duration

	// When node is just created, e.g. cluster bootstrap or node creation, we give
	// a longer grace period.
	nodeStartupGracePeriod time.Duration

	// Controller will not proactively sync node health, but will monitor node
	// health signal updated from kubelet. There are 2 kinds of node healthiness
	// signals: NodeStatus and NodeLease. NodeLease signal is generated only when
	// NodeLease feature is enabled. If it doesn't receive update for this amount
	// of time, it will start posting "NodeReady==ConditionUnknown". The amount of
	// time before which Controller start evicting pods is controlled via flag
	// 'pod-eviction-timeout'.
	// Note: be cautious when changing the constant, it must work with
	// nodeStatusUpdateFrequency in kubelet and renewInterval in NodeLease
	// controller. The node health signal update frequency is the minimal of the
	// two.
	// There are several constraints:
	// 1. nodeMonitorGracePeriod must be N times more than  the node health signal
	//    update frequency, where N means number of retries allowed for kubelet to
	//    post node status/lease. It is pointless to make nodeMonitorGracePeriod
	//    be less than the node health signal update frequency, since there will
	//    only be fresh values from Kubelet at an interval of node health signal
	//    update frequency. The constant must be less than podEvictionTimeout.
	// 2. nodeMonitorGracePeriod can't be too large for user experience - larger
	//    value takes longer for user to see up-to-date node health.
	nodeMonitorGracePeriod time.Duration

	podEvictionTimeout          time.Duration
	evictionLimiterQPS          float32
	secondaryEvictionLimiterQPS float32
	largeClusterThreshold       int32
	unhealthyZoneThreshold      float32

	// if set to true Controller will start TaintManager that will evict Pods from
	// tainted nodes, if they're not tolerated.
	runTaintManager bool

	nodeUpdateQueue workqueue.Interface
	podUpdateQueue  workqueue.RateLimitingInterface
}

// NewNodeLifecycleController returns a new taint controller.
// dfy:
// 核心逻辑如下：
//（1）根据参数初始化Controller
//（2）定义了pod的监听处理逻辑。都是先nc.podUpdated，如果enable-taint-manager=true,还会经过nc.taintManager.PodUpdated函数处理
//（3）实现找出所有node上pod的函数
//（4）如果enable-taint-manager=true，node有变化都需要经过 nc.taintManager.NodeUpdated函数
//（5）实现node的监听处理，这里不管开没开taint-manager，都是要监听
//（6）实现node, ds, lease的list，用于获取对象
func NewNodeLifecycleController(
	leaseInformer coordinformers.LeaseInformer,
	podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer,
	daemonSetInformer appsv1informers.DaemonSetInformer,
	kubeClient clientset.Interface,
	nodeMonitorPeriod time.Duration,
	nodeStartupGracePeriod time.Duration,
	nodeMonitorGracePeriod time.Duration,
	podEvictionTimeout time.Duration,
	evictionLimiterQPS float32,
	secondaryEvictionLimiterQPS float32,
	largeClusterThreshold int32,
	unhealthyZoneThreshold float32,
	runTaintManager bool,
) (*Controller, error) {

	if kubeClient == nil {
		klog.Fatalf("kubeClient is nil when starting Controller")
	}

	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "node-controller"})
	eventBroadcaster.StartStructuredLogging(0)

	klog.Infof("Sending events to api server.")
	eventBroadcaster.StartRecordingToSink(
		&v1core.EventSinkImpl{
			Interface: v1core.New(kubeClient.CoreV1().RESTClient()).Events(""),
		})

	if kubeClient.CoreV1().RESTClient().GetRateLimiter() != nil {
		ratelimiter.RegisterMetricAndTrackRateLimiterUsage("node_lifecycle_controller", kubeClient.CoreV1().RESTClient().GetRateLimiter())
	}

	nc := &Controller{
		kubeClient:                  kubeClient,
		now:                         metav1.Now,
		knownNodeSet:                make(map[string]*v1.Node),
		nodeHealthMap:               newNodeHealthMap(),
		nodeEvictionMap:             newNodeEvictionMap(),
		recorder:                    recorder,
		nodeMonitorPeriod:           nodeMonitorPeriod,
		nodeStartupGracePeriod:      nodeStartupGracePeriod,
		nodeMonitorGracePeriod:      nodeMonitorGracePeriod,
		zonePodEvictor:              make(map[string]*scheduler.RateLimitedTimedQueue),
		zoneNoExecuteTainter:        make(map[string]*scheduler.RateLimitedTimedQueue),
		nodesToRetry:                sync.Map{},
		zoneStates:                  make(map[string]ZoneState),
		podEvictionTimeout:          podEvictionTimeout,
		evictionLimiterQPS:          evictionLimiterQPS,
		secondaryEvictionLimiterQPS: secondaryEvictionLimiterQPS,
		largeClusterThreshold:       largeClusterThreshold,
		unhealthyZoneThreshold:      unhealthyZoneThreshold,
		runTaintManager:             runTaintManager,
		nodeUpdateQueue:             workqueue.NewNamed("node_lifecycle_controller"),
		podUpdateQueue:              workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node_lifecycle_controller_pods"),
	}

	nc.enterPartialDisruptionFunc = nc.ReducedQPSFunc
	nc.enterFullDisruptionFunc = nc.HealthyQPSFunc
	nc.computeZoneStateFunc = nc.ComputeZoneState

	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			nc.podUpdated(nil, pod)
			if nc.taintManager != nil {
				nc.taintManager.PodUpdated(nil, pod)
			}
		},
		UpdateFunc: func(prev, obj interface{}) {
			prevPod := prev.(*v1.Pod)
			newPod := obj.(*v1.Pod)
			nc.podUpdated(prevPod, newPod)
			if nc.taintManager != nil {
				nc.taintManager.PodUpdated(prevPod, newPod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, isPod := obj.(*v1.Pod)
			// We can get DeletedFinalStateUnknown instead of *v1.Pod here and we need to handle that correctly.
			if !isPod {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.Errorf("Received unexpected object: %v", obj)
					return
				}
				pod, ok = deletedState.Obj.(*v1.Pod)
				if !ok {
					klog.Errorf("DeletedFinalStateUnknown contained non-Pod object: %v", deletedState.Obj)
					return
				}
			}
			nc.podUpdated(pod, nil)
			if nc.taintManager != nil {
				nc.taintManager.PodUpdated(pod, nil)
			}
		},
	})
	nc.podInformerSynced = podInformer.Informer().HasSynced
	podInformer.Informer().AddIndexers(cache.Indexers{
		nodeNameKeyIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				return []string{}, nil
			}
			if len(pod.Spec.NodeName) == 0 {
				return []string{}, nil
			}
			return []string{pod.Spec.NodeName}, nil
		},
	})

	podIndexer := podInformer.Informer().GetIndexer()
	nc.getPodsAssignedToNode = func(nodeName string) ([]*v1.Pod, error) {
		objs, err := podIndexer.ByIndex(nodeNameKeyIndex, nodeName)
		if err != nil {
			return nil, err
		}
		pods := make([]*v1.Pod, 0, len(objs))
		for _, obj := range objs {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				continue
			}
			pods = append(pods, pod)
		}
		return pods, nil
	}
	nc.podLister = podInformer.Lister()

	// dfy: 启用了 TaintManager
	if nc.runTaintManager {
		podGetter := func(name, namespace string) (*v1.Pod, error) { return nc.podLister.Pods(namespace).Get(name) }
		nodeLister := nodeInformer.Lister()
		nodeGetter := func(name string) (*v1.Node, error) { return nodeLister.Get(name) }
		nc.taintManager = scheduler.NewNoExecuteTaintManager(kubeClient, podGetter, nodeGetter, nc.getPodsAssignedToNode)
		nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: nodeutil.CreateAddNodeHandler(func(node *v1.Node) error {
				nc.taintManager.NodeUpdated(nil, node)
				return nil
			}),
			UpdateFunc: nodeutil.CreateUpdateNodeHandler(func(oldNode, newNode *v1.Node) error {
				nc.taintManager.NodeUpdated(oldNode, newNode)
				return nil
			}),
			DeleteFunc: nodeutil.CreateDeleteNodeHandler(func(node *v1.Node) error {
				nc.taintManager.NodeUpdated(node, nil)
				return nil
			}),
		})
	}

	klog.Infof("Controller will reconcile labels.")
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: nodeutil.CreateAddNodeHandler(func(node *v1.Node) error {
			nc.nodeUpdateQueue.Add(node.Name)
			nc.nodeEvictionMap.registerNode(node.Name)
			return nil
		}),
		UpdateFunc: nodeutil.CreateUpdateNodeHandler(func(_, newNode *v1.Node) error {
			nc.nodeUpdateQueue.Add(newNode.Name)
			return nil
		}),
		DeleteFunc: nodeutil.CreateDeleteNodeHandler(func(node *v1.Node) error {
			nc.nodesToRetry.Delete(node.Name)
			nc.nodeEvictionMap.unregisterNode(node.Name)
			return nil
		}),
	})

	// dfy: --feature-gates=NodeLease=xxx：默认值true，使用lease对象上报node心跳信息，替换老的更新node的status的方式，能大大减轻apiserver的负担；
	// 以前通过门控开关 NodeLease 来判别是否使用 leaseInformer，现在直接使用。 可以参考 1.16版本
	nc.leaseLister = leaseInformer.Lister()
	nc.leaseInformerSynced = leaseInformer.Informer().HasSynced

	nc.nodeLister = nodeInformer.Lister()
	nc.nodeInformerSynced = nodeInformer.Informer().HasSynced

	nc.daemonSetStore = daemonSetInformer.Lister()
	nc.daemonSetInformerSynced = daemonSetInformer.Informer().HasSynced

	return nc, nil
}

// Run starts an asynchronous loop that monitors the status of cluster nodes.
// dfy:
// 逻辑如下：
//（1）等待leaseInformer、nodeInformer、podInformerSynced、daemonSetInformerSynced同步完成。
//（2）如果enable-taint-manager=true,开启nc.taintManager.Run
//（3）执行doNodeProcessingPassWorker，这个是处理nodeUpdateQueue队列的node
//（4）doPodProcessingWorker，这个是处理podUpdateQueue队列的pod
//（5）如果开启了feature-gates=TaintBasedEvictions=true，执行doNoExecuteTaintingPass函数。否则执行doEvictionPass函数
//（6）一直监听node状态是否健康
//
//链接：https://juejin.cn/post/7130531136878411789
func (nc *Controller) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()

	klog.Infof("Starting node controller")
	defer klog.Infof("Shutting down node controller")

	if !cache.WaitForNamedCacheSync("taint", stopCh, nc.leaseInformerSynced, nc.nodeInformerSynced, nc.podInformerSynced, nc.daemonSetInformerSynced) {
		return
	}

	// dfy: 若开启了 TaintManager，便运行
	// --enable-taint-manager：默认值true，代表启动taintManager，当已经调度到该node上的pod不能容忍node的 NoExecute污点时，由TaintManager负责驱逐此类pod，若为false即不启动taintManager，则根据--pod-eviction-timeout来做驱逐操作；
	// --feature-gates=TaintBasedEvictions=xxx：默认值true，配合--enable-taint-manager共同作用，两者均为true，才会开启污点驱逐；
	//原文链接：https://blog.csdn.net/kyle18826138721/article/details/126879327
	if nc.runTaintManager {
		// 如果node没有taint了，那就取消该pod的处理（可能在定时队列中挂着）
		go nc.taintManager.Run(stopCh)
	}

	// Close node update queue to cleanup go routine.
	defer nc.nodeUpdateQueue.ShutDown()
	defer nc.podUpdateQueue.ShutDown()

	// Start workers to reconcile labels and/or update NoSchedule taint for nodes.
	for i := 0; i < scheduler.UpdateWorkerSize; i++ {
		// Thanks to "workqueue", each worker just need to get item from queue, because
		// the item is flagged when got from queue: if new event come, the new item will
		// be re-queued until "Done", so no more than one worker handle the same item and
		// no event missed.
		go wait.Until(nc.doNodeProcessingPassWorker, time.Second, stopCh)
	}

	// dfy: doPodProcessingWorker --> processPod --> processNoTaintBaseEviction --> evictPods
	// 根据 podEvictionTimeout 情况，将 node 入队；若 node 已被标记为 evicted 状态，就直接删除 pod
	for i := 0; i < podUpdateWorkerSize; i++ {
		go wait.Until(nc.doPodProcessingWorker, time.Second, stopCh)
	}

	// dfy: v1.19 取消了 TaintBasedEvictions 门控开关，以前此处是通过门控开关控制 if nc.useTaintBasedEvictions {
	// 现在只通过 --enable-taint-manager 参数来控制是否开启 TaintManager
	//
	// 以前是 TaintBasedEvictions 和 enable-taint-manager 都为 true，才能使用  TaintManager
	// enable-taint-manager 都为 true, 只能初始化和运行 TaintManager
	// 但要是门控开关 TaintBasedEvictions 不开启的话，此处无法跳转到 TaintManager 的处理逻辑
	if nc.runTaintManager {
		// Handling taint based evictions. Because we don't want a dedicated logic in TaintManager for NC-originated
		// taints and we normally don't rate limit evictions caused by taints, we need to rate limit adding taints.
		go wait.Until(nc.doNoExecuteTaintingPass, scheduler.NodeEvictionPeriod, stopCh)
	} else {
		// Managing eviction of nodes:
		// When we delete pods off a node, if the node was not empty at the time we then
		// queue an eviction watcher. If we hit an error, retry deletion.
		go wait.Until(nc.doEvictionPass, scheduler.NodeEvictionPeriod, stopCh)
	}

	// Incorporate the results of node health signal pushed from kubelet to master.
	go wait.Until(func() {
		if err := nc.monitorNodeHealth(); err != nil {
			klog.Errorf("Error monitoring node health: %v", err)
		}
	}, nc.nodeMonitorPeriod, stopCh)

	<-stopCh
}

// dfy: 处理 nodeUpdateQueue 中的 node，为其添加合适的 NoSchedule taint 以及 label
// 可以看出来doNodeProcessingPassWorker核心就是2件事：
//（1）给node添加NoScheduleTaint
//（2）给node添加lables
func (nc *Controller) doNodeProcessingPassWorker() {
	for {
		obj, shutdown := nc.nodeUpdateQueue.Get()
		// "nodeUpdateQueue" will be shutdown when "stopCh" closed;
		// we do not need to re-check "stopCh" again.
		if shutdown {
			return
		}
		nodeName := obj.(string)
		// dfy: 之前需要门控开关 TaintNodeByCondition 来开启 doNoScheduleTaintingPass 函数使用
		// 现在不需要门控开关了，直接使用，为符合条件的 Node 打上 NoSchedule 的 taint
		if err := nc.doNoScheduleTaintingPass(nodeName); err != nil {
			klog.Errorf("Failed to taint NoSchedule on node <%s>, requeue it: %v", nodeName, err)
			// TODO(k82cn): Add nodeName back to the queue
		}
		// TODO: re-evaluate whether there are any labels that need to be
		// reconcile in 1.19. Remove this function if it's no longer necessary.
		// dfy: reconcileNodeLabels就是及时给node更新
		if err := nc.reconcileNodeLabels(nodeName); err != nil {
			klog.Errorf("Failed to reconcile labels for node <%s>, requeue it: %v", nodeName, err)
			// TODO(yujuhong): Add nodeName back to the queue
		}
		nc.nodeUpdateQueue.Done(nodeName)
	}
}

// dfy:
// 核心逻辑就是检查该 node 是否需要添加对应的NoSchedule
//逻辑为：
//1、从 nodeLister 中获取该 node 对象；
//2、判断该 node 是否存在以下几种 Condition：
//	(1) False 或 Unknown 状态的 NodeReady Condition；(2) MemoryPressureCondition；(3) DiskPressureCondition；(4) NetworkUnavailableCondition；(5) PIDPressureCondition；
//		若任一一种存在会添加对应的 NoSchedule taint；
//3、判断 node 是否处于 Unschedulable 状态，若为 Unschedulable 也添加对应的 NoSchedule taint；
//4、对比 node 已有的 taints 以及需要添加的 taints，以需要添加的 taints 为准，调用 nodeutil.SwapNodeControllerTaint 为 node 添加不存在的 taints 并删除不需要的 taints；
//链接：https://juejin.cn/post/7130531136878411789

func (nc *Controller) doNoScheduleTaintingPass(nodeName string) error {
	node, err := nc.nodeLister.Get(nodeName)
	if err != nil {
		// If node not found, just ignore it.
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Map node's condition to Taints.
	var taints []v1.Taint
	for _, condition := range node.Status.Conditions {
		if taintMap, found := nodeConditionToTaintKeyStatusMap[condition.Type]; found {
			if taintKey, found := taintMap[condition.Status]; found {
				taints = append(taints, v1.Taint{
					Key:    taintKey,
					Effect: v1.TaintEffectNoSchedule,
				})
			}
		}
	}
	if node.Spec.Unschedulable {
		// If unschedulable, append related taint.
		taints = append(taints, v1.Taint{
			Key:    v1.TaintNodeUnschedulable,
			Effect: v1.TaintEffectNoSchedule,
		})
	}

	// Get exist taints of node.
	nodeTaints := taintutils.TaintSetFilter(node.Spec.Taints, func(t *v1.Taint) bool {
		// only NoSchedule taints are candidates to be compared with "taints" later
		if t.Effect != v1.TaintEffectNoSchedule {
			return false
		}
		// Find unschedulable taint of node.
		if t.Key == v1.TaintNodeUnschedulable {
			return true
		}
		// Find node condition taints of node.
		_, found := taintKeyToNodeConditionMap[t.Key]
		return found
	})
	taintsToAdd, taintsToDel := taintutils.TaintSetDiff(taints, nodeTaints)
	// If nothing to add not delete, return true directly.
	if len(taintsToAdd) == 0 && len(taintsToDel) == 0 {
		return nil
	}
	if !nodeutil.SwapNodeControllerTaint(nc.kubeClient, taintsToAdd, taintsToDel, node) {
		return fmt.Errorf("failed to swap taints of node %+v", node)
	}
	return nil
}

// dfy: doNoExecuteTaintingPass(if useTaintBasedEvictions==true)
// 启用taint manager 执行doNoExecuteTaintingPass–添加NoExecute的taint。这里不执行驱逐，驱逐单独在taint manager里处理。
// doNoExecuteTaintingPass是一个令牌桶限速队列（也是受受参数evictionLimiterQPS影响，默认0.1也就是10s驱逐一个node）
//
// - 遍历zoneNoExecuteTainter，获得一个zone的node队列，从队列中获取一个node，执行下面步骤
// - 从缓存中获取node
// - 如果node ready condition为false，移除“node.kubernetes.io/unreachable”的taint，
//   添加“node.kubernetes.io/not-ready” 的taint，Effect为NoExecute。
// - 如果node ready condition为unknown，移除“node.kubernetes.io/not-ready” 的taint，
//   添加“node.kubernetes.io/unreachable” 的taint，Effect为NoExecute。
//
//链接：https://juejin.cn/post/7130531136878411789
func (nc *Controller) doNoExecuteTaintingPass() {
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	for k := range nc.zoneNoExecuteTainter {
		// Function should return 'false' and a time after which it should be retried, or 'true' if it shouldn't (it succeeded).
		nc.zoneNoExecuteTainter[k].Try(func(value scheduler.TimedValue) (bool, time.Duration) {
			node, err := nc.nodeLister.Get(value.Value)
			if apierrors.IsNotFound(err) {
				klog.Warningf("Node %v no longer present in nodeLister!", value.Value)
				return true, 0
			} else if err != nil {
				klog.Warningf("Failed to get Node %v from the nodeLister: %v", value.Value, err)
				// retry in 50 millisecond
				return false, 50 * time.Millisecond
			}
			// dfy: 获取节点状态
			_, condition := nodeutil.GetNodeCondition(&node.Status, v1.NodeReady)
			// Because we want to mimic NodeStatus.Condition["Ready"] we make "unreachable" and "not ready" taints mutually exclusive.
			taintToAdd := v1.Taint{}
			oppositeTaint := v1.Taint{}
			switch condition.Status {
			// dfy: not ready taint
			case v1.ConditionFalse:
				taintToAdd = *NotReadyTaintTemplate
				oppositeTaint = *UnreachableTaintTemplate
				// dfy: unreachable taint
			case v1.ConditionUnknown:
				taintToAdd = *UnreachableTaintTemplate
				oppositeTaint = *NotReadyTaintTemplate
			default:
				// It seems that the Node is ready again, so there's no need to taint it.
				klog.V(4).Infof("Node %v was in a taint queue, but it's ready now. Ignoring taint request.", value.Value)
				return true, 0
			}

			// dfy: 更新节点的 taint
			result := nodeutil.SwapNodeControllerTaint(nc.kubeClient, []*v1.Taint{&taintToAdd}, []*v1.Taint{&oppositeTaint}, node)
			if result {
				//count the evictionsNumber
				zone := utilnode.GetZoneKey(node)
				evictionsNumber.WithLabelValues(zone).Inc()
			}

			return result, 0
		})
	}
}

// dfy:  doEvictionPass(if useTaintBasedEvictions==false)
// doEvictionPass是一个令牌桶限速队列(受参数evictionLimiterQPS影响，默认0.1也就是10s驱逐一个node) ，
// +加入这个队列的node都是 unready状态持续时间大于podEvictionTimeout。(这个就是processNoTaintBaseEviction将node加入了队列)
// - 遍历zonePodEvictor，获取一个zone里的node队列，从队列中获取一个node，执行下面步骤
// - 获取node的uid，从缓存中获取node上的所有pod
// - 执行DeletePods–删除daemonset之外的所有pod，保留daemonset的pod
// 1) 遍历所由的pod，检查pod绑定的node是否跟提供的一样，不一样则跳过这个pod
// 2)执行SetPodTerminationReason–设置pod Status.Reason为NodeLost，Status.Message为"Node %v which was running pod %v is unresponsive"，并更新pod。
// 3)如果pod 设置了DeletionGracePeriodSeconds，说明pod已经被删除，则跳过这个pod
// 4)判断pod是否为daemonset的pod，如果是则跳过这个pod
// 5)删除这个pod
// - 在nodeEvictionMap设置node的状态为evicted
//
//链接：https://juejin.cn/post/7130531136878411789
func (nc *Controller) doEvictionPass() {
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	for k := range nc.zonePodEvictor {
		// Function should return 'false' and a time after which it should be retried, or 'true' if it shouldn't (it succeeded).
		nc.zonePodEvictor[k].Try(func(value scheduler.TimedValue) (bool, time.Duration) {
			node, err := nc.nodeLister.Get(value.Value)
			if apierrors.IsNotFound(err) {
				klog.Warningf("Node %v no longer present in nodeLister!", value.Value)
			} else if err != nil {
				klog.Warningf("Failed to get Node %v from the nodeLister: %v", value.Value, err)
			}
			nodeUID, _ := value.UID.(string)
			// dfy: 获得分配到该节点上的 Pod
			pods, err := nc.getPodsAssignedToNode(value.Value)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("unable to list pods from node %q: %v", value.Value, err))
				return false, 0
			}
			// dfy: 删除 Pod
			remaining, err := nodeutil.DeletePods(nc.kubeClient, pods, nc.recorder, value.Value, nodeUID, nc.daemonSetStore)
			if err != nil {
				// We are not setting eviction status here.
				// New pods will be handled by zonePodEvictor retry
				// instead of immediate pod eviction.
				utilruntime.HandleError(fmt.Errorf("unable to evict node %q: %v", value.Value, err))
				return false, 0
			}
			if !nc.nodeEvictionMap.setStatus(value.Value, evicted) {
				klog.V(2).Infof("node %v was unregistered in the meantime - skipping setting status", value.Value)
			}
			if remaining {
				klog.Infof("Pods awaiting deletion due to Controller eviction")
			}

			if node != nil {
				zone := utilnode.GetZoneKey(node)
				evictionsNumber.WithLabelValues(zone).Inc()
			}

			return true, 0
		})
	}
}

// dfy:
// - 无论是否启用了 TaintBasedEvictions 特性，需要打 taint 或者驱逐 pod 的 node 都会被放在 zoneNoExecuteTainter 或者 zonePodEvictor 队列中，
// 而 nc.monitorNodeHealth 就是这两个队列中数据的生产者。
// - nc.monitorNodeHealth 的主要功能是持续监控 node 的状态，当 node 处于异常状态时更新 node 的 taint 以及 node 上 pod 的状态
// 或者直接驱逐 node 上的 pod，此外还会为集群下的所有 node 划分 zoneStates 并为每个 zoneStates 设置对应的驱逐速率。
// - 每隔nodeMonitorPeriod周期，执行一次monitorNodeHealth，维护node状态和zone的状态，更新未响应的node
// – 设置node status为unknown和根据集群不同状态设置zone的速率。
//
//链接：https://juejin.cn/post/7130531136878411789
// monitorNodeHealth verifies node health are constantly updated by kubelet, and
// if not, post "NodeReady==ConditionUnknown".
// This function will taint nodes who are not ready or not reachable for a long period of time.
func (nc *Controller) monitorNodeHealth() error {
	// We are listing nodes from local cache as we can tolerate some small delays
	// comparing to state from etcd and there is eventual consistency anyway.
	// dfy: 上面说的是，从本地缓存监听 node 状态，对比 etcd 的状态有短暂的延迟，不过可以接收，并且最终会保持一致的
	nodes, err := nc.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}
	// dfy: 将 node 分为了三类
	//   1. added: the nodes that in 'allNodes', but not in 'knownNodeSet'
	//   2. deleted: the nodes that in 'knownNodeSet', but not in 'allNodes'
	//   3. newZoneRepresentatives: the nodes that in both 'knownNodeSet' and 'allNodes', but no zone states
	added, deleted, newZoneRepresentatives := nc.classifyNodes(nodes)

	// dfy: 为这三类 node 添加 podEvictor （pod驱逐器？）
	for i := range newZoneRepresentatives {
		// dfy: zonePodEvictor 负责将 pod 从无响应的节点驱逐出去
		// dfy: zoneNoExecuteTainter 负责为 node 打上污点 taint（是给 node 打上 不可执行的 taint？）
		// dfy: 考虑是否打上 NoExecute Taint
		nc.addPodEvictorForNewZone(newZoneRepresentatives[i])
	}

	for i := range added {
		klog.V(1).Infof("Controller observed a new Node: %#v", added[i].Name)
		nodeutil.RecordNodeEvent(nc.recorder, added[i].Name, string(added[i].UID), v1.EventTypeNormal, "RegisteredNode", fmt.Sprintf("Registered Node %v in Controller", added[i].Name))
		// dfy: 将 node 添加到  knownNodeSet 中
		nc.knownNodeSet[added[i].Name] = added[i]
		nc.addPodEvictorForNewZone(added[i])
		if nc.runTaintManager {
			// dfy: 移除 node 的 unreach taint 和 notReady taint，并从 zoneNoExecuteTainter 移除该 node
			// dfy: 考虑是否移除  NoExecute Taint
			nc.markNodeAsReachable(added[i])
		} else {
			// dfy: 从 zonePodEvictor 删除该 node
			nc.cancelPodEviction(added[i])
		}
	}

	for i := range deleted {
		klog.V(1).Infof("Controller observed a Node deletion: %v", deleted[i].Name)
		nodeutil.RecordNodeEvent(nc.recorder, deleted[i].Name, string(deleted[i].UID), v1.EventTypeNormal, "RemovingNode", fmt.Sprintf("Removing Node %v from Controller", deleted[i].Name))
		delete(nc.knownNodeSet, deleted[i].Name)
	}

	zoneToNodeConditions := map[string][]*v1.NodeCondition{}
	for i := range nodes {
		var gracePeriod time.Duration
		var observedReadyCondition v1.NodeCondition
		var currentReadyCondition *v1.NodeCondition
		node := nodes[i].DeepCopy()
		if err := wait.PollImmediate(retrySleepTime, retrySleepTime*scheduler.NodeHealthUpdateRetry, func() (bool, error) {
			// dfy: 更新 node 的健康状态
			gracePeriod, observedReadyCondition, currentReadyCondition, err = nc.tryUpdateNodeHealth(node)
			if err == nil {
				return true, nil
			}
			name := node.Name
			node, err = nc.kubeClient.CoreV1().Nodes().Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				klog.Errorf("Failed while getting a Node to retry updating node health. Probably Node %s was deleted.", name)
				return false, err
			}
			return false, nil
		}); err != nil {
			klog.Errorf("Update health of Node '%v' from Controller error: %v. "+
				"Skipping - no pods will be evicted.", node.Name, err)
			continue
		}

		// Some nodes may be excluded from disruption checking
		if !isNodeExcludedFromDisruptionChecks(node) {
			zoneToNodeConditions[utilnode.GetZoneKey(node)] = append(zoneToNodeConditions[utilnode.GetZoneKey(node)], currentReadyCondition)
		}

		if currentReadyCondition != nil {
			// dfy: 获取指定节点上的 pod
			pods, err := nc.getPodsAssignedToNode(node.Name)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("unable to list pods of node %v: %v", node.Name, err))
				if currentReadyCondition.Status != v1.ConditionTrue && observedReadyCondition.Status == v1.ConditionTrue {
					// If error happened during node status transition (Ready -> NotReady)
					// we need to mark node for retry to force MarkPodsNotReady execution
					// in the next iteration.
					nc.nodesToRetry.Store(node.Name, struct{}{})
				}
				continue
			}
			// dfy: 若 runTaintManager 为 true ，
			if nc.runTaintManager {
				// 重点  打 Taint 方式驱逐
				nc.processTaintBaseEviction(node, &observedReadyCondition)
			} else {
				// 重点  不打 Taint 方式驱逐
				if err := nc.processNoTaintBaseEviction(node, &observedReadyCondition, gracePeriod, pods); err != nil {
					utilruntime.HandleError(fmt.Errorf("unable to evict all pods from node %v: %v; queuing for retry", node.Name, err))
				}
			}

			_, needsRetry := nc.nodesToRetry.Load(node.Name)
			switch {
			// dfy: 就记录个 event？
			case currentReadyCondition.Status != v1.ConditionTrue && observedReadyCondition.Status == v1.ConditionTrue:
				// Report node event only once when status changed.
				nodeutil.RecordNodeStatusChange(nc.recorder, node, "NodeNotReady")
				fallthrough // 这个是什么意思？
			case needsRetry && observedReadyCondition.Status != v1.ConditionTrue: // dfy: 二次尝试？ 标记 pod not ready？
				if err = nodeutil.MarkPodsNotReady(nc.kubeClient, nc.recorder, pods, node.Name); err != nil {
					utilruntime.HandleError(fmt.Errorf("unable to mark all pods NotReady on node %v: %v; queuing for retry", node.Name, err))
					nc.nodesToRetry.Store(node.Name, struct{}{})
					continue
				}
			}
		}
		nc.nodesToRetry.Delete(node.Name)
	}
	// dfy: 解决冲突？
	nc.handleDisruption(zoneToNodeConditions, nodes)

	return nil
}

// dfy: 重点
func (nc *Controller) processTaintBaseEviction(node *v1.Node, observedReadyCondition *v1.NodeCondition) {
	decisionTimestamp := nc.now()
	// Check eviction timeout against decisionTimestamp
	switch observedReadyCondition.Status {
	case v1.ConditionFalse:
		// We want to update the taint straight away if Node is already tainted with the UnreachableTaint
		// dfy: 如果 Node 已经被 UnreachableTaint 污染，我们希望立即更新污染
		if taintutils.TaintExists(node.Spec.Taints, UnreachableTaintTemplate) { // 具有 UnreachableTaint 就打上 NotReadyTaint, 并立即更新
			taintToAdd := *NotReadyTaintTemplate
			// dfy: 立即更新 taints
			if !nodeutil.SwapNodeControllerTaint(nc.kubeClient, []*v1.Taint{&taintToAdd}, []*v1.Taint{UnreachableTaintTemplate}, node) {
				klog.Errorf("Failed to instantly swap UnreachableTaint to NotReadyTaint. Will try again in the next cycle.")
			}
		} else if nc.markNodeForTainting(node, v1.ConditionFalse) { // dfy: 若是第一次，那么就打上 NotReady 或 UnReach taint
			klog.V(2).Infof("Node %v is NotReady as of %v. Adding it to the Taint queue.",
				node.Name,
				decisionTimestamp,
			)
		}
	case v1.ConditionUnknown: // 类似上面逻辑
		// We want to update the taint straight away if Node is already tainted with the UnreachableTaint
		if taintutils.TaintExists(node.Spec.Taints, NotReadyTaintTemplate) { // 具有 NotReadyTaint 就打上 UnreachableTaint, 并立即更新
			taintToAdd := *UnreachableTaintTemplate
			if !nodeutil.SwapNodeControllerTaint(nc.kubeClient, []*v1.Taint{&taintToAdd}, []*v1.Taint{NotReadyTaintTemplate}, node) {
				klog.Errorf("Failed to instantly swap NotReadyTaint to UnreachableTaint. Will try again in the next cycle.")
			}
		} else if nc.markNodeForTainting(node, v1.ConditionUnknown) {
			klog.V(2).Infof("Node %v is unresponsive as of %v. Adding it to the Taint queue.",
				node.Name,
				decisionTimestamp,
			)
		}
	case v1.ConditionTrue:
		removed, err := nc.markNodeAsReachable(node)
		if err != nil {
			klog.Errorf("Failed to remove taints from node %v. Will retry in next iteration.", node.Name)
		}
		if removed {
			klog.V(2).Infof("Node %s is healthy again, removing all taints", node.Name)
		}
	}
}

// dfy: 在 podEvictionTimeout 时间后，驱逐该 node 上的 pod ；不看 Taint 只看是否到时间该驱逐了
// 核心逻辑如下：
//（1）node最后发现ReadyCondition为false，如果nodeHealthMap里的readyTransitionTimestamp加上podEvictionTimeout的时间是过去的时间
//  –ReadyCondition为false状态已经持续了至少podEvictionTimeout，执行evictPods。
//（2）node最后发现ReadyCondition为unknown，如果nodeHealthMap里的probeTimestamp加上podEvictionTimeout的时间是过去的时间
//  –ReadyCondition为false状态已经持续了至少podEvictionTimeout，执行evictPods。
//（3）node最后发现ReadyCondition为true，则执行cancelPodEviction
//  –在nodeEvictionMap设置status为unmarked，然后node从zonePodEvictor队列中移除。
//
// evictPods并不会马上驱逐pod，他还是看node是否已经是驱逐状态。
// evictPods先从nodeEvictionMap获取node驱逐的状态，如果是evicted说明node已经发生驱逐，则把node上的这个pod删除。
// 否则设置状态为toBeEvicted，然后node加入zonePodEvictor队列等待执行驱逐pod
//链接：https://juejin.cn/post/7130531136878411789
func (nc *Controller) processNoTaintBaseEviction(node *v1.Node, observedReadyCondition *v1.NodeCondition, gracePeriod time.Duration, pods []*v1.Pod) error {
	decisionTimestamp := nc.now()
	nodeHealthData := nc.nodeHealthMap.getDeepCopy(node.Name)
	if nodeHealthData == nil {
		return fmt.Errorf("health data doesn't exist for node %q", node.Name)
	}
	// Check eviction timeout against decisionTimestamp
	switch observedReadyCondition.Status {
	case v1.ConditionFalse:
		// dfy: 在 readyTransitionTimestamp + podEvictionTimeout 时间后，驱逐该 node 上的 pod
		if decisionTimestamp.After(nodeHealthData.readyTransitionTimestamp.Add(nc.podEvictionTimeout)) {
			// dfy: 将 node 放入到待驱逐队列
			enqueued, err := nc.evictPods(node, pods) // dfy: 驱逐 pod 逻辑，待看
			if err != nil {
				return err
			}
			if enqueued {
				klog.V(2).Infof("Node is NotReady. Adding Pods on Node %s to eviction queue: %v is later than %v + %v",
					node.Name,
					decisionTimestamp,
					nodeHealthData.readyTransitionTimestamp,
					nc.podEvictionTimeout,
				)
			}
		}
	case v1.ConditionUnknown: // dfy: 逻辑与上面类似
		if decisionTimestamp.After(nodeHealthData.probeTimestamp.Add(nc.podEvictionTimeout)) {
			enqueued, err := nc.evictPods(node, pods)
			if err != nil {
				return err
			}
			if enqueued {
				klog.V(2).Infof("Node is unresponsive. Adding Pods on Node %s to eviction queues: %v is later than %v + %v",
					node.Name,
					decisionTimestamp,
					nodeHealthData.readyTransitionTimestamp,
					nc.podEvictionTimeout-gracePeriod,
				)
			}
		}
	case v1.ConditionTrue:
		if nc.cancelPodEviction(node) {
			klog.V(2).Infof("Node %s is ready again, cancelled pod eviction", node.Name)
		}
	}
	return nil
}

// labelNodeDisruptionExclusion is a label on nodes that controls whether they are
// excluded from being considered for disruption checks by the node controller.
const labelNodeDisruptionExclusion = "node.kubernetes.io/exclude-disruption"

func isNodeExcludedFromDisruptionChecks(node *v1.Node) bool {
	// DEPRECATED: will be removed in 1.19
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.LegacyNodeRoleBehavior) {
		if legacyIsMasterNode(node.Name) {
			return true
		}
	}
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.NodeDisruptionExclusion) {
		if _, ok := node.Labels[labelNodeDisruptionExclusion]; ok {
			return true
		}
	}
	return false
}

// legacyIsMasterNode returns true if given node is a registered master according
// to the logic historically used for this function. This code path is deprecated
// and the node disruption exclusion label should be used in the future.
// This code will not be allowed to update to use the node-role label, since
// node-roles may not be used for feature enablement.
// DEPRECATED: Will be removed in 1.19
func legacyIsMasterNode(nodeName string) bool {
	// We are trying to capture "master(-...)?$" regexp.
	// However, using regexp.MatchString() results even in more than 35%
	// of all space allocations in ControllerManager spent in this function.
	// That's why we are trying to be a bit smarter.
	if strings.HasSuffix(nodeName, "master") {
		return true
	}
	if len(nodeName) >= 10 {
		return strings.HasSuffix(nodeName[:len(nodeName)-3], "master-")
	}
	return false
}

// tryUpdateNodeHealth checks a given node's conditions and tries to update it. Returns grace period to
// which given node is entitled, state of current and last observed Ready Condition, and an error if it occurred.
func (nc *Controller) tryUpdateNodeHealth(node *v1.Node) (time.Duration, v1.NodeCondition, *v1.NodeCondition, error) {
	nodeHealth := nc.nodeHealthMap.getDeepCopy(node.Name)
	defer func() {
		nc.nodeHealthMap.set(node.Name, nodeHealth)
	}()

	var gracePeriod time.Duration
	var observedReadyCondition v1.NodeCondition
	// dfy: 判断当前这个 node 是否具有 Ready  condition，一个 node 可以有多中 condition  如 MemoryPressure  DiskPressure Ready 等
	_, currentReadyCondition := nodeutil.GetNodeCondition(&node.Status, v1.NodeReady)
	if currentReadyCondition == nil {
		// If ready condition is nil, then kubelet (or nodecontroller) never posted node status.
		// A fake ready condition is created, where LastHeartbeatTime and LastTransitionTime is set
		// to node.CreationTimestamp to avoid handle the corner case.
		// 若 ready condition 为 nil，说明 kubelet 从未上报过状态，此处创建个假的 Ready condition
		observedReadyCondition = v1.NodeCondition{
			Type:               v1.NodeReady,
			Status:             v1.ConditionUnknown,
			LastHeartbeatTime:  node.CreationTimestamp,
			LastTransitionTime: node.CreationTimestamp,
		}
		gracePeriod = nc.nodeStartupGracePeriod
		if nodeHealth != nil {
			nodeHealth.status = &node.Status
		} else {
			nodeHealth = &nodeHealthData{
				status:                   &node.Status,
				probeTimestamp:           node.CreationTimestamp,
				readyTransitionTimestamp: node.CreationTimestamp,
			}
		}
	} else {
		// If ready condition is not nil, make a copy of it, since we may modify it in place later.
		observedReadyCondition = *currentReadyCondition
		gracePeriod = nc.nodeMonitorGracePeriod
	}
	// There are following cases to check:
	// - both saved and new status have no Ready Condition set - we leave everything as it is,
	// - saved status have no Ready Condition, but current one does - Controller was restarted with Node data already present in etcd,
	// - saved status have some Ready Condition, but current one does not - it's an error, but we fill it up because that's probably a good thing to do,
	// - both saved and current statuses have Ready Conditions and they have the same LastProbeTime - nothing happened on that Node, it may be
	//   unresponsive, so we leave it as it is,
	// - both saved and current statuses have Ready Conditions, they have different LastProbeTimes, but the same Ready Condition State -
	//   everything's in order, no transition occurred, we update only probeTimestamp,
	// - both saved and current statuses have Ready Conditions, different LastProbeTimes and different Ready Condition State -
	//   Ready Condition changed it state since we last seen it, so we update both probeTimestamp and readyTransitionTimestamp.
	// TODO: things to consider:
	//   - if 'LastProbeTime' have gone back in time its probably an error, currently we ignore it,
	//   - currently only correct Ready State transition outside of Node Controller is marking it ready by Kubelet, we don't check
	//     if that's the case, but it does not seem necessary.
	var savedCondition *v1.NodeCondition
	var savedLease *coordv1.Lease
	if nodeHealth != nil {
		_, savedCondition = nodeutil.GetNodeCondition(nodeHealth.status, v1.NodeReady)
		savedLease = nodeHealth.lease
	}

	if nodeHealth == nil {
		klog.Warningf("Missing timestamp for Node %s. Assuming now as a timestamp.", node.Name)
		nodeHealth = &nodeHealthData{
			status:                   &node.Status,
			probeTimestamp:           nc.now(),
			readyTransitionTimestamp: nc.now(),
		}
	} else if savedCondition == nil && currentReadyCondition != nil {
		klog.V(1).Infof("Creating timestamp entry for newly observed Node %s", node.Name)
		nodeHealth = &nodeHealthData{
			status:                   &node.Status,
			probeTimestamp:           nc.now(),
			readyTransitionTimestamp: nc.now(),
		}
	} else if savedCondition != nil && currentReadyCondition == nil {
		klog.Errorf("ReadyCondition was removed from Status of Node %s", node.Name)
		// TODO: figure out what to do in this case. For now we do the same thing as above.
		nodeHealth = &nodeHealthData{
			status:                   &node.Status,
			probeTimestamp:           nc.now(),
			readyTransitionTimestamp: nc.now(),
		}
	} else if savedCondition != nil && currentReadyCondition != nil && savedCondition.LastHeartbeatTime != currentReadyCondition.LastHeartbeatTime {
		var transitionTime metav1.Time
		// If ReadyCondition changed since the last time we checked, we update the transition timestamp to "now",
		// otherwise we leave it as it is.
		if savedCondition.LastTransitionTime != currentReadyCondition.LastTransitionTime {
			klog.V(3).Infof("ReadyCondition for Node %s transitioned from %v to %v", node.Name, savedCondition, currentReadyCondition)
			transitionTime = nc.now()
		} else {
			transitionTime = nodeHealth.readyTransitionTimestamp
		}
		if klog.V(5).Enabled() {
			klog.Infof("Node %s ReadyCondition updated. Updating timestamp: %+v vs %+v.", node.Name, nodeHealth.status, node.Status)
		} else {
			klog.V(3).Infof("Node %s ReadyCondition updated. Updating timestamp.", node.Name)
		}
		nodeHealth = &nodeHealthData{
			status:                   &node.Status,
			probeTimestamp:           nc.now(),
			readyTransitionTimestamp: transitionTime,
		}
	}
	// Always update the probe time if node lease is renewed.
	// Note: If kubelet never posted the node status, but continues renewing the
	// heartbeat leases, the node controller will assume the node is healthy and
	// take no action.
	observedLease, _ := nc.leaseLister.Leases(v1.NamespaceNodeLease).Get(node.Name)
	if observedLease != nil && (savedLease == nil || savedLease.Spec.RenewTime.Before(observedLease.Spec.RenewTime)) {
		nodeHealth.lease = observedLease
		nodeHealth.probeTimestamp = nc.now()
	}

	if nc.now().After(nodeHealth.probeTimestamp.Add(gracePeriod)) {
		// NodeReady condition or lease was last set longer ago than gracePeriod, so
		// update it to Unknown (regardless of its current value) in the master.

		nodeConditionTypes := []v1.NodeConditionType{
			v1.NodeReady,
			v1.NodeMemoryPressure,
			v1.NodeDiskPressure,
			v1.NodePIDPressure,
			// We don't change 'NodeNetworkUnavailable' condition, as it's managed on a control plane level.
			// v1.NodeNetworkUnavailable,
		}

		nowTimestamp := nc.now()
		// dfy: 寻找 node 是否有上面几个异常状态
		for _, nodeConditionType := range nodeConditionTypes {
			// dfy: 具有异常状态，就进行记录
			_, currentCondition := nodeutil.GetNodeCondition(&node.Status, nodeConditionType)
			if currentCondition == nil {
				klog.V(2).Infof("Condition %v of node %v was never updated by kubelet", nodeConditionType, node.Name)
				node.Status.Conditions = append(node.Status.Conditions, v1.NodeCondition{
					Type:               nodeConditionType,
					Status:             v1.ConditionUnknown,
					Reason:             "NodeStatusNeverUpdated",
					Message:            "Kubelet never posted node status.",
					LastHeartbeatTime:  node.CreationTimestamp,
					LastTransitionTime: nowTimestamp,
				})
			} else {
				klog.V(2).Infof("node %v hasn't been updated for %+v. Last %v is: %+v",
					node.Name, nc.now().Time.Sub(nodeHealth.probeTimestamp.Time), nodeConditionType, currentCondition)
				if currentCondition.Status != v1.ConditionUnknown {
					currentCondition.Status = v1.ConditionUnknown
					currentCondition.Reason = "NodeStatusUnknown"
					currentCondition.Message = "Kubelet stopped posting node status."
					currentCondition.LastTransitionTime = nowTimestamp
				}
			}
		}
		// We need to update currentReadyCondition due to its value potentially changed.
		_, currentReadyCondition = nodeutil.GetNodeCondition(&node.Status, v1.NodeReady)

		if !apiequality.Semantic.DeepEqual(currentReadyCondition, &observedReadyCondition) {
			if _, err := nc.kubeClient.CoreV1().Nodes().UpdateStatus(context.TODO(), node, metav1.UpdateOptions{}); err != nil {
				klog.Errorf("Error updating node %s: %v", node.Name, err)
				return gracePeriod, observedReadyCondition, currentReadyCondition, err
			}
			nodeHealth = &nodeHealthData{
				status:                   &node.Status,
				probeTimestamp:           nodeHealth.probeTimestamp,
				readyTransitionTimestamp: nc.now(),
				lease:                    observedLease,
			}
			return gracePeriod, observedReadyCondition, currentReadyCondition, nil
		}
	}

	return gracePeriod, observedReadyCondition, currentReadyCondition, nil
}

func (nc *Controller) handleDisruption(zoneToNodeConditions map[string][]*v1.NodeCondition, nodes []*v1.Node) {
	newZoneStates := map[string]ZoneState{}
	allAreFullyDisrupted := true
	for k, v := range zoneToNodeConditions {
		zoneSize.WithLabelValues(k).Set(float64(len(v)))
		unhealthy, newState := nc.computeZoneStateFunc(v)
		zoneHealth.WithLabelValues(k).Set(float64(100*(len(v)-unhealthy)) / float64(len(v)))
		unhealthyNodes.WithLabelValues(k).Set(float64(unhealthy))
		if newState != stateFullDisruption {
			allAreFullyDisrupted = false
		}
		newZoneStates[k] = newState
		if _, had := nc.zoneStates[k]; !had {
			klog.Errorf("Setting initial state for unseen zone: %v", k)
			nc.zoneStates[k] = stateInitial
		}
	}

	allWasFullyDisrupted := true
	for k, v := range nc.zoneStates {
		if _, have := zoneToNodeConditions[k]; !have {
			zoneSize.WithLabelValues(k).Set(0)
			zoneHealth.WithLabelValues(k).Set(100)
			unhealthyNodes.WithLabelValues(k).Set(0)
			delete(nc.zoneStates, k)
			continue
		}
		if v != stateFullDisruption {
			allWasFullyDisrupted = false
			break
		}
	}

	// At least one node was responding in previous pass or in the current pass. Semantics is as follows:
	// - if the new state is "partialDisruption" we call a user defined function that returns a new limiter to use,
	// - if the new state is "normal" we resume normal operation (go back to default limiter settings),
	// - if new state is "fullDisruption" we restore normal eviction rate,
	//   - unless all zones in the cluster are in "fullDisruption" - in that case we stop all evictions.
	if !allAreFullyDisrupted || !allWasFullyDisrupted {
		// We're switching to full disruption mode
		if allAreFullyDisrupted {
			klog.V(0).Info("Controller detected that all Nodes are not-Ready. Entering master disruption mode.")
			for i := range nodes {
				if nc.runTaintManager {
					_, err := nc.markNodeAsReachable(nodes[i])
					if err != nil {
						klog.Errorf("Failed to remove taints from Node %v", nodes[i].Name)
					}
				} else {
					nc.cancelPodEviction(nodes[i])
				}
			}
			// We stop all evictions.
			for k := range nc.zoneStates {
				if nc.runTaintManager {
					nc.zoneNoExecuteTainter[k].SwapLimiter(0)
				} else {
					nc.zonePodEvictor[k].SwapLimiter(0)
				}
			}
			for k := range nc.zoneStates {
				nc.zoneStates[k] = stateFullDisruption
			}
			// All rate limiters are updated, so we can return early here.
			return
		}
		// We're exiting full disruption mode
		if allWasFullyDisrupted {
			klog.V(0).Info("Controller detected that some Nodes are Ready. Exiting master disruption mode.")
			// When exiting disruption mode update probe timestamps on all Nodes.
			now := nc.now()
			for i := range nodes {
				v := nc.nodeHealthMap.getDeepCopy(nodes[i].Name)
				v.probeTimestamp = now
				v.readyTransitionTimestamp = now
				nc.nodeHealthMap.set(nodes[i].Name, v)
			}
			// We reset all rate limiters to settings appropriate for the given state.
			for k := range nc.zoneStates {
				nc.setLimiterInZone(k, len(zoneToNodeConditions[k]), newZoneStates[k])
				nc.zoneStates[k] = newZoneStates[k]
			}
			return
		}
		// We know that there's at least one not-fully disrupted so,
		// we can use default behavior for rate limiters
		for k, v := range nc.zoneStates {
			newState := newZoneStates[k]
			if v == newState {
				continue
			}
			klog.V(0).Infof("Controller detected that zone %v is now in state %v.", k, newState)
			nc.setLimiterInZone(k, len(zoneToNodeConditions[k]), newState)
			nc.zoneStates[k] = newState
		}
	}
}

func (nc *Controller) podUpdated(oldPod, newPod *v1.Pod) {
	if newPod == nil {
		return
	}
	if len(newPod.Spec.NodeName) != 0 && (oldPod == nil || newPod.Spec.NodeName != oldPod.Spec.NodeName) {
		podItem := podUpdateItem{newPod.Namespace, newPod.Name}
		nc.podUpdateQueue.Add(podItem)
	}
}

// dfy:
// doPodProcessingWorker从podUpdateQueue读取一个pod，执行processPod。（注意这里的podUpdateQueue和tainManger的podUpdateQueue不是一个队列，是同名而已）
//processPod和新逻辑如下：
//（1） 判断NodeCondition是否notReady
//（2）如果feature-gates=TaintBasedEvictions=false，则执行processNoTaintBaseEviction
//（3）最终都会判断node ReadyCondition是否不为true，如果不为true, 执行MarkPodsNotReady
//	–如果pod的ready condition不为false， 将pod的ready condition设置为false，并更新LastTransitionTimestamp；否则不更新pod
//链接：https://juejin.cn/post/7130531136878411789
func (nc *Controller) doPodProcessingWorker() {
	for {
		obj, shutdown := nc.podUpdateQueue.Get()
		// "podUpdateQueue" will be shutdown when "stopCh" closed;
		// we do not need to re-check "stopCh" again.
		if shutdown {
			return
		}

		podItem := obj.(podUpdateItem)
		nc.processPod(podItem)
	}
}

// processPod is processing events of assigning pods to nodes. In particular:
// 1. for NodeReady=true node, taint eviction for this pod will be cancelled
// 2. for NodeReady=false or unknown node, taint eviction of pod will happen and pod will be marked as not ready
// 3. if node doesn't exist in cache, it will be skipped and handled later by doEvictionPass
func (nc *Controller) processPod(podItem podUpdateItem) {
	defer nc.podUpdateQueue.Done(podItem)
	pod, err := nc.podLister.Pods(podItem.namespace).Get(podItem.name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// If the pod was deleted, there is no need to requeue.
			return
		}
		klog.Warningf("Failed to read pod %v/%v: %v.", podItem.namespace, podItem.name, err)
		nc.podUpdateQueue.AddRateLimited(podItem)
		return
	}

	nodeName := pod.Spec.NodeName

	nodeHealth := nc.nodeHealthMap.getDeepCopy(nodeName)
	if nodeHealth == nil {
		// Node data is not gathered yet or node has beed removed in the meantime.
		// Pod will be handled by doEvictionPass method.
		return
	}

	node, err := nc.nodeLister.Get(nodeName)
	if err != nil {
		klog.Warningf("Failed to read node %v: %v.", nodeName, err)
		nc.podUpdateQueue.AddRateLimited(podItem)
		return
	}

	_, currentReadyCondition := nodeutil.GetNodeCondition(nodeHealth.status, v1.NodeReady)
	if currentReadyCondition == nil {
		// Lack of NodeReady condition may only happen after node addition (or if it will be maliciously deleted).
		// In both cases, the pod will be handled correctly (evicted if needed) during processing
		// of the next node update event.
		return
	}

	pods := []*v1.Pod{pod}
	// In taint-based eviction mode, only node updates are processed by NodeLifecycleController.
	// Pods are processed by TaintManager.
	if !nc.runTaintManager {
		// dfy: 没有 Taint 是的处理方式，等待 podEvictionTimeout 时间，将 pod 加入待驱逐队列
		if err := nc.processNoTaintBaseEviction(node, currentReadyCondition, nc.nodeMonitorGracePeriod, pods); err != nil {
			klog.Warningf("Unable to process pod %+v eviction from node %v: %v.", podItem, nodeName, err)
			nc.podUpdateQueue.AddRateLimited(podItem)
			return
		}
	}

	if currentReadyCondition.Status != v1.ConditionTrue {
		if err := nodeutil.MarkPodsNotReady(nc.kubeClient, nc.recorder, pods, nodeName); err != nil {
			klog.Warningf("Unable to mark pod %+v NotReady on node %v: %v.", podItem, nodeName, err)
			nc.podUpdateQueue.AddRateLimited(podItem)
		}
	}
}

func (nc *Controller) setLimiterInZone(zone string, zoneSize int, state ZoneState) {
	switch state {
	case stateNormal:
		if nc.runTaintManager {
			nc.zoneNoExecuteTainter[zone].SwapLimiter(nc.evictionLimiterQPS)
		} else {
			nc.zonePodEvictor[zone].SwapLimiter(nc.evictionLimiterQPS)
		}
	case statePartialDisruption:
		if nc.runTaintManager {
			nc.zoneNoExecuteTainter[zone].SwapLimiter(
				nc.enterPartialDisruptionFunc(zoneSize))
		} else {
			nc.zonePodEvictor[zone].SwapLimiter(
				nc.enterPartialDisruptionFunc(zoneSize))
		}
	case stateFullDisruption:
		if nc.runTaintManager {
			nc.zoneNoExecuteTainter[zone].SwapLimiter(
				nc.enterFullDisruptionFunc(zoneSize))
		} else {
			nc.zonePodEvictor[zone].SwapLimiter(
				nc.enterFullDisruptionFunc(zoneSize))
		}
	}
}

// classifyNodes classifies the allNodes to three categories:
//   1. added: the nodes that in 'allNodes', but not in 'knownNodeSet'
//   2. deleted: the nodes that in 'knownNodeSet', but not in 'allNodes'
//   3. newZoneRepresentatives: the nodes that in both 'knownNodeSet' and 'allNodes', but no zone states
func (nc *Controller) classifyNodes(allNodes []*v1.Node) (added, deleted, newZoneRepresentatives []*v1.Node) {
	for i := range allNodes {
		if _, has := nc.knownNodeSet[allNodes[i].Name]; !has {
			added = append(added, allNodes[i])
		} else {
			// Currently, we only consider new zone as updated.
			zone := utilnode.GetZoneKey(allNodes[i])
			if _, found := nc.zoneStates[zone]; !found {
				newZoneRepresentatives = append(newZoneRepresentatives, allNodes[i])
			}
		}
	}

	// If there's a difference between lengths of known Nodes and observed nodes
	// we must have removed some Node.
	if len(nc.knownNodeSet)+len(added) != len(allNodes) {
		knowSetCopy := map[string]*v1.Node{}
		for k, v := range nc.knownNodeSet {
			knowSetCopy[k] = v
		}
		for i := range allNodes {
			delete(knowSetCopy, allNodes[i].Name)
		}
		for i := range knowSetCopy {
			deleted = append(deleted, knowSetCopy[i])
		}
	}
	return
}

// HealthyQPSFunc returns the default value for cluster eviction rate - we take
// nodeNum for consistency with ReducedQPSFunc.
func (nc *Controller) HealthyQPSFunc(nodeNum int) float32 {
	return nc.evictionLimiterQPS
}

// ReducedQPSFunc returns the QPS for when a the cluster is large make
// evictions slower, if they're small stop evictions altogether.
func (nc *Controller) ReducedQPSFunc(nodeNum int) float32 {
	if int32(nodeNum) > nc.largeClusterThreshold {
		return nc.secondaryEvictionLimiterQPS
	}
	return 0
}

// addPodEvictorForNewZone checks if new zone appeared, and if so add new evictor.
func (nc *Controller) addPodEvictorForNewZone(node *v1.Node) {
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	zone := utilnode.GetZoneKey(node)
	if _, found := nc.zoneStates[zone]; !found {
		// dfy: 没有找到 zone value，设置为 Initial
		nc.zoneStates[zone] = stateInitial
		// dfy: 没有 TaintManager，创建一个 限速队列，不太清楚有什么作用？？？
		if !nc.runTaintManager {
			// dfy: zonePodEvictor 负责将 pod 从无响应的节点驱逐出去
			nc.zonePodEvictor[zone] =
				scheduler.NewRateLimitedTimedQueue(
					flowcontrol.NewTokenBucketRateLimiter(nc.evictionLimiterQPS, scheduler.EvictionRateLimiterBurst))
		} else {
			// dfy: zoneNoExecuteTainter 负责为 node 打上污点 taint
			nc.zoneNoExecuteTainter[zone] =
				scheduler.NewRateLimitedTimedQueue(
					flowcontrol.NewTokenBucketRateLimiter(nc.evictionLimiterQPS, scheduler.EvictionRateLimiterBurst))
		}
		// Init the metric for the new zone.
		klog.Infof("Initializing eviction metric for zone: %v", zone)
		evictionsNumber.WithLabelValues(zone).Add(0)
	}
}

// cancelPodEviction removes any queued evictions, typically because the node is available again. It
// returns true if an eviction was queued.
// cancelPodEviction 删除任何排队的驱逐，通常是因为节点再次可用。如果驱逐已排队，则它返回 true。
func (nc *Controller) cancelPodEviction(node *v1.Node) bool {
	zone := utilnode.GetZoneKey(node)
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	if !nc.nodeEvictionMap.setStatus(node.Name, unmarked) {
		klog.V(2).Infof("node %v was unregistered in the meantime - skipping setting status", node.Name)
	}
	wasDeleting := nc.zonePodEvictor[zone].Remove(node.Name)
	// dfy: 节点可用？ 删除 pod驱逐者 成功？
	if wasDeleting {
		klog.V(2).Infof("Cancelling pod Eviction on Node: %v", node.Name)
		return true
	}
	return false
}

// evictPods:
// - adds node to evictor queue if the node is not marked as evicted.
//   Returns false if the node name was already enqueued.
// - deletes pods immediately if node is already marked as evicted.
//   Returns false, because the node wasn't added to the queue.
// - 若 node 没有被标记为 evicted，就将node放入到 evictor 队列；若已在队列，返回 false
// - 若 node 已被标记 evicted，就立刻删除 pods；若node 没有被添加到队列，返回 false
func (nc *Controller) evictPods(node *v1.Node, pods []*v1.Pod) (bool, error) {
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	status, ok := nc.nodeEvictionMap.getStatus(node.Name)
	if ok && status == evicted {
		// Node eviction already happened for this node.
		// Handling immediate pod deletion.
		_, err := nodeutil.DeletePods(nc.kubeClient, pods, nc.recorder, node.Name, string(node.UID), nc.daemonSetStore)
		if err != nil {
			return false, fmt.Errorf("unable to delete pods from node %q: %v", node.Name, err)
		}
		return false, nil
	}
	if !nc.nodeEvictionMap.setStatus(node.Name, toBeEvicted) {
		klog.V(2).Infof("node %v was unregistered in the meantime - skipping setting status", node.Name)
	}
	// dfy: 将 node 放入到待驱逐队列？
	return nc.zonePodEvictor[utilnode.GetZoneKey(node)].Add(node.Name, string(node.UID)), nil
}

func (nc *Controller) markNodeForTainting(node *v1.Node, status v1.ConditionStatus) bool {
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	if status == v1.ConditionFalse {
		if !taintutils.TaintExists(node.Spec.Taints, NotReadyTaintTemplate) {
			nc.zoneNoExecuteTainter[utilnode.GetZoneKey(node)].Remove(node.Name)
		}
	}

	if status == v1.ConditionUnknown {
		if !taintutils.TaintExists(node.Spec.Taints, UnreachableTaintTemplate) {
			nc.zoneNoExecuteTainter[utilnode.GetZoneKey(node)].Remove(node.Name)
		}
	}

	return nc.zoneNoExecuteTainter[utilnode.GetZoneKey(node)].Add(node.Name, string(node.UID))
}

func (nc *Controller) markNodeAsReachable(node *v1.Node) (bool, error) {
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	// dfy: 移除 不可达 taint
	err := controller.RemoveTaintOffNode(nc.kubeClient, node.Name, node, UnreachableTaintTemplate)
	if err != nil {
		klog.Errorf("Failed to remove taint from node %v: %v", node.Name, err)
		return false, err
	}
	// dfy: 移除 notReady taint
	err = controller.RemoveTaintOffNode(nc.kubeClient, node.Name, node, NotReadyTaintTemplate)
	if err != nil {
		klog.Errorf("Failed to remove taint from node %v: %v", node.Name, err)
		return false, err
	}
	// dfy： 从 zoneNoExecuteTainter 记录中移除该 node
	return nc.zoneNoExecuteTainter[utilnode.GetZoneKey(node)].Remove(node.Name), nil
}

// ComputeZoneState returns a slice of NodeReadyConditions for all Nodes in a given zone.
// The zone is considered:
// - fullyDisrupted if there're no Ready Nodes,
// - partiallyDisrupted if at least than nc.unhealthyZoneThreshold percent of Nodes are not Ready,
// - normal otherwise
func (nc *Controller) ComputeZoneState(nodeReadyConditions []*v1.NodeCondition) (int, ZoneState) {
	readyNodes := 0
	notReadyNodes := 0
	for i := range nodeReadyConditions {
		if nodeReadyConditions[i] != nil && nodeReadyConditions[i].Status == v1.ConditionTrue {
			readyNodes++
		} else {
			notReadyNodes++
		}
	}
	switch {
	case readyNodes == 0 && notReadyNodes > 0:
		return notReadyNodes, stateFullDisruption
	case notReadyNodes > 2 && float32(notReadyNodes)/float32(notReadyNodes+readyNodes) >= nc.unhealthyZoneThreshold:
		return notReadyNodes, statePartialDisruption
	default:
		return notReadyNodes, stateNormal
	}
}

// reconcileNodeLabels reconciles node labels.
func (nc *Controller) reconcileNodeLabels(nodeName string) error {
	node, err := nc.nodeLister.Get(nodeName)
	if err != nil {
		// If node not found, just ignore it.
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if node.Labels == nil {
		// Nothing to reconcile.
		return nil
	}

	labelsToUpdate := map[string]string{}
	for _, r := range labelReconcileInfo {
		primaryValue, primaryExists := node.Labels[r.primaryKey]
		secondaryValue, secondaryExists := node.Labels[r.secondaryKey]

		if !primaryExists {
			// The primary label key does not exist. This should not happen
			// within our supported version skew range, when no external
			// components/factors modifying the node object. Ignore this case.
			continue
		}
		if secondaryExists && primaryValue != secondaryValue {
			// Secondary label exists, but not consistent with the primary
			// label. Need to reconcile.
			labelsToUpdate[r.secondaryKey] = primaryValue

		} else if !secondaryExists && r.ensureSecondaryExists {
			// Apply secondary label based on primary label.
			labelsToUpdate[r.secondaryKey] = primaryValue
		}
	}

	if len(labelsToUpdate) == 0 {
		return nil
	}
	if !nodeutil.AddOrUpdateLabelsOnNode(nc.kubeClient, labelsToUpdate, node) {
		return fmt.Errorf("failed update labels for node %+v", node)
	}
	return nil
}
