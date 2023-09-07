/*
Copyright 2019 The Kubernetes Authors.

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

package podtopologyspread

import (
	"context"
	"fmt"
	"math"
	"sync/atomic"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/helper"
	framework "k8s.io/kubernetes/pkg/scheduler/framework/v1alpha1"
	"k8s.io/kubernetes/pkg/scheduler/internal/parallelize"
)

const preFilterStateKey = "PreFilter" + Name

// preFilterState computed at PreFilter and used at Filter.
// It combines TpKeyToCriticalPaths and TpPairToMatchNum to represent:
// (1) critical paths where the least pods are matched on each spread constraint.
// (2) number of pods matched on each spread constraint.
// A nil preFilterState denotes it's not set at all (in PreFilter phase);
// An empty preFilterState object denotes it's a legit state and is set in PreFilter phase.
// Fields are exported for comparison during testing.
type preFilterState struct {
	Constraints []topologySpreadConstraint
	// We record 2 critical paths instead of all critical paths here.
	// criticalPaths[0].MatchNum always holds the minimum matching number.
	// criticalPaths[1].MatchNum is always greater or equal to criticalPaths[0].MatchNum, but
	// it's not guaranteed to be the 2nd minimum match number.
	TpKeyToCriticalPaths map[string]*criticalPaths
	// TpPairToMatchNum is keyed with topologyPair, and valued with the number of matching pods.
	TpPairToMatchNum map[topologyPair]*int32
}

// Clone makes a copy of the given state.
func (s *preFilterState) Clone() framework.StateData {
	if s == nil {
		return nil
	}
	copy := preFilterState{
		// Constraints are shared because they don't change.
		Constraints:          s.Constraints,
		TpKeyToCriticalPaths: make(map[string]*criticalPaths, len(s.TpKeyToCriticalPaths)),
		TpPairToMatchNum:     make(map[topologyPair]*int32, len(s.TpPairToMatchNum)),
	}
	for tpKey, paths := range s.TpKeyToCriticalPaths {
		copy.TpKeyToCriticalPaths[tpKey] = &criticalPaths{paths[0], paths[1]}
	}
	for tpPair, matchNum := range s.TpPairToMatchNum {
		copyPair := topologyPair{key: tpPair.key, value: tpPair.value}
		copyCount := *matchNum
		copy.TpPairToMatchNum[copyPair] = &copyCount
	}
	return &copy
}

// CAVEAT: the reason that `[2]criticalPath` can work is based on the implementation of current
// preemption algorithm, in particular the following 2 facts:
// Fact 1: we only preempt pods on the same node, instead of pods on multiple nodes.
// Fact 2: each node is evaluated on a separate copy of the preFilterState during its preemption cycle.
// If we plan to turn to a more complex algorithm like "arbitrary pods on multiple nodes", this
// structure needs to be revisited.
// Fields are exported for comparison during testing.
// dfy:
// [2]criticalPath能够工作的原因是基于当前抢占算法的实现，特别是以下两个事实
// 事实 1：只抢占同一节点上的Pod，而不是多个节点上的 Pod。
// 事实 2：每个节点在其抢占周期期间在“preFilterState”的单独副本上进行评估。如果我们计划转向更复杂的算法，例如“多个节点上的任意pod”时则需要重新考虑这种结构。
// https://blog.csdn.net/JavaShark/article/details/126055770
// dfy: 此处定义是，criticalPaths 是具有 2 个 struct 的数组， struct 定义如下
type criticalPaths [2]struct {
	// TopologyValue denotes the topology value mapping to topology key.
	// dfy: 匹配 topology key 的对应的  topology value
	TopologyValue string
	// dfy: 匹配 Pod 的数量，理解为具有相同  topology value 的 pod 数量
	// MatchNum denotes the number of matching pods.
	MatchNum int32
}

func newCriticalPaths() *criticalPaths {
	return &criticalPaths{{MatchNum: math.MaxInt32}, {MatchNum: math.MaxInt32}}
}

func (p *criticalPaths) update(tpVal string, num int32) {
	// first verify if `tpVal` exists or not
	i := -1
	if tpVal == p[0].TopologyValue {
		i = 0
	} else if tpVal == p[1].TopologyValue {
		i = 1
	}

	if i >= 0 {
		// `tpVal` exists
		// dfy: tpVal 存在时，进行更新
		p[i].MatchNum = num
		if p[0].MatchNum > p[1].MatchNum {
			// swap paths[0] and paths[1]
			p[0], p[1] = p[1], p[0]
		}
	} else {
		// `tpVal` doesn't exist
		// dfy: tpVal 不存在时，可以理解为初始化
		// p[0] 记录的 MatchNum 永远是小于  p[1] 记录的 MatchNum
		if num < p[0].MatchNum {
			// update paths[1] with paths[0]
			p[1] = p[0]
			// update paths[0]
			p[0].TopologyValue, p[0].MatchNum = tpVal, num
		} else if num < p[1].MatchNum {
			// update paths[1]
			p[1].TopologyValue, p[1].MatchNum = tpVal, num
		}
	}
}

func (s *preFilterState) updateWithPod(updatedPod, preemptorPod *v1.Pod, node *v1.Node, delta int32) {
	if s == nil || updatedPod.Namespace != preemptorPod.Namespace || node == nil {
		return
	}
	// dfy: 该 Node 是否具有 constraints 规定的所有 topologyKey,若不具有某个 key，直接返回
	if !nodeLabelsMatchSpreadConstraints(node.Labels, s.Constraints) {
		return
	}

	// dfy: 获取该 Pod 的 label
	podLabelSet := labels.Set(updatedPod.Labels)
	for _, constraint := range s.Constraints {
		// dfy: 该 constraints 不适用于 此 Pod，跳过
		if !constraint.Selector.Matches(podLabelSet) {
			continue
		}

		// dfy: 更新该 Node 对应的 topologyPair 匹配的 Pod 数
		k, v := constraint.TopologyKey, node.Labels[constraint.TopologyKey]
		pair := topologyPair{key: k, value: v}
		*s.TpPairToMatchNum[pair] += delta

		// dfy: 更新该 topologyKey 所有 topologyValue 中 匹配 Pod 的是最小值的 topologyValue
		s.TpKeyToCriticalPaths[k].update(v, *s.TpPairToMatchNum[pair])
	}
}

// PreFilter invoked at the prefilter extension point.
func (pl *PodTopologySpread) PreFilter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod) *framework.Status {
	// dfy: 此处只考虑策略为 DoNotSchedule 的 constraints
	// dfy: 此处计算满足 PodTopologySpread 约束的情况，符合要求的 Node 上有多少个 Pod
	s, err := pl.calPreFilterState(pod)
	if err != nil {
		return framework.NewStatus(framework.Error, err.Error())
	}
	// dfy: 写入到公共结构体中，用于传输，可以理解 cycleState 为全局变量
	// s 参数就是返回的梳理后的数据关系
	cycleState.Write(preFilterStateKey, s)
	return nil
}

// PreFilterExtensions returns prefilter extensions, pod add and remove.
func (pl *PodTopologySpread) PreFilterExtensions() framework.PreFilterExtensions {
	return pl
}

// AddPod from pre-computed data in cycleState.
// dfy: 这个函数，一般是用于抢占 Pod，更新 PreFilter 梳理的信息
func (pl *PodTopologySpread) AddPod(ctx context.Context, cycleState *framework.CycleState, podToSchedule *v1.Pod, podToAdd *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	s, err := getPreFilterState(cycleState)
	if err != nil {
		return framework.NewStatus(framework.Error, err.Error())
	}

	s.updateWithPod(podToAdd, podToSchedule, nodeInfo.Node(), 1)
	return nil
}

// RemovePod from pre-computed data in cycleState.
// dfy: 这个函数，一般是用于抢占 Pod，更新 PreFilter 梳理的信息
func (pl *PodTopologySpread) RemovePod(ctx context.Context, cycleState *framework.CycleState, podToSchedule *v1.Pod, podToRemove *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	s, err := getPreFilterState(cycleState)
	if err != nil {
		return framework.NewStatus(framework.Error, err.Error())
	}

	s.updateWithPod(podToRemove, podToSchedule, nodeInfo.Node(), -1)
	return nil
}

// getPreFilterState fetches a pre-computed preFilterState.
func getPreFilterState(cycleState *framework.CycleState) (*preFilterState, error) {
	c, err := cycleState.Read(preFilterStateKey)
	if err != nil {
		// preFilterState doesn't exist, likely PreFilter wasn't invoked.
		return nil, fmt.Errorf("error reading %q from cycleState: %v", preFilterStateKey, err)
	}

	s, ok := c.(*preFilterState)
	if !ok {
		return nil, fmt.Errorf("%+v convert to podtopologyspread.preFilterState error", c)
	}
	return s, nil
}

// calPreFilterState computes preFilterState describing how pods are spread on topologies.
// dfy: 计算 pod 的拓扑分布，记录到 preFilterState 中
func (pl *PodTopologySpread) calPreFilterState(pod *v1.Pod) (*preFilterState, error) {
	allNodes, err := pl.sharedLister.NodeInfos().List()
	if err != nil {
		return nil, fmt.Errorf("listing NodeInfos: %v", err)
	}
	var constraints []topologySpreadConstraint
	// dfy: 1. 有配置 拓扑约束条件，筛选 DoNotSchedule 的约束
	if len(pod.Spec.TopologySpreadConstraints) > 0 {
		// We have feature gating in APIServer to strip the spec
		// so don't need to re-check feature gate, just check length of Constraints.
		// dfy: 记录配置 动作为 DoNotSchedule（不满足条件不调度）的 约束条件 constraints
		constraints, err = filterTopologySpreadConstraints(pod.Spec.TopologySpreadConstraints, v1.DoNotSchedule)
		if err != nil {
			return nil, fmt.Errorf("obtaining pod's hard topology spread constraints: %v", err)
		}
	} else {
		// dfy: 2. 没有配置 拓扑约束条件，采用默认配置的 拓扑约束，筛选 DoNotSchedule 的约束
		constraints, err = pl.defaultConstraints(pod, v1.DoNotSchedule)
		if err != nil {
			return nil, fmt.Errorf("setting default hard topology spread constraints: %v", err)
		}
	}
	// dfy: 3. 没有配置且没有默认拓扑约束条件，直接返回 preFilterState
	if len(constraints) == 0 {
		return &preFilterState{}, nil
	}

	s := preFilterState{
		Constraints: constraints,
		// dfy: 该 map 长度，为 len(constraints) 的大小，目前不太清楚作用
		// dfy: key: 为 constraints 中的 topologyKey，value 为 criticalPaths 数组，可记录两个struct
		// dfy: 该 constraints 在该集群不同 topologyValue Selector 匹配上的 Pod，
		// dfy: 这两个 struct 记录最少匹配 Pod 数及对应的 topologyValue，和第二少匹配 Pod 数及对应的 topologyValue
		// dfy:
		//  简单来说
		//  因为 Pod 是一个一个调度的，假如我们要部署 6 个Pod，均匀分配到 3 个 node 上，那么这 6 个 Pod 要具有一个相同的 label
		//  用于被 constraints 具有个 Selector 选中，同时要具有 topologyKey 为 kubernetes.io/hostname，拓扑为 node，实现均匀分布
		//  调度第一个 Pod 的时候，Selector 在各个 node 上匹配的 Pod 数可能都为 0，此处 criticalPaths 记录数据可能为  { topologyValue: node1, MatchNum: 0}  { topologyValue: node2, MatchNum: 0}
		//  若调度第五个 Pod 的时候， Pod 的分布可能为 2 2 1，此处 criticalPaths 记录数据可能为  { topologyValue: node3, MatchNum: 1}  { topologyValue: node1, MatchNum: 2}
		TpKeyToCriticalPaths: make(map[string]*criticalPaths, len(constraints)),
		// dfy: 若 contraints 具有 "kubernetes.io/hostname" key，则创建 map 大小为 len(allNodes)
		// dfy: 此处只是创建个最基础的 map，若具有 "kubernetes.io/hostname" key，则创建 map 大小为 len(allNodes)；没有，就为 0
		// dfy: 此处记录 topologyPair{ constraints.topologyKey,topologyValue} 在集群内 Selector 匹配的 Pod 数量，如 {key: kubernetes.io/hostname,value: node1}: 2
		TpPairToMatchNum: make(map[topologyPair]*int32, sizeHeuristic(len(allNodes), constraints)),
	}
	for _, n := range allNodes {
		node := n.Node()
		if node == nil {
			klog.Error("node not found")
			continue
		}
		// In accordance to design, if NodeAffinity or NodeSelector is defined,
		// spreading is applied to nodes that pass those filters.
		// dfy：判断该 node 是否符合 pod 定义的 NodeSelector 和 Node 亲和性，不满足，就跳过此次判断
		if !helper.PodMatchesNodeSelectorAndAffinityTerms(pod, node) {
			continue
		}
		// Ensure current node's labels contains all topologyKeys in 'Constraints'.
		// dfy: 确定该 node 具有 constraints 规定的 topologyKeys
		if !nodeLabelsMatchSpreadConstraints(node.Labels, constraints) {
			continue
		}
		// dfy: 此处 TpPairToMatchNum map 可能会超过上面定义的  len(allNodes)，不过没关系，map 直接添加就好，会自动扩容
		// dfy: 假如有 2 个 constraints （zone 和 kubernetes.io/hostname），同时所有节点都有这两个 topologyKey，namespace此处 TpPairToMatchNum 长度最大就有可能是 2*len(allNodes)
		// dfy: 可以理解为根据 constraints 的 TopologyKey，和 node 对应的 TopologyValue，可以组成多少个键值对
		for _, c := range constraints {
			pair := topologyPair{key: c.TopologyKey, value: node.Labels[c.TopologyKey]}
			s.TpPairToMatchNum[pair] = new(int32)
		}
	}

	processNode := func(i int) {
		nodeInfo := allNodes[i]
		node := nodeInfo.Node()

		for _, constraint := range constraints {
			// dfy: constraint.TopologyKey 和 当前node 对应的 TopologyValue
			pair := topologyPair{key: constraint.TopologyKey, value: node.Labels[constraint.TopologyKey]}
			tpCount := s.TpPairToMatchNum[pair]
			if tpCount == nil {
				continue
			}
			// dfy: 统计该 constraints 对应的 Selector ，匹配到当前 node 上与此 pod 同 namespace 下的 Pod 的数量
			count := countPodsMatchSelector(nodeInfo.Pods, constraint.Selector, pod.Namespace)
			// dfy: 将其累加到对应的 TpPair
			atomic.AddInt32(tpCount, int32(count))
		}
	}
	// dfy: 统计所有 Node，最后会形成 TpPairToMatchNum 的 key 为 TpPair，value 为该 TpPair 在整个集群内的 Pod 数
	parallelize.Until(context.Background(), len(allNodes), processNode)

	// calculate min match for each topology pair
	// dfy: 计算每个 topology pair 的最小匹配数量
	for i := 0; i < len(constraints); i++ {
		key := constraints[i].TopologyKey
		s.TpKeyToCriticalPaths[key] = newCriticalPaths()
	}
	// dfy： 更新，记录每种 topologyKey ，匹配最少 Pod 的 topologyValue，和第二少 Pod 的 topologyValue，存储在 TpKeyToCriticalPaths[pair.key].criticalPaths 数组中
	for pair, num := range s.TpPairToMatchNum {
		s.TpKeyToCriticalPaths[pair.key].update(pair.value, *num)
	}

	return &s, nil
}

// Filter invoked at the filter extension point.
func (pl *PodTopologySpread) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	// dfy: 获取当前 node 信息
	node := nodeInfo.Node()
	if node == nil {
		return framework.NewStatus(framework.Error, "node not found")
	}

	// dfy: 获取 Prefilter 梳理的信息
	s, err := getPreFilterState(cycleState)
	if err != nil {
		return framework.NewStatus(framework.Error, err.Error())
	}

	// However, "empty" preFilterState is legit which tolerates every toSchedule Pod.
	if len(s.Constraints) == 0 {
		return nil
	}

	// dfy: 获取 Pod 的 Labels
	podLabelSet := labels.Set(pod.Labels)
	for _, c := range s.Constraints {
		tpKey := c.TopologyKey
		// dfy: 当前 Node 对应的 topologyValue
		tpVal, ok := node.Labels[c.TopologyKey]
		if !ok {
			klog.V(5).Infof("node '%s' doesn't have required label '%s'", node.Name, tpKey)
			// dfy: 此 Node 没有通过该 Filter 的筛选，返回错误及原因
			return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReasonNodeLabelNotMatch)
		}

		selfMatchNum := int32(0)
		// dfy: 当前 Pod 是否匹配 constraints 的 Selector
		if c.Selector.Matches(podLabelSet) {
			selfMatchNum = 1
		}

		pair := topologyPair{key: tpKey, value: tpVal}
		paths, ok := s.TpKeyToCriticalPaths[tpKey]
		if !ok {
			// error which should not happen
			klog.Errorf("internal error: get paths from key %q of %#v", tpKey, s.TpKeyToCriticalPaths)
			continue
		}
		// judging criteria:
		// 'existing matching num' + 'if self-match (1 or 0)' - 'global min matching num' <= 'maxSkew'
		// dfy: 当前 topologyKey 对应所有 topologyValue 中，目前最少匹配 Pod 数
		minMatchNum := paths[0].MatchNum
		matchNum := int32(0)
		// dfy: tpCount 表示当前 Node 对应的 topologyValue 匹配的 Pod 数（符合 constraints selector）
		if tpCount := s.TpPairToMatchNum[pair]; tpCount != nil {
			matchNum = *tpCount
		}
		// dfy: 考虑将当前 Pod 放在当前 Node 上，是否符合 倾斜度的要求
		skew := matchNum + selfMatchNum - minMatchNum
		// dfy: 不满足倾斜度要求，说明当前 Pod 不能符合此 constraints，不能调度到当前 Node 上
		if skew > c.MaxSkew {
			// dfy: 此 Node 没有通过该 Filter 的筛选，返回错误及原因
			klog.V(5).Infof("node '%s' failed spreadConstraint[%s]: MatchNum(%d) + selfMatchNum(%d) - minMatchNum(%d) > maxSkew(%d)", node.Name, tpKey, matchNum, selfMatchNum, minMatchNum, c.MaxSkew)
			return framework.NewStatus(framework.Unschedulable, ErrReasonConstraintsNotMatch)
		}
	}

	// dfy: 此 Node 通过 Filter 的筛选，什么都没返回
	return nil
}

func sizeHeuristic(nodes int, constraints []topologySpreadConstraint) int {
	for _, c := range constraints {
		if c.TopologyKey == v1.LabelHostname {
			return nodes
		}
	}
	return 0
}
