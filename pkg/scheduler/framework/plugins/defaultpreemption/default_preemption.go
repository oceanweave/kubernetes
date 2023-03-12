/*
Copyright 2020 The Kubernetes Authors.

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

package defaultpreemption

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	policy "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	policylisters "k8s.io/client-go/listers/policy/v1beta1"
	extenderv1 "k8s.io/kube-scheduler/extender/v1"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/scheduler/core"
	framework "k8s.io/kubernetes/pkg/scheduler/framework/v1alpha1"
	"k8s.io/kubernetes/pkg/scheduler/internal/parallelize"
	"k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/kubernetes/pkg/scheduler/util"
)

const (
	// Name of the plugin used in the plugin registry and configurations.
	Name = "DefaultPreemption"
)

// DefaultPreemption is a PostFilter plugin implements the preemption logic.
type DefaultPreemption struct {
	fh        framework.FrameworkHandle
	pdbLister policylisters.PodDisruptionBudgetLister
}

var _ framework.PostFilterPlugin = &DefaultPreemption{}

// Name returns name of the plugin. It is used in logs, etc.
func (pl *DefaultPreemption) Name() string {
	return Name
}

// New initializes a new plugin and returns it.
func New(_ runtime.Object, fh framework.FrameworkHandle) (framework.Plugin, error) {
	pl := DefaultPreemption{
		fh:        fh,
		pdbLister: getPDBLister(fh.SharedInformerFactory()),
	}
	return &pl, nil
}

// PostFilter invoked at the postFilter extension point.
func (pl *DefaultPreemption) PostFilter(ctx context.Context, state *framework.CycleState, pod *v1.Pod, m framework.NodeToStatusMap) (*framework.PostFilterResult, *framework.Status) {
	preemptionStartTime := time.Now()
	defer func() {
		metrics.PreemptionAttempts.Inc()
		metrics.SchedulingAlgorithmPreemptionEvaluationDuration.Observe(metrics.SinceInSeconds(preemptionStartTime))
		metrics.DeprecatedSchedulingDuration.WithLabelValues(metrics.PreemptionEvaluation).Observe(metrics.SinceInSeconds(preemptionStartTime))
	}()

	// dfy: 抢占逻辑  此处是主要内容  要重点看
	nnn, err := pl.preempt(ctx, state, pod, m)
	if err != nil {
		return nil, framework.NewStatus(framework.Error, err.Error())
	}
	if nnn == "" {
		return nil, framework.NewStatus(framework.Unschedulable)
	}
	return &framework.PostFilterResult{NominatedNodeName: nnn}, framework.NewStatus(framework.Success)
}

// preempt finds nodes with pods that can be preempted to make room for "pod" to
// schedule. It chooses one of the nodes and preempts the pods on the node and
// returns 1) the node name which is picked up for preemption, 2) any possible error.
// preempt does not update its snapshot. It uses the same snapshot used in the
// scheduling cycle. This is to avoid a scenario where preempt finds feasible
// nodes without preempting any pod. When there are many pending pods in the
// scheduling queue a nominated pod will go back to the queue and behind
// other pods with the same priority. The nominated pod prevents other pods from
// using the nominated resources and the nominated pod could take a long time
// before it is retried after many other pending pods.
func (pl *DefaultPreemption) preempt(ctx context.Context, state *framework.CycleState, pod *v1.Pod, m framework.NodeToStatusMap) (string, error) {
	cs := pl.fh.ClientSet()
	ph := pl.fh.PreemptHandle()
	nodeLister := pl.fh.SnapshotSharedLister().NodeInfos()

	// 0) Fetch the latest version of <pod>.
	// TODO(Huang-Wei): get pod from informer cache instead of API server.
	pod, err := util.GetUpdatedPod(cs, pod)
	if err != nil {
		klog.Errorf("Error getting the updated preemptor pod object: %v", err)
		return "", err
	}

	// 1) Ensure the preemptor is eligible to preempt other pods.
	// dfy: 1. 确认抢占者有资格抢占其他 Pod
	// - 有提名 node，但 node 是不可调度或不可解析的，有资格进行再次抢占
	// - 有提名 node，但目前有小于当前 pod 优先级的 pod 正在停止，没资格抢占（可理解为有 pod 让位了，应该等其让位后再次判断）
	// - 没有提名 node，有资格进行再次抢占
	if !PodEligibleToPreemptOthers(pod, nodeLister, m[pod.Status.NominatedNodeName]) {
		klog.V(5).Infof("Pod %v/%v is not eligible for more preemption.", pod.Namespace, pod.Name)
		return "", nil
	}

	// 2) Find all preemption candidates.
	// dfy: 2. 找到所有抢占候选人（就是原先不满足调度的 node，通过驱逐 pod 可以满足调度要求的 node）
	// a. 之前未通过 predicate 预选的 node，只要不是 node 不可解析等错误，就记为潜在选择 potentialNodes
	// b. 遍历这些 Node，判断通过驱逐低优先级 Pod，通过模拟调度判断是否可以调度新 Pod，可以的话，将此 Node 作为候选人 Candidate
	//    （被驱逐的 PDB Pod 记在 Candidate 的 Victims 中，此处 PDB Pod 指代业务容器要求最少运行的 Pod）
	// - 以下都是模拟调度逻辑
	// - 首先将低于新 Pod 的所有低优先级 Pod 进行驱逐，之后通过 PreFilterExtensions 更新 Prefilter 统计的信息，之后经过所有 Filter 插件进行判断
	//   若通过 Filter，证明该 Node 可以作为 Candidate
	// - 接下来考虑，是否可以不将所有低优先级 Pod 都驱逐，因此就是在上面驱逐全部低优先级 Pod 的基础上，逐步添加低优先级 Pod
	//   - 首先添加 PDB 要求的 Pod（PDB是用户定义的，此处 PDB 规定该业务最多可以驱逐 Pod 数量，若超过该数量的此业务 Pod 不应该被驱逐.
	//   因此若被驱逐了，我们应该首要考虑进行恢复，所以此处应该首先添加被驱逐的 PDB 要求的 Pod），若该 Pod 无法调度回来，记作为受害者 Victims
	//   - 接下来，恢复非 PDB Pod（这部分 Pod 没有设置 PDB 安全保障），因此能恢复最好，不能恢复的话，由于没有 PDB，我们可以理解为是可以被驱逐的
	// - ps: 每尝试恢复一个驱逐的低优先级 Pod，都需要通过 PreFilterExtensions 更新 Prefilter 统计的信息，再经过所有 Filter 插件判断
	candidates, err := FindCandidates(ctx, cs, state, pod, m, ph, nodeLister, pl.pdbLister)
	if err != nil || len(candidates) == 0 {
		return "", err
	}

	// 3) Interact with registered Extenders to filter out some candidates if needed.
	// dfy: 3. 如果需要，与注册的 Extenders 交互来找出候选人（可选，该http extender 需要实现 ProcessPreemption 方法）
	// dfy: CallExtenders 通过 Extender 来选择可行的 feasible candidates, 我们只是使用支持抢占的 extender 俩检查 candidte
	// dfy： 不支持抢占的 extenders 可能或阻止 抢占器preemptor 调度到指定 node，在这种情况下，调度器将会在后续调度周期为 抢占器 preemptor 寻找一个其他的 host
	candidates, err = CallExtenders(ph.Extenders(), pod, nodeLister, candidates)
	if err != nil {
		return "", err
	}

	// 4) Find the best candidate.
	// dfy: 4. 找到最佳候选人
	// dfy: 总体原则就是：
	// a. 违反 PDB 数量最少
	// b. 上面相同，取 victims Pod 最高优先级最低的 node
	// c. 上面相同，取 victims Pod 优先级sum最低的 node
	// d. 上面相同，取 victims Pod 数量最少的 node
	// e. 上面相同，取 victims 最高优先级 Pod 中最早启动的 Pod，启动时间离目前最近的 Pod，所在的 node
	// f. 若仍相同，取经过上面 5 步筛选的第一个 node
	bestCandidate := SelectCandidate(candidates)
	if bestCandidate == nil || len(bestCandidate.Name()) == 0 {
		return "", nil
	}

	// 5) Perform preparation work before nominating the selected candidate.
	// dfy: 5. 在提名所选候选人之前进行准备工作。
	// dfy:
	// 1. 驱逐受害者 pod，真正的执行，之前是模拟
	// 2. 拒绝 waitingPod，也就是阻止该 Pod 调度，发送拒绝信息到 PermitPlugin，将其放回到待调度队列
	// 3. 清理低于当前调度 Pod 优先级的 nominated Pod，将其放回到 active queue 中，理解指定 Pod，就是指定了 Node，但还未运行
	if err := PrepareCandidate(bestCandidate, pl.fh, cs, pod); err != nil {
		return "", err
	}

	return bestCandidate.Name(), nil
}

// FindCandidates calculates a slice of preemption candidates.
// Each candidate is executable to make the given <pod> schedulable.
func FindCandidates(ctx context.Context, cs kubernetes.Interface, state *framework.CycleState, pod *v1.Pod,
	m framework.NodeToStatusMap, ph framework.PreemptHandle, nodeLister framework.NodeInfoLister,
	pdbLister policylisters.PodDisruptionBudgetLister) ([]Candidate, error) {
	allNodes, err := nodeLister.List()
	if err != nil {
		return nil, err
	}
	if len(allNodes) == 0 {
		return nil, core.ErrNoNodesAvailable
	}

	// dfy: 返回一些 node（未通过 predicate 预选），但是通过移除 pods 满足要求【新pod的调度需求】
	potentialNodes := nodesWherePreemptionMightHelp(allNodes, m)
	if len(potentialNodes) == 0 {
		klog.V(3).Infof("Preemption will not help schedule pod %v/%v on any node.", pod.Namespace, pod.Name)
		// In this case, we should clean-up any existing nominated node name of the pod.
		if err := util.ClearNominatedNodeName(cs, pod); err != nil {
			klog.Errorf("Cannot clear 'NominatedNodeName' field of pod %v/%v: %v", pod.Namespace, pod.Name, err)
			// We do not return as this error is not critical.
		}
		return nil, nil
	}
	if klog.V(5).Enabled() {
		var sample []string
		for i := 0; i < 10 && i < len(potentialNodes); i++ {
			sample = append(sample, potentialNodes[i].Node().Name)
		}
		klog.Infof("%v potential nodes for preemption, first %v are: %v", len(potentialNodes), len(sample), sample)
	}
	// dfy: 获取 pdb https://blog.csdn.net/weixin_43616190/article/details/126433485
	// dfy: pdb 是一种 k8s 资源，有用户创建，可定义一个服务最少运行副本数或最大可驱逐副本数，保证服务的最低运行能力
	pdbs, err := getPodDisruptionBudgets(pdbLister)
	if err != nil {
		return nil, err
	}
	// dfy：模拟驱逐进行调度
	return dryRunPreemption(ctx, ph, state, pod, potentialNodes, pdbs), nil
}

// PodEligibleToPreemptOthers determines whether this pod should be considered
// for preempting other pods or not. If this pod has already preempted other
// pods and those are in their graceful termination period, it shouldn't be
// considered for preemption.
// We look at the node that is nominated for this pod and as long as there are
// terminating pods on the node, we don't consider this for preempting more pods.
func PodEligibleToPreemptOthers(pod *v1.Pod, nodeInfos framework.NodeInfoLister, nominatedNodeStatus *framework.Status) bool {
	if pod.Spec.PreemptionPolicy != nil && *pod.Spec.PreemptionPolicy == v1.PreemptNever {
		klog.V(5).Infof("Pod %v/%v is not eligible for preemption because it has a preemptionPolicy of %v", pod.Namespace, pod.Name, v1.PreemptNever)
		return false
	}
	// dfy: 该 pod 记录的 提名node
	nomNodeName := pod.Status.NominatedNodeName
	if len(nomNodeName) > 0 {
		// If the pod's nominated node is considered as UnschedulableAndUnresolvable by the filters,
		// then the pod should be considered for preempting again.
		// dfy: 若该提名 node 的状态是 不可调度或不可解析，那么可以进行再次抢占
		if nominatedNodeStatus.Code() == framework.UnschedulableAndUnresolvable {
			return true
		}

		// dfy: 若该 node 上，有低于当前优先级的 pod 正在停止 terminating，那么无法再次抢占
		if nodeInfo, _ := nodeInfos.Get(nomNodeName); nodeInfo != nil {
			podPriority := podutil.GetPodPriority(pod)
			for _, p := range nodeInfo.Pods {
				if p.Pod.DeletionTimestamp != nil && podutil.GetPodPriority(p.Pod) < podPriority {
					// There is a terminating pod on the nominated node.
					return false
				}
			}
		}
	}
	// dfy: 若没有 提名node，表示可以进行抢占
	return true
}

// nodesWherePreemptionMightHelp returns a list of nodes with failed predicates
// that may be satisfied by removing pods from the node.
// dfy: 返回一些 node（未通过 predicate 预选），但是通过移除 pods 满足要求【新pod的调度需求】
func nodesWherePreemptionMightHelp(nodes []*framework.NodeInfo, m framework.NodeToStatusMap) []*framework.NodeInfo {
	var potentialNodes []*framework.NodeInfo
	for _, node := range nodes {
		name := node.Node().Name
		// We reply on the status by each plugin - 'Unschedulable' or 'UnschedulableAndUnresolvable'
		// to determine whether preemption may help or not on the node.
		if m[name].Code() == framework.UnschedulableAndUnresolvable {
			continue
		}
		potentialNodes = append(potentialNodes, node)
	}
	return potentialNodes
}

// dryRunPreemption simulates Preemption logic on <potentialNodes> in parallel,
// and returns all possible preemption candidates.
// dfy: 在 potentialNodes 上 模拟抢占，返回所有有可能的抢占候选者
func dryRunPreemption(ctx context.Context, fh framework.PreemptHandle, state *framework.CycleState,
	pod *v1.Pod, potentialNodes []*framework.NodeInfo, pdbs []*policy.PodDisruptionBudget) []Candidate {
	var resultLock sync.Mutex
	var candidates []Candidate

	checkNode := func(i int) {
		nodeInfoCopy := potentialNodes[i].Clone()
		stateCopy := state.Clone()
		// dfy: 此处是重点，挑选受害者
		pods, numPDBViolations, fits := selectVictimsOnNode(ctx, fh, stateCopy, pod, nodeInfoCopy, pdbs)
		if fits {
			resultLock.Lock()
			// dfy: 此处记录，若待调度 Pod 运行到该 node 上，有多少个 Pod 不应该被驱逐，或称这些不该被移除的 pod 为受害者 victims
			victims := extenderv1.Victims{
				Pods:             pods,
				NumPDBViolations: int64(numPDBViolations),
			}
			c := candidate{
				victims: &victims,
				name:    nodeInfoCopy.Node().Name,
			}
			candidates = append(candidates, &c)
			resultLock.Unlock()
		}
	}
	parallelize.Until(ctx, len(potentialNodes), checkNode)
	return candidates
}

// CallExtenders calls given <extenders> to select the list of feasible candidates.
// We will only check <candidates> with extenders that support preemption.
// Extenders which do not support preemption may later prevent preemptor from being scheduled on the nominated
// node. In that case, scheduler will find a different host for the preemptor in subsequent scheduling cycles.
// dfy: CallExtenders 通过 Extender 来选择可行的 feasible candidates, 我们只是使用支持抢占的 extender 俩检查 candidte
// dfy： 不支持抢占的 extenders 可能或阻止 抢占器preemptor 调度到指定 node，在这种情况下，调度器将会在后续调度周期为 抢占器 preemptor 寻找一个其他的 host
func CallExtenders(extenders []framework.Extender, pod *v1.Pod, nodeLister framework.NodeInfoLister,
	candidates []Candidate) ([]Candidate, error) {
	if len(extenders) == 0 {
		return candidates, nil
	}

	// Migrate candidate slice to victimsMap to adapt to the Extender interface.
	// It's only applicable for candidate slice that have unique nominated node name.
	victimsMap := candidatesToVictimsMap(candidates)
	if len(victimsMap) == 0 {
		return candidates, nil
	}
	for _, extender := range extenders {
		if !extender.SupportsPreemption() || !extender.IsInterested(pod) {
			continue
		}
		nodeNameToVictims, err := extender.ProcessPreemption(pod, victimsMap, nodeLister)
		if err != nil {
			if extender.IsIgnorable() {
				klog.Warningf("Skipping extender %v as it returned error %v and has ignorable flag set",
					extender, err)
				continue
			}
			return nil, err
		}
		// Replace victimsMap with new result after preemption. So the
		// rest of extenders can continue use it as parameter.
		victimsMap = nodeNameToVictims

		// If node list becomes empty, no preemption can happen regardless of other extenders.
		if len(victimsMap) == 0 {
			break
		}
	}

	var newCandidates []Candidate
	for nodeName := range victimsMap {
		newCandidates = append(newCandidates, &candidate{
			victims: victimsMap[nodeName],
			name:    nodeName,
		})
	}
	return newCandidates, nil
}

// This function is not applicable for out-of-tree preemption plugins that exercise
// different preemption candidates on the same nominated node.
func candidatesToVictimsMap(candidates []Candidate) map[string]*extenderv1.Victims {
	m := make(map[string]*extenderv1.Victims)
	for _, c := range candidates {
		m[c.Name()] = c.Victims()
	}
	return m
}

// SelectCandidate chooses the best-fit candidate from given <candidates> and return it.
func SelectCandidate(candidates []Candidate) Candidate {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		return candidates[0]
	}

	victimsMap := candidatesToVictimsMap(candidates)
	candidateNode := pickOneNodeForPreemption(victimsMap)

	// Same as candidatesToVictimsMap, this logic is not applicable for out-of-tree
	// preemption plugins that exercise different candidates on the same nominated node.
	for _, candidate := range candidates {
		if candidateNode == candidate.Name() {
			return candidate
		}
	}
	// We shouldn't reach here.
	klog.Errorf("None candidate can be picked from %v.", candidates)
	// To not break the whole flow, return the first candidate.
	return candidates[0]
}

// pickOneNodeForPreemption chooses one node among the given nodes. It assumes
// pods in each map entry are ordered by decreasing priority.
// It picks a node based on the following criteria:
// 1. A node with minimum number of PDB violations.
// 2. A node with minimum highest priority victim is picked.
// 3. Ties are broken by sum of priorities of all victims.
// 4. If there are still ties, node with the minimum number of victims is picked.
// 5. If there are still ties, node with the latest start time of all highest priority victims is picked.
// 6. If there are still ties, the first such node is picked (sort of randomly).
// The 'minNodes1' and 'minNodes2' are being reused here to save the memory
// allocation and garbage collection time.
// dfy: 挑选一个 node 遵循下面的规则，同时假设 pods 在每个 map 中都是优先级降序的排序港式
// 1. 最小的 PDB 违反数量
// 2. 受害者中最高优先级  最小的（一个node上可能有多个受害者，获取最高优先级，多个 node，有多个最高优先级，取其中最高优先级最小的 node，若仍有最小的相同，那继续判断）
// 3. 通过统计所有 victims 的优先级总和，打破 ties（上面最小最高优先级，仍有相同 node，统计 node 上 victims 优先级总和，选择总和最小的）
// 4. 如果仍有 ties，选择最少受害者的 node （ 上面仍相同，选择 victims pod 数最少得 node）
// 5. 如果仍有 ties，选择具有所有最高优先级受害者刚开始的 node （ 上面仍相同，统计 每个node最高优先级pod 最早start time，之后选择离现在最近的 pod 所在的 node）
// 6. 如果仍有 ties，挑选第一个 node（经过上面 5 步骤筛选的 第一个node）
// 'minNodes1' and 'minNodes2' 被重复使用，来节省内存分配和垃圾回收时间
func pickOneNodeForPreemption(nodesToVictims map[string]*extenderv1.Victims) string {
	if len(nodesToVictims) == 0 {
		return ""
	}
	minNumPDBViolatingPods := int64(math.MaxInt32)
	var minNodes1 []string
	lenNodes1 := 0
	for node, victims := range nodesToVictims {
		numPDBViolatingPods := victims.NumPDBViolations
		if numPDBViolatingPods < minNumPDBViolatingPods {
			minNumPDBViolatingPods = numPDBViolatingPods
			minNodes1 = nil
			lenNodes1 = 0
		}
		// dfy: minNodes1 记录与最小值 minNumPDBViolatingPods 相等的信息
		if numPDBViolatingPods == minNumPDBViolatingPods {
			minNodes1 = append(minNodes1, node)
			lenNodes1++
		}
	}
	// dfy: 只有一个最小值，直接进行返回
	if lenNodes1 == 1 {
		return minNodes1[0]
	}

	// There are more than one node with minimum number PDB violating pods. Find
	// the one with minimum highest priority victim.
	// dfy: 有多个最小值，选择受害者最高优先级 最小的
	minHighestPriority := int32(math.MaxInt32)
	var minNodes2 = make([]string, lenNodes1)
	lenNodes2 := 0
	for i := 0; i < lenNodes1; i++ {
		node := minNodes1[i]
		victims := nodesToVictims[node]
		// highestPodPriority is the highest priority among the victims on this node.
		// dfy: victims 已经是排好序的数组，降序，因此第一个 pod 优先级最高
		highestPodPriority := podutil.GetPodPriority(victims.Pods[0])
		if highestPodPriority < minHighestPriority {
			minHighestPriority = highestPodPriority
			lenNodes2 = 0
		}
		// dfy: minNodes2 记录最小最高优先级 想同 的 node
		if highestPodPriority == minHighestPriority {
			minNodes2[lenNodes2] = node
			lenNodes2++
		}
	}
	// dfy: 若只有一个 便直接返回
	if lenNodes2 == 1 {
		return minNodes2[0]
	}

	// There are a few nodes with minimum highest priority victim. Find the
	// smallest sum of priorities.
	// dfy: 最小最高优先级相同的 node，统计 node 上 victims 的优先级总和，若仍有相同的，记录到 minNodes1 中，继续比较
	minSumPriorities := int64(math.MaxInt64)
	lenNodes1 = 0
	for i := 0; i < lenNodes2; i++ {
		var sumPriorities int64
		node := minNodes2[i]
		for _, pod := range nodesToVictims[node].Pods {
			// We add MaxInt32+1 to all priorities to make all of them >= 0. This is
			// needed so that a node with a few pods with negative priority is not
			// picked over a node with a smaller number of pods with the same negative
			// priority (and similar scenarios).
			sumPriorities += int64(podutil.GetPodPriority(pod)) + int64(math.MaxInt32+1)
		}
		if sumPriorities < minSumPriorities {
			minSumPriorities = sumPriorities
			lenNodes1 = 0
		}
		if sumPriorities == minSumPriorities {
			minNodes1[lenNodes1] = node
			lenNodes1++
		}
	}
	if lenNodes1 == 1 {
		return minNodes1[0]
	}

	// There are a few nodes with minimum highest priority victim and sum of priorities.
	// Find one with the minimum number of pods.
	// dfy: 若最小最高优先级 以及 总和 都相同，就比较 pod 数量，选择数量少的
	minNumPods := math.MaxInt32
	lenNodes2 = 0
	for i := 0; i < lenNodes1; i++ {
		node := minNodes1[i]
		numPods := len(nodesToVictims[node].Pods)
		if numPods < minNumPods {
			minNumPods = numPods
			lenNodes2 = 0
		}
		if numPods == minNumPods {
			minNodes2[lenNodes2] = node
			lenNodes2++
		}
	}
	if lenNodes2 == 1 {
		return minNodes2[0]
	}

	// dfy: 首先就是统计各个 node 上最高优先级 pod 中，启动最早的 pod，记录其时间为 earliestStartTimeOnNode
	// dfy: 接下来，选择其中离现在最近的 earliestStartTimeOnNode 的 Pod 所在的 Node
	// There are a few nodes with same number of pods.
	// Find the node that satisfies latest(earliestStartTime(all highest-priority pods on node))
	latestStartTime := util.GetEarliestPodStartTime(nodesToVictims[minNodes2[0]])
	if latestStartTime == nil {
		// If the earliest start time of all pods on the 1st node is nil, just return it,
		// which is not expected to happen.
		klog.Errorf("earliestStartTime is nil for node %s. Should not reach here.", minNodes2[0])
		return minNodes2[0]
	}
	nodeToReturn := minNodes2[0]
	for i := 1; i < lenNodes2; i++ {
		node := minNodes2[i]
		// Get earliest start time of all pods on the current node.
		// dfy: 获得 该 node 上所有 victims 中，最高优先级 pod 中 最早 start 的时间
		earliestStartTimeOnNode := util.GetEarliestPodStartTime(nodesToVictims[node])
		if earliestStartTimeOnNode == nil {
			klog.Errorf("earliestStartTime is nil for node %s. Should not reach here.", node)
			continue
		}
		// dfy: 在多个 node 的 earliestStartTimeOnNode 中，选择离现在时间最近的 node
		if earliestStartTimeOnNode.After(latestStartTime.Time) {
			latestStartTime = earliestStartTimeOnNode
			nodeToReturn = node
		}
	}

	// dfy: 上面扔相同，就返回经过筛选的第一个 node 了
	return nodeToReturn
}

// selectVictimsOnNode finds minimum set of pods on the given node that should
// be preempted in order to make enough room for "pod" to be scheduled. The
// minimum set selected is subject to the constraint that a higher-priority pod
// is never preempted when a lower-priority pod could be (higher/lower relative
// to one another, not relative to the preemptor "pod").
// The algorithm first checks if the pod can be scheduled on the node when all the
// lower priority pods are gone. If so, it sorts all the lower priority pods by
// their priority and then puts them into two groups of those whose PodDisruptionBudget
// will be violated if preempted and other non-violating pods. Both groups are
// sorted by priority. It first tries to reprieve as many PDB violating pods as
// possible and then does them same for non-PDB-violating pods while checking
// that the "pod" can still fit on the node.
// NOTE: This function assumes that it is never called if "pod" cannot be scheduled
// due to pod affinity, node affinity, or node anti-affinity reasons. None of
// these predicates can be satisfied by removing more pods from the node.
func selectVictimsOnNode(
	ctx context.Context,
	ph framework.PreemptHandle,
	state *framework.CycleState,
	pod *v1.Pod,
	nodeInfo *framework.NodeInfo,
	pdbs []*policy.PodDisruptionBudget,
) ([]*v1.Pod, int, bool) {
	var potentialVictims []*v1.Pod

	removePod := func(rp *v1.Pod) error {
		// dfy: 移除 Pod
		if err := nodeInfo.RemovePod(rp); err != nil {
			return err
		}
		// dfy: 更新 cyclestate 记录的 Prefilter 关系
		status := ph.RunPreFilterExtensionRemovePod(ctx, state, pod, rp, nodeInfo)
		if !status.IsSuccess() {
			return status.AsError()
		}
		return nil
	}
	addPod := func(ap *v1.Pod) error {
		// dfy: 新增 Pod
		nodeInfo.AddPod(ap)
		// dfy: 更新 cyclestate 记录的 Prefilter 关系
		status := ph.RunPreFilterExtensionAddPod(ctx, state, pod, ap, nodeInfo)
		if !status.IsSuccess() {
			return status.AsError()
		}
		return nil
	}
	// As the first step, remove all the lower priority pods from the node and
	// check if the given pod can be scheduled.
	podPriority := podutil.GetPodPriority(pod)
	// 总体逻辑1：首先移除所有优先级低于当前待调度 Pod 优先级的 所有 Pod，然后经过 Filter 判断该 node 是否合适
	for _, p := range nodeInfo.Pods {
		// dfy： 挑选优先级低于待调度 Pod 的 Pod，作为潜在受害者 potentialVictims
		if podutil.GetPodPriority(p.Pod) < podPriority {
			potentialVictims = append(potentialVictims, p.Pod)
			// dfy: 移除 Pod
			if err := removePod(p.Pod); err != nil {
				return nil, 0, false
			}
		}
	}

	// No potential victims are found, and so we don't need to evaluate the node again since its state didn't change.
	if len(potentialVictims) == 0 {
		return nil, 0, false
	}

	// If the new pod does not fit after removing all the lower priority pods,
	// we are almost done and this node is not suitable for preemption. The only
	// condition that we could check is if the "pod" is failing to schedule due to
	// inter-pod affinity to one or more victims, but we have decided not to
	// support this case for performance reasons. Having affinity to lower
	// priority pods is not a recommended configuration anyway.
	// dfy：若移除了所有的低优先级 Pod 仍不成功调度，说明该 node 是不适合记性抢占的
	// dfy: 关于不成功原因，我们唯一能检查的就是 新Pod 与受害者低优先级的 Pod 的亲和性因素，但出于性能原因，决定不支持这一点
	// dfy: 同时，与低优先级 Pod 亲和，也是不建议的 配置

	// dfy：进行 Filter 筛选
	if fits, _, err := core.PodPassesFiltersOnNode(ctx, ph, state, pod, nodeInfo); !fits {
		if err != nil {
			klog.Warningf("Encountered error while selecting victims on node %v: %v", nodeInfo.Node().Name, err)
		}

		return nil, 0, false
	}
	var victims []*v1.Pod
	numViolatingVictim := 0

	// dfy: 总体逻辑2：看是否可以低优先级 Pod 不全部移除？逐个 Pod 添加，尝试是否可以通过 Filter，首先是考虑 对违反PDB的受害者 中的 Pod，接下来是 nonViolatingVictims 中的 Pod
	// dfy: 进行排序，高优先级在前面，优先级相同，创建时间早的在前面
	sort.Slice(potentialVictims, func(i, j int) bool { return util.MoreImportantPod(potentialVictims[i], potentialVictims[j]) })
	// Try to reprieve as many pods as possible. We first try to reprieve the PDB
	// violating victims and then other non-violating ones. In both cases, we start
	// from the highest priority victims.
	// dfy: 尽可能多地暂缓执行。我们首先尝试对违反PDB的受害者进行缓刑，然后对其他非违反者进行缓刑。在这两种情况下，我们都从最高优先级的受害者开始。
	// dfy: PodDisruptionBudget是一个对象，用于定义可能对一组Pod造成的最大中断
	// https://blog.csdn.net/weixin_43616190/article/details/126433485
	// https://blog.csdn.net/qq_35745940/article/details/126805215
	// PDB 表示该类型业务，最少存在 pod 必须运行着或最多驱逐多少个pod，保障着即使被驱逐时，也不至于使该业务 Pod 完全消失，但是没有创建 PDB，该业务 Pod 可能就会完全被驱逐

	// dfy: 这两个切片中的 Pod 排序都是，优先级从高到低
	// dfy: violatingVictims 表示可以驱逐的 pod，nonViolatingVictims 表示不能驱逐的 pod

	// pdb.Status.DisruptionsAllowed 此处 pdb 采用最多可以有多少个 Pod 被驱逐，
	// 因此超过该数量的该业务 Pod 是不能被驱逐的，记为 violatingVictims
	// 若一个业务有 5 个 Pod，设置了 pdb DisruptionsAllowed 为 3，那么可以驱逐 3 个，那么 nonViolatingVictims 记录其中 3 个 pod，violatingVictims 记录剩余 2 个Pod
	violatingVictims, nonViolatingVictims := filterPodsWithPDBViolation(potentialVictims, pdbs)
	reprievePod := func(p *v1.Pod) (bool, error) {
		// dfy: 尝试添加此 Pod，看看是否可以通过 Filter
		if err := addPod(p); err != nil {
			return false, err
		}
		fits, _, _ := core.PodPassesFiltersOnNode(ctx, ph, state, pod, nodeInfo)
		// dfy: 若不能通过 Filter，再移除此 Pod
		if !fits {
			if err := removePod(p); err != nil {
				return false, err
			}
			// dfy: 无法调度成功的 Pod，记为受害则，添加到 victims 切片中
			victims = append(victims, p)
			klog.V(5).Infof("Pod %v/%v is a potential preemption victim on node %v.", p.Namespace, p.Name, nodeInfo.Node().Name)
		}
		return fits, nil
	}

	for _, p := range violatingVictims {
		if fits, err := reprievePod(p); err != nil {
			klog.Warningf("Failed to reprieve pod %q: %v", p.Name, err)
			return nil, 0, false
		} else if !fits {
			// dfy: ！fits  表示添加失败，要被驱逐
			// dfy: 此数量记录不能拿被驱逐的 Pod 的数量
			numViolatingVictim++
		}
	}
	// Now we try to reprieve non-violating victims.
	for _, p := range nonViolatingVictims {
		// dfy：对于没有 PDB 保护的 Pod，若调度不成功，也是要移除的，假如到 victims 中
		if _, err := reprievePod(p); err != nil {
			klog.Warningf("Failed to reprieve pod %q: %v", p.Name, err)
			return nil, 0, false
		}
	}
	// dfy:
	// victims Pod = 有 PDB 保护要驱逐的 Pod + 没有 PDB 保护要驱逐的 Pod
	// numViolatingVictim = 在 PDB 保护下，仍要驱逐的 Pod（就是违反 PDB 要驱逐的 Pod 数量）
	return victims, numViolatingVictim, true
}

// PrepareCandidate does some preparation work before nominating the selected candidate:
// - Evict the victim pods
// - Reject the victim pods if they are in waitingPod map
// - Clear the low-priority pods' nominatedNodeName status if needed
// dfy:
// 1. 驱逐受害者 pod，真正的执行，之前是模拟
// 2. 拒绝 waitingPod，也就是阻止该 Pod 调度，发送拒绝信息到 PermitPlugin，将其放回到待调度队列
// 3. 清理低于当前调度 Pod 优先级的 nominated Pod，将其放回到 active queue 中，理解指定 Pod，就是指定了 Node，但还未运行
func PrepareCandidate(c Candidate, fh framework.FrameworkHandle, cs kubernetes.Interface, pod *v1.Pod) error {
	for _, victim := range c.Victims().Pods {
		// dfy: 此处是真正驱逐 victims Pod，之前是模拟
		if err := util.DeletePod(cs, victim); err != nil {
			klog.Errorf("Error preempting pod %v/%v: %v", victim.Namespace, victim.Name, err)
			return err
		}
		// If the victim is a WaitingPod, send a reject message to the PermitPlugin
		// dfy: 若其中 victim pod 是 waiting，发送一个拒绝信息到 PermitPlugin（阻止该 Pod 调度，放回到待调度队列中）
		if waitingPod := fh.GetWaitingPod(victim.UID); waitingPod != nil {
			waitingPod.Reject("preempted")
		}
		fh.EventRecorder().Eventf(victim, pod, v1.EventTypeNormal, "Preempted", "Preempting", "Preempted by %v/%v on node %v",
			pod.Namespace, pod.Name, c.Name())
	}
	metrics.PreemptionVictims.Observe(float64(len(c.Victims().Pods)))

	// Lower priority pods nominated to run on this node, may no longer fit on
	// this node. So, we should remove their nomination. Removing their
	// nomination updates these pods and moves them to the active queue. It
	// lets scheduler find another place for them.
	// dfy: 获取指定到该 node 上的 Pod，进行清理（此处理解为，这些指定 Pod 还未真正在该 node 上执行，只是指定到了过来)
	// dfy: 之后会将这些指定 pod, 放入到 active queue 中，调度器将会为他们寻找一个更合适的去处
	nominatedPods := getLowerPriorityNominatedPods(fh.PreemptHandle(), pod, c.Name())
	if err := util.ClearNominatedNodeName(cs, nominatedPods...); err != nil {
		klog.Errorf("Cannot clear 'NominatedNodeName' field: %v", err)
		// We do not return as this error is not critical.
	}

	return nil
}

// getLowerPriorityNominatedPods returns pods whose priority is smaller than the
// priority of the given "pod" and are nominated to run on the given node.
// Note: We could possibly check if the nominated lower priority pods still fit
// and return those that no longer fit, but that would require lots of
// manipulation of NodeInfo and PreFilter state per nominated pod. It may not be
// worth the complexity, especially because we generally expect to have a very
// small number of nominated pods per node.
func getLowerPriorityNominatedPods(pn framework.PodNominator, pod *v1.Pod, nodeName string) []*v1.Pod {
	pods := pn.NominatedPodsForNode(nodeName)

	if len(pods) == 0 {
		return nil
	}

	var lowerPriorityPods []*v1.Pod
	podPriority := podutil.GetPodPriority(pod)
	for _, p := range pods {
		if podutil.GetPodPriority(p) < podPriority {
			lowerPriorityPods = append(lowerPriorityPods, p)
		}
	}
	return lowerPriorityPods
}

// filterPodsWithPDBViolation groups the given "pods" into two groups of "violatingPods"
// and "nonViolatingPods" based on whether their PDBs will be violated if they are
// preempted.
// This function is stable and does not change the order of received pods. So, if it
// receives a sorted list, grouping will preserve the order of the input list.
// dfy: PodDisruptionBudget是一个对象，用于定义可能对一组Pod造成的最大中断
// dfy: PodDisruptionBudget 具有 label，表示最多可以中断多少个符合 此 label  的 Pod
func filterPodsWithPDBViolation(pods []*v1.Pod, pdbs []*policy.PodDisruptionBudget) (violatingPods, nonViolatingPods []*v1.Pod) {
	pdbsAllowed := make([]int32, len(pdbs))
	// dfy: 每个 pdb 规定了，该业务最多中断的副本数，也就是该业务可以驱逐的 pod 数量
	for i, pdb := range pdbs {
		pdbsAllowed[i] = pdb.Status.DisruptionsAllowed
	}

	// dfy: pods 中的 Pod 是高优先级到低优先级
	for _, obj := range pods {
		pod := obj
		pdbForPodIsViolated := false
		// A pod with no labels will not match any PDB. So, no need to check.
		// dfy: 若 Pod 没有 labels，将不会匹配任何 PDB，所以不需要检查
		if len(pod.Labels) != 0 {
			for i, pdb := range pdbs {
				if pdb.Namespace != pod.Namespace {
					continue
				}
				// dfy: pdb  selector
				selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
				if err != nil {
					continue
				}
				// A PDB with a nil or empty selector matches nothing.
				// dfy: pdb  selector 为空，或 Pod label 没有 匹配上，就跳过此pdb
				if selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
					continue
				}

				// Existing in DisruptedPods means it has been processed in API server,
				// we don't treat it as a violating case.
				// dfy: pdb status 中有此 pod，表示处理过该 pod 了
				if _, exist := pdb.Status.DisruptedPods[pod.Name]; exist {
					continue
				}
				// Only decrement the matched pdb when it's not in its <DisruptedPods>;
				// otherwise we may over-decrement the budget number.
				// dfy: 执行到此，表示可以中断此 pod，因此 pdb -1
				pdbsAllowed[i]--
				// We have found a matching PDB.
				if pdbsAllowed[i] < 0 {
					pdbForPodIsViolated = true
				}
			}
		}
		// dfy: 这两个切片中的 Pod 排序都是，优先级从高到低
		if pdbForPodIsViolated {
			violatingPods = append(violatingPods, pod)
		} else {
			nonViolatingPods = append(nonViolatingPods, pod)
		}
	}
	return violatingPods, nonViolatingPods
}

func getPDBLister(informerFactory informers.SharedInformerFactory) policylisters.PodDisruptionBudgetLister {
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.PodDisruptionBudget) {
		return informerFactory.Policy().V1beta1().PodDisruptionBudgets().Lister()
	}
	return nil
}

func getPodDisruptionBudgets(pdbLister policylisters.PodDisruptionBudgetLister) ([]*policy.PodDisruptionBudget, error) {
	if pdbLister != nil {
		return pdbLister.List(labels.Everything())
	}
	return nil, nil
}
