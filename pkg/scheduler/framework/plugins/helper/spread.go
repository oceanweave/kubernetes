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

package helper

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	appslisters "k8s.io/client-go/listers/apps/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
)

// DefaultSelector returns a selector deduced from the Services, Replication
// Controllers, Replica Sets, and Stateful Sets matching the given pod.
// dfy: DefaultSelector 返回在该 pod namespace 下，匹配该 Pod 的 service、rc控制器、rs 控制器和 statefulset 的标签选择器 Selector
func DefaultSelector(pod *v1.Pod, sl corelisters.ServiceLister, cl corelisters.ReplicationControllerLister, rsl appslisters.ReplicaSetLister, ssl appslisters.StatefulSetLister) labels.Selector {
	labelSet := make(labels.Set)
	// Since services, RCs, RSs and SSs match the pod, they won't have conflicting
	// labels. Merging is safe.

	// dfy: 获取该 pod 所在 namespace 下，匹配该 pod 的所有 service，将这些 service 的 selector 汇总，记录到 labelSet
	if services, err := GetPodServices(sl, pod); err == nil {
		for _, service := range services {
			labelSet = labels.Merge(labelSet, service.Spec.Selector)
		}
	}

	// dfy: 获取该 pod 所在 namespace 下，匹配该 pod 的所有 rcController ，将这些 rcController 的 selector 汇总，记录到 labelSet
	if rcs, err := cl.GetPodControllers(pod); err == nil {
		for _, rc := range rcs {
			labelSet = labels.Merge(labelSet, rc.Spec.Selector)
		}
	}

	// dfy: 将 labelSet 转换为 Selector（实际就是 internalSelector ）
	selector := labels.NewSelector()
	if len(labelSet) != 0 {
		selector = labelSet.AsSelector()
	}

	// dfy: 因为 RS 比 RC 多了标签选择器 MatchExpressions，所以此处处理逻辑不一样；下面同理
	// dfy: RS 和 RC 的异同：https://blog.csdn.net/rzy1248873545/article/details/125875697
	// dfy: 此处就是获取该 pod 所在 namespace 下，匹配该 pod 的所有 RS
	if rss, err := rsl.GetPodReplicaSets(pod); err == nil {
		for _, rs := range rss {
			// dfy: 将 rs 的 Selector 字段转换为 selector（实际就是 internalSelector）
			if other, err := metav1.LabelSelectorAsSelector(rs.Spec.Selector); err == nil {
				// dfy: 此处就是将 selector 转换为 requirements 结构体，用于 Add 到已有 selector 上
				// dfy: 因为此处 Add 函数，只支持 requirements 类型，因此要进行转换
				if r, ok := other.Requirements(); ok {
					selector = selector.Add(r...)
				}
			}
		}
	}

	if sss, err := ssl.GetPodStatefulSets(pod); err == nil {
		for _, ss := range sss {
			if other, err := metav1.LabelSelectorAsSelector(ss.Spec.Selector); err == nil {
				if r, ok := other.Requirements(); ok {
					selector = selector.Add(r...)
				}
			}
		}
	}

	return selector
}

// GetPodServices gets the services that have the selector that match the labels on the given pod.
func GetPodServices(sl corelisters.ServiceLister, pod *v1.Pod) ([]*v1.Service, error) {
	// dfy： 列出 pod 所在 namespace 的所有 service
	allServices, err := sl.Services(pod.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	var services []*v1.Service
	for i := range allServices {
		service := allServices[i]
		if service.Spec.Selector == nil {
			// services with nil selectors match nothing, not everything.
			continue
		}
		// dfy: 将 service 中的 Selector 字段，转为代码中的 selector 结构体。中间过程，通过 Set 进行传输
		selector := labels.Set(service.Spec.Selector).AsSelectorPreValidated()
		// dfy: 记录下 匹配该 Pod 的 services
		if selector.Matches(labels.Set(pod.Labels)) {
			services = append(services, service)
		}
	}

	return services, nil
}
