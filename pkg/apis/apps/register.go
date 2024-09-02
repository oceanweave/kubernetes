/*
Copyright 2016 The Kubernetes Authors.

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

package apps

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/apis/autoscaling"
)

var (
	// SchemeBuilder stores functions to add things to a scheme.
	// dfy: 可以将 SchemeBuilder 当做一个数组，同时此数组存储的是类型是函数，目前存储的是 addKnownTypes 函数（该函数就是注册该 GVK 对应的资源 go struct）
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme applies all stored functions t oa scheme.
	// dfy: 供外部调用，调用方式为 AddToScheme(scheme)，用户调用传入参数 scheme 到 AddToScheme 中，便可将该 GVK 对应的资源 go struct 注册到 scheme 中
	AddToScheme = SchemeBuilder.AddToScheme
)

// GroupName is the group name use in this package
const GroupName = "apps"

// SchemeGroupVersion is group version used to register these objects
// dfy: runtime.APIVersionInternal 表示内部版本
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: runtime.APIVersionInternal}

// Kind takes an unqualified kind and returns a Group qualified GroupKind
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

// Adds the list of known types to the given scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	// TODO this will get cleaned up with the scheme types are fixed
	scheme.AddKnownTypes(SchemeGroupVersion,
		&DaemonSet{},
		&DaemonSetList{},
		&Deployment{},
		&DeploymentList{},
		&DeploymentRollback{},
		&autoscaling.Scale{},
		&StatefulSet{},
		&StatefulSetList{},
		&ControllerRevision{},
		&ControllerRevisionList{},
		&ReplicaSet{},
		&ReplicaSetList{},
	)
	return nil
}
