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

package v1

import (
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the group name use in this package
const GroupName = "apps"

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1"}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// dfy: localSchemeBuilder 就是个数组，存储的是函数，但是奇怪，我们未见到 AddKnownTypes 注册资源 go struct 的函数？
	// dfy: 跳转便能看到，该函数写在和 外部资源定义 type.go 同文件夹内
	localSchemeBuilder = &appsv1.SchemeBuilder
	// dfy: 供外部调用来使用此 Group 的资源，如外部定义变量 scheme，可以如下调用 AddToScheme(scheme)，便可以将该 Group 的资源 go struct 注册到外部 scheme 中
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	// dfy: 注册一些默认值填充函数
	localSchemeBuilder.Register(addDefaultingFuncs)
}
