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

// Package install installs the apps API group, making it available as
// an option to all of the API encoding/decoding machinery.
package install

import (
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/apps/v1"
	"k8s.io/kubernetes/pkg/apis/apps/v1beta1"
	"k8s.io/kubernetes/pkg/apis/apps/v1beta2"
)

func init() {
	// dfy: legacyscheme.Scheme是kube-apiserver组件的全局资源注册表，
	// dfy: Kubernetes的所有资源信息都交给资源注册表统一管理。
	Install(legacyscheme.Scheme)
}

// Install registers the API group and adds types to a scheme
// dfy:
// - 将资源信息注册到资源注册表 Scheme 中
// - Scheme 是 apiserver 的全局资源注册表，记录资源版本与对应结构体的信息
func Install(scheme *runtime.Scheme) {
	// dfy: apps group 资源的[internal 内部版本]信息  apps/internal
	//  utilruntime.Must 函数通常用于简化错误处理过程。
	//  它的作用是接收一个函数调用，并检查该函数调用是否返回了错误。
	//  如果函数调用返回了错误，utilruntime.Must 会抛出 panic，并输出错误信息，导致程序终止。
	utilruntime.Must(apps.AddToScheme(scheme))
	// dfy: apps group 资源的 v1beta1 版本信息 apps/v1beta1
	utilruntime.Must(v1beta1.AddToScheme(scheme))
	// dfy: apps group 资源的 v1beta2 版本信息 apps/v1beta2
	utilruntime.Must(v1beta2.AddToScheme(scheme))
	// dfy: apps group 资源的 v1 版本信息  apps/v1
	utilruntime.Must(v1.AddToScheme(scheme))
	// dfy: 资源版本使用顺序，v1,v1betea2,v1beta1, 此处不包含内部版本
	// 当通过资源注册表scheme.PreferredVersionAllGroups函数获取所 有资源组下的首选版本时，将位于最前面的资源版本作为首选版本
	utilruntime.Must(scheme.SetVersionPriority(v1.SchemeGroupVersion, v1beta2.SchemeGroupVersion, v1beta1.SchemeGroupVersion))
}
