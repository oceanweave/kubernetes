/*
Copyright 2014 The Kubernetes Authors.

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

package endpoints

import (
	"path"
	"time"

	restful "github.com/emicklei/go-restful"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/discovery"
	"k8s.io/apiserver/pkg/endpoints/handlers/fieldmanager"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storageversion"
	openapiproto "k8s.io/kube-openapi/pkg/util/proto"
)

// ConvertabilityChecker indicates what versions a GroupKind is available in.
type ConvertabilityChecker interface {
	// VersionsForGroupKind indicates what versions are available to convert a group kind. This determines
	// what our decoding abilities are.
	VersionsForGroupKind(gk schema.GroupKind) []schema.GroupVersion
}

// APIGroupVersion is a helper for exposing rest.Storage objects as http.Handlers via go-restful
// It handles URLs of the form:
// /${storage_key}[/${object_name}]
// Where 'storage_key' points to a rest.Storage object stored in storage.
// This object should contain all parameterization necessary for running a particular API version
type APIGroupVersion struct {
	Storage map[string]rest.Storage

	Root string

	// GroupVersion is the external group version
	GroupVersion schema.GroupVersion

	// OptionsExternalVersion controls the Kubernetes APIVersion used for common objects in the apiserver
	// schema like api.Status, api.DeleteOptions, and metav1.ListOptions. Other implementors may
	// define a version "v1beta1" but want to use the Kubernetes "v1" internal objects. If
	// empty, defaults to GroupVersion.
	OptionsExternalVersion *schema.GroupVersion
	// MetaGroupVersion defaults to "meta.k8s.io/v1" and is the scheme group version used to decode
	// common API implementations like ListOptions. Future changes will allow this to vary by group
	// version (for when the inevitable meta/v2 group emerges).
	MetaGroupVersion *schema.GroupVersion

	// RootScopedKinds are the root scoped kinds for the primary GroupVersion
	RootScopedKinds sets.String

	// Serializer is used to determine how to convert responses from API methods into bytes to send over
	// the wire.
	Serializer     runtime.NegotiatedSerializer
	ParameterCodec runtime.ParameterCodec

	Typer                 runtime.ObjectTyper
	Creater               runtime.ObjectCreater
	Convertor             runtime.ObjectConvertor
	ConvertabilityChecker ConvertabilityChecker
	Defaulter             runtime.ObjectDefaulter
	Namer                 runtime.Namer
	UnsafeConvertor       runtime.ObjectConvertor
	TypeConverter         fieldmanager.TypeConverter

	EquivalentResourceRegistry runtime.EquivalentResourceRegistry

	// Authorizer determines whether a user is allowed to make a certain request. The Handler does a preliminary
	// authorization check using the request URI but it may be necessary to make additional checks, such as in
	// the create-on-update case
	Authorizer authorizer.Authorizer

	Admit admission.Interface

	MinRequestTimeout time.Duration

	// OpenAPIModels exposes the OpenAPI models to each individual handler.
	OpenAPIModels openapiproto.Models

	// The limit on the request body size that would be accepted and decoded in a write request.
	// 0 means no limit.
	MaxRequestBodyBytes int64
}

// InstallREST registers the REST handlers (storage, watch, proxy and redirect) into a restful Container.
// It is expected that the provided path root prefix will serve all operations. Root MUST NOT end
// in a slash.
func (g *APIGroupVersion) InstallREST(container *restful.Container) ([]*storageversion.ResourceInfo, error) {
	// ymjx:
	// 1. prefix 定 义 了 HTTP PATH 请 求 路 径 ， 其 表 现 形 式 为 <apiPrefix>/<group>/<version>（即/apis/apiextensions.k8s.io/v 1beta1）
	prefix := path.Join(g.Root, g.GroupVersion.Group, g.GroupVersion.Version)
	// ymjx:
	// 2. 实例化APIInstaller安装器
	installer := &APIInstaller{
		group:             g,
		prefix:            prefix,
		minRequestTimeout: g.MinRequestTimeout,
	}

	// installer.Install: 返回最终restful.WebService对象
	// ymjx:
	// 3. 在 installer.Install 安 装 器 内 部 创 建 一 个 go-restful WebService， 然后通过a.registerResourceHandlers函数，
	// 为资源注 册对应的Handlers方法（即资源存储对象Resource Storage）， 完成 资源与资源Handlers方法的绑定并为go-restful WebService添加该路 由。
	apiResources, resourceInfos, ws, registrationErrors := installer.Install()
	versionDiscoveryHandler := discovery.NewAPIVersionHandler(g.Serializer, g.GroupVersion, staticLister{apiResources})
	versionDiscoveryHandler.AddToWebService(ws)
	// ymjx:
	// 4. 最 后 通 过 container.Add 函 数 将 WebService 添 加 到 gorestful Container中
	container.Add(ws)
	return removeNonPersistedResources(resourceInfos), utilerrors.NewAggregate(registrationErrors)
}

func removeNonPersistedResources(infos []*storageversion.ResourceInfo) []*storageversion.ResourceInfo {
	var filtered []*storageversion.ResourceInfo
	for _, info := range infos {
		// if EncodingVersion is empty, then the apiserver does not
		// need to register this resource via the storage version API,
		// thus we can remove it.
		if info != nil && len(info.EncodingVersion) > 0 {
			filtered = append(filtered, info)
		}
	}
	return filtered
}

// staticLister implements the APIResourceLister interface
type staticLister struct {
	list []metav1.APIResource
}

func (s staticLister) ListAPIResources() []metav1.APIResource {
	return s.list
}

var _ discovery.APIResourceLister = &staticLister{}
