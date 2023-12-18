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

package authorizer

import (
	"context"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/user"
)

// Attributes is an interface used by an Authorizer to get information about a request
// that is used to make an authorization decision.
type Attributes interface {
	// GetUser returns the user.Info object to authorize
	GetUser() user.Info

	// GetVerb returns the kube verb associated with API requests (this includes get, list, watch, create, update, patch, delete, deletecollection, and proxy),
	// or the lowercased HTTP verb associated with non-API requests (this includes get, put, post, patch, and delete)
	GetVerb() string

	// When IsReadOnly() == true, the request has no side effects, other than
	// caching, logging, and other incidentals.
	IsReadOnly() bool

	// The namespace of the object, if a request is for a REST object.
	GetNamespace() string

	// The kind of object, if a request is for a REST object.
	GetResource() string

	// GetSubresource returns the subresource being requested, if present
	GetSubresource() string

	// GetName returns the name of the object as parsed off the request.  This will not be present for all request types, but
	// will be present for: get, update, delete
	GetName() string

	// The group of the resource, if a request is for a REST object.
	GetAPIGroup() string

	// GetAPIVersion returns the version of the group requested, if a request is for a REST object.
	GetAPIVersion() string

	// IsResourceRequest returns true for requests to API resources, like /api/v1/nodes,
	// and false for non-resource endpoints like /api, /healthz
	IsResourceRequest() bool

	// GetPath returns the path of the request
	GetPath() string
}

// Authorizer makes an authorization decision based on information gained by making
// zero or more calls to methods of the Attributes interface.  It returns nil when an action is
// authorized, otherwise it returns an error.
// ymjx: 授权
// 在客户端请求通过认证之后， 会来到授权阶段。 kube-apiserver 同样也支持多种授权机制，并支持同时开启多个授权功能，
// 如果开启 多个授权功能，则按照顺序执行授权器，在前面的授权器具有更高的 优先级来允许或拒绝请求。
// 客户端发起一个请求， 在经过授权阶段 后，只要有一个授权器通过则授权成功。
// kube-apiserver目前提供了6种授权机制， 分别是AlwaysAllow、 AlwaysDeny 、 ABAC 、 Webhook 、 RBAC 、 Node ，
// 可 通 过 指 定 -authorization-mode参数设置授权机制。
// - AlwaysAllow ：允许所有请求。
// - AlwaysDeny：阻止所有请求。
// - ABAC：即Attribute-Based Access Control，基于属性的访问控制。
// - Webhook：基于Webhook的一种HTTP协议回调，可进行远程授权管理。
// - RBAC：即Role-Based Access Control，基于角色的访问控制。
// - Node ：节点授权，专门授权给kubelet发出的API请求。
// 在kube-apiserver中， 授权有3个概念， 分别是 Decision决策状态、授权器接口、RuleResolver规则解析器。
// 1.Decision决策状态 —— 在下方，常量定义
// 2.授权器接口 —— 在此处
//   每一种授权机制都需要实现authorizer.Authorizer授权器接口方 法、接口定义
// 3.RuleResolver规则解析器 —— 在下方
type Authorizer interface {
	// ymjx:
	// - unionAuthzHandler: 遍历已启用的授权 器列表并执行授权器
	//   vendor/k8s.io/apiserver/pkg/authorization/union/union.go
	// - alwaysAllowAuthorizer: AlwaysAllow授权
	//   路径：vendor/k8s.io/apiserver/pkg/authorization/authorizerfactory/builtin.go
	// - alwaysDenyAuthorizer: AlwaysDeny授权
	//   路径：vendor/k8s.io/apiserver/pkg/authorization/authorizerfactory/builtin.go
	// - PolicyList: ABAC授权
	//   路径：pkg/auth/authorizer/abac/abac.go
	// - WebhookAuthorizer: Webhook授权
	//   路径：vendor/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go
	// - RBACAuthorizer: RBAC授权
	//   路径：plugin/pkg/auth/authorizer/rbac/rbac.go
	// - NodeAuthorizer: Node授权
	//   路径：plugin/pkg/auth/authorizer/node/node_authorizer.go
	Authorize(ctx context.Context, a Attributes) (authorized Decision, reason string, err error)
}

type AuthorizerFunc func(ctx context.Context, a Attributes) (Decision, string, error)

func (f AuthorizerFunc) Authorize(ctx context.Context, a Attributes) (Decision, string, error) {
	return f(ctx, a)
}

// RuleResolver provides a mechanism for resolving the list of rules that apply to a given user within a namespace.
// ymjx: 3.RuleResolver规则解析器
// 授权器通过RuleResolver规则解析器去解析规则
// RuleResolver接口定义了RulesFor方法， 每个授权器都需要实现该方法，
// RulesFor方法通过接收的user用户信息及namespace命名空间参数，解析出规则列表并返回。规则列表分为如下两种。
// - ResourceRuleInfo : 资 源 类 型 的 规 则 列 表 ， 例 如/api/v1/pods的资源接口。
// - NonResourceRuleInfo : 非资源类型的规则列表， 例如/api 或/health的资源接口。
// 以ResourceRuleInfo资源类型为例，其中通配符（*）表示匹配所有
type RuleResolver interface {
	// RulesFor get the list of cluster wide rules, the list of rules in the specific namespace, incomplete status and errors.
	RulesFor(user user.Info, namespace string) ([]ResourceRuleInfo, []NonResourceRuleInfo, bool, error)
}

// RequestAttributesGetter provides a function that extracts Attributes from an http.Request
type RequestAttributesGetter interface {
	GetRequestAttributes(user.Info, *http.Request) Attributes
}

// AttributesRecord implements Attributes interface.
type AttributesRecord struct {
	User            user.Info
	Verb            string
	Namespace       string
	APIGroup        string
	APIVersion      string
	Resource        string
	Subresource     string
	Name            string
	ResourceRequest bool
	Path            string
}

func (a AttributesRecord) GetUser() user.Info {
	return a.User
}

func (a AttributesRecord) GetVerb() string {
	return a.Verb
}

func (a AttributesRecord) IsReadOnly() bool {
	return a.Verb == "get" || a.Verb == "list" || a.Verb == "watch"
}

func (a AttributesRecord) GetNamespace() string {
	return a.Namespace
}

func (a AttributesRecord) GetResource() string {
	return a.Resource
}

func (a AttributesRecord) GetSubresource() string {
	return a.Subresource
}

func (a AttributesRecord) GetName() string {
	return a.Name
}

func (a AttributesRecord) GetAPIGroup() string {
	return a.APIGroup
}

func (a AttributesRecord) GetAPIVersion() string {
	return a.APIVersion
}

func (a AttributesRecord) IsResourceRequest() bool {
	return a.ResourceRequest
}

func (a AttributesRecord) GetPath() string {
	return a.Path
}

// ymjx: 1.Decision决策状态
// Decision决策状态类似于认证中的true和false，用于决定是否授 权成功。
// 授权支持3种Decision决策状态， 例如授权成功， 则返回 DecisionAllow决策状态
// DecisionDeny：表示授权器拒绝该操作。
// DecisionAllow：表示授权器允许该操作。
// DecisionNoOpionion ：表示授权器对是否允许或拒绝某个操作没有意见，会继续执行下一个授权器。
type Decision int

const (
	// DecisionDeny means that an authorizer decided to deny the action.
	DecisionDeny Decision = iota
	// DecisionAllow means that an authorizer decided to allow the action.
	DecisionAllow
	// DecisionNoOpionion means that an authorizer has no opinion on whether
	// to allow or deny an action.
	DecisionNoOpinion
)
