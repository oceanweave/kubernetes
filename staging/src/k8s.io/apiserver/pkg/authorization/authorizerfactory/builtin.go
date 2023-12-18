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

package authorizerfactory

import (
	"context"
	"errors"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// alwaysAllowAuthorizer is an implementation of authorizer.Attributes
// which always says yes to an authorization request.
// It is useful in tests and when using kubernetes in an open manner.
type alwaysAllowAuthorizer struct{}

// ymjx: AlwaysAllow授权
// AlwaysAllow授权器会允许所有请求，其也是kube-apiserver的默 认选项。
// 1.启用AlwaysAllow授权
//   kube-apiserver通过指定--authorization-mode=AlwaysAllow参 数启用AlwaysAllow授权。
// 2.AlwaysAllow授权实现
//   在进行AlwaysAllow授权时， 直接授权成功， 返回DecisionAllow 决策状态。
func (alwaysAllowAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	return authorizer.DecisionAllow, "", nil
}
// ymjx:
// 另外，AlwaysAllow的规则解析器会将资源类型的规则列表（ResourceRuleInfo）和非资源类型的规则列表（NonResourceRuleInfo）都设置为通配符（*）匹配所有资源版本、 资源及资源操作方法。
func (alwaysAllowAuthorizer) RulesFor(user user.Info, namespace string) ([]authorizer.ResourceRuleInfo, []authorizer.NonResourceRuleInfo, bool, error) {
	return []authorizer.ResourceRuleInfo{
			&authorizer.DefaultResourceRuleInfo{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
		}, []authorizer.NonResourceRuleInfo{
			&authorizer.DefaultNonResourceRuleInfo{
				Verbs:           []string{"*"},
				NonResourceURLs: []string{"*"},
			},
		}, false, nil
}

func NewAlwaysAllowAuthorizer() *alwaysAllowAuthorizer {
	return new(alwaysAllowAuthorizer)
}

// alwaysDenyAuthorizer is an implementation of authorizer.Attributes
// which always says no to an authorization request.
// It is useful in unit tests to force an operation to be forbidden.
type alwaysDenyAuthorizer struct{}

// ymjx: AlwaysDeny授权
// AlwaysDeny授权器会阻止所有请求，该授权器很少单独使用，一般会结合其他授权器一起使用。它的应用场景是先拒绝所有请求，再允许授权过的用户请求。
// 1.启用AlwaysDeny授权
// kube-apiserver通过指定--authorization-mode=AlwaysDeny参数 启用AlwaysDeny授权。
// 2.AlwaysDeny授权实现
// 在进行AlwaysDeny授权时， 直接返回DecisionNoOpionion决策状态。如果存在下一个授权器，会继续执行下一个授权器；
// 如果不存在 下一个授权器， 则会拒绝所有请求。 这就是kube-apiserver使用 AlwaysDeny的应用场景
func (alwaysDenyAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (decision authorizer.Decision, reason string, err error) {
	return authorizer.DecisionNoOpinion, "Everything is forbidden.", nil
}

// ymjx:
// 另外，AlwaysDeny的规则解析器会将资源类型的规则列表（ResourceRuleInfo）和非资源类型的规则列表（NonResourceRuleInfo）都设置为空
func (alwaysDenyAuthorizer) RulesFor(user user.Info, namespace string) ([]authorizer.ResourceRuleInfo, []authorizer.NonResourceRuleInfo, bool, error) {
	return []authorizer.ResourceRuleInfo{}, []authorizer.NonResourceRuleInfo{}, false, nil
}

func NewAlwaysDenyAuthorizer() *alwaysDenyAuthorizer {
	return new(alwaysDenyAuthorizer)
}

type privilegedGroupAuthorizer struct {
	groups []string
}

func (r *privilegedGroupAuthorizer) Authorize(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	if attr.GetUser() == nil {
		return authorizer.DecisionNoOpinion, "Error", errors.New("no user on request.")
	}
	for _, attr_group := range attr.GetUser().GetGroups() {
		for _, priv_group := range r.groups {
			if priv_group == attr_group {
				return authorizer.DecisionAllow, "", nil
			}
		}
	}
	return authorizer.DecisionNoOpinion, "", nil
}

// NewPrivilegedGroups is for use in loopback scenarios
func NewPrivilegedGroups(groups ...string) *privilegedGroupAuthorizer {
	return &privilegedGroupAuthorizer{
		groups: groups,
	}
}
