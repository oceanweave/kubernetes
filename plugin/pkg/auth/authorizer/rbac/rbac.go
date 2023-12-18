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

// Package rbac implements the authorizer.Authorizer interface using roles base access control.
package rbac

import (
	"bytes"
	"context"
	"fmt"

	"k8s.io/klog/v2"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbaclisters "k8s.io/client-go/listers/rbac/v1"
	rbacv1helpers "k8s.io/kubernetes/pkg/apis/rbac/v1"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

type RequestToRuleMapper interface {
	// RulesFor returns all known PolicyRules and any errors that happened while locating those rules.
	// Any rule returned is still valid, since rules are deny by default.  If you can pass with the rules
	// supplied, you do not have to fail the request.  If you cannot, you should indicate the error along
	// with your denial.
	RulesFor(subject user.Info, namespace string) ([]rbacv1.PolicyRule, error)

	// VisitRulesFor invokes visitor() with each rule that applies to a given user in a given namespace,
	// and each error encountered resolving those rules. Rule may be nil if err is non-nil.
	// If visitor() returns false, visiting is short-circuited.
	VisitRulesFor(user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool)
}

type RBACAuthorizer struct {
	authorizationRuleResolver RequestToRuleMapper
}

// authorizingVisitor short-circuits once allowed, and collects any resolution errors encountered
type authorizingVisitor struct {
	requestAttributes authorizer.Attributes

	allowed bool
	reason  string
	errors  []error
}

func (v *authorizingVisitor) visit(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool {
	if rule != nil && RuleAllows(v.requestAttributes, rule) {
		v.allowed = true
		v.reason = fmt.Sprintf("RBAC: allowed by %s", source.String())
		return false
	}
	if err != nil {
		v.errors = append(v.errors, err)
	}
	return true
}

// Authorize ymjx: RBAC授权
// RBAC授权器现实了基于角色的权限访问控制（Role-BasedAccessControl），其也是目前使用最为广泛的授权模型。
// 在RBAC授权器中，权限与角色相关联，形成了用户—角色—权限的授权模型。用户通过加入某些角色从而得到这些角色的操作权限，这极大地简化了权限管理。
// 1.RBAC核心数据结构
// 在kube-apiserver设计的RBAC授权器中，新增了角色与集群绑定的概念，也就是说，kube-apiserver可以提供4种数据类型来表达基于角色的授权，
// 它们分别是角色（Role）、集群角色（ClusterRole）、角色绑定（RoleBinding）及集群角色绑定（ClusterRoleBinding），
// 这4种数据类型定义在vendor/k8s.io/api/rbac/v1/types.go中
// 2.RBAC授权详解
// 在进行RBAC授权时，首先通过r.authorizationRuleResolver.VisitRulesFor函数调用给定的ruleCheckingVisitor.visit函数来验证授权，
// 该函数返回的allowed字段为true，表示授权成功并返回DecisionAllow决策状态。
// ruleCheckingVisitor.visit函数会调用RBAC的RuleAllows函数， RuleAllows函数是实际验证授权规则的函数， 该函数的验证授权原理
// RuleAllows函数验证授权规则的过程如下。
// 首先通过IsResourceRequest函数判断请求的资源是资源类型接口（例如/api/v1/nodes）还是非资源类型接口（例如/healthz）。
// 如果是资源类型接口，则执行一系列的Matches函数：VerbMatches（匹配操作）→APIGroupMatches（匹配资源组）→ResourceMatches（匹配资源或子资源）→ResourceNameMatches（匹配资源名称），当全部Matches函数返回true时，授权成功。
// 如果是非资源类型接口，也需要执行一些Matches函数：VerbMatches（匹配操作）→NonResourceURLMatches（匹配非资源类型的接口URL），当全部Matches函数返回true时，授权成功
// 3.内置集群角色
// kube-apiserver在启动时会默认创建内置角色。 例如clusteradmin集群角色， 它拥有Kubernetes的最高权限
// cluster-admin集群角色的定义中将资源类型和非资源类型都设置 为通配符（*），匹配所有资源版本、资源，拥有Kubernetes的最高控 制权限。
// 然后将cluster-admin集群角色与system：masters组进行绑 定。
// 默认创建的内置角色定义与cluster-admin集群角色定义类似，内 置角色定义在plugin/pkg/auth/authorizer/rbac/bootstrappolicy目 录下
// 注意：不建议擅自改动内置集群角色及内置权限的定义，因为这样可能会造成Kubernetes 系统中的某些组件因权限问题导致不可以被授权。
// Component Roles说明。
// 控制器角色，kube-controller-manager组件负责运行核心控制循环。
// 当使用--use-service-account-credentials参数运行kube-controller-manager时，每个控制循环都使用单独的服务账户启动，每一个控制循环都对应控制器角色前缀名system：controller：。
// 如果不使用--use-service-account-credentials参数，kube-controller-manager将会使用自己的凭证运行所有的控制循环， 而这些凭证必须被授予相关的角色(手动配置上controller-manager所有Controller的所有权限）
func (r *RBACAuthorizer) Authorize(ctx context.Context, requestAttributes authorizer.Attributes) (authorizer.Decision, string, error) {
	ruleCheckingVisitor := &authorizingVisitor{requestAttributes: requestAttributes}

	r.authorizationRuleResolver.VisitRulesFor(requestAttributes.GetUser(), requestAttributes.GetNamespace(), ruleCheckingVisitor.visit)
	if ruleCheckingVisitor.allowed {
		return authorizer.DecisionAllow, ruleCheckingVisitor.reason, nil
	}

	// Build a detailed log of the denial.
	// Make the whole block conditional so we don't do a lot of string-building we won't use.
	if klogV := klog.V(5); klogV.Enabled() {
		var operation string
		if requestAttributes.IsResourceRequest() {
			b := &bytes.Buffer{}
			b.WriteString(`"`)
			b.WriteString(requestAttributes.GetVerb())
			b.WriteString(`" resource "`)
			b.WriteString(requestAttributes.GetResource())
			if len(requestAttributes.GetAPIGroup()) > 0 {
				b.WriteString(`.`)
				b.WriteString(requestAttributes.GetAPIGroup())
			}
			if len(requestAttributes.GetSubresource()) > 0 {
				b.WriteString(`/`)
				b.WriteString(requestAttributes.GetSubresource())
			}
			b.WriteString(`"`)
			if len(requestAttributes.GetName()) > 0 {
				b.WriteString(` named "`)
				b.WriteString(requestAttributes.GetName())
				b.WriteString(`"`)
			}
			operation = b.String()
		} else {
			operation = fmt.Sprintf("%q nonResourceURL %q", requestAttributes.GetVerb(), requestAttributes.GetPath())
		}

		var scope string
		if ns := requestAttributes.GetNamespace(); len(ns) > 0 {
			scope = fmt.Sprintf("in namespace %q", ns)
		} else {
			scope = "cluster-wide"
		}

		klogV.Infof("RBAC: no rules authorize user %q with groups %q to %s %s", requestAttributes.GetUser().GetName(), requestAttributes.GetUser().GetGroups(), operation, scope)
	}

	reason := ""
	if len(ruleCheckingVisitor.errors) > 0 {
		reason = fmt.Sprintf("RBAC: %v", utilerrors.NewAggregate(ruleCheckingVisitor.errors))
	}
	return authorizer.DecisionNoOpinion, reason, nil
}

func (r *RBACAuthorizer) RulesFor(user user.Info, namespace string) ([]authorizer.ResourceRuleInfo, []authorizer.NonResourceRuleInfo, bool, error) {
	var (
		resourceRules    []authorizer.ResourceRuleInfo
		nonResourceRules []authorizer.NonResourceRuleInfo
	)

	policyRules, err := r.authorizationRuleResolver.RulesFor(user, namespace)
	for _, policyRule := range policyRules {
		if len(policyRule.Resources) > 0 {
			r := authorizer.DefaultResourceRuleInfo{
				Verbs:         policyRule.Verbs,
				APIGroups:     policyRule.APIGroups,
				Resources:     policyRule.Resources,
				ResourceNames: policyRule.ResourceNames,
			}
			var resourceRule authorizer.ResourceRuleInfo = &r
			resourceRules = append(resourceRules, resourceRule)
		}
		if len(policyRule.NonResourceURLs) > 0 {
			r := authorizer.DefaultNonResourceRuleInfo{
				Verbs:           policyRule.Verbs,
				NonResourceURLs: policyRule.NonResourceURLs,
			}
			var nonResourceRule authorizer.NonResourceRuleInfo = &r
			nonResourceRules = append(nonResourceRules, nonResourceRule)
		}
	}
	return resourceRules, nonResourceRules, false, err
}

func New(roles rbacregistryvalidation.RoleGetter, roleBindings rbacregistryvalidation.RoleBindingLister, clusterRoles rbacregistryvalidation.ClusterRoleGetter, clusterRoleBindings rbacregistryvalidation.ClusterRoleBindingLister) *RBACAuthorizer {
	authorizer := &RBACAuthorizer{
		authorizationRuleResolver: rbacregistryvalidation.NewDefaultRuleResolver(
			roles, roleBindings, clusterRoles, clusterRoleBindings,
		),
	}
	return authorizer
}

func RulesAllow(requestAttributes authorizer.Attributes, rules ...rbacv1.PolicyRule) bool {
	for i := range rules {
		if RuleAllows(requestAttributes, &rules[i]) {
			return true
		}
	}

	return false
}

func RuleAllows(requestAttributes authorizer.Attributes, rule *rbacv1.PolicyRule) bool {
	if requestAttributes.IsResourceRequest() {
		combinedResource := requestAttributes.GetResource()
		if len(requestAttributes.GetSubresource()) > 0 {
			combinedResource = requestAttributes.GetResource() + "/" + requestAttributes.GetSubresource()
		}

		return rbacv1helpers.VerbMatches(rule, requestAttributes.GetVerb()) &&
			rbacv1helpers.APIGroupMatches(rule, requestAttributes.GetAPIGroup()) &&
			rbacv1helpers.ResourceMatches(rule, combinedResource, requestAttributes.GetSubresource()) &&
			rbacv1helpers.ResourceNameMatches(rule, requestAttributes.GetName())
	}

	return rbacv1helpers.VerbMatches(rule, requestAttributes.GetVerb()) &&
		rbacv1helpers.NonResourceURLMatches(rule, requestAttributes.GetPath())
}

type RoleGetter struct {
	Lister rbaclisters.RoleLister
}

func (g *RoleGetter) GetRole(namespace, name string) (*rbacv1.Role, error) {
	return g.Lister.Roles(namespace).Get(name)
}

type RoleBindingLister struct {
	Lister rbaclisters.RoleBindingLister
}

func (l *RoleBindingLister) ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error) {
	return l.Lister.RoleBindings(namespace).List(labels.Everything())
}

type ClusterRoleGetter struct {
	Lister rbaclisters.ClusterRoleLister
}

func (g *ClusterRoleGetter) GetClusterRole(name string) (*rbacv1.ClusterRole, error) {
	return g.Lister.Get(name)
}

type ClusterRoleBindingLister struct {
	Lister rbaclisters.ClusterRoleBindingLister
}

func (l *ClusterRoleBindingLister) ListClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error) {
	return l.Lister.List(labels.Everything())
}
