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

package filters

import (
	"context"
	"errors"
	"net/http"

	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
)

const (
	// Annotation key names set in advanced audit
	decisionAnnotationKey = "authorization.k8s.io/decision"
	reasonAnnotationKey   = "authorization.k8s.io/reason"

	// Annotation values set in advanced audit
	decisionAllow  = "allow"
	decisionForbid = "forbid"
	reasonError    = "internal error"
)

// WithAuthorizationCheck passes all authorized requests on to handler, and returns a forbidden error otherwise.
// ymjx:
// 每一种授权机制被实例化后会成为授权器（Authorizer）， 每一个授权器都被封装在http.Handler函数中， 它们接收组件或客户端的 请求并授权请求。
// 当客户端请求到达kube-apiserver的授权器， 并返 回DecisionAllow决策状态时，则表示授权成功。
// 假设kube-apiserver开启了Node授权器和RBAC授权器。 当客户端发送请求到kube-apiserver服务，该请求会进入 Authorization Handler函数（即处理授权相关的Handler函数），
// 在Authorization Handler函数中，会遍历已启用的授权器列表，按顺序尝试执行每个授权器，
// 例如在Node授权器返回DecisionNoOpinion决策状态时，会继续 执行下一个RBAC授权器，而当RBAC授权器返回DecisionAllow决策状态 时，则表示授权成功。
//
// WithAuthorization函数是kube-apiserver的授权Handler 方法。
// 如果a授权器为空， 则说明kube-apiserver未启用任何授权功 能；如果a授权器不为空， 则通过GetAuthorizerAttributes函数从 HTTP请求中获取客户端信息。
// a.Authorize函数对请求进行授权，
// 如果授权失败 ， 则 通 过 responsewriters.Forbidden 函 数 返 回 HTTP 401 Unauthorized并返回授权失败的原因。
// 如果返回DecisionAllow决策状 态，则表示授权成功，并进入准入控制器阶段。
//
// 在a.Authorize函数对请求进行授权的过程中，遍历已启用的授权 器列表并执行授权器，
func WithAuthorization(handler http.Handler, a authorizer.Authorizer, s runtime.NegotiatedSerializer) http.Handler {
	if a == nil {
		klog.Warning("Authorization is disabled")
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		attributes, err := GetAuthorizerAttributes(ctx)
		if err != nil {
			responsewriters.InternalError(w, req, err)
			return
		}
		// ymjx: 在a.Authorize函数对请求进行授权的过程中，遍历已启用的授权 器列表并执行授权器
		authorized, reason, err := a.Authorize(ctx, attributes)
		// an authorizer like RBAC could encounter evaluation errors and still allow the request, so authorizer decision is checked before error here.
		if authorized == authorizer.DecisionAllow {
			audit.AddAuditAnnotations(ctx,
				decisionAnnotationKey, decisionAllow,
				reasonAnnotationKey, reason)
			handler.ServeHTTP(w, req)
			return
		}
		if err != nil {
			audit.AddAuditAnnotation(ctx, reasonAnnotationKey, reasonError)
			responsewriters.InternalError(w, req, err)
			return
		}

		klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "Reason", reason)
		audit.AddAuditAnnotations(ctx,
			decisionAnnotationKey, decisionForbid,
			reasonAnnotationKey, reason)
		responsewriters.Forbidden(ctx, attributes, w, req, reason, s)
	})
}

func GetAuthorizerAttributes(ctx context.Context) (authorizer.Attributes, error) {
	attribs := authorizer.AttributesRecord{}

	user, ok := request.UserFrom(ctx)
	if ok {
		attribs.User = user
	}

	requestInfo, found := request.RequestInfoFrom(ctx)
	if !found {
		return nil, errors.New("no RequestInfo found in the context")
	}

	// Start with common attributes that apply to resource and non-resource requests
	attribs.ResourceRequest = requestInfo.IsResourceRequest
	attribs.Path = requestInfo.Path
	attribs.Verb = requestInfo.Verb

	attribs.APIGroup = requestInfo.APIGroup
	attribs.APIVersion = requestInfo.APIVersion
	attribs.Resource = requestInfo.Resource
	attribs.Subresource = requestInfo.Subresource
	attribs.Namespace = requestInfo.Namespace
	attribs.Name = requestInfo.Name

	return &attribs, nil
}
