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

package filters

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"
)

type recordMetrics func(context.Context, *authenticator.Response, bool, error, authenticator.Audiences, time.Time, time.Time)

// WithAuthentication creates an http handler that tries to authenticate the given request as a user, and then
// stores any such user found onto the provided context for the request. If authentication fails or returns an error
// the failed handler is used. On success, "Authorization" header is removed from the request and handler
// is invoked to serve the request.
// ymjx:
// 假 设 所 有 的 认 证 器 都 被 启 用 ， 当 客 户 端 发 送 请 求 到 kubeapiserver服务，该请求会进入Authentication Handler函数（处理认 证相关的Handler函数），
// 在Authentication Handler函数中，会遍历已启用的认证器列表， 尝试执行每个认证器， 当有一个认证器返回 true时，则认证成功，否则继续尝试下一个认证器。
//
// WithAuthentication函数可以作为kube-apiserver的认证Handler 函数。
// 如果auth认证器为空， 说明kube-apiserver未启用任何认证功 能；
// 如果其不为空， 则通过auth.AuthenticateRequest函数对请求进 行认证。
// 如果身份认证失败， 则通过failed.ServeHTTP函数返回HTTP 401 Unauthorized， 表示认证被拒绝；
// 如果身份认证成功， 则不再需 要Authorization请求头并进入授权阶段。
//
// 在auth.AuthenticateRequest函数对请求进行认证的过程中， 遍 历已启用的认证器列表并执行每个认证器

func WithAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler, apiAuds authenticator.Audiences) http.Handler {
	return withAuthentication(handler, auth, failed, apiAuds, recordAuthMetrics)
}

func withAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler, apiAuds authenticator.Audiences, metrics recordMetrics) http.Handler {
	if auth == nil {
		klog.Warning("Authentication is disabled")
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authenticationStart := time.Now()

		if len(apiAuds) > 0 {
			req = req.WithContext(authenticator.WithAudiences(req.Context(), apiAuds))
		}
		// ymjx: 在auth.AuthenticateRequest函数对请求进行认证的过程中， 遍 历已启用的认证器列表并执行每个认证器
		//		 此处重要！！！  是认证部分的关键函数接口
		resp, ok, err := auth.AuthenticateRequest(req)
		authenticationFinish := time.Now()
		defer func() {
			metrics(req.Context(), resp, ok, err, apiAuds, authenticationStart, authenticationFinish)
		}()
		if err != nil || !ok {
			if err != nil {
				klog.ErrorS(err, "Unable to authenticate the request")
			}
			failed.ServeHTTP(w, req)
			return
		}

		if !audiencesAreAcceptable(apiAuds, resp.Audiences) {
			err = fmt.Errorf("unable to match the audience: %v , accepted: %v", resp.Audiences, apiAuds)
			klog.Error(err)
			failed.ServeHTTP(w, req)
			return
		}

		// authorization header is not required anymore in case of a successful authentication.
		req.Header.Del("Authorization")

		req = req.WithContext(genericapirequest.WithUser(req.Context(), resp.User))
		handler.ServeHTTP(w, req)
	})
}

func Unauthorized(s runtime.NegotiatedSerializer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		requestInfo, found := genericapirequest.RequestInfoFrom(ctx)
		if !found {
			responsewriters.InternalError(w, req, errors.New("no RequestInfo found in the context"))
			return
		}

		gv := schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}
		responsewriters.ErrorNegotiated(apierrors.NewUnauthorized("Unauthorized"), s, gv, w, req)
	})
}

func audiencesAreAcceptable(apiAuds, responseAudiences authenticator.Audiences) bool {
	if len(apiAuds) == 0 || len(responseAudiences) == 0 {
		return true
	}

	return len(apiAuds.Intersect(responseAudiences)) > 0
}
