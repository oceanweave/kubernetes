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

package authenticator

import (
	"context"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/user"
)

// Token checks a string value against a backing authentication store and
// returns a Response or an error if the token could not be checked.
type Token interface {
	// AuthenticateToken 接口：
	// Token 认证接口定义了AuthenticateToken方法，该方法接收token 字符串。
	// 若验证失败， bool值会为false；
	// 若验证成功， bool值会为 true， 并返回*authenticator.Response，
	// *authenticator.Response 中携带了身份验证用户的信息， 例如Name、 UID、 Groups、 Extra等信 息。
	//
	// ymjx:
	// - TokenAuthenticator(tokenfile.go): TokenAuth认证
	//   路径 vendor/k8s.io/apiserver/pkg/authentication/token/tokenfile/tokenfile.go
	// - TokenAuthenticator(bootstrap.go): BootstrapToken认证
	//   路径 plugin/pkg/auth/authenticator/token/bootstrap/bootstrap.go
	// - WebhookTokenAuthenticator: WebhookTokenAuth认证
	//   路径 vendor/k8s.io/apiserver/plugin/pkg/authenticator/token/webhook/webhook.go
	// - Authticator: OIDC认证
	//   路径 vendor/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go
	// - jwtTokenAuthenticator: ServiceAccountAuth认证
	//   pkg/serviceaccount/jwt.go
	AuthenticateToken(ctx context.Context, token string) (*Response, bool, error)
}

// Request attempts to extract authentication information from a request and
// returns a Response or an error if the request could not be checked.
type Request interface {
	// AuthenticateRequest 接口：
	// 路径 vendor/k8s.io/apiserver/pkg/authentication/request

	// Request 认证接口定义了AuthenticateRequest方法，该方法接收 客户端请求。
	// 若验证失败，bool值会为false；
	// 若验证成功，bool值会 为 true ， 并 返 回 *authenticator.Response ，
	// *authenticator.Response中携带了身份验证用户的信息，例如Name、 UID、Groups、Extra等信息。
	//
	// ymjx:
	// - unionAuthRequestHandler 遍历已启用的认证器列表， 尝试执行每个认证器， 当有一个认证器返回 true时，则认证成功，否则继续尝试下一个认证器
	//   路径：vendor/k8s.io/apiserver/pkg/authentication/request/union/union.go
	// - Authenticator(bearertoken): BasicAuth认证
	//   路径：vendor/k8s.io/apiserver/pkg/authentication/request/bearertoken/bearertoken.go
	// - Authenticator(x509): ClientCA认证
	//   路径：vendor/k8s.io/apiserver/pkg/authentication/request/x509/x509.go
	// - requestHeadAuthRequestHandler: RequestHeader认证
	//   路径：vendor/k8s.io/apiserver/pkg/authentication/request/headerrequest/requestheader.go
	// - Anonymous认证: 该认证方式，没有直接实现接口，而是用另一个函数包装，返回值为该接口
	//   路径：vendor/k8s.io/apiserver/pkg/authentication/request/anonymous/anonymous.go
	AuthenticateRequest(req *http.Request) (*Response, bool, error)
}

// TokenFunc is a function that implements the Token interface.
type TokenFunc func(ctx context.Context, token string) (*Response, bool, error)

// AuthenticateToken implements authenticator.Token.
func (f TokenFunc) AuthenticateToken(ctx context.Context, token string) (*Response, bool, error) {
	return f(ctx, token)
}

// RequestFunc is a function that implements the Request interface.
type RequestFunc func(req *http.Request) (*Response, bool, error)

// AuthenticateRequest implements authenticator.Request.
func (f RequestFunc) AuthenticateRequest(req *http.Request) (*Response, bool, error) {
	return f(req)
}

// Response is the struct returned by authenticator interfaces upon successful
// authentication. It contains information about whether the authenticator
// authenticated the request, information about the context of the
// authentication, and information about the authenticated user.
type Response struct {
	// Audiences is the set of audiences the authenticator was able to validate
	// the token against. If the authenticator is not audience aware, this field
	// will be empty.
	Audiences Audiences
	// User is the UserInfo associated with the authentication context.
	User user.Info
}
