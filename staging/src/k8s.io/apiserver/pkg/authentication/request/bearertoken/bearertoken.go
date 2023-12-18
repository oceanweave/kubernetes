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

package bearertoken

import (
	"errors"
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

type Authenticator struct {
	auth authenticator.Token
}

func New(auth authenticator.Token) *Authenticator {
	return &Authenticator{auth}
}

var invalidToken = errors.New("invalid bearer token")

// ymjx: BasicAuth认证实现
// 在进行BasicAuth认证时， 通过req.BasicAuth函数尝试从请求头 中读取Authorization字段，通过Base64解码出用户、密码信息，并通
// 过 a.auth.AuthenticatePassword 函 数 进 行 认 证 ， 认 证 失 败 会 返 回 false，而认证成功会返回true。
//
// BasicAuth认证接口定义了AuthenticateRequest方法， 该方法接 收客户端请求。
// 若验证失败，bool值会为false；
// 若验证成功，bool值 会 为 true ， 并 返 回 *authenticator.Response ，
// *authenticator.Response中携带了身份验证用户的信息，例如Name、 UID、Groups、Extra等信息。
//
// BasicAuth 认证介绍
// BasicAuth是一种简单的HTTP协议上的认证机制，客户端将用户、 密码写入请求头中，
// HTTP服务端尝试从请求头中验证用户、 密码信 息，从而实现身份验证。客户端发送的请求头示例如下：
// 请 求 头 的 key 为 Authorization ， value 为 Basic BASE64ENCODED（USER：PASSWORD），其中用户名及密码是通过Base64 编码后的字符串。
// kube-apiserver通过指定--basic-auth-file参数启用BasicAuth 认证。 AUTH_FILE是一个CSV文件， 每个用户在CSV中的表现形式为 password、username、uid
func (a *Authenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if auth == "" {
		return nil, false, nil
	}
	parts := strings.SplitN(auth, " ", 3)
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, false, nil
	}

	token := parts[1]

	// Empty bearer tokens aren't valid
	if len(token) == 0 {
		return nil, false, nil
	}

	resp, ok, err := a.auth.AuthenticateToken(req.Context(), token)
	// if we authenticated successfully, go ahead and remove the bearer token so that no one
	// is ever tempted to use it inside of the API server
	if ok {
		req.Header.Del("Authorization")
	}

	// If the token authenticator didn't error, provide a default error
	if !ok && err == nil {
		err = invalidToken
	}

	return resp, ok, err
}
