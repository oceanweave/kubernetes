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

package anonymous

import (
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	anonymousUser = user.Anonymous

	unauthenticatedGroup = user.AllUnauthenticated
)

// ymjx: (此处函数的返回值，就是定义的 Request 接口，不像别的认证结构清晰）
// Anonymous认证
// Anonymous认证就是匿名认证，未被其他认证器拒绝的请求都可视 为匿名请求。kube-apiserver默认开启Anonymous（匿名）认证。
// 1.启用Anonymous认证
// kube-apiserver通过指定--anonymous-auth参数启用Anonymous认 证，默认该参数值为true。
// 2.Anonymous认证实现
// 在进行Anonymous认证时，直接验证成功，返回true。
func NewAuthenticator() authenticator.Request {
	return authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		auds, _ := authenticator.AudiencesFrom(req.Context())
		return &authenticator.Response{
			User: &user.DefaultInfo{
				Name:   anonymousUser,
				Groups: []string{unauthenticatedGroup},
			},
			Audiences: auds,
		}, true, nil
	})
}
