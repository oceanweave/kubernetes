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

package headerrequest

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	x509request "k8s.io/apiserver/pkg/authentication/request/x509"
	"k8s.io/apiserver/pkg/authentication/user"
	utilcert "k8s.io/client-go/util/cert"
)

// StringSliceProvider is a way to get a string slice value.  It is heavily used for authentication headers among other places.
type StringSliceProvider interface {
	// Value returns the current string slice.  Callers should never mutate the returned value.
	Value() []string
}

// StringSliceProviderFunc is a function that matches the StringSliceProvider interface
type StringSliceProviderFunc func() []string

// Value returns the current string slice.  Callers should never mutate the returned value.
func (d StringSliceProviderFunc) Value() []string {
	return d()
}

// StaticStringSlice a StringSliceProvider that returns a fixed value
type StaticStringSlice []string

// Value returns the current string slice.  Callers should never mutate the returned value.
func (s StaticStringSlice) Value() []string {
	return s
}

type requestHeaderAuthRequestHandler struct {
	// nameHeaders are the headers to check (in order, case-insensitively) for an identity. The first header with a value wins.
	nameHeaders StringSliceProvider

	// groupHeaders are the headers to check (case-insensitively) for group membership.  All values of all headers will be added.
	groupHeaders StringSliceProvider

	// extraHeaderPrefixes are the head prefixes to check (case-insensitively) for filling in
	// the user.Info.Extra.  All values of all matching headers will be added.
	extraHeaderPrefixes StringSliceProvider
}

func New(nameHeaders, groupHeaders, extraHeaderPrefixes []string) (authenticator.Request, error) {
	trimmedNameHeaders, err := trimHeaders(nameHeaders...)
	if err != nil {
		return nil, err
	}
	trimmedGroupHeaders, err := trimHeaders(groupHeaders...)
	if err != nil {
		return nil, err
	}
	trimmedExtraHeaderPrefixes, err := trimHeaders(extraHeaderPrefixes...)
	if err != nil {
		return nil, err
	}

	return NewDynamic(
		StaticStringSlice(trimmedNameHeaders),
		StaticStringSlice(trimmedGroupHeaders),
		StaticStringSlice(trimmedExtraHeaderPrefixes),
	), nil
}

func NewDynamic(nameHeaders, groupHeaders, extraHeaderPrefixes StringSliceProvider) authenticator.Request {
	return &requestHeaderAuthRequestHandler{
		nameHeaders:         nameHeaders,
		groupHeaders:        groupHeaders,
		extraHeaderPrefixes: extraHeaderPrefixes,
	}
}

func trimHeaders(headerNames ...string) ([]string, error) {
	ret := []string{}
	for _, headerName := range headerNames {
		trimmedHeader := strings.TrimSpace(headerName)
		if len(trimmedHeader) == 0 {
			return nil, fmt.Errorf("empty header %q", headerName)
		}
		ret = append(ret, trimmedHeader)
	}

	return ret, nil
}

func NewSecure(clientCA string, proxyClientNames []string, nameHeaders []string, groupHeaders []string, extraHeaderPrefixes []string) (authenticator.Request, error) {
	if len(clientCA) == 0 {
		return nil, fmt.Errorf("missing clientCA file")
	}

	// Wrap with an x509 verifier
	caData, err := ioutil.ReadFile(clientCA)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %v", clientCA, err)
	}
	opts := x509request.DefaultVerifyOptions()
	opts.Roots = x509.NewCertPool()
	certs, err := utilcert.ParseCertsPEM(caData)
	if err != nil {
		return nil, fmt.Errorf("error loading certs from  %s: %v", clientCA, err)
	}
	for _, cert := range certs {
		opts.Roots.AddCert(cert)
	}

	trimmedNameHeaders, err := trimHeaders(nameHeaders...)
	if err != nil {
		return nil, err
	}
	trimmedGroupHeaders, err := trimHeaders(groupHeaders...)
	if err != nil {
		return nil, err
	}
	trimmedExtraHeaderPrefixes, err := trimHeaders(extraHeaderPrefixes...)
	if err != nil {
		return nil, err
	}

	return NewDynamicVerifyOptionsSecure(
		x509request.StaticVerifierFn(opts),
		StaticStringSlice(proxyClientNames),
		StaticStringSlice(trimmedNameHeaders),
		StaticStringSlice(trimmedGroupHeaders),
		StaticStringSlice(trimmedExtraHeaderPrefixes),
	), nil
}

func NewDynamicVerifyOptionsSecure(verifyOptionFn x509request.VerifyOptionFunc, proxyClientNames, nameHeaders, groupHeaders, extraHeaderPrefixes StringSliceProvider) authenticator.Request {
	headerAuthenticator := NewDynamic(nameHeaders, groupHeaders, extraHeaderPrefixes)

	return x509request.NewDynamicCAVerifier(verifyOptionFn, headerAuthenticator, proxyClientNames)
}

// ymjx:
// RequestHeader认证
// Kubernetes可以设置一个认证代理， 客户端发送的认证请求可以 通过认证代理将验证信息发送给kube-apiserver组件。
// RequestHeader 认证使用的就是这种代理方式，它使用请求头将用户名和组信息发送 给kube-apiserver。
// RequestHeader认证有几个列表，分别介绍如下。
// - 用户名列表：建 议 使 用 X-Remote-User ， 如 果 启 用 RequestHeader认证，该参数必选。
// - 组列表： 建议使用X-Remote-Group，如果启用RequestHeader 认证，该参数可选。
// - 额外列表： 建 议 使 用 X-Remote-Extra- ， 如 果 启 用 RequestHeader认证，该参数可选。
// 当客户端发送认证请求时，kube-apiserver根据Header Values中 的用户名列表来识别用户， 例如返回X-Remote-User：Bob则表示验证 成功。
// 1.启用RequestHeader认证
// kube-apiserver通过指定如下参数启用RequestHeader认证。
// --requestheader-client-ca-file ：指定有效的客户端CA证 书。
// --requestheader-allowed-names ：指定通用名称（Common Name）。
// --requestheader-extra-headers-prefix ：指定额外列表。
// --requestheader-group-headers ：指定组列表。
// --requestheader-username-headers ：指定用户名列表。
// kube-apiserver 收 到 客 户 端 验 证 请 求 后 ， 会 先 通 过 -requestheader-client-ca-file参数对客户端证书进行验证。
// --requestheader-username-headers参数指定了Header中包含的 用户名，这一参数中的列表确定了有效的用户名列表，
// 如果该列表为 空， 则所有通过--requestheader-client-ca-file参数校验的请求都 允许通过。
// 2.RequestHeader认证实现
// 在进行RequestHeader认证时， 通过headerValue函数从请求头中 读取所有的用户信息，通过allHeaderValues函数读取所有组的信息，
// 通过newExtra函数读取所有额外的信息。 当用户名无法匹配时， 则认 证失败返回false，反之则认证成功返回true。
func (a *requestHeaderAuthRequestHandler) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	name := headerValue(req.Header, a.nameHeaders.Value())
	if len(name) == 0 {
		return nil, false, nil
	}
	groups := allHeaderValues(req.Header, a.groupHeaders.Value())
	extra := newExtra(req.Header, a.extraHeaderPrefixes.Value())

	// clear headers used for authentication
	for _, headerName := range a.nameHeaders.Value() {
		req.Header.Del(headerName)
	}
	for _, headerName := range a.groupHeaders.Value() {
		req.Header.Del(headerName)
	}
	for k := range extra {
		for _, prefix := range a.extraHeaderPrefixes.Value() {
			req.Header.Del(prefix + k)
		}
	}

	return &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   name,
			Groups: groups,
			Extra:  extra,
		},
	}, true, nil
}

func headerValue(h http.Header, headerNames []string) string {
	for _, headerName := range headerNames {
		headerValue := h.Get(headerName)
		if len(headerValue) > 0 {
			return headerValue
		}
	}
	return ""
}

func allHeaderValues(h http.Header, headerNames []string) []string {
	ret := []string{}
	for _, headerName := range headerNames {
		headerKey := http.CanonicalHeaderKey(headerName)
		values, ok := h[headerKey]
		if !ok {
			continue
		}

		for _, headerValue := range values {
			if len(headerValue) > 0 {
				ret = append(ret, headerValue)
			}
		}
	}
	return ret
}

func unescapeExtraKey(encodedKey string) string {
	key, err := url.PathUnescape(encodedKey) // Decode %-encoded bytes.
	if err != nil {
		return encodedKey // Always record extra strings, even if malformed/unencoded.
	}
	return key
}

func newExtra(h http.Header, headerPrefixes []string) map[string][]string {
	ret := map[string][]string{}

	// we have to iterate over prefixes first in order to have proper ordering inside the value slices
	for _, prefix := range headerPrefixes {
		for headerName, vv := range h {
			if !strings.HasPrefix(strings.ToLower(headerName), strings.ToLower(prefix)) {
				continue
			}

			extraKey := unescapeExtraKey(strings.ToLower(headerName[len(prefix):]))
			ret[extraKey] = append(ret[extraKey], vv...)
		}
	}

	return ret
}
