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

package tokenfile

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/klog/v2"
)

type TokenAuthenticator struct {
	tokens map[string]*user.DefaultInfo
}

// New returns a TokenAuthenticator for a single token
func New(tokens map[string]*user.DefaultInfo) *TokenAuthenticator {
	return &TokenAuthenticator{
		tokens: tokens,
	}
}

// NewCSV returns a TokenAuthenticator, populated from a CSV file.
// The CSV file must contain records in the format "token,username,useruid"
func NewCSV(path string) (*TokenAuthenticator, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	recordNum := 0
	tokens := make(map[string]*user.DefaultInfo)
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) < 3 {
			return nil, fmt.Errorf("token file '%s' must have at least 3 columns (token, user name, user uid), found %d", path, len(record))
		}

		recordNum++
		if record[0] == "" {
			klog.Warningf("empty token has been found in token file '%s', record number '%d'", path, recordNum)
			continue
		}

		obj := &user.DefaultInfo{
			Name: record[1],
			UID:  record[2],
		}
		if _, exist := tokens[record[0]]; exist {
			klog.Warningf("duplicate token has been found in token file '%s', record number '%d'", path, recordNum)
		}
		tokens[record[0]] = obj

		if len(record) >= 4 {
			obj.Groups = strings.Split(record[3], ",")
		}
	}

	return &TokenAuthenticator{
		tokens: tokens,
	}, nil
}

// AuthenticateToken
// ymjx:
// Token也被称为令牌，服务端为了验证客户端的身份，需要客户端 向服务端提供一个可靠的验证信息， 这个验证信息就是Token。
// TokenAuth是基于Token的认证，Token一般是一个字符串。
// 1.启用TokenAuth认证
// kube-apiserver通过指定--token-auth-file参数启用TokenAuth 认证。
// TOKEN_FILE是一个CSV文件， 每个用户在CSV中的表现形式为 token、user、userid、group ，示例如下：
// a0d715cf548£6659662f2b8019614164,kubelet-bootstrap, 10001, "system:kubelet-bootstrap"
// 2.Token认证实现
// 在进行Token认证时， a.tokens中存储了服务端的Token列表， 通 过a.tokens查询客户端提供的Token，
// 如果查询不到，则认证失败返回 false，反之则认证成功返回true。
func (a *TokenAuthenticator) AuthenticateToken(ctx context.Context, value string) (*authenticator.Response, bool, error) {
	user, ok := a.tokens[value]
	if !ok {
		return nil, false, nil
	}
	return &authenticator.Response{User: user}, true, nil
}
