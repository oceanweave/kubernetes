/*
Copyright 2015 The Kubernetes Authors.

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

/*
oidc implements the authenticator.Token interface using the OpenID Connect protocol.

	config := oidc.Options{
		IssuerURL:     "https://accounts.google.com",
		ClientID:      os.Getenv("GOOGLE_CLIENT_ID"),
		UsernameClaim: "email",
	}
	tokenAuthenticator, err := oidc.New(config)
*/
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc"

	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
)

var (
	// synchronizeTokenIDVerifierForTest should be set to true to force a
	// wait until the token ID verifiers are ready.
	synchronizeTokenIDVerifierForTest = false
)

type Options struct {
	// IssuerURL is the URL the provider signs ID Tokens as. This will be the "iss"
	// field of all tokens produced by the provider and is used for configuration
	// discovery.
	//
	// The URL is usually the provider's URL without a path, for example
	// "https://accounts.google.com" or "https://login.salesforce.com".
	//
	// The provider must implement configuration discovery.
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	IssuerURL string

	// Optional KeySet to allow for synchronous initialization instead of fetching from the remote issuer.
	KeySet oidc.KeySet

	// ClientID the JWT must be issued for, the "sub" field. This plugin only trusts a single
	// client to ensure the plugin can be used with public providers.
	//
	// The plugin supports the "authorized party" OpenID Connect claim, which allows
	// specialized providers to issue tokens to a client for a different client.
	// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	ClientID string

	// PEM encoded root certificate contents of the provider.  Mutually exclusive with Client.
	CAContentProvider CAContentProvider

	// Optional http.Client used to make all requests to the remote issuer.  Mutually exclusive with CAContentProvider.
	Client *http.Client

	// UsernameClaim is the JWT field to use as the user's username.
	UsernameClaim string

	// UsernamePrefix, if specified, causes claims mapping to username to be prefix with
	// the provided value. A value "oidc:" would result in usernames like "oidc:john".
	UsernamePrefix string

	// GroupsClaim, if specified, causes the OIDCAuthenticator to try to populate the user's
	// groups with an ID Token field. If the GroupsClaim field is present in an ID Token the value
	// must be a string or list of strings.
	GroupsClaim string

	// GroupsPrefix, if specified, causes claims mapping to group names to be prefixed with the
	// value. A value "oidc:" would result in groups like "oidc:engineering" and "oidc:marketing".
	GroupsPrefix string

	// SupportedSigningAlgs sets the accepted set of JOSE signing algorithms that
	// can be used by the provider to sign tokens.
	//
	// https://tools.ietf.org/html/rfc7518#section-3.1
	//
	// This value defaults to RS256, the value recommended by the OpenID Connect
	// spec:
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
	SupportedSigningAlgs []string

	// RequiredClaims, if specified, causes the OIDCAuthenticator to verify that all the
	// required claims key value pairs are present in the ID Token.
	RequiredClaims map[string]string

	// now is used for testing. It defaults to time.Now.
	now func() time.Time
}

// Subset of dynamiccertificates.CAContentProvider that can be used to dynamically load root CAs.
type CAContentProvider interface {
	CurrentCABundleContent() []byte
}

// initVerifier creates a new ID token verifier for the given configuration and issuer URL.  On success, calls setVerifier with the
// resulting verifier.
func initVerifier(ctx context.Context, config *oidc.Config, iss string) (*oidc.IDTokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, iss)
	if err != nil {
		return nil, fmt.Errorf("init verifier failed: %v", err)
	}
	return provider.Verifier(config), nil
}

// asyncIDTokenVerifier is an ID token verifier that allows async initialization
// of the issuer check.  Must be passed by reference as it wraps sync.Mutex.
type asyncIDTokenVerifier struct {
	m sync.Mutex

	// v is the ID token verifier initialized asynchronously.  It remains nil
	// up until it is eventually initialized.
	// Guarded by m
	v *oidc.IDTokenVerifier
}

// newAsyncIDTokenVerifier creates a new asynchronous token verifier.  The
// verifier is available immediately, but may remain uninitialized for some time
// after creation.
func newAsyncIDTokenVerifier(ctx context.Context, c *oidc.Config, iss string) *asyncIDTokenVerifier {
	t := &asyncIDTokenVerifier{}

	sync := make(chan struct{})
	// Polls indefinitely in an attempt to initialize the distributed claims
	// verifier, or until context canceled.
	initFn := func() (done bool, err error) {
		klog.V(4).Infof("oidc authenticator: attempting init: iss=%v", iss)
		v, err := initVerifier(ctx, c, iss)
		if err != nil {
			klog.Errorf("oidc authenticator: async token verifier for issuer: %q: %v", iss, err)
			return false, nil
		}
		t.m.Lock()
		defer t.m.Unlock()
		t.v = v
		close(sync)
		return true, nil
	}

	go func() {
		if done, _ := initFn(); !done {
			go wait.PollUntil(time.Second*10, initFn, ctx.Done())
		}
	}()

	if synchronizeTokenIDVerifierForTest {
		<-sync
	}

	return t
}

// verifier returns the underlying ID token verifier, or nil if one is not yet initialized.
func (a *asyncIDTokenVerifier) verifier() *oidc.IDTokenVerifier {
	a.m.Lock()
	defer a.m.Unlock()
	return a.v
}

type Authenticator struct {
	issuerURL string

	usernameClaim  string
	usernamePrefix string
	groupsClaim    string
	groupsPrefix   string
	requiredClaims map[string]string

	// Contains an *oidc.IDTokenVerifier. Do not access directly use the
	// idTokenVerifier method.
	verifier atomic.Value

	cancel context.CancelFunc

	// resolver is used to resolve distributed claims.
	resolver *claimResolver
}

func (a *Authenticator) setVerifier(v *oidc.IDTokenVerifier) {
	a.verifier.Store(v)
}

func (a *Authenticator) idTokenVerifier() (*oidc.IDTokenVerifier, bool) {
	if v := a.verifier.Load(); v != nil {
		return v.(*oidc.IDTokenVerifier), true
	}
	return nil, false
}

func (a *Authenticator) Close() {
	a.cancel()
}

// whitelist of signing algorithms to ensure users don't mistakenly pass something
// goofy.
var allowedSigningAlgs = map[string]bool{
	oidc.RS256: true,
	oidc.RS384: true,
	oidc.RS512: true,
	oidc.ES256: true,
	oidc.ES384: true,
	oidc.ES512: true,
	oidc.PS256: true,
	oidc.PS384: true,
	oidc.PS512: true,
}

func New(opts Options) (*Authenticator, error) {
	url, err := url.Parse(opts.IssuerURL)
	if err != nil {
		return nil, err
	}

	if url.Scheme != "https" {
		return nil, fmt.Errorf("'oidc-issuer-url' (%q) has invalid scheme (%q), require 'https'", opts.IssuerURL, url.Scheme)
	}

	if opts.UsernameClaim == "" {
		return nil, errors.New("no username claim provided")
	}

	supportedSigningAlgs := opts.SupportedSigningAlgs
	if len(supportedSigningAlgs) == 0 {
		// RS256 is the default recommended by OpenID Connect and an 'alg' value
		// providers are required to implement.
		supportedSigningAlgs = []string{oidc.RS256}
	}
	for _, alg := range supportedSigningAlgs {
		if !allowedSigningAlgs[alg] {
			return nil, fmt.Errorf("oidc: unsupported signing alg: %q", alg)
		}
	}

	if opts.Client != nil && opts.CAContentProvider != nil {
		return nil, fmt.Errorf("oidc: Client and CAContentProvider are mutually exclusive")
	}

	client := opts.Client

	if client == nil {
		var roots *x509.CertPool
		if opts.CAContentProvider != nil {
			// TODO(enj): make this reload CA data dynamically
			roots, err = certutil.NewPoolFromBytes(opts.CAContentProvider.CurrentCABundleContent())
			if err != nil {
				return nil, fmt.Errorf("Failed to read the CA contents: %v", err)
			}
		} else {
			klog.Info("OIDC: No x509 certificates provided, will use host's root CA set")
		}

		// Copied from http.DefaultTransport.
		tr := net.SetTransportDefaults(&http.Transport{
			// According to golang's doc, if RootCAs is nil,
			// TLS uses the host's root CA set.
			TLSClientConfig: &tls.Config{RootCAs: roots},
		})

		client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oidc.ClientContext(ctx, client)

	now := opts.now
	if now == nil {
		now = time.Now
	}

	verifierConfig := &oidc.Config{
		ClientID:             opts.ClientID,
		SupportedSigningAlgs: supportedSigningAlgs,
		Now:                  now,
	}

	var resolver *claimResolver
	if opts.GroupsClaim != "" {
		resolver = newClaimResolver(opts.GroupsClaim, client, verifierConfig)
	}

	authenticator := &Authenticator{
		issuerURL:      opts.IssuerURL,
		usernameClaim:  opts.UsernameClaim,
		usernamePrefix: opts.UsernamePrefix,
		groupsClaim:    opts.GroupsClaim,
		groupsPrefix:   opts.GroupsPrefix,
		requiredClaims: opts.RequiredClaims,
		cancel:         cancel,
		resolver:       resolver,
	}

	if opts.KeySet != nil {
		// We already have a key set, synchronously initialize the verifier.
		authenticator.setVerifier(oidc.NewVerifier(opts.IssuerURL, opts.KeySet, verifierConfig))
	} else {
		// Asynchronously attempt to initialize the authenticator. This enables
		// self-hosted providers, providers that run on top of Kubernetes itself.
		go wait.PollImmediateUntil(10*time.Second, func() (done bool, err error) {
			provider, err := oidc.NewProvider(ctx, opts.IssuerURL)
			if err != nil {
				klog.Errorf("oidc authenticator: initializing plugin: %v", err)
				return false, nil
			}

			verifier := provider.Verifier(verifierConfig)
			authenticator.setVerifier(verifier)
			return true, nil
		}, ctx.Done())
	}

	return authenticator, nil
}

// untrustedIssuer extracts an untrusted "iss" claim from the given JWT token,
// or returns an error if the token can not be parsed.  Since the JWT is not
// verified, the returned issuer should not be trusted.
func untrustedIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("error decoding token: %v", err)
	}
	claims := struct {
		// WARNING: this JWT is not verified. Do not trust these claims.
		Issuer string `json:"iss"`
	}{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("while unmarshaling token: %v", err)
	}
	// Coalesce the legacy GoogleIss with the new one.
	//
	// http://openid.net/specs/openid-connect-core-1_0.html#GoogleIss
	if claims.Issuer == "accounts.google.com" {
		return "https://accounts.google.com", nil
	}
	return claims.Issuer, nil
}

func hasCorrectIssuer(iss, tokenData string) bool {
	uiss, err := untrustedIssuer(tokenData)
	if err != nil {
		return false
	}
	if uiss != iss {
		return false
	}
	return true
}

// endpoint represents an OIDC distributed claims endpoint.
type endpoint struct {
	// URL to use to request the distributed claim.  This URL is expected to be
	// prefixed by one of the known issuer URLs.
	URL string `json:"endpoint,omitempty"`
	// AccessToken is the bearer token to use for access.  If empty, it is
	// not used.  Access token is optional per the OIDC distributed claims
	// specification.
	// See: http://openid.net/specs/openid-connect-core-1_0.html#DistributedExample
	AccessToken string `json:"access_token,omitempty"`
	// JWT is the container for aggregated claims.  Not supported at the moment.
	// See: http://openid.net/specs/openid-connect-core-1_0.html#AggregatedExample
	JWT string `json:"JWT,omitempty"`
}

// claimResolver expands distributed claims by calling respective claim source
// endpoints.
type claimResolver struct {
	// claim is the distributed claim that may be resolved.
	claim string

	// client is the to use for resolving distributed claims
	client *http.Client

	// config is the OIDC configuration used for resolving distributed claims.
	config *oidc.Config

	// verifierPerIssuer contains, for each issuer, the appropriate verifier to use
	// for this claim.  It is assumed that there will be very few entries in
	// this map.
	// Guarded by m.
	verifierPerIssuer map[string]*asyncIDTokenVerifier

	m sync.Mutex
}

// newClaimResolver creates a new resolver for distributed claims.
func newClaimResolver(claim string, client *http.Client, config *oidc.Config) *claimResolver {
	return &claimResolver{claim: claim, client: client, config: config, verifierPerIssuer: map[string]*asyncIDTokenVerifier{}}
}

// Verifier returns either the verifier for the specified issuer, or error.
func (r *claimResolver) Verifier(iss string) (*oidc.IDTokenVerifier, error) {
	r.m.Lock()
	av := r.verifierPerIssuer[iss]
	if av == nil {
		// This lazy init should normally be very quick.
		// TODO: Make this context cancelable.
		ctx := oidc.ClientContext(context.Background(), r.client)
		av = newAsyncIDTokenVerifier(ctx, r.config, iss)
		r.verifierPerIssuer[iss] = av
	}
	r.m.Unlock()

	v := av.verifier()
	if v == nil {
		return nil, fmt.Errorf("verifier not initialized for issuer: %q", iss)
	}
	return v, nil
}

// expand extracts the distributed claims from claim names and claim sources.
// The extracted claim value is pulled up into the supplied claims.
//
// Distributed claims are of the form as seen below, and are defined in the
// OIDC Connect Core 1.0, section 5.6.2.
// See: https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
//
// {
//   ... (other normal claims)...
//   "_claim_names": {
//     "groups": "src1"
//   },
//   "_claim_sources": {
//     "src1": {
//       "endpoint": "https://www.example.com",
//       "access_token": "f005ba11"
//     },
//   },
// }
func (r *claimResolver) expand(c claims) error {
	const (
		// The claim containing a map of endpoint references per claim.
		// OIDC Connect Core 1.0, section 5.6.2.
		claimNamesKey = "_claim_names"
		// The claim containing endpoint specifications.
		// OIDC Connect Core 1.0, section 5.6.2.
		claimSourcesKey = "_claim_sources"
	)

	_, ok := c[r.claim]
	if ok {
		// There already is a normal claim, skip resolving.
		return nil
	}
	names, ok := c[claimNamesKey]
	if !ok {
		// No _claim_names, no keys to look up.
		return nil
	}

	claimToSource := map[string]string{}
	if err := json.Unmarshal([]byte(names), &claimToSource); err != nil {
		return fmt.Errorf("oidc: error parsing distributed claim names: %v", err)
	}

	rawSources, ok := c[claimSourcesKey]
	if !ok {
		// Having _claim_names claim,  but no _claim_sources is not an expected
		// state.
		return fmt.Errorf("oidc: no claim sources")
	}

	var sources map[string]endpoint
	if err := json.Unmarshal([]byte(rawSources), &sources); err != nil {
		// The claims sources claim is malformed, this is not an expected state.
		return fmt.Errorf("oidc: could not parse claim sources: %v", err)
	}

	src, ok := claimToSource[r.claim]
	if !ok {
		// No distributed claim present.
		return nil
	}
	ep, ok := sources[src]
	if !ok {
		return fmt.Errorf("id token _claim_names contained a source %s missing in _claims_sources", src)
	}
	if ep.URL == "" {
		// This is maybe an aggregated claim (ep.JWT != "").
		return nil
	}
	return r.resolve(ep, c)
}

// resolve requests distributed claims from all endpoints passed in,
// and inserts the lookup results into allClaims.
func (r *claimResolver) resolve(endpoint endpoint, allClaims claims) error {
	// TODO: cache resolved claims.
	jwt, err := getClaimJWT(r.client, endpoint.URL, endpoint.AccessToken)
	if err != nil {
		return fmt.Errorf("while getting distributed claim %q: %v", r.claim, err)
	}
	untrustedIss, err := untrustedIssuer(jwt)
	if err != nil {
		return fmt.Errorf("getting untrusted issuer from endpoint %v failed for claim %q: %v", endpoint.URL, r.claim, err)
	}
	v, err := r.Verifier(untrustedIss)
	if err != nil {
		return fmt.Errorf("verifying untrusted issuer %v failed: %v", untrustedIss, err)
	}
	t, err := v.Verify(context.Background(), jwt)
	if err != nil {
		return fmt.Errorf("verify distributed claim token: %v", err)
	}
	var distClaims claims
	if err := t.Claims(&distClaims); err != nil {
		return fmt.Errorf("could not parse distributed claims for claim %v: %v", r.claim, err)
	}
	value, ok := distClaims[r.claim]
	if !ok {
		return fmt.Errorf("jwt returned by distributed claim endpoint %q did not contain claim: %v", endpoint.URL, r.claim)
	}
	allClaims[r.claim] = value
	return nil
}

// ymjx:
// OIDC认证
// OIDC（OpenID Connect）是一套基于OAuth 2.0协议的轻量级认证 规范，其提供了通过API进行身份交互的框架。
// OIDC认证除了认证请求 外， 还会标明请求的用户身份（ID Token）。
// 其中Token被称为ID Token，此ID Token是JSON Web Token （JWT），具有由服务器签名的 相关字段。
// OIDC认证流程介绍如下。
// （1）Kubernetes用户想访问Kubernetes API Server，先通过认证服务（AuthServer，例如GoogleAccounts服务）认证自己，
//     得到access_token、id_token和refresh_token。
// （2） Kubernetes 用户把access_token、id_token和refresh_token配置到客户端应用程序（如kubectl或dashboard工具 等）中。
// （3）Kubernetes客户端使用Token以用户的身份访问Kubernetes API Server。
// Kubernetes API Server和Auth Server并没有直接进行交互， 而是鉴定客户端发送的Token是否为合法Token。下面详细描述 Kubernetes Authentication OIDC Token的完整过程
// （1）用户登录到身份提供商（即Auth Server， 例如Google Accounts服务）。
// （2） 用户的身份提供商将提供 access_token 、 id_token 和 refresh_token。
// （3）用户使用kubectl工具，通过--token参数指定id_token，或 者将id_token写入kubeconfig文件中。
// （4）kubectl工具将id_token设置为Authorization的请求头并发 送给Kubernetes API Server。
// （5）Kubernetes API Server将通过检查配置文件中指定的证书 来确保JWT签名有效。
// （6）检查并确保id_token未过期。
// （7）检查并确保用户已获得授权。
// （8）获得授权后，Kubernetes API Server会响应kubectl工具。
// （9）kubectl工具向用户提供反馈。
// 重点！！！
// Kubernetes API Server不与Auth Server交互就能够认证Token的 合法性， 其关键在于第（5）步， 所有JWT Token都由颁发它的 Auth Service进行了数字签名，
// 只需在Kubernetes API Server中配置信任 的Auth Server的证书，并用它来验证收到的id_token中的签名是否合 法， 这样就可以验证Token的合法性。
// 使用这种基于PKI的验证机制， 在配置完成并进行认证的过程中，Kubernetes API Server无须与Auth Server有任何交互。
//
// 1.启用OIDC认证 kube-apiserver通过指定如下参数启用OIDC认证。
// --oidc-ca-file ：签署身份提供商的CA证书的路径，默认值为主机的根CA证书的路径（即 /etc/kubernetes/ssl/kcca.pem）。
// --oidc-client-id：颁发所有Token的Client ID。
// --oidc-groups-claim : JWT (JSON Web Token）声明的用户组名称。
// --oidc-groups-prefix ：组名前缀，所有组都将以此值为前缀，以避免与其他身份验证策略发生冲突。
// --oidc-issuer-url： Auth Server服务的URL地址，例如使用 Google Accounts服务。
// --oidc-required-claim：该参数是键值对，用于描述I Token中的必要声明。如果设置该参数，则验证声明是否以匹配值存在于ID Token中。重复指定该参数可以设置多个声明。
// --oide-signing-algs：JOSE非对称签名算法列表，算法以逗号分隔。如果以alg开头的JWT请求不在此列表中，请求会被拒绝（默认值为[RS256])。
// --oide-username-claim：JWT （JSON Web Token）声明的用户名称（默认值为sub）。
// --oidc-username-prefix：用户名前缀，所有用户名都将以此值为前缀，以避免与其他身份验证策略发生冲突。如果要跳过任何前缀，请设置该参数值为一。
// 2. OIDC认证实现
// 在进行OIDC认证时， 通过verifier.Verify函数验证接收到的 id_token中的签名是否合法，
// 如果不合法则认证失败返回false，如果 合法则认证成功返回true。
func (a *Authenticator) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	if !hasCorrectIssuer(a.issuerURL, token) {
		return nil, false, nil
	}

	verifier, ok := a.idTokenVerifier()
	if !ok {
		return nil, false, fmt.Errorf("oidc: authenticator not initialized")
	}

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, false, fmt.Errorf("oidc: verify token: %v", err)
	}

	var c claims
	if err := idToken.Claims(&c); err != nil {
		return nil, false, fmt.Errorf("oidc: parse claims: %v", err)
	}
	if a.resolver != nil {
		if err := a.resolver.expand(c); err != nil {
			return nil, false, fmt.Errorf("oidc: could not expand distributed claims: %v", err)
		}
	}

	var username string
	if err := c.unmarshalClaim(a.usernameClaim, &username); err != nil {
		return nil, false, fmt.Errorf("oidc: parse username claims %q: %v", a.usernameClaim, err)
	}

	if a.usernameClaim == "email" {
		// If the email_verified claim is present, ensure the email is valid.
		// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
		if hasEmailVerified := c.hasClaim("email_verified"); hasEmailVerified {
			var emailVerified bool
			if err := c.unmarshalClaim("email_verified", &emailVerified); err != nil {
				return nil, false, fmt.Errorf("oidc: parse 'email_verified' claim: %v", err)
			}

			// If the email_verified claim is present we have to verify it is set to `true`.
			if !emailVerified {
				return nil, false, fmt.Errorf("oidc: email not verified")
			}
		}
	}

	if a.usernamePrefix != "" {
		username = a.usernamePrefix + username
	}

	info := &user.DefaultInfo{Name: username}
	if a.groupsClaim != "" {
		if _, ok := c[a.groupsClaim]; ok {
			// Some admins want to use string claims like "role" as the group value.
			// Allow the group claim to be a single string instead of an array.
			//
			// See: https://github.com/kubernetes/kubernetes/issues/33290
			var groups stringOrArray
			if err := c.unmarshalClaim(a.groupsClaim, &groups); err != nil {
				return nil, false, fmt.Errorf("oidc: parse groups claim %q: %v", a.groupsClaim, err)
			}
			info.Groups = []string(groups)
		}
	}

	if a.groupsPrefix != "" {
		for i, group := range info.Groups {
			info.Groups[i] = a.groupsPrefix + group
		}
	}

	// check to ensure all required claims are present in the ID token and have matching values.
	for claim, value := range a.requiredClaims {
		if !c.hasClaim(claim) {
			return nil, false, fmt.Errorf("oidc: required claim %s not present in ID token", claim)
		}

		// NOTE: Only string values are supported as valid required claim values.
		var claimValue string
		if err := c.unmarshalClaim(claim, &claimValue); err != nil {
			return nil, false, fmt.Errorf("oidc: parse claim %s: %v", claim, err)
		}
		if claimValue != value {
			return nil, false, fmt.Errorf("oidc: required claim %s value does not match. Got = %s, want = %s", claim, claimValue, value)
		}
	}

	return &authenticator.Response{User: info}, true, nil
}

// getClaimJWT gets a distributed claim JWT from url, using the supplied access
// token as bearer token.  If the access token is "", the authorization header
// will not be set.
// TODO: Allow passing in JSON hints to the IDP.
func getClaimJWT(client *http.Client, url, accessToken string) (string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO: Allow passing request body with configurable information.
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("while calling %v: %v", url, err)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", accessToken))
	}
	req = req.WithContext(ctx)
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	// Report non-OK status code as an error.
	if response.StatusCode < http.StatusOK || response.StatusCode > http.StatusIMUsed {
		return "", fmt.Errorf("error while getting distributed claim JWT: %v", response.Status)
	}
	defer response.Body.Close()
	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("could not decode distributed claim response")
	}
	return string(responseBytes), nil
}

type stringOrArray []string

func (s *stringOrArray) UnmarshalJSON(b []byte) error {
	var a []string
	if err := json.Unmarshal(b, &a); err == nil {
		*s = a
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = []string{str}
	return nil
}

type claims map[string]json.RawMessage

func (c claims) unmarshalClaim(name string, v interface{}) error {
	val, ok := c[name]
	if !ok {
		return fmt.Errorf("claim not present")
	}
	return json.Unmarshal([]byte(val), v)
}

func (c claims) hasClaim(name string) bool {
	if _, ok := c[name]; !ok {
		return false
	}
	return true
}
