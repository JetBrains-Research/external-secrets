/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crusoe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace    = "crusoe"
	testSecretName   = "crusoe-credentials"
	testAccessKeyID  = "test-access-key-id"
	testClientID     = "test-client-id"
	testClientSecret = "test-client-secret"
	testAccessToken  = "test-oauth2-access-token"
)

var (
	testSecretKey = base64.RawURLEncoding.EncodeToString([]byte("test-secret-key-material"))
	testNow       = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
)

const accessKeyAuth = `  auth:
    accessKey:
      accessKeyIDSecretRef:
        name: crusoe-credentials
        key: access-key-id
      secretKeySecretRef:
        name: crusoe-credentials
        key: secret-key
`

func serviceAccountAuth(tokenURL, audience string) string {
	return fmt.Sprintf(`  auth:
    serviceAccount:
      clientIDSecretRef:
        name: crusoe-credentials
        key: client-id
      clientSecretSecretRef:
        name: crusoe-credentials
        key: client-secret
      tokenURL: %q
      audience: %q
`, tokenURL, audience)
}

// newKube returns a client holding the seed credentials. The secret key has a
// trailing newline, as it would when created with kubectl --from-file.
func newKube() client.Client {
	return clientfake.NewClientBuilder().WithObjects(&corev1.Secret{
		Name:      testSecretName,
		Namespace: testNamespace,
		Data: map[string][]byte{
			"access-key-id": []byte(testAccessKeyID),
			"secret-key":    []byte(testSecretKey + "\n"),
			"client-id":     []byte(testClientID),
			"client-secret": []byte(testClientSecret),
		},
	}).Build()
}

// specJSON renders a generator manifest. auth and fields are YAML fragments
// indented to sit under spec.
func specJSON(kind, apiURL, auth, fields string) *apiextensions.JSON {
	raw := fmt.Sprintf(`apiVersion: generators.external-secrets.io/v1alpha1
kind: %s
spec:
  apiURL: %q
%s%s`, kind, apiURL, auth, fields)
	return &apiextensions.JSON{Raw: []byte(raw)}
}

type recordedRequest struct {
	method string
	path   string
	query  url.Values
	header http.Header
	body   map[string]any
}

type response struct {
	status int
	body   string
}

// fakeCrusoe mimics the Crusoe Cloud API. Routes are keyed by "METHOD /path".
type fakeCrusoe struct {
	*httptest.Server
	t      *testing.T
	routes map[string]response

	mu       sync.Mutex
	requests []recordedRequest
}

func newFakeCrusoe(t *testing.T, routes map[string]response) *fakeCrusoe {
	f := &fakeCrusoe{t: t, routes: routes}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// newTLSFakeCrusoe serves over TLS, as the service account token URL must be https.
func newTLSFakeCrusoe(t *testing.T, routes map[string]response) *fakeCrusoe {
	f := &fakeCrusoe{t: t, routes: routes}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeCrusoe) serve(rw http.ResponseWriter, req *http.Request) {
	rec := recordedRequest{
		method: req.Method,
		path:   req.URL.Path,
		query:  req.URL.Query(),
		header: req.Header.Clone(),
	}
	raw, _ := io.ReadAll(req.Body)
	if req.Header.Get("Content-Type") == "application/json" && len(raw) > 0 {
		require.NoError(f.t, json.Unmarshal(raw, &rec.body))
	} else if len(raw) > 0 {
		form, err := url.ParseQuery(string(raw))
		require.NoError(f.t, err)
		rec.body = map[string]any{}
		for k := range form {
			rec.body[k] = form.Get(k)
		}
	}
	f.mu.Lock()
	f.requests = append(f.requests, rec)
	f.mu.Unlock()

	route, ok := f.routes[req.Method+" "+req.URL.Path]
	if !ok {
		route = response{status: http.StatusNotFound, body: `{"code":"not_found","message":"no such route"}`}
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(route.status)
	_, _ = rw.Write([]byte(route.body))
}

func (f *fakeCrusoe) recorded() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.requests...)
}

// assertSigned verifies the Crusoe HMAC request signature independently of
// the client library.
func assertSigned(t *testing.T, req recordedRequest) {
	t.Helper()
	timestamp := req.header.Get("X-Crusoe-Timestamp")
	require.NotEmpty(t, timestamp)
	parts := strings.Split(strings.TrimPrefix(req.header.Get("Authorization"), "Bearer "), ":")
	require.Len(t, parts, 3)
	assert.Equal(t, "1.0", parts[0])
	assert.Equal(t, testAccessKeyID, parts[1])

	key, err := base64.RawURLEncoding.DecodeString(testSecretKey)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(req.path + "\n" + req.query.Encode() + "\n" + req.method + "\n" + timestamp + "\n"))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), parts[2])
}

func testBase(httpClient *http.Client) base {
	return base{httpClient: httpClient, now: func() time.Time { return testNow }}
}

func TestServiceAccountAuth(t *testing.T) {
	cases := []struct {
		name     string
		audience string
		want     string
	}{
		{name: "default audience", want: "https://api.crusoe.ai"},
		{name: "custom audience", audience: "https://api.staging.example", want: "https://api.staging.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newTLSFakeCrusoe(t, map[string]response{
				"POST /oauth2/token":  {status: http.StatusOK, body: fmt.Sprintf(`{"access_token":%q,"token_type":"bearer","expires_in":3600}`, testAccessToken)},
				"POST /v1/ccr/tokens": {status: http.StatusOK, body: `{"token":"ccr-token"}`},
			})
			g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}

			spec := specJSON("CrusoeContainerRegistryKey", api.URL+"/v1", serviceAccountAuth(api.URL+"/oauth2/token", tc.audience), "")
			got, _, err := g.Generate(context.Background(), spec, newKube(), testNamespace)
			require.NoError(t, err)
			assert.Equal(t, []byte("ccr-token"), got["token"])

			reqs := api.recorded()
			require.Len(t, reqs, 2)
			tokenReq, apiReq := reqs[0], reqs[1]
			assert.Equal(t, "/oauth2/token", tokenReq.path)
			assert.Equal(t, "client_credentials", tokenReq.body["grant_type"])
			assert.Equal(t, tc.want, tokenReq.body["audience"])
			wantBasic := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
			assert.Equal(t, "Basic "+wantBasic, tokenReq.header.Get("Authorization"))

			assert.Equal(t, "/v1/ccr/tokens", apiReq.path)
			assert.Equal(t, "Bearer "+testAccessToken, apiReq.header.Get("Authorization"))
			assert.Empty(t, apiReq.header.Get("X-Crusoe-Timestamp"))
		})
	}
}

func TestAuthErrors(t *testing.T) {
	cases := []struct {
		name    string
		auth    string
		wantErr string
	}{
		{
			name:    "no authentication method",
			auth:    "  auth: {}\n",
			wantErr: "no Crusoe authentication method configured",
		},
		{
			name: "missing secret key",
			auth: `  auth:
    accessKey:
      accessKeyIDSecretRef:
        name: crusoe-credentials
        key: access-key-id
      secretKeySecretRef:
        name: crusoe-credentials
        key: does-not-exist
`,
			wantErr: "unable to get Crusoe secret key",
		},
		{
			name:    "insecure token URL",
			auth:    serviceAccountAuth("http://auth.example/oauth2/token", ""),
			wantErr: "tokenURL must be an https:// URL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeCrusoe(t, nil)
			g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}
			_, _, err := g.Generate(context.Background(), specJSON("CrusoeContainerRegistryKey", api.URL+"/v1", tc.auth, ""), newKube(), testNamespace)
			require.ErrorContains(t, err, tc.wantErr)
			assert.Empty(t, api.recorded())
		})
	}
}

// TestDefaultClientUntouched guards against client-go's NewAuthenticatedConfig,
// which installs request signing on http.DefaultClient for the whole process.
func TestDefaultClientUntouched(t *testing.T) {
	before := http.DefaultClient.Transport
	api := newFakeCrusoe(t, map[string]response{
		"POST /v1/ccr/tokens": {status: http.StatusOK, body: `{"token":"ccr-token"}`},
	})
	g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}
	_, _, err := g.Generate(context.Background(), specJSON("CrusoeContainerRegistryKey", api.URL+"/v1", accessKeyAuth, ""), newKube(), testNamespace)
	require.NoError(t, err)
	assert.True(t, before == http.DefaultClient.Transport, "http.DefaultClient.Transport was modified")
}

func TestKinds(t *testing.T) {
	assert.Equal(t, "CrusoeContainerRegistryKey", ContainerRegistryKeyKind())
	assert.Equal(t, "CrusoeIntelligenceAPIKey", IntelligenceAPIKeyKind())
	assert.Equal(t, "CrusoeMonitoringKey", MonitoringKeyKind())
	assert.Equal(t, "CrusoeObjectStorageKey", ObjectStorageKeyKind())
}
