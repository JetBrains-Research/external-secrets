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
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

const limitedUsagePath = "/v1/users/limited-usage-api-key"

// newLimitedUsageGenerator builds a generator through its public constructor,
// so the tests also cover the kind to usage mapping.
func newLimitedUsageGenerator(t *testing.T, newGenerator func() genv1alpha1.Generator, httpClient *http.Client) *LimitedUsageAPIKeyGenerator {
	t.Helper()
	g, ok := newGenerator().(*LimitedUsageAPIKeyGenerator)
	require.True(t, ok)
	g.base = testBase(httpClient)
	return g
}

func TestLimitedUsageAPIKeyGenerate(t *testing.T) {
	cases := []struct {
		kind         string
		newGenerator func() genv1alpha1.Generator
		usage        string
	}{
		{kind: "CrusoeIntelligenceAPIKey", newGenerator: NewIntelligenceAPIKeyGenerator, usage: "inference"},
		{kind: "CrusoeMonitoringKey", newGenerator: NewMonitoringKeyGenerator, usage: "observability"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			api := newFakeCrusoe(t, map[string]response{
				"POST " + limitedUsagePath: {status: http.StatusOK, body: `{"api_key_info":{
					"alias":"eso","api_key":"secret-api-key","key_id":"key-1",
					"created_at":"2026-10-17T12:00:00Z","expires_at":"2026-10-24T12:00:00Z",
					"project_id":"project-1","usage":"` + tc.usage + `"}}`},
			})
			g := newLimitedUsageGenerator(t, tc.newGenerator, api.Client())

			fields := "  alias: eso\n  projectID: project-1\n  expiresAfter: 168h\n"
			got, state, err := g.Generate(context.Background(), specJSON(tc.kind, api.URL+"/v1", accessKeyAuth, fields), newKube(), testNamespace)
			require.NoError(t, err)

			assert.Equal(t, map[string][]byte{
				"api_key":    []byte("secret-api-key"),
				"key_id":     []byte("key-1"),
				"expires_at": []byte(strconv.FormatInt(testNow.Add(7*24*time.Hour).Unix(), 10)),
			}, got)
			require.NotNil(t, state)
			assert.JSONEq(t, `{"keyID":"key-1"}`, string(state.Raw))

			reqs := api.recorded()
			require.Len(t, reqs, 1)
			assert.Equal(t, http.MethodPost, reqs[0].method)
			assert.Equal(t, limitedUsagePath, reqs[0].path)
			assert.Equal(t, tc.usage, reqs[0].query.Get("usage"))
			assert.Equal(t, map[string]any{
				"alias":      "eso",
				"expires_at": "2026-10-24T12:00:00Z",
				"project_id": "project-1",
			}, reqs[0].body)
			assertSigned(t, reqs[0])
		})
	}

	t.Run("falls back to the requested expiry", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST " + limitedUsagePath: {status: http.StatusOK, body: `{"api_key_info":{"api_key":"secret-api-key","key_id":"key-1"}}`},
		})
		g := newLimitedUsageGenerator(t, NewIntelligenceAPIKeyGenerator, api.Client())

		got, _, err := g.Generate(context.Background(), specJSON("CrusoeIntelligenceAPIKey", api.URL+"/v1", accessKeyAuth, ""), newKube(), testNamespace)
		require.NoError(t, err)
		assert.Equal(t, []byte(strconv.FormatInt(testNow.Add(24*time.Hour).Unix(), 10)), got["expires_at"])
	})

	t.Run("rejects a response without a key", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST " + limitedUsagePath: {status: http.StatusOK, body: `{"api_key_info":{"key_id":"key-1"}}`},
		})
		g := newLimitedUsageGenerator(t, NewMonitoringKeyGenerator, api.Client())

		_, _, err := g.Generate(context.Background(), specJSON("CrusoeMonitoringKey", api.URL+"/v1", accessKeyAuth, ""), newKube(), testNamespace)
		require.ErrorContains(t, err, "observability API key missing")
	})

	t.Run("reports API errors", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST " + limitedUsagePath: {status: http.StatusUnauthorized, body: `{"code":"unauthorized","message":"invalid signature"}`},
		})
		g := newLimitedUsageGenerator(t, NewIntelligenceAPIKeyGenerator, api.Client())

		_, _, err := g.Generate(context.Background(), specJSON("CrusoeIntelligenceAPIKey", api.URL+"/v1", accessKeyAuth, ""), newKube(), testNamespace)
		require.ErrorContains(t, err, "unable to create Crusoe inference API key: 401 Unauthorized: invalid signature")
	})
}

func TestLimitedUsageAPIKeyCleanup(t *testing.T) {
	state := &apiextensions.JSON{Raw: []byte(`{"keyID":"key-1"}`)}
	cases := []struct {
		name    string
		routes  map[string]response
		state   *apiextensions.JSON
		wantErr string
		// wantRequests lists the expected "METHOD path" of each request.
		wantRequests []string
	}{
		{
			name:         "revokes the key",
			routes:       map[string]response{"DELETE " + limitedUsagePath: {status: http.StatusOK, body: `{}`}},
			state:        state,
			wantRequests: []string{"DELETE " + limitedUsagePath},
		},
		{
			name:         "treats a missing key as revoked",
			routes:       map[string]response{"DELETE " + limitedUsagePath: {status: http.StatusNotFound, body: `{}`}},
			state:        state,
			wantRequests: []string{"DELETE " + limitedUsagePath},
		},
		{
			name: "treats an unlisted key as revoked",
			routes: map[string]response{
				"DELETE " + limitedUsagePath: {status: http.StatusInternalServerError, body: `{"code":"internal","message":"key not found"}`},
				"GET " + limitedUsagePath:    {status: http.StatusOK, body: `{"items":[{"key_id":"key-2"}]}`},
			},
			state:        state,
			wantRequests: []string{"DELETE " + limitedUsagePath, "GET " + limitedUsagePath},
		},
		{
			name: "fails when the key still exists",
			routes: map[string]response{
				"DELETE " + limitedUsagePath: {status: http.StatusForbidden, body: `{"code":"forbidden","message":"permission denied"}`},
				"GET " + limitedUsagePath:    {status: http.StatusOK, body: `{"items":[{"key_id":"key-1"}]}`},
			},
			state:        state,
			wantErr:      "unable to revoke Crusoe inference API key key-1: 403 Forbidden: permission denied",
			wantRequests: []string{"DELETE " + limitedUsagePath, "GET " + limitedUsagePath},
		},
		{
			name:  "nothing to revoke without state",
			state: nil,
		},
		{
			name:  "nothing to revoke without a key ID",
			state: &apiextensions.JSON{Raw: []byte(`{}`)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeCrusoe(t, tc.routes)
			g := newLimitedUsageGenerator(t, NewIntelligenceAPIKeyGenerator, api.Client())

			err := g.Cleanup(context.Background(), specJSON("CrusoeIntelligenceAPIKey", api.URL+"/v1", accessKeyAuth, ""), tc.state, newKube(), testNamespace)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}

			reqs := api.recorded()
			var got []string
			for _, req := range reqs {
				got = append(got, req.method+" "+req.path)
				assertSigned(t, req)
			}
			assert.Equal(t, tc.wantRequests, got)
			if len(reqs) > 0 {
				assert.Equal(t, "key-1", reqs[0].query.Get("key_id"))
			}
		})
	}
}
