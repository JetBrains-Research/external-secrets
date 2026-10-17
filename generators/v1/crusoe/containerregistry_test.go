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
)

func TestContainerRegistryKeyGenerate(t *testing.T) {
	const kind = "CrusoeContainerRegistryKey"

	t.Run("nil spec", func(t *testing.T) {
		g := &ContainerRegistryKeyGenerator{}
		_, _, err := g.Generate(context.Background(), nil, newKube(), testNamespace)
		require.ErrorContains(t, err, errNoSpec)
	})

	t.Run("creates a token", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST /v1/ccr/tokens": {status: http.StatusOK, body: `{"token":"ccr-token"}`},
		})
		g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}

		got, state, err := g.Generate(context.Background(), specJSON(kind, api.URL+"/v1/", accessKeyAuth, "  alias: eso-pull\n"), newKube(), testNamespace)
		require.NoError(t, err)
		assert.Nil(t, state)

		wantExpiry := testNow.Add(24 * time.Hour)
		assert.Equal(t, map[string][]byte{
			"token":      []byte("ccr-token"),
			"expires_at": []byte(strconv.FormatInt(wantExpiry.Unix(), 10)),
		}, got)

		reqs := api.recorded()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodPost, reqs[0].method)
		assert.Equal(t, "/v1/ccr/tokens", reqs[0].path)
		assert.Equal(t, map[string]any{
			"alias":      "eso-pull",
			"expires_at": "2026-10-18T12:00:00Z",
		}, reqs[0].body)
		assertSigned(t, reqs[0])
	})

	t.Run("respects expiresAfter", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST /v1/ccr/tokens": {status: http.StatusOK, body: `{"token":"ccr-token"}`},
		})
		g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}

		got, _, err := g.Generate(context.Background(), specJSON(kind, api.URL+"/v1", accessKeyAuth, "  expiresAfter: 90m\n"), newKube(), testNamespace)
		require.NoError(t, err)
		assert.Equal(t, "2026-10-17T13:30:00Z", api.recorded()[0].body["expires_at"])
		assert.Equal(t, []byte(strconv.FormatInt(testNow.Add(90*time.Minute).Unix(), 10)), got["expires_at"])
	})

	t.Run("rejects non-positive expiresAfter", func(t *testing.T) {
		api := newFakeCrusoe(t, nil)
		g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}

		_, _, err := g.Generate(context.Background(), specJSON(kind, api.URL+"/v1", accessKeyAuth, "  expiresAfter: 0s\n"), newKube(), testNamespace)
		require.ErrorContains(t, err, "expiresAfter must be positive")
		assert.Empty(t, api.recorded())
	})

	t.Run("reports API errors", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST /v1/ccr/tokens": {status: http.StatusBadRequest, body: `{"code":"bad_request","message":"expires_at is too far in the future"}`},
		})
		g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}

		_, _, err := g.Generate(context.Background(), specJSON(kind, api.URL+"/v1", accessKeyAuth, ""), newKube(), testNamespace)
		require.ErrorContains(t, err, "400 Bad Request: expires_at is too far in the future")
	})

	t.Run("rejects a response without a token", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST /v1/ccr/tokens": {status: http.StatusOK, body: `{}`},
		})
		g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}

		_, _, err := g.Generate(context.Background(), specJSON(kind, api.URL+"/v1", accessKeyAuth, ""), newKube(), testNamespace)
		require.ErrorContains(t, err, "container registry token missing")
	})
}

func TestContainerRegistryKeyCleanup(t *testing.T) {
	api := newFakeCrusoe(t, nil)
	g := &ContainerRegistryKeyGenerator{base: testBase(api.Client())}

	spec := specJSON("CrusoeContainerRegistryKey", api.URL+"/v1", accessKeyAuth, "")
	err := g.Cleanup(context.Background(), spec, &apiextensions.JSON{Raw: []byte(`{}`)}, newKube(), testNamespace)
	require.NoError(t, err)
	assert.Empty(t, api.recorded())
}
