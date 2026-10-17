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

const (
	objectStorageKind = "CrusoeObjectStorageKey"
	s3KeysPath        = "/v1/organizations/org-1/storage/s3/keys"
	orgField          = "  organizationID: org-1\n"
)

func TestObjectStorageKeyGenerate(t *testing.T) {
	t.Run("creates a key", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST " + s3KeysPath: {status: http.StatusOK, body: `{"access_key_id":"S3U_key","secret_key":"s3-secret","expire_at":"2026-10-18T11:00:00Z"}`},
		})
		g := &ObjectStorageKeyGenerator{base: testBase(api.Client())}

		got, state, err := g.Generate(context.Background(), specJSON(objectStorageKind, api.URL+"/v1", accessKeyAuth, orgField+"  alias: eso-s3\n"), newKube(), testNamespace)
		require.NoError(t, err)

		assert.Equal(t, map[string][]byte{
			"access_key_id":     []byte("S3U_key"),
			"secret_access_key": []byte("s3-secret"),
			"expires_at":        []byte(strconv.FormatInt(testNow.Add(23*time.Hour).Unix(), 10)),
		}, got)
		require.NotNil(t, state)
		assert.JSONEq(t, `{"accessKeyID":"S3U_key"}`, string(state.Raw))

		reqs := api.recorded()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodPost, reqs[0].method)
		assert.Equal(t, s3KeysPath, reqs[0].path)
		assert.Equal(t, map[string]any{
			"alias":     "eso-s3",
			"expire_at": "2026-10-18T12:00:00Z",
		}, reqs[0].body)
		assertSigned(t, reqs[0])
	})

	t.Run("requires an organization", func(t *testing.T) {
		api := newFakeCrusoe(t, nil)
		g := &ObjectStorageKeyGenerator{base: testBase(api.Client())}

		_, _, err := g.Generate(context.Background(), specJSON(objectStorageKind, api.URL+"/v1", accessKeyAuth, ""), newKube(), testNamespace)
		require.ErrorContains(t, err, "organizationID must be set")
		assert.Empty(t, api.recorded())
	})

	t.Run("rejects a response without a secret", func(t *testing.T) {
		api := newFakeCrusoe(t, map[string]response{
			"POST " + s3KeysPath: {status: http.StatusOK, body: `{"access_key_id":"S3U_key"}`},
		})
		g := &ObjectStorageKeyGenerator{base: testBase(api.Client())}

		_, _, err := g.Generate(context.Background(), specJSON(objectStorageKind, api.URL+"/v1", accessKeyAuth, orgField), newKube(), testNamespace)
		require.ErrorContains(t, err, "object storage key missing")
	})
}

func TestObjectStorageKeyCleanup(t *testing.T) {
	state := &apiextensions.JSON{Raw: []byte(`{"accessKeyID":"S3U_key"}`)}
	deleteRoute := "DELETE " + s3KeysPath + "/S3U_key"
	cases := []struct {
		name         string
		routes       map[string]response
		state        *apiextensions.JSON
		wantErr      string
		wantRequests int
	}{
		{
			name:         "revokes the key",
			routes:       map[string]response{deleteRoute: {status: http.StatusNoContent}},
			state:        state,
			wantRequests: 1,
		},
		{
			name:         "treats a missing key as revoked",
			routes:       map[string]response{deleteRoute: {status: http.StatusNotFound, body: `{"code":"not_found","message":"key not found"}`}},
			state:        state,
			wantRequests: 1,
		},
		{
			name:         "reports API errors",
			routes:       map[string]response{deleteRoute: {status: http.StatusForbidden, body: `{"code":"forbidden","message":"permission denied"}`}},
			state:        state,
			wantErr:      "unable to revoke Crusoe object storage key S3U_key: 403 Forbidden: permission denied",
			wantRequests: 1,
		},
		{
			name:  "nothing to revoke without state",
			state: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeCrusoe(t, tc.routes)
			g := &ObjectStorageKeyGenerator{base: testBase(api.Client())}

			err := g.Cleanup(context.Background(), specJSON(objectStorageKind, api.URL+"/v1", accessKeyAuth, orgField), tc.state, newKube(), testNamespace)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}

			reqs := api.recorded()
			require.Len(t, reqs, tc.wantRequests)
			for _, req := range reqs {
				assert.Equal(t, http.MethodDelete, req.method)
				assert.Equal(t, s3KeysPath+"/S3U_key", req.path)
				assertSigned(t, req)
			}
		})
	}
}
