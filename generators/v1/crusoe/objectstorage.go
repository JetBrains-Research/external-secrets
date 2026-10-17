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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	swagger "github.com/crusoecloud/client-go/swagger/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

// ObjectStorageKeyGenerator generates Crusoe Object Storage S3 access keys.
type ObjectStorageKeyGenerator struct {
	base
}

// objectStorageKeyState is persisted as the generator state so that Cleanup
// can revoke the key that Generate created.
type objectStorageKeyState struct {
	AccessKeyID string `json:"accessKeyID"`
}

// Generate creates a new S3 access key.
func (g *ObjectStorageKeyGenerator) Generate(ctx context.Context, jsonSpec *apiextensions.JSON, kube client.Client, namespace string) (map[string][]byte, genv1alpha1.GeneratorProviderState, error) {
	if jsonSpec == nil {
		return nil, nil, errors.New(errNoSpec)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	res, err := parseObjectStorageKey(jsonSpec.Raw)
	if err != nil {
		return nil, nil, err
	}
	expiresAt, err := g.expiresAt(res.Spec.ExpiresAfter)
	if err != nil {
		return nil, nil, err
	}
	api, err := g.newAPIClient(ctx, kube, namespace, res.Spec.APIURL, &res.Spec.Auth)
	if err != nil {
		return nil, nil, err
	}

	// The client does not escape path parameters.
	out, _, err := api.S3KeysApi.CreateS3Key(ctx, swagger.CreateS3KeyRequest{ //nolint:bodyclose // closed by client-go
		Alias:    res.Spec.Alias,
		ExpireAt: expiresAt.Format(time.RFC3339),
	}, url.PathEscape(res.Spec.OrganizationID))
	if err != nil {
		return nil, nil, apiError("create Crusoe object storage key", err)
	}
	if out.AccessKeyId == "" || out.SecretKey == "" {
		return nil, nil, errors.New("object storage key missing from Crusoe Cloud response")
	}

	state, err := json.Marshal(objectStorageKeyState{AccessKeyID: out.AccessKeyId})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal generator state: %w", err)
	}
	return map[string][]byte{
		"access_key_id":     []byte(out.AccessKeyId),
		"secret_access_key": []byte(out.SecretKey),
		"expires_at":        expiryValue(out.ExpireAt, expiresAt),
	}, &apiextensions.JSON{Raw: state}, nil
}

// Cleanup revokes the key created during Generate. It is idempotent: a key
// that has already been deleted (HTTP 404) is treated as success.
func (g *ObjectStorageKeyGenerator) Cleanup(ctx context.Context, jsonSpec *apiextensions.JSON, rawState genv1alpha1.GeneratorProviderState, kube client.Client, namespace string) error {
	if jsonSpec == nil || rawState == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	res, err := parseObjectStorageKey(jsonSpec.Raw)
	if err != nil {
		return err
	}
	var state objectStorageKeyState
	if err := json.Unmarshal(rawState.Raw, &state); err != nil {
		return fmt.Errorf("unable to parse generator state: %w", err)
	}
	if state.AccessKeyID == "" {
		return nil
	}
	api, err := g.newAPIClient(ctx, kube, namespace, res.Spec.APIURL, &res.Spec.Auth)
	if err != nil {
		return err
	}

	resp, err := api.S3KeysApi.DeleteS3Key(ctx, url.PathEscape(res.Spec.OrganizationID), url.PathEscape(state.AccessKeyID)) //nolint:bodyclose // closed by client-go
	if err == nil || isNotFound(resp) {
		return nil
	}
	return apiError("revoke Crusoe object storage key "+state.AccessKeyID, err)
}

func parseObjectStorageKey(data []byte) (*genv1alpha1.CrusoeObjectStorageKey, error) {
	var res genv1alpha1.CrusoeObjectStorageKey
	if err := yaml.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf(errParseSpec, err)
	}
	if res.Spec.OrganizationID == "" {
		return nil, errors.New("organizationID must be set")
	}
	return &res, nil
}

// NewObjectStorageKeyGenerator creates a generator for the CrusoeObjectStorageKey kind.
func NewObjectStorageKeyGenerator() genv1alpha1.Generator {
	return &ObjectStorageKeyGenerator{}
}

// ObjectStorageKeyKind returns the kind served by NewObjectStorageKeyGenerator.
func ObjectStorageKeyKind() string {
	return string(genv1alpha1.GeneratorKindCrusoeObjectStorageKey)
}
