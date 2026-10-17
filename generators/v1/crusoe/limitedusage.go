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
	"time"

	swagger "github.com/crusoecloud/client-go/swagger/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

// Usage types of Crusoe Cloud limited usage API keys.
const (
	usageInference     = "inference"
	usageObservability = "observability"
)

// LimitedUsageAPIKeyGenerator generates Crusoe Cloud limited usage API keys
// of a single usage type. It serves both the CrusoeIntelligenceAPIKey and the
// CrusoeMonitoringKey kinds, which share CrusoeLimitedUsageAPIKeySpec.
type LimitedUsageAPIKeyGenerator struct {
	base
	usage string
}

// limitedUsageAPIKeyState is persisted as the generator state so that Cleanup
// can revoke the key that Generate created.
type limitedUsageAPIKeyState struct {
	KeyID string `json:"keyID"`
}

// limitedUsageAPIKey is the part of both kinds the generator reads.
type limitedUsageAPIKey struct {
	Spec genv1alpha1.CrusoeLimitedUsageAPIKeySpec `json:"spec"`
}

// Generate creates a new limited usage API key.
func (g *LimitedUsageAPIKeyGenerator) Generate(ctx context.Context, jsonSpec *apiextensions.JSON, kube client.Client, namespace string) (map[string][]byte, genv1alpha1.GeneratorProviderState, error) {
	if jsonSpec == nil {
		return nil, nil, errors.New(errNoSpec)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var res limitedUsageAPIKey
	if err := yaml.Unmarshal(jsonSpec.Raw, &res); err != nil {
		return nil, nil, fmt.Errorf(errParseSpec, err)
	}
	expiresAt, err := g.expiresAt(res.Spec.ExpiresAfter)
	if err != nil {
		return nil, nil, err
	}
	api, err := g.newAPIClient(ctx, kube, namespace, res.Spec.APIURL, &res.Spec.Auth)
	if err != nil {
		return nil, nil, err
	}

	out, _, err := api.LimitedUsageAPIKeyApi.CreateLimitedUsageAPIKey(ctx, swagger.CreateLimitedUsageApiKeyRequest{ //nolint:bodyclose // closed by client-go
		Alias:     res.Spec.Alias,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		ProjectId: res.Spec.ProjectID,
	}, g.usage)
	if err != nil {
		return nil, nil, apiError(fmt.Sprintf("create Crusoe %s API key", g.usage), err)
	}
	key := out.ApiKeyInfo
	if key == nil || key.ApiKey == "" || key.KeyId == "" {
		return nil, nil, fmt.Errorf("%s API key missing from Crusoe Cloud response", g.usage)
	}

	state, err := json.Marshal(limitedUsageAPIKeyState{KeyID: key.KeyId})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal generator state: %w", err)
	}
	return map[string][]byte{
		"api_key":    []byte(key.ApiKey),
		"key_id":     []byte(key.KeyId),
		"expires_at": expiryValue(key.ExpiresAt, expiresAt),
	}, &apiextensions.JSON{Raw: state}, nil
}

// Cleanup revokes the key created during Generate. It is idempotent: a key
// that no longer exists is treated as already revoked.
func (g *LimitedUsageAPIKeyGenerator) Cleanup(ctx context.Context, jsonSpec *apiextensions.JSON, rawState genv1alpha1.GeneratorProviderState, kube client.Client, namespace string) error {
	if jsonSpec == nil || rawState == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var res limitedUsageAPIKey
	if err := yaml.Unmarshal(jsonSpec.Raw, &res); err != nil {
		return fmt.Errorf(errParseSpec, err)
	}
	var state limitedUsageAPIKeyState
	if err := json.Unmarshal(rawState.Raw, &state); err != nil {
		return fmt.Errorf("unable to parse generator state: %w", err)
	}
	if state.KeyID == "" {
		return nil
	}
	api, err := g.newAPIClient(ctx, kube, namespace, res.Spec.APIURL, &res.Spec.Auth)
	if err != nil {
		return err
	}

	resp, err := api.LimitedUsageAPIKeyApi.DeleteLimitedUsageAPIKey(ctx, state.KeyID) //nolint:bodyclose // closed by client-go
	if err == nil || isNotFound(resp) {
		return nil
	}
	// The delete endpoint does not document how it reports a key that is
	// already gone (e.g. revoked in the console), so look the key up before
	// failing; otherwise the GeneratorState would be retried forever.
	keys, _, listErr := api.LimitedUsageAPIKeyApi.GetLimitedUsageAPIKeys(ctx) //nolint:bodyclose // closed by client-go
	if listErr == nil && !containsKey(keys.Items, state.KeyID) {
		return nil
	}
	return apiError(fmt.Sprintf("revoke Crusoe %s API key %s", g.usage, state.KeyID), err)
}

func containsKey(keys []swagger.LimitedUsageApiKeyInfo, keyID string) bool {
	for _, key := range keys {
		if key.KeyId == keyID {
			return true
		}
	}
	return false
}

// NewIntelligenceAPIKeyGenerator creates a generator for the CrusoeIntelligenceAPIKey kind.
func NewIntelligenceAPIKeyGenerator() genv1alpha1.Generator {
	return &LimitedUsageAPIKeyGenerator{usage: usageInference}
}

// IntelligenceAPIKeyKind returns the kind served by NewIntelligenceAPIKeyGenerator.
func IntelligenceAPIKeyKind() string {
	return string(genv1alpha1.GeneratorKindCrusoeIntelligenceAPIKey)
}

// NewMonitoringKeyGenerator creates a generator for the CrusoeMonitoringKey kind.
func NewMonitoringKeyGenerator() genv1alpha1.Generator {
	return &LimitedUsageAPIKeyGenerator{usage: usageObservability}
}

// MonitoringKeyKind returns the kind served by NewMonitoringKeyGenerator.
func MonitoringKeyKind() string {
	return string(genv1alpha1.GeneratorKindCrusoeMonitoringKey)
}
