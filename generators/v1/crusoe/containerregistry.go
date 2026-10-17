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
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/antihax/optional"
	swagger "github.com/crusoecloud/client-go/swagger/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

// ContainerRegistryKeyGenerator generates Crusoe Container Registry tokens.
type ContainerRegistryKeyGenerator struct {
	base
}

// Generate creates a new container registry token.
func (g *ContainerRegistryKeyGenerator) Generate(
	ctx context.Context,
	jsonSpec *apiextensions.JSON,
	kube client.Client,
	namespace string,
) (map[string][]byte, genv1alpha1.GeneratorProviderState, error) {
	if jsonSpec == nil {
		return nil, nil, errors.New(errNoSpec)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var res genv1alpha1.CrusoeContainerRegistryKey
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

	out, _, err := api.ContainerRegistryApi.CreateCcrToken(ctx, &swagger.ContainerRegistryApiCreateCcrTokenOpts{ //nolint:bodyclose // closed by client-go
		Body: optional.NewInterface(swagger.CcrTokenRequest{
			Alias:     res.Spec.Alias,
			ExpiresAt: expiresAt.Format(time.RFC3339),
		}),
	})
	if err != nil {
		return nil, nil, apiError("create Crusoe container registry token", err)
	}
	if out.Token == "" {
		return nil, nil, errors.New("container registry token missing from Crusoe Cloud response")
	}

	return map[string][]byte{
		"token":      []byte(out.Token),
		"expires_at": []byte(strconv.FormatInt(expiresAt.Unix(), 10)),
	}, nil, nil
}

// Cleanup is a no-op. The Crusoe Cloud API cannot revoke container registry
// tokens, so their lifetime is bounded by expiresAfter instead.
func (g *ContainerRegistryKeyGenerator) Cleanup(_ context.Context, _ *apiextensions.JSON, _ genv1alpha1.GeneratorProviderState, _ client.Client, _ string) error {
	return nil
}

// NewContainerRegistryKeyGenerator creates a generator for the CrusoeContainerRegistryKey kind.
func NewContainerRegistryKeyGenerator() genv1alpha1.Generator {
	return &ContainerRegistryKeyGenerator{}
}

// ContainerRegistryKeyKind returns the kind served by NewContainerRegistryKeyGenerator.
func ContainerRegistryKeyKind() string {
	return string(genv1alpha1.GeneratorKindCrusoeContainerRegistryKey)
}
