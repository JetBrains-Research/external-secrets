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

package resolvers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

// TestClusterGeneratorToVirtualCrusoe checks that the virtual objects carry
// their kind, which GeneratorState cleanup uses to find the generator.
func TestClusterGeneratorToVirtualCrusoe(t *testing.T) {
	registrySpec := &genv1alpha1.CrusoeContainerRegistryKeySpec{Alias: "registry"}
	apiKeySpec := &genv1alpha1.CrusoeLimitedUsageAPIKeySpec{Alias: "api-key"}
	storageSpec := &genv1alpha1.CrusoeObjectStorageKeySpec{OrganizationID: "org"}

	cases := []struct {
		kind      genv1alpha1.GeneratorKind
		generator genv1alpha1.GeneratorSpec
		want      any
	}{
		{
			kind:      genv1alpha1.GeneratorKindCrusoeContainerRegistryKey,
			generator: genv1alpha1.GeneratorSpec{CrusoeContainerRegistryKeySpec: registrySpec},
			want:      *registrySpec,
		},
		{
			kind:      genv1alpha1.GeneratorKindCrusoeIntelligenceAPIKey,
			generator: genv1alpha1.GeneratorSpec{CrusoeIntelligenceAPIKeySpec: apiKeySpec},
			want:      *apiKeySpec,
		},
		{
			kind:      genv1alpha1.GeneratorKindCrusoeMonitoringKey,
			generator: genv1alpha1.GeneratorSpec{CrusoeMonitoringKeySpec: apiKeySpec},
			want:      *apiKeySpec,
		},
		{
			kind:      genv1alpha1.GeneratorKindCrusoeObjectStorageKey,
			generator: genv1alpha1.GeneratorSpec{CrusoeObjectStorageKeySpec: storageSpec},
			want:      *storageSpec,
		},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			obj, err := clusterGeneratorToVirtual(&genv1alpha1.ClusterGenerator{
				Spec: genv1alpha1.ClusterGeneratorSpec{Kind: tc.kind, Generator: tc.generator},
			})
			require.NoError(t, err)

			gvk := obj.GetObjectKind().GroupVersionKind()
			assert.Equal(t, genv1alpha1.SchemeGroupVersion.WithKind(string(tc.kind)), gvk)
			switch o := obj.(type) {
			case *genv1alpha1.CrusoeContainerRegistryKey:
				assert.Equal(t, tc.want, o.Spec)
			case *genv1alpha1.CrusoeIntelligenceAPIKey:
				assert.Equal(t, tc.want, o.Spec)
			case *genv1alpha1.CrusoeMonitoringKey:
				assert.Equal(t, tc.want, o.Spec)
			case *genv1alpha1.CrusoeObjectStorageKey:
				assert.Equal(t, tc.want, o.Spec)
			default:
				t.Fatalf("unexpected type %T", obj)
			}

			_, err = clusterGeneratorToVirtual(&genv1alpha1.ClusterGenerator{
				Spec: genv1alpha1.ClusterGeneratorSpec{Kind: tc.kind},
			})
			require.ErrorContains(t, err, "must be set")
		})
	}
}
