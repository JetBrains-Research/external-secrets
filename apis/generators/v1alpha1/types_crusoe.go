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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// CrusoeAuth configures how ESO authenticates with the Crusoe Cloud API.
// Exactly one authentication method must be set.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type CrusoeAuth struct {
	// AccessKey authenticates with a Crusoe Cloud API access key pair.
	// +optional
	AccessKey *CrusoeAccessKeyAuth `json:"accessKey,omitempty"`

	// ServiceAccount authenticates as a Crusoe Cloud service account (not a
	// Kubernetes ServiceAccount) using the OAuth2 client credentials grant.
	// +optional
	ServiceAccount *CrusoeServiceAccountAuth `json:"serviceAccount,omitempty"`
}

// CrusoeAccessKeyAuth references a Crusoe Cloud API access key pair.
type CrusoeAccessKeyAuth struct {
	// AccessKeyID references the secret key containing the Crusoe Cloud API access key ID.
	AccessKeyID esmeta.SecretKeySelector `json:"accessKeyIDSecretRef"`

	// SecretKey references the secret key containing the Crusoe Cloud API secret key.
	SecretKey esmeta.SecretKeySelector `json:"secretKeySecretRef"`
}

// CrusoeServiceAccountAuth references the OAuth2 client credentials of a Crusoe Cloud service account.
type CrusoeServiceAccountAuth struct {
	// ClientID references the secret key containing the OAuth2 client ID of the service account credential.
	ClientID esmeta.SecretKeySelector `json:"clientIDSecretRef"`

	// ClientSecret references the secret key containing the OAuth2 client secret of the service account credential.
	ClientSecret esmeta.SecretKeySelector `json:"clientSecretSecretRef"`

	// TokenURL is the OAuth2 token endpoint. It must use https.
	// Defaults to https://auth.crusoe.ai/oauth2/token.
	// +optional
	TokenURL string `json:"tokenURL,omitempty"`

	// Audience is requested for the issued access token.
	// Defaults to https://api.crusoe.ai.
	// +optional
	Audience string `json:"audience,omitempty"`
}

// CrusoeContainerRegistryKeySpec controls the behavior of the Crusoe Container Registry key generator.
type CrusoeContainerRegistryKeySpec struct {
	// APIURL is the base URL of the Crusoe Cloud API, including the version path.
	// Defaults to https://api.cloud.crusoe.ai/v1.
	// +optional
	APIURL string `json:"apiURL,omitempty"`

	// Auth configures how ESO authenticates with the Crusoe Cloud API.
	Auth CrusoeAuth `json:"auth"`

	// Alias is an optional human-readable name attached to each generated token.
	// +optional
	Alias string `json:"alias,omitempty"`

	// ExpiresAfter is the lifetime of each generated token. The Crusoe Cloud API
	// cannot revoke container registry tokens, so every token stays valid until
	// it expires. Keep this short and set the ExternalSecret refreshInterval below it.
	// +optional
	// +kubebuilder:default="24h"
	ExpiresAfter *metav1.Duration `json:"expiresAfter,omitempty"`
}

// CrusoeLimitedUsageAPIKeySpec controls the behavior of the Crusoe Intelligence API key
// and Crusoe Monitoring key generators.
type CrusoeLimitedUsageAPIKeySpec struct {
	// APIURL is the base URL of the Crusoe Cloud API, including the version path.
	// Defaults to https://api.cloud.crusoe.ai/v1.
	// +optional
	APIURL string `json:"apiURL,omitempty"`

	// Auth configures how ESO authenticates with the Crusoe Cloud API.
	Auth CrusoeAuth `json:"auth"`

	// Alias is an optional human-readable name attached to each generated key.
	// +optional
	Alias string `json:"alias,omitempty"`

	// ProjectID optionally scopes the generated key to a single Crusoe Cloud project.
	// +optional
	ProjectID string `json:"projectID,omitempty"`

	// ExpiresAfter is the lifetime of each generated key. Keys are also revoked
	// when the generator state is cleaned up.
	// +optional
	// +kubebuilder:default="24h"
	ExpiresAfter *metav1.Duration `json:"expiresAfter,omitempty"`
}

// CrusoeObjectStorageKeySpec controls the behavior of the Crusoe Object Storage key generator.
type CrusoeObjectStorageKeySpec struct {
	// APIURL is the base URL of the Crusoe Cloud API, including the version path.
	// Defaults to https://api.cloud.crusoe.ai/v1.
	// +optional
	APIURL string `json:"apiURL,omitempty"`

	// Auth configures how ESO authenticates with the Crusoe Cloud API.
	Auth CrusoeAuth `json:"auth"`

	// OrganizationID is the ID of the Crusoe Cloud organization that owns the S3 access key.
	// +kubebuilder:validation:MinLength=1
	OrganizationID string `json:"organizationID"`

	// Alias is an optional human-readable name attached to each generated key.
	// +optional
	Alias string `json:"alias,omitempty"`

	// ExpiresAfter is the lifetime of each generated key. Keys are also revoked
	// when the generator state is cleaned up.
	// +optional
	// +kubebuilder:default="24h"
	ExpiresAfter *metav1.Duration `json:"expiresAfter,omitempty"`
}

// CrusoeContainerRegistryKey generates a token for the Crusoe Container Registry.
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="external-secrets.io/component=controller"
// +kubebuilder:resource:scope=Namespaced,categories={external-secrets, external-secrets-generators}
type CrusoeContainerRegistryKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec CrusoeContainerRegistryKeySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// CrusoeContainerRegistryKeyList contains a list of CrusoeContainerRegistryKey resources.
type CrusoeContainerRegistryKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CrusoeContainerRegistryKey `json:"items"`
}

// CrusoeIntelligenceAPIKey generates an API key for Crusoe Intelligence (managed inference).
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="external-secrets.io/component=controller"
// +kubebuilder:resource:scope=Namespaced,categories={external-secrets, external-secrets-generators}
type CrusoeIntelligenceAPIKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec CrusoeLimitedUsageAPIKeySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// CrusoeIntelligenceAPIKeyList contains a list of CrusoeIntelligenceAPIKey resources.
type CrusoeIntelligenceAPIKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CrusoeIntelligenceAPIKey `json:"items"`
}

// CrusoeMonitoringKey generates an API key for Crusoe Monitoring (observability).
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="external-secrets.io/component=controller"
// +kubebuilder:resource:scope=Namespaced,categories={external-secrets, external-secrets-generators}
type CrusoeMonitoringKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec CrusoeLimitedUsageAPIKeySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// CrusoeMonitoringKeyList contains a list of CrusoeMonitoringKey resources.
type CrusoeMonitoringKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CrusoeMonitoringKey `json:"items"`
}

// CrusoeObjectStorageKey generates an S3 access key for Crusoe Object Storage.
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="external-secrets.io/component=controller"
// +kubebuilder:resource:scope=Namespaced,categories={external-secrets, external-secrets-generators}
type CrusoeObjectStorageKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec CrusoeObjectStorageKeySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// CrusoeObjectStorageKeyList contains a list of CrusoeObjectStorageKey resources.
type CrusoeObjectStorageKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CrusoeObjectStorageKey `json:"items"`
}
