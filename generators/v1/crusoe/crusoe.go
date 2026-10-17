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

// Package crusoe provides generators for Crusoe Cloud container registry,
// intelligence, monitoring and object storage keys.
package crusoe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	auth "github.com/crusoecloud/client-go/auth/v1"
	swagger "github.com/crusoecloud/client-go/swagger/v1"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
)

const (
	errNoSpec    = "no config spec provided"
	errParseSpec = "unable to parse spec: %w"

	// defaultExpiresAfter mirrors the +kubebuilder:default of the expiresAfter
	// fields, for specs that did not pass through the API server's defaulting.
	defaultExpiresAfter = 24 * time.Hour

	// requestTimeout bounds a single Generate or Cleanup, including the OAuth2
	// token exchange when authenticating as a service account.
	requestTimeout = 30 * time.Second
)

// base holds the dependencies shared by all Crusoe generators.
type base struct {
	// httpClient replaces the default HTTP client for Crusoe Cloud API calls
	// and service account token requests.
	httpClient *http.Client
	// now replaces time.Now when computing expiry timestamps.
	now func() time.Time
}

// newAPIClient builds a Crusoe Cloud API client for a single Generate or
// Cleanup call. ctx must stay alive for as long as the client is used, as the
// service account token exchange happens lazily on the first request.
func (b *base) newAPIClient(ctx context.Context, kube client.Client, namespace, apiURL string, spec *genv1alpha1.CrusoeAuth) (*swagger.APIClient, error) {
	var cfg *swagger.Configuration
	switch {
	case spec.AccessKey != nil:
		accessKeyID, err := resolveSecret(ctx, kube, namespace, &spec.AccessKey.AccessKeyID)
		if err != nil {
			return nil, fmt.Errorf("unable to get Crusoe access key ID: %w", err)
		}
		secretKey, err := resolveSecret(ctx, kube, namespace, &spec.AccessKey.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("unable to get Crusoe secret key: %w", err)
		}
		// auth.NewAuthenticatedConfig installs the signing transport on
		// http.DefaultClient, which would leak these credentials to every
		// other user of the default client in the controller process.
		hc := b.client()
		cfg = swagger.NewConfiguration()
		cfg.HTTPClient = &http.Client{
			Transport: auth.NewAuthenticatingTransport(hc.Transport, accessKeyID, secretKey),
			Timeout:   hc.Timeout,
		}
	case spec.ServiceAccount != nil:
		clientID, err := resolveSecret(ctx, kube, namespace, &spec.ServiceAccount.ClientID)
		if err != nil {
			return nil, fmt.Errorf("unable to get Crusoe service account client ID: %w", err)
		}
		clientSecret, err := resolveSecret(ctx, kube, namespace, &spec.ServiceAccount.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("unable to get Crusoe service account client secret: %w", err)
		}
		// The OAuth2 client uses the context's HTTP client for the token
		// request and as the base transport for API calls.
		ctx = context.WithValue(ctx, oauth2.HTTPClient, b.client())
		cfg, err = auth.NewServiceAccountConfig(ctx, clientID, clientSecret, spec.ServiceAccount.TokenURL, spec.ServiceAccount.Audience)
		if err != nil {
			return nil, fmt.Errorf("unable to configure Crusoe service account authentication: %w", err)
		}
	default:
		return nil, errors.New("no Crusoe authentication method configured: set auth.accessKey or auth.serviceAccount")
	}

	if apiURL != "" {
		cfg.BasePath = strings.TrimRight(apiURL, "/")
	}
	return swagger.NewAPIClient(cfg), nil
}

func (b *base) client() *http.Client {
	if b.httpClient != nil {
		return b.httpClient
	}
	return &http.Client{Timeout: requestTimeout}
}

// expiresAt returns the absolute expiry for a key created now with the given
// lifetime, truncated to the second precision of RFC 3339 timestamps.
func (b *base) expiresAt(expiresAfter *metav1.Duration) (time.Time, error) {
	lifetime := defaultExpiresAfter
	if expiresAfter != nil {
		lifetime = expiresAfter.Duration
	}
	if lifetime <= 0 {
		return time.Time{}, fmt.Errorf("expiresAfter must be positive, got %s", lifetime)
	}
	now := time.Now
	if b.now != nil {
		now = b.now
	}
	return now().Add(lifetime).UTC().Truncate(time.Second), nil
}

// resolveSecret reads a credential from the generator's namespace. Surrounding
// whitespace is dropped, as a trailing newline (e.g. from kubectl
// --from-file) would otherwise break request signing or the token exchange.
func resolveSecret(ctx context.Context, kube client.Client, namespace string, ref *esmeta.SecretKeySelector) (string, error) {
	value, err := resolvers.SecretKeyRef(ctx, kube, resolvers.EmptyStoreKind, namespace, ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

// expiryValue formats the expiry reported by the Crusoe Cloud API as UNIX
// seconds, falling back to the requested expiry if the API omitted it.
func expiryValue(reported string, requested time.Time) []byte {
	if t, err := time.Parse(time.RFC3339, reported); err == nil {
		requested = t
	}
	return []byte(strconv.FormatInt(requested.Unix(), 10))
}

// apiError describes a failed Crusoe Cloud API call, including the message
// from the response body when there is one.
func apiError(action string, err error) error {
	if swaggerErr, ok := errors.AsType[swagger.GenericSwaggerError](err); ok {
		var body struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(swaggerErr.Body(), &body) == nil && body.Message != "" {
			return fmt.Errorf("unable to %s: %s: %s", action, swaggerErr.Error(), body.Message)
		}
	}
	return fmt.Errorf("unable to %s: %w", action, err)
}

func isNotFound(resp *http.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusNotFound
}
