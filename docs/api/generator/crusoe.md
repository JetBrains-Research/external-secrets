## Crusoe Cloud Generators

The Crusoe Cloud generators create short-lived keys for [Crusoe Cloud](https://crusoe.ai/) services, so workloads can get their own credentials in their namespace without anyone handling the keys by hand.

| Kind                         | Crusoe Cloud key        | Output keys                                          | Revoked on cleanup |
|------------------------------|-------------------------|------------------------------------------------------|--------------------|
| `CrusoeContainerRegistryKey` | Container Registry key  | `token`, `expires_at`                                | No, expires only   |
| `CrusoeIntelligenceAPIKey`   | Intelligence API key    | `api_key`, `key_id`, `expires_at`                    | Yes                |
| `CrusoeMonitoringKey`        | Monitoring key          | `api_key`, `key_id`, `expires_at`                    | Yes                |
| `CrusoeObjectStorageKey`     | Object Storage (S3) key | `access_key_id`, `secret_access_key`, `expires_at`   | Yes                |

`expires_at` is the expiry of the generated key in UNIX time (seconds since January 1, 1970 UTC).

### Authentication

The generators call the [Crusoe Cloud API](https://docs.crusoecloud.com/api) with a credential you store in a Kubernetes secret. Like all generators, they read that secret from the namespace of the `ExternalSecret`, even when they are used through a `ClusterGenerator`. Set exactly one of the following methods in `spec.auth`:

- `accessKey`: a Crusoe Cloud API access key pair. Requests are signed with the secret key, which never leaves the cluster.
- `serviceAccount`: the OAuth2 client credentials of a Crusoe Cloud service account (not a Kubernetes ServiceAccount). `tokenURL` and `audience` default to the Crusoe Cloud production endpoints.

```bash
kubectl create secret generic crusoe-credentials \
  --from-literal=access-key-id=<access key> \
  --from-literal=secret-key=<secret key>
```

The credential needs permission to create and delete the type of key it generates. Container Registry, Intelligence and Monitoring keys are owned by the principal that authenticates.

`spec.apiURL` overrides the Crusoe Cloud API base URL, including the version path. It defaults to `https://api.cloud.crusoe.ai/v1`.

### Expiry and rotation

Every generated key expires after `spec.expiresAfter`, which defaults to `24h`. Set the `refreshInterval` of the `ExternalSecret` well below it so that a new key is in place before the old one expires.

Each refresh creates a new key. Intelligence, Monitoring and Object Storage keys are recorded in the generator state, and the previous key is revoked shortly after the new one is written (after the controller's `--generator-gc-grace-period`, two minutes by default) and when the `ExternalSecret` is deleted.

The Crusoe Cloud API cannot revoke Container Registry keys, so they stay valid until they expire. Keep `expiresAfter` short for them.

### Container Registry Keys

`CrusoeContainerRegistryKey` creates a token for the [Crusoe Container Registry](https://docs.crusoecloud.com/container-registry/quickstart/index.html). To pull images, use the email address of your Crusoe Cloud account as the username and the token as the password.

```yaml
{% include 'generator-crusoe-container-registry-key.yaml' %}
```

Example `ExternalSecret` that builds an image pull secret from the token:

```yaml
{% include 'generator-crusoe-container-registry-key-example.yaml' %}
```

### Intelligence API Keys

`CrusoeIntelligenceAPIKey` creates an API key for Crusoe Intelligence (managed inference). Set `spec.projectID` to scope the key to a single project. This example authenticates as a service account:

```yaml
{% include 'generator-crusoe-intelligence-api-key.yaml' %}
```

### Monitoring Keys

`CrusoeMonitoringKey` creates an API key for Crusoe Monitoring, for example to scrape project metrics with Prometheus. Set `spec.projectID` to scope the key to a single project.

```yaml
{% include 'generator-crusoe-monitoring-key.yaml' %}
```

### Object Storage Keys

`CrusoeObjectStorageKey` creates an S3 access key for Crusoe Object Storage in the organization set in `spec.organizationID`.

```yaml
{% include 'generator-crusoe-object-storage-key.yaml' %}
```
