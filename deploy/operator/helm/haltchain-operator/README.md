# HaltChain Operator

A Helm chart for deploying the HaltChain Kubernetes operator, which manages AI agent security sidecars.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+

## Installation

### Basic Installation

```bash
helm install haltchain-operator ./deploy/operator/helm/haltchain-operator \
  --namespace haltchain-system \
  --create-namespace
```

### Upgrade

```bash
helm upgrade haltchain-operator ./deploy/operator/helm/haltchain-operator \
  --namespace haltchain-system
```

### Custom Values

```bash
helm install haltchain-operator ./deploy/operator/helm/haltchain-operator \
  --namespace haltchain-system \
  --create-namespace \
  --set image.tag=v0.2.0 \
  --set replicaCount=2
```

## Configuration

The following table lists the configurable parameters and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of operator replicas | `1` |
| `image.repository` | Container image repository | `ghcr.io/haltchain/operator` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag | `latest` |
| `namespace.create` | Create the namespace | `true` |
| `namespace.name` | Namespace name | `haltchain-system` |
| `nameOverride` | Override the chart name | `""` |
| `fullnameOverride` | Override the full name | `""` |
| `crds.install` | Install CRDs | `true` |
| `webhook.port` | Webhook container port | `8443` |
| `webhook.servicePort` | Webhook service port | `443` |
| `webhook.tls.secretName` | TLS secret name | `haltchain-operator-webhook-tls` |
| `webhook.tls.create` | Create TLS secret | `false` |
| `webhook.tls.cert` | TLS certificate (base64) | `""` |
| `webhook.tls.key` | TLS key (base64) | `""` |
| `webhook.failurePolicy` | Webhook failure policy | `Ignore` |
| `webhook.namespaceSelector` | Namespace selector for injection | `{haltchain.io/inject: enabled}` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `securityContext` | Pod security context | `{runAsNonRoot: true, runAsUser: 65534}` |
| `containerSecurityContext` | Container security context | `{allowPrivilegeEscalation: false}` |
| `env` | Environment variables | `{RUST_LOG: info}` |
| `podAnnotations` | Pod annotations | `{}` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |

## Cert-Manager Integration

To use cert-manager for automatic TLS certificate management:

1. Install cert-manager:
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
```

2. Create a Certificate resource:
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: haltchain-operator-webhook
  namespace: haltchain-system
spec:
  secretName: haltchain-operator-webhook-tls
  dnsNames:
    - haltchain-operator-webhook.haltchain-system.svc
    - haltchain-operator-webhook.haltchain-system.svc.cluster.local
  issuerRef:
    kind: ClusterIssuer
    name: selfsigned
```

3. Install the chart without creating the TLS secret:
```bash
helm install haltchain-operator ./deploy/operator/helm/haltchain-operator \
  --namespace haltchain-system \
  --create-namespace \
  --set webhook.tls.create=false
```

## Uninstall

```bash
helm uninstall haltchain-operator --namespace haltchain-system
```

To remove CRDs (this will delete all HaltChain custom resources):

```bash
kubectl delete -f ./deploy/operator/helm/haltchain-operator/crds/
```
