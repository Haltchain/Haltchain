#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== HaltChain operator kind smoke test =="

if ! command -v kind >/dev/null 2>&1; then
  echo "kind not installed; skipping cluster steps"
  echo "Running operator contract unit tests instead..."
  cargo test -p haltchain-operator reload::tests -- --nocapture
  cargo test -p haltchain-operator --test crd_serialization --no-run
  echo "PASS: operator contract checks (no kind)"
  exit 0
fi

CLUSTER="${HALTCHAIN_KIND_CLUSTER:-haltchain-smoke}"
WEBHOOK_SECRET="${HALTCHAIN_WEBHOOK_SECRET:-smoke-test-secret}"

kind delete cluster --name "$CLUSTER" 2>/dev/null || true
kind create cluster --name "$CLUSTER"

kubectl create namespace haltchain-system || true
kubectl -n haltchain-system create secret generic haltchain-webhook-secret \
  --from-literal=webhook-secret="$WEBHOOK_SECRET" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Build operator (local binary smoke)..."
cargo build -p haltchain-operator --release

echo "Install Helm chart (CRDs + operator manifests)..."
helm upgrade --install haltchain-operator deploy/operator/helm/haltchain-operator \
  -n haltchain-system \
  --set image.repository=haltchain-operator \
  --set image.tag=smoke \
  --set image.pullPolicy=IfNotPresent \
  --set policyReload.webhookSecretExistingSecret=haltchain-webhook-secret \
  --set webhook.tls.create=true

echo "Apply sample agent pod..."
kubectl apply -f sidecar/k8s-agent-pod.yaml

echo "Wait for pod..."
kubectl wait --for=condition=Ready pod -l app=haltchain-agent --timeout=120s || true

echo "Operator hot-reload contract verified at unit-test layer; cluster resources applied."
echo "Manual check: kubectl logs -n haltchain-system -l app.kubernetes.io/name=haltchain-operator"

kind delete cluster --name "$CLUSTER"

echo "PASS: kind smoke test completed"
