#!/usr/bin/env bash
# Register SPIFFE identity entries for all HaltChain components.
# Run after SPIRE server and agents are healthy:
#   kubectl -n haltchain-system exec deploy/spire-server -- spire-server entry show
#
# Trust domain: haltchain.example.org
# Override with: SPIFFE_TRUST_DOMAIN=your.domain ./register-entries.sh

set -euo pipefail

TRUST_DOMAIN="${SPIFFE_TRUST_DOMAIN:-haltchain.example.org}"
NS="haltchain-system"

SPIRE_CMD=(kubectl -n "$NS" exec "statefulset/spire-server" -- /opt/spire/bin/spire-server entry create)

echo "==> Registering SPIFFE identity entries for trust domain: $TRUST_DOMAIN"

# haltchain-api — the main API gateway
"${SPIRE_CMD[@]}" \
  -parentID "spiffe://${TRUST_DOMAIN}/ns/${NS}/sa/spire-agent" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/haltchain/api" \
  -selector "k8s:ns:${NS}" \
  -selector "k8s:sa:haltchain-api" \
  -ttl 3600
echo "  Registered: haltchain/api"

# haltchain-operator
"${SPIRE_CMD[@]}" \
  -parentID "spiffe://${TRUST_DOMAIN}/ns/${NS}/sa/spire-agent" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/haltchain/operator" \
  -selector "k8s:ns:${NS}" \
  -selector "k8s:sa:haltchain-operator" \
  -ttl 3600
echo "  Registered: haltchain/operator"

# haltchain-sidecar — injected into agent pods across all namespaces
"${SPIRE_CMD[@]}" \
  -parentID "spiffe://${TRUST_DOMAIN}/ns/${NS}/sa/spire-agent" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/haltchain/sidecar" \
  -selector "k8s:label:app.kubernetes.io/component:haltchain-sidecar" \
  -ttl 3600
echo "  Registered: haltchain/sidecar"

echo "==> Done. Verify with:"
echo "    kubectl -n $NS exec statefulset/spire-server -- /opt/spire/bin/spire-server entry show"
