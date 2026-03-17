#!/usr/bin/env bash
# deploy-testnet.sh — launch 3 Raft nodes across Fly.io regions
# Usage: ./deploy-testnet.sh
set -euo pipefail

APP="haltchain-consensus"
REGIONS=(iad lhr sin)

echo "Building and pushing image..."
fly deploy --config fly.toml --strategy immediate --wait-timeout 120

echo "Scaling to 1 machine per region..."
for i in "${!REGIONS[@]}"; do
  NODE_ID=$((i + 1))
  REGION="${REGIONS[$i]}"

  # Peers list excludes self
  PEERS=""
  for j in "${!REGIONS[@]}"; do
    if [[ $j -ne $i ]]; then
      PEER_ID=$((j + 1))
      PEERS+="${PEER_ID}=${APP}-${PEER_ID}.internal:7000,"
    fi
  done
  PEERS="${PEERS%,}"

  echo "Launching node ${NODE_ID} in ${REGION} (peers: ${PEERS})"
  fly machine run \
    --app "$APP" \
    --region "$REGION" \
    --name "${APP}-${NODE_ID}" \
    --env HALTCHAIN_NODE_ID="${NODE_ID}" \
    --env HALTCHAIN_PEERS="${PEERS}" \
    --port 8080:8080 \
    --port 7000:7000 \
    --vm-memory 512 \
    --vm-cpus 1 \
    .
done

echo ""
echo "Testnet deployed. Check health:"
for i in "${!REGIONS[@]}"; do
  NODE_ID=$((i + 1))
  echo "  curl https://${APP}.fly.dev/health  (node ${NODE_ID} / ${REGIONS[$i]})"
done
