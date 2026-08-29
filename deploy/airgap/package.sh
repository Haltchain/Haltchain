#!/usr/bin/env bash
# Air-gapped deployment packager for HaltChain.
#
# Bundles the haltchain-api binary, ONNX embedding model, all regulatory rule
# packs, migration SQL files, and an install script into a single .tar.gz
# that can be transported to an air-gapped environment.
#
# Usage:
#   ./package.sh [--target <release|debug>] [--out <output-dir>]
#
# Output:
#   haltchain-airgap-<version>-<arch>.tar.gz
#
# Run from the workspace root.

set -euo pipefail

###############################################################################
# Defaults
###############################################################################
TARGET="${TARGET:-release}"
OUT_DIR="${OUT_DIR:-./dist}"
WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(grep '^version' "$WORKSPACE_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')"
ARCH="$(uname -m)"
PACKAGE_NAME="haltchain-airgap-${VERSION}-${ARCH}"

###############################################################################
# Parse args
###############################################################################
while [[ $# -gt 0 ]]; do
  case $1 in
    --target) TARGET="$2"; shift 2 ;;
    --out)    OUT_DIR="$2"; shift 2 ;;
    *)        echo "Unknown argument: $1"; exit 1 ;;
  esac
done

echo "==> Building HaltChain air-gap package v${VERSION} (target=${TARGET})"

###############################################################################
# 1. Build the binary
###############################################################################
echo "==> Building haltchain-api (${TARGET})"
cd "$WORKSPACE_ROOT"
if [[ "$TARGET" == "release" ]]; then
  cargo build --release -p haltchain-api
  BINARY="$WORKSPACE_ROOT/target/release/haltchain-api"
else
  cargo build -p haltchain-api
  BINARY="$WORKSPACE_ROOT/target/debug/haltchain-api"
fi

if [[ ! -f "$BINARY" ]]; then
  echo "ERROR: Binary not found at $BINARY"; exit 1
fi

###############################################################################
# 2. Gather artifacts
###############################################################################
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

PKG_DIR="$STAGE/$PACKAGE_NAME"
mkdir -p \
  "$PKG_DIR/bin" \
  "$PKG_DIR/models" \
  "$PKG_DIR/rules" \
  "$PKG_DIR/migrations"

# Binary
cp "$BINARY" "$PKG_DIR/bin/haltchain-api"
chmod +x "$PKG_DIR/bin/haltchain-api"

# ONNX model (optional — only if present; operators can skip embeddings in offline mode)
MODEL_PATH="${HALTCHAIN_MODEL_PATH:-$WORKSPACE_ROOT/models/all-minilm-l6-v2.onnx}"
if [[ -f "$MODEL_PATH" ]]; then
  cp "$MODEL_PATH" "$PKG_DIR/models/"
  echo "==> Included ONNX model: $(basename "$MODEL_PATH")"
else
  echo "WARNING: ONNX model not found at $MODEL_PATH — embeddings will use hash fallback in standalone mode"
fi

# Regulatory rule packs (YAML)
RULE_PACK_DIR="$WORKSPACE_ROOT/crates/rules/src/packs"
if [[ -d "$RULE_PACK_DIR" ]]; then
  cp "$RULE_PACK_DIR"/*.yaml "$PKG_DIR/rules/" 2>/dev/null || true
  echo "==> Included $(ls "$PKG_DIR/rules/" | wc -l) rule pack(s)"
else
  echo "WARNING: Rule packs directory not found at $RULE_PACK_DIR"
fi

# Migrations
cp "$WORKSPACE_ROOT/migrations/"*.sql "$PKG_DIR/migrations/"
echo "==> Included $(ls "$PKG_DIR/migrations/" | wc -l) migration file(s)"

###############################################################################
# 3. Write install script
###############################################################################
cat > "$PKG_DIR/install.sh" << 'INSTALL'
#!/usr/bin/env bash
# HaltChain air-gapped installer.
# Run as root or with sudo on the target machine.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/haltchain}"
DATA_DIR="${DATA_DIR:-/var/lib/haltchain}"
LOG_DIR="${LOG_DIR:-/var/log/haltchain}"
PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing HaltChain to ${INSTALL_DIR}"

mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/models" "$INSTALL_DIR/rules" \
         "$DATA_DIR" "$LOG_DIR"

cp "$PACKAGE_DIR/bin/haltchain-api"   "$INSTALL_DIR/bin/"
chmod +x "$INSTALL_DIR/bin/haltchain-api"

[[ -d "$PACKAGE_DIR/models" ]] && cp -r "$PACKAGE_DIR/models/"* "$INSTALL_DIR/models/" 2>/dev/null || true
[[ -d "$PACKAGE_DIR/rules"  ]] && cp -r "$PACKAGE_DIR/rules/"*  "$INSTALL_DIR/rules/"  2>/dev/null || true

# systemd unit
cat > /etc/systemd/system/haltchain-api.service << UNIT
[Unit]
Description=HaltChain Safety API
After=network.target

[Service]
Type=simple
User=haltchain
WorkingDirectory=${DATA_DIR}
ExecStart=${INSTALL_DIR}/bin/haltchain-api --profile standalone
Environment=HALTCHAIN_ENV=standalone
Environment=HALTCHAIN_SQLITE_PATH=${DATA_DIR}/haltchain.db
Environment=HALTCHAIN_RULE_PACK_DIR=${INSTALL_DIR}/rules
Environment=HALTCHAIN_MODEL_PATH=${INSTALL_DIR}/models
Environment=RUST_LOG=info
StandardOutput=append:${LOG_DIR}/api.log
StandardError=append:${LOG_DIR}/api.error.log
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# Create user if not present
id haltchain &>/dev/null || useradd -r -s /bin/false haltchain
chown -R haltchain:haltchain "$DATA_DIR" "$LOG_DIR"

systemctl daemon-reload
systemctl enable haltchain-api
systemctl start haltchain-api

echo "==> HaltChain installed and started."
echo "    Logs: journalctl -u haltchain-api -f"
INSTALL

chmod +x "$PKG_DIR/install.sh"

###############################################################################
# 4. Write README
###############################################################################
cat > "$PKG_DIR/README.md" << README
# HaltChain Air-Gap Deployment Package ${VERSION}

## Contents

| Path | Description |
|------|-------------|
| bin/haltchain-api | Pre-built API server binary (standalone mode) |
| models/           | ONNX embedding model (if included) |
| rules/            | Regulatory rule pack YAML files |
| migrations/       | PostgreSQL migration SQL (optional, for DB mode) |
| install.sh        | Automated installer (systemd) |

## Quick Install

```bash
# Copy the .tar.gz to the target machine then:
tar -xzf haltchain-airgap-${VERSION}-$(uname -m).tar.gz
cd haltchain-airgap-${VERSION}-$(uname -m)
sudo ./install.sh
```

## Configuration

The installer creates \`/etc/systemd/system/haltchain-api.service\`.
Override any environment variable by editing that file:

| Variable | Default | Description |
|----------|---------|-------------|
| HALTCHAIN_SQLITE_PATH | /var/lib/haltchain/haltchain.db | SQLite database path |
| HALTCHAIN_RULE_PACK_DIR | /opt/haltchain/rules | Directory of YAML rule packs |
| HALTCHAIN_MODEL_PATH | /opt/haltchain/models | ONNX model directory |
| HALTCHAIN_ENV | standalone | Deployment mode (standalone / production) |
| PORT | 8080 | Listening port |

## Offline Mode

When HALTCHAIN_ENV=standalone the server uses SQLite for storage and
hash-based embeddings as a fallback if the ONNX model is absent.
All safety decisions are enforced locally — no external network calls.
README

###############################################################################
# 5. Create tarball
###############################################################################
mkdir -p "$OUT_DIR"
TAR_PATH="$OUT_DIR/${PACKAGE_NAME}.tar.gz"
tar -czf "$TAR_PATH" -C "$STAGE" "$PACKAGE_NAME"
echo "==> Package written to: $TAR_PATH"
echo "    Size: $(du -h "$TAR_PATH" | cut -f1)"
