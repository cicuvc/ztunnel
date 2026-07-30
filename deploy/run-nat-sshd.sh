#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-$(dirname "$0")/../target/release/nat-sshd}"
STUN="${STUN_SERVER:-stunserver2025.stunprotocol.org:3478}"
REG="${REGISTRY_URL:-https://tapi.cicuvc.top}"

if [ ! -f "$BIN" ]; then
  echo "Usage: $0 [path-to-nat-sshd-binary]"
  echo "Binary not found: $BIN"
  exit 1
fi

# Check secret
SECRET_FILE="${HOME}/.config/ztunnel/secret"
if [ ! -f "$SECRET_FILE" ]; then
  echo "Missing secret: $SECRET_FILE"
  exit 1
fi

exec env \
  RUST_LOG="${RUST_LOG:-nat_sshd=info}" \
  STUN_SERVER="$STUN" \
  REGISTRY_URL="$REG" \
  "$BIN"
