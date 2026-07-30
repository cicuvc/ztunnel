#!/usr/bin/env bash
set -euo pipefail

SERVICE="ztunnel.nat-sshd"
UNIT="deploy/${SERVICE}.service"
TARGET="${HOME}/.config/systemd/user/"

mkdir -p "$TARGET"
cp "$UNIT" "${TARGET}/${SERVICE}.service"

systemctl --user daemon-reload
systemctl --user enable --now "$SERVICE"

echo "✓ ${SERVICE} installed and started"
echo "  Status: systemctl --user status ${SERVICE}"
echo "  Logs:   journalctl --user -u ${SERVICE} -f"
