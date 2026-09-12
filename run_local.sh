#!/usr/bin/env bash
# Локальный запуск meeyota-vpn (без проверок соединения).
# Для проверок «VPN Wi-fi» дополнительно нужен sing-box в PATH или SINGBOX_BIN.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  ./.venv/bin/pip install --upgrade pip
  ./.venv/bin/pip install -r requirements.txt
fi

ARGS=()
if command -v sing-box >/dev/null 2>&1 || [ -n "${SINGBOX_BIN:-}" ]; then
  ARGS+=(--checks)
fi

./.venv/bin/python -m src.main "${ARGS[@]}" --verbose
