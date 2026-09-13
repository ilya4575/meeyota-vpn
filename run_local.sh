#!/usr/bin/env bash
# Запуск pipeline локально для отладки.

set -euo pipefail

cd "$(dirname "$0")"

pip install -q -r requirements.txt

# Опционально — прокинуть GITHUB_TOKEN для увеличения rate-limit
if [ -n "${GITHUB_TOKEN:-}" ]; then
  export GITHUB_TOKEN
fi

python -m src.main "$@"

echo
echo "Output:"
ls -la output/
