#!/usr/bin/env bash
# End-to-end demo: fake vulnerable PHP host -> scan -> code-base audit -> fixes.
# Nothing outside a temp directory is modified.
set -euo pipefail

PORT="${PORT:-8089}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"

cleanup() { [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "==> starting fake PHP 8.1.2 host on port $PORT"
python3 "$HERE/examples/fake_php_host.py" --port "$PORT" --version 8.1.2 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1.5

echo "==> copying the sample project to $WORK/app"
cp -r "$HERE/examples/sample-app" "$WORK/app"

echo
echo "==> scan + audit + plan fixes (offline mock engine, dry run)"
python3 "$HERE/php2shell.py" scan "http://127.0.0.1:$PORT" \
    --probe \
    --codebase "$WORK/app" \
    --fix \
    --llm-provider mock \
    --dry-run \
    --report-dir "$WORK/reports"

echo
echo "==> reports:"
ls -1 "$WORK/reports"
echo
echo "==> now try the interactive flow yourself:"
echo "    python3 $HERE/php2shell.py"
