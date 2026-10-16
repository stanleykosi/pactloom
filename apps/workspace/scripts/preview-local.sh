#!/bin/bash
set -eu
cd "$(dirname "$0")/../../.."
test -x target/debug/wholepact-service
test -f apps/workspace/package.json
./target/debug/wholepact-service --development-fixture --database "${WHOLEPACT_FIXTURE_DB:-/tmp/wholepact-cloud-ui-synthetic.sqlite}" &
service_pid=$!
trap 'kill "$service_pid" 2>/dev/null || true' EXIT
if command -v npm >/dev/null 2>&1; then
  npm run dev --prefix apps/workspace
else
  test -f apps/workspace/dist/index.html
  python3 -m http.server 4319 --bind 127.0.0.1 --directory apps/workspace/dist
fi
