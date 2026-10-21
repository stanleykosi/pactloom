#!/usr/bin/env bash
# Bootstrap-only disposable GitHub CI. Never a local/product qualification entry.
set -euo pipefail
umask 077
ulimit -c 0
exec python3 -I -B scripts/ci-bootstrap-supervisor.py run
