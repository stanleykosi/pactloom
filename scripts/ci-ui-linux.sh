#!/usr/bin/env bash
# Exact-event disposable GitHub CI only. Never a local installation or runner.
set -euo pipefail
umask 077
ulimit -c 0
exec python3 -I -B scripts/ci-ui-reuse-runner.py
