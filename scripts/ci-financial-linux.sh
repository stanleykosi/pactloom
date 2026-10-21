#!/usr/bin/env bash
# Exact-event disposable GitHub CI only. Never a local installation.
set -euo pipefail
umask 077
ulimit -c 0
# Pure fail-closed recipe/projection checks run before any credential or fixture.
python3 -I -B scripts/ci-financial-launch-tests.py
exec python3 -I -B scripts/ci-financial-supervisor.py run
