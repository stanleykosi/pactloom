#!/usr/bin/env bash
# Exact-event disposable GitHub CI only. Never a local installation.
set -euo pipefail
umask 077
ulimit -c 0
# Pure fail-closed recipe/projection checks run before any credential or fixture.
python3 -I -B scripts/ci-financial-launch-tests.py
# Includes actual AF_UNIX bind regression; mandatory on the authorized runner.
python3 -I -B -m unittest discover -s scripts/tests -p 'test*financial*.py'
exec python3 -I -B scripts/ci-financial-supervisor.py run
