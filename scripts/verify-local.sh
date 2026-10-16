#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v cargo >/dev/null 2>&1; then
  echo 'A supported Rust toolchain is required on PATH.' >&2
  exit 1
fi

# Fail closed when the pinned encrypted-storage native libraries are missing.
source scripts/encrypted-storage-env.sh

# Local code checks only. This script never signs or broadcasts a network payment.
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings

if [[ -f apps/workspace/package-lock.json ]]; then
  (cd apps/workspace && npm ci && npm run build)
fi

printf '\nLocal code checks passed. This is not network or release qualification.\n'
