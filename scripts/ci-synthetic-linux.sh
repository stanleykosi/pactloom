#!/usr/bin/env bash
# One expressly authorized disposable Linux job. No secrets, public-chain calls,
# caches, runtime archives or global security changes. This is not GUI acceptance.
set -euo pipefail
umask 077
ulimit -c 0
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]]
[[ "${GITHUB_REPOSITORY:-}" == stanleykosi/pactloom ]]
[[ "${GITHUB_REF:-}" == refs/heads/qualification/linux-native-synthetic-wip90 ]]
[[ "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]]
[[ "$(uname -m)" == x86_64 ]]
for program in rustup curl sha256sum tar make gcc perl tclsh pkg-config python3 timeout openssl; do
  command -v "$program" >/dev/null || { echo "Missing prerequisite: $program" >&2; exit 2; }
done
python3 - <<'PY'
import os, pathlib, resource, shutil
assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
memory = next(int(line.split()[1]) * 1024 for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
free = shutil.disk_usage('.').free
assert memory >= 8 * 1024**3 and free >= 8 * 1024**3, 'Insufficient clean standard-runner headroom'
try:
    value = pathlib.Path('/proc/sys/kernel/core_pattern').read_bytes()[:4097]
    collector = 'Pipe' if value.lstrip().startswith(b'|') else 'File' if 0 < len(value) <= 4096 else 'Unknown'
except OSError:
    collector = 'Unknown'
print(f'CI_PREFLIGHT cpu={os.cpu_count()} memory_available_bytes={memory} disk_free_bytes={free} core_limit=0 collector={collector}')
print('Synthetic disposable runner only; collector crash-copy absence and secure deletion are not verified.')
PY
build_root="$(mktemp -d "${RUNNER_TEMP:?}/pactloom-build.XXXXXX")"
# A short path is essential for the actual Linux Unix-domain socket budget.
runtime_root="$(mktemp -d /tmp/wpc.XXXXXX)"
finish() {
  local status=$?
  trap - EXIT
  # Never remove unknown contents or files beneath potentially live descendants.
  if rmdir -- "$runtime_root" 2>/dev/null; then
    echo 'CI_RUNTIME_CONTAINER empty_removed=true'
  else
    echo 'CI_RUNTIME_CONTAINER empty_removed=false cleanup_unverified=true'
    if [[ $status -eq 0 ]]; then status=1; fi
  fi
  exit "$status"
}
trap finish EXIT
export CARGO_HOME="$build_root/cargo" CARGO_TARGET_DIR="$build_root/target"
export WHOLEPACT_SQLCIPHER_PREFIX="$build_root/sqlcipher"
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 WHOLEPACT_BUILD_JOBS=3
unset RUST_MIN_STACK RUST_BACKTRACE RUST_LOG
# Official numbered toolchain, not floating stable or the runner's future default.
timeout --signal=TERM --kill-after=30s 600s rustup toolchain install 1.99.0 --profile minimal --no-self-update
[[ "$(rustup run 1.99.0 rustc --version)" == 'rustc 1.99.0 (b940084d7 2026-09-28)' ]]
rustup run 1.99.0 rustc -Vv
rustup run 1.99.0 cargo -V
# Existing official-source checksums, private prefix, static SQLCipher/OpenSSL.
timeout --signal=TERM --kill-after=30s 1500s bash scripts/build-encrypted-storage-deps.sh
# The existing provider recipe builds libraries only. Build its same pinned CLI
# privately too; runtime TLS must not silently use a different image version.
timeout --signal=TERM --kill-after=30s 300s make -C "$WHOLEPACT_SQLCIPHER_PREFIX/build/openssl-3.5.9" -j3 build_programs
export PATH="$WHOLEPACT_SQLCIPHER_PREFIX/build/openssl-3.5.9/apps:$PATH"
# install_dev does not install the CLI default config. Use only the same pinned
# official source config for these private synthetic certificate commands.
export OPENSSL_CONF="$WHOLEPACT_SQLCIPHER_PREFIX/build/openssl-3.5.9/apps/openssl.cnf"
[[ -f "$OPENSSL_CONF" ]]
[[ "$(openssl version)" == OpenSSL\ 3.5.9\ * ]]
source scripts/encrypted-storage-env.sh
# The locked libsqlite3-sys uses this exact .pc through SQLCIPHER_LIB_DIR.
# Prove the complete private static dependency list instead of allowing its bare
# SQLCipher fallback to conceal a missing OpenSSL link edge.
[[ "$(PKG_CONFIG_PATH="$SQLCIPHER_LIB_DIR/pkgconfig" pkg-config --variable=prefix sqlcipher)" == "$WHOLEPACT_SQLCIPHER_PREFIX" ]]
link_flags="$(PKG_CONFIG_PATH="$SQLCIPHER_LIB_DIR/pkgconfig" pkg-config --static --libs sqlcipher)"
[[ "$link_flags" == "-L$WHOLEPACT_SQLCIPHER_PREFIX/lib -lsqlcipher -L$WHOLEPACT_SQLCIPHER_PREFIX/openssl/lib -lcrypto -ldl -lpthread -lm " ]]
unset link_flags
# Both runtime TLS CLI and encrypted storage use the verified 3.5.9 build.
openssl version
sha256sum Cargo.lock
# No project test executes during compilation; metadata contains public build data.
timeout --signal=TERM --kill-after=30s 3600s rustup run 1.99.0 cargo test --locked --release -p wholepact-native-host --all-features --lib --no-run --message-format=json > "$build_root/build-metadata.jsonl"
executable="$(python3 - "$build_root/build-metadata.jsonl" "$CARGO_TARGET_DIR" <<'PY'
import json, pathlib, sys
found=[]
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    row=json.loads(line)
    if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='wholepact_native_host' and row.get('profile',{}).get('test') and row.get('executable'):
        found.append(pathlib.Path(row['executable']).resolve(strict=True))
assert len(set(found))==1
exe=found[0]; assert exe.is_file() and exe.is_relative_to(pathlib.Path(sys.argv[2]).resolve(strict=True))
print(exe)
PY
)"
sha256sum "$executable"
# The private account/envelope regressions live in the signer lib, not the Host
# executable. Reuse this exact release target and dependencies; do not run a
# broad signer suite or any ignored/native tests during this separate build.
# The unchanged 150-minute whole-job cap is authoritative and may interrupt
# before all individual phase maxima are exhausted; they are not additive grants.
timeout --signal=TERM --kill-after=30s 1200s rustup run 1.99.0 cargo test --locked --release -p wholepact-signer --all-features --lib --no-run --message-format=json > "$build_root/signer-build-metadata.jsonl"
signer_executable="$(python3 - "$build_root/signer-build-metadata.jsonl" "$CARGO_TARGET_DIR" <<'PY'
import json, pathlib, sys
found=[]
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    row=json.loads(line)
    if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='wholepact_signer' and row.get('profile',{}).get('test') and row.get('executable'):
        found.append(pathlib.Path(row['executable']).resolve(strict=True))
assert len(set(found))==1
exe=found[0]; assert exe.is_file() and exe.is_relative_to(pathlib.Path(sys.argv[2]).resolve(strict=True))
print(exe)
PY
)"
sha256sum "$signer_executable"
# All runtime output is bounded and allowlisted by this script; never tee raw PTY,
# test panics, private paths, wallets, collector files or process environments.
export TMPDIR="$runtime_root"
python3 -B scripts/ci-synthetic-output-tests.py
python3 -B scripts/ci-synthetic-output.py "$signer_executable" signer-validation
python3 -B scripts/ci-synthetic-output.py "$executable" pure
python3 -B scripts/ci-synthetic-output.py "$executable" storage-bootstrap
python3 -B scripts/ci-synthetic-output.py "$executable" initial
python3 -B scripts/ci-synthetic-output.py "$executable" full
# A leftover runtime container is a job failure, never an implicit cleanup pass.
rmdir -- "$runtime_root"
trap - EXIT
echo 'CI_RUNTIME_CONTAINER empty_removed=true'
printf '%s\n' 'Synthetic-only initial and full path passed; no public-chain settlement, attended GUI, Windows, or production activation claimed.'
