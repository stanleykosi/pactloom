# Source from a shell before Cargo, after build-encrypted-storage-deps.sh.
# Override WHOLEPACT_SQLCIPHER_PREFIX for an explicitly selected private prefix.
wholepact_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wholepact_cipher_prefix="${WHOLEPACT_SQLCIPHER_PREFIX:-$wholepact_root/target/encrypted-storage-deps}"
if [ ! -f "$wholepact_cipher_prefix/env.sh" ]; then
  printf '%s\n' 'Encrypted storage dependencies are missing. Run scripts/build-encrypted-storage-deps.sh.' >&2
  return 1
fi
. "$wholepact_cipher_prefix/env.sh"
unset wholepact_root wholepact_cipher_prefix
