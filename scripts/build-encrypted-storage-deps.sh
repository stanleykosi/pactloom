#!/usr/bin/env bash
# Build pinned official releases into a private prefix. No sudo/system installs.
set -euo pipefail
umask 077
root="$(cd "$(dirname "$0")/.." && pwd)"
prefix="${WHOLEPACT_SQLCIPHER_PREFIX:-$root/target/encrypted-storage-deps}"
jobs="${WHOLEPACT_BUILD_JOBS:-4}"
case "$prefix" in /*) ;; *) echo 'Prefix must be absolute' >&2; exit 1;; esac
case "$prefix" in *[[:space:]]*) echo 'Prefix must not contain whitespace' >&2; exit 1;; esac
for program in curl sha256sum tar make gcc perl tclsh pkg-config; do command -v "$program" >/dev/null; done
mkdir -p "$prefix/sources" "$prefix/build" "$prefix/lib/pkgconfig" "$prefix/include" "$prefix/licenses"
fetch() {
  local url="$1" file="$2" digest="$3"
  if [[ ! -f "$file" ]]; then
    curl --proto '=https' --tlsv1.2 --fail --show-error --location "$url" --output "$file.part"
    mv "$file.part" "$file"
  fi
  printf '%s  %s\n' "$digest" "$file" | sha256sum --check --status
}
openssl_version=3.5.9
openssl_digest=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
cipher_commit=c4b275a47932888216bade83aff2bbc73df0ff85
cipher_digest=e56d1f43cb18ec90d68b4b52d54c00b8b1c11605a27fbbba4249a1d6fc042a6f
fetch "https://github.com/openssl/openssl/releases/download/openssl-$openssl_version/openssl-$openssl_version.tar.gz" "$prefix/sources/openssl-$openssl_version.tar.gz" "$openssl_digest"
fetch "https://codeload.github.com/sqlcipher/sqlcipher/tar.gz/$cipher_commit" "$prefix/sources/sqlcipher-4.19.0.tar.gz" "$cipher_digest"
if [[ ! -f "$prefix/build/openssl-$openssl_version/libcrypto.a" ]]; then
  tar -xzf "$prefix/sources/openssl-$openssl_version.tar.gz" -C "$prefix/build"
  (
    cd "$prefix/build/openssl-$openssl_version"
    ./Configure --prefix="$prefix/openssl" --libdir=lib no-shared no-tests no-module -fPIC
    make -j"$jobs" build_libs
    make install_dev
  )
fi
# A failed install may leave a built library; repair installation without rebuild.
if [[ ! -f "$prefix/openssl/lib/libcrypto.a" ]]; then
  (cd "$prefix/build/openssl-$openssl_version" && make install_dev)
fi
if [[ ! -f "$prefix/build/sqlcipher-$cipher_commit/sqlite3.c" ]]; then
  tar -xzf "$prefix/sources/sqlcipher-4.19.0.tar.gz" -C "$prefix/build"
fi
(
  cd "$prefix/build/sqlcipher-$cipher_commit"
  CFLAGS="-O2 -fPIC -DSQLITE_HAS_CODEC -DSQLITE_TEMP_STORE=3 -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_API_ARMOR -DSQLCIPHER_OMIT_LOG -DSQLITE_DEFAULT_FOREIGN_KEYS=1 -I$prefix/openssl/include" \
  LDFLAGS="-L$prefix/openssl/lib -lcrypto -ldl -lpthread" \
    ./configure --prefix="$prefix" --disable-shared --disable-readline --with-tempstore=always --enable-fts5
  make -j"$jobs" libsqlite3.a sqlite3
  # Upstream renamed its library in 4.7; rusqlite sqlcipher expects libsqlcipher.
  cp libsqlite3.a "$prefix/lib/libsqlcipher.a"
  cp sqlite3.h sqlite3ext.h "$prefix/include/"
  mkdir -p "$prefix/bin"
  cp sqlite3 "$prefix/bin/sqlcipher"
  cp LICENSE.md "$prefix/licenses/SQLCipher-LICENSE.md"
)
cp "$prefix/build/openssl-$openssl_version/LICENSE.txt" "$prefix/licenses/OpenSSL-LICENSE.txt"
cat > "$prefix/lib/pkgconfig/sqlcipher.pc" <<PC
prefix=$prefix
libdir=\${prefix}/lib
includedir=\${prefix}/include
Name: sqlcipher
Description: Wholepact pinned SQLCipher 4.19.0 / OpenSSL 3.5.9
Version: 3.53.4
Libs: -L\${libdir} -lsqlcipher -L\${prefix}/openssl/lib -lcrypto -ldl -lpthread -lm
Cflags: -I\${includedir} -DSQLITE_HAS_CODEC
PC
cat > "$prefix/env.sh" <<ENV
export SQLCIPHER_LIB_DIR='$prefix/lib'
export SQLCIPHER_INCLUDE_DIR='$prefix/include'
export SQLCIPHER_STATIC=1
export PKG_CONFIG_ALL_STATIC=1
export WHOLEPACT_SQLCIPHER_PREFIX='$prefix'
ENV
# An explicitly synthetic, in-memory check. Provider queries require a keyed handle.
# The fixed test string is never an actual database or user credential.
cat > "$prefix/build/version-check.c" <<'C'
#include <stdio.h>
#define SQLITE_HAS_CODEC 1
#include "sqlite3.h"
static int print_value(void *unused, int n, char **values, char **names) {
  (void) unused; (void) names;
  for (int i=0;i<n;i++) if (values[i]) puts(values[i]);
  return 0;
}
int main(void) {
  sqlite3 *db = NULL;
  if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
  if (sqlite3_key(db, "synthetic-build-smoke", 21) != SQLITE_OK) return 2;
  int rc = sqlite3_exec(db, "PRAGMA cipher_version; PRAGMA cipher_provider; PRAGMA cipher_provider_version;", print_value, NULL, NULL);
  sqlite3_close(db);
  return rc;
}
C
gcc -I"$prefix/include" "$prefix/build/version-check.c" -L"$prefix/lib" -lsqlcipher -L"$prefix/openssl/lib" -lcrypto -ldl -lpthread -lm -o "$prefix/build/version-check"
"$prefix/build/version-check" | tee "$prefix/build-versions.txt"
grep -q '^4\.19\.0 ' "$prefix/build-versions.txt"
grep -q 'OpenSSL 3\.5\.9 ' "$prefix/build-versions.txt"
printf '\nSource the build environment before Cargo: . %s/env.sh\n' "$prefix"
