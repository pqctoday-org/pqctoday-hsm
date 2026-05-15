#!/usr/bin/env bash
# build-pkcs11-provider-wasm.sh — Build pkcs11-provider 0.4.0 as a static WASM archive.
#
# Output: build-wasm/lib/libpkcs11-provider.a
#
# This is the OpenSSL 3.x provider that bridges PKCS#11 modules into OpenSSL's
# crypto stack. In the native build the library is loaded via dlopen("pkcs11-provider.so").
# In the WASM build we link the provider statically into the consuming binary
# (e.g. pqctoday-hub/openssl.wasm) so that during a TLS handshake the OpenSSL TLS
# state machine's EVP_DigestSign on a pkcs11: URI key dispatches into the
# statically-linked softhsmv3 in-process. No dynamic linking, no postMessage RPC.
#
# The provider's entry point (OSSL_provider_init) is renamed via -DOSSL_provider_init=p11prov_init
# so it doesn't collide with anything else and so the consumer can call:
#   extern int p11prov_init(...);
#   OSSL_PROVIDER_add_builtin(NULL, "pkcs11", p11prov_init);
#   OSSL_PROVIDER_load(NULL, "pkcs11");
#
# Idempotent: skips the build if the output already exists. Set FORCE=1 to rebuild.
#
# Requirements: emcc (Emscripten SDK), and a previously built OpenSSL WASM
# (libcrypto.a + headers) at $OPENSSL_WASM. Run pqctoday-hsm/scripts/build-openssl-wasm.sh
# first if you don't have it.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"            # pqctoday-hsm/
SRC_DIR="$ROOT/src/vendor/pkcs11-provider/src"
BUILD_DIR="$ROOT/build-wasm/pkcs11-provider"
INSTALL_LIB="$ROOT/build-wasm/lib"
OUTPUT_AR="$INSTALL_LIB/libpkcs11-provider.a"

OPENSSL_WASM="${OPENSSL_WASM:-$ROOT/deps/openssl-wasm}"

# ── Sanity ────────────────────────────────────────────────────────────────────
command -v emcc  >/dev/null || { echo "[p11prov-wasm] emcc not in PATH" >&2; exit 1; }
command -v emar  >/dev/null || { echo "[p11prov-wasm] emar not in PATH" >&2; exit 1; }
[[ -d "$SRC_DIR" ]] || { echo "[p11prov-wasm] missing $SRC_DIR" >&2; exit 1; }
[[ -f "$OPENSSL_WASM/lib/libcrypto.a" ]] || {
    echo "[p11prov-wasm] missing libcrypto.a at $OPENSSL_WASM/lib (run build-openssl-wasm.sh first)" >&2
    exit 1
}
[[ -d "$OPENSSL_WASM/include" ]] || {
    echo "[p11prov-wasm] missing OpenSSL headers at $OPENSSL_WASM/include" >&2
    exit 1
}

if [[ -f "$OUTPUT_AR" && "${FORCE:-0}" != "1" ]]; then
    echo "[p11prov-wasm] $OUTPUT_AR already exists. Set FORCE=1 to rebuild."
    exit 0
fi

echo "[p11prov-wasm] emcc        : $(emcc --version 2>&1 | head -1)"
echo "[p11prov-wasm] OpenSSL WASM: $OPENSSL_WASM"
echo "[p11prov-wasm] build dir   : $BUILD_DIR"
echo "[p11prov-wasm] output      : $OUTPUT_AR"

mkdir -p "$BUILD_DIR" "$INSTALL_LIB"

# ── Source list (mirrors CMakeLists.txt PROVIDER_SOURCES) ─────────────────────
SOURCES=(
    "asymmetric_cipher.c"
    "cipher.c"
    "composite.c"
    "debug.c"
    "decoder.c"
    "digests.c"
    "encoder.c"
    "exchange.c"
    "kdf.c"
    "keymgmt.c"
    "pk11_uri.c"
    "interface.c"
    "objects.c"
    "provider.c"
    "random.c"
    "session.c"
    "sig/signature.c"
    "sig/rsasig.c"
    "sig/ecdsa.c"
    "sig/eddsa.c"
    "sig/mldsa.c"
    "skeymgmt.c"
    "slot.c"
    "store.c"
    "tls.c"
    "util.c"
    "kem/mlkem.c"
    "sig/slhdsa.c"
    "sig/xmss.c"
)

# ── Compile each source ───────────────────────────────────────────────────────
CFLAGS=(
    "-O2"
    "-Wno-unused-parameter"
    "-Wno-unused-but-set-variable"
    "-Wno-implicit-function-declaration"
    "-fno-strict-aliasing"
    # Rename the entry point so the consumer can declare it explicitly.
    "-DOSSL_provider_init=p11prov_OSSL_provider_init"
    # PACKAGE_*/P11PROV_VERSION come from config.h — do not redefine here.
    "-I$SRC_DIR"
    "-I$SRC_DIR/.."
    "-I$OPENSSL_WASM/include"
    # Force-include pthread.h: a couple of source files (e.g. slot.c) rely on
    # a transitively-included pthread.h that's pulled in by glibc <features.h>
    # under _GNU_SOURCE. Emscripten's libc doesn't pull it implicitly. We need
    # the type declarations + function prototypes; the actual rwlock/mutex
    # implementations are stubbed (single-threaded WASM) by the consumer's
    # pkcs11_static_shim.c. Do NOT pass -pthread — that would force
    # --shared-memory at link, which is incompatible with the pre-built
    # libssl.a / libcrypto.a (compiled with no-threads).
    "-include" "pthread.h"
)

OBJS=()
for src in "${SOURCES[@]}"; do
    obj="$BUILD_DIR/${src//\//__}.o"
    OBJS+=("$obj")
    echo "[p11prov-wasm] CC  $src"
    emcc "${CFLAGS[@]}" -c "$SRC_DIR/$src" -o "$obj"
done

# ── Pack into static archive ──────────────────────────────────────────────────
rm -f "$OUTPUT_AR"
echo "[p11prov-wasm] AR  $(basename "$OUTPUT_AR")"
emar rcs "$OUTPUT_AR" "${OBJS[@]}"

echo "[p11prov-wasm] Done. $(ls -lh "$OUTPUT_AR" | awk '{print $5, $9}')"
