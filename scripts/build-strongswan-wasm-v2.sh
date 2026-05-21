#!/usr/bin/env bash
# build-strongswan-wasm-v2.sh — Clean-slate Emscripten build for strongSwan.
#
# Supersedes scripts/build-strongswan-wasm.sh (which produced a broken binary
# that aborted at library_init → settings_parser_parse_string).  The v1 script
# applied strongswan-6.0.5-wasm.patch that duplicated settings_parser_load_string
# with a wrong return type; removing that patch fixes the crash.
#
# This build:
#   1. Fetches upstream strongSwan 6.0.5.
#   2. Applies ONLY strongswan-6.0.5-pqc.patch (ML-DSA core — 882 lines).
#   3. Regenerates ASN.1 OID tables via oid.pl.
#   4. Overlays strongswan-pkcs11/ (our fork with ECDH + derive + BUILD_BLOB fixes).
#   5. Copies strongswan-wasm-v2-shims/*.c into the charon source tree.
#   6. autoreconf → emconfigure → emmake.
#   7. Produces dist/strongswan-v2.{js,wasm}.
#
# DOES NOT install to pqctoday-hub.  Phase 7 of the plan handles deployment.
# To copy the artifact into the hub, run scripts/copy-strongswan-wasm-v2-to-hub.sh
# (which doesn't exist yet; lands when Phase 6 cross-check passes).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"         # pqctoday-hsm/
BUILD_DIR="$ROOT/build/strongswan-wasm-v2"
SRC_DIR="$BUILD_DIR/strongswan-src"
DIST_DIR="$ROOT/strongswan-wasm-v2-shims/dist"

STRONGSWAN_VERSION="6.0.5"
TARBALL_URL="https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2"
PQC_PATCH="$ROOT/strongswan-6.0.5-pqc.patch"
PKCS1_SUPP_PATCH="$ROOT/strongswan-6.0.5-pqc-supplement.patch"
PLUGIN_SRC="$ROOT/strongswan-pkcs11"
SHIMS_SRC="$ROOT/strongswan-wasm-v2-shims"

OPENSSL_WASM="${OPENSSL_WASM:-$ROOT/deps/openssl-wasm}"
SOFTHSM_WASM="${SOFTHSM_WASM:-$ROOT/build-wasm/src/lib/libsofthsmv3-static.a}"

# ── Sanity ────────────────────────────────────────────────────────────────────
command -v emcc      >/dev/null || { echo "[v2] emcc not in PATH" >&2; exit 1; }
command -v autoreconf>/dev/null || { echo "[v2] autoreconf not found" >&2; exit 1; }
[[ -f "$OPENSSL_WASM/lib/libcrypto.a" ]] || { echo "[v2] missing libcrypto.a at $OPENSSL_WASM/lib" >&2; exit 1; }
[[ -f "$SOFTHSM_WASM" ]] || { echo "[v2] missing $SOFTHSM_WASM" >&2; exit 1; }
[[ -f "$PQC_PATCH" ]] || { echo "[v2] missing $PQC_PATCH" >&2; exit 1; }

echo "[v2] emcc       : $(emcc --version 2>&1 | head -1)"
echo "[v2] OpenSSL    : $OPENSSL_WASM"
echo "[v2] softhsmv3  : $SOFTHSM_WASM"
echo "[v2] build dir  : $BUILD_DIR"

mkdir -p "$BUILD_DIR" "$DIST_DIR"

# ── Step 1: Fetch strongSwan 6.0.5 ────────────────────────────────────────────
if [[ "${SKIP_FETCH:-0}" != "1" || ! -d "$SRC_DIR" ]]; then
    echo "[v2] Fetching strongSwan $STRONGSWAN_VERSION..."
    rm -rf "$SRC_DIR"
    TARBALL="$BUILD_DIR/strongswan-${STRONGSWAN_VERSION}.tar.bz2"
    [[ -f "$TARBALL" ]] || curl -fsSL -o "$TARBALL" "$TARBALL_URL"
    tar -xjf "$TARBALL" -C "$BUILD_DIR"
    mv "$BUILD_DIR/strongswan-${STRONGSWAN_VERSION}" "$SRC_DIR"
fi

cd "$SRC_DIR"

# ── Step 2: Apply PQC core patch ──────────────────────────────────────────────
echo "[v2] Applying $PQC_PATCH..."
patch -p1 --forward --no-backup-if-mismatch < "$PQC_PATCH" || true
if [[ -f "$PKCS1_SUPP_PATCH" ]]; then
    echo "[v2] Applying $PKCS1_SUPP_PATCH..."
    patch -p1 --forward --no-backup-if-mismatch < "$PKCS1_SUPP_PATCH" || true
fi

# ── Step 3: Regenerate OID tables ─────────────────────────────────────────────
echo "[v2] Regenerating ASN.1 OID tables via oid.pl..."
(cd src/libstrongswan/asn1 && perl oid.pl oid.txt oid.h oid.c)

# ── Step 3.1: Align settings_parser_load_string declaration with definition ──
# Harmless on native; WASM-ld warns and Emscripten's EMULATE_FUNCTION_POINTER_CASTS
# handles the runtime trampolining for the rest.  Keep just this one tiny fix.
echo "[v2] Patching settings_parser.c load_string declaration..."
sed -i.bak 's/^bool settings_parser_load_string(parser_helper_t \*ctx, const char \*content);$/void settings_parser_load_string(parser_helper_t *ctx, const char *content);/' \
    src/libstrongswan/settings/settings_parser.c

# ── Step 4: Overlay our pkcs11 plugin fork ────────────────────────────────────
echo "[v2] Overlaying $PLUGIN_SRC..."
cp -R "$PLUGIN_SRC"/* src/libstrongswan/plugins/pkcs11/

# ── Step 5: Drop in WASM shims ────────────────────────────────────────────────
echo "[v2] Installing WASM shims..."
cp "$SHIMS_SRC"/charon_wasm_main.c  src/charon/
cp "$SHIMS_SRC"/pkcs11_static.c     src/charon/
cp "$SHIMS_SRC"/posix_stubs.c       src/charon/
cp "$ROOT/strongswan-wasm-shims/pkcs11_wasm_rpc.c" src/charon/

# ── Step 6: autoreconf ────────────────────────────────────────────────────────
echo "[v2] Running autoreconf..."
autoreconf -i >/dev/null 2>&1

# ── Step 7: Phase 1 boot harness — just libstrongswan, no charon ──────────────
# For Checkpoint 1 we only want to prove library_init() doesn't crash.
# Full charon config + configure+make comes in Phase 2+.  For now:
#   - configure libstrongswan with minimal plugins
#   - build libstrongswan.a (static)
#   - link: charon_wasm_main.c + posix_stubs.c + pkcs11_static.c
#            + libstrongswan.a + libsofthsmv3-static.a + libcrypto.a
#   - emit dist/strongswan-v2-boot.{js,wasm}
echo "[v2] Configuring libstrongswan (Phase 1 boot)..."

export CC=emcc CXX=em++ AR=emar RANLIB=emranlib
export CFLAGS="-O2 -s USE_PTHREADS=0 -I$OPENSSL_WASM/include"
export LDFLAGS="-s USE_PTHREADS=0 -L$OPENSSL_WASM/lib"

# Cross-compile hint — we're emitting .wasm, not native host code.
# --disable-gmp, --disable-pgp: skip plugins that pull heavy deps.
# --with-lib-prefix=lib : static .a outputs.
emconfigure ./configure \
    --host=wasm32-unknown-emscripten \
    --prefix="$BUILD_DIR/install" \
    --disable-defaults \
    --enable-static \
    --disable-shared \
    --enable-monolithic \
    --enable-pem \
    --enable-pkcs1 \
    --enable-pkcs8 \
    --enable-x509 \
    --enable-pkcs11 \
    --enable-nonce \
    --enable-kdf \
    --enable-openssl \
    --enable-random \
    --enable-constraints \
    --enable-revocation \
    --enable-socket-default \
    --disable-kernel-netlink \
    --disable-kernel-pfkey \
    --disable-charon \
    --disable-tools \
    --disable-tests \
    --disable-scepclient \
    --disable-scripts \
    --disable-conftest \
    --with-capabilities=no \
    >"$BUILD_DIR/configure.log" 2>&1 || {
        echo "[v2] configure failed — see $BUILD_DIR/configure.log" >&2
        tail -30 "$BUILD_DIR/configure.log" >&2
        exit 1
    }

echo "[v2] Building libstrongswan.a..."
emmake make -j4 -C src/libstrongswan >"$BUILD_DIR/make.log" 2>&1 || {
    echo "[v2] make libstrongswan failed — see $BUILD_DIR/make.log" >&2
    tail -60 "$BUILD_DIR/make.log" >&2
    exit 1
}

# ── Step 8: Link Phase 1 boot harness ─────────────────────────────────────────
echo "[v2] Linking strongswan-v2-boot.{js,wasm}..."
LIBSTRONGSWAN="$SRC_DIR/src/libstrongswan/.libs/libstrongswan.a"
[[ -f "$LIBSTRONGSWAN" ]] || { echo "[v2] libstrongswan.a not built at $LIBSTRONGSWAN" >&2; exit 1; }

emcc \
    -O2 \
    -g \
    -include "$SRC_DIR/config.h" \
    -DWASM_CHARON_MAIN \
    -D__EMSCRIPTEN__ \
    -I"$SRC_DIR/src/libstrongswan" \
    -I"$SRC_DIR/src/libstrongswan/plugins/pkcs11" \
    -I"$OPENSSL_WASM/include" \
    "$SHIMS_SRC/charon_wasm_main.c" \
    "$SHIMS_SRC/pkcs11_static.c" \
    "$SHIMS_SRC/posix_stubs.c" \
    "$ROOT/strongswan-wasm-shims/pkcs11_wasm_rpc.c" \
    "$LIBSTRONGSWAN" \
    "$SOFTHSM_WASM" \
    "$OPENSSL_WASM/lib/libcrypto.a" \
    -s MODULARIZE=1 \
    -s EXPORT_NAME=StrongswanV2 \
    -s ASYNCIFY=1 \
    -s ASSERTIONS=2 \
    -s EMULATE_FUNCTION_POINTER_CASTS=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s INITIAL_MEMORY=32MB \
    -s MAXIMUM_MEMORY=256MB \
    -s EXPORTED_FUNCTIONS='["_main","_wasm_vpn_boot","_wasm_vpn_shutdown","_wasm_vpn_pkcs11_probe","_wasm_vpn_list_pqc_mechanisms","_wasm_vpn_ml_dsa_selftest","_wasm_vpn_ml_kem_selftest","_wasm_vpn_kem_alice_init","_wasm_vpn_kem_bob_encap","_wasm_vpn_kem_alice_decap","_wasm_vpn_kem_get_secret","_wasm_vpn_configure_json","_wasm_vpn_initiate","_wasm_vpn_get_result","_wasm_vpn_validate_proposal","_wasm_vpn_validate_cert","_wasm_vpn_list_key_exchanges","_malloc","_free"]' \
    -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","stringToUTF8","lengthBytesUTF8","HEAPU8"]' \
    -s ENVIRONMENT=web,worker,node \
    -o "$DIST_DIR/strongswan-v2-boot.js" \
    >"$BUILD_DIR/link.log" 2>&1 || {
        echo "[v2] link failed — see $BUILD_DIR/link.log" >&2
        tail -60 "$BUILD_DIR/link.log" >&2
        exit 1
    }

echo "[v2] ✓ Phase 1 artifact: $DIST_DIR/strongswan-v2-boot.{js,wasm}"
ls -la "$DIST_DIR"
