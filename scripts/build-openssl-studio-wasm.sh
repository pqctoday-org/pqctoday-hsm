#!/usr/bin/env bash
# build-openssl-studio-wasm.sh — Link the OpenSSL Studio engine bundle
# (`openssl-pkcs11` in engines/bundles.json): the OpenSSL 3.6.3 command-line
# tool for the browser, with pkcs11-provider and the Rust PKCS#11 engine
# (softhsmrustv3) linked in statically, plus the C shims the Hub's OpenSSL
# Studio, TLS, CMS and CMP workshops call.
#
# Output (a staging folder laid out like the consumer, gitignored):
#   build-wasm/engines-staging/public/wasm/openssl.js
#   build-wasm/engines-staging/public/wasm/openssl.wasm
#   build-wasm/engines-staging/openssl-link-inputs.json   (record, not shipped)
# scripts/publish_engines.py package --from build-wasm/engines-staging ...
# packages the two declared files. Nothing is copied into any other checkout.
#
# Run it in the Emscripten image the bundle is built with (pinned by digest,
# emsdk 6.0.4 arm64), from the repository root:
#
#   docker run --rm -v "$PWD:/src" -w /src --entrypoint bash \
#     emscripten/emsdk@sha256:3a0d11e50f072dc2c4bc92e3b05ab1340fb7d4dd152f80b8af35fc1c6f15e644 \
#     scripts/build-openssl-studio-wasm.sh
#
# Inputs:
#   - OpenSSL 3.6.3 source tarball, pinned by SHA-256 (the same pin as
#     scripts/build-openssl-wasm.sh; the cached tarball is shared with it).
#     This script configures its own tree WITH the apps, so it cannot reuse
#     the no-apps library build in deps/openssl-wasm.
#   - wasm/openssl-studio/patches/*.patch, applied to the fresh tree.
#   - wasm/openssl-studio/shims/*.c, the C entry points the Hub calls.
#   - build-wasm/lib/libpkcs11-provider.a from
#     scripts/build-pkcs11-provider-wasm.sh (built here if missing; it needs
#     deps/openssl-wasm from scripts/build-openssl-wasm.sh, also built here if
#     missing).
#   - libsofthsmrustv3.a, the Rust engine as a wasm32-unknown-emscripten
#     staticlib. It is built in the Rust container, not here:
#       cd rust && cargo rustc --locked --release \
#         --target wasm32-unknown-emscripten --lib --crate-type staticlib
#     and is expected at rust/target/wasm32-unknown-emscripten/release/
#     (copy it there if your CARGO_TARGET_DIR is elsewhere, or set SOFTHSM_AR).
#     Only ONE PKCS#11 engine may be linked: both engines export the same C_*
#     symbols. The Rust engine is used because it does not depend on OpenSSL,
#     so the provider path is an independent implementation rather than
#     OpenSSL calling itself through PKCS#11.
#
# Env overrides:
#   SOFTHSM_AR=...        path to libsofthsmrustv3.a
#   PKCS11_PROVIDER_AR=.. path to libpkcs11-provider.a
#   STAGING_DIR=...       output folder (default build-wasm/engines-staging)
#   JOBS=N                make parallelism (default: CPU count)

set -euo pipefail

OSSL_VERSION=3.6.3
OSSL_SHA256="243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1"
OSSL_URL="https://www.openssl.org/source/openssl-${OSSL_VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STUDIO_DIR="$ROOT/wasm/openssl-studio"
SHIMS="$STUDIO_DIR/shims"
PATCH_DIR="$STUDIO_DIR/patches"
WORK_DIR="$ROOT/build-wasm/openssl-studio"
STAGING_DIR="${STAGING_DIR:-$ROOT/build-wasm/engines-staging}"
TARBALL_DIR="$ROOT/deps/openssl-src"
TARBALL="$TARBALL_DIR/openssl-${OSSL_VERSION}.tar.gz"
PKCS11_PROVIDER_AR="${PKCS11_PROVIDER_AR:-$ROOT/build-wasm/lib/libpkcs11-provider.a}"
SOFTHSM_AR="${SOFTHSM_AR:-$ROOT/rust/target/wasm32-unknown-emscripten/release/libsofthsmrustv3.a}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

log() { echo "[openssl-studio-wasm] $*"; }
die() { echo "[openssl-studio-wasm] ERROR: $*" >&2; exit 1; }

command -v emcc >/dev/null || die "emcc not in PATH (run inside the Emscripten image, see header)"
log "emcc: $(emcc --version 2>&1 | head -1)"

# ── Link inputs from this repository ─────────────────────────────────────────
if [[ ! -f "$ROOT/deps/openssl-wasm/lib/libcrypto.a" && ! -f "$PKCS11_PROVIDER_AR" ]]; then
    log "deps/openssl-wasm missing; building it (needed by pkcs11-provider)"
    bash "$ROOT/scripts/build-openssl-wasm.sh"
fi
if [[ ! -f "$PKCS11_PROVIDER_AR" ]]; then
    log "pkcs11-provider archive missing; building it"
    bash "$ROOT/scripts/build-pkcs11-provider-wasm.sh"
fi
[[ -f "$PKCS11_PROVIDER_AR" ]] || die "no pkcs11-provider archive at $PKCS11_PROVIDER_AR"
[[ -f "$SOFTHSM_AR" ]] || die "no Rust engine staticlib at $SOFTHSM_AR (build it in the Rust container, see header)"
log "pkcs11-provider : $PKCS11_PROVIDER_AR"
log "pkcs11 module   : $SOFTHSM_AR"
for f in tls_simulation.c tls_simulation_hsm.c pkcs11_static_shim.c cms_provider_init.c cmp_simulation.c; do
    [[ -f "$SHIMS/$f" ]] || die "missing shim $SHIMS/$f"
done

# ── OpenSSL source: verified tarball, fresh tree every run ───────────────────
# A fresh extract means a pristine tree plus exactly the patches below; a
# reused, hand-patched tree is how a patch was once silently lost.
mkdir -p "$TARBALL_DIR"
if [[ ! -f "$TARBALL" ]]; then
    log "downloading $OSSL_URL"
    curl -fL "$OSSL_URL" -o "$TARBALL.part"
    mv "$TARBALL.part" "$TARBALL"
fi
ACTUAL_SHA256=$(shasum -a 256 "$TARBALL" 2>/dev/null | awk '{print $1}' || sha256sum "$TARBALL" | awk '{print $1}')
if [[ "$ACTUAL_SHA256" != "$OSSL_SHA256" ]]; then
    rm -f "$TARBALL"
    die "SHA-256 mismatch for $(basename "$TARBALL"): expected $OSSL_SHA256, got $ACTUAL_SHA256"
fi
log "tarball SHA-256 OK"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
tar xzf "$TARBALL" -C "$WORK_DIR"
OSSL_SRC="$WORK_DIR/openssl-${OSSL_VERSION}"
cd "$OSSL_SRC"

for patch in "$PATCH_DIR"/*.patch; do
    [[ -e "$patch" ]] || continue
    log "applying $(basename "$patch")"
    patch -p1 -N --silent < "$patch" || die "patch failed: $(basename "$patch")"
done

# ── Configure + compile OpenSSL with the apps ────────────────────────────────
export CC=emcc CXX=em++ AR=emar RANLIB=emranlib
EM_FLAGS="-sMODULARIZE=1 -sEXPORT_NAME=createOpenSSLModule -sINVOKE_RUN=0 -sEXIT_RUNTIME=1 -sALLOW_MEMORY_GROWTH=1 -sEXPORTED_RUNTIME_METHODS=FS,callMain -sEXPORTED_FUNCTIONS=_main -sWASM_BIGINT=1"

log "configuring OpenSSL ${OSSL_VERSION}"
./Configure linux-generic32 \
  no-asm \
  no-async \
  no-threads \
  no-shared \
  no-afalgeng \
  enable-legacy \
  enable-trace \
  -DOPENSSL_NO_SECURE_MEMORY \
  -DOPENSSL_NO_CONST_TIME \
  $EM_FLAGS

log "compiling with $JOBS jobs"
# Explicit targets, not build_sw: build_sw also builds the test providers,
# which cannot link under no-shared + Emscripten and abort the make before
# libcrypto.a and the apps objects exist.
make -j"$JOBS" build_generated
make -j"$JOBS" libcrypto.a libssl.a apps/libapps.a
# apps/openssl itself cannot link here (pqctoday_cms_init, called by the
# patch, is in a shim OpenSSL's Makefile does not know). That failure is
# expected; what matters is that every apps/openssl-bin-*.o is compiled first.
make -j"$JOBS" apps/openssl >/dev/null 2>&1 || log "apps/openssl link failed (expected); continuing with the custom link"
ls apps/openssl-bin-*.o >/dev/null 2>&1 || die "no apps/openssl-bin-*.o produced; the OpenSSL build failed earlier than expected"

# ── Shims ────────────────────────────────────────────────────────────────────
log "compiling shims"
emcc -Iinclude "$SHIMS/tls_simulation.c" -c -o tls_simulation.o
emcc -Iinclude "$SHIMS/tls_simulation_hsm.c" -c -o tls_simulation_hsm.o
emcc -Iinclude "$SHIMS/pkcs11_static_shim.c" -c -o pkcs11_static_shim.o
# cms_provider_init.c's composite helpers call into the statically linked
# provider and need its composite.h declarations.
emcc -Iinclude -I"$ROOT/src/vendor/pkcs11-provider/src" "$SHIMS/cms_provider_init.c" -c -o cms_provider_init.o
emcc -Iinclude "$SHIMS/cmp_simulation.c" -c -o cmp_simulation.o

# ── Link ─────────────────────────────────────────────────────────────────────
# STACK_SIZE: the 64 KB default overflows in the Rust engine's ML-DSA/ML-KEM
# key generation ("memory access out of bounds"); 8 MB costs address space,
# not committed memory.
LINK_FLAGS="-sMODULARIZE=1 -sEXPORT_NAME=createOpenSSLModule -sINVOKE_RUN=0 -sEXIT_RUNTIME=1 -sALLOW_MEMORY_GROWTH=1 -sWASM_BIGINT=1 -sSTACK_SIZE=8MB"
# Every apps/<cmd>.c subcommand is reached only through the dispatch table in
# apps/progs.c, which the optimiser may strip, so each *_main the Hub drives
# is exported explicitly.
EXPORTS="-sEXPORTED_FUNCTIONS=['_main','_execute_tls_simulation','_pqctoday_cms_init','_pqctoday_cms_shutdown','_pqctoday_composite_mkcert','_pqctoday_composite_cms_sign','_pqctoday_composite_cms_verify','_execute_cmp_simulation','_generate_mock_ca_root','_C_GetFunctionList','_C_Initialize','_C_Finalize','_C_GetSlotList','_C_GetTokenInfo','_C_InitToken','_C_InitPIN','_C_OpenSession','_C_CloseSession','_C_Login','_C_Logout','_C_GenerateKeyPair','_C_GetAttributeValue','_C_FindObjectsInit','_C_FindObjects','_C_FindObjectsFinal','_C_SignInit','_C_Sign','_C_MessageSignInit','_C_SignMessage','_C_MessageSignFinal','_pqctoday_hsm_state_take','_pqctoday_hsm_state_load','_pqctoday_hsm_state_free','_malloc','_free','_cmp_main','_req_main','_x509_main','_cms_main','_genpkey_main','_pkey_main','_pkeyutl_main','_crl2pkcs7_main','_verify_main','_asn1parse_main'] -sEXPORTED_RUNTIME_METHODS=['FS','callMain','cwrap','stringToUTF8','UTF8ToString','lengthBytesUTF8','ENV','HEAPU8','HEAP32','setValue','getValue']"

APPS_OBJS=$(ls apps/openssl-bin-*.o)
log "linking openssl.{js,wasm}"
# shellcheck disable=SC2086
emcc -o apps/openssl.js \
  $APPS_OBJS \
  apps/lib/openssl-bin-cmp_mock_srv.o \
  apps/libapps.a \
  libssl.a \
  libcrypto.a \
  tls_simulation.o \
  tls_simulation_hsm.o \
  pkcs11_static_shim.o \
  cms_provider_init.o \
  cmp_simulation.o \
  "$PKCS11_PROVIDER_AR" \
  "$SOFTHSM_AR" \
  $LINK_FLAGS \
  $EXPORTS

# ── Stage ────────────────────────────────────────────────────────────────────
mkdir -p "$STAGING_DIR/public/wasm"
cp apps/openssl.wasm "$STAGING_DIR/public/wasm/openssl.wasm"
cp apps/openssl.js   "$STAGING_DIR/public/wasm/openssl.js"

# Record what was actually linked. A commit hash cannot show that an input
# archive was stale; the archives' own digests can.
digest() { (shasum -a 256 "$1" 2>/dev/null || sha256sum "$1") | awk '{print $1}'; }
mtime()  { date -u -d "@$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1")" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
           || date -u -r "$(stat -f %m "$1")" +%Y-%m-%dT%H:%M:%SZ; }
HSM_COMMIT=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
cat > "$STAGING_DIR/openssl-link-inputs.json" <<JSON
{
  "_comment": "SHA-256 of every archive linked into openssl.wasm, recorded at link time by scripts/build-openssl-studio-wasm.sh.",
  "linked_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hsm_commit": "$HSM_COMMIT",
  "emcc": "$(emcc --version 2>&1 | head -1 | sed 's/"/\\"/g')",
  "openssl_tarball_sha256": "$OSSL_SHA256",
  "inputs": {
    "pkcs11_provider_ar": {
      "path": "${PKCS11_PROVIDER_AR#"$ROOT/"}",
      "sha256": "$(digest "$PKCS11_PROVIDER_AR")",
      "built_at": "$(mtime "$PKCS11_PROVIDER_AR")"
    },
    "softhsm_ar": {
      "path": "${SOFTHSM_AR#"$ROOT/"}",
      "sha256": "$(digest "$SOFTHSM_AR")",
      "built_at": "$(mtime "$SOFTHSM_AR")"
    }
  },
  "output_sha256": "$(digest apps/openssl.wasm)"
}
JSON

# Warn loudly when an input archive predates the commit it will be recorded
# against: not fatal (an untouched archive can be legitimately reused), but
# never silent.
src_epoch=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)
for ar in "$PKCS11_PROVIDER_AR" "$SOFTHSM_AR"; do
    ar_epoch=$(stat -c %Y "$ar" 2>/dev/null || stat -f %m "$ar" 2>/dev/null || echo 0)
    if (( ar_epoch > 0 && src_epoch > ar_epoch )); then
        echo "[openssl-studio-wasm] WARNING: $(basename "$ar") was built before the current HEAD commit; rebuild it." >&2
    fi
done

log "staged in ${STAGING_DIR#"$ROOT/"}/public/wasm:"
ls -l "$STAGING_DIR/public/wasm/openssl.js" "$STAGING_DIR/public/wasm/openssl.wasm"
