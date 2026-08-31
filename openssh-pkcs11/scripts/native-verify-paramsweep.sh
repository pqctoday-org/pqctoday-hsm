#!/usr/bin/env bash
# native-verify-paramsweep.sh — native (non-WASM) end-to-end verification for
# every ML-DSA / SLH-DSA parameter set this connector implements.
#
# Added 2026-08-31 alongside the ML-DSA-44/87 + 8-parameter-set SLH-DSA
# expansion: this environment had no Emscripten toolchain (emcc), so the
# existing sm1-smoke.cjs/sm5-slhdsa-smoke.cjs/sm6-paramsweep-smoke.cjs WASM
# harnesses could not be run. This script instead builds openssh-portable
# NATIVELY against a real OpenSSL 3.6.x (Homebrew openssl@3, or OPENSSL_DIR)
# and compiles native_paramsweep_test.c — a native port of
# wasm-shims/sshd_wasm_main.c's in-process drive_kex()/do_userauth() logic —
# linked against the REAL native softhsmv3 build (dlopen, OpenSSH's actual
# provider path, not the WASM static-link shim). It then drives a real SSH
# KEX + RFC 4252 publickey userauth round trip for all 11 new/existing
# parameter sets and asserts each one's exact FIPS 204/205 signature length.
#
# This does NOT replace the WASM smoke tests (sm1/sm5/sm6) — it is what
# stood in for them here. Run sm6-paramsweep-smoke.cjs for real the next time
# dist/ is rebuilt with emcc available (see STATUS.md).
#
# Prerequisites:
#   autoconf, automake, python3, a native softhsmv3 build (libsofthsmv3.dylib
#   or .so — SOFTHSM_NATIVE env, or the pqctoday-hsm root's build-native/)
#   OpenSSL >= 3.5 (OPENSSL_DIR env, default: brew --prefix openssl@3)
#
# Usage (from pqctoday-hsm/ root):
#   bash openssh-pkcs11/scripts/native-verify-paramsweep.sh
#   SKIP_OPENSSH_FETCH=1 bash openssh-pkcs11/scripts/native-verify-paramsweep.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"      # openssh-pkcs11/
HSM_ROOT="$(cd "$ROOT/.." && pwd)"            # pqctoday-hsm/
OPENSSH_VERSION="V_10_3_P1"
OPENSSH_SRC="$ROOT/build/openssh-src"
VERIFY_DIR="$ROOT/build/native-verify"

OPENSSL_DIR="${OPENSSL_DIR:-$(brew --prefix openssl@3 2>/dev/null || true)}"
SOFTHSM_NATIVE="${SOFTHSM_NATIVE:-$HSM_ROOT/build-native/src/lib/libsofthsmv3.dylib}"
if [[ ! -f "$SOFTHSM_NATIVE" ]]; then
    SOFTHSM_NATIVE="$HSM_ROOT/build/src/lib/libsofthsmv3.so"
fi

if [[ -z "$OPENSSL_DIR" || ! -x "$OPENSSL_DIR/bin/openssl" ]]; then
    echo "[native-verify] ERROR: OpenSSL >=3.5 dir not found (set OPENSSL_DIR)" >&2
    exit 1
fi
if [[ ! -f "$SOFTHSM_NATIVE" ]]; then
    echo "[native-verify] ERROR: native softhsmv3 build not found (set SOFTHSM_NATIVE)" >&2
    echo "  Build it: cd $HSM_ROOT && cmake -B build-native -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=\$(brew --prefix openssl@3) && cmake --build build-native" >&2
    exit 1
fi
echo "[native-verify] OpenSSL: $("$OPENSSL_DIR/bin/openssl" version)"
echo "[native-verify] softhsmv3: $SOFTHSM_NATIVE"

# ── Step 1: Fetch + patch OpenSSH source (same as build-wasm.sh step 1) ──────
mkdir -p "$ROOT/build"
if [[ "${SKIP_OPENSSH_FETCH:-0}" != "1" || ! -d "$OPENSSH_SRC" ]]; then
    echo "[native-verify] Cloning OpenSSH $OPENSSH_VERSION..."
    rm -rf "$OPENSSH_SRC"
    git clone --depth 1 --branch "$OPENSSH_VERSION" \
        https://github.com/openssh/openssh-portable.git "$OPENSSH_SRC"
fi
cp "$ROOT/patches/ssh-mldsa.c"  "$OPENSSH_SRC/"
cp "$ROOT/patches/ssh-slhdsa.c" "$OPENSSH_SRC/"
(cd "$OPENSSH_SRC" && python3 "$ROOT/patches/apply_mldsa_patches.py" --dry-run)
(cd "$OPENSSH_SRC" && python3 "$ROOT/patches/apply_mldsa_patches.py")

# ── Step 2: native autoreconf + configure + build ─────────────────────────────
echo "[native-verify] autoreconf..."
(cd "$OPENSSH_SRC" && autoreconf -i 2>/dev/null)

echo "[native-verify] configure..."
(cd "$OPENSSH_SRC" && ./configure \
    --with-ssl-dir="$OPENSSL_DIR" \
    --without-openssl-header-check \
    --prefix=/tmp/openssh-native-verify >/dev/null)

echo "[native-verify] make (ssh, sshd, ssh-keygen, ssh-pkcs11-helper, ...)..."
NCPU=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
(cd "$OPENSSH_SRC" && make -j"$NCPU" >/dev/null)

# ── Step 3: compile + link the native parameter-sweep test ───────────────────
cp "$ROOT/patches/native_paramsweep_test.c" "$OPENSSH_SRC/"
echo "[native-verify] compiling native_paramsweep_test.c..."
(cd "$OPENSSH_SRC" && cc -std=gnu23 -g -O0 \
    -I. -Iopenbsd-compat -I"$OPENSSL_DIR/include" -DOPENSSL_API_COMPAT=0x10100000L \
    -c native_paramsweep_test.c -o native_paramsweep_test.o)
(cd "$OPENSSH_SRC" && cc -std=gnu23 \
    -o native_paramsweep_test native_paramsweep_test.o ssh-pkcs11.o ssh-sk-client.o \
    -L. -Lopenbsd-compat/ -L"$OPENSSL_DIR/lib" \
    -lssh -lopenbsd-compat -lresolv -lcrypto -lz)

# ── Step 4: run against a fresh token ─────────────────────────────────────────
rm -rf "$VERIFY_DIR/tokens"
mkdir -p "$VERIFY_DIR/tokens"
cat > "$VERIFY_DIR/softhsm2.conf" <<EOF
log.level = DEBUG
objectstore.backend = file
directories.tokendir = $VERIFY_DIR/tokens
EOF

echo "[native-verify] running parameter sweep (11 ML-DSA/SLH-DSA variants)..."
SOFTHSM2_CONF="$VERIFY_DIR/softhsm2.conf" "$OPENSSH_SRC/native_paramsweep_test" "$SOFTHSM_NATIVE"
