#!/usr/bin/env bash
# build-wasm.sh — Emscripten WASM build for the openssh-pkcs11 connector.
#
# Produces two artifacts:
#   dist/openssh-server.{js,wasm}  — sshd single-connection state machine
#   dist/openssh-client.{js,wasm}  — ssh client
#
# Both are statically linked against:
#   - OpenSSL 3.6.x WASM (from pqctoday-hsm deps/ or OPENSSL_WASM env)
#   - softhsmv3 static archive (SOFTHSM_WASM env or built by pqctoday-hsm root)
#
# Prerequisites:
#   emcc 3.x+ in PATH, autoconf, automake, python3
#   OPENSSL_WASM  — path to OpenSSL WASM install prefix (lib/libcrypto.a required)
#   SOFTHSM_WASM  — path to softhsmv3 static archive (libsofthsmv3.a)
#
# Usage (from pqctoday-hsm/ root):
#   bash openssh-pkcs11/scripts/build-wasm.sh
#   SKIP_OPENSSH_FETCH=1 bash openssh-pkcs11/scripts/build-wasm.sh   # reuse existing source

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"      # openssh-pkcs11/
HSM_ROOT="$(cd "$ROOT/.." && pwd)"            # pqctoday-hsm/
OPENSSH_VERSION="V_10_3_P1"
OPENSSH_SRC="$ROOT/build/openssh-src"
OUTPUT_DIR="$ROOT/dist"

# Resolve OpenSSL WASM prefix — default to in-tree pqctoday-hsm build
OPENSSL_WASM="${OPENSSL_WASM:-$HSM_ROOT/deps/openssl-wasm}"
# softhsmv3 static archive
SOFTHSM_WASM="${SOFTHSM_WASM:-$HSM_ROOT/build-wasm/src/lib/libsofthsmv3-static.a}"

if ! command -v emcc &>/dev/null; then
    echo "[openssh-pkcs11] ERROR: emcc not found" >&2; exit 1
fi
echo "[openssh-pkcs11] emcc: $(emcc --version 2>&1 | head -1)"

if [[ ! -f "$OPENSSL_WASM/lib/libcrypto.a" ]]; then
    echo "[openssh-pkcs11] ERROR: $OPENSSL_WASM/lib/libcrypto.a not found" >&2
    echo "  Build it: cd $HSM_ROOT && bash scripts/build-openssl-wasm.sh" >&2
    exit 1
fi
if [[ ! -f "$SOFTHSM_WASM" ]]; then
    echo "[openssh-pkcs11] ERROR: $SOFTHSM_WASM not found" >&2
    echo "  Build it: cd $HSM_ROOT && bash scripts/build-wasm.sh" >&2
    exit 1
fi

# ── Step 1: Fetch + patch OpenSSH source ─────────────────────────────────────
mkdir -p "$ROOT/build"
if [[ "${SKIP_OPENSSH_FETCH:-0}" != "1" || ! -d "$OPENSSH_SRC" ]]; then
    echo "[openssh-pkcs11] Cloning OpenSSH $OPENSSH_VERSION..."
    rm -rf "$OPENSSH_SRC"
    git clone --depth 1 --branch "$OPENSSH_VERSION" \
        https://github.com/openssh/openssh-portable.git "$OPENSSH_SRC"
fi

echo "[openssh-pkcs11] Applying ML-DSA-65 patches (draft-sfluhrer-ssh-mldsa-06)..."
cp "$ROOT/patches/ssh-mldsa.c" "$OPENSSH_SRC/"
(cd "$OPENSSH_SRC" && python3 "$ROOT/patches/apply_mldsa_patches.py")

echo "[openssh-pkcs11] Copying WASM shims..."
cp "$ROOT/wasm-shims/socket_wasm.c"   "$OPENSSH_SRC/"
cp "$ROOT/wasm-shims/pkcs11_static.c" "$OPENSSH_SRC/"
cp "$ROOT/wasm-shims/sshd_wasm_main.c" "$OPENSSH_SRC/"

# ── Step 2: autoconf ──────────────────────────────────────────────────────────
echo "[openssh-pkcs11] Running autoreconf..."
(cd "$OPENSSH_SRC" && autoreconf -i 2>/dev/null)

# Force cross_compiling=yes for the OpenSSL header/library version checks.
# Under emcc, autoconf's AC_PROG_CC detects that conftest programs "run" via
# node (because emcc emits a JS launcher that node can execute), so it sets
# cross_compiling=no even with --host=wasm32-unknown-emscripten. But the
# conftests write to Emscripten MEMFS, not host disk, so the files OpenSSH
# configure expects (conftest.sslincver, conftest.ssllibver) never appear and
# the version check errors out. Override the flag right before those checks.
python3 - "$OPENSSH_SRC/configure" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as fh:
    text = fh.read()
marker = '\t# Determine OpenSSL header version'
inject = '\tcross_compiling=yes\n' + marker
assert marker in text, 'expected OpenSSL header-version marker in configure'
assert inject not in text, 'cross_compiling=yes already injected'
text = text.replace(marker, inject, 1)
with open(path, 'w') as fh:
    fh.write(text)
PYEOF

# ── Step 3: emconfigure ───────────────────────────────────────────────────────
SOFTHSM_INCLUDE="$HSM_ROOT/src/lib"
SOFTHSM_PKCS11_H="$HSM_ROOT/src/lib/pkcs11"

SHARED_LDFLAGS=(
    "-s" "MODULARIZE=1"
    "-s" "ALLOW_MEMORY_GROWTH=1"
    "-s" "INITIAL_MEMORY=67108864"
    "-s" "EXPORTED_RUNTIME_METHODS=['cwrap','ccall','UTF8ToString','stringToUTF8','getValue','setValue']"
    "-s" "ASYNCIFY=1"
    "-s" "ASYNCIFY_IMPORTS=['__wasm_read_sab','__wasm_write_sab']"
    "--no-entry"
)
# Note: SHARED_MEMORY / PTHREAD_POOL_SIZE are intentionally OFF. softhsmv3 and
# OpenSSL WASM archives (deps/openssl-wasm/, build-wasm/src/lib/) were compiled
# single-threaded (no +atomics Wasm feature); mixing in -s SHARED_MEMORY=1 here
# causes wasm-ld to refuse the link. JS-side SharedArrayBuffer transport via
# socket_wasm.c still works — it uses asyncify imports, not Wasm shared memory.

COMMON_CFLAGS="-O2 -Wno-error -DWASM_OPENSSH -DSOFTHSM_STATIC_LINKED \
    -Wno-implicit-function-declaration -Wno-error=implicit-function-declaration \
    -Wno-int-conversion -Wno-error=int-conversion \
    -Wno-incompatible-pointer-types -Wno-error=incompatible-pointer-types \
    -Wno-incompatible-function-pointer-types -Wno-error=incompatible-function-pointer-types \
    -Wno-implicit-int -Wno-error=implicit-int \
    -Wno-deprecated-declarations -Wno-error=deprecated-declarations \
    -I${OPENSSL_WASM}/include \
    -I${SOFTHSM_INCLUDE} \
    -I${SOFTHSM_PKCS11_H}"

COMMON_LIBS="${SOFTHSM_WASM} \
    ${OPENSSL_WASM}/lib/libcrypto.a \
    ${OPENSSL_WASM}/lib/libssl.a"

echo "[openssh-pkcs11] Configuring (sshd)..."
mkdir -p "$ROOT/build/sshd-wasm"
(cd "$ROOT/build/sshd-wasm" && \
    env \
        ac_cv_func_arc4random=no \
        ac_cv_func_arc4random_buf=no \
        ac_cv_func_arc4random_stir=no \
        ac_cv_func_arc4random_uniform=no \
        ac_cv_func_bcrypt_pbkdf=no \
        ac_cv_func_closefrom=no \
        ac_cv_func_fmt_scaled=no \
        ac_cv_func_scan_scaled=no \
        ac_cv_func_freezero=no \
        ac_cv_func_nlist=no \
        ac_cv_func_readpassphrase=no \
        ac_cv_func_recallocarray=no \
        ac_cv_func_reallocarray=no \
        ac_cv_func_strtonum=no \
        ac_cv_func_timingsafe_bcmp=no \
        ac_cv_func_getrrsetbyname=no \
        ac_cv_func_setproctitle=no \
        ac_cv_header_libutil_h=no \
        ac_cv_header_nlist_h=no \
        ac_cv_header_readpassphrase_h=no \
    emconfigure "$OPENSSH_SRC/configure" \
        --host=wasm32-unknown-emscripten \
        --disable-shared --enable-static \
        --with-ssl-dir="$OPENSSL_WASM" \
        --without-openssl-header-check \
        --without-pam --without-selinux --without-zlib \
        --without-shadow --without-audit --without-libedit \
        --disable-strip \
        CFLAGS="$COMMON_CFLAGS -DWASM_SSHD_MAIN" \
        LDFLAGS="${SHARED_LDFLAGS[*]} -s EXPORT_NAME=createSshdModule ${COMMON_LIBS}")

echo "[openssh-pkcs11] Configuring (ssh client)..."
mkdir -p "$ROOT/build/ssh-wasm"
(cd "$ROOT/build/ssh-wasm" && \
    env \
        ac_cv_func_arc4random=no \
        ac_cv_func_arc4random_buf=no \
        ac_cv_func_arc4random_stir=no \
        ac_cv_func_arc4random_uniform=no \
        ac_cv_func_bcrypt_pbkdf=no \
        ac_cv_func_closefrom=no \
        ac_cv_func_fmt_scaled=no \
        ac_cv_func_scan_scaled=no \
        ac_cv_func_freezero=no \
        ac_cv_func_nlist=no \
        ac_cv_func_readpassphrase=no \
        ac_cv_func_recallocarray=no \
        ac_cv_func_reallocarray=no \
        ac_cv_func_strtonum=no \
        ac_cv_func_timingsafe_bcmp=no \
        ac_cv_func_getrrsetbyname=no \
        ac_cv_func_setproctitle=no \
        ac_cv_header_libutil_h=no \
        ac_cv_header_nlist_h=no \
        ac_cv_header_readpassphrase_h=no \
    emconfigure "$OPENSSH_SRC/configure" \
        --host=wasm32-unknown-emscripten \
        --disable-shared --enable-static \
        --with-ssl-dir="$OPENSSL_WASM" \
        --without-openssl-header-check \
        --without-pam --without-selinux --without-zlib \
        --without-shadow --without-audit --without-libedit \
        --disable-strip \
        CFLAGS="$COMMON_CFLAGS -DWASM_SSH_CLIENT" \
        LDFLAGS="${SHARED_LDFLAGS[*]} -s EXPORT_NAME=createSshModule ${COMMON_LIBS}")

# ── Step 3.5: Patch generated config.h ────────────────────────────────────────
# Emscripten's musl DECLARES many libc/compat functions in its headers (so OpenSSH's
# AC_CHECK_FUNC compile-test passes and configure writes HAVE_<FN>=1) but does NOT
# provide a linkable definition for them. The override also leaks past the
# ac_cv_func_* env vars (the cache var name disagrees with the AC_CHECK_DECL test that
# writes the #define). With HAVE_<FN> defined, OpenSSH's openbsd-compat shim is skipped,
# so the symbol is absent at link -> wasm-ld "undefined symbol" (or, for setproctitle,
# a "function signature mismatch" because callers fall back to an implicit declaration).
# Strip the leaked defines post-configure so openbsd-compat compiles its own
# implementation / no-op for each. Every function listed has an openbsd-compat source:
# getrrsetbyname.c, setproctitle.c, daemon.c, bsd-getpeereid.c, bsd-misc.c (pledge),
# bsd-closefrom.c (close_range), base64.c (b64_*), blowfish.c (Blowfish_*/blf_enc).
LEAKED_HAVE_DEFINES=(
    GETRRSETBYNAME SETPROCTITLE
    DAEMON GETPEEREID PLEDGE CLOSE_RANGE
    B64_NTOP B64_PTON __B64_NTOP __B64_PTON
    BLF_ENC BLOWFISH_INITSTATE BLOWFISH_EXPANDSTATE BLOWFISH_EXPAND0STATE BLOWFISH_STREAM2WORD
)
for cfg in "$ROOT/build/sshd-wasm/config.h" "$ROOT/build/ssh-wasm/config.h"; do
    [[ -f "$cfg" ]] || continue
    for d in "${LEAKED_HAVE_DEFINES[@]}"; do
        if grep -q "^#define HAVE_$d 1" "$cfg"; then
            echo "[openssh-pkcs11] Patching out HAVE_$d in $cfg"
            sed -i.bak "s|^#define HAVE_$d 1|/* #undef HAVE_$d */|" "$cfg"
        fi
    done
done

# ── Step 4: Build ─────────────────────────────────────────────────────────────
NCPU=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo "[openssh-pkcs11] Building sshd WASM with ${NCPU} jobs..."
(cd "$ROOT/build/sshd-wasm" && emmake make -j"$NCPU" sshd)

echo "[openssh-pkcs11] Building ssh WASM with ${NCPU} jobs..."
(cd "$ROOT/build/ssh-wasm" && emmake make -j"$NCPU" ssh)

# ── Step 5: Copy outputs ──────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
cp "$ROOT/build/sshd-wasm/sshd"      "$OUTPUT_DIR/openssh-server.js"
cp "$ROOT/build/sshd-wasm/sshd.wasm" "$OUTPUT_DIR/openssh-server.wasm"
cp "$ROOT/build/ssh-wasm/ssh"        "$OUTPUT_DIR/openssh-client.js"
cp "$ROOT/build/ssh-wasm/ssh.wasm"   "$OUTPUT_DIR/openssh-client.wasm"

echo ""
echo "[openssh-pkcs11] Build complete."
ls -lh "$OUTPUT_DIR/"
echo ""
echo "Copy to hub:  bash openssh-pkcs11/scripts/copy-to-hub.sh"
