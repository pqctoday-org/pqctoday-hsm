#!/bin/bash
# build-strongswan-wasm.sh — End-to-end Emscripten WASM build for strongSwan charon.
#
# STATUS: VERIFIED (2026-06-12) — produces the working v1 full-daemon build.
# Output matches the shipped 13 MB strongswan.wasm (same wasm_* export set,
# "strongSwan 6.0.5" banner, size within ~7%). Verified with emcc 5.0.7.
# Capabilities included: RFC 7383 fragmentation default (WASM_FRAGMENTATION=no
# to opt out), RFC 9370 multi-KE hybrid proposal (mlkem768 + ke1_ecp256),
# Tier A stub kernel for real CHILD_SA negotiation (opt in via WASM_CHILDSA=1).
# NOTE: the default install target below is pqctoday-hub — when iterating or
# installing into a worktree, run with SKIP_INSTALL_TO_HUB=1 and copy manually.
#
# Pipeline:
#   1. Fetch upstream strongSwan 6.0.5 tarball (if not cached)
#   2. Unpack into /tmp/strongswan-build/
#   3. Apply strongswan-6.0.5-pqc.patch (core ML-DSA/ML-KEM enum + SPKI plumbing)
#   4. Regenerate ASN.1 OID tables from patched oid.txt
#   5. Overlay the pqctoday-hsm strongswan-pkcs11 plugin (our adapter)
#   6. Apply strongswan-6.0.5-wasm.patch (Emscripten/WASM plumbing — targets
#      both core strongSwan files AND the just-overlaid pkcs11_library.c)
#   7. Copy strongswan-wasm-shims/*.{c,h} into src/charon/
#   8. autoreconf → emconfigure → emmake
#   9. Copy charon.{js,wasm} to pqctoday-hub/public/wasm/strongswan.{js,wasm}
#
# Prerequisites:
#   - emcc 3.x+ in PATH (Emscripten SDK)
#   - autoreconf, make, curl, tar, bzip2, perl (for oid_maker.pl)
#   - Homebrew Python (for Emscripten's Python 3.10+ requirement on macOS)
#   - Static softhsmv3 library (set SOFTHSM_WASM_LIB to the .a path) —
#     provided as a link-time dependency that exports C_GetFunctionList.
#
# Env overrides:
#   SKIP_FETCH=1          skip tarball fetch/unpack (reuse existing tree)
#   SKIP_INSTALL_TO_HUB=1 don't overwrite the hub's strongswan.{js,wasm}
#                         (useful while iterating — set this whenever the
#                         build is not yet known-good)
#   BUILD_ROOT=...        override /tmp/strongswan-build
#   SOFTHSM_WASM_LIB=...  path to libsofthsmv3.a (or an .o/.bc) with
#                         C_GetFunctionList; defaults to
#                         $HSM_ROOT/build-wasm/src/lib/libsofthsmv3.a
#
# Output (unless SKIP_INSTALL_TO_HUB=1):
#   /Users/ericamador/antigravity/pqctoday-hub/public/wasm/strongswan.js
#   /Users/ericamador/antigravity/pqctoday-hub/public/wasm/strongswan.wasm

set -euo pipefail

# macOS: Emscripten requires Python 3.10+ (uses `match` syntax)
export PATH="/opt/homebrew/bin:$PATH"

HSM_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HUB_WASM_OUT="/Users/ericamador/antigravity/pqctoday-hub/public/wasm"
BUILD_ROOT="${BUILD_ROOT:-/tmp/strongswan-build}"
TARBALL="strongswan-6.0.5.tar.bz2"
TARBALL_URL="https://download.strongswan.org/${TARBALL}"
SRC_DIR="${BUILD_ROOT}/strongswan-6.0.5"
PQC_PATCH="${HSM_ROOT}/strongswan-6.0.5-pqc.patch"
WASM_PATCH="${HSM_ROOT}/strongswan-6.0.5-wasm.patch"
PLUGIN_SRC="${HSM_ROOT}/strongswan-pkcs11"
SHIMS_SRC="${HSM_ROOT}/strongswan-wasm-shims"
SOFTHSM_WASM_LIB="${SOFTHSM_WASM_LIB:-${HSM_ROOT}/build-wasm/src/lib/libsofthsmv3-static.a}"

# Preflight
command -v emcc       >/dev/null || { echo "[build] ERROR: emcc not in PATH — install emsdk" >&2; exit 1; }
command -v autoreconf >/dev/null || { echo "[build] ERROR: autoreconf not in PATH" >&2; exit 1; }
[[ -f "$PQC_PATCH"  ]] || { echo "[build] ERROR: PQC patch not found: $PQC_PATCH"   >&2; exit 1; }
[[ -f "$WASM_PATCH" ]] || { echo "[build] ERROR: WASM patch not found: $WASM_PATCH" >&2; exit 1; }
[[ -d "$PLUGIN_SRC" ]] || { echo "[build] ERROR: plugin source not found: $PLUGIN_SRC" >&2; exit 1; }
[[ -d "$SHIMS_SRC"  ]] || { echo "[build] ERROR: WASM shims not found: $SHIMS_SRC"   >&2; exit 1; }

echo "[build] emcc: $(emcc --version 2>&1 | head -1)"

# 1-2. Fetch + unpack (idempotent). Always rebuild from a pristine tree
#      so patches apply cleanly — wipe any previous unpacked dir.
if [[ "${SKIP_FETCH:-0}" != "1" ]]; then
    mkdir -p "$BUILD_ROOT"
    cd "$BUILD_ROOT"
    if [[ ! -f "$TARBALL" ]]; then
        echo "[build] Downloading $TARBALL_URL..."
        curl -sSfL -o "$TARBALL" "$TARBALL_URL"
    fi
    echo "[build] Wiping previous source tree for a clean rebuild..."
    rm -rf "$SRC_DIR"
    echo "[build] Extracting $TARBALL..."
    tar xjf "$TARBALL"
fi

[[ -d "$SRC_DIR" ]] || { echo "[build] ERROR: source tree missing: $SRC_DIR" >&2; exit 1; }
cd "$SRC_DIR"

# 3. Apply PQC core patch
echo "[build] Applying $PQC_PATCH..."
patch -p1 --forward --no-backup-if-mismatch < "$PQC_PATCH" || true

# 4. Regenerate ASN.1 OID tables from patched oid.txt
echo "[build] Regenerating ASN.1 OID tables (strongSwan uses oid.pl, not oid_maker.pl)..."
cd src/libstrongswan/asn1
perl oid.pl oid.txt oid.h oid.c
cd "$SRC_DIR"

# 5. Overlay pqctoday pkcs11 plugin (must happen before the WASM patch
#    because the WASM patch targets pkcs11_library.c in this tree).
echo "[build] Overlaying pqctoday pkcs11 plugin from $PLUGIN_SRC..."
cp -R "$PLUGIN_SRC"/* src/libstrongswan/plugins/pkcs11/

# 5.5. SLH-DSA compat shim for 6.0.5. The shared strongswan-pkcs11/ plugin
#      gained SLH-DSA support for the 6.0.6/v2 build (KEY_SLH_DSA_* and
#      SIGN_SLH_DSA_* enums added to libstrongswan core by
#      strongswan-6.0.6-pqc-slhdsa.patch). The 6.0.5 PQC patch does not add
#      those enum values, so the overlaid plugin fails to compile. Append
#      macro equivalents (values match the 6.0.6 enum layout exactly:
#      key_type_t 9/10/11 after KEY_ML_DSA_87=8, signature schemes right
#      after SIGN_ML_DSA_87) to the plugin's local pkcs11.h, which all three
#      affected sources include. Build-tree only — repo sources untouched.
PKCS11_PLUGIN_H="src/libstrongswan/plugins/pkcs11/pkcs11.h"
if ! grep -q "WASM_SLHDSA_COMPAT_605" "$PKCS11_PLUGIN_H"; then
    cat >> "$PKCS11_PLUGIN_H" <<'EOF'

/* WASM_SLHDSA_COMPAT_605 — SLH-DSA key/signature enum values for the 6.0.5
 * build (only the 6.0.6 core patch defines them in public_key.h). Values
 * mirror strongswan-6.0.6-pqc-slhdsa.patch. */
#ifndef KEY_SLH_DSA_SHA2_128S
#define KEY_SLH_DSA_SHA2_128S  ((key_type_t)9)
#define KEY_SLH_DSA_SHA2_192S  ((key_type_t)10)
#define KEY_SLH_DSA_SHA2_256S  ((key_type_t)11)
#define SIGN_SLH_DSA_SHA2_128S ((signature_scheme_t)(SIGN_ML_DSA_87 + 1))
#define SIGN_SLH_DSA_SHA2_192S ((signature_scheme_t)(SIGN_ML_DSA_87 + 2))
#define SIGN_SLH_DSA_SHA2_256S ((signature_scheme_t)(SIGN_ML_DSA_87 + 3))
#endif
EOF
    echo "[build]   appended SLH-DSA 6.0.5 compat defines to $PKCS11_PLUGIN_H"
else
    echo "[build]   $PKCS11_PLUGIN_H already has SLH-DSA compat defines, skipping"
fi

# 6. Apply WASM patch (core emscripten plumbing + pkcs11_library static-link
#    hooks). Applied AFTER the plugin overlay so its pkcs11_library.c hunks
#    target the pqctoday version that's now in the tree.
echo "[build] Applying $WASM_PATCH..."
patch -p1 --forward --no-backup-if-mismatch < "$WASM_PATCH" || true

# 7. Copy WASM shim sources into the charon source dir. These are
#    referenced by the Makefile.am hunk in the WASM patch; copying here
#    makes them available at build time.
echo "[build] Copying WASM shims from $SHIMS_SRC into src/charon/..."
cp "$SHIMS_SRC"/socket_wasm.c       src/charon/
cp "$SHIMS_SRC"/socket_wasm.h       src/charon/
cp "$SHIMS_SRC"/wasm_hsm_init.c     src/charon/
cp "$SHIMS_SRC"/wasm_backend.c      src/charon/
cp "$SHIMS_SRC"/pkcs11_wasm_rpc.c   src/charon/
cp "$SHIMS_SRC"/kernel_wasm.c       src/charon/

# 7.5. Patch Makefile.am to actually compile plugin_constructors.c into the
#      archive. Upstream lists the generated file under BUILT_SOURCES but
#      never adds it to *_la_SOURCES, so the static plugin constructor never
#      runs and 7 of 16 enabled libstrongswan plugins (x509, pubkey, pem,
#      pkcs1, pkcs8, constraints, revocation) get dead-stripped at link time.
#      One-line fix per Makefile.am, applied before autoreconf so the
#      regenerated Makefile.in picks it up. Idempotent via grep -q guard.
# Only patch libstrongswan — libcharon has no plugins enabled in our config,
# so its plugin_constructors.c has an empty register_plugins() body. With the
# non-static patch (step 7.6), compiling both would produce duplicate
# `register_plugins` symbols. Skip libcharon to avoid the collision.
echo "[build] Patching libstrongswan/Makefile.am to compile plugin_constructors.c..."
makefile_am="src/libstrongswan/Makefile.am"
if ! grep -q "_la_SOURCES += \$(srcdir)/plugin_constructors.c" "$makefile_am"; then
    sed -i.bak '/^if STATIC_PLUGIN_CONSTRUCTORS$/,/^endif$/{
        /^CLEANFILES = \$(srcdir)\/plugin_constructors\.c$/a\
libstrongswan_la_SOURCES += $(srcdir)/plugin_constructors.c
    }' "$makefile_am"
    echo "[build]   patched $makefile_am"
else
    echo "[build]   $makefile_am already patched, skipping"
fi

# 7.6. Patch the constructor generator to emit a non-static, used register_plugins.
#      wasm-ld's archive selection only pulls a .o from a .a when one of its
#      EXTERNAL symbols is referenced. The upstream generator declares
#      `register_plugins` as static (file-local, no external symbol), so even
#      with the .o in libstrongswan.a the linker never selects it — the
#      constructor body never enters __wasm_call_ctors. Making the symbol
#      non-static + __attribute__((used)) lets us force-link via
#      -Wl,--undefined=register_plugins below.
# 7.55. Skip getopt_long in WASM build. Upstream charon.c calls getopt_long
#       BEFORE the WASM `__EMSCRIPTEN__` block that handles `--role`. Result:
#       getopt sees `--role` as unrecognized and aborts via usage(""). The
#       WASM patch positions its handler too late. Quick fix: under EMSCRIPTEN,
#       short-circuit `c = EOF` so the loop exits and execution falls through
#       to the WASM role parser.
# 7.45. Patch array_destroy_function callbacks where 1-arg destructors are
#       cast via `(void*)` to the 3-arg array_callback_t typedef. WASM is
#       strict about function-pointer arity; native x86 forgives this via
#       cdecl, but wasm-ld emits an indirect-call signature trap. Add static
#       wrapper functions in each affected file and replace the cast with
#       the wrapper. The trap in our current build fires from
#       settings_parser_parse_string -> destroy -> array_destroy_function ->
#       array_invoke -> *(void*)free  (1-arg vs 3-arg expected).
echo "[build] Patching array_destroy_function callbacks for WASM strict typing..."

# Helper: insert a forward declaration of the wrapper near the top of the
# file (after the last #include, where it's at file scope), and append the
# full body at the END of the file (where every type and destructor is in
# scope). This avoids both "function definition not allowed here" (when the
# wrapper would land inside another function) and "use of undeclared
# identifier" (when the call site precedes the wrapper definition).
# Idempotent via sentinel comment markers. Targeted sed so the replacement
# only fires inside `array_destroy_function(...)` calls — not in struct
# initializers that incidentally contain `(void*)free`.
patch_array_cb() {
    local file="$1"           # path to .c source
    local marker="$2"         # unique sentinel comment
    local wrapper_name="$3"   # name of the wrapper to insert
    local wrapper_body="$4"   # full function body (single line)
    local cast_token="$5"     # the bare cast token, e.g. "(void*)free"

    if grep -q "$marker" "$file"; then
        echo "[build]   $file already patched, skipping"
        return
    fi

    local escaped_cast
    escaped_cast=$(printf '%s' "$cast_token" | sed 's/[][\.*^$/]/\\&/g')

    # 1. Insert forward declaration after the last #include (file scope, no
    #    type/function bodies needed at this point — just a name + signature).
    awk -v marker="$marker" -v fwd="static void $wrapper_name(void *data, int idx, void *user);" '
        /^#include / { last_inc = NR }
        { lines[NR] = $0 }
        END {
            for (i = 1; i <= NR; i++) {
                print lines[i]
                if (i == last_inc) {
                    print ""
                    print "/* " marker " (forward decl) */"
                    print fwd
                }
            }
        }
    ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"

    # 2. Append the full body at end of file (all referenced types and the
    #    underlying destructor are now in scope).
    {
        echo ""
        echo "/* $marker (definition) */"
        echo "$wrapper_body"
    } >> "$file"

    # 3. Replace the cast at every array_destroy_function call site.
    sed -i.bak "s#array_destroy_function(\\([^,]*\\), $escaped_cast, \\([^)]*\\))#array_destroy_function(\\1, $wrapper_name, \\2)#g" "$file"
    echo "[build]   patched $file"
}

WASM_FREE_CB_BODY='static void _wasm_free_cb(void *data, int idx, void *user) { (void)idx; (void)user; free(data); }'

# settings_parser.c (YACC-generated): (void*)free on refs array
patch_array_cb "src/libstrongswan/settings/settings_parser.c" \
    "WASM_ARRAY_CB_FREE_CB" \
    "_wasm_free_cb" \
    "$WASM_FREE_CB_BODY" \
    "(void*)free"

# settings_parser.y (kept in sync in case yacc regenerates the .c)
patch_array_cb "src/libstrongswan/settings/settings_parser.y" \
    "WASM_ARRAY_CB_FREE_CB" \
    "_wasm_free_cb" \
    "$WASM_FREE_CB_BODY" \
    "(void*)free"

# identification.c: (void*)free on rdns. Other (void*)free uses in struct
# initializers (line ~221) are NOT touched because the targeted sed only
# matches inside array_destroy_function(...) calls.
patch_array_cb "src/libstrongswan/utils/identification.c" \
    "WASM_ARRAY_CB_FREE_CB" \
    "_wasm_free_cb" \
    "$WASM_FREE_CB_BODY" \
    "(void*)free"

# parser_helper.c: (void*)parser_helper_file_destroy is 1-arg
patch_array_cb "src/libstrongswan/utils/parser_helper.c" \
    "WASM_ARRAY_CB_PHFD" \
    "_wasm_phfd_cb" \
    "static void _wasm_phfd_cb(void *data, int idx, void *user) { (void)idx; (void)user; parser_helper_file_destroy((parser_helper_file_t*)data); }" \
    "(void*)parser_helper_file_destroy"

# metadata_set.c: (void*)destroy_entry is 1-arg
patch_array_cb "src/libstrongswan/metadata/metadata_set.c" \
    "WASM_ARRAY_CB_DESTROY_ENTRY" \
    "_wasm_destroy_entry_cb" \
    "static void _wasm_destroy_entry_cb(void *data, int idx, void *user) { (void)idx; (void)user; destroy_entry((entry_t*)data); }" \
    "(void*)destroy_entry"

# message.c: (void*)fragment_destroy is 1-arg
patch_array_cb "src/libcharon/encoding/message.c" \
    "WASM_ARRAY_CB_FRAGMENT_DESTROY" \
    "_wasm_fragment_destroy_cb" \
    "static void _wasm_fragment_destroy_cb(void *data, int idx, void *user) { (void)idx; (void)user; fragment_destroy((fragment_t*)data); }" \
    "(void*)fragment_destroy"

# 7.5. Wrap 2-arg comparator passed to array_sort in plugin_loader.c.
#      `array_sort` typedef expects `int (*)(const void*, const void*, void*)`
#      but `plugin_priority_cmp_name` is 2-arg. Native x86 forgives this; WASM
#      traps in qsort_r -> compare_elements with function-signature mismatch.
#      Add a 3-arg wrapper that drops the unused `user` and calls the 2-arg
#      comparator. Forward decl after last #include, body at EOF, cast
#      replaced at the call site only.
PLUGIN_LOADER_C="src/libstrongswan/plugins/plugin_loader.c"
if ! grep -q "WASM_PLUGIN_PRIORITY_CMP_NAME_CB" "$PLUGIN_LOADER_C"; then
    awk -v fwd='static int _wasm_ppcn_cb(const void *a, const void *b, void *user);' '
        /^#include / { last_inc = NR }
        { lines[NR] = $0 }
        END {
            for (i = 1; i <= NR; i++) {
                print lines[i]
                if (i == last_inc) {
                    print ""
                    print "/* WASM_PLUGIN_PRIORITY_CMP_NAME_CB (forward decl) */"
                    print fwd
                }
            }
        }
    ' "$PLUGIN_LOADER_C" > "$PLUGIN_LOADER_C.tmp" && mv "$PLUGIN_LOADER_C.tmp" "$PLUGIN_LOADER_C"
    cat >> "$PLUGIN_LOADER_C" <<'WASM_EOF'

/* WASM_PLUGIN_PRIORITY_CMP_NAME_CB (definition) */
static int _wasm_ppcn_cb(const void *a, const void *b, void *user)
{
    (void)user;
    return plugin_priority_cmp_name((const plugin_priority_t*)a,
                                    (const plugin_priority_t*)b);
}
WASM_EOF
    # Targeted replacement: only inside array_sort(...) calls (3-arg comparator).
    # Do NOT touch array_bsearch(...) at line 1274 — that one expects a 2-arg
    # comparator typedef, and the original (void*)plugin_priority_cmp_name cast
    # is the right shape for it (2-arg → 2-arg, just discards type info).
    sed -i.bak 's|array_sort(\([^,]*\), (void\*)plugin_priority_cmp_name, \([^)]*\))|array_sort(\1, _wasm_ppcn_cb, \2)|g' "$PLUGIN_LOADER_C"
    echo "[build]   patched $PLUGIN_LOADER_C"
else
    echo "[build]   $PLUGIN_LOADER_C already patched, skipping"
fi

echo "[build] Patching charon.c to skip getopt_long under __EMSCRIPTEN__..."
CHARON_C="src/charon/charon.c"
if ! grep -q "EMSCRIPTEN_SKIP_GETOPT" "$CHARON_C"; then
    sed -i.bak \
        's|int c = getopt_long(argc, argv, "", long_opts, NULL);|/* EMSCRIPTEN_SKIP_GETOPT */\
#ifdef __EMSCRIPTEN__\
		int c = EOF;\
		(void)long_opts;\
#else\
		int c = getopt_long(argc, argv, "", long_opts, NULL);\
#endif|' "$CHARON_C"
    echo "[build]   patched $CHARON_C"
else
    echo "[build]   $CHARON_C already patched, skipping"
fi

# 7.7. WASM receiver driver — strongswan-6.0.5-wasm.patch already short-circuits
#      the queue_job in receiver_create() (no thread pool in WASM), but never
#      wired anything to actually call receive_packets(). The patch comment
#      says "the replacement main loop in src/charon/charon.c spins forever;
#      receive_packets() is invoked from there" — but charon.c just sleep(1)s.
#      Result: incoming packets sit in the netInbox SAB forever and the
#      responder never advances past IKE_SA_INIT receipt.
#
#      Fix: append a non-static `wasm_receiver_drain_once()` to receiver.c
#      that drives one pass of receive_packets() (which itself synchronously
#      dispatches process_message_job under EMSCRIPTEN), and replace charon.c's
#      busy loop with a tight loop calling it. socket_wasm's wasm_net_receive
#      blocks on Atomics.wait, so the loop is naturally event-driven (the
#      bridge's Atomics.notify wakes it).
RECEIVER_C="src/libcharon/network/receiver.c"
if ! grep -q "wasm_receiver_drain_once" "$RECEIVER_C"; then
    cat >> "$RECEIVER_C" <<'WASM_EOF'

#ifdef __EMSCRIPTEN__
/* WASM single-thread receive driver. Called from charon.c's main loop.
 * receive_packets() blocks inside socket->receive() (wasm_net_receive
 * Atomics.wait), then dispatches process_message_job synchronously per
 * the EMSCRIPTEN ifdef inside receive_packets above. The receiver_t
 * pointed to by charon->receiver is in fact a private_receiver_t (the
 * METHOD pattern guarantees public is the first member), so the cast is
 * layout-safe. */
void wasm_receiver_drain_once(void)
{
    if (charon && charon->receiver) {
        (void)receive_packets((private_receiver_t*)charon->receiver);
    }
}
#endif
WASM_EOF
    echo "[build]   patched $RECEIVER_C — appended wasm_receiver_drain_once"
else
    echo "[build]   $RECEIVER_C already has wasm_receiver_drain_once, skipping"
fi
if ! grep -q "wasm_receiver_drain_once" "$CHARON_C"; then
    sed -i.bak 's|while (1) { sleep(1); }|extern void wasm_receiver_drain_once(void); while (1) { wasm_receiver_drain_once(); }|' "$CHARON_C"
    echo "[build]   patched $CHARON_C — main loop now drives receiver"
fi

# 7.8. Widen return_need_more() / return_failed() / return_success() / return_false()
#      to take args matching the slot signatures they get cast into. Multiple
#      ikev2 task and authenticator files cast these 0-arg helpers as
#      `(void*)return_X` and store them into vtable slots like
#      `status_t (*)(task_t*, message_t*)` (2 args) or `bool (*)(authenticator_t*)`
#      (1 arg). Native cdecl forgives the arity mismatch; WASM strict
#      function-pointer typing traps with "function signature mismatch" deep
#      inside build_i during IKE_AUTH (PSK auth path: psk_authenticator.c
#      lines 232,260,235,264 cast (void*)return_failed / return_false; tasks:
#      ike_cert_pre/ike_config/child_create/ike_mobike cast (void*)return_need_more).
#      No production direct callers (verified — only test_utils.c calls them
#      directly, and tests aren't built in WASM), so widening is ABI-safe.
#      Idempotent via grep guards.
RNM_C="src/libstrongswan/utils/utils/status.c"
RNM_H="src/libstrongswan/utils/utils/status.h"
RNF_C="src/libstrongswan/utils/utils.c"
RNF_H="src/libstrongswan/utils/utils.h"
echo "[build] Patching return_need_more/failed/success/false() arities for WASM strict typing..."

# return_need_more — 2 args (status_t (task_t*, message_t*) etc.)
if grep -q '^status_t return_need_more()$' "$RNM_C"; then
    sed -i.bak 's|^status_t return_need_more()$|status_t return_need_more(void *unused1, void *unused2)|' "$RNM_C"
    sed -i.bak '/^status_t return_need_more(void \*unused1, void \*unused2)$/,/^}$/{
        /^{$/a\
\	(void)unused1; (void)unused2;
    }' "$RNM_C"
    sed -i.bak 's|^status_t return_need_more();$|status_t return_need_more(void *unused1, void *unused2);|' "$RNM_H"
    echo "[build]   patched return_need_more"
fi

# return_failed — 2 args (cast into status_t (authenticator_t*, message_t*))
if grep -q '^status_t return_failed()$' "$RNM_C"; then
    sed -i.bak 's|^status_t return_failed()$|status_t return_failed(void *unused1, void *unused2)|' "$RNM_C"
    sed -i.bak '/^status_t return_failed(void \*unused1, void \*unused2)$/,/^}$/{
        /^{$/a\
\	(void)unused1; (void)unused2;
    }' "$RNM_C"
    sed -i.bak 's|^status_t return_failed();$|status_t return_failed(void *unused1, void *unused2);|' "$RNM_H"
    echo "[build]   patched return_failed"
fi

# return_success — 2 args (used as task.build / task.process in ike_dpd.c)
if grep -q '^status_t return_success()$' "$RNM_C"; then
    sed -i.bak 's|^status_t return_success()$|status_t return_success(void *unused1, void *unused2)|' "$RNM_C"
    sed -i.bak '/^status_t return_success(void \*unused1, void \*unused2)$/,/^}$/{
        /^{$/a\
\	(void)unused1; (void)unused2;
    }' "$RNM_C"
    sed -i.bak 's|^status_t return_success();$|status_t return_success(void *unused1, void *unused2);|' "$RNM_H"
    echo "[build]   patched return_success"
fi

# return_false — 1 arg (cast into bool (authenticator_t*) for is_mutual)
if grep -q '^bool return_false()$' "$RNF_C"; then
    sed -i.bak 's|^bool return_false()$|bool return_false(void *unused1)|' "$RNF_C"
    sed -i.bak '/^bool return_false(void \*unused1)$/,/^}$/{
        /^{$/a\
\	(void)unused1;
    }' "$RNF_C"
    sed -i.bak 's|^bool return_false();$|bool return_false(void *unused1);|' "$RNF_H"
    echo "[build]   patched return_false"
fi

# 7.9. credential_set_t method slot casts — many credential set implementations
#      (auth_cfg_wrapper, cert_cache, ocsp_response_wrapper, mem_cred,
#      callback_cred) have unsupported methods stubbed via `(void*)return_null`
#      and `(void*)nop`, but the credential_manager iterates ALL sets and calls
#      these slots with 3/4/5-arg signatures (create_shared_enumerator: 4-arg,
#      create_private_enumerator: 3-arg, create_cdp_enumerator: 3-arg,
#      create_cert_enumerator: 5-arg, cache_cert: 2-arg). 0-arg return_null/nop
#      cast to those slots traps in WASM during PSK auth (initiator's
#      `lib->credmgr->create_shared_enumerator(...)` PSK lookup hits
#      auth_cfg_wrapper.set->create_shared_enumerator → return_null → trap).
#
#      Fix: prepend file-local properly-typed stubs to each credential_set.c
#      and rewrite the cast sites to use them. The stubs return NULL/empty
#      and have args matching the credential_set_t slot typedef.
echo "[build] Patching credential_set stubs (return_null/nop) for WASM strict typing..."
for f in src/libstrongswan/credentials/sets/auth_cfg_wrapper.c \
         src/libstrongswan/credentials/sets/cert_cache.c \
         src/libstrongswan/credentials/sets/ocsp_response_wrapper.c \
         src/libstrongswan/credentials/sets/mem_cred.c \
         src/libstrongswan/credentials/sets/callback_cred.c; do
    if [[ -f "$f" ]] && ! grep -q "_wasm_credset_null_shared" "$f"; then
        # Prepend stubs after the last #include — same pattern as
        # _wasm_ppcn_cb in plugin_loader.c.
        awk -v stubs='\n/* WASM strict-typing stubs for credential_set_t method slots\n * (replaces (void*)return_null / (void*)nop casts that traps in WASM). */\nstatic enumerator_t *_wasm_credset_null_shared(void *a, void *b, void *c, void *d) { (void)a;(void)b;(void)c;(void)d; return enumerator_create_empty(); }\nstatic enumerator_t *_wasm_credset_null_private(void *a, void *b, void *c) { (void)a;(void)b;(void)c; return enumerator_create_empty(); }\nstatic enumerator_t *_wasm_credset_null_cdp(void *a, void *b, void *c) { (void)a;(void)b;(void)c; return enumerator_create_empty(); }\nstatic enumerator_t *_wasm_credset_null_cert(void *a, void *b, void *c, void *d, int e) { (void)a;(void)b;(void)c;(void)d;(void)e; return enumerator_create_empty(); }\nstatic void _wasm_credset_nop_cache(void *a, void *b) { (void)a;(void)b; }\n' '
            /^#include / { last_inc = NR }
            { lines[NR] = $0 }
            END {
                for (i = 1; i <= NR; i++) {
                    print lines[i]
                    if (i == last_inc) {
                        printf "%s", stubs
                    }
                }
            }
        ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
        # Replace the cast sites with the typed stubs.
        sed -i.bak \
            -e 's|\.create_shared_enumerator = (void\*)return_null|.create_shared_enumerator = (void*)_wasm_credset_null_shared|g' \
            -e 's|\.create_private_enumerator = (void\*)return_null|.create_private_enumerator = (void*)_wasm_credset_null_private|g' \
            -e 's|\.create_cdp_enumerator = (void\*)return_null|.create_cdp_enumerator = (void*)_wasm_credset_null_cdp|g' \
            -e 's|\.create_cdp_enumerator  = (void\*)return_null|.create_cdp_enumerator  = (void*)_wasm_credset_null_cdp|g' \
            -e 's|\.create_cert_enumerator = (void\*)return_null|.create_cert_enumerator = (void*)_wasm_credset_null_cert|g' \
            -e 's|\.cache_cert = (void\*)nop|.cache_cert = (void*)_wasm_credset_nop_cache|g' \
            "$f"
        echo "[build]   patched $f"
    fi
done

echo "[build] Patching plugin_constructors.py to emit non-static constructor..."
PLUGIN_CTORS_PY="src/libstrongswan/plugins/plugin_constructors.py"
if grep -q '__attribute__ ((constructor))' "$PLUGIN_CTORS_PY"; then
    # Use weak linkage so libtool's tendency to list libstrongswan.a twice in
    # the link line (once directly, once via libcharon.la's dependency chain)
    # doesn't cause duplicate-symbol errors. With weak, the second definition
    # is simply discarded. `used` prevents compiler dead-strip; the
    # -Wl,--undefined=register_plugins flag below triggers archive lookup.
    sed -i.bak \
        -e 's|"static void register_plugins() __attribute__ ((constructor));"|"void register_plugins(void) __attribute__((weak,used,constructor));"|' \
        -e 's|"static void register_plugins()"|"void register_plugins(void)"|' \
        -e 's|"static void unregister_plugins() __attribute__ ((destructor));"|"void unregister_plugins(void) __attribute__((weak,used,destructor));"|' \
        -e 's|"static void unregister_plugins()"|"void unregister_plugins(void)"|' \
        "$PLUGIN_CTORS_PY"
    echo "[build]   patched $PLUGIN_CTORS_PY"
else
    echo "[build]   $PLUGIN_CTORS_PY already patched, skipping"
fi

# 8a. autoreconf (Makefile.am changes in our plugin + patch → need
#     regenerated Makefile.in)
echo "[build] Running autoreconf..."
autoreconf -i

# 8b. Emscripten configure — strip everything except charon + pkcs11
# Export CFLAGS/LDFLAGS so configure's libcrypto link-test can find the
# openssl-wasm install. Without these, --enable-openssl aborts at:
#   checking for EVP_CIPHER_CTX_new in -lcrypto... no
#   configure: error: OpenSSL libcrypto not found
OPENSSL_WASM_DIR_FOR_CONFIGURE="${OPENSSL_WASM_LIB_DIR:-${HSM_ROOT}/deps/openssl-wasm/lib}"
OPENSSL_WASM_INC_DIR="$(dirname "$OPENSSL_WASM_DIR_FOR_CONFIGURE")/include"
export CFLAGS="${CFLAGS:-} -g -I${OPENSSL_WASM_INC_DIR}"
export LDFLAGS="${LDFLAGS:-} -L${OPENSSL_WASM_DIR_FOR_CONFIGURE}"
echo "[build] CFLAGS=${CFLAGS}"
echo "[build] LDFLAGS=${LDFLAGS}"

echo "[build] Running emconfigure..."
emconfigure ./configure \
    --host=wasm32-unknown-emscripten \
    --disable-shared \
    --enable-static \
    --disable-defaults \
    --enable-charon \
    --enable-ikev2 \
    --enable-monolithic \
    --enable-pkcs11 \
    --enable-nonce \
    --enable-random \
    --enable-sha1 \
    --enable-sha2 \
    --enable-aes \
    --enable-hmac \
    --enable-pem \
    --enable-pkcs1 \
    --enable-pkcs8 \
    --enable-x509 \
    --enable-pubkey \
    --enable-constraints \
    --enable-revocation \
    --enable-openssl \
    --enable-kdf \
    --disable-kernel-netlink \
    --disable-socket-default

# 8c. Compile + link
NCPU=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo "[build] Running emmake (-j${NCPU})..."

# Extra link flags:
#  - Link the static softhsmv3 archive for C_GetFunctionList
#  - ALLOW_MEMORY_GROWTH: heap can grow past initial
#  - ALLOW_TABLE_GROWTH: JS can addFunction() pointers (used by worker.js
#    to register C_GetFunctionList for the dlsym fallback path)
#  - ERROR_ON_UNDEFINED_SYMBOLS=0: let env imports (wasm_net_*, pkcs11_*)
#    bind lazily in the worker
#  - EXPORTED_FUNCTIONS: explicitly export every symbol the worker calls
#  - EXPORTED_RUNTIME_METHODS: runtime helpers used by worker.js
EXPORTED_FUNCS='_main,_wasm_set_proposal_mode,_wasm_set_auth_mode,_pkcs11_set_rpc_mode,_wasm_hsm_init,_wasm_net_set_sab,_wasm_setup_config,_wasm_initiate,_wasm_get_peer_by_name,_wasm_create_peer_enum,_wasm_create_ike_enum,_socket_wasm_create,_wasm_socket_destroy,_pkcs11_wasm_wrap_function_list,_pkcs11_wasm_rpc_function_list,_pkcs11_wasm_C_GetFunctionList,_C_GetFunctionList,_C_GetSlotList,_C_OpenSession,_C_CloseSession,_C_Login,_C_GenerateKeyPair,_C_GetAttributeValue,_C_SetAttributeValue,_C_SignInit,_C_Sign,_malloc,_free'
EXPORTED_RUNTIME='stackAlloc,stackSave,stackRestore,addFunction,removeFunction,lengthBytesUTF8,stringToUTF8,UTF8ToString,FS,ENV,HEAPU8,HEAP32,HEAPU32,getValue,setValue'

# The softhsm static archive is linked ONLY into the final charon
# executable — not into libstrongswan.la (which emar can't swallow since
# it's an ar archive itself). We append it to charon_LDADD on the make
# command line. softhsmv3 depends on OpenSSL for RAND_bytes / EVP / BIGNUM
# primitives, so libcrypto.a must be linked alongside it — without this,
# C_Initialize aborts at wasm_hsm_init time with "missing function RAND_bytes".
OPENSSL_WASM_LIB_DIR="${OPENSSL_WASM_LIB_DIR:-${HSM_ROOT}/deps/openssl-wasm/lib}"
OPENSSL_CRYPTO_WASM="${OPENSSL_WASM_LIB_DIR}/libcrypto.a"
OPENSSL_SSL_WASM="${OPENSSL_WASM_LIB_DIR}/libssl.a"

CHARON_EXTRA_LDADD=""
if [[ -f "$SOFTHSM_WASM_LIB" ]]; then
    echo "[build] Linking softhsmv3 static lib into charon: $SOFTHSM_WASM_LIB"
    CHARON_EXTRA_LDADD="$SOFTHSM_WASM_LIB"
else
    echo "[build] WARNING: SOFTHSM_WASM_LIB not found ($SOFTHSM_WASM_LIB)"
    echo "[build]          Link step will likely fail with an unresolved"
    echo "[build]          C_GetFunctionList symbol. Build the softhsmv3"
    echo "[build]          WASM target first or set SOFTHSM_WASM_LIB."
fi
if [[ -f "$OPENSSL_CRYPTO_WASM" ]]; then
    echo "[build] Linking libcrypto.a into charon: $OPENSSL_CRYPTO_WASM"
    CHARON_EXTRA_LDADD="$CHARON_EXTRA_LDADD $OPENSSL_CRYPTO_WASM"
    if [[ -f "$OPENSSL_SSL_WASM" ]]; then
        CHARON_EXTRA_LDADD="$CHARON_EXTRA_LDADD $OPENSSL_SSL_WASM"
    fi
else
    echo "[build] WARNING: libcrypto.a not found ($OPENSSL_CRYPTO_WASM)"
    echo "[build]          charon will abort at C_Initialize (missing RAND_bytes)."
    echo "[build]          Run pqctoday-hsm/scripts/build-openssl-wasm.sh first."
fi

# LDFLAGS here apply to ALL link steps (libraries + charon). Library
# link steps use emar — Emscripten flags like -s ALLOW_MEMORY_GROWTH
# are ignored by emar so they're safe. EXPORTED_FUNCTIONS etc. only
# take effect on final-executable links.
LINK_FLAGS="-L${OPENSSL_WASM_DIR_FOR_CONFIGURE} \
    -g \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s ALLOW_TABLE_GROWTH=1 \
    -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
    -s EMULATE_FUNCTION_POINTER_CASTS=1 \
    -s EXPORTED_FUNCTIONS=[${EXPORTED_FUNCS}] \
    -s EXPORTED_RUNTIME_METHODS=[${EXPORTED_RUNTIME}] \
    -s INITIAL_MEMORY=67108864 \
    -s STACK_SIZE=5242880 \
    -s MODULARIZE=0 \
    -s ASSERTIONS=1 \
    -fexceptions \
    -s NO_DISABLE_EXCEPTION_CATCHING=1"
# EMULATE_FUNCTION_POINTER_CASTS=1 — global trampoline that papers over
# function-pointer arity mismatches. strongSwan has dozens of (void*)func
# casts (return_null, return_failed, status helpers, credential set stubs,
# array_destroy_function destructors, plugin_priority_cmp_name, etc.) where
# a 0/1-arg helper is stored into a 2/3/4/5-arg slot. Native cdecl forgives
# the arity mismatch; WASM strict function-signature typing traps. We've
# patched the largest-impact sites individually (helpers + credential sets
# + sa/ikev2 task vtables) but the long tail is too large to enumerate.
# This flag generates type-erased trampolines so any indirect call works
# regardless of declared arity. Cost: a small per-call overhead and slightly
# larger code; benefit: full strongSwan IKE_AUTH path completes without
# whack-a-mole patching. Earlier attempts hit a task_manager_create issue
# but the engine fixes that have since landed (drain, ike_cfg enum, etc.)
# should make this safe to re-enable.

# Force-link the plugin constructor: wasm-ld archive selection requires an
# external symbol reference. Step 7.5 added plugin_constructors.c to
# libstrongswan_la_SOURCES; step 7.6 made `register_plugins` non-static. This
# -Wl,--undefined flag triggers archive lookup and pulls plugin_constructors.o
# into the link, which transitively retains all 16 xxx_plugin_create symbols
# referenced from inside register_plugins().
emmake make -j"$NCPU" \
    LDFLAGS="$LINK_FLAGS -Wl,--undefined=register_plugins" \
    charon_LDADD="\$(top_builddir)/src/libstrongswan/libstrongswan.la \$(top_builddir)/src/libcharon/libcharon.la -lm \$(PTHREADLIB) \$(ATOMICLIB) \$(DLLIB) \$(top_builddir)/src/libstrongswan/plugin_constructors.o $CHARON_EXTRA_LDADD" \
    || { echo "[build] emmake failed — see /tmp/wasm-build.log"; exit 1; }

# 9. Copy outputs to hub (unless guarded)
CHARON_JS="src/charon/charon"
CHARON_WASM="src/charon/charon.wasm"
[[ -f "$CHARON_JS"   ]] || CHARON_JS="src/charon/charon.js"
[[ -f "$CHARON_JS"   ]] || { echo "[build] ERROR: $CHARON_JS not found"   >&2; exit 1; }
[[ -f "$CHARON_WASM" ]] || { echo "[build] ERROR: $CHARON_WASM not found" >&2; exit 1; }

echo "[build] Built: $CHARON_JS ($(stat -f%z "$CHARON_JS" 2>/dev/null || stat -c%s "$CHARON_JS") bytes)"
echo "[build] Built: $CHARON_WASM ($(stat -f%z "$CHARON_WASM" 2>/dev/null || stat -c%s "$CHARON_WASM") bytes)"

if [[ "${SKIP_INSTALL_TO_HUB:-0}" != "1" ]]; then
    echo "[build] Copying charon WASM artifacts to ${HUB_WASM_OUT}..."
    mkdir -p "$HUB_WASM_OUT"
    cp "$CHARON_JS"   "$HUB_WASM_OUT/strongswan.js"
    cp "$CHARON_WASM" "$HUB_WASM_OUT/strongswan.wasm"
    ls -lh "$HUB_WASM_OUT/strongswan.js" "$HUB_WASM_OUT/strongswan.wasm"
else
    echo "[build] SKIP_INSTALL_TO_HUB=1 — not overwriting baseline hub artifacts."
fi

echo "[build] Done."
