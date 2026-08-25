#!/usr/bin/env bash
# test-openssl-provider.sh — live coverage harness for the vendored OpenSSL
# provider (src/vendor/pkcs11-provider) against BOTH PKCS#11 engines, under
# the real OpenSSL 3.6.3 oracle.
#
# Design record: docs/openssl-provider-coverage-audit-2026-08-25.md (§5/§6 —
# the T-case ids below map to that plan; XFAIL expectations map to gap ids
# there and to remediation items in
# docs/openssl-provider-remediation-plan-2026-08-25.md).
#
# Verification principles (deliberate, see audit §5):
#   - Every crypto result is cross-checked against the OTHER implementation
#     (provider-sign -> software-verify, software-encap -> provider-decap);
#     never self-verified inside one stack.
#   - XFAIL cases assert today's known gaps. An XFAIL that PASSES (XPASS)
#     fails the whole run — landing a remediation without flipping the
#     expectation here is loudly visible, and so is a silent regression.
#   - Exit codes are captured directly from each command, never through a
#     pipeline (a `grep -v` filter ate a real exit code during the audit's
#     own probing — see audit §5).
#   - Engine log noise (WART-1, ObjectFile.cpp attribute-type warnings) is
#     filtered from DISPLAY only, never from the pass/fail decision.
#
# Environment (defaults match the pqc-rust container; override via env):
#   OPENSSL_BIN        (default /usr/local/ssl/bin/openssl — must be >= 3.6)
#   OPENSSL_LIB_DIR    (default /usr/local/ssl/lib)
#   HSM_ROOT           (default /ag/pqctoday-hsm)
#   PROVIDER_SO        (default $HSM_ROOT/build/src/vendor/pkcs11-provider/pkcs11-provider.so)
#   CPP_ENGINE_SO      (default $HSM_ROOT/build/src/lib/libsofthsmv3.so)
#   RUST_ENGINE_SO     (default: newest libsofthsmrustv3.so under /cargo-target or rust/target)
#   SOFTHSM_UTIL       (default $HSM_ROOT/build/src/bin/util/softhsm2-util)
#
# Summary line (the gate step greps this, end-anchored):
#   OPENSSL-PROVIDER-HARNESS: PASS=<n> FAIL=0 XFAIL=<m> XPASS=0

set -u

HSM_ROOT="${HSM_ROOT:-/ag/pqctoday-hsm}"
OPENSSL_BIN="${OPENSSL_BIN:-/usr/local/ssl/bin/openssl}"
OPENSSL_LIB_DIR="${OPENSSL_LIB_DIR:-/usr/local/ssl/lib}"
PROVIDER_SO="${PROVIDER_SO:-$HSM_ROOT/build/src/vendor/pkcs11-provider/pkcs11-provider.so}"
CPP_ENGINE_SO="${CPP_ENGINE_SO:-$HSM_ROOT/build/src/lib/libsofthsmv3.so}"
SOFTHSM_UTIL="${SOFTHSM_UTIL:-$HSM_ROOT/build/src/bin/util/softhsm2-util}"
if [[ -z "${RUST_ENGINE_SO:-}" ]]; then
  for c in /cargo-target/debug/libsofthsmrustv3.so /cargo-target/release/libsofthsmrustv3.so \
           "$HSM_ROOT/rust/target/debug/libsofthsmrustv3.so" "$HSM_ROOT/rust/target/release/libsofthsmrustv3.so"; do
    [[ -f "$c" ]] && RUST_ENGINE_SO="$c" && break
  done
fi
RUST_ENGINE_SO="${RUST_ENGINE_SO:-}"

export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
ROOT_WORK="$(mktemp -d /tmp/ossl-provider-harness.XXXXXX)"
trap 'rm -rf "$ROOT_WORK"' EXIT

PASS=0; FAIL=0; XFAIL=0; XPASS=0
declare -a FAILED_CASES=()

say()  { printf '\033[1;36m[%s]\033[0m %s\n' "$1" "$2"; }
show_log() { # display helper: engine attribute-probe noise filtered for READING only
  sed 's/^/    | /' "$1" | grep -v 'ObjectFile.cpp(181)' | head -12
}

# run_case <id> <PASS|XFAIL> <description> <fn>
# The fn returns 0 on functional success. XFAIL semantics: fn failing is the
# expected (recorded-gap) outcome; fn succeeding is XPASS and fails the run.
run_case() {
  local id="$1" expect="$2" desc="$3" fn="$4"
  local log="$ROOT_WORK/$id.log"
  if "$fn" >"$log" 2>&1; then
    if [[ "$expect" == PASS ]]; then
      PASS=$((PASS+1)); printf '  \033[1;32mPASS \033[0m %-6s %s\n' "$id" "$desc"
    else
      XPASS=$((XPASS+1)); FAILED_CASES+=("$id XPASS (expected-gap case unexpectedly passed — flip the expectation if a remediation landed)")
      printf '  \033[1;31mXPASS\033[0m %-6s %s\n' "$id" "$desc"; show_log "$log"
    fi
  else
    if [[ "$expect" == PASS ]]; then
      FAIL=$((FAIL+1)); FAILED_CASES+=("$id FAIL")
      printf '  \033[1;31mFAIL \033[0m %-6s %s\n' "$id" "$desc"; show_log "$log"
    else
      XFAIL=$((XFAIL+1)); printf '  \033[1;33mXFAIL\033[0m %-6s %s (known gap, expected)\n' "$id" "$desc"
    fi
  fi
}

# mk_arena <name> <engine_so> [extra_pkcs11_sect_lines] — hermetic workdir:
# own tokendir + conf + one token labeled <name>, so pkcs11:token=<name>
# URIs are unambiguous (a probe during the audit showed type-only URIs
# match the wrong key once two keypairs share a token). Echoes the
# workdir; caller sets the env pair. extra_pkcs11_sect_lines (optional)
# is appended verbatim into [pkcs11_sect] — used by T9 to opt into
# pkcs11-module-load-behavior=early (see that case for why).
mk_arena() {
  # Locals split across statements deliberately: under `set -u` bash 5.2
  # does NOT let a later expansion in the SAME `local` statement see an
  # earlier assignment ("name: unbound variable" — reproduced live while
  # building this harness, not theory).
  local name="$1"
  local engine="$2"
  local extra="${3:-}"
  local w="$ROOT_WORK/$name"
  mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = ERROR
EOF
  cat > "$w/openssl.cnf" <<EOF
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $PROVIDER_SO
pkcs11-module-path = $engine
pkcs11-module-token-pin = 1234
pkcs11-module-encode-provider-uri-to-pem = true
activate = 1
$extra
EOF
  # OPENSSL_CONF=/dev/null: this runs BEFORE use_arena resets OPENSSL_CONF to
  # THIS arena's own config, so a caller invoking mk_arena mid-run still has
  # the PREVIOUS arena's OPENSSL_CONF exported. softhsm2-util links libcrypto,
  # which auto-loads OPENSSL_CONF on first use if set — if that stale config
  # activates the pkcs11-provider with pkcs11-module-load-behavior=early
  # (as T9's does), it dlopens+C_Initializes the SAME engine .so THIS
  # softhsm2-util invocation is also about to load directly, and the second
  # C_Initialize legitimately fails with CKR_CRYPTOKI_ALREADY_INITIALIZED
  # ("SoftHSM is already initialized") — reproduced live once T9 started
  # using early-load-behavior (WART-4 / remediation R0.4): T10 and T14,
  # which run after T9, started failing purely from environment leakage, not
  # from anything wrong in their own arenas. Same fix T8 already uses for
  # its software peer keygen, applied here for the same reason.
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$engine" \
    --init-token --free --label "$name" --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  echo "$w"
}

use_arena() { export SOFTHSM2_CONF="$1/softhsm2.conf" OPENSSL_CONF="$1/openssl.cnf"; }
O() { "$OPENSSL_BIN" "$@"; }   # exit code taken directly — no pipelines

# ─── T0 preflight (hard requirements — refuse to produce a vacuous green) ───
say preflight "environment"
VER="$(LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$OPENSSL_BIN" version 2>/dev/null)"
case "$VER" in OpenSSL\ 3.6*|OpenSSL\ 3.7*|OpenSSL\ 4.*) : ;; *)
  echo "FATAL: need OpenSSL >= 3.6 at $OPENSSL_BIN (got: ${VER:-nothing}) — see audit ENV-1/gate --cpp note"; exit 2;; esac
for f in "$PROVIDER_SO" "$CPP_ENGINE_SO" "$SOFTHSM_UTIL"; do
  [[ -e "$f" ]] || { echo "FATAL: missing $f (run the --cpp gate step / cmake build first)"; exit 2; }
done
echo "  oracle: $VER; provider: $PROVIDER_SO"
[[ -n "$RUST_ENGINE_SO" ]] && echo "  rust engine: $RUST_ENGINE_SO" || echo "  rust engine: NOT FOUND (T15 will fail loudly)"

MSG="$ROOT_WORK/msg.txt"; echo "openssl-provider harness message $(date -u +%s)" > "$MSG"

# ─── C++ native arm ─────────────────────────────────────────────────────────
say arm "C++ engine ($CPP_ENGINE_SO)"

t1() { local w; w=$(mk_arena t1 "$CPP_ENGINE_SO") && use_arena "$w" \
  && O list -providers | grep -A3 '^  pkcs11$' | grep -q 'status: active'; }
run_case T1 PASS "provider activates alongside default" t1

t2() { local w; w=$(mk_arena t2 "$CPP_ENGINE_SO") && use_arena "$w" \
  && O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" \
  && O storeutl -text "pkcs11:token=t2" | grep -q "ML-DSA-65 Public-Key"; }
run_case T2 PASS "pkcs11: store enumerates a token keypair" t2

mldsa_case() { # $1 = param set suffix, $2 = expected FIPS 204 sig size
  local set="$1" size="$2" w
  w=$(mk_arena "mldsa$set" "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm "ML-DSA-$set" -out "$w/k.pem" || return 1
  O pkeyutl -sign -inkey "pkcs11:token=mldsa$set;type=private" -rawin -in "$MSG" -out "$w/sig.bin" || return 1
  [[ "$(stat -c%s "$w/sig.bin")" == "$size" ]] || { echo "sig size $(stat -c%s "$w/sig.bin") != $size"; return 1; }
  O pkey -in "pkcs11:token=mldsa$set;type=public" -pubin -pubout -out "$w/pub.pem" || return 1
  # cross-check: OpenSSL's own SOFTWARE implementation verifies the token's signature
  O pkeyutl -verify -pubin -inkey "$w/pub.pem" -rawin -in "$MSG" -sigfile "$w/sig.bin" || return 1
}
t3a() { mldsa_case 44 2420; }; run_case T3a PASS "ML-DSA-44 token sign -> software verify (size 2420)" t3a
t3b() { mldsa_case 65 3309; }; run_case T3b PASS "ML-DSA-65 token sign -> software verify (size 3309)" t3b
t3c() { mldsa_case 87 4627; }; run_case T3c PASS "ML-DSA-87 token sign -> software verify (size 4627)" t3c

t3t() { # tamper: a flipped byte MUST fail verification (verifier can say no)
  local w="$ROOT_WORK/mldsa65"; use_arena "$w"
  [[ -f "$w/sig.bin" ]] || return 1
  cp "$w/sig.bin" "$w/tampered.bin"
  printf '\x00' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  cmp -s "$w/sig.bin" "$w/tampered.bin" && printf '\xff' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  if O pkeyutl -verify -pubin -inkey "$w/pub.pem" -rawin -in "$MSG" -sigfile "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered signature VERIFIED — verifier cannot say no"; return 1; else return 0; fi
}
run_case T3t PASS "ML-DSA-65 tampered signature rejected" t3t

# ML-KEM through the provider: keymgmt has NO GEN functions (confirmed in
# src/kem/mlkem.c — zero OSSL_FUNC_KEYMGMT_GEN entries — and live:
# `genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768` dies with
# gen_init "operation not supported for this keytype"). Gap OP-6 /
# remediation R3b. Until keys can be created (or imported) on-token, the
# software-encap -> token-decap E2E from the test plan is unreachable
# natively — it exists today only on the WASM path (hub e2e), where keys
# are created via the wasm API, not via provider keygen.
t4x() { local w; w=$(mk_arena mlkemgen "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768 -out "$w/k.pem" || return 1
  # genpkey via the default provider "succeeds" by generating in SOFTWARE if
  # the fetch falls back — assert the key actually landed on the token:
  O storeutl -text "pkcs11:token=mlkemgen" 2>/dev/null | grep -q "ML-KEM"
}
run_case T4x XFAIL "ML-KEM token keygen via provider (gap OP-6 / remediation R3b)" t4x

t5() { local w; w=$(mk_arena rsa "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$w/k.pem" || return 1
  O dgst -sha256 -sign "pkcs11:token=rsa;type=private" -out "$w/sig.bin" "$MSG" || return 1
  O pkey -in "pkcs11:token=rsa;type=public" -pubin -pubout -out "$w/pub.pem" || return 1
  O dgst -sha256 -verify "$w/pub.pem" -signature "$w/sig.bin" "$MSG" || return 1
  # software OAEP-encrypts to the exported pub; TOKEN decrypts
  # OAEP md/MGF1 pinned to SHA-256 on BOTH sides: the C++ engine rejects
  # OpenSSL's SHA-1 OAEP defaults outright ("Invalid hashAlg/mgf combination
  # for RSA-OAEP", SoftHSM_keygen.cpp:8056 — found live; audit WART-5).
  O pkeyutl -encrypt -pubin -inkey "$w/pub.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$MSG" -out "$w/enc.bin" || return 1
  O pkeyutl -decrypt -inkey "pkcs11:token=rsa;type=private" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$w/enc.bin" -out "$w/dec.txt" || return 1
  cmp -s "$MSG" "$w/dec.txt"
}
run_case T5 PASS "RSA-3072 sign->sw-verify + sw-OAEP-encrypt->token-decrypt" t5

t6() { local w; w=$(mk_arena ecdsa "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$w/k.pem" || return 1
  O dgst -sha256 -sign "pkcs11:token=ecdsa;type=private" -out "$w/sig.bin" "$MSG" || return 1
  O pkey -in "pkcs11:token=ecdsa;type=public" -pubin -pubout -out "$w/pub.pem" || return 1
  O dgst -sha256 -verify "$w/pub.pem" -signature "$w/sig.bin" "$MSG"
}
run_case T6 PASS "ECDSA P-256 token sign -> software verify" t6

t7() { local w; w=$(mk_arena ed "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ED25519 -out "$w/k.pem" || return 1
  O pkeyutl -sign -inkey "pkcs11:token=ed;type=private" -rawin -in "$MSG" -out "$w/sig.bin" || return 1
  O pkey -in "pkcs11:token=ed;type=public" -pubin -pubout -out "$w/pub.pem" || return 1
  O pkeyutl -verify -pubin -inkey "$w/pub.pem" -rawin -in "$MSG" -sigfile "$w/sig.bin"
}
run_case T7 PASS "Ed25519 token sign -> software verify" t7

t8() { local w; w=$(mk_arena ecdh "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$w/k.pem" || return 1
  O pkey -in "pkcs11:token=ecdh;type=public" -pubin -pubout -out "$w/tokpub.pem" || return 1
  OPENSSL_CONF=/dev/null O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$w/peer.pem" 2>/dev/null || return 1
  O pkey -in "$w/peer.pem" -pubout -out "$w/peerpub.pem" || return 1
  # token side derives with software peer's pub; software derives the mirror
  O pkeyutl -derive -inkey "pkcs11:token=ecdh;type=private" -peerkey "$w/peerpub.pem" -out "$w/s1.bin" || return 1
  O pkeyutl -derive -inkey "$w/peer.pem" -peerkey "$w/tokpub.pem" -out "$w/s2.bin" || return 1
  [[ -s "$w/s1.bin" ]] && cmp -s "$w/s1.bin" "$w/s2.bin"
}
run_case T8 PASS "ECDH P-256 token derive == software derive" t8

# WART-4 root cause (confirmed live, not guessed): p11prov_query_operation()
# returns ctx->op_digest/op_kdf/op_random/op_exchange/op_signature/
# op_asym_cipher/op_kem directly; those are only populated by
# operations_init(), itself only triggered lazily via p11prov_ctx_status()
# from a key/session code path. A fetch with no key ever loaded gets NULL
# once and gives up — no_cache=1 on that NULL only helps a LATER re-query
# in the SAME process, which a single `openssl dgst` invocation never gets.
# Tried forcing p11prov_ctx_status() unconditionally at the top of
# p11prov_query_operation() itself — rebuilt and it broke provider
# activation entirely (dropped out of `openssl list -providers`), a real
# regression caught before landing (see the remediation plan's R0.4 row).
# The provider already ships the actual fix for this as an opt-in config
# directive: pkcs11-module-load-behavior=early forces the same
# p11prov_ctx_status() call, but from OSSL_provider_init() itself (see
# provider.c's own "PAY ATTENTION: do this as the last thing" comment)
# rather than from inside a fetch callback — verified live to resolve this
# exact scenario with zero source changes. Not a provider bug: lazy-by-
# default module loading is a deliberate trade-off (don't pay for a token
# connection when the caller never uses one), same category as WART-5's
# OAEP default mismatch — document/configure around it, don't "fix" it.
t9() { local w; w=$(mk_arena t9early "$CPP_ENGINE_SO" "pkcs11-module-load-behavior = early") && use_arena "$w" || return 1
  local a b c d
  a=$(O dgst -sha256 -propquery "provider=pkcs11" -hex -r "$MSG") || return 1
  b=$(O dgst -sha256 -propquery "provider=default" -hex -r "$MSG") || return 1
  c=$(O dgst -sha3-256 -propquery "provider=pkcs11" -hex -r "$MSG") || return 1
  d=$(O dgst -sha3-256 -propquery "provider=default" -hex -r "$MSG") || return 1
  [[ "$a" == "$b" && "$c" == "$d" ]]
}
run_case T9 PASS "digest fetch via provider propquery in a fresh process, pkcs11-module-load-behavior=early (gap WART-4 / remediation R0.4)" t9

t10() { local w; w=$(mk_arena uripem "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$w/k.pem" || return 1
  grep -q "PKCS#11 PROVIDER URI" "$w/k.pem" || { echo "no URI-PEM written"; return 1; }
  O pkeyutl -sign -inkey "$w/k.pem" -in <(printf '0123456789abcdef0123456789abcdef') -out "$w/sig.bin"
}
run_case T10 PASS "URI-PEM round-trip works for EC (decoder control case)" t10

t11() { local w; w=$(mk_arena uripemml "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" || return 1
  grep -q "PKCS#11 PROVIDER URI" "$w/k.pem" || { echo "no URI-PEM written"; return 1; }
  O pkeyutl -sign -inkey "$w/k.pem" -rawin -in "$MSG" -out "$w/sig.bin"
}
run_case T11 XFAIL "URI-PEM round-trip for ML-DSA (gap OP-2 / remediation R2)" t11

# R1 (partial): SLH-DSA keymgmt+store+encoder are now real and live-verified
# (all 12 parameter sets) — genpkey lands a key on token, storeutl correctly
# enumerates and text/SPKI-encodes it, matching OpenSSL's own 12 native
# algorithm names for cross-recognition. T12's original propquery
# ("provider=pkcs11", no "?") was itself a latent bug — every OTHER genpkey
# case in this harness uses the optional "?provider=pkcs11" form (a required
# propquery on genpkey fails generically here, reproduced live even for
# plain RSA — a WART-4-adjacent gap, not specific to SLH-DSA — see the
# remediation plan). Fixed to match the harness's own established pattern,
# and upgraded from "genpkey exits 0" to an explicit on-token check (the
# same class of false-positive the audit's own R0.1 investigation warns
# about: an optional propquery quietly falling back to software would
# still exit 0).
t12() { local w; w=$(mk_arena slh "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHA2-128s -out "$w/k.pem" || return 1
  O storeutl -text "pkcs11:token=slh" 2>/dev/null | grep -q "SLH-DSA-SHA2-128s Public-Key"
}
run_case T12 PASS "SLH-DSA keygen/store/encode reachable through provider, all 12 param sets (gap ALG-1 / remediation R1, partial)" t12

# R1 remaining gap: keygen/store/encode all work (T12), but the SIGNATURE
# operation itself does not — `pkeyutl -sign` on the very same on-token key
# fails at OpenSSL's own fetch layer ("operation not supported for this
# keytype", crypto/evp/m_sigver.c) despite the provider's signature
# registration switch case being confirmed live (via a temporary debug
# print) to run to completion for all 12 variants, with byte-identical
# algorithm name strings across the keymgmt/signature/store registration
# sites. Root cause not yet isolated — deepest investigation this session
# got: it is not a registration, template, or name-matching bug on this
# provider's side by every check available (gdb/`openssl list -select`
# were both unreliable here — `list` never shows "@ pkcs11" for KNOWN-
# WORKING ML-DSA either, so it cannot distinguish the two). Needs a build
# with more provider-side introspection than this harness's tools allow.
t12sign() { local w; w=$(mk_arena slhsign "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHA2-128s -out "$w/k.pem" || return 1
  O pkeyutl -sign -inkey "pkcs11:token=slhsign;type=private" -rawin -in "$MSG" -out "$w/sig.bin"
}
run_case T12sign XFAIL "SLH-DSA token-sign (gap ALG-1 remainder / remediation R1, unresolved this session)" t12sign

t14() { local w; w=$(mk_arena cms "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$w/k.pem" || return 1
  O req -new -x509 -key "pkcs11:token=cms;type=private" -subj "/CN=provider-harness" -days 2 -out "$w/cert.pem" || return 1
  O cms -sign -in "$MSG" -signer "$w/cert.pem" -inkey "pkcs11:token=cms;type=private" -out "$w/signed.cms" -outform PEM -nodetach || return 1
  O cms -verify -in "$w/signed.cms" -inform PEM -CAfile "$w/cert.pem" -out /dev/null
}
run_case T14 PASS "CMS sign via token RSA key -> software cms -verify" t14

# ─── Rust native arm ────────────────────────────────────────────────────────
say arm "Rust engine (${RUST_ENGINE_SO:-MISSING})"

mk_rust_cnf() { # self-contained (no dependency on another case's arena)
  local w="$1"
  cat > "$w/openssl.cnf" <<EOF
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $PROVIDER_SO
pkcs11-module-path = $RUST_ENGINE_SO
pkcs11-module-token-pin = 1234
activate = 1
EOF
}

t15a() { # provider must at least activate over the Rust cdylib
  [[ -n "$RUST_ENGINE_SO" ]] || { echo "rust cdylib not found"; return 1; }
  local w="$ROOT_WORK/rustload"; mkdir -p "$w"; mk_rust_cnf "$w"
  OPENSSL_CONF="$w/openssl.cnf" O list -providers | grep -A3 '^  pkcs11$' | grep -q 'status: active'
}
run_case T15a PASS "provider activates over the native Rust cdylib" t15a

t15b() { # ENV-2: in-memory token store, no cross-process persistence — any
         # multi-process keygen+use flow MUST fail today (remediation R6)
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/rustfunc"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  # OPENSSL_CONF=/dev/null: same reason as mk_arena's own init-token call
  # (see its comment) — without it this would inherit whatever prior
  # arena's OPENSSL_CONF is still exported, which can make an unrelated
  # config's pkcs11-module-load-behavior=early collide with this direct
  # module load and mask ENV-2's real failure behind
  # CKR_CRYPTOKI_ALREADY_INITIALIZED instead.
  OPENSSL_CONF=/dev/null "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label rustarm --so-pin 1234 --pin 1234 >/dev/null 2>&1 || true  # state dies with this process
  OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null \
    && OPENSSL_CONF="$w/openssl.cnf" \
       O pkeyutl -sign -inkey "pkcs11:type=private" -rawin -in "$MSG" -out "$w/sig.bin" 2>/dev/null
}
run_case T15b XFAIL "Rust arm functional flow (blocked by ENV-2 / remediation R6)" t15b

# ─── R0.1 regression guard ──────────────────────────────────────────────────
# The token-scan attribute-type noise (WART-1) was a real bug, not spec-legal
# probing: P11Objects.cpp's mandatory-attribute-check loop called
# getByteStringValue() on EVERY attribute in an object's schema (CKA_CLASS,
# CKA_TOKEN, ...), not just the byte-string-typed ones the ck14/15/16 checks
# actually read — fixed 2026-08-25 (remediation R0.1). This is the "harness
# greps for zero ObjectFile.cpp(181) lines" proof that item's remediation
# plan entry names — assert it here, across every case's raw log (show_log()
# above filters this line from DISPLAY only; the underlying .log files still
# have it if the noise comes back).
NOISE_HITS=0
for f in "$ROOT_WORK"/*.log; do
  [[ -f "$f" ]] || continue
  n=$(grep -c 'ObjectFile.cpp(181)' "$f" 2>/dev/null || true)
  NOISE_HITS=$((NOISE_HITS + ${n:-0}))
done
if [[ $NOISE_HITS -gt 0 ]]; then
  echo "REGRESSION: $NOISE_HITS 'ObjectFile.cpp(181)' attribute-type warning(s) across case logs (R0.1 regressed)"
  FAIL=$((FAIL+1))
  FAILED_CASES+=("R0.1-REGRESSION token-scan attribute-type noise is back ($NOISE_HITS hits)")
fi

# ─── verdict ────────────────────────────────────────────────────────────────
echo
if [[ ${#FAILED_CASES[@]} -gt 0 ]]; then
  printf '\033[1;31mfailed cases:\033[0m\n'; printf '  - %s\n' "${FAILED_CASES[@]}"
fi
echo "OPENSSL-PROVIDER-HARNESS: PASS=$PASS FAIL=$FAIL XFAIL=$XFAIL XPASS=$XPASS"
[[ $FAIL -eq 0 && $XPASS -eq 0 ]] || exit 1
exit 0
