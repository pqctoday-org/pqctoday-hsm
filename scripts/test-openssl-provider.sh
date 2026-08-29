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
#   HSM_ROOT           (default: this script's own repo root — see below)
#   PROVIDER_SO        (default $HSM_ROOT/build/src/vendor/pkcs11-provider/pkcs11-provider.so)
#   CPP_ENGINE_SO      (default $HSM_ROOT/build/src/lib/libsofthsmv3.so)
#   RUST_ENGINE_SO     (default: newest libsofthsmrustv3.so under /cargo-target or rust/target)
#   SOFTHSM_UTIL       (default $HSM_ROOT/build/src/bin/util/softhsm2-util)
#
# Summary line (the gate step greps this, end-anchored):
#   OPENSSL-PROVIDER-HARNESS: PASS=<n> FAIL=0 XFAIL=<m> XPASS=0

set -u

# HSM_ROOT defaults to THIS SCRIPT's own repo root, not a hardcoded
# /ag/pqctoday-hsm. The old hardcoded default silently tested the MAIN
# checkout's binaries whenever the harness was run from a git worktree
# (`cd <worktree> && bash scripts/test-openssl-provider.sh` loaded
# /ag/pqctoday-hsm/build/.../pkcs11-provider.so + libsofthsmv3.so), because
# nothing here is cwd-relative — every artifact path below hangs off
# HSM_ROOT. Symptom: PASS=16 FAIL=74, with only the baseline RSA/ECDSA/
# Ed25519/ECDH cases surviving (main's provider has none of this branch's
# PQC/TLS/store work) plus a spurious "R0.1-REGRESSION ... noise is back"
# from main's engine, which does not carry the R0.1 P11Objects.cpp fix.
# Same self-locating idiom as scripts/build-strongswan-wasm.sh.
HSM_ROOT="${HSM_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
OPENSSL_BIN="${OPENSSL_BIN:-/usr/local/ssl/bin/openssl}"
OPENSSL_LIB_DIR="${OPENSSL_LIB_DIR:-/usr/local/ssl/lib}"
PROVIDER_SO="${PROVIDER_SO:-$HSM_ROOT/build/src/vendor/pkcs11-provider/pkcs11-provider.so}"
CPP_ENGINE_SO="${CPP_ENGINE_SO:-$HSM_ROOT/build/src/lib/libsofthsmv3.so}"
SOFTHSM_UTIL="${SOFTHSM_UTIL:-$HSM_ROOT/build/src/bin/util/softhsm2-util}"
COMPOSITE_PROBE="${COMPOSITE_PROBE:-$HSM_ROOT/build/composite_sig_probe}"
DUMP_INT_PARAM="${DUMP_INT_PARAM:-$HSM_ROOT/build/dump_int_param}"
LMS_XDR_VERIFY="${LMS_XDR_VERIFY:-$HSM_ROOT/build/lms_xdr_verify}"
HSS_PUBKEY_DUMP="${HSS_PUBKEY_DUMP:-$HSM_ROOT/build/hss_pubkey_dump}"
HSS_W4_KEYGEN="${HSS_W4_KEYGEN:-$HSM_ROOT/build/hss_w4_keygen}"
HSS_FALLBACK_FIXTURE="${HSS_FALLBACK_FIXTURE:-$HSM_ROOT/build/hss_fallback_fixture}"
SKEY_FLOW_PROBE="${SKEY_FLOW_PROBE:-$HSM_ROOT/build/skey_flow_probe}"
SHAKE_SIGN_PROBE="${SHAKE_SIGN_PROBE:-$HSM_ROOT/build/shake_sign_probe}"
AEAD_PROBE="${AEAD_PROBE:-$HSM_ROOT/build/aead_probe}"
AEAD_EDGE_PROBE="${AEAD_EDGE_PROBE:-$HSM_ROOT/build/aead_edge_probe}"
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
for f in "$PROVIDER_SO" "$CPP_ENGINE_SO" "$SOFTHSM_UTIL" "$COMPOSITE_PROBE" "$DUMP_INT_PARAM" "$LMS_XDR_VERIFY" "$HSS_PUBKEY_DUMP" "$HSS_W4_KEYGEN" "$HSS_FALLBACK_FIXTURE" "$SKEY_FLOW_PROBE" "$AEAD_PROBE" "$AEAD_EDGE_PROBE" "$SHAKE_SIGN_PROBE"; do
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

# ML-KEM token keygen (gap OP-6 / remediation R3b, landed): the per-variant
# ML-KEM keymgmt tables in src/kem/mlkem.c now carry real GEN_INIT/GEN/
# GEN_CLEANUP/GEN_SET_PARAMS/GEN_SETTABLE_PARAMS entries (implemented in
# keymgmt.c, modeled on the ML-DSA block, and exported non-static because
# mlkem.c is a separate translation unit — see the comment ahead of
# p11prov_mlkem_gen_init_int in keymgmt.c). genpkey's own exit code is
# deliberately NOT gating this test: `-out` also needs a PrivateKeyInfo PEM
# encoder to serialize the result, and ML-KEM has ZERO encoders registered
# (confirmed live and in source — zero ADD_ALGO_EXT(..., encoder, ...)
# lines for ML_KEM in provider.c) — a separate, distinct gap, OP-3 /
# remediation R3, not yet landed. genpkey therefore prints "Error writing
# key(s)" and exits 1 even on a fully successful keygen, because the key
# generation + token persistence happens as a side effect BEFORE the
# write-to-file step that fails. storeutl (a different provider entry
# point, STORE not ENCODER) is the actual, authoritative proof this test
# needs for R3b's own claim; see T4x_encode below for the encoder gap.
t4x() { local w; w=$(mk_arena mlkemgen "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768 -out "$w/k.pem" >/dev/null 2>&1
  O storeutl -text "pkcs11:token=mlkemgen" 2>/dev/null | grep -q "ML-KEM"
}
run_case T4x PASS "ML-KEM token keygen reachable through provider, verified via storeutl (gap OP-6 / remediation R3b)" t4x

# Distinct from T4x above: genpkey's own `-out` PEM write (gap OP-3 /
# remediation R3 core, landed). The encoder never touches the actual
# private key bytes — it PEM-wraps a pkcs11: URI reference
# (p11prov_encoder_private_key_to_asn1 -> p11prov_obj_get_public_uri) —
# so the assertion checks for the URI label and that no PRIVATE KEY
# label ever appears, not just exit 0.
t4x_encode() { local w; w=$(mk_arena mlkemenc "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768 -out "$w/k.pem" || return 1
  grep -q "PKCS#11 PROVIDER URI" "$w/k.pem" || { echo "no URI-PEM written"; return 1; }
  grep -q "PRIVATE KEY" "$w/k.pem" && { echo "raw private key material written — must never happen"; return 1; }
  return 0
}
run_case T4x_encode PASS "ML-KEM genpkey -out writes a pkcs11: URI reference, never key bytes (gap OP-3 / remediation R3 core)" t4x_encode

# ML-KEM SPKI + text encoders (remediation R16 encoder-parity tier): public
# key PEM output and -text rendering, matching what ML-DSA already had.
# Proof per the plan: pkey -pubout and -text on a token ML-KEM key; round-
# trip the SPKI through the software provider (OPENSSL_CONF=/dev/null, no
# pkcs11 active at all) to prove the DER structure is standards-correct,
# not just readable by this provider's own decoder.
t4x_spki() { local w; w=$(mk_arena mlkemspki "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768 -out "$w/k.pem" || return 1
  O pkey -in "pkcs11:token=mlkemspki;type=private" -pubout -out "$w/pub.pem" || return 1
  grep -q "BEGIN PUBLIC KEY" "$w/pub.pem" || { echo "no SPKI PEM written"; return 1; }
  OPENSSL_CONF=/dev/null O pkey -pubin -in "$w/pub.pem" -text -noout \
    | grep -q "ML-KEM-768 Public-Key" || { echo "software provider couldn't read the SPKI"; return 1; }
  O pkey -in "pkcs11:token=mlkemspki;type=private" -text -noout \
    | grep -q "PKCS11 ML-KEM-768 Private Key" || { echo "private-key -text rendering missing"; return 1; }
}
run_case T4x_spki PASS "ML-KEM -pubout SPKI PEM round-trips through the software provider + -text renders both key halves (remediation R16)" t4x_spki

# ─── T4x_spki_noexport: dedicated encoder reachability (remediation R40) ───
# Phase-8 R40 grounding: this provider's own dedicated SPKI-DER/text
# encoders for ML-DSA/ML-KEM (encoder.c) already exist and are registered
# (R16, phase 3) -- but live-checking under PKCS11_PROVIDER_DEBUG (this
# case's own predecessor investigation, not assumed) shows T4x_spki's own
# `pkey -pubout` NEVER reaches p11prov_mlkem_encoder_spki_der_encode: it's
# OpenSSL core's own generic keymgmt-export bridge that produces the SPKI
# PEM, exactly as R16's own honest self-assessment flagged ("not
# independently proven necessary"). This case forces the ONE config where
# the bridge genuinely cannot run -- pkcs11-module-allow-export=1 sets
# DISALLOW_EXPORT_PUBLIC (provider.h), blocking OSSL_PKEY_PARAM_PUB_KEY
# export -- to find out what (if anything) still works.
#   text:  DOES reach the dedicated encoder (engine-log verified) and
#          still renders correctly -- the one genuinely load-bearing half.
#   SPKI:  `-pubout` fails cleanly (no output, no crash) -- the dedicated
#          SPKI-DER encoder is registered but OpenSSL's own encoder
#          selection never falls back to it, even with the bridge blocked.
#          A real, narrow, permanent limitation (not something a routing
#          fix in THIS provider can close -- it's OpenSSL core's own
#          encoder-selection deciding not to try a 3rd-party ENCODER for
#          a keymgmt whose algorithm name maps to a well-known OID),
#          documented rather than silently left unproven.
t4x_spki_noexport() { local w; w=$(mk_arena mlkemnoexp "$CPP_ENGINE_SO" "pkcs11-module-allow-export = 1") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768 -out "$w/k.pem" || return 1

  PKCS11_PROVIDER_DEBUG=file:"$w/dbg_text.log" O pkey -in "pkcs11:token=mlkemnoexp;type=private" -text -noout \
    || { echo "-text failed under DISALLOW_EXPORT_PUBLIC -- should still work"; return 1; }
  grep -q "mlkem Text Encoder" "$w/dbg_text.log" \
    || { echo "dedicated text encoder did not run -- engine-log check failed"; return 1; }

  # SPKI must fail CLEANLY (no output file, no crash) — never silently
  # succeed with wrong/empty data.
  O pkey -in "pkcs11:token=mlkemnoexp;type=private" -pubout -out "$w/pub.pem" 2>/dev/null \
    && { echo "-pubout unexpectedly succeeded under DISALLOW_EXPORT_PUBLIC"; return 1; }
  [[ -s "$w/pub.pem" ]] && { echo "-pubout left a non-empty file despite failing"; return 1; }

  return 0
}
run_case T4x_spki_noexport PASS "ML-KEM dedicated encoder reachability under DISALLOW_EXPORT_PUBLIC (remediation R40): -text genuinely reaches the provider's own dedicated text encoder (engine-log verified) and still renders correctly; -pubout fails cleanly with no path available (SPKI-DER encoder confirmed registered-but-unreachable via any CLI surface tested — a documented, permanent, OpenSSL-core-level limitation, not a routing bug in this provider)" t4x_spki_noexport

# R5 prerequisites (gap F36-1, TLS groups — client role): exports the
# public share from the PRIVATE object TLS actually holds after ephemeral
# keygen (was: strictly required class==CKO_PUBLIC_KEY, refusing this;
# fixed via ENCODED_PUBLIC_KEY get_params + relaxed export_fn selection
# check, both in kem/mlkem.c), then proves the exported share is really
# usable: a simulated server encapsulates against it, and the client
# decapsulates with its private key directly, matching secrets. This is
# the exact sequence TLS's client role needs; the TLS handshake itself
# (tls.c group registration, landed) does not yet complete end-to-end —
# a separate, deeper bug in this provider's own TLS13-KDF implementation
# breaks secret derivation once the token genuinely participates. See the
# remediation plan's R5 entry for the full, evidence-based state.
t4kemexport() {
  local w; w=$(mk_arena mlkemexp "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768 -out "$w/k.pem" >/dev/null 2>&1
  O pkey -in "pkcs11:token=mlkemexp;type=private" -pubout -out "$w/pub_from_priv.pem" || return 1
  O pkeyutl -encap -pubin -inkey "$w/pub_from_priv.pem" -secret "$w/secret_server.bin" -out "$w/ct.bin" || return 1
  O pkeyutl -decap -inkey "pkcs11:token=mlkemexp;type=private" -in "$w/ct.bin" -secret "$w/secret_client.bin" || return 1
  [[ "$(stat -c%s "$w/secret_server.bin")" == "32" && "$(stat -c%s "$w/secret_client.bin")" == "32" ]] || { echo "wrong secret size"; return 1; }
  cmp -s "$w/secret_server.bin" "$w/secret_client.bin"
}
run_case T4kemexport PASS "ML-KEM public-share export from the private object (R5 prerequisite): server-encap/client-decap parity" t4kemexport

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

# X25519/X448 key exchange (gap ALG-5 / remediation R4). Deliberately
# token-to-token (two independent arenas), NOT T8's software-peer pattern:
# a montgomery token key deriving against a genuinely foreign
# (OPENSSL_CONF=/dev/null, default-provider-only) peer key hits a real,
# separate, narrower gap during OpenSSL's cross-provider peer VALIDATION
# step (EVP_PKEY_public_check -> a legacy EC_KEY-control translation path
# that assumes Weierstrass X/Y BIGNUM coordinates montgomery keys don't
# have) — confirmed live: T8's exact "-inkey pkcs11:...;type=private
# -peerkey <software-peer>.pem" shape works for EC but fails for X25519
# with "OSSL_PARAM_get_BN: param of incompatible type", even though the
# provider's own derive mechanism is fully correct (proven here). Left
# open, not silently dropped — see the remediation plan's R17 entry.
#
# genpkey's own exit code now GATES these arenas' keygen step (remediation
# R16 core: X25519/X448 previously had no URI-PEM encoder at all — same
# gap class ML-KEM had pre-R3 — so genpkey reported "Error writing
# key(s)" even though the key generated and persisted on-token fine as a
# side effect; that's why this used to swallow the exit code). Also
# asserts the URI label + no PRIVATE KEY block, same as T4x_encode.
t16() {
  local wa wb
  wa=$(mk_arena x25519a "$CPP_ENGINE_SO") || return 1
  wb=$(mk_arena x25519b "$CPP_ENGINE_SO") || return 1
  SOFTHSM2_CONF="$wa/softhsm2.conf" OPENSSL_CONF="$wa/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm X25519 -out "$wa/ka.pem" || return 1
  SOFTHSM2_CONF="$wb/softhsm2.conf" OPENSSL_CONF="$wb/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm X25519 -out "$wb/kb.pem" || return 1
  grep -q "PKCS#11 PROVIDER URI" "$wa/ka.pem" || { echo "no URI-PEM written"; return 1; }
  grep -q "PRIVATE KEY" "$wa/ka.pem" && { echo "raw private key material written — must never happen"; return 1; }
  SOFTHSM2_CONF="$wb/softhsm2.conf" OPENSSL_CONF="$wb/openssl.cnf" \
    O pkey -in "pkcs11:token=x25519b;type=public" -pubin -pubout -out "$wb/kbpub.pem" || return 1
  SOFTHSM2_CONF="$wa/softhsm2.conf" OPENSSL_CONF="$wa/openssl.cnf" \
    O pkeyutl -derive -inkey "pkcs11:token=x25519a;type=private" -peerkey "$wb/kbpub.pem" -out "$wa/secretA.bin" || return 1
  SOFTHSM2_CONF="$wa/softhsm2.conf" OPENSSL_CONF="$wa/openssl.cnf" \
    O pkey -in "pkcs11:token=x25519a;type=public" -pubin -pubout -out "$wa/kapub.pem" || return 1
  SOFTHSM2_CONF="$wb/softhsm2.conf" OPENSSL_CONF="$wb/openssl.cnf" \
    O pkeyutl -derive -inkey "pkcs11:token=x25519b;type=private" -peerkey "$wa/kapub.pem" -out "$wb/secretB.bin" || return 1
  [[ "$(stat -c%s "$wa/secretA.bin")" == "32" && "$(stat -c%s "$wb/secretB.bin")" == "32" ]] || { echo "wrong secret size"; return 1; }
  cmp -s "$wa/secretA.bin" "$wb/secretB.bin"
}
run_case T16 PASS "X25519 token-to-token derive parity, 32-byte secret (gap ALG-5 / remediation R4); genpkey URI-PEM encoder gated on exit code (remediation R16)" t16

t16b() {
  local wa wb
  wa=$(mk_arena x448a "$CPP_ENGINE_SO") || return 1
  wb=$(mk_arena x448b "$CPP_ENGINE_SO") || return 1
  SOFTHSM2_CONF="$wa/softhsm2.conf" OPENSSL_CONF="$wa/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm X448 -out "$wa/ka.pem" || return 1
  SOFTHSM2_CONF="$wb/softhsm2.conf" OPENSSL_CONF="$wb/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm X448 -out "$wb/kb.pem" || return 1
  grep -q "PKCS#11 PROVIDER URI" "$wa/ka.pem" || { echo "no URI-PEM written"; return 1; }
  grep -q "PRIVATE KEY" "$wa/ka.pem" && { echo "raw private key material written — must never happen"; return 1; }
  SOFTHSM2_CONF="$wb/softhsm2.conf" OPENSSL_CONF="$wb/openssl.cnf" \
    O pkey -in "pkcs11:token=x448b;type=public" -pubin -pubout -out "$wb/kbpub.pem" || return 1
  SOFTHSM2_CONF="$wa/softhsm2.conf" OPENSSL_CONF="$wa/openssl.cnf" \
    O pkeyutl -derive -inkey "pkcs11:token=x448a;type=private" -peerkey "$wb/kbpub.pem" -out "$wa/secretA.bin" || return 1
  SOFTHSM2_CONF="$wa/softhsm2.conf" OPENSSL_CONF="$wa/openssl.cnf" \
    O pkey -in "pkcs11:token=x448a;type=public" -pubin -pubout -out "$wa/kapub.pem" || return 1
  SOFTHSM2_CONF="$wb/softhsm2.conf" OPENSSL_CONF="$wb/openssl.cnf" \
    O pkeyutl -derive -inkey "pkcs11:token=x448b;type=private" -peerkey "$wa/kapub.pem" -out "$wb/secretB.bin" || return 1
  [[ "$(stat -c%s "$wa/secretA.bin")" == "56" && "$(stat -c%s "$wb/secretB.bin")" == "56" ]] || { echo "wrong secret size"; return 1; }
  cmp -s "$wa/secretA.bin" "$wb/secretB.bin"
}
run_case T16b PASS "X448 token-to-token derive parity, 56-byte secret (gap ALG-5 / remediation R4); genpkey URI-PEM encoder gated on exit code (remediation R16)" t16b

# R17 (montgomery software-peer interop, investigate-first in the phase-3
# plan): T16/T16b are deliberately token-to-token, not software-peer,
# because the plan recorded a real, separately-observed failure deriving
# a montgomery token key against a genuinely foreign (default-provider-
# only) peer key — OSSL_PARAM_get_BN "param of incompatible type" from a
# legacy EC_KEY-control path assuming Weierstrass X/Y coordinates. Traced
# live before writing this case: that failure does NOT reproduce, in
# either curve or either direction, checked at two points — the current
# tree (with R16's montgomery URI-PEM encoder in place) and a working
# copy reverted to the R15-only baseline (R16's encoder code fully
# absent). Since it doesn't reproduce even without R16's changes, R16
# isn't what fixed it; most plausibly R4 (this provider's original
# X25519/X448 keyexch work, landed before this session) already closed
# it as a side effect and the plan's own written finding simply predates
# that landing. No code change was needed for R17 — this case exists so
# that fact is a permanent, checked assertion instead of a one-off CLI
# transcript, per this project's own "proof means a harness case, not a
# transcript" standard.
r17_case() { # $1 = X25519|X448, $2 = expected secret size
  local alg="$1" size="$2" w
  w=$(mk_arena "r17${alg}" "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm "$alg" -out "$w/tok.pem" || return 1
  OPENSSL_CONF=/dev/null O genpkey -algorithm "$alg" -out "$w/sw.pem" || return 1
  OPENSSL_CONF=/dev/null O pkey -in "$w/sw.pem" -pubout -out "$w/sw_pub.pem" || return 1
  O pkey -in "pkcs11:token=r17${alg};type=public" -pubin -pubout -out "$w/tok_pub.pem" || return 1
  # token derives against the software peer
  O pkeyutl -derive -inkey "pkcs11:token=r17${alg};type=private" \
    -peerkey "$w/sw_pub.pem" -out "$w/secret_tok.bin" || return 1
  # the reverse pairing: software derives against the token's public key
  OPENSSL_CONF=/dev/null O pkeyutl -derive -inkey "$w/sw.pem" \
    -peerkey "$w/tok_pub.pem" -out "$w/secret_sw.bin" || return 1
  [[ "$(stat -c%s "$w/secret_tok.bin")" == "$size" && "$(stat -c%s "$w/secret_sw.bin")" == "$size" ]] \
    || { echo "wrong secret size"; return 1; }
  cmp -s "$w/secret_tok.bin" "$w/secret_sw.bin"
}
r17() { r17_case X25519 32; }
run_case T17 PASS "X25519 token<->software-peer derive interop, both directions, 32-byte secret (remediation R17 — investigated, does not reproduce, no code change needed)" r17
r17b() { r17_case X448 56; }
run_case T17b PASS "X448 token<->software-peer derive interop, both directions, 56-byte secret (remediation R17 — investigated, does not reproduce, no code change needed)" r17b

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
run_case T11 PASS "URI-PEM round-trip for ML-DSA (gap OP-2 / remediation R2)" t11

# R2, SLH-DSA variant: same decoder chain, one representative parameter set
# (the other 11 share the identical code path — all 12 were registered
# together in this remediation).
t11slh() { local w; w=$(mk_arena uripemslh "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHA2-128s -out "$w/k.pem" || return 1
  grep -q "PKCS#11 PROVIDER URI" "$w/k.pem" || { echo "no URI-PEM written"; return 1; }
  O pkeyutl -sign -inkey "$w/k.pem" -rawin -in "$MSG" -out "$w/sig.bin" || return 1
  [[ "$(stat -c%s "$w/sig.bin")" == "7856" ]] || { echo "sig size $(stat -c%s "$w/sig.bin") != 7856"; return 1; }
}
run_case T11slh PASS "URI-PEM round-trip for SLH-DSA-SHA2-128s (gap OP-2 / remediation R2)" t11slh

# R2, ML-KEM variant: proves the decoder+load chain, not encapsulate-from-
# private-object reachability — that needs a SEPARATE, still-open fix
# (ML-KEM's export function requires a public-class object and does not
# walk private->associated-public the way ML-DSA's does; confirmed live:
# `pkey -pubout` and `pkeyutl -encap` both fail on a URI-PEM-loaded ML-KEM
# private object with "attribute does not exist: 0x633" (CKA_ENCAPSULATE),
# tracked under remediation R5's prerequisites). Decapsulate needs none of
# that — it only reads the loaded private key's OWN attributes — so it is
# the correct, honest proof that the decoder itself resolved a real,
# usable private-key object from the URI-PEM file.
t11kem() { local w; w=$(mk_arena uripemkem "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768 -out "$w/k.pem" || return 1
  grep -q "PKCS#11 PROVIDER URI" "$w/k.pem" || { echo "no URI-PEM written"; return 1; }
  O pkeyutl -encap -inkey "pkcs11:token=uripemkem;type=public" -secret "$w/secret_ref.bin" -out "$w/ct.bin" || return 1
  O pkeyutl -decap -inkey "$w/k.pem" -in "$w/ct.bin" -secret "$w/secret_dec.bin" || return 1
  [[ "$(stat -c%s "$w/secret_ref.bin")" == "32" && "$(stat -c%s "$w/secret_dec.bin")" == "32" ]] || { echo "secret size wrong"; return 1; }
  cmp -s "$w/secret_ref.bin" "$w/secret_dec.bin"
}
run_case T11kem PASS "URI-PEM round-trip for ML-KEM-768: decoder-loaded private key decapsulates correctly (gap OP-2 / remediation R2)" t11kem

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
run_case T12 PASS "SLH-DSA keygen/store/encode reachable through provider, all 12 param sets (gap ALG-1 / remediation R1)" t12

# R1 remainder, ROOT-CAUSED AND FIXED (2026-08-25, follow-up pass): the
# signature dispatch tables registered GETTABLE_CTX_PARAMS without its
# mandatory pair GET_CTX_PARAMS, violating provider-signature(7)'s
# documented consistency contract ("if one of them is provided then the
# other one must also be provided"). OpenSSL 3.6's own
# evp_signature_from_algorithm() (crypto/evp/signature.c) enforces this at
# fetch time — an unpaired count raises EVP_R_INVALID_PROVIDER_FUNCTIONS
# and returns NULL, so the whole method silently fails to construct. That
# is why every provider-side probe last session showed nothing wrong: our
# sign_init code was never reached, rejected one layer above it. Fixed by
# implementing get_ctx_params (OSSL_SIGNATURE_PARAM_ALGORITHM_ID, one DER
# AlgorithmIdentifier per parameter set, OIDs 2.16.840.1.101.3.4.3.20-31
# live-confirmed via `openssl list-signature-algorithms`) — deliberately
# dispatched on the key's own CKA_PARAMETER_SET, NOT key size the way
# mldsa.c's version does: SLH-DSA's SHA2 and SHAKE variants at the same
# security level share identical key sizes (e.g. SHA2-128s and
# SHAKE-128s are both 32-byte public keys), so size alone can't tell them
# apart. T12sign flipped XPASS the moment the fix landed (ratchet doing
# its job); now a real, thorough case: SHA2-128s full round trip with
# exact FIPS 205 signature size + tamper rejection, plus an independent
# SHAKE-128f cross-check (different hash family) in ITS OWN arena — a
# manual verification during the fix reused one arena across two
# algorithms and silently re-signed with the stale first key, exactly
# the URI-ambiguity trap this harness's own mk_arena comment already
# warns about.
t12sign() { local w; w=$(mk_arena slhsign "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHA2-128s -out "$w/k.pem" || return 1
  O pkeyutl -sign -inkey "pkcs11:token=slhsign;type=private" -rawin -in "$MSG" -out "$w/sig.bin" || return 1
  [[ "$(stat -c%s "$w/sig.bin")" == "7856" ]] || { echo "sig size $(stat -c%s "$w/sig.bin") != 7856"; return 1; }
  O pkey -in "pkcs11:token=slhsign;type=public" -pubin -pubout -out "$w/pub.pem" || return 1
  O pkeyutl -verify -pubin -inkey "$w/pub.pem" -rawin -in "$MSG" -sigfile "$w/sig.bin" || return 1
  cp "$w/sig.bin" "$w/tampered.bin"
  printf '\x00' | dd of="$w/tampered.bin" bs=1 seek=50 count=1 conv=notrunc 2>/dev/null
  cmp -s "$w/sig.bin" "$w/tampered.bin" && printf '\xff' | dd of="$w/tampered.bin" bs=1 seek=50 count=1 conv=notrunc 2>/dev/null
  if O pkeyutl -verify -pubin -inkey "$w/pub.pem" -rawin -in "$MSG" -sigfile "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered SLH-DSA signature VERIFIED — verifier cannot say no"; return 1; else return 0; fi
}
run_case T12sign PASS "SLH-DSA-SHA2-128s token sign -> software verify (size 7856) + tamper rejection (gap ALG-1 remainder / remediation R1)" t12sign

t12sign_shake() { local w; w=$(mk_arena slhshake "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHAKE-128f -out "$w/k.pem" || return 1
  O pkeyutl -sign -inkey "pkcs11:token=slhshake;type=private" -rawin -in "$MSG" -out "$w/sig.bin" || return 1
  [[ "$(stat -c%s "$w/sig.bin")" == "17088" ]] || { echo "sig size $(stat -c%s "$w/sig.bin") != 17088"; return 1; }
  O pkey -in "pkcs11:token=slhshake;type=public" -pubin -pubout -out "$w/pub.pem" || return 1
  O pkeyutl -verify -pubin -inkey "$w/pub.pem" -rawin -in "$MSG" -sigfile "$w/sig.bin"
}
run_case T12sign_shake PASS "SLH-DSA-SHAKE-128f token sign -> software verify (size 17088, independent hash family) (gap ALG-1 remainder / remediation R1)" t12sign_shake

t14() { local w; w=$(mk_arena cms "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$w/k.pem" || return 1
  O req -new -x509 -key "pkcs11:token=cms;type=private" -subj "/CN=provider-harness" -days 2 -out "$w/cert.pem" || return 1
  O cms -sign -in "$MSG" -signer "$w/cert.pem" -inkey "pkcs11:token=cms;type=private" -out "$w/signed.cms" -outform PEM -nodetach || return 1
  O cms -verify -in "$w/signed.cms" -inform PEM -CAfile "$w/cert.pem" -out /dev/null
}
run_case T14 PASS "CMS sign via token RSA key -> software cms -verify" t14

# t13 — real TLS 1.3 handshake negotiating MLKEM768, token performing both
# the client-side KEM ops AND the TLS13-KDF byte derives (gap F36-1,
# remediation R5 phase 1 + R12's CKM_HKDF_DATA fix). Needs its own arena
# (not mk_arena) because it requires log.level=DEBUG, not mk_arena's
# hardcoded ERROR, to get engine-log evidence of token participation.
#
# R13 discipline (silent-software-fallback false-pass hazard, confirmed
# live during R12): a green handshake proves nothing on its own — without
# -propquery pinning fetches to pkcs11, the identical command succeeds
# using the DEFAULT provider's own software ML-KEM, zero token objects
# touched. Every positive TLS case therefore ships with its negative-
# control twin: same arena, same command, propquery removed — must still
# succeed (the hazard is real) but with zero token decrypt activity in the
# engine log (proving the positive case's log evidence isn't background
# noise from arena setup).
t13() {
  local w="$ROOT_WORK/t13"
  mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-encode-provider-uri-to-pem = true
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label t13 --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  OPENSSL_CONF=/dev/null "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -keyout "$w/server.key" \
    -out "$w/server.crt" -days 1 -subj "/CN=t13" >/dev/null 2>&1 || return 1

  # ── Positive: propquery pinned, token must do the work ──
  local port=14713
  OPENSSL_CONF=/dev/null "$OPENSSL_BIN" s_server -cert "$w/server.crt" -key "$w/server.key" \
    -accept "$port" -naccept 1 -tls1_3 -groups MLKEM768 -quiet >"$w/server.log" 2>&1 &
  local spid=$!
  sleep 1.5
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" timeout 10 "$OPENSSL_BIN" \
    s_client -connect "127.0.0.1:$port" -tls1_3 -groups MLKEM768 -propquery "?provider=pkcs11" \
    </dev/null >"$w/client.log" 2>"$w/client.err.log"
  wait "$spid" 2>/dev/null

  grep -q "Negotiated TLS1.3 group: MLKEM768" "$w/client.log" || return 1
  grep -q "Cipher is TLS_" "$w/client.log" || return 1
  # Engine-log evidence, not exit code: the token decrypting its own
  # at-rest attributes is the arbiter that it — not the default provider —
  # performed the KEM decapsulation and the TLS13-KDF derives.
  grep -qE "Decrypting [0-9]+ bytes into buffer of [0-9]+ bytes" "$w/client.err.log" || return 1

  # ── Negative control (R13): same arena, propquery removed ──
  local port2=14714
  OPENSSL_CONF=/dev/null "$OPENSSL_BIN" s_server -cert "$w/server.crt" -key "$w/server.key" \
    -accept "$port2" -naccept 1 -tls1_3 -groups MLKEM768 -quiet >"$w/server2.log" 2>&1 &
  local spid2=$!
  sleep 1.5
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" timeout 10 "$OPENSSL_BIN" \
    s_client -connect "127.0.0.1:$port2" -tls1_3 -groups MLKEM768 </dev/null \
    >"$w/client2.log" 2>"$w/client2.err.log"
  wait "$spid2" 2>/dev/null

  grep -q "Negotiated TLS1.3 group: MLKEM768" "$w/client2.log" || return 1
  # The hazard confirmed: it still negotiates MLKEM768 — but must show ZERO
  # token decrypt activity, or the positive case above proves nothing.
  if grep -qE "Decrypting [0-9]+ bytes into buffer of [0-9]+ bytes" "$w/client2.err.log"; then
    return 1
  fi
  return 0
}
run_case T13 PASS "TLS 1.3 handshake negotiates MLKEM768, token performs KEM ops + TLS13-KDF derives, engine-log verified (gap F36-1 / remediation R5+R12); negative-control twin proves it (R13)" t13

# t15 — real TLS 1.3 handshake with a FULLY token-backed SERVER (remediation
# R15): unlike T13 (token only on the client/decapsulate side, server cert
# is plain software RSA), here the server's own certificate key is a
# token-resident ML-DSA-65 key (CertificateVerify signs on the token) AND
# -propquery pins the server's ephemeral ML-KEM group keygen/encapsulate to
# the token too — both halves of "fully token-backed", not a minimal
# encap-only proof. Needs its own arena for the same log.level=DEBUG reason
# as T13.
#
# Neither operation has a dedicated success-path engine log line (checked
# live: SoftHSM_kem.cpp only logs on error, and there is no sign-success
# log at all) — so, same standard T13 already set, this asserts two
# independently attributable proxies instead of a direct log line:
#   - sign: "Peer signature type: mldsa65" + "Verify return code: 0 (ok)"
#     on the client is cryptographic proof the token's private key signed
#     CertificateVerify — that key was generated via
#     `genpkey -propquery "?provider=pkcs11"` and, per this project's own
#     no-fake-copy design, never leaves the token, so a valid client-side
#     verify has no other possible source.
#   - encapsulate: the SAME "Decrypting N bytes into buffer of M bytes"
#     TLS13-KDF marker T13 uses, but read from server.err.log (R15 is the
#     server's own KDF chain, not the client's) — those derives only run
#     against a token object in the first place if the ML-KEM shared
#     secret they're derived from was itself a token object, i.e. if the
#     token performed the encapsulation.
# A regression in either op breaks a different one of these two
# assertions, keeping them attributable per-op as the plan requires.
#
# R13 discipline applies here too, and the hazard is DIFFERENT from T13's:
# the cert key's own pkcs11: URI identity forces ML-DSA signing onto the
# token regardless of propquery, so the negative control still shows a
# valid mldsa65 signature — propquery only controls whether the *KEM*
# side (no fixed provider identity of its own; a fresh ephemeral keygen
# each handshake) lands on the token or silently falls back to the
# default provider's own software ML-KEM. The negative control's real
# job is proving THAT specific fallback, via the same zero-KDF-decrypt
# check T13 uses.
t15() {
  local w="$ROOT_WORK/t15"
  mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-encode-provider-uri-to-pem = true
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label t15 --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" "$OPENSSL_BIN" genpkey \
    -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" >/dev/null 2>&1 || return 1
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" "$OPENSSL_BIN" req -new -x509 \
    -key "pkcs11:token=t15;type=private" -subj "/CN=t15" -days 1 -out "$w/cert.pem" >/dev/null 2>&1 \
    || return 1

  # ── Positive: propquery pinned, token must sign AND encapsulate ──
  local port=14715
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" "$OPENSSL_BIN" s_server \
    -accept "$port" -cert "$w/cert.pem" -key "$w/k.pem" -groups MLKEM768 -tls1_3 -no_ticket \
    -naccept 1 -quiet -propquery "?provider=pkcs11" >"$w/server.log" 2>"$w/server.err.log" &
  local spid=$!
  sleep 1.5
  OPENSSL_CONF=/dev/null timeout 10 "$OPENSSL_BIN" \
    s_client -connect "127.0.0.1:$port" -tls1_3 -groups MLKEM768 -CAfile "$w/cert.pem" \
    </dev/null >"$w/client.log" 2>"$w/client.err.log"
  wait "$spid" 2>/dev/null

  grep -q "Negotiated TLS1.3 group: MLKEM768" "$w/client.log" || return 1
  grep -q "Cipher is TLS_" "$w/client.log" || return 1
  grep -q "Peer signature type: mldsa65" "$w/client.log" || return 1
  grep -q "Verify return code: 0 (ok)" "$w/client.log" || return 1
  # NOT the generic "Decrypting N bytes" regex T13 uses: on the server
  # role, that also fires (in BOTH cases below) for the cert's own
  # ML-DSA-65 private key being unwrapped from at-rest storage to sign
  # with — a propquery-independent operation the cert key's own pkcs11:
  # URI identity forces regardless, so it can't distinguish the KEM/KDF
  # question T15 actually cares about. Empirically distinguishing size
  # (checked live against both arms below): the later key-schedule
  # derives that only touch the token when the shared secret feeding them
  # is ITSELF a token object show as "64 bytes into buffer of 80" — 74
  # occurrences with propquery pinned, 0 without.
  grep -q "Decrypting 64 bytes into buffer of 80 bytes" "$w/server.err.log" || return 1

  # ── Negative control (R13): same arena, propquery removed ──
  local port2=14716
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" "$OPENSSL_BIN" s_server \
    -accept "$port2" -cert "$w/cert.pem" -key "$w/k.pem" -groups MLKEM768 -tls1_3 -no_ticket \
    -naccept 1 -quiet >"$w/server2.log" 2>"$w/server2.err.log" &
  local spid2=$!
  sleep 1.5
  OPENSSL_CONF=/dev/null timeout 10 "$OPENSSL_BIN" \
    s_client -connect "127.0.0.1:$port2" -tls1_3 -groups MLKEM768 -CAfile "$w/cert.pem" \
    </dev/null >"$w/client2.log" 2>"$w/client2.err.log"
  wait "$spid2" 2>/dev/null

  grep -q "Negotiated TLS1.3 group: MLKEM768" "$w/client2.log" || return 1
  grep -q "Peer signature type: mldsa65" "$w/client2.log" || return 1
  grep -q "Verify return code: 0 (ok)" "$w/client2.log" || return 1
  # The hazard confirmed: the cert key's own URI identity still forces a
  # valid token signature (and, with it, some propquery-independent key-
  # unwrap decrypt noise — see the comment on the positive case above) —
  # but the KEM/KDF-specific "64 into 80" marker must be ZERO, or the
  # positive case's evidence above proves nothing.
  if grep -q "Decrypting 64 bytes into buffer of 80 bytes" "$w/server2.err.log"; then
    return 1
  fi
  return 0
}
run_case T15 PASS "TLS 1.3 handshake with a fully token-backed server: token-resident ML-DSA cert signs CertificateVerify AND token performs the ML-KEM encapsulation, both independently engine-log verified (remediation R15); negative-control twin proves the KEM half (R13)" t15

# t18/t18b — real TLS 1.3 handshake with a token-backed SERVER negotiating a
# classic ECDHE-style montgomery group (remediation R18, found while
# investigating whether EC/ECDH had R15's same latent server-role gap —
# they didn't; X25519/X448 did, but for THREE different, independent
# reasons, not the one hypothesized). Plain software RSA cert, same shape
# as T13 (not T15's token-resident cert): unlike ML-KEM's pure-KEM
# asymmetry, an ECDHE-style group needs BOTH sides to generate a REAL
# ephemeral keypair, so there's no cert-signing noise to route around and
# T13's own generic "Decrypting N bytes" marker is precise here.
#
# Three independent, live-traced bugs, all in code paths ML-KEM's own
# server-role fix (R15) never touched, none of them the SET_PARAMS gap
# R18 was originally scoped to investigate (that WAS also missing here —
# see fix 3 — but it was the last of three, not the only one):
#   1. p11prov_montgomery_gen_init_int had no `else` branch setting the
#      CK_UNAVAILABLE_INFORMATION sentinel when the requested selection is
#      domain/other-parameters-only (TLS's own placeholder-object pattern,
#      selection=0x84, live-confirmed) — unlike p11prov_ec_gen_init's own
#      else branch. The struct's zero-initialized mechanism (0x0) leaked
#      through instead, so p11prov_ec_gen's mock-object check (which
#      compares against the REAL sentinel, not 0) never matched, and the
#      real-keygen path ran with mechanism 0 against a montgomery-shaped
#      template — the engine correctly rejected it as "conflicting
#      attributes" (keymgmt.c:1388, live-traced).
#   2. p11prov_montgomery_get_params/gettable_params never exposed
#      OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY — the param TLS reads via
#      EVP_PKEY_get1_encoded_public_key to hand its own generated public
#      share back for the server's key_share response. Live-traced:
#      tls_construct_stoc_key_share failed parsing uninitialized OSSL_PARAM
#      data as ASN.1 DER ("header too long"/"bad object header").
#   3. The gap this item was scoped to check: montgomery's keymgmt
#      registered no SET_PARAMS/SETTABLE_PARAMS at all (a real, prior
#      comment in this file said as much and reasoned it wasn't worth
#      adding — reasoning that held for ML-DSA and Ed's own no-op stubs,
#      but missed that EC's own set_params is real working code directly
#      reusable here), so installing the CLIENT's public share into the
#      server's own placeholder object had no code path at all —
#      ssl_derive failed the same ASN.1-parsing way as fix 2, for the
#      peer's share instead of the server's own.
# Fixed 1+2 in keymgmt.c; fix 3 reuses p11prov_ec_set_params/
# settable_params directly (same translation unit) plus one missing
# CKK_EC_MONTGOMERY case in objects.c's
# p11prov_obj_set_ec_encoded_public_key (the function fix 3's reused
# set_params calls into — CKA_EC_POINT is always a DER-wrapped OCTET
# STRING regardless of curve family, so no montgomery-specific encoding
# was needed there, only the missing case label).
r18_case() { # $1 = X25519|X448
  local grp="$1" w
  w="$ROOT_WORK/r18${grp}"
  mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-encode-provider-uri-to-pem = true
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label "r18${grp}" --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  OPENSSL_CONF=/dev/null "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -keyout "$w/server.key" \
    -out "$w/server.crt" -days 1 -subj "/CN=r18${grp}" >/dev/null 2>&1 || return 1

  # ── Positive: propquery pinned, token must generate + derive ──
  local port=$((14717 + RANDOM % 1000))
  OPENSSL_CONF=/dev/null "$OPENSSL_BIN" s_server -cert "$w/server.crt" -key "$w/server.key" \
    -accept "$port" -naccept 1 -tls1_3 -groups "$grp" -quiet >"$w/server.log" 2>&1 &
  local spid=$!
  sleep 1.5
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" timeout 10 "$OPENSSL_BIN" \
    s_client -connect "127.0.0.1:$port" -tls1_3 -groups "$grp" -propquery "?provider=pkcs11" \
    </dev/null >"$w/client.log" 2>"$w/client.err.log"
  wait "$spid" 2>/dev/null

  grep -q "Cipher is TLS_" "$w/client.log" || return 1
  grep -qE "Decrypting [0-9]+ bytes into buffer of [0-9]+ bytes" "$w/client.err.log" || return 1

  # ── Negative control (R13): same arena, propquery removed ──
  local port2=$((14718 + RANDOM % 1000))
  OPENSSL_CONF=/dev/null "$OPENSSL_BIN" s_server -cert "$w/server.crt" -key "$w/server.key" \
    -accept "$port2" -naccept 1 -tls1_3 -groups "$grp" -quiet >"$w/server2.log" 2>&1 &
  local spid2=$!
  sleep 1.5
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" timeout 10 "$OPENSSL_BIN" \
    s_client -connect "127.0.0.1:$port2" -tls1_3 -groups "$grp" </dev/null \
    >"$w/client2.log" 2>"$w/client2.err.log"
  wait "$spid2" 2>/dev/null

  grep -q "Cipher is TLS_" "$w/client2.log" || return 1
  if grep -qE "Decrypting [0-9]+ bytes into buffer of [0-9]+ bytes" "$w/client2.err.log"; then
    return 1
  fi
  return 0
}
r18() { r18_case X25519; }
run_case T18 PASS "TLS 1.3 handshake with a token-backed server negotiating X25519 (ECDHE-style, not KEM): server generates its own ephemeral keypair AND installs the peer's share on-token, engine-log verified (remediation R18); negative-control twin (R13)" r18
r18b() { r18_case X448; }
run_case T18b PASS "TLS 1.3 handshake with a token-backed server negotiating X448 (ECDHE-style, not KEM): server generates its own ephemeral keypair AND installs the peer's share on-token, engine-log verified (remediation R18); negative-control twin (R13)" r18b

# t18c/t18d — the SERVER-role mirror of t18/t18b (server token-backed,
# client plain software — T15's own shape, not T13's). Necessary, not
# redundant: sabotage-tested live before writing this — reverting R18
# fix #1 (gen_init's else branch, which sets the CK_UNAVAILABLE_
# INFORMATION sentinel for a domain/other-parameters-only selection) does
# NOT make t18/t18b fail, because a token-backed CLIENT never calls
# gen_init with anything but a full OSSL_KEYMGMT_SELECT_KEYPAIR selection
# for its own key (it generates immediately, no placeholder phase) — only
# the SERVER's own key generation goes through the params-only-first
# pattern that else branch exists for. t18/t18b alone would let a
# regression in that specific branch ship silently.
r18_server_case() { # $1 = X25519|X448
  local grp="$1" w
  w="$ROOT_WORK/r18srv${grp}"
  mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-encode-provider-uri-to-pem = true
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label "r18s${grp}" --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  OPENSSL_CONF=/dev/null "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -keyout "$w/server.key" \
    -out "$w/server.crt" -days 1 -subj "/CN=r18s${grp}" >/dev/null 2>&1 || return 1

  # ── Positive: propquery pinned on the SERVER, token must generate + derive ──
  local port=$((14719 + RANDOM % 1000))
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" "$OPENSSL_BIN" s_server \
    -cert "$w/server.crt" -key "$w/server.key" -accept "$port" -naccept 1 -tls1_3 \
    -groups "$grp" -quiet -propquery "?provider=pkcs11" >"$w/server.log" 2>"$w/server.err.log" &
  local spid=$!
  sleep 1.5
  OPENSSL_CONF=/dev/null timeout 10 "$OPENSSL_BIN" \
    s_client -connect "127.0.0.1:$port" -tls1_3 -groups "$grp" </dev/null \
    >"$w/client.log" 2>"$w/client.err.log"
  wait "$spid" 2>/dev/null

  grep -q "Cipher is TLS_" "$w/client.log" || return 1
  grep -qE "Decrypting [0-9]+ bytes into buffer of [0-9]+ bytes" "$w/server.err.log" || return 1

  # ── Negative control (R13): same arena, propquery removed ──
  local port2=$((14720 + RANDOM % 1000))
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" "$OPENSSL_BIN" s_server \
    -cert "$w/server.crt" -key "$w/server.key" -accept "$port2" -naccept 1 -tls1_3 \
    -groups "$grp" -quiet >"$w/server2.log" 2>"$w/server2.err.log" &
  local spid2=$!
  sleep 1.5
  OPENSSL_CONF=/dev/null timeout 10 "$OPENSSL_BIN" \
    s_client -connect "127.0.0.1:$port2" -tls1_3 -groups "$grp" </dev/null \
    >"$w/client2.log" 2>"$w/client2.err.log"
  wait "$spid2" 2>/dev/null

  grep -q "Cipher is TLS_" "$w/client2.log" || return 1
  if grep -qE "Decrypting [0-9]+ bytes into buffer of [0-9]+ bytes" "$w/server2.err.log"; then
    return 1
  fi
  return 0
}
r18c() { r18_server_case X25519; }
run_case T18c PASS "TLS 1.3 handshake, token-backed SERVER negotiating X25519 (server-role mirror of T18 — exercises gen_init's params-only placeholder path T18's client-role structure cannot reach), engine-log verified (remediation R18); negative-control twin (R13)" r18c
r18d() { r18_server_case X448; }
run_case T18d PASS "TLS 1.3 handshake, token-backed SERVER negotiating X448 (server-role mirror of T18b), engine-log verified (remediation R18); negative-control twin (R13)" r18d

# t20/t20b/t20c/t20d — token HMAC (remediation R8, phase-4 plan): bytes-in
# mode only (OSSL_MAC_PARAM_KEY -> ephemeral session secret key object ->
# C_SignInit/Update/Final), no SKEYMGMT dependency, per the plan's own C5
# scoping. Registered as a single generic "HMAC" algorithm (matching the
# default provider's own naming — confirmed live via
# `openssl list -mac-algorithms -provider default`, one bare "HMAC" name,
# not one per digest) with the digest chosen at runtime via
# OSSL_MAC_PARAM_DIGEST, exactly like `openssl mac -digest SHA256 HMAC`
# already does against the default provider. A first attempt registered
# one pre-bound name per digest (HMAC-SHA2-256 etc.) — real, spec-correct
# algorithm identities, but unreachable by the exact CLI form this proof
# uses; caught live, not by a wrong value (HMAC output is deterministic,
# so a silent default-provider fallback produces byte-identical output —
# only the engine log tells the two apart, matching R13's own founding
# lesson applied to a brand new operation type for the first time).
# Own arena (not mk_arena), same reason as T13/T15/T18: mk_arena hardcodes
# log.level=ERROR, which suppresses the "Created new object" DEBUG-level
# line this case's engine-log evidence needs — reproduced live, not
# assumed, the same mistake T13/T15's own comments already flagged for
# anyone tempted to reach for mk_arena's convenience here. Minimum key
# sizes are a real, deliberate engine constraint (FIPS 198-1: key length
# >= digest length — SoftHSM_slots.cpp declares ulMinKeySize per
# mechanism accordingly), not a provider bug — the 64-byte key below
# satisfies all four variants' minimums at once.
t20_case() { # $1 = SHA1|SHA256|SHA384|SHA512
  local dig="$1" w
  w="$ROOT_WORK/r8${dig}"
  mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-load-behavior = early
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label "r8${dig}" --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1

  local key="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
  echo "hmac harness message" > "$w/msg.txt"

  # ── Positive: propquery pinned, token must do the work ──
  local tokout swout
  tokout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -propquery "?provider=pkcs11" -macopt "key:$key" \
    -digest "$dig" -in "$w/msg.txt" HMAC 2>"$w/tok.err.log") || return 1
  swout=$(OPENSSL_CONF=/dev/null O mac -macopt "key:$key" \
    -digest "$dig" -in "$w/msg.txt" HMAC 2>/dev/null) || return 1
  [[ -n "$tokout" && "$tokout" == "$swout" ]] || return 1
  # Engine-log evidence, not exit code or output value: the token creating
  # the ephemeral session secret key object is the arbiter that it — not
  # the default provider — computed the HMAC.
  grep -q "Created new object" "$w/tok.err.log" || return 1

  # ── Negative control (R13): same arena, propquery removed ──
  local ctrlout
  ctrlout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -macopt "key:$key" -digest "$dig" -in "$w/msg.txt" HMAC \
    2>"$w/ctrl.err.log") || return 1
  [[ "$ctrlout" == "$swout" ]] || return 1
  # The hazard confirmed: output is still correct — but must show ZERO
  # token object-creation activity, or the positive case proves nothing.
  if grep -q "Created new object" "$w/ctrl.err.log"; then
    return 1
  fi
  return 0
}
t20() { t20_case SHA1; }
run_case T20 PASS "token HMAC-SHA1 via generic 'HMAC' algorithm (OSSL_MAC_PARAM_DIGEST-selected, matching the default provider's own naming) == software HMAC, engine-log verified (remediation R8); negative-control twin (R13)" t20
t20b() { t20_case SHA256; }
run_case T20b PASS "token HMAC-SHA256 == software HMAC, engine-log verified (remediation R8); negative-control twin (R13)" t20b
t20c() { t20_case SHA384; }
run_case T20c PASS "token HMAC-SHA384 == software HMAC, engine-log verified (remediation R8); negative-control twin (R13)" t20c
t20d() { t20_case SHA512; }
run_case T20d PASS "token HMAC-SHA512 == software HMAC, engine-log verified (remediation R8); negative-control twin (R13)" t20d

# ─── T26: CMAC + KMAC-128/256 as EVP_MAC, + INIT_SKEY (remediation R23) ─────
# CMAC is C++-only (confirmed live by reading rust/src/crypto/handlers.rs's
# own sign dispatch: CKM_AES_CMAC appears only inside its KBKDF-PRF
# selection code, never as a standalone C_SignInit case — matching the
# audit's own ALG-8 row) so t26_cmac only runs against the C++ arm; KMAC
# dispatches on both (handlers.rs:1461/1468), so t26_kmac takes the engine
# .so as a parameter.
t26_cmac() {
  local w; w="$ROOT_WORK/r23cmac"; mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-load-behavior = early
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label r23cmac --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1

  local key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  echo "cmac harness message" > "$w/msg.txt"

  local tokout swout
  tokout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -propquery "?provider=pkcs11" -macopt "hexkey:$key" -cipher AES-256-CBC \
    -in "$w/msg.txt" CMAC 2>"$w/tok.err.log") || return 1
  swout=$(OPENSSL_CONF=/dev/null O mac -macopt "hexkey:$key" -cipher AES-256-CBC \
    -in "$w/msg.txt" CMAC 2>/dev/null) || return 1
  [[ -n "$tokout" && "$tokout" == "$swout" ]] || return 1
  grep -q "Created new object" "$w/tok.err.log" || return 1

  local ctrlout
  ctrlout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -macopt "hexkey:$key" -cipher AES-256-CBC -in "$w/msg.txt" CMAC \
    2>"$w/ctrl.err.log") || return 1
  [[ "$ctrlout" == "$swout" ]] || return 1
  grep -q "Created new object" "$w/ctrl.err.log" && return 1

  # Sabotage: a different (but still valid, 32-byte) key must NOT
  # produce the same CMAC.
  local sabkey; sabkey=$(printf 'ff%.0s' {1..32})
  local sabout
  sabout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -propquery "?provider=pkcs11" -macopt "hexkey:$sabkey" \
    -cipher AES-256-CBC -in "$w/msg.txt" CMAC 2>/dev/null) || return 1
  [[ "$sabout" != "$tokout" ]] || { echo "sabotage: different key produced the SAME CMAC"; return 1; }

  # Rejection: a non-CBC AES cipher name is never honorable (the engine
  # always derives its actual cipher from the key's own byte length).
  if SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -propquery "?provider=pkcs11" -macopt "hexkey:$key" \
    -cipher AES-256-GCM -in "$w/msg.txt" CMAC >/dev/null 2>&1
  then echo "non-CBC cipher was accepted (should be rejected)"; return 1; fi

  return 0
}
run_case T26 PASS "token CMAC-AES-256 == software CMAC, engine-log verified, sabotage + non-CBC-cipher rejection (remediation R23); negative-control twin (R13)" t26_cmac

t26_kmac() { # $1=engine.so $2=KMAC-128|KMAC-256 $3=label-suffix
  local engine="$1" algo="$2" suffix="$3" w
  w="$ROOT_WORK/r23kmac${suffix}"; mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-load-behavior = early
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$engine" \
    --init-token --free --label "r23k${suffix}" --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1

  local key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  echo "kmac harness message" > "$w/msg.txt"

  local tokout swout
  tokout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -propquery "?provider=pkcs11" -macopt "hexkey:$key" -in "$w/msg.txt" \
    "$algo" 2>"$w/tok.err.log") || return 1
  swout=$(OPENSSL_CONF=/dev/null O mac -macopt "hexkey:$key" -in "$w/msg.txt" \
    "$algo" 2>/dev/null) || return 1
  [[ -n "$tokout" && "$tokout" == "$swout" ]] || return 1
  grep -q "Created new object" "$w/tok.err.log" || return 1

  local ctrlout
  ctrlout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -macopt "hexkey:$key" -in "$w/msg.txt" "$algo" 2>"$w/ctrl.err.log") || return 1
  [[ "$ctrlout" == "$swout" ]] || return 1
  grep -q "Created new object" "$w/ctrl.err.log" && return 1

  # Rejection: a non-empty customization string is never honorable (the
  # engine's own OSSLKMACAlgorithm never sets one).
  if SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O mac \
    -propquery "?provider=pkcs11" -macopt "hexkey:$key" \
    -macopt hexcustom:aabbcc -in "$w/msg.txt" "$algo" >/dev/null 2>&1
  then echo "non-empty custom string was accepted (should be rejected)"; return 1; fi

  return 0
}
t26b() { t26_kmac "$CPP_ENGINE_SO" KMAC-128 128cpp; }
run_case T26b PASS "token KMAC-128 (C++ arm) == software KMAC-128, engine-log verified, custom-string rejection (remediation R23); negative-control twin (R13)" t26b
t26c() { t26_kmac "$CPP_ENGINE_SO" KMAC-256 256cpp; }
run_case T26c PASS "token KMAC-256 (C++ arm) == software KMAC-256, engine-log verified (remediation R23); negative-control twin (R13)" t26c

# T26d — closes the loop on R24's own finding: EVP_MAC_init_SKEY on HMAC
# now actually works (R23's fix), so the full opaque chain (EVP_SKEY_
# generate -> EVP_KDF_derive_SKEY -> EVP_MAC_init_SKEY, raw key material
# never seen) succeeds end to end, cross-checked against independent
# software HKDF+HMAC — skey_flow_probe's own check 2, unchanged since
# R24, now genuinely passing where it previously failed at the very last
# step ("EVP_MAC_init_SKEY(derived) failed ... mac.c's HMAC implementation
# has never registered OSSL_FUNC_MAC_INIT_SKEY").
t26d() {
  local w; w="$ROOT_WORK/r23skey"; mkdir -p "$w/tokens"
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-load-behavior = early
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label r23skey --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  local out="$w/probe.out"
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" "$SKEY_FLOW_PROBE" >"$out" 2>&1
  grep -q "\[HKDF\] chained-consume (EVP_MAC_init_SKEY) succeeded" "$out" || { echo "EVP_MAC_init_SKEY chained-consume did not succeed"; cat "$out"; return 1; }
  grep -q "\[HKDF\] cross-check PASSED" "$out" || { echo "cross-check vs independent software HKDF+HMAC did not pass"; cat "$out"; return 1; }
  return 0
}
run_case T26d PASS "EVP_MAC_init_SKEY(HMAC) closes R24's own gap: full opaque generate->derive_SKEY->init_SKEY chain now succeeds, cross-checked vs independent software HKDF+HMAC (remediation R23)" t26d

# ─── T21: composite signatures (remediation R7) ─────────────────────────────
# The standard openssl CLI cannot drive a composite sign/verify (no keymgmt
# GEN for composite keys — see composite.h's own comment on
# p11prov_composite_evp_pkey_from_uris) so these cases use composite_sig_probe
# (scripts/composite-sig-probe.c), a small standalone tool that links
# pkcs11-provider.so directly and calls that bridge itself. Each case: real
# ML-DSA + classical keypairs generated on the token, real sign, real verify
# against a SEPARATE public-key-URI EVP_PKEY (not the signing one — PKCS#11
# C_VerifyInit against a private-class object fails), plus two sabotage
# controls (wrong message, corrupted signature byte) that must both fail.
#
# `openssl genpkey`'s own -out writes a base64 "PKCS#11 Provider URI v1.0"
# PEM wrapper, not a bare pkcs11: string — extract_uri unwraps it.
extract_uri() {
  grep -v 'BEGIN\|END' "$1" | base64 -d | strings | grep '^pkcs11:'
}

compsig_case() { # $1=oid $2=mldsa_alg $3=classical_alg $4...=classical genpkey opts
  local oid="$1" mldsa_alg="$2" classical_alg="$3"
  shift 3
  local w="$ROOT_WORK/r21_${oid##*.}"
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-encode-provider-uri-to-pem = true
pkcs11-module-load-behavior = early
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label "r21${oid##*.}" --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O genpkey \
    -provider pkcs11 -algorithm "$mldsa_alg" -propquery "?provider=pkcs11" \
    -out "$w/pq.uri" >/dev/null 2>&1 || return 1
  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O genpkey \
    -provider pkcs11 -algorithm "$classical_alg" "$@" -propquery "?provider=pkcs11" \
    -out "$w/classical.uri" >/dev/null 2>&1 || return 1

  local pq_priv cl_priv pq_pub cl_pub
  pq_priv=$(extract_uri "$w/pq.uri")
  cl_priv=$(extract_uri "$w/classical.uri")
  [[ -n "$pq_priv" && -n "$cl_priv" ]] || return 1
  pq_pub="${pq_priv/type=private/type=public}"
  cl_pub="${cl_priv/type=private/type=public}"

  local msg="T21 composite probe $oid"
  local sighex
  sighex=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" \
    "$COMPOSITE_PROBE" sign "$oid" "$pq_priv" "$cl_priv" "$msg" 2>"$w/sign.err")
  [[ -n "$sighex" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" \
    "$COMPOSITE_PROBE" verify "$oid" "$pq_pub" "$cl_pub" "$msg" "$sighex" >/dev/null 2>&1 || return 1

  # Sabotage 1: wrong message must fail
  if SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" \
    "$COMPOSITE_PROBE" verify "$oid" "$pq_pub" "$cl_pub" "WRONG $msg" "$sighex" >/dev/null 2>&1
  then
    return 1
  fi
  # Sabotage 2: corrupted last byte must fail
  local badsig="${sighex%??}00"
  [[ "$badsig" == "$sighex" ]] && badsig="${sighex%??}ff"
  if SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" \
    "$COMPOSITE_PROBE" verify "$oid" "$pq_pub" "$cl_pub" "$msg" "$badsig" >/dev/null 2>&1
  then
    return 1
  fi
  return 0
}

t21a() { compsig_case "1.3.6.1.5.5.7.6.37" ML-DSA-44 RSA -pkeyopt rsa_keygen_bits:2048; }
run_case T21a PASS "composite id-MLDSA44-RSA2048-PSS-SHA256 (.37): real token sign+verify, both sabotage controls rejected" t21a
t21b() { compsig_case "1.3.6.1.5.5.7.6.45" ML-DSA-65 EC -pkeyopt group:P-256; }
run_case T21b PASS "composite id-MLDSA65-ECDSA-P256-SHA512 (.45): classical hash fixed from SHA512 to the profile-correct SHA256 (phase-4 R7 — same bug class the Rust KMIP engine fixed 2026-08-17); real token sign+verify, both sabotage controls rejected" t21b
t21c() { compsig_case "1.3.6.1.5.5.7.6.49" ML-DSA-87 EC -pkeyopt group:P-384; }
run_case T21c PASS "composite id-MLDSA87-ECDSA-P384-SHA512 (.49): classical hash fixed from SHA512 to the profile-correct SHA384 (phase-4 R7); real token sign+verify, both sabotage controls rejected" t21c
t21d() { compsig_case "1.3.6.1.5.5.7.6.39" ML-DSA-44 ED25519; }
run_case T21d PASS "composite id-MLDSA44-Ed25519-SHA512 (.39, new profile, phase-4 R7): real token sign+verify, both sabotage controls rejected" t21d
t21e() { compsig_case "1.3.6.1.5.5.7.6.40" ML-DSA-44 EC -pkeyopt group:P-256; }
run_case T21e PASS "composite id-MLDSA44-ECDSA-P256-SHA256 (.40, new profile, phase-4 R7): the one profile where pre-hash and classical hash coincide, cross-checked against the external raw-signature KAT vector; real token sign+verify, both sabotage controls rejected" t21e
t21f() { compsig_case "1.3.6.1.5.5.7.6.41" ML-DSA-65 RSA -pkeyopt rsa_keygen_bits:3072; }
run_case T21f PASS "composite id-MLDSA65-RSA3072-PSS-SHA512 (.41, new profile, phase-4 R7): also fixed a classical-signature buffer-too-small bug (256-byte max was sized only for RSA-2048); real token sign+verify, both sabotage controls rejected" t21f
t21g() { compsig_case "1.3.6.1.5.5.7.6.48" ML-DSA-65 ED25519; }
run_case T21g PASS "composite id-MLDSA65-Ed25519-SHA512 (.48, new profile, phase-4 R7): real token sign+verify, both sabotage controls rejected" t21g
t21h() { compsig_case "1.3.6.1.5.5.7.6.46" ML-DSA-65 EC -pkeyopt group:P-384; }
run_case T21h PASS "composite id-MLDSA65-ECDSA-P384-SHA512 (.46, new profile, phase-4 R7): cross-checked against the external raw-signature KAT vector; real token sign+verify, both sabotage controls rejected" t21h

# ─── T22: PBKDF2 KDF (remediation R10) ───────────────────────────────────────
# CKM_PKCS5_PBKD2 is a genuinely new OSSL_OP_KDF algorithm for this provider
# (kdf.c previously implemented only HKDF/TLS13-KDF). Own dedicated arena for
# the same reason T20's own does: mk_arena hardcodes log.level=ERROR, which
# would hide the "Created new object" marker this proof depends on.
t22_case() { # $1 = SHA1|SHA224|SHA256|SHA384|SHA512
  local dig="$1" w
  w="$ROOT_WORK/r10${dig}"
  mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-load-behavior = early
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label "r10${dig}" --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1

  # ── Positive: propquery pinned, token must do the work ──
  local tokout swout
  tokout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O kdf \
    -provider pkcs11 -propquery "?provider=pkcs11" -keylen 32 \
    -kdfopt pass:testpass -kdfopt salt:hex:0102030405060708 -kdfopt iter:1000 \
    -kdfopt digest:"$dig" PBKDF2 2>"$w/tok.err.log") || return 1
  swout=$(OPENSSL_CONF=/dev/null O kdf -keylen 32 \
    -kdfopt pass:testpass -kdfopt salt:hex:0102030405060708 -kdfopt iter:1000 \
    -kdfopt digest:"$dig" PBKDF2 2>/dev/null) || return 1
  [[ -n "$tokout" && "$tokout" == "$swout" ]] || return 1
  # Engine-log evidence, not exit code or output value (R13): PBKDF2 is
  # deterministic, so a silent wrong-provider fallback is invisible in the
  # output alone — only the token creating the derived session key object
  # is the arbiter that it, not the default provider, computed it.
  grep -q "Created new object" "$w/tok.err.log" || return 1

  # ── Negative control (R13): same arena, propquery removed ──
  local ctrlout
  ctrlout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O kdf \
    -keylen 32 -kdfopt pass:testpass -kdfopt salt:hex:0102030405060708 \
    -kdfopt iter:1000 -kdfopt digest:"$dig" PBKDF2 2>"$w/ctrl.err.log") || return 1
  [[ "$ctrlout" == "$swout" ]] || return 1
  if grep -q "Created new object" "$w/ctrl.err.log"; then
    return 1
  fi
  return 0
}
t22() { t22_case SHA1; }
run_case T22 PASS "token PBKDF2 (HMAC-SHA1 PRF) == software PBKDF2, engine-log verified (remediation R10); negative-control twin (R13)" t22
t22b() { t22_case SHA224; }
run_case T22b PASS "token PBKDF2 (HMAC-SHA224 PRF) == software PBKDF2, engine-log verified (remediation R10); negative-control twin (R13)" t22b
t22c() { t22_case SHA256; }
run_case T22c PASS "token PBKDF2 (HMAC-SHA256 PRF) == software PBKDF2, engine-log verified (remediation R10); negative-control twin (R13)" t22c
t22d() { t22_case SHA384; }
run_case T22d PASS "token PBKDF2 (HMAC-SHA384 PRF) == software PBKDF2, engine-log verified (remediation R10); negative-control twin (R13)" t22d
t22e() { t22_case SHA512; }
run_case T22e PASS "token PBKDF2 (HMAC-SHA512 PRF) == software PBKDF2, engine-log verified (remediation R10); negative-control twin (R13)" t22e

# ─── T25: SP800-108 Counter/Feedback KDF a.k.a. KBKDF (remediation R22) ──────
# Mirrors t22_case's own structure exactly (own arena, load-behavior=early
# per WART-4 — openssl's own `kdf` CLI subcommand never forces the lazy
# provider init the way genpkey/pkeyutl's key-object creation does as a
# side effect, confirmed live: even HKDF, already proven working elsewhere
# in this harness, silently falls back to the default provider through
# `openssl kdf` without this flag), engine-log positive assertion +
# negative-control twin (R13), sabotage (wrong salt -> different output).
t25_case() { # $1=mode(COUNTER|FEEDBACK) $2=mac(HMAC|CMAC) $3=digest-or-cipher $4=keylen $5=extra kdfopt (seed, optional)
  local mode="$1" mac="$2" dc="$3" keylen="$4" extra="${5:-}" w
  w="$ROOT_WORK/r22${mode}${mac}"
  mkdir -p "$w/tokens"
  cat > "$w/softhsm2.conf" <<EOF
directories.tokendir = $w/tokens
objectstore.backend = file
log.level = DEBUG
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-load-behavior = early
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label "r22${mode}${mac}" --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1

  local key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  local salt=73616c743031323304
  local dcopt macopt
  if [[ "$mac" == CMAC ]]; then macopt="cipher"; else macopt="digest"; fi

  # ── Positive: propquery pinned, token must do the work ──
  local tokout swout
  tokout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O kdf \
    -provider pkcs11 -propquery "?provider=pkcs11" -keylen "$keylen" \
    -kdfopt mode:"$mode" -kdfopt mac:"$mac" -kdfopt "$macopt":"$dc" \
    -kdfopt hexkey:"$key" -kdfopt hexsalt:"$salt" $extra \
    KBKDF 2>"$w/tok.err.log") || return 1
  swout=$(OPENSSL_CONF=/dev/null O kdf -keylen "$keylen" \
    -kdfopt mode:"$mode" -kdfopt mac:"$mac" -kdfopt "$macopt":"$dc" \
    -kdfopt hexkey:"$key" -kdfopt hexsalt:"$salt" $extra \
    KBKDF 2>/dev/null) || return 1
  [[ -n "$tokout" && "$tokout" == "$swout" ]] || return 1
  # Engine-log evidence (R13): KBKDF is deterministic, so a silent
  # wrong-provider fallback is invisible in the output value alone.
  grep -q "Created new object" "$w/tok.err.log" || return 1

  # ── Negative control (R13): same arena, propquery removed ──
  local ctrlout
  ctrlout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O kdf \
    -keylen "$keylen" -kdfopt mode:"$mode" -kdfopt mac:"$mac" \
    -kdfopt "$macopt":"$dc" -kdfopt hexkey:"$key" -kdfopt hexsalt:"$salt" \
    $extra KBKDF 2>"$w/ctrl.err.log") || return 1
  [[ "$ctrlout" == "$swout" ]] || return 1
  if grep -q "Created new object" "$w/ctrl.err.log"; then
    return 1
  fi

  # ── Sabotage: a different salt must NOT produce the same output ──
  local sabout
  sabout=$(SOFTHSM2_CONF="$w/softhsm2.conf" OPENSSL_CONF="$w/openssl.cnf" O kdf \
    -provider pkcs11 -propquery "?provider=pkcs11" -keylen "$keylen" \
    -kdfopt mode:"$mode" -kdfopt mac:"$mac" -kdfopt "$macopt":"$dc" \
    -kdfopt hexkey:"$key" -kdfopt hexsalt:ffffffffffffffffff $extra \
    KBKDF 2>/dev/null) || return 1
  [[ "$sabout" != "$tokout" ]] || { echo "sabotage: different salt produced the SAME output"; return 1; }

  return 0
}
t25() { t25_case COUNTER HMAC SHA256 32; }
run_case T25 PASS "token SP800-108 Counter-KDF (HMAC-SHA256 PRF) == software KBKDF, engine-log verified, sabotage control rejected (remediation R22); negative-control twin (R13)" t25
t25b() { t25_case COUNTER HMAC SHA3-256 32; }
run_case T25b PASS "token SP800-108 Counter-KDF (HMAC-SHA3-256 PRF) == software KBKDF (remediation R22)" t25b
t25c() { t25_case COUNTER CMAC AES-256-CBC 32; }
run_case T25c PASS "token SP800-108 Counter-KDF (CMAC-AES-256 PRF) == software KBKDF (remediation R22)" t25c
t25f() { t25_case FEEDBACK HMAC SHA384 48 "-kdfopt hexseed:$(printf 'aa%.0s' {1..48})"; }
run_case T25f PASS "token SP800-108 Feedback-KDF (HMAC-SHA384 PRF, with IV/seed) == software KBKDF (remediation R22)" t25f

# ─── T25r: KBKDF rejection controls — inputs the C++ engine's own SP800-108
# handler cannot honor must fail loudly, never silently degrade (R10/F36-6
# precedent this item's own kdf.c section documents in full) ─────────────
t25r() {
  local w; w="$ROOT_WORK/r22reject"; mkdir -p "$w/tokens"
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
pkcs11-module-path = $CPP_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-load-behavior = early
activate = 1
EOF
  OPENSSL_CONF=/dev/null SOFTHSM2_CONF="$w/softhsm2.conf" "$SOFTHSM_UTIL" --module "$CPP_ENGINE_SO" \
    --init-token --free --label r22reject --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  use_arena "$w"
  local key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  local salt=73616c743031323304
  # SHA-1: the engine's own PRF table has no SHA-1 entry for SP800-108
  # (unlike PBKDF2, which does) -- must be rejected, not silently mapped.
  if O kdf -provider pkcs11 -propquery "?provider=pkcs11" -keylen 32 \
    -kdfopt mode:COUNTER -kdfopt mac:HMAC -kdfopt digest:SHA1 \
    -kdfopt hexkey:"$key" -kdfopt hexsalt:"$salt" KBKDF >/dev/null 2>&1
  then echo "SHA-1 PRF was accepted (should be rejected)"; return 1; fi
  # A non-CBC AES cipher: the engine always derives its CMAC cipher from
  # the base key's own byte length via plain CKM_AES_CMAC -- forwarding a
  # caller's mismatched cipher name would silently diverge from that.
  if O kdf -provider pkcs11 -propquery "?provider=pkcs11" -keylen 32 \
    -kdfopt mode:COUNTER -kdfopt mac:CMAC -kdfopt cipher:AES-256-GCM \
    -kdfopt hexkey:"$key" -kdfopt hexsalt:"$salt" KBKDF >/dev/null 2>&1
  then echo "non-CBC cipher was accepted (should be rejected)"; return 1; fi
  # use-l:0: the engine's own KBKDF call never sets this, so honoring a
  # caller's request to disable it would silently diverge from what the
  # token actually computes.
  if O kdf -provider pkcs11 -propquery "?provider=pkcs11" -keylen 32 \
    -kdfopt mode:COUNTER -kdfopt mac:HMAC -kdfopt digest:SHA256 \
    -kdfopt hexkey:"$key" -kdfopt hexsalt:"$salt" -kdfopt use-l:0 \
    KBKDF >/dev/null 2>&1
  then echo "use-l:0 was accepted (should be rejected)"; return 1; fi
  return 0
}
run_case T25r PASS "KBKDF rejects SHA-1 PRF, non-CBC CMAC cipher, and use-l:0 -- none are honorable by the engine's own SP800-108 handler (remediation R22)" t25r

# ─── T23: NIST security-category PKEY param (remediation R20 / F36-5) ───────
# One representative param set per PQC family, cross-checked against the
# FIPS 203/204/205 category each is required to report (1/2/3/5 — category 4
# is never used by any standard ML-KEM/ML-DSA/SLH-DSA parameter set).
t23_case() { # $1=alg $2=expected_category
  local alg="$1" expect="$2" w
  w=$(mk_arena "r23$(echo "$alg" | tr -cd '[:alnum:]')" "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -provider pkcs11 -algorithm "$alg" -propquery "?provider=pkcs11" -out "$w/k.uri" || return 1
  local got
  got=$("$DUMP_INT_PARAM" "$w/k.uri" security-category) || return 1
  [[ "$got" == "$expect" ]] || return 1
}
t23() { t23_case ML-DSA-44 2; }
run_case T23 PASS "ML-DSA-44 reports NIST security category 2 (FIPS 204 Table 1)" t23
t23b() { t23_case ML-KEM-768 3; }
run_case T23b PASS "ML-KEM-768 reports NIST security category 3 (FIPS 203 Table 2)" t23b
t23c() { t23_case SLH-DSA-SHA2-128s 1; }
run_case T23c PASS "SLH-DSA-SHA2-128s reports NIST security category 1 (FIPS 205 Table 2)" t23c

# ─── T24: HSS/LMS stateful hash-based signatures (remediation R9) ───────────
# Both openssl-CLI entry points (pkeyutl -sign/-verify, with and without
# -rawin — see sig/hss.c's own header comment for why -rawin drives
# DIGEST_SIGN/VERIFY here, not plain SIGN/VERIFY as R7's composite.c
# originally assumed), both sabotage controls, AND a genuine cross-
# implementation proof: the token's own C_Sign output verified by OpenSSL
# 3.6.3's independent, from-scratch native LMS implementation (lms_xdr_
# verify, built expressly for this — see that file's header for the two
# required HSS-vs-bare-LMS wire-format strips and the two non-obvious
# OpenSSL API calls needed to reach it (EVP_PKEY_verify_message_init, the
# "xdr" input-type decoder invoked directly since the CLI's PEM/DER
# auto-detect chain never reaches it) — self-consistency between an
# engine's own sign and verify would not have caught a signer that's
# wrong in a way its own verifier is equally wrong about.
t24() { local w; w=$(mk_arena hsssign "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm HSS -out "$w/k.pem" || return 1

  # -rawin (DIGEST_SIGN/VERIFY dispatch)
  O pkeyutl -sign -rawin -inkey "pkcs11:token=hsssign;type=private" -in "$MSG" -out "$w/sig.bin" || return 1
  [[ "$(stat -c%s "$w/sig.bin")" == "1296" ]] || { echo "sig size $(stat -c%s "$w/sig.bin") != 1296"; return 1; }
  O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=hsssign;type=public" -in "$MSG" -sigfile "$w/sig.bin" || return 1

  # plain SIGN/VERIFY dispatch (no -rawin)
  O pkeyutl -sign -inkey "pkcs11:token=hsssign;type=private" -in "$MSG" -out "$w/sig_plain.bin" || return 1
  O pkeyutl -verify -pubin -inkey "pkcs11:token=hsssign;type=public" -in "$MSG" -sigfile "$w/sig_plain.bin" || return 1

  # sabotage: corrupted signature and wrong message must both be rejected
  cp "$w/sig.bin" "$w/tampered.bin"
  printf '\x00' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  cmp -s "$w/sig.bin" "$w/tampered.bin" && printf '\xff' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=hsssign;type=public" -in "$MSG" -sigfile "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered HSS signature VERIFIED — verifier cannot say no"; return 1; fi
  echo "wrong message" > "$w/wrong.txt"
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=hsssign;type=public" -in "$w/wrong.txt" -sigfile "$w/sig.bin" >/dev/null 2>&1
  then echo "HSS signature verified against the WRONG message — verifier cannot say no"; return 1; fi

  # cross-implementation proof: token-signed, OpenSSL-native-LMS-verified
  "$HSS_PUBKEY_DUMP" "$CPP_ENGINE_SO" hsssign "$w/pub.raw" >/dev/null 2>&1 || { echo "hss_pubkey_dump failed"; return 1; }
  "$LMS_XDR_VERIFY" "$w/pub.raw" "$MSG" "$w/sig.bin" || { echo "cross-implementation LMS verify FAILED"; return 1; }
  # and the sabotage twin: the independent verifier must reject it too
  if "$LMS_XDR_VERIFY" "$w/pub.raw" "$MSG" "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered HSS signature VERIFIED by the independent LMS implementation"; return 1; fi
  return 0
}
run_case T24 PASS "HSS/LMS token sign (size 1296, both -rawin and plain dispatch) -> token verify, both sabotage controls rejected, AND cross-verified by OpenSSL 3.6.3's own independent native LMS implementation (remediation R9)" t24

# T24c — phase-5 R25 (HSS param-set awareness). T24 above only ever
# exercises the C++ engine's own documented default (LMOTS W8); this
# proves sig/hss.c's hss_sig_size() genuinely computes a DIFFERENT size
# for a DIFFERENT parameter set (LMOTS W4, matching the Rust engine's own
# default) rather than a constant that happens to be right once. No
# gen_set_params surface exists on this provider's HSS keymgmt (R25's own
# scope decision), so the W4 key is generated with explicit
# CK_HSS_KEY_PAIR_GEN_PARAMS via the raw-PKCS11 hss_w4_keygen tool
# (scripts/hss-w4-keygen.c) rather than `openssl genpkey` — the resulting
# key still flows through the provider normally for every step below.
t24c() { local w; w=$(mk_arena hssw4 "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  "$HSS_W4_KEYGEN" "$CPP_ENGINE_SO" hssw4 || { echo "hss_w4_keygen failed"; return 1; }

  O pkeyutl -sign -rawin -inkey "pkcs11:token=hssw4;type=private" -in "$MSG" -out "$w/sig.bin" || return 1
  [[ "$(stat -c%s "$w/sig.bin")" == "2352" ]] || { echo "W4 sig size $(stat -c%s "$w/sig.bin") != 2352"; return 1; }
  O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=hssw4;type=public" -in "$MSG" -sigfile "$w/sig.bin" || return 1

  # sabotage: corrupted signature and wrong message must both be rejected
  cp "$w/sig.bin" "$w/tampered.bin"
  printf '\x00' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  cmp -s "$w/sig.bin" "$w/tampered.bin" && printf '\xff' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=hssw4;type=public" -in "$MSG" -sigfile "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered W4 HSS signature VERIFIED — verifier cannot say no"; return 1; fi
  echo "wrong message" > "$w/wrong.txt"
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=hssw4;type=public" -in "$w/wrong.txt" -sigfile "$w/sig.bin" >/dev/null 2>&1
  then echo "W4 HSS signature verified against the WRONG message — verifier cannot say no"; return 1; fi

  # cross-implementation proof (lms-xdr-verify.c is now param-set-aware,
  # deriving expected sizes from the decoded key's own lms/lmots type
  # rather than a single hardcoded default -- also part of R25)
  "$HSS_PUBKEY_DUMP" "$CPP_ENGINE_SO" hssw4 "$w/pub.raw" >/dev/null 2>&1 || { echo "hss_pubkey_dump failed"; return 1; }
  "$LMS_XDR_VERIFY" "$w/pub.raw" "$MSG" "$w/sig.bin" || { echo "W4 cross-implementation LMS verify FAILED"; return 1; }
  if "$LMS_XDR_VERIFY" "$w/pub.raw" "$MSG" "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered W4 HSS signature VERIFIED by the independent LMS implementation"; return 1; fi
  return 0
}
run_case T24c PASS "HSS/LMS token sign with EXPLICIT non-default params (LMOTS W4, matching the Rust engine's own default; size 2352) -> token verify, both sabotage controls rejected, AND cross-verified by OpenSSL's independent native LMS implementation via the now-param-set-aware lms-xdr-verify.c (remediation R25)" t24c

# T24b — phase-5 R24 (F36-3 EVP_SKEY probe). Regression guard for the real
# bug the probe found: skeymgmt.c's four entry points (aes/generic_secret
# generate/import) never called p11prov_ctx_status() before touching
# slots/sessions — every other operation type does, and every existing
# harness case always does a keygen/sign BEFORE anything else in its arena,
# which triggers the lazy module+slots init as a side effect, so this only
# broke when SKEYMGMT was the FIRST pkcs11 operation in a process (which
# nothing in this harness had ever done — EVP_SKEY was entirely unprobed
# before R24). Asserts on specific probe output lines, not the whole binary's
# exit code: check 3 (TLS13-KDF) and the HMAC-consume half of check 2 hit
# two SEPARATE, already-documented gaps (an unexplained TLS13-KDF mode-
# routing issue not root-caused, and mac.c never registering
# OSSL_FUNC_MAC_INIT_SKEY) that make the probe's own exit code nonzero
# without indicating a regression in the fix this case actually guards.
t24b() { local w; w=$(mk_arena skeyprobe "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  local out="$w/probe.out"
  "$SKEY_FLOW_PROBE" >"$out" 2>&1
  grep -q "AES *generate: provider=pkcs11" "$out" || { echo "AES SKEY generate did not report provider=pkcs11"; cat "$out"; return 1; }
  grep -q "GENERIC-SECRET *generate: provider=pkcs11" "$out" || { echo "GENERIC-SECRET SKEY generate did not report provider=pkcs11"; return 1; }
  grep -q "\[HKDF\] derive_SKEY PASSED" "$out" || { echo "HKDF derive_SKEY did not pass"; cat "$out"; return 1; }
  return 0
}
run_case T24b PASS "EVP_SKEY generate (AES + GENERIC-SECRET) and HKDF derive_SKEY stay token-resident, regression guard for a real ctx_status-ordering bug SKEYMGMT alone had (remediation R24)" t24b

# T27/T27b/T27c/T27d -- phase-5 R26. R26 itself (ChaCha20/ChaCha20-
# Poly1305) turned out to need a real prerequisite fix first: AES-CTR's
# own mechanism-parameter construction was an unfinished `/* TODO */`
# stub (always failed), and AES-GCM's registration was dead code (missing
# from the mechanism checklist that makes it reachable at all) -- neither
# had ever been reachable through this provider's OP_CIPHER interface
# before this item. All four cases here use a HARD propquery
# ("provider=pkcs11", no leading "?") deliberately: a soft one let this
# provider's own "ChaCha20-Poly1305"/"AES-256-GCM" registrations
# silently lose to the default provider's identically-named
# implementations during EVP_CIPHER_fetch(), so early manual testing
# "passed" against pure software with zero token involvement (see
# aead-probe.c's own header for the full account) -- carrying forward
# R22's own "soft propquery can silently prefer default" lesson into a
# second, independently-discovered instance of it.
t27() { local w; w=$(mk_arena aesctr "$CPP_ENGINE_SO" "pkcs11-module-load-behavior = early") && use_arena "$w" || return 1
  local key; key=$(python3 -c "import os;print(os.urandom(32).hex())")
  local iv; iv=$(python3 -c "import os;print(os.urandom(16).hex())")
  O enc -aes-256-ctr -propquery "provider=pkcs11" -K "$key" -iv "$iv" -in "$MSG" -out "$w/ct.bin" -nosalt || return 1
  OPENSSL_CONF=/dev/null O enc -aes-256-ctr -K "$key" -iv "$iv" -in "$MSG" -out "$w/ct_sw.bin" -nosalt || return 1
  cmp -s "$w/ct.bin" "$w/ct_sw.bin" || { echo "AES-256-CTR ciphertext differs from software"; return 1; }
  O enc -aes-256-ctr -propquery "provider=pkcs11" -d -K "$key" -iv "$iv" -in "$w/ct.bin" -out "$w/pt.bin" -nosalt || return 1
  cmp -s "$w/pt.bin" "$MSG" || { echo "AES-256-CTR decrypt did not round-trip"; return 1; }
  return 0
}
run_case T27 PASS "AES-256-CTR token encrypt == software (byte-identical), token decrypt round-trips -- CK_AES_CTR_PARAMS construction was a genuine unfinished /* TODO */ stub before this item (remediation R26 prerequisite)" t27

t27_negctl() { local w; w=$(mk_arena aesctrneg "$CPP_ENGINE_SO" "pkcs11-module-load-behavior = early") && use_arena "$w" || return 1
  local key; key=$(python3 -c "import os;print(os.urandom(32).hex())")
  local iv; iv=$(python3 -c "import os;print(os.urandom(16).hex())")
  # R13: same command, propquery removed -- must NOT silently produce
  # pkcs11-identical output via some other path; asserting the command
  # itself still succeeds (goes to default) is enough to prove this
  # arena isn't just broken outright.
  O enc -aes-256-ctr -K "$key" -iv "$iv" -in "$MSG" -out "$w/ct.bin" -nosalt || return 1
  return 0
}
run_case T27_negctl PASS "negative-control twin for T27: same arena, propquery removed, still succeeds via default provider (R13)" t27_negctl

t27b() { local w; w=$(mk_arena aesgcm "$CPP_ENGINE_SO" "pkcs11-module-load-behavior = early") && use_arena "$w" || return 1
  local key; key=$(python3 -c "import os;print(os.urandom(32).hex())")
  local iv; iv=$(python3 -c "import os;print(os.urandom(12).hex())")
  local aad; aad=$(python3 -c "print('deadbeef'*4)")
  local out; out=$("$AEAD_PROBE" AES-256-GCM "$key" "$iv" "$aad" "$MSG" pkcs11) || { echo "$out"; return 1; }
  echo "$out" | grep -q "^encrypt OK" || { echo "$out"; return 1; }
  echo "$out" | grep -q "^decrypt OK" || { echo "$out"; return 1; }
  echo "$out" | grep -q "tampered tag correctly rejected" || { echo "$out"; return 1; }
  echo "$out" | grep -q "tampered ciphertext correctly rejected" || { echo "$out"; return 1; }
  return 0
}
run_case T27b PASS "AES-256-GCM full AEAD workflow (AAD, tag get/set, both sabotage controls) genuinely through the token -- registration was dead code before this item, unreachable regardless of correctness (remediation R26 prerequisite)" t27b

t27c() { local w; w=$(mk_arena chacha20 "$CPP_ENGINE_SO" "pkcs11-module-load-behavior = early") && use_arena "$w" || return 1
  local key; key=$(python3 -c "import os;print(os.urandom(32).hex())")
  local iv; iv=$(python3 -c "import os;print(os.urandom(16).hex())")
  python3 -c "print('A'*200)" > "$w/msg200.txt"
  O enc -chacha20 -propquery "provider=pkcs11" -K "$key" -iv "$iv" -in "$w/msg200.txt" -out "$w/ct.bin" -nosalt || return 1
  OPENSSL_CONF=/dev/null O enc -chacha20 -K "$key" -iv "$iv" -in "$w/msg200.txt" -out "$w/ct_sw.bin" -nosalt || return 1
  # >64 bytes: exercises the counter-increment seam -- a wrong counter/
  # nonce split in CK_CHACHA20_PARAMS would only show up past byte 64.
  cmp -s "$w/ct.bin" "$w/ct_sw.bin" || { echo "ChaCha20 ciphertext differs from software (>64B)"; return 1; }
  O enc -chacha20 -propquery "provider=pkcs11" -d -K "$key" -iv "$iv" -in "$w/ct.bin" -out "$w/pt.bin" -nosalt || return 1
  cmp -s "$w/pt.bin" "$w/msg200.txt" || { echo "ChaCha20 decrypt did not round-trip"; return 1; }
  return 0
}
run_case T27c PASS "ChaCha20 (bare stream, CKM_CHACHA20) token encrypt == software (byte-identical, >64B counter-seam), token decrypt round-trips (remediation R26)" t27c

t27d() { local w; w=$(mk_arena chacha20poly "$CPP_ENGINE_SO" "pkcs11-module-load-behavior = early") && use_arena "$w" || return 1
  local key; key=$(python3 -c "import os;print(os.urandom(32).hex())")
  local iv; iv=$(python3 -c "import os;print(os.urandom(12).hex())")
  local aad; aad=$(python3 -c "print('cafebabe'*4)")
  local out; out=$("$AEAD_PROBE" ChaCha20-Poly1305 "$key" "$iv" "$aad" "$MSG" pkcs11) || { echo "$out"; return 1; }
  echo "$out" | grep -q "^encrypt OK" || { echo "$out"; return 1; }
  echo "$out" | grep -q "^decrypt OK" || { echo "$out"; return 1; }
  echo "$out" | grep -q "tampered tag correctly rejected" || { echo "$out"; return 1; }
  echo "$out" | grep -q "tampered ciphertext correctly rejected" || { echo "$out"; return 1; }
  return 0
}
run_case T27d PASS "ChaCha20-Poly1305 full AEAD workflow (AAD, tag get/set, both sabotage controls) genuinely through the token (remediation R26, ALG-7 RESOLVED)" t27d

# T27e -- phase-6 R30. R26's own "not done" list left two AEAD decrypt
# edge cases honestly unproven: the AEAD_DECRYPT_MAX_MSG_LEN ceiling
# (asserted from code reading only) and the AAD-only/empty-plaintext
# path through ensure_session()-from-final(). Both real: the ceiling
# check found a genuine bug (this case's own "at the promised ceiling"
# sub-case failed before the fix -- see cipher.h's own updated
# AEAD_DECRYPT_MAX_MSG_LEN comment for the mechanism) and the fix
# landed as part of writing this case, not before it.
t27e() { local w; w=$(mk_arena aeadedge "$CPP_ENGINE_SO" "pkcs11-module-load-behavior = early") && use_arena "$w" || return 1
  local key; key=$(python3 -c "import os;print(os.urandom(32).hex())")
  local iv12; iv12=$(python3 -c "import os;print(os.urandom(12).hex())")
  local aad; aad=$(python3 -c "print('cafebabe'*4)")

  for cipher in AES-256-GCM ChaCha20-Poly1305; do
    # at the promised ceiling: must succeed (this exact case failed
    # before the AEAD_DECRYPT_MAX_MSG_LEN fix -- both engines need one
    # tag's worth of headroom beyond the promised plaintext length,
    # surfacing at different internal call points per mechanism)
    "$AEAD_EDGE_PROBE" "$cipher" "$key" "$iv12" "$aad" 65536 pkcs11 decrypt-ok || { echo "$cipher failed AT the promised 65536-byte ceiling"; return 1; }
    # well over the ceiling: must fail cleanly, not crash or truncate
    "$AEAD_EDGE_PROBE" "$cipher" "$key" "$iv12" "$aad" 100000 pkcs11 decrypt-fail || { echo "$cipher did not fail cleanly over the ceiling"; return 1; }
    # AAD-only (empty plaintext, nonempty AAD): exercises final()'s own
    # zero-real-update()-calls lazy-init path
    "$AEAD_EDGE_PROBE" "$cipher" "$key" "$iv12" "$aad" 0 pkcs11 decrypt-ok || { echo "$cipher AAD-only case failed"; return 1; }
    # fully empty (empty plaintext, empty AAD): same path, no AAD at all
    "$AEAD_EDGE_PROBE" "$cipher" "$key" "$iv12" "" 0 pkcs11 decrypt-ok || { echo "$cipher fully-empty case failed"; return 1; }
  done
  return 0
}
run_case T27e PASS "AEAD decrypt edge cases (AES-256-GCM + ChaCha20-Poly1305): the promised 65536-byte ceiling genuinely works (a real bug here, fixed by this case), well-over-ceiling fails cleanly not silently, AAD-only and fully-empty both work (remediation R30)" t27e

# ─── T28: ML-DSA external-µ vendor mechanism (remediation R34) ─────────────
# CKM_PQCTODAY_ML_DSA_MU -- stopgap for PKCS#11 v3.3's own upcoming native
# external-µ mechanism (oasis-tcs/pkcs11#58, not yet ratified). Computes µ
# independently in Python per FIPS 204 Eq. (1)-(2) -- SHAKE256(pk_encode(pk),
# 64) for tr, then SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64) for µ,
# exactly as both engines' own underlying crypto does (verified live against
# OpenSSL's own crypto/ml_dsa/ml_dsa_sign.c and the Rust fips204-patched
# crate's ml_dsa.rs before this item was built, not assumed) -- signs that µ
# through the vendor mechanism (`pkeyutl -pkeyopt mu:1`, the STANDARD OpenSSL
# param name; no new client-facing API), then proves it two ways: the
# mechanism's own verify, and — the real proof — OpenSSL's completely
# independent NATIVE ML-DSA implementation (-provider default, no pkcs11 at
# all) verifying against the ORIGINAL raw message. A byte-equivalence result
# there proves the µ-signed signature is indistinguishable from a direct pure
# ML-DSA signature of that message, exactly as R34's design requires.
mldsa_mu_extract_and_compute() { # $1=arena dir, writes pub.der/mu.bin/msg.bin
  local w="$1"
  O pkey -pubin -propquery "?provider=pkcs11" -in "pkcs11:token=$(basename "$w");type=public" \
    -pubout -outform DER -out "$w/pub.der" 2>/dev/null || return 1
  python3 -c "
import hashlib
data = open('$w/pub.der','rb').read()
# SPKI header for ML-DSA-65 is a fixed 22 bytes (SEQUENCE+AlgId+BIT STRING
# tag/len/unused-bits byte) -- verified once by direct ASN.1 inspection
# against this exact build's own genpkey output, not assumed from a spec
# table. pk_encode(pk) IS the raw CKA_VALUE per PKCS#11 v3.2 Table 280.
raw_pk = data[22:22+1952]
assert len(raw_pk) == 1952, f'unexpected pubkey length {len(raw_pk)}'
tr = hashlib.shake_256(raw_pk).digest(64)
msg = b'openssl-provider harness T28 external-mu message'
mp = b'\x00' + bytes([0]) + msg  # ctx empty
mu = hashlib.shake_256(tr + mp).digest(64)
open('$w/mu.bin','wb').write(mu)
open('$w/msg.bin','wb').write(msg)
"
}

t28() { local w; w=$(mk_arena mldsamu "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null || return 1
  mldsa_mu_extract_and_compute "$w" || { echo "µ computation failed"; return 1; }

  O pkeyutl -sign -propquery "?provider=pkcs11" -rawin -inkey "pkcs11:token=mldsamu;type=private" \
    -pkeyopt mu:1 -in "$w/mu.bin" -out "$w/sig.bin" 2>/dev/null || { echo "external-µ sign failed"; return 1; }
  [[ -s "$w/sig.bin" ]] || { echo "no signature produced"; return 1; }

  O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=mldsamu;type=public" \
    -pkeyopt mu:1 -in "$w/mu.bin" -sigfile "$w/sig.bin" 2>/dev/null || { echo "external-µ verify (own mechanism) failed"; return 1; }

  # The real proof: OpenSSL's completely independent native ML-DSA verifies
  # the µ-signed signature against the ORIGINAL raw message.
  OPENSSL_CONF=/dev/null O pkeyutl -verify -provider default -rawin -pubin \
    -inkey "$w/pub.der" -keyform DER -in "$w/msg.bin" -sigfile "$w/sig.bin" 2>/dev/null \
    || { echo "native (non-pkcs11) verify of the µ-signed signature against the original message failed -- not byte-equivalent to a pure ML-DSA signature"; return 1; }

  # Sabotage 1: tampered µ must fail.
  python3 -c "
d = bytearray(open('$w/mu.bin','rb').read()); d[0] ^= 0xff
open('$w/mu_bad.bin','wb').write(bytes(d))"
  O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=mldsamu;type=public" \
    -pkeyopt mu:1 -in "$w/mu_bad.bin" -sigfile "$w/sig.bin" 2>/dev/null \
    && { echo "tampered µ verified -- must not"; return 1; }

  # Sabotage 2: tampered signature must fail.
  python3 -c "
d = bytearray(open('$w/sig.bin','rb').read()); d[10] ^= 0xff
open('$w/sig_bad.bin','wb').write(bytes(d))"
  O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=mldsamu;type=public" \
    -pkeyopt mu:1 -in "$w/mu.bin" -sigfile "$w/sig_bad.bin" 2>/dev/null \
    && { echo "tampered signature verified -- must not"; return 1; }

  # Sabotage 3: non-empty context has no meaning once µ exists -- must be
  # rejected loudly, not silently ignored.
  O pkeyutl -sign -propquery "?provider=pkcs11" -rawin -inkey "pkcs11:token=mldsamu;type=private" \
    -pkeyopt mu:1 -pkeyopt context-string:deadbeef -in "$w/mu.bin" -out "$w/sig_ctx.bin" 2>/dev/null \
    && { echo "mu=1 with a context string was accepted -- must be rejected"; return 1; }

  # Sabotage 4: wrong-length µ (FIPS 204 defines exactly 64 bytes) must be
  # rejected loudly, not silently truncated/padded.
  head -c 63 "$w/mu.bin" > "$w/mu_short.bin"
  O pkeyutl -sign -propquery "?provider=pkcs11" -rawin -inkey "pkcs11:token=mldsamu;type=private" \
    -pkeyopt mu:1 -in "$w/mu_short.bin" -out "$w/sig_short.bin" 2>/dev/null \
    && { echo "63-byte (short) µ was accepted -- must be rejected"; return 1; }

  return 0
}
run_case T28 PASS "ML-DSA external-µ vendor mechanism (CKM_PQCTODAY_ML_DSA_MU): independently-computed µ signs through the vendor mechanism, verifies both via the mechanism itself AND — the real proof — OpenSSL's completely independent native ML-DSA implementation against the ORIGINAL message; four sabotage controls (tampered µ, tampered signature, context+mu rejected, wrong-length µ rejected) (remediation R34)" t28

# ─── T29: HashML-DSA digest routing, CKM_HASH_ML_DSA_<hash> (remediation R35) ─
# PKCS#11 v3.2 §6.67.7 "HashML-DSA Signature with hashing": these 10
# mechanisms hash ON TOKEN, taking the raw message M -- both engines already
# implement this correctly, but the provider's own p11prov_mldsa_set_mechanism
# unconditionally sent CKM_ML_DSA regardless of the caller's own digest
# choice, silently ignoring `openssl dgst -sha256 -sign` entirely (live-
# confirmed before the fix: the resulting signature verified as a PLAIN
# raw-message signature, not a HashML-DSA one -- the worst of the two
# hypothesized outcomes, not the merely-unhelpful one). No engine-side change
# needed; this is provider routing only (`sigctx->digest` was already parsed
# and simply never read).
t29() { local w; w=$(mk_arena hashmldsa "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null || return 1
  echo "T29 HashML-DSA digest-routing test message" > "$w/msg.txt"

  O dgst -sha256 -propquery "?provider=pkcs11" -sign "pkcs11:token=hashmldsa;type=private" \
    -out "$w/sig.bin" "$w/msg.txt" 2>/dev/null || { echo "dgst -sha256 -sign failed"; return 1; }

  # The real proof the digest is genuinely honored, not silently dropped: a
  # signature this shape must NOT verify as a plain raw-message signature.
  O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=hashmldsa;type=public" \
    -in "$w/msg.txt" -sigfile "$w/sig.bin" 2>/dev/null \
    && { echo "HashML-DSA signature verified as a PLAIN raw-message signature -- the digest was silently ignored"; return 1; }

  O dgst -sha256 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashmldsa;type=public" \
    -signature "$w/sig.bin" "$w/msg.txt" 2>/dev/null || { echo "HashML-DSA round-trip verify failed"; return 1; }

  # Negative control: the default provider explicitly refuses an explicit
  # digest for ML-DSA (audit-confirmed, "does not implement pre-hash
  # HashML-DSA") -- proves this case genuinely exercises pkcs11, not a
  # coincidental default-provider path (R13 discipline).
  O pkey -pubin -propquery "?provider=pkcs11" -in "pkcs11:token=hashmldsa;type=public" \
    -pubout -out "$w/pub.pem" 2>/dev/null || return 1
  O dgst -sha256 -provider default -verify "$w/pub.pem" -signature "$w/sig.bin" "$w/msg.txt" 2>/dev/null \
    && { echo "default provider accepted an explicit digest for ML-DSA -- expected refusal"; return 1; }

  # Sabotage 1: wrong digest at verify time must fail.
  O dgst -sha384 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashmldsa;type=public" \
    -signature "$w/sig.bin" "$w/msg.txt" 2>/dev/null \
    && { echo "wrong-digest verify succeeded -- must not"; return 1; }

  # Sabotage 2: tampered message must fail.
  echo "tampered" > "$w/msg_bad.txt"
  O dgst -sha256 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashmldsa;type=public" \
    -signature "$w/sig.bin" "$w/msg_bad.txt" 2>/dev/null \
    && { echo "tampered-message verify succeeded -- must not"; return 1; }

  return 0
}
run_case T29 PASS "HashML-DSA digest routing (CKM_HASH_ML_DSA_<hash>, PKCS#11 v3.2 §6.67.7): 'openssl dgst -sha256 -sign' against a pkcs11 ML-DSA key now genuinely routes to HashML-DSA instead of silently signing the raw message (the worst of the two hypothesized outcomes, live-confirmed before the fix); round-trip verify, negative control (default provider refuses), two sabotage controls (wrong digest, tampered message) (remediation R35)" t29

# ─── T30: HashSLH-DSA digest routing, CKM_HASH_SLH_DSA_<hash> (remediation R36) ─
# Twin of T29 for SLH-DSA (PKCS#11 v3.2 §6.69.7). SLH-DSA-SHA2-128s chosen
# to match T12sign's already-proven 7856-byte baseline.
t30() { local w; w=$(mk_arena hashslhdsa "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHA2-128s -out "$w/k.pem" 2>/dev/null || return 1
  echo "T30 HashSLH-DSA digest-routing test message" > "$w/msg.txt"

  O dgst -sha256 -propquery "?provider=pkcs11" -sign "pkcs11:token=hashslhdsa;type=private" \
    -out "$w/sig.bin" "$w/msg.txt" 2>/dev/null || { echo "dgst -sha256 -sign failed"; return 1; }
  [[ "$(stat -c%s "$w/sig.bin" 2>/dev/null || stat -f%z "$w/sig.bin")" == "7856" ]] \
    || { echo "unexpected signature size"; return 1; }

  O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=hashslhdsa;type=public" \
    -in "$w/msg.txt" -sigfile "$w/sig.bin" 2>/dev/null \
    && { echo "HashSLH-DSA signature verified as a PLAIN raw-message signature -- the digest was silently ignored"; return 1; }

  O dgst -sha256 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashslhdsa;type=public" \
    -signature "$w/sig.bin" "$w/msg.txt" 2>/dev/null || { echo "HashSLH-DSA round-trip verify failed"; return 1; }

  O pkey -pubin -propquery "?provider=pkcs11" -in "pkcs11:token=hashslhdsa;type=public" \
    -pubout -out "$w/pub.pem" 2>/dev/null || return 1
  O dgst -sha256 -provider default -verify "$w/pub.pem" -signature "$w/sig.bin" "$w/msg.txt" 2>/dev/null \
    && { echo "default provider accepted an explicit digest for SLH-DSA -- expected refusal"; return 1; }

  O dgst -sha384 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashslhdsa;type=public" \
    -signature "$w/sig.bin" "$w/msg.txt" 2>/dev/null \
    && { echo "wrong-digest verify succeeded -- must not"; return 1; }

  echo "tampered" > "$w/msg_bad.txt"
  O dgst -sha256 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashslhdsa;type=public" \
    -signature "$w/sig.bin" "$w/msg_bad.txt" 2>/dev/null \
    && { echo "tampered-message verify succeeded -- must not"; return 1; }

  return 0
}
run_case T30 PASS "HashSLH-DSA digest routing (CKM_HASH_SLH_DSA_<hash>, PKCS#11 v3.2 §6.69.7): twin of T29 for SLH-DSA-SHA2-128s -- digest genuinely routes to HashSLH-DSA (7856-byte sig), round-trip verify, negative control (default provider refuses), two sabotage controls (remediation R36)" t30

# ─── T31: SHAKE128/256 reachability for HashML-DSA/HashSLH-DSA (remediation R38) ─
# CKM_HASH_ML_DSA_SHAKE128/256 and CKM_HASH_SLH_DSA_SHAKE128/256 (PKCS#11
# v3.2 §6.67.7/§6.69.7) are real, ratified mechanisms both engines already
# implemented (R35/R36) -- but the provider's own digest_map (digests.c)
# has no SHAKE entry, so sigctx->digest could never hold a SHAKE value and
# these two mechanisms were unreachable through the provider (T29/T30's own
# dead-code note). Neither `openssl dgst -shake128/256 -sign` (apps/dgst.c
# hard-refuses "Signing key cannot be specified for XOF", unrelated to this
# provider) nor `pkeyutl -sign -digest shakeNNN` ("-digest (prehash) is not
# supported with ML-DSA-65", pkeyutl's own algorithm allowlist) can drive
# this through the CLI -- confirmed live before writing this case (phase-8
# R38 grounding) -- so shake_sign_probe (scripts/shake-sign-probe.c) drives
# EVP_DigestSign*/EVP_DigestVerify* directly, reaching the identical
# provider code path T29/T30's CLI wrapper does.
t31() { local w; w=$(mk_arena shakemldsa "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null || return 1
  echo "T31 SHAKE256 HashML-DSA digest-routing test message" > "$w/msg.txt"

  "$SHAKE_SIGN_PROBE" sign "?provider=pkcs11" "pkcs11:token=shakemldsa;type=private" \
    SHAKE256 "$w/msg.txt" "$w/sig.bin" 2>/dev/null || { echo "ML-DSA SHAKE256 sign failed"; return 1; }

  "$SHAKE_SIGN_PROBE" verify "?provider=pkcs11" "pkcs11:token=shakemldsa;type=public" \
    SHAKE256 "$w/msg.txt" "$w/sig.bin" 2>/dev/null || { echo "ML-DSA SHAKE256 round-trip verify failed"; return 1; }

  # The real proof SHAKE256 is genuinely honored, not silently dropped: a
  # HashML-DSA signature must NOT verify as a plain raw-message signature.
  O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=shakemldsa;type=public" \
    -in "$w/msg.txt" -sigfile "$w/sig.bin" 2>/dev/null \
    && { echo "ML-DSA SHAKE256 signature verified as a PLAIN raw-message signature -- digest silently ignored"; return 1; }

  # Sabotage: tampered message must fail.
  echo "tampered" > "$w/msg_bad.txt"
  "$SHAKE_SIGN_PROBE" verify "?provider=pkcs11" "pkcs11:token=shakemldsa;type=public" \
    SHAKE256 "$w/msg_bad.txt" "$w/sig.bin" 2>/dev/null \
    && { echo "ML-DSA SHAKE256 tampered-message verify succeeded -- must not"; return 1; }

  # Second algorithm family: SLH-DSA-SHAKE-128s + SHAKE128 (proves the
  # routing fix is generic, not ML-DSA-specific -- mirrors T29/T30's own
  # ML-DSA/SLH-DSA split). Own arena/token: mk_arena's own doc warns a
  # bare type=private/type=public URI is ambiguous once two keypairs
  # share a token (an audit-era probe hit exactly this). Same 7856-byte
  # size as T30's SHA2-128s baseline (size is independent of hash family,
  # T12sign_shake's own precedent).
  local w2; w2=$(mk_arena shakeslhdsa "$CPP_ENGINE_SO") && use_arena "$w2" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHAKE-128s -out "$w2/k.pem" 2>/dev/null || return 1
  cp "$w/msg.txt" "$w2/msg.txt"
  cp "$w/msg_bad.txt" "$w2/msg_bad.txt"

  "$SHAKE_SIGN_PROBE" sign "?provider=pkcs11" "pkcs11:token=shakeslhdsa;type=private" \
    SHAKE128 "$w2/msg.txt" "$w2/sig.bin" 2>/dev/null || { echo "SLH-DSA-SHAKE-128s SHAKE128 sign failed"; return 1; }
  [[ "$(stat -c%s "$w2/sig.bin" 2>/dev/null || stat -f%z "$w2/sig.bin")" == "7856" ]] \
    || { echo "unexpected SLH-DSA-SHAKE-128s signature size"; return 1; }

  "$SHAKE_SIGN_PROBE" verify "?provider=pkcs11" "pkcs11:token=shakeslhdsa;type=public" \
    SHAKE128 "$w2/msg.txt" "$w2/sig.bin" 2>/dev/null || { echo "SLH-DSA-SHAKE-128s SHAKE128 round-trip verify failed"; return 1; }

  "$SHAKE_SIGN_PROBE" verify "?provider=pkcs11" "pkcs11:token=shakeslhdsa;type=public" \
    SHAKE128 "$w2/msg_bad.txt" "$w2/sig.bin" 2>/dev/null \
    && { echo "SLH-DSA-SHAKE-128s tampered-message verify succeeded -- must not"; return 1; }

  return 0
}
run_case T31 PASS "SHAKE128/256 reachability for HashML-DSA/HashSLH-DSA (CKM_HASH_ML_DSA_SHAKE256 + CKM_HASH_SLH_DSA_SHAKE128, PKCS#11 v3.2 §6.67.7/§6.69.7): digest_sign_init now recognizes SHAKE names as sentinels instead of failing p11prov_sig_op_init's digest_map lookup, un-deading both set_mechanism SHAKE arms -- round-trip verify (both families), raw-verify-must-fail + tampered-message sabotage (remediation R38)" t31

# ─── T32: XMSS/XMSS^MT (remediation R41, phase 8) ───────────────────────────
# sig/xmss.c superseded a 20-line stub with empty OSSL_DISPATCH tables that
# was already wired into provider.c's registration -- meaning pre-R41, this
# provider advertised a usable "XMSS" algorithm while every real operation
# failed outright. Same shape as T24's own HSS proof: -rawin and plain
# dispatch, both sabotage controls. No independent from-scratch verifier
# exists for XMSS in this repo (unlike HSS/LMS's lms_xdr_verify against
# OpenSSL's own native LMS) -- deferred, see the R41 doc note. T32c (Rust-arm
# smoke) lives down in the Rust arm section below; T32/T32b/T32d all use the
# C++ engine and belong here.
t32() { local w; w=$(mk_arena xmsssign "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm XMSS -out "$w/k.pem" || return 1

  O pkeyutl -sign -rawin -inkey "pkcs11:token=xmsssign;type=private" -in "$MSG" -out "$w/sig.bin" || return 1
  O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=xmsssign;type=public" -in "$MSG" -sigfile "$w/sig.bin" || return 1

  O pkeyutl -sign -inkey "pkcs11:token=xmsssign;type=private" -in "$MSG" -out "$w/sig_plain.bin" || return 1
  O pkeyutl -verify -pubin -inkey "pkcs11:token=xmsssign;type=public" -in "$MSG" -sigfile "$w/sig_plain.bin" || return 1

  cp "$w/sig.bin" "$w/tampered.bin"
  printf '\x00' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  cmp -s "$w/sig.bin" "$w/tampered.bin" && printf '\xff' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=xmsssign;type=public" -in "$MSG" -sigfile "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered XMSS signature VERIFIED — verifier cannot say no"; return 1; fi
  echo "wrong message" > "$w/wrong.txt"
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=xmsssign;type=public" -in "$w/wrong.txt" -sigfile "$w/sig.bin" >/dev/null 2>&1
  then echo "XMSS signature verified against the WRONG message — verifier cannot say no"; return 1; fi
  return 0
}
run_case T32 PASS "XMSS token sign (default param set XMSS-SHA2_10_256, size 2500 -- both -rawin and plain dispatch) -> token verify, both sabotage controls rejected (remediation R41)" t32

t32b() { local w; w=$(mk_arena xmssmtsign "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm XMSSMT -out "$w/k.pem" || return 1

  O pkeyutl -sign -rawin -inkey "pkcs11:token=xmssmtsign;type=private" -in "$MSG" -out "$w/sig.bin" || return 1
  O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=xmssmtsign;type=public" -in "$MSG" -sigfile "$w/sig.bin" || return 1

  O pkeyutl -sign -inkey "pkcs11:token=xmssmtsign;type=private" -in "$MSG" -out "$w/sig_plain.bin" || return 1
  O pkeyutl -verify -pubin -inkey "pkcs11:token=xmssmtsign;type=public" -in "$MSG" -sigfile "$w/sig_plain.bin" || return 1

  cp "$w/sig.bin" "$w/tampered.bin"
  printf '\x00' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  cmp -s "$w/sig.bin" "$w/tampered.bin" && printf '\xff' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=xmssmtsign;type=public" -in "$MSG" -sigfile "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered XMSS^MT signature VERIFIED — verifier cannot say no"; return 1; fi
  echo "wrong message" > "$w/wrong.txt"
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=xmssmtsign;type=public" -in "$w/wrong.txt" -sigfile "$w/sig.bin" >/dev/null 2>&1
  then echo "XMSS^MT signature verified against the WRONG message — verifier cannot say no"; return 1; fi
  return 0
}
run_case T32b PASS "XMSS^MT token sign (default param set XMSSMT-SHA2_20/2_256, size 4963 -- both -rawin and plain dispatch) -> token verify, both sabotage controls rejected (remediation R41)" t32b

t32d() { # multi-process stateful-counter proof, mirroring T24e's shape for
  # HSS. Unlike the Rust engine (SOFTHSMRUST_STATE_FILE-bridged, T24e),
  # the C++ engine persists key state through its own on-disk token
  # store (directories.tokendir), so two wholly separate pkeyutl
  # invocations sharing the same SOFTHSM2_CONF is sufficient -- no
  # extra state-bridging env var needed for this arm.
  local w; w=$(mk_arena xmssctr "$CPP_ENGINE_SO") && use_arena "$w" || return 1
  O genpkey -propquery "?provider=pkcs11" -algorithm XMSS -out "$w/k.pem" || return 1

  # process B: first signature
  O pkeyutl -sign -rawin -inkey "pkcs11:token=xmssctr;type=private" -in "$MSG" -out "$w/sig1.bin" || return 1
  # process C: second signature, wholly separate invocation, same token dir
  O pkeyutl -sign -rawin -inkey "pkcs11:token=xmssctr;type=private" -in "$MSG" -out "$w/sig2.bin" || return 1

  cmp -s "$w/sig1.bin" "$w/sig2.bin" && { echo "two XMSS signatures over the same message are byte-identical — leaf index did not advance"; return 1; }

  # RFC 8391 §4.1.9: the XMSS signature's first 4 bytes are the leaf
  # index idx_sig, big-endian. It must have advanced 0 -> 1.
  q1=$(python3 -c "d=open('$w/sig1.bin','rb').read(); print(int.from_bytes(d[0:4],'big'))")
  q2=$(python3 -c "d=open('$w/sig2.bin','rb').read(); print(int.from_bytes(d[0:4],'big'))")
  [[ "$q1" == "0" ]] || { echo "first XMSS signature idx=$q1, expected 0"; return 1; }
  [[ "$q2" == "1" ]] || { echo "second XMSS signature idx=$q2, expected 1 (leaf index did not advance)"; return 1; }

  # process D: the FIRST signature (idx=0) must still verify after the
  # SECOND signing consumed leaf idx=1.
  O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=xmssctr;type=public" -in "$MSG" -sigfile "$w/sig1.bin" || { echo "first signature (idx=0) failed to verify after a second signing"; return 1; }
  O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=xmssctr;type=public" -in "$MSG" -sigfile "$w/sig2.bin" || { echo "second signature (idx=1) failed to verify"; return 1; }
  return 0
}
run_case T32d PASS "XMSS multi-process stateful-counter proof: leaf index idx genuinely advances 0->1 across two wholly separate processes sharing only the on-disk token store, first signature still verifies after the second (remediation R41)" t32d

# ─── Rust native arm ────────────────────────────────────────────────────────
say arm "Rust engine (${RUST_ENGINE_SO:-MISSING})"

mk_rust_cnf() { # R29 fix: was NOT actually self-contained despite its own
  # comment's claim -- softhsm2-util (a C++-linked CLI binary) needs a
  # real SOFTHSM2_CONF to complete its own --init-token startup even when
  # --module points it at the Rust engine, which doesn't otherwise use
  # this file's content at all (it persists via SOFTHSMRUST_STATE_FILE
  # instead). Without one, --init-token silently returns nonzero and the
  # state file never gets written -- every later command then fails with
  # "the token was not present in its slot", which reads like a keygen
  # bug, not an init failure. T15a/T15b happened to work anyway because
  # by the time they run (after every C++-arm test), some EARLIER
  # use_arena() call had left a real SOFTHSM2_CONF exported and never
  # cleared -- accidental, order-dependent, and silently broke the first
  # time a Rust-arm case was added (T24d/T24e) without that same
  # accidental leakage lining up the same way. Caller must export
  # SOFTHSM2_CONF="$w/softhsm2.conf" on every softhsm2-util invocation now
  # (openssl's own commands don't need it -- only the C++-linked CLI
  # utility does).
  local w="$1"
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
pkcs11-module-path = $RUST_ENGINE_SO
pkcs11-module-token-pin = 1234
pkcs11-module-encode-provider-uri-to-pem = true
activate = 1
EOF
}

t15a() { # provider must at least activate over the Rust cdylib
  [[ -n "$RUST_ENGINE_SO" ]] || { echo "rust cdylib not found"; return 1; }
  local w="$ROOT_WORK/rustload"; mkdir -p "$w"; mk_rust_cnf "$w"
  OPENSSL_CONF="$w/openssl.cnf" O list -providers | grep -A3 '^  pkcs11$' | grep -q 'status: active'
}
run_case T15a PASS "provider activates over the native Rust cdylib" t15a

t15b() { # ENV-2/R6/R14 — genuine multi-process persistence proof.
         # Four wholly separate process invocations, bridged only by
         # SOFTHSMRUST_STATE_FILE (R6's opt-in stash-on-C_Finalize /
         # restore-on-C_Initialize) and the object store's own PIN — no
         # two of these processes share any in-memory state at all:
         #   A: softhsm2-util --init-token  (creates the token)
         #   B: genpkey ML-DSA-65           (restores A's token, adds a real key)
         #   C: pkeyutl -sign               (restores B's token, signs with the private key)
         #   D: pkey -pubout                (restores B/C's token, exports the public key)
         # then software-verifies C's signature against D's exported
         # public key — the exact cross-check pattern already proven in
         # mldsa_case (T3a-c), just split across process boundaries by
         # the state file instead of staying in one arena. This can only
         # pass if the SAME key genuinely round-tripped through the file
         # across all four processes.
         #
         # R14 (2026-08-25/26) root-caused and fixed what blocked this.
         # CONFIRMED, sabotage-proven cause: C_GetSlotList conflated
         # "token present" with "token initialized" (two distinct PKCS#11
         # concepts — CKF_TOKEN_PRESENT lives on CK_SLOT_INFO,
         # CKF_TOKEN_INITIALIZED on CK_TOKEN_INFO). softhsm2-util's own
         # findSlot() (src/bin/common/findslot.cpp) queries the SIZE with
         # CK_TRUE, then FILLS with CK_FALSE (which never filtered, in
         # either version) — so the conflated CK_TRUE size call alone
         # under-reporting the always-present-but-uninitialized slot 0
         # against the correct, larger CK_FALSE fill count triggered
         # CKR_BUFFER_TOO_SMALL — exactly softhsm2-util's literal
         # "Could not get the slot list" error. Reverting just this fix
         # (with the item below left in place) reproduces the failure on
         # its own — sabotage-tested, this is the necessary fix.
         # Also fixed, kept as a spec-aligned hardening but NOT a second
         # proven bug (said plainly, not overclaimed): the "always keep
         # one spare uninitialized slot" auto-advance now mutates the
         # store only on the size-query call, not the fill call too,
         # matching the spec's own "the set of slots... is checked at the
         # time... the NULL pSlotList argument is used" (§5.5.1) and the
         # C++ engine's reference implementation (SlotManager::
         # getSlotList). Sabotage-testing this one in isolation did NOT
         # reproduce any failure — TOKEN_STORE persists across both calls
         # within a process, so the previous code's redundant re-check on
         # the fill call was, empirically, always idempotent in every
         # scenario this session could construct.
         # Separately (not a bug, a discovered dependency): softhsm2-
         # util's own --init-token flow does an internal C_Finalize/
         # C_Initialize reload within the same process to re-discover the
         # newly initialized token by serial+label — which requires
         # SOFTHSMRUST_STATE_FILE to be set for THAT invocation too, or
         # the reload legitimately loses the token it just created.
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/rustfunc"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  local statefile="$w/state.bin"
  # OPENSSL_CONF=/dev/null: same reason as mk_arena's own init-token call
  # (see its comment) — without it this would inherit whatever prior
  # arena's OPENSSL_CONF is still exported, which can make an unrelated
  # config's pkcs11-module-load-behavior=early collide with this direct
  # module load and mask a real failure behind
  # CKR_CRYPTOKI_ALREADY_INITIALIZED instead.
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label rustarm --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null || return 1
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -sign -propquery "?provider=pkcs11" -inkey "pkcs11:token=rustarm;type=private" \
      -rawin -in "$MSG" -out "$w/sig.bin" 2>/dev/null || return 1
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkey -propquery "?provider=pkcs11" -in "pkcs11:token=rustarm;type=public" \
      -pubin -pubout -out "$w/pub.pem" 2>/dev/null || return 1

  [[ -s "$w/sig.bin" && -s "$w/pub.pem" ]] || return 1
  O pkeyutl -verify -pubin -inkey "$w/pub.pem" -rawin -in "$MSG" -sigfile "$w/sig.bin"
}
run_case T15b PASS "Rust arm multi-process persistence: 4 separate processes round-trip a real ML-DSA-65 key through SOFTHSMRUST_STATE_FILE (gap ENV-2 / remediation R6+R14)" t15b

# T24d/T24e -- phase-6 R29. R9's own original goal (a Rust-arm twin of
# T24 plus a multi-process stateful-counter test) was parked on a
# genuine cross-engine parameter-set mismatch; R25 (phase 5) fixed the
# provider to read a key's real parameter set instead of assuming the
# C++ engine's own default, unblocking both -- but neither was wired
# up as a permanent test until now. Naming note (already flagged in the
# phase-5 plan's own R25 execution update): the phase-4/5 plans' text
# called these "T24b/T24c", but both IDs were already taken by the time
# R25 landed (R24's own EVP_SKEY guard, R25's own W4 case) -- using
# T24d/T24e instead, as that update already directed.
#
# Every command below carries the SAME SOFTHSMRUST_STATE_FILE +
# OPENSSL_CONF pair, matching T15b's own established pattern -- the
# Rust engine's own state is in-memory only by default (R6's opt-in
# stash-on-C_Finalize/restore-on-C_Initialize), so a single dropped env
# var on any one command loses everything the prior commands built,
# not just that one call.
t24d() {
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/rusths"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  local statefile="$w/state.bin"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label rusths --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm HSS -out "$w/k.pem" 2>/dev/null || return 1

  # Rust's own CKM_HSS_KEY_PAIR_GEN default is LMOTS_SHA256_N32_W4 (not
  # the C++ engine's W8) -- 2352 bytes is the size assert that actually
  # proves the provider read this key's real parameter set (R25)
  # rather than assuming the C++ default's 1296.
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -sign -propquery "?provider=pkcs11" -rawin \
      -inkey "pkcs11:token=rusths;type=private" -in "$MSG" -out "$w/sig.bin" 2>/dev/null || return 1
  [[ "$(stat -c%s "$w/sig.bin")" == "2352" ]] || { echo "Rust-arm HSS sig size $(stat -c%s "$w/sig.bin") != 2352"; return 1; }

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin \
      -inkey "pkcs11:token=rusths;type=public" -in "$MSG" -sigfile "$w/sig.bin" 2>/dev/null || return 1

  # sabotage: corrupted signature and wrong message must both be rejected
  cp "$w/sig.bin" "$w/tampered.bin"
  printf '\x00' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  cmp -s "$w/sig.bin" "$w/tampered.bin" && printf '\xff' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  if SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin \
      -inkey "pkcs11:token=rusths;type=public" -in "$MSG" -sigfile "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered Rust-arm HSS signature VERIFIED — verifier cannot say no"; return 1; fi
  echo "wrong message" > "$w/wrong.txt"
  if SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin \
      -inkey "pkcs11:token=rusths;type=public" -in "$w/wrong.txt" -sigfile "$w/sig.bin" >/dev/null 2>&1
  then echo "Rust-arm HSS signature verified against the WRONG message — verifier cannot say no"; return 1; fi

  # cross-implementation proof: Rust-token-signed, OpenSSL-native-LMS-verified
  # (hss_pubkey_dump/lms_xdr_verify are engine-agnostic raw-PKCS11/pure-math
  # tools -- same binaries T24 already uses, just pointed at the Rust .so)
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" "$HSS_PUBKEY_DUMP" "$RUST_ENGINE_SO" rusths "$w/pub.raw" >/dev/null 2>&1 || { echo "hss_pubkey_dump failed (Rust arm)"; return 1; }
  "$LMS_XDR_VERIFY" "$w/pub.raw" "$MSG" "$w/sig.bin" || { echo "Rust-arm cross-implementation LMS verify FAILED"; return 1; }
  if "$LMS_XDR_VERIFY" "$w/pub.raw" "$MSG" "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered Rust-arm HSS signature VERIFIED by the independent LMS implementation"; return 1; fi
  return 0
}
run_case T24d PASS "Rust-arm HSS/LMS token sign (size 2352, Rust's own LMOTS W4 default) -> token verify, both sabotage controls rejected, AND cross-verified by OpenSSL's independent native LMS implementation -- proves the provider reads the real parameter set (R9's own parked goal, unblocked by R25, remediation R29)" t24d

t24e() { # R9's own original multi-process stateful-counter goal: the
         # LMS leaf counter q must genuinely advance across two wholly
         # separate process invocations bridged only by
         # SOFTHSMRUST_STATE_FILE, and the FIRST signature must still
         # verify after the SECOND one was produced -- the one property
         # that makes a stateful signature scheme dangerous to get
         # wrong, and nothing in this provider-facing test surface
         # exercised state persistence across processes for HSS before
         # this case.
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/rusthsstate"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  local statefile="$w/state.bin"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label rustcnt --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm HSS -out "$w/k.pem" 2>/dev/null || return 1

  # process B: first signature
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -sign -propquery "?provider=pkcs11" -rawin \
      -inkey "pkcs11:token=rustcnt;type=private" -in "$MSG" -out "$w/sig1.bin" 2>/dev/null || return 1

  # process C: second signature, wholly separate invocation, same statefile
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -sign -propquery "?provider=pkcs11" -rawin \
      -inkey "pkcs11:token=rustcnt;type=private" -in "$MSG" -out "$w/sig2.bin" 2>/dev/null || return 1

  # bytes 4-8 of the BARE LMS signature (i.e. after stripping the HSS
  # u32str(Nspk) 4-byte prefix -- the same strip lms-xdr-verify.c's own
  # header documents) hold the leaf index q, big-endian. It must have
  # advanced 0 -> 1.
  q1=$(python3 -c "import sys; d=open('$w/sig1.bin','rb').read(); print(int.from_bytes(d[4:8],'big'))")
  q2=$(python3 -c "import sys; d=open('$w/sig2.bin','rb').read(); print(int.from_bytes(d[4:8],'big'))")
  [[ "$q1" == "0" ]] || { echo "first Rust-arm HSS signature q=$q1, expected 0"; return 1; }
  [[ "$q2" == "1" ]] || { echo "second Rust-arm HSS signature q=$q2, expected 1 (counter did not advance)"; return 1; }

  # process D: the FIRST signature (q=0) must still verify after the
  # SECOND signing consumed leaf q=1 -- proves the state advanced
  # forward without corrupting or replaying an already-used leaf.
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin \
      -inkey "pkcs11:token=rustcnt;type=public" -in "$MSG" -sigfile "$w/sig1.bin" 2>/dev/null || { echo "first signature (q=0) failed to verify after a second signing"; return 1; }
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin \
      -inkey "pkcs11:token=rustcnt;type=public" -in "$MSG" -sigfile "$w/sig2.bin" 2>/dev/null || { echo "second signature (q=1) failed to verify"; return 1; }
  return 0
}
run_case T24e PASS "Rust-arm HSS multi-process stateful-counter proof: leaf index q genuinely advances 0->1 across two wholly separate processes bridged only by SOFTHSMRUST_STATE_FILE, first signature still verifies after the second (R9's own original goal, remediation R29)" t24e

# T24f -- phase-6 R29. R25's own three-step fallback chain (official
# attrs -> parse CKA_VALUE -> HSS_L1_DEFAULT_SIG_SIZE constant) only had
# its first leg live-proven; R25 skipped the CKA_VALUE-parsing leg for
# want of a pre-standardization/imported-key fixture. Built one instead
# of waiting for one: hss-fallback-fixture.c creates a real public HSS
# key object holding genuine CKA_VALUE bytes but deliberately WITHOUT
# the official CKA_HSS_LEVELS/LMS_TYPE/LMOTS_TYPE attrs.
#
# Deliberately built from a W4 key (hss-w4-keygen, the same tool T24c
# already uses), not the C++ engine's own W8 default: a W4 signature is
# 2352 bytes, genuinely different from HSS_L1_DEFAULT_SIG_SIZE's own
# 1296. If verify against this attrs-less fixture only "worked" by
# coincidentally landing on the same constant both paths agree on (as
# it would for a W8 key), that would prove nothing about which fallback
# leg actually ran -- a real W4 signature verifying here is the only
# way to know the parse-from-CKA_VALUE leg genuinely engaged.
t24f() {
  local wsrc; wsrc=$(mk_arena hssfbsrc "$CPP_ENGINE_SO") && use_arena "$wsrc" || return 1
  "$HSS_W4_KEYGEN" "$CPP_ENGINE_SO" hssfbsrc || { echo "hss_w4_keygen failed"; return 1; }
  O pkeyutl -sign -rawin -inkey "pkcs11:token=hssfbsrc;type=private" -in "$MSG" -out "$wsrc/sig.bin" || return 1
  [[ "$(stat -c%s "$wsrc/sig.bin")" == "2352" ]] || { echo "source W4 sig size $(stat -c%s "$wsrc/sig.bin") != 2352"; return 1; }
  "$HSS_PUBKEY_DUMP" "$CPP_ENGINE_SO" hssfbsrc "$wsrc/pub.raw" >/dev/null 2>&1 || { echo "hss_pubkey_dump failed"; return 1; }

  # fresh, SEPARATE token: the ONLY HSS object on it is the bare fixture
  local wfix; wfix=$(mk_arena hssfallback "$CPP_ENGINE_SO") && use_arena "$wfix" || return 1
  "$HSS_FALLBACK_FIXTURE" "$CPP_ENGINE_SO" hssfallback "$wsrc/pub.raw" || { echo "hss_fallback_fixture creation failed"; return 1; }

  O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=hssfallback;type=public" -in "$MSG" -sigfile "$wsrc/sig.bin" || { echo "verify against attrs-less fallback fixture FAILED -- CKA_VALUE-parsing leg did not engage"; return 1; }

  # sabotage: the fallback path must reject a tampered signature exactly
  # like the official-attrs path already does (T24/T24c)
  cp "$wsrc/sig.bin" "$wsrc/tampered.bin"
  printf '\x00' | dd of="$wsrc/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  cmp -s "$wsrc/sig.bin" "$wsrc/tampered.bin" && printf '\xff' | dd of="$wsrc/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  use_arena "$wfix"
  if O pkeyutl -verify -rawin -pubin -inkey "pkcs11:token=hssfallback;type=public" -in "$MSG" -sigfile "$wsrc/tampered.bin" >/dev/null 2>&1
  then echo "tampered signature VERIFIED against the fallback fixture — verifier cannot say no"; return 1; fi
  return 0
}
run_case T24f PASS "HSS fallback path (parse CKA_VALUE, no official attrs) genuinely engages and computes the correct size for a non-default W4 key (2352 bytes, not the 1296 last-resort constant), sabotage rejected (R25's own untested fallback leg, remediation R29)" t24f

# ─── T28b: ML-DSA external-µ, Rust arm (remediation R34) ───────────────────
t28b() { # Rust-arm twin of T28 -- same proof, over libsofthsmrustv3.so.
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/mldsamurust"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  local statefile="$w/state.bin"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label mldsamurust --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkey -pubin -propquery "?provider=pkcs11" -in "pkcs11:token=mldsamurust;type=public" \
      -pubout -outform DER -out "$w/pub.der" 2>/dev/null || return 1
  python3 -c "
import hashlib
data = open('$w/pub.der','rb').read()
raw_pk = data[22:22+1952]
assert len(raw_pk) == 1952
tr = hashlib.shake_256(raw_pk).digest(64)
msg = b'openssl-provider harness T28b external-mu RUST message'
mu = hashlib.shake_256(tr + b'\x00' + bytes([0]) + msg).digest(64)
open('$w/mu.bin','wb').write(mu)
open('$w/msg.bin','wb').write(msg)
"

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -sign -propquery "?provider=pkcs11" -rawin -inkey "pkcs11:token=mldsamurust;type=private" \
      -pkeyopt mu:1 -in "$w/mu.bin" -out "$w/sig.bin" 2>/dev/null || { echo "Rust-arm external-µ sign failed"; return 1; }

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=mldsamurust;type=public" \
      -pkeyopt mu:1 -in "$w/mu.bin" -sigfile "$w/sig.bin" 2>/dev/null || { echo "Rust-arm external-µ verify (own mechanism) failed"; return 1; }

  OPENSSL_CONF=/dev/null O pkeyutl -verify -provider default -rawin -pubin \
    -inkey "$w/pub.der" -keyform DER -in "$w/msg.bin" -sigfile "$w/sig.bin" 2>/dev/null \
    || { echo "Rust-arm: native verify of µ-signed signature against original message failed"; return 1; }

  python3 -c "
d = bytearray(open('$w/mu.bin','rb').read()); d[0] ^= 0xff
open('$w/mu_bad.bin','wb').write(bytes(d))"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=mldsamurust;type=public" \
      -pkeyopt mu:1 -in "$w/mu_bad.bin" -sigfile "$w/sig.bin" 2>/dev/null \
      && { echo "Rust-arm: tampered µ verified -- must not"; return 1; }

  return 0
}
run_case T28b PASS "ML-DSA external-µ vendor mechanism, Rust arm: same proof as T28 over libsofthsmrustv3.so -- independently-computed µ signs, verifies via the mechanism AND OpenSSL's native implementation against the original message, tampered-µ sabotage rejected (remediation R34)" t28b

# ─── T29b: HashML-DSA digest routing, Rust arm (remediation R35) ───────────
t29b() { # Rust-arm twin of T29 -- same proof, over libsofthsmrustv3.so. No
  # Rust-engine code change was needed for this item (its own CKM_HASH_ML_DSA_*
  # dispatch already correctly hashed on token) -- this proves the provider's
  # shared C routing fix reaches both engines identically.
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/hashmldsarust"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  local statefile="$w/state.bin"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label hashmldsarust --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null || return 1
  echo "T29b HashML-DSA digest-routing RUST test message" > "$w/msg.txt"

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O dgst -sha256 -propquery "?provider=pkcs11" -sign "pkcs11:token=hashmldsarust;type=private" \
      -out "$w/sig.bin" "$w/msg.txt" 2>/dev/null || { echo "Rust-arm dgst -sha256 -sign failed"; return 1; }

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=hashmldsarust;type=public" \
      -in "$w/msg.txt" -sigfile "$w/sig.bin" 2>/dev/null \
      && { echo "Rust-arm: HashML-DSA signature verified as a plain raw-message signature -- digest silently ignored"; return 1; }

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O dgst -sha256 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashmldsarust;type=public" \
      -signature "$w/sig.bin" "$w/msg.txt" 2>/dev/null || { echo "Rust-arm HashML-DSA round-trip verify failed"; return 1; }

  echo "tampered" > "$w/msg_bad.txt"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O dgst -sha256 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashmldsarust;type=public" \
      -signature "$w/sig.bin" "$w/msg_bad.txt" 2>/dev/null \
      && { echo "Rust-arm: tampered-message verify succeeded -- must not"; return 1; }

  return 0
}
run_case T29b PASS "HashML-DSA digest routing, Rust arm: same proof as T29 over libsofthsmrustv3.so -- no engine-side change needed, proves the provider's shared routing fix reaches both engines identically; round-trip verify, tampered-message sabotage rejected (remediation R35)" t29b

# ─── T30b: HashSLH-DSA digest routing, Rust arm (remediation R36) ──────────
t30b() { # Rust-arm twin of T30 -- same proof, over libsofthsmrustv3.so.
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/hashslhdsarust"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  local statefile="$w/state.bin"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label hashslhdsarust --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHA2-128s -out "$w/k.pem" 2>/dev/null || return 1
  echo "T30b HashSLH-DSA digest-routing RUST test message" > "$w/msg.txt"

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O dgst -sha256 -propquery "?provider=pkcs11" -sign "pkcs11:token=hashslhdsarust;type=private" \
      -out "$w/sig.bin" "$w/msg.txt" 2>/dev/null || { echo "Rust-arm dgst -sha256 -sign failed"; return 1; }

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=hashslhdsarust;type=public" \
      -in "$w/msg.txt" -sigfile "$w/sig.bin" 2>/dev/null \
      && { echo "Rust-arm: HashSLH-DSA signature verified as a plain raw-message signature -- digest silently ignored"; return 1; }

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O dgst -sha256 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashslhdsarust;type=public" \
      -signature "$w/sig.bin" "$w/msg.txt" 2>/dev/null || { echo "Rust-arm HashSLH-DSA round-trip verify failed"; return 1; }

  echo "tampered" > "$w/msg_bad.txt"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O dgst -sha256 -propquery "?provider=pkcs11" -verify "pkcs11:token=hashslhdsarust;type=public" \
      -signature "$w/sig.bin" "$w/msg_bad.txt" 2>/dev/null \
      && { echo "Rust-arm: tampered-message verify succeeded -- must not"; return 1; }

  return 0
}
run_case T30b PASS "HashSLH-DSA digest routing, Rust arm: same proof as T30 over libsofthsmrustv3.so -- round-trip verify, tampered-message sabotage rejected (remediation R36)" t30b

# ─── T31b: SHAKE128/256 reachability, Rust arm (remediation R38) ───────────
t31b() { # Rust-arm twin of T31 -- same proof, over libsofthsmrustv3.so. No
  # Rust-engine code change was needed for this item either (its own
  # CKM_HASH_ML_DSA_SHAKE128/256 and CKM_HASH_SLH_DSA_SHAKE128/256 arms
  # already existed) -- this proves the provider's shared SHAKE-sentinel
  # routing fix reaches both engines identically, same as T29b/T30b.
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/shakemldsarust"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  local statefile="$w/state.bin"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label shakemldsarust --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null || return 1
  echo "T31b SHAKE256 HashML-DSA digest-routing RUST test message" > "$w/msg.txt"

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    "$SHAKE_SIGN_PROBE" sign "?provider=pkcs11" "pkcs11:token=shakemldsarust;type=private" \
      SHAKE256 "$w/msg.txt" "$w/sig.bin" 2>/dev/null || { echo "Rust-arm ML-DSA SHAKE256 sign failed"; return 1; }

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    "$SHAKE_SIGN_PROBE" verify "?provider=pkcs11" "pkcs11:token=shakemldsarust;type=public" \
      SHAKE256 "$w/msg.txt" "$w/sig.bin" 2>/dev/null || { echo "Rust-arm ML-DSA SHAKE256 round-trip verify failed"; return 1; }

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin -inkey "pkcs11:token=shakemldsarust;type=public" \
      -in "$w/msg.txt" -sigfile "$w/sig.bin" 2>/dev/null \
      && { echo "Rust-arm: ML-DSA SHAKE256 signature verified as a plain raw-message signature -- digest silently ignored"; return 1; }

  echo "tampered" > "$w/msg_bad.txt"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    "$SHAKE_SIGN_PROBE" verify "?provider=pkcs11" "pkcs11:token=shakemldsarust;type=public" \
      SHAKE256 "$w/msg_bad.txt" "$w/sig.bin" 2>/dev/null \
      && { echo "Rust-arm: ML-DSA SHAKE256 tampered-message verify succeeded -- must not"; return 1; }

  # Second algorithm family, own arena (same type=private/public ambiguity
  # reason T31 gave for its own second arena).
  local w2="$ROOT_WORK/shakeslhdsarust"; mkdir -p "$w2/tokens"; mk_rust_cnf "$w2"
  local statefile2="$w2/state.bin"
  SOFTHSM2_CONF="$w2/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile2" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label shakeslhdsarust --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile2" ]] || return 1

  SOFTHSM2_CONF="$w2/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile2" OPENSSL_CONF="$w2/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm SLH-DSA-SHAKE-128s -out "$w2/k.pem" 2>/dev/null || return 1
  cp "$w/msg.txt" "$w2/msg.txt"
  cp "$w/msg_bad.txt" "$w2/msg_bad.txt"

  SOFTHSM2_CONF="$w2/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile2" OPENSSL_CONF="$w2/openssl.cnf" \
    "$SHAKE_SIGN_PROBE" sign "?provider=pkcs11" "pkcs11:token=shakeslhdsarust;type=private" \
      SHAKE128 "$w2/msg.txt" "$w2/sig.bin" 2>/dev/null || { echo "Rust-arm SLH-DSA-SHAKE-128s SHAKE128 sign failed"; return 1; }
  [[ "$(stat -c%s "$w2/sig.bin" 2>/dev/null || stat -f%z "$w2/sig.bin")" == "7856" ]] \
    || { echo "Rust-arm: unexpected SLH-DSA-SHAKE-128s signature size"; return 1; }

  SOFTHSM2_CONF="$w2/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile2" OPENSSL_CONF="$w2/openssl.cnf" \
    "$SHAKE_SIGN_PROBE" verify "?provider=pkcs11" "pkcs11:token=shakeslhdsarust;type=public" \
      SHAKE128 "$w2/msg.txt" "$w2/sig.bin" 2>/dev/null || { echo "Rust-arm SLH-DSA-SHAKE-128s SHAKE128 round-trip verify failed"; return 1; }

  SOFTHSM2_CONF="$w2/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile2" OPENSSL_CONF="$w2/openssl.cnf" \
    "$SHAKE_SIGN_PROBE" verify "?provider=pkcs11" "pkcs11:token=shakeslhdsarust;type=public" \
      SHAKE128 "$w2/msg_bad.txt" "$w2/sig.bin" 2>/dev/null \
      && { echo "Rust-arm: SLH-DSA-SHAKE-128s tampered-message verify succeeded -- must not"; return 1; }

  return 0
}
run_case T31b PASS "SHAKE128/256 reachability, Rust arm: same proof as T31 over libsofthsmrustv3.so -- no engine-side change needed, proves the provider's shared SHAKE-sentinel routing fix reaches both engines identically; round-trip verify (both families), raw-verify-must-fail + tampered-message sabotage (remediation R38)" t31b

# ─── T32c: XMSS Rust-arm smoke (remediation R41, phase 8) ──────────────────
# T32/T32b/T32d (C++-engine XMSS/XMSS^MT proofs) live up in the C++ arm
# section, right after T31 -- this one alone belongs here since it's the
# genuinely Rust-arm case.
t32c() { # Rust-arm smoke: proves the provider's XMSS sign/signature.c dispatch
  # is genuinely engine-agnostic (raw PKCS#11 C_Sign/C_Verify), not
  # incidentally coupled to the C++ engine's own object layout -- same
  # precedent as T24d for HSS.
  [[ -n "$RUST_ENGINE_SO" ]] || return 1
  local w="$ROOT_WORK/rustxmss"; mkdir -p "$w/tokens"; mk_rust_cnf "$w"
  local statefile="$w/state.bin"
  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label rustxmss --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm XMSS -out "$w/k.pem" 2>/dev/null || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -sign -propquery "?provider=pkcs11" -rawin \
      -inkey "pkcs11:token=rustxmss;type=private" -in "$MSG" -out "$w/sig.bin" 2>/dev/null || return 1

  SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin \
      -inkey "pkcs11:token=rustxmss;type=public" -in "$MSG" -sigfile "$w/sig.bin" 2>/dev/null || return 1

  cp "$w/sig.bin" "$w/tampered.bin"
  printf '\x00' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  cmp -s "$w/sig.bin" "$w/tampered.bin" && printf '\xff' | dd of="$w/tampered.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
  if SOFTHSM2_CONF="$w/softhsm2.conf" SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -verify -propquery "?provider=pkcs11" -rawin -pubin \
      -inkey "pkcs11:token=rustxmss;type=public" -in "$MSG" -sigfile "$w/tampered.bin" >/dev/null 2>&1
  then echo "tampered Rust-arm XMSS signature VERIFIED — verifier cannot say no"; return 1; fi
  return 0
}
run_case T32c PASS "XMSS Rust-arm token sign -> token verify, sabotage control rejected -- proves the provider's XMSS dispatch is genuinely engine-agnostic (remediation R41)" t32c


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
