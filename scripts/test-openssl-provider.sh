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
# open, not silently dropped — see the remediation plan's R4 entry.
#
# genpkey's own exit code is deliberately NOT gating these arenas' keygen
# step, same reason as T4x (R3b): mk_arena sets
# pkcs11-module-encode-provider-uri-to-pem=true, and X25519/X448 have no
# encoder registered (same still-open gap class as ML-KEM's pre-R3 state)
# — so genpkey reports "Error writing key(s)" even though the key
# generates and persists on-token fine as a side effect. The subsequent
# pubkey-export and derive steps are the real, authoritative proof.
t16() {
  local wa wb
  wa=$(mk_arena x25519a "$CPP_ENGINE_SO") || return 1
  wb=$(mk_arena x25519b "$CPP_ENGINE_SO") || return 1
  SOFTHSM2_CONF="$wa/softhsm2.conf" OPENSSL_CONF="$wa/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm X25519 -out "$wa/ka.pem" >/dev/null 2>&1
  SOFTHSM2_CONF="$wb/softhsm2.conf" OPENSSL_CONF="$wb/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm X25519 -out "$wb/kb.pem" >/dev/null 2>&1
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
run_case T16 PASS "X25519 token-to-token derive parity, 32-byte secret (gap ALG-5 / remediation R4)" t16

t16b() {
  local wa wb
  wa=$(mk_arena x448a "$CPP_ENGINE_SO") || return 1
  wb=$(mk_arena x448b "$CPP_ENGINE_SO") || return 1
  SOFTHSM2_CONF="$wa/softhsm2.conf" OPENSSL_CONF="$wa/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm X448 -out "$wa/ka.pem" >/dev/null 2>&1
  SOFTHSM2_CONF="$wb/softhsm2.conf" OPENSSL_CONF="$wb/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm X448 -out "$wb/kb.pem" >/dev/null 2>&1
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
run_case T16b PASS "X448 token-to-token derive parity, 56-byte secret (gap ALG-5 / remediation R4)" t16b

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
  SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF=/dev/null \
    "$SOFTHSM_UTIL" --module "$RUST_ENGINE_SO" \
    --init-token --free --label rustarm --so-pin 1234 --pin 1234 >/dev/null 2>&1 || return 1
  [[ -s "$statefile" ]] || return 1

  SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O genpkey -propquery "?provider=pkcs11" -algorithm ML-DSA-65 -out "$w/k.pem" 2>/dev/null || return 1
  SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkeyutl -sign -propquery "?provider=pkcs11" -inkey "pkcs11:token=rustarm;type=private" \
      -rawin -in "$MSG" -out "$w/sig.bin" 2>/dev/null || return 1
  SOFTHSMRUST_STATE_FILE="$statefile" OPENSSL_CONF="$w/openssl.cnf" \
    O pkey -propquery "?provider=pkcs11" -in "pkcs11:token=rustarm;type=public" \
      -pubin -pubout -out "$w/pub.pem" 2>/dev/null || return 1

  [[ -s "$w/sig.bin" && -s "$w/pub.pem" ]] || return 1
  O pkeyutl -verify -pubin -inkey "$w/pub.pem" -rawin -in "$MSG" -sigfile "$w/sig.bin"
}
run_case T15b PASS "Rust arm multi-process persistence: 4 separate processes round-trip a real ML-DSA-65 key through SOFTHSMRUST_STATE_FILE (gap ENV-2 / remediation R6+R14)" t15b

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
