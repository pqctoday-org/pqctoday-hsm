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
COMPOSITE_PROBE="${COMPOSITE_PROBE:-$HSM_ROOT/build/composite_sig_probe}"
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
for f in "$PROVIDER_SO" "$CPP_ENGINE_SO" "$SOFTHSM_UTIL" "$COMPOSITE_PROBE"; do
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
