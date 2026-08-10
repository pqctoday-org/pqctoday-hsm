#!/usr/bin/env bash
# Runs the IETF MLS gating tests pqctoday-vs-{openmls,mls-rs} and writes
# each JSON report into interop/reports/.
#
# Usage:
#   ./run-gating-tests.sh             # all known healthy peers
#   ./run-gating-tests.sh openmls     # only pqctoday-vs-openmls
#   ./run-gating-tests.sh openmls mls-rs
#
# Output naming: reports/{peer}_{scenario}_{UTC-timestamp}.json

set -e
cd "$(dirname "$0")"

REPORTS_DIR="reports"
mkdir -p "$REPORTS_DIR"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SCENARIOS="welcome_join commit external_join"

# Of those, only these may FAIL THE BUILD. Measured 2026-08-09/10 on the first
# real runs of this rig:
#
#   welcome_join   72/72 against openmls, including 32 cross-vendor. Clean.
#   commit         78/872 — and 792 of the failures are one error,
#                  "stream terminated by RST"
#   external_join  8/96 on suites 1-2, same error
#
# That error is not a protocol disagreement. It is OPENMLS'S OWN interop client
# crashing:
#
#   thread 'tokio-rt-worker' panicked at interop_client/src/main.rs:255:45:
#   called `Result::unwrap()` on an `Err` value: PoisonError { .. }
#
# — i.e. `self.groups.lock().unwrap()` on a mutex an earlier panic poisoned, so
# every subsequent request panics and the stream resets. Our client logged zero
# panics across the same run.
#
# Gating on someone else's crash would make the build red for a defect we
# cannot fix and did not cause. They still RUN, because a genuine regression on
# our side would show up as a different error and is worth seeing.
GATING_SCENARIOS="${GATING_SCENARIOS:-welcome_join}"

# ── Ciphersuites we actually support ─────────────────────────────────────────
# Measured 2026-08-09 on the first real run of this rig, not assumed. Suites
# 1-3 pass; 4-7 fail with "HSM signer gen: UnsupportedSignatureScheme" — a
# capability gap in our signer, NOT an interop defect (they fail with our own
# client on BOTH sides of the test).
#
# Why this has to be stated explicitly: the WG runner negotiates the
# INTERSECTION of what the two clients advertise. Against openmls, which
# advertises 1-3, suites 4-7 are never attempted and everything passes.
# Against mls-rs, which advertises more, the runner reaches into 4-7 and we
# fail 32 cases. Same client, same code — the peer's capability list decides
# whether our gap is visible. Pinning the set here makes the gate measure what
# we claim to support instead of whatever the peer happens to offer.
#
# The mapping, CONFIRMED 2026-08-10 against two independent implementations
# (openmls traits/src/types.rs and mls-rs-core/src/crypto/cipher_suite.rs,
# which agree exactly) rather than recalled:
#
#   1  X25519 / AES-128-GCM / SHA-256 / Ed25519          SUPPORTED
#   2  P-256  / AES-128-GCM / SHA-256 / ECDSA P-256      SUPPORTED
#   3  X25519 / ChaCha20    / SHA-256 / Ed25519          SUPPORTED
#   4  X448   / AES-256-GCM / SHA-512 / Ed448            missing: Ed448
#   5  P-521  / AES-256-GCM / SHA-512 / ECDSA P-521      missing: P-521
#   6  X448   / ChaCha20    / SHA-512 / Ed448            missing: Ed448
#   7  P-384  / AES-256-GCM / SHA-384 / ECDSA P-384      missing: P-384
#
# So the gap is exactly three signature schemes — Ed448, ECDSA P-521 and
# ECDSA P-384 — not seven unrelated problems. Adding Ed448 alone would close
# suites 4 and 6.
#
# WORTH KNOWING for this project specifically: MLS now has PQC ciphersuites,
# behind openmls's `draft-ietf-mls-pq-ciphersuites` feature —
# MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 (0x0906) and an X-Wing suite
# (0x004D). ML-KEM-1024 and ML-DSA-87 are algorithms this HSM already
# implements, so the interesting question is not really Ed448; it is whether
# this rig should be testing the PQC suites, which is the whole point of the
# engine underneath it.
SUITES="${SUITES:-1 2 3}"

# ── Peers that gate, versus peers that report ────────────────────────────────
# openmls GATES: 72/72 including 32 cross-vendor, measured 2026-08-09.
#
# mls-rs REPORTS ONLY. Even restricted to suites 1-3 it fails ~28 cases, and
# the cause is a policy difference the RFC explicitly permits rather than a bug
# on either side: openmls (which backs our client) rejects any key package
# whose total lifetime exceeds ~84 days, and mls-rs issues them lasting a year.
# RFC 9420 requires every application to choose a maximum and enforce it, and
# deliberately does not say what the value should be. Both are compliant.
#
# It is kept running because the result is real signal — cross-vendor cases DO
# pass under that ceiling — but it must not fail the build for a disagreement
# neither implementation is wrong about. See
# mls-interop-failure-triage-08092026.md.
GATING_PEERS="${GATING_PEERS:-openmls}"

peer_addr() {
  case "$1" in
    openmls) echo "openmls:50051" ;;
    mls-rs)  echo "mls-rs:50054" ;;
    *)       echo "" ;;
  esac
}

PEERS="$*"
if [ -z "$PEERS" ]; then
  PEERS="openmls mls-rs"
fi

PASSED=0
FAILED=0
SKIPPED=0
REPORTED=0

for peer in $PEERS; do
  addr="$(peer_addr "$peer")"
  if [ -z "$addr" ]; then
    echo "Unknown peer '$peer'; valid: openmls mls-rs"
    exit 2
  fi
  if ! docker compose -f docker/docker-compose.yml ps "$peer" 2>/dev/null | grep -q "healthy"; then
    echo "  skip pqctoday vs $peer (service not healthy)"
    for s in $SCENARIOS; do SKIPPED=$((SKIPPED + 1)); done
    continue
  fi

  # Is this peer allowed to fail the build?
  peer_gates=no
  for g in $GATING_PEERS; do [ "$g" = "$peer" ] && peer_gates=yes; done

  for scenario in $SCENARIOS; do
    # ...and is this scenario allowed to?
    scen_gates=no
    for g in $GATING_SCENARIOS; do [ "$g" = "$scenario" ] && scen_gates=yes; done
    gating=no
    [ "$peer_gates" = "yes" ] && [ "$scen_gates" = "yes" ] && gating=yes

    # Restart the peer before each scenario. openmls's interop client poisons
    # its own mutex on the first panic (see GATING_SCENARIOS above) and STAYS
    # poisoned for the life of the container, so every later request fails
    # regardless of what it is testing. Without this, results depend on the
    # ORDER scenarios happen to run in: welcome_join passed 72/72 first, then
    # failed outright when it ran after commit had crashed the peer. A gate
    # whose answer depends on run order is not measuring anything.
    docker compose -f docker/docker-compose.yml restart "$peer" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
      docker compose -f docker/docker-compose.yml ps "$peer" 2>/dev/null | grep -q healthy && break
      sleep 1
    done

    for suite in $SUITES; do
      out="$REPORTS_DIR/${peer}_${scenario}_cs${suite}_${TIMESTAMP}.json"
      echo "==> pqctoday vs $peer / $scenario / ciphersuite $suite  ($out)"
      if docker compose -f docker/docker-compose.yml run --rm --no-deps -T test-runner \
           -client pqctoday:50053 -client "$addr" -suite "$suite" \
           -config "/configs/${scenario}.json" \
           > "$out" 2>&1; then
        echo "    PASS"
        PASSED=$((PASSED + 1))
      else
        ec=$?
        if [ "$gating" = "yes" ]; then
          echo "    FAIL (exit $ec)"
          FAILED=$((FAILED + 1))
        else
          echo "    FAIL (exit $ec) — reported, not gating (see GATING_PEERS above)"
          REPORTED=$((REPORTED + 1))
        fi
      fi
    done
  done
done

echo ""
echo "Summary: $PASSED passed, $FAILED failed (gating), $REPORTED failed (reported only), $SKIPPED skipped"
echo "Ciphersuites: $SUITES   Gating peers: $GATING_PEERS   Gating scenarios: $GATING_SCENARIOS"
exit $FAILED
