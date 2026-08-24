#!/usr/bin/env bash
# local-gate.sh — the pre-push validation gate for pqctoday-hsm (WP2.0).
#
# Project directive (2026-07-01): new test suites run LOCALLY, never in GitHub
# CI. This script is the single entry point that runs them. Everything a PR
# needs validated for the KMIP/CACP/policy scope runs here, on your machine,
# before you push — GitHub is not a test platform.
#
# What it runs (in order; each step must pass):
#   1. kmip  cargo test                       — ~600 unit + integration tests
#   2. kmip  cargo test -- --include-ignored  — the local-only suites CI skips
#                                               (op-layer policy conformance …)
#   3. rust  cargo test                       — softhsmrustv3 engine tests
#   4. OASIS KMIP 3.0 replay + baseline assert + staleness guard (97/0/5)
#   5. wasm  smoke.cjs                         — CACP bundle boots + round-trips
#   6. Rust engine PKCS#11 v3.2 conformance (257 checks) + report freshness
#   7. cross-engine PKCS#11 differential harness (49 scenarios vs exceptions.json)
#   8. (--cpp)  C++ ctest incl. the v3.2 compliance harness + report freshness  [opt-in, slow]
#   9. (--acvp-wasm)  20-suite ACVP wasm harness              [opt-in, slow]
#  10. (--tls-interop) §3.3.3 hybrid TLS groups vs real OpenSSL 3.6  [opt-in]
#
# Steps 6-7 (Rust PKCS#11 conformance, differential harness) were opt-in
# until 2026-08-23 — both are core PKCS#11 v3.2 evidence, and both had gone
# stale invisibly while opt-in (the Rust report 45 source-commits behind
# HEAD; the differential harness never run at all outside a manual
# invocation). --cpp stays opt-in: unlike the other two, its slow step is a
# full CMake+ctest build, not proportionate to run on every push.
#
# On success it writes .gate-ok-<HEAD-sha> (with the flag set that produced
# it) so a pre-push hook can verify the gate ran on the current commit —
# see scripts/git-hooks/pre-push, installed via scripts/install-hooks.sh.
#
# Usage:
#   bash scripts/local-gate.sh                 # core gate (steps 1-7)
#   bash scripts/local-gate.sh --cpp           # + C++ ctest
#   bash scripts/local-gate.sh --acvp-wasm     # + ACVP wasm harness
#   bash scripts/local-gate.sh --all           # everything (required before a release — see RELEASING.md)
#   RUST_CONTAINER=pqc-rust bash scripts/local-gate.sh
#
# Rust steps run inside the warm OrbStack container ($RUST_CONTAINER, default
# pqc-rust) which mounts ~/Antigravity → /ag with a prebuilt cargo cache.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_CONTAINER="${RUST_CONTAINER:-pqc-rust}"
AG_KMIP="/ag/pqctoday-hsm/kmip"
AG_RUST="/ag/pqctoday-hsm/rust"

RUN_CPP=0
RUN_ACVP_WASM=0
RUN_TLS_INTEROP=0
for arg in "$@"; do
  case "$arg" in
    --cpp) RUN_CPP=1 ;;
    --acvp-wasm) RUN_ACVP_WASM=1 ;;
    --rust-p11) : ;; # now always runs (step 6); flag kept accepted, no-op, for muscle memory
    --tls-interop) RUN_TLS_INTEROP=1 ;;
    --all) RUN_CPP=1; RUN_ACVP_WASM=1; RUN_TLS_INTEROP=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

# ── plumbing ────────────────────────────────────────────────────────────────
STEP=0
FAILED=()
say()  { printf '\n\033[1;36m[gate] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; FAILED+=("$*"); }

dexec() {
  # pipefail inside the nested shell for the same reason run_step_host sets
  # it: `docker exec ... bash -c "..."` starts a fresh shell that does not
  # inherit this script's own `set -o pipefail`, so a step whose command
  # ends in `| tail -N` or another filter would report the filter's exit
  # status, not the real command's. Central fix here covers every run_step
  # call, present and future, not just the one that already got bitten
  # (the differential harness step masked a real FATAL as PASS this way —
  # this function protects the equivalent-shaped ACVP wasm step too).
  docker exec "$RUST_CONTAINER" bash -c "set -o pipefail; $1"
}

ensure_container() {
  if ! docker exec "$RUST_CONTAINER" true 2>/dev/null; then
    say "starting container $RUST_CONTAINER"
    docker start "$RUST_CONTAINER" >/dev/null 2>&1 || {
      echo "cannot start $RUST_CONTAINER — is OrbStack running?" >&2; exit 3; }
  fi
}

run_step() { # name, command(run in container)
  STEP=$((STEP+1))
  say "step $STEP: $1"
  if dexec "$2"; then ok "$1"; else bad "$1"; fi
}

run_step_host() { # name, command(run on host) — for node/wasm steps
  STEP=$((STEP+1))
  say "step $STEP: $1"
  # pipefail: a command string ending in `| tail -N` (or any filter) must
  # report the REAL command's exit status, not the filter's — bash -c
  # starts a fresh shell that does NOT inherit this script's own `set -o
  # pipefail` (that only governs pipes run directly in THIS shell), so
  # without setting it again inside the nested shell, `real_cmd | tail -15`
  # always "succeeds" here regardless of what real_cmd actually did. Found
  # 2026-08-23: the differential harness step printed "FATAL: engine not
  # built" and was still marked PASS by this function.
  if bash -c "set -o pipefail; $2"; then ok "$1"; else bad "$1"; fi
}

# ── steps ───────────────────────────────────────────────────────────────────
ensure_container

run_step "kmip cargo test" \
  "cd $AG_KMIP && RUST_MIN_STACK=134217728 cargo test --quiet 2>&1 | grep -E 'test result: FAILED|[1-9][0-9]* failed' && exit 1; \
   RUST_MIN_STACK=134217728 cargo test --quiet 2>&1 | grep -E 'test result' | awk '{p+=\$4; f+=\$6} END {print \"  \"p\" passed, \"f\" failed\"; exit (f>0)}'"

run_step "kmip local-only suites (--include-ignored)" \
  "cd $AG_KMIP && RUST_MIN_STACK=134217728 cargo test --quiet -- --include-ignored 2>&1 | grep -E 'test result: FAILED|[1-9][0-9]* failed' && exit 1; \
   RUST_MIN_STACK=134217728 cargo test --quiet --test policy_op_layer -- --include-ignored 2>&1 | grep -E 'test result'"

run_step "rust engine cargo test" \
  "cd $AG_RUST && RUST_MIN_STACK=134217728 cargo test --quiet 2>&1 | grep -E 'test result: FAILED|[1-9][0-9]* failed' && exit 1; \
   RUST_MIN_STACK=134217728 cargo test --quiet 2>&1 | grep -E 'test result' | awk '{p+=\$4; f+=\$6} END {print \"  \"p\" passed, \"f\" failed\"; exit (f>0)}'"

# Cheap, and it runs BEFORE the replay on purpose: if the corpus is not the
# corpus we think it is, the replay figure below is measuring something else.
run_step "OASIS corpus provenance (102 transcripts vs the CSD02 zip)" \
  "cd $AG_KMIP && python3 conformance/verify_corpus_provenance.py"

run_step "OASIS KMIP 3.0 replay (97 PASS / 0 FAIL / 5 SKIP_DEPRECATED)" \
  "cd $AG_KMIP && cargo build --release --bin pqctoday-kmip --quiet && \
   mkdir -p target/release && ln -sf \$(readlink -f \${CARGO_TARGET_DIR:-/cargo-target}/release/pqctoday-kmip) target/release/pqctoday-kmip 2>/dev/null; \
   python3 conformance/harness/dispatcher_replay.py >/dev/null && \
   python3 conformance/assert_replay_report.py && \
   python3 conformance/check_report_fresh.py"

# Does the wasm target still COMPILE? The smoke step below cannot answer that:
# it runs the already-staged bundle, so a source change that breaks the wasm
# build passes the gate and only surfaces at the next restage. That is not
# hypothetical — #166 added `server/secp384r1mlkem1024.rs` (rustls, native-only)
# without a cfg gate, the whole gate went green, and the breakage was found days
# later when someone tried to rebuild the bundle. A type-check is cheap; a full
# wasm build is not, so this checks rather than builds.
run_step "wasm target still compiles (cargo check)" \
  "cd /ag/pqctoday-hsm/wasm && cargo check --quiet --release --target wasm32-unknown-unknown 2>&1 | grep -E '^error' -A6 && exit 1; echo '  wasm32 type-check clean'"

# wasm smoke runs on the HOST (node lives there, not in the Rust container).
# Runs the STAGED bundle — see the check above for why that is not sufficient on
# its own. Run scripts/build-kmip-wasm.sh after any wasm/ or kmip/ source change
# to regenerate it.
run_step_host "wasm CACP smoke" \
  "cd '$ROOT/wasm' && node smoke/smoke.cjs 2>&1 | tail -2 | grep -q 'PASS'"

# Was opt-in (--rust-p11) until 2026-08-23. The Rust engine's own conformance
# report went 45 source-commits stale while this was skippable — a default
# gate step is what stops that recurring. Builds the wasm pkg (dev + acvp +
# larger stack) in the container, drives the real PKCS#11 ABI through the
# v3.2 conformance matrix on the host. test_p11_conformance.js itself
# regenerates rust/RUST_P11_V32_CONFORMANCE_REPORT.md from this run's real
# per-section results every time it runs to completion; the freshness check
# right after confirms the regenerated report actually matches what's
# committed (or fails loudly if it doesn't — see check_pkcs11_reports_fresh.py).
STEP=$((STEP+1)); say "step $STEP: Rust PKCS#11 v3.2 conformance (257 checks)"
# wasm-pack is built but not on the container's PATH — plain `wasm-pack` here
# fails with "command not found" and always has, invisibly, because this step
# was opt-in until now. Full path, matching how it was actually invoked by
# hand before this step was promoted to default. Found 2026-08-23.
if dexec "cd $AG_RUST && RUSTFLAGS='-C link-arg=-zstack-size=2097152' /cargo-target/release/wasm-pack build --target bundler --out-dir pkg --dev -- --features acvp >/dev/null 2>&1" \
   && ( cd "$ROOT/rust" && node test_p11_conformance.js 2>&1 | grep -q 'RESULT: .* 0 failed' ) \
   && ( cd "$ROOT" && python3 scripts/check_pkcs11_reports_fresh.py --rust ); then
  ok "Rust PKCS#11 v3.2 conformance (report regenerated + fresh)"
else
  bad "Rust PKCS#11 v3.2 conformance (report regenerated regardless — check it, or check_pkcs11_reports_fresh.py, for the real failure)"
fi

# Was a manual-only tool until 2026-08-23 — never wired into any gate,
# despite being the instrument the 2026-08 remediation added specifically
# "to gate the rest from rotting." Builds BOTH engines fresh (see the
# script's own header for why that matters) and diffs every observable
# outcome across 49 scenarios; only divergences already recorded with a
# citation in tests/differential/exceptions.json are allowed.
run_step_host "cross-engine PKCS#11 differential harness (49 scenarios)" \
  "cd '$ROOT' && bash scripts/run-differential-harness.sh 2>&1 | tail -15"

if [[ $RUN_CPP == 1 ]]; then
  # Preflight. $RUST_CONTAINER is a long-lived pet container built for Rust, and
  # it shipped without cmake, ctest or cppunit — so this step failed during
  # SETUP, never reaching a single test, while looking like an ordinary build
  # error. Check for the tools and install them once rather than rediscovering
  # this. Found 2026-08-10.
  say "step $((STEP+1)) preflight: C++ toolchain in $RUST_CONTAINER"
  if ! dexec "command -v cmake >/dev/null && command -v ctest >/dev/null && pkg-config --exists cppunit" 2>/dev/null; then
    echo "  installing cmake + libcppunit-dev (one-off, container is not rebuilt)"
    dexec "apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cmake libcppunit-dev >/dev/null 2>&1" || true
  fi
  if dexec "command -v cmake >/dev/null && command -v ctest >/dev/null && pkg-config --exists cppunit" 2>/dev/null; then
    ok "C++ toolchain present ($(dexec 'cmake --version | head -1' 2>/dev/null))"
  else
    bad "C++ toolchain missing in $RUST_CONTAINER — cannot run ctest"
  fi

  # NOTE ON COVERAGE: this container is arm64 and links a RELEASE OpenSSL, while
  # CI is amd64. It therefore cannot reproduce arch- or OpenSSL-specific faults —
  # the 2026-08 EdDSA keygen flake (CI building OpenSSL master; see PR #160) was
  # invisible here by construction. Green locally is necessary, not sufficient.
  # cpp_compliance_report.{json,md} land in $ROOT (--report path below), not
  # build/ — ctest's own add_test invocation (CMakeLists.txt) writes into
  # build/ and that copy is discarded; this explicit run is what regenerates
  # the checked-in copy, with the freshness guard immediately after it.
  run_step "C++ ctest (incl. PKCS#11 v3.2 compliance harness) + report freshness" \
    "cd /ag/pqctoday-hsm && (test -d build || cmake -S . -B build -DWITH_RIPEMD160=ON >/dev/null) && \
     cmake --build build -j\$(nproc) >/dev/null && cd build && ctest --output-on-failure && \
     cd /ag/pqctoday-hsm && \
     ENGINE=./build/src/lib/libsofthsmv3.so; [ -f \"\$ENGINE\" ] || ENGINE=./build/src/lib/libsofthsmv3.dylib; \
     ./build/p11_v32_compliance_test --engine \"\$ENGINE\" \
       --workdir ./build/p11_v32_compliance_workdir --report ./cpp_compliance_report \
       --engine-commit \$(git rev-parse HEAD) >/dev/null && \
     python3 scripts/check_pkcs11_reports_fresh.py --cpp"
fi

if [[ $RUN_ACVP_WASM == 1 ]]; then
  run_step "ACVP wasm harness (20 suites, cross-engine)" \
    "cd /ag/pqctoday-hsm && npm run test:acvp 2>&1 | tail -5"
fi

if [[ $RUN_TLS_INTEROP == 1 ]]; then
  # §3.3.3 requires all three hybrid TLS groups. SecP384r1MLKEM1024 is composed
  # locally (src/server/secp384r1mlkem1024.rs) because rustls 0.23 lacks it, and
  # a locally-composed hybrid MUST be proven against an independent peer: a
  # reversed combiner agrees perfectly with itself and with nobody else. OpenSSL
  # 3.6 has the group natively, so it is that peer.
  #
  # The container ships OpenSSL 3.5.6, which has ML-KEM but NOT this hybrid, so
  # point OPENSSL_BIN at a >= 3.6 build. One way, if a container on this host has
  # one (e.g. the sandbox network image):
  #   docker exec <ossl36-container> tar -cf - -C /usr/local ssl \
  #     | docker exec -i $RUST_CONTAINER tar -xf - -C /usr/local
  # then LD_LIBRARY_PATH=/usr/local/ssl/lib OPENSSL_BIN=/usr/local/ssl/bin/openssl.
  # The test FAILS (never skips) if the tool is missing or too old.
  OSSL_BIN="${OPENSSL_BIN:-/usr/local/ssl/bin/openssl}"
  OSSL_LIB="${OPENSSL_LIB_DIR:-/usr/local/ssl/lib}"
  # `touch` first: cargo has missed source changes across this bind mount, and a
  # stale binary once made a deliberately-sabotaged combiner report all-green.
  run_step "§3.3.3 hybrid TLS groups vs OpenSSL 3.6" \
    "cd $AG_KMIP && touch src/server/secp384r1mlkem1024.rs && \
     LD_LIBRARY_PATH=$OSSL_LIB OPENSSL_BIN=$OSSL_BIN RUST_MIN_STACK=134217728 \
     cargo test --quiet --test secp384r1mlkem1024_interop -- --ignored --test-threads=1"
fi

# ── verdict ─────────────────────────────────────────────────────────────────
echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
  HEAD_SHA="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  MARKER="$ROOT/.gate-ok-$HEAD_SHA"
  FLAGS="core"
  [[ $RUN_CPP == 1 ]] && FLAGS="$FLAGS,cpp"
  [[ $RUN_ACVP_WASM == 1 ]] && FLAGS="$FLAGS,acvp-wasm"
  [[ $RUN_TLS_INTEROP == 1 ]] && FLAGS="$FLAGS,tls-interop"
  {
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "flags: $FLAGS"
    echo "steps: $STEP"
  } > "$MARKER"
  printf '\033[1;32m[gate] ALL %d STEPS PASSED\033[0m  (marker: .gate-ok-%s, flags: %s)\n' "$STEP" "$HEAD_SHA" "$FLAGS"
  exit 0
else
  printf '\033[1;31m[gate] %d/%d STEP(S) FAILED:\033[0m\n' "${#FAILED[@]}" "$STEP"
  printf '   - %s\n' "${FAILED[@]}"
  exit 1
fi
