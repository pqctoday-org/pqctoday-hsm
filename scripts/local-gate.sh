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
#   4. OASIS KMIP 3.0 replay + baseline assert + staleness guard (92/0/10)
#   5. wasm  smoke.cjs                         — CACP bundle boots + round-trips
#   6. (--cpp)  C++ ctest incl. the v3.2 compliance harness  [opt-in, slow]
#   7. (--acvp-wasm)  20-suite ACVP wasm harness              [opt-in, slow]
#   8. (--rust-p11)  Rust engine PKCS#11 v3.2 conformance (188 checks) [opt-in]
#
# On success it writes .gate-ok-<HEAD-sha> so a pre-push hook can verify the
# gate ran on the current commit.
#
# Usage:
#   bash scripts/local-gate.sh                 # core gate (steps 1-5)
#   bash scripts/local-gate.sh --cpp           # + C++ ctest
#   bash scripts/local-gate.sh --acvp-wasm     # + ACVP wasm harness
#   bash scripts/local-gate.sh --all           # everything
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
RUN_RUST_P11=0
for arg in "$@"; do
  case "$arg" in
    --cpp) RUN_CPP=1 ;;
    --acvp-wasm) RUN_ACVP_WASM=1 ;;
    --rust-p11) RUN_RUST_P11=1 ;;
    --all) RUN_CPP=1; RUN_ACVP_WASM=1; RUN_RUST_P11=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

# ── plumbing ────────────────────────────────────────────────────────────────
STEP=0
FAILED=()
say()  { printf '\n\033[1;36m[gate] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; FAILED+=("$*"); }

dexec() { docker exec "$RUST_CONTAINER" bash -c "$1"; }

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
  if bash -c "$2"; then ok "$1"; else bad "$1"; fi
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

run_step "OASIS KMIP 3.0 replay (92/0/10)" \
  "cd $AG_KMIP && cargo build --release --bin pqctoday-kmip --quiet && \
   mkdir -p target/release && ln -sf \$(readlink -f \${CARGO_TARGET_DIR:-/cargo-target}/release/pqctoday-kmip) target/release/pqctoday-kmip 2>/dev/null; \
   python3 conformance/harness/dispatcher_replay.py >/dev/null && \
   python3 conformance/assert_replay_report.py && \
   python3 conformance/check_report_fresh.py"

# wasm smoke runs on the HOST (node lives there, not in the Rust container).
# Assumes the bundle is current; run scripts/build-kmip-wasm.sh after any wasm/
# or kmip/ source change to regenerate it first.
run_step_host "wasm CACP smoke" \
  "cd '$ROOT/wasm' && node smoke/smoke.cjs 2>&1 | tail -2 | grep -q 'PASS'"

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
  run_step "C++ ctest (incl. PKCS#11 v3.2 compliance harness)" \
    "cd /ag/pqctoday-hsm && (test -d build || cmake -S . -B build -DWITH_RIPEMD160=ON >/dev/null) && \
     cmake --build build -j\$(nproc) >/dev/null && cd build && ctest --output-on-failure"
fi

if [[ $RUN_ACVP_WASM == 1 ]]; then
  run_step "ACVP wasm harness (20 suites, cross-engine)" \
    "cd /ag/pqctoday-hsm && npm run test:acvp 2>&1 | tail -5"
fi

if [[ $RUN_RUST_P11 == 1 ]]; then
  # Build the Rust engine's wasm pkg (dev + acvp + larger stack) then drive its
  # real PKCS#11 ABI through the v3.2 conformance matrix. This is the Rust-engine
  # conformance evidence (report gap P2/T1) — the wasm build runs in the
  # container, the node driver on the host.
  STEP=$((STEP+1)); say "step $STEP: Rust PKCS#11 v3.2 conformance (188 checks)"
  if dexec "cd $AG_RUST && RUSTFLAGS='-C link-arg=-zstack-size=2097152' wasm-pack build --target bundler --out-dir pkg --dev -- --features acvp >/dev/null 2>&1" \
     && ( cd "$ROOT/rust" && node test_p11_conformance.js 2>&1 | grep -q 'RESULT: .* 0 failed' ); then
    ok "Rust PKCS#11 v3.2 conformance"
  else
    bad "Rust PKCS#11 v3.2 conformance"
  fi
fi

# ── verdict ─────────────────────────────────────────────────────────────────
echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
  HEAD_SHA="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  MARKER="$ROOT/.gate-ok-$HEAD_SHA"
  : > "$MARKER"
  printf '\033[1;32m[gate] ALL %d STEPS PASSED\033[0m  (marker: .gate-ok-%s)\n' "$STEP" "$HEAD_SHA"
  exit 0
else
  printf '\033[1;31m[gate] %d/%d STEP(S) FAILED:\033[0m\n' "${#FAILED[@]}" "$STEP"
  printf '   - %s\n' "${FAILED[@]}"
  exit 1
fi
