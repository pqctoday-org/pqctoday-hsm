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
#  10. (--release-xmss) XMSS/XMSS^MT round trip vs RELEASE wasm build  [opt-in, ~15s]
#  11. (--tls-interop) §3.3.3 hybrid TLS groups vs real OpenSSL 3.6  [opt-in]
#  12. (--javajce) JavaJCE provider suite (mvn test) in pqc-dev-sandbox  [opt-in]
#  13. (--javajce-remote) JavaJCE-remote gRPC provider suite vs live pqc-grpc  [opt-in]
#  14. (--openssl-provider) vendored pkcs11-provider vs real OpenSSL 3.6, both
#                            engines (26 PASS / 0 FAIL / 1 XFAIL / 0 XPASS)  [opt-in]
#
# Steps 6-7 (Rust PKCS#11 conformance, differential harness) were opt-in
# until 2026-08-23 — both are core PKCS#11 v3.2 evidence, and both had gone
# stale invisibly while opt-in (the Rust report 45 source-commits behind
# HEAD; the differential harness never run at all outside a manual
# invocation). --cpp stays opt-in: unlike the other two, its slow step is a
# full CMake+ctest build, not proportionate to run on every push. --javajce
# stays opt-in too, for a different reason (plan
# docs/implementation-plan-jca-remaining-gaps-2026-08-25.md §WS-F): it needs
# a second container ($SANDBOX_CONTAINER, pqc-dev-sandbox — JDK 27 RC, a
# different glibc than $RUST_CONTAINER, so binaries are NOT interchangeable
# between them, see JavaJCE/README.md), which not every gate run has
# available — FAIL-never-skip semantics when the flag IS passed, matching
# --tls-interop's own precedent.
#
# --javajce-remote (plan §7, WS-E) is separate from --javajce, not folded
# into it: it exercises the gRPC client module (JavaJCE-remote/) against a
# genuinely running pqc-grpc server over real mTLS — a network-dependent
# integration suite, not the local-FFM unit suite --javajce runs. It needs
# BOTH $SANDBOX_CONTAINER (JDK 27 RC, same reason as --javajce) AND the
# pqc-grpc/admin-certs stack from pqctoday-sandbox's docker-compose.yml
# already up — checked explicitly below and failed loudly (not skipped)
# if pqc-grpc isn't reachable, same FAIL-never-skip semantics.
#
# On success it writes .gate-ok-<HEAD-sha> (with the flag set that produced
# it) so a pre-push hook can verify the gate ran on the current commit —
# see scripts/git-hooks/pre-push, installed via scripts/install-hooks.sh.
#
# Usage:
#   bash scripts/local-gate.sh                 # core gate (steps 1-7)
#   bash scripts/local-gate.sh --cpp           # + C++ ctest
#   bash scripts/local-gate.sh --acvp-wasm     # + ACVP wasm harness
#   bash scripts/local-gate.sh --release-xmss  # + XMSS/XMSS^MT vs release wasm build
#   bash scripts/local-gate.sh --javajce       # + JavaJCE provider suite (needs pqc-dev-sandbox)
#   bash scripts/local-gate.sh --javajce-remote  # + JavaJCE-remote suite (needs pqc-dev-sandbox + live pqc-grpc)
#   bash scripts/local-gate.sh --all           # everything (required before a release — see RELEASING.md)
#   RUST_CONTAINER=pqc-rust bash scripts/local-gate.sh
#
# Rust steps run inside the warm OrbStack container ($RUST_CONTAINER, default
# pqc-rust) which mounts ~/Antigravity → /ag with a prebuilt cargo cache.
# The --javajce step runs inside a SEPARATE container ($SANDBOX_CONTAINER,
# default pqc-dev-sandbox) instead — that is where JDK 27 actually lives.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_CONTAINER="${RUST_CONTAINER:-pqc-rust}"
SANDBOX_CONTAINER="${SANDBOX_CONTAINER:-pqc-dev-sandbox}"
AG_KMIP="/ag/pqctoday-hsm/kmip"
AG_RUST="/ag/pqctoday-hsm/rust"
JAVAJCE_DIR="$ROOT/JavaJCE"
JAVAJCE_REMOTE_DIR="$ROOT/JavaJCE-remote"

RUN_CPP=0
RUN_ACVP_WASM=0
RUN_TLS_INTEROP=0
RUN_RELEASE_XMSS=0
RUN_JAVAJCE=0
RUN_JAVAJCE_REMOTE=0
RUN_OPENSSL_PROVIDER=0
for arg in "$@"; do
  case "$arg" in
    --cpp) RUN_CPP=1 ;;
    --acvp-wasm) RUN_ACVP_WASM=1 ;;
    --rust-p11) : ;; # now always runs (step 6); flag kept accepted, no-op, for muscle memory
    --tls-interop) RUN_TLS_INTEROP=1 ;;
    --release-xmss) RUN_RELEASE_XMSS=1 ;;
    --javajce) RUN_JAVAJCE=1 ;;
    --javajce-remote) RUN_JAVAJCE_REMOTE=1 ;;
    --openssl-provider) RUN_OPENSSL_PROVIDER=1 ;;
    --all) RUN_CPP=1; RUN_ACVP_WASM=1; RUN_TLS_INTEROP=1; RUN_RELEASE_XMSS=1; RUN_JAVAJCE=1; RUN_JAVAJCE_REMOTE=1; RUN_OPENSSL_PROVIDER=1 ;;
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

# $SANDBOX_CONTAINER (pqc-dev-sandbox) is a DIFFERENT container than
# $RUST_CONTAINER — different glibc, JDK 27 RC lives only here — so this is
# a separate exec/ensure pair, not a parameter on the existing ones. See
# JavaJCE/README.md and the --javajce header comment above for why a
# binary built in one container cannot simply run in the other.
dexec_sandbox() {
  docker exec "$SANDBOX_CONTAINER" bash -c "set -o pipefail; $1"
}

ensure_sandbox_container() {
  if ! docker exec "$SANDBOX_CONTAINER" true 2>/dev/null; then
    say "starting container $SANDBOX_CONTAINER"
    docker start "$SANDBOX_CONTAINER" >/dev/null 2>&1 || {
      echo "cannot start $SANDBOX_CONTAINER — is OrbStack running?" >&2; exit 3; }
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
  #
  # OpenSSL >= 3.6 is required to even COMPILE now, not just for
  # --tls-interop's own proof below: src/vendor/pkcs11-provider's ML-KEM
  # CMS-decrypt code (commit 2cca4f0) uses
  # OSSL_PKEY_PARAM_CMS_RI_TYPE/CMS_RECIPINFO_KEM — real OpenSSL RFC 9629
  # KEMRecipientInfo support that landed in 3.6, confirmed absent from
  # 3.5.6's own headers (undeclared-identifier compile errors, not a
  # warning — found live running the real --all gate, 2026-08-25). Same
  # env-var override pattern and default path as --tls-interop below, so
  # a host that already staged that build for TLS interop needs no extra
  # setup. -DBUILD_TESTS=ON is also required and was previously missing
  # here entirely — CMakeLists.txt defaults it OFF, so this step only
  # ever found tests because a stale, undocumented `build/` from long ago
  # happened to have it cached; the `test -d build ||` guard below means
  # a truly fresh checkout would have silently found zero tests.
  OSSL_ROOT="${OPENSSL_ROOT_DIR:-/usr/local/ssl}"
  OSSL_LIB="${OPENSSL_LIB_DIR:-/usr/local/ssl/lib}"
  run_step "C++ ctest (incl. PKCS#11 v3.2 compliance harness) + report freshness" \
    "cd /ag/pqctoday-hsm && (test -d build || cmake -S . -B build -DWITH_RIPEMD160=ON -DBUILD_TESTS=ON -DOPENSSL_ROOT_DIR=$OSSL_ROOT >/dev/null) && \
     LD_LIBRARY_PATH=$OSSL_LIB cmake --build build -j\$(nproc) >/dev/null && cd build && LD_LIBRARY_PATH=$OSSL_LIB ctest --output-on-failure && \
     cd /ag/pqctoday-hsm && \
     ENGINE=./build/src/lib/libsofthsmv3.so; [ -f \"\$ENGINE\" ] || ENGINE=./build/src/lib/libsofthsmv3.dylib; \
     LD_LIBRARY_PATH=$OSSL_LIB ./build/p11_v32_compliance_test --engine \"\$ENGINE\" \
       --workdir ./build/p11_v32_compliance_workdir --report ./cpp_compliance_report \
       --engine-commit \$(git rev-parse HEAD) >/dev/null && \
     python3 scripts/check_pkcs11_reports_fresh.py --cpp"
fi

if [[ $RUN_OPENSSL_PROVIDER == 1 ]]; then
  # Coverage harness for the vendored OpenSSL provider (src/vendor/pkcs11-provider)
  # against BOTH PKCS#11 engines under the real OpenSSL 3.6.3 oracle. Design
  # record: docs/openssl-provider-coverage-audit-2026-08-25.md (§5/§6);
  # remediation priorities: docs/openssl-provider-remediation-plan-2026-08-25.md.
  # Reuses --cpp's build artifacts (provider .so + C++ engine .so); does NOT
  # force RUN_CPP itself — same FAIL-never-skip precedent as --tls-interop:
  # if the build is absent, the harness's own T0 preflight fails loudly with
  # a clear "run the --cpp gate step / cmake build first" message rather than
  # silently skipping.
  run_step "OpenSSL provider coverage (26 PASS / 0 FAIL / 1 XFAIL / 0 XPASS)" \
    "cd /ag/pqctoday-hsm && bash scripts/test-openssl-provider.sh"
fi

if [[ $RUN_ACVP_WASM == 1 ]]; then
  run_step "ACVP wasm harness (20 suites, cross-engine)" \
    "cd /ag/pqctoday-hsm && npm run test:acvp 2>&1 | tail -5"
fi

if [[ $RUN_RELEASE_XMSS == 1 ]]; then
  # P-1 (formalized 2026-08-24) — XMSS/XMSS^MT keygen+sign+verify against
  # the RELEASE wasm build, where it is genuinely fast (~4.6s / ~6.8s total)
  # rather than the ~80s+ the main conformance harness measured against its
  # own --dev build (see that harness's own G7 section comment for why THAT
  # build stays untested by default). Builds pkg-release/ fresh on the HOST
  # (wasm-pack + rustup, not the Linux container — build-wasm-bundle.sh is
  # tied to $HOME/.rustup) before running the round trip.
  run_step_host "XMSS/XMSS^MT round trip vs release wasm build (P-1)" \
    "cd '$ROOT/rust' && ./build-wasm-bundle.sh >/dev/null 2>&1 && node test_xmss_release.js 2>&1 | tail -25"
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

if [[ $RUN_JAVAJCE == 1 ]]; then
  # JDK 27's javax.crypto.KDF (JEP 478) and the JEP 527 TLS 1.3 hybrid-KEM
  # path this provider bridges to both need the JDK 27 RC — only
  # $SANDBOX_CONTAINER has it, so this step syncs source in fresh each
  # run (docker cp, not a bind mount — same flow used throughout the
  # provider's own development, see the implementation plan docs) rather
  # than assuming a stale prior copy is still current.
  STEP=$((STEP+1)); say "step $STEP: JavaJCE provider suite (mvn test, pqc-dev-sandbox)"
  ensure_sandbox_container
  GATE_DEST=/tmp/hsm-javajce-gate
  # Maven emits real ANSI color escapes even under `docker exec` with no
  # TTY (confirmed live — `[INFO]` is genuinely `\x1b[1;34mINFO\x1b[m]` on
  # the wire, not just a terminal-rendering artifact) — strip them before
  # writing the log so both this grep and a human reading the file later
  # see plain text, not escape-code noise wrapping the very line being
  # matched against.
  # `rm -rf $GATE_DEST/JavaJCE` (the WHOLE thing, not just target/) before
  # the copy — real bug caught by a sabotage test while writing this step:
  # `docker cp SRC container:DEST` copies SRC AS A SUBDIRECTORY of DEST
  # when DEST already exists (rather than overwriting DEST's contents in
  # place), so a second run without this would silently nest the new
  # source under the stale prior copy and test THAT instead — a false
  # green that would have gone undetected without deliberately re-running
  # with a flipped assertion first.
  # The success grep below must match ONLY the final aggregate summary
  # line, not one of the 25 per-suite "Tests run: N, Failures: 0..." lines
  # Surefire prints along the way (real bug caught live: an early version
  # of this pattern had no end-anchor, so it happily matched any passing
  # suite's own line even when a LATER suite failed and the real
  # aggregate read "Failures: 1" — a sabotage test with one flipped
  # assertion still reported green until this was anchored). The
  # aggregate line is the only one with no trailing
  # ", Time elapsed: ... -- in <ClassName>" text, hence the `$` anchor;
  # it is tagged [ERROR] instead of [INFO] on a real failure, hence
  # matching either prefix (a genuine failure still won't match the
  # "Failures: 0" requirement itself).
  AGG_PATTERN='^\[(INFO|ERROR)\][[:space:]]+Tests run: [0-9]+, Failures: 0, Errors: 0, Skipped: [0-9]+$'
  if dexec_sandbox "rm -rf $GATE_DEST/JavaJCE && mkdir -p $GATE_DEST" \
     && docker cp "$JAVAJCE_DIR" "$SANDBOX_CONTAINER:$GATE_DEST/JavaJCE" >/dev/null 2>&1 \
     && dexec_sandbox "cd $GATE_DEST/JavaJCE && \
          export JAVA_HOME=/usr/lib/jvm/jdk-27-rc && export PATH=\$JAVA_HOME/bin:\$PATH && \
          mvn -o test 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' > /tmp/javajce-gate.log; \
          grep -E '$AGG_PATTERN' /tmp/javajce-gate.log >/dev/null"; then
    ok "JavaJCE provider suite ($(dexec_sandbox "grep -E '$AGG_PATTERN' /tmp/javajce-gate.log | tail -1"))"
  else
    bad "JavaJCE provider suite — see /tmp/javajce-gate.log inside $SANDBOX_CONTAINER for the real failure"
  fi
fi

if [[ $RUN_JAVAJCE_REMOTE == 1 ]]; then
  # Unlike --javajce (local FFM, no network), this step's whole point is a
  # real network round trip against the live pqc-grpc server over real
  # mTLS — same "run it for real, never mock" discipline as
  # remoting/acceptance/tests/three_way_parity.rs on the Rust side. That
  # server isn't part of $SANDBOX_CONTAINER itself (it's the pqc-grpc
  # container from pqctoday-sandbox's docker-compose.yml, reached over the
  # shared playground-network) — checked explicitly so a missing stack
  # fails loudly with a clear reason instead of a confusing mvn stack
  # trace three steps later.
  STEP=$((STEP+1)); say "step $STEP: JavaJCE-remote gRPC provider suite (mvn test, pqc-dev-sandbox, live pqc-grpc)"
  ensure_sandbox_container
  if ! dexec_sandbox "getent hosts pqc-grpc >/dev/null 2>&1"; then
    bad "JavaJCE-remote provider suite — pqc-grpc is not reachable from $SANDBOX_CONTAINER (start it: cd pqctoday-sandbox && docker compose up -d pqc-grpc)"
  elif ! dexec_sandbox "[[ -f /admin-certs/client.crt && -f /admin-certs/client.key && -f /admin-certs/ca.crt ]]"; then
    bad "JavaJCE-remote provider suite — /admin-certs mTLS material missing inside $SANDBOX_CONTAINER"
  else
    GATE_DEST_REMOTE=/tmp/hsm-javajce-remote-gate
    # protoSourceRoot in JavaJCE-remote/pom.xml is ../remoting/proto/proto
    # (consumed verbatim from the real Rust schema, never copied into the
    # module's own tree — see that pom's own header comment) — staged at
    # the matching relative path here, same fix as the original ad-hoc
    # staging bug (a bare parent dir doesn't exist by default under
    # docker cp; the intermediate dirs must be made first).
    if dexec_sandbox "rm -rf $GATE_DEST_REMOTE && mkdir -p $GATE_DEST_REMOTE/remoting/proto/proto" \
       && docker cp "$JAVAJCE_DIR" "$SANDBOX_CONTAINER:$GATE_DEST_REMOTE/JavaJCE" >/dev/null 2>&1 \
       && docker cp "$JAVAJCE_REMOTE_DIR" "$SANDBOX_CONTAINER:$GATE_DEST_REMOTE/JavaJCE-remote" >/dev/null 2>&1 \
       && docker cp "$ROOT/remoting/proto/proto/pkcs11_remote.proto" \
            "$SANDBOX_CONTAINER:$GATE_DEST_REMOTE/remoting/proto/proto/pkcs11_remote.proto" >/dev/null 2>&1 \
       && dexec_sandbox "cd $GATE_DEST_REMOTE/JavaJCE && \
            export JAVA_HOME=/usr/lib/jvm/jdk-27-rc && export PATH=\$JAVA_HOME/bin:\$PATH && \
            mvn -o install -DskipTests -q" \
       && dexec_sandbox "cd $GATE_DEST_REMOTE/JavaJCE-remote && \
            export JAVA_HOME=/usr/lib/jvm/jdk-27-rc && export PATH=\$JAVA_HOME/bin:\$PATH && \
            mvn -o test 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' > /tmp/javajce-remote-gate.log; \
            grep -E '$AGG_PATTERN' /tmp/javajce-remote-gate.log >/dev/null"; then
      ok "JavaJCE-remote provider suite ($(dexec_sandbox "grep -E '$AGG_PATTERN' /tmp/javajce-remote-gate.log | tail -1"))"
    else
      bad "JavaJCE-remote provider suite — see /tmp/javajce-remote-gate.log inside $SANDBOX_CONTAINER for the real failure"
    fi
  fi
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
  [[ $RUN_RELEASE_XMSS == 1 ]] && FLAGS="$FLAGS,release-xmss"
  [[ $RUN_JAVAJCE == 1 ]] && FLAGS="$FLAGS,javajce"
  [[ $RUN_JAVAJCE_REMOTE == 1 ]] && FLAGS="$FLAGS,javajce-remote"
  [[ $RUN_OPENSSL_PROVIDER == 1 ]] && FLAGS="$FLAGS,openssl-provider"
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
