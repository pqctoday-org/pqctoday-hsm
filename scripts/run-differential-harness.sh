#!/usr/bin/env bash
# ============================================================================
# run-differential-harness.sh — drive both PKCS#11 engines through identical
# call sequences and diff every observable outcome.
#
#   ./scripts/run-differential-harness.sh                 # build both, run all
#   ./scripts/run-differential-harness.sh --list          # list scenarios
#   ./scripts/run-differential-harness.sh --only bytes.   # one group
#   ./scripts/run-differential-harness.sh --drop-exception DEFECT-RUST-AES-CTR-CIPHERTEXT
#   ./scripts/run-differential-harness.sh --no-build      # reuse what is built
#   ./scripts/run-differential-harness.sh --parallel      # shard across every core
#   ./scripts/run-differential-harness.sh --jobs 6        # shard across exactly 6 workers
#
# Exit code 0 means every divergence is accounted for in
# tests/differential/exceptions.json. Non-zero means at least one is not, and
# the console names the operation, the field and both values.
#
# --parallel/--jobs run N separate p11_diff PROCESSES, each --shard'd to a
# disjoint round-robin slice of the scenario list, each with its own workdir
# and each dlopen-ing both engines fresh — real multi-core speedup without
# putting either engine (or this harness) under concurrent access from
# multiple threads in one process, which neither has ever been asserted
# safe for. Every scenario still prints "[i/N] name ... running" the moment
# it starts, flushed immediately, specifically so a hang shows exactly
# where it's stuck instead of going silent — watch scripts/merge-
# differential-shards.py's live tail, or each shard's own log under
# $BUILD_DIR/p11_diff_workdir/shard-*.log.
#
# BUILDS BOTH ENGINES BY DEFAULT, deliberately. A stale cdylib makes this
# harness lie in the most convincing possible way: the first run of this
# harness was against a Rust library built six hours before the conformance
# merge, and it confidently reported every Phase 1 security fix as missing.
# Every one of those "findings" evaporated on rebuild. Use --no-build only
# when you have just built both yourself.
# ============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

BUILD_DIR="${P11DIFF_BUILD_DIR:-build_union}"
DO_BUILD=1
PARALLEL=0
JOBS=""
PASSTHRU=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) DO_BUILD=0; shift ;;
    --build-dir) BUILD_DIR="$2"; shift 2 ;;
    --parallel) PARALLEL=1; shift ;;
    --jobs) PARALLEL=1; JOBS="$2"; shift 2 ;;
    -h|--help) sed -n '2,24p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) PASSTHRU+=("$1"); shift ;;
  esac
done
[[ -n "$JOBS" ]] || JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"

if [[ $DO_BUILD -eq 1 ]]; then
  echo "==> building the C++ engine ($BUILD_DIR)"
  # Reconfigure unless the previous configure actually SUCCEEDED. Testing
  # CMakeCache.txt alone (what this did) tests only that configure once
  # *started*: cmake writes the cache early and then, on a failure, leaves it
  # behind with no generated build system. The next run therefore skipped
  # configure and went straight to `cmake --build`, which died with
  #
  #     gmake: Makefile: No such file or directory
  #
  # and kept dying on every subsequent run until a human deleted the directory
  # by hand. Any interrupted configure — Ctrl-C, a missing submodule, a full
  # disk — wedged the build dir permanently.
  #
  # Found 2026-09-24: a first gate run failed to configure because this
  # worktree's submodules were not initialised (src/lib/crypto/oqs/liboqs was
  # an empty directory), and every later run then failed for this *different*
  # reason, masking the real cause and costing a full gate cycle to diagnose.
  #
  # The generated build system is the honest success marker, so check for it
  # too. Both generator outputs are accepted: Unix Makefiles (the default here)
  # and Ninja, so this keeps working if -G Ninja is ever used.
  if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]] \
     || { [[ ! -f "$BUILD_DIR/Makefile" ]] && [[ ! -f "$BUILD_DIR/build.ninja" ]]; }; then
    cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON \
          -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3 2>/dev/null || echo /usr)"
  fi
  cmake --build "$BUILD_DIR" --target softhsmv3 -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

  echo "==> building the Rust engine (cdylib)"
  ( cd rust && cargo build --lib )
fi

# Resolve outputs AFTER building, honor Cargo's configured target directory,
# and select the shared-library format for the current operating system. This
# prevents a mounted Linux container from loading a stale host-format library
# merely because that filename also exists in the worktree.
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  if [[ "$CARGO_TARGET_DIR" = /* ]]; then
    RUST_TARGET_DIR="$CARGO_TARGET_DIR"
  else
    RUST_TARGET_DIR="$REPO/rust/$CARGO_TARGET_DIR"
  fi
else
  RUST_TARGET_DIR="$REPO/rust/target"
fi

case "$(uname -s)" in
  Darwin)
    CPP_ENGINE="$BUILD_DIR/src/lib/libsofthsmv3.dylib"
    RUST_ENGINE="$RUST_TARGET_DIR/debug/libsofthsmrustv3.dylib"
    ;;
  *)
    CPP_ENGINE="$BUILD_DIR/src/lib/libsofthsmv3.so"
    RUST_ENGINE="$RUST_TARGET_DIR/debug/libsofthsmrustv3.so"
    ;;
esac

for f in "$CPP_ENGINE" "$RUST_ENGINE"; do
  [[ -f "$f" ]] || { echo "FATAL: engine not built: $f" >&2; exit 2; }
done

# The harness is a single translation unit and links nothing but libdl, so it
# is compiled directly rather than added to CMake. That keeps `ctest` and the
# existing p11_v32_compliance target byte-for-byte unchanged — the differential
# harness must never be able to alter the numbers the conformance suites report.
BIN="$BUILD_DIR/p11_diff"
echo "==> compiling the harness"
CXX="${CXX:-clang++}"
"$CXX" -std=c++17 -O1 -I. -I"$BUILD_DIR" -Itests/differential \
       -o "$BIN" tests/differential/p11_diff.cpp

echo "==> C++  engine: $CPP_ENGINE ($(date -r "$CPP_ENGINE" '+%Y-%m-%d %H:%M'))"
echo "==> Rust engine: $RUST_ENGINE ($(date -r "$RUST_ENGINE" '+%Y-%m-%d %H:%M'))"
echo

WORKDIR="$BUILD_DIR/p11_diff_workdir"
REPORT="$BUILD_DIR/p11_diff_report"

set +e
if [[ $PARALLEL -eq 1 ]]; then
  echo "==> running $JOBS shards in parallel (cores detected: $JOBS)"
  mkdir -p "$WORKDIR"
  PIDS=()
  for ((i = 0; i < JOBS; i++)); do
    "$BIN" \
      --cpp-engine  "$CPP_ENGINE" \
      --rust-engine "$RUST_ENGINE" \
      --workdir     "$WORKDIR/shard-$i" \
      --report      "$WORKDIR/shard-$i-report" \
      --exceptions  tests/differential/exceptions.json \
      --shard       "$i/$JOBS" \
      ${PASSTHRU[@]+"${PASSTHRU[@]}"} \
      > "$WORKDIR/shard-$i.log" 2>&1 &
    PIDS+=($!)
  done

  # Poll each shard's current progress line every 3s while waiting, so a
  # hang is visible immediately rather than going silent until the whole
  # thing times out — the exact concern that motivated --shard printing
  # per-scenario in the first place.
  while true; do
    alive=0
    for pid in "${PIDS[@]}"; do kill -0 "$pid" 2>/dev/null && alive=$((alive + 1)); done
    [[ $alive -eq 0 ]] && break
    echo "--- $(date '+%H:%M:%S') ($alive/$JOBS shards still running) ---"
    for ((i = 0; i < JOBS; i++)); do
      last="$(tail -1 "$WORKDIR/shard-$i.log" 2>/dev/null | tr -d '\r')"
      printf "  shard %d: %s\n" "$i" "${last:-(starting...)}"
    done
    sleep 3
  done
  for pid in "${PIDS[@]}"; do wait "$pid" || true; done

  echo
  echo "==> merging $JOBS shard reports"
  shard_reports=()
  for ((i = 0; i < JOBS; i++)); do shard_reports+=("$WORKDIR/shard-$i-report.json"); done
  python3 scripts/merge-differential-shards.py "$REPORT" "${shard_reports[@]}"
  rc=$?
else
  "$BIN" \
    --cpp-engine  "$CPP_ENGINE" \
    --rust-engine "$RUST_ENGINE" \
    --workdir     "$WORKDIR" \
    --report      "$REPORT" \
    --exceptions  tests/differential/exceptions.json \
    ${PASSTHRU[@]+"${PASSTHRU[@]}"}
  rc=$?
fi
set -e

echo
if [[ $rc -eq 0 ]]; then
  echo "PASS — every divergence is accounted for in tests/differential/exceptions.json"
else
  echo "FAIL — at least one divergence has no entry in tests/differential/exceptions.json."
  echo "       Adjudicate it against the spec, then add an entry with status 'legal'"
  echo "       (with a citation) or 'defect' (naming the plan item). Do not widen an"
  echo "       existing entry's glob to make it disappear."
fi
exit $rc
