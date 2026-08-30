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
  if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
    cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON \
          -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3 2>/dev/null || echo /usr)"
  fi
  cmake --build "$BUILD_DIR" --target softhsmv3 -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

  echo "==> building the Rust engine (cdylib)"
  ( cd rust && cargo build --lib )
fi

# Detected AFTER the build, not before: on a fresh $BUILD_DIR (no prior
# successful run) the .dylib does not exist yet at the top of this script,
# so checking here-then-never-again would silently lock onto the .so
# fallback forever — even after the build above produces a real .dylib —
# and every subsequent run would FATAL "engine not built" against a path
# macOS never produces. Only ever caught because every prior invocation of
# this script happened to run against an ALREADY-built $BUILD_DIR (its own
# header even hints at that habit: "--no-build only when you have just
# built both yourself"); promoting this script into the default local
# gate (2026-08-23) was the first genuinely from-clean-state run and hit
# it immediately. If DO_BUILD=0, this still correctly detects whatever
# was already on disk, unchanged from before.
CPP_ENGINE="$BUILD_DIR/src/lib/libsofthsmv3.dylib"
[[ -f "$CPP_ENGINE" ]] || CPP_ENGINE="$BUILD_DIR/src/lib/libsofthsmv3.so"
RUST_ENGINE="rust/target/debug/libsofthsmrustv3.dylib"
[[ -f "$RUST_ENGINE" ]] || RUST_ENGINE="rust/target/debug/libsofthsmrustv3.so"

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
