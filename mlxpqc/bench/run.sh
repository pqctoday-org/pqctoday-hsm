#!/bin/zsh
# Build + run the Metal PQC acceleration benchmark.
# Usage:
#   ./run.sh                # build, then run all mechanism micro-benchmarks
#   ./run.sh --scale        # build, then run the GPU core-scaling study
#   ./run.sh --only M1,M5   # subset of mechanisms
#   ./run.sh --list         # list mechanisms / modes
set -e
cd "$(dirname "$0")"
BIN=./mlxpqc_bench
SRC=MetalPQCBench.swift

# rebuild if source is newer than binary
if [[ ! -x "$BIN" || "$SRC" -nt "$BIN" ]]; then
  echo "building $BIN ..."
  swiftc -O "$SRC" -o "$BIN" -framework Metal -framework Foundation
fi

"$BIN" "$@"
