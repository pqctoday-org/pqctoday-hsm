#!/usr/bin/env bash
# Build the FHE browser-matrix bundle (FHE plan §7): softhsmrustv3 for
# wasm32-unknown-unknown with `educational-fhe`, wasm-bindgen target `web`,
# into rust/pkg-fhe-web/. Test-only; never staged into a shipped bundle.
set -euo pipefail
cd "$(dirname "$0")/../rust"
RUSTUP_ROOT="${RUSTUP_HOME:-$HOME/.rustup}"
TOOLCHAIN="$(rustup show active-toolchain | awk '{print $1}')"
TC="$RUSTUP_ROOT/toolchains/$TOOLCHAIN/bin"
PATH="$TC:$PATH" RUSTC="$TC/rustc" RUSTUP_TOOLCHAIN="$TOOLCHAIN" \
  RUSTFLAGS='-C link-arg=-zstack-size=8388608' \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target-fhe-web}" \
  wasm-pack build --target web --out-dir pkg-fhe-web --release --no-typescript -- --features educational-fhe
ls -l pkg-fhe-web/*.wasm
