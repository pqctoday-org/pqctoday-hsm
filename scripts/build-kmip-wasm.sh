#!/usr/bin/env bash
# build-kmip-wasm.sh — build the in-browser crypto-agile KMIP 3.0 control plane
# (the `wasm/` crate: pqctoday-kmip library core + softhsmrustv3 PKCS#11 engine)
# to WebAssembly, generate the wasm-bindgen JS bindings, smoke-test them, and
# stage the bundler artifact into the hub.
#
# Counterpart of `build-wasm.sh` (which builds the C++/Emscripten engine). This
# one is pure Rust → `wasm32-unknown-unknown` via wasm-bindgen, exactly like the
# standalone `rust/` engine bundle (`pkg_bundler`).
#
# Toolchain: needs `cargo` + the `wasm32-unknown-unknown` target +
# `wasm-bindgen` (= the pinned crate version) + `node`. If `cargo` is not on the
# host PATH, the script runs the Rust steps inside an OrbStack/Docker container
# named `$RUST_CONTAINER` (default `pqc-rust`, image `rust:1`).
#
# Usage:
#   bash scripts/build-kmip-wasm.sh            # build + bindings + smoke + stage
#   SKIP_SMOKE=1 bash scripts/build-kmip-wasm.sh
#   RUST_CONTAINER=my-rust bash scripts/build-kmip-wasm.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"          # …/pqctoday-hsm
WASM_CRATE="$ROOT/wasm"
HUB="${HUB:-$(cd "$ROOT/.." && pwd)/pqctoday-hub}"  # sibling checkout (override: HUB=… )
WASM_BINDGEN_VERSION="0.2.117"                       # MUST match wasm/Cargo.toml

# Hub staging targets (mirrors the engine layout: shim in src/, binary in public/).
HUB_SHIM_DIR="$HUB/src/wasm/kmip"
HUB_WASM_DIR="$HUB/public/wasm/rust-kmip"

# ── Pick a runner: host cargo, or `docker exec` into the build container ──────
RUST_CONTAINER="${RUST_CONTAINER:-pqc-rust}"
if command -v cargo >/dev/null 2>&1; then
  echo "[kmip-wasm] using host cargo ($(cargo --version))"
  run() { ( cd "$WASM_CRATE" && "$@" ); }
  CARGO_TARGET_ROOT="$WASM_CRATE/target"
else
  echo "[kmip-wasm] no host cargo — using container '$RUST_CONTAINER'"
  if ! docker ps --format '{{.Names}}' | grep -qx "$RUST_CONTAINER"; then
    echo "[kmip-wasm] starting container '$RUST_CONTAINER' (image rust:1)"
    docker rm -f "$RUST_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$RUST_CONTAINER" \
      -v "$(cd "$ROOT/.." && pwd)":/ag \
      -v pqc-cargo-registry:/usr/local/cargo/registry \
      -v pqc-cargo-git:/usr/local/cargo/git \
      -e CARGO_TARGET_DIR=/cargo-target \
      -v pqc-cargo-target:/cargo-target \
      -w /ag/pqctoday-hsm rust:1 sleep infinity >/dev/null
    docker exec "$RUST_CONTAINER" rustup target add wasm32-unknown-unknown
    docker exec "$RUST_CONTAINER" sh -c "command -v wasm-bindgen >/dev/null 2>&1 || cargo install wasm-bindgen-cli --version $WASM_BINDGEN_VERSION"
  fi
  run() { docker exec "$RUST_CONTAINER" sh -c "cd /ag/pqctoday-hsm/wasm && $*"; }
  CARGO_TARGET_ROOT="/cargo-target"
fi

# ── 1. Compile the crate to wasm32 ───────────────────────────────────────────
echo "[kmip-wasm] cargo build --release --target wasm32-unknown-unknown"
run cargo build --release --target wasm32-unknown-unknown

WASM_IN="$CARGO_TARGET_ROOT/wasm32-unknown-unknown/release/pqctoday_kmip_wasm.wasm"

# ── 2. wasm-bindgen → bundler (hub/vite) + nodejs (smoke test) ────────────────
echo "[kmip-wasm] wasm-bindgen → pkg_bundler + pkg_node (v$WASM_BINDGEN_VERSION)"
run wasm-bindgen --target bundler --out-dir pkg_bundler "$WASM_IN"
run wasm-bindgen --target nodejs  --out-dir pkg_node    "$WASM_IN"
ls -lh "$WASM_CRATE/pkg_bundler/"*.wasm

# ── 3. Smoke test (host node; the wasm is portable) ──────────────────────────
if [[ "${SKIP_SMOKE:-0}" != "1" ]]; then
  echo "[kmip-wasm] node smoke test"
  node "$WASM_CRATE/smoke/smoke.cjs"
fi

# ── 4. Stage into the hub ────────────────────────────────────────────────────
# The bundler shim (`_bg.js`) imports `_bg.wasm` by relative path, so the whole
# pkg must stay together for Vite — copy it verbatim into src/wasm/kmip/. Also
# drop the raw .wasm into public/ for the Web-Worker fetch+instantiate path.
echo "[kmip-wasm] staging into hub: $HUB_SHIM_DIR + $HUB_WASM_DIR"
mkdir -p "$HUB_SHIM_DIR" "$HUB_WASM_DIR"
cp "$WASM_CRATE"/pkg_bundler/pqctoday_kmip_wasm*.js     "$HUB_SHIM_DIR/"
cp "$WASM_CRATE"/pkg_bundler/pqctoday_kmip_wasm*.d.ts   "$HUB_SHIM_DIR/"
cp "$WASM_CRATE"/pkg_bundler/pqctoday_kmip_wasm_bg.wasm "$HUB_SHIM_DIR/"
cp "$WASM_CRATE"/pkg_bundler/pqctoday_kmip_wasm_bg.wasm "$HUB_WASM_DIR/"

# Crypto-agility policy presets (Plane 1) — the canonical YAMLs the playground's
# policy panel loads. Copied verbatim so they never drift from the server's set.
HUB_POLICY_DIR="$HUB/public/kmip-policies"
echo "[kmip-wasm] staging policy presets into $HUB_POLICY_DIR"
mkdir -p "$HUB_POLICY_DIR"
cp "$ROOT"/kmip/policies/*.yaml "$HUB_POLICY_DIR/"

echo ""
echo "[kmip-wasm] done."
echo "  hub shim:   $HUB_SHIM_DIR/pqctoday_kmip_wasm.js"
echo "  hub binary: $HUB_WASM_DIR/pqctoday_kmip_wasm_bg.wasm"
