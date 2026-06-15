#!/usr/bin/env bash
# Build the softhsmrustv3 Rust→WASM bundle (release, bundler target) and refresh
# the tracked rust/pkg_bundler artifacts the @pqctoday/softhsm-wasm package
# vendors into the hub playground.
#
# Why this script exists:
#   1. Homebrew's cargo/rustc (ahead on PATH) has no wasm32 sysroot, so we force
#      the rustup toolchain binaries directly (rustup run/which still resolve to
#      Homebrew). See memory: rust-wasm-build-toolchain.
#   2. Newer wasm-bindgen no longer auto-exports __wbg_get_memory, which the hub
#      loader (softhsm.ts) needs to build HEAPU8/getValue/setValue from the wasm
#      linear memory. It MUST be re-appended after every wasm-pack rebuild —
#      this script does that automatically (idempotently) so it can never be
#      forgotten again.
#
# Usage:  ./build-wasm-bundle.sh            # release (default; updates pkg_bundler)
#         ./build-wasm-bundle.sh --dev      # dev build into pkg/ (for node harnesses)
set -euo pipefail
cd "$(dirname "$0")"

PROFILE="release"; OUT="pkg-release"; EXTRA_RUSTFLAGS=""
if [[ "${1:-}" == "--dev" ]]; then
  PROFILE="dev"; OUT="pkg"
  # Unoptimized fips204 ML-DSA keygen overflows the default 1MB wasm shadow
  # stack under --dev ("memory access out of bounds" in expand_a); release fits.
  EXTRA_RUSTFLAGS='-C link-arg=-zstack-size=2097152'
fi

# Resolve the rustup toolchain bin dir (NOT Homebrew's cargo/rustc).
TOOLCHAIN="$(rustup show active-toolchain | awk '{print $1}')"
TC="$HOME/.rustup/toolchains/$TOOLCHAIN/bin"
[[ -x "$TC/cargo" ]] || { echo "rustup toolchain not found at $TC" >&2; exit 1; }

echo "▶ wasm-pack build ($PROFILE, target=bundler, toolchain=$TOOLCHAIN) → $OUT/"
PATH="$TC:$PATH" RUSTC="$TC/rustc" RUSTUP_TOOLCHAIN="$TOOLCHAIN" \
  ${EXTRA_RUSTFLAGS:+RUSTFLAGS="$EXTRA_RUSTFLAGS"} \
  wasm-pack build --target bundler --out-dir "$OUT" --"$PROFILE"

# ── Re-apply the __wbg_get_memory post-build shim (idempotent) ───────────────
BG="$OUT/softhsmrustv3_bg.js"
if grep -q "__wbg_get_memory" "$BG"; then
  echo "▶ __wbg_get_memory shim already present in $BG"
else
  echo "▶ appending __wbg_get_memory shim to $BG"
  cat >> "$BG" <<'SHIM'

// Post-build shim — wasm-bindgen no longer auto-exports __wbg_get_memory.
// The hub loader builds HEAPU8/getValue/setValue from WebAssembly.Memory via
// this. wasm.memory is the linear memory exported by the .wasm binary, valid
// after __wbg_set_wasm runs. Re-applied automatically by build-wasm-bundle.sh.
export function __wbg_get_memory() {
    return wasm.memory;
}
SHIM
fi

# ── Re-export the shim from the wrapper (wasm-pack regenerates a curated
#    `export { … } from "./softhsmrustv3_bg.js"` list that omits the post-build
#    __wbg_get_memory) so consumers importing from softhsmrustv3.js get it too ──
WRAP="$OUT/softhsmrustv3.js"
if grep -q "__wbg_get_memory" "$WRAP"; then
  echo "▶ wrapper $WRAP already re-exports __wbg_get_memory"
else
  echo "▶ adding __wbg_get_memory to the $WRAP re-export list"
  perl -0pi -e 's/(export \{\s*\n\s*)/${1}__wbg_get_memory,\n    /' "$WRAP"
  grep -q "__wbg_get_memory" "$WRAP" || { echo "✗ wrapper re-export patch failed" >&2; exit 1; }
fi

# ── Refresh the tracked bundler artifact (release only) ──────────────────────
if [[ "$PROFILE" == "release" ]]; then
  echo "▶ updating tracked rust/pkg_bundler/"
  cp "$OUT/softhsmrustv3.js" "$OUT/softhsmrustv3_bg.js" "$OUT/softhsmrustv3_bg.wasm" pkg_bundler/
  grep -q "__wbg_get_memory" pkg_bundler/softhsmrustv3_bg.js \
    && echo "✓ pkg_bundler carries the __wbg_get_memory shim" \
    || { echo "✗ shim missing from pkg_bundler — aborting" >&2; exit 1; }
fi
echo "✓ done ($OUT/)"
