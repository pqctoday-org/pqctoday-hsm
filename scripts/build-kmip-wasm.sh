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

# FrodoKEM's largest matrix (the 1344 parameter set's n×n generation) exceeds
# wasm32-unknown-unknown's default ~1MiB shadow stack even in a --release
# build — reproduced directly: `native::encrypt::encapsulate` traps with
# "memory access out of bounds" at the default size, passes cleanly at 8MiB.
# This is the same class of issue rust/build-wasm-bundle.sh already works
# around for ML-DSA (there, only under --dev; FrodoKEM's matrices are large
# enough to need the larger stack in --release too).
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-zstack-size=8388608"

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
  # The container mounts the parent of $ROOT at /ag, so derive the repo dir
  # from $ROOT instead of hardcoding it — a `git worktree` checkout (e.g.
  # pqctoday-hsm-kmip-honest-maximum) builds ITS OWN tree, not the main one.
  run() { docker exec -e RUSTFLAGS="$RUSTFLAGS" "$RUST_CONTAINER" sh -c "cd /ag/$(basename "$ROOT")/wasm && $*"; }
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
# The CACP guide (policy language + workbench testing + KMIP 3.0 hybrid
# status) rides along so the playground's "Guide" button always shows the
# version matching the staged policies/engine.
cp "$ROOT"/kmip/docs/CACP_GUIDE.md "$HUB_POLICY_DIR/"

# ── 5. Stage the conformance corpus (Corpus Replay tab) ─────────────────────
# The OASIS + PQC-interop XML fixtures the playground replays live in-browser,
# plus the manifest.json the tab's loader fetches first. Re-staged on every
# build so the browser replay can never drift from the engine's own corpus.
HUB_CORPUS_DIR="$HUB/public/kmip-corpus"
CONF="$ROOT/kmip/conformance"
echo "[kmip-wasm] staging conformance corpus into $HUB_CORPUS_DIR"
mkdir -p "$HUB_CORPUS_DIR/oasis/mandatory" "$HUB_CORPUS_DIR/oasis/optional" "$HUB_CORPUS_DIR/pqc"
cp "$CONF"/oasis_corpus/mandatory/*.xml "$HUB_CORPUS_DIR/oasis/mandatory/"
cp "$CONF"/oasis_corpus/optional/*.xml  "$HUB_CORPUS_DIR/oasis/optional/"
cp "$CONF"/pqc_corpus/*.xml             "$HUB_CORPUS_DIR/pqc/"

# Spec-extraction JSON (2026-07-23 re-audit, finding X1): this was
# previously staged manually, out of band from this script, so a real
# rebuild would silently leave hub's copy stale. Re-staged here so it can
# never drift from the engine's own spec/ directory again. As of 2026-07-24
# this is extracted straight from the published CSD02 HTML — no separate
# delta file is needed (that existed only because OASIS had never published
# an HTML export of the WD19 draft this previously trailed).
SPEC_DIR="$ROOT/kmip/spec/oasis-kmip-3.0"
cp "$SPEC_DIR/kmip-spec-3.0-tags-enums.json" "$HUB_CORPUS_DIR/tags-enums.json"
# §6.1.x operation-number-to-name table (both CSD01 and CSD02) — feeds the
# citation-drift guard test on both sides (kmip/tests/section61_citation_drift.rs,
# src/wasm/kmip/section61CitationDrift.local.test.ts). Re-staged for the same
# never-drift-out-of-band reason as tags-enums.json above.
cp "$SPEC_DIR/kmip-spec-3.0-section61-headings.json" "$HUB_CORPUS_DIR/section61-headings.json"

# Provenance for the manifest below. Without these the staged corpus carries no
# statement of WHAT it is or WHERE it came from — freshness was inferable only
# from file mtimes, and a corpus silently drifting from the bundle that replays
# it looks identical to one that is in sync (2026-08-12 audit, NC-8). hsmCommit
# is asserted against the wasm bundle's own provenance manifest by the hub-side
# test src/wasm/kmip/corpus/runner.local.test.ts.
HSM_COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
BUILT_AT="$(date -u +%Y-%m-%d)"

python3 - "$HUB_CORPUS_DIR" "$HSM_COMMIT" "$BUILT_AT" <<'PY'
import json, os, sys
root, hsm_commit, built_at = sys.argv[1], sys.argv[2], sys.argv[3]
tests = []
def add(rel_dir, tier, category):
    d = os.path.join(root, rel_dir)
    for name in sorted(os.listdir(d)):
        if not name.endswith('.xml'):
            continue
        # e.g. "CS-AC-M-1-30.xml" → "CS-AC" (profile prefix before -M-/-O-)
        cat = category or name.split('-M-')[0].split('-O-')[0]
        tests.append({'file': f'{rel_dir}/{name}', 'tier': tier, 'category': cat, 'name': name})
add('oasis/mandatory', 'mandatory', None)
add('oasis/optional', 'optional', None)
add('pqc', 'pqc', 'PQC Interop')
tiers = {}
for t in tests:
    tiers[t['tier']] = tiers.get(t['tier'], 0) + 1
manifest = {'generated_by': 'scripts/build-kmip-wasm.sh (corpus staging step)',
            'hsmCommit': hsm_commit,
            'builtAt': built_at,
            'specBaseline': 'KMIP 3.0 CSD02 (2026-05-07); Profiles 3.0 CSD02 (2026-05-21)',
            'corpusSource': {
                'oasis': 'kmip-profiles-v3.0-csd02.zip test-cases/kmip-v3.0/{mandatory,optional}',
                'pqc': 'vendored subset of OASIS kmip-3-0-pqc-tests-03.zip',
            },
            'tierCounts': tiers,
            'count': len(tests), 'tests': tests}
with open(os.path.join(root, 'manifest.json'), 'w') as f:
    json.dump(manifest, f, indent=2)
    f.write('\n')
print(f"[kmip-wasm]   manifest.json: {len(tests)} corpus tests "
      f"({', '.join(f'{k}={v}' for k, v in sorted(tiers.items()))}) @ {hsm_commit[:9]}")
PY

# This script writes plain `cp`/`json.dump` output, not the hub's own
# formatter, so every rebuild reintroduced formatting the hub's own
# `format:check` gate then rejected on the next push — hit twice in one
# release (2026-08-18) as a manual follow-up commit each time. Run the
# hub's prettier on exactly the files this step just touched, from inside
# the hub checkout so it picks up the hub's own config. Best-effort: a
# missing `node_modules` (e.g. a fresh hub clone before its own `npm
# install`) must not fail the wasm build over a formatting nicety.
if [ -x "$HUB/node_modules/.bin/prettier" ]; then
  ( cd "$HUB" && node_modules/.bin/prettier --write \
      public/kmip-corpus/manifest.json \
      public/kmip-corpus/section61-headings.json ) \
    || echo "[kmip-wasm]   warning: prettier formatting step failed — run 'npm run format' in the hub before pushing" >&2
else
  echo "[kmip-wasm]   note: hub node_modules not found, skipped auto-formatting staged corpus JSON" >&2
fi

echo ""
echo "[kmip-wasm] done."
echo "  hub shim:   $HUB_SHIM_DIR/pqctoday_kmip_wasm.js"
echo "  hub binary: $HUB_WASM_DIR/pqctoday_kmip_wasm_bg.wasm"
echo "  hub corpus: $HUB_CORPUS_DIR/manifest.json"
