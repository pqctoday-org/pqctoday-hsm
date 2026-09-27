#!/usr/bin/env bash
# Re-derive rust/vendor/aws-lc-sys-0.44.0 from crates.io + the checked-in patch and
# diff it against the vendored tree. Exit 0 only if identical.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WANT=f09fae7be8bb3174e05c6afdb34199e6dc0c7c04ba9fa237b1967adfbde27483
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
curl -fsSL -o "$T/c.crate" https://static.crates.io/crates/aws-lc-sys/aws-lc-sys-0.44.0.crate
GOT=$( (sha256sum "$T/c.crate" 2>/dev/null || shasum -a 256 "$T/c.crate") | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || { echo "crate checksum mismatch: $GOT" >&2; exit 1; }
tar xzf "$T/c.crate" -C "$T"
(cd "$T/aws-lc-sys-0.44.0/aws-lc" && patch -p1 -s < "$ROOT/rust/vendor/aws-lc-sys-0.44.0-cortex-a5x.patch")
diff -r "$T/aws-lc-sys-0.44.0" "$ROOT/rust/vendor/aws-lc-sys-0.44.0" && echo "vendored aws-lc-sys 0.44.0 = crates.io + patch: OK"
