#!/usr/bin/env bash
# regen-strongswan-pkcs11-patch.sh
#
# Regenerates strongswan-pkcs11.patch from the strongswan-pkcs11/ directory
# against a pristine strongSwan release tarball. Run this after editing any
# file in strongswan-pkcs11/, or whenever the pinned strongSwan version in
# pqctoday-sandbox/docker/Dockerfile.network changes — that Dockerfile
# `patch -p1`s the output of this script; it does not read the directory
# directly (see strongswan-pkcs11.patch's own header for why).
#
# Usage: ./regen-strongswan-pkcs11-patch.sh [strongswan-version]
#        (defaults to the version currently in the patch header if omitted)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORK_DIR="$HERE/strongswan-pkcs11"
OUT="$HERE/strongswan-pkcs11.patch"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(grep -m1 -oE 'strongSwan [0-9]+\.[0-9]+\.[0-9]+' "$OUT" | grep -oE '[0-9.]+' || true)"
  [ -n "$VERSION" ] || { echo "Could not detect current version from $OUT — pass it explicitly." >&2; exit 1; }
fi
echo "Regenerating against pristine strongSwan $VERSION..."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -fsSL "https://download.strongswan.org/strongswan-${VERSION}.tar.bz2" \
  -o "$WORK/strongswan.tar.bz2"
tar xjf "$WORK/strongswan.tar.bz2" -C "$WORK"
PRISTINE="$WORK/strongswan-${VERSION}/src/libstrongswan/plugins/pkcs11"
[ -d "$PRISTINE" ] || { echo "No such directory in the release tarball: $PRISTINE" >&2; exit 1; }

mkdir -p "$WORK/a/src/libstrongswan/plugins/pkcs11" "$WORK/b/src/libstrongswan/plugins/pkcs11"

# Files whose content actually differs from upstream get a real diff hunk.
# Files that are identical to upstream are deliberately excluded (see the
# patch header) so an upstream change to one of THEM shows up here as a new
# entry in this list next time it's regenerated, rather than staying silent.
MODIFIED=() NEW=() UNCHANGED=()
for f in "$FORK_DIR"/*; do
  name="$(basename "$f")"
  [ -f "$f" ] || continue
  if [ -f "$PRISTINE/$name" ]; then
    if cmp -s "$f" "$PRISTINE/$name"; then
      UNCHANGED+=("$name")
    else
      MODIFIED+=("$name")
      cp "$PRISTINE/$name" "$WORK/a/src/libstrongswan/plugins/pkcs11/$name"
      cp "$f" "$WORK/b/src/libstrongswan/plugins/pkcs11/$name"
    fi
  else
    NEW+=("$name")
    cp "$f" "$WORK/b/src/libstrongswan/plugins/pkcs11/$name"
  fi
done

echo "  modified from upstream: ${MODIFIED[*]:-(none)}"
echo "  new (fork-only):        ${NEW[*]:-(none)}"
echo "  unchanged (excluded):   ${UNCHANGED[*]:-(none)}"

(cd "$WORK" && git diff --no-index --no-prefix a b > "$WORK/raw.patch") || true
[ -s "$WORK/raw.patch" ] || { echo "Diff is empty — nothing to regenerate?" >&2; exit 1; }

# Verify it actually applies before overwriting the committed patch.
TEST_APPLY="$WORK/test-apply"
cp -R "$WORK/strongswan-${VERSION}" "$TEST_APPLY"
if ! (cd "$TEST_APPLY" && patch -p1 --dry-run < "$WORK/raw.patch" >/dev/null); then
  echo "Generated patch does NOT apply cleanly to strongSwan $VERSION — not overwriting $OUT." >&2
  exit 1
fi

# Keep the existing hand-written header (version note, rationale, file lists)
# untouched — rewriting it programmatically risks silently corrupting the one
# part of this file meant to be read by a human. Only the diff body below the
# header is replaced. If MODIFIED/NEW/UNCHANGED changed since the header was
# last written, the printed lists above are the source of truth — update the
# header by hand to match before committing.
HEADER_END="$(grep -n '^diff --git' "$OUT" | head -1 | cut -d: -f1)"
{
  head -n "$((HEADER_END - 1))" "$OUT"
  cat "$WORK/raw.patch"
} > "$OUT.new"
mv "$OUT.new" "$OUT"

echo
echo "Wrote $OUT ($(wc -l < "$OUT") lines)."
echo "The header comment was left as-is — compare the file lists printed above"
echo "against the header's own lists and edit by hand if they now differ."
echo "Verify with: patch -p1 --dry-run < strongswan-pkcs11.patch   # from an extracted strongswan-${VERSION}/"
