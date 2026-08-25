#!/usr/bin/env bash
# install-hooks.sh — one-time setup: installs this repo's git hooks.
#
# Deliberately copies into .git/hooks/ rather than setting core.hooksPath,
# so cloning or fetching this repo never silently changes a contributor's
# git configuration — installing a hook is an explicit, visible action.
#
# Usage (run once per clone):
#   bash scripts/install-hooks.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/scripts/git-hooks"
DST="$ROOT/.git/hooks"

if [[ ! -d "$DST" ]]; then
  echo "error: $DST not found — is this a git checkout (not a worktree with a relocated git-dir)?" >&2
  exit 1
fi

for hook in "$SRC"/*; do
  name="$(basename "$hook")"
  install -m 755 "$hook" "$DST/$name"
  echo "installed $name -> .git/hooks/$name"
done
