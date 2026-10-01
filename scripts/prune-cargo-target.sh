#!/usr/bin/env bash
# prune-cargo-target.sh — keep the shared cargo build cache under a size cap.
#
# Runs INSIDE the gate container ($RUST_CONTAINER, default pqc-rust), called by
# scripts/local-gate.sh's container preflight before any build step:
#
#   bash scripts/prune-cargo-target.sh <this run's CARGO_TARGET_DIR>
#
# Why (owner decision 2026-10-01): /cargo-target is the named volume
# pqc-cargo-target. local-gate.sh gives every worktree its own build dir,
# /cargo-target/worktrees/<basename> (~20 GB each, see the
# CARGO_TARGET_DIR_FOR_RUN block in local-gate.sh for why), and nothing ever
# deleted those dirs. The volume grew past 1 TB and was deleted by hand.
#
# What it does:
#   1. Measures the whole root with one `du -sxk`. At or under the cap: done.
#   2. Over the cap: deletes whole /cargo-target/worktrees/<name> dirs, least
#      recently used first, until the total is at or under the cap.
#   3. Still over after that: prints a warning with the sizes and the manual
#      command to clear the main tree's cache. It never deletes that cache
#      itself.
#
# Never deleted:
#   - the current run's own dir (argument 1);
#   - any worktree dir holding a file or dir modified in the last
#     CARGO_TARGET_RECENT_MIN minutes (default 180): another session's gate
#     may be building there right now. local-gate.sh touches its own dir
#     (.gate-last-used) just before calling this, so a gate that has started
#     but not yet compiled anything is protected too;
#   - anything outside /cargo-target/worktrees/, which includes the main
#     tree's cache and /cargo-target/release/wasm-pack (the image keeps
#     wasm-pack there and the gate calls it by that path; see
#     scripts/gate-container/Dockerfile).
#
# LRU signal: the newest mtime of anything inside the dir, read with GNU
# `du --time` in the same pass that measures the dir's size. The dir's own
# mtime is not used: it changes only when an entry directly under it is added
# or removed, and cargo writes deep inside (debug/deps, debug/.fingerprint),
# so a dir in daily use can show a weeks-old mtime. Recency is re-checked with
# `find -mmin` right before each deletion, to narrow the window in which a
# gate could start in a dir between the scan and the rm.
#
# Settings (environment):
#   CARGO_TARGET_CAP_GB      cap in GiB (default 100). 0 disables pruning.
#   CARGO_TARGET_RECENT_MIN  recency window in minutes (default 180).
#   CARGO_TARGET_ROOT        root to manage (default /cargo-target; the test
#                            points it at a temp dir).
#   CARGO_TARGET_CAP_KB      cap in KiB; overrides CARGO_TARGET_CAP_GB. Only
#                            for tests, which cannot write 100 GiB.
#
# This script must never fail the gate: every error prints a warning and the
# script exits 0.

set -u

ROOT="${CARGO_TARGET_ROOT:-/cargo-target}"
CURRENT="${1:-}"
WT="$ROOT/worktrees"

log()  { printf '[cargo-cap] %s\n' "$*"; }
warn() { printf '[cargo-cap] WARNING: %s\n' "$*" >&2; }
gib()  { awk -v k="$1" 'BEGIN { if (k >= 1048576) printf "%.1f GiB", k / 1048576; else printf "%.1f MiB", k / 1024 }'; }

is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

CAP_GB="${CARGO_TARGET_CAP_GB:-100}"
if ! is_uint "$CAP_GB"; then
  warn "CARGO_TARGET_CAP_GB='$CAP_GB' is not a whole number; using 100"
  CAP_GB=100
fi
RECENT_MIN="${CARGO_TARGET_RECENT_MIN:-180}"
if ! is_uint "$RECENT_MIN"; then
  warn "CARGO_TARGET_RECENT_MIN='$RECENT_MIN' is not a whole number; using 180"
  RECENT_MIN=180
fi

if [ -n "${CARGO_TARGET_CAP_KB:-}" ] && is_uint "$CARGO_TARGET_CAP_KB"; then
  CAP_KB="$CARGO_TARGET_CAP_KB"
else
  CAP_KB=$((CAP_GB * 1048576))
fi

if [ "$CAP_KB" -eq 0 ]; then
  log "cap disabled (CARGO_TARGET_CAP_GB=0); not measuring $ROOT"
  exit 0
fi
if [ ! -d "$ROOT" ]; then
  warn "$ROOT does not exist; nothing to prune"
  exit 0
fi

total_kb="$(du -sxk "$ROOT" 2>/dev/null | awk 'NR==1 { print $1 }')"
if ! is_uint "${total_kb:-}"; then
  warn "could not measure $ROOT; skipping pruning"
  exit 0
fi
before_kb="$total_kb"

if [ "$total_kb" -le "$CAP_KB" ]; then
  log "$ROOT is $(gib "$total_kb"), cap $(gib "$CAP_KB"): nothing to do"
  exit 0
fi
log "$ROOT is $(gib "$total_kb"), over the cap of $(gib "$CAP_KB"); pruning worktree build dirs, least recently used first"

current_real=""
[ -n "$CURRENT" ] && current_real="$(realpath -m "$CURRENT" 2>/dev/null || echo "$CURRENT")"
now="$(date +%s)"
recent_s=$((RECENT_MIN * 60))

# One line per worktree dir: "<newest mtime epoch> <size KiB> <path>",
# oldest first. du --time prints the newest mtime of anything in the tree.
candidates=""
if [ -d "$WT" ]; then
  candidates="$(find "$WT" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null \
    | xargs -0 -r du -sxk --time --time-style=+%s 2>/dev/null \
    | awk -F'\t' 'NF >= 3 { print $2 " " $1 " " $3 }' \
    | sort -n -k1,1)"
fi

removed=0
while IFS=' ' read -r mtime size dir; do
  [ -n "${dir:-}" ] || continue
  [ "$total_kb" -le "$CAP_KB" ] && break
  name="$(basename "$dir")"
  dir_real="$(realpath -m "$dir" 2>/dev/null || echo "$dir")"
  if [ -n "$current_real" ] && [ "$dir_real" = "$current_real" ]; then
    log "keep $name ($(gib "$size")): this run's own build dir"
    continue
  fi
  if ! is_uint "$mtime" || [ $((now - mtime)) -lt "$recent_s" ]; then
    log "keep $name ($(gib "$size")): modified within the last $RECENT_MIN min, may be in use"
    continue
  fi
  # Re-check right before deleting: a gate may have started here since the scan.
  if [ -n "$(find "$dir" -mmin "-$RECENT_MIN" -print -quit 2>/dev/null)" ]; then
    log "keep $name ($(gib "$size")): modified within the last $RECENT_MIN min (re-check), may be in use"
    continue
  fi
  age_h=$(( (now - mtime) / 3600 ))
  if rm -rf --one-file-system -- "$dir" 2>/dev/null && [ ! -e "$dir" ]; then
    total_kb=$((total_kb - size))
    [ "$total_kb" -lt 0 ] && total_kb=0
    removed=$((removed + 1))
    log "removed $name ($(gib "$size"), last used ${age_h}h ago); total now about $(gib "$total_kb")"
  else
    warn "could not remove $dir; continuing"
  fi
done <<EOF
$candidates
EOF

# Re-measure once for an exact "after" figure (only reached when over the cap).
after_kb="$(du -sxk "$ROOT" 2>/dev/null | awk 'NR==1 { print $1 }')"
is_uint "${after_kb:-}" || after_kb="$total_kb"
log "removed $removed worktree build dir(s): $(gib "$before_kb") before, $(gib "$after_kb") after, cap $(gib "$CAP_KB")"

if [ "$after_kb" -gt "$CAP_KB" ]; then
  wt_kb="$(du -sxk "$WT" 2>/dev/null | awk 'NR==1 { print $1 }')"
  is_uint "${wt_kb:-}" || wt_kb=0
  warn "$ROOT is still over the cap: $(gib "$after_kb") of $(gib "$CAP_KB") ($(gib "$wt_kb") in worktrees/ that is recent or this run's own, $(gib $((after_kb - wt_kb))) in the main tree's cache and release/)."
  warn "The main tree's warm cache is never deleted automatically. To clear it by hand while keeping release/wasm-pack, when no gate is running:"
  warn "  docker exec pqc-rust bash -c 'find $ROOT -mindepth 1 -maxdepth 1 ! -name release ! -name worktrees -exec rm -rf {} +; find $ROOT/release -mindepth 1 -maxdepth 1 ! -name wasm-pack -exec rm -rf {} +'"
fi
exit 0
