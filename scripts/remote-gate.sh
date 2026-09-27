#!/usr/bin/env bash
# remote-gate.sh — run scripts/local-gate.sh for THIS commit on another host,
# and write this checkout's .gate-ok-<sha> marker only if it passed there.
#
# Invoked as:  bash scripts/local-gate.sh --host=<user@host> [gate flags]
#         or:  bash scripts/remote-gate.sh <user@host> [gate flags]
#
# Why (2026-09-27): every hsm gate ran in the one shared `pqc-rust` container
# on the M5 Max, which was running at a load of ~48 on 18 cores while the
# M4 Pro sat idle. The marker the pre-push hook checks is only worth
# something if it means "the gate passed on exactly this commit", so running
# elsewhere must not weaken that. What makes a remote PASS count:
#
#   1. The local checkout must be clean (tracked files == HEAD). An edited
#      worktree is refused, exactly the state a local run would have tested.
#   2. The commit travels as a `git bundle` over ssh — objects only. No
#      GitHub credentials exist on the remote; submodules are fetched there
#      from their public URLs (.gitmodules).
#   3. On the remote, HEAD must be that commit and HEAD^{tree} must equal the
#      local tree hash, with no tracked-file changes, BEFORE the run — and
#      still AFTER it, so a gate that rewrote a tracked file is not counted.
#   4. The remote gate's exit status must be 0 AND it must have written a
#      fresh .gate-ok-<sha> (any old marker is deleted first).
#   5. Only then is the local marker written, with `host=<label>` added to
#      its flags and the commit, tree and remote recorded in it.
#
# The remote host needs: git, bash, python3, docker CLI, node/npm, and a
# rustup toolchain with the wasm32 targets plus wasm-pack / wasm-bindgen —
# several gate steps run on the HOST, not in the container (the wasm CACP
# smoke builds with host cargo when one exists, and a Homebrew cargo without
# wasm32 fails it). Kept under $HOME/<GATE_REMOTE_BASE>/tools so nothing
# global on the remote changes; versions match the local host's. And a
# `pqc-rust` container built from
# scripts/gate-container/Dockerfile with $HOME/<GATE_REMOTE_BASE> mounted at
# /ag. Equivalence with the local container is measured, not assumed: run the
# same commit both ways and compare.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${1:-}"
[[ -n "$HOST" ]] || { echo "usage: remote-gate.sh <user@host> [local-gate flags]" >&2; exit 2; }
shift
GATE_FLAGS=("$@")
for f in "${GATE_FLAGS[@]+"${GATE_FLAGS[@]}"}"; do
  [[ "$f" == --host=* ]] && { echo "remote-gate: nested --host is not allowed" >&2; exit 2; }
done

SSH_KEY="${GATE_REMOTE_SSH_KEY:-$HOME/.ssh/pqc-appliance_ed25519}"
REMOTE_BASE="${GATE_REMOTE_BASE:-ag-gate}"          # under the remote $HOME; mounted at /ag
REMOTE_NAME="${GATE_REMOTE_DIR:-pqctoday-hsm-remote}" # one persistent checkout (warm build caches)
REMOTE_TOOLS="\$HOME/$REMOTE_BASE/tools"
REMOTE_PATH="${GATE_REMOTE_PATH:-$REMOTE_TOOLS/cargo/bin:$REMOTE_TOOLS/node/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin}"
REMOTE_ENV="export PATH=$REMOTE_PATH RUSTUP_HOME=$REMOTE_TOOLS/rustup CARGO_HOME=$REMOTE_TOOLS/cargo"
HOST_LABEL="${GATE_HOST_LABEL:-${HOST#*@}}"
RDIR="\$HOME/$REMOTE_BASE/$REMOTE_NAME"

say()  { printf '\n\033[1;36m[remote-gate] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[remote-gate] %s\033[0m\n' "$*" >&2; exit 1; }
# Commands are written for a POSIX shell; the remote login shell may be zsh
# (macOS), which errors on an unmatched glob — so no globs in remote commands.
rsh()  { ssh -o BatchMode=yes -o ConnectTimeout=15 -i "$SSH_KEY" "$HOST" "$@"; }

cd "$ROOT"
[[ -z "$(git status --porcelain --untracked-files=no)" ]] \
  || die "tracked files differ from HEAD — commit or discard them first; the marker must describe a commit"
SHA="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short HEAD)"
TREE="$(git rev-parse 'HEAD^{tree}')"
say "commit $SHORT  tree ${TREE:0:12}  →  $HOST:$REMOTE_BASE/$REMOTE_NAME"

# ── ship the commit ─────────────────────────────────────────────────────────
rsh "mkdir -p $RDIR && cd $RDIR && { [ -d .git ] || git init -q; }" || die "cannot prepare $RDIR on $HOST"
REMOTE_HAVE="$(rsh "cd $RDIR && git rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null" || true)"
if ! rsh "cd $RDIR && git cat-file -e '$SHA^{commit}' 2>/dev/null"; then
  REF="refs/gate/remote-$SHORT"
  git update-ref "$REF" "$SHA"
  BUNDLE="$(mktemp -t remote-gate.XXXXXX).bundle"
  if [[ -n "$REMOTE_HAVE" ]] && git cat-file -e "$REMOTE_HAVE^{commit}" 2>/dev/null; then
    git bundle create -q "$BUNDLE" "$REF" "^$REMOTE_HAVE" || die "git bundle failed"
  else
    git bundle create -q "$BUNDLE" "$REF" || die "git bundle failed"
  fi
  git update-ref -d "$REF"
  say "sending bundle ($(du -h "$BUNDLE" | cut -f1))"
  rsh "cat > $RDIR/.gate.bundle" < "$BUNDLE" || die "bundle transfer failed"
  rm -f "$BUNDLE"
  rsh "cd $RDIR && git fetch -q .gate.bundle '$REF:$REF' && rm -f .gate.bundle" || die "remote fetch from bundle failed"
fi

# ── pin the remote checkout to exactly this commit and tree ────────────────
verify_remote_tree() { # $1 = when
  local got
  got="$(rsh "cd $RDIR && [ \"\$(git rev-parse HEAD)\" = '$SHA' ] && [ -z \"\$(git status --porcelain --untracked-files=no)\" ] && git rev-parse 'HEAD^{tree}'")" \
    || die "$1: remote checkout is not a clean $SHORT"
  [[ "$got" == "$TREE" ]] || die "$1: remote tree $got != local tree $TREE"
}
rsh "cd $RDIR && git checkout -q --force --detach '$SHA' && git submodule sync -q && git submodule update --init --force -q && find . -maxdepth 1 -name '.gate-ok-*' -delete" \
  || die "remote checkout/submodule update failed"
verify_remote_tree "before the run"

# ── run the gate there ──────────────────────────────────────────────────────
say "running local-gate.sh ${GATE_FLAGS[*]+${GATE_FLAGS[*]}} on $HOST"
rsh "cd $RDIR && $REMOTE_ENV && AG_CONTAINER_ROOT=/ag/$REMOTE_NAME bash scripts/local-gate.sh ${GATE_FLAGS[*]+${GATE_FLAGS[*]}}"
RC=$?
[[ $RC -eq 0 ]] || die "remote gate FAILED (exit $RC) — no marker written"

REMOTE_MARKER="$(rsh "cat $RDIR/.gate-ok-$SHORT" 2>/dev/null)" \
  || die "remote gate exited 0 but wrote no .gate-ok-$SHORT — not counted"
verify_remote_tree "after the run"

REMOTE_FLAGS="$(printf '%s\n' "$REMOTE_MARKER" | sed -n 's/^flags: //p')"
REMOTE_STEPS="$(printf '%s\n' "$REMOTE_MARKER" | sed -n 's/^steps: //p')"
[[ -n "$REMOTE_FLAGS" && -n "$REMOTE_STEPS" ]] || die "remote marker unreadable — not counted"
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "flags: $REMOTE_FLAGS,host=$HOST_LABEL"
  echo "steps: $REMOTE_STEPS"
  echo "commit: $SHA"
  echo "tree: $TREE"
  echo "remote: $HOST:$REMOTE_BASE/$REMOTE_NAME"
} > "$ROOT/.gate-ok-$SHORT"
printf '\033[1;32m[remote-gate] ALL %s STEPS PASSED on %s\033[0m  (marker: .gate-ok-%s, flags: %s,host=%s)\n' \
  "$REMOTE_STEPS" "$HOST_LABEL" "$SHORT" "$REMOTE_FLAGS" "$HOST_LABEL"
