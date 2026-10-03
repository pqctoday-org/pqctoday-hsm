# shellcheck shell=bash
# gate-container-root.sh — sourced by scripts/local-gate.sh.
#
# derive_container_root <host-dir-mounted-at-/ag> <checkout-root>
#   Prints the container-side path of <checkout-root> (/ag/<relative path>),
#   or returns 1 when the checkout is not inside the mounted directory, in
#   which case the container cannot see it at all.
#
# Why (2026-10-03): local-gate.sh used to default AG_CONTAINER_ROOT to
# /ag/pqctoday-hsm, the shared MAIN checkout. A run from any other worktree
# therefore built and tested the main tree's code in the container and could
# write .gate-ok-<sha> for a commit it never built. It was found when a run from
# pqctoday-hsm-plans-v7-1002 failed on files that exist only in that worktree.
derive_container_root() {
  local mount="${1%/}" root="${2%/}" rel
  [ -n "$mount" ] && [ -n "$root" ] || return 1
  case "$root/" in
    "$mount"/*) ;;
    *) return 1 ;;
  esac
  rel="${root#"$mount"}"
  rel="${rel#/}"
  [ -n "$rel" ] || return 1   # the mount itself is not a checkout
  printf '/ag/%s\n' "$rel"
}
