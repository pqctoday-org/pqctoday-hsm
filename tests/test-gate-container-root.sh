#!/usr/bin/env bash
# Unit test for scripts/lib/gate-container-root.sh (derive_container_root).
# Pure string logic: no Docker, no network. Exits non-zero on any failure.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=../scripts/lib/gate-container-root.sh
source scripts/lib/gate-container-root.sh
fails=0
want() { # mount root expected(or FAIL)
  local got rc
  got="$(derive_container_root "$1" "$2")"; rc=$?
  if [ "$3" = FAIL ]; then
    [ $rc -ne 0 ] && return 0
    echo "FAIL: ($1, $2) should be refused, got '$got'"; fails=$((fails + 1)); return 0
  fi
  [ $rc -eq 0 ] && [ "$got" = "$3" ] && return 0
  echo "FAIL: ($1, $2) want '$3', got '$got' (rc=$rc)"; fails=$((fails + 1))
}
M=/Users/pqctoday/Antigravity
want "$M"  "$M/pqctoday-hsm"                          /ag/pqctoday-hsm
want "$M"  "$M/pqctoday-hsm-plans-v7-1002"            /ag/pqctoday-hsm-plans-v7-1002
want "$M/" "$M/pqctoday-hsm-gate-root-1003/"          /ag/pqctoday-hsm-gate-root-1003
want "$M"  "$M/pqctoday-hsm/.claude/worktrees/agent-a" /ag/pqctoday-hsm/.claude/worktrees/agent-a
want "$M"  "/private/tmp/scratch/hsm-wt"              FAIL   # outside the mount
want "$M"  "${M}X/pqctoday-hsm"                       FAIL   # prefix collision, not a subdirectory
want "$M"  "$M"                                       FAIL   # the mount itself
want ""    "$M/pqctoday-hsm"                          FAIL   # no /ag mount found
want "$M"  ""                                         FAIL
if [ $fails -eq 0 ]; then echo "gate container-root derivation: 9 cases OK"; exit 0; fi
echo "gate container-root derivation: $fails FAILED"; exit 1
