#!/usr/bin/env bash
# tests/test-pre-push-hook.sh — exercises scripts/git-hooks/pre-push in a
# throwaway repo: delete-only pushes pass without a marker; any push that
# sends a commit still needs .gate-ok-<HEAD-short-sha>.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="$HERE/scripts/git-hooks/pre-push"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git -C "$TMP" init -q
git -C "$TMP" -c user.email=t@t -c user.name=t commit -q --allow-empty -m init
HEAD_FULL="$(git -C "$TMP" rev-parse HEAD)"
SHORT="$(git -C "$TMP" rev-parse --short HEAD)"
Z40=0000000000000000000000000000000000000000
Z64=0000000000000000000000000000000000000000000000000000000000000000
fail=0; n=0
run() { # name expected-exit stdin
  n=$((n+1))
  ( cd "$TMP" && printf '%b' "$3" | bash "$HOOK" >/dev/null 2>&1 ); local rc=$?
  if [[ "$rc" == "$2" ]]; then echo "ok   $1"; else echo "FAIL $1 (exit $rc, want $2)"; fail=1; fi
}
DEL="(delete) $Z40 refs/heads/old $HEAD_FULL\n"
PUSH="refs/heads/main $HEAD_FULL refs/heads/main $Z40\n"
run "single delete, no marker -> allowed"            0 "$DEL"
run "two deletes, no marker -> allowed"              0 "$DEL(delete) $Z40 refs/heads/old2 $HEAD_FULL\n"
run "sha256-length delete -> allowed"                0 "(delete) $Z64 refs/heads/old $HEAD_FULL\n"
run "empty ref list, no marker -> blocked"           1 ""
run "push commit, no marker -> blocked"              1 "$PUSH"
run "delete + push commit, no marker -> blocked"     1 "$DEL$PUSH"
touch "$TMP/.gate-ok-$SHORT"
run "push commit, marker present -> allowed"         0 "$PUSH"
run "delete + push commit, marker present -> allowed" 0 "$DEL$PUSH"
echo "$n cases"; exit $fail
