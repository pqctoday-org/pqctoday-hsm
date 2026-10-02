#!/usr/bin/env bash
# Test for scripts/prune-cargo-target.sh, against a temp dir standing in for
# /cargo-target. Needs GNU coreutils (du --time, touch -d, realpath -m), so it
# runs inside the gate container; local-gate.sh runs it as a step:
#
#   docker exec pqc-rust bash /ag/<worktree>/tests/test-prune-cargo-target.sh
#
# Each worktree dir holds 1 MiB of real (non-sparse) data, so du sees it.
# Sabotage-checked 2026-10-01: with the recency guard removed from the script,
# case 2 fails (the recent dir is deleted).

set -u

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/scripts/prune-cargo-target.sh"
FAILS=0
pass() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; FAILS=$((FAILS + 1)); }
expect_present() { if [ -e "$1" ]; then pass "$2"; else fail "$2 ($1 was deleted)"; fi; }
expect_absent()  { if [ -e "$1" ]; then fail "$2 ($1 still exists)"; else pass "$2"; fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# make_dir <path> <age, as `touch -d` understands it>
make_dir() {
  mkdir -p "$1/debug/deps"
  head -c 1048576 /dev/urandom > "$1/debug/deps/libx.rlib"
  find "$1" -exec touch -h -d "$2" {} +
}

# A fresh fake /cargo-target:
#   release/wasm-pack, main-tree cache (2 MiB)
#   worktrees/old-a (3 days), old-b (2 days), old-c (1 day),
#   worktrees/cur (5 days, but it is this run's own dir),
#   worktrees/recent (10 minutes ago)
setup() {
  R="$TMP/$1"
  mkdir -p "$R/release" "$R/debug"
  head -c 1048576 /dev/urandom > "$R/release/wasm-pack"
  head -c 2097152 /dev/urandom > "$R/debug/main-cache"
  find "$R/release" "$R/debug" -exec touch -h -d '30 days ago' {} +
  make_dir "$R/worktrees/old-a" '3 days ago'
  make_dir "$R/worktrees/old-b" '2 days ago'
  make_dir "$R/worktrees/old-c" '1 day ago'
  make_dir "$R/worktrees/cur" '5 days ago'
  make_dir "$R/worktrees/recent" '10 minutes ago'
}
total_kb() { du -sxk "$1" | awk '{ print $1 }'; }
run_prune() { # root, cap_kb, [CARGO_TARGET_CAP_GB]
  CARGO_TARGET_ROOT="$1" CARGO_TARGET_CAP_KB="$2" CARGO_TARGET_CAP_GB="${3:-100}" \
    bash "$SCRIPT" "$1/worktrees/cur" > "$TMP/out.log" 2>&1
  local rc=$?
  sed 's/^/      | /' "$TMP/out.log"
  return $rc
}

echo "case 1: oldest dir goes first, and pruning stops once under the cap"
setup c1
T="$(total_kb "$R")"
# Removing old-a alone (1 MiB + a little) is enough.
run_prune "$R" $((T - 512)) && pass "exit 0" || fail "non-zero exit"
expect_absent  "$R/worktrees/old-a" "oldest (old-a) removed"
expect_present "$R/worktrees/old-b" "old-b kept (cap already met)"
expect_present "$R/worktrees/old-c" "old-c kept (cap already met)"
expect_present "$R/worktrees/cur" "current run's dir kept"

echo "case 2: cap below what pruning can reach — recent, current and wasm-pack survive"
setup c2
run_prune "$R" 1024 && pass "exit 0" || fail "non-zero exit"
expect_absent  "$R/worktrees/old-a" "old-a removed"
expect_absent  "$R/worktrees/old-b" "old-b removed"
expect_absent  "$R/worktrees/old-c" "old-c removed"
expect_present "$R/worktrees/recent" "recent dir (10 min) kept"
expect_present "$R/worktrees/cur" "current run's dir (5 days old) kept"
expect_present "$R/release/wasm-pack" "release/wasm-pack kept"
expect_present "$R/debug/main-cache" "main tree cache kept"
grep -q 'still over the cap' "$TMP/out.log" && pass "still-over-cap warning printed" || fail "no still-over-cap warning"
grep -q "! -name wasm-pack" "$TMP/out.log" && pass "manual command keeps wasm-pack" || fail "manual command missing"
# Order of removal is oldest first.
order="$(grep -o 'removed old-[abc]' "$TMP/out.log" | tr '\n' ' ')"
[ "$order" = "removed old-a removed old-b removed old-c " ] && pass "removal order old-a, old-b, old-c" || fail "removal order was: $order"

echo "case 3: CARGO_TARGET_CAP_GB=0 disables the cap"
setup c3
CARGO_TARGET_ROOT="$R" CARGO_TARGET_CAP_GB=0 bash "$SCRIPT" "$R/worktrees/cur" > "$TMP/out.log" 2>&1 \
  && pass "exit 0" || fail "non-zero exit"
sed 's/^/      | /' "$TMP/out.log"
for d in old-a old-b old-c cur recent; do expect_present "$R/worktrees/$d" "$d kept"; done
grep -q 'cap disabled' "$TMP/out.log" && pass "says the cap is disabled" || fail "no 'cap disabled' line"

echo "case 4: under the cap is a no-op"
setup c4
T="$(total_kb "$R")"
run_prune "$R" $((T + 1024)) && pass "exit 0" || fail "non-zero exit"
for d in old-a old-b old-c cur recent; do expect_present "$R/worktrees/$d" "$d kept"; done
grep -q 'nothing to do' "$TMP/out.log" && pass "says nothing to do" || fail "no 'nothing to do' line"

echo "case 5: a missing root never fails"
CARGO_TARGET_ROOT="$TMP/does-not-exist" CARGO_TARGET_CAP_KB=1 bash "$SCRIPT" x >/dev/null 2>&1 \
  && pass "exit 0 on a missing root" || fail "non-zero exit on a missing root"

echo
if [ "$FAILS" -eq 0 ]; then
  echo "prune-cargo-target test: PASS"
  exit 0
fi
echo "prune-cargo-target test: $FAILS FAILED"
exit 1
