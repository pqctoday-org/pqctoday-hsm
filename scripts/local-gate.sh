#!/usr/bin/env bash
# local-gate.sh — the pre-push validation gate for pqctoday-hsm (WP2.0).
#
# Project directive (2026-07-01): new test suites run LOCALLY, never in GitHub
# CI. This script is the single entry point that runs them. Everything a PR
# needs validated for the KMIP/CACP/policy scope runs here, on your machine,
# before you push — GitHub is not a test platform.
#
# What it runs (in order; each step must pass):
#   0. PKCS#11 mechanism ledger (per-CKM_*, both engines, static)
#   1. kmip  cargo test                       — ~600 unit + integration tests
#   2. kmip  cargo test -- --include-ignored  — the local-only suites CI skips
#                                               (op-layer policy conformance …)
#   3. rust  cargo test                       — softhsmrustv3 engine tests
#      + rust replication K2–K4 acceptance (--features educational-replication)
#   4. OASIS corpus provenance (the XML is the OASIS XML)
#   5. OASIS byte vectors match that XML (drift guard, added 2026-09-07)
#   6. OASIS KMIP 3.0 replay + baseline assert + staleness guard (99/0/3)
#   7. wasm  smoke.cjs                         — CACP bundle boots + round-trips
#   8. Rust engine PKCS#11 v3.2 conformance (257 checks) + report freshness
#   9. cross-engine PKCS#11 differential harness (every scenario vs exceptions.json)
#  10. (--cpp)  C++ ctest incl. the v3.2 compliance harness + report freshness  [opt-in, slow]
#      (--cpp also runs the ACVP harness's C++ half + cross-engine checks, C++
#      engine built to wasm in a digest-pinned emsdk image — plan 2.E)
#  11. (--acvp-wasm)  20-suite ACVP wasm harness              [opt-in, slow]
#  12. (--release-xmss) XMSS/XMSS^MT round trip vs RELEASE wasm build  [opt-in, ~15s]
#  13. (--tls-interop) §3.3.3 hybrid TLS groups vs real OpenSSL 3.6  [opt-in]
#  14. (--javajce) JavaJCE provider suite (mvn test) in pqc-dev-sandbox  [opt-in]
#  15. (--javajce-remote) JavaJCE-remote gRPC provider suite vs live pqc-grpc  [opt-in]
#  16. (--openssl-provider) vendored pkcs11-provider vs real OpenSSL 3.6, both
#                            engines (27 PASS / 0 FAIL / 0 XFAIL / 0 XPASS)  [opt-in]
#
# Steps 8-9 (Rust PKCS#11 conformance, differential harness) were opt-in
# until 2026-08-23 — both are core PKCS#11 v3.2 evidence, and both had gone
# stale invisibly while opt-in (the Rust report 45 source-commits behind
# HEAD; the differential harness never run at all outside a manual
# invocation). --cpp stays opt-in: unlike the other two, its slow step is a
# full CMake+ctest build, not proportionate to run on every push. --javajce
# stays opt-in too, for a different reason (plan
# docs/implementation-plan-jca-remaining-gaps-2026-08-25.md §WS-F): it needs
# a second container ($SANDBOX_CONTAINER, pqc-dev-sandbox — JDK 27 RC, a
# different glibc than $RUST_CONTAINER, so binaries are NOT interchangeable
# between them, see JavaJCE/README.md), which not every gate run has
# available — FAIL-never-skip semantics when the flag IS passed, matching
# --tls-interop's own precedent.
#
# --javajce-remote (plan §7, WS-E) is separate from --javajce, not folded
# into it: it exercises the gRPC client module (JavaJCE-remote/) against a
# genuinely running pqc-grpc server over real mTLS — a network-dependent
# integration suite, not the local-FFM unit suite --javajce runs. It needs
# BOTH $SANDBOX_CONTAINER (JDK 27 RC, same reason as --javajce) AND the
# pqc-grpc/admin-certs stack from pqctoday-sandbox's docker-compose.yml
# already up — checked explicitly below and failed loudly (not skipped)
# if pqc-grpc isn't reachable, same FAIL-never-skip semantics.
#
# On success it writes .gate-ok-<HEAD-sha> (with the flag set that produced
# it) so a pre-push hook can verify the gate ran on the current commit —
# see scripts/git-hooks/pre-push, installed via scripts/install-hooks.sh.
#
# Usage:
#   bash scripts/local-gate.sh                 # core gate (steps 1-7)
#   bash scripts/local-gate.sh --cpp           # + C++ ctest
#   bash scripts/local-gate.sh --acvp-wasm     # + ACVP wasm harness
#   bash scripts/local-gate.sh --release-xmss  # + XMSS/XMSS^MT vs release wasm build
#   bash scripts/local-gate.sh --javajce       # + JavaJCE provider suite (needs pqc-dev-sandbox)
#   bash scripts/local-gate.sh --javajce-remote  # + JavaJCE-remote suite (needs pqc-dev-sandbox + live pqc-grpc)
#   bash scripts/local-gate.sh --all           # everything (required before a release — see RELEASING.md)
#   RUST_CONTAINER=pqc-rust bash scripts/local-gate.sh
#   bash scripts/local-gate.sh --host=user@host --cpp  # run on another host (scripts/remote-gate.sh)
#
# Rust steps run inside the warm OrbStack container ($RUST_CONTAINER, default
# pqc-rust) which mounts ~/Antigravity → /ag with a prebuilt cargo cache.
# The --javajce step runs inside a SEPARATE container ($SANDBOX_CONTAINER,
# default pqc-dev-sandbox) instead — that is where JDK 27 actually lives.
#
# Cargo cache size cap (2026-10-01): before any build step, the preflight runs
# scripts/prune-cargo-target.sh in $RUST_CONTAINER, which keeps the shared
# /cargo-target volume (pqc-cargo-target) at or under CARGO_TARGET_CAP_GB GiB
# (default 100; 0 disables) by deleting whole /cargo-target/worktrees/<name>
# build dirs, least recently used first. It never deletes this run's dir, a
# dir modified in the last 180 minutes, the main tree's cache or
# /cargo-target/release/wasm-pack, and it never fails the gate.
#   CARGO_TARGET_CAP_GB=200 bash scripts/local-gate.sh   # raise the cap
#   CARGO_TARGET_CAP_GB=0   bash scripts/local-gate.sh   # no pruning

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_CONTAINER="${RUST_CONTAINER:-pqc-rust}"
SANDBOX_CONTAINER="${SANDBOX_CONTAINER:-pqc-dev-sandbox}"
# AG_CONTAINER_ROOT is the container-side path of THIS checkout. An explicit
# value wins (scripts/remote-gate.sh sets one). Unset, it is derived after the
# --host dispatch below from $RUST_CONTAINER's /ag mount; see "container root".
# Until 2026-10-03 it defaulted to /ag/pqctoday-hsm, the shared main tree, so a
# run from any other worktree silently tested the main tree's code.
AG_CONTAINER_ROOT="${AG_CONTAINER_ROOT:-}"

# Per-worktree cargo build directory (2026-09-02). The container image sets a
# single global CARGO_TARGET_DIR=/cargo-target, shared by EVERY worktree and
# every crate. Two gate runs in different worktrees therefore compiled into
# one fingerprint database concurrently, and nothing serialized them: cargo's
# "Blocking waiting for file lock on build directory" message appears in 0 of
# 26 gate logs on this machine, and no /cargo-target/.cargo-lock is held.
#
# That is not theoretical. On 2026-09-02 a `kmip cargo test` step failed with
#   error[E0425]: cannot find function `reset_all_engine_state_for_test`
#                 in crate `softhsmrustv3`
# while three gates ran concurrently. Root cause, from the cache's own
# bookkeeping: no softhsmrustv3 fingerprint was written during that build at
# all (a gap from 05:42 straight to 08:14) and the compiler warnings in the
# log were REPLAYED from cache, i.e. cargo judged the dependency fresh and
# reused an artifact — one built WITHOUT the dev-only `test-support` feature
# that kmip's own #[cfg(test)] code needs. The identical command, run alone
# minutes later, built the correct variant and passed.
#
# A cache that can fabricate a failure can equally fabricate a PASS, which is
# disqualifying for a validation gate whose entire job is to be believed. So
# isolate rather than retry-on-failure: every worktree gets its own build
# directory. The main tree keeps /cargo-target unchanged, so its large warm
# cache is not thrown away by this change.
# CARGO_TARGET_DIR_FOR_RUN is set in the "container root" block below, once
# AG_CONTAINER_ROOT is known.
JAVAJCE_DIR="$ROOT/JavaJCE"
JAVAJCE_REMOTE_DIR="$ROOT/JavaJCE-remote"

# --host=<user@host> (2026-09-27): run this gate for the current commit on
# another machine and write the local marker only on a PASS there at the same
# commit and tree. All of that logic, and why it is sound, is in
# scripts/remote-gate.sh; this only dispatches. Without --host nothing below
# changes: the local run is the default.
GATE_HOST=""
GATE_PASS=()
for arg in "$@"; do
  case "$arg" in
    --host=*) GATE_HOST="${arg#--host=}" ;;
    *) GATE_PASS+=("$arg") ;;
  esac
done
if [[ -n "$GATE_HOST" ]]; then
  exec bash "$ROOT/scripts/remote-gate.sh" "$GATE_HOST" "${GATE_PASS[@]+"${GATE_PASS[@]}"}"
fi

RUN_CPP=0
RUN_ACVP_WASM=0
RUN_TLS_INTEROP=0
RUN_RELEASE_XMSS=0
RUN_JAVAJCE=0
RUN_JAVAJCE_REMOTE=0
RUN_OPENSSL_PROVIDER=0
for arg in "$@"; do
  case "$arg" in
    --cpp) RUN_CPP=1 ;;
    --acvp-wasm) RUN_ACVP_WASM=1 ;;
    --rust-p11) : ;; # now always runs (step 6); flag kept accepted, no-op, for muscle memory
    --tls-interop) RUN_TLS_INTEROP=1 ;;
    --release-xmss) RUN_RELEASE_XMSS=1 ;;
    --javajce) RUN_JAVAJCE=1 ;;
    --javajce-remote) RUN_JAVAJCE_REMOTE=1 ;;
    --openssl-provider) RUN_OPENSSL_PROVIDER=1 ;;
    --all) RUN_CPP=1; RUN_ACVP_WASM=1; RUN_TLS_INTEROP=1; RUN_RELEASE_XMSS=1; RUN_JAVAJCE=1; RUN_JAVAJCE_REMOTE=1; RUN_OPENSSL_PROVIDER=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

# ── plumbing ────────────────────────────────────────────────────────────────
STEP=0
FAILED=()
say()  { printf '\n\033[1;36m[gate] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; FAILED+=("$*"); }

dexec() {
  # pipefail inside the nested shell for the same reason run_step_host sets
  # it: `docker exec ... bash -c "..."` starts a fresh shell that does not
  # inherit this script's own `set -o pipefail`, so a step whose command
  # ends in `| tail -N` or another filter would report the filter's exit
  # status, not the real command's. Central fix here covers every run_step
  # call, present and future, not just the one that already got bitten
  # (the differential harness step masked a real FATAL as PASS this way —
  # this function protects the equivalent-shaped ACVP wasm step too).
  # -e CARGO_TARGET_DIR: overrides the image's single global /cargo-target so
  # concurrent gate runs in different worktrees cannot share one fingerprint
  # database — see the CARGO_TARGET_DIR_FOR_RUN block above for the incident
  # that made this necessary.
  docker exec -e CARGO_TARGET_DIR="$CARGO_TARGET_DIR_FOR_RUN" "$RUST_CONTAINER" bash -c "set -o pipefail; $1"
}

ensure_container() {
  if ! docker exec "$RUST_CONTAINER" true 2>/dev/null; then
    say "starting container $RUST_CONTAINER"
    docker start "$RUST_CONTAINER" >/dev/null 2>&1 || {
      echo "cannot start $RUST_CONTAINER — is OrbStack running?" >&2; exit 3; }
  fi
}

# $SANDBOX_CONTAINER (pqc-dev-sandbox) is a DIFFERENT container than
# $RUST_CONTAINER — different glibc, JDK 27 RC lives only here — so this is
# a separate exec/ensure pair, not a parameter on the existing ones. See
# JavaJCE/README.md and the --javajce header comment above for why a
# binary built in one container cannot simply run in the other.
dexec_sandbox() {
  docker exec "$SANDBOX_CONTAINER" bash -c "set -o pipefail; $1"
}

ensure_sandbox_container() {
  if ! docker exec "$SANDBOX_CONTAINER" true 2>/dev/null; then
    say "starting container $SANDBOX_CONTAINER"
    docker start "$SANDBOX_CONTAINER" >/dev/null 2>&1 || {
      echo "cannot start $SANDBOX_CONTAINER — is OrbStack running?" >&2; exit 3; }
  fi
}

run_step() { # name, command(run in container)
  STEP=$((STEP+1))
  say "step $STEP: $1"
  if dexec "$2"; then ok "$1"; else bad "$1"; fi
}

run_step_host() { # name, command(run on host) — for node/wasm steps
  STEP=$((STEP+1))
  say "step $STEP: $1"
  # pipefail: a command string ending in `| tail -N` (or any filter) must
  # report the REAL command's exit status, not the filter's — bash -c
  # starts a fresh shell that does NOT inherit this script's own `set -o
  # pipefail` (that only governs pipes run directly in THIS shell), so
  # without setting it again inside the nested shell, `real_cmd | tail -15`
  # always "succeeds" here regardless of what real_cmd actually did. Found
  # 2026-08-23: the differential harness step printed "FATAL: engine not
  # built" and was still marked PASS by this function.
  if bash -c "set -o pipefail; $2"; then ok "$1"; else bad "$1"; fi
}

# ── parallel step groups (2026-09-08) ────────────────────────────────────────
# The steps below were entirely sequential, one `docker exec` at a time, on a
# machine with 18 idle cores and (after this same change) 62GB given to the
# container instead of 16GB. Several of them touch completely different
# crates/workspaces (kmip, rust, remoting, wasm) and have no dependency on one
# another — the only reason they ever waited in line was that this script
# asked them to.
#
# The one real hazard, and it is not hypothetical (see the CARGO_TARGET_DIR_FOR_RUN
# comment above this function): two `cargo` invocations sharing ONE target
# directory concurrently can make cargo believe a fingerprint is fresh when it
# was built by the OTHER invocation with different features/profile, and reuse
# the wrong artifact — silently. That is what happened on 2026-09-02 between
# concurrent WORKTREES; running kmip/rust/remoting cargo commands concurrently
# WITHIN one gate invocation, sharing $CARGO_TARGET_DIR_FOR_RUN, is the same
# hazard one level down. So each parallel lane below gets its OWN target
# directory (a subdirectory of this run's already-isolated one) — no two
# concurrent cargo processes ever point at the same target dir. Steps that
# stay logically sequential (the three kmip sub-steps: same crate, same
# reasoning as the original comments on each) run one after another WITHIN a
# single lane/subshell, so they still share a target dir safely, in series.
declare -a BG_PIDS=() BG_NAMES=() BG_LOGS=()
GATE_PARLOGS="$(mktemp -d "${TMPDIR:-/tmp}/gate-parallel.XXXXXX")"
trap 'rm -rf "$GATE_PARLOGS"' EXIT

dexec_lane() { # cmd, lane — like dexec, but isolated to its own target dir
  docker exec -e CARGO_TARGET_DIR="$CARGO_TARGET_DIR_FOR_RUN/lanes/$2" "$RUST_CONTAINER" bash -c "set -o pipefail; $1"
}

run_step_bg() { # name, command(run in container), lane
  STEP=$((STEP+1))
  local step_no=$STEP name="$1" cmd="$2" lane="$3"
  local log="$GATE_PARLOGS/step-$step_no.log"
  say "step $step_no: $name (parallel, lane=$lane)"
  ( dexec_lane "$cmd" "$lane" > "$log" 2>&1 ) &
  BG_PIDS+=("$!"); BG_NAMES+=("$name"); BG_LOGS+=("$log")
}

run_step_bg_host() { # name, command(run on host)
  STEP=$((STEP+1))
  local step_no=$STEP name="$1" cmd="$2"
  local log="$GATE_PARLOGS/step-$step_no.log"
  say "step $step_no: $name (parallel, host)"
  ( bash -c "set -o pipefail; $cmd" > "$log" 2>&1 ) &
  BG_PIDS+=("$!"); BG_NAMES+=("$name"); BG_LOGS+=("$log")
}

# A lane that must stay sequential WITHIN itself (same crate as its
# sibling sub-steps — see the kmip group below) but should still run
# CONCURRENTLY with the other lanes: run_step_bg_seq queues a (name, cmd)
# pair against a lane name without launching anything; launch_seq_lanes
# starts exactly one background subshell per distinct lane afterward, which
# runs that lane's queued commands one at a time, in the order queued — so
# two commands in the same lane never share a target dir AT THE SAME TIME,
# only in succession, which is what the CARGO_TARGET_DIR_FOR_RUN comment
# above requires. check_gate_steps_can_fail.py parses this exactly like
# run_step/run_step_bg (same `func "name" \n "cmd"` shape), so a step
# written this way gets the same UNFAILABLE/NARROWED scrutiny as any other.
declare -a SEQ_NAMES=() SEQ_CMDS=() SEQ_STEPS=() SEQ_LANES=()
declare -a LANE_PIDS=() LANE_LANE_NAMES=()

run_step_bg_seq() { # name, command(run in container), lane
  STEP=$((STEP+1))
  say "step $STEP: $1 (parallel, lane=$3, sequential within lane)"
  SEQ_NAMES+=("$1"); SEQ_CMDS+=("$2"); SEQ_STEPS+=("$STEP"); SEQ_LANES+=("$3")
}

launch_seq_lanes() { # backgrounds one subshell per distinct lane queued above.
                      # Each queued step gets its OWN rc file (step-N.rc,
                      # next to its step-N.log) written by exactly one command
                      # — no shared per-lane file to count lines in, and no
                      # ambiguity if a lane's subshell dies partway through:
                      # every step downstream of the death simply has no rc
                      # file, which join_seq_lanes reports as a plain FAILED
                      # rather than crashing the whole gate on a bad array
                      # index (the bug this replaced: a shared lane-wide rc
                      # file occasionally came back one line short of what
                      # every step's own log proved had actually run to
                      # completion — cause unconfirmed, consequence fixed by
                      # removing the shared file entirely).
  local lane i seen l2 log rc_file
  local -a seen_lanes=()
  for lane in "${SEQ_LANES[@]}"; do
    seen=0
    for l2 in "${seen_lanes[@]:-}"; do [ "$l2" = "$lane" ] && seen=1 && break; done
    [ "$seen" -eq 1 ] && continue
    seen_lanes+=("$lane")
    (
      for i in "${!SEQ_LANES[@]}"; do
        [ "${SEQ_LANES[$i]}" = "$lane" ] || continue
        log="$GATE_PARLOGS/step-${SEQ_STEPS[$i]}.log"
        rc_file="$GATE_PARLOGS/step-${SEQ_STEPS[$i]}.rc"
        dexec_lane "${SEQ_CMDS[$i]}" "$lane" > "$log" 2>&1
        echo "$?" > "$rc_file"
      done
    ) &
    LANE_PIDS+=("$!"); LANE_LANE_NAMES+=("$lane")
  done
}

join_seq_lanes() { # waits for every lane started by launch_seq_lanes, THEN
                    # prints each queued step's output and calls ok()/bad()
                    # in the order it was queued — waiting for every lane
                    # first, rather than per-lane, means a step's own rc file
                    # is always fully written by the time anything reads it.
  local li i rc
  for li in "${!LANE_PIDS[@]}"; do
    wait "${LANE_PIDS[$li]}"
  done
  for i in "${!SEQ_NAMES[@]}"; do
    cat "$GATE_PARLOGS/step-${SEQ_STEPS[$i]}.log"
    rc="$(cat "$GATE_PARLOGS/step-${SEQ_STEPS[$i]}.rc" 2>/dev/null)"
    if [ "$rc" = "0" ]; then
      ok "${SEQ_NAMES[$i]}"
    else
      bad "${SEQ_NAMES[$i]} (lane rc file: ${rc:-<missing — lane may have died early>})"
    fi
  done
  SEQ_NAMES=(); SEQ_CMDS=(); SEQ_STEPS=(); SEQ_LANES=(); LANE_PIDS=(); LANE_LANE_NAMES=()
}

join_bg_group() { # waits for every job launched by run_step_bg(_host) since
                   # the last join, in launch order, printing each one's
                   # captured output and calling ok()/bad() exactly as if it
                   # had run in place — same verdict semantics, different timing.
  local i rc
  for i in "${!BG_PIDS[@]}"; do
    wait "${BG_PIDS[$i]}"; rc=$?
    cat "${BG_LOGS[$i]}"
    if [ "$rc" -eq 0 ]; then ok "${BG_NAMES[$i]}"; else bad "${BG_NAMES[$i]}"; fi
  done
  BG_PIDS=(); BG_NAMES=(); BG_LOGS=()
}

# ── container root (2026-10-03) ─────────────────────────────────────────────
# The steps below build and test the code the container sees at
# AG_CONTAINER_ROOT, and the marker then certifies this checkout's HEAD. Those
# must be the same code, so: derive the path from the container's own /ag mount
# (never assume the main tree), prove the container sees THIS directory with a
# probe file, and record the commit and tree. The verdict writes no marker if
# tracked files differed from HEAD at the start or end of the run.
# shellcheck source=lib/gate-container-root.sh
source "$ROOT/scripts/lib/gate-container-root.sh"
if [ -z "$AG_CONTAINER_ROOT" ]; then
  GATE_HOST_AG="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/ag"}}{{.Source}}{{end}}{{end}}' "$RUST_CONTAINER" 2>/dev/null)"
  AG_CONTAINER_ROOT="$(derive_container_root "$GATE_HOST_AG" "$(cd "$ROOT" && pwd -P)")" || {
    echo "[gate] $ROOT is not inside $RUST_CONTAINER's /ag mount (${GATE_HOST_AG:-none found}), so the container cannot see this checkout." >&2
    echo "[gate] Run it with --host=<user@host>, or set AG_CONTAINER_ROOT to this checkout's container path." >&2
    exit 2
  }
fi
AG_KMIP="$AG_CONTAINER_ROOT/kmip"
AG_RUST="$AG_CONTAINER_ROOT/rust"
if [ "$AG_CONTAINER_ROOT" = "/ag/pqctoday-hsm" ]; then
  CARGO_TARGET_DIR_FOR_RUN="/cargo-target"
else
  CARGO_TARGET_DIR_FOR_RUN="/cargo-target/worktrees/$(basename "$AG_CONTAINER_ROOT")"
fi
ensure_container
GATE_PROBE=".gate-probe-$$-$RANDOM"
: > "$ROOT/$GATE_PROBE"
if ! docker exec "$RUST_CONTAINER" test -f "$AG_CONTAINER_ROOT/$GATE_PROBE"; then
  rm -f "$ROOT/$GATE_PROBE"
  echo "[gate] $RUST_CONTAINER does not see this checkout at $AG_CONTAINER_ROOT (probe file missing there). Refusing to run: the steps would test some other tree." >&2
  exit 2
fi
rm -f "$ROOT/$GATE_PROBE"
# The C++ engine and the differential harness build from three git submodules
# (liboqs, hash-sigs, xmss-reference). A fresh worktree has none of them, and
# now that the gate tests the worktree it runs from (not the main tree), that
# would fail the differential step 15 minutes in with "does not contain a
# CMakeLists.txt". Fail now instead. remote-gate.sh initialises them itself.
GATE_SUBMODULES_MISSING="$(git -C "$ROOT" submodule status 2>/dev/null | awk '/^-/ {print $2}')"
if [ -n "$GATE_SUBMODULES_MISSING" ]; then
  echo "[gate] uninitialised git submodule(s) in $ROOT:" >&2
  printf '         %s\n' $GATE_SUBMODULES_MISSING >&2
  echo "[gate] run: git -C '$ROOT' submodule update --init   (or use --host=…, which does it)" >&2
  exit 2
fi
GATE_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
GATE_TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
GATE_DIRTY_START="$(git -C "$ROOT" status --porcelain --untracked-files=no)"
say "container root: $AG_CONTAINER_ROOT (probe seen by $RUST_CONTAINER); commit ${GATE_HEAD:0:12}${GATE_DIRTY_START:+ — tracked files differ from HEAD, so no marker will be written}"

# ── steps ───────────────────────────────────────────────────────────────────

# WS-0.4 (2026-08-30): every tests/acvp/*.json vector file must carry a real,
# re-verifiable NIST/RFC provenance block — checked live against the actual
# source on every run (source_sha256 re-fetch), not just structurally. Runs
# on the host (pure Python + network, nothing container-specific needed) and
# first, before anything else: nothing downstream is trustworthy if the
# vectors it's testing against might be self-generated or drifted.
# Step 0 in spirit: the gate checks ITSELF before it checks anything else.
# Four times on 2026-09-07 a guard turned out to be protecting a defect rather
# than catching it, twice in this very file — a step that printed compiler
# errors and then declared success, and a step that ran 1032 tests while
# checking 10. Both are the same class: a verdict that cannot carry a failure.
# `check_gate_steps_can_fail.py` re-runs that judgement mechanically, and is
# sabotage-verified against both of those historical bugs.
run_step_host "gate self-check (every step can fail)" \
  "cd '$ROOT' && python3 scripts/check_gate_steps_can_fail.py"

# The container-root derivation above decides which tree every container step
# tests, so its own unit test runs on every gate (prefix collisions, paths
# outside the mount, the mount itself).
run_step_host "gate container-root derivation test" \
  "cd '$ROOT' && bash tests/test-gate-container-root.sh"

# The pre-push hook trusts the marker this gate writes; its own test pins the
# rule it enforces (delete-only pushes pass, any pushed commit needs a marker).
run_step_host "pre-push hook test (delete-only pushes allowed)" \
  "cd '$ROOT' && bash tests/test-pre-push-hook.sh"

run_step_host "ACVP vector provenance (tests/acvp/*.json)" \
  "cd $ROOT && python3 scripts/check_acvp_provenance.py"

# Plan item 2.C (ruled 2026-09-26: fail, no allowlist; live 2026-09-27 at zero
# orphans). Every tracked vector file under the test-vector roots must be
# named by a CODE line of some loader — a file only a comment or a provenance
# checker mentions is an orphan. Its scope and counts print on every run.
run_step_host "test-vector reachability (every vector file is loaded by code)" \
  "cd $ROOT && python3 scripts/check_vector_reachability.py"

# X2' (2026-09-07): per-CKM_* ledger of what each engine implements, checked
# against the two source files that BUILD the advertised lists — no engine is
# built or run, so it costs nothing and can sit up front with the other pure
# checks. Catches a mechanism added to an engine with no recorded decision, a
# ledger row that overstates, and a new header mechanism with no row at all —
# none of which the differential harness can see, because exceptions.json's
# LEGAL-MECHANISM-SET excuses `mech*` wholesale.
run_step_host "PKCS#11 mechanism ledger (per-CKM_*, both engines)" \
  "cd $ROOT && python3 scripts/check_pkcs11_mechanism_ledger.py"

ensure_container

# Cargo cache size cap (owner decision 2026-10-01). The per-worktree build
# dirs under /cargo-target/worktrees/ (see CARGO_TARGET_DIR_FOR_RUN above) are
# ~20 GB each and nothing ever deleted them: the pqc-cargo-target volume grew
# past 1 TB and was deleted by hand. scripts/prune-cargo-target.sh keeps the
# volume at or under CARGO_TARGET_CAP_GB (default 100 GiB; 0 disables) by
# deleting whole worktree build dirs, least recently used first. It never
# deletes this run's own dir, a dir modified in the last 180 minutes (another
# gate may be building there), the main tree's cache, or
# /cargo-target/release/wasm-pack; if that is not enough it only warns. The
# touch first marks this run's dir as in use, so a concurrent gate's prune
# leaves it alone even before cargo has written anything. Pruning is not a
# gate step and can never fail the gate: errors only warn.
say "preflight: cargo cache size cap (CARGO_TARGET_CAP_GB=${CARGO_TARGET_CAP_GB:-100})"
docker exec -e CARGO_TARGET_CAP_GB="${CARGO_TARGET_CAP_GB:-100}" "$RUST_CONTAINER" bash -c \
  "mkdir -p '$CARGO_TARGET_DIR_FOR_RUN' && touch '$CARGO_TARGET_DIR_FOR_RUN/.gate-last-used'; \
   bash '$AG_CONTAINER_ROOT/scripts/prune-cargo-target.sh' '$CARGO_TARGET_DIR_FOR_RUN'" \
  || printf '[cargo-cap] WARNING: pruning did not run cleanly; continuing\n' >&2

# The pruning script's own test (temp dir, never the real volume): oldest
# first, recent/current/wasm-pack kept, 0 disables, under the cap is a no-op.
run_step "cargo cache cap: prune-cargo-target.sh test" \
  "bash $AG_CONTAINER_ROOT/tests/test-prune-cargo-target.sh"

# Everything below down to the "join_bg_group" call is one parallel batch:
# kmip (its own 3 sub-steps, kept sequential WITHIN this lane — same crate,
# same reasoning each sub-step's original comment already gave), the rust
# engine, remoting, and the wasm type-check are four independent lanes, each
# with its own isolated target dir (see the block above run_step_bg's
# definition for why that isolation is required, not optional); the wasm
# smoke test and the differential harness run on the host, where there is no
# shared-target-dir hazard at all. None of these five things touch a file the
# others write, so nothing is gained by making them wait in line.
# Migrated to `cargo nextest` 2026-09-08 — measured 3m12s wall-clock for this
# ENTIRE crate (1016 tests, cold compile included) versus cargo test's default
# of running each of the 33 separate integration-test FILES as its own
# process, one at a time: parallelism only ever happened within a single
# binary, never across the crate's many binaries, so most of the machine sat
# idle for the whole step regardless of how many cores it had. nextest runs
# every binary concurrently against one shared thread pool instead. Its exit
# code is directly trustworthy (verified by sabotage: a deliberately failed
# assertion produced exit 100, propagated correctly through PIPESTATUS)
# without any of the pipefail/grep/awk machinery the cargo-test steps below
# needed just to get a verdict that couldn't be silently defeated — there is
# no pipe in any of these commands at all now, so there is nothing for
# pipefail to matter to.
#
# slh_dsa_sigver_and_siggen is still excluded here and run separately below
# with --no-capture: it's the one genuinely slow test in this suite (12
# SLH-DSA parameter sets, ~200s dominated by the slowest "s" set), and running
# it a second time here would silently double real wall-clock cost every gate
# invocation for no benefit — it's already exercised, just not in this step.
# --skip matches by substring, so this also skips nothing else by accident:
# no other test name contains this string.
run_step_bg_seq "kmip cargo test" \
  "cd $AG_KMIP && RUST_MIN_STACK=134217728 cargo nextest run --no-fail-fast -- --skip slh_dsa_sigver_and_siggen" \
  kmip

# Progress-logged separately (not folded into the step above) so a slow run
# reads as "12 parameter sets in flight," not silence — nextest's own SLOW
# marker (crossing 60s, then 120s) already does this automatically, so
# --no-capture here is belt-and-braces rather than load-bearing the way
# --nocapture was for cargo test.
run_step_bg_seq "kmip known-slow mechanisms (live progress)" \
  "cd $AG_KMIP && RUST_MIN_STACK=134217728 cargo nextest run --no-fail-fast --test acvp_roundtrip slh_dsa_sigver_and_siggen --no-capture" \
  kmip

# The verdict covers the WHOLE run: nextest's own exit code, not a narrower
# re-run of one binary (the historic bug this step's old comment recorded —
# a verdict taken from `--test policy_op_layer` alone, 10 of 1032 tests,
# while the other 1022 passed silently — cannot recur here because there is
# no second, narrower command left to accidentally decide the exit status).
run_step_bg_seq "kmip local-only suites (--include-ignored)" \
  "cd $AG_KMIP && RUST_MIN_STACK=134217728 cargo nextest run --no-fail-fast --run-ignored all" \
  kmip

launch_seq_lanes

run_step_bg "rust engine cargo test" \
  "cd $AG_RUST && RUST_MIN_STACK=134217728 cargo nextest run --no-fail-fast" \
  rust-engine

# K2–K4 key hierarchy, attestation and protected replication (2026-10-02).
# Compiled only with the non-default `educational-replication` feature, so the
# step above never builds or runs it. This lane re-runs the engine's unit
# tests WITH the feature (the vendor-interface discovery and snapshot paths
# change shape under it) plus the three acceptance suites: every K2/K3/K4
# positive, negative, crash-window, concurrency, native-ABI and two-process
# case for AES-128/192/256, ML-KEM-768 and ML-DSA-65, plus FHE P1/P2 (the
# `educational-fhe` feature implies educational-replication and pins TFHE-rs
# 1.8.1; it reproduces the client-key KAT).
run_step_bg "rust replication K2-K4 acceptance (educational-replication)" \
  "cd $AG_RUST && RUST_MIN_STACK=134217728 cargo nextest run --no-fail-fast --features educational-fhe,test-support --lib --test replication_k2 --test replication_k3 --test replication_k4 --test replication_store --test replication_store_contexts --test replication_admin_stage --test replication_admin --test replication_fhe_p1 --test replication_fhe_p2" \
  rust-replication

# The remoting workspace (gRPC + REST PKCS#11 services) had NO gate step at
# all before 2026-08-26 — its three-transport parity suite
# (remoting/acceptance) was developer-run only, so a proto/service change
# could regress CKR parity across transports invisibly. Added with the
# Pkcs11V32 C_* mirror work (docs/remoting-pkcs11-v32-full-coverage-plan-
# 2026-08-26.md, RW0). Standalone workspace ⇒ its own `cargo test`; the
# first grep catches any FAILED summary, the second reports the aggregate.
# Grown in RW-T (docs/remoting-pkcs11-v32-remaining-gaps-plan-2026-08-26.md)
# with the coverage-ledger ratchet: `cargo test` intentionally does NOT run
# the #[ignore]d v21b_xmss_hss_sign_verify_parity case (326s at this
# engine's smallest XMSS parameter set — see that test's own doc comment),
# so it stays out of the routine gate; the ledger still accounts for it via
# case_ids, and the ratchet below checks the LEDGER, not live execution of
# every ignored test. G4 (docs/remoting-pkcs11-v32-gap-remediation-plan-
# 2026-08-26.md) split the original combined V21 into this slow, still-
# ignored XMSS/HSS case and a separate fast v21a_slh_dsa_sign_verify_parity
# case (SLH-DSA-128S keygen is fast) that DOES run here — do not re-merge
# them without re-measuring, and do not remove #[ignore] from v21b without
# first re-measuring its cost; 326s per run would take this step from
# ~seconds to 5+ minutes for every contributor.
# Cheap, and it runs BEFORE the replay on purpose: if the corpus is not the
# corpus we think it is, the replay figure below is measuring something else.
run_step "OASIS corpus provenance (102 transcripts vs the CSD02 zip)" \
  "cd $AG_KMIP && python3 conformance/verify_corpus_provenance.py"

# Immediately after the corpus check, and for the same reason. That step asks
# "is the XML the OASIS XML?"; this asks "are the committed byte vectors what
# that XML actually produces?" — a question NOTHING asked before 2026-09-07.
# The Rust suites (oasis_codec_roundtrip.rs and friends) round-trip the
# committed .bin files through our own codec, so a vector that no longer
# matches its source XML still round-trips perfectly; the corpus is never
# consulted. Four vectors were stale from the 2026-07 CSD02 refresh until
# 2026-09-06 and surfaced only by accident, when an unrelated regeneration
# changed their size. --check writes nothing.
run_step "OASIS byte vectors match the XML corpus (1358 vectors)" \
  "cd $AG_KMIP && python3 conformance/harness/generate_byte_vectors.py --check"

run_step "OASIS KMIP 3.0 replay (99 PASS / 0 FAIL / 3 SKIP_DEPRECATED)" \
  "cd $AG_KMIP && cargo build --release --bin pqctoday-kmip --quiet && \
   mkdir -p target/release && ln -sf \$(readlink -f \${CARGO_TARGET_DIR:-/cargo-target}/release/pqctoday-kmip) target/release/pqctoday-kmip 2>/dev/null; \
   python3 conformance/harness/dispatcher_replay.py >/dev/null && \
   python3 conformance/assert_replay_report.py && \
   python3 conformance/check_report_fresh.py"

# Migrated to nextest along with the steps above. The old `tee /dev/stderr`
# existed because cargo test's own summary line ("85 passed, 1 failed")
# discards the failing test's NAME — on 2026-09-07 that gap led to a real
# failure being explained away with a stored assumption instead of
# diagnosed, since the name was never printed and the run wasn't
# reproducible afterwards. nextest prints a `FAIL [time] (n/total) crate::test
# full::test::name` line for every failure as part of its normal output, so
# the name is never lost in the first place — nothing to route around.
run_step_bg "remoting gRPC+REST services + three-transport parity" \
  "cd $AG_CONTAINER_ROOT/remoting && cargo nextest run --no-fail-fast && \
   python3 scripts/check_coverage_ledger.py" \
  remoting

# Does the wasm target still COMPILE? The smoke step below cannot answer that:
# it runs the already-staged bundle, so a source change that breaks the wasm
# build passes the gate and only surfaces at the next restage. That is not
# hypothetical — #166 added `server/secp384r1mlkem1024.rs` (rustls, native-only)
# without a cfg gate, the whole gate went green, and the breakage was found days
# later when someone tried to rebuild the bundle. A type-check is cheap; a full
# wasm build is not, so this checks rather than builds.
# `cmd | grep ... && exit 1` CANNOT fail once dexec sets pipefail: when the
# real command errors, the PIPELINE's status is that error (not grep's 0), so
# `&&` short-circuits and `exit 1` never runs — control falls to the statement
# after the `;`, which reports success. Found 2026-09-07: this step printed two
# E0063 errors and then "wasm32 type-check clean ✓" in the same breath, letting
# a genuinely broken wasm crate through. Take the verdict from the compiler's
# own status via PIPESTATUS[0] instead; grep stays purely for display.
run_step_bg "wasm target still compiles (cargo check)" \
  "cd $AG_CONTAINER_ROOT/wasm && cargo check --quiet --release --target wasm32-unknown-unknown 2>&1 | grep -E '^error' -A6; rc=\${PIPESTATUS[0]}; [ \"\$rc\" -eq 0 ] || exit 1; echo '  wasm32 type-check clean'" \
  wasm-check

# bench-harness is a member of the rust/ workspace, but `-p softhsmrustv3`
# tests never compile it, so nothing here built it. On 2026-09-27 hsm #241
# added a required `attributes` field to the KMIP Encapsulate/Decapsulate
# requests; bench-harness stopped compiling on main and only the KV260 image
# build (cacp pqc-fpga-bench do_compile) noticed. Same PIPESTATUS verdict as
# the wasm check above.
run_step_bg "bench-harness compiles (cargo check)" \
  "cd $AG_CONTAINER_ROOT/rust && cargo check --quiet --release --locked -p bench-harness --bin bench-harness 2>&1 | grep -E '^error' -A6; rc=\${PIPESTATUS[0]}; [ \"\$rc\" -eq 0 ] || exit 1; echo '  bench-harness type-check clean'" \
  bench-check

# wasm smoke runs on the HOST (node lives there, not in the Rust container).
# Runs the STAGED bundle — see the check above for why that is not sufficient
# on its own. Run scripts/build-kmip-wasm.sh after any wasm/ or kmip/ source
# change to regenerate it.
#
# wasm/pkg_node/ is gitignored, so a fresh worktree has never had one and this
# step failed there on a missing module rather than on anything about the code.
# Build it on demand, with --no-stage: without that flag the build also copies
# its output into the sibling pqctoday-hub checkout and stamps the current
# commit into that repo's corpus manifest, so running this gate in a feature
# worktree quietly restaged the hub from an unmerged branch (observed
# 2026-09-25). A gate must not modify a different repository.
run_step_bg_host "wasm CACP smoke" \
  "cd '$ROOT/wasm' && { [ -f pkg_node/pqctoday_kmip_wasm.js ] || NO_STAGE=1 bash '$ROOT/scripts/build-kmip-wasm.sh' --no-stage >'$ROOT/.gate-wasm-pkgnode.log' 2>&1; } && node smoke/smoke.cjs 2>&1 | tail -2 | grep -q 'PASS'"

# Was a manual-only tool until 2026-08-23 — never wired into any gate,
# despite being the instrument the 2026-08 remediation added specifically
# "to gate the rest from rotting." Builds BOTH engines fresh (see the
# script's own header for why that matters) and diffs every observable
# outcome across every registered scenario; only divergences already recorded with a
# citation in tests/differential/exceptions.json are allowed. Runs in the
# Linux validation container so the same compiler and shared-library format
# are used on every development host. Its dedicated build and cargo lane
# keep it isolated from the Rust and KMIP jobs above.
run_step_bg "cross-engine PKCS#11 differential harness" \
  "cd $AG_CONTAINER_ROOT && P11DIFF_BUILD_DIR=build_union_linux bash scripts/run-differential-harness.sh --jobs 4 2>&1 | tail -15" \
  differential

# These three touch $AG_KMIP but nothing else in the batch does, and none of
# them shares a target dir with a debug test build: the two Python checks
# below build nothing at all (pure XML/JSON/committed-.bin comparisons — the
# CARGO_TARGET_DIR a lane sets is simply irrelevant to them), and the replay's
# own `cargo build --release` is a different profile from every debug test
# build above, so it was never sharing compiled work with them regardless of
# when it runs. All three moved into the batch 2026-09-08 — they used to run
# sequentially afterward for no reason stronger than "they happen to also
# touch kmip/", which is not a real dependency.
#
# Cheap, and it's queued before the replay for the same reason it always ran
# before it: if the corpus is not the corpus we think it is, the replay
# figure is measuring something else — kept in reading order even though
# nothing here enforces it at run time.
run_step_bg "OASIS corpus provenance (102 transcripts vs the CSD02 zip)" \
  "cd $AG_KMIP && python3 conformance/verify_corpus_provenance.py" \
  oasis-checks

# Immediately after the corpus check, and for the same reason. That step asks
# "is the XML the OASIS XML?"; this asks "are the committed byte vectors what
# that XML actually produces?" — a question NOTHING asked before 2026-09-07.
# The Rust suites (oasis_codec_roundtrip.rs and friends) round-trip the
# committed .bin files through our own codec, so a vector that no longer
# matches its source XML still round-trips perfectly; the corpus is never
# consulted. Four vectors were stale from the 2026-07 CSD02 refresh until
# 2026-09-06 and surfaced only by accident, when an unrelated regeneration
# changed their size. --check writes nothing.
run_step_bg "OASIS byte vectors match the XML corpus (1358 vectors)" \
  "cd $AG_KMIP && python3 conformance/harness/generate_byte_vectors.py --check" \
  oasis-checks

run_step_bg "OASIS KMIP 3.0 replay (99 PASS / 0 FAIL / 3 SKIP_DEPRECATED)" \
  "cd $AG_KMIP && cargo build --release --bin pqctoday-kmip --quiet && \
   mkdir -p target/release && ln -sf \$(readlink -f \${CARGO_TARGET_DIR:-/cargo-target}/release/pqctoday-kmip) target/release/pqctoday-kmip 2>/dev/null; \
   python3 conformance/harness/dispatcher_replay.py >/dev/null && \
   python3 conformance/assert_replay_report.py && \
   python3 conformance/check_report_fresh.py" \
  oasis-replay

join_bg_group
join_seq_lanes

# Was opt-in (--rust-p11) until 2026-08-23. The Rust engine's own conformance
# report went 45 source-commits stale while this was skippable — a default
# gate step is what stops that recurring. Builds the wasm pkg (dev + acvp +
# larger stack) in the container, drives the real PKCS#11 ABI through the
# v3.2 conformance matrix on the host. test_p11_conformance.js itself
# regenerates rust/RUST_P11_V32_CONFORMANCE_REPORT.md from this run's real
# per-section results every time it runs to completion; the freshness check
# right after confirms the regenerated report actually matches what's
# committed (or fails loudly if it doesn't — see check_pkcs11_reports_fresh.py).
# Kept sequential, AFTER the parallel batch above rather than inside it: this
# is the one place a lane's isolated target dir would cost more than it
# saves — it wants the "rust engine cargo test" lane's own build of the same
# rust/ crate to already be warm, not a second cold compile of it running at
# the same time.
STEP=$((STEP+1)); say "step $STEP: Rust PKCS#11 v3.2 conformance (257 checks)"
# wasm-pack is built but not on the container's PATH — plain `wasm-pack` here
# fails with "command not found" and always has, invisibly, because this step
# was opt-in until now. Full path, matching how it was actually invoked by
# hand before this step was promoted to default. Found 2026-08-23.
# Stack: 8 MiB, the same value rust/build-wasm-bundle.sh ships. This step used
# 2 MiB until 2026-09-27, so the gate validated a configuration nobody ships;
# with 2 MiB the ACVP harness dies at SLH-DSA-192f ("memory access out of
# bounds", a wasm stack overflow). Keep the two in step.
if dexec "cd $AG_RUST && RUSTFLAGS='-C link-arg=-zstack-size=8388608' /cargo-target/release/wasm-pack build --target bundler --out-dir pkg --dev -- --features acvp >/dev/null 2>&1" \
   && ( cd "$ROOT/rust" && node test_p11_conformance.js 2>&1 | grep -q 'RESULT: .* 0 failed' ) \
   && ( cd "$ROOT" && python3 scripts/check_pkcs11_reports_fresh.py --rust ); then
  ok "Rust PKCS#11 v3.2 conformance (report regenerated + fresh)"
else
  bad "Rust PKCS#11 v3.2 conformance (report regenerated regardless — check it, or check_pkcs11_reports_fresh.py, for the real failure)"
fi

# Plan item 2.B (2026-09-27): the NIST ACVP wasm harness, Rust engine only,
# on every gate run. Its scope is in its name on purpose — the C++ half needs
# an Emscripten toolchain that exists nowhere here (plan 2.E), so a name that
# claimed "the ACVP harness" would reassure about an engine it never loads.
# It runs against an explicitly TEST-ONLY release build with the 8 MiB stack
# and the acvp feature. The shipped build omits that feature; this gate writes
# to gitignored rust/pkg-acvp/ and never refreshes pkg_bundler/. The conformance
# step's rust/pkg is a --dev build,
# on which the SLH-DSA "s" sets take minutes each; release runs the whole
# harness in about a minute). wasm/rust/ is gitignored and nothing else
# populates it, so the step stages the two files itself, and installs the
# harness's npm dependencies (asn1js) when a fresh worktree lacks them.
# The harness's exit code is the verdict: since 2.A it FAILs, rather than
# SKIPs, a mechanism missing from C_GetMechanismList and an HSS import error;
# known engine defects are pinned as XFAIL by register id and turn into a
# FAIL if they start passing.
run_step "ACVP harness wasm build (Rust, release, 8 MiB stack, acvp feature)" \
  "cd $AG_RUST && RUSTFLAGS='-C link-arg=-zstack-size=8388608' /cargo-target/release/wasm-pack build --release --target bundler --out-dir pkg-acvp -- --features acvp >/dev/null 2>&1"
run_step_host "ACVP wasm harness — Rust engine only (C++ WASM half not exercised)" \
  "cd '$ROOT' && (test -d node_modules/asn1js || npm ci --silent --no-audit --no-fund) && mkdir -p wasm/rust && cp rust/pkg-acvp/softhsmrustv3_bg.js rust/pkg-acvp/softhsmrustv3_bg.wasm wasm/rust/ && node tests/acvp-wasm.mjs --engine=rust 2>&1 | tail -60"

# Plan item 2.E (2026-09-27): the C++ half of the same harness, plus the
# cross-engine checks (HSS, ML-DSA, SLH-DSA, ML-KEM: signed/encapsulated by one
# engine, verified/decapsulated by the other) that only run with
# --engine=both. The C++ engine is built to wasm by the existing
# scripts/build-wasm.sh inside the official Emscripten image PINNED BY DIGEST
# (emsdk 6.0.10, arm64) — nothing is installed on the host or in
# $RUST_CONTAINER. OpenSSL-for-wasm is cached in the worktree (deps/, first
# run only); the engine build is incremental. The build log is kept in the
# worktree. --cpp only: it is the C++ lane.
EMSDK_IMAGE="emscripten/emsdk@sha256:e077d54e2b8970575ebc4f185ac1de0b95c05f2b266134d4ba27449af7aebf65"
if [[ $RUN_CPP == 1 ]]; then
  run_step_host "ACVP wasm harness — C++ engine + cross-engine checks (--engine=both)" \
    "cd '$ROOT' && docker run --rm -v '$ROOT:/src' -w /src --entrypoint bash $EMSDK_IMAGE scripts/build-wasm.sh >'$ROOT/.gate-wasm-cpp-build.log' 2>&1 && test -s wasm/softhsm.wasm && node tests/acvp-wasm.mjs --engine=both 2>&1 | tail -40"
fi

if [[ $RUN_CPP == 1 ]]; then
  # Preflight. $RUST_CONTAINER is a long-lived pet container built for Rust, and
  # it shipped without cmake, ctest or cppunit — so this step failed during
  # SETUP, never reaching a single test, while looking like an ordinary build
  # error. Check for the tools and install them once rather than rediscovering
  # this. Found 2026-08-10.
  say "step $((STEP+1)) preflight: C++ toolchain in $RUST_CONTAINER"
  if ! dexec "command -v cmake >/dev/null && command -v ctest >/dev/null && pkg-config --exists cppunit" 2>/dev/null; then
    echo "  installing cmake + libcppunit-dev (one-off, container is not rebuilt)"
    dexec "apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cmake libcppunit-dev >/dev/null 2>&1" || true
  fi
  if dexec "command -v cmake >/dev/null && command -v ctest >/dev/null && pkg-config --exists cppunit" 2>/dev/null; then
    ok "C++ toolchain present ($(dexec 'cmake --version | head -1' 2>/dev/null))"
  else
    bad "C++ toolchain missing in $RUST_CONTAINER — cannot run ctest"
  fi

  # NOTE ON COVERAGE: this container is arm64 and links a RELEASE OpenSSL, while
  # CI is amd64. It therefore cannot reproduce arch- or OpenSSL-specific faults —
  # the 2026-08 EdDSA keygen flake (CI building OpenSSL master; see PR #160) was
  # invisible here by construction. Green locally is necessary, not sufficient.
  # cpp_compliance_report.{json,md} land in $ROOT (--report path below), not
  # build/ — ctest's own add_test invocation (CMakeLists.txt) writes into
  # build/ and that copy is discarded; this explicit run is what regenerates
  # the checked-in copy, with the freshness guard immediately after it.
  #
  # OpenSSL >= 3.6 is required to even COMPILE now, not just for
  # --tls-interop's own proof below: src/vendor/pkcs11-provider's ML-KEM
  # CMS-decrypt code (commit 2cca4f0) uses
  # OSSL_PKEY_PARAM_CMS_RI_TYPE/CMS_RECIPINFO_KEM — real OpenSSL RFC 9629
  # KEMRecipientInfo support that landed in 3.6, confirmed absent from
  # 3.5.6's own headers (undeclared-identifier compile errors, not a
  # warning — found live running the real --all gate, 2026-08-25). Same
  # env-var override pattern and default path as --tls-interop below, so
  # a host that already staged that build for TLS interop needs no extra
  # setup. -DBUILD_TESTS=ON is also required and was previously missing
  # here entirely — CMakeLists.txt defaults it OFF, so this step only
  # ever found tests because a stale, undocumented `build/` from long ago
  # happened to have it cached; the `test -d build ||` guard below means
  # a truly fresh checkout would have silently found zero tests.
  OSSL_ROOT="${OPENSSL_ROOT_DIR:-/usr/local/ssl}"
  OSSL_LIB="${OPENSSL_LIB_DIR:-/usr/local/ssl/lib}"
  # >/dev/null removed from the build/compliance-test sub-steps below (was
  # silencing a multi-minute build + a several-hundred-case conformance
  # binary with zero live output — indistinguishable from a hang). Safe:
  # pass/fail here has always come from `&&`-chained exit codes, never from
  # matching this output, so surfacing it changes nothing but visibility.
  run_step "C++ ctest (incl. PKCS#11 v3.2 compliance harness) + report freshness" \
    "cd $AG_CONTAINER_ROOT && (test -d build || cmake -S . -B build -DWITH_RIPEMD160=ON -DBUILD_TESTS=ON -DOPENSSL_ROOT_DIR=$OSSL_ROOT) && \
     LD_LIBRARY_PATH=$OSSL_LIB cmake --build build -j\$(nproc) && cd build && LD_LIBRARY_PATH=$OSSL_LIB ctest --output-on-failure && \
     cd $AG_CONTAINER_ROOT && \
     ENGINE=./build/src/lib/libsofthsmv3.so; [ -f \"\$ENGINE\" ] || ENGINE=./build/src/lib/libsofthsmv3.dylib; \
     LD_LIBRARY_PATH=$OSSL_LIB ./build/p11_v32_compliance_test --engine \"\$ENGINE\" \
       --workdir ./build/p11_v32_compliance_workdir --report ./cpp_compliance_report \
       --engine-commit \$(git rev-parse HEAD) && \
     python3 scripts/check_pkcs11_reports_fresh.py --cpp"
fi

if [[ $RUN_OPENSSL_PROVIDER == 1 ]]; then
  # Coverage harness for the vendored OpenSSL provider (src/vendor/pkcs11-provider)
  # against BOTH PKCS#11 engines under the real OpenSSL 3.6.3 oracle. Design
  # record: docs/openssl-provider-coverage-audit-2026-08-25.md (§5/§6);
  # remediation priorities: docs/openssl-provider-remediation-plan-2026-08-25.md.
  # Reuses --cpp's build artifacts (provider .so + C++ engine .so); does NOT
  # force RUN_CPP itself — same FAIL-never-skip precedent as --tls-interop:
  # if the build is absent, the harness's own T0 preflight fails loudly with
  # a clear "run the --cpp gate step / cmake build first" message rather than
  # silently skipping.
  # Count is 89 as of phase-8 R41, not the 27 this label carried from the
  # audit's original phase-0 harness — a stale expectation that has already
  # cost one misdiagnosis (a real PASS=16/FAIL=74 run was read against "27"
  # as if 27 were still the target). The gate keys off the harness's own
  # exit status, never this string; keep it honest anyway.
  run_step "OpenSSL provider coverage (89 PASS / 0 FAIL / 0 XFAIL / 0 XPASS)" \
    "cd $AG_CONTAINER_ROOT && bash scripts/test-openssl-provider.sh"
fi

if [[ $RUN_ACVP_WASM == 1 ]]; then
  # tee before the tail: `tail -5` was discarding the live suite-by-suite
  # progress this harness already prints, leaving several minutes of
  # silence before the final summary — pass/fail here comes from
  # `npm run test:acvp`'s own exit code (dexec's pipefail propagates it
  # through tee/tail regardless), not from matching this output, so this
  # only adds visibility.
  run_step "ACVP wasm harness (20 suites, cross-engine)" \
    "cd $AG_CONTAINER_ROOT && npm run test:acvp 2>&1 | tee /dev/stderr | tail -5"
fi

if [[ $RUN_RELEASE_XMSS == 1 ]]; then
  # P-1 (formalized 2026-08-24) — XMSS/XMSS^MT keygen+sign+verify against
  # the RELEASE wasm build, where it is genuinely fast (~4.6s / ~6.8s total)
  # rather than the ~80s+ the main conformance harness measured against its
  # own --dev build (see that harness's own G7 section comment for why THAT
  # build stays untested by default). Builds pkg-release/ fresh on the HOST
  # (wasm-pack + rustup, not the Linux container — build-wasm-bundle.sh is
  # tied to $HOME/.rustup) before running the round trip.
  run_step_host "XMSS/XMSS^MT round trip vs release wasm build (P-1)" \
    "cd '$ROOT/rust' && ./build-wasm-bundle.sh >/dev/null 2>&1 && node test_xmss_release.js 2>&1 | tail -25"
fi

if [[ $RUN_TLS_INTEROP == 1 ]]; then
  # §3.3.3 requires all three hybrid TLS groups. SecP384r1MLKEM1024 is composed
  # locally (src/server/secp384r1mlkem1024.rs) because rustls 0.23 lacks it, and
  # a locally-composed hybrid MUST be proven against an independent peer: a
  # reversed combiner agrees perfectly with itself and with nobody else. OpenSSL
  # 3.6 has the group natively, so it is that peer.
  #
  # The container ships OpenSSL 3.5.6, which has ML-KEM but NOT this hybrid, so
  # point OPENSSL_BIN at a >= 3.6 build. One way, if a container on this host has
  # one (e.g. the sandbox network image):
  #   docker exec <ossl36-container> tar -cf - -C /usr/local ssl \
  #     | docker exec -i $RUST_CONTAINER tar -xf - -C /usr/local
  # then LD_LIBRARY_PATH=/usr/local/ssl/lib OPENSSL_BIN=/usr/local/ssl/bin/openssl.
  # The test FAILS (never skips) if the tool is missing or too old.
  OSSL_BIN="${OPENSSL_BIN:-/usr/local/ssl/bin/openssl}"
  OSSL_LIB="${OPENSSL_LIB_DIR:-/usr/local/ssl/lib}"
  # `touch` first: cargo has missed source changes across this bind mount, and a
  # stale binary once made a deliberately-sabotaged combiner report all-green.
  run_step "§3.3.3 hybrid TLS groups vs OpenSSL 3.6" \
    "cd $AG_KMIP && touch src/server/secp384r1mlkem1024.rs && \
     LD_LIBRARY_PATH=$OSSL_LIB OPENSSL_BIN=$OSSL_BIN RUST_MIN_STACK=134217728 \
     cargo test --quiet --test secp384r1mlkem1024_interop -- --ignored --test-threads=1"
fi

# Shared between --javajce and --javajce-remote (both grep a Surefire log for
# this same aggregate line) — must be defined unconditionally, not inside
# either block below: running --javajce-remote alone used to crash on
# "AGG_PATTERN: unbound variable" under this script's own `set -u`, since it
# was previously declared only inside the --javajce block and nothing ever
# ran --javajce-remote by itself to notice. Found 2026-09-08 doing exactly
# that for the first time. Definition itself (why this exact pattern, the
# end-anchor, the dual INFO/ERROR prefix) is unchanged — see the comment that
# used to sit directly above it, now above --javajce's own use of it below.
AGG_PATTERN='^\[(INFO|ERROR)\][[:space:]]+Tests run: [0-9]+, Failures: 0, Errors: 0, Skipped: [0-9]+$'

if [[ $RUN_JAVAJCE == 1 ]]; then
  # JDK 27's javax.crypto.KDF (JEP 478) and the JEP 527 TLS 1.3 hybrid-KEM
  # path this provider bridges to both need the JDK 27 RC — only
  # $SANDBOX_CONTAINER has it, so this step syncs source in fresh each
  # run (docker cp, not a bind mount — same flow used throughout the
  # provider's own development, see the implementation plan docs) rather
  # than assuming a stale prior copy is still current.
  STEP=$((STEP+1)); say "step $STEP: JavaJCE provider suite (mvn test, pqc-dev-sandbox)"
  ensure_sandbox_container
  GATE_DEST=/tmp/hsm-javajce-gate

  # 2026-09-07 — build the engine this step tests AGAINST, from this commit.
  #
  # Until now the suite ran against $SANDBOX_CONTAINER's INSTALLED
  # /usr/local/lib/softhsm/libsofthsmv3.so, which is baked into the image and
  # was dated 2026-09-01. So the step validated today's Java against a native
  # engine months old, and would keep reporting green as the two drifted
  # apart. That is not hypothetical: it was found by adding a JavaJCE test for
  # CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS, which the installed engine did not have —
  # the Java was correct and the engine was stale, and no gate run could have
  # told the difference. ANY engine-side change was invisible here.
  #
  # $SANDBOX_CONTAINER has cmake, g++ and OpenSSL 3.6.3, so it can build its
  # own. It MUST build its own: its glibc differs from $RUST_CONTAINER's, so
  # the --cpp step's binaries are not interchangeable (JavaJCE/README.md).
  #
  # The build directory is kept between runs so an unchanged tree relinks
  # rather than rebuilds. Only the files CMake needs are copied — the two
  # *.in templates are easy to forget and configure fails without them.
  JCE_ENGINE_SRC=/tmp/hsm-jce-engine
  say "  building the C++ engine inside $SANDBOX_CONTAINER (so the suite tests THIS commit's engine)"
  if ! dexec_sandbox "mkdir -p $JCE_ENGINE_SRC" \
     || ! tar czf - -C "$ROOT" CMakeLists.txt cmake src config.h.in.cmake softhsmv3.pc.in 2>/dev/null \
          | docker exec -i "$SANDBOX_CONTAINER" tar xzf - -C "$JCE_ENGINE_SRC" 2>/dev/null \
     || ! dexec_sandbox "cd $JCE_ENGINE_SRC && \
            (test -f b/CMakeCache.txt || cmake -S . -B b -DCMAKE_BUILD_TYPE=Release \
               -DWITH_RIPEMD160=ON -DOPENSSL_ROOT_DIR=/usr/local/ssl >/tmp/jce-engine-cmake.log 2>&1) && \
            LD_LIBRARY_PATH=/usr/local/ssl/lib64 cmake --build b --target softhsmv3 -j\$(nproc) \
              >/tmp/jce-engine-build.log 2>&1"; then
    bad "JavaJCE provider suite — could not build the engine inside $SANDBOX_CONTAINER (see /tmp/jce-engine-cmake.log and /tmp/jce-engine-build.log inside it)"
  fi
  JCE_MODULE="$JCE_ENGINE_SRC/b/src/lib/libsofthsmv3.so"
  # Fail loudly rather than silently falling back to the installed engine —
  # a silent fallback is exactly the failure this whole block removes.
  if ! dexec_sandbox "test -f $JCE_MODULE"; then
    bad "JavaJCE provider suite — engine built but $JCE_MODULE is missing"
  fi
  # Maven emits real ANSI color escapes even under `docker exec` with no
  # TTY (confirmed live — `[INFO]` is genuinely `\x1b[1;34mINFO\x1b[m]` on
  # the wire, not just a terminal-rendering artifact) — strip them before
  # writing the log so both this grep and a human reading the file later
  # see plain text, not escape-code noise wrapping the very line being
  # matched against.
  # `rm -rf $GATE_DEST/JavaJCE` (the WHOLE thing, not just target/) before
  # the copy — real bug caught by a sabotage test while writing this step:
  # `docker cp SRC container:DEST` copies SRC AS A SUBDIRECTORY of DEST
  # when DEST already exists (rather than overwriting DEST's contents in
  # place), so a second run without this would silently nest the new
  # source under the stale prior copy and test THAT instead — a false
  # green that would have gone undetected without deliberately re-running
  # with a flipped assertion first.
  # The success grep below must match ONLY the final aggregate summary
  # line, not one of the 25 per-suite "Tests run: N, Failures: 0..." lines
  # Surefire prints along the way (real bug caught live: an early version
  # of this pattern had no end-anchor, so it happily matched any passing
  # suite's own line even when a LATER suite failed and the real
  # aggregate read "Failures: 1" — a sabotage test with one flipped
  # assertion still reported green until this was anchored). The
  # aggregate line is the only one with no trailing
  # ", Time elapsed: ... -- in <ClassName>" text, hence the `$` anchor;
  # it is tagged [ERROR] instead of [INFO] on a real failure, hence
  # matching either prefix (a genuine failure still won't match the
  # "Failures: 0" requirement itself). Definition (shared with --javajce-remote
  # below) lives above both blocks now — see that comment for why.
  if dexec_sandbox "rm -rf $GATE_DEST/JavaJCE && mkdir -p $GATE_DEST" \
     && docker cp "$JAVAJCE_DIR" "$SANDBOX_CONTAINER:$GATE_DEST/JavaJCE" >/dev/null 2>&1 \
     && dexec_sandbox "cd $GATE_DEST/JavaJCE && \
          export JAVA_HOME=/usr/lib/jvm/jdk-27-rc && export PATH=\$JAVA_HOME/bin:\$PATH && \
          export PKCS11_MODULE=$JCE_MODULE && \
          mvn -o test 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' > /tmp/javajce-gate.log; \
          grep -E '$AGG_PATTERN' /tmp/javajce-gate.log >/dev/null"; then
    ok "JavaJCE provider suite ($(dexec_sandbox "grep -E '$AGG_PATTERN' /tmp/javajce-gate.log | tail -1"))"
  else
    bad "JavaJCE provider suite — see /tmp/javajce-gate.log inside $SANDBOX_CONTAINER for the real failure"
  fi
fi

if [[ $RUN_JAVAJCE_REMOTE == 1 ]]; then
  # Unlike --javajce (local FFM, no network), this step's whole point is a
  # real network round trip against the live pqc-grpc server over real
  # mTLS — same "run it for real, never mock" discipline as
  # remoting/acceptance/tests/three_way_parity.rs on the Rust side. That
  # server isn't part of $SANDBOX_CONTAINER itself (it's the pqc-grpc
  # container from pqctoday-sandbox's docker-compose.yml, reached over the
  # shared playground-network) — checked explicitly so a missing stack
  # fails loudly with a clear reason instead of a confusing mvn stack
  # trace three steps later.
  STEP=$((STEP+1)); say "step $STEP: JavaJCE-remote gRPC provider suite (mvn test, pqc-dev-sandbox, live pqc-grpc)"
  ensure_sandbox_container
  if ! dexec_sandbox "getent hosts pqc-grpc >/dev/null 2>&1"; then
    bad "JavaJCE-remote provider suite — pqc-grpc is not reachable from $SANDBOX_CONTAINER (start it: cd pqctoday-sandbox && docker compose up -d pqc-grpc)"
  elif ! dexec_sandbox "[[ -f /admin-certs/client.crt && -f /admin-certs/client.key && -f /admin-certs/ca.crt ]]"; then
    bad "JavaJCE-remote provider suite — /admin-certs mTLS material missing inside $SANDBOX_CONTAINER"
  else
    GATE_DEST_REMOTE=/tmp/hsm-javajce-remote-gate
    # protoSourceRoot in JavaJCE-remote/pom.xml is ../remoting/proto/proto
    # (consumed verbatim from the real Rust schema, never copied into the
    # module's own tree — see that pom's own header comment) — staged at
    # the matching relative path here, same fix as the original ad-hoc
    # staging bug (a bare parent dir doesn't exist by default under
    # docker cp; the intermediate dirs must be made first).
    if dexec_sandbox "rm -rf $GATE_DEST_REMOTE && mkdir -p $GATE_DEST_REMOTE/remoting/proto/proto" \
       && docker cp "$JAVAJCE_DIR" "$SANDBOX_CONTAINER:$GATE_DEST_REMOTE/JavaJCE" >/dev/null 2>&1 \
       && docker cp "$JAVAJCE_REMOTE_DIR" "$SANDBOX_CONTAINER:$GATE_DEST_REMOTE/JavaJCE-remote" >/dev/null 2>&1 \
       && docker cp "$ROOT/remoting/proto/proto/pkcs11_remote.proto" \
            "$SANDBOX_CONTAINER:$GATE_DEST_REMOTE/remoting/proto/proto/pkcs11_remote.proto" >/dev/null 2>&1 \
       && dexec_sandbox "cd $GATE_DEST_REMOTE/JavaJCE && \
            export JAVA_HOME=/usr/lib/jvm/jdk-27-rc && export PATH=\$JAVA_HOME/bin:\$PATH && \
            mvn -o install -DskipTests 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' > /tmp/javajce-remote-install.log" \
       && dexec_sandbox "cd $GATE_DEST_REMOTE/JavaJCE-remote && \
            export JAVA_HOME=/usr/lib/jvm/jdk-27-rc && export PATH=\$JAVA_HOME/bin:\$PATH && \
            mvn -o test 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' > /tmp/javajce-remote-gate.log; \
            grep -E '$AGG_PATTERN' /tmp/javajce-remote-gate.log >/dev/null"; then
      ok "JavaJCE-remote provider suite ($(dexec_sandbox "grep -E '$AGG_PATTERN' /tmp/javajce-remote-gate.log | tail -1"))"
    else
      # Name BOTH logs, and say which is which. This step runs two Maven
      # invocations and only the second one wrote a log, so a failure in the
      # first (the JavaJCE `install`) used to print "see
      # /tmp/javajce-remote-gate.log" for a file that did not exist —
      # 2026-09-25, when an uncached maven-jar-plugin broke `install` and the
      # message sent the reader to a nonexistent file. `install` now logs too,
      # and dropped `-q` so that log has something in it.
      #
      # Note `install` reaches the `jar` phase while --javajce's `test` does
      # not, so this step can fail on a missing plugin that --javajce never
      # needs — which is why "but --javajce passed" is not evidence here.
      bad "JavaJCE-remote provider suite — inside $SANDBOX_CONTAINER see /tmp/javajce-remote-install.log (JavaJCE 'mvn -o install', runs first) then /tmp/javajce-remote-gate.log (JavaJCE-remote 'mvn -o test')"
    fi
  fi
fi

# ── verdict ─────────────────────────────────────────────────────────────────
echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
  HEAD_SHA="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  MARKER="$ROOT/.gate-ok-$HEAD_SHA"
  # The marker certifies a COMMIT. Write it only if the tracked tree equalled
  # HEAD at the start and at the end, and HEAD did not move during the run.
  GATE_DIRTY_END="$(git -C "$ROOT" status --porcelain --untracked-files=no)"
  if [[ "$(git -C "$ROOT" rev-parse HEAD)" != "$GATE_HEAD" || -n "$GATE_DIRTY_START$GATE_DIRTY_END" ]]; then
    printf '\033[1;33m[gate] ALL %d STEPS PASSED, but NO MARKER: tracked files differed from HEAD (or HEAD moved) during the run, so the result does not describe commit %s.\033[0m\n' "$STEP" "$HEAD_SHA"
    exit 0
  fi
  FLAGS="core"
  [[ $RUN_CPP == 1 ]] && FLAGS="$FLAGS,cpp"
  [[ $RUN_ACVP_WASM == 1 ]] && FLAGS="$FLAGS,acvp-wasm"
  [[ $RUN_TLS_INTEROP == 1 ]] && FLAGS="$FLAGS,tls-interop"
  [[ $RUN_RELEASE_XMSS == 1 ]] && FLAGS="$FLAGS,release-xmss"
  [[ $RUN_JAVAJCE == 1 ]] && FLAGS="$FLAGS,javajce"
  [[ $RUN_JAVAJCE_REMOTE == 1 ]] && FLAGS="$FLAGS,javajce-remote"
  [[ $RUN_OPENSSL_PROVIDER == 1 ]] && FLAGS="$FLAGS,openssl-provider"
  {
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "flags: $FLAGS"
    echo "steps: $STEP"
    echo "commit: $GATE_HEAD"
    echo "tree: $GATE_TREE"
    echo "container_root: $AG_CONTAINER_ROOT (probe ok)"
  } > "$MARKER"
  printf '\033[1;32m[gate] ALL %d STEPS PASSED\033[0m  (marker: .gate-ok-%s, flags: %s)\n' "$STEP" "$HEAD_SHA" "$FLAGS"
  exit 0
else
  printf '\033[1;31m[gate] %d/%d STEP(S) FAILED:\033[0m\n' "${#FAILED[@]}" "$STEP"
  printf '   - %s\n' "${FAILED[@]}"
  exit 1
fi
