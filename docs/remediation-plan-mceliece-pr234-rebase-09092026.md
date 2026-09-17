# PR #234 (Classic McEliece, all parameter sets) — merge-conflict remediation plan

**Date:** 2026-09-09
**Branch:** `feat/classic-mceliece-all-param-sets` (15 commits, pushed) · PR #234 open
**Blocker:** `mergeable_state: dirty` against `main` — confirmed by a real trial merge
(`git merge --no-commit --no-ff origin/feat/classic-mceliece-all-param-sets` onto
`origin/main`, in a disposable worktree), not a stale GitHub cache. This is also
why no check-suite has ever run on this PR: GitHub cannot compute a test-merge
to run CI against.
**Root cause:** the branch was cut before PR #233 (PKCS#11 v3.2 phases 2–5,
merged 2026-09-09 as `92261d48`) and before the `0.30.0` release commit
(`a3300368`). Both #233 and this branch independently touched
`SoftHSM_keygen.cpp`'s key-pair-type validation.
**Governing rules:** never resolve a conflict by mechanically favouring one side
(`--ours`/`--theirs`) without verifying the actual delta; this repo's PKCS#11
engine surface is single-editor — no parallel/unreviewed edits.

---

## 0. Conflict inventory

Four files, verified with a real trial merge (not `git merge-tree`, which
under-reported — see §7):

| File | Kind | Effort |
|---|---|---|
| `CHANGELOG.md` | Additive, no real conflict | trivial |
| `rust/RUST_P11_V32_CONFORMANCE_REPORT.md` | Machine-generated report | trivial (don't hand-merge) |
| `src/lib/SoftHSM_keygen.cpp` | Real code, but additive/independent | S |
| `tests/differential/scenarios.inc` | Two new scenarios inserted at the same list position | trivial |

None of the four represents a genuine design disagreement between #233 and
this branch — every conflict is two features whose edits happen to land on
adjacent lines. There is no case here where "pick one side" is correct; every
file needs **both** sides' content.

---

## 1. `CHANGELOG.md`

`HEAD` (main) carries the `## [0.30.0]` release section for #233. The branch
carries its own `### Added`/`### Changed` entries (still under `[Unreleased]`,
since this branch predates the 0.30.0 cut) for Classic McEliece.

**Resolution:** keep both, branch's `[Unreleased]` entries staying under
`[Unreleased]`, above `## [0.30.0]` — i.e. the same position they already
occupy on the branch, just re-based to sit above the new release section
instead of above `## [0.29.0]`. No content from either side is dropped or
edited.

---

## 2. `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`

Both sides' hunks are `machine-written` (the file says so literally) —
diverging pass counts and timestamps from two different `local-gate.sh` runs.
**Do not hand-merge this file.** Resolve the conflict by taking either side
(`git checkout --ours` is fine here specifically, because the content is
about to be discarded anyway) — then let step 18 of `local-gate.sh`
(`Rust PKCS#11 v3.2 conformance`) regenerate it fresh in §5. Verify after
the gate run that the regenerated report includes McEliece's **G8b** section
(`- G8b — Classic McEliece (BSI TR-02102-1 §2.4.2, all 10 parameter sets)`),
confirming the merge didn't silently drop that suite from the harness.

---

## 3. `src/lib/SoftHSM_keygen.cpp` — the real conflict

Both hunks sit inside `SoftHSM::generateKeyPairImpl` (`src/lib/SoftHSM_keygen.cpp:518`),
at two call sites (public-template and private-template validation) that
repeat the same guard-clause shape. At each site:

- **#233 (`HEAD`)** widened the existing EC guard to also accept the new
  `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` mechanism:
  ```cpp
  if ((pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN ||
       pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS) && keyType != CKK_EC)
  ```
- **This branch** inserted a *new*, independent guard ahead of the
  (pre-#233) EC check, for the new McEliece mechanism/key type:
  ```cpp
  if (pMechanism->mechanism == CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN && keyType != CKK_PQCTODAY_CLASSIC_MCELIECE)
      return CKR_TEMPLATE_INCONSISTENT;
  if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
  ```

These do not disagree — they're two unrelated mechanism checks that both
happen to precede the same line. **Resolution (apply identically at both
conflict sites, lines ~612 and ~650):**

```cpp
if (pMechanism->mechanism == CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN && keyType != CKK_PQCTODAY_CLASSIC_MCELIECE)
    return CKR_TEMPLATE_INCONSISTENT;
if ((pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN ||
     pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS) && keyType != CKK_EC)
```

i.e. keep the McEliece guard's early-return form, and keep #233's widened EC
condition — do not reintroduce the narrower pre-#233 EC check the branch's
side shows, since that would silently regress `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS`.

**Do not trust this by inspection alone** — §5's targeted test names exist
specifically to prove both mechanisms still work post-merge.

---

## 4. `tests/differential/scenarios.inc`

Not a logic conflict: `HEAD` inserted a new `env.mechanism_info_all` scenario
and the branch inserted a new `env.mechanism_info_classic_mceliece` scenario,
both via `add({...})` at the same point in an ordered list of scenario
registrations. **Resolution:** keep both `add({...})` blocks, in either
order (registration order in this file has no semantic meaning — each
scenario is independent and self-contained). Confirm afterward that the file
still compiles as valid C++ (balanced braces around both blocks) and that the
differential harness's scenario count increases by both scenarios, not just
one.

---

## 5. Execution steps

Follow this repo's established convention for bringing a stale feature
branch current (see `cda685d2` — merge `main` into the feature branch, not a
rebase, so the branch's own commit history and any external reviewers'
existing comments stay intact):

1. `git fetch origin`
2. Check out the branch in its own worktree (`.worktrees/mceliece-all-params`
   already exists for this) and merge main in:
   ```bash
   git -C .worktrees/mceliece-all-params merge origin/main
   ```
3. Resolve the four files per §1–§4 above.
4. `git add` the four files, then `git commit` (a plain merge commit message
   is fine — do not squash away the fact that this was a merge).
5. Run the full local gate, since this touches shared crypto/keygen code —
   don't scope down to a subset:
   ```bash
   bash scripts/local-gate.sh
   ```
   Pay specific attention to (all already-passing tests that exercise the
   two mechanisms this conflict touched):
   - `JavaJCE/src/test/java/com/pqctoday/hsm/jce/ECExtraBitsTest.java` (#233's
     `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` coverage — proves the EC guard rewrite
     in §3 didn't regress it)
   - `kmip/tests/frodokem_mceliece_e2e.rs` (`classic_mceliece_6688128_round_trip`
     and friends — proves the McEliece guard still accepts its own key type)
   - Rust PKCS#11 v3.2 conformance step (step 18) — confirm `G8b` (Classic
     McEliece) appears in the regenerated report per §2
   - Cross-engine differential harness (step 9) — confirm both new §4
     scenarios ran and passed, not just one
6. Push the merge commit: `git push` (expect the pre-push hook to require a
   fresh `.gate-ok-<sha>` marker for the merge commit itself — step 5 already
   produces this).

---

## 6. Merge mechanics — do not admin-override this one

PR #233 was merged today via `--admin`, but only because it was blocked
*solely* by a missing code-owner review with 8/8 CI checks green — the code
itself was fully machine-verified. **This PR is different**: it currently has
*zero* CI history, and the conflict resolution in §3 is a hand-edit to shared
crypto keygen validation, not machine-generated. Once §5 is pushed:

- Let the PR's own `pull_request`-triggered CI run for real this time (it
  couldn't before, per the root cause above) and confirm all 8 checks that
  ran on #233 also pass here.
- Get an actual code-owner review of the §3 resolution specifically — it's a
  hand merge of two independent guard clauses, exactly the kind of change
  that reads as obviously-correct and is easy to get subtly wrong (e.g.
  reversing which condition returns early).
- Only merge normally (no `--admin`) once both are satisfied.

---

## 7. Note on tooling

`git merge-tree <merge-base> <A> <B>` (the three-argument deprecated form)
reported **zero** conflicts for this exact pair of refs, while GitHub's
`mergeable_state` said `dirty` and a real `git merge --no-commit --no-ff` in a
disposable worktree found the four conflicts documented above. Don't trust
the plumbing command's silence as proof of a clean merge on this repo again —
confirm with a real trial merge (and `git merge --abort` /
`git worktree remove --force` afterward) before reporting mergeability either
way.
