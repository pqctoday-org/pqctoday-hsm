# K0B second independent review — Claude, fresh context

Reviewer: Claude, fresh context. It was independent of both the spec author (Codex) and the
implementer (a separate Claude session), and it was read-only.
Scope: worktree `pqctoday-hsm-replication-k2k4-1002` at `099d3125` (spec revision 2 and the K2–K4
implementation). It confirmed findings by reading the source and by running probe tests in a
scratch copy outside the repository.
Commissioned by the owner on 2026-10-02 because the first reviewer (Codex) also wrote the spec.

## Findings and dispositions

Every disposition was re-verified against the source before fixing. Each fix has a regression test
in `rust/tests/replication_k4.rs`, `replication_k2.rs` or `replication_store.rs`.

| ID | Sev | Finding | Disposition | Proving test |
|---|---|---|---|---|
| R2-01 | high | A replica lost the source's restriction templates; the reviewer's probe showed a replica decapsulating to an extractable secret the source refused | **Fixed:** keys carrying `CKA_*_TEMPLATE` or `CKA_WRAP_WITH_TRUSTED` (either half) are not eligible in v1 (spec §8) | `k4_restricted_keys_are_not_eligible_k0b_r2_01` |
| R2-02 | high | With the SQLite store, logout re-keyed private objects only in memory; the next login rehydrated duplicates, each with its own budget. **Pre-existing engine bug affecting every private token object** | **Fixed in the engine:** the stored rows follow the re-key in one SQL transaction | `store_relogin_and_restart_keep_one_copy_and_conserve_budget` (sabotage of the fix → red) |
| R2-03 | medium | `commit_objects_atomically` was atomic only in memory; store rows were written one by one with errors ignored | **Fixed:** all rows of one commit are written in one SQLite transaction BEFORE memory changes; a store failure returns `CKR_DEVICE_ERROR` with nothing changed | same store test: restart from SQLite yields exactly one replica and the byte-identical receipt |
| R2-04 | medium | Records were never evicted: the cache bricked at 256 creates, challenges grew without bound, and abandoned offline reservations were stuck | **Fixed:** cached packages are pruned after 1 h, dead challenges are pruned, `cancel_receive` added; ledger entries are still never pruned (spec §11) | `k4_records_are_pruned_and_reservations_cancellable_k0b_r2_04` |
| R2-05 | low | The importer did not re-check the destination policy against the source policy | **Fixed:** the source policy must be enrolled at the destination and the destination policy must be equal or stricter | `k4_importer_rechecks_source_policy_k0b_r2_05` |
| R2-06 | low | Mutating operations were accepted from read-only sessions | **Fixed:** `CKR_SESSION_READ_ONLY` | `k4_read_only_sessions_cannot_mutate_k0b_r2_06` |
| R2-07 | low | Collapsed codes meant two negative tests passed for a different reason than claimed; no expired-peer-CRL test existed | **Fixed:** `replication::last_refusal()` (audit reason, test use); the wrong-recipient test now asserts its true reason; a new expired-CRL test asserts "no current CRL for issuer". The recipient-key check itself is defence in depth (unreachable without forging the source signature), and that is now stated | `k4_trust_*`, `k4_expired_peer_crl_fails_closed_k0b_r2_07`, `k4_budget_*` |
| R2-08 | low | Precedence: CloneKey sizing skipped source checks; import checked state before DER; a CloneKey receipt failure followed the commit | **Fixed** for the first two; the third is now documented in spec §3.3 | `k4_clone_sizing_checks_the_source_first_k0b_r2_08` |
| R2-09 | low | A receipt was bound only by package hash | **Fixed:** `verify_receipt` takes the request and binds the recipient device, transaction, lineage and installed policy | `k4_receipt_is_bound_to_the_packages_recipient_k0b_r2_09` |
| R2-10 | low | The requester's policy choice set the transferred budget, so one request could drain the source | **Fixed:** the source fixes the transfer (1 for offline backup, 0 otherwise; spec §8) | `k4_one_request_cannot_drain_the_source_k0b_r2_10`, `k4_budget_*` |
| R2-11 | low | Native `destroy_object` ignored `CKA_DESTROYABLE`. **Pre-existing engine gap** | **Fixed in the engine** | `k4_native_destroy_respects_destroyable_k0b_r2_11` |
| R2-12 | info | The spec called the snapshot "authenticated"; an untrusted u32 sized an allocation | **Fixed:** spec now says unauthenticated; the attribute count is bounded by the remaining input | `k2_snapshot_format_f14` |

## Found while fixing R2-02/R2-03

**Pre-existing engine data-loss bug in `store::configure_persistent_store`.** On a multi-slot restart
it created `CKO_PROFILE` objects before reserving stored handles. A new profile object could get a
handle another slot already stored, and its persist overwrote that row. Here that lost the trust
anchor, the enrollment record and the device public key. **Fixed:** all stored handles (private rows
included) are reserved first, then tokens and objects are restored, and only then are profile objects
created for slots that have none. The store test failed on the old code and passes now.

## Confirmations of the first review

The reviewer confirmed the Codex fixes R-01, R-02, R-03, R-04, R-06, R-07, R-08, R-11 and R-13 as
correct in code. It found R-05, R-09, R-10, R-12, R-14 and R-15 incomplete; all of those are
addressed by the rows above.
