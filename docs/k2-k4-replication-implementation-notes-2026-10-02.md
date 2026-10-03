# K2–K4 key hierarchy, attestation and replication — implementation notes

Date: 2026-10-02 · Branch: `feat/hsm-replication-k2k4-1002` (stacked on `ba9c5d41`, local only)
Scope: Rust engine `softhsmrustv3`, native. **Educational software token only.**

This records what was built, every decision the K0B specification
(`docs/proposals/pqctoday-key-replication-interface-1.0.md`) left open, and how each
finding of the independent review (`docs/k0b-protocol-review-codex-2026-10-02.md`) was
disposed of. The §B edits were approved by the owner and applied to the K0B spec as revision 2. Fixes from the
second independent review (`docs/k0b-protocol-review-claude-2026-10-03.md`) are spec revision 3;
where this file and that review differ, the review's dispositions are current.

## A. What exists now

| Phase | Delivered | Evidence |
|---|---|---|
| K2 hierarchy | In-token device identity key + PKCS#10 proof of possession; host-side test manufacturing CA; SO enrollment of root, device certificate and root CRL; five function keys certified under the device issuer; device-issuer CRLs; peer CRL enrollment; policy enrollment; recovery-key rotation; snapshot format F14 (`SHR3SNP3`) | `rust/tests/replication_k2.rs` — 6 tests |
| K3 attestation | RATS -07-shaped evidence, engine-computed claims, domain-separated ML-DSA-65 signature; shared verification core used by the engine and by a host verifier over public bytes | `rust/tests/replication_k3.rs` — 3 tests |
| K4 replication | Challenge reservations, request/package/receipt, HPKE ML-KEM-768/HKDF-SHA384/AES-256-GCM sealing, atomic install + ledger commit, exact-retry recovery, crash injection, `CloneKey`, budget conservation, native `PQCTODAY_KEY_REPLICATION_1_0` discovery | `rust/tests/replication_k4.rs` — 19 tests incl. a real two-process run |

Everything compiles only with the non-default cargo feature `educational-replication`
and is inert until a caller runs `replication::select_educational_profile()`. No shipped
build enables the feature. `C_GetInterface*` returns the vendor interface only when both
are true; a NULL interface name still selects the standard `PKCS 11` 3.2 list, and
`CK_FUNCTION_LIST_3_2` is unchanged.

Not delivered (deliberately out of this change): K5 WASM/browser flow and Hub lessons
(start only after K4 freezes and the authority lands), FHE seed profile (R5), production
OIDs (G2), hardware roots (K6), archival validation (see R-14).

## B. Spec edits (owner approved 2026-10-02; applied as K0B spec revision 2)

| Edit | Spec § | Change | Reason |
|---|---|---|---|
| E-01 | §5.1 | Evidence signed bytes = `"PQCToday Key Replication Evidence 1.0" ‖ 0x00 ‖ role ‖ DER(TbsEvidence)`; roles source 0, destination 1, key attestation 2 | K0B-R-01 |
| E-02 | §5.1 | Freeze the claim profile in §E below; strict DER and canonical-order check before signature verification | K0B-R-02 |
| E-03 | §5, §7 | `deviceID = SHA-256(DER(device certificate SubjectPublicKeyInfo))`; every device claim must equal the device of the chain that signed it | K0B-R-03, R-10 |
| E-04 | §5.1 | Challenges are engine-issued and durably reserved: `issue_source_challenge` (5 min) and `begin_receive` (destination challenge + transaction ID, bound to operation and requested policy) | K0B-R-04 |
| E-06 | §5, §6 | Base mode; KEM 0x0041, KDF 0x0002, AEAD 0x0002; encapsulation exactly 1,088 bytes; ciphertext checked against bounds before decapsulation | K0B-R-06 |
| E-07 | §3.1 | The destination engine generates the 32-byte transaction ID; the source rejects any reuse of a cached transaction ID with a different request or source key | K0B-R-07 |
| E-09 | §3.2 | Ledger states `reserved` → `committed`. An exact retry of a reserved transaction re-runs the import; only a committed one returns the stored receipt | K0B-R-09 |
| E-11 | §3.2 | The public partner of an ML-KEM/ML-DSA replica is a token object sharing `CKA_ID` and the lineage; it is installed in the same commit | K0B-R-11 |
| E-12 | §6, §8 | Header gains `transferredBudget`; an export costs 1 plus the budget it transfers, so a lineage never exceeds the source's `maxReplicas`. Canonical `ReplicationProvenance` DER defined | K0B-R-12 |
| E-13 | §9 | Every trust, identity, recipient and policy refusal after DER parsing returns `CKR_ACTION_PROHIBITED`; the reason goes to `oplog` only | K0B-R-13 |
| E-14 | §3.2 | Reservation lifetime is the freshness bound at import: 5 min for live clone and restore, the requested policy's `notAfter` for offline backup | needed for offline restore |

## C. Decisions on points the spec left open

1. **Enrollment surface.** K0B specifies only the three replication calls. Enrollment,
   CRL, policy, rotation and challenge operations are Rust-level functions in
   `replication::*`, SO- or user-gated as the spec's role model requires. They are not
   exported through the C ABI or WASM; K5 adds the WASM shims.
2. **Where state lives.** Hierarchy keys, certificates, anchors, CRLs, policies,
   challenge reservations, ledger entries and cached packages are token objects tagged with
   the engine-private `CKA_PRIV_REPL_ROLE`. The snapshot and the SQLite store therefore
   persist them like any key. They are `CKA_MODIFIABLE`, `CKA_COPYABLE` and
   `CKA_DESTROYABLE` false.
3. **Eligibility.** A key is replicable only when both the public
   `CKA_PQCTODAY_REPLICATION_POLICY_ID` and the engine-private `CKA_PRIV_REPL_BINDING`
   agree. Binding happens only in `C_GenerateKey`/`C_GenerateKeyPair` (locally generated,
   token, sensitive, non-extractable, non-copyable, non-modifiable, non-derivable,
   AES-128/192/256, ML-KEM-768 or ML-DSA-65). Every other creation path refuses the four
   replication attributes, the generic template absorber skips them, and
   `C_SetAttributeValue` refuses them. These guards apply in **all** builds, not only the
   feature build.
4. **Mechanism allowlist.** At binding, the key's `CKA_ALLOWED_MECHANISMS` is set to the
   policy's list. A template asking for a different list is refused.
5. **CRLs.** The SO enrolls the root CRL and each peer device's CRL (with the peer device
   certificate, which must itself chain to an enrolled root). CRL numbers must strictly
   increase per issuer. Verification fails closed when no current CRL exists for an
   issuer.
6. **Function keys are not oracles.** Usage flags are false and the allowlist names only
   an engine-internal mechanism (or nothing), so `C_Sign`/`C_Decapsulate` refuse them.
7. **Same-device copies** require `allowSameDevice` in both policies.
8. **Concurrency.** One process-wide lock serializes every replication state transition.
   A logout (which re-keys private handles) racing an import makes the atomic commit
   abort rather than half-apply.
9. **Snapshot F14.** `SHR3SNP3` = SNP2 body + trailer (`REPL`, section version 1,
   replication-object count, `SNP3END\0`). SNP2 migrates by **dropping** all replication
   objects and attributes, so a forged pre-feature record cannot grant eligibility.
   `SHR3SNP4+` and an unknown section version return
   `CKR_PQCTODAY_SNAPSHOT_FORMAT_UNSUPPORTED`. The bump applies to all builds.
10. **Recovery-key rotation.** The new key is certified by the same device issuer (that
    chain is the continuity proof). The old key is retained as retired, so packages already
    sealed to it still import. Revoking the old certificate is a separate explicit CRL step.

## D. Review dispositions (G1)

Reviewer: Codex `gpt-5.6-sol`, fresh context, read-only.
**Independence caveat:** the K0B spec and K1 were authored in a Codex IDE session, so
this reviewer is the same model family as the author, though not the same context. The
implementer (Claude) did not review its own work. Whether this satisfies "the reviewer
must not be the protocol author" is an owner call.

| ID | Sev | Disposition | Executable proof |
|---|---|---|---|
| R-01 | high | Adopted (E-01) | `k3_refusals` (wrong role ×2) |
| R-02 | high | Adopted (E-02) | `k3_refusals` (BER, reordered claims) |
| R-03 | high | Adopted (E-03) | `k3_refusals` (device swap), `k4_substitution_*` |
| R-04 | high | Adopted (E-04) | `k4_trust_*` (unissued challenge, reuse across transactions) |
| R-05 | info | Bindings retained | `k4_trust_*`, `k4_substitution_*` |
| R-06 | medium | Adopted (E-06) | `k4_malformed_*`, `parse_package` length checks |
| R-07 | high | Adopted (E-07) | `k4_trust_*` (transaction-ID reuse across keys) |
| R-08 | info | Retained | `k4_sizing_*`, `k4_native_interface_*` |
| R-09 | high | Adopted (E-09) | `k4_every_crash_window_*` (5 points, restart via snapshot) |
| R-10 | medium | Adopted (E-03) | `host_verify::verify_receipt` device-equality check; `k4_clone_key_*` |
| R-11 | medium | Adopted (E-11) | `k4_offline_*` (public partners), payload consistency checks |
| R-12 | high | Adopted (E-12) | `k4_budget_is_conserved_*` |
| R-13 | medium | Adopted (E-13) | every `PROHIBITED` assertion in `replication_k4.rs` |
| R-14 | high | **Accepted limitation (owner decision 2026-10-02: keep refusing; spec §10a).** Tombstones are retained independently of object deletion, and a deleted replica's retry is terminal. Archival-time validation is **not** implemented: a restore whose signer certificate or CRL has expired is refused (fail closed). An offline backup is restorable only while the chain and CRLs are current | `k4_offline_*`; CRL expiry fail-closed in `k4_substitution_*` |
| R-15 | high | Mostly adopted: bounds on policy DER, policy count, CRL size, count and entries, evidence, request, package, plaintext, cached packages, ledger and open challenges; checked before allocation or signature work. Not done: an authenticated-snapshot size cap | constants in `records.rs`/`package.rs`; `k4_malformed_*` |

Owner decision on independence: a second, fresh reviewer who wrote neither the spec nor the
code reviewed the amended spec and this implementation. It found 12 issues, all fixed (see
`docs/k0b-protocol-review-claude-2026-10-03.md`). **G1 closed: the owner signed off on both reviews on 2026-10-03 08:05 CDT.**

## E. Educational evidence claim profile (`1.3.6.1.4.1.32473.20261002.3`)

Three elements, always in this order, with claims in this order (optional claims are
omitted, never null):

- `.3.0.0` transaction: nonce (OCTET STRING 32), role (INTEGER), transactionID?, domainID?, policy?, suite (OID)
- `.3.0.1` platform: deviceID (OCTET STRING 32), engine (UTF8), custody scope (UTF8), issuedAt (GeneralizedTime)
- `.3.0.2` key: uniqueID (UTF8), publicKeyHash? (SHA-384 of SPKI), keyType, parameterSet (AES: key length in bytes), sensitive, extractable, neverExtractable, local, lineage?, policy?, provenance?

Claim OIDs are `.3.1.<element>.<n>`; see `rust/src/replication/oids.rs`. Every claim is
recomputed by the engine from the object; only the nonce comes from outside.

## F. Known limitations (all disclosed as educational)

- The snapshot is not authenticated: whoever can supply one can forge replication state.
- Software token: no tamper resistance or rollback resistance. A host administrator can
  roll back the snapshot, including the ledger. Host clock only.
- The K2 CSR carries proof of possession but no LAMPS CSR-attestation statement.
- `deviceID` binds only to the device certificate SPKI; there is no hardware identity before K6.
- Ledger capacity exhaustion (4,096) is enforced but not exercised by a test, because it
  would need 4,096 imports.
- The host verifier shares its verification core with the engine. K3 agreement tests
  prove that trust inputs from public bytes and trust inputs from enrolled records give
  the same verdicts. They do not prove two independent implementations.
