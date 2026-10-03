# Second independent review: replication admin/ceremony addendum DRAFT 3.1

Date: 2026-10-03 · Reviewer: Codex `gpt-5.6-terra` (owner: second review on terra), fresh context, read-only.
Prompt: `k0b-admin-addendum-review2-codex-2026-10-03.prompt.txt`.

reviewer model: gpt-5.6-terra

1. **B-01 — medium — §3.4, §3.6 (`issueDeviceCrl`).** An admin can revoke the active receipt-signing certificate in the same operation whose receipt must be signed by that key. The receipt is then immediately invalid under §3.6’s requirement to validate it against current CRLs. This also makes the durable ledger’s recovered receipt unverifiable. **Fix:** forbid revoking the active receipt-signing leaf in `issueDeviceCrl`, or define a signed successor/receipt-validation transition that preserves verifiability of the operation’s receipt. Define historical receipt validation semantics explicitly.

2. **B-02 — high — §6.3, §6.8–§6.11; A-02/A-04/A-05 are not applied to the current bridge.** The present KMIP bridge still serves `PQCTODAY_KEY_REPLICATION_1_0`, resolves a session from mutable `auth.identity`, accepts raw package bytes for Import while discarding templates, returns only a receipt, and exposes the test ceremony interface. It has neither the specified `ImportCall`/`ImportResult` envelopes nor connection-scoped application contexts or transport-EKU roles. Thus the document’s assertion that the bridge is fixed is inaccurate, and an enabled educational build can diverge from the proposed security contract. **Fix:** disable this bridge pending the final binding, or implement and gate the full §6 contract together: immutable transport metadata, C1 contexts, exact interfaces, canonical envelopes, template handling, listener/frame limits, and tests.

3. **B-03 — medium — §1, §3.2 step 3, §3.5.** The replay-ledger pruning rule contradicts the promised retry and receipt-recovery behavior. Pruning deletes the full request and receipt but retains only `(hash, sequence)`; step 3 requires a byte-equal stored request and returns its stored receipt. A tombstone therefore cannot perform the specified lookup or recover the receipt, despite §1 saying receipts under a replaced authority remain recoverable. **Fix:** either retain request and receipt for the promised recovery period, or define tombstone matching as a terminal refusal keyed by `adminKeyID`, sequence, hash, and exact-request evidence. State clearly that pruned receipts are not recoverable if that is intended.

4. **B-04 — medium — §6.3.** The transport-role profile still does not normatively specify client-certificate path validation: the exact configured trust anchor(s), validity and revocation checking, permitted chain shape, and rejection behavior are absent. “Issued by a dedicated … CA configured for this listener” is insufficiently precise for interoperable authorization and can devolve into a broad TLS trust-store check. **Fix:** require validation only to explicitly pinned replication-client CA roots, with validity, revocation, EKU-criticality, chain-length, and dual-role rejection checks before context creation.

5. **B-05 — low — §3.1, §3.6.** `AdminSignedRequest.signatureAlgorithm` is constrained to ML-DSA-65 with absent parameters, but `AdminReceipt.signatureAlgorithm` is not. The receipt verifier is told to verify a signature but not to reject an unexpected AlgorithmIdentifier, parameter encoding, BIT STRING unused bits, or non-3309-byte signature. This permits implementation divergence and weakens signature-format domain separation. **Fix:** require the receipt AlgorithmIdentifier to equal canonical `id-ml-dsa-65` with absent parameters, and require exactly 3309 octets with zero unused bits.

6. **B-06 — low — §4, §3.4, base §9.** Return-code treatment of malformed operation payloads is ambiguous. For example, malformed policy DER or malformed CRL DER sits inside a DER-valid `AdminSignedRequest`; §4 can be read as making it an operation-specific `CKR_ACTION_PROHIBITED`, while the current engine returns `CKR_DATA_INVALID` for malformed policies. **Fix:** explicitly classify syntactic failures of each embedded payload as `CKR_DATA_INVALID` before trust validation, reserving `CKR_ACTION_PROHIBITED` for syntactically valid trust/authorization failures.

Sound aspects:

- The immutable interface/version rule and distinct signed-byte prefixes provide good downgrade and cross-protocol protection.
- The nonce-plus-strict-sequence design, exact committed retry before freshness checks, and single-transaction commit model address the original replay/crash gap well.
- Restricting root, device, and admin-authority replacement to board-local administration limits escalation from a stolen admin signing key.
- The new ceremony split, 1-based KMIP ordinal rule, canonical attribute ordering, and explicit refusal of remote `CloneKey` are sound design choices.
---

## Dispositions (1c + 7f, 2026-10-03) — all 6 adopted, applied as DRAFT 3.2

| ID | Sev | Disposition |
|---|---|---|
| B-01 | med | `issueDeviceCrl` refuses to revoke the **active** receipt-signing leaf (rotate it first with `issueFunctionCerts`, whose receipt is signed by the outgoing key before retirement). Receipts are verified against **current** CRLs (7f: `committedAt` is self-asserted by the judged key and CRL entries carry no reason code, so as-of validation would let a compromised key backdate); as-of semantics with reason codes deferred to v1.1 (§3.6) |
| B-02 | high | Correct: the pre-ceremony-ABI bridge does **not** conform to §6. §6.0 now states its status: lab test build only, feature-gated, `replication-user` operations only, no admin interface, replaced by the conforming binding before the branch merges anywhere (7f condition) |
| B-03 | med | Tombstones are a **terminal refusal** (`CKR_ACTION_PROHIBITED`) keyed by admin key ID + sequence + request hash; pruned receipts are explicitly **not** recoverable; §1 now says "while retained in the ledger" |
| B-04 | med | Client-certificate validation normative: pinned replication-client CA roots only (not the system trust store), validity at handshake, chain = leaf directly under a pinned root, exactly one of the two critical EKUs, optional configured CRL (residual stated when absent), all before context creation |
| B-05 | low | `AdminReceipt.signatureAlgorithm` = canonical `id-ml-dsa-65` with absent parameters; signature exactly 3309 octets, zero unused bits (same for the request) |
| B-06 | low | Syntactic failure of any embedded payload (policy DER, CRL DER, certificate DER) → `CKR_DATA_INVALID`, checked before trust validation; `CKR_ACTION_PROHIBITED` only for syntactically valid trust/authorization failures |
