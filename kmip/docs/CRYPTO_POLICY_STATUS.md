# Crypto-Agility Policy Layer — Capabilities, Limits & Gaps

**Subsystem**: `kmip/src/policy/` (Plane-1 policy engine, on top of the KMIP 3.0 dispatcher)
**Assessed against the stated goal** (below). **Date**: 2026-06-14.

> **UPDATE (implemented in this PR).** The gaps G1–G4 below were the *pre-work*
> assessment. They are now closed by the mechanism-dimension implementation
> (plan `CRYPTO_POLICY_GAPS_IMPLEMENTATION_PLAN.md`, phases P0–P5):
> - **G1 (hashing)** — `hash_algorithm_allowlist` gates it; `mechanism_parameter_default` forces it.
> - **G2 (mechanism params)** — `mechanism_parameter_constraint` gates mode/padding/deterministic; forced via `mechanism_parameter_default`.
> - **G3 (PKCS#11 granularity)** — `mechanism_allowlist`/`mechanism_denylist` gate on the canonical `CKM_*` (full mechanism surface, incl. KMAC), bypass-proof by construction.
> - **G4 (symmetric mode)** — gated + forceable.
>
> Four categories now: **signing ✅ · KEM ✅ · encryption ✅ · hashing ✅.**
> Remaining/deferred: Encrypt mechanism-param *forcing* (AES-GCM is the default;
> the meaningful encryption control is the gating, which is done), and parsing
> the raw `CKM_*` out of the PKCS#11 *passthrough* `input_parameters` (the op is
> a v0.1 stub — Phase 7). The §3 gap list below is retained as the historical
> assessment that motivated the work.

> **UPDATE 2026-06-14 (post-W2 / PR #107 + #109).** Two items above advanced:
> - **Encrypt mechanism-param *forcing*** is now implemented (W2.1, PR #107):
>   Encrypt applies `Decision.cp_override`, so a policy can *force* the block
>   cipher mode / padding, not only gate it. The "remaining/deferred" note above
>   is superseded.
> - **KEM was not actually policy-gated until PR #109.** Encapsulate/Decapsulate
>   previously bypassed `engine.evaluate()` entirely (no p1 decision) — the
>   "KEM ✅" above was aspirational. They are now routed through the Plane-1
>   engine (emit a p1 `PolicyDecided`, enforce allow/deny) **and** resolve the
>   engine handle by PKCS#11 class, so **KEM ✅ is now literally true**.
>
> Operator guide: [CRYPTO_AGILITY_CONFIGURATION.md](CRYPTO_AGILITY_CONFIGURATION.md).

## Goal (target state)

> Enable crypto-agility through **crypto-policy definitions**, such that
> **encryption, signing, KEM, and hashing** algorithms are *abstracted* and can
> be **updated via policy edits** (no application code change). The policy must
> allow **flexible configuration across all supported PKCS#11 v3.2 mechanisms**
> and **leverage the flexibility of KMIP 3.0 mechanisms** (CryptographicParameters).

The application talks to KMIP in terms of *operations on key handles*; the
policy layer decides *which algorithm/mechanism* actually runs. Flipping a YAML
policy migrates the deployment (e.g. classical → PQC) transparently.

---

## 1. Current capabilities (what works today)

The engine (`policy/engine.rs`) evaluates a normalized `PolicyRequest` and
returns `Allow { algorithm_override }` / `RekeyAndProceed { new_algorithm }` /
`Deny`, in two passes (resolve algorithm → gate). Confirmed working:

| Capability | Mechanism | Status |
|---|---|---|
| **Algorithm substitution** | `AlgorithmSubstitution` (X → Y) at the request boundary | ✅ working, tested |
| **Algorithm defaulting** | `AlgorithmDefault` (None → Y) when app omits the algorithm | ✅ working, tested |
| **Use-time rekey orchestration** | `RekeyAndProceed` when policy-resolved algo ≠ stored key algo | ⚠️ decision emitted + wired in Sign/Encrypt/Decrypt; full transaction is Phase 6 |
| **Allow/denylist gating** | `AlgorithmAllowlist` / `AlgorithmDenylist` per op, with time windows | ✅ |
| **Temporal deprecation** | `TemporalCutoff` (ban a *class* after a date) | ✅ |
| **Min key length** | `MinKeyLength` (e.g. RSA ≥ 3072) | ✅ |
| **Lifecycle gating** | `LifecycleStateGate` (only Active keys sign/encrypt) | ✅ |
| **Usage-mask requirement** | `RequireUsageMask` (ML-KEM must declare KeyAgreement) | ✅ |
| **Custom-attribute requirement** | `RequireCustomAttribute` | ✅ |
| **Hybrid dual-sign requirement** | `HybridDualSignRequirement` (composite during a window) | ✅ rule logic; composite wire format deferred |
| **Safe defaults & ops** | deny-all default, atomic swap (RwLock+Arc), SHA-256 fingerprint audit, YAML load/validate/dry-run, filesystem persistence + active marker | ✅ |

**Coverage of the four categories — by *key algorithm name*:**
- **Signing**: ML-DSA / SLH-DSA / ECDSA / EdDSA / RSA — selectable/gateable. ✅
- **KEM**: ML-KEM — selectable/gateable. ✅
- **Encryption (asymmetric)**: RSA, and ML-KEM as the migration target. ✅
- **Encryption (symmetric)**: AES recognized by *name* for default/deny. ⚠️ (algorithm only — see limits)
- **Hashing**: ❌ **not represented in the policy vocabulary at all.**

Example policies exist and are tested: `classical.yaml`, `pqc.yaml`,
`fips-only.yaml`, `cnsa-2.0.yaml`, `pqc-migration-2030.yaml`,
`hybrid-migration-window.yaml`, `training-permissive.yaml`. The classical↔PQC
flip is exercised end-to-end (`tests/policy_classical_pqc_switch.rs`,
`policy_demo_flows.rs`).

---

## 2. Limits (the layer's current shape)

The engine operates on a **single dimension: the key algorithm string**, classified
only as **`pqc` vs `classical`** by name prefix (`rule.rs::matches_class`,
lines 564–577 — `ML-KEM/ML-DSA/SLH-DSA/HSS/LMS/XMSS/Falcon` ⇒ pqc, else classical).

It does **not** model, carry, or act on:
- the **PKCS#11 mechanism** (`CKM_*`) — only the algorithm family;
- the **KMIP `CryptographicParameters`** — `block_cipher_mode`, `padding_method`,
  `mask_generator` (MGF), `hashing_algorithm`, `tag_length`, `salt_length`,
  `deterministic` / `internal` / `external_mu`. (`PolicyRequest` carries none of
  these — confirmed: no references in `policy/*.rs`.)

So a policy can say *"use ML-DSA-65 instead of ECDSA"* but cannot say
*"AES must be GCM, not CBC"*, *"RSA must be OAEP-SHA-256"*, *"ML-DSA must sign
deterministically"*, or *"hash with SHA-3-256, not SHA-256"*.

---

## 3. Gaps vs the goal (prioritized)

### G1 — Hashing is not abstracted by policy *(goal explicitly requires it)*
No hash algorithm appears in the policy vocabulary or any rule (`grep` of
`policy/*.rs`: SHA-256 is used only for policy *fingerprinting*, not as a
controllable algorithm). The `MacAndHash` op consults the engine, but there is
no rule that can default/substitute/gate the **hash** (SHA-2 ↔ SHA-3 ↔ SHAKE) or
the **MAC mechanism** (HMAC vs KMAC vs CMAC). **Hashing agility: absent.**

### G2 — Mechanism parameters (KMIP 3.0 `CryptographicParameters`) not policy-controlled *(goal: "leverage KMIP 3.0 mechanisms")*
The policy can choose the *algorithm* but not the *mechanism details* KMIP 3.0
exposes per call. Cannot enforce or default: block-cipher mode, RSA padding
(OAEP/PKCS1/PSS), MGF + MGF-hash, AEAD tag length, PSS salt length, or the PQC
signing flags (`deterministic`/`internal`/`external_mu`, now decoded in the
Sign/Verify path). **Note:** the I4 work already added decode of these
`CryptographicParameters` fields and threads them to the engine — so the data
path exists; the policy layer just doesn't *govern* them yet.

### G3 — Not full PKCS#11 v3.2 mechanism coverage *(goal: "all supported PKCS#11 v3.2 mechanisms")*
The vocabulary is a curated set of **algorithm names** + a **binary pqc/classical
class**. There is no `CKM_*` mechanism granularity, so individual mechanisms are
not policy-addressable: AES modes, the MAC family (HMAC/KMAC/CMAC), KDF
mechanisms (HKDF/PBKDF2/SP800-108), RSA mechanism variants, prehash signature
variants (HashML-DSA, ECDSA-SHA*), etc. A policy cannot, e.g., allow
`CKM_AES_GCM` while denying `CKM_AES_CBC`.

### G4 — Symmetric-encryption agility is name-only
AES can be defaulted/denied by name, but the actual symmetric *mechanism* (mode,
padding, IV policy) is outside policy control — so "encryption agility" is
partial for symmetric keys (asymmetric KEM/RSA migration is the strong path).

### G5 — Known stubs / deferred (pre-existing, documented in code)
- `MaxKeyAgeDays` — Phase-4.5 stub (needs Phase-6 store `activated_at`).
- `ComplianceProfileGate` — documentational only (enforcement composes from
  allowlist/denylist).
- `RekeyAndProceed` — decision + op wiring exist; the full multi-op rekey
  transaction (state→Deprecated, supersedes-link, re-issue) completes in Phase 6.
- Composite/hybrid signatures — rule logic present; KMIP wire format deferred.

---

## 4. Recommendations to reach the goal

1. **Extend `PolicyRequest`** to carry the mechanism dimension already available
   at the op boundary: `hashing_algorithm`, `block_cipher_mode`, `padding_method`,
   `mask_generator`(+hash), `tag_length`, `salt_length`, and the PQC flags
   (`deterministic`/`internal`/`external_mu`). The Sign/Encrypt handlers already
   compute an effective `CryptographicParameters` — pass it into `evaluate()`.
2. **Add rule types** for the missing dimensions:
   `HashAlgorithmDefault` / `…Substitution` / `…Allowlist` (closes G1);
   `MechanismParameterConstraint` (mode/padding/MGF/tag/salt — closes G2);
   `MacMechanismPolicy` (HMAC/KMAC/CMAC).
3. **Introduce a mechanism vocabulary** mapping policy terms ↔ PKCS#11 `CKM_*`
   (grep `src/lib/pkcs11/pkcs11t.h` for the canonical values — source of truth)
   so policies can address mechanisms, not just algorithm families (closes G3/G4).
4. **Let policy *emit* CryptographicParameters overrides**, not just gate them —
   the op handlers already accept an effective CP; have `Decision::Allow` optionally
   carry a CP override (parallel to today's `algorithm_override`), so a policy can
   *force* `AES-GCM` / `RSA-OAEP-SHA256` / deterministic ML-DSA transparently.

---

## 5. Verdict

The crypto-agility layer is **production-shaped for *asymmetric key-algorithm*
agility** — signing and KEM migration (classical → PQC), with substitution,
defaulting, allow/deny gating, temporal cutoffs, and rekey orchestration, all
YAML-driven with safe defaults and audit. **Measured against the full goal it is
~50% there:** it abstracts *which key algorithm* runs, but not *which mechanism*
or *which hash*, and it is not yet expressed in PKCS#11 v3.2 mechanism terms.
The four required categories stand at: **signing ✅, KEM ✅, encryption ⚠️
(asymmetric yes / symmetric-mechanism no), hashing ❌.** Closing G1–G3 (the
mechanism + hashing dimensions, on the `CryptographicParameters` data path that
I4 already wired) is the work needed to fully realize policy-driven crypto agility
across the PKCS#11 v3.2 / KMIP 3.0 mechanism surface.
