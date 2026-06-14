# Plane 1 — Crypto Agility Management Plane Policy Library

Example + default policy files consumed by the `pqctoday-hsm/kmip/` subsystem's policy engine (`src/policy/loader.rs`).

Loaded at server start via `pqctoday-kmip --policy-file policies/<name>.yaml`. The engine evaluates every KMIP request against the loaded policy before dispatching it to a Plane 2 op handler. A `Deny` decision short-circuits the request with a KMIP `PermissionDenied` response.

## Files

| File | Use case |
|---|---|
| [`classical.yaml`](classical.yaml) | **Headline-demo "before".** Every new key defaults to classical (ECDH-P256 KEM / ECDSA-P256 sig / RSA-3072 enc / AES-256). Pair with `pqc.yaml`. |
| [`pqc.yaml`](pqc.yaml) | **Headline-demo "after".** Every new key defaults to PQC (ML-KEM-1024 / ML-DSA-87 / AES-256). Substitution rules auto-rekey existing classical keys at first Sign / Encrypt. Pair with `classical.yaml`. |
| [`training-permissive.yaml`](training-permissive.yaml) | **Default for sandbox.** Allows everything. Used for KAT validation, KMIP conformance testing, and trainee exploration. |
| [`pqc-migration-2030.yaml`](pqc-migration-2030.yaml) | Realistic migration policy: classical algorithms allowed for verify/decrypt only, banned for sign/encrypt after 2030-01-01. |
| [`fips-only.yaml`](fips-only.yaml) | FIPS 140-3 mode: only FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) plus FIPS-validated classical. |
| [`hybrid-migration-window.yaml`](hybrid-migration-window.yaml) | Dual-signing enforced during 2026–2029 migration window: every signature is ML-DSA-65 + Ed25519 composite per LAMPS draft-19. |
| [`cnsa-2.0.yaml`](cnsa-2.0.yaml) | NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0): ML-KEM-1024 + ML-DSA-87 + AES-256 + SHA-384. |
| [`fips-hashing.yaml`](fips-hashing.yaml) | **Mechanism dimension (hashing).** Restrict Sign/Verify hashing to FIPS SHA-2/SHA-3; deny SHA-1 — gates the KMIP `Hashing Algorithm`, not just the key algorithm. |
| [`aead-only.yaml`](aead-only.yaml) | **Mechanism dimension (mode/padding).** AES Encrypt/Decrypt must be GCM/CCM; RSA must be OAEP — gates KMIP `Block Cipher Mode` / `Padding Method`. |
| [`deterministic-signing.yaml`](deterministic-signing.yaml) | **Mechanism forcing.** Forces deterministic ML-DSA/SLH-DSA via the WD19 `Deterministic` flag — policy *sets* the mechanism param, transparent to the app. |

## Headline-demo dropdown (Hub scenario UI)

The Hub scenario UI exposes a dropdown with `classical` and `pqc` as the
two entries. The application code on both sides of the dropdown is
byte-identical — only the active policy changes. Flipping the dropdown
demonstrates the agility engine's three capabilities:

1. **Defaulting** — application calls `CreateKeyPair` without specifying
   an algorithm; engine supplies one from the active policy.
2. **Substitution** — application asks for ECDSA-P256 / RSA-3072; engine
   silently rewrites to ML-DSA-87 / ML-KEM-1024.
3. **Rekey orchestration** — existing classical key handles are
   transparently migrated to PQC at first use after the flip
   (`Decision::RekeyAndProceed` → dispatcher runs the rekey transaction).

### Op-name canonicalisation convention

KMIP `CreateKeyPair` is a single op but the policy needs to default
different algorithms for KEM vs signature vs encryption keys. The
dispatcher resolves this by canonicalising `CreateKeyPair` into one of
three purpose-discriminated op strings based on `CryptographicUsageMask`:

| Mask flags | Canonical op string |
|---|---|
| `KeyAgreement` | `CreateKeyPair:KeyAgreement` |
| `Sign`, `Verify` | `CreateKeyPair:Sign` |
| `Encrypt`, `Decrypt` | `CreateKeyPair:Encrypt` |

`Create` (symmetric) keeps its plain op name. The Hub UI dropdown and
the dry-run panel use the same convention.

## Schema (v0.1)

```yaml
# Policy file schema v0.1
schema_version: 1
metadata:
  name: <human readable>
  description: <one paragraph>
  authority: <who owns this policy>
  effective: <ISO 8601 date or "always">
  compliance_mapping:                    # optional: links to standards
    - { framework: FIPS-140-3, level: 3 }
    - { framework: CNSA-2.0, status: aligned }

rules:                                   # ordered; first matching Deny wins
  - type: <rule type>                    # see §Rule Types
    <type-specific fields>
    reason: <human reason for audit log>
```

## Rule types (v0.1 — 12 built-in primitives)

Two families:

- **Resolution rules** run in Pass 1 — they can rewrite the request's
  algorithm before gating begins. Last match wins (later rules in the file
  override earlier ones, so a "general default" + "specific exception"
  pattern works as you'd expect).
- **Gating rules** run in Pass 2 — first `Deny` short-circuits.

### Resolution rules (Pass 1)

| Type | Fields | Effect |
|---|---|---|
| `algorithm_default` | `ops: [...]`, `default_algorithm: <name>` | When request carries `algorithm = None` AND `op ∈ ops`, supply `default_algorithm`. Lets applications call `CreateKeyPair` without naming an algorithm and let policy decide. |
| `algorithm_substitution` | `ops: [...]`, `from: <name>`, `to: <name>` | When `algorithm == from` AND `op ∈ ops`, rewrite to `to`. **Headline demo:** application keeps asking for ECDSA-P256, policy substitutes ML-DSA-65 silently. |

### Gating rules (Pass 2)

| Type | Fields | Effect |
|---|---|---|
| `algorithm_allowlist` | `ops: [...]`, `algorithms: [...]` | If `op ∈ ops` AND `algorithm ∉ algorithms` → Deny. Optional `effective_from` / `effective_until` (`YYYY-MM-DD` or `"always"`) gate the rule by date. |
| `algorithm_denylist` | `ops: [...]`, `algorithms: [...]` | If `op ∈ ops` AND `algorithm ∈ algorithms` → Deny. Optional `exception_custom_attribute: { name, value }` suppresses the deny when the request carries that attribute. |
| `min_key_length` | `algorithm: <name>`, `min_bits: N` | If `algorithm == name` AND `key_length < min_bits` → Deny |
| `max_key_age_days` | `days: N`, `ops: [...]` | If `op ∈ ops` AND `(now - key.activated_at) > days` → Deny (rotate). **Phase 4.5 stub** — needs Phase 6 object store to expose key timestamps; loader emits a warning at load time. |
| `require_usage_mask` | `algorithm: <name>`, `flags: [...]` | If creating `algorithm` without all `flags` set (or with no mask at all) → Deny. Flag names: `Sign`, `Verify`, `Encrypt`, `Decrypt`, `WrapKey`, `UnwrapKey`, `Export`, `MacGenerate`, `MacVerify`, `DeriveKey`, `ContentCommitment`, `KeyAgreement`, `CertificateSign`, `CrlSign`, `Authenticate`. |
| `require_custom_attribute` | `attribute_name: <name>`, `algorithms: [...]` | If `algorithm ∈ algorithms` AND `x-<attribute_name>` not set → Deny |
| `temporal_cutoff` | `op: <name>`, `algorithm_class: <classical\|pqc>`, `after: <YYYY-MM-DD>`, optional `algorithms: [...]` | If `now >= after` AND `op == name` AND algorithm matches class (and optional narrow list) → Deny |
| `lifecycle_state_gate` | `op: <name>`, `allowed_states: [...]` | If `op == name` AND `state ∉ allowed_states` → Deny |
| `hybrid_dual_sign_requirement` | `primary: <alg>`, `secondary: <alg>`, `effective_from: <date>`, `effective_until: <date>`, `ops_affected: [...]` | During window, every op in `ops_affected` MUST carry the composite algorithm name `<primary>-<SECONDARY>` (e.g. `ML-DSA-65-ED25519`). |
| `compliance_profile_gate` | `profile: <FIPS-140-3\|CNSA-2.0\|...>`, `ops: [...]` | **Documentational only in Phase 4.5.** Composing allowlist/denylist rules carry actual enforcement; this variant exists so the Phase 8 compliance tool can map a policy back to its profile name. |

## Decisions

The engine emits one of three decisions. **KMIP 3.0 cannot natively express
the third one — it's the agility engine's value-add.**

| Decision | Dispatcher action |
|---|---|
| `Allow { algorithm_override: None }` | Forward request unchanged to Plane 2. |
| `Allow { algorithm_override: Some(name) }` | Rewrite request's `CryptographicAlgorithm` to `name`, then forward. Used on Create/CreateKeyPair when policy substitutes the algorithm at key-gen time. |
| `RekeyAndProceed { original_uid, from_algorithm, new_algorithm }` | Plan a rekey: generate fresh key under `new_algorithm`, mark `original_uid` as `Deprecated`, link new ↔ old via `x-pqctoday-supersedes`, re-issue the op against the new handle. Triggered when a substitution rule fires against an existing stored object whose algorithm differs from the policy's resolved algorithm. **This is how the engine transparently migrates an application from classical to PQC at the next use of an existing key.** |
| `Deny { kmip_reason, human, fired_rule_index }` | Return KMIP `OperationFailed` with `ResultReason = kmip_reason` and message `human`. `fired_rule_index` (1-based) identifies which rule fired, surfaceable in the Hub UI. |

## Evaluation order

**Pass 1 — algorithm resolution.** Walk all rules; collect substitutions
from `algorithm_default` (when request.algorithm is `None`) and
`algorithm_substitution` (when request.algorithm matches `from`). Last
match wins.

**Pass 2 — gating.** Walk gating rules in declaration order against the
*resolved* algorithm. First `Deny` short-circuits. A substitution that
points at a banned algorithm is denied at Pass 2 — there is no orphan
rekey to a forbidden algorithm.

If Pass 1 produced a substitution AND the request targets an existing
object whose `current_object_algorithm` differs from the substituted
value, the engine emits `RekeyAndProceed` instead of plain `Allow`.

## No-policy default

If the engine has no active policy loaded, **every** request is denied
with `kmip_reason = PolicyNotLoaded` — the safe default. Sandbox / dev
runs must explicitly load `training-permissive.yaml` or call
`Engine::permissive()` for unit tests.

## Security-officer editing workflow

Policies are plain YAML files. The intended workflow:

1. Edit the file (Hub UI, text editor, or `pqctoday-kmip-compliance edit`).
2. Validate the draft via [`PolicyStore::validate_draft`] — line-aware
   parse errors surface for UI display.
3. Dry-run the draft against a sample request via [`PolicyStore::dry_run`]
   to see the resulting `Decision` before activating.
4. Save via [`PolicyStore::save`] — writes to a tempfile then atomic-renames
   onto the target path. Broken drafts never reach disk.
5. Activate via [`Engine::activate`] — atomic swap; in-flight evaluations
   observe either the old or new policy, never a partially-applied one.
   Every activation is recorded in the audit ring with SHA-256 fingerprints
   of both prior and new YAML.

## Audit

Every policy decision (`Allow` OR `Deny`) is logged at Plane 1 with the matching rule's `reason` string, the policy file's filename + sha256, and a `correlation_id` shared with the Plane 2 KMIP op and Plane 3 PKCS#11 audit entries.

## Custom attribute namespace

`x-pqctoday-*` is reserved for our policy metadata. Customers writing their own policies should use `x-<their-org>-*` to avoid collision.

## Adding a new rule type

1. Implement the `Rule` trait in `src/policy/rules.rs`.
2. Register the rule type identifier in `src/policy/loader.rs`'s `match` arm.
3. Add a unit test in `src/policy/rules.rs` with positive + negative + boundary cases.
4. Update this README's "Rule types" table.
5. Bump `schema_version` if the rule type adds new top-level YAML fields.
