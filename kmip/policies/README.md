# Plane 1 — Crypto Agility Management Plane Policy Library

Example + default policy files consumed by the `pqctoday-hsm/kmip/` subsystem's policy engine (`src/policy/loader.rs`).

Loaded at server start via `pqctoday-kmip --policy-file policies/<name>.yaml`. The engine evaluates every KMIP request against the loaded policy before dispatching it to a Plane 2 op handler. A `Deny` decision short-circuits the request with a KMIP `PermissionDenied` response.

## Files

| File | Use case |
|---|---|
| [`training-permissive.yaml`](training-permissive.yaml) | **Default for sandbox.** Allows everything. Used for KAT validation, KMIP conformance testing, and trainee exploration. |
| [`pqc-migration-2030.yaml`](pqc-migration-2030.yaml) | Realistic migration policy: classical algorithms allowed for verify/decrypt only, banned for sign/encrypt after 2030-01-01. |
| [`fips-only.yaml`](fips-only.yaml) | FIPS 140-3 mode: only FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) plus FIPS-validated classical. |
| [`hybrid-migration-window.yaml`](hybrid-migration-window.yaml) | Dual-signing enforced during 2026–2029 migration window: every signature is ML-DSA-65 + Ed25519 composite per LAMPS draft-19. |
| [`cnsa-2.0.yaml`](cnsa-2.0.yaml) | NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0): ML-KEM-1024 + ML-DSA-87 + AES-256 + SHA-384. |

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

## Rule types (v0.1)

| Type | Fields | Effect |
|---|---|---|
| `algorithm_allowlist` | `ops: [...]`, `algorithms: [...]` | If `op ∈ ops` AND `algorithm ∉ algorithms` → Deny |
| `algorithm_denylist` | `ops: [...]`, `algorithms: [...]` | If `op ∈ ops` AND `algorithm ∈ algorithms` → Deny |
| `min_key_length` | `algorithm: <name>`, `min_bits: N` | If `algorithm == name` AND `key_length < min_bits` → Deny |
| `max_key_age_days` | `days: N`, `ops: [...]` | If `op ∈ ops` AND `(now - key.activated_at) > days` → Deny (rotate) |
| `require_usage_mask` | `algorithm: <name>`, `flags: [...]` | If creating `algorithm` without all `flags` set → Deny |
| `require_custom_attribute` | `attribute_name: <name>`, `algorithms: [...]` | If creating any in `algorithms` without `x-<attribute_name>` set → Deny |
| `temporal_cutoff` | `op: <name>`, `algorithm_class: <classical\|pqc>`, `after: <ISO 8601>` | If `now >= after` AND request matches → Deny |
| `lifecycle_state_gate` | `op: <name>`, `allowed_states: [...]` | If `op == name` AND `key.state ∉ allowed_states` → Deny |
| `hybrid_dual_sign_requirement` | `primary: <alg>`, `secondary: <alg>`, `effective: <date range>` | During range, every `Sign` op MUST use composite `primary + secondary` |
| `compliance_profile_gate` | `profile: <FIPS\|CNSA\|...>`, `ops: [...]` | If `op ∈ ops` AND request not compliant with profile → Deny |

## Evaluation order

Rules are evaluated **in order**. The first rule that returns `Deny` short-circuits the request — subsequent rules are not evaluated. If no rule denies, the request is `Allow`ed.

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
