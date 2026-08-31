# Plane 1 — Crypto Agility Management Plane Policy Library

> **New here?** [`../docs/CACP_GUIDE.md`](../docs/CACP_GUIDE.md) is the full
> guide: the policy language, how to test policies in the hub's Agility
> Workbench (policies, batches & macros), and the verified KMIP 3.0 status
> for hybrid KEMs and hybrid signatures.

Example + default policy files consumed by the `pqctoday-hsm/kmip/` subsystem's policy engine (`src/policy/loader.rs`).

Loaded at server start via `pqctoday-kmip --policy-dir policies --policy <name>`. The engine evaluates every KMIP request against the loaded policy before dispatching it to a Plane 2 op handler. A `Deny` decision short-circuits the request with a KMIP `PermissionDenied` response.

## Files

| File | Use case |
|---|---|
| [`classical.yaml`](classical.yaml) | **Headline-demo "before".** Every new key defaults to classical (ECDH-P256 KEM / ECDSA-P256 sig / RSA-3072 enc / AES-256). Pair with `pqc.yaml`. |
| [`pqc.yaml`](pqc.yaml) | **Headline-demo "after".** Every new key defaults to PQC (ML-KEM-1024 / ML-DSA-87 / AES-256). Substitution rules auto-rekey existing classical keys at first Sign / Encapsulate (corrected 2026-08-28 — not Encrypt; RSA key-transport's Encrypt-path rekey is a deferred cross-primitive migration the Encrypt op cannot execute in one call). Pair with `classical.yaml`. |
| [`training-permissive.yaml`](training-permissive.yaml) | **Default for sandbox.** Allows everything. Used for KAT validation, KMIP conformance testing, and trainee exploration. |
| [`pqc-migration-2030.yaml`](pqc-migration-2030.yaml) | Realistic migration policy: classical algorithms allowed for verify/decrypt only, banned for sign/encrypt after 2030-01-01. |
| [`fips-only.yaml`](fips-only.yaml) | FIPS 140-3 mode: only FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) plus FIPS-validated classical. |
| [`hybrid-migration-window.yaml`](hybrid-migration-window.yaml) | During 2026–2029, pure-classical signing is denied and pure PQC (ML-DSA/SLH-DSA) is allowed untagged; requests that opt in via `x-pqctoday-dual-sign`/`x-pqctoday-assurance` are held to an ML-DSA+classical LAMPS composite. (Not an unconditional composite mandate — corrected 2026-08-28; composite keygen isn't wired into Plane 2 yet, so an unconditional mandate would leave the policy with no signable algorithm at all.) |
| [`cnsa-2.0.yaml`](cnsa-2.0.yaml) | NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0): ML-KEM-1024 + ML-DSA-87 + AES-256 + SHA-384. |
| [`fips-hashing.yaml`](fips-hashing.yaml) | **Mechanism dimension (hashing).** Restrict Sign/Verify hashing to FIPS SHA-2/SHA-3; deny SHA-1 — gates the KMIP `Hashing Algorithm`, not just the key algorithm. |
| [`aead-only.yaml`](aead-only.yaml) | **Mechanism dimension (mode/padding).** AES Encrypt/Decrypt must be GCM/CCM; RSA must be OAEP — gates KMIP `Block Cipher Mode` / `Padding Method`. |
| [`deterministic-signing.yaml`](deterministic-signing.yaml) | **Mechanism forcing.** Forces deterministic ML-DSA/SLH-DSA via the CSD02 `Deterministic` flag — policy *sets* the mechanism param, transparent to the app. |
| [`auto-migrate-on-use.yaml`](auto-migrate-on-use.yaml) | Auto-rekey classical key handles to their PQC equivalent on first use (Sign/Encapsulate), via `algorithm_substitution`, with a class-based backstop denying any classical algorithm not covered by an explicit rekey target. |
| [`bsi-tr-02102.yaml`](bsi-tr-02102.yaml) | German BSI TR-02102 profile: allowed PQC + classical algorithms and key lengths per the BSI technical guideline. |
| [`pkcs11-mechanism-lockdown.yaml`](pkcs11-mechanism-lockdown.yaml) | **Mechanism dimension.** Allowlists the specific PKCS#11 mechanisms permitted (keygen, sign/verify, KDF families), denying everything else. |
| [`migration-classical.yaml`](migration-classical.yaml) | **Migration tab "before".** Label-pattern defaults give each of the tab's seven demo keys its classical algorithm (application passes only key names); PQC gated off class-wide. Pair with `migration-pqc.yaml` / `migration-hybrid.yaml`. |
| [`migration-pqc.yaml`](migration-pqc.yaml) | **Migration tab "after" (full-PQC).** Same seven labels; new keys default to FIPS 203/204, existing classical keys auto-rekey on first use or via the ReKey sweep, mappings follow the Hub algorithm-transitions dataset. |
| [`migration-hybrid.yaml`](migration-hybrid.yaml) | **Migration tab "hedge".** Same seven labels; key establishment migrates to the hybrid KEM X25519MLKEM768, signing to ML-DSA-44 — belt-and-braces during the transition. |

### Modular siblings (schema v3)

Eleven of the files above — `classical`, `pqc`, `auto-migrate-on-use`,
`migration-classical`, `migration-pqc`, `migration-hybrid`,
`pqc-migration-2030`, `hybrid-migration-window`, `cnsa-2.0`, `fips-only`,
`bsi-tr-02102` — also ship as a set of per-scope module files (modular-policy
plan, 2026-08-28), e.g. `classical-signing.yaml`,
`classical-key-establishment.yaml`, `classical-encryption.yaml`,
`classical-global.yaml`. Each set reproduces its monolithic file's behavior
exactly, as independently-activatable [modules](#modular-policies-schema-v3--scopes-and-multi-file-composition)
instead of one `replace_all` swap.

**Both forms are kept, deliberately, not a migrate-then-delete pair.** The
monolithic file is the Hub playground's catalog entry (`kmipMeta.ts` loads
it by literal filename for the single-file demo flow, the Compare tab, and
the visual rule editor); the split files are what the SAME preset activates
as modules when the playground's catalog loads its `files: [...]` list
instead of `file`. Editing a policy's rules means editing both forms — they
will drift if only one is touched. `deterministic-signing.yaml`, `fips-hashing.yaml`, `aead-only.yaml`, and
`pkcs11-mechanism-lockdown.yaml` were retagged to schema v3 with
`scopes: [global]` (their rules already reference multiple domains or no
domain at all) but stay ONE file each — nothing to split.
`training-permissive.yaml` (`rules: []`) stays schema v1/unscoped; it has no
rules to declare a scope for, and works unchanged via `replace_all`.

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

## Modular policies (schema v3) — scopes and multi-file composition

Added 2026-08-28 in response to a real maintenance problem: a single
enterprise-wide policy that governs signing AND key-establishment AND
encryption AND every mechanism constraint grows into one file nobody wants
to touch, because a change for one team's signing rules risks a typo
breaking another team's encryption rules three hundred lines away. Schema
v3 lets a policy declare which slice of the request surface it governs, so
several small, independently-owned files can be active on the engine at
once instead of one that keeps growing.

### The `Scope` taxonomy

```yaml
metadata:
  scopes: [signing]        # a list — see below for why not a single value
```

Seven scopes, each owning a fixed, non-overlapping set of ops (see
`Scope::scope_ops` in `src/policy/rule.rs` for the authoritative table):

| Scope | Owns |
|---|---|
| `signing` | `Sign`, `SignatureVerify`, `CreateKeyPair:Sign`, `ReKeyKeyPair:Sign` |
| `key-establishment` | `Encapsulate`, `Decapsulate`, `CreateKeyPair:KeyAgreement`, `ReKeyKeyPair:KeyAgreement` |
| `encryption` | `Encrypt`, `Decrypt`, `Create`, `ReKey`, `CreateKeyPair:Encrypt`, `ReKeyKeyPair:Encrypt` |
| `mac-hash` | `MAC`, `MACVerify`, `Hash` |
| `ingress` | `Register`, `Import` |
| `lifecycle` | `Activate`, `Revoke`, `Destroy`, `Locate`, `GetAttributes` |
| `global` | **Exempt from containment** (see below) — cross-cutting hygiene rules that legitimately gate more than one domain, or a bare/unrefined op that can't be assigned to one scope in isolation |

A file's `scopes:` is a **list**, not a single value, because some
genuinely single-purpose policies still need more than one — nothing in the
taxonomy forces a 1:1 file-to-scope mapping, `scopes:` just has to be
declared and machine-verified.

`CreateKeyPair` and `ReKeyKeyPair` are ambiguous **bare** (they could be
Sign, KeyAgreement, or Encrypt depending on the key's usage mask) — a scoped
file must use the refined form (`CreateKeyPair:Sign`, `ReKeyKeyPair:Encrypt`,
etc.) in its `ops:` lists; the loader rejects a bare form in any
non-`global`-scoped file. `Global` is exempt from this too — a bare op there
is a deliberate signal that the rule intentionally applies across every
purpose.

### Containment: declared vs. actual

At load time, `check_scope_containment` (`src/policy/loader.rs`) verifies
every op a rule actually references falls inside the file's declared
`scopes:` — a `signing`-scoped file whose `ops:` sneaks in `Encrypt` fails
to load. `global` is exempt from this check entirely (by design — it can
reference any op, including a bare, unrefined one); `check_global_is_gating_only`
enforces the other half of that exemption — a `global`-scoped file cannot
declare `algorithm_default`/`algorithm_substitution` (true *resolution*
rules, which must own a specific domain to resolve into), but
`mechanism_parameter_default` (parameter *forcing* — e.g. deterministic
signing) is allowed, since it composes across domains the same way gating
does rather than picking one algorithm.

### Non-conflict model

Three rules keep multiple active modules from fighting each other, instead
of a priority-number stack (considered and dropped — the modular-policy
plan's whole point was to make policies NOT conflict, so a resolution order
between conflicting files was the wrong feature to build):

1. **One module owns each scope.** `Engine::activate` refuses to activate a
   module whose scope is already claimed by a **differently-named** active
   module (`ActivateError::ScopeConflict`) — deactivate the incumbent first.
   Activating a module under the SAME name it's already active under
   replaces it in place (not a conflict — that's how you push an edited
   revision of a module you already own).
2. **Every module gates.** A module's non-resolution rules (allowlist,
   denylist, min-key-length, temporal cutoffs, …) all apply to any request
   whose op falls in its scope OR whose op a `global` module references —
   composition, not override.
3. **Only the owning module resolves.** `algorithm_default` /
   `algorithm_substitution` for an op only ever run from the ONE module
   that owns that op's scope — there is structurally only one candidate, so
   "which resolution wins" never comes up.

### Engine API

`src/policy/engine.rs`:

| Method | Effect |
|---|---|
| `activate(loaded)` | Push/upsert one scoped module. Refused if unscoped (`ActivateError::Unscoped`), if a legacy `replace_all` policy is active (`LegacyPolicyActive`), or on a scope conflict (see above). |
| `deactivate(name)` | Remove one module by name. `bool` — `false` if no module by that name was active. |
| `set_module_enabled(name, bool)` | Disable a module without unloading it — its rules stop applying but its scope stays claimed (nothing else can take it over while it's merely disabled). |
| `clear_modules()` | Drop every module. Does not touch a legacy `replace_all` policy — they're mutually exclusive slots, whichever is non-empty governs. |
| `modules()` | `Vec<(ActivePolicy, enabled)>` — snapshot for an admin listing. |
| `set_uncovered_ops(mode)` / `uncovered_ops()` | See below. |

`replace_all(loaded)` — the original single-policy activation, renamed
2026-08-28 (`activate` was free for the modular verb above) — is **not**
deprecated; it stays supported indefinitely as the legacy path for an
unscoped file, and clears any active modules on swap (legacy and modular
modes are mutually exclusive, never mixed).

### Uncovered ops

An op whose scope no active module claims is "uncovered." `UncoveredOps`
(`Deny` or `Allow`) decides what happens to it in modular mode — `Deny` is
the universal, fail-closed default (`--uncovered-ops deny`, the native
server's only supported value in practice); `Allow` exists for the wasm
playground and incremental adoption, never a production default. Note a
`global` module's gates still apply to an "uncovered" op even under
`Allow` — "uncovered" means no module *resolves or scope-owns* it, not that
every module ignores it.

## Schema (v3)

```yaml
# Policy file schema v3
schema_version: 3
metadata:
  name: <human readable>
  description: <one paragraph>
  authority: <who owns this policy>
  effective: <ISO 8601 date or "always">
  expires: <ISO 8601 date or "never">    # optional, added schema v2
  scopes: [signing]                      # optional, added schema v3 — omit
                                          # for a legacy file activated via
                                          # `replace_all` (see above)
  compliance_mapping:                    # optional: links to standards
    - { framework: FIPS-140-3, level: 3 }
    - { framework: CNSA-2.0, status: aligned }

rules:                                   # ordered; first matching Deny wins
  - type: <rule type>                    # see §Rule Types
    <type-specific fields>
    reason: <human reason for audit log>
```

`schema_version` gates which fields the loader accepts: 1 = base (no
`expires`/`scopes`), 2 adds `expires`, 3 adds `scopes`. A v1/v2 file loads
and runs exactly as before — `scopes` is opt-in, not a breaking change.

## Rule types (18 built-in primitives)

Two families:

- **Resolution rules** run in Pass 0/1 — they can rewrite the request's
  algorithm before gating begins. `algorithm_default` and
  `algorithm_substitution` do NOT share one "last match wins" rule
  (corrected 2026-08-28 — see [Evaluation order](#evaluation-order) below
  for the precise, and different, semantics of each).
- **Gating rules** run in Pass 2 — first `Deny` short-circuits.

### Resolution rules (Pass 1)

| Type | Fields | Effect |
|---|---|---|
| `algorithm_default` | `ops: [...]`, `default_algorithm: <name>` | When request carries `algorithm = None` AND `op ∈ ops`, supply `default_algorithm`. Lets applications call `CreateKeyPair` without naming an algorithm and let policy decide. |
| `algorithm_substitution` | `ops: [...]`, `from: <name>`, `to: <name>` | When `algorithm == from` AND `op ∈ ops`, rewrite to `to`. **Headline demo:** application keeps asking for ECDSA-P256, policy substitutes ML-DSA-65 silently. Now also supported for `Encapsulate` (2026-07-05) — classical ECDH/X25519/X448 key-establishment keys rekey to ML-KEM/hybrid the same way, via `encapsulate.rs::rekey_and_encapsulate`. **`ops:` must never include `Decapsulate`, `DeriveKey`, or `Decrypt`** ("consumer ops" — see `policy::rule::is_consumer_op`): their input was already fixed to an algorithm by an earlier, possibly different-party call, so there is nothing to substitute. This is an **engine invariant, not a convention** — the loader rejects such a rule at load time, and the engine ignores it at runtime even if it somehow got through. |

### Gating rules (Pass 2)

| Type | Fields | Effect |
|---|---|---|
| `algorithm_allowlist` | `ops: [...]`, `algorithms: [...]` | If `op ∈ ops` AND `algorithm ∉ algorithms` → Deny. Optional `effective_from` / `effective_until` (`YYYY-MM-DD` or `"always"`) gate the rule by date. |
| `algorithm_denylist` | `ops: [...]`, `algorithms: [...]` | If `op ∈ ops` AND `algorithm ∈ algorithms` → Deny. Optional `exception_custom_attribute: { name, value }` suppresses the deny when the request carries that attribute. Optional `severity: deny\|warn` (default `deny`) — see [Deprecation warn-tier](#deprecation-warn-tier) below. |
| `min_key_length` | `algorithm: <name>`, `min_bits: N` | If `algorithm == name` AND `key_length < min_bits` → Deny |
| `max_key_age_days` | `days: N`, `ops: [...]` | If `op ∈ ops` AND `(now - key.activated_at) > days` → Deny (rotate). **Genuinely enforced** against the stored object's real Activation Date — corrected 2026-08-28; this table previously called it a "Phase 4.5 stub", which stopped being true once Sign/Encrypt/Decrypt/Encapsulate/Decapsulate started populating `object_activation_date`. Fires only for ops that target an already-activated key — `Create` and never-activated objects have no activation date to age out (the loader still emits a load-time note to that effect, not a "this doesn't work" warning). |
| `require_usage_mask` | `algorithm: <name>`, `flags: [...]`, optional `ops: [...]` | If `op ∈ ops` AND `algorithm` matches AND not all `flags` set (or no mask at all) → Deny. `ops` defaults to the creation/ingress ops (`Create`, `CreateKeyPair`, `Register`, `Import`) — un-scoped it re-closed the use ops policies leave open (2026-07-04). Flag names: `Sign`, `Verify`, `Encrypt`, `Decrypt`, `WrapKey`, `UnwrapKey`, `Export`, `MacGenerate`, `MacVerify`, `DeriveKey`, `ContentCommitment`, `KeyAgreement`, `CertificateSign`, `CrlSign`, `Authenticate`. |
| `require_custom_attribute` | `attribute_name: <name>`, `algorithms: [...]`, optional `ops: [...]` | If `op ∈ ops` AND `algorithm ∈ algorithms` AND `x-<attribute_name>` not set → Deny. `ops` defaults to `Create`/`CreateKeyPair`/`Register`/`Import` (see above). |
| `temporal_cutoff` | `op: <name>`, `algorithm_class: <classical\|pqc>`, `after: <YYYY-MM-DD>`, optional `algorithms: [...]`, optional `severity: deny\|warn` | If `now >= after` AND `op == name` AND algorithm matches class (and optional narrow list) → Deny (or warn, see [Deprecation warn-tier](#deprecation-warn-tier)) |
| `lifecycle_state_gate` | `op: <name>`, `allowed_states: [...]` | If `op == name` AND `state ∉ allowed_states` → Deny |
| `hybrid_dual_sign_requirement` | `primary: <alg>`, `secondary: <alg>`, `effective_from: <date>`, `effective_until: <date>`, `ops_affected: [...]` | During window, every op in `ops_affected` MUST carry the composite algorithm name `<primary>-<secondary>` in KMIP 3.0 spelling (e.g. `ML-DSA-65-Ed25519`); matched case-insensitively. |
| `compliance_profile_gate` | `profile: <FIPS-140-3\|CNSA-2.0\|...>`, `ops: [...]` | **Documentational only in Phase 4.5.** Composing allowlist/denylist rules carry actual enforcement; this variant exists so the Phase 8 compliance tool can map a policy back to its profile name. |

### Mechanism-dimension rules

These gate/resolve the KMIP *mechanism* parameters (hash, cipher mode, padding,
MAC, deterministic flag) rather than just the key algorithm — the "mechanism
dimension" advertised by `fips-hashing.yaml`, `aead-only.yaml`,
`deterministic-signing.yaml` and `pkcs11-mechanism-lockdown.yaml`.

| Type | Effect |
|---|---|
| `mechanism_allowlist` | If `op ∈ ops` AND the requested PKCS#11 mechanism ∉ `mechanisms` → Deny. |
| `mechanism_denylist` | If `op ∈ ops` AND the requested mechanism ∈ `mechanisms` → Deny. Optional `severity: deny\|warn`. |
| `hash_algorithm_allowlist` | Restrict the KMIP `Hashing Algorithm` for any op listed in `ops` (not just Sign/Verify — e.g. Encrypt's RSA-OAEP hash) to an allowed set (e.g. deny SHA-1). A request with no hash carried is not gated. Optional `severity: deny\|warn`. |
| `mac_mechanism_policy` | Constrain the MAC mechanism family (e.g. require HMAC-SHA2+). |
| `mechanism_parameter_constraint` | Gate a mechanism parameter — e.g. AES `Block Cipher Mode` ∈ {GCM, CCM}, RSA `Padding Method` = OAEP. Optional `severity: deny\|warn`. |
| `mechanism_parameter_default` | Resolution rule (Pass 1): *set* a mechanism parameter the request omitted — e.g. force the CSD02 `Deterministic` flag on ML-DSA/SLH-DSA. |

## Deprecation warn-tier

Added 2026-08-28 (A1, gaps-remediation plan). Five gating rule types accept
an optional `severity: deny | warn` field (default `deny` — every existing
policy file, none of which declare it, keeps its exact current behavior):
`algorithm_denylist`, `mechanism_denylist`, `hash_algorithm_allowlist`,
`temporal_cutoff`, `mechanism_parameter_constraint`.

A `severity: warn` match does **not** deny — Pass 2 keeps walking the
remaining rules instead of short-circuiting, and a `PolicyWarning { rule_index,
reason, policy }` is attached to the eventual `Allow`/`RekeyAndProceed`
(`policy` is the legacy policy's or, in modular mode, the owning module's
name — more than one policy can be active at once, so a bare rule index
alone doesn't say which file to look in). Every warning also fires a
`PolicyWarned` audit event, the same "separate event alongside
`PolicyDecided`" convention `RekeyPlanned` already uses.

**Recommended pattern: write the same condition twice.** A `severity: warn`
rule today, paired with a second `severity: deny` (the default — no field
needed) copy carrying a future `effective_from`/`after`, so the deprecation
notice and the eventual enforcement are two independent, auditable rules
rather than one rule silently changing behavior on a date nobody
re-reviewed. Worked example: `pqc-migration-2030.yaml`'s rule 3a warns
(continuously, from the policy's own `effective` date) about classical
signing-key creation, while rule 3 denies it from 2027-01-01 — same `op`/
`algorithm_class`, two rules, two severities.

The loader's lint flags the version of this pattern that's missing its
second half: a `severity: warn` rule with no dated escalation of its own
(`effective_from` if the type carries one) and no sibling `severity: deny`
rule of the same type is an **advisory** ("deprecation with no sunset") —
never fatal, since a permanently warn-only rule is also a legitimate,
deliberate choice.

## Decisions

The engine emits one of three decisions. **KMIP 3.0 cannot natively express
the third one — it's the agility engine's value-add.**

| Decision | Dispatcher action |
|---|---|
| `Allow { algorithm_override: None }` | Forward request unchanged to Plane 2. |
| `Allow { algorithm_override: Some(name) }` | Rewrite request's `CryptographicAlgorithm` to `name`, then forward. Used on Create/CreateKeyPair when policy substitutes the algorithm at key-gen time. |
| `RekeyAndProceed { original_uid, from_algorithm, new_algorithm }` | Plan a rekey: generate fresh key under `new_algorithm`, activate it, move `original_uid` to KMIP's real `Deactivated` state (corrected 2026-08-28 — KMIP has no `Deprecated` state; §3.2's Active→Deactivated transition IS the superseded-key move), link new ↔ old via the custom `x-pqctoday-supersedes` attribute, re-issue the op against the new handle. Triggered when a substitution rule fires against an existing stored object whose algorithm differs from the policy's resolved algorithm. **This is how the engine transparently migrates an application from classical to PQC at the next use of an existing key.** Note: this custom-attribute link is DIFFERENT from the native KMIP `ReplacedObjectLink`/`ReplacementObjectLink` pair an explicit `ReKey`/`ReKeyKeyPair` operation sets — a client cannot currently discover an *automatic* rekey's lineage via `GetAttributes` (only via the audit log or the Hub's keystore inspector, which reads the object store directly). |
| `Deny { kmip_reason, human, fired_rule_index }` | Return KMIP `OperationFailed` with `ResultReason = kmip_reason` and message `human`. `fired_rule_index` (1-based) identifies which rule fired, surfaceable in the Hub UI. |

## Evaluation order

**Corrected 2026-08-28** — this section previously described one blanket
"Pass-1, last match wins" rule for all resolution rules. The real semantics
differ between the two resolution rule types, and matter for how you order
rules in a file:

**Pass 0 — `algorithm_default`.** Only runs when the request carries no
algorithm at all. **First matching default wins**, with a two-phase sweep:
every rule carrying a `name_pattern` is checked (in file order) before any
generic (no-`name_pattern`) rule is checked — so a `name_pattern:
"payments-*"` default always beats a generic default for the same op,
regardless of which one is listed first in the file. Within the same
specificity tier, the first rule in file order wins.

**Pass 1 — `algorithm_substitution`.** Walks every rule in file order
against the Pass-0-resolved algorithm, and each match REWRITES the running
value — so later matching rules do genuinely override earlier ones for the
same input (**last match wins**, and rules can chain: rule B's `from:` can
match rule A's `to:`).

**Pass 2 — gating.** Walk gating rules in declaration order against the
*resolved* algorithm from Pass 0/1. First `Deny` short-circuits (the
remaining gating rules are never evaluated for that request — this matters
for what the audit trace shows, not for the allow/deny outcome, which is
the same either way). A substitution that points at a banned algorithm is
denied at Pass 2 — there is no orphan rekey to a forbidden algorithm.

If Pass 1 produced a substitution AND the request targets an existing
object whose `current_object_algorithm` differs from the substituted
value, the engine emits `RekeyAndProceed` instead of plain `Allow`.

## No-policy default

If the engine has no active legacy policy AND no active modules, **every**
request is denied with `kmip_reason = PolicyNotLoaded` — the safe default.
Sandbox / dev runs must explicitly load `training-permissive.yaml` or call
`Engine::permissive()` for unit tests.

With one or more modules active, an op whose scope none of them claims
follows `UncoveredOps` instead — same fail-closed `Deny` by default; see
[Uncovered ops](#uncovered-ops) above for the `Allow` escape hatch and why
it's playground-only.

## Security-officer editing workflow

Policies are plain YAML files. The intended workflow:

1. Edit the file (Hub UI, text editor, or `pqctoday-kmip-compliance edit`).
2. Validate the draft via [`PolicyStore::validate_draft`] — line-aware
   parse errors surface for UI display.
3. Dry-run the draft against a sample request via [`PolicyStore::dry_run`]
   to see the resulting `Decision` before activating.
4. Save via [`PolicyStore::save`] — writes to a tempfile then atomic-renames
   onto the target path. Broken drafts never reach disk.
5. Activate: [`Engine::replace_all`] for a legacy/unscoped file (atomic
   swap — in-flight evaluations observe either the old or new policy, never
   a partially-applied one), or [`Engine::activate`] to push/upsert one
   scoped module alongside whatever else is active (see
   [Modular policies](#modular-policies-schema-v3--scopes-and-multi-file-composition)
   above). Every activation is recorded in the audit ring with SHA-256
   fingerprints of both prior and new YAML.

## Audit

Every policy decision (`Allow` OR `Deny`) is logged at Plane 1 with the matching rule's `reason` string, the policy file's filename + sha256, and a `correlation_id` shared with the Plane 2 KMIP op and Plane 3 PKCS#11 audit entries.

## Custom attribute namespace

`x-pqctoday-*` is reserved for our policy metadata. Customers writing their own policies should use `x-<their-org>-*` to avoid collision.

## Adding a new rule type

**Corrected 2026-08-28** — this section previously named a `Rule` trait in
`src/policy/rules.rs`; neither exists. `Rule` is an internally-tagged serde
enum in `src/policy/rule.rs` (see that file's own doc comment at the top of
the enum for the authoritative steps). In outline:

1. Add the variant to the `Rule` enum in `src/policy/rule.rs`
   (`#[serde(tag = "type", rename_all = "snake_case")]` — the variant name
   becomes the YAML `type:` value automatically).
2. Add its entry to `known_fields_for_rule_type` in the same file (the S-6
   fail-closed unknown-field guard `loader.rs` uses) — the drift-guard test
   `rule_field_lists_match_declared_struct_fields` will not compile until
   you do, by construction (see its doc comment).
3. Wire evaluation into `resolve_default`/`resolve_substitution` (Pass 0/1)
   or `check_pass2` (Pass 2) as appropriate.
4. Add value-lint coverage in `src/policy/lint.rs`'s `lint_one` if the rule
   carries algorithm/mechanism/hash/op names — including its `ops`/`op`
   field, which must go through `lint_ops`/`lint_op` like every other rule.
5. Add a unit test in `src/policy/rule.rs` with positive + negative +
   boundary cases.
6. Update this README's "Rule types" table.
7. Bump `schema_version` if the rule type — or any change to `Metadata` —
   adds a new top-level YAML field old engines must not silently ignore.
