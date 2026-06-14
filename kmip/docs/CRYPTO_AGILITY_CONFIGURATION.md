# Crypto-Agility Configuration Guide — pqctoday-kmip

How to configure, apply, and observe the crypto-agility layer of the
`pqctoday-kmip` server. This is the consolidated operator/integrator guide;
the deeper design rationale lives in
[THREE_PLANE_ARCHITECTURE.md](THREE_PLANE_ARCHITECTURE.md), the policy YAML
library in [../policies/README.md](../policies/README.md), and the client/
observability tooling in [../pykmip/README.md](../pykmip/README.md).

---

## 1. What it is

The server has three planes:

| Plane | Role | Surface |
|-------|------|---------|
| **Plane 1 — Crypto Agility** | Decides *whether* an operation is allowed and *which* algorithm / mechanism parameters it must use, from the **active policy**. | YAML policy files (this guide) |
| **Plane 2 — KMIP 3.0** | The protocol applications speak. Unchanged by policy. | KMIP over TLS (`--listen`) |
| **Plane 3 — PKCS#11** | The `softhsmrustv3` engine that does the crypto. | in-process bridge |

**Enforcement is the KMIP protocol itself** — there is no separate
enforcement API. Every Encrypt / Sign / CreateKeyPair / Encapsulate /
Decapsulate / Hash / MAC request is evaluated against the active policy
*before* it reaches the engine. The application's code never changes; flip
the active policy and the same requests are allowed, denied, or transparently
re-keyed.

**Management is out-of-band** (separation of duties): a KMIP client cannot
read or change the policy that governs it. Policies are authored as files and
selected when the server starts (see §3). There is intentionally **no KMIP
operation** to read/write/update a policy.

---

## 2. How an application talks to it

Applications issue ordinary KMIP 3.0 requests over TLS. They do **not** name a
policy, a rule, or an algorithm-override — the agility layer supplies those.
A typical agile pattern is to omit the algorithm entirely:

```
CreateKeyPair { CommonAttributes: { CryptographicUsageMask: Sign|Verify } }
```

Under a classical policy this resolves to ECDSA; flip to a PQC policy and the
identical call returns an ML-DSA key (`algorithm_default` rule, §4). For
driving the server + reading back the decision trail from Python, see
[`pykmip`](../pykmip/README.md).

---

## 3. Configuring & applying a policy

A policy is one YAML file. Library of ready-made ones:
[`../policies/`](../policies/) (`training-permissive`, `classical`, `pqc`,
`fips-only`, `cnsa-2.0`, `aead-only`, `fips-hashing`,
`deterministic-signing`, `pqc-migration-2030`, `hybrid-migration-window`).

### File shape

```yaml
schema_version: 1
metadata:
  name: my-policy
  description: |
    Human-readable intent.
  authority: my-org
  effective: always                 # or a time window
  compliance_mapping:               # optional, informational
    - { framework: "FIPS 140-3", status: aligned }
rules:
  - type: <rule_type>               # see §4
    # … rule-specific fields …
```

An **empty `rules: []` allows everything** at Plane 1 (that is what
`training-permissive` is). Rules then *gate* (deny), *force* (rewrite a
parameter), or *migrate* (substitute / rekey). Rule order matters: Pass-1
algorithm resolution is **last-match-wins**; Pass-2 gates all apply.

> **Fail-safe default:** if the server has *no* active policy at all, every
> request is **denied**. A loaded policy with no rules allows everything; the
> two are different states.

### Apply it

```bash
pqctoday-kmip \
  --listen 127.0.0.1:5696 --store-memory \
  --policy-dir policies \        # directory of *.yaml policies
  --policy aead-only \           # which one to activate at boot
  --audit-log /tmp/agility.jsonl # three-plane decision log (see §6)
```

- `--policy-dir` — the policy library directory.
- `--policy <name>` — activate `<name>.yaml` at boot and write the
  `.active` marker.
- Omit `--policy` and the server resumes the `.active` marker if present,
  else loads the built-in permissive fallback (with a warning).
- The `PolicyStore` Rust API (`list / load / validate_draft / dry_run / save /
  activate_with_engine / resume_active`) backs all of this; there is no network
  management surface (a server-side HTTP admin facade is a separate, parked
  decision).

**Changing the active policy today requires a (re)launch** — there is no live
hot-swap over the wire.

---

## 4. Rule-type reference

Every rule is `{ type: <snake_case>, … }`. The authoritative source is the
`Rule` enum in [`../src/policy/rule.rs`](../src/policy/rule.rs); names below are
the exact YAML `type:` values.

### Algorithm selection (Pass-1, last-match-wins)
| `type` | Effect |
|--------|--------|
| `algorithm_default` | When the request omits the algorithm and `op ∈ ops`, supply `default_algorithm`. The agility backbone — same app call, policy picks the algorithm. |
| `algorithm_substitution` | When the request asks for `from` and `op ∈ ops`, rewrite to `to`. Hard-cutover migration; if the stored key differs, the engine emits **RekeyAndProceed**. |

### Algorithm gating (Pass-2, deny)
| `type` | Denies when |
|--------|-------------|
| `algorithm_allowlist` | `op ∈ ops` and `algorithm ∉ algorithms` |
| `algorithm_denylist` | `op ∈ ops` and `algorithm ∈ algorithms` (optional `unless` custom-attribute escape hatch) |
| `min_key_length` | `algorithm` matches and `key_length < min_bits` |
| `require_usage_mask` | creating `algorithm` without all `flags` set |
| `require_custom_attribute` | creating any of `algorithms` without `x-<attribute_name>` set |
| `lifecycle_state_gate` | `op == op` and object `state ∉ allowed_states` |

### Mechanism-level gating & forcing (the "how", not just "which")
| `type` | Effect |
|--------|--------|
| `hash_algorithm_allowlist` | gate the `Hashing Algorithm` (KMIP enum names, e.g. `SHA-256`, `SHA3-256`) for the listed ops; deny others. |
| `mechanism_parameter_constraint` | gate `Block Cipher Mode` / `Padding Method` (e.g. AES → `[GCM, CCM]`, RSA → `[OAEP]`). Governs *how* a cipher is used. |
| `mechanism_parameter_default` | **force** a hash / mode / padding / deterministic flag when the request leaves it unset (`Decision.cp_override`). |
| `mac_mechanism_policy` | gate the MAC mechanism family. |
| `mechanism_allowlist` / `mechanism_denylist` | gate on the canonical **`CKM_*`** mechanism codepoint — the full PKCS#11 v3.2 surface (incl. vendor `CKM_KMAC_*`), bypass-proof by construction. |

### Migration & temporal
| `type` | Effect |
|--------|--------|
| `temporal_cutoff` | after `after`, deny `op` for an `algorithm_class` (`classical`/`pqc`) — optionally narrowed to `algorithms`. |
| `max_key_age_days` | deny `op` when the key is older than `days`. *(Stub: needs object-store timestamps; logs a warning, never fires today.)* |
| `hybrid_dual_sign_requirement` | during `effective`, require a composite `primary + secondary` algorithm. |
| `compliance_profile_gate` | informational profile marker (`FIPS-140-3` / `CNSA-2.0` / …); actual enforcement is composed from the allow/deny rules above. |

---

## 5. Decision outcomes

`engine.evaluate(request)` returns one of:

- **Allow** — proceed (optionally with a forced `cp_override` merged into the
  effective Cryptographic Parameters).
- **Deny** — the op fails with KMIP `PermissionDenied` and the rule's reason;
  **no engine call happens**.
- **RekeyAndProceed** — policy substituted the algorithm and the stored key
  doesn't match; surfaced as a typed rekey-required error (the inline op
  handlers do not execute the multi-op rekey transaction).

**Operations routed through Plane 1:** Create, CreateKeyPair, Encrypt, Decrypt,
Sign, SignatureVerify, Hash, MAC, **Encapsulate, Decapsulate**, Derive, and the
lifecycle/attribute ops. (Encapsulate/Decapsulate were brought under the policy
plane in the 2026-06-14 work — previously a KEM blind spot.)

---

## 6. Observing enforcement

Run the server with `--audit-log <path>`. Every event carries a `plane`
(`p1`/`p2`/`p3`) and a `correlation_id` shared across all three planes for one
request:

```
p1 — PolicyDecided   { op, algorithm, outcome: Allow|Deny|Rekey }
p2 — KmipResponseSent{ op, result: Success|OperationFailed }
p3 — Pkcs11Call      { function, mechanism: CKM_*, rv_name }
```

[`pykmip.audit`](../pykmip/audit.py) groups the log into per-request trails.
A **denied** request shows a p1 Deny and **no** p3 call — visible proof the
agility layer stopped it before the engine.

### Worked example — `aead-only`

```
ALLOW  Encrypt   p1: Allow             p2: Success          p3: native::encrypt [AES-GCM]
DENY   Encrypt   p1: Deny "AES must    p2: OperationFailed  p3: (no engine call)
                    use GCM or CCM"
```

Identical client code; the policy alone decides. Swap `--policy aead-only` for
`--policy training-permissive` and both Encrypts are allowed. That is the
agility story end-to-end. See [`pykmip/demo.py`](../pykmip/demo.py).

---

## 7. See also

- [THREE_PLANE_ARCHITECTURE.md](THREE_PLANE_ARCHITECTURE.md) — design rationale.
- [../policies/README.md](../policies/README.md) — the policy library.
- [CRYPTO_POLICY_STATUS.md](CRYPTO_POLICY_STATUS.md) — capabilities & limits.
- [../pykmip/README.md](../pykmip/README.md) — drive it + read the trail.
