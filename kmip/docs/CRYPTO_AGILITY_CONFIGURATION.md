# Crypto-Agility Configuration Guide — pqctoday-kmip

How to configure, apply, and observe the crypto-agility layer of the
`pqctoday-kmip` server. This is the consolidated operator/integrator guide;
the deeper design rationale lives in
[THREE_PLANE_ARCHITECTURE.md](THREE_PLANE_ARCHITECTURE.md), the policy YAML
library in [../policies/README.md](../policies/README.md), and the client/
observability tooling in [../python-client/README.md](../python-client/README.md).

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
[the `pqctoday-kmip` client](../python-client/README.md).

---

## 3. Configuring & applying a policy

A policy is one YAML file. Library of ready-made ones: see
[`../policies/README.md`](../policies/README.md) for the full, current
catalog and its "Modular policies (schema v3)" section — the list is not
duplicated here because it grows too often to keep two copies in sync.

### File shape

```yaml
schema_version: 3                   # 1 = base; 2 adds `expires`; 3 adds `scopes`
metadata:
  name: my-policy
  description: |
    Human-readable intent.
  authority: my-org
  effective: always                 # or a date, or "immediate"
  expires: never                    # optional (schema v2+); or a date
  scopes: [signing]                 # optional (schema v3+) — see §3.2
  compliance_mapping:               # optional, informational
    - { framework: "FIPS 140-3", status: aligned }
rules:
  - type: <rule_type>               # see §4
    # … rule-specific fields …
```

An **empty `rules: []` allows everything** at Plane 1 (that is what
`training-permissive` is). Rules then *gate* (deny), *force* (rewrite a
parameter), or *migrate* (substitute / rekey). Rule order matters, but
differently for each pass — corrected here 2026-08-28, this section
previously described one blanket "last-match-wins" rule for all of Pass 1:

- **Pass 0 — `algorithm_default`.** Only runs when the request omits the
  algorithm. First matching default wins, and every `name_pattern` rule is
  checked (in file order) before any generic (no-`name_pattern`) rule —
  a label-specific default always beats a generic one for the same op,
  regardless of listing order.
- **Pass 1 — `algorithm_substitution`.** Walks every rule in file order
  against the Pass-0 result; each match rewrites the running value, so
  **last match wins** and rules can chain.
- **Pass 2 — gating.** Walks gating rules in declaration order against the
  Pass 0/1-resolved algorithm; **first Deny wins** (short-circuits).

A policy also has a **validity window**: `effective`/`expires` are checked
per request, not just at load time. A request timestamped outside
`[effective, expires]` is denied — the policy is treated as fully inert for
that request, the same fail-closed posture as no policy loaded at all.

> **Fail-safe default:** if the server has *no* active policy/module at all,
> every request is **denied**. A loaded policy with no rules allows
> everything; the two are different states.

### 3.1 Apply it

```bash
pqctoday-kmip \
  --listen 127.0.0.1:5696 --store-memory \
  --policy-dir policies \        # directory of *.yaml policies
  --policy aead-only \           # single-file activation at boot
  --audit-log /tmp/agility.jsonl # three-plane decision log (see §6)
```

- `--policy-dir` — the policy library directory.
- `--policy <name>` — activate `<name>.yaml` at boot (the legacy,
  single-policy mode — see §3.2 for the modular alternative) and write the
  `.active` marker.
- Omit `--policy`/`--module` and the server resumes whichever marker
  (`.active` or `.active-modules`) is present, else loads the built-in
  permissive fallback and logs a boxed, multi-line warning naming the exact
  flags to fix it — worth grepping your server logs for on every deploy.

### 3.2 Modular policies — multiple active modules, no priority stack

Added 2026-08-28. A policy can declare `metadata.scopes` (a list drawn from
`signing`, `key-establishment`, `encryption`, `mac-hash`, `ingress`,
`lifecycle`, `global`) instead of governing every operation. Several such
files can be active **at once**, each owning its own slice of the request
surface — no priority number, because a scope can only ever be claimed by
one named module, so modules compose instead of needing an order. `global`
is exempt from scope containment (it can gate any op, including a bare,
unrefined one) but cannot itself resolve an algorithm default/substitution.

```bash
pqctoday-kmip \
  --policy-dir policies \
  --module classical-signing --module classical-key-establishment \
  --module classical-encryption --module classical-global \
  --uncovered-ops deny            # default; `allow` is playground-only
```

`--module <name>` is repeatable and mutually exclusive with `--policy` — a
server runs either the legacy single-policy mode or the modular mode, never
both. `--uncovered-ops` decides what happens to a request whose op no
active module's scope covers; `deny` (fail closed) is the only value a
production deployment should use. Full reference (containment rules, the
non-conflict model, the engine API): `policies/README.md`'s "Modular
policies" section.

### 3.3 Live management — the admin API

**Corrected 2026-08-28** — this section previously said "there is no
network management surface… requires a (re)launch"; that was false even
before this session (the admin facade below has existed since before this
plan started) and is more false now that it also covers the modular set.

`cryptopolicy-manager` is a live, mTLS-protected HTTP admin facade — the
server does NOT require a restart to change its active policy. Every
mutating route requires a client certificate whose CN is on the
server's write allowlist (mTLS + X25519MLKEM768 hybrid KEM, TLS 1.3 only).
Key routes (full request/response shapes:
[`../cryptopolicy-manager/openapi.yaml`](../cryptopolicy-manager/openapi.yaml)):

| Route | Effect |
|---|---|
| `GET/PUT/DELETE /api/v1/active` | Legacy single-policy slot: read, hot-swap, or clear (deny-all) the live policy — no restart. |
| `GET/POST/DELETE /api/v1/active-modules` | Modular set: list, activate/upsert one module, or clear the whole set. |
| `DELETE/PATCH /api/v1/active-modules/{name}` | Deactivate one module, or enable/disable it in place. |
| `GET/PUT /api/v1/config/uncovered-ops` | Read/set the modular fallback mode. |
| `GET/POST/PUT /api/v1/policies[/{name}]` | List / create / update a policy file in the store. |
| `POST /api/v1/validate`, `POST /api/v1/dry-run` | Validate a draft, or dry-run it against a sample request, without activating anything. |

Every activation records a p1 audit event carrying SHA-256 fingerprints of
the prior and new policy — this is the security-critical surface operators
most need to know exists and to lock down (the write-CN allowlist), not the
part of this guide most likely to be skipped.

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
| `algorithm_denylist` | `op ∈ ops` and `algorithm ∈ algorithms` (optional `exception_custom_attribute: { name, value }` escape hatch — the request carrying that attribute suppresses the deny) |
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
| `max_key_age_days` | deny `op` when the key is older than `days`, checked against the stored object's real Activation Date. **Genuinely enforced** (corrected 2026-08-28 — this row previously called it a stub that never fires; that stopped being true once Sign/Encrypt/Decrypt/Encapsulate/Decapsulate started populating the object's activation date). Only fires for ops that target an already-activated key. |
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
  doesn't match. **Genuinely executed end to end** for `Sign` and
  `Encapsulate` (corrected 2026-08-28 — this used to say the multi-op
  rekey transaction wasn't executed; it is): the op handler generates a
  fresh key under the new algorithm, activates it, moves the original key
  to KMIP's real `Deactivated` state, links the two via the custom
  `x-pqctoday-supersedes` attribute, then re-issues the original op against
  the new key — transparent migration from classical to PQC at next use.
  For every other op, `RekeyAndProceed` is structurally impossible (there
  is no existing object to rekey at `Create`/`CreateKeyPair`, and
  substitution rules must never target a "consumer" op like
  `Decrypt`/`Decapsulate`/`DeriveKey` — the loader rejects such a rule), so
  the handler treats seeing it there as an internal-error bug marker, not
  a designed path.

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

`python -m pqctoday_kmip audit <log>` (module `pqctoday_kmip.audit`) groups the log into per-request trails.
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
agility story end-to-end. See `python -m pqctoday_kmip demo` ([../python-client/README.md](../python-client/README.md)).

---

## 7. See also

- [THREE_PLANE_ARCHITECTURE.md](THREE_PLANE_ARCHITECTURE.md) — design rationale.
- [../policies/README.md](../policies/README.md) — the policy library.
- [CRYPTO_POLICY_STATUS.md](CRYPTO_POLICY_STATUS.md) — capabilities & limits.
- [../python-client/README.md](../python-client/README.md) — drive it + read the trail.
