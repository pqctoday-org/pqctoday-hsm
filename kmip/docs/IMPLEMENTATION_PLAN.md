# `pqctoday-hsm/kmip/` Subsystem — Implementation Plan (Rust)

Focused implementation plan for the **KMIP 3.0 PKCS#11 wrapper** subsystem of `pqctoday-hsm`. Written in **Rust**.

| Field | Value |
|---|---|
| Subsystem name | `pqctoday-hsm/kmip/` |
| Language | **Rust (edition 2024)** — matches the parent repo's `rust/` engine (`softhsmrustv3`); no Go, no new language introduced |
| **Required parent release** | **`pqctoday-hsm` ≥ v0.5.0** — ✅ **released 2026-06-04** as commit `025b074` (PR #65). `rust/Cargo.toml` aligned at `0.5.0`. All FIPS-surface fixes from the original §0.1 manifest are on `main`. **`main` is now a valid base.** The P0-ALGO-SURFACE algorithm expansion (vendor mech IDs `0x4040`+) ships in a future minor release. |
| Goal | **Validate KMIP 3.0 with PQC + classical keys** by wrapping our PKCS#11 v3.2 HSM library as a KMIP 3.0 protocol surface |
| Status | 🟦 Not Started |
| License | MIT (matches `pqctoday-hsm` parent) |
| Architecture choice | **Option A — thin KMIP wrapper directly over PKCS#11**, NO Thales kmip-go (no Go anywhere) |
| Architecture model | **Three-plane model** (see [`THREE_PLANE_ARCHITECTURE.md`](THREE_PLANE_ARCHITECTURE.md)): Crypto Agility Management → KMIP 3.0 Key Management → PKCS#11 Crypto Execution |
| Cargo project layout | Standalone Cargo project (matches `pqctoday-hsm/rust/`, `pqctoday-hsm/openpgp/`, `pqctoday-hsm/openmls-provider/` pattern). Internal workspace with library + binaries. |
| PKCS#11 backend | Direct path dependency on `../rust` (`softhsmrustv3`); zero FFI inside the subsystem (the Rust engine IS the PKCS#11 implementation we call) |
| Authoritative codepoints | [`pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`](../../../../pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md) |
| Sandbox integration plan | [`pqctoday-sandbox/tasks/p0-kmip-wrapper-22-impl.md`](../../../../pqctoday-sandbox/tasks/p0-kmip-wrapper-22-impl.md) (Phase 2 — sandbox-side wiring only) |
| Effort estimate | 13.5–14.0 PD (standalone subsystem, Phase 1 → Phase 9) + 1 PD sandbox integration |

## 0. Parent release status: ✅ v0.5.0 shipped 2026-06-04

`pqctoday-hsm` v0.5.0 was released as commit `025b074` (PR #65), bundling 5 intermediate tag bumps (`v0.4.26` → `v0.4.29`) plus the alignment commit that catches `rust/Cargo.toml` up to `0.5.0`. **Phase 0 of this plan is no longer blocked.**

Historical fix manifest preserved below for context — every entry is now on `main`.

### 0.1 Fix manifest (post-0.4.25, all on main as of v0.5.0)

| Commit | Title | Why it matters for the KMIP wrapper |
|---|---|---|
| `1b6c9ef` | v0.4.25 — PKCS#11 v3.2 full compliance 127/0/0 | Already shipped — baseline |
| `8a0de8f` | resolve gaps 37, 38, 50 for v0.4.24 release | Compliance baseline |
| `08f843b` | XMSS-MT support, ML-DSA/SLH-DSA full HashSign parity, security hardening | XMSS-MT exposes the stateful-sig path; HashSign parity needed for KMIP `Sign` op to match KMIP's `digested_data` semantics for ML-DSA/SLH-DSA byte-exactly |
| `f57dd02` | align Token Model ID cross-engine parity to PQCToday | KMIP `Query` op reports the engine identifier; needs C++ + Rust to agree |
| `73622e2` | pkcs11-provider: ML-DSA MANDATORY_DIGEST + composite SPKI encoders (phase 4b) | KMIP `Create` for ML-DSA-65 with composite parameters depends on correct SPKI encoding; KMIP `Get` of composite public keys depends on the new encoder |
| `2dbd036` | **AES-GCM AAD authentication restored — critical correctness + security fix** | **CRITICAL.** KMIP `Encrypt` / `Decrypt` for AES-256-GCM (the classical symmetric default in the `classical-baseline` profile) would silently accept tampered ciphertext under v0.4.25. **Hard-blocker.** |
| `d086081` | **populate KCV on `C_UnwrapKey` / `C_DeriveKey` + store `CKA_VALUE` on RSA public key** | **KCV bug.** Affects: KMIP `Get` returning Key Check Value attribute (KMIP exposes KCV via `Cryptographic Length` + key digest); KMIP `Re-key` round-trip would emit wrong KCV; future KMIP `Wrap`/`Unwrap` (out of v0.1 but planned) would inherit the bug. **`store CKA_VALUE on RSA public key`** is also material: KMIP `Get` of an RSA public key currently returns wrong (or empty) `Key Value` field without this fix. |
| `3146344` | XMSS param-set storage + ECDSA P-521 sig length + EC point long-form DER | XMSS param-set storage needed for KMIP attribute roundtrip on stateful HSS/XMSS keys; ECDSA P-521 sig length affects `classical-baseline` profile correctness; EC long-form DER needed for `Get` of P-521 public keys |

### 0.2 v0.5.0 release checklist — ✅ all items complete (preserved for audit)

- [x] Cherry-pick / merge `fix/rust-xmss-ecdsa-p521-compliance` branch into `main` — landed as PR #63 (`fbc5468`).
- [x] Bump `rust/Cargo.toml` `version = "0.4.25"` → `version = "0.5.0"` — done; CHANGELOG notes the manifest was stale through v0.4.26–v0.4.29 tags and finally caught up at v0.5.0.
- [x] Update `CHANGELOG.md` — done; v0.5.0 entry dated 2026-06-04.
- [x] Tag `v0.5.0` — done as commit `025b074`.
- ⚠️ **DEFERRED:** P0-ALGO-SURFACE vendor mech IDs `0x4040`–`0x404F` were NOT bundled into v0.5.0. They ship in a future minor release (v0.5.x or v0.6.0) — this is a scope split from the original plan, not a regression. The KMIP subsystem's v0.1 algorithm shelf is therefore limited to the v0.5.0 FIPS surface (`0x4030`–`0x4037`): ML-KEM, ML-DSA, SLH-DSA, HSS.

### 0.3 Regression test coverage at v0.5.0 — ✅ shipped green

Per the post-0.4.25 fix list, the parent repo's existing test suite (107 conformance tests + 127 PKCS#11 v3.2 compliance) must continue to be 100% green at v0.5.0. Additionally:

- [ ] AES-GCM AAD authentication regression test: encrypt with AAD, tamper the AAD, decrypt MUST fail with `CKR_GENERAL_ERROR` (not silent success).
- [ ] KCV regression test on `C_UnwrapKey` / `C_DeriveKey`: `CKA_CHECK_VALUE` MUST be populated and match the deterministic computation (encrypt 8 bytes of zero, take first 3).
- [ ] RSA public-key `CKA_VALUE` regression test: generate RSA-2048 keypair, fetch `CKA_VALUE` on the public key handle, MUST return the modulus + public exponent in proper DER/raw form.
- [ ] XMSS param-set storage regression: keygen XMSS-MT, store, fetch param-set attribute, MUST round-trip identical bytes.
- [ ] ECDSA P-521 signature length regression: P-521 ECDSA signature output MUST be the maximum 139 bytes (DER-encoded) per RFC 5480; earlier truncation bug rejected.

## 1. Why Rust (lock-in)

| Reason | Detail |
|---|---|
| Matches existing engine | `pqctoday-hsm/rust/softhsmrustv3` is already shipping PQC; the KMIP subsystem calls into it as a Rust crate, not via FFI |
| Memory safety on the network surface | KMIP servers parse untrusted TTLV bytes from the network — Rust's borrow checker eliminates a CVE class that plagues C++ KMIP implementations |
| Zero FFI boundary inside the subsystem | Plane 2 (KMIP) calls Plane 3 (PKCS#11) via `use softhsmrustv3` — no extern, no CGO, no headers |
| Async-first | `tokio` async runtime handles many concurrent KMIP connections cleanly; no goroutine/CGO interaction risks |
| Strong-type plane boundaries | The compiler enforces Plane 1 → Plane 2 → Plane 3 transitions; you can't accidentally call PKCS#11 from the policy engine |
| Aligned with parent's forward direction | `pqctoday-hsm/rust/` is where new development is going; the C++ engine is maintenance-only |
| Trustworthy TLS via `rustls` | Memory-safe TLS without OpenSSL FFI complexity |
| Customer story | "Built in Rust on our Rust PQC engine" beats "Go wrapper that calls C++ via FFI" |

## 2. Subsystem boundary

This subsystem owns:

- KMIP 3.0 protocol surface (TTLV codec, operations, attributes)
- Crypto Agility Management policy engine (Plane 1)
- KMIP-specific persistence layer (object metadata + lifecycle state, SQLite)
- KMIP 3.0 compliance validation tool
- KAT vector corpus for KMIP TTLV + PQC + classical algorithms
- Local copies of OASIS KMIP 3.0 + 2.1 specs (for offline reference + validation)
- Reference CLI client + lab guides

This subsystem does NOT own:

- PKCS#11 mechanism implementations — that's `pqctoday-hsm/rust/softhsmrustv3` (we depend on it)
- Vendor mech codepoint allocation — authoritative file lives in `pqctoday-priv`
- Sandbox image build or scenario-22 orchestration — that's `pqctoday-sandbox`
- Production-KMS scaffolding (multi-tenant, HA, replication) — explicit non-goal

## 3. Persistence layer (KMIP-specific, NOT reusing PKCS#11 token storage)

### 3.1 Why separate

| Property | Stored by PKCS#11? | Stored by KMIP store? |
|---|---|---|
| Key material (bytes) | ✅ yes — softhsmv3 token | ❌ never — stays in HSM |
| Stable key identifier | ✅ `CKA_ID` (we set this at keygen) | ✅ `kmip_uid → CKA_ID` mapping |
| Session-scoped handle | ✅ ephemeral, per-session | ❌ never persisted |
| KMIP lifecycle state | ❌ PKCS#11 has no Active/Deactivated/Destroyed concept | ✅ yes — required by KMIP spec |
| KMIP timestamps (Created/Activated/...) | ❌ | ✅ |
| KMIP cryptographic usage mask | ❌ (CKA_SIGN/CKA_ENCRYPT are similar but not byte-compatible) | ✅ stored separately |
| KMIP custom attributes + tags | ❌ | ✅ |
| KMIP key versions (re-key) | ❌ | ✅ each version is a separate object |
| Per-op audit trail | ❌ | ✅ separate persistent log |

**Conclusion:** SQLite-backed object store, owned by the KMIP subsystem. Key material stays in `softhsmrustv3`, referenced by stable `CKA_ID`.

### 3.2 Crate choice: `rusqlite`

- Pure-Rust SQLite bindings (no C dep beyond the SQLite amalgamation it pulls in).
- Synchronous API — fine, our store ops are short.
- Migrations via `rusqlite_migration`.
- Schema per §3.3.

### 3.3 Schema

`src/store/schema.sql`:

```sql
CREATE TABLE IF NOT EXISTS schema_meta (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS objects (
    uid              TEXT PRIMARY KEY,            -- KMIP Unique Identifier (urn:pqctoday:obj:<uuid>)
    pkcs11_cka_id    BLOB NOT NULL UNIQUE,        -- stable PKCS#11 identifier; NOT the session handle
    pkcs11_slot      INTEGER NOT NULL DEFAULT 0,
    object_type      TEXT NOT NULL,               -- SymmetricKey | PublicKey | PrivateKey | OpaqueObject
    algorithm        TEXT NOT NULL,               -- ML-KEM-768 | ML-DSA-65 | RSA | AES | ...
    cryptographic_length INTEGER,
    state            TEXT NOT NULL,               -- PreActive | Active | Deactivated | Compromised | Destroyed
    usage_mask       INTEGER NOT NULL DEFAULT 0,  -- KMIP CryptographicUsageMask bitfield
    version          INTEGER NOT NULL DEFAULT 1,
    parent_uid       TEXT REFERENCES objects(uid),
    created_at       TEXT NOT NULL,
    activated_at     TEXT,
    deactivated_at   TEXT,
    destroyed_at     TEXT,
    last_op_at       TEXT,
    op_count         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_objects_state     ON objects(state);
CREATE INDEX IF NOT EXISTS idx_objects_algorithm ON objects(algorithm);

CREATE TABLE IF NOT EXISTS object_attributes (
    uid          TEXT NOT NULL REFERENCES objects(uid) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    value        TEXT NOT NULL,
    index_order  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (uid, name, index_order)
);

CREATE TABLE IF NOT EXISTS object_tags (
    uid TEXT NOT NULL REFERENCES objects(uid) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (uid, tag)
);
CREATE INDEX IF NOT EXISTS idx_object_tags_tag ON object_tags(tag);

CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    client_cn      TEXT,
    plane          TEXT NOT NULL,             -- "policy" | "kmip" | "pkcs11"
    op             TEXT NOT NULL,
    uid            TEXT,
    request_size   INTEGER,
    response_size  INTEGER,
    result_status  TEXT NOT NULL,
    result_reason  TEXT,
    duration_us    INTEGER,
    correlation_id TEXT NOT NULL             -- correlates the three plane entries for one request
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts             ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_correlation_id ON audit_log(correlation_id);
```

### 3.4 Lifecycle FSM

State transitions allowed (rejected otherwise with KMIP `PermissionDenied`):

```text
PreActive → Active        (Activate op)
PreActive → Destroyed     (Destroy op while never-activated)
Active    → Deactivated   (Revoke op)
Active    → Compromised   (Revoke op, reason=Compromise)
Deactivated → Destroyed   (Destroy op)
Compromised → Destroyed   (Destroy op)
Destroyed   → (terminal)
```

Per-state op allowance:

| State | Encrypt | Decrypt | Sign | Verify | Get | Locate |
|---|---|---|---|---|---|---|
| PreActive | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Active | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Deactivated | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Compromised | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Destroyed | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

(KMIP 3.0 reuses `Encrypt` op for ML-KEM encapsulation when the key is an asymmetric KEM key, and `Decrypt` for decapsulation. There is no separate `Encapsulate` / `Decapsulate` op in the KMIP 3.0 operation enumeration — verified against OASIS test cases 2026-06-04.)

## 4. Cargo project layout

```text
pqctoday-hsm/kmip/
├── Cargo.toml                                # workspace root (binaries + library)
├── Cargo.lock
├── LICENSE                                   # MIT
├── README.md
│
├── src/                                      # library crate (pqctoday_kmip)
│   ├── lib.rs
│   │
│   ├── server/                               # KMIP server (Plane 2 entry point)
│   │   ├── mod.rs
│   │   ├── listener.rs                       # tokio TCP listener
│   │   └── tls.rs                            # rustls + self-signed ML-DSA-65 cert
│   │
│   ├── codec/                                # KMIP TTLV codec (hand-rolled)
│   │   ├── mod.rs
│   │   ├── tag.rs                            # Tag enum (typed) — KMIP 1.4 + 2.0 + 3.0 codepoints
│   │   ├── value.rs                          # Value enum: Integer, LongInt, Bool, TextString,
│   │   │                                     #  ByteString, Structure, Enumeration, Interval,
│   │   │                                     #  DateTime, BigInteger
│   │   ├── encode.rs                         # serialize → bytes
│   │   ├── decode.rs                         # bytes → Value (nom-style hand-written parser)
│   │   └── tests.rs                          # round-trip property tests via proptest
│   │
│   ├── kmip30/                               # KMIP 3.0 extension layer
│   │   ├── mod.rs
│   │   ├── algos.rs                          # KMIP algo enum ↔ PKCS#11 vendor mech ID
│   │   ├── attrs.rs                          # standard KMIP attribute types
│   │   ├── ops.rs                            # request/response struct definitions per op
│   │   └── spec_source.json                  # extracted from OASIS KMIP 3.0 PDF
│   │
│   ├── dispatcher/                           # Plane 2 routing
│   │   └── mod.rs                            # match on Operation enum; route to ops/*
│   │
│   ├── ops/                                  # Plane 2 operation handlers (≤ 100 LOC each)
│   │   ├── mod.rs
│   │   ├── query.rs
│   │   ├── create_sym.rs
│   │   ├── create_asym.rs
│   │   ├── get.rs
│   │   ├── locate.rs
│   │   ├── activate.rs
│   │   ├── revoke.rs
│   │   ├── destroy.rs
│   │   ├── encrypt.rs
│   │   ├── decrypt.rs
│   │   #                                     # NOTE: KMIP 3.0 does NOT add separate
│   │   #                                     # Encapsulate/Decapsulate ops. ML-KEM
│   │   #                                     # encapsulation reuses Encrypt; ML-KEM
│   │   #                                     # decapsulation reuses Decrypt. Branch
│   │   #                                     # on key algorithm inside those handlers.
│   │   ├── sign.rs
│   │   └── signature_verify.rs
│   │
│   ├── policy/                               # Plane 1 — Crypto Agility Management Plane
│   │   ├── mod.rs
│   │   ├── engine.rs                         # Evaluate(req) → Decision
│   │   ├── rules.rs                          # AllowList, DenyList, MinKeyLength,
│   │   │                                     #  RequireUsageMask, TemporalCutoff,
│   │   │                                     #  RequireCustomAttribute, LifecycleStateGate,
│   │   │                                     #  HybridDualSignRequirement, ComplianceProfileGate
│   │   ├── loader.rs                         # serde_yaml policy file loader
│   │   ├── inventory.rs                      # crypto inventory + drift detection
│   │   └── report.rs                         # compliance mapping output
│   │
│   ├── store/                                # SQLite-backed object store
│   │   ├── mod.rs
│   │   ├── schema.sql                        # included via include_str!()
│   │   ├── object.rs                         # objects CRUD
│   │   ├── lifecycle.rs                      # FSM rules
│   │   └── tags.rs                           # tag CRUD + Locate query builder
│   │
│   ├── attrmap/                              # KMIP attr ↔ PKCS#11 template translation
│   │   └── mod.rs
│   │
│   ├── pkcs11bridge/                         # Plane 3 wrapper (NO FFI — direct Rust dep)
│   │   ├── mod.rs                            # re-exports softhsmrustv3 surface
│   │   ├── session.rs                        # session lifecycle helpers
│   │   ├── mechs.rs                          # vendor mech constants from manifest
│   │   └── tests.rs                          # smoke against softhsmrustv3
│   │
│   ├── auditlog/                             # cross-plane audit writer
│   │   └── mod.rs
│   │
│   ├── types/                                # shared types (Uid, Algorithm, State, ...)
│   │   └── mod.rs
│   │
│   └── error.rs                              # KmipError, mapping to KMIP ResultReason codes
│
├── bin/
│   ├── pqctoday-kmip.rs                      # KMIP server entry point
│   ├── pqctoday-kmip-client.rs               # reference CLI client
│   └── pqctoday-kmip-compliance.rs           # KMIP 3.0 compliance test runner
│
├── compliance/                               # KMIP 3.0 compliance tool resources
│   ├── README.md                             # mirrors PKCS#11 v3.2 compliance tool README
│   ├── profiles/
│   │   ├── baseline.yaml
│   │   ├── pqc-kem.yaml
│   │   ├── pqc-sig.yaml
│   │   ├── classical-baseline.yaml
│   │   ├── policy-enforcement.yaml           # tests the Plane 1 engine
│   │   └── full-v0.1.yaml
│   ├── src/                                  # Rust modules used by bin/pqctoday-kmip-compliance.rs
│   │   ├── runner.rs
│   │   ├── profile.rs
│   │   ├── expectations.rs
│   │   └── reporter.rs
│   └── testdata/                             # third-party KMIP endpoint configs (interop)
│
├── policies/                                 # Plane 1 — example + default policies
│   ├── README.md
│   ├── pqc-migration-2030.yaml
│   ├── fips-only.yaml
│   ├── hybrid-migration-window.yaml
│   ├── cnsa-2.0.yaml
│   └── training-permissive.yaml
│
├── spec/                                     # local reference + validation source
│   ├── README.md
│   ├── oasis-kmip-3.0/
│   │   ├── kmip-spec-3.0.pdf
│   │   ├── kmip-spec-3.0-tags-enums.json    # generated by Rust HTML parser over kmip-spec-v3.0.html
│   │   └── kmip-spec-3.0.pdf.sha256
│   ├── oasis-kmip-2.1/
│   │   └── kmip-spec-2.1.pdf
│   └── oasis-pkcs11-3.2/
│       └── PKCS11-V32-OASIS.html
│
├── kat/                                      # known-answer test vectors
│   ├── README.md                             # provenance + sha256 per file
│   ├── ttlv-wire/                            # KMIP TTLV byte-exact vectors
│   │   ├── *.req.bin
│   │   ├── *.resp.bin
│   │   └── manifest.json
│   ├── ml-kem/ml-kem-768-acvp.json
│   ├── ml-dsa/ml-dsa-65-acvp.json
│   ├── slh-dsa/slh-dsa-sha2-128s-acvp.json
│   ├── rsa/rsa-2048-pkcs1-sha256-kat.json
│   ├── ecdsa/ecdsa-p256-sha256-kat.json
│   └── aes/aes-256-gcm-kat.json
│
├── docs/
│   ├── IMPLEMENTATION_PLAN.md                # THIS FILE
│   ├── THREE_PLANE_ARCHITECTURE.md           # architectural lodestar
│   ├── KMIP_3_0_DELTA.md                     # divergence from OASIS published codepoints
│   ├── PQC_BACKEND_DECISION.md               # why Rust direct dep on softhsmrustv3
│   ├── SUBSYSTEM_BOUNDARY.md
│   ├── STANDALONE_VALIDATION.md              # Phase-1 acceptance checklist
│   ├── PERSISTENCE_LAYER.md                  # §3 expanded
│   ├── CLASSICAL_KMIP_FLOW.md
│   ├── PQC_KMIP_FLOW.md
│   ├── POLICY_ENGINE.md                      # Plane 1 reference manual
│   ├── COSMIAN_REFERENCE.md
│
├── examples/
│   ├── ml-kem-768-lifecycle.sh
│   ├── ml-dsa-65-sign-verify.sh
│   ├── rsa-2048-classical-baseline.sh
│   ├── policy-enforcement-demo.sh
│   └── compliance-self-test.sh
│
├── tests/                                    # integration tests (cargo test runs them)
│   ├── kmip_op_roundtrip.rs
│   ├── lifecycle_fsm.rs
│   ├── policy_engine.rs
│   ├── kat_replay.rs                         # replays kat/ttlv-wire/
│   ├── acvp_roundtrip.rs                     # NIST ACVP vectors
│   └── compliance_self_test.rs
│
└── Dockerfile                                # multi-stage; builds softhsmrustv3 + kmip
```

## 5. Cargo.toml (top-level)

```toml
[package]
name        = "pqctoday-kmip"
version     = "0.1.0"
edition     = "2024"
license     = "MIT"
description = "KMIP 3.0 PQC + classical key management wrapper over pqctoday-hsm PKCS#11"
repository  = "https://github.com/pqctoday-org/pqctoday-hsm"

[lib]
name = "pqctoday_kmip"
path = "src/lib.rs"

[[bin]]
name = "pqctoday-kmip"
path = "bin/pqctoday-kmip.rs"

[[bin]]
name = "pqctoday-kmip-client"
path = "bin/pqctoday-kmip-client.rs"

[[bin]]
name = "pqctoday-kmip-compliance"
path = "bin/pqctoday-kmip-compliance.rs"

[dependencies]
# Plane 3 — direct Rust dependency on the engine, NO FFI
softhsmrustv3 = { path = "../rust" }

# Async runtime + I/O
tokio        = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
rustls       = { version = "0.23", features = ["ring"] }
rustls-pemfile = "2"

# Persistence
rusqlite           = { version = "0.32", features = ["bundled"] }
rusqlite_migration = "1"

# Serialization (policy + spec JSON + compliance profiles)
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
serde_yaml  = "0.9"

# CLI
clap = { version = "4", features = ["derive"] }

# Observability
tracing            = "0.1"
tracing-subscriber = "0.3"

# Crypto helpers (NOT for PQC — that's softhsmrustv3 — only for TLS bootstrap)
rand        = "0.8"
sha2        = "0.10"

# IDs
uuid = { version = "1", features = ["v4"] }

# Time
time = { version = "0.3", features = ["serde", "formatting"] }

# Error handling
thiserror = "1"
anyhow    = "1"

[dev-dependencies]
proptest   = "1"
hex        = "0.4"
test-case  = "3"
assert_cmd = "2"
predicates = "3"
```

## 6. Implementation phases

### Phase 0 — Bootstrap (0.5 PD) ✅ **COMPLETE 2026-06-07**

**Prerequisite:** ~~§0 v0.5.0 release MUST be cut before this phase starts~~ → ✅ **satisfied:** v0.5.0 shipped 2026-06-04 (`025b074`); §0.3 regression suite green; Phase 0 unblocked.

- [x] `pqctoday-hsm` is on `v0.5.0` tag (verified via `git log v0.5.0..HEAD` → empty).
- [x] §0.3 regression tests green at v0.5.0 (AES-GCM AAD, KCV on Unwrap/Derive, RSA pubkey CKA_VALUE, XMSS param-set, ECDSA P-521 sig length).
- [x] Create branch `feat/kmip-subsystem` in `pqctoday-hsm`.
- [x] Init Cargo project under `pqctoday-hsm/kmip/` matching the layout above. Library `pqctoday_kmip` + three bins (`pqctoday-kmip`, `pqctoday-kmip-client`, `pqctoday-kmip-compliance`). All 11 modules (codec, kmip30, dispatcher, ops, store, attrmap, server, pkcs11bridge, policy, auditlog, types + `error.rs`) declared as Phase-0 stub `mod.rs` files documenting their target phase. Removed leftover Go-style `cmd/` and `internal/` directories from the pre-pivot scaffold.
- [x] Add path dep `softhsmrustv3 = { path = "../rust" }` — version constraint pinned `>= 0.5.0`.
- [x] Mirror `[patch.crates-io]` block for `fips204` / `fips205` patched crates (same trick as `openmls-provider/Cargo.toml`). Cargo's `[patch]` does not propagate via `path =` deps, so the patches must be duplicated wherever `softhsmrustv3` is consumed.
- [x] ✅ **Resolved 2026-06-04 probe:** `softhsmrustv3` exposes `C_EncapsulateKey` at `rust/src/ffi.rs:1675` and `C_DecapsulateKey` at `:1765`, both citing PKCS#11 v3.2 §5.18.8/§5.18.9. C++ engine exposes them at `src/lib/SoftHSM_kem.cpp:111`/`:318` per §5.20. The KMIP wrapper calls `C_EncapsulateKey` / `C_DecapsulateKey` (with `Key` suffix, per spec). KEM ops in v0.5.0 are confirmed available.
- [x] Probe confirmed `softhsmrustv3` exposes vendor mechs `0x4032`–`0x4037` (six active codepoints: HSS keygen, SLH-DSA sign/verify, ML-KEM keygen, ML-DSA keygen, ML-DSA sign/verify, ML-KEM encap/decap). `0x4040`–`0x404E` reserved for P0-ALGO-SURFACE (Falcon/HQC/BIKE/FrodoKEM/Classic McEliece/XMSS) per `pkcs11-vendor-mech-allocation.md` §1.2; not yet shipping as of v0.5.0.
- [x] `pkcs11-mech-manifest.json` written at `pqctoday-hsm/kmip/pkcs11-mech-manifest.json` with `authority.sha256 = 3f63146bca1a8bd1454ea8f80e59911886014aebcab082754dec8c46eb70ab58` referencing `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`. Covers six active codepoints in `active.*` and fifteen reserved codepoints in `provisional_v0_5_x.*`. CI gate documented in `consumer_contract.ci_gate`.
- [x] `cargo build` green on the scaffold (24.32s, 13 transitive deps + softhsmrustv3 build).

### Phase 1 — Spec + KAT acquisition (1.0 PD)

- [ ] Download OASIS KMIP 3.0 spec PDF → `spec/oasis-kmip-3.0/kmip-spec-3.0.pdf`; record sha256.
- [ ] Write a small Rust HTML parser (Phase 2 deliverable) that walks `spec/oasis-kmip-3.0/kmip-spec-v3.0.html` and emits `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` byte-exact against the OASIS structured tables. No LLM in the loop.
- [ ] Cross-reference our placeholder JSON in `src/kmip30/spec_source.json`; reconcile divergences in `docs/KMIP_3_0_DELTA.md`.
- [ ] Download OASIS KMIP 2.1 PDF for fallback reference.
- [ ] Source NIST ACVP vectors (ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s) → `kat/`. Copy from `pqctoday-hub/src/data/acvp/`.
- [ ] Source classical KAT (RSA-2048 PKCS#1 SHA-256, ECDSA P-256 SHA-256, AES-256-GCM) from NIST FIPS 186-4 + CAVP.
- [ ] Hand-craft (or capture via a Rust test) TTLV wire vectors → `kat/ttlv-wire/`. Index in `manifest.json`.

### Phase 2 — TTLV codec (Plane 2 foundation) (2.0 PD)

- [ ] `src/codec/tag.rs` — `Tag` enum with `#[repr(u32)]` codepoints for KMIP 1.4 + 2.0 + 3.0.
- [ ] `src/codec/value.rs` — `Value` enum (Integer, LongInteger, BigInteger, Boolean, Enumeration, Interval, DateTime, ByteString, TextString, Structure). Each variant tagged with KMIP TTLV type byte.
- [ ] `src/codec/encode.rs` — `fn encode(value: &Value, buf: &mut BytesMut)`. Handles 8-byte alignment padding per spec.
- [ ] `src/codec/decode.rs` — `fn decode(input: &[u8]) -> Result<(Value, usize), CodecError>`. Hand-written; uses `nom`-style position tracking but without the `nom` dependency.
- [ ] `src/codec/tests.rs` — proptest round-trip: `encode(decode(bytes)) == bytes` for every Value variant.
- [ ] KAT replay sub-test in `tests/kat_replay.rs` — every pair in `kat/ttlv-wire/manifest.json` decodes + re-encodes byte-exact.

**Net new code (codec): ~3,500–5,000 LOC including tests.**

### Phase 3 — KMIP 3.0 extension layer + algo map (1.0 PD)

- [ ] `src/kmip30/algos.rs` — `pub enum KmipAlgorithm { MlKem512, MlKem768, MlKem1024, MlDsa44, MlDsa65, MlDsa87, SlhDsaSha2_128s, ..., Rsa, EcdsaP256, ..., Aes }` with `to_pkcs11_mech(&self) -> CkMechanismType` mapping per `pkcs11-vendor-mech-allocation.md`.
- [ ] `src/kmip30/attrs.rs` — `pub enum Attribute { CryptographicAlgorithm(KmipAlgorithm), CryptographicLength(u32), UsageMask(UsageMaskFlags), ... }`.
- [ ] `src/kmip30/ops.rs` — request/response struct definitions per op (one per file in src/ops/ later).
- [ ] Compile-time test: `KmipAlgorithm::to_pkcs11_mech` for every algorithm matches the mech allocation manifest.

### Phase 4 — PKCS#11 bridge (Plane 3 wrapper) (0.5 PD)

**Note:** this phase is trivial in Rust — no FFI. Just `use softhsmrustv3;` and wrap session management.

- [ ] `src/pkcs11bridge/mod.rs` — re-exports the engine surface, plus higher-level helpers.
- [ ] `src/pkcs11bridge/session.rs` — `Session` struct wrapping the engine's session handle; RAII close on drop.
- [ ] `src/pkcs11bridge/mechs.rs` — vendor mech constants generated against the manifest; CI gate checks authority sha256.
- [ ] Smoke test: open session, ML-KEM-768 keygen, encap/decap round-trip, destroy. Run via `cargo test`.

### Phase 4.5 — Plane 1 Crypto Agility Management Plane / policy engine (1.5 PD)

Implemented before op handlers (Phase 5) so handlers can call `policy::Engine::evaluate()`.

- [ ] `src/policy/engine.rs`:

  ```rust
  pub struct Engine { rules: Vec<Box<dyn Rule + Send + Sync>>, audit: Arc<AuditLog> }

  pub struct PolicyRequest<'a> {
      pub op: &'a str,                   // "Sign", "Encrypt", "Create", ...
      pub algorithm: Option<KmipAlgorithm>,
      pub key_length: Option<u32>,
      pub usage_mask: Option<UsageMaskFlags>,
      pub custom_attrs: &'a HashMap<String, String>,
      pub caller_cn: Option<&'a str>,
      pub ts: time::OffsetDateTime,
      pub correlation_id: &'a str,
  }

  pub enum Decision {
      Allow { algorithm_override: Option<KmipAlgorithm> },
      Deny  { kmip_reason: KmipResultReason, human: String },
  }

  impl Engine {
      pub fn evaluate(&self, req: &PolicyRequest) -> Decision { ... }
  }
  ```

- [ ] `src/policy/rules.rs` — built-in rule types: `AlgorithmAllowlist`, `AlgorithmDenylist`, `MinKeyLength`, `MaxKeyAge`, `RequireUsageMask`, `RequireCustomAttribute`, `TemporalCutoff`, `LifecycleStateGate`, `HybridDualSignRequirement`, `ComplianceProfileGate`. Each implements `trait Rule { fn check(&self, req: &PolicyRequest) -> Option<Decision>; }` (returns `Some(Deny)` to short-circuit, `None` to pass through).
- [ ] `src/policy/loader.rs` — `serde_yaml`-based loader; schema validation; line/column error reporting.
- [ ] `src/policy/inventory.rs` — `pub fn inventory(store: &Store) -> InventoryReport` walks objects + their algorithms + lifecycle state; basis for drift detection.
- [ ] `src/policy/report.rs` — compliance mapping output (FIPS, CNSA-2.0, NIS2, ANSSI, BSI cross-reference).
- [ ] `policies/training-permissive.yaml` — default policy loaded when no override is provided (sandbox testing).
- [ ] `policies/{pqc-migration-2030,fips-only,hybrid-migration-window,cnsa-2.0}.yaml` — example policy files.
- [ ] Unit tests per rule type covering positive + negative + boundary cases.

### Phase 5 — Op handlers (Plane 2) (2.0 PD)

11 ops, one module each, ≤ 100 LOC including tests. Note KMIP 3.0 reuses `Encrypt` for ML-KEM encapsulation and `Decrypt` for decapsulation — the handler branches on key algorithm:

```rust
// src/ops/encrypt.rs
use crate::{Deps, Result, KmipError, Algorithm, UsageMaskFlags};

pub async fn encrypt(
    deps: &Deps,
    req: EncryptRequest,
) -> Result<EncryptResponse> {
    // Plane 1: policy gate (already evaluated upstream in dispatcher; double-check)
    if !deps.policy_already_evaluated(&req.correlation_id) {
        return Err(KmipError::internal("missing policy decision"));
    }

    // Plane 2: resolve UID → object; lifecycle check
    let obj = deps.store.get(&req.uid).await?
        .ok_or(KmipError::not_found(&req.uid))?;
    obj.check_lifecycle_allows("Encrypt")?;

    // Plane 3: open session, find by stable CKA_ID
    let session = deps.pkcs11.open_session(obj.pkcs11_slot)?;
    session.login(&deps.config.pin)?;
    let handle = session.find_by_cka_id(&obj.pkcs11_cka_id)?;

    // Branch on key algorithm — KMIP 3.0 ML-KEM encapsulation uses Encrypt op
    let response = match obj.algorithm {
        Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
            obj.check_usage_mask(UsageMaskFlags::KEY_AGREEMENT)?;
            let (ciphertext, shared_secret) = session.encapsulate_key(handle)?;
            deps.audit.record(req.correlation_id, "pkcs11", "C_EncapsulateKey", Status::Success).await;
            EncryptResponse::kem(obj.uid.clone(), ciphertext, shared_secret)
        }
        _ => {
            obj.check_usage_mask(UsageMaskFlags::ENCRYPT)?;
            let ciphertext = session.encrypt(handle, &req.data)?;
            deps.audit.record(req.correlation_id, "pkcs11", "C_Encrypt", Status::Success).await;
            EncryptResponse::classical(obj.uid.clone(), ciphertext)
        }
    };

    deps.store.increment_op_count(&req.uid).await?;
    Ok(response)
}
```

`src/ops/decrypt.rs` mirrors the same shape — ML-KEM → `C_DecapsulateKey`; classical → `C_Decrypt`.

All 11 ops: `query`, `create_sym`, `create_asym`, `get`, `locate`, `activate`, `revoke`, `destroy`, `encrypt`, `decrypt`, `sign`, `signature_verify`. (Verified 2026-06-04 against the OASIS KMIP 3.0 test-case op enum — KMIP 3.0 does NOT add `Encapsulate` / `Decapsulate` as distinct operations; PQC algorithm enum values are added to `CryptographicAlgorithm` and KEM ops reuse the existing `Encrypt` / `Decrypt` machinery.)

Per-op unit tests (mock store + mock pkcs11 surface) + integration tests against real `softhsmrustv3`.

### Phase 6 — Object store + lifecycle FSM (0.75 PD)

- [ ] `src/store/mod.rs` — `Store` struct wrapping `rusqlite::Connection` in `Arc<Mutex<_>>`.
- [ ] `src/store/schema.sql` — embedded via `include_str!()`.
- [ ] `src/store/object.rs` — CRUD: `create`, `get`, `update_state`, `delete`, `find_by_tags`.
- [ ] `src/store/lifecycle.rs` — FSM per §3.4; `Object::transition(to_state) -> Result<()>`.
- [ ] `src/store/tags.rs` — KMIP Locate query builder.
- [ ] Migration via `rusqlite_migration`: schema version 1 = initial.

### Phase 7 — Dispatcher + KMIP server (0.75 PD)

- [ ] `src/dispatcher/mod.rs`:

  ```rust
  pub async fn dispatch(deps: &Deps, req: KmipRequest) -> KmipResponse {
      let correlation_id = Uuid::new_v4().to_string();

      // Plane 1: policy evaluation (before any op work)
      let policy_decision = deps.policy.evaluate(&req.to_policy_request(&correlation_id));
      if let Decision::Deny { kmip_reason, human } = policy_decision {
          deps.audit.record(&correlation_id, "policy", &req.op_name(), Status::Denied(human)).await;
          return KmipResponse::error(kmip_reason);
      }

      // Plane 2: route to op handler
      match req.operation {
          Operation::Encrypt(r)     => ops::encrypt(deps, r).await.into(),  // handles classical + ML-KEM
          Operation::Decrypt(r)     => ops::decrypt(deps, r).await.into(),  // handles classical + ML-KEM
          Operation::Sign(r)        => ops::sign(deps, r).await.into(),
          // ... 11 ops total
      }
  }
  ```

- [ ] `src/server/listener.rs` — `tokio::net::TcpListener`; per-connection `tokio::spawn`; read length-prefixed KMIP frame, decode, dispatch, encode, write.
- [ ] `src/server/tls.rs` — `tokio_rustls::TlsAcceptor` configured with self-signed ML-DSA-65 cert generated on first start (via `softhsmrustv3`).
- [ ] `bin/pqctoday-kmip.rs` — `clap`-parsed CLI; loads policy from `--policy-file`; opens store; binds TLS listener.

### Phase 8 — Compliance tool + KAT harness (1.5 PD)

- [ ] `compliance/profiles/*.yaml` — declarative profile definitions: list of (op, algorithm, expected_status) tuples.
- [ ] `compliance/src/profile.rs` — `serde_yaml` profile loader.
- [ ] `compliance/src/runner.rs` — async test runner: opens TLS connection to any KMIP 3.0 endpoint, executes profile expectations.
- [ ] `compliance/src/reporter.rs` — emit JSON + Markdown report (op × algorithm pass/fail matrix).
- [ ] `bin/pqctoday-kmip-compliance.rs` — CLI: `pqctoday-kmip-compliance --endpoint tls://localhost:9998 --profile full-v0.1 --output reports/`.
- [ ] `tests/kat_replay.rs` — `cargo test` integration replaying every `kat/ttlv-wire/` pair.
- [ ] `tests/acvp_roundtrip.rs` — NIST ACVP vectors drive Create + crypto op; assert byte-exact.

### Phase 9 — Audit log + reference CLI client + docs + labs (1.0 PD)

- [ ] `src/auditlog/mod.rs` — async JSONL writer; one line per plane-event per request; all entries share a `correlation_id`.
- [ ] `bin/pqctoday-kmip-client.rs` — `clap`-parsed CLI: `create / get / locate / activate / encrypt / decrypt / sign / verify / revoke / destroy / query / policy-test`. (The `encrypt` subcommand handles ML-KEM encapsulation transparently when the target key is an ML-KEM key; similarly `decrypt` for decapsulation.)
- [ ] All `docs/*.md` files per the layout in §4.

## 7. Phase-1 standalone validation gate

Phase 1 (the entire subsystem, standalone) is NOT complete until ALL of these are green:

- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] `cargo test --all --release` 100% pass.
- [ ] `cargo test --all --release -- --include-ignored` 100% pass (long-running KAT suites).
- [ ] Coverage ≥ 80% on `src/ops/`, `src/store/`, `src/policy/`, `src/codec/` (`cargo llvm-cov`).
- [ ] `kat/ttlv-wire/` byte-exact replay: every entry passes.
- [ ] NIST ACVP vectors: 100% pass across ML-KEM, ML-DSA, SLH-DSA, RSA, ECDSA, AES.
- [ ] Compliance tool reports 100% green on `baseline`, `pqc-kem`, `pqc-sig`, `classical-baseline`, `policy-enforcement` profiles against itself.
- [ ] License audit: `cargo deny check` shows zero BUSL deps; all transitives MIT / Apache-2.0 / BSD; report committed at `docs/LICENSE_AUDIT.md`.
- [ ] `pkcs11-mech-manifest.json` authority sha256 matches `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`.
- [ ] Reference CLI client successfully drives one round-trip per (op × algorithm) cell in §1.
- [ ] `docs/STANDALONE_VALIDATION.md` checklist file is checked-in with every box ticked + commit sha.
- [ ] Pedagogical readability gates: every op handler ≤ 100 LOC; every file ≤ 300 LOC (CI gate via `tools/check-loc.sh`).
- [ ] `cargo bench` baselines for ML-KEM-768 KEM encapsulation (via `C_EncapsulateKey`) + ML-DSA-65 Sign captured (not gated, just recorded for trend tracking).

## 8. Integration with `pqctoday-hsm` parent

- Standalone Cargo project (no parent workspace). Matches existing pattern (`rust/`, `openpgp/`, `openmls-provider/`).
- Path dependency on `../rust` (`softhsmrustv3`).
- Subsystem version follows `pqctoday-hsm` parent version (e.g. `pqctoday-hsm v0.5.0` ships kmip v0.1).
- `pqctoday-hsm/CHANGELOG.md` records every kmip subsystem change.
- Parent CI adds a `kmip` job: `cargo test --manifest-path kmip/Cargo.toml --all --release`.
- Dockerfile in `pqctoday-hsm/kmip/Dockerfile` is multi-stage; bundles the parent `softhsmrustv3` engine.

## 9. Out of scope (explicit non-goals)

| Item | Why out of scope |
|---|---|
| Full OASIS KMIP 3.0 conformance (1,452-test interop) | Validation/training tool, not a certified product |
| `Register` (import existing key) | Defer to v0.2 |
| `Wrap` / `Unwrap` (KMIP-level key wrapping) | Defer to v0.2 |
| `Re-key` (full lifecycle versioning) | Schema supports it; op handler defers to v0.2 |
| Web UI | Lives in `pqctoday-hub`, not here |
| Multi-tenancy / per-tenant slot isolation | Single-slot v0.1 |
| Replication / clustering / HA | Standalone single-process |
| KMIP-as-CA (cert issuance via Register Cert) | Out of scope |
| Standalone `pqctoday-kmip` repo on GitHub | Decided no — subsystem only |
| `ThalesGroup/kmip-go` dependency | Explicitly NOT used — Rust, no Go |
| `miekg/pkcs11` Go binding | Explicitly NOT used — no Go |
| `cryptoki` Rust PKCS#11 crate | Not needed — we depend on `softhsmrustv3` directly; `cryptoki` could be added in v0.2 for cross-vendor HSM testing |
| `cloudflare/circl` or any Go-native PQC crypto | Explicitly NOT used — single-provenance via `softhsmrustv3` |
| `oqs-provider` for OpenSSL | Explicitly NOT used — single-provenance |
| Fork of any KMIP library | Explicitly NOT done — codec written from scratch in Rust |

## 10. Effort breakdown

| Phase | Description | PD |
|---|---|---|
| 0 | Cargo project bootstrap + softhsmrustv3 probe | 0.5 |
| 1 | OASIS spec + KAT acquisition | 1.0 |
| 2 | TTLV codec (from scratch in Rust) | 2.0 |
| 3 | KMIP 3.0 extension layer + algo map | 1.0 |
| 4 | PKCS#11 bridge (trivial — direct dep) | 0.5 |
| 4.5 | Crypto Agility Management Plane / policy engine | 1.5 |
| 5 | Op handlers (11 ops; `encrypt`/`decrypt` each handle classical + ML-KEM via algorithm branch) | 2.0 |
| 6 | Object store + lifecycle FSM | 0.75 |
| 7 | Dispatcher + TLS server | 0.75 |
| 8 | Compliance tool + KAT harness | 1.5 |
| 9 | Audit + reference CLI + docs + labs | 1.0 |
| **Phase 1 standalone total** | | **12.5 PD** |
| 10 | Sandbox integration (Phase 2 / downstream) | 1.0 |
| **Grand total** | | **13.5 PD** |

(Was 12.5 PD with Go + codec dependency. Rust adds ~+2 PD for the from-scratch codec, gains ~−1 PD from eliminating the FFI boundary. Net +1 PD; bought memory safety + single-language stack.)

## 11. Risk register

| Risk | Mitigation |
|---|---|
| ~~`softhsmrustv3` may not yet expose `C_Encapsulate` / `C_Decapsulate`~~ | ✅ **Resolved 2026-06-04 probe:** v0.4.25 already exports `C_EncapsulateKey` (`rust/src/ffi.rs:1675`) + `C_DecapsulateKey` (`:1765`) per PKCS#11 v3.2 §5.18.8/§5.18.9. C++ engine same at `src/lib/SoftHSM_kem.cpp` §5.20. Note the correct names use the `Key` suffix. |
| Hand-written TTLV codec has encoding bugs | Heavy proptest in Phase 2; KAT replay in `tests/kat_replay.rs`; any bug surfaces against multiple vector pairs |
| OASIS KMIP 3.0 codepoint divergence from placeholders | Cross-reference during Phase 1; document divergences in `docs/KMIP_3_0_DELTA.md`; v0.1 sandbox-scope, not OASIS-certified |
| Rust edition 2024 may not stabilize before this slice ships | Parent repo already pins edition 2024 in `rust/Cargo.toml`; if 2024 issues arise, downgrade to 2021 (no code change required) |
| `rustls` `ring` backend may lack ML-DSA support for cert signing | If so, bootstrap the server cert with classical Ed25519 for v0.1; route ML-DSA listener cert through `softhsmrustv3` directly in v0.2 |
| Compliance tool's cross-vendor claim is unproven | Self-test only for v0.1; cross-vendor interop testing deferred to v0.2 |
| KAT vector provenance — TTLV-wire vectors derived from our own codec | Mark `provenance: codec-roundtrip` in manifest; cross-check by adding a Python `pykmip`-based fixture generator in v0.2 |
| 100-LOC-per-op-handler gate forces helper proliferation | Hard CI gate; prefer extracting helpers into `src/ops/_common.rs` over relaxing the gate |
| Policy YAML schema drift over time | `policies/SCHEMA.md` documents the v0.1 schema; loader validates against it; bump schema version + provide migration |

## 12. Status log

| Date | Note |
|---|---|
| 2026-06-03 | Plan written. **Language locked: Rust** (edition 2024) to match `pqctoday-hsm/rust/softhsmrustv3` engine. No Go anywhere. Direct path dependency on `../rust` eliminates the FFI boundary that the Go version required. TTLV codec written from scratch (~3500–5000 LOC, proptest-validated). Three-plane architecture preserved with Plane 1 = `src/policy/`, Plane 2 = `src/{codec,kmip30,dispatcher,ops,store,server,attrmap,auditlog}/`, Plane 3 = `src/pkcs11bridge/` (trivial wrapper around `softhsmrustv3`). Effort 12.5 → 13.5 PD net. |
| 2026-06-07 | **Phase 0 (Bootstrap) ✅ complete on branch `feat/kmip-subsystem`.** Cargo project initialized at `pqctoday-hsm/kmip/`: top-level `Cargo.toml` per §5, library `pqctoday_kmip` with all 11 plane modules declared as Phase-0 stubs (each `mod.rs` documents its target phase), three binaries (`pqctoday-kmip`, `pqctoday-kmip-client`, `pqctoday-kmip-compliance`) shipping as exit-1 placeholders, `error.rs` minimal stub. `pkcs11-mech-manifest.json` checked in with `authority.sha256 = 3f63146bca1a8bd1454ea8f80e59911886014aebcab082754dec8c46eb70ab58` (against `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`); six active codepoints `0x4032`–`0x4037` + fifteen reserved `0x4040`–`0x404E` for P0-ALGO-SURFACE. `cargo build` green in 24.32s after mirroring the `[patch.crates-io] fips204 / fips205` block from `openmls-provider/Cargo.toml` (Cargo's `[patch]` does not propagate via `path =` deps to standalone crates that consume `softhsmrustv3`). Empty Go-style `cmd/` + `internal/` directories from the pre-pivot scaffold removed. Sandbox-side `pqctoday-sandbox/tasks/p0-kmip-pqc-22-impl.md` (Go/Thales plan) superseded by a pointer to this file. Phase 1 next: most spec/KAT material already present from earlier scaffolding (only TTLV wire vectors and the JSON spec extraction remain). |
