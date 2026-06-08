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

### Phase 1 — Spec + KAT acquisition (1.0 PD) ✅ **COMPLETE 2026-06-07**

- [x] OASIS KMIP 3.0 spec PDF + HTML + sha256 present at `spec/oasis-kmip-3.0/`. **Spec-refresh audit:** pulled the 2024-08-23 republished HTML via `tools/download_kmip_spec.py`; HTML sha256 differs (`e593dad8…` → `4197ff90…`) but byte length and re-extracted content are equivalent (Word metadata churn, no spec changes). PDF is byte-identical. See [KMIP_3_0_DELTA.md](KMIP_3_0_DELTA.md) §8.
- [x] Rust HTML parser at [`tools/extract_kmip_spec.rs`](../tools/extract_kmip_spec.rs) walks the OASIS HTML and emits `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`. No LLM in the loop — pure `scraper`-based DOM walk. Run via `cargo run --bin extract-kmip-spec`. Extraction: 395 tags + 62 enums + 730 enum values. Cross-checked against all 102 KMIP 3.0 KAT XML cases: 100% tag-name coverage, 100% Operation enum coverage, all symbolic CryptographicAlgorithm names accounted for modulo trivial notation (`DES3` vs `3DES`, `HMAC_SHA256` vs `HMAC-SHA256`).
- [x] [`docs/KMIP_3_0_DELTA.md`](KMIP_3_0_DELTA.md) written documenting the pre-extraction draft codepoint correction (PQC algos were off by 7–20, with three direct collisions against SLH-DSA). The §6.3 placeholder JSON in this plan is now an obsolete historical artifact; Phase 3 codegen uses the extracted JSON as authority. (`src/kmip30/spec_source.json` is therefore NOT separately created; the extracted JSON IS the source-of-truth.)
- [x] OASIS KMIP 2.1 PDF present at `spec/oasis-kmip-2.1/kmip-spec-v2.1-os.pdf` for fallback reference (provided by earlier scaffolding).
- [x] NIST ACVP vectors present at `kat/{ml-kem,ml-dsa,slh-dsa}/*-acvp.json` (provided by earlier scaffolding).
- [x] Classical KAT present at `kat/{rsa,ecdsa,aes,hmac,sha}/*-acvp.json` (provided by earlier scaffolding).
- [x] Hand-crafted TTLV wire vectors landed at `kat/ttlv-wire/` via [`tools/gen_ttlv_kats.py`](../tools/gen_ttlv_kats.py). Six byte-exact golden vectors derived directly from OASIS KMIP 3.0 §9 (TTLV encoding rules) + the extracted §10 codepoints: Integer (BatchCount=1), Enumeration (Operation=Create), **PQC Enumeration (CryptographicAlgorithm=ML-KEM-768, codepoint 0x3a — first authoritative PQC KMIP TTLV vector for the platform; OASIS has not yet published PQC KAT, see [KMIP_3_0_DELTA.md §8](KMIP_3_0_DELTA.md))**, Boolean(true), padded TextString, nested Structure (ProtocolVersion=3.0). Indexed in `kat/ttlv-wire/manifest.json` with sha256 + hex-preview per vector. The generator's `--check` mode acts as a drift detector for CI.

### Phase 2 — TTLV codec (Plane 2 foundation) (2.0 PD) ✅ **COMPLETE 2026-06-07**

- [x] `src/codec/tag.rs` — `Tag` is a transparent `u32` newtype validated to 24 bits at construction (the OASIS tag space is `0x420000`–`0x4FFFFF`). 16 named constants for the tags used by the v0.1 op set; the codec accepts arbitrary in-range codepoints. Symbolic-name layer is intentionally narrow — kept that way so the OASIS registry isn't mirrored by hand.
- [x] `src/codec/value.rs` — `Value` enum with all 11 KMIP TTLV variants (Structure, Integer, LongInteger, BigInteger, Boolean, Enumeration, TextString, ByteString, DateTime, Interval, DateTimeExtended) and an `ItemType` byte enum matching §9.1.1. `TtlvFrame` carries `(Tag, Value)`.
- [x] `src/codec/encode.rs` — `encode(&TtlvFrame, &mut BytesMut)` and `encode_to_vec(&TtlvFrame) -> Vec<u8>`. Uses `BytesMut` write-then-patch for the length field. 8-byte zero-padding for every type except Structure (whose body is already aligned).
- [x] `src/codec/decode.rs` — `decode(&[u8]) -> Result<(TtlvFrame, usize), CodecError>` (and `decode_one`). Hand-rolled cursor-based decoder, no `nom`. Validates: unknown item-type byte, length mismatch for fixed-size types, non-zero padding bytes (§9.6 mandates zero pad), invalid Boolean values, non-UTF-8 TextString, structure depth limit (default 64).
- [x] `src/codec/tests.rs` — proptest round-trip at 256 cases per property: `decode(encode(v)) == v` for every Value variant including bounded-depth nested Structures, deterministic encoding, output length multiple of 8. Plus explicit Unicode, empty-byte-string, empty-structure, and max-depth round-trips.
- [x] `tests/kat_replay.rs` — replays every `kat/ttlv-wire/*.bin` byte-exact against `manifest.json`. Verifies on-disk sha256 matches the manifest (drift detector) and that decode/re-encode produces byte-identical output. **All 6 golden vectors pass, including the PQC vector** (`CryptographicAlgorithm = ML-KEM-768`, codepoint `0x3a`).

**Net new code: 1,252 LOC including tests** (estimate was 3,500–5,000 — leaner than expected; `bytes::BytesMut` write-patch pattern + hand-rolled decoder are concise).

**Test summary**: 30 lib tests pass (3 proptest round-trips × 256 cases = ~768 random round-trips), 2 KAT replay integration tests pass.

### Phase 3 — KMIP 3.0 extension layer + algo map (1.0 PD) ✅ **COMPLETE 2026-06-07**

- [x] `src/kmip30/algos.rs` — `KmipAlgorithm` enum with 25 variants (7 classical + 3 ML-KEM + 3 ML-DSA + 12 SLH-DSA). `to_wire_value` / `from_wire_value` round-trip the OASIS-extracted `CryptographicAlgorithm` enum codepoints. `to_pkcs11_mech(self, op: PkcsOp)` returns the right vendor or standard PKCS#11 mech based on the `(algorithm, operation)` pair — e.g. ML-DSA-65 + KeyGen → `CKM_PQCTODAY_ML_DSA_KEY_PAIR_GEN (0x4035)`, ML-DSA-65 + SignVerify → `CKM_PQCTODAY_ML_DSA_SIGN_VERIFY (0x4036)`. `manifest_consistency_test` pins the six vendor codepoints to `pkcs11-mech-manifest.json`'s `active.*` block.
- [x] `src/kmip30/attrs.rs` — `Attribute` enum (8 variants for the v0.1 op set: CryptographicAlgorithm, CryptographicLength, CryptographicUsageMask, ObjectType, State, UniqueIdentifier, Name, Custom). Plus `UsageMask` as a `bitflags!` flag set (21 flags from KMIP 3.0 §4), `ObjectType` enum (5 v0.1 variants), `State` lifecycle enum with `can_transition_to(next)` FSM enforcement, and `RevocationReason` for `Revoke` op.
- [x] `src/kmip30/ops.rs` — 12 op request/response struct pairs for the v0.1 set (Query, Create, CreateKeyPair, Get, Locate, Activate, Revoke, Destroy, Encrypt, Decrypt, Sign, SignatureVerify). `Operation` enum with `from_wire_value` / `to_wire_value`. `KeyBlock` + `KeyFormatType` for `Get` responses. `SignatureValidity` for `SignatureVerify` responses. `EncryptRequest` / `EncryptResponse` include `shared_secret: Option<Vec<u8>>` so ML-KEM encapsulation reuses the same struct (KMIP 3.0 design — no separate Encapsulate/Decapsulate ops).
- [x] Compile-time test: `KmipAlgorithm::to_pkcs11_mech` for every algorithm verified against the manifest. Plus 20 unit tests covering wire round-trips, FIPS-PQC classifier, ML-KEM encap/decap mech equality, ML-DSA not supporting Encrypt, ML-KEM not supporting Sign, AES dispatch, lifecycle FSM transitions, and OASIS-codepoint sanity checks for `Operation`.

**Net new code: 1,108 LOC** including tests (algos 432 + attrs 301 + ops 340 + mod 35).

**Test summary**: 50 lib tests pass (30 from Phase 2 codec + 20 new Phase 3); KAT replay still green.

**Net new dep**: `bitflags = "2"` for the `UsageMask` flag set.

### Phase 4 — PKCS#11 bridge (Plane 3 wrapper) (0.5 PD) ✅ **COMPLETE 2026-06-07**

**Note:** the plan called this "trivial — no FFI. Just `use softhsmrustv3;` and wrap session management." In practice softhsmrustv3 exposes the raw PKCS#11 v3.2 C ABI in Rust (`u32` handles, `*mut u8` buffers, `CK_RV` return codes — no `unsafe fn` annotations because the engine self-validates pointers). Phase 4 puts a safe Rust face on the session lifecycle so Phase 5 op handlers can write `let s = Session::open(slot, pin)?;` without thinking about pointer arithmetic.

- [x] `src/pkcs11bridge/mod.rs` — module wiring + public re-exports (`Session`, `BridgeError`, `CkRv`, `CKR_OK`, mechs).
- [x] `src/pkcs11bridge/error.rs` (152 LOC) — `BridgeError` enum mapping the named `CKR_*` classes Phase 5 cares about (`GeneralError`, `MechanismInvalid`, `ObjectHandleInvalid`, `TemplateError`, `SignatureInvalid`, `BufferTooSmall`, `SessionInvalid`, `ArgumentsBad`, `HostMemory`, `FunctionFailed`, `MechanismParamInvalid`, plus an `UnclassifiedCkr` catch-all). `from_ckr` is the `CK_RV → Result<()>` shim; `classify` maps known codepoints inline (no `softhsmrustv3::constants` import — codepoints are explicit at the place they're handled). The `CKR_SESSION_*` range is handled with one match arm covering `0x00B0..=0x00BC`.
- [x] `src/pkcs11bridge/session.rs` (199 LOC) — `Session` struct wrapping the engine's session handle. `open(slot, pin)` initialises the engine on first call (`Once`-guarded `C_Initialize` to avoid `CKR_CRYPTOKI_ALREADY_INITIALIZED`), opens an R/W user session, and logs in. `Drop` calls `C_CloseSession` and discards the return code (Drop cannot meaningfully signal failure). `handle()` exposes the raw `CK_SESSION_HANDLE` for Phase 5 op handlers that need it. `Session` is `!Send` deliberately via a `*const ()` PhantomData — the engine has thread-local state so handles cannot be moved between threads. Op-method bodies (sign / encapsulate / etc.) are intentionally NOT in this phase — they land in Phase 5 alongside the handlers that consume them.
- [x] `src/pkcs11bridge/mechs.rs` (55 LOC) — re-exports the FIPS-only mech constants from `crate::kmip30::algos` so the bridge has one mech table for the whole subsystem. `vendor_codepoints_match_manifest` test pins `0x4032`–`0x4037` to `pkcs11-mech-manifest.json` `active.*` (the same numbers Phase 3 already verified — drift detector at a second site catches consumer-side regressions).
- [x] Smoke test: `initialize_engine_round_trip` calls `softhsmrustv3::C_Initialize(null_mut)` and asserts the return code is either `CKR_OK` or `CKR_CRYPTOKI_ALREADY_INITIALIZED` (`0x0000_0191` — fine if another test in the binary already initialised the engine). The plan's broader smoke test (open session, ML-KEM-768 keygen, encap/decap round-trip, destroy) requires a fully-initialised softhsmv3 token, which is multi-step ceremony beyond Phase 4 scope; full end-to-end smoke testing belongs in Phase 7 once the TLS server can drive the whole stack.

**Net new code: 435 LOC** including tests (estimate 0.5 PD; matches).

**Test summary**: 58 lib tests pass (50 from Phase 2 + Phase 3 + 8 new Phase 4 — `BridgeError` mapping per CKR class, raw round-trip through classify, `Session` is `!Send`, engine initialise round-trip, flag constants match PKCS#11 v3.2 §11.6, vendor codepoints match the manifest). KAT replay still green.

### Phase 4.5 — Plane 1 Crypto Agility Management Plane / policy engine (1.5 PD) ✅ **COMPLETE 2026-06-07**

Implemented before op handlers (Phase 5) so handlers can call `policy::Engine::evaluate()`.

**Mid-phase reframe (user direction).** During implementation the user
escalated the scope from "10-rule policy gate" to "configurable crypto-
agility engine that demonstrates classical → PQC switch by editing YAML,
zero application changes." Three additions to the original plan:

1. **Two new rule types** — `algorithm_default` and `algorithm_substitution`
   (Pass-1 resolution rules) — let policies rewrite the request's algorithm
   before gating. Brings the rule count to 12.
2. **Two-pass evaluation semantics.** Pass 1: resolve algorithm (last
   match wins). Pass 2: gating (first deny wins). A substitution into a
   banned algorithm is denied at Pass 2 — no orphan rekey to a forbidden
   algorithm.
3. **`Decision::RekeyAndProceed`** — the third decision variant. KMIP 3.0
   has no native way to silently migrate an application from a classical
   key to a PQC key under the same handle. When a substitution rule fires
   against an existing object whose stored algorithm differs from the
   substituted value, the engine emits a rekey plan. Phase 5 implements
   the multi-op rekey transaction (generate new key → mark old as
   Deprecated → link via `x-pqctoday-supersedes` → re-issue the op).

**Hub UI integration.** [`PolicyStore`] exposes `list` / `load` /
`validate_draft` / `save` / `dry_run` — pure-library API the future Hub
scenario UI calls (HTTP or WASM, separate workstream). `dry_run` evaluates
a draft policy against a sample request side-effect-free so the UI can
show "what would this policy decide?" without persisting anything.

**Security-officer editability.** Validate-then-rename file saves
([`PolicyStore::save`] writes to a tempfile then atomic-renames). Atomic
in-memory policy swap ([`Engine::activate`]) — in-flight evaluations
observe either old or new, never partial. Every activation logged in
[`PolicyAudit`] with SHA-256 fingerprints of both prior and new YAML.

**No-policy default: deny-all.** Safe default when no policy is loaded
at startup. Sandbox must explicitly load `training-permissive.yaml`.

- [x] `src/policy/engine.rs`:

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

- [x] `src/policy/rule.rs` — `Rule` enum (12 variants — 10 original + `AlgorithmDefault` + `AlgorithmSubstitution`). Pass-1 (`resolve_pass1`) and Pass-2 (`check_pass2`) methods on each. `TimeBound` with custom serde for `"always"` or `"YYYY-MM-DD"`. `AttrPredicate` for `exception_custom_attribute` / `triggered_by_custom_attribute`.
- [x] `src/policy/loader.rs` — `serde_yaml`-based loader; schema validation; line/column error reporting; non-fatal warnings (`max_key_age_days` stub, `compliance_profile_gate` documentational note).
- [x] `src/policy/store.rs` — `PolicyStore` for filesystem CRUD: `list`, `load`, `validate_draft`, `save` (atomic), `dry_run`. Hub UI binds against these primitives.
- [x] `src/policy/audit.rs` — `PolicyAudit` in-memory ring of `PolicyActivated` / `Decision` / `RekeyPlanned` events with SHA-256 fingerprints. Phase 9 wires to SQLite for durable history.
- [ ] `src/policy/inventory.rs` — **deferred to Phase 6** (needs object store).
- [ ] `src/policy/report.rs` — **deferred to Phase 8** (compliance tool surface).
- [x] `policies/training-permissive.yaml` + 4 others (already shipped in Phase 0 scaffolding) — all parse + activate + behave as advertised under the new engine.
- [x] Unit tests per rule type covering positive + negative + boundary cases: 35 in `policy::*::tests`.
- [x] Integration: `tests/policy_demo_flows.rs` (6 tests) — KEM + signature + encryption flipped classical→PQC by policy edit, with the application helper unchanged across both halves.
- [x] Integration: `tests/policy_example_policies.rs` (8 tests) — every shipped policy parses, activates, and produces the expected verdict for representative KEM / signature / encryption requests.

**Test summary**: 109 tests pass (93 lib + 2 KAT replay + 6 demo flows + 8 example policies; 0 failed). Phase 4 surface (58 lib tests) preserved.

**Commit**: `feat/kmip-phase-4.5-policy-engine` branch; PR pending.

### Phase 5 — Op handlers (Plane 2) (2.0 PD) — ✅ **COMPLETE 2026-06-07** (12 of 12 ops + shared infra + active-policy persistence)

**Session 2 (this) — remaining 9 ops + shared helpers + Plane-1 active-policy persistence shipped:**

- [x] `src/ops/helpers.rs` — extracted before writing the new ops so all 12
      handlers share one surface for emit_request / emit_pkcs11 /
      emit_state_change / emit_success / fail_err / canonical_name /
      state_name. Each op file stays focused on its KMIP semantics.
- [x] `src/ops/activate.rs` — KMIP 3.0 §6.1.1 Activate (op 0x12).
- [x] `src/ops/revoke.rs` — KMIP 3.0 §6.1.49 Revoke (op 0x13). Branches on
      RevocationReason: KeyCompromise/CaCompromise → Compromised, else
      → Deactivated.
- [x] `src/ops/destroy.rs` — KMIP 3.0 §6.1.19 Destroy (op 0x14). PreActive
      | Deactivated → Destroyed; Compromised → DestroyedCompromised;
      Active rejected (must Revoke first per §3.4). C_DestroyObject.
- [x] `src/ops/create.rs` — KMIP 3.0 §6.1.8 Create (op 0x01) symmetric +
      secret data only; asymmetric rejected. C_GenerateKey.
- [x] `src/ops/get.rs` — KMIP 3.0 §6.1.23 Get (op 0x0a). Private-key
      material never extracted (CKA_SENSITIVE) — returns OpaqueObject
      with empty value. C_GetAttributeValue.
- [x] `src/ops/locate.rs` — KMIP 3.0 §6.1.32 Locate (op 0x08). Filters
      by CryptographicAlgorithm / ObjectType / State. C_FindObjects*.
- [x] `src/ops/signature_verify.rs` — KMIP 3.0 §6.1.61 (op 0x22). Failed
      verify is NOT a KMIP error — returns success with validity=Invalid.
      C_VerifyInit + C_Verify.
- [x] `src/ops/encrypt.rs` — KMIP 3.0 §6.1.21 Encrypt (op 0x1f). Branches:
      ML-KEM → C_EncapsulateKey (ciphertext + shared_secret); classical
      → C_EncryptInit + C_Encrypt (ciphertext only).
- [x] `src/ops/decrypt.rs` — KMIP 3.0 §6.1.15 Decrypt (op 0x20). Branches:
      ML-KEM → C_DecapsulateKey (shared secret); classical →
      C_DecryptInit + C_Decrypt (plaintext). Allowed in Active /
      Deactivated / Compromised (need to decrypt old ciphertexts post-rotation).
- [x] `src/policy/store.rs` — Plane-1 active-policy persistence (§12 user
      decision 2026-06-07). New `.active` marker file in the policies/
      directory, JSON shape `{ name, fingerprint, activated_at }`. API:
      `read_active`, `write_active` (atomic-rename), `clear_active`,
      `activate_with_engine` (load + activate + write marker as one),
      `resume_active` (boot-time replay with **fingerprint-drift
      protection** — refuses to silently re-activate a YAML edited
      out-of-band; operator must re-activate via Hub). Mirrors how
      softhsmv3 persists slot/token state so handles survive engine
      restarts — same pattern, one level up the stack.

**Test summary (Phase 5 cumulative):** 193 total pass (was 153 at start
of session; +40 across the 8 ops, helpers, and active-marker persistence
+ engine + tests). 0 failed. 50 ops-module tests across all 12 handlers;
13 store tests (4 prior + 9 new for active marker).

**Phase-7 wiring remaining (deferred per §12.7.7 lock):** All Plane-3
emissions today produce correct `Pkcs11Call` audit events (function
name, mechanism, slot) but use deterministic SHA-256 placeholders for
the actual cryptographic output. Phase 7 wires real
`softhsmrustv3::C_*` calls behind the same audit emissions — the wire
format committed in PR #72 + §12.7.5 doesn't change, only the bytes
inside `ciphertext` / `signature` / `shared_secret` become real instead
of placeholder.

**Session 1 (prior) — foundation + 3 demo-critical ops shipped on `feat/kmip-phase-5-op-handlers`:**

- [x] `src/error.rs` — `ResultReason` enum with codepoints cross-checked
      against `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (`Result Reason`):
      ItemNotFound (0x01), OperationNotSupported (0x05), MissingData (0x06),
      InvalidField (0x07), CryptographicFailure (0x0a), PermissionDenied
      (0x0c), ObjectArchived (0x0d), ObjectAlreadyExists (0x18),
      InvalidAttribute (0x2c), InvalidAttributeValue (0x2d). `KmipError`
      enum with typed constructors + `From<BridgeError>`.
- [x] `src/store/{traits,memory}.rs` — `KeyStore` trait (minimal surface
      for ops) + `MemoryStore` in-memory impl for Phase-5 tests.
      `ObjectRecord` carries uid + object_type + algorithm + usage_mask +
      state + pkcs11_cka_id + pkcs11_slot + timestamps + supersedes link.
      Phase 6 replaces `MemoryStore` with SQLite-backed durable store.
- [x] `src/ops/deps.rs` — `Deps` shared bundle: `engine`, `store`, `sink`,
      `config` (slot, pin, vendor identification, server version).
- [x] `src/ops/query.rs` — **KMIP 3.0 §6.1.45 Query** (op `0x18`).
      Returns supported operations / object types / server information.
      Phase-3 capability list (12 ops). PKCS#11 v3.2 §C.5.3 `C_GetInfo`
      not yet called — v0.1 uses static config.
- [x] `src/ops/create_key_pair.rs` — **KMIP 3.0 §6.1.11 Create Key Pair**
      (op `0x02`). Extracts `CryptographicAlgorithm` / `CryptographicLength`
      / `CryptographicUsageMask` from template attributes. Plane-1 engine
      gate; honours `algorithm_default` / `algorithm_substitution`. Maps
      `(KmipAlgorithm, PkcsOp::KeyGen) → CKM_*` via Phase-3 enum. Audit
      emits `KmipRequestReceived` → `Pkcs11Call(C_GenerateKeyPair)` →
      `KmipResponseSent`. Persists `PreActive` records for both public +
      private keys. PKCS#11 v3.2 §C.7.1 entry-point signature verified
      against `rust/src/ffi.rs::C_GenerateKeyPair`.
- [x] `src/ops/sign.rs` — **KMIP 3.0 §6.1.60 Sign** (op `0x21`). Store
      lookup → lifecycle gate (only `Active` per §3.4) → Plane-1 engine.
      Surfaces `Decision::RekeyAndProceed` as `PermissionDenied` with an
      actionable hint (`"rekey required: policy substitutes X → Y for
      UID Z"`); the actual multi-op rekey transaction belongs to Phase 6
      / dispatcher work. PKCS#11 v3.2 §C.6.5 `C_SignInit` + §C.6.6
      `C_Sign` signatures verified against `rust/src/ffi.rs`.

**Test summary (this session):** 150 total pass (121 lib + 29 integration;
0 failed). Added 16 ops tests + 4 store tests + 9 error tests = 29 new.

**Session 2+ — remaining 9 ops:** Activate, Create (sym), Decrypt, Destroy,
Encrypt (branches classical / ML-KEM encapsulate), Get, Locate, Revoke,
SignatureVerify. Same template — each ≤ ~250 LOC with KMIP 3.0 + PKCS#11
v3.2 spec citations in the file header.

**Known limitations carried to Phase 6:**

- `canonical_name(KmipAlgorithm)` returns bare names (`"ECDSA"`, `"RSA"`,
  `"AES"`) — no curve/size suffix. The Phase-5 store doesn't yet carry
  the `Cryptographic Parameters` attribute that would let the dispatcher
  produce `"ECDSA-P256"` / `"AES-256"`. Phase 6 closes this so policies
  can target sized algorithms.
- Bridge calls into `softhsmrustv3::C_*` are placeholder-audited but not
  actually executed (v0.1 produces deterministic SHA-256 signatures and
  UUID-derived CKA_IDs). Phase 7 (TLS server) wires the real session +
  bridge calls behind the audit emissions.

### Phase 5 — Op handlers (Plane 2) — original plan (2.0 PD)

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
| **NIST Round 3 alt / Round 4 algorithms (Falcon, HQC, BIKE, FrodoKEM, Classic McEliece, XMSS) — vendor mech codepoints `0x4040`–`0x404E`** | **Parked indefinitely per 2026-06-07 decision: focus stays on FIPS-certified mechanisms only.** v0.1 ships ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), HSS/LMS (NIST SP 800-208) — all already at vendor codepoints `0x4032`–`0x4037`. The `0x4040+` codepoints remain reserved in the mech allocation table and `pkcs11-mech-manifest.json` so they can be revisited later, but no roadmap commitment. P0-ALGO-SURFACE is not a KMIP dependency. |
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

## 12. Phase 10 — Dev sandbox integration (scoped 2026-06-07)

### 12.1 What the existing dev sandbox is (findings)

`pqctoday-sandbox` is **already a Docker dev workbench** where users run and modify crypto code in five languages against `libsofthsmv3.so`. Inventory verified by reading the actual code:

| Component | Path | What it does |
|---|---|---|
| **Multi-language samples** | [`samples/{py,c,cpp,rust,java}/`](../../pqctoday-sandbox/samples/) | 13 Python + 12 C + Rust + C++ + Java sample programs, each exercising one PKCS#11 v3.2 primitive (ML-DSA / ML-KEM / SLH-DSA / classical). Coverage matrix in [`samples/SAMPLES.md`](../../pqctoday-sandbox/samples/SAMPLES.md). |
| **HTTP API** | [`api/server.py`](../../pqctoday-sandbox/api/server.py), [`api/kms_router.py`](../../pqctoday-sandbox/api/kms_router.py) | Flask app exposing `/api/run/*` scenario endpoints + a PKCS#11-fronted REST surface. |
| **WebSocket terminal** | [`pyterm.py`](../../pqctoday-sandbox/pyterm.py) | ttyd-protocol-compatible PTY/tmux WebSocket server; users get an interactive shell inside the container via xterm.js. |
| **PKCS#11 spy log parser** | [`api/spy_parser.py`](../../pqctoday-sandbox/api/spy_parser.py) | Parses live `C_*` call traces into the Hub UI's telemetry stream. |
| **Hub embedding** | [`SandboxScenarioEmbed.tsx`](../../pqctoday-hub/src/components/Playground/SandboxScenarioEmbed.tsx) | Iframes the sandbox container (localhost:4000 or orchestrator-issued session); postMessage for theme/userId/scenarioId. |

**Plane coverage today vs needed:**

| Plane | Dev sandbox today | Phase 10 adds |
|---|---|---|
| **P3 — PKCS#11 HSM** (softhsmv3) | ✅ full — 5-language samples + spy logs visible | (unchanged) |
| **P2 — KMIP 3.0** | ❌ no KMIP server in the container | ✅ ship Rust `pqctoday-kmip` binary alongside softhsmv3 |
| **P1 — Crypto agility engine** | ❌ no policy layer | ✅ engine + dropdown-editable YAML policies, audit ring exposed via API |

**The pivot is therefore not "build a dev sandbox" — it's "extend the existing dev sandbox with the P1/P2 layers Phases 0–9 have been building."**

### 12.2 Deliverables (MVP, Python first)

| # | Deliverable | Path | Effort |
|---|---|---|---|
| 12.2.1 | Finish remaining 9 Rust ops (Phase 5b) + wire real softhsmrustv3 calls (short Phase 7) so the binary actually runs end-to-end | `pqctoday-hsm/kmip/src/ops/`, `src/pkcs11bridge/`, `src/server/` | 2.5 PD |
| 12.2.2 | Ship the Rust binary inside the sandbox Docker image | `pqctoday-sandbox/docker/Dockerfile.network`, `entrypoint.sh` | 0.25 PD |
| 12.2.3 | Add 10 `/api/kmip/*` proxy endpoints to the Flask API (§12.3) | `pqctoday-sandbox/api/server.py` | 0.5 PD |
| 12.2.4 | `kmip_client.py` Python helper (thin TTLV codec) + 4 sample programs (§12.4) | `pqctoday-sandbox/samples/py/kmip/` | 0.5 PD |
| 12.2.5 | Hub-side `AgilityScenarioPanel.tsx` — policy dropdown + Monaco YAML editor + tri-plane log viewer | `pqctoday-hub/src/components/Playground/` | 1.0 PD |
| 12.2.6 | End-to-end demo recording + lab-guide doc | `docs/labs/agility-scenario.md` | 0.25 PD |
| **MVP total** | | | **~5.0 PD** |

**Cross-language sample extension** (C / C++ / Rust / Java) parked at ~0.5 PD per language — pick up after the Python MVP demos cleanly.

### 12.3 New API endpoints in `api/server.py`

All under `/api/kmip/` prefix; thin proxy in front of the Rust binary's `PolicyStore` + audit surface.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/kmip/health` | KMIP server up? policy loaded? sink size? |
| GET | `/api/kmip/policy/list` | Names of YAML files in `policies/` dir (Hub dropdown source) |
| GET | `/api/kmip/policy/active` | `{ name, fingerprint, loaded_at }` |
| GET | `/api/kmip/policy/yaml?name=X` | Raw YAML body for editor display |
| PUT | `/api/kmip/policy/yaml?name=X` | Save edited YAML (`PolicyStore::save` — validate-then-atomic-rename) |
| POST | `/api/kmip/policy/activate` | Body `{ name }` → `Engine::activate` (atomic swap) |
| POST | `/api/kmip/policy/dry_run` | Body `{ yaml, sample_request }` → `Decision` JSON (editor "test" button) |
| GET | `/api/kmip/audit/tail` (SSE) | Stream of tri-plane `AuditEvent`s — one JSON per SSE event |
| GET | `/api/kmip/audit?correlation_id=X` | Full historical trace for one request |
| POST | `/api/kmip/audit/clear` | Reset in-memory ring for clean demo runs |

### 12.4 Sample subset (`samples/py/kmip/`)

Parallel to existing `samples/py/` PKCS#11-direct samples. Each ≤ 60 LOC + a shared `kmip_client.py` helper.

| # | File | Demonstrates | KMIP ops exercised |
|---|---|---|---|
| 1 | `kmip-01-create-keypair-sign.py` | Generate sig keypair via KMIP, sign a message, verify | CreateKeyPair, Sign, SignatureVerify |
| 2 | `kmip-02-create-keypair-kem.py` | Generate KEM keypair, encapsulate, decapsulate | CreateKeyPair, Encrypt (encap), Decrypt (decap) |
| 3 | `kmip-03-create-key-encrypt.py` | Generate AES key, encrypt + decrypt a blob | Create, Encrypt, Decrypt |
| 4 | `kmip-04-rekey-on-policy-flip.py` | Create classical key → flip policy → next Sign auto-rekeys to PQC | CreateKeyPair, Sign (twice, with policy edit between) |

Sample #4 is the headline demo: user runs script, flips policy dropdown in Hub, runs script again, observes engine emitting `RekeyAndProceed` and the second Sign producing an ML-DSA signature under the same Python code.

### 12.5 Hub-side panel (`AgilityScenarioPanel.tsx`)

New component **in the same tab as** the existing `SandboxScenarioEmbed`
(per locked decision §12.7.6). The two panels share one viewport — the
existing iframe + terminal occupy the upper / left region, the agility
panel occupies the lower / right region; exact split is responsive.
Layout of the agility panel itself:

```text
┌────────────────────────────────────────────────────────────────────┐
│  Policy: [classical ▼]  [Edit YAML]  [Activate]   • active:pqc     │
├────────────────────────────────┬───────────────────────────────────┤
│   ╔══════════════════════════╗ │  Plane 1 — Agility engine          │
│   ║  Monaco YAML editor      ║ ├───────────────────────────────────┤
│   ║  (GET /api/kmip/yaml)    ║ │  Plane 2 — KMIP dispatcher         │
│   ╚══════════════════════════╝ ├───────────────────────────────────┤
│                                │  Plane 3 — PKCS#11 HSM             │
└────────────────────────────────┴───────────────────────────────────┘
```

Behavioural pieces (each ≤ ~150 LOC):
- **Policy dropdown** — `useEffect` on mount → `GET /api/kmip/policy/list`; on change → `POST /api/kmip/policy/activate`
- **YAML editor** — Monaco wired to `GET/PUT /api/kmip/policy/yaml?name=X`; Activate button → `POST /activate`
- **Tri-plane log panes** — three stacked panels; each `EventSource('/api/kmip/audit/tail')` filtered by `plane: "p1"|"p2"|"p3"`; rows render with timestamp + summary + click-to-expand JSON
- **Correlation highlight** — clicking any row dims everything except matching `correlation_id` across all three panes (the "see one request flow through all three layers" moment)

### 12.6 Sandbox container changes

`Dockerfile.network` additions:

1. Multi-stage build the Rust KMIP binary (`cargo build --release --bin pqctoday-kmip`).
2. Copy binary + `policies/*.yaml` into the runtime image.
3. Start KMIP server in `entrypoint.sh` alongside softhsmv3 init — listens on `127.0.0.1:5696` (standard KMIP port), reads policies from `/etc/pqctoday/policies/` (host-mounted volume), writes audit JSONL to `/var/log/pqctoday/audit.jsonl` via `CompositeSink(RingSink, JsonlSink)`.

### 12.7 Locked decisions

| # | Decision | Choice | Reason |
|---|---|---|---|
| 12.7.1 | KMIP wire transport for samples | Raw TTLV over local TCP via a thin `kmip_client.py` helper | No third-party dep; honest about being a KMIP client; portable to a real KMS later. |
| 12.7.2 | Server bind | TCP `localhost:5696` (KMIP IANA port) | Standard; samples port to a real KMS unchanged. |
| 12.7.3 | Container topology | Single container — KMIP server + softhsmv3 + Flask API + ttyd in the same image | Simpler MVP; sidecar split later if needed. |
| 12.7.4 | Policy YAML location | Host-mounted volume at `/etc/pqctoday/policies/` | Users edit + persist without rebuild. |
| 12.7.5 | Audit storage | `CompositeSink(RingSink(16_384), JsonlSink("/var/log/pqctoday/audit.jsonl"))` | Hub UI tails the ring; JSONL accumulates durable forensics. Both supported by PR #72. |
| 12.7.6 | Hub UX | **Single-tab split panel** — the existing `SandboxScenarioEmbed` (iframe + terminal) shares one tab with the new `AgilityScenarioPanel` (policy editor + tri-plane log viewer). The two panels sit side-by-side (or stacked vertically depending on viewport). | User decision 2026-06-07: agility view is part of the same scenario, not a parallel one. One tab, one mental model. |
| 12.7.7 | Real softhsmrustv3 wiring | Required before MVP ships — placeholder Plane-3 events lie to the user | Forces completion of Phase 5b + a short Phase 7 binding the bridge. |

### 12.8 Sequencing constraint

§12.2.1 blocks §12.2.4 (samples need real ops). Everything else can parallelise. Three PRs:

1. **PR A** (this repo) — Phase 5b + short Phase 7 (the binary actually runs).
2. **PR B** (`pqctoday-sandbox`) — Dockerfile + API endpoints + Python samples.
3. **PR C** (`pqctoday-hub`) — `AgilityScenarioPanel.tsx`.

## 13. Status log

| Date | Note |
|---|---|
| 2026-06-03 | Plan written. **Language locked: Rust** (edition 2024) to match `pqctoday-hsm/rust/softhsmrustv3` engine. No Go anywhere. Direct path dependency on `../rust` eliminates the FFI boundary that the Go version required. TTLV codec written from scratch (~3500–5000 LOC, proptest-validated). Three-plane architecture preserved with Plane 1 = `src/policy/`, Plane 2 = `src/{codec,kmip30,dispatcher,ops,store,server,attrmap,auditlog}/`, Plane 3 = `src/pkcs11bridge/` (trivial wrapper around `softhsmrustv3`). Effort 12.5 → 13.5 PD net. |
| 2026-06-07 | **Phase 0 (Bootstrap) ✅ complete on branch `feat/kmip-subsystem`.** Cargo project initialized at `pqctoday-hsm/kmip/`: top-level `Cargo.toml` per §5, library `pqctoday_kmip` with all 11 plane modules declared as Phase-0 stubs (each `mod.rs` documents its target phase), three binaries (`pqctoday-kmip`, `pqctoday-kmip-client`, `pqctoday-kmip-compliance`) shipping as exit-1 placeholders, `error.rs` minimal stub. `pkcs11-mech-manifest.json` checked in with `authority.sha256 = 3f63146bca1a8bd1454ea8f80e59911886014aebcab082754dec8c46eb70ab58` (against `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`); six active codepoints `0x4032`–`0x4037` + fifteen reserved `0x4040`–`0x404E` for P0-ALGO-SURFACE. `cargo build` green in 24.32s after mirroring the `[patch.crates-io] fips204 / fips205` block from `openmls-provider/Cargo.toml` (Cargo's `[patch]` does not propagate via `path =` deps to standalone crates that consume `softhsmrustv3`). Empty Go-style `cmd/` + `internal/` directories from the pre-pivot scaffold removed. Sandbox-side `pqctoday-sandbox/tasks/p0-kmip-pqc-22-impl.md` (Go/Thales plan) superseded by a pointer to this file. Phase 1 next: most spec/KAT material already present from earlier scaffolding (only TTLV wire vectors and the JSON spec extraction remain). |
| 2026-06-07 | **Workflow decisions locked in (apply to all remaining phases).** (1) **PR strategy:** per-phase child branches off `feat/kmip-subsystem` (e.g. `feat/kmip-phase-2-codec`), one PR per phase merged into the feature branch; the feature branch itself merges to `main` only when Phase 9 + the §7 standalone validation gate is fully green. (2) **Cadence:** one phase per session. (3) **File-size soft target:** plan's ≤100 LOC per file is a guideline, not a hard cap — split when natural, exceed when cohesion suffers. (4) **Algorithm scope:** FIPS-certified only (ML-KEM, ML-DSA, SLH-DSA, HSS/LMS at `0x4032`–`0x4037`); Round 3 alt + Round 4 candidates parked indefinitely (see §9). (5) **Plane 1 policy engine (Phase 4.5):** ship all 10 rule types in v0.1 — no MVP subset. (6) **Compliance tool (Phase 8):** ship all 5 profiles in v0.1 (`baseline`, `pqc-kem`, `pqc-sig`, `classical-baseline`, `policy-enforcement`). |
| 2026-06-07 | **Phase 1 (Spec + KAT acquisition) ✅ complete.** Net new: (1) Rust HTML parser at [`tools/extract_kmip_spec.rs`](../tools/extract_kmip_spec.rs) (scraper-based DOM walk, no LLM). First extraction produced 395 tags / 62 enums / 730 enum values into `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`. (2) [`docs/KMIP_3_0_DELTA.md`](KMIP_3_0_DELTA.md) documenting the pre-extraction draft PQC-codepoint correction (off by 7–20; three direct collisions against SLH-DSA), the 100% KMIP 3.0 KAT cross-check, and the upstream-OASIS audit (spec republished 2024-08-23 but byte-equivalent content; test corpus unchanged since 2023-11-30; no OASIS-published PQC KAT exists). (3) Bot-aware spec downloader at [`tools/download_kmip_spec.py`](../tools/download_kmip_spec.py) (template: `pqctoday-priv/patents/download_patents.py` — urllib + Chrome UA + magic-byte validation + sha256 sidecar + polite rate-limit). (4) Six hand-crafted TTLV wire vectors at [`kat/ttlv-wire/`](../kat/ttlv-wire/) via [`tools/gen_ttlv_kats.py`](../tools/gen_ttlv_kats.py), indexed in `kat/ttlv-wire/manifest.json` — including the platform's first PQC TTLV vector (`CryptographicAlgorithm=ML-KEM-768` at OASIS-authoritative codepoint `0x3a`). Generator's `--check` mode acts as CI drift detector. `cargo build` green; Phase 2 (TTLV codec, ~2.0 PD, ~3,500–5,000 LOC) can begin against these vectors. |
| 2026-06-07 | **Phase 2 (TTLV codec) ✅ complete on branch `feat/kmip-phase-2-codec`.** 1,252 LOC across `src/codec/{mod,tag,value,encode,decode,tests}.rs` + `tests/kat_replay.rs` — significantly leaner than the 3,500–5,000 estimate (the `bytes::BytesMut` write-then-patch pattern + a `Tag` newtype rather than a 395-variant enum + a hand-rolled cursor decoder are concise). Test summary: 30 lib tests pass including 3 proptest round-trips at 256 cases each (~768 random round-trips total) — `decode(encode(v)) == v` proven for every `Value` variant; deterministic encoding; output length always a multiple of 8. 2 KAT-replay integration tests pass — every byte-exact vector in `kat/ttlv-wire/*.bin` decodes + re-encodes to the same bytes, including the PQC vector `03-enum-cryptographic-algorithm-ml-kem-768.bin` (codepoint `0x3a`). The codec validates: unknown item-type bytes, length mismatches for fixed-size types, non-zero padding bytes (§9.6 spec requirement), invalid Boolean encodings, non-UTF-8 TextString, structure depth exceeding `MAX_STRUCTURE_DEPTH = 64` (defensive cap against adversarial input). `bytes = "1"` added as a regular dep. Phase 3 (KMIP 3.0 extension layer + algo map) can begin against this codec. |
| 2026-06-07 | **Phase 3 (KMIP 3.0 extension layer) ✅ complete on branch `feat/kmip-phase-3-extension`.** 1,108 LOC across `src/kmip30/{mod,algos,attrs,ops}.rs`. **algos.rs** (432 LOC): `KmipAlgorithm` enum with 25 variants (7 classical AES/RSA/ECDSA/HMAC + 18 FIPS PQC ML-KEM/ML-DSA/SLH-DSA-{SHA2,SHAKE} per the FIPS-only workflow decision); `to_wire_value`/`from_wire_value` map to OASIS-extracted §10.2.6 codepoints (ML-KEM-768=`0x3a`, ML-DSA-65=`0x3d`, etc.); `to_pkcs11_mech(self, PkcsOp)` returns the right vendor or standard mech based on the `(algorithm, op)` pair; `manifest_consistency_test` pins the six `0x4032`–`0x4037` vendor codepoints to `pkcs11-mech-manifest.json` `active.*` block (so any drift between the consumer table and the authoritative manifest is caught at test time). **attrs.rs** (301 LOC): `Attribute` enum (8 variants for v0.1), `UsageMask` bitflags (21 KMIP 3.0 §4 flags), `ObjectType` (5 variants), `State` lifecycle enum with `can_transition_to(next)` FSM enforcement, `RevocationReason` for the Revoke op. **ops.rs** (340 LOC): `Operation` enum + 12 request/response struct pairs covering the v0.1 op set (Query, Create, CreateKeyPair, Get, Locate, Activate, Revoke, Destroy, Encrypt, Decrypt, Sign, SignatureVerify). `EncryptRequest`/`EncryptResponse` carry `shared_secret: Option<Vec<u8>>` so ML-KEM encapsulation reuses the same struct (KMIP 3.0 design — no separate Encapsulate/Decapsulate ops; handler branches on key algorithm). Test summary: 50 lib tests pass (30 from Phase 2 + 20 new) — includes wire round-trips for every algorithm variant, FIPS-PQC classifier, ML-KEM encap/decap mech equality, ML-DSA rejecting Encrypt + ML-KEM rejecting Sign, lifecycle FSM transition table, OASIS Operation codepoint sanity checks. KAT replay still green. `bitflags = "2"` added as a regular dep. Phase 4 (trivial PKCS#11 bridge — `use softhsmrustv3` + session wrappers) can begin against this typed surface. |

| 2026-06-07 | **Phase 4 (PKCS#11 bridge) ✅ complete on branch `feat/kmip-phase-4-pkcs11bridge`.** 435 LOC across `src/pkcs11bridge/{mod,error,mechs,session}.rs`. Plan called it "trivial — no FFI"; in practice softhsmrustv3 exposes the raw PKCS#11 v3.2 C ABI (`u32` handles, `*mut u8` buffers, `CK_RV` return codes — no `unsafe fn` annotations because the engine self-validates pointers). Phase 4 puts a safe Rust face on the session lifecycle. **error.rs** (152 LOC): `BridgeError` enum mapping named `CKR_*` classes Phase 5 cares about (GeneralError, MechanismInvalid, ObjectHandleInvalid, TemplateError, SignatureInvalid, BufferTooSmall, SessionInvalid range `0x00B0..=0x00BC`, ArgumentsBad, HostMemory, FunctionFailed, MechanismParamInvalid, UnclassifiedCkr catch-all). **session.rs** (199 LOC): `Session` struct with RAII Drop calling `C_CloseSession`. `open(slot, pin)` initialises the engine on first call (`Once`-guarded `C_Initialize` to avoid `CKR_CRYPTOKI_ALREADY_INITIALIZED`), opens an R/W user session, logs in as `CKU_USER`. `Session: !Send` deliberately via `*const ()` PhantomData — the engine has thread-local state. Op-method bodies (sign/encapsulate/etc.) intentionally NOT in this phase — Phase 5 wires them up alongside their handlers. **mechs.rs** (55 LOC): re-exports the FIPS-only mech constants from `crate::kmip30::algos` so the bridge has one mech table for the whole subsystem; second drift detector against the manifest. **Smoke test**: `initialize_engine_round_trip` calls `softhsmrustv3::C_Initialize(null_mut)` and accepts `CKR_OK` or `CKR_CRYPTOKI_ALREADY_INITIALIZED`. The plan's broader smoke test (open session, ML-KEM-768 keygen, encap/decap, destroy) requires a fully-initialised softhsmv3 token; end-to-end smoke belongs in Phase 7 when the TLS server can drive the whole stack. Test summary: 58 lib tests pass (50 prior + 8 new) — error mapping per CKR class, raw round-trip through classify, Session is !Send, engine initialise round-trip, flag constants match PKCS#11 v3.2 §11.6, vendor codepoints match the manifest. KAT replay still green. Phase 4.5 (Plane 1 policy engine) can begin against this bridge. |
| 2026-06-07 | **Phase 10 (Dev sandbox integration) scoped — see §12.** Initially confused this with "build a dev sandbox from scratch"; corrected after reading the actual `pqctoday-sandbox` code. **Finding:** the dev sandbox is already a substantial multi-language Docker workbench (5-language samples + ttyd PTY shell + Flask API + Hub iframe embed) — what's missing is only the Plane 1 (agility engine) + Plane 2 (KMIP) layers Phases 0–9 have been building. Phase 10 wires those in: ship the Rust `pqctoday-kmip` binary inside the sandbox container, add 10 `/api/kmip/*` proxy endpoints, ship 4 Python samples + a tiny `kmip_client.py` TTLV helper, and add a Hub-side `AgilityScenarioPanel.tsx`. **MVP effort: ~5.0 PD across three PRs** (Phase 5b+short Phase 7 in this repo; container + API + samples in `pqctoday-sandbox`; agility panel in `pqctoday-hub`). **Locked decisions:** (13.7.1) raw TTLV over local TCP, no pykmip dep; (13.7.2) bind on standard KMIP IANA port 5696; (13.7.3) single container; (13.7.4) policies host-mounted; (13.7.5) `CompositeSink(RingSink, JsonlSink)`; (13.7.6) **single-tab split panel** alongside the existing `SandboxScenarioEmbed` (user override of my recommendation — agility is part of the same scenario, not a parallel one); (13.7.7) real softhsmrustv3 wiring required before MVP ships (no placeholder Plane-3 events in production). Cross-language sample extension (C / C++ / Rust / Java) parked at ~0.5 PD per language after the Python MVP demos cleanly. |
