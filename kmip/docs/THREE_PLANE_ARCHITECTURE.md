# Three-Plane Architecture — Crypto Agility / KMIP / PKCS#11

The architectural lodestar for the `pqctoday-hsm/kmip/` subsystem and, by extension, the entire `pqctoday-hsm` platform when consumed by KMIP-aware applications.

Every design choice in the subsystem MUST map cleanly to exactly one of these three planes. If a feature spans planes, the implementation MUST respect the plane boundaries (no shortcuts).

## 1. The model

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Application / Training Lab                         │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ Business request
                                   │ ("sign this document", "encrypt this payload")
                                   ▼
╔═════════════════════════════════════════════════════════════════════╗
║  Plane 1 — Crypto Agility Management Plane                          ║
║  Role:    Policy + governance                                       ║
║  Standard: Our policy model (YAML/JSON, OPA-style; not standardised)║
║  Question answered: "What crypto is ALLOWED?"                       ║
╠═════════════════════════════════════════════════════════════════════╣
║  - Algorithm allowlist / denylist                                   ║
║  - PQC migration roadmap rules                                      ║
║  - Hybrid-mode requirements                                         ║
║  - Approval workflows / exceptions                                  ║
║  - Compliance mapping (FIPS, NIS2, CNSA, ANSSI, BSI, …)             ║
║  - Audit + reporting                                                ║
║  - Inventory + drift detection                                      ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │ Policy decision: ALLOW + algo selection
                                   │ ("use ML-DSA-65, no fallback")
                                   ▼
╔═════════════════════════════════════════════════════════════════════╗
║  Plane 2 — KMIP 3.0 Key Management Plane                            ║
║  Role:    Lifecycle + interoperability                              ║
║  Standard: OASIS KMIP 2.1 / 3.0                                     ║
║  Question answered: "WHERE are keys, what are their ATTRIBUTES,     ║
║                     what OPERATIONS are allowed?"                   ║
╠═════════════════════════════════════════════════════════════════════╣
║  - Create / Register / Locate / Get / Destroy                       ║
║  - CryptographicAlgorithm, CryptographicLength, UsageMask attrs     ║
║  - Lifecycle FSM (PreActive→Active→Deactivated→Compromised→Destroyed)║
║  - Encapsulate / Decapsulate (KMIP 3.0 NEW)                         ║
║  - Sign / SignatureVerify / Encrypt / Decrypt                       ║
║  - Cross-vendor interop (third-party KMS clients can talk to us)    ║
║  - Audit log of KMIP operations                                     ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │ KMIP operation dispatched to a specific key
                                   │ (UID → PKCS#11 stable CKA_ID lookup)
                                   ▼
╔═════════════════════════════════════════════════════════════════════╗
║  Plane 3 — PKCS#11 Crypto Execution Plane                           ║
║  Role:    Mechanism execution against a token / HSM / provider      ║
║  Standard: OASIS PKCS#11 v3.2 (+ pqctoday-hsm vendor mechs)         ║
║  Question answered: "Can this TOKEN execute this MECHANISM with     ║
║                     this KEY HANDLE?"                               ║
╠═════════════════════════════════════════════════════════════════════╣
║  - C_GenerateKey / C_GenerateKeyPair                                ║
║  - C_Sign / C_Verify                                                ║
║  - C_Encrypt / C_Decrypt                                            ║
║  - C_Encapsulate / C_Decapsulate (PKCS#11 v3.2)                     ║
║  - C_DeriveKey / C_WrapKey / C_UnwrapKey                            ║
║  - Vendor mechs 0x4030–0x404F (ML-KEM, ML-DSA, SLH-DSA, HSS,        ║
║    Falcon, HQC, BIKE, FrodoKEM, Classic McEliece, XMSS)             ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │ FFI: CGO → C++ engine
                                   │  or  cbindgen → Rust engine
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  pqctoday-hsm core PKCS#11 library                                  │
│  (C++ softhsmv3 engine + Rust engine — same vendor mech surface)    │
└─────────────────────────────────────────────────────────────────────┘
```

## 2. The three planes side-by-side

| Plane | Role | Standard / Interface | Question answered | Owns |
|---|---|---|---|---|
| **1. Crypto Agility Management Plane** | Define policy, inventory, migration, approval rules | Our policy model (YAML/JSON; dashboard); not a standardised protocol | **"What crypto is allowed?"** | Policy engine, rule types, compliance mapping, exception handling, drift reporting |
| **2. KMIP 3.0 Key Management Plane** | Manage keys and crypto objects across KMS / HSM systems | OASIS KMIP 2.1 / 3.0 | **"Where are keys, what are their attributes, what operations are allowed?"** | Object model, lifecycle FSM, attribute storage, KMIP operation set, TLS+TTLV protocol surface |
| **3. PKCS#11 Crypto Execution Plane** | Execute cryptographic operations inside a token / HSM / provider | OASIS PKCS#11 v3.x | **"Perform this crypto operation with this key."** | `C_*` calls, mechanism IDs, attribute templates, session management, key material |

## 3. Plane boundary rules (NON-NEGOTIABLE)

| Rule | Why it matters |
|---|---|
| **R1.** Plane 1 NEVER calls Plane 3 directly. | Policy decisions must flow through KMIP's object model so they are interoperable, auditable, and not coupled to a specific HSM. |
| **R2.** Plane 2 NEVER embeds policy logic. | KMIP ops are mechanically deterministic. "Is this allowed?" is a Plane 1 question. KMIP just enforces what Plane 1 decided. |
| **R3.** Plane 3 NEVER knows about KMIP UIDs. | PKCS#11 deals in handles and `CKA_ID`. The UID → CKA_ID mapping lives in Plane 2's persistence layer. |
| **R4.** Plane 3 NEVER knows about policy. | The HSM executes what it's asked. Policy rejection happens at Plane 1 before the request reaches Plane 3. |
| **R5.** Plane 1 outputs ARE Plane 2 inputs. | A policy decision is "ALLOW + algorithm choice + attribute requirements." Plane 2 takes those as KMIP attributes when invoking ops. |
| **R6.** Plane 2 outputs ARE Plane 3 inputs. | A KMIP op resolves to one or more PKCS#11 calls. The translation happens in Plane 2's op handlers. |
| **R7.** Audit spans all three planes. | Every request gets logged at each plane (policy decision, KMIP op, PKCS#11 calls) for full forensic traceability. |

## 4. Mapping to our subsystem layout

| Plane | Subsystem location | Files |
|---|---|---|
| 1. Crypto Agility | `internal/policy/`, `policies/*.yaml` | `engine.go`, `rules.go`, `loader.go`, `report.go` |
| 2. KMIP | `internal/server/`, `internal/codec/`, `internal/kmip30/`, `internal/dispatcher/`, `internal/ops/`, `internal/store/`, `internal/attrmap/`, `internal/auditlog/` | All KMIP protocol + lifecycle + storage code |
| 3. PKCS#11 | `internal/pkcs11bridge/` | FFI to parent repo's C++ + Rust engines |

External (not in this subsystem):

- **Plane 3 implementations** live in `pqctoday-hsm/src/` (C++) and `pqctoday-hsm/rust/` (Rust). The subsystem only WRAPS them.
- **Plane 1 dashboards / UIs** live in `pqctoday-hub/` and are out of scope for this subsystem (the subsystem only provides the policy engine + API; visualisation is downstream).

## 5. Example end-to-end flow

A training-lab application asks: *"Sign this document."*

```
Application:
  POST /sign  { document: "...", purpose: "production-release" }
     │
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Plane 1 — Crypto Agility                                           │
│  Loaded policy: policies/pqc-migration-2030.yaml                    │
│  Rule:    "purpose=production-release requires ML-DSA-65            │
│            or composite ML-DSA-65+Ed25519 after 2026-01-01"         │
│  Decision: ALLOW, algorithm = ML-DSA-65, usage = Sign                │
│  Audit:   policy_decision_id = p-7f3a..., rule = pqc-mig-2030       │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Plane 2 — KMIP                                                     │
│  1. Locate(CryptographicAlgorithm=ML-DSA-65,                        │
│            State=Active,                                            │
│            Tag=production-signer)                                   │
│     → returns UID urn:pqctoday:obj:abc-123                          │
│  2. Sign(UID=urn:pqctoday:obj:abc-123,                              │
│          Data=<document-hash>)                                      │
│     → returns Signature bytes                                       │
│  Persistence: SELECT pkcs11_cka_id, state                           │
│               FROM objects WHERE uid='urn:...'                      │
│  Audit:       kmip_op_id = k-9e1c..., uid = urn:..., op = Sign      │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Plane 3 — PKCS#11                                                  │
│  C_OpenSession(slot=0)                                              │
│  C_Login(USER, "1234")                                              │
│  C_FindObjectsInit(template={CKA_ID = <blob from Plane 2>})         │
│  C_FindObjects() → handle = 12345                                   │
│  C_SignInit(handle, mech=CKM_PQCTODAY_ML_DSA_SIGN_VERIFY[0x4036])   │
│  C_Sign(<document-hash>) → signature bytes                          │
│  C_CloseSession()                                                   │
│  Audit:  pkcs11_call_id = c-2d4f..., mech = 0x4036                  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
Application receives the signature.
Audit log retains three correlated entries (policy / KMIP / PKCS#11)
for the single request.
```

## 6. What changes if the policy changes

Suppose tomorrow the operations team tightens the policy:

```yaml
# policies/pqc-migration-2030.yaml (updated)
signing:
  preferred: composite-ml-dsa-65-ed25519   # was: ml-dsa-65
  required_after: 2026-12-01
```

Then:

- **Plane 1** loads the new policy. All future signing requests get the composite algorithm choice.
- **Plane 2** receives `Sign` requests addressed to a composite key UID. KMIP op handler dispatches a dual-mechanism PKCS#11 invocation.
- **Plane 3** executes both mechanisms (`CKM_PQCTODAY_ML_DSA_SIGN_VERIFY` AND `CKM_EDDSA`), concatenates per LAMPS draft-19.

**The application doesn't change.** That is crypto agility delivered by the three-plane separation.

## 7. Why this is a strong product story

1. **Each plane is industry-standardised** (KMIP, PKCS#11) or **clearly customer-owned** (the policy plane). No fuzzy middle.
2. **Each plane is independently testable** — policy unit tests, KMIP compliance tests, PKCS#11 mechanism tests.
3. **Each plane is independently observable** — three distinct audit streams that correlate via request ID.
4. **Each plane has a clear customer-facing message:**
   - "Our policy plane lets you encode your PQC migration roadmap as YAML."
   - "Our KMIP plane is OASIS-conformant — your existing KMS clients work."
   - "Our PKCS#11 plane runs in hardware-equivalent HSM mode — keys never leave the token."
5. **Each plane is independently swappable** — a customer can plug in their own policy engine (e.g. drive Plane 1 from OPA), keep our Plane 2 + 3; or use a different HSM in Plane 3 while keeping our Plane 1 + 2.

## 8. Key terminology lock-in

When discussing the subsystem internally or with customers, always use these terms:

- **Crypto Agility Management Plane** (not "policy layer", not "governance layer")
- **KMIP 3.0 Key Management Plane** (not "the KMIP layer", not "the protocol layer")
- **PKCS#11 Crypto Execution Plane** (not "the HSM layer", not "the backend")

Layer-numbering convention: **Plane 1 / Plane 2 / Plane 3** (top-to-bottom).

Direction terminology:

- Requests flow **down** the planes (Application → Plane 1 → Plane 2 → Plane 3 → token).
- Responses flow **up** the planes.
- Audit events flow **out** to a shared collector from each plane.

## 9. References

- OASIS KMIP 2.1 specification: `spec/oasis-kmip-2.1/`
- OASIS KMIP 3.0 specification: `spec/oasis-kmip-3.0/`
- OASIS PKCS#11 v3.2 specification: `spec/oasis-pkcs11-3.2/`
- pqctoday-hsm PKCS#11 vendor mechanism allocation: [`pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`](../../../../pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md)
- This subsystem's implementation plan: [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)
- Subsystem boundary doc: [`SUBSYSTEM_BOUNDARY.md`](SUBSYSTEM_BOUNDARY.md)

## 10. Status

| Date | Note |
|---|---|
| 2026-06-03 | Architecture locked in three-plane model. Naming convention adopted. Plane boundary rules R1–R7 written. This doc supersedes prior ad-hoc references to "policy layer" or "wrapper layer." All downstream artifacts (implementation plan, scoping notes, training material) MUST align with this terminology. |
