# Changelog

All notable changes to `@pqctoday/softhsm-wasm` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Fixed — C++ ChaCha20-Poly1305 full AEAD round-trip + spec CKA_VALUE_LEN (2026-06-15)

`CKM_CHACHA20_POLY1305` was bolted onto the GCM AEAD path with several GCM-only /
AES-shaped gates left unadjusted, so an encrypt→decrypt round-trip failed and key
generation rejected the spec-mandated template attribute. Four scoped fixes, all
in the C++ engine; native `p11_v32_compliance_test -c all` stays **315 / 0 / 0**
and the hub dual-engine ACVP matrix is fully green (C++ 54/54, Rust 55/55). The
1452-case KMIP interop + KAT replay stays **15/15**.

- **`P11Objects.cpp` — register `CKA_VALUE_LEN` on `P11ChaCha20SecretKeyObj`.**
  PKCS#11 v3.2 §6.58.2 Table 254 defines it for ChaCha20; without it
  `C_GenerateKey` rejected the keygen template with `CKR_ATTRIBUTE_TYPE_INVALID`.
  Registered `ck2`-only (NOT `ck3`) — ChaCha20 is fixed 256-bit so the attribute
  is OPTIONAL for keygen (the AES default `ck2|ck3` would wrongly make it
  mandatory and break the conformance suite's keygen test). `P11AttrValueLen`'s
  constructor now takes its checks as a parameter (default `ck2|ck3`, so AES /
  generic-secret are unchanged).
- **`crypto/SymmetricAlgorithm.cpp` `decryptUpdate`** — buffer the ciphertext into
  `currentAEADBuffer` for `CHACHA_POLY1305` too (was GCM-only); otherwise the
  buffer is empty and `decryptFinal` cannot locate the tag →
  `CKR_ENCRYPTED_DATA_INVALID`.
- **`crypto/OSSLEVPSymmetricAlgorithm.cpp` `decryptUpdate`** — defer plaintext and
  withhold the tag for `CHACHA_POLY1305` too (was GCM-only).

GCM and all non-ChaCha20 paths are untouched (changes are strictly
`CHACHA_POLY1305`/ChaCha20-scoped). AES-GCM in the conformance harness is
decrypt-KAT-only, so the AEAD encrypt+round-trip path was exercised only by
ChaCha20 — which is why these defects were latent.

### Fixed — softhsmrustv3 native PKCS#11 v3.2 C-ABI compliance: 28 → 315 PASS / 0 FAIL (2026-06-15)

The Rust engine's C ABI (`rust/src/ck_abi.rs` + `ffi.rs`) was architecturally
32-bit/WASM-shaped — it marshaled every attribute template and `CK_MECHANISM`
(and nested param structs) as `u32` triples and reconstructed pointers from
`u32`. On native 64-bit this truncated pointers (`CKR_FUNCTION_FAILED`/heap
corruption), so `p11_v32_compliance_test -c all` scored only **28 PASS**. The
validated KMIP/ACVP path was unaffected (it bypasses the C ABI via
`softhsmrustv3::native::*`). Re-plumbed to native width and wired the
remaining functionality to **315 PASS / 0 FAIL / 0 SKIP — byte-for-byte identical to the C++ engine**, on the isolated
branch `feat/cabi-native-64bit`, with the **1452-case KMIP interop + KAT replay
staying 15/15** as the gate after every commit.

- **Width re-plumb (`u32 → usize`).** Portable: `usize` == `u32` on wasm32,
  `u64` on native; nested C structs read at `size_of::<usize>()` offsets so the
  same code is correct on both. Covers templates, `CK_MECHANISM`/params,
  `store_ulong` (native CK_ULONG width — fixes `C_FindObjects` byte-exact
  matching), HKDF/PBKDF2/SP800-108/GCM/ECDH/RSA-PSS/auth-wrap param structs, and
  the `C_GetAttributeValue` length write-back (`CK_UNAVAILABLE_INFORMATION` =
  `usize::MAX`).
- **Crypto wired through the C ABI:** X25519/X448 ECDH derive, AES-CBC(-PAD) key
  wrap, ChaCha20 keygen, AES-CMAC SP800-108 PRF, RIPEMD-160 digest+HMAC,
  SHA3-384-RSA (PKCS#1 v1.5 + PSS), raw `CKM_RSA_PKCS` sign/verify, the four
  dual-function ops, ML-DSA/SLH-DSA/EdDSA multi-part, HSS/LMS keygen+sign (with
  `CKA_HSS_KEYS_REMAINING` decrement), and XMSS^MT keygen/sign/verify (worked
  around an `xmss 0.1.0-pre.0` serialized-key OID round-trip bug).
- **Conformance behaviors:** keygen `CKA_KEY_TYPE`-vs-mechanism validation
  (`CKR_TEMPLATE_INCONSISTENT`), `CKA_PUBLIC_KEY_INFO` (SPKI) on private PQC
  keys, `CKA_UNIQUE_ID` as a 36-char UUID, RSA-PSS hashAlg validation,
  generic-secret KCV via **SHA-1** (not SHA-256), `CKF_ASYNC_SESSION` rejected
  with `CKR_SESSION_ASYNC_NOT_SUPPORTED`, RSA private-component sensitivity.
- **Function exports:** all `C_*` are now exported as `#[unsafe(no_mangle)]`
  symbols (standard PKCS#11 module behavior), lighting up the async,
  session-cancel, ML-KEM encapsulate/decapsulate, authenticated-wrap, and v3.0
  message-based (`C_MessageSign*`/`C_MessageEncrypt*`) APIs.
- **Constants:** every `CK*` value added was verified against the normative
  `src/lib/pkcs11/pkcs11t.h`. XMSS^MT keygen now exposes the standard
  `CKA_PARAMETER_SET` (0x61d), not only the legacy vendor attribute.
- **Tests:** in-process `cargo test --lib` restored to green (201/0) — the old
  `[u32;3]` test scaffolding (which SIGSEGV'd against the now-usize ABI) was
  converted to `[usize;3]`.
- **Not merged to `main`.** The validated checkout's `rust/` tree is unchanged;
  full per-commit table and rationale in `rust/CK_ABI_NATIVE_COMPLIANCE_PLAN.md`.
### Added — KMIP request-wire encoder + OASIS bidirectional conformance gate; policy/store/persistence hardening (2026-06-20)

The CACP engine could already **read** KMIP requests and **write** responses (the
server halves) but could not **write** requests. This batch adds the missing
mirror and tightens the policy/store/persistence layers around it. Full kmip
suite green: **492 lib tests + integration suites** (incl. the new OASIS
round-trip and spec-crosscheck gates).

- **F-6 — `encode_request_message` (client-side TTLV request encoder).** The
  byte-for-byte mirror of the request decoder, so the Rust→WASM playground can
  act as an in-browser KMIP client: encode a typed `RequestMessage` → hand the
  bytes to the in-process server → decode the reply. The encoder returns `None`
  for any header field / operation payload it cannot yet emit, so callers surface
  the gap instead of shipping wrong bytes. Typed decode stays intentionally lossy,
  so the guarantee is decode-stability (`decode(encode(decode(x))) == decode(x)`),
  not raw byte-identity.
- **OASIS conformance gate** — the 95 in-repo OASIS KMIP 3.0 *mandatory* cases
  now run as a permanent bidirectional test (`oasis_request_roundtrip`,
  `oasis_typed_decode`, `spec_crosscheck`): round-trip every operation **plus**
  byte-exact-vs-OASIS for every operation the corpus covers, validating both the
  new request-encode and the existing response-encode.
- **F-2 — algorithm-default resolution made order-independent.** Defaults now
  resolve in a dedicated Pass 0 *before* substitutions, so a substitution always
  operates on the defaulted value regardless of the order defaults and
  substitutions appear in a policy.
- **F-5 — AEAD / RSA-PSS parameters flow through the policy.** Crypto-parameter
  rules now carry `mask_generator` (MGF), `tag_length` (AEAD auth tag), and
  `salt_length` (PSS salt), wired through sign / encrypt.
- **S-10 — lifecycle-FSM parity across store backends.** `MemoryStore` (the
  default and WASM backend) now enforces the §3.4 state-transition FSM at the
  store layer, at parity with `SqliteStore`; illegal transitions (e.g.
  `Active→PreActive`) are rejected rather than silently accepted, and
  initial/original-creation dates are immutable across updates.
- **D-1 — full-record persistence.** `ObjectRecord` is now serde-serialisable
  (with a `UsageMask` bits adapter) for complete metadata round-trips.

### Removed — legacy `kmip/pykmip/` Python client (2026-06-20)

The hand-rolled `pykmip/` sandbox-dev client is replaced by the packaged
`kmip/python-client/` (`pqctoday_kmip`, 38 unit tests + wheel smoke check).
Downstream references (sandbox docs / UI labels / proxy) updated to match.

### Added — mlxpqc: standalone ML-DSA-65 Metal acceleration benchmark (2026-06-17)

New self-contained `mlxpqc/` subfolder — a small, **independent** research/benchmark
tool for GPU-accelerated ML-DSA-65 on Apple Metal. It does not touch the softhsm
library or the hub; it is reference ML-DSA code + a Metal port + benchmarks, with
its own `NOTICE.md`/`LICENSE`. The Apple corecrypto reference (`arm/`) is
`.gitignore`d — its license forbids redistribution, so it is never committed.

### Fixed — pkcs11-provider no longer crashes the host at process exit (2026-06-17)

A program that loads softhsmv3 as an OpenSSL provider (our pkcs11-provider) could
**segfault at process exit** — intermittently, about two in three `openssl req`
ML-DSA signing runs. The signing itself always succeeded and the certificate was
written; the crash came afterwards, during OpenSSL's `atexit` cleanup, so it
showed up as a non-zero exit code on an otherwise-good operation.

Root cause was a C++ **static-destruction-order** problem, not the crypto.
OpenSSL's `OPENSSL_cleanup` tears the provider down and calls back into the
module (`C_CloseSession`, `C_Finalize`) *after* softhsm's global singletons had
already been destroyed by C++ static destruction — dereferencing freed memory
(`HandleManager::getSessionShared`), and later a NULL OpenSSL RAND lock.

- **`LeakingPtr`** (new — `src/lib/common/LeakingPtr.h`) replaces the
  `std::unique_ptr` singletons (`SoftHSM`, `MutexFactory`, `OSSLCryptoFactory`,
  `SecureMemoryRegistry`). Its destructor does not free, so the module outlives
  C++ static destruction and stays valid for OpenSSL's late callbacks; `reset()`
  still frees, so `C_Finalize`/fork do **not** leak during normal operation.
- **`C_Finalize` process-exit guard** (`SoftHSM_slots.cpp`): an `atexit` sentinel
  registered in `C_Initialize` (which runs before OpenSSL's cleanup) lets
  `C_Finalize` skip OpenSSL-touching teardown (RAND / EVP / provider unload)
  during exit, where those globals are already gone.

Verified: **20/20 clean** `openssl req` ML-DSA certificate generations, was 4/6
crashing. Long-running servers (`s_server`) were never affected.

### Added — PQC tooling forks: step-ca, cosign, osslsigncode (ML-DSA, HSM-backed) (2026-06-15)

Three strongSwan-style fork patches (each `<tool>-pqc.patch` + a
`docs/<TOOL>_PQC_FORK.md` finish plan), consolidated on `feat/pqc-tooling-forks`
(PR #114) and validated end-to-end in the `pqc-network` Linux image. Upstreams
are unmodified in-tree; the patch is the source of truth.

- **step-ca** (smallstep/certificates v0.30.2) — `step-ca-pqc.patch`: SoftCAS
  issues a fully post-quantum ML-DSA-44/65/87 chain (FIPS 204; a hand-assembled
  TBSCertificate + SubjectPublicKeyInfo work around Go's lack of an ML-DSA OID).
  The issuing key is HSM-resident in softhsmv3 (non-extractable,
  `C_Sign(CKM_ML_DSA)`) via a new in-repo `mldsahsm` KMS, and a running `step-ca`
  server boots on it serving HTTPS + ACME. (Sandbox scenario 18.)
- **cosign** (sigstore/cosign v3.0.6) — `cosign-pqc.patch`: real
  `sign-blob` / `verify-blob` / `generate-key-pair` with ML-DSA-65, key either
  HSM-resident (`mldsa-pkcs11:` → softhsmv3) or in-process (cloudflare/circl).
  Transparency-log upload left off (Rekor has no ML-DSA entry type yet).
  (Sandbox scenario 34.)
- **osslsigncode** (mtrojnar/osslsigncode 2.13) — `osslsigncode-pqc.patch`:
  ML-DSA Authenticode PKCS#7 **sign and verify** over OpenSSL 3.6 native ML-DSA,
  including a content-binding (`messageDigest`) fix found while building the
  verify side. (Sandbox scenario 17.)

Honest boundaries documented per fork: no Microsoft PQC Authenticode profile
(Windows won't trust ML-DSA-signed PEs), Rekor PQC support pending, and Go/LibreSSL
clients cannot verify ML-DSA chains (OpenSSL ≥ 3.5 can).

### Added — cryptopolicy-manager `GET /audit` (three-plane log inspection) (2026-06-14)

The admin facade gains `GET /audit?limit=N`, returning the in-memory `RingSink`
snapshot (the p1 policy / p2 KMIP / p3 PKCS#11 audit trail, newest last) as
JSON over the same mTLS interface. This is the "inspect logs" data source for
the dev-sandbox UI: a `pykmip`-driven op shows up as p1 `PolicyDecided` +
p2 `KmipRequestReceived`/`KmipResponseSent` + p3 `Pkcs11Call`, all correlated
by `correlation_id`. `serve_admin` now takes the `RingSink`; unit test added.

### Added — cryptopolicy-manager: quantum-safe-mTLS HTTP policy-admin facade (2026-06-14)

The W4 server-side admin facade for the crypto-agility plane (`kmip/cryptopolicy-manager/`),
enabled with `--admin-listen`. A JSON HTTP API over the existing `PolicyStore`
so out-of-band tooling (the dev-sandbox policy-management UI) can list / load /
validate / dry-run / save / **activate** crypto-agility policies on the
**running** server — never on the KMIP surface (separation of duties; there is
no KMIP "reboot/reload" op, and inventing one would breach that boundary).

- **In-process, live hot-swap.** Compiled into the `pqctoday-kmip` crate via a
  `#[path]` module; the server spawns the admin listener with a clone of the
  live `policy::Engine` (`Arc<RwLock>` inside), so `POST /policies/{name}/activate`
  changes the policy the KMIP dispatcher enforces on the very next request —
  no restart.
- **Quantum-safe mTLS.** `X25519MLKEM768`-only key exchange (ML-KEM-768 hybrid,
  TLS 1.3) via the rustls **aws-lc-rs** provider (the KMIP listener's `ring`
  default is untouched), plus **required client certificates**. Client/server
  certs stay classical (ECDSA/Ed25519) — rustls 0.23 has no ML-DSA *certificate*
  support, so the quantum-safety is in the session KEX (harvest-now-decrypt-later
  resistance), documented as such.
- **Routes:** `GET /policies`, `GET /policies/{name}` (incl. raw YAML for an
  editor), `GET /active`, `POST /validate` (line/col errors for live lint),
  `POST /dry-run`, `PUT /policies/{name}`, `POST /policies/{name}/activate`.
  Activations are audited with the mTLS client-cert CN
  (`admin: LIVE policy activated name=… by cn=…`).
- New server flags: `--admin-listen`, `--admin-tls-cert/key`, `--admin-client-ca`
  (mTLS, requires `--policy-dir`). rustls gains the `aws_lc_rs` feature.

Verified manually against an OpenSSL 3.6.2 client: `Negotiated TLS1.3 group:
X25519MLKEM768`, certless client rejected, all seven routes correct, live
activation reflected immediately in `GET /active`. Unit tests cover the router
+ the PQC-mTLS config build; KMIP suite 477 tests green.

### Added — KMIP PQC interop (full 1452 byte-exact) + crypto-policy completeness + sandbox-dev client (2026-06-14)

Three PRs completing the crypto-agility layer's interop claim and its first
integration. KMIP suite 472 tests green throughout; OASIS replay held at 92/0/10.

- **Crypto-policy completeness** (`3dc86e1`, PR #107). W2: Encrypt now applies a
  policy-forced `Decision.cp_override` (mechanism-parameter *forcing*, not just
  gating); the keyless Hash op is policy-gated (`hash_algorithm_allowlist`); the
  canonical `CKM_*` map expanded (SHA-2/3 hashes, ECDSA-SHA3, EdDSA, ChaCha20,
  KWP, KDFs); confirmed `CKM_KMAC_*` is vendor-defined (OASIS v3.2 standardises
  no codepoint). Closes W2 of `CRYPTO_POLICY_GAPS_IMPLEMENTATION_PLAN.md`.
- **OASIS KMIP 3.0 PQC interop — 1452/1452 byte-exact through the live server**
  (`9626e6a`, `46e2f8c`, `c7c907f`, PR #108). W1/I4: the full OASIS PQC interop
  set (keygen, encapsulate/decapsulate, sign/verify across ML-DSA 44/65/87,
  ML-KEM 512/768/1024, all 12 SLH-DSA parameter sets) now replays **byte-exact**
  through the real `pqctoday-kmip` server over TLS. Taught the replay codec the
  KMIP 3.0 WD19 PQC tags + `SeedPrivateKey` KeyFormatType (`0x18`) +
  Encapsulate/Decapsulate ops, with per-test port cycling for large local
  sweeps. Server side: the ML-KEM shared secret is served as
  `SecretDataType=Seed` in a 2-child KeyBlock, born `PreActive`; keygen serves
  `Get` of `SeedPrivateKey` (`{Seed, Key}`) + `Raw` via born-extractable seeded
  keygen (`generate_{ml_dsa,ml_kem,slh_dsa}_keypair_from_seed_extractable`) gated
  by the KMIP `Extractable` attribute; `Get` resolves the engine handle by
  PKCS#11 class. New `KMIP PQC Interop Replay` CI job over a vendored
  42-transcript subset (`kmip/conformance/pqc_corpus/`); the full 1452-case set
  stays unvendored (`KMIP_REPLAY_CORPUS=<dir>`).
- **pykmip sandbox-dev client + ML-KEM ops through the policy engine** (PR #109).
  First sandbox-dev integration: a Python KMIP client (`kmip/pykmip/`) that
  drives the agile server and a correlator that renders the `--audit-log` as
  per-request three-plane trails (p1 policy / p2 KMIP / p3 PKCS#11). Building it
  surfaced + fixed two findings in the WD19 ML-KEM ops: Encapsulate/Decapsulate
  now resolve the engine handle by PKCS#11 class (a `CreateKeyPair` pair shares
  one CKA_ID → the bare lookup hit the wrong half →
  `CKR_KEY_FUNCTION_NOT_PERMITTED`), and they now route through the Plane-1
  policy engine (emit a p1 decision + enforce allow/deny) instead of bypassing
  it — closing a crypto-agility blind spot for KEM operations.

### Added — KMIP 3.0 coverage Phase 2: implementable spec-surface gaps (2026-06-13)

Closes the implementable spec-surface gaps from `kmip/docs/COVERAGE_GAP_PLAN.md`,
on top of Phase 1's CI-gated safety net. OASIS replay held at 92/0/10 throughout;
kmip suite 554 tests green.

- **P2.4 — spec-correct result reasons** (`31421ca`). Added emit paths for
  Wrapping Object Not Found / Archived / Destroyed (on Get/Register wrap KEK
  resolution) and Circular Link Error (self / direct-reciprocal Link mutation),
  each with negative tests. MissingInitializationVector and Constraint Violation
  deferred (the former's reachable condition is corpus-pinned to InvalidMessage;
  the latter has no enforcement site without inventing a feature).
- **P2.1 — Object Group + group-membership Locate** (`83533da`). Multi-valued
  Object Group attribute stored at Create/Register; Locate filters by group. The
  capability behind the 2 SASED-M-3/TL-M-3 precondition transcripts (which stay
  SKIP due to hermetic cross-transcript isolation, now with the filter
  implemented + e2e-tested). Also fixed a P2.4 over-match where the circular-link
  check wrongly flagged legitimate inverse link pairs (Next/Previous,
  Public/Private), which had deterministically broken AX-M.
- **P2.5 — ML-KEM through the KMIP op surface + AES-XTS status** (`807635d`).
  ML-KEM encap/decap now exercised through the dispatcher Encrypt/Decrypt path
  (512/768/1024 round-trip shared-secret recovery + tampered-ct negative + FIPS
  203 implicit rejection), not just the engine bridge. AES-XTS confirmed
  engine-unsupported → honest UnsupportedCryptographicParameters (0x3e), tested.
  Corrected the audit's mislabel: the AX-M profile is AES key-wrap + rotation
  links, not AES-XTS.
- **P2.2 — Validate operation** (`47923fb`). §6.1 certificate-chain Validate via
  real `x509-parser`+`ring` (parse + validity-date + issuer/subject chain-link +
  signature verification where the issuer is available), with an honest
  Valid/Invalid/Unknown contract — never a false Valid. Moved into
  HANDLED_OPERATIONS.
- **P2.3 — Certify / Re-certify: a PQC-capable certificate authority**
  (`75083d1`, `fa74831`). Implements §6.1.6 Certify and §6.1.50 Re-certify
  (reversing the prior KMIP-as-CA out-of-scope decision). Parses PKCS#10 CSRs
  (rcgen), builds the TBSCertificate via `x509-cert` with arbitrary
  AlgorithmIdentifiers, and signs it in the engine via `native::sign` for RSA,
  ECDSA (raw r‖s → DER `Ecdsa-Sig-Value`), **and ML-DSA** (id-ml-dsa-44/65/87) —
  the CA private key never leaves the engine, and ML-DSA-signed certs are
  issuable (rcgen alone cannot). CA key designated by config; Re-certify
  recomputes validity from Offset + sets Replaced/Replacement links. The CA cert
  carries BasicConstraints CA:TRUE + KeyUsage keyCertSign per RFC 5280.
  **External cross-check**: `openssl_cert_crosscheck.rs` validates issued certs
  with an independent OpenSSL 3.6 toolchain — `openssl x509 -text` parses the DER
  and confirms the AlgorithmIdentifier (incl. `ML-DSA-65`), and `openssl verify`
  independently confirms the CA signature our engine produced for all three
  algorithms (the ML-DSA-65 signature verified by a separate FIPS-204
  implementation). Cert format confirmed consistent with the hub playground's
  PQC OIDs where they overlap.

### Added — KMIP 3.0 coverage Phase 1: test rigor & regression safety net (2026-06-13)

Closes the test-rigor gaps found by the KMIP 3.0 spec-coverage audit (see
`kmip/docs/COVERAGE_GAP_PLAN.md`). Four slices, no behavior change except one
spec-correctness FSM fix the new exhaustive matrix surfaced.

- **CI-gate the OASIS conformance replay** (`2adc4df`). New `kmip-conformance`
  CI job builds the release server, runs the 102-transcript replay, and fails on
  `FAIL>0` / `PASS<92` / skip-set drift. Fixed a harness bug where
  `dispatcher_replay.py main()` returned 0 unconditionally regardless of FAILs —
  exactly why the 92→89 Locate regression shipped past manual runs. Added a
  report-staleness guard that fails CI if the committed `REPLAY_REPORT` differs
  from a fresh run (timestamp-normalized), so the checked-in report can no
  longer go stale and hide a regression. The replay is now a real gate, not a
  manual step.
- **Execute the NIST/ACVP KAT vectors** (`ef2289c`). The `kat/*-acvp.json`
  vectors were checked in and manifest-hashed but never run (the consumer
  `tests/acvp_roundtrip.rs` the README referenced did not exist). New
  `acvp_roundtrip.rs`: 17 manifest-integrity-gated known-answer tests driving
  `softhsmrustv3::native` byte-exact against published NIST outputs — SHA2/SHA3,
  HMAC/KMAC128, AES-CBC/CTR/GCM/KW, RSA-PSS/OAEP, ECDSA P-256/384/521, Ed25519,
  ML-KEM 512/768/1024 decap, ML-DSA 44/65/87 sigVer, SLH-DSA. Turns crypto
  coverage from self-consistency round-trips into published-known-answer
  correctness. A no-orphan guard fails if any `kat/` vector is neither consumed
  nor explicitly listed unconsumed (4 deferred for missing engine primitives:
  AES-CMAC, HKDF, Ed448, composite-sigs). Surfaced two corpus defects honestly
  (a truncated KMAC256 vector; generator-specific SLH-DSA sigGen).
- **Full-round-trip e2e for the 18 corpus-uncovered ops** (`d6dc53e`).
  `op_coverage_e2e.rs`: real-engine e2e for Archive/Recover, Deactivate,
  Import/Export, Set/AdjustAttribute, DeriveKey, ReKey(+KeyPair),
  GetUsageAllocation, GetConstraints, SetDefaults, SetEndpointRole,
  DiscoverVersions, Ping, Login/Logout — each asserting a substantive outcome
  (state, material bytes, links, error reason), not just success. Plus a
  coverage meta-test asserting every one of the 49 `HANDLED_OPERATIONS` has a
  covering test, so a new op can't ship uncovered.
- **Exhaustive 6×6 object-state transition matrix + FSM fix** (`352effc`). The
  matrix (all 36 `(from,to)` cells vs the §3.2 diagram / §6.1.19) found
  `State::can_transition_to` allowed two edges the spec forbids: **Active→
  Destroyed** (§6.1.19: destroy only from Pre-Active/Deactivated) and
  **PreActive→Deactivated** (no §3.2 edge). Latent — the Destroy/Deactivate op
  handlers already gated these — but the predicate contradicted both the spec
  and its own handlers. Both edges removed, the tests that encoded them
  corrected, IMPLEMENTATION_PLAN §3.4 updated; matrix passes 36/36 as the
  regression guard. OASIS replay unchanged at 92/0/10.

### Fixed — KMIP Locate orphan filter regressed OASIS conformance 92→89 (2026-06-13)

A conformance-harness accuracy/completeness audit found `main` was at **89 PASS
/ 3 FAIL**, not the claimed 92/0 — a regression hidden by a stale
`conformance/REPLAY_REPORT.md` (a 1-test partial run). The Phase 7b.1 "Locate
orphan filter" (`9176662`) dropped every Locate result whose PKCS#11 handle was
absent from the engine, including legitimately **store-only** objects (Raw AES /
cert / secret-data Registers that are never engine-imported) — so a freshly
Registered key vanished from its own Locate (BL-M-1/4/14: empty payload where a
UniqueIdentifier was expected). The filter now keys on `ObjectRecord.key_material`:
store-backed objects (`Some`) stay locatable; only true engine-only orphans
(`None` + missing handle) are hidden, preserving the persistent-store/volatile-
engine guard the filter was written for. Replay restored to **92 PASS / 0 FAIL /
10 SKIP**; `REPLAY_REPORT` regenerated from a full run.

Audit findings (no code change, recorded for accuracy): the replay harness is
sound — it drives the real compiled server over TLS with exact tree-wise
comparison and no error-as-PASS path, and all 10 SKIPs are legitimate
(5 deprecated DES/3DES/DSA, 2 cross-transcript precondition, 3 mutually-exclusive
RNG policy variants). The checked-in corpus is the **complete** official OASIS
KMIP 3.0 package (102/102 transcripts, 1234/1234 messages, byte-identical). Two
honest scope limits: (1) crypto outputs (signature/ciphertext/MAC/digest) are
placeholder-bound, not KAT-verified — the claim is protocol/structural/status
conformance, not cryptographic-correctness; (2) the replay is **not CI-gated**,
which is how this regression slipped in — wiring it is recommended follow-up.

### Fixed — C++ engine: token encrypt/decrypt hardening + C++17 enforcement (2026-06-13)

A security hardening sweep over all 111 `Token::encrypt`/`decrypt` call sites in
`src/lib`, closing the round-6 bug *class* in the pre-existing key-serialization
paths (from the H1 file-split) rather than one bug at a time. Commit `5e1183e`;
compliance suite 315 PASS / 0 FAIL / 0 SKIP, ctest 8/8.

- **Every discarded return now handled.** 45 bare-statement `encrypt`/`decrypt`
  sites (RSA/EC/EdDSA/ML-DSA/ML-KEM/SLH-DSA/AES/generic-secret keygen, ML-KEM
  encap/decap, PBKD2 derive, set\*PrivateKey unwrap helpers, BIP32 derive, and
  two RSA-AES-KW unwrap decrypts) were ignoring the bool return — on an
  encryption failure they would commit empty/garbage key material. Each now
  folds into the in-scope `bOK` flag (aborting the transaction with cleanup) or
  returns `CKR_GENERAL_ERROR`, so a failed `encrypt`/`decrypt` aborts the
  operation instead of producing a silently corrupt key.
- **The class is now unrepresentable.** `Token::encrypt`/`decrypt` and the
  underlying `SecureDataManager::encrypt`/`decrypt` are marked `[[nodiscard]]`,
  so an ignored return is a compile error — the bug cannot be reintroduced.
- **C++17 is now actually enforced.** `cmake/modules/CompilerOptions.cmake` had
  been forcing `-std=c++11`, silently overriding the top-level C++17 setting the
  project (and CLAUDE.md) assumes — which is why `[[nodiscard]]` had no effect
  engine-wide. Corrected to C++17; full rebuild clean, all suites green.

### Fixed — C++ engine round 6: review-confirmed bugs (2026-06-13)

A high-effort code review of the round 4–5 changes confirmed four bugs, two
of them introduced by this branch's own fixes. All resolved in commit
`94532bc`; compliance suite 308 → **315 PASS / 0 FAIL / 0 SKIP**, ctest 8/8.

- **Digest dual-op NULL-deref (crash/DoS), introduced by R5-2.** In a §5.13
  dual op (`C_EncryptInit` + `C_DigestInit`), finalizing the digest half first
  freed `digestOp` but left the session's `operation` stale at
  `SESSION_OP_DIGEST` (the cipher partner survived), so a following
  `C_DigestUpdate`/`C_Digest` dereferenced a NULL op. Fixed at the root:
  `Session::endOpFamily` now tracks both dual-op families and advances
  `operation` to the surviving partner instead of leaving it stale; plus
  defense-in-depth NULL guards on `C_Digest`/`C_DigestUpdate`/`C_DigestKey`.
- **Unchecked `token->encrypt()` → silent private-key corruption, introduced
  by the V-13 fix.** `token->encrypt()` returns `false` (wiping its output) on
  RNG/AES failure without throwing; several keygen sites committed the empty
  result as a private `CKA_VALUE`, yielding a key that fails only at first use.
  The return is now checked at the HSS/XMSS keypair site (both halves torn
  down + `CKR_FUNCTION_FAILED`) and the five KDF/unwrap sites. (~30 further
  discarded-return sites in pre-existing upstream serialization paths are noted
  for a separate hardening pass.)
- **StatefulSign two-call-convention violation.** A `C_Sign(pSignature=NULL)`
  size query computed and then discarded the full stateful signature. It now
  answers from the known signature length (`hss_get_signature_len_from_working_key`
  / parsed OID `sig_bytes`) without signing; the no-leaf-burn-on-too-small
  guarantee and mutex/commit ordering are preserved.
- **Unique-id migration robustness.** The 0x17→0x4 `CKA_UNIQUE_ID` migration is
  now best-effort: a read-only / write-refusing store no longer fails object
  `init()`; the in-memory id is retained.

### Fixed — C++ engine PKCS#11 v3.2 compliance, round 4 (2026-06-12)

Full v3.2 remediation of the C++ `src/lib/` engine, which rounds 1–3 had
scoped out (rust was the focus). Driven by
`docs/compliance-audit-cpp-pkcs11-v3.2-2026-06-12.md`; six commits on branch
`fix/cpp-pkcs11-v3.2-compliance` (G1 `74fa6f3`, G2 `6ee89ed`, G3 `11d7c56`,
G4 `0e00701`, G5 `4c6bf74`, Part-A `520bff4`).

- **G1 — 4 criticals (security):** reject zero-length IV/nonce
  (`CKR_MECHANISM_PARAM_INVALID`) and remove the OSSL all-zero-IV fallback for
  GCM/ChaCha20-Poly1305 (catastrophic nonce reuse); enforce the
  ChaCha20-Poly1305 12-byte nonce and check `SET_IVLEN`; heap-size the
  XMSS/XMSSMT signature buffer to fix a stack-buffer overflow on large C_Sign;
  `CKM_RIPEMD160` now returns `CKR_MECHANISM_INVALID` instead of silently
  computing SHA-1; HSS/XMSS private `CKA_VALUE` is now token-encrypted like
  every other private key; stateful sign serialized with state committed before
  the signature is released (leaf-reuse race).
- **G2 — mechanism table:** ML-DSA/SLH-DSA `C_GetMechanismInfo` report
  public-key byte sizes (1312/2592, 32/64); advertise↔dispatch reconciled
  (bare `CKM_CHACHA20` wired, `RIPEMD160_HMAC`/Keccak-256 dropped, raw RSA-PSS /
  MD5 / SHA3-384-RSA / X25519/X448/BIP32-derive reconciled); ChaCha20 keygen no
  longer mislabels keys as AES; `CKF_MESSAGE_*` advertised where the message API
  dispatches.
- **G3 — keygen/template validation:** mismatched `CKA_KEY_TYPE` →
  `CKR_TEMPLATE_INCONSISTENT`; missing `CKA_PARAMETER_SET` →
  `CKR_TEMPLATE_INCOMPLETE` (no more silent ML-DSA/ML-KEM/SLH-DSA defaults);
  XMSSMT keygen and sign (0x4036→0x4037 stale literal) now reachable;
  `CKA_HSS_KEYS_REMAINING` reports the real 2^h leaf count; AES-CBC/CBC-PAD wrap
  is real CBC encryption with the caller IV (not disguised AES-KW).
- **G4 — return-code precision:** `CKR_WRAPPED_KEY_INVALID` on unwrap integrity
  failure; spec-correct `C_SessionCancel` (flags==0 no-op, ignore-unmatched,
  honor `CKF_MESSAGE_*`/FIND); one-shot-after-Update → `CKR_OPERATION_ACTIVE`
  incl. the missing `C_Digest` guard; `C_WrapKeyAuthenticated` sets the length on
  `CKR_BUFFER_TOO_SMALL`; `C_GetSessionValidationFlags` gates init+session;
  `pInitArgs->pReserved != NULL` → `CKR_ARGUMENTS_BAD`; try/catch firewall on the
  KEM C-ABI shims; KEM/derive handle codes and Stateful sign/verify
  length/error distinctions corrected.
- **G5 + Part-A — attributes:** `C_CopyObject` mints a fresh `CKA_UNIQUE_ID`
  instead of duplicating the source's; `CKA_UNIQUE_ID` is strictly
  token-assigned (rejected in every template incl. derive); load-time shim
  migrates legacy objects from the pre-resync type `0x17` to canonical `0x4`;
  `CKA_UNIQUE_ID` is now readable on private/sensitive objects (it was stored in
  plaintext but `retrieve()` tried to decrypt it → `CKR_GENERAL_ERROR`); `CKA_SEED`
  is a sensitive-protected PQC private-key attribute enabling deterministic
  ML-DSA/ML-KEM/SLH-DSA keygen via the OpenSSL 3.6.2 keygen "seed" `OSSL_PARAM`.

Verification: all 8 `ctest` suites pass; the `p11_v32_compliance_test` binary
reports **268 PASS / 0 FAIL / 1 SKIP**. The stale gap-analysis v16 banner and
its G7/G8/G9 "intentional omission" entries are corrected in
`docs/gap-analysis-pkcs11-v3.2.md` (v17): async ops return
`CKR_OPERATION_NOT_INITIALIZED` (not `FUNCTION_NOT_SUPPORTED`),
`C_SignRecover`/`C_VerifyRecover` are fully implemented, and
`C_GetSessionValidationFlags` was defective (now fixed). The only genuinely
intentional omissions retained are the 4 dual-function combined ops and
RIPEMD-160 in the WASM build (`no-module` legacy-provider constraint).

### Fixed — C++ engine PKCS#11 v3.2 compliance, round 5 close-out (2026-06-12)

Closes every item the round-4 audit left as "deferred / intentionally out of
scope." Five commits on branch `fix/cpp-pkcs11-v3.2-compliance`
(R5-1 `38357a4`, R5-2 `4bce9ef`, R5-3 `7432b2f`, R5-4 `b9f6cd3`,
R5-5 `a6d2614`). gap-analysis bumped to **v18**.

- **R5-1 — SHA3-384-RSA family completed (`38357a4`):** `CKM_SHA3_384_RSA_PKCS`
  and `CKM_SHA3_384_RSA_PKCS_PSS` now sign/verify end-to-end, closing the
  one-family hole in the SHA3-RSA signature set (round 4 had only reconciled the
  advertise↔dispatch table entry).
- **R5-2 — dual-function combined ops (`4bce9ef`):** `C_DigestEncryptUpdate`,
  `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` are now
  implemented; these were the last `CKR_FUNCTION_NOT_SUPPORTED` stubs in the
  engine.
- **R5-3 — async conformance (`7432b2f`):** `C_OpenSession` now rejects
  `CKF_ASYNC_SESSION`, and the `C_Async*` entry points gate on init then return
  `CKR_FUNCTION_NOT_SUPPORTED` (replacing the stale
  `CKR_OPERATION_NOT_INITIALIZED`). Async stays a deliberate non-feature, but the
  engine no longer mis-reports its state.
- **R5-4 — cross-token handle isolation (`b9f6cd3`):** a handle minted on token A
  is no longer usable from a session bound to token B (upstream-inherited defect
  from audit object §6 OBS).
- **R5-5 — RIPEMD-160 via the native legacy provider (`a6d2614`):** the native
  engine exposes `CKM_RIPEMD160` through the OpenSSL legacy provider, gated behind
  a build option. RIPEMD-160 stays **off by design in the WASM build**
  (`no-module` disables the legacy provider; Bitcoin HASH160 is computed
  client-side via `@noble/hashes/ripemd160`).

Verification: all 8 `ctest` suites pass (8/8); the `p11_v32_compliance_test`
binary reports **308 PASS / 0 FAIL / 0 SKIP**. The only items still intentionally
out of scope are `CKM_RIPEMD160_RSA_PKCS` (RSA-over-RIPEMD-160 was not added —
only the bare digest mechanism) and RIPEMD-160 in the WASM build.

### Added — strongSwan-wasm: IKEv2 fragmentation, multi-KE, CHILD_SA stub kernel (2026-06-12)

(`feat/wasm-vpn-frag-multike-childsa` track; CHANGELOG entry added at
consolidation — the work landed in four commits without entries.)

- **RFC 7383 IKEv2 message fragmentation + RFC 9370 multiple key
  exchanges** wired through the wasm strongSwan build, with a Tier A
  CHILD_SA stub kernel (`strongswan-wasm-shims/kernel_wasm.c`, new) so
  CHILD_SA negotiation completes against the in-browser stack.
- **CHILD_SA traffic selectors + race-free stub-kernel registration**
  (`kernel_wasm.c`, `wasm_backend.c`).
- **SLH-DSA 6.0.5 compat defines** for the shared strongswan-pkcs11
  overlay so one overlay serves both strongSwan series.
- v1 strongSwan wasm build pipeline marked VERIFIED
  (`docs/wasm-charon-phase-3b-plus-roadmap.md`).


### Compliance round 3 — spec-truth for code and tests (2026-06-12)

The test-infrastructure audit found the instruments measuring compliance
were themselves out of spec. Six slices (F1-F4 + two engine fixes), all
against the canonical OASIS v3.2 reference now pinned at
docs/refs/pkcs11t-canonical-v3.2.h (sha256 95738fdc…).

- **F1 header re-sync**: local pkcs11t.h had drifted from canonical —
  CKA_UNIQUE_ID was 0x17 (canonical 0x4; the rust engine served the
  unique id under the wrong attribute type), CKM_GOSTR3410_DERIVE was
  0x1202, and local inventions (X25519/X448, BIP32) squatted on
  OASIS-assigned codepoints, 0x4033/0x4034 shadowing real CKM_HSS /
  CKM_XMSS_KEY_PAIR_GEN dispatch in the C++ engine. All moved to a
  marked vendor-extension section; rust constants follow; deprecated
  BIP32 aliases accepted at dispatch.
- **F2 constants gate**: constants.js (published npm surface) had 12
  spec-wrong values (SO-PIN flags, MD2 family, XEDDSA, AES-KWP,
  encap/decap templates) and invented non-spec names — fixed.
  check_pkcs11_constants.py rewritten: validates rust + constants.js +
  kmip mech manifest against the header, pins 99 formerly-whitelisted
  IANA/vendor values, detects duplicate codepoints per class, verifies
  the local header against the pinned canonical include. Wired into CI
  with rust+kmip cargo test.
- **F3 JS harnesses**: rust/pkg artifacts rebuilt (were 38+ commits
  stale — every prior JS pass validated the pre-remediation engine);
  fabricated X25519/SP800-108 "PASSED" outputs in test_kat_parity.js
  replaced with real RFC 7748 / NIST CAVS KATs; CK_ATTRIBUTE layout and
  vendor attr ids fixed; round-2 regression section added to
  test_p11_conformance.js (now 188 assertions incl. CKA_UNIQUE_ID via
  0x4, dynamic TokenInfo, T4/T5/T6 surfaces, message-API streaming
  byte-equality); ECDSA-SHA512 loader un-bitrotted.
- **F4 C++ compliance suite**: spec-wrong template constants fixed
  (CKK_ML_KEM 0x49, CKM_HSS 0x4033, SP800-108 param types),
  error-returns-as-PASS eliminated (advertised-feature gating +
  SKIP/XFAIL kinds), non-spec mechanism-presence mandates dropped,
  hermetic ctest wiring added, dead generator scripts and stale
  binaries/reports deleted. Reproducible result: 193 PASS / 0 FAIL /
  1 SKIP (was an unreproducible "120 PASS" claim).
- **Engine fixes the honest tests forced**: both engines accepted a
  bare hash as the SP800-108 KBKDF PRF and the rust engine silently
  wrong-digested SHA-384/512 HMAC PRFs to HMAC-SHA256 — C++
  (SoftHSM_keygen.cpp) and rust (ffi.rs KBKDF cores) now accept only
  keyed-MAC PRF mechanisms, each mapped to its own digest, with
  KAT-pinned references.


### Compliance round 2 — remaining-gap remediation (2026-06-12)

Execution of the round-2 remediation (engine slices T1–T8, KMIP slices
K16–K22) closing the gaps left after the 2026-06-10 audit remediation.
All gates green throughout: engine tests 197/197, constants 349/349,
kmip tests 426/426, OASIS replay 92 PASS / 0 FAIL.

- **Engine (softhsmrustv3, T1–T8)**: advertise/dispatch holes closed
  (P-521 under all hash-ECDSA mechs with FIPS 186-5 digest truncation,
  wasm ChaCha20{,-Poly1305} encrypt/decrypt dispatch, SHA3-ECDSA/ECDH
  ranges) — T1; dynamic TokenInfo (flags from real PIN/init state,
  settable label, live session counters) — T2; token-scoped object
  enumeration with strict cross-slot handle invalidation — T3;
  multi-part C_Sign/C_Verify Update/Final for hash-composite and HMAC
  mechanisms — T4; message-encrypt rework (see detailed T5 entry
  below); C_SetAttributeValue (§4.1.3 modifiability, all-or-nothing),
  C_CopyObject (CKA_COPYABLE, no security weakening), C_GetObjectSize,
  C_SetPIN (PBKDF2 rotation), C_SeedRandom →
  CKR_RANDOM_SEED_NOT_SUPPORTED — T6; seed-deterministic PQC keygen via
  CKA_SEED (FIPS 203 d‖z via ml-kem generate_deterministic, FIPS 204 ξ
  via fips204 keygen_from_seed, FIPS 205 3-seed via fips205
  keygen_with_seeds; ACVP keyGen KATs byte-exact where vectors exist) —
  T7; native C_GetFunctionList — real CK_FUNCTION_LIST{,_3_0,_3_2}
  (104 entries) via checked-narrowing ABI adapter shims on non-wasm
  targets — T8.
- **KMIP server (K16–K22)**: Export honors KeyWrappingSpecification
  (shares Get's AES-KW machinery) — K16; Register accepts wrapped key
  material (KeyWrappingData → KEK UnwrapKey-mask gate → AES-KW unwrap →
  TTLV/raw KeyValue decode → normal pipeline) — K17; RSA-PSS Salt
  Length decoded from CryptographicParameters and threaded to the
  engine (salt-0 byte-matches OpenSSL) — K18; Baseline §5.1.2 item-9
  ops implemented (GetUsageAllocation against the real usage budget,
  GetConstraints from engine truth, SetDefaults applied beneath client
  templates, SetEndpointRole identity-accept/switch-reject per
  §6.1.59.1) — K19; Derive Key (HMAC/HASH/PBKDF2/NIST 800-108-C per
  the §7.13 constructions, derivation links both directions,
  unsupported methods → the spec-listed reason) — K20; Re-key + Re-key
  Key Pair (§6.1.51/52 attribute inheritance incl. Name transfer,
  Offset date shifts, Replaced/Replacement links, original
  deactivation) — K21; Archive/Recover now real (storage status
  enforced: Get/crypto ops on archived objects → Object Archived 0x0d,
  attributes stay readable, Locate Storage Status Mask filters actual
  state) — K22.

### Fixed — T5 message-encrypt multipart rework (2026-06-12)

`C_EncryptMessage*`/`C_DecryptMessage*` (PKCS#11 v3.2 §5.15, AES-GCM) — closes
gap-analysis Appendix B:

- **Incremental GCM streaming**: `C_EncryptMessageNext` runs O(chunk) through
  an extended `GcmState` (CTR keystream carry across non-block-aligned chunk
  boundaries + running GHASH; AAD folded at Begin, §7.1 J0 derivation for
  non-96-bit IVs). Previously each part re-ran the full GCM over the
  accumulated payload — O(n²). Chunked output is byte-identical to one-shot
  (SP 800-38D KATs at 1/16/7-13/empty-part splits, 96/128-bit tags, 12- and
  8-byte IVs; single-pass pinned by a keystream-block-counter test).
- **Verify-then-release decrypt**: `C_DecryptMessageNext` buffers plaintext
  internally (memory bound: one message) and emits it only after the final
  part's tag verifies; on mismatch → `CKR_ENCRYPTED_DATA_INVALID`, buffered
  plaintext zeroized, caller buffer untouched. Previously each chunk's
  unauthenticated plaintext was released before tag verification.
- **Truncated tags**: one-shot `C_DecryptMessage` with `ulTagBits < 128` now
  verifies the truncated tag prefix (constant-time) instead of always failing.
- **Zeroization**: message state (`key`, armed GCM stream, withheld plaintext)
  wiped on `C_MessageEncrypt/DecryptFinal`, `C_CloseSession`,
  `C_SessionCancel` (CKF_MESSAGE_ENCRYPT/DECRYPT) and `C_Finalize`;
  `GcmState` zeroizes its keystream/counter/buffers on drop.
- Scope: AES-GCM only — the message family dispatches `CKM_AES_GCM`
  exclusively (ChaCha20-Poly1305 message ops are not advertised; round-1 S1
  left `CKF_MESSAGE_*` off for it).

### Compliance — KMIP 3.0 / PKCS#11 v3.2 audit remediation (2026-06-10)

Full execution of the two-track compliance fix plans
(`docs/fix-plan-rust-pkcs11-v3.2-compliance.md` S1–S7,
`kmip/docs/COMPLIANCE_FIX_PLAN.md` K1–K15) against the audit
`docs/compliance-audit-kmip30-pkcs11v32-2026-06-10.md`. 22 slices, all
gates green throughout (engine tests 135/135, constants 339/339, kmip
tests 389/389, OASIS replay 92 PASS / 0 FAIL).

- **Engine (softhsmrustv3, S1–S7)**: PQC mechanism-info sizes in
  public-key bytes per §6.67–6.69; ChaCha20{,-Poly1305} + BIP32
  advertised; pre-init `C_GetInterfaceList`/`C_GetInterface`;
  `nonnull!` input-pointer sweep; honest
  ALWAYS_SENSITIVE/NEVER_EXTRACTABLE on `C_CreateObject`; CKA_SEED in
  the sensitive-blocked set; token-assigned `CKA_UNIQUE_ID`;
  CKA_TRUSTED server-managed + `CKA_WRAP_WITH_TRUSTED` →
  `CKR_KEY_NOT_WRAPPABLE`; wrap-family handle-invalid codes
  (`CKR_WRAPPING/UNWRAPPING_KEY_HANDLE_INVALID`, AES-KW
  `CKR_WRAPPED_KEY_INVALID`/`_LEN_RANGE`); operate-stage
  `require_session!` (§5.2 priority); ML-KEM encap/decap key-type +
  param-set strictness; new `CKM_SHA384/512_RSA_PKCS{,_PSS}` (OpenSSL
  cross-validated); native ML-DSA/ML-KEM/SLH-DSA key import.
- **KMIP server (K1–K15)**: six new ResultReasons + full CKR→reason
  table (default GeneralFailure, not CryptographicFailure); dead
  pkcs11bridge/attrmap modules deleted; ObjectNotFound /
  WrongKeyLifecycleState / ObjectDestroyed precision sweep (~25 sites,
  one corpus-pinned exception documented); all 64 op codepoints decode,
  unimplemented ops fail per-batch-item with OperationNotSupported;
  truthful Query + honest QueryCapabilities/QueryProfiles (and fixed
  QueryFunction codepoints 0x0a/0x0b); AsynchronousIndicator=Mandatory
  honored, critical MessageExtension rejected; vendor mech block
  0x4032–0x4037 retired for standard PQC codepoints (collision with
  CKM_HSS/CKM_XMSS*); silent algorithm substitution eliminated
  (AES-CTR wired, CFB/OFB/PCBC/CCM/XTS → 0x3e, RSA padding + OAEP/sign
  hashes honored-or-rejected, request-CP precedence); Sensitive (0x16)
  / NotExtractable (0x17) enforced on Get/Export, no empty KeyBlocks;
  KeyFormatType spec enum + no Raw coercion + TransparentRSAPrivateKey
  parsing + requested-format conversion; PQC Register imports into the
  engine (registered keys usable); ML-KEM shared secret on vendor tag
  0x540001 instead of IVCounterNonce; LastChangeDate on attribute
  mutation, real persisted Digest (engine-boundary hashing for
  non-extractable halves), honest RNG attribute, full Links +
  UsageLimits; usage-mask enforcement (0x29) + Locate
  OffsetItems/StorageStatusMask; config-gated authentication
  (UsernameAndPassword credential verify, Login validation, mTLS
  client-CA wiring); truthful post-call audit records with native
  entry-point names, HMAC via engine for engine-resident keys.

### Added

- **kmip — KMIP-level key wrapping on `Get`: OASIS conformance 91 → 92 of 92 actionable tests (100%)** (`kmip/src/ops/get.rs`, `kmip/src/kmip30/{ops,wire,mod}.rs`, `rust/src/native/encrypt.rs`). Closes AX-M-2, the last open conformance failure — pulled forward from the v0.2 deferral. `Get` with a `KeyWrappingSpecification` (KMIP 3.0 §6.1.23: `WrappingMethod=Encrypt` + `EncryptionKeyInformation` with `BlockCipherMode=NISTKeyWrap`) now returns the KeyBlock with the TTLV-encoded `KeyValue` wrapped via AES-KW (RFC 3394) under the referenced wrap key, the `KeyValue` flipped to ByteString form, and a `KeyWrappingData` structure echoing the spec. Wrap-key gating: Active state, `WrapKey` usage mask, material from Register-supplied bytes or the engine (`CKA_VALUE`). New tags verified from the spec extract: `KeyWrappingData` 0x420046, `KeyWrappingSpecification` 0x420047, `WrappingMethod` 0x42009e, `EncryptionKeyInformation` 0x420036. Engine gains `native::aes_key_wrap` / `aes_key_unwrap` (RFC 3394, KEK 128/192/256) verified against the RFC 3394 §4.1 KAT. Register-side unwrap (importing a wrapped key) remains v0.2.

- **kmip — multi-part streaming `Encrypt` + arbitrary GCM IV lengths: OASIS conformance 89 → 91 of 92 actionable tests (98.9%)** (`kmip/src/ops/encrypt.rs`, `kmip/src/ops/deps.rs`, `kmip/src/kmip30/{ops,wire}.rs`, `rust/src/crypto/multipart.rs`, `rust/src/native/encrypt.rs`). Closes CS-BC-M-GCM-2 and CS-BC-M-GCM-3, the last two crypto-op conformance failures. (1) KMIP 3.0 §6.1.21 streaming: `Init Indicator` opens a stream (server issues a `Correlation Value`), chained parts feed the engine's PKCS#11 §5.2 Update state machines held on `Deps::streams`, `Final Indicator` closes it emitting the AEAD tag — wire codec gains `InitIndicator` (0x4200d7) / `FinalIndicator` (0x4200d8) / payload `CorrelationValue` and the §6.1.21 response field ordering (IV → Correlation Value → Tag). (2) `GcmState` now accepts any SP 800-38D IV length — non-96-bit IVs derive J0 via GHASH (§7.1 step 2b; new NIST test-case-5 KAT with 64-bit IV) — and `native::aes_gcm_{en,de}crypt` were rewritten on top of it, replacing the typenum matrix (adds AES-192 + 12–16-byte truncated tags uniformly). (3) AEAD tag split honours the request's `Tag Length` (a 15-byte tag over empty plaintext previously failed the hardcoded 16-byte split). The remaining failure, AX-M-2, is the documented KMIP-key-wrapping v0.2 deferral.

### Fixed

- **kmip — `CKM_CHACHA20` / `CKM_CHACHA20_POLY1305` codepoint drift vs the engine** (`kmip/src/kmip30/algos.rs`). The kmip crate's duplicated mech table still carried `0x1071`/`0x1093` after `softhsmrustv3::constants` was corrected to the normative `pkcs11t.h` values (`0x1226`/`0x4021`), so every ChaCha20 Encrypt resolved to an unknown engine mechanism (`CKR_MECHANISM_INVALID`). Re-pinned to the spec values with `pkcs11t.h` line citations.
- **kmip conformance harness — tag-name auto-binds no longer shadow explicit corpus placeholders** (`kmip/conformance/harness/dispatcher_replay.py`). The eager `$TAG_NAME` auto-bind (added for `$MAC_DATA`) captured `$AUTHENTICATED_ENCRYPTION_TAG` from pair #1 of CS-BC-M-GCM-2, so the RandomIV pair #111's placeholder compared against a stale value. Auto-binds now live in a separate fallback map consulted only for request resolution; the comparator's bind-on-first-use always wins.
- **Docs refreshed to the 91/92 reality** (`kmip/docs/CONFORMANCE_REPORT.md`, `kmip/docs/IMPLEMENTATION_PLAN.md`, `kmip/conformance/analysis/REMEDIATION_PLAN.md`). The conformance report's "12 ops, non-conformant, harness pending" sections, the plan's "Not Started" status header, and the PR-#88-era remediation analysis (11/102) were all stale; updated/bannered with current standing.

---

## [0.6.1] — 2026-06-10

### Added

- **softhsmrustv3 — SP 800-208 SHAKE-256 LMS/HSS via `hbs-lms-patched`** (`rust/hbs-lms-patched/` (new, vendored hbs-lms 0.1.1 + patch), `rust/src/crypto/lms.rs`, `rust/src/ffi.rs`, `tests/acvp-wasm.mjs`). Upstream hbs-lms 0.1.1 hardcodes the RFC 8554 SHA-256 type IDs into all serialized keys/signatures regardless of hash family, so SHAKE-256 material carried SHA-256 type codes — the engine's own SHAKE round-trip failed and external SP 800-208 vectors could not be parsed (80 ACVP KATs permanently skipped). The patch adds per-family IANA type-ID bases to the `HashChain` trait (`LMS_TYPE_BASE`/`LMOTS_TYPE_BASE`: SHA-256 N32 0x05/0x01, N24 0x0A/0x05, SHAKE N32 0x0F/0x09, N24 0x14/0x0D), makes parameter construction/parsing family-aware, and keeps the compressed private-key format byte-compatible (canonical discriminants; family re-derived from the hash type at decode). Mirrors the C++ engine's patched `hash-sigs` submodule fix. The engine's 240-line custom SHAKE verifier is retired — all four families now sign/verify through the crate; `C_Verify` additionally derives the LMS parameter set from the self-describing public-key bytes when `CKA_LMS_PARAM_SET` is absent (external ACVP imports).

### Fixed

- **hbs-lms-patched — panic-hardened wire parsers**. All five `InMemory*::new` signature/key parsers sliced caller-controlled bytes unchecked and `.unwrap()`ed unknown type IDs — a malformed (or corrupt-by-design ACVP sigver) input aborted the entire wasm instance. New bounds-checked `try_read`/`try_read_and_advance` helpers; every parse failure now returns `None` → `CKR_SIGNATURE_INVALID`. Wire `level` field bounded before `ArrayVec` extension.
- **tests — ACVP runner loaded a stale (April 14) Rust wasm** from `wasm/rust/`; the §12.3 SHAKE SigVer KATs were also hard-skipped for the Rust engine. Both fixed; suite result moves from 51 PASS / 1 FAIL / 22 SKIP to **133 PASS / 0 FAIL / 1 SKIP** (the remaining skip is the Botan-specific SLH-DSA SigGen vector).

## [0.6.0] — 2026-06-10

**softhsmrustv3 PKCS#11 v3.2 conformance release** — the multi-part cipher work plus
the full compliance-remediation program: the R1–R3/R6.1 phases below and the executed
deferred-work plan (`docs/implementation-plan-rust-pkcs11-deferred.md`, 9 PR slices:
template validation, native-API parity, session-object lifecycle, entry-point surface,
mechanism-parameter sweep, mechanism-table reconciliation). Validation at release:
121/121 `rust/test_p11_conformance.js`, 4/4 KAT parity, 80 native unit tests,
328/328 `scripts/check_pkcs11_constants.py`.

### Added

- **softhsmrustv3 — multi-part cipher operations: `C_EncryptUpdate` / `C_EncryptFinal` / `C_DecryptUpdate` / `C_DecryptFinal` for all five AES modes** ([#89](https://github.com/pqctoday-org/pqctoday-hsm/pull/89), `rust/src/crypto/multipart.rs` (new), `rust/src/ffi.rs`, `rust/src/state.rs`). The four entry points were stubs returning `CKR_FUNCTION_NOT_SUPPORTED` — a PKCS#11 v3.2 §5.2 conformance gap. New `MultipartCipher` state machines implement streaming ECB (§6.27.2), CBC (§6.27.3), CBC_PAD (§6.27.4 — decrypt holds back the final block until `Final` to strip PKCS#7 padding), CTR (§6.27.5), and GCM (§6.27.7 — incremental GHASH via the pure-Rust `ghash` crate: AAD at Init, ciphertext streamed per-Update, tag emitted/verified constant-time at Final; decrypt withholds the trailing `tag_len` bytes since the ciphertext/tag boundary is unknowable mid-stream). Honors the §5.2 two-pass convention (NULL output → size query without consuming input; `CKR_BUFFER_TOO_SMALL` keeps the op alive; any other failure terminates it) and §5.2.5/§5.2.9 `CKR_OPERATION_ACTIVE` on double-Init. Spec-correct error codes throughout (`CKR_DATA_LEN_RANGE` vs `CKR_ENCRYPTED_DATA_LEN_RANGE` by direction, `CKR_ENCRYPTED_DATA_INVALID` for bad padding/tag). AES-192 now supported in streaming GCM (one-shot path remains 128/256). Validated against NIST SP 800-38A KATs (ECB/CBC/CTR), the canonical GCM vectors with/without AAD, cross-checks vs the one-shot `aes-gcm`/`cbc` crates across five chunk-split patterns, plus FFI-level integration tests (tag split across Update calls, lifecycle/error-priority assertions).

- **softhsmrustv3 — `CKM_AES_ECB` + `CKM_AES_CBC` exposed as first-class mechanisms** ([#89](https://github.com/pqctoday-org/pqctoday-hsm/pull/89), `rust/src/ffi.rs`, `rust/src/constants.rs`). Both raw block modes now work through single-shot `C_Encrypt`/`C_Decrypt` (routed through the streaming state machines) and appear in `C_GetMechanismList` / `C_GetMechanismInfo`.

- **softhsmrustv3 — PKCS#11 v3.2 compliance gap analysis + R1–R3/R6.1 remediation** (`docs/gap-analysis-rust-pkcs11-v3.2.md` (new), `rust/src/ffi.rs`, `rust/src/state.rs`, `rust/src/crypto/handlers.rs`, `rust/src/constants.rs`). Library lifecycle enforcement per §5.4/§5.6 — `require_init!()` gates on every entry point (`CKR_CRYPTOKI_NOT_INITIALIZED`), strict double-`C_Initialize` (`CKR_CRYPTOKI_ALREADY_INITIALIZED`), `C_Finalize` zeroizes key material and resets lifecycle; session-handle validation (`CKR_SESSION_HANDLE_INVALID`) ordered per §5.1 error priority; server-managed read-only attributes (`CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_LOCAL`, `CKA_KEY_GEN_MECHANISM`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`, `CKA_CHECK_VALUE`) are no longer absorbable from caller templates (prevents key-provenance forgery). See the gap-analysis doc's remediation ledger for per-item detail.

- **softhsmrustv3 — PKCS#11 v3.2 conformance suite + CI constants guard** (`rust/test_p11_conformance.js` (new, 121 checks), `scripts/check_pkcs11_constants.py` (new)). Table-driven negative-path matrix asserting exact CKR_* codes in §5.4/§5.12 priority order (init → session → key → operation → buffer); scripted diff of every `constants.rs` value against the normative `pkcs11t.h` (whitelisted vendor/IANA names) — permanently prevents the wrong-mechanism-ID bug class. The harness found two real memory-safety bugs on day one (see Fixed).

- **softhsmrustv3 — ML-DSA context string + hedge variant (FIPS 204 §5.2 / §6.67)** (`rust/src/ffi.rs`, `rust/src/crypto/handlers.rs`). `CK_SIGN_ADDITIONAL_CONTEXT` parsed for ML-DSA and SLH-DSA (pure + all pre-hash variants) at every sign/verify init site; context >255 bytes now `CKR_MECHANISM_PARAM_INVALID` (was silently dropped to empty); `CKH_HEDGE_PREFERRED/REQUIRED/DETERMINISTIC_REQUIRED` validated; deterministic mode via the FIPS 204 zero-rnd substitution; context threaded through `sign_ml_dsa`/`verify_ml_dsa`. Tests: ctx round-trip, cross-context verify failure, deterministic repeatability, hedged uniqueness.

- **softhsmrustv3 — full pkcs11f.h v3.2 entry-point surface** (`rust/src/ffi.rs`). `C_GetInterfaceList`/`C_GetInterface` ("PKCS 11" v3.2 negotiation; the wasm function-pointer constraint is documented — the JS shim is the function table); `C_CloseAllSessions`; `C_SessionCancel` (flag-selected operation cancellation with message-state key zeroization); `C_LoginUser`; `C_SignMessageBegin/Next` + `C_VerifyMessageBegin/Next` (multipart-message accumulators with §5.2-preserving final calls); spec-mandated stubs for legacy/recover/dual-function ops (`CKR_FUNCTION_NOT_PARALLEL`, `CKR_NO_EVENT`, `CKR_FUNCTION_NOT_SUPPORTED`). `C_MessageSignFinal` corrected from a 5-arg shape to the 1-arg pkcs11f.h declaration (pqctoday-hub callers updated in lockstep).

- **softhsmrustv3 — mechanism-parameter compliance sweep** (`rust/src/ffi.rs`, `rust/src/crypto/handlers.rs`, `rust/src/crypto/multipart.rs`). GCM `ulTagBits` validated per SP 800-38D §5.2.1.2 ({0,32,64,96,104,112,120,128} — 32/64 retained for KMIP CS-BC-M-GCM-1 truncatable tags) and honored in single-shot, which is now routed through the KAT-verified streaming `GcmState` (single-shot ≡ multipart byte-for-byte); `ulIvBits` consistency enforced. AES-CTR `ulCounterBits` validated (byte-granular) and honored via a width-parameterized counter in both single-shot and multipart. RSA-PSS `CK_RSA_PKCS_PSS_PARAMS` parsed and validated (caller `sLen` pinned; param-less native/KMIP paths keep the documented dual-salt acceptance). RSA-OAEP full parameters (hash × MGF1 matrix + UTF-8 label) across Encrypt/Decrypt/Wrap/Unwrap; OAEP decode failures uniformly `CKR_ENCRYPTED_DATA_INVALID` (padding-oracle hygiene). SP 800-108 counter+feedback KDFs honor ordered `CK_PRF_DATA_PARAM` segments (counter width/endianness, [L]₂ DKM-length field). Five `CKM_*_HMAC_GENERAL` mechanisms end-to-end (truncated MACs, constant-time verify, `CKR_SIGNATURE_LEN_RANGE` on wrong-length signatures). KMAC customization string + variable output length (`sign_kmac_ext`).

- **softhsmrustv3 — `C_CreateObject` template validation (§4.1.1)** (`rust/src/ffi.rs`). `CKA_CLASS` and `CKA_KEY_TYPE` required (`CKR_TEMPLATE_INCOMPLETE`), class↔key-type consistency (`CKR_TEMPLATE_INCONSISTENT`), per-class key-material requirements, AES value-length checks (`CKR_ATTRIBUTE_VALUE_INVALID`). Closes the missing-`CKA_CLASS` sensitivity bypass (class defaulted to CKO_PUBLIC_KEY, exposing an imported secret key's `CKA_VALUE`).

- **softhsmrustv3 — session-object lifecycle (§4.4)** (`rust/src/state.rs`, `rust/src/ffi.rs`). Objects carry their creating session (`CKA_PRIV_OWNER_SESSION`, set across all 27 C-ABI creation sites); session objects (`CKA_TOKEN=FALSE`) are destroyed and zeroized at `C_CloseSession`; token objects and native/KMIP-registered (library-scoped) objects survive session churn.

### Changed

- **softhsmrustv3 — native-API parity hardening** (`rust/src/state.rs`, `rust/src/native/object.rs`, `rust/src/native/keygen.rs`). Raw `state::` object accessors demoted to `pub(crate)`; one shared `value_is_blocked` predicate — `CKA_VALUE` of private/secret keys now blocked when `CKA_SENSITIVE=TRUE` **or** `CKA_EXTRACTABLE=FALSE` on both the C-ABI and native surfaces; new `native::object::set_attribute` enforcing read-only attributes and the one-way `CKA_SENSITIVE`/`CKA_EXTRACTABLE` transitions (vendor stateful-key attrs exempt — they are the engine/KMIP state channel). Symmetric native keygen defaults flipped to `CKA_EXTRACTABLE=TRUE` (coherent with `SENSITIVE=FALSE`; keeps KMIP Get/Export working under the stricter gate); import/Register paths get explicit §4.3 provenance defaults (`LOCAL=FALSE`, `KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION`, `ALWAYS_SENSITIVE`/`NEVER_EXTRACTABLE=FALSE`).

- **softhsmrustv3 — mechanism-table reconciliation (R6.2)** (`rust/src/ffi.rs`, `rust/src/constants.rs`). All 11 advertised-but-unanswerable mechanisms (raw ECDSA, EdDSA-ph, parametrized HASH_ML_DSA/HASH_SLH_DSA, HSS/XMSS/XMSS^MT keygen+sign, Keccak-256) now answerable by `C_GetMechanismInfo`; `CKF_MESSAGE_*` flags advertised on ML-DSA/SLH-DSA/AES-GCM; AES-192 accepted by `C_GenerateKey` (resolves the keygen/native/mechanism-info three-way disagreement). A unit test (`supported_mechs_all_have_info`) pins `SUPPORTED_MECHS` ↔ `mechanism_info` so the two tables can never drift again.

### Fixed

- **softhsmrustv3 — misaligned-pointer panic on legal caller templates** (`rust/src/crypto/handlers.rs`, `rust/src/state.rs`). `get_attr_ulong` performed an aligned `u32` deref of `CK_ATTRIBUTE.pValue`, which carries no alignment guarantee — a perfectly legal unaligned template panicked the whole engine (found by the new conformance harness on its first run). Fixed with `read_unaligned`; engine `_malloc` now uses align-8 layouts (`_free` matched) so caller-built template arrays are always aligned.

- **softhsmrustv3 — ECDSA SHA3-512-on-P-384 digest truncation (FIPS 186-5 §6.4)** (`rust/src/crypto/handlers.rs`). The SHA-3 pre-hash arms fed the full 64-byte digest into the P-384 signer/verifier; now truncated to the 48-byte field size on both sign and verify (the SHA-2 arms already did this).

- **softhsmrustv3 — `static mut KAT_SEED` UB + dangling-pointer hack + null-deref sweep** (`rust/src/crypto/xmss_bridge.rs`, `rust/src/ffi.rs`). KAT seed moved behind a Mutex; `C_VerifySignatureFinal`'s fabricated `4 as *mut u8` empty-message pointer replaced with a valid backing buffer; null-checks added across `C_Sign`/`C_Verify`/`C_GetAttributeValue`/`C_FindObjects`/`C_DecapsulateKey`/`C_GenerateKeyPair` in/out pointers (`CKR_ARGUMENTS_BAD` instead of a wasm memory[0] access).

- **test scripts — latent template bug** (`rust/test_kat_parity.js`). The ChaCha20 import template passed `CKA_CLASS=3` (CKO_PRIVATE_KEY) while its own comment said CKO_SECRET_KEY (=4) — caught by the new template validation; fixed to 4.
- **softhsmrustv3 — `native::session::init()` made idempotent** (`rust/src/native/session.rs`). With strict §5.6 double-init now in force, the typed wrapper absorbs the non-fatal `CKR_CRYPTOKI_ALREADY_INITIALIZED` so composed helpers (`bootstrap_default_token`) keep working.
- **softhsmrustv3 — stale test expectations vs current spec behavior** (`rust/src/native/keygen.rs`, `rust/src/native/parity.rs`, `rust/test_kat_parity.js`). AES-192 keygen is valid per §6.5 (was asserted to fail); `C_SignInit` on a destroyed handle returns `CKR_KEY_HANDLE_INVALID` per §5.1 error priority (was `CKR_KEY_FUNCTION_NOT_PERMITTED`); KAT parity harness opens sessions with the mandatory `CKF_SERIAL_SESSION` flag per §5.6.

---

## [0.5.0] — 2026-06-04

**Major release** — first release after the stale v0.4.25 Cargo.toml manifest. Aggregates 60+ commits since v0.4.26 across the Rust WASM engine, C++ engine, strongSwan integration (upgraded to 6.0.6 with full SLH-DSA), pkcs11-provider (composite-sig + ML-KEM CMS), OpenMLS provider, OpenPGP bridge, and openssh-pkcs11. Required base for the upcoming `pqctoday-hsm/kmip/` subsystem.

### Fixed

- **softhsmrustv3 — XMSS `C_Sign` → `CKR_FUNCTION_FAILED` + ECDSA P-521 sig length + SEC1 long-form DER** ([#63](https://github.com/pqctoday-org/pqctoday-hsm/pull/63), `rust/src/ffi.rs`, `rust/src/crypto/handlers.rs`, `rust/src/state.rs`). Three PKCS#11 v3.2 compliance gaps surfaced by pqctoday-hub's `HsmAcvpTesting` workshop. (1) `C_GenerateKeyPair(CKM_XMSS_KEY_PAIR_GEN)` stored the raw `param_code` from `CK_XMSS_PARAMS` in `CKA_XMSS_PARAM_SET`; when the caller omitted the struct, the stored 0 fell through `xmss_sign`'s `CKP_XMSS_*` match → catch-all `CKR_FUNCTION_FAILED`. Fix: store the *effective* param (default `CKP_XMSS_SHA2_10_256`). (2) `get_sig_len(CKM_ECDSA_SHA512, _)` returned a hardcoded 64 B regardless of curve; ECDSA size is `2 × ⌈curve_bits/8⌉` (P-521 → 132 B). Size-query returned 64 → caller allocated 64 → sign wrote 132 → `CKR_BUFFER_TOO_SMALL`. Fix: curve-aware lookup across all ECDSA mechanism arms. (3) `get_ec_point_sec1` only stripped DER OCTET STRING **short-form** length (`0x04 <len ≤ 127> <data>`); P-521's 133-byte SEC1 point requires **long-form** (`0x04 0x81 0x85 <data>`). Keygen already emitted long-form; the strip helper now recognizes it. Short-form path preserved (P-256 / P-384 / secp256k1 unaffected). Verified XMSS Stateful + ECDSA P-521 + secp256k1 (regression) sign+verify all PASS in-browser.

- **softhsmrustv3 — KCV missing on `C_UnwrapKey` / `C_DeriveKey` + RSA public key missing `CKA_VALUE`** ([#62](https://github.com/pqctoday-org/pqctoday-hsm/pull/62), `rust/src/ffi.rs`). Two PKCS#11 v3.2 compliance gaps surfaced in pqctoday-hub's `/learn/kms-pqc` Envelope Encryption workshop. (1) `C_UnwrapKey`, `C_UnwrapKeyAuthenticated`, `C_DeriveKey` (§5.18.4 / §5.18.7 / §6.5.6) built new secret-key objects but never called `compute_kcv` before `allocate_handle`. §4.10.2 + §4.11 require `CKA_CHECK_VALUE` regardless of creation path. `C_GetAttributeValue(CKA_CHECK_VALUE)` on an unwrapped AES DEK returned `CKR_ATTRIBUTE_TYPE_INVALID`. Fix at 4 call sites (RSA-OAEP/AES-KW unwrap, AES-GCM authenticated unwrap, ECDH/X25519 derive, HKDF/SP800-108 derive). (2) `C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN)` stored modulus + exponent in spec attributes but not in the packed `[n_len:4LE][n_bytes][e_bytes]` form under `CKA_VALUE` that the Rust engine's `C_Encrypt` + `C_WrapKey(CKM_RSA_PKCS_OAEP)` parse. Every RSA-OAEP wrap returned `CKR_ARGUMENTS_BAD`. The C++ engine doesn't have this issue because OpenSSL EVP_PKEY carries both halves natively. Verified ML-KEM-768 / AES-KW AND RSA-2048 / RSA-OAEP flows now end-to-end with KCV displayed and integrity verified.

- **softhsmv3 C++ engine — `CKA_CHECK_VALUE` populated on `C_UnwrapKey` + `C_DeriveKey`** ([#61](https://github.com/pqctoday-org/pqctoday-hsm/pull/61), `src/lib/SoftHSM_keygen.cpp`). PKCS#11 v3.2 §4.11 mandates `CKA_CHECK_VALUE` "regardless of how the key object is created or derived." Every `C_GenerateKey` path was compliant, but `C_UnwrapKey` and four `C_DeriveKey` paths (PBKD2, SP800-108 Counter, SP800-108 Feedback, HKDF) silently skipped it → `CKR_ATTRIBUTE_TYPE_INVALID` on the recovered key. Mirrors the Rust engine fix in PR #62.

- **composite-sig — 8 root-cause fixes + dormant SPKI decoder (`X509_sign` works end-to-end)** (`vendor/pkcs11-provider/`). Resolves the LAMPS draft-19 composite-sig path through `pkcs11-provider` → softhsmv3. Composite OIDs now sign + verify under `X509_sign` for cert issuance.

- **pkcs11-provider — ML-KEM CMS decrypt end-to-end via softhsm** (`vendor/pkcs11-provider/`). CMS AuthEnvelopedData (KEMRecipientInfo per RFC 9629/9936) now decapsulates a wrapped CEK using an ML-KEM key resident in softhsmv3, then unwraps the CEK and decrypts the inner payload — fully driven through pkcs11-provider, no JS-side fallback.

- **pkcs11_dh — WASM `C_Login` guard in `find_token`** (`strongswan-pkcs11/pkcs11_dh.c`). Same WASM-routing fix previously applied to `pkcs11_kem.c`. Without this, ECDH key agreement during IKEv2 failed at token-find when the WASM build's softhsm context required a synthetic Login.

- **traced_C_GenerateKeyPair — belt-and-suspenders `C_Login` guard** (`strongswan-pkcs11/`). Defensive Login check on the traced wrapper so a missing session login on the WASM build doesn't surface as a generic generate-key failure.

- **composite-provider — wire composite / KEM / SLH-DSA / XMSS sources into meson build** (`vendor/pkcs11-provider/meson.build`). The composite + PQC source files existed but weren't compiled into the provider .so / .a, so symbols were missing at link time. Now wired and built.

### Added

- **strongSwan 6.0.6 — full SLH-DSA support in PKCS#11 plugin** (`strongswan-pkcs11/`). New feature registrations and crypto plumbing for SLH-DSA (SHA2-128s / 192s / 256s) on both PRIVKEY and PUBKEY paths. Enables IKEv2 `leftauth=pubkey` with SLH-DSA-signed certificates routed through softhsmv3.
- **strongSwan 6.0.6 patches** (`patches/strongswan-6.0.6-pqc-slhdsa.patch`, plus dry-run-verified variants). Upgraded the IKEv2 base from 6.0.5 → 6.0.6 with the PQC + SLH-DSA stack rebased on top. Required by `Dockerfile.network`.
- **softhsm-wasm-v2 — emscripten 5.0.7 rebuild + `pkcs11_dh` Login fix bundled**. Bumped the published WASM artifact to the new emscripten + the `pkcs11_dh` C_Login guard above.

### Changed

- **`rust/Cargo.toml` version**: `0.4.25` → `0.5.0`. The 0.4.25 manifest had been stale since 2026-04-15 despite v0.4.26–v0.4.29 tags shipping; this catches the Rust crate up to the release line.

### Notes

- Untracked `kmip/` directory in the working tree is an unreleased standalone subsystem (KMIP 3.0 wrapper over PKCS#11) — explicitly NOT shipped in this release. See `kmip/docs/IMPLEMENTATION_PLAN.md` for scope.
- The entries below were previously under `[Unreleased]` while v0.4.27–v0.4.29 shipped without CHANGELOG updates. Folded into this release for a single source of truth.

### Fixed (continued — folded from prior [Unreleased])

- **softhsmrustv3 (WASM engine) — AES-GCM AAD authentication restored** (`rust/src/ffi.rs`). Critical correctness + security bug: AES-GCM in the Rust/WASM engine silently dropped the AAD parameter on both encrypt and decrypt — meaning every in-browser AES-GCM operation produced *unauthenticated* ciphertext (the tag was computed over empty AAD regardless of what the caller passed). The C++ engine (`src/lib/SoftHSM_cipher.cpp` + `src/lib/crypto/OSSLEVPSymmetricAlgorithm.cpp`) used by native softhsmv3.so/.dylib was unaffected.

  Surfaced when `/learn/mls-group-messaging` Step 3 (AES-128-GCM application message demo in pqctoday-hub) reported `✗ AAD check did not throw — unexpected` against a perfectly correct test. Reproducer: encrypting identical plaintext+IV+key with three different AAD values produced byte-for-byte identical ciphertext+tag — proof that AAD was never folded into GHASH.

  Compare the `CKM_CHACHA20_POLY1305` branch at ffi.rs:2789 which already used `Payload { msg: plaintext, aad: &aad }` correctly. The AES-GCM branch was half-finished — Init parsed only IV from `CK_GCM_PARAMS`, never read `pAAD` / `ulAADLen`, and `*gcm.add(4)` was treated as `tag_bits` even though that offset is `ulAADLen` (the real `ulTagBits` is at `*gcm.add(5)`).

  Seven fix sites in `rust/src/ffi.rs`:

  | Site | Bug → Fix |
  | --- | --- |
  | `C_EncryptInit` GCM branch (≈ line 2583) | Never read `pAAD` / `ulAADLen`; read `ulAADLen` into `tag_bits` slot. → Read `aad_ptr` from `*gcm.add(3)`, `aad_len` from `*gcm.add(4)`; move `tag_bits` to `*gcm.add(5)`; bump `ul_param_len` floor 20 → 24. |
  | `C_Encrypt` GCM branch (≈ line 2696) | `cipher.encrypt(nonce, plaintext)` auto-coerced `&[u8]` → `Payload { msg, aad: &[] }`. → `cipher.encrypt(nonce, Payload { msg: plaintext, aad: &aad })` for both Aes128Gcm and Aes256Gcm. |
  | Encrypt size-query re-insert (≈ line 2820) | Wiped AAD with `Vec::new()` between the dual-call PKCS#11 length-query pattern. → Preserve `aad` field. |
  | `C_DecryptInit` GCM branch (≈ line 2854) | Same parsing bugs as `C_EncryptInit`. → Same fix. |
  | `C_Decrypt` state extract (≈ line 2928) | Destructured ctx as `(mech_type, key_handle, iv, tag_bits)` — never pulled `aad`. → Added `aad` to the tuple. |
  | `C_Decrypt` GCM branch (≈ line 2940) | `cipher.decrypt(nonce, ciphertext)` dropped AAD. → `cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &aad })`. |
  | Decrypt size-query re-insert (≈ line 3046) | Same wipe as encrypt. → Preserve `aad` field. |

  Validation:

  - WASM produces NIST GCM Test Case 4 byte-exact output now: ciphertext `522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662` + tag `76fc6ece0f4e1768cddf8853bb2d551b` (per McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", also NIST SP 800-38D). The pqctoday-hub NIST KAT was previously self-pinned to the buggy tag `eb9f796c8d356fc31a8433884b696f4f` — fixed in pqctoday-hub at the same time.
  - Two new regression-guard KATs added to pqctoday-hub: tag-divergence (changing AAD must change last 16 bytes) and AAD-tamper (decrypt with wrong AAD must throw). All 17 tests in `softhsm.kat.test.ts` pass.
  - Rebuilt WASM bundle deployed into pqctoday-hub at `src/wasm/softhsmrustv3_bg.wasm` via `cargo build --target wasm32-unknown-unknown --release` + `wasm-bindgen --target bundler --no-typescript`. Custom `__wbg_get_memory()` shim re-added to `softhsmrustv3.js` / `softhsmrustv3_bg.js` per the post-build pattern in `feedback-wasm-bindgen-bundler-target`.

  Notes for future audits: the previous NIST KAT in pqctoday-hub was effectively `assertEqual(buggyOutput, buggyOutput)` — the expected tag was a snapshot of this implementation's own output, not the actual NIST vector. Any future pinned KAT in this repo should be cross-checked against a second independent implementation (Node 24's native `crypto.createCipheriv('aes-256-gcm', ...)`, or the upstream NIST/RFC vector itself) before being committed, per [feedback-pqc-kat-harness](../../.claude/projects/-Users-ericamador-antigravity-pqctoday-hub/memory/feedback-pqc-kat-harness.md).

- **strongSwan WASM — ML-DSA-65 dual-auth IKEv2 reaches `ESTABLISHED` end-to-end** (closes the WIP entry below). Resolves four chained root causes; fixing only one was insufficient.

  1. **Explicit private-key load via `BUILD_PKCS11_KEYID`** (`strongswan-wasm-shims/wasm_backend.c`): upstream `strongswan-pkcs11/pkcs11_creds.c:241` wires `create_private_enumerator = enumerator_create_empty` — meaning credmgr's `get_private_by_keyid` always returns NULL for PKCS#11 keys *unless* the private key was previously loaded via `lib->creds->create(BUILD_PKCS11_KEYID, ...)` and inserted into a `mem_cred` set. Real strongSwan deployments do this in stroke / vici / nm config plugins; the WASM build has none of those plugins. Fix: in `wasm_setup_config` (dual-auth branch) decode `WASM_LOCAL_KEYID` env hex to a `chunk_t`, call `lib->creds->create(CRED_PRIVATE_KEY, KEY_ANY, BUILD_PKCS11_KEYID, chunk, BUILD_END)`, register the result via `mem_cred->add_key` + `lib->credmgr->add_set`. Without this, IKE_AUTH always fails with `no private key found for '<keyid>'`.

  2. **`cert_policy = CERT_ALWAYS_SEND` for dual auth** (`strongswan-wasm-shims/wasm_backend.c`): default `CERT_SEND_IF_ASKED` keeps the cert off the wire when the peer didn't include a `CERTREQ` (which our self-signed setup doesn't). Without the cert, the peer can't extract the pubkey to verify the signature and returns `IKE_AUTH response 1 [ N(AUTH_FAILED) ]`. Fix: set `peer_data.cert_policy = CERT_ALWAYS_SEND` when `wasm_auth_mode == 1`. With this, IKE_AUTH carries `[ IDi CERT N(INIT_CONTACT) IDr AUTH ... ]` (~9 KB).

  3. **Peer cert as trust anchor** (`strongswan-wasm-shims/wasm_backend.c`): even with the cert on the wire, the verifier needs to trust the issuer. For self-signed certs that means the cert IS the anchor. Fix: each worker now also reads the *peer's* cert from `/etc/ipsec.d/certs/{peer}.crt` (already written by the panel via `WRITE_FILES`) and registers it via `mem_cred->add_cert(creds, /*trusted=*/TRUE, peer_cert)` in a separate set.

  4. **Identity hex env vars must be in `preRun` ENV, not late-set on START** (panel-side fix in pqctoday-hub `VpnSimulationPanel.tsx::generateCertsViaWorker`, but recorded here because the symptom appeared on the C side as `getenv("WASM_LOCAL_KEYID")` returning NULL despite JS having set it). Emscripten snapshots `ENV` during `preRun`; setting `ENV[k] = v` after Module instantiation has no effect on `getenv()` from C. The hub now pre-generates the 20-byte CKA_IDs *before* `engine.init`, passes them in INIT-payload `keyIds`, so preRun seeds the C env table correctly.

  Verified end-to-end:

  - `[CFG] WASM: loaded PKCS#11 private key for keyid <hex> into mem_cred` (both peers)
  - `[CFG] WASM: loaded peer cert from /etc/ipsec.d/certs/{peer}.crt as trust anchor` (both peers)
  - `[PKCS#11 INIT] C_SignInit mech=CKM_ML_DSA → CKR_OK`, `C_Sign sigLen=3309 → CKR_OK`
  - `[PKCS#11 RESP] C_VerifyInit mech=CKM_ML_DSA → CKR_OK`, `C_Verify dataLen=2175 sigLen=3309 → CKR_OK` (and reverse)
  - `[CFG] using trusted certificate "CN=vpn-{initiator,responder}, O=PQC-Simulation"`
  - `[IKE] authentication of '<peer-id>' with ML_DSA_65 successful` (both directions)
  - `[IKE] IKE_SA wasm[1] state change: CONNECTING => ESTABLISHED` (both peers)

  Cosmetic remainder: post-establish CHILD_CREATE re-runs and trips on `unable to allocate SPI from kernel` → `ESTABLISHED => DESTROYING`. The IKE_SA itself reaches ESTABLISHED with full ML-DSA cert auth before this happens; the panel `[SIM] CREATE_CHILD_SA` lines simulate the child SA establishment for the visualization. Pre-existing issue documented in the kernel-IPSec section below — not regressed by this change.

### Added

- **OpenMLS interop — `GroupContextExtensionsProposal` RPC + IETF gating-test harness** (`openmls-provider/interop/src/lib.rs`, `openmls-provider/interop/run-gating-tests.sh`, `openmls-provider/interop/reports/`, `.github/workflows/openmls-interop.yml`): implemented the 22nd of 34 IETF `mls_client.MLSClient` RPCs — `GroupContextExtensionsProposal`. Three layered fixes were needed before openmls's commit-validator accepted the resulting proposal:

  1. **Proto extension decoding** (`decode_proto_extension` helper): proto `Extension(extension_type, extension_data)` pairs arrive as raw bytes. Wrapping every entry as `Extension::Unknown(N, bytes)` caused openmls to miss `RequiredCapabilities` / `ExternalSenders` and fall through to leaf-node capability checks with `Required extensions: [Unknown(5)]`. Fix: TLS-deserialize the five default extension types (`ApplicationId` 1, `RatchetTree` 2, `RequiredCapabilities` 3, `ExternalPub` 4, `ExternalSenders` 5) from their payload bytes; only fall back to `Unknown` for truly unrecognised type IDs.

  2. **Auto-patch `RequiredCapabilities`** (handler body): when the proposed extension set still contains `Extension::Unknown(N, _)` entries, scan them and either extend the existing `RequiredCapabilitiesExtension` or insert a fresh one listing those type IDs. Without this, `validate_group_context_extension_proposal` in `openmls/.../public_group/validation.rs` fires `ExtensionNotInRequiredCapabilities` at commit time.

  3. **`Extensions::<GroupContext>::from_vec`**: imported `GroupContext` validator so duplicate-type errors surface as `Status::invalid_argument` instead of silent corruption.

  Also landed:

  - **`run-gating-tests.sh`** — bash-3.2-compatible (no `declare -A`) runner that loops `pqctoday vs {openmls, mls-rs} × {welcome_join, commit, external_join}` and writes each scenario report to `reports/{peer}_{scenario}_{UTC}.json`. Reports are kept in the repo for audit trail.
  - **`.github/workflows/openmls-interop.yml`** — nightly (04:30 UTC) + `workflow_dispatch` CI that builds the pqctoday + peer Docker images, runs the gating script, uploads reports as artifacts (90-day retention), and dumps `docker compose logs pqctoday` on failure. Heavy (~30 min cold cache) so deliberately not on every PR — Rust-side coverage stays in `openmls-provider.yml`.

  Gating-test results (pqctoday vs openmls, cipher suites 1+2+3):

  | Scenario        | Result                          |
  | --------------- | ------------------------------- |
  | `welcome_join`  | PASS                            |
  | `commit`        | FAIL (538 / ~1780 — see below)  |
  | `external_join` | PASS                            |

  Of the 538 `commit` failures: **524 are on the openmls reference side** (`Group context extension is not implemented yet` — openmls 0.8.1 has no implementation either); 6 are us deferring `Commit.by_value{groupContextExtensions}` (needs a `CommitBuilder` refactor — 6/1780 = 0.3%); 8 are pre-existing `force_path:true + resumptionPSK by_value` decryption/confirmation-tag bugs scoped for separate investigation. Net real-pqctoday-bug rate: 14 of ~1780 scenarios = **0.8%**.

- **PKCS#11 v3.2 compliance test — CKA_ID retrieval coverage** (`p11_v32_compliance_test.cpp`): added `test_cka_id_retrieval()` (registered under category `cka-id`) with 6 cases covering the lookup pattern strongswan-pkcs11 uses at IKE_AUTH (`pkcs11_private_key.c::find_lib_by_keyid`):
  1. `Setup_KeyGen` — generate ML-DSA-65 keypair with explicit `CKA_ID` + `CKA_PRIVATE=FALSE` on pubkey
  2. `FindByCkaId_Pubkey_LoggedIn` — `C_FindObjects({CKA_CLASS=PUBLIC, CKA_ID})` from logged-in session
  3. `FindByCkaId_Privkey_LoggedIn` — same template with `CKA_CLASS=PRIVATE`
  4. ★ `FindByCkaId_Pubkey_NoLogin` — opens fresh public-only RO session (mirrors charon's session) and verifies `CKA_PRIVATE=FALSE` on the hit
  5. `Default_CkaPrivate_Pubkey` — verifies PKCS#11 v3.2 §4.5: pubkey `CKA_PRIVATE` defaults to FALSE
  6. `Default_CkaPrivate_Pubkey_NoLoginFind` — confirms default-`CKA_PRIVATE` pubkey is findable from no-login session

  All 6 PASS against `libsofthsmv3.dylib`, confirming softhsm itself was always correct — the bug was in the strongswan plugin path, not the HSM core. Run via:
  `./build_fresh/p11_v32_compliance_test --engine ./build_fresh/src/lib/libsofthsmv3.dylib --category cka-id`

- **In-WASM softhsm health probe at charon startup** (`strongswan-wasm-shims/wasm_backend.c`): `wasm_setup_config` now logs (via `fprintf(stderr)`, which Emscripten routes to the panel's printErr handler) the slot list, per-slot pubkey count, and the result of charon's exact CKA_ID-filtered query. Used to confirm pre-fix that the keys were correctly stored and findable in the in-process softhsm — isolating the bug to strongswan-pkcs11's call path. Tagged `WASM-DIAG:` for grep, can be removed for a clean release build.

### Work in progress (superseded by the Fixed entries above)

  **C-side changes that landed (build #18, 13.8 MB):**

  - **`pkcs11_wasm_C_GetFunctionList` wrapper** (`pkcs11_wasm_rpc.c`): drop-in replacement that calls real `C_GetFunctionList`, then runs the result through `pkcs11_wasm_wrap_function_list` so the strongswan-pkcs11 plugin (which dlsym's its function list) gets the **traced shadow** instead of the raw softhsmv3 table. Without this wrapper, only `pkcs11_kem.c`'s direct `wasm_pkcs11_trace_kem` calls reached the panel — every other crypto op went through the unwrapped fl and was invisible.
  - **Crypto-only trace shim set** (`pkcs11_wasm_rpc.c`): replaced 10 admin-op shims with 14 crypto-only shims (`C_GenerateKeyPair`, `C_GenerateKey`, `C_SignInit`, `C_Sign`, `C_VerifyInit`, `C_Verify`, `C_DigestInit`, `C_Digest`, `C_DeriveKey`, `C_EncryptInit`, `C_Encrypt`, `C_DecryptInit`, `C_Decrypt`, `C_GenerateRandom`). ML-KEM `C_EncapsulateKey`/`C_DecapsulateKey` traces continue to come from `pkcs11_kem.c`'s direct extern path.
  - **EXPORTED_FUNCTIONS expanded** (`scripts/build-strongswan-wasm.sh`): added `_pkcs11_wasm_C_GetFunctionList`, `_C_GetSlotList`, `_C_OpenSession`, `_C_CloseSession`, `_C_Login`, `_C_GenerateKeyPair`, `_C_GetAttributeValue`, `_C_SignInit`, `_C_Sign` so the panel's worker-RPC handler can call them directly via `Module._C_*`.
  - **EXPORTED_RUNTIME expanded** (`scripts/build-strongswan-wasm.sh`): added `HEAPU8`, `HEAP32`, `HEAPU32`, `getValue`, `setValue` so the worker handler can marshal byte buffers and call PKCS#11 functions directly without `'HEAPU8' was not exported` runtime aborts.

  **What still doesn't work:** charon's strongSwan-pkcs11 plugin loads, finds the token (no more `TOKEN_NOT_RECOGNIZED`), enumerates mechanisms, then never attempts to load `/etc/ipsec.d/certs/*.crt` from the WASM FS or call `C_FindObjects(CKA_ID=ski)` to locate a private key. IKE_AUTH proceeds with PSK MAC even when `ipsec.conf` declares `leftauth=pubkey leftcert=...`.

  **Suspected (unverified) cause:** ipsec.conf legacy format may not auto-load filesystem certs the same way `swanctl` does, OR a step in `pkcs11_creds.c` / `pkcs11_private_key.c` that we haven't traced. Next session: read those two source files end-to-end before adding more glue.

  **Note:** the prior `pkcs11_wasm_rpc_function_list` "memcpy stub" entry below is partially superseded — the wrapper now installs a real traced shadow. The ML-DSA cert-auth blocker is no longer the two-instance softhsm split (worker softhsm has the keys via panel-driven RPC) but rather the unverified strongSwan-pkcs11 cert-load path.

### Fixed

- **strongSwan WASM — full IKE_SA `ESTABLISHED` end-to-end with real ML-KEM-768 + PSK auth** (`scripts/build-strongswan-wasm.sh`, `strongswan-pkcs11/pkcs11_kem.c`, `strongswan-wasm-shims/socket_wasm.c`, `strongswan-wasm-shims/wasm_backend.c`): the WASM charon now completes a full IKEv2 handshake between two browser Web Workers, with real ML-KEM-768 keypair generation, encapsulation, decapsulation via softhsmv3, and PSK MAC verification. Final log lines from a successful run:

  ```text
  IKE_SA wasm[1] established between 192.168.0.1...192.168.0.2
  IKE_SA wasm[1] state change: CONNECTING => ESTABLISHED
  ```

  This was achieved via a chain of fixes spanning ten rebuilds, each targeting a distinct blocker. Documenting the chain because the same patterns are likely to recur in other strongSwan-on-WASM efforts:

  - **Cross-worker packet transport rewritten** (`socket_wasm.c`): the original `wasm_net_send` wrote to `Module._wasm_net_sab` (the worker's own inbox) and the bridge had no polling loop, so workers self-loopbacked instead of communicating. Replaced with a `self.postMessage({type: 'PACKET_OUT', ...})` so the bridge's existing `case 'PACKET_OUT'` actually fires and routes to the peer worker's SAB. Receive side updated in lock-step: `Int32Array(sab, 0, 6)` (was 4) so the 6-i32 header from the bridge — including `dst_ip` — plumbs through to charon's IKEv2 config matcher. Body offset moved from 16 to 24 to match. Without this, every previous "successful" cross-worker test was self-loopback masquerading as cross-worker delivery.

  - **`wasm_create_ike_enum` projects peer_cfgs → ike_cfgs** (`wasm_backend.c`): was returning `enumerator_create_empty()` with a comment claiming "the responder branch is driven by peer_cfgs directly" — wrong. `find_ike_cfg()` (in `backend_manager.c`) drives this on the responder when an IKE_SA_INIT request arrives — no peer_cfg has been chosen yet because IDs only show up in IKE_AUTH. With no ike_cfg returned, the responder logs `no IKE config found for 192.168.0.2...192.168.0.1` and replies `NO_PROPOSAL_CHOSEN` even when peer_cfgs is populated. Fix: project via `enumerator_create_filter` — same `CALLBACK` pattern as `pkcs11_creds.c::certs_filter`. The `me`/`other` args are unused here; charon's backend_manager handles host-match filtering after we return the candidates.

  - **PKCS#11 v3.2 KEM functions resolved at link time, not via dlopen** (`pkcs11_kem.c::get_v3_kem_funcs`): on native, strongSwan dlopens `libsofthsmv3.so` and dlsyms `C_EncapsulateKey` / `C_DecapsulateKey` because pkcs11-spy < 0.26 doesn't forward the v3 entry points in the function list (so casting `this->lib->f` to `CK_FUNCTION_LIST_3_0*` reads garbage). The browser has no dynamic linker. Under `__EMSCRIPTEN__` we now bind both via extern declarations matching `encap_fn_t` / `decap_fn_t`; same in-process instance as everything else (handleManager state shared).

  - **Status helpers widened to match slot signatures** (`status.c`, `utils.c`, build script): `return_need_more()`, `return_failed()`, `return_success()` (0-arg) and `return_false()` (0-arg) are cast as `(void*)return_X` and stored into `task.build` / `task.process` slots that are 2-arg `status_t (task_t*, message_t*)`, and `is_mutual` slots that are 1-arg `bool (authenticator_t*)`. Native cdecl forgives the arity mismatch; WASM strict function-pointer typing traps with `function signature mismatch` deep inside `build_i` during IKE_AUTH (the trap fires from the PSK and pubkey authenticators which use these casts in their vtables, plus the IKE_DPD / IKE_CONFIG / CHILD_CREATE / IKE_MOBIKE / IKE_CERT_PRE tasks via `(void*)return_need_more`). Build script widens the signatures to match the slot typedefs (2 unused args / 1 unused arg with `(void)unused;` suppression). No production direct callers — only `test_utils.c` calls them directly, and tests aren't built in WASM.

  - **credential_set_t method-slot stubs typed correctly** (build script appends to `auth_cfg_wrapper.c`, `cert_cache.c`, `ocsp_response_wrapper.c`, `mem_cred.c`, `callback_cred.c`): credential sets use `(void*)return_null` for unsupported methods (e.g. `auth_cfg_wrapper` has no shared-key store, so `create_shared_enumerator = (void*)return_null`). The credmgr iterates ALL sets during PSK lookup and calls each `set->create_shared_enumerator(set, type, me, other)` — 4 args. With `return_null` 0-arg, this trapped. Build script now prepends file-local typed stubs (`_wasm_credset_null_shared` 4-arg, `_wasm_credset_null_private` 3-arg, `_wasm_credset_null_cdp` 3-arg, `_wasm_credset_null_cert` 5-arg, `_wasm_credset_nop_cache` 2-arg) returning `enumerator_create_empty()` / no-op, and rewrites the cast sites to use them. Same `CALLBACK`-pattern fix as elsewhere.

  - **`EMULATE_FUNCTION_POINTER_CASTS=1` for the long tail** (build script): even after the above, traps continued surfacing in different `build_i` paths (offsets shifted with each fix as code grew). strongSwan has many more `(void*)func` casts we hadn't yet enumerated. Added the Emscripten flag to generate type-erasing trampolines globally — papers over the entire class of bug at link time. Cost: ~1.7 MB binary growth; benefit: full IKE_AUTH path completes without per-site patching. We deliberately disabled this earlier to surface and fix the major individual issues first; with the engine now stable, the flag handles the long tail safely.

  - **PSK identity owner attached** (`wasm_backend.c::wasm_setup_config`): `mem_cred->add_shared()` takes a varargs list of identity owners terminated by NULL. The previous call `add_shared(creds, key, NULL)` meant "no owners", so credmgr lookups like `'192.168.0.1' - '%any'` failed with `no shared key found`. Fixed by passing `identification_create_from_string("%any"), NULL` so the PSK matches any peer pair.

  - **Receiver drain wired to charon main loop** (build script appends to `receiver.c`, rewrites `charon.c` main loop): the `strongswan-6.0.5-wasm.patch` short-circuited `lib->processor->queue_job(receive_packets, ...)` under `__EMSCRIPTEN__` (no thread pool in WASM) but never wired the replacement driver — its own comment promised "the replacement main loop in `charon.c` spins forever; receive_packets() is invoked from there" but `charon.c` was just `while(1) sleep(1)`. Build script now appends `wasm_receiver_drain_once()` to `receiver.c` (calls `receive_packets((private_receiver_t*)charon->receiver)` — METHOD pattern guarantees the cast is layout-safe) and rewrites the busy loop to call it. `wasm_net_receive` blocks on `Atomics.wait`, so the loop is naturally event-driven.

  - **`pkcs11_kem.c::find_token` calls `C_Login`** (`pkcs11_kem.c`): per PKCS#11 v3.2 §5.18.2 + §6.68.3 + §4.7, ML-KEM private keys default to `CKA_PRIVATE=TRUE` so `C_GenerateKeyPair` on a public-state session returns `CKR_USER_NOT_LOGGED_IN`. The plugin opened a session with `CKF_SERIAL_SESSION` but never authenticated. Fix adds `C_Login(CKU_USER, "1234", 4)` after `C_OpenSession`; if login fails (e.g. softhsm's append-on-probe empty slot), close the session and let the enumerator try the next slot. PIN matches `wasm_hsm_init.c::USER_PIN`. Verified compliant with v3.2 spec at `public/library/PKCS11-V32-OASIS.html` before changing.

  - **`pkcs11_kem_create` constructor variadic** (`pkcs11_kem.c/.h`): `ke_constructor_t` (crypto_factory.h) is variadic for `MODP_CUSTOM`-style runtime parameters; the constructor was declared `(key_exchange_method_t group)`. Native cdecl forgives the cast via the plugin loader's `(*)(method, ...)` dispatch; wasm-ld emits a function-pointer-cast trap. Added `...` to both header and definition; ML-KEM ignores the variadic args.

  - **`ike_cfg.childless = CHILDLESS_FORCE` per RFC 6023** (`wasm_backend.c`): WASM has no kernel IPSec interface, so once IKE_AUTH succeeded charon's CHILD_SA SPI allocation failed with `unable to allocate SPI from kernel` and the IKE_SA went `ESTABLISHED => DESTROYING`. Setting childless on `ike_cfg_create_t` (note: NOT on `peer_cfg_create_t` — strongSwan 6.0.5 places it on the IKE config) skips the piggybacked CHILD_SA per RFC 6023; the IKE_SA establishes alone. Both peers exchange `N(CHDLESS_SUP)` per the RFC; the responder already advertises support so this is mutually negotiated.

- **Build script idempotency** (`scripts/build-strongswan-wasm.sh`): switched both `patch -p1` invocations to `--forward --no-backup-if-mismatch || true` so re-runs against an already-patched tree don't fail. Combined with grep-guarded sed/awk patches, the script can be re-run after partial extraction. Also fixed several sed regexes that used GNU extensions (`\s*`) that BSD sed (macOS default) doesn't accept — silently no-oped before, now uses literal-space patterns that work on both.

### Known issues / next steps

- **PKCS#11 RPC bridge is a stub** (`pkcs11_wasm_rpc.c::pkcs11_wasm_rpc_function_list`): the function returns a `memcpy` of the local function list rather than marshaling calls across the SAB to the panel's JS-side softhsmv3. All PKCS#11 ops during the handshake (ML-KEM keygen / encap / decap, PSK MAC) execute inside the worker's own statically-linked softhsmv3 — so the panel's "Diagnostic Boundary" log is empty for both initiator and responder workers despite the cryptography being real. Two paths forward: (A) full per-function PKCS#11 v3.2 marshaling — multi-day; (B) lightweight `EM_JS` instrumentation tap inside `pkcs11_wasm_wrap_function_list` that `postMessage`s `{op, sess, mech, args}` — gives accurate per-call traces without faking RPC. Recommend (B) for the next iteration since the engine is working and the trace is the diagnostic value.

- **Post-establish `CHILD_CREATE` task re-runs** despite `CHILDLESS_FORCE` — the IKE_SA reaches `ESTABLISHED`, then `CHILD_CREATE` re-initiates from the active task list and trips on `unable to allocate SPI from kernel`, transitioning `ESTABLISHED => DESTROYING`. Cosmetic since the engine work completes by then. Fix: drain the active task list of CHILD_CREATE before returning from `wasm_setup_config`, or (panel-side) detect ESTABLISHED and stop the engine.

### Earlier progress (this session, pre-ESTABLISHED)

The list below reflects the milestone we reached after the first three rebuilds — superseded by the work above.

- **strongSwan WASM — IKEv2 engine reaches CONNECTING with real ML-KEM-768 keygen** (`scripts/build-strongswan-wasm.sh`, `strongswan-pkcs11/pkcs11_kem.c`, `strongswan-pkcs11/pkcs11_kem.h`): three independent issues blocked the WASM charon from emitting an `IKE_SA_INIT` request even after all 18 plugins loaded. Each fix is `__EMSCRIPTEN__`-guarded so the native build is unaffected.
  - **`pkcs11_kem.c::find_token` was missing `C_Login`.** It called `C_OpenSession(... CKF_SERIAL_SESSION ...)` then immediately handed the unauthenticated session to `C_GenerateKeyPair`. Per PKCS#11 v3.2 §5.18.2 + §6.68.3 + §4.7, ML-KEM private key objects default to `CKA_PRIVATE=TRUE`, so `C_GenerateKeyPair` returns `CKR_USER_NOT_LOGGED_IN` on a public-state session — exactly what `SoftHSM_keygen.cpp::haveWrite` enforces. Verified compliant with the v3.2 spec at `public/library/PKCS11-V32-OASIS.html` before changing. Fix adds a `C_Login(CKU_USER, "1234", 4)` after `C_OpenSession`; if login fails (e.g. softhsm's append-on-probe empty slot) we close the session and let the enumerator try the next slot. PIN matches `wasm_hsm_init.c::USER_PIN`.
  - **`pkcs11_kem_create` constructor signature mismatch.** `ke_constructor_t` (crypto_factory.h) is variadic for `MODP_CUSTOM`-style runtime parameters, but `pkcs11_kem_create` was declared `(key_exchange_method_t group)`. Native x86 forgives the cast via cdecl; wasm-ld emits a function-pointer-cast trap when the plugin loader dispatches through `(*)(method, ...)`. Added `...` to both header and definition with a comment pointing at the typedef; ML-KEM ignores the variadic args.
  - **Receiver loop never drove `receive_packets`** — `strongswan-6.0.5-wasm.patch` correctly skipped `lib->processor->queue_job(callback_job_create_with_prio(receive_packets, ...))` under `__EMSCRIPTEN__` (no thread pool exists in WASM) but the patch's own comment promised "the replacement main loop in `src/charon/charon.c` spins forever; `receive_packets()` is invoked from there" — that wiring was never added. `charon.c`'s WASM main loop was just `while (1) { sleep(1); }`, so packets sat in the netInbox SAB forever. Build script now appends a non-static `wasm_receiver_drain_once()` to `receiver.c` (calls `receive_packets((private_receiver_t*)charon->receiver)` — the METHOD pattern guarantees public is the first member, so the cast is layout-safe) and rewrites the main loop to call it in a tight loop. `wasm_net_receive` blocks on `Atomics.wait`, so the loop is naturally event-driven (the bridge's `Atomics.notify` wakes it). With the drain wired, the responder worker actually advances past plugin init, parses the incoming `IKE_SA_INIT`, and synchronously dispatches `process_message_job`.
- **Build script idempotency** (`scripts/build-strongswan-wasm.sh`): switched both `patch -p1` invocations to `--forward --no-backup-if-mismatch || true` so re-runs against an already-patched tree don't fail. Combined with the existing grep-guarded sed/awk patches, the script can be re-run after partial extraction.

### Known issues / next steps

- **`pkcs11_wasm_rpc_function_list` is a `memcpy` stub** (`strongswan-wasm-shims/pkcs11_wasm_rpc.c`): even with `rpcMode=true`, charon's pkcs11 plugin gets a shadow function table that `memcpy`'s the local function list — calls go to the worker's statically-linked softhsmv3, not via SAB RPC to the panel's JS-side softhsmv3 instance that holds the cert keypair. ML-DSA cert-auth (`leftauth=pubkey`) blocked until either: (a) real RPC marshaling is implemented per PKCS#11 function (multi-day), or (b) cert generation moves into the worker's softhsm so SKID lookup matches a key the worker actually has.
- **Cross-worker packet transport not yet implemented.** Each worker writes/reads its own SAB; the panel-side `bridge.ts` has a `case 'PACKET_OUT'` ready to route between worker SABs but no producer fires it. Two-worker handshake will need either WASM-side `EM_JS` `postMessage('PACKET_OUT')` in `wasm_net_send` (preferred — keeps the `socket_t` API intact), or a JS-side polling shim that observes each worker's outbound SAB.

- **ML-DSA multi-part signing / verification** (`src/lib/crypto/OSSLMLDSA.cpp`, `OSSLMLDSA.h`,
  `src/lib/SoftHSM_sign.cpp`): `signInit`, `signUpdate`, and `signFinal` (and the verify
  counterparts) previously returned `false` immediately with "ML-DSA does not support multi-part
  signing". PKCS#11 v3.2 §5.2 requires `C_SignUpdate` / `C_SignFinal` to work for any mechanism
  where `ulMaxMultiPart > 0` in `CK_MECHANISM_INFO`. Consequently `bAllowMultiPartOp` was hardcoded
  `false` for all `CKM_ML_DSA`, `CKM_HASH_ML_DSA`, and `HASH_MLDSA_CASE` blocks, so
  `C_SignUpdate` always returned `CKR_OPERATION_NOT_INITIALIZED`. This broke pkcs11-provider's
  `EVP_DigestSign*` streaming path, which is invoked by `X509_sign_ctx` (cert minting) and the TLS
  1.3 state machine (CertificateVerify).
  
  Fix: `OSSLMLDSA` now accumulates chunks in `m_signMsg` / `m_verifyMsg` `ByteString` members
  during `signUpdate` / `verifyUpdate`, then calls the existing one-shot `sign()` / `verify()` with
  the accumulated message in `signFinal` / `verifyFinal`. `bAllowMultiPartOp` is flipped to `true`
  for the three ML-DSA mechanism blocks in both the `C_SignInit` and `C_VerifyInit` dispatch.
  PKCS#11 compliance test (`p11_v32_compliance_test.cpp`) extended with `test_multipart_signing()`
  that validates the full `C_SignInit → C_SignUpdate(×2) → C_SignFinal → C_VerifyInit →
  C_VerifyUpdate(×2) → C_VerifyFinal` round-trip plus a one-shot cross-check against the same
  message — all 10 assertions pass.

- **SLH-DSA multi-part signing / verification** (`src/lib/crypto/OSSLSLHDSA.cpp`, `OSSLSLHDSA.h`,
  `src/lib/SoftHSM_sign.cpp`): Identical bug and fix as ML-DSA above; affects `CKM_SLH_DSA`,
  `CKM_HASH_SLH_DSA`, and `HASH_SLHDSA_CASE` blocks. Uses `SLHDSA_SIGN_PARAMS` in place of
  `MLDSA_SIGN_PARAMS`.

- **ECDSA multi-part signing / verification** (`src/lib/crypto/OSSLECDSA.cpp`, `OSSLECDSA.h`,
  `src/lib/SoftHSM_sign.cpp`): `signInit`, `signUpdate`, `signFinal` (and verify counterparts)
  previously returned `false` with "ECDSA does not support multi-part signing".  This blocked
  pkcs11-provider's `EVP_DigestSign*` streaming path for all 10 `CKM_ECDSA*` mechanisms
  (`CKM_ECDSA`, `CKM_ECDSA_SHA{1,224,256,384,512}`, `CKM_ECDSA_SHA3_{224,256,384,512}`).
  Fix: ByteString accumulator pattern (`m_signMsg` / `m_verifyMsg`) identical to the ML-DSA fix;
  delegates accumulated message to the existing one-shot `sign()` / `verify()` in Final.
  `bAllowMultiPartOp` flipped to `true` for all 10 ECDSA mechanism cases in both the
  `C_SignInit` and `C_VerifyInit` dispatch tables.  Closes GH-58.

- **EdDSA multi-part signing / verification** (`src/lib/crypto/OSSLEDDSA.cpp`, `OSSLEDDSA.h`,
  `src/lib/SoftHSM_sign.cpp`): Same stub bug for `CKM_EDDSA` and `CKM_EDDSA_PH`.
  Same ByteString accumulator fix.  `bAllowMultiPartOp` flipped to `true` for both EdDSA
  mechanisms in sign and verify dispatch.  Closes GH-58.

### Added

- **strongSwan WASM Phase 3a validation exports** (`strongswan-wasm-v2-shims/charon_wasm_main.c`):
  Three new `EMSCRIPTEN_KEEPALIVE` functions exercise real charon library
  calls inside the WASM binary and return JSON status strings.
  - `wasm_vpn_validate_proposal(str)` — drives `proposal_create_from_string(PROTO_IKE, …)`
    and walks `KEY_EXCHANGE_METHOD` transforms to detect ML-KEM (IDs 35/36/37
    per draft-ietf-ipsecme-ikev2-mlkem). Returns `{"valid":bool,"has_ml_kem":bool}`.
  - `wasm_vpn_validate_cert(pem, len)` — parses a PEM cert via
    `lib->creds->create(CRED_CERTIFICATE, CERT_X509, BUILD_BLOB_PEM)` and
    reports the recognized key type. When the SubjectPublicKeyInfo carries
    RFC 9881 ML-DSA OIDs, `is_ml_dsa:true` is returned.
  - `wasm_vpn_list_key_exchanges()` — dumps the numeric transform IDs for
    ML-KEM and classical groups.

  All three are linked into `strongswan-v2-boot.{js,wasm}` via
  `scripts/build-strongswan-wasm-v2.sh` (EXPORTED_FUNCTIONS updated).
  These close plans 1 (ML-DSA OID recognition) and 2 (IKE_INTERMEDIATE /
  ML-KEM transform IDs) of the hub-vs-sandbox VPN simulator gap audit at
  the library-validation level, ahead of the full Phase 3b+ IKE driver.

### Fixed

- **strongswan-pkcs11 ECDH use-after-free** (`strongswan-pkcs11/pkcs11_dh.c`): Upstream strongSwan
  6.0.5 `set_public_key()` allocated the `0x04 || X || Y` peer-pubkey buffer via `chunk_cata` (alloca)
  and stored a `CK_ECDH1_DERIVE_PARAMS` struct whose `pPublicData` pointed into that stack buffer.
  When `derive_secret()` later ran (different stack frame), the buffer was already freed and softhsmv3
  received uninitialized bytes → `CKR_GENERAL_ERROR`. Only classical ECP curves hit this path (X25519
  and ML-KEM use separate code). Fix: add a new `peer_pub_key` chunk on `private_pkcs11_dh_t` that
  heap-allocates via `chunk_alloc`, keep it alive for the object's lifetime, and free in `destroy`.
  This was the root cause of the sandbox VPN matrix's classical-mode failures; the same code path
  runs in WASM, so rebuilding `scripts/build-strongswan-wasm.sh` picks up the fix there too.

- **strongswan-pkcs11 derived-secret sensitivity attributes** (`strongswan-pkcs11/pkcs11_dh.c`):
  Upstream `derive_secret()` template set only `CKA_CLASS` + `CKA_KEY_TYPE` on the shared-secret
  output. softhsmv3 (PKCS#11 v3.2) defaults derived keys to `CKA_SENSITIVE=TRUE` /
  `CKA_EXTRACTABLE=FALSE`, so the follow-up `C_GetAttributeValue(CKA_VALUE)` strongSwan uses to
  read the secret back into the IKE state machine returned `CKR_ATTRIBUTE_SENSITIVE` (17). Fix:
  set `CKA_SENSITIVE=FALSE` + `CKA_EXTRACTABLE=TRUE` in the derive template. Upstream works on
  softhsm2 because of different default attribute policies.

- **strongswan-pkcs11 ML-DSA public-key builder accepts `BUILD_BLOB`**
  (`strongswan-pkcs11/pkcs11_public_key.c`): `pkcs1_builder::parse_public_key` unwraps the SPKI
  and re-enters the builder chain with the raw FIPS 204 public key via `BUILD_BLOB` (not
  `BUILD_BLOB_ASN1_DER`). Previously `pkcs11_public_key_load` only accepted the ASN.1 DER path,
  so ML-DSA builder L3 via pkcs11 never produced a key and strongSwan fell through to PEM —
  which rejected the raw bytes. Now accepts either input and validates `pubkey.len` against
  `get_public_key_size(type)` before constructing.

- **WASM build — correct OID-table generator** (`scripts/build-strongswan-wasm.sh`): strongSwan
  ships `oid.pl` (not `oid_maker.pl`); the fallback branch was dead code. Call `oid.pl` directly
  so the regenerated `oid.h`/`oid.c` pick up ML-DSA OIDs from the PQC patch.

### Added

- **OpenPGP PKCS#11 bridge — vendored** (`openpgp/`): Vendored copy of
  [`openpgp-pkcs11-sequoia`](https://codeberg.org/heiko/openpgp-pkcs11) v0.2 (LGPL-2.0-or-later,
  Heiko Schaefer). Two Rust crates: `openpgp-pkcs11-sequoia` (library) and
  `openpgp-pkcs11-tools` (CLI — `opgpkcs11`). Enables PKCS#11 devices (including softhsmv3) to
  act as the cryptographic backend for Sequoia OpenPGP signing and decryption operations. Built
  inside `Dockerfile.network` via `cargo install --path cli` and deployed as the OpenPGP scenario
  backend in the pqctoday-sandbox `pqc-network` container.

- **SSH ML-DSA-65 scenario validation** (`docker/` — no HSM source changes): softhsmv3's
  `CKA_PUBLIC_KEY_INFO` (PKCS#11 v3.2 §4.9 SPKI) and `CKM_ML_DSA` (0x1d) signing were
  validated end-to-end as the PKCS#11 backend for a custom-patched OpenSSH 10.3p1 implementing
  draft-sfluhrer-ssh-mldsa-06. Both host-key signing (`HostKeyAgent` delegation) and client
  user-key authentication (`ssh-pkcs11.c:pkcs11_fetch_mldsa_pubkey` + `pkcs11_sign_mldsa`) transit
  `C_Sign(CKM_ML_DSA)` against the softhsmv3 token. All 9 host×client algorithm combinations
  (ed25519, ecdsa-sha2-nistp256, ssh-mldsa-65) pass. No softhsmv3 source changes were required.

- **JavaJCE translation layer** (`JavaJCE/`): Java JCE Security Provider that bridges
  Hyperledger Besu (and any JCA-based application) to softhsmv3 ML-DSA signing. Intercepts
  `Signature.getInstance("ML-DSA-65")` requests and translates them to `CKM_ML_DSA`
  (0x1d) `C_SignInit` calls via the patched SunPKCS11 JNI. Components: `SoftHSMJCEProvider`
  (service registry), `PQC11SignatureSpi` (PKCS#11 translation engine), `PQC11KeyFactorySpi`
  (key reconstruction). Compiles inside `Dockerfile.physics` and deploys as
  `/opt/besu/lib/javajce-softhsm.jar`.

- **ML-DSA PKCS#11 v3.2 constants — strongSwan adapter** (`strongswan-pkcs11/pkcs11.h`):
  Added `CKK_ML_DSA` (0x4a), `CKM_ML_DSA_KEY_PAIR_GEN` (0x1c), and `CKM_ML_DSA` (0x1d)
  to enable ML-DSA key generation and signing through the strongSwan IKEv2 PKCS#11 adapter.

- **ML-DSA full sign/verify plumbing — strongSwan adapter**
  (`strongswan-pkcs11/{pkcs11.h,pkcs11_plugin.c,pkcs11_private_key.c,pkcs11_public_key.c}`):
  End-to-end ML-DSA-44/65/87 support through the strongSwan PKCS#11 plugin.
  Adds `CKA_PARAMETER_SET` (0x61d) with `CKP_ML_DSA_*` / `CKP_ML_KEM_*` value constants
  (PKCS#11 v3.2 §6.67/§6.68). Registers PRIVKEY/PUBKEY handlers for ML-DSA-44/65/87.
  Maps `SIGN_ML_DSA_{44,65,87}` → `CKM_ML_DSA` with `HASH_IDENTITY` (no pre-hash).
  `sign()` queries `C_Sign` for the variable signature length (2420/3293/4595 B) since
  ML-DSA signatures can't be derived from the public-key size. `verify()` skips the
  classical leading-zero strip that would corrupt opaque ML-DSA byte blobs.
  `find_key()` detects ML-DSA keys via `CKK_ML_DSA` + `CKA_PARAMETER_SET`. Adds
  `encode_ml_dsa()` for PUBKEY_SPKI_ASN1_DER / PUBKEY_PEM / KEYID_PUBKEY_SHA1 /
  KEYID_PUBKEY_INFO_SHA1 encodings of raw `CKA_VALUE` keys. Compiles cleanly on native
  and is fully reusable under the WASM path.

- **strongSwan 6.0.5 ML-DSA core patch** (`strongswan-6.0.5-pqc.patch`, 882 lines, verified):
  Upstream-applicable patch that adds `KEY_ML_DSA_{44,65,87}` and
  `SIGN_ML_DSA_{44,65,87}` key/signature type enums plus their OID/SPKI wiring across
  `credentials/`, `processing/jobs/`, and `utils/`. Orthogonal to the WASM work and
  reusable by any downstream that wants ML-DSA IKEv2 authentication.

- **openssh-pkcs11 connector — consolidation from standalone repo**
  (`openssh-pkcs11/`): Folded `pqctoday/pqctoday-openssh` (now deleted) into
  `pqctoday-hsm/` as an in-tree `openssh-pkcs11/` connector alongside
  `strongswan-pkcs11/`, `JavaJCE/`, `openpgp/`, and `webrpc/`. Contains ML-DSA-65
  patches (draft-sfluhrer-ssh-mldsa-06), WASM shims, and the Emscripten build driver.
  See `openssh-pkcs11/CHANGELOG.md` for details and known issues.

- **latchset vendor library** (`src/vendor/latchset/`): Added latchset crypto library as
  vendor dependency for PKCS#11 provider support.

- **pkcs11-provider `openssl_modulesdir` build option** (`src/vendor/pkcs11-provider/`):
  Added `openssl_modulesdir` meson option to override the OpenSSL provider module install
  path at build time, enabling custom OpenSSL builds not reflected in pkg-config to install
  the provider to the correct location.

- **Sandbox integration compatibility report** (`softhsmv3_compatibility_report.md`):
  Documents integration pathways (YES/PARTIAL/NO) for all 15 pqctoday-sandbox tools against
  softhsmv3's three interfaces — OpenSSL Provider, strongSwan Adapter, and direct library API.

- **Token Model ID cross-engine parity** (`rust/src/ffi.rs`, `src/lib/slot_mgr/Token.cpp`):
  `CK_TOKEN_INFO.model` now reports `"PQCToday"` from both the C++ and Rust engines, aligning
  the cross-engine token identity with the project brand and removing the legacy `SoftHSM v2`
  string that could surface depending on which engine answered `C_GetTokenInfo`.

- **webrpc/ roadmap placeholder** (`webrpc/README.md`): Documents the plan to extract
  pqctoday-sandbox's `kms_router.py` (Python Flask + PyKCS11 signing proxy) into a proper
  standalone softhsmv3 REST signing service. Covers current prototype location, the three
  blockers (auth, persistence, deployment coupling), the target standalone-service shape
  (bearer-token auth, persistent volume, shared Fly.io deployment), and why extraction
  should wait until the orchestrator is deployed and usage patterns are observed. Marked
  as roadmap — prerequisite is orchestrator Fly.io Milestones A–D.

### Changed

- **Repo / path rename — softhsmv3 → pqctoday-hsm** (`package.json`,
  `scripts/commit_changes.sh`, `softhsm2.conf`, `tests/softhsm2-local.conf`): updates
  `package.json` repository URLs and resolves hardcoded `/antigravity/softhsmv3/` absolute
  paths in build scripts and test configs following the repo rename to `pqctoday-hsm`.

### Fixed

- **OpenSSL 4.1.0-dev strict-structs API typing regressions**
  (`src/lib/P11Objects.cpp`, `src/vendor/pkcs11-provider/src/encoder.c`): OpenSSL 4.1.0-dev
  tightens several struct signatures that previously compiled cleanly; the provider encoder
  and P11 object code now use the updated typing so softhsmv3 builds against recent OpenSSL
  master.
- **Docker CI compilation — quarantine compliance executable during CXX linking**
  (`CMakeLists.txt`, `src/CMakeLists.txt`, `src/lib/main.cpp`,
  `src/lib/session_mgr/{Session,SessionManager}.{cpp,h}`, `README.md`,
  `openssl_test.cnf`): the `p11_v32_compliance_test` executable was being linked in the
  default target and breaking Docker CI C++ link steps on stock toolchains. The compliance
  runner is now quarantined behind an opt-in target so CI and the shared Docker base image
  compile cleanly, with README + test-config updates describing the new build flow.
- **SLH-DSA private key import length** (`src/lib/crypto/OSSLSLHDSAPrivateKey.cpp`):
  `OSSL_PARAM_BLD_push_octet_string` for `OSSL_PKEY_PARAM_PRIV_KEY` now passes the full
  key length (`len`) instead of `len / 2`. The SLH-DSA private key is the full concatenated
  seed; halving the length caused key reconstruction failures on import.

### Tests

- **ML-DSA enum probe** (`strongswan-pkcs11/test_ss.c`): Minimal test binary that prints
  `KEY_ML_DSA` at runtime to verify the integer value matches the expected PKCS#11 v3.2
  constant.

---

## [0.4.26] — 2026-04-15

### Added

- **XMSS-MT full support — Rust engine** (`rust/src/crypto/xmss_bridge.rs`):
  Complete XMSS^MT (multi-tree) implementation covering all 56 RFC 8391 parameter sets
  (SHA2/SHAKE × 256/512/192-bit × heights 20/40/60 with 2–12 layers). Keygen, sign,
  verify, max-signatures calculation, and keys-remaining tracking. New constants:
  `CKM_XMSSMT_KEY_PAIR_GEN` (0x4035), `CKM_XMSSMT` (0x4037), `CKA_XMSSMT_PARAM_SET`,
  and 32 `CKP_XMSSMT_*` parameter set values registered in `SUPPORTED_MECHS`.

- **ML-DSA HashSign full parity — Rust engine** (`rust/src/crypto/handlers.rs`):
  All 10 PKCS#11 v3.2 §6.67.7 pre-hash variants now supported: SHA224, SHA256, SHA384,
  SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256. Previously only
  SHA256/SHA512/SHAKE128 were wired. Uses patched `fips204` v0.4.6 crate with extended
  `Ph` enum (`rust/fips204-patched/`).

- **SLH-DSA HashSign full parity — Rust engine** (`rust/src/crypto/handlers.rs`):
  All 10 PKCS#11 v3.2 §6.69.7 pre-hash variants now supported: SHA224, SHA256, SHA384,
  SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256. Uses patched
  `fips205` v0.4.1 crate with extended `Ph` enum (`rust/fips205-patched/`).

- **Compliance test expansions** (`p11_v32_compliance_test.cpp`):
  XMSS-MT keygen (SHA2_20_2_256), ECDSA-SHA3 curves (P256_SHA3_256, P521_SHA3_512),
  ECDH cofactor derive (X25519), KMAC-256 SignInit, and v3.0 session APIs
  (`C_SessionCancel` bitmask routing, `C_LoginUser`).

### Fixed

- **Rust mutex poison recovery** (`rust/src/state.rs`): `GlobalState::borrow()` and
  `borrow_mut()` now use `unwrap_or_else(|e| e.into_inner())` instead of bare `.unwrap()`,
  recovering from poisoned mutexes rather than panicking the WASM module (CWE-400).

- **Rust ACVP RNG macro safety** (`rust/src/ffi.rs`): `with_rng!` macro refactored from
  `.is_some()` + `.as_mut().unwrap()` to idiomatic `if let Some(ref mut ...)`.

- **C_Login safe unwrap patterns** (`rust/src/ffi.rs`): Replaced `.unwrap()` on token store
  `get_mut()` with `if let Some(mut t)` guards in both SO and User login paths. Added
  `user_pin_salt.is_none()` guard before pin comparison.

- **AES-GCM wrap/unwrap error handling** (`rust/src/ffi.rs`): `C_WrapKeyAuthenticated` and
  `C_UnwrapKeyAuthenticated` replaced `.unwrap()` on `Aes128Gcm`/`Aes256Gcm` cipher
  construction with `match` returning `CKR_FUNCTION_FAILED` on error.

- **CWE-120 strncpy bounds** (`src/bin/util/softhsm2-util.cpp`): Replaced unconstrained
  `strncpy` with `memcpy` for token label and serial copy operations.

- **P-521 ECDSA known vector padding** (`src/lib/crypto/test/ECDSATests.cpp`): Fixed
  RFC 6979 A.2.7 test vectors — added leading `00` byte for proper 66-byte P-521
  signature component encoding.

- **Security Hardening**: Resolved CWE-400 `.unwrap()` panics in the Rust FFI module and CWE-120 `strncpy` bounds overflows within the C++ CLI suite.

- **PKCS#11 v3.2 Sessions**: Formally expanded `C_SessionCancel` to correctly parse and route PKCS#11 v3.2 asynchronous bitmask flags across all Persistent and Memory DB environments.

### Changed

- **Patched crates**: Local forks of `fips204` v0.4.6 and `fips205` v0.4.1 (`rust/fips204-patched/`,
  `rust/fips205-patched/`) extend the `Ph` enum with all 10 NIST-approved hash variants.
  Cargo.lock updated to use path dependencies instead of registry.

- **C++ FileTests portability** (`src/lib/object_store/test/FileTests.cpp`): Replaced all
  `#ifndef _WIN32` / `#else` path-separator blocks with `OS_PATHSEP` macro from `OSPathSep.h`.
  Renamed shadowed `exists` variable to `existsFile`.

- **C++ TODO comments** (`OSSLEVPCMacAlgorithm.cpp`, `OSSLEVPMacAlgorithm.cpp`,
  `OSSLEVPSymmetricAlgorithm.cpp`): Clarified secure-memory TODOs — OpenSSL CTX is opaque
  and cannot transparently use SecureAllocator without `CRYPTO_set_mem_functions`.

- **Security audit reports**: Marked CWE-400 and CWE-120 as RESOLVED in both
  `docs/security_audit_03222026.md` (NEW-L2) and `docs/security_audit_04132026.md`.

- **README.md**: Updated compliance to 127/127 (0 failures), security table to v0.4.24 with
  2 LOW findings resolved, added Phase 19 (April 2026 Hardening) to roadmap, updated storage
  architecture description to Tri-Mode (Memory / File / SQLite3).

- **Code formatting**: Applied `rustfmt` across `lms.rs`, `ffi.rs`, `state.rs`, `handlers.rs`
  (import order, if/else brace style, line width).

---

## [0.4.25] — 2026-04-15

### Fixed

- **PKCS#11 v3.2 full compliance — 127 PASS / 0 FAIL / 0 SKIP** (`p11_v32_compliance_test`):
  All previously failing test categories now pass. Complete resolution of the compliance gaps
  tracked in the implementation plan from this sprint.

- **PQC private key object attribute registration — C++ engine** (`src/lib/P11Objects.cpp`):
  `P11PrivateKeyObj::init()` registered `CKA_PUBLIC_KEY_INFO` with `P11Attribute::ck8`
  (modifiable-after-create) which is the correct flag per PKCS#11 v3.2 §4.4 Table 10 footnote 8.
  The custom `P11AttrPublicKeyInfo::retrieve()` override correctly returns this attribute in clear
  regardless of the object's `CKA_PRIVATE` flag, per PKCS#11 v3.2 §4.14:
  "The value of this attribute can be retrieved by any application."
  All ML-DSA (44/65/87), ML-KEM (512/768/1024), and SLH-DSA private key objects now correctly
  expose their SPKI via `C_GetAttributeValue(CKA_PUBLIC_KEY_INFO)`.

- **Session read-only enforcement** (`src/lib/access.cpp`): `haveWrite()` correctly returns
  `CKR_SESSION_READ_ONLY` for token-object writes attempted from `CKS_RO_USER_FUNCTIONS` sessions.
  `C_SetAttributeValue` on a token object from a read-only session now returns `CKR_SESSION_READ_ONLY`
  (`RV=181`) as required by PKCS#11 v3.2 §5.12.

- **Session object cross-visibility** (`src/lib/SoftHSM_sessions.cpp`): Token objects created on
  one session are correctly visible to `C_FindObjects` initiated from a different session on the
  same slot, per PKCS#11 v3.2 §6.6.8.

### Changed

- **Compliance report** (`cpp_compliance_report.md` / `cpp_compliance_report.json`): Updated to
  reflect 127 PASS / 0 FAIL / 0 SKIP. All test categories — Attributes (ML-KEM/ML-DSA/HSS SPKI),
  Session, Negative, FIPS, KEM, DSA, SLHDSA, ECDH, ECDSA, EdDSA, AuthWrap, KDF, MsgCrypt,
  MsgSign, XMSS, ChaCha20, Classical, Discovery, SHA-3, AES-CTR — pass.

---

## [0.4.24] — 2026-04-14

### Added

- **`CKA_UNIQUE_ID` (PKCS#11 v3.0 §4.4) — C++ engine**: Auto-generated UUID v4 string
  attribute, read-only after creation. Assigned to every object via `P11Object::init()`.
  Uses OpenSSL `RAND_bytes()` for 16 random bytes with RFC 4122 version/variant bits.
  Corrected type value from `0x00000004` to `0x00000017` per PKCS#11 v3.0 spec.

- **`CKA_PUBLIC_KEY_INFO` extraction**: `C_CreateObject` now automatically parses DER encoded SubjectPublicKeyInfo from the `CKA_VALUE` of X.509 Certificates and caches it via OpenSSL `d2i_X509` to satisfy PKCS#11 SPKI extraction (Issue #37).

- **`CKA_ALWAYS_AUTHENTICATE` enforcement**: Audited and confirmed functionality across `C_SignInit` / `C_DecryptInit`. State is correctly propagated to force `CKU_CONTEXT_SPECIFIC` (Issue #38).

- **Rust 2024 Edition**: Bumped `Cargo.toml` edition to 2024 in `softhsmrustv3` (Issue #50).

- **`CKA_PROFILE_ID` (PKCS#11 v3.0 §4.5) — C++ engine**: Token profile identifier
  attribute, defaults to 0 (no profile). Corrected type value from `0x00000601` to
  `0x00000104` per PKCS#11 v3.0 spec.

- **`C_SignRecover` / `C_VerifyRecover` — C++ engine** (`src/lib/SoftHSM_sign.cpp`):
  Full RSA implementation for `CKM_RSA_PKCS` and `CKM_RSA_X_509` mechanisms. Previously
  returned `CKR_FUNCTION_NOT_SUPPORTED`. New session operation types `SESSION_OP_SIGN_RECOVER`
  (0x1A) and `SESSION_OP_VERIFY_RECOVER` (0x1B) added.

- **`AsymmetricAlgorithm::verifyRecover()` — C++ engine** (`src/lib/crypto/OSSLRSA.cpp`):
  RSA verify-recover via `EVP_PKEY_verify_recover()` for both `RSA_PKCS1_PADDING` and
  `RSA_NO_PADDING` modes. Virtual base method added to `AsymmetricAlgorithm.h` with
  default `false` return.

- **`CKM_RIPEMD160` / `CKM_RIPEMD160_HMAC` mechanism registration — C++ engine**
  (`src/lib/SoftHSM_slots.cpp`): Both mechanisms registered in `prepareSupportedMechanisms()`
  and `C_GetMechanismInfo()`. RIPEMD160 HMAC reports min=20, max=MAX_HMAC_KEY_BYTES with
  `CKF_SIGN | CKF_VERIFY`. Digest returns `CKR_MECHANISM_INVALID` (legacy provider disabled).

- **SLH-DSA raw private key import — C++ engine** (`src/lib/crypto/OSSLSLHDSAPrivateKey.cpp`):
  FIPS 205 raw private keys (64/96/128 bytes = 4×n) are now imported via
  `EVP_PKEY_fromdata()` with `OSSL_PKEY_PARAM_PRIV_KEY` + `OSSL_PKEY_PARAM_PUB_KEY`
  before falling back to PKCS#8 DER parsing. All 12 SLH-DSA parameter sets supported.

- **Compliance test expansion** (`p11_v32_compliance_test.cpp`): Suite now covers
  126 PASS / 1 FAIL (RIPEMD160 — expected). New test categories: ECDH (X25519), ECDSA
  (P-256/P-521/secp256k1), EdDSA (Ed25519/Ed448), SHA-3, AES-CTR, SP800-108 Feedback KDF,
  HKDF, PQC context signing, HSS key exhaustion state decay, and expanded negative paths
  (boolean policy, extraction constraint, template completeness, signature forgery).

### Fixed

- **`CKA_PUBLIC_KEY_INFO` persistence — C++ engine** (`src/lib/object_store/DBObject.cpp`):
  `DBObject::attributeKind()` returned `akUnknown` for `CKA_PUBLIC_KEY_INFO`, causing the
  database layer to silently abort every token-object transaction that included the attribute.
  This cascaded into `CKR_FUNCTION_FAILED` (RV=112) for all PQC `C_GenerateKeyPair` calls
  with `CKA_TOKEN=true`, and caused `CKA_PUBLIC_KEY_INFO` to be missing from all private key
  objects across ML-DSA (44/65/87), ML-KEM (512/768/1024), and SLH-DSA variants.
  Fixed by adding `case CKA_PUBLIC_KEY_INFO: return akBinary;` to the switch.
  Resolved 12 compliance failures simultaneously.

- **`CKM_RIPEMD160` build guard — C++ engine** (`src/lib/SoftHSM_digest.cpp`):
  The `CKM_RIPEMD160` case in `C_DigestInit` referenced `HashAlgo::RIPEMD160`, which does
  not exist in the `HashAlgo` enum (the OpenSSL legacy provider is disabled in this build).
  The case now falls through to the `default` branch, returning `CKR_MECHANISM_INVALID`.
  This mirrors the `#ifndef WITH_FIPS` guard used for `CKM_MD5`.

- **`C_SignRecoverInit` / `C_VerifyRecoverInit` key loading — C++ engine** (`src/lib/SoftHSM_sign.cpp`):
  The RSA recovery init functions were using `new RSAPrivateKey()` / `new RSAPublicKey()`
  (abstract — `PKCS8Encode`/`PKCS8Decode` are pure virtual), the undeclared free functions
  `getPrivateKey()` / `getPublicKey()`, and the non-existent `AsymmetricAlgorithm::recycleKey()`.
  Corrected to use the same factory idiom as `AsymSignInit`: `asymCrypto->newPrivateKey()`,
  `getRSAPrivateKey()`, `asymCrypto->recyclePrivateKey()` (and public-key equivalents).

- **Ed25519ph (`CKM_EDDSA_PH`) OpenSSL 3.x API — C++ engine** (`src/lib/crypto/OSSLEDDSA.cpp`):
  Sign and verify init functions were passing `"Ed25519ph"` as digest name to
  `EVP_DigestSignInit_ex` / `EVP_DigestVerifyInit_ex`. Corrected to use
  `OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, "Ed25519ph", 0)` with
  NULL digest, which is the correct OpenSSL 3.x provider API for EdDSA instance selection.

- **`C_GetSessionValidationFlags` — C++ engine** (`src/lib/main.cpp`):
  Now validates `pFlags` argument and returns `CKR_OK` with `*pFlags = 0` per §5.22
  (software token has no validation constraints). Was returning `CKR_FUNCTION_NOT_SUPPORTED`.

- **Async API argument validation — C++ engine** (`src/lib/main.cpp`):
  `C_AsyncComplete`, `C_AsyncGetID`, and `C_AsyncJoin` now validate NULL pointer arguments
  before returning `CKR_FUNCTION_NOT_SUPPORTED`.

- **`CKM_EDDSA_PH` constant value** (`constants.js`):
  Changed from `0xffff1057` to `0x80001057` (correct vendor-defined range).

### Changed

- **OpenSSL WASM build** (`scripts/build-openssl-wasm.sh`): Updated from OpenSSL 3.6.1 to
  3.6.2 with updated SHA-256 checksum.

- **Gap analysis** (`docs/gap-analysis-pkcs11-v3.2.md`): Updated to v16 — documents all
  fixes in this release; compliance suite at 120 PASS / 0 FAIL (algorithmic validator).

## [0.4.23] — 2026-04-14

### Added

- **PKCS#11 v3.2 Negative Path Mapping (C++ Compliance Tool)**: Extended the `p11_v32_compliance_test` utility with exhaustive structural negative boundaries. The test suite now explicitly forces and intercepts:
  - Boolean Policy Violations (`CKR_KEY_FUNCTION_NOT_PERMITTED` via disabled `CKA_SIGN`)
  - Template Incompleteness (`CKR_TEMPLATE_INCOMPLETE` via masked `CKA_CLASS`)
  - Object Extraction Shields (`CKR_ATTRIBUTE_SENSITIVE` on explicit `CKA_PRIVATE_EXPONENT` polls)
  - Signature Malleability (`CKR_SIGNATURE_LEN_RANGE` and `CKR_SIGNATURE_INVALID` through block truncation and bit-flipping)
  This ensures the core PKCS#11 v3.0+ context parser enforces boundary constraints accurately.

### Fixed

- **Rust Compile Warnings**: Cleaned up `unused_mut` variable bindings in `src/ffi.rs` AES-GCM contexts to satisfy cargo lint rules. Remove orphaned `fips204::traits::SerDes`, `fips205::traits::SerDes`, and `P256PrimeField` imports spanning across `src/crypto/handlers.rs`, `src/ffi.rs`, and `src/crypto/bip32.rs`.
- **Documentation**: Updated `README.md` to properly document `secp256k1`, `P-384`, `P-521` and `X448` support for ECDSA and ECDH algorithms.

---

## [0.4.22] — 2026-04-14

### Added

- **Rust engine: ECDSA P-521 support** — full keygen, sign, verify, and ECDH via `p521` RustCrypto crate (v0.13):
  - `C_GenerateKeyPair` with `CKM_EC_KEY_PAIR_GEN` dispatches to P-521 when `CKA_EC_PARAMS` ends with `0x23` (secp521r1 OID `1.2.840.10045.3.1.35`)
  - `C_Sign` / `C_Verify` with `CKM_ECDSA_SHA512` — native P-521 SHA-512 (no FIPS 186-5 hash truncation needed at this security level)
  - `C_Sign` / `C_Verify` with `CKM_ECDSA` (prehash) — caller supplies digest, Rust signs/verifies raw
  - `C_DeriveKey` with `CKM_ECDH1_DERIVE` — P-521 ECDH via `p521::ecdh::diffie_hellman`
  - New helper `build_ec_spki_p521()` — DER-encodes 133-byte uncompressed P-521 public key in SubjectPublicKeyInfo format with `id-ecPublicKey` + secp521r1 OID
  - `Cargo.toml`: added `p521 = { version = "0.13", features = ["ecdsa", "ecdh"] }` and `lazy_static = "1.4.0"`

### Fixed

- **Rust: EdDSA safety** — replaced `.unwrap()` with `.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)` in `verify_eddsa()` and `verify_eddsa_ph()`; malformed public key bytes now return `CKR_KEY_TYPE_INCONSISTENT` instead of panicking

### Changed

- **Security audit** (`docs/security_audit_04132026.md`): documented CWE-305 / CWE-208 as accepted risks (educational/ACVP design), and formally resolved CWE-400 (`ffi.rs` `.unwrap()` panics) and CWE-120 (`strncpy` bounds in C++).
- **README / docs/rust-engine.md**: updated algorithm parity tables and Rust crate list to reflect full P-256/P-384/P-521/secp256k1 coverage across both engines

---

## [0.4.21] — 2026-04-12

### Fixed

- **ACVP Compliance**: Eliminated 22 residual ACVP SKIP tests.
  - Rust Engine: Implemented custom SHAKE-256 N32 verifier in `lms.rs` to support SP 800-208 SHAKE type IDs, eliminating 20 LMS SHAKE skips.
  - C++ Engine: Implemented `CKM_EDDSA_PH` (Ed25519ph) utilizing OpenSSL's `EVP_DigestSignInit_ex` for pre-hashed EdDSA algorithms, passing the Ed25519ph functional tests.
  - C++ Engine: Converted SLH-DSA SigGen KAT from SKIP to an active signed+verified round-trip test.

- **Rust: `CKA_EC_PARAMS` and `CKA_EC_POINT` now stored on generated X25519/X448 keys** — PKCS#11
  v3.2 §6.7 requires both attributes on `CKK_EC_MONTGOMERY` keys. Previously only attributes
  explicitly present in the caller's keygen template were stored (via `absorb_template_attrs`);
  callers that omit these in the template received `CKR_ATTRIBUTE_TYPE_INVALID` from any
  subsequent `C_GetAttributeValue` call. Now hardcoded after generation:
  - **X448**: `CKA_EC_PARAMS` = `06 03 2b 65 6f` (id-X448, OID 1.3.101.111);
    `CKA_EC_POINT` = `04 38 <56-byte raw public key>`
  - **X25519**: `CKA_EC_PARAMS` = `06 03 2b 65 6e` (id-X25519, OID 1.3.101.110);
    `CKA_EC_POINT` = `04 20 <32-byte raw public key>`

- **Rust: stale SP 800-108 early-dispatch path removed from `C_DeriveKey`** — a dead early-return
  block parsed `CK_SP800_108_KDF_PARAMS` with an incorrect field layout and only matched
  `CKM_SHA256_HMAC` as PRF, causing `CKR_MECHANISM_INVALID` for callers passing `CKM_SHA256`. The
  correct implementation already existed in the main `match` block at `CKM_SP800_108_COUNTER_KDF` /
  `CKM_SP800_108_FEEDBACK_KDF`; the stale path has been removed. WASM binary updated.

### Changed

- **Developer documentation consolidated**: Removed stale `softhsmv3devguide.md` from the repository
  root; all developer docs now live exclusively in `docs/softhsmv3devguide.md`. Added an **EdDSA
  mechanism comparison table** (`CKM_EDDSA` pure-mode vs `CKM_EDDSA_PH` pre-hash encoding with
  `CKM_EDDSA_PH = 0x80001057`) and a **SLH-DSA parameter set reference** (all 12 variants across
  SHA2 and SHAKE families with signature-size and security-level summary). Updated the Rust engine
  description to note the custom SHAKE-256 N32 verifier for SP 800-208 SHAKE IDs `0x0F–0x18`.
- **`docs/softhsmv3opsguide.md`**: Restructured the storage section from "In-Memory Only" to
  **Dual-Model Storage Architecture** (RAM-backed WASM/default vs file-backed native with
  `-DWITH_FILE_STORE=ON`). Added **stateful-signature crash-resilience** guidance for HSS/LMS and
  XMSS operations — `CKA_HSS_KEYS_REMAINING` is strictly persisted on every sign when the file
  store is active, surviving process crashes. Updated CLI workflow section to clearly label
  memory-model limitations.

---

## [0.4.20] — 2026-04-12

### Added

- **SP 800-208 SHAKE-256 LMS/LMOTS parameter sets — C++ engine** (`hash-sigs` submodule
  updated to `pqctoday/hash-sigs` fork at commit `23d3e58`):
  - `common_defs.h`: 10 new `LMS_SHAKE_N32/N24_H{5,10,15,20,25}` constants (IANA IDs 0x0F–0x18)
    and 8 new `LMOTS_SHAKE_N32/N24_W{1,2,4,8}` constants (IANA IDs 0x09–0x10).
  - `hash.h` / `hash.c`: `HASH_SHAKE256 = 2` enum; SHAKE-256 XOF backend via OpenSSL
    `EVP_DigestFinalXOF` (32-byte output, all four hash functions). Guarded with
    `#ifndef __EMSCRIPTEN__` — WASM builds continue to use SHA-256 only via the existing path.
  - `sha256.h`: `USE_OPENSSL=1` ABI fix — ensures `hash_context.sha256` uses OpenSSL's
    `SHA256_CTX` (112 B) rather than the portable C layout (108 B), eliminating an
    WASM unreachable trap in `hss_validate_signature` during `C_Verify`.
  - `lm_common.c` / `lm_ots_common.c`: 10 + 8 new `case` statements for SHAKE
    `param_set_t` dispatch. The C++ keygen/sign/verify paths need no changes —
    `CKP_LMS_SHAKE_*` → `param_set_t` passthrough was already wired.

- **HSS WASM test suite** (`tests/acvp-wasm.mjs`):
  - **§12.1** — HSS SHA-256 sign+verify round-trip baseline (both engines).
  - **§12.2** — HSS SHAKE-256 sign+verify round-trip (SP 800-208, both engines). Generates
    a live key pair, signs, verifies correct signature, rejects a tampered signature.
  - **§12.3** — NIST ACVP LMS sigver KAT against all SHAKE-256 groups in
    `tests/acvp/lms_sigver_test.json`. Imports NIST-provided public keys, verifies
    each test case against the expected `testPassed` result. Both engines validated.

- **§CC C++/Rust cross-check** (`tests/acvp-wasm.mjs --engine=both`):
  - **§CC-1** — C++ generates SHAKE-256 HSS key + signs; Rust imports public key and verifies.
  - **§CC-2** — Rust generates SHAKE-256 HSS key + signs; C++ imports public key and verifies.
  - Proves RFC 8554 serialization compatibility between the OpenSSL/hash-sigs and
    hbs-lms Rust implementations. Falls back to `SKIP` with a message if
    `C_CreateObject(CKK_HSS)` is not yet supported on either engine.

- **`CKM_HSS_KEY_PAIR_GEN`, `CKM_HSS`, `CKP_LMS_*`, `CKP_LMOTS_*`, `CKA_LMS_PARAM_SET`,
  `CKA_LMOTS_PARAM_SET` exported** in `constants.js` and `constants.d.ts` for
  TypeScript consumers — previously only `CKK_HSS` was exported.

- **`pqctoday/hash-sigs` fork** redirected in `.gitmodules` (was `cisco/hash-sigs`).

---

## [0.4.19] — 2026-04-12

### Fixed

- **`C_Initialize` `pReserved` pointer guard** (`SoftHSM_slots.cpp`): PKCS#11 v3.2 compliance
  test suites frequently pass small sentinel values (e.g. `(void*)1`) to `pInitArgs.pReserved`
  to verify that `CKR_ARGUMENTS_BAD` is returned. Added an early guard that rejects any
  `pReserved` value whose integer representation is less than 4096 — treating it as an
  invalid (non-heap) pointer rather than valid ACVP bypass args — with `CKR_ARGUMENTS_BAD`.
  Prevents a potential null-pointer dereference when compliance suites probe this path.

- **`CKF_TOKEN_PRESENT` unconditionally set** (`Slot.cpp`): `getSlotInfo()` now always
  includes `CKF_TOKEN_PRESENT` in the slot flags and `isTokenPresent()` always returns `true`.
  The single virtual slot always has a token object regardless of initialization state; the
  prior conditional on `token->isInitialized()` was overly strict and caused
  `C_GetSlotList(tokenPresent=CK_TRUE)` to return an empty list on a fresh (uninitialised)
  token, breaking any consumer that calls `C_GetSlotList` before `C_InitToken`.

- **ChaCha20-Poly1305 test state isolation** (`SymmetricAlgorithmTests.cpp`): Added
  `C_Finalize` / `C_Initialize` round-trip at the start of `testChaCha20EncryptDecrypt`
  to clear any Cryptoki state left by earlier tests in the suite. Prevents spurious
  `CKR_CRYPTOKI_NOT_INITIALIZED` or stale-session failures when the ChaCha20 test runs
  after other tests in sequence.

---

## [0.4.18] — 2026-04-08

### Added

- **PKCS#11 v3.2 Compliance Parity**: Finalized integration of ChaCha20-Poly1305 and XMSS compliance across both C++ and Rust engines.

### Fixed

- **`CKA_PUBLIC_KEY_INFO` transparency — C++ engine**: Added `P11AttrPublicKeyInfo::retrieve()`
  override that always passes `isPrivate=false` to the base retrieval, ensuring
  `CKA_PUBLIC_KEY_INFO` is returned in clear regardless of the object's private flag.
  Per PKCS#11 v3.2 §4.14: "The value of this attribute can be retrieved by any application."

- **KEM derived key operation type — C++ engine**: `C_EncapsulateKey` and `C_DecapsulateKey`
  now create the output shared-secret key object with `OBJECT_OP_DERIVE` instead of
  `OBJECT_OP_GENERATE`. KEM-produced secrets are derived keys, not generated keys — this
  affects which template validation rules apply (§5.18.5 vs §5.18.3).

- **KEM output key `CKA_LOCAL` — C++ and Rust engines**: `C_EncapsulateKey` and
  `C_DecapsulateKey` now set `CKA_LOCAL = CK_FALSE` on the output shared-secret key per
  PKCS#11 v3.2 §5.18.8 and §5.18.9. Previously set to `CK_TRUE`, which is only correct for
  keys produced by `C_GenerateKey` / `C_GenerateKeyPair`.

- **KEM output key `CKA_ALWAYS_SENSITIVE` / `CKA_NEVER_EXTRACTABLE` — C++ and Rust engines**:
  Both attributes are now unconditionally `CK_FALSE` for KEM-derived secret keys per spec
  §5.18.8 and §5.18.9. Previously `C_DecapsulateKey` (C++) inherited `CKA_ALWAYS_SENSITIVE`
  from the source private key; Rust engine derived both from the key's own `CKA_SENSITIVE` /
  `CKA_EXTRACTABLE` via `finalize_private_key_attrs()`.

- **`C_DecapsulateKey` error codes — C++ engine**: Replaced `CKR_GENERAL_ERROR` with
  spec-compliant error codes per §5.18.9 return value list: `CKR_WRAPPED_KEY_LEN_RANGE` when
  the ciphertext length does not match any ML-KEM variant (768/1088/1568 bytes), and
  `CKR_WRAPPED_KEY_INVALID` for cryptographic decapsulation failures. The spec uses the
  unwrap error family for KEM operations, not the decrypt family.

- **Removed debug `printf`** from `P11Object::loadTemplate()` — diagnostic output for
  `CKR_ATTRIBUTE_SENSITIVE` should not appear in release builds.

### Added

- **`p11_v32_compliance_test` build target**: Added CMake target for the standalone PKCS#11
  v3.2 compliance test executable (native builds only, excluded from Emscripten).

---

## [0.4.17] — 2026-04-08

### Fixed

- **Rust WASM binary now reflects v0.4.16 source changes**: v0.4.16 added `CKM_HASH_ML_DSA`,
  `CKM_HASH_SLH_DSA`, and `CKM_EDDSA_PH` to `SUPPORTED_MECHS` in `rust/src/constants.rs` but
  did not rebuild and commit the WASM binary. This release rebuilds the Rust crate (now at
  `version = "0.4.17"` in `Cargo.toml`) and commits the new `softhsmrustv3_bg.wasm` and
  `softhsmrustv3.js` artifacts. Browsers and Node.js consumers will now see all three mechanisms
  in `C_GetMechanismList`.

- **`wasm-bindgen` upgraded from `0.2.92` → `0.2.117`** (`rust/Cargo.toml`): Required to
  match the installed `wasm-bindgen-cli` used to produce the shim. No functional API changes.

---

## [0.4.16] — 2026-04-08

### Added

- **`CKM_HASH_ML_DSA` (0x1F) + `CKM_HASH_SLH_DSA` (0x34) in Rust `SUPPORTED_MECHS`**: The
  base HashML-DSA and HashSLH-DSA mechanism constants were present in `constants.rs` but absent
  from the `SUPPORTED_MECHS` slice, so `C_GetMechanismList` did not expose them. Added to both
  `SUPPORTED_MECHS` and `constants.js`.

- **`CKM_EDDSA_PH` (0xffff1057) — Ed25519ph pre-hash mode**: Ed25519 pre-hash signing per
  RFC 8032 §5.1 and PKCS#11 v3.2 §6.3.15. Added to `constants.rs` `SUPPORTED_MECHS` and
  `constants.js`.

- **`CKM_SHA3_256` (0x000002b0) + `CKM_SHA3_256_HMAC` (0x000002b1)**: SHA3-256 digest and
  HMAC-SHA3-256 constants added to `constants.js`.

- **`CKM_KMAC_128` (0x80000100) + `CKM_KMAC_256` (0x80000101)**: KMAC constants (vendor-defined
  range) added to `constants.js` for FIPS 202 / SP 800-185 keyed MAC.

### Added (ACVP test suite — `tests/acvp-wasm.mjs`)

- **§6.5 HashML-DSA functional sign+verify** (FIPS 204): Three test cases covering
  HashML-DSA-44-SHA256, HashML-DSA-65-SHA512, and HashML-DSA-87-SHA512 via
  `CKM_HASH_ML_DSA_SHA256` / `CKM_HASH_ML_DSA_SHA512`. Skips gracefully when
  `CKM_HASH_ML_DSA` is absent from the mechanism list.

- **§9.5 HashSLH-DSA functional sign+verify**: Two test cases covering
  HashSLH-DSA-SHA2-128f-SHA256 and HashSLH-DSA-SHA2-256f-SHA512 via
  `CKM_HASH_SLH_DSA_SHA256` / `CKM_HASH_SLH_DSA_SHA512`. Skips gracefully when
  `CKM_HASH_SLH_DSA` is absent.

- **§10.5 SHA3-256 digest empty-string KAT** (FIPS 202): Validates
  `digest([], CKM_SHA3_256) == a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`.
  Skips when `CKM_SHA3_256` absent.

- **§16.5 Ed25519ph functional sign+verify**: Round-trip test using `CKM_EDDSA_PH`. Generates
  Ed25519 key pair, signs with pre-hash mode, verifies. Skips when `CKM_EDDSA_PH` absent.

Total ACVP test vectors: **37 per engine, 74 in dual-HSM mode** (was 31 / 62).

### Removed

- **`rust/tests/pqc_api_test.rs`**: Pure-Rust unit tests for ML-KEM and SLH-DSA context/
  deterministic signing removed. Superseded by the WASM-layer ACVP test suite
  (`tests/acvp-wasm.mjs`) which validates these paths against real PKCS#11 dispatch.

- **`rust/tests/test_xmss.rs`**: Stub XMSS unit test removed. XMSS is tested end-to-end in
  the WASM integration suite.

---

## [0.4.15] — 2026-04-07

### Fixed

- **RSA public key: `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` per PKCS#11 v3.2 §2.1.2 — Rust engine**:
  RSA public keys generated by `C_GenerateKeyPair` were stored as `CKA_VALUE` with a custom
  `[n_len:4LE][n_bytes][e_bytes]` packed format. PKCS#11 v3.2 §2.1.2 (Table 37) requires
  `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` as distinct attributes; `CKA_VALUE` is not defined for
  `CKO_PUBLIC_KEY / CKK_RSA` objects.

  **Impact of the bug:**
  - `C_GetAttributeValue` returned `CK_UNAVAILABLE_INFORMATION` (0xFFFFFFFF) for both
    `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT`, causing a JavaScript `RangeError: Length out of
    range of buffer` crash in callers that allocated based on the returned length.
  - `C_Verify` for `CKM_SHA256_RSA_PKCS` / `CKM_SHA256_RSA_PKCS_PSS` always failed with
    `CKR_KEY_TYPE_INCONSISTENT` because `get_rsa_public_components()` reads `CKA_MODULUS` and
    `CKA_PUBLIC_EXPONENT` from the object store and returned `None`.

  **Fix:** store `n_bytes` as `CKA_MODULUS`, `e_bytes` as `CKA_PUBLIC_EXPONENT`, and the key
  size as `CKA_MODULUS_BITS`. Removed `CKA_VALUE` from RSA public key objects. Private key
  `CKA_VALUE` (PKCS#8 DER) is unchanged.

---

## [0.4.10] — 2026-04-07

### Added

- **`CKM_ECDSA_SHA512` (0x1046) — Rust engine**: ECDSA with SHA-512 prehash on P-256 and P-384.
  Required for the `id-MLDSA65-ECDSA-P256-SHA512` composite certificate OID
  (draft-ietf-lamps-pq-composite-sigs). Previously returned `CKR_MECHANISM_INVALID`.

- **Message Encrypt/Decrypt API — Rust engine** (PKCS#11 v3.0 per-message AEAD, 10 functions):
  `C_MessageEncryptInit`, `C_EncryptMessage`, `C_EncryptMessageBegin`, `C_EncryptMessageNext`,
  `C_MessageEncryptFinal`, `C_MessageDecryptInit`, `C_DecryptMessage`, `C_DecryptMessageBegin`,
  `C_DecryptMessageNext`, `C_MessageDecryptFinal`. AES-GCM with per-message IV and AAD.
  State tracked in `MsgAeadCtx` (key, IV, AAD, tag bits, payload accumulator, `in_message` guard).

- **`C_VerifySignatureUpdate` / `C_VerifySignatureFinal` — Rust engine**: Streaming pre-bound
  verify (PKCS#11 v3.2 §11.15). Accumulates message parts in `VerifySigCtx.msg_acc`, then
  delegates to `C_Verify` on `Final`. Completes the multi-part pre-bound verify surface
  introduced in v0.4.8.

- **PKCS#11 v3.2 async stubs — Rust engine**: `C_GetSessionValidationFlags`, `C_AsyncComplete`,
  `C_AsyncGetID` return `CKR_FUNCTION_NOT_SUPPORTED`. Brings total Rust exports to **85 PKCS#11
  functions** (plus `set_kat_seed`).

### Fixed

- **`CKM_ECDSA_SHA512` hash truncation (FIPS 186-5 §6.4)**: SHA-512 produces 64 bytes but
  `p256::PrehashSigner` requires exactly 32 bytes (P-256 field size). Sign and verify now
  truncate to the leftmost 32 bytes for P-256, 48 bytes for P-384, per spec.

- **G-ATTR1a — ML-DSA public key `CKA_VALUE` — C++ engine**: Was `checks=0`; corrected to
  `ck1|ck4` per PKCS#11 v3.2 Table 280 (`^1` required for `C_CreateObject`, `^4` MUST NOT for
  `C_GenerateKeyPair`). `CKA_PARAMETER_SET` corrected to `ck1|ck3` (was `ck3` only, missing `^1`).

- **G-ATTR1b — SLH-DSA public key `CKA_VALUE` — C++ engine**: Same fix as G-ATTR1a; references
  spec Table 287. `CKA_PARAMETER_SET` corrected to `ck1|ck3`.

- **G-ATTR1c — ML-KEM public key `CKA_VALUE` — C++ engine**: Same fix; references spec Table 290.
  `CKA_PARAMETER_SET` corrected to `ck1|ck3`.

- **HSS public key attribute flags — C++ engine**: `CKA_VALUE` corrected to `ck1|ck4`;
  `CKA_HSS_LEVELS`, `CKA_HSS_LMS_TYPE`, `CKA_HSS_LMOTS_TYPE`, `CKA_HSS_LMS_TYPES`,
  `CKA_HSS_LMOTS_TYPES` corrected to `ck2|ck4` (MUST NOT for both create and generate) per
  PKCS#11 v3.2 Table 269. HSS private key `CKA_VALUE` corrected to `ck1|ck4|ck6|ck7`.

- **XMSS / XMSS-MT attribute flags — C++ engine**: Public key `CKA_VALUE` corrected to `ck1|ck4`,
  `CKA_PARAMETER_SET` to `ck1|ck3`. Private key `CKA_VALUE` corrected to `ck1|ck4|ck6|ck7`,
  `CKA_PARAMETER_SET` to `ck1|ck4|ck6`. Same corrections applied to XMSS-MT objects. Per
  PKCS#11 v3.2 Tables 273, 275 (and XMSS-MT equivalents).

- **`P11AttrParameterSet`, `P11AttrHssLevels/LmsType/LmotsType/LmsTypes/LmotsTypes` base
  constructors — C++ engine**: Removed erroneous `ck1` from default `checks` in base constructor
  bodies. Flags are now set exclusively at the call site in `P11Objects.cpp` via the `inchecks`
  parameter, eliminating double-application of `ck1` that could cause spurious
  `CKR_TEMPLATE_INCOMPLETE` on `C_GenerateKeyPair`.

- **`Slot::isTokenPresent()` — C++ engine**: Now returns `token->isInitialized()` instead of
  unconditional `true`. Uninitialized placeholder slots are no longer reported as token-present,
  fixing `C_GetSlotList(tokenPresent=CK_TRUE)` to correctly exclude empty slots per PKCS#11
  v3.2 §4.2.2.

---

## [0.4.8] — 2026-04-06

### Added

- **`CKA_XMSS_KEYS_REMAINING` (vendor attr 0x80000106)**: Separate from `CKA_HSS_KEYS_REMAINING`;
  tracks remaining XMSS signature operations as a `u32` LE value per PKCS#11 v3.2 §6.15.
- **`xmss_param_max_sigs()` / `xmss_keys_remaining()`**: Compute XMSS signature capacity (2^H)
  and derive remaining count by reading the leaf index directly from the serialised key blob
  (big-endian at offset 4 after OID), tolerating crate-internal leaf skipping.
- **`CKR_ATTRIBUTE_TYPE_INVALID` (0x00000012)**: Exported constant per PKCS#11 v3.2 §11.7.

### Fixed

- **`C_GetSlotList` token-present filter**: Now correctly filters on `token.initialized` when
  `tokenPresent = CK_TRUE` (was always returning all slots regardless of flag).
- **`C_GetAttributeValue` PKCS#11 v3.2 §5.7.5 compliance**:
  - Public keys (`CKO_PUBLIC_KEY`) are always fully readable — `CKA_SENSITIVE` / `CKA_EXTRACTABLE`
    restrictions now apply only to private and secret keys.
  - Absent attributes now set `ulValueLen = CK_UNAVAILABLE_INFORMATION` and the function returns
    `CKR_ATTRIBUTE_TYPE_INVALID` as required (was silently returning `CKR_OK`).
- **`C_Sign` XMSS state tracking**: Updates `CKA_XMSS_KEYS_REMAINING` by re-reading the leaf
  index from the updated key blob after each sign — avoids off-by-one from simple decrement.
- **`C_Sign` HSS state update**: `new_state` clone now stored correctly; leaf index and
  keys-remaining tracked in separate HSS vs XMSS code paths.
- **HSS keygen `CKA_HSS_KEYS_REMAINING`**: Computes actual capacity (∏ 2^H_i across levels,
  capped at `u32::MAX`) instead of hardcoded placeholder value of 32.
- **XMSS keygen `CKA_XMSS_KEYS_REMAINING`**: Stored under the new vendor attribute
  `CKA_XMSS_KEYS_REMAINING` (0x80000106) — was incorrectly aliased to `CKA_HSS_KEYS_REMAINING`.
- **`hss_sign()` hash-family dispatch**: Now takes `lms_param` and routes to the correct
  `hbs-lms` generic (`Sha256_256 / Sha256_192 / Shake256_256 / Shake256_192`) — previously
  always used `Sha256_256`, causing silent `CKR_KEY_EXHAUSTED` on M24/SHAKE parameter sets.
- **`lms_single_sig_len()` full SP 800-208 coverage**: Derives `n` and `p` from IANA type-ID
  ranges — correct for all 20 LMS × 16 LMOTS combinations (SHA-256 N24, SHAKE-256 N32/N24
  were previously returning wrong lengths).
- **`hss_sig_len()` LMS public key size**: Corrected 52 → 56 bytes per RFC 8554 §5.4
  (`lms_type(4) + lmots_type(4) + I(16) + T[1](32)`).
- **`get_sig_len()` XMSS support**: Added `CKM_XMSS` case; removed duplicate unreachable
  `CKM_HSS` match arm.
- **`C_GetMechanismInfo` ML-KEM key sizes**: Corrected from security-bit values (128/256) to
  actual encapsulation key byte lengths (800/1568 per FIPS 203).

---

## [0.4.7] — 2026-04-05

### Added

- **SP 800-208 full parameter coverage**: All 20 LMS and 16 LMOTS parameter sets now supported
  across C++ and Rust engines (SHA-256 N32/N24, SHAKE-256 N32/N24).
- **C++ `StatefulVerifyInit` / `StatefulVerify`**: HSS/LMS/XMSS/XMSS^MT signature verification
  through PKCS#11 `C_VerifyInit` / `C_Verify`. Previously only signing was implemented in C++.
- **C++ SHAKE-256 hash type**: Added `HASH_SHAKE256` to hash-sigs library using OpenSSL
  `EVP_shake256()` for SHAKE-256 XOF output (32-byte and 24-byte modes).
- **C++ XMSS/XMSS^MT in `C_GetMechanismInfo`**: Registered `CKM_XMSS_KEY_PAIR_GEN`,
  `CKM_XMSS`, `CKM_XMSSMT_KEY_PAIR_GEN`, `CKM_XMSSMT` with `CKF_SIGN | CKF_VERIFY`.
- **Rust N24/SHAKE dispatch**: `lms_keygen` dispatches to `Sha256_192`, `Shake256_256`,
  `Shake256_192` hash types via hbs-lms 0.1.1 built-in support.
- **NIST ACVP LMS sigVer validation**: 320/320 official demo vectors validated
  ([usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)) covering all
  80 parameter combinations. Test runner: `tests/test_acvp_lms_sigver.py`.
- **ACVP vector files**: `tests/acvp/lms_keygen_*`, `lms_sigver_*`, `lms_siggen_*` from NIST.

### Fixed

- **XMSS keygen buffer overflow**: Public/private key buffers now correctly allocate
  `XMSS_OID_LEN + pk/sk_bytes` (was `pk/sk_bytes` only — missing 4-byte OID prefix caused
  truncation and verify failure).
- **XMSS `C_Sign` PKCS#11 v3.2 compliance**: Stripped appended message from signature output.
  `xmss_sign()` returns `[sig || msg]`; `C_Sign` now returns signature-only as required by spec.
- **XMSS^MT keygen OID parsing**: Changed from `xmss_parse_oid` to `xmssmt_parse_oid` for
  XMSS^MT parameter sets.
- **CKP_ constants corrected to IANA registry values**: LMS constants used tree-height values
  (e.g., `CKP_LMS_SHA256_M32_H10 = 10`) instead of IANA type IDs (`0x06`). LMOTS constants
  used Winternitz W values (e.g., `CKP_LMOTS_SHA256_N32_W4 = 4`) instead of type IDs (`0x03`).
  All corrected to match RFC 8554 + SP 800-208 IANA registry.
- **C++ dead code removed**: Unreachable XMSS keygen stub at `SoftHSM_keygen.cpp:649`.
- **Session `verifyKeyHandle` initialization**: Both constructors now initialize
  `signKeyHandle` and `verifyKeyHandle` to `CK_INVALID_HANDLE`.

### Changed

- **Gap analysis G10 resolved**: `docs/gap-analysis-pkcs11-v3.2.md` §3.4 updated from
  "out of scope" to "RESOLVED" with implementation details for C++ and Rust engines.

---

## [0.4.6] — 2026-04-04

### Added

- **C++ Native Stateful Hash Signatures Bounds**: Integrated explicit fallback object-generation mapping in `SoftHSM_keygen.cpp` for native CKM_HSS_KEY_PAIR_GEN tracking, bounding `CKA_HSS_KEYS_REMAINING` properties directly in the object store.
- **WASM v3.2 Strict Mapping Attributes**: Mapped exactly `CKA_HSS_KEYS_REMAINING` with ID `0x0000061cUL` strictly enforcing exact signature deductions within C_Sign loop execution to guarantee PKCS#11 backend exhaustion on WebAssembly integrations.

---

## [0.4.5] — 2026-04-03

### Fixed

- **WASM session exclusivity checks:** Fixed CKR return codes and token tracking logic in `C_Login` and `C_OpenSession` within the Rust engine to correctly conform to PKCS#11 v3.2 boundaries (`CKR_SESSION_READ_ONLY_EXISTS` and `CKR_USER_ANOTHER_ALREADY_LOGGED_IN`).
- **WASM PIN hashing:** Implemented PKCS#11 compliant PBKDF2 hashing for PINs across the WASM layer.

---

## [0.4.4] — 2026-04-03

### Added

- **G10 — LMS/HSS stateful hash-based signatures (NIST SP 800-208, RFC 8554)**
  - `CKM_LMS_KEY_PAIR_GEN` / `CKM_LMS` (vendor, single-level LMS) via Rust hbs-lms 0.1.1
  - `CKM_HSS_KEY_PAIR_GEN` / `CKM_HSS` (PKCS#11 v3.2 §6.14, multi-level HSS, 1–8 levels)
  - Vendor key type `CKK_LMS`; standard `CKK_HSS`, `CKK_XMSS`, `CKK_XMSSMT`
  - Vendor attributes: `CKA_STATEFUL_KEY_STATE`, `CKA_LMS_PARAM_SET`, `CKA_LMOTS_PARAM_SET`,
    `CKA_XMSS_PARAM_SET`, `CKA_LEAF_INDEX` (range 0x80000101–0x80000105)
  - All 5 LMS tree-height parameter sets (H5/H10/H15/H20/H25) and 4 LMOTS Winternitz
    parameter sets (W1/W2/W4/W8) via `CKP_*` constants mirroring SP 800-208 Table 1
  - Key exhaustion: `CKR_KEY_EXHAUSTED` (0x203) returned on sign attempt past capacity
    — LMS: pre-check via `CKA_LEAF_INDEX ≥ 2^H`; HSS: callback_fired pattern
  - `C_Sign` / `C_Verify` dispatch for `CKM_LMS` and `CKM_HSS` via early-return path
    before standard object-value lookup; state atomically persisted via PKCS#11 callback
  - `CK_HSS_KEY_PAIR_GEN_PARAMS` struct (68 bytes) in `vendor_mechanisms.h` for HSS keygen
  - New C++ header `src/lib/vendor_mechanisms.h` — all vendor CKM/CKA/CKP constants,
    mirrored in `rust/src/constants.rs` and `src/wasm/softhsm/constants.ts`
  - Mechanism entries in `prepareSupportedMechanisms()` and `C_GetMechanismInfo` for
    CKM_LMS_KEY_PAIR_GEN, CKM_HSS_KEY_PAIR_GEN, CKM_LMS, CKM_HSS
  - TypeScript helpers in `src/wasm/softhsm/stateful.ts`: `hsm_generateLMSKeyPair`,
    `hsm_generateHSSKeyPair`, `hsm_lmsSign`, `hsm_lmsVerify`, `hsm_lmsGetLeafIndex`,
    `hsm_hssSign`, `hsm_hssVerify`

- **G11 — Keccak-256 (Ethereum address derivation)**
  - `CKM_KECCAK_256` (vendor 0x80000010) — Rust engine only via tiny-keccak 2.0
  - Streaming `C_DigestInit` / `C_DigestUpdate` / `C_DigestFinal` + one-shot `C_Digest`
  - C++ engine returns `CKR_MECHANISM_INVALID` (non-standard Keccak padding not in OpenSSL)
  - `DigestCtx::Keccak256(Vec<u8>)` variant in the Rust digest state machine
  - TypeScript helper `hsm_keccak256` in `src/wasm/softhsm/stateful.ts`
  - Mechanism entry in `prepareSupportedMechanisms()` for `CKM_KECCAK_256` (Rust engine only)

---

## [0.4.3] — 2026-04-02

### Added

- **X448 Diffie-Hellman** (PKCS#11 v3.2 §6.7, RFC 7748 §6.2) via x448 0.14 crate
  - `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` now dispatches X25519 vs X448 by last OID byte
  - RFC 7748 clamping applied at keygen; 56-byte shared secret from `diffie_hellman()`
  - `build_x448_spki()` helper: AlgId OID 1.3.101.111 (id-X448, RFC 8410)
- **X9.63 KDF SHA3 variants** (PKCS#11 v3.2 §5.2.12)
  - `CKD_SHA3_256_KDF` and `CKD_SHA3_512_KDF` counter-mode KDF loops
- **C_GetMechanismInfo**: Montgomery key-size range extended to 255–448

---

## [0.4.1] — 2026-03-29

### Security

- **OpenSSL 3.6.0 → 3.6.1:** 9 CVE fixes including TLS 1.3 CompressedCertificate
  excessive memory allocation (CVE-2025-66199), CMS AuthEnvelopedData stack buffer
  overflow (CVE-2025-15467), and OCSP stapling regression.

### Fixed

- **C_EncapsulateKey / C_DecapsulateKey template rejection (CKR 0x13):**
  `extractObjectInformation()` parsed CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, and
  CKA_KEY_TYPE from the caller's template, then a subsequent loop rejected those
  same attributes with `CKR_ATTRIBUTE_VALUE_INVALID` instead of skipping them.
  Full ML-KEM-768 encapsulate → decapsulate → shared-secret-match flow now passes.
- **handle_mgr missing OpenSSL include path:** `HandleManager.cpp` includes
  `<openssl/rand.h>` but `CMakeLists.txt` was missing `${CRYPTO_INCLUDES}`,
  causing `fatal error: 'openssl/rand.h' file not found` on clean WASM builds.

---

## [0.4.0] — 2026-03-22

### Security

Full remediation of the March 2026 security audit (`docs/security_audit_03222026.md`).
All 62 ACVP test vectors pass across both C++ and Rust WASM engines (31 per engine,
zero failures, zero skips) after these changes.

**Full audit report:** [`docs/security_audit_03222026.md`](docs/security_audit_03222026.md)

#### HIGH severity — fixed

- **RSA X.509 integer underflow (NEW-H1):** `size - ulDataLen` could underflow to
  `SIZE_MAX` when `ulDataLen > size`, causing a heap buffer overread. Added an explicit
  `ulDataLen > size → CKR_DATA_LEN_RANGE` guard in both sign and verify paths.
- **AES-CBC IV length not validated (NEW-H2):** `EncryptInit` / `DecryptInit` only
  rejected a NULL IV pointer; a non-16-byte IV silently used garbage memory as the
  remainder. Now returns `CKR_MECHANISM_PARAM_INVALID` unless `ulParameterLen == 16`.
- **WrapKeySym mode variable left zero (NEW-H3):** `CKM_AES_CBC` and `CKM_AES_CBC_PAD`
  cases in both `WrapKeySym` and `UnwrapKeySym` set `algo` but never set `mode`, leaving
  it at zero (`SymWrap::Unknown`). Now sets `mode = SymWrap::AES_KEYWRAP` /
  `AES_KEYWRAP_PAD` so the correct cipher path is selected.
- **pValue NULL dereference in object creation (NEW-H4):** Five required attributes
  (`CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_CERTIFICATE_TYPE`, `CKA_TOKEN`, `CKA_PRIVATE`)
  dereferenced `pTemplate[i].pValue` without a NULL check. Now returns
  `CKR_ATTRIBUTE_VALUE_INVALID` for any of these with a NULL value pointer.

#### MEDIUM severity — fixed

- **GcmMsgCtx param not wiped on reset (NEW-M1):** `Session::resetOp` called `free(param)`
  without zeroing first; the freed region retained GCM key material until reallocated.
  Now uses `memset(param, 0, paramLen)` before `free`.
- **Unbounded string read in object store (NEW-M2):** `File::readString` allocates a
  `std::vector<char>` of the on-disk `len` field; a malformed file could request GBs.
  Capped at 64 MiB — legitimate serialised strings never approach this.
- **Path traversal and symlink follow in Directory (NEW-M3):** `Directory::refresh` did
  not reject entries containing `..` or `/`, and followed symlinks. Now rejects both
  and explicitly skips `DT_LNK` entries (with `S_ISLNK` fallback for filesystems
  that return `DT_UNKNOWN`).
- **ML-KEM shared secret not wiped (NEW-M4):** After `C_EncapsulateKey` /
  `C_DecapsulateKey`, both `sharedSecret` and `storedValue` are now explicitly wiped
  via `ByteString::wipe()` before going out of scope.
- **RSA-PSS salt length unbounded (NEW-M5):** A caller-supplied `sLen > 512` could
  exceed the maximum salt length OpenSSL accepts, causing an EVP error or signed output
  inconsistency. Now returns `CKR_MECHANISM_PARAM_INVALID` for `sLen > 512` at all
  20 PSS parameter sites in `SignInit` and `VerifyInit`.
- **Predictable PKCS#11 handle counter (NEW-M6):** `HandleManager` previously started
  at handle 1 on every process start. A 20-bit random offset (via `RAND_bytes`) is now
  applied at construction, making handles non-predictable across sessions.
- **SLH-DSA pure mode accepted non-NULL parameters (NEW-M7):** `CKM_SLH_DSA` cases
  in `SignInit` / `VerifyInit` passed without checking `pParameter`. Since the pure
  mode takes no parameters, a non-NULL `pParameter` is now rejected with
  `CKR_MECHANISM_PARAM_INVALID`.
- **Rust NULL output pointer dereferences (NEW-M8/9/10):** Several Rust FFI entry
  points (`C_GetSlotList`, `C_OpenSession`, `C_GenerateKeyPair`, `C_GenerateKey`,
  `C_EncapsulateKey`, `C_DecapsulateKey`) wrote to caller-supplied output pointers
  without checking for NULL. Added `.is_null()` guards returning `CKR_ARGUMENTS_BAD`.
- **HMAC timing side-channel (NEW-M11):** `verify_hmac` used `==` comparison, which
  short-circuits on the first mismatching byte. Replaced with
  `subtle::ConstantTimeEq::ct_eq()` for a branch-free constant-time comparison.
- **KMAC timing side-channel (NEW-M12):** Same issue in the KMAC verify path in
  `ffi.rs`. Fixed with `subtle::ConstantTimeEq`.
- **SymDecryptUpdate length overflow (NEW-M13):** `ulEncryptedDataLen + remainingSize`
  could overflow `CK_ULONG` for large inputs. Added an explicit overflow check before
  the addition, returning `CKR_ENCRYPTED_DATA_LEN_RANGE` on overflow.
- **IV not zeroized on error paths (CR-05):** Six error exit paths in
  `OSSLEVPSymmetricAlgorithm::encryptInit` and `decryptInit` returned without
  calling `iv.wipe()`. The local `iv` ByteString now wipes on all error paths.

#### Build and supply chain — fixed

- **Default build type changed to Release (SC-09):** `CMakeLists.txt` now defaults
  to `Release` instead of `RelWithDebInfo`, removing DWARF debug info from production
  binaries.
- **`package-lock.json` added (SC-03):** Lock file committed for reproducible `npm ci`
  installs.
- **Cargo files added to npm package manifest (SC-08):** `rust/Cargo.toml` and
  `rust/Cargo.lock` included in the published `files` array.
- **Optional GPG verification for OpenSSL (SC-01):** `build-openssl-wasm.sh` now
  downloads the detached `.asc` signature and verifies it with `gpg --verify` when
  GPG is available. Emits a warning rather than a hard error when GPG is absent.
- **Cargo audit CI job (SC-04):** New `rust-audit` GitHub Actions job runs
  `cargo audit --deny warnings` to catch known CVEs in Rust dependencies on every push.
- **Compiler hardening flags (SC-05):** `-fstack-protector-strong` added for all
  non-Emscripten / non-MSVC targets; `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`
  added for Linux builds.
- **WASM maximum memory limit (WS-01):** Emscripten link flags now include
  `-sMAXIMUM_MEMORY=536870912` (512 MiB) to prevent unbounded WASM heap growth.
- **SECURITY.md WASM limitations section (WS-02/03):** New section documents inherent
  WASM security constraints: no secure memory, exposed linear memory API, no ASLR,
  recommended HTTP headers.

---

## [0.3.0] — 2026-03-22

### Added

- ACVP Validation Suite with deterministic PRNG support for both C++ and Rust engines
- `CKA_CHECK_VALUE` (KCV) on all generated and imported keys — both engines
- Rust WASM engine: pre-hash ML-DSA / SLH-DSA (10 variants each), KMAC-128/256,
  SP 800-108 Counter/Feedback KDF, HKDF
- `C_VerifySignatureInit` / `C_VerifySignature` pre-bound verification (PKCS#11 v3.2)
- `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated` (PKCS#11 v3.2)
- `C_MessageEncryptInit` / `C_EncryptMessage` / `C_DecryptMessage` (PKCS#11 v3.0)
- `C_SignMessageBegin` / `C_SignMessageNext` streaming message sign/verify
- `CKA_PUBLIC_KEY_INFO` (SPKI/DER encoding for public keys)
- `CKM_HKDF_DERIVE`, `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`
- ECDSA + RSA SHA-3 signature variants (`CKM_ECDSA_SHA3_*`, `CKM_RSA_SHA3_*_PKCS`,
  `CKM_RSA_SHA3_*_PKCS_PSS`)
- `CKM_PKCS5_PBKD2` — password-based key derivation (PKCS#5 v2.1)

### Fixed

- ACVP deterministic PRNG correctness (C++ and Rust engines)
- `C_DecryptMessageNext` null-buffer query consumed ciphertext
- `C_VerifySignatureFinal` did not work with ML-DSA mechanisms
- `CKP_SLH_DSA_*` and `CKM_HASH_SLH_DSA_*` constant values aligned with OASIS pkcs11t.h

---

## [0.2.0] — 2026-03-22

### Added

#### Rust WASM Engine

A second WASM engine built entirely in Rust (RustCrypto backend, no C/OpenSSL dependency).
Both engines expose the same `SoftHSMModule` interface, so existing code works with either one.

| | C++ / Emscripten | Rust |
| --- | --- | --- |
| Binary size | ~2.2 MB | **~1.4 MB** |
| Crypto backend | OpenSSL 3.6 | RustCrypto crates |
| Pre-hash ML-DSA / SLH-DSA | Yes (10 variants each) | **Yes (10 variants each)** |
| Build toolchain | Emscripten + CMake | `wasm-pack` |

**Selecting an engine:**

```js
// C++ engine (default)
import { getSoftHSMCppModule } from '@pqctoday/softhsm-wasm'
const M = await getSoftHSMCppModule()

// Rust engine
import { getSoftHSMRustModule } from '@pqctoday/softhsm-wasm'
const M = await getSoftHSMRustModule()
```

Both return the same `SoftHSMModule` type — all `_C_*` function calls, `_malloc`, `_free`,
`HEAPU8`, `setValue`, and `getValue` work identically.

**Algorithms supported by the Rust engine:**

- **Post-quantum:** ML-KEM-512/768/1024, ML-DSA-44/65/87 (pure + 10 pre-hash variants each),
  SLH-DSA (all 12 parameter sets, pure + 10 pre-hash variants each)
- **Classical:** RSA (PKCS#1 v1.5 / OAEP / PSS), ECDSA P-256/P-384 (+ SHA-3 variants), Ed25519, ECDH P-256, X25519
- **Symmetric:** AES-128/192/256 (GCM, CBC, Key Wrap)
- **Digest / MAC:** SHA-256/384/512, SHA3-256/512, HMAC-SHA256/384/512, HMAC-SHA3-256/512, KMAC-128/256
- **Key derivation:** HKDF (RFC 5869), PKCS#5 PBKDF2, SP 800-108 Counter/Feedback KDF

#### New mechanisms (C++ engine)

**Key derivation:**

- **HKDF** (`CKM_HKDF_DERIVE`) — HMAC-based extract-and-expand key derivation (RFC 5869)
- **SP 800-108 Counter KDF** (`CKM_SP800_108_COUNTER_KDF`) — NIST key-based KDF using
  counter mode, commonly used for deriving multiple keys from a master key
- **SP 800-108 Feedback KDF** (`CKM_SP800_108_FEEDBACK_KDF`) — NIST key-based KDF using
  feedback mode, where each block's output feeds into the next derivation
- **Cofactor ECDH** (`CKM_ECDH1_COFACTOR_DERIVE`) — ECDH key agreement that multiplies
  the shared secret by the curve cofactor, preventing small-subgroup attacks

**Pre-hash signatures — SLH-DSA:**

10 pre-hash variants that hash the message before signing, useful when the message
is large or when you need a specific hash algorithm for compliance:
`CKM_HASH_SLH_DSA_SHA224`, `CKM_HASH_SLH_DSA_SHA256`, `CKM_HASH_SLH_DSA_SHA384`,
`CKM_HASH_SLH_DSA_SHA512`, `CKM_HASH_SLH_DSA_SHA3_224`, `CKM_HASH_SLH_DSA_SHA3_256`,
`CKM_HASH_SLH_DSA_SHA3_384`, `CKM_HASH_SLH_DSA_SHA3_512`, `CKM_HASH_SLH_DSA_SHAKE128`,
`CKM_HASH_SLH_DSA_SHAKE256`

**SHA-3 signature variants:**

- ECDSA with SHA-3: `CKM_ECDSA_SHA3_224/256/384/512`
- RSA PKCS#1 v1.5 with SHA-3: `CKM_RSA_SHA3_224/256/384/512_PKCS`
- RSA-PSS with SHA-3: `CKM_RSA_SHA3_224/256/384/512_PKCS_PSS`
- Password-based key derivation: `CKM_PKCS5_PBKD2`

#### New PKCS#11 APIs (C++ engine)

**Streaming message sign/verify** (PKCS#11 v3.2 §5.8) — sign or verify data in
chunks without buffering the entire message:

- `C_SignMessageBegin` / `C_SignMessageNext`
- `C_VerifyMessageBegin` / `C_VerifyMessageNext`

**Per-message AES-GCM encrypt/decrypt** (PKCS#11 v3.0) — encrypt multiple messages
under the same key in a single session, with automatic per-message IV management:

- `C_MessageEncryptInit` → `C_EncryptMessage` (one-shot) or
  `C_EncryptMessageBegin` / `C_EncryptMessageNext` (streaming) → `C_MessageEncryptFinal`
- Matching decrypt: `C_MessageDecryptInit` → `C_DecryptMessage` /
  `C_DecryptMessageBegin` / `C_DecryptMessageNext` → `C_MessageDecryptFinal`

**Pre-bound signature verification** (PKCS#11 v3.2) — bind a signature to the session
first, then supply data to verify against. Useful when the signature arrives before the data:

- `C_VerifySignatureInit` / `C_VerifySignature` (one-shot)
- `C_VerifySignatureUpdate` / `C_VerifySignatureFinal` (multi-part)

**Authenticated key wrap/unwrap** (PKCS#11 v3.2) — export and import keys with
AES-GCM integrity protection, ensuring the wrapped key hasn't been tampered with:

- `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated`

**Session management** (PKCS#11 v3.0):

- `C_LoginUser` — extended login with user type parameter
- `C_SessionCancel` — cancel an active multi-part operation

**Other:**

- `CKA_PUBLIC_KEY_INFO` attribute — retrieve a public key in standard SubjectPublicKeyInfo
  (SPKI / DER) encoding, as used in X.509 certificates

#### CKA_CHECK_VALUE (KCV) — both engines

All generated and imported keys now include a `CKA_CHECK_VALUE` attribute
(PKCS#11 v3.2 §4.10.2), enabling key integrity and identity verification without
exposing the key material:

- **Symmetric keys (AES):** first 3 bytes of AES-ECB encryption of a 16-byte zero block
- **Asymmetric keys (RSA, EC, EdDSA, ML-DSA, ML-KEM, SLH-DSA):** first 3 bytes of
  SHA-256 over the primary key material (modulus for RSA; public point for EC/EdDSA;
  raw bytes for PQC keys)
- **Imported keys** via `C_CreateObject` also receive a computed KCV
- Supported by both the C++ engine (`SoftHSM_keygen.cpp`, `SoftHSM_objects.cpp`)
  and the Rust engine (`state.rs: compute_kcv`)

#### ACVP test infrastructure — C++ engine

- Added `OSSLRNG_disableACVP()` to restore OpenSSL's default `RAND_OpenSSL()` method
  and release the internal cipher context after ACVP testing completes

### Fixed

- **ACVP deterministic PRNG — C++ engine:** Previous implementation repeated the
  32-byte seed cyclically with `buf[i] = seed[i % 32]` rather than generating a
  proper key-stream; now uses a ChaCha20 stream cipher (`EVP_chacha20`) seeded once
  and streamed continuously, matching the NIST ACVP test-vector generation process
- **ACVP deterministic PRNG — Rust engine:** Previous `with_rng!` macro created a
  fresh `ChaCha20Rng::from_seed(seed)` on every invocation, resetting the counter
  before each operation; now stores a persistent per-thread `ChaCha20Rng` in
  `ACVP_RNG` that advances its counter across operations, matching C++ engine behaviour
- Calling `C_DecryptMessageNext` with a null output buffer to query the required output
  size incorrectly performed the actual decryption, consuming the ciphertext
- `C_VerifySignatureFinal` / `C_VerifySignatureUpdate` did not work with ML-DSA mechanisms
- `C_DeriveKey` returned `CKR_MECHANISM_INVALID` for HKDF, SP 800-108, and cofactor ECDH
  mechanisms — these were registered but unreachable due to missing dispatch entries
- `C_GetMechanismInfo` returned incorrect capabilities for several SLH-DSA mechanisms
- `CKP_SLH_DSA_*` and `CKM_HASH_SLH_DSA_*` constant values aligned with the canonical
  `pkcs11t.h` header from OASIS (values were previously non-standard)

### Security

- **GCM authentication bypass in key unwrap** — `C_UnwrapKeyAuthenticated` did not
  validate the GCM authentication tag, allowing tampered wrapped keys to be imported.
  Now returns `CKR_ENCRYPTED_DATA_INVALID` on tag mismatch
- **Integer underflow in RSA-AES key unwrap** — crafted wrapped-key lengths could
  cause a negative-size subtraction leading to heap corruption
- **Integer overflow in symmetric encrypt** — large input buffers could overflow the
  output size calculation, causing an undersized allocation
- **Unbounded heap allocation from object store** — a malformed on-disk object file
  could trigger a multi-gigabyte allocation. Now capped at 64 MiB
- **Thread-safety race in token encryption** — concurrent access to the same token
  could corrupt internal AES cipher state. Each operation now uses an isolated cipher instance
- **Session state leak** — error paths in `C_FindObjectsInit` left the session locked
  in a find-operation state, preventing further operations until session close
- **Sensitive key material not wiped** — key data was not zeroed on object destruction.
  Now explicitly cleared from memory

---

## [0.1.0] — 2026

First public release of `@pqctoday/softhsm-wasm` — a PKCS#11 HSM emulator for
browsers and Node.js, with post-quantum cryptography support.

### Highlights

- **PKCS#11 v3.2** compliant interface (71 exported functions)
- **ML-KEM** (FIPS 203) — key encapsulation via `C_EncapsulateKey` / `C_DecapsulateKey`,
  ML-KEM-512/768/1024
- **ML-DSA** (FIPS 204) — digital signatures via `C_Sign` / `C_Verify`,
  ML-DSA-44/65/87, plus 10 pre-hash variants (`CKM_HASH_ML_DSA_*`)
- **SLH-DSA** (FIPS 205) — stateless hash-based signatures, all 12 SHA2/SHAKE parameter sets
- **One-shot message signing** — `C_MessageSignInit` / `C_SignMessage` /
  `C_MessageVerifyInit` / `C_VerifyMessage` (PKCS#11 v3.0)
- **Interface negotiation** — `C_GetInterfaceList` / `C_GetInterface` for
  runtime PKCS#11 version discovery
- **TypeScript declarations** included — full `SoftHSMModule` type with all `_C_*` functions
- **Constants module** — `import CK from '@pqctoday/softhsm-wasm/constants'` for all
  `CKM_*`, `CKA_*`, `CKR_*`, `CKK_*` values
- Works in modern browsers (Chrome, Firefox, Safari, Edge) and Node.js 18+

### Removed (vs SoftHSM2)

- GOST R 34.10 / R 34.11 algorithms
- DES / 3DES mechanisms
- Classical DSA and Diffie-Hellman key agreement
- OpenSSL ENGINE API (replaced with EVP-only backend)
- Autotools build system (replaced with CMake)

[0.4.26]: https://github.com/pqctoday/softhsmv3/compare/v0.4.25...v0.4.26
[0.4.25]: https://github.com/pqctoday/softhsmv3/compare/v0.4.24...v0.4.25
[0.4.24]: https://github.com/pqctoday/softhsmv3/compare/v0.4.0...v0.4.24
[0.4.0]: https://github.com/pqctoday/softhsmv3/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pqctoday/softhsmv3/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pqctoday/softhsmv3/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pqctoday/softhsmv3/releases/tag/v0.1.0
