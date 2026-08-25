# Implementation Plan — JDK 27 JCA/JCE Provider over softhsmv3 PKCS#11

**Date:** 2026-08-24
**Status:** PLAN — not started. No code exists for this yet.
**Replaces:** the `JavaJCE/` directory (audited 2026-08-24 and found to be
non-functional placeholder code: hardcoded fake return values, missing
implementing classes, references to a patched JVM and a
`playground-physics`/`Dockerfile.physics` container that do not exist in
this repo, and a wrong `CKM_ML_KEM` constant). Nothing in `JavaJCE/` is
reused; this plan is a from-scratch build on the proven `P11Ffm` pattern
from pqctoday-sandbox.

---

## 1. Objective

A real, installable `java.security.Provider` that bridges the JDK 27
JCA/JCE framework to our PKCS#11 v3.2 implementation, so ordinary Java
code can do

- `Signature.getInstance("ML-DSA-65")`
- `KEM.getInstance("ML-KEM-768")`
- `Cipher.getInstance("AES/GCM/NoPadding")`
- `KeyStore.getInstance("PKCS11-SoftHSMv3")`

…with every operation executed **inside the token**, never in Java
software crypto. Coverage target: **all published FIPS PQC standards
(ML-DSA, ML-KEM, SLH-DSA) plus the FIPS-approved classical set**, under a
**FIPS 140-3 Level 3 operational posture** — deprecated and non-approved
mechanisms are deliberately excluded even though the engine implements
them.

### Decisions locked (user, 2026-08-24)

| Decision | Choice |
|---|---|
| Engine | **Phase 1: C++ `libsofthsmv3.so` in-process via FFM.** Phase 2: Rust engine via the existing gRPC remoting (the Rust engine is memory-only in-process, so it is reached through `remoting/`, not loaded directly). |
| Home | **pqctoday-hsm, replacing `JavaJCE/`** — a Maven module beside the other protocol wrappers (`openssh-pkcs11/`, `openmls-provider/`, `strongswan-pkcs11/`). |
| PQC scope | **All FIPS: ML-DSA-44/65/87, ML-KEM-512/768/1024, SLH-DSA (12 parameter sets).** Stateful HSS/LMS + XMSS/XMSS-MT (SP 800-208) documented as a later phase (§10). |
| TLS | **Yes — distinct phase**: JDK 27 (JEP 527) hybrid TLS handshake using HSM-backed ML-KEM, verified live against `pqc-rest`'s quantum-safe endpoint. |
| Algorithm policy | **FIPS 140-3 L3 coverage only; deprecated mechanisms dropped** (no SHA-1, no MD5, no raw RSA, no RSA PKCS#1 v1.5 *encryption*, no ChaCha20 family, etc. — full exclusion table in §5). |

---

## 2. Facts this plan is grounded on (verified this session)

1. **`SunPKCS11` cannot do PQC — even on JDK 27 RC.** Empirically
   confirmed against a real token: `Signature.getInstance("ML-DSA", sunPkcs11)`
   throws `NoSuchAlgorithmException`. JEP 496/497/527 added software
   implementations and TLS wiring but never touched SunPKCS11's
   mechanism-mapping table, and SunPKCS11 speaks PKCS#11 v2.x (no
   `C_GetInterface`, no `C_EncapsulateKey`/`C_DecapsulateKey`). A custom
   provider is the only path — this is the gap the fabricated `JavaJCE`
   pretended to fill.
2. **The FFM bridge pattern is proven.** pqctoday-sandbox's
   `P11Ffm.java` already performs, against the live C++ token via
   `java.lang.foreign`: `C_GetInterface` (v3.2 negotiation), session
   open/login, ML-DSA-65 keygen/sign/verify (real 3309-byte signatures),
   ML-KEM-768 keygen/encapsulate/decapsulate (real 1088-byte
   ciphertexts). The provider's native layer is a generalization of this
   file, not new research.
3. **JDK version ladder:** FFM final since JDK 22 (JEP 454); `javax.crypto.KEM`
   API since JDK 21 (JEP 452); ML-KEM/ML-DSA standard names + software
   providers since JDK 24 (JEP 496/497); hybrid TLS groups
   (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) in JDK 27
   (JEP 527, status Closed/Delivered) — currently **RC build 27+35-2325
   (2026-08-20), GA targeted 2026-09-15**. The RC is already installed in
   the dev-sandbox image at `/usr/lib/jvm/jdk-27-rc` (sha256-verified).
   Anchored against the JEP 527 text (fetched 2026-08-24): only
   `X25519MLKEM768` is **enabled by default** (default group list:
   `X25519MLKEM768, x25519, secp256r1, secp384r1, secp521r1, x448,
   ffdhe2048/3072/4096`); **`SecP256r1MLKEM768` and `SecP384r1MLKEM1024`
   are NOT enabled by default** and must be turned on via
   `jdk.tls.namedGroups` or `SSLParameters::setNamedGroups`. Pure
   (non-hybrid) ML-KEM groups are an explicit JEP non-goal. The
   `X25519MLKEM768` share concatenation order is ML-KEM-first (reversed
   per RFC 10024 — noted in the JDK source).
3a. **JSSE *does* delegate ML-KEM to installed providers — confirmed in
   JDK source (2026-08-24), not just planned as a spike.** JDK 27
   implements the hybrids in `sun.security.ssl.HybridProvider` /
   `Hybrid.java` (openjdk/jdk master). `HybridProvider` itself is
   internal (never installed in the searched provider list), but its
   `Hybrid` machinery resolves components via **system provider search**:
   `KeyPairGenerator.getInstance("ML-KEM-768"|"ML-KEM-1024")`,
   `KeyFactory.getInstance(...)`, and `KEM.getInstance("ML-KEM")` — the
   source comment says verbatim: *"This is done to work with 3rd-party
   providers that only have 'ML-KEM' KEM algorithm."* The classical half
   (X25519/secp*) is pinned to the internal DH-as-KEM wrapper.
   Consequences for our provider (binding requirements):
   - register `KEM` under the **family name `"ML-KEM"`** (JSSE requests
     that, not the parameterized name), plus parameterized aliases;
   - register `KeyPairGenerator`/`KeyFactory` under `ML-KEM-768`/`-1024`;
   - hybrid share assembly calls `getEncoded()` on the **public** key —
     public keys must export standard encodings (private keys stay
     opaque; the KEM API's delayed provider selection picks the provider
     whose `KEMSpi` accepts our opaque private key for decapsulation).
3b. **SunPKCS11's gap is documented, not just observed:** the JDK 26
   PKCS#11 Reference Guide states the provider targets **PKCS#11 v2.20
   or later**, and its supported-mechanism table (Table 5-3) contains no
   ML-DSA/ML-KEM/SLH-DSA and no `C_GetInterface`/v3.x features —
   corroborating our empirical `NoSuchAlgorithmException` on the JDK 27
   RC. (ML-KEM/ML-DSA private-key encoding follow-ups are tracked
   upstream as JDK-8349163 — relevant to W2 KeyFactory design.)
3c. **JDK 27 Standard Algorithm Names (EA doc, checked 2026-08-24):**
   ML-DSA-44/65/87 and ML-KEM-512/768/1024 are standard names
   (KeyFactory/KeyPairGenerator/Signature/KEM); HKDF appears as
   `HKDF-SHA256/384/512` under the **KDF API**; **SLH-DSA, HashML-DSA,
   and KMAC are absent** — so our provider-defined names for those are
   confirmed non-colliding today (risk table §9 covers a future JDK
   claim of the names).
4. **The C++ engine is conformant:** 779 PASS / 0 FAIL / 36 SKIP on the
   v3.2 compliance test (`p11_v32_compliance_test.cpp`), run live
   2026-08-24.
5. **Engine mechanism inventory** (grepped from `src/lib/SoftHSM*.cpp`
   2026-08-24) is the basis of the coverage matrix in §4/§5 — the
   provider maps only what the engine actually dispatches.
6. **Rust remoting exists and works:** `remoting/proto/proto/pkcs11_remote.proto`
   (8 RPCs), gRPC :5710 / REST :5720, mTLS via the shared `/admin-certs`
   volume, kebab-case algorithm ids (`ml-dsa65`, `ml-kem768`), quantum-safe
   TLS profile refusing classical groups. Verified live from Python, C,
   C++, and Java this week. Phase 2 reuses this — nothing new is invented.

---

## 3. Architecture

```
 Java application
   │  Signature / KEM / Cipher / Mac / MessageDigest / KeyStore /
   │  KeyPairGenerator / KeyAgreement / SecureRandom / KeyFactory
   ▼
 SoftHSMv3Provider (java.security.Provider, name "SoftHSMv3")
   │  registers *Spi classes; enforces the approved-only algorithm policy;
   │  runs power-on self-tests before first service is handed out
   ▼
 P11 runtime layer (one class family, no JDK-internal APIs)
   ├─ P11Library    — FFM binding: dlopen, C_GetInterface → CK_FUNCTION_LIST_3_2,
   │                  MethodHandles per function, Arena/MemorySegment lifecycle
   ├─ P11SessionPool— login state, per-thread/per-op session leasing, PIN policy
   ├─ P11Error      — CKR_* → JCA exception mapping (no swallowed errors)
   └─ P11ObjectMap  — attribute templates, opaque handle↔Key object mapping
   ▼
 Transport (interface — selected by provider config)
   ├─ Phase 1: InProcessTransport → libsofthsmv3.so (C++ engine, file-backed token)
   └─ Phase 2: GrpcTransport      → remoting gRPC :5710 → softhsmrustv3 (Rust)
   ▼
 PKCS#11 v3.2 token
```

Key architectural rules:

- **No software crypto in the provider. Ever.** Every primitive routes to
  `C_*` calls. If the token can't do it, the operation fails — no silent
  fallback to SunJCE (a FIPS 140-3 bypass would otherwise exist).
- **No JDK-internal APIs.** No `sun.security.pkcs11.wrapper.*` (the
  fabricated JavaJCE's mistake). Pure `java.lang.foreign` + public JCA
  SPIs. Runs with `--enable-native-access=ALL-UNNAMED` only.
- **Opaque keys.** Private/secret keys surface as handle-backed `Key`
  objects with `getFormat() == null` and `getEncoded() == null` —
  key material never crosses into the JVM (L3 posture, §6). Public keys
  export as X.509 `SubjectPublicKeyInfo` via `KeyFactory`.
- **Transport is an interface from day 1** so Phase 2 (Rust via gRPC) is
  a new transport class + config, not a rewrite. The JCA surface and
  tests are transport-agnostic.
- **Build:** Maven module `JavaJCE/` (directory name kept, contents
  replaced), jar consumable by pqctoday-sandbox's `samples/java/` and
  anything else. `maven.compiler.release=24` for the core (FFM + KEM API
  are all ≥21/22), with the TLS phase's tests requiring the JDK 27 RC.

---

## 4. Coverage matrix — approved surface (what the provider registers)

Legend: **P11 mechanism** = what the engine dispatches (verified
inventory); **FIPS basis** = why it's in the approved set.

### 4.1 FIPS PQC (the core deliverable)

| JCA service | Names registered | P11 mechanism | FIPS basis |
|---|---|---|---|
| KeyPairGenerator, Signature | `ML-DSA-44/65/87` (+ alias `ML-DSA`) | `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA` | FIPS 204 |
| Signature (pre-hash) | `HashML-DSA-SHA512` etc. | `CKM_HASH_ML_DSA(_SHA256/384/512, _SHA3_*, _SHAKE128/256)` | FIPS 204 §5.4 |
| KeyPairGenerator, KEM | `ML-KEM-512/768/1024` **and the family name `ML-KEM`** (JSSE requests `KEM.getInstance("ML-KEM")` — §2.3a; the family entry resolves the parameter set from the key/spec) | `CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM` via `C_EncapsulateKey`/`C_DecapsulateKey` | FIPS 203 |
| KeyPairGenerator, Signature | `SLH-DSA-SHA2-128S` … `SLH-DSA-SHAKE-256F` (12 sets) | `CKM_SLH_DSA_KEY_PAIR_GEN`, `CKM_SLH_DSA` | FIPS 205 |
| Signature (pre-hash) | `HashSLH-DSA-*` | `CKM_HASH_SLH_DSA_*` | FIPS 205 §10.2 |

Notes:
- ML-DSA/ML-KEM names match JDK 24's standard names exactly, so the same
  application code runs against our provider or the JDK's software
  provider by changing only provider selection — and cross-verification
  between the two is a first-class test (§8).
- SLH-DSA has **no** JDK standard API yet; we define names following the
  NIST/IANA parameter-set spelling. Cross-verification uses ACVP KATs
  (already in this repo's test assets), not the JDK.
- Parameter set maps to `CKA_PARAMETER_SET` (`0x61d`); ML-KEM keys carry
  `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` (`0x633`/`0x634`), not
  encrypt/decrypt — same fixes we just made across the sandbox samples.

### 4.2 Classical asymmetric (FIPS-approved subset)

| JCA service | Names | P11 mechanism | FIPS basis |
|---|---|---|---|
| KeyPairGenerator | `EC` (P-256/384/521), `RSA` (≥2048, prefer 3072), `Ed25519`/`Ed448` | `CKM_EC_KEY_PAIR_GEN`, `CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_EC_EDWARDS_KEY_PAIR_GEN` | FIPS 186-5, SP 800-186 |
| Signature | `SHA256/384/512withECDSA`, SHA3 variants | `CKM_ECDSA_SHA256/384/512`, `CKM_ECDSA_SHA3_*` (single-part `CKM_ECDSA` for `NONEwithECDSA…InP11` internal use) | FIPS 186-5 |
| Signature | `Ed25519`, `Ed448` (+ pre-hash `EDDSA_PH`) | `CKM_EDDSA`, `CKM_EDDSA_PH` | FIPS 186-5 |
| Signature | `RSASSA-PSS` (SHA-2/SHA-3 params), `SHA256/384/512withRSA` | `CKM_SHA*_RSA_PKCS_PSS`, `CKM_SHA*_RSA_PKCS` | FIPS 186-5 (v1.5 remains approved **for signatures**) |
| Cipher (key transport) | `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` (+384/512) | `CKM_RSA_PKCS_OAEP` | SP 800-56B r2 |
| KeyAgreement | `ECDH` | `CKM_ECDH1_DERIVE` (cofactor variant where applicable) | SP 800-56A r3 |

### 4.3 Symmetric, MAC, digest, KDF, RNG

| JCA service | Names | P11 mechanism | FIPS basis |
|---|---|---|---|
| KeyGenerator | `AES` (128/192/256) | `CKM_AES_KEY_GEN` | FIPS 197 |
| Cipher | `AES/GCM/NoPadding`, `AES/CBC/PKCS5Padding`, `AES/CBC/NoPadding`, `AES/CTR/NoPadding` | `CKM_AES_GCM`, `CKM_AES_CBC_PAD`, `CKM_AES_CBC`, `CKM_AES_CTR` | SP 800-38A/38D |
| Cipher (key wrap) | `AESWrap`, `AESWrapPad` | `CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_PAD` | SP 800-38F |
| Mac | `HmacSHA224/256/384/512`, `HmacSHA3-224/256/384/512`, `AESCMAC`, `KMAC128/256` | `CKM_SHA*_HMAC`, `CKM_SHA3_*_HMAC`, `CKM_AES_CMAC`, `CKM_KMAC_128/256` | FIPS 198-1, SP 800-38B, SP 800-185 |
| MessageDigest | `SHA-224/256/384/512`, `SHA3-224/256/384/512` | `CKM_SHA224…512`, `CKM_SHA3_*` | FIPS 180-4, FIPS 202 |
| KDF (`javax.crypto.KDF` / `KDFSpi`) | `HKDF-SHA256/384/512` — these are the JDK 27 standard KDF names (§2.3c), so HKDF registers via the KDF API, **not** SecretKeyFactory | `CKM_HKDF_DERIVE` | SP 800-56C r2 |
| SecretKeyFactory | `PBKDF2WithHmacSHA256/512`; SP 800-108 counter/feedback KDFs as provider-named services | `CKM_PKCS5_PBKD2`, `CKM_SP800_108_COUNTER_KDF`/`_FEEDBACK_KDF` | SP 800-132, SP 800-108 r1 |
| SecureRandom | `SoftHSMv3-DRBG` | `C_GenerateRandom` / `C_SeedRandom` | SP 800-90A (engine's OpenSSL DRBG) |
| KeyStore | `PKCS11-SoftHSMv3` | `C_FindObjects` + attribute templates | — |

GCM note (L3-relevant): IVs for encryption are generated **inside the
module** (SP 800-38D §8.2 compliance) — the provider rejects
caller-supplied encryption IVs by default, returning the token-generated
IV via `Cipher.getIV()`. A config flag documents the non-FIPS escape
hatch but ships off.

---

## 5. Excluded surface — deprecated / non-approved (deliberate)

The engine dispatches all of these; the provider **must not register
any of them**. The policy layer additionally refuses them if requested by
alias, so exclusion is enforced, not just omitted.

| Mechanism family | Why excluded |
|---|---|
| `CKM_SHA_1`, `CKM_SHA_1_HMAC`, `CKM_ECDSA_SHA1`, `CKM_SHA1_RSA_PKCS(_PSS)` | SHA-1 deprecated; NIST retirement by 2030; no new use permitted |
| `CKM_MD5`, `CKM_MD5_HMAC`, `CKM_MD5_RSA_PKCS` | Never FIPS-approved |
| `CKM_RIPEMD160`, `CKM_RIPEMD160_HMAC`, `CKM_KECCAK_256` | Not FIPS-approved |
| `CKM_RSA_X_509` (raw RSA) | Unpadded — not approved |
| `CKM_RSA_PKCS` **as Cipher** (v1.5 encryption/key transport) | Not approved by SP 800-56B r2; kept **only** as a signature mechanism (§4.2) |
| `CKM_CHACHA20`, `CKM_CHACHA20_POLY1305`, `CKM_CHACHA20_KEY_GEN` | Not FIPS-approved |
| `CKM_AES_ECB` (+ `_ENCRYPT_DATA` derive variants) | ECB excluded as a confidentiality mode from this provider's surface |
| `CKM_X25519`, `CKM_X448`, `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` | Montgomery key agreement outside the current SP 800-56A approved set — see the JEP 527 hybrid-group caveat in §7 |
| `CKM_BIP32_MASTER_DERIVE`, `CKM_BIP32_CHILD_DERIVE` | Application-specific (wallet), out of scope |
| `CKM_CONCATENATE_*`, `CKM_SHAKE_256_KEY_DERIVATION` | Internal building blocks; not exposed as standalone JCA services (used inside KDF/hybrid flows only) |
| `CKM_HSS`, `CKM_XMSS`, `CKM_XMSSMT` (+ keygen) | SP 800-208-approved but **deferred by scope decision** — see §10 (stateful signatures need a state-management design; a naive JCA mapping risks state reuse, which is catastrophic for LMS/XMSS) |

---

## 6. FIPS 140-3 Level 3 operational posture

softhsmv3 is software, so a literal L3 *certification* (physical
tamper evidence etc.) is not claimable — the plan targets the **L3
operational profile** so the provider behaves correctly in front of a
certified L3 device later (same PKCS#11 contract):

1. **Identity-based authentication mapping.** Provider config requires an
   explicit role: `user` (crypto operations) or `so` (admin). PIN is
   sourced from provider configuration (`KeyStore.load(null, pin)` /
   `AuthProvider.login`) — never hardcoded, never logged. `AuthProvider`
   subclass so JAAS-style `login()/logout()` works.
2. **No plaintext key export.** Generation templates always set
   `CKA_SENSITIVE=TRUE`, `CKA_EXTRACTABLE=FALSE`, `CKA_TOKEN=TRUE` for
   private/secret keys. `Key.getEncoded()` returns `null`; wrap-out is
   only via `Cipher.wrap()` → `CKM_AES_KEY_WRAP(_PAD)` (SP 800-38F), i.e.
   keys leave the boundary encrypted or not at all.
3. **Power-on self-tests.** Provider construction runs a KAT battery
   before any service is issued: one sign/verify KAT per signature family
   (ML-DSA-65, SLH-DSA-SHA2-128S, ECDSA-P256, Ed25519, RSA-PSS), one
   encap/decap KAT (ML-KEM-768), one AES-GCM and one HMAC-SHA-256 KAT,
   DRBG health check. Any failure → provider enters an error state and
   every `getService()` throws (fail-closed, mirroring the CACP
   fail-open remediation lesson).
4. **Approved-only enforcement.** §5 exclusions are enforced in the
   policy layer, not just unregistered.
5. **Zeroization.** Confined `Arena`s per operation; buffers that carried
   secret material are explicitly zeroed before `Arena.close()`;
   `C_CloseSession`/`C_Logout` on pool shutdown and JVM shutdown hook;
   `destroy()` implemented on opaque key objects (`Destroyable`).
6. **Error discipline.** Every `CKR_*` maps to a specific JCA exception
   with the CKR name preserved in the message; no return-code is ever
   ignored (the audit standard the sandbox samples were just held to).
7. **KEM shared-secret handling.** Decision (see W0 open question): the
   `KEM` API must hand JSSE a usable secret for HKDF, so decapsulated
   secrets surface as session-only `SecretKey`s marked
   `CKA_TOKEN=FALSE, CKA_SENSITIVE=TRUE`, extracted once for the TLS key
   schedule, zeroed after. The stricter alternative — keeping the secret
   in-token and running the whole HKDF chain via `CKM_HKDF_DERIVE` — is
   specified as a follow-up hardening item since JSSE's key schedule does
   not currently delegate HKDF to the KEM provider.

---

## 7. TLS phase caveat — hybrid groups vs FIPS

JEP 527 ships three groups. Their FIPS standing differs:

| Group | FIPS standing |
|---|---|
| `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | Hybrid of two approved primitives (P-curves per SP 800-56A + ML-KEM per FIPS 203) — the FIPS-friendly choices; our `pqc-rest`/`pqc-grpc` quantum-safe profile already offers both |
| `X25519MLKEM768` | X25519 half is outside the current approved set (§5) — supported by the JDK and our servers, but **excluded from the provider's approved surface**; the TLS phase pins `jdk.tls.namedGroups` to the SecP* hybrids for FIPS runs |

---

## 8. Workstreams

Ordering rule: each workstream ends with **live verification inside the
dev-sandbox container** (the standard used all week — no claim without a
run), and nothing is pushed without the local gate (`scripts/local-gate.sh`).

### W0 — Verification spikes (before any provider code)
1. **JSSE delegation validation (JDK 27 RC) — DONE 2026-08-24, PASSED,
   with one load-bearing correction.** Built a probe `Provider`
   (`KeyPairGenerator."ML-KEM-768"/"ML-KEM-1024"`, `KeyFactory` same,
   `KEM."ML-KEM"` family name), installed at `Security.insertProviderAt(p, 1)`
   (top priority, ahead of SunJCE), ran a real `SSLSocket` handshake from
   inside the dev-sandbox container (JDK 27 RC 27+35-2325) against the
   live `pqc-rest` quantum-safe endpoint, requesting
   `SecP256r1MLKEM768` first (the FIPS-friendly, **not
   default-enabled** group — deliberately chosen over the default
   `X25519MLKEM768` to prove the non-default path also delegates).
   **Result: HANDSHAKE SUCCEEDED (TLS 1.3, TLS_AES_256_GCM_SHA384),
   `-Djavax.net.debug=ssl:handshake` confirms the wire-negotiated group
   was `SecP256r1MLKEM768`, and the probe's `KeyPairGenerator`,
   `initialize()`, `generateKeyPair()`, and `KEM` decapsulator were all
   invoked by JSSE** — genuine provider-search delegation, confirmed on
   the actual RC binary, not just from source reading.
   - **Correction to the plan surfaced by this spike:** a first probe
     pass that implemented only the no-arg-friendly `generateKeyPair()`
     (no `initialize(AlgorithmParameterSpec, SecureRandom)` override)
     was silently skipped for key generation — JSSE fell back to
     `SunJCE` for that step alone while still using the probe for
     decapsulation, with **no exception surfaced, no error logged** (a
     genuine footgun: a provider missing this override degrades to
     silent partial-bypass, not a hard failure). Root-caused by adding
     constructor-level logging and testing the override explicitly.
     **New W2 requirement:** `KeyPairGeneratorSpi` implementations in
     this provider MUST override
     `initialize(AlgorithmParameterSpec, SecureRandom)` — JSSE calls
     this exact overload (passing a `NamedParameterSpec`, e.g.
     `"ML-KEM-768"`) before `generateKeyPair()`; relying only on the
     legacy `initialize(int, SecureRandom)` is not sufficient and fails
     open (silently defers to a lower-priority provider) rather than
     failing closed. W5's POST/policy-enforcement design (§6.3/§6.4)
     must include an explicit self-test that every registered
     KeyPairGenerator's `AlgorithmParameterSpec` path actually reaches
     our native layer — a unit test alone would not have caught this;
     it takes an end-to-end JSSE-driven check.
2. **Mechanism-info sweep — DONE 2026-08-24, PASSED.** Built
   `libsofthsmv3.dylib` fresh (clean build, only pre-existing
   unused-parameter warnings), dumped `C_GetMechanismList`/
   `C_GetMechanismInfo` live (127 mechanisms), resolved every code
   against `pkcs11t.h` including `CKM_VENDOR_DEFINED`-namespaced ones
   (`CKM_KMAC_128/256`, `CKM_EDDSA_PH`, `CKM_X25519`/`X448`,
   `CKM_BIP32_*`) — 127/127 resolved, none unaccounted for. Confirms
   §4/§5 tables against ground truth:
   - `CKM_ML_KEM` flags `0x30000000` = `CKF_ENCAPSULATE|CKF_DECAPSULATE`
     exactly (not encrypt/decrypt) — key range 800–1568 bytes matches
     ML-KEM-512↔1024 public-key sizes (FIPS 203) exactly.
   - `CKM_ML_DSA` key range 1312–2592 bytes matches ML-DSA-44↔87
     public-key sizes (FIPS 204) exactly.
   - `CKM_SLH_DSA` key range 32–64 bytes matches the 128-bit↔256-bit
     SLH-DSA public-key sizes (FIPS 205), covering all 12 parameter sets.
   - Every §5-excluded mechanism (MD5, SHA-1 family, RIPEMD-160, raw
     RSA, ChaCha20, X25519/X448, BIP32) **is** advertised by the engine
     (this build has `WITH_FIPS`/`WITH_RIPEMD160` off) — confirms the
     provider's approved-only policy layer is load-bearing: the engine
     is permissive, the FIPS narrowing is the provider's job, not the
     engine's.
   - `CKM_EC_KEY_PAIR_GEN`/`CKM_ECDSA_KEY_PAIR_GEN` share one value
     (`0x1040`); the header marks the latter `/* Deprecated */` —
     confirms §4.2's use of the non-deprecated name is correct.
3. **SLH-DSA + KMAC sanity — DONE 2026-08-24, PASSED.** SP 800-108
   deferred (below). Ran live inside the dev-sandbox container (JDK 24,
   `libsofthsmv3.so`) by reusing `P11Ffm.java` directly (its existing
   `generateKeyPair`/`sign`/`verify` needed zero new bindings for
   SLH-DSA; KMAC needed one small `C_GenerateKey` — single-key, not
   keypair — binding added in the spike script, not in `P11Ffm.java`
   itself, to keep the spike disposable):
   - **SLH-DSA-SHA2-128S**: keygen → sign → verify(correct)=true →
     verify(tampered)=correctly rejected. Signature was **7856 bytes** —
     matches the FIPS 205 SLH-DSA-SHA2-128s signature size exactly.
   - **KMAC-256**: generated a 32-byte generic-secret key, MAC → 64-byte
     output, verify(correct)=true, verify(tampered)=correctly rejected,
     two MACs of the same input were byte-identical (deterministic, as
     KMAC should be with no customization string). **Self-correction
     during this spike:** my first assertion guessed the output would be
     32 bytes (misreading `SoftHSM_sign.cpp`'s mac table `{ CKM_KMAC_256,
     ..., 32, ... }` as an output-length field); the engine returned 64
     bytes and the guess was simply wrong — that `32` is the minimum
     *key* size, not output length. Fixed the test's assumption, not the
     engine, and reran to a clean pass. Recorded here as a reminder that
     the real provider's KMAC output-length handling (W4) must read the
     actual `CK_MECHANISM_INFO`/engine behavior, never assume a size.
   - **SP 800-108 (`CKM_SP800_108_COUNTER_KDF`/`_FEEDBACK_KDF`) —
     deferred, not skipped.** `CK_SP800_108_KDF_PARAMS` has a
     variable-length PRF-data-array parameter structure; marshaling it
     correctly is real native-layer work that belongs in W1's struct
     builder, not a disposable spike. No claim is made about it working
     until W1/W4 build and test it properly.
4. **JavaJCE teardown — DONE 2026-08-24.** `git rm -r JavaJCE` (removed
   `JavaJCESofthsmv3.md` and all 4 source files); honest CHANGELOG entry
   added under a new `### Removed` section documenting exactly what was
   fabricated (hardcoded fake signature/secret bytes, missing
   implementing classes, nonexistent patched-JVM/`Dockerfile.physics`
   claims, wrong `CKM_ML_KEM` constant) so the history stays truthful
   rather than silently overwritten.

**W0 status: all 4 items done.** Branch `feat/jdk27-jca-provider` created
off `main` (`94a5797`). `libsofthsmv3.dylib` built clean locally
(pre-existing unused-parameter warnings only). Nothing pushed.

### W1 — Module skeleton + native layer — DONE 2026-08-24, PASSED

Built and live-verified. Real deviations from the original plan text below
(struct-walk decision, function resolution scope) and one real
architectural bug class found and fixed via `mvn test`, documented in
full since both are load-bearing for W2+.

- Maven module in `JavaJCE/` (contents replaced): `pom.xml` (release 24;
  JUnit 5 added — the plan's original "shade not needed" call stands,
  this is a library jar). Package **`com.pqctoday.hsm.jce`** (chosen to
  match the sandbox's existing `com.pqctoday.pkcs11` convention; no
  longer "TBD" — this is the real package now in the repo).
- `P11Library` (FFM), **one deliberate deviation from the original plan
  text**: functions are resolved by symbol name (`dlsym`/`SymbolLookup.find`)
  uniformly, not via a `C_GetInterface` → `CK_FUNCTION_LIST_3_2` struct
  walk. Reasoning recorded in the class's own javadoc: `P11Ffm`'s header
  comment already establishes that the v3.2 KEM entry points
  (`C_EncapsulateKey`/`C_DecapsulateKey`) **must** be resolved by name
  because `C_GetFunctionList` returns a v2-sized struct without those
  slots — so by-name resolution is required for at least those functions
  regardless of what's chosen for the rest, and maintaining two different
  binding mechanisms for functions that are otherwise identical work has
  no benefit. `C_GetInterface` is still probed once at construction
  (verification only — confirms v3.2 negotiation) exactly as `P11Ffm`
  does. This W1 slice bound 11 functions this way, all verified correct
  by live execution: `C_Initialize`, `C_GetSlotList`, `C_OpenSession`,
  `C_Login`, `C_Logout`, `C_CloseSession`, `C_DigestInit/Update/Final`,
  `C_GenerateRandom`, `C_SeedRandom`.
- `P11Error`: CKR_RV → JCA exception mapping, 105 codes generated
  directly from `pkcs11t.h` (same technique as W0.2's mechanism sweep —
  parsed the header, not hand-typed).
- `SoftHSMv3Provider` registering `SecureRandom` ("SoftHSMv3-DRBG") +
  8 approved `MessageDigest` algorithms (SHA-224/256/384/512,
  SHA3-224/256/384/512) — SHA-1/MD5/RIPEMD-160 deliberately **not**
  registered, live-confirmed via `NoSuchAlgorithmException` even though
  the engine advertises and dispatches all three (§0.2's finding: the
  engine is permissive, this provider's policy layer is what enforces
  FIPS 140-3 L3, and this is the first place that enforcement became
  real code, not just a plan table). POST harness (§6.3): one SHA-256("abc")
  FIPS 180-4 KAT run through the real native path before any service is
  registered; construction throws `ProviderException` and registers
  nothing on failure — confirmed on a **sabotaged throwaway copy** (never
  the real file — per this repo's sabotage-testing convention) with a
  corrupted expected value, which threw exactly as designed with zero
  services exposed. `P11SessionPool` and opaque key classes are genuinely
  deferred to W2 (nothing in W1's slice needed them) — not built here, as
  planned.
- **Real bug found and fixed via `mvn test` (not caught by raw `javac`/
  manual smoke test — needed 2+ Provider instances in one JVM to surface,
  which is exactly what a real JUnit suite does and a single-shot smoke
  script doesn't):** `C_Initialize` and `C_Login` are PKCS#11-spec
  **process-/token-global** state, not per-caller (confirmed by reading
  the engine's own `C_Initialize` — `src/lib/SoftHSM_slots.cpp:84-101`,
  which tracks one `isInitialised` flag and even registers its own
  `atexit` handler, signaling process-exit teardown is the intended
  design). The first version of `P11Library` called
  `C_Initialize`/`C_Login`/`C_Logout`/`C_Finalize` per-instance
  (matching `P11Ffm`'s single-session sample pattern, which never needed
  to construct two instances in one process). The second test's
  `SoftHSMv3Provider` construction failed with
  `CKR_CRYPTOKI_ALREADY_INITIALIZED`, then after that fix,
  `CKR_USER_ALREADY_LOGGED_IN` — both genuine engine responses confirming
  correct spec behavior, not engine bugs. **Fixed**: `C_Initialize` is
  now called at most once per JVM process (`synchronized` idempotent
  guard); `C_Login`'s `CKR_USER_ALREADY_LOGGED_IN` is tolerated as
  benign (a prior instance already authenticated the whole token — every
  other `CK_RV` still fails hard); `C_Logout`/`C_Finalize` are **never**
  called from an individual instance's `close()` (both are token-/
  process-wide — one instance closing must not log out or tear down
  state other live instances still depend on). Real per-token
  reference-counted logout is left to W2's `P11SessionPool`, which is
  the class actually positioned to know when the LAST session on a token
  closes — noted at the `cLogout` field with a forward reference so this
  isn't silently forgotten.
- **Verify — all live, via the real `mvn test`/`mvn package` (not just
  raw `javac`+`java`):** all 4 JUnit tests pass against the live engine
  inside the dev-sandbox container (SHA-256("abc") matches the FIPS
  180-4 KAT exactly; all 8 approved digests produce correct output
  lengths; SHA-1/MD5 confirmed unavailable; `SecureRandom` produces
  distinct draws, supports `generateSeed`/`setSeed` through
  `C_GenerateRandom`/`C_SeedRandom`). `mvn package` produces a real
  17.5KB jar. POST fail-closed path verified via sabotaged copy (above).

### W2 — Signatures + key generation

**ML-DSA: DONE. SLH-DSA (all 12 parameter sets): DONE. EdDSA
(Ed25519/Ed448): DONE. EC/ECDSA (P-256/384/521): DONE. RSA
(2048/3072/4096, PKCS#1 v1.5 + PSS): DONE. `KeyFactorySpi` (public-key
import, all 5 families): DONE. `KeyStoreSpi` read path: DONE.** All
2026-08-24, all PASSED. **W2 is complete.**

**KeyStore read path — user decision: `CKA_LABEL` alias with a
synthesized fallback, closes the classic SunPKCS11 "0 keys" gap for this
engine (noted against this exact token in the sandbox's own
OpenSession.java/ListKeys.java samples earlier this session).**
- New `C_FindObjects{Init,Final}` bindings + `P11Library.findObjects(Attr[])`.
  `P11KeyStoreSpi` enumerates via `CKA_CLASS ∈ {CKO_PUBLIC_KEY,
  CKO_PRIVATE_KEY}`, resolving each discovered object's own JCA algorithm
  name from its own attributes (`CKA_KEY_TYPE` → `CKA_PARAMETER_SET` for
  ML-DSA/SLH-DSA, → `CKA_EC_PARAMS` for EdDSA specifically) — this works
  for objects this *session* didn't itself just generate, not only
  freshly-created ones.
- **Two real bugs found and fixed via the full `mvn test` suite — neither
  reproduced in isolation, both are genuine correctness gaps regardless:**
  1. `findObjects` originally called `C_FindObjects` exactly **once**
     with a fixed 256-object cap and returned whatever came back — not
     spec-compliant (PKCS#11 §5.6 requires repeated calls until a call
     returns fewer than requested). Fixed to loop properly. Kept even
     though it turned out not to be the actual cause of the test failure
     below — it's a real gap on its own, any token with >256 matching
     objects would have silently truncated.
  2. **The actual cause**: the alias-fallback logic used `CKA_ID` when
     "present" (non-null) — but generating a key without an explicit
     `CKA_ID` returns a **present, zero-length** byte array, not `null`
     (confirmed live: two distinct freshly-generated ML-DSA-65 keys both
     read back `CKA_ID=""`, `len=0`). Both collapsed to the identical
     synthesized alias `"ML-DSA-65-"`, so `engineGetKey`'s
     first-match lookup silently returned the *first* such key for every
     later request, permanently shadowing every other key of the same
     algorithm with an unset `CKA_ID`. Root-caused with a dedicated
     probe (not guessed) reading both keys' real `CKA_LABEL`/`CKA_ID`
     bytes back from the live token. Fixed by always folding the
     object's own PKCS#11 handle (guaranteed unique within a session)
     into the synthesized alias, using `CKA_ID`'s content only when it's
     actually non-empty.
  3. Passed in isolation both times (`mvn test -Dtest=KeyStoreTest`) but
     failed within the full 81-test suite — the accumulated session
     objects from ~80 other key-generating tests were exactly what
     surfaced both bugs; an isolated single-key test would never have
     caught either. Worth remembering for W3+: this module's own test
     suite is now large enough to be a meaningful adversarial-scale
     input on its own.
- Write path (`engineSetKeyEntry`/`engineDeleteEntry`/certificate
  entries) explicitly throws `UnsupportedOperationException` rather than
  silently no-op-ing — matches the plan's original W2 scope (read path
  only) and is confirmed by a dedicated test that the write path fails
  loudly, not quietly.
- **Verify — all live:** `mvn test`, 81/81 total (2 new KeyStore tests +
  79 existing). A key generated via this provider is discoverable by
  alias, `KeyStore.getKey()` returns a correctly-typed, correctly-handled
  `P11Key.Pub`, `containsAlias`/`isKeyEntry`/`size()` all behave
  correctly, and every write-path method throws rather than silently
  accepting.

**KeyFactory import — user decision: all 5 families at once, closes the
reverse-cross-check gap flagged since the ML-DSA commit (a
foreign-provider key could not be verified by our provider; only the
reverse direction worked).**
- New native binding, `C_CreateObject`, plus `P11Library.createObject(Attr[])`
  — the same struct-building path `generateKeyPair` already uses, no new
  struct shape needed.
- **Every per-algorithm wire-format decision was confirmed empirically
  against the live engine before being hardcoded, not derived from the
  spec alone** — this surfaced one genuine asymmetry that would have
  silently broken import if assumed: **EdDSA's `CKA_EC_POINT` is RAW**
  (32 bytes for Ed25519, unwrapped), while **ordinary EC's `CKA_EC_POINT`
  is a DER `OCTET STRING` wrapping the same kind of raw point bytes** (67
  bytes for secp256r1 — tag `04`, length `41`, then the 65-byte
  uncompressed point) — despite both using the identical attribute
  number. Found by generating one real key per algorithm through this
  provider and reading the attribute straight back via
  `C_GetAttributeValue`, not by reading engine source alone (the source
  reads `pub->getQ()`/`pub->getA()` from two different internal accessors
  with no obvious tell from the C++ alone that their wire format
  differs). The same live-probe method also independently reconfirmed
  the secp384r1 OID derived during the EC/ECDSA work (`params=1.3.132.0.34`,
  matching exactly) and produced the **complete real OID table** for
  every registered algorithm/parameter set (all read from our own
  generated SPKIs via Bouncy Castle, not guessed): ML-DSA-44/65/87 =
  `2.16.840.1.101.3.4.3.{17,18,19}`; the 12 SLH-DSA parameter sets =
  `2.16.840.1.101.3.4.3.{20-31}` (NIST CSOR arc, SHA2 variants first then
  SHAKE); Ed25519/Ed448 = `1.3.101.{112,113}`; EC = `1.2.840.10045.2.1`
  with the curve OID as `AlgorithmIdentifier` parameters; RSA =
  `1.2.840.113549.1.1.1`.
- ASN.1 parsing (`SubjectPublicKeyInfo`/`AlgorithmIdentifier`/
  `RSAPublicKey`/`DEROctetString`) uses Bouncy Castle — same dependency,
  same "pure syntax, not crypto" boundary as the ECDSA codec, every
  class/method confirmed via `javap` against the real jar before use
  (same discipline as the SLH-DSA cross-verify work).
- **Private key import refused unconditionally** — not a new decision,
  the original plan text already called this (§4, §6.2): an imported
  private key's material would have already crossed through JVM memory
  to reach this provider, exactly what the opaque-key/L3 design exists
  to prevent. `engineGeneratePrivate` always throws
  `InvalidKeySpecException`; confirmed by a dedicated test.
- One generic `P11PublicKeyFactorySpi`, registered under all 19
  algorithm names (matching the `P11PureSigSignatureSpi` precedent) —
  import dispatches on the imported SPKI's own embedded OID, which is
  self-describing, not on which registered name was used to look the
  factory up.
- **Verify — all live, first attempt (no debugging cycle needed —
  the empirical pre-verification of every wire format paid off):**
  `mvn test`, 79/79 total (9 new + 70 existing). For each of ML-DSA×3,
  Ed25519, EC×3 curves, RSA: generate a keypair with **JDK's own software
  implementation** (zero involvement of our provider), sign with it,
  import the public key into our provider via `KeyFactory`, verify the
  JDK-produced signature with **our** token — the exact reverse direction
  that did not work before this workstream. All pass.

**RSA — user clarifications locked in before starting: 2048/3072/4096
with exponent 65537 (2048 stays FIPS-approved through 2030, rejected
outright below that rather than silently allowed):**
- `P11RSAKeyPairGeneratorSpi`: same single-service,
  `initialize()`-configured shape as `P11ECKeyPairGeneratorSpi`.
  `CKA_MODULUS_BITS`/`CKA_PUBLIC_EXPONENT` requirements confirmed
  directly from `SoftHSM_keygen.cpp`'s `generateRSA` (required/defaulted
  respectively) before building the template.
- PKCS#1 v1.5 (`SHA256/384/512withRSA`) needed **no new Signature
  class** — reused `P11PureSigSignatureSpi` unchanged. Unlike ECDSA,
  RSA's PKCS#1 v1.5 signature format is already a raw modulus-size
  big-endian block in both PKCS#11 and JCA (no ASN.1 wrapping) —
  confirmed live via cross-verification against JDK's `SunRsaSign`
  before trusting the general "RSA doesn't need this" convention as fact.
- RSASSA-PSS needed a new class, `P11RSAPSSSignatureSpi`, for a
  different reason than ECDSA's: PSS's mechanism and mechanism
  parameters (`CK_RSA_PKCS_PSS_PARAMS { hashAlg; mgf; sLen; }`) are
  chosen by the *caller* via `engineSetParameter(PSSParameterSpec)`
  after construction, not fixed at Service registration time like every
  algorithm above — matches how `SunRsaSign` itself registers
  `"RSASSA-PSS"` as one configurable service. Required a new
  `P11Library.mechWithParams(type, long...)` helper (a `CK_MECHANISM`
  with an all-`CK_ULONG` parameter block) — generalized narrowly for
  this shape only; `CK_SP800_108_KDF_PARAMS`'s variable-length PRF-data
  array needs a different builder, deliberately not attempted here.
  SHA-1 PSS is explicitly rejected (same FIPS 140-3 L3 policy as every
  digest registration); SHA-3 PSS variants are a real, scoped-out gap
  (SHA-2 only for now), noted rather than silently incomplete.
- **Verify — all live:** `mvn test`, 70/70 total (9 new RSA + 61
  existing). Keygen + PKCS#1 v1.5 sign/verify/tamper-rejection across
  all 3 modulus sizes, signature length exactly one modulus-size block.
  **Cross-verified against JDK's `SunRsaSign`** for both PKCS#1 v1.5 and
  PSS. SHA-1 PSS request correctly throws
  `InvalidAlgorithmParameterException`; sub-2048 modulus request
  correctly throws `InvalidParameterException`.

**EC/ECDSA — the workstream that changed the project's dependency
posture:**
- `P11ECKeyPairGeneratorSpi`: standard JCA "EC" registration shape
  (**one** service, curve chosen at `initialize(ECGenParameterSpec)`
  time — matching `SunEC`), genuinely different from every algorithm
  above (one-service-per-parameter-set). `secp256r1`'s `CKA_EC_PARAMS`
  OID bytes reused from the sandbox's proven C samples; `secp521r1`'s
  from this repo's own `p11_v32_compliance_test.cpp` (already
  live-verified 779/0 this session); **`secp384r1`'s were not found
  reused anywhere in this repo** — derived by direct DER-structure
  analogy to the proven `secp521r1` encoding (same SECG OID arc, only
  the final arc byte differs) and **not trusted on the derivation
  alone**: empirically confirmed live by generating a real key and
  decoding it through JDK's own EC `KeyFactory`, checking the resulting
  field size is genuinely 48 bytes (P-384's real coordinate size), not
  just that key generation didn't error.
- **Real bug found via cross-verification, not assumed away:** a first
  pass reusing `P11PureSigSignatureSpi` unchanged for ECDSA passed our
  own sign→verify round-trip (self-consistent, since both sides used the
  same raw format) but **failed** cross-verification against JDK's own
  `SunEC` with a genuine `SignatureException` ("Invalid encoding for
  signature" / "Not the correct tag"). Root cause: PKCS#11's
  `C_Sign`/`C_Verify` for ECDSA use raw `r‖s` bytes (§2.3.1), but JCA's
  `SHA256withECDSA` convention is ASN.1 DER `SEQUENCE{INTEGER r,
  INTEGER s}` (RFC 3279 §2.2.3) — a well-known PKCS#11-to-JCA bridging
  gotcha. This is exactly the class of defect the plan's
  cross-verification testing convention exists to catch; a
  self-consistency-only test suite would have shipped it silently.
- **Dependency decision, made explicitly with the user rather than
  unilaterally:** fixing this needs an ASN.1 DER codec. A first pass
  hand-rolled a minimal ~80-line codec (exactly the 2-INTEGER SEQUENCE
  shape, nothing more). Before committing to it, checked this repo's own
  precedent for wire-format codecs (`@peculiar/asn1-schema`/`@peculiar/x509`
  in `pqctoday-hub`'s `package.json`, `nlohmann::json` in the sandbox's
  C++ REST sample, `org.json` in its Java sample) — all "pull in a
  small, established library," never hand-roll. Confirmed via exhaustive
  search that no Java ASN.1 library (Bouncy Castle or otherwise) was
  already a dependency anywhere in this monorepo (`JavaJCE/pom.xml` is
  the only Java `pom.xml` that exists). Presented the real tradeoff to
  the user (new supply-chain dependency vs. custom crypto-adjacent
  parsing code) rather than deciding unilaterally; **user chose Bouncy
  Castle**. `bcprov-jdk18on` **1.85.2** (confirmed current release via
  Maven Central metadata, not guessed) added as a dependency, used
  **only** for its `org.bouncycastle.asn1` package (`ASN1Integer`/
  `DERSequence`/`ASN1Sequence` — pure DER syntax). No BC `Provider` is
  ever registered and no BC crypto class is ever used — same boundary as
  `nlohmann::json`/`org.json` elsewhere in this project. `P11ECDSASignatureSpi`
  rewritten on top of it, hand-rolled codec deleted.
- **Verify — all live:** `mvn test`, 49/49 total (9 new ECDSA + 40
  existing). Curve-identity check (including the empirically-derived
  P-384 OID) passes for all 3 curves. Sign/verify round-trip + tamper
  rejection across `SHA256/384/512withECDSA` on multiple curve/hash
  combinations. **Cross-verified against JDK's own `SunEC`** for every
  combination — the exact check that caught the DER-format bug in the
  first place, now passing.

**EdDSA:**
- New `P11EdDSAKeyPairGeneratorSpi` — **not** built on the generic
  `P11PureSig*` base: traced `SoftHSM_keygen.cpp`'s `generateED` and
  found EdDSA keygen identifies its curve via `CKA_EC_PARAMS` (a
  DER-encoded curve OID), not `CKA_PARAMETER_SET` — a genuinely
  different shape, confirmed before assuming the ML-DSA/SLH-DSA pattern
  would transfer a third time. The curve OID byte arrays
  (`{0x06,0x03,0x2B,0x65,0x70}` for Ed25519, `...0x71` for Ed448) are
  the exact values already proven live in the sandbox's
  `samples/c/12_ed25519.c` / `samples/rust/src/12_ed25519.rs` — reused,
  not re-derived.
- The **Signature** side, by contrast, needed no new class at all:
  `CKM_EDDSA` is curve-agnostic (the curve lives on the key) — the exact
  same shape `P11PureSigSignatureSpi` already handles for ML-DSA/SLH-DSA,
  so EdDSA registration just parametrizes the existing class.
- **Verify — all live:** `mvn test`, 40/40 total (2 new EdDSA + 38
  existing). SPKI/signature sizes match spec exactly: Ed25519 44-byte
  SPKI / 64-byte signature (RFC 8032), Ed448 69-byte SPKI / 114-byte
  signature. **Cross-verified against JDK's own native `SunEC`
  Ed25519/Ed448** (JEP 339, JDK 15+) — our SPKI export imports cleanly
  into `KeyFactory.getInstance("Ed25519")` (no provider arg = JDK's own
  impl) and verifies our token-produced signature, for both curves.

**SLH-DSA, added on top of the ML-DSA slice:**
- Refactored `P11MLDSAKeyPairGeneratorSpi`/`P11MLDSASignatureSpi` into
  generic `P11PureSigKeyPairGeneratorSpi`/`P11PureSigSignatureSpi` (both
  algorithms are the exact same shape: single-mechanism pure keygen +
  parameter-set-agnostic pure sign/verify — confirmed for SLH-DSA the
  same way as ML-DSA, by reading `SoftHSM_keygen.cpp`'s dispatch and
  `generateSLHDSA`'s `CKA_PUBLIC_KEY_INFO` write before assuming the
  pattern transferred). Regression-tested the ML-DSA suite (still 14/14)
  immediately after the refactor, before adding SLH-DSA on top — the
  refactor itself never went unverified.
- All 12 parameter sets registered (`SLH-DSA-{SHA2,SHAKE}-{128,192,256}{S,F}`),
  `CKA_PARAMETER_SET` values taken from `pkcs11t.h`
  (`CKP_SLH_DSA_SHA2_128S`..`CKP_SLH_DSA_SHAKE_256F`, 0x1–0xc).
- **Verify — all live, all 12 parameter sets:** sign/verify round-trip,
  tampered-message rejection, `mvn test` 24/24 new tests pass (38/38
  total with W1+ML-DSA). **Every observed signature size matches the
  published FIPS 205 table exactly** (128S/128F = 7856/17088 bytes,
  192S/192F = 16224/35664, 256S/256F = 29792/49856 — SHA2 and SHAKE
  variants of the same size class are equal-length, as expected), and
  the SPKI-wrapped public key sizes (50/66/82 bytes) exactly match the
  raw 32/48/64-byte FIPS 205 public keys plus the ASN.1 DER overhead
  measured for ML-DSA's SPKI wrapping — cross-checked arithmetic, not
  asserted from memory. No JDK software SLH-DSA exists to cross-verify
  against (confirmed absent from the JDK 27 EA standard names doc during
  W0).
  **Gap closed 2026-08-24** (user's own suggestion, prompted by the
  Bouncy Castle dependency discussion during the EC/ECDSA work): added
  `SLHDSACrossVerifyTest`, an independent cross-check of every one of
  the 12 token-produced SLH-DSA signatures against **Bouncy Castle's own
  SLH-DSA implementation** (`bcprov-jdk18on` 1.85.2, already a dependency
  for the ECDSA DER codec — confirmed real PQC support via BC's own
  release notes, 1.79+). Used BC's low-level `org.bouncycastle.crypto`
  API (`SLHDSASigner`/`SLHDSAPublicKeyParameters`/`SLHDSAParameters`),
  not its JCA `Signature.getInstance(String)` wrapper — BC's own issue
  tracker (`bcgit/bc-java#1841`) documents real, unresolved
  algorithm-name inconsistency for SLH-DSA in that layer, so the
  string-free typed API sidesteps it entirely. Every class/field name
  used was confirmed via `javap` against the real installed jar before
  writing any code, not guessed from documentation (BC's own docs didn't
  have a usable code sample either). Fed with our RAW public key bytes
  (`CKA_VALUE` — confirmed to hold "raw pub key bytes" for SLH-DSA in
  `SoftHSM_keygen.cpp`, same as ML-DSA), not our own SPKI export, so this
  check has zero dependency on our own `KeyFactory`/`P11Key` code being
  correct — a genuinely independent verification path. **All 12
  parameter sets pass** (`mvn test`, 61/61 total). This is explicitly
  test-only: the provider itself never touches BC's PQC classes, only
  its ASN.1 syntax classes for the unrelated ECDSA codec (see the pom.xml
  dependency comment for that exact boundary).

- `P11Constants`: shared CK_* constants class (values from `pkcs11t.h`,
  same source-of-truth discipline as everywhere else in this repo) — the
  home for every algorithm's constants going forward, so W2's remaining
  algorithms don't scatter magic numbers per-file the way W1's digest
  mechanisms did (a known, accepted minor inconsistency from W1, not
  worth churning working code to fix retroactively).
- `P11Key.Pub`/`P11Key.Priv`: opaque handle-backed key objects (plan
  §6.2). Private keys: `getFormat()`/`getEncoded()` both `null` —
  confirmed live via a dedicated test (`privateKeyNeverExportsMaterial`).
  Public keys export their **real** X.509 SubjectPublicKeyInfo DER — and
  critically, this class does **not** hand-assemble that ASN.1 itself.
  Traced the engine's own `generateMLDSA` (`SoftHSM_keygen.cpp:5201+`)
  and found it already computes a correct SPKI via `spkiFromPkey()` and
  stores it under `CKA_PUBLIC_KEY_INFO` (PKCS#11 v3.2 §4.14) — so
  `P11Key.Pub` just reads that attribute via `C_GetAttributeValue`
  rather than reinventing ASN.1 encoding (same "don't reinvent
  codecs" principle the sandbox samples were held to all session).
- `P11MLDSAKeyPairGeneratorSpi`, one instance per registered parameter
  set (ML-DSA-44/65/87 are separate JCA service names). Overrides
  `initialize(AlgorithmParameterSpec, SecureRandom)` — a direct,
  concrete application of the W0.1 finding: a caller may call this
  overload redundantly even when the algorithm identity is already fixed
  by the service name, the JDK's default implementation throws if not
  overridden, and W0.1 showed that failure mode can be silently absorbed
  by a caller (JSSE fell back to a different provider with no visible
  error) rather than surfaced — so leaving it unoverridden here would
  reproduce the exact footgun already found once this session.
- `P11MLDSASignatureSpi`: **one class serves all three parameter sets**
  — `CKM_ML_DSA` is parameter-set-agnostic; the parameter set lives on
  the KEY (`CKA_PARAMETER_SET`), not the mechanism, confirmed via the
  engine's own dispatch code before assuming it.
- Native layer additions to `P11Library`: `C_GenerateKeyPair`,
  `C_SignInit`/`C_Sign`, `C_VerifyInit`/`C_Verify`,
  `C_GetAttributeValue`, and the `CK_ATTRIBUTE` struct builder —
  **cross-checked against `P11Ffm`'s own already-live-verified bindings**
  rather than re-derived from the spec by hand, specifically to avoid
  repeating the `C_Login` parameter-count transcription slip caught
  during W1 (documented there; same discipline applied proactively here).
- **Verify — all live:** `mvn test`, 10 new ML-DSA tests (parameterized
  across all 3 parameter sets) + the 4 existing W1 tests, 14/14 pass.
  Confirmed: sign/verify round-trips; tampered-message verify correctly
  returns `false` (not an exception); signature sizes match FIPS 204
  exactly (2420 / 3309 / 4627 bytes for 44/65/87); private key material
  never exports (`null`/`null`); and — the strongest check —
  **our-generated public key (real SPKI DER) imported into JDK 24's own
  software ML-DSA `KeyFactory`, verifying our token-produced signature,
  succeeds** — proving the SPKI export is standards-correct, not merely
  self-consistent with our own `KeyFactory`.
- **Known gap, not silently skipped:** the reverse cross-check (a
  JDK-software-generated keypair, signed by JDK, verified by *our*
  provider) does not work yet — `P11MLDSASignatureSpi.engineInitVerify`
  only accepts `P11Key.Pub` instances; there is no import path for a
  foreign-provider `PublicKey`. `KeyFactorySpi`'s import side (still
  unbuilt, listed above) is exactly what closes this gap — recorded here
  so it isn't forgotten between now and then.
- Original plan text below retained for the remaining W2 scope
  (SLH-DSA/EC/RSA/EdDSA, KeyFactory import, KeyStore read path):

### W3 — KEM + key agreement + OAEP

**ML-KEM (512/768/1024): DONE 2026-08-24, PASSED — the headline feature
this whole plan exists for.** User clarifications locked in before
starting: session-only `SecretKey` for the shared secret (§6.7's open
question, now resolved — see below), sequencing all three W3 sub-parts
in one pass. ECDH and OAEP: not yet built.

**Shared-secret handling (§6.7) — resolved with a precise architectural
answer, not just a policy pick:** the user asked directly whether the
KEM secret could be kept entirely out of JVM memory, mirroring the
private-key opaque design. The honest answer, given before writing any
code: no — unlike the private key (which no caller ever legitimately
needs raw), the KEM secret's entire purpose is to be consumed by JSSE's
own HKDF key schedule and AES-GCM record cipher, both of which run in
the JVM. The "in-token HKDF chain" alternative only moves the boundary
one derivation step further (raw secret stays in-token, but the
*derived* traffic keys still have to reach JSSE's cipher code somehow);
it doesn't eliminate JVM exposure. The only architecture that would is
replacing JSSE's entire record-layer cipher engine with a token-backed
one — a real, much larger undertaking (effectively a TLS-offload
appliance), flagged as a genuinely open question for W6 rather than
solved here. `P11MLKEMSpi` therefore extracts the decapsulated secret as
a plain `SecretKeySpec` — the one deliberate, singular exception in this
module to the "never `CKA_EXTRACTABLE=true`" pattern every other secret
follows, and documented as such directly in the class.
- `P11MLKEMKeyPairGeneratorSpi`: same single-mechanism,
  parameter-set-on-the-key shape as ML-DSA/SLH-DSA, but **not** built on
  `P11PureSigKeyPairGeneratorSpi` — ML-KEM keys carry
  `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` (confirmed against `pkcs11t.h`:
  `0x633`/`0x634`), not `CKA_SIGN`/`CKA_VERIFY`.
- `P11MLKEMSpi implements KEMSpi` — registered under the **bare family
  name `"ML-KEM"`** (no parameter-set suffix) *and* the three
  parameter-set names. The bare-name registration is not a guess:
  W0.1's live JSSE probe (this exact provider, a real TLS handshake
  against `pqc-rest`, back in W0) already proved JDK 27's
  `Hybrid.getKEM()` requests exactly `KEM.getInstance("ML-KEM")`,
  verbatim, regardless of which parameter set the hybrid group needs.
  Interface shape (`KEMSpi`/`EncapsulatorSpi`/`DecapsulatorSpi`/
  `KEM.Encapsulated`) confirmed via `javap` against the real JDK 24
  classes before implementing, not assumed from the W0.1 probe's memory
  alone.
- Ciphertext ("encapsulation") sizes per parameter set and the 32-byte
  secret size (FIPS 203 invariant, all parameter sets) were **verified
  live** against the real engine before being hardcoded into
  `engineEncapsulationSize()`/`engineSecretSize()` — confirmed exact:
  512/768/1024 → 768/1088/1568 bytes.
- `KeyFactory` extended to ML-KEM (3 more registered names), reusing the
  same generic `P11PublicKeyFactorySpi` — `CKA_ENCAPSULATE` instead of
  `CKA_VERIFY` on import, same pattern as generation. OIDs (NIST CSOR
  arc `2.16.840.1.101.3.4.4.{1,2,3}` — a different sub-arc from
  ML-DSA's `.3.x`, as expected) read from our own generated SPKIs via
  Bouncy Castle, same discipline as every other algorithm's OID table.
- **Verify — all live, first attempt (no debugging cycle):** `mvn test`,
  90/90 total (9 new + 81 existing).
  - Self round-trip via the standard `javax.crypto.KEM` API (the exact
    API JSSE uses) for all 3 parameter sets: `encapsulationSize()`/
    `secretSize()` match the FIPS 203 values exactly, encapsulate→
    decapsulate produces identical secrets.
  - **Both genuinely achievable cross-verification directions against
    JDK 24's own software ML-KEM** (the third direction — JDK
    decapsulating with *our* private key — is not achievable at all,
    since decapsulation needs the private key and ours never leaves the
    token; noted directly in the test rather than attempted):
    JDK generates+encapsulates, we decapsulate (secrets match, no import
    needed); JDK generates, we import via `KeyFactory`+encapsulate, JDK
    decapsulates (secrets match — this direction specifically exercises
    the KeyFactory import path added this workstream, not just the one
    proven for Signature in W2).

**ECDH: DONE 2026-08-24, PASSED.**
- `P11ECDHKeyAgreementSpi implements KeyAgreementSpi`, registered as
  `"ECDH"`, works across all three curves already proven for ECDSA
  (P-256/P-384/P-521). `engineDoPhase` extracts the peer's point from
  `CKA_EC_POINT` and, because that attribute is DER `OCTET STRING`-wrapped
  for ordinary EC keys (unlike EdDSA's raw encoding — see W2), unwraps it
  via `ASN1OctetString.getInstance(...).getOctets()` before building the
  `CK_ECDH1_DERIVE_PARAMS`. A foreign (non-token) peer public key is
  imported on-the-fly through the same `P11PublicKeyFactorySpi` path
  proven in W2/ML-KEM, not a separate code path.
- **Real bug found and fixed at the root:** `C_DeriveKey` failed with
  `CKR_KEY_FUNCTION_NOT_PERMITTED (0x68)` on the first live attempt.
  Root cause: `P11ECKeyPairGeneratorSpi`'s private-key template only
  granted `CKA_SIGN` (built for ECDSA in W2), never `CKA_DERIVE`. Fixed
  by adding `CKA_DERIVE, true` to the private-key template. Re-ran the
  full suite immediately after — 99/99, no ECDSA regression. The same
  class of gap was then checked *proactively* on the RSA template (see
  OAEP below) before it could bite the same way twice.
- Shared secret extracted as a plain raw-byte `SecretKeySpec` — the same
  deliberate, documented `CKA_EXTRACTABLE=true` exception as ML-KEM's
  secret, for the identical reason (JSSE's own key schedule needs it in
  JVM memory; see the ML-KEM section above).
- **Verify:** two-of-our-own-keys agree; cross-verified against `SunEC`
  (JDK's own ECDH) with a foreign-peer-key-accepted-directly test
  exercising the on-the-fly import path.

**RSA-OAEP: DONE 2026-08-24, PASSED — including a genuine C++ engine
compliance-gap fix, not just Java-side work.**
- `P11RSAOAEPCipherSpi implements CipherSpi`, one instance per
  (digest, MGF) pair, registered as
  `"RSA/ECB/OAEPWith" + digest + "AndMGF1Padding"` for the fuller
  SHA-2 + SHA-3 matrix the user chose during W3 clarification
  (SHA-256/384/512 and SHA3-256/384/512 — SHA-1 stays excluded per this
  provider's FIPS 140-3 L3 policy, unchanged from W2).
- **Real bug #1 (proactive fix):** applying the lesson just learned from
  ECDH's `CKA_DERIVE` gap, the RSA key templates were checked before
  first run and found to have the identical class of gap —
  `P11RSAKeyPairGeneratorSpi` only granted `CKA_SIGN`/`CKA_VERIFY`, never
  `CKA_ENCRYPT`/`CKA_DECRYPT`. Fixed before running rather than after a
  failure.
- **Real bug #2:** `initKey()` only recognized `Cipher.ENCRYPT_MODE`/
  `DECRYPT_MODE` (opmodes 1/2), so `Cipher.WRAP_MODE`/`UNWRAP_MODE`
  (opmodes 3/4) threw `InvalidKeyException`. Fixed by normalizing
  wrap→encrypt-direction and unwrap→decrypt-direction before the
  existing direction check; `engineWrap`/`engineUnwrap` implemented via
  `engineDoFinal`. Verified via `wrapUnwrapRoundTripsAnAesKey`.
- **Real bug #3 (a genuine C++ engine compliance gap, not a Java-side
  issue) — found, spec-verified, and fixed at the root per explicit user
  instruction ("ok then fix the gap"):** `C_EncryptInit` rejected every
  SHA3-* OAEP combination with `CKR_ARGUMENTS_BAD`. Root cause, found by
  reading source directly: `SoftHSM_keygen.cpp`'s
  `MechParamCheckRSAPKCSOAEP` hardcoded a `validCombo` allow-list
  covering only `{SHA-1, SHA224, SHA256, SHA384, SHA512}`. Verified
  against the actual OASIS PKCS#11 v3.2 Standard PDF (`docs/refs/`,
  §6.1.8, page 198, extracted via `pdftotext -layout`) — not the header
  file, not memory — that `CK_RSA_PKCS_OAEP_PARAMS.hashAlg` is spec-defined
  generically with no hash-family restriction, and that
  `CKG_MGF1_SHA3_224/256/384/512` are defined in the same normative MGF
  table as the SHA-2 variants. This confirmed the gap as a genuine engine
  completeness bug, not a spec-mandated restriction. Fixed across four
  sites in three files, all reusing the exact `EVP_sha3_*()` pattern
  already proven working elsewhere in this codebase (ECDSA, HMAC):
  - `AsymmetricAlgorithm.h`: added `RSA_PKCS_OAEP_SHA3_{224,256,384,512}`
    to the `AsymMech::Type` enum.
  - `OSSLRSA.cpp`: extended both the encrypt and decrypt padding-check
    and MD-selection logic (4 sites) to accept and dispatch the new
    enum values via `EVP_sha3_*()`.
  - `SoftHSM_cipher.cpp`: extended the `CKM_SHA3_*` → `AsymMech`
    mapping switch at both encrypt-init and decrypt-init sites.
  - `SoftHSM_keygen.cpp`: extended `MechParamCheckRSAPKCSOAEP`'s
    `validCombo` check with the four SHA3 hashAlg/MGF1 combinations,
    with a comment citing the spec verification.
  - Rebuilt for both macOS (sanity) and Linux (the real target, via a
    standalone `docker build --target hsm-builder`), hot-swapped the
    fresh `.so` into the running sandbox container, and ran the full
    regression suite before touching any Java code: 106/107 passed, the
    one failure being the not-yet-resynced WRAP_MODE Java fix above, not
    a new regression.
- **JDK/SunJCE quirk found and correctly attributed, not worked around in
  the provider:** decrypting JDK-encrypted SHA-384/512 OAEP ciphertext
  initially failed with `CKR_ENCRYPTED_DATA_INVALID`, SHA-256 did not.
  Isolated via three standalone probes (self-round-trip in isolation →
  fine; JDK-encrypts/we-decrypt in isolation → fails; forcing an explicit
  `OAEPParameterSpec` with a matching `MGF1ParameterSpec` on the JDK side
  → fixed). Conclusion: our provider is spec-correct (MGF1 digest always
  matches the main hash); the plain transformation string alone doesn't
  reliably make SunJCE default its MGF digest to match for SHA-384/512.
  Fixed the **test**, not the provider, to pass an explicit
  `OAEPParameterSpec` when cross-verifying against JDK.
- **A second, harder JDK limitation found during cross-verify test
  design:** SHA-3 OAEP cannot be cross-verified against the JDK at all,
  for a different and more fundamental reason than the quirk above —
  confirmed live that `Cipher.getInstance("RSA/ECB/OAEPWithSHA3-256AndMGF1Padding", "SunJCE")`
  throws `NoSuchPaddingException` unconditionally, regardless of
  provider or params: SunJCE's OAEP transformation-string parser simply
  doesn't recognize a `SHA3-*` digest name inside
  `"OAEPWith...AndMGF1Padding"`. This is why SHA-3 OAEP has its own
  self-round-trip test (`sha3OaepSelfRoundTrips`) separate from the
  SHA-2 JDK-cross-verify test, and why the user's Bouncy Castle
  cross-check request (next) was the *only* way to get third-party
  verification for SHA-3 at all — the JDK cannot serve as the oracle
  here even in principle.
- **Cross-checked against Bouncy Castle per explicit user request ("can
  you cross check the fix with bouncy castle ?")**, using the same
  `bcprov-jdk18on:1.85.2` dependency already present for ASN.1 codec work
  and the W2 SLH-DSA cross-verify. `sha3OaepInteropsWithBouncyCastle`
  proves both directions for all three SHA-3 digests: BC encrypts
  against our exported public key, we decrypt (proves our engine fix
  against BC's independent RSA-OAEP implementation); we encrypt against
  a BC-generated public key (imported via `KeyFactory`), BC decrypts
  (the reverse direction). The reverse direction surfaced one more real
  bug: `P11PublicKeyFactorySpi.importRSA` only granted `CKA_VERIFY` on a
  foreign-imported RSA public key, never `CKA_ENCRYPT` — the same class
  of template-completeness gap as the ECDH/RSA-generation bugs above,
  caught here because the test actually exercised encryption against an
  imported key rather than only a generated one. Fixed by adding
  `CKA_ENCRYPT, true` to `importRSA`'s template.
- **Verify — full suite, all green:** `mvn test`, 110/110 (9 SHA-2
  round-trip+JDK-cross-verify, 1 wrap/unwrap, 3 SHA-3 self-round-trip,
  3 SHA-3×BC bidirectional cross-verify, 1 SHA-1-excluded negative test,
  plus all prior W0–W2 tests unchanged).

### W4 — Symmetric, MAC, KDF, KeyStore write path
- `CipherSpi` (AES GCM/CBC/CTR + AESWrap), `MacSpi` (HMAC/CMAC/KMAC),
  `KeyGeneratorSpi` (AES, generic-secret), `SecretKeyFactorySpi`
  (HKDF/PBKDF2/SP 800-108), KeyStore `setEntry`/`deleteEntry`.
- GCM in-token IV policy (§4.3 note).
- **Verify:** NIST CAVP/ACVP vectors for AES-GCM/CMAC/HKDF; interop with
  SunJCE for CBC/CTR; GCM IV-uniqueness test across sessions.

### W5 — FIPS posture completion + docs
- Full POST battery, policy-layer refusal tests for every §5 row,
  zeroization audit (heap-dump assertion that key bytes never appear),
  `AuthProvider` login/logout, provider configuration file format.
- Deliverables: `JavaJCE/README.md` (honest capability table — replaces
  the fabricated doc), a security-posture doc mapping each §6 item to
  its FIPS 140-3 section.

### W6 — TLS (JDK 27 / JEP 527)
- Install the provider at higher priority than SunJCE and pin
  `jdk.tls.namedGroups=SecP256r1MLKEM768,SecP384r1MLKEM1024` (FIPS run
  profile, §7 — note these two are **not** enabled by default per the
  JEP, so setting the property is mandatory, not optional hardening).
- Path is provider-delegated KEM (confirmed, §2.3a), validated by W0.1;
  no `SSLContext` surgery expected.
- **Verify:** live handshake against `pqc-rest`'s quantum-safe endpoint
  (which refuses classical groups — a handshake success *is* the proof),
  confirm via provider-side logging that encap/decap ran in the token;
  compare handshake latency HSM-backed vs JDK-software ML-KEM (reuse the
  transport-arms benchmark methodology).
- GA follow-up task: swap RC 27+35 → JDK 27 GA when it lands
  (2026-09-15 target), re-verify, update the migrate-catalog row again
  (RC→GA status change).

### W7 — Phase 2: Rust engine via gRPC transport
- `GrpcTransport` implementing the same transport interface: reuse
  `remoting/proto/proto/pkcs11_remote.proto` verbatim (grpc-java +
  protobuf codegen — the same stub-generation approach just added for
  Python in the sandbox image), mTLS from `/admin-certs`, kebab-case
  algorithm ids.
- Scope note: the remoting verb layer exposes a subset (health/session/
  keygen/sign/verify/encap/decap) — so Phase 2 initially covers the PQC
  services only, with the classical/symmetric surface staying on the
  in-process C++ transport. Extending `remoting/core` verbs to close
  that gap is listed as an explicit follow-on with its own gate run.
- **Verify:** same W2/W3 cross-provider suites re-run against the Rust
  engine through gRPC; three-way parity check (C++ in-process vs Rust
  gRPC vs JDK software) mirroring `three_way_parity.rs`.

### W8 — Integration + release
- dev-sandbox: replace `P11Ffm`-based *provider-shaped* usage where it
  makes teaching sense (P11Ffm itself stays — it teaches the raw FFM
  layer), add a `24-jca-provider` Java sample consuming the jar, wire the
  jar build into `Dockerfile.dev-sandbox`.
- hsm: add provider build+tests to `scripts/local-gate.sh` (local gate,
  **not** GitHub CI — repo directive), CHANGELOG entry, README link.
- Migrate-catalog follow-up: once real, the catalog can reference an
  actual PKCS#11 JCA provider with PQC — a genuinely rare product claim.

---

## 9. Risks & open questions

| # | Risk / question | Handling |
|---|---|---|
| 1 | ~~JSSE may not delegate ML-KEM to third-party providers~~ **Resolved 2026-08-24**: delegation confirmed in JDK master source and explicitly intended for 3rd-party providers (§2.3a) | Residual risk: RC binary could differ from master — W0.1 validates on the exact RC build |
| 2 | JDK 27 is RC until ~2026-09-15 | Core provider targets JDK 24+ (nothing in W1–W5 needs 27); only W6 rides the RC; GA swap task listed |
| 3 | FFM call overhead vs JNI for high-rate symmetric ops | Benchmark in W4 (reuse transport-arms harness); acceptable for an HSM bridge — ops are token-bound anyway |
| 4 | SLH-DSA JCA naming may collide with a future JDK standard API | Names follow NIST parameter-set spelling; alias table isolates renames |
| 5 | GCM in-token IV policy may break callers expecting to supply IVs | Documented behavior + explicit non-FIPS config flag (ships off) |
| 6 | Stateful sigs (HSS/XMSS) tempting to "just add" | Deliberately fenced to §10 — state-reuse risk requires its own design |
| 7 | `JavaJCE/` history contains fabricated claims | W0.4 removes it with an honest CHANGELOG note rather than silently overwriting |
| 8 | Rust remoting verb subset < full JCA surface | Phase 2 scoped to PQC services first; verb-layer extension is its own follow-on (own gate) |

## 10. Deferred (explicitly out of scope for this plan)

- **Stateful hash-based signatures** (HSS/LMS, XMSS/XMSS-MT — SP 800-208):
  engine support exists; a JCA mapping needs a state-management design
  (state persistence, exhaustion accounting, no-clone guarantees) before
  any code. Separate plan when prioritized.
- Composite signature profiles (§10.4 work) via JCA — after the base
  provider lands.
- In-token TLS key schedule (full `CKM_HKDF_DERIVE` chain, §6.7 hardening).
- Rust engine in-process FFM transport (memory-only token makes it a
  weak KeyStore fit; superseded by the gRPC path).
- CMVP validation itself — this plan delivers the L3 *operational
  posture*, not a certification effort.

---

## 11. References (anchoring sources, checked 2026-08-24)

- JEP 527 — Post-Quantum Hybrid Key Exchange for TLS 1.3 (full text
  fetched): https://openjdk.org/jeps/527 — status Closed/Delivered,
  Release 27; default-enabled group set; `jdk.tls.namedGroups` /
  `SSLParameters::setNamedGroups`; pure ML-KEM groups a non-goal.
- JDK master source (openjdk/jdk, read 2026-08-24):
  `src/java.base/share/classes/sun/security/ssl/HybridProvider.java`
  (internal, not installed in the searched provider list) and
  `sun/security/ssl/Hybrid.java` (`getKEM()` → `KEM.getInstance("ML-KEM")`
  with the comment *"This is done to work with 3rd-party providers"*;
  `KeyPairGenerator/KeyFactory.getInstance(name)` system search;
  X25519MLKEM768 share order reversed per RFC 10024).
- Java Security Standard Algorithm Names, JDK 27 EA docs
  (download.java.net/java/early_access/jdk27/docs/specs/security/standard-names.html):
  ML-DSA/ML-KEM names present; KDF names `HKDF-SHA256/384/512`;
  SLH-DSA / HashML-DSA / KMAC absent.
- JDK 26 PKCS#11 Reference Guide
  (docs.oracle.com/en/java/javase/26/security/pkcs11-reference-guide1.html):
  SunPKCS11 targets PKCS#11 **v2.20+**, no ML-* mechanisms, no
  `C_GetInterface` — corroborates the empirical JDK 27 RC test.
- Upstream tracker: JDK-8349163 (latest ML-KEM/ML-DSA private-key
  encodings) — W2 KeyFactory design input.
- JEP 452 (KEM API, JDK 21), JEP 454 (FFM, JDK 22), JEP 496/497
  (ML-KEM/ML-DSA, JDK 24) — established earlier this session.
- Engine ground truth: mechanism inventory grepped from
  `src/lib/SoftHSM*.cpp` (2026-08-24); PKCS#11 v3.2 constants from
  `src/lib/pkcs11/pkcs11t.h`; v3.2 compliance evidence
  `p11_v32_compliance_test.cpp` (779 PASS / 0 FAIL, live 2026-08-24);
  remoting contract `remoting/proto/proto/pkcs11_remote.proto` +
  `docs/PKCS11_REMOTING.md`.
