# OpenSSL provider coverage audit — vendored pkcs11-provider vs OpenSSL 3.6.3 (2026-08-25)

Scope agreed with the user (2026-08-25): all three gap dimensions
(provider operations vs OpenSSL 3.6.3; backend algorithms not exposed;
new 3.6 features unused), both engine backends (C++ `libsofthsmv3` and
Rust `softhsmrustv3`), test harness delivered as a new opt-in
`local-gate.sh` step, remediation as a **plan only** (no fixes executed
under this audit).

Method: every claim below is grounded in one of (a) the real OpenSSL
3.6 documentation (docs.openssl.org/3.6 man7 pages, release notes,
CHANGES for 3.6.0–3.6.3), (b) the live `/usr/local/ssl` OpenSSL 3.6.3
build inside the `pqc-rust` container, (c) source reads of
`src/vendor/pkcs11-provider/` with file:line anchors, or (d) live probes
run 2026-08-25 loading the actual built `pkcs11-provider.so` into the
real 3.6.3 `openssl` against the real C++ engine. Nothing below is
inferred from upstream latchset docs alone — this fork has diverged
substantially (composites, CMS-KEM wiring, PQC scaffolding).

---

## 1. The OpenSSL 3.6.3 surface (what "full coverage" would mean)

**Provider operation types** (provider(7), 3.6): `OSSL_OP_DIGEST`,
`CIPHER`, `MAC`, `KDF`, `RAND`, `KEYMGMT`, `KEYEXCH`, `SIGNATURE`,
`ASYM_CIPHER`, `KEM`, `ENCODER`, `DECODER`, `STORE`, `SKEYMGMT` — plus
two provider **capabilities** (provider-base(7)): `TLS-GROUP` and
`TLS-SIGALG`.

**Native algorithms in the staged 3.6.3 build** (confirmed live via
`openssl list`): ML-DSA-44/65/87, ML-KEM-512/768/1024, all 12 SLH-DSA
parameter sets, Ed25519/Ed448 (+ph/ctx), the four TLS hybrid KEM
implementations (X25519MLKEM768, X448MLKEM1024/`X448+ML-KEM-1024`,
SecP256r1MLKEM768, SecP384r1MLKEM1024) and TLS groups
`MLKEM512/768/1024` + `X25519MLKEM768` + `SecP256r1MLKEM768` +
`SecP384r1MLKEM1024`. **LMS is NOT present in the staged build** — LMS
verification (new in 3.6, SP 800-208, verify-only by design) is
compile-gated behind `enable-lms` and this build was configured without
it (ENV-1 below).

**New in 3.6.0 relevant here** (release notes + CHANGES, confirmed):
CMS **KEMRecipientInfo (RFC 9629) + ML-KEM in CMS**; LMS signature
*verification*; `EVP_SKEY` opaque symmetric keys extended into KDF/
key-exchange provider methods (`EVP_KDF_derive_SKEY()`,
`EVP_PKEY_derive_SKEY()`); NIST security categories for PKEY objects;
default TLS group list now leads with hybrid PQC
(`?*X25519MLKEM768 / …`); FIPS 186-5 deterministic ECDSA (FIPS
provider). ML-DSA signature params (EVP_SIGNATURE-ML-DSA(7)):
`context-string`, `message-encoding`, `deterministic`, `mu`,
`test-entropy`; **OpenSSL explicitly does not implement pre-hash
HashML-DSA**.

---

## 2. What the vendored provider actually implements

Full inventory with file:line anchors from the source sweep (registration
is **dynamic**: mechanism-gated via the token's `C_GetMechanismList`
against a `checklist[]` at `src/vendor/pkcs11-provider/src/provider.c:896-915`,
plus a static set at `provider.c:1379`):

| OSSL op | Registered | Notes |
|---|---|---|
| SIGNATURE | RSA (PKCS#1 + SHA1/SHA2-224..512/SHA3-224..512 combos), ECDSA (+ SHA1/SHA2/SHA3 combos), ED25519/ED448 (+ ph/ctx), ML-DSA-44/65/87, 3 composite profiles | `provider.c:980-1242` |
| KEM | ML-KEM-512/768/1024 (per-variant; umbrella name deliberately unregistered — namemap conflict, `provider.c:1253-1260`) | dispatch lacks `SET_CTX_PARAMS` (`kem/mlkem.c:259-289`) |
| KEYEXCH | ECDH, HKDF; X25519/X448 entries exist but are **unreachable** (CKM_X25519/X448 not in `checklist[]`) | `provider.c:1148-1163` |
| KDF | HKDF, TLS13-KDF only | `provider.c:1161-1162` |
| DIGEST | SHA-1, SHA-2 family (incl. 512/224, 512/256), SHA-3 family | `provider.c:1166-1209` |
| ASYM_CIPHER | RSA only | `provider.c:1356` |
| CIPHER | AES-{128,192,256}-{ECB,CBC,OFB,CFB,CFB1,CFB8,CTR,CBC-CTS,GCM,CCM} (gated on `SKEY_SUPPORT`) | `provider.c:1277-1335` |
| RAND | PKCS11-RAND | `provider.c:1372` |
| KEYMGMT | RSA, RSA-PSS, EC, HKDF, ED25519/448, ML-DSA×3, ML-KEM×3, composites×3 (static) | `provider.c:1534-1552` |
| SKEYMGMT | AES, GENERIC-SECRET | `provider.c:1557-1558` |
| ENCODER | RSA/RSA-PSS/EC: text+PKCS#1+SPKI; ED25519/448: text; ML-DSA: text+SPKI; composites: SPKI der/pem; URI-PEM PrivateKeyInfo for RSA/RSA-PSS/EC/Ed/ML-DSA **iff** `encode_pkey_as_pk11_uri` | **no ML-KEM encoders** (latchset sibling has them) |
| DECODER | `DER<-pem`; RSA/RSA-PSS/EC/ED25519/ED448/ML-DSA×3/ML-KEM×3/SLH-DSA×12 from DER (R2, 2026-08-25) | composite decoders remain defined but unregistered — recursion issue, `provider.c:1512-1525` (unchanged) |
| STORE | `pkcs11:` URI scheme | works, proven live |
| MAC | **absent entirely** | `OSSL_OP_MAC` appears only in the block-list name table |
| TLS-GROUP | 13 classical entries (P-224/256/384/521, ffdhe2048..8192) — **zero PQC/hybrid** | `tls.c:89-174` |
| TLS-SIGALG | mldsa44/65/87 (0x0904-0x0906) + 3 composite sigalgs on private-use 0xFEB0-2 | `tls.c:288-299` |

**Live-proven working today (C++ engine arm, 2026-08-25):** provider
loads (version 1.1) alongside default; `pkcs11:` store enumeration; ML-DSA-65
keygen ON TOKEN via `genpkey -propquery "?provider=pkcs11"`; sign via
`pkcs11:` URI producing a correct 3309-byte FIPS 204 signature that
**OpenSSL's own software implementation cross-verifies**; SPKI public
export. This is the first time the native (non-WASM) provider path has
been proven at all — the repo's only prior harness
(`test_openssl_integration.sh`) soft-fails every step (`|| echo`) and is
wired into nothing (ENV-3).

---

## 3. Engine surfaces (what the provider COULD expose)

C++ engine: **127 mechanisms** (`src/lib/SoftHSM_slots.cpp:419-660`).
Rust engine: **116 mechanisms** (`rust/src/constants.rs:717-864`), 98
common, differences adjudicated in
`tests/differential/exceptions.json` (`LEGAL-MECHANISM-SET` et al.).
Both engines advertise, beyond what the provider registers: SLH-DSA (13
mechs, all 12 parameter sets), XMSS/XMSS-MT (sign+verify), HSS/LMS
(sign+verify), X25519/X448 derive, ECDH-as-KEM
(`CKM_ECDH1_DERIVE` carries ENCAPSULATE|DECAPSULATE), ChaCha20 /
ChaCha20-Poly1305, HMAC families, KMAC-128/256 (+ CMAC, C++ only),
PBKDF2, SP800-108 counter/feedback KDFs, SHAKE-256 derive (C++),
AES message-based GCM, and the Rust-only vendor KEMs
(FrodoKEM, Classic McEliece). Composite signatures are **not** engine
mechanisms anywhere — they are assembled above PKCS#11 (KMIP crate:
all 8 §10.4 profiles; provider `composite.c`: 3 profiles) from
`CKM_ML_DSA`(+context) plus one classical mechanism.

---

## 4. Gap matrix

### A. Provider operations vs OpenSSL 3.6.3

| ID | Gap | Evidence | Severity |
|---|---|---|---|
| OP-1 | `OSSL_OP_MAC` not implemented at all — token HMAC/CMAC/KMAC unreachable from `EVP_MAC`; every MAC falls back to software | source sweep; block-list table `provider.c:1570` | Medium |
| OP-2 | **RESOLVED (R2, 2026-08-25)** — was: no DECODERs for ML-DSA/ML-KEM/SLH-DSA (composites remain intentionally unregistered — §2's table, recursion issue) → URI-PEM round-trip broken; loading a written PEM back failed. Now: 18 decoder registrations (3 ML-DSA + 3 ML-KEM + 12 SLH-DSA) in `decoder.c`/`provider.c`, using the same generic PEM→DER→store-fetch chain already proven live by T10 (the EC control). Each per-type decoder's FORMAT_NAME had to be the exact single-name string `store.c` emits as `DATA_TYPE` (e.g. `MLDSA_44` = `"ML-DSA-44"`), not the colon-separated registration list. Live-verified for all three families: ML-DSA loads back and signs; SLH-DSA loads back and signs (7856-byte signature, correct size); ML-KEM loads back and **decapsulates** correctly (matched a reference secret from a direct-URI encapsulation). **A genuinely separate gap surfaced during ML-KEM's proof**: a URI-PEM-loaded ML-KEM object identifies as `type=private`, and neither `pkey -pubout` nor `pkeyutl -encap` work against it — confirmed live (`attribute does not exist: 0x633`/CKA_ENCAPSULATE) — because the keymgmt EXPORT function requires a public-class object and does not walk private→associated-public the way ML-DSA's does. This is not a decoder bug (decapsulate, which only needs the loaded private key's own attributes, works perfectly) — it is the same prerequisite already tracked for remediation R5 (TLS groups), now confirmed by a second, independent code path. | `decoder.c`, `provider.c`; live (T11, T11slh, T11kem) | ~~**High**~~ — |
| OP-3 | **Core RESOLVED (R3, 2026-08-25)** — was: ML-KEM had zero encoders registered, so `genpkey -algorithm ML-KEM-768 -out k.pem` generated and persisted a real key on-token (R3b) but the `-out` write step failed, `Error writing key(s)`/exit 1. **Correction to this row's own earlier wording** (found live during R3, not assumed): public-key output was never actually broken — `storeutl -text`/`pkey -pubout` already worked with zero encoders, because ML-KEM's keymgmt EXPORT function bridges the public bytes into OpenSSL's default provider, which encodes them. The real, sole functional gap was the **private**-key URI-PEM PrivateKeyInfo encoder — the one path that can't use that bridge (private material never crosses into another provider). Fixed: `p11prov_mlkem_encoder_priv_key_info_pem_encode` (`encoder.c`), registered for all 3 variants inside the `encode_pkey_as_pk11_uri` block (`provider.c`). Like every other PrivateKeyInfo encoder in this fork, it never touches raw key bytes — `p11prov_encoder_private_key_to_asn1` calls `p11prov_obj_get_public_uri(key)` and PEM-wraps that `pkcs11:` URI string; live-verified the written file decodes to a `type=private` URI, and a negative harness assertion checks no `PRIVATE KEY` label ever appears. **Remaining, deliberately separate parity tier**: SPKI/text encoders for public keys (would let public output work even in `DISALLOW_EXPORT_PUBLIC` configs, and match every other PQC family in this fork) — not functionally required, scoped as follow-up. | `encoder.c`; live (T4x_encode, T10 as network-effect control) | ~~Medium~~ — |
| OP-4 | KEM dispatch lacks `SET_CTX_PARAMS`/`SETTABLE` | `kem/mlkem.c:259-289` | Low |
| OP-6 | **RESOLVED (R3b, 2026-08-25)** — was: ML-KEM keys could not be GENERATED on token through the provider (ML-KEM keymgmt had no `OSSL_FUNC_KEYMGMT_GEN*` entries; ML-DSA keygen worked, so this was an asymmetry, not a design rule). Now: real `GEN_INIT`/`GEN`/`GEN_CLEANUP`/`GEN_SET_PARAMS`/`GEN_SETTABLE_PARAMS` wired into all 3 per-variant ML-KEM keymgmt tables (`kem/mlkem.c`), implemented in `keymgmt.c` (mirroring the ML-DSA block) and exported non-static since `kem/mlkem.c` is a separate translation unit. `CKA_PARAMETER_SET` is mandatory on the public-key template per the C++ engine's own `extractParameterSet` call (no silent default, matching ML-DSA's pattern); `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` requested explicitly on pub/priv templates to match what a spec-correct caller sends (both engines enforce these server-side regardless of template content). Live-verified: key generates, persists on-token, and is independently confirmed via `storeutl -text` showing `ML-KEM-768 Public-Key`. Landing this surfaced OP-3 (above) as a distinct, still-open gap — genpkey's own `-out` write needs an encoder this fix does not provide. | both engines, live probe + source | ~~**High**~~ — |
| OP-5 | KDF surface is HKDF+TLS13-KDF only; engines also offer PBKDF2 and SP800-108 counter/feedback KDFs that OpenSSL has standard fetch names for | `provider.c:1161` vs engine KDF mechs | Low–Medium |
| WART-1 | Every provider token scan spams the C++ engine log: `ObjectFile.cpp(181): The attribute is not a byte string: 0x0/0x1/0x2/0x86/0x100/0x170-0x172/0x601` — provider queries CKA_CLASS/CKA_TOKEN/CKA_PRIVATE/CKA_TRUSTED/CKA_KEY_TYPE/CKA_MODIFIABLE/CKA_COPYABLE/CKA_DESTROYABLE/etc. with byte-string templates | observed on every live probe | Low (noise; masks real errors) |
| WART-3 | Build hygiene: the gitignored WASM-generated `src/config.h` leaks into the **native** CMake build — compile warnings `"PACKAGE_MAJOR redefined"` and the live provider reports version **1.1** (config.h) while CMake defines **0.4.0** | observed in gate build log + live `list -providers` | Low |
| WART-4 | **RESOLVED (R0.4, 2026-08-25 later same day)** — was: mechanism-gated operation tables are invisible to fresh-process fetches: `openssl list` shows nothing `@ pkcs11` for signature/KEM, AND a strict property-targeted fetch (`dgst -sha256 -propquery provider=pkcs11`) **functionally fails** in a fresh process (`inner_evp_generic_fetch:unsupported`) — operations only resolve once a token object forces module init in-process. Fix: the provider already ships `pkcs11-module-load-behavior = early` for exactly this case (forces the same lazy-init call from inside `OSSL_provider_init()` instead of leaving it to a key-object path); wired into the harness's T9 arena. See `docs/openssl-provider-remediation-plan-2026-08-25.md` R0.4 for the full story, including a real `mk_arena()` ordering bug it exposed and fixed along the way. | live probes (T9) | ~~Medium~~ |
| WART-5 | The C++ engine rejects OpenSSL's SHA-1 OAEP defaults (`Invalid hashAlg/mgf combination for RSA-OAEP`, `SoftHSM_keygen.cpp:8056`) — plain `-pkeyopt rsa_padding_mode:oaep` against a token key fails until the caller pins `rsa_oaep_md`/`rsa_mgf1_md` (sha256 verified working). Likely deliberate FIPS posture; needs documenting, not fixing | live (T5's first run) | Low (interop caveat) |

### B. Backend algorithms not exposed

| ID | Gap | Engine support | Provider state | Severity |
|---|---|---|---|---|
| ALG-1 | **RESOLVED (R1, 2026-08-25 later same day)** — was: SLH-DSA (all 12 sets), `sig/slhdsa.c` a `{0,NULL}` stub, registration branch unreachable. Now: real keymgmt+signature+encoders for all 12 parameter sets; keygen/store/text-and-SPKI-encode/**sign** all live-verified working, cryptographically correct (exact FIPS 205 sizes, independent software cross-verify, tamper rejection). The sign gap took two passes: registration alone worked immediately, but signing failed at OpenSSL's own fetch layer until a follow-up pass (prompted by checking the OpenSSL 3.6 documentation directly rather than continuing to guess) found the dispatch tables violated provider-signature(7)'s documented consistency contract — `GETTABLE_CTX_PARAMS` registered without its mandatory `GET_CTX_PARAMS` pair, so OpenSSL rejected the whole method at fetch time, before any provider code ran. See `docs/openssl-provider-remediation-plan-2026-08-25.md` R1 for the full trail. Two other, unrelated real bugs found and fixed along the way: `objects.c`'s and `store.c`'s key-type dispatch switches both lacked a `CKK_SLH_DSA` case. | both engines, 13 mechs each | ~~`sig/slhdsa.c` is a `{0,NULL}` stub AND the registration branch is unreachable (`CKM_SLH_DSA` absent from `checklist[]`/`PQC_MECHS`, `provider.c:859`); OpenSSL 3.6 has native names/OIDs to mirror~~ | ~~**High**~~ — |
| ALG-2 | XMSS/XMSS-MT | both engines (sign+verify, stateful) | `sig/xmss.c` stub, unreachable; no native OpenSSL names exist (custom names required; no CMS/TLS story) | Medium |
| ALG-3 | HSS/LMS | both engines **sign+verify** | nothing in provider; OpenSSL 3.6 native LMS is *verify-only* → token-sign/OpenSSL-verify is a uniquely coherent split, but blocked by ENV-1 (no `enable-lms` in staged build) | Medium |
| ALG-4 | Composite profiles 4–8 | KMIP layer has all 8 §10.4 profiles | provider `composite.c` registry has 3; missing 5 include **all four §10.4-recommended** (MLDSA44-Ed25519-SHA512, MLDSA44-ECDSA-P256-SHA256, MLDSA65-RSA3072-PSS-SHA512, MLDSA65-Ed25519-SHA512) + MLDSA65-ECDSA-P384-SHA512 | Medium–High |
| ALG-5 | **RESOLVED (R4, 2026-08-25)** — was: registration branch dead. Turned out to need five real fixes, not the originally-guessed "2-line checklist omission": (1) two fabricated fallback constants in `exchange.c` (`CKK_X25519`/`CKK_X448` do not exist in the PKCS#11 spec — real montgomery keys are `CKK_EC_MONTGOMERY`, distinguished by curve name/size, matching Edwards' own pattern; the fake values meant the key-type sniff could never match a real key) — fixed, key-exchange mechanism now correctly resolves from bit size. (2) Four missing-case bugs across `objects.c` (fetch, export, `get_ec_public_raw`'s peer-marshalling gate, and two import/store-dispatch switches) and `store.c` (naming) — the same missing-case class found twice in R1. (3) **The actual root cause of "genpkey succeeds but the token silently creates the wrong key type"**: the C++ engine's `generateED()` (shared by `CKM_EC_EDWARDS_KEY_PAIR_GEN` and `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` — the mechanism itself is never passed into that function) determines the resulting key's `CKK_*` type solely from an explicit `CKA_KEY_TYPE` on the public-key template, defaulting to `CKK_EC_EDWARDS` when absent — found live, not assumed: `genpkey` exited 0 and created two real objects, but reading the result back showed `CKK_EC_EDWARDS` (0x40), not `CKK_EC_MONTGOMERY` (0x41). EC/Edwards never needed to send this explicitly (the engine's default already matched them); montgomery does. Fixed by conditionally adding `CKA_KEY_TYPE` to the shared `p11prov_ec_gen`'s public-key template only for montgomery (zero diff for the already-working EC/Edwards paths). Curve-parameter DER bytes (`curve25519`/`curve448` PrintableStrings) verified two independent ways: direct DER-encoding computation and byte-for-byte match against the latchset sibling's own shipped constants. **Live-verified, both curves, both directions, token-to-token**: X25519 produces a byte-identical 32-byte shared secret; X448 a byte-identical 56-byte one. **A sixth, narrower, separate gap surfaced and was left open**: deriving against a genuinely foreign (default-provider-only) peer key with OpenSSL's peer validation enabled fails with `OSSL_PARAM_get_BN: param of incompatible type` — T8's identical shape works for regular EC but not montgomery; traced to OpenSSL's cross-provider `EVP_PKEY_public_check` falling into a legacy EC_KEY-control translation path that assumes Weierstrass X/Y BIGNUM coordinates montgomery keys don't have. The provider's own derive mechanism is unaffected and proven correct; this is a peer-validation-specific interaction, documented in `T16`'s comment rather than silently dropped. | both engines advertise `CKM_X25519`/`CKM_X448`; live probe + source (`exchange.c`, `objects.c`, `store.c`, `keymgmt.c`, `SoftHSM_keygen.cpp`) | ~~Medium~~ — |
| ALG-6 | ECDH-as-KEM | both engines flag ENCAP/DECAP on `CKM_ECDH1_DERIVE` | not exposed as an OSSL KEM | Low |
| ALG-7 | ChaCha20 / ChaCha20-Poly1305 | both engines | cipher table is AES-only | Low |
| ALG-8 | HMAC/CMAC/KMAC as EVP_MAC | both (CMAC C++-only, KMAC both) | see OP-1 | Medium |
| — | FrodoKEM / Classic McEliece (Rust vendor mechs), BIP32, Keccak-256, split-key | Rust engine / KMIP | deliberately out of OpenSSL scope — recorded, not gapped | — |

### C. New 3.6 features unused

| ID | Gap | Evidence | Severity |
|---|---|---|---|
| F36-1 | **RESOLVED for the client role (R5 phase 1 + R12, 2026-08-25)** — server role (R15) remains unbuilt, tracked separately. Was: `TLS-GROUP` capability registered zero PQC groups. Now: `MLKEM512`/`768`/`1024` registered as pure (non-hybrid) TLS 1.3 groups (`tls.c`), IANA code points and security-bits read live from the staged 3.6.3 build's own source (`0x0200`/`0x0201`/`0x0202`, 128/192/256 bits — not from memory). Two client-role prerequisites landed and live-verified: ML-KEM's `ENCODED_PUBLIC_KEY` get_params (TLS's key-share export mechanism) and relaxing its export function's class check so it works on the private object TLS actually holds post-keygen (was: strictly `CKO_PUBLIC_KEY`-only) — proven with a full simulated handshake sequence (export share from private → simulated server encapsulates → client decapsulates), byte-matched. A separate, real bug found and fixed along the way: `p11prov_common_gen_set_params`'s type switch had no case for `CKK_ML_KEM`/`CKK_SLH_DSA`, hit live by TLS's own ephemeral-keygen call path (which passes real params, unlike a bare `genpkey` CLI call). **A genuine, live TLS 1.3 handshake was run and the token demonstrably participated** — `s_client -groups MLKEM768 -propquery "?provider=pkcs11"` against a software `s_server`: `Negotiated TLS1.3 group: MLKEM768`, and the C++ engine's own log shows 6 real objects created (the ephemeral keypair) — not assumed, counted. **Both things that remained open after R5 phase 1 are now resolved by R12/R13 (2026-08-25), see the update log below for the full mechanism**: (1) full handshake completion — the `TLS13_KDF` blocker was root-caused to four layered, precisely-diagnosed bugs (not one) and fixed in both engines; a real TLS 1.3 handshake now completes end-to-end with `MLKEM768` and a genuine cipher suite negotiated; (2) the silent-software-fallback hazard is now caught mechanically — harness case T13 asserts token participation from the engine log and ships a negative-control twin proving the hazard is real, per R13. Server role (importing a peer's raw public share to encapsulate against) remains unbuilt — tracked as R15. | `tls.c`, `kem/mlkem.c`, `kdf.c` (root-caused, unchanged), `SoftHSM_keygen.cpp`, `rust/src/ffi.rs`; harness T13 | ~~**High**~~ ~~Medium~~ Low (client role complete; server role is R15) |
| F36-2 | LMS: OpenSSL 3.6's new verify-only LMS unused (see ALG-3, ENV-1) | release notes + live build | Medium |
| F36-3 | `EVP_SKEY` KDF/KEYEXCH integration (3.6): provider has SKEYMGMT but the new `EVP_KDF_derive_SKEY`-style opaque-key flows are unprobed — token-resident secrets may not chain into OpenSSL KDFs without export | 3.6 CHANGES; needs probe (T-plan P2) | Medium |
| F36-4 | *(positive baseline, not a gap)* CMS KEMRecipientInfo + `OSSL_PKEY_PARAM_CMS_RI_TYPE` already wired for ML-KEM (local commit `2cca4f0`) — must be regression-guarded by the new harness | `kem/mlkem.c:414-433` | — |
| F36-5 | NIST security-category PKEY param (new 3.6) not exposed by provider keymgmt | 3.6 release notes | Low |
| F36-6 | ML-DSA signature params: provider plumbs `context-string` + hedging (`9cc52e6`/`d895c1a`); `mu`/`message-encoding`/`deterministic` parity vs software unverified | source + EVP_SIGNATURE-ML-DSA(7) | Low–Medium |

### Environment / infrastructure findings

| ID | Finding |
|---|---|
| ENV-1 | Staged OpenSSL 3.6.3 (`/usr/local/ssl` in `pqc-rust`) built **without** `enable-lms` — LMS test/remediation work needs a rebuilt oracle first. |
| ENV-2 | **Partially addressed (R6, 2026-08-25) — reported precisely, not claimed done.** Was: native Rust-engine arm structurally blocked, snapshot/restore wired only for WASM. Now: an opt-in, env-var-gated (`SOFTHSMRUST_STATE_FILE`) native persistence path added to `C_Initialize`/`C_Finalize` (`rust/src/ffi.rs`), reusing `state_snapshot.rs`'s existing `serialize_token_state`/`deserialize_token_state` verbatim (already unit-tested — `round_trip_restores_tokens_and_token_objects_only`, `truncated_snapshot_is_rejected_and_state_untouched`, both pass) and inheriting its `SHR3SNP2` refuse-don't-migrate policy unchanged. Byte-identical to today's in-memory-only behavior when the env var is unset (confirmed: the change is purely additive, gated, and does not touch any code path exercised when unset). **A separate, pre-existing bug was found and confirmed unrelated to this fix** (reproduced identically against the pre-R6 binary via `git stash`): `softhsm2-util --init-token` against the Rust engine fails with "Could not get the slot list" — traced to `C_GetSlotList`'s auto-advance-a-fresh-slot logic behaving inconsistently between the tool's two required calls (count-only, then buffered), confirmed live via a temporary debug trace (first call reports zero slots, second reports one). This blocks END-TO-END verification of R6 via the same tool T15b uses, but does not indicate the persistence code itself is wrong — not fixed here, given the risk of a blind fix to unfamiliar, pre-existing slot-management logic under time constraints. Provider+Rust coverage on the WASM static-link path (hub e2e) is unaffected either way. |
| ENV-3 | Existing provider test assets are dead: `test_openssl_integration.sh` soft-fails every functional step and is referenced by nothing; `openssl_test.cnf` hardcodes another developer's absolute `.dylib` paths; the vendored meson test suite (30 tests) is dormant — no CMake/ctest/CI/gate wiring. |

---

## 5. Validation plan

**Objective:** continuously prove (a) what the provider claims to cover
actually works end-to-end against real engines under the real OpenSSL
3.6.3, cross-checked against OpenSSL's own software implementations;
(b) known gaps stay explicitly marked (XFAIL) so any remediation or
regression flips a visible state, never silently.

**Environment:** `pqc-rust` container; OpenSSL 3.6.3 at
`/usr/local/ssl` (same `OPENSSL_ROOT_DIR`/`OPENSSL_LIB_DIR` override
pattern the `--cpp` and `--tls-interop` gate steps use);
`build/src/vendor/pkcs11-provider/pkcs11-provider.so` +
`build/src/lib/libsofthsmv3.so` from the `--cpp` step's own build (the
new step orders after it / builds if absent). Hermetic per-case
workdirs under `/tmp` — one token directory per algorithm family so
`pkcs11:token=<label>` URIs are unambiguous (a live probe showed
type-only URIs match the wrong key once two keypairs share a token).

**Arms:**
1. **C++ native arm** — full functional matrix (below). Primary.
2. **Rust native arm** — load + registration checks only; the
   functional matrix is XFAIL-ENV with the ENV-2 root cause asserted
   (the probe must fail *for that reason*), so the arm self-activates
   when ENV-2's remediation lands.
3. **WASM arm** — out of scope here (already covered by hub e2e
   `cms-hsm-sign.spec.ts` etc.); noted for the coverage ledger.

**Verification principles** (house discipline): every crypto result is
cross-checked against the *other* implementation (provider-sign →
software-verify; software-encap → provider-decap), never self-verified
within one stack; tamper cases prove the verifier can say no; exit
codes captured directly, never through pipelines (`grep -v` ate a real
exit code during this audit's own probing); the harness itself gets
sabotage-tested (flipped assertion on a copy) before its green is
trusted; unexpected PASS of an XFAIL case fails the run (ratchet).

## 6. Test plan (implemented in `scripts/test-openssl-provider.sh`)

| ID | Case | Check | Expect |
|---|---|---|---|
| T0 | Preflight | OpenSSL 3.6.x present, provider .so, engine .so, softhsm2-util | hard fail if missing |
| T1 | Provider activates | `list -providers` shows `pkcs11` active | PASS |
| T2 | Store | `storeutl` enumerates a freshly created token keypair | PASS |
| T3a-c | ML-DSA-44/65/87 | token keygen → URI sign → **software** verify; FIPS 204 signature sizes (2420/3309/4627) | PASS |
| T3t | Tamper | flipped-byte signature must fail software verify | PASS (reject) |
| T4x | ML-KEM token keygen (OP-6) | provider keygen lands a key on token, confirmed via `storeutl` (not gated on genpkey's own `-out` exit code — that write needs a still-missing encoder, tracked separately below) | **PASS** (flipped by R3b, 2026-08-25) |
| T4x_encode | ML-KEM `genpkey -out` PEM write (OP-3) | genpkey exit 0, URI-PEM label present, no `PRIVATE KEY` label ever present | **PASS** (flipped by R3 core, 2026-08-25) |
| T5 | RSA-3072 | token keygen → PKCS#1 sign → software verify; software OAEP-encrypt → provider decrypt | PASS |
| T6 | ECDSA P-256 | token keygen → sign → software verify | PASS |
| T7 | Ed25519 | token keygen → sign → software verify | PASS |
| T8 | ECDH P-256 | provider derive vs software derive — same shared secret | PASS |
| T9 | Digest fetch (WART-4) | `dgst -propquery provider=pkcs11` in a fresh process, dedicated arena with `pkcs11-module-load-behavior=early` | **PASS** (flipped by R0.4, 2026-08-25) |
| T10 | URI-PEM round-trip, EC (control) | genpkey URI-PEM → load back → sign | PASS |
| T11 | URI-PEM round-trip, ML-DSA (OP-2) | same flow | **PASS** (flipped by R2, 2026-08-25) |
| T11slh | URI-PEM round-trip, SLH-DSA-SHA2-128s (OP-2) | same flow, one representative parameter set of the 12 registered | **PASS** (new case, R2) |
| T11kem | URI-PEM round-trip, ML-KEM-768 (OP-2) | decoder-loaded private key decapsulates and matches a reference secret from a direct-URI encapsulation — encapsulate/pubout-from-private-object is a separate, still-open gap (see OP-2's row) | **PASS** (new case, R2) |
| T12 | SLH-DSA keygen/store/encode reachability (ALG-1) | genpkey (all 12 param sets registered) → storeutl confirms on-token, correctly typed/named | **PASS** (flipped by R1, 2026-08-25) |
| T12sign | SLH-DSA-SHA2-128s token-sign (ALG-1 remainder) | `pkeyutl -sign` → software verify (exact 7856-byte sig) + tamper rejection | **PASS** (flipped by R1's `get_ctx_params` fix, 2026-08-25) |
| T12sign_shake | SLH-DSA-SHAKE-128f token-sign, independent hash family | same, exact 17088-byte sig | **PASS** (new case, R1) |
| T13 | TLS-GROUP gap (F36-1) | live `s_server`/`s_client` TLS 1.3 handshake negotiating `MLKEM768`, real cipher suite completes, engine-log evidence (token-side attribute decrypt activity) proves the token performed both the KEM ops and the TLS13-KDF derives; negative-control twin (same arena, no propquery) proves the same command silently succeeds via software with zero token activity when not pinned (R13) | **PASS** (new case, R12/R13, 2026-08-25; sabotage-tested) |
| T4kemexport | ML-KEM public-share export from private object (R5 prerequisites) | `pkey -pubout` on a `type=private` URI → simulated server encap → client decap, byte-matched | **PASS** (new case, R5) |
| T14 | CMS RSA | CMS sign via token key → software cmsverify | PASS |
| T16 | X25519 key exchange (ALG-5) | token-to-token derive (two independent arenas), both directions, byte-identical 32-byte secret | **PASS** (new case, R4) |
| T16b | X448 key exchange (ALG-5) | same, 56-byte secret | **PASS** (new case, R4) |
| T15a/b | Rust arm | provider activates over `libsofthsmrustv3.so` (PASS); multi-process functional flow (XFAIL, ENV-2) | PASS + **XFAIL** (R6 code landed, PARTIAL — see ENV-2; a separate pre-existing `softhsm2-util`/Rust-engine slot-list bug, confirmed unrelated to R6, blocks flipping this) |
| P2 (plan-only, not scripted yet) | AES/SKEY cipher path, EVP_SKEY KDF chaining (F36-3), CMS KEMRecipientInfo native round-trip (needs ML-KEM cert tooling), composite COMPSIG CLI case, ML-DSA `mu`/`deterministic` parity, RAND fetch | — | design first |

**First full run (2026-08-25, C++ arm + Rust arm, ~40s):**
`OPENSSL-PROVIDER-HARNESS: PASS=13 FAIL=0 XFAIL=5 XPASS=0` — passes:
provider activation (both engines), store enumeration, ML-DSA-44/65/87
token-sign→software-verify at exact FIPS 204 sizes + tamper rejection,
RSA-3072 sign/verify + software-OAEP(SHA-256)→token-decrypt, ECDSA P-256,
Ed25519, ECDH shared-secret parity, EC URI-PEM round-trip, CMS
token-sign→software-verify. XFAILs = OP-6, WART-4, OP-2, ALG-1, ENV-2 —
exactly the documented gaps. Harness sabotage-tested both directions
(flipped size assertion → FAIL+exit 1; XFAIL case aimed at a working
algorithm → XPASS+exit 1).

**Independently re-run in a fresh session (2026-08-25, same day, same
container/build) to validate this document rather than take its own
self-report on trust:** identical result, `PASS=13 FAIL=0 XFAIL=5
XPASS=0`, real exit code 0 (captured directly, not through a pipe — see
verification principles above). Both sabotage directions re-run against
throwaway copies (`/tmp`, never the checked-in script): (1) `mldsa_case
65 3309` → `9999` in a copy made `T3b`'s real 3309-byte signature fail
its assertion — `PASS=12 FAIL=1 XFAIL=5 XPASS=0`, exit code 1, confirmed
by reading `$?` directly with no intervening pipeline (the first attempt
piped through `tail` and silently read exit 0 — the exact failure mode
this document's own verification principles warn about, reproduced
live). (2) T12's algorithm swapped from `SLH-DSA-SHA2-128s` (unreachable)
to `ML-DSA-65` (known-working) — the expected-gap case unexpectedly
succeeded — `PASS=13 FAIL=0 XFAIL=4 XPASS=1`, exit code 1. A sample of
the highest-severity source citations (OP-6's zero `KEYMGMT_GEN` entries
in ML-KEM's per-variant dispatch tables vs. ML-DSA's `GEN_INIT`/`GEN`
pair in `keymgmt.c`; ALG-1's `{0, NULL}` stub in `sig/slhdsa.c`; F36-1's
all-classical `TLS_PARAMS_ENTRY` list in `tls.c` with zero ML-KEM/hybrid
names; ENV-2's `SHR3SNP2` magic and confirmed absence of any
`SOFTHSMRUST_STATE_FILE`-style persistence) were re-derived independently
from source and matched the claims above.

Gate wiring: **implemented and verified live**, `scripts/local-gate.sh`
step 14, opt-in `--openssl-provider` flag (also included in `--all`).
FAIL-never-skip when flagged, matching `--tls-interop`/`--cpp`
precedent: `run_step` checks the harness's own exit code directly (no
separate grep needed — `test-openssl-provider.sh` already exits 1 on any
FAIL or XPASS, so the exit code alone is equivalent to parsing the
summary line; this differs from `--javajce`'s pattern, where the
underlying tool's exit code is not by itself a reliable aggregate
signal). Placed after the `--cpp` block (reuses its build artifacts;
does not force `RUN_CPP=1` — a missing build fails loudly via the
harness's own T0 preflight rather than skipping silently). Verified live
2026-08-25 by replicating the exact `dexec` invocation
(`cd /ag/pqctoday-hsm && bash scripts/test-openssl-provider.sh`) outside
the full gate run (the mandatory core steps 1-7 are unrelated and slow;
this reproduces the identical command path `run_step` uses) — real exit
code 0, `OPENSSL-PROVIDER-HARNESS: PASS=13 FAIL=0 XFAIL=5 XPASS=0`.

**Update (2026-08-25, later same day) — P0 remediation batch executed:**
R0.1/R0.2/R0.3/R0.4/R0.5 all landed (R0.4 on a second, careful attempt
after a first attempt regressed provider activation and was reverted —
see the remediation plan for the full story). Harness was
`OPENSSL-PROVIDER-HARNESS: PASS=14 FAIL=0 XFAIL=4 XPASS=0` — T9 flipped
from XFAIL to PASS; WART-4 is resolved (§4A above); WART-1/3/5 are
resolved/documented.

**Further update (2026-08-25, same day) — R1 (SLH-DSA), fully done:**
keygen/store/encode/sign all real and working for all 12 parameter
sets. Landing keygen/store/encode surfaced two real, unrelated bugs
(fixed); landing sign itself took a second pass — prompted by the
user asking whether the actual OpenSSL 3.6 documentation had been
checked, which it had not been closely enough. It had the answer:
provider-signature(7) documents a mandatory function-pairing rule our
dispatch tables violated. Fixed, and verified with real cryptographic
checks (exact FIPS 205 signature sizes, independent software
cross-verify, tamper rejection, a second independent algorithm from
the other hash family) — not just "the fetch stopped erroring". See
remediation plan R1 for the full mechanism and fix. Harness now reads
`OPENSSL-PROVIDER-HARNESS: PASS=17 FAIL=0 XFAIL=3 XPASS=0` — T12
flipped PASS (rescoped); T12sign and new T12sign_shake both flipped
PASS. Remaining XFAILs at that point: OP-6 (T4x), OP-2 (T11), ENV-2
(T15b) — all still plan-only, Priority 1/2 items.

**Further update (2026-08-25, same day) — R3b (ML-KEM token keygen),
done:** added real `GEN_INIT`/`GEN`/`GEN_CLEANUP`/`GEN_SET_PARAMS`/
`GEN_SETTABLE_PARAMS` to all 3 ML-KEM keymgmt tables (`kem/mlkem.c`),
implemented in `keymgmt.c` and exported non-static across the
translation-unit boundary. Live-verified: `genpkey -algorithm ML-KEM-768`
now generates a real key and persists it on-token, independently
confirmed via `storeutl -text`. Landing it surfaced a real, previously
undiscovered gap: `genpkey`'s own `-out` file write still fails
(`Error writing key(s)`, exit 1) because ML-KEM has zero encoders
registered — OP-3, a distinct, already-tracked gap, not part of R3b's
scope. The original T4x test (as designed during the initial audit) had
`|| return 1` directly after the `genpkey` call, meaning it could never
have flipped to PASS on R3b alone even after R3b was fully correct — it
was accidentally coupled to OP-3 too. Rescoped T4x to assert on
`storeutl` alone (the actual claim R3b makes), and added a new case,
T4x_encode, to independently track OP-3's gap so it isn't lost. Both
sabotage-tested (T4x: broken storeutl assertion, FAIL exit 1;
T4x_encode: swapped in a trivially-succeeding body, XPASS exit 1).
Harness now reads `OPENSSL-PROVIDER-HARNESS: PASS=18 FAIL=0 XFAIL=3
XPASS=0`. Remaining XFAILs at that point: OP-3 (T4x_encode), OP-2
(T11), ENV-2 (T15b).

**Further update (2026-08-25, same day) — the phase-2 plan
(`docs/openssl-provider-remediation-plan-phase2-2026-08-25.md`) was
written, then adversarially challenged against the source before
execution (v2 of that document records 8 challenge results, 5 of
which changed scope) — see that document's own log rather than
duplicating it here. R3's challenge (C1) corrected a claim this audit
itself had made: ML-KEM public-key output was never actually broken;
only the private-key URI-PEM encoder was. **R3 core is now landed**
per that corrected scope — see OP-3 above. T4x_encode flipped to PASS.
A negative security assertion (no `PRIVATE KEY` label ever appears in
the written file) was added, not just the positive check, and both
were sabotage-tested — the first sabotage attempt produced a false
alarm (an unrelated test, T10, also failed) that traced to a mistake
in the sabotage script itself (a non-scoped string replace hit an
identical line shared by three test functions), not a real product
bug; corrected and re-verified. Harness is now `PASS=19 FAIL=0
XFAIL=2 XPASS=0`. Remaining XFAILs at that point: OP-2 (T11), ENV-2
(T15b).

**Further update (2026-08-25, same day) — R2 (PQC decoders) landed:**
18 decoder registrations (ML-DSA×3, ML-KEM×3, SLH-DSA×12) — see OP-2
above for the full mechanism and the genuinely separate gap (ML-KEM
private→public bridge, already tracked under R5) that its own proof
surfaced. T11 flipped PASS; T11slh and T11kem added, both PASS.
Sabotage-tested (T11: broken sign-target path → FAIL, exit 1; T11kem:
corrupted one byte of the decapsulated secret before the comparison →
FAIL, exit 1 — proving the byte-equality check is real, not
decorative). Harness: `PASS=22 FAIL=0 XFAIL=1 XPASS=0`. Only
remaining XFAIL: ENV-2 (T15b).

**Further update (2026-08-25, same day) — R4 (X25519/X448) landed:**
see ALG-5 above for the full mechanism — five real fixes, not the
originally-guessed 2-line checklist omission, including a root-caused
engine-interaction bug (the C++ engine's shared Edwards/Montgomery
keygen function silently defaulted to the wrong key type without an
explicit `CKA_KEY_TYPE`) found live via direct object-type readback,
not assumed. T16 (X25519) and T16b (X448) added, both PASS,
token-to-token, both directions, byte-identical shared secrets at the
correct FIPS-equivalent sizes (32/56 bytes). Sabotage-tested both
(T16: corrupted one byte of the compared secret → FAIL; T16b: size
assertion flipped to an impossible value → FAIL). A sixth, narrower,
separate gap was found and deliberately left open rather than
silently dropped: peer-key validation against a genuinely foreign
(non-pkcs11) key fails for montgomery specifically, traced to an
OpenSSL legacy-compatibility interaction, not the provider's own
derive logic (which is proven correct). Harness: `PASS=24 FAIL=0
XFAIL=1 XPASS=0`. Only remaining XFAIL: ENV-2 (T15b, remediation R6).

**Further update (2026-08-25, same day) — R5 phase 1 (TLS groups),
partial, honestly reported:** see F36-1 above for the full mechanism.
Landed and live-verified: pure `MLKEM512`/`768`/`1024` TLS 1.3 group
registration with IANA code points read from the staged build's own
source; both client-role prerequisites (`ENCODED_PUBLIC_KEY` export,
export-from-private-object); a real `CKK_ML_KEM`/`CKK_SLH_DSA` gap in
`p11prov_common_gen_set_params` found live by TLS's own keygen call
path and fixed. **A genuine TLS 1.3 handshake was run**, the group
negotiated as `MLKEM768`, and the C++ engine's own log confirms the
token generated a real ephemeral keypair (6 objects created) — this
is the first time in this remediation effort the token has been shown
participating in an actual protocol handshake, not just a CLI probe.
Two things left open and precisely documented rather than glossed
over: full handshake completion is blocked by a separate bug in this
provider's own `TLS13_KDF` implementation once the token genuinely
participates; without forcing that participation via propquery, the
identical handshake silently succeeds using zero token involvement — a
real false-pass risk worth knowing about. New harness case
T4kemexport (the proven prerequisite chain) added, PASS,
sabotage-tested. Harness: `PASS=25 FAIL=0 XFAIL=1 XPASS=0`.

**Further update (2026-08-25, same day) — R6 (Rust engine
persistence), partial, honestly reported:** see ENV-2 above for the
full mechanism. The persistence code (opt-in `SOFTHSMRUST_STATE_FILE`
env var, `C_Initialize`/`C_Finalize` in `rust/src/ffi.rs`) landed,
reusing `state_snapshot.rs`'s already-unit-tested serialize/
deserialize functions verbatim, purely additive and gated (zero
behavior change when unset) — the full Rust lib suite (410 tests)
passes with no regressions. **Cannot be flipped to PASS**: a separate,
genuinely pre-existing bug — confirmed unrelated to R6 by reproducing
it identically against the pre-R6 binary — makes `softhsm2-util
--init-token` fail against the Rust engine entirely
("Could not get the slot list", traced to inconsistent slot counts
across the tool's two required `C_GetSlotList` calls, confirmed via a
temporary debug trace). This means the harness's own multi-process
test was already never getting a real token before R6 either — its
`XFAIL` has likely never specifically proven the persistence gap, only
that the Rust arm's CLI flow doesn't work, for a reason this session
had not previously distinguished. Deliberately not fixed blind under
time constraints; T15b's own comment and the plan's R6 entry document
the precise next step. This closes out this session's execution of
the phase-2 remediation plan: R3 core, R2, R4, R5 phase 1 (partial),
and R6 (partial) all attempted, each reported at exactly the
confidence level the evidence supports — full completion for the
first three, precise partial-progress reporting for the last two.
Harness remains `PASS=25 FAIL=0 XFAIL=1 XPASS=0`.

**Further update (2026-08-25/26, phase-3 execution) — R12 (TLS13-KDF
root cause + fix) and R13 (anti-false-pass harness rule), both DONE:**
see F36-1 above for the current-state summary. Full mechanism, since
this took three rounds of live instrumentation to nail precisely — the
phase-3 plan's own written hypothesis (missing `CKM_HKDF_DATA`
support) turned out to be only the first of four layered, independent
bugs, each found by re-instrumenting and re-testing rather than
guessing forward from the previous fix:

1. **`CKM_HKDF_DATA` (0x402b) genuinely unimplemented in both
   engines** — confirmed by live trace: the provider's slot-selection
   loop silently masked this as `CKR_TOKEN_NOT_PRESENT` (from a
   second, unrelated "spare uninitialized slot" it fell through to
   after the real slot's mechanism check failed unprinted) — a red
   herring that cost real investigation time before the C++ engine's
   own log-free rejection was traced to `p11prov_check_mechanism`.
   Fixed: identical HKDF computation reused in both engines
   (`SoftHSM_keygen.cpp`, `rust/src/ffi.rs`), differing only in output
   object shape (`CKO_DATA`, no key-lifecycle attributes) — matching
   PKCS#11 v3.2 §6.62.4 exactly ("HKDF Data derive mechanism ... is
   identical to HKDF Derive except the output is a CKO_DATA object"),
   verified against the ratified OASIS Standard text (`pkcs11-spec-
   v3.2-os.pdf`), not the draft.
2. **A second, independent bug**, found only after fix #1 changed the
   failure symptom: `C_DeriveKey`'s own top-of-function mechanism
   whitelist `switch` (`SoftHSM_keygen.cpp`) never included
   `CKM_HKDF_DATA` at all — a hard `default: return
   CKR_MECHANISM_INVALID` gate upstream of fix #1's own code, entirely
   separate from the mechanism-capability check in #1.
3. **A third, independent bug**, found only after fix #2 changed the
   symptom again: a *shared* pre-check (`extractObjectInformation` +
   `if (objClass != CKO_SECRET_KEY) return
   CKR_ATTRIBUTE_VALUE_INVALID`) applies to every mechanism reaching
   that point in `C_DeriveKey`, including the new one — correct for
   `CKM_HKDF_DERIVE` (whose template requests `CKO_SECRET_KEY`) but
   wrong for `CKM_HKDF_DATA` (whose template correctly requests
   `CKO_DATA` per the spec). Carved out an explicit exemption.
4. **A fourth bug**, surfaced only once the first derive call fully
   succeeded and a *second* one — never reached before — ran: the
   vendored provider's own `p11prov_tls13_expand_label()` helper
   (confirmed identical in the unmodified upstream
   `openssl-projects/pkcs11-provider` source, not a fork divergence)
   leaves `CK_HKDF_PARAMS.ulSaltType` as a raw zero-initialized struct
   field on every expand-only call, rather than the named
   `CKF_HKDF_SALT_NULL` constant (which is `0x1`, not `0`, per
   `pkcs11t.h`). The engine's strict three-value `ulSaltType`
   allow-list rejected this as `CKR_MECHANISM_PARAM_INVALID`. Fixed
   with direct spec grounding, not a guess: PKCS#11 v3.2 §6.62.3
   states verbatim "The salt should be ignored if bExtract is false"
   — so `ulSaltType` is only meaningful, and only validated, when
   `bExtract` is true; the gate now reads `if (hkdfp->bExtract &&
   ulSaltType not in {NULL,DATA,KEY}) reject`. Same gate added to the
   Rust engine for parity (it had no equivalent strict check at all,
   so it wasn't broken, just inconsistent) — `CKF_HKDF_SALT_NULL` was
   missing from `rust/src/constants.rs` entirely and had to be added.

**No new PKCS#11 constants or mechanisms were invented anywhere in
this fix** — every constant (`CKM_HKDF_DATA`, `CKO_DATA`,
`CKF_HKDF_SALT_NULL`) was cross-checked against both the canonical
`pkcs11t.h` and the ratified OASIS PKCS#11 v3.2 spec text before use;
Table 265 in the spec confirms `CKM_HKDF_DATA` supports only the
Derive function, matching this implementation's scope exactly.

**Result**: a real TLS 1.3 handshake with `-groups MLKEM768
-propquery "?provider=pkcs11"` now completes end-to-end — `Negotiated
TLS1.3 group: MLKEM768`, `New, TLSv1.3, Cipher is
TLS_AES_256_GCM_SHA384` — the first time in this remediation effort a
full, real cipher suite has been negotiated with the token performing
both the KEM operations and the key-schedule derivation. R13 (the
anti-false-pass harness rule from the phase-3 plan) is folded directly
into the new harness case rather than built separately: T13 asserts
token participation from engine-log evidence (at-rest attribute
decrypt activity), not exit codes alone, and ships a negative-control
twin (same arena, `propquery` removed) proving the identical command
silently succeeds via the default provider's software ML-KEM with
zero token activity when not pinned — making the phase-2/phase-3
false-pass hazard an executable, permanent fact instead of prose.
T13 was sabotage-tested: reverting fix #2 (the mechanism whitelist
entry) in a working copy makes T13 — and only T13 — fail; restoring it
makes T13 pass again. Both engines' full test suites pass with zero
regressions (C++: 8/8 CTest suites including `p11_v32_compliance`;
Rust: 410/410 unit tests). Harness: `PASS=26 FAIL=0 XFAIL=1 XPASS=0`
— one case gained (T13), the sole remaining XFAIL (T15b) unchanged
and out of scope for this fix (blocked by the separate, pre-existing
R14 `C_GetSlotList` bug in the Rust engine, still open).

**Not investigated as part of this fix, noted for completeness**: a
small residual `asn1_check_tlen`/`PKCS8_PRIV_KEY_INFO` error queue
entry still appears in the client's stderr even on the now-passing
handshake. Traced only as far as: it does *not* appear in an
equivalent pure-software control run (no provider active at all), so
it is specific to having pkcs11's decoders registered — most likely
benign OpenSSL provider-decoder-chain probe noise (R2's new DER
decoders being tried against the peer's plain RSA certificate,
correctly rejecting it, but pushing an expected-failure ASN.1 error
onto the queue before the real RSA decoder succeeds — a well-
understood OpenSSL provider framework pattern). Does not affect the
handshake outcome (cipher suite negotiates, `Verify return code: 18`
is the correct answer for an untrusted self-signed test cert, not a
parse failure) and was not chased further, per the same
instrument-before-fixing discipline as everything else in this
session — flagged rather than silently ignored or blindly patched.

## 7. Companion document

Remediation priorities, effort estimates and sequencing:
`docs/openssl-provider-remediation-plan-2026-08-25.md`.
