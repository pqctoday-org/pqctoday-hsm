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
| OP-1 | **RESOLVED (R8 + R23, 2026-08-25/26)** — was: `OSSL_OP_MAC` not implemented at all — token HMAC/CMAC/KMAC unreachable from `EVP_MAC`; every MAC falls back to software. R8: token HMAC (bytes-in mode), live-verified against all four SHA sizes (T20/T20b-d). R23: CMAC (AES-128/192/256, key-type-constrained to `CKK_AES` matching the engine's own table) and KMAC-128/256 (fixed 32/64-byte output, empty customization string — both non-honorable inputs rejected loudly, not silently degraded) join it, plus `OSSL_FUNC_MAC_INIT_SKEY` for all three (an R24 finding: a correctly-derived, correctly-opaque `EVP_SKEY` had nothing in this provider that could consume it natively) — live-verified byte-identical to software, engine-log confirmed, sabotage-tested (T26/T26b/T26c/T26d). | source sweep; block-list table `provider.c:1570` | ~~Medium~~ — |
| OP-2 | **RESOLVED (R2, 2026-08-25)** — was: no DECODERs for ML-DSA/ML-KEM/SLH-DSA (composites remain intentionally unregistered — §2's table, recursion issue) → URI-PEM round-trip broken; loading a written PEM back failed. Now: 18 decoder registrations (3 ML-DSA + 3 ML-KEM + 12 SLH-DSA) in `decoder.c`/`provider.c`, using the same generic PEM→DER→store-fetch chain already proven live by T10 (the EC control). Each per-type decoder's FORMAT_NAME had to be the exact single-name string `store.c` emits as `DATA_TYPE` (e.g. `MLDSA_44` = `"ML-DSA-44"`), not the colon-separated registration list. Live-verified for all three families: ML-DSA loads back and signs; SLH-DSA loads back and signs (7856-byte signature, correct size); ML-KEM loads back and **decapsulates** correctly (matched a reference secret from a direct-URI encapsulation). **A genuinely separate gap surfaced during ML-KEM's proof**: a URI-PEM-loaded ML-KEM object identifies as `type=private`, and neither `pkey -pubout` nor `pkeyutl -encap` work against it — confirmed live (`attribute does not exist: 0x633`/CKA_ENCAPSULATE) — because the keymgmt EXPORT function requires a public-class object and does not walk private→associated-public the way ML-DSA's does. This is not a decoder bug (decapsulate, which only needs the loaded private key's own attributes, works perfectly) — it is the same prerequisite already tracked for remediation R5 (TLS groups), now confirmed by a second, independent code path. | `decoder.c`, `provider.c`; live (T11, T11slh, T11kem) | ~~**High**~~ — |
| OP-3 | **Core RESOLVED (R3, 2026-08-25)** — was: ML-KEM had zero encoders registered, so `genpkey -algorithm ML-KEM-768 -out k.pem` generated and persisted a real key on-token (R3b) but the `-out` write step failed, `Error writing key(s)`/exit 1. **Correction to this row's own earlier wording** (found live during R3, not assumed): public-key output was never actually broken — `storeutl -text`/`pkey -pubout` already worked with zero encoders, because ML-KEM's keymgmt EXPORT function bridges the public bytes into OpenSSL's default provider, which encodes them. The real, sole functional gap was the **private**-key URI-PEM PrivateKeyInfo encoder — the one path that can't use that bridge (private material never crosses into another provider). Fixed: `p11prov_mlkem_encoder_priv_key_info_pem_encode` (`encoder.c`), registered for all 3 variants inside the `encode_pkey_as_pk11_uri` block (`provider.c`). Like every other PrivateKeyInfo encoder in this fork, it never touches raw key bytes — `p11prov_encoder_private_key_to_asn1` calls `p11prov_obj_get_public_uri(key)` and PEM-wraps that `pkcs11:` URI string; live-verified the written file decodes to a `type=private` URI, and a negative harness assertion checks no `PRIVATE KEY` label ever appears. **Remaining, deliberately separate parity tier**: SPKI/text encoders for public keys (would let public output work even in `DISALLOW_EXPORT_PUBLIC` configs, and match every other PQC family in this fork) — not functionally required, scoped as follow-up. | `encoder.c`; live (T4x_encode, T10 as network-effect control) | ~~Medium~~ — |
| OP-4 | **CLOSED, no gap (R20, 2026-08-26)** — investigated by reading OpenSSL's own CMS source (`crypto/cms/cms_kemri.c`) rather than inferring from the CLI: the real KEMRecipientInfo call sites (`EVP_PKEY_encapsulate_init`/`decapsulate_init`) pass a NULL params argument unconditionally for every KEM algorithm — `OSSL_KEM_PARAM_OPERATION` is a generic-KEM-wrapper concept for RSA/DH keys with no CMS caller and no meaning for a natively-implemented algorithm like ML-KEM. No gap exists; closed without code. | ~~`kem/mlkem.c:259-289`~~ — | ~~Low~~ — |
| OP-6 | **RESOLVED (R3b, 2026-08-25)** — was: ML-KEM keys could not be GENERATED on token through the provider (ML-KEM keymgmt had no `OSSL_FUNC_KEYMGMT_GEN*` entries; ML-DSA keygen worked, so this was an asymmetry, not a design rule). Now: real `GEN_INIT`/`GEN`/`GEN_CLEANUP`/`GEN_SET_PARAMS`/`GEN_SETTABLE_PARAMS` wired into all 3 per-variant ML-KEM keymgmt tables (`kem/mlkem.c`), implemented in `keymgmt.c` (mirroring the ML-DSA block) and exported non-static since `kem/mlkem.c` is a separate translation unit. `CKA_PARAMETER_SET` is mandatory on the public-key template per the C++ engine's own `extractParameterSet` call (no silent default, matching ML-DSA's pattern); `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` requested explicitly on pub/priv templates to match what a spec-correct caller sends (both engines enforce these server-side regardless of template content). Live-verified: key generates, persists on-token, and is independently confirmed via `storeutl -text` showing `ML-KEM-768 Public-Key`. Landing this surfaced OP-3 (above) as a distinct, still-open gap — genpkey's own `-out` write needs an encoder this fix does not provide. | both engines, live probe + source | ~~**High**~~ — |
| OP-5 | **RESOLVED (R10 + R22, 2026-08-25/26)** — was: KDF surface is HKDF+TLS13-KDF only; engines also offer PBKDF2 and SP800-108 counter/feedback KDFs that OpenSSL has standard fetch names for. R10: real `CKM_PKCS5_PBKD2` PBKDF2 support, live-verified byte-identical to software PBKDF2 across five PRFs (T22/T22b-e). R22: real `CKM_SP800_108_COUNTER_KDF`/`CKM_SP800_108_FEEDBACK_KDF` support ("KBKDF" fetch name), live-verified byte-identical to software KBKDF across Counter+Feedback modes, HMAC (SHA-256/SHA3-256/SHA-384) and CMAC PRFs, engine-log confirmed, sabotage-tested, three deliberate-divergence inputs rejected (T25/T25b/T25c/T25f/T25r). | `provider.c:1161` vs engine KDF mechs | ~~Low–Medium~~ — |
| WART-1 | **RESOLVED (R0.1, 2026-08-25 later same day; re-verified R21, 2026-08-26)** — was: `ObjectFile.cpp(181): The attribute is not a byte string: 0x0/0x1/0x2/0x86/0x100/0x170-0x172/0x601` — provider queries CKA_CLASS/CKA_TOKEN/CKA_PRIVATE/CKA_TRUSTED/CKA_KEY_TYPE/CKA_MODIFIABLE/CKA_COPYABLE/CKA_DESTROYABLE/etc. with byte-string templates. Fix: `P11Objects.cpp`'s mandatory-attribute-check loop gated on ck14\|ck15\|ck16 actually being set, not called for every attribute in an object's full schema; harness's own tail section now regression-guards zero `ObjectFile.cpp(181)` lines across every case log. | observed on every live probe | ~~Low~~ — |
| WART-3 | **RESOLVED (R0.2, 2026-08-25 later same day; re-verified R21, 2026-08-26)** — was: build hygiene: the gitignored WASM-generated `src/config.h` leaks into the **native** CMake build — compile warnings `"PACKAGE_MAJOR redefined"` and the live provider reports version **1.1** (config.h) while CMake defines **0.4.0**. Fix: CMakeLists.txt now generates a real `config.h` at configure time deriving `P11PROV_VERSION` from `meson.build`'s own `version:` field — single source of truth across native/meson/WASM builds; re-verified live: `list -providers` reports `1.1`, matching, zero redefinition warnings. | observed in gate build log + live `list -providers` | ~~Low~~ — |
| WART-4 | **RESOLVED (R0.4, 2026-08-25 later same day)** — was: mechanism-gated operation tables are invisible to fresh-process fetches: `openssl list` shows nothing `@ pkcs11` for signature/KEM, AND a strict property-targeted fetch (`dgst -sha256 -propquery provider=pkcs11`) **functionally fails** in a fresh process (`inner_evp_generic_fetch:unsupported`) — operations only resolve once a token object forces module init in-process. Fix: the provider already ships `pkcs11-module-load-behavior = early` for exactly this case (forces the same lazy-init call from inside `OSSL_provider_init()` instead of leaving it to a key-object path); wired into the harness's T9 arena. See `docs/openssl-provider-remediation-plan-2026-08-25.md` R0.4 for the full story, including a real `mk_arena()` ordering bug it exposed and fixed along the way. | live probes (T9) | ~~Medium~~ |
| WART-5 | **RESOLVED (R0.5, 2026-08-25 later same day; re-verified R21, 2026-08-26)** — was: the C++ engine rejects OpenSSL's SHA-1 OAEP defaults (`Invalid hashAlg/mgf combination for RSA-OAEP`, `SoftHSM_keygen.cpp:8056`) — plain `-pkeyopt rsa_padding_mode:oaep` against a token key fails until the caller pins `rsa_oaep_md`/`rsa_mgf1_md` (sha256 verified working). Deliberate FIPS posture, documented not fixed: `src/vendor/pkcs11-provider/README.md` has a working `-pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256` example matching harness T5. | live (T5's first run) | ~~Low~~ — |
| WART-6 | **RESOLVED-AS-DOCUMENTED (R19c, 2026-08-26)** — a real TLS 1.3 handshake with this provider active and propquery pinning the client leaves `asn1_check_tlen`/`PKCS8_PRIV_KEY_INFO` errors on the error queue even though the handshake succeeds. Confirmed benign: absent with the provider inactive (control run), present whenever active regardless of group; live-traced to a genuine RSA object create/free cycle through this provider's own keymgmt while processing the peer's plain RSA certificate — one of several normal trial-decode attempts OpenSSL's generic multi-format decoder-chain framework makes, not an over-claiming `does_selection`. Not fixed (nothing to fix); documented as an interop caveat: callers must check the operation's own return code, not merely whether the error queue is empty | live (T13/T19c reproduction + no-provider control) | Low (interop caveat) |

### B. Backend algorithms not exposed

| ID | Gap | Engine support | Provider state | Severity |
|---|---|---|---|---|
| ALG-1 | **RESOLVED (R1, 2026-08-25 later same day)** — was: SLH-DSA (all 12 sets), `sig/slhdsa.c` a `{0,NULL}` stub, registration branch unreachable. Now: real keymgmt+signature+encoders for all 12 parameter sets; keygen/store/text-and-SPKI-encode/**sign** all live-verified working, cryptographically correct (exact FIPS 205 sizes, independent software cross-verify, tamper rejection). The sign gap took two passes: registration alone worked immediately, but signing failed at OpenSSL's own fetch layer until a follow-up pass (prompted by checking the OpenSSL 3.6 documentation directly rather than continuing to guess) found the dispatch tables violated provider-signature(7)'s documented consistency contract — `GETTABLE_CTX_PARAMS` registered without its mandatory `GET_CTX_PARAMS` pair, so OpenSSL rejected the whole method at fetch time, before any provider code ran. See `docs/openssl-provider-remediation-plan-2026-08-25.md` R1 for the full trail. Two other, unrelated real bugs found and fixed along the way: `objects.c`'s and `store.c`'s key-type dispatch switches both lacked a `CKK_SLH_DSA` case. | both engines, 13 mechs each | ~~`sig/slhdsa.c` is a `{0,NULL}` stub AND the registration branch is unreachable (`CKM_SLH_DSA` absent from `checklist[]`/`PQC_MECHS`, `provider.c:859`); OpenSSL 3.6 has native names/OIDs to mirror~~ | ~~**High**~~ — |
| ALG-2 | XMSS/XMSS-MT | both engines (sign+verify, stateful) | `sig/xmss.c` stub, unreachable; no native OpenSSL names exist (custom names required; no CMS/TLS story) | Medium |
| ALG-3 | **RESOLVED (R9, 2026-08-26)** — was: nothing in provider; OpenSSL 3.6 native LMS is *verify-only* → token-sign/OpenSSL-verify is a uniquely coherent split, but blocked by ENV-1 (no `enable-lms` in staged build). Now: real `HSS` keymgmt + `sig/hss.c` (both plain SIGN/VERIFY and DIGEST_SIGN/VERIFY dispatch); ENV-1's oracle rebuild done as this item's own step 0; the token-sign/OpenSSL-verify split itself proven live via two new permanent test tools (`lms-xdr-verify`, `hss-pubkey-dump`) — a genuine engine-signed HSS signature verifies under OpenSSL 3.6.3's own independent native LMS implementation, sabotage-tested. Five sequential bugs found and fixed to reach a working sign/verify at all — see `docs/openssl-provider-remediation-plan-phase4-2026-08-26.md` R9 and this doc's own "Phase 4, R9" entry below for the full trail. **Update (R25, 2026-08-26):** the cross-engine default-parameter mismatch itself is resolved — both engines now standardize on the official `CKA_HSS_LEVELS`/`LMS_TYPE`/`LMOTS_TYPE` attrs (a real Rust spec bug fixed along the way: it stored the level count under `CKA_HSS_LMS_TYPE`, which per spec is the LMS *type*), and the provider reads the key's own real parameter set (`hss_sig_size()`, RFC 8554 formula) instead of assuming one — live-proven across two genuinely different parameter sets (1296 bytes/LMOTS-W8, 2352 bytes/LMOTS-W4), both cross-verified by OpenSSL's own independent native LMS implementation. See this doc's own "Phase 5, R25" entry below. The Rust-arm harness case itself (running the same sign/verify through `libsofthsmrustv3.so`) is still not wired up — that was never blocked on the mismatch alone and remains a separate follow-up. | both engines **sign+verify** | ~~nothing in provider; OpenSSL 3.6 native LMS is *verify-only* → token-sign/OpenSSL-verify is a uniquely coherent split, but blocked by ENV-1 (no `enable-lms` in staged build)~~ — | ~~Medium~~ — |
| ALG-4 | **RESOLVED (R7, 2026-08-26)** — was: provider `composite.c` registry had 3 of the 8 draft-lamps-pq-composite-sigs-19 §6 profiles; missing 5 included all four §10.4-recommended plus MLDSA65-ECDSA-P384-SHA512. Now: all 8 profiles registered and live-verified (real token sign+verify, both sabotage controls rejected, per profile — harness T21a-h). Landing them also fixed two pre-existing bugs in the original 3 (classical-hash-tracked-profile-name-not-classical-algorithm's-own-convention, affecting .45/.49) and an RSA-3072 signature-buffer sizing bug. | KMIP layer has all 8 §10.4 profiles | ~~provider `composite.c` registry has 3; missing 5 include **all four §10.4-recommended** (MLDSA44-Ed25519-SHA512, MLDSA44-ECDSA-P256-SHA256, MLDSA65-RSA3072-PSS-SHA512, MLDSA65-Ed25519-SHA512) + MLDSA65-ECDSA-P384-SHA512~~ — | ~~Medium–High~~ — |
| ALG-5 | **RESOLVED (R4, 2026-08-25)** — was: registration branch dead. Turned out to need five real fixes, not the originally-guessed "2-line checklist omission": (1) two fabricated fallback constants in `exchange.c` (`CKK_X25519`/`CKK_X448` do not exist in the PKCS#11 spec — real montgomery keys are `CKK_EC_MONTGOMERY`, distinguished by curve name/size, matching Edwards' own pattern; the fake values meant the key-type sniff could never match a real key) — fixed, key-exchange mechanism now correctly resolves from bit size. (2) Four missing-case bugs across `objects.c` (fetch, export, `get_ec_public_raw`'s peer-marshalling gate, and two import/store-dispatch switches) and `store.c` (naming) — the same missing-case class found twice in R1. (3) **The actual root cause of "genpkey succeeds but the token silently creates the wrong key type"**: the C++ engine's `generateED()` (shared by `CKM_EC_EDWARDS_KEY_PAIR_GEN` and `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` — the mechanism itself is never passed into that function) determines the resulting key's `CKK_*` type solely from an explicit `CKA_KEY_TYPE` on the public-key template, defaulting to `CKK_EC_EDWARDS` when absent — found live, not assumed: `genpkey` exited 0 and created two real objects, but reading the result back showed `CKK_EC_EDWARDS` (0x40), not `CKK_EC_MONTGOMERY` (0x41). EC/Edwards never needed to send this explicitly (the engine's default already matched them); montgomery does. Fixed by conditionally adding `CKA_KEY_TYPE` to the shared `p11prov_ec_gen`'s public-key template only for montgomery (zero diff for the already-working EC/Edwards paths). Curve-parameter DER bytes (`curve25519`/`curve448` PrintableStrings) verified two independent ways: direct DER-encoding computation and byte-for-byte match against the latchset sibling's own shipped constants. **Live-verified, both curves, both directions, token-to-token**: X25519 produces a byte-identical 32-byte shared secret; X448 a byte-identical 56-byte one. **A sixth, narrower, separate gap surfaced and was left open**: deriving against a genuinely foreign (default-provider-only) peer key with OpenSSL's peer validation enabled fails with `OSSL_PARAM_get_BN: param of incompatible type` — T8's identical shape works for regular EC but not montgomery; traced to OpenSSL's cross-provider `EVP_PKEY_public_check` falling into a legacy EC_KEY-control translation path that assumes Weierstrass X/Y BIGNUM coordinates montgomery keys don't have. The provider's own derive mechanism is unaffected and proven correct; this is a peer-validation-specific interaction, documented in `T16`'s comment rather than silently dropped. | both engines advertise `CKM_X25519`/`CKM_X448`; live probe + source (`exchange.c`, `objects.c`, `store.c`, `keymgmt.c`, `SoftHSM_keygen.cpp`) | ~~Medium~~ — |
| ALG-6 | **CLOSED, deliberately unexposed (R20, 2026-08-26)** — investigated: OpenSSL 3.6 does have a standard EC KEM fetch surface (`ec_kem.c`, RFC 9180 DHKEM), but this project's own engine-level "ECDH-as-KEM" capability is **raw ECDH**, not RFC 9180's HKDF-Extract-and-Expand construction — exposing it under OpenSSL's `EC` KEM name would silently produce non-DHKEM-compliant output for any caller expecting RFC 9180 semantics. No current consumer needs the generic KEM operation type for EC (the real hybrid-KEM combiner bypasses it entirely). Deliberately unexposed; closed without code. | both engines flag ENCAP/DECAP on `CKM_ECDH1_DERIVE` | ~~not exposed as an OSSL KEM~~ — | ~~Low~~ — |
| ALG-7 | **RESOLVED (R26, 2026-08-26)** — was: cipher table is AES-only. Now: `chacha.c` implements CKM_CHACHA20 (bare stream) and CKM_CHACHA20_POLY1305 (AEAD), reusing cipher.c's own generic newctx/freectx/update/final/skey_init entry points (had to become genuinely cross-family for this, not AES-private) plus new shared AEAD deferred-mechanism-parameter machinery (see the item's own narrative for why deferred). **A real prerequisite surfaced first and was fixed as part of this item**: neither `CKM_AES_CTR` (a genuine unfinished `/* TODO */` stub) nor `CKM_AES_GCM` (dead registration code, missing from the mechanism checklist that makes anything reachable) had ever actually worked through this provider's OP_CIPHER interface — both fixed, both live-proven byte-identical to software (CTR) or cross-implementation-tag-matched (GCM), same rigor as ChaCha20/ChaCha20-Poly1305 themselves. | both engines | ~~cipher table is AES-only~~ — | ~~Low~~ — |
| ALG-8 | **RESOLVED (R8 + R23, 2026-08-25/26)** — HMAC/CMAC/KMAC-128/256 all reach `EVP_MAC` (see OP-1). CMAC's own C++-only status confirmed accurate, not stale, before R23 scoped its own harness to the C++ arm only: `rust/src/crypto/handlers.rs`'s sign dispatch has no `CKM_AES_CMAC` case (the constant is used only inside its own SP800-108-PRF-selection code); KMAC-128/256 dispatch on both engines (`handlers.rs:1461/1468`). | both (CMAC C++-only, KMAC both) | see OP-1 | ~~Medium~~ — |
| — | FrodoKEM / Classic McEliece (Rust vendor mechs), BIP32, Keccak-256, split-key | Rust engine / KMIP | deliberately out of OpenSSL scope — recorded, not gapped | — |

### C. New 3.6 features unused

| ID | Gap | Evidence | Severity |
|---|---|---|---|
| F36-1 | **RESOLVED, both roles (R5 phase 1 + R12 client role, R15 server role, 2026-08-25/26)** — R28 correction (2026-08-26): this row previously said "server role (R15) remains unbuilt, tracked separately" — stale; R15 executed in phase 4 (see `objects.c`'s own R15-tagged peer-share-import code and harness **T15**: "TLS 1.3 handshake with a fully token-backed server: token-resident ML-DSA cert signs CertificateVerify AND token performs the ML-KEM encapsulation, both independently engine-log verified"). Was: `TLS-GROUP` capability registered zero PQC groups. Now: `MLKEM512`/`768`/`1024` registered as pure (non-hybrid) TLS 1.3 groups (`tls.c`), IANA code points and security-bits read live from the staged 3.6.3 build's own source (`0x0200`/`0x0201`/`0x0202`, 128/192/256 bits — not from memory). Two client-role prerequisites landed and live-verified: ML-KEM's `ENCODED_PUBLIC_KEY` get_params (TLS's key-share export mechanism) and relaxing its export function's class check so it works on the private object TLS actually holds post-keygen (was: strictly `CKO_PUBLIC_KEY`-only) — proven with a full simulated handshake sequence (export share from private → simulated server encapsulates → client decapsulates), byte-matched. A separate, real bug found and fixed along the way: `p11prov_common_gen_set_params`'s type switch had no case for `CKK_ML_KEM`/`CKK_SLH_DSA`, hit live by TLS's own ephemeral-keygen call path (which passes real params, unlike a bare `genpkey` CLI call). **A genuine, live TLS 1.3 handshake was run and the token demonstrably participated** — `s_client -groups MLKEM768 -propquery "?provider=pkcs11"` against a software `s_server`: `Negotiated TLS1.3 group: MLKEM768`, and the C++ engine's own log shows 6 real objects created (the ephemeral keypair) — not assumed, counted. **Both things that remained open after R5 phase 1 are now resolved by R12/R13 (2026-08-25), see the update log below for the full mechanism**: (1) full handshake completion — the `TLS13_KDF` blocker was root-caused to four layered, precisely-diagnosed bugs (not one) and fixed in both engines; a real TLS 1.3 handshake now completes end-to-end with `MLKEM768` and a genuine cipher suite negotiated; (2) the silent-software-fallback hazard is now caught mechanically — harness case T13 asserts token participation from the engine log and ships a negative-control twin proving the hazard is real, per R13. Server role (importing a peer's raw public share to encapsulate against) is DONE (R15, phase 4) — `objects.c`'s peer-share-import + `keymgmt.c`'s parameters-only-selection handling, live-proven by harness T15's fully token-backed server handshake. | `tls.c`, `kem/mlkem.c`, `kdf.c` (root-caused, unchanged), `SoftHSM_keygen.cpp`, `rust/src/ffi.rs`, `objects.c`, `keymgmt.c` (R15); harness T13, T15 | ~~**High**~~ ~~Medium~~ ~~Low~~ — |
| F36-2 | **RESOLVED (R9, 2026-08-26)** — was: LMS: OpenSSL 3.6's new verify-only LMS unused (see ALG-3, ENV-1). Now: OpenSSL's native LMS is exactly the independent verifier the ALG-3/R9 cross-implementation proof uses — see that entry. | ~~release notes + live build~~ — | ~~Medium~~ — |
| F36-3 | **RESOLVED (R24 probe + R23 consume-side, 2026-08-25/26)** — R28 correction (2026-08-26): this row previously called the `mac.c` INIT_SKEY gap "still-open... handed to R23" — stale; R23 executed and closed it (see OP-1's own row: "`OSSL_FUNC_MAC_INIT_SKEY` for all three [MAC families]... live-verified byte-identical to software, engine-log confirmed, sabotage-tested"), and harness **T26d** re-runs R24's own probe specifically to prove the previously-failing consume step now passes end to end. Was: provider has SKEYMGMT but the new `EVP_KDF_derive_SKEY`-style opaque-key flows are unprobed. Now: `EVP_SKEY_generate` (AES + GENERIC-SECRET) and HKDF's `derive_SKEY` → `EVP_MAC_init_SKEY` chain both exercised live via a new permanent probe tool (`skey-flow-probe.c`) — HKDF's derived key is cryptographically CORRECT and stays fully token-resident, cross-checked against independent pure-software HKDF+HMAC of the same known inputs (never exporting the intermediate DKM), and (since R23) the derived key can be CONSUMED natively too. Found and fixed a real bug along the way: `skeymgmt.c`'s four entry points (AES/GENERIC-SECRET generate/import) never called `p11prov_ctx_status()` before touching slots/sessions — every other operation type does, and it only failed (`CKR_GENERAL_ERROR`) when SKEYMGMT was the FIRST pkcs11 operation in a process, which nothing in this harness had ever done before this probe. TLS13-KDF's own `derive_SKEY` hit an unexplained mode-routing anomaly (reached the EXPAND_ONLY branch despite EXTRACT_ONLY being requested) — investigated, not root-caused, not pursued further within R24's own budget (HKDF's already-verified proof answers this item's core question; matches this project's own precedent for not forcing an inconclusive investigation, see ALG-6/R17 above); a bounded follow-up attempt is planned as phase-6 R31. PBKDF2 (R10) correctly still lacks `derive_SKEY` (negative control), confirming R10's own documented scoping stands unchanged. **R31 correction (2026-08-26): the "anomaly" was never a mode-routing bug — see phase-6 R31 below.** TLS 1.3's own Derive-Secret construction is itself built from HKDF-Expand-Label, so `EXTRACT_ONLY`'s correct implementation legitimately calls the same internal helper R24's trace saw; the real (and only) issue was the probe never supplying the `PREFIX`/`LABEL` params that call requires, which the provider correctly rejected. Fixed at the probe level; check 3 is now a full mode-verified derive → consume chain, not existence-only. | 3.6 CHANGES; harness T24b, T26d | ~~Low~~ ~~—~~ — (R31 correction: was never a real gap, see below) |
| F36-4 | *(positive baseline, not a gap)* CMS KEMRecipientInfo + `OSSL_PKEY_PARAM_CMS_RI_TYPE` already wired for ML-KEM (local commit `2cca4f0`) — must be regression-guarded by the new harness | `kem/mlkem.c:414-433` | — |
| F36-5 | **RESOLVED (R20, 2026-08-26)** — was: NIST security-category PKEY param (new 3.6) not exposed by provider keymgmt. Now: `OSSL_PKEY_PARAM_SECURITY_CATEGORY` added to ML-DSA/ML-KEM/SLH-DSA `get_params`/`gettable_params`, values per FIPS 203/204/205, live-verified across all 8 algorithm variants (new `dump_int_param` tool, harness T23/T23b/T23c), sabotage-tested. | ~~3.6 release notes~~ — | ~~Low~~ — |
| F36-6 | **`mu` RESOLVED via vendor stopgap (R34, phase 7, 2026-08-26); `deterministic` no gap; `message-encoding=0` correctly stays rejected** — was: `mu`/`message-encoding`/`deterministic` parity vs software unverified. `deterministic` verified genuinely functional (byte-identical signatures when set, varying when not, matching `CK_SIGN_ADDITIONAL_CONTEXT.hedgeVariant`) — no gap. `message-encoding=0` (arbitrary pre-encoded M') stays correctly rejected under plain `CKM_ML_DSA` — no well-defined shape exists to accept it there (the one standard mechanism family that DOES cover a well-shaped pre-hash case, `CKM_HASH_ML_DSA_<hash>` — 10 of its 11 codepoints, the "with hashing" variants both engines already implement correctly — was a real, previously-unflagged provider *routing* gap, now **RESOLVED, phase-7 R35**, see below; the 11th, bare generic `CKM_HASH_ML_DSA`, has a narrower, separate, lower-priority gap of its own, deferred, no confirmed consumer). Externally-supplied `mu` was originally called "not fixable... regardless of provider-side code" — wrong: confirmed against the *ratified* PKCS#11 v3.2 OASIS Standard no field exists *today*, but PKCS#11 v3.3 (OASIS TC tracking issue [oasis-tcs/pkcs11#58](https://github.com/oasis-tcs/pkcs11/issues/58)) will add it natively, it preserves pure-ML-DSA's own security assumptions (FIPS 204's own Sign_internal/Verify_internal + NIST's FAQ addendum — not a weakening), and a vendor-private stopgap is industry-precedented (Thales's own proprietary PKCS#11 extension for the related XMSS/LMS problem). **Now shipped**: `CKM_PQCTODAY_ML_DSA_MU`, both engines, tagged `PQCTODAY-VENDOR-EXT-MU` at every site for wholesale deletion once v3.3 ratifies. Live-verified, both arms: a signature produced via the vendor mechanism from independently-computed µ verifies against OpenSSL's completely independent native ML-DSA implementation checked against the original raw message — byte-equivalent to a direct pure signature. Full design + execution trail: `docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md`; narrative below. | source + EVP_SIGNATURE-ML-DSA(7); harness T28/T28b; `docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md` | ~~Low~~ — |

### Environment / infrastructure findings

| ID | Finding |
|---|---|
| ENV-1 | **RESOLVED (R9, 2026-08-26)** — was: staged OpenSSL 3.6.3 (`/usr/local/ssl` in `pqc-rust`) built **without** `enable-lms` — LMS test/remediation work needs a rebuilt oracle first. Now: rebuilt from a fresh, isolated clone of the same `openssl-3.6.3` tag with `enable-lms` added to the existing `Configure` line (kept isolated from the hub's own shared/WASM-configured `openssl-3.6.3-src` tree, whose Emscripten config a reused build directory would have destroyed) — validated in an isolated prefix first (`list -tls-groups -signature-algorithms -kem-algorithms` diffed against the pre-rebuild oracle showed only `LMS @ default` added, SONAME `libcrypto.so.3` unchanged), then installed over the shared location; full harness re-confirmed 55/55 immediately after, before any HSS code was written. |
| ENV-2 | **RESOLVED (R6 + R14, 2026-08-25/26)** — the pre-existing `softhsm2-util`/`C_GetSlotList` bug that blocked end-to-end verification is fixed; see the update log below for the full mechanism and sabotage-test result. Was: native Rust-engine arm structurally blocked, snapshot/restore wired only for WASM. Was: native Rust-engine arm structurally blocked, snapshot/restore wired only for WASM. Now: an opt-in, env-var-gated (`SOFTHSMRUST_STATE_FILE`) native persistence path added to `C_Initialize`/`C_Finalize` (`rust/src/ffi.rs`), reusing `state_snapshot.rs`'s existing `serialize_token_state`/`deserialize_token_state` verbatim (already unit-tested — `round_trip_restores_tokens_and_token_objects_only`, `truncated_snapshot_is_rejected_and_state_untouched`, both pass) and inheriting its `SHR3SNP2` refuse-don't-migrate policy unchanged. Byte-identical to today's in-memory-only behavior when the env var is unset (confirmed: the change is purely additive, gated, and does not touch any code path exercised when unset). **A separate, pre-existing bug was found and confirmed unrelated to this fix** (reproduced identically against the pre-R6 binary via `git stash`): `softhsm2-util --init-token` against the Rust engine fails with "Could not get the slot list" — traced to `C_GetSlotList`'s auto-advance-a-fresh-slot logic behaving inconsistently between the tool's two required calls (count-only, then buffered), confirmed live via a temporary debug trace (first call reports zero slots, second reports one). This blocks END-TO-END verification of R6 via the same tool T15b uses, but does not indicate the persistence code itself is wrong — not fixed here, given the risk of a blind fix to unfamiliar, pre-existing slot-management logic under time constraints. Provider+Rust coverage on the WASM static-link path (hub e2e) is unaffected either way. |
| ENV-3 | **RESOLVED (R0.3, 2026-08-25 later same day; re-verified R21, 2026-08-26)** — was: existing provider test assets are dead: `test_openssl_integration.sh` soft-fails every functional step and is referenced by nothing; `openssl_test.cnf` hardcodes another developer's absolute `.dylib` paths; the vendored meson test suite (30 tests) is dormant — no CMake/ctest/CI/gate wiring. Now: both dead files deleted (confirmed via `git log --diff-filter=D`; repo-wide grep found no remaining live reference); the vendored meson suite documented as intentionally unwired in `src/vendor/pkcs11-provider/README.md` rather than left silently dormant. |

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
| T15a/b | Rust arm | provider activates over `libsofthsmrustv3.so`; multi-process functional flow — 4 wholly separate process invocations round-trip a real ML-DSA-65 key through `SOFTHSMRUST_STATE_FILE` (init-token → genpkey → sign → pubout), software-verified | **PASS + PASS** (R6 + R14, 2026-08-25/26; sabotage-tested) |
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

**Further update (2026-08-26, phase-3 execution continued) — R14
(Rust `C_GetSlotList` root cause + fix), DONE, finishing R6/ENV-2:**
see ENV-2 above for the current-state summary. Full mechanism:

`softhsm2-util --init-token` failed against the Rust engine with
"Could not get the slot list." Root-caused precisely, then
sabotage-tested to confirm which of two candidate defects actually
mattered (the phase-3 plan flagged both as plausible without knowing
which):

1. **The confirmed, necessary fix**: `C_GetSlotList` conflated "token
   present" with "token initialized" — two genuinely distinct PKCS#11
   concepts (`CKF_TOKEN_PRESENT` lives on `CK_SLOT_INFO`,
   `CKF_TOKEN_INITIALIZED` on `CK_TOKEN_INFO` — separate flags, separate
   structs, confirmed against the canonical `pkcs11t.h`). The tool's own
   `findSlot()` (`src/bin/common/findslot.cpp`) queries the size with
   `CK_TRUE` and fills with `CK_FALSE` — the fill call never filtered in
   either version, so the conflated `CK_TRUE` size call alone
   under-reporting the always-present-but-uninitialized slot 0 (`engine
   seeds it at start via init_token_store()`) against the correct,
   larger `CK_FALSE` fill count triggered `CKR_BUFFER_TOO_SMALL` —
   exactly the tool's literal error text. Fixed to match the C++
   engine's own reference semantics (`SlotManager::getSlotList`,
   `src/lib/slot_mgr/SlotManager.cpp`), which filters on
   `isTokenPresent()`, never `isInitialized()`. Sabotage-tested in
   isolation: reverting only this fix reproduces the exact original
   failure; restoring it fixes it again.
2. **A second fix, kept but reported at its true confidence, not
   overclaimed**: the "always keep one spare uninitialized slot"
   auto-advance now mutates the store only on the size-query call, not
   the fill call too — matching the ratified OASIS PKCS#11 v3.2 spec's
   own §5.5.1 language ("the set of slots... is checked at the time
   that C_GetSlotList, for list length prediction (NULL pSlotList
   argument), is called") and the C++ engine's reference gating.
   Sabotage-tested independently: reverting only this one did **not**
   reproduce any failure — `TOKEN_STORE` persists across both calls
   within a process, so the previous code's redundant re-check on the
   fill call was, empirically, always idempotent in every scenario this
   session could construct. Kept as a genuine, spec-aligned hardening;
   documented plainly as not independently proven necessary, rather
   than folded silently into a single "found the bug" narrative.

A third, separate finding (not a bug — a discovered dependency): the
tool's own `--init-token` flow does an internal `C_Finalize`/
`C_Initialize` reload within the same process to re-discover the
newly-initialized token by serial+label. This requires
`SOFTHSMRUST_STATE_FILE` (R6's own opt-in native persistence, landed
2026-08-25) to be set for *that* invocation too, or the reload
legitimately loses the token it just created — the Rust engine is
deliberately in-memory-only by design, not a compliance gap.

**Compliance check performed on request**: the tool's use of
`C_GetSlotList`, `CK_TOKEN_INFO`, `C_InitToken`, `C_Finalize`, and
`C_Initialize` was verified against the canonical `pkcs11f.h`/
`pkcs11t.h` and the ratified OASIS PKCS#11 v3.2 spec text
(`pkcs11-spec-v3.2-os.pdf`) — none of these have changed shape or
semantics between PKCS#11 v2.x and v3.2; the tool's own
reload-then-rediscover design is not a version-compatibility gap.

Harness case T15b — previously the sole permanent `XFAIL` — is
rewritten as a real, sabotage-tested multi-process proof: four wholly
separate process invocations (`softhsm2-util --init-token` → `genpkey
ML-DSA-65` → `pkeyutl -sign` → `pkey -pubout`), bridged only by the
state file, no in-memory continuity between any of them, followed by a
software cross-verify of the signature against the exported public key
— the same proven cross-check pattern `mldsa_case` (T3a-c) already
uses, just split across process boundaries. Flipped `XFAIL → PASS`.
Both engines' full test suites remain green (C++ unaffected by this
item; Rust: 410/410, zero regressions from either `C_GetSlotList`
fix). **Harness: `PASS=27 FAIL=0 XFAIL=0 XPASS=0`** — zero remaining
known gaps in this harness for the first time in this remediation
effort's history.

**Further update (2026-08-26, phase-3 execution continued) — R15 (fully
token-backed TLS server role), DONE:** the phase-3 plan's own stated gate
(user decision 2026-08-25: token-resident ML-DSA certificate key AND
token-performed KEM encapsulation, not a minimal encap-only proof) is now
met end-to-end. No prior server-role code existed in this provider at all
before this item — everything below is genuinely new, not a fix to
something that previously half-worked. Six independent, root-caused bugs,
each found by re-instrumenting and re-testing after the previous fix
changed the failure symptom, matching this session's standing "confirm
before fixing" discipline:

1. **`gen_init` rejected the TLS server's actual selection value.**
   `p11prov_mlkem_gen_init_int` required `OSSL_KEYMGMT_SELECT_KEYPAIR`;
   live trace showed OpenSSL passes `selection=0x84`
   (`OSSL_KEYMGMT_SELECT_ALL`, i.e. domain+other-parameters-only) when
   building the server-side placeholder object for the peer's eventual
   public share. Widened the accepted-selection check to
   `OSSL_KEYMGMT_SELECT_ALL` and branched the mechanism assignment,
   modeled directly on the already-working `p11prov_ec_gen_init`.
2. **The generic keymgmt `SET_PARAMS`/`SETTABLE_PARAMS` functions were
   entirely absent** — the actual missing piece, confirmed by tracing the
   real call chain in the OpenSSL 3.6.3 source
   (`ssl/statem/extensions_srvr.c:tls_accept_ksgroup` →
   `ssl/t1_lib.c:tls13_set_encoded_pub_key` →
   `crypto/evp/p_lib.c:EVP_PKEY_set1_encoded_public_key` →
   `EVP_PKEY_set_octet_string_param(..., OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
   ...)`), not guessed from a hunch. TLS 1.3's server-side key_share
   processing installs the peer's public key into the placeholder object
   gen_init/gen already built via this generic dispatch pair — not via
   keymgmt IMPORT, which explicitly refuses to run on an already-non-empty
   object. Added `p11prov_mlkem_keymgmt_set_params_fn` +
   `..._settable_params_fn`, registered in all three ML-KEM param-set
   dispatch tables. **Noted, not chased**: no keymgmt in this whole
   provider appears to have registered `SET_PARAMS` before this — EC/ECDH's
   own server role likely has the identical latent gap. Flagged as a
   separate, out-of-scope finding rather than silently left undocumented.
3. **Two independent `CKA_PRIVATE` gaps**, both live-traced to the C++
   engine's own default (`CK_BBOOL getBooleanValue(CKA_PRIVATE, true)` —
   confirmed via direct grep across `SoftHSM_objects.cpp`): any
   object-creation template omitting an explicit `CKA_PRIVATE` entry
   silently becomes private, requiring a login the current session may
   never have established.
   - `objects.c`'s `p11prov_store_mlkem_public_key` (materializing the
     peer's public share onto a real token object) was missing it —
     fixed by adding an explicit `{ CKA_PRIVATE, &val_false, ... }` entry,
     modeled on the sibling `p11prov_store_mldsa_public_key`.
   - `kem/mlkem.c`'s `p11prov_kem_encapsulate`'s own output-secret
     template (`ts[3]`) was missing it too — a second, independent
     instance of the same class of bug, not a duplicate report — fixed by
     widening to `ts[4]` with the same explicit `CKA_PRIVATE = CK_FALSE`
     entry. Applied the identical fix to `p11prov_kem_decapsulate`'s
     matching template for consistency, but that half was **not**
     independently sabotage-tested — reported at that true confidence
     level, not folded into the encapsulate finding's stronger proof.
   - **A red herring along the way**: the first "User is not authorized"
     observed while chasing this traced, on exhaustive instrumentation, to
     an unrelated cause — the test setup's own plain-software RSA
     certificate key being routed through the provider (global
     `propquery=pkcs11`) for an operation that had nothing to do with
     ML-KEM. Not a bug; a test-design issue, resolved by switching to the
     properly-scoped token-resident-certificate setup R15's own gate
     requires anyway.
4. **`p11prov_kem_encapsulate` looked up its session before the key was
   materialized onto a real slot.** A freshly built mock/placeholder
   object (from fix #1/#2's path) has `slotid ==
   CK_UNAVAILABLE_INFORMATION` until `p11prov_obj_get_handle` triggers its
   lazy on-token materialization — but the session lookup
   (`p11prov_try_session_ref`) read the object's slotid to validate the
   mechanism against that slot, and `CK_UNAVAILABLE_INFORMATION` never
   matches a real slot, silently failing `CKR_MECHANISM_INVALID` before
   materialization ever ran. Fixed by moving the `get_handle` call before
   the session lookup — every existing decapsulate-exercising test never
   hit this because its key was always already materialized (a real token
   object from keygen), never a fresh mock.
5. **The encapsulate size-query branch never reported the shared-secret
   length.** `EVP_PKEY_encapsulate`'s query call
   (`ssl/s3_lib.c:ssl_encapsulate`) checks `pmslen == 0` as a hard failure;
   the size-query path set `*outlen` (ciphertext size) but left
   `*secretlen` untouched at the caller's zero default. Live-traced: the
   PKCS#11 call itself succeeded (`ctlen=1088, CKR_OK`) and this was still
   why the handshake failed. Fixed by setting `*secretlen = 32` — FIPS
   203's fixed ML-KEM shared-secret size for all three parameter sets.
6. **The digest `dupctx` fallback silently emptied the running TLS
   transcript hash after its first use.** Found only after fixes #1–#5
   got the handshake past a successful encapsulate to a new failure,
   `ssl_handshake_hash: internal error` (`ssl/ssl_lib.c`, the
   `EVP_MD_CTX_copy_ex`/`EVP_DigestFinal_ex` branch specifically — pinned
   by exact line number against the real `openssl-3.5.6` and `3.6.3`
   sources, not inferred). Root cause, confirmed via
   `PKCS11_PROVIDER_DEBUG` trace: SoftHSM correctly returns
   `CKR_STATE_UNSAVEABLE` (84) from `C_GetOperationState` for an in-flight
   digest session (most tokens can't export mid-stream digest state — the
   vendored `digests.c`'s own comment already anticipated this). The
   existing fallback on that failure *moved* the live session to the
   duplicate and left the original with none — correct for a duplicate
   that's used once and discarded, but TLS 1.3 duplicates the SAME running
   transcript-hash context twice (once for CertificateVerify, again for
   Finished): the second duplication found an already-empty original and
   `C_DigestFinal` failed with `CKR_SESSION_HANDLE_INVALID` (179) — traced
   to that exact PKCS#11 return code, not guessed. This is a pre-existing
   gap in the vendored `pkcs11-provider` itself, exposed for the first
   time by R15 because no earlier scenario duplicated a token-backed
   running digest more than once. Fixed by adding a software shadow buffer
   of everything fed to `update()`, consulted only by `dupctx()`'s
   fallback: when `GetOperationState` fails, replay the shadow into a
   freshly opened session for the *copy*, leaving the original session
   and context completely untouched. This is the one fix in this list
   that was independently **sabotage-tested**: reverting only this change
   (`git stash` on `digests.c` alone, everything else in place) reproduces
   T15's exact original failure and only T15 fails — 27 other harness
   cases, including T13 (which also exercises `dupctx` but never
   duplicates the same live context twice), stay green; restoring it makes
   T15 pass again.

**A second false-pass hazard, distinct from R13's original finding**: the
very first end-to-end handshake attempt against a completely fresh test
arena succeeded cleanly with zero errors — but with **zero** token KEM
activity, because nothing forced the server's ephemeral ML-KEM
group-keygen/encapsulate through the token; OpenSSL's own `default`
provider implements ML-KEM natively (`openssl list -kem-algorithms
-provider default` lists `MLKEM768` and friends) and silently won that
selection with no `-propquery` pinning it. The certificate's own
`pkcs11:`-URI-identified ML-DSA key forces signing onto the token
regardless of propquery, so a green handshake with a valid signature is
*not* sufficient evidence the KEM half is token-backed either — exactly
the class of false pass R13 exists to prevent, now confirmed live a
second time in a scenario R13's own T13 case doesn't cover. T15 pins
`-propquery "?provider=pkcs11"` on the server and ships the same
negative-control-twin discipline. One adaptation was needed: T13's plain
`"Decrypting N bytes"` regex isn't precise enough here, because the same
generic log line *also* fires (in both the positive and negative arms)
for the certificate's own ML-DSA private key being unwrapped from at-rest
storage to sign with — a propquery-independent operation. Checked live
against both arms' full decrypt-size histograms: `"Decrypting 64 bytes
into buffer of 80 bytes"` is the one pattern that appears only when the
KEM-derived secret itself is a token object (74 occurrences pinned, 0
unpinned) — that exact string is T15's marker instead.

**Result**: `s_server`/`s_client` with a token-resident ML-DSA-65
certificate and `-groups MLKEM768 -propquery "?provider=pkcs11"` on the
server now completes a full TLS 1.3 handshake —
`Negotiated TLS1.3 group: MLKEM768`, `Peer signature type: mldsa65`,
`New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384`, `Verify return code: 0
(ok)` — with the CertificateVerify signature and the KEM encapsulation
both independently engine-log verified, matching the plan's own stated
proof requirement verbatim. All temporary diagnostic instrumentation
(`R15TRACE-*` and friends) was stripped before this was considered done.
Both engines' full test suites remain green (C++: 8/8 CTest suites; Rust:
410/410 unit tests, zero regressions from the `digests.c` change).
**Harness: `PASS=28 FAIL=0 XFAIL=0 XPASS=0`** — one case gained (T15),
zero regressions, zero remaining known gaps.

**Further update (2026-08-26, phase-3 execution continued) — R16
(encoder-parity tier), DONE:** both leftovers from R3/R4 closed. Same
"live-instrumentation-before-declaring-done" discipline as every other
item in this phase surfaced a genuine correction to the plan's own
premise for the first item below — reported honestly rather than
folded silently into a "both closed" narrative.

1. **ML-KEM SPKI + text encoders.** The plan described both as missing;
   only the **text** encoder actually was. Checked live before writing
   any code (the same discipline this session has used throughout):
   `pkey -pubout` on a token ML-KEM key already produced a correct,
   standards-shaped SubjectPublicKeyInfo PEM *before* any of this
   item's code existed — some pre-existing, provider-agnostic path
   (most plausibly OpenSSL's own generic `OSSL_ENCODER` SPKI builder,
   driven off the keymgmt's `OSSL_PKEY_PARAM_PUB_KEY` export and the
   NID the *default* provider already registers for the standardized
   ML-KEM OIDs) already covered it — confirmed by fully reverting this
   item's `encoder.c`/`encoder.h`/`provider.c` changes in a working
   copy and re-running `pkey -pubout`: still exit 0, still a valid SPKI
   PEM. `-text`, in the same revert, failed outright (exit 1, no
   output) — that half was the one genuine gap. Added both anyway,
   modeled directly on ML-DSA's own SPKI-DER + text encoder pair (same
   `X509_PUBKEY`-construction helper shape, same NID switch on
   `CKA_PARAMETER_SET`) — the SPKI encoder is kept as parity/hardening
   with the rest of this provider's key types, consistent with how
   every other asymmetric type here has one, but is reported at its
   true confidence: not independently proven necessary, since the
   pre-existing generic path already covers the case this harness
   exercises. Sabotage-tested each half separately: breaking only the
   text encoder's type check reproduces the exact `-text` failure and
   only `T4x_spki` fails; restoring it fixes it again (the SPKI half
   was not separately sabotage-tested, for the reason just given — a
   broken SPKI encoder wouldn't currently be observable through this
   harness's own assertions since the generic path would still answer).
   New case **T4x_spki**: `-pubout` SPKI PEM round-trips through the
   pure software provider (`OPENSSL_CONF=/dev/null`, no pkcs11 active
   at all — proving the DER structure is standards-correct, not merely
   readable by this provider's own decoder), plus `-text` renders both
   the private-key placeholder line and, on a public-key object, the
   decoded key bytes.
2. **X25519/X448 URI-PEM private-key encoders.** Genuinely missing, as
   the plan stated: `genpkey -out` for a montgomery token key
   previously reported `Error writing key(s)` (the key generated and
   persisted on-token fine as a side effect, but the write-to-file step
   had nothing registered to call) — the same gap class ML-KEM had
   before R3. Added `p11prov_montgomery_encoder_priv_key_info_pem_functions`,
   modeled directly on Ed25519/Ed448's own `ec_edwards` encoder (a
   distinct PKCS#11 key type, `CKK_EC_MONTGOMERY` vs `CKK_EC_EDWARDS`,
   sharing the same generic `p11prov_encoder_private_key_write_pem`
   helper everything else in this file uses — PEM-wraps a `pkcs11:` URI,
   never touches the private key bytes). **T16/T16b re-gated on the
   `genpkey` exit code** and now assert the URI label + absence of any
   `PRIVATE KEY` block, exactly like `T4x_encode`, replacing the
   previous exit-code-suppressed workaround. Sabotage-tested: reverting
   the key-type constant to `CKK_EC_EDWARDS` in a working copy makes
   both T16 and T16b fail on their new `genpkey` gate (they share one
   encoder function) while T4x_spki and T7 (Ed25519, the *other*
   encoder) stay green; restoring it fixes both again.

Both engines' full test suites remain green (C++: 8/8 CTest suites;
Rust: unaffected by this item — pkcs11-provider changes are C-side
only, backend-agnostic to which engine sits underneath). **Harness:
`PASS=29 FAIL=0 XFAIL=0 XPASS=0`** — one case gained (T4x_spki), zero
regressions, zero remaining known gaps.

**Further update (2026-08-26, phase-3 execution continued) — R17
(montgomery software-peer interop), INVESTIGATED, no code change
needed:** the plan's own investigate-first framing turned out to be
exactly the right call — the described gap does not reproduce.

The plan recorded a real, specific failure: a token X25519/X448 key
deriving against a genuinely foreign (default-provider-only, no
`pkcs11:` URI) software peer key, via `OSSL_PARAM_get_BN "param of
incompatible type"` from a legacy `EC_KEY`-control translation path
that assumes Weierstrass X/Y `BIGNUM` coordinates montgomery keys
don't have. Reproduced the exact shape the plan describes — before
writing any fix — at two separate points to rule out this session's
own R16 work being an accidental cause: the current tree (R16's
montgomery URI-PEM encoder in place) and a working copy fully reverted
to the R15-only baseline (R16's encoder code completely absent, tested
by temporarily discarding `encoder.c`/`encoder.h`/`provider.c` and
rebuilding). **Both derive cleanly in both directions, both curves**:
token-private-key-derives-against-software-peer and the reverse
pairing (software-private-key-derives-against-token peer), X25519
(32-byte secret) and X448 (56-byte secret), secrets equal across the
pairing in every case. Since it doesn't reproduce even without R16's
changes, R16 isn't what closed it; most plausibly R4 (this provider's
original X25519/X448 keyexch work, landed in phase 2, before this
session) already fixed it as a side effect of its own implementation,
and the phase-3 plan's written finding — carried forward from an
earlier observation — simply predates that landing without being
re-verified against the final, landed R4 code. Not a case of "looked
but couldn't find it": the exact reproduction shape from the plan was
run, twice, at two different points in this session's own history, and
came back clean both times.

No product code was touched for this item. Two new harness cases,
**T17** and **T17b**, exist so this is a permanent, checked assertion
rather than a one-off CLI transcript that could silently bit-rot:
token key generated via the provider, independent software key
generated via the plain default provider, `pkeyutl -derive` run in
both directions, non-empty-and-correct-size guard on both outputs (the
same lesson phase 2 already learned the hard way), `cmp` for equality.
Harness: **`PASS=31 FAIL=0 XFAIL=0 XPASS=0`** — two cases gained
(T17, T17b), zero regressions. **This closes the entire R12→R17
phase-3 remediation plan — zero remaining known gaps of any kind in
this harness.**

**Phase 4, R18 (EC/ECDH/montgomery generic `SET_PARAMS` — the
latent server-role gap R15 flagged), DONE:** the investigation R15
flagged — "no keymgmt but ML-KEM's own three tables had `SET_PARAMS`
before this; EC/ECDH's own server role likely has the identical
latent gap" — turned out to be wrong in its specifics but right in
its instinct. EC (Weierstrass) already had a real, working
`SET_PARAMS`/`SETTABLE_PARAMS` pair (`p11prov_ec_set_params`,
confirmed live: `prime256v1` server-role and client-role both
handshake cleanly with zero changes). Ed25519/Ed448 have their own
(no-op, by design — EdDSA keys are never used for key exchange, so
TLS never asks them to install a peer share). **Only X25519/X448 had
the gap** — and reproducing it surfaced four independent, layered
bugs, three of them different from what R15's own SET_PARAMS
hypothesis anticipated, each found only after the previous fix
changed the failure symptom (the by-now-familiar pattern from every
item in this plan):

1. **`p11prov_montgomery_gen_init_int` had no `else` branch** setting
   the `CK_UNAVAILABLE_INFORMATION` sentinel for a domain/other-
   parameters-only selection (TLS's server-side placeholder pattern,
   `selection=0x84`, live-confirmed — the same selection R15 found
   for ML-KEM's server role). Unlike `p11prov_ec_gen_init`'s own else
   branch, this one was simply missing; the struct's zero-initialized
   mechanism (`0x0`) leaked through, `p11prov_ec_gen`'s mock-object
   check (which compares against the real sentinel, not `0`) never
   matched, and the real-keygen path ran with mechanism `0` against a
   montgomery-shaped template — the engine correctly rejected it as
   "conflicting attributes" (`keymgmt.c:1388`, live-traced exact file:
   line before any fix). Fixed by adding the else branch, matching
   EC's own pattern exactly.
2. **`p11prov_montgomery_get_params`/`gettable_params` never exposed
   `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY`** — the param TLS reads via
   `EVP_PKEY_get1_encoded_public_key` to hand a locally-generated
   key's own public half back for the key_share extension (server's
   *own* response, or the client's *own* ClientHello share — needed
   by both roles, confirmed by sabotage: reverting only this fix
   breaks all four new harness cases, not just one role's). Only
   `OSSL_PKEY_PARAM_PUB_KEY` was handled; TLS asks for a differently-
   named param. Live-traced: `tls_construct_stoc_key_share` (or the
   client-side equivalent) failed parsing uninitialized `OSSL_PARAM`
   data as ASN.1 DER (`"header too long"`/`"bad object header"`).
   Fixed by adding the same branch as the existing `PUB_KEY` one — for
   montgomery keys the encoded form *is* the raw public key, byte for
   byte, no point-compression step, so the same accessor
   (`p11prov_obj_get_ed_pub_key`) serves both params unchanged.
3. **Montgomery's keymgmt registered no `SET_PARAMS`/`SETTABLE_PARAMS`
   at all** — the gap this item was actually scoped to check, and the
   only one of the four that matches R15's original hypothesis.
   A pre-existing comment in this file explicitly said as much and
   reasoned it wasn't worth adding ("ML-DSA's keymgmt tables omit them
   too and Ed's own versions are no-op stubs, so there is nothing
   worth reusing or stubbing") — reasoning that held for those two
   cases but missed that EC's own `set_params` is real, working code
   directly reusable here. First attempt: register EC's functions
   directly in both montgomery dispatch tables (same translation
   unit, same generic-enough signature). This alone fixed the
   server-role scenario completely — but not the client-role one (see
   fix 4).
4. **A fourth bug, found only via the harness's own client-role test
   case, not the manual server-role reproduction that had already
   confirmed fixes 1–3 sufficient**: a token-backed *client* installs
   the server's peer share through a genuinely different construction
   route than the server-role placeholder ever touches — a bare
   keymgmt `NEW()` object straight into `SET_PARAMS`, no
   `gen_init`/`gen` in between at all. Live-traced:
   `key->data.key.type == 0` (never set — numerically collides with
   `CKK_RSA`, confirmed against `pkcs11t.h` before relying on it) and
   `key->class == CK_UNAVAILABLE_INFORMATION`. Weierstrass EC never
   reaches `p11prov_obj_set_ec_encoded_public_key` in this bare-object
   shape at all — a legacy, non-provider-native `EC_KEY` fallback path
   in OpenSSL almost certainly handles peer-key installation for it
   instead (not confirmed by reading that path directly, but the only
   explanation consistent with every other piece of live evidence:
   EC's own `set_params` code, which has no type-establishment logic
   of any kind, cannot otherwise explain EC working here while
   montgomery — running the identical function — did not). Fixed with
   a small montgomery-specific `set_params` wrapper
   (`p11prov_montgomery_set_params`) and a new shared helper,
   `p11prov_obj_ensure_ec_type` (gates on `class`, not `type`,
   specifically to sidestep the `CKK_RSA`-is-`0` ambiguity), that
   establishes the object's type/class before falling through to the
   same install logic EC's function already uses — replacing the
   direct-reuse-of-EC's-functions from fix 3 rather than adding a
   second registration.

**Also flagged, not chased**: `p11prov_obj_set_ec_encoded_public_key`'s
own type switch also lacked a `CKK_EC_MONTGOMERY` case (a fifth,
trivially small fix, same commit) — a second independent instance of
the "missing-case-in-a-switch" bug class this provider has now hit
several times across different phases (R1, R4, and now R18).

Four new harness cases, matching R15's own client/T15-vs-T13-style
split exactly, because sabotage-testing showed the split is not
cosmetic: **T18/T18b** (client token-backed, server plain software —
T13's shape) catch fixes 2 and 4; **T18c/T18d** (server token-backed,
client plain software — T15's shape) catch fixes 1 and 2. Reverting
fix 1 alone leaves T18/T18b green and only breaks T18c/T18d;
reverting fix 4 alone leaves T18c/T18d green and only breaks
T18/T18b — each of the four fixes independently sabotage-tested and
confirmed caught by exactly the case(s) that should catch it, none
by the others. Both server-role and client-role scenarios manually
verified working end-to-end with the final build (`Cipher is
TLS_AES_256_GCM_SHA384`, clean shutdown) in addition to the permanent
harness proof.

Both engines' full test suites remain green (C++: 8/8 CTest suites;
Rust: unaffected — this item's changes are C-provider-side only).
**Harness: `PASS=35 FAIL=0 XFAIL=0 XPASS=0`** — four cases gained
(T18, T18b, T18c, T18d), zero regressions.

**Phase 4, R19 (proof-debt closure), DONE — no code changes,
documentation only:** all three sub-items closed with definitive
answers rather than fixes; each investigated live, not assumed.

**R19a — decapsulate's `CKA_PRIVATE` fix, independent proof.**
Structurally unreachable through this provider, not merely
unobserved. `p11prov_kem_decapsulate` always operates on the
*private* key first (`kemctx->key` — the opposite of encapsulate's
*public* peer key), and PKCS#11's own object model requires a
logged-in session to obtain a handle to any `CKA_PRIVATE=true`
object, independent of any provider config — confirmed by reading
`PUBKEY_LOGIN_AUTO`/`PUBKEY_LOGIN_ALWAYS` (`session.c`), which govern
only whether *public*-key access also triggers a login (the exact
knob R15's encapsulate scenario needed relaxed — a public peer key
needs no login by default, so the output secret's own missing
`CKA_PRIVATE` created a real auth gap there). No equivalent knob
relaxes the requirement for *private* keys — there structurally isn't
one to relax. By the time `p11prov_kem_decapsulate` successfully
obtains `hKey` for the private key, the session is necessarily
already logged in, so the output secret's own missing `CKA_PRIVATE`
template entry can never independently cause an authorization
failure. Confirmed further: ML-KEM's own keymgmt exposes no settable
param that could force a private key to `CKA_PRIVATE=false` at
creation (only `P11PROV_PARAM_URI`/`P11PROV_PARAM_KEY_USAGE` are
settable), so even a deliberately-adversarial test setup has no way
to construct the scenario through this provider's own tooling. The
fix is kept (it is still spec-correct and harmless), but is now
documented as unobservable-and-explained rather than merely
unproven.

**R19b — is the ML-KEM SPKI encoder ever load-bearing?** Checked
against the one condition that could make it so: public-key export
disallowed via `pkcs11-module-allow-export` (`DISALLOW_EXPORT_PUBLIC`,
checked live at `montgomery_export`'s own gate and, by the same
pattern, ML-KEM's). Result: `pkey -pubout` fails **entirely** under
that config — exit 1, empty output file, no error queue entry at all
— meaning the export-blocking check intercepts before any encoder
(generic or this provider's own) is ever reached. Combined with the
earlier finding (the default-config case: `-pubout` already succeeds
via a pre-existing generic path with zero code from this item), both
of the two configurations this provider supports were checked and
neither exercises the new SPKI encoder as the sole path to an
answer. The encoder remains genuinely inert in this provider's
current design — real, correct, round-trip-tested code kept for
parity with every other asymmetric type here, but with no live
scenario in which it is load-bearing. Reported at exactly that
confidence; not a reason to remove it (parity has its own value, and
a future OpenSSL/decoder-framework change could make the generic path
stop covering this case without warning).

**R19c — the residual `asn1_check_tlen`/`PKCS8_PRIV_KEY_INFO` noise.**
Confirmed benign OpenSSL decoder-framework probe noise, not a defect
in any of this provider's own `does_selection` functions. Reproduced
live (T13's own exact shape) and isolated with a control run: the
noise is **absent** when this provider is inactive (`OPENSSL_CONF=
/dev/null` on both ends) and **present** whenever it's active with
propquery pinning the client to it, regardless of which specific
group is negotiated. `PKCS11_PROVIDER_DEBUG` tracing around the exact
moment the error appears shows a real, successful RSA object
create/free cycle through this provider's own keymgmt
(`p11prov_rsa_free`, `keymgmt.c:737`) immediately adjacent to the
error — the peer's plain RSA certificate genuinely gets processed
through this provider (an expected consequence of propquery pinning
essentially all operations to it, not a bug), and the ASN.1 error is
one of several normal trial-decode attempts OpenSSL's own generic
multi-format decoder-chain framework makes while determining which
concrete format a given blob of key material is in — a well-
documented, expected pattern (`man OSSL_DECODER_CTX`: a decoder chain
tries each compatible decoder in turn; failed trials populate the
error queue even though the overall operation succeeds). Not a
provider-side bug to fix; documented as an interop caveat instead
(new `WART-6`, §4.A): callers that treat a non-empty OpenSSL error
queue as a hard failure signal, rather than checking the actual
return code of the operation they care about, will misdiagnose a
successful handshake as broken when this provider is active with a
broad propquery.

No harness changes for R19 (nothing to sabotage-test — no code
changed). Both engines' suites unaffected (no code touched).
**Harness: `PASS=35 FAIL=0 XFAIL=0 XPASS=0`**, unchanged from R18.

**Phase 4, R21.1 (composite.c stray debug output), DONE:** the 33
committed `fprintf(stderr, "[composite-...]")` lines found while
drafting the phase-4 plan — present on both `main` and this feature
branch, predating phase 3 entirely — converted to `P11PROV_debug`,
this provider's own gated debug macro (silent unless
`PKCS11_PROVIDER_DEBUG` is set), matching every other diagnostic
message in this codebase. Purely mechanical: same messages, same
format arguments, no logic touched. Landed deliberately before R7
(composite profiles 4–8) so that item's own diff stays legible rather
than drowning in an unrelated cleanup. `ERR_print_errors_fp(stderr)`
calls on genuine failure paths were left alone — those are real
diagnostic output on an actual error, not debug narration, and
outside this item's scope. Clean rebuild, no format-string warnings.
No harness case exists for composite signatures yet (that is R7's own
scope) so this was verified by clean compile plus the full existing
suite (a flaky, unrelated `p11test` X448-derive failure appeared once
and did not reproduce on retry — confirmed pre-existing test flake
under this session's heavy concurrent container load, not a
regression from this change). **Harness: `PASS=35 FAIL=0 XFAIL=0
XPASS=0`**, unchanged. C++: 8/8 CTest suites on retry. Rust
unaffected (C-provider-side only).

**Phase 4, R8 (`OSSL_OP_MAC`: token HMAC, bytes-in mode), DONE:** a
genuinely new operation type for this provider — `OSSL_OP_MAC` had no
`op_mac` arm in `p11prov_query_operation` at all before this, so every
`EVP_MAC` fetch fell through to the default provider unconditionally.
Bytes-in mode only, no `SKEYMGMT` dependency, exactly as scoped —
`OSSL_MAC_PARAM_KEY` arrives as raw bytes, becomes an ephemeral
session secret key object (new `p11prov_create_mac_key`, objects.c —
written as a new function rather than parameterizing the existing
`p11prov_create_secret_key`, which has exactly one caller (`kdf.c`)
and hardcodes `CKA_DERIVE`, not the `CKA_SIGN` capability HMAC needs),
then `C_SignInit`/`C_SignUpdate`/`C_SignFinal` with the matching
`CKM_SHA*_HMAC` mechanism compute the MAC on-token. New `mac.c`/
`mac.h`, wired into `provider.c`'s checklist-driven mechanism
discovery and `CMakeLists.txt`.

**A real design correction, caught live before it shipped wrong:**
the first implementation registered one pre-bound algorithm name per
digest (`HMAC-SHA2-256`, `HMAC-SHA2-384`, ...), modeled directly on
`digests.c`'s own per-variant `DISPATCH` pattern — a legitimate,
correctly-named algorithm identity per NIST convention, but not what
the plan's own proof command (`openssl mac -propquery
"?provider=pkcs11" ...`) actually resolves to. OpenSSL's own default
provider registers a *single* generic `"HMAC"` name and takes the
digest as a runtime parameter (`OSSL_MAC_PARAM_DIGEST`, the same one
`openssl mac -digest SHA256 HMAC` sets) — confirmed live via `openssl
list -mac-algorithms -provider default` before assuming, not after
guessing. Under the per-digest design, `mac HMAC -digest SHA256`
silently resolved to `HMAC @ default` even with propquery pinned,
because nothing pkcs11-registered was named bare `"HMAC"` — and the
output was still byte-identical to the correct answer, because HMAC
is deterministic, so a wrong-provider silent fallback here produces
*no observable symptom in the value at all*. Only checking the engine
log (zero token activity) caught it — the exact same class of false
pass R13 exists to prevent, now confirmed live for the first
genuinely new operation type added since R13 was written, not just
carried forward by analogy. Rewritten to match: one `"HMAC"`
algorithm, digest selected dynamically via `mac_set_digest`
(`p11prov_digest_get_by_name` -> a small `CKM_SHA*` -> `CKM_SHA*_HMAC`
mapping table), key and digest choice both deferred and cached until
the first real operation (`C_SignInit` lazily invoked from
`update()`/`final()`, since neither the key nor the digest choice is
guaranteed to have arrived by the time `init()` returns — OpenSSL's
own `mac` app and `EVP_MAC_init` can supply either via `init()`'s own
arguments or a later `set_ctx_params()` call, and this provider does
not get to assume which).

**Minimum key sizes are a real, deliberate engine constraint, not a
provider bug** — surfaced while building the harness case, chased
down before being dismissed: `SoftHSM_slots.cpp` declares
`ulMinKeySize` per HMAC mechanism equal to that digest's own output
length (20/32/48/64 bytes for SHA-1/256/384/512), matching FIPS
198-1's own key-length guidance. A too-short test key produces a
genuine, correct `CKR_KEY_SIZE_RANGE` rejection from the engine, not
a provider defect; the harness case's key is sized to satisfy all
four digests' minimums at once.

Four new harness cases (T20/T20b/T20c/T20d, one per digest), each
proving token computation via engine-log evidence (`"Created new
object"` — the ephemeral session key, the same class of proof T13/T15
established) rather than output equality, with an R13 negative-
control twin. Each needed its **own** dedicated arena, not the shared
`mk_arena` helper — `mk_arena` hardcodes `log.level = ERROR`, which
silently suppresses exactly the debug-level log line this proof
depends on; T13/T15/T18's own comments already documented this
precise trap, and it was hit again live here before being caught,
underscoring why those comments exist rather than being redundant
with this entry. Sabotage-tested independently: reverting the
SHA2-256 mechanism mapping alone breaks only T20b, the other three
digests stay green; reverting the ephemeral key's `CKA_PRIVATE`
attribute alone (the same class of bug R15 first found, confirmed to
recur in genuinely new code, not copy-pasted from a fixed instance)
breaks all four T20 cases uniformly, since they share the same
key-creation helper.

Both engines' full test suites remain green (C++: 8/8 CTest suites;
Rust unaffected, confirmed — this item's changes are C-provider-side
only). **Harness: `PASS=39 FAIL=0 XFAIL=0 XPASS=0`** — four cases
gained (T20/T20b/T20c/T20d), zero regressions.

**Deferred, not started**: `EVP_MAC_init_SKEY` opaque-token-key mode
(a separate, later step per the plan's own C5 scoping — bytes-in mode
is complete in itself); AES-CMAC and KMAC128/256 (both mechanisms
this provider's engines already advertise per `SoftHSM_slots.cpp`,
same `mac.c` shape should extend cleanly, not attempted in this pass
to keep this item's own diff and proof scoped to what was actually
built and verified).

**Phase 4, R7 (composite signature profiles 4–8), DONE:** `composite.c`
registered exactly 3 of the 8 draft-lamps-pq-composite-sigs-19 §6
profiles (.37/.45/.49) before this item. Added the five missing
(.39/.40/.41/.46/.48 — corrected from the phase-4 plan's own guessed
OID digits, verified against `kmip/src/kmip30/algos.rs` and the draft
itself), plus fixed three real bugs the new profiles' verification
work exposed in the existing code along the way.

**Bug 1 (pre-existing, .45/.49): classical hash tracked the profile
NAME's hash instead of the classical algorithm's own conventional
hash.** `composite.c` hardcoded `CKM_ECDSA_SHA512` for every ECDSA
profile, reading the "SHA512" in "MLDSA65-ECDSA-P256-SHA512" as the
classical signing hash — it is actually the M' pre-hash (draft-19 §2.2:
`M' = Prefix||Label||len(ctx)||ctx||PH(M)`); the classical half signs
M' using its own standard hash-then-sign convention, which for ECDSA
tracks the curve (P-256 → SHA-256, P-384 → SHA-384), not the pre-hash.
This is the SAME bug class the Rust KMIP engine's `composite_sig.rs`
already found and fixed on 2026-08-17 in its own independent
implementation of the same draft (its own comments there call out the
exact mechanism: "Corrected 2026-08-17: was CKM_ECDSA_SHA512, which
produced signatures that verified only against implementations sharing
the same misreading") — this provider never got the equivalent fix,
because no harness case existed for composite signatures at all until
this item. Caught not by inspection but by the plan's own prescribed
gate: independently reconstructing draft-19's M' in Python and
verifying the external `raw_signature_vectors` KAT (4 vectors covering
.40/.45/.46/.49) — three of four initially failed to verify under
SHA-512, and DID verify under the curve-conventional hash, with a
negative control confirming they fail again under any other hash.
Fixed by adding an explicit `classical_type`/`classical_mechanism`
field pair to `struct p11prov_composite_profile` (see bug 3) and
setting .45→`CKM_ECDSA_SHA256`, .49→`CKM_ECDSA_SHA384`.

**Bug 2 (pre-existing, all ECDSA profiles): the composite signature's
classical component was embedded as PKCS#11's raw fixed-width r||s,
not the DER `ECDSA-Sig-Value` draft-19's wire format actually
carries.** Every external KAT vector's classical-signature tail parses
as a valid DER `SEQUENCE { INTEGER r, INTEGER s }` (confirmed via
`openssl asn1parse`); this provider's `p11prov_sig_operate` — a thin
wrapper around raw `C_Sign`/`C_Verify` — was writing/reading that raw
PKCS#11 output straight into the composite signature bytes with no
conversion, even though the buffer-sizing comment already (correctly,
if not consistently) said "ECDSA-P256 DER ≤ 72". Fixed with new
`ecdsa_raw_to_der`/`ecdsa_der_to_raw` helpers (`ECDSA_SIG_new`/
`ECDSA_SIG_set0`/`i2d_ECDSA_SIG` and `d2i_ECDSA_SIG`/`ECDSA_SIG_get0`/
`BN_bn2binpad`, not hand-rolled ASN.1), wired into
`p11prov_composite_digest_sign_final` (raw scratch buffer → DER at the
real wire position) and `...verify_final` (DER from the wire → raw
scratch buffer before `C_Verify`) via a new per-profile
`ec_field_width` (32 for P-256, 48 for P-384). **Sabotage-verified**:
disabling only the sign-side conversion (falling back to the old raw
passthrough) breaks exactly the four ECDSA profiles (T21b/T21c/T21e/
T21h) while the RSA-PSS and Ed25519 profiles (unaffected by this bug
class) stay green — confirms the fix is load-bearing, not incidental.

**Bug 3 (structural, would have miscompiled the new profiles even
without bugs 1/2): the classical-family dispatch inferred RSA-vs-ECDSA
from `mldsa_param_set` (44→RSA, 65/87→ECDSA), which the 8-profile set
genuinely breaks** — .40 pairs MLDSA44 with ECDSA, .41 pairs MLDSA65
with RSA-PSS, .39/.48 pair MLDSA44/65 with Ed25519. Adding any of
these five profiles under the old inference would have silently
selected the wrong classical algorithm entirely (not just the wrong
hash). Replaced with an explicit `enum p11prov_composite_classical`
field plus a concrete `classical_mechanism`/PSS-params/`ec_field_width`
per profile, used directly by `composite_setup_classical_sigctx`,
`composite_digest_op_init`'s family selection, and
`p11prov_composite_obj_get_pubkey_bytes`'s pubkey-extraction dispatch
(which gained a new `composite_get_ed25519_pubkey`, mirroring the
existing ECDSA/RSA collectors with `CKK_EC_EDWARDS`).

**Bug 4 (found building the RSA-3072 profile's own test): classical
signature buffer sizing (`classical_sig_max = 256`,
`p11prov_composite_keymgmt_get_params`'s matching `+ 256`) was sized
only for RSA-2048's 256-byte signature — RSA-3072 needs 384 and failed
sign with a buffer-too-small provider error the caller couldn't
recover from, since the SAME constant under-reported OpenSSL's own
sizing-query result too.** Bumped to 512 in both places (comfortably
covers every registered profile: RSA-3072's 384 bytes, ECDSA-P384 DER's
~104).

**A fifth, genuinely new capability gap, not a bug in existing code**:
composite.c registered ONLY `OSSL_FUNC_SIGNATURE_DIGEST_SIGN/VERIFY_*`,
never plain `SIGN_INIT`/`SIGN`/`VERIFY_INIT`/`VERIFY` — meaning
`openssl pkeyutl -sign/-verify -rawin`, the exact API this harness
already relies on for every other hash-internal algorithm (ML-DSA,
SLH-DSA, Ed25519 — see T3/T7/T12sign's own `pkeyutl -rawin` calls),
could never reach composite signing or verification at all. Confirmed
this is not composite-specific: `openssl dgst -verify` against a
plain, already-shipped ML-DSA key hits the identical "no default
digest" `do_sigver_init` failure via `EVP_DigestVerifyInit_ex`'s
digest-name resolution — a general provider quirk on the VERIFY
direction of the digest-wrapping API, unrelated to composite, that
`pkeyutl -rawin`'s plain `EVP_PKEY_sign`/`verify` path sidesteps
entirely. Added `p11prov_composite_sign_init`/`sign`/`verify_init`/
`verify` as thin one-shot wrappers over the existing
`composite_digest_op_init`/`digest_op_update`/`digest_sign_final`/
`digest_verify_final` (no new signing logic — same trio the
DIGEST_SIGN path already used, just reachable from the plain SIGN/
VERIFY operation type OpenSSL dispatches for `pkeyutl -rawin`).

**Test infrastructure, new**: the standard `openssl` CLI cannot drive
composite sign/verify at all — there is no `OSSL_FUNC_KEYMGMT_GEN` for
composite keys, only a two-subkey-URI bridge
(`p11prov_composite_evp_pkey_from_uris`, exported from
`pkcs11-provider.so` for pqctoday-hub's `cms_provider_init.c`, per
composite.h's own comment). Added `scripts/composite-sig-probe.c` (new
CMake target `composite_sig_probe`, top-level `CMakeLists.txt`, gated
on `BUILD_TESTS` alongside `p11_v32_compliance_test`) — a small
standalone tool that loads the pkcs11 + default providers, calls the
bridge directly with real token-resident ML-DSA + classical keypairs,
and drives `EVP_PKEY_sign`/`EVP_PKEY_verify`. Linking a MODULE-type
CMake library (`pkcs11-provider`) into a plain executable needed the
GNU `-l:exact-filename.so` linker form — CMake's normal
`target_link_libraries(... pkcs11-provider)`, even wrapped in
`$<TARGET_FILE:...>` or a literal matching path, kept re-deriving a
bare `-lpkcs11-provider` (which the linker can't find — no `lib`
prefix on a provider module) because CMake recognizes the path as that
target's output regardless of how it's spelled; `-l:pkcs11-provider.so`
plus an explicit `-L`/`-rpath` bypasses that resolution while keeping
normal link-order placement (unlike `target_link_options`, which
misordered the library before the object file needing its symbols).

**Proof per profile** (T21a–T21h, `scripts/test-openssl-provider.sh`):
real ML-DSA + classical keypair generation on the token, real sign via
`composite_sig_probe`, real verify against a SEPARATE public-key-URI
EVP_PKEY (feeding the signing private-key URIs to verify fails
`EVP_PKEY_verify_init` with an empty OpenSSL error queue — PKCS#11
`C_VerifyInit` against a `CKO_PRIVATE_KEY`-class object fails below the
level this provider raises an OSSL error for, which looks like a
silent crash until you know to check the key class), plus two sabotage
controls per case (wrong message, corrupted signature byte) that must
both fail. Sabotage-tested the harness itself per the plan's own
prescription: corrupting only .39's OID constant broke only T21d,
all seven other cases stayed green.

Both engines' full test suites remain green (C++: 8/8 CTest suites;
Rust: unaffected — confirmed no code changed under `rust/`, one
flaky pre-existing failure in an unrelated FFI param-width test
reproduced as a genuine one-off — passes in isolation and on rerun,
not touched by this item). **Harness: `PASS=47 FAIL=0 XFAIL=0
XPASS=0`** — eight cases gained (T21a–T21h), zero regressions.

**Deferred, not started**: fixing composite SPKI decoder registration
(a separately tracked, pre-existing issue — "composite decoders remain
defined but unregistered — recursion issue", §2's table — out of this
item's scope; cert-vector-based verify-only KAT proof for .39/.41/.48
would need it, so those three profiles' M' construction was instead
cross-checked directly against the certificate_vectors' extracted
bytes in Python, independent of this provider, before writing any
signing code); `tls.c` TLS-SIGALG entries for the five new profiles
were added (private-use range 0xFEB3–0xFEB7, continuing R7's original
scoping) but not harness-proven over an actual TLS handshake — no
existing harness case negotiates a composite sigalg at all, including
for the three pre-existing profiles, so this is a pre-existing gap
this item did not close, not a new one it introduced.

**Phase 4, R10 (KDF widening — PBKDF2), DONE (PBKDF2 only; SP800-108
deferred):** two probes, both re-verifying the plan's own premise
before scoping any work, per the plan's own "probes first" framing.

**Probe (a) — PBKDF2/SP800-108 engine support**: the plan's premise
("the C++ engine advertises CKM_PKCS5_PBKD2 and
CKM_SP800_108_COUNTER_KDF/_FEEDBACK_KDF") looked, on a first grep of
`SoftHSM_slots.cpp`, like it might only be a `C_GetMechanismInfo`
advertisement with no real `C_DeriveKey` handling behind it (a "fake
advertisement" gap that would have meant the actual work belonged in
the C++ engine, not the provider) — re-checked in `SoftHSM_keygen.cpp`
before trusting that read, and the premise held: PBKDF2 and both
SP800-108 variants (Counter, Feedback) are fully implemented in
`C_DeriveKey`, with real PRF/parameter validation. The gap is
provider-only, exactly as scoped — `kdf.c` implemented only HKDF/
TLS13-KDF, nothing registered CKM_PKCS5_PBKD2 at the `OSSL_OP_KDF`
level at all.

**Probe (b) — `EVP_KDF_derive_SKEY` opaque-handoff viability**: the
plan called `set_skey`/`derive_skey` "dispatch stubs (lines 43-44)" —
those line numbers are only the `DISPATCH_HKDF_FN` forward
declarations; the actual `p11prov_hkdf_set_skey`/`derive_skey`/
`p11prov_tls13_kdf_derive_skey` functions have real, complete bodies
already. Not a stub needing implementation — and not just
code-present-but-unproven either: T13's own harness case already
exercises this path live ("token performs KEM ops + TLS13-KDF derives,
engine-log verified"), since OpenSSL's TLS 1.3 key-schedule machinery
chains HKDF/TLS13-KDF secrets via the SKEY API internally. No work
needed; this probe's finding is a documentation correction; the plan's
own claim of stub status was wrong.

**Scoped work**: PBKDF2 only, per the plan's own stated priority
("PBKDF2 first — highest caller demand — SP800-108 second"); SP800-108
deferred to keep this item's diff and proof scoped to what was built
and verified, matching R8's own precedent for AES-CMAC/KMAC. New
PBKDF2 section in `kdf.c` (`struct p11prov_pbkdf2_ctx`,
newctx/freectx/reset/set_ctx_params/settable_ctx_params/
get_ctx_params/gettable_ctx_params/derive, new
`p11prov_pbkdf2_kdf_functions[]` dispatch table), wired into
`provider.c`'s checklist-driven mechanism discovery (new
`CKM_PKCS5_PBKD2` checklist entry and registration case) and
`provider.h` (name `"PBKDF2:1.2.840.113549.1.5.12"` — matches the
default provider's own name + OID, confirmed live via `openssl list
-kdf-algorithms -provider default` before assuming, the same check R8
made).

**Structurally different from HKDF, not just a copy with renamed
fields**: PBKDF2 needs no input-key-material object — the password
travels directly in `CK_PKCS5_PBKD2_PARAMS2`, and the engine's own
`C_DeriveKey` special-cases `CKM_PKCS5_PBKD2` *before* validating
`hBaseKey` (confirmed by reading that dispatch, not assumed). HKDF's
existing `p11prov_derive_key` helper requires and dereferences a real
`P11PROV_OBJ` key handle this operation has no equivalent of, so
`derive()` calls `p11prov_DeriveKey` directly with `hBaseKey =
CK_INVALID_HANDLE` instead of reusing that helper.

**A genuine, non-obvious authorization requirement, caught live and
confirmed NOT provider-specific before treating it as a fix**: the
first working build failed every case with `CKR_USER_NOT_LOGGED_IN`
("User is not authorized") from `SoftHSM_keygen.cpp`'s `haveWrite`
check on a bare, freshly-initialized session. Before assuming this was
a PBKDF2-specific gap, reproduced the identical failure against the
pre-existing, already-shipped HKDF path under the same bare conditions
(`openssl kdf HKDF ...` with no prior session activity) — it fails
identically. This is a general `C_DeriveKey` requirement HKDF's own
real callers (TLS handshakes) never hit because the session is already
logged in by the time HKDF runs, not a template or dispatch gap PBKDF2
introduced. Fixed by requesting a logged-in session
(`p11prov_get_session(..., reqlogin=true, ...)`, vs HKDF's own
`false` — the two operations' actual call sites just have different
authentication preconditions, this isn't a case of one being "more
correct" than the other).

**Proof**: five new harness cases (T22/T22b/T22c/T22d/T22e, one per
supported PRF — SHA-1/224/256/384/512, the engine's own PRF switch in
`SoftHSM_keygen.cpp`), each cross-checking token output against
software PBKDF2 byte-for-byte AND requiring engine-log evidence
("Created new object" — the same class of proof T13/T15/T18/T20
established, not output equality, since PBKDF2 is deterministic and a
silent wrong-provider fallback would be invisible in the value alone),
with an R13 negative-control twin. Own dedicated arena per case (not
shared `mk_arena`), same reason as T20's own — `mk_arena` hardcodes
`log.level = ERROR`, which would hide the debug-level marker this
proof depends on. Sabotage-tested at the harness level per the plan's
own prescription: corrupting only the SHA-256 PRF mapping (mapping it
to `CKP_PKCS5_PBKD2_HMAC_SHA1` instead) broke only T22c, all four other
digests stayed green.

Both engines' full test suites remain green (C++: 8/8 CTest suites;
Rust: unaffected — no code under `rust/` changed by this item).
**Harness: `PASS=52 FAIL=0 XFAIL=0 XPASS=0`** — five cases gained
(T22/T22b/T22c/T22d/T22e), zero regressions.

**Deferred, not started**: SP800-108 Counter/Feedback KDFs (both fully
implemented in the engine per probe (a) above — same shape of work as
this item, not attempted here to keep the diff scoped); `EVP_SKEY`
support for PBKDF2 itself (HKDF/TLS13-KDF already have it per probe
(b); PBKDF2's own `derive_skey` was out of this item's "PBKDF2 first"
scoping).

**Phase 4, R20 (small-surface tier, five independent micro-items),
DONE — two shipped with code, three closed by investigation:**

**OP-4 (KEM SET_CTX_PARAMS) — investigated, no gap, no code.** The
plan's premise was that CMS `-encrypt`/`-decrypt` to an ML-KEM cert
might need `kem/mlkem.c` to handle `OSSL_KEM_PARAM_OPERATION` via
`SET_CTX_PARAMS`/`SETTABLE_CTX_PARAMS`, neither of which exist there.
Settled definitively by reading OpenSSL's own CMS source
(`crypto/cms/cms_kemri.c` in the vendored 3.6.3 tree) rather than
inferring from the CLI: the real call sites are
`EVP_PKEY_encapsulate_init(kemri->pctx, NULL)` and
`EVP_PKEY_decapsulate_init(pctx, NULL)` — both pass a **NULL** params
argument, unconditionally, for every KEM algorithm. `OSSL_KEM_PARAM_
OPERATION` (the `-kemop DHKEM`/`RSASVE` values `pkeyutl`'s own CLI
flag sets) is a generic-KEM-wrapper concept for RSA/DH keys routed
through OpenSSL's own `ec_kem.c`/RSA-KEM code; it has no CMS caller
and no meaning for a natively-implemented algorithm like ML-KEM. No
gap exists for CMS KEMRecipientInfo; closing without code.

**F36-5 (NIST security-category param) — DONE.** Added
`OSSL_PKEY_PARAM_SECURITY_CATEGORY` to ML-DSA (`keymgmt.c`), ML-KEM
(`kem/mlkem.c`), and SLH-DSA (`keymgmt.c`) `get_params`/
`gettable_params`, values per FIPS 203 Table 2 / FIPS 204 Table 1 /
FIPS 205 Table 2: ML-KEM-512/768/1024 → 1/3/5; ML-DSA-44/65/87 →
2/3/5; SLH-DSA (all 12 parameter sets, uniform across SHA2/SHAKE and
s/f — the category tracks the hash-output size, not the speed/size
tradeoff) → 1 (128-bit) / 3 (192-bit) / 5 (256-bit). New
`scripts/dump-int-param.c` (CMake target `dump_int_param`, gated on
`BUILD_TESTS`) — a generic `EVP_PKEY_get_int_param` reader, since no
`openssl` CLI subcommand dumps an arbitrary int param (`pkey -text` is
algorithm-specific and only prints what that algorithm's own print
function was written to show). Verified live for all 8 algorithm
variants (all three ML-DSA, all three ML-KEM, two representative
SLH-DSA variants) before writing the harness case; three new cases
(T23/T23b/T23c, one per PQC family) in the harness itself.
Sabotage-tested: corrupting ML-DSA-44's category value alone broke
only T23, T23b/T23c stayed green.

**F36-6 (ML-DSA signature-param parity) — investigated, one real
divergence found and documented (not fixed — not fixable within
PKCS#11 v3.2).** `deterministic`/`message-encoding`/`mu` are already
implemented in `sig/mldsa.c` (`p11prov_mldsa_set_ctx_params`), not
absent as the plan's framing might suggest — the real question was
whether they're *correct*, not present.
- `deterministic`: verified genuinely functional, not just
  accepted-and-ignored — signing the same message twice with
  `deterministic:1` produces byte-identical signatures; with
  `deterministic:0` (hedged) it produces different signatures each
  time, matching `CKH_DETERMINISTIC_REQUIRED` vs `CKH_HEDGE_REQUIRED`
  in the underlying `CK_SIGN_ADDITIONAL_CONTEXT.hedgeVariant`. No gap.
- `message-encoding`: this provider accepts only value `1` (rejects
  anything else); the default provider's `ml_dsa_sign.c` documents
  `encode=0` as "M' is provided raw [pre-encoded], the following
  parameters are ignored" — i.e. the caller supplies the already-
  encoded message representative directly, bypassing FIPS 204's
  standard `M' = Prefix||ctx||M` construction. Confirmed this is a
  real divergence (default provider accepts it, this one doesn't) —
  and confirmed it is **not fixable** short of a non-standard PKCS#11
  extension: `CK_SIGN_ADDITIONAL_CONTEXT` (the v3.2 mechanism param
  struct `mldsa_params` uses) has fields only for `hedgeVariant`/
  `pContext`/`ulContextLen` — no field for a pre-encoded M' bypass, so
  no PKCS#11-v3.2-compliant ML-DSA token can accept this input at the
  mechanism level regardless of provider-side code. Documenting as a
  known, spec-rooted limitation (same category of finding as R21's
  WART-5, below).
- `mu`: same root cause and same conclusion — externally-supplied `mu`
  (bypassing both the encoding step AND ML-DSA's own internal SHAKE256
  hash) has no `CK_SIGN_ADDITIONAL_CONTEXT` field either. Documented,
  not fixed, for the same structural reason.

**ALG-6 (ECDH-as-KEM) — investigated, deliberately unexposed, no
code.** OpenSSL 3.6 does have a standard KEM fetch surface for EC keys
(`ec_kem.c`, RFC 9180 DHKEM — confirmed via `openssl list
-kem-algorithms -provider default`, which lists bare `EC` alongside
ML-KEM). But this project's own engine-level "ECDH-as-KEM" capability
(`CKM_ECDH1_DERIVE` under `C_Encapsulate`/`DecapsulateKey`, per
`CLAUDE.md`'s own description — a building block the KMIP/hub hybrid
combiner drives directly, not through this generic KEM op) is **raw
ECDH**, not RFC 9180's HKDF-Extract-and-Expand construction. Exposing
it under OpenSSL's `EC` KEM algorithm name would silently produce
non-DHKEM-compliant output for any caller fetching `"EC"` as a KEM and
expecting RFC 9180 semantics — a correctness hazard, not a safe
drop-in registration. No current consumer needs the generic KEM
operation type for EC (the real hybrid-KEM combiner path bypasses it
entirely). Deliberately unexposed; closing without code, per the
plan's own suggested fallback for this item.

**ALG-7 (ChaCha20/ChaCha20-Poly1305) — investigated, scope corrected,
deferred as its own item.** Re-verified the carried premise first, per
the plan's own instruction: both engines genuinely implement it, not
just advertise it — confirmed via `OSSLChaCha20.cpp` (a real,
dedicated crypto class, C++ engine) and `rust/src/constants.rs`'s own
mechanism table (Rust engine), the same "advertised vs. actually
dispatched" distinction R10's PBKDF2 probe drew. Where the plan's
"straightforward... mirroring the AES entries" characterization did
not hold up: `cipher.c` (1074 lines) is AES-block-cipher-specific
machinery throughout — hardcoded `aes`-prefixed dispatch function
names, an `AESBLOCK`/padding-oriented context struct, CBC/CTS-specific
logic — not a generic symmetric-cipher framework a stream cipher
(ChaCha20, no block/pad concept) or its AEAD mode (ChaCha20-Poly1305,
needs its own tag-length/nonce-size handling, distinct from
`CKM_AES_GCM`'s) could mechanically "mirror." Wiring this in correctly
needs new cipher-family plumbing, not a mechanism-table entry — the
same class of scope correction R8 (MAC) and R10 (KDF) each made when a
"small" item's real implementation surface turned out larger than
billed. Deferred as its own future item rather than rushed under this
tier's effort budget, matching R10's own precedent for SP800-108.

Both engines' full test suites remain green (C++: 8/8 CTest suites;
Rust: unaffected — no code under `rust/` changed by this item).
**Harness: `PASS=55 FAIL=0 XFAIL=0 XPASS=0`** — three cases gained
(T23/T23b/T23c), zero regressions.

**Phase 4, R21 (hygiene tier, remaining four items), CLOSED —
already resolved before this plan was written; zero code changes.**
Item 1 of R21 (composite.c stray debug output) was executed earlier
this session as R21.1. The other four — WART-1, WART-3, WART-5, ENV-3
— turned out to be stale carryovers: all four were already fixed by a
"P0 hygiene batch" (commit `3bf6f56`, R0.1–R0.5, dated 2026-08-25,
same day as this audit but predating the phase-4 plan) that the
phase-4 plan's own gap list did not check against before listing these
as open work — the same class of stale-premise carry-forward this
session already caught for R10 (SP800-108's real status) and F36-6's
`set_skey`/`derive_skey` "stub" claim, just older. Re-verified each
claim directly rather than trusting the commit message alone:
- **WART-1**: `P11Objects.cpp`'s mandatory-attribute-check loop no
  longer calls `getByteStringValue()` on non-byte-string attributes
  (root-caused via gdb per R0.1's own commit message, not guessed).
  The harness's own tail section (`test-openssl-provider.sh`) already
  greps every case log for `ObjectFile.cpp(181)` and fails the run if
  any appear — this exact assertion has been passing on every harness
  run this entire session (R7 through R20's 55/55), which is itself
  live, repeated confirmation the fix holds.
- **WART-3**: `src/vendor/pkcs11-provider/CMakeLists.txt` generates a
  real `config.h` at configure time (deriving `P11PROV_VERSION` from
  the same `meson.build` `version:` field the WASM generator parses —
  single source of truth), replacing the previous silent dependency on
  a stale WASM-generated file happening to already sit on disk.
  Re-verified live this session (R20 investigation): `openssl list
  -providers` reports version `1.1`, matching `meson.build`'s own
  declared version — no mismatch, no redefinition warnings.
- **WART-5**: `src/vendor/pkcs11-provider/README.md` documents the
  RSA-OAEP SHA-1-default-vs-engine-FIPS-posture mismatch with a
  working `-pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256`
  example matching harness T5 — read directly, confirmed present and
  accurate, not just claimed.
- **ENV-3**: `test_openssl_integration.sh` and `openssl_test.cnf` are
  genuinely deleted (`git log --diff-filter=D` confirms, same P0
  batch) — grepped the whole repo (scripts, CI configs, `docs/`) for
  any remaining reference; only historical mentions in `CHANGELOG.md`
  and the plan/audit docs themselves remain, no live/broken reference.
  The vendored meson test suite (30 tests) is documented as
  intentionally unwired in `src/vendor/pkcs11-provider/README.md`
  ("assumes upstream's build layout and a SoftHSM2/NSS-softokn token
  backend... would need real adaptation work rather than a flag flip")
  — the gap matrix's ENV-3 row (§4.A) still reads as an open gap and
  should be corrected to RESOLVED to match.

No commit needed beyond this documentation update — there is no code
to change; the fixes already exist and are already proven (the
harness's own standing R0.1 regression guard, a live version check,
two README reads, and a repo-wide reference grep all independently
confirm it). Filed as its own commit anyway, per this project's
convention that even a zero-code closure (matching R19's own
"proof-debt closure, DONE, no code changes" precedent) gets recorded.

**Phase 4, R9 (HSS/LMS token-sign / OpenSSL-verify), DONE — new
`sig/hss.c` and `HSS` keymgmt, real cross-implementation proof.**
`CKM_HSS`/`CKM_HSS_KEY_PAIR_GEN` (PKCS#11 v3.2 §6.14) were previously
unreachable through the provider at all — no keymgmt, no signature
dispatch. This item wires up the single default variant the engine
generates when `CK_HSS_KEY_PAIR_GEN_PARAMS` is omitted (L=1,
LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W8 — the C++ engine's own
documented default), following five bugs found and fixed in sequence,
each surfaced only after the previous fix changed the failure symptom
(the same layered-discovery shape as R7's and R18's four bugs each):

1. **`objects.c`'s key-type switch had no `case CKK_HSS:`** — fell to
   `default: return CKR_ARGUMENTS_BAD`, even though the token itself
   had genuinely created the object (`C_GenerateKeyPair` logged
   "Created new object" twice). Fixed with a new `fetch_hss_key()`.
2. **`store.c`'s data-type-resolution switch had no `case CKK_HSS:`**
   — `pkeyutl -inkey pkcs11:...` failed with "Could not find private
   key" even though the object existed. Fixed with a plain `data_type
   = "HSS"` case (no per-variant split needed, unlike ML-DSA/SLH-DSA).
3. **No SPKI/PrivateKeyInfo PEM encoder existed for HSS at all** —
   `genpkey -out` failed with "Error writing key(s)". Fixed by adding
   `p11prov_hss_encoder_priv_key_info_pem_encode`, a thin wrapper over
   the shared, generic `p11prov_encoder_private_key_write_pem`,
   mirroring SLH-DSA's identical pattern.
4. **`keymgmt.c`'s `OSSL_PKEY_PARAM_BITS` handler aborted the whole
   `get_params` call for private-key objects** (no `CKA_VALUE` on a
   private HSS object → immediate `return RET_OSSL_ERR`), which
   silently prevented `OSSL_PKEY_PARAM_MAX_SIZE` from ever being set
   in the SAME call — a single early `return` inside one param's
   handling aborts every subsequent param in that call, an OpenSSL
   provider-API contract easy to miss. `EVP_PKEY_get_size()` then
   failed with "unknown max size", cascading into "Error initializing
   context" for every sign/verify attempt. Fixed by walking to the
   associated public object (`p11prov_obj_get_associated`, matching
   ML-KEM's own precedent) and gracefully skipping — not erroring —
   when the public value isn't available that way.
5. **`pkeyutl -sign -rawin` needs `DIGEST_SIGN`/`DIGEST_VERIFY`
   dispatch, not plain `SIGN`/`VERIFY`.** Corrects a wrong assumption
   this project's own R7 composite.c work made under the same
   pressure: reading OpenSSL's actual `apps/pkeyutl.c` source (not
   assumed) shows `-rawin` always calls `EVP_DigestSignInit_ex`/
   `EVP_DigestVerifyInit_ex`, even with `mdname=NULL` — plain
   `SIGN`/`VERIFY` is only the CLI's `-rawin`-absent branch. `sig/
   hss.c` implements both: DIGEST_SIGN/VERIFY accumulate the raw
   message in provider memory across update calls (mirroring
   composite.c's own `tbs_buf` pattern from R7 — HSS's engine
   mechanism, like every stateful signature here, is single-part-only:
   `SoftHSM_sign.cpp`'s `StatefulSignInit` explicitly disables
   multi-part operation), then make one real `C_Sign`/`C_Verify` at
   FINAL time. Two of the provider's existing generic reuse candidates
   were checked and rejected for this, not assumed unusable:
   `p11prov_sig_digest_update`/`final` call *real* `C_SignUpdate`/
   `C_VerifyUpdate` (unsupported here), and `P11PROV_SIG_CTX`'s
   `fallback_digest` path pre-hashes the message in *software* before
   signing the digest — correct for RSA/ECDSA-shaped "sign(digest)"
   algorithms, wrong for a hash-internal algorithm like HSS/LMS whose
   own RFC 8554 hashing must see the untouched full message.

Two further bugs surfaced once sign_init/verify_init actually
dispatched, found via live `pkeyutl -sign -rawin` runs against a real
token key, not guessed:

- **Sizing queries (`sig == NULL`) were routed through
  `p11prov_sig_operate`, which flatly rejects a NULL `sig`
  (`signature.c`: `if (sig == NULL) return CKR_ARGUMENTS_BAD;`).**
  Every other algorithm here (ML-DSA's own
  `p11prov_mldsa_sig_size()`/per-paramset table is the precedent)
  answers a sizing query from a known constant instead of a live token
  round trip — HSS's signature length depends only on (L, LMS,
  LM-OTS), never message length, so `sig/hss.c` does the same via
  `HSS_L1_DEFAULT_SIG_SIZE`. Also non-obvious and confirmed by reading
  OpenSSL's own `EVP_DigestSign()` (`crypto/evp/m_sigver.c`): its
  one-shot wrapper skips `DIGEST_SIGN_UPDATE` entirely when
  `sigret == NULL`, so the sizing call's accumulator is *always*
  empty regardless of message size — passing it through to the token
  would have been wrong even if `p11prov_sig_operate` allowed it.
  `HSS_L1_DEFAULT_SIG_SIZE = 1296` is derived from RFC 8554's own
  byte-accounting for this exact parameter combination (OTS sig
  4+32+34×32=1124; LMS sig 4+1124+4+5×32=1292; HSS sig 4+1292=1296)
  and independently confirmed live: a real `pkeyutl -sign -rawin`
  output file is exactly 1296 bytes.
- **`p11prov_sig_newctx()` leaves `sigctx->mechanism.mechanism` at the
  `CK_UNAVAILABLE_INFORMATION` sentinel** — every other algorithm sets
  its real mechanism explicitly before calling `p11prov_sig_operate`
  (ML-DSA's own `p11prov_mldsa_set_mechanism()` is the established
  precedent); `sig/hss.c` never did, so the token was being queried
  (`C_GetMechanismInfo`/`C_SignInit`) about mechanism
  `CK_UNAVAILABLE_INFORMATION`, not `CKM_HSS` — confirmed by direct
  comparison against a standalone raw-PKCS#11 probe that showed the
  engine correctly advertising `CKM_HSS` with `CKF_SIGN|CKF_VERIFY`
  (`flags=0x2800`) on the exact same slot the provider was failing
  against. Fixed with a one-line `ctx->sigctx->mechanism.mechanism =
  CKM_HSS;` in both `sign_init`/`verify_init` — CKM_HSS takes no
  `CK_MECHANISM` parameter, so nothing else was needed.

**Live proof (harness `T24`, all in one arena):** `genpkey -algorithm
HSS` → `pkeyutl -sign -rawin` (1296-byte signature) → `pkeyutl -verify
-rawin` (token-verified); the same round trip again via plain
`SIGN`/`VERIFY` (no `-rawin`); both sabotage controls (corrupted
signature byte, wrong message) rejected. **Then the genuine
cross-implementation proof the plan's own R9 text calls "the whole
point"**: the token's own `C_Sign` output verified by OpenSSL 3.6.3's
*independent*, from-scratch native LMS implementation — never through
the pkcs11-provider, never through the engine's own `C_Verify` (a
signer that's wrong in a way its own verifier agrees with would pass
self-consistency and still be broken). Two new permanent test tools
support this (`scripts/lms-xdr-verify.c`, `scripts/hss-pubkey-dump.c`,
both CMake targets, following `composite_sig_probe`'s established
precedent for scaffolding the CLI can't reach):
- `openssl` CLI genuinely cannot reach this path: the native LMS
  decoder is registered `DECODER("LMS", xdr, lms, yes)` — no
  `structure=` property at all (`providers/decoders.inc`, read
  directly) — so the standard PEM→DER `OSSL_STORE` auto-detect chain
  `pkeyutl`/`pkey` use never tries it. `lms-xdr-verify.c` calls
  `OSSL_DECODER_CTX_new_for_pkey(..., "xdr", ...)` directly.
- Native LMS registers `OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT` (the
  one-call "message" family for hash-internal algorithms;
  `lms_signature.c`, read directly), not `VERIFY_INIT` or
  `DIGEST_VERIFY_INIT` — `EVP_PKEY_verify_message_init()`, not
  `EVP_PKEY_verify_init()` or `EVP_DigestVerifyInit_ex()`.
- Two wire-format strips are required, both because HSS always wraps
  LMS even at a single level (RFC 8554 §6.1/§6.2), while OpenSSL's
  native support is bare-LMS only: the 60-byte HSS pubkey is
  `u32str(L=1) || 56-byte LMS pubkey`; the 1296-byte HSS signature is
  `u32str(Nspk=0) || 1292-byte LMS signature`. Both tools auto-detect
  by length and strip the wrapper. The FIRST attempt at this cross-
  check passed the pubkey's L-prefix stripped but the FULL
  (unstripped) 1296-byte signature to a bare-LMS verify — decoded
  without error, then verified **false** on a genuinely valid
  signature/message/key triple, which (correctly) read as a possible
  engine signing bug before the wrapper mismatch was found; stripping
  the signature's own 4-byte `Nspk` prefix the same way fixed it.
  Documented here because that failure shape — decodes clean, verifies
  false — is exactly what a *real* cross-implementation bug would also
  look like, and is worth remembering as "check the wire format before
  trusting the crypto is wrong."
- Sabotage-checked the cross-verifier too: a corrupted byte in the
  bare-LMS signature and a wrong message are both rejected by the
  independent verifier, not just by the engine's own.

**Rust arm — investigated, genuine cross-engine inconsistency found,
not fixed here (out of this plan's scope).** The plan's own R9 text
names a multi-process stateful-counter test riding on R14's Rust CLI
flow as a goal. A smoke test (`genpkey -algorithm HSS` /
`pkeyutl -sign -rawin`, over `libsofthsmrustv3.so`, same provider
code, same `HSS_L1_DEFAULT_SIG_SIZE` constant) failed
`CKR_BUFFER_TOO_SMALL` on `C_Sign`. Root cause, confirmed by reading
both engines' own keygen source directly: the two engines pick
**different LM-OTS defaults** when `CK_HSS_KEY_PAIR_GEN_PARAMS` is
omitted — the C++ engine defaults to `LMOTS_SHA256_N32_W8` (IANA
`0x04`, 1296-byte signature, confirmed above); the Rust engine's own
`ffi.rs` (`CKM_HSS_KEY_PAIR_GEN` arm, `Ok(None) => ...
CKP_LMOTS_SHA256_N32_W4`) defaults to `LMOTS_SHA256_N32_W4` (IANA
`0x03`, a 2352-byte signature — larger `p` from the smaller Winternitz
parameter). The two engines are also inconsistent about *storing* the
parameter set at all: the Rust engine's `CKM_HSS_KEY_PAIR_GEN` arm
writes `CKA_LMS_PARAM_SET`/`CKA_LMOTS_PARAM_SET` on the generated
keys; the C++ engine's (`SoftHSM_keygen.cpp`) does not — only
`CKA_KEY_GEN_MECHANISM` and a vendor `ATTR_CKA_HSS_KEYS_REMAINING`
counter. Reconciling either "what is the default" or "how is the
chosen parameter set exposed back to a reader" is a decision for
whoever owns both engines' HSS behavior — it is not a pkcs11-provider
bug, and fixing it from the provider side (a hardcoded per-key-object
formula reading an attribute one engine doesn't set) would be working
around a real inconsistency rather than reporting it. Left
undone, following this harness's own established "investigated, does
not hold up as a mechanical fix, documented rather than forced"
precedent (matching R17's own entry above). `T24` accordingly covers
the C++ arm only; the Rust engine's OWN, independent HSS test coverage
(`rust/src/native/sign.rs`, `native::parity::
hss_ffi_and_native_advance_the_leaf_index_identically`, all passing)
already establishes HSS correctness there — R9 does not need to
duplicate it, only to reach it through this provider, which the
parameter mismatch above currently blocks.

Full regression, both engines: **C++ CTest 8/8 passed** (no C++
engine source changed by this item); **Rust `cargo test --release`:
410 passed, 0 failed, 9 ignored** (no `rust/` source changed by this
item — the 9 ignored are pre-existing, unrelated to R9). **Harness:
`PASS=56 FAIL=0 XFAIL=0 XPASS=0`** — one case gained (T24), zero
regressions.

**Phase 5, R24 (`EVP_SKEY` opaque-key flow probe, F36-3), DONE — one
real bug found and fixed, one real gap found and handed to R23.** The
plan's own framing was "probe first, code only if a real gap with a
real consumer path emerges" — both halves of that happened. New
permanent test tool `scripts/skey-flow-probe.c` (CMake target
`skey_flow_probe`, plain OpenSSL linking, no provider-internal
symbols — loads pkcs11-provider at runtime like any application)
exercises, in order: `EVP_SKEY_generate` over this provider's AES and
GENERIC-SECRET SKEYMGMT; `EVP_KDF_derive_SKEY` over HKDF, with the
derived key consumed by `EVP_MAC_init_SKEY` (HMAC) and cross-checked
byte-for-byte against an independent, pure-software HKDF+HMAC
computation of the SAME known input/salt/info/digest — never exporting
the intermediate derived key material at any point; the identical
chain over TLS13-KDF (existence + opacity only, lighter check); and a
negative control confirming PBKDF2 (R10) still correctly lacks
`derive_SKEY`.

**Bug found and fixed: `skeymgmt.c`'s four entry points never called
`p11prov_ctx_status()`.** First run failed both `EVP_SKEY_generate`
calls and the HKDF chain's own key-import step with
`CKR_GENERAL_ERROR`/"Failed to get PKCS#11 session" — traced via
`PKCS11_PROVIDER_DEBUG` to `p11prov_get_session()` never even being
reached; `p11prov_take_slots()` returned `CKR_GENERAL_ERROR`
immediately (no debug trace of its own) because
`p11prov_ctx_get_slots(ctx)` returned NULL — the provider's lazy
module-init (`dlopen`+`C_Initialize`+slot enumeration,
`p11prov_module_init` in `interface.c`) had never run. Every OTHER
operation type in this provider calls `p11prov_ctx_status(ctx)` first
specifically to trigger that lazy init on demand (confirmed directly:
`sig/signature.c`'s `p11prov_sig_op_init` does it as its first line;
`cipher.c`'s init functions do it too) — `skeymgmt.c`'s four entry
points (`p11prov_aes_generate`/`import`, `p11prov_generic_secret_
generate`/`import`) were the one place in the whole provider that
skipped it, and it only broke when SKEYMGMT was the FIRST pkcs11
operation in a process. Every existing test in this project's harness
always does a keygen or sign before anything else in its arena, which
triggers the lazy init as a side effect — masking this bug completely
until a probe that does nothing BUT exercise `EVP_SKEY` first hit it.
Fixed by adding the same `p11prov_ctx_status()` check, in the same
place, to all four functions. Regression-guarded by harness `T24b`.

**Gap found, not fixed here, handed to R23**: `mac.c`'s HMAC
implementation (R8) never registered `OSSL_FUNC_MAC_INIT_SKEY` — only
the classic raw-bytes `OSSL_FUNC_MAC_INIT`. `EVP_MAC_init_SKEY`'s own
precondition check (`ctx->meth->init_skey != NULL`, confirmed by
reading `crypto/evp/mac_lib.c` directly) fails before any provider
code runs, so a correctly-derived, correctly-opaque SKEY (proven
above) has nothing in this provider that can consume it natively.
R23's own plan already touches `mac.c` for CMAC/KMAC — adding
`INIT_SKEY` support there (for HMAC and the new algorithms both) is
now folded into that item's scope rather than treated as a separate
R-item, since it's the same file, the same kind of dispatch-table gap,
and R23 was already next in the execution order.

**Investigated, not pursued: TLS13-KDF's `derive_SKEY` mode routing.**
Setting `OSSL_KDF_PARAM_MODE` to `"EXTRACT_ONLY"` (a UTF8_STRING param,
matching `p11prov_hkdf_set_ctx_params`'s own string-parsing branch,
read directly) still reached `p11prov_tls13_expand_label` — the
EXPAND_ONLY branch — per a live debug trace, not assumed. Read
`EVP_KDF_derive_SKEY`'s own OpenSSL-core source
(`crypto/evp/kdf_lib.c`) to rule out params being merged or reordered
before reaching the provider — they aren't; `params` reaches
`derive_skey` unmodified. Root cause not found within this item's
probe-first budget. Not chased further: HKDF's already-complete,
independently-cross-checked proof answers R24's actual question (does
a genuinely opaque, correct chain exist at all — yes), and TLS13-KDF's
own check was scoped as the lighter of the two from the start. Matches
this project's own established precedent for an investigation that
doesn't resolve cleanly (ALG-6/R17, above) — logged plainly rather than
either forced to a conclusion or silently dropped.

Full regression: **C++ CTest 8/8 passed**; Rust `cargo test` not
re-run (no `rust/` source touched by this item). **Harness:
`PASS=57 FAIL=0 XFAIL=0 XPASS=0`** — one case gained (T24b), zero
regressions.

**Phase 5, R22 (SP800-108 Counter/Feedback KDF, "KBKDF"), DONE —
byte-identical to software across both modes, both PRF families, one
real bug found and fixed.** New `kdf.c` section wires up
`CKM_SP800_108_COUNTER_KDF`/`CKM_SP800_108_FEEDBACK_KDF` under
OpenSSL's standard `KBKDF` fetch name, reusing HKDF's own
`inner_pkcs11_key`/`inner_derive_key`/`inner_extract_key_value` helpers
(the first, refactored to take `provctx`/`session` directly instead of
an HKDF-specific context struct, so KBKDF's differently-shaped one
could reuse it too — three call sites updated, HKDF's own behavior
unchanged).

**The OSSL_PARAM ↔ `CK_PRF_DATA_PARAM[]` mapping is grounded in the
C++ engine's own handler, not designed independently and hoped to
match**: `SoftHSM_keygen.cpp`'s `CKM_SP800_108_COUNTER_KDF`/
`FEEDBACK_KDF` handlers, read directly, themselves derive via OpenSSL's
own `KBKDF` fetch — so the shape this provider's caller-facing side
produces is provably the one the token-side software actually reads on
the other end of `C_DeriveKey`. That reading also surfaced the exact
scope of what's honorable: `OSSL_KDF_PARAM_KBKDF_USE_L`/
`_USE_SEPARATOR` are not settable here (the engine's own KBKDF call
never sets either, so the token always gets OpenSSL KBKDF's own
default regardless of what a caller of this provider asks for), CMAC's
`OSSL_KDF_PARAM_CIPHER` name is validated but never forwarded (the
engine always derives its actual CMAC cipher from the imported base
key's own byte length via plain `CKM_AES_CMAC`), and SHA-1 is rejected
as an HMAC PRF (the engine's own `ckmHmacPrfToDigestName()` table has
no SHA-1 entry for SP800-108, unlike PBKDF2, which does) — all three
enforced by rejecting loudly rather than silently accepting and
diverging, the R10/F36-6 pattern this section's own header comment
cites explicitly.

**Two real bugs found and fixed, both via live-trace, neither guessed:**
1. **A general C_DeriveKey write-authorization requirement, already
   documented by R10's own comment on `p11prov_pbkdf2_derive`** (a few
   hundred lines above this section in `kdf.c`) but not yet applied to
   any *other* real base-key-object derive path: HKDF's own bare
   `inner_pkcs11_key` call only avoids `CKR_USER_NOT_LOGGED_IN` in
   practice because its real callers (TLS handshakes) always already
   have a logged-in session from an earlier operation — a KBKDF call as
   the first operation in a session does not. Confirmed live before
   writing the fix, not assumed: HKDF was made to fail the identical
   way via the identical bare-session `openssl kdf` invocation this
   item's own harness cases use, ruling out "HKDF secretly doesn't need
   this" as an explanation. Fixed by pre-acquiring a logged-in,
   read-write session (`p11prov_get_session(..., true, true, ...)`)
   *before* the base-key import step, so `inner_pkcs11_key`'s own
   internal (non-logged-in) session acquisition finds one already
   present and reuses it for both the import and the later derive.
2. **`CKA_KEY_TYPE = CK_UNAVAILABLE_INFORMATION` in the output key
   template, harmless for `CKM_HKDF_DERIVE` (the engine's own HKDF
   handler explicitly skips CKA_CLASS/TOKEN/PRIVATE/KEY_TYPE from the
   caller's template, using hardcoded values instead — confirmed by
   reading it directly), fatal for `CKM_SP800_108_COUNTER_KDF`/
   `FEEDBACK_KDF`** (`CKR_TEMPLATE_INCONSISTENT` from `C_DeriveKey`,
   reproduced live). `inner_derive_key`'s shared output template passes
   its `key_type` argument straight through as `CKA_KEY_TYPE`; HKDF's
   own call site has always passed `CK_UNAVAILABLE_INFORMATION` there
   (untested against SP800-108's own, evidently less permissive,
   template validation until now). Fixed on the KBKDF call site only —
   passing `CKK_GENERIC_SECRET` explicitly, matching what the engine
   hardcodes as the output type regardless — confirmed live, both
   before (fails) and after (succeeds, byte-identical to software) the
   one-line change; HKDF's own call site deliberately left unchanged
   (matches its own working behavior, no reason to touch it).

**A methodology trap worth recording, not just the bugs it hid**: this
item's own first pass of manual smoke tests all "passed" — byte-
identical to software, no errors — with zero code changes, before
either bug fix existed. Every one of them had silently computed the
result through the *default* provider, not the token: `openssl kdf`'s
own CLI subcommand never forces this provider's lazy module/slots init
the way `genpkey`/`pkeyutl`'s key-object creation does as a side
effect (the same WART-4/R0.4 class of gap, just for a code path — bare
KDF fetch — nothing had exercised that way before), so a soft
`?provider=pkcs11` propquery fell through to `default` with no visible
error, and `default` trivially matched `default`. Caught only by
checking the provider's own debug trace for `kbkdf` dispatch lines and
finding none — the exact discipline R13 established (engine-log
evidence, not exit code or output value, is the arbiter) — before
declaring anything working. `pkcs11-module-load-behavior = early` in
every T25 arena (T22's own PBKDF2 arena already carries it) is the
fix; both bugs above were found only *after* applying it and watching
the CLI genuinely fail against the token for the first time.

Five new harness cases: T25 (Counter, HMAC-SHA256, sabotage-tested),
T25b (Counter, HMAC-SHA3-256), T25c (Counter, CMAC-AES-256), T25f
(Feedback, HMAC-SHA384, with IV/seed), T25r (three rejection controls:
SHA-1 PRF, non-CBC CMAC cipher, `use-l:0`). Full regression: **C++
CTest 8/8 passed** (no C++ engine source changed by this item — the
mapping was grounded in reading its existing SP800-108 handler, not
modifying it); Rust `cargo test` not re-run (no `rust/` source touched).
**Harness: `PASS=62 FAIL=0 XFAIL=0 XPASS=0`** — five cases gained,
zero regressions.

**Phase 5, R23 (CMAC + KMAC-128/256 as EVP_MAC, + `OSSL_FUNC_MAC_
INIT_SKEY` for all three MACs), DONE — closes R24's own gap, live
end-to-end, both new algorithms sabotage-tested.** Extends `mac.c`
(R8's own file, not a new one): CMAC and KMAC-128/256 join HMAC as
real `OSSL_OP_MAC` implementations, and all three now register
`OSSL_FUNC_MAC_INIT_SKEY` — the dispatch entry R24's probe found
missing (a correctly-derived, correctly-opaque `EVP_SKEY` had nothing
in this provider that could consume it natively; `EVP_MAC_init_SKEY`
failed at the OpenSSL EVP layer before reaching any provider code).

**CMAC**: `p11prov_create_mac_key` (`objects.c`, shared with HMAC)
extended to take an explicit `CK_KEY_TYPE` — CMAC's ephemeral base key
must be `CKK_AES` (the engine's own `kMacMechTable` row for
`CKM_AES_CMAC` has `allowGenericSecret=false`, confirmed by reading it
directly; HMAC's own `CKK_GENERIC_SECRET` default is unchanged). The
caller's `OSSL_MAC_PARAM_CIPHER` name is validated (must be a plain
AES-`{128,192,256}`-CBC name) but never forwarded to the token — the
engine always derives its actual cipher choice from the imported base
key's own byte length via plain `CKM_AES_CMAC` regardless of which
name a caller sends, the identical reasoning and the identical three
accepted names as R22's own KBKDF-CMAC handling.

**KMAC-128/256**: fixed 32/64-byte output and an always-empty
customization string, matching the engine's own `OSSLKMACAlgorithm`
implementation exactly (`OSSLKMAC.h`'s `OSSLKMAC128`/`256` constructors
hardcode `defaultSize` 32/64; `OSSLKMAC.cpp`'s own `signInit` never
sets `OSSL_MAC_PARAM_CUSTOM` at all) — confirmed by reading the actual
crypto class, not inferred from the mechanism table alone. A caller
requesting a non-empty customization string or a different output
length is rejected loudly rather than silently held at the token's own
fixed behavior, the same R10/F36-6 pattern this file's own KBKDF
section already established.

**`OSSL_FUNC_MAC_INIT_SKEY`**: takes the SKEY's own `keydata` directly
— for this provider's AES/GENERIC-SECRET `SKEYMGMT` (`skeymgmt.c`)
that is already a `P11PROV_OBJ*`, the same object type every other
sign path here uses, confirmed by reading `skeymgmt.c`'s own
generate/import functions directly rather than assumed. No raw key
bytes cross into the new `p11prov_mac_init_skey` at any point; it
validates the SKEY's own key type matches what the target algorithm
needs (`CKK_AES` for CMAC, `CKK_GENERIC_SECRET` otherwise) before
taking its own reference and skipping straight to `C_SignInit` — no
ephemeral key creation, because the key already exists as a real token
object.

**Closing the loop on R24, live-verified**: re-ran `skey_flow_probe`
(built for R24, unchanged since) against the now-fixed provider —
check 2 (`EVP_SKEY_import_raw_key` → `EVP_KDF_derive_SKEY` over HKDF →
`EVP_MAC_init_SKEY` over HMAC) now passes end to end where it
previously failed at the very last step, and the byte-for-byte
cross-check against independent, pure-software HKDF+HMAC of the same
known inputs still passes — the whole opaque chain (generate, derive,
*and* consume) is now genuinely proven, not just two-thirds of it.
Harness `T26d` regression-guards this specifically.

**No new bugs found this item** (unlike R22/R24) — the design fell out
cleanly from R24's own diagnosis and R8's existing `mac.c` shape.
**Two genuine bugs in this item's own test cases were found and
fixed**, both the same class of mistake, neither in provider code:
the CMAC/KMAC rejection-control assertions (`T26`/`T26b`) were missing
the `SOFTHSM2_CONF`/`OPENSSL_CONF` env-var prefix every other command
in those same functions carries — without it, the check silently ran
against whatever arena a PRIOR test case had left exported, not this
one, so a rejection that should have failed loudly instead reported
"accepted" from the wrong provider entirely. Caught immediately by
manually reproducing the exact failing command outside the harness
(it correctly rejected) and diffing it against the harness's own
invocation. Separately, `T26`'s own sabotage key was 31 bytes (a
copy/paste hex-string miscount, not a deliberate choice) — an invalid
AES key length the engine correctly rejected, which surfaced as an
unrelated-looking "sabotage" failure until traced to the key length
itself; fixed with `printf 'ff%.0s' {1..32}` (matching T25f's own
established technique for generating a byte string of an exact length,
rather than hand-typing hex and miscounting it again).

New harness cases: T26 (CMAC-AES-256, sabotage + rejection-tested),
T26b/T26c (KMAC-128/256, C++ arm, custom-string rejection), T26d
(closes R24's loop). Full regression: **C++ CTest 8/8 passed** (no C++
engine source changed by this item); Rust `cargo test` not re-run (no
`rust/` source touched — CMAC's own Rust-arm absence was reverified
live, not assumed, before scoping the harness to C++ only). **Harness:
`PASS=66 FAIL=0 XFAIL=0 XPASS=0`** — four cases gained, zero
regressions.

**Phase 5, R25 (HSS param-set-aware provider + cross-engine attribute
standardization), DONE — one real Rust spec bug fixed, one real
under-sizing bug found and fixed in `keymgmt.c`.** Chosen direction
(user, 2026-08-26): keep both engines' differing LM-OTS defaults (C++
W8, Rust W4) and make the provider read the key's ACTUAL parameter set
instead of assuming one.

**The Rust spec bug (found while grounding the plan, confirmed by
reading `ffi.rs` directly):** PKCS#11 v3.2 defines official HSS
attributes (`pkcs11t.h:636-641` in this repo's own vendored copy):
`CKA_HSS_LEVELS` (0x617), `CKA_HSS_LMS_TYPE` (0x618), `CKA_HSS_LMOTS_
TYPE` (0x619). The Rust engine's `CKM_HSS_KEY_PAIR_GEN` arm stored the
LEVEL COUNT under `CKA_HSS_LMS_TYPE`, which per spec is the LMS *type*
— internally self-consistent (its own `handlers.rs` sig-size lookup
read the same attribute back as "levels"), but spec-non-conformant, and
inconsistent with what the C++ engine would need to store for this
item's own read side to work. The C++ engine stored neither official
attribute at all (only `CKA_KEY_GEN_MECHANISM` + a vendor
`ATTR_CKA_HSS_KEYS_REMAINING` counter).

**Fix, both engines (`SoftHSM_keygen.cpp`'s `CKM_HSS_KEY_PAIR_GEN`
block; `ffi.rs`'s same arm; `native/keygen.rs`'s two KMIP-import
registration functions; `handlers.rs`'s sig-size reader retargeted from
`CKA_HSS_LMS_TYPE` to the new `CKA_HSS_LEVELS`):** both now write
`CKA_HSS_LEVELS` = L, `CKA_HSS_LMS_TYPE`/`CKA_HSS_LMOTS_TYPE` = the
top-level IANA type IDs, on both key halves — verified live for the
C++ engine via a throwaway raw-PKCS11 attribute-dump tool (read back
1/5/4 off both public and private objects, matching the documented L=1/
H5/W8 default exactly) before touching any provider code. Rust's own
vendor attrs (`CKA_LMS_PARAM_SET`/`CKA_LMOTS_PARAM_SET`) are kept
unchanged — its ACVP flow reads them.

**Provider reads them (`objects.c`, `sig/hss.c`, `keymgmt.c`):**
`fetch_hss_key` fetches the three official attrs into three new
`struct p11prov_key` fields (optional — `CK_UNAVAILABLE_INFORMATION`
when absent, e.g. a pre-R25-engine or imported key), exposed via three
new accessors (`p11prov_obj_get_key_hss_levels`/`_lms_type`/
`_lmots_type`). `sig/hss.c` gained a real `hss_sig_size(levels,
lms_type, lmots_type)` — the RFC 8554 §5.4/§6.3 formula, ported from
the SAME type-id table already live in the Rust engine's own
`handlers.rs::lms_single_sig_len`/`hss_sig_len` (so the two stay
provably in sync rather than independently re-derived) — replacing the
`HSS_L1_DEFAULT_SIG_SIZE` constant at both sizing-query call sites.
`hss_sig_size_for_key()` wraps it with a documented three-step fallback
for a key lacking the attrs: parse the top-level `u32(L) || lms_type(4)
|| lmots_type(4)` straight out of the (public, or the private key's
own associated public via `p11prov_obj_get_associated`) `CKA_VALUE` —
self-describing per RFC 8554 §5.3/§6.1 — else the original 1296-byte
constant as a last resort, which is honest: it's the only combination
any key created before this session's attribute fix could have. **Real
bug found along the way:** `keymgmt.c`'s `p11prov_hss_get_params` had a
hardcoded `OSSL_PKEY_PARAM_MAX_SIZE` of 1536 ("headroom" over the W8
default's 1296) — silently WRONG for a W4 key (2352 bytes, already
exceeding that "headroom"), which would have undersized every W4
caller's signature buffer. Fixed to share `hss_sig_size_for_key()` with
`sig/hss.c` (declared in `provider.h`, defined non-static in
`sig/hss.c`) so the two can't drift apart again.

**Live proof across two genuinely different parameter sets, not
asserted from a single case that happens to match by coincidence.**
The provider's own HSS keymgmt has no `gen_set_params` surface (kept
that way per this item's own scope decision — a raw tool is smaller);
a new permanent test tool (`scripts/hss-w4-keygen.c`, CMake target
`hss_w4_keygen`) generates a second keypair with EXPLICIT non-default
`CK_HSS_KEY_PAIR_GEN_PARAMS` (LMOTS W4) via direct `C_GenerateKeyPair`,
then the key flows through the provider normally for every later step.
Both parameter sets sign/verify correctly through the provider with
the CORRECT, formula-computed, hand-derived-and-confirmed size (W8:
1296 bytes, matching R9's original derivation; W4: 2352 bytes),
cross-verified by OpenSSL's own independent native LMS implementation,
both sabotage twins (tampered signature, wrong message) rejected by
both the provider and the independent verifier. `scripts/lms-xdr-
verify.c` — previously hardcoded to the single 1296/1292-byte L=1/W8
pair — was generalized to derive its own expected signature length
from the (lms_type, lmots_type) already sitting in the decoded public
key's own first 8 bytes, via the identical ported table, so it now
recognizes a signature from either parameter set rather than only the
one default.

New harness case `T24c` (own arena, `hss_w4_keygen` then sign/verify/
sabotage/cross-verify, mirroring `T24`'s own structure). Full
regression: **C++ CTest 8/8 passed**; **Rust `cargo test --release`:
410 passed, 0 failed, 9 ignored** (no HSS-specific Rust unit test
exists to exercise the attribute fix directly — covered here only by
"the whole suite still passes" plus this item's own live raw-PKCS11
checks against the C++ engine; a dedicated Rust-side HSS attribute
test remains a gap, not just the harness case noted below). **Harness:
`PASS=67 FAIL=0 XFAIL=0 XPASS=0`** — one case gained, zero regressions.

**What remains, explicitly not done by this item:** the Rust-arm
harness case itself (same sign/verify through `libsofthsmrustv3.so`,
now technically unblocked but not yet wired up as a permanent test);
the R9-parked multi-process stateful-counter test; multi-level (L>1)
HSS is still unexercised by anything in this codebase (both engines'
own keygen only ever produces L=1 today, and `hss_sig_size()`'s
multi-level math is accordingly unverified beyond the formula itself);
XMSS/XMSS-MT (R27) remains untouched and parked.

**Phase 5, R26 (ChaCha20 + ChaCha20-Poly1305, ALG-7), DONE — a real
prerequisite bug found and fixed first (AES-CTR/GCM never actually
worked through this provider), three more real bugs found and fixed
while building ChaCha20 on top of the now-shared plumbing, one genuine
architectural limitation found and accommodated by design.**

**The prerequisite, found while designing chacha.c's own shape (before
writing any ChaCha20 code):** `p11prov_cipher_prep_mech`'s own
`CKM_AES_CTR` case was a literal `/* TODO */` stub returning
`CKR_MECHANISM_INVALID` unconditionally — never finished, not broken by
anything this session touched. Separately, `CKM_AES_GCM`'s own
registration code in `provider.c` was present but **dead**: `AES_MECHS`
(the checklist that determines which mechanisms actually get scanned
into a slot's algorithm table) never included it, so the `ADD_ALGO`
block for GCM was unreachable regardless of correctness. Neither gap
was ever caught because nothing in this harness — or, per a live check,
anything else in this project — had ever exercised AES-CTR or AES-GCM
through this provider's own `OSSL_OP_CIPHER` interface before. Both
engines' own native PKCS#11 handling of these mechanisms (confirmed by
reading `SoftHSM_cipher.cpp` and `rust/src/ffi.rs` directly) was never
in question — this was purely a provider-side gap.

**Fixed, and made genuinely shared** (chacha.c needed the exact same
machinery, so this had to stop being AES-private): CTR now builds a
real `CK_AES_CTR_PARAMS` (`ulCounterBits=128`, matching OpenSSL's own
whole-128-bit-counter CTR semantics) instead of misapplying CBC's bare-
IV pattern. GCM's checklist gap is fixed; its own `get_params` gained a
`case MODE_gcm` it never had (the function returned an error for GCM
unconditionally before); its `get_ctx_params`/`set_ctx_params` gained
real `OSSL_CIPHER_PARAM_AEAD_TAG`/`AEAD_TAGLEN` handling that did not
exist anywhere in this provider before this item, plus the AAD-
accumulation and deferred-mechanism-construction machinery described
below.

**The core design problem, and why it applies equally to AES-GCM and
ChaCha20-Poly1305:** PKCS#11's own `CK_GCM_PARAMS`/`CK_SALSA20_
CHACHA20_POLY1305_PARAMS` need the COMPLETE AAD baked into the
mechanism parameter at `C_EncryptInit`/`C_DecryptInit` time. OpenSSL's
own EVP AEAD convention delivers AAD via zero or more `update(out=
NULL)` calls made AFTER `encrypt_init`/`decrypt_init` has already
returned — the mechanism literally cannot be built at the point PKCS#11
wants it built. Solved by deferring the real `CK_*_PARAMS` construction
(and the real `C_EncryptInit`/`C_DecryptInit` call) from `prep_mech` to
a new `p11prov_cipher_ensure_session()`, invoked from the first REAL
(non-AAD) `update()` call or from `final()` if there was none — by
which point all AAD has necessarily arrived. New ctx fields (`is_aead`,
`aead_iv`/`aead_ivlen`, `aad`/`aadlen`, `tag`/`taglen`/`tag_set`) carry
the state across that gap. `update()`'s own `out==NULL` branch now
means "accumulate AAD," matching the EVP convention, and is rejected
loudly (not silently dropped) if it arrives after real data has already
started, or on a non-AEAD mechanism.

**Four real bugs found and fixed while building this, three of them the
same class of mistake — case-label/timing traps that only show up once
something is actually exercised, not visible from reading the code
statically:**

1. `case MODE_gcm:`/`case MODE_poly1305:` never matched their own
   switch expression. `MODE_gcm`'s own macro value already carries
   `MODE_flag_aead`, but the `switch (mode & MODE_modes_mask)` above it
   masks that bit off before comparing — the case label needed the same
   mask (`case MODE_gcm & MODE_modes_mask:`) or it silently fell to
   `default` every time. Caught live: a HARD-propquery `EVP_CIPHER_
   fetch()` of AES-256-GCM failed outright where a SOFT one had masked
   the failure by quietly falling back to software (see finding 3
   below) — chacha.c's own equivalent was rewritten to switch on the
   real `mechanism` constant instead, sidestepping the whole bitmask
   class of bug rather than just patching this one instance.
2. `get_ctx_params(OSSL_CIPHER_PARAM_IVLEN)` read `cctx->is_aead`/
   `aead_ivlen` to decide what IV length to report — but OpenSSL's own
   `EVP_CIPHER_CTX_get_iv_length()` (confirmed by reading `evp_lib.c`
   directly) calls THIS function to compute the `ivlen` it then passes
   TO `encrypt_init`/`decrypt_init` — i.e. it runs before `prep_mech`'s
   own `set_aead_iv()` has ever set `is_aead` true, so it always saw the
   pre-init default and silently reported the wrong length (this
   provider's own generic 16 instead of GCM/ChaCha20-Poly1305's real
   12) — no error anywhere, just a wrong length quietly flowing into
   `encrypt_init`'s own `ivlen` argument. Caught by adding targeted
   `P11PROV_debug()` tracing and watching `aead_ivlen` arrive at
   `prep_mech` as 16, not 12, mid-operation — not visible from reading
   either function in isolation. Fixed by keying off `cctx->mech.
   mechanism` (reliably set from `newctx()` onward) for the mechanism's
   own default, preferring the real negotiated value only once one
   exists.
3. Manual live testing initially used a SOFT propquery (`"?provider=
   pkcs11"`) — with this provider's own "ChaCha20-Poly1305"/"AES-256-
   GCM" registered under the exact same names OpenSSL's default
   provider already uses, `EVP_CIPHER_fetch()` silently resolved to
   software with zero token involvement, every single time, including
   passing a cross-implementation tag comparison against real software
   (trivially, since it secretly WAS software on both sides) — the R22
   "openssl kdf CLI" trap rediscovered one layer down, in `EVP_CIPHER_
   fetch()` instead of a CLI subcommand. Fixed by switching to a HARD
   propquery (`"provider=pkcs11"`) for this item's own new test tooling
   (`aead-probe.c`) and harness cases, which immediately turned the
   silent wrong-answer into a loud, honest fetch failure — surfacing
   findings 1 and 4 that the soft propquery had been hiding.
4. The new harness cases (`T27`/`T27b`/`T27c`/`T27d`) initially failed
   outright even after the case-label and IVLEN fixes and the switch to
   a hard propquery — `EVP_CIPHER_fetch()` failed with "unsupported"
   because none of the four new arenas set `pkcs11-module-load-behavior
   = early`, the exact WART-4/R0.4 lesson this project's own R22
   narrative already documents (a hard propquery with no early module
   load means the provider's own algorithm registry is still empty at
   fetch time, since nothing has yet triggered the lazy module/slot
   scan) — written down once already, not re-applied to this item's own
   new arenas until it broke live. Fixed; all four arenas now set it.

**A genuine architectural limitation found and accommodated, not
patched around — decided by the user (2026-08-26):** GCM/ChaCha20-
Poly1305 decrypt on this engine (`OSSLEVPSymmetricAlgorithm.cpp`)
deliberately withholds ALL plaintext until the tag is verified — a
correct security design (never hand back unauthenticated data) — and
releases the entire message at once once it is. OpenSSL's own
`EVP_DecryptFinal_ex` (confirmed by reading `crypto/evp/evp_enc.c`
directly) hardcodes the buffer it gives a provider's `final()` callback
to exactly `EVP_CIPHER_CTX_get_block_size(ctx)`, with no per-message way
to enlarge it — the two designs are incompatible for any message whose
plaintext doesn't fit in one declared block. (Encrypt never hits this:
ciphertext streams out via `update()` immediately, with no
authentication gate on release.) Accommodated by reporting a generous
but FIXED `AEAD_DECRYPT_MAX_MSG_LEN` (65536 bytes, `cipher.h`) as both
mechanisms' own decrypt-side block size — ordinary messages now work
through the standard `update()`/`final()` API; anything larger fails
cleanly with `CKR_BUFFER_TOO_SMALL`, not silent truncation or
corruption. Documented here as a known, deliberate ceiling, not a bug.

**Live-proven, both mechanisms, both new and prerequisite:** AES-256-
CTR and ChaCha20 (bare stream) byte-identical to software across 200+
bytes (crossing the counter-increment seam past one AES/ChaCha block —
a wrong counter/nonce split would only show up past that point).
AES-256-GCM and ChaCha20-Poly1305 full AEAD workflows (`aead-probe.c`,
a new permanent tool — `openssl enc` itself refuses AEAD ciphers
outright, an unrelated, long-standing CLI limitation): AAD, real
`EVP_CTRL_AEAD_GET_TAG`/`SET_TAG`, both tampered-tag and tampered-
ciphertext sabotage controls rejected BY THE TOKEN ITSELF (confirmed via
engine-log: `Error 64 returned by C_DecryptFinal` on both sabotage
paths, not a software-side check). Cross-implementation proof: same
key/IV/AAD/plaintext through the pkcs11 and default providers produces
byte-identical tags for both mechanisms — genuine cryptographic
correctness, not just internal self-consistency.

**Object-store side-effect, needed for the legacy bytes-in key-import
path both `openssl enc -K <hex>` and `aead-probe.c` exercise:**
`p11prov_cipher_legacy_init` (now shared, was AES-only) hardcoded
`CKK_AES` for every imported key regardless of mechanism — harmless
while only AES existed, wrong for ChaCha20 (the engine's own type check
rejects a `CKK_AES`-typed key for `CKM_CHACHA20`/`_POLY1305`). Fixed to
switch on `cctx->mech.mechanism`. `p11prov_store_aes_key` (`objects.c`)
took an explicit `CK_KEY_TYPE` parameter (was hardcoded `CKK_AES`
internally too) so `CKK_CHACHA20` import shares it rather than
duplicating it, the same pattern R23 already established for CMAC's own
`CKK_AES`-only base key via `p11prov_create_mac_key`.

New harness cases: `T27` (AES-256-CTR, software-parity + round-trip),
`T27_negctl` (R13 negative-control twin), `T27b` (AES-256-GCM full AEAD
workflow), `T27c` (ChaCha20 stream, software-parity + round-trip),
`T27d` (ChaCha20-Poly1305 full AEAD workflow). Full regression: **C++
CTest 8/8 passed**; Rust `cargo test` not re-run (no `rust/` source
touched by this item). **Harness: `PASS=72 FAIL=0 XFAIL=0 XPASS=0`** —
five cases gained, zero regressions.

**What remains, explicitly not done by this item:** AES-CCM (still
genuinely unregistered, out of this item's own scope — user's choice
named AES-CTR/GCM specifically); AES-OFB/CFB* (still the genuine `/*
TODO */` stub, never touched — **reframed by phase-6 R32, see below:
neither engine implements CCM or OFB/CFB\* at all, so this and the CCM
gap above are honest, not open provider work**); the `AEAD_DECRYPT_MAX_MSG_LEN` ceiling
itself has no dedicated over-the-limit test proving it fails cleanly
rather than corrupting something (asserted from code reading, not
independently live-verified — **closed by phase-6 R30, see below**);
ChaCha20's own AAD-only / zero-length-plaintext edge case is untested
(the four new harness cases all use non-empty plaintext — **closed by
phase-6 R30**).

**Phase 6, R30 (AEAD decrypt edge cases), DONE — a real bug found and
fixed exactly where the plan expected one might be, test-first.** Both
edge cases R26 left honestly undone: the `AEAD_DECRYPT_MAX_MSG_LEN`
ceiling had no dedicated over-the-limit test, and ChaCha20-Poly1305's
own AAD-only/empty-plaintext path (the `ensure_session()`-from-`final()`
branch written for zero real `update()` calls) had never actually been
exercised.

**The bug, found by the very first edge-case probe run:** a message at
*exactly* the documented 65536-byte ceiling — the size the ceiling is
supposed to promise WORKS — failed to decrypt. Traced via PKCS#11's own
two-pass `CKR_BUFFER_TOO_SMALL` convention (a failing call reports the
buffer size it actually needed): for a 65535-byte ChaCha20-Poly1305
message, the tag-carrying `DecryptUpdate` call reported needing 65551
bytes — exactly `msglen + 16` (the tag length) — not `msglen` alone.
AES-256-GCM has a genuinely different internal release shape (traced
live, not assumed to match ChaCha20-Poly1305): its own `DecryptUpdate`
call for the tag always returns 0, and the ENTIRE plaintext is released
at `DecryptFinal` instead — but needs that SAME `+16` of headroom there
too (confirmed live: 65520 bytes succeeds, 65521 fails). Same net
effect, two different internal shapes — worth tracing both explicitly
rather than assuming one mechanism's behavior generalizes to the other,
the same lesson R26's own case-label fix already taught this session.
**Root cause:** `AEAD_DECRYPT_MAX_MSG_LEN` was reported as both the
declared block_size AND treated as if it were the usable plaintext
ceiling — it needed to be strictly larger than the promise, not equal
to it. Fixed: split into `AEAD_DECRYPT_MAX_PLAINTEXT_LEN` (65536, the
actual promise) and `AEAD_DECRYPT_MAX_MSG_LEN` (`+64`, the declared
block_size — a safety margin over the observed 16-byte tag overhead,
not just exactly 16, in case some other overhead exists that this
session's own two data points didn't surface).

**Live-proven, both mechanisms:** encrypt has no ceiling at all (100000
bytes succeeds, matches R26's own finding that ciphertext streams out
via `update()` immediately with no authentication gate on release).
Decrypt at exactly the promised 65536-byte ceiling now succeeds for
both AES-256-GCM and ChaCha20-Poly1305; decrypt well over the ceiling
(100000 bytes) fails cleanly — the process stays alive, reports exactly
which EVP call failed, and never returns a truncated-but-"successful"
plaintext (the silent-corruption failure mode this test was written to
rule out, not just "does it error"). AAD-only (empty plaintext, real
AAD) and fully-empty (both empty) both decrypt correctly for both
mechanisms, exercising the zero-real-`update()`-calls path for the
first time.

New permanent tool `aead-edge-probe.c` (deliberately separate from
`aead-probe.c` — different shape: takes a byte COUNT instead of a
message file, and asserts an `expect: decrypt-ok|decrypt-fail`
outcome rather than always expecting success). Built once with
AddressSanitizer to look for silent memory corruption at the buffer
boundary under test; found incompatible with this provider's own
`RTLD_DEEPBIND` dlopen flag for the engine `.so` (a known,
documented sanitizer limitation, not a workaround-able provider issue)
— fell back to the plain build, whose own "process alive + exact
failure point reported" check remains meaningful evidence against
both crash and silent-corruption failure modes, just not as strong as
ASan would have been.

New harness case `T27e` (both mechanisms, all four sub-cases in one
parameterized case, matching `t26_kmac`'s own style). Full regression:
**C++ CTest 8/8 passed**; Rust `cargo test` not re-run (no `rust/`
source touched). **Harness: `PASS=73 FAIL=0 XFAIL=0 XPASS=0`** — one
case gained, zero regressions.

**Phase 6, R29 (HSS follow-up bundle), DONE — a real, provider-level
bug found, affecting both engines.** R9's original goal — proving an
HSS/LMS key's leaf-index counter genuinely advances across two
separate signing operations, the one property that makes a stateful
signature scheme dangerous to get wrong — had never actually been
achieved for either engine before this item; the C++ arm's own T24
signs exactly once, and no harness case anywhere signed the same
stateful key twice and checked the leaf advanced.

**Two test-infrastructure bugs surfaced first, both fixed before the
real one was reachable.** (1) `mk_rust_cnf` never actually set
`SOFTHSM2_CONF`, despite its own comment claiming self-containment —
`softhsm2-util --init-token` is a C++-linked CLI binary that needs a
real config file to complete its own startup regardless of which
engine `--module` points it at. T15a/T15b only ever passed because, in
a full harness run, an earlier C++-arm case had left a real
`SOFTHSM2_CONF` exported and never cleared — order-dependent, and it
broke the moment a Rust-arm case ran standalone. (2) The harness's own
`RUST_ENGINE_SO` auto-discovery prefers the debug build over release;
only `cargo build --release` had been run after R25's own source fix
landed, so the debug `.so` silently predated it and every
default-discovery test was exercising pre-R25 Rust code.

**The real bug, in `src/vendor/pkcs11-provider/src/objects.c`, not
either engine.** With both test-infra bugs fixed, T24e (two signs in
two separate processes sharing one `SOFTHSMRUST_STATE_FILE`) still
produced byte-identical signatures — leaf index `q=0` both times.
Traced by instrumenting `hbs::sign_commit` directly (confirmed it
correctly advances `CKA_PRIV_LEAF_INDEX` on whatever handle it
receives) and capturing a backtrace at the point a second HSS object
got created mid-process: `p11prov_hss_digest_sign_init` →
`p11prov_sig_op_init` → `p11prov_obj_ref` → `cache_key` →
`C_CopyObject`. `cache_key()` (`objects.c:368`) opportunistically
clones a token key into a `CKA_TOKEN=FALSE` session object the first
time a session references it, as a speed optimization for tokens that
support it (`P11PROV_OBJ.cached`) — and every later operation against
that object, including `C_Sign`, targets the clone, not the original.
For an ordinary key this is invisible: the clone is cryptographically
identical and signing is idempotent. For a one-time-signature scheme
it is not — the leaf-index advance a stateful sign performs lands on
the clone, which is session-scoped and is discarded, never written
back to the real token object, when the session/process ends. Every
new process that re-resolves the same key by URI gets the original's
own still-unadvanced state and reuses the same leaf. Confirmed this is
engine-agnostic, not a Rust defect: `C_CopyObject` in the C++ engine
(`SoftHSM_objects.cpp`) mints a fresh `CKA_UNIQUE_ID` session-object
copy the exact same way (verified by reading both implementations
side by side) — the C++ arm was simply never tested against this
exact failure mode. Also confirmed the OUID-generation mechanism
itself is sound and consistent between engines (both correctly mint a
fresh, spec-correct `CKA_UNIQUE_ID` on every copy) — the defect is
entirely in choosing to cache/sign against the copy at all for a
stateful key type, not in how either engine implements copying.

**Fix:** `cache_key()` now skips caching for `CKK_HSS`, and
pre-emptively for `CKK_XMSS`/`CKK_XMSSMT` (XMSS remains unimplemented
per R27, but the same defect would apply the moment it lands), so
`C_Sign` always targets the real token object directly for these key
types. **Live-verified:** manual two-process repro now gives `q1=0`,
`q2=1`; the first signature still verifies after the second consumed
the next leaf.

New permanent harness cases `T24d` (Rust-arm HSS sign/verify, asserts
the real 2352-byte W4 size — proving the provider reads the actual
parameter set, not an assumed default), `T24e` (the multi-process
counter proof itself), and `T24f` (the fallback-path fixture:
verifies a real W4 signature against a public-key object holding
`CKA_VALUE` but deliberately none of the official
`CKA_HSS_LEVELS`/`LMS_TYPE`/`LMOTS_TYPE` attrs, proving R25's
parse-from-`CKA_VALUE` fallback leg genuinely engages rather than
silently agreeing with the 1296-byte last-resort constant). The
parked L>1 multi-level sub-item stays parked, unchanged, per the
plan's own sketch.

Full regression: **harness 76/76** (both arms; three new cases, zero
regressions), **C++ CTest 8/8**, **Rust `cargo test --release` 410+
passed / 0 failed**.

**Phase 6, R31 (TLS13-KDF `derive_SKEY` mode-routing anomaly), DONE —
root-caused as a test-probe gap, no provider bug.** R24's own write-up
(F36-3, above) had left one unexplained observation: a live debug trace
requesting `EXTRACT_ONLY` mode on TLS13-KDF's `derive_SKEY` appeared to
reach `p11prov_tls13_expand_label`, the function backing the
*EXPAND_ONLY* branch — read at the time as a possible mode-routing bug,
deliberately not chased further since HKDF's own complete proof already
answered R24's real question.

**Instrumented and re-ran, timeboxed.** Temporary `P11PROV_debug` lines
at `p11prov_tls13_kdf_derive_skey`'s mode switch (`kdf.c:676`) showed,
live: `hkdfctx->mode` correctly reads `EXTRACT_ONLY`, and the switch
correctly takes the `EXTRACT_ONLY` case — no split-brain ctx bug, no
routing defect. The trace then genuinely does show
`p11prov_tls13_expand_label` running, immediately followed by
`EVP_KDF_derive_SKEY` returning NULL — but reading
`p11prov_tls13_derive_secret()` (`EXTRACT_ONLY`'s own implementation)
explains both: TLS 1.3's Derive-Secret construction (RFC 8446 §7.1) is
itself defined in terms of HKDF-Expand-Label, so the correct
`EXTRACT_ONLY` code path legitimately calls the same shared helper
internally, to turn the caller's salt into a derivation key. That is
expected behavior, not evidence of the wrong branch. The actual
failure: `p11prov_tls13_expand_label()` unconditionally requires a
non-empty prefix+label pair (the RFC 8446 `HkdfLabel` wire format) and
correctly rejects a NULL one — and `skey-flow-probe.c`'s own TLS13-KDF
params never supplied `OSSL_KDF_PARAM_PREFIX`/`OSSL_KDF_PARAM_LABEL`;
its own header comment had explicitly (and, this finding shows,
wrongly) claimed `EXTRACT_ONLY` didn't need them.

**No provider fix required — the provider's behavior was correct.**
Fixed `skey-flow-probe.c` instead: added TLS 1.3's own real `"tls13 "`
prefix and `"derived"` label (the exact pair the real key schedule uses
between the Early and Handshake Secret stages), which took check 3 from
`EVP_KDF_derive_SKEY` returning NULL all the way to a full derive →
token-resident-key → `EVP_MAC_init_SKEY` chain — genuinely
mode-verified now, not existence-only. F36-3's row is corrected above:
this was never a real routing gap.

Regression: **harness 76/76**, **C++ CTest 8/8**; no `rust/` source
touched, `cargo test` not re-run. Root cause found in the first
instrumented run — well inside the timebox, no second session needed.

**Phase 6, R32 (AES-CCM / OFB / CFB\* disposition), DONE — reframed,
not implemented; disposition only, no behavior change.** The previous
session-end gap report listed "AES-CCM still unregistered" and
"AES-OFB/CFB\* still a `/* TODO */` stub" as if they were provider work
waiting to happen. Checked against both engines directly:
**neither engine implements any of them.** `SoftHSM_cipher.cpp`'s
symmetric dispatch handles exactly
ECB/CBC/CBC_PAD/CTR/GCM/CHACHA20/CHACHA20_POLY1305 — no `CKM_AES_CCM`,
`CKM_AES_OFB`, or `CKM_AES_CFB*` anywhere in the C++ engine; the Rust
engine has no trace of them either. A provider registration for any of
these would route to `CKR_MECHANISM_INVALID` at the engine boundary
regardless of what the provider side does. The provider's "gaps" here
are therefore honest, not open work: the OFB/CFB\* stub and CCM's
unreachable dispatch tables front mechanisms that do not exist behind
them.

**Disposition (user's explicit choice, asked at this plan's own
decision point): annotate, don't delete.** Stripping the dead CCM
tables/`case` arms would churn vendored code for zero behavior change
and create upstream-diff noise the comments avoid at near-zero risk.
Annotated both provider sites so the next reader doesn't repeat this
plan's own initial mistake of treating them as unimplemented provider
work: the OFB/CFB\* `/* TODO */` case in `p11prov_cipher_prep_mech`
(`cipher.c`) now states plainly that neither engine implements these
mechanisms, so finishing the stub is pointless without engine work
first; CCM's three `DISPATCH_TABLE_CIPHER_FN(aes, *, ccm, ...)` entries
(`cipher.c`) get the same note, plus CCM's own extra wrinkle if anyone
ever revisits it: PKCS#11's `CK_CCM_PARAMS` needs the total data length
up front, which collides with the streaming EVP API harder than GCM's
AAD-timing wrinkle (phase-6 R30) did.

No behavior change — comment-only. Regression run anyway per this
item's own ground rules, since comments touch compiled files: **harness
76/76**, **C++ CTest 8/8** (one `p11_v32_compliance` failure on the
first run reproduced as pre-existing flakiness — a comment-only diff
cannot change runtime behavior — confirmed by two clean reruns, 8/8
both times). No `rust/` source touched.

**Phase 7, R34 (ML-DSA external-µ vendor mechanism), DONE — F36-6's
"not fixable" claim corrected and shipped as a stopgap.** A user-driven
re-audit of F36-6 found the original claim overstated: PKCS#11 v3.2
(ratified) genuinely has no field for a caller-supplied µ, but PKCS#11
v3.3 will add one natively (OASIS TC tracking issue
[oasis-tcs/pkcs11#58](https://github.com/oasis-tcs/pkcs11/issues/58)),
external-µ preserves pure ML-DSA's own security assumptions rather than
weakening them (FIPS 204's Sign_internal/Verify_internal + NIST's own
FAQ addendum), and a vendor-private stopgap is industry-precedented
(Thales's own proprietary PKCS#11 extension for the related XMSS/LMS
short-message-representative problem). Full research trail and design:
`docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md`.

**Shipped**: `CKM_PQCTODAY_ML_DSA_MU` (`vendor_mechanisms.h`,
`0x80000013`), both engines, provider routing in `sig/mldsa.c`. No new
OpenSSL-facing API — `OSSL_SIGNATURE_PARAM_MU` is already a standard
param name; the provider previously declared it settable only to
reject any non-default value, and now honors it. Two design corrections
surfaced live before commit (full detail in the scope doc's own
execution-update section): (1) µ travels via the normal
`C_Sign`/`C_Verify` data argument — exactly how OpenSSL's own
`ossl_ml_dsa_sign` treats `mu=1` (a flag, not a value-carrying param) —
so the mechanism reuses `CK_SIGN_ADDITIONAL_CONTEXT` verbatim
(rejecting a non-empty context, since none is meaningful once µ
exists) rather than a new struct; (2) the mechanism needed multi-part
(`C_SignUpdate`/`C_SignFinal`) support after all — live-traced via
`PKCS11_PROVIDER_DEBUG` after the Rust arm failed at `C_SignUpdate`:
OpenSSL's own `EVP_DigestSign` machinery drives *every* ML-DSA sign
through Update/Final internally, even a one-shot `pkeyutl -sign` call.
The C++ arm's own first attempt at this item passed only because an
uninitialized `bAllowMultiPartOp` boolean happened to evaluate truthy —
a real bug, caught by the Rust arm's deterministic rejection exposing
what the C++ arm's own undefined behavior was masking. Both engines now
set the flag explicitly, reusing their existing accumulate-then-single-
sign machinery (already proven correct for plain `CKM_ML_DSA`) with no
new buffering logic.

**Live-proven, both arms**: independently-computed µ (Python
`hashlib.shake_256`, replicating `tr = SHAKE256(pk_encode, 64)` then
`µ = SHAKE256(tr‖0x00‖len(ctx)‖ctx‖M, 64)` — verified byte-for-byte
against both engines' own underlying crypto source, `ossl_ml_dsa_sign`
in OpenSSL's `crypto/ml_dsa/ml_dsa_sign.c` for the C++ arm and the
`fips204-patched` crate's `ml_dsa.rs` for the Rust arm, before this
item was built) signs through the vendor mechanism and — the real
cross-implementation proof — the resulting signature verifies against
OpenSSL's **completely independent native** ML-DSA implementation
(`-provider default`, no pkcs11 involvement at all) checked against the
*original raw message*: byte-equivalent to a direct pure-ML-DSA
signature, exactly as the design requires. Four sabotage controls pass
on both arms: tampered µ, tampered signature, non-empty context+mu
rejected, wrong-length µ rejected — all loud, none silent.

New permanent harness cases `T28` (C++ arm) and `T28b` (Rust arm,
twin) — no bespoke C test tool needed; the proof runs entirely on
Python (µ computation) plus OpenSSL's own standard `pkeyutl -pkeyopt
mu:1` CLI flag. Every touch point across both engines and the provider
carries the literal tag `PQCTODAY-VENDOR-EXT-MU`, so the whole
extension is one `grep` away from wholesale deletion once this project
adopts ratified PKCS#11 v3.3 natively.

Full regression: **harness 78/78** (two new cases, zero regressions),
**C++ CTest 8/8**, **Rust `cargo test --release` 410 passed / 0
failed**.

**Phase 7, R35 (HashML-DSA provider surface), DONE — a genuine
self-correction along the way.** While starting this item, re-reading
the ratified spec caught a real error in its own grounding: the earlier
claim that both engines deviate from spec across the whole
`CKM_HASH_ML_DSA*` family was wrong. PKCS#11 v3.2 draws a sharp,
deliberate line the earlier pass missed — §6.67.6 (the one *generic*
`CKM_HASH_ML_DSA` mechanism) wants an already-hashed PHM input, but
§6.67.7 (the ten hash-specific `CKM_HASH_ML_DSA_<hash>` mechanisms,
`_SHA224` through `_SHAKE256`) is an explicitly separate "mechanism
with hashing" pattern — the same shape PKCS#11 already uses for
RSA/DSA/ECDSA elsewhere in the spec — stating plainly: *"This mechanism
computes the entire HashML-DSA specification, including the hashing on
token."* Independently confirmed against the OASIS PKCS#11 TC's own
v3.3 working draft (`oasis-tcs/pkcs11` GitHub repo), identical wording.
Both engines' existing `preHash`-dispatch (the `HASH_MLDSA_CASE` macro
in C++, `Ph`-mapped `try_hash_sign` in Rust) is exactly the §6.67.7
shape — **already spec-correct for 10 of the 11 codepoints**; only the
bare generic mechanism has a real (much narrower) gap, deferred with no
confirmed consumer. This also dissolved what looked like a real
trade-off: a live consumer-inventory sweep (`pqctoday-hub`'s Sign/Verify
Playground genuinely drives `CKM_HASH_ML_DSA_*` with raw typed text)
turned out not to matter, since fixing the routing doesn't touch the
already-correct hash-on-token behavior those 10 mechanisms have.

**The real, remaining gap: pure provider routing, not engine
behavior.** `p11prov_sig_op_init` already parsed a caller's digest name
into `sigctx->digest` — but `p11prov_mldsa_set_mechanism` unconditionally
sent plain `CKM_ML_DSA` and never read it. **Live-confirmed before the
fix**, not assumed: `openssl dgst -sha256 -sign` against a pkcs11
ML-DSA key returned success, and the resulting signature verified as a
**plain, unhashed** raw-message signature — the digest was completely
and silently discarded. The worse of the two hypothesized outcomes.

**Fix**: `p11prov_mldsa_set_mechanism` now maps `sigctx->digest` to the
matching `CKM_HASH_ML_DSA_<hash>` codepoint for the 8 digests reachable
through the provider's own digest-name table today (SHA224/256/384/512,
SHA3-224/256/384/512 — SHAKE128/256 stay unreachable via this path
because `digests.c`'s own name table has no entry for them yet, a
separate pre-existing limitation, not a regression); unmapped digests
get a loud `CKR_MECHANISM_INVALID`, never a silent fallback to pure
ML-DSA. **One real bug found in the Rust arm along the way, same class
as R34's**: the 10 hash-specific mechanisms are explicitly single- and
multi-part per §6.67.7, and OpenSSL's own `EVP_DigestSign` machinery
drives even a one-shot `dgst -sign` through `C_SignUpdate`/`C_SignFinal`
internally — the C++ arm's own dispatch macro has always allowed
multi-part for these (unrelated, pre-existing), but Rust's own
multi-part allowlist never included them. Fixed by adding the
already-existing `is_prehash_ml_dsa()` helper (covering exactly the 10
hash-specific mechanisms, correctly excluding the single-part-only bare
generic one) to that allowlist — no new buffering logic, same
accumulate-then-single-call machinery R34 already proved correct.

**Live-proven**: post-fix, the same `dgst -sha256`-signed signature no
longer verifies as a raw-message signature (proving the digest is
genuinely honored) and round-trips correctly through
`dgst -sha256 -verify`. Negative control: the default provider
explicitly refuses ("Explicit digest not supported for ML-DSA
operations"), confirming the harness case genuinely exercises pkcs11.
Two sabotage controls pass: wrong digest at verify, tampered message.
No independent third-party oracle exists for cross-verification here
(unlike R34's µ — the default provider refuses HashML-DSA entirely) —
the underlying `preHash` crypto in both engines is separately covered
by the Rust crate's own pre-existing ACVP KAT tests
(`native::prehash_kat`/`_slh`, which bypass PKCS#11 entirely); this
item's own proof is specifically that the provider's routing is
correct, verified via round-trip, negative control, and sabotage.

New permanent harness cases `T29` (C++) and `T29b` (Rust, twin — no
Rust engine change needed beyond the multi-part allowlist fix, proving
the provider's shared C routing reaches both engines identically).

Full regression: **harness 80/80** (two new cases, zero regressions),
**C++ CTest 8/8**, **Rust `cargo test --release` 410 passed / 0
failed**.

**Phase 7, R36 (HashSLH-DSA provider surface), DONE — low-surprise
replay of R35, exactly as predicted.** Same shape as ML-DSA's §6.67.6/
§6.67.7 split, mirrored at §6.69.6/§6.69.7 for SLH-DSA: the ten
hash-specific `CKM_HASH_SLH_DSA_<hash>` mechanisms are the "with
hashing" pattern both engines already implement correctly; only the
routing was missing. `p11prov_slhdsa_set_mechanism` gained the
identical digest→mechanism mapping R35 built for ML-DSA; Rust's
multi-part allowlist gained `is_prehash_slh_dsa(mech)`, the SLH-DSA
twin of R35's `is_prehash_ml_dsa` fix. No new findings — both `T30`
(C++, SLH-DSA-SHA2-128s, 7856-byte baseline matching T12sign) and
`T30b` (Rust, twin) passed on the first run.

Full regression: **harness 82/82** (two new cases, zero regressions),
**C++ CTest 8/8** (one `p11test` failure on the first post-change run
reproduced as pre-existing flakiness, confirmed via two clean reruns —
same class as phase-6 R32's own `p11_v32_compliance` flakiness, not a
new finding), **Rust `cargo test --release` 410 passed / 0 failed**.

This closes phase 7's active work (R34, R35, R36). R33 and R27 remain
parked, unchanged.

**Phase 8, R38 (SHAKE128/256 reachability for HashML-DSA/HashSLH-DSA),
DONE — closes the gap R35/R36 each explicitly deferred.**
`CKM_HASH_ML_DSA_SHAKE128/256` and `CKM_HASH_SLH_DSA_SHAKE128/256`
(PKCS#11 v3.2 §6.67.7/§6.69.7) are real, ratified mechanisms both
engines already implemented — but `sigctx->digest` could never hold a
SHAKE value, because `p11prov_sig_op_init`'s shared digest-name lookup
(`digests.c`'s `digest_map`) has no SHAKE entry at all (deliberately: it
also feeds `p11prov_digest_get_digest_size`, whose fixed-length-digest
contract a variable-length XOF doesn't fit). Fix: `mldsa.c`/`slhdsa.c`
each gained a small `*_shake_sentinel()` helper that recognizes
`"SHAKE128"/"SHAKE-128"/"SHAKE256"/"SHAKE-256"` in `digest_sign_init`/
`digest_verify_init`, one layer *before* the shared lookup would reject
them — calling `p11prov_sig_op_init` with `digest=NULL` (skipping the
lookup, keeping the real key/session setup) and setting
`sigctx->digest` to `CKM_SHAKE_128/256_KEY_DERIVATION` directly, used
purely as carrier sentinels (never passed to an actual KDF) that the
existing `set_mechanism` switches now match with two new `case` arms
mapping to the real `CKM_HASH_*_SHAKE128/256` mechanisms. Zero change
to `digest_map` itself, zero impact on any other algorithm's digest
handling.

**Live-confirmed before writing the fix, not assumed**: neither CLI
surface can drive this at all, for reasons that have nothing to do with
this provider — `openssl dgst -shake128/-shake256 -sign` reaches the
provider's `digest_sign_init` fine but `apps/dgst.c` itself then
hard-refuses with `"Signing key cannot be specified for XOF"` (a
hardcoded string in the `openssl` CLI binary, not a core EVP or
provider check); `pkeyutl -sign -digest shakeNNN` refuses even earlier
with `"-digest (prehash) is not supported with ML-DSA-65"` — `pkeyutl`'s
own algorithm allowlist for `-digest` doesn't know about ML-DSA at all.
Both are call-site restrictions in the `openssl(1)` app layer. New
permanent test helper `shake_sign_probe` (`scripts/shake-sign-probe.c`,
registered in `CMakeLists.txt` alongside the project's other bespoke
EVP-API probes) drives `EVP_DigestSign*`/`EVP_DigestVerify*` directly,
reaching the identical provider code path T29/T30's CLI wrapper does,
sidestepping both app-level gates.

**Live-proven, both mechanism families, both digests**: sign + verify
round-trip for ML-DSA-65 under SHAKE256 and SLH-DSA-SHAKE-128s under
SHAKE128 (engine-log-confirmed mechanism `0x2b` = `CKM_HASH_ML_DSA_
SHAKE128` genuinely dispatched, not a coincidental fallback); raw-verify
sabotage (a HashML-DSA signature must NOT verify as a plain raw-message
signature — proves the digest is genuinely honored, not silently
dropped, same shape as T29/T30's own strongest check); tampered-message
sabotage; SLH-DSA-SHAKE-128s signature size matches T30's own
7856-byte SHA2-128s baseline (size is independent of hash family,
T12sign_shake's own precedent).

New permanent harness cases `T31` (C++, both algorithm families) and
`T31b` (Rust, twin — no Rust engine change needed, both
`CKM_HASH_*_SHAKE128/256` arms already existed from R35/R36; proves the
provider's shared SHAKE-sentinel routing fix reaches both engines
identically).

Full regression: **harness 84/84** (two new cases, zero regressions),
**C++ CTest 8/8**. No Rust source touched, so `cargo test` was not
re-run for this item.

This closes phase 8's R38. R37, R39, R40, R41 remain open; R33 and R27
remain parked.

**Phase 8, R37 (bare generic `CKM_HASH_ML_DSA`/`CKM_HASH_SLH_DSA` PHM
conformance), DONE — both engines had the SAME bug, confirmed live
before coding (not the two-different-bugs claim the phase-8 plan's own
first-pass grounding made).** PKCS#11 v3.2 §6.67.6/§6.69.6 define the
bare generic mechanism's data argument as an ALREADY-HASHED PHM ("Length
of hash") — distinct from the ten hash-specific §6.67.7/§6.69.7
mechanisms (R35/R36), which hash a raw message ON TOKEN. New permanent
fixture `generic-hash-mldsa-probe` (raw PKCS#11 C_* API, bypassing the
provider entirely — nothing routes to the generic mechanism through it
by design) found, for BOTH engines: a generic-mechanism signature over
a known PHM verified successfully under the hash-specific mechanism's
own verify fed the PHM *as if it were the message* — i.e. both engines
hashed the caller's already-hashed PHM a SECOND time before the
`0x01‖ctx‖OID‖…` encoding. (This corrects the plan document's own
static-read grounding, which had guessed a DIFFERENT, "pure path" bug
for the C++ engine — struck through with the correction in place,
`docs/openssl-provider-remediation-plan-phase8-2026-08-26.md`'s own R37
section.)

**Fix, both engines:** C++ — `parseMLDSASignContext`/
`parseSLHDSASignContext`'s own `CK_HASH_SIGN_ADDITIONAL_CONTEXT` branch
(fires only for the generic mechanism) now sets a new `phmInput` flag
instead of the wrong `preHash`; `OSSLMLDSA`/`OSSLSLHDSA` `sign()`/
`verify()` build `M′` directly from the caller's PHM via a new
`buildMPrimeFromPHM`/`buildSLHDSAMPrimeFromPHM` (sharing the existing
encoding tail, skipping the internal hash step), with PHM-length
validation against the hash's own digest length; all four
generic-mechanism dispatch sites now correctly set
`bAllowMultiPartOp = false` (single-part only — this mechanism is
unreachable via OpenSSL's Update/Final machinery at all, unlike R34's
own first, wrong attempt at a similar flag). Rust — `remap_generic_hash
_mech` no longer collapses the generic mechanism onto a hash-specific
one; new `try_hash_sign_with_rng_phm`/`hash_verify_phm` trait methods
in both vendored `fips204-patched`/`fips205-patched` crates reuse the
existing internal oid/phm-direct signing primitives (the same shape
R34's own `ext_mu` entry points already established); a new
session-keyed `GENERIC_HASH_STATE` side-table (kept separate from
`SIGN_STATE`/`VERIFY_STATE`'s own tuple shape, same rationale as the
pre-existing `SIGN_RECOVER_STATE`) carries the caller's chosen digest
from `*Init` to `C_Sign`/`C_Verify` now that `mech_type` itself no
longer encodes it.

**Two pre-existing tests were themselves built on the same wrong
assumption R37 fixes, and only started failing once the bug they
(accidentally) depended on was gone** — `p11_v32_compliance_test.cpp`'s
two generic-mechanism cases and one Rust FFI unit test all fed the
generic mechanism a raw message; their prior green result was evidence
of the double-hash bug, not of correctness. Both fixed to feed a
genuine SHA-256 PHM (full detail in the plan doc's own execution
update).

**Live-proven, both engines, both algorithm families**: a
generic-mechanism signature over a known PHM now verifies correctly
under the hash-specific mechanism's own verify fed the original message
(the conformant oracle — the two mechanisms are defined to be
verify-interchangeable for `PHM = H(M)`, the strongest available check
since OpenSSL has no HashML-DSA/HashSLH-DSA at all); neither the
"pure path" nor the "double-hash" bug hypothesis reproduces post-fix;
wrong-length PHM rejected loudly on both engines; multi-part
(`C_SignUpdate`) correctly rejected on both.

Full regression: **harness 84/84** (unchanged — the generic mechanism
isn't reachable through the provider, so no new harness case), **C++
CTest 8/8** (after fixing `p11_v32_compliance_test.cpp`'s own wrong
assumption — first run surfaced 2 genuine new failures, root-caused to
the test), **Rust `cargo test --release` 410/410** (same story, 1
failure, same root cause).

This closes phase 8's R37. R39, R40, R41 remain open; R33 and R27
remain parked.

**Phase 8, R39 (`CKM_PQCTODAY_ML_DSA_MU_GEN`: token-side µ computation),
DONE — the produce half of external-µ, completing what R34 started.**
R34 (phase 7) shipped the *consume* half (sign a caller-supplied µ);
the PKCS#11 v3.3 working draft's own second external-µ mechanism,
`CKM_ML_DSA_EXTERNAL_MU_GEN`, computes µ ON THE TOKEN instead — a
digest-type mechanism (`C_Digest`/`C_DigestUpdate`/`C_DigestFinal`)
so a caller can stream an arbitrarily large message through
`C_DigestUpdate` and get back the 64-byte µ = `SHAKE256(tr‖0x00‖len(ctx)
‖ctx‖M, 64)` (FIPS 204 Eq. 2) without ever buffering the whole message
or implementing the SHAKE256/`tr` derivation itself. Shipped as
`CKM_PQCTODAY_ML_DSA_MU_GEN` (`0x80000014`, vendor range,
`PQCTODAY-VENDOR-EXT-MU`-tagged alongside R34's own mechanism —
**engines only, deliberately no OpenSSL-provider wiring**: an OpenSSL
caller already holds the public key and can compute µ trivially in
software, so provider wiring would add surface with no consumer.

**C++**: first-ever SHAKE-family `HashAlgorithm` implementation in this
engine (`OSSLMuGenDigest`) — `OSSLCryptoFactory::getHashAlgorithm` had
no `HashAlgo::SHAKE128/256` case at all before this (confirmed by
reading it, not assumed). Deliberately not built on the existing
`OSSLEVPHashAlgorithm` base (its `hashFinal()` uses `EVP_DigestFinal_ex`,
wrong for a XOF) and deliberately not registered as a general
`HashAlgo::Type` (fixed 64-byte output only, nothing else needs a
general SHAKE256 digest through this interface). The new
`CKM_PQCTODAY_ML_DSA_MU_GEN` case in `C_DigestInit` resolves `tr`
(one-shot `EVP_DigestFinalXOF` over a key handle's `CKA_VALUE`, or a
caller-precomputed 64 bytes) and seeds the digest with `tr‖0x00‖len(ctx)
‖ctx` before returning — `C_DigestUpdate`/`C_DigestFinal`/`C_Digest`
needed zero changes, already generic over `HashAlgorithm`.

**Rust**: `DigestCtx` gained a `MuGen(sha3::Shake256)` variant; a new
`ck_param::mu_gen_params` layout (own both-ABI offset-table row) parses
`CK_PQCTODAY_MU_GEN_PARAMS`; the existing exhaustive `match ctx { ... }`
dispatch in `C_DigestUpdate`/`C_DigestFinal`/`C_Digest` picked up the
new arm everywhere the compiler required it — exhaustiveness checking
was the correctness guardrail here, not manual auditing.

**Live-proven, both engines, first try (no fix-then-refix cycle this
time)**: new permanent fixture `mu-gen-probe.c` (raw PKCS#11 C_Digest*
API) proves µ from the mechanism is byte-identical to an independently
computed `SHAKE256(SHAKE256(pk,64)‖0x00‖len(ctx)‖ctx‖M,64)`; multi-part
`C_DigestUpdate` (2 calls) equals one-shot `C_Digest`; the
TR-supplied and handle-supplied paths produce the identical µ for the
same key; the token-computed µ, fed into R34's own
`CKM_PQCTODAY_ML_DSA_MU`, signs a signature that verifies under that
same mechanism (R34's own T28/T28b already independently proved that
mechanism's signatures verify under OpenSSL's native ML-DSA, so this
isn't re-derived here — re-proving it would just re-prove R34, not
R39); both-absent and both-present `hTrKey`/`pTr` rejected loudly.

Full regression: **harness 84/84** (unchanged — engines-only, nothing
routes through the provider), **C++ CTest 8/8**, **Rust `cargo test
--release` 410/410** — both clean on the first run.

This closes phase 8's R39. R40, R41 remain open; R33 and R27 remain
parked.

## 7. Companion document

Remediation priorities, effort estimates and sequencing:
`docs/openssl-provider-remediation-plan-2026-08-25.md`.
