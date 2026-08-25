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
| DECODER | `DER<-pem`; RSA/RSA-PSS/EC/ED25519/ED448 from DER | **no ML-DSA/ML-KEM/composite decoders** (composite ones defined but unregistered — recursion issue, `provider.c:1512-1525`) |
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
| OP-2 | No DECODERs for ML-DSA / ML-KEM / composites → **URI-PEM round-trip broken for PQC keys** (keygen writes the PEM; loading it back fails `store_result.c:160 unsupported` — proven live). Workaround: raw `pkcs11:` URIs, which do work | live probe; `provider.c:1500-1525` | **High** |
| OP-3 | No ML-KEM encoders at all (no SPKI, no URI-PEM) — ML-KEM public keys can only leave via `pkey -pubout` on a URI-loaded key; latchset sibling tree has these encoders to port | `provider.c:1395-1494` vs `vendor/latchset/src/provider.c:1445-1457` | Medium |
| OP-4 | KEM dispatch lacks `SET_CTX_PARAMS`/`SETTABLE` | `kem/mlkem.c:259-289` | Low |
| OP-6 | **ML-KEM keys cannot be GENERATED on token through the provider** — the ML-KEM keymgmt has no `OSSL_FUNC_KEYMGMT_GEN*` entries (`kem/mlkem.c`, confirmed zero hits) and `genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768` dies live with `gen_init: operation not supported for this keytype`. ML-DSA keygen works, so this is an asymmetry, not a design rule. Blocks any native software-encap→token-decap E2E (today that flow is proven only on the WASM path, where keys are created via the wasm API) | live probe + source | **High** |
| OP-5 | KDF surface is HKDF+TLS13-KDF only; engines also offer PBKDF2 and SP800-108 counter/feedback KDFs that OpenSSL has standard fetch names for | `provider.c:1161` vs engine KDF mechs | Low–Medium |
| WART-1 | Every provider token scan spams the C++ engine log: `ObjectFile.cpp(181): The attribute is not a byte string: 0x0/0x1/0x2/0x86/0x100/0x170-0x172/0x601` — provider queries CKA_CLASS/CKA_TOKEN/CKA_PRIVATE/CKA_TRUSTED/CKA_KEY_TYPE/CKA_MODIFIABLE/CKA_COPYABLE/CKA_DESTROYABLE/etc. with byte-string templates | observed on every live probe | Low (noise; masks real errors) |
| WART-3 | Build hygiene: the gitignored WASM-generated `src/config.h` leaks into the **native** CMake build — compile warnings `"PACKAGE_MAJOR redefined"` and the live provider reports version **1.1** (config.h) while CMake defines **0.4.0** | observed in gate build log + live `list -providers` | Low |
| WART-4 | **RESOLVED (R0.4, 2026-08-25 later same day)** — was: mechanism-gated operation tables are invisible to fresh-process fetches: `openssl list` shows nothing `@ pkcs11` for signature/KEM, AND a strict property-targeted fetch (`dgst -sha256 -propquery provider=pkcs11`) **functionally fails** in a fresh process (`inner_evp_generic_fetch:unsupported`) — operations only resolve once a token object forces module init in-process. Fix: the provider already ships `pkcs11-module-load-behavior = early` for exactly this case (forces the same lazy-init call from inside `OSSL_provider_init()` instead of leaving it to a key-object path); wired into the harness's T9 arena. See `docs/openssl-provider-remediation-plan-2026-08-25.md` R0.4 for the full story, including a real `mk_arena()` ordering bug it exposed and fixed along the way. | live probes (T9) | ~~Medium~~ |
| WART-5 | The C++ engine rejects OpenSSL's SHA-1 OAEP defaults (`Invalid hashAlg/mgf combination for RSA-OAEP`, `SoftHSM_keygen.cpp:8056`) — plain `-pkeyopt rsa_padding_mode:oaep` against a token key fails until the caller pins `rsa_oaep_md`/`rsa_mgf1_md` (sha256 verified working). Likely deliberate FIPS posture; needs documenting, not fixing | live (T5's first run) | Low (interop caveat) |

### B. Backend algorithms not exposed

| ID | Gap | Engine support | Provider state | Severity |
|---|---|---|---|---|
| ALG-1 | SLH-DSA (all 12 sets) | both engines, 13 mechs each | `sig/slhdsa.c` is a `{0,NULL}` stub AND the registration branch is unreachable (`CKM_SLH_DSA` absent from `checklist[]`/`PQC_MECHS`, `provider.c:859`); OpenSSL 3.6 has native names/OIDs to mirror | **High** |
| ALG-2 | XMSS/XMSS-MT | both engines (sign+verify, stateful) | `sig/xmss.c` stub, unreachable; no native OpenSSL names exist (custom names required; no CMS/TLS story) | Medium |
| ALG-3 | HSS/LMS | both engines **sign+verify** | nothing in provider; OpenSSL 3.6 native LMS is *verify-only* → token-sign/OpenSSL-verify is a uniquely coherent split, but blocked by ENV-1 (no `enable-lms` in staged build) | Medium |
| ALG-4 | Composite profiles 4–8 | KMIP layer has all 8 §10.4 profiles | provider `composite.c` registry has 3; missing 5 include **all four §10.4-recommended** (MLDSA44-Ed25519-SHA512, MLDSA44-ECDSA-P256-SHA256, MLDSA65-RSA3072-PSS-SHA512, MLDSA65-Ed25519-SHA512) + MLDSA65-ECDSA-P384-SHA512 | Medium–High |
| ALG-5 | X25519/X448 key exchange | both engines advertise CKM_X25519/X448 | registration branch dead (checklist omission) — likely a 2-line fix | Medium |
| ALG-6 | ECDH-as-KEM | both engines flag ENCAP/DECAP on `CKM_ECDH1_DERIVE` | not exposed as an OSSL KEM | Low |
| ALG-7 | ChaCha20 / ChaCha20-Poly1305 | both engines | cipher table is AES-only | Low |
| ALG-8 | HMAC/CMAC/KMAC as EVP_MAC | both (CMAC C++-only, KMAC both) | see OP-1 | Medium |
| — | FrodoKEM / Classic McEliece (Rust vendor mechs), BIP32, Keccak-256, split-key | Rust engine / KMIP | deliberately out of OpenSSL scope — recorded, not gapped | — |

### C. New 3.6 features unused

| ID | Gap | Evidence | Severity |
|---|---|---|---|
| F36-1 | `TLS-GROUP` capability registers **zero** PQC/hybrid groups — in any TLS handshake the ML-KEM share is computed by OpenSSL's software, never the token, even with the provider active. The staged 3.6.3 has group names MLKEM512/768/1024 + 3 hybrids natively for comparison | `tls.c:89-174`; live `-tls-groups` | **High** (flagship PQC story) |
| F36-2 | LMS: OpenSSL 3.6's new verify-only LMS unused (see ALG-3, ENV-1) | release notes + live build | Medium |
| F36-3 | `EVP_SKEY` KDF/KEYEXCH integration (3.6): provider has SKEYMGMT but the new `EVP_KDF_derive_SKEY`-style opaque-key flows are unprobed — token-resident secrets may not chain into OpenSSL KDFs without export | 3.6 CHANGES; needs probe (T-plan P2) | Medium |
| F36-4 | *(positive baseline, not a gap)* CMS KEMRecipientInfo + `OSSL_PKEY_PARAM_CMS_RI_TYPE` already wired for ML-KEM (local commit `2cca4f0`) — must be regression-guarded by the new harness | `kem/mlkem.c:414-433` | — |
| F36-5 | NIST security-category PKEY param (new 3.6) not exposed by provider keymgmt | 3.6 release notes | Low |
| F36-6 | ML-DSA signature params: provider plumbs `context-string` + hedging (`9cc52e6`/`d895c1a`); `mu`/`message-encoding`/`deterministic` parity vs software unverified | source + EVP_SIGNATURE-ML-DSA(7) | Low–Medium |

### Environment / infrastructure findings

| ID | Finding |
|---|---|
| ENV-1 | Staged OpenSSL 3.6.3 (`/usr/local/ssl` in `pqc-rust`) built **without** `enable-lms` — LMS test/remediation work needs a rebuilt oracle first. |
| ENV-2 | **Native Rust-engine arm is structurally blocked**: `rust/src/state_snapshot.rs:1-27`'s own doc — all token state is in-memory; the snapshot/restore surface exists but is wired only for the WASM embedding. Any multi-process CLI flow (genpkey, then pkeyutl) loses the token between processes, and no script in the repo has ever pointed the provider at the native Rust cdylib (`grep -rl libsofthsmrustv3` over scripts/configs → differential harness only). Provider+Rust coverage today exists ONLY on the WASM static-link path (hub e2e). |
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
| T4x | ML-KEM token keygen (OP-6) | provider keygen lands a key on token | **XFAIL** (flips on R3b; the full software-encap → token-decap E2E from the original plan is unreachable until then) |
| T5 | RSA-3072 | token keygen → PKCS#1 sign → software verify; software OAEP-encrypt → provider decrypt | PASS |
| T6 | ECDSA P-256 | token keygen → sign → software verify | PASS |
| T7 | Ed25519 | token keygen → sign → software verify | PASS |
| T8 | ECDH P-256 | provider derive vs software derive — same shared secret | PASS |
| T9 | Digest fetch (WART-4) | `dgst -propquery provider=pkcs11` in a fresh process, dedicated arena with `pkcs11-module-load-behavior=early` | **PASS** (flipped by R0.4, 2026-08-25) |
| T10 | URI-PEM round-trip, EC (control) | genpkey URI-PEM → load back → sign | PASS |
| T11 | URI-PEM round-trip, ML-DSA (OP-2) | same flow | **XFAIL** (flips on R2) |
| T12 | SLH-DSA reachability (ALG-1) | provider-propquery SLH-DSA-SHA2-128s keygen | **XFAIL** (flips on R1) |
| T13 | TLS-GROUP gap (F36-1) | not CLI-checkable cleanly (`list -tls-groups` merges all providers) — plan-only P2; the gap itself is source-anchored (`tls.c:89-174`) | plan-only |
| T14 | CMS RSA | CMS sign via token key → software cmsverify | PASS |
| T15a/b | Rust arm | provider activates over `libsofthsmrustv3.so` (PASS); multi-process functional flow (XFAIL, ENV-2) | PASS + **XFAIL** (flips on R6) |
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
see the remediation plan for the full story). The harness now reads
`OPENSSL-PROVIDER-HARNESS: PASS=14 FAIL=0 XFAIL=4 XPASS=0` — T9 flipped
from XFAIL to PASS; WART-4 is resolved (§4A above); WART-1/3/5 are
resolved/documented. Remaining XFAILs: OP-6 (T4x), OP-2 (T11), ALG-1
(T12), ENV-2 (T15b) — all still plan-only, Priority 1/2 items.

## 7. Companion document

Remediation priorities, effort estimates and sequencing:
`docs/openssl-provider-remediation-plan-2026-08-25.md`.
