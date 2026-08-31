# OpenSSL provider remediation plan (2026-08-25) — plan, with the P0 batch executed

Companion to `docs/openssl-provider-coverage-audit-2026-08-25.md` (gap
IDs referenced from there). Per the user's decision (2026-08-25):
remediations are planned and prioritized here but **not executed** under
the audit; each item runs later under its own go-ahead. Every item names
the test that must flip from XFAIL→PASS (or be newly added green) so
completion is observable, not claimed — the harness fails on unexpected
XFAIL passes, so landing a fix without updating the expectation is
loudly visible, and vice versa.

**Update (2026-08-25, later same day):** the user asked to start
remediation execution with the P0 batch. R0.1/R0.2/R0.3/R0.5 landed
(commit `3bf6f56`). R0.4's first attempt caused a real regression and
was reverted; a second, careful attempt found the provider already
ships the real fix as an opt-in config directive and landed it — see
its row below. **P0 batch is now fully done: harness was
`PASS=14 FAIL=0 XFAIL=4 XPASS=0`.**

**Further update (2026-08-25, same day):** user asked to continue with
R1 (SLH-DSA end-to-end, the highest-value P1 item). Landed **partially**:
keygen/store/encode work for all 12 parameter sets (two real, unrelated
bugs found and fixed along the way — see R1's row); token **sign** itself
still fails with a not-yet-root-caused OpenSSL-side fetch error. Harness
was `PASS=15 FAIL=0 XFAIL=4 XPASS=0` (T12 flipped PASS, rescoped; new
T12sign added XFAIL, tracking the remaining gap).

**Further update (2026-08-25, same day) — R1 root-caused and finished:**
the user asked to check the actual OpenSSL 3.6 documentation for the
sign gap rather than continue guessing. That was the answer:
provider-signature(7) documents a mandatory pairing rule our
signature tables violated (see R1's row for the full mechanism). Fix
written, built, and verified live — T12sign flipped XPASS exactly as
predicted the instant the fix landed (ratchet caught it, as designed),
then was upgraded into a real test (exact FIPS 205 signature size +
independent software verify + tamper rejection) plus a second,
independent case for a SHAKE variant to prove it's not a SHA2-only
fix. **R1 is now fully done.** Harness is `PASS=17 FAIL=0 XFAIL=3
XPASS=0`. Everything else below P0 is still plan-only, unchanged.

**Further update (2026-08-25, same day) — R3b landed, one new gap
found along the way:** the user chose R3b (ML-KEM token keygen) next.
Landed as sketched — see R3b's row below — and along the way surfaced
a real, previously undocumented gap: ML-KEM has zero encoders
registered at all, so `genpkey -out` cannot serialize the generated key
even though generation itself works. That's OP-3 (already tracked as
R3, still plan-only) — not scope creep into R3, just a more precise,
live-confirmed description of exactly what R3 needs to fix, discovered
because R3b's own test (T4x) turned out to be accidentally coupled to
it. Harness is now `PASS=18 FAIL=0 XFAIL=3 XPASS=0`.

**Further update (2026-08-25, same day) — phase-2 plan written:** every
remaining item (R2/R3/R4/R5/R6 and the P2 tail) was re-explored against
the source and re-planned in detail — several scopes changed materially
on re-inspection (R4 in particular gained two newly found latent bugs
and grew from S to M), and a KMIP-crate cross-reference section was
added. **The detailed, current plan for all remaining work is
`docs/openssl-provider-remediation-plan-phase2-2026-08-25.md`** — the
P1/P2 rows below stand as the original record but are superseded by
that document for execution.

## Priority 0 — correctness / hygiene of what already ships

| # | Item | Gap | Status | Sketch (original) | Effort | Proof |
|---|---|---|---|---|---|---|
| R0.1 | Quiet the token-scan attribute-type noise | WART-1 | **DONE** | ~~Root-cause which side is wrong: provider queries CKA_CLASS/CKA_TOKEN/etc. with byte-string templates vs C++ `ObjectFile.cpp:181` warning on non-bytestring attrs...~~ Actual root cause (found live via gdb, not the guessed "spec-legal probing"): `P11Objects.cpp`'s mandatory-attribute-check loop called `getByteStringValue()` on every attribute in the object's full schema to compute `selfEmpty`, even though only the ck14/15/16-flagged cert attributes ever read it. Gated the block on those flags. | S | **Live-verified**: 0 `ObjectFile.cpp(181)` hits on a required-propquery genpkey (was 41/key). Full C++ ctest 8/8 green. New harness regression guard added and sabotage-tested (reverted the fix on a copy → guard caught 449 hits, exit 1). |
| R0.2 | Native build must not inhale the WASM `config.h` | WART-3 | **DONE** | ~~`gen-pkcs11-provider-config-h.sh` output is for the emcc path only...~~ Confirmed nothing in the native path ever generated `config.h` at all — a fresh checkout with no prior WASM build would fail to compile outright, not just warn. Fixed by having CMake generate it at configure time, version derived from meson.build's own `version:` field (single source of truth across native/meson/WASM). | S | **Live-verified**: `list -providers` reports `version: 1.1` (was the stale hardcoded `0.4.0`); zero `PACKAGE_*` redefined warnings in a clean rebuild. |
| R0.4 | Fresh-process operation fetch (lazy-init) | WART-4 | **DONE** | Root-cause why mechanism-gated tables don't resolve for property-targeted fetches before a token object is referenced (likely `operations_init` ordering vs `query_operation`); harness T9 flips when fixed | M | Root cause confirmed: `p11prov_query_operation()` returns `ctx->op_digest`/etc. directly, populated only by `operations_init()`, itself only triggered lazily via `p11prov_ctx_status()` from key/session code paths — a fetch with no key ever loaded gets `NULL` once, no retry. **First fix attempt reverted**: calling `p11prov_ctx_status(ctx)` unconditionally at the top of `p11prov_query_operation()` forced full PKCS#11 module init on every operation-id query and made the provider disappear from `list -providers` entirely — live-tested, caught before commit. **Second attempt found the real fix already exists**: `OSSL_provider_init()` itself supports an opt-in `pkcs11-module-load-behavior = early` config directive that calls the exact same `p11prov_ctx_status()`, but from its own straight-line init code rather than from inside a fetch callback — tested directly (unmodified provider source) and it resolves T9's scenario cleanly. Lazy-by-default module loading is a deliberate trade-off (don't open a token connection when the caller never uses one), same category as R0.5's OAEP mismatch — document/configure around it, not "fix" it. **Second real bug found and fixed along the way**: wiring `early` into T9's arena exposed a genuine ordering bug in `mk_arena()` itself — its internal `softhsm2-util --init-token` call ran *before* `use_arena()` reset `OPENSSL_CONF` to the new arena's own config, so it inherited whatever the *previous* test's arena had exported. `softhsm2-util` links libcrypto, which auto-loads `OPENSSL_CONF` on first use — with a stale config that activates `pkcs11-module-load-behavior=early`, it ended up double-`C_Initialize`-ing the same engine `.so` from within one process, failing with `CKR_CRYPTOKI_ALREADY_INITIALIZED` ("SoftHSM is already initialized"). This silently broke T10 and T14 (any test running *after* T9) the moment T9 started using `early`. Fixed with the same `OPENSSL_CONF=/dev/null` pattern T8 already uses for its software peer keygen, applied to both `mk_arena()`'s and T15b's own `softhsm2-util` calls. | T9 XFAIL→PASS (harness now `PASS=14 FAIL=0 XFAIL=4 XPASS=0`); T9 itself sabotage-tested (flipped assertion → FAIL, exit 1); full run repeated 4× clean after the `mk_arena` fix, confirming T10/T14 stayed green. |
| R0.5 | Document the OAEP-defaults mismatch | WART-5 | **DONE** | Engine rejects SHA-1-default OAEP (likely deliberate FIPS posture) — document the required `rsa_oaep_md`/`rsa_mgf1_md` pins in the provider README/HOWTO rather than "fixing" either side | S | Added to `src/vendor/pkcs11-provider/README.md` with a working example matching harness T5. |
| R0.3 | Retire dead test assets | ENV-3 | **DONE** | Delete or rewrite `test_openssl_integration.sh` + `openssl_test.cnf` in favor of `scripts/test-openssl-provider.sh` (this audit's harness); note the dormant vendored meson suite in the vendor README as intentionally unwired | S | Both files deleted; vendor README now documents the meson suite as intentionally unwired (assumes upstream's build layout/token backend, not this fork's). |

## Priority 1 — high-value coverage gaps

| # | Item | Gap | Sketch | Effort | Proof |
|---|---|---|---|---|---|
| R1 | **SLH-DSA end-to-end** — **DONE (2026-08-25, later same day): all 12 param sets, keygen/store/encode/sign** | ALG-1 | ~~Add `CKM_SLH_DSA`/`CKM_SLH_DSA_KEY_PAIR_GEN` to `PQC_MECHS`/`checklist[]`; implement `sig/slhdsa.c` keymgmt+signature (model: `sig/mldsa.c`); SPKI encoder like ML-DSA's~~ Done as sketched, for all 12 parameter sets (not just SHA2-128s/SHAKE-128f) — full `sig/slhdsa.c`, 12 keymgmt tables in `keymgmt.c`, SPKI/text/URI-PEM encoders in `encoder.c`. Landing it surfaced **two real, pre-existing bugs unrelated to registration**, both now fixed: (1) `p11prov_obj_from_handle`'s key-type switch (`objects.c`) had no `CKK_SLH_DSA` case — fell into `default: return CKR_ARGUMENTS_BAD`, so a freshly-generated key could never be read back, even though the engine had already created it correctly (confirmed via C++ engine DEBUG logs — both PUBLIC and PRIVATE objects were created on-token before the provider-side failure). Added `fetch_slhdsa_key()`, sizes (32/48/64-byte PK per FIPS 205 security level) cross-checked live via `openssl asn1parse` on native 3.6.3 SPKI output. (2) `store.c`'s key-type-to-`data_type`-name switch (used by `pkcs11:` URI resolution) had the same gap, silently dropping SLH-DSA objects from `storeutl` enumeration entirely (empty output, no error). Both are the same *class* of bug as each other — a type-specific dispatch switch missing the new `CKK_SLH_DSA` case — found only by tracing live C++ engine logs after the generic "Invalid or improper arguments" provider error gave no line number. **Remaining, unresolved gap**: `pkeyutl -sign` against a correctly-created, correctly-enumerable on-token key fails at OpenSSL's own EVP fetch layer ("operation not supported for this keytype", not a provider-side error) — confirmed via a temporary debug print that the provider's 12-variant signature registration switch case runs to completion with byte-identical name strings across all three registration sites (keymgmt/signature/store); `openssl list -select` and gdb were both tried and found unreliable for this specific question (`list` never shows `@ pkcs11` for ML-DSA either, a known-working case, so it can't distinguish the two). **ROOT CAUSE FOUND (2026-08-25, follow-up investigation, at the user's explicit prompt to check the OpenSSL 3.6 documentation):** the SLH-DSA signature dispatch tables violate OpenSSL's documented provider-signature consistency contract. provider-signature(7), 3.6: *"The OSSL_FUNC_signature_set_ctx_params() and OSSL_FUNC_signature_settable_ctx_params() functions are optional, but if one of them is provided then the other one must also be provided. The same applies to the OSSL_FUNC_signature_get_ctx_params() and OSSL_FUNC_signature_gettable_ctx_params() functions."* Our 12 tables registered `GETTABLE_CTX_PARAMS` **without** `GET_CTX_PARAMS` (mldsa.c's working tables have both). Enforcement confirmed in 3.6 source (`crypto/evp/signature.c`, `evp_signature_from_algorithm`): `(gparamfncnt != 0 && gparamfncnt != 2)` → `EVP_R_INVALID_PROVIDER_FUNCTIONS` → method construction returns NULL → the provider-constrained fetch in `do_sigver_init` (m_sigver.c) gets no method and raises the exact observed error, `OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` — before any provider sign code ran, which is why every provider-side probe last session showed nothing wrong. Explains the whole evidence pattern: registration/names fine, keymgmt/store/encoder fine (their own tables satisfy their own invariants), ML-DSA fine (complete pair).

**FIX WRITTEN AND VERIFIED (same day):** implemented `p11prov_slhdsa_get_ctx_params`, returning `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` per parameter set — 12 DER AlgorithmIdentifiers on the NIST sigAlgs arc, OIDs 2.16.840.1.101.3.4.3.**20–31** (live-confirmed from `openssl list-signature-algorithms`), `sig/slhdsa.c`, mirroring mldsa.c's `der_ml_dsa_*` byte-array pattern with final arc octets 0x14–0x1f; added `ALGORITHM_ID` to the gettable list and `GET_CTX_PARAMS` to all 12 dispatch tables. **Applied the caveat correctly**: dispatch is on `p11prov_obj_get_key_param_set(sigctx->key)` (the token's own `CKA_PARAMETER_SET`), not key size — SLH-DSA SHA2 and SHAKE variants at the same security level share identical key sizes (128s of either hash family = 32-byte PK), so mldsa.c's size-based approach would have picked the wrong OID silently. **Live result**: rebuilt, ran the harness — T12sign flipped to XPASS on the very first run after the fix, exactly as predicted (the ratchet caught it and failed the run, as designed, forcing the expectation update rather than a silent pass). Manually confirmed real cryptographic correctness, not just "didn't error": SHA2-128s signs at exactly 7856 bytes (FIPS 204... FIPS 205 Table 2), independent OpenSSL software verify succeeds, a flipped signature byte is correctly rejected; SHAKE-128f (independent hash family, different arena to avoid the URI-ambiguity trap the audit's own methodology already warns about) signs at exactly 17088 bytes and independently verifies. | L | T12 flipped from XFAIL to **PASS**, rescoped to what it actually tests (keygen+store+encode reachability — its original propquery had its own bug, fixed to match every other genpkey call in the harness). **T12sign** rewritten into a real test — SHA2-128s full round trip (exact FIPS 205 size + independent verify + tamper rejection) — now **PASS**; sabotage-tested (flipped size assertion → FAIL, exit 1). New **T12sign_shake** added, SHAKE-128f independent hash-family cross-check, **PASS**; sabotage-tested (flipped size assertion → FAIL, exit 1). Harness: `PASS=17 FAIL=0 XFAIL=3 XPASS=0`, stable across repeated runs. |
| R2 | **PQC decoders (URI-PEM round-trip)** | OP-2 | Register ML-DSA + ML-KEM decoders (`input=der,structure=P11PROV_DER_STRUCTURE` like RSA/EC's); the URI-PEM body is provider-defined DER, so no d2i_X509_PUBKEY recursion applies (that issue was composite-SPKI-specific, `provider.c:1512-1525`) | M | T11 flips; add ML-KEM variant |
| R3 | **ML-KEM encoders** | OP-3 | Port the latchset sibling's ML-KEM SPKI/text encoders (`vendor/latchset/src/provider.c:1445-1457`) + URI-PEM PrivateKeyInfo entry. **Confirmed live (2026-08-25, while landing R3b) exactly what breaks without this**: `genpkey -algorithm ML-KEM-768 -out k.pem` generates and persists a real key on-token (R3b works) but its own `-out` write fails, `Error writing key(s)`, exit 1 — there is no PrivateKeyInfo (or even text) encoder to serialize ANY ML-KEM output through, PEM file or stdout. Tracked by T4x_encode (XFAIL). | S–M | T4x_encode flips; new T-case: `pkey -pubout` without URI hop; ML-KEM URI-PEM round-trip |
| R3b | **ML-KEM token keygen (keymgmt GEN)** — **DONE (2026-08-25, same day)** | OP-6 | Add `OSSL_FUNC_KEYMGMT_GEN*` to the per-variant ML-KEM keymgmt tables (model: the working ML-DSA gen path; token template `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` per the engines' own CKM_ML_KEM flags); unlocks the native software-encap→token-decap E2E and is a prerequisite for R5-ph1. Landed as sketched: `GEN_INIT`(×3 variants)/`GEN`/`GEN_CLEANUP`/`GEN_SET_PARAMS`/`GEN_SETTABLE_PARAMS` implemented in `keymgmt.c` (mirroring the ML-DSA block — same `struct key_generator`, same `p11prov_common_gen*` helpers) and exported non-static, since ML-KEM's keymgmt tables live in the separate translation unit `kem/mlkem.c` (unlike ML-DSA/SLH-DSA, which assemble their tables in `keymgmt.c` itself). `CKA_PARAMETER_SET` is mandatory on the public-key template — confirmed from the C++ engine's own `extractParameterSet` call in `SoftHSM_keygen.cpp`, "no silent default per audit V-3" — matching ML-DSA's existing pattern exactly (present on pubkey template, intentionally absent from privkey template since the engine re-derives it from the generated key pair and silently discards a private-template copy). `CKA_ENCAPSULATE=true`/`CKA_DECAPSULATE=true` requested explicitly on pub/priv templates: not strictly required (both engines hardcode these server-side for `CKM_ML_KEM_KEY_PAIR_GEN` regardless of template content — confirmed in `SoftHSM_keygen.cpp:7591/7674` and `rust/src/ffi.rs:1647/1666`) but sent anyway to match what a spec-correct caller does. **Live-verified**: `genpkey -propquery "?provider=pkcs11" -algorithm ML-KEM-768` generates a real key, persisted on-token, independently confirmed via `storeutl -text "pkcs11:token=..."` showing `ML-KEM-768 Public-Key`. **One real gap found along the way, NOT part of this item**: `genpkey`'s own `-out` file write still fails because ML-KEM has zero encoders — see R3 above; T4x's original test design had accidentally coupled the two (`|| return 1` right after the `genpkey` call meant T4x could never flip on R3b alone), fixed by rescoping T4x to assert on `storeutl` only and adding a new T4x_encode case to independently track R3's gap. | M | T4x flips (rescoped: asserts via `storeutl`, not genpkey's own exit code — see R3); then add the full T4 KEM E2E cases (512/768/1024, ct sizes 768/1088/1568, secret equality) |
| R4 | **X25519/X448 exchange** | ALG-5 | Add `CKM_X25519`/`CKM_X448` to `checklist[]` — the dispatch tables already exist and both engines advertise the mechs; verify shared-secret parity vs software | S | new T-case: provider derive == software derive over X25519 |
| R5 | **PQC TLS-GROUPs** | F36-1 | Phase 1: register pure `MLKEM512/768/1024` groups (`tls-group-is-kem=1`, IANA ids matching the staged build's own list) backed by token CKM_ML_KEM — makes the token the TLS KEM participant. Phase 2 (separate gate): hybrid groups need the classical+KEM combiner provider-side; assess against `pqctoday-tls`'s existing composed SecP384r1MLKEM1024 before writing new crypto | M (ph1) / L (ph2) | T13 flips; live `s_client -groups MLKEM768` handshake with provider group actually selected + token op evidence |

## Priority 2 — structural / larger

| # | Item | Gap | Sketch | Effort | Proof |
|---|---|---|---|---|---|
| R6 | **Native Rust-arm persistence** | ENV-2 | The snapshot format already exists (`state_snapshot.rs`, `SHR3SNP2`). Add an env-var-gated native path: restore-on-`C_Initialize` / stash-on-`C_Finalize` to a file (e.g. `SOFTHSMRUST_STATE_FILE`). Respect the existing zeroize discipline; single-writer only (document: no concurrent processes) | M | harness Rust arm flips from XFAIL-ENV to the full functional matrix |
| R7 | Remaining 5 composite profiles | ALG-4 | Extend `composite.c`'s registry with the KMIP crate's OIDs/labels (all 8 already there as the reference); Ed25519 classical half needs a `CKM_EDDSA` dispatch branch alongside PSS/ECDSA (`composite.c:941`); keep TLS-SIGALG private code points until IANA | M–L | per-profile sign + M′ vector check against `rust/kat/composite-sigs/external-composite-vectors.json` |
| R8 | `OSSL_OP_MAC` | OP-1/ALG-8 | New `mac.c` implementing EVP_MAC over CKM_*_HMAC / CKM_AES_CMAC / CKM_KMAC_*; gate per mech presence | M | `openssl mac -provider pkcs11 HMAC-SHA256` == software |
| R9 | LMS/HSS story | ALG-3/F36-2/ENV-1 | First rebuild the 3.6.3 oracle with `enable-lms` (ENV-1); then provider-side LMS *verify* offload is low-value (OpenSSL verifies natively) — the coherent target is exposing token HSS/LMS **signing** under custom names + XDR pub export for OpenSSL-native verification | M (after ENV-1) | sign-on-token → `openssl pkeyutl -verify` with native LMS |
| R10 | KDF widening (PBKDF2, SP800-108) + EVP_SKEY probe | OP-5/F36-3 | Investigate first (P2 probes in the test plan): whether OpenSSL's KDF fetch honors provider-priority for PBKDF2/KBKDF names, and whether `EVP_KDF_derive_SKEY` can hand a token-resident derived key back as SKEYMGMT ref without export | probe first | probe writeup, then scoped items |
| R11 | XMSS/XMSS-MT exposure | ALG-2 | Custom names, no native OpenSSL counterpart — value case is weaker (no CMS/TLS integration possible); rank last unless a consumer materializes | L | — |

## Sequencing

R0.x anytime (small, independent). R1→R2→R3 share the sig/keymgmt/encoder
patterns (do consecutively). R4 is an isolated quick win. R3b before
R5-ph1 (a TLS KEM group backed by a token that cannot hold a generated
KEM key is incoherent); R5-ph1 after R2/R3/R3b. R6 unlocks the whole Rust arm
and should precede any "both engines verified" claim in docs. R7+
demand-driven. Every landed item updates the harness expectations in the
same commit (ratchet discipline: an XFAIL that starts passing fails the
run until the expectation is flipped).

## Explicitly out of scope

FrodoKEM/Classic McEliece/BIP32/Keccak-256/split-key exposure through
OpenSSL (vendor/KMIP surfaces, no OpenSSL consumers); WASM-arm changes
(hub-owned e2e covers it); any OpenSSL version work beyond the 3.6.3
oracle already staged.
