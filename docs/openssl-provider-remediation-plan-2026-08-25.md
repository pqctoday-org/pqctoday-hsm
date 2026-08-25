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
its row below. **P0 batch is now fully done: harness is
`PASS=14 FAIL=0 XFAIL=4 XPASS=0`.** Everything below P0 is still
plan-only, unchanged.

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
| R1 | **SLH-DSA end-to-end** | ALG-1 | Add `CKM_SLH_DSA`/`CKM_SLH_DSA_KEY_PAIR_GEN` to `PQC_MECHS`/`checklist[]` (`provider.c:859,896`); implement `sig/slhdsa.c` keymgmt+signature (model: `sig/mldsa.c`, which already solved context-string plumbing; parameter set via `CKA_PARAMETER_SET`, names mirror OpenSSL's own 12 native names for cross-verify); SPKI encoder like ML-DSA's | L | new T-cases: keygen+sign via provider, software cross-verify, for at least SHA2-128s/SHAKE-128f; T12 flips |
| R2 | **PQC decoders (URI-PEM round-trip)** | OP-2 | Register ML-DSA + ML-KEM decoders (`input=der,structure=P11PROV_DER_STRUCTURE` like RSA/EC's); the URI-PEM body is provider-defined DER, so no d2i_X509_PUBKEY recursion applies (that issue was composite-SPKI-specific, `provider.c:1512-1525`) | M | T11 flips; add ML-KEM variant |
| R3 | **ML-KEM encoders** | OP-3 | Port the latchset sibling's ML-KEM SPKI/text encoders (`vendor/latchset/src/provider.c:1445-1457`) + URI-PEM PrivateKeyInfo entry | S–M | new T-case: `pkey -pubout` without URI hop; ML-KEM URI-PEM round-trip |
| R3b | **ML-KEM token keygen (keymgmt GEN)** | OP-6 | Add `OSSL_FUNC_KEYMGMT_GEN*` to the per-variant ML-KEM keymgmt tables (model: the working ML-DSA gen path; token template `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` per the engines' own CKM_ML_KEM flags); unlocks the native software-encap→token-decap E2E and is a prerequisite for R5-ph1 | M | T4x flips; then add the full T4 KEM E2E cases (512/768/1024, ct sizes 768/1088/1568, secret equality) |
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
