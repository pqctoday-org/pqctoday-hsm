# OpenSSL provider remediation plan (2026-08-25) — PLAN ONLY, not executed

Companion to `docs/openssl-provider-coverage-audit-2026-08-25.md` (gap
IDs referenced from there). Per the user's decision (2026-08-25):
remediations are planned and prioritized here but **not executed** under
the audit; each item runs later under its own go-ahead. Every item names
the test that must flip from XFAIL→PASS (or be newly added green) so
completion is observable, not claimed — the harness fails on unexpected
XFAIL passes, so landing a fix without updating the expectation is
loudly visible, and vice versa.

## Priority 0 — correctness / hygiene of what already ships

| # | Item | Gap | Sketch | Effort | Proof |
|---|---|---|---|---|---|
| R0.1 | Quiet the token-scan attribute-type noise | WART-1 | Root-cause which side is wrong: provider queries CKA_CLASS/CKA_TOKEN/etc. with byte-string templates vs C++ `ObjectFile.cpp:181` warning on non-bytestring attrs. Fix the provider's template types (likely `fetch_attrs` shape) OR downgrade the engine log line if the probe pattern is spec-legal (`C_GetAttributeValue` type-probing is legal §5.7.5 — likely engine-side downgrade) | S | probe run's stderr is clean; harness greps for zero `ObjectFile.cpp(181)` lines |
| R0.2 | Native build must not inhale the WASM `config.h` | WART-3 | `gen-pkcs11-provider-config-h.sh` output is for the emcc path only; native CMake should either define `P11PROV_CONFIG_NO_H` or the build should exclude/clean `src/config.h`; reconcile the 0.4.0-vs-1.1 version strings to one source of truth | S | rebuild log has no `PACKAGE_* redefined` warnings; `list -providers` version matches CMake |
| R0.4 | Fresh-process operation fetch (lazy-init) | WART-4 | Root-cause why mechanism-gated tables don't resolve for property-targeted fetches before a token object is referenced (likely `operations_init` ordering vs `query_operation`); harness T9 flips when fixed | M | T9 XFAIL→PASS |
| R0.5 | Document the OAEP-defaults mismatch | WART-5 | Engine rejects SHA-1-default OAEP (likely deliberate FIPS posture) — document the required `rsa_oaep_md`/`rsa_mgf1_md` pins in the provider README/HOWTO rather than "fixing" either side | S | docs |
| R0.3 | Retire dead test assets | ENV-3 | Delete or rewrite `test_openssl_integration.sh` + `openssl_test.cnf` in favor of `scripts/test-openssl-provider.sh` (this audit's harness); note the dormant vendored meson suite in the vendor README as intentionally unwired | S | repo grep shows one provider harness, wired |

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
