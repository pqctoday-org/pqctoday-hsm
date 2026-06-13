# KMIP Crypto Backend Architecture — softhsmrustv3 (primary) + OpenSSL alternate

**Date**: 2026-06-13 · **Status**: design / scoping (read-only explorations done; no code yet)
**Companion**: `PQC_INTEROP_TEST_PLAN.md` (the 1452-case interop set this enables)

## Goal & constraints

- **softhsmrustv3 (pure-Rust) is the PRIMARY, reference, and ONLY wasm-capable
  backend.** It must work first (engine-first: see `PQC_INTEROP_TEST_PLAN.md`
  I0) and remains the browser/in-page HSM.
- Add an **OpenSSL-3.6-backed ALTERNATE backend for native builds only**, behind
  a `trait CryptoBackend` abstraction, to enable **two-backend interop
  cross-validation**: run the 1452 PQC interop vectors through both an
  independent RustCrypto/fips20x stack and an OpenSSL stack; byte-exact
  agreement on both is powerful evidence of FIPS 203/204/205 correctness.

## The abstraction

The KMIP server reaches crypto only through `Deps::engine_session`
(`kmip/src/ops/deps.rs`) → `softhsmrustv3::native::*` (handle-based, `CK_RV`/
`CKM_` vocabulary). Introduce:

```
Deps.backend: Option<Arc<dyn CryptoBackend>>   // replaces engine_session: Option<u32>
trait CryptoBackend  // ~17 methods, handle-based, keeps CK_RV/CKM_ as the wire vocabulary
```

(Full method list in `PQC_INTEROP_TEST_PLAN.md`/the backend exploration:
generate_*_keypair[_from_seed], register_*, sign/verify, encrypt/decrypt,
encapsulate/decapsulate, aes_key_wrap, find_by_cka_id, get_attribute,
get_value_digest_sha256, destroy_object.) Keep `CK_RV`/`CKM_` as the shared
vocabulary so `ck_rv_to_kmip_error` and the `native_*_mech` helpers are
untouched. Impls:

1. **`SofthsmRustV3Backend`** — thin shim over today's free functions
   (mechanical; no behavior change). Validates the seam.
2. **`Pkcs11Backend`** (the alternate) — see below.

## Backend options for the OpenSSL path (explored)

| | Option B — rust-openssl direct FFI | **Option C — KMIP → C++ SoftHSM (PKCS#11) → OpenSSL 3.6** |
|---|---|---|
| PQC reach | **Blocked** — rust-openssl exposes no ML-DSA/ML-KEM/SLH-DSA; needs hand-rolled raw `EVP_PKEY` FFI + seed/deterministic OSSL_PARAMs from scratch | **Solved** — PQC already wired through the C++ engine's OpenSSL integration (`OSSLMLDSA/MLKEM/SLHDSA.cpp`), all seed + deterministic-sign knobs present |
| Seam | Unstable raw EVP FFI | **Stable PKCS#11 v3.2 C ABI** (the engine's real public contract) |
| Reuse | None | **Reuses the 315/0-compliant C++ engine** |
| Interop value | Rust-PQC vs your own fresh FFI (two new things) | Rust-PQC vs an **independently spec-compliant** impl (stronger cross-check) |
| Effort | **L** | **M** |

**Decision: pursue Option C, drop Option B.** Option C reaches OpenSSL through
code that already does PQC correctly, over a stable ABI, reusing the compliance
work from rounds 4–6.

## Option C — concrete shape

- **The C++ engine is already a loadable PKCS#11 v3.2 token**: `libsofthsmv3.dylib`
  (`src/lib/CMakeLists.txt:86` SHARED) exports `CK_FUNCTION_LIST_3_2` incl.
  `C_EncapsulateKey`/`C_DecapsulateKey` (`main.cpp:235,333,334`), reachable via
  `C_GetInterface`. 100% of the needed C_* surface is exported (proven in the
  backend exploration).
- **Drive it from Rust with raw `libloading`** + the engine's own
  `src/lib/pkcs11/*.h` (NOT the `cryptoki` crate — it lags on v3.2 KEM ops and
  `CKA_PARAMETER_SET`/`CKA_SEED`). `dlopen` the `.dylib`, resolve
  `C_GetInterface`, cast to `CK_FUNCTION_LIST_3_2*`, call directly.
- **Deterministic knobs the C++ engine HAS** (verified): seeded keygen for
  ML-DSA/ML-KEM/SLH-DSA (`OSSL_PKEY_PARAM_*_SEED`), `CKA_SEED`/
  `CKA_PARAMETER_SET` in keygen templates, deterministic ML-DSA/SLH-DSA signing
  (`OSSL_SIGNATURE_PARAM_DETERMINISTIC`). These cover keygen + siggen interop
  determinism.

## Shared & Option-C-specific blockers (honest)

1. **Encaps-with-coins (SHARED gap, blocks deterministic ML-KEM encaps KATs).**
   Neither backend accepts caller-supplied coins `m`: C++ `OSSLMLKEM.cpp:75`
   (`EVP_PKEY_encapsulate_init(ctx, NULL)`, internal RNG) and Rust
   `native/encrypt.rs:73` (`&mut rng`) both self-generate. The 75 encapsulation
   interop transcripts can't be byte-exact on EITHER backend until an OpenSSL
   `EVP_PKEY_encapsulate` coins param + a `CKA_SEED`-on-encaps template path is
   added. This is the same I5 gate as in the interop plan — now known to be
   symmetric across both backends.
2. **Digest-of-sensitive-CKA_VALUE provenance (Option-C-specific).** The current
   native bridge digests the raw stored key value (`create_key_pair.rs:356`); a
   real PKCS#11 token hides sensitive `CKA_VALUE`, so `get_value_digest_sha256`
   can't be replicated through the C++ token for sensitive keys. Needs a
   non-sensitive digest path or a different provenance signal under Option C.
3. **Native-only + process-global lifecycle.** The C++ emscripten build is a
   JS/WASM module, not a `dlopen`-able `.so` — so Option C is native-only; the
   browser stays pure-Rust softhsmrustv3. `C_Initialize` is process-global
   (singleton + MutexFactory): the backend owns one init + session/login
   lifecycle; test isolation can't re-init freely.

## Sequencing

```
0. softhsmrustv3 engine proven interop-correct (PQC_INTEROP_TEST_PLAN I0) — PRIMARY
1. Extract `trait CryptoBackend` + `SofthsmRustV3Backend` shim (no behavior change)
2. `Pkcs11Backend` (libloading + C_GetInterface v3.2): classical first, then PQC
3. --backend {softhsmrustv3|pkcs11-cxx} flag + `--features openssl-backend` Cargo gate
   (default/wasm build never pulls the C++ dep)
4. Run the 1452 interop set through BOTH backends → byte-exact cross-validation
   (encaps deferred on both per blocker #1 until coins support lands)
```

## What this buys

- A KMIP server that runs on either a pure-Rust PQC stack (browser + native) or,
  natively, on the OpenSSL-3.6-backed C++ engine — selectable.
- **Two independent implementations** of FIPS 203/204/205 both validated
  byte-exact against the OASIS 2025 PQC interop vectors — the strongest
  correctness signal short of live multi-vendor interop.
- Reuse of the rounds 4–6 C++ compliance work as a production backend, not just
  a sibling engine.

**Effort:** trait + Rust shim **S–M**; `Pkcs11Backend` **M**; backend selection
+ feature gate **S**; dual-backend interop run **M** (gated by I0 + the shared
encaps-coins blocker). Option B (rust-openssl) is **not** pursued.
