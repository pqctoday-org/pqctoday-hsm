# Implementation plan — Classic McEliece, all parameter sets, both engines (2026-09-08)

Baseline: `main` at v0.29.0 (`dcf1b0c0`), branch `feat/classic-mceliece-all-param-sets`.
Nothing implemented yet — this document is the plan, the decision record, and the
verification standard. It supersedes the Classic McEliece rows of two earlier plans:

- `cacp-frodokem-mceliece-softhsm-kmip-policy-plan-07062026.md` (workspace root) —
  Phase 0.5 resolved to `mceliece6688128` only, option (a), because the Rust crate can
  compile exactly one parameter set per build. That scoping is what this plan removes.
- `docs/remediation-plan-cpp-rust-pkcs11-parity-2026-07-25.md` — designed C++ parity
  via liboqs, recommended "confirm intent before starting", and was never executed.
  Intent is now confirmed (§2, D-2).

Standing rules that apply throughout: one editor on PKCS#11/KMIP code (research may be
delegated, edits may not); OpenSSL 3.6.3+ only; PKCS#11 v3.2 baseline with v3.3 filling
gaps; the pre-push gate is `scripts/local-gate.sh`, and nothing is pushed without an
explicit go-ahead.

---

## 1. Where things stand (verified 2026-09-08, not recalled)

| Surface | Today | Evidence |
|---|---|---|
| C++ engine | **No Classic McEliece at all** | `grep -ri mceliece src/lib/` → 0 hits |
| Rust engine | **1 of 10** parameter sets: `mceliece6688128` (BSI's Category-5 pick), via `classic-mceliece-rust = "3"` with the single feature `mceliece6688128` | `rust/Cargo.toml:199`, `rust/src/constants.rs:821-828`, `rust/src/native/keygen.rs:1884-1918` |
| Mechanisms | Vendor-defined, both engines' headers lack any standard constant (neither the v3.2 header nor the vendored v3.3 draft mentions McEliece): `CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN` `0x80000003`, `..._ENCAPSULATE` `0x80000004`, `CKK_PQCTODAY_CLASSIC_MCELIECE` `0x80000002`, `CKP_CLASSIC_MCELIECE_6688128 = 0x1` | `rust/src/constants.rs:202,472-473,828`; authority: `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` §1.4 |
| Mechanism ledger | both rows `cpp: not-advertised`, `rust: implemented` | `docs/pkcs11-mechanism-ledger.json:3120-3130` |
| KMIP 3.0 | `KmipAlgorithm::ClassicMcEliece6688128` on the **generic** OASIS codepoint `0x34` ("McEliece"). OASIS also defines `0x35` = McEliece-6960119 and `0x36` = McEliece-8192128; nothing for the other sizes or any `f` variant | `kmip/src/kmip30/algos.rs:368-380`, `kmip/spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json:2097-2105` |
| CACP policies | BSI presets allow-list `Classic-McEliece-460896` / `-6688128` by name; fips-only / cnsa-2.0 deny McEliece by name | `kmip/policies/bsi-tr-02102*.yaml`, `cnsa-2.0*.yaml`, `fips-only*.yaml` |
| Cross-validation | Bidirectional round trips against liboqs via the `oqs` crate (dev-dependency only, `0.10`) — 40 trials, 6688128 only | `rust/src/native/encrypt.rs:1977`, `kmip/tests/frodokem_mceliece_e2e.rs:171` |
| wasm (Rust) | Builds; 8 MiB shadow stack already set because a 6688128 public key (1,044,992 B) overflowed the 1 MiB default | `rust/build-wasm-bundle.sh:23-39`, `scripts/build-kmip-wasm.sh:39` |
| Hub | Already ships per-variant liboqs wasm for **all 10** variants (`@oqs/liboqs-js` 0.15.1 → `public/dist/classic-mceliece-*.js`), playground exposes 5 non-f sizes via `src/wasm/liboqs_kem.ts`; mirrors the engine's vendor constants in `src/wasm/softhsm/constants.ts:22-28` | hub `package.json:164`, `src/wasm/liboqs_kem.ts:17-99` |
| Hub migrate catalog | Rows exist for liboqs, oqs-provider, liboqs-rust (`oqs` crate), pqcrypto, Botan, Bouncy Castle, 01 Quantum IronCAP — **no row for `classic-mceliece-rust`**, the crate this engine actually ships | `pqctoday-hub/src/data/pqc_product_catalog_09072026_r15.csv` (33 rows mention McEliece) |

### 1.1 Library facts this plan is built on

- **liboqs 0.16.0** (2026-07-09) — all 10 variants (`348864, 348864f, 460896, 460896f,
  6688128, 6688128f, 6960119, 6960119f, 8192128, 8192128f`), implementation from
  SUPERCOP-20221025 (clean + AVX2, runtime CPU detection). liboqs's own algorithm page
  says the implementation "may not be constant-time", upstream is "no active
  maintenance" (OQS support tier 3), and `460896`, `460896f`, `6960119`, `6960119f`
  **fail liboqs's memory-leak tests on x86-64 under clang -O2/-O3**. The 0.16.0 release
  notes contain no McEliece changes. CMake: `OQS_MINIMAL_BUILD="KEM_classic_mceliece_…;…"`,
  per-variant `OQS_ENABLE_KEM_classic_mceliece_<variant>`, `OQS_USE_OPENSSL` (AES/SHA2/SHA3
  via OpenSSL ≥ 1.1.1 — we have 3.6.3), `OQS_BUILD_ONLY_LIB`, `OQS_DIST_BUILD`.
- **oqs-provider dropped Classic McEliece in 0.8.0+** (open-quantum-safe/oqs-provider
  discussion #646; its `ALGORITHMS.md` lists no McEliece at all). There is therefore
  **no OpenSSL-EVP route** for C++ — it must call liboqs's C API directly. This is the
  first non-OpenSSL crypto dependency in the C++ engine, a deliberate exception to
  `CLAUDE.md`'s "OpenSSL EVP-only" principle, recorded as decision D-2.
- **`classic-mceliece-rust` 3.1.0** (docs.rs, 2026-07-21 tag) — pure Rust, all 10
  variants, but one per build: the parameter set is selected by a Cargo feature that
  gates crate-level constants (`params.rs`, `api.rs`: `CRYPTO_PUBLICKEYBYTES` etc.), and
  fixed-size arrays are sized by those constants. 6,743 LOC across 23 files; the
  `cfg(feature = …)` sites are concentrated in `api.rs` (11), `pk_gen.rs` (13),
  `encrypt.rs` (6), `controlbits.rs` (4), `lib.rs` (38). Cargo feature unification
  applies per package across the whole graph, so the "depend on it three times under
  different names" idea from the July plan's option (b) cannot isolate features and is
  dead — the choice is fork or C.
- **`oqs` crate 0.11.0** (2026-08-09) bundles liboqs **0.13.0** via `oqs-sys` unless
  `LIBOQS_NO_VENDOR=1` links a system liboqs. Not a wasm crate.
- **`pqcrypto-classicmceliece`** binds PQClean, which was **archived read-only
  2026-08-04** (hub catalog row `pqclean`). Not a viable new dependency.
- **Sizes** (liboqs page; the crate's `api.rs` constants agree byte for byte):

| Set | NIST cat. | Public key | Secret key | Ciphertext | Shared secret |
|---|---|---|---|---|---|
| 348864 / 348864f | 1 | 261,120 | 6,492 | 96 | 32 |
| 460896 / 460896f | 3 | 524,160 | 13,608 | 156 | 32 |
| 6688128 / 6688128f | 5 | 1,044,992 | 13,932 | 208 | 32 |
| 6960119 / 6960119f | 5 | 1,047,319 | 13,948 | 194 | 32 |
| 8192128 / 8192128f | 5 | 1,357,824 | 14,120 | 208 | 32 |

  The big object is always the **public** key; secret keys are ≤ 14,120 bytes, so
  at-rest encryption cost (C++ `SecureDataManager`, Rust `store`) is small.

### 1.2 Standing of the algorithm (for the record, not for the design)

- **ISO/IEC 18033-2:2006/Amd 2:2026** (June 2026) standardized Classic McEliece
  (alongside ML-KEM and FrodoKEM). Which parameter sets the amendment names is
  **unverified** here (paywalled; Phase 0 item P0-6).
- **NIST**: not a NIST standard; NIST selected HQC (March 2025) and said it "may
  consider" McEliece after ISO completes.
- **BSI TR-02102-1 v2026-01 §2.4.2** recommends `460896`, `6688128`, `8192128` (+ `f`),
  in hybrid deployment. Not 348864, not 6960119.
- **Cryptanalysis**: the 2026 quasipolynomial result (ePrint 2026/1630) is a
  *distinguisher* (public code vs random code, 2^114–2^124 operations, exabyte
  storage), explicitly not a decryption or key-recovery break; no security claim of
  the scheme depends on indistinguishability. No parameter change is implied.
- **`f` variants**: liboqs describes them as "functionally equivalent" to the non-f
  sets with identical sizes — they differ in key *generation* (semi-systematic form,
  (u,v)=(32,64)). Whether an `f`-generated key pair is byte-interoperable with the
  non-f encapsulate/decapsulate is **not asserted here** — three fetches of
  classic.mceliece.org failed and the IETF draft (draft-josefsson-mceliece-05) treats
  each as a distinct conformance target. Phase 0 item P0-5 settles it by test, not
  by reading.

---

## 2. Decisions taken (2026-09-08, with the user)

| Ref | Decision | Consequence |
|---|---|---|
| **D-1** | Scope = **all 10 liboqs/crate variants** (5 sizes × {plain, f}). Not BSI's 6 only; not the IETF draft's `pc`/`pcf` variants (no library implements them). | Every table below is 10 rows. `pc` variants are explicitly out of scope. |
| **D-2** | C++ gets McEliece by **vendoring liboqs 0.16.0 and calling its C API directly** — a documented exception to the EVP-only rule, forced by oqs-provider having dropped the algorithm. | New `src/lib/crypto/OSSLClassicMcEliece*` files (the file pattern stays, the "OSSL" prefix is kept for consistency even though the backend is liboqs; noted in each header). |
| **D-3** | Rust gets all 10 by **forking `classic-mceliece-rust` 3.1.0 into a multi-parameter-set crate** vendored under `rust/`, same layout as `fips204-patched`/`fips205-patched`. Pure Rust, wasm-capable, upstreamable. | The `oqs` crate stays a dev-dependency (oracle), never a shipping one. |
| **D-4** | **Rust wasm: yes, all 10. C++ Emscripten wasm: no** — the C++ wasm engine keeps not advertising McEliece; the asymmetry is documented and already has an adjudication shape (`LEGAL-BUILD-FLAG-VARYING-MECHANISM-SETS`). | Browser users get McEliece from the Rust engine bundle or the hub's existing liboqs-js, never from `libsofthsmv3.wasm`. |

Decisions still open are in §8.

---

## 3. Target surface (both engines must match exactly — the differential harness enforces it)

### 3.1 PKCS#11

- Mechanisms/key type unchanged: `CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN`
  (`0x80000003`), `CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE` (`0x80000004`),
  `CKK_PQCTODAY_CLASSIC_MCELIECE` (`0x80000002`). No new mechanism codepoints.
- `CKA_PARAMETER_SET` is **required** on keygen (no silent default — same rule as
  ML-KEM, and the rule the HBS-1 fix restored for HSS). Values (keep `0x1` where it is;
  it is already on the wire in the hub's `constants.ts`):

| `CKP_CLASSIC_MCELIECE_*` | Value | | `CKP_CLASSIC_MCELIECE_*` | Value |
|---|---|---|---|---|
| `6688128` (existing) | `0x1` | | `6688128F` | `0x6` |
| `348864` | `0x2` | | `6960119` | `0x7` |
| `348864F` | `0x3` | | `6960119F` | `0x8` |
| `460896` | `0x4` | | `8192128` | `0x9` |
| `460896F` | `0x5` | | `8192128F` | `0xA` |

  Recorded in the priv authority file (new "CKP values" subsection under §1.4 —
  it currently tracks only CKM/CKK; open item O-2).
- `CKA_VALUE` stays **raw** bytes for both public and private keys (no SPKI/PKCS#8
  wrapper: there is no registered OID — the IETF draft defines none — and the
  differential harness already treats a secret/PQC `CKA_VALUE` as unstructured, per
  the 2026-09-07/08 `classify()` fixes). `CKA_PUBLIC_KEY_INFO` absent, as today.
- `C_GetMechanismInfo`: `ulMinKeySize`/`ulMaxKeySize` become the public-key byte range
  across the advertised sets — **261,120 … 1,357,824** — for both mechanisms, both
  engines (Rust's hard-coded `(1_044_992, 1_044_992)` at `rust/src/ffi.rs:1478-1479`
  goes away). Flags unchanged: keygen `CKF_GENERATE_KEY_PAIR`; encapsulate
  `CKF_ENCAPSULATE | CKF_DECAPSULATE`. The ledger pin (`scripts/pin_pkcs11_mechanism_info_ranges.py`)
  is regenerated so a drift on either side fails the gate.
- `C_EncapsulateKey`/`C_DecapsulateKey` semantics unchanged; derived key attribute
  handling identical to ML-KEM (`CKA_VALUE_LEN` 32, template rules per v3.2 §6.68.5).
- Imported keys (`C_CreateObject`) accepted for every set, length-checked against the
  set's exact sizes — extend `register_classic_mceliece_{private,public}_key`
  (`rust/src/native/keygen.rs:1583-1631`) and add the C++ equivalents.

### 3.2 KMIP 3.0 / CACP

- Keep `ClassicMcEliece6688128 = 0x34` (generic OASIS "McEliece") — it is on the wire
  and in the hub's `kmipMeta.ts`/`codepointTable.ts`; renaming it would be a silent
  wire break.
- Use the **real OASIS codepoints** for the two the spec names: `0x35` →
  `ClassicMcEliece6960119`, `0x36` → `ClassicMcEliece8192128`.
- The remaining seven (`348864`, `460896`, and all five `f` variants) get **vendor
  extension codepoints** in the `0x80000000|n` range, continuing after FrodoKEM's
  block (`0x8000005f–0x64`) and the hybrid-KEM entries — exactly the precedent
  `kmip/src/kmip30/algos.rs:382-393` set for FrodoKEM's six variants. Recorded in the
  same authority file. `no_invented_codepoints_in_the_standard_range` (`algos.rs:1326`)
  loses its "one deliberate exception" clause once 6960119/8192128 sit on their real
  codepoints.
- Display names follow the existing `Classic-McEliece-6688128` shape; `f` variants
  as `Classic-McEliece-6688128f` (matches liboqs's own names and the hub playground).
- Policies: BSI presets allow-list exactly BSI's six (`460896`, `6688128`, `8192128`
  + `f`), **not** `348864`/`6960119`; fips-only and cnsa-2.0 deny all ten by name.
  This is a precision improvement, not a relaxation.

### 3.3 wasm

- Rust engine bundle (`rust/build-wasm-bundle.sh`) and the KMIP wasm
  (`scripts/build-kmip-wasm.sh`): all ten. Stack stays 8 MiB; every McEliece call
  path must use the heap (`*_boxed`) API — an `8192128` public key on the shadow
  stack would exceed it.
- C++ Emscripten build (`scripts/build-wasm.sh`): liboqs is **not** cross-compiled;
  `WITH_LIBOQS` is forced off under `EMSCRIPTEN` and the mechanisms are not
  advertised there (D-4).

---

## 4. Rust engine — Phase 1

**Goal**: one build, ten parameter sets, pure Rust, wasm-clean.

1. **Vendor the fork**: `rust/classic-mceliece-multi/` (a *new package name*, not a
   `[patch]` of `classic-mceliece-rust` — the public API changes, and a patched crate
   with the same name would still be one-set-per-build). Keep upstream's MIT license,
   `CHANGELOG.md`, and add a `README.md` stating the upstream tag (3.1.0), what was
   changed, and that an upstream PR is intended (same convention as
   `rust/fips204-patched/README.md`).
2. **Refactor shape** (spike first — P0-1): keep upstream's code nearly verbatim and
   instantiate it **once per parameter set as a module** via a `macro_rules!` that
   takes the set's constants (`GFBITS`, `SYS_N`, `SYS_T`, the size constants, the
   `f`/semi-systematic switch). Every function that today reads a crate-level constant
   reads its module's constant instead; the public API becomes
   `classic_mceliece_multi::mceliece348864::{keypair_boxed, encapsulate_boxed, decapsulate_boxed, PublicKey, SecretKey, Ciphertext, SharedSecret}` × 10,
   plus a `ParameterSet` enum with `fn sizes(self) -> (pk, sk, ct)` and
   `fn from_ckp(u32) -> Option<Self>`. This keeps the diff against upstream reviewable
   and avoids `generic_const_exprs` (array lengths derived from parameters are why
   const generics don't work on stable). Fallback if the spike shows the macro
   approach is unmanageable: runtime parameters with heap buffers (bigger diff,
   smallest binary).
3. **Engine wiring**: `rust/src/constants.rs` (the nine new `CKP_*`), `rust/src/ffi.rs`
   keygen arm (`:3911-3978`) and the mechanism-info table (`:1474-1479`),
   `rust/src/native/keygen.rs` (`generate_classic_mceliece_keypair`, both `register_*`),
   `rust/src/native/encrypt.rs` (`classic_mceliece_{en,de}capsulate`,
   `:570` onward) — all keyed on the stored `CKA_PARAMETER_SET`, never on a size
   guess. `rust/src/ck_param.rs` validation of `CKA_PARAMETER_SET` values.
4. **Build-time cost**: keygen for the 8192128 sets is minutes-slow in unoptimized
   builds (`rust/src/native/keygen.rs:2580-2585` already `#[ignore]`s the 6688128
   test for this reason). Add `[profile.dev.package.classic-mceliece-multi] opt-level = 3`
   and the same under `profile.test` so the crate is optimized even in debug/test
   builds — the standard Cargo answer, no test needs to be ignored.
5. **Tests** (see §7 for the standard): per-set size assertions; keygen → encaps →
   decaps round trip per set; wrong-set rejection; import length checks; the
   `#[ignore]` on the 6688128 keygen test is removed once step 4 lands.

Effort: **M** (the spike decides; the wiring is mechanical once the crate exists).

## 5. C++ engine — Phase 2

**Goal**: native C++ parity, liboqs-backed, off by default under Emscripten.

1. **Dependency**: git submodule `src/lib/crypto/oqs/liboqs` pinned to the `0.16.0`
   tag (the repo's existing submodule pattern — `hash-sigs`, `xmss-reference` live
   under `src/lib/crypto/stateful/`), `add_subdirectory` from `CMakeLists.txt` with:
   `OQS_BUILD_ONLY_LIB=ON`, `OQS_MINIMAL_BUILD` listing exactly the ten
   `KEM_classic_mceliece_*` entries (exact identifiers confirmed in P0-2),
   `OQS_USE_OPENSSL=ON` (+ AES/SHA2/SHA3 via the already-resolved OpenSSL ≥ 3.5),
   `OQS_DIST_BUILD=ON` (AVX2 with runtime detection, one binary), static-linked into
   `softhsmv3`. A `WITH_LIBOQS` CMake option, default ON natively, forced OFF when
   `EMSCRIPTEN` (D-4). `README.md`/`CLAUDE.md` gain one paragraph recording the
   EVP-only exception and why.
2. **Classes**, mirroring the ML-KEM file pattern (`OSSLMLKEM*`,
   `MLKEMParameters`): `ClassicMcElieceParameters.{h,cpp}` (parameter set +
   `serialise`/`deserialise`, required, no default), `OSSLClassicMcEliece.{h,cpp}`
   (`AsymmetricAlgorithm` — `generateKeyPair`, `encapsulate`, `decapsulate`,
   `getMinKeySize`/`getMaxKeySize`, `reconstruct*`, sign/verify/encrypt/decrypt
   return false), `OSSLClassicMcEliecePublicKey`/`PrivateKey`/`KeyPair` holding raw
   bytes + the set; registration in `OSSLCryptoFactory::getAsymmetricAlgorithm()`
   (`AsymAlgo::CLASSIC_MCELIECE`). Each liboqs call goes through one thin RAII wrapper
   (`OQS_KEM_new`/`keypair`/`encaps`/`decaps`/`OQS_KEM_free`) selected by set name.
3. **PKCS#11 wiring**: `SoftHSM::prepareSupportedMechanisms()`, `C_GetMechanismInfo`
   (`SoftHSM_slots.cpp`, the same size range as §3.1), `C_GenerateKeyPair` arm in
   `SoftHSM_keygen.cpp` (require `CKA_PARAMETER_SET`, set `CKA_KEY_TYPE`,
   `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` defaults exactly as ML-KEM), the
   `C_EncapsulateKey`/`C_DecapsulateKey` dispatch, `C_CreateObject` import checks,
   and the vendor constants in `src/lib/pkcs11/` (vendor header, not the canonical
   v3.2 header — `scripts/check_pkcs11_constants.py` must stay green).
4. **Memory/timing hygiene**: liboqs's own CI shows leak-test failures for four
   variants under clang -O2/-O3. Phase 2 exit requires an ASan/LSan (host clang) or
   valgrind (container) run of keygen/encaps/decaps for **all ten** with zero leaks;
   if a variant genuinely leaks inside liboqs, it is **not advertised** by C++ until
   fixed upstream (and the asymmetry goes into `exceptions.json` with the liboqs issue
   cited) — no silent partial support. Do not claim constant-time anywhere; carry the
   same audit-status caveat the July plan §0.7 established.
5. **Cross-validation**: a new C++ test (`test_classic_mceliece_kat.cpp`, built with
   `BUILD_TESTS`) that (a) runs the official KATs from §7, and (b) round-trips against
   the Rust engine in both directions (C++ keygen → Rust encaps → C++ decaps, and the
   reverse) for all ten — the §3 cross-engine pattern of the July plan.

Effort: **L** (new C dependency + build integration is the bulk; the class code is
formulaic once liboqs links).

## 6. Shared surface — Phase 3

1. **Differential harness** (`tests/differential/scenarios.inc`): a keygen scenario
   per set (attribute set, sizes, `CKA_PARAMETER_SET` round trip), an encaps/decaps
   scenario per set (ciphertext length, shared-secret length, tamper rejection —
   ciphertext bit-flip must yield a *different* secret, never an error, per implicit
   rejection), a missing-/wrong-parameter-set negative, and the mechanism-info range
   check. Every divergence adjudicated in `exceptions.json` with a citation or fixed —
   the harness's standing rule.
2. **Ledger**: `scripts/gen_pkcs11_mechanism_ledger.py` → both rows become
   `implemented`/`implemented`; `scripts/pin_pkcs11_mechanism_info_ranges.py` pins the
   new min/max on both sides.
3. **KMIP/CACP** (§3.2): `kmip/src/kmip30/algos.rs` enum + wire mapping + names;
   `kmip/policies/*.yaml`; `kmip/tests/policy_op_layer.rs` (allow/deny per policy per
   variant), `kmip/tests/frodokem_mceliece_e2e.rs` (round trip per variant), the
   OASIS replay baseline unchanged (no corpus test names these variants).
4. **Evidence regen**: `cpp_compliance_report.*`, `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`
   (new cases for the nine sets), `docs/pkcs11-mechanism-ledger.json`, KMIP replay
   report — via the gate, never by hand.
5. **Hub follow-ups (separate repo, separate PR)**: `src/wasm/softhsm/constants.ts`
   (nine `CKP_*`), `src/wasm/softhsm/pqc.ts` (`hsm_generateClassicMcElieceKeyPair`
   takes the set), `src/wasm/kmip/kmipMeta.ts` + `ttlv/codepointTable.ts` (new
   codepoints), and one migrate-catalog row for `classic-mceliece-rust` (through the
   normal `add-catalog-row` flow with real evidence — the catalog currently omits the
   crate this engine ships).

Effort: **M**.

---

## 7. Verification standard

Nothing here is "done" on a green build. Each item below is a gate for the phase that
owns it; all of it runs through `scripts/local-gate.sh` (core + `--cpp`), scoped runs
during iteration, the full run before a push — the 2026-09-07 lesson.

| Check | How | Owner |
|---|---|---|
| Official KATs, all ten | Phase 0 sources the round-4 submission's `kat_kem.rsp`/`.req` per set (NIST-DRBG seeded; the crate's own `test_katkem.rs` consumes exactly this format) with provenance (source URL, sha256, retrieval date) into `kmip/kat/classic-mceliece/` beside `kmip/kat/frodokem/`, registered in `kmip/kat/manifest.sha256` and in `scripts/check_acvp_provenance.py`'s discipline. Both engines must reproduce `pk`/`sk`/`ct`/`ss` byte-for-byte from the seeds. If the official package turns out not to ship KATs for a set, say so in the README and fall back to the next row — never generate "KATs" with the implementation under test. | P0-3 / Phases 1, 2 |
| Cross-implementation | Rust engine ↔ liboqs (`oqs` crate) both directions, N=20 trials per set (the pattern already in `rust/src/native/encrypt.rs:1977`); C++ engine ↔ Rust engine both directions, all ten. | Phases 1, 2 |
| Oracle version hygiene | The Rust oracle currently vendors liboqs 0.13.0 (`oqs` 0.11 → `oqs-sys` 0.11). Either pin the oracle to the same 0.16.0 the C++ engine links (`LIBOQS_NO_VENDOR=1` in the container) or record the version skew explicitly in the test's doc comment — not both versions unlabelled. | P0-4 |
| Negative paths | Missing `CKA_PARAMETER_SET`, unknown value, wrong-length import, decapsulate with the wrong set's key, ciphertext tamper → new secret (implicit rejection), oversized template. Exact `CKR_*` codes identical on both engines. | Phases 1, 2 |
| Memory | ASan/LSan or valgrind over all ten on C++ (§5.4); Rust `miri` is not required (safe Rust, `#![forbid(unsafe_code)]` upstream — keep it in the fork). | Phase 2 |
| Large objects | Store, list, `C_GetAttributeValue`, export/import and KMIP Get of an 8192128 key pair on both engines; the differential harness records length and a fingerprint, never the bytes. Object-store file size and a `--cpp` gate time delta are recorded in the plan's execution log. | Phase 3 |
| wasm | `rust/test_xmss_release.js`-style node smoke for at least `348864` and `8192128` through the Rust wasm bundle, plus the KMIP wasm smoke (`wasm/smoke/smoke.cjs`) extended with one McEliece Create/Encapsulate — memory growth and the 8 MiB stack confirmed, not assumed. | Phase 1 |
| Evidence freshness | `scripts/check_pkcs11_reports_fresh.py --cpp --rust` green on the final commit; ledger regenerated; no hand-edited report. | Phase 3 |
| Gate | Full `scripts/local-gate.sh --cpp` green (marker written for the pushed commit); `--javajce`/`--openssl-provider` only if their surfaces are touched (they are not, unless the openssl-provider vendor code gains a McEliece arm — out of scope). | Landing |

Test time is a first-class constraint: ten keygens, each side, each direction. Use
release-level optimization for the fork (§4.4), `cargo nextest` if it has landed on
`main` by then, and keep any test over ~60 s behind an explicit, documented reason,
not a silent `#[ignore]`.

---

## 8. Open decisions (need an owner before the phase that depends on them)

| Ref | Question | Recommendation | Blocks |
|---|---|---|---|
| **O-1** | KMIP codepoints for the seven variants without an OASIS value: vendor extension codepoints (FrodoKEM precedent) vs generic `0x34` + a parameter attribute (the `Ecdh`/`RecommendedCurve` shape `algos.rs:378` mentions). | Vendor codepoints — one variant per algorithm value is what every other multi-set KEM in this codebase does, and it keeps policies name-based. | Phase 3 |
| **O-2** | Record `CKP_*` values in the priv authority file (which today lists only CKM/CKK)? | Yes — add a "parameter-set values" subsection under §1.4; they are wire-visible and mirrored in the hub. | Phase 1 |
| **O-3** | Ship all ten by default, or advertise only BSI's six by default with the other four behind a build/config switch? | All ten (D-1); policy, not the engine, is where BSI-vs-not is expressed (§3.2). | Phase 3 |
| **O-4** | Upstream the fork (PR to `Colfenor/classic-mceliece-rust`)? | Yes, after Phase 1 ships and the KATs pass — but the vendored copy is the shipping source regardless of upstream's response. | After Phase 1 |
| **O-5** | Version/CHANGELOG: this is a `[Unreleased]` "Added" for both engines; minor bump. | v0.30.0 when it lands; per-engine "Added" bullets, plus a "Changed" bullet for the mechanism-info range. | Landing |

---

## 9. Phase 0 — verify before building (all cheap, all before Phase 1 starts)

| # | Item | Done when |
|---|---|---|
| P0-1 | **Fork spike**: instantiate `mceliece348864` and `mceliece8192128f` together from the macro-module approach in a scratch copy; both round-trip; binary size delta measured natively and for wasm32. | A commit on this branch with the two-set prototype and the numbers, or a written verdict that the runtime-parameter fallback is needed. |
| P0-2 | **DONE (2026-09-09)**. Submodule `src/lib/crypto/oqs/liboqs` pinned to `0.16.0` (`5a1a854b0`). Minimal build (`-DOQS_MINIMAL_BUILD="KEM_classic_mceliece_348864;…_8192128f"` — exact identifiers confirmed in `.CMake/alg_support.cmake:440`, which even ships a matching `OQS_ALGS_ENABLED=NIST_R4` preset, unused here since it also pulls in HQC/BIKE we deliberately deferred) configured and built clean in the `pqc-rust` container against the OpenSSL 3.6.3 already resolved there (`Found OpenSSL: ...libcrypto.so ... "3.6.3"`), zero warnings, 1.2 MB static `liboqs.a`. A throwaway C program confirmed: `OQS_KEM_alg_count()` returns 41 (the full compiled-in identifier table, not just enabled ones — corrects this row's own earlier phrasing), of which **exactly 10 report `enabled=1`**, all Classic-McEliece; a full keypair→encaps→decaps round trip matched on both size extremes, `348864` (pk 261,120 / sk 6,492 / ct 96 / ss 32) and `8192128f` (pk 1,357,824 / sk 14,120 / ct 208 / ss 32) — both exactly matching §1.1's table. Not yet spiked on the macOS host (native build, no container) — low risk, same CMake path, deferred to Phase 2 itself rather than blocking Phase 0. |
| P0-3 | **DONE (2026-09-09, `22c31699`)**. All 10 variants' `kat_kem.rsp` staged under `kmip/kat/classic-mceliece/raw/`, sourced from `classic.mceliece.org/nist/mceliece-kat-20221023.tar.gz` (sha256 pinned in the README), 10 vectors/variant (not FrodoKEM's 100 — confirmed by count, matches the much larger key size), checksums in `kmip/kat/manifest.sha256`. Sourcing only; no test consumes them yet (that's Phase 1/2's job). |
| P0-4 | **Oracle version**: decide `LIBOQS_NO_VENDOR=1` (share the 0.16.0 build) vs recorded skew. | One line in the cross-validation test's doc comment and in this plan. |
| P0-5 | **`f` interoperability by test, not by reading**: with liboqs, encapsulate to a `348864f`-generated public key using the `348864` KEM object and decapsulate with the `f` secret key (and the reverse). | Result recorded here. If interoperable, the engines may share import paths across the pair; if not, each set is strictly its own — either way the harness scenarios encode the measured answer. |
| P0-6 | **ISO parameter-set list**: confirm which sets ISO/IEC 18033-2 Amd 2:2026 names (the amendment text, or classic.mceliece.org/iso.html once reachable). | One sentence in §1.2 with the source. Informational only; D-1 does not depend on it. |
| P0-7 | **Codepoint registration**: reserve the seven KMIP vendor codepoints and the nine `CKP_*` values in the priv authority file *before* code uses them — the registry's own rule after the retired `0x40xx` block. | Authority file commit in `pqctoday-priv`. |

---

## 10. Sequencing and landing

1. This branch (`feat/classic-mceliece-all-param-sets`) is cut from `main` v0.29.0 and
   stays independent of `fix/pkcs11-d2-pkcs8-wire-format` (landing separately). If
   pkcs11-d2 merges first, rebase once; its harness fixes (`classify()` for raw PQC and
   secret keys, the gate's single-run steps) are ones this work relies on.
2. Phase 0 → Phase 1 (Rust) → Phase 2 (C++) → Phase 3 (shared). Phases 1 and 2 are
   independent after Phase 0 and could be split across two PRs if review size demands
   it; Phase 3 needs both.
3. One commit per fix, evidence regenerated by the gate, plan doc updated with an
   execution log (same discipline as `docs/remediation-plan-pkcs11-phase5-09072026.md`).
4. Before proposing a push: full `scripts/local-gate.sh --cpp` with
   `AG_CONTAINER_ROOT` set; the pre-push hook enforces the marker.
5. Hub changes (§6.5) land as their own PR after the hsm release that ships the
   engines, so the hub never mirrors constants an engine doesn't yet advertise.

Effort overall: **L** — Phase 2 dominates; Phase 1's spike is the real unknown.

---

## Sources

- liboqs Classic McEliece page — https://openquantumsafe.org/liboqs/algorithms/kem/classic_mceliece.html
- liboqs 0.16.0 release — https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0
- liboqs CONFIGURE.md — https://github.com/open-quantum-safe/liboqs/blob/main/CONFIGURE.md
- PQCA announcement, liboqs 0.14.0 — https://pqca.org/blog/2025/pqca-announces-release-of-liboqs-version-0-14-0-from-open-quantum-safe-project/
- oqs-provider ALGORITHMS.md — https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md
- oqs-provider discussion #646 (McEliece/NTRU removed in 0.8.0+) — https://github.com/open-quantum-safe/oqs-provider/discussions/646
- classic-mceliece-rust on crates.io / docs.rs — https://crates.io/crates/classic-mceliece-rust , https://docs.rs/classic-mceliece-rust/latest/classic_mceliece_rust/
- classic-mceliece-rust CHANGELOG — https://github.com/Colfenor/classic-mceliece-rust/blob/main/CHANGELOG.md
- liboqs-rust (`oqs` crate) — https://github.com/open-quantum-safe/liboqs-rust , https://docs.rs/oqs/latest/oqs/
- IETF draft-josefsson-mceliece-05 — https://datatracker.ietf.org/doc/html/draft-josefsson-mceliece-05
- ISO/IEC 18033-2:2006/Amd 2:2026 — https://www.iso.org/standard/86890.html ; coverage: https://thequantuminsider.com/2026/07/15/classic-mceliece-iso-standard-post-quantum-cryptography/
- NIST 4th-round outcome — https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/w-6RREtb7-c/m/S50CuhfqAAAJ ; https://classic.mceliece.org/nist.html
- D. J. Bernstein, McEliece standardization (2025-04-23) — https://blog.cr.yp.to/20250423-mceliece.html
- ePrint 2026/1630 and its assessment — https://eprint.iacr.org/2026/1630.pdf ; https://postquantum.com/security-pqc/mceliece-quasipolynomial-distinguisher/
