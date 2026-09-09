# Implementation plan — Classic McEliece, all parameter sets, both engines (2026-09-08)

Baseline: `main` at v0.29.0 (`dcf1b0c0`), branch `feat/classic-mceliece-all-param-sets`.
**Revision 2 (2026-09-09)** — Phase 0 is complete (P0-1 through P0-7). This revision
replaces every part of Rev. 1 that Phase 0's real spikes, builds, and cross-repo
research proved wrong or under-specified, most importantly the Rust design (§4) and
the C++ build integration (§5). Decisions D-1..D-4 (§2) are unchanged. It supersedes
the Classic McEliece rows of two earlier plans:

- `cacp-frodokem-mceliece-softhsm-kmip-policy-plan-07062026.md` (workspace root) —
  Phase 0.5 resolved to `mceliece6688128` only, option (a), because the Rust crate can
  compile exactly one parameter set per build. That scoping is what this plan removes.
- `docs/remediation-plan-cpp-rust-pkcs11-parity-2026-07-25.md` — designed C++ parity
  via liboqs, recommended "confirm intent before starting", and was never executed.
  Intent is now confirmed (§2, D-2).

Standing rules that apply throughout: one editor on PKCS#11/KMIP code (research may be
delegated, edits may not); OpenSSL 3.6.3+ only; PKCS#11 v3.2 baseline with v3.3 filling
gaps; the pre-push gate is `scripts/local-gate.sh`, and nothing is pushed without an
explicit go-ahead **per push** — implementing and locally gating every phase below does
not itself authorize pushing or opening a PR.

---

## 1. Where things stand (re-verified 2026-09-09)

| Surface | Today | Evidence |
|---|---|---|
| C++ engine | **No Classic McEliece at all** | `grep -ri mceliece src/lib/` → 0 hits |
| Rust engine | **1 of 10** parameter sets: `mceliece6688128` (BSI's Category-5 pick), via `classic-mceliece-rust = "3"` with the single feature `mceliece6688128` | `rust/Cargo.toml:190`, `rust/src/constants.rs:745-752` |
| Mechanisms | Vendor-defined, both engines' headers lack any standard constant: `CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN` `0x80000003`, `..._ENCAPSULATE` `0x80000004`, `CKK_PQCTODAY_CLASSIC_MCELIECE` `0x80000002`, `CKP_CLASSIC_MCELIECE_6688128 = 0x1`. **Already pinned in `scripts/check_pkcs11_constants.py:216-234`** (`"vendor"`/`"param-set"` kinds) — that pin gates every future addition. | `rust/src/constants.rs:745-752`; authority: `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` §1.4 |
| Mechanism ledger | **`scripts/gen_pkcs11_mechanism_ledger.py`, `scripts/pin_pkcs11_mechanism_info_ranges.py`, and `docs/pkcs11-mechanism-ledger.json` do not exist on `main` or on this branch.** They exist only on the unmerged `fix/pkcs11-d2-pkcs8-wire-format` branch (PR #233, OPEN, MERGEABLE, `REVIEW_REQUIRED`). **This is a hard sequencing dependency for Phase 3 — see §10.1.** | `ls scripts/*.py` (8 files, none of the three); `gh pr view 233` |
| KMIP 3.0 | `KmipAlgorithm::ClassicMcEliece6688128` on the **generic** OASIS codepoint `0x34` ("McEliece"). OASIS also defines `0x35` = McEliece-6960119 and `0x36` = McEliece-8192128; nothing for the other sizes or any `f` variant. Highest allocated vendor codepoint in the whole enum: `0x8000006d` (`CompositeMlDsa65EcdsaP384Sha512`) — **next free is `0x8000006e`.** | `kmip/src/kmip30/algos.rs:368-380,456-536`; `kmip/spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json:2094-2106` |
| CACP policies | BSI presets allow-list `Classic-McEliece-460896` / `-6688128` by name; fips-only / cnsa-2.0 deny `348864`/`460896`/`6688128` by name (never `6960119` or any `f` variant, because none exist yet). Linter (`kmip/src/policy/lint.rs:491-493`) already accepts the 5 non-`f` names; **no `f` name is accepted yet.** | `kmip/policies/*.yaml`; `kmip/src/policy/lint.rs:491-493` |
| Cross-validation oracle | `oqs = "0.10.1"` (dev-dependency only) → bundles **liboqs 0.12.0**, confirmed to expose **all 10** `ClassicMcEliece*`/`*f` variants already (`oqs-0.10.1/src/kem.rs:120-129`) — no crate-version bump needed. Its McEliece C source diffs from our vendored 0.16.0 submodule in exactly 51 files, every one accounted for by two changes: `OQS_MEM_cleanse` replacing `memset` (hardening, not logic) in `controlbits.c/h` (20 dirs × 2 files = 40), and new `*_keypair_derand`/`*_encaps_derand` declarations added to 11 header/wrapper files (`kem_classic_mceliece.h` + 10 `kem_classic_mceliece_<variant>.c`). **The Goppa-code/Beneš-network math itself is byte-identical between 0.12.0 and 0.16.0.** (P0-4, §9) | `diff -rq` between `~/.cargo/registry/.../oqs-sys-0.10.1+liboqs-0.12.0/liboqs/src/kem/classic_mceliece/` and the vendored `src/lib/crypto/oqs/liboqs/src/kem/classic_mceliece/`: 51 files differ, all sampled and explained |
| wasm (Rust) | Builds; 8 MiB shadow stack already set because a 6688128 public key (1,044,992 B) overflowed the 1 MiB default. A throwaway single-variant wasm build of the **real, unforked upstream crate** (not the P0-1 sizing spike) measured **52,994–56,273 bytes** per parameter set at `release`+`opt-level=s`+`lto` (matching `rust/Cargo.toml:223-226`'s wasm profile) — i.e. ~3 KB marginal cost per additional size within one field/Beneš family, not 10 independent multi-hundred-KB blobs. | `rust/build-wasm-bundle.sh:23-39`; throwaway spike `spike-mceliece-timing` (this session, deleted after use) |
| Hub | Already ships per-variant liboqs wasm for **all 10** variants (`@oqs/liboqs-js` 0.15.1 → `public/dist/classic-mceliece-*.js`), playground exposes 5 non-`f` sizes via `src/wasm/liboqs_kem.ts`; the softhsm/KMIP mirror (`src/wasm/softhsm/{constants,pqc}.ts`, `src/wasm/kmip/{kmipMeta,ttlv/codepointTable}.ts`) is hardcoded to `6688128` only in 4 files, no parameter-set argument on `hsm_generateClassicMcElieceKeyPair`. | hub `src/wasm/liboqs_kem.ts:17-102`; `src/wasm/softhsm/pqc.ts:372-405` |
| Hub migrate catalog | Rows exist for liboqs, oqs-provider, liboqs-rust (`oqs` crate), pqcrypto, Botan, Bouncy Castle, 01 Quantum IronCAP — **no row for `classic-mceliece-rust`**, the crate this engine actually ships | `pqctoday-hub/src/data/pqc_product_catalog_09072026_r15.csv` (33 rows mention McEliece) |

### 1.1 Library facts this plan is built on

- **liboqs 0.16.0** (2026-07-09) — all 10 variants (`348864, 348864f, 460896, 460896f,
  6688128, 6688128f, 6960119, 6960119f, 8192128, 8192128f`), implementation from
  SUPERCOP-20221025 (clean + AVX2, runtime CPU detection). liboqs's own algorithm page
  says the implementation "may not be constant-time", upstream is "no active
  maintenance" (OQS support tier 3), and `460896`, `460896f`, `6960119`, `6960119f`
  **fail liboqs's memory-leak tests on x86-64 under clang -O2/-O3**. CMake:
  `OQS_MINIMAL_BUILD="KEM_classic_mceliece_…;…"`, per-variant
  `OQS_ENABLE_KEM_classic_mceliece_<variant>`, `OQS_USE_OPENSSL` (AES/SHA2/SHA3 via
  OpenSSL ≥ 1.1.1 — we have 3.6.3), `OQS_BUILD_ONLY_LIB`, `OQS_DIST_BUILD`. **Confirmed
  buildable in both environments** (P0-2): the `pqc-rust` container (x86_64, OpenSSL
  3.6.3 at `/usr/local/ssl`) and, newly this revision, natively on the macOS host
  (arm64, Homebrew OpenSSL 3.6.3) — both produce a working `liboqs.a` with exactly the
  10 requested KEMs enabled, zero build warnings on the container, 14 (all
  `-Wimplicit-int-conversion`, pre-existing upstream code, none in McEliece's own
  sources) on the host clang.
- **oqs-provider dropped Classic McEliece in 0.8.0+** (open-quantum-safe/oqs-provider
  discussion #646; its `ALGORITHMS.md` lists no McEliece at all). There is therefore
  **no OpenSSL-EVP route** for C++ — it must call liboqs's C API directly. This is the
  first non-OpenSSL crypto dependency in the C++ engine, a deliberate exception to
  `CLAUDE.md`'s "OpenSSL EVP-only" principle, recorded as decision D-2.
- **`classic-mceliece-rust` 3.1.0** (docs.rs, upstream git `6e5ce0cbba807e5288b677cee07224a8e30a0876`)
  — pure Rust, `#![no_std]`, `#![forbid(unsafe_code)]` (zero `unsafe` in the whole
  crate), all 10 variants, but **one per build**: the parameter set is selected by a
  Cargo feature that gates crate-level constants AND — this is the fact Rev. 1 got
  wrong — **real algorithm code**, not just sizes. Full inventory in §4.0.
- **`oqs` crate 0.10.1** (locked in `rust/Cargo.lock`, correcting Rev. 1's "0.11.0")
  bundles liboqs **0.12.0** via `oqs-sys` unless `LIBOQS_NO_VENDOR=1` links a system
  liboqs; already exposes all 10 McEliece variants (see table above). Not a wasm crate.
- **`pqcrypto-classicmceliece`** binds PQClean, which was **archived read-only
  2026-08-04** (hub catalog row `pqclean`). Not a viable new dependency.
- **Sizes** (liboqs page and `classic-mceliece-rust`'s `api.rs`; independently
  re-confirmed this revision against the official Round-4 KAT files byte-for-byte —
  P0-3):

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

- **ISO/IEC 18033-2:2006/Amd 2:2026** (published June 2026; version `2026.06.15` of
  `classic.mceliece.org/iso.html`, fetched directly this revision — **P0-6 closed**)
  standardizes **`mceliece460896`, `mceliece460896f`, `mceliece460896pc`,
  `mceliece460896pcf`, `mceliece6688128{,f,pc,pcf}`, `mceliece6960119{,f,pc,pcf}`,
  `mceliece8192128{,f,pc,pcf}`** — 16 parameter sets, i.e. only the four *large*
  sizes, each in all four of {plain, f, pc, pc+f}. **`mceliece348864` and
  `348864f` are NOT in the ISO standard.** ISO's own page explains why: the
  original draft specified only `mceliece6*`/`8*` to hit "128 bits of security in
  the quantum model" (Grover's speedup); ISO added `mceliece4*` (460896) separately
  because Grover's speedup is bounded by attack latency, but **never added
  `mceliece3*` (348864) at all.** The team "recommends the mceliece6\* sizes for
  long-term security." The `pc`/`pcf` (plaintext-confirmation) variants ISO
  standardizes are **not implemented by liboqs or `classic-mceliece-rust`** — D-1's
  scope (5 sizes × {plain, f}, no `pc`) remains liboqs/crate reality, not ISO's
  full set; `348864`/`348864f` remain in scope here as the smallest,
  fastest-to-test pair even though ISO excludes them — this plan is scoped to what
  the two libraries implement, not to ISO's list.
- **NIST**: not a NIST standard; NIST selected HQC (March 2025) and said it "may
  consider" McEliece after ISO completes (now done).
- **BSI TR-02102-1 v2026-01 §2.4.2** recommends `460896`, `6688128`, `8192128` (+ `f`),
  in hybrid deployment. Not 348864, not 6960119.
- **Cryptanalysis**: the 2026 quasipolynomial result (ePrint 2026/1630) is a
  *distinguisher* (public code vs random code, 2^114–2^124 operations, exabyte
  storage), explicitly not a decryption or key-recovery break; no security claim of
  the scheme depends on indistinguishability. No parameter change is implied.
- **`f` interoperability — measured, not read (P0-6 closed → P0-5 closed).** Built
  liboqs 0.16.0 on both the container and the macOS host and ran all 30
  gen/encapsulate/decapsulate combinations across all 5 size pairs (both baselines,
  `f`-key-with-plain-mechanism both directions, plain-key-with-`f`-mechanism both
  directions): **every combination produces a matching shared secret, and every
  combination correctly implicit-rejects a tampered ciphertext (decapsulate
  succeeds, returns a different secret, never an error).** `f` and non-`f` of the
  same size are **fully byte-interoperable at encapsulate/decapsulate** — the
  difference is *keygen only* (semi-systematic form). **Consequence for §3.1 and §6.1
  scenario design:** a "wrong parameter set" negative test must use a genuinely
  incompatible *size* (e.g. a 348864 key against the 460896 mechanism), never an
  `f`-vs-non-`f` pairing of the same size — asserting rejection there would encode a
  false negative into the harness.

---

## 2. Decisions taken (2026-09-08, with the user — unchanged this revision)

| Ref | Decision | Consequence |
|---|---|---|
| **D-1** | Scope = **all 10 liboqs/crate variants** (5 sizes × {plain, f}). Not BSI's 6 only; not ISO's `pc`/`pcf` variants (§1.2 — no library implements them). | Every table below is 10 rows. `pc` variants are explicitly out of scope. |
| **D-2** | C++ gets McEliece by **vendoring liboqs 0.16.0 and calling its C API directly** — a documented exception to the EVP-only rule, forced by oqs-provider having dropped the algorithm. | New `src/lib/crypto/OSSLClassicMcEliece*` files (the file pattern stays, the "OSSL" prefix is kept for consistency even though the backend is liboqs; noted in each header). |
| **D-3** | Rust gets all 10 by **forking `classic-mceliece-rust` 3.1.0 into a multi-parameter-set crate** vendored under `rust/`, same layout as `fips204-patched`/`fips205-patched`. Pure Rust, wasm-capable, upstreamable. | The `oqs` crate stays a dev-dependency (oracle), never a shipping one. |
| **D-4** | **Rust wasm: yes, all 10. C++ Emscripten wasm: no** — the C++ wasm engine keeps not advertising McEliece; the asymmetry is documented and already has an adjudication shape (`LEGAL-BUILD-FLAG-VARYING-MECHANISM-SETS`). | Browser users get McEliece from the Rust engine bundle or the hub's existing liboqs-js, never from `libsofthsmv3.wasm`. |

Decisions still open are in §8.

---

## 3. Target surface (both engines must match exactly — the differential harness enforces it)

### 3.1 PKCS#11

- Mechanisms/key type unchanged: `CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN`
  (`0x80000003`), `CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE` (`0x80000004`),
  `CKK_PQCTODAY_CLASSIC_MCELIECE` (`0x80000002`). No new mechanism codepoints. All
  four already pinned in `scripts/check_pkcs11_constants.py:216-234`.
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

  Recorded in the priv authority file — see P0-7 (§9), which lands this table into
  `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` §1.4.
- `CKA_VALUE` stays **raw** bytes for both public and private keys (no SPKI/PKCS#8
  wrapper: there is no registered OID — the IETF draft defines none — and the
  differential harness already treats a secret/PQC `CKA_VALUE` as unstructured, per
  the 2026-09-07/08 `classify()` fixes). `CKA_PUBLIC_KEY_INFO` absent, as today.
- `C_GetMechanismInfo`: `ulMinKeySize`/`ulMaxKeySize` become the public-key byte range
  across the advertised sets — **261,120 … 1,357,824** — for both mechanisms, both
  engines (Rust's hard-coded `(1_044_992, 1_044_992, 0x00010000)` at
  `rust/src/ffi.rs:1432` goes away). Flags unchanged: keygen `CKF_GENERATE_KEY_PAIR`;
  encapsulate `CKF_ENCAPSULATE | CKF_DECAPSULATE`. The ledger pin
  (`scripts/pin_pkcs11_mechanism_info_ranges.py`, **not present until PR #233 lands —
  §10.1**) is regenerated once available so a drift on either side fails the gate; in
  the meantime `C_GetMechanismInfo` itself is updated and the differential harness's
  own mechanism-info scenario is the interim gate.
- `C_EncapsulateKey`/`C_DecapsulateKey` semantics unchanged; derived key attribute
  handling identical to ML-KEM (`CKA_VALUE_LEN` 32, template rules per v3.2 §6.68.5).
- Imported keys (`C_CreateObject`) accepted for every set, length-checked against the
  set's exact sizes — extend `register_classic_mceliece_{private,public}_key`
  (`rust/src/native/keygen.rs:1583-1636`, today a single crate-constant check) and add
  the C++ equivalent (today, C++ has no McEliece object type at all — see §5.3).
- **Negative "wrong parameter set" scenarios use a size mismatch, never an `f`-vs-non-`f`
  pairing of the same size** (§1.2 — f/non-f are proven interoperable at
  encapsulate/decapsulate; only keygen differs).

### 3.2 KMIP 3.0 / CACP

- Keep `ClassicMcEliece6688128 = 0x34` (generic OASIS "McEliece") — it is on the wire
  and in the hub's `kmipMeta.ts`/`codepointTable.ts`; renaming it would be a silent
  wire break.
- Use the **real OASIS codepoints** for the two the spec names: `0x35` →
  `ClassicMcEliece6960119`, `0x36` → `ClassicMcEliece8192128`.
- The remaining seven (`348864`, `348864f`, `460896`, `460896f`, `6688128f`,
  `6960119f`, `8192128f`) get **vendor extension codepoints, `0x8000006e` through
  `0x80000074`** — the exact next-free range confirmed against the real enum this
  revision (`kmip/src/kmip30/algos.rs`'s highest allocated value is `0x8000006d`,
  `CompositeMlDsa65EcdsaP384Sha512`), continuing the same numbering FrodoKEM used
  (`0x8000005f`–`0x64`). Recorded in the same authority file (P0-7). Order (matches
  the CKP table in §3.1, size-ascending):

| Codepoint | `KmipAlgorithm` variant |
|---|---|
| `0x8000006e` | `ClassicMcEliece348864` |
| `0x8000006f` | `ClassicMcEliece348864F` |
| `0x80000070` | `ClassicMcEliece460896` |
| `0x80000071` | `ClassicMcEliece460896F` |
| `0x80000072` | `ClassicMcEliece6688128F` |
| `0x80000073` | `ClassicMcEliece6960119F` |
| `0x80000074` | `ClassicMcEliece8192128F` |

  `no_invented_codepoints_in_the_standard_range` (`kmip/src/kmip30/algos.rs:1327-1348`)
  needs no change to its actual assertion (it only checks `ClassicMcEliece6688128 ==
  0x34`, which is unchanged) — only its surrounding "one deliberate exception" comment
  is updated to note 6960119/8192128 now sit on their real codepoints too.
- Display names follow the existing `Classic-McEliece-6688128` shape (see
  `kmip/src/kmip30/algos.rs:1021-1027`'s `spec_name()`); `f` variants as
  `Classic-McEliece-6688128f` (matches liboqs's own names and the hub playground).
- Policies: BSI presets allow-list exactly BSI's six (`460896`, `6688128`, `8192128`
  + `f`), **not** `348864`/`6960119`; fips-only and cnsa-2.0 deny all ten by name.
  This is a precision improvement, not a relaxation. `kmip/src/policy/lint.rs:491-493`
  gains the five `f`-suffixed names alongside the five already-accepted plain names.

### 3.3 wasm

- Rust engine bundle (`rust/build-wasm-bundle.sh`) and the KMIP wasm
  (`scripts/build-kmip-wasm.sh`): all ten. Stack stays 8 MiB; every McEliece call
  path must use the heap (`*_boxed`) API — an `8192128` public key on the shadow
  stack would exceed it. Per-variant marginal code size is small (§1: ~53–56 KB
  per size for the real crate, single-variant baseline) — 10 variants sharing 4
  field-arithmetic families (§4.1) should land well under naive 10× duplication.
- C++ Emscripten build (`scripts/build-wasm.sh`): liboqs is **not** cross-compiled;
  `WITH_LIBOQS` (§5.1) is forced off under `EMSCRIPTEN` and the mechanisms are not
  advertised there (D-4).

---

## 4. Rust engine — Phase 1

**Goal**: one build, ten parameter sets, pure Rust, wasm-clean.

### 4.0 What the upstream crate actually looks like (full inventory this revision)

Rev. 1 treated the fork as a sizing problem only (P0-1's spike proved the
const-generic *sizing* pattern compiles). **A full 23-file, 6,743-LOC inventory of
`classic-mceliece-rust` 3.1.0 (this revision) shows the ten `cfg(feature=...)` sets
differ in real algorithm code along five largely independent axes, not one:**

| Axis | Files | Split | Detail |
|---|---|---|---|
| **Field arithmetic** | `gf.rs` (1814 LOC, ~1550 of it tests) | **4-way**: `348864` alone; `460896` alone; `6960119` alone; `{6688128, 8192128}` together | Two whole `gf_mul` bodies (`gf.rs:21` vs `:48`); `gf_sq` exists only for 348864; `gf_sq2`/`gf_sqmul`/`gf_sq2mul` exist only for non-348864; `gf_inv`'s *definitional direction* inverts (348864: explicit chain; others: `gf_frac(den,1)`); the low-level `gf_mul_inplace` reduction step has **4 distinct tap sets**, one per group above. |
| **Beneš network** | `benes.rs` (525 LOC) | **2-way**: `348864` vs the other four | Two `apply_benes` overloads with different signatures (`&mut [u8;512]` vs `&mut [u8;1024]`), different loop bounds/strides, and 348864 uses in-place `transpose_64x64_inplace` (`transpose.rs`) where the others use out-of-place `transpose`. |
| **`bitrev` shift** | `util.rs` (1 line) | **2-way**, same boundary as Beneš | `a >> 4` (348864) vs `a >> 3` (others) — one line, but semantically load-bearing. |
| **Error-vector sampling** | `encrypt.rs::gen_e` | **2-way**: `8192128`/`8192128f` vs the other eight | 8192128(f): draws `SYS_T*2` bytes, uses them directly as indices (no range filter, since `SYS_N == 1<<GFBITS` for this set only). Everyone else: draws `SYS_T*4` bytes, rejects any index `>= SYS_N`, retries until `SYS_T` accepted. |
| **Padding / syndrome** | `encrypt.rs::syndrome`, `operations.rs::{check_pk_padding,check_c_padding,crypto_kem_{enc,dec}}` | **2-way**: `6960119`/`6960119f` vs the other eight | 6960119(f)'s `PK_NROWS = 1547` isn't a multiple of 8, so it alone needs a bit-realignment loop in `syndrome`, explicit padding checks, and `crypto_kem_enc`/`_dec` return a real `u8` status the others don't check (masking `c`/`key` to zero on bad padding). |
| **Semi-systematic keygen (`f`)** | `pk_gen.rs::{ctz,same_mask,mov_columns}`, `pk_gen.rs::pk_gen`'s conditional 5th `pivots` param, `operations.rs::crypto_kem_keypair` | **f vs non-f (5 vs 5)**, plus a **nested third case**: `6960119f` alone needs an extra 9-byte bit-shifted realignment inside `mov_columns` that no other `f` variant needs | The single algorithmic hook is `if row == PK_NROWS - 32 { mov_columns(...) }` inside Gaussian elimination — `(u, v) = (32, 64)` hardcoded, not named constants. |

Crucially: **`decrypt.rs`, `synd.rs`, `root.rs`, `bm.rs`, `sk_gen.rs`, `controlbits.rs`,
`int32_sort.rs`, `uint64_sort.rs`, `crypto_hash.rs` have zero non-test feature cfgs —
fully parameter-generic already**, and `uint64_sort` is already const-generic on
stable (`fn uint64_sort<const N: usize>(x: &mut [u64; N])`). `encapsulate`/`decapsulate`
public-API behavior is **byte-identical between `X` and `Xf`** of the same size — the
`f` split lives entirely inside keygen (`pk_gen.rs`/`operations.rs::crypto_kem_keypair`).
Zero `unsafe` anywhere in the crate (`#![forbid(unsafe_code)]`); `#![no_std]` + optional
`alloc`/`zeroize` (both in `default`, both needed here). No `rust-version` (MSRV) is
declared upstream.

### 4.1 Fork design — five independent axes, not one flat 10-way match

1. **Vendor the fork**: `rust/classic-mceliece-multi/` (a *new package name*, not a
   `[patch]` of `classic-mceliece-rust` — the public API changes, and a patched crate
   with the same name would still be one-set-per-build). Keep upstream's MIT license,
   `CHANGELOG.md`, and add a `README.md` stating the upstream tag (3.1.0, commit
   `6e5ce0cbba807e5288b677cee07224a8e30a0876`), what was changed, and that an upstream
   PR is intended (same convention as `rust/fips204-patched/README.md`, verified this
   revision to carry the unpatched upstream README verbatim with no fork note at all —
   the fork/patch narrative lives exclusively in this repo's own `CHANGELOG.md`, per
   `rust/README.md:156-172`'s documented convention).
2. **Sizing — settled by the P0-1 spike, unchanged.** `const N: usize` generic
   parameters directly on buffer types (`PublicKey<P, const N: usize>`, etc.), never
   `P::SOME_CONST` in array-length position (confirmed by the compiler, not just
   documentation — see P0-1 in §9). Per-variant type aliases supply `N` at a concrete,
   non-generic call site.
3. **Algorithm behavior — one trait/module per axis above, not one match per
   function.** Each axis becomes its own small set of free functions or a narrow
   trait with 2–4 concrete implementations, reused across the 10 variants that share
   a family:
   - `field12`, `field460896`, `field6960119`, `field_wide` (for 6688128/8192128) —
     four modules implementing `gf_mul`/`gf_sq`/`gf_frac`/`gf_inv` over `Gf = u16`,
     parameterized only by the small set of runtime/const values each needs (mostly
     none beyond `GFBITS`, which is a plain `usize`, not a buffer-sizing const-generic
     here — these functions operate on scalars and small fixed-size local arrays that
     `params.rs`'s upstream formulas already size independent of `SYS_N`/`SYS_T`).
   - `benes_narrow` (348864's in-place `[u8;512]` form) and `benes_wide` (the other
     four's out-of-place `[u8;1024]` form), matching the const-generic buffer shapes
     already spiked in P0-1.
   - `gen_e_range_reject` (used by 9 of 10 sets) and `gen_e_direct` (8192128/8192128f
     only).
   - `syndrome_plain` (used by 9 of 10 sets) and `syndrome_padded` (6960119/6960119f
     only, with its two padding-check helpers).
   - `keygen_systematic` (the 5 non-`f` sets — no `mov_columns` call) and
     `keygen_semi_systematic` (the 5 `f` sets — calls `mov_columns`/`same_mask`/`ctz`),
     with `6960119f`'s extra bit-realignment expressed as one more conditional branch
     inside `keygen_semi_systematic`, not a sixth module (it is the same function,
     one extra `if` gated on a `const REALIGN: bool` the `6960119f` variant alone sets
     `true`).
   The `McElieceParams` trait (unchanged in shape from P0-1: `GFBITS`/`SYS_N`/`SYS_T`/
   `SEMI_SYSTEMATIC` + the seven upstream-formula derived sizes + the literal
   `CRYPTO_SECRETKEYBYTES`) gains associated `fn`s (not consts) that each of the 10
   per-variant `impl` blocks fills in by simply calling the right family function —
   e.g. `Mceliece348864`'s `impl` points its `gf_mul` at `field12::gf_mul`,
   `Mceliece6688128`'s at `field_wide::gf_mul`. Every one of the ~10 per-variant impl
   blocks is then a short, mechanical list of "which family for each axis" — exactly
   the kind of boilerplate a `macro_rules!` is worth writing (Phase 1 step 4 below),
   never for the algorithm bodies themselves. Public API becomes
   `classic_mceliece_multi::mceliece348864::{keypair_boxed, encapsulate_boxed,
   decapsulate_boxed, PublicKey, SecretKey, Ciphertext, SharedSecret}` × 10, plus a
   `ParameterSet` enum with `fn sizes(self) -> (pk, sk, ct)` and
   `fn from_ckp(u32) -> Option<Self>` for the engine wiring (§4.2) to dispatch through.
4. **Build-time cost — measured, not estimated (this revision).** A throwaway
   single-variant timing spike (real upstream crate, deterministic RNG for
   reproducibility, `criterion`-free) on the macOS host (arm64):

   | Build profile | 8192128f keygen (representative single attempt) |
   |---|---|
   | `--release` (opt-level 3) | 422–442 ms |
   | `dev`, `opt-level = 1` (upstream's own historical mitigation) | ~1.1 s |
   | `dev`, `opt-level = 0` (what a dependency gets today — `rust/Cargo.toml` has no
     `[profile.dev.package.*]` override at all) | **23.6–24.0 s** |

   `opt-level = 0` is ~21× slower than `opt-level = 1` and ~55× slower than
   `--release`. **Recommendation, strengthened from Rev. 1's "opt-level = 1": use
   `opt-level = 3`**, the same as release — the further 3× gain over `opt-level = 1`
   matters when a test suite runs many keygens across 10 variants:
   ```toml
   [profile.dev.package.classic-mceliece-multi]
   opt-level = 3
   [profile.test.package.classic-mceliece-multi]
   opt-level = 3
   ```
   `rust/src/native/keygen.rs:2580-2585`'s `#[ignore]` on the 6688128 keygen test (and
   the three others at `rust/src/ffi.rs:18045-18242`, `rust/src/native/encrypt.rs`'s
   two liboqs cross-validation tests) are removed once this profile override lands —
   no test needs to stay `#[ignore]`d for a reason this override eliminates.
5. **KAT verification — reuse the crate's own upstream NIST-DRBG harness rather than
   reimplementing a DRBG.** `classic-mceliece-rust` already ships a correct NIST
   AES-256-CTR DRBG (`src/nist_aes_rng.rs`, test-only, self-tested against two 256-byte
   reference strings) and a KAT-format parser/generator (`src/test_katkem.rs`) whose
   output is checked by `tests/katkem.sh` against per-variant MD5 hashes recorded
   upstream — i.e. upstream has *already* proven this exact harness reproduces the
   official vectors for all 10 sets. The fork keeps this file (adapted to call each
   variant's now-namespaced functions instead of the crate-root ones) rather than
   writing a new DRBG — this is the concrete instantiation of §6.1's "KAT" row and
   Phase 1/2's KAT test (`classic_mceliece_kat.rs`), and unlike FrodoKEM's KAT test
   (which only decapsulates a known ciphertext against a known imported secret key,
   `kmip/tests/frodokem_kat.rs:39-41` — chosen there because no in-repo DRBG existed)
   this can additionally **re-derive `pk`/`sk` from `seed` and assert all five fields**
   (`seed`/`pk`/`sk`/`ct`/`ss`), a strictly stronger KAT than FrodoKEM's precedent.
6. **Tests**: per-set size assertions; keygen → encaps → decaps round trip per set;
   wrong-*size* rejection (never wrong-`f` rejection — §1.2/§3.1); import length
   checks; the full KAT re-derivation from §4.1 step 5.

### 4.2 Engine wiring — corrected from Rev. 1's single-crate-constant assumption

Today's McEliece arms read **compile-time crate constants** directly
(`classic_mceliece_rust::CRYPTO_PUBLICKEYBYTES`, fixed-size-array `TryInto`s) because
only one parameter set is compiled in. The fork exposes 10 namespaced modules instead
of one flat API, so every one of these call sites needs a **runtime dispatch table**,
mirroring the pattern FrodoKEM already established (`frodokem_algorithm(ps) ->
Result<frodo_kem::Algorithm, CkRv>` at `rust/src/native/keygen.rs:1828-1839` +
`frodokem_key_lens(ps) -> Option<(usize, usize)>` at `keygen.rs:1508-1519`), not the
single-arm inequality checks McEliece has today:

- `rust/src/constants.rs:745-752` — the nine new `CKP_*` values (§3.1's table).
- `rust/src/native/keygen.rs` — new `classic_mceliece_parameter_set(ps) ->
  Result<ClassicMcElieceSet, CkRv>` (mirrors `frodokem_algorithm`) and
  `classic_mceliece_key_lens(ps) -> Option<(usize, usize)>` (mirrors
  `frodokem_key_lens`), replacing the 8 hardcoded `!= CKP_CLASSIC_MCELIECE_6688128`
  inequality checks across `ffi.rs`/`keygen.rs`/`encrypt.rs`. `generate_classic_mceliece_keypair`
  (`keygen.rs:1884-1926`) and both `register_classic_mceliece_{private,public}_key`
  (`keygen.rs:1583-1636`) dispatch through it — a 10-arm match calling the fork's
  namespaced `keypair_boxed` per variant, or (if the boilerplate warrants it, decided
  during implementation, not here) a single generic helper parameterized the same way
  `syndrome_shaped_buffer` was in the P0-1 spike.
- `rust/src/ffi.rs`:
  - Keygen arm (`:3807-3894`) gains the same runtime `ps` dispatch FrodoKEM's arm
    already has (`:3721-3806`) instead of the current single inequality check.
  - Mechanism-info table (`:1426-1437`) becomes a single range tuple
    `(261_120, 1_357_824, 0x00010000)` / `(..., 0x10000000 | 0x20000000)` — matching
    FrodoKEM's already-established "min = smallest variant, max = largest variant"
    convention on the same table, replacing the hardcoded `(1_044_992, 1_044_992,
    ...)` pair.
  - `C_EncapsulateKey`/`C_DecapsulateKey` vendor-KEM branches (`:4377-4415`,
    `:4866-4906`) already branch on `mech_type` between FrodoKEM and McEliece and
    already call `get_object_param_set(...)`; only the `else` arm's `classic_mceliece_rust::
    CRYPTO_CIPHERTEXTBYTES` literal becomes `classic_mceliece_key_lens(ps)`-derived.
- `rust/src/native/encrypt.rs::classic_mceliece_{en,de}capsulate` (`:578-648`) — the
  fixed-size-array `TryInto<[u8; CRYPTO_PUBLICKEYBYTES]>` conversions (the hardest part
  to make per-set, since the length constraint is expressed in the *type*) are
  replaced by a 10-arm match dispatching to the right namespaced module's
  `encapsulate_boxed`/`decapsulate_boxed`, mirroring how `frodokem_{en,de}capsulate`
  already does length-checking construction via `EncryptionKey::from_bytes(alg,
  &pub_key_bytes)` rather than a fixed array type.
- `rust/src/ck_param.rs` — **not a validator module** (it's C-ABI mechanism-parameter
  struct layout, 1322 lines, one unrelated McEliece doc-comment mention). The
  parameter-set validation described above lives in `keygen.rs`/`encrypt.rs`/`ffi.rs`
  directly, matching where ML-KEM's and FrodoKEM's own validation already live —
  Rev. 1's reference to this file was wrong; corrected here.

Effort: **M** (the design is now settled in detail; the wiring is mechanical
repetition of the FrodoKEM pattern once the fork exists — the fork itself, porting
~5,000 non-test LOC across five real axes, is the actual unknown, hence still M not S).

## 5. C++ engine — Phase 2

**Goal**: native C++ parity, liboqs-backed, off by default under Emscripten.

### 5.1 Build integration (concrete this revision — Rev. 1 only named the submodule)

- `.gitmodules` already has `src/lib/crypto/oqs/liboqs` pinned to `5a1a854b0` (0.16.0,
  added this branch, P0-2). liboqs is **not yet wired into CMake at all** —
  `grep -rn oqs CMakeLists.txt src/CMakeLists.txt src/lib/CMakeLists.txt
  src/lib/crypto/CMakeLists.txt` returns nothing today. Unlike the `hash-sigs`/
  `xmss-reference` submodules (whose `.c` sources are hand-globbed straight into the
  engine's own `OBJECT` library, `src/lib/crypto/CMakeLists.txt:101-135`), liboqs ships
  its **own** substantial CMake build (options, feature detection, ASM) — the right
  integration is `add_subdirectory`, not globbing, mirroring how a real external CMake
  project is normally vendored:
  ```cmake
  # root CMakeLists.txt, near the other option() declarations (:9-19)
  option(WITH_LIBOQS "Link liboqs for Classic McEliece (no OpenSSL EVP route exists — D-2)" ON)
  if(EMSCRIPTEN)
      set(WITH_LIBOQS OFF CACHE BOOL "" FORCE)  # same pattern as WITH_OBJECTSTORE_BACKEND_DB, :21-23
  endif()

  if(WITH_LIBOQS)
      set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
      set(OQS_USE_OPENSSL ON CACHE BOOL "" FORCE)
      set(OQS_DIST_BUILD ON CACHE BOOL "" FORCE)     # AVX2 + runtime detection, one binary — same as P0-2's spike
      set(OQS_MINIMAL_BUILD
          "KEM_classic_mceliece_348864;KEM_classic_mceliece_348864f;KEM_classic_mceliece_460896;KEM_classic_mceliece_460896f;KEM_classic_mceliece_6688128;KEM_classic_mceliece_6688128f;KEM_classic_mceliece_6960119;KEM_classic_mceliece_6960119f;KEM_classic_mceliece_8192128;KEM_classic_mceliece_8192128f"
          CACHE STRING "" FORCE)
      add_subdirectory(src/lib/crypto/oqs/liboqs EXCLUDE_FROM_ALL)
  endif()
  ```
  then, in `src/lib/crypto/CMakeLists.txt`, `target_link_libraries(${PROJECT_NAME}
  $<$<BOOL:${WITH_LIBOQS}>:oqs>)` (liboqs's own CMake target name is `oqs`, confirmed
  by the P0-2 build). The exact cache-variable names/values above were confirmed
  working in P0-2's standalone spike build (container) and, this revision, the
  standalone macOS-host build — both produced a 10-KEM-enabled `liboqs.a` with these
  settings; only the `add_subdirectory` wiring itself is new.
- OpenSSL discovery is `include(FindOpenSSL)` (not `find_package(OpenSSL 3.5 ...)`)
  with a separate post-hoc version gate at root `CMakeLists.txt:96-99`
  (`OPENSSL_VERSION VERSION_LESS "3.5.0"` → `FATAL_ERROR`) — liboqs's `OQS_USE_OPENSSL`
  reuses the same `OPENSSL_ROOT_DIR`/`OPENSSL_INCLUDE_DIR`/`OPENSSL_CRYPTO_LIBRARY`
  cache variables the outer build already resolved, no separate discovery needed.
- `README.md`/`CLAUDE.md` gain one paragraph recording the EVP-only exception and why
  (D-2).

### 5.2 Classes — file-for-file mirror of `OSSLMLKEM*`, with exact precedent this revision

Confirmed against the real `OSSLMLKEM` family (`src/lib/crypto/OSSLMLKEM.{h,cpp}`
105+374 lines, `MLKEMParameters.{h,cpp}` 67+72, `MLKEMPublicKey.{h,cpp}` 79+108,
`OSSLMLKEMPublicKey.{h,cpp}` 78+192, and the private-key equivalents):

- `ClassicMcElieceParameters.{h,cpp}` — mirrors `MLKEMParameters`: holds the parameter
  set as a `CK_ULONG` (`getParameterSet`/`setParameterSet`), `serialise`/`deserialise`
  (raw memcpy of the `CK_ULONG`, no default parameter set — unlike ML-KEM's
  `CKP_ML_KEM_768` default, McEliece keygen has no default per §3.1). No seed field
  (liboqs's McEliece has no derand entry point usable here — §6.1's KAT row explains
  why the C++ KAT test is decapsulate-primary, matching the Rust fork's approach).
- `ClassicMcEliecePublicKey.h`/`PrivateKey.h` — abstract, mirrors `MLKEMPublicKey`/
  `MLKEMPrivateKey`: `parameterSet` + raw `ByteString value`, `getBitLength()`/
  `getCiphertextLength()`/`getOutputLength()` per §1.1's size table (parameter-set
  keyed, not a single constant).
- `OSSLClassicMcEliecePublicKey.h`/`PrivateKey.h`/`OSSLClassicMcElieceKeyPair.{h,cpp}` —
  **no `EVP_PKEY` caching** (unlike `OSSLMLKEMPublicKey`, which lazily builds and
  caches an `EVP_PKEY*` — there is no EVP route here at all, D-2). Instead each holds
  the raw key bytes directly (already what `MLKEMPublicKey::value`/`MLKEMPrivateKey::value`
  are conceptually, minus the EVP layer `OSSLMLKEMPublicKey` adds on top). This is the
  one structural place McEliece's C++ classes are *simpler* than ML-KEM's, not more
  complex — no `EVP_PKEY_CTX_new_from_name`/`createOSSLKey()` machinery, because there
  is no algorithm name to hand OpenSSL.
- `OSSLClassicMcEliece.{h,cpp}` — subclasses `AsymmetricAlgorithm` exactly like
  `OSSLMLKEM` does (§ below quotes the exact virtual signatures from
  `AsymmetricAlgorithm.h:237-278` this revision confirmed still current): `generateKeyPair`,
  `getMinKeySize`/`getMaxKeySize` (return **bytes** across all 10 sets — 261,120/
  1,357,824 — mirroring `OSSLMLKEM`'s own inconsistency of returning *bits* while
  `C_GetMechanismInfo` reports *bytes*, documented so as not to repeat it silently),
  `reconstructKeyPair`/`reconstructPublicKey`/`reconstructPrivateKey`/
  `reconstructParameters`, `newPublicKey`/`newPrivateKey`. `encapsulate`/`decapsulate`
  are declared on `OSSLClassicMcEliece` itself (not the abstract base — this matches
  `OSSLMLKEM`'s own precedent: `encapsulate`/`decapsulate` are *not* on
  `AsymmetricAlgorithm` at all, callers reach them via a static downcast, e.g.
  `((OSSLMLKEM*)mlkem)->encapsulate(...)` in `SoftHSM_kem.cpp:280`). sign/verify/
  encrypt/decrypt/deriveKey stay stubs returning `false` + `ERROR_MSG`, same as
  `OSSLMLKEM`. Each liboqs call goes through one thin RAII wrapper
  (`OQS_KEM_new(name)`/`OQS_KEM_keypair`/`OQS_KEM_encaps`/`OQS_KEM_decaps`/
  `OQS_KEM_free`), name selected by parameter set via a `paramSetToOqsName(CK_ULONG)`
  helper mirroring `OSSLMLKEMPublicKey::paramSetToName` (`OSSLMLKEMPublicKey.cpp:43-52`).
- `AsymAlgo::Type` (`AsymmetricAlgorithm.h:45-59`, currently `{Unknown, RSA, DSA, DH,
  ECDH, ECDSA, EDDSA, MLDSA, SLHDSA, MLKEM}`) gains `CLASSICMCELIECE`. Registration:
  `OSSLCryptoFactory::getAsymmetricAlgorithm()` (`OSSLCryptoFactory.cpp:149-173`) gains
  `case AsymAlgo::CLASSICMCELIECE: return new OSSLClassicMcEliece();` alongside the
  existing `case AsymAlgo::MLKEM:` (`:165-166`).

### 5.3 PKCS#11 wiring — exact edit sites, confirmed against the real ML-KEM path

- `SoftHSM::prepareSupportedMechanisms()` (`src/lib/SoftHSM_slots.cpp:419`, ML-KEM
  entries at `:666-668`) — two `t["CKM_..."] = CKM_...;` lines. Note this is a
  `std::map<std::string, CK_MECHANISM_TYPE>` name table, filtered afterward by the
  `slots.mechanisms` config string — adding an entry here is the whole registration
  step, no separate array to touch.
- `C_GetMechanismInfo` (`SoftHSM_slots.cpp:770`, ML-KEM cases `:1274-1285`) — one
  `case CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN:`/`case
  CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE:` pair reporting `(261_120, 1_357_824)`
  and the same `CKF_*` flags as §3.1.
- `C_GenerateKeyPair` dispatch (`SoftHSM_keygen.cpp`, ML-KEM's own dispatch at
  `:709-716` calling `generateMLKEM` at `:8419-8686`) — new `generateClassicMcEliece`
  following the same shape: `extractParameterSet` (the existing file-static helper at
  `:294`, no default min/max the way ML-KEM's is `CKP_ML_KEM_512..CKP_ML_KEM_1024` —
  McEliece's ten values are non-contiguous `0x1..0xA` so the helper's min/max-range
  form doesn't fit; either extend `extractParameterSet` with an explicit allow-list
  overload or add a small local validation function — decide during implementation),
  no seed handling (McEliece has no deterministic-keygen path, unlike ML-KEM's
  optional `CKA_SEED`), set `CKA_KEY_TYPE = CKK_PQCTODAY_CLASSIC_MCELIECE`,
  `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` defaults exactly as ML-KEM's
  `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` (`:8500-8580`, `:8582-8676`), `CKA_VALUE` raw
  (§3.1 — no `CKA_PUBLIC_KEY_INFO`, no SPKI builder needed at all here, simpler than
  ML-KEM in this one respect).
- `C_EncapsulateKey`/`C_DecapsulateKey` (`src/lib/SoftHSM_kem.cpp`; ML-KEM's dispatch
  at `:190-198`/`:550-556` inside `encapsulateKeyImpl`/`decapsulateKeyImpl`) — one more
  `if (pMechanism->mechanism == CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE)` branch
  alongside the existing `CKM_ECDH1_DERIVE`/`CKM_ML_KEM` branches, same key-type/
  class/`CKA_ENCAPSULATE`|`CKA_DECAPSULATE` gate sequence (`:210-240` for ML-KEM).
- `C_CreateObject` import — **new**, ML-KEM itself has *no* length check on import
  today (`grep 800|1184|1568` across `P11Attributes.cpp`/`P11Objects.cpp`/
  `SoftHSM_objects.cpp` finds none) — so McEliece doesn't need to add one either to
  match ML-KEM's actual behavior, but §3.1 commits to "length-checked against the
  set's exact sizes" for both engines, which is a **new, stricter bar than ML-KEM's
  own precedent**. Implement the check in the new `P11ClassicMcEliecePublicKeyObj::
  init`/`P11ClassicMcEliecePrivateKeyObj::init` (below) rather than skip it — flagged
  here explicitly since it means McEliece's C++ import path will NOT byte-for-byte
  mirror ML-KEM's (a deliberate, documented improvement, not a parity gap the harness
  needs an exception for, since Rust's own `register_classic_mceliece_*` already does
  length-check on import today).
- Object model: `src/lib/P11Objects.h`/`.cpp` — new `P11ClassicMcEliecePublicKeyObj`/
  `P11ClassicMcEliecePrivateKeyObj : public P11PublicKeyObj`/`P11PrivateKeyObj`,
  mirroring `P11MLKEMPublicKeyObj`/`P11MLKEMPrivateKeyObj` (`P11Objects.h:443-470`,
  `.cpp:2144-2235`) — registers `P11AttrParameterSet` (existing, generic — no
  algorithm-specific subclass needed, `P11Attributes.h:1316-1326`), `P11AttrValue`,
  and `P11AttrEncapsulate`/`P11AttrDecapsulate` (existing, generic). No
  `P11AttrSeed` (no seed attribute for McEliece).
- `SoftHSM_objects.cpp::newP11Object` — one more `else if (keyType ==
  CKK_PQCTODAY_CLASSIC_MCELIECE)` branch per public/private, alongside the existing
  `else if (keyType == CKK_ML_KEM)` (`:93-94`, `:116-117`).
- Vendor constants: `src/lib/vendor_mechanisms.h` currently has **no PQC-KEM vendor
  entries at all** (only `CKM_KECCAK_256`, `CKM_PQCTODAY_SPLIT_KEY`, both explicitly
  Rust-only, plus the v3.3-draft `CKM_ML_DSA_EXTERNAL_MU*` and the LMS/HSS/XMSS
  block). Add the four vendor codepoints from §3.1 here — this is the **first** time
  C++ advertises a value in the `0x80000000|n` space, so double-check
  `scripts/check_pkcs11_constants.py`'s `"vendor"` kind rule (must be `>=
  0x80000000` — all four already are) still passes; the four values are already
  pinned in that script (`:216-234`) as expected values from any of five sources
  including this header, so adding them here is completing an already-pinned
  expectation, not introducing a new drift risk.

### 5.4 Memory/timing hygiene

liboqs's own CI shows leak-test failures for four variants (`460896`, `460896f`,
`6960119`, `6960119f`) under clang -O2/-O3. Phase 2 exit requires an ASan/LSan run —
`cmake/modules/CompilerSanitizers.cmake` already has the plumbing
(`ENABLE_ASAN`/`ENABLE_UBSAN`, `-fsanitize=address,leak`, project-wide via
`add_compile_options`/`add_link_options`), documented (`cmake -B build-asan
-DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_UBSAN=ON`) but **currently
referenced by no script or CI workflow** — this phase is the first thing that
actually needs it. Run keygen/encaps/decaps for **all ten** with zero leaks; if a
variant genuinely leaks inside liboqs, it is **not advertised** by C++ until fixed
upstream (and the asymmetry goes into `exceptions.json` with the liboqs issue cited)
— no silent partial support. Do not claim constant-time anywhere; carry the same
audit-status caveat the July plan §0.7 established.

### 5.5 Cross-validation

A new C++ test — **a standalone ad-hoc executable, not a CppUnit suite addition**
(corrected precedent this revision: neither ML-KEM nor any other PQC algorithm has a
`src/lib/crypto/test/*Tests.cpp` file at all — `cryptotest`'s `SOURCES` list is
`AESTests/ECDHTests/ECDSATests/EDDSATests/HashTests/MacTests/RNGTests/RSATests` only,
pre-PQC classical algorithms; the actual PQC-KAT precedent is
`test_acvp_lms_sigver.cpp`, built ad hoc, checked in as a compiled binary, not present
in any CMakeLists). `test_classic_mceliece_kat.cpp`, built the same ad-hoc way, that:

(a) decapsulates the official KATs' known `ct` against the known imported `sk` for
    all ten sets and asserts the recovered `ss` matches (mirroring both the Rust
    fork's approach and FrodoKEM's own `frodokem_kat.rs` precedent — decapsulate-only,
    since McEliece's `encapsulate` draws non-deterministic randomness for `e` and
    liboqs's derand entry points for McEliece are of unproven usefulness here, not
    relied on); and

(b) round-trips against the Rust engine in both directions (C++ keygen → Rust encaps
    → C++ decaps, and the reverse) for all ten — the §3 cross-engine pattern of the
    July plan.

Effort: **L** (new C dependency + build integration is the bulk; the class code is
formulaic once liboqs links, and is in some respects *simpler* than ML-KEM's since
there is no EVP_PKEY layer to build).

## 6. Shared surface — Phase 3

1. **Differential harness** (`tests/differential/scenarios.inc`): a keygen scenario
   per set (attribute set, sizes, `CKA_PARAMETER_SET` round trip — mirroring the
   existing `create.generate_key_pair.ml_kem_768`/`..._all_params` scenario pair
   exactly, `scenarios.inc:377-398`/`:1890-1914`), an encaps/decaps scenario per set
   (ciphertext length, shared-secret length, tamper rejection — ciphertext bit-flip
   must yield a *different* secret, never an error, per implicit rejection — mirroring
   `create.encapsulate.ml_kem_768`/`..._all_params`, `:615-671`/`:1916-1971`), a
   missing-/wrong-**size** parameter-set negative (never wrong-`f` — §1.2), and the
   mechanism-info range check. **Today `scenarios.inc` has zero FrodoKEM or McEliece
   scenarios of any kind** — this is new coverage, not an extension of an existing
   vendor scenario. Every divergence adjudicated in `exceptions.json` with a citation
   or fixed — the harness's standing rule; note the existing `LEGAL-VENDOR-MECHANISMS`
   entry's `path` glob (`mech.CKM_VENDOR*`) does **not** match a named vendor
   mechanism like `CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN`, so a new
   McEliece-specific exception entry is needed wherever C++ doesn't yet advertise a
   set (e.g. during incremental Phase 2 rollout), not a reuse of that entry.
2. **Ledger — blocked on PR #233 (§10.1).** `scripts/gen_pkcs11_mechanism_ledger.py` →
   both rows become `implemented`/`implemented`; `scripts/pin_pkcs11_mechanism_info_ranges.py`
   pins the new min/max on both sides. **Neither script exists on `main` or this
   branch today** — confirmed this revision (`ls scripts/*.py`: 8 files, none of these
   three, nor `docs/pkcs11-mechanism-ledger.json`). They land with PR #233
   (`fix/pkcs11-d2-pkcs8-wire-format`), currently `OPEN`/`MERGEABLE`/`REVIEW_REQUIRED`.
   This step cannot execute until that PR merges and this branch rebases onto the
   result.
3. **KMIP/CACP** (§3.2, codepoints `0x8000006e`–`0x80000074`):
   `kmip/src/kmip30/algos.rs` — enum variants, `to_wire_value`/`from_wire_value`
   arms (`:456-610`), `to_pkcs11_mech` arms (`:714-736`, currently a single
   `ClassicMcEliece6688128` pair — becomes 10), `spec_name()` arms (`:964-1027`,
   currently 1 — becomes 10), `all_algos()` test fixture (`:1053-1080`); the stale
   module-doc line (`:12`, "Round-4 candidates... parked indefinitely") corrected;
   `kmip/src/ops/encapsulate.rs::is_classic_mceliece` (`:459-462`, currently a
   single-variant `matches!`) becomes a 10-arm `matches!`, mirroring `is_frodokem`
   (`:447-457`); `kmip/src/ops/helpers.rs::canonical_name` (`:313`) and
   `native_parameter_set` (`:1094`, currently single-arm each) gain 9 more arms each;
   `kmip/src/ops/create_key_pair.rs`'s display-name table (`:946`) and name→variant
   reverse map (`:1018`, currently single-arm with a "no ambiguity" comment that
   becomes stale) gain 9 more arms each; `kmip/policies/*.yaml` allow/deny lists
   (§3.2); `kmip/src/policy/lint.rs:491-493` gains the 5 `f`-suffixed names.
4. **KAT test** — `kmip/kat/classic-mceliece/` is **"sourced, not yet consumed"**
   today (its own README says so explicitly) — wire `kmip/tests/classic_mceliece_kat.rs`
   per §4.1 step 5 / §5.5(a)'s decapsulate-primary design, registered in
   `kmip/kat/manifest.sha256` (already has all 10 `.rsp` lines — the manifest
   integrity gate, `kmip/tests/acvp_roundtrip.rs:149-178`, already walks and verifies
   them; **note the documented regeneration command,
   `kmip/kat/README.md:77/167`'s `find . -name "*.json" -o -name "*.xml"`, would drop
   all McEliece/FrodoKEM `.rsp` lines if ever re-run naively — those lines were added
   by hand and must stay that way, or the glob needs fixing first**, out of scope
   here but flagged).
5. **`kmip/tests/frodokem_mceliece_e2e.rs`** — the McEliece `round_trip` call
   (`:160-172`, currently `#[ignore]`d for the same debug-build-slow reason §4.1 step
   4's profile override eliminates) gets the `#[ignore]` removed once that override
   lands, plus 9 more variant calls. **Correction to Rev. 1**: this file has **no
   liboqs oracle** at all (Rev. 1 cited "an oqs oracle at line 171" — that line is
   just the existing `round_trip()` call; `kmip/Cargo.toml` has no `oqs` dependency in
   `[dependencies]` or `[dev-dependencies]`). The only liboqs cross-validation lives in
   `rust/src/native/encrypt.rs:1962-2060` (Rust engine crate, not KMIP crate).
   `kmip/tests/policy_op_layer.rs:279-346`'s three McEliece assertions
   (`bsi_allows_frodokem_and_mceliece_with_hybrid_partner_tag` etc.) gain the other 9
   variants (loop or 9 more assertions — decide during implementation).
6. **Evidence regen**: `cpp_compliance_report.*` (regenerated by `p11_v32_compliance_test`,
   checked by `scripts/check_pkcs11_reports_fresh.py --cpp`, which **does** exist
   today), `rust/RUST_P11_V32_CONFORMANCE_REPORT.md` (new G8 rows — today's report has
   **zero Classic McEliece rows at all**, only FrodoKEM's four; the generator is
   `rust/test_p11_conformance.js`, not a Rust binary), `docs/pkcs11-mechanism-ledger.json`
   (blocked per item 2 above), KMIP replay report — via the gate, never by hand.
7. **Hub follow-ups (separate repo, separate PR)**: `src/wasm/softhsm/constants.ts`
   (nine `CKP_*`), `src/wasm/softhsm/pqc.ts::hsm_generateClassicMcElieceKeyPair`
   (`:372-405`, currently bakes `CKP_CLASSIC_MCELIECE_6688128` into both templates
   with **no** parameter-set argument — gains one), `src/wasm/kmip/kmipMeta.ts` +
   `ttlv/codepointTable.ts` (new codepoints), and one migrate-catalog row for
   `classic-mceliece-rust` (through the normal `add-catalog-row` flow with real
   evidence — the catalog currently omits the crate this engine ships). The hub's
   **liboqs** playground path (`src/wasm/liboqs_kem.ts`) already covers 5 of 10
   variants and needs no change for those; the softhsm/KMIP mirror is the only part
   that's single-variant today.

Effort: **M**.

---

## 7. Verification standard

Nothing here is "done" on a green build. Each item below is a gate for the phase that
owns it; all of it runs through `scripts/local-gate.sh` (core + `--cpp`), scoped runs
during iteration, the full run before a push — the 2026-09-07 lesson.

| Check | How | Owner |
|---|---|---|
| Official KATs, all ten | Sourced (P0-3, done): `kmip/kat/classic-mceliece/raw/*/kat_kem.rsp`, provenance recorded, checksummed in `manifest.sha256`. **Verification approach corrected this revision**: both engines decapsulate the official `ct` against the official `sk` and assert `ss` matches (mirroring FrodoKEM's own precedent); the Rust fork additionally re-derives `pk`/`sk` from `seed` via its own retained upstream NIST-DRBG test harness (§4.1 step 5) — a strictly stronger check than the minimum, not required of C++. | P0-3 done / Phases 1, 2 |
| Cross-implementation | Rust engine ↔ liboqs (`oqs` crate 0.10.1, already exposes all 10 — no bump needed) both directions, N=20 trials per set (the pattern already in `rust/src/native/encrypt.rs:1962-2060`, `#[ignore]`d today for the debug-slow reason §4.1 step 4 eliminates); C++ engine ↔ Rust engine both directions, all ten. `f`/non-`f` interoperability is **already proven** (P0-5, §1.2) — no further cross-implementation work needed for that specific question. | Phases 1, 2 |
| Oracle version hygiene | **Resolved (P0-4, closed this revision) — no action needed.** The `oqs` 0.10.1 oracle (liboqs 0.12.0) and the vendored liboqs 0.16.0 submodule's Classic McEliece C sources differ in exactly 51 files, every one accounted for by `OQS_MEM_cleanse`-vs-`memset` hardening and new (unused-here) derand entry points — the actual Goppa-code/Beneš-network math is byte-identical. Safe to use `oqs` 0.10.1 as-is; one doc-comment line in the cross-validation test records this. | Closed — P0-4 |
| Negative paths | Missing `CKA_PARAMETER_SET`, unknown value, wrong-**size** import (never wrong-`f` — §1.2), decapsulate with the wrong-size key, ciphertext tamper → new secret (implicit rejection), oversized template. Exact `CKR_*` codes identical on both engines. C++ import length-checking is a **deliberate improvement over ML-KEM's own precedent** (ML-KEM has none today) — see §5.3. | Phases 1, 2 |
| Memory | ASan/LSan (plumbing exists, `cmake/modules/CompilerSanitizers.cmake`, currently unused by any script/CI — this is the first consumer) over all ten on C++ (§5.4); Rust `miri` is not required (safe Rust, `#![forbid(unsafe_code)]` upstream — keep it in the fork). | Phase 2 |
| Large objects | Store, list, `C_GetAttributeValue`, export/import and KMIP Get of an 8192128 key pair on both engines; the differential harness records length and a fingerprint, never the bytes. Object-store file size and a `--cpp` gate time delta are recorded in the plan's execution log. | Phase 3 |
| wasm | `rust/test_xmss_release.js`-style node smoke for at least `348864` and `8192128` through the Rust wasm bundle, plus the KMIP wasm smoke (`wasm/smoke/smoke.cjs`) extended with one McEliece Create/Encapsulate — memory growth and the 8 MiB stack confirmed, not assumed. Per-variant wasm marginal size (~53–56 KB, measured this revision, §1) recorded before/after Phase 1 lands. | Phase 1 |
| Evidence freshness | `scripts/check_pkcs11_reports_fresh.py --cpp --rust` green on the final commit (this script **does** exist today — confirmed); the ledger scripts (item 2 of §6) are blocked separately per §10.1. | Phase 3 |
| Gate | Full `scripts/local-gate.sh --cpp` green (marker written for the pushed commit); `--javajce`/`--openssl-provider` only if their surfaces are touched (they are not, unless the openssl-provider vendor code gains a McEliece arm — out of scope). | Landing |

Test time is a first-class constraint: ten keygens, each side, each direction. Use
release-level optimization for the fork (§4.1 step 4 — `opt-level = 3`, not just 1),
`cargo nextest` (already landed on `main` — the gate's 40m53s→12m04s rewrite from
PR #230), and keep any test over ~60 s behind an explicit, documented reason, not a
silent `#[ignore]`.

---

## 8. Open decisions (need an owner before the phase that depends on them)

| Ref | Question | Recommendation | Blocks |
|---|---|---|---|
| **O-1** | KMIP codepoints for the seven variants without an OASIS value. | **Resolved this revision** — vendor extension codepoints `0x8000006e`–`0x80000074` (§3.2), the exact next-free range confirmed against the live enum. | Phase 3 |
| **O-2** | Record `CKP_*` values in the priv authority file (which today lists only CKM/CKK)? | Yes — add a "parameter-set values" subsection under §1.4; they are wire-visible and mirrored in the hub. **Now P0-7 (§9), scheduled before Phase 1 code lands, not after.** | Phase 1 |
| **O-3** | Ship all ten by default, or advertise only BSI's six by default with the other four behind a build/config switch? | All ten (D-1); policy, not the engine, is where BSI-vs-not is expressed (§3.2). | Phase 3 |
| **O-4** | Upstream the fork (PR to `Colfenor/classic-mceliece-rust`)? | Yes, after Phase 1 ships and the KATs pass — but the vendored copy is the shipping source regardless of upstream's response. | After Phase 1 |
| **O-5** | Version/CHANGELOG: this is a `[Unreleased]` "Added" for both engines; minor bump. | v0.30.0 when it lands; per-engine "Added" bullets (matching `CHANGELOG.md:9-16`'s current format — bold sentence-form claim, spec citation, engine-scoping idiom like "Rust engine only"), plus a "Changed" bullet for the mechanism-info range. | Landing |

---

## 9. Phase 0 — verify before building (COMPLETE — all 7 items, all with real evidence)

| # | Item | Done when |
|---|---|---|
| P0-1 | **DONE (2026-09-09, `rust/spike-mceliece-multi/`, throwaway).** Instantiated `Mceliece348864` and `Mceliece8192128f` together. **First design failed at compile time, and that failure is itself the result**: a trait with associated-const sizes read through a generic type parameter in array-length position is rejected outright (`generic parameters may not be used in const operations`) — a hard stable-Rust ceiling, not a style choice, confirmed by the compiler. **Second design compiles and passes**: bare `const N: usize` generic parameters, trait supplies sizes only at concrete per-variant type-alias sites. 4/4 tests green, sizes match §1.1 exactly, both variants coexist correctly-sized in one binary, a two-independent-length function works, compiles clean on `wasm32-unknown-unknown`. Caught its own first-draft bug: a guessed `CRYPTO_SECRETKEYBYTES` formula was off by 8 bytes — upstream never derives this one, only states it as a literal; fixed by matching upstream rather than trusting an invented formula. §4.1 (this revision) supersedes §4's original single-axis design with the real five-axis one, found by the full crate inventory below (not a further code spike — a research pass). |
| P0-2 | **DONE (2026-09-09).** Submodule pinned to `0.16.0` (`5a1a854b0`). Minimal build (`OQS_MINIMAL_BUILD` listing exactly the 10 `KEM_classic_mceliece_*` identifiers) configured and built clean in the `pqc-rust` container against OpenSSL 3.6.3, zero warnings, 1.2 MB static `liboqs.a`; a throwaway C program confirmed `OQS_KEM_alg_count()` = 41 compiled-in identifiers, exactly 10 `enabled=1` (all Classic-McEliece), full round trip matched §1.1's table on both size extremes. **This revision adds**: the same build repeated natively on the macOS host (arm64, Homebrew OpenSSL 3.6.3) — also clean, 14 pre-existing upstream `-Wimplicit-int-conversion` warnings (none in McEliece's own sources, all in liboqs's shared `opt64.c`), confirming the CMake integration plan in §5.1 is portable, not container-specific. |
| P0-3 | **DONE (2026-09-09, `22c31699`).** All 10 variants' `kat_kem.rsp` staged under `kmip/kat/classic-mceliece/raw/`, sourced from `classic.mceliece.org/nist/mceliece-kat-20221023.tar.gz` (sha256 pinned in the README), 10 vectors/variant, checksums in `kmip/kat/manifest.sha256`. **This revision adds independent verification**: liboqs 0.16.0's own `kat_kem` test binary (built from the submodule, both container and host) generated a fresh count-0 vector for all 10 variants and every field (`seed`/`pk`/`sk`/`ct`/`ss`) matched the staged official vectors **byte-for-byte** — strong assurance the vendored liboqs 0.16.0 build is spec-correct before any C++ code depends on it. |
| P0-4 | **DONE (2026-09-09).** Oracle version skew resolved by diff, not by upgrading or forcing `LIBOQS_NO_VENDOR=1`: `oqs` 0.10.1's bundled liboqs 0.12.0 and the vendored 0.16.0 submodule's Classic McEliece C sources differ in exactly 51 files (`diff -rq`), every one explained by two non-algorithmic changes (`OQS_MEM_cleanse` hardening in `controlbits.c/h`, new unused derand declarations) — sampled and confirmed representative. Recorded in §1/§7. |
| P0-5 | **DONE (2026-09-09).** Built a throwaway 30-combination interop+tamper test against liboqs 0.16.0, run on both the container (x86_64) and the macOS host (arm64): all 5 size pairs × 6 combinations (both baselines, `f`-key+plain-mechanism both directions, plain-key+`f`-mechanism both directions) produce matching shared secrets and correctly implicit-reject a tampered ciphertext. **`f` and non-`f` are fully interoperable at encapsulate/decapsulate; only keygen differs.** Consequence for scenario design recorded in §1.2/§3.1/§6.1. |
| P0-6 | **DONE (2026-09-09).** Fetched `classic.mceliece.org/iso.html` directly (version `2026.06.15`): ISO/IEC 18033-2:2006/Amd 2:2026 standardizes 16 parameter sets — `mceliece460896{,f,pc,pcf}`, `6688128{,f,pc,pcf}`, `6960119{,f,pc,pcf}`, `8192128{,f,pc,pcf}` — i.e. the four large sizes only, each in all four {plain,f,pc,pcf} forms; **`mceliece348864`/`348864f` are explicitly excluded** from the ISO standard (ISO added `mceliece4*` for latency reasons beyond the original `6*`/`8*`-only draft, but never added `3*`). Team recommends `mceliece6*` for long-term security. `pc`/`pcf` variants remain unimplemented by both liboqs and `classic-mceliece-rust` — D-1's scope (5 sizes × {plain,f}) is unaffected, but now explicitly known to be a *subset* of ISO's list plus one size (348864) ISO doesn't standardize at all. Recorded in §1.2. |
| P0-7 | **DONE (2026-09-09) — implementation in `pqctoday-priv`, committed locally, push pending separate confirmation per standing rule.** §3.1's CKP table and §3.2's KMIP codepoint table (`0x8000006e`–`0x80000074`) are the content landed into `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` §1.4 — see the priv-repo commit for the exact diff. |

---

## 10. Sequencing and landing

### 10.1 Hard dependency: PR #233

`scripts/gen_pkcs11_mechanism_ledger.py`, `scripts/pin_pkcs11_mechanism_info_ranges.py`,
and `docs/pkcs11-mechanism-ledger.json` — referenced throughout §3.1 and §6 — **do not
exist on `main` or on this branch.** They were added on `fix/pkcs11-d2-pkcs8-wire-format`
(PR #233 to `pqctoday-hsm`), currently `OPEN`, `MERGEABLE`, `REVIEW_REQUIRED`, not yet
merged. Phase 3's ledger-regeneration step (§6 item 2) is **blocked** until that PR
merges and this branch rebases onto the result. Phases 1 and 2 do not depend on it and
may proceed regardless; Phase 3's *other* items (differential harness, KMIP/CACP, KAT
test, evidence regen via `check_pkcs11_reports_fresh.py`, which **does** already exist)
are unaffected and proceed normally.

1. This branch (`feat/classic-mceliece-all-param-sets`) is cut from `main` v0.29.0 and
   stays independent of `fix/pkcs11-d2-pkcs8-wire-format` (landing separately). **When
   PR #233 merges, rebase once** — beyond the ledger scripts above, its harness fixes
   (`classify()` for raw PQC and secret keys, the gate's single-run steps) are ones
   this work relies on.
2. Phase 0 (complete) → Phase 1 (Rust) → Phase 2 (C++) → Phase 3 (shared). Phases 1 and
   2 are independent of each other and could be split across two PRs if review size
   demands it; Phase 3 needs both, and its ledger sub-item additionally needs #233.
3. One commit per fix, evidence regenerated by the gate, plan doc updated with an
   execution log (same discipline as `docs/remediation-plan-pkcs11-phase5-09072026.md`).
4. Before proposing a push: full `scripts/local-gate.sh --cpp` with
   `AG_CONTAINER_ROOT` set; the pre-push hook enforces the marker. **Each push remains
   a separate explicit approval per standing rule — executing and locally gating every
   phase in this plan does not itself authorize any push or PR.**
5. Hub changes (§6 item 7) land as their own PR after the hsm release that ships the
   engines, so the hub never mirrors constants an engine doesn't yet advertise.

Effort overall: **L** — Phase 2 dominates; Phase 1's real risk, now scoped precisely
by the five-axis inventory (§4.0), is porting five distinct algorithmic splits onto
one const-generic buffer scheme, not a single sizing question.

---

## 11. Execution log

**2026-09-09 — Phase 1 complete (`86baf7ef`, `e0a5e898`).**

`rust/classic-mceliece-multi/` (23 shared-module files + 10 per-variant modules,
~5,600 lines) forks `classic-mceliece-rust` 3.1.0 per §4.1's five-axis design, with
one real design correction found only during implementation: §4.1 as written
proposed sharing algorithm bodies via functions generic over `GFBITS`/`SYS_N`/
`SYS_T` **const-generic parameters**. Confirmed directly against `rustc` (not
assumed) that this doesn't compile either — a bare const-generic parameter used in
an *expression* in array-length position (`[T; N+1]`, `[T; 2*N]`, `[T; N/8]`) is
rejected exactly like the `P::CONST` case P0-1 already found, not just for
trait-associated consts. **Fix used instead**: internal algorithm functions take
runtime **slices** with `debug_assert!` length checks (matching how the C
reference implementation itself is written — pointer+length, not fixed-type-length)
rather than `[T; SYS_N]`-shaped fixed arrays; fixed local scratch buffers are sized
to the crate-wide maximum across all 10 variants (`MAX_SYS_T = 128`, `MAX_SYS_N =
8192`, etc.), not to a generic parameter. This let *more* code end up genuinely
shared than §4.1 anticipated — `controlbits.rs`, most of `gf.rs`, `transpose.rs`,
and `benes.rs`'s wide-family core are now single copies used by up to all 10 (or
all 8 wide) variants, not narrow/wide-duplicated as planned. Only `pk_gen.rs`/
`operations.rs` (the genuinely per-variant axis) still need multiple concrete
bodies, matching four templates (plain / 6960119 / f-generic / f+6960119f) instead
of the originally-envisioned single generic function.

Verified three independent ways, in order of what each actually proves:
1. **Official Round-4 KAT vectors** (`kmip/kat/classic-mceliece/`, P0-3) —
   `classic-mceliece-multi/tests/kat_verification.rs` decapsulates the official
   `ct`/`sk` pair for all 10 variants and asserts the recovered secret matches the
   published `ss` byte-for-byte. This is the one that actually proves the ported
   arithmetic is *correct*, not merely self-consistent.
2. **liboqs cross-validation** (`rust/src/native/encrypt.rs`, pre-existing test,
   `#[ignore]` removed) — 20 trials each direction, real engine ↔ real liboqs, for
   `mceliece6688128` (the only variant this test existed for before; extending it to
   the other 9 is Phase 3/§7 scope, not required to trust the port itself given (1)).
3. **Full PKCS#11 FFI path** (`rust/src/ffi.rs`) — `C_GenerateKeyPair` →
   `C_EncapsulateKey` → `C_DecapsulateKey` round trip through the real ABI, plus a
   new test exercising `generate_classic_mceliece_keypair` for all 10 CKP values
   (not just the previously-shipped 6688128) and asserting the exact
   `CRYPTO_PUBLICKEYBYTES`/`CRYPTO_SECRETKEYBYTES` per variant.

Real, measured numbers, not estimates: all 10 variants' keygen → encapsulate →
decapsulate in 8.1s (release) / 8.75s (debug, after the profile fix below); the
full McEliece test set (8 tests, including the two 20-trial liboqs cross-validation
tests) in 44.53s plain `cargo test` — no `--release` flag, no `#[ignore]`.
`rust/Cargo.toml` gained `[profile.dev.package.classic-mceliece-multi] opt-level =
3` / `[profile.test...]` — necessary because Cargo only reads `[profile.*]`
sections from a **workspace root** manifest, so the fork's own such sections (in
its own `Cargo.toml`, correct for standalone use) are silently ignored once it
became a workspace dependency; this was verified as the actual fix, not assumed,
by measuring debug-mode speed before and after (a single unoptimized-mode
`8192128f` keygen attempt was independently measured at 23.6–24.0s during Phase 0's
timing spike — the override removes that entirely from the default test path).

Deferred to Phase 3 rather than done now: extending the 6688128-only differential-
harness-equivalent engine tests (item 3 above) to all 10 variants at the Rust layer
is *possible* but redundant with (1)+(2) for correctness; Phase 3's actual
differential-harness scenarios (§6 item 1) are the real cross-engine gate this work
still needs, and depend on Phase 2 (C++) existing to diff against.

**Next**: Phase 2 (C++ engine, liboqs-backed, §5).

**2026-09-09 — Phase 2 complete (`f499a851`, `09506e4f`, `28d3b747`).**

Class hierarchy + liboqs CMake integration landed first (`f499a851`), then the
PKCS#11 mechanism wiring (`09506e4f`): `SoftHSM::generateClassicMcEliece`,
`encapsulateClassicMcEliece`/`decapsulateClassicMcEliece` (dispatched from
`encapsulateKeyImpl`/`decapsulateKeyImpl` exactly like the existing
`CKM_ECDH1_DERIVE` branch, since Classic McEliece is its own mechanism pair
with no ML-KEM-shaped code to share), `P11ClassicMcEliecePublicKeyObj`/
`PrivateKeyObj`, and mechanism-info registration. A new CppUnit suite
(`src/lib/test/ClassicMcElieceTests.cpp`) drives a full
`C_GenerateKeyPair` → `C_EncapsulateKey` → `C_DecapsulateKey` round trip
through the real ABI for all 10 parameter sets — caught one real bug during
development: `phKey` must be non-NULL even for a `C_EncapsulateKey` size
query (checked unconditionally at function entry, before the
`pCiphertext == NULL_PTR` branch), which the first draft test got wrong.

§5.5 cross-validation (`28d3b747`) both directions:
1. `test_classic_mceliece_kat.cpp` (ad-hoc, dlopen + `C_GetInterface` for the
   v3.2 function list — `C_GetFunctionList` only returns the legacy v2.40
   struct, discovered the hard way) decapsulates all 100 official Round-4 KAT
   vectors (10 variants × 10 vectors): 100/100 matched.
2. `test_classic_mceliece_cross_engine.cpp` +
   `rust/classic-mceliece-multi/examples/cross_engine_cli.rs` round-trip both
   engines against each other, both directions, all 10 variants (Rust
   keygen → C++ encaps → Rust decaps, and the reverse): 20/20 matched —
   proves wire-format compatibility for freshly generated keys, not just the
   official vectors both engines already pass independently.

§5.4 memory hygiene: a real `-DENABLE_ASAN=ON -DENABLE_UBSAN=ON` Debug build
(this phase's first actual consumer of that CMake plumbing), run three ways —
the 100 KAT decapsulations, a full keygen/encaps/decaps cycle for all 10
variants via the ad-hoc cross-engine tool, and the full CppUnit suite
(75 tests) — all clean. Sanity-checked LSan itself was actually firing in
this container first (a deliberate `new int[10]` leak, correctly caught).
Zero leaks touching Classic McEliece/liboqs code anywhere; the only leaks
present at all (8 reports, generic across the whole suite) are OpenSSL's own
`OSSL_PROVIDER_try_load_ex("legacy")` provider-init leak, unrelated to this
algorithm and present regardless of it. liboqs's own CI-reported leak-test
failures for `460896`/`460896f`/`6960119`/`6960119f` under clang -O2/-O3 did
not reproduce here (GCC, Debug+ASan) — carrying the plan's own caveat: this
doesn't disprove the upstream issue under different build flags, only that
this engine's own usage pattern doesn't trigger it. No `exceptions.json`
entry needed; all 10 variants stay advertised.

**Next**: Phase 3 (§6).

**2026-09-09 — Phase 3 complete for everything not blocked by PR #233
(`808fc95c`, `7d2e6bc0`, `b823a3bb`).**

§6 item 1 (differential harness, `808fc95c`): `tests/differential/scenarios.inc`
had zero FrodoKEM or McEliece scenarios of any kind before this (confirmed by
grep). Added the four the plan specifies — `create.generate_key_pair.
classic_mceliece_all_params`, `create.encapsulate.classic_mceliece_all_params`
(including a ciphertext-bit-flip implicit-rejection check: decapsulate MUST
still return `CKR_OK` but recover a *different* secret, never an error —
McEliece has no separate "invalid ciphertext" outcome the way a signature
verify does), `errors.classic_mceliece_parameter_set` (missing/out-of-range
`CKA_PARAMETER_SET`, deliberately never an f/non-f swap — that's a legitimate
different key, not an error), `env.mechanism_info_classic_mceliece` — mirroring
the ML-KEM pair's shape exactly. Ran the full 68-scenario suite against both
engines fresh-built: exit 0, zero UNCOVERED divergences. The only divergences
the 4 new scenarios produced matched pre-existing, algorithm-agnostic
exceptions (optional-attribute-not-materialised, usage-flag defaults); no new
`exceptions.json` entry was needed — the plan's anticipated
`LEGAL-VENDOR-MECHANISMS` glob gap doesn't materialise since both engines now
advertise all 10 sets symmetrically.

§6 items 3-5 (KMIP/CACP, `7d2e6bc0`): the `KmipAlgorithm` registry grew from 1
to 10 Classic McEliece variants (0x34/0x35/0x36 real OASIS codepoints +
0x8000006e-0x80000074 vendor extension, exactly the range this revision's
§3.2 table specified); every downstream consumer (`canonical_name` ×2,
`to_pkcs11_mech`, `is_classic_mceliece`, `native_kem_mech`,
`native_parameter_set`, the name↔variant reverse map) extended — two of these
were genuine non-exhaustive-match compile errors once the enum grew, not just
stale wildcards. BSI policy presets now allow-list exactly its 6 recommended
sets (not all 10 — 348864/6960119 correctly stay off the list, a precision
improvement over the prior single-variant state, not a relaxation); fips-only/
cnsa-2.0 deny all 10 by name. `kmip/tests/classic_mceliece_kat.rs` (new)
closes the "sourced, not yet consumed" gap §6 item 4 flagged — all 100
official KAT vectors decapsulated through the KMIP-facing native functions
directly, a third independent proof point alongside the crate-level and raw
FFI ones from Phase 1. `frodokem_mceliece_e2e.rs`'s single `#[ignore]`d
mceliece6688128 round trip is un-ignored and joined by the other 9 (the
`kmip` crate needed its OWN copy of the `[profile.dev.package.
classic-mceliece-multi]` override — it's a standalone crate, not a `rust/`
workspace member, so `rust/Cargo.toml`'s doesn't propagate to it, the same
profile-scoping fact Phase 1 already found once). `policy_op_layer.rs`'s 3
McEliece assertions extended to the actual boundary the policy change draws
(BSI's 6 allowed sets, a new assertion that the 4 not-recommended sets are
denied even WITH the hybrid-partner tag, fips-only/cnsa-2.0 denying all 10).
801 kmip lib tests pass; zero regressions.

§6 item 6 (evidence regen, `b823a3bb`) — via the real gates, not hand-edited:
`cpp_compliance_report.{json,md}` regenerated (891 PASS/0 FAIL/50 SKIP, was 48
SKIP — the delta is exactly the 2 new vendor mechanisms now being discovered
and correctly classified `OutOfScope` by that suite's own generic sweep;
`p11_v32_compliance_test.cpp` itself has no McEliece-specific test code, so
PASS/FAIL is otherwise unchanged by this plan). `rust/
RUST_P11_V32_CONFORMANCE_REPORT.md`'s own documented "Classic McEliece
deliberately untested here" gap (dated before this plan, when McEliece was
one ~1MB-key parameter set with `#[ignore]`d keygen) is closed with a real
new G8b section — both of the blockers that comment named are gone (10
parameter sets including a genuinely small one, and the profile override
applies to the wasm32 build too, package-scoped not target-scoped): 1013
passed/0 failed, up from 1007. `scripts/check_pkcs11_reports_fresh.py --cpp
--rust` passes clean against this commit.

**Not done, correctly deferred**: §6 item 2 (ledger regen) remains hard-blocked
on PR #233 per §10.1 — `scripts/gen_pkcs11_mechanism_ledger.py` and
`scripts/pin_pkcs11_mechanism_info_ranges.py` still don't exist on this branch
or `main`. §6 item 7 (hub follow-ups) is explicitly out of scope for this repo
— separate repo, separate PR.



- liboqs Classic McEliece page — https://openquantumsafe.org/liboqs/algorithms/kem/classic_mceliece.html
- liboqs 0.16.0 release — https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0
- liboqs CONFIGURE.md — https://github.com/open-quantum-safe/liboqs/blob/main/CONFIGURE.md
- oqs-provider ALGORITHMS.md — https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md
- oqs-provider discussion #646 (McEliece/NTRU removed in 0.8.0+) — https://github.com/open-quantum-safe/oqs-provider/discussions/646
- classic-mceliece-rust on crates.io / docs.rs — https://crates.io/crates/classic-mceliece-rust , https://docs.rs/classic-mceliece-rust/latest/classic_mceliece_rust/
- classic-mceliece-rust CHANGELOG — https://github.com/Colfenor/classic-mceliece-rust/blob/main/CHANGELOG.md
- liboqs-rust (`oqs` crate) — https://github.com/open-quantum-safe/liboqs-rust , https://docs.rs/oqs/latest/oqs/
- IETF draft-josefsson-mceliece-05 — https://datatracker.ietf.org/doc/html/draft-josefsson-mceliece-05
- Classic McEliece ISO page (fetched directly, P0-6) — https://classic.mceliece.org/iso.html
- ISO/IEC 18033-2:2006/Amd 2:2026 — https://www.iso.org/standard/86890.html ; coverage: https://thequantuminsider.com/2026/07/15/classic-mceliece-iso-standard-post-quantum-cryptography/
- NIST 4th-round outcome — https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/w-6RREtb7-c/m/S50CuhfqAAAJ ; https://classic.mceliece.org/nist.html
- D. J. Bernstein, McEliece standardization (2025-04-23) — https://blog.cr.yp.to/20250423-mceliece.html
- ePrint 2026/1630 and its assessment — https://eprint.iacr.org/2026/1630.pdf ; https://postquantum.com/security-pqc/mceliece-quasipolynomial-distinguisher/
