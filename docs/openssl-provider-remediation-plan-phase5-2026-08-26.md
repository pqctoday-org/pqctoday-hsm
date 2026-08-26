# OpenSSL provider remediation plan, phase 5 (2026-08-26) — plan only, nothing executed

Successor to `docs/openssl-provider-remediation-plan-phase4-2026-08-26.md`
(R7–R21, executed in full). Phase 4's close-out left exactly five active
gaps plus one parked family, confirmed by a full re-read of the coverage
audit's gap matrix (`docs/openssl-provider-coverage-audit-2026-08-25.md`
§4, corrected 2026-08-26 — 8 stale rows fixed in the same pass, commit
`4620968`). This plan covers those five as full items (R22–R26) and the
parked family (XMSS/XMSS-MT) as a scoping sketch (R27). Item numbering
continues phase 4's.

Everything below is grounded in a source-level pre-check done while
writing this plan (file:line anchors are from that pass, 2026-08-26),
not carried forward from earlier documents — phase 4 caught stale
carried premises three separate times (R10, R21, F36-6), so each item
here re-states its evidence explicitly and marks the one thing it could
NOT confirm from source as a probe step.

**Scope decisions (user, 2026-08-26):** five active items + XMSS
parked; the HSS cross-engine mismatch is resolved by making the
**provider param-set-aware** (not by changing either engine's default);
plan-only — execution is a separate, later instruction.

## Standing discipline (unchanged from phase 4)

- **Live-trace-confirm before fixing**: reproduce, trace to file:line,
  read the actual source, then fix. Never guess from an error string.
- **Cross-implementation proof**: every crypto result verified against
  the OTHER stack (token-op vs software-op byte parity, or an
  independent implementation), never self-verified.
- **Sabotage-test every new proof**: corrupt the thing the proof
  depends on; the proof must fail, and only the right cases must fail.
- **Engine-log verification + negative-control twin** (R13 pattern)
  for anything where silent software fallback could fake a pass.
- **Full regression before every commit**: C++ ctest, Rust
  `cargo test --release`, full `scripts/test-openssl-provider.sh`.
- **One commit per R-item**; coverage-audit §6 gets an append-only
  "Phase 5, R##" entry per item; this plan's header and the item's own
  section get an "Execution update" paragraph when it lands; the gap
  matrix row flips to RESOLVED **in the same commit** (phase 4 left 8
  rows stale by deferring this — don't repeat it).
- **No push without explicit confirmation.**

## Recommended execution order

| Order | Item | Gap ids | Effort | Why this position |
|---|---|---|---|---|
| 1 | R24 EVP_SKEY probe | F36-3 | S (probe) | Its findings decide whether R22/R23 ship `derive_SKEY`/SKEY-input support in the same pass or not — run it first so they land complete. |
| 2 | R22 SP800-108 KDF | OP-5 remainder | M | Same shape as R10's PBKDF2 (proven pattern, `kdf.c`); highest standard-caller relevance of the code items. |
| 3 | R23 CMAC + KMAC | OP-1/ALG-8 remainder | S–M | Extends R8's existing `mac.c`; small diff, one probe unknown (KMAC customization string). |
| 4 | R25 HSS param-set awareness | R9 carry-over + new cross-engine finding | M | Touches provider + BOTH engines + spec-conformance fix in Rust; unblocks R9's parked multi-process test. |
| 5 | R26 ChaCha20/Poly1305 | ALG-7 | M–L | Largest genuinely-new plumbing (a second cipher family); last so everything else isn't hostage to it. |
| — | R27 XMSS/XMSS-MT | ALG-2 | parked | Demand-driven; sketch only (below). No trigger exists today. |

---

### R22 — SP800-108 Counter/Feedback KDF ("KBKDF") — effort M

**Execution update (2026-08-26):** R22 executed and landed — see
`docs/openssl-provider-coverage-audit-2026-08-25.md`'s "Phase 5, R22"
entry for the full mechanism. Byte-identical to software across both
Counter and Feedback modes and both HMAC/CMAC PRF families, live-
verified, sabotage-tested. Two real bugs found and fixed along the
way, neither anticipated by this plan: a general C_DeriveKey write-
authorization requirement R10's own PBKDF2 fix had already documented
but never applied to another base-key-object derive path (HKDF's own
bare session-acquisition call only avoided it because its real callers
always logged in first for other reasons); and a `CKA_KEY_TYPE =
CK_UNAVAILABLE_INFORMATION` output-template value that HKDF's own
engine handler silently ignores but SP800-108's does not
(`CKR_TEMPLATE_INCONSISTENT`), fixed by passing `CKK_GENERIC_SECRET`
explicitly on KBKDF's own call site only. Also surfaced and worth
carrying forward to R23/R25/R26: `openssl kdf`'s CLI subcommand needs
`pkcs11-module-load-behavior=early` to reach this provider at all
(same WART-4 class of gap as the original finding, just for a
previously-unexercised code path) — its absence produces a SILENT
fallback to the default provider that looks byte-identical and error-
free, the exact hazard R13 exists to catch; budget time for it in any
item whose harness cases drive `openssl kdf` directly. Base HKDF's own
call site deliberately left unchanged by the second fix (its current
behavior is proven working; there was no reason to touch it).

**Premise, re-verified from source (not carried):** both engines fully
implement it, not just advertise it. C++: advertised
(`SoftHSM_slots.cpp:471-472`, mech-info `:1178-1179`) AND really
dispatched in `C_DeriveKey` (`SoftHSM_keygen.cpp:2755-2756`, counter
implementation at `:3208`, `CK_SP800_108_PRF_TYPE` validation per the
§6.26 comment at `:173`). Rust: advertised (`ffi.rs:1214-1215`) AND a
real `CK_PRF_DATA_PARAM` parser exists (`ffi.rs:7490-7544`, including
`CK_SP800_108_COUNTER_FORMAT` handling). R10's probe (a) reached the
same conclusion independently.

**OpenSSL side:** fetch name `KBKDF` (default provider), mode selected
via `OSSL_KDF_PARAM_MODE` (`COUNTER`/`FEEDBACK`); params `mac`
(`HMAC`/`CMAC`), `digest`, `key`, `salt` (label), `info` (context),
`use-l`, `use-separator`, `r` (counter width). The provider registers a
matching `KBKDF` implementation the same way R10's PBKDF2 section does
(`kdf.c`: newctx/freectx/reset/set+settable/get+gettable/derive plus a
dispatch table and a `provider.c` registration gated on the mechanisms).

**Where this is NOT a PBKDF2 clone — plan for these up front:**
1. **Base key handle required.** PBKDF2's password travels inside
   `CK_PKCS5_PBKD2_PARAMS2`; SP800-108 derives FROM a real base key
   object. Reuse `p11prov_create_secret_key` (already used by HKDF, and
   it hardcodes `CKA_DERIVE` — which is exactly right here, unlike the
   R8 MAC case where that hardcoding forced a new function).
2. **Data-param sequence construction.** OpenSSL's KBKDF
   `use-l`/`use-separator`/`r`/salt/info knobs must be translated into
   the PKCS#11 `CK_PRF_DATA_PARAM[]` sequence (`CK_SP800_108_ITERATION_
   VARIABLE` + `CK_SP800_108_BYTE_ARRAY` entries + optional
   `CK_SP800_108_DKM_LENGTH`; types at `pkcs11t.h:2463-2470`). The
   byte-exact layout the ENGINE produces for a given sequence is the
   thing to match against software KBKDF — get parity empirically, per
   mode, before writing the harness case. If a specific OpenSSL knob
   combination cannot be expressed in `CK_PRF_DATA_PARAM` terms, reject
   it in `set_ctx_params` loudly (documented divergence) rather than
   silently deriving something else — the R10/F36-6 precedent.
3. **PRF coverage:** engine PRF is `CK_SP800_108_PRF_TYPE` =
   `CKM_SHA*_HMAC` mechanisms. CMAC-PRF (`mac=CMAC`) support in the
   engines is UNKNOWN — probe first; if absent, register with
   HMAC-only `mac` values and record it, don't fake it.
4. **`derive_SKEY`:** include iff R24's probe (run first) shows the
   opaque-key flow works through this provider's SKEYMGMT; otherwise
   record as F36-3-dependent, same as PBKDF2's own deferred half.

**Proof plan:** token KBKDF == software KBKDF byte parity, both modes,
≥3 digests each; engine-log verified (`log.level=DEBUG` arena, T13
pattern) + negative-control twin; sabotage = corrupt exactly one
digest→PRF mapping, exactly one case must fail. Harness cases T25
(counter, per-digest) / T25f (feedback). Gap-matrix OP-5 flips to fully
RESOLVED in the same commit.

### R23 — CMAC + KMAC-128/256 as EVP_MAC, + HMAC/CMAC/KMAC `INIT_SKEY` — effort S–M

**Execution update (2026-08-26):** R23 executed and landed — see
`docs/openssl-provider-coverage-audit-2026-08-25.md`'s "Phase 5, R23"
entry for the full mechanism. CMAC and KMAC-128/256 both live-verified
byte-identical to software, sabotage-tested; `OSSL_FUNC_MAC_INIT_SKEY`
added to all three MACs, closing R24's own gap — re-ran R24's own
`skey_flow_probe` unchanged and its previously-failing consume step
now passes end to end, cross-checked against independent software
HKDF+HMAC. No new provider bugs found this item (unlike R22/R24); two
bugs in this item's own new test cases were found and fixed instead —
a missing env-var prefix on two rejection-control assertions (silently
checked the wrong arena) and a hand-typed sabotage key one byte short
of a valid AES length — both caught by manually reproducing the exact
failing command outside the harness before concluding the provider
code was at fault.

**Scope addition (from R24's own execution, 2026-08-26):** R24's probe
found `mac.c`'s HMAC never registered `OSSL_FUNC_MAC_INIT_SKEY` — a
correctly-derived, correctly-opaque `EVP_SKEY` (proven working via
HKDF's `derive_SKEY`) has nothing in this provider that can consume it
natively; `EVP_MAC_init_SKEY` fails at the OpenSSL EVP layer before
reaching any provider code. Add `INIT_SKEY` dispatch to `mac.c` for
HMAC (existing, R8) alongside the new CMAC/KMAC entries below — same
file, same class of gap, and this was already the next item touching
it. Proof: repeat R24's own HKDF-derive→consume cross-check
(independent software HKDF+HMAC of known inputs), this time actually
reaching the consume step; extend to CMAC/KMAC once those land.

**Premise, re-verified:** the C++ engine's MAC table
(`SoftHSM_sign.cpp:134-136`) really dispatches all three: `CKM_AES_CMAC`
(key MUST be `CKK_AES`, generic-secret NOT accepted — table column
`allowGenericSecret=false`), `CKM_KMAC_128`/`CKM_KMAC_256`
(`CKK_GENERIC_SECRET` accepted, minimum key 16/32 bytes). KMAC ids are
**vendor-defined** (`CKM_VENDOR_DEFINED|0x100/0x101`,
`pkcs11t.h:1264-1265`) and the Rust engine uses the identical values
(`constants.rs:457-458`); Rust also lists `CKM_AES_CMAC`
(`constants.rs:595`, mech list `:808-809`) — but the audit's ALG-8 row
says "CMAC C++-only", so **probe the Rust CMAC dispatch first** and
plan the Rust harness arm accordingly (advertise-vs-dispatch is the
distinction R10 established).

**Provider work** — extend R8's `mac.c`, no new file:
- CMAC: EVP_MAC name `CMAC`. OpenSSL callers select the cipher via
  `OSSL_MAC_PARAM_CIPHER` (e.g. `AES-256-CBC`) — accept AES-CBC names
  only, map key length from the cipher name, and create the ephemeral
  session key as `CKK_AES` (NOT the HMAC-typed keys `mac.c` makes
  today — the engine's table enforces the key type, so reusing the
  existing key path would fail against the real engine; extend
  `p11prov_create_mac_key` with a key-type argument).
- KMAC: EVP_MAC names `KMAC-128`/`KMAC-256`; params `key`, `size`,
  `custom`. **Probe first:** whether the engines' `CKM_KMAC_*` accept a
  mechanism parameter for the customization string S and/or a variable
  output length. `SoftHSM_sign.cpp`'s table row carries only key-type
  and min-key info, which suggests fixed defaults — if S/`size` are not
  expressible, register KMAC with `custom` restricted to empty and
  `size` restricted to the engine's output length, rejecting anything
  else loudly (documented divergence, F36-6 pattern).

**Proof plan:** byte parity vs software `CMAC`/`KMAC-128`/`KMAC-256`;
engine-log + negative twin (R13); sabotage = corrupt the CMAC key-type
selection (send generic-secret) — the engine itself must reject it,
proving the table constraint is real. Harness T26/T26b/T26c. OP-1 and
ALG-8 flip to fully RESOLVED in the same commit.

### R24 — `EVP_SKEY` opaque-key flow probe (F36-3) — effort S, probe-first

**Execution update (2026-08-26):** R24 executed and landed — see
`docs/openssl-provider-coverage-audit-2026-08-25.md`'s "Phase 5, R24"
entry for the full mechanism. One real bug found and fixed
(`skeymgmt.c`'s four entry points never called `p11prov_ctx_status()`,
so `EVP_SKEY` was broken as the first pkcs11 operation in a process —
masked until now because every other test always does a keygen/sign
first); one real gap found and folded into R23's scope instead of
treated separately (`mac.c`'s HMAC never registered
`OSSL_FUNC_MAC_INIT_SKEY`, so a correctly-derived, correctly-opaque
SKEY has nothing in this provider that can consume it yet); one
investigation not pursued to a conclusion (TLS13-KDF's own
`derive_SKEY` mode routing — logged, not chased, per this plan's own
ALG-6/R17-style precedent). HKDF's derive_SKEY → EVP_MAC_init_SKEY
chain is proven cryptographically correct AND fully opaque via an
independent software cross-check. Harness `T24b` added as a regression
guard. **R23 now additionally scopes: add `INIT_SKEY` dispatch to
`mac.c` for HMAC (existing) and the new CMAC/KMAC (planned) alike** —
see R23's own section below, updated to reflect this.

**The question** (unprobed through all of phases 1–4): the provider
registers SKEYMGMT for `AES` and `GENERIC-SECRET` (`provider.c:
1835-1837`), and the staged 3.6.3 exposes the full new API
(`EVP_SKEY_generate` at `evp.h:2268`, `EVP_PKEY_derive_SKEY` at
`evp.h:2060`, `EVP_KDF_derive_SKEY` at `kdf.h:47`) — but nobody has
ever checked whether a token-resident secret actually CHAINS through
these flows without its bytes being exported to software.

**Probe tool** (permanent, CMake-target, `dump-int-param` precedent —
the CLI cannot drive any of this): `scripts/skey-flow-probe.c`,
exercising against a live arena:
(a) `EVP_SKEY_generate` over the pkcs11 SKEYMGMT — does a token object
    get created (engine log), and is the SKEY opaque?
(b) `EVP_KDF_derive_SKEY` with HKDF/TLS13-KDF (the two KDFs R10's
    probe (b) said already have skeymgmt support) — does the derived
    key stay token-resident?
(c) Chain the derived SKEY into a consuming operation (EVP_MAC via R8's
    HMAC, or AES cipher) — do the bytes ever cross into software?
    (Assert via engine log + absence of `EVP_SKEY_get0_raw_key`-style
    export in the trace.)

**Output:** a mandatory write-up in the coverage audit (F36-3 row flips
to RESOLVED-as-probed either way). Code changes only if a real gap with
a real consumer path emerges — and if (b) works, R22 picks up
`derive_SKEY` for KBKDF in its own item. This is deliberately the
FIRST item executed.

### R25 — HSS param-set-aware provider + cross-engine attribute standardization — effort M

**Chosen direction (user, 2026-08-26):** keep both engines' differing
LM-OTS defaults (C++: `LMOTS_SHA256_N32_W8`, `SoftHSM_keygen.cpp:774`;
Rust: `CKP_LMOTS_SHA256_N32_W4`, `ffi.rs:2728`) and make the provider
read the key's ACTUAL parameter set instead of assuming one. This also
unlocks non-default parameter sets later, which neither alternative
would have.

**New finding while grounding this plan — a real Rust spec bug rides
along:** PKCS#11 v3.2 defines official HSS attributes
(`pkcs11t.h:636-641`): `CKA_HSS_LEVELS` (0x617), `CKA_HSS_LMS_TYPE`
(0x618), `CKA_HSS_LMOTS_TYPE` (0x619), plural `..._TYPES` (0x61a/0x61b),
`CKA_HSS_KEYS_REMAINING` (0x61c). The Rust engine stores the **level
count under `CKA_HSS_LMS_TYPE`** (`ffi.rs:2756/2768` — `store_ulong(...,
CKA_HSS_LMS_TYPE, levels)`), which per spec is the LMS *type*, and puts
the actual types under vendor attrs `0x80000102/0x80000103`
(`vendor_mechanisms.h:35-36`). The C++ engine stores neither (only
`CKA_KEY_GEN_MECHANISM` + vendor `ATTR_CKA_HSS_KEYS_REMAINING`,
`SoftHSM_keygen.cpp:919-941`).

**Work, in dependency order:**
1. **Standardize both engines on the official attributes** at HSS
   keygen: `CKA_HSS_LEVELS` = L, `CKA_HSS_LMS_TYPE`/`CKA_HSS_LMOTS_
   TYPE` = the (top-level) IANA type ids, on BOTH key halves. Fix the
   Rust `CKA_HSS_LMS_TYPE`-holds-levels misuse; KEEP writing the vendor
   attrs too (Rust's own ACVP flow reads them, `ffi.rs:5481-5482` —
   back-compat, not duplication for its own sake). C++ adds the same
   stores in its keygen transaction blocks.
2. **Provider reads them**: `fetch_hss_key` (objects.c) fetches the
   three official attrs; `keymgmt.c` `get_params` and `sig/hss.c`
   replace `HSS_L1_DEFAULT_SIG_SIZE` with a real RFC 8554 size function
   `hss_sig_size(levels, lms_type, lmots_type)` built from the IANA
   parameter tables (n/h from LMS type, n/w/p from LM-OTS type; the
   §5.4/§6.1 accounting already derived and live-confirmed for W8 in
   R9). **Fallback** for keys with no attrs (pre-standardization tokens,
   imported keys): parse the public `CKA_VALUE` — the HSS wire format
   is self-describing for the top level (`u32 L || lms_type || ots_type
   || I || K`), which is sufficient for L=1.
3. **Live proof across ≥2 parameter sets**: generate a second,
   non-default key (W4, matching Rust's default) via a direct-PKCS#11
   keygen tool passing an explicit `CK_HSS_KEY_PAIR_GEN_PARAMS`
   (extend `scripts/hss-pubkey-dump.c`'s pattern; do NOT grow provider
   `gen_set_params` surface for this — a raw tool is smaller and the
   generated key still flows through the provider for load/sign).
   Assert the provider signs/verifies BOTH keys with correct sizes
   (1296 for W8; the W4 size asserted from the formula AND the live
   output — never one alone).
4. **Unblocks R9's parked halves**: the Rust-arm T24 twin (same case
   over `libsofthsmrustv3.so`, now working because the provider reads
   the real param set) and the multi-process stateful-counter test the
   phase-4 plan's R9 text specified — `SOFTHSMRUST_STATE_FILE`, sign in
   two separate processes, assert the LMS leaf counter `q` advanced
   (bytes 4–8 of the bare LMS signature: q=0 then q=1) and the first
   signature still verifies. Both become harness cases (T24b/T24c).

**Proof plan:** all of the above + cross-implementation re-verify (the
R9 `lms_xdr_verify` tool) for BOTH parameter sets — noting
`lms-xdr-verify.c`'s hardcoded 1296/60-byte length checks must become
param-set-aware too (its own header documents the lengths as
L=1-default-specific). Sabotage: corrupt the size formula for exactly
one (lms, lmots) pair; only that key's cases fail. Regression risk to
watch: `fetch_hss_key` attribute additions against OLD tokens lacking
the attrs (the fallback path IS the regression test — keep one
pre-standardization token fixture in the case).

**Execution update (2026-08-26):** R25 executed and landed — see
`docs/openssl-provider-coverage-audit-2026-08-25.md`'s "Phase 5, R25"
entry for the full mechanism. Both engines standardized on the
official `CKA_HSS_LEVELS`/`LMS_TYPE`/`LMOTS_TYPE` attrs (the Rust spec
bug fixed as part of this — it held the level count under
`CKA_HSS_LMS_TYPE`); `sig/hss.c` gained a real `hss_sig_size()` shared
with `keymgmt.c` (which had its own separate hardcoded-1536 under-
sizing bug for W4 keys, found and fixed along the way); live-proven
across two genuinely different parameter sets (1296/W8, 2352/W4),
cross-verified by OpenSSL's own independent native LMS implementation
via the now-generalized `lms-xdr-verify.c`. New tool `hss-w4-keygen.c`
(no provider `gen_set_params` growth, per this section's own
direction); new harness case `T24c`. Full regression: C++ CTest 8/8,
Rust `cargo test --release` 410/410 (no dedicated Rust-side HSS
attribute unit test exists — a documented gap, not a silent one),
harness `PASS=67 FAIL=0` (one case gained, zero regressions). **Not
done, by design or deferral:** the formula-corruption sabotage variant
from this section's own proof plan (superseded in practice by two
independently hand-derived-and-confirmed parameter sets giving
different, correct answers — judged sufficient rather than pursued
further); the pre-standardization-token fallback-path regression test
(no such fixture exists in this repo to test against); the Rust-arm
T24 twin and the R9-parked multi-process test (item 4 above) — both
still open, now unblocked at the attribute layer but not yet wired up
as harness cases; `lms-xdr-verify.c`'s naming in this plan's own item 4
(`T24b`/`T24c`) collided with R24's own already-taken `T24b` and this
item's own new `T24c` — whoever picks those up next needs fresh,
non-colliding IDs (e.g. `T24d`/`T24e`).

### R26 — ChaCha20 + ChaCha20-Poly1305 cipher family — effort M–L

**Premise, re-verified (R20's scope correction stands):** both engines
implement it (`OSSLChaCha20.cpp` C++; `constants.rs:623-627` Rust;
dispatch lives in `SoftHSM_cipher.cpp` — read THAT first when
executing, per live-trace-confirm; this plan pass only located it).
`cipher.c` (1074 lines) is AES-block-cipher machinery throughout —
this item builds a separate `chacha.c`, not a "mirror the AES entries"
table edit.

**Format facts to design against (verify live before coding):**
- PKCS#11: `CKM_CHACHA20` takes `CK_CHACHA20_PARAMS`
  (`pkcs11t.h:2548-2553` — blockCounter bits + nonce);
  `CKM_CHACHA20_POLY1305` takes `CK_SALSA20_CHACHA20_POLY1305_PARAMS`
  (`pkcs11t.h:2564-2569` — pNonce/ulNonceBits/pAAD/ulAADLen). Key type
  `CKK_CHACHA20`, 32 bytes.
- OpenSSL: name `ChaCha20` uses a **16-byte IV = 4-byte little-endian
  counter || 12-byte nonce** (OpenSSL-specific packing — the mapping to
  `CK_CHACHA20_PARAMS`' separate counter/nonce fields is exactly the
  kind of seam that silently corrupts byte 64+ of a stream if the
  counter half is dropped; make the parity test span >64 bytes so a
  wrong counter mapping cannot pass). `ChaCha20-Poly1305`: 12-byte IV,
  16-byte tag via `OSSL_CIPHER_PARAM_AEAD_TAG`, AAD via the update-
  with-NULL-output convention — a genuinely different ctx shape from
  the stream cipher, plan them as two dispatch tables in one file.

**Provider work:** new `chacha.c` + registration under a
`CKM_CHACHA20`/`CKM_CHACHA20_POLY1305` checklist gate; skeymgmt name
for `CKK_CHACHA20` keys if key-object flows need it (probe — bytes-in
EVP_CIPHER may suffice, matching how the AES cipher path handles keys
today; read `cipher.c`'s key handling before deciding).

**Proof plan:** byte parity vs software in both directions, stream case
>64 bytes (counter seam), AEAD case with nonempty AAD; tag-corruption
AND AAD-corruption rejection; engine-log + negative twin; sabotage the
counter/nonce packing. Harness T27/T27b. ALG-7 flips RESOLVED.

**Execution update (2026-08-26):** R26 executed and landed — see
`docs/openssl-provider-coverage-audit-2026-08-25.md`'s "Phase 5, R26"
entry for the full mechanism. A real prerequisite surfaced BEFORE any
ChaCha20 code was written: neither `CKM_AES_CTR` (a genuine unfinished
`/* TODO */` stub) nor `CKM_AES_GCM` (dead registration, missing from
the mechanism checklist) had ever worked through this provider's own
cipher interface. User's own choice (2026-08-26, asked live once this
was found): fix both properly first, then build ChaCha20 sharing that
now-real AEAD infrastructure, rather than shipping ChaCha20 alone or
descoping to document-only. `chacha.c` reuses cipher.c's own generic
newctx/freectx/update/final/skey_init (had to become genuinely cross-
family, not AES-private, for this to work) plus new shared AEAD
deferred-mechanism-parameter machinery (AAD must be complete before
PKCS#11's own mechanism param can be built, but OpenSSL's own AAD
delivery happens after encrypt_init/decrypt_init already returned — see
the coverage-audit's own narrative for the resolution). Four real bugs
found and fixed (a case-label/bitmask trap, a chicken-and-egg IVLEN
timing bug, a SECOND independent instance of R22's own "soft propquery
silently prefers default" trap, and R22's own load-behavior=early
lesson not yet applied to this item's own new arenas). One genuine
architectural limitation found and accommodated by explicit user
decision, not silently patched around: this engine's own GCM/ChaCha20-
Poly1305 decrypt withholds all plaintext until the tag verifies
(correct security design) but OpenSSL's own `EVP_DecryptFinal_ex`
hardcodes a fixed, per-message-unenlargeable output buffer sized to the
cipher's own declared block_size — accommodated with a documented
65536-byte ceiling (`AEAD_DECRYPT_MAX_MSG_LEN`, `cipher.h`), not a
silent truncation. New permanent tool `aead-probe.c` (`openssl enc`
itself refuses AEAD ciphers outright). Both AES-CTR/ChaCha20 (stream)
proven byte-identical to software across the >64-byte counter seam; both
AES-GCM/ChaCha20-Poly1305 (AEAD) proven via full workflow (AAD, real
tag get/set, both sabotage controls rejected BY THE TOKEN ITSELF per
engine-log) AND cross-implementation tag-matched against software.
New harness cases T27/T27_negctl/T27b/T27c/T27d (T27_negctl added
beyond this plan's own T27/T27b naming, an R13 negative-control twin).
Full regression: C++ CTest 8/8, Rust not re-run (no rust/ touched),
harness `PASS=72 FAIL=0` (five cases gained, zero regressions). ALG-7
flips RESOLVED, as planned.

---

### R27 (PARKED) — XMSS/XMSS-MT — sketch only, demand-driven

Not planned for execution; recorded so the next trigger doesn't start
from zero. Both engines sign+verify (`SoftHSM_sign.cpp:2809` §6.14
comment covers CKM_XMSS/XMSSMT alongside HSS; same single-part-only
constraint). What makes it different from R9, and why it stays parked:

- **No OpenSSL-side anything**: 3.6 has no native XMSS names, OIDs,
  or verify support (unlike LMS) — so no cross-implementation oracle
  exists in the stack, and no CMS/TLS/X.509 consumer path either.
  Custom algorithm names (`XMSS`, `XMSSMT`) would be reachable only by
  propquery-aware callers who already know about this provider.
- **The R9 template transfers almost wholesale**: `sig/hss.c`'s
  accumulate-then-single-C_Sign shape, the `objects.c`/`store.c`/
  encoder/keymgmt checklist (expect the same five-gap sequence), and
  the engine's `CKA_PARAMETER_SET_M` attribute (already stored by C++
  keygen, `SoftHSM_keygen.cpp:923-924/935-936`) gives R25-style
  param-awareness for free.
- **Independent verification plan when triggered**: RFC 8391 KATs
  (NIST SP 800-208 test vectors) verified in-provider, plus
  C++-signs/Rust-verifies cross-engine checks — weaker than R9's
  OpenSSL-native oracle but the strongest thing available.
- **Trigger**: an actual consumer asking for XMSS through OpenSSL.
  Effort then: M–L.

## Explicitly out of scope (documented limitations, not deferred work)

Restated so this plan's "remaining gaps" claim is complete:
- **F36-6** ML-DSA `message-encoding=0`/external `mu`: structurally
  impossible under PKCS#11 v3.2 (`CK_SIGN_ADDITIONAL_CONTEXT` has no
  field). Permanent, documented.
- **ALG-5 residual**: montgomery derive vs foreign peer with OpenSSL
  peer-validation enabled — OpenSSL-core legacy-path interaction,
  documented at T16.
- **WART-6**: benign error-queue noise during provider-active TLS —
  documented interop caveat.
- **OP-3 parity tier** (SPKI/text encoders for ML-KEM public keys):
  cosmetic parity, no functional consumer; remains "scoped as
  follow-up" in OP-3's row, deliberately not promoted into this plan.
