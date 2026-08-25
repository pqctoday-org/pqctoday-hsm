# OpenSSL provider remediation plan, phase 2 (2026-08-25, v2) — PLAN ONLY, not executed

Successor to `docs/openssl-provider-remediation-plan-2026-08-25.md`
(phase 1: P0 batch, R1, R3b all executed and verified). Covers
everything that remains. Gap IDs refer to
`docs/openssl-provider-coverage-audit-2026-08-25.md` §4.

**v2 (same day):** v1 was adversarially challenged claim-by-claim
against the source before any execution. The challenge round changed
the plan materially — see the log immediately below. v1's structure
survives; several scopes, dependencies, and proofs do not.

**Nothing here has been executed.** Phase-1 discipline applies to every
item: named test flips in the same commit, sabotage-tested both
directions, verified live against the 3.6.3 oracle, exit codes read
directly (never through a pipe), never via `openssl list` (proven
blind for this provider), never with two keypairs sharing a token.

## Challenge round — what v2 changed and the evidence

| # | v1 claim | Challenge result | Effect |
|---|---|---|---|
| C1 | R3: "ML-KEM public keys can only leave via `pkey -pubout` on a URI-loaded key" (audit OP-3 wording) — SPKI/text/URI-PEM encoders all functionally required | **Partly wrong.** Live evidence from the R3b session: `storeutl -text` already prints the full `ML-KEM-768 Public-Key` hex **and a real `-----BEGIN PUBLIC KEY-----` SPKI PEM** with zero ML-KEM encoders registered. Public-key output flows keymgmt-export → OpenSSL imports into the **default provider's** ML-KEM → default's own encoder writes real SPKI. The only *functionally broken* path is the private key: `genpkey -out` (URI-PEM PrivateKeyInfo), because private material can't take the export bridge. | R3 split into a required core (URI-PEM PrivateKeyInfo, flips T4x_encode) and an explicitly-justified parity tier (SPKI/text). Effort drops toward S. |
| C2 | R5: "client role needs no import work; prerequisites met by R3b" | **Wrong — two gaps hid under it.** (a) TLS key-share marshalling uses `EVP_PKEY_get1_encoded_public_key` → keymgmt get_params `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — implemented **only in EC keymgmt** (`keymgmt.c:1645`); ML-KEM keymgmt lacks it. (b) ML-KEM's export_fn (`kem/mlkem.c:456`) requires `class == CKO_PUBLIC_KEY` strictly, but TLS holds the **generated private object** — compare mldsa's export, which also accepts a private object when only public params are selected and then walks to the associated public key. Both must land before any group registration can work, client role included. | R5 gains two named prerequisite work items; the "client-role-is-free" framing deleted. |
| C3 | R4: fix list ended at exchange.c key-type sniff + registration + keymgmt + objects/store cases | **Incomplete — a fifth layer.** The derive path marshals the peer public key via `p11prov_obj_get_ec_public_raw` (`objects.c:3002`), which hard-rejects `key->data.key.type != CKK_EC` — a montgomery peer key is refused before any mechanism is chosen, independently of the CKK-sniff bug. (Silver lining verified in the same read: that function already handles private→associated-public replacement.) | R4 work list grows by one item; effort stays M but the estimate is now honest about why. |
| C4 | KMIP section: "independent SPKI oracle" for R3's ML-KEM encoders | **Overreached.** The KMIP crate has ML-DSA OID parsing (`spki_verify.rs:63`) and a *hybrid* X25519MLKEM768 SPKI wrapper (`composite_kem.rs`), but **no pure ML-KEM SPKI builder** — there is no in-repo second implementation to byte-compare pure ML-KEM SPKIs against. | Oracle claim rescoped: ML-DSA + composites keep the KMIP cross-check; pure ML-KEM verifies against the default provider's parser (`pkey -pubin` + `asn1parse` OID assert) — still a different implementation than our encoder, honestly labeled a weaker independence. |
| C5 | R8: "a provider MAC is only useful with a token-resident key, which arrives through SKEYMGMT — verify that first" | **Wrong dependency.** `EVP_MAC_init(key, len)` hands the provider raw key bytes (`OSSL_MAC_PARAM_KEY`); the MAC implementation creates its own ephemeral session key object via `C_CreateObject` — no SKEYMGMT involvement. SKEYMGMT matters only for the separate 3.6 `EVP_MAC_init_SKEY` opaque-key flow. | R8's sequencing gate removed; scoped as two independent modes (bytes-in now, SKEY later). |
| C6 | R2: mechanics as described | **Survived challenge**, with one proof strengthened: the concern that a decoder-initiated store fetch might hit the WART-4 fresh-process lazy-init trap is already answered by T10 — the EC URI-PEM round trip passes today in a fresh-process arena *without* `early` load behavior, so the decode→store→load chain self-initializes. Cited as the control. | Proof section cites T10 as chain-liveness control; no scope change. |
| C7 | R6: design as described | Survived, with one wiring detail added: T15b's flip needs the env var exported by the **Rust arm's arena helper** (`mk_rust_cnf`/T15b body), not just documented — and T15b's own `OPENSSL_CONF=/dev/null` guard comment shows the arena discipline to preserve. | Wiring note added. |
| C8 | R7: "Ed25519 classical half needs a CKM_EDDSA branch" | Survived but under-specified: draft-19's M′ construction for Ed25519 profiles must be checked against the KMIP implementation + KAT vectors **before** choosing pure-Ed25519 vs prehashed dispatch — a wrong guess would sign structurally valid, cryptographically wrong composites that only the KAT check catches. | Verification-first step added to R7. |

Current baseline: `PASS=18 FAIL=0 XFAIL=3 XPASS=0` at `9052c31`.
Open XFAILs: T4x_encode → **R3**, T11 → **R2**, T15b → **R6**.

Recommended order (unchanged by the challenge): **R3 → R2 → R4 →
R5-ph1 → R6**, P2 tail demand-driven.

---

## R3 — ML-KEM encoders (gap OP-3) — Priority 1, effort S (core) + S (parity)

**Core claim (what actually flips T4x_encode):** `genpkey -algorithm
ML-KEM-* -out k.pem` exits 0 and writes a URI-PEM the R2 decoders will
later load. Per C1, the functional gap is **only the private-key
side**: the URI-PEM PrivateKeyInfo encoder, registered inside the
`if (ctx->encode_pkey_as_pk11_uri)` block (the harness config sets
`pkcs11-module-encode-provider-uri-to-pem = true`). Public-key output
already works today through the export→default-provider bridge —
verified live during R3b.

**Core work items:**

1. `encoder.c`: ML-KEM PrivateKeyInfo/URI-PEM encode functions (3
   variants) calling the shared `p11prov_encoder_private_key_write_pem`
   (`encoder.c:537`) with `CKK_ML_KEM` — the exact shape of ML-DSA's
   (`encoder.c:1268`) and SLH-DSA's (R1) equivalents.
2. `encoder.h`: externs. `provider.c`: 3 registrations in the URI-PEM
   block.

**Parity tier (do in the same item, separately justified):** SPKI +
text encoders for the 3 variants, mirroring `p11prov_mldsa_pubkey_to_x509`
(`encoder.c:1128`) with `NID_ML_KEM_512/768/1024 = 1454/1455/1456`
(staged `obj_mac.h:6634-6646`), dispatched by `CKA_PARAMETER_SET`.
Justification is no longer "public output is broken" (it isn't — C1)
but: (a) deployments with public-key export disallowed
(`p11prov_ctx_allow_export` / `DISALLOW_EXPORT_PUBLIC`) lose all
public output without provider-side encoders; (b) every other PQC
family in this fork ships all three encoder kinds (R1 set the
convention) — an asymmetric ML-KEM would be the odd one out the next
audit flags again. If parity is dropped for time, say so in the audit
rather than letting the bridge masquerade as provider encoding.

**Optionally fold in OP-4** (KEM tables lack SET/SETTABLE_CTX_PARAMS,
`kem/mlkem.c:259-297`): before touching those tables, read
provider-kem(7) in the staged 3.6.3 for its pairing contract — the R1
lesson (provider-signature(7)'s mandatory GET/GETTABLE pairing
rejected the whole method at fetch time) applied proactively, not
retrospectively.

**Proof:** T4x_encode flips (ratchet forces the expectation update);
upgrade it into a real test: exit 0 + `PKCS#11 PROVIDER URI` PEM label
present (the load-back half stays with R2/T11k). Parity tier: with a
config that sets the export-disallow knob, `pkey -pubout` must still
produce SPKI whose `asn1parse` OID is 2.16.840.1.101.3.4.4.{1,2,3};
cross-check note per C4: the parse-side oracle is the default
provider, not KMIP. Sabotage both directions.

---

## R2 — PQC decoders / URI-PEM load-back (gap OP-2) — Priority 1, effort M

Unchanged in scope by the challenge round (C6); mechanics restated
compactly with the strengthened proof.

**The pipeline (all generic parts exist and work — T10 is the live
control, including fresh-process lazy-init):** PEM label
`"PKCS#11 PROVIDER URI"` (`pk11_uri.h:10`) → generic PEM→DER decoder
re-emits the blob as structure `"pk11-uri"` (`decoder.c:152`,
`pk11_uri.h:9`) → **missing piece:** per-key-type DER decoders
(property `",input=der,structure=pk11-uri"`, `provider.c:1563`) that
run a store fetch and filter on the store's `DATA_TYPE` string
(`decoder.c:70,85`) → keymgmt LOAD by reference.

**Work items:** 18 two-macro instantiations in `decoder.c`
(`P11PROV_DER_COMMON_DECODE_FN` + `DISPATCH_DECODER_FN_LIST`,
`decoder.h:23-40`) — 3 ML-DSA + 3 ML-KEM + 12 SLH-DSA — with the
FORMAT_NAME argument being the **single-name** string that `store.c`
emits (the `objects.h` macros: `MLDSA_44` = `"ML-DSA-44"`, `MLKEM_512`,
`SLHDSA_*` — *not* the colon-separated `P11PROV_NAMES_*` lists, which
are for registration); 18 externs in `decoder.h`; 18
`ADD_ALGO_EXT(..., decoder, DEFAULT_PROPERTY(DER_DECODER_PROP), ...)`
lines in `provider.c`. Store side and keymgmt LOADs are already
complete for all 18 (verified; SLH-DSA's 12 landed in R1).

**Dependency:** only the ML-KEM *round-trip test* waits on R3 (no
URI-PEM to load until its encoder exists). ML-DSA/SLH-DSA decode work
is unblocked today.

**Proof:** T11 flips (its body already round-trips: genpkey → label
grep → `pkeyutl -sign` on the PEM). Add one SLH-DSA round-trip case
(single variant; the other 11 share the path) and — after R3 — T11k
(ML-KEM: load back + `pkey -pubout` equality against the
storeutl-obtained public key). T10 remains the EC control. Sabotage
both directions.

---

## R4 — X25519/X448 exchange (gap ALG-5) — Priority 1, effort M

Five layers, in dependency order — the first four are why the phase-1
"2-line fix" framing was wrong, layer 5 found by this pass's challenge
(C3). Mechanism/code agreement across the stack is verified and NOT a
problem: `CKM_X25519 = 0x80001058`, `CKM_X448 = 0x80001059` (vendor
arc) in provider `pkcs11.h:1006` and engine `pkcs11t.h:1272`; both
engines advertise them (`SoftHSM_slots.cpp:555`, `constants.rs:582`);
keygen is `CKM_EC_MONTGOMERY_KEY_PAIR_GEN = 0x1056`.

1. **objects.c fetch/export:** no `CKK_EC_MONTGOMERY` anywhere —
   `p11prov_obj_from_handle` falls to `CKR_ARGUMENTS_BAD` (the same
   missing-case class fixed twice in R1). Latchset upstream has the
   full logic to port (`latchset/src/obj/fetch.c:194`,
   `export.c:239,749`) — port the logic, not the diff (their tree is
   refactored into `obj/`/`kmgmt/`; ours is flat).
2. **store.c data-type case:** add `CKK_EC_MONTGOMERY` → `"X25519"`/
   `"X448"` by bit size (model: our `CKK_EC_EDWARDS` case at
   `store.c:391`; latchset's montgomery version at their
   `store.c:470-476`).
3. **keymgmt:** none exists. Model: our ed25519 keymgmt, which drives
   gen through the common machinery with a preset mechanism
   (`CKM_EC_EDWARDS_KEY_PAIR_GEN`, `keymgmt.c:1820`) — montgomery
   analog uses `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` + the curve's
   EC_PARAMS OID (X25519 = 1.3.101.110 arc; confirm the engines'
   expected template against `SoftHSM_keygen.cpp:495-619` at
   execution). Register under `"X25519"`/`"X448"`.
4. **exchange.c key-type sniff (latent bug):** `exchange.c:203-207`
   compares against locally-invented `CKK_X25519 = 0x45` /
   `CKK_X448 = 0x46` (`exchange.c:9-14`; the names exist in **no**
   header, so the fallbacks always activate). Real montgomery keys are
   `CKK_EC_MONTGOMERY = 0x41` → the check never matches a real key,
   and `0x46` **collides with CKK_HSS** (`pkcs11.h:521`) — an HSS key
   reaching this path would silently select `CKM_X448`. Fix: dispatch
   on `CKK_EC_MONTGOMERY` + curve (EC_PARAMS or key size); delete the
   bogus CKK fallbacks and the inert-but-wrong
   `#define CKM_X25519 0x0000021A` (`exchange.c:15-16`).
5. **exchange.c peer marshalling (C3):** the derive path feeds
   `CK_ECDH1_DERIVE_PARAMS.pPublicData` from
   `p11prov_obj_get_ec_public_raw` (`exchange.c:~295`,
   `objects.c:3002`), which hard-rejects non-`CKK_EC` keys. Needs a
   montgomery branch (raw u-coordinate; verify the engines' expected
   public-data encoding for CKM_X25519 — raw 32/56 bytes vs
   DER-wrapped EC_POINT — against `SoftHSM_keygen.cpp:3181`'s derive
   implementation before writing it). The private→associated-public
   replacement in that function already works and carries over.

**Proof:** T16: X25519 token keygen → provider derive vs software peer
derive (T8's shape, including the `OPENSSL_CONF=/dev/null` software
peer), byte-identical secret; T16b (X448) cheap once T16 exists. The
CKK_HSS-collision hazard is removed by deleting the constants — note
in the commit message; a scripted negative test is not worth the HSS
setup cost. Sabotage T16 both directions.

---

## R5 phase 1 — pure ML-KEM TLS groups (gap F36-1) — Priority 1, effort M

**Claim:** a real TLS 1.3 handshake negotiates `MLKEM512/768/1024`
with the token performing the client-side KEM operations. Hybrids
remain phase 2 (combiner question — out of scope).

**Prerequisites (C2 — must land first, in this order):**

1. **ML-KEM keymgmt `ENCODED_PUBLIC_KEY`:** implement
   `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` in `get_params` (TLS reads the
   key share via `EVP_PKEY_get1_encoded_public_key`; for ML-KEM the
   encoded form IS the raw public bytes, so this is the CKA_VALUE
   lookup the PUB_KEY branch already does under another name). Only EC
   keymgmt has it today (`keymgmt.c:1645-1744` — also the model for
   the settable/peer side).
2. **ML-KEM export from a private object:** relax
   `p11prov_mlkem_keymgmt_export_fn` (`kem/mlkem.c:456`) to mldsa's
   contract — accept a private object when only public params are
   selected, exporting the **associated** public key (R3b's gen
   already sets the association via `p11prov_obj_set_associated`).

**Then the group registration itself (`tls.c`):** 3 entries; KEM
groups need `OSSL_CAPABILITY_TLS_GROUP_IS_KEM` (`core_names.h:151`),
which the existing 10-slot `TLS_PARAMS_ENTRY` (`tls.c:72-91`) cannot
hold — a widened/KEM-specific entry shape. `TLS_GROUP_ALG` =
`"ML-KEM-768"` etc. (our registered names). **IANA code points read
from the staged build's own `ssl/t1_lib.c` group table at execution
time, never from memory.** Registering ids the linked OpenSSL also
serves natively raises provider-vs-builtin precedence — resolve by
live probe, with the C++ engine DEBUG log as the arbiter of whose
implementation actually ran.

**Server role (separately gated, inside R5, after phase 1):** peer
share import (`EVP_PKEY_set1_encoded_public_key` →
set_params/import), keymgmt IMPORT/IMPORT_TYPES (absent), the
`p11prov_obj_import_key` type-gate (covers only
`CKK_ML_DSA || CKK_SLH_DSA`), and an import that yields a real object
handle `C_EncapsulateKey` can use.

**Proof:** T13 becomes scriptable: software `s_server`
(`OPENSSL_CONF=/dev/null`) + `s_client -groups MLKEM768` with the
provider active client-side **and the fetch pinned** (propquery or
config default_properties — without pinning, the default provider's
ML-KEM can serve the group silently and the test proves nothing);
handshake completes AND the engine DEBUG log shows the token
decapsulate. Negative control: same config, `-groups X25519` → no KEM
op in the engine log. Sabotage by breaking the group entry in a copy.

---

## R6 — native Rust-engine persistence (gap ENV-2) — Priority 2, effort M

Unchanged by the challenge except wiring detail C7.

**Grounding:** `serialize_token_state`/`deserialize_token_state`
(`state_snapshot.rs:67/173`) already compile natively; only the
`C_Finalize` stash call is emscripten-gated (`ffi.rs:251-252`), with an
explicit zeroize rationale — so the native path must be **opt-in**
(env var, e.g. `SOFTHSMRUST_STATE_FILE`): restore on `C_Initialize`
(missing file = fresh token), stash on `C_Finalize` before the zeroize
pass, byte-identical legacy behavior when unset. Inherit the
`SHR3SNP2` load-refusal policy verbatim (`state_snapshot.rs:35-53`):
refuse foreign/old snapshots loudly — silently rehydrated stateful-HBS
counters are a forgery risk. File perms 0600; single-writer only
(documented, not locked). **Honest limitation, stated in module doc
and README:** the snapshot is plaintext at rest, unlike the C++ token
directory's PIN-derived encryption of sensitive attributes —
dev/test-grade persistence; an encrypted variant is a possible R6b,
not scoped.

**Wiring (C7):** the harness's Rust arm must export the env var in
its own arena setup (`mk_rust_cnf` + every process in T15b's flow) —
preserving T15b's existing `OPENSSL_CONF=/dev/null` init-token guard.

**Proof:** T15b flips; then extend the Rust arm beyond a stub —
minimum: store enumeration, ML-DSA sign round-trip, ML-KEM keygen
(mirror T2/T3b/T4x). Sabotage: (a) unset the env var in a copy →
flow fails again, proving the variable carries the persistence;
(b) corrupt the magic in a written state file → next init must refuse
loudly, not half-load.

---

## Priority 2 tail

### R7 — remaining composite profiles (ALG-4), M–L
Registry (`composite.c:96-130`) has 3 of 8 (.37/.45/.49); missing five
include all four §10.4-recommended. **Verification-first step (C8):**
before wiring the Ed25519 classical half (`CKM_EDDSA` branch at the
`composite.c:941` dispatch), pin draft-19's M′ construction for the
Ed25519 profiles against the KMIP implementation and
`rust/kat/composite-sigs/external-composite-vectors.json` — pure vs
prehashed chosen by evidence, not assumption; a wrong guess signs
well-formed, wrong composites that only KATs catch. Then: registry
rows, name macros, `tls.c` sigalg entries (0xFEB0+ private-range
pattern). Proof per profile: sign + M′ KAT check + one harness COMPSIG
case.

### R8 — `OSSL_OP_MAC` (OP-1/ALG-8), M
New `mac.c` over `CKM_*_HMAC`/`CKM_AES_CMAC`/`CKM_KMAC_*` (both
engines advertise; 45 hits in `SoftHSM_slots.cpp` alone), mech-gated,
plus the `OSSL_OP_MAC` arm in `p11prov_query_operation`. **C5:** the
bytes-in mode (`OSSL_MAC_PARAM_KEY` → ephemeral session key object via
`C_CreateObject` → `C_SignInit`) has **no** SKEYMGMT dependency and is
the whole of phase one; the `EVP_MAC_init_SKEY` opaque-token-key mode
is a separate later step. Proof: `openssl mac -propquery
"?provider=pkcs11"` == software HMAC over identical key bytes, plus
engine-log evidence the token computed it.

### R9 — LMS/HSS (ALG-3/F36-2/ENV-1), M after ENV-1
Gated on ENV-1 (rebuild oracle with `enable-lms`). Token HSS **sign**
+ XDR public export → native `pkeyutl -verify` (3.6 LMS is
verify-only, making this split uniquely coherent). Run after R6 so the
stateful-key arm doesn't forget its own leaf counters mid-test.

### R10 — KDF widening + EVP_SKEY probes (OP-5/F36-3), probe-first
Two cheap probes, writeups appended to the audit before any scoped
work: (a) PBKDF2/KBKDF provider-priority under propquery (reuse T9's
fresh-process arena pattern); (b) `EVP_KDF_derive_SKEY` opaque
handoff viability.

### R11 — XMSS/XMSS-MT (ALG-2), L, last
No native OpenSSL counterpart, no consumer. Revisit only on demand;
R9's stateful groundwork would be its base.

---

## KMIP cross-reference (rescoped per C4)

How the KMIP Rust code manages key-object encoding/decoding — surveyed
2026-08-25:

- **Explicit wire formats, honest refusal:** KeyFormatType stored per
  object, surfaced faithfully; all conversions through one rule table
  (`ops/helpers.rs:1243`) — Raw↔TransparentSymmetricKey and RSA
  PKCS#1↔PKCS#8 convert for real, everything else refuses loudly
  (`KeyFormatTypeNotSupported`), never a silent substitute.
- **PQC/HSS material is Raw-only** on Register (engine import takes
  raw bytes; PKCS#8-wrapped PQC refused —
  `register_import_export.rs:449-533`); RSA alone has multi-format
  ingest with real DER normalization.
- **Pure-Rust SPKI stack** (`der`/`spki` 0.7, `x509-cert` 0.2):
  ML-DSA OID→mechanism mapping in `spki_verify.rs:63-142`; composite
  SPKI assembly cached inline for two-engine-object keys
  (`create_key_pair.rs:~335`); hybrid X25519MLKEM768 SPKI wrapper in
  `composite_kem.rs`. **No pure ML-KEM SPKI builder exists** (C4).

**What this plan actually borrows:**

1. **Byte-level SPKI oracle where a second implementation truly
   exists:** ML-DSA and composites (KMIP side) — same key bytes, two
   independent builders, identical DER required. Pure ML-KEM instead
   verifies against the default provider's parser (different
   implementation of the *counterpart* operation — weaker independence,
   labeled as such).
2. **Three-way OID agreement gate** for R3/R2/R7: provider `NAMES`
   macros ↔ KMIP OID constants ↔ staged `obj_mac.h` NIDs.
3. **The honest-refusal error model** for encoders/decoders: fail
   loudly on unsupported selections; a silent software fallback is
   indistinguishable from token coverage — the audit's founding
   premise.
4. **R7's registry + KAT vectors** come from the KMIP tree outright.
5. **Boundary honesty:** no code crosses the C/Rust boundary; reuse is
   oracle + reference tables only.

---

## Sequencing and dependencies (v2)

```
R3 core (URI-PEM priv encoder)  ──┬──> R2 (T11k needs R3; ML-DSA/SLH-DSA parts free)
R3 parity (SPKI/text) ────────────┘
R4 (5 layers, order internal)  — independent
R5 pre-1 (ENCODED_PUBLIC_KEY) ──┐
R5 pre-2 (export-from-private) ─┼──> R5-ph1 groups (client role)
R3b (done) ─────────────────────┘        └─> R5 server role (import stack)
R6 — independent; before R9; unlocks "both engines" claims
R7 (M′ verification first), R8 (bytes-in mode first) — demand-driven
R9 — after ENV-1 + preferably R6;  R10 — probes anytime;  R11 — last
```

Every landed item updates harness expectations in the same commit
(ratchet), updates `local-gate.sh`'s two count labels, and appends —
never rewrites — the audit's and this plan's update logs.

## Explicitly out of scope (unchanged)

Hybrid TLS groups (R5-ph2; combiner question vs `pqctoday-tls`'s
SecP384r1MLKEM1024 first); FrodoKEM / Classic McEliece / BIP32 /
Keccak-256 / split-key via OpenSSL; WASM-arm changes; OpenSSL version
work beyond the staged 3.6.3 oracle except ENV-1's `enable-lms`
rebuild (gates R9 only).
