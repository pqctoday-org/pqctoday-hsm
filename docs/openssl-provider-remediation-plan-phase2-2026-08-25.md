# OpenSSL provider remediation plan, phase 2 (2026-08-25) — PLAN ONLY, not executed

Successor to `docs/openssl-provider-remediation-plan-2026-08-25.md`
(phase 1), whose P0 batch, R1 (SLH-DSA end-to-end), and R3b (ML-KEM
token keygen) are all executed and verified. This document covers
**everything that remains**, re-explored against the source on
2026-08-25 (after R3b landed) rather than carried over from the
original audit — several items' scope changed materially on
re-inspection, and two new latent bugs were found during this planning
pass (see R4). Gap IDs still refer to
`docs/openssl-provider-coverage-audit-2026-08-25.md` §4.

**Nothing in this document has been executed.** Every item runs later
under its own explicit go-ahead, one at a time, with the same
discipline phase 1 used: the named test must flip (or be newly added
green) in the same commit, sabotage-tested in both directions, verified
live against the real OpenSSL 3.6.3 oracle — never by exit codes read
through a pipe, never via `openssl list` (proven unreliable for this
provider: it never shows `@ pkcs11` even for known-working
algorithms), and never with two keypairs sharing a token (type-only
`pkcs11:` URIs match the wrong key — both traps were hit and
documented in phase 1).

## Current state (baseline for this plan)

Harness: `OPENSSL-PROVIDER-HARNESS: PASS=18 FAIL=0 XFAIL=3 XPASS=0`
as of commit `9052c31`. The three open XFAILs, and the item that flips
each:

| XFAIL | Gap | Flips on |
|---|---|---|
| T4x_encode | OP-3 (no ML-KEM encoders) | **R3** |
| T11 | OP-2 (no PQC decoders / URI-PEM load-back) | **R2** |
| T15b | ENV-2 (Rust arm loses state across processes) | **R6** |

Recommended execution order: **R3 → R2 → R4 → R5-ph1 → R6**, then the
Priority-2 tail (R7–R11) demand-driven. Rationale in the sequencing
section at the end.

---

## R3 — ML-KEM encoders (gap OP-3) — Priority 1, effort S–M

**Claim when done:** an ML-KEM public key on the token can leave
through every standard OpenSSL output path — `genpkey -out` writes a
loadable URI-PEM, `pkey -pubout` emits a real SubjectPublicKeyInfo,
`-text` prints a human-readable block — for all three parameter sets.

**Ground truth (verified this pass):**

- ML-KEM has **zero** encoder registrations: no
  `ADD_ALGO_EXT(ML_KEM_*, encoder, ...)` lines exist in
  `src/vendor/pkcs11-provider/src/provider.c` (confirmed by sweep, and
  live by T4x_encode's `Error writing key(s)`).
- OpenSSL 3.6.3 has native NIDs ready to use:
  `NID_ML_KEM_512 = 1454`, `NID_ML_KEM_768 = 1455`,
  `NID_ML_KEM_1024 = 1456` (staged `obj_mac.h:6634-6646`), so the SPKI
  encoder can be built exactly like our ML-DSA one — no manual OID DER
  needed on the X509_PUBKEY path.
- Two in-tree models exist, in order of preference:
  1. **Our own ML-DSA and SLH-DSA encoders** in `encoder.c`
     (`p11prov_mldsa_pubkey_to_x509` at ~1128, the SLH-DSA block from
     R1 at ~1391+, both feeding the shared
     `p11prov_encoder_private_key_write_pem` helper at `encoder.c:537`
     for the URI-PEM PrivateKeyInfo side). These use this fork's actual
     internal APIs — mirror these.
  2. The latchset sibling (`src/vendor/latchset/src/encoder.c:1395-1503`,
     registrations at `provider.c:1445-1499`) — use as a completeness
     checklist only; its `p11prov_obj_export_public_key` has a
     different signature than our fork's, so it does not transplant.

**Work items:**

1. `encoder.c`: ML-KEM keypoint struct + export callback + a
   `pubkey_to_x509` switching on the three NIDs by
   `CKA_PARAMETER_SET` (**not** key size — same caveat R1 proved for
   SLH-DSA; ML-KEM sizes do differ per set, but the parameter-set
   dispatch is the established, self-documenting pattern), SPKI-DER
   encode + does_selection + dispatch table, text encoder (12-way not
   needed here — 3-way), and a PrivateKeyInfo URI-PEM encode calling
   the shared helper with `CKK_ML_KEM`.
2. `encoder.h`: the three extern dispatch-table declarations
   (convention per R1 cleanup: domain header, not provider.h).
3. `provider.c`: text + SPKI registrations in the encoder block, and
   URI-PEM registrations inside the
   `if (ctx->encode_pkey_as_pk11_uri)` block — per variant, matching
   how ML-DSA/SLH-DSA register.
4. Fold in **OP-4** here if desired (same file family, low risk): the
   KEM operation tables (`kem/mlkem.c:259-297`) lack
   `SET_CTX_PARAMS`/`SETTABLE_CTX_PARAMS`. Note the phase-1 R1 lesson
   **in reverse**: provider-kem(7) has the same pairing contract as
   provider-signature(7) — if these are added, BOTH of the pair must
   be added, and the same check applies to GET/GETTABLE. Check the doc
   before touching the tables, not after.

**Proof:** T4x_encode flips XFAIL→PASS (the ratchet will force the
expectation update). Upgrade it into a real test: `genpkey -out` exit
0, PEM label present, `pkey -pubin -text` shows
`ML-KEM-768 Public-Key`, and `openssl asn1parse` on the SPKI shows OID
2.16.840.1.101.3.4.4.2 (768; .1/.3 for 512/1024). Add a
`pkey -pubout` case for a second parameter set. Byte-level cross-check
against the KMIP oracle (see the KMIP section below). Sabotage both
directions.

---

## R2 — PQC decoders / URI-PEM load-back (gap OP-2) — Priority 1, effort M

**Claim when done:** a URI-PEM file written by `genpkey` for any PQC
key type loads back and is usable (`pkeyutl -sign` for signers,
`pkeyutl -encap` reachability for ML-KEM) — closing the asymmetry
where the provider can write URI-PEMs it cannot read.

**Ground truth — the entire decode pipeline, mapped this pass**
(`decoder.c` is only 202 lines; the mechanism is fully generic):

1. The URI-PEM body is not key material: it is a tiny DER blob
   (`P11PROV_PK11_URI`) wrapping the `pkcs11:` URI string, under PEM
   label `"PKCS#11 PROVIDER URI"` (`pk11_uri.h:10`).
2. A single generic PEM→DER decoder
   (`p11prov_pem_decoder_p11prov_der_decode`, `decoder.c:152`) strips
   the PEM and re-emits the blob tagged with
   `OSSL_OBJECT_PARAM_DATA_STRUCTURE = "pk11-uri"` (`pk11_uri.h:9`).
3. Per-key-type DER decoders — registered with property
   `",input=der,structure=pk11-uri"` (`DER_DECODER_PROP`,
   `provider.c:1563`) — parse the blob, extract the URI, and run a
   store fetch (`p11prov_store_direct_fetch`), filtering results to
   those whose store `DATA_TYPE` string equals the decoder's own name
   (`filter_for_desired_data_type`, `decoder.c:70`). The surviving
   object reference flows to the matching keymgmt's LOAD.
4. Each per-type decoder is ~4 lines via two macros:
   `P11PROV_DER_COMMON_DECODE_FN(<data-type-name>, <suffix>)` +
   `DISPATCH_DECODER_FN_LIST(der, p11prov, <suffix>)`
   (`decoder.h:23-40`). Today only rsa/ec/ed25519/ed448 exist
   (`decoder.c:193-202`).

**Why PQC fails today:** step 3 has no PQC decoders — nothing else.
Steps 1–2 are type-agnostic and already work (T10 proves the chain for
EC). And the store side is **already done**: `store.c` emits exact
per-variant data-type names for ML-DSA (`"ML-DSA-44/65/87"`), ML-KEM
(`"ML-KEM-512/768/1024"`), and all 12 SLH-DSA variants (added in R1).
The keymgmt LOAD functions all exist.

**Work items:**

1. `decoder.c`: 18 macro instantiations — 3 ML-DSA + 3 ML-KEM + 12
   SLH-DSA — each `P11PROV_DER_COMMON_DECODE_FN(NAME, suffix)` +
   `DISPATCH_DECODER_FN_LIST`. The NAME argument must be the exact
   store.c data-type string (which is the first element of each
   `P11PROV_NAMES_*` macro — e.g. `P11PROV_NAMES_ML_DSA_44` =
   `"ML-DSA-44:MLDSA44:2.16.840.1.101.3.4.3.17:id-ml-dsa-44"`, so use
   the single-name macro/string, not the colon-list).
2. `decoder.h`: 18 externs.
3. `provider.c`: 18 `ADD_ALGO_EXT(<VARIANT>, decoder,
   DEFAULT_PROPERTY(DER_DECODER_PROP), ...)` lines next to the
   existing five.
4. The audit's note stands: no `d2i_X509_PUBKEY` recursion concern
   here — that was specific to composite SPKI decoding
   (`provider.c:1577-1590` documents it); the pk11-uri structure
   property firewalls these decoders from SPKI input.

**Dependency:** the ML-KEM URI-PEM decode *test* needs R3 first (no
URI-PEM exists to load until the ML-KEM URI-PEM encoder lands). The
ML-DSA and SLH-DSA parts have no dependency — their encoders already
work (T11 today writes the PEM fine and fails only on load).

**Proof:** T11 flips (its body already does the full round trip:
genpkey → grep PEM label → `pkeyutl -sign` with the PEM as `-inkey`).
Add: an SLH-DSA round-trip case (one variant suffices; the other 11
share the code path), and — after R3 — an ML-KEM round-trip
(load-back + `pkeyutl -encap` reachability or `pkey -pubout`
equality against the storeutl-obtained public key). Sabotage both
directions; reuse T10 (EC) as the living control.

---

## R4 — X25519/X448 exchange (gap ALG-5) — Priority 1, effort M (was S; rescoped)

**The phase-1 sketch ("registration branch dead — likely a 2-line
fix") is wrong.** Re-exploration found four distinct problems, two of
them real latent bugs; this is a medium item, structurally similar to
what R1 turned out to be for SLH-DSA.

**Ground truth (all verified this pass):**

1. **Dead registration (the known part).** `checklist[]`
   (`provider.c:910`) lists no `CKM_X25519`/`CKM_X448`, so the
   `case CKM_X25519:` registration branch (`provider.c:1154-1160`)
   is unreachable. Mechanism codes agree across the whole stack —
   provider `pkcs11.h:1006-1007` and engine `pkcs11t.h:1272` both say
   `CKM_X25519 = 0x80001058`, `CKM_X448 = 0x80001059` (vendor arc);
   the C++ engine advertises them (`SoftHSM_slots.cpp:555-556`,
   dispatch at `SoftHSM_keygen.cpp:2744`), the Rust engine too
   (`constants.rs:582-583`, `ffi.rs:1097`). Keygen is
   `CKM_EC_MONTGOMERY_KEY_PAIR_GEN = 0x1056`, in both engines.
2. **No keymgmt at all.** The dead branch registers only the
   `exchange` op. There is no montgomery keymgmt table and no
   registration — OpenSSL cannot even load an X25519 token key. (The
   ed25519 keymgmt is the in-fork model; latchset upstream has a full
   montgomery keymgmt — `latchset/src/obj/keymgmt.c:954-975` maps
   x25519 OID/ec_params → `NID_X25519` — usable as a logic reference,
   though its file layout is refactored relative to ours.)
3. **Latent bug: object fetch would fail.** Our `objects.c` has zero
   `CKK_EC_MONTGOMERY` handling — `p11prov_obj_from_handle`'s key-type
   switch would return `CKR_ARGUMENTS_BAD` for a montgomery key. This
   is the **same missing-case bug class found and fixed twice in R1**
   (objects.c fetch, store.c naming) — the third and fourth instances.
   `store.c`'s data-type switch also lacks the case (our fork's
   `CKK_EC_EDWARDS` case at `store.c:391` is the nearest neighbor;
   latchset's `store.c:470-476` shows the montgomery version emitting
   `X25519_NAME`/`X448_NAME` by bit size).
4. **Latent bug: wrong fallback constants in exchange.c.** The derive
   path's key-type sniffing (`exchange.c:203-207`) compares against
   `CKK_X25519`/`CKK_X448` — constants that **do not exist in
   PKCS#11**; the local fallbacks (`exchange.c:9-14`) define them as
   `0x45`/`0x46`, and they always activate (neither header defines
   the names). Real montgomery keys are `CKK_EC_MONTGOMERY = 0x41` —
   so the check can never match a real key (mechtype silently stays
   `CKM_ECDH1_DERIVE`) — **and `0x46` collides with `CKK_HSS`**
   (`pkcs11.h:521`): an HSS key reaching this code would silently
   select `CKM_X448`. There is also a dead-but-wrong
   `#define CKM_X25519 0x0000021A` fallback (`exchange.c:15-16`;
   inert because `pkcs11.h` wins, but a trap for any future include
   reshuffle). Fix direction: dispatch on `CKK_EC_MONTGOMERY` +
   curve identification (EC_PARAMS OID or key size), delete the
   bogus fallback constants entirely.

**Work items (in dependency order):** objects.c fetch/export cases →
store.c data-type case → montgomery keymgmt (+ keygen via
`CKM_EC_MONTGOMERY_KEY_PAIR_GEN`, following the now-thrice-proven
gen-block pattern) → exchange.c key-type-sniff fix → checklist +
registration (keymgmt + exchange per variant). Engine-side nothing to
do — both engines are ready.

**Proof:** new T16: X25519 token keygen → provider derive vs software
peer derive, byte-identical shared secret (mirror T8's ECDH shape,
including its `OPENSSL_CONF=/dev/null` software-peer trick); T16b for
X448 optional but cheap. A negative guard for the CKK_HSS collision
is impractical to script cheaply (needs an HSS key in an exchange
context) — the constant deletion itself removes the hazard; note it
in the commit message. Sabotage T16 both directions.

---

## R5 phase 1 — pure ML-KEM TLS groups (gap F36-1) — Priority 1, effort M

**Claim when done:** a real TLS 1.3 handshake negotiates
`MLKEM512/768/1024` with the **token** performing the KEM operations
on its side of the connection — the flagship "PQC TLS backed by the
HSM" story, phase 1 (pure groups only; hybrids are phase 2 and out of
scope here).

**Ground truth (verified this pass):**

- `tls.c` registers 13 classical groups and 0 KEM groups. The
  registration mechanics are simple and fully local to `tls.c`:
  `tls_params[]` entries built by `TLS_PARAMS_ENTRY` (9 params + END
  in a fixed `OSSL_PARAM list[10]`, `tls.c:72-91`), delivered via
  `tls_group_capabilities` (`tls.c:176`). The sigalg side of the same
  file already registers ML-DSA + 3 composites — the KEM-group gap is
  the last hole in this file, not a new subsystem.
- KEM groups additionally require
  `OSSL_CAPABILITY_TLS_GROUP_IS_KEM = "tls-group-is-kem"` (confirmed
  present in staged 3.6.3 `core_names.h:151`) — so either a widened
  entry macro (`list[11]`) or a KEM-specific one. The
  `TLS_GROUP_ALG` value must be a name our provider registers for
  BOTH keymgmt and KEM ops — `"ML-KEM-768"` etc. (already true since
  the per-variant registrations).
- **IANA code points must be read from the staged build's own source
  during execution, not from memory** (`ssl/t1_lib.c` group table —
  its default-groups string includes `X25519MLKEM768`, confirming the
  staged build speaks these groups natively). Registering a
  provider-side group under an id the linked OpenSSL also serves
  natively raises a provider-vs-builtin precedence question — probe
  it live first (register, then verify via handshake evidence WHOSE
  implementation ran; engine DEBUG log is the arbiter).
- **Prerequisite met:** client-side KEM-group participation needs
  ephemeral keygen (R3b, done), public export (done), decapsulate
  (done). **Prerequisite NOT met for the server role:** the server
  must *import* the client's raw public share and encapsulate to it —
  ML-KEM keymgmt has **no IMPORT/IMPORT_TYPES** (verified:
  `kem/mlkem.c` dispatch tables), and `objects.c`'s
  `p11prov_obj_import_key` type-gate covers only
  `CKK_ML_DSA || CKK_SLH_DSA` (R1's fix). Import must also produce an
  object the KEM op can use — i.e. a real session object handle via
  `C_CreateObject`, since `C_EncapsulateKey` takes a handle, not
  bytes.

**Scope decision for phase 1:** token-as-**client** first
(keygen/decap on token, software `s_server` peer): it needs no import
work and already exercises the whole group-registration surface.
Token-as-server (import + encap) is a separately gated follow-up
inside R5 — do the keymgmt import work then.

**Work items:** KEM-capable entry macro + 3 group entries (+ alias
spellings if the staged build uses them) in `tls.c`; live probe of
provider-vs-native precedence; harness case.

**Proof:** T13 finally becomes scriptable (the audit left it plan-only
because `list -tls-groups` merges providers — the handshake IS the
test): `s_server` (software, `OPENSSL_CONF=/dev/null`) +
`s_client -groups MLKEM768` with the provider active on the client
side; assert handshake completes AND token participation via the C++
engine DEBUG log (the R1-proven diagnostic; grep for the ML-KEM
decapsulate op against the client's token) — not via any `openssl
list` output. Negative control: same handshake with the token config
but `-groups X25519` must not touch the engine log's KEM path.
Sabotage by breaking the group registration in a copy.

---

## R6 — native Rust-engine persistence (gap ENV-2) — Priority 2, effort M

**Claim when done:** the harness's Rust arm runs the same functional
matrix as the C++ arm — multi-process CLI flows (`genpkey` then
`pkeyutl` in separate processes) find the token state again.

**Ground truth (verified this pass):**

- The snapshot surface is **already compiled natively**:
  `serialize_token_state()` / `deserialize_token_state()`
  (`rust/src/state_snapshot.rs:67/173`) are not cfg-gated; only the
  **wiring** is — the `stash_before_finalize()` call in `C_Finalize`
  sits under `#[cfg(target_os = "emscripten")]` (`ffi.rs:251-252`),
  with an explicit comment: *"Native/wasm-bindgen builds skip this —
  there, parking key material past finalize would defeat the
  zeroize."* That is a deliberate security posture, not an oversight —
  R6 must be **opt-in**, defaulting to today's zeroize-everything
  behavior.
- Format is versioned (`SHR3SNP2`), hand-rolled, with a
  **load-refusal policy already designed in**: a v1 (`SHR3SNP1`)
  snapshot is refused loudly because silently rehydrating stateful-HBS
  keys under moved attribute ids would present a partially-used
  XMSS/LMS key as fresh — a forgery risk (`state_snapshot.rs:35-53`).
  R6 inherits this: refuse, never migrate.

**Design (per the audit's original sketch, now grounded):** an
env-var-gated file path (e.g. `SOFTHSMRUST_STATE_FILE`); when set:
restore on `C_Initialize` (file absent = fresh token, not an error),
stash on `C_Finalize` *before* the zeroize pass. When unset: byte-for-
byte today's behavior. Document single-writer only (no locking; two
concurrent processes would last-writer-win — same limitation class the
C++ file backend handles with its own locking, which R6 does not need
to replicate for a test-enablement feature). File perms 0600.
**Honest limitation to document, not hide:** the snapshot stores key
material unencrypted at rest — unlike the C++ engine's token
directory, which encrypts sensitive attributes under a PIN-derived
key. That makes this a dev/test persistence surface, not a production
one; say so in the module doc and README. (Closing that gap — e.g.
reusing the snapshot format under a PIN-derived AEAD — is a possible
R6b, not scoped here.)

**Proof:** T15b flips. Then the Rust arm stops being a two-test stub:
wire the arm to export the env var in its arenas and run the
functional flows the C++ arm runs (at minimum: store enumeration,
ML-DSA sign round-trip, ML-KEM keygen — mirroring T2/T3b/T4x).
Sabotage: unset the env var in a copy's Rust arm → T15b's flow must
fail again (proving the variable, not something else, carries the
persistence); flip a byte in the magic in a written state file → next
init must refuse loudly (the SHR3SNP2 policy), not half-load.

---

## Priority 2 tail (R7–R11) — briefer, still grounded

### R7 — remaining composite profiles (ALG-4), effort M–L
`composite.c`'s registry (`:96-130`) holds 3 of 8 draft-19 §6 profiles
(.37, .45, .49). Missing five include all four §10.4-recommended ones
(MLDSA44-Ed25519-SHA512, MLDSA44-ECDSA-P256-SHA256,
MLDSA65-RSA3072-PSS-SHA512, MLDSA65-Ed25519-SHA512) +
MLDSA65-ECDSA-P384-SHA512. The Ed25519-classical profiles need a
`CKM_EDDSA` branch in the classical-half dispatch (audit anchor
`composite.c:941`) — the other profiles are registry rows + name
macros + TLS sigalg entries (the `tls.c` private-code-point pattern,
0xFEB0-2, extends naturally). **The KMIP tree is the oracle**: all 8
profiles live in `kmip`'s composite module and the external KAT
vectors at `rust/kat/composite-sigs/external-composite-vectors.json` —
per-profile proof is sign + M′ vector check against those, plus a
harness COMPSIG sign case for at least one new profile.

### R8 — `OSSL_OP_MAC` (OP-1/ALG-8), effort M
New `mac.c` implementing EVP_MAC over `CKM_*_HMAC` / `CKM_AES_CMAC` /
`CKM_KMAC_*` (both engines advertise these; 45 HMAC/CMAC/KMAC
references in `SoftHSM_slots.cpp` alone), mech-gated like every other
op table, plus the `OSSL_OP_MAC` arm in `p11prov_query_operation`.
Sequencing note: a provider MAC is only useful with a token-resident
secret key, which arrives through SKEYMGMT (`skeymgmt.c`,
`SKEY_SUPPORT`) — verify the secret-key import path works before
building on it. Proof: `openssl mac` via provider == software HMAC
over the same imported key bytes.

### R9 — LMS/HSS story (ALG-3/F36-2/ENV-1), effort M after ENV-1
Strictly gated on ENV-1: rebuild the 3.6.3 oracle with `enable-lms`.
Then the coherent split (token signs with HSS/LMS, OpenSSL 3.6
verifies natively — its LMS is verify-only) needs: custom-name
signature exposure for token HSS sign + XDR public-key export for the
native verifier. Proof: sign-on-token → `openssl pkeyutl -verify`
native. The Rust engine's stateful-key rewind protections (SHR3SNP2
policy, R6) interact here — R9 after R6 avoids testing stateful keys
on an arm that forgets its own leaf counters.

### R10 — KDF widening + EVP_SKEY probes (OP-5/F36-3), probe-first
Two cheap probes before any scoped work: (a) do PBKDF2/KBKDF
fetches honor provider priority under a `?provider=pkcs11` propquery
(same question WART-4 answered for digests — reuse T9's
fresh-process + early-load arena pattern); (b) can
`EVP_KDF_derive_SKEY` hand back a token-resident derived key as an
opaque SKEYMGMT reference without exporting bytes. Probe output is a
writeup appended to the audit, which then scopes (or closes) the item.

### R11 — XMSS/XMSS-MT (ALG-2), effort L, ranked last
Custom names, no native OpenSSL counterpart, no CMS/TLS integration
possible; no consumer has materialized. Keep last; the R9 stateful
groundwork (state discipline, XDR-ish export) would be its foundation
if one appears.

---

## How the KMIP Rust code manages key-object encoding/decoding — and what this plan borrows

Surveyed this pass (2026-08-25) at the user's request; this section
doubles as the reference map.

**What KMIP does (kmip/src):**

- **Wire formats are explicit KMIP KeyFormatType codepoints**, stored
  per object and surfaced faithfully on Get/Export (the K8 fix:
  stored format is never remapped to Raw). Requested-format
  conversion runs through one shared rule table —
  `ops/helpers.rs:1243 convert_key_format`: absent → stored; same →
  as-is; Raw ↔ TransparentSymmetricKey (byte-identical rewrap);
  PKCS#1 ↔ PKCS#8 for RSA private keys (real re-encode via the
  RustCrypto `rsa` crate); **everything else → a loud
  `KeyFormatTypeNotSupported` (0x10), never a silent lie.**
- **PQC and HSS key material moves as Raw only** on Register — the
  engine import path takes raw key bytes; PKCS#8-wrapped PQC private
  keys are refused with the explicit unsupported error
  (`register_import_export.rs:449-533`). RSA is the only family with
  multi-format ingest (PKCS#1/PKCS#8/X.509 SPKI, normalized by real
  DER parsing).
- **SPKI construction/parsing is pure-Rust RustCrypto** — `der` 0.7 /
  `spki` 0.7 / `x509-cert` 0.2 (Cargo.toml:104-110) — with its own
  authoritative OID table (`ops/spki_verify.rs:63-65` — the NIST
  sigAlgs arc strings) mapping OID → PKCS#11 mechanism+parameter-set
  plans (`:135-142`). Composite public keys (which span two engine
  objects and have no single handle) get their draft-19 §4 SPKI
  assembled and cached inline as the KMIP record's `key_material`
  (`ops/create_key_pair.rs:~335-360`).

**What this plan borrows from it:**

1. **An independent SPKI oracle for R3 (and R1-regression checks):**
   the same public-key bytes pushed through (a) the provider's
   encoder and (b) a KMIP-side/RustCrypto SPKI build must produce
   byte-identical DER. Different language, different ASN.1 stack,
   different authorship — a genuinely independent implementation, in
   the same repo, already trusted by the KMIP conformance evidence.
   Concretely: `storeutl`/`pkey -pubout` DER vs a small
   `x509-cert`-based check (or an existing KMIP test helper) over the
   raw `CKA_VALUE` bytes.
2. **A three-way OID agreement gate** for R3/R2/R7: provider name
   macros (`provider.h` NAMES strings embed OIDs), KMIP's OID
   constants (`spki_verify.rs`), and the staged OpenSSL `obj_mac.h`
   NIDs must all agree before an encoder/decoder lands — cheap to
   check, catches transposition typos that produce valid-but-wrong
   DER that only fails at a third-party verifier years later.
3. **The honest-refusal pattern as the error model**: provider
   encoders/decoders must fail loudly on unsupported selections
   (KMIP's 0x10 discipline), never fall through to a software
   implementation silently — the audit's whole premise is that "works
   via silent software fallback" is indistinguishable from "works on
   the token" unless refusal is explicit.
4. **R7's vectors and registry** come from the KMIP tree outright
   (all 8 profiles + external KAT file) — the provider side is a port
   with an existing in-repo oracle, not new cryptography.
5. **Boundary honesty:** no code is shared across the C/Rust boundary
   — KMIP KeyBlock formats are transport encodings, not OpenSSL
   provider encoders. The reuse is oracle + reference tables only.

---

## Sequencing and dependencies

```
R3 (ML-KEM encoders)  ──┐
                        ├──> R2 (decoders; ML-KEM round-trip case needs R3)
R4 (X25519/X448)  ──────┤        [R2's ML-DSA/SLH-DSA parts independent]
                        │
R3b (done) ─────────────┴──> R5-ph1 (TLS groups, client role)
                                  └─> R5 server role (needs ML-KEM keymgmt IMPORT)
R6 (Rust persistence) — independent; unlocks any "both engines" claim;
                        do before R9 (stateful keys need a non-amnesiac arm)
R7, R8 — demand-driven; R8 after verifying SKEYMGMT import
R9 — after ENV-1 (oracle rebuild) and preferably R6
R10 — probes anytime (cheap); scoped items only after probe writeups
R11 — last, on demonstrated demand only
```

Every landed item updates the harness expectations in the same commit
(ratchet discipline), updates `local-gate.sh`'s two count labels, and
appends — never rewrites — the audit's and this plan's update logs.

## Explicitly out of scope (unchanged from phase 1)

Hybrid TLS groups (R5 phase 2 — needs the classical+KEM combiner
question answered against `pqctoday-tls`'s existing composed
SecP384r1MLKEM1024 first); FrodoKEM / Classic McEliece / BIP32 /
Keccak-256 / split-key exposure through OpenSSL; WASM-arm changes;
any OpenSSL version work beyond the staged 3.6.3 oracle (except
ENV-1's `enable-lms` rebuild, which gates R9 and nothing else).
