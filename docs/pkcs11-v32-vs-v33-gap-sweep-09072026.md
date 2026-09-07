# PKCS#11 v3.2 vs v3.3 — systematic gap sweep

**Date:** 2026-09-07
**Rule this serves:** v3.2 is the baseline; the OASIS TC's v3.3 working tree governs **where v3.2 has a gap or a plain error** (see `CLAUDE.md`, "Source of Truth").
**v3.2:** `docs/refs/pkcs11-spec-v3.2-os.pdf` (published OASIS Standard)
**v3.3:** `docs/refs/pkcs11-v3.3-draft-git-snapshot-20260828/`, TC working tree at commit `2b25dd8` (2026-08-26) — **unpublished**

Three parallel read-only sweeps covered the generic attribute tables, the key-type sections, and the function/return-code model. Every finding below carries a v3.2 locator (PDF page or `/tmp/p11os.txt` line) and a v3.3 `file:line`.

---

## 0. The headline: the delta is small, and mostly additive

- **`pkcs11t.h`: 937 defines on each side. Zero added, zero removed, two changed** — both the `CKF_ARRAY_ATTRIBUTE` correction already adopted (`V33_CORRECTIONS`).
- **`pkcs11f.h`: no function added or removed.** The 44-line diff is comments only (one spelling fix, parameter comments on the two `*Authenticated` calls).
- **`CKR_*`: 99 codes each, name-for-name identical.** No code added, removed, or repurposed. One description broadened (§E below).
- **`CK_INFO` / `CK_TOKEN_INFO` / `CK_SLOT_INFO` / `CK_MECHANISM_INFO`: byte-identical**, no flag added or redefined.
- **`C_GetAttributeValue` is unchanged in substance** — the same five-step algorithm and the same `CKR_ATTRIBUTE_SENSITIVE` / `CKR_ATTRIBUTE_TYPE_INVALID` split this project's adjudications lean on heavily. Nothing from today's E1 work is disturbed.
- **Reporting Cryptoki 3.2.0 stays correct**: the v3.3 header still declares `CRYPTOKI_VERSION_MINOR 2`, and its version table has no 3.3 row.

**Both load-bearing facts behind today's E1 fix were independently re-confirmed on both versions:** neither RSA table has a `CKA_VALUE` row in v3.2 *or* v3.3, and all six HSS/XMSS/XMSS-MT `CKA_VALUE` rows are unchanged in row, footnote set, and meaning. The footnote definitions themselves (Table 13, footnotes 1–13) are identical, so a footnote number means the same thing in both.

---

## 1. Genuine v3.2 gaps that v3.3 fills — the rule applies squarely

These are the items the precedence rule was made for: v3.2 is silent or self-contradictory, and v3.3 supplies the answer.

### 1.1 `CKA_ENCAPSULATE_TEMPLATE` / `CKA_DECAPSULATE_TEMPLATE` — constants with no specification *(highest value)*

v3.2 defines both constants in the header and then **never mentions them again**: zero hits in the whole v3.2 spec text, and no row in Table 27 or Table 29. They are unusable as specified.

v3.3 supplies all of it — table rows (`public_key_objects.md:17`, `private_key_objects.md:21`), array-attribute status (`key_objects.md:71`), and **SHALL-level enforcement**:

- `key_management_functions.md:762-771` — the encapsulation template partitions which keys a key may encapsulate; on conflict the function **SHALL** return `CKR_KEY_HANDLE_INVALID`.
- `key_management_functions.md:868-878` — the decapsulation template is applied to the new key's attributes before the caller's own template; on conflict, **SHALL** return `CKR_TEMPLATE_INCONSISTENT`.

**Our position:** neither engine implements either attribute. The header correction is already taken; the enforcement is not. This is the cleanest gap-fill in the sweep and the natural next implementation item.

### 1.2 New normative "Template Attributes" section — deep-copy MUST *(largest adjudication delta)*

v3.2 has nothing equivalent. v3.3 `key_objects.md:67-135` adds MUST-level rules for all five `*_TEMPLATE` attributes: a token **MUST NOT** store the caller's `CK_ATTRIBUTE` array verbatim (it holds pointers into volatile application memory) and must deep-copy or return `CKR_TEMPLATE_INCONSISTENT`; plus a multi-call `C_GetAttributeValue` discovery protocol using `CK_UNAVAILABLE_INFORMATION` as a type sentinel.

**Our position:** an engine that stores the caller's array as-is is legal under v3.2's silence and a defect under v3.3. Needs a read of both engines' `CKA_WRAP_TEMPLATE`/`CKA_UNWRAP_TEMPLATE` handling before anything is claimed either way.

### 1.3 `CK_ULONG` capped at the 32-bit **signed** range

v3.2 says only that `CK_ULONG` "will sometimes be 32 bits, and sometimes perhaps 64 bits" (PDF p.23). v3.3 `introduction.md:303` adds a flat cap: every `CK_ULONG`, "regardless of the underlying implementation-defined size", may only carry values up to `0x7FFFFFFF`, and "any type defined in terms of `CK_ULONG` carries the same restriction."

**Our position:** worth an audit. It binds lengths, counts, handles, mechanism and attribute types, and flags. Note C++ already reports `UNLIMITED_KEY_SIZE` = 2³¹ (`0x80000000`) as `ulMaxKeySize` for the AES key-wrap mechanisms — that is **one over** the new cap, and the harness records it.

### 1.4 Big integers must be non-empty

v3.2 (PDF p.51): "a string of `CK_BYTE`s". v3.3 `objects.md:33`: "a **nonempty** string of `CK_BYTE`s". Every `Big integer`-typed attribute is affected.

**Our position: checked, and we are clean.** No big-integer attribute is returned zero-length by either engine across all 66 harness scenarios. Recorded so a future change is measured against it.

### 1.5 Smaller gap-fills

| Finding | v3.2 | v3.3 | Affects us? |
|---|---|---|---|
| `CKR_USER_PIN_NOT_INITIALIZED` | "only by `C_Login`" (PDF p.87) | "…and `C_LoginUser`" (`function_return_values.md:515`) | Corrects an omission — `C_LoginUser` already listed the code in v3.2 |
| `C_VerifySignatureInit` early length reject | not permitted | may return `CKR_SIGNATURE_LEN_RANGE`, no operation becomes active (`functions_for_verifying_signatures_and_macs.md:315`) | Permissive ("may"), no forced change |
| `C_EncapsulateKey` output convention | ad-hoc sentence | explicitly adopts the §5.2 two-call convention (`key_management_functions.md:759`) | Licenses the NULL-buffer size query |
| XMSS / XMSS-MT `CKA_KEYS_REMAINING` | tables have 2 rows | third row added (`xmss_and_xmss-mt.md:141`, `:185`) | Yes — but see §3, no constant is allocated |
| `CKA_OBJECT_VALIDATION_FLAGS` footnote 12 | present (read-only latch once `CK_FALSE`) | removed (`key_objects.md:34`) | Footnote 12 is boolean-specific and `CK_FLAGS` is not a boolean — reads as an erratum |
| `CKA_LOCAL` on domain parameters | `^2,4^` | `^2,4,6^` (`domain_parameter_objects.md:29`) | Adds a MUST-NOT on an unwrap path that yields domain parameters — largely moot |
| `C_Verify` "signing operation is terminated" | says "signing" | says "verification" | Plain v3.2 error; every implementation already does the right thing |

---

## 2. v3.3 **changes its mind** — the rule does *not* obviously cover these

These are not gaps or errors in v3.2. v3.2 states a rule, and v3.3 states a different one. Following them would change behaviour that is correct today and, in two cases, would change bytes on the wire.

**They need a separate decision, and I have not acted on any of them.**

### 2.1 `CKM_HSS` / `CKM_XMSS` input: hash → message *(wire-visible)*

- v3.2 §6.65.5: HSS "without hashing" — "corresponds only to the part of LMS that **processes the hash value** … **it does not compute the hash value**."
- v3.3 `hss.md:147-151`: "**The data passed in is the message.**" Same shift for XMSS (`xmss_and_xmss-mt.md:251`).

The two readings produce **different signatures for the same input**. Adopting v3.3 changes our output; not adopting leaves us aligned with the published standard.

### 2.2 `CKM_ML_DSA` single-part restriction dropped, `CKM_SLH_DSA` keeps it

v3.2 marks both single-part-only. v3.3 removes the restriction from ML-DSA (`ml_dsa.md:15`, `:271-276`) and keeps it for SLH-DSA (`slh-dsa.md:15`). A shared verify path would now have to diverge between the two.

### 2.3 HSS / XMSS multi-part verify permitted via `C_VerifySignatureInit`

v3.2: "Single-part operations only." v3.3 `hss.md:19`: also multi-part "when the `C_VerifySignatureInit` interface is used", plus a new `C_VerifySignature` length row.

### 2.4 `CKA_UNIQUE_ID` moves from *storage* objects to **all** objects

v3.2 Table 19 (storage objects only). v3.3 `common_attributes.md:67` — Common Object Attributes, so it now covers `CKO_HW_FEATURE`, `CKO_MECHANISM`, `CKO_PROFILE`, `CKO_VALIDATION` too. An engine that mints no unique id for those is conformant under v3.2 and not under v3.3.

### 2.5 Every "FIPS 186-4" subsection deleted

v3.2 §6.1.21 (RSA moduli **SHALL** be 1024/2048/3072 in FIPS mode), §6.2.13 (DSA), §6.3.24 (ECDSA curve list) are **all absent** from v3.3 — "FIPS mode" returns zero hits across the snapshot. This was the only spec text constraining FIPS-mode moduli and curves. Plausibly held pending a FIPS 186-5 rewrite; the snapshot gives no rationale.

### 2.6 X.509 keyUsage mapping gains `keyAgreement, keyEncipherment → CKA_ENCAPSULATE`

`public_key_objects.md:33-42`. Guidance, not a MUST.

---

## 3. Additive, and **not implementable today**

New v3.3 material whose constants do not exist in *either* header, so nothing can be built against it:

- **KMAC** (`kmac.md`) — and it depends on a whole new `C_DigestXof*` function family (`message_digesting_functions.md:208-410`) that is **absent from `pkcs11f.h`** and absent from the function-count summary, which still says "5 functions".
- **Composite signatures** (`comp_sig.md`, 18 `CKP_COMP_SIG_*` parameter sets) and **composite KEM** (`comp_kem.md`, 12 sets) — no `CKK_`/`CKM_`/`CKP_` constants allocated anywhere.
- **`CKM_SHAKE_128` / `CKM_SHAKE_256` as digest mechanisms** — no constants (v3.2 has only the `_KEY_DERIVATION` forms).
- **`CKM_ML_DSA_EXTERNAL_MU` / `_GEN`** — values `0x403b`/`0x403c` are allocated in the TC identifier DB but **not in the header**, and the proposal file itself says "Please update your spec before sending it to ballot."

**Precedent worth noting:** this project already adopted `0x403b`/`0x403c` for exactly these two mechanisms in `src/lib/vendor_mechanisms.h:54,81`, with an explicit "proposed, not-yet-ratified" caveat. So the v3.2-baseline/v3.3-fills-gaps rule was already being applied informally before it was written down.

---

## 4. Draft defects — report upstream, do not implement

Found while sweeping; all are v3.3 working-tree quality issues, not requirements:

- `CK_MU_GEN_PARAMS` (`ml_dsa.md:119-130`) — first member ends in a **comma, not a semicolon**; does not compile as written.
- `comp_kem.md:96` — private key objects said to hold key type `CKK_ML_KEM`; should be `CKK_COMP_KEM` (the sample template two lines below is correct).
- `aes.md` — mechanism table says `CKM_AES_EC`; the definitions list and prose both say `CKM_AES_ECB`.
- `elliptic_curves.md:992` — dangling `^1^` on `pPublicData` whose footnote text (v3.2's V2.20-encoding interop warning) exists nowhere in the snapshot.
- `slh-dsa.md:85,87` — v3.2's copy/paste bug reproduced unfixed: `CKP_SLH_DSA_SHAKE_256S` listed twice, `..._256F` missing.
- `certificate_objects.md:19` — `CKA_TRUSTED10` with the superscript markup lost.
- `revsion_history.md` — an unfilled OASIS template stub, so it gave no cross-check on completeness.

---

## 5. What I did not sweep

Out of the scope set for the three passes: `otp_key_objects.md`, `trust_objects.md`, `validation_objects.md`, `mechanism_objects.md`, `profile_objects.md`. **Trust objects matter to us** — we implement `CKO_TRUST` (plan item C2), and v3.2's Table 25 is sizeable. Worth a follow-up pass.

---

## 6. Recommended disposition

| | Action |
|---|---|
| **§1.1** encapsulate/decapsulate templates | Implement. Clean gap-fill, SHALL-level, and we already took the header half. |
| **§1.2** template deep-copy rules | Audit both engines first, then decide. |
| **§1.3** `CK_ULONG` 32-bit cap | Audit. C++'s `UNLIMITED_KEY_SIZE` (2³¹) is one over the cap. |
| **§1.4** non-empty big integers | Already clean. Recorded. |
| **§1.5** smaller gap-fills | Adopt the cheap ones; none forces a change. |
| **§2** all six | **Decision needed** — these are changes, not gap-fills. §2.1 in particular changes signature bytes. |
| **§3** additive | Watch. Re-pin the snapshot when the TC allocates constants. |
| **§4** draft defects | Report upstream; do not implement. |
| **§5** trust objects | Sweep next. |

---

## 7. Decisions taken (2026-09-07)

Every §2 item was decided individually. The §2.1 framing in this document's first draft was **wrong and is corrected below**.

| Item | Decision | Work |
|---|---|---|
| **§2.1** HSS/XMSS input: hash vs message | **Adopt v3.3. No code change.** | Record the adjudication |
| **§2.2** ML-DSA single-part restriction dropped | **Adopt** | Allow multi-part ML-DSA sign/verify, both engines |
| **§2.3** HSS/XMSS multi-part verify via `C_VerifySignatureInit` | **Adopt** | New capability, both engines |
| **§2.4** `CKA_UNIQUE_ID` on all object classes | **Adopt** | Mint it for the non-storage classes too |
| **§2.5** FIPS 186-4 deletions | **Do NOT adopt. Keep the v3.2 constraints**, and raise the deletion with the TC | Upstream question |
| **§2.6** X.509 keyUsage → `CKA_ENCAPSULATE` mapping | No action | Guidance, not a MUST |
| **§1.1** KEM encapsulate/decapsulate templates | **Implement in both engines** | SHALL-level enforcement |

### Correction to §2.1 — it is not a wire-format change, and we were already right

The first draft of this document listed HSS/XMSS signing input under "v3.3 changes its mind" and warned that adopting it "would change our signature bytes". **That was wrong**, and it was wrong because I reasoned from the two spec texts without first reading our own code.

Both engines pass the caller's buffer **directly** to the reference signers, which hash the message internally per RFC 8554 / the XMSS reference:

- C++ `SoftHSM_sign.cpp:1830` — `hss_generate_signature(..., pData, ulDataLen, ...)`
- C++ `SoftHSM_sign.cpp:1858` — `xmss_sign(privKeyBytes.byte_str(), sig, &sig_len, pData, ulDataLen)`
- Rust `crypto/lms.rs:130` — `lms::sign::<Sha256_256>(message, priv_key_bytes, ...)`

So we already implement v3.3's reading. v3.2's text — "corresponds only to the part of LMS that **processes the hash value** … **it does not compute the hash value**" — contradicts RFC 8554, which is what both the hash-sigs and xmss-reference libraries implement and what every other token does.

That makes this a **plain error in v3.2**, which the precedence rule already reaches. The consequence is the opposite of what the first draft implied: **no code change**, and the record exists so that a future auditor reading v3.2 literally does not "fix" the engines into a wrong and non-interoperable behaviour.

### §2.5 — kept, and to be raised upstream

The FIPS 186-4 deletions only ever *loosen* a security constraint, on the authority of an unpublished draft that gives no rationale. We keep v3.2's constraints. The deletion goes on the upstream question list alongside the draft defects in §4.

---

## 8. Second sweep — trust, validation, profile, mechanism and OTP objects

### 8.1 `CKO_TRUST` is **identical in substance** — our recent work stands

This was the reason for the second sweep: `CKO_TRUST` was implemented on both engines only days ago (plan item C2), adjudicated strictly against v3.2. Everything it relies on is reconfirmed:

- All 11 attribute rows: none added, none removed, same order, types and meanings.
- Footnote sets unchanged, **confirmed on the PDF page** rather than the text render: `CKA_ISSUER¹`, `CKA_SERIAL_NUMBER¹`, `CKA_HASH_OF_CERTIFICATE²`, `CKA_NAME_HASH_ALGORITHM²`, superscript `3` on all seven `CKA_TRUST_*` rows. Footnote texts 1/2/3 verbatim identical.
- The **closed `CK_TRUST` value domain** — same five values, same order, header values byte-identical.
- `CKA_NAME_HASH_ALGORITHM` **still defaults to SHA-1**.
- The WTO merge algorithm, the `CKT_TRUST_MUST_VERIFY_TRUST` reset rule, and the EKU mapping are verbatim identical.
- v3.3's new `object_classification.md` explicitly lists `CKO_TRUST` as a **storage object**, confirming the classification we chose.

Only difference: v3.2's sample template typo `CKM_SHA265` is fixed. (Both versions still mislabel that block as "creating an X.509 certificate object" — the bug survives into v3.3.)

### 8.2 Also identical in substance

`CKO_VALIDATION` (all 11 rows, both enum domains, the validation-indicator rules), `CKO_PROFILE`, and `CKO_OTP_KEY` (16 rows, same footnotes) — no behavioural change. OTP keys merely **move** from the mechanisms chapter into the objects chapter.

### 8.3 `CKO_MECHANISM` changes, but is not implementable

v3.2 Table 32 has one row (`CKA_MECHANISM_TYPE`) and says it "may not be set". v3.3 adds `CKA_SUPPORTED_PARAMETER_SETS` and `CKA_FLAGS`, moves immutability from the attribute to the whole object, and adds a SHOULD that applications verify a parameter set against the specific mechanism rather than inferring it from a related one.

**Neither new attribute has a numeric value anywhere** — not in v3.2, not in the v3.3 draft's own header. Spec-markdown only. Do not add to the local header or `V33_CORRECTIONS`.

### 8.4 `CKO_VALIDATION` / `CKO_PROFILE` / `CKO_MECHANISM` are explicitly non-storage in v3.3

v3.2 defines storage objects only positionally ("the object classes that follow"), which ambiguously sweeps these in. v3.3's `object_classification.md` states it outright. An engine that templates them as storage objects diverges from v3.3's explicit reading, though from no v3.2 text.

---

## 9. Verification of the adopted items — two need no code at all

### 9.1 §2.1 HSS/XMSS input — **already conformant, no change**

Verified in code, not inferred (see §7). Both engines pass the caller's buffer to the reference signers, which hash internally.

### 9.2 §2.4 `CKA_UNIQUE_ID` on all object classes — **already conformant, no change**

Both engines already mint it for **every** object, not just storage objects:

- **C++**: `P11Object::init` (`P11Objects.cpp:91`) creates `P11AttrUniqueId` for every class, and every subclass — including `P11ProfileObj` (`:420`) — chains to it.
- **Rust**: `state.rs:1348` inserts it unconditionally at "the single choke point through which all objects enter `OBJECTS`, so the attribute is guaranteed on every surface (FFI, native, KMIP)".

Adopting v3.3 here **ratifies what both engines already do**. Under v3.2's narrower table this was arguably over-materialising; under v3.3 it is exactly right.

### 9.3 Still to implement

| Item | Status |
|---|---|
| §1.1 KEM encapsulate/decapsulate template enforcement | Not started — the real gap-fill |
| §2.2 ML-DSA multi-part sign/verify | Not started |
| §2.3 HSS/XMSS multi-part verify via `C_VerifySignatureInit` | Not started |
| §2.5 FIPS 186-4 deletions | Kept; upstream question to draft |
