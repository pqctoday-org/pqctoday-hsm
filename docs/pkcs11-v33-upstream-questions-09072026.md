# PKCS#11 v3.3 working draft — questions for the OASIS TC

**Date:** 2026-09-07
**Source:** OASIS PKCS 11 TC working tree, `https://github.com/oasis-tcs/pkcs11`, branch `master`
**Snapshot commit:** `2b25dd8ed4a85d22937d8509bb296555cd329f43` (2026-08-26), pinned at `https://github.com/oasis-tcs/pkcs11/tree/2b25dd8ed4a85d22937d8509bb296555cd329f43` (a local copy was vendored until 2026-10-15; see `docs/refs/README.md`)
**Status:** Recorded per phase-5 decision D-4. **Not sent.** Whether and when to raise these with the TC is a separate decision; this document exists so the defects are on file rather than re-discovered.
**Re-checked:** 2026-10-21 against TC commit `9ef73f9f44ed8a240b05484427a0851ab36be251` (the current pin), for every item, by the v3.2 → v3.3 full delta audit. Item 1 is withdrawn (its premise was wrong), items 4 and 5 are fixed upstream, items 7 and 8 are answered, items 2, 3, 6 and 9 stay open, and items 10–19 are new. Each item carries its own "Status at 9ef73f9" line; see also "Re-check at 9ef73f9" and "New items (2026-10-21)" at the end. Still **not sent**.

Every item below was re-verified against the vendored snapshot before being written down (`https://github.com/oasis-tcs/pkcs11/tree/2b25dd8ed4a85d22937d8509bb296555cd329f43/working/doc/spec`), not carried forward from an earlier draft of this list.

---

## 1. FIPS 186-4 subsections deleted without rationale

v3.2 constrains RSA moduli and EC curves under FIPS mode via subsections carried from FIPS 186-4. The v3.3 working tree drops them, and the snapshot gives no changelog entry, issue reference, or commit message explaining why. This engine keeps the v3.2 constraints (standing rule: v3.3 governs where v3.2 has a *gap or a plain error* — silent deletion of a constraint is neither).

**Question:** was this deletion intentional, and if so, what replaces the FIPS-mode guidance for RSA modulus and EC curve selection?

**Status at 9ef73f9: WITHDRAWN — the premise was wrong.** The deletion has a stated rationale: TC issue #80 ("outdated … rather remove these sections than update them") and PR #102, commit `f3858f7` (2026-05-06, "Outdated key sizes for operation in fips mode"), which replaced the subsections with a general note under `C_GetMechanismInfo` (`slot_and_token_mgmt_functions.md:320`): a module whose capabilities differ in a compliance mode "ought to" report that in its mechanism information. The sentence above that "this engine keeps the v3.2 constraints" also had no effect in code: neither engine has a FIPS or compliance mode, so the v3.2 FIPS-mode subsections never applied to it. If a compliance mode is ever added, the new `C_GetMechanismInfo` note is the rule to follow.

---

## 2. `CK_MU_GEN_PARAMS` does not compile

`ml_dsa.md:123-129`:

```c
typedef struct CK_MU_GEN_PARAMS {
  CK_OBJECT_HANDLE hKey, //public or private.
  CK_BYTE_PTR         pTR; //pre computed TR from public key
  CK_ULONG            ulTRLen;
  CK_BYTE_PTR         pctx;
  CK_ULONG            ulctxLen;
} CK_MU_GEN_PARAMS;
```

Line 124 ends the first member with a comma (`hKey,`) instead of a semicolon. As written this is not valid C.

**Question:** confirm the intended separator is `;` and that no other member was meant to follow `hKey` on that line.

---

## 3. `comp_kem.md:96` — private key objects said to hold `CKK_ML_KEM`

```
comp_kem.md:96: **CKK_ML_KEM**) hold Composite KEM private keys.
```

Every other reference to the Composite KEM key type in the same file (lines 21, 55, 76, 125) correctly names `CKK_COMP_KEM`. Line 96 — the private-key-object definition — is the one outlier, and describing a Composite KEM private key as holding an `CKK_ML_KEM` key type is a real type-confusion, not a formatting slip.

**Question:** confirm line 96 should read `CKK_COMP_KEM`.

---

## 4. `aes.md:14` — mechanism table says `CKM_AES_EC`

The mechanism-vs-function capability table's AES-ECB row spells the mechanism `CKM_AES_EC`:

```
aes.md:14: | CKM_AES_EC                           |  ✓  |     |      |     |       |  ✓  |     |      |
```

Every other reference to this mechanism in the same file's definitions and prose spells it `CKM_AES_ECB`. No mechanism named `CKM_AES_EC` exists in the header.

**Question:** confirm line 14 is a table typo for `CKM_AES_ECB`.

**Status at 9ef73f9: FIXED UPSTREAM** by commit `11d4370` (2026-09-08, "Correct AES ECB mechanism name in spec"). Withdrawn.

---

## 5. `slh-dsa.md:85,87` — v3.2's own copy/paste bug, carried forward

```
slh-dsa.md:85: - CKP_SLH_DSA_SHAKE_256S
slh-dsa.md:87: - CKP_SLH_DSA_SHAKE_256S
```

`CKP_SLH_DSA_SHAKE_256S` is listed twice; `CKP_SLH_DSA_SHAKE_256F` is missing from the list entirely. This is the same defect v3.2 itself has in the equivalent table — a pre-existing bug, not something v3.3 introduced, but it was carried into the new draft rather than fixed.

**Question:** confirm line 87 should read `CKP_SLH_DSA_SHAKE_256F`.

**Status at 9ef73f9: FIXED UPSTREAM** by commit `ea60dfa` (2026-09-11, "Doc cleanup", #130): the list now ends `CKP_SLH_DSA_SHAKE_256S`, `CKP_SLH_DSA_SHA2_256F`, `CKP_SLH_DSA_SHAKE_256F`. Withdrawn.

---

## 6. `elliptic_curves.md:992` — dangling `^1^` footnote reference

```
elliptic_curves.md:992: _pPublicData_^1^
```

This is inside the field-by-field description of `CK_ECDH1_DERIVE_PARAMS` (key derivation). The same file defines a `^1^` footnote elsewhere (lines 68, 700: *"Single-part operations only"*), but that footnote is attached to signing/verification mechanism rows and has no coherent meaning applied to a key-derivation parameter struct field. No other footnote text with marker `1` exists near line 992, and the field's own description (lines 992–1000+) makes no reference to single-part-vs-multi-part at all.

**Question:** is the `^1^` at line 992 a leftover from copy-pasting the table structure, and if so, should it be removed?

---

## 7. `CKO_MECHANISM`'s two new attributes have no allocated value

`mechanism_objects.md:12-16` defines three attributes for the `CKO_MECHANISM` object class: `CKA_MECHANISM_TYPE` (already allocated, pre-dates v3.3), `CKA_SUPPORTED_PARAMETER_SETS`, and `CKA_FLAGS`. Checked against the draft's own header (`working/headers/pkcs11t.h`): **neither `CKA_SUPPORTED_PARAMETER_SETS` nor `CKA_FLAGS` has a `#define`** anywhere in it. The prose defines behaviour for two attributes an implementer cannot actually reference by value.

**Question:** are these two attributes awaiting allocation, or was the header update simply not yet committed alongside the prose?

**Status at 9ef73f9: ANSWERED.** Commit `9ef73f9` (#156) allocates them in the identifier database as **proposed**: `CKA_FLAGS` = `0x638`, `CKA_SUPPORTED_PARAMETER_SETS` = `0x639` (`working/identifier_db/raw_ids.db:83-84`). They are not yet in `working/headers/pkcs11t.h`. See item 19 for a follow-on question about the flag bit.

---

## 8. `CKA_OBJECT_VALIDATION_FLAGS` footnote 12 — erratum or deliberate?

v3.2 gives `CKA_OBJECT_VALIDATION_FLAGS` a read-only latch under footnote 12 of its table. v3.3's prose for the same attribute drops that latch with no accompanying rationale — the same shape as item 1 above (a constraint disappearing silently), but scoped to one attribute rather than a whole subsection. Phase-5 D-3 checked both engines: neither implements this attribute at all today, so nothing in this repository currently depends on the answer, but a future implementer would.

**Question:** was dropping the read-only latch on `CKA_OBJECT_VALIDATION_FLAGS` deliberate, and if so, what is the rationale?

**Status at 9ef73f9: ANSWERED.** Deliberate: TC issue #33 / PR #78, commit `d5dffc8` ("Remove footnote 12 for CKA_OBJECT_VALIDATION_FLAGS"). Footnote 12 is a `CK_BBOOL` rule ("… CK_FALSE …") that was misapplied to a `CK_FLAGS` attribute. Withdrawn.

---

## 9. Composite chapters cite superseded IETF drafts

`references.md:75` and `references.md:81` (TC commit `9ef73f9`) cite `[COMP_KEM]` as draft-ietf-lamps-pq-composite-kem **-12** and `[COMP_SIG]` as draft-ietf-lamps-pq-composite-sigs **-14** (both dated January 2026). The current drafts are **-23** and **-19**. `comp_kem.md` and `comp_sig.md` cite sections of these documents (for example `comp_kem.md:175,178`, "section 3.2/3.3 of [COMP_KEM]").

Compared on 2026-10-21: the OIDs, the combiner labels and the signature prefix are unchanged between the cited and the current drafts, and the lists of parameter sets in the v3.3 header (18 `CKP_COMP_SIG_*`, 12 `CKP_COMP_KEM_*`) still match the current drafts one for one. Nothing in this repository depends on the stale citation; the engine implements and cites -23 and -19.

**Question:** should the references move to the current drafts (or to the RFC numbers once published), and should the section references in `comp_kem.md` / `comp_sig.md` be re-checked when they do?

---

## Re-check at 9ef73f9 (2026-10-21)

Recorded for the composite work (the v3.3 pin moved from `2b25dd8` to `9ef73f9`); still **not sent**.

- **Item 2 (`CK_MU_GEN_PARAMS`):** unfixed, and the comma is now also in the TC's own header: `working/headers/pkcs11t.h:2744` reads `CK_OBJECT_HANDLE    hKey,     /* public or private. */`. `ml_dsa.md:124` still has it too. A C compiler including that header as written fails, so the defect is no longer prose-only. This repository's `src/lib/pkcs11/pkcs11t.h` stays canonical v3.2 and does not carry the struct.
- **Item 3 (`comp_kem.md:96`):** unfixed at `9ef73f9`: the Composite KEM private key object is still said to have key type `CKK_ML_KEM`. The engine uses `CKK_COMP_KEM` for both composite KEM objects, as every other line of the chapter and the header do.
- **Item 9:** new, above.
- **Items 1, 4, 5, 7, 8:** withdrawn, fixed or answered; see each item's status line.
- **Item 6 (`elliptic_curves.md:992`):** still open.

## New items (2026-10-21)

Found by the v3.2 → v3.3 full delta audit at TC commit `9ef73f9`. Recorded only; **not sent**.

### 10. The CK_ULONG limit (#122) contradicts the rest of the specification

`introduction.md:300` (commit `24f8e1a`, closing issue #111) says a `CK_ULONG` "can only ever contain values up to the maximum value representable as a 32-bit **signed** integer" (2^31−1). The same specification and header use larger values: `CKA_VENDOR_DEFINED` / `CKM_VENDOR_DEFINED` / `CKK_VENDOR_DEFINED` = `0x80000000`; `CK_UNAVAILABLE_INFORMATION` = `~0`; and `CKA_KEYS_REMAINING` is capped at **2^32−1** (`hss.md:85`, `xmss_and_xmss-mt.md:141, 185`). Issue #111 describes a 32-bit *unsigned* limit and explicitly carves out `CK_UNAVAILABLE_INFORMATION`; the merged text keeps neither. This engine narrows `CK_ULONG` input to 32 bits unsigned.

**Question:** should the sentence say *unsigned*, and keep the `CK_UNAVAILABLE_INFORMATION` exception the issue proposed?

### 11. Wrong deprecation pointer in the header

`working/headers/pkcs11t.h:2290-2291` reads `/* Deprecated. Use CK_CCM_PARAMS_PTR */` above `CK_AES_GCM_PARAMS_PTR`. It should name `CK_GCM_PARAMS_PTR`; the CCM pointer at line 2304 is the correct one.

**Question:** confirm the comment should read `CK_GCM_PARAMS_PTR`.

### 12. The XOF function family and the KMAC chapter cannot be implemented as written

- The six `C_DigestXof*` functions (`message_digesting_functions.md:208-440`) have no `pkcs11f.h` prototypes, no function-list slot and no interface version, so a token cannot export them interoperably.
- `C_DigestXofInit` says `pMechanism` "should contain the handle of the key" (:229), but the key travels in `CK_KMAC_PARAMS.hKey`.
- `C_DigestXofKeyValue` is described as a "message-digesting operation".
- The example uses `CKM_KMAC_256` (:430), which does not exist (the allocated names are `CKM_KMAC128` / `CKM_KMAC256`).
- `kmac.md`: "set non a non-zero value" (:73) and "ulMaxLength" (:130).
- For `C_Sign` / `C_Verify`, `CK_KMAC_PARAMS.hKey` duplicates the function's own `hKey` argument, and nothing says which one wins.

**Question:** are the XOF functions meant for v3.3 (then they need prototypes, a function-list slot and an interface), and which `hKey` governs a KMAC `C_Sign`?

### 13. `CKM_ML_DSA_EXTERNAL_MU_GEN` is under-specified

`ml_dsa.md:119-130, 364-375`:
- `hKey` may be "public or private", but the text never says how to obtain tr from a private key. (This engine computes tr = H(pk, 64) from the public key re-derived from the private key, so the µ is the same whichever half is named; hashing the private key's value would give a µ no signature verifies against.)
- "If the key handle is empty" is undefined (presumably `CK_INVALID_HANDLE`).
- The prose promises single- and multi-part digest; the table lists only `C_Digest`.
- `ulMinKeySize` / `ulMaxKeySize` are described as "ML-DSA public keys" for a digest mechanism whose key is optional.
- Nothing says which return code a key of the wrong type, or a handle the session may not use, gets (this engine: `CKR_KEY_TYPE_INCONSISTENT` / `CKR_KEY_HANDLE_INVALID`, as for any key-using operation).

**Question:** can the text state that tr is always H(pk, 64) of the ML-DSA public key, define "empty" as `CK_INVALID_HANDLE`, add the multi-part rows and name the error codes?

### 14. External-µ context wording conflicts with itself

`ml_dsa.md:392`: "In all cases ulContextLen will be zero and pContext are ignored" — a requirement and "ignored" in one sentence. This engine refuses a non-empty context (`CKR_MECHANISM_PARAM_INVALID`), which satisfies the first half.

**Question:** is a non-empty context an error or ignored?

Related deviation, recorded here and in `tests/differential/exceptions.json` (`LEGAL-V33-DRAFT-EXTERNAL-MU-MULTI-PART`): the draft makes `CKM_ML_DSA_EXTERNAL_MU` single-part only; both engines accept it multi-part, because OpenSSL's provider interface drives every ML-DSA signature through `C_SignInit`/`C_SignUpdate`/`C_SignFinal`. A note to the TC could ask whether "single-part" is meant to forbid a token from buffering a 64-byte input.

### 15. `comp_sig.md` key/data table footnote is incomplete

Footnote `^1^` ("Single-part operations only when the CKM_COMP_SIG_EXTERNAL_HASH mechanism is used", `comp_sig.md:216`) is attached to the `C_Verify` row only. The `C_Sign` and `C_VerifySignature` rows lack it, so whether `CKM_COMP_SIG_EXTERNAL_HASH` signing may be multi-part is ambiguous. The intent of ticket #100 is single-part; this engine refuses it multi-part everywhere.

**Question:** add the footnote to the `C_Sign` and `C_VerifySignature` rows.

### 16. The HSS and XMSS tables are inconsistent with their own prose

- `hss.md:166` still says "^1^ Single-part operations only" for `C_Verify`, while the mechanism-table footnote (:19) and the prose (:149) now allow multi-part verification through `C_VerifySignatureInit`.
- `hss.md:163` reads "N//A".
- The XMSS / XMSS^MT key and data tables (`xmss_and_xmss-mt.md:258-279`) lack the `C_VerifySignature` row HSS gained.

**Question:** align the three tables with the prose.

### 17. The `CKA_ENCAPSULATE_TEMPLATE` paragraph is copied from the wrap text

`key_management_functions.md:763-773` says the template is "compared against the attributes of **the key to be encapsulated** … then **the wrap** will proceed". A KEM creates the key; there is no existing key to compare against. This engine reads it as the key being created by `C_EncapsulateKey`.

**Question:** confirm that reading and fix the wording.

### 18. The template-attribute validity rule is garbled

`key_objects.md:102`: "If either *all* or *none* of the attribute type fields are set to CK_UNAVAILABLE_INFORMATION (i.e., all contain a valid attribute type …)" — the parenthesis contradicts the "all" case. Typos: "successuive" (:85), "tempate" (:86). This engine implements the evident intent: all-unavailable is discovery, none-unavailable must name exactly the stored attributes, anything else is `CKR_TEMPLATE_INCONSISTENT`.

**Question:** rewrite the sentence so the two cases are stated separately.

### 19. Should `CKA_SUPPORTED_PARAMETER_SETS` carry `CKF_ARRAY_ATTRIBUTE`?

It is allocated as plain `0x639` (`identifier_db/pkcs11v3.3/mechanism_attributes.*`) although its type is an array (`CK_ULONG_PTR`, `mechanism_objects.md`). That is the pattern the TC just corrected for `CKA_ENCAPSULATE_TEMPLATE` / `CKA_DECAPSULATE_TEMPLATE` (commit `941c208`). Precedent is mixed (`CKA_ALLOWED_MECHANISMS` carries the flag, `CKA_HSS_LMS_TYPES` does not), so this is a question rather than a certain defect.

**Question:** which convention applies to new array-valued attributes?

