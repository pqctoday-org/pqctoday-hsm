# PKCS#11 v3.3 working draft — questions for the OASIS TC

**Date:** 2026-09-07
**Source:** OASIS PKCS 11 TC working tree, `https://github.com/oasis-tcs/pkcs11`, branch `master`
**Snapshot commit:** `2b25dd8ed4a85d22937d8509bb296555cd329f43` (2026-08-26), vendored at `docs/refs/pkcs11-v3.3-draft-git-snapshot-20260828/`
**Status:** Recorded per phase-5 decision D-4. **Not sent.** Whether and when to raise these with the TC is a separate decision; this document exists so the defects are on file rather than re-discovered.

Every item below was re-verified against the vendored snapshot before being written down (`docs/refs/pkcs11-v3.3-draft-git-snapshot-20260828/working/doc/spec/`), not carried forward from an earlier draft of this list.

---

## 1. FIPS 186-4 subsections deleted without rationale

v3.2 constrains RSA moduli and EC curves under FIPS mode via subsections carried from FIPS 186-4. The v3.3 working tree drops them, and the snapshot gives no changelog entry, issue reference, or commit message explaining why. This engine keeps the v3.2 constraints (standing rule: v3.3 governs where v3.2 has a *gap or a plain error* — silent deletion of a constraint is neither).

**Question:** was this deletion intentional, and if so, what replaces the FIPS-mode guidance for RSA modulus and EC curve selection?

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

---

## 5. `slh-dsa.md:85,87` — v3.2's own copy/paste bug, carried forward

```
slh-dsa.md:85: - CKP_SLH_DSA_SHAKE_256S
slh-dsa.md:87: - CKP_SLH_DSA_SHAKE_256S
```

`CKP_SLH_DSA_SHAKE_256S` is listed twice; `CKP_SLH_DSA_SHAKE_256F` is missing from the list entirely. This is the same defect v3.2 itself has in the equivalent table — a pre-existing bug, not something v3.3 introduced, but it was carried into the new draft rather than fixed.

**Question:** confirm line 87 should read `CKP_SLH_DSA_SHAKE_256F`.

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

---

## 8. `CKA_OBJECT_VALIDATION_FLAGS` footnote 12 — erratum or deliberate?

v3.2 gives `CKA_OBJECT_VALIDATION_FLAGS` a read-only latch under footnote 12 of its table. v3.3's prose for the same attribute drops that latch with no accompanying rationale — the same shape as item 1 above (a constraint disappearing silently), but scoped to one attribute rather than a whole subsection. Phase-5 D-3 checked both engines: neither implements this attribute at all today, so nothing in this repository currently depends on the answer, but a future implementer would.

**Question:** was dropping the read-only latch on `CKA_OBJECT_VALIDATION_FLAGS` deliberate, and if so, what is the rationale?
