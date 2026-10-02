# Remediation plan: Rust engine slot and certificate discovery (2026-10-02)

**Source audit.** `~/Antigravity/pqctoday-hsm-rust-cert-discovery-audit-10022026.md`. A black-box C
client calls the native C ABI with 5 slots × 20 objects and lists slot ID, `CKA_LABEL`,
`CKA_SUBJECT` and `CKA_ID` for every `CKO_CERTIFICATE`. Result at `origin/main@ceddd554`: 28 pass, 10 fail.

**Branch.** `fix/rust-cert-discovery-1002`, cut from `ceddd554`, in the worktree
`pqctoday-hsm-discovery-audit-1002`.

**Definition of done.**
- Each fix has an in-crate regression test that **failed before the fix** (R1–R6).
- The Rust crate suite is green in `pqc-rust`.
- The black-box probe (`audit-probe/run.sh`) reports 0 FAIL, and both listing scenarios return 50/50
  rows with `CKR_OK`.
- The differential-ledger entries this work makes false are retired.

## Items

### R1 (G1): report the attributes the spec gives a default

**Rule.** §4, lines 2034–2037: attributes with defaults "need not be specified when creating an
object … Nonetheless, the object possesses these attributes". `C_GetAttributeValue` may answer
`CKR_ATTRIBUTE_TYPE_INVALID` only when the object does not possess the attribute (§5.7.5).

**Change.** In `state::apply_object_defaults`, which every newly created object passes through via
`allocate_handle`, fill in the following when the caller didn't supply them. Every row is checked
against the v3.2 OASIS Standard PDF. Line numbers refer to the PDF's own margin numbering.

| Class | Attribute | Default | v3.2 source |
|---|---|---|---|
| Storage objects: `CKO_DATA`, `CKO_CERTIFICATE`, `CKO_PUBLIC_KEY`, `CKO_PRIVATE_KEY`, `CKO_SECRET_KEY`, `CKO_DOMAIN_PARAMETERS` | `CKA_LABEL` | empty | Table 19, l.2182: "Description of the object (default empty)". Figure 1 (l.2013) shows Storage over Data, Key, Certificate and Domain parameters. |
| `CKO_PUBLIC_KEY`, `CKO_PRIVATE_KEY`, `CKO_SECRET_KEY` | `CKA_ID` | empty | Table 26, l.2455: "Key identifier for key (default empty)" |
| `CKO_CERTIFICATE` | `CKA_PRIVATE` | `CK_FALSE` | Table 19: "Default value is token-specific". The engine already treats an absent value as public, and Profiles §5.5 8a needs certificates to be public. |
| `CKO_CERTIFICATE` | `CKA_CERTIFICATE_CATEGORY` | `CK_CERTIFICATE_CATEGORY_UNSPECIFIED` (0) | Table 21, l.2244 |
| `CKO_CERTIFICATE` | `CKA_START_DATE`, `CKA_END_DATE` | empty | Table 21: "(default empty)" |
| `CKO_CERTIFICATE` | `CKA_PUBLIC_KEY_INFO` | empty | Table 21: "(default empty)" |
| `CKO_CERTIFICATE` (X.509 is the only type the engine accepts) | `CKA_ID`, `CKA_ISSUER`, `CKA_SERIAL_NUMBER`, `CKA_URL`, `CKA_HASH_OF_SUBJECT_PUBLIC_KEY`, `CKA_HASH_OF_ISSUER_PUBLIC_KEY` | empty | Table 22, l.2270: each is "(default empty)" |
| `CKO_CERTIFICATE` | `CKA_JAVA_MIDP_SECURITY_DOMAIN` | `CK_SECURITY_DOMAIN_UNSPECIFIED` (0) | Table 22 |

No new attribute is introduced. `CKA_JAVA_MIDP_SECURITY_DOMAIN` (0x88), `CK_SECURITY_DOMAIN_UNSPECIFIED`
(0) and `CKO_DOMAIN_PARAMETERS` (0x06) are added to `constants.rs` with the values in
`docs/refs/pkcs11t-canonical-v3.2.h` (lines 510, 457 and 331).

**Deliberately excluded after checking the spec.**
- `CKA_TRUSTED` on certificates: Table 21 states no default.
- `CKA_NAME_HASH_ALGORITHM`: Table 22 says "If the attribute is not present then the type defaults
  to SHA-1", so absence is allowed.
- `CKA_LABEL` on `CKO_TRUST`: Trust objects do not appear under Storage in Figure 1.
- Profile objects: Figure 1 places them directly under Object, not under Storage.
- The `CKA_PRIVATE` default for other storage classes: making private keys default to private would
  change who can see existing objects, which is a separate decision.

**Objects that existed before the fix.** Objects loaded from `SOFTHSMRUST_STATE_FILE`
(`state_snapshot::deserialize_token_state`) or from the SQLite store (`state::rehydrate_insert`) get
**only the attributes in the table above**, through `state::apply_possessed_defaults`. They do not
go through the full creation-time `apply_object_defaults`, so a load changes nothing else. A first
draft ran the full function on load. The existing snapshot round-trip test caught it adding
`CKA_MODIFIABLE`, `CKA_COPYABLE` and `CKA_DESTROYABLE` to a loaded object, and it was narrowed.

**Ledger.** Delete `LEGAL-OPTIONAL-ATTR-NOT-MATERIALISED-LABEL` and `LEGAL-OPTIONAL-ATTR-NOT-MATERIALISED-ID`
from `tests/differential/exceptions.json`. They become false: the C++ engine already returns these
attributes empty, and after this fix the Rust engine does too.

### R2 (G2): slots created by `C_GetSlotList` get their `CKO_PROFILE` objects

**Rule.** Profiles §5.1 condition 4 and §5.5 condition 5b.

**Change.** The spare-slot branch of `ffi::C_GetSlotList` must create the slot through
`state::ensure_slot`, the same path slot 0 uses, which already creates the profile objects.

**Existing state files.** After loading one, give any slot that has no profile objects its set.

### R3 (G3): a search template entry with an empty value must still filter

**Rule.** §5.7.7: "an exact byte-for-byte match with all attributes in the template".

**Change.** In `ffi::C_FindObjectsInit`:
- A zero-length entry becomes a filter for an empty value.
- An entry with a non-zero length but a NULL value pointer returns `CKR_ARGUMENTS_BAD`. Today it is
  silently dropped, which widens the search. §5.7.7 does not name this case. The basis is that
  `CKR_ARGUMENTS_BAD` is in §5.7.7's return list, and §5.1.6 defines it as "the arguments supplied to
  the Cryptoki function were in some way not appropriate". This is the same reasoning as the existing
  W5 fix.

### R4 (G4): report `CK_UNAVAILABLE_INFORMATION` when the buffer is too small

**Rule.** §5.7.5 case 5. The v3.3 draft is unchanged.

**Change.** On a too-small buffer, `ffi::C_GetAttributeValue` writes `CK_UNAVAILABLE_INFORMATION`
into `ulValueLen` instead of the real length.

**Callers checked.** The hub (`pqcCryptoBridge.ts`, `softhsm.ts`, the conformance runner) and
remoting (`verbs_v32.rs`) all read the length first, then the value, so they are unaffected.

### R5 (G5): `C_Initialize` refuses a partial set of mutex callbacks

**Rule.** §5.4.1.

**Change.** `ck_abi::C_Initialize` returns `CKR_ARGUMENTS_BAD` unless the four mutex function
pointers are either all NULL or all set.

### R6 (G6, owner decision 2026-10-02): each token reports its own serial number

**Not a v3.2 requirement.** `CK_TOKEN_INFO.serialNumber` carries no uniqueness rule. This item
exists because the owner requires multiple slots and chose the format: serial = slot ID + 1,
zero-padded to 4 digits. Slot 0 keeps `0001`; slot 1 reports `0002`, and so on.

**Change.** `ffi::C_GetTokenInfo`.

## Owner decisions (2026-10-02)

| Question | Decision |
|---|---|
| R1 scope | All storage objects, per Table 19 and Figure 1 for `CKA_LABEL` and Table 26 for `CKA_ID`. Retire both ledger entries. |
| Certificate `CKA_PRIVATE` default | `CK_FALSE` |
| R3: NULL value pointer with a non-zero length | Return `CKR_ARGUMENTS_BAD` |
| G6: token serial number | Slot ID + 1 (R6) |

## Out of scope (recorded, not done)

- **G7: no explicit way for a C client to create a slot.** That would be a vendor extension, so it
  needs an owner decision. The spare-slot behaviour is legal under §5.5.1.
- **`slotDescription` says "WASM" on the native build.** Cosmetic only.
- **Deriving `CKA_PUBLIC_KEY_INFO` from the certificate.** Table 21 defaults it to empty; deriving it
  is only a recommendation (§4.6.2).

## Verification

1. **Regression tests.** New in-crate tests for R1–R6, run on the unfixed engine first to show each
   one fails, then on the fixed engine.
2. **Rust crate suite** in the `pqc-rust` container, with its own target directory.
3. **Black-box probe.** Rerun `audit-probe/run.sh` against the rebuilt library.
4. **Differential harness / local gate.** Run if it is available. Otherwise record it as not run.
