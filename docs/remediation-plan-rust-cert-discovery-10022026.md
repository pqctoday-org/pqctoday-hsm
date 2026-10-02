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
| Storage objects: `CKO_DATA`, `CKO_CERTIFICATE`, `CKO_TRUST`, `CKO_PUBLIC_KEY`, `CKO_PRIVATE_KEY`, `CKO_SECRET_KEY`, `CKO_DOMAIN_PARAMETERS` | `CKA_LABEL` | empty | Table 19, l.2182: "Description of the object (default empty)". For which classes are storage objects, v3.2 is ambiguous: §4.4 (l.2180-2181) covers "the object classes that follow", which includes §4.7 Trust, but Figure 1 (l.2013) predates Trust and omits it. Under the repo's v3.3 rule (CLAUDE.md), v3.3's `object_classification.md` "Storage Objects" table governs; it lists Trust (snapshot `2b25dd8e`). |
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

**R1 correction (found by the local gate).** The first version also left `CKO_TRUST` out of the
`CKA_LABEL` set because it is missing from Figure 1. After the ledger entry was deleted, the
differential harness reported 3 uncovered divergences on `create.trust_object`: C++ reports
`CKA_LABEL` as empty, while Rust reported it absent. The v3.3 table above resolves the ambiguity, so
Trust was added.

### R7 (owner decision 2026-10-02): `CKA_PRIVATE` defaults match C++; private objects need a user session

**Rule.** Table 19 leaves the default for `CKA_PRIVATE` "token-specific". The decision is to use the
C++ engine's values:
- `TRUE` for data objects, private keys, secret keys and domain parameters
  (`P11AttrPrivate::setDefault`, and `isPrivate = CK_TRUE` in `SoftHSM_keygen`, `SoftHSM_kem` and
  derive).
- `FALSE` for certificates and public keys (`P11CertificateObj` and `P11PublicKeyObj`).
- `FALSE` for trust objects, per §4.7's prose.

Usage Guide Table 3 gives public sessions and the SO session no access to private objects. Creating
one there is therefore `CKR_USER_NOT_LOGGED_IN`. The Rust engine had no such check: a public session
could generate a key pair whose private key that same session could not see.

**Change.** Every `ffi::C_*` creation path now allocates through `ffi_alloc` or `ffi_alloc_key_pair`:
`C_CreateObject`, `C_GenerateKey`, `C_GenerateKeyPair`, `C_DeriveKey`, `C_UnwrapKey`,
`C_UnwrapKeyAuthenticated`, and encapsulate/decapsulate. These apply the class default and refuse a
private object outside a user session; both halves of a key pair are checked before either is
allocated. `C_CopyObject` keeps the source's value and applies the same check. Eleven hard-coded
`CKA_PRIVATE=FALSE` defaults in `C_GenerateKey`, encapsulate/decapsulate and `C_DeriveKey` are now
`TRUE`; three of the six encapsulate/decapsulate ones cited a non-existent "§4.1 default".

**Not changed.** The `native::*` (KMIP) surface keeps its historical rule that an absent
`CKA_PRIVATE` means public. Objects loaded from older state get `CKA_PRIVATE=FALSE`, the value they
were always treated as, so a load never changes who can see an object.

**Test fixtures.** Existing tests that created secret keys, private keys or data objects in public
sessions now log the user in (`state::test_login_user`). Where the test was about something else
(persistence across `C_Finalize`, SO-only trusted copies, or a no-login known-answer test through
the C ABI), the fixture object is made explicitly public instead.

**Hub impact (read-only audit 2026-10-02, against hub `origin/main`).** Any flow that creates a
private object outside a user session now gets `CKR_USER_NOT_LOGGED_IN`. Nearly every hub path gets
its session from `hsm_openUserSession` (user login) and is unaffected. Two break; both have been
verified in the source. They are to be fixed in the hub with the bundle re-pin (owner decision:
report now, fix at re-pin):

1. **Learn → v3.2 → "Trust & wrapping policy"**, step "Log in as SO and import a genuinely trusted
   wrapping key". `hsm_importTrustedWrapKey` (`src/wasm/softhsm.ts:915-932`) creates a secret key
   without `CKA_PRIVATE` on an SO-logged-in session (`pkcs11LessonsV32.ts:949-951`). Under R7 the key
   is private, and SO sessions have no access to private objects, so the step is refused and the
   following wrap step fails. Fix: set `CKA_PRIVATE=FALSE` in that helper's template.
2. **`src/wasm/secp256k1.kat.test.ts`** opens a raw session on slot 0 with no login, then generates
   a key pair whose private template sets `CKA_PRIVATE=TRUE`. Fix: initialize the token and use
   `hsm_openUserSession`, like the other engine tests.

There is also an existing bug that R7 does not cause. In dual mode, `KemOpsTab.tsx` and
`SignVerifyTab.tsx` pass the C++ engine's session handle to the Rust cross-check module, which never
set up a token, session or login (`HsmContext.tsx:505-510`). R7 only changes which error it gets.

Cosmetic: key inspectors now show `CKA_PRIVATE=TRUE` for generated, derived and encapsulated secret
keys.

### R8 (owner decision 2026-10-02, G7): `SOFTHSMRUST_SLOTS=N`

`ffi::C_Initialize` brings slots `0..N-1` online through `ensure_slot`, each with its `CKO_PROFILE`
objects. This is engine configuration, not a PKCS#11 API. Slots already loaded from the state file
are left as they are. A malformed value, or one outside 1..=256 (`MAX_CONFIGURED_SLOTS`, a guard
against typos), fails `C_Initialize` with `CKR_FUNCTION_FAILED` rather than being ignored. The
spare-slot behaviour of `C_GetSlotList` is unchanged. `C_WaitForSlotEvent` is left as it is (owner
decision).

### R9 (owner decision 2026-10-02): `slotDescription`

Every build and every slot reports "PQCToday HSM Virtual Slot", and the slot's `manufacturerID`
reads "PQCToday" (owner decision 2026-10-02). The library-level `CK_INFO.manufacturerID`
(`C_GetInfo`) is unchanged; the ledger's `LEGAL-IDENTITY-STRINGS` entry covers it.

### R10 (§4.6.2 recommendation): `CKA_PUBLIC_KEY_INFO` from the certificate

§4.6.2 l.2246-2247: Cryptoki "does recommend that the key be extracted from the certificate to
create this value". `C_CreateObject` for an X.509 certificate without `CKA_PUBLIC_KEY_INFO` stores
the SubjectPublicKeyInfo found in `CKA_VALUE`, using the existing `der_read_tlv`. A value the caller
supplies is kept. A certificate that does not parse keeps Table 21's empty default.

## Owner decisions (2026-10-02)

| Question | Decision |
|---|---|
| R1 scope | All storage objects, per Table 19 and Figure 1 for `CKA_LABEL` and Table 26 for `CKA_ID`. Retire both ledger entries. |
| Certificate `CKA_PRIVATE` default | `CK_FALSE` |
| R3: NULL value pointer with a non-zero length | Return `CKR_ARGUMENTS_BAD` |
| G6: token serial number | Slot ID + 1 (R6) |
| `CKA_PRIVATE` on keys and data | Match C++ (R7) |
| G7: creating slots | `SOFTHSMRUST_SLOTS=N` (R8) |
| `C_WaitForSlotEvent` | Leave as is |
| `slotDescription` | "PQCToday HSM Virtual Slot"; slot `manufacturerID` "PQCToday" (R9) |
| `CKA_PUBLIC_KEY_INFO` from the certificate | Yes (R10) |

## Out of scope (recorded, not done)


## Verification

1. **Regression tests.** New in-crate tests for R1–R6, run on the unfixed engine first to show each
   one fails, then on the fixed engine.
2. **Rust crate suite** in the `pqc-rust` container, with its own target directory.
3. **Black-box probe.** Rerun `audit-probe/run.sh` against the rebuilt library.
4. **Differential harness / local gate.** Run if it is available. Otherwise record it as not run.
