# rust/kat/kmac — provenance

KMAC known-answer data for the committee's `CKM_KMAC128` / `CKM_KMAC256` and the vendor `CKM_KMAC_128` / `CKM_KMAC_256`, which run on one implementation. Replayed by `rust/src/acvp_nist_vectors_tests.rs` (`k1_*`).

| File | What | Class |
|---|---|---|
| `kmac_sp800185_samples.json` | The six worked KMAC examples of NIST SP 800-185 (NIST "Examples with Intermediate Values", `KMAC_samples.pdf`). Values copied from the document; also reproduced by OpenSSL 3.6.3. | published standard KAT |
| `kmac_openssl_oracle.json` | 48 byte-aligned cases generated with OpenSSL 3.6.3 at the Keccak rate and bytepad boundaries. | independent oracle (not a NIST vector) |

The NIST ACVP KMAC sets (`KMAC-128-1.0`, `KMAC-256-1.0`, 800 cases each) cannot be replayed beyond two cases: they use random **bit** lengths, which a byte-oriented interface cannot express (the PKCS#11 v3.3 draft says it "restricts inputs and outputs to byte sized lengths"), and half are XOF cases, which need the draft's `C_DigestXof*` functions that are not in its header. The two byte-aligned, non-XOF cases are in `../acvp-ws-e/kmac_acvp_test.json`.

## Rules and limits of the committee's numbers

What `CKM_KMAC128` / `CKM_KMAC256` accept and refuse, so a caller reads the rule here instead of finding it by trial:

- **Key handle.** The `hKey` inside `CK_KMAC_PARAMS` must equal the key passed to `C_SignInit` / `C_VerifyInit`. A different handle, or an empty one, is refused with `CKR_MECHANISM_PARAM_INVALID`. The draft says only that `hKey` is "the handle to the key to be used", so the engine requires the two to agree.
- **Key type and length.** `CKK_KMAC` or `CKK_GENERIC_SECRET`, any non-empty length (checked from 1 to 65,536 bytes). The draft numbers advertise 1 byte upward in `C_GetMechanismInfo`; the vendor numbers keep their earlier answer of 16 to 64 bytes, so recorded results do not change, although they accept the same keys.
- **MAC length.** `ulMacLength` from 1 to 1,024 bytes. The draft requires at least 16 to 256 bytes to work and lets an implementation restrict the rest. A very short MAC can be guessed; the choice is the caller's.
- **Customization string.** Up to 1,024 bytes; a non-zero length needs a non-null pointer.
- **XOF mode.** `ulMacLength` 0 is refused for `C_Sign` / `C_Verify`, as the draft requires.

## What is not implemented, and why

The draft's `CKM_SHAKE_128` (0x2f) and `CKM_SHAKE_256` (0x35) digest mechanisms are defined only for the `C_DigestXofInit` / `Update` / `Extract` / `Final` functions, which the draft's own `pkcs11f.h` does not declare (it adds no functions). They take no parameter because the output length comes from those functions, so they cannot be expressed through `C_Digest`. KMAC's extendable-output mode depends on the same functions. Both are left out for that reason. This is a limit, not a postponement.

