# rust/kat/kmac — provenance

KMAC known-answer data for the committee's `CKM_KMAC128` / `CKM_KMAC256` and the vendor `CKM_KMAC_128` / `CKM_KMAC_256`, which run on one implementation. Replayed by `rust/src/acvp_nist_vectors_tests.rs` (`k1_*`).

| File | What | Class |
|---|---|---|
| `kmac_sp800185_samples.json` | The six worked KMAC examples of NIST SP 800-185 (NIST "Examples with Intermediate Values", `KMAC_samples.pdf`). Values copied from the document; also reproduced by OpenSSL 3.6.3. | published standard KAT |
| `kmac_openssl_oracle.json` | 48 byte-aligned cases generated with OpenSSL 3.6.3 at the Keccak rate and bytepad boundaries. | independent oracle (not a NIST vector) |

The NIST ACVP KMAC sets (`KMAC-128-1.0`, `KMAC-256-1.0`, 800 cases each) cannot be replayed beyond two cases: they use random **bit** lengths, which a byte-oriented interface cannot express (the PKCS#11 v3.3 draft says it "restricts inputs and outputs to byte sized lengths"), and half are XOF cases, which need the draft's `C_DigestXof*` functions that are not in its header. The two byte-aligned, non-XOF cases are in `../acvp-ws-e/kmac_acvp_test.json`.
