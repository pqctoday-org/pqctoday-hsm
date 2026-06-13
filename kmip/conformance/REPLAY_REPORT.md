# OASIS KMIP 3.0 Dispatcher Replay Report

Generated: 2026-06-13 17:12:51 UTC


## Aggregate


| Status | Count | % of total |
|---|---|---|
| **PASS** | 92 | 90.2% |
| **FAIL** | 0 | 0.0% |
| ERROR | 0 | 0.0% |
| SKIP_OP (op not implemented) | 0 | 0.0% |
| SKIP_DEPRECATED (DES / 3DES / DSA out of scope) | 5 | 4.9% |
| SKIP_PRECONDITION (needs prior-transcript state) | 2 | 2.0% |
| SKIP_POLICY_VARIANT (mutually-exclusive policy) | 3 | 2.9% |
| SKIP_PARSE (XML malformed) | 0 | 0.0% |
| **Total** | **102** | 100.0% |


Of the 92 tests that exercise only implemented + non-deprecated ops:

  - **92 pass (100%)**

  - 0 fail

  - 0 errored


5 test(s) skipped per the deprecated-mechanism policy 
(see `kmip/DEPRECATED.md`):

  - `BL-M-12-30.xml` — DSA — deprecated (NIST SP 800-186 §5.4)

  - `BL-M-13-30.xml` — DSA — deprecated (NIST SP 800-186 §5.4)

  - `SKFF-M-12-30.xml` — 3DES — deprecated (NIST SP 800-131A r2 §1.2.1)

  - `SKFF-M-4-30.xml` — 3DES — deprecated (NIST SP 800-131A r2 §1.2.1)

  - `SKFF-M-8-30.xml` — 3DES — deprecated (NIST SP 800-131A r2 §1.2.1)



2 test(s) skipped — depend on inter-transcript state 
our hermetic per-test harness wipes:

  - `SASED-M-3-30.xml` — Locate-by-GroupLink of SecretData Registered in SASED-M-2; hermetic per-test isolation wipes it

  - `TL-M-3-30.xml` — Locate-by-ApplicationSpecificInformation of object Created in TL-M-2; hermetic per-test isolation wipes it



3 test(s) skipped — pin a mutually-exclusive policy 
choice our server does not select:

  - `CS-RNG-O-2-30.xml` — RNGSeed policy variant: partial-consume (DataLength=16). We implement full-consume per CS-RNG-O-1

  - `CS-RNG-O-3-30.xml` — RNGSeed policy variant: ignore-seed (DataLength=0). We implement full-consume per CS-RNG-O-1

  - `CS-RNG-O-4-30.xml` — RNGSeed policy variant: deny (PermissionDenied). We implement full-consume per CS-RNG-O-1



## Per-test breakdown


| Test | Status | Detail |
|---|---|---|
| `AKLC-M-1-30.xml` | PASS |  |
| `AKLC-M-2-30.xml` | PASS |  |
| `AKLC-M-3-30.xml` | PASS |  |
| `AKLC-O-1-30.xml` | PASS |  |
| `AX-M-1-30.xml` | PASS |  |
| `AX-M-2-30.xml` | PASS |  |
| `BL-M-1-30.xml` | PASS |  |
| `BL-M-10-30.xml` | PASS |  |
| `BL-M-11-30.xml` | PASS |  |
| `BL-M-14-30.xml` | PASS |  |
| `BL-M-15-30.xml` | PASS |  |
| `BL-M-16-30.xml` | PASS |  |
| `BL-M-17-30.xml` | PASS |  |
| `BL-M-18-30.xml` | PASS |  |
| `BL-M-19-30.xml` | PASS |  |
| `BL-M-2-30.xml` | PASS |  |
| `BL-M-20-30.xml` | PASS |  |
| `BL-M-21-30.xml` | PASS |  |
| `BL-M-3-30.xml` | PASS |  |
| `BL-M-4-30.xml` | PASS |  |
| `BL-M-5-30.xml` | PASS |  |
| `BL-M-6-30.xml` | PASS |  |
| `BL-M-7-30.xml` | PASS |  |
| `BL-M-8-30.xml` | PASS |  |
| `BL-M-9-30.xml` | PASS |  |
| `CS-AC-M-1-30.xml` | PASS |  |
| `CS-AC-M-2-30.xml` | PASS |  |
| `CS-AC-M-3-30.xml` | PASS |  |
| `CS-AC-M-4-30.xml` | PASS |  |
| `CS-AC-M-5-30.xml` | PASS |  |
| `CS-AC-M-6-30.xml` | PASS |  |
| `CS-AC-M-7-30.xml` | PASS |  |
| `CS-AC-M-8-30.xml` | PASS |  |
| `CS-AC-M-OAEP-1-30.xml` | PASS |  |
| `CS-AC-M-OAEP-10-30.xml` | PASS |  |
| `CS-AC-M-OAEP-2-30.xml` | PASS |  |
| `CS-AC-M-OAEP-3-30.xml` | PASS |  |
| `CS-AC-M-OAEP-4-30.xml` | PASS |  |
| `CS-AC-M-OAEP-5-30.xml` | PASS |  |
| `CS-AC-M-OAEP-6-30.xml` | PASS |  |
| `CS-AC-M-OAEP-7-30.xml` | PASS |  |
| `CS-AC-M-OAEP-8-30.xml` | PASS |  |
| `CS-AC-M-OAEP-9-30.xml` | PASS |  |
| `CS-BC-M-1-30.xml` | PASS |  |
| `CS-BC-M-10-30.xml` | PASS |  |
| `CS-BC-M-11-30.xml` | PASS |  |
| `CS-BC-M-12-30.xml` | PASS |  |
| `CS-BC-M-13-30.xml` | PASS |  |
| `CS-BC-M-14-30.xml` | PASS |  |
| `CS-BC-M-2-30.xml` | PASS |  |
| `CS-BC-M-3-30.xml` | PASS |  |
| `CS-BC-M-4-30.xml` | PASS |  |
| `CS-BC-M-5-30.xml` | PASS |  |
| `CS-BC-M-6-30.xml` | PASS |  |
| `CS-BC-M-7-30.xml` | PASS |  |
| `CS-BC-M-8-30.xml` | PASS |  |
| `CS-BC-M-9-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20-1-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20-2-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20-3-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20-4-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20POLY1305-1-30.xml` | PASS |  |
| `CS-BC-M-GCM-1-30.xml` | PASS |  |
| `CS-BC-M-GCM-2-30.xml` | PASS |  |
| `CS-BC-M-GCM-3-30.xml` | PASS |  |
| `CS-RNG-M-1-30.xml` | PASS |  |
| `CS-RNG-O-1-30.xml` | PASS |  |
| `MSGENC-HTTPS-M-1-30.xml` | PASS |  |
| `MSGENC-JSON-M-1-30.xml` | PASS |  |
| `MSGENC-XML-M-1-30.xml` | PASS |  |
| `OMOS-M-1-30.xml` | PASS |  |
| `OMOS-O-1-30.xml` | PASS |  |
| `PKCS11-M-1-30.xml` | PASS |  |
| `QS-M-1-30.xml` | PASS |  |
| `QS-M-2-30.xml` | PASS |  |
| `SASED-M-1-30.xml` | PASS |  |
| `SASED-M-2-30.xml` | PASS |  |
| `SKFF-M-1-30.xml` | PASS |  |
| `SKFF-M-10-30.xml` | PASS |  |
| `SKFF-M-11-30.xml` | PASS |  |
| `SKFF-M-2-30.xml` | PASS |  |
| `SKFF-M-3-30.xml` | PASS |  |
| `SKFF-M-5-30.xml` | PASS |  |
| `SKFF-M-6-30.xml` | PASS |  |
| `SKFF-M-7-30.xml` | PASS |  |
| `SKFF-M-9-30.xml` | PASS |  |
| `SKLC-M-1-30.xml` | PASS |  |
| `SKLC-M-2-30.xml` | PASS |  |
| `SKLC-M-3-30.xml` | PASS |  |
| `SKLC-O-1-30.xml` | PASS |  |
| `TL-M-1-30.xml` | PASS |  |
| `TL-M-2-30.xml` | PASS |  |
| `BL-M-12-30.xml` | SKIP_DEPRECATED | DSA — deprecated (NIST SP 800-186 §5.4) |
| `BL-M-13-30.xml` | SKIP_DEPRECATED | DSA — deprecated (NIST SP 800-186 §5.4) |
| `SKFF-M-12-30.xml` | SKIP_DEPRECATED | 3DES — deprecated (NIST SP 800-131A r2 §1.2.1) |
| `SKFF-M-4-30.xml` | SKIP_DEPRECATED | 3DES — deprecated (NIST SP 800-131A r2 §1.2.1) |
| `SKFF-M-8-30.xml` | SKIP_DEPRECATED | 3DES — deprecated (NIST SP 800-131A r2 §1.2.1) |
| `CS-RNG-O-2-30.xml` | SKIP_POLICY_VARIANT | RNGSeed policy variant: partial-consume (DataLength=16). We implement full-consume per CS-RNG-O-1 |
| `CS-RNG-O-3-30.xml` | SKIP_POLICY_VARIANT | RNGSeed policy variant: ignore-seed (DataLength=0). We implement full-consume per CS-RNG-O-1 |
| `CS-RNG-O-4-30.xml` | SKIP_POLICY_VARIANT | RNGSeed policy variant: deny (PermissionDenied). We implement full-consume per CS-RNG-O-1 |
| `SASED-M-3-30.xml` | SKIP_PRECONDITION | Locate-by-GroupLink of SecretData Registered in SASED-M-2; hermetic per-test isolation wipes it |
| `TL-M-3-30.xml` | SKIP_PRECONDITION | Locate-by-ApplicationSpecificInformation of object Created in TL-M-2; hermetic per-test isolation wipes it |
