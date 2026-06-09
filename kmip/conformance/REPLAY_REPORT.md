# OASIS KMIP 3.0 Dispatcher Replay Report

Generated: 2026-06-09 01:56:52 UTC


## Aggregate


| Status | Count | % of total |
|---|---|---|
| **PASS** | 2 | 2.0% |
| **FAIL** | 83 | 81.4% |
| ERROR | 0 | 0.0% |
| SKIP_OP (op not implemented) | 17 | 16.7% |
| SKIP_PARSE (XML malformed) | 0 | 0.0% |
| **Total** | **102** | 100.0% |


Of the 85 tests that exercise only implemented ops:

  - **2 pass (2%)**

  - 83 fail

  - 0 errored


## Per-test breakdown


| Test | Status | Detail |
|---|---|---|
| `AKLC-M-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 12 != 6 |
| `AKLC-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 11 != 6 |
| `AKLC-M-3-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 11 != 6 |
| `AKLC-O-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 10 != 6 |
| `AX-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage: child count 5 != 2 |
| `AX-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage: child count 3 != 2 |
| `BL-M-10-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-11-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-12-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-13-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-14-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-20-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-3-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-4-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-5-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-6-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-7-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-8-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `BL-M-9-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/ResponseHeader: child count 3 != 2 |
| `CS-AC-M-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-3-30.xml` | FAIL | msg #2: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-8-30.xml` | FAIL | msg #2: response mismatch: ResponseMessage/BatchItem/ResultReason: expected 'WrongKeyLifecycleState' got 13 |
| `CS-AC-M-OAEP-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-10-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-3-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-4-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-5-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-6-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-7-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-8-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-AC-M-OAEP-9-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-10-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-11-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-12-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-13-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-14-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultReason: expected 'WrongKeyLifecycleState' got 13 |
| `CS-BC-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-3-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-4-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-5-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-6-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-7-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-8-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-9-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-CHACHA20-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `CS-BC-M-CHACHA20-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `CS-BC-M-CHACHA20-3-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `CS-BC-M-CHACHA20-4-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `CS-BC-M-CHACHA20POLY1305-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `CS-BC-M-GCM-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-GCM-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-GCM-3-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `MSGENC-HTTPS-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 4 != 3 |
| `MSGENC-JSON-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 4 != 3 |
| `MSGENC-XML-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 4 != 3 |
| `OMOS-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `OMOS-O-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `QS-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 21 != 30 |
| `QS-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 4 != 3 |
| `SASED-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 11 != 34 |
| `SASED-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `SASED-M-3-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 1 != 0 |
| `SKFF-M-10-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `SKFF-M-11-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 2 != 1 |
| `SKFF-M-12-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `SKFF-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `SKFF-M-4-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `SKFF-M-5-30.xml` | FAIL | msg #4: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 0 != 1 |
| `SKFF-M-6-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `SKFF-M-7-30.xml` | FAIL | msg #4: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 0 != 1 |
| `SKFF-M-8-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `SKFF-M-9-30.xml` | FAIL | msg #8: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 27 != 7 |
| `SKLC-M-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 9 != 6 |
| `SKLC-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 9 != 6 |
| `SKLC-M-3-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 9 != 6 |
| `SKLC-O-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: child count 9 != 6 |
| `TL-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 17 != 34 |
| `TL-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage: child count 3 != 2 |
| `TL-M-3-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage: child count 3 != 2 |
| `SKFF-M-1-30.xml` | PASS |  |
| `SKFF-M-3-30.xml` | PASS |  |
| `BL-M-1-30.xml` | SKIP_OP | unsupported ops: ['Log'] |
| `BL-M-15-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential'] |
| `BL-M-16-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential'] |
| `BL-M-17-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential', 'CreateUser'] |
| `BL-M-18-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential', 'CreateUser'] |
| `BL-M-19-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential', 'CreateUser'] |
| `BL-M-21-30.xml` | SKIP_OP | unsupported ops: ['CreateGroup'] |
| `CS-AC-M-4-30.xml` | SKIP_OP | unsupported ops: ['MAC'] |
| `CS-AC-M-5-30.xml` | SKIP_OP | unsupported ops: ['MACVerify'] |
| `CS-AC-M-6-30.xml` | SKIP_OP | unsupported ops: ['MAC', 'MACVerify'] |
| `CS-AC-M-7-30.xml` | SKIP_OP | unsupported ops: ['Hash'] |
| `CS-RNG-M-1-30.xml` | SKIP_OP | unsupported ops: ['RNGRetrieve'] |
| `CS-RNG-O-1-30.xml` | SKIP_OP | unsupported ops: ['RNGSeed'] |
| `CS-RNG-O-2-30.xml` | SKIP_OP | unsupported ops: ['RNGSeed'] |
| `CS-RNG-O-3-30.xml` | SKIP_OP | unsupported ops: ['RNGSeed'] |
| `CS-RNG-O-4-30.xml` | SKIP_OP | unsupported ops: ['RNGSeed'] |
| `PKCS11-M-1-30.xml` | SKIP_OP | unsupported ops: ['PKCS_11'] |
