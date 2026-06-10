# OASIS KMIP 3.0 Dispatcher Replay Report

Generated: 2026-06-10 00:18:23 UTC


## Aggregate


| Status | Count | % of total |
|---|---|---|
| **PASS** | 49 | 48.0% |
| **FAIL** | 53 | 52.0% |
| ERROR | 0 | 0.0% |
| SKIP_OP (op not implemented) | 0 | 0.0% |
| SKIP_PARSE (XML malformed) | 0 | 0.0% |
| **Total** | **102** | 100.0% |


Of the 102 tests that exercise only implemented ops:

  - **49 pass (48%)**

  - 53 fail

  - 0 errored


## Per-test breakdown


| Test | Status | Detail |
|---|---|---|
| `AKLC-M-3-30.xml` | FAIL | msg #4: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `AKLC-O-1-30.xml` | FAIL | msg #3: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: missing expected attribute 'AlwaysSensitive' (§4.1.1 item 2 |
| `AX-M-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage: child count 3 != 2 |
| `AX-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/SymmetricKey/KeyBlock: child count 5 != 4 |
| `BL-M-10-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `BL-M-12-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `BL-M-13-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `BL-M-14-30.xml` | FAIL | msg #5: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: missing expected attribute 'AlwaysSensitive' (§4.1.1 item 2 |
| `BL-M-4-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `BL-M-5-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `BL-M-7-30.xml` | FAIL | msg #2: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `BL-M-8-30.xml` | FAIL | msg #2: response mismatch: ResponseMessage/BatchItem/ResultReason: expected 'NonUniqueNameAttribute' got 7 |
| `CS-AC-M-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-AC-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-AC-M-3-30.xml` | FAIL | msg #2: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-AC-M-4-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-AC-M-5-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-AC-M-6-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-AC-M-8-30.xml` | FAIL | msg #2: response mismatch: ResponseMessage/BatchItem/ResultReason: expected 'WrongKeyLifecycleState' got 1 |
| `CS-BC-M-11-30.xml` | FAIL | msg #3: response mismatch: ResponseMessage/BatchItem/ResultReason: expected 'InvalidMessage' got 45 |
| `CS-BC-M-12-30.xml` | FAIL | msg #2: response mismatch: ResponseMessage/BatchItem/ResultReason: expected 'InvalidMessage' got 45 |
| `CS-BC-M-13-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-BC-M-14-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `CS-BC-M-7-30.xml` | FAIL | msg #2: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `CS-BC-M-8-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Data: expected 'd9bcce11b0b437b90239552df3a360c90efb6bfed93b4d1ea2123ba |
| `CS-BC-M-9-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-BC-M-GCM-1-30.xml` | FAIL | msg #6: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-BC-M-GCM-2-30.xml` | FAIL | msg #16: response mismatch: ResponseMessage/BatchItem/ResponsePayload/AuthenticatedEncryptionTag: expected '5bc94fbc3221a5db94fae95ae7121a47 |
| `CS-BC-M-GCM-3-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `CS-RNG-O-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload/DataLength: expected '16' got 32 |
| `CS-RNG-O-3-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload/DataLength: expected '0' got 32 |
| `CS-RNG-O-4-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `MSGENC-HTTPS-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `MSGENC-JSON-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `MSGENC-XML-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `OMOS-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `OMOS-O-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `PKCS11-M-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 4 != 3 |
| `QS-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `SASED-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `SASED-M-3-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 1 != 0 |
| `SKFF-M-10-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `SKFF-M-11-30.xml` | FAIL | msg #8: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 27 != 10 |
| `SKFF-M-12-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `SKFF-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `SKFF-M-4-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `SKFF-M-6-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `SKFF-M-8-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'Success' got 1 |
| `SKFF-M-9-30.xml` | FAIL | msg #8: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 27 != 10 |
| `SKLC-M-3-30.xml` | FAIL | msg #4: response mismatch: ResponseMessage/BatchItem/ResultStatus: expected 'OperationFailed' got 0 |
| `SKLC-O-1-30.xml` | FAIL | msg #3: response mismatch: ResponseMessage/BatchItem/ResponsePayload/Attributes: missing expected attribute 'AlwaysSensitive' (§4.1.1 item 2 |
| `TL-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/Query ResponsePayload: non-list child count 2 != 3 |
| `TL-M-3-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 1 != 0 |
| `AKLC-M-1-30.xml` | PASS |  |
| `AKLC-M-2-30.xml` | PASS |  |
| `BL-M-1-30.xml` | PASS |  |
| `BL-M-11-30.xml` | PASS |  |
| `BL-M-15-30.xml` | PASS |  |
| `BL-M-16-30.xml` | PASS |  |
| `BL-M-17-30.xml` | PASS |  |
| `BL-M-18-30.xml` | PASS |  |
| `BL-M-19-30.xml` | PASS |  |
| `BL-M-2-30.xml` | PASS |  |
| `BL-M-20-30.xml` | PASS |  |
| `BL-M-21-30.xml` | PASS |  |
| `BL-M-3-30.xml` | PASS |  |
| `BL-M-6-30.xml` | PASS |  |
| `BL-M-9-30.xml` | PASS |  |
| `CS-AC-M-7-30.xml` | PASS |  |
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
| `CS-BC-M-2-30.xml` | PASS |  |
| `CS-BC-M-3-30.xml` | PASS |  |
| `CS-BC-M-4-30.xml` | PASS |  |
| `CS-BC-M-5-30.xml` | PASS |  |
| `CS-BC-M-6-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20-1-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20-2-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20-3-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20-4-30.xml` | PASS |  |
| `CS-BC-M-CHACHA20POLY1305-1-30.xml` | PASS |  |
| `CS-RNG-M-1-30.xml` | PASS |  |
| `CS-RNG-O-1-30.xml` | PASS |  |
| `QS-M-1-30.xml` | PASS |  |
| `SASED-M-1-30.xml` | PASS |  |
| `SKFF-M-1-30.xml` | PASS |  |
| `SKFF-M-3-30.xml` | PASS |  |
| `SKFF-M-5-30.xml` | PASS |  |
| `SKFF-M-7-30.xml` | PASS |  |
| `SKLC-M-1-30.xml` | PASS |  |
| `SKLC-M-2-30.xml` | PASS |  |
| `TL-M-2-30.xml` | PASS |  |
