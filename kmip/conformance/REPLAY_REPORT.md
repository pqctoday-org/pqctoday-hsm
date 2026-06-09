# OASIS KMIP 3.0 Dispatcher Replay Report

Generated: 2026-06-09 00:37:25 UTC


## Aggregate


| Status | Count | % of total |
|---|---|---|
| **PASS** | 2 | 2.0% |
| **FAIL** | 17 | 16.7% |
| ERROR | 0 | 0.0% |
| SKIP_OP (op not implemented) | 83 | 81.4% |
| SKIP_PARSE (XML malformed) | 0 | 0.0% |
| **Total** | **102** | 100.0% |


Of the 19 tests that exercise only implemented ops:

  - **2 pass (11%)**

  - 17 fail

  - 0 errored


## Per-test breakdown


| Test | Status | Detail |
|---|---|---|
| `CS-BC-M-1-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-2-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `CS-BC-M-3-30.xml` | FAIL | msg #1: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `MSGENC-HTTPS-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 4 != 3 |
| `MSGENC-JSON-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 4 != 3 |
| `MSGENC-XML-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 4 != 3 |
| `QS-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 21 != 12 |
| `QS-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 4 != 3 |
| `SASED-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 11 != 16 |
| `SKFF-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `SKFF-M-4-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `SKFF-M-5-30.xml` | FAIL | msg #4: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 0 != 1 |
| `SKFF-M-6-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem: child count 3 != 4 |
| `SKFF-M-7-30.xml` | FAIL | msg #4: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 0 != 1 |
| `SKFF-M-8-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/tag 'Operation' != 'Result Status' |
| `TL-M-1-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage/BatchItem/ResponsePayload: child count 17 != 16 |
| `TL-M-2-30.xml` | FAIL | msg #0: response mismatch: ResponseMessage: child count 3 != 2 |
| `SKFF-M-1-30.xml` | PASS |  |
| `SKFF-M-3-30.xml` | PASS |  |
| `AKLC-M-1-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes'] |
| `AKLC-M-2-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes'] |
| `AKLC-M-3-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'ModifyAttribute'] |
| `AKLC-O-1-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes'] |
| `AX-M-1-30.xml` | SKIP_OP | unsupported ops: ['AddAttribute', 'GetAttributes'] |
| `AX-M-2-30.xml` | SKIP_OP | unsupported ops: ['AddAttribute', 'GetAttributes'] |
| `BL-M-1-30.xml` | SKIP_OP | unsupported ops: ['Interop', 'Log', 'Register'] |
| `BL-M-10-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'ModifyAttribute', 'Register'] |
| `BL-M-11-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'Register'] |
| `BL-M-12-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'Register'] |
| `BL-M-13-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'Register'] |
| `BL-M-14-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'Register'] |
| `BL-M-15-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential', 'Interop'] |
| `BL-M-16-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential', 'Interop'] |
| `BL-M-17-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential', 'CreateUser', 'Interop'] |
| `BL-M-18-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential', 'CreateUser', 'Interop'] |
| `BL-M-19-30.xml` | SKIP_OP | unsupported ops: ['CreateCredential', 'CreateUser', 'Interop'] |
| `BL-M-2-30.xml` | SKIP_OP | unsupported ops: ['Check', 'GetAttributes', 'Interop', 'Register'] |
| `BL-M-20-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'Obliterate', 'Register'] |
| `BL-M-21-30.xml` | SKIP_OP | unsupported ops: ['CreateGroup', 'Interop'] |
| `BL-M-3-30.xml` | SKIP_OP | unsupported ops: ['Check', 'GetAttributes', 'Interop', 'Register'] |
| `BL-M-4-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'Register'] |
| `BL-M-5-30.xml` | SKIP_OP | unsupported ops: ['AddAttribute', 'GetAttributes', 'Interop', 'Register'] |
| `BL-M-6-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'Register'] |
| `BL-M-7-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'ModifyAttribute', 'Register'] |
| `BL-M-8-30.xml` | SKIP_OP | unsupported ops: ['AddAttribute', 'GetAttributes', 'Interop', 'Register'] |
| `BL-M-9-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'Interop', 'Register'] |
| `CS-AC-M-1-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-2-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-3-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-4-30.xml` | SKIP_OP | unsupported ops: ['MAC', 'Register'] |
| `CS-AC-M-5-30.xml` | SKIP_OP | unsupported ops: ['MACVerify', 'Register'] |
| `CS-AC-M-6-30.xml` | SKIP_OP | unsupported ops: ['MAC', 'MACVerify', 'Register'] |
| `CS-AC-M-7-30.xml` | SKIP_OP | unsupported ops: ['Hash'] |
| `CS-AC-M-8-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-1-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-10-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-2-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-3-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-4-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-5-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-6-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-7-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-8-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-AC-M-OAEP-9-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-10-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-11-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-12-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-13-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-14-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-4-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-5-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-6-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-7-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-8-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-9-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-CHACHA20-1-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-CHACHA20-2-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-CHACHA20-3-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-CHACHA20-4-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-CHACHA20POLY1305-1-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-GCM-1-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-GCM-2-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-BC-M-GCM-3-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `CS-RNG-M-1-30.xml` | SKIP_OP | unsupported ops: ['RNGRetrieve'] |
| `CS-RNG-O-1-30.xml` | SKIP_OP | unsupported ops: ['RNGSeed'] |
| `CS-RNG-O-2-30.xml` | SKIP_OP | unsupported ops: ['RNGSeed'] |
| `CS-RNG-O-3-30.xml` | SKIP_OP | unsupported ops: ['RNGSeed'] |
| `CS-RNG-O-4-30.xml` | SKIP_OP | unsupported ops: ['RNGSeed'] |
| `OMOS-M-1-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `OMOS-O-1-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `PKCS11-M-1-30.xml` | SKIP_OP | unsupported ops: ['PKCS_11'] |
| `SASED-M-2-30.xml` | SKIP_OP | unsupported ops: ['Register'] |
| `SASED-M-3-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes'] |
| `SKFF-M-10-30.xml` | SKIP_OP | unsupported ops: ['AddAttribute', 'DeleteAttribute', 'GetAttributeList', 'GetAttributes', 'ModifyAttribute'] |
| `SKFF-M-11-30.xml` | SKIP_OP | unsupported ops: ['AddAttribute', 'DeleteAttribute', 'GetAttributeList', 'GetAttributes', 'ModifyAttribute'] |
| `SKFF-M-12-30.xml` | SKIP_OP | unsupported ops: ['AddAttribute', 'DeleteAttribute', 'GetAttributeList', 'GetAttributes', 'ModifyAttribute'] |
| `SKFF-M-9-30.xml` | SKIP_OP | unsupported ops: ['AddAttribute', 'DeleteAttribute', 'GetAttributeList', 'GetAttributes', 'ModifyAttribute'] |
| `SKLC-M-1-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes'] |
| `SKLC-M-2-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes'] |
| `SKLC-M-3-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes', 'ModifyAttribute'] |
| `SKLC-O-1-30.xml` | SKIP_OP | unsupported ops: ['GetAttributes'] |
| `TL-M-3-30.xml` | SKIP_OP | unsupported ops: ['GetAttributeList', 'GetAttributes', 'ModifyAttribute'] |
