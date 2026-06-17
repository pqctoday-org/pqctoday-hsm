# smoke-import — P0-SEQUOIA-PQC-05 composite-half PRIVATE-KEY IMPORT probe

Grounds the composite `upload_key` path. The composite custody model stores each
key's TWO component private halves as two PKCS#11 objects (plan §4/§5). sequoia
hands each PQC half to the bridge as a deterministic *seed*
(ML-DSA xi = 32 B, ML-KEM d||z = 64 B — sequoia `crypto/mpi.rs`
`SecretKeyMaterial::{MLDSA65_Ed25519,MLKEM768_X25519}`), but softhsmv3
reconstructs an ML-DSA/ML-KEM private key from `CKA_VALUE` interpreted as PKCS#8
DER (`OSSL{MLDSA,MLKEM}PrivateKey::createOSSLKey -> d2i_PKCS8_PRIV_KEY_INFO`).

So importing a composite PQC half = build the OpenSSL EVP_PKEY from the seed
(`PKey::private_key_from_seed`, OpenSSL >= 3.5) and DER-encode PKCS#8
(`private_key_to_pkcs8`), then store as `CKA_VALUE`. The traditional half
(Ed25519 / X25519) imports as a raw scalar (`CKA_VALUE`) + curve OID
(`CKA_EC_PARAMS`).

This probe proves all four shapes end-to-end against the live softhsmv3 module —
exactly the attribute templates `upload.rs::upload_composite_private` emits.

## What it does

- **[A] ML-DSA-65**: seed -> PKCS#8 DER -> `C_CreateObject` (CKK_ML_DSA) ->
  `C_Sign(Mechanism::MlDsa)` -> assert 3309-byte signature.
- **[B] ML-KEM-768**: seed -> PKCS#8 DER (priv) + raw FIPS-203 pub bytes ->
  import both -> `C_EncapsulateKey` then `C_DecapsulateKey` -> assert the two
  32-byte shared secrets match.
- **[C] Ed25519** (the MLDSA65_Ed25519 traditional half): raw scalar +
  Ed25519 OID -> `C_CreateObject` (CKK_EC_EDWARDS) -> `C_Sign(Eddsa)` -> 64 B.
- **[D] X25519** (the MLKEM768_X25519 traditional half): raw scalar + X25519 OID
  -> `C_CreateObject` (CKK_EC_MONTGOMERY) -> `C_DeriveKey(Ecdh1Derive)` -> 32 B.

## Run

```bash
OPENSSL_DIR=$(brew --prefix openssl@3) \
SOFTHSM2_CONF=build/smoke-softhsm2.conf \
  cargo run --manifest-path openpgp/smoke-import/Cargo.toml -- \
    build/src/lib/libsofthsmv3.dylib test 1234
```

## Result (captured 2026-06-14, softhsmv3, OpenSSL 3.6.2)

```
[A] ML-DSA-65 : seed 32 B -> PKCS#8 DER 4098 B -> import -> C_Sign 3309 B   PASS
[B] ML-KEM-768: seed 64 B -> PKCS#8 DER 2498 B (priv) + raw pub 1184 B ->
                import both -> encap/decap shared secrets match              PASS
[C] Ed25519   : raw 32 B -> import -> C_Sign 64 B                           PASS
[D] X25519    : raw 32 B -> import -> ECDH derive 32 B                      PASS
```

**Verdict: import recipe PROVEN.** Pins the exact `C_CreateObject` attribute
shapes the composite `upload_private` path emits, with no softhsmv3 patch.

Note: the ML-DSA-65 PKCS#8 emitted by OpenSSL 3.6.2 here is the *expanded* form
(4098 B), not the 32-byte seed-only PrivateKey encoding; both import and sign
fine in softhsmv3.
