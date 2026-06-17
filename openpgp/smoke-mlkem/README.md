# smoke-mlkem — P0-SEQUOIA-PQC-05 §8 LIVE HSM ML-KEM SMOKE TEST

The KEM-side companion to [`../smoke-mldsa`](../smoke-mldsa). The ML-DSA smoke
proved the HSM *signing* dispatch path; this proves the HSM *KEM* dispatch path:
that **softhsmv3 accepts a cryptoki-0.12 `Mechanism::MlKem`
`C_EncapsulateKey` / `C_DecapsulateKey` round-trip** and that the recovered
shared secret is byte-identical to the one produced by encapsulation.

This is the live proof behind the bridge's composite ML-KEM decryptor
(`../lib/src/decryptor.rs` `ml_kem_decapsulate`, plan §4) — that code does exactly
the `C_DecapsulateKey(Mechanism::MlKem, ...)` call exercised here.

Standalone crate (own `[workspace]`) so its dep set does not touch the bridge's
`Cargo.lock`.

## What it does

1. `dlopen`s the softhsmv3 PKCS#11 module and `C_Initialize`s it.
2. Finds the slot whose token has the given label, opens an RW session, logs in.
3. Generates an ML-KEM-768 keypair (`CKM_ML_KEM_KEY_PAIR_GEN`,
   `CKA_PARAMETER_SET = CKP_ML_KEM_768`).
4. `C_EncapsulateKey` to the public key → (1088-byte ciphertext, 32-byte secret).
5. `C_DecapsulateKey` the ciphertext with the private key → 32-byte secret.
6. Asserts the two shared secrets match.

## Run

```bash
# from the worktree root, after `cmake --build build` and token init (see ../smoke-mldsa)
SOFTHSM2_CONF=build/smoke-softhsm2.conf \
  cargo run --manifest-path openpgp/smoke-mlkem/Cargo.toml -- \
    build/src/lib/libsofthsmv3.dylib test 1234
```

## Result (captured 2026-06-14, softhsmv3, cryptoki 0.12.0, OpenSSL 3.6.2)

```
[3] generated ML-KEM-768 keypair (pub ObjectHandle { handle: 108953 }, priv ObjectHandle { handle: 108954 })
[4] C_EncapsulateKey OK: ciphertext = 1088 bytes, shared secret = 32 bytes
[5] C_DecapsulateKey OK: recovered shared secret = 32 bytes

=== ASSERTION ===
PASS: softhsmv3 ML-KEM-768 encap/decap round-trip recovered the same 32-byte shared secret.
      ciphertext length = 1088 bytes
```

**Verdict: GATE PASSES.** softhsmv3 accepts the standard `CKM_ML_KEM` (0x17)
mechanism with a bare (no-parameter) `Mechanism::MlKem` for both
`C_EncapsulateKey` and `C_DecapsulateKey`. ML-KEM-768 emits a 1088-byte
ciphertext and a 32-byte shared secret (FIPS 203), and the encap/decap secrets
match — so the bridge can use the native `Mechanism::MlKem` decapsulation with no
softhsmv3 patch and no vendor codepoint.
