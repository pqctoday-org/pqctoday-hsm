# smoke-mldsa — P0-SEQUOIA-PQC-05 §5.4 LIVE HSM SMOKE TEST

The make-or-break integration gate for the PQC OpenPGP bridge migration. The
software spike (`../spike-pqc/`) proved the *wire format* (algorithm ID 30); this
crate proves the *HSM dispatch path*: that **softhsmv3 accepts a cryptoki-0.12
`Mechanism::MlDsa` `C_Sign`** and returns a real **3309-byte ML-DSA-65**
signature.

This is a standalone crate (own `[workspace]`) so its dep set does not touch the
bridge's `Cargo.lock`.

## What it does

1. `dlopen`s the softhsmv3 PKCS#11 module and `C_Initialize`s it.
2. Finds the slot whose token has the given label, opens an RW session, logs in.
3. Generates an ML-DSA-65 keypair (`CKM_ML_DSA_KEY_PAIR_GEN` = 0x1C,
   `CKA_PARAMETER_SET = CKP_ML_DSA_65`).
4. Calls `C_Sign` with three `CK_SIGN_ADDITIONAL_CONTEXT` param shapes in turn
   (empty-ctx / null / deterministic) and reports which softhsmv3 accepts plus
   the signature length.

## Run

```bash
# from the worktree root, after `cmake --build build`
SOFTHSM2_CONF=build/smoke-softhsm2.conf \
  build/src/bin/util/softhsm2-util --module build/src/lib/libsofthsmv3.dylib \
    --init-token --slot 0 --label test --so-pin 1234 --pin 1234

SOFTHSM2_CONF=build/smoke-softhsm2.conf \
  cargo run --manifest-path openpgp/smoke-mldsa/Cargo.toml -- \
    build/src/lib/libsofthsmv3.dylib test 1234
```

## Result (captured 2026-06-14, softhsmv3 3.0.0, cryptoki 0.12.0, OpenSSL 3.6.2)

```
[3] generated ML-DSA-65 keypair (priv handle ObjectHandle { handle: 685145 })
[4] C_Sign attempt: Mechanism::MlDsa(SignAdditionalContext::new(Preferred, Some(&[])))  -> OK, signature length = 3309 bytes
[4] C_Sign attempt: Mechanism::MlDsa(SignAdditionalContext::new(Preferred, None))       -> OK, signature length = 3309 bytes
[4] C_Sign attempt: Mechanism::MlDsa(SignAdditionalContext::new(DeterministicRequired, Some(&[]))) -> OK, signature length = 3309 bytes

=== ASSERTION ===
PASS: softhsmv3 returned a 3309-byte ML-DSA-65 signature.
```

**Verdict: GATE PASSES.** softhsmv3's `parseMLDSASignContext`
(`src/lib/SoftHSM_sign.cpp:247`) accepts both the 12-byte
`CK_SIGN_ADDITIONAL_CONTEXT` and the null-param form, so the bridge can use the
native `Mechanism::MlDsa` variant with no softhsmv3 patch and no vendor codepoint.
