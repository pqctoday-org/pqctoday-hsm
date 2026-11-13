# CMP encrypted-certificate acceptance

These tests use fictional keys and a disposable test directory. They require the
OpenSSL 3.6.3 source tree with the patches from `wasm/openssl-studio/patches`
applied and a native static `libcrypto.a` built in that tree. They test the real
CMP client and server; the transaction harness serializes and decodes messages at
the transfer boundary. Run functional acceptance inside PQCToday Sandbox or the
mini-lab, without production CA credentials.

The encrypted-certificate server option is a local, default-disabled extension.
It supports the ML-KEM-768 KUR / subsequentMessage=encrCert sample profile only.
It does not modify generic CRMF proof verification. The server must have an
explicit confirmation callback; it never grants implicit confirmation for this
profile. That callback must compare the hash to the pending issued certificate
and authorize the prior certificate independently of the request.

Example compilation (set `OPENSSL_SRC` to that built source tree):

```sh
cc -g -Wall -I"$OPENSSL_SRC" -I"$OPENSSL_SRC/include" \
  -Iwasm/openssl-studio/shims tests/openssl-studio/cmp_transaction_test.c \
  "$OPENSSL_SRC/libcrypto.a" -ldl -pthread -o cmp-transaction-test
cc -g -Wall -I"$OPENSSL_SRC/include" -Iwasm/openssl-studio/shims \
  tests/openssl-studio/cmp_key_update_test.c "$OPENSSL_SRC/libcrypto.a" \
  -ldl -pthread -o cmp-key-update-test
```

Run each case in a separate temporary working directory. Transaction cases:
`valid`, `default-off`, `missing-callback`, `wrong-key`,
`wrong-old-certificate`, `wrong-hash`, `wrong-request-id`, `wrong-transaction`,
`wrong-nonce`, `missing-confirmation`, `altered-envelope`, `truncated-envelope`,
`rejected-confirmation`. The valid case also rejects replay of its confirmation.
The negative cases assert that they reached the expected stage and never
completed confirmation. Retained DER messages contain public transaction data;
never retain private keys from the test process.

Callable-shim cases: `valid`, `ir-signature`, `wrong-prior`, `same-key`,
`missing-key`, `wrong-algorithm`. Each starts by checking the unchanged ML-KEM
initial-enrollment operation. `ir-signature` also checks signing-key enrollment.
Negative key updates must not leave an output certificate.

Run the upstream CMP/CRMF suite too:

```sh
make test TESTS="test_cmp* test_crmf"
```

Rebuild the JS/WASM pair using `scripts/build-openssl-studio-wasm.sh` and validate
the same success/failure outcomes through `execute_cmp_key_update` before
publishing an engine bundle. Use freshly built or independently verified linked
archives and retain their hashes with the build receipt. Native tests alone do
not validate the browser bundle or the Hub lesson.
