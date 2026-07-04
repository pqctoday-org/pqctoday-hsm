# strongswan-pkcs11 — PQC-enabled strongSwan PKCS#11 plugin

A drop-in replacement for strongSwan's stock `pkcs11` plugin, extended so that
IKEv2 can perform **ML-KEM key exchange** and **ML-DSA authentication** through
a PKCS#11 v3.2 token — i.e. against the softhsmv3 module. Private keys stay
inside the token; charon calls `C_EncapsulateKey` / `C_DecapsulateKey` and
`C_Sign` on the module.

## What it is

These are strongSwan plugin sources (the `libstrongswan-pkcs11.la` plugin, per
`Makefile.am`) — they compile *inside* the strongSwan tree, not standalone. Key
additions over upstream:

| File | Role |
|---|---|
| `pkcs11_kem.c/.h` | `key_exchange_t` backed by ML-KEM `C_EncapsulateKey`/`C_DecapsulateKey` (IKEv2 KE payload) |
| `pkcs11_private_key.c` / `pkcs11_public_key.c` | ML-DSA sign/verify + SPKI handling via the token |
| `pkcs11_library.c`, `pkcs11_manager.c` | Module load + slot/token management |
| `pkcs11_creds.c`, `pkcs11_hasher.c`, `pkcs11_rng.c`, `pkcs11_dh.c` | Credentials, hashing, RNG, classical DH |
| `test_ss.c` | Minimal standalone smoke of the key-type constants |

## Build

Layer these sources into a strongSwan 6.0.5/6.0.6 tree (the ML-DSA core patch is
`../strongswan-6.0.5-pqc.patch` / `../strongswan-6.0.6-pqc.patch`) and configure
with the plugin enabled:

```bash
./configure --enable-pkcs11    # plus your usual strongSwan options
make && make install
```

For the WASM path see `../strongswan-wasm-shims/` (the actively-maintained shim
tree) and `../scripts/build-strongswan-wasm.sh`.

## Test against softhsmv3

1. Build/install softhsmv3 and initialize a token with an ML-DSA-65 key
   (see `../docs/softhsmv3opsguide.md` §4).
2. Point the plugin at the module in `strongswan.conf`:

   ```ini
   charon { plugins { pkcs11 { modules {
     softhsmv3 { path = /usr/local/lib/softhsm/libsofthsmv3.so }
   } } } }
   ```

3. Configure an IKEv2 connection that negotiates a PQC key-exchange group
   (ML-KEM-768) and `auth = pubkey` referencing the token cert
   (`pkcs11:token=...;id=...;type=cert`), then initiate — the KE and the
   authentication signature both run through the token. See
   `../docs/softhsmv3opsguide.md` §4 for the full `swanctl.conf` example.
