# strongswan-pkcs11 — PQC-enabled strongSwan PKCS#11 plugin

A drop-in replacement for strongSwan's stock `pkcs11` plugin, extended so that
IKEv2 can perform **ML-KEM key exchange** (all three sizes: ML-KEM-512/768/1024)
and **ML-DSA (44/65/87), SLH-DSA-SHA2 (128s/192s/256s), Ed448, or Ed25519
authentication** through a PKCS#11 v3.2 token — i.e. against the softhsmv3
module. Private keys stay inside the token; charon calls `C_EncapsulateKey` /
`C_DecapsulateKey` and `C_Sign` on the module.

## What it is

These are strongSwan plugin sources (the `libstrongswan-pkcs11.la` plugin, per
`Makefile.am`) — they compile *inside* the strongSwan tree, not standalone. Key
additions over upstream:

| File | Role |
|---|---|
| `pkcs11_kem.c/.h` | `key_exchange_t` backed by ML-KEM `C_EncapsulateKey`/`C_DecapsulateKey` (IKEv2 KE payload), all three sizes (512/768/1024) |
| `pkcs11_private_key.c` / `pkcs11_public_key.c` | ML-DSA (44/65/87), SLH-DSA-SHA2 (128s/192s/256s), Ed448, and Ed25519 sign/verify + SPKI handling via the token |
| `pkcs11_library.c`, `pkcs11_manager.c` | Module load + slot/token management |
| `pkcs11_creds.c`, `pkcs11_hasher.c`, `pkcs11_rng.c`, `pkcs11_dh.c` | Credentials, hashing, RNG, classical DH |
| `test_ss.c` | Minimal standalone smoke of the key-type constants |

## Build

**Confirmed baseline: strongSwan 6.0.7.** `../strongswan-pkcs11.patch` (which
overlays this directory's sources onto `src/libstrongswan/plugins/pkcs11/`) is
generated against — and requires — 6.0.7 specifically: 6.0.7 renamed
`OID_SECT*R1` to `OID_SECP*R1` inside this same plugin directory, and this
patch's `pkcs11_public_key.c` uses the new names (see that patch file's own
header for the full rationale, and `regen-strongswan-pkcs11-patch.sh` to
regenerate it if the pinned version bumps again). The top-level
`../strongswan-6.0.5-pqc.patch`/`../strongswan-6.0.6-pqc.patch` files target
older baselines and are not the patch set actually build-tested end to end —
`strongswan-pkcs11/tests/README.md` documents the real, verified recipe (base
6.0.7 + `../strongswan-pqc.patch` + `../strongswan-pqc-supplement.patch` +
`../strongswan-pqc-slhdsa.patch` + `../strongswan-pkcs11.patch`, applied with
`patch -p1` against a pristine 6.0.7 tree) and is the one to follow; that exact
sequence was used to build a real `libstrongswan-pkcs11.so` and pass a live
ML-DSA-44/65/87 + SLH-DSA-SHA2-128s/192s/256s + Ed448 + Ed25519 sign/verify
test (2026-09-01/02, extended with Ed25519 2026-09-02).

Once patched, configure with the plugin enabled:

```bash
./configure --enable-pkcs11    # plus your usual strongSwan options
make && make install
```

For the WASM path see `../strongswan-wasm-shims/` (the actively-maintained shim
tree) and `../scripts/build-strongswan-wasm.sh`.

## Automated connector test (no swanctl/network needed)

`tests/test_pkcs11_conn.c` links directly against a real `libstrongswan.so` +
this plugin and drives the actual credential-layer sign/verify path IKEv2
peer auth uses, for all 8 signature key types this connector supports
(ML-DSA-44/65/87, SLH-DSA-SHA2-128s/192s/256s, Ed448, Ed25519) — see
`tests/README.md` for the full build/run steps and the last confirmed
pass/fail table.

## Test against softhsmv3 (full IKEv2 handshake)

1. Build/install softhsmv3 and initialize a token with an ML-DSA-65 key
   (see `../docs/softhsmv3opsguide.md` §4).
2. Point the plugin at the module in `strongswan.conf`:

   ```ini
   charon { plugins { pkcs11 { modules {
     softhsmv3 { path = /usr/local/lib/softhsm/libsofthsmv3.so }
   } } } }
   ```

3. Configure an IKEv2 connection that negotiates a PQC key-exchange group
   (ML-KEM-512, ML-KEM-768, or ML-KEM-1024 — all three are wired through
   `pkcs11_kem_create()`/`PLUGIN_PROVIDE(KE, ...)`) and `auth = pubkey`
   referencing the token cert (`pkcs11:token=...;id=...;type=cert`), then
   initiate — the KE and the authentication signature both run through the
   token. See `../docs/softhsmv3opsguide.md` §4 for the full
   `swanctl.conf` example.

## Hybrid key exchange (RFC 9370)

This plugin's `pkcs11_kem_t` slots into strongSwan's own unmodified RFC 9370
multi-key-exchange machinery (IKE_INTERMEDIATE, ADDKE1-7 transform types) —
no wrapper-level hybrid logic of our own, just a `key_exchange_t`
implementation strongSwan's real proposal parser can select for any KE
round, including the additional ones. A proposal string that pairs an
ML-KEM group as the initial IKE_SA_INIT key exchange with a classical ECP
group as Additional Key Exchange 1 looks like:

```
aes256-sha256-mlkem768-ke1_ecp256
```

Any of the three registered ML-KEM sizes works as the primary KE method,
independently of which one (if any) is layered in via `ke1_`:

```
aes256-sha256-mlkem512-ke1_ecp256
aes256-sha256-mlkem768-ke1_ecp256
aes256-sha256-mlkem1024-ke1_ecp256
```

`strongswan-wasm-shims/wasm_backend.c` demonstrates this proposal shape
end-to-end (`proposal_ike_hybrid`) as part of its hybrid proposal mode; see
`../docs/softhsmv3opsguide.md` §4 for the equivalent `swanctl.conf`
`proposals =` line.
