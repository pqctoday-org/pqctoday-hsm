# strongswan-pkcs11 connector tests

**Added 2026-09** to close a real gap: `pkcs11_plugin.c` has registered
SLH-DSA-SHA2-{128s,192s,256s} `PRIVKEY`/`PUBKEY`/`PRIVKEY_SIGN`/`PUBKEY_VERIFY`
features since the ML-KEM-512/1024 + SLH-DSA-registration commit
(`0daa8e71`), and `pkcs11_private_key.c`/`pkcs11_public_key.c` fully wire
SLH-DSA sign/verify + SPKI handling — but nothing in this repo, automated or
manual, had ever exercised that path. The only real evidence for this
connector's PQC authentication was `../../strongswan-wasm-shims/STATUS.md`'s
"browser-verified" dual ML-DSA-65 certificate handshake, which is real but
neither automated nor SLH-DSA-covering (`wasm_backend.c`'s
`wasm_set_auth_mode()` only has modes 0=PSK and 1=ML-DSA cert).

`test_pkcs11_conn.c` closes that: it links directly against a real
`libstrongswan.so` + `libstrongswan-pkcs11.so` (built from this repo's
`strongswan-pkcs11/` sources, patched onto a pristine strongSwan tree — see
below) and drives the exact credential-layer call sequence real IKEv2 peer
authentication uses — `lib->creds->create(CRED_PRIVATE_KEY, ...,
BUILD_PKCS11_*, ...)` → `private_key_t.sign()` (a real `C_Sign` on a real
softhsmv3 token) → `public_key_t.verify()` (a real `C_Verify`) — for all 6
signature key types this connector supports: ML-DSA-44/65/87 and
SLH-DSA-SHA2-128s/192s/256s. Each case also asserts a corrupted signature is
rejected (negative control).

This does **not** attempt a full two-peer IKEv2 network handshake — that
would need either a Linux host with kernel IPsec (charon's `kernel-netlink`
plugin) or the browser/WASM path's custom Tier-A stub kernel
(`strongswan-wasm-shims/kernel_wasm.c`), neither available in a plain macOS
dev build. What it *does* prove for real is the exact thing an IKEv2 AUTH
exchange actually calls: the connector's private_key/public_key sign/verify
implementation against the genuine PKCS#11 mechanism, for every registered
key type, with a negative control.

`test_pkcs11_kem.c` (added 2026-09, same day) closes the other half of the
gap: `pkcs11_kem.c` implements ML-KEM-768 key EXCHANGE, which strongSwan
models through a completely different interface (`key_exchange_t`, not
`private_key_t`/`public_key_t`) — `test_pkcs11_conn.c` doesn't touch it at
all. Before this file, the connector's only evidence for ML-KEM-768 key
exchange was the same browser-verified WASM handshake referenced above (real,
but not automated and not runnable from the command line). This test drives
two independently-created `pkcs11_kem_t` instances (via two separate
`lib->crypto->create_ke(lib->crypto, ML_KEM_768)` calls, simulating the two
IKEv2 peers) through the real `get_public_key()`/`set_public_key()`/
`get_shared_secret()` sequence key_exchange_t's own header documents, with
real `C_GenerateKeyPair`/`C_EncapsulateKey`/`C_DecapsulateKey` against the
same softhsmv3 token — asserting both sides land on a byte-identical 32-byte
shared secret, plus a negative control (one corrupted byte in the
responder's ciphertext) that the two sides then *disagree*, proving the
exchange is using real key material and not a constant.

## What's here

| File | Role |
|---|---|
| `test_pkcs11_conn.c` | The real connector test for ML-DSA/SLH-DSA sign+verify (see its own header for the exact call path). |
| `test_pkcs11_kem.c` | The real connector test for ML-KEM-768 key exchange (see its own header for the exact call path, and the two real prerequisites — `use_dh = yes` and a pre-established token login — its own investigation turned up). |
| `keygen_pkcs11_key.c` | Dependency-free PKCS#11 C-API helper that provisions a token-persistent ML-DSA/SLH-DSA keypair with a chosen `CKA_ID`, so `test_pkcs11_conn` can find it via `BUILD_PKCS11_KEYID`. Needs nothing but `dlopen`/`dlsym` — no strongSwan or engine headers. Not needed by `test_pkcs11_kem` (it generates its own ephemeral ML-KEM keypairs), which instead reuses the same raw-PKCS11 technique inline (`raw_pkcs11_login()`) just to log the token in first. |

## Build (macOS or Linux; no Emscripten needed)

**1. Build softhsmv3 natively** (if not already built):

```bash
cmake -B build-native -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build-native --target softhsmv3 softhsm2-util
```

**2. Patch a pristine strongSwan 6.0.7 tree** (the version
`strongswan-pkcs11.patch` is generated against — see that file's own header;
`regen-strongswan-pkcs11-patch.sh` regenerates it if the pinned version
changes):

```bash
SS=/tmp/strongswan-6.0.7   # any scratch path
curl -fsSL https://download.strongswan.org/strongswan-6.0.7.tar.bz2 | tar xjC "$(dirname "$SS")"
mv "$(dirname "$SS")/strongswan-6.0.7" "$SS"
cd /path/to/pqctoday-hsm
patch -d "$SS" -p1 < strongswan-pqc.patch
patch -d "$SS" -p1 < strongswan-pqc-supplement.patch
patch -d "$SS" -p1 < strongswan-pqc-slhdsa.patch
patch -d "$SS" -p1 < strongswan-pkcs11.patch   # overlays strongswan-pkcs11/ onto src/libstrongswan/plugins/pkcs11/
```

**3. Configure + build strongSwan** (`--enable-charon` is required —
`--disable-defaults` also disables `charon` itself, not just plugins, unless
named explicitly; this is what makes `USE_LIBSTRONGSWAN`/`src/Makefile`'s
`SUBDIRS` skip straight past `libstrongswan` to `starter` with **no error**,
which is why this went unbuilt for so long — first real native build attempt
against this exact patch set surfaced it):

```bash
cd "$SS" && autoreconf -fi
ac_cv_prog_cc_c23=no ac_cv_prog_cc_c17=no CC=clang \
CPPFLAGS="-I$(brew --prefix openssl@3)/include" \
LDFLAGS="-L$(brew --prefix openssl@3)/lib" \
./configure --disable-defaults \
  --enable-charon --enable-stroke --enable-swanctl --enable-vici \
  --enable-pkcs11 --enable-openssl --enable-pem --enable-pkcs1 --enable-pkcs8 \
  --enable-x509 --enable-nonce --enable-random --enable-kdf \
  --enable-constraints --enable-revocation \
  --enable-socket-default --enable-kernel-pfroute
make
```

(`ac_cv_prog_cc_c23=no` works around a real portability trap on newer
Clang/autoconf pairings unrelated to this repo — autoconf 2.71+'s `AC_PROG_CC`
auto-upgrades to `-std=gnu23` regardless of any `-std=` already in `CC`,
which breaks strongSwan's `gperf`-generated K&R-style function bodies.)

**4. Build the tests:**

```bash
cc -O0 -g -o keygen_pkcs11_key strongswan-pkcs11/tests/keygen_pkcs11_key.c -ldl

cc -g -O0 -I"$SS/src/libstrongswan" -I"$SS" -DHAVE_CONFIG_H -include "$SS/config.h" \
  -c strongswan-pkcs11/tests/test_pkcs11_conn.c -o test_pkcs11_conn.o
cc -g -O0 test_pkcs11_conn.o -L"$SS/src/libstrongswan/.libs" -lstrongswan \
  -Wl,-rpath,"$SS/src/libstrongswan/.libs" -o test_pkcs11_conn

cc -g -O0 -I"$SS/src/libstrongswan" -I"$SS" -DHAVE_CONFIG_H -include "$SS/config.h" \
  -c strongswan-pkcs11/tests/test_pkcs11_kem.c -o test_pkcs11_kem.o
cc -g -O0 test_pkcs11_kem.o -L"$SS/src/libstrongswan/.libs" -lstrongswan \
  -Wl,-rpath,"$SS/src/libstrongswan/.libs" -ldl -o test_pkcs11_kem
```

## Run — test_pkcs11_conn (signatures)

```bash
# 1. Init a token and provision one keypair per CKA_ID the test expects
#    (01/02/03 = SLH-DSA-SHA2 128s/256s/192s, 04/05/06 = ML-DSA-44/65/87):
export SOFTHSM2_CONF=/tmp/test-softhsm2.conf
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = /tmp/test-tokens
objectstore.backend = file
EOF
mkdir -p /tmp/test-tokens
SOFTHSM=build-native/src/lib/libsofthsmv3.dylib   # .so on Linux
build-native/src/bin/util/softhsm2-util --module "$SOFTHSM" \
  --init-token --slot 0 --label IKEv2Token --so-pin 1234 --pin 1234
# note the reassigned slot ID printed above, then for each of:
#   01 128s / 02 256s / 03 192s / 04 mldsa44 / 05 mldsa65 / 06 mldsa87
./keygen_pkcs11_key "$SOFTHSM" IKEv2Token 1234 <id> <paramset> <label>

# 2. Point a settings file at the module under the *same* config-name
#    the test's argv[1] will use (pkcs11_private_key_connect's find_lib()
#    matches on this configured name, not the raw .so path):
cat > test.conf <<EOF
test_pkcs11_conn {
    plugins { pkcs11 { modules { softhsmv3 { path = $(pwd)/$SOFTHSM } } } }
}
EOF

# 3. Run (slot-id is the reassigned numeric slot from step 1's output):
DYLD_LIBRARY_PATH="$SS/src/libstrongswan/.libs:$(brew --prefix openssl@3)/lib" \
  ./test_pkcs11_conn softhsmv3 <slot-id> \
  "$SS/src/libstrongswan/plugins/pkcs11/.libs" pkcs11 test.conf
```

(On Linux, `LD_LIBRARY_PATH` instead of `DYLD_LIBRARY_PATH`.)

## Run — test_pkcs11_kem (ML-KEM-768 key exchange)

Reuses the same initialized token from above — no per-key provisioning
needed (`pkcs11_kem_create()` generates its own ephemeral ML-KEM keypairs).
Two things this test's own settings file needs that `test_pkcs11_conn`'s
doesn't, both discovered empirically while building this test (see
`test_pkcs11_kem.c`'s header comment for the full explanation of each):

- `plugins.pkcs11.use_dh = yes` — `pkcs11_plugin.c` only registers its
  `KE(ML_KEM_768)` feature (and, incidentally, the per-type ML-DSA/SLH-DSA
  `PRIVKEY`/`PUBKEY` features) under this flag; without it,
  `lib->crypto->create_ke(lib->crypto, ML_KEM_768)` returns `NULL` with zero
  diagnostic output, because `pkcs11_kem_create()` is never even called.
- `$PKCS11SPY` environment variable set to the module path —
  `pkcs11_kem.c`'s `get_v3_kem_funcs()` resolves the real
  `C_EncapsulateKey`/`C_DecapsulateKey` v3.2 entry points by `dlopen`ing
  this path directly (falling back to a fixed `/usr/local/lib/softhsm/...`
  path otherwise, which won't exist on a from-source native build).

```bash
# 1. Settings file — same module path as above, plus use_dh = yes:
cat > test_kem.conf <<EOF
test_pkcs11_kem {
    plugins {
        pkcs11 {
            use_dh = yes
            modules { softhsmv3 { path = $(pwd)/$SOFTHSM } }
        }
    }
}
EOF

# 2. Run (module/token-label/pin are for this test's own pre-login step —
#    see test_pkcs11_kem.c's header for why a real deployment always has
#    the token already logged in by this point, and why the test
#    reproduces that instead of special-casing pkcs11_kem.c):
PKCS11SPY="$(pwd)/$SOFTHSM" \
  DYLD_LIBRARY_PATH="$SS/src/libstrongswan/.libs:$(brew --prefix openssl@3)/lib" \
  ./test_pkcs11_kem "$(pwd)/$SOFTHSM" IKEv2Token 1234 \
  "$SS/src/libstrongswan/plugins/pkcs11/.libs" pkcs11 test_kem.conf
```

(On Linux, `LD_LIBRARY_PATH` instead of `DYLD_LIBRARY_PATH`.)

## Last confirmed run (2026-09-01)

`test_pkcs11_conn`: all 6 PASS, real `C_Sign`/`C_Verify`, signature lengths
byte-exact to FIPS 204/205, negative control rejecting a corrupted signature
in every case:

```
[SLH-DSA-SHA2-128s] C_Sign OK: signature length = 7856 bytes
[SLH-DSA-SHA2-128s] C_Verify OK: genuine signature verified
[SLH-DSA-SHA2-128s] negative control OK: corrupted signature correctly rejected
[SLH-DSA-SHA2-128s] PASS
[SLH-DSA-SHA2-256s] C_Sign OK: signature length = 29792 bytes ... PASS
[SLH-DSA-SHA2-192s] C_Sign OK: signature length = 16224 bytes ... PASS
[ML-DSA-44]  C_Sign OK: signature length = 2420 bytes ... PASS
[ML-DSA-65]  C_Sign OK: signature length = 3309 bytes ... PASS
[ML-DSA-87]  C_Sign OK: signature length = 4627 bytes ... PASS

6 test(s), 0 failure(s)
```

`test_pkcs11_kem`: both PASS — real `C_GenerateKeyPair`/`C_EncapsulateKey`/
`C_DecapsulateKey`, ciphertext/pubkey lengths byte-exact to FIPS 203
(pubkey 1184B, ciphertext 1088B, shared secret 32B), positive case's two
independently-computed shared secrets byte-identical, negative control's
two secrets correctly mismatched after a single corrupted ciphertext byte:

```
[ML-KEM-768 positive] initiator get_public_key() OK: 1184 bytes (expect 1184)
[ML-KEM-768 positive] responder set_public_key()+get_public_key() OK: ciphertext 1088 bytes (expect 1088)
[ML-KEM-768 positive] responder get_shared_secret() OK: 32 bytes
[ML-KEM-768 positive] initiator get_shared_secret() OK: 32 bytes
[ML-KEM-768 positive] positive case OK: initiator and responder shared secrets are byte-identical
[ML-KEM-768 positive] PASS
[ML-KEM-768 negative-control] initiator get_public_key() OK: 1184 bytes (expect 1184)
[ML-KEM-768 negative-control] responder set_public_key()+get_public_key() OK: ciphertext 1088 bytes (expect 1088)
[ML-KEM-768 negative-control] responder get_shared_secret() OK: 32 bytes
[ML-KEM-768 negative-control] negative control: flipped byte 0 of the responder's ciphertext
[ML-KEM-768 negative-control] initiator get_shared_secret() OK: 32 bytes
[ML-KEM-768 negative-control] negative control OK: corrupted ciphertext produced a MISMATCHED shared secret
[ML-KEM-768 negative-control] PASS

2 test(s), 0 failure(s)
```

Re-ran `test_pkcs11_conn` against the same freshly-initialized token
immediately afterward to confirm the KEM test's build/patch process didn't
disturb anything shared: still 6/6 PASS.

## Known gaps, not covered here

- **Ed448 / standalone EdDSA authentication**: this connector has never
  wired `CKK_EC_EDWARDS`/`CKM_EDDSA` at all (grep `strongswan-pkcs11/*.c` for
  `EC_EDWARDS`/`CKM_EDDSA`/`KEY_ED448` — zero hits outside the bundled
  `pkcs11.h` constant header). The Rust engine's new Ed448 support
  (`CHANGELOG.md` 0.27.0) has no IKEv2 auth-method mapping in this connector;
  adding one is a real protocol-integration decision (which strongSwan
  `SIGN_ED448`/`KEY_ED448` scheme to bind to which token mechanism), not a
  missing test — flagged, not implemented here.
