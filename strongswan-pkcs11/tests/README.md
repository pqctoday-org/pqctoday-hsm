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
softhsmv3 token) → `public_key_t.verify()` (a real `C_Verify`) — for all 7
signature key types this connector supports: ML-DSA-44/65/87,
SLH-DSA-SHA2-128s/192s/256s, and Ed448 (added 2026-09-02 — `CKK_EC_EDWARDS`/
`CKM_EDDSA` were previously unwired here at all). Each case also asserts a
corrupted signature is rejected (negative control).

This does **not** attempt a full two-peer IKEv2 network handshake — that
would need either a Linux host with kernel IPsec (charon's `kernel-netlink`
plugin) or the browser/WASM path's custom Tier-A stub kernel
(`strongswan-wasm-shims/kernel_wasm.c`), neither available in a plain macOS
dev build. What it *does* prove for real is the exact thing an IKEv2 AUTH
exchange actually calls: the connector's private_key/public_key sign/verify
implementation against the genuine PKCS#11 mechanism, for every registered
key type, with a negative control.

## What's here

| File | Role |
|---|---|
| `test_pkcs11_conn.c` | The real connector test (see its own header for the exact call path). |
| `keygen_pkcs11_key.c` | Dependency-free PKCS#11 C-API helper that provisions a token-persistent ML-DSA/SLH-DSA/Ed448 keypair with a chosen `CKA_ID`, so `test_pkcs11_conn` can find it via `BUILD_PKCS11_KEYID`. Needs nothing but `dlopen`/`dlsym` — no strongSwan or engine headers. |

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
```

## Run

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
#   01 128s / 02 256s / 03 192s / 04 mldsa44 / 05 mldsa65 / 06 mldsa87 / 07 ed448
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

## Last confirmed run (2026-09-02)

All 7 PASS, real `C_Sign`/`C_Verify`, signature lengths byte-exact to
FIPS 204/205 and RFC 8032 §5.2.6 (Ed448: 57-byte key -> 114-byte R||S
signature), negative control rejecting a corrupted signature in every case:

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
[Ed448]      C_Sign OK: signature length = 114 bytes ... PASS

7 test(s), 0 failure(s)
```

**Ed448 independent-oracle cross-check**: the connector's own `C_Sign`/
`C_Verify` round-trip only proves internal self-consistency (a wrong but
symmetric `CK_EDDSA_PARAMS`/instance choice — e.g. accidentally signing under
Ed448ph — would still pass it), so the genuine signature from the run above
was additionally verified against OpenSSL 3.6's own, independently-invoked
Ed448 verify — a real SubjectPublicKeyInfo built from the same raw 57-byte
`CKA_EC_POINT` and the 114-byte signature from the same `C_Sign` call:

```
$ openssl pkey -pubin -inform DER -in ed448_pub.der -text -noout
ED448 Public-Key:
pub:
    11:a1:9e:5e:d5:b0:6c:32:...

$ openssl pkeyutl -verify -pubin -inkey ed448_pub.der -keyform DER \
    -rawin -in ed448_msg.bin -sigfile ed448_sig.bin
Signature Verified Successfully

$ openssl pkeyutl -verify -pubin -inkey ed448_pub.der -keyform DER \
    -rawin -in ed448_msg.bin -sigfile ed448_sig_bad.bin   # 1 byte flipped
...ED448 digest_verify:...
Signature Verification Failure
```

Both outcomes match the connector's own verdicts (genuine signature accepted,
corrupted signature rejected) — the token's `CKM_EDDSA` dispatch is producing
real, standards-correct RFC 8032 Ed448 signatures, not merely internally
self-consistent ones.

## Known gaps, not covered here

- **ML-KEM key exchange** (`pkcs11_kem.c`, all 3 sizes) uses a different
  strongSwan API (`key_exchange_t`, not `private_key_t`) and is not exercised
  by this harness — it has real evidence via the WASM path's browser-verified
  handshake (`../../strongswan-wasm-shims/STATUS.md`) but no standalone
  native test yet.
- **Ed25519 / Ed25519ctx authentication**: only Ed448 is wired into this
  connector (`pkcs11_private_key.c`/`pkcs11_public_key.c`'s `KEY_ED448`/
  `SIGN_ED448` handling, `pkcs11_plugin.c`'s `f_pqc` registrations). Ed25519
  is a separate, not-yet-implemented scope — this engine's own
  `src/lib/crypto/OSSLEDDSA.cpp` already distinguishes Ed25519/Ed25519ctx/
  Ed25519ph via `CK_EDDSA_PARAMS`, so wiring it in would follow the same
  `CKK_EC_EDWARDS` pattern Ed448 uses here, just keyed off the 32-byte
  `CKA_EC_POINT`/`CKA_VALUE` length instead of 57.
