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
softhsmv3 token) → `public_key_t.verify()` (a real `C_Verify`) — for all 8
signature key types this connector supports: ML-DSA-44/65/87,
SLH-DSA-SHA2-128s/192s/256s, Ed448 (added 2026-09-02 — `CKK_EC_EDWARDS`/
`CKM_EDDSA` were previously unwired here at all), and Ed25519 (added
2026-09-02, same day — see "Known gaps" below for the one EdDSA variant,
Ed25519ctx, this still doesn't reach through strongSwan's own credential
API). Each case also asserts a corrupted signature is rejected (negative
control).

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
| `test_pkcs11_conn.c` | The real connector test for ML-DSA/SLH-DSA/Ed448/Ed25519 sign+verify (see its own header for the exact call path). |
| `test_pkcs11_kem.c` | The real connector test for ML-KEM-768 key exchange (see its own header for the exact call path, and the two real prerequisites — `use_dh = yes` and a pre-established token login — its own investigation turned up). |
| `keygen_pkcs11_key.c` | Dependency-free PKCS#11 C-API helper that provisions a token-persistent ML-DSA/SLH-DSA/Ed448/Ed25519 keypair with a chosen `CKA_ID`, so `test_pkcs11_conn` can find it via `BUILD_PKCS11_KEYID`. Needs nothing but `dlopen`/`dlsym` — no strongSwan or engine headers. Not needed by `test_pkcs11_kem` (it generates its own ephemeral ML-KEM keypairs), which instead reuses the same raw-PKCS11 technique inline (`raw_pkcs11_login()`) just to log the token in first. |
| `test_pkcs11_ed25519ctx.c` | RAW PKCS#11 (not through strongSwan's `private_key_t`/`public_key_t`) `C_Sign`/`C_Verify` test of RFC 8032 Ed25519ctx against the same softhsmv3 module — see "Known gaps" below for why this variant is tested this way instead of through `test_pkcs11_conn.c`. |

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

# test_pkcs11_ed25519ctx is dependency-free (raw PKCS#11, dlopen/dlsym only —
# same as keygen_pkcs11_key), so it needs no strongSwan include path at all:
cc -O0 -g -o test_pkcs11_ed25519ctx strongswan-pkcs11/tests/test_pkcs11_ed25519ctx.c -ldl
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
#   01 128s / 02 256s / 03 192s / 04 mldsa44 / 05 mldsa65 / 06 mldsa87 /
#   07 ed448 / 08 ed25519
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

## Run — test_pkcs11_ed25519ctx (RFC 8032 Ed25519ctx, raw PKCS#11)

Reuses the SAME token and the Ed25519 keypair (`08`) provisioned above — no
strongSwan settings file needed, since this test never loads the strongSwan
plugin at all (see "Known gaps" below for why). Optionally pass an output
directory as the last argument to dump `pub.der`/`msg.bin`/`sig.bin`/
`ctx.txt`/`wrong_ctx.txt` for an independent `openssl pkeyutl` cross-check:

```bash
mkdir -p /tmp/ed25519ctx-out
./test_pkcs11_ed25519ctx "$(pwd)/$SOFTHSM" IKEv2Token 1234 08 /tmp/ed25519ctx-out
```

Then cross-check the genuine signature against OpenSSL's own, independently
invoked Ed25519ctx verify (see "Last confirmed run" below for the actual
transcript, including the negative-context control):

```bash
CTX="$(cat /tmp/ed25519ctx-out/ed25519ctx_ctx.txt)"
openssl pkeyutl -verify -pubin -inkey /tmp/ed25519ctx-out/ed25519ctx_pub.der -keyform DER \
  -rawin -in /tmp/ed25519ctx-out/ed25519ctx_msg.bin \
  -pkeyopt instance:Ed25519ctx -pkeyopt "context-string:$CTX" \
  -sigfile /tmp/ed25519ctx-out/ed25519ctx_sig.bin
```

## Last confirmed run (2026-09-02, extended with Ed25519 same day)

`test_pkcs11_conn`: all 8 PASS, real `C_Sign`/`C_Verify`, signature lengths
byte-exact to FIPS 204/205, RFC 8032 §5.2.6 (Ed448: 57-byte key -> 114-byte
R||S signature) and RFC 8032 §5.1.6 (Ed25519: 32-byte key -> 64-byte R||S
signature), negative control rejecting a corrupted signature in every case:

```
[SLH-DSA-SHA2-128s] connected: key_type=SLH_DSA_SHA2_128S, keysize=256 bits
[SLH-DSA-SHA2-128s] C_Sign OK: signature length = 7856 bytes
[SLH-DSA-SHA2-128s] C_Verify OK: genuine signature verified
[SLH-DSA-SHA2-128s] negative control OK: corrupted signature correctly rejected
[SLH-DSA-SHA2-128s] PASS
[SLH-DSA-SHA2-256s] C_Sign OK: signature length = 29792 bytes ... PASS
[SLH-DSA-SHA2-192s] C_Sign OK: signature length = 16224 bytes ... PASS
[ML-DSA-44]  connected: key_type=ML_DSA_44, keysize=10496 bits
[ML-DSA-44]  C_Sign OK: signature length = 2420 bytes ... PASS
[ML-DSA-65]  connected: key_type=ML_DSA_65, keysize=15616 bits
[ML-DSA-65]  C_Sign OK: signature length = 3309 bytes ... PASS
[ML-DSA-87]  connected: key_type=ML_DSA_87, keysize=20736 bits
[ML-DSA-87]  C_Sign OK: signature length = 4627 bytes ... PASS
[Ed448]      connected: key_type=ED448, keysize=456 bits
[Ed448]      C_Sign OK: signature length = 114 bytes ... PASS
[Ed25519]    connected: key_type=ED25519, keysize=256 bits
[Ed25519]    C_Sign OK: signature length = 64 bytes
[Ed25519]    C_Verify OK: genuine signature verified
[Ed25519]    negative control OK: corrupted signature correctly rejected
[Ed25519]    PASS

8 test(s), 0 failure(s)
```

(`keysize=256 bits` for Ed25519 is the connector's `get_keysize()` reporting
32 bytes × 8, the same convention `keysize=456 bits` uses for Ed448's 57-byte
key — matches strongSwan core's `get_public_key_size(KEY_ED25519) == 32`,
confirmed directly against `../../strongswan-pqc.patch`.)

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
disturb anything shared: still 8/8 PASS.

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

**Ed25519 independent-oracle cross-check**: same method as Ed448 above,
applied to the genuine `C_Sign` output from the `[Ed25519]` case:

```
$ openssl pkey -pubin -inform DER -in ed25519_pub.der -text -noout
ED25519 Public-Key:
pub:
    4c:52:43:15:48:c4:a3:d7:32:46:7b:07:57:bc:35:
    54:7a:f9:72:93:fa:9f:cf:99:c0:02:72:29:ef:7f:
    a3:a7

$ openssl pkeyutl -verify -pubin -inkey ed25519_pub.der -keyform DER \
    -rawin -in ed25519_msg.bin -sigfile ed25519_sig.bin
Signature Verified Successfully
```

**`test_pkcs11_ed25519ctx` — RFC 8032 Ed25519ctx, raw PKCS#11, cross-checked
against OpenSSL (2026-09-02)**: 1 test, 0 failures, all four assertions PASS
(genuine-signature verify, wrong-context negative control, corrupted-signature
negative control, and — separately, by hand, mirroring the Ed448 method above
— an independent OpenSSL verify of the same signature):

```
[Ed25519ctx] C_Sign OK: signature length = 64 bytes (context="strongswan-pkcs11-ctx", 21 bytes)
[Ed25519ctx] C_Verify OK: genuine signature verified under its own context
[Ed25519ctx] negative control OK: wrong-context verify correctly rejected (rv=192)
[Ed25519ctx] negative control OK: corrupted signature correctly rejected (rv=192)

1 test(s), 0 failure(s)
```

```
$ openssl pkeyutl -verify -pubin -inkey ed25519ctx_pub.der -keyform DER \
    -rawin -in ed25519ctx_msg.bin \
    -pkeyopt instance:Ed25519ctx -pkeyopt context-string:strongswan-pkcs11-ctx \
    -sigfile ed25519ctx_sig.bin
Signature Verified Successfully

$ openssl pkeyutl -verify -pubin -inkey ed25519ctx_pub.der -keyform DER \
    -rawin -in ed25519ctx_msg.bin \
    -pkeyopt instance:Ed25519ctx -pkeyopt context-string:different-context-str \
    -sigfile ed25519ctx_sig.bin
...ED25519 digest_verify:...
Signature Verification Failure
```

All four outcomes agree: OpenSSL independently verifies the genuine
signature under its real context and independently rejects the SAME
signature under a wrong context, matching the engine's own `C_Verify`
verdicts exactly (`rv=192` is `CKR_SIGNATURE_INVALID`). This proves
`CK_EDDSA_PARAMS.ulContextDataLen`/`pContextData` genuinely change what gets
signed — not silently ignored the way B1/T39/T39b found the Rust engine's
FFI dispatch was doing before that fix (`rust/src/ffi.rs`'s
`ed25519ctx_ffi_dispatch_cross_checks_against_openssl` test) — for the C++
softhsmv3 engine this connector actually targets. This test does NOT go
through the strongSwan plugin at all (raw `dlopen` of the same module) —
see the "Known gaps" entry below for exactly why, and what would need to
change in strongSwan itself to close it.

## Known gaps, not covered here

- **Ed25519ctx authentication through IKEv2 peer auth (i.e. through
  `private_key_t.sign()`/`public_key_t.verify()`)**: plain Ed25519 is fully
  wired into this connector as of 2026-09-02 — `pkcs11_private_key.c`/
  `pkcs11_public_key.c`'s `KEY_ED25519`/`SIGN_ED25519` handling and
  `pkcs11_plugin.c`'s `f_pqc` registrations mirror `KEY_ED448`/`SIGN_ED448`
  exactly, verified above (`test_pkcs11_conn`'s `[Ed25519]` case). Ed25519ctx
  (a non-empty RFC 8032 context string) is a different matter: strongSwan's
  own `signature_scheme_t` (`../../strongswan-pqc.patch`,
  `src/libstrongswan/credentials/keys/public_key.h`) has `SIGN_ED25519` but
  no `SIGN_ED25519_CTX` value and no params type analogous to
  `rsa_pss_params_t` that could carry a caller-supplied context string for
  EdDSA — `pkcs11_signature_scheme_to_mech()`'s `SIGN_ED25519`/`SIGN_ED448`
  arm therefore always builds `CK_EDDSA_PARAMS` with an EMPTY context, the
  only variant `private_key_t.sign()`/`public_key_t.verify()` (and hence
  real IKEv2 peer authentication) can ever reach. This is a real, load-bearing
  gap in strongSwan's own credential API, not a bug in this connector or in
  the engine — the engine (both the C++ softhsmv3 build this connector
  targets and the Rust engine) correctly implements Ed25519ctx end-to-end,
  proven above by `test_pkcs11_ed25519ctx.c` driving the SAME module directly
  via raw PKCS#11 `C_Sign`/`C_Verify` and cross-checked against OpenSSL.
  Closing this for real IKEv2 use would mean patching strongSwan's own
  `signature_scheme_t`/credential builder chain to carry a context string —
  out of scope for a PKCS#11-plugin-only change, and the same kind of
  real, separate, not-silently-worked-around gap the `CKA_EC_PARAMS`
  dual-encoding note in `pkcs11_private_key.c`'s/`pkcs11_public_key.c`'s
  `find_key()`/`find_key_by_keyid()` comments documents for the engine one
  layer down (see those files — this connector accepts either encoding as a
  read-side workaround there rather than fixing the engine's own
  inconsistent normalisation, exactly the same "leave the root thing
  alone, document and route around it" call this Ed25519ctx gap makes).
