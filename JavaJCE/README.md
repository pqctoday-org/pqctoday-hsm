# softhsmv3-jce

A JDK 27 JCA/JCE `Provider` bridging `java.security`/`javax.crypto` to this
repo's PKCS#11 v3.2 engine (`softhsmv3`) over
[`java.lang.foreign`](https://openjdk.org/jeps/454) (FFM) — no JNI, no
`sun.security.pkcs11.wrapper` internals. Every cryptographic operation
routes to the token via the native layer; this provider never computes a
signature, hash, key, or derived secret on the JVM side.

Package: `com.pqctoday.hsm.jce`. See
[`docs/implementation-plan-jdk27-jca-provider-2026-08-24.md`](../docs/implementation-plan-jdk27-jca-provider-2026-08-24.md)
for the full build history, every design decision's rationale, and every
live-verification result this module was built under — this README is
the summary, that document is the record.

This replaces an earlier `JavaJCE/` that shipped fabricated capability
claims; see the CHANGELOG entry for what it replaced and why.

## Quick start

```java
Security.addProvider(new SoftHSMv3Provider());   // PKCS11_MODULE / PKCS11_PIN env vars
// or, explicitly:
SoftHSMv3Provider p = new SoftHSMv3Provider("/usr/local/lib/softhsm/libsofthsmv3.so", "1234");

KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", p);
KeyPair kp = kpg.generateKeyPair();

Signature sig = Signature.getInstance("ML-DSA-65", p);
sig.initSign(kp.getPrivate());
sig.update("hello".getBytes());
byte[] signature = sig.sign();
```

Or configure from a file instead of env vars:

```java
SoftHSMv3Provider configured =
    new SoftHSMv3Provider().configure("/etc/softhsmv3-jce.properties");
```

```properties
# /etc/softhsmv3-jce.properties
library = /usr/local/lib/softhsm/libsofthsmv3.so
pinEnv = PKCS11_PIN
# pin = 1234          # or a literal PIN — pinEnv wins if both are set
# name = second-token  # registers as "SoftHSMv3-second-token"
```

Requires: JDK 27, `--enable-native-access=ALL-UNNAMED` (already wired into
`pom.xml`'s surefire `argLine` and the built jar's manifest).

## Build & test

```bash
JAVA_HOME=/path/to/jdk-27 mvn test
```

Every test runs live against the real engine (`PKCS11_MODULE`/`PKCS11_PIN`
env vars, defaulting to `/usr/local/lib/softhsm/libsofthsmv3.so` / `1234`)
— nothing is mocked. As of 2026-08-25: **198/198 passing.**

## What's actually implemented

| JCA/JCE service | Algorithms | Notes |
|---|---|---|
| `SecureRandom` | `SoftHSMv3-DRBG` | Token DRBG via `C_GenerateRandom`/`C_SeedRandom` |
| `MessageDigest` | SHA-224/256/384/512, SHA3-224/256/384/512 | |
| `KeyPairGenerator` + `Signature` | ML-DSA-44/65/87 (FIPS 204) | |
| `KeyPairGenerator` + `Signature` | SLH-DSA — all 12 SHA2/SHAKE × 128S/128F/192S/192F/256S/256F param sets (FIPS 205) | |
| `KeyPairGenerator` + `Signature` | Ed25519, Ed448 | |
| `KeyPairGenerator` + `Signature` | `"EC"` (secp256r1/384r1/521r1, curve chosen via `ECGenParameterSpec`) — SHA256/384/512/SHA3-256/384/512withECDSA | Raw PKCS#11 r‖s output converted to ASN.1 DER for JCA interop |
| `KeyPairGenerator` + `Signature` | `"RSA"` (2048/3072/4096) — SHA256/384/512withRSA (PKCS#1 v1.5), RSASSA-PSS (SHA-2 only) | |
| `KeyFactory` | Public-key import for every algorithm above, plus ML-KEM-512/768/1024 | Public-key import only — private-key import is refused (FIPS 140-3 L3: keys are generated on-token, not brought in) |
| `KeyPairGenerator` + `KEM` | ML-KEM-512/768/1024 (FIPS 203); also registered under the bare family name `"ML-KEM"` — the exact string JDK 27's own `Hybrid.getKEM()` requests for JEP 527 TLS | Decapsulated secret is the one deliberate exception to this module's opaque-key design — see §6.5 in the plan doc |
| `Cipher` | `RSA/ECB/OAEPWith{SHA-256,SHA-384,SHA-512,SHA3-256,SHA3-384,SHA3-512}AndMGF1Padding` | |
| `Cipher` | `AES/GCM/NoPadding`, `AES/CBC/NoPadding`, `AES/CBC/PKCS5Padding`, `AES/CTR/NoPadding`, `AESWrap`, `AESWrapPad` (SP 800-38F) | GCM encryption IVs are always module-generated (SP 800-38D §8.2) — a caller-supplied IV on `ENCRYPT_MODE` is refused |
| `KeyAgreement` | `ECDH` (`CKD_NULL`, plain ECDH, no built-in KDF) | |
| `KeyGenerator` | `AES`, `HmacSHA{224,256,384,512}`, `HmacSHA3-{224,256,384,512}`, `KMAC128`, `KMAC256` | |
| `Mac` | Same HMAC/KMAC set as above, plus `AESCMAC` | |
| `KDF` | `HKDF-SHA256/384/512` (JEP 478) | Single-IKM, single-salt only — a real PKCS#11 `CK_HKDF_PARAMS` constraint, not a shortcut |
| `SecretKeyFactory` | `PBKDF2WithHmacSHA{256,384,512}` (SP 800-132), `SP800-108-Counter`, `SP800-108-Feedback` | |
| `KeyStore` | `"PKCS11-SoftHSMv3"` | Full read/write/delete, both `PrivateKeyEntry` (with real certificate chains) and standalone `TrustedCertificateEntry`; genuine PKIX trust-path validation via the JDK's own `PKIXParameters`/`CertPathValidator` works against it |
| `AuthProvider` | `login()`/`logout()`/`setCallbackHandler()` | Construction still logs in eagerly by default; explicit login/logout is for callers who want the real lifecycle — see the plan doc's §6.1 entry for the (real, disclosed) token-wide-state consequence of `logout()` |
| `Provider.configure(String)` | File-based configuration | Plain `key = value` file, not a SunPKCS11-format port — see `configure()`'s own javadoc |

## What's deliberately excluded

Enforced by never registering a `Service` under these names (§5 of the
plan) — not because the engine can't do them (it can; this provider's job
is the FIPS 140-3 L3 narrowing, not the engine's):

- SHA-1, MD5, RIPEMD-160, Keccak-256 (and every signature/HMAC composite built on them)
- Raw/unpadded RSA and PKCS#1 v1.5 as a **Cipher** (kept as a *signature* mechanism only)
- ChaCha20, ChaCha20-Poly1305
- AES in ECB mode
- X25519, X448 (Montgomery-curve key agreement)
- BIP32 key derivation (application-specific, out of scope)
- `CONCATENATE_*`/standalone `SHAKE_256_KEY_DERIVATION` (internal KDF building blocks only)
- HSS/XMSS/XMSS-MT (SP 800-208-approved, but deferred — stateful signatures need their own state-management design before any JCA mapping is safe; see plan §10)

## FIPS 140-3 Level 3 operational posture

Targets the **L3 operational profile** (this is software, so literal
physical-tamper-evidence certification isn't claimable) — see plan §6 for
the full posture and, once written, the companion security-posture
document for the section-by-section mapping. Summary:

- Full power-on self-test battery before any service is exposed —
  SHA-256/HMAC-SHA-256/AES-GCM KATs against real published vectors, a DRBG
  sanity check, and a sign/verify or encap/decap pairwise-consistency
  check for every asymmetric family. Any failure closes the session and
  throws out of the constructor — fail-closed, not fail-open.
- No plaintext key export: generated private/secret keys are opaque
  (`getEncoded()` is `null`); the one deliberate exception is ML-KEM's
  decapsulated shared secret, which genuinely needs to leave the token to
  be usable at all.
- `Destroyable` implemented on every key type — `destroy()` genuinely
  issues `C_DestroyObject`, not just a Java-side flag.
- A JVM shutdown hook provides best-effort session cleanup even if a
  caller never explicitly closes the provider.
- **Known, disclosed gap, not hidden:** the native layer currently uses
  one shared `Arena` for a session's whole lifetime rather than confined
  per-operation arenas with an explicit zero-fill pass before release —
  see the plan doc's zeroization-audit entry for exactly what's left and
  why it wasn't rushed through as part of this pass.

## Known limitations

- Stateful hash-based signatures (HSS/XMSS) are not implemented — deferred
  by explicit scope decision (plan §10), not an oversight.
- TLS integration (JEP 527 hybrid KEM groups via JSSE) is validated at the
  spike level (plan §W0.1) but not yet wired into a full end-to-end
  handshake test in this module — tracked as plan W6.
- The Arena/zeroization gap noted above.
- This module targets JDK 24+ for everything except TLS (W6), which rides
  JDK 27's JEP 527; JDK 27 itself is RC until ~2026-09-15 (see the plan's
  risk register for the GA-swap follow-up).
