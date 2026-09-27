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

Pass the provider instance directly to `getInstance(...)` — no
`Security.addProvider` registration required (the pattern every test in
this module uses):

```java
SoftHSMv3Provider p = new SoftHSMv3Provider();   // PKCS11_MODULE / PKCS11_PIN env vars
// or, explicitly:
SoftHSMv3Provider p2 = new SoftHSMv3Provider("/usr/local/lib/softhsm/libsofthsmv3.so", "1234");

KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", p);
KeyPair kp = kpg.generateKeyPair();

Signature sig = Signature.getInstance("ML-DSA-65", p);
sig.initSign(kp.getPrivate());
sig.update("hello".getBytes());
byte[] signature = sig.sign();
```

If you'd rather look the provider up by name (e.g. so other code that
only calls `getInstance(alg)` without a provider argument can find it
too), register it globally instead: `Security.addProvider(new
SoftHSMv3Provider())`, then `KeyPairGenerator.getInstance("ML-DSA-65",
"SoftHSMv3")`.

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
— nothing is mocked. As of 2026-08-30: **272/272 passing.**

## What's actually implemented

| JCA/JCE service | Algorithms | Notes |
|---|---|---|
| `SecureRandom` | `SoftHSMv3-DRBG` | Token DRBG via `C_GenerateRandom`/`C_SeedRandom` |
| `MessageDigest` | SHA-224/256/384/512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512 | |
| `KeyPairGenerator` + `Signature` | ML-DSA-44/65/87 (FIPS 204), plus fixed `ML-DSA-44/65/87-ExternalMu` names (FIPS 204 external-µ mode) | |
| `KeyPairGenerator` + `Signature` | SLH-DSA — all 12 SHA2/SHAKE × 128S/128F/192S/192F/256S/256F param sets (FIPS 205) | |
| `KeyPairGenerator` + `Signature` | Ed25519, Ed448 | |
| `KeyPairGenerator` + `Signature` | `"EC"` (secp256r1/384r1/521r1, curve chosen via `ECGenParameterSpec`) — SHA224/256/384/512/SHA3-224/256/384/512withECDSA | Raw PKCS#11 r‖s output converted to ASN.1 DER for JCA interop |
| `KeyPairGenerator` + `Signature` | `"RSA"` (2048/3072/4096) — SHA224/256/384/512/SHA3-224/256/384/512withRSA (PKCS#1 v1.5), RSASSA-PSS (SHA-2 incl. SHA-224, and SHA-3 families) | |
| `KeyFactory` | Public-key import for every algorithm above, plus ML-KEM-512/768/1024 | Public-key import only — private-key import is refused (FIPS 140-3 L3: keys are generated on-token, not brought in) |
| `KeyPairGenerator` + `KEM` | ML-KEM-512/768/1024 (FIPS 203); also registered under the bare family name `"ML-KEM"` — the exact string JDK 27's own `Hybrid.getKEM()` requests for JEP 527 TLS | Decapsulated secret is the one deliberate exception to this module's opaque-key design — see §6.5 in the plan doc |
| `Cipher` | `RSA/ECB/OAEPWith{SHA-256,SHA-384,SHA-512,SHA3-256,SHA3-384,SHA3-512}AndMGF1Padding` | |
| `Cipher` | `AES/GCM/NoPadding`, `AES/CCM/NoPadding`, `AES/CBC/NoPadding`, `AES/CBC/PKCS5Padding`, `AES/CTR/NoPadding`, `AES/OFB/NoPadding`, `AES/CFB1/NoPadding`, `AES/CFB8/NoPadding`, `AES/CFB128/NoPadding`, `AES/XTS/NoPadding`, `AESWrap`, `AESWrapPad`, `AESWrapKWP` (SP 800-38F) | GCM encryption IVs are always module-generated (SP 800-38D §8.2) — a caller-supplied IV on `ENCRYPT_MODE` is refused. `AESWrapKWP` (`CKM_AES_KEY_WRAP_KWP`) is PKCS#11 v3.2 §6.16.3's spec-current successor to `AESWrapPad` |
| `KeyAgreement` | `ECDH` (`CKD_NULL`, plain ECDH, no built-in KDF), `ECDHC` (`CKM_ECDH1_COFACTOR_DERIVE`) | |
| `KeyGenerator` | `AES`, `AES_XTS` (double-width key), `HmacSHA{224,256,384,512}`, `HmacSHA512/224`, `HmacSHA512/256`, `HmacSHA3-{224,256,384,512}`, `KMAC128`, `KMAC256` | |
| `Mac` | Same HMAC/KMAC set as above, plus `AESCMAC`, `AES-GMAC` (standalone `CKM_AES_GMAC`), and truncated-output `HmacSHA{224,256,384,512}General`/`HmacSHA3-{224,256,384,512}General` | |
| `KDF` | `HKDF-SHA256/384/512` (JEP 478) | Single-IKM, single-salt only — a real PKCS#11 `CK_HKDF_PARAMS` constraint, not a shortcut |
| `SecretKeyFactory` | `PBKDF2WithHmacSHA{256,384,512}` (SP 800-132), `SP800-108-Counter`, `SP800-108-Feedback`, `SP800-108-DoublePipeline` | |
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

## Extending: adding a new algorithm

Every JCA service this provider exposes is registered in one place,
`SoftHSMv3Provider.registerServices()`, as a `putService(new Service(this,
type, name, spiClassName, List.of(), Map.of()) { newInstance(...) {...} })`
call — the anonymous `Service` subclass's `newInstance` is where the SPI
object is actually constructed, closing over the provider's shared `lib`
(`P11Library`) field. To add a new algorithm:

1. **Reuse an existing `registerXxx` helper if the shape already exists.**
   `registerDigest`/`registerHmac`/`registerPureSig`/`registerECDSASignature`/
   `registerRSAPKCS1`/`registerAESCipher`/`registerAESWrap`/`registerRSAOAEP`/
   `registerHKDF`/`registerPBKDF2`/`registerGenericSecretKeyGenerator`/
   `registerMLKEMKeyPairGenerator`/`registerEdDSA` each cover one recurring
   registration shape (e.g. "one mechanism-agnostic `SignatureSpi`, keyed
   only by mechanism type" for `registerPureSig`). A new SLH-DSA-shaped
   signature or another SHA-2/SHA-3 digest is usually a one-line call to
   one of these, next to the existing calls in `registerServices()`.
2. **Write a new SPI class only when the shape genuinely differs** — e.g.
   `P11RSAPSSSignatureSpi` exists separately from
   `P11PureSigSignatureSpi` because RSASSA-PSS's mechanism parameters are
   chosen by the *caller* via `engineSetParameter(PSSParameterSpec)` after
   construction, not fixed at registration time like every plain-digest
   signature. Follow the `P11*Spi` naming convention and extend the
   matching `java.security`/`javax.crypto` SPI base class
   (`SignatureSpi`, `CipherSpi`, `KeyPairGeneratorSpi`, `KeyGeneratorSpi`,
   `KeyAgreementSpi`, `MacSpi`, `SecretKeyFactorySpi`, `KDFSpi`, ...).
3. **Add any new native binding to `P11Library`, not the SPI class.** If
   the mechanism needs a `CK_MECHANISM_TYPE`/`CKA_*`/`CKR_*` constant this
   module doesn't have yet, add it to `P11Constants` (grep
   `src/lib/pkcs11/pkcs11t.h` first — see the repo's `CLAUDE.md`). If it
   needs a PKCS#11 function this module hasn't bound yet, resolve it by
   name in `P11Library`'s constructor via the existing `h(linker, lib,
   "C_Xxx", fd(...))` pattern (FFM `dlsym`-by-name, no JDK-internal APIs
   — see `P11Library`'s own class javadoc for why). If the mechanism
   carries parameters, add a `mechXxx(Arena, ...)` builder alongside the
   existing ones (`mechGcm`, `mechOaep`, `mechHkdf`, `mechPbkdf2`, ...) —
   return a `BuiltMech` instead of a plain `MemorySegment` if any embedded
   byte content is real secret material (see `P11Library`'s "Memory-lifetime
   architecture" javadoc note on zeroing).
4. **Gate on real mechanism advertisement if the mechanism isn't always
   present** (a draft/optional PKCS#11 codepoint, not a ratified one) —
   check `lib.mechanismSupported(CKM_...)` *inside* `Service#newInstance`,
   not at registration time, and throw `NoSuchAlgorithmException` if
   absent. `registerMLDSAExternalMu` is the worked example: registration
   always happens, but `getInstance("ML-DSA-65-ExternalMu", p)` only
   succeeds if the connected token actually advertises
   `CKM_ML_DSA_EXTERNAL_MU`.
5. **Respect the FIPS 140-3 L3 exclusion policy** — don't register a
   mechanism this provider deliberately keeps out (see "What's
   deliberately excluded" above) just because the engine happens to
   support it.
6. Add real, live tests (no mocks — every test in this module runs
   against the real engine) following the shape of `MLDSATest.java` or
   `MLKEMTest.java`: round-trip sign/verify or encapsulate/decapsulate,
   a tamper-rejection case, and — where a standard JDK software
   implementation of the same algorithm exists — a cross-verify against
   it (`KeyFactory.getInstance(alg)` with no provider argument, `Signature
   .getInstance(alg)` likewise) to prove the encoding is standards-correct,
   not just self-consistent.

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
- Native (off-heap) memory is scrubbed too, not just the JVM heap: every
  operation opens its own short-lived confined arena, and every buffer
  carrying real byte content is explicitly zero-filled before that arena
  closes (2026-08-25 — see the remaining-gaps plan's WS-C entry; this
  used to be a disclosed gap, one shared session-lifetime `Arena` with
  no zero-fill pass, closed as part of that workstream).

## Known limitations

- Stateful hash-based signatures (HSS/XMSS) are not implemented — deferred
  by explicit scope decision (plan §10), not an oversight.
- TLS integration (JEP 527 hybrid KEM groups via JSSE) completes real,
  live TLS 1.3 handshakes for both FIPS-profile groups
  (`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) against a real quantum-safe
  endpoint, token-side proof included (2026-08-25 — see the remaining-gaps
  plan's WS-B entry; the standalone spike `JavaJCE/spikes/
  W6TlsHandshakeSpike.java` reproduces this). Needs
  `-Dsofthsmv3.jce.callerGcmIv=true` (default off, non-FIPS) for the
  record cipher — see `P11AESCipherSpi`'s own javadoc for why.
- Pre-hash ML-DSA/SLH-DSA (`CKM_HASH_ML_DSA_*`, `CKM_HASH_SLH_DSA_*`) are
  genuinely implemented by the engine but not exposed by this provider:
  this same JDK's own ML-DSA implementation has no standard "HashML-DSA"
  algorithm name or pre-hash `Signature` API surface to build against or
  model a naming convention on — see `P11PureSigSignatureSpi`'s own
  javadoc for the full investigation.
- `KeyStore.engineGetCreationDate` always returns the epoch for an entry
  that exists — PKCS#11 has no creation-timestamp attribute to report.
- This module targets JDK 24+ for everything except TLS (W6), which rides
  JDK 27's JEP 527; JDK 27 itself is RC until ~2026-09-15 (see the plan's
  risk register for the GA-swap follow-up).
- `CKM_HPKE` (RFC 9180, added to the Rust engine 2026-09-01) is not exposed
  by this provider — deferred by explicit decision, not an oversight. The
  engine's `C_EncapsulateKey`/`C_DecapsulateKey(CKM_HPKE)` return KEM +
  KeySchedule output only (encapsulation, an AEAD key handle, base nonce,
  optional exporter-secret handle) — not the AEAD Seal/Open step itself.
  That return shape maps reasonably onto `javax.crypto.KEM`'s
  `Encapsulator`/`Decapsulator` (the precedent this module already
  established for `P11MLKEMSpi`), *if* the extra suite-selection (KEM/KDF/
  AEAD IDs), mode (base/PSK/Auth/AuthPSK), and base-nonce output can ride in
  a custom `AlgorithmParameterSpec`/`AlgorithmParameters` pair — but the
  caller would then have to chain a separate, ordinary `Cipher` call for
  Seal/Open, reproducing exactly the multi-call complexity `CKM_HPKE` exists
  to collapse at the PKCS#11 layer. A custom ECIES/BC-style `Cipher` SPI
  (`doFinal()` returning `enc‖ciphertext` as one self-describing blob) could
  collapse that back into one call, but has no precedent in this module and
  can't represent HPKE's Export-only mode (a derived secret, not
  ciphertext) at all. Two real, imperfect candidate shapes, no clean third
  option — this needs an explicit API-design decision, not a guess (see
  `docs/proposals/pkcs11-ckm-hpke-mechanism-proposal.md` for the mechanism
  itself). Revisit if/when a standard JDK HPKE API lands.
- The engine/KMIP layer's eight §10.4 composite signature profiles
  (`CKM_HASH_COMP_SIG_*`, vendor codepoints, closed 2026-08-31) are not
  exposed via JCA — doubly documented as out of scope in
  `docs/implementation-plan-jdk27-jca-provider-2026-08-24.md` §10 and
  `docs/implementation-plan-jca-remaining-gaps-2026-08-25.md` §13. Reaffirmed
  here rather than left to rediscovery: this is a scope boundary, not a gap
  to close opportunistically.
