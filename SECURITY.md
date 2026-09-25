# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x (main) | Yes |
| 2.x (upstream SoftHSM2) | No — report to [opendnssec/SoftHSMv2](https://github.com/opendnssec/SoftHSMv2) |

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Please report security issues via **GitHub's private security advisory** feature:

1. Go to <https://github.com/pqctoday-org/pqctoday-hsm/security/advisories>
2. Click **"New draft security advisory"**
3. Fill in the title, severity, description, and steps to reproduce

We aim to acknowledge reports within **2 business days** and provide a fix
timeline within **7 business days** for critical issues.

## Scope

Issues in scope:
- Memory safety bugs (use-after-free, buffer overflow, integer overflow/underflow) in the PKCS#11 layer or crypto backend
- Cryptographic weaknesses introduced by this fork (not upstream OpenSSL/SoftHSM2 issues)
- PIN or key material leakage via timing side-channels, logging, or improper memory clearing
- WASM build issues that expose secret key material to JavaScript callers beyond the intended API

Out of scope:
- Vulnerabilities in OpenSSL itself (report to <https://openssl.org/policies/general/security-policy.html>)
- Attacks requiring physical access to the host system
- Denial-of-service via resource exhaustion (treat as a regular bug)

## Security Design Notes

- Key material is stored masked in memory (`SecureDataManager`) with per-operation local AES instances to avoid shared cipher state races
- `SecureAllocator` + `mlock()` prevent secret buffers from being swapped to disk
- PBE key derivation uses PBKDF2-SHA256 with a random 256-bit salt per wrapped key blob
- PKCS#11 v3.2 `C_EncapsulateKey` / `C_DecapsulateKey` use ML-KEM (FIPS 203) via OpenSSL EVP
- All EVP contexts are freed on every code path; no ENGINE API is used

## Known Third-Party Dependency Risks

- **`rsa` crate — Marvin Attack timing side-channel
  (RUSTSEC-2023-0071 / GHSA-c58m-fhrc-h4r9, medium severity).** RSA PKCS#1
  v1.5 decryption in the `rsa` crate is vulnerable to a timing-based padding
  oracle. **No patched version exists upstream** as of 2026-09-02 (confirmed
  via GitHub's own security-advisory data — `first_patched_version: null`
  for the affected range `<= 0.9.6`).
  - **The exposed decrypt oracle is closed on native builds.** An earlier
    version of this note scoped the advisory to `openpgp/`'s legacy
    `RSAEncryptSign` path only. That was wrong: the `softhsmrustv3` engine's
    own `CKM_RSA_PKCS` decrypt and `C_UnwrapKey` used the `rsa` crate's
    non-constant-time unpad, and that engine is statically linked into the
    `pqctoday-kmip` server that serves RSA decrypt over TLS on a network port
    — precisely where the timing is observable. As of 2026-09-15 both v1.5
    decrypt sites route through **aws-lc-rs** (AWS-LC's constant-time unpad)
    on every non-wasm32 target (`rust/src/crypto/awslc.rs`), so the network
    oracle no longer exists in a native build. RSA sign, verify, keygen, and
    PKCS#1 v1.5 encrypt/decrypt, plus NIST-curve ECDH, moved to AWS-LC in
    that change (1.39x RSA-2048 sign measured on the FRDM-IMX95 A55).
  - **OAEP decrypt followed on 2026-09-25, not in the 09-15 change.** An
    earlier version of this note listed OAEP alongside the v1.5 sites above.
    That was inaccurate: `awslc::rsa_oaep_decrypt` was written and cached but
    had **no production callers**, so every OAEP decrypt — including the one
    `pqctoday-kmip`'s Decrypt reaches on :5696 — still ran the pure-Rust
    unpad. All four decrypt sites (`C_Decrypt`, `C_UnwrapKey`,
    `CKM_RSA_AES_KEY_WRAP`, and `native::encrypt`, the KMIP path) now probe
    AWS-LC first. A unit test pins the probe actually engaging, since a silent
    fallback returns identical plaintext and no functional test can tell them
    apart.
    **ECDSA deliberately stays on the pure-Rust `p256`/`p384`/`p521` crates**:
    they sign with RFC 6979 deterministic nonces, which this engine's contract
    relies on, and aws-lc-rs offers no deterministic-ECDSA API — so ECDSA keeps
    its determinism (and is unaffected by RUSTSEC-2023-0071, which is a
    v1.5-decrypt issue, not an ECDSA one).
  - **The `rsa` crate is still in the tree, so the advisory ID remains
    ignored in CI**, but only on paths that are *not* the Marvin decrypt
    surface: (a) `openpgp/`'s legacy classical OpenPGP interop; (b) the engine
    fallback for mechanisms AWS-LC does not expose (raw `CKM_RSA_X_509`,
    unprefixed `CKM_RSA_PKCS`, PSS with a caller-chosen salt length, the
    MD5/SHA-1/SHA-224/SHA-3 RSA variants, and OAEP where the hash differs
    from the MGF1 hash or the private key is PKCS#1 `RSAPrivateKey` DER
    rather than PKCS#8 — AWS-LC has no algorithm for the mismatched pairs and
    its loader declines that key format) — none of which is v1.5 decryption;
    (c) `pqctoday-kmip`'s DER key-format conversion (`KeyFormatType`
    PKCS#1↔PKCS#8, component reconstruction), which performs no private-key
    math and has no timing oracle. This fork's core posture continues to rest
    on the PQC composite algorithms (`MLDSA65_Ed25519`, `MLDSA87_Ed448`,
    `MLKEM768_X25519`, `MLKEM1024_X448`), none of which touch `rsa` at all.
  - **wasm32** keeps the pure-Rust `rsa` path (aws-lc-rs is a C library and
    does not build for the hub's `wasm32-unknown-unknown` target). A browser
    tab has no network-observable timing channel against its own in-page key,
    so the oracle that matters on a server does not apply there.
  - Tracked via GitHub Dependabot. Revisit if/when the `rsa` crate ships a
    constant-time release (its `crypto-bigint` migration, RustCrypto/RSA #390),
    which would let the fallback paths drop the AWS-LC split.

## WASM Security Limitations

When built for WebAssembly (Emscripten or wasm32-unknown-unknown), the following platform-level security guarantees do **not** apply:

- **No secure memory**: `mlock()`, `madvise(MADV_DONTDUMP)`, and `SecureAllocator` are no-ops. Key material in WASM linear memory may be observable by the host JavaScript environment and is subject to garbage collection and memory snapshots.
- **Exposed linear memory**: WASM modules export their entire linear memory as an `ArrayBuffer`. Any JavaScript code in the same origin can read all key material directly via `Module.HEAPU8`.
- **No ASLR or memory isolation**: WASM linear memory has a fixed, deterministic layout. Memory addresses are predictable and cannot be randomized.
- **Maximum memory cap**: The WASM build is capped at 512 MB (`MAXIMUM_MEMORY=536870912`) to prevent unbounded growth.

### Required HTTP Headers

Deployments serving the WASM module **must** set these response headers to enable `SharedArrayBuffer` (required by Emscripten pthreads):

```
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
```

### Recommendations for WASM Consumers

1. Treat the WASM HSM as an **educational/development tool**, not a production HSM
2. Never store production secrets in the WASM module's object store
3. Serve the module only over HTTPS with the required CORP/COOP headers
4. Use `Content-Security-Policy: script-src 'self' 'wasm-unsafe-eval'` to prevent code injection
5. Zeroize keys via `C_DestroyObject` when no longer needed (the Rust module zeroizes `CKA_VALUE` on destroy)

## Disclosure Policy

Once a fix is merged and released, we will:
1. Publish a GitHub Security Advisory with full details
2. Add an entry to [CHANGELOG.md](CHANGELOG.md) under the release version
3. Tag a new release within 24 hours of the advisory publication
