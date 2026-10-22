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
    ignored in CI**, but it no longer performs any RSA private-key operation
    in a native build. Since 2026-10-03 the engine runs every native RSA
    private-key operation in AWS-LC (all signing variants, PKCS#1 v1.5 and
    OAEP decryption and unwrapping, sign-recover and key generation), for keys
    of 2048 to 8192 bits; other sizes are refused. A test drives every RSA
    private-key mechanism and fails if the `rsa` crate runs one natively. What
    the crate is still used for: (a) the **browser (wasm32) build's** RSA
    private-key operations (see below); (b) `openpgp/`'s legacy classical
    OpenPGP interop (`RSAEncryptSign`), an accepted risk of that fork; (c)
    public-key operations, parsing and key-container handling in the engine,
    which involve no private-key math; and (d) `pqctoday-kmip`'s DER key-format
    conversion (`KeyFormatType` PKCS#1↔PKCS#8, component reconstruction),
    which also performs no private-key math and has no timing oracle. This
    fork's core posture continues to rest on the PQC composite algorithms
    (`MLDSA65_Ed25519`, `MLDSA87_Ed448`, `MLKEM768_X25519`, `MLKEM1024_X448`),
    none of which touch `rsa` at all.
  - **wasm32** keeps the pure-Rust `rsa` path (aws-lc-rs is a C library and
    does not build for the hub's `wasm32-unknown-unknown` target). A browser
    tab has no network-observable timing channel against its own in-page key,
    so the oracle that matters on a server does not apply there.
  - Tracked via GitHub Dependabot. Revisit if/when the `rsa` crate ships a
    constant-time release (its `crypto-bigint` migration, RustCrypto/RSA #390),
    which would let the browser build and the openpgp fork drop the exception.

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

## Optional test inputs for randomised operations (outside the PKCS#11 standard)

Some NIST ACVP tests hand the module the value it would otherwise draw at
random, then check for one exact answer. Both engines therefore accept that
value as an **optional extra input** on the operations below. If the caller
leaves it out, the engine draws the value itself exactly as the standard says,
so a caller using only standard PKCS#11 sees no difference. These inputs are
not defined by PKCS#11 v3.2 or the v3.3 working draft; FIPS 203, 204 and 205
reserve such interfaces for testing, and a validated module would keep them out
of its approved mode. Like the rest of this module, they are for education and
development only (see recommendation 1 above).

| Mechanism | Operation | Optional input |
|---|---|---|
| `CKM_ML_KEM` | `C_EncapsulateKey` | the mechanism parameter is m (32 bytes) |
| `CKM_ECDSA` | `C_Sign` | the mechanism parameter is k (curve-order length, 1 ≤ k < n) |
| `CKM_ML_DSA`, `CKM_HASH_ML_DSA*`, `CKM_ML_DSA_EXTERNAL_MU` | sign | rnd (32 bytes), in the extended signing structure |
| `CKM_SLH_DSA`, `CKM_HASH_SLH_DSA*` | sign | addrnd (n bytes), in the extended signing structure |
| `CKM_SLH_DSA` | sign, verify | `messageEncoding = internal`: the message is used as given (FIPS 205 slh_sign/slh_verify_internal) |
| `CKM_COMP_KEM`, `CKM_COMP_SIG` (Rust engine) | encapsulate, sign | the random values of both components, concatenated |

The extended signing structures (`CK_PQCTODAY_SIGN_ADDITIONAL_CONTEXT_EXT`,
`CK_PQCTODAY_HASH_SIGN_ADDITIONAL_CONTEXT_EXT`, `vendor_mechanisms.h`) are the
standard structures followed by `pRandom`, `ulRandomLen` and `messageEncoding`;
the engine recognises them by their exact size. A supplied value with
`CKH_DETERMINISTIC_REQUIRED`, a wrong length, or a parameter on decapsulation
or verification is refused with `CKR_MECHANISM_PARAM_INVALID` at `Init`.
Whenever a supplied value is used, the operation log records `test_input=`.

**ECDSA k recovers the key.** From one signature (r, s) over a digest z made
with a known k, anyone computes d = r⁻¹ · (s·k − z) mod n. A caller who can
supply k for a key can therefore always recover that key; treat it as
equivalent to being able to export the key. Signatures made this way are
ordinary ECDSA and verify normally. Likewise, a chosen ML-DSA or SLH-DSA random
value removes the protection hedged signing gives against side-channel and
fault attacks.

There is no switch or per-key guard: the inputs are available in every build,
on every key (owner decision, 21 October 2026), because the module as a whole
is an educational tool. The former vendor mechanism
`CKM_PQCTODAY_ECDSA_EXPLICIT_K` (`0x80000015`) is **retired**: both engines
refuse it and no longer advertise it, and the codepoint is never re-used.

## Disclosure Policy

Once a fix is merged and released, we will:
1. Publish a GitHub Security Advisory with full details
2. Add an entry to [CHANGELOG.md](CHANGELOG.md) under the release version
3. Tag a new release within 24 hours of the advisory publication
