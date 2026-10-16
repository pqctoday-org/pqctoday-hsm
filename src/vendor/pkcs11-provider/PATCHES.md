# Changes to this copy of pkcs11-provider

Upstream: pkcs11-provider by Simo Sorce and contributors,
https://github.com/latchset/pkcs11-provider, Apache-2.0 (`COPYING`,
`LICENSES/`, kept unchanged; upstream ships no NOTICE file).

Base: upstream commit `663dea335c80bec7fd96d544ff875af08d6461a9`
(2025-09-29, `git describe`: `v1.1.0-17-g663dea3`). This copy was imported on
2026-04-15 and is the provider that this repository builds (`CMakeLists.txt`,
`scripts/build-pkcs11-provider-wasm.sh`). The base was found by comparing this
folder with every upstream commit since 2024: it is the closest one (615
changed lines at import). The import already carried some local changes.

Changed by PQC Today, LLC, 2026-04-15 to 2026-10. Each modified file carries a
one-line "Modified by PQC Today, LLC" notice at the top (Apache-2.0 section
4(b)). What changed: ML-KEM key management, encoders and KEM; ML-DSA
external-mu and HashML-DSA; SLH-DSA, HSS/LMS and XMSS/XMSS-MT keys and
signatures; composite (ML-DSA plus classical) signatures and their TLS
signature algorithms; ML-KEM TLS groups; X25519/X448 key exchange; HMAC, CMAC,
KMAC and AES-GMAC as EVP_MAC; PBKDF2 and SP 800-108 KDFs; AES Key Wrap,
AES-XTS and ChaCha20 ciphers; a CMake build next to meson; fixes for
softhsmv3 and OpenSSL 3.6/4.x. `git log -- src/vendor/pkcs11-provider` in this
repository gives every change, its date and its reason.

Modified upstream files: `BUILD.md`, `README.md`, `meson.build`, `meson_options.txt`, `src/cipher.c`, `src/cipher.h`, `src/decoder.c`, `src/decoder.h`, `src/digests.c`, `src/encoder.c`, `src/encoder.h`, `src/exchange.c`, `src/interface.c`, `src/interface.gen.c`, `src/interface.h`, `src/interface.pre`, `src/kdf.c`, `src/kdf.h`, `src/keymgmt.c`, `src/keymgmt.h`, `src/meson.build`, `src/objects.c`, `src/objects.h`, `src/pkcs11.h`, `src/provider.c`, `src/provider.h`, `src/provider.map`, `src/sig/eddsa.c`, `src/sig/internal.h`, `src/sig/mldsa.c`, `src/sig/signature.c`, `src/sig/signature.h`, `src/skeymgmt.c`, `src/store.c`, `src/tls.c`.

Added files (written for this repository, Apache-2.0 like the rest of the
provider): `CMakeLists.txt`, `src/chacha.c`, `src/composite.c`, `src/composite.h`, `src/kem/mlkem.c`, `src/mac.c`, `src/mac.h`, `src/sig/hss.c`, `src/sig/slhdsa.c`, `src/sig/xmss.c`.

Not copied from upstream (git submodules and the top-level Makefile):
`Makefile`, `python-ecdsa`, `tlsfuzzer`, `tlslite-ng`.
