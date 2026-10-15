# Changes to this copy of pkcs11-provider

Upstream: pkcs11-provider by Simo Sorce and contributors,
https://github.com/latchset/pkcs11-provider, Apache-2.0 (`COPYING`,
`LICENSES/`, kept unchanged; upstream ships no NOTICE file).

Base: upstream commit `078877c71a93bfce37df122b8d7fd55f9f3212f9`
(2026-04-08, `git describe`: `v1.2.0-24-g078877c`), found by comparing this folder
with every upstream commit since mid-2024: it is the closest one. Imported on
2026-04-17 (commit b0e3b640) as a reference copy; this repository's builds use
`src/vendor/pkcs11-provider/`, not this folder.

Changed by PQC Today, LLC, 2026-04-17: SLH-DSA, HSS/LMS and XMSS key
management and signatures. Each modified file carries a one-line "Modified by
PQC Today, LLC" notice at the top (Apache-2.0 section 4(b)).

Modified upstream files: `src/kmgmt/internal.h`, `src/kmgmt/keymgmt.h`, `src/meson.build`, `src/provider.c`, `src/provider.h`, `src/sig/internal.h`, `src/sig/signature.h`.

Added files: `MIGRATION_GUIDE.md`, `src/kmgmt/hss.c`, `src/kmgmt/slhdsa.c`, `src/kmgmt/xmss.c`, `src/sig/hss.c`, `src/sig/slhdsa.c`, `src/sig/xmss.c`.

Not copied from upstream (git submodules and the top-level Makefile):
`Makefile`, `python-ecdsa`, `tlsfuzzer`, `tlslite-ng`.
