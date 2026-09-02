# openpgp-pkcs11 — PQC OpenPGP over softhsmv3 (pqctoday fork)

> **This is the pqctoday fork.** It extends the upstream
> [`heiko/openpgp-pkcs11`](https://codeberg.org/heiko/openpgp-pkcs11) Sequoia
> bridge with **post-quantum OpenPGP** — draft-ietf-openpgp-pqc composite
> signing (`MLDSA65_Ed25519` algo 30, `MLDSA87_Ed448` algo 31) and composite
> ML-KEM decryption (`MLKEM768_X25519` algo 35, `MLKEM1024_X448` algo 36) —
> where the private key stays inside the **softhsmv3** PKCS#11 token. The
> original upstream README follows below for reference — note its examples use
> upstream SoftHSMv2 (`/usr/lib64/softhsm/libsofthsm.so`, YubiKey); in this repo
> the module is **`libsofthsmv3`** and the PQC path is what's exercised.
>
> **How to test the PQC bridge against softhsmv3** (real HSM smoke tests):
> - `openpgp/smoke-mldsa/` — proves softhsmv3 `C_Sign` returns a 3309-byte
>   ML-DSA-65 signature (see its README for the exact `softhsm2-util` +
>   `cargo run` commands; requires `cmake --build build` first).
> - `openpgp/smoke-mlkem/` — ML-KEM decapsulation path.
> - `openpgp/smoke-import/` — key import/custody.
> - `openpgp/spike-pqc/` — the wire-format spike (RFC 9580 v6, algorithm ID 30).
> - Design: `openpgp/docs/PQC_PGP_IMPLEMENTATION_PLAN.md` (authoritative;
>   supersedes `SEQUOIA_PQC_MIGRATION.md`).

---

# Using PKCS #&#8203;11 hardware security devices for OpenPGP operations

[![status-badge](https://ci.codeberg.org/api/badges/heiko/openpgp-pkcs11/status.svg)](https://ci.codeberg.org/heiko/openpgp-pkcs11)
[![Mastodon](https://img.shields.io/badge/mastodon-read-5da168.svg)](https://fosstodon.org/@hko)
[![Matrix: #openpgp-card:matrix.org](https://matrix.to/img/matrix-badge.svg)](https://matrix.to/#/#openpgp-card:matrix.org)

**NOTE: This project is a work in progress, it is not yet intended for production use!**

This repository contains two Rust crates:

- In [`lib` (openpgp-pkcs11-sequoia)](https://codeberg.org/heiko/openpgp-pkcs11/src/branch/main/lib):
  a library for using PKCS #&#8203;11 devices in an OpenPGP context.  
  [![crates.io openpgp-pkcs11-sequoia](https://img.shields.io/crates/v/openpgp-pkcs11-sequoia.svg)](https://crates.io/crates/openpgp-pkcs11-sequoia)
  [![docs.rs openpgp-pkcs11-sequoia](https://img.shields.io/badge/docs.rs-openpgp--pkcs11--sequoia-66c2a5?logo=docs.rs)](https://docs.rs/openpgp-pkcs11-sequoia)

- In [`cli` (openpgp-pkcs11-tools)](https://codeberg.org/heiko/openpgp-pkcs11/src/branch/main/cli):
  the experimental `opgpkcs11` CLI tool for performing OpenPGP operations on PKCS #&#8203;11 devices.  
  [![crates.io openpgp-pkcs11-tools](https://img.shields.io/crates/v/openpgp-pkcs11-tools.svg)](https://crates.io/crates/openpgp-pkcs11-tools)

See https://codeberg.org/heiko/pkcs11-openpgp-notes for more context.
