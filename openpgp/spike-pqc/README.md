<!-- SPDX-License-Identifier: CC0 -->
# spike-pqc — feasibility spike for P0-SEQUOIA-PQC-05

Throwaway proof that the upstream Sequoia `pqc` branch emits **wire-correct**
PQC OpenPGP: a detached signature made with a `MLDSA65_Ed25519` (composite,
draft-ietf-openpgp-pqc v17, the MUST-implement scheme) v6 key must carry
**public-key-algorithm == 30** on the wire.

This crate is intentionally **not** part of the `openpgp/` workspace (it has its
own `[workspace]` table) so its bleeding-edge git dependency does not contaminate
the bridge's `Cargo.lock`. HSM backing is **out of scope** for the spike — key
generation is in software; the only thing under test is the upstream wire format.

## Run

```bash
export OPENSSL_DIR=$(brew --prefix openssl@3)
export PKG_CONFIG_PATH="$OPENSSL_DIR/lib/pkgconfig"
export DYLD_LIBRARY_PATH="$OPENSSL_DIR/lib"   # macOS, for the ossl backend at runtime
cargo run
```

Exit 0 + `PASS:` line == proven. The dependency is pinned by commit SHA in
`Cargo.toml` and `Cargo.lock`; PQC requires the `crypto-openssl` backend
(OpenSSL >= 3.5 — verified against 3.6.2) because Sequoia's default Nettle
backend has no ML-DSA/ML-KEM.

## Result (captured 2026-06-14)

```
sequoia-openpgp 2.2.0-pqc.1, pqc branch @ 3d05138bf1536e63886e7a079fa50aeb080ab573
primary key pk_algo  = MLDSA65_Ed25519 (id 30)
signature packet     = version=6, pk_algo=MLDSA65_Ed25519 (id 30)
de-armored bytes     = c2 cc c5 06 00 1e 0a ...
                                   ^^ ^^ ^^
                                   v6 type algo=0x1e(30)
PASS: signature public-key-algorithm == 30
```

See `../docs/PQC_PGP_IMPLEMENTATION_PLAN.md` §1 for the full analysis.
