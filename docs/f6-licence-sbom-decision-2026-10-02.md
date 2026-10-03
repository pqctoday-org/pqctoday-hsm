# F6 — licence and dependency (SBOM) decision for K2–K4

Date: 2026-10-02 · Gate: plan item F6 / remaining-gaps register G3.

## 1. Licence finding

The repository root `LICENSE` is BSD-2-Clause. Four files carried
`SPDX-License-Identifier: GPL-3.0-only`. Three of them are in the Rust engine that ships
in the WASM bundle:

| File | In shipped Rust engine? | Commit authors | Derived from GPL code? |
|---|---|---|---|
| `src/lib/vendor_mechanisms.h` | No — Rust has no `build.rs`/bindgen; `rust/src/constants.rs` mirrors values by hand | Eric Amador, pqctoday | No derivation stated |
| `rust/src/crypto/keccak.rs` | Yes | pqctoday | No derivation stated |
| `rust/src/crypto/lms.rs` | Yes | Eric Amador, eramusa, pqctoday | No — "Supports all SP 800-208 parameter sets" |
| `rust/src/crypto/split_key.rs` | Yes | Eric Amador | No — "implemented directly from KMIP 3.0" |

## 2. Decision

Owner decision (2026-10-02, in session): **relicense to BSD-2-Clause, because the project
owner is the sole author.** Applied to all four files, since the same facts hold for each.
The owner named the header in the decision; the three Rust files were extended to it on
identical facts. **Revert those three if that extension is not wanted.**

Out of the replication scope and **unchanged**: GPL-marked files in `kmip/`, `tls/` and
`openmls-provider/` (`kmip/src/server/secp384r1mlkem1024.rs`,
`tls/src/secp384r1mlkem1024.rs`, `openmls-provider/lib/tests/software_kats.rs`). They need
their own review.

## 3. Dependency delta

The new normal dependencies are optional and enabled only by the non-default
`educational-replication` feature. Graph delta for
`cargo tree -e normal -p softhsmrustv3 --features educational-replication` against the
default build:

| Crate | Version | Licence |
|---|---|---|
| x509-cert | 0.2.5 | Apache-2.0 OR MIT |
| der_derive (proc-macro, build-time) | 0.7.3 | Apache-2.0 OR MIT |
| flagset | 0.4.7 | Apache-2.0 |
| sha1 | 0.10.6 | MIT OR Apache-2.0 |

`der 0.7.10`, `spki 0.7.3` and `const-oid 0.9.6` were already in the shipped graph through
existing dependencies, and were pinned by the K0A spike's dev-dependencies. All delta
licences are permissive and compatible with BSD-2-Clause. `Cargo.lock` is unchanged by
the feature, since the versions were already resolved for KMIP and the K0A spikes.

Not done here: no `cargo-deny`/`cargo-audit` is installed on the host, so advisory and
yanked status is **not yet machine-checked**. That is the remaining F6 item before any
release that enables the feature.
