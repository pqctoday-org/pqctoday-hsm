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
release that enables the feature. **Done 2026-10-03; see §4.**

## 4. Machine check (2026-10-03)

Run on main `496f9e52` plus this change, on the M4 Pro, with `cargo-audit 0.22.2` and
`cargo-deny 0.20.2` installed into a scratch directory (not part of the gate container).
The policy is checked in as `rust/deny.toml`, so the run is reproducible from `rust/`:

```text
cargo audit
cargo deny check                                  # default build
cargo deny --features educational-replication check
cargo deny --features educational-fhe check       # implies replication
```

The graph covers macOS arm64, Linux x86_64/aarch64 and wasm32. The advisory database was
fetched at run time.

The crate now declares `license = "BSD-2-Clause"` in `rust/Cargo.toml`, matching the root
`LICENSE`.

| Check | Default | + `educational-replication` | + `educational-fhe` |
|---|---|---|---|
| Licences | ok | ok | ok |
| Sources | ok | ok | ok |
| Advisories | 1 vulnerability | 1 vulnerability | 1 vulnerability, 2 unmaintained |
| Bans | wildcard error, duplicate-version warnings | same | same |

Findings:

1. **RUSTSEC-2023-0071, `rsa 0.9.10` (Marvin timing side channel)**: a vulnerability, no
   fixed upstream release. The engine depends on `rsa` directly, so it is in **every**
   build, including the default one. It predates and is unrelated to K2–K4 and FHE. It
   matters wherever RSA private-key decryption or signing runs on attacker-timed inputs.
   It needs its own owner decision (accept for the educational engine, route RSA private
   operations to a constant-time backend, or drop RSA private operations from the Rust
   path). It is **not** waived here.
2. **RUSTSEC-2025-0141, `bincode 1.3.3` (unmaintained)** and **RUSTSEC-2024-0436,
   `paste 1.0.15` (unmaintained)**: both arrive only through `tfhe =1.8.1`, so only with
   `educational-fhe`. They are maintenance notices, not vulnerabilities, and no
   replacement exists without a TFHE-rs upgrade. Accepted for the educational FHE
   feature, and to be re-checked whenever the `tfhe` pin moves.
3. **Wildcard**: `classic-mceliece-multi = { path = ... }` has no version. That matters
   only if the crate is published to crates.io, which it is not (it ships as WASM/npm
   and native libraries).
4. **Duplicates**: two generations of RustCrypto crates (for example `der`/`spki`
   0.7/0.8, `digest`, `cipher`) coexist. These are warnings, a size cost and not a
   correctness issue.

Licence result: every crate in all three graphs is under a licence on the `deny.toml`
allow-list, all compatible with BSD-2-Clause. The only non-OSI-standard entry is TFHE-rs's
BSD-3-Clause-Clear (educational use only, because of the upstream patent notice), which
§3 and the FHE P2 record already state.
