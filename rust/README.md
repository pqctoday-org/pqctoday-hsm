# softhsmrustv3 — the Rust PKCS#11 engine

`softhsmrustv3` is the second crypto engine in this repository (alongside the
C++ engine in `../src/`). It is:

- the **WASM crypto path** for the in-browser HSM (`../wasm/`), and
- the **production backend for the KMIP server and CACP policy engine**
  (`../kmip/`).

It implements the PKCS#11 v3.2 surface — ML-KEM, ML-DSA, SLH-DSA, stateful
HSS/LMS, AES/HMAC, RSA/ECDSA/EdDSA, SP800-108 KBKDF — plus a vendor
`CKM_HPKE` / `CKM_HPKE_KEM_KEY_PAIR_GEN` mechanism pair (full RFC 9180 HPKE
+ a PQ/T hybrid KEM combiner, driven through `C_EncapsulateKey`/
`C_DecapsulateKey`; provisional codepoints, not part of PKCS#11 v3.2, this
engine only — see `src/native/hpke.rs`) — and carries its own checked-in
conformance evidence.

## Build

```bash
# Native library + tests
cd rust
cargo build --release
cargo test                     # engine unit/integration tests

# WASM bundle (bundler target) — the ACVP feature enables the conformance KATs.
# Runs in the OrbStack/Docker `pqc-rust` container if cargo isn't on PATH.
RUSTFLAGS="-C link-arg=-zstack-size=2097152" \
  wasm-pack build --target bundler --out-dir pkg --dev -- --features acvp
```

See also `build-wasm-bundle.sh` for the packaged bundle build.

## Testing & conformance

| Harness | What it checks |
|---|---|
| `cargo test` | Engine unit + integration tests |
| `node test_p11_conformance.js` | **PKCS#11 v3.2 conformance** — 999 checks / 51 sections, exact `CKR_*` codes in spec priority order, PQC keygen/param-set, SP800-108 KBKDF, message-based crypto |
| `node test_kat_parity.js` | KAT parity vs the C++ engine |
| `node test_r36_paramset.js` | R3.6 parameter-set coverage |

Regenerate the conformance report with `../scripts/local-gate.sh --rust-p11`
(the harness itself now writes the report file — see `writeReport()` in
`test_p11_conformance.js`). Results and the exact procedure live in
[`RUST_P11_V32_CONFORMANCE_REPORT.md`](RUST_P11_V32_CONFORMANCE_REPORT.md)
(**999 passed / 0 failed** as of engine commit `7018794a9504`). The native `CK_*`
ABI compliance plan (315/0/0, parity with C++) is in
[`CK_ABI_NATIVE_COMPLIANCE_PLAN.md`](CK_ABI_NATIVE_COMPLIANCE_PLAN.md). The
native Rust API is described in [`docs/NATIVE_API.md`](docs/NATIVE_API.md).

## Patched crates

FIPS reference crates carrying local fixes live alongside the engine:
`fips204-patched/` (ML-DSA), `fips205-patched/` (SLH-DSA),
`hbs-lms-patched/` (stateful HSS/LMS). See each crate's README.
