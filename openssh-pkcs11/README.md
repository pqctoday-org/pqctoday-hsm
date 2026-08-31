# openssh-pkcs11

OpenSSH PKCS#11 connector for softhsmv3. ML-DSA (44/65/87) and SLH-DSA
(8 of the 12 FIPS 205 parameter sets — see [Parameter set coverage](#parameter-set-coverage))
patches, plus WASM build scaffolding, implementing
[draft-sfluhrer-ssh-mldsa-08](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/)
and [draft-josefsson-ssh-sphincs-02](https://datatracker.ietf.org/doc/draft-josefsson-ssh-sphincs/).

This subfolder contains the minimal custom code needed to:

1. Patch `openssh-portable` with ML-DSA (`ssh-mldsa-44`/`-65`/`-87`) and
   SLH-DSA (`ssh-slh-dsa-{sha2,shake}-{128,256}{s,f}`) key/signature types.
2. Drive signing through the softhsmv3 PKCS#11 backend provided by the parent
   `pqctoday-hsm` repo (`CKM_ML_DSA` 0x1d, `CKM_SLH_DSA` 0x2e).
3. Compile both the client (`ssh`) and a privsep-free server
   (`sshd_wasm_main.c`) to WebAssembly for in-browser demos in
   [`pqctoday-hub`](https://github.com/pqctoday/pqctoday-hub).

## Parameter set coverage

| Family | Parameter sets | Status |
| --- | --- | --- |
| ML-DSA | 44, 65, 87 (all 3, FIPS 204) | Full |
| SLH-DSA | SHA2/SHAKE × {128,256} × {s,f} (8 of 12 FIPS 205 sets) | Partial — see below |
| SLH-DSA | SHA2/SHAKE × 192 × {s,f} | **Not exposed over SSH** |

The engine (`SoftHSM_slots.cpp`) implements all 12 standard FIPS 205 SLH-DSA
parameter sets. `draft-josefsson-ssh-sphincs-02` — the only IETF draft
defining SSH wire-format names for SLH-DSA — does **not** define standalone
`ssh-slh-dsa-sha2-192s`/`-192f`/`shake-192s`/`-192f` names; its own 192-bit
entries (`ssh-slh-dsa-{sha2,shake}-192-24`) reference a *different*,
non-FIPS-205 parameter family from NIST SP 800-230 IDP ("Additional SLH-DSA
Parameter Sets for Limited Signature Use Cases") that the engine does not
implement (different key/signature sizes; see the draft's Table 3 vs.
`SoftHSM_slots.cpp:1252-1273`). Rather than invent a name the draft doesn't
specify, the 192-category standard parameter sets are left unexposed over SSH
pending a future draft revision.

## Layout

| Path | Description |
| --- | --- |
| [`patches/`](patches/) | `ssh-mldsa.c` (ML-DSA-44/65/87 key-type module), `ssh-slhdsa.c` (8 SLH-DSA key-type modules), `apply_mldsa_patches.py` (applies the source-tree patches to `openssh-portable`), `native_paramsweep_test.c` (native, non-WASM, end-to-end handshake test for every parameter set — see `scripts/native-verify-paramsweep.sh`) |
| [`wasm-shims/`](wasm-shims/) | WASM-specific shims: `pkcs11_static.c` (static softhsmv3 linkage), `posix_stubs.c`, `socket_wasm.c` (SharedArrayBuffer transport), `sshd_wasm_main.c` (privsep-free server entry point; `HOSTKEY_VARIANTS` table drives all 11 PQC parameter sets + ECDSA P-256) |
| [`scripts/`](scripts/) | `build-wasm.sh` (Emscripten build driver), `copy-to-hub.sh` (deploy WASM bundles to the hub app), `native-verify-paramsweep.sh` (native build + real handshake sweep across every parameter set; no Emscripten required) |

`build/` and `dist/` are `.gitignore`'d — upstream OpenSSH sources and
generated WASM bundles live there but are rebuilt on demand (bundles ship via
the hub deploy pipeline, not git history).

## Build

Run from the `pqctoday-hsm/` repo root (after the softhsmv3 WASM archive and
OpenSSL WASM prefix have been built):

```bash
bash openssh-pkcs11/scripts/build-wasm.sh
bash openssh-pkcs11/scripts/copy-to-hub.sh
```

See the script headers for required environment variables (`OPENSSL_WASM`,
`SOFTHSM_WASM`, `HUB`).

## Verification

Two independent paths, both driving the same real KEX + RFC 4252 publickey
userauth logic against the real PKCS#11 provider path:

- **WASM** (requires Emscripten): `bash scripts/build-wasm.sh`, then
  `node sm1-smoke.cjs && node sm5-slhdsa-smoke.cjs && node sm6-paramsweep-smoke.cjs`.
- **Native, no Emscripten required**: `bash scripts/native-verify-paramsweep.sh`
  — builds `openssh-portable` natively against a real OpenSSL 3.5+, links
  `patches/native_paramsweep_test.c` (a native port of
  `wasm-shims/sshd_wasm_main.c`'s handshake driver) against the real native
  softhsmv3 build, and drives a real handshake + userauth round trip for all
  11 ML-DSA/SLH-DSA parameter sets in one run. See `CHANGELOG.md`'s
  2026-08-31 entry for the full pass/fail table and byte-size citations.

## History

This connector previously lived as the standalone repo
`pqctoday/pqctoday-openssh`. It has been folded into `pqctoday-hsm` alongside
the other PKCS#11 consumers (`strongswan-pkcs11/`, `JavaJCE/`, `openpgp/`,
`webrpc/`) so that all HSM connectors are maintained together.

## License

BSD 2-Clause — see [`LICENSE`](LICENSE). Files derived from `openssh-portable`
retain their upstream BSD/ISC terms.
