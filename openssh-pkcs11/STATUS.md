# openssh-pkcs11 WASM build status

**Status: working — real end-to-end post-quantum SSH handshake** (updated
2026-08-31). This supersedes the earlier "scaffold" status; the notes below
reflect the current bundle. See `CHANGELOG.md` for the full detail.

**Algorithm coverage (2026-08-31):** ML-DSA-44/65/87 (all 3 FIPS 204
parameter sets) and SLH-DSA-{SHA2,SHAKE}-{128,256}{s,f} (8 of the 12 FIPS 205
parameter sets — the 192-category standard sets have no SSH wire name in the
governing draft; see `README.md#parameter-set-coverage`).

## Build infrastructure

- `emcc 5.0.2` (Homebrew) tested; OpenSSL 3.x WASM and the `softhsmv3` static
  archive are consumed from the paths `scripts/build-wasm.sh` expects.
- `bash openssh-pkcs11/scripts/build-wasm.sh` clones OpenSSH 10.3p1, applies the
  ML-DSA patches, runs autoreconf/emconfigure, and links cleanly. The prior
  link wall (leaked `HAVE_*` symbols, `setproctitle`/`getrrsetbyname` cache
  overrides, `<sys/queue.h>` include path) is resolved in the script.

## Current artifact state — driveable

The build produces a working bundle in `dist/`:

- `dist/openssh-server.{js,wasm}` and `dist/openssh-client.{js,wasm}` link and
  run. `___wrap_main` is exported and the harness invokes it via `ccall`.
- `wasm-shims/pkcs11_static.c` returns the HSM's genuine `C_GetFunctionList`
  handle, so OpenSSH walks the **real `ssh-pkcs11.c` provider path** — not a
  bypass.

## Verification — `node sm1-smoke.cjs` / `node sm5-slhdsa-smoke.cjs` / `node sm6-paramsweep-smoke.cjs`

The `sm1-smoke.cjs` harness proves a full PQ SSH session runs entirely in the
WASM sandbox, with both private keys staying inside the in-WASM software HSM:

- **SM1** — real ML-DSA-65 host key generated on the token; 3,309-byte signature
  via `CKM_ML_DSA` `C_Sign`. Key never leaves the token.
- **SM2** — genuine `mlkem768x25519-sha256` (ML-KEM-768 + X25519) key exchange
  runs OpenSSH's own KEX state machine to NEWKEYS on both sides.
- **SM3** — host authentication: the exchange-hash signature is produced by the
  token's `C_Sign` through the real provider path.
- **SM4** — real RFC 4252 publickey userauth to `USERAUTH_SUCCESS`; the user's
  ML-DSA-65 key signs the signed-data blob (3,329-byte SSH wire format) and the
  server verifies with `sshkey_verify`.

`sm5-slhdsa-smoke.cjs` repeats the same round trip for SLH-DSA-SHA2-128s.
`sm6-paramsweep-smoke.cjs` (added 2026-08-31) generalizes the same
KAT-length-assertion pattern across every newly-added ML-DSA/SLH-DSA
parameter set — **11/11 PASS** against the real WASM bundle (confirmed
2026-09-01; see `CHANGELOG.md`'s "Update (2026-09-01)" note for the run and
the full per-parameter-set verification table for the byte-size sources).

## Configurability

`set_handshake_config(kex, hostalg)` selects the profile at runtime: host keys
`ssh-mldsa-44`/`-65`/`-87`, `ssh-slh-dsa-{sha2,shake}-{128,256}{s,f}`, or
`ecdsa-sha2-nistp256` (ECDSA P-256), and any compiled KEX
(`mlkem768x25519-sha256`, `curve25519-sha256`, `ecdh-sha2-nistp*`) — enabling
a real classical-vs-PQC comparison. The `mlkem768x25519-sha256` method is
stock upstream OpenSSH behavior, standardized in
[draft-ietf-sshm-mlkem-hybrid-kex-10](https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/)
(WG-adopted) — this connector doesn't patch it in, it's exercised as-is. A
PKCS#11 trace tap emits a `pkcs11` event per `C_Login` / `C_FindObjects` /
`C_GetAttributeValue` / `C_SignInit` / `C_Sign` so a UI can render the genuine
call sequence.

## Honest scope

Every security-critical operation is real OpenSSH code (signed-data format, both
`C_Sign` signatures, `sshkey_verify`, the KEX). Only message orchestration and a
minimal accept policy are shim-driven, because OpenSSH's auth loop is bound to an
OS (PAM, privsep, accounts) that does not exist in a browser. No PTY/shell —
handshake-only by design.
