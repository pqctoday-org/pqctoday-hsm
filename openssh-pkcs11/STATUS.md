# openssh-pkcs11 WASM build status

**Status: working — real end-to-end post-quantum SSH handshake** (updated
2026-06-27). This supersedes the earlier "scaffold" status; the notes below
reflect the current bundle. See `CHANGELOG.md` for the full detail.

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

## Verification — `node sm1-smoke.cjs`

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

## Configurability

`set_handshake_config(kex, hostalg)` selects the profile at runtime: host keys
`ssh-mldsa-65` (ML-DSA-65) or `ecdsa-sha2-nistp256` (ECDSA P-256), and any
compiled KEX (`mlkem768x25519-sha256`, `curve25519-sha256`, `ecdh-sha2-nistp*`)
— enabling a real classical-vs-PQC comparison. A PKCS#11 trace tap emits a
`pkcs11` event per `C_Login` / `C_FindObjects` / `C_GetAttributeValue` /
`C_SignInit` / `C_Sign` so a UI can render the genuine call sequence.

## Honest scope

Every security-critical operation is real OpenSSH code (signed-data format, both
`C_Sign` signatures, `sshkey_verify`, the KEX). Only message orchestration and a
minimal accept policy are shim-driven, because OpenSSH's auth loop is bound to an
OS (PAM, privsep, accounts) that does not exist in a browser. No PTY/shell —
handshake-only by design.
