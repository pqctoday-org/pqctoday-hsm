# Changelog

All notable changes to the `openssh-pkcs11` connector are documented in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added — SLH-DSA-SHA2-128s SSH authentication, realigning this connector with the sandbox (2026-07-27)

This connector's patch set had silently fallen behind the copy it was forked
from, leaving every build that consumes it with less SSH PQC capability than
the sandbox's own network image.

- **`ssh-slhdsa.c` + the full SLH-DSA patch block are now here.**
  `patches/apply_mldsa_patches.py` gains 12 further patch steps implementing
  SLH-DSA-SHA2-128s host-key and user authentication
  (`draft-josefsson-ssh-sphincs-02`), alongside the existing ML-DSA-65
  (`draft-sfluhrer-ssh-mldsa-06`) support. Signature verification runs through
  OpenSSL's `SLH-DSA-SHA2-128s` provider (requires OpenSSL ≥ 3.5; the WASM
  build already links 3.6.x).
- **`build-wasm.sh` now copies `ssh-slhdsa.c` alongside `ssh-mldsa.c`.** This is
  required, not cosmetic: the patch script's S1 step rewrites `Makefile.in` to
  reference both `ssh-mldsa.o` and `ssh-slhdsa.o`, so omitting the source file
  fails the build at link time rather than at patch time.

**Why it drifted.** This connector was imported from `pqctoday-sandbox` on
2026-04-18, one day after ML-DSA-65 SSH auth landed there. The sandbox added
SLH-DSA on 2026-05-25; this copy was never updated, so it stayed ML-DSA-only
for roughly nine weeks with nothing recording the difference.

**Guarding against a recurrence.** `patches/apply_mldsa_patches.py` is now
**byte-identical** to `pqctoday-sandbox/docker/apply_mldsa_patches.py`. A plain
`diff` between the two files is the drift check — please keep them identical
when either side changes.

**Verification.** Applied against a clean `V_10_3_P1` checkout: 24 edits,
exit 0. All nine touched files (`Makefile.in`, `myproposal.h`, `sshkey.h`,
`sshkey.c`, `ssh-pkcs11.c`, `sshd-auth.c`, `sshd.c`, `ssh-mldsa.c`,
`ssh-slhdsa.c`) are byte-identical to a sandbox-patched tree. Not yet compiled
or WASM-rebuilt.

**Known follow-up.** On a future OpenSSH 10.4 bump, the `sshkey.h` anchor in
step 3 needs widening to `\s+KEY_ED25519_SK_CERT,\n(?:\s+KEY_\w+,\n)*\s+KEY_UNSPEC`
— upstream 10.4 inserts `KEY_MLDSA44_ED25519[_CERT]` between the current anchor
lines. Because the two copies are now identical, that fix can be made once and
copied across.

### Added — selectable KEX + host-key profile and an in-WASM PKCS#11 trace tap (2026-06-27)

For the hub playground integration:

- **`set_handshake_config(kex, hostalg)`** — the driver now runs a selectable
  profile instead of the hardcoded combo. Two host-key types provision on the
  token and sign via the real provider path: `ssh-mldsa-65` (ML-DSA-65,
  `CKM_ML_DSA`) and `ecdsa-sha2-nistp256` (ECDSA P-256, `CKM_ECDSA`); KEX is any
  compiled algorithm (`mlkem768x25519-sha256`, `curve25519-sha256`,
  `ecdh-sha2-nistp*`). Enables a real-vs-real classical/PQC comparison in the UI.
- **PKCS#11 trace tap** — `pkcs11_static.c` hands OpenSSH's provider a wrapped
  function list that emits a `pkcs11` event per `C_Login` / `C_FindObjects` /
  `C_GetAttributeValue` / `C_SignInit` / `C_Sign` before delegating to softhsm,
  so the hub can render the genuine call sequence (including the two `C_Sign`
  operations) without touching the generated OpenSSH source. The provisioning
  `C_GenerateKeyPair` is emitted from the shim.

### Added — the WASM bundle now runs a real, end-to-end post-quantum SSH handshake (2026-06-27)

The OpenSSH WASM build is no longer a scaffold: it links cleanly and runs a
genuine post-quantum SSH session entirely in the browser sandbox, with both
private keys staying inside the in-WASM software HSM the whole time. Proven by
the `sm1-smoke.cjs` node harness in four steps:

- **SM1 — real ML-DSA-65 signature from the token.** The bundle brings up
  softhsmv3 in-instance (init token, SO/USER login, `C_GenerateKeyPair` for an
  ML-DSA-65 host key), then produces a 3,309-byte signature via `CKM_ML_DSA`
  `C_Sign`. The private key is generated on, and never leaves, the token.
- **SM2 — real key exchange to NEWKEYS.** A genuine in-process
  `mlkem768x25519-sha256` (ML-KEM-768 + X25519) key exchange runs OpenSSH's own
  KEX state machine to NEWKEYS on both client and server sides.
- **SM3 — the handshake is host-authenticated by the HSM.** The `ssh-mldsa-65`
  host key is fetched from the token through OpenSSH's **real `ssh-pkcs11.c`
  provider path** (not a bypass), and the exchange-hash signature is produced by
  the token's `C_Sign` — the demo's whole point: the server proves its identity
  with a key it cannot read.
- **SM4 — real publickey login to USERAUTH_SUCCESS.** A genuine RFC 4252
  publickey userauth completes: the user's ML-DSA-65 key (also on the token)
  signs the real signed-data blob via `C_Sign` (3,329-byte SSH wire format), the
  server verifies it with `sshkey_verify`, and the exchange reaches
  `USERAUTH_SUCCESS`.

Honest scope: every security-critical operation is real OpenSSH code (the
signed-data format, both `C_Sign` signatures, `sshkey_verify`, the KEX). Only
the message orchestration and a minimal accept policy are driven by the shim,
because OpenSSH's auth loop is bound to an OS (PAM, privsep, accounts) that does
not exist in a browser. No PTY/shell — handshake-only by design.

### Changed

- **`scripts/build-wasm.sh` — link wall cleared; bundle now builds.** The
  remaining wasm-ld failures were resolved: a `setproctitle` cache override, a
  Step 3.5 strip of 13 leaked `HAVE_*` link symbols, compiling the shims through
  the Makefile's own `.c.o` rule (so `<sys/queue.h>` and the build CFLAGS
  resolve), and linking `sshd` with the static softhsm archive,
  `--pre-js softhsm_pre.js` (writes the softhsmv3 config + token dirs into
  MEMFS), `-Wl,--wrap,lib_contains_symbol`, and `___wrap_main` as the exported
  entry (native `main()` is GC'd; the harness calls it via `ccall`).
- **`wasm-shims/pkcs11_static.c` — returns the real function-list handle.**
  The dlopen-static bridge now hands back `(void*)C_GetFunctionList` (the HSM's
  genuine handle) instead of a placeholder, so OpenSSH's provider walks the real
  PKCS#11 entry point.
- **Relocated into `pqctoday-hsm` as `openssh-pkcs11/`.** Previously maintained
  in the standalone `pqctoday/pqctoday-openssh` repo; consolidated alongside
  the other PKCS#11 connectors (`strongswan-pkcs11/`, `JavaJCE/`, `openpgp/`,
  `webrpc/`). Build now runs from the hsm root:
  `bash openssh-pkcs11/scripts/build-wasm.sh`.
- **`scripts/build-wasm.sh` — major Emscripten-portability fixes (partial):**
  - Dropped `-s SHARED_MEMORY=1` / `-s PTHREAD_POOL_SIZE=2`. softhsmv3 and
    OpenSSL WASM archives were compiled single-threaded (no `+atomics` Wasm
    feature), so pthread-enabled linkage was refused by wasm-ld. JS-side
    `SharedArrayBuffer` transport via `socket_wasm.c` still works through
    asyncify imports.
  - Added `--host=wasm32-unknown-emscripten` and `--without-openssl-header-check`.
  - Post-autoreconf Python patch injects `cross_compiling=yes` into `configure`
    right before the OpenSSL header/library version tests. Needed because
    emcc's node fallback lets autoconf's probes "run" (reading/writing
    MEMFS, not host FS), which confuses the version-detection conftest.
  - Expanded CFLAGS with `-Wno-error=` for clang 15+ default-errors:
    `implicit-function-declaration`, `int-conversion`,
    `incompatible-pointer-types`, `incompatible-function-pointer-types`,
    `implicit-int`, `deprecated-declarations`.
  - Added 18 `ac_cv_func_*=no` / `ac_cv_header_*=no` autoconf-cache
    overrides so OpenSSH routes BSD functions (`arc4random`, `bcrypt_pbkdf`,
    `recallocarray`, `strtonum`, `fmt_scaled`, `readpassphrase`, `closefrom`,
    `freezero`, `timingsafe_bcmp`, `nlist`, `getrrsetbyname`) through
    `openbsd-compat/` instead of linking to Emscripten's header-less musl
    symbols.

### Known Issues

- **Not yet wired into the hub playground.** The real handshake is proven by
  the node smoke harness (`sm1-smoke.cjs`) against the freshly built
  `dist/openssh-server.{js,wasm}`, but the hub's SSH playground still runs the
  old TypeScript model. Integration is the next step: produce the bundle into
  `pqctoday-hub/public/wasm/` under the hub's naming + provenance-manifest
  convention and swap the loader (`src/wasm/openssh.ts`) onto the real path.
- **`dns.c` BSD-compat build quirk (resolved during the link work).** The
  earlier `dns.c` failure (`struct rrsetinfo` / `ERRSET_*` undeclared, from the
  ignored `ac_cv_func_getrrsetbyname=no` cache override) no longer blocks the
  build; the `sshd` link path used by the WASM bundle does not pull it in.

### Added

- **Initial release** — ML-DSA-65 patches and WASM build scaffolding for
  OpenSSH, implementing
  [draft-sfluhrer-ssh-mldsa-06](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/).
- **`patches/ssh-mldsa.c`** — new OpenSSH key-type module implementing the
  `ssh-mldsa-65` algorithm (NIST Category 3, FIPS 204). Public-key format is
  the raw 1,952-byte ML-DSA pk; signing is PKCS#11-only and delegates to
  `pqctoday-hsm` softhsmv3 via `CKM_ML_DSA` (0x1d).
- **`patches/apply_mldsa_patches.py`** — Python driver that applies the full
  set of source-tree patches to an extracted `openssh-portable` tree
  (`sshkey.c`, `ssh-pkcs11.c`, `Makefile.in`, etc.).
- **`wasm-shims/sshd_wasm_main.c`** — privsep-free `sshd` entry point for the
  WASM build. Replaces `fork()` / PAM / PTY / `setuid()` with a single-transport
  handshake running over a SharedArrayBuffer socket shim.
- **`wasm-shims/pkcs11_static.c`** — static `C_GetFunctionList` linkage against
  softhsmv3 so the WASM bundle ships self-contained without `dlopen`.
- **`wasm-shims/{posix_stubs,socket_wasm}.c`** — POSIX/networking stubs for
  Emscripten, bridging OpenSSH's file-descriptor I/O to the browser's
  SharedArrayBuffer transport.
- **`scripts/build-wasm.sh`** — end-to-end Emscripten build driver producing
  `openssh-client.{js,wasm}` and `openssh-server.{js,wasm}` bundles.
- **`scripts/copy-to-hub.sh`** — deploys built WASM bundles into the
  `pqctoday-hub` repo for the SSH ML-DSA-65 learning scenario.
