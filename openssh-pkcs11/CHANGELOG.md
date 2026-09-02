# Changelog

All notable changes to the `openssh-pkcs11` connector are documented in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added — ML-DSA-44/87 and 8-of-12 SLH-DSA parameter set coverage (2026-08-31)

This connector previously wired only ML-DSA-65 and SLH-DSA-SHA2-128s, even
though the engine already supported all 3 ML-DSA and all 12 FIPS 205 SLH-DSA
parameter sets, and the governing IETF drafts already named most of them.
Remediation plan §3 (`docs/remediation-plan-provider-wrapper-coverage-gaps-2026-08-31.md`).

**Code changes:**
- `patches/ssh-mldsa.c` — generalized from a single hardcoded ML-DSA-65
  implementation to a `DEFINE_MLDSA_IMPL(...)` macro instantiated 3 times
  (`ssh-mldsa-44`, `ssh-mldsa-65`, `ssh-mldsa-87`), each producing its own
  `sshkey_impl` (cleanup/equal/serialize/deserialize/copy/verify), sized per
  parameter set.
- `patches/ssh-slhdsa.c` — same generalization via `DEFINE_SLHDSA_IMPL(...)`,
  instantiated 8 times: SHA2/SHAKE × {128,256} × {s,f}.
- `patches/apply_mldsa_patches.py` — regenerated (21 anchors declared,
  self-counted by the script; some steps that were previously chained per
  algorithm are now consolidated into one multi-case insertion). Adds:
  `sshkey.h` enum values for all 11 new key types; `sshkey.c` externs +
  `keyimpls[]` registration; `myproposal.h` default proposal entries for all
  11; and, in `ssh-pkcs11.c`, a **parameter-set dispatch table**
  (`mldsa_variants[]` / `slhdsa_variants[]`) so the shared `CKK_ML_DSA` /
  `CKK_SLH_DSA` PKCS#11 key types resolve to the right variant via
  `CKA_PARAMETER_SET` or (preferentially) the self-describing decoded SPKI —
  `pkcs11_fetch_mldsa_pubkey`/`pkcs11_sign_mldsa` and their SLH-DSA
  equivalents are now single functions covering every parameter set in their
  family, not one function per parameter set.
- `wasm-shims/sshd_wasm_main.c` — the 3-way `HOSTKEY_MLDSA65/ECDSA_P256/
  SLHDSA_128S` enum replaced with a `HOSTKEY_VARIANTS[]` table (12 entries:
  11 PQC parameter sets + classical ECDSA P-256), so `set_handshake_config()`
  can select any of them by name; `sm1_provision()`/`sm1_prove_sign()`/
  `drive_kex()` are now table-driven instead of hardcoded per-type branches.
- `sm6-paramsweep-smoke.cjs` (new) — generalizes the `sm1`/`sm5` smoke-test
  pattern across all 11 parameter sets in one harness (fresh WASM instance
  per variant, since `set_handshake_config` only takes effect before
  `__wrap_main`). **Not executed** — see Verification below.
- `patches/native_paramsweep_test.c` + `scripts/native-verify-paramsweep.sh`
  (new) — a native (non-WASM) port of `sshd_wasm_main.c`'s in-process
  `drive_kex()`/`do_userauth()` driver, used for real verification (below)
  because this environment has no Emscripten toolchain.
- `README.md` / `STATUS.md` — documentation catch-up: SLH-DSA disclosed
  (previously undocumented, "ML-DSA-65 patches" only), `draft-sfluhrer-ssh-mldsa`
  citation bumped `-06` → `-08`, `draft-ietf-sshm-mlkem-hybrid-kex-10`
  attributed near the KEX section, and a new "Parameter set coverage" table
  explaining the SLH-DSA 192 exclusion (below).

**Byte sizes used, and where they came from** (not assumed — cross-checked
against two independent sources: the vendored OpenSSL 3.6.3 this connector
and the engine both build against, and the live IETF draft text):

| Algorithm | pk (bytes) | sig (bytes) | Source |
| --- | --- | --- | --- |
| ML-DSA-44 | 1312 | 2420 | `deps/openssl-src/openssl-3.6.3/include/crypto/ml_dsa.h`; confirmed against live `draft-sfluhrer-ssh-mldsa-08` §4/§6 |
| ML-DSA-65 | 1952 | 3309 | same (unchanged from the existing implementation) |
| ML-DSA-87 | 2592 | **4627** | same. **Note**: the remediation plan's placeholder value was 4595 — wrong; the real FIPS 204 value, confirmed by both the vendored OpenSSL source and the live draft, is 4627 |
| SLH-DSA-{SHA2,SHAKE}-128s | 32 | 7856 | `deps/openssl-src/openssl-3.6.3/crypto/slh_dsa/slh_params.c` (`OSSL_SLH_DSA_128S_*`); confirmed against live `draft-josefsson-ssh-sphincs-02` §4/§6/§10 Table 3 |
| SLH-DSA-{SHA2,SHAKE}-128f | 32 | 17088 | same (`OSSL_SLH_DSA_128F_*`) |
| SLH-DSA-{SHA2,SHAKE}-256s | 64 | 29792 | same (`OSSL_SLH_DSA_256S_*`) |
| SLH-DSA-{SHA2,SHAKE}-256f | 64 | 49856 | same (`OSSL_SLH_DSA_256F_*`) |

**SLH-DSA scope: 8 of 12, not 12 of 12 — a real spec gap, not a shortcut.**
The task was to cover all 12 engine-supported FIPS 205 parameter sets, but
`draft-josefsson-ssh-sphincs-02` (fetched live and cross-checked against its
own IANA table, §10, and against a search of its full text for "192s"/
"192f" — zero occurrences in any of revisions 00/01/02) **does not define
standalone SSH wire-format names for the standard FIPS 205 192-category
parameter sets** (SHA2/SHAKE-192s/192f, pk=48, sig=16224/35664). Its own
192-bit table entries — `ssh-slh-dsa-sha2-192-24` and
`ssh-slh-dsa-shake-192-24` — are a **different, non-FIPS-205 parameter
family** from `[NIST.SP.800.230.IDP]` ("Additional SLH-DSA Parameter Sets
for Limited Signature Use Cases"), with different sizes entirely (pk=48,
sig=**7752**, per the draft's own Table 3) that this engine's OpenSSL 3.6.3
backend does not implement at all (`src/lib/pkcs11/pkcs11t.h`'s
`CKP_SLH_DSA_*` enumerates only the 12 standard sets — no `-24` variant
exists anywhere in this codebase). Inventing an `ssh-slh-dsa-{sha2,shake}
-192{s,f}` name not specified by the draft was explicitly out of scope
("don't invent a naming pattern the draft doesn't specify"), so the 192
category is left unexposed over SSH pending a future draft revision that
defines one. This is disclosed in `README.md`'s new "Parameter set coverage"
section, not silently dropped.

**Verification.** This environment has no Emscripten toolchain (`emcc` not
found), so the WASM smoke-test harnesses (`sm1-smoke.cjs`, `sm5-slhdsa-smoke.cjs`,
the new `sm6-paramsweep-smoke.cjs`) could not be executed. Real, non-WASM
verification was performed instead:

1. `python3 patches/apply_mldsa_patches.py --dry-run` and a real apply
   against a fresh `git clone --depth 1 --branch V_10_3_P1
   openssh-portable` — all 21 anchors applied cleanly.
2. A full **native** build (`autoreconf -i && ./configure --with-ssl-dir
   $(brew --prefix openssl@3) && make`, Homebrew OpenSSL 3.6.3 — the exact
   same OpenSSL version this repo vendors) — `ssh`, `sshd`, `ssh-keygen`,
   `ssh-pkcs11-helper`, etc. all compiled and linked cleanly against the
   generalized `ssh-mldsa.o`/`ssh-slhdsa.o`/`ssh-pkcs11.o`.
3. `native_paramsweep_test.c` — a native, non-WASM port of
   `sshd_wasm_main.c`'s in-process `drive_kex()`/`do_userauth()` logic —
   compiled and linked against the real patched OpenSSH object files and the
   **real native `libsofthsmv3.dylib`** (via genuine `dlopen`, OpenSSH's
   actual `pkcs11_add_provider` provider path — not a mock, not the WASM
   static-link shim). Reproducible via
   `bash scripts/native-verify-paramsweep.sh` from a clean `openssh-src`
   checkout.

   For **all 11** ML-DSA/SLH-DSA parameter sets (all 3 ML-DSA + all 8
   SLH-DSA this change adds), the harness: generated a real host+user
   keypair on the token, negotiated `mlkem768x25519-sha256` KEX with that
   exact host-key algorithm forced, ran OpenSSH's real KEX state machine to
   `NEWKEYS` (host signature via real `C_Sign`), then ran real RFC 4252
   `publickey` userauth to `USERAUTH_SUCCESS` (`sshkey_verify` on the
   server side) — asserting the exact FIPS 204/205 signature length at both
   steps. Result: **11/11 PASS, 0 failures.**

   | Algorithm | Result | Sig len asserted |
   | --- | --- | --- |
   | `ssh-mldsa-44` | PASS | 2420 |
   | `ssh-mldsa-65` | PASS | 3309 |
   | `ssh-mldsa-87` | PASS | 4627 |
   | `ssh-slh-dsa-sha2-128s` | PASS | 7856 |
   | `ssh-slh-dsa-sha2-128f` | PASS | 17088 |
   | `ssh-slh-dsa-shake-128s` | PASS | 7856 |
   | `ssh-slh-dsa-shake-128f` | PASS | 17088 |
   | `ssh-slh-dsa-sha2-256s` | PASS | 29792 |
   | `ssh-slh-dsa-sha2-256f` | PASS | 49856 |
   | `ssh-slh-dsa-shake-256s` | PASS | 29792 |
   | `ssh-slh-dsa-shake-256f` | PASS | 49856 |

**Not done / follow-up:** the WASM bundle (`dist/`) was not rebuilt or
smoke-tested here — `sm6-paramsweep-smoke.cjs` needs a real run the next
time this connector is built with `emcc` available (`bash
scripts/build-wasm.sh`, then `node sm1-smoke.cjs && node sm5-slhdsa-smoke.cjs
&& node sm6-paramsweep-smoke.cjs`). The `wasm-shims/sshd_wasm_main.c` changes
were reviewed for correctness against the same table-driven pattern the
native harness already proved works, but have not themselves been compiled.
SLH-DSA-{SHA2,SHAKE}-192{s,f} remain unexposed over SSH pending a future
draft revision (see above) — this is a scope decision to flag for review,
not an oversight.

**Update (2026-09-01): WASM harness run — 11/11 PASS.** With `dist/`
rebuilt, all three smoke harnesses now run and pass against the real WASM
bundle: `sm1-smoke.cjs` (ML-DSA-65) and `sm5-slhdsa-smoke.cjs`
(SLH-DSA-SHA2-128s) both reach `USERAUTH_SUCCESS`, and
`sm6-paramsweep-smoke.cjs` confirms all 11 ML-DSA/SLH-DSA parameter sets
end-to-end (`node sm6-paramsweep-smoke.cjs` → `SM6 OK — 11 parameter sets
verified end-to-end`), with the exact signature lengths from the table
above. This closes the "not executed" gap noted above — it was a real
Emscripten-toolchain limitation of that session's environment, not a defect
in the WASM shims.

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
`ssh-slhdsa.c`) are byte-identical to a sandbox-patched tree.

**Update (2026-07-29): WASM-rebuilt.** `ssh-mldsa.o`/`ssh-slhdsa.o` both link
cleanly into `dist/openssh-server.wasm` and `dist/openssh-client.wasm` as
part of the toolchain update below (see the `[0.19.0]` entry in the root
`CHANGELOG.md`). `sm1-smoke.cjs` (ML-DSA-65 host-key + user-key auth over a
real in-process PKCS#11-backed handshake) passes end-to-end.

**Update (2026-07-29): SLH-DSA now runtime-verified, not just compiled.**
The WASM test harness (`wasm-shims/sshd_wasm_main.c`) only ever drove
ML-DSA-65 or ECDSA P-256 — SLH-DSA had no path to actually run. Added a
third host-key profile (`HOSTKEY_SLHDSA_128S`) covering key generation,
signing, and host-key selection, selectable via
`set_handshake_config(kex, "ssh-slh-dsa-sha2-128s")`. New
`sm5-slhdsa-smoke.cjs` passes end-to-end: host key generated on the token,
KEX exchange-hash signed via `C_Sign` (7856 raw bytes, FIPS 205 §11 Table
2), NEWKEYS reached, publickey userauth to `USERAUTH_SUCCESS` with the user
key also token-signed and server-verified. See the `[0.20.0]` root
changelog entry for the full detail.

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
