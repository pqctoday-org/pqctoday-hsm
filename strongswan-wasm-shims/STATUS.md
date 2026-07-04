# strongswan-wasm-shims — STATUS

> **Update 2026-07-03 — this is the actively-maintained WASM shim tree.** The
> "DO NOT SHIP / superseded by strongswan-wasm-v2-shims" framing below is from
> the 2026-04-18 reconstruction and is now **out of date**. Per `git log`, this
> directory received the most recent development (2026-06-12: RFC 7383
> fragmentation, RFC 9370 multi-KE, Tier A CHILD_SA stub kernel, race-free stub
> kernel registration), while `../strongswan-wasm-v2-shims/` has had no changes
> since 2026-05-20. Treat this tree — plus `../strongswan-6.0.5-wasm.patch` — as
> the current path and `git log`/the root `CHANGELOG.md` as the source of truth.
> The historical failure-mode notes below predate the June fixes; do not read
> them as the present state. (A full runtime re-verification is still owed.)

---

## Summary (historical — 2026-04-18)

The files in this directory are a **partial, non-functional reconstruction** of
custom C shims that were used in a prior session to build the working 12 MB
`strongswan.wasm` binary shipped under git tag `v2.80.0`
(commit `17c71b20`, size 11,994,532 bytes).

The original shims and source patches lived only in `/tmp/strongswan-build/`
and were erased when macOS cleared `/tmp` on 2026-04-14. The compiled binary
survives in git history; the sources do not.

## What's here

| File | Purpose | Status |
|---|---|---|
| `socket_wasm.c` / `.h` | SAB + Atomics network plugin | Compiles, runtime behavior not verified |
| `wasm_hsm_init.c` | softhsmv3 static token init | Compiles + slot discovery works; RSA-only keygen (ML-DSA branch is TODO) |
| `wasm_backend.c` | C config backend (replaces stroke/vici) | Compiles, runtime PSK handling is minimal (`%any` identity) |
| `pkcs11_wasm_rpc.c` | PKCS#11 function-table wrappers | Compiles, RPC wiring is straight-through stub |
| `README.md` | one-pager describing ABI | accurate for the above approximations |

## Known failure mode

When this infrastructure is used to build a replacement WASM (via
`../scripts/build-strongswan-wasm.sh`), the resulting binary boots the workers
successfully but aborts during `library_init → settings_parser_parse_string`
with an invalid-function-pointer crash in `array_destroy_function`. This
indicates the reconstructed `settings_lexer.c` patch (void→bool) and/or the
associated callers in the charon / libstrongswan core patches do not match
the real prior-session edits.

## Do not ship this

The build script (`scripts/build-strongswan-wasm.sh`) and the companion patch
`strongswan-6.0.5-wasm.patch` will produce a broken WASM that regresses
ML-KEM (the daemon never reaches IKE_SA_INIT). Running the build without
`SKIP_INSTALL_TO_HUB=1` will overwrite the working baseline in
`pqctoday-hub/public/wasm/strongswan.wasm` and break the VPN simulator.

**If you run the build, pass `SKIP_INSTALL_TO_HUB=1` and compare the output
against the `v2.80.0` binary before considering deployment.**

## Path forward (Phase 3 — deferred)

The recommended approach for a reproducible strongSwan WASM build is **not**
to continue reconstructing the prior session. Instead, adopt the
[`openssh-pkcs11`](../openssh-pkcs11/) build pattern:

- `ASYNCIFY=1` + `MODULARIZE=1` instead of manual SAB+Atomics surgery
- 4 minimal shims (`socket_wasm.c`, `pkcs11_static.c`, `posix_stubs.c`,
  `charon_wasm_main.c`) following the openssh template at
  `../openssh-pkcs11/wasm-shims/`
- Committed, reproducible, <16 KB total shim footprint
- Known to produce working `openssh-{client,server}.wasm` binaries

The ML-DSA core strongSwan patch (`../strongswan-6.0.5-pqc.patch`, 882 lines,
validated applies cleanly to upstream 6.0.5) is orthogonal and reusable under
the openssh-style approach. The strongSwan PKCS#11 plugin ML-DSA wiring in
`../strongswan-pkcs11/` is also orthogonal and reusable.

## Related files (also UNVERIFIED)

- `../strongswan-6.0.5-wasm.patch` — 682-line patch attempting to reproduce
  the 8 `__EMSCRIPTEN__`-guarded core patches from the prior session. Applies
  cleanly but runtime behavior is broken (see above).
- `../scripts/build-strongswan-wasm.sh` — build pipeline that applies both
  patches and produces a broken binary. **Always run with
  `SKIP_INSTALL_TO_HUB=1` until a proper Phase 3 rewrite lands.**

## Related files (VERIFIED, keep)

- `../strongswan-6.0.5-pqc.patch` — ML-DSA core strongSwan patch. Applies
  cleanly to 6.0.5. Independent of the WASM reconstruction.
- `../strongswan-pkcs11/` — PKCS#11 plugin with ML-DSA sign/verify/SPKI
  wiring. Compiles cleanly on the native path as well as the WASM path.
