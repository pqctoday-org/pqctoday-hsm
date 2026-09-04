# strongswan-wasm-shims

Emscripten/WASM-only source files layered into the strongSwan 6.0.5 tree
at build time. They are copied into the charon build directory by
`scripts/build-strongswan-wasm.sh` *before* `emmake make` runs, and are
referenced by the WASM patch (`strongswan-6.0.5-wasm.patch`) which adds
them to `Makefile.am`.

All source is `#ifdef __EMSCRIPTEN__` — on native builds these files are
effectively empty, so shipping them alongside the core tree is safe.

**Not a standalone crate** — there's no build step to run from inside this
directory. Build from the repo root:

```bash
bash scripts/build-strongswan-wasm.sh
```

which fetches/patches strongSwan 6.0.5, copies these shims in, and (unless
`SKIP_INSTALL_TO_HUB=1` is set) installs the resulting `strongswan.{js,wasm}`
into the [`pqctoday-hub`](https://github.com/pqctoday/pqctoday-hub) app's
`public/wasm/` — a separate repo, which is the actual consumer of this WASM
bundle (in-browser IPsec/IKEv2 VPN simulation). This README documents the
per-file purpose/exports and the C↔JS ABI; for current working/known-broken
status and the "what works today" summary, see [`STATUS.md`](STATUS.md).

## Files

| File | Purpose | Exports |
| --- | --- | --- |
| `socket_wasm.c`/`.h` | Replaces the POSIX UDP socket plugin with a SharedArrayBuffer-backed transport. Implements the `socket_t` interface (send/receive/get_port/supported_families/destroy). | `socket_wasm_create`, `wasm_socket_destroy`, `wasm_net_set_sab`, and the EM_JS env imports `wasm_net_receive`, `wasm_net_send`. |
| `wasm_hsm_init.c` | softhsmv3 static-link token initializer. Opens a session against two slots (`charon-left`, `charon-right`), runs `C_InitToken`/`C_InitPIN`/`C_GenerateKeyPair`. | `wasm_hsm_init(alg_type, slot0_bits, slot1_bits)` |
| `wasm_backend.c` | C-level config backend that registers a single `peer_cfg_t` + `ike_cfg_t` + `child_cfg_t` and a PSK shared key (from `WASM_PSK` env var) or an ML-DSA cert (`wasm_set_auth_mode(1)`). Holds the proposal-mode selector (classical / pure-pqc / hybrid, plus an opt-in `WASM_IKE_PROPOSAL` override string), enables RFC 7383 fragmentation by default (`WASM_FRAGMENTATION=no` to opt out), and — via `ke1_ecp256`-style proposal strings — RFC 9370 Additional Key Exchange rounds over the real IKE_INTERMEDIATE task. `WASM_CHILDSA=1` switches the IKE config from `CHILDLESS_FORCE` to negotiating a real CHILD_SA against `kernel_wasm.c` below. | `wasm_setup_config`, `wasm_get_peer_by_name`, `wasm_create_peer_enum`, `wasm_create_ike_enum`, `wasm_initiate`, `wasm_set_proposal_mode`, `wasm_set_auth_mode`. |
| `kernel_wasm.c` | Tier A stub `kernel_ipsec_t` backend (added 2026-06-12) — the browser has no real kernel IPsec stack, so this hands out sequential SPIs and no-ops `add_sa`/`add_policy`/etc., letting a genuine CHILD_SA (real proposals, nonces, traffic selectors, KEYMAT) negotiate over the wire without a SADB/SPD to install into. Opt-in via `WASM_CHILDSA=1`. | `kernel_wasm_ipsec_create`. |
| `pkcs11_wasm_rpc.c` | PKCS#11 function-table wrappers. `pkcs11_wasm_wrap_function_list` is the real path: a traced pass-through to the worker's own statically-linked softhsmv3. `pkcs11_wasm_rpc_function_list` is designed as a forward-to-main-thread-over-SAB path (its EM_JS imports — `pkcs11_rpc_call`, `pkcs11_sab_wi32`, `pkcs11_sab_ri32`, `pkcs11_sab_read`, `pkcs11_sab_write` — are declared) but is currently just an alias to the pass-through wrapper (no real cross-worker RPC yet — see the file's own comment and dual-auth's workaround below). | `pkcs11_wasm_wrap_function_list`, `pkcs11_wasm_rpc_function_list`, `pkcs11_set_rpc_mode`. |

## C↔JS ABI

Every C symbol exported by these shims is called from
`public/wasm/strongswan_worker.js` or an EM_JS block above — read that
worker for the authoritative protocol spec. A quick cheat-sheet:

### SharedArrayBuffer layouts

**Network SAB (passed via `wasm_net_set_sab`)**

```
offset 0   int32 state    (0 = empty, 1 = ready)
offset 4   int32 length   (bytes in payload)
offset 8   uint32 src_ip  (network-order)
offset 12  uint16 src_port + padding
offset 16  packet bytes
```

`wasm_net_receive` blocks on `Atomics.wait(hdr, 0, 0)` until `state==1`,
`wasm_net_send` waits for `state==0` then writes and sets `state=1`.

**PKCS#11 SAB (passed via `Module._wasm_pkcs11_sab`)**

Opcode + marshalled args layout is managed entirely by the worker
bootstrap; the C side just reads/writes int32 cells via
`pkcs11_sab_wi32`/`pkcs11_sab_ri32`. This scaffold keeps the symbol
surface stable; full RPC marshalling lives in `strongswan_worker.js`
with the peer HSM worker on the main thread.

### Exported C functions called from JS

| JS call site | C entry point | Signature (from baseline WASM) |
| --- | --- | --- |
| `Module._wasm_set_proposal_mode(n)` | `wasm_set_proposal_mode` | `(i32)->nil` |
| `Module._pkcs11_set_rpc_mode(n)` | `pkcs11_set_rpc_mode` | `(i32)->nil` |
| `Module._wasm_hsm_init(a, s0, s1)` | `wasm_hsm_init` | `(i32,i32,i32)->i32` |
| `Module._wasm_net_set_sab(ptr)` | `wasm_net_set_sab` | `(i32)->nil` |
| `Module._main(argc, argv)` | stock charon `main()` | `(i32,i32)->i32` |

### Integration into strongSwan

The patch `strongswan-6.0.5-wasm.patch` does the following:

1. Adds `socket_wasm.c` / `socket_wasm.h` to
   `src/libcharon/plugins/Makefile.am` as a new monolithic plugin,
   included under `--enable-socket-wasm`.
2. Registers `socket_wasm_create` in `src/libcharon/daemon.c` via the
   plugin-static-features hook, under `#ifdef __EMSCRIPTEN__`.
3. Adds `wasm_hsm_init.c`, `wasm_backend.c`, `pkcs11_wasm_rpc.c`,
   `kernel_wasm.c` to `src/charon/Makefile.am`'s `charon_SOURCES` — they
   compile directly into the `charon` binary alongside `charon.c`.
4. In `src/charon/charon.c`, calls `wasm_setup_config(0)` after
   `charon->initialize()` and `wasm_initiate(0)` when `--role initiator`
   is passed on argv.
5. Adds a `bool`-returning shim for `settings_parser_load_string` so
   the JS-injected config (via `STRONGSWAN_CONF_DATA` env var) can be
   parsed on-the-fly inside `library_init`.
6. Bypasses mutex/rwlock calls in sender, receiver, socket_manager, and
   daemon (WASM is single-threaded in this build — mutex acquisition
   is either a no-op or outright skipped).
7. Silences `pthread_sigmask` in `src/charon/charon.c` (no signals in
   WASM).
