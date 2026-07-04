# strongswan-wasm-v2-shims

> **Update 2026-07-03 — not the active tree.** This clean-slate rewrite was
> started 2026-04/05, but subsequent development (through 2026-06-12: RFC 7383
> fragmentation, RFC 9370 multi-KE, CHILD_SA) landed in the **v1**
> `../strongswan-wasm-shims/` tree instead, together with
> `../strongswan-6.0.5-wasm.patch`. So the "Supersedes v1" line below did not
> play out — v1 is the currently-maintained path. This directory is kept for the
> ASYNCIFY/MODULARIZE approach it prototypes. Check `git log` before choosing a
> tree.

Clean-slate Emscripten shims for strongSwan charon, modeled on the proven
`openssh-pkcs11/wasm-shims/` pattern (ASYNCIFY + MODULARIZE, single-thread
per WASM instance, SAB+Atomics ring buffer between two Web Workers).

## Files

| File | Role |
|---|---|
| `charon_wasm_main.c` | Replaces charon's `main()`. Custom init: `library_init`, plugin load, softhsmv3 static init, config injection from JS, single-daemon dispatch loop. |
| `socket_wasm.c` | POSIX socket API backed by two SABs between peer Workers (`init` ↔ `resp`). Each WASM instance sees one `FAKE_SOCKFD` (= 42) that `read()/write()` to the SAB ring. |
| `pkcs11_static.c` | Intercepts `dlopen("…softhsm…")` / `dlsym("C_GetFunctionList")` and routes to the statically-linked softhsmv3 symbol. |
| `posix_stubs.c` | No-op stubs for POSIX calls absent from Emscripten sysroot (res_*, initgroups, setgroups, utmp/wtmp, ptrace-adjacent). |

## Design notes

- **Threading:** single-threaded WASM + `charon.threads=1` in injected config.
  ASYNCIFY unwinds blocking reads. Each role (init, resp) runs in its own
  Web Worker; the two Workers exchange IKE packets via a pair of SABs.
- **Link strategy:** exclude `src/charon/charon.o` from the native `main`,
  wire our `charon_wasm_main.c` instead. Exported entry points
  (`wasm_vpn_boot`, `wasm_vpn_configure_json`, `wasm_vpn_initiate`,
  `wasm_vpn_get_result`, `wasm_vpn_shutdown`) are marked
  `EMSCRIPTEN_KEEPALIVE`.
- **No `strongswan-6.0.5-wasm.patch`.** The v1 reconstruction applied a
  682-line core patch that duplicated `settings_parser_load_string` with
  conflicting return types, causing the `array_destroy_function`
  invalid-function-pointer crash at `library_init` time. Clean upstream
  6.0.5 + `strongswan-6.0.5-pqc.patch` is sufficient.

## Plugin set (must stay in sync with hub side)

The hub's worker (`pqctoday-hub/public/wasm/strongswan_worker.js`) and the
panel's `buildCharonConf` both write a `strongswan.conf` with this `load =`
list. **Every plugin named here must be compiled in via `--enable-*` in
`scripts/build-strongswan-wasm-v2.sh`** — listing a plugin charon was not
linked with is silently ignored by the loader, but `pkcs11`, `kdf`, and
`socket-default` are required for the IKE flow to work at all.

Required runtime plugin list (kept identical in three places — hub worker,
hub panel `buildCharonConf`, and `WASM_STRONGSWAN_CONF` in
`charon_wasm_main.c`):

```text
pem pkcs1 pkcs8 x509 pkcs11 nonce kdf openssl random constraints revocation socket-default
```

`aes`, `sha1`, `sha2`, `hmac` are intentionally absent — the `openssl` plugin
provides them. Listing them anyway adds noise to charon's plugin-load log.

### Verifying the WASM binary actually has them

After `scripts/build-strongswan-wasm-v2.sh` completes, run:

```sh
wasm-objdump -x dist/strongswan-v2.wasm \
  | grep -E "(pem|pkcs1|pkcs8|x509|pkcs11|nonce|kdf|openssl|random|constraints|revocation|socket-default)_plugin_create"
```

Each plugin name should produce exactly one hit. If `socket-default_plugin_create`
is missing the IKE socket layer is not linked in — the bridge's syscall
overrides will receive nothing because charon never opens a socket. If
`pkcs11_plugin_create` is missing, softhsmv3 RPC is unreachable.

## IKEv2 fragmentation (RFC 7383)

strongSwan 6.x compiles RFC 7383 fragmentation support directly into charon's
core IKEv2 engine — there is no separate plugin to enable. Activation is
controlled by:

- `charon.fragment_size` in `strongswan.conf` (the hub passes this from the
  MTU slider).
- `fragmentation = yes` in the connection block of `ipsec.conf`.

If the hub UI's "Enable IKE Message Fragmentation" toggle has no observable
effect, check the charon log for `received fragment #1 of …` lines on the
responder side. Their absence means charon's core IKE state machine is not
fragmenting — the proposal may be small enough to fit in one packet, or the
toggle did not propagate to the connection block.

## ML-KEM / ML-DSA via the PKCS#11 bridge

ML-KEM is **not** a strongSwan transform plugin. It reaches charon through
the PKCS#11 plugin's `C_EncapsulateKey` / `C_DecapsulateKey` calls, which we
intercept on the JS side and route to softhsmv3's CKM_ML_KEM mechanisms. The
proposal token charon recognizes is `mlkem768`; the C-side has no #ifdef
gating it as long as the `strongswan-6.0.5-pqc.patch` is applied.

Verify the patch wired the proposal grammar correctly:

```sh
emstrip dist/strongswan-v2.wasm  # optional
wasm-objdump -d dist/strongswan-v2.wasm | grep -A2 mlkem768
```
