# strongswan-wasm-shims — STATUS

**Status: working — real end-to-end post-quantum IKEv2 VPN, plus fragmentation,
multi-KE, and CHILD_SA** (updated 2026-09-01). This supersedes both the
"partial, non-functional reconstruction" framing further below and the
2026-07-03 update banner that replaced it — both are now historical. This is
the actively-maintained WASM shim tree (`../strongswan-wasm-v2-shims/` was
deleted 2026-08-31; see `../docs/wasm-charon-phase-3b-plus-roadmap.md`'s
superseded-notice for the rationale). See `../CHANGELOG.md` for full commit
detail on everything below.

## What works

- **Boot + real PQC handshake to `ESTABLISHED`.** Two browser Web Workers run
  the full WASM charon daemon, negotiate a genuine `mlkem768x25519-sha256`
  IKE_SA_INIT (real `C_EncapsulateKey`/`C_DecapsulateKey` via softhsmv3), and
  authenticate either with a PSK or with dual ML-DSA-65 certificate auth
  (`wasm_set_auth_mode(1)`; real `C_Sign`/`C_Verify`, 3309-byte signatures) —
  both reach `IKE_SA wasm[1] state change: CONNECTING => ESTABLISHED`.
- **RFC 7383 IKEv2 message fragmentation** — on by default
  (`WASM_FRAGMENTATION=no` to opt out).
- **RFC 9370 multiple key exchanges** — a hybrid proposal string like
  `aes256-sha256-mlkem768-ke1_ecp256` runs ECP-256 as a real Additional Key
  Exchange over the IKE_INTERMEDIATE task (unmodified strongSwan core parses
  the `ke1_..ke7_` prefixes; nothing in the WASM patch disables it).
- **CHILD_SA negotiation** — `kernel_wasm.c` (Tier A stub `kernel_ipsec_t`)
  lets a real CHILD_SA negotiate (real proposals, nonces, traffic selectors,
  KEYMAT derivation) with SADB/SPD "installation" as SUCCESS no-ops, since the
  browser has no kernel IPsec stack. Opt-in via `WASM_CHILDSA=1`. Browser-
  verified: both the responder's `N(TS_UNACCEPTABLE)` (missing traffic
  selectors on the child config) and an intermittent initiator
  `unable to allocate SPI from kernel` (registration race) were found and
  fixed on 2026-06-12.

## Known limitations

- **PKCS#11 RPC mode is a stub, not real cross-worker forwarding.**
  `pkcs11_wasm_rpc_function_list()` in `pkcs11_wasm_rpc.c` is currently just
  an alias to the pass-through wrapper — see that file's own comment. Dual
  ML-DSA cert auth does **not** go through this path; it works because each
  worker loads its own private key and the peer's cert locally (see
  `wasm_backend.c`'s `BUILD_PKCS11_KEYID` + `CERT_ALWAYS_SEND` + trust-anchor
  logic, landed 2026-04-28), not via SAB RPC to a shared main-thread HSM.
- **`kernel_wasm.c` is Tier A**: it lets CHILD_SA *negotiate*, but does not
  actually install any SA/policy state (no real SADB/SPD) or move any ESP
  traffic — this is enough for the negotiation/visualization use case, not a
  real data-plane.
- **`wasm_hsm_init.c` slot bring-up is unchanged from the original
  reconstruction** (ML-DSA/ML-KEM keygen paths); not re-audited as part of
  this update.

## Build infrastructure

- `scripts/build-strongswan-wasm.sh` applies `../strongswan-6.0.5-wasm.patch`
  (or the 6.0.6/6.0.7-compatible variant) plus the shared ML-DSA/SLH-DSA core
  patch, copies these shim files into the charon build tree, and links a
  working `strongswan.{js,wasm}`.
- `SKIP_INSTALL_TO_HUB=1` skips the copy-to-hub step for a dry build; without
  it, the script installs into the hub's `public/wasm/` (back up first if
  testing against a shared checkout).

## Files

See [`README.md`](README.md) for the per-file purpose/exports table.

## History (superseded)

The sections that used to occupy this file (a 2026-04-18 "partial,
non-functional reconstruction" with a documented `array_destroy_function`
boot crash, and a 2026-07-03 banner disclaiming it as out of date but not
replacing it) described a state that predates all of the above — the boot
crash, the RSA-only/ML-DSA-TODO keygen gap, and the "do not ship" caution
were all resolved between 2026-04-26 and 2026-06-12. Kept out of this file
now; see `../CHANGELOG.md`'s entries for `strongswan-wasm` (2026-04-26
through 2026-06-12) for the full blow-by-blow if the archaeology is useful.
