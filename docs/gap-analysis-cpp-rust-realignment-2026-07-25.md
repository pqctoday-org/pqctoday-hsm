# C++ ↔ Rust PKCS#11 engine realignment — gap analysis (2026-07-25)

Read-only audit. Verified against source at commit `859774b` on
`feat/rust-pkcs11-emscripten-staticlib`, not against doc prose — several
existing docs in this repo are stale and are flagged below rather than
trusted.

## Context

This repo carries two independent PKCS#11 v3.2 engines:

- **C++** (`src/lib/`) — SoftHSMv2 fork, OpenSSL 3.6 EVP-only backend.
- **Rust** (`rust/`, crate `softhsmrustv3`) — pure-Rust (RustCrypto), zero
  OpenSSL dependency. Compiles to native, `wasm32-unknown-unknown`
  (browser), and — as of three commits from 2026-07-24
  (`0d6d0b5`/`49d41da`/`859774b`, "WP1") — `wasm32-unknown-emscripten` as a
  staticlib.

The WP1 work links the Rust engine directly into `openssl.wasm` so the
vendored OpenSSL `pkcs11-provider` (`src/vendor/pkcs11-provider/`) resolves
its Cryptoki entry points against Rust instead of C++. The stated reason
(commit `0d6d0b5`): the C++ engine's only crypto backend is the same
statically-linked `libcrypto` the CLI/provider chain already uses, making
that chain circular for cross-verification. KMIP server and the CACP
policy engine already use the Rust engine exclusively (`kmip/Cargo.toml`
depends only on `softhsmrustv3`).

This is a continuation of that realignment, not a fresh design — the
question here is what's left before Rust can be treated as a full,
drop-in replacement for C++ across every consumer.

## 1. Branch status

- `feat/rust-pkcs11-emscripten-staticlib` is pushed to `origin`, working
  tree clean, exactly 3 commits ahead of `main` / 0 behind. Merges cleanly.
- **No PR open.** Nothing on `main` has moved since this branch forked, so
  there's no urgency from drift — but nothing formalizes this work either.

## 2. Mechanism/algorithm coverage — gap runs both directions

The common assumption ("Rust is behind C++") is wrong. Verified by reading
source, not the mechanism-count docs:

| Family | C++ | Rust | Note |
|---|---|---|---|
| RSA, ECDSA/ECDH, EdDSA/X25519/X448, AES modes, HMAC/SHA family | Full | Full | parity |
| ML-DSA, ML-KEM, SLH-DSA (incl. pre-hash variants) | Full | Full | parity — the doc claiming otherwise is stale, see §5 |
| HSS/LMS, XMSS/XMSS-MT | Full | Full (56 XMSS-MT param sets) | parity — same stale-doc issue |
| ECDH cofactor mode | Present (compliance report: `Derive_X25519_Cofactor` PASS) | Not found in `rust/src/native/agree.rs` | **Rust gap** — not exhaustively re-verified, worth a direct read before treating as settled |
| Hybrid KEMs (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) | **Absent** — zero hits anywhere in `src/lib/` | Full (`rust/src/native/hybrid.rs`) | **C++ gap.** Root `CLAUDE.md` currently attributes hybrid KEMs to the C++ engine's PQC feature list — that's wrong; KMIP calls `softhsmrustv3::native::hybrid::encapsulate` directly, C++ isn't in that path at all. Worth fixing the CLAUDE.md claim. |
| FrodoKEM (6 param sets), Classic McEliece | **Absent** in C++ | Full in Rust | **C++ gap**, Rust-only vendor mechanisms |

Net: C++ leads on ECDH cofactor; Rust leads on hybrid KEMs, FrodoKEM,
Classic McEliece. Anyone treating this as a one-directional
"Rust catching up to C++" gap list is working from a stale premise.

## 3. Behavioral gap: sign/verify-with-recovery

- **C++**: real RSA-PKCS/RSA-X.509 implementation
  (`src/lib/SoftHSM_sign.cpp:1823-1877`, `3740-3800+`).
- **Rust**: hard stub, always `CKR_FUNCTION_NOT_SUPPORTED`
  (`rust/src/ffi.rs:8525-8557`).

`CKR_FUNCTION_NOT_SUPPORTED` is spec-legal (§5.13 is optional), but the
Rust engine's own conformance report files this alongside genuinely
shared, engine-agnostic non-features (async sessions, operation-state
save/restore) as if C++ had the same limitation. It doesn't. A consumer
relying on sign-with-recovery works against C++ and silently breaks
against Rust.

Everything else checked in this category — `C_GetFunctionStatus`,
`C_CancelFunction`, `C_WaitForSlotEvent`, `C_GetOperationState`/
`C_SetOperationState`, the `C_Async*` family, the message-API
(`C_MessageSignInit`/`C_MessageEncryptInit`/etc. families) — is at
genuine parity: both engines implement the same subset for the same
spec-legal reasons, no silently-broken stubs found in either.

## 4. Persistence/state model — the largest structural gap

C++ behaves like a real token by default: `SlotManager`
(`src/lib/slot_mgr/SlotManager.h`) enumerates however many token
directories exist on disk at startup; `Token::setSOPIN`/`setUserPIN`
(`src/lib/slot_mgr/Token.cpp:255-366`) write PINs and token objects
through to disk. Keys and PIN state survive a process restart
unconditionally.

Rust keeps all state in memory by design. Its own `state_snapshot.rs`
module doc says as much, explicitly contrasting itself with "the exact
failure mode the C++ engine avoided with its file-backed token
directory." The snapshot mechanism that exists to close this gap is
narrow:

- Wired **only** into the emscripten-staticlib/`openssl.wasm` embedding
  path. Zero references to it anywhere in `kmip/src/` or the
  wasm-bindgen browser build.
- Covers only `CKA_TOKEN=TRUE` objects and handle counters. Session
  objects and login state are explicitly **not** restored — login state
  is force-reset to `Public` on every restore
  (`rust/src/state_snapshot.rs:17-20`).

Concretely for the KMIP server (Rust's primary production consumer):
`kmip/bin/pqctoday-kmip.rs:277-283` calls
`softhsmrustv3::native::session::bootstrap_default_token(...)`
unconditionally on every process start — a fresh, empty token every time.
The KMIP `SqliteStore` durably persists KMIP object *metadata*, but
`kmip/src/ops/create_key_pair.rs:262` documents that the private-key
record stores no key material — the real private key lives only in the
in-memory engine. **There is no boot-time re-hydration path from the
SQLite store back into the engine**, so any engine-generated key is
orphaned by a KMIP server restart regardless of `--store` configuration.

This is the gap that most concretely blocks calling Rust a full
replacement for C++, independent of any specific WASM/emscripten effort.

## 5. Build health

- `rust/` (the engine itself): compiles clean on all three targets —
  native, `wasm32-unknown-unknown`, and the new
  `wasm32-unknown-emscripten` staticlib target. No regressions from WP1.
- `wasm/` (separate crate `pqctoday-kmip-wasm`, the KMIP browser
  playground, also depends on `softhsmrustv3`): **currently fails to
  compile.**
  ```
  error[E0061]: this function takes 4 arguments but 3 arguments were supplied
     --> wasm/src/lib.rs:861:13
      |
  861 |     pqctoday_kmip::ops::register_import_export::register(&self.deps, req, "wp3-register-cert-demo")
      |                                                          ------------------------ argument #3 `&AuthContext` is missing
  ```
  Pre-existing drift, not caused by WP1 — the `register()` signature grew
  an `AuthContext` parameter in a later tenancy commit that never updated
  this call site. Matches an earlier flagged note; confirmed still broken
  at current HEAD.
- Checked-out `wasm/softhsm.wasm` / `wasm/softhsm.js` (gitignored build
  artifacts) predate all three WP1 commits — **stale relative to current
  Rust source.** Anyone running the checked-out build today isn't running
  current engine code.
- **CI has zero coverage of any of this**: no workflow references
  `wasm32` or `emscripten`; Rust CI jobs only run `cargo test`/
  `cargo build` natively. CI would not have caught the `wasm/` compile
  error above, and provides no regression protection for the new
  emscripten staticlib path.
- C++ side: no current full build directory exists to check against;
  last known-good Emscripten build predates the WP1 commits by about a
  day, so it's stale too, but that's expected (C++ wasn't touched by WP1).

## 6. Known vendor-code gap, unrelated to either engine's own code

`CKK_EC_MONTGOMERY` (X25519/X448 as a PKCS#11 key type) is still missing
from the vendored `pkcs11-provider`'s key-type dispatch
(`src/vendor/pkcs11-provider/src/objects.c:1416-1470`) — falls to
`default: CKR_ARGUMENTS_BAD`. This sits in the third-party provider layer
both engines are accessed through in the OpenSSL Studio integration, not
in either engine itself. No user-facing flow currently exercises it, but
it blocks X25519 HSM keygen through that specific path regardless of
which engine backs it.

## 7. Doc hygiene

`docs/rust-engine.md` (dated 2026-03-08) is roughly four months stale and
actively wrong in ways that make the Rust engine look less mature than it
is: claims 45 exported functions (current: 109 advertised mechanisms,
104-function full Cryptoki surface all linkable), claims ML-DSA/SLH-DSA
pre-hash and XMSS-MT are unimplemented (both are fully wired). `docs/README.md`
already marks the older gap-analysis docs as historical — this file
should get the same treatment or a rewrite; right now it's live-linked
from the docs index as the current Rust engine reference.

## Priority list

1. **KMIP private-key persistence**: engine-generated private keys have
   no durable storage path at all — a server restart silently loses them
   even with `--store` configured. This is the gap most likely to bite a
   real deployment.
2. **Sign/verify-with-recovery**: decide whether to implement in Rust
   (RSA-only, matching C++) or explicitly document as an intentional,
   asymmetric non-feature — right now the Rust conformance report's
   framing obscures that it's not shared with C++.
3. **`wasm/src/lib.rs:861` compile error** — one-line fix (thread an
   `AuthContext` through), currently blocks building the KMIP browser
   playground entirely.
4. **Zero CI coverage for `wasm32-unknown-unknown`/`wasm32-unknown-emscripten`**
   — the exact class of break in #3 will keep recurring silently without it.
5. **Stale `wasm/softhsm.wasm`/`.js` build artifacts** — rebuild before
   anyone demos or ships from this checkout.
6. **`CLAUDE.md` hybrid-KEM attribution** — currently credits the C++
   engine for a Rust-only feature; low effort, high confusion-reduction fix.
7. **`docs/rust-engine.md`** — mark historical or rewrite; it currently
   undersells the Rust engine's real feature set by ~4 months.
8. **ECDH cofactor mode in Rust** — confirmed absent by grep, not yet
   confirmed by a full code read; verify before prioritizing a fix.
9. **`CKK_EC_MONTGOMERY` in the vendored `pkcs11-provider`** — low
   priority, no current consumer, but blocks X25519 HSM keygen through
   that provider path for either engine.

No files were modified as part of this audit.
