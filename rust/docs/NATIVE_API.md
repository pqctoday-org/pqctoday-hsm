# `softhsmrustv3::native` — typed Rust API for native callers

> **Status**: scoping document (this commit) + module skeleton.
> Implementations land in follow-up commits.
> **Branch**: `feat/rust-native-api`.

## 1. Why this module exists

`softhsmrustv3` was originally written wasm32-first. The PKCS#11 C ABI it
exposes via `pub mod ffi` was designed for the WebAssembly target:

- `CK_ATTRIBUTE` template entries are **12 bytes** (`type:u32 + pValue:u32 +
  ulValueLen:u32`).
- `pValue` is a **32-bit pointer**, cast from / to `usize` and dereferenced
  via `as usize as *const u8`.

This works in wasm32 (pointers ARE 32 bits there). It **silently truncates**
on native 64-bit hosts when callers construct attribute templates from
ordinary Rust `Vec<u8>` / stack buffers whose addresses exceed the u32
range.

The `pqctoday-hsm/openmls-provider/wasm-smoke/` crate gates its
`softhsmrustv3` path-dependency behind
`cfg(target_arch = "wasm32")` for exactly this reason — its
`Cargo.toml:13` reads:

```toml
# This crate is wasm32-only by design — every dep below is conditioned.
# Building it for native targets is a no-op (empty rlib).
[target.'cfg(target_arch = "wasm32")'.dependencies]
softhsmrustv3 = { path = "../../rust" }
```

**`pqctoday-hsm/kmip/` is a native target.** Phase 4's `Session` wrapper
compiles (it only calls `C_Initialize` / `C_OpenSession` / `C_Login` /
`C_CloseSession`, none of which take templates) but Phase 7b would need
to construct attribute templates — which would silently break on native.

## 2. Architectural principle

**Typed Rust is the source of truth; the C ABI is a marshalling layer.**

The engine already has typed Rust primitives in
`src/crypto/handlers.rs`:

```rust
pub fn sign_ml_dsa(mech: u32, ps: u32, sk_bytes: &[u8], msg: &[u8])
    -> Result<Vec<u8>, u32>;
pub fn verify_ml_dsa(mech: u32, ps: u32, pk_bytes: &[u8], msg: &[u8], sig: &[u8])
    -> Result<(), u32>;
pub fn sign_slh_dsa(...) / verify_slh_dsa(...);
pub fn sign_rsa(...) / verify_rsa(...) / verify_ecdsa(...) / etc.
```

And typed object storage in `src/state.rs`:

```rust
pub fn allocate_handle(attrs: Attributes) -> u32;
pub fn get_object_value(handle: u32) -> Option<Vec<u8>>;
pub fn get_object_attr_bytes(handle: u32, attr_type: u32) -> Option<Vec<u8>>;
pub fn set_object_attr_bytes(handle: u32, attr_type: u32, value: Vec<u8>) -> bool;
pub fn store_param_set / store_algo_family / store_bool / store_ulong;
```

The C ABI handlers (`ffi::C_GenerateKeyPair`, `ffi::C_Sign`,
`ffi::C_EncapsulateKey`, …) **already call these typed primitives
internally** — they're the marshalling layer.

**What's missing** for a clean native API is a thin `pub mod native` that
exposes the **composite operations** (keygen + storage + sign as one
call) without the C ABI surface in between.

## 3. Public surface — `pub mod native`

### 3.1 Sessions

```rust
/// Initialise the engine. Idempotent (subsequent calls return
/// `Ok(())` instead of `CKR_CRYPTOKI_ALREADY_INITIALIZED`).
pub fn init() -> Result<(), CkRv>;

/// Open an R/W user session against `slot`. Returns the session handle.
/// `pin` is verified via the engine's PIN store.
pub fn open_session(slot: u32, pin: &str) -> Result<u32, CkRv>;

/// Close a session handle.
pub fn close_session(session: u32) -> Result<(), CkRv>;
```

### 3.2 Key generation — PQC

```rust
/// Generate an ML-KEM keypair. `parameter_set` ∈ {ML_KEM_512, ML_KEM_768,
/// ML_KEM_1024}. Returns `(public_handle, private_handle)`.
pub fn generate_ml_kem_keypair(
    session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv>;

/// Generate an ML-DSA keypair. `parameter_set` ∈ {ML_DSA_44, ML_DSA_65,
/// ML_DSA_87}.
pub fn generate_ml_dsa_keypair(
    session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv>;

/// Generate an SLH-DSA keypair.
pub fn generate_slh_dsa_keypair(
    session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv>;
```

### 3.3 Key generation — classical

```rust
pub fn generate_rsa_keypair(session: u32, bits: u32, cka_id: &[u8], label: &str)
    -> Result<(u32, u32), CkRv>;
pub fn generate_ecdsa_keypair(session: u32, curve_oid: &[u8], cka_id: &[u8], label: &str)
    -> Result<(u32, u32), CkRv>;
pub fn generate_aes_key(session: u32, bits: u32, cka_id: &[u8], label: &str)
    -> Result<u32, CkRv>;
```

### 3.4 Sign / Verify

```rust
pub fn sign(session: u32, key: u32, mechanism: u32, data: &[u8])
    -> Result<Vec<u8>, CkRv>;
pub fn verify(session: u32, key: u32, mechanism: u32, data: &[u8], signature: &[u8])
    -> Result<bool, CkRv>;
```

### 3.5 Encrypt / Decrypt (classical + ML-KEM encap/decap)

```rust
pub fn encrypt(session: u32, key: u32, mechanism: u32, plaintext: &[u8], iv: Option<&[u8]>)
    -> Result<Vec<u8>, CkRv>;
pub fn decrypt(session: u32, key: u32, mechanism: u32, ciphertext: &[u8], iv: Option<&[u8]>)
    -> Result<Vec<u8>, CkRv>;

/// ML-KEM encapsulation. Returns `(ciphertext, shared_secret)`.
pub fn encapsulate(session: u32, public_key: u32, mechanism: u32)
    -> Result<(Vec<u8>, Vec<u8>), CkRv>;
pub fn decapsulate(session: u32, private_key: u32, mechanism: u32, ciphertext: &[u8])
    -> Result<Vec<u8>, CkRv>;
```

### 3.6 Object lifecycle / queries

```rust
pub fn destroy_object(session: u32, handle: u32) -> Result<(), CkRv>;

/// Find an object handle by `CKA_ID`. Used by the KMIP store layer to
/// recover the session-scoped handle from the stable PKCS#11 identifier
/// it persists.
pub fn find_by_cka_id(session: u32, cka_id: &[u8]) -> Result<Option<u32>, CkRv>;

/// Read a single attribute. Returns `None` if absent.
pub fn get_attribute(session: u32, handle: u32, attr_type: u32) -> Option<Vec<u8>>;
```

### 3.7 Token initialisation (for first-boot setup)

```rust
pub fn init_token(slot: u32, so_pin: &str, label: &str) -> Result<(), CkRv>;
pub fn init_pin(session: u32, user_pin: &str) -> Result<(), CkRv>;
```

## 4. Threading model

The engine's internal storage (`OBJECTS`, `SESSIONS`, `SIGN_STATE`,
`ENCRYPT_STATE`, etc.) is currently `thread_local!`. That's correct for
wasm32 (single-threaded execution model).

For native callers (tokio multi-threaded), two viable approaches:

### Option A — pinned engine thread (recommended)

The `softhsmrustv3::native` API documents that **all calls must come from
a single thread**. Native callers pin one OS thread (e.g.
`tokio::task::spawn_blocking` onto a single-thread runtime) and route all
crypto requests through it. Phase 4's `Session: !Send` already encodes
this constraint.

**Pros**: No engine changes. Thread-local storage is correct as-is. Lowest
risk of state corruption.

**Cons**: Caller has to manage thread affinity. KMIP `Deps` needs an
`Arc<Mutex<Session>>` and all crypto goes through a single-thread executor.

### Option B — replace thread_local with parking_lot::Mutex

Convert `OBJECTS`, `SESSIONS`, `SIGN_STATE`, `ENCRYPT_STATE` to global
`Mutex<HashMap<...>>`. Multi-threaded callers serialise via the mutex.

**Pros**: API users don't need thread affinity.

**Cons**: Wider engine change. Mutex contention under load. Risk of
deadlocks if engine internals ever call out and back.

### Decision: **Option A for v0.1; Option B as a future option if profiling shows contention.**

The Phase 4 `Session: !Send` constraint already aligns the KMIP server
with Option A. The KMIP server can route crypto through a single
`tokio::task::spawn_blocking` thread without touching the engine.

## 5. C ABI relationship

The new `pub mod native` does **not** replace `pub mod ffi`. They coexist:

- `ffi::C_GenerateKeyPair` (wasm32 PKCS#11 spec compliance) — unchanged.
- `native::generate_ml_kem_keypair` (new) — same logic, typed args.

Where practical, the implementation strategy is:

1. **Extract** the keygen / encap / encrypt body from each `ffi::C_*`
   handler into a private `_impl_*(typed args) -> Result<...>` function.
2. **Wrap** the new private impl with the existing `ffi::C_*` (marshalling
   raw pointers in) AND the new `native::*` (typed pass-through).

The C ABI stays bit-exact (no behaviour change for WASM consumers). The
native API is a parallel surface backed by the same internal logic.

## 6. File-by-file plan

| File | Action | Estimated LOC |
|---|---|---|
| `src/lib.rs` | Add `pub mod native;` | +1 |
| `src/native/mod.rs` | Re-exports + module docs | ~40 |
| `src/native/session.rs` | `init` / `open_session` / `close_session` / `init_token` / `init_pin` | ~120 |
| `src/native/keygen.rs` | All 6 keygen functions (ML-KEM/ML-DSA/SLH-DSA/RSA/ECDSA/AES) — refactored from `ffi::C_GenerateKeyPair` + `ffi::C_GenerateKey` | ~250 |
| `src/native/sign.rs` | `sign` / `verify` — thin dispatcher over `crypto::handlers::sign_*` + `verify_*` | ~80 |
| `src/native/encrypt.rs` | `encrypt` / `decrypt` / `encapsulate` / `decapsulate` — refactored from `ffi::C_Encrypt*` + `ffi::C_*EncapsulateKey` | ~200 |
| `src/native/object.rs` | `find_by_cka_id` / `destroy_object` / `get_attribute` | ~100 |
| **Total new code** | | **~790 LOC** |
| **Plus refactor** in `ffi.rs` to call into the new impl bodies | | ~200 LOC moved |

## 7. Test plan

| Layer | Test | Purpose |
|---|---|---|
| `tests/native_smoke.rs` (new) | Init engine → open session → generate ML-DSA-65 keypair → sign 32-byte msg → verify | Proves the native API actually works end-to-end on native |
| `tests/native_parity.rs` (new) | Same operation via `ffi::C_*` (in wasm32 cfg) and via `native::*` (native cfg) produces byte-equivalent output | Proves the dual API doesn't drift |
| Existing `pqctoday-mls-wasm-smoke` tests | Should still pass | Proves the C ABI refactor didn't break wasm32 callers |
| KAT replay in `tests/` | Should still pass | No regression to NIST vector replay |

## 8. Risks + mitigation

| Risk | Likelihood | Mitigation |
|---|---|---|
| Refactor breaks wasm32 callers | Medium | Existing `wasm-smoke` tests gate every commit; CI runs them |
| Native API surface drift from C ABI | Medium | Parity test in `tests/native_parity.rs` exercises both paths against the same KAT |
| Thread-local OBJECTS map needs Mutex for native | Low | Option A (pinned thread) deferred to caller — KMIP `Session: !Send` already aligns |
| RNG state — engine uses thread-local CSPRNG | Low | Same as thread-local OBJECTS; pinned-thread caller handles it |

## 9. This commit's scope

This first commit ships **only the scoping doc + module skeleton**. The
skeleton:

- Adds `pub mod native;` to `src/lib.rs`.
- Creates `src/native/mod.rs` with the function signatures from §3 as
  `unimplemented!()` stubs.
- Creates `src/native/{session,keygen,sign,encrypt,object}.rs` as empty
  modules.

**No implementations yet.** Follow-up commits land each
sub-module's real impl + tests:

| Commit | Sub-module | Tests |
|---|---|---|
| 2 | `native/session.rs` | `tests/native_session.rs` |
| 3 | `native/keygen.rs` (ML-DSA + ML-KEM first) | `tests/native_keygen_pqc.rs` |
| 4 | `native/sign.rs` | `tests/native_sign_verify.rs` |
| 5 | `native/encrypt.rs` | `tests/native_encap_decap.rs` |
| 6 | `native/keygen.rs` (classical: RSA, ECDSA, AES) | `tests/native_keygen_classical.rs` |
| 7 | `native/object.rs` | `tests/native_object.rs` |
| 8 | `tests/native_parity.rs` | (cross-validation) |

Roughly **6–8 follow-up commits**, each ~150 LOC + a focused test. Each
commit independently verifiable; CI gates against wasm32 regressions.

## 10. Out of scope

- Changing the wasm32 C ABI semantics (no behaviour change for existing
  WASM consumers).
- Adding async / multi-threaded engine internals.
- Replacing thread-local storage with `Mutex` (deferred — see §4).
- Adding new crypto primitives. The native API exposes what the engine
  already implements.
- Token persistence format changes.

## 11. Open questions for review

1. **Module name**: `native` vs `rust_api` vs `direct`. `native` is shortest
   and contrasts cleanly with `ffi` (the C ABI). Other suggestions welcome.
2. **Error type**: `Result<T, u32>` where `u32` is `CK_RV` keeps parity
   with the existing crypto-primitive functions. Alternative: a typed
   `enum NativeError` mirroring `pqctoday-kmip::pkcs11bridge::BridgeError`.
   The `u32` path is simpler and lets KMIP wrap on its side.
3. **Should `native::*` take `&mut Session` instead of raw `session: u32`**?
   More type-safe but couples the native API to a Rust struct definition.
   Counterargument: the C ABI uses `u32`; staying with `u32` keeps the two
   APIs visually parallel.
