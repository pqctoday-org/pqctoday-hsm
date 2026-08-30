#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::ck_param::{self, ParamReader};
use crate::constants::*;
use crate::crypto::*;
use crate::slh_dsa_keygen;
use crate::state::*;

use rand::SeedableRng;
use rand::rngs::OsRng;

/// ACVP-aware RNG selection macro.
/// In ACVP mode, uses the persistent ChaCha20Rng from global engine state
/// (`ACVP_RNG`, a `Mutex<Option<ChaCha20Rng>>` — see `state.rs`) so the
/// counter advances across operations (matching C++ OpenSSL behaviour).
/// In normal mode, uses OsRng for non-deterministic randomness.
///
/// Implementation: `take()` extracts the RNG from `ACVP_RNG` into a local
/// variable, runs $body inline (NOT in a closure — so `return` works normally),
/// then restores the advanced RNG back to `ACVP_RNG`. If $body exits via
/// `return` (error paths), the RNG is lost but `C_Initialize` recreates it.
///
/// PERF-BENCH FIX (2026-07-18, B4 step 1): the `acvp` Cargo feature is
/// opt-in and OFF in every shipped artifact (KMIP server, wasm playground
/// bundle, this crate's cdylib — see the feature doc comment in
/// Cargo.toml). `C_Initialize` only ever populates `ACVP_RNG` with `Some`
/// under `#[cfg(feature = "acvp")]`; without that feature it is `None`
/// for the lifetime of the process. So every production `with_rng!` call
/// was taking the `ACVP_RNG` mutex, finding `None`, and moving on — a
/// pure-overhead lock acquisition on every rng-using FFI operation with
/// zero chance of ever finding work to do. Below, the `acvp`-feature
/// build keeps the original mutex-checking macro; the default
/// (non-`acvp`) build gets a second definition that goes straight to
/// `OsRng`, touching no lock at all.
#[cfg(feature = "acvp")]
macro_rules! with_rng {
    ($rng:ident, $body:block) => {{
        let mut _acvp_rng_cell = crate::state::ACVP_RNG.with(|r| r.borrow_mut().take());
        if let Some(ref mut _acvp) = _acvp_rng_cell {
            // Re-bind through `let mut` so the LOCAL binding is mutable.
            // Call sites use `&mut $rng` to pass to crypto crates; that
            // requires the binding to be `mut`. The `ref mut` pattern alone
            // makes the binding immutable (value mutable), which fails
            // `&mut $rng` borrow-check on wasm32 (E0596).
            let mut $rng = _acvp;
            let _with_rng_result = { $body };
            // Restore the (now-advanced) RNG back to global state
            crate::state::ACVP_RNG.with(|r| {
                *r.borrow_mut() = _acvp_rng_cell;
            });
            _with_rng_result
        } else {
            let mut $rng = OsRng;
            $body
        }
    }};
}

#[cfg(not(feature = "acvp"))]
macro_rules! with_rng {
    ($rng:ident, $body:block) => {{
        let mut $rng = OsRng;
        $body
    }};
}

// ── Session Management ───────────────────────────────────────────────────────

/// PKCS#11 v3.2 §5.4: every Cryptoki function except C_Initialize and the
/// function-list/interface getters must return CKR_CRYPTOKI_NOT_INITIALIZED
/// when the library has not been initialized. Insert at the top of each entry
/// point's body.
macro_rules! require_init {
    () => {
        if !crate::state::is_initialized() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
    };
}

/// PKCS#11 v3.2 §5.12 — session-handle validation. Per the error-priority
/// ordering, this is checked after CKR_CRYPTOKI_NOT_INITIALIZED but before any
/// key/operation/mechanism error. Insert immediately after `require_init!()`.
macro_rules! require_session {
    ($h:expr) => {
        if !crate::state::session_exists($h) {
            return CKR_SESSION_HANDLE_INVALID;
        }
    };
}

/// PKCS#11 v3.2 §5.2 — required pointer arguments must not be NULL
/// (CKR_ARGUMENTS_BAD). Output buffers in the two-call size-query
/// convention MAY be NULL and must NOT be gated with this macro; apply it
/// to input pointers and required out-params (handles, counts) only. In
/// wasm linear memory address 0 is readable/writable, so a missing check
/// silently corrupts memory instead of faulting.
macro_rules! nonnull {
    ($($p:expr),+ $(,)?) => {
        $(
            if $p.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
        )+
    };
}

/// C2 (2026-08-13) — the NULL-mechanism CANCEL form the `C_*Init` functions
/// all share: "C_EncryptInit can be called with pMechanism set to NULL_PTR to
/// terminate an active encryption operation. If an active operation
/// operations cannot be cancelled, CKR_OPERATION_CANCEL_FAILED must be
/// returned." (§5.11, and the identical sentence in §5.12/§5.13/§5.14 for
/// sign, verify, digest, sign-recover, verify-recover and
/// verify-signature.)
///
/// Every one of these entry points previously answered a NULL mechanism with
/// CKR_ARGUMENTS_BAD, an inapplicable code — the usual "return-value latitude"
/// argument does not apply, because the cancel form is a DOCUMENTED call
/// shape, not an error.
///
/// Returns `Some(rv)` when the call was the cancel form and has been handled;
/// `None` when the caller supplied a real mechanism and should carry on.
/// Every operation this engine runs is cancellable (state is a map entry),
/// so CKR_OPERATION_CANCEL_FAILED is unreachable in practice — it is wired
/// through `cancelled` so that stops being true silently if some future
/// operation cannot be torn down.
fn cancel_active_operation(
    h_session: u32,
    p_mechanism: *mut u8,
    op: OpFamily,
) -> Option<u32> {
    if !p_mechanism.is_null() {
        return None;
    }
    let cancelled = match op {
        OpFamily::Encrypt => {
            ENCRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
            true
        }
        OpFamily::Decrypt => {
            DECRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
            true
        }
        OpFamily::Sign => {
            SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
            SIGN_MULTIPART_ACC.with(|s| s.borrow_mut().remove(&h_session));
            true
        }
        OpFamily::Verify => {
            VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
            VERIFY_MULTIPART_ACC.with(|s| s.borrow_mut().remove(&h_session));
            true
        }
        OpFamily::Digest => {
            DIGEST_STATE.with(|s| s.borrow_mut().remove(&h_session));
            DIGEST_MULTIPART.with(|s| s.borrow_mut().remove(&h_session));
            true
        }
        OpFamily::SignRecover => {
            SIGN_RECOVER_STATE.with(|s| s.borrow_mut().remove(&h_session));
            true
        }
        OpFamily::VerifyRecover => {
            VERIFY_RECOVER_STATE.with(|s| s.borrow_mut().remove(&h_session));
            true
        }
        OpFamily::VerifySignature => {
            VERIFY_SIG_STATE.with(|s| s.borrow_mut().remove(&h_session));
            true
        }
    };
    Some(if cancelled { CKR_OK } else { CKR_OPERATION_CANCEL_FAILED })
}

/// The operation families that share the NULL-mechanism cancel form.
#[derive(Clone, Copy)]
enum OpFamily {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Digest,
    SignRecover,
    VerifyRecover,
    VerifySignature,
}

/// PKCS#11 v3.2 §5.4.4 C_GetFunctionList — the classic 68-entry v2.40
/// CK_FUNCTION_LIST. Field order matches ck_abi.rs's `FnListV240` exactly
/// (pkcs11f.h's canonical order, asserted by tests there) — reused
/// verbatim rather than re-derived.
///
/// Each field is a real WASM indirect-function-table index. Verified
/// 2026-08-28 with a standalone probe: a value obtained this way,
/// invoked from JS as `__indirect_function_table.get(idx)(args)`,
/// produces byte-identical CK_RV results to calling the same function's
/// named wasm-bindgen export — CKR_OK then CKR_CRYPTOKI_ALREADY_
/// INITIALIZED across two calls, exactly matching the spec's own
/// C_GetFunctionList example (`(*pC_Initialize)(NULL_PTR)`). The prior
/// belief that "C function pointers cannot cross wasm-bindgen" (see
/// lib.rs's `ck_abi` module gate) was correct about wasm-bindgen-cli's
/// default JS glue not exposing the table, but conflated that with
/// genuine platform impossibility — wasm32's indirect function table is
/// real and exportable; the build just needed `--export-table` on the
/// linker plus a post-processing step re-adding the export
/// wasm-bindgen-cli otherwise strips (see build-wasm-bundle.sh, same
/// pattern already used there for `__wbg_get_memory`).
///
/// Written by explicit byte offset (not a native `#[repr(C)]` struct) to
/// avoid compiler-inserted alignment padding — CK_VERSION's 2 bytes would
/// otherwise misalign the first u32 field by 2 bytes on a naturally-
/// aligned struct (the exact bug this session found and fixed in the
/// browser-side CK_INFO decoder for the C++ engine's own struct). Matches
/// how CK_INFO/CK_SLOT_INFO/CK_TOKEN_INFO are already hand-written
/// elsewhere in this file.
fn function_list_bytes() -> &'static [u8] {
    static LIST: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut buf = vec![0u8; 2 + 68 * 4];
        buf[0] = 3; // CryptokiVersion.major
        buf[1] = 2; // CryptokiVersion.minor
        macro_rules! idx {
            ($f:expr) => {
                ($f as *const ()) as usize as u32
            };
        }
        #[rustfmt::skip]
        let entries: [u32; 68] = [
            idx!(C_Initialize), idx!(C_Finalize), idx!(C_GetInfo), idx!(C_GetFunctionList),
            idx!(C_GetSlotList), idx!(C_GetSlotInfo), idx!(C_GetTokenInfo),
            idx!(C_GetMechanismList), idx!(C_GetMechanismInfo), idx!(C_InitToken),
            idx!(C_InitPIN), idx!(C_SetPIN), idx!(C_OpenSession), idx!(C_CloseSession),
            idx!(C_CloseAllSessions), idx!(C_GetSessionInfo), idx!(C_GetOperationState),
            idx!(C_SetOperationState), idx!(C_Login), idx!(C_Logout), idx!(C_CreateObject),
            idx!(C_CopyObject), idx!(C_DestroyObject), idx!(C_GetObjectSize),
            idx!(C_GetAttributeValue), idx!(C_SetAttributeValue), idx!(C_FindObjectsInit),
            idx!(C_FindObjects), idx!(C_FindObjectsFinal), idx!(C_EncryptInit), idx!(C_Encrypt),
            idx!(C_EncryptUpdate), idx!(C_EncryptFinal), idx!(C_DecryptInit), idx!(C_Decrypt),
            idx!(C_DecryptUpdate), idx!(C_DecryptFinal), idx!(C_DigestInit), idx!(C_Digest),
            idx!(C_DigestUpdate), idx!(C_DigestKey), idx!(C_DigestFinal), idx!(C_SignInit),
            idx!(C_Sign), idx!(C_SignUpdate), idx!(C_SignFinal), idx!(C_SignRecoverInit),
            idx!(C_SignRecover), idx!(C_VerifyInit), idx!(C_Verify), idx!(C_VerifyUpdate),
            idx!(C_VerifyFinal), idx!(C_VerifyRecoverInit), idx!(C_VerifyRecover),
            idx!(C_DigestEncryptUpdate), idx!(C_DecryptDigestUpdate), idx!(C_SignEncryptUpdate),
            idx!(C_DecryptVerifyUpdate), idx!(C_GenerateKey), idx!(C_GenerateKeyPair),
            idx!(C_WrapKey), idx!(C_UnwrapKey), idx!(C_DeriveKey), idx!(C_SeedRandom),
            idx!(C_GenerateRandom), idx!(C_GetFunctionStatus), idx!(C_CancelFunction),
            idx!(C_WaitForSlotEvent),
        ];
        for (i, v) in entries.iter().enumerate() {
            buf[2 + i * 4..2 + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        buf
    })
}

/// PKCS#11 v3.2 §5.4.4. "It's OK to call C_GetFunctionList before calling
/// C_Initialize" — no `require_init!()` guard, matching that requirement
/// (also matches C_GetInterfaceList/C_GetInterface just below, and the
/// C++ engine's own C_GetFunctionList).
#[wasm_bindgen(js_name = _C_GetFunctionList)]
pub fn C_GetFunctionList(pp_function_list: *mut u8) -> u32 {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let ptr = function_list_bytes().as_ptr() as u32;
    unsafe {
        (pp_function_list as *mut u32).write(ptr);
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Initialize)]
pub fn C_Initialize(p_init_args: *mut u8) -> u32 {
    // PKCS#11 v3.2 §5.6 — a second C_Initialize without an intervening
    // C_Finalize must fail.
    if crate::state::is_initialized() {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    unsafe {
        if !p_init_args.is_null() {
            // CK_C_INITIALIZE_ARGS (wasm32, 4-byte pointers):
            //   pCreateMutex, pDestroyMutex, pLockMutex, pUnlockMutex,
            //   flags, pReserved  → pReserved is at byte offset 20.
            let p_reserved = *(p_init_args.add(20) as *const *const u8);
            if !p_reserved.is_null() {
                #[cfg(feature = "acvp")]
                {
                    // Vendor ACVP KAT hook (test builds only): pReserved points
                    // to CK_ACVP_TEST_ARGS { pSeed, ulSeedLen }. A non-matching
                    // shape is silently ignored to stay permissive for the
                    // harness. See the `acvp` feature in Cargo.toml.
                    let p_seed = *(p_reserved as *const *const u8);
                    let ul_seed_len = *(p_reserved.add(4) as *const u32);
                    if !p_seed.is_null() && ul_seed_len == 32 {
                        let seed_slice = std::slice::from_raw_parts(p_seed, 32);
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(seed_slice);
                        let rng = rand_chacha::ChaCha20Rng::from_seed(seed);
                        ACVP_RNG.with(|r| {
                            *r.borrow_mut() = Some(rng);
                        });
                    }
                }
                #[cfg(not(feature = "acvp"))]
                {
                    // PKCS#11 v3.2 §5.6 — pReserved MUST be NULL.
                    return CKR_ARGUMENTS_BAD;
                }
            }
        }
    }
    crate::state::init_token_store();
    crate::state::set_initialized(true);
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Finalize)]
pub fn C_Finalize(p_reserved: *mut u8) -> u32 {
    require_init!();
    // PKCS#11 v3.2 §5.6 — pReserved MUST be NULL.
    if !p_reserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // Emscripten staticlib embedding only (openssl.wasm): park a snapshot of
    // token-resident state BEFORE the wipe below, so the next callMain()'s
    // fresh module can rehydrate it. Native/wasm-bindgen builds skip this —
    // there, parking key material past finalize would defeat the zeroize.
    // See state_snapshot.rs and openssl-studio-pkcs11-wiring-plan-07242026.md.
    #[cfg(target_os = "emscripten")]
    crate::state_snapshot::stash_before_finalize();
    // §5.6 doesn't call for token objects to be destroyed by C_Finalize —
    // only session objects don't survive past a session's lifetime, and a
    // session can't outlive Finalize. Token objects (CKA_TOKEN=TRUE, e.g.
    // the built-in CKO_PROFILE from init_profile_objects) must persist
    // across a library unload/reload, same as C_InitToken already respects
    // via CKA_DESTROYABLE in destroy_destroyable_objects_on_slot. A prior
    // fix (e6d9668) stopped TOKEN_STORE from being wiped here but missed
    // this second store — WS-11's conformance runner caught it: a token
    // freshly re-initialized after Finalize came back with zero CKO_PROFILE
    // objects. CKA_TOKEN defaults to CK_FALSE (session object) when absent.
    OBJECTS.with(|o| {
        let mut store = o.borrow_mut();
        let session_objects: Vec<u32> = store
            .iter()
            .filter(|(_, attrs)| {
                !attrs
                    .get(&CKA_TOKEN)
                    .map(|v| v.first().copied().unwrap_or(0) != 0)
                    .unwrap_or(false)
            })
            .map(|(h, _)| *h)
            .collect();
        for h in session_objects {
            if let Some(mut attrs) = store.remove(&h) {
                if let Some(val) = attrs.get_mut(&CKA_VALUE) {
                    val.zeroize();
                }
            }
        }
    });
    // NEXT_HANDLE is intentionally NOT reset here anymore: token objects
    // above can now survive Finalize, so resetting the counter to 100 would
    // let the next allocate_handle() collide with (and silently overwrite)
    // a surviving object's handle. Handles keep counting up monotonically
    // across Finalize/Initialize cycles instead — matching a real token,
    // whose object handles don't reset just because the library reloaded.
    SIGN_STATE.with(|s| s.borrow_mut().clear());
    VERIFY_STATE.with(|s| s.borrow_mut().clear());
    VERIFY_SIG_STATE.with(|s| s.borrow_mut().clear());
    ENCRYPT_STATE.with(|s| s.borrow_mut().clear());
    DECRYPT_STATE.with(|s| s.borrow_mut().clear());
    // Message-based AEAD state holds raw key bytes, an armed GCM stream and
    // (decrypt) withheld plaintext — zeroize all of it before drop.
    MESSAGE_ENCRYPT_STATE.with(|s| {
        let mut m = s.borrow_mut();
        for ctx in m.values_mut() {
            ctx.wipe();
        }
        m.clear();
    });
    MESSAGE_DECRYPT_STATE.with(|s| {
        let mut m = s.borrow_mut();
        for ctx in m.values_mut() {
            ctx.wipe();
        }
        m.clear();
    });
    DIGEST_STATE.with(|s| s.borrow_mut().clear());
    DIGEST_MULTIPART.with(|s| s.borrow_mut().clear());
    FIND_STATE.with(|s| s.borrow_mut().clear());
    MESSAGE_SIGN_ACC.with(|s| s.borrow_mut().clear());
    MESSAGE_VERIFY_ACC.with(|s| s.borrow_mut().clear());
    SIGN_MULTIPART_ACC.with(|s| s.borrow_mut().clear());
    VERIFY_MULTIPART_ACC.with(|s| s.borrow_mut().clear());
    ACVP_RNG.with(|r| *r.borrow_mut() = None);
    SESSIONS.with(|s| s.borrow_mut().clear());
    // §5.4.2/§5.4.1 (checked directly against the OASIS spec text, 2026-08-28,
    // not assumed): C_Initialize/C_Finalize govern the application's
    // relationship with the *library* ("initialize its internal memory
    // buffers, or any other resources it requires" / "the last Cryptoki
    // call made by an application") — neither section mentions tokens,
    // objects, or persistent state at all. A token is meant to behave like
    // persistent storage (a smart card that stays inserted while the
    // driver unloads/reloads), so wiping TOKEN_STORE here was a real
    // non-conformance: WS-11's Tier A conformance runner caught it via
    // BL-M-1-32 (Profiles v3.2 §5.1.1), which assumes a token already
    // TOKEN_INITIALIZED/USER_PIN_INITIALIZED survives a fresh
    // C_Initialize — confirmed by a standalone probe (1 slot reporting
    // tokenPresent=1 before C_Finalize, 0 after C_Finalize + re-
    // C_Initialize with no intervening C_InitToken) and by contrast with
    // the C++ engine, which correctly retains token state across the same
    // cycle. Every session is gone at this point (cleared just above), so
    // each token's `login_state` still needs resetting — reuse the same
    // per-slot helper C_CloseAllSessions already uses for exactly this,
    // rather than the blanket `.clear()` that used to sit here.
    let all_slots: Vec<u32> = TOKEN_STORE.with(|ts| ts.borrow().keys().copied().collect());
    for slot_id in all_slots {
        reset_login_state_if_no_sessions(slot_id);
    }
    // UNLOCKED_MASTER_KEYS is a deliberately separate cache from TOKEN_STORE
    // (see its own doc comment in store/mod.rs) with one job — zeroize on
    // logout/finalize. Clearing it here is orthogonal to the TOKEN_STORE
    // persistence fix above: the token's objects survive Finalize, but any
    // unwrapped durable-storage master key an active session had cached
    // must not.
    crate::store::clear_all_unlocked_master_keys();
    crate::state::set_initialized(false);
    CKR_OK
}

/// Test-only full reset, including `TOKEN_STORE` — the wipe `C_Finalize`
/// used to (wrongly) do in production. `OBJECTS`/`SESSIONS`/`TOKEN_STORE`
/// are genuinely global (`lazy_static! GlobalState<T>`, a `Mutex` wrapper —
/// see `native::test_lock`'s own doc comment), so `cargo test`'s parallel
/// runner shares this state across every test unless serialized; every
/// `#[test]` here already takes `test_lock::acquire()` first for exactly
/// that reason. Before this function existed, individual tests' own
/// `reset_engine()` helpers got a guaranteed-clean slate as a side effect
/// of C_Finalize's now-removed TOKEN_STORE wipe — this restores that
/// guarantee explicitly, for tests only, without depending on production
/// C_Finalize behavior (which correctly no longer provides it). Does not
/// go through C_Finalize/`require_init!()` at all, unlike the individual
/// `reset_engine()` helpers that call this — a test that panicked without
/// finalizing must still get a truly clean slate, not a silent no-op.
///
/// `pub`, gated by `feature = "test-support"` in addition to `cfg(test)`:
/// kmip's own test suite (a downstream crate) hit the exact same
/// cross-test poisoning this function was built to prevent — its
/// fixtures share slot 0 with two different PIN literal conventions, and
/// used to get away with it only because production `C_Finalize` quietly
/// wiped `TOKEN_STORE`. `#[cfg(test)]` alone is crate-local and cannot
/// expose this to kmip's test binary, so `test-support` (opt-in,
/// dev-dependency only — see `Cargo.toml`) makes it a real, always-
/// compiled function for that one purpose without touching the
/// production `[dependencies]` build.
#[cfg(any(test, feature = "test-support"))]
pub fn reset_all_engine_state_for_test() {
    OBJECTS.with(|o| {
        let mut store = o.borrow_mut();
        for attrs in store.values_mut() {
            if let Some(val) = attrs.get_mut(&CKA_VALUE) {
                val.zeroize();
            }
        }
        store.clear();
    });
    NEXT_HANDLE.store(100, std::sync::atomic::Ordering::Relaxed);
    SIGN_STATE.with(|s| s.borrow_mut().clear());
    VERIFY_STATE.with(|s| s.borrow_mut().clear());
    VERIFY_SIG_STATE.with(|s| s.borrow_mut().clear());
    ENCRYPT_STATE.with(|s| s.borrow_mut().clear());
    DECRYPT_STATE.with(|s| s.borrow_mut().clear());
    MESSAGE_ENCRYPT_STATE.with(|s| {
        let mut m = s.borrow_mut();
        for ctx in m.values_mut() {
            ctx.wipe();
        }
        m.clear();
    });
    MESSAGE_DECRYPT_STATE.with(|s| {
        let mut m = s.borrow_mut();
        for ctx in m.values_mut() {
            ctx.wipe();
        }
        m.clear();
    });
    DIGEST_STATE.with(|s| s.borrow_mut().clear());
    DIGEST_MULTIPART.with(|s| s.borrow_mut().clear());
    FIND_STATE.with(|s| s.borrow_mut().clear());
    MESSAGE_SIGN_ACC.with(|s| s.borrow_mut().clear());
    MESSAGE_VERIFY_ACC.with(|s| s.borrow_mut().clear());
    SIGN_MULTIPART_ACC.with(|s| s.borrow_mut().clear());
    VERIFY_MULTIPART_ACC.with(|s| s.borrow_mut().clear());
    ACVP_RNG.with(|r| *r.borrow_mut() = None);
    SESSIONS.with(|s| s.borrow_mut().clear());
    TOKEN_STORE.with(|ts| ts.borrow_mut().clear());
    crate::state::set_initialized(false);
}

#[wasm_bindgen(js_name = _C_GetSlotList)]
pub fn C_GetSlotList(token_present: u8, p_slot_list: *mut u32, pul_count: *mut u32) -> u32 {
    require_init!();
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let token_present_bool = token_present != 0;

    // Auto-advance slots if needed (mimic SoftHSMv2/v3 shift: always provide 1 uninitialized token)
    TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        let all_initialized = store.values().all(|t| t.initialized);
        if all_initialized {
            let next_slot = store.keys().max().unwrap_or(&0) + 1;
            store.insert(
                next_slot,
                TokenState {
                    slot_id: next_slot,
                    initialized: false,
                    label: [0x20; 32],
                    login_state: LoginState::Public,
                    so_pin_salt: [0u8; 16],
                    so_pin_hash: [0u8; 32],
                    user_pin_salt: None,
                    user_pin_hash: None,
                },
            );
        }
    });

    let mut slots: Vec<u32> = TOKEN_STORE.with(|ts| {
        ts.borrow()
            .values()
            .filter(|t| !token_present_bool || t.initialized)
            .map(|t| t.slot_id)
            .collect()
    });
    slots.sort_unstable();

    unsafe {
        if p_slot_list.is_null() {
            *pul_count = slots.len() as u32;
        } else {
            if *pul_count < slots.len() as u32 {
                *pul_count = slots.len() as u32;
                return CKR_BUFFER_TOO_SMALL;
            }
            for (i, &slot_id) in slots.iter().enumerate() {
                *p_slot_list.add(i) = slot_id;
            }
            *pul_count = slots.len() as u32;
        }
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_InitToken)]
pub fn C_InitToken(slot_id: u32, p_pin: *mut u8, ul_pin_len: u32, p_label: *mut u8) -> u32 {
    require_init!();
    if p_pin.is_null() || p_label.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // In PKCS#11, you generally shouldn't call C_InitToken when sessions are open on that slot.
    let has_sessions = SESSIONS.with(|s| s.borrow().values().any(|sess| sess.slot_id == slot_id));
    if has_sessions {
        return CKR_SESSION_EXISTS;
    }

    let pin_bytes = unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) };

    // S1 (2026-08-13) — §5.5.7: "If the token is being reinitialized, the
    // pPin parameter is checked against the existing SO PIN to authorize the
    // initialization operation", and CKF_TOKEN_INITIALIZED "indicates the
    // action that will result from calling C_InitToken. If set, the token
    // will be reinitialized, and the client MUST supply the existing SO
    // password in pPin."
    //
    // Before this, the SO PIN hash was overwritten unconditionally and
    // `token.initialized` was never read: any caller could seize an
    // initialised token and install their own security-officer PIN. The
    // check runs BEFORE any state change, so a refused call leaves the token
    // and its objects exactly as they were.
    //
    // Deliberately NOT added (per §5.5.7's return list, which omits the
    // length-range code): PIN-length validation.
    let existing = match TOKEN_STORE.with(|ts| ts.borrow().get(&slot_id).cloned()) {
        Some(t) => t,
        None => return CKR_SLOT_ID_INVALID,
    };
    if crate::state::token_initialized(&existing)
        && hash_pin(pin_bytes, &existing.so_pin_salt) != existing.so_pin_hash
    {
        return CKR_PIN_INCORRECT;
    }

    // Hash PIN with PBKDF2
    let mut salt = [0u8; 16];
    if getrandom::getrandom(&mut salt).is_err() {
        return CKR_GENERAL_ERROR;
    }
    let so_pin_hash = hash_pin(pin_bytes, &salt);

    let label_bytes = unsafe { std::slice::from_raw_parts(p_label, 32) };
    let mut label = [0x20u8; 32];
    label.copy_from_slice(label_bytes);

    let success = TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        if let Some(token) = store.get_mut(&slot_id) {
            token.initialized = true;
            token.label = label;
            token.so_pin_salt = salt;
            token.so_pin_hash = so_pin_hash;
            token.user_pin_hash = None;
            token.user_pin_salt = None;
            token.login_state = LoginState::Public;
            true
        } else {
            false
        }
    });
    if !success {
        return CKR_SLOT_ID_INVALID;
    }

    // Encryption-at-rest master key: only when a durable store is
    // configured (memory-only mode does no PBKDF2/AES-GCM work at all).
    // Always FRESH here, on both first init and reinit — §5.5.7 already
    // destroys every destroyable object on this path, so there is no
    // surviving ciphertext a preserved key would need to keep decrypting;
    // generating fresh is simpler and strictly safer than trying to detect
    // "is this genuinely the first init" and branch.
    if crate::store::is_persistent() {
        if let Ok(master_key) = crate::store::crypto::generate_master_key() {
            if let Ok(so_wrapped) = crate::store::crypto::wrap_master_key(pin_bytes, &master_key) {
                crate::store::active().put_token(
                    slot_id,
                    &crate::store::PersistedToken {
                        initialized: true,
                        label,
                        so_pin_salt: salt,
                        so_pin_hash,
                        user_pin_salt: None,
                        user_pin_hash: None,
                        master_key_so_wrapped: Some(so_wrapped),
                        master_key_user_wrapped: None,
                        next_handle: 0,
                        unique_id_counter: 0,
                    },
                );
                crate::store::set_unlocked_master_key(slot_id, master_key);
            }
        }
    }

    // §5.5.7 — "When a token is initialized, all objects that can be
    // destroyed are destroyed." Scoped to THIS slot's token; CKA_DESTROYABLE
    // =FALSE objects (the built-in CKO_PROFILE) survive, as the wording
    // requires.
    crate::state::destroy_destroyable_objects_on_slot(slot_id);
    CKR_OK
}

#[wasm_bindgen(js_name = _C_OpenSession)]
pub fn C_OpenSession(
    slot_id: u32,
    flags: u32,
    _p_application: *mut u8,
    _notify: *mut u8,
    ph_session: *mut u32,
) -> u32 {
    require_init!();
    if ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let is_valid_slot = TOKEN_STORE.with(|ts| ts.borrow().contains_key(&slot_id));
    if !is_valid_slot {
        return CKR_SLOT_ID_INVALID;
    }
    // PKCS#11 v3.2 §5.6 — CKF_SERIAL_SESSION MUST be set; the legacy parallel
    // mode is not supported.
    if (flags & CKF_SERIAL_SESSION) == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    // §5.6.1 — async sessions are not supported; the token does not advertise
    // CKF_ASYNC_SESSION_SUPPORTED, so the request flag must be rejected.
    if (flags & CKF_ASYNC_SESSION) != 0 {
        return CKR_SESSION_ASYNC_NOT_SUPPORTED;
    }
    // Check if SO is logged in and trying to open a RO session
    let so_logged_in = TOKEN_STORE.with(|ts| {
        ts.borrow()
            .get(&slot_id)
            .map(|t| t.login_state == LoginState::SO)
            .unwrap_or(false)
    });
    let rw_session = (flags & CKF_RW_SESSION) != 0;
    if so_logged_in && !rw_session {
        return CKR_SESSION_READ_WRITE_SO_EXISTS;
    }
    unsafe {
        let handle = NEXT_SESSION_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *ph_session = handle;
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                handle,
                SessionState {
                    slot_id,
                    rw_session,
                },
            );
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_CloseSession)]
pub fn C_CloseSession(h_session: u32) -> u32 {
    require_init!();
    let slot = crate::state::session_slot(h_session);
    let existed = SESSIONS.with(|s| s.borrow_mut().remove(&h_session).is_some());
    if !existed {
        return CKR_SESSION_HANDLE_INVALID;
    }
    // PKCS#11 v3.2 §4.4 — session objects die with their creating session.
    crate::state::destroy_session_objects(h_session);
    // PKCS#11 v3.2 §5.6 — closing a session terminates all of its active
    // operations. Clear every per-session state map, zeroizing any that hold
    // raw key material (the message-based AEAD contexts).
    SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
    VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
    VERIFY_SIG_STATE.with(|s| s.borrow_mut().remove(&h_session));
    ENCRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
    DECRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
    MESSAGE_ENCRYPT_STATE.with(|s| {
        if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
            ctx.wipe();
        }
    });
    MESSAGE_DECRYPT_STATE.with(|s| {
        if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
            ctx.wipe();
        }
    });
    DIGEST_STATE.with(|s| s.borrow_mut().remove(&h_session));
    DIGEST_MULTIPART.with(|s| s.borrow_mut().remove(&h_session));
    FIND_STATE.with(|s| s.borrow_mut().remove(&h_session));
    MESSAGE_SIGN_ACC.with(|s| s.borrow_mut().remove(&h_session));
    MESSAGE_VERIFY_ACC.with(|s| s.borrow_mut().remove(&h_session));
    SIGN_MULTIPART_ACC.with(|s| s.borrow_mut().remove(&h_session));
    VERIFY_MULTIPART_ACC.with(|s| s.borrow_mut().remove(&h_session));
    // S6 — §5.6.2: when the LAST session on the slot closes, the login state
    // returns to public.
    if let Some(slot) = slot {
        reset_login_state_if_no_sessions(slot);
    }
    CKR_OK
}

/// PKCS#11 v3.2 §5.6 — close every session on the slot (op-state cleanup +
/// session-object destruction per C_CloseSession semantics).
#[wasm_bindgen(js_name = _C_CloseAllSessions)]
pub fn C_CloseAllSessions(slot_id: u32) -> u32 {
    require_init!();
    let valid = TOKEN_STORE.with(|ts| ts.borrow().contains_key(&slot_id));
    if !valid {
        return CKR_SLOT_ID_INVALID;
    }
    let handles: Vec<u32> = SESSIONS.with(|s| {
        s.borrow()
            .iter()
            .filter(|(_, ss)| ss.slot_id == slot_id)
            .map(|(h, _)| *h)
            .collect()
    });
    for h in handles {
        let _ = C_CloseSession(h);
    }
    // S6 — §5.6.3 states the reset explicitly for this function. C_CloseSession
    // already performs it when it removes the last session, but a slot with
    // ZERO sessions open must also end up public, so call it unconditionally.
    reset_login_state_if_no_sessions(slot_id);
    CKR_OK
}

/// PKCS#11 v3.0+ §5.6 — cancel active operations selected by `flags`
/// (CKF_ENCRYPT 0x100, CKF_DECRYPT 0x200, CKF_DIGEST 0x400, CKF_SIGN 0x800,
/// CKF_VERIFY 0x2000, CKF_FIND_OBJECTS 0x40, CKF_MESSAGE_ENCRYPT 0x2,
/// CKF_MESSAGE_DECRYPT 0x4, CKF_MESSAGE_SIGN 0x8, CKF_MESSAGE_VERIFY 0x10).
/// flags == 0 cancels nothing.
#[wasm_bindgen(js_name = _C_SessionCancel)]
pub fn C_SessionCancel(h_session: u32, flags: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    if flags & 0x100 != 0 {
        ENCRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x200 != 0 {
        DECRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x400 != 0 {
        DIGEST_STATE.with(|s| s.borrow_mut().remove(&h_session));
        DIGEST_MULTIPART.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x800 != 0 {
        SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
        // T4 — the multi-part accumulator dies with the sign op.
        SIGN_MULTIPART_ACC.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x2000 != 0 {
        VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
        VERIFY_SIG_STATE.with(|s| s.borrow_mut().remove(&h_session));
        // T4 — the multi-part accumulator dies with the verify op.
        VERIFY_MULTIPART_ACC.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x40 != 0 {
        FIND_STATE.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x2 != 0 {
        // CKF_MESSAGE_ENCRYPT — wipe key, armed GCM stream and buffers.
        MESSAGE_ENCRYPT_STATE.with(|s| {
            if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
                ctx.wipe();
            }
        });
    }
    if flags & 0x4 != 0 {
        // CKF_MESSAGE_DECRYPT — also zeroizes any withheld plaintext.
        MESSAGE_DECRYPT_STATE.with(|s| {
            if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
                ctx.wipe();
            }
        });
    }
    if flags & 0x8 != 0 {
        // CKF_MESSAGE_SIGN — terminate the message-based sign op (the
        // C_MessageSignInit state lives in SIGN_STATE; the per-message
        // accumulator in MESSAGE_SIGN_ACC), mirroring C_CloseSession.
        SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
        MESSAGE_SIGN_ACC.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x10 != 0 {
        // CKF_MESSAGE_VERIFY — terminate the message-based verify op.
        VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
        MESSAGE_VERIFY_ACC.with(|s| s.borrow_mut().remove(&h_session));
    }
    CKR_OK
}

/// PKCS#11 v3.0+ §5.6 — C_Login with a username. This single-user token
/// accepts only an empty username (delegates to C_Login); anything else is
/// CKR_OPERATION_NOT_SUPPORTED... which v3.2 spells CKR_FUNCTION_NOT_SUPPORTED
/// for an unsupported variant.
#[wasm_bindgen(js_name = _C_LoginUser)]
pub fn C_LoginUser(
    h_session: u32,
    user_type: u32,
    p_pin: *mut u8,
    ul_pin_len: u32,
    _p_username: *mut u8,
    _ul_username_len: u32,
) -> u32 {
    require_init!();
    // PKCS#11 v3.2 §5.6 — this token has no distinct-named-user concept (only
    // the single CKU_USER / CKU_SO roles), so pUsername is advisory and
    // ignored; C_LoginUser behaves exactly as C_Login. (Matches the C++ engine,
    // which returns CKR_USER_ALREADY_LOGGED_IN when a session is already
    // logged in, rather than refusing a named login outright.)
    C_Login(h_session, user_type, p_pin, ul_pin_len)
}

#[wasm_bindgen(js_name = _C_Login)]
pub fn C_Login(h_session: u32, user_type: u32, p_pin: *mut u8, ul_pin_len: u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class takes
    // MANDATORY precedence over argument codes.
    let session = match SESSIONS.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(s) => s,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    if p_pin.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // C2 (2026-08-13) — CKU_CONTEXT_SPECIFIC is one of the THREE valid
    // CK_USER_TYPE values; returning CKR_USER_TYPE_INVALID for it (the old
    // behaviour, via the catch-all arm below) told the application the type
    // does not exist. It is the per-operation re-authentication login used
    // with CKA_ALWAYS_AUTHENTICATE keys. This engine has no operation that
    // sets a re-authentication pending state, so the correct answer is
    // "accepted, but there is nothing to authenticate for":
    // CKR_OPERATION_NOT_INITIALIZED.
    if user_type == CKU_CONTEXT_SPECIFIC {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let slot_id = session.slot_id;

    if user_type == CKU_SO && !session.rw_session {
        return CKR_SESSION_READ_ONLY_EXISTS;
    }

    // PERF-BENCH FIX (2026-07-18): the exclusivity check (§5.6 "only one
    // login wins") and the login_state write used to happen in two SEPARATE
    // TOKEN_STORE lock acquisitions, with the check evaluated against a
    // `.cloned()` snapshot taken before the write. Under concurrent
    // C_Login calls on the same token (20-thread spike,
    // p0_spike_multitenant_concurrency.rs::p0c) this is a TOCTOU race: many
    // threads can all read the pre-login snapshot before any of them
    // writes, so all of them pass the "not already logged in" check and
    // all "succeed" — silently violating the one-login-wins guarantee.
    // Fixed by making read-check-PIN-hash-write one atomic critical
    // section per branch, inside a single lock acquisition (matching the
    // pattern C_Logout already used correctly). `has_ro` still reads
    // SESSIONS before entering the TOKEN_STORE closure, preserving the
    // existing lock-acquisition order used throughout this file.
    let has_ro = SESSIONS.with(|s| {
        s.borrow()
            .values()
            .any(|sess| sess.slot_id == slot_id && !sess.rw_session)
    });
    let pin_bytes = unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) };

    let rv = TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        let token = match store.get_mut(&slot_id) {
            Some(t) => t,
            None => return CKR_GENERAL_ERROR,
        };
        if !token.initialized {
            return CKR_OPERATION_NOT_INITIALIZED;
        }

        // Evaluate PKCS#11 v3.2 Exclusivity Boundaries
        match user_type {
            CKU_SO => {
                if token.login_state == LoginState::SO {
                    return CKR_USER_ALREADY_LOGGED_IN;
                }
                if token.login_state == LoginState::User {
                    return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                }
                if has_ro {
                    return CKR_SESSION_READ_ONLY_EXISTS;
                }
                if hash_pin(pin_bytes, &token.so_pin_salt) != token.so_pin_hash {
                    return CKR_PIN_INCORRECT;
                }
                token.login_state = LoginState::SO;
            }
            CKU_USER => {
                if token.login_state == LoginState::User {
                    return CKR_USER_ALREADY_LOGGED_IN;
                }
                if token.login_state == LoginState::SO {
                    return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                }
                let (salt, hash) = match (&token.user_pin_salt, &token.user_pin_hash) {
                    (Some(salt), Some(hash)) => (*salt, *hash),
                    _ => return CKR_USER_PIN_NOT_INITIALIZED,
                };
                if hash_pin(pin_bytes, &salt) != hash {
                    return CKR_PIN_INCORRECT;
                }
                token.login_state = LoginState::User;
            }
            _ => return CKR_USER_TYPE_INVALID,
        }
        CKR_OK
    });
    if rv == CKR_OK && crate::store::is_persistent() {
        // Unlock: fetch this role's wrapped master-key blob and open it
        // with the PIN just verified above. Outside the TOKEN_STORE lock —
        // PBKDF2 (210k iterations) + AES-GCM open have no business running
        // under a global mutex. A missing/unopenable blob is not an error
        // here: an older token created before persistence was configured,
        // or one whose PIN was set before this slot ever pointed at a
        // store, simply has nothing to unlock yet.
        let role = if user_type == CKU_SO {
            crate::store::PinRole::So
        } else {
            crate::store::PinRole::User
        };
        if let Some(token) = crate::store::active().get_token(slot_id) {
            let wrapped = match role {
                crate::store::PinRole::So => token.master_key_so_wrapped,
                crate::store::PinRole::User => token.master_key_user_wrapped,
            };
            if let Some(wrapped) = wrapped {
                if let Ok(master_key) = crate::store::crypto::unwrap_master_key(pin_bytes, &wrapped) {
                    crate::store::set_unlocked_master_key(slot_id, master_key);
                    crate::store::rehydrate_private_objects(slot_id, &master_key);
                }
            }
        }
    }
    rv
}

#[wasm_bindgen(js_name = _C_Logout)]
pub fn C_Logout(h_session: u32) -> u32 {
    require_init!();
    let session = match SESSIONS.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(s) => s,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let slot_id = session.slot_id;
    let mut changed = false;
    TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        if let Some(token) = store.get_mut(&slot_id) {
            if token.login_state != LoginState::Public {
                token.login_state = LoginState::Public;
                changed = true;
            }
        }
    });
    if changed {
        // S6 (2026-08-13) — §5.6.10. Before this, C_Logout flipped the login
        // state and returned: every outstanding handle to a private object
        // kept working the moment a user logged back in, and private session
        // objects survived. Both are now handled in one pass; see
        // state::invalidate_private_handles_on_slot for why token objects are
        // re-keyed rather than marked.
        crate::state::invalidate_private_handles_on_slot(slot_id);
        crate::store::clear_unlocked_master_key(slot_id);
        CKR_OK
    } else {
        CKR_USER_NOT_LOGGED_IN
    }
}

/// S6 — §5.6.2 / §5.6.3: closing the last session on a slot, and
/// C_CloseAllSessions, both return "the login state of the token for the
/// application … to public sessions". Without this a fresh session opened on
/// the slot afterwards was already authenticated. Runs the same private-handle
/// invalidation C_Logout does, since the application's authenticated context
/// is equally gone.
fn reset_login_state_if_no_sessions(slot_id: u32) {
    let still_open = SESSIONS.with(|s| s.borrow().values().any(|ss| ss.slot_id == slot_id));
    if still_open {
        return;
    }
    let was_logged_in = TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        match store.get_mut(&slot_id) {
            Some(token) if token.login_state != LoginState::Public => {
                token.login_state = LoginState::Public;
                true
            }
            _ => false,
        }
    });
    if was_logged_in {
        crate::state::invalidate_private_handles_on_slot(slot_id);
        crate::store::clear_unlocked_master_key(slot_id);
    }
}

/// T6 — PIN length bounds enforced by C_InitPIN / C_SetPIN. These are the
/// very values C_GetTokenInfo advertises (ulMinPinLen / ulMaxPinLen), so the
/// token cannot advertise one policy and enforce another. Violations →
/// CKR_PIN_LEN_RANGE (PKCS#11 v3.2 §5.6).
pub const PIN_MIN_LEN: u32 = 4;
pub const PIN_MAX_LEN: u32 = 256;

#[wasm_bindgen(js_name = _C_InitPIN)]
pub fn C_InitPIN(h_session: u32, p_pin: *mut u8, ul_pin_len: u32) -> u32 {
    require_init!();
    if p_pin.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // T6 — enforce the advertised PIN bounds (see PIN_MIN_LEN/PIN_MAX_LEN).
    if !(PIN_MIN_LEN..=PIN_MAX_LEN).contains(&ul_pin_len) {
        return CKR_PIN_LEN_RANGE;
    }
    let session = match SESSIONS.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(s) => s,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    if !session.rw_session {
        // PKCS#11 v3.2 §5.7 — C_InitPIN requires a read/write SO session.
        return CKR_SESSION_READ_ONLY;
    }
    let slot_id = session.slot_id;
    let pin_bytes = unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) };
    let mut success = false;
    let mut not_logged_in = false;
    // Snapshot for persistence, captured from inside the same lock that
    // makes the change (cheap — no I/O under the lock), used after it
    // releases.
    let mut snapshot: Option<crate::store::PersistedToken> = None;
    TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        if let Some(token) = store.get_mut(&slot_id) {
            if token.login_state != LoginState::SO {
                not_logged_in = true;
                return;
            }
            let mut salt = [0u8; 16];
            if getrandom::getrandom(&mut salt).is_err() {
                return;
            }
            token.user_pin_hash = Some(hash_pin(pin_bytes, &salt));
            token.user_pin_salt = Some(salt);
            success = true;
            if crate::store::is_persistent() {
                snapshot = Some(crate::store::PersistedToken {
                    initialized: token.initialized,
                    label: token.label,
                    so_pin_salt: token.so_pin_salt,
                    so_pin_hash: token.so_pin_hash,
                    user_pin_salt: token.user_pin_salt,
                    user_pin_hash: token.user_pin_hash,
                    master_key_so_wrapped: None, // filled in below, unchanged
                    master_key_user_wrapped: None, // filled in below
                    next_handle: 0,
                    unique_id_counter: 0,
                });
            }
        }
    });
    if not_logged_in {
        return CKR_USER_NOT_LOGGED_IN;
    }
    if !success {
        return CKR_GENERAL_ERROR;
    }
    if let Some(mut snap) = snapshot {
        // SO is required to be logged in above, so the master key is
        // already unlocked for this slot — wrap it under the new User PIN
        // too, keeping the existing SO wrap untouched.
        let existing = crate::store::active().get_token(slot_id);
        snap.master_key_so_wrapped = existing.and_then(|t| t.master_key_so_wrapped);
        if let Some(master_key) = crate::store::unlocked_master_key(slot_id) {
            if let Ok(wrapped) = crate::store::crypto::wrap_master_key(pin_bytes, &master_key) {
                snap.master_key_user_wrapped = Some(wrapped);
            }
        }
        crate::store::active().put_token(slot_id, &snap);
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetSessionInfo)]
pub fn C_GetSessionInfo(h_session: u32, p_info: *mut u8) -> u32 {
    require_init!();
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let session = match SESSIONS.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(s) => s,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let login_state = TOKEN_STORE.with(|ts| {
        ts.borrow()
            .get(&session.slot_id)
            .map(|t| t.login_state)
            .unwrap_or(LoginState::Public)
    });
    unsafe {
        let ptr = p_info as *mut u32;
        *ptr = session.slot_id;
        let actual_state = match (login_state, session.rw_session) {
            (LoginState::SO, true) => CKS_RW_SO_FUNCTIONS,     // 4
            (LoginState::User, true) => CKS_RW_USER_FUNCTIONS, // 3
            (LoginState::User, false) => CKS_RO_USER_FUNCTIONS, // 1
            (LoginState::Public, true) => CKS_RW_PUBLIC_SESSION, // 2
            (LoginState::Public, false) => CKS_RO_PUBLIC_SESSION, // 0
            _ => 0,
        };
        *ptr.add(1) = actual_state;
        let flags = CKF_SERIAL_SESSION
            | if session.rw_session {
                CKF_RW_SESSION
            } else {
                0
            };
        *ptr.add(2) = flags;
        *ptr.add(3) = 0; // ulDeviceError
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetTokenInfo)]
pub fn C_GetTokenInfo(slot_id: u32, p_info: *mut u8) -> u32 {
    require_init!();
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // PKCS#11 v3.2 §5.5 — validate the slot.
    let token = TOKEN_STORE.with(|ts| ts.borrow().get(&slot_id).cloned());
    let token = match token {
        Some(t) => t,
        None => return CKR_SLOT_ID_INVALID,
    };
    // Audit H-15 — TokenInfo is dynamic: flags derive from real token state
    // (state::token_info_flags), the label is the per-instance token label
    // (default "SoftHSM3-Rust", settable via native::set_token_label or
    // C_InitToken), and session counters come from the live session table.
    let flags = crate::state::token_info_flags(&token);
    let (session_count, rw_session_count) = crate::state::session_counts(slot_id);
    unsafe {
        // utcTime [144..160] stays blank-padded: no CKF_CLOCK_ON_TOKEN.
        std::ptr::write_bytes(p_info, 0x20, 160);
        // label[32] @0 — already space-padded to 32 bytes in TokenState.
        std::ptr::copy_nonoverlapping(token.label.as_ptr(), p_info, 32);
        write_fixed_str(p_info, 32, "SoftHSM project", 32);
        write_fixed_str(p_info, 64, "PQCToday", 16);
        write_fixed_str(p_info, 80, "0001", 16);

        let ptr = p_info as *mut u32;
        *ptr.add(24) = flags; // flags @96
        // Session limits are unbounded (C_OpenSession never refuses on
        // count), so the max fields report CK_UNAVAILABLE_INFORMATION;
        // the current counts are live values from SESSIONS.
        *ptr.add(25) = CK_UNAVAILABLE_INFORMATION; // ulMaxSessionCount @100
        *ptr.add(26) = session_count; // ulSessionCount @104
        *ptr.add(27) = CK_UNAVAILABLE_INFORMATION; // ulMaxRwSessionCount @108
        *ptr.add(28) = rw_session_count; // ulRwSessionCount @112
        *ptr.add(29) = PIN_MAX_LEN; // ulMaxPinLen @116 — enforced by C_InitPIN/C_SetPIN
        *ptr.add(30) = PIN_MIN_LEN; // ulMinPinLen @120 — enforced by C_InitPIN/C_SetPIN
        // The engine does not meter object memory — report
        // CK_UNAVAILABLE_INFORMATION rather than fake numbers (§5.5).
        *ptr.add(31) = CK_UNAVAILABLE_INFORMATION; // ulTotalPublicMemory @124
        *ptr.add(32) = CK_UNAVAILABLE_INFORMATION; // ulFreePublicMemory @128
        *ptr.add(33) = CK_UNAVAILABLE_INFORMATION; // ulTotalPrivateMemory @132
        *ptr.add(34) = CK_UNAVAILABLE_INFORMATION; // ulFreePrivateMemory @136
        *p_info.add(140) = 3; // hardwareVersion.major
        *p_info.add(141) = 2; // hardwareVersion.minor
        *p_info.add(142) = 0; // firmwareVersion.major
        *p_info.add(143) = 1; // firmwareVersion.minor
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetMechanismInfo)]
pub fn C_GetMechanismInfo(slot_id: u32, mech_type: u32, p_info: *mut u8) -> u32 {
    require_init!();
    // W6 (2026-08-13) — §5.5.6: "slotID is the ID of the token's slot", with
    // CKR_SLOT_ID_INVALID enumerated. The parameter was bound as `_slot_id`
    // and never read, so ANY slot id returned success with slot-0 data.
    // C_GetMechanismList (right above) already validated it; the two are now
    // consistent.
    if !TOKEN_STORE.with(|ts| ts.borrow().contains_key(&slot_id)) {
        return CKR_SLOT_ID_INVALID;
    }
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (min_key, max_key, flags) = match mechanism_info(mech_type) {
        Some(t) => t,
        None => return CKR_MECHANISM_INVALID,
    };
    unsafe {
        let ptr = p_info as *mut u32;
        *ptr = min_key;
        *ptr.add(1) = max_key;
        *ptr.add(2) = flags;
    }
    CKR_OK
}

/// (ulMinKeySize, ulMaxKeySize, flags) for every supported mechanism — the
/// single source backing C_GetMechanismInfo. A unit test asserts every entry
/// of `SUPPORTED_MECHS` is answerable here, so the advertised list and this
/// table can never drift apart (gap-analysis R6.2).
/// C3 (2026-08-13) — PKCS#11 v3.2 §6.3.3 states three times, once per flag
/// group, that a library performing EC mechanisms **must set** these on EACH
/// EC mechanism: the field type (`CKF_EC_F_P` / `CKF_EC_F_2M`), the
/// CKA_EC_PARAMS encodings it accepts (`CKF_EC_OID` / `CKF_EC_CURVENAME` /
/// `CKF_EC_ECPARAMETERS`), and the point forms it accepts
/// (`CKF_EC_UNCOMPRESS` / `CKF_EC_COMPRESS`).
///
/// This engine advertised NONE of them on ANY EC mechanism, though it
/// supports prime-field curves, both named-curve encodings (W1's
/// `decode_ec_params` accepts the OID and curveName CHOICE arms) and
/// uncompressed points. Ten mechanisms were affected. Flag VALUES are taken
/// from the pinned canonical OASIS header, not from a pdftotext rendering.
///
/// Not set, deliberately and accurately: `CKF_EC_F_2M` (no binary-field
/// curves), `CKF_EC_ECPARAMETERS` (explicit parameters are rejected — see
/// `decode_ec_params`), and `CKF_EC_COMPRESS` (the engine emits and expects
/// uncompressed points).
const EC_CAPABILITY_FLAGS: u32 =
    CKF_EC_F_P | CKF_EC_OID | CKF_EC_CURVENAME | CKF_EC_UNCOMPRESS;

pub fn mechanism_info(mech_type: u32) -> Option<(u32, u32, u32)> {
    let info = match mech_type {
        // WS-11 Phase 1 (2026-08-28) widened 1024-4096 to 512-16384 — the
        // Extended Provider mandatory test case (EXT-M-1-32) records these
        // exact bounds from the OASIS example (itself SoftHSM2's own
        // advertised range, matching this engine's C++ sibling,
        // OSSLRSA::getMinKeySize/getMaxKeySize). 512-bit RSA is
        // cryptographically weak and never the default (rsa_keygen's own
        // floor comment already says so) — advertising it is not
        // recommending it, and RSA-1024-4096 test coverage is unaffected.
        CKM_RSA_PKCS_KEY_PAIR_GEN => (512, 16384, 0x00010000u32),
        // Raw RSA PKCS#1 v1.5 — sign/verify + encrypt/decrypt + (2026-07-25)
        // sign-recover/verify-recover (CKF_SIGN_RECOVER 0x1000 |
        // CKF_VERIFY_RECOVER 0x4000; C_SignRecover reuses this mechanism's
        // existing sign_rsa() primitive directly, see that fn's doc comment).
        // R-2 (2026-08-24): encrypt/decrypt are now genuinely wired (see
        // CKM_RSA_PKCS's arms in C_Encrypt/C_Decrypt) — this advertisement
        // was accurate in intent from 2026-07-25 but the dispatch match
        // didn't back it until now; the decrypt arm carries a reviewed,
        // accepted padding-oracle risk decision, documented in full there.
        // WS-11 Phase 1: CKF_WRAP|CKF_UNWRAP (0x00020000|0x00040000) added
        // alongside real CKM_RSA_PKCS support in C_WrapKey/C_UnwrapKey
        // (same under-advertised-capability class as the CKM_RSA_PKCS_OAEP
        // arm below) — EXT-M-1-32 expects both bits set.
        CKM_RSA_PKCS => (
            512,
            16384,
            0x00000800
                | 0x00002000
                | 0x00000100
                | 0x00000200
                | 0x00001000
                | 0x00004000
                | 0x00020000
                | 0x00040000,
        ),
        // CKM_RSA_X_509 — raw RSASP1/RSAVP1, no padding. Added 2026-07-25
        // for sign-recover/verify-recover ONLY; CKF_SIGN/CKF_VERIFY/
        // CKF_ENCRYPT/CKF_DECRYPT are deliberately NOT set here — this
        // mechanism has no regular Sign/Verify/Encrypt/Decrypt
        // implementation in this engine, and advertising flags for
        // operations that don't exist would be exactly the kind of
        // dishonest capability claim this engine's conformance work has
        // consistently avoided elsewhere.
        CKM_RSA_X_509 => (1024, 4096, 0x00001000 | 0x00004000),
        CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
        | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS
        | CKM_RSA_PKCS_PSS | CKM_SHA3_384_RSA_PKCS | CKM_SHA3_384_RSA_PKCS_PSS => {
            (2048, 4096, 0x00000800 | 0x00002000)
        }
        // C3 (2026-08-13) — a mechanism flag is DEFINED as "the mechanism can
        // be used with function F". C_WrapKey / C_UnwrapKey accept
        // CKM_RSA_PKCS_OAEP, CKM_AES_CBC and CKM_AES_CBC_PAD, so all three
        // under-advertised wrap: an application checking capabilities before
        // use would conclude the engine could not do what it in fact does.
        CKM_RSA_PKCS_OAEP => (
            2048,
            4096,
            0x00000100 | 0x00000200 | CKF_WRAP | CKF_UNWRAP,
        ),
        // PKCS#11 v3.2 §6.67–§6.69: ulMin/MaxKeySize for ML-DSA / ML-KEM /
        // SLH-DSA are PUBLIC-KEY sizes in BYTES (FIPS 203/204/205), not
        // parameter-set numbers.
        // ML-KEM ek: 800 B (ML-KEM-512) … 1568 B (ML-KEM-1024) — FIPS 203 Table 3.
        CKM_ML_KEM_KEY_PAIR_GEN => (800, 1568, 0x00010000),
        CKM_ML_KEM => (800, 1568, 0x10000000 | 0x20000000),
        // FrodoKEM (BSI TR-02102-1 §2.4.1) — ek: 9616 B (FrodoKEM-640) … 21520 B
        // (FrodoKEM-1344), verified directly against `frodo-kem` v0.1.0's
        // `AlgorithmParams::encryption_key_length` (not the spec PDF, to avoid
        // a version mismatch between the two).
        CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN => (9616, 21520, 0x00010000),
        CKM_PQCTODAY_FRODOKEM_ENCAPSULATE => (9616, 21520, 0x10000000 | 0x20000000),
        // Classic McEliece (BSI TR-02102-1 §2.4.2) — scoped to mceliece6688128
        // only (see implementation plan Phase 0.5); ek: 1,044,992 B, verified
        // directly against `classic-mceliece-rust` v2.0.2's
        // `CRYPTO_PUBLICKEYBYTES` for that parameter set.
        CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN => (1_044_992, 1_044_992, 0x00010000),
        CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE => (1_044_992, 1_044_992, 0x10000000 | 0x20000000),
        // ML-DSA pk: 1312 B (ML-DSA-44) … 2592 B (ML-DSA-87) — FIPS 204 Table 2.
        CKM_ML_DSA_KEY_PAIR_GEN => (1312, 2592, 0x00010000),
        // CKF_SIGN | CKF_VERIFY | CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY —
        // C_MessageSign/Verify* are implemented for these (pkcs11t.h 0x8/0x10).
        CKM_ML_DSA => (1312, 2592, 0x00000800 | 0x00002000 | 0x0008 | 0x0010),
        // SLH-DSA pk: 32 B (128-bit sets) … 64 B (256-bit sets) — FIPS 205 Table 2.
        CKM_SLH_DSA_KEY_PAIR_GEN => (32, 64, 0x00010000),
        CKM_SLH_DSA => (32, 64, 0x00000800 | 0x00002000 | 0x0008 | 0x0010),
        CKM_SHA256 | CKM_SHA384 | CKM_SHA512 | CKM_SHA3_256 | CKM_SHA3_512 => (0, 0, 0x00000400),
        // Historical RIPEMD-160 digest (CKF_DIGEST).
        CKM_RIPEMD160 => (0, 0, 0x00000400),
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
        | CKM_SHA3_512_HMAC | CKM_RIPEMD160_HMAC => (16, 64, 0x00000800 | 0x00002000),
        CKM_SHA256_HMAC_GENERAL
        | CKM_SHA384_HMAC_GENERAL
        | CKM_SHA512_HMAC_GENERAL
        | CKM_SHA3_256_HMAC_GENERAL
        | CKM_SHA3_512_HMAC_GENERAL => (16, 64, 0x00000800 | 0x00002000),
        CKM_KMAC_128 | CKM_KMAC_256 => (16, 64, 0x00000800 | 0x00002000),
        CKM_GENERIC_SECRET_KEY_GEN => (1, 512, 0x00008000),
        // Engine generates P-256/P-384/P-521 (+ secp256k1) — range unified
        // with CKM_ECDSA below (compliance-audit P-15).
        CKM_EC_KEY_PAIR_GEN => (256, 521, 0x00010000 | EC_CAPABILITY_FLAGS),
        CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
            (256, 521, 0x00000800 | 0x00002000 | EC_CAPABILITY_FLAGS)
        }
        // T1 — C_DeriveKey dispatches P-256 / secp256k1 / P-384 / P-521 for
        // both ECDH1 mechanisms; advertise the full dispatched range.
        // 2026-08-13 (ECDH-as-KEM parity with the C++ engine): plain
        // CKM_ECDH1_DERIVE is also dispatched by C_EncapsulateKey /
        // C_DecapsulateKey (§6.3.17 Table 78) — advertise
        // CKF_ENCAPSULATE (0x10000000) | CKF_DECAPSULATE (0x20000000),
        // mirroring CKM_ML_KEM above. The cofactor variant stays derive-only.
        CKM_ECDH1_DERIVE => (
            256,
            521,
            0x00080000 | 0x10000000 | 0x20000000 | EC_CAPABILITY_FLAGS,
        ),
        CKM_ECDH1_COFACTOR_DERIVE => (256, 521, 0x00080000 | EC_CAPABILITY_FLAGS),
        // Ed25519 (255-bit) and Ed448 (448-bit) — both curves implemented
        // (2026-08-27), mirroring the Montgomery arm's range just below.
        CKM_EC_EDWARDS_KEY_PAIR_GEN => (255, 448, 0x00010000 | EC_CAPABILITY_FLAGS),
        CKM_EDDSA => (255, 448, 0x00000800 | 0x00002000 | EC_CAPABILITY_FLAGS),
        // PKCS#11 v3.2 §6.7 — Montgomery-curve key pair generation (X25519=255-bit, X448=448-bit)
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN => (255, 448, 0x00010000 | EC_CAPABILITY_FLAGS),
        // PKCS#11 v3.2 §6.7 — Montgomery key derivation (X25519 or X448)
        CKM_EC_MONTGOMERY_KEY_DERIVE => (255, 448, 0x00080000 | EC_CAPABILITY_FLAGS),
        // PKCS#11 v3.2 §6.7 — dedicated X25519 / X448 Diffie-Hellman (CKF_DERIVE)
        CKM_X25519 => (255, 255, 0x00080000 | EC_CAPABILITY_FLAGS),
        CKM_X448 => (448, 448, 0x00080000 | EC_CAPABILITY_FLAGS),
        CKM_AES_KEY_GEN => (16, 32, 0x00008000),
        // §6.20 — ChaCha20 key generation (fixed 256-bit key, CKF_GENERATE).
        CKM_CHACHA20_KEY_GEN => (32, 32, 0x00008000),
        // AES-GCM additionally has C_EncryptMessage/C_DecryptMessage support
        // (CKF_MESSAGE_ENCRYPT 0x2 | CKF_MESSAGE_DECRYPT 0x4, pkcs11t.h).
        CKM_AES_GCM => (16, 32, 0x00000100 | 0x00000200 | 0x0002 | 0x0004),
        // C3 — CKM_AES_CBC / CKM_AES_CBC_PAD are accepted by the wrap path;
        // CKM_AES_ECB is NOT, so it keeps encrypt/decrypt only.
        CKM_AES_CBC_PAD | CKM_AES_CBC => {
            (16, 32, 0x00000100 | 0x00000200 | CKF_WRAP | CKF_UNWRAP)
        }
        CKM_AES_ECB => (16, 32, 0x00000100 | 0x00000200),
        CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP | CKM_AES_KEY_WRAP_PAD => {
            (16, 32, 0x00040000 | 0x00020000)
        }
        CKM_AES_CTR => (16, 32, 0x00000100 | 0x00000200),
        // ML-DSA pre-hash variants — same sign/verify capabilities as pure ML-DSA
        CKM_HASH_ML_DSA_SHA224
        | CKM_HASH_ML_DSA_SHA256
        | CKM_HASH_ML_DSA_SHA384
        | CKM_HASH_ML_DSA_SHA512
        | CKM_HASH_ML_DSA_SHA3_224
        | CKM_HASH_ML_DSA_SHA3_256
        | CKM_HASH_ML_DSA_SHA3_384
        | CKM_HASH_ML_DSA_SHA3_512
        | CKM_HASH_ML_DSA_SHAKE128
        | CKM_HASH_ML_DSA_SHAKE256 => (1312, 2592, 0x00000800 | 0x00002000),
        // SLH-DSA pre-hash variants — same sign/verify capabilities as pure SLH-DSA
        CKM_HASH_SLH_DSA_SHA224
        | CKM_HASH_SLH_DSA_SHA256
        | CKM_HASH_SLH_DSA_SHA384
        | CKM_HASH_SLH_DSA_SHA512
        | CKM_HASH_SLH_DSA_SHA3_224
        | CKM_HASH_SLH_DSA_SHA3_256
        | CKM_HASH_SLH_DSA_SHA3_384
        | CKM_HASH_SLH_DSA_SHA3_512
        | CKM_HASH_SLH_DSA_SHAKE128
        | CKM_HASH_SLH_DSA_SHAKE256 => (32, 64, 0x00000800 | 0x00002000),
        // ECDSA-SHA3 variants — T1: the sign/verify matrix now dispatches the
        // same named curves as the SHA-2 composites (P-256 / secp256k1 /
        // P-384 / P-521), so the range is unified with CKM_ECDSA_SHAx above.
        CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256 | CKM_ECDSA_SHA3_384 | CKM_ECDSA_SHA3_512 => {
            (256, 521, 0x00000800 | 0x00002000 | EC_CAPABILITY_FLAGS)
        }
        // Key derivation functions
        CKM_PKCS5_PBKD2
        | CKM_HKDF_DERIVE
        | CKM_SP800_108_COUNTER_KDF
        | CKM_SP800_108_FEEDBACK_KDF => (1, 512, 0x00080000),
        // ── R6.2 — arms for every remaining SUPPORTED_MECHS entry ──────────
        // (a unit test iterates SUPPORTED_MECHS and asserts none of them
        //  return CKR_MECHANISM_INVALID here — keep the two in sync)
        // Raw ECDSA (§6.3.12) — pre-hashed input, sign/verify only
        CKM_ECDSA => (256, 521, 0x00000800 | 0x00002000 | EC_CAPABILITY_FLAGS),
        // Ed25519ph / Ed448ph (pkcs11t.h CKM_EDDSA_PH 0x80001057)
        CKM_EDDSA_PH => (255, 448, 0x00000800 | 0x00002000 | EC_CAPABILITY_FLAGS),
        // Parametrized pre-hash mechanisms (hash chosen via param, §6.67.7/§6.69.7)
        CKM_HASH_ML_DSA => (1312, 2592, 0x00000800 | 0x00002000),
        CKM_HASH_SLH_DSA => (32, 64, 0x00000800 | 0x00002000),
        // Stateful hash-based signatures (§6.14/§6.66) — sign on the private
        // key only while it has leaves remaining; verify is stateless
        CKM_HSS_KEY_PAIR_GEN | CKM_XMSS_KEY_PAIR_GEN | CKM_XMSSMT_KEY_PAIR_GEN => {
            (0, 0, 0x00010000)
        }
        CKM_HSS | CKM_XMSS | CKM_XMSSMT => (0, 0, 0x00000800 | 0x00002000),
        // Vendor Keccak-256 digest (Ethereum address derivation)
        CKM_KECCAK_256 => (0, 0, 0x00000400),
        // ChaCha20 stream cipher / ChaCha20-Poly1305 AEAD (§6.20/§6.25) —
        // 256-bit keys only. CKF_ENCRYPT | CKF_DECRYPT; no CKF_MESSAGE_*
        // (the message-based family does not dispatch these mechanisms).
        CKM_CHACHA20 | CKM_CHACHA20_POLY1305 => (32, 32, 0x00000100 | 0x00000200),
        // BIP32 HD derivation (C_DeriveKey) — 32-byte seeds/keys, CKF_DERIVE.
        CKM_BIP32_MASTER_DERIVE | CKM_BIP32_CHILD_DERIVE => (32, 32, 0x00080000),
        // Hybrid-KEM combiner building blocks (§6.43 concat, §6.22/§6.29
        // digest key-derivation) — arbitrary-length secret values, CKF_DERIVE.
        CKM_CONCATENATE_BASE_AND_KEY
        | CKM_CONCATENATE_BASE_AND_DATA
        | CKM_SHA256_KEY_DERIVATION
        | CKM_SHA384_KEY_DERIVATION
        | CKM_SHA512_KEY_DERIVATION
        | CKM_SHA3_256_KEY_DERIVATION
        | CKM_SHA3_384_KEY_DERIVATION
        | CKM_SHA3_512_KEY_DERIVATION => (0, 0, 0x00080000),
        _ => return None,
    };
    Some(info)
}

#[cfg(test)]
mod mechanism_table_tests {
    use super::*;

    /// R6.2 — every mechanism advertised by C_GetMechanismList must be
    /// answerable by C_GetMechanismInfo. This test pins the two tables
    /// together; adding a mechanism to SUPPORTED_MECHS without an info arm
    /// fails CI immediately.
    #[test]
    fn supported_mechs_all_have_info() {
        let missing: Vec<u32> = SUPPORTED_MECHS
            .iter()
            .copied()
            .filter(|m| mechanism_info(*m).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "SUPPORTED_MECHS entries without a C_GetMechanismInfo arm: {missing:#06x?}"
        );
    }

    /// P1 (remediated) — the GENERIC pre-hash sign mechanisms are now
    /// advertised: `remap_generic_hash_mech` parses
    /// `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash` in C_SignInit/C_VerifyInit/
    /// C_VerifySignatureInit and remaps onto the hash-SPECIFIC mechanism
    /// below, so advertise-and-fail no longer applies. The hash-SPECIFIC
    /// variants remain advertised too (reachable directly, unchanged).
    #[test]
    fn p2_generic_hash_sign_mechs_advertised() {
        assert!(
            SUPPORTED_MECHS.contains(&CKM_HASH_ML_DSA),
            "generic CKM_HASH_ML_DSA (0x1F) must be advertised now that its hash param is parsed"
        );
        assert!(
            SUPPORTED_MECHS.contains(&CKM_HASH_SLH_DSA),
            "generic CKM_HASH_SLH_DSA (0x34) must be advertised now that its hash param is parsed"
        );
        for m in [
            CKM_HASH_ML_DSA_SHA256,
            CKM_HASH_ML_DSA_SHA512,
            CKM_HASH_SLH_DSA_SHA256,
            CKM_HASH_SLH_DSA_SHA512,
        ] {
            assert!(SUPPORTED_MECHS.contains(&m), "hash-specific mech {m:#06x} must stay advertised");
        }
    }

    /// P2 — `map_generic_hash_mech` covers exactly the 8 real digest
    /// mechanisms (no SHAKE — SHAKE128/256 have no standalone digest CKM_
    /// identifier in the v3.2 header, so they're reachable only through
    /// their own dedicated CKM_HASH_{ML,SLH}_DSA_SHAKE128/256 mechanism).
    #[test]
    fn p2_map_generic_hash_mech_matrix() {
        let cases: &[(u32, u32)] = &[
            (CKM_SHA224, CKM_HASH_ML_DSA_SHA224),
            (CKM_SHA256, CKM_HASH_ML_DSA_SHA256),
            (CKM_SHA384, CKM_HASH_ML_DSA_SHA384),
            (CKM_SHA512, CKM_HASH_ML_DSA_SHA512),
            (CKM_SHA3_224, CKM_HASH_ML_DSA_SHA3_224),
            (CKM_SHA3_256, CKM_HASH_ML_DSA_SHA3_256),
            (CKM_SHA3_384, CKM_HASH_ML_DSA_SHA3_384),
            (CKM_SHA3_512, CKM_HASH_ML_DSA_SHA3_512),
        ];
        for &(hash, expected) in cases {
            assert_eq!(
                crate::crypto::handlers::map_generic_hash_mech(CKM_HASH_ML_DSA, hash),
                Some(expected)
            );
        }
        assert_eq!(
            crate::crypto::handlers::map_generic_hash_mech(CKM_HASH_SLH_DSA, CKM_SHA256),
            Some(CKM_HASH_SLH_DSA_SHA256)
        );
        assert_eq!(
            crate::crypto::handlers::map_generic_hash_mech(CKM_HASH_ML_DSA, CKM_HASH_ML_DSA_SHAKE128),
            None,
            "SHAKE has no digest CKM_ identifier — not selectable via the generic hash param"
        );
        assert_eq!(
            crate::crypto::handlers::map_generic_hash_mech(CKM_HASH_ML_DSA, 0xdead_beef),
            None
        );
    }

    /// S6 — the four RSA hash-variant mechanisms are advertised at
    /// (2048, 4096) with CKF_SIGN | CKF_VERIFY.
    #[test]
    fn s6_rsa_hash_variant_mechs_advertised() {
        for m in [
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_SHA384_RSA_PKCS_PSS,
            CKM_SHA512_RSA_PKCS_PSS,
        ] {
            assert!(SUPPORTED_MECHS.contains(&m), "mech {m:#06x} not advertised");
            assert_eq!(
                mechanism_info(m),
                Some((2048, 4096, 0x00000800 | 0x00002000)),
                "mech {m:#06x}"
            );
        }
    }

    /// S1 / P-1 — PKCS#11 v3.2 §6.67–§6.69: ulMin/MaxKeySize for the PQC
    /// mechanisms are public-key sizes in BYTES per FIPS 203/204/205, not
    /// parameter-set numbers. Pin the exact values.
    #[test]
    fn pqc_mechanism_key_sizes_are_fips_public_key_bytes() {
        // FIPS 204 Table 2: pk = 1312 (ML-DSA-44) … 2592 (ML-DSA-87)
        assert_eq!(mechanism_info(CKM_ML_DSA).map(|(a, b, _)| (a, b)), Some((1312, 2592)));
        assert_eq!(
            mechanism_info(CKM_ML_DSA_KEY_PAIR_GEN).map(|(a, b, _)| (a, b)),
            Some((1312, 2592))
        );
        // FIPS 203 Table 3: ek = 800 (ML-KEM-512) … 1568 (ML-KEM-1024)
        assert_eq!(mechanism_info(CKM_ML_KEM).map(|(a, b, _)| (a, b)), Some((800, 1568)));
        assert_eq!(
            mechanism_info(CKM_ML_KEM_KEY_PAIR_GEN).map(|(a, b, _)| (a, b)),
            Some((800, 1568))
        );
        // FIPS 205 Table 2: pk = 32 (128-bit sets) … 64 (256-bit sets)
        assert_eq!(mechanism_info(CKM_SLH_DSA).map(|(a, b, _)| (a, b)), Some((32, 64)));
        assert_eq!(
            mechanism_info(CKM_SLH_DSA_KEY_PAIR_GEN).map(|(a, b, _)| (a, b)),
            Some((32, 64))
        );
    }

    /// S1 — ChaCha20 / ChaCha20-Poly1305 are implemented and must be both
    /// advertised in C_GetMechanismList and answerable by C_GetMechanismInfo.
    #[test]
    fn chacha20_mechs_advertised_with_info() {
        for mech in [CKM_CHACHA20, CKM_CHACHA20_POLY1305] {
            assert!(
                SUPPORTED_MECHS.contains(&mech),
                "mech {mech:#06x} missing from SUPPORTED_MECHS"
            );
            // 256-bit key only, CKF_ENCRYPT | CKF_DECRYPT, no CKF_MESSAGE_*
            assert_eq!(mechanism_info(mech), Some((32, 32, 0x00000100 | 0x00000200)));
        }
    }

    /// S1 — BIP32 derive mechanisms are dispatched by C_DeriveKey and must be
    /// advertised with CKF_DERIVE.
    #[test]
    fn bip32_mechs_advertised_with_info() {
        for mech in [CKM_BIP32_MASTER_DERIVE, CKM_BIP32_CHILD_DERIVE] {
            assert!(
                SUPPORTED_MECHS.contains(&mech),
                "mech {mech:#06x} missing from SUPPORTED_MECHS"
            );
            assert_eq!(mechanism_info(mech), Some((32, 32, 0x00080000)));
        }
    }

    /// F1 — canonical OASIS v3.2 re-sync: CKA_UNIQUE_ID is 0x4 (the local
    /// header had drifted to 0x17), and the BIP32 inventions live in the
    /// vendor-defined space; the legacy bare codepoints are dispatch-only
    /// deprecated aliases and must NOT be advertised.
    #[test]
    fn f1_canonical_constant_values() {
        assert_eq!(CKA_UNIQUE_ID, 0x0000_0004);
        assert_eq!(CKM_BIP32_MASTER_DERIVE, 0x8000_105B);
        assert_eq!(CKM_BIP32_CHILD_DERIVE, 0x8000_105C);
        assert_eq!(CKA_BIP32_CHAIN_CODE, 0x8000_1021);
        assert_eq!(CKA_BIP32_CHILD_INDEX, 0x8000_1022);
        for legacy in [CKM_BIP32_MASTER_DERIVE_LEGACY, CKM_BIP32_CHILD_DERIVE_LEGACY] {
            assert!(
                !SUPPORTED_MECHS.contains(&legacy),
                "legacy BIP32 codepoint {legacy:#06x} must not be advertised"
            );
            assert_eq!(mechanism_info(legacy), None);
        }
    }

    /// S1 / P-15 / T1 — ECDSA + ECDH mechanism ranges unified to P-521
    /// (the engine generates, signs, and derives over P-256 / secp256k1 /
    /// P-384 / P-521 for every one of these mechanisms).
    #[test]
    fn ecdsa_mech_ranges_cover_p521() {
        for mech in [
            CKM_EC_KEY_PAIR_GEN,
            CKM_ECDSA,
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
            CKM_ECDSA_SHA3_224,
            CKM_ECDSA_SHA3_256,
            CKM_ECDSA_SHA3_384,
            CKM_ECDSA_SHA3_512,
            CKM_ECDH1_DERIVE,
            CKM_ECDH1_COFACTOR_DERIVE,
        ] {
            let (min, max, _) = mechanism_info(mech).expect("EC mech must have info");
            assert_eq!((min, max), (256, 521), "mech {mech:#06x}");
        }
    }

    /// T1 — advertise/dispatch consistency for the ECDSA matrix, derived
    /// from a single curve-support table: for every hash-composite ECDSA
    /// mechanism and every named curve whose bit size falls inside the
    /// mechanism's advertised (ulMinKeySize, ulMaxKeySize) range, a
    /// sign + verify round-trip through the shared handler matrix must
    /// succeed. If a future change narrows dispatch without narrowing the
    /// advertisement (or vice versa), this test fails immediately.
    #[test]
    fn t1_ecdsa_mech_curve_matrix_round_trips() {
        use crate::crypto::handlers::{
            sign_ecdsa, verify_ecdsa, CURVE_K256, CURVE_P256, CURVE_P384, CURVE_P521,
        };

        // Single source of truth: every named curve the engine supports,
        // with its key size in bits (what mechanism_info ranges are
        // expressed in). secp256k1 is a 256-bit curve.
        let curve_table: &[(u32, u32, &str)] = &[
            (CURVE_P256, 256, "P-256"),
            (CURVE_K256, 256, "secp256k1"),
            (CURVE_P384, 384, "P-384"),
            (CURVE_P521, 521, "P-521"),
        ];
        let mechs = [
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
            CKM_ECDSA_SHA3_224,
            CKM_ECDSA_SHA3_256,
            CKM_ECDSA_SHA3_384,
            CKM_ECDSA_SHA3_512,
        ];

        fn gen_keypair(curve: u32) -> (Vec<u8>, Vec<u8>) {
            let mut rng = rand::rngs::OsRng;
            match curve {
                CURVE_P256 => {
                    let sk = p256::ecdsa::SigningKey::random(&mut rng);
                    let pk = p256::ecdsa::VerifyingKey::from(&sk);
                    (
                        sk.to_bytes().to_vec(),
                        pk.to_encoded_point(false).as_bytes().to_vec(),
                    )
                }
                CURVE_P384 => {
                    let sk = p384::ecdsa::SigningKey::random(&mut rng);
                    let pk = p384::ecdsa::VerifyingKey::from(&sk);
                    (
                        sk.to_bytes().to_vec(),
                        pk.to_encoded_point(false).as_bytes().to_vec(),
                    )
                }
                CURVE_P521 => {
                    let sk = p521::ecdsa::SigningKey::random(&mut rng);
                    let pk = p521::ecdsa::VerifyingKey::from(&sk);
                    (
                        sk.to_bytes().to_vec(),
                        pk.to_encoded_point(false).as_bytes().to_vec(),
                    )
                }
                _ => {
                    let sk = k256::ecdsa::SigningKey::random(&mut rng);
                    let pk = k256::ecdsa::VerifyingKey::from(&sk);
                    (
                        sk.to_bytes().to_vec(),
                        pk.to_encoded_point(false).as_bytes().to_vec(),
                    )
                }
            }
        }

        let msg = b"T1 ECDSA advertise/dispatch consistency probe";
        for &mech in &mechs {
            let (min, max, _) = mechanism_info(mech).expect("ECDSA mech must have info");
            for &(curve, bits, name) in curve_table {
                if bits < min || bits > max {
                    continue; // outside the advertised range — may reject
                }
                let (sk, pk) = gen_keypair(curve);
                let sig = sign_ecdsa(mech, curve, &sk, msg).unwrap_or_else(|rv| {
                    panic!("sign mech={mech:#06x} {name}: CKR {rv:#x} (advertised but not dispatched)")
                });
                verify_ecdsa(mech, curve, &pk, msg, &sig).unwrap_or_else(|rv| {
                    panic!("verify mech={mech:#06x} {name}: CKR {rv:#x} (advertised but not dispatched)")
                });
                // Tampered message must NOT verify (guards against a
                // degenerate always-Ok arm).
                assert!(
                    verify_ecdsa(mech, curve, &pk, b"tampered", &sig).is_err(),
                    "tampered verify mech={mech:#06x} {name} unexpectedly passed"
                );
            }
        }
    }
}

// ── Key Generation ───────────────────────────────────────────────────────────

/// W3 (2026-08-13) — resolve an XMSS / XMSS^MT key's parameter set.
///
/// §6.66.6: the key pair is generated "using an oid, as specified in the
/// CKA_PARAMETER_SET attribute of the template for the public key", and the
/// mechanism itself "does not have a parameter". Generation already reads and
/// stores the STANDARD attribute; sign and verify read only the legacy vendor
/// attribute and defaulted to one parameter set when it was absent — so a key
/// imported through C_CreateObject carrying only CKA_PARAMETER_SET signed
/// under the WRONG parameter set, silently.
///
/// Order: standard attribute, then the legacy vendor attribute (keys this
/// engine generated carry both), then `None` — no silent default.
fn xmss_param_set_of(h_key: u32, multi_tree: bool) -> Option<u32> {
    let vendor = if multi_tree { CKA_XMSSMT_PARAM_SET } else { CKA_XMSS_PARAM_SET };
    get_object_attr_u32(h_key, CKA_PARAMETER_SET)
        .filter(|v| *v != 0)
        .or_else(|| get_object_attr_u32(h_key, vendor).filter(|v| *v != 0))
}

/// Resolve the parameter set for `CKM_XMSS_KEY_PAIR_GEN` /
/// `CKM_XMSSMT_KEY_PAIR_GEN` from the **public key template**, and from
/// nothing else.
///
/// PKCS#11 v3.2 §6.66.6, verbatim: *"This mechanism does not have a
/// parameter."* — followed immediately by where the parameter set does come
/// from: *"The mechanism generates XMSS public/private key pairs using an oid,
/// as specified in the CKA_PARAMETER_SET attribute of the template for the
/// public key."* §6.66.7 inherits both sentences for XMSSMT: *"All other
/// restrictions detailed in section 6.66.6 apply, using XMSSMT types where
/// necessary."*
///
/// **This function takes no mechanism pointer, deliberately.** That is the
/// pin. Until 2026-08-14 the two generation arms each read a one-word
/// mechanism parameter as a fallback, and read it at *different widths* — a
/// `u32` in the XMSS arm, a native `usize` in the XMSSMT arm — so the same
/// caller buffer meant two different things depending on which mechanism it
/// was handed to. Neither width could be adjudicated, because there is no
/// `CK_XMSS_KEY_PAIR_GEN_PARAMS` in `src/lib/pkcs11/pkcs11t.h` and none in the
/// canonical OASIS header either. The specification resolves it by saying the
/// parameter does not exist; the C++ engine already ignores `pParameter` here
/// (plan item W4). Making the parameter unreachable from one shared resolver
/// is what makes the two arms agree by construction rather than by review.
///
/// Order: the standard `CKA_PARAMETER_SET`, then the legacy vendor attribute
/// (`vendor_attr`) for templates written by older callers, then `default_ps`.
///
/// # Safety
/// `p_public_key_template` must be NULL or point to `count` readable
/// `CK_ATTRIBUTE`s.
unsafe fn xmss_keygen_param_set(
    p_public_key_template: *mut u8,
    count: u32,
    vendor_attr: u32,
    default_ps: u32,
) -> u32 {
    let ps = get_attr_ulong(p_public_key_template, count, CKA_PARAMETER_SET)
        .filter(|v| *v != 0)
        .or_else(|| {
            get_attr_ulong(p_public_key_template, count, vendor_attr).filter(|v| *v != 0)
        });
    ps.unwrap_or(default_ps)
}

fn C_GenerateKeyPair_impl(
    _h_session: u32,
    p_mechanism: *mut u8,
    p_public_key_template: *mut u8,
    ul_public_key_attribute_count: u32,
    p_private_key_template: *mut u8,
    ul_private_key_attribute_count: u32,
    ph_public_key: *mut u32,
    ph_private_key: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    if ph_public_key.is_null() || ph_private_key.is_null() || p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        // S7 — either half asking for a token object needs a R/W session.
        if let Err(rv) = gate_ro_session_for_template(
            _h_session,
            p_public_key_template,
            ul_public_key_attribute_count,
        ) {
            return rv;
        }
        if let Err(rv) = gate_ro_session_for_template(
            _h_session,
            p_private_key_template,
            ul_private_key_attribute_count,
        ) {
            return rv;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        // V4 — a CKA_KEY_TYPE in either template that contradicts the key-pair
        // mechanism is CKR_TEMPLATE_INCONSISTENT, not silently overwritten.
        let expected_kt = match mech_type {
            CKM_ML_KEM_KEY_PAIR_GEN => Some(CKK_ML_KEM),
            CKM_ML_DSA_KEY_PAIR_GEN => Some(CKK_ML_DSA),
            CKM_SLH_DSA_KEY_PAIR_GEN => Some(CKK_SLH_DSA),
            CKM_RSA_PKCS_KEY_PAIR_GEN => Some(CKK_RSA),
            CKM_EC_KEY_PAIR_GEN => Some(CKK_EC),
            // HSS, XMSS, and XMSS-MT keygen are all implemented below
            // (real LMS/LM-OTS / XMSS tree generation), and this FFI
            // layer's own C_Sign/C_Verify sign/verify both mechanisms
            // for real too. Only the newer typed `native::sign` module
            // hasn't been extended past HSS to XMSS/XMSS-MT yet (see
            // that module's doc comment) — this FFI path is unaffected.
            // The keytype-vs-mech consistency rule (V4) still applies
            // up-front for all three here: a contradictory CKA_KEY_TYPE
            // is CKR_TEMPLATE_INCONSISTENT before any keygen work runs.
            CKM_HSS_KEY_PAIR_GEN => Some(CKK_HSS),
            CKM_XMSS_KEY_PAIR_GEN => Some(CKK_XMSS),
            CKM_XMSSMT_KEY_PAIR_GEN => Some(CKK_XMSSMT),
            CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN => Some(CKK_PQCTODAY_FRODOKEM),
            CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN => Some(CKK_PQCTODAY_CLASSIC_MCELIECE),
            _ => None,
        };
        if let Some(exp) = expected_kt {
            for (t, n) in [
                (p_public_key_template, ul_public_key_attribute_count),
                (p_private_key_template, ul_private_key_attribute_count),
            ] {
                if let Some(kt) = get_attr_ulong(t, n, CKA_KEY_TYPE) {
                    if kt != exp {
                        return CKR_TEMPLATE_INCONSISTENT;
                    }
                }
            }
        }
        match mech_type {
            CKM_ML_KEM_KEY_PAIR_GEN => {
                use ml_kem::{EncodedSizeUser, KemCore};

                // PKCS#11 v3.2 §6.68.2 — CKA_PARAMETER_SET is a REQUIRED template
                // attribute for ML-KEM key-pair generation.
                let ps = match get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_PARAMETER_SET,
                ) {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_ML_KEM);
                store_algo_family(&mut prv_attrs, ALGO_ML_KEM);
                // PKCS#11 v3.2 defaults — ML-KEM public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_ML_KEM);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_ML_KEM_KEY_PAIR_GEN,
                );
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, false);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                // PKCS#11 v3.2 defaults — ML-KEM private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_ML_KEM);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_ML_KEM_KEY_PAIR_GEN,
                );
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, false);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);

                // T7 — PKCS#11 v3.2 §6.68.2: CKA_SEED (d ‖ z, 64 bytes) in the
                // keygen template selects deterministic generation per FIPS 203
                // Algorithm 16 `ML-KEM.KeyGen_internal(d, z)`. The seed is read
                // explicitly because `absorb_template_attrs` deliberately skips
                // CKA_SEED (sensitive-material class). CKA_SEED is an attribute
                // of the private key; the public template is honored as a
                // fallback rather than silently ignoring an explicit seed.
                let mut seed = get_attr_bytes(
                    p_private_key_template,
                    ul_private_key_attribute_count,
                    CKA_SEED,
                )
                .or_else(|| {
                    get_attr_bytes(p_public_key_template, ul_public_key_attribute_count, CKA_SEED)
                });
                if let Some(ref s) = seed {
                    if s.len() != 64 {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                }
                // P5 (PKCS#11 v3.2 §6.68.4 / FIPS 203): keygen CONTRIBUTES CKA_SEED
                // (d ‖ z) to the private key. On the random path, sample the
                // 64-byte seed explicitly and expand it deterministically —
                // functionally identical to generate() but the seed is retained.
                if seed.is_none() {
                    use rand::RngCore;
                    let mut dz = [0u8; 64];
                    rand::rngs::OsRng.fill_bytes(&mut dz);
                    seed = Some(dz.to_vec());
                }
                macro_rules! mlkem_gen {
                    ($t:ty) => {{
                        let s = seed.as_deref().expect("seed set above");
                        let d = ml_kem::B32::try_from(&s[..32]).expect("length checked");
                        let z = ml_kem::B32::try_from(&s[32..64]).expect("length checked");
                        let (dk, ek) = <$t>::generate_deterministic(&d, &z);
                        pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                        prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                    }};
                }
                match ps {
                    CKP_ML_KEM_512 => mlkem_gen!(ml_kem::MlKem512),
                    CKP_ML_KEM_768 => mlkem_gen!(ml_kem::MlKem768),
                    CKP_ML_KEM_1024 => mlkem_gen!(ml_kem::MlKem1024),
                    // Table 6 — unrecognized CKA_PARAMETER_SET value in the template.
                    _ => return CKR_PARAMETER_SET_NOT_SUPPORTED,
                }
                // Store the seed on the private object — engine-side, in the
                // sensitive-blocked readback set (state::attr_is_sensitive_material).
                if let Some(s) = seed {
                    prv_attrs.insert(CKA_SEED, s);
                }
                // CKA_PUBLIC_KEY_INFO (SPKI) — PKCS#11 v3.2 §4.14
                if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
                    let spki = match ps {
                        CKP_ML_KEM_512 => build_mlkem512_spki(&pk_bytes),
                        CKP_ML_KEM_768 => build_mlkem768_spki(&pk_bytes),
                        CKP_ML_KEM_1024 => build_mlkem1024_spki(&pk_bytes),
                        _ => Vec::new(),
                    };
                    if !spki.is_empty() {
                        // §4.14 — CKA_PUBLIC_KEY_INFO is exposed on BOTH halves:
                        // a private key carries its own public-key info (SPKI).
                        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki.clone());
                        prv_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                    }
                }
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            CKM_ML_DSA_KEY_PAIR_GEN => {
                // PKCS#11 v3.2 §6.67.2 — CKA_PARAMETER_SET is a REQUIRED template
                // attribute for ML-DSA key-pair generation.
                let ps = match get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_PARAMETER_SET,
                ) {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_ML_DSA);
                store_algo_family(&mut prv_attrs, ALGO_ML_DSA);
                // PKCS#11 v3.2 defaults — ML-DSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_ML_DSA);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_ML_DSA_KEY_PAIR_GEN,
                );
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                // PKCS#11 v3.2 defaults — ML-DSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_ML_DSA);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_ML_DSA_KEY_PAIR_GEN,
                );
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);

                // T7 — PKCS#11 v3.2 §6.67.2: CKA_SEED (ξ, 32 bytes) in the keygen
                // template selects deterministic generation per FIPS 204
                // Algorithm 6 `ML-DSA.KeyGen_internal(ξ)` (patched fips204
                // `KeyGen::keygen_from_seed`). Read explicitly —
                // `absorb_template_attrs` skips CKA_SEED (sensitive-material
                // class). Private-key attribute; public template is a fallback.
                let mut seed = get_attr_bytes(
                    p_private_key_template,
                    ul_private_key_attribute_count,
                    CKA_SEED,
                )
                .or_else(|| {
                    get_attr_bytes(p_public_key_template, ul_public_key_attribute_count, CKA_SEED)
                });
                if let Some(ref s) = seed {
                    if s.len() != 32 {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                }
                // P5 (PKCS#11 v3.2 §6.67.4 / FIPS 204): key generation CONTRIBUTES
                // CKA_SEED to the new private key. On the random path (no caller
                // seed) generate the 32-byte ξ explicitly and expand it via
                // keygen_from_seed — functionally identical to try_keygen_with_rng
                // (FIPS 204 KeyGen samples ξ then expands) but the seed is now
                // retained so the private key carries CKA_SEED (stored below,
                // sensitive/non-extractable) and can be backed up / re-derived.
                if seed.is_none() {
                    use rand::RngCore;
                    let mut xi = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut xi);
                    seed = Some(xi.to_vec());
                }
                macro_rules! mldsa_gen {
                    ($m:ident) => {{
                        use fips204::traits::{KeyGen, SerDes};
                        let s = seed.as_deref().expect("seed set above");
                        let xi: &[u8; 32] = s.try_into().expect("length checked");
                        let (vk, sk) = fips204::$m::KG::keygen_from_seed(xi);
                        pub_attrs.insert(CKA_VALUE, SerDes::into_bytes(vk).to_vec());
                        prv_attrs.insert(CKA_VALUE, SerDes::into_bytes(sk).to_vec());
                    }};
                }
                match ps {
                    CKP_ML_DSA_44 => mldsa_gen!(ml_dsa_44),
                    CKP_ML_DSA_65 => mldsa_gen!(ml_dsa_65),
                    CKP_ML_DSA_87 => mldsa_gen!(ml_dsa_87),
                    // Table 6 — unrecognized CKA_PARAMETER_SET value in the template.
                    _ => return CKR_PARAMETER_SET_NOT_SUPPORTED,
                }
                // Store the seed on the private object — engine-side, in the
                // sensitive-blocked readback set (state::attr_is_sensitive_material).
                if let Some(s) = seed {
                    prv_attrs.insert(CKA_SEED, s);
                }
                // CKA_PUBLIC_KEY_INFO (SPKI) — PKCS#11 v3.2 §4.14
                if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
                    let spki = match ps {
                        CKP_ML_DSA_44 => build_mldsa44_spki(&pk_bytes),
                        CKP_ML_DSA_65 => build_mldsa65_spki(&pk_bytes),
                        CKP_ML_DSA_87 => build_mldsa87_spki(&pk_bytes),
                        _ => Vec::new(),
                    };
                    if !spki.is_empty() {
                        // §4.14 — CKA_PUBLIC_KEY_INFO is exposed on BOTH halves:
                        // a private key carries its own public-key info (SPKI).
                        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki.clone());
                        prv_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                    }
                }
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            CKM_SLH_DSA_KEY_PAIR_GEN => {
                // PKCS#11 v3.2 §6.69.2 — CKA_PARAMETER_SET is a REQUIRED template
                // attribute for SLH-DSA key-pair generation.
                let ps = match get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_PARAMETER_SET,
                ) {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_SLH_DSA);
                store_algo_family(&mut prv_attrs, ALGO_SLH_DSA);
                // PKCS#11 v3.2 defaults — SLH-DSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_SLH_DSA);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_SLH_DSA_KEY_PAIR_GEN,
                );
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                // PKCS#11 v3.2 defaults — SLH-DSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_SLH_DSA);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_SLH_DSA_KEY_PAIR_GEN,
                );
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);

                // T7 — PKCS#11 v3.2 §6.69.2: CKA_SEED (SK.seed ‖ SK.prf ‖
                // PK.seed, 3n bytes) in the keygen template selects
                // deterministic generation per FIPS 205 Algorithm 18
                // `slh_keygen_internal` (fips205 `KeyGen::keygen_with_seeds`).
                // Read explicitly — `absorb_template_attrs` skips CKA_SEED
                // (sensitive-material class). Private-key attribute; public
                // template is a fallback. Per-param-set length validation
                // (3n = 48/72/96) lives in the `slh_dsa_keygen!` macro.
                let seed = get_attr_bytes(
                    p_private_key_template,
                    ul_private_key_attribute_count,
                    CKA_SEED,
                )
                .or_else(|| {
                    get_attr_bytes(p_public_key_template, ul_public_key_attribute_count, CKA_SEED)
                });
                match ps {
                    CKP_SLH_DSA_SHA2_128S => {
                        slh_dsa_keygen!(slh_dsa_sha2_128s, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_128S => {
                        slh_dsa_keygen!(slh_dsa_shake_128s, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_128F => {
                        slh_dsa_keygen!(slh_dsa_sha2_128f, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_128F => {
                        slh_dsa_keygen!(slh_dsa_shake_128f, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_192S => {
                        slh_dsa_keygen!(slh_dsa_sha2_192s, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_192S => {
                        slh_dsa_keygen!(slh_dsa_shake_192s, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_192F => {
                        slh_dsa_keygen!(slh_dsa_sha2_192f, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_192F => {
                        slh_dsa_keygen!(slh_dsa_shake_192f, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_256S => {
                        slh_dsa_keygen!(slh_dsa_sha2_256s, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_256S => {
                        slh_dsa_keygen!(slh_dsa_shake_256s, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHA2_256F => {
                        slh_dsa_keygen!(slh_dsa_sha2_256f, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    CKP_SLH_DSA_SHAKE_256F => {
                        slh_dsa_keygen!(slh_dsa_shake_256f, seed.as_deref(), pub_attrs, prv_attrs)
                    }
                    // Table 6 — unrecognized CKA_PARAMETER_SET value in the template.
                    _ => return CKR_PARAMETER_SET_NOT_SUPPORTED,
                }
                // E7 (2026-08-13) — §6.69.4 lists the attributes CKM_SLH_DSA_
                // KEY_PAIR_GEN contributes to the new private key, and
                // CKA_SEED is NOT among them; the SLH-DSA private-key table
                // defines no such attribute at all. (§6.67.4 and §6.68.4 DO
                // list it for ML-DSA and ML-KEM, which is why those two arms
                // still persist it above.) A caller-supplied seed is still
                // honoured for deterministic generation — it is CONSUMED,
                // producing the same key FIPS 205 Algorithm 18 would, and then
                // dropped rather than stored under an attribute the spec does
                // not define for this key type.
                let _ = &seed;
                // CKA_PUBLIC_KEY_INFO (SPKI) — PKCS#11 v3.2 §4.14
                if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
                    let spki = build_slhdsa_spki(ps, &pk_bytes);
                    if !spki.is_empty() {
                        // §4.14 — CKA_PUBLIC_KEY_INFO is exposed on BOTH halves:
                        // a private key carries its own public-key info (SPKI).
                        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki.clone());
                        prv_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                    }
                }
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            CKM_RSA_PKCS_KEY_PAIR_GEN => {
                let bits = get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_MODULUS_BITS,
                )
                .unwrap_or(2048) as usize;
                // WS-11 Phase 1 (2026-08-28): widened 1024-4096 to 512-16384
                // to genuinely back the range mechanism_info now advertises
                // for CKM_RSA_PKCS_KEY_PAIR_GEN (Extended Provider,
                // EXT-M-1-32 — the OASIS example's bounds, matching the C++
                // engine's non-FIPS OSSLRSA::getMinKeySize()==512 floor).
                // 2048+ remains the recommended/default size; the
                // conformance suite mints a throwaway 1024-bit key to
                // exercise negative key-usage policy paths
                // (CKA_SIGN=false, CKA_EXTRACTABLE=false). Every size below
                // 2048 is cryptographically weak and never the default —
                // advertising the range is not recommending a point in it;
                // callers should use >= 2048. 16384-bit generation is slow
                // (seconds, not the sub-100ms this engine's other sizes
                // manage) — exercised only by a native, #[ignore]-marked
                // test, never by the browser's own default-key paths.
                if !(512..=16384).contains(&bits) {
                    return CKR_ARGUMENTS_BAD;
                }
                let private_key =
                    match with_rng!(rng, { rsa::RsaPrivateKey::new(&mut rng, bits).ok() }) {
                        Some(k) => k,
                        None => return CKR_FUNCTION_FAILED,
                    };
                let public_key = rsa::RsaPublicKey::from(&private_key);

                use rsa::pkcs8::EncodePrivateKey;
                let sk_der = match private_key.to_pkcs8_der() {
                    Ok(d) => d,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };

                use rsa::traits::PublicKeyParts;
                let n_bytes = public_key.n().to_bytes_be();
                let e_bytes = public_key.e().to_bytes_be();

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_RSA);
                store_algo_family(&mut prv_attrs, ALGO_RSA);
                // PKCS#11 v3.2 defaults — RSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_RSA);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, true);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, true);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_RSA_PKCS_KEY_PAIR_GEN,
                );
                // PKCS#11 v3.2 defaults — RSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_RSA);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, true);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, true);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_RSA_PKCS_KEY_PAIR_GEN,
                );
                // PKCS#11 v3.2 §2.1.2 — RSA public key MUST expose CKA_MODULUS and
                // CKA_PUBLIC_EXPONENT as distinct attributes (not packed into CKA_VALUE).
                pub_attrs.insert(CKA_MODULUS, n_bytes.clone());
                pub_attrs.insert(CKA_PUBLIC_EXPONENT, e_bytes.clone());
                // …and so MUST the PRIVATE key. v3.2's RSA private-key object table
                // lists CKA_MODULUS and CKA_PUBLIC_EXPONENT alongside the private
                // factors; they are public values, so exposing them leaks nothing.
                //
                // Omitting them broke a real consumer. pkcs11-provider's
                // fetch_rsa_key() requests CKA_MODULUS and CKA_PUBLIC_EXPONENT with
                // required=true and CKA_ID/CKA_LABEL with required=false
                // (src/vendor/pkcs11-provider/src/objects.c). Run against a private
                // key that had neither, the required fetch failed and the optional
                // CKA_ID was never populated on the provider's cached object — which
                // surfaced far away, and misleadingly, as:
                //
                //   p11prov_obj_find_associated: No CKA_ID in source object
                //                                (objects.c:1646)
                //
                // reached from p11prov_obj_export_public_rsa_key (objects.c:2229).
                // The engine DOES store CKA_ID correctly; the provider simply never
                // got as far as reading it.
                //
                // Only RSA is affected: an EC or ML-DSA public key is derivable from
                // its private key, so the provider never needs to resolve a sibling
                // object. That is why the LAMPS composite
                // id-MLDSA44-RSA2048-PSS-SHA256 failed while
                // id-MLDSA65-ECDSA-P256-SHA512 passed — the ML-DSA half was never
                // the problem (pqctoday-hub e2e/cms-workshop-crypto.spec.ts:392).
                prv_attrs.insert(CKA_MODULUS, n_bytes.clone());
                prv_attrs.insert(CKA_PUBLIC_EXPONENT, e_bytes.clone());
                // E5 (2026-08-13) — §6.1.3: "The only attributes from Table 38
                // for which a Cryptoki implementation is required to be able
                // to return values are CKA_MODULUS, CKA_PUBLIC_EXPONENT and
                // CKA_PRIVATE_EXPONENT." The private exponent was NEVER
                // written, so a required-to-be-returnable attribute simply did
                // not exist. The RSA tables define no CKA_VALUE at all, and
                // §6.7 forbids preparing a key for wrapping without the CRT
                // set — which is why E6's PKCS#8 wrapping depends on this.
                // The full CRT set is written, not just the minimum.
                {
                    use rsa::traits::PrivateKeyParts;
                    use rsa::traits::PublicKeyParts as _;
                    let _ = private_key.size();
                    let be = |v: &rsa::BigUint| v.to_bytes_be();
                    prv_attrs.insert(CKA_PRIVATE_EXPONENT, be(private_key.d()));
                    let primes = private_key.primes();
                    if primes.len() == 2 {
                        prv_attrs.insert(CKA_PRIME_1, be(&primes[0]));
                        prv_attrs.insert(CKA_PRIME_2, be(&primes[1]));
                    }
                    if let Some(dp) = private_key.dp() {
                        prv_attrs.insert(CKA_EXPONENT_1, be(dp));
                    }
                    if let Some(dq) = private_key.dq() {
                        prv_attrs.insert(CKA_EXPONENT_2, be(dq));
                    }
                    if let Some(qinv) = private_key.qinv() {
                        // qinv is a signed BigInt in the `rsa` crate; it is
                        // mathematically positive for a valid key.
                        prv_attrs.insert(
                            CKA_COEFFICIENT,
                            qinv.to_biguint().map(|v| v.to_bytes_be()).unwrap_or_default(),
                        );
                    }
                }
                store_ulong(&mut pub_attrs, CKA_MODULUS_BITS, bits as u32);
                // SubjectPublicKeyInfo DER (CKA_PUBLIC_KEY_INFO)
                {
                    use rsa::pkcs8::EncodePublicKey;
                    if let Ok(spki_der) = public_key.to_public_key_der() {
                        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki_der.as_bytes().to_vec());
                    }
                }
                // Internal CKA_VALUE in packed `[n_len:4LE][n_bytes][e_bytes]`
                // format. This is the Rust engine's per-object cipher-input
                // convention used by C_Encrypt/C_WrapKey (CKM_RSA_PKCS_OAEP) and
                // C_Decrypt/C_UnwrapKey. Storing it here means
                // get_object_value(pub_handle) returns a parsable buffer; without
                // this, C_WrapKey returns CKR_ARGUMENTS_BAD (0x07) because no
                // CKA_VALUE exists on the public-key object. The C++ engine
                // doesn't need this because OpenSSL EVP keys carry both halves
                // natively; the Rust engine reconstructs from raw modulus/exp.
                let mut packed = Vec::with_capacity(4 + n_bytes.len() + e_bytes.len());
                packed.extend_from_slice(&(n_bytes.len() as u32).to_le_bytes());
                packed.extend_from_slice(&n_bytes);
                packed.extend_from_slice(&e_bytes);
                pub_attrs.insert(CKA_VALUE, packed);
                prv_attrs.insert(CKA_VALUE, sk_der.as_bytes().to_vec());
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            CKM_EC_KEY_PAIR_GEN => {
                // W1 (2026-08-13) — decode CKA_EC_PARAMS properly and NEVER
                // default a curve. The attribute is mandatory at generation
                // (§6.3.9), so absence is CKR_TEMPLATE_INCOMPLETE; a
                // recognised-but-unimplemented curve is
                // CKR_CURVE_NOT_SUPPORTED; an undecodable representation is
                // CKR_DOMAIN_PARAMS_INVALID. Accepts the private-key
                // template as a fallback source, matching the Montgomery arm.
                let ec_params = get_attr_bytes(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_EC_PARAMS,
                )
                .or_else(|| {
                    get_attr_bytes(
                        p_private_key_template,
                        ul_private_key_attribute_count,
                        CKA_EC_PARAMS,
                    )
                });
                let ec_params = match ec_params {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                let curve = match crate::crypto::handlers::decode_ec_params(&ec_params) {
                    Ok(c) => c,
                    Err(rv) => return rv,
                };
                let (is_p521, is_p384, is_secp256k1) = match curve {
                    CURVE_P521 => (true, false, false),
                    CURVE_P384 => (false, true, false),
                    CURVE_K256 => (false, false, true),
                    CURVE_P256 => (false, false, false),
                    // Edwards / Montgomery curves have their own mechanisms
                    // (§6.3.10); asking for one here names a curve this
                    // mechanism cannot generate.
                    _ => return CKR_CURVE_NOT_SUPPORTED,
                };

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_ECDSA);
                store_algo_family(&mut prv_attrs, ALGO_ECDSA);
                // PKCS#11 v3.2 defaults — ECDSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN);
                // PKCS#11 v3.2 defaults — ECDSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, true); // supports ECDH
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN);

                // E2 (2026-08-13) — §6.3.9: "the mechanism contributes the
                // CKA_CLASS, CKA_KEY_TYPE, CKA_EC_PARAMS and CKA_VALUE
                // attributes to the new private key", and the attribute is
                // mandatory on the public key. This engine wrote it to
                // NEITHER half — the curve lived only in an engine-internal
                // attribute that is filtered out of client templates, and the
                // public key kept it purely by accident of the caller's
                // template being echoed back. That is the direct cause of an
                // already-observed interop break: the C++ engine's KEM path
                // requires the attribute and therefore rejected every
                // Rust-generated EC key. Written in the OID form (both forms
                // are legal; decode_ec_params accepts either on input).
                let curve_oid: Vec<u8> = match curve {
                    CURVE_P521 => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
                    CURVE_P384 => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
                    CURVE_K256 => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],
                    _ => vec![
                        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                    ],
                };
                // Written AFTER absorb_template_attrs below — the attribute
                // must describe the key the engine ACTUALLY generated, so a
                // caller who supplied the curveName form gets the canonical
                // OID back rather than their own bytes echoed.
                if is_p521 {
                    store_param_set(&mut pub_attrs, CURVE_P521);
                    store_param_set(&mut prv_attrs, CURVE_P521);
                    let sk = with_rng!(rng, { p521::ecdsa::SigningKey::random(&mut rng) });
                    let vk = p521::ecdsa::VerifyingKey::from(&sk);
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
                    let mut ec_point = Vec::with_capacity(3 + vk_bytes.len());
                    ec_point.push(0x04u8); // DER OCTET STRING tag
                    // 133 fits in short-form length
                    ec_point.push(0x81u8); // multi-byte length
                    ec_point.push(vk_bytes.len() as u8); // 133
                    ec_point.extend_from_slice(&vk_bytes);
                    pub_attrs.insert(CKA_EC_POINT, ec_point);
                    let spki = build_ec_spki_p521(&vk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                } else if is_p384 {
                    store_param_set(&mut pub_attrs, CURVE_P384);
                    store_param_set(&mut prv_attrs, CURVE_P384);
                    let sk = with_rng!(rng, { p384::ecdsa::SigningKey::random(&mut rng) });
                    let vk = p384::ecdsa::VerifyingKey::from(&sk);
                    // CKA_VALUE on private key = big-endian private scalar (PKCS#11 v3.2 §2.3.7)
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
                    // CKA_EC_POINT: DER OCTET STRING wrapping uncompressed SEC1 point (PKCS#11 v3.2 §2.3.3)
                    // CKA_VALUE is NOT defined for CKO_PUBLIC_KEY/CKK_EC objects.
                    let mut ec_point = Vec::with_capacity(2 + vk_bytes.len());
                    ec_point.push(0x04u8); // DER OCTET STRING tag
                    ec_point.push(vk_bytes.len() as u8); // short-form length (97 fits in 1 byte)
                    ec_point.extend_from_slice(&vk_bytes);
                    pub_attrs.insert(CKA_EC_POINT, ec_point);
                    // SubjectPublicKeyInfo DER for P-384 (97-byte uncompressed point)
                    // 30 76 30 10 06 07 2a86 48ce3d0201 06 05 2b81 0400 22 03 62 00 <97 bytes>
                    let spki = build_ec_spki_p384(&vk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                } else if is_secp256k1 {
                    store_param_set(&mut pub_attrs, CURVE_K256);
                    store_param_set(&mut prv_attrs, CURVE_K256);
                    let sk = with_rng!(rng, { k256::ecdsa::SigningKey::random(&mut rng) });
                    let vk = k256::ecdsa::VerifyingKey::from(&sk);
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
                    let mut ec_point = Vec::with_capacity(2 + vk_bytes.len());
                    ec_point.push(0x04u8);
                    ec_point.push(vk_bytes.len() as u8);
                    ec_point.extend_from_slice(&vk_bytes);
                    pub_attrs.insert(CKA_EC_POINT, ec_point);
                    // OID: 1.3.132.0.10 (secp256k1) = 0x06 0x05 0x2b 0x81 0x04 0x00 0x0a
                    let alg_id: &[u8] = &[
                        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                        0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a,
                    ];
                    let spki = build_spki_from_parts(alg_id, &vk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                } else {
                    store_param_set(&mut pub_attrs, CURVE_P256);
                    store_param_set(&mut prv_attrs, CURVE_P256);
                    let sk = with_rng!(rng, { p256::ecdsa::SigningKey::random(&mut rng) });
                    let vk = p256::ecdsa::VerifyingKey::from(&sk);
                    // CKA_VALUE on private key = big-endian private scalar (PKCS#11 v3.2 §2.3.7)
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
                    // CKA_EC_POINT: DER OCTET STRING wrapping uncompressed SEC1 point (PKCS#11 v3.2 §2.3.3)
                    // CKA_VALUE is NOT defined for CKO_PUBLIC_KEY/CKK_EC objects.
                    let mut ec_point = Vec::with_capacity(2 + vk_bytes.len());
                    ec_point.push(0x04u8); // DER OCTET STRING tag
                    ec_point.push(vk_bytes.len() as u8); // short-form length (65 fits in 1 byte)
                    ec_point.extend_from_slice(&vk_bytes);
                    pub_attrs.insert(CKA_EC_POINT, ec_point);
                    // SubjectPublicKeyInfo DER for P-256 (65-byte uncompressed point)
                    // 30 59 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107 03 42 00 <65 bytes>
                    let spki = build_ec_spki_p256(&vk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                }
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                // E2 — engine truth, after absorb (see the curve_oid comment).
                pub_attrs.insert(CKA_EC_PARAMS, curve_oid.clone());
                prv_attrs.insert(CKA_EC_PARAMS, curve_oid);
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            CKM_EC_EDWARDS_KEY_PAIR_GEN => {
                // W2 (2026-08-13) — §6.3.10: these curves "can only be
                // specified in the CKA_EC_PARAMS attribute of the template for
                // the public key using the curveName or the oID methods.
                // Attempts to generate keys over these curves using any other
                // EC key pair generation mechanism will fail with
                // CKR_CURVE_NOT_SUPPORTED." This arm never read the attribute
                // at all and hardcoded Ed25519, so an Ed448 request returned
                // an Ed25519 key with success.
                //
                // The Montgomery arm below already switched on the attribute,
                // which is why Edwards was the outlier rather than a position.
                //
                // Ed448 (2026-08-27) — §6.3.14 permits supporting only one of
                // the two, and this engine initially chose Ed25519-only
                // (CKR_CURVE_NOT_SUPPORTED for an Ed448 request). Both curves
                // are now implemented: `ed448-goldilocks` was already a
                // transitive dependency (pulled in by `x448` below, for its
                // Montgomery/X448 arm only) and mirrors `ed25519-dalek`'s API
                // closely enough that both branches share this arm's
                // attribute scaffolding, just not the key material or its
                // fixed sizes (32B key / 64B sig for Ed25519, 57B key / 114B
                // sig for Ed448 — see get_sig_len and verify_eddsa/PH, which
                // both dispatch on the stored key's length rather than the
                // mechanism alone, since CKM_EDDSA covers both curves).
                let ed_params = get_attr_bytes(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_EC_PARAMS,
                )
                .or_else(|| {
                    get_attr_bytes(
                        p_private_key_template,
                        ul_private_key_attribute_count,
                        CKA_EC_PARAMS,
                    )
                });
                let ed_params = match ed_params {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                let is_ed448 = match crate::crypto::handlers::decode_ec_params(&ed_params) {
                    Ok(CURVE_ED25519) => false,
                    Ok(CURVE_ED448) => true,
                    Ok(_) => return CKR_CURVE_NOT_SUPPORTED,
                    Err(rv) => return rv,
                };

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_algo_family(&mut pub_attrs, ALGO_EDDSA);
                store_algo_family(&mut prv_attrs, ALGO_EDDSA);
                // PKCS#11 v3.2 defaults — EdDSA public key
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC_EDWARDS);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_EC_EDWARDS_KEY_PAIR_GEN,
                );
                // PKCS#11 v3.2 defaults — EdDSA private key
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC_EDWARDS);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_EC_EDWARDS_KEY_PAIR_GEN,
                );
                // E4 (2026-08-13) — the Edwards public-key table says "Public
                // key bytes in little endian order as defined in [RFC 8032]",
                // deliberately different wording from the Weierstrass table's
                // "DER-encoding of ANSI X9.62 ECPoint value Q". That
                // difference IS the specification. This arm previously put
                // the key in CKA_VALUE with no EC point and no parameters at
                // all — the worst of the three engines' variants. Now:
                // CKA_EC_POINT holds the BARE key bytes, CKA_EC_PARAMS is
                // present, and there is no CKA_VALUE on a public key.
                let (vk_bytes, ec_params_oid, spki) = if is_ed448 {
                    use ed448_goldilocks::elliptic_curve::Generate;
                    use getrandom_0_4::rand_core::UnwrapErr;
                    use getrandom_0_4::SysRng;
                    let mut rng = UnwrapErr(SysRng);
                    let sk = ed448_goldilocks::SigningKey::generate_from_rng(&mut rng);
                    let vk = sk.verifying_key();
                    let vk_bytes = vk.to_bytes().to_vec();
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    // OID 1.3.101.113 — id-Ed448 (RFC 8410)
                    let oid = vec![0x06, 0x03, 0x2b, 0x65, 0x71];
                    // SubjectPublicKeyInfo DER for Ed448 (57-byte key)
                    // 30 43 30 05 06 03 2b6571 03 3a 00 <57 bytes>
                    let alg_id: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71];
                    let spki = build_spki_from_parts(alg_id, &vk_bytes);
                    (vk_bytes, oid, spki)
                } else {
                    let sk = with_rng!(rng, { ed25519_dalek::SigningKey::generate(&mut rng) });
                    let vk = sk.verifying_key();
                    let vk_bytes = vk.to_bytes().to_vec();
                    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                    // OID 1.3.101.112 — id-Ed25519 (RFC 8410)
                    let oid = vec![0x06, 0x03, 0x2b, 0x65, 0x70];
                    // SubjectPublicKeyInfo DER for Ed25519 (32-byte key)
                    // 30 2a 30 05 06 03 2b6570 03 22 00 <32 bytes>
                    let spki = build_ed25519_spki(&vk_bytes);
                    (vk_bytes, oid, spki)
                };
                pub_attrs.insert(CKA_EC_POINT, vk_bytes);
                pub_attrs.insert(CKA_EC_PARAMS, ec_params_oid.clone());
                prv_attrs.insert(CKA_EC_PARAMS, ec_params_oid);
                pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            CKM_EC_MONTGOMERY_KEY_PAIR_GEN => {
                // PKCS#11 v3.2 §6.7 — EC Montgomery key pair generation.
                // Distinguish X25519 (OID last byte 0x6e) from X448 (OID last byte 0x6f)
                // via CKA_EC_PARAMS in the public or private key template.
                let oid_bytes = get_attr_bytes(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_EC_PARAMS,
                )
                .or_else(|| {
                    get_attr_bytes(
                        p_private_key_template,
                        ul_private_key_attribute_count,
                        CKA_EC_PARAMS,
                    )
                });
                // W1 / E4 — decode the CHOICE instead of sniffing the last
                // byte, and accept the curveName form as well as the OID
                // (§6.3.10's interop note: C++ emits curve names, Rust OIDs,
                // and "both engines accept both forms on input" is the fix).
                let oid_bytes = match oid_bytes {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                let is_x448 = match crate::crypto::handlers::decode_ec_params(&oid_bytes) {
                    Ok(CURVE_X448) => true,
                    Ok(CURVE_X25519) => false,
                    Ok(_) => return CKR_CURVE_NOT_SUPPORTED,
                    Err(rv) => return rv,
                };

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC_MONTGOMERY);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, false);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
                );
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC_MONTGOMERY);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, false);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DERIVE, true);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
                );

                if is_x448 {
                    // X448 — 56-byte keys (RFC 8410, OID 1.3.101.111)
                    use x448::{PublicKey as X448PublicKey, StaticSecret as X448StaticSecret};
                    let mut sk_bytes_arr = [0u8; 56];
                    if getrandom::getrandom(&mut sk_bytes_arr).is_err() {
                        return CKR_FUNCTION_FAILED;
                    }
                    let sk = X448StaticSecret::from(sk_bytes_arr);
                    let pk = X448PublicKey::from(&sk);
                    let pk_bytes = pk.as_bytes().to_vec();
                    let sk_bytes = sk.as_bytes().to_vec();
                    store_algo_family(&mut pub_attrs, ALGO_ECDH_X448);
                    store_algo_family(&mut prv_attrs, ALGO_ECDH_X448);
                    prv_attrs.insert(CKA_VALUE, sk_bytes);
                    let spki = build_x448_spki(&pk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                    // CKA_EC_PARAMS — DER OID for id-X448 (RFC 8410, 1.3.101.111).
                    let oid_x448: Vec<u8> = vec![0x06, 0x03, 0x2b, 0x65, 0x6f];
                    pub_attrs.insert(CKA_EC_PARAMS, oid_x448.clone());
                    prv_attrs.insert(CKA_EC_PARAMS, oid_x448);
                    // E4 (2026-08-13) — the Montgomery public-key table says
                    // "Public key bytes in little endian order as defined in
                    // [RFC 7748]". No DER wrapper, and no CKA_VALUE on a
                    // public key: this arm previously DER-wrapped the point
                    // AND duplicated it into CKA_VALUE.
                    pub_attrs.insert(CKA_EC_POINT, pk_bytes.clone());
                } else {
                    // X25519 — 32-byte keys (RFC 8410, OID 1.3.101.110)
                    let sk = with_rng!(rng, {
                        x25519_dalek::StaticSecret::random_from_rng(&mut rng)
                    });
                    let pk = x25519_dalek::PublicKey::from(&sk);
                    let pk_bytes = pk.as_bytes().to_vec();
                    let sk_bytes = sk.to_bytes().to_vec();
                    store_algo_family(&mut pub_attrs, ALGO_ECDH_X25519);
                    store_algo_family(&mut prv_attrs, ALGO_ECDH_X25519);
                    prv_attrs.insert(CKA_VALUE, sk_bytes);
                    let spki = build_x25519_spki(&pk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                    // CKA_EC_PARAMS — DER OID for id-X25519 (RFC 8410, 1.3.101.110).
                    let oid_x25519: Vec<u8> = vec![0x06, 0x03, 0x2b, 0x65, 0x6e];
                    pub_attrs.insert(CKA_EC_PARAMS, oid_x25519.clone());
                    prv_attrs.insert(CKA_EC_PARAMS, oid_x25519);
                    // E4 — bare little-endian bytes, no DER, no CKA_VALUE on
                    // the public half (see the X448 arm above).
                    pub_attrs.insert(CKA_EC_POINT, pk_bytes.clone());
                }

                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            // ── HSS keygen (PKCS#11 v3.2 §6.14 CKM_HSS_KEY_PAIR_GEN) ─────────
            // Single-level LMS: use levels=1 in CK_HSS_KEY_PAIR_GEN_PARAMS.
            CKM_HSS_KEY_PAIR_GEN => {
                // CK_HSS_KEY_PAIR_GEN_PARAMS (optional): ulLevels + ulLmsParamSet[8]
                // + ulLmotsParamSet[8], all CK_ULONG → 17 words at native width
                // (68 B wasm32, 136 B native). Absent params ⇒ a single-level LMS
                // with the default SHA-256 parameter set (PKCS#11 v3.2 §6.14).
                let (levels, lms_params, lmots_params): (usize, Vec<u32>, Vec<u32>) =
                    match ck_param::mech(p_mechanism).opt_params(
                        &ck_param::hss_key_pair_gen::LAYOUT,
                        ck_param::hss_key_pair_gen::FIELD_COUNT,
                    ) {
                        Ok(None) => (1, vec![CKP_LMS_SHA256_M32_H5], vec![CKP_LMOTS_SHA256_N32_W4]),
                        Err(_) => return CKR_MECHANISM_PARAM_INVALID,
                        Ok(Some(r)) => {
                            let levels = r.ulong(ck_param::hss_key_pair_gen::UL_LEVELS);
                            if levels == 0 || levels > 8 {
                                return CKR_MECHANISM_PARAM_INVALID;
                            }
                            let lms: Vec<u32> = (0..levels)
                                .map(|i| r.ulong32(ck_param::hss_key_pair_gen::LMS_0 + i))
                                .collect();
                            let lmots: Vec<u32> = (0..levels)
                                .map(|i| r.ulong32(ck_param::hss_key_pair_gen::LMOTS_0 + i))
                                .collect();
                            (levels, lms, lmots)
                        }
                    };

                let (pub_bytes, priv_bytes) =
                    match crate::crypto::lms::hss_keygen(levels, &lms_params, &lmots_params) {
                        Ok(pair) => pair,
                        Err(_) => return CKR_FUNCTION_FAILED,
                    };

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                // Public key attributes
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_HSS);
                store_ulong(&mut pub_attrs, CKA_HSS_LMS_TYPE, levels as u32);
                store_ulong(&mut pub_attrs, CKA_LMS_PARAM_SET, lms_params[0]);
                store_ulong(&mut pub_attrs, CKA_LMOTS_PARAM_SET, lmots_params[0]);
                store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_HSS_KEY_PAIR_GEN);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                pub_attrs.insert(CKA_VALUE, pub_bytes);
                // Private key attributes
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_HSS);
                store_ulong(&mut prv_attrs, CKA_HSS_LMS_TYPE, levels as u32);
                store_ulong(&mut prv_attrs, CKA_LMS_PARAM_SET, lms_params[0]);
                store_ulong(&mut prv_attrs, CKA_LMOTS_PARAM_SET, lmots_params[0]);
                store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_HSS_KEY_PAIR_GEN);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                // Total HSS capacity = ∏(2^H_i) for each level, capped at u32::MAX per PKCS#11 v3.2 §6.14.
                let mut total_sigs: u64 = 1u64;
                for &p in &lms_params {
                    if let Some(leaves) = crate::crypto::lms::lms_param_max_leaves(p) {
                        total_sigs = total_sigs.saturating_mul(leaves);
                    }
                }
                let total_sigs = total_sigs.min(u32::MAX as u64) as u32;
                store_ulong(&mut pub_attrs, CKA_HSS_KEYS_REMAINING, total_sigs);
                store_ulong(&mut prv_attrs, CKA_HSS_KEYS_REMAINING, total_sigs);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                prv_attrs.insert(CKA_PRIV_STATEFUL_KEY_STATE, priv_bytes);
                prv_attrs.insert(CKA_PRIV_LEAF_INDEX, 0u64.to_le_bytes().to_vec());
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            // ── XMSS single-level keygen (PKCS#11 v3.2 §6.14 CKM_XMSS_KEY_PAIR_GEN) ─
            CKM_XMSS_KEY_PAIR_GEN => {
                // NO MECHANISM PARAMETER IS READ. Settled 2026-08-14 against
                // the Standard rather than against the two arms' habits.
                //
                // PKCS#11 v3.2 §6.66.6, verbatim: "This mechanism does not
                // have a parameter." The very next sentence says where the
                // parameter set comes from instead: "The mechanism generates
                // XMSS public/private key pairs using an oid, as specified in
                // the CKA_PARAMETER_SET attribute of the template for the
                // public key." §6.66.7 makes XMSSMT inherit that in full —
                // "All other restrictions detailed in section 6.66.6 apply".
                //
                // Until today this arm read a one-word mechanism parameter as
                // a fallback and the XMSSMT arm below read one too, AT A
                // DIFFERENT WIDTH (u32 here, native there). There is no
                // CK_XMSS_KEY_PAIR_GEN_PARAMS in pkcs11t.h and none in the
                // canonical OASIS header, so neither width could be checked
                // against anything — the disagreement was unresolvable while
                // the read existed, and resolving it by picking a width would
                // have invented an ABI the specification says has no members.
                // Deleting the read makes the two arms agree exactly, and
                // agree with the C++ engine, which already ignores
                // pParameter here (SoftHSM_keygen.cpp, W4).
                //
                // Anything in pParameter is now ignored, as §6.66.6 requires.

                // P4 — the parameter set is carried in the STANDARD
                // CKA_PARAMETER_SET (0x61d, PKCS#11 v3.2 Table 273); the
                // legacy vendor CKA_XMSS_PARAM_SET stays as an input fallback
                // for keys written by older callers. Previously only the
                // vendor attr + mech word were read, so a conformant client's
                // CKA_PARAMETER_SET was ignored.
                let xmss_param = xmss_keygen_param_set(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_XMSS_PARAM_SET,
                    CKP_XMSS_SHA2_10_256,
                );

                // C2 (2026-08-13) — an unrecognised CKA_PARAMETER_SET is
                // CKR_PARAMETER_SET_NOT_SUPPORTED ("This parameter set is not
                // supported by this token", §5.1.6 Table 6), the code this
                // engine already uses correctly for ML-DSA / ML-KEM /
                // SLH-DSA. CKR_FUNCTION_FAILED said nothing about WHY.
                // xmss_keygen's only failure mode besides an entropy failure
                // is an unknown parameter set.
                let (pub_bytes, priv_bytes) =
                    match crate::crypto::xmss_bridge::xmss_keygen(xmss_param) {
                        Ok(pair) => pair,
                        Err(_) => return CKR_PARAMETER_SET_NOT_SUPPORTED,
                    };

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                // Public key attributes
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_XMSS);
                // Store the EFFECTIVE xmss_param (with default applied) — not
                // the raw param_code. xmss_sign / xmss_verify read this attr
                // and dispatch on it; a stored 0 falls into the catch-all
                // `_ => Err(CKR_FUNCTION_FAILED)` arm and breaks every sign.
                // P4 — expose the param set under the STANDARD CKA_PARAMETER_SET
                // (what a conformant client reads back) as well as the legacy
                // vendor attr the sign/verify path dispatches on.
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, xmss_param);
                store_ulong(&mut pub_attrs, CKA_XMSS_PARAM_SET, xmss_param);
                store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_XMSS_KEY_PAIR_GEN);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                // CKA_ENCRYPT and CKA_WRAP are COMMON PUBLIC key attributes
                // (Table 27) and CKA_DERIVE a COMMON KEY attribute (§4.8
                // Table 26), so an XMSS public key possesses all three
                // whatever it can do with them — this engine answered
                // CKR_ATTRIBUTE_TYPE_INVALID for each. FALSE, truthfully: XMSS
                // is a signature scheme and its public key verifies and does
                // nothing else. (C++ has all three and answers TRUE for
                // encrypt and wrap, which overstates its own dispatch; that
                // residual value difference is a token-specific default under
                // Table 13 footnote 9 and is already adjudicated by the
                // LEGAL-USAGE-FLAG-DEFAULT-* entries.)
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                // NO CKA_EXTRACTABLE on the public half. §4.9 Table 27 (common
                // PUBLIC key attributes) does not define it; it is a private/
                // secret key attribute, and it is one of the two attributes
                // §6.66.4's "CKA_SENSITIVE MUST be true and CKA_EXTRACTABLE
                // MUST be false for this key" is expressed through — so having
                // it on the wrong half made that MUST uncheckable on the right
                // one.
                pub_attrs.insert(CKA_VALUE, pub_bytes);
                // Private key attributes
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_XMSS);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, xmss_param);
                store_ulong(&mut prv_attrs, CKA_XMSS_PARAM_SET, xmss_param);
                store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_XMSS_KEY_PAIR_GEN);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                // XMSS capacity = 2^H from the parameter set (PKCS#11 v3.2 §6.15).
                // Tracked under the vendor attribute CKA_PRIV_XMSS_KEYS_REMAINING, separate from CKA_HSS_KEYS_REMAINING.
                let xmss_max_sigs = crate::crypto::xmss_bridge::xmss_param_max_sigs(xmss_param);
                store_ulong(&mut pub_attrs, CKA_PRIV_XMSS_KEYS_REMAINING, xmss_max_sigs);
                store_ulong(&mut prv_attrs, CKA_PRIV_XMSS_KEYS_REMAINING, xmss_max_sigs);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                prv_attrs.insert(CKA_PRIV_STATEFUL_KEY_STATE, priv_bytes);
                prv_attrs.insert(CKA_PRIV_LEAF_INDEX, 0u64.to_le_bytes().to_vec());
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            // ── XMSS^MT keygen (PKCS#11 v3.2 §6.16 CKM_XMSSMT_KEY_PAIR_GEN) ───
            CKM_XMSSMT_KEY_PAIR_GEN => {
                // NO MECHANISM PARAMETER IS READ — §6.66.7 pulls in §6.66.6's
                // "This mechanism does not have a parameter" wholesale ("All
                // other restrictions detailed in section 6.66.6 apply, using
                // XMSSMT types where necessary"). See the CKM_XMSS_KEY_PAIR_GEN
                // arm above for the full reasoning; this arm is its twin and
                // the width disagreement between them is what the deletion
                // resolves.
                //
                // Parameter set: CKA_PARAMETER_SET (0x61d, verified vs
                // pkcs11t.h), with the legacy vendor CKA_XMSSMT_PARAM_SET as an
                // input fallback; default CKP_XMSSMT_SHA2_20_2_256.
                let mt_param = xmss_keygen_param_set(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_XMSSMT_PARAM_SET,
                    CKP_XMSSMT_SHA2_20_2_256,
                );
                // C2 — see the XMSS arm above.
                let (pub_bytes, priv_bytes) =
                    match crate::crypto::xmss_bridge::xmssmt_keygen(mt_param) {
                        Ok(pair) => pair,
                        Err(_) => return CKR_PARAMETER_SET_NOT_SUPPORTED,
                    };
                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_XMSSMT);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, mt_param);
                store_ulong(&mut pub_attrs, CKA_XMSSMT_PARAM_SET, mt_param);
                store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_XMSSMT_KEY_PAIR_GEN);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                // CKA_ENCRYPT and CKA_WRAP are COMMON PUBLIC key attributes
                // (Table 27) and CKA_DERIVE a COMMON KEY attribute (§4.8
                // Table 26), so an XMSS public key possesses all three
                // whatever it can do with them — this engine answered
                // CKR_ATTRIBUTE_TYPE_INVALID for each. FALSE, truthfully: XMSS
                // is a signature scheme and its public key verifies and does
                // nothing else. (C++ has all three and answers TRUE for
                // encrypt and wrap, which overstates its own dispatch; that
                // residual value difference is a token-specific default under
                // Table 13 footnote 9 and is already adjudicated by the
                // LEGAL-USAGE-FLAG-DEFAULT-* entries.)
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                // NO CKA_EXTRACTABLE on the public half. §4.9 Table 27 (common
                // PUBLIC key attributes) does not define it; it is a private/
                // secret key attribute, and it is one of the two attributes
                // §6.66.4's "CKA_SENSITIVE MUST be true and CKA_EXTRACTABLE
                // MUST be false for this key" is expressed through — so having
                // it on the wrong half made that MUST uncheckable on the right
                // one.
                pub_attrs.insert(CKA_VALUE, pub_bytes);
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_XMSSMT);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, mt_param);
                store_ulong(&mut prv_attrs, CKA_XMSSMT_PARAM_SET, mt_param);
                store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_XMSSMT_KEY_PAIR_GEN);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                let mt_max = crate::crypto::xmss_bridge::xmssmt_param_max_sigs(mt_param)
                    .min(u32::MAX as u64) as u32;
                store_ulong(&mut pub_attrs, CKA_PRIV_XMSS_KEYS_REMAINING, mt_max);
                store_ulong(&mut prv_attrs, CKA_PRIV_XMSS_KEYS_REMAINING, mt_max);
                prv_attrs.insert(CKA_PRIV_STATEFUL_KEY_STATE, priv_bytes);
                prv_attrs.insert(CKA_PRIV_LEAF_INDEX, 0u64.to_le_bytes().to_vec());
                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            // BSI TR-02102-1 §2.4.1 — CKA_PARAMETER_SET selects one of the 6
            // standard FrodoKEM variants; REQUIRED, same convention as
            // ML-KEM above. No deterministic (CKA_SEED) keygen path exists —
            // `frodo-kem` doesn't expose a keygen-from-seed entry point.
            CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN => {
                let ps = match get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_PARAMETER_SET,
                ) {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                let alg = match crate::native::keygen::frodokem_algorithm(ps) {
                    Ok(a) => a,
                    Err(_) => return CKR_ATTRIBUTE_VALUE_INVALID,
                };
                if get_attr_bytes(p_private_key_template, ul_private_key_attribute_count, CKA_SEED)
                    .is_some()
                    || get_attr_bytes(p_public_key_template, ul_public_key_attribute_count, CKA_SEED)
                        .is_some()
                {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_FRODOKEM);
                store_algo_family(&mut prv_attrs, ALGO_FRODOKEM);
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_PQCTODAY_FRODOKEM);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, false);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_PQCTODAY_FRODOKEM);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, false);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);

                // RNG note (see native::keygen::generate_frodokem_keypair):
                // `frodo-kem` needs rand_core 0.10's CryptoRng, not this
                // engine's usual rand 0.8 OsRng.
                use getrandom_0_4::rand_core::UnwrapErr;
                use getrandom_0_4::SysRng;
                let mut rng = UnwrapErr(SysRng);
                let (ek, dk) = alg.generate_keypair(&mut rng);
                pub_attrs.insert(CKA_VALUE, ek.value().to_vec());
                prv_attrs.insert(CKA_VALUE, dk.value().to_vec());

                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            // BSI TR-02102-1 §2.4.2 — scoped to mceliece6688128 only
            // (implementation plan Phase 0.5: classic-mceliece-rust can only
            // have one parameter-set feature compiled in at a time).
            CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN => {
                let ps = match get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_PARAMETER_SET,
                ) {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                if ps != CKP_CLASSIC_MCELIECE_6688128 {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                if get_attr_bytes(p_private_key_template, ul_private_key_attribute_count, CKA_SEED)
                    .is_some()
                    || get_attr_bytes(p_public_key_template, ul_public_key_attribute_count, CKA_SEED)
                        .is_some()
                {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }

                let mut pub_attrs = HashMap::new();
                let mut prv_attrs = HashMap::new();
                store_param_set(&mut pub_attrs, ps);
                store_param_set(&mut prv_attrs, ps);
                store_algo_family(&mut pub_attrs, ALGO_CLASSIC_MCELIECE);
                store_algo_family(&mut prv_attrs, ALGO_CLASSIC_MCELIECE);
                store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_PQCTODAY_CLASSIC_MCELIECE);
                store_ulong(&mut pub_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut pub_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN,
                );
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, false);
                store_bool(&mut pub_attrs, CKA_WRAP, false);
                store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
                store_bool(&mut pub_attrs, CKA_DERIVE, false);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_PQCTODAY_CLASSIC_MCELIECE);
                store_ulong(&mut prv_attrs, CKA_PARAMETER_SET, ps);
                store_ulong(
                    &mut prv_attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN,
                );
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_DECRYPT, false);
                store_bool(&mut prv_attrs, CKA_SIGN, false);
                store_bool(&mut prv_attrs, CKA_UNWRAP, false);
                store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
                store_bool(&mut prv_attrs, CKA_DERIVE, false);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);

                // Unlike FrodoKEM, classic-mceliece-rust uses rand 0.8 — the
                // same version this engine already uses elsewhere.
                let mut rng = rand::rngs::OsRng;
                let (pk, sk) = classic_mceliece_rust::keypair_boxed(&mut rng);
                pub_attrs.insert(CKA_VALUE, pk.as_ref().to_vec());
                prv_attrs.insert(CKA_VALUE, sk.as_ref().to_vec());

                absorb_template_attrs(
                    &mut pub_attrs,
                    p_public_key_template,
                    ul_public_key_attribute_count,
                );
                absorb_template_attrs(
                    &mut prv_attrs,
                    p_private_key_template,
                    ul_private_key_attribute_count,
                );
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            _ => CKR_MECHANISM_INVALID,
        }
    }
}

/// S7 — read the effective CKA_TOKEN from a caller template (absent = FALSE,
/// the §4.4 default) and apply the read-only-session gate. One call per
/// creating function; see `state::check_rw_for_token_object`.
unsafe fn gate_ro_session_for_template(
    h_session: u32,
    p_template: *mut u8,
    count: u32,
) -> Result<(), u32> {
    let wants_token = get_attr_bytes(p_template, count, CKA_TOKEN)
        .map(|v| v.first().copied().unwrap_or(0) != 0)
        .unwrap_or(false);
    crate::state::check_rw_for_token_object(h_session, wants_token)
}

#[wasm_bindgen(js_name = _C_GenerateKey)]
pub fn C_GenerateKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    p_template: *mut u8,
    ul_count: u32,
    ph_key: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    // §5.18.1 — pMechanism is a required input pointer.
    nonnull!(p_mechanism, ph_key);
    unsafe {
        // S7 — §5.7.1: only session objects during a read-only session.
        if let Err(rv) = gate_ro_session_for_template(_h_session, p_template, ul_count) {
            return rv;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        // V4 — a CKA_KEY_TYPE in the template that contradicts the secret-key
        // generation mechanism is CKR_TEMPLATE_INCONSISTENT.
        let expected_kt = match mech_type {
            CKM_AES_KEY_GEN => Some(CKK_AES),
            CKM_CHACHA20_KEY_GEN => Some(CKK_CHACHA20),
            CKM_GENERIC_SECRET_KEY_GEN => Some(CKK_GENERIC_SECRET),
            _ => None,
        };
        if let Some(exp) = expected_kt {
            if let Some(kt) = get_attr_ulong(p_template, ul_count, CKA_KEY_TYPE) {
                if kt != exp {
                    return CKR_TEMPLATE_INCONSISTENT;
                }
            }
        }
        match mech_type {
            CKM_CHACHA20_KEY_GEN => {
                // §6.20 — ChaCha20 keys are always 256-bit (32 bytes).
                let mut key = vec![0u8; 32];
                if getrandom::getrandom(&mut key).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let mut attrs = HashMap::new();
                attrs.insert(CKA_VALUE, key);
                store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_CHACHA20);
                store_ulong(&mut attrs, CKA_VALUE_LEN, 32);
                store_bool(&mut attrs, CKA_TOKEN, false);
                store_bool(&mut attrs, CKA_PRIVATE, false);
                store_bool(&mut attrs, CKA_SENSITIVE, false);
                store_bool(&mut attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut attrs, CKA_ENCRYPT, true);
                store_bool(&mut attrs, CKA_DECRYPT, true);
                store_bool(&mut attrs, CKA_WRAP, false);
                store_bool(&mut attrs, CKA_UNWRAP, false);
                store_bool(&mut attrs, CKA_SIGN, false);
                store_bool(&mut attrs, CKA_VERIFY, false);
                store_bool(&mut attrs, CKA_DERIVE, false);
                store_bool(&mut attrs, CKA_LOCAL, true);
                store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_CHACHA20_KEY_GEN);
                absorb_template_attrs(&mut attrs, p_template, ul_count);
                finalize_private_key_attrs(&mut attrs);
                compute_kcv(&mut attrs);
                *ph_key = allocate_handle_owned(_h_session, attrs);
                CKR_OK
            }
            CKM_AES_KEY_GEN => {
                // PKCS#11 v3.2 §6.27.2 — CKA_VALUE_LEN is a REQUIRED template
                // attribute for CKM_AES_KEY_GEN (no silent 16-byte default).
                let key_len = match get_attr_ulong(p_template, ul_count, CKA_VALUE_LEN) {
                    Some(l) => l as usize,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                // 16/24/32 per C_GetMechanismInfo (16–32) and the native API,
                // which already accepts AES-192.
                if key_len != 16 && key_len != 24 && key_len != 32 {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                let mut key = vec![0u8; key_len];
                if getrandom::getrandom(&mut key).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let mut attrs = HashMap::new();
                attrs.insert(CKA_VALUE, key);
                // PKCS#11 v3.2 defaults — AES secret key
                store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
                store_ulong(&mut attrs, CKA_VALUE_LEN, key_len as u32);
                store_bool(&mut attrs, CKA_TOKEN, false);
                store_bool(&mut attrs, CKA_PRIVATE, false);
                store_bool(&mut attrs, CKA_SENSITIVE, false);
                store_bool(&mut attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut attrs, CKA_ENCRYPT, true);
                store_bool(&mut attrs, CKA_DECRYPT, true);
                store_bool(&mut attrs, CKA_WRAP, true);
                store_bool(&mut attrs, CKA_UNWRAP, true);
                store_bool(&mut attrs, CKA_SIGN, false);
                store_bool(&mut attrs, CKA_VERIFY, false);
                store_bool(&mut attrs, CKA_DERIVE, false);
                store_bool(&mut attrs, CKA_LOCAL, true);
                store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_AES_KEY_GEN); // PKCS#11 v3.2 §4.3
                absorb_template_attrs(&mut attrs, p_template, ul_count);
                finalize_private_key_attrs(&mut attrs); // sets CKA_ALWAYS_SENSITIVE + CKA_NEVER_EXTRACTABLE
                compute_kcv(&mut attrs);
                *ph_key = allocate_handle_owned(_h_session, attrs);
                CKR_OK
            }
            CKM_GENERIC_SECRET_KEY_GEN => {
                let key_len =
                    get_attr_ulong(p_template, ul_count, CKA_VALUE_LEN).unwrap_or(32) as usize;
                // §4.1 / §5.18.1 — an out-of-range CKA_VALUE_LEN is a bad
                // attribute VALUE, not bad function arguments.
                if key_len == 0 || key_len > 512 {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                let mut key = vec![0u8; key_len];
                if getrandom::getrandom(&mut key).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                let mut attrs = HashMap::new();
                attrs.insert(CKA_VALUE, key);
                // PKCS#11 v3.2 defaults — GENERIC_SECRET key (used for HMAC)
                store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_ulong(&mut attrs, CKA_VALUE_LEN, key_len as u32);
                store_bool(&mut attrs, CKA_TOKEN, false);
                store_bool(&mut attrs, CKA_SENSITIVE, false);
                store_bool(&mut attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut attrs, CKA_ENCRYPT, false);
                store_bool(&mut attrs, CKA_DECRYPT, false);
                store_bool(&mut attrs, CKA_WRAP, false);
                store_bool(&mut attrs, CKA_UNWRAP, false);
                store_bool(&mut attrs, CKA_SIGN, true); // HMAC signing
                store_bool(&mut attrs, CKA_VERIFY, true);
                store_bool(&mut attrs, CKA_DERIVE, false);
                store_bool(&mut attrs, CKA_LOCAL, true);
                store_ulong(
                    &mut attrs,
                    CKA_KEY_GEN_MECHANISM,
                    CKM_GENERIC_SECRET_KEY_GEN,
                ); // PKCS#11 v3.2 §4.3
                absorb_template_attrs(&mut attrs, p_template, ul_count);
                finalize_private_key_attrs(&mut attrs); // sets CKA_ALWAYS_SENSITIVE + CKA_NEVER_EXTRACTABLE
                compute_kcv(&mut attrs);
                *ph_key = allocate_handle_owned(_h_session, attrs);
                CKR_OK
            }
            _ => CKR_MECHANISM_INVALID,
        }
    }
}

// ── ML-KEM Encapsulate/Decapsulate ──────────────────────────────────────────

/// DER-wrap an uncompressed SEC1 EC point exactly the way the engines encode
/// CKA_EC_POINT (OCTET STRING, short form or 0x81 long form). This is the
/// byte format the C++ engine's `encapsulateECDH` emits as the KEM
/// "ciphertext" (`ephPub->getQ()`), so cross-engine decapsulation works.
fn der_wrap_ec_point(point: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + point.len());
    out.push(0x04); // DER OCTET STRING tag
    if point.len() < 0x80 {
        out.push(point.len() as u8);
    } else {
        out.push(0x81);
        out.push(point.len() as u8);
    }
    out.extend_from_slice(point);
    out
}

/// Strip a DER OCTET STRING wrapper from an EC point if present. Mirrors the
/// C++ engine's `getECDHPubData` tolerance: raw uncompressed SEC1 points for
/// the supported curves (65/97/133 bytes) pass through untouched — length is
/// checked FIRST because a raw point also starts with 0x04 and could
/// otherwise be misread as a DER header.
fn ec_point_unwrap(bytes: &[u8]) -> &[u8] {
    match bytes.len() {
        65 | 97 | 133 => bytes, // raw uncompressed SEC1 (P-256 / P-384 / P-521)
        _ if bytes.len() >= 2 && bytes[0] == 0x04 => {
            if bytes[1] < 0x80 && bytes[1] as usize + 2 == bytes.len() {
                &bytes[2..]
            } else if bytes.len() >= 3 && bytes[1] == 0x81 && bytes[2] as usize + 3 == bytes.len() {
                &bytes[3..]
            } else {
                bytes
            }
        }
        _ => bytes,
    }
}

// ── KEM template CKA_VALUE_LEN reconciliation (PKCS#11 v3.2) ────────────────
//
// SPEC BASIS (all quotes from pkcs11-spec-v3.2-os, docs/refs/):
//
// §4.1.1 "Creating objects" names the KEM functions as object-creation
// functions: "Objects may be created with the Cryptoki functions
// C_CreateObject …, C_GenerateKey, C_GenerateKeyPair, C_UnwrapKey,
// C_DeriveKey, C_EncapsulateKey, and C_DecapsulateKey (see Section 5.18)."
// Rule 5: "If the attribute values in the supplied template, together with any
// default attribute values and any attribute values contributed to the object
// by the object-creation function itself, are inconsistent, then the attempt
// should fail with the error code CKR_TEMPLATE_INCONSISTENT."
// Rule 6: a template value that merely repeats what the function contributes
// MAY succeed, and "Library developers are encouraged to make their libraries
// behave as though the attribute had only appeared once in the template."
//
// §6.68.5 (CKM_ML_KEM, and by construction the vendor FrodoKEM /
// Classic-McEliece arms): "The mechanism contributes the result as the
// CKA_VALUE attribute of the new key; other attributes required by the key
// type must be specified in the template." There is no length knob — the
// shared-secret length is fixed by the mechanism.
//
// §6.8.2 Table 103 defines CKA_VALUE_LEN on a CKK_GENERIC_SECRET object as
// "Length in bytes of key value", i.e. of CKA_VALUE. A CKA_VALUE_LEN that is
// not len(CKA_VALUE) is therefore self-contradictory on the object.
//
// §5.18.8 / §5.18.9: "If a call to C_EncapsulateKey [C_DecapsulateKey] cannot
// support the precise template supplied to it, it will fail and return without
// creating any key object." Both list CKR_TEMPLATE_INCONSISTENT.
//
// => fixed-length KEMs: a matching caller CKA_VALUE_LEN is accepted silently
//    (rule 6), a differing one is CKR_TEMPLATE_INCONSISTENT (rule 5), and the
//    engine's own value is always the one stored.

/// Reconcile a caller-supplied CKA_VALUE_LEN against the length the mechanism
/// itself contributes, for a KEM whose shared-secret length is fixed
/// (CKM_ML_KEM §6.68.5, vendor FrodoKEM / Classic-McEliece).
/// See the §4.1.1 rules 5/6 block above.
unsafe fn kem_check_template_value_len(
    template: *mut u8,
    count: u32,
    actual: usize,
) -> Result<(), u32> {
    match get_attr_ulong(template, count, CKA_VALUE_LEN) {
        // §4.1.1 rule 6 — same value the function contributes: behave as though
        // it had only appeared once.
        Some(want) if want as usize == actual => Ok(()),
        // §4.1.1 rule 5 — cannot be satisfied alongside the contributed
        // CKA_VALUE; §5.18.8/§5.18.9 forbid creating the key object anyway.
        Some(_) => Err(CKR_TEMPLATE_INCONSISTENT),
        None => Ok(()),
    }
}

/// ECDH-as-KEM (CKM_ECDH1_DERIVE) is the one arm where the spec makes the
/// template's CKA_VALUE_LEN an *input*, not a claim to be checked:
///
/// §6.3.17: "This mechanism derives a secret value, and truncates the result
/// according to the CKA_KEY_TYPE attribute of the template and, if it has one
/// and the key type supports it, the CKA_VALUE_LEN attribute of the template.
/// (The truncation removes bytes from the leading end of the secret value.)"
///
/// and the same section binds encapsulate/decapsulate to that very operation:
/// "For C_EncapsulateKey, an ephemeral key pair is generated. … The generated
/// private key is used with public key provided in the API to generate a
/// symmetric key using EC Derive … For C_DecapsulateKey, the ciphertext is
/// used with the private key provided in the API to generate a symmetric key
/// using EC Derive."
///
/// A length LONGER than the raw shared secret cannot be produced by truncation,
/// so it falls back to §4.1.1 rule 5 → CKR_TEMPLATE_INCONSISTENT.
/// Either way `ss.len()` is afterwards the authoritative CKA_VALUE_LEN.
unsafe fn ecdh_kem_apply_template_value_len(
    template: *mut u8,
    count: u32,
    ss: &mut Vec<u8>,
) -> Result<(), u32> {
    if let Some(want) = get_attr_ulong(template, count, CKA_VALUE_LEN) {
        let want = want as usize;
        if want > ss.len() || want == 0 {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
        // §6.3.17 — "removes bytes from the leading end of the secret value".
        ss.drain(..ss.len() - want);
    }
    Ok(())
}

fn C_EncapsulateKey_impl(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_key: u32,
    _p_template: *mut u8,
    _ul_attribute_count: u32,
    p_ciphertext: *mut u8,
    pul_ciphertext_len: *mut u32,
    ph_key: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    use ml_kem::{EncodedSizeUser, KemCore, kem::Encapsulate};

    nonnull!(p_mechanism, ph_key, pul_ciphertext_len);
    // PKCS#11 v3.2 §5.18.8 — the key must permit encapsulation.
    if let Err(rv) = check_key_usage(_h_session, h_key, CKA_ENCAPSULATE) {
        return rv;
    }
    unsafe {
        let mech_type = ck_param::mech(p_mechanism).mechanism;

        // BSI TR-02102-1 §2.4.1/§2.4.2 vendor KEMs. Delegates the actual
        // crypto to `native::encrypt::encapsulate` (shared with KMIP's
        // native API) instead of a third copy of the
        // frodo-kem/classic-mceliece-rust crate usage — unlike ML-KEM
        // below, whose C-ABI path predates that shared module and
        // reimplements the math directly.
        if mech_type == CKM_PQCTODAY_FRODOKEM_ENCAPSULATE
            || mech_type == CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE
        {
            let expected_kt = if mech_type == CKM_PQCTODAY_FRODOKEM_ENCAPSULATE {
                CKK_PQCTODAY_FRODOKEM
            } else {
                CKK_PQCTODAY_CLASSIC_MCELIECE
            };
            if get_object_attr_u32(h_key, CKA_KEY_TYPE) != Some(expected_kt) {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS. N5 remediation
            // 2026-08-13: this vendor arm returned before the shared check
            // further down, so a restricted key was never enforced here.
            if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
                return rv;
            }
            let ps = get_object_param_set(h_key);
            if ps == 0 {
                return CKR_TEMPLATE_INCOMPLETE;
            }
            let ct_len: u32 = if mech_type == CKM_PQCTODAY_FRODOKEM_ENCAPSULATE {
                match crate::native::keygen::frodokem_algorithm(ps) {
                    Ok(alg) => alg.params().ciphertext_length as u32,
                    Err(_) => return CKR_ARGUMENTS_BAD,
                }
            } else {
                if ps != CKP_CLASSIC_MCELIECE_6688128 {
                    return CKR_ARGUMENTS_BAD;
                }
                classic_mceliece_rust::CRYPTO_CIPHERTEXTBYTES as u32
            };
            if p_ciphertext.is_null() {
                *pul_ciphertext_len = ct_len;
                return CKR_OK;
            }
            if *pul_ciphertext_len < ct_len {
                *pul_ciphertext_len = ct_len;
                return CKR_BUFFER_TOO_SMALL;
            }
            let (ct, ss) = match crate::native::encrypt::encapsulate(_h_session, h_key, mech_type) {
                Ok(r) => r,
                Err(rv) => return rv,
            };
            debug_assert_eq!(ct.len(), ct_len as usize, "ct_len must match the actual ciphertext");
            std::ptr::copy_nonoverlapping(ct.as_ptr(), p_ciphertext, ct_len as usize);
            *pul_ciphertext_len = ct_len;
            // PKCS#11 v3.2 §4.1.1 rules 5/6 (see kem_check_template_value_len):
            // a caller CKA_VALUE_LEN that contradicts the mechanism-contributed
            // CKA_VALUE is CKR_TEMPLATE_INCONSISTENT, before any key object exists.
            if let Err(rv) =
                kem_check_template_value_len(_p_template, _ul_attribute_count, ss.len())
            {
                return rv;
            }
            let ss_len = ss.len() as u32;
            let mut ss_attrs = HashMap::new();
            ss_attrs.insert(CKA_VALUE, ss);
            store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
            store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
            store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
            store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
            store_bool(&mut ss_attrs, CKA_TOKEN, false); // PKCS#11 v3.2 §4.1 default
            store_bool(&mut ss_attrs, CKA_PRIVATE, false); // PKCS#11 v3.2 §4.1 default
            store_bool(&mut ss_attrs, CKA_LOCAL, false); // PKCS#11 v3.2 §5.18.8 — KEM keys are not locally generated
            store_ulong(&mut ss_attrs, CKA_KEY_GEN_MECHANISM, mech_type); // PKCS#11 v3.2 §4.3
            absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
            // §6.8.2 Table 103 — CKA_VALUE_LEN is "Length in bytes of key
            // value", so it is engine truth and is written AFTER absorb: it can
            // never be made to contradict CKA_VALUE by a caller template.
            store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss_len);
            // PKCS#11 v3.2 §5.18.8: unconditionally CK_FALSE for encapsulated keys
            store_bool(&mut ss_attrs, CKA_ALWAYS_SENSITIVE, false);
            store_bool(&mut ss_attrs, CKA_NEVER_EXTRACTABLE, false);
            // S11 (2026-08-13) — §4.11: the check value SHALL be supplied on
            // every created key, and a caller-supplied value MUST be compared,
            // not silently dropped. The KEM paths computed neither.
            if let Err(rv) = crate::state::apply_check_value_policy(
                &mut ss_attrs,
                find_template_entry(_p_template, _ul_attribute_count, CKA_CHECK_VALUE).as_deref(),
            ) {
                return rv;
            }
            *ph_key = allocate_handle_owned(_h_session, ss_attrs);
            return CKR_OK;
        }

        // ── ECDH-as-KEM (PKCS#11 v3.2 §6.3.17 Table 78) ─────────────────────
        // 2026-08-13 parity with the C++ engine's encapsulateECDH
        // (SoftHSM_kem.cpp): the "ciphertext" is a fresh ephemeral public EC
        // point, byte-identical to the C++ wire form (DER OCTET STRING
        // wrapping the uncompressed SEC1 point — the CKA_EC_POINT encoding);
        // the shared secret is the raw ECDH X coordinate, no KDF (combining
        // is the CALLER's job, e.g. CKM_CONCATENATE_BASE_AND_KEY — same
        // "DHKEM" ephemeral-static pattern as native/hybrid.rs).
        if mech_type == CKM_ECDH1_DERIVE {
            // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS (N5).
            if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
                return rv;
            }
            // V-09 (divergence report, 2026-08-13) — Table 78 lists
            // CKK_EC_MONTGOMERY for this mechanism under C_EncapsulateKey /
            // C_DecapsulateKey. The engine advertised the encapsulate flags on
            // CKM_ECDH1_DERIVE but accepted only CKK_EC, so the advertised
            // capability was partly untrue; accepting is preferred over
            // dropping the flags.
            let key_type = get_object_attr_u32(h_key, CKA_KEY_TYPE);
            if key_type != Some(CKK_EC) && key_type != Some(CKK_EC_MONTGOMERY) {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            let curve = if key_type == Some(CKK_EC_MONTGOMERY) {
                match get_object_attr_bytes(h_key, CKA_EC_PARAMS)
                    .map(|p| crate::crypto::handlers::decode_ec_params(&p))
                {
                    Some(Ok(c)) => c,
                    Some(Err(rv)) => return rv,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                }
            } else {
                get_object_param_set(h_key)
            };
            // E1 (2026-08-13) — §6.3.17: "an ephemeral key pair is generated.
            // The value of the generated public key is returned as the
            // ciphertext", and that value "has the same format as the public
            // key used in C_DeriveKey" — which is specified as "a token MUST
            // be able to accept this value encoded as a raw octet string … A
            // token MAY, in addition, support accepting this value as a
            // DER-encoded ECPoint." For Montgomery keys "the public key is
            // provided as bytes in little endian order" and there is no DER
            // option at all.
            //
            // Both engines emitted the DER-wrapped form — P-256 at 67 bytes
            // where 65 are mandated. Mutual agreement is not a defence; the
            // spec footnotes precisely this hazard ("The encoding in V2.20
            // was not specified and resulted in different implementations
            // choosing different encodings"). The tolerant READER on
            // decapsulation stays, which is correct practice and keeps
            // anything already deployed working.
            let ct_len: u32 = match curve {
                CURVE_P256 => 65,
                CURVE_P384 => 97,
                CURVE_P521 => 133,
                CURVE_X25519 => 32,
                CURVE_X448 => 56,
                // secp256k1-as-KEM is not offered (the C++ mirror covers the
                // NIST prime curves; this arm adds the Montgomery curves
                // Table 78 lists).
                _ => return CKR_CURVE_NOT_SUPPORTED,
            };
            if p_ciphertext.is_null() {
                *pul_ciphertext_len = ct_len;
                return CKR_OK;
            }
            if *pul_ciphertext_len < ct_len {
                *pul_ciphertext_len = ct_len;
                return CKR_BUFFER_TOO_SMALL;
            }
            // Peer static public point (CKA_EC_POINT is DER-wrapped; raw
            // SEC1 tolerated, mirroring the C++ getECDHPubData).
            let peer_point_attr = match get_object_attr_bytes(h_key, CKA_EC_POINT) {
                Some(v) => v,
                None => return CKR_ARGUMENTS_BAD,
            };
            let peer_point = ec_point_unwrap(&peer_point_attr);
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            macro_rules! ecdh_encap {
                ($c:ident, $rng:expr) => {{
                    let peer = match $c::PublicKey::from_sec1_bytes(peer_point) {
                        Ok(pk) => pk,
                        Err(_) => return CKR_ARGUMENTS_BAD,
                    };
                    // §6.3.17: one fresh ephemeral pair per encapsulation.
                    let eph = $c::SecretKey::random($rng);
                    let eph_pub = eph.public_key().to_encoded_point(false);
                    let ss =
                        $c::ecdh::diffie_hellman(eph.to_nonzero_scalar(), peer.as_affine());
                    // E1 — RAW ephemeral public key, not DER.
                    (
                        eph_pub.as_bytes().to_vec(),
                        ss.raw_secret_bytes().to_vec(),
                    )
                }};
            }
            let (ct, mut ss) = with_rng!(rng, {
                match curve {
                    CURVE_P256 => ecdh_encap!(p256, &mut rng),
                    CURVE_P384 => ecdh_encap!(p384, &mut rng),
                    CURVE_P521 => ecdh_encap!(p521, &mut rng),
                    // V-09 — Montgomery: the peer public and the emitted
                    // ephemeral are both bare little-endian bytes (§6.3.10),
                    // so there is no encoding to strip or add.
                    CURVE_X25519 => {
                        let peer: [u8; 32] = match peer_point.try_into() {
                            Ok(p) => p,
                            Err(_) => return CKR_ARGUMENTS_BAD,
                        };
                        let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
                        let eph_pub = x25519_dalek::PublicKey::from(&eph);
                        let ss = eph.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
                        (eph_pub.as_bytes().to_vec(), ss.as_bytes().to_vec())
                    }
                    CURVE_X448 => {
                        let peer: [u8; 56] = match peer_point.try_into() {
                            Ok(p) => p,
                            Err(_) => return CKR_ARGUMENTS_BAD,
                        };
                        let mut eph_sk = [0u8; 56];
                        if getrandom::getrandom(&mut eph_sk).is_err() {
                            return CKR_FUNCTION_FAILED;
                        }
                        let sk = x448::StaticSecret::from(eph_sk);
                        let eph_pub = x448::PublicKey::from(&sk);
                        let ss = match x448::x448(eph_sk, peer) {
                            Some(v) => v.to_vec(),
                            None => return CKR_ARGUMENTS_BAD,
                        };
                        (eph_pub.as_bytes().to_vec(), ss)
                    }
                    _ => return CKR_CURVE_NOT_SUPPORTED,
                }
            });
            debug_assert_eq!(ct.len(), ct_len as usize, "ct_len must match the emitted point");
            std::ptr::copy_nonoverlapping(ct.as_ptr(), p_ciphertext, ct.len());
            *pul_ciphertext_len = ct.len() as u32;
            // §6.3.17 — for this mechanism (unlike the fixed-length KEMs above)
            // the template's CKA_VALUE_LEN is a truncation request, applied
            // from the leading end of the secret value.
            if let Err(rv) =
                ecdh_kem_apply_template_value_len(_p_template, _ul_attribute_count, &mut ss)
            {
                return rv;
            }
            let ss_len = ss.len() as u32;
            let mut ss_attrs = HashMap::new();
            ss_attrs.insert(CKA_VALUE, ss);
            store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
            store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
            store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
            store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
            store_bool(&mut ss_attrs, CKA_TOKEN, false); // PKCS#11 v3.2 §4.1 default
            store_bool(&mut ss_attrs, CKA_PRIVATE, false); // PKCS#11 v3.2 §4.1 default
            store_bool(&mut ss_attrs, CKA_LOCAL, false); // §5.18.8 — KEM keys are not locally generated
            store_ulong(&mut ss_attrs, CKA_KEY_GEN_MECHANISM, CKM_ECDH1_DERIVE); // §4.3
            absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
            // §6.8.2 Table 103 — CKA_VALUE_LEN is the length of the (possibly
            // truncated) CKA_VALUE; written AFTER absorb so it always agrees.
            store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss_len);
            // PKCS#11 v3.2 §5.18.8: unconditionally CK_FALSE for encapsulated keys
            store_bool(&mut ss_attrs, CKA_ALWAYS_SENSITIVE, false);
            store_bool(&mut ss_attrs, CKA_NEVER_EXTRACTABLE, false);
            // S11 (2026-08-13) — §4.11: the check value SHALL be supplied on
            // every created key, and a caller-supplied value MUST be compared,
            // not silently dropped. The KEM paths computed neither.
            if let Err(rv) = crate::state::apply_check_value_policy(
                &mut ss_attrs,
                find_template_entry(_p_template, _ul_attribute_count, CKA_CHECK_VALUE).as_deref(),
            ) {
                return rv;
            }
            *ph_key = allocate_handle_owned(_h_session, ss_attrs);
            return CKR_OK;
        }

        if mech_type != CKM_ML_KEM {
            return CKR_MECHANISM_INVALID;
        }
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS.
        if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
            return rv;
        }

        // PKCS#11 v3.2 §5.18.8 — CKM_ML_KEM requires an ML-KEM key
        // (compliance-audit P-10).
        if get_object_attr_u32(h_key, CKA_KEY_TYPE) != Some(CKK_ML_KEM) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        let ps = get_object_param_set(h_key);
        // P-10: no silent ML-KEM-768 default — a key without
        // CKA_PARAMETER_SET is an incomplete object.
        if ps == 0 {
            return CKR_TEMPLATE_INCOMPLETE;
        }
        let ct_len: u32 = match ps {
            CKP_ML_KEM_512 => 768,
            CKP_ML_KEM_768 => 1088,
            CKP_ML_KEM_1024 => 1568,
            _ => return CKR_ARGUMENTS_BAD,
        };
        if p_ciphertext.is_null() {
            *pul_ciphertext_len = ct_len;
            return CKR_OK;
        }
        if *pul_ciphertext_len < ct_len {
            *pul_ciphertext_len = ct_len;
            return CKR_BUFFER_TOO_SMALL;
        }

        let pub_key_bytes = match crate::state::get_key_material(h_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        macro_rules! encap {
            ($kem:ty, $rng:expr) => {{
                let ek_enc = match ml_kem::array::Array::try_from(pub_key_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let ek = <$kem as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
                let (ct, ss) = match Encapsulate::encapsulate(&ek, $rng) {
                    Ok(r) => r,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                std::ptr::copy_nonoverlapping(
                    ct.as_slice().as_ptr(),
                    p_ciphertext,
                    ct_len as usize,
                );
                *pul_ciphertext_len = ct_len;
                // §6.68.5 gives CKM_ML_KEM no length knob — §4.1.1 rules 5/6.
                if let Err(rv) = kem_check_template_value_len(
                    _p_template,
                    _ul_attribute_count,
                    ss.as_slice().len(),
                ) {
                    return rv;
                }
                let mut ss_attrs = HashMap::new();
                ss_attrs.insert(CKA_VALUE, ss.as_slice().to_vec());
                store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
                store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
                store_bool(&mut ss_attrs, CKA_TOKEN, false);   // PKCS#11 v3.2 §4.1 default
                store_bool(&mut ss_attrs, CKA_PRIVATE, false); // PKCS#11 v3.2 §4.1 default
                store_bool(&mut ss_attrs, CKA_LOCAL, false); // PKCS#11 v3.2 §5.18.8 — KEM keys are not locally generated
                store_ulong(&mut ss_attrs, CKA_KEY_GEN_MECHANISM, CKM_ML_KEM); // PKCS#11 v3.2 §4.3
                absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
                // §6.8.2 Table 103 — engine truth, written AFTER absorb.
                store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss.as_slice().len() as u32);
                // PKCS#11 v3.2 §5.18.8: unconditionally CK_FALSE for encapsulated keys
                store_bool(&mut ss_attrs, CKA_ALWAYS_SENSITIVE, false);
                store_bool(&mut ss_attrs, CKA_NEVER_EXTRACTABLE, false);
                // S11 (2026-08-13) — §4.11: the check value SHALL be supplied on
                // every created key, and a caller-supplied value MUST be compared,
                // not silently dropped. The KEM paths computed neither.
                if let Err(rv) = crate::state::apply_check_value_policy(
                    &mut ss_attrs,
                    find_template_entry(_p_template, _ul_attribute_count, CKA_CHECK_VALUE).as_deref(),
                ) {
                    return rv;
                }
                *ph_key = allocate_handle_owned(_h_session, ss_attrs);
            }};
        }

        with_rng!(rng, {
            match ps {
                CKP_ML_KEM_512 => encap!(ml_kem::MlKem512, &mut rng),
                CKP_ML_KEM_768 => encap!(ml_kem::MlKem768, &mut rng),
                CKP_ML_KEM_1024 => encap!(ml_kem::MlKem1024, &mut rng),
                _ => return CKR_ARGUMENTS_BAD,
            }
        });
    }
    CKR_OK
}

fn C_DecapsulateKey_impl(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_private_key: u32,
    _p_template: *mut u8,
    _ul_attribute_count: u32,
    p_ciphertext: *mut u8,
    ul_ciphertext_len: u32,
    ph_key: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    use ml_kem::{EncodedSizeUser, KemCore, kem::Decapsulate};

    nonnull!(p_mechanism, p_ciphertext, ph_key);
    // PKCS#11 v3.2 §5.18.9 — the key must permit decapsulation.
    if let Err(rv) = check_key_usage(_h_session, h_private_key, CKA_DECAPSULATE) {
        return rv;
    }
    unsafe {
        let mech_type = ck_param::mech(p_mechanism).mechanism;

        // BSI TR-02102-1 §2.4.1/§2.4.2 vendor KEMs — mirrors
        // `C_EncapsulateKey`'s delegation to `native::encrypt::decapsulate`.
        if mech_type == CKM_PQCTODAY_FRODOKEM_ENCAPSULATE
            || mech_type == CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE
        {
            let expected_kt = if mech_type == CKM_PQCTODAY_FRODOKEM_ENCAPSULATE {
                CKK_PQCTODAY_FRODOKEM
            } else {
                CKK_PQCTODAY_CLASSIC_MCELIECE
            };
            if get_object_attr_u32(h_private_key, CKA_KEY_TYPE) != Some(expected_kt) {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS. N5 remediation
            // 2026-08-13: this vendor arm returned before the shared check
            // further down, so a restricted key was never enforced here.
            if let Err(rv) = check_mechanism_allowed(h_private_key, mech_type) {
                return rv;
            }
            let ps = get_object_param_set(h_private_key);
            if ps == 0 {
                return CKR_TEMPLATE_INCOMPLETE;
            }
            let expected_ct: u32 = if mech_type == CKM_PQCTODAY_FRODOKEM_ENCAPSULATE {
                match crate::native::keygen::frodokem_algorithm(ps) {
                    Ok(alg) => alg.params().ciphertext_length as u32,
                    Err(_) => return CKR_ARGUMENTS_BAD,
                }
            } else {
                if ps != CKP_CLASSIC_MCELIECE_6688128 {
                    return CKR_ARGUMENTS_BAD;
                }
                classic_mceliece_rust::CRYPTO_CIPHERTEXTBYTES as u32
            };
            // PKCS#11 v3.2 §5.18.9 — a ciphertext of the wrong length for the
            // key's parameter set is invalid input ciphertext.
            if ul_ciphertext_len != expected_ct {
                return CKR_ENCRYPTED_DATA_INVALID;
            }
            if p_ciphertext.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            let ct_bytes =
                std::slice::from_raw_parts(p_ciphertext, ul_ciphertext_len as usize).to_vec();
            let ss = match crate::native::encrypt::decapsulate(
                _h_session,
                h_private_key,
                mech_type,
                &ct_bytes,
            ) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            // §4.1.1 rules 5/6 — reject a contradicting caller CKA_VALUE_LEN.
            if let Err(rv) =
                kem_check_template_value_len(_p_template, _ul_attribute_count, ss.len())
            {
                return rv;
            }
            let ss_len = ss.len() as u32;
            let mut ss_attrs = HashMap::new();
            ss_attrs.insert(CKA_VALUE, ss);
            store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
            store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
            store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
            store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
            store_bool(&mut ss_attrs, CKA_TOKEN, false); // PKCS#11 v3.2 §4.1 default
            store_bool(&mut ss_attrs, CKA_PRIVATE, false); // PKCS#11 v3.2 §4.1 default
            store_bool(&mut ss_attrs, CKA_LOCAL, false); // PKCS#11 v3.2 §5.18.9 — KEM keys are not locally generated
            store_ulong(&mut ss_attrs, CKA_KEY_GEN_MECHANISM, mech_type); // PKCS#11 v3.2 §4.3
            absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
            // §6.8.2 Table 103 — "Length in bytes of key value". This stored the
            // CIPHERTEXT length (`expected_ct`) until 2026-08-13: FrodoKEM-640
            // reported CKA_VALUE_LEN = 9720 for a 16-byte CKA_VALUE. Engine
            // truth, and written AFTER absorb so no template can override it.
            store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss_len);
            // PKCS#11 v3.2 §5.18.9: unconditionally CK_FALSE for decapsulated keys
            store_bool(&mut ss_attrs, CKA_ALWAYS_SENSITIVE, false);
            store_bool(&mut ss_attrs, CKA_NEVER_EXTRACTABLE, false);
            // S11 (2026-08-13) — §4.11: the check value SHALL be supplied on
            // every created key, and a caller-supplied value MUST be compared,
            // not silently dropped. The KEM paths computed neither.
            if let Err(rv) = crate::state::apply_check_value_policy(
                &mut ss_attrs,
                find_template_entry(_p_template, _ul_attribute_count, CKA_CHECK_VALUE).as_deref(),
            ) {
                return rv;
            }
            *ph_key = allocate_handle_owned(_h_session, ss_attrs);
            return CKR_OK;
        }

        // ── ECDH-as-KEM (PKCS#11 v3.2 §6.3.17 Table 78) ─────────────────────
        // 2026-08-13 parity with the C++ engine's decapsulateECDH
        // (SoftHSM_kem.cpp): the ciphertext is the encapsulator's ephemeral
        // public EC point (DER-wrapped or raw SEC1, both accepted); the
        // shared secret is the raw ECDH X coordinate of static-scalar ×
        // ephemeral-point, no KDF.
        if mech_type == CKM_ECDH1_DERIVE {
            // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS (N5).
            if let Err(rv) = check_mechanism_allowed(h_private_key, mech_type) {
                return rv;
            }
            // V-09 — Table 78 lists CKK_EC_MONTGOMERY here too.
            let key_type = get_object_attr_u32(h_private_key, CKA_KEY_TYPE);
            if key_type != Some(CKK_EC) && key_type != Some(CKK_EC_MONTGOMERY) {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            let curve = if key_type == Some(CKK_EC_MONTGOMERY) {
                match get_object_attr_bytes(h_private_key, CKA_EC_PARAMS)
                    .map(|p| crate::crypto::handlers::decode_ec_params(&p))
                {
                    Some(Ok(c)) => c,
                    Some(Err(rv)) => return rv,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                }
            } else {
                get_object_param_set(h_private_key)
            };
            let scalar = match get_object_value(h_private_key) {
                Some(v) => v,
                None => return CKR_ARGUMENTS_BAD,
            };
            let ct_bytes =
                std::slice::from_raw_parts(p_ciphertext, ul_ciphertext_len as usize);
            let peer_point = ec_point_unwrap(ct_bytes);
            macro_rules! ecdh_decap {
                ($c:ident) => {{
                    let sk = match $c::NonZeroScalar::try_from(scalar.as_slice()) {
                        Ok(s) => s,
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    };
                    let peer = match $c::PublicKey::from_sec1_bytes(peer_point) {
                        Ok(pk) => pk,
                        // §5.18.9 — an undecodable point is invalid input
                        // ciphertext (this file's ML-KEM convention).
                        Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
                    };
                    $c::ecdh::diffie_hellman(&sk, peer.as_affine())
                        .raw_secret_bytes()
                        .to_vec()
                }};
            }
            let mut ss = match curve {
                CURVE_P256 => ecdh_decap!(p256),
                CURVE_P384 => ecdh_decap!(p384),
                CURVE_P521 => ecdh_decap!(p521),
                // V-09 — Montgomery: bare little-endian bytes both ways.
                // E1 keeps the TOLERANT READER on this side, which for
                // Montgomery means accepting the historical DER-wrapped
                // form as well as the raw 32/56 bytes the spec mandates
                // (ec_point_unwrap above already normalises it).
                CURVE_X25519 => {
                    let sk: [u8; 32] = match scalar.as_slice().try_into() {
                        Ok(v) => v,
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    };
                    let peer: [u8; 32] = match peer_point.try_into() {
                        Ok(v) => v,
                        Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
                    };
                    x25519_dalek::StaticSecret::from(sk)
                        .diffie_hellman(&x25519_dalek::PublicKey::from(peer))
                        .as_bytes()
                        .to_vec()
                }
                CURVE_X448 => {
                    let sk: [u8; 56] = match scalar.as_slice().try_into() {
                        Ok(v) => v,
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    };
                    let peer: [u8; 56] = match peer_point.try_into() {
                        Ok(v) => v,
                        Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
                    };
                    match x448::x448(sk, peer) {
                        Some(v) => v.to_vec(),
                        None => return CKR_ENCRYPTED_DATA_INVALID,
                    }
                }
                _ => return CKR_CURVE_NOT_SUPPORTED,
            };
            // §6.3.17 — template CKA_VALUE_LEN truncates from the leading end
            // (mirrors the encapsulate side so both peers get the same key).
            if let Err(rv) =
                ecdh_kem_apply_template_value_len(_p_template, _ul_attribute_count, &mut ss)
            {
                return rv;
            }
            let ss_len = ss.len() as u32;
            let mut ss_attrs = HashMap::new();
            ss_attrs.insert(CKA_VALUE, ss);
            store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
            store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
            store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
            store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
            store_bool(&mut ss_attrs, CKA_TOKEN, false); // PKCS#11 v3.2 §4.1 default
            store_bool(&mut ss_attrs, CKA_PRIVATE, false); // PKCS#11 v3.2 §4.1 default
            store_bool(&mut ss_attrs, CKA_LOCAL, false); // §5.18.9 — KEM keys are not locally generated
            store_ulong(&mut ss_attrs, CKA_KEY_GEN_MECHANISM, CKM_ECDH1_DERIVE); // §4.3
            absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
            // §6.8.2 Table 103 — engine truth, written AFTER absorb.
            store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss_len);
            // PKCS#11 v3.2 §5.18.9: unconditionally CK_FALSE for decapsulated keys
            store_bool(&mut ss_attrs, CKA_ALWAYS_SENSITIVE, false);
            store_bool(&mut ss_attrs, CKA_NEVER_EXTRACTABLE, false);
            // S11 (2026-08-13) — §4.11: the check value SHALL be supplied on
            // every created key, and a caller-supplied value MUST be compared,
            // not silently dropped. The KEM paths computed neither.
            if let Err(rv) = crate::state::apply_check_value_policy(
                &mut ss_attrs,
                find_template_entry(_p_template, _ul_attribute_count, CKA_CHECK_VALUE).as_deref(),
            ) {
                return rv;
            }
            *ph_key = allocate_handle_owned(_h_session, ss_attrs);
            return CKR_OK;
        }

        if mech_type != CKM_ML_KEM {
            return CKR_MECHANISM_INVALID;
        }
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS.
        if let Err(rv) = check_mechanism_allowed(h_private_key, mech_type) {
            return rv;
        }

        // PKCS#11 v3.2 §5.18.9 — CKM_ML_KEM requires an ML-KEM key
        // (compliance-audit P-10).
        if get_object_attr_u32(h_private_key, CKA_KEY_TYPE) != Some(CKK_ML_KEM) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        let ps = get_object_param_set(h_private_key);
        // P-10: no silent ML-KEM-768 default — a key without
        // CKA_PARAMETER_SET is an incomplete object.
        if ps == 0 {
            return CKR_TEMPLATE_INCOMPLETE;
        }
        let expected_ct: u32 = match ps {
            CKP_ML_KEM_512 => 768,
            CKP_ML_KEM_768 => 1088,
            CKP_ML_KEM_1024 => 1568,
            _ => return CKR_ARGUMENTS_BAD,
        };
        // PKCS#11 v3.2 §5.18.9 — a ciphertext of the wrong length for the
        // key's parameter set is invalid input ciphertext.
        if ul_ciphertext_len != expected_ct {
            return CKR_ENCRYPTED_DATA_INVALID;
        }

        let prv_key_bytes = match get_object_value(h_private_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        if p_ciphertext.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let ct_bytes =
            std::slice::from_raw_parts(p_ciphertext, ul_ciphertext_len as usize).to_vec();

        macro_rules! decap {
            ($kem:ty) => {{
                let dk_enc = match ml_kem::array::Array::try_from(prv_key_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let dk = <$kem as KemCore>::DecapsulationKey::from_bytes(&dk_enc);
                let ct_enc = match ml_kem::array::Array::try_from(ct_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(_) => return CKR_ARGUMENTS_BAD,
                };
                let ss = match Decapsulate::decapsulate(&dk, &ct_enc) {
                    Ok(s) => s,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                // §6.68.5 gives CKM_ML_KEM no length knob — §4.1.1 rules 5/6.
                if let Err(rv) = kem_check_template_value_len(
                    _p_template,
                    _ul_attribute_count,
                    ss.as_slice().len(),
                ) {
                    return rv;
                }
                let mut ss_attrs = HashMap::new();
                ss_attrs.insert(CKA_VALUE, ss.as_slice().to_vec());
                store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
                store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
                store_bool(&mut ss_attrs, CKA_TOKEN, false);   // PKCS#11 v3.2 §4.1 default
                store_bool(&mut ss_attrs, CKA_PRIVATE, false); // PKCS#11 v3.2 §4.1 default
                store_bool(&mut ss_attrs, CKA_LOCAL, false); // PKCS#11 v3.2 §5.18.9 — KEM keys are not locally generated
                store_ulong(&mut ss_attrs, CKA_KEY_GEN_MECHANISM, CKM_ML_KEM); // PKCS#11 v3.2 §4.3
                absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
                // §6.8.2 Table 103 — engine truth, written AFTER absorb.
                store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss.as_slice().len() as u32);
                // PKCS#11 v3.2 §5.18.9: unconditionally CK_FALSE for decapsulated keys
                store_bool(&mut ss_attrs, CKA_ALWAYS_SENSITIVE, false);
                store_bool(&mut ss_attrs, CKA_NEVER_EXTRACTABLE, false);
                // S11 (2026-08-13) — §4.11: the check value SHALL be supplied on
                // every created key, and a caller-supplied value MUST be compared,
                // not silently dropped. The KEM paths computed neither.
                if let Err(rv) = crate::state::apply_check_value_policy(
                    &mut ss_attrs,
                    find_template_entry(_p_template, _ul_attribute_count, CKA_CHECK_VALUE).as_deref(),
                ) {
                    return rv;
                }
                *ph_key = allocate_handle_owned(_h_session, ss_attrs);
            }};
        }

        match ps {
            CKP_ML_KEM_512 => decap!(ml_kem::MlKem512),
            CKP_ML_KEM_768 => decap!(ml_kem::MlKem768),
            CKP_ML_KEM_1024 => decap!(ml_kem::MlKem1024),
            _ => return CKR_ARGUMENTS_BAD,
        }
    }
    CKR_OK
}

// ── Object Operations ────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GetAttributeValue)]
pub fn C_GetAttributeValue(h_session: u32, h_object: u32, p_template: *mut u8, count: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    if p_template.is_null() && count > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let attrs = OBJECTS.with(|o| o.borrow().get(&h_object).cloned());
    if let Some(obj_attrs) = attrs {
        // PKCS#11 v3.2 §4.4 — a private object is not visible (its handle is
        // treated as invalid) to a session whose token is not logged in.
        if !crate::state::can_access_object(h_session, &obj_attrs) {
            return CKR_OBJECT_HANDLE_INVALID;
        }
        // PKCS#11 v3.2 §4.7: CKA_VALUE access restrictions apply only to private and
        // secret keys. Public keys (CKO_PUBLIC_KEY) are always fully readable.
        let class = obj_attrs
            .get(&CKA_CLASS)
            .filter(|v| v.len() >= 4)
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
            .unwrap_or(CKO_PUBLIC_KEY);
        let is_private_or_secret = class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY;
        let sensitive = is_private_or_secret && read_bool_attr(&obj_attrs, CKA_SENSITIVE);
        let extractable = !is_private_or_secret || read_bool_attr(&obj_attrs, CKA_EXTRACTABLE);
        // PKCS#11 v3.2 §5.7.5 — process EVERY template entry, recording each
        // failure class, then return one consolidated code. The whole template
        // is filled in regardless of any single entry's failure.
        let mut had_missing = false;
        let mut had_sensitive = false;
        let mut had_small = false;
        unsafe {
            let tmpl_ptr = p_template as *mut usize;
            for i in 0..count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize) as u32;
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as *mut u8;
                let val_len_ptr = tmpl_ptr.add((i * 3 + 2) as usize); // *mut usize (native width)
                // Block CKA_VALUE / CKA_SEED (raw secret material — see
                // state::attr_is_sensitive_material) for sensitive or
                // non-extractable private/secret keys → CKR_ATTRIBUTE_SENSITIVE.
                //
                // The `contains_key` guard is load-bearing. §5.7.5 gives the
                // two codes different meanings: CKR_ATTRIBUTE_TYPE_INVALID is
                // for when "the object does not possess such an attribute",
                // CKR_ATTRIBUTE_SENSITIVE for one the object HAS and will not
                // disclose. Without the guard this engine answered
                // CKR_ATTRIBUTE_SENSITIVE for attributes an object does not
                // have at all — CKA_SEED on EC, Edwards, Montgomery, XMSS and
                // AES keys (§6.67.4/§6.68.4 define it for ML-DSA and ML-KEM
                // only), and the RSA CRT attributes on every non-RSA private
                // key (Table 38 defines them for RSA only). That is not merely
                // the wrong code: it tells a caller the object holds a secret
                // it may not read, when the object holds nothing of the kind.
                // Forty-one observations in the differential harness, against
                // C++'s correct CKR_ATTRIBUTE_TYPE_INVALID.
                if attr_is_sensitive_material(attr_type)
                    && (sensitive || !extractable)
                    && obj_attrs.contains_key(&attr_type)
                {
                    *val_len_ptr = usize::MAX; // CK_UNAVAILABLE_INFORMATION (native width)
                    had_sensitive = true;
                    continue;
                }
                if let Some(val) = obj_attrs.get(&attr_type) {
                    if val_ptr.is_null() {
                        *val_len_ptr = val.len();
                    } else if *val_len_ptr >= val.len() {
                        std::ptr::copy_nonoverlapping(val.as_ptr(), val_ptr, val.len());
                        *val_len_ptr = val.len();
                    } else {
                        // §5.7.5 — record, set length, keep processing the rest.
                        *val_len_ptr = val.len();
                        had_small = true;
                    }
                } else {
                    // §5.7.5 — attribute not present → CK_UNAVAILABLE_INFORMATION.
                    *val_len_ptr = usize::MAX;
                    had_missing = true;
                }
            }
        }
        // §5.7.5 precedence — sensitive/unextractable first, then invalid type,
        // then buffer-too-small.
        if had_sensitive {
            CKR_ATTRIBUTE_SENSITIVE
        } else if had_missing {
            CKR_ATTRIBUTE_TYPE_INVALID
        } else if had_small {
            CKR_BUFFER_TOO_SMALL
        } else {
            CKR_OK
        }
    } else {
        // PKCS#11 v3.2 §5.7.5 — unknown object handle.
        CKR_OBJECT_HANDLE_INVALID
    }
}

/// PKCS#11 v3.2 §4.1.1/§5.7 — validate a C_CreateObject template.
fn validate_create_template(attrs: &Attributes) -> Result<(), u32> {
    let read_u32 = |t: u32| -> Option<u32> {
        attrs
            .get(&t)
            .filter(|v| v.len() >= 4)
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    };
    // CKA_CLASS is required on every object (§4.1.1). Its absence used to
    // silently default to CKO_PUBLIC_KEY, which let an imported secret key
    // bypass the CKA_VALUE sensitivity gate.
    let class = match attrs.get(&CKA_CLASS) {
        None => return Err(CKR_TEMPLATE_INCOMPLETE),
        Some(v) if v.len() < 4 => return Err(CKR_ATTRIBUTE_VALUE_INVALID),
        Some(_) => read_u32(CKA_CLASS).unwrap(),
    };
    // PKCS#11 Profiles v3.2 §3 — CKO_PROFILE identity is entirely
    // token-computed (state::init_profile_objects, at slot creation); a
    // client-supplied one is never valid, mirroring how CREATE_READ_ONLY
    // below rejects other token-computed attributes.
    if class == CKO_PROFILE {
        return Err(CKR_ATTRIBUTE_READ_ONLY);
    }
    // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS is a packed CK_MECHANISM_TYPE[];
    // a length that isn't a whole number of entries is malformed. S9: the
    // element width is the exported ABI's (state::MECHANISM_TYPE_SIZE), the
    // same constant the parser and the mutation gate use.
    if let Some(v) = attrs.get(&CKA_ALLOWED_MECHANISMS) {
        if v.len() % crate::state::MECHANISM_TYPE_SIZE != 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    if class == CKO_CERTIFICATE {
        // §4.6.1 Table 19 footnote 1 — CKA_CERTIFICATE_TYPE MUST be
        // specified when the object is created.
        let cert_type = match read_u32(CKA_CERTIFICATE_TYPE) {
            None => return Err(CKR_TEMPLATE_INCOMPLETE),
            Some(t) => t,
        };
        // X.509 only — CKC_X_509_ATTR_CERT (§4.6.5) and CKC_WTLS (§4.6.4)
        // are recognized but not implemented (no consumer in this
        // workspace, no KMIP 3.0 counterpart).
        if cert_type != CKC_X_509 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        // §4.6.3 Table 20 footnote 1 — CKA_SUBJECT MUST be specified for
        // an X.509 certificate.
        if !attrs.contains_key(&CKA_SUBJECT) {
            return Err(CKR_TEMPLATE_INCOMPLETE);
        }
        // §4.6.3 Table 20 footnotes 2-6 — at least one of CKA_VALUE /
        // CKA_URL must be present and non-empty; if CKA_URL is used
        // instead of an inline CKA_VALUE, both public-key hash
        // attributes must accompany it so the cert can still be
        // identified/verified without fetching it.
        let non_empty = |t: u32| attrs.get(&t).is_some_and(|v| !v.is_empty());
        let has_value = non_empty(CKA_VALUE);
        let has_url = non_empty(CKA_URL);
        if !has_value && !has_url {
            return Err(CKR_TEMPLATE_INCOMPLETE);
        }
        if has_url
            && !has_value
            && (!non_empty(CKA_HASH_OF_SUBJECT_PUBLIC_KEY) || !non_empty(CKA_HASH_OF_ISSUER_PUBLIC_KEY))
        {
            return Err(CKR_TEMPLATE_INCOMPLETE);
        }
        // §4.6 Table 19 footnote — CKA_TRUSTED on a certificate can only
        // be set to CK_TRUE by the SO user. Session role isn't visible
        // here (this function is attribute-shape-only); the caller
        // (ffi::C_CreateObject) enforces this before calling in.
        return Ok(());
    }
    let is_key_class =
        class == CKO_SECRET_KEY || class == CKO_PUBLIC_KEY || class == CKO_PRIVATE_KEY;
    if !is_key_class {
        // CKO_DATA / certificates / vendor classes — no key-specific rules.
        return Ok(());
    }
    // Key objects require CKA_KEY_TYPE (§4.7).
    let key_type = match read_u32(CKA_KEY_TYPE) {
        None => return Err(CKR_TEMPLATE_INCOMPLETE),
        Some(kt) => kt,
    };
    // KEY_TYPE ↔ CLASS consistency (§4.1.1 — CKR_TEMPLATE_INCONSISTENT).
    let secret_only = key_type == CKK_AES || key_type == CKK_GENERIC_SECRET
        || key_type == 0x33 /* CKK_CHACHA20 */;
    let asym_only = key_type == CKK_RSA
        || key_type == CKK_EC
        || key_type == CKK_EC_EDWARDS
        || key_type == CKK_EC_MONTGOMERY
        || key_type == CKK_ML_KEM
        || key_type == CKK_ML_DSA
        || key_type == CKK_SLH_DSA
        || key_type == CKK_HSS
        || key_type == CKK_XMSS
        || key_type == CKK_XMSSMT;
    if secret_only && class != CKO_SECRET_KEY {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    if asym_only && class == CKO_SECRET_KEY {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    // Required key material per class/type (§4.7+ tables).
    if class == CKO_SECRET_KEY {
        let val = attrs.get(&CKA_VALUE).ok_or(CKR_TEMPLATE_INCOMPLETE)?;
        if val.is_empty() {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        if key_type == CKK_AES && !matches!(val.len(), 16 | 24 | 32) {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    } else if class == CKO_PUBLIC_KEY && key_type == CKK_RSA {
        // RSA public: modulus+exponent, or a DER blob in CKA_VALUE.
        let has_components =
            attrs.contains_key(&CKA_MODULUS) && attrs.contains_key(&CKA_PUBLIC_EXPONENT);
        if !has_components && !attrs.contains_key(&CKA_VALUE) {
            return Err(CKR_TEMPLATE_INCOMPLETE);
        }
    } else if class == CKO_PUBLIC_KEY
        && (key_type == CKK_EC || key_type == CKK_EC_EDWARDS || key_type == CKK_EC_MONTGOMERY)
    {
        // EC-family public: EC_POINT (the engine also accepts raw CKA_VALUE).
        if !attrs.contains_key(&CKA_EC_POINT) && !attrs.contains_key(&CKA_VALUE) {
            return Err(CKR_TEMPLATE_INCOMPLETE);
        }
    } else if !attrs.contains_key(&CKA_VALUE) {
        // PQC public/private and remaining private keys: raw CKA_VALUE.
        return Err(CKR_TEMPLATE_INCOMPLETE);
    }
    Ok(())
}

/// Engine core of `C_CreateObject` — operates on an already-marshalled
/// attribute map. Split from the FFI wrapper so policy can be unit-tested on
/// 64-bit native builds, where CK_ATTRIBUTE templates (32-bit value pointers)
/// cannot be constructed.
pub(crate) fn create_object_from_attrs(
    h_session: u32,
    mut new_attrs: Attributes,
) -> Result<u32, u32> {
    // PKCS#11 v3.2 §4.1.1 Table 12 — token-computed attributes may never
    // appear in a C_CreateObject template → CKR_ATTRIBUTE_READ_ONLY.
    const CREATE_READ_ONLY: &[u32] = &[
        CKA_ALWAYS_SENSITIVE,  // §4.9/§4.10 — provenance is token-computed
        CKA_NEVER_EXTRACTABLE, // §4.9/§4.10 — provenance is token-computed
        CKA_KEY_GEN_MECHANISM, // §4.3 Table 13 — token-computed
        CKA_UNIQUE_ID,         // §4.4.1 — token-generated (state::allocate_handle)
    ];
    for ro in CREATE_READ_ONLY {
        if new_attrs.contains_key(ro) {
            return Err(CKR_ATTRIBUTE_READ_ONLY);
        }
    }
    // §4.1.1 Table 12 / §4.6 Table 19 footnote — CKA_TRUSTED requires SO
    // login to set (on any object class it appears on: certificates,
    // public/secret keys). A non-SO caller supplying it at all is
    // rejected — including CK_FALSE, so a non-SO session can't probe
    // whether SO-only enforcement is even wired. The SO session may set
    // it either way.
    if new_attrs.contains_key(&CKA_TRUSTED) && !crate::state::session_is_so(h_session) {
        return Err(CKR_ATTRIBUTE_READ_ONLY);
    }
    // PKCS#11 v3.2 §4.1.1 — template validation (required attrs, value
    // sanity, class/type consistency) before any object is created.
    validate_create_template(&new_attrs)?;
    // PKCS#11 v3.2 §5.6 — a token object (CKA_TOKEN=TRUE) may only be
    // created from a read/write session. Session objects are allowed in R/O.
    if read_bool_attr(&new_attrs, CKA_TOKEN) && !crate::state::session_is_rw(h_session) {
        return Err(CKR_SESSION_READ_ONLY);
    }
    if let Some(ps_bytes) = new_attrs.get(&CKA_PARAMETER_SET).cloned() {
        if ps_bytes.len() >= 4 {
            let ps = u32::from_le_bytes([ps_bytes[0], ps_bytes[1], ps_bytes[2], ps_bytes[3]]);
            store_param_set(&mut new_attrs, ps);
        }
    } else if let Some(ec_params) = new_attrs.get(&CKA_EC_PARAMS).cloned() {
        // Derive curve from CKA_EC_PARAMS OID for imported EC keys.
        // P-384 OID (1.3.132.0.34): 06 05 2b 81 04 00 22 — last byte 0x22
        // P-256 OID (1.2.840.10045.3.1.7): 06 07 2a 86 48 ce 3d 03 01 07 — last byte 0x07
        let is_p521 = ec_params.len() >= 7 && ec_params[ec_params.len() - 1] == 0x23;
        let is_p384 = ec_params.len() >= 7 && ec_params[ec_params.len() - 1] == 0x22;
        store_param_set(
            &mut new_attrs,
            if is_p521 {
                CURVE_P521
            } else if is_p384 {
                CURVE_P384
            } else {
                CURVE_P256
            },
        );
    }
    let class = new_attrs
        .get(&CKA_CLASS)
        .filter(|v| v.len() >= 4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
    let is_key = matches!(
        class,
        Some(CKO_PUBLIC_KEY) | Some(CKO_PRIVATE_KEY) | Some(CKO_SECRET_KEY)
    );

    // PKCS#11 v3.2 §4.3 — CKA_LOCAL=FALSE is mandatory for imported objects and
    // CKA_KEY_GEN_MECHANISM = CKM_UNAVAILABLE_INFORMATION for imported keys;
    // both override any caller-provided value, since they are server-managed.
    //
    // ONLY ON KEYS. Both are COMMON KEY attributes (§4.9 Table 27); the
    // data-object table (§4.5 Table 12) defines CKA_APPLICATION, CKA_OBJECT_ID
    // and CKA_VALUE and nothing else. Stamping them on every class made a
    // CKO_DATA object answer CKA_LOCAL and CKA_KEY_GEN_MECHANISM with CKR_OK
    // where C++ correctly answers CKR_ATTRIBUTE_TYPE_INVALID — the harness's
    // DEFECT-RUST-DATA-OBJECT-CARRIES-KEY-ATTRIBUTES, eight observations.
    if is_key {
        store_bool(&mut new_attrs, CKA_LOCAL, false);
        store_ulong(
            &mut new_attrs,
            CKA_KEY_GEN_MECHANISM,
            CKM_UNAVAILABLE_INFORMATION,
        );
    }

    // PKCS#11 v3.2 §6.14 (and every other secret-key table): CKA_VALUE_LEN is
    // "Length in bytes of key value", defined for the key type regardless of
    // how the object came into being. The generate and unwrap paths already
    // derive it; C_CreateObject did not, so an AES key imported with an
    // explicit CKA_VALUE answered CKR_ATTRIBUTE_TYPE_INVALID for its own
    // length while C++ answered 32 — DEFECT-RUST-IMPORTED-AES-NO-VALUE-LEN.
    // Derived, never taken from the template: §4.1.1 rule 5 already rejects a
    // contradicting caller value upstream.
    if class == Some(CKO_SECRET_KEY) && !new_attrs.contains_key(&CKA_VALUE_LEN) {
        if let Some(len) = new_attrs.get(&CKA_VALUE).map(|v| v.len() as u32) {
            store_ulong(&mut new_attrs, CKA_VALUE_LEN, len);
        }
    }

    // PKCS#11 v3.2 §4.9/§4.10 — an object created via C_CreateObject was born
    // OUTSIDE the token, so it can never claim CKA_ALWAYS_SENSITIVE or
    // CKA_NEVER_EXTRACTABLE, regardless of the template's CKA_SENSITIVE /
    // CKA_EXTRACTABLE values (mirrors the C_UnwrapKey / C_DeriveKey paths).
    if matches!(class, Some(CKO_PRIVATE_KEY) | Some(CKO_SECRET_KEY)) {
        store_bool(&mut new_attrs, CKA_ALWAYS_SENSITIVE, false);
        store_bool(&mut new_attrs, CKA_NEVER_EXTRACTABLE, false);
    }
    // Compute CKA_CHECK_VALUE (KCV) — PKCS#11 v3.2
    compute_kcv(&mut new_attrs);
    Ok(allocate_handle_owned(h_session, new_attrs))
}

#[wasm_bindgen(js_name = _C_CreateObject)]
pub fn C_CreateObject(
    _h_session: u32,
    p_template: *mut u8,
    count: u32,
    ph_object: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    if ph_object.is_null() || (p_template.is_null() && count > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        if count > 65536 {
            return CKR_ARGUMENTS_BAD;
        }
        let tmpl_ptr = p_template as *mut usize;
        let mut new_attrs = HashMap::new();
        for i in 0..count {
            let attr_type = *tmpl_ptr.add((i * 3) as usize) as u32;
            let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as u32;
            if !val_ptr.is_null() && val_len > 0 {
                // S2 — an ATTRIBUTE-array attribute (CKA_WRAP_TEMPLATE and
                // friends) has a CK_ATTRIBUTE[] as its value, whose inner
                // pValue pointers die with this call. Flatten it into a
                // self-contained blob; every other attribute is copied
                // verbatim as before. Same treatment absorb_template_attrs
                // applies on the keygen paths, so a wrapping key created
                // either way carries the same stored form.
                let v = if crate::crypto::handlers::attr_is_attribute_array(attr_type) {
                    match crate::crypto::handlers::flatten_attr_array(val_ptr, val_len as usize) {
                        Some(flat) => flat,
                        None => return CKR_ATTRIBUTE_VALUE_INVALID,
                    }
                } else {
                    let mut v = vec![0u8; val_len as usize];
                    std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                    v
                };
                new_attrs.insert(attr_type, v);
            }
        }
        match create_object_from_attrs(_h_session, new_attrs) {
            Ok(handle) => *ph_object = handle,
            Err(rv) => return rv,
        }
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DestroyObject)]
pub fn C_DestroyObject(h_session: u32, h_object: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // PKCS#11 v3.2 §4.4 — a private object cannot be destroyed (or even seen)
    // by a session whose token is not logged in.
    let exists = OBJECTS.with(|o| o.borrow().contains_key(&h_object));
    if exists && !crate::state::can_access_handle(h_session, h_object) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    // S7 — §5.7.3: a read-only session cannot DELETE a token object either.
    if exists {
        let is_token = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_object)
                .map(|a| read_bool_attr(a, CKA_TOKEN))
                .unwrap_or(false)
        });
        if let Err(rv) = crate::state::check_rw_for_token_object(h_session, is_token) {
            return rv;
        }
    }
    // §4.1.3 — CKA_DESTROYABLE=FALSE forbids C_DestroyObject. Absent attr
    // defaults TRUE (state::apply_object_defaults stamps it on every
    // allocate path) — mirrors the CKA_COPYABLE/CKA_MODIFIABLE gates on
    // C_CopyObject/C_SetAttributeValue. Protects token-managed objects such
    // as the built-in CKO_PROFILE (state::init_profile_objects).
    if exists {
        let destroyable = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_object)
                .map(|a| {
                    a.get(&CKA_DESTROYABLE)
                        .map(|v| v.first().copied().unwrap_or(0) != 0)
                        .unwrap_or(true)
                })
                .unwrap_or(true)
        });
        if !destroyable {
            return CKR_ACTION_PROHIBITED;
        }
    }
    let mut removed_slot: Option<u32> = None;
    let removed = OBJECTS.with(|objs| {
        let mut store = objs.borrow_mut();
        if let Some(mut attrs) = store.remove(&h_object) {
            if read_bool_attr(&attrs, CKA_TOKEN) {
                removed_slot = Some(crate::state::object_slot_of(&attrs));
            }
            // Zeroize key material before deallocation (RS-02)
            if let Some(val) = attrs.get_mut(&CKA_VALUE) {
                val.zeroize();
            }
            true
        } else {
            false
        }
    });
    if let Some(slot) = removed_slot {
        crate::store::persist_delete(slot, h_object);
    }
    if removed {
        // PKCS#11 v3.2: clean up any active operation state referencing the destroyed key.
        // Without this, a session that called C_SignInit then C_DestroyObject would hold a
        // stale key handle, causing undefined behaviour on the subsequent C_Sign call.
        SIGN_STATE.with(|s| s.borrow_mut().retain(|_, v| v.1 != h_object));
        VERIFY_STATE.with(|s| s.borrow_mut().retain(|_, v| v.1 != h_object));
        ENCRYPT_STATE.with(|s| s.borrow_mut().retain(|_, ctx| ctx.key_handle != h_object));
        DECRYPT_STATE.with(|s| s.borrow_mut().retain(|_, ctx| ctx.key_handle != h_object));
        CKR_OK
    } else {
        CKR_OBJECT_HANDLE_INVALID
    }
}

// ── Sign/Verify ─────────────────────────────────────────────────────────────

/// Resolve a key handle for an operation requiring the usage flag `usage_attr`
/// (e.g. CKA_SIGN). Enforces, with spec-correct priority (PKCS#11 v3.2 §5.12):
///   1. the handle exists                → else CKR_KEY_HANDLE_INVALID
///   2. the (private) object is visible   → else CKR_KEY_HANDLE_INVALID (§4.4)
///   3. the usage flag is set             → else CKR_KEY_FUNCTION_NOT_PERMITTED
fn check_key_usage(h_session: u32, h_key: u32, usage_attr: u32) -> Result<(), u32> {
    check_key_usage_as(h_session, h_key, usage_attr, CKR_KEY_HANDLE_INVALID)
}

/// `check_key_usage` parameterized on the handle-invalid code, so the wrap
/// family can report the role-specific codes the spec assigns:
/// CKR_WRAPPING_KEY_HANDLE_INVALID (C_WrapKey) and
/// CKR_UNWRAPPING_KEY_HANDLE_INVALID (C_UnwrapKey).
fn check_key_usage_as(
    h_session: u32,
    h_key: u32,
    usage_attr: u32,
    handle_invalid_rv: u32,
) -> Result<(), u32> {
    let attrs = match OBJECTS.with(|o| o.borrow().get(&h_key).cloned()) {
        Some(a) => a,
        None => return Err(handle_invalid_rv),
    };
    if !crate::state::can_access_object(h_session, &attrs) {
        return Err(handle_invalid_rv);
    }
    if !read_bool_attr(&attrs, usage_attr) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    Ok(())
}


/// RSA-PSS mechanism → (expected CKM_* hashAlg, expected CKG_MGF1_* mgf) for
/// CK_RSA_PKCS_PSS_PARAMS validation (§6.4.5: hashAlg/mgf must match the
/// digest baked into the mechanism; MGF1 uses the same hash per §6.2).
fn rsa_pss_mech_params(mech: u32) -> Option<(u32, u32)> {
    match mech {
        CKM_SHA256_RSA_PKCS_PSS => Some((CKM_SHA256, CKG_MGF1_SHA256)),
        CKM_SHA384_RSA_PKCS_PSS => Some((CKM_SHA384, CKG_MGF1_SHA384)),
        CKM_SHA512_RSA_PKCS_PSS => Some((CKM_SHA512, CKG_MGF1_SHA512)),
        CKM_SHA3_384_RSA_PKCS_PSS => Some((CKM_SHA3_384, CKG_MGF1_SHA3_384)),
        _ => None,
    }
}

/// R-1 (2026-08-24) — bare `CKM_RSA_PKCS_PSS`'s hash is NOT fixed by the
/// mechanism ID; it comes from the caller's `CK_RSA_PKCS_PSS_PARAMS.hashAlg`/
/// `mgf` fields at runtime (§6.4.5). This validates the hashAlg/mgf PAIRING
/// by reusing the exact associations `rsa_pss_mech_params` above already
/// encodes per hash-specific sibling mechanism (SHA256↔MGF1_SHA256, etc.) —
/// deliberately NOT a second, independently-maintained table that could
/// silently drift out of sync with the first.
fn pss_hash_mgf_pairing_valid(hash_alg: u32, mgf: u32) -> bool {
    [
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
        CKM_SHA3_384_RSA_PKCS_PSS,
    ]
    .into_iter()
    .any(|m| rsa_pss_mech_params(m) == Some((hash_alg, mgf)))
}

fn C_SignInit_impl(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::Sign) {
        return rv;
    }
    // PKCS#11 v3.2 §5.12 — a sign operation is already active on this session.
    if SIGN_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_ACTIVE;
    }
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.12.4 — key handle, visibility, and CKA_SIGN permission.
        if let Err(rv) = check_key_usage(h_session, h_key, CKA_SIGN) {
            return rv;
        }
        let mut mech_type = ck_param::mech(p_mechanism).mechanism;
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS, checked against the
        // caller's original request before any internal remap below.
        if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
            return rv;
        }
        // §6.4 — raw CKM_RSA_PKCS takes NO mechanism parameter; a supplied one
        // (e.g. a CK_SIGN_ADDITIONAL_CONTEXT meant for ML-DSA/SLH-DSA) is
        // CKR_MECHANISM_PARAM_INVALID.
        if mech_type == CKM_RSA_PKCS {
            if ck_param::mech(p_mechanism).has_param() {
                return CKR_MECHANISM_PARAM_INVALID;
            }
        }
        // Parse CK_EDDSA_PARAMS: if phFlag is set, use internal CKM_EDDSA_PH
        if mech_type == CKM_EDDSA {
            if eddsa_ph_flag(p_mechanism) {
                mech_type = CKM_EDDSA_PH;
            }
        }
        // GENERIC pre-hash mechanisms (CKM_HASH_ML_DSA/CKM_HASH_SLH_DSA)
        // remap onto the concrete hash-specific mechanism via their
        // CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash param.
        mech_type = match remap_generic_hash_mech(p_mechanism, mech_type) {
            Ok(m) => m,
            Err(rv) => return rv,
        };
        // Mechanism parameters — see parse_sign_mech_params (shared with
        // the other two *SignInit/*VerifyInit entry points).
        let (slh_ctx, slh_det) = match parse_sign_mech_params(p_mechanism, mech_type) {
            Ok(v) => v,
            Err(rv) => return rv,
        };
        SIGN_STATE.with(|s| {
            s.borrow_mut()
                .insert(h_session, (mech_type, h_key, slh_ctx, slh_det));
        });
    }
    CKR_OK
}

/// If `mech_type` is a GENERIC pre-hash mechanism (CKM_HASH_ML_DSA /
/// CKM_HASH_SLH_DSA, §6.67.7/§6.69.7), parse
/// `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash` and remap onto the concrete
/// hash-specific mechanism so the rest of the sign/verify pipeline
/// (`takes_sign_additional_ctx` / `parse_sign_additional_ctx` / dispatch)
/// runs unchanged — same idiom as the CKM_EDDSA -> CKM_EDDSA_PH phFlag
/// remap just above each call site. Returns `mech_type` unchanged for every
/// other mechanism.
///
/// `CK_HASH_SIGN_ADDITIONAL_CONTEXT` shares `CK_SIGN_ADDITIONAL_CONTEXT`'s
/// first 3 fields (hedgeVariant, pContext, ulContextLen — read later by
/// `parse_sign_additional_ctx` against this same pointer) plus a trailing
/// `hash` (CK_MECHANISM_TYPE) at native width; this only extracts `hash`.
unsafe fn remap_generic_hash_mech(p_mechanism: *const u8, mech_type: u32) -> Result<u32, u32> {
    if mech_type != CKM_HASH_ML_DSA && mech_type != CKM_HASH_SLH_DSA {
        return Ok(mech_type);
    }
    // The generic mechanism cannot select a digest without this field —
    // absent/undersized params are a caller error, not a default.
    let r = ck_param::mech(p_mechanism)
        .params(
            &ck_param::hash_sign_ctx::LAYOUT,
            ck_param::hash_sign_ctx::FIELD_COUNT,
        )
        .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    let hash = r.ulong32(ck_param::hash_sign_ctx::HASH);
    map_generic_hash_mech(mech_type, hash).ok_or(CKR_MECHANISM_PARAM_INVALID)
}

/// True when `mech` takes a CK_SIGN_ADDITIONAL_CONTEXT parameter
/// (PKCS#11 v3.2 §6.67/§6.69 — ML-DSA and SLH-DSA, pure and pre-hash).
fn takes_sign_additional_ctx(mech: u32) -> bool {
    mech == CKM_ML_DSA
        || mech == CKM_SLH_DSA
        || is_prehash_ml_dsa(mech)
        || is_prehash_slh_dsa(mech)
}

/// Parse CK_SIGN_ADDITIONAL_CONTEXT from a CK_MECHANISM pointer (WASM32,
/// 12-byte param struct: hedgeVariant(4) + pContext(4) + ulContextLen(4)).
/// Absent parameter ⇒ empty context, hedged (the spec default).
///
/// Errors (CKR_MECHANISM_PARAM_INVALID):
/// - context longer than 255 bytes (FIPS 204 §5.2 / FIPS 205 §9.2 — an
///   overlong context is an error, NOT "ignore");
/// - unknown hedge variant value.
/// `CK_EDDSA_PARAMS.phFlag` (PKCS#11 v3.2 §6.3.7).
///
///     typedef struct CK_EDDSA_PARAMS {
///         CK_BBOOL    phFlag;
///         CK_ULONG    ulContextDataLen;
///         CK_BYTE_PTR pContextData;
///     } CK_EDDSA_PARAMS;
///
/// `phFlag` is a CK_BBOOL — ONE byte, followed by padding to the alignment
/// of the CK_ULONG that comes next (3 bytes on wasm32, 7 on LP64). Reading
/// it as a u32 pulled 3 of those padding bytes in with it, so a caller who
/// set `phFlag = CK_FALSE` without zeroing the whole struct could be
/// switched to the PRE-HASHED variant by leftover stack bytes and get an
/// Ed25519ph signature where it asked for pure Ed25519 — a silently wrong
/// signature, from a completely valid call.
///
/// Byte 0 is the right read on every target, and it also stays compatible
/// with the little-endian 32-bit `phFlag` the wasm/TS callers write.
///
/// Ported to `ck_param` (2026-08-14): the one-byte read is now a property of
/// the *declaration* (`F::Bbool`), not of this function remembering to do it.
unsafe fn eddsa_ph_flag(p_mechanism: *const u8) -> bool {
    let m = ck_param::mech(p_mechanism);
    // Absent parameter ⇒ pure EdDSA, which is the spec default.
    match m.opt_params(&ck_param::eddsa::LAYOUT, 1) {
        Ok(Some(r)) => r.bbool(ck_param::eddsa::PH_FLAG),
        _ => false,
    }
}

/// The mechanism-parameter half of `C_SignInit` / `C_VerifyInit` /
/// `C_MessageSignInit`, which were three byte-identical copies of the same
/// four-branch parse. Instances 2, 3 and 4 of the parameter-width defect all
/// lived here, in triplicate — extracting it is the part of this change that
/// makes those fixes structural rather than three edits that have to stay in
/// step by hand.
///
/// Returns `(ctx_bytes, deterministic)` in the encoding the sign/verify
/// pipeline already carries in its state map.
unsafe fn parse_sign_mech_params(
    p_mechanism: *const u8,
    mech_type: u32,
) -> Result<(Vec<u8>, bool), u32> {
    let m = ck_param::mech(p_mechanism);
    if takes_sign_additional_ctx(mech_type) {
        // CK_SIGN_ADDITIONAL_CONTEXT — ML-DSA + SLH-DSA, pure and pre-hash
        // (PKCS#11 v3.2 §6.67/§6.69). Overlong ctx / bad hedge → error.
        return parse_sign_additional_ctx(p_mechanism);
    }
    if let Some((exp_hash, exp_mgf)) = rsa_pss_mech_params(mech_type) {
        // CK_RSA_PKCS_PSS_PARAMS (§6.4.5) — params are caller-authoritative;
        // hashAlg/mgf must match the mechanism's digest. An absent parameter
        // keeps the legacy defaults, and so does a short one — unchanged from
        // before this port, hence `.ok().flatten()` rather than `?`.
        let r = m
            .opt_params(&ck_param::pss::LAYOUT, ck_param::pss::FIELD_COUNT)
            .ok()
            .flatten();
        return Ok(match r {
            Some(r) => {
                let hash_alg = r.ulong32(ck_param::pss::HASH_ALG);
                let mgf = r.ulong32(ck_param::pss::MGF);
                let s_len = r.ulong32(ck_param::pss::S_LEN);
                if hash_alg != exp_hash || mgf != exp_mgf {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                // carried to C_Sign/C_Verify in the ctx vec (LE u32)
                (s_len.to_le_bytes().to_vec(), false)
            }
            None => (Vec::new(), false),
        });
    }
    if mech_type == CKM_RSA_PKCS_PSS {
        // R-1 (2026-08-24) — bare CKM_RSA_PKCS_PSS. Unlike the hash-specific
        // siblings above (whose hash is implied by the mechanism ID, so only
        // sLen needs to travel to C_Sign/C_Verify), THIS mechanism has no
        // implied hash at all — CK_RSA_PKCS_PSS_PARAMS is therefore REQUIRED,
        // not optional (`.params()`, not `.opt_params()`), and hashAlg/mgf/
        // sLen all have to be threaded through to the actual sign/verify
        // dispatch for runtime hash selection.
        let r = m
            .params(&ck_param::pss::LAYOUT, ck_param::pss::FIELD_COUNT)
            .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
        let hash_alg = r.ulong32(ck_param::pss::HASH_ALG);
        let mgf = r.ulong32(ck_param::pss::MGF);
        let s_len = r.ulong32(ck_param::pss::S_LEN);
        if !pss_hash_mgf_pairing_valid(hash_alg, mgf) {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        // ctx vec layout for bare PSS: hashAlg(4) || mgf(4) || sLen(4), all
        // LE u32 — see C_Sign_impl / C_Verify's own CKM_RSA_PKCS_PSS arm,
        // which is the only reader of this 12-byte format.
        let mut v = hash_alg.to_le_bytes().to_vec();
        v.extend_from_slice(&mgf.to_le_bytes());
        v.extend_from_slice(&s_len.to_le_bytes());
        return Ok((v, false));
    }
    if mech_type == CKM_KMAC_128 || mech_type == CKM_KMAC_256 {
        // Vendor KMAC params — INSTANCE 3. `pCustomization` is a POINTER;
        // reading the three fields as u32s on LP64 kept its low half and then
        // dereferenced it. `ptr()`/`ulong()` cannot express that mistake, and
        // `buffer()` reads the pointer/length pair as the declaration says
        // they are typed. Absent (or short) ⇒ defaults, as before.
        let r = m
            .opt_params(&ck_param::kmac::LAYOUT, ck_param::kmac::FIELD_COUNT)
            .ok()
            .flatten();
        return Ok(match r {
            Some(r) => {
                let s_len = r.ulong(ck_param::kmac::UL_CUSTOMIZATION_LEN);
                let out_len = r.ulong32(ck_param::kmac::UL_OUTPUT_LEN);
                if out_len > 1024 || s_len > 1024 {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let mut v = out_len.to_le_bytes().to_vec();
                v.extend_from_slice(
                    r.buffer(ck_param::kmac::P_CUSTOMIZATION, ck_param::kmac::UL_CUSTOMIZATION_LEN),
                );
                (v, false)
            }
            None => (Vec::new(), false),
        });
    }
    if let Some((_, digest_len)) = hmac_general_base(mech_type) {
        // CK_MAC_GENERAL_PARAMS — INSTANCE 4. A bare `typedef CK_ULONG`, so
        // the whole "struct" is one native-width word. The old reading took
        // four bytes (right by accident on little-endian LP64, zero on
        // big-endian) and its length guard accepted a HALF-SIZED parameter,
        // reading the other four bytes from past the buffer. `require_len`
        // is now what rejects that.
        let r = m
            .params(&ck_param::mac_general::LAYOUT, ck_param::mac_general::FIELD_COUNT)
            .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
        let mac_len = r.ulong(ck_param::mac_general::UL_MAC_LENGTH);
        if mac_len == 0 || mac_len > digest_len {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        return Ok(((mac_len as u32).to_le_bytes().to_vec(), false));
    }
    Ok((Vec::new(), false))
}

unsafe fn parse_sign_additional_ctx(p_mechanism: *const u8) -> Result<(Vec<u8>, bool), u32> {
    // An absent parameter — and, unchanged from before this port, a short one
    // — means "empty context, hedged".
    let r = match ck_param::mech(p_mechanism)
        .opt_params(&ck_param::sign_ctx::LAYOUT, ck_param::sign_ctx::FIELD_COUNT)
    {
        Ok(Some(r)) => r,
        _ => return Ok((Vec::new(), false)),
    };
    let hedge = r.ulong32(ck_param::sign_ctx::HEDGE_VARIANT);
    // CKH_HEDGE_PREFERRED(0) / CKH_HEDGE_REQUIRED(1) both sign hedged here
    // (hedging is always available); CKH_DETERMINISTIC_REQUIRED(2) selects
    // the deterministic variant.
    let deterministic = match hedge {
        0 | 1 => false,
        x if x == CKH_DETERMINISTIC_REQUIRED => true,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    };
    if r.ulong(ck_param::sign_ctx::UL_CONTEXT_LEN) > 255 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let context = r
        .buffer(ck_param::sign_ctx::P_CONTEXT, ck_param::sign_ctx::UL_CONTEXT_LEN)
        .to_vec();
    Ok((context, deterministic))
}

fn C_Sign_impl(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // §5.2 error priority — session-handle validity outranks
    // CKR_OPERATION_NOT_INITIALIZED and argument checks.
    // §5.13.2 — "C_Sign ... MUST be called after C_SignInit without
    // intervening C_SignUpdate calls". A sign op already in its multi-part
    // phase is a sequencing error (mirror C_Digest-after-Update, round-1
    // S4/M-2); the accumulated parts MUST NOT be consumed by this error.
    if SIGN_MULTIPART_ACC.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_ACTIVE;
    }
    if pul_signature_len.is_null() || (p_data.is_null() && ul_data_len > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    // Peek first to support the size-query path (p_signature == null) without consuming state.
    let state = SIGN_STATE.with(|s| s.borrow().get(&h_session).cloned());
    let (mech, hkey, ctx_bytes, deterministic) = match state {
        Some(s) => s,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };

    unsafe {
        if p_signature.is_null() {
            *pul_signature_len = if hmac_general_base(mech).is_some() && ctx_bytes.len() >= 4 {
                u32::from_le_bytes([ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3]])
            } else {
                get_sig_len(mech, hkey)
            };
            return CKR_OK;
        }

        // ── HSS/LMS stateful sign — single source of truth for the
        // leaf advance-and-persist core lives in `native::hbs`, shared
        // with the KMIP-facing `native::sign` path (see that module's
        // doc comment: drift here means a leaf index gets reused,
        // breaking the one-time-signature security property). ───────
        if mech == CKM_HSS {
            let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
            let rv = match crate::native::hbs::sign_prepare(hkey, msg) {
                Ok(prepared) => {
                    // PKCS#11 v3.2 §5.2 — for a one-time (stateful) key the leaf
                    // MUST NOT be consumed until the caller's output buffer is
                    // known to be adequate. Validate the buffer FIRST; on
                    // CKR_BUFFER_TOO_SMALL leave the on-object key state
                    // unchanged and keep the operation active so the caller can
                    // retry with a larger buffer (re-signing the same leaf is
                    // deterministic and idempotent here).
                    if (*pul_signature_len as usize) < prepared.signature.len() {
                        *pul_signature_len = prepared.signature.len() as u32;
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    // Buffer is adequate — now atomically advance and persist
                    // the key state, then emit the signature.
                    crate::native::hbs::sign_commit(hkey, &prepared);
                    std::ptr::copy_nonoverlapping(
                        prepared.signature.as_ptr(),
                        p_signature,
                        prepared.signature.len(),
                    );
                    *pul_signature_len = prepared.signature.len() as u32;
                    CKR_OK
                }
                Err(e) => e,
            };
            SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
            return rv;
        }

        // ── XMSS / XMSS^MT stateful sign — separate path (uses CKA_PRIV_STATEFUL_KEY_STATE) ───
        if mech == CKM_XMSS || mech == CKM_XMSSMT {
            let priv_bytes = match get_object_attr_bytes(hkey, CKA_PRIV_STATEFUL_KEY_STATE) {
                Some(v) => v,
                None => return CKR_KEY_TYPE_INCONSISTENT,
            };
            let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);

            // Capture hkey for the state-update closure (WASM single-threaded, no Send needed)
            let mut new_state: Option<Vec<u8>> = None;
            let mut update_fn = |new_priv: &[u8]| -> Result<(), ()> {
                new_state = Some(new_priv.to_vec());
                Ok(())
            };

            let sign_result = if mech == CKM_XMSS {
                let xmss_param =
                    match xmss_param_set_of(hkey, false) {
                        Some(p) => p,
                        None => return CKR_TEMPLATE_INCOMPLETE,
                    };
                match crate::crypto::xmss_bridge::xmss_sign(xmss_param, &priv_bytes, msg) {
                    Ok((sig, updated_sk)) => match update_fn(&updated_sk) {
                        Ok(_) => Ok(sig),
                        Err(_) => Err(CKR_FUNCTION_FAILED),
                    },
                    Err(e) => Err(e),
                }
            } else {
                let mt_param = match xmss_param_set_of(hkey, true) {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                match crate::crypto::xmss_bridge::xmssmt_sign(mt_param, &priv_bytes, msg) {
                    Ok((sig, updated_sk)) => match update_fn(&updated_sk) {
                        Ok(_) => Ok(sig),
                        Err(_) => Err(CKR_FUNCTION_FAILED),
                    },
                    Err(e) => Err(e),
                }
            };

            let rv = match sign_result {
                Ok(sig) => {
                    // PKCS#11 v3.2 §5.2 — for a one-time (stateful) key the leaf
                    // MUST NOT be consumed until the caller's output buffer is
                    // known to be adequate. Validate the buffer FIRST; on
                    // CKR_BUFFER_TOO_SMALL leave the on-object key state
                    // unchanged and keep the operation active so the caller can
                    // retry with a larger buffer (re-signing the same leaf is
                    // deterministic and idempotent here).
                    if (*pul_signature_len as usize) < sig.len() {
                        *pul_signature_len = sig.len() as u32;
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    // Buffer is adequate — now atomically advance and persist the
                    // key state, then emit the signature. Both fields (state blob
                    // + remaining-keys counter) are ONE logical "this leaf was
                    // consumed" transition — coalesced into one
                    // set_object_attrs_bytes_batch call so a crash between them
                    // can't leave disk/memory disagreeing about the last-used
                    // leaf (same hazard native::hbs::sign_commit guards against
                    // for HSS/LMS).
                    if let Some(ref new_priv_bytes) = new_state {
                        let mut changes =
                            vec![(CKA_PRIV_STATEFUL_KEY_STATE, new_priv_bytes.clone())];

                        if mech == CKM_XMSSMT {
                            // XMSS^MT: derive remaining from the MT signing-key
                            // state (the index width differs from single-tree).
                            let mt_param = xmss_param_set_of(hkey, true)
                                .unwrap_or(CKP_XMSSMT_SHA2_20_2_256);
                            let remaining = crate::crypto::xmss_bridge::xmssmt_keys_remaining(
                                mt_param,
                                new_priv_bytes,
                            )
                            .min(u32::MAX as u64) as u32;
                            changes.push((
                                CKA_PRIV_XMSS_KEYS_REMAINING,
                                remaining.to_le_bytes().to_vec(),
                            ));
                        } else {
                            // XMSS: derive remaining from the updated signing key state.
                            // The xmss crate stores the leaf index as big-endian bytes at offset 4
                            // inside the serialised signing key. Reading it directly is more accurate
                            // than a simple -1 decrement (the crate may skip leaves internally).
                            let xmss_param = xmss_param_set_of(hkey, false)
                                .unwrap_or(CKP_XMSS_SHA2_10_256);
                            let remaining = crate::crypto::xmss_bridge::xmss_keys_remaining(
                                xmss_param,
                                new_priv_bytes,
                            );
                            changes.push((
                                CKA_PRIV_XMSS_KEYS_REMAINING,
                                remaining.to_le_bytes().to_vec(),
                            ));
                        }
                        crate::state::set_object_attrs_bytes_batch(hkey, &changes);
                    }
                    std::ptr::copy_nonoverlapping(sig.as_ptr(), p_signature, sig.len());
                    *pul_signature_len = sig.len() as u32;
                    CKR_OK
                }
                Err(e) => e,
            };
            SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
            return rv;
        }

        let sk_bytes = match get_object_value(hkey) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let ps = get_object_param_set(hkey);

        // then sign the digest as if it were plain CKM_ML_DSA / CKM_SLH_DSA.
        let eff_mech = mech;
        let eff_msg = msg;
        let result = match eff_mech {
            m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => {
                sign_ml_dsa(m, ps, &sk_bytes, msg, &ctx_bytes, deterministic)
            }
            m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => {
                sign_slh_dsa(m, ps, &sk_bytes, msg, &ctx_bytes, deterministic)
            }
            CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
            | CKM_SHA3_512_HMAC | CKM_RIPEMD160_HMAC => sign_hmac(eff_mech, &sk_bytes, eff_msg),
            m if hmac_general_base(m).is_some() => {
                let (base, _) = hmac_general_base(m).unwrap();
                let mac_len = if ctx_bytes.len() >= 4 {
                    u32::from_le_bytes([ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3]])
                        as usize
                } else {
                    0
                };
                sign_hmac(base, &sk_bytes, eff_msg).map(|mut mac| {
                    mac.truncate(mac_len.max(1));
                    mac
                })
            }
            CKM_KMAC_128 | CKM_KMAC_256 => {
                if ctx_bytes.len() >= 4 {
                    let out_len = u32::from_le_bytes([
                        ctx_bytes[0],
                        ctx_bytes[1],
                        ctx_bytes[2],
                        ctx_bytes[3],
                    ]) as usize;
                    sign_kmac_ext(eff_mech, &sk_bytes, eff_msg, &ctx_bytes[4..], out_len)
                } else {
                    sign_kmac(eff_mech, &sk_bytes, eff_msg)
                }
            }
            CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
            | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS
            | CKM_SHA3_384_RSA_PKCS | CKM_SHA3_384_RSA_PKCS_PSS | CKM_RSA_PKCS => {
                let pss_salt = if rsa_pss_mech_params(eff_mech).is_some() && ctx_bytes.len() >= 4 {
                    Some(u32::from_le_bytes([
                        ctx_bytes[0],
                        ctx_bytes[1],
                        ctx_bytes[2],
                        ctx_bytes[3],
                    ]) as usize)
                } else {
                    None
                };
                sign_rsa(eff_mech, &sk_bytes, eff_msg, pss_salt)
            }
            // R-1 (2026-08-24) — bare CKM_RSA_PKCS_PSS. `eff_msg` here is
            // ALREADY a digest, not a message: unlike the hash-specific PSS
            // siblings just above (whose `sign_rsa` internally hashes the
            // full message via `BlindedSigningKey<D>::sign()`), bare PSS
            // operates directly on caller-supplied hashed bytes (RFC 8017
            // §8.1 EMSA-PSS-ENCODE takes `mHash`, not `M`) — the caller has
            // hashed the message itself before calling C_Sign. ctx_bytes is
            // the 12-byte hashAlg||mgf||sLen format parse_sign_mech_params's
            // CKM_RSA_PKCS_PSS branch produces (not the 4-byte sLen-only
            // format the block above reads).
            CKM_RSA_PKCS_PSS => {
                if ctx_bytes.len() < 12 {
                    Err(CKR_MECHANISM_PARAM_INVALID)
                } else {
                    let hash_alg = u32::from_le_bytes([
                        ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3],
                    ]);
                    let s_len = u32::from_le_bytes([
                        ctx_bytes[8], ctx_bytes[9], ctx_bytes[10], ctx_bytes[11],
                    ]) as usize;
                    sign_rsa_pss_bare(hash_alg, &sk_bytes, eff_msg, s_len)
                }
            }
            CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512
            | CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256 | CKM_ECDSA_SHA3_384 | CKM_ECDSA_SHA3_512 => {
                sign_ecdsa(eff_mech, ps, &sk_bytes, eff_msg)
            }
            CKM_EDDSA => sign_eddsa(&sk_bytes, eff_msg),
            CKM_EDDSA_PH => sign_eddsa_ph(&sk_bytes, eff_msg),
            _ => Err(CKR_MECHANISM_INVALID),
        };

        let rv = match result {
            Ok(sig) => {
                if (*pul_signature_len as usize) < sig.len() {
                    *pul_signature_len = sig.len() as u32;
                    return CKR_BUFFER_TOO_SMALL;
                }
                std::ptr::copy_nonoverlapping(sig.as_ptr(), p_signature, sig.len());
                *pul_signature_len = sig.len() as u32;
                CKR_OK
            }
            Err(e) => e,
        };
        // Consume sign state after the actual sign (not the size-query path above)
        SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
        rv
    }
}

#[wasm_bindgen(js_name = _C_VerifyInit)]
pub fn C_VerifyInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::Verify) {
        return rv;
    }
    // PKCS#11 v3.2 §5.12 — a verify operation is already active on this session.
    if VERIFY_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_ACTIVE;
    }
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.12.4 — key handle, visibility, and CKA_VERIFY permission.
        if let Err(rv) = check_key_usage(h_session, h_key, CKA_VERIFY) {
            return rv;
        }
        let mut mech_type = ck_param::mech(p_mechanism).mechanism;
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS, checked before any remap.
        if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
            return rv;
        }
        // Parse CK_EDDSA_PARAMS: if phFlag is set, use internal CKM_EDDSA_PH
        if mech_type == CKM_EDDSA {
            if eddsa_ph_flag(p_mechanism) {
                mech_type = CKM_EDDSA_PH;
            }
        }
        // GENERIC pre-hash mechanisms (CKM_HASH_ML_DSA/CKM_HASH_SLH_DSA)
        // remap onto the concrete hash-specific mechanism via their
        // CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash param.
        mech_type = match remap_generic_hash_mech(p_mechanism, mech_type) {
            Ok(m) => m,
            Err(rv) => return rv,
        };
        // Mechanism parameters — see parse_sign_mech_params (shared with
        // the other two *SignInit/*VerifyInit entry points).
        let (slh_ctx, slh_det) = match parse_sign_mech_params(p_mechanism, mech_type) {
            Ok(v) => v,
            Err(rv) => return rv,
        };
        VERIFY_STATE.with(|s| {
            s.borrow_mut()
                .insert(h_session, (mech_type, h_key, slh_ctx, slh_det));
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Verify)]
pub fn C_Verify(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    ul_signature_len: u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // §5.15.2 — "C_Verify ... MUST be called after C_VerifyInit without
    // intervening C_VerifyUpdate calls" (mirror the C_Sign guard above); the
    // accumulated parts MUST NOT be consumed by this error.
    if VERIFY_MULTIPART_ACC.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_ACTIVE;
    }
    if (p_data.is_null() && ul_data_len > 0) || p_signature.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let state = VERIFY_STATE.with(|s| s.borrow().get(&h_session).cloned());
    let (mech, hkey, ctx_bytes, _deterministic) = match state {
        Some(s) => s,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };

    // PKCS#11 v3.2 §5.12.6 — a signature whose LENGTH is wrong for the
    // mechanism is CKR_SIGNATURE_LEN_RANGE, not SIGNATURE_INVALID. Enforce for
    // mechanisms with a definite fixed size (ML-DSA/SLH-DSA(+prehash), EdDSA,
    // hashed-ECDSA, HMAC, KMAC). RSA (modulus-dependent), raw CKM_ECDSA, and
    // stateful HSS/XMSS (length checked inside their verifiers) are excluded.
    let fixed_len = match mech {
        m if m == CKM_ML_DSA
            || is_prehash_ml_dsa(m)
            || m == CKM_SLH_DSA
            || is_prehash_slh_dsa(m)
            || m == CKM_EDDSA
            || m == CKM_EDDSA_PH
            || matches!(
                m,
                CKM_ECDSA_SHA256
                    | CKM_ECDSA_SHA384
                    | CKM_ECDSA_SHA512
                    | CKM_ECDSA_SHA3_224
                    | CKM_ECDSA_SHA3_256
                    | CKM_ECDSA_SHA3_384
                    | CKM_ECDSA_SHA3_512
                    | CKM_SHA256_HMAC
                    | CKM_SHA384_HMAC
                    | CKM_SHA512_HMAC
                    | CKM_SHA3_256_HMAC
                    | CKM_SHA3_512_HMAC
                    | CKM_KMAC_128
                    | CKM_KMAC_256
            ) =>
        {
            Some(get_sig_len(mech, hkey))
        }
        _ => None,
    };
    if let Some(expected) = fixed_len {
        if ul_signature_len != expected {
            // op terminates like any failed verify
            VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
            return CKR_SIGNATURE_LEN_RANGE;
        }
    }

    unsafe {
        // ── LMS / HSS stateful verify — separate path (public key in CKA_VALUE) ───
        if mech == CKM_HSS || mech == CKM_XMSS || mech == CKM_XMSSMT {
            // E4 — Edwards / Montgomery public keys keep their material in
            // CKA_EC_POINT, not CKA_VALUE.
            let pub_bytes = match crate::state::get_key_material(hkey) {
                Some(v) => v,
                None => return CKR_KEY_TYPE_INCONSISTENT,
            };
            let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
            let sig_bytes = std::slice::from_raw_parts(p_signature, ul_signature_len as usize);
            let ok = if mech == CKM_XMSS {
                let xmss_param =
                    match xmss_param_set_of(hkey, false) {
                        Some(p) => p,
                        None => return CKR_TEMPLATE_INCOMPLETE,
                    };
                crate::crypto::xmss_bridge::xmss_verify(xmss_param, &pub_bytes, msg, sig_bytes)
            } else if mech == CKM_XMSSMT {
                let mt_param = match xmss_param_set_of(hkey, true) {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                crate::crypto::xmss_bridge::xmssmt_verify(mt_param, &pub_bytes, msg, sig_bytes)
            } else {
                // The key material is self-describing (lms_type embedded in
                // the HSS public key) — authoritative for imported keys that
                // carry no CKA_LMS_PARAM_SET (e.g. external ACVP vectors).
                let lms_param = get_object_attr_u32(hkey, CKA_LMS_PARAM_SET)
                    .or_else(|| crate::crypto::lms::lms_param_from_pubkey(&pub_bytes))
                    .unwrap_or(0x05);
                crate::crypto::lms::hss_verify(&pub_bytes, msg, sig_bytes, lms_param)
            };
            VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
            return if ok { CKR_OK } else { CKR_SIGNATURE_INVALID };
        }

        // CKA_VALUE: raw key bytes for symmetric/asymmetric keys (RSA, HMAC, ML-DSA,
        //            SLH-DSA, EdDSA).  May be absent for EC public keys.
        // E4 — see get_key_material: Edwards / Montgomery public keys have
        // no CKA_VALUE.
        let pk_bytes = crate::state::get_key_material(hkey).unwrap_or_default();
        // CKA_EC_POINT: PKCS#11 v3.2 standard attribute for EC public key material.
        // get_ec_point_sec1 strips the DER OCTET STRING header when present so the
        // result is always raw SEC1 (04 || x || y) ready for from_sec1_bytes().
        let ec_point_bytes = get_ec_point_sec1(hkey);
        let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let sig_bytes = std::slice::from_raw_parts(p_signature, ul_signature_len as usize);
        let ps = get_object_param_set(hkey);

        // Pre-hash dispatch: same logic as C_Sign
        let eff_mech = mech;
        let eff_msg = msg;
        let rv = match match eff_mech {
            m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => {
                verify_ml_dsa(m, ps, &pk_bytes, msg, sig_bytes, &ctx_bytes)
            }
            m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => {
                verify_slh_dsa(m, ps, &pk_bytes, msg, sig_bytes, &ctx_bytes)
            }
            CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
            | CKM_SHA3_512_HMAC | CKM_RIPEMD160_HMAC => {
                verify_hmac(eff_mech, &pk_bytes, eff_msg, sig_bytes)
            }
            m if hmac_general_base(m).is_some() => {
                let (base, _) = hmac_general_base(m).unwrap();
                let mac_len = if ctx_bytes.len() >= 4 {
                    u32::from_le_bytes([ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3]])
                        as usize
                } else {
                    0
                };
                if sig_bytes.len() != mac_len {
                    Err(CKR_SIGNATURE_LEN_RANGE)
                } else {
                    match sign_hmac(base, &pk_bytes, eff_msg) {
                        Ok(mut mac) => {
                            use subtle::ConstantTimeEq;
                            mac.truncate(mac_len);
                            if mac.ct_eq(sig_bytes).into() {
                                Ok(())
                            } else {
                                Err(CKR_SIGNATURE_INVALID)
                            }
                        }
                        Err(e) => Err(e),
                    }
                }
            }
            CKM_KMAC_128 | CKM_KMAC_256 => match {
                if ctx_bytes.len() >= 4 {
                    let out_len = u32::from_le_bytes([
                        ctx_bytes[0],
                        ctx_bytes[1],
                        ctx_bytes[2],
                        ctx_bytes[3],
                    ]) as usize;
                    sign_kmac_ext(eff_mech, &pk_bytes, eff_msg, &ctx_bytes[4..], out_len)
                } else {
                    sign_kmac(eff_mech, &pk_bytes, eff_msg)
                }
            } {
                Ok(sig) => {
                    use subtle::ConstantTimeEq;
                    if sig.len() == sig_bytes.len() && sig.ct_eq(sig_bytes).into() {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
                Err(e) => Err(e),
            },
            // PKCS#11 v3.2: RSA public key material is in CKA_MODULUS + CKA_PUBLIC_EXPONENT.
            // CKA_VALUE is NOT defined for CKO_PUBLIC_KEY/CKK_RSA objects.
            CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
            | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS
            | CKM_SHA3_384_RSA_PKCS | CKM_SHA3_384_RSA_PKCS_PSS | CKM_RSA_PKCS => {
                match get_rsa_public_components(hkey) {
                    Some((n, e)) => {
                        let pss_salt =
                            if rsa_pss_mech_params(eff_mech).is_some() && ctx_bytes.len() >= 4 {
                                Some(u32::from_le_bytes([
                                    ctx_bytes[0],
                                    ctx_bytes[1],
                                    ctx_bytes[2],
                                    ctx_bytes[3],
                                ]) as usize)
                            } else {
                                None
                            };
                        verify_rsa(eff_mech, &n, &e, eff_msg, sig_bytes, pss_salt)
                    }
                    None => Err(CKR_KEY_TYPE_INCONSISTENT),
                }
            }
            // R-1 (2026-08-24) — bare CKM_RSA_PKCS_PSS, mirroring C_Sign's
            // own CKM_RSA_PKCS_PSS arm: `eff_msg` is already a digest, and
            // ctx_bytes is the 12-byte hashAlg||mgf||sLen format.
            CKM_RSA_PKCS_PSS => {
                if ctx_bytes.len() < 12 {
                    Err(CKR_MECHANISM_PARAM_INVALID)
                } else {
                    let hash_alg = u32::from_le_bytes([
                        ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3],
                    ]);
                    let s_len = u32::from_le_bytes([
                        ctx_bytes[8], ctx_bytes[9], ctx_bytes[10], ctx_bytes[11],
                    ]) as usize;
                    match get_rsa_public_components(hkey) {
                        Some((n, e)) => verify_rsa_pss_bare(hash_alg, &n, &e, eff_msg, sig_bytes, s_len),
                        None => Err(CKR_KEY_TYPE_INCONSISTENT),
                    }
                }
            }
            // PKCS#11 v3.2: EC public key material is in CKA_EC_POINT.
            CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512
            | CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256 | CKM_ECDSA_SHA3_384 | CKM_ECDSA_SHA3_512 => {
                match &ec_point_bytes {
                    Some(b) => verify_ecdsa(eff_mech, ps, b, eff_msg, sig_bytes),
                    None => Err(CKR_KEY_TYPE_INCONSISTENT),
                }
            }
            CKM_EDDSA => verify_eddsa(&pk_bytes, eff_msg, sig_bytes),
            CKM_EDDSA_PH => verify_eddsa_ph(&pk_bytes, eff_msg, sig_bytes),
            _ => Err(CKR_MECHANISM_INVALID),
        } {
            Ok(()) => CKR_OK,
            Err(e) => e,
        };
        // Consume verify state after the actual verify operation
        VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
        rv
    }
}

// ── Message-based Sign/Verify API ───────────────────────────────────────────

#[wasm_bindgen(js_name = _C_MessageSignInit)]
pub fn C_MessageSignInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    C_SignInit(h_session, p_mechanism, h_key)
}

#[wasm_bindgen(js_name = _C_SignMessage)]
pub fn C_SignMessage(
    h_session: u32,
    _p_param: *mut u8,
    _ul_param_len: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    require_init!();
    let saved = SIGN_STATE.with(|s| s.borrow().get(&h_session).cloned());
    let rv = C_Sign(
        h_session,
        p_data,
        ul_data_len,
        p_signature,
        pul_signature_len,
    );
    if let Some(st) = saved {
        SIGN_STATE.with(|s| {
            s.borrow_mut().insert(h_session, st);
        });
    }
    rv
}

#[wasm_bindgen(js_name = _C_MessageSignFinal)]
pub fn C_MessageSignFinal(h_session: u32) -> u32 {
    // pkcs11f.h shape: (CK_SESSION_HANDLE) only. §5.14 — must follow an
    // active message-based sign operation.
    require_init!();
    MESSAGE_SIGN_ACC.with(|s| {
        s.borrow_mut().remove(&h_session);
    });
    let had = SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session).is_some());
    if had {
        CKR_OK
    } else {
        CKR_OPERATION_NOT_INITIALIZED
    }
}

/// §5.14 — start one multipart message inside an active message-sign op.
#[wasm_bindgen(js_name = _C_SignMessageBegin)]
pub fn C_SignMessageBegin(h_session: u32, _p_param: *mut u8, _ul_param_len: u32) -> u32 {
    require_init!();
    if !SIGN_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    MESSAGE_SIGN_ACC.with(|s| {
        s.borrow_mut().insert(h_session, Vec::new());
    });
    CKR_OK
}

/// §5.14 — feed a message part. `pulSignatureLen == NULL` marks a non-final
/// part; non-NULL marks the final part (then NULL `pSignature` is the §5.2
/// length query, which does not consume the accumulated message).
#[wasm_bindgen(js_name = _C_SignMessageNext)]
pub fn C_SignMessageNext(
    h_session: u32,
    _p_param: *mut u8,
    _ul_param_len: u32,
    p_part: *mut u8,
    ul_part_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    require_init!();
    if !SIGN_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let in_msg = MESSAGE_SIGN_ACC.with(|s| s.borrow().contains_key(&h_session));
    if !in_msg {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if p_part.is_null() && ul_part_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let part = if ul_part_len > 0 {
        unsafe { std::slice::from_raw_parts(p_part, ul_part_len as usize).to_vec() }
    } else {
        Vec::new()
    };
    if pul_signature_len.is_null() {
        // non-final part — accumulate
        MESSAGE_SIGN_ACC.with(|s| {
            if let Some(acc) = s.borrow_mut().get_mut(&h_session) {
                acc.extend_from_slice(&part);
            }
        });
        return CKR_OK;
    }
    // final part — assemble full message; sign via the C_Sign machinery,
    // preserving SIGN_STATE so further messages can follow (§5.14).
    let mut full = MESSAGE_SIGN_ACC
        .with(|s| s.borrow().get(&h_session).cloned())
        .unwrap_or_default();
    full.extend_from_slice(&part);
    if full.is_empty() {
        full.push(0); // keep the pointer valid; len passed separately
        let saved = SIGN_STATE.with(|s| s.borrow().get(&h_session).cloned());
        let rv = C_Sign(h_session, full.as_mut_ptr(), 0, p_signature, pul_signature_len);
        if let Some(st) = saved {
            SIGN_STATE.with(|s| {
                s.borrow_mut().insert(h_session, st);
            });
        }
        if rv == CKR_OK && !p_signature.is_null() {
            MESSAGE_SIGN_ACC.with(|s| {
                s.borrow_mut().insert(h_session, Vec::new());
            });
        }
        return rv;
    }
    let full_len = full.len() as u32;
    let saved = SIGN_STATE.with(|s| s.borrow().get(&h_session).cloned());
    let rv = C_Sign(
        h_session,
        full.as_mut_ptr(),
        full_len,
        p_signature,
        pul_signature_len,
    );
    if let Some(st) = saved {
        SIGN_STATE.with(|s| {
            s.borrow_mut().insert(h_session, st);
        });
    }
    // length query / BUFFER_TOO_SMALL keep the accumulated message intact
    if rv == CKR_OK && !p_signature.is_null() {
        MESSAGE_SIGN_ACC.with(|s| {
            s.borrow_mut().insert(h_session, Vec::new());
        });
    }
    rv
}

#[wasm_bindgen(js_name = _C_MessageVerifyInit)]
pub fn C_MessageVerifyInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    C_VerifyInit(h_session, p_mechanism, h_key)
}

#[wasm_bindgen(js_name = _C_VerifyMessage)]
pub fn C_VerifyMessage(
    h_session: u32,
    _p_param: *mut u8,
    _ul_param_len: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    ul_signature_len: u32,
) -> u32 {
    require_init!();
    let saved = VERIFY_STATE.with(|s| s.borrow().get(&h_session).cloned());
    let rv = C_Verify(
        h_session,
        p_data,
        ul_data_len,
        p_signature,
        ul_signature_len,
    );
    if let Some(st) = saved {
        VERIFY_STATE.with(|s| {
            s.borrow_mut().insert(h_session, st);
        });
    }
    rv
}

#[wasm_bindgen(js_name = _C_MessageVerifyFinal)]
pub fn C_MessageVerifyFinal(h_session: u32) -> u32 {
    require_init!();
    MESSAGE_VERIFY_ACC.with(|s| {
        s.borrow_mut().remove(&h_session);
    });
    let had = VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session).is_some());
    if had {
        CKR_OK
    } else {
        CKR_OPERATION_NOT_INITIALIZED
    }
}

/// §5.15 — start one multipart message inside an active message-verify op.
#[wasm_bindgen(js_name = _C_VerifyMessageBegin)]
pub fn C_VerifyMessageBegin(h_session: u32, _p_param: *mut u8, _ul_param_len: u32) -> u32 {
    require_init!();
    if !VERIFY_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    MESSAGE_VERIFY_ACC.with(|s| {
        s.borrow_mut().insert(h_session, Vec::new());
    });
    CKR_OK
}

/// §5.15 — feed a message part. NULL `pSignature` marks a non-final part;
/// non-NULL carries the signature and finalizes the message.
#[wasm_bindgen(js_name = _C_VerifyMessageNext)]
pub fn C_VerifyMessageNext(
    h_session: u32,
    _p_param: *mut u8,
    _ul_param_len: u32,
    p_part: *mut u8,
    ul_part_len: u32,
    p_signature: *mut u8,
    ul_signature_len: u32,
) -> u32 {
    require_init!();
    if !VERIFY_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if !MESSAGE_VERIFY_ACC.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if p_part.is_null() && ul_part_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let part = if ul_part_len > 0 {
        unsafe { std::slice::from_raw_parts(p_part, ul_part_len as usize).to_vec() }
    } else {
        Vec::new()
    };
    if p_signature.is_null() {
        MESSAGE_VERIFY_ACC.with(|s| {
            if let Some(acc) = s.borrow_mut().get_mut(&h_session) {
                acc.extend_from_slice(&part);
            }
        });
        return CKR_OK;
    }
    let mut full = MESSAGE_VERIFY_ACC
        .with(|s| s.borrow().get(&h_session).cloned())
        .unwrap_or_default();
    full.extend_from_slice(&part);
    let full_len = full.len() as u32;
    if full.is_empty() {
        full.push(0);
    }
    let saved = VERIFY_STATE.with(|s| s.borrow().get(&h_session).cloned());
    let rv = C_Verify(h_session, full.as_mut_ptr(), full_len, p_signature, ul_signature_len);
    if let Some(st) = saved {
        VERIFY_STATE.with(|s| {
            s.borrow_mut().insert(h_session, st);
        });
    }
    MESSAGE_VERIFY_ACC.with(|s| {
        s.borrow_mut().insert(h_session, Vec::new());
    });
    rv
}

// ── Signature-only Verification (PKCS#11 v3.2 Pre-bound Verify) ─────────────

#[wasm_bindgen(js_name = _C_VerifySignatureInit)]
pub fn C_VerifySignatureInit(
    h_session: u32,
    p_mechanism: *mut u8,
    h_key: u32,
    p_signature: *mut u8,
    ul_signature_len: u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::VerifySignature) {
        return rv;
    }
    unsafe {
        if p_mechanism.is_null() || p_signature.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.12.4 — key handle, visibility, and CKA_VERIFY permission.
        if let Err(rv) = check_key_usage(h_session, h_key, CKA_VERIFY) {
            return rv;
        }
        let mut mech_type = ck_param::mech(p_mechanism).mechanism;
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS, checked before any remap.
        if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
            return rv;
        }
        if mech_type == CKM_EDDSA {
            if eddsa_ph_flag(p_mechanism) {
                mech_type = CKM_EDDSA_PH;
            }
        }
        // GENERIC pre-hash mechanisms (CKM_HASH_ML_DSA/CKM_HASH_SLH_DSA)
        // remap onto the concrete hash-specific mechanism via their
        // CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash param.
        mech_type = match remap_generic_hash_mech(p_mechanism, mech_type) {
            Ok(m) => m,
            Err(rv) => return rv,
        };
        // Mechanism parameters — see parse_sign_mech_params (shared with
        // the other two *SignInit/*VerifyInit entry points).
        let (slh_ctx, slh_det) = match parse_sign_mech_params(p_mechanism, mech_type) {
            Ok(v) => v,
            Err(rv) => return rv,
        };
        let signature = std::slice::from_raw_parts(p_signature, ul_signature_len as usize).to_vec();

        VERIFY_SIG_STATE.with(|s| {
            s.borrow_mut().insert(
                h_session,
                VerifySigCtx {
                    mech_type,
                    key_handle: h_key,
                    signature,
                    msg_acc: Vec::new(),
                    slh_ctx,
                    slh_det,
                },
            );
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_VerifySignature)]
pub fn C_VerifySignature(h_session: u32, p_data: *mut u8, ul_data_len: u32) -> u32 {
    require_init!();
    let state = VERIFY_SIG_STATE.with(|s| s.borrow_mut().remove(&h_session));
    if let Some(ctx) = state {
        VERIFY_STATE.with(|s| {
            s.borrow_mut().insert(
                h_session,
                (ctx.mech_type, ctx.key_handle, ctx.slh_ctx, ctx.slh_det),
            );
        });
        let mut sig_clone = ctx.signature.clone();
        C_Verify(
            h_session,
            p_data,
            ul_data_len,
            sig_clone.as_mut_ptr(),
            sig_clone.len() as u32,
        )
    } else {
        CKR_OPERATION_NOT_INITIALIZED
    }
}

#[wasm_bindgen(js_name = _C_VerifySignatureUpdate)]
pub fn C_VerifySignatureUpdate(h_session: u32, p_part: *mut u8, ul_part_len: u32) -> u32 {
    require_init!();
    let mut ok = false;
    VERIFY_SIG_STATE.with(|s| {
        if let Some(ctx) = s.borrow_mut().get_mut(&h_session) {
            if ul_part_len > 0 {
                unsafe {
                    let part = std::slice::from_raw_parts(p_part, ul_part_len as usize);
                    ctx.msg_acc.extend_from_slice(part);
                }
            }
            ok = true;
        }
    });
    if ok {
        CKR_OK
    } else {
        CKR_OPERATION_NOT_INITIALIZED
    }
}

#[wasm_bindgen(js_name = _C_VerifySignatureFinal)]
pub fn C_VerifySignatureFinal(h_session: u32) -> u32 {
    require_init!();
    let state = VERIFY_SIG_STATE.with(|s| s.borrow_mut().remove(&h_session));
    if let Some(ctx) = state {
        VERIFY_STATE.with(|s| {
            s.borrow_mut().insert(
                h_session,
                (ctx.mech_type, ctx.key_handle, ctx.slh_ctx, ctx.slh_det),
            );
        });
        // Keep a 1-byte backing buffer for the empty-message case so the
        // pointer passed to C_Verify is always valid (len stays 0) — the old
        // `4 as *mut u8` fabricated-address trick was UB-adjacent.
        let mut data = ctx.msg_acc.clone();
        let data_len = data.len() as u32;
        if data.is_empty() {
            data.push(0);
        }
        let mut sig = ctx.signature.clone();
        C_Verify(
            h_session,
            data.as_mut_ptr(),
            data_len,
            sig.as_mut_ptr(),
            sig.len() as u32,
        )
    } else {
        CKR_OPERATION_NOT_INITIALIZED
    }
}

/// Build an `rsa::Oaep` from CK_RSA_PKCS_OAEP_PARAMS fields (§6.4.4).
/// Supported: hashAlg ∈ {SHA-256, SHA-384, SHA-512} × mgf ∈ {MGF1-SHA256,
/// MGF1-SHA384, MGF1-SHA512}; label = pSourceData (the `rsa` crate models the
/// label as UTF-8, so non-UTF-8 labels are rejected).
fn oaep_padding(hash_alg: u32, mgf: u32, label: &[u8]) -> Result<rsa::Oaep, u32> {
    let label_s: Option<String> = if label.is_empty() {
        None
    } else {
        Some(String::from_utf8(label.to_vec()).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?)
    };
    macro_rules! oaep {
        ($h:ty, $m:ty) => {
            match label_s {
                Some(l) => rsa::Oaep::new_with_mgf_hash_and_label::<$h, $m, String>(l),
                None => rsa::Oaep::new_with_mgf_hash::<$h, $m>(),
            }
        };
    }
    Ok(match (hash_alg, mgf) {
        (CKM_SHA256, CKG_MGF1_SHA256) | (CKM_SHA256, 0) => oaep!(sha2::Sha256, sha2::Sha256),
        (CKM_SHA256, CKG_MGF1_SHA384) => oaep!(sha2::Sha256, sha2::Sha384),
        (CKM_SHA256, CKG_MGF1_SHA512) => oaep!(sha2::Sha256, sha2::Sha512),
        (CKM_SHA384, CKG_MGF1_SHA256) => oaep!(sha2::Sha384, sha2::Sha256),
        (CKM_SHA384, CKG_MGF1_SHA384) | (CKM_SHA384, 0) => oaep!(sha2::Sha384, sha2::Sha384),
        (CKM_SHA384, CKG_MGF1_SHA512) => oaep!(sha2::Sha384, sha2::Sha512),
        (CKM_SHA512, CKG_MGF1_SHA256) => oaep!(sha2::Sha512, sha2::Sha256),
        (CKM_SHA512, CKG_MGF1_SHA384) => oaep!(sha2::Sha512, sha2::Sha384),
        (CKM_SHA512, CKG_MGF1_SHA512) | (CKM_SHA512, 0) => oaep!(sha2::Sha512, sha2::Sha512),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    })
}

/// Parse CK_RSA_PKCS_OAEP_PARAMS (§6.4.4: hashAlg, mgf, source, pSourceData,
/// ulSourceDataLen) at NATIVE width → (hashAlg, mgf, label). Absent/short
/// param keeps the legacy default (SHA-256, MGF1-SHA256, no label).
///
/// Fixed from a hardcoded-4-byte-word parse (`*const u32`), which only
/// matched wasm32's 4-byte `usize`/`CK_ULONG` layout and misparsed on
/// native 64-bit builds (where `CK_ULONG`/pointer fields are 8 bytes —
/// `pSourceData` at word-index 3 would land at the wrong byte offset
/// entirely, and `ulSourceDataLen` past it further still). Same bug class
/// `CKM_AES_GCM`'s and `CKM_CHACHA20_POLY1305`'s params parsing already
/// had fixed elsewhere in this file (see `parse_chacha20_params` above for
/// the exact precedent this copies: read as `*const usize`, which is 4
/// bytes on wasm32 and 8 bytes on native 64-bit — one code path, both
/// targets, matching the real struct's actual field width on each).
unsafe fn parse_oaep_params(p_param: *const u8, ul_param_len: usize) -> Result<(u32, u32, Vec<u8>), u32> {
    // Read progressively: a hashAlg-only prefix is meaningful here (it is
    // what several callers send), so the reader is built for ONE field and
    // `covers()` decides whether the rest is present. Both thresholds come
    // from the declaration, not from `usz` arithmetic at the call site.
    let r = match ParamReader::optional(p_param, ul_param_len, &ck_param::oaep::LAYOUT, 1) {
        Ok(Some(r)) => r,
        _ => return Ok((CKM_SHA256, CKG_MGF1_SHA256, Vec::new())),
    };
    let hash_alg = r.ulong32(ck_param::oaep::HASH_ALG);
    if !r.covers(ck_param::oaep::FIELD_COUNT) {
        return Ok((hash_alg, 0, Vec::new()));
    }
    let mgf = r.ulong32(ck_param::oaep::MGF);
    let source = r.ulong32(ck_param::oaep::SOURCE);
    let label = r.buffer(ck_param::oaep::P_SOURCE_DATA, ck_param::oaep::UL_SOURCE_DATA_LEN);
    if !label.is_empty() {
        // §6.4.4 — only CKZ_DATA_SPECIFIED carries a label.
        if source != CKZ_DATA_SPECIFIED {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
    }
    Ok((hash_alg, mgf, label.to_vec()))
}

// ── Encrypt/Decrypt ─────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_EncryptInit)]
pub fn C_EncryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::Encrypt) {
        return rv;
    }
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.2.5 — at most one active encryption operation
        // per session.
        if ENCRYPT_STATE.with(|s| s.borrow().contains_key(&h_session)) {
            return CKR_OPERATION_ACTIVE;
        }
        // PKCS#11 v3.2 §5.12.4 — key handle, visibility, and CKA_ENCRYPT permission.
        if let Err(rv) = check_key_usage(h_session, h_key, CKA_ENCRYPT) {
            return rv;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS.
        if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
            return rv;
        }
        let ck_param::Mech { p_parameter: p_param, ul_parameter_len: ul_param_len, .. } =
            ck_param::mech(p_mechanism);

        // W7 — `CK_CHACHA20_PARAMS.pBlockCounter`; stays 0 for every other
        // mechanism.
        let mut chacha_block_counter: u64 = 0;
        let (iv, aad, tag_bits) = match mech_type {
            CKM_AES_GCM => {
                // CK_GCM_PARAMS — 6 CK_ULONG/pointer fields (pIv, ulIvLen,
                // ulIvBits, pAAD, ulAADLen, ulTagBits) read at native width
                // (size_of::<usize>(): 24 B wasm32, 48 B native). Reading them
                // as u32 truncated pIv and shifted ulIvLen onto the pointer's
                // high half on 64-bit, so a valid 12-byte IV looked invalid.
                let gcm = match ParamReader::new(
                    p_param,
                    ul_param_len,
                    &ck_param::gcm::LAYOUT,
                    ck_param::gcm::FIELD_COUNT,
                ) {
                    Ok(r) => r,
                    Err(_) => return CKR_ARGUMENTS_BAD,
                };
                let iv_ptr = gcm.ptr(ck_param::gcm::P_IV);
                let iv_len = gcm.ulong(ck_param::gcm::UL_IV_LEN);
                let iv_bits = gcm.ulong32(ck_param::gcm::UL_IV_BITS);
                let aad_ptr = gcm.ptr(ck_param::gcm::P_AAD);
                let aad_len = gcm.ulong(ck_param::gcm::UL_AAD_LEN);
                let tag_bits = gcm.ulong32(ck_param::gcm::UL_TAG_BITS);
                // SP 800-38D §5.2.1.2 — permitted tag lengths {128,120,112,
                // 104,96} plus {64,32} for special applications (KMIP's
                // truncatable-tag feature uses these). 0 ⇒ default 128.
                if !matches!(tag_bits, 0 | 32 | 64 | 96 | 104 | 112 | 120 | 128) {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // ulIvBits, when supplied, must agree with ulIvLen (§6.27.7).
                if iv_bits != 0 && iv_bits as usize != iv_len * 8 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // PKCS#11 v3.2 §6.27.7 / SP 800-38D §8: the IV is REQUIRED and
                // must be unique per (key, encryption). A NULL/empty IV here is
                // never valid — silently substituting a fixed zero nonce would
                // be catastrophic nonce reuse. Reject per mechanism-param error.
                if iv_ptr.is_null() || iv_len == 0 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                if iv_len != 12 {
                    return CKR_MECHANISM_PARAM_INVALID; // AES-GCM requires a 12-byte nonce
                }
                let iv = std::slice::from_raw_parts(iv_ptr, iv_len).to_vec();
                let aad = if !aad_ptr.is_null() && aad_len > 0 {
                    std::slice::from_raw_parts(aad_ptr, aad_len).to_vec()
                } else {
                    Vec::new()
                };
                (iv, aad, tag_bits)
            }
            // §6.27.2 — ECB takes no mechanism parameter.
            CKM_AES_ECB => (Vec::new(), Vec::new(), 0),
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if p_param.is_null() || ul_param_len < 16 {
                    return CKR_ARGUMENTS_BAD;
                }
                (
                    std::slice::from_raw_parts(p_param, 16).to_vec(),
                    Vec::new(),
                    0,
                )
            }
            CKM_AES_CTR => {
                // CK_AES_CTR_PARAMS (§6.11.2) — INSTANCE 1, now read through
                // ck_param so `cb`'s offset comes from the declaration
                // (4 on wasm32, 8 on LP64) rather than a literal.
                // tag_bits doubles as the mechanism's bits parameter: GCM tag
                // bits / CTR counter bits (see EncryptCtx).
                match parse_aes_ctr_params(p_param, ul_param_len) {
                    Ok((cb, bits)) => (cb, Vec::new(), bits),
                    Err(rv) => return rv,
                }
            }
            CKM_RSA_PKCS_OAEP => {
                // Full CK_RSA_PKCS_OAEP_PARAMS (§6.4.4). EncryptCtx packing:
                // tag_bits = hashAlg, aad = LE u32 mgf, iv = label bytes.
                let (hash_alg, mgf, label) = match parse_oaep_params(p_param, ul_param_len) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                };
                (label, mgf.to_le_bytes().to_vec(), hash_alg)
            }
            // R-2 (2026-08-24) — raw PKCS#1 v1.5, §6.4.1: takes NO mechanism
            // parameter (same as CKM_AES_ECB above). See CKM_RSA_PKCS's arm
            // in C_Decrypt below for this mechanism's full risk-acceptance
            // documentation (encrypt is the public-key half; it carries none
            // of the padding-oracle risk decrypt does).
            CKM_RSA_PKCS => (Vec::new(), Vec::new(), 0),
            CKM_CHACHA20_POLY1305 => {
                // CK_SALSA20_CHACHA20_POLY1305_PARAMS (§6.21). The old length
                // guard was a literal 16 — the struct's wasm32 sizeof. On LP64
                // it is 32, so a 16-byte parameter passed the guard and pAAD /
                // ulAADLen were then read from PAST the caller's buffer. The
                // field OFFSETS were already right, which is why the earlier
                // audit cleared this struct; the length was not.
                let r = match ParamReader::new(
                    p_param,
                    ul_param_len,
                    &ck_param::salsa20_poly1305::LAYOUT,
                    ck_param::salsa20_poly1305::FIELD_COUNT,
                ) {
                    Ok(r) => r,
                    Err(_) => return CKR_ARGUMENTS_BAD,
                };
                if r.ulong(ck_param::salsa20_poly1305::UL_NONCE_LEN) != 12 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let nonce = r
                    .buffer(
                        ck_param::salsa20_poly1305::P_NONCE,
                        ck_param::salsa20_poly1305::UL_NONCE_LEN,
                    )
                    .to_vec();
                let aad = r
                    .buffer(
                        ck_param::salsa20_poly1305::P_AAD,
                        ck_param::salsa20_poly1305::UL_AAD_LEN,
                    )
                    .to_vec();
                (nonce, aad, 0)
            }
            // T1 — plain ChaCha20 stream cipher (§6.20), advertised since
            // round-1 S1 but previously not dispatched on the wasm path.
            CKM_CHACHA20 => match parse_chacha20_params(p_param, ul_param_len) {
                // W7 — the starting block counter travels with the op.
                Ok((nonce, ctr)) => {
                    chacha_block_counter = ctr;
                    (nonce, Vec::new(), 0)
                }
                Err(rv) => return rv,
            },
            _ => return CKR_MECHANISM_INVALID,
        };

        ENCRYPT_STATE.with(|s| {
            s.borrow_mut().insert(
                h_session,
                EncryptCtx {
                    mech_type,
                    key_handle: h_key,
                    iv,
                    aad,
                    tag_bits,
                    multipart: None,
                    block_counter: chacha_block_counter,
                },
            );
        });
    }
    CKR_OK
}

/// Parse a `CK_CHACHA20_PARAMS` (PKCS#11 v3.2 §6.20) and return
/// `(nonce_bytes, start_block_counter)`.
///
/// W7 (2026-08-13). Two defects, both here:
///
/// * `blockCounterBits` — the field "can be either 32 or 64". The old code
///   accepted ANY width from 1 to 64.
/// * `pBlockCounter` — the old code REJECTED any non-zero starting counter,
///   which defeats the field's whole reason for existing: §6.20 says the
///   counter is exposed because "in certain settings (e.g. disk encryption)
///   it is necessary to address these blocks in random order". Random-access
///   ChaCha20 was therefore unusable through this engine.
///
/// The nonce/counter pair is validated as the two ChaCha20 variants define
/// it: a 96-bit (IETF, RFC 8439) nonce pairs with a 32-bit counter, and a
/// 64-bit (original DJB / "legacy") nonce with a 64-bit counter. Any other
/// combination is `CKR_MECHANISM_PARAM_INVALID` rather than being silently
/// coerced. The counter is little-endian, matching both variants' own
/// serialisation of the block-count word(s).
///
/// `CK_AES_CTR_PARAMS` (PKCS#11 v3.2 §6.11.2):
///
/// ```text
/// typedef struct CK_AES_CTR_PARAMS {
///     CK_ULONG ulCounterBits;
///     CK_BYTE  cb[16];
/// } CK_AES_CTR_PARAMS;
/// ```
///
/// **Instance 1 of the parameter-width defect.** `cb` was taken at a
/// hard-coded offset 4, so on an LP64 build the engine read the high half of
/// `ulCounterBits` as `cb[0..4]` and dropped the caller's real `cb[12..16]`:
/// `a0a1…aeaf` became `00000000a0a1…aaab`, and EVERY AES-CTR ciphertext the
/// native library ever produced was non-interoperable, at every counter
/// width. Verified numerically against OpenSSL and NIST SP 800-38A in
/// `844ed27`.
///
/// Shared by `C_EncryptInit` and `C_DecryptInit`, which had byte-identical
/// copies of the decode.
///
/// # Safety
/// `p_param` must point to `ul_param_len` readable bytes.
unsafe fn parse_aes_ctr_params(p_param: *const u8, ul_param_len: usize) -> Result<(Vec<u8>, u32), u32> {
    let r = ParamReader::new(
        p_param,
        ul_param_len,
        &ck_param::aes_ctr::LAYOUT,
        ck_param::aes_ctr::FIELD_COUNT,
    )
    .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    // §6.11.2 — "This number shall be such that 0 < ulCounterBits ≤ 128. For
    // any values outside this range the mechanism shall return
    // CKR_MECHANISM_PARAM_INVALID." Engine restriction: byte-granular widths
    // only (8,16,…,128).
    let counter_bits = r.ulong(ck_param::aes_ctr::UL_COUNTER_BITS);
    if counter_bits == 0 || counter_bits > 128 || counter_bits % 8 != 0 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    Ok((r.bytes(ck_param::aes_ctr::CB).to_vec(), counter_bits as u32))
}

/// # Safety
/// `p_param` must point to `ul_param_len` readable bytes.
unsafe fn parse_chacha20_params(
    p_param: *const u8,
    ul_param_len: usize,
) -> Result<(Vec<u8>, u64), u32> {
    let r = ParamReader::new(
        p_param,
        ul_param_len,
        &ck_param::chacha20::LAYOUT,
        ck_param::chacha20::FIELD_COUNT,
    )
    .map_err(|_| CKR_ARGUMENTS_BAD)?;
    let ctr_ptr = r.ptr(ck_param::chacha20::P_BLOCK_COUNTER);
    let ctr_bits = r.ulong(ck_param::chacha20::BLOCK_COUNTER_BITS);
    let nonce_ptr = r.ptr(ck_param::chacha20::P_NONCE);
    let nonce_bits = r.ulong(ck_param::chacha20::UL_NONCE_BITS);
    if nonce_ptr.is_null() || !(nonce_bits == 64 || nonce_bits == 96) {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let mut counter: u64 = 0;
    if ctr_ptr.is_null() {
        // No counter supplied: block 0, and the width field is then moot.
        if ctr_bits != 0 && ctr_bits != 32 && ctr_bits != 64 {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
    } else {
        // §6.20 — "can be either 32 or 64".
        if ctr_bits != 32 && ctr_bits != 64 {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        // The two variants' counter widths are fixed by their nonce widths.
        let expected_ctr_bits = if nonce_bits == 96 { 32 } else { 64 };
        if ctr_bits != expected_ctr_bits {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        let ctr = std::slice::from_raw_parts(ctr_ptr, ctr_bits / 8);
        for (i, b) in ctr.iter().enumerate() {
            counter |= (*b as u64) << (8 * i);
        }
    }
    Ok((
        std::slice::from_raw_parts(nonce_ptr, nonce_bits / 8).to_vec(),
        counter,
    ))
}

#[wasm_bindgen(js_name = _C_Encrypt)]
pub fn C_Encrypt(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_encrypted_data: *mut u8,
    pul_encrypted_data_len: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // Remove state on entry — consumed on all paths except null-buffer size query
    let ctx = ENCRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
    let ctx = match ctx {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    // PKCS#11 v3.2 §5.2 — a one-shot C_Encrypt after C_EncryptUpdate is a
    // sequencing error; the streaming op must be completed with C_EncryptFinal.
    // Preserve the in-flight multipart op and reject the misuse.
    if ctx.multipart.is_some() {
        ENCRYPT_STATE.with(|s| s.borrow_mut().insert(h_session, ctx));
        return CKR_OPERATION_ACTIVE;
    }
    let (mech_type, key_handle, iv, aad, tag_bits, block_counter) = (
        ctx.mech_type,
        ctx.key_handle,
        ctx.iv,
        ctx.aad,
        ctx.tag_bits,
        // W7 — CKM_CHACHA20's starting keystream block; 0 elsewhere.
        ctx.block_counter,
    );
    let key_bytes = match get_object_value(key_handle) {
        Some(v) => v,
        None => return CKR_ARGUMENTS_BAD,
    };

    // §5.2 — pData is the INPUT; NULL with a nonzero length is
    // CKR_ARGUMENTS_BAD (only output buffers may be NULL for the two-call
    // size query). NULL with zero length is an empty input, consistent
    // with C_Decrypt and C_SignMessageNext.
    if p_data.is_null() && ul_data_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let plaintext: &[u8] = if p_data.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(p_data, ul_data_len as usize)
        };
        let ct = match mech_type {
            CKM_AES_GCM => {
                // GcmState honours ulTagBits (truncated tags) and keeps the
                // single-shot path byte-identical to multipart (§6.27.7).
                use crate::crypto::multipart::{AesKey, CipherDirection, GcmState, MultipartCipher};
                let key = match AesKey::new(&key_bytes) {
                    Some(k) => k,
                    None => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let iv12: [u8; 12] = match iv.as_slice().try_into() {
                    Ok(v) => v,
                    Err(_) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let mut gcm = MultipartCipher::Gcm(GcmState::new(
                    key,
                    &iv12,
                    &aad,
                    tag_bits,
                    CipherDirection::Encrypt,
                ));
                let mut out = match gcm.update(plaintext) {
                    Ok(o) => o,
                    Err(rv) => return rv,
                };
                match gcm.finalize() {
                    Ok(tag) => out.extend_from_slice(&tag),
                    Err(rv) => return rv,
                }
                out
            }
            CKM_AES_CBC_PAD => {
                use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
                type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
                type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
                let padded_len = plaintext.len() + 16 - (plaintext.len() % 16);
                let mut buf = vec![0u8; padded_len];
                buf[..plaintext.len()].copy_from_slice(plaintext);
                match key_bytes.len() {
                    16 => match Aes128CbcEnc::new_from_slices(&key_bytes, &iv) {
                        Ok(cipher) => match cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len()) {
                            Ok(ct) => ct.to_vec(),
                            Err(_) => return CKR_FUNCTION_FAILED,
                        },
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    },
                    32 => match Aes256CbcEnc::new_from_slices(&key_bytes, &iv) {
                        Ok(cipher) => match cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len()) {
                            Ok(ct) => ct.to_vec(),
                            Err(_) => return CKR_FUNCTION_FAILED,
                        },
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    },
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                }
            }
            CKM_AES_CTR => {
                // CTR is its own inverse. Width-aware keystream honours
                // ulCounterBits (stored in tag_bits) — §6.27.6.
                use crate::crypto::multipart::{AesKey, CtrState};
                let key = match AesKey::new(&key_bytes) {
                    Some(k) => k,
                    None => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let cb: [u8; 16] = match iv.as_slice().try_into() {
                    Ok(c) => c,
                    Err(_) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let width = ((tag_bits.max(8)) / 8) as usize;
                let mut ctr = CtrState::new_with_width(key, cb, width);
                ctr.update_public(plaintext)
            }
            CKM_RSA_PKCS_OAEP => {
                if key_bytes.len() < 8 {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
                let n_len =
                    u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]])
                        as usize;
                if key_bytes.len() < 4 + n_len + 1 {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
                let n = rsa::BigUint::from_bytes_be(&key_bytes[4..4 + n_len]);
                let e = rsa::BigUint::from_bytes_be(&key_bytes[4 + n_len..]);
                let pk = match rsa::RsaPublicKey::new(n, e) {
                    Ok(k) => k,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let mgf = if aad.len() >= 4 {
                    u32::from_le_bytes([aad[0], aad[1], aad[2], aad[3]])
                } else {
                    0
                };
                let oaep = match oaep_padding(tag_bits, mgf, &iv) {
                    Ok(o) => o,
                    Err(rv) => return rv,
                };
                with_rng!(rng, {
                    match pk.encrypt(&mut rng, oaep, plaintext) {
                        Ok(ct) => ct,
                        Err(_) => return CKR_FUNCTION_FAILED,
                    }
                })
            }
            // R-2 (2026-08-24) — raw PKCS#1 v1.5 encrypt (§6.4.1): the
            // public-key half of this mechanism. No decrypt-oracle risk
            // applies here (that only exists on the DECRYPT side — see
            // CKM_RSA_PKCS's arm in C_Decrypt below for the full,
            // reviewed-and-accepted risk documentation covering this
            // mechanism). Same key_bytes layout (`4-byte LE n_len || n ||
            // e`) and `rsa` crate integration pattern as CKM_RSA_PKCS_OAEP
            // just above.
            CKM_RSA_PKCS => {
                if key_bytes.len() < 8 {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
                let n_len =
                    u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]])
                        as usize;
                if key_bytes.len() < 4 + n_len + 1 {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
                let n = rsa::BigUint::from_bytes_be(&key_bytes[4..4 + n_len]);
                let e = rsa::BigUint::from_bytes_be(&key_bytes[4 + n_len..]);
                let pk = match rsa::RsaPublicKey::new(n, e) {
                    Ok(k) => k,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                with_rng!(rng, {
                    match pk.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, plaintext) {
                        Ok(ct) => ct,
                        Err(_) => return CKR_FUNCTION_FAILED,
                    }
                })
            }
            CKM_CHACHA20_POLY1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, Payload}};
                use chacha20poly1305::aead::generic_array::GenericArray;
                if key_bytes.len() != 32 {
                    return CKR_KEY_SIZE_RANGE;
                }
                if iv.len() != 12 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));
                let nonce = GenericArray::from_slice(&iv);
                match cipher.encrypt(nonce, Payload { msg: plaintext, aad: &aad }) {
                    Ok(ct) => ct,
                    Err(_) => return CKR_FUNCTION_FAILED,
                }
            }
            // T1 — plain ChaCha20 (§6.20). Same primitive as the native
            // engine path: 32-byte key, 8-byte (legacy) or 12-byte (IETF)
            // nonce, keystream from block 0.
            CKM_CHACHA20 => {
                if key_bytes.len() != 32 {
                    return CKR_KEY_SIZE_RANGE;
                }
                match crate::native::encrypt::chacha20_encrypt_at(&key_bytes, &iv, plaintext, block_counter) {
                    Ok(ct) => ct,
                    Err(rv) => return rv,
                }
            }
            CKM_AES_ECB | CKM_AES_CBC => {
                // §6.27.2/§6.27.3 — raw block modes; reuse the streaming
                // state machines as update-then-finalize in one go.
                use crate::crypto::multipart::*;
                let key = match AesKey::new(&key_bytes) {
                    Some(k) => k,
                    None => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let mut mp = if mech_type == CKM_AES_ECB {
                    MultipartCipher::Ecb(EcbState::new(key, CipherDirection::Encrypt))
                } else {
                    let iv_arr: [u8; 16] = match iv.as_slice().try_into() {
                        Ok(v) => v,
                        Err(_) => return CKR_MECHANISM_PARAM_INVALID,
                    };
                    MultipartCipher::Cbc(CbcState::new(key, iv_arr, CipherDirection::Encrypt))
                };
                let mut out = match mp.update(plaintext) {
                    Ok(o) => o,
                    Err(rv) => return rv,
                };
                match mp.finalize() {
                    Ok(tail) => out.extend_from_slice(&tail),
                    Err(rv) => return rv, // CKR_DATA_LEN_RANGE on residue
                }
                out
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        // PKCS#11 v3.2 §5.2 — neither a NULL-buffer length query nor a
        // CKR_BUFFER_TOO_SMALL may terminate the operation. Re-insert the state
        // for both so the caller can retry with an adequate buffer. (Preserve
        // aad: the retry recomputes the tag from the same AAD bytes.)
        let need = ct.len();
        let too_small = !p_encrypted_data.is_null() && (*pul_encrypted_data_len as usize) < need;
        if p_encrypted_data.is_null() || too_small {
            *pul_encrypted_data_len = need as u32;
            ENCRYPT_STATE.with(|s| {
                s.borrow_mut().insert(
                    h_session,
                    EncryptCtx {
                        mech_type,
                        key_handle,
                        iv,
                        aad,
                        tag_bits,
                        multipart: None,
                        block_counter: 0,
                    },
                );
            });
            return if too_small { CKR_BUFFER_TOO_SMALL } else { CKR_OK };
        }
        std::ptr::copy_nonoverlapping(ct.as_ptr(), p_encrypted_data, need);
        *pul_encrypted_data_len = need as u32;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DecryptInit)]
pub fn C_DecryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::Decrypt) {
        return rv;
    }
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.2.9 — at most one active decryption operation
        // per session.
        if DECRYPT_STATE.with(|s| s.borrow().contains_key(&h_session)) {
            return CKR_OPERATION_ACTIVE;
        }
        // PKCS#11 v3.2 §5.12.4 — key handle, visibility, and CKA_DECRYPT permission.
        if let Err(rv) = check_key_usage(h_session, h_key, CKA_DECRYPT) {
            return rv;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS.
        if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
            return rv;
        }
        let ck_param::Mech { p_parameter: p_param, ul_parameter_len: ul_param_len, .. } =
            ck_param::mech(p_mechanism);

        // W7 — `CK_CHACHA20_PARAMS.pBlockCounter`; stays 0 for every other
        // mechanism.
        let mut chacha_block_counter: u64 = 0;
        let (iv, aad, tag_bits) = match mech_type {
            CKM_AES_GCM => {
                // CK_GCM_PARAMS — 6 CK_ULONG/pointer fields (pIv, ulIvLen,
                // ulIvBits, pAAD, ulAADLen, ulTagBits) read at native width
                // (size_of::<usize>(): 24 B wasm32, 48 B native). Reading them
                // as u32 truncated pIv and shifted ulIvLen onto the pointer's
                // high half on 64-bit, so a valid 12-byte IV looked invalid.
                let gcm = match ParamReader::new(
                    p_param,
                    ul_param_len,
                    &ck_param::gcm::LAYOUT,
                    ck_param::gcm::FIELD_COUNT,
                ) {
                    Ok(r) => r,
                    Err(_) => return CKR_ARGUMENTS_BAD,
                };
                let iv_ptr = gcm.ptr(ck_param::gcm::P_IV);
                let iv_len = gcm.ulong(ck_param::gcm::UL_IV_LEN);
                let iv_bits = gcm.ulong32(ck_param::gcm::UL_IV_BITS);
                let aad_ptr = gcm.ptr(ck_param::gcm::P_AAD);
                let aad_len = gcm.ulong(ck_param::gcm::UL_AAD_LEN);
                let tag_bits = gcm.ulong32(ck_param::gcm::UL_TAG_BITS);
                // SP 800-38D §5.2.1.2 — permitted tag lengths {128,120,112,
                // 104,96} plus {64,32} for special applications (KMIP's
                // truncatable-tag feature uses these). 0 ⇒ default 128.
                if !matches!(tag_bits, 0 | 32 | 64 | 96 | 104 | 112 | 120 | 128) {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // ulIvBits, when supplied, must agree with ulIvLen (§6.27.7).
                if iv_bits != 0 && iv_bits as usize != iv_len * 8 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // PKCS#11 v3.2 §6.27.7 / SP 800-38D §8: the IV is REQUIRED and
                // must be unique per (key, encryption). A NULL/empty IV here is
                // never valid — silently substituting a fixed zero nonce would
                // be catastrophic nonce reuse. Reject per mechanism-param error.
                if iv_ptr.is_null() || iv_len == 0 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                if iv_len != 12 {
                    return CKR_MECHANISM_PARAM_INVALID; // AES-GCM requires a 12-byte nonce
                }
                let iv = std::slice::from_raw_parts(iv_ptr, iv_len).to_vec();
                let aad = if !aad_ptr.is_null() && aad_len > 0 {
                    std::slice::from_raw_parts(aad_ptr, aad_len).to_vec()
                } else {
                    Vec::new()
                };
                (iv, aad, tag_bits)
            }
            // §6.27.2 — ECB takes no mechanism parameter.
            CKM_AES_ECB => (Vec::new(), Vec::new(), 0),
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if p_param.is_null() || ul_param_len < 16 {
                    return CKR_ARGUMENTS_BAD;
                }
                (
                    std::slice::from_raw_parts(p_param, 16).to_vec(),
                    Vec::new(),
                    0,
                )
            }
            CKM_AES_CTR => {
                // CK_AES_CTR_PARAMS (§6.11.2) — INSTANCE 1, now read through
                // ck_param so `cb`'s offset comes from the declaration
                // (4 on wasm32, 8 on LP64) rather than a literal.
                // tag_bits doubles as the mechanism's bits parameter: GCM tag
                // bits / CTR counter bits (see EncryptCtx).
                match parse_aes_ctr_params(p_param, ul_param_len) {
                    Ok((cb, bits)) => (cb, Vec::new(), bits),
                    Err(rv) => return rv,
                }
            }
            CKM_RSA_PKCS_OAEP => {
                // Full CK_RSA_PKCS_OAEP_PARAMS (§6.4.4). EncryptCtx packing:
                // tag_bits = hashAlg, aad = LE u32 mgf, iv = label bytes.
                let (hash_alg, mgf, label) = match parse_oaep_params(p_param, ul_param_len) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                };
                (label, mgf.to_le_bytes().to_vec(), hash_alg)
            }
            // R-2 (2026-08-24) — raw PKCS#1 v1.5, §6.4.1: takes NO mechanism
            // parameter (same as CKM_AES_ECB above). See CKM_RSA_PKCS's arm
            // in C_Decrypt below for this mechanism's full risk-acceptance
            // documentation.
            CKM_RSA_PKCS => (Vec::new(), Vec::new(), 0),
            // T1 — both ChaCha20 mechanisms advertise CKF_DECRYPT but were
            // previously only dispatched on the encrypt side of the wasm path.
            CKM_CHACHA20_POLY1305 => {
                // CK_SALSA20_CHACHA20_POLY1305_PARAMS (§6.21). The old length
                // guard was a literal 16 — the struct's wasm32 sizeof. On LP64
                // it is 32, so a 16-byte parameter passed the guard and pAAD /
                // ulAADLen were then read from PAST the caller's buffer. The
                // field OFFSETS were already right, which is why the earlier
                // audit cleared this struct; the length was not.
                let r = match ParamReader::new(
                    p_param,
                    ul_param_len,
                    &ck_param::salsa20_poly1305::LAYOUT,
                    ck_param::salsa20_poly1305::FIELD_COUNT,
                ) {
                    Ok(r) => r,
                    Err(_) => return CKR_ARGUMENTS_BAD,
                };
                if r.ulong(ck_param::salsa20_poly1305::UL_NONCE_LEN) != 12 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let nonce = r
                    .buffer(
                        ck_param::salsa20_poly1305::P_NONCE,
                        ck_param::salsa20_poly1305::UL_NONCE_LEN,
                    )
                    .to_vec();
                let aad = r
                    .buffer(
                        ck_param::salsa20_poly1305::P_AAD,
                        ck_param::salsa20_poly1305::UL_AAD_LEN,
                    )
                    .to_vec();
                (nonce, aad, 0)
            }
            CKM_CHACHA20 => match parse_chacha20_params(p_param, ul_param_len) {
                // W7 — the starting block counter travels with the op.
                Ok((nonce, ctr)) => {
                    chacha_block_counter = ctr;
                    (nonce, Vec::new(), 0)
                }
                Err(rv) => return rv,
            },
            _ => return CKR_MECHANISM_INVALID,
        };

        DECRYPT_STATE.with(|s| {
            s.borrow_mut().insert(
                h_session,
                EncryptCtx {
                    mech_type,
                    key_handle: h_key,
                    iv,
                    aad,
                    tag_bits,
                    multipart: None,
                    block_counter: chacha_block_counter,
                },
            );
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Decrypt)]
pub fn C_Decrypt(
    h_session: u32,
    p_encrypted_data: *mut u8,
    ul_encrypted_data_len: u32,
    p_data: *mut u8,
    pul_data_len: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // Remove state on entry — consumed on all paths except null-buffer size query
    let ctx = DECRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
    let ctx = match ctx {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    // PKCS#11 v3.2 §5.2 — a one-shot C_Decrypt after C_DecryptUpdate is a
    // sequencing error; the streaming op must be completed with C_DecryptFinal.
    if ctx.multipart.is_some() {
        DECRYPT_STATE.with(|s| s.borrow_mut().insert(h_session, ctx));
        return CKR_OPERATION_ACTIVE;
    }
    let (mech_type, key_handle, iv, aad, tag_bits, block_counter) = (
        ctx.mech_type,
        ctx.key_handle,
        ctx.iv,
        ctx.aad,
        ctx.tag_bits,
        // W7 — CKM_CHACHA20's starting keystream block; 0 elsewhere.
        ctx.block_counter,
    );
    let key_bytes = match get_object_value(key_handle) {
        Some(v) => v,
        None => return CKR_ARGUMENTS_BAD,
    };

    // §5.2 — pEncryptedData is the INPUT; NULL with a nonzero length is
    // CKR_ARGUMENTS_BAD. NULL with zero length is an empty input
    // (consistent with C_Encrypt).
    if p_encrypted_data.is_null() && ul_encrypted_data_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let ciphertext: &[u8] = if p_encrypted_data.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(p_encrypted_data, ul_encrypted_data_len as usize)
        };
        let pt = match mech_type {
            CKM_AES_GCM => {
                // GcmState verifies the (possibly truncated) tag before any
                // plaintext is released — §6.27.7 / SP 800-38D.
                use crate::crypto::multipart::{AesKey, CipherDirection, GcmState, MultipartCipher};
                let key = match AesKey::new(&key_bytes) {
                    Some(k) => k,
                    None => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let iv12: [u8; 12] = match iv.as_slice().try_into() {
                    Ok(v) => v,
                    Err(_) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let mut gcm = MultipartCipher::Gcm(GcmState::new(
                    key,
                    &iv12,
                    &aad,
                    tag_bits,
                    CipherDirection::Decrypt,
                ));
                let mut out = match gcm.update(ciphertext) {
                    Ok(o) => o,
                    Err(rv) => return rv,
                };
                match gcm.finalize() {
                    Ok(tail) => out.extend_from_slice(&tail),
                    Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
                }
                out
            }
            CKM_AES_CBC_PAD => {
                use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
                type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
                type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
                let mut buf = ciphertext.to_vec();
                let pt_slice: &[u8] = match key_bytes.len() {
                    16 => match Aes128CbcDec::new_from_slices(&key_bytes, &iv) {
                        Ok(cipher) => match cipher.decrypt_padded_mut::<Pkcs7>(&mut buf) {
                            Ok(pt) => pt,
                            Err(_) => return CKR_FUNCTION_FAILED,
                        },
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    },
                    32 => match Aes256CbcDec::new_from_slices(&key_bytes, &iv) {
                        Ok(cipher) => match cipher.decrypt_padded_mut::<Pkcs7>(&mut buf) {
                            Ok(pt) => pt,
                            Err(_) => return CKR_FUNCTION_FAILED,
                        },
                        Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                    },
                    _ => return CKR_KEY_TYPE_INCONSISTENT,
                };
                pt_slice.to_vec()
            }
            CKM_AES_CTR => {
                // CTR is its own inverse. Width-aware keystream honours
                // ulCounterBits (stored in tag_bits) — §6.27.6.
                use crate::crypto::multipart::{AesKey, CtrState};
                let key = match AesKey::new(&key_bytes) {
                    Some(k) => k,
                    None => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let cb: [u8; 16] = match iv.as_slice().try_into() {
                    Ok(c) => c,
                    Err(_) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let width = ((tag_bits.max(8)) / 8) as usize;
                let mut ctr = CtrState::new_with_width(key, cb, width);
                ctr.update_public(ciphertext)
            }
            CKM_RSA_PKCS_OAEP => {
                use rsa::pkcs8::DecodePrivateKey;
                let sk = match rsa::RsaPrivateKey::from_pkcs8_der(&key_bytes) {
                    Ok(k) => k,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let mgf = if aad.len() >= 4 {
                    u32::from_le_bytes([aad[0], aad[1], aad[2], aad[3]])
                } else {
                    0
                };
                let oaep = match oaep_padding(tag_bits, mgf, &iv) {
                    Ok(o) => o,
                    Err(rv) => return rv,
                };
                match sk.decrypt(oaep, ciphertext) {
                    Ok(pt) => pt,
                    // §6.16 — decode failure is CKR_ENCRYPTED_DATA_INVALID
                    // (uniform code, no padding-oracle distinction).
                    Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
                }
            }
            // R-2 (2026-08-24) — raw CKM_RSA_PKCS (PKCS#1 v1.5) decrypt.
            //
            // SECURITY-REVIEWED, ACCEPTED RISK — NOT AN OVERSIGHT. This wires
            // bare CKM_RSA_PKCS decrypt using the `rsa` crate's own
            // `Pkcs1v15Encrypt` padding primitive (`rsa` 0.9, "hazmat"
            // feature — the same crate/feature already depended on for this
            // engine's CKM_RSA_X_509 raw RSASP1/RSAVP1 path). The crate's OWN
            // source (rsa-0.9.10/src/algorithms/pkcs1v15.rs,
            // `pkcs1v15_encrypt_unpad`'s padding-validity check) carries this
            // unresolved author TODO, verbatim:
            //
            //   "TODO: WARNING: THIS MUST BE CONSTANT TIME CHECK: [...] This
            //   is currently copy & paste from the constant time impl in go,
            //   but very likely not sufficient."
            //
            // and that same function's doc comment warns: "Note that whether
            // this function returns an error or not discloses secret
            // information. If an attacker can cause this function to run
            // repeatedly and learn whether each instance returned an error
            // then they can decrypt and forge signatures as if they had the
            // private key." That is precisely a Bleichenbacher-class
            // padding-oracle attack, and PKCS#11's C_Decrypt is structurally
            // a repeated-query API — a caller may invoke it as many times as
            // it likes against the same key, with no rate limiting at this
            // layer.
            //
            // This engine's C++/OpenSSL backend already implements
            // CKM_RSA_PKCS decrypt SAFELY for this product (OpenSSL's own
            // constant-time unpadding). Weighed against that fact, the
            // decision — made and confirmed by the product owner as of
            // 2026-08-24 — is to ship this Rust-side implementation anyway,
            // using the crate's primitive AS-IS: no additional hand-rolled
            // hardening layered on top (a larger mitigation option was
            // considered and deliberately NOT chosen). Future readers,
            // including future compliance audits of this file: this gap is
            // KNOWN and ACCEPTED, not missed.
            CKM_RSA_PKCS => {
                use rsa::pkcs8::DecodePrivateKey;
                let sk = match rsa::RsaPrivateKey::from_pkcs8_der(&key_bytes) {
                    Ok(k) => k,
                    Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                };
                match sk.decrypt(rsa::Pkcs1v15Encrypt, ciphertext) {
                    Ok(pt) => pt,
                    // Uniform error code, no padding-oracle distinction AT
                    // THIS DISPATCH LAYER (matches CKM_RSA_PKCS_OAEP's
                    // existing convention just above) — this mitigates an
                    // ADDITIONAL oracle ffi.rs itself could otherwise
                    // introduce; it does NOT address the crate-internal
                    // timing risk documented above, which is inherent to the
                    // `rsa` crate's own primitive.
                    Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
                }
            }
            // T1 — ChaCha20-Poly1305 AEAD open (§6.25); tag verified before
            // any plaintext is released.
            CKM_CHACHA20_POLY1305 => {
                if key_bytes.len() != 32 {
                    return CKR_KEY_SIZE_RANGE;
                }
                match crate::native::encrypt::chacha20_poly1305_decrypt(
                    &key_bytes, &iv, ciphertext, &aad,
                ) {
                    Ok(pt) => pt,
                    Err(rv) => return rv,
                }
            }
            // T1 — plain ChaCha20 (§6.20) is self-inverse: same keystream
            // XOR as the encrypt direction.
            CKM_CHACHA20 => {
                if key_bytes.len() != 32 {
                    return CKR_KEY_SIZE_RANGE;
                }
                match crate::native::encrypt::chacha20_encrypt_at(&key_bytes, &iv, ciphertext, block_counter) {
                    Ok(pt) => pt,
                    Err(rv) => return rv,
                }
            }
            CKM_AES_ECB | CKM_AES_CBC => {
                // §6.27.2/§6.27.3 — raw block modes; reuse the streaming
                // state machines as update-then-finalize in one go.
                use crate::crypto::multipart::*;
                let key = match AesKey::new(&key_bytes) {
                    Some(k) => k,
                    None => return CKR_KEY_TYPE_INCONSISTENT,
                };
                let mut mp = if mech_type == CKM_AES_ECB {
                    MultipartCipher::Ecb(EcbState::new(key, CipherDirection::Decrypt))
                } else {
                    let iv_arr: [u8; 16] = match iv.as_slice().try_into() {
                        Ok(v) => v,
                        Err(_) => return CKR_MECHANISM_PARAM_INVALID,
                    };
                    MultipartCipher::Cbc(CbcState::new(key, iv_arr, CipherDirection::Decrypt))
                };
                let mut out = match mp.update(ciphertext) {
                    Ok(o) => o,
                    Err(rv) => return rv,
                };
                match mp.finalize() {
                    Ok(tail) => out.extend_from_slice(&tail),
                    // CKR_ENCRYPTED_DATA_LEN_RANGE on residue
                    Err(rv) => return rv,
                }
                out
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        // PKCS#11 v3.2 §5.2 — neither a NULL-buffer length query nor a
        // CKR_BUFFER_TOO_SMALL may terminate the operation. Re-insert the state
        // for both so the caller can retry. (Preserve aad: the retry re-verifies
        // the tag from the same AAD bytes.)
        let need = pt.len();
        let too_small = !p_data.is_null() && (*pul_data_len as usize) < need;
        if p_data.is_null() || too_small {
            *pul_data_len = need as u32;
            DECRYPT_STATE.with(|s| {
                s.borrow_mut().insert(
                    h_session,
                    EncryptCtx {
                        mech_type,
                        key_handle,
                        iv,
                        aad,
                        tag_bits,
                        multipart: None,
                        block_counter: 0,
                    },
                );
            });
            return if too_small { CKR_BUFFER_TOO_SMALL } else { CKR_OK };
        }
        std::ptr::copy_nonoverlapping(pt.as_ptr(), p_data, need);
        *pul_data_len = need as u32;
    }
    CKR_OK
}

// ── SHA Digest ──────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_DigestInit)]
pub fn C_DigestInit(h_session: u32, p_mechanism: *mut u8) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::Digest) {
        return rv;
    }
    // PKCS#11 v3.2 §5.12 — a digest operation is already active on this session.
    if DIGEST_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_ACTIVE;
    }
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        use sha2::Digest;
        let ctx = match mech_type {
            CKM_SHA256 => DigestCtx::Sha256(sha2::Sha256::new()),
            CKM_SHA384 => DigestCtx::Sha384(sha2::Sha384::new()),
            CKM_SHA512 => DigestCtx::Sha512(sha2::Sha512::new()),
            CKM_SHA3_256 => DigestCtx::Sha3_256(sha3::Sha3_256::new()),
            CKM_SHA3_512 => DigestCtx::Sha3_512(sha3::Sha3_512::new()),
            CKM_KECCAK_256 => DigestCtx::Keccak256(Vec::new()),
            CKM_RIPEMD160 => DigestCtx::Ripemd160(ripemd::Ripemd160::new()),
            _ => return CKR_MECHANISM_INVALID,
        };
        DIGEST_STATE.with(|s| {
            s.borrow_mut().insert(h_session, ctx);
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DigestUpdate)]
pub fn C_DigestUpdate(h_session: u32, p_part: *mut u8, ul_part_len: u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    use sha2::Digest;
    let has_state = DIGEST_STATE.with(|s| s.borrow().contains_key(&h_session));
    if !has_state {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    // §5.13 — the op is now multi-part; a one-shot C_Digest on this session
    // is CKR_OPERATION_ACTIVE until C_DigestFinal completes it.
    DIGEST_MULTIPART.with(|s| s.borrow_mut().insert(h_session));
    unsafe {
        let data = std::slice::from_raw_parts(p_part, ul_part_len as usize);
        DIGEST_STATE.with(|s| {
            let mut map = s.borrow_mut();
            if let Some(ctx) = map.get_mut(&h_session) {
                match ctx {
                    DigestCtx::Sha256(h) => h.update(data),
                    DigestCtx::Sha384(h) => h.update(data),
                    DigestCtx::Sha512(h) => h.update(data),
                    DigestCtx::Sha3_256(h) => h.update(data),
                    DigestCtx::Sha3_512(h) => h.update(data),
                    DigestCtx::Keccak256(buf) => crate::crypto::keccak::keccak256_update(buf, data),
                    DigestCtx::Ripemd160(h) => h.update(data),
                }
            }
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DigestFinal)]
pub fn C_DigestFinal(h_session: u32, p_digest: *mut u8, pul_digest_len: *mut u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    unsafe {
        // Size-only query: return expected length WITHOUT consuming state.
        // Per PKCS#11 v3.2 §5.7.2, a null pDigest must not terminate the operation.
        if p_digest.is_null() {
            let len = DIGEST_STATE.with(|s| {
                s.borrow().get(&h_session).map(|ctx| match ctx {
                    DigestCtx::Sha256(_) => 32u32,
                    DigestCtx::Sha384(_) => 48,
                    DigestCtx::Sha512(_) => 64,
                    DigestCtx::Sha3_256(_) => 32,
                    DigestCtx::Sha3_512(_) => 64,
                    DigestCtx::Keccak256(_) => 32,
                    DigestCtx::Ripemd160(_) => 20,
                })
            });
            return match len {
                Some(l) => {
                    *pul_digest_len = l;
                    CKR_OK
                }
                None => CKR_OPERATION_NOT_INITIALIZED,
            };
        }
        use sha2::Digest;
        // PKCS#11 v3.2 §5.2 — determine the digest length WITHOUT consuming the
        // operation, so a too-small buffer leaves the op active for retry.
        let expected_len = DIGEST_STATE.with(|s| {
            s.borrow().get(&h_session).map(|ctx| match ctx {
                DigestCtx::Sha256(_) => 32usize,
                DigestCtx::Sha384(_) => 48,
                DigestCtx::Sha512(_) => 64,
                DigestCtx::Sha3_256(_) => 32,
                DigestCtx::Sha3_512(_) => 64,
                DigestCtx::Keccak256(_) => 32,
                DigestCtx::Ripemd160(_) => 20,
            })
        });
        let expected_len = match expected_len {
            Some(l) => l,
            None => return CKR_OPERATION_NOT_INITIALIZED,
        };
        if (*pul_digest_len as usize) < expected_len {
            *pul_digest_len = expected_len as u32;
            return CKR_BUFFER_TOO_SMALL; // op stays active (§5.2)
        }
        // Buffer is adequate — now consume the operation and finalize.
        let ctx = DIGEST_STATE
            .with(|s| s.borrow_mut().remove(&h_session))
            .expect("digest state present (checked above)");
        DIGEST_MULTIPART.with(|s| s.borrow_mut().remove(&h_session));
        let hash = match ctx {
            DigestCtx::Sha256(h) => h.finalize().to_vec(),
            DigestCtx::Sha384(h) => h.finalize().to_vec(),
            DigestCtx::Sha512(h) => h.finalize().to_vec(),
            DigestCtx::Sha3_256(h) => h.finalize().to_vec(),
            DigestCtx::Sha3_512(h) => h.finalize().to_vec(),
            DigestCtx::Keccak256(buf) => crate::crypto::keccak::keccak256_finalize(&buf).to_vec(),
            DigestCtx::Ripemd160(h) => h.finalize().to_vec(),
        };
        std::ptr::copy_nonoverlapping(hash.as_ptr(), p_digest, hash.len());
        *pul_digest_len = hash.len() as u32;
        CKR_OK
    }
}

#[wasm_bindgen(js_name = _C_Digest)]
pub fn C_Digest(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_digest: *mut u8,
    pul_digest_len: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // §5.13 convention — a digest op already in its multi-part phase
    // (C_DigestUpdate called) must be completed with C_DigestFinal; the
    // one-shot API is a sequencing error, not a silent append.
    if DIGEST_MULTIPART.with(|s| s.borrow().contains(&h_session)) {
        return CKR_OPERATION_ACTIVE;
    }
    unsafe {
        // Size-only query: return expected length WITHOUT updating state.
        // Per PKCS#11 v3.2 §5.7.2, data must not be processed on a null-pDigest call.
        if p_digest.is_null() {
            let len = DIGEST_STATE.with(|s| {
                s.borrow().get(&h_session).map(|ctx| match ctx {
                    DigestCtx::Sha256(_) => 32u32,
                    DigestCtx::Sha384(_) => 48,
                    DigestCtx::Sha512(_) => 64,
                    DigestCtx::Sha3_256(_) => 32,
                    DigestCtx::Sha3_512(_) => 64,
                    DigestCtx::Keccak256(_) => 32,
                    DigestCtx::Ripemd160(_) => 20,
                })
            });
            return match len {
                Some(l) => {
                    *pul_digest_len = l;
                    CKR_OK
                }
                None => CKR_OPERATION_NOT_INITIALIZED,
            };
        }
        let rv = C_DigestUpdate(h_session, p_data, ul_data_len);
        if rv != CKR_OK {
            return rv;
        }
        // The internal Update marked the op multi-part; the one-shot path is
        // not — clear the marker so a §5.2 BUFFER_TOO_SMALL retry of C_Digest
        // is not misreported as CKR_OPERATION_ACTIVE.
        DIGEST_MULTIPART.with(|s| s.borrow_mut().remove(&h_session));
        C_DigestFinal(h_session, p_digest, pul_digest_len)
    }
}

// ── FindObjects ─────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_FindObjectsInit)]
pub fn C_FindObjectsInit(h_session: u32, p_template: *mut u8, ul_count: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // PKCS#11 v3.2 §5.10.1 — a find operation is already active on this session.
    if FIND_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_ACTIVE;
    }
    // W5 (2026-08-13) — §5.7.7: "The matching criterion is an exact
    // byte-for-byte match with all attributes in the template. To find all
    // objects, set ulCount to 0." Two paths previously produced a find-ALL
    // from a request that asked for a FILTER: a NULL template with a non-zero
    // count, and a count above the engine's 65536 guard. Both erred toward
    // returning MORE objects than asked for — the wrong direction for a
    // search whose results gate every later by-handle operation.
    if p_template.is_null() && ul_count > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    if ul_count > 65536 {
        // Honouring it is impractical; failing is the only other option the
        // spec leaves. Never drop the filter.
        return CKR_ARGUMENTS_BAD;
    }
    let mut match_attrs: Vec<(u32, Vec<u8>)> = Vec::new();
    unsafe {
        if !p_template.is_null() && ul_count > 0 {
            let tmpl_ptr = p_template as *mut usize;
            for i in 0..ul_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize) as u32;
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as usize;
                if !val_ptr.is_null() && val_len > 0 {
                    match_attrs.push((
                        attr_type,
                        std::slice::from_raw_parts(val_ptr, val_len).to_vec(),
                    ));
                }
            }
        }
    }
    let mut matching = OBJECTS.with(|objs| {
        objs.borrow()
            .iter()
            .filter(|(_, attrs)| {
                // PKCS#11 v3.2 §4.4 — private objects (CKA_PRIVATE=TRUE) are
                // invisible to sessions whose token is not logged in, AND
                // (T3) enumeration is scoped to the session's token: objects
                // owned by another slot never match. Both gates live in
                // state::can_access_object.
                crate::state::can_access_object(h_session, attrs)
                    // §5.7.7 matching — the SAME comparator §5.18.3's
                    // wrap-template check uses (S2), so find-matching and
                    // wrap-matching cannot drift apart.
                    && crate::state::attrs_match_template(attrs, &match_attrs)
            })
            .map(|(handle, attrs)| {
                (*handle, crate::state::get_object_attr_u32_from(attrs, CKA_CLASS))
            })
            .collect::<Vec<(u32, Option<u32>)>>()
    });
    // WS-11 Phase 1 (2026-08-28) — §5.7.8 specifies no result order, but
    // OBJECTS is a HashMap: iteration order was arbitrary, which OASIS's
    // CERT-M-1-32 mandatory test case (implicitly, by asserting on
    // Object.Object[0]/[1]) and the cross-engine differential harness both
    // depend on being stable. Deterministic order: application objects
    // first (by handle, i.e. creation order), library-descriptor objects
    // (CKO_PROFILE — the only one this engine has; CKO_VALIDATION isn't
    // implemented) last, since those are metadata ABOUT the token rather
    // than something the caller asked for.
    matching.sort_unstable_by_key(|(handle, class)| (*class == Some(CKO_PROFILE), *handle));
    let matching: Vec<u32> = matching.into_iter().map(|(handle, _)| handle).collect();
    FIND_STATE.with(|s| {
        s.borrow_mut().insert(
            h_session,
            FindCtx {
                handles: matching,
                cursor: 0,
            },
        );
    });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_FindObjects)]
pub fn C_FindObjects(
    h_session: u32,
    ph_object: *mut u32,
    ul_max_object_count: u32,
    pul_object_count: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // §5.10.2 — phObject and pulObjectCount are required pointers.
    nonnull!(ph_object, pul_object_count);
    FIND_STATE.with(|s| {
        let mut map = s.borrow_mut();
        if let Some(ctx) = map.get_mut(&h_session) {
            let remaining = ctx.handles.len() - ctx.cursor;
            let count = remaining.min(ul_max_object_count as usize);
            unsafe {
                for i in 0..count {
                    *ph_object.add(i) = ctx.handles[ctx.cursor + i];
                }
                *pul_object_count = count as u32;
            }
            ctx.cursor += count;
            CKR_OK
        } else {
            CKR_OPERATION_NOT_INITIALIZED
        }
    })
}

#[wasm_bindgen(js_name = _C_FindObjectsFinal)]
pub fn C_FindObjectsFinal(h_session: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // PKCS#11 v3.2 §5.10.3 — must follow an active C_FindObjectsInit.
    let had = FIND_STATE.with(|s| s.borrow_mut().remove(&h_session).is_some());
    if had {
        CKR_OK
    } else {
        CKR_OPERATION_NOT_INITIALIZED
    }
}

// ── GenerateRandom ──────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GenerateRandom)]
pub fn C_GenerateRandom(_h_session: u32, p_random_data: *mut u8, ul_random_len: u32) -> u32 {
    require_init!();
    require_session!(_h_session);
    if p_random_data.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let buf = std::slice::from_raw_parts_mut(p_random_data, ul_random_len as usize);
        match getrandom::getrandom(buf) {
            Ok(_) => CKR_OK,
            Err(_) => CKR_FUNCTION_FAILED,
        }
    }
}

// ── DeriveKey (ECDH, PBKDF2, HKDF, KBKDF) ──────────────────────────────────

/// One parsed SP 800-108 data segment (CK_PRF_DATA_PARAM), in caller order.
enum Sp800Seg {
    /// counter: (little_endian, width_bytes)
    Counter(bool, usize),
    /// [L]: pre-encoded DKM length field bytes
    DkmLength(Vec<u8>),
    Bytes(Vec<u8>),
}

/// PKCS#11 v3.2 §6.42.2 — PRF output length in bytes for the SP 800-108
/// PRF types this engine supports (used only to size
/// `CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS`). `None` for an unrecognized
/// PRF type or an invalid AES-CMAC key length.
fn sp800_108_prf_output_len(prf_type: u32, base_key_len: usize) -> Option<usize> {
    match prf_type {
        CKM_SHA_1_HMAC => Some(20),
        CKM_SHA224_HMAC => Some(28),
        CKM_SHA256_HMAC => Some(32),
        CKM_SHA384_HMAC => Some(48),
        CKM_SHA512_HMAC => Some(64),
        CKM_SHA512_224_HMAC => Some(28),
        CKM_SHA512_256_HMAC => Some(32),
        CKM_SHA3_224_HMAC => Some(28),
        CKM_SHA3_256_HMAC => Some(32),
        CKM_SHA3_384_HMAC => Some(48),
        CKM_SHA3_512_HMAC => Some(64),
        // CMAC output = the underlying block cipher's block size (AES = 16
        // bytes), independent of key length; base_key_len is only checked
        // for AES key-size validity, mirroring sp800_108_counter_kbkdf.
        CKM_AES_CMAC if matches!(base_key_len, 16 | 24 | 32) => Some(16),
        _ => None,
    }
}

/// Parse CK_PRF_DATA_PARAM[] — { type: CK_PRF_DATA_TYPE, pValue, ulValueLen },
/// all CK_ULONG/pointer-width, so the array stride and the nested COUNTER /
/// DKM_LENGTH format-struct field offsets are taken at size_of::<usize>()
/// (4 B wasm32, 8 B native). `key_len` is the requested DKM length in bytes.
/// `prf_type`/`base_key_len` size a `SUM_OF_SEGMENTS` DKM length.
/// `allow_explicit_counter` — Table 199 (Counter Mode) forbids the separate
/// `CK_SP800_108_COUNTER` field (the counter there is the mandatory
/// ITERATION_VARIABLE); Table 200 (Feedback Mode) allows it as optional.
unsafe fn parse_sp800_108_segments(
    p_segs: *const u8,
    num_segs: usize,
    key_len: usize,
    prf_type: u32,
    base_key_len: usize,
    allow_explicit_counter: bool,
) -> Result<Vec<Sp800Seg>, u32> {
    let mut out = Vec::new();
    if p_segs.is_null() {
        return Ok(out);
    }
    // The array stride is sizeof(CK_PRF_DATA_PARAM), which is 12 bytes on
    // wasm32 and 24 on LP64 — the same hazard as any single struct, applied
    // once per element.
    let stride = ck_param::prf_data_param::LAYOUT.size();
    for i in 0..num_segs.min(64) {
        let seg = ParamReader::new(
            p_segs.add(i * stride),
            stride,
            &ck_param::prf_data_param::LAYOUT,
            ck_param::prf_data_param::FIELD_COUNT,
        )
        .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
        let seg_type = seg.ulong32(ck_param::prf_data_param::TYPE);
        let val_ptr = seg.ptr(ck_param::prf_data_param::P_VALUE);
        let val_len = seg.ulong(ck_param::prf_data_param::UL_VALUE_LEN);
        match seg_type {
            t if t == CK_SP800_108_ITERATION_VARIABLE => {
                // pValue → CK_SP800_108_COUNTER_FORMAT { bLittleEndian: CK_BBOOL,
                // ulWidthInBits: CK_ULONG } — width at one CK_ULONG offset.
                let cf = ParamReader::new(
                    val_ptr,
                    val_len,
                    &ck_param::counter_format::LAYOUT,
                    ck_param::counter_format::FIELD_COUNT,
                )
                .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
                let le = cf.bbool(ck_param::counter_format::B_LITTLE_ENDIAN);
                let width_bits = cf.ulong32(ck_param::counter_format::UL_WIDTH_IN_BITS);
                if !matches!(width_bits, 8 | 16 | 24 | 32) {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                out.push(Sp800Seg::Counter(le, (width_bits / 8) as usize));
            }
            t if t == CK_SP800_108_COUNTER => {
                // Table 199 — invalid data field for Counter Mode KDF.
                if !allow_explicit_counter {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                // Same wire shape as ITERATION_VARIABLE: pValue →
                // CK_SP800_108_COUNTER_FORMAT.
                let cf = ParamReader::new(
                    val_ptr,
                    val_len,
                    &ck_param::counter_format::LAYOUT,
                    ck_param::counter_format::FIELD_COUNT,
                )
                .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
                let le = cf.bbool(ck_param::counter_format::B_LITTLE_ENDIAN);
                let width_bits = cf.ulong32(ck_param::counter_format::UL_WIDTH_IN_BITS);
                if !matches!(width_bits, 8 | 16 | 24 | 32) {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                out.push(Sp800Seg::Counter(le, (width_bits / 8) as usize));
            }
            t if t == CK_SP800_108_DKM_LENGTH => {
                // pValue → CK_SP800_108_DKM_LENGTH_FORMAT { method: CK_ULONG,
                // bLittleEndian: CK_BBOOL, ulWidthInBits: CK_ULONG }.
                let df = ParamReader::new(
                    val_ptr,
                    val_len,
                    &ck_param::dkm_length_format::LAYOUT,
                    ck_param::dkm_length_format::FIELD_COUNT,
                )
                .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
                let method = df.ulong32(ck_param::dkm_length_format::DKM_LENGTH_METHOD);
                let le = df.bbool(ck_param::dkm_length_format::B_LITTLE_ENDIAN);
                let width_bits = df.ulong32(ck_param::dkm_length_format::UL_WIDTH_IN_BITS);
                if !matches!(width_bits, 8 | 16 | 32 | 64) {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                // Table 198 — SUM_OF_KEYS is just the requested key length;
                // SUM_OF_SEGMENTS is that length rounded UP to a whole
                // number of PRF-output blocks (the KDF always emits whole
                // segments even if only part of the last one is kept).
                let l_bits: u64 = if method == CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS {
                    (key_len as u64) * 8
                } else if method == CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS {
                    let prf_out = sp800_108_prf_output_len(prf_type, base_key_len)
                        .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
                    let segments = key_len.div_ceil(prf_out).max(1);
                    ((segments * prf_out) as u64) * 8
                } else {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                };
                let width = (width_bits / 8) as usize;
                let full = if le {
                    l_bits.to_le_bytes()
                } else {
                    l_bits.to_be_bytes()
                };
                let bytes = if le {
                    full[..width].to_vec()
                } else {
                    full[8 - width..].to_vec()
                };
                out.push(Sp800Seg::DkmLength(bytes));
            }
            t if t == CK_SP800_108_BYTE_ARRAY => {
                if !val_ptr.is_null() && val_len > 0 {
                    out.push(Sp800Seg::Bytes(
                        std::slice::from_raw_parts(val_ptr, val_len).to_vec(),
                    ));
                }
            }
            t if t == CK_SP800_108_KEY_HANDLE => {
                // pValue → CK_OBJECT_HANDLE_PTR, ulValueLen == sizeof(CK_OBJECT_HANDLE).
                // Splices the referenced key's CKA_VALUE in as a byte-array segment.
                if val_len != ck_param::object_handle_param::LAYOUT.size() {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let hr = ParamReader::new(
                    val_ptr,
                    val_len,
                    &ck_param::object_handle_param::LAYOUT,
                    ck_param::object_handle_param::FIELD_COUNT,
                )
                .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
                let handle = hr.ulong32(ck_param::object_handle_param::H_KEY);
                let key_bytes = get_object_value(handle).ok_or(CKR_KEY_HANDLE_INVALID)?;
                out.push(Sp800Seg::Bytes(key_bytes));
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID),
        }
    }
    Ok(out)
}

/// Feedback-mode per-iteration input: segments in order, NO implicit
/// counter when ITERATION_VARIABLE is absent (SP 800-108 §4.2 makes the
/// counter optional in feedback mode).
fn sp800_108_feedback_input(segs: &[Sp800Seg], counter: u32) -> Vec<Vec<u8>> {
    let mut pieces = Vec::new();
    for seg in segs {
        match seg {
            Sp800Seg::Counter(le, width) => {
                let full = if *le {
                    (counter as u64).to_le_bytes()
                } else {
                    (counter as u64).to_be_bytes()
                };
                pieces.push(if *le {
                    full[..*width].to_vec()
                } else {
                    full[8 - *width..].to_vec()
                });
            }
            Sp800Seg::DkmLength(b) => pieces.push(b.clone()),
            Sp800Seg::Bytes(b) => pieces.push(b.clone()),
        }
    }
    pieces
}

/// Per-iteration PRF input pieces, in segment order. With no
/// ITERATION_VARIABLE segment the legacy 32-bit BE counter is prepended
/// (the engine's historical behavior).
fn sp800_108_iter_input(segs: &[Sp800Seg], counter: u32) -> Vec<Vec<u8>> {
    let mut pieces = Vec::new();
    let has_counter = segs.iter().any(|s| matches!(s, Sp800Seg::Counter(..)));
    if !has_counter {
        pieces.push(counter.to_be_bytes().to_vec());
    }
    for seg in segs {
        match seg {
            Sp800Seg::Counter(le, width) => {
                let full = if *le {
                    (counter as u64).to_le_bytes()
                } else {
                    (counter as u64).to_be_bytes()
                };
                pieces.push(if *le {
                    full[..*width].to_vec()
                } else {
                    full[8 - *width..].to_vec()
                });
            }
            Sp800Seg::DkmLength(b) => pieces.push(b.clone()),
            Sp800Seg::Bytes(b) => pieces.push(b.clone()),
        }
    }
    pieces
}

/// Counter-mode KBKDF core: K(i) = PRF(base_key, iter_input(segs, i)).
fn sp800_108_run_counter<M>(
    base_key: &[u8],
    segs: &[Sp800Seg],
    key_len: usize,
) -> Result<Vec<u8>, u32>
where
    M: hmac::Mac + hmac::digest::KeyInit,
{
    use hmac::Mac;
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < key_len {
        let mut mac = <M as Mac>::new_from_slice(base_key).map_err(|_| CKR_FUNCTION_FAILED)?;
        for piece in sp800_108_iter_input(segs, counter) {
            mac.update(&piece);
        }
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(key_len);
    Ok(out)
}

/// Feedback-mode KBKDF core: K(i) = PRF(base_key, K(i-1) ‖ feedback_input(segs, i)),
/// K(0) = IV.
fn sp800_108_run_feedback<M>(
    base_key: &[u8],
    iv: &[u8],
    segs: &[Sp800Seg],
    key_len: usize,
) -> Result<Vec<u8>, u32>
where
    M: hmac::Mac + hmac::digest::KeyInit,
{
    use hmac::Mac;
    let mut k_prev = iv.to_vec();
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < key_len {
        let mut mac = <M as Mac>::new_from_slice(base_key).map_err(|_| CKR_FUNCTION_FAILED)?;
        mac.update(&k_prev);
        // Feedback mode: an absent ITERATION_VARIABLE means NO counter
        // (unlike counter mode), so only emit explicitly-requested segments.
        for piece in sp800_108_feedback_input(segs, counter) {
            mac.update(&piece);
        }
        k_prev = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&k_prev);
        counter += 1;
    }
    out.truncate(key_len);
    Ok(out)
}

/// PKCS#11 v3.2 §6.26 — the SP 800-108 PRF must be a keyed-MAC mechanism
/// (HMAC/CMAC). Bare hashes (CKM_SHA256 etc.) and any unrecognised mechanism
/// fail with CKR_MECHANISM_PARAM_INVALID. AES-CMAC is not implemented by
/// this engine, so only the HMAC mechanisms it supports are accepted.
fn sp800_108_counter_kbkdf(
    prf_type: u32,
    base_key: &[u8],
    segs: &[Sp800Seg],
    key_len: usize,
) -> Result<Vec<u8>, u32> {
    use hmac::Hmac;
    match prf_type {
        CKM_SHA_1_HMAC => sp800_108_run_counter::<Hmac<sha1::Sha1>>(base_key, segs, key_len),
        CKM_SHA224_HMAC => sp800_108_run_counter::<Hmac<sha2::Sha224>>(base_key, segs, key_len),
        CKM_SHA256_HMAC => sp800_108_run_counter::<Hmac<sha2::Sha256>>(base_key, segs, key_len),
        CKM_SHA384_HMAC => sp800_108_run_counter::<Hmac<sha2::Sha384>>(base_key, segs, key_len),
        CKM_SHA512_HMAC => sp800_108_run_counter::<Hmac<sha2::Sha512>>(base_key, segs, key_len),
        CKM_SHA512_224_HMAC => {
            sp800_108_run_counter::<Hmac<sha2::Sha512_224>>(base_key, segs, key_len)
        }
        CKM_SHA512_256_HMAC => {
            sp800_108_run_counter::<Hmac<sha2::Sha512_256>>(base_key, segs, key_len)
        }
        CKM_SHA3_224_HMAC => {
            sp800_108_run_counter::<Hmac<sha3::Sha3_224>>(base_key, segs, key_len)
        }
        CKM_SHA3_384_HMAC => {
            sp800_108_run_counter::<Hmac<sha3::Sha3_384>>(base_key, segs, key_len)
        }
        CKM_SHA3_256_HMAC => {
            sp800_108_run_counter::<Hmac<sha3::Sha3_256>>(base_key, segs, key_len)
        }
        CKM_SHA3_512_HMAC => {
            sp800_108_run_counter::<Hmac<sha3::Sha3_512>>(base_key, segs, key_len)
        }
        // AES-CMAC PRF — the AES variant is fixed by the base key length.
        CKM_AES_CMAC => match base_key.len() {
            16 => sp800_108_run_counter::<cmac::Cmac<aes::Aes128>>(base_key, segs, key_len),
            24 => sp800_108_run_counter::<cmac::Cmac<aes::Aes192>>(base_key, segs, key_len),
            32 => sp800_108_run_counter::<cmac::Cmac<aes::Aes256>>(base_key, segs, key_len),
            _ => Err(CKR_KEY_SIZE_RANGE),
        },
        _ => Err(CKR_MECHANISM_PARAM_INVALID),
    }
}

/// Feedback-mode twin of [`sp800_108_counter_kbkdf`]; same PRF policy.
fn sp800_108_feedback_kbkdf(
    prf_type: u32,
    base_key: &[u8],
    iv: &[u8],
    segs: &[Sp800Seg],
    key_len: usize,
) -> Result<Vec<u8>, u32> {
    use hmac::Hmac;
    match prf_type {
        CKM_SHA_1_HMAC => {
            sp800_108_run_feedback::<Hmac<sha1::Sha1>>(base_key, iv, segs, key_len)
        }
        CKM_SHA224_HMAC => {
            sp800_108_run_feedback::<Hmac<sha2::Sha224>>(base_key, iv, segs, key_len)
        }
        CKM_SHA256_HMAC => {
            sp800_108_run_feedback::<Hmac<sha2::Sha256>>(base_key, iv, segs, key_len)
        }
        CKM_SHA384_HMAC => {
            sp800_108_run_feedback::<Hmac<sha2::Sha384>>(base_key, iv, segs, key_len)
        }
        CKM_SHA512_HMAC => {
            sp800_108_run_feedback::<Hmac<sha2::Sha512>>(base_key, iv, segs, key_len)
        }
        CKM_SHA512_224_HMAC => {
            sp800_108_run_feedback::<Hmac<sha2::Sha512_224>>(base_key, iv, segs, key_len)
        }
        CKM_SHA512_256_HMAC => {
            sp800_108_run_feedback::<Hmac<sha2::Sha512_256>>(base_key, iv, segs, key_len)
        }
        CKM_SHA3_224_HMAC => {
            sp800_108_run_feedback::<Hmac<sha3::Sha3_224>>(base_key, iv, segs, key_len)
        }
        CKM_SHA3_384_HMAC => {
            sp800_108_run_feedback::<Hmac<sha3::Sha3_384>>(base_key, iv, segs, key_len)
        }
        CKM_SHA3_256_HMAC => {
            sp800_108_run_feedback::<Hmac<sha3::Sha3_256>>(base_key, iv, segs, key_len)
        }
        CKM_SHA3_512_HMAC => {
            sp800_108_run_feedback::<Hmac<sha3::Sha3_512>>(base_key, iv, segs, key_len)
        }
        // AES-CMAC PRF — the AES variant is fixed by the base key length.
        CKM_AES_CMAC => match base_key.len() {
            16 => sp800_108_run_feedback::<cmac::Cmac<aes::Aes128>>(base_key, iv, segs, key_len),
            24 => sp800_108_run_feedback::<cmac::Cmac<aes::Aes192>>(base_key, iv, segs, key_len),
            32 => sp800_108_run_feedback::<cmac::Cmac<aes::Aes256>>(base_key, iv, segs, key_len),
            _ => Err(CKR_KEY_SIZE_RANGE),
        },
        _ => Err(CKR_MECHANISM_PARAM_INVALID),
    }
}

#[wasm_bindgen(js_name = _C_DeriveKey)]
pub fn C_DeriveKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_base_key: u32,
    p_template: *mut u8,
    ul_attribute_count: u32,
    ph_key: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // S7 — §5.7.1.
        if let Err(rv) =
            gate_ro_session_for_template(_h_session, p_template, ul_attribute_count)
        {
            return rv;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        // DEPRECATED aliases: BIP32 mechanisms formerly shipped on the bare
        // (OASIS-unassigned) codepoints 0x105B/0x105C before moving to the
        // vendor space (F1 re-sync). Only the vendor codepoints are
        // advertised, but in-the-wild JS callers may still send the old
        // values — accept them at dispatch.
        let mech_type = match mech_type {
            CKM_BIP32_MASTER_DERIVE_LEGACY => CKM_BIP32_MASTER_DERIVE,
            CKM_BIP32_CHILD_DERIVE_LEGACY => CKM_BIP32_CHILD_DERIVE,
            m => m,
        };
        let key_len =
            get_attr_ulong(p_template, ul_attribute_count, CKA_VALUE_LEN).unwrap_or(32) as usize;

        // PKCS#11 v3.2 §5.18.5 — base key: handle exists + visible (login
        // gate) → else CKR_KEY_HANDLE_INVALID; then CKA_DERIVE → else
        // CKR_KEY_FUNCTION_NOT_PERMITTED. PBKDF2 uses h_base_key=0
        // (password in params), so skip the check for that case.
        if h_base_key != 0 {
            if let Err(rv) = check_key_usage(_h_session, h_base_key, CKA_DERIVE) {
                return rv;
            }
            // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS on the base key.
            if let Err(rv) = check_mechanism_allowed(h_base_key, mech_type) {
                return rv;
            }
        }

        if mech_type == CKM_BIP32_MASTER_DERIVE || mech_type == CKM_BIP32_CHILD_DERIVE {
            let mut attrs = std::collections::HashMap::new();
            let tmpl_ptr = p_template as *mut usize;
            for i in 0..ul_attribute_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize) as u32;
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as u32;
                if !val_ptr.is_null() && val_len > 0 {
                    let mut v = vec![0u8; val_len as usize];
                    std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                    attrs.insert(attr_type, v);
                }
            }

            let ec_params = match attrs.get(&CKA_EC_PARAMS) {
                Some(v) => v.clone(),
                None => return CKR_TEMPLATE_INCONSISTENT,
            };

            let curve = match crate::crypto::HDCurve::from_oid(&ec_params) {
                Some(c) => c,
                None => return CKR_KEY_TYPE_INCONSISTENT,
            };

            let (priv_key, chain_code) = if mech_type == CKM_BIP32_MASTER_DERIVE {
                let seed = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_OBJECT_HANDLE_INVALID,
                };
                match crate::crypto::derive_master_node(&seed, curve) {
                    Ok(res) => res,
                    Err(e) => return e,
                }
            } else {
                let parent_priv = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_OBJECT_HANDLE_INVALID,
                };
                let parent_chain_code = OBJECTS.with(|o| {
                    if let Some(o_attrs) = o.borrow().get(&h_base_key) {
                        if let Some(v) = o_attrs.get(&CKA_BIP32_CHAIN_CODE) {
                            return v.clone();
                        }
                        // Deprecated alias: objects imported by older callers
                        // may carry the chain code under the bare legacy id.
                        if let Some(v) = o_attrs.get(&CKA_BIP32_CHAIN_CODE_LEGACY) {
                            return v.clone();
                        }
                    }
                    vec![]
                });
                if parent_chain_code.is_empty() {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }

                // Adjudicated 2026-08-14. The engine now reads the struct the
                // header declares; see ck_param::bip32_child_derive for the
                // declaration and the evidence.
                //
                // The question was which of two disagreeing parties is right.
                // BIP32 is a PQCToday vendor extension — CKM_BIP32_CHILD_DERIVE
                // is CKM_VENDOR_DEFINED | 0x105c — so there is no OASIS text to
                // appeal to: `grep -c bip32 docs/refs/pkcs11t-canonical-v3.2.h`
                // is 0, and so is the count in the v3.2 Standard's own text.
                // That leaves three parties:
                //
                //   src/lib/pkcs11/pkcs11t.h:2139  pNext, flags, index
                //                                  (24 bytes LP64 / 12 wasm32)
                //   the C++ engine                 follows the header exactly,
                //                                  and rejects any other
                //                                  ulParameterLen outright
                //                                  (SoftHSM_keygen.cpp:3010)
                //   this engine + the hub's TS     two u32s, 8 bytes, no pNext
                //   playground                     (helpers.ts
                //                                  buildBIP32ChildDeriveParams)
                //
                // The engine and its caller agreeing with each other is not
                // evidence: both are ours, and neither is the published
                // interface. The header is what a third party compiles
                // against, and the C++ engine already honours it, so the
                // header wins and this engine was wrong on every target — it
                // read pNext as flags, and on LP64 read pNext's high half as
                // index. The consequence is not theoretical: a native caller's
                // 24-byte struct derives a wholly different child key here
                // than under the C++ engine.
                //
                // The hub playground must be changed to match; the exact edit
                // is written down in the commit that introduced this comment.
                let m = crate::ck_param::mech(p_mechanism as *const u8);
                let r = match crate::ck_param::ParamReader::new(
                    m.p_parameter,
                    m.ul_parameter_len,
                    &crate::ck_param::bip32_child_derive::LAYOUT,
                    crate::ck_param::bip32_child_derive::FIELD_COUNT,
                ) {
                    Ok(r) => r,
                    // C++ answers CKR_ARGUMENTS_BAD for both an absent and a
                    // wrong-sized parameter here; match it.
                    Err(_) => return CKR_ARGUMENTS_BAD,
                };
                let flags = r.ulong(crate::ck_param::bip32_child_derive::FLAGS);
                // BIP32 child numbers are 32-bit (BIP-0032 §"Child key
                // derivation"), with the hardened bit carried in `flags`.
                let index = r.ulong32(crate::ck_param::bip32_child_derive::INDEX);

                match crate::crypto::derive_child_node(
                    &parent_priv,
                    &parent_chain_code,
                    index,
                    flags != 0,
                    curve,
                ) {
                    Ok(res) => res,
                    Err(e) => return e,
                }
            };

            // Respect CKA_EXTRACTABLE from the caller's template (default: false / sensitive)
            let extractable = attrs
                .get(&CKA_EXTRACTABLE)
                .and_then(|v| v.first())
                .map(|&b| b != 0)
                .unwrap_or(false);

            store_ulong(&mut attrs, CKA_CLASS, CKO_PRIVATE_KEY);
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_EC);
            attrs.insert(CKA_VALUE, priv_key);
            attrs.insert(CKA_BIP32_CHAIN_CODE, chain_code.clone());
            // Deprecated alias: also expose the chain code under the bare
            // legacy id so pre-F1 readers (GetAttributeValue 0x1021) work.
            attrs.insert(CKA_BIP32_CHAIN_CODE_LEGACY, chain_code);

            store_bool(&mut attrs, CKA_TOKEN, false);
            store_bool(&mut attrs, CKA_PRIVATE, true);
            store_bool(&mut attrs, CKA_SENSITIVE, !extractable);
            store_bool(&mut attrs, CKA_EXTRACTABLE, extractable);

            // PKCS#11 v3.2 §4.11: KCV mandatory on derived secret keys.
            crate::state::compute_kcv(&mut attrs);

            *ph_key = allocate_handle_owned(_h_session, attrs);
            return CKR_OK;
        }

        let key_value: Vec<u8> = match mech_type {
            // ── Concatenate base key ‖ second key (PKCS#11 v3.2 §6.43.3) ─────
            // The universal step-1 building block for composing a hybrid-KEM
            // shared secret entirely in-HSM (classical ‖ PQC). pParameter is a
            // single CK_OBJECT_HANDLE (the second/appended key), read at
            // native width like the other derive params. Derived value =
            // base.CKA_VALUE ‖ second.CKA_VALUE; flows through the unified
            // secret-key finalization below (template-aware per the spec's
            // "if no length/key type provided ⇒ generic secret" rule).
            CKM_CONCATENATE_BASE_AND_KEY => {
                let r = match ck_param::mech(p_mechanism)
                    .params(&ck_param::object_handle_param::LAYOUT, ck_param::object_handle_param::FIELD_COUNT)
                {
                    Ok(r) => r,
                    Err(ck_param::ParamErr::Absent) => return CKR_ARGUMENTS_BAD,
                    Err(ck_param::ParamErr::TooShort) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let second_handle = r.ulong32(ck_param::object_handle_param::H_KEY);
                // The second key must permit derivation too (its value is being
                // consumed into a new key), and must have a readable value.
                if let Err(rv) = check_key_usage(_h_session, second_handle, CKA_DERIVE) {
                    return rv;
                }
                let base_val = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_KEY_HANDLE_INVALID,
                };
                let second_val = match get_object_value(second_handle) {
                    Some(v) => v,
                    None => return CKR_KEY_HANDLE_INVALID,
                };
                [base_val.as_slice(), second_val.as_slice()].concat()
            }

            // ── Concatenate base key ‖ data (PKCS#11 v3.2 §6.43.4) ──────────
            // Appends caller-supplied data (ciphertext/pubkey/label) onto the
            // running secret — the transcript-binding step for X-Wing/Chempat.
            // pParameter is a CK_KEY_DERIVATION_STRING_DATA { pData, ulLen }.
            CKM_CONCATENATE_BASE_AND_DATA => {
                let r = match ck_param::mech(p_mechanism)
                    .params(&ck_param::key_deriv_string::LAYOUT, ck_param::key_deriv_string::FIELD_COUNT)
                {
                    Ok(r) => r,
                    Err(ck_param::ParamErr::Absent) => return CKR_ARGUMENTS_BAD,
                    Err(ck_param::ParamErr::TooShort) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let data: &[u8] = r.buffer(
                    ck_param::key_deriv_string::P_DATA,
                    ck_param::key_deriv_string::UL_LEN,
                );
                let base_val = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_KEY_HANDLE_INVALID,
                };
                [base_val.as_slice(), data].concat()
            }

            // ── Digest key derivation (PKCS#11 v3.2 §6.22 SHA-2 / §6.29 SHA-3)
            // Derived value = SHAx(base.CKA_VALUE), left-truncated to an
            // explicit CKA_VALUE_LEN when the template supplies one. The
            // hash-second-step for concat-then-hash combiners. Reuses
            // native::derive::digest_of so the mech→hasher map exists once.
            CKM_SHA256_KEY_DERIVATION
            | CKM_SHA384_KEY_DERIVATION
            | CKM_SHA512_KEY_DERIVATION
            | CKM_SHA3_256_KEY_DERIVATION
            | CKM_SHA3_384_KEY_DERIVATION
            | CKM_SHA3_512_KEY_DERIVATION => {
                let base_val = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_KEY_HANDLE_INVALID,
                };
                let mut digest = match crate::native::derive::digest_of(mech_type, &base_val) {
                    Ok(d) => d,
                    Err(rv) => return rv,
                };
                // Truncate only when the caller EXPLICITLY set CKA_VALUE_LEN
                // (the generic `key_len` default of 32 must not silently clip a
                // longer digest the caller wanted in full).
                if let Some(want) =
                    get_attr_ulong(p_template, ul_attribute_count, CKA_VALUE_LEN)
                {
                    let want = want as usize;
                    if want > digest.len() {
                        return CKR_KEY_SIZE_RANGE;
                    }
                    digest.truncate(want);
                }
                digest
            }

            // ── ECDH ────────────────────────────────────────────────────────
            CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE | CKM_EC_MONTGOMERY_KEY_DERIVE
            | CKM_X25519 | CKM_X448 => {
                // CK_ECDH1_DERIVE_PARAMS — 5 CK_ULONG/pointer fields read at
                // native width (size_of::<usize>()): [kdf, ulSharedDataLen,
                // pSharedData, ulPublicDataLen, pPublicData]. Reading them as
                // u32 at WASM offsets truncated ulPublicDataLen/pPublicData to
                // the wrong words on 64-bit (→ peer_pk_len 0 → ARGUMENTS_BAD).
                let r = match ck_param::mech(p_mechanism)
                    .params(&ck_param::ecdh1::LAYOUT, ck_param::ecdh1::FIELD_COUNT)
                {
                    Ok(r) => r,
                    Err(ck_param::ParamErr::Absent) => return CKR_ARGUMENTS_BAD,
                    Err(ck_param::ParamErr::TooShort) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let peer_pk_raw = r.buffer(
                    ck_param::ecdh1::P_PUBLIC_DATA,
                    ck_param::ecdh1::UL_PUBLIC_DATA_LEN,
                );
                if peer_pk_raw.is_empty() {
                    return CKR_ARGUMENTS_BAD;
                }
                // Strip DER OCTET STRING wrapper if present: 0x04 <len> <point bytes>
                // PKCS#11 v3.2 §2.3.5 allows either raw SEC1 or the DER-wrapped form.
                let peer_pk_bytes: &[u8] = if peer_pk_raw.len() >= 3 && peer_pk_raw[0] == 0x04 {
                    if (peer_pk_raw[1] as usize) + 2 == peer_pk_raw.len() {
                        &peer_pk_raw[2..]
                    } else if peer_pk_raw.len() >= 4
                        && peer_pk_raw[1] == 0x81
                        && (peer_pk_raw[2] as usize) + 3 == peer_pk_raw.len()
                    {
                        &peer_pk_raw[3..]
                    } else if peer_pk_raw.len() >= 5 && peer_pk_raw[1] == 0x82 {
                        let len = ((peer_pk_raw[2] as usize) << 8) | (peer_pk_raw[3] as usize);
                        if len + 4 == peer_pk_raw.len() {
                            &peer_pk_raw[4..]
                        } else {
                            peer_pk_raw
                        }
                    } else {
                        peer_pk_raw
                    }
                } else {
                    peer_pk_raw
                };
                let our_sk_bytes = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                let algo = get_object_algo_family(h_base_key);
                let curve = get_object_param_set(h_base_key);
                // PKCS#11 v3.2 §6.3.18, Table 79 ("ECDH with cofactor:
                // Allowed Key Types") restricts CKM_ECDH1_COFACTOR_DERIVE to
                // CKK_EC — unlike plain ECDH (§6.3.17, Table 78), which also
                // allows CKK_EC_MONTGOMERY (X25519/X448). Reject up front
                // rather than silently computing the same result standard
                // ECDH1_DERIVE would (RFC 7748 clamping already applies its
                // own cofactor clearing, so the math wouldn't even be wrong —
                // but the mechanism is not spec-valid for this key type).
                if mech_type == CKM_ECDH1_COFACTOR_DERIVE
                    && (algo == ALGO_ECDH_X25519 || algo == ALGO_ECDH_X448)
                {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
                let shared = match (algo, curve) {
                    (ALGO_ECDSA, CURVE_P256) | (ALGO_ECDH_P256, _) | (0, CURVE_P256) => {
                        let sk = match p256::NonZeroScalar::try_from(our_sk_bytes.as_slice()) {
                            Ok(s) => s,
                            Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                        };
                        let peer_pk = match p256::PublicKey::from_sec1_bytes(peer_pk_bytes) {
                            Ok(pk) => pk,
                            Err(_) => return CKR_ARGUMENTS_BAD,
                        };
                        p256::ecdh::diffie_hellman(&sk, peer_pk.as_affine())
                            .raw_secret_bytes()
                            .to_vec()
                    }
                    (ALGO_ECDSA, CURVE_K256) | (0, CURVE_K256) => {
                        let sk = match k256::NonZeroScalar::try_from(our_sk_bytes.as_slice()) {
                            Ok(s) => s,
                            Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                        };
                        let peer_pk = match k256::PublicKey::from_sec1_bytes(peer_pk_bytes) {
                            Ok(pk) => pk,
                            Err(_) => return CKR_ARGUMENTS_BAD,
                        };
                        k256::ecdh::diffie_hellman(&sk, peer_pk.as_affine())
                            .raw_secret_bytes()
                            .to_vec()
                    }
                    (ALGO_ECDSA, CURVE_P384) | (0, CURVE_P384) => {
                        let sk = match p384::NonZeroScalar::try_from(our_sk_bytes.as_slice()) {
                            Ok(s) => s,
                            Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                        };
                        let peer_pk = match p384::PublicKey::from_sec1_bytes(peer_pk_bytes) {
                            Ok(pk) => pk,
                            Err(_) => return CKR_ARGUMENTS_BAD,
                        };
                        p384::ecdh::diffie_hellman(&sk, peer_pk.as_affine())
                            .raw_secret_bytes()
                            .to_vec()
                    }
                    (ALGO_ECDSA, CURVE_P521) | (0, CURVE_P521) => {
                        let sk = match p521::NonZeroScalar::try_from(our_sk_bytes.as_slice()) {
                            Ok(s) => s,
                            Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                        };
                        let peer_pk = match p521::PublicKey::from_sec1_bytes(peer_pk_bytes) {
                            Ok(pk) => pk,
                            Err(_) => return CKR_ARGUMENTS_BAD,
                        };
                        p521::ecdh::diffie_hellman(&sk, peer_pk.as_affine())
                            .raw_secret_bytes()
                            .to_vec()
                    }
                    (ALGO_ECDH_X25519, _) => {
                        if our_sk_bytes.len() != 32 || peer_pk_bytes.len() != 32 {
                            return CKR_KEY_TYPE_INCONSISTENT;
                        }
                        let mut sk_arr = [0u8; 32];
                        sk_arr.copy_from_slice(&our_sk_bytes);
                        let sk = x25519_dalek::StaticSecret::from(sk_arr);
                        let mut pk_arr = [0u8; 32];
                        pk_arr.copy_from_slice(peer_pk_bytes);
                        let result = sk
                            .diffie_hellman(&x25519_dalek::PublicKey::from(pk_arr))
                            .as_bytes()
                            .to_vec();
                        pk_arr.zeroize();
                        result
                    }
                    (ALGO_ECDH_X448, _) => {
                        // X448 Diffie-Hellman (PKCS#11 v3.2 §6.7, RFC 7748 §6.2)
                        use x448::{PublicKey as X448PublicKey, StaticSecret as X448StaticSecret};
                        if our_sk_bytes.len() != 56 || peer_pk_bytes.len() != 56 {
                            return CKR_KEY_TYPE_INCONSISTENT;
                        }
                        let mut sk_arr = [0u8; 56];
                        sk_arr.copy_from_slice(&our_sk_bytes);
                        let mut pk_arr = [0u8; 56];
                        pk_arr.copy_from_slice(peer_pk_bytes);
                        let pk = match X448PublicKey::from_bytes(&pk_arr) {
                            Some(pk) => pk,
                            None => return CKR_ARGUMENTS_BAD, // wrong length or low-order point
                        };
                        pk_arr.zeroize();
                        // StaticSecret::from() applies RFC7748 clamping; zeroizes on drop
                        let sk = X448StaticSecret::from(sk_arr);
                        let shared = sk.diffie_hellman(&pk);
                        shared.as_bytes().to_vec()
                    }
                    _ => {
                        if our_sk_bytes.len() == 32 && peer_pk_bytes.len() == 65 {
                            let sk = match p256::NonZeroScalar::try_from(our_sk_bytes.as_slice()) {
                                Ok(s) => s,
                                Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
                            };
                            let peer_pk = match p256::PublicKey::from_sec1_bytes(peer_pk_bytes) {
                                Ok(pk) => pk,
                                Err(_) => return CKR_ARGUMENTS_BAD,
                            };
                            p256::ecdh::diffie_hellman(&sk, peer_pk.as_affine())
                                .raw_secret_bytes()
                                .to_vec()
                        } else {
                            return CKR_KEY_TYPE_INCONSISTENT;
                        }
                    }
                };
                let kdf = r.ulong32(ck_param::ecdh1::KDF);
                let shared_data =
                    r.buffer(ck_param::ecdh1::P_SHARED_DATA, ck_param::ecdh1::UL_SHARED_DATA_LEN);

                match kdf {
                    0x00000001 /* CKD_NULL */ => {
                        if key_len > 0 && key_len < shared.len() {
                            shared[..key_len].to_vec()
                        } else {
                            shared
                        }
                    }
                    0x00000006 /* CKD_SHA256_KDF */
                    | 0x00000007 /* CKD_SHA384_KDF */
                    | 0x00000008 /* CKD_SHA512_KDF */ => {
                        use sha2::Digest;
                        macro_rules! x963_kdf {
                            ($Hash:ty) => {{
                                let mut out = Vec::new();
                                let mut counter: u32 = 1;
                                while out.len() < key_len {
                                    let mut hasher = <$Hash>::new();
                                    hasher.update(&shared);
                                    hasher.update(&counter.to_be_bytes());
                                    hasher.update(shared_data);
                                    out.extend_from_slice(&hasher.finalize());
                                    counter += 1;
                                }
                                out.truncate(key_len);
                                out
                            }};
                        }
                        match kdf {
                            0x00000007 => x963_kdf!(sha2::Sha384),
                            0x00000008 => x963_kdf!(sha2::Sha512),
                            _ => x963_kdf!(sha2::Sha256),
                        }
                    }
                    CKD_SHA3_256_KDF | CKD_SHA3_512_KDF => {
                        // PKCS#11 v3.2 §5.2.12 — X9.63 KDF with SHA3-256 / SHA3-512
                        use sha3::Digest;
                        macro_rules! x963_kdf_sha3 {
                            ($Hash:ty) => {{
                                let mut out = Vec::new();
                                let mut counter: u32 = 1;
                                while out.len() < key_len {
                                    let mut hasher = <$Hash>::new();
                                    hasher.update(&shared);
                                    hasher.update(&counter.to_be_bytes());
                                    hasher.update(shared_data);
                                    out.extend_from_slice(&hasher.finalize());
                                    counter += 1;
                                }
                                out.truncate(key_len);
                                out
                            }};
                        }
                        match kdf {
                            CKD_SHA3_512_KDF => x963_kdf_sha3!(sha3::Sha3_512),
                            _ => x963_kdf_sha3!(sha3::Sha3_256),
                        }
                    }
                    _ => return CKR_MECHANISM_INVALID,
                }
            }

            // ── PBKDF2 ──────────────────────────────────────────────────────
            CKM_PKCS5_PBKD2 => {
                let r = match ck_param::mech(p_mechanism)
                    .params(&ck_param::pbkd2::LAYOUT, ck_param::pbkd2::FIELD_COUNT)
                {
                    Ok(r) => r,
                    Err(ck_param::ParamErr::Absent) => return CKR_ARGUMENTS_BAD,
                    Err(ck_param::ParamErr::TooShort) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let iterations = r.ulong32(ck_param::pbkd2::ITERATIONS);
                if iterations < 1000 {
                    return CKR_ARGUMENTS_BAD;
                }
                let prf = r.ulong32(ck_param::pbkd2::PRF);
                let salt = r.buffer(
                    ck_param::pbkd2::P_SALT_SOURCE_DATA,
                    ck_param::pbkd2::UL_SALT_SOURCE_DATA_LEN,
                );
                let pass = r.buffer(
                    ck_param::pbkd2::P_PASSWORD,
                    ck_param::pbkd2::UL_PASSWORD_LEN,
                );
                let mut out = vec![0u8; key_len];
                match prf {
                    CKP_PBKDF2_HMAC_SHA256 => {
                        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass, salt, iterations, &mut out)
                    }
                    CKP_PBKDF2_HMAC_SHA384 => {
                        pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pass, salt, iterations, &mut out)
                    }
                    CKP_PBKDF2_HMAC_SHA512 => {
                        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pass, salt, iterations, &mut out)
                    }
                    _ => return CKR_ARGUMENTS_BAD,
                }
                out
            }

            // ── HKDF ────────────────────────────────────────────────────────
            CKM_HKDF_DERIVE => {
                let ikm = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                let r = match ck_param::mech(p_mechanism)
                    .params(&ck_param::hkdf::LAYOUT, ck_param::hkdf::FIELD_COUNT)
                {
                    Ok(r) => r,
                    Err(ck_param::ParamErr::Absent) => return CKR_ARGUMENTS_BAD,
                    Err(ck_param::ParamErr::TooShort) => return CKR_MECHANISM_PARAM_INVALID,
                };
                // bExtract/bExpand are two ADJACENT CK_BBOOLs, at bytes 0 and
                // 1 — not at word 0 and word 1. The old code extracted bExpand
                // by shifting the first word right by 8, which is the same
                // byte on a little-endian host and the wrong one on a
                // big-endian one; `bbool()` reads byte 1 on both.
                let b_expand = r.bbool(ck_param::hkdf::B_EXPAND);
                let prf = r.ulong32(ck_param::hkdf::PRF_HASH_MECHANISM);
                let salt_type = r.ulong32(ck_param::hkdf::UL_SALT_TYPE);
                // Salt-as-key (CKF_HKDF_SALT_KEY): the salt is another key
                // handle (hSaltKey @ word5); HKDF-Extract keys HMAC on its
                // CKA_VALUE — the keyed dual-PRF combiner form,
                // HMAC(salt_key.value, ikm). The salt key's value is read
                // in-HSM and never leaves; it need NOT be extractable (using a
                // key internally is not exporting it).
                let salt_owned: Option<Vec<u8>> = if salt_type == CKF_HKDF_SALT_KEY {
                    let h_salt = r.ulong32(ck_param::hkdf::H_SALT_KEY);
                    match get_object_value(h_salt) {
                        Some(v) => Some(v),
                        None => return CKR_KEY_HANDLE_INVALID,
                    }
                } else {
                    None
                };
                let salt_opt: Option<&[u8]> = if let Some(ref v) = salt_owned {
                    Some(v.as_slice())
                } else if salt_type == CKF_HKDF_SALT_DATA {
                    match r.buffer(ck_param::hkdf::P_SALT, ck_param::hkdf::UL_SALT_LEN) {
                        [] => None,
                        v => Some(v),
                    }
                } else {
                    None
                };
                let info = r.buffer(ck_param::hkdf::P_INFO, ck_param::hkdf::UL_INFO_LEN);
                let mut out = vec![0u8; key_len];
                // PRF dispatch must be exhaustive over every hash this engine
                // can name, with a hard rejection for anything else — the
                // previous `_ => SHA-256` fallback silently substituted the
                // wrong hash (and returned CKR_OK) for any PRF outside a
                // 4-way allowlist, confirmed against real ACVP KDA-HKDF
                // vectors (2026-08-30). CKR_MECHANISM_PARAM_INVALID matches
                // the honest-failure convention already used by the
                // SP800-108 Counter/Feedback PRF dispatch below.
                if b_expand {
                    macro_rules! hkdf_expand {
                        ($H:ty) => {{
                            let hk = hkdf::Hkdf::<$H>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }};
                    }
                    match prf {
                        CKM_SHA_1 => hkdf_expand!(sha1::Sha1),
                        CKM_SHA224 => hkdf_expand!(sha2::Sha224),
                        CKM_SHA256 => hkdf_expand!(sha2::Sha256),
                        CKM_SHA384 => hkdf_expand!(sha2::Sha384),
                        CKM_SHA512 => hkdf_expand!(sha2::Sha512),
                        CKM_SHA512_224 => hkdf_expand!(sha2::Sha512_224),
                        CKM_SHA512_256 => hkdf_expand!(sha2::Sha512_256),
                        CKM_SHA3_224 => hkdf_expand!(sha3::Sha3_224),
                        CKM_SHA3_256 => hkdf_expand!(sha3::Sha3_256),
                        CKM_SHA3_384 => hkdf_expand!(sha3::Sha3_384),
                        CKM_SHA3_512 => hkdf_expand!(sha3::Sha3_512),
                        _ => return CKR_MECHANISM_PARAM_INVALID,
                    }
                } else {
                    // extract-only: write PRK to output using the requested PRF
                    macro_rules! hkdf_extract {
                        ($H:ty) => {{
                            let (prk, _) = hkdf::Hkdf::<$H>::extract(salt_opt, &ikm);
                            let copy_len = key_len.min(prk.len());
                            out[..copy_len].copy_from_slice(&prk[..copy_len]);
                        }};
                    }
                    match prf {
                        CKM_SHA_1 => hkdf_extract!(sha1::Sha1),
                        CKM_SHA224 => hkdf_extract!(sha2::Sha224),
                        CKM_SHA256 => hkdf_extract!(sha2::Sha256),
                        CKM_SHA384 => hkdf_extract!(sha2::Sha384),
                        CKM_SHA512 => hkdf_extract!(sha2::Sha512),
                        CKM_SHA512_224 => hkdf_extract!(sha2::Sha512_224),
                        CKM_SHA512_256 => hkdf_extract!(sha2::Sha512_256),
                        CKM_SHA3_224 => hkdf_extract!(sha3::Sha3_224),
                        CKM_SHA3_256 => hkdf_extract!(sha3::Sha3_256),
                        CKM_SHA3_384 => hkdf_extract!(sha3::Sha3_384),
                        CKM_SHA3_512 => hkdf_extract!(sha3::Sha3_512),
                        _ => return CKR_MECHANISM_PARAM_INVALID,
                    }
                }
                out
            }

            // ── SP 800-108 Counter KBKDF ─────────────────────────────────────
            CKM_SP800_108_COUNTER_KDF => {
                let base_key = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                // CK_SP800_108_KDF_PARAMS. Only the first three fields are
                // required: this engine does not implement the trailing
                // additional-derived-key pair, so demanding the whole struct
                // would reject a conformant caller that omits it.
                let r = match ck_param::mech(p_mechanism)
                    .params(&ck_param::sp800_108_kdf::LAYOUT, 3)
                {
                    Ok(r) => r,
                    Err(ck_param::ParamErr::Absent) => return CKR_ARGUMENTS_BAD,
                    Err(ck_param::ParamErr::TooShort) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let prf_type = r.ulong32(ck_param::sp800_108_kdf::PRF_TYPE);
                let num_segs = r.ulong(ck_param::sp800_108_kdf::UL_NUMBER_OF_DATA_PARAMS);
                let p_segs = r.ptr(ck_param::sp800_108_kdf::P_DATA_PARAMS);
                // SP 800-108 §4.1 / PKCS#11 §6.x — process the data params IN
                // ORDER. Supported segment types: ITERATION_VARIABLE (counter
                // at caller-specified width/endianness), DKM_LENGTH ([L]
                // field), BYTE_ARRAY (fixed input), KEY_HANDLE (spliced-in key
                // value). Legacy default when no ITERATION_VARIABLE is
                // present: 32-bit BE counter prefix. Table 199 — the separate
                // CK_SP800_108_COUNTER field is invalid for Counter Mode.
                let segs = match parse_sp800_108_segments(
                    p_segs,
                    num_segs,
                    key_len,
                    prf_type,
                    base_key.len(),
                    /* allow_explicit_counter */ false,
                ) {
                    Ok(s) => s,
                    Err(rv) => return rv,
                };
                match sp800_108_counter_kbkdf(prf_type, &base_key, &segs, key_len) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }

            // ── SP 800-108 Feedback KBKDF ────────────────────────────────────
            CKM_SP800_108_FEEDBACK_KDF => {
                let base_key = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                // CK_SP800_108_FEEDBACK_KDF_PARAMS — five required fields;
                // the additional-derived-key tail is not implemented.
                let r = match ck_param::mech(p_mechanism)
                    .params(&ck_param::sp800_108_feedback::LAYOUT, 5)
                {
                    Ok(r) => r,
                    Err(ck_param::ParamErr::Absent) => return CKR_ARGUMENTS_BAD,
                    Err(ck_param::ParamErr::TooShort) => return CKR_MECHANISM_PARAM_INVALID,
                };
                let prf_type = r.ulong32(ck_param::sp800_108_feedback::PRF_TYPE);
                let num_segs = r.ulong(ck_param::sp800_108_feedback::UL_NUMBER_OF_DATA_PARAMS);
                let p_segs = r.ptr(ck_param::sp800_108_feedback::P_DATA_PARAMS);
                let iv = r
                    .buffer(
                        ck_param::sp800_108_feedback::P_IV,
                        ck_param::sp800_108_feedback::UL_IV_LEN,
                    )
                    .to_vec();
                // SP 800-108 §4.2 — ordered data params: optional counter at
                // caller width/endianness, [L] field, byte arrays, spliced-in
                // key values. K(0) = IV. Table 200 — CK_SP800_108_COUNTER is
                // optional for Feedback Mode (unlike Counter Mode).
                let segs = match parse_sp800_108_segments(
                    p_segs,
                    num_segs,
                    key_len,
                    prf_type,
                    base_key.len(),
                    /* allow_explicit_counter */ true,
                ) {
                    Ok(s) => s,
                    Err(rv) => return rv,
                };
                // K(i) = PRF(base_key, K(i-1) || [i] || fixed || [L])
                match sp800_108_feedback_kbkdf(prf_type, &base_key, &iv, &segs, key_len) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }

            _ => return CKR_MECHANISM_INVALID,
        };

        let mut attrs = HashMap::new();
        let vlen = key_value.len() as u32;
        attrs.insert(CKA_VALUE, key_value);
        store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
        store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        store_bool(&mut attrs, CKA_SENSITIVE, false);
        store_ulong(&mut attrs, CKA_VALUE_LEN, vlen);
        // PKCS#11 v3.2 §4.1 defaults — caller may override via template
        store_bool(&mut attrs, CKA_TOKEN, false);
        store_bool(&mut attrs, CKA_PRIVATE, false);
        absorb_template_attrs(&mut attrs, p_template, ul_attribute_count);
        // Server-managed attributes — set AFTER absorb to override any caller-provided values.
        // PKCS#11 v3.2 §4.3 Table 13 — a DERIVED key is NOT locally generated:
        // CKA_LOCAL = FALSE and CKA_KEY_GEN_MECHANISM = CK_UNAVAILABLE_INFORMATION.
        store_bool(&mut attrs, CKA_LOCAL, false);
        store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
        // PKCS#11 v3.2 §4.9/§4.10 — a key derived from external material can never
        // be marked ALWAYS_SENSITIVE / NEVER_EXTRACTABLE.
        store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
        store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);

        // PKCS#11 v3.2 §4.11: KCV mandatory on every secret-key derivation result.
        crate::state::compute_kcv(&mut attrs);

        *ph_key = allocate_handle_owned(_h_session, attrs);
    }
    CKR_OK
}

// ── Key Wrap/Unwrap ─────────────────────────────────────────────────────────

/// PKCS#11 v3.2 §4.9/§4.10 (CKA_WRAP_WITH_TRUSTED) + §4.1.1 Table 12
/// (CKA_TRUSTED) — a key with CKA_WRAP_WITH_TRUSTED=TRUE may only be wrapped
/// by a wrapping key whose CKA_TRUSTED=TRUE. Returns true when the policy is
/// violated (caller must fail with CKR_KEY_NOT_WRAPPABLE).
fn wrap_with_trusted_violation(h_wrapping_key: u32, h_key: u32) -> bool {
    OBJECTS.with(|o| {
        let store = o.borrow();
        let wwt = store
            .get(&h_key)
            .map(|a| read_bool_attr(a, CKA_WRAP_WITH_TRUSTED))
            .unwrap_or(false);
        if !wwt {
            return false;
        }
        let trusted = store
            .get(&h_wrapping_key)
            .map(|a| read_bool_attr(a, CKA_TRUSTED))
            .unwrap_or(false);
        !trusted
    })
}

/// AES-CBC key wrap (CKM_AES_CBC / CKM_AES_CBC_PAD, PKCS#11 v3.2 §6.27): the
/// target key bytes are encrypted under the KEK with the caller IV. `pad` ⇒
/// PKCS#7 (arbitrary length); otherwise the data must already be a multiple of
/// the 16-byte block (CKM_AES_CBC). The AES variant is fixed by the KEK length.
unsafe fn aes_cbc_encrypt_wrap(kek: &[u8], iv: &[u8], data: &[u8], pad: bool) -> Result<Vec<u8>, u32> {
    use aes::cipher::{
        block_padding::{NoPadding, Pkcs7},
        BlockEncryptMut, KeyIvInit,
    };
    if iv.len() != 16 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    if !pad && data.len() % 16 != 0 {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let buf_len = if pad {
        data.len() + 16 - (data.len() % 16)
    } else {
        data.len()
    };
    let mut buf = vec![0u8; buf_len];
    buf[..data.len()].copy_from_slice(data);
    macro_rules! enc {
        ($t:ty) => {{
            let c = <cbc::Encryptor<$t>>::new_from_slices(kek, iv)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let ct = if pad {
                c.encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
            } else {
                c.encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
            }
            .map_err(|_| CKR_FUNCTION_FAILED)?;
            ct.to_vec()
        }};
    }
    match kek.len() {
        16 => Ok(enc!(aes::Aes128)),
        24 => Ok(enc!(aes::Aes192)),
        32 => Ok(enc!(aes::Aes256)),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// AES-CBC key unwrap — inverse of [`aes_cbc_encrypt_wrap`].
unsafe fn aes_cbc_decrypt_unwrap(kek: &[u8], iv: &[u8], ct: &[u8], pad: bool) -> Result<Vec<u8>, u32> {
    use aes::cipher::{
        block_padding::{NoPadding, Pkcs7},
        BlockDecryptMut, KeyIvInit,
    };
    if iv.len() != 16 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    if ct.is_empty() || ct.len() % 16 != 0 {
        return Err(CKR_WRAPPED_KEY_LEN_RANGE);
    }
    let mut buf = ct.to_vec();
    macro_rules! dec {
        ($t:ty) => {{
            let c = <cbc::Decryptor<$t>>::new_from_slices(kek, iv)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let pt = if pad {
                c.decrypt_padded_mut::<Pkcs7>(&mut buf)
            } else {
                c.decrypt_padded_mut::<NoPadding>(&mut buf)
            }
            .map_err(|_| CKR_WRAPPED_KEY_INVALID)?;
            pt.to_vec()
        }};
    }
    match kek.len() {
        16 => Ok(dec!(aes::Aes128)),
        24 => Ok(dec!(aes::Aes192)),
        32 => Ok(dec!(aes::Aes256)),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// The `AlgorithmIdentifier` DER for a post-quantum key type + parameter set,
/// lifted from the engine's own SPKI builder for that combination so the
/// PKCS#8 (E6) and SPKI (§4.14) encodings cannot name different OIDs.
/// `None` for a combination with no OID assignment in this engine.
fn pqc_alg_id_from_spki(key_type: u32, ps: u32) -> Option<Vec<u8>> {
    use crate::crypto::handlers::*;
    let spki = match key_type {
        CKK_ML_KEM => match ps {
            CKP_ML_KEM_512 => build_mlkem512_spki(&[]),
            CKP_ML_KEM_768 => build_mlkem768_spki(&[]),
            CKP_ML_KEM_1024 => build_mlkem1024_spki(&[]),
            _ => return None,
        },
        CKK_ML_DSA => match ps {
            CKP_ML_DSA_44 => build_mldsa44_spki(&[]),
            CKP_ML_DSA_65 => build_mldsa65_spki(&[]),
            CKP_ML_DSA_87 => build_mldsa87_spki(&[]),
            _ => return None,
        },
        CKK_SLH_DSA => build_slhdsa_spki(ps, &[]),
        // HSS/XMSS/XMSS^MT: §6.7 lists them, but this engine has no
        // AlgorithmIdentifier table for them yet. Refusing is honest; a
        // wrong OID would be worse than a refusal.
        _ => return None,
    };
    if spki.is_empty() {
        return None;
    }
    // SPKI ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }. Skip the outer
    // header and return the AlgorithmIdentifier TLV verbatim.
    let mut i = 1usize;
    let first = *spki.get(i)?;
    i += 1;
    if first & 0x80 != 0 {
        i += (first & 0x7f) as usize;
    }
    let alg_start = i;
    let alg_len_byte = *spki.get(i + 1)?;
    let (hdr, len) = if alg_len_byte & 0x80 == 0 {
        (2usize, alg_len_byte as usize)
    } else {
        let n = (alg_len_byte & 0x7f) as usize;
        let mut l = 0usize;
        for k in 0..n {
            l = (l << 8) | *spki.get(i + 2 + k)? as usize;
        }
        (2 + n, l)
    };
    spki.get(alg_start..alg_start + hdr + len).map(|b| b.to_vec())
}

/// E6 (2026-08-13) — §6.7: "For wrapping, a private key is BER-encoded
/// according to [PKCS #8] PrivateKeyInfo ASN.1 type. [PKCS #8] requires an
/// algorithm identifier for the type of the private key."
///
/// `C_WrapKey` wrapped the RAW STORED VALUE. An RSA key came out as PKCS#8 by
/// accident (that happens to be how this engine stores it); EC, Ed25519 and
/// every post-quantum key came out as raw bytes; an EC public key came out as
/// the engine's internal packed blob. The format therefore varied BY KEY TYPE
/// WITHIN ONE ENGINE, so no consumer could parse the output without
/// out-of-band knowledge of which key it had just wrapped.
///
/// Depends on E5: §6.7's RSA arm needs the CRT components, which this engine
/// did not write until that item landed.
///
/// Returns the DER `PrivateKeyInfo` for `attrs`, or `Err(CKR_KEY_NOT_WRAPPABLE)`
/// for a private key type §6.7 does not enumerate.
fn pkcs8_private_key_info(attrs: &Attributes) -> Result<Vec<u8>, u32> {
    let key_type = attrs
        .get(&CKA_KEY_TYPE)
        .filter(|v| v.len() >= 4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        .ok_or(CKR_KEY_NOT_WRAPPABLE)?;
    let raw = attrs.get(&CKA_VALUE).cloned().ok_or(CKR_KEY_NOT_WRAPPABLE)?;

    // Already a PrivateKeyInfo? The RSA path stores the PKCS#8 DER directly,
    // so re-wrapping it would produce a doubly-encoded structure.
    if key_type == CKK_RSA {
        return Ok(raw);
    }

    // AlgorithmIdentifier for each family §6.7 enumerates.
    let alg_id: Vec<u8> = match key_type {
        // id-ecPublicKey (1.2.840.10045.2.1) + the named-curve parameter.
        CKK_EC => {
            let curve = attrs.get(&CKA_EC_PARAMS).cloned().ok_or(CKR_KEY_NOT_WRAPPABLE)?;
            let mut inner = vec![
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            ];
            inner.extend_from_slice(&curve);
            der_sequence(&inner)
        }
        // Ed25519 / X25519 / X448 carry no AlgorithmIdentifier parameters
        // (RFC 8410 §3: "the parameters field MUST be absent").
        CKK_EC_EDWARDS => der_sequence(&[0x06, 0x03, 0x2b, 0x65, 0x70]),
        CKK_EC_MONTGOMERY => {
            let curve = attrs.get(&CKA_EC_PARAMS).cloned().unwrap_or_default();
            let oid = if curve.last() == Some(&0x6f) {
                [0x06u8, 0x03, 0x2b, 0x65, 0x6f]
            } else {
                [0x06u8, 0x03, 0x2b, 0x65, 0x6e]
            };
            der_sequence(&oid)
        }
        // NIST PQC OIDs are parameter-set-specific; the parameter set is
        // already on the object, and the engine's SPKI builders hold the same
        // table. Reuse it so the two encodings cannot disagree.
        CKK_ML_DSA | CKK_ML_KEM | CKK_SLH_DSA | CKK_HSS | CKK_XMSS | CKK_XMSSMT => {
            let ps = attrs
                .get(&CKA_PRIV_PARAM_SET)
                .filter(|v| v.len() >= 4)
                .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
                .unwrap_or(0);
            // Reuse the SPKI builders' own AlgorithmIdentifier bytes: build
            // an SPKI over an empty key and take its leading AlgId SEQUENCE,
            // so the PKCS#8 and SPKI encodings can never name different OIDs
            // for the same key.
            match pqc_alg_id_from_spki(key_type, ps) {
                Some(a) => a,
                None => return Err(CKR_KEY_NOT_WRAPPABLE),
            }
        }
        _ => return Err(CKR_KEY_NOT_WRAPPABLE),
    };

    // PrivateKeyInfo ::= SEQUENCE { version INTEGER (0), privateKeyAlgorithm
    //                               AlgorithmIdentifier, privateKey OCTET STRING }
    let mut body = vec![0x02, 0x01, 0x00]; // version 0
    body.extend_from_slice(&alg_id);
    body.extend_from_slice(&der_octet_string(&raw));
    Ok(der_sequence(&body))
}

/// DER SEQUENCE around `body` (definite length, long form when needed).
fn der_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    der_push_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// DER OCTET STRING around `body`.
fn der_octet_string(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    der_push_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn der_push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

#[wasm_bindgen(js_name = _C_WrapKey)]
pub fn C_WrapKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_wrapping_key: u32,
    h_key: u32,
    p_wrapped_key: *mut u8,
    pul_wrapped_key_len: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        let is_kwp = mech_type == CKM_AES_KEY_WRAP_KWP || mech_type == CKM_AES_KEY_WRAP_PAD;
        let is_aes_wrap = mech_type == CKM_AES_KEY_WRAP || is_kwp;
        let is_rsa_oaep = mech_type == CKM_RSA_PKCS_OAEP;
        // WS-11 Phase 1 (2026-08-28) — raw RSA PKCS#1 v1.5 wrap, closing the
        // Extended Provider (EXT-M-1-32) gap: mechanism_info advertised
        // CKF_WRAP|CKF_UNWRAP for CKM_RSA_PKCS with neither backed by a real
        // dispatch arm — an application checking capabilities before use
        // would have concluded the engine could do what it in fact could
        // not, the exact under-advertised-capability class already fixed
        // for CKM_RSA_PKCS_OAEP/AES_CBC above. Same PKCS1v15 padding
        // primitive C_Encrypt/C_Decrypt's CKM_RSA_PKCS arms already use.
        let is_rsa_pkcs = mech_type == CKM_RSA_PKCS;
        let is_aes_cbc = mech_type == CKM_AES_CBC || mech_type == CKM_AES_CBC_PAD;
        if !is_aes_wrap && !is_rsa_oaep && !is_rsa_pkcs && !is_aes_cbc {
            return CKR_MECHANISM_INVALID;
        }

        // PKCS#11 v3.2 §5.18.2 — wrapping key: handle exists + visible (login
        // gate) → else CKR_WRAPPING_KEY_HANDLE_INVALID; then CKA_WRAP → else
        // CKR_KEY_FUNCTION_NOT_PERMITTED.
        if let Err(rv) =
            check_key_usage_as(_h_session, h_wrapping_key, CKA_WRAP, CKR_WRAPPING_KEY_HANDLE_INVALID)
        {
            return rv;
        }
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS on the wrapping key.
        if let Err(rv) = check_mechanism_allowed(h_wrapping_key, mech_type) {
            return rv;
        }

        // Target key: handle exists + visible → else CKR_KEY_HANDLE_INVALID;
        // CKR_KEY_UNEXTRACTABLE only when the key EXISTS but CKA_EXTRACTABLE=FALSE.
        let target_attrs = match OBJECTS.with(|o| o.borrow().get(&h_key).cloned()) {
            Some(a) => a,
            None => return CKR_KEY_HANDLE_INVALID,
        };
        if !crate::state::can_access_object(_h_session, &target_attrs) {
            return CKR_KEY_HANDLE_INVALID;
        }
        if !read_bool_attr(&target_attrs, CKA_EXTRACTABLE) {
            return CKR_KEY_UNEXTRACTABLE;
        }

        // CKA_WRAP_WITH_TRUSTED=TRUE on the target requires CKA_TRUSTED=TRUE
        // on the wrapping key (PKCS#11 v3.2 §4.9/§4.10).
        if wrap_with_trusted_violation(h_wrapping_key, h_key) {
            return CKR_KEY_NOT_WRAPPABLE;
        }

        // S2 (2026-08-13) — §5.18.3: "To partition the wrapping keys so they
        // can only wrap a subset of extractable keys the attribute
        // CKA_WRAP_TEMPLATE can be used on the wrapping key … If any
        // attribute mismatch occurs on an attempt to wrap a key then the
        // function SHALL return CKR_KEY_HANDLE_INVALID." The whole mechanism
        // was absent from this engine — neither attribute was defined,
        // stored, read nor enforced — so an application that believed it had
        // constrained a wrapping key had constrained nothing.
        let kek_attrs = match OBJECTS.with(|o| o.borrow().get(&h_wrapping_key).cloned()) {
            Some(a) => a,
            None => return CKR_WRAPPING_KEY_HANDLE_INVALID,
        };
        if !crate::state::key_template_permits(&kek_attrs, CKA_WRAP_TEMPLATE, &target_attrs) {
            return CKR_KEY_HANDLE_INVALID;
        }

        let wrapping_key = match get_object_value(h_wrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        // E6 (2026-08-13) — §6.7: a PRIVATE key is BER-encoded as a PKCS#8
        // PrivateKeyInfo for wrapping. Everything else (secret keys) is
        // wrapped as its raw value, which is what §6.7 describes.
        //
        // §5.18.3 class checks, also missing: "C_WrapKey wraps (i.e.,
        // encrypts) a private or secret key" and can be used "To wrap any
        // secret key with a public key…", "any secret key with any other
        // secret key", "a private key with any secret key". A PUBLIC key is
        // not a wrappable object — it was previously wrapped as the engine's
        // internal packed modulus/exponent blob, a format no consumer can
        // parse.
        let target_class = target_attrs
            .get(&CKA_CLASS)
            .filter(|v| v.len() >= 4)
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
        let key_to_wrap = match target_class {
            Some(CKO_PRIVATE_KEY) => match pkcs8_private_key_info(&target_attrs) {
                Ok(v) => v,
                Err(rv) => return rv,
            },
            Some(CKO_SECRET_KEY) => match get_object_value(h_key) {
                Some(v) => v,
                None => return CKR_ARGUMENTS_BAD,
            },
            _ => return CKR_KEY_NOT_WRAPPABLE,
        };

        let wrapped = if is_aes_cbc {
            // AES-CBC(-PAD) wrap — IV is the 16-byte mechanism parameter.
            // The parameter here is a bare 16-byte IV, not a struct — but it
            // still travels in CK_MECHANISM.pParameter/ulParameterLen, whose
            // own offsets move with the ABI.
            let iv = ck_param::mech(p_mechanism).raw();
            if iv.len() != 16 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            match aes_cbc_encrypt_wrap(
                &wrapping_key,
                iv,
                &key_to_wrap,
                mech_type == CKM_AES_CBC_PAD,
            ) {
                Ok(v) => v,
                Err(rv) => return rv,
            }
        } else if is_rsa_oaep {
            // RSA-OAEP wrapping — encrypt key value with RSA public key.
            // Full CK_RSA_PKCS_OAEP_PARAMS (§6.4.4): hash, MGF, label.
            let ck_param::Mech { p_parameter: p_param, ul_parameter_len: ul_param_len, .. } =
                ck_param::mech(p_mechanism);
            let (hash_alg, mgf, label) = match parse_oaep_params(p_param, ul_param_len) {
                Ok(v) => v,
                Err(rv) => return rv,
            };
            if wrapping_key.len() < 8 {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            let n_len = u32::from_le_bytes([
                wrapping_key[0],
                wrapping_key[1],
                wrapping_key[2],
                wrapping_key[3],
            ]) as usize;
            if wrapping_key.len() < 4 + n_len + 1 {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            let n = rsa::BigUint::from_bytes_be(&wrapping_key[4..4 + n_len]);
            let e = rsa::BigUint::from_bytes_be(&wrapping_key[4 + n_len..]);
            let pk = match rsa::RsaPublicKey::new(n, e) {
                Ok(k) => k,
                Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
            };
            let oaep = match oaep_padding(hash_alg, mgf, &label) {
                Ok(o) => o,
                Err(rv) => return rv,
            };
            with_rng!(rng, {
                match pk.encrypt(&mut rng, oaep, &key_to_wrap) {
                    Ok(ct) => ct,
                    Err(_) => return CKR_FUNCTION_FAILED,
                }
            })
        } else if is_rsa_pkcs {
            // Raw RSA PKCS#1 v1.5 wrap — same packed-modulus wrapping-key
            // parse as the OAEP arm above, PKCS1v15 padding instead of OAEP.
            if wrapping_key.len() < 8 {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            let n_len = u32::from_le_bytes([
                wrapping_key[0],
                wrapping_key[1],
                wrapping_key[2],
                wrapping_key[3],
            ]) as usize;
            if wrapping_key.len() < 4 + n_len + 1 {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
            let n = rsa::BigUint::from_bytes_be(&wrapping_key[4..4 + n_len]);
            let e = rsa::BigUint::from_bytes_be(&wrapping_key[4 + n_len..]);
            let pk = match rsa::RsaPublicKey::new(n, e) {
                Ok(k) => k,
                Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
            };
            with_rng!(rng, {
                match pk.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &key_to_wrap) {
                    Ok(ct) => ct,
                    Err(_) => return CKR_FUNCTION_FAILED,
                }
            })
        } else if is_kwp {
            use aes::cipher::generic_array::GenericArray;
            // AES-KWP (RFC 5649) — supports arbitrary-length data
            if key_to_wrap.is_empty() {
                return CKR_DATA_INVALID;
            }
            let result = match wrapping_key.len() {
                16 => aes_kw::KekAes128::new(GenericArray::from_slice(&wrapping_key))
                    .wrap_with_padding_vec(&key_to_wrap),
                24 => aes_kw::KekAes192::new(GenericArray::from_slice(&wrapping_key))
                    .wrap_with_padding_vec(&key_to_wrap),
                32 => aes_kw::KekAes256::new(GenericArray::from_slice(&wrapping_key))
                    .wrap_with_padding_vec(&key_to_wrap),
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };
            match result {
                Ok(v) => v,
                Err(_) => return CKR_FUNCTION_FAILED,
            }
        } else {
            use aes::cipher::generic_array::GenericArray;
            // AES-KW (RFC 3394) — requires data to be multiple of 8 and >= 16
            if key_to_wrap.len() % 8 != 0 || key_to_wrap.len() < 16 {
                return CKR_DATA_INVALID;
            }
            let mut buf = vec![0u8; key_to_wrap.len() + 8];
            let wrap_ok = match wrapping_key.len() {
                16 => aes_kw::KekAes128::new(GenericArray::from_slice(&wrapping_key))
                    .wrap(&key_to_wrap, &mut buf)
                    .is_ok(),
                24 => aes_kw::KekAes192::new(GenericArray::from_slice(&wrapping_key))
                    .wrap(&key_to_wrap, &mut buf)
                    .is_ok(),
                32 => aes_kw::KekAes256::new(GenericArray::from_slice(&wrapping_key))
                    .wrap(&key_to_wrap, &mut buf)
                    .is_ok(),
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };
            if !wrap_ok {
                return CKR_FUNCTION_FAILED;
            }
            buf
        };

        if p_wrapped_key.is_null() {
            *pul_wrapped_key_len = wrapped.len() as u32;
            return CKR_OK;
        }
        if (*pul_wrapped_key_len as usize) < wrapped.len() {
            *pul_wrapped_key_len = wrapped.len() as u32;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(wrapped.as_ptr(), p_wrapped_key, wrapped.len());
        *pul_wrapped_key_len = wrapped.len() as u32;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_UnwrapKey)]
pub fn C_UnwrapKey(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_unwrapping_key: u32,
    p_wrapped_key: *mut u8,
    ul_wrapped_key_len: u32,
    p_template: *mut u8,
    ul_attribute_count: u32,
    ph_key: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    // §5.18.4 — pWrappedKey is the input ciphertext and phKey the required
    // out-param; neither may be NULL.
    nonnull!(p_mechanism, p_wrapped_key, ph_key);
    unsafe {
        // S7 — §5.7.1, before any unwrap work.
        if let Err(rv) =
            gate_ro_session_for_template(_h_session, p_template, ul_attribute_count)
        {
            return rv;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        let is_kwp = mech_type == CKM_AES_KEY_WRAP_KWP || mech_type == CKM_AES_KEY_WRAP_PAD;
        let is_aes_wrap = mech_type == CKM_AES_KEY_WRAP || is_kwp;
        let is_rsa_oaep = mech_type == CKM_RSA_PKCS_OAEP;
        // WS-11 Phase 1 — mirrors C_WrapKey's is_rsa_pkcs above.
        let is_rsa_pkcs = mech_type == CKM_RSA_PKCS;
        let is_aes_cbc = mech_type == CKM_AES_CBC || mech_type == CKM_AES_CBC_PAD;
        if !is_aes_wrap && !is_rsa_oaep && !is_rsa_pkcs && !is_aes_cbc {
            return CKR_MECHANISM_INVALID;
        }

        // PKCS#11 v3.2 §5.18.4 — unwrapping key: handle exists + visible
        // (login gate) → else CKR_UNWRAPPING_KEY_HANDLE_INVALID; then
        // CKA_UNWRAP → else CKR_KEY_FUNCTION_NOT_PERMITTED.
        if let Err(rv) = check_key_usage_as(
            _h_session,
            h_unwrapping_key,
            CKA_UNWRAP,
            CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        ) {
            return rv;
        }
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS on the unwrapping key.
        if let Err(rv) = check_mechanism_allowed(h_unwrapping_key, mech_type) {
            return rv;
        }

        let unwrapping_key = match get_object_value(h_unwrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let wrapped_data = std::slice::from_raw_parts(p_wrapped_key, ul_wrapped_key_len as usize);

        let key_value = if is_aes_cbc {
            // AES-CBC(-PAD) unwrap — IV is the 16-byte mechanism parameter.
            // The parameter here is a bare 16-byte IV, not a struct — but it
            // still travels in CK_MECHANISM.pParameter/ulParameterLen, whose
            // own offsets move with the ABI.
            let iv = ck_param::mech(p_mechanism).raw();
            if iv.len() != 16 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            match aes_cbc_decrypt_unwrap(
                &unwrapping_key,
                iv,
                wrapped_data,
                mech_type == CKM_AES_CBC_PAD,
            ) {
                Ok(v) => v,
                Err(rv) => return rv,
            }
        } else if is_rsa_oaep {
            // RSA-OAEP unwrapping — decrypt wrapped key with RSA private key.
            // Full CK_RSA_PKCS_OAEP_PARAMS (§6.4.4): hash, MGF, label.
            let ck_param::Mech { p_parameter: p_param, ul_parameter_len: ul_param_len, .. } =
                ck_param::mech(p_mechanism);
            let (hash_alg, mgf, label) = match parse_oaep_params(p_param, ul_param_len) {
                Ok(v) => v,
                Err(rv) => return rv,
            };
            use rsa::pkcs8::DecodePrivateKey;
            let sk = match rsa::RsaPrivateKey::from_pkcs8_der(&unwrapping_key) {
                Ok(k) => k,
                Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
            };
            let oaep = match oaep_padding(hash_alg, mgf, &label) {
                Ok(o) => o,
                Err(rv) => return rv,
            };
            match sk.decrypt(oaep, wrapped_data) {
                Ok(pt) => pt,
                // §6.16 — wrapped-key decode failure (uniform code).
                Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
            }
        } else if is_rsa_pkcs {
            // Raw RSA PKCS#1 v1.5 unwrap — same PKCS8 private-key parse as
            // the OAEP arm above, PKCS1v15 padding instead of OAEP.
            use rsa::pkcs8::DecodePrivateKey;
            let sk = match rsa::RsaPrivateKey::from_pkcs8_der(&unwrapping_key) {
                Ok(k) => k,
                Err(_) => return CKR_KEY_TYPE_INCONSISTENT,
            };
            match sk.decrypt(rsa::Pkcs1v15Encrypt, wrapped_data) {
                Ok(pt) => pt,
                // §6.16 — wrapped-key decode failure (uniform code).
                Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
            }
        } else if is_kwp {
            use aes::cipher::generic_array::GenericArray;
            // AES-KWP (RFC 5649) — ciphertext must be ≥ 16 bytes and a
            // multiple of the 8-byte semiblock. §5.18.4 / §6.16 —
            // length violations are CKR_WRAPPED_KEY_LEN_RANGE.
            if wrapped_data.len() < 16 || wrapped_data.len() % 8 != 0 {
                return CKR_WRAPPED_KEY_LEN_RANGE;
            }
            let result = match unwrapping_key.len() {
                16 => aes_kw::KekAes128::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap_with_padding_vec(wrapped_data),
                24 => aes_kw::KekAes192::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap_with_padding_vec(wrapped_data),
                32 => aes_kw::KekAes256::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap_with_padding_vec(wrapped_data),
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };
            match result {
                Ok(v) => v,
                // RFC 5649 ICV/padding check failed — the wrapped key is
                // corrupt or keyed wrong: CKR_WRAPPED_KEY_INVALID.
                Err(_) => return CKR_WRAPPED_KEY_INVALID,
            }
        } else {
            use aes::cipher::generic_array::GenericArray;
            // AES-KW (RFC 3394) — ciphertext is (n+1) 8-byte semiblocks, n ≥ 2.
            if wrapped_data.len() < 24 || wrapped_data.len() % 8 != 0 {
                return CKR_WRAPPED_KEY_LEN_RANGE;
            }
            let mut buf = vec![0u8; wrapped_data.len() - 8];
            let unwrap_ok = match unwrapping_key.len() {
                16 => aes_kw::KekAes128::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap(wrapped_data, &mut buf)
                    .is_ok(),
                24 => aes_kw::KekAes192::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap(wrapped_data, &mut buf)
                    .is_ok(),
                32 => aes_kw::KekAes256::new(GenericArray::from_slice(&unwrapping_key))
                    .unwrap(wrapped_data, &mut buf)
                    .is_ok(),
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };
            if !unwrap_ok {
                // RFC 3394 integrity (IV) check failed: CKR_WRAPPED_KEY_INVALID.
                return CKR_WRAPPED_KEY_INVALID;
            }
            buf
        };
        let key_len = key_value.len() as u32;

        // Parse template attributes (if provided)
        let mut attrs = HashMap::new();
        if !p_template.is_null() && ul_attribute_count > 0 {
            let tmpl_ptr = p_template as *mut usize;
            for i in 0..ul_attribute_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize) as u32;
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as u32;
                // Skip CKA_VALUE — it comes from the unwrap operation
                if attr_type == CKA_VALUE {
                    continue;
                }
                if !val_ptr.is_null() && val_len > 0 {
                    let mut v = vec![0u8; val_len as usize];
                    std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                    attrs.insert(attr_type, v);
                }
            }
        }

        // Set key material from unwrap operation
        attrs.insert(CKA_VALUE, key_value);

        // Apply defaults for missing attributes
        if !attrs.contains_key(&CKA_CLASS) {
            store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        }
        if !attrs.contains_key(&CKA_KEY_TYPE) {
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
        }
        // CKA_VALUE_LEN is a SECRET-key attribute (§4.10 / Table 32); the
        // common private-key table does not define it. Storing it
        // unconditionally made an unwrapped EC PRIVATE key report a
        // CKA_VALUE_LEN of 60 — the length of this engine's internal stored
        // blob, which is not a concept the caller has
        // (DEFECT-RUST-UNWRAPPED-PRIVATE-VALUE-LEN).
        let unwrapped_class = attrs
            .get(&CKA_CLASS)
            .filter(|v| v.len() >= 4)
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
        if unwrapped_class == Some(CKO_SECRET_KEY) && !attrs.contains_key(&CKA_VALUE_LEN) {
            store_ulong(&mut attrs, CKA_VALUE_LEN, key_len);
        }
        if !attrs.contains_key(&CKA_TOKEN) {
            store_bool(&mut attrs, CKA_TOKEN, false);
        }
        if !attrs.contains_key(&CKA_EXTRACTABLE) {
            store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        }
        if !attrs.contains_key(&CKA_SENSITIVE) {
            store_bool(&mut attrs, CKA_SENSITIVE, false);
        }
        // PKCS#11 v3.2 §4.3 Table 13 / §4.9 / §4.10 — an UNWRAPPED key originates
        // from external material: CKA_LOCAL=FALSE, KEY_GEN_MECHANISM=
        // CK_UNAVAILABLE_INFORMATION, and ALWAYS_SENSITIVE / NEVER_EXTRACTABLE
        // are unconditionally CK_FALSE (server-managed; override any template).
        store_bool(&mut attrs, CKA_LOCAL, false);
        store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
        store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
        store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);

        // Handle CKA_PARAMETER_SET for PQC keys
        if let Some(ps_bytes) = attrs.get(&CKA_PARAMETER_SET).cloned() {
            if ps_bytes.len() >= 4 {
                let ps = u32::from_le_bytes([ps_bytes[0], ps_bytes[1], ps_bytes[2], ps_bytes[3]]);
                store_param_set(&mut attrs, ps);
            }
        }

        // PKCS#11 v3.2 §4.10.2 / §4.11: CKA_CHECK_VALUE is mandatory on all
        // secret-key objects regardless of how the key was created. C_UnwrapKey
        // builds a new secret-key object from the unwrapped bytes, so the KCV
        // MUST be computed and stored before the handle is exposed. Mirrors
        // the C++ engine's C_UnwrapKey path (SoftHSM_keygen.cpp §C_UnwrapKey).
        crate::state::compute_kcv(&mut attrs);

        // S2 (2026-08-13) — §5.18.3's CKA_UNWRAP_TEMPLATE twin: the
        // unwrapping key may constrain the attribute set of the key it
        // produces. Evaluated against the FULLY resolved attributes (template
        // ‖ engine defaults), so a caller cannot evade the constraint by
        // simply omitting the attribute. A contradiction is
        // CKR_TEMPLATE_INCONSISTENT, and no object is created.
        let kek_attrs = OBJECTS.with(|o| o.borrow().get(&h_unwrapping_key).cloned());
        if let Some(kek_attrs) = kek_attrs {
            if !crate::state::key_template_permits(&kek_attrs, CKA_UNWRAP_TEMPLATE, &attrs) {
                return CKR_TEMPLATE_INCONSISTENT;
            }
        }

        *ph_key = allocate_handle_owned(_h_session, attrs);
    }
    CKR_OK
}

// ── Authenticated key wrapping (PKCS#11 v3.2 §5.18.6 / §5.18.7) ────────────
// C_WrapKeyAuthenticated wraps a key using an AEAD mechanism (AES-GCM).
// C_UnwrapKeyAuthenticated unwraps, creating a new key object.
// Signature follows pkcs11f.h exactly.

#[wasm_bindgen(js_name = _C_WrapKeyAuthenticated)]
pub fn C_WrapKeyAuthenticated(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_wrapping_key: u32,
    h_key: u32,
    p_associated_data: *mut u8,
    ul_associated_data_len: u32,
    p_wrapped_key: *mut u8,
    pul_wrapped_key_len: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        if mech_type != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }

        // Parse CK_GCM_PARAMS from mechanism parameter
        let ck_param::Mech { p_parameter: p_param, ul_parameter_len: ul_param_len, .. } =
            ck_param::mech(p_mechanism);
        // CK_GCM_PARAMS. The old guard was a literal 20 — neither ABI's
        // sizeof (24 on wasm32, 48 on LP64); it let a caller through with a
        // struct from neither. Only pIv/ulIvLen are read here, so require
        // exactly those two fields, computed from the declaration.
        let gcm = match ParamReader::new(p_param, ul_param_len, &ck_param::gcm::LAYOUT, 2) {
            Ok(r) => r,
            Err(_) => return CKR_ARGUMENTS_BAD,
        };
        let iv_ptr = gcm.ptr(ck_param::gcm::P_IV);
        let iv_len = gcm.ulong(ck_param::gcm::UL_IV_LEN);
        // PKCS#11 v3.2 §6.27.7 / SP 800-38D §8 — IV required and unique per
        // (key, encryption); never substitute a fixed zero nonce.
        if iv_ptr.is_null() || iv_len == 0 {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        if iv_len != 12 {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        let iv = std::slice::from_raw_parts(iv_ptr, iv_len).to_vec();

        // PKCS#11 v3.2 §5.18.6 — the caller-supplied associated data MUST be
        // bound into the AEAD authentication tag.
        let aad: Vec<u8> = if !p_associated_data.is_null() && ul_associated_data_len > 0 {
            std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize).to_vec()
        } else {
            Vec::new()
        };

        // §5.18.6 — same handle/permission ordering as C_WrapKey: wrapping-key
        // handle → CKR_WRAPPING_KEY_HANDLE_INVALID; CKA_WRAP → NOT_PERMITTED.
        if let Err(rv) =
            check_key_usage_as(_h_session, h_wrapping_key, CKA_WRAP, CKR_WRAPPING_KEY_HANDLE_INVALID)
        {
            return rv;
        }
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS on the wrapping key.
        if let Err(rv) = check_mechanism_allowed(h_wrapping_key, mech_type) {
            return rv;
        }

        // Target key: handle → CKR_KEY_HANDLE_INVALID; unextractable (exists,
        // CKA_EXTRACTABLE=FALSE) → CKR_KEY_UNEXTRACTABLE.
        let target_attrs = match OBJECTS.with(|o| o.borrow().get(&h_key).cloned()) {
            Some(a) => a,
            None => return CKR_KEY_HANDLE_INVALID,
        };
        if !crate::state::can_access_object(_h_session, &target_attrs) {
            return CKR_KEY_HANDLE_INVALID;
        }
        if !read_bool_attr(&target_attrs, CKA_EXTRACTABLE) {
            return CKR_KEY_UNEXTRACTABLE;
        }

        // CKA_WRAP_WITH_TRUSTED=TRUE on the target requires CKA_TRUSTED=TRUE
        // on the wrapping key (PKCS#11 v3.2 §4.9/§4.10).
        if wrap_with_trusted_violation(h_wrapping_key, h_key) {
            return CKR_KEY_NOT_WRAPPABLE;
        }

        // S2 (2026-08-13) — §5.18.3: "To partition the wrapping keys so they
        // can only wrap a subset of extractable keys the attribute
        // CKA_WRAP_TEMPLATE can be used on the wrapping key … If any
        // attribute mismatch occurs on an attempt to wrap a key then the
        // function SHALL return CKR_KEY_HANDLE_INVALID." The whole mechanism
        // was absent from this engine — neither attribute was defined,
        // stored, read nor enforced — so an application that believed it had
        // constrained a wrapping key had constrained nothing.
        let kek_attrs = match OBJECTS.with(|o| o.borrow().get(&h_wrapping_key).cloned()) {
            Some(a) => a,
            None => return CKR_WRAPPING_KEY_HANDLE_INVALID,
        };
        if !crate::state::key_template_permits(&kek_attrs, CKA_WRAP_TEMPLATE, &target_attrs) {
            return CKR_KEY_HANDLE_INVALID;
        }

        let wrapping_key = match get_object_value(h_wrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let key_to_wrap = match get_object_value(h_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };

        // AES-GCM encrypt, binding the associated data into the tag.
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::Aead, aead::Payload};
        let nonce = GenericArray::from_slice(&iv);
        let payload = Payload {
            msg: key_to_wrap.as_slice(),
            aad: aad.as_slice(),
        };
        let wrapped = match wrapping_key.len() {
            16 => {
                let cipher = match Aes128Gcm::new_from_slice(&wrapping_key) {
                    Ok(c) => c,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                cipher.encrypt(nonce, payload)
            }
            32 => {
                let cipher = match Aes256Gcm::new_from_slice(&wrapping_key) {
                    Ok(c) => c,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                cipher.encrypt(nonce, payload)
            }
            _ => return CKR_KEY_TYPE_INCONSISTENT,
        };
        let wrapped = match wrapped {
            Ok(ct) => ct,
            Err(_) => return CKR_FUNCTION_FAILED,
        };

        // Length query or copy
        if p_wrapped_key.is_null() {
            *pul_wrapped_key_len = wrapped.len() as u32;
            return CKR_OK;
        }
        if (*pul_wrapped_key_len as usize) < wrapped.len() {
            *pul_wrapped_key_len = wrapped.len() as u32;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(wrapped.as_ptr(), p_wrapped_key, wrapped.len());
        *pul_wrapped_key_len = wrapped.len() as u32;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_UnwrapKeyAuthenticated)]
pub fn C_UnwrapKeyAuthenticated(
    _h_session: u32,
    p_mechanism: *mut u8,
    h_unwrapping_key: u32,
    p_wrapped_key: *mut u8,
    ul_wrapped_key_len: u32,
    p_template: *mut u8,
    ul_attribute_count: u32,
    p_associated_data: *mut u8,
    ul_associated_data_len: u32,
    ph_key: *mut u32,
) -> u32 {
    require_init!();
    require_session!(_h_session);
    // Same required-pointer surface as C_UnwrapKey.
    nonnull!(p_mechanism, p_wrapped_key, ph_key);
    unsafe {
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        if mech_type != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }

        // Parse CK_GCM_PARAMS from mechanism parameter
        let ck_param::Mech { p_parameter: p_param, ul_parameter_len: ul_param_len, .. } =
            ck_param::mech(p_mechanism);
        // CK_GCM_PARAMS. The old guard was a literal 20 — neither ABI's
        // sizeof (24 on wasm32, 48 on LP64); it let a caller through with a
        // struct from neither. Only pIv/ulIvLen are read here, so require
        // exactly those two fields, computed from the declaration.
        let gcm = match ParamReader::new(p_param, ul_param_len, &ck_param::gcm::LAYOUT, 2) {
            Ok(r) => r,
            Err(_) => return CKR_ARGUMENTS_BAD,
        };
        let iv_ptr = gcm.ptr(ck_param::gcm::P_IV);
        let iv_len = gcm.ulong(ck_param::gcm::UL_IV_LEN);
        // PKCS#11 v3.2 §6.27.7 / SP 800-38D §8 — IV required and unique.
        if iv_ptr.is_null() || iv_len == 0 {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        if iv_len != 12 {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        let iv = std::slice::from_raw_parts(iv_ptr, iv_len).to_vec();

        // PKCS#11 v3.2 §5.18.7 — the associated data MUST be bound into the
        // AEAD tag; an unwrap with mismatched AAD must fail authentication.
        let aad: Vec<u8> = if !p_associated_data.is_null() && ul_associated_data_len > 0 {
            std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize).to_vec()
        } else {
            Vec::new()
        };

        // §5.18.7 — same handle/permission ordering as C_UnwrapKey:
        // unwrapping-key handle → CKR_UNWRAPPING_KEY_HANDLE_INVALID;
        // CKA_UNWRAP → CKR_KEY_FUNCTION_NOT_PERMITTED.
        if let Err(rv) = check_key_usage_as(
            _h_session,
            h_unwrapping_key,
            CKA_UNWRAP,
            CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        ) {
            return rv;
        }
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS on the unwrapping key.
        if let Err(rv) = check_mechanism_allowed(h_unwrapping_key, mech_type) {
            return rv;
        }

        let unwrapping_key = match get_object_value(h_unwrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let wrapped_data = std::slice::from_raw_parts(p_wrapped_key, ul_wrapped_key_len as usize);

        // AES-GCM decrypt, verifying the associated data against the tag.
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::Aead, aead::Payload};
        let nonce = GenericArray::from_slice(&iv);
        let payload = Payload {
            msg: wrapped_data,
            aad: aad.as_slice(),
        };
        let key_value = match unwrapping_key.len() {
            16 => {
                let cipher = match Aes128Gcm::new_from_slice(&unwrapping_key) {
                    Ok(c) => c,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                cipher.decrypt(nonce, payload)
            }
            32 => {
                let cipher = match Aes256Gcm::new_from_slice(&unwrapping_key) {
                    Ok(c) => c,
                    Err(_) => return CKR_FUNCTION_FAILED,
                };
                cipher.decrypt(nonce, payload)
            }
            _ => return CKR_KEY_TYPE_INCONSISTENT,
        };
        let key_value = match key_value {
            // PKCS#11 v3.2 §5.18.7 — authentication failure (wrong key, tag, or
            // associated data) is reported as CKR_ENCRYPTED_DATA_INVALID.
            Ok(pt) => pt,
            Err(_) => return CKR_ENCRYPTED_DATA_INVALID,
        };
        let key_len = key_value.len() as u32;

        // Parse template attributes (same as C_UnwrapKey)
        let mut attrs = HashMap::new();
        if !p_template.is_null() && ul_attribute_count > 0 {
            let tmpl_ptr = p_template as *mut usize;
            for i in 0..ul_attribute_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize) as u32;
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as u32;
                if attr_type == CKA_VALUE {
                    continue;
                }
                if !val_ptr.is_null() && val_len > 0 {
                    let mut v = vec![0u8; val_len as usize];
                    std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                    attrs.insert(attr_type, v);
                }
            }
        }

        // Set key material from unwrap operation
        attrs.insert(CKA_VALUE, key_value);

        // Apply defaults for missing attributes
        if !attrs.contains_key(&CKA_CLASS) {
            store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        }
        if !attrs.contains_key(&CKA_KEY_TYPE) {
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
        }
        // CKA_VALUE_LEN is a SECRET-key attribute (§4.10 / Table 32); the
        // common private-key table does not define it. Storing it
        // unconditionally made an unwrapped EC PRIVATE key report a
        // CKA_VALUE_LEN of 60 — the length of this engine's internal stored
        // blob, which is not a concept the caller has
        // (DEFECT-RUST-UNWRAPPED-PRIVATE-VALUE-LEN).
        let unwrapped_class = attrs
            .get(&CKA_CLASS)
            .filter(|v| v.len() >= 4)
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
        if unwrapped_class == Some(CKO_SECRET_KEY) && !attrs.contains_key(&CKA_VALUE_LEN) {
            store_ulong(&mut attrs, CKA_VALUE_LEN, key_len);
        }
        if !attrs.contains_key(&CKA_TOKEN) {
            store_bool(&mut attrs, CKA_TOKEN, false);
        }
        if !attrs.contains_key(&CKA_EXTRACTABLE) {
            store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        }
        if !attrs.contains_key(&CKA_SENSITIVE) {
            store_bool(&mut attrs, CKA_SENSITIVE, false);
        }
        // PKCS#11 v3.2 §4.3 / §4.9 / §4.10 — unwrapped (external-origin) key.
        store_bool(&mut attrs, CKA_LOCAL, false);
        store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
        store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
        store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);

        if let Some(ps_bytes) = attrs.get(&CKA_PARAMETER_SET).cloned() {
            if ps_bytes.len() >= 4 {
                let ps = u32::from_le_bytes([ps_bytes[0], ps_bytes[1], ps_bytes[2], ps_bytes[3]]);
                store_param_set(&mut attrs, ps);
            }
        }

        // PKCS#11 v3.2 §4.10.2 / §4.11: KCV MUST be populated on every
        // secret-key object — C_UnwrapKeyAuthenticated counts as a new
        // object-creation path per §5.18.7.
        crate::state::compute_kcv(&mut attrs);

        *ph_key = allocate_handle_owned(_h_session, attrs);
    }
    CKR_OK
}

// ── Multi-part C_Sign / C_Verify (PKCS#11 v3.2 §5.13.3/§5.13.4 and
//    §5.15.3/§5.15.4) ────────────────────────────────────────────────────────
//
// T4 (audit: multi-part sign gap). Update appends to a per-session
// accumulator (SIGN_MULTIPART_ACC / VERIFY_MULTIPART_ACC — same pattern as
// MESSAGE_SIGN_ACC and DIGEST_MULTIPART); Final computes the result through
// the existing one-shot C_Sign / C_Verify handler over the accumulated
// message. Follow-up (deliberately NOT this slice): stream the
// hash-composite mechanisms into incremental digest state to bound memory
// instead of buffering the whole message.

/// True when `mech`'s sign/verify operation accepts the multi-part
/// Update/Final flow: the hash-composite RSA/ECDSA mechanisms, the MAC
/// families (HMAC, HMAC_GENERAL, KMAC), and pure ML-DSA / SLH-DSA / EdDSA —
/// anything whose signature is a deterministic function of the full message,
/// so the accumulator can buffer the streamed parts and Final delegates to the
/// one-shot handler over the concatenation. Still single-part only: raw
/// CKM_RSA_PKCS / CKM_ECDSA (caller supplies the digest), the pre-hash ML-DSA /
/// SLH-DSA / EdDSA-ph variants, and the stateful HSS/XMSS mechanisms.
fn sign_mech_supports_multipart(mech: u32) -> bool {
    matches!(
        mech,
        CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS
            | CKM_SHA3_384_RSA_PKCS
            | CKM_SHA3_384_RSA_PKCS_PSS
            | CKM_ECDSA_SHA256
            | CKM_ECDSA_SHA384
            | CKM_ECDSA_SHA512
            | CKM_ECDSA_SHA3_224
            | CKM_ECDSA_SHA3_256
            | CKM_ECDSA_SHA3_384
            | CKM_ECDSA_SHA3_512
            | CKM_SHA256_HMAC
            | CKM_SHA384_HMAC
            | CKM_SHA512_HMAC
            | CKM_SHA3_256_HMAC
            | CKM_SHA3_512_HMAC
            | CKM_KMAC_128
            | CKM_KMAC_256
            | CKM_ML_DSA
            | CKM_SLH_DSA
            | CKM_EDDSA
    ) || hmac_general_base(mech).is_some()
}

/// Shared §5.13.3/§5.15.3 gate for the four Update/Final entry points:
/// resolve the active op's mechanism and tear the op down if it is
/// single-part-only.
///
/// Return code for the single-part-only case, pinned from the spec
/// (docs/refs/pkcs11-spec-v3.2-csd01.pdf): the §5.13.3 C_SignUpdate and
/// §5.15.3 C_VerifyUpdate return-value lists contain NEITHER
/// CKR_MECHANISM_INVALID NOR CKR_FUNCTION_NOT_SUPPORTED; the listed code
/// that fits is CKR_OPERATION_NOT_INITIALIZED, defined in §5.1 as "there is
/// no active operation of an APPROPRIATE TYPE in the specified session" — a
/// single-part-only sign/verify op is not of multi-part type. Per §5.13.3 /
/// §5.15.3 ("a call to C_SignUpdate which results in an error terminates the
/// current signature operation") the active op is terminated.
fn multipart_op_mech(
    h_session: u32,
    op_state: &crate::state::GlobalState<HashMap<u32, (u32, u32, Vec<u8>, bool)>>,
    acc: &crate::state::GlobalState<HashMap<u32, Vec<u8>>>,
) -> Result<u32, u32> {
    let mech = match op_state.with(|s| s.borrow().get(&h_session).map(|st| st.0)) {
        Some(m) => m,
        None => return Err(CKR_OPERATION_NOT_INITIALIZED),
    };
    if !sign_mech_supports_multipart(mech) {
        op_state.with(|s| s.borrow_mut().remove(&h_session));
        acc.with(|s| s.borrow_mut().remove(&h_session));
        return Err(CKR_OPERATION_NOT_INITIALIZED);
    }
    Ok(mech)
}

#[wasm_bindgen(js_name = _C_SignUpdate)]
pub fn C_SignUpdate(h_session: u32, p_part: *mut u8, ul_part_len: u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // §5.2 error priority — session handle before operation state
    // (operate-stage, round-1 S4).
    // nonnull! convention (S2): pPart is a required input pointer, but a
    // zero-length part with a NULL pointer is legal (mirror C_Sign's pData).
    if p_part.is_null() && ul_part_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    if let Err(rv) = multipart_op_mech(h_session, &SIGN_STATE, &SIGN_MULTIPART_ACC) {
        return rv;
    }
    // The op enters its multi-part phase even for an empty part — the
    // one-shot C_Sign is CKR_OPERATION_ACTIVE until C_SignFinal (mirror
    // DIGEST_MULTIPART).
    SIGN_MULTIPART_ACC.with(|s| {
        let mut m = s.borrow_mut();
        let acc = m.entry(h_session).or_default();
        if ul_part_len > 0 {
            unsafe {
                acc.extend_from_slice(std::slice::from_raw_parts(p_part, ul_part_len as usize));
            }
        }
    });
    CKR_OK
}

fn C_SignFinal_impl(h_session: u32, p_signature: *mut u8, pul_signature_len: *mut u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    nonnull!(pul_signature_len);
    if let Err(rv) = multipart_op_mech(h_session, &SIGN_STATE, &SIGN_MULTIPART_ACC) {
        return rv;
    }
    // §5.13.4 — C_SignFinal with no preceding C_SignUpdate signs the empty
    // message (legal); the accumulator entry is simply absent.
    let msg = SIGN_MULTIPART_ACC
        .with(|s| s.borrow_mut().remove(&h_session))
        .unwrap_or_default();
    // Delegate to the one-shot handler over the accumulated message (the
    // accumulator entry was taken out above, so C_Sign's OPERATION_ACTIVE
    // guard passes). C_Sign already implements the §5.2 two-call convention:
    // it keeps SIGN_STATE alive on a NULL-buffer size query and on
    // CKR_BUFFER_TOO_SMALL — restore the accumulator on exactly those paths
    // so the multi-part op survives for the second call.
    let rv = C_Sign(
        h_session,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        p_signature,
        pul_signature_len,
    );
    if rv == CKR_BUFFER_TOO_SMALL || (rv == CKR_OK && p_signature.is_null()) {
        SIGN_MULTIPART_ACC.with(|s| s.borrow_mut().insert(h_session, msg));
    }
    rv
}

#[wasm_bindgen(js_name = _C_VerifyUpdate)]
pub fn C_VerifyUpdate(h_session: u32, p_part: *mut u8, ul_part_len: u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    if p_part.is_null() && ul_part_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    if let Err(rv) = multipart_op_mech(h_session, &VERIFY_STATE, &VERIFY_MULTIPART_ACC) {
        return rv;
    }
    VERIFY_MULTIPART_ACC.with(|s| {
        let mut m = s.borrow_mut();
        let acc = m.entry(h_session).or_default();
        if ul_part_len > 0 {
            unsafe {
                acc.extend_from_slice(std::slice::from_raw_parts(p_part, ul_part_len as usize));
            }
        }
    });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_VerifyFinal)]
pub fn C_VerifyFinal(h_session: u32, p_signature: *mut u8, ul_signature_len: u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    nonnull!(p_signature);
    if let Err(rv) = multipart_op_mech(h_session, &VERIFY_STATE, &VERIFY_MULTIPART_ACC) {
        return rv;
    }
    // §5.15.4 — "a call to C_VerifyFinal always terminates the active
    // verification operation": take the accumulator out unconditionally and
    // delegate to the one-shot C_Verify, which consumes VERIFY_STATE on
    // every reachable path and returns CKR_OK / CKR_SIGNATURE_INVALID /
    // CKR_SIGNATURE_LEN_RANGE exactly as the one-shot does. No Updates ⇒
    // verify against the empty message (legal).
    let msg = VERIFY_MULTIPART_ACC
        .with(|s| s.borrow_mut().remove(&h_session))
        .unwrap_or_default();
    C_Verify(
        h_session,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        p_signature,
        ul_signature_len,
    )
}

// ── Multi-part Encrypt/Decrypt (PKCS#11 v3.2 §5.2.6/7 and §5.2.10/11) ────────
//
// The streaming state machines live in `crate::crypto::multipart`; this
// layer owns the session bookkeeping and the §5.2 two-pass output-length
// convention (NULL output → report size, op untouched; short buffer →
// CKR_BUFFER_TOO_SMALL, op untouched; any other failure terminates).

/// Build the streaming cipher for an op initialised by `C_EncryptInit` /
/// `C_DecryptInit`. Called lazily on the first Update/Final call so the
/// single-shot `C_Encrypt`/`C_Decrypt` paths stay untouched.
fn build_multipart_cipher(
    ctx: &EncryptCtx,
    dir: crate::crypto::multipart::CipherDirection,
) -> Result<crate::crypto::multipart::MultipartCipher, u32> {
    use crate::crypto::multipart::*;
    let make_key = || -> Result<AesKey, u32> {
        let key_bytes = get_object_value(ctx.key_handle).ok_or(CKR_ARGUMENTS_BAD)?;
        AesKey::new(&key_bytes).ok_or(CKR_KEY_TYPE_INCONSISTENT)
    };
    match ctx.mech_type {
        CKM_AES_ECB => Ok(MultipartCipher::Ecb(EcbState::new(make_key()?, dir))),
        CKM_AES_CBC => {
            let iv: [u8; 16] =
                ctx.iv.as_slice().try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
            Ok(MultipartCipher::Cbc(CbcState::new(make_key()?, iv, dir)))
        }
        CKM_AES_CBC_PAD => {
            let iv: [u8; 16] =
                ctx.iv.as_slice().try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
            Ok(MultipartCipher::CbcPad(CbcPadState::new(make_key()?, iv, dir)))
        }
        CKM_AES_CTR => {
            let cb: [u8; 16] =
                ctx.iv.as_slice().try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
            // ulCounterBits travels in tag_bits (see EncryptCtx docs).
            let width = ((ctx.tag_bits.max(8)) / 8) as usize;
            Ok(MultipartCipher::Ctr(CtrState::new_with_width(make_key()?, cb, width)))
        }
        CKM_AES_GCM => {
            let iv: [u8; 12] =
                ctx.iv.as_slice().try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
            Ok(MultipartCipher::Gcm(GcmState::new(
                make_key()?,
                &iv,
                &ctx.aad,
                ctx.tag_bits,
                dir,
            )))
        }
        // RSA-OAEP / ChaCha20-Poly1305 are single-part-only mechanisms:
        // feeding them through Update is an input-length violation.
        _ => Err(match dir {
            CipherDirection::Encrypt => CKR_DATA_LEN_RANGE,
            CipherDirection::Decrypt => CKR_ENCRYPTED_DATA_LEN_RANGE,
        }),
    }
}

fn multipart_update(
    state: &GlobalState<HashMap<u32, EncryptCtx>>,
    dir: crate::crypto::multipart::CipherDirection,
    h_session: u32,
    p_in: *mut u8,
    in_len: u32,
    p_out: *mut u8,
    pul_out_len: *mut u32,
) -> u32 {
    if pul_out_len.is_null() || (p_in.is_null() && in_len > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    let mut map = state.borrow_mut();
    let Some(ctx) = map.get_mut(&h_session) else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    if ctx.multipart.is_none() {
        match build_multipart_cipher(ctx, dir) {
            Ok(mp) => ctx.multipart = Some(mp),
            Err(rv) => {
                map.remove(&h_session); // failed Update terminates the op
                return rv;
            }
        }
    }
    let mp = ctx.multipart.as_mut().unwrap();
    let need = mp.update_len(in_len as usize) as u32;
    unsafe {
        if p_out.is_null() {
            *pul_out_len = need;
            return CKR_OK; // size query — input not consumed (§5.2)
        }
        if *pul_out_len < need {
            *pul_out_len = need;
            return CKR_BUFFER_TOO_SMALL; // op stays active (§5.2)
        }
        let part: &[u8] = if in_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(p_in as *const u8, in_len as usize)
        };
        match mp.update(part) {
            Ok(out) => {
                std::ptr::copy_nonoverlapping(out.as_ptr(), p_out, out.len());
                *pul_out_len = out.len() as u32;
                CKR_OK
            }
            Err(rv) => {
                map.remove(&h_session);
                rv
            }
        }
    }
}

fn multipart_final(
    state: &GlobalState<HashMap<u32, EncryptCtx>>,
    dir: crate::crypto::multipart::CipherDirection,
    h_session: u32,
    p_out: *mut u8,
    pul_out_len: *mut u32,
) -> u32 {
    if pul_out_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut map = state.borrow_mut();
    let Some(ctx) = map.get_mut(&h_session) else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    // Final straight after Init (no Update calls) is legal: it closes a
    // zero-length stream, so the cipher may still need building.
    if ctx.multipart.is_none() {
        match build_multipart_cipher(ctx, dir) {
            Ok(mp) => ctx.multipart = Some(mp),
            Err(rv) => {
                map.remove(&h_session);
                return rv;
            }
        }
    }
    let need = ctx.multipart.as_ref().unwrap().final_len() as u32;
    unsafe {
        if p_out.is_null() {
            *pul_out_len = need;
            return CKR_OK;
        }
        if *pul_out_len < need {
            *pul_out_len = need;
            return CKR_BUFFER_TOO_SMALL;
        }
        // §5.2.7/§5.2.11 — beyond the two cases above, Final always
        // terminates the operation, success or failure.
        let mp = map.remove(&h_session).unwrap().multipart.unwrap();
        match mp.finalize() {
            Ok(out) => {
                std::ptr::copy_nonoverlapping(out.as_ptr(), p_out, out.len());
                *pul_out_len = out.len() as u32;
                CKR_OK
            }
            Err(rv) => rv,
        }
    }
}

#[wasm_bindgen(js_name = _C_EncryptUpdate)]
pub fn C_EncryptUpdate(
    h_session: u32,
    p_part: *mut u8,
    ul_part_len: u32,
    p_encrypted_part: *mut u8,
    pul_encrypted_part_len: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    multipart_update(
        &ENCRYPT_STATE,
        crate::crypto::multipart::CipherDirection::Encrypt,
        h_session,
        p_part,
        ul_part_len,
        p_encrypted_part,
        pul_encrypted_part_len,
    )
}

#[wasm_bindgen(js_name = _C_EncryptFinal)]
pub fn C_EncryptFinal(
    h_session: u32,
    p_last_encrypted_part: *mut u8,
    pul_last_encrypted_part_len: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    multipart_final(
        &ENCRYPT_STATE,
        crate::crypto::multipart::CipherDirection::Encrypt,
        h_session,
        p_last_encrypted_part,
        pul_last_encrypted_part_len,
    )
}

#[wasm_bindgen(js_name = _C_DecryptUpdate)]
pub fn C_DecryptUpdate(
    h_session: u32,
    p_encrypted_part: *mut u8,
    ul_encrypted_part_len: u32,
    p_part: *mut u8,
    pul_part_len: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    multipart_update(
        &DECRYPT_STATE,
        crate::crypto::multipart::CipherDirection::Decrypt,
        h_session,
        p_encrypted_part,
        ul_encrypted_part_len,
        p_part,
        pul_part_len,
    )
}

// ── PKCS#11 v3.2 Asynchronous and Session Flag Stubs ────────────────────────

#[wasm_bindgen(js_name = _C_GetSessionValidationFlags)]
pub fn C_GetSessionValidationFlags(h_session: u32, type_: u32, p_flags: *mut u32) -> u32 {
    require_init!();
    require_session!(h_session);
    if p_flags.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // PKCS#11 v3.2 §5.6.9 — the only defined type is CKS_LAST_VALIDATION_OK (1).
    if type_ != 1 {
        return CKR_ARGUMENTS_BAD;
    }
    // This token performs no FIPS/validation-authority checks, so the
    // validation-flags set is empty.
    unsafe {
        *p_flags = 0;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_AsyncComplete)]
pub fn C_AsyncComplete(_h_session: u32, _p_function_name: *mut u8, _p_result: *mut u8) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_AsyncGetID)]
pub fn C_AsyncGetID(_h_session: u32, _p_function_name: *mut u8, _pul_id: *mut u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_AsyncJoin)]
pub fn C_AsyncJoin(
    _h_session: u32,
    _p_function_name: *mut u8,
    _ul_id: u32,
    _p_data: *mut u8,
    _ul_data_len: u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_DecryptFinal)]
pub fn C_DecryptFinal(h_session: u32, p_last_part: *mut u8, pul_last_part_len: *mut u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    multipart_final(
        &DECRYPT_STATE,
        crate::crypto::multipart::CipherDirection::Decrypt,
        h_session,
        p_last_part,
        pul_last_part_len,
    )
}

// ── Stubs for optional PKCS#11 v3.2 admin/management functions ───────────────
//
// These functions are not required for cryptographic operations but must exist
// in a compliant library. All return CKR_FUNCTION_NOT_SUPPORTED per PKCS#11 v3.2 §11.17.
// Exceptions: C_GetInfo and C_GetSlotInfo are implemented with basic data.

/// CK_INFO: cryptokiVersion(2) + manufacturerID(32) + flags(4) + libraryDescription(32) + libraryVersion(2) = 72 bytes
#[wasm_bindgen(js_name = _C_GetInfo)]
pub fn C_GetInfo(p_info: *mut u8) -> u32 {
    require_init!();
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let info = std::slice::from_raw_parts_mut(p_info, 72);
        info.fill(0);
        // cryptokiVersion: major=3, minor=2
        info[0] = 3;
        info[1] = 2;
        // manufacturerID[32]: "SoftHSMv3 Rust WASM            " (padded with spaces)
        let mfr = b"SoftHSMv3 Rust WASM             ";
        info[2..34].copy_from_slice(&mfr[..32]);
        // flags (4 bytes at offset 34): 0
        // libraryDescription[32] at offset 38
        let desc = b"PQC PKCS#11 v3.2 Rust WASM      ";
        info[38..70].copy_from_slice(&desc[..32]);
        // libraryVersion at offset 70: major=3, minor=0
        info[70] = 3;
        info[71] = 0;
    }
    CKR_OK
}

/// C_GetSlotInfo: returns basic slot info for slot 0.
/// CK_SLOT_INFO: slotDescription(64) + manufacturerID(32) + flags(4) + hardwareVersion(2) + firmwareVersion(2) = 104 bytes
/// PKCS#11 v3.2 §5.5 — C_GetInterfaceList. Reports one interface,
/// "PKCS 11" version 3.2. Callable BEFORE C_Initialize (§5.4: the
/// function-list/interface getters are exempt from the init gate;
/// CKR_CRYPTOKI_NOT_INITIALIZED is not in this function's return list).
/// wasm constraint: exported functions are not
/// addressable as C function pointers in linear memory, so pFunctionList
/// points to a CK_VERSION{3,2} header only; symbol binding happens in the
/// JS shim (each `_C_*` export), which is the function table for every
/// real consumer of this engine. CK_INTERFACE (wasm32, 12 B):
/// pInterfaceName, pFunctionList, flags.
#[wasm_bindgen(js_name = _C_GetInterfaceList)]
pub fn C_GetInterfaceList(p_interfaces_list: *mut u8, pul_count: *mut u32) -> u32 {
    // No require_init!() — §5.4 pre-init surface.
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        if p_interfaces_list.is_null() {
            *pul_count = 1;
            return CKR_OK;
        }
        if *pul_count < 1 {
            *pul_count = 1;
            return CKR_BUFFER_TOO_SMALL;
        }
        let (name_ptr, ver_ptr) = interface_statics();
        let ifc = p_interfaces_list as *mut u32;
        *ifc = name_ptr;
        *ifc.add(1) = ver_ptr;
        *ifc.add(2) = 0; // flags
        *pul_count = 1;
    }
    CKR_OK
}

/// §5.5 — C_GetInterface. NULL name/version match the default interface.
/// Callable BEFORE C_Initialize (§5.4 — same pre-init surface as
/// C_GetFunctionList / C_GetInterfaceList).
#[wasm_bindgen(js_name = _C_GetInterface)]
pub fn C_GetInterface(
    p_interface_name: *mut u8,
    p_version: *mut u8,
    pp_interface: *mut u32,
    _flags: u32,
) -> u32 {
    // No require_init!() — §5.4 pre-init surface.
    if pp_interface.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        // name must be "PKCS 11" (NUL-terminated) when supplied
        if !p_interface_name.is_null() {
            let want = b"PKCS 11\0";
            let got = std::slice::from_raw_parts(p_interface_name, want.len());
            if got != want {
                *pp_interface = 0;
                return CKR_FUNCTION_FAILED;
            }
        }
        // version must be 3.2 when supplied
        if !p_version.is_null() {
            let major = *p_version;
            let minor = *p_version.add(1);
            if major != 3 || minor != 2 {
                *pp_interface = 0;
                return CKR_FUNCTION_FAILED;
            }
        }
        let (name_ptr, ver_ptr) = interface_statics();
        // build (or reuse) a CK_INTERFACE in linear memory
        let ifc = crate::state::malloc(12) as *mut u32;
        if ifc.is_null() {
            return CKR_HOST_MEMORY;
        }
        *ifc = name_ptr;
        *ifc.add(1) = ver_ptr;
        *ifc.add(2) = 0;
        *pp_interface = ifc as u32;
    }
    CKR_OK
}

/// Lazily allocated linear-memory statics for the interface records:
/// ("PKCS 11\0" string, CK_VERSION{3,2}). Allocated once, intentionally
/// never freed (they must stay valid for the library lifetime).
fn interface_statics() -> (u32, u32) {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(u32, u32)>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pair) = *guard {
        return pair;
    }
    unsafe {
        let name = crate::state::malloc(8);
        std::ptr::copy_nonoverlapping(b"PKCS 11\0".as_ptr(), name, 8);
        // pFunctionList → CK_VERSION{major=3, minor=2} header (see
        // C_GetInterfaceList docs for the wasm constraint).
        let ver = crate::state::malloc(2);
        *ver = 3;
        *ver.add(1) = 2;
        let pair = (name as u32, ver as u32);
        *guard = Some(pair);
        pair
    }
}

#[wasm_bindgen(js_name = _C_GetSlotInfo)]
pub fn C_GetSlotInfo(slot_id: u32, p_info: *mut u8) -> u32 {
    require_init!();
    // W6 audit (2026-08-13) — §5.5.2 enumerates CKR_SLOT_ID_INVALID here too,
    // and this was the second `_slot_id` entry point that ignored its slot
    // argument entirely. C_GetTokenInfo, C_InitToken and C_OpenSession were
    // audited alongside and already validate.
    if !TOKEN_STORE.with(|ts| ts.borrow().contains_key(&slot_id)) {
        return CKR_SLOT_ID_INVALID;
    }
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let info = std::slice::from_raw_parts_mut(p_info, 104);
        info.fill(b' '); // PKCS#11 padding is spaces for char arrays
        // slotDescription[64] at offset 0
        let desc = b"SoftHSMv3 Rust WASM Virtual Slot                                ";
        info[0..64].copy_from_slice(&desc[..64]);
        // manufacturerID[32] at offset 64
        let mfr = b"SoftHSMv3 Rust WASM             ";
        info[64..96].copy_from_slice(&mfr[..32]);
        // flags (4 bytes at offset 96): CKF_TOKEN_PRESENT(1) | CKF_HW_SLOT(0) = 0x01
        info[96] = 0x01;
        info[97] = 0x00;
        info[98] = 0x00;
        info[99] = 0x00;
        // hardwareVersion at offset 100: {1, 0}
        info[100] = 1;
        info[101] = 0;
        // firmwareVersion at offset 102: {3, 0}
        info[102] = 3;
        info[103] = 0;
    }
    CKR_OK
}

// ── D4 — spec-mandated entry points absent from the engine (PKCS#11 v3.2) ───
// Exact pkcs11f.h shapes; return the code the spec requires for an
// implementation that does not provide the capability.

/// §5.21 (legacy) — always CKR_FUNCTION_NOT_PARALLEL per spec.
#[wasm_bindgen(js_name = _C_GetFunctionStatus)]
pub fn C_GetFunctionStatus(_h_session: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_PARALLEL
}

/// §5.21 (legacy) — always CKR_FUNCTION_NOT_PARALLEL per spec.
#[wasm_bindgen(js_name = _C_CancelFunction)]
pub fn C_CancelFunction(_h_session: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_PARALLEL
}

/// §5.5 — no slot events exist on this soft token. Non-blocking poll gets
/// CKR_NO_EVENT; a blocking wait would never return, so refuse it.
#[wasm_bindgen(js_name = _C_WaitForSlotEvent)]
pub fn C_WaitForSlotEvent(flags: u32, _p_slot: *mut u32, _p_reserved: *mut u8) -> u32 {
    require_init!();
    if (flags & CKF_DONT_BLOCK) != 0 {
        CKR_NO_EVENT
    } else {
        CKR_FUNCTION_NOT_SUPPORTED
    }
}

// §5.13 — signatures-with-recovery. RSA only (CKM_RSA_PKCS / CKM_RSA_X_509),
// matching the C++ engine's restriction (PKCS#11 v3.2 Tables 39/44/45 also
// permit CKM_RSA_9796; neither engine implements that one — a separate,
// lower-priority gap, not closed here). Single-part-only per §5.13.5/§5.13.6:
// *RecoverInit, then exactly one *Recover call.
//
// CKM_RSA_PKCS sign-recover is the IDENTICAL RSASSA-PKCS1-v1_5 raw-sign
// primitive `sign_rsa(CKM_RSA_PKCS, ...)` already performs for regular
// C_Sign (PKCS#11 v3.2 Table 39: `C_Sign1`/`C_SignRecover1` have the same
// key type / length row) — reused directly, not reimplemented. Only
// CKM_RSA_X_509 (raw RSASP1, no padding at all) and the VerifyRecover
// direction (recover the message rather than compare a caller-supplied
// one) need new primitives, via `rsa::hazmat`'s raw modexp functions.
#[wasm_bindgen(js_name = _C_SignRecoverInit)]
pub fn C_SignRecoverInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::SignRecover) {
        return rv;
    }
    // A regular Sign and a Sign-Recover op are mutually exclusive on one
    // session (both are "the signing category" per §5.13's own grouping).
    if SIGN_STATE.with(|s| s.borrow().contains_key(&h_session))
        || SIGN_RECOVER_STATE.with(|s| s.borrow().contains_key(&h_session))
    {
        return CKR_OPERATION_ACTIVE;
    }
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech_type = unsafe { ck_param::mech(p_mechanism).mechanism };
    if mech_type != CKM_RSA_PKCS && mech_type != CKM_RSA_X_509 {
        return CKR_MECHANISM_INVALID;
    }
    if let Err(rv) = check_key_usage(h_session, h_key, CKA_SIGN_RECOVER) {
        return rv;
    }
    if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
        return rv;
    }
    SIGN_RECOVER_STATE.with(|s| {
        s.borrow_mut().insert(h_session, (mech_type, h_key));
    });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_SignRecover)]
pub fn C_SignRecover(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    if pul_signature_len.is_null() || (p_data.is_null() && ul_data_len > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    let state = SIGN_RECOVER_STATE.with(|s| s.borrow().get(&h_session).cloned());
    let (mech, hkey) = match state {
        Some(s) => s,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    let sk_bytes = match get_object_value(hkey) {
        Some(v) => v,
        None => return CKR_ARGUMENTS_BAD,
    };
    unsafe {
        let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let result: Result<Vec<u8>, u32> = if mech == CKM_RSA_PKCS {
            sign_rsa(CKM_RSA_PKCS, &sk_bytes, msg, None)
        } else {
            rsa_x509_sign_recover(&sk_bytes, msg)
        };
        match result {
            Ok(sig) => {
                if p_signature.is_null() {
                    *pul_signature_len = sig.len() as u32;
                    return CKR_OK; // length query — op stays active
                }
                if (*pul_signature_len as usize) < sig.len() {
                    *pul_signature_len = sig.len() as u32;
                    return CKR_BUFFER_TOO_SMALL; // op stays active, retry with a bigger buffer
                }
                std::ptr::copy_nonoverlapping(sig.as_ptr(), p_signature, sig.len());
                *pul_signature_len = sig.len() as u32;
                SIGN_RECOVER_STATE.with(|s| s.borrow_mut().remove(&h_session));
                CKR_OK
            }
            Err(rv) => {
                SIGN_RECOVER_STATE.with(|s| s.borrow_mut().remove(&h_session));
                rv
            }
        }
    }
}

#[wasm_bindgen(js_name = _C_VerifyRecoverInit)]
pub fn C_VerifyRecoverInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::VerifyRecover) {
        return rv;
    }
    if VERIFY_STATE.with(|s| s.borrow().contains_key(&h_session))
        || VERIFY_RECOVER_STATE.with(|s| s.borrow().contains_key(&h_session))
    {
        return CKR_OPERATION_ACTIVE;
    }
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech_type = unsafe { ck_param::mech(p_mechanism).mechanism };
    if mech_type != CKM_RSA_PKCS && mech_type != CKM_RSA_X_509 {
        return CKR_MECHANISM_INVALID;
    }
    if let Err(rv) = check_key_usage(h_session, h_key, CKA_VERIFY_RECOVER) {
        return rv;
    }
    if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
        return rv;
    }
    VERIFY_RECOVER_STATE.with(|s| {
        s.borrow_mut().insert(h_session, (mech_type, h_key));
    });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_VerifyRecover)]
pub fn C_VerifyRecover(
    h_session: u32,
    p_signature: *mut u8,
    ul_signature_len: u32,
    p_data: *mut u8,
    pul_data_len: *mut u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    if pul_data_len.is_null() || (p_signature.is_null() && ul_signature_len > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    let state = VERIFY_RECOVER_STATE.with(|s| s.borrow().get(&h_session).cloned());
    let (mech, hkey) = match state {
        Some(s) => s,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    let (n, e) = match get_rsa_public_components(hkey) {
        Some(v) => v,
        None => return CKR_ARGUMENTS_BAD,
    };
    unsafe {
        let sig = std::slice::from_raw_parts(p_signature, ul_signature_len as usize);
        let result: Result<Vec<u8>, u32> = if mech == CKM_RSA_PKCS {
            rsa_pkcs_verify_recover(&n, &e, sig)
        } else {
            rsa_x509_verify_recover(&n, &e, sig)
        };
        match result {
            Ok(data) => {
                if p_data.is_null() {
                    *pul_data_len = data.len() as u32;
                    return CKR_OK; // length query — op stays active
                }
                if (*pul_data_len as usize) < data.len() {
                    *pul_data_len = data.len() as u32;
                    return CKR_BUFFER_TOO_SMALL;
                }
                std::ptr::copy_nonoverlapping(data.as_ptr(), p_data, data.len());
                *pul_data_len = data.len() as u32;
                VERIFY_RECOVER_STATE.with(|s| s.borrow_mut().remove(&h_session));
                CKR_OK
            }
            Err(rv) => {
                VERIFY_RECOVER_STATE.with(|s| s.borrow_mut().remove(&h_session));
                rv
            }
        }
    }
}

/// CKM_RSA_X_509 sign-recover — raw RSASP1 (RFC 8017 §5.2.1), no padding.
/// PKCS#11 v3.2 Table 45: input length ≤ k (modulus bytes), output exactly
/// k bytes (left-zero-padded if the numeric result is shorter). Uses
/// `rsa::hazmat::rsa_decrypt` — the same raw primitive `RSA-SignaturePrimitive-2.0`
/// (NIST ACVP) exercises; blinded (RNG passed) against timing side channels.
fn rsa_x509_sign_recover(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    let priv_key =
        rsa::RsaPrivateKey::from_pkcs8_der(sk_bytes).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let k = priv_key.size();
    if msg.len() > k {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let m = rsa::BigUint::from_bytes_be(msg);
    let mut rng = rand::rngs::OsRng;
    let sig = rsa::hazmat::rsa_decrypt(Some(&mut rng), &priv_key, &m)
        .map_err(|_| CKR_DATA_LEN_RANGE)?; // "message representative >= modulus" (Table 45 note)
    let mut sig_bytes = sig.to_bytes_be();
    if sig_bytes.len() < k {
        let mut padded = vec![0u8; k - sig_bytes.len()];
        padded.extend_from_slice(&sig_bytes);
        sig_bytes = padded;
    }
    Ok(sig_bytes)
}

/// CKM_RSA_X_509 verify-recover — raw RSAVP1 (RFC 8017 §5.2.2), no padding.
/// Output is the raw modexp result with natural leading zeros dropped
/// (Table 45: output length "≤ k", not always exactly k).
fn rsa_x509_verify_recover(n_bytes: &[u8], e_bytes: &[u8], sig: &[u8]) -> Result<Vec<u8>, u32> {
    use rsa::traits::PublicKeyParts;
    if n_bytes.is_empty() || e_bytes.is_empty() {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let n = rsa::BigUint::from_bytes_be(n_bytes);
    let e = rsa::BigUint::from_bytes_be(e_bytes);
    let pub_key = rsa::RsaPublicKey::new(n, e).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let k = pub_key.size();
    if sig.len() != k {
        return Err(CKR_SIGNATURE_LEN_RANGE);
    }
    let c = rsa::BigUint::from_bytes_be(sig);
    let m = rsa::hazmat::rsa_encrypt(&pub_key, &c).map_err(|_| CKR_SIGNATURE_INVALID)?;
    Ok(m.to_bytes_be())
}

/// CKM_RSA_PKCS verify-recover — raw RSAVP1, then strip the EMSA-PKCS1-v1_5
/// padding block (RFC 8017 §9.2: `EM = 0x00 || 0x01 || PS(0xFF, >=8 bytes)
/// || 0x00 || M`) to recover `M`. This is the "verify AND recover" half
/// the `rsa` crate's high-level `Pkcs1v15Sign`/`Verifier` API doesn't
/// expose (it's verify-or-fail against a caller-supplied expected value);
/// the padding-format check below IS the security-relevant part of this
/// primitive, so it follows RFC 8017 exactly rather than a loose scan.
fn rsa_pkcs_verify_recover(n_bytes: &[u8], e_bytes: &[u8], sig: &[u8]) -> Result<Vec<u8>, u32> {
    use rsa::traits::PublicKeyParts;
    if n_bytes.is_empty() || e_bytes.is_empty() {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let n = rsa::BigUint::from_bytes_be(n_bytes);
    let e = rsa::BigUint::from_bytes_be(e_bytes);
    let pub_key = rsa::RsaPublicKey::new(n, e).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let k = pub_key.size();
    if sig.len() != k {
        return Err(CKR_SIGNATURE_LEN_RANGE);
    }
    let c = rsa::BigUint::from_bytes_be(sig);
    let m = rsa::hazmat::rsa_encrypt(&pub_key, &c).map_err(|_| CKR_SIGNATURE_INVALID)?;
    let mut em = m.to_bytes_be();
    if em.len() < k {
        let mut padded = vec![0u8; k - em.len()];
        padded.extend_from_slice(&em);
        em = padded;
    }
    rsa_pkcs1v15_unpad(&em)
}

/// RFC 8017 §9.2 EMSA-PKCS1-v1_5 decode: `0x00 || 0x01 || PS || 0x00 || M`,
/// `PS` all-0xFF and at least 8 bytes. Any deviation is `CKR_SIGNATURE_INVALID`
/// — this is the actual security boundary of RSA_PKCS verify-recover, so it
/// rejects rather than best-effort-parses on any malformed byte.
fn rsa_pkcs1v15_unpad(em: &[u8]) -> Result<Vec<u8>, u32> {
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x01 {
        return Err(CKR_SIGNATURE_INVALID);
    }
    let mut i = 2;
    while i < em.len() && em[i] == 0xFF {
        i += 1;
    }
    if i - 2 < 8 || i >= em.len() || em[i] != 0x00 {
        return Err(CKR_SIGNATURE_INVALID);
    }
    Ok(em[i + 1..].to_vec())
}

// §5.16 — dual-function cryptographic operations. Each composes the two
// already-validated single-part streaming primitives in lockstep. Both
// component operations must be active (else CKR_OPERATION_NOT_INITIALIZED);
// the operations keep their own independent state slots, so the complementary
// inits coexist. A NULL output buffer is a length query and must not advance
// either operation, so it delegates to the cipher half alone.
#[wasm_bindgen(js_name = _C_DigestEncryptUpdate)]
pub fn C_DigestEncryptUpdate(
    h_session: u32,
    p_part: *mut u8,
    ul_part_len: u32,
    p_encrypted_part: *mut u8,
    pul_encrypted_part_len: *mut u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    if !DIGEST_STATE.with(|s| s.borrow().contains_key(&h_session))
        || !ENCRYPT_STATE.with(|s| s.borrow().contains_key(&h_session))
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    // Length query — advance neither operation.
    if p_encrypted_part.is_null() {
        return C_EncryptUpdate(h_session, p_part, ul_part_len, p_encrypted_part, pul_encrypted_part_len);
    }
    // Encrypt the plaintext part (output → ciphertext), then digest the same
    // plaintext. Encrypt first so a cipher error does not advance the digest.
    let rv = C_EncryptUpdate(h_session, p_part, ul_part_len, p_encrypted_part, pul_encrypted_part_len);
    if rv != CKR_OK {
        return rv;
    }
    C_DigestUpdate(h_session, p_part, ul_part_len)
}
#[wasm_bindgen(js_name = _C_DecryptDigestUpdate)]
pub fn C_DecryptDigestUpdate(
    h_session: u32,
    p_encrypted_part: *mut u8,
    ul_encrypted_part_len: u32,
    p_part: *mut u8,
    pul_part_len: *mut u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    if !DECRYPT_STATE.with(|s| s.borrow().contains_key(&h_session))
        || !DIGEST_STATE.with(|s| s.borrow().contains_key(&h_session))
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if p_part.is_null() {
        return C_DecryptUpdate(h_session, p_encrypted_part, ul_encrypted_part_len, p_part, pul_part_len);
    }
    // Decrypt the ciphertext part (output → recovered plaintext), then digest
    // exactly the recovered plaintext bytes.
    let rv = C_DecryptUpdate(h_session, p_encrypted_part, ul_encrypted_part_len, p_part, pul_part_len);
    if rv != CKR_OK {
        return rv;
    }
    let plaintext_len = unsafe { *pul_part_len };
    C_DigestUpdate(h_session, p_part, plaintext_len)
}
#[wasm_bindgen(js_name = _C_SignEncryptUpdate)]
pub fn C_SignEncryptUpdate(
    h_session: u32,
    p_part: *mut u8,
    ul_part_len: u32,
    p_encrypted_part: *mut u8,
    pul_encrypted_part_len: *mut u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    if !SIGN_STATE.with(|s| s.borrow().contains_key(&h_session))
        || !ENCRYPT_STATE.with(|s| s.borrow().contains_key(&h_session))
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if p_encrypted_part.is_null() {
        return C_EncryptUpdate(h_session, p_part, ul_part_len, p_encrypted_part, pul_encrypted_part_len);
    }
    // Encrypt the plaintext part, then feed the same plaintext to the signer.
    let rv = C_EncryptUpdate(h_session, p_part, ul_part_len, p_encrypted_part, pul_encrypted_part_len);
    if rv != CKR_OK {
        return rv;
    }
    C_SignUpdate(h_session, p_part, ul_part_len)
}
#[wasm_bindgen(js_name = _C_DecryptVerifyUpdate)]
pub fn C_DecryptVerifyUpdate(
    h_session: u32,
    p_encrypted_part: *mut u8,
    ul_encrypted_part_len: u32,
    p_part: *mut u8,
    pul_part_len: *mut u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    if !DECRYPT_STATE.with(|s| s.borrow().contains_key(&h_session))
        || !VERIFY_STATE.with(|s| s.borrow().contains_key(&h_session))
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if p_part.is_null() {
        return C_DecryptUpdate(h_session, p_encrypted_part, ul_encrypted_part_len, p_part, pul_part_len);
    }
    // Decrypt the ciphertext part, then feed the recovered plaintext to the
    // verifier.
    let rv = C_DecryptUpdate(h_session, p_encrypted_part, ul_encrypted_part_len, p_part, pul_part_len);
    if rv != CKR_OK {
        return rv;
    }
    let plaintext_len = unsafe { *pul_part_len };
    C_VerifyUpdate(h_session, p_part, plaintext_len)
}

/// PKCS#11 v3.2 §5.6.7 — C_SetPIN rotates the PIN of the user that is
/// currently logged in (SO session → SO PIN; user session OR public session →
/// the normal user PIN, per the spec's session-state table). Works only from
/// a R/W session; the old PIN is verified against the stored PBKDF2 hash and
/// the new PIN is re-salted and re-hashed (`state::hash_pin`).
#[wasm_bindgen(js_name = _C_SetPIN)]
pub fn C_SetPIN(
    h_session: u32,
    p_old_pin: *mut u8,
    ul_old_len: u32,
    p_new_pin: *mut u8,
    ul_new_len: u32,
) -> u32 {
    require_init!();
    // No protected authentication path on this token — both PINs must be
    // supplied through the API.
    nonnull!(p_old_pin, p_new_pin);
    let session = match SESSIONS.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(s) => s,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    if !session.rw_session {
        // §5.6.7 — C_SetPIN may only be called from a read/write session.
        return CKR_SESSION_READ_ONLY;
    }
    // T6 — the NEW PIN must satisfy the advertised bounds (the old one is
    // verified against the stored hash, so its length needs no range gate).
    if !(PIN_MIN_LEN..=PIN_MAX_LEN).contains(&ul_new_len) {
        return CKR_PIN_LEN_RANGE;
    }
    let old_pin = unsafe { std::slice::from_raw_parts(p_old_pin, ul_old_len as usize) };
    let new_pin = unsafe { std::slice::from_raw_parts(p_new_pin, ul_new_len as usize) };
    let mut salt = [0u8; 16];
    if getrandom::getrandom(&mut salt).is_err() {
        return CKR_GENERAL_ERROR;
    }
    let slot_id = session.slot_id;
    let mut changed_role: Option<crate::store::PinRole> = None;
    let mut snapshot: Option<crate::store::PersistedToken> = None;
    let rv = TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        let token = match store.get_mut(&slot_id) {
            Some(t) => t,
            None => return CKR_GENERAL_ERROR,
        };
        let rv = match token.login_state {
            LoginState::SO => {
                if hash_pin(old_pin, &token.so_pin_salt) != token.so_pin_hash {
                    return CKR_PIN_INCORRECT;
                }
                token.so_pin_salt = salt;
                token.so_pin_hash = hash_pin(new_pin, &salt);
                changed_role = Some(crate::store::PinRole::So);
                CKR_OK
            }
            // §5.6.7 table — both the user session AND the public session
            // change the normal user PIN.
            LoginState::User | LoginState::Public => {
                let (cur_salt, cur_hash) = match (&token.user_pin_salt, &token.user_pin_hash) {
                    (Some(s), Some(h)) => (*s, *h),
                    // No user PIN exists yet (C_InitPIN never ran) — there is
                    // nothing to verify the old PIN against.
                    _ => return CKR_USER_PIN_NOT_INITIALIZED,
                };
                if hash_pin(old_pin, &cur_salt) != cur_hash {
                    return CKR_PIN_INCORRECT;
                }
                token.user_pin_salt = Some(salt);
                token.user_pin_hash = Some(hash_pin(new_pin, &salt));
                changed_role = Some(crate::store::PinRole::User);
                CKR_OK
            }
        };
        if rv == CKR_OK && crate::store::is_persistent() {
            snapshot = Some(crate::store::PersistedToken {
                initialized: token.initialized,
                label: token.label,
                so_pin_salt: token.so_pin_salt,
                so_pin_hash: token.so_pin_hash,
                user_pin_salt: token.user_pin_salt,
                user_pin_hash: token.user_pin_hash,
                master_key_so_wrapped: None,   // filled in below
                master_key_user_wrapped: None, // filled in below
                next_handle: 0,
                unique_id_counter: 0,
            });
        }
        rv
    });
    if let (Some(mut snap), Some(role)) = (snapshot, changed_role) {
        // The old PIN was just verified above (in whichever branch ran),
        // regardless of session login state — including the Public-session
        // "reset my own user PIN with the current one" path, which has no
        // cached unlocked master key to fall back on. So unwrap with
        // old_pin here rather than relying on the login-time cache.
        let existing = crate::store::active().get_token(slot_id);
        let (so_wrapped, user_wrapped) = existing
            .map(|t| (t.master_key_so_wrapped, t.master_key_user_wrapped))
            .unwrap_or((None, None));
        let old_wrapped = match role {
            crate::store::PinRole::So => &so_wrapped,
            crate::store::PinRole::User => &user_wrapped,
        };
        match old_wrapped {
            Some(old_wrapped) => {
                match crate::store::crypto::unwrap_master_key(old_pin, old_wrapped)
                    .and_then(|master_key| {
                        crate::store::crypto::wrap_master_key(new_pin, &master_key)
                            .map(|w| (master_key, w))
                    }) {
                    Ok((master_key, new_wrapped)) => {
                        match role {
                            crate::store::PinRole::So => {
                                snap.master_key_so_wrapped = Some(new_wrapped);
                                snap.master_key_user_wrapped = user_wrapped;
                            }
                            crate::store::PinRole::User => {
                                snap.master_key_user_wrapped = Some(new_wrapped);
                                snap.master_key_so_wrapped = so_wrapped;
                            }
                        }
                        crate::store::set_unlocked_master_key(slot_id, master_key);
                    }
                    Err(_) => {
                        // Should not happen (old_pin was just verified against
                        // the PIN hash above) — leave both wraps as they were
                        // rather than risk persisting a half-updated pair.
                        snap.master_key_so_wrapped = so_wrapped;
                        snap.master_key_user_wrapped = user_wrapped;
                    }
                }
            }
            None => {
                // Nothing wrapped yet for this role (e.g. persistence was
                // configured after this PIN was first set) — persist the
                // PIN hash change; there is no master key to re-wrap.
                snap.master_key_so_wrapped = so_wrapped;
                snap.master_key_user_wrapped = user_wrapped;
            }
        }
        crate::store::active().put_token(slot_id, &snap);
    }
    rv
}

/// Engine core of `C_CopyObject` — clone + template overlay with §4.1.2/§4.1.3
/// copy semantics. Split from the FFI wrapper so policy is unit-testable on
/// 64-bit native builds (32-bit CK_ATTRIBUTE templates cannot embed native
/// value pointers there).
pub(crate) fn copy_object_from_attrs(
    h_session: u32,
    h_object: u32,
    template: Attributes,
) -> Result<u32, u32> {
    let src = match OBJECTS.with(|o| o.borrow().get(&h_object).cloned()) {
        Some(a) => a,
        None => return Err(CKR_OBJECT_HANDLE_INVALID),
    };
    // §4.4 — invisible (private-while-logged-out or cross-slot) handles are
    // invalid handles.
    if !crate::state::can_access_object(h_session, &src) {
        return Err(CKR_OBJECT_HANDLE_INVALID);
    }
    // §4.1.3 — CKA_COPYABLE=FALSE forbids C_CopyObject. Absent attr defaults
    // TRUE (state::apply_object_defaults stamps it on every allocate path).
    let copyable = src
        .get(&CKA_COPYABLE)
        .map(|v| v.first().copied().unwrap_or(0) != 0)
        .unwrap_or(true);
    if !copyable {
        return Err(CKR_ACTION_PROHIBITED);
    }
    // WP-5 remediation — CKA_TRUSTED needs its own SO-aware gate, separate
    // from the generic attr_mutation_allowed loop below (which
    // unconditionally rejects it — correct for C_SetAttributeValue, but
    // too strict here: an SO session copying an object should be able to
    // produce a trusted copy, mirroring C_CreateObject's own SO exception
    // per §4.1.1 Table 12 / §4.6 Table 19 footnote). Before this fix, an
    // explicit CKA_TRUSTED in the template was rejected for EVERY session
    // including SO.
    let is_so = crate::state::session_is_so(h_session);
    if template.contains_key(&CKA_TRUSTED) && !is_so {
        return Err(CKR_ATTRIBUTE_READ_ONLY);
    }
    // WP-5 remediation — identity-field respoofing guard. If the SOURCE
    // object is CKA_TRUSTED=TRUE, a non-SO caller could previously omit
    // CKA_TRUSTED from the template (letting it silently carry over
    // unchanged — see the clone below) while simultaneously rewriting
    // CKA_SUBJECT / CKA_ISSUER / CKA_SERIAL_NUMBER / CKA_ID / CKA_LABEL /
    // CKA_PRIVATE in the same copy: a trusted-looking object with
    // attacker-chosen identity metadata, entirely outside the SO gate
    // C_CreateObject enforces. Require SO for any of those changes
    // whenever the source is already trusted.
    if read_bool_attr(&src, CKA_TRUSTED) && !is_so {
        let identity_attrs = [
            CKA_SUBJECT,
            CKA_ISSUER,
            CKA_SERIAL_NUMBER,
            crate::native::keygen::CKA_ID,
            crate::native::keygen::CKA_LABEL,
            CKA_PRIVATE,
        ];
        if template.keys().any(|t| identity_attrs.contains(t)) {
            return Err(CKR_ATTRIBUTE_READ_ONLY);
        }
    }
    // §4.1.2-3 — the copy template may set CKA_TOKEN / CKA_PRIVATE /
    // CKA_MODIFIABLE (not in the gate's read-only set) but may NOT touch
    // server-managed attrs or weaken security (CKA_SENSITIVE TRUE→FALSE,
    // CKA_EXTRACTABLE FALSE→TRUE). Weakening is pinned to
    // CKR_ATTRIBUTE_READ_ONLY from C_CopyObject's §5.7.2 return list,
    // through the same gate C_SetAttributeValue uses (single source of
    // truth: state::attr_mutation_allowed). CKA_TRUSTED is excluded here —
    // handled above with its own SO-aware check.
    for (t, v) in &template {
        if *t == CKA_TRUSTED {
            continue;
        }
        attr_mutation_allowed(&src, *t, v)?;
    }
    // §5.7.2 — a R/O session cannot produce a token object. The copy's
    // effective CKA_TOKEN is the template's value, else the source's.
    let token_attr = template
        .get(&CKA_TOKEN)
        .or_else(|| src.get(&CKA_TOKEN))
        .map(|v| v.first().copied().unwrap_or(0) != 0)
        .unwrap_or(false);
    if token_attr && !crate::state::session_is_rw(h_session) {
        return Err(CKR_SESSION_READ_ONLY);
    }
    // Clone the record and overlay the template. Engine-internal owner/slot
    // tags are dropped so allocate_handle_owned re-stamps them for THIS
    // session; CKA_UNIQUE_ID is unconditionally regenerated inside
    // allocate_handle, so the copy never carries the source's identifier.
    // CKA_ALWAYS_SENSITIVE / CKA_NEVER_EXTRACTABLE carry over unchanged:
    // weakening was rejected above and strengthening (e.g. SENSITIVE
    // FALSE→TRUE in the template) cannot rewrite history.
    let mut new_attrs = src.clone();
    new_attrs.remove(&CKA_PRIV_OWNER_SESSION);
    new_attrs.remove(&CKA_PRIV_SLOT_ID);
    // WP-5 remediation — CKA_TRUSTED must not silently carry over from the
    // source for a non-SO copy (the gap this whole block closes): force it
    // FALSE here, before the template overlay below. A non-SO template can
    // never contain CKA_TRUSTED (rejected above), so this stands
    // unconditionally for a non-SO session regardless of the template's
    // contents; an SO session's explicit CKA_TRUSTED=TRUE is applied by
    // the overlay immediately after and overwrites this default.
    if !is_so {
        new_attrs.insert(CKA_TRUSTED, vec![0]);
    }
    for (t, v) in template {
        new_attrs.insert(t, v);
    }
    let handle = allocate_handle_owned(h_session, new_attrs);
    if handle == 0 {
        // NEXT_HANDLE saturated — allocation refused.
        return Err(CKR_GENERAL_ERROR);
    }
    Ok(handle)
}

#[wasm_bindgen(js_name = _C_CopyObject)]
pub fn C_CopyObject(
    h_session: u32,
    h_object: u32,
    p_template: *mut u8,
    ul_count: u32,
    ph_new_object: *mut u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    nonnull!(ph_new_object);
    if p_template.is_null() && ul_count > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    if ul_count > 65536 {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let tmpl_ptr = p_template as *mut usize;
        let mut template = Attributes::new();
        for i in 0..ul_count {
            let attr_type = *tmpl_ptr.add((i * 3) as usize) as u32;
            let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as u32;
            if val_ptr.is_null() && val_len > 0 {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            let mut v = vec![0u8; val_len as usize];
            if val_len > 0 {
                std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
            }
            template.insert(attr_type, v);
        }
        match copy_object_from_attrs(h_session, h_object, template) {
            Ok(handle) => {
                *ph_new_object = handle;
                CKR_OK
            }
            Err(rv) => rv,
        }
    }
}

/// T6 — per-attribute overhead used by `C_GetObjectSize`: one CK_ATTRIBUTE
/// header on the engine's 32-bit ABI (type + pValue + ulValueLen, 4 B each).
const OBJECT_SIZE_ATTR_OVERHEAD: u32 = 12;

/// PKCS#11 v3.2 §5.7.4 — "an estimate of the amount of storage the object
/// occupies". Honest estimate: Σ(stored attribute value lengths) + a fixed
/// 12-byte per-attribute header ([`OBJECT_SIZE_ATTR_OVERHEAD`]). The
/// engine-internal CKA_PRIV_* bookkeeping attrs (≥0xFFFF_0000) are excluded —
/// they are implementation plumbing, not object storage the client created.
#[wasm_bindgen(js_name = _C_GetObjectSize)]
pub fn C_GetObjectSize(h_session: u32, h_object: u32, pul_size: *mut u32) -> u32 {
    require_init!();
    require_session!(h_session);
    nonnull!(pul_size);
    let size = OBJECTS.with(|o| {
        o.borrow().get(&h_object).map(|attrs| {
            if !crate::state::can_access_object(h_session, attrs) {
                return None;
            }
            Some(
                attrs
                    .iter()
                    .filter(|(t, _)| **t < 0xFFFF_0000)
                    .map(|(_, v)| v.len() as u32 + OBJECT_SIZE_ATTR_OVERHEAD)
                    .sum::<u32>(),
            )
        })
    });
    match size.flatten() {
        Some(sz) => {
            unsafe { *pul_size = sz };
            CKR_OK
        }
        None => CKR_OBJECT_HANDLE_INVALID,
    }
}

/// Engine core of `C_SetAttributeValue` — two-phase (validate ALL, then
/// apply) so a template mixing valid and invalid entries leaves the object
/// untouched. §5.7.6 only promises "may or may not be modified" on failure;
/// all-or-nothing is the quality bar this engine pins. `updates` preserves
/// template order (later duplicates win, as they would applying in order).
pub(crate) fn set_attribute_values_from_list(
    h_session: u32,
    h_object: u32,
    updates: &[(u32, Vec<u8>)],
) -> u32 {
    let obj_attrs = match OBJECTS.with(|o| o.borrow().get(&h_object).cloned()) {
        Some(a) => a,
        None => return CKR_OBJECT_HANDLE_INVALID,
    };
    // §4.4 — invisible (private-while-logged-out or cross-slot) handles are
    // invalid handles.
    if !crate::state::can_access_object(h_session, &obj_attrs) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    // §5.6 — token objects may only be modified from a R/W session (same
    // gate C_CreateObject applies to creating them).
    if read_bool_attr(&obj_attrs, CKA_TOKEN) && !crate::state::session_is_rw(h_session) {
        return CKR_SESSION_READ_ONLY;
    }
    // §4.1.3 — CKA_MODIFIABLE=FALSE forbids C_SetAttributeValue entirely.
    // Absent attr defaults TRUE (apply_object_defaults stamps it).
    let modifiable = obj_attrs
        .get(&CKA_MODIFIABLE)
        .map(|v| v.first().copied().unwrap_or(0) != 0)
        .unwrap_or(true);
    if !modifiable {
        return CKR_ACTION_PROHIBITED;
    }
    // Phase 1 — validate EVERY entry against the object's current state
    // through the shared gate (state::attr_mutation_allowed: read-only set,
    // one-way CKA_SENSITIVE/CKA_EXTRACTABLE transitions).
    for (attr_type, value) in updates {
        if let Err(rv) = crate::state::attr_mutation_allowed(&obj_attrs, *attr_type, value) {
            return rv;
        }
    }
    // Phase 2 — apply in template order. CKA_ALWAYS_SENSITIVE /
    // CKA_NEVER_EXTRACTABLE are NOT recomputed: they record creation-time
    // history and legal one-way flips must not alter them.
    for (attr_type, value) in updates {
        if !set_object_attr_bytes(h_object, *attr_type, value.clone()) {
            return CKR_OBJECT_HANDLE_INVALID; // unreachable: existence checked above
        }
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_SetAttributeValue)]
pub fn C_SetAttributeValue(
    h_session: u32,
    h_object: u32,
    p_template: *mut u8,
    ul_count: u32,
) -> u32 {
    require_init!();
    require_session!(h_session);
    if p_template.is_null() && ul_count > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    if ul_count > 65536 {
        return CKR_ARGUMENTS_BAD;
    }
    let mut updates: Vec<(u32, Vec<u8>)> = Vec::with_capacity(ul_count as usize);
    unsafe {
        let tmpl_ptr = p_template as *mut usize;
        for i in 0..ul_count {
            let attr_type = *tmpl_ptr.add((i * 3) as usize) as u32;
            let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *tmpl_ptr.add((i * 3 + 2) as usize) as u32;
            if val_ptr.is_null() && val_len > 0 {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            let mut v = vec![0u8; val_len as usize];
            if val_len > 0 {
                std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
            }
            updates.push((attr_type, v));
        }
    }
    set_attribute_values_from_list(h_session, h_object, &updates)
}

// §5.13 — digesting a secret key into an active digest op is optional;
// CKR_FUNCTION_NOT_SUPPORTED is the spec-legal answer (T6 audit: documented
// optional-stub gap, same as the operation-state pair below).
#[wasm_bindgen(js_name = _C_DigestKey)]
pub fn C_DigestKey(_h_session: u32, _h_key: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

// §5.6 — operation-state serialization is optional; this engine does not
// provide it (spec-legal CKR_FUNCTION_NOT_SUPPORTED).
#[wasm_bindgen(js_name = _C_GetOperationState)]
pub fn C_GetOperationState(
    _h_session: u32,
    _p_operation_state: *mut u8,
    _pul_operation_state_len: *mut u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SetOperationState)]
pub fn C_SetOperationState(
    _h_session: u32,
    _p_operation_state: *mut u8,
    _ul_operation_state_len: u32,
    _h_encryption_key: u32,
    _h_authentication_key: u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SeedRandom)]
pub fn C_SeedRandom(_h_session: u32, _p_seed: *mut u8, _ul_seed_len: u32) -> u32 {
    require_init!();
    // WASM getrandom is OS-backed; external seeding is not supported. §5.14
    // assigns this exact condition CKR_RANDOM_SEED_NOT_SUPPORTED (T6 honesty
    // fix — previously CKR_FUNCTION_NOT_SUPPORTED).
    CKR_RANDOM_SEED_NOT_SUPPORTED
}

// ============================================================================
// PKCS#11 v3.0 Message Encryption
// ============================================================================

fn parse_gcm_msg_params(p: *mut u8) -> Result<(Vec<u8>, *mut u8, u32), u32> {
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    unsafe {
        // CK_GCM_MESSAGE_PARAMS at native width (usize words): pIv@0, ulIvLen@1,
        // ulIvBits@2 (skipped), ivGenerator@3, pTag@4, ulTagBits@5.
        let pu = p as *const usize;
        let p_iv = *pu as *mut u8;
        let ul_iv_len = *pu.add(1) as u32;
        let iv_gen = *pu.add(3) as u32;
        let p_tag = *pu.add(4) as *mut u8;
        let ul_tag_bits = *pu.add(5) as u32;

        if p_iv.is_null() || ul_iv_len == 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        if p_tag.is_null() || ul_tag_bits == 0 || ul_tag_bits > 128 || ul_tag_bits % 8 != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }

        if iv_gen != 0 {
            let mut rand_iv = vec![0u8; ul_iv_len as usize];
            if getrandom::getrandom(&mut rand_iv).is_err() {
                return Err(CKR_GENERAL_ERROR);
            }
            std::ptr::copy_nonoverlapping(rand_iv.as_ptr(), p_iv, ul_iv_len as usize);
        }

        let iv = std::slice::from_raw_parts(p_iv, ul_iv_len as usize).to_vec();
        Ok((iv, p_tag, ul_tag_bits))
    }
}

pub fn msg_encrypt_init_internal(
    h_session: u32,
    p_mechanism: *mut u8,
    h_key: u32,
    is_encrypt: bool,
) -> u32 {
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = ck_param::mech(p_mechanism).mechanism;
        if mech_type != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }

        let can_use = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| {
                    read_bool_attr(attrs, if is_encrypt { CKA_ENCRYPT } else { CKA_DECRYPT })
                })
                .unwrap_or(false)
        });
        if !can_use {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS. Covers both
        // C_MessageEncryptInit and C_MessageDecryptInit, which both delegate
        // here.
        if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
            return rv;
        }

        let key_bytes = match get_object_value(h_key) {
            Some(v) => v,
            None => return CKR_KEY_TYPE_INCONSISTENT,
        };

        if key_bytes.len() != 16 && key_bytes.len() != 32 {
            return CKR_KEY_SIZE_RANGE;
        }

        let ctx = MsgAeadCtx {
            key: key_bytes,
            in_message: false,
            tag_bits: 0,
            stream: None,
            plaintext_acc: Vec::new(),
        };

        if is_encrypt {
            MESSAGE_ENCRYPT_STATE.with(|s| s.borrow_mut().insert(h_session, ctx));
        } else {
            MESSAGE_DECRYPT_STATE.with(|s| s.borrow_mut().insert(h_session, ctx));
        }

        CKR_OK
    }
}

// ── T5 message-stream cores ─────────────────────────────────────────────────
//
// The C_*MessageBegin/Next entry points split into thin FFI wrappers (which
// parse CK_GCM_MESSAGE_PARAMS — a struct of WASM32 4-byte pointers that
// cannot be built in native 64-bit tests) and the cores below, which take
// already-resolved slices/pointers and own all state-machine logic. Native
// tests drive the cores directly with real pointers.

/// C_EncryptMessageBegin / C_DecryptMessageBegin: fold the AAD and derive
/// J0 up front, arming an incremental `GcmState` for the message.
fn message_begin_core(
    h_session: u32,
    iv: &[u8],
    aad: &[u8],
    tag_bits: u32,
    is_encrypt: bool,
) -> u32 {
    use crate::crypto::multipart::{AesKey, CipherDirection, GcmState};
    let state = if is_encrypt { &*MESSAGE_ENCRYPT_STATE } else { &*MESSAGE_DECRYPT_STATE };
    state.with(|s| {
        let mut store = s.borrow_mut();
        let Some(c) = store.get_mut(&h_session) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if c.in_message {
            return CKR_OPERATION_ACTIVE;
        }
        let Some(key) = AesKey::new(&c.key) else {
            return CKR_KEY_SIZE_RANGE;
        };
        // Full 128-bit tag internally; truncation to ulTagBits happens at
        // the final Next (mirrors the one-shot path's tag handling).
        let dir = if is_encrypt { CipherDirection::Encrypt } else { CipherDirection::Decrypt };
        c.stream = Some(GcmState::new(key, iv, aad, 128, dir));
        c.tag_bits = tag_bits;
        c.plaintext_acc.clear();
        c.in_message = true;
        CKR_OK
    })
}

/// C_EncryptMessageNext core: O(chunk) — CTR-encrypt the part through the
/// session's `GcmState` (keystream remainder carries across chunk
/// boundaries) and fold the ciphertext into the running GHASH. On
/// CKF_END_OF_MESSAGE, write the truncated tag to `p_tag`.
///
/// # Safety
/// `p_part`/`p_out`/`pul_out`/`p_tag` must be valid for the lengths
/// involved (`p_tag` only when `end_of_message`).
unsafe fn encrypt_message_next_core(
    h_session: u32,
    p_part: *const u8,
    part_len: u32,
    p_out: *mut u8,
    pul_out: *mut u32,
    end_of_message: bool,
    p_tag: *mut u8,
) -> u32 {
    match MESSAGE_ENCRYPT_STATE
        .with(|s| s.borrow().get(&h_session).map(|c| c.in_message && c.stream.is_some()))
    {
        None | Some(false) => return CKR_OPERATION_NOT_INITIALIZED,
        Some(true) => {}
    }
    // §5.2 — NULL plaintext part with a nonzero length is invalid input.
    if (p_part.is_null() && part_len > 0) || pul_out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        // §5.2 two-call convention: a NULL output buffer is a pure size
        // query — it must not consume input or advance the stream.
        if p_out.is_null() {
            *pul_out = part_len;
            return CKR_OK;
        }
        if *pul_out < part_len {
            *pul_out = part_len;
            return CKR_BUFFER_TOO_SMALL;
        }
        if end_of_message && p_tag.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let part: &[u8] =
            if part_len == 0 { &[] } else { std::slice::from_raw_parts(p_part, part_len as usize) };

        MESSAGE_ENCRYPT_STATE.with(|s| {
            let mut store = s.borrow_mut();
            let Some(c) = store.get_mut(&h_session) else {
                return CKR_OPERATION_NOT_INITIALIZED;
            };
            let Some(stream) = c.stream.as_mut() else {
                return CKR_OPERATION_NOT_INITIALIZED;
            };
            let ct = stream.msg_update(part);
            std::ptr::copy_nonoverlapping(ct.as_ptr(), p_out, ct.len());
            *pul_out = ct.len() as u32;
            if end_of_message {
                let gcm = c.stream.take().expect("stream checked above");
                let tag = gcm.msg_compute_tag(); // full 16 bytes
                let tag_bytes = ((c.tag_bits / 8) as usize).min(tag.len());
                std::ptr::copy_nonoverlapping(tag.as_ptr(), p_tag, tag_bytes);
                c.in_message = false;
            }
            CKR_OK
        })
    }
}

/// C_DecryptMessageNext core: verify-then-release. Each part is CTR-
/// decrypted incrementally (O(chunk)) but the plaintext is buffered in
/// `plaintext_acc`; intermediate parts emit nothing. The final part
/// verifies the out-of-band tag and only then emits the whole message
/// (memory bound: one message). On mismatch the buffered plaintext is
/// zeroized and the caller's buffer is left untouched.
///
/// # Safety
/// `p_part`/`p_out`/`pul_out`/`p_tag` must be valid for the lengths
/// involved (`p_tag` only when `end_of_message`).
unsafe fn decrypt_message_next_core(
    h_session: u32,
    p_part: *const u8,
    part_len: u32,
    p_out: *mut u8,
    pul_out: *mut u32,
    end_of_message: bool,
    p_tag: *const u8,
) -> u32 {
    let acc_len = match MESSAGE_DECRYPT_STATE.with(|s| {
        s.borrow()
            .get(&h_session)
            .filter(|c| c.in_message && c.stream.is_some())
            .map(|c| c.plaintext_acc.len())
    }) {
        Some(n) => n,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    // §5.2 — NULL ciphertext part with a nonzero length is invalid input.
    if (p_part.is_null() && part_len > 0) || pul_out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // Output requirement: intermediate parts release nothing, but report
    // the part length as an upper bound (§5.2 permits over-estimates); the
    // final part releases the whole withheld message — exact size.
    let need: u32 =
        if end_of_message { (acc_len + part_len as usize) as u32 } else { part_len };
    unsafe {
        // §5.2 two-call convention: a NULL output buffer is a pure size
        // query — it must NOT consume input or advance the stream. Only a
        // successful copy-out consumes.
        if p_out.is_null() {
            *pul_out = need;
            return CKR_OK;
        }
        if *pul_out < need {
            *pul_out = need;
            return CKR_BUFFER_TOO_SMALL;
        }
        if end_of_message && p_tag.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let part: &[u8] =
            if part_len == 0 { &[] } else { std::slice::from_raw_parts(p_part, part_len as usize) };

        MESSAGE_DECRYPT_STATE.with(|s| {
            let mut store = s.borrow_mut();
            let Some(c) = store.get_mut(&h_session) else {
                return CKR_OPERATION_NOT_INITIALIZED;
            };
            let Some(stream) = c.stream.as_mut() else {
                return CKR_OPERATION_NOT_INITIALIZED;
            };
            let mut pt = stream.msg_update(part);
            c.plaintext_acc.extend_from_slice(&pt);
            pt.zeroize();
            if !end_of_message {
                *pul_out = 0;
                return CKR_OK;
            }
            // Final part: verify the tag BEFORE releasing anything.
            let gcm = c.stream.take().expect("stream checked above");
            let tag_bytes = ((c.tag_bits / 8) as usize).min(16);
            let tag = std::slice::from_raw_parts(p_tag, tag_bytes);
            c.in_message = false;
            match gcm.msg_verify_tag(tag) {
                Ok(()) => {
                    std::ptr::copy_nonoverlapping(
                        c.plaintext_acc.as_ptr(),
                        p_out,
                        c.plaintext_acc.len(),
                    );
                    *pul_out = c.plaintext_acc.len() as u32;
                    c.plaintext_acc.zeroize();
                    CKR_OK
                }
                Err(e) => {
                    // §5.15 caveat — no pre-authentication plaintext
                    // escapes: wipe the withheld buffer, leave the
                    // caller's output untouched.
                    c.plaintext_acc.zeroize();
                    e
                }
            }
        })
    }
}

/// One-shot AES-GCM for the §5.15 single-part message calls
/// (C_EncryptMessage / C_DecryptMessage). The tag travels out-of-band:
/// encrypt writes `tag_bits/8` bytes to `p_tag`; decrypt reads them back
/// and verifies (truncated tags per SP 800-38D — fixes the Appendix B
/// always-fail bug where the truncated tag was handed to a 128-bit-only
/// AEAD). T5: backed by the same `GcmState` engine as the streaming path.
pub fn aes_gcm_exec(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    payload: &[u8],
    is_encrypt: bool,
    p_tag: *mut u8,
    tag_bits: u32,
) -> Result<Vec<u8>, u32> {
    use crate::crypto::multipart::{AesKey, CipherDirection, GcmState};

    // The message API supports AES-128/256 (matches C_MessageEncryptInit).
    if key.len() != 16 && key.len() != 32 {
        return Err(CKR_KEY_SIZE_RANGE);
    }
    let aes = AesKey::new(key).ok_or(CKR_KEY_SIZE_RANGE)?;
    let tag_bytes = ((tag_bits / 8) as usize).min(16);

    if is_encrypt {
        let mut gcm = GcmState::new(aes, iv, aad, 128, CipherDirection::Encrypt);
        let ct = gcm.msg_update(payload);
        let tag = gcm.msg_compute_tag();
        unsafe {
            std::ptr::copy_nonoverlapping(tag.as_ptr(), p_tag, tag_bytes);
        }
        Ok(ct)
    } else {
        let mut gcm = GcmState::new(aes, iv, aad, 128, CipherDirection::Decrypt);
        let mut pt = gcm.msg_update(payload);
        let tag = unsafe { std::slice::from_raw_parts(p_tag, tag_bytes) };
        match gcm.msg_verify_tag(tag) {
            Ok(()) => Ok(pt),
            Err(e) => {
                // Unauthenticated plaintext must not survive.
                pt.zeroize();
                Err(e)
            }
        }
    }
}

#[wasm_bindgen(js_name = _C_MessageEncryptInit)]
pub fn C_MessageEncryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    msg_encrypt_init_internal(h_session, p_mechanism, h_key, true)
}

#[wasm_bindgen(js_name = _C_EncryptMessage)]
pub fn C_EncryptMessage(
    h_session: u32,
    p_parameter: *mut u8,
    _ul_parameter_len: u32,
    p_associated_data: *const u8,
    ul_associated_data_len: u32,
    p_plaintext: *const u8,
    ul_plaintext_len: u32,
    p_ciphertext: *mut u8,
    pul_ciphertext_len: *mut u32,
) -> u32 {
    require_init!();
    let (mut key, in_message) = match MESSAGE_ENCRYPT_STATE
        .with(|s| s.borrow().get(&h_session).map(|c| (c.key.clone(), c.in_message)))
    {
        Some(v) => v,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if in_message {
        key.zeroize();
        return CKR_OPERATION_ACTIVE;
    }
    // §5.2 — input pointers (AAD, plaintext) may be NULL only with zero
    // length; only the output buffer participates in the size query.
    if (p_associated_data.is_null() && ul_associated_data_len > 0)
        || (p_plaintext.is_null() && ul_plaintext_len > 0)
    {
        key.zeroize();
        return CKR_ARGUMENTS_BAD;
    }

    let rv = unsafe {
        if p_ciphertext.is_null() {
            *pul_ciphertext_len = ul_plaintext_len;
            key.zeroize();
            return CKR_OK;
        }
        if *pul_ciphertext_len < ul_plaintext_len {
            *pul_ciphertext_len = ul_plaintext_len;
            key.zeroize();
            return CKR_BUFFER_TOO_SMALL;
        }

        let (iv, p_tag, tag_bits) = match parse_gcm_msg_params(p_parameter) {
            Ok(v) => v,
            Err(e) => {
                key.zeroize();
                return e;
            }
        };
        let aad: &[u8] = if p_associated_data.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize)
        };
        let plain: &[u8] = if p_plaintext.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(p_plaintext, ul_plaintext_len as usize)
        };

        match aes_gcm_exec(&key, &iv, aad, plain, true, p_tag, tag_bits) {
            Ok(ct) => {
                std::ptr::copy_nonoverlapping(ct.as_ptr(), p_ciphertext, ct.len());
                *pul_ciphertext_len = ct.len() as u32;
                CKR_OK
            }
            Err(e) => e,
        }
    };
    key.zeroize();
    rv
}

#[wasm_bindgen(js_name = _C_EncryptMessageBegin)]
pub fn C_EncryptMessageBegin(
    h_session: u32,
    p_parameter: *mut u8,
    _ul_parameter_len: u32,
    p_associated_data: *const u8,
    ul_associated_data_len: u32,
) -> u32 {
    require_init!();
    // Error priority: operation state outranks argument validation.
    match MESSAGE_ENCRYPT_STATE.with(|s| s.borrow().get(&h_session).map(|c| c.in_message)) {
        None => return CKR_OPERATION_NOT_INITIALIZED,
        Some(true) => return CKR_OPERATION_ACTIVE,
        Some(false) => {}
    }
    // §5.2 — NULL AAD with a nonzero length is invalid input.
    if p_associated_data.is_null() && ul_associated_data_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let (iv, _p_tag, tag_bits) = match parse_gcm_msg_params(p_parameter) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let aad: &[u8] = if p_associated_data.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize)
        };
        message_begin_core(h_session, &iv, aad, tag_bits, true)
    }
}

#[wasm_bindgen(js_name = _C_EncryptMessageNext)]
pub fn C_EncryptMessageNext(
    h_session: u32,
    p_parameter: *mut u8,
    _ul_parameter_len: u32,
    p_plaintext_part: *const u8,
    ul_plaintext_part_len: u32,
    p_ciphertext_part: *mut u8,
    pul_ciphertext_part_len: *mut u32,
    flags: u32,
) -> u32 {
    require_init!();
    let end_of_message = (flags & 0x0000_0001) != 0; // CKF_END_OF_MESSAGE
    unsafe {
        // The tag destination comes from CK_GCM_MESSAGE_PARAMS.pTag; it is
        // only required (and only dereferenced) on the final part, and the
        // core defers that check until after the §5.2 size-query handling.
        let p_tag: *mut u8 = if end_of_message && !p_parameter.is_null() {
            // CK_GCM_MESSAGE_PARAMS.pTag at native width = usize word 4.
            *((p_parameter as *const usize).add(4)) as *mut u8
        } else {
            std::ptr::null_mut()
        };
        encrypt_message_next_core(
            h_session,
            p_plaintext_part,
            ul_plaintext_part_len,
            p_ciphertext_part,
            pul_ciphertext_part_len,
            end_of_message,
            p_tag,
        )
    }
}

#[wasm_bindgen(js_name = _C_MessageEncryptFinal)]
pub fn C_MessageEncryptFinal(h_session: u32) -> u32 {
    require_init!();
    MESSAGE_ENCRYPT_STATE.with(|s| {
        if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
            ctx.wipe();
        }
    });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_MessageDecryptInit)]
pub fn C_MessageDecryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    msg_encrypt_init_internal(h_session, p_mechanism, h_key, false)
}

#[wasm_bindgen(js_name = _C_DecryptMessage)]
pub fn C_DecryptMessage(
    h_session: u32,
    p_parameter: *mut u8,
    _ul_parameter_len: u32,
    p_associated_data: *const u8,
    ul_associated_data_len: u32,
    p_ciphertext: *const u8,
    ul_ciphertext_len: u32,
    p_plaintext: *mut u8,
    pul_plaintext_len: *mut u32,
) -> u32 {
    require_init!();
    let (mut key, in_message) = match MESSAGE_DECRYPT_STATE
        .with(|s| s.borrow().get(&h_session).map(|c| (c.key.clone(), c.in_message)))
    {
        Some(v) => v,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if in_message {
        key.zeroize();
        return CKR_OPERATION_ACTIVE;
    }
    // §5.2 — input pointers (AAD, ciphertext) may be NULL only with zero
    // length; only the output buffer participates in the size query.
    if (p_associated_data.is_null() && ul_associated_data_len > 0)
        || (p_ciphertext.is_null() && ul_ciphertext_len > 0)
    {
        key.zeroize();
        return CKR_ARGUMENTS_BAD;
    }

    let rv = unsafe {
        if p_plaintext.is_null() {
            *pul_plaintext_len = ul_ciphertext_len;
            key.zeroize();
            return CKR_OK;
        }
        if *pul_plaintext_len < ul_ciphertext_len {
            *pul_plaintext_len = ul_ciphertext_len;
            key.zeroize();
            return CKR_BUFFER_TOO_SMALL;
        }

        let (iv, p_tag, tag_bits) = match parse_gcm_msg_params(p_parameter) {
            Ok(v) => v,
            Err(e) => {
                key.zeroize();
                return e;
            }
        };
        let aad: &[u8] = if p_associated_data.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize)
        };
        let ct: &[u8] = if p_ciphertext.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(p_ciphertext, ul_ciphertext_len as usize)
        };

        match aes_gcm_exec(&key, &iv, aad, ct, false, p_tag, tag_bits) {
            Ok(mut plain) => {
                std::ptr::copy_nonoverlapping(plain.as_ptr(), p_plaintext, plain.len());
                *pul_plaintext_len = plain.len() as u32;
                plain.zeroize();
                CKR_OK
            }
            Err(e) => e,
        }
    };
    key.zeroize();
    rv
}

#[wasm_bindgen(js_name = _C_DecryptMessageBegin)]
pub fn C_DecryptMessageBegin(
    h_session: u32,
    p_parameter: *mut u8,
    _ul_parameter_len: u32,
    p_associated_data: *const u8,
    ul_associated_data_len: u32,
) -> u32 {
    require_init!();
    // Error priority: operation state outranks argument validation.
    match MESSAGE_DECRYPT_STATE.with(|s| s.borrow().get(&h_session).map(|c| c.in_message)) {
        None => return CKR_OPERATION_NOT_INITIALIZED,
        Some(true) => return CKR_OPERATION_ACTIVE,
        Some(false) => {}
    }
    // §5.2 — NULL AAD with a nonzero length is invalid input.
    if p_associated_data.is_null() && ul_associated_data_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let (iv, _p_tag, tag_bits) = match parse_gcm_msg_params(p_parameter) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let aad: &[u8] = if p_associated_data.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize)
        };
        message_begin_core(h_session, &iv, aad, tag_bits, false)
    }
}

#[wasm_bindgen(js_name = _C_DecryptMessageNext)]
pub fn C_DecryptMessageNext(
    h_session: u32,
    p_parameter: *mut u8,
    _ul_parameter_len: u32,
    p_ciphertext_part: *const u8,
    ul_ciphertext_part_len: u32,
    p_plaintext_part: *mut u8,
    pul_plaintext_part_len: *mut u32,
    flags: u32,
) -> u32 {
    require_init!();
    let end_of_message = (flags & 0x0000_0001) != 0; // CKF_END_OF_MESSAGE
    unsafe {
        // The expected tag comes from CK_GCM_MESSAGE_PARAMS.pTag; it is
        // only required (and only dereferenced) on the final part, and the
        // core defers that check until after the §5.2 size-query handling.
        let p_tag: *const u8 = if end_of_message && !p_parameter.is_null() {
            // CK_GCM_MESSAGE_PARAMS.pTag at native width = usize word 4.
            *((p_parameter as *const usize).add(4)) as *const u8
        } else {
            std::ptr::null()
        };
        decrypt_message_next_core(
            h_session,
            p_ciphertext_part,
            ul_ciphertext_part_len,
            p_plaintext_part,
            pul_plaintext_part_len,
            end_of_message,
            p_tag,
        )
    }
}

#[wasm_bindgen(js_name = _C_MessageDecryptFinal)]
pub fn C_MessageDecryptFinal(h_session: u32) -> u32 {
    require_init!();
    MESSAGE_DECRYPT_STATE.with(|s| {
        if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
            ctx.wipe();
        }
    });
    CKR_OK
}

#[wasm_bindgen]
pub struct SoftHsmRust {}

#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: u32,
    pub pParameter: *mut u8,
    pub ulParameterLen: u32,
}

impl Default for SoftHsmRust {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl SoftHsmRust {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SoftHsmRust {
        // Initialize underlying WASM runtime hooks if needed
        C_Initialize(std::ptr::null_mut());
        SoftHsmRust {}
    }

    pub fn init_token(&self, slot_id: u32, pin: &str, label: &str) -> bool {
        // Just a mock pass for tests
        let mut p_pin = pin.as_bytes().to_vec();
        let mut p_label = label.as_bytes().to_vec();
        p_label.resize(32, b' ');

        let result = C_InitToken(
            slot_id,
            p_pin.as_mut_ptr(),
            p_pin.len() as u32,
            p_label.as_mut_ptr(),
        );
        result == CKR_OK
    }

    pub fn generate_aes_key(&self, key_size: u32) -> u32 {
        let mut h_session: u32 = 0;
        C_OpenSession(
            0,
            6,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut h_session,
        );

        // Mock template for AES key
        let mut h_key: u32 = 0;
        let ck_true = 1u8;
        let k_type = CKK_AES;
        let class = CKO_SECRET_KEY;
        let val_len = key_size;

        let mut tmpl = vec![
            CKA_CLASS,
            &class as *const _ as u32,
            4,
            CKA_KEY_TYPE,
            &k_type as *const _ as u32,
            4,
            CKA_VALUE_LEN,
            &val_len as *const _ as u32,
            4,
            CKA_ENCRYPT,
            &ck_true as *const _ as u32,
            1,
            CKA_DECRYPT,
            &ck_true as *const _ as u32,
            1,
        ];

        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        C_GenerateKey(
            h_session,
            &mut mech as *mut _ as *mut u8,
            tmpl.as_mut_ptr() as *mut u8,
            5,
            &mut h_key,
        );
        h_key
    }

    pub fn aes_ctr_encrypt(
        &self,
        key_handle: u32,
        iv: &[u8],
        plaintext: &[u8],
    ) -> js_sys::Uint8Array {
        // CK_AES_CTR_PARAMS at native width (20 B on wasm32, 24 B on LP64) —
        // the same layout C_EncryptInit decodes.
        let usz = core::mem::size_of::<usize>();
        let mut param = vec![0u8; usz + 16];
        param[0..usz].copy_from_slice(&128usize.to_ne_bytes());
        param[usz..usz + 16].copy_from_slice(iv);
        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: param.as_mut_ptr(),
            ulParameterLen: param.len() as u32,
        };

        // Use a mock session 1 since it's just tests
        let h_session = 1;
        C_EncryptInit(h_session, &mut mech as *mut _ as *mut u8, key_handle);

        let mut out_len = plaintext.len() as u32;
        let mut out = vec![0u8; plaintext.len()];

        C_Encrypt(
            h_session,
            plaintext.as_ptr() as *mut u8,
            plaintext.len() as u32,
            out.as_mut_ptr(),
            &mut out_len,
        );

        js_sys::Uint8Array::from(&out[..out_len as usize])
    }

    pub fn aes_ctr_decrypt(
        &self,
        key_handle: u32,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> js_sys::Uint8Array {
        // CK_AES_CTR_PARAMS at native width (20 B on wasm32, 24 B on LP64) —
        // the same layout C_EncryptInit decodes.
        let usz = core::mem::size_of::<usize>();
        let mut param = vec![0u8; usz + 16];
        param[0..usz].copy_from_slice(&128usize.to_ne_bytes());
        param[usz..usz + 16].copy_from_slice(iv);
        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: param.as_mut_ptr(),
            ulParameterLen: param.len() as u32,
        };

        let h_session = 1;
        C_DecryptInit(h_session, &mut mech as *mut _ as *mut u8, key_handle);

        let mut out_len = ciphertext.len() as u32;
        let mut out = vec![0u8; ciphertext.len()];

        C_Decrypt(
            h_session,
            ciphertext.as_ptr() as *mut u8,
            ciphertext.len() as u32,
            out.as_mut_ptr(),
            &mut out_len,
        );

        js_sys::Uint8Array::from(&out[..out_len as usize])
    }
}

// ----------------------------------------------------------------------------
// KAT Testing Seed Hook
// ----------------------------------------------------------------------------
#[wasm_bindgen(js_name = _set_kat_seed)]
pub fn set_kat_seed(seed_ptr: *const u8, seed_len: u32) {
    if seed_len == 96 && !seed_ptr.is_null() {
        let mut seed = [0u8; 96];
        unsafe {
            std::ptr::copy_nonoverlapping(seed_ptr, seed.as_mut_ptr(), 96);
        }
        crate::crypto::xmss_bridge::set_kat_seed_value(Some(seed));
    } else {
        crate::crypto::xmss_bridge::set_kat_seed_value(None);
    }
}

// ----------------------------------------------------------------------------
// Multi-part Encrypt/Decrypt FFI integration tests
// ----------------------------------------------------------------------------
//
// `C_EncryptInit` cannot be driven from native 64-bit tests (the mechanism
// parameter blocks embed WASM32 4-byte pointers), so these tests seed
// ENCRYPT_STATE / DECRYPT_STATE with an `EncryptCtx` directly — exactly
// what Init produces — and exercise the Update/Final entry points through
// real pointers: the §5.2 two-pass convention, CKR_BUFFER_TOO_SMALL,
// CKR_OPERATION_NOT_INITIALIZED, and a full GCM round-trip.
#[cfg(test)]
mod multipart_ffi_tests {
    use super::*;
    use crate::native::test_lock;

    // High fixed handles to avoid colliding with parallel native tests
    // that allocate via NEXT_HANDLE / NEXT_SESSION_HANDLE.
    const KEY_HANDLE: u32 = 0x4D50_0002;

    fn install_aes_key(key: &[u8]) {
        // §5.4 — the entry points are gated by `require_init!()`; flip the
        // lifecycle flag directly (tests hold `test_lock`, so this cannot
        // race the lifecycle dance of the `native::*` tests).
        crate::state::set_initialized(true);
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, key.to_vec());
            o.borrow_mut().insert(KEY_HANDLE, attrs);
        });
    }

    /// S4 — Update/Final now validate the session handle (§5.2 priority);
    /// register the test session so the seeded ctx is reachable.
    fn install_session(h: u32) {
        SESSIONS.with(|s| {
            s.borrow_mut()
                .insert(h, crate::state::SessionState { slot_id: 0, rw_session: true });
        });
    }

    fn seed_ctx(
        state: &GlobalState<HashMap<u32, EncryptCtx>>,
        session: u32,
        mech_type: u32,
        iv: Vec<u8>,
        aad: Vec<u8>,
        tag_bits: u32,
    ) {
        state.borrow_mut().insert(
            session,
            EncryptCtx { mech_type, key_handle: KEY_HANDLE, iv, aad, tag_bits, multipart: None, block_counter: 0 },
        );
    }

    /// Drive C_EncryptUpdate/C_EncryptFinal (or the Decrypt pair) over
    /// `parts`, using the NULL-output size query before every call.
    fn run_multipart(session: u32, encrypt: bool, parts: &[&[u8]]) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        for part in parts {
            let p_in = part.as_ptr() as *mut u8;
            let mut need: u32 = 0;
            let rv = if encrypt {
                C_EncryptUpdate(session, p_in, part.len() as u32, std::ptr::null_mut(), &mut need)
            } else {
                C_DecryptUpdate(session, p_in, part.len() as u32, std::ptr::null_mut(), &mut need)
            };
            if rv != CKR_OK {
                return Err(rv);
            }
            let mut buf = vec![0u8; need as usize];
            let mut len = need;
            let rv = if encrypt {
                C_EncryptUpdate(session, p_in, part.len() as u32, buf.as_mut_ptr(), &mut len)
            } else {
                C_DecryptUpdate(session, p_in, part.len() as u32, buf.as_mut_ptr(), &mut len)
            };
            if rv != CKR_OK {
                return Err(rv);
            }
            assert_eq!(len, need, "second-pass length must match the size query");
            out.extend_from_slice(&buf[..len as usize]);
        }
        let mut need: u32 = 0;
        let rv = if encrypt {
            C_EncryptFinal(session, std::ptr::null_mut(), &mut need)
        } else {
            C_DecryptFinal(session, std::ptr::null_mut(), &mut need)
        };
        if rv != CKR_OK {
            return Err(rv);
        }
        let mut buf = vec![0u8; need as usize];
        let mut len = need;
        let rv = if encrypt {
            C_EncryptFinal(session, buf.as_mut_ptr(), &mut len)
        } else {
            C_DecryptFinal(session, buf.as_mut_ptr(), &mut len)
        };
        if rv != CKR_OK {
            return Err(rv);
        }
        out.extend_from_slice(&buf[..len as usize]);
        Ok(out)
    }

    #[test]
    fn gcm_multipart_ffi_round_trip() {
        let _guard = test_lock::acquire();
        let session = 0x4D50_1001;
        install_aes_key(&[0x42u8; 32]);
        install_session(session);
        let iv = vec![0x24u8; 12];
        let aad = b"context".to_vec();
        let pt: Vec<u8> = (0..200u8).collect();

        seed_ctx(&ENCRYPT_STATE, session, CKM_AES_GCM, iv.clone(), aad.clone(), 128);
        let ct = run_multipart(session, true, &[&pt[..33], &pt[33..34], &pt[34..]]).unwrap();
        assert_eq!(ct.len(), pt.len() + 16); // ciphertext + 128-bit tag

        seed_ctx(&DECRYPT_STATE, session, CKM_AES_GCM, iv, aad, 128);
        // Split so the tag itself straddles two Update calls.
        let cut = ct.len() - 8;
        let round = run_multipart(session, false, &[&ct[..5], &ct[5..cut], &ct[cut..]]).unwrap();
        assert_eq!(round, pt);
    }

    #[test]
    fn cbc_pad_multipart_ffi_round_trip() {
        let _guard = test_lock::acquire();
        let session = 0x4D50_1002;
        install_aes_key(&[0x42u8; 32]);
        install_session(session);
        let iv = vec![0x07u8; 16];
        let pt = b"seventeen bytes!!".to_vec(); // 17 bytes — crosses a block

        seed_ctx(&ENCRYPT_STATE, session, CKM_AES_CBC_PAD, iv.clone(), Vec::new(), 0);
        let ct = run_multipart(session, true, &[&pt[..10], &pt[10..]]).unwrap();
        assert_eq!(ct.len(), 32); // 17 → two padded blocks

        seed_ctx(&DECRYPT_STATE, session, CKM_AES_CBC_PAD, iv, Vec::new(), 0);
        let round = run_multipart(session, false, &[&ct]).unwrap();
        assert_eq!(round, pt);
    }

    #[test]
    fn update_without_init_is_not_initialized() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true); // library up, but no EncryptInit
        let session = 0x4D50_1003;
        install_session(session);
        let mut need: u32 = 0;
        let part = [0u8; 4];
        assert_eq!(
            C_EncryptUpdate(session, part.as_ptr() as *mut u8, 4, std::ptr::null_mut(), &mut need),
            CKR_OPERATION_NOT_INITIALIZED,
        );
        assert_eq!(
            C_DecryptFinal(session, std::ptr::null_mut(), &mut need),
            CKR_OPERATION_NOT_INITIALIZED,
        );
        // §5.2 priority — an unknown session handle outranks the
        // operation-not-initialized error.
        assert_eq!(
            C_EncryptUpdate(0x4D50_1FFF, part.as_ptr() as *mut u8, 4, std::ptr::null_mut(), &mut need),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_DecryptFinal(0x4D50_1FFF, std::ptr::null_mut(), &mut need),
            CKR_SESSION_HANDLE_INVALID,
        );
    }

    #[test]
    fn update_short_buffer_keeps_operation_alive() {
        let _guard = test_lock::acquire();
        let session = 0x4D50_1004;
        install_aes_key(&[0x42u8; 16]);
        install_session(session);
        seed_ctx(&ENCRYPT_STATE, session, CKM_AES_GCM, vec![1u8; 12], Vec::new(), 128);

        let part = [0xABu8; 20];
        let mut len: u32 = 3; // deliberately too small
        let mut buf = [0u8; 3];
        assert_eq!(
            C_EncryptUpdate(session, part.as_ptr() as *mut u8, 20, buf.as_mut_ptr(), &mut len),
            CKR_BUFFER_TOO_SMALL,
        );
        assert_eq!(len, 20); // required size reported back
        // §5.2 — the operation must still be active after BUFFER_TOO_SMALL.
        let mut buf = vec![0u8; 20];
        let mut len = 20u32;
        assert_eq!(
            C_EncryptUpdate(session, part.as_ptr() as *mut u8, 20, buf.as_mut_ptr(), &mut len),
            CKR_OK,
        );
        ENCRYPT_STATE.borrow_mut().remove(&session); // cleanup
    }

    #[test]
    fn ecb_residue_final_terminates_with_data_len_range() {
        let _guard = test_lock::acquire();
        let session = 0x4D50_1005;
        install_aes_key(&[0x42u8; 16]);
        install_session(session);
        seed_ctx(&ENCRYPT_STATE, session, CKM_AES_ECB, Vec::new(), Vec::new(), 0);

        let part = [0u8; 5]; // not a block multiple
        let mut len = 0u32;
        assert_eq!(
            C_EncryptUpdate(session, part.as_ptr() as *mut u8, 5, std::ptr::null_mut(), &mut len),
            CKR_OK,
        );
        let mut buf = [0u8; 16];
        let mut len = 0u32;
        assert_eq!(
            C_EncryptUpdate(session, part.as_ptr() as *mut u8, 5, buf.as_mut_ptr(), &mut len),
            CKR_OK,
        );
        let mut len = 16u32;
        assert_eq!(C_EncryptFinal(session, buf.as_mut_ptr(), &mut len), CKR_DATA_LEN_RANGE);
        // Failed Final terminates the operation.
        assert!(!ENCRYPT_STATE.borrow().contains_key(&session));
    }
}

#[cfg(test)]
mod abi_hygiene_ffi_tests {
    //! S2 — ABI hygiene: pre-init surface, C_GetMechanismList gate,
    //! `nonnull!` sweep, and C_SessionCancel message-op flags.
    use super::*;
    use crate::native::test_lock;

    /// High fixed handles, disjoint from `multipart_ffi_tests` and the
    /// `native::*` allocators.
    const SESSION: u32 = 0x5332_1001;
    const KEY_HANDLE: u32 = 0x5332_0002;

    fn install_session(h: u32) {
        SESSIONS.with(|s| {
            s.borrow_mut()
                .insert(h, crate::state::SessionState { slot_id: 0, rw_session: true });
        });
    }

    fn install_aes_key(key: &[u8]) {
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, key.to_vec());
            o.borrow_mut().insert(KEY_HANDLE, attrs);
        });
    }

    /// §5.4 — C_GetInterfaceList / C_GetInterface are callable BEFORE
    /// C_Initialize. The init flag is process-global; `test_lock` serializes
    /// every test that touches it (the established crate pattern), so the
    /// flag is flipped off, exercised, and restored under the lock.
    #[test]
    fn interface_getters_callable_before_initialize() {
        let _guard = test_lock::acquire();
        let was = crate::state::is_initialized();
        crate::state::set_initialized(false);

        let mut count: u32 = 0;
        let rv = C_GetInterfaceList(std::ptr::null_mut(), &mut count);
        assert_ne!(rv, CKR_CRYPTOKI_NOT_INITIALIZED);
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, 1);

        let mut iface: u32 = 0;
        let rv = C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), &mut iface, 0);
        assert_ne!(rv, CKR_CRYPTOKI_NOT_INITIALIZED);
        assert_eq!(rv, CKR_OK);
        assert_ne!(iface, 0);

        // Counter-check: C_GetMechanismList IS gated (§5.4).
        let mut n: u32 = 0;
        assert_eq!(
            crate::constants::C_GetMechanismList(0, std::ptr::null_mut(), &mut n),
            CKR_CRYPTOKI_NOT_INITIALIZED,
        );

        crate::state::set_initialized(was);
    }

    /// C_GetMechanismList: NULL pulCount → CKR_ARGUMENTS_BAD; unknown slot →
    /// CKR_SLOT_ID_INVALID; valid slot size query → CKR_OK.
    #[test]
    fn get_mechanism_list_null_count_and_bad_slot() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        crate::state::init_token_store(); // slot 0

        assert_eq!(
            crate::constants::C_GetMechanismList(0, std::ptr::null_mut(), std::ptr::null_mut()),
            CKR_ARGUMENTS_BAD,
        );
        let mut n: u32 = 0;
        assert_eq!(
            crate::constants::C_GetMechanismList(0xDEAD, std::ptr::null_mut(), &mut n),
            CKR_SLOT_ID_INVALID,
        );
        assert_eq!(
            crate::constants::C_GetMechanismList(0, std::ptr::null_mut(), &mut n),
            CKR_OK,
        );
        assert_eq!(n as usize, crate::constants::SUPPORTED_MECHS.len());
    }

    #[test]
    fn find_objects_null_pointers() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        install_session(SESSION);
        let mut count: u32 = 0;
        let mut handle: u32 = 0;
        assert_eq!(
            C_FindObjects(SESSION, std::ptr::null_mut(), 8, &mut count),
            CKR_ARGUMENTS_BAD,
        );
        assert_eq!(
            C_FindObjects(SESSION, &mut handle, 1, std::ptr::null_mut()),
            CKR_ARGUMENTS_BAD,
        );
    }

    /// C_Encrypt / C_Decrypt: pData/pEncryptedData is the INPUT — NULL with a
    /// nonzero length is CKR_ARGUMENTS_BAD (the two-call NULL convention only
    /// applies to the output buffer).
    #[test]
    fn encrypt_decrypt_null_input_pointer() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        install_session(SESSION);
        install_aes_key(&[0x11u8; 32]);

        ENCRYPT_STATE.with(|s| {
            s.borrow_mut().insert(
                SESSION,
                EncryptCtx {
                    mech_type: CKM_AES_GCM,
                    key_handle: KEY_HANDLE,
                    iv: vec![0u8; 12],
                    aad: Vec::new(),
                    tag_bits: 128,
                    multipart: None,
                    block_counter: 0,
                },
            );
        });
        let mut out_len: u32 = 0;
        assert_eq!(
            C_Encrypt(SESSION, std::ptr::null_mut(), 16, std::ptr::null_mut(), &mut out_len),
            CKR_ARGUMENTS_BAD,
        );

        DECRYPT_STATE.with(|s| {
            s.borrow_mut().insert(
                SESSION,
                EncryptCtx {
                    mech_type: CKM_AES_GCM,
                    key_handle: KEY_HANDLE,
                    iv: vec![0u8; 12],
                    aad: Vec::new(),
                    tag_bits: 128,
                    multipart: None,
                    block_counter: 0,
                },
            );
        });
        let mut out_len: u32 = 0;
        assert_eq!(
            C_Decrypt(SESSION, std::ptr::null_mut(), 16, std::ptr::null_mut(), &mut out_len),
            CKR_ARGUMENTS_BAD,
        );
        DECRYPT_STATE.with(|s| s.borrow_mut().remove(&SESSION));
    }

    #[test]
    fn unwrap_key_null_pointers() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        install_session(SESSION);
        // CK_MECHANISM (wasm32 layout): mechanism, pParameter, ulParameterLen.
        let mech = [CKM_AES_KEY_WRAP, 0u32, 0u32];
        let p_mech = mech.as_ptr() as *mut u8;
        let mut wrapped = [0u8; 24];
        let mut h_key: u32 = 0;

        // NULL pMechanism
        assert_eq!(
            C_UnwrapKey(
                SESSION,
                std::ptr::null_mut(),
                KEY_HANDLE,
                wrapped.as_mut_ptr(),
                24,
                std::ptr::null_mut(),
                0,
                &mut h_key,
            ),
            CKR_ARGUMENTS_BAD,
        );
        // NULL pWrappedKey
        assert_eq!(
            C_UnwrapKey(
                SESSION,
                p_mech,
                KEY_HANDLE,
                std::ptr::null_mut(),
                24,
                std::ptr::null_mut(),
                0,
                &mut h_key,
            ),
            CKR_ARGUMENTS_BAD,
        );
        // NULL phKey
        assert_eq!(
            C_UnwrapKey(
                SESSION,
                p_mech,
                KEY_HANDLE,
                wrapped.as_mut_ptr(),
                24,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            ),
            CKR_ARGUMENTS_BAD,
        );
    }

    #[test]
    fn generate_key_null_mechanism() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        install_session(SESSION);
        let mut h_key: u32 = 0;
        assert_eq!(
            C_GenerateKey(
                SESSION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut h_key,
            ),
            CKR_ARGUMENTS_BAD,
        );
    }

    #[test]
    fn encapsulate_decapsulate_null_mechanism() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        install_session(SESSION);
        let mut ct_len: u32 = 0;
        let mut h_key: u32 = 0;
        let mut ct = [0u8; 4];
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                std::ptr::null_mut(),
                KEY_HANDLE,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut ct_len,
                &mut h_key,
            ),
            CKR_ARGUMENTS_BAD,
        );
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                std::ptr::null_mut(),
                KEY_HANDLE,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                4,
                &mut h_key,
            ),
            CKR_ARGUMENTS_BAD,
        );
    }

    /// C_SessionCancel CKF_MESSAGE_SIGN (0x8) / CKF_MESSAGE_VERIFY (0x10) —
    /// terminate the message-based ops so the *MessageNext entry points
    /// report CKR_OPERATION_NOT_INITIALIZED.
    #[test]
    fn session_cancel_message_sign_and_verify_flags() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        install_session(SESSION);

        // Seed an in-flight message-sign op (C_MessageSignInit state lives in
        // SIGN_STATE; the per-message accumulator in MESSAGE_SIGN_ACC).
        SIGN_STATE
            .with(|s| s.borrow_mut().insert(SESSION, (CKM_EDDSA, KEY_HANDLE, Vec::new(), false)));
        MESSAGE_SIGN_ACC.with(|s| s.borrow_mut().insert(SESSION, vec![1, 2, 3]));
        assert_eq!(C_SessionCancel(SESSION, 0x8), CKR_OK);
        assert!(!MESSAGE_SIGN_ACC.with(|s| s.borrow().contains_key(&SESSION)));
        let part = [0u8; 4];
        let mut sig_len: u32 = 0;
        assert_eq!(
            C_SignMessageNext(
                SESSION,
                std::ptr::null_mut(),
                0,
                part.as_ptr() as *mut u8,
                4,
                std::ptr::null_mut(),
                &mut sig_len,
            ),
            CKR_OPERATION_NOT_INITIALIZED,
        );

        // Same for the message-verify op.
        VERIFY_STATE
            .with(|s| s.borrow_mut().insert(SESSION, (CKM_EDDSA, KEY_HANDLE, Vec::new(), false)));
        MESSAGE_VERIFY_ACC.with(|s| s.borrow_mut().insert(SESSION, vec![4, 5]));
        assert_eq!(C_SessionCancel(SESSION, 0x10), CKR_OK);
        assert!(!MESSAGE_VERIFY_ACC.with(|s| s.borrow().contains_key(&SESSION)));
        let sig = [0u8; 64];
        assert_eq!(
            C_VerifyMessageNext(
                SESSION,
                std::ptr::null_mut(),
                0,
                part.as_ptr() as *mut u8,
                4,
                sig.as_ptr() as *mut u8,
                64,
            ),
            CKR_OPERATION_NOT_INITIALIZED,
        );
    }
}

#[cfg(test)]
mod attr_integrity_ffi_tests {
    //! S3 — object attribute integrity: honest provenance on import,
    //! CKA_SEED sensitive-class blocking, token-generated CKA_UNIQUE_ID,
    //! CKA_TRUSTED / CKA_WRAP_WITH_TRUSTED policy.
    use super::*;
    use crate::native::test_lock;

    /// High fixed session handle, disjoint from the other ffi test modules
    /// and the `native::*` allocators.
    const SESSION: u32 = 0x5333_1001;

    fn setup() {
        crate::state::set_initialized(true);
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                SESSION,
                crate::state::SessionState { slot_id: 0, rw_session: true },
            );
        });
    }

    /// Minimal valid C_CreateObject template for an AES secret key.
    fn aes_import_attrs() -> Attributes {
        let mut attrs = Attributes::new();
        store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
        attrs.insert(CKA_VALUE, vec![0x42u8; 16]);
        attrs
    }

    fn obj_attr(handle: u32, attr_type: u32) -> Option<Vec<u8>> {
        OBJECTS.with(|o| o.borrow().get(&handle).and_then(|a| a.get(&attr_type).cloned()))
    }

    fn obj_bool(handle: u32, attr_type: u32) -> Option<bool> {
        obj_attr(handle, attr_type).map(|v| !v.is_empty() && v[0] == 0x01)
    }

    /// PKCS#11 v3.2 — an RSA PRIVATE key object must expose CKA_MODULUS and
    /// CKA_PUBLIC_EXPONENT, not only the public key. Both are public values, so
    /// nothing is leaked by returning them.
    ///
    /// This is a CONSUMER contract, not a formality. pkcs11-provider's
    /// fetch_rsa_key() requests both with required=true and CKA_ID with
    /// required=false; a private key missing them made the required fetch fail
    /// and left CKA_ID unpopulated on the provider's cached object, which
    /// surfaced later as "No CKA_ID in source object" from
    /// p11prov_obj_find_associated(). Only RSA hits that path — EC and ML-DSA
    /// public keys are derivable from their private half — which is why the
    /// LAMPS composite id-MLDSA44-RSA2048-PSS-SHA256 failed while the
    /// ECDSA-P256 composite passed.
    #[test]
    fn rsa_private_key_exposes_modulus_and_public_exponent() {
        let _guard = test_lock::acquire();
        setup();

        let mut mech = [0usize; 3];
        mech[0] = CKM_RSA_PKCS_KEY_PAIR_GEN as usize;
        let mut h_pub: u32 = 0;
        let mut h_prv: u32 = 0;
        let bits: usize = 2048;
        let mut pub_tmpl = [0usize; 3];
        pub_tmpl[0] = CKA_MODULUS_BITS as usize;
        pub_tmpl[1] = (&bits as *const usize) as usize;
        pub_tmpl[2] = std::mem::size_of::<usize>();

        let rv = unsafe {
            C_GenerateKeyPair_impl(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                pub_tmpl.as_mut_ptr() as *mut u8,
                1,
                std::ptr::null_mut(),
                0,
                &mut h_pub,
                &mut h_prv,
            )
        };
        assert_eq!(rv, CKR_OK, "RSA-2048 keygen must succeed");

        let pub_n = obj_attr(h_pub, CKA_MODULUS).expect("public key must carry CKA_MODULUS");
        let pub_e =
            obj_attr(h_pub, CKA_PUBLIC_EXPONENT).expect("public key must carry CKA_PUBLIC_EXPONENT");

        // The regression: these were absent on the private key.
        let prv_n = obj_attr(h_prv, CKA_MODULUS).expect("PRIVATE key must carry CKA_MODULUS");
        let prv_e = obj_attr(h_prv, CKA_PUBLIC_EXPONENT)
            .expect("PRIVATE key must carry CKA_PUBLIC_EXPONENT");

        // Same key pair — the values must agree, not merely exist.
        assert_eq!(prv_n, pub_n, "private CKA_MODULUS must equal the public one");
        assert_eq!(
            prv_e, pub_e,
            "private CKA_PUBLIC_EXPONENT must equal the public one"
        );
        assert_eq!(prv_e, vec![0x01, 0x00, 0x01], "public exponent is 65537");
    }

    /// §4.9/§4.10 — a key imported via C_CreateObject with CKA_SENSITIVE=TRUE
    /// must still get CKA_ALWAYS_SENSITIVE=FALSE and CKA_NEVER_EXTRACTABLE=
    /// FALSE: it was born outside the token, so provenance cannot be claimed.
    #[test]
    fn create_object_import_stores_honest_provenance() {
        let _guard = test_lock::acquire();
        setup();
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_SENSITIVE, true);
        let h = create_object_from_attrs(SESSION, attrs).expect("import must succeed");

        assert_eq!(obj_bool(h, CKA_SENSITIVE), Some(true));
        assert_eq!(obj_bool(h, CKA_ALWAYS_SENSITIVE), Some(false));
        assert_eq!(obj_bool(h, CKA_NEVER_EXTRACTABLE), Some(false));
        assert_eq!(obj_bool(h, CKA_LOCAL), Some(false));
        let kgm = obj_attr(h, CKA_KEY_GEN_MECHANISM).expect("KEY_GEN_MECHANISM stored");
        assert_eq!(
            u32::from_le_bytes([kgm[0], kgm[1], kgm[2], kgm[3]]),
            CKM_UNAVAILABLE_INFORMATION
        );
    }

    /// §4.1.1 Table 12 — token-computed / SO-only attributes in a
    /// C_CreateObject template → CKR_ATTRIBUTE_READ_ONLY.
    #[test]
    fn create_object_rejects_read_only_template_attrs() {
        let _guard = test_lock::acquire();
        setup();
        for ro in [
            CKA_ALWAYS_SENSITIVE,
            CKA_NEVER_EXTRACTABLE,
            CKA_KEY_GEN_MECHANISM,
            CKA_UNIQUE_ID,
            CKA_TRUSTED,
        ] {
            let mut attrs = aes_import_attrs();
            attrs.insert(ro, vec![0x01]);
            assert_eq!(
                create_object_from_attrs(SESSION, attrs).unwrap_err(),
                CKR_ATTRIBUTE_READ_ONLY,
                "attr 0x{ro:x} must be rejected as read-only"
            );
        }
    }

    /// CKA_SEED readback on a sensitive secret key → CKR_ATTRIBUTE_SENSITIVE
    /// with ulValueLen = CK_UNAVAILABLE_INFORMATION (same gate as CKA_VALUE);
    /// readable on a non-sensitive extractable key.
    #[test]
    fn seed_readback_blocked_on_sensitive_key() {
        let _guard = test_lock::acquire();
        setup();
        // Sensitive key carrying a seed.
        let mut attrs = aes_import_attrs();
        attrs.insert(CKA_SEED, vec![0xAAu8; 32]);
        store_bool(&mut attrs, CKA_SENSITIVE, true);
        let h = create_object_from_attrs(SESSION, attrs).unwrap();

        // CK_ATTRIBUTE { type, pValue = NULL, ulValueLen } — size query form,
        // safe on 64-bit native (no embedded value pointers).
        let mut tmpl: [usize; 3] = [CKA_SEED as usize, 0, 0];
        let rv = C_GetAttributeValue(SESSION, h, tmpl.as_mut_ptr() as *mut u8, 1);
        assert_eq!(rv, CKR_ATTRIBUTE_SENSITIVE);
        assert_eq!(tmpl[2], usize::MAX, "ulValueLen = CK_UNAVAILABLE_INFORMATION");

        // Non-sensitive + extractable key: CKA_SEED length is readable.
        let mut attrs = aes_import_attrs();
        attrs.insert(CKA_SEED, vec![0xBBu8; 32]);
        store_bool(&mut attrs, CKA_SENSITIVE, false);
        store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        let h2 = create_object_from_attrs(SESSION, attrs).unwrap();
        let mut tmpl2: [usize; 3] = [CKA_SEED as usize, 0, 0];
        let rv = C_GetAttributeValue(SESSION, h2, tmpl2.as_mut_ptr() as *mut u8, 1);
        assert_eq!(rv, CKR_OK);
        assert_eq!(tmpl2[2], 32);
    }

    /// CKA_SEED (and the other server-managed / material attrs) must never be
    /// absorbed from generate/derive/unwrap templates. The skip predicate
    /// backs `absorb_template_attrs`, which cannot be called with value
    /// pointers from 64-bit native tests (32-bit CK_ATTRIBUTE ABI).
    #[test]
    fn generate_template_skip_list_covers_seed_and_server_managed() {
        for skipped in [
            CKA_VALUE,
            CKA_SEED,
            CKA_UNIQUE_ID,
            CKA_TRUSTED,
            CKA_ALWAYS_SENSITIVE,
            CKA_NEVER_EXTRACTABLE,
            CKA_KEY_GEN_MECHANISM,
            CKA_CHECK_VALUE,
            CKA_CLASS,
            CKA_KEY_TYPE,
            CKA_LOCAL,
            CKA_PRIV_PARAM_SET,
        ] {
            assert!(
                crate::crypto::handlers::template_attr_is_skipped(skipped),
                "0x{skipped:x} must be skipped by template absorption"
            );
        }
        // Client-settable attrs still flow through.
        for absorbable in [crate::native::keygen::CKA_LABEL, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_WRAP_WITH_TRUSTED] {
            assert!(
                !crate::crypto::handlers::template_attr_is_skipped(absorbable),
                "0x{absorbable:x} must remain client-settable"
            );
        }
    }

    /// §4.4.1 — every created object carries a token-generated CKA_UNIQUE_ID;
    /// two objects get distinct values.
    #[test]
    fn unique_id_assigned_and_distinct() {
        let _guard = test_lock::acquire();
        setup();
        let h1 = create_object_from_attrs(SESSION, aes_import_attrs()).unwrap();
        let h2 = create_object_from_attrs(SESSION, aes_import_attrs()).unwrap();
        let id1 = obj_attr(h1, CKA_UNIQUE_ID).expect("object 1 has CKA_UNIQUE_ID");
        let id2 = obj_attr(h2, CKA_UNIQUE_ID).expect("object 2 has CKA_UNIQUE_ID");
        assert_eq!(id1.len(), 36, "canonical 36-char UUID unique id");
        assert_eq!(id2.len(), 36, "canonical 36-char UUID unique id");
        assert_ne!(id1, id2, "unique ids must differ across objects");
    }

    /// §4.9/§4.10 wrap-with-trusted matrix:
    ///  (WWT=TRUE, wrapping key not trusted) → CKR_KEY_NOT_WRAPPABLE
    ///  (WWT=TRUE, wrapping key TRUSTED=TRUE) → CKR_OK
    ///  (WWT absent/FALSE)                    → CKR_OK
    #[test]
    fn wrap_with_trusted_policy_matrix() {
        let _guard = test_lock::acquire();
        setup();

        // Wrapping key: AES-128, CKA_WRAP=TRUE (CKA_TRUSTED defaults FALSE —
        // callers cannot set it; see create_object_rejects_read_only_template_attrs).
        let mut wrap_attrs = aes_import_attrs();
        store_bool(&mut wrap_attrs, CKA_WRAP, true);
        let h_wrap = create_object_from_attrs(SESSION, wrap_attrs).unwrap();

        // Target key: extractable, WRAP_WITH_TRUSTED=TRUE.
        let mut tgt_attrs = aes_import_attrs();
        store_bool(&mut tgt_attrs, CKA_EXTRACTABLE, true);
        store_bool(&mut tgt_attrs, CKA_WRAP_WITH_TRUSTED, true);
        let h_tgt = create_object_from_attrs(SESSION, tgt_attrs).unwrap();

        // CK_MECHANISM { CKM_AES_KEY_WRAP, NULL, 0 }; length-query call form.
        let mut mech: [usize; 3] = [CKM_AES_KEY_WRAP as usize, 0, 0];
        let mut wrapped_len: u32 = 0;

        // 1. WWT=TRUE, wrapping key lacks CKA_TRUSTED → CKR_KEY_NOT_WRAPPABLE.
        let rv = C_WrapKey(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            h_wrap,
            h_tgt,
            std::ptr::null_mut(),
            &mut wrapped_len,
        );
        assert_eq!(rv, CKR_KEY_NOT_WRAPPABLE);

        // 2. Mark the wrapping key trusted via internal store manipulation
        //    (the only way — CKA_TRUSTED is SO-only/read-only to callers).
        OBJECTS.with(|o| {
            let mut store = o.borrow_mut();
            let attrs = store.get_mut(&h_wrap).unwrap();
            store_bool(attrs, CKA_TRUSTED, true);
        });
        let rv = C_WrapKey(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            h_wrap,
            h_tgt,
            std::ptr::null_mut(),
            &mut wrapped_len,
        );
        assert_eq!(rv, CKR_OK);
        assert_eq!(wrapped_len, 24, "AES-KW of 16-byte key = 24 bytes");

        // 3. Target without WRAP_WITH_TRUSTED (defaults FALSE) wraps fine even
        //    under an untrusted wrapping key.
        let mut wrap2 = aes_import_attrs();
        store_bool(&mut wrap2, CKA_WRAP, true);
        let h_wrap2 = create_object_from_attrs(SESSION, wrap2).unwrap();
        let mut tgt2 = aes_import_attrs();
        store_bool(&mut tgt2, CKA_EXTRACTABLE, true);
        let h_tgt2 = create_object_from_attrs(SESSION, tgt2).unwrap();
        let mut wrapped_len2: u32 = 0;
        let rv = C_WrapKey(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            h_wrap2,
            h_tgt2,
            std::ptr::null_mut(),
            &mut wrapped_len2,
        );
        assert_eq!(rv, CKR_OK);
        assert_eq!(wrapped_len2, 24);
    }
}

#[cfg(test)]
mod object_mgmt_ffi_tests {
    //! T6 — object-management completeness: C_SetAttributeValue modifiability
    //! matrix (all-or-nothing), C_CopyObject copy semantics, C_GetObjectSize,
    //! C_SetPIN lifecycle, C_SeedRandom return code.
    use super::*;
    use crate::native::test_lock;

    /// High fixed session handles, disjoint from the other ffi test modules
    /// and the `native::*` allocators.
    const SESSION_RW: u32 = 0x5436_1001;
    const SESSION_RO: u32 = 0x5436_1002;
    const SESSION_SLOT9: u32 = 0x5436_1003;

    fn setup() {
        crate::state::set_initialized(true);
        crate::state::ensure_slot(0);
        SESSIONS.with(|s| {
            let mut store = s.borrow_mut();
            store.insert(
                SESSION_RW,
                crate::state::SessionState { slot_id: 0, rw_session: true },
            );
            store.insert(
                SESSION_RO,
                crate::state::SessionState { slot_id: 0, rw_session: false },
            );
        });
    }

    /// Minimal valid AES secret-key import template.
    fn aes_import_attrs() -> Attributes {
        let mut attrs = Attributes::new();
        store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
        attrs.insert(CKA_VALUE, vec![0x42u8; 16]);
        attrs
    }

    fn obj_attr(handle: u32, attr_type: u32) -> Option<Vec<u8>> {
        OBJECTS.with(|o| o.borrow().get(&handle).and_then(|a| a.get(&attr_type).cloned()))
    }

    fn obj_bool(handle: u32, attr_type: u32) -> Option<bool> {
        obj_attr(handle, attr_type).map(|v| !v.is_empty() && v[0] == 0x01)
    }

    // ── C_SetAttributeValue ──────────────────────────────────────────────

    /// §4.1.3 — client-modifiable attrs (label, id, usage flags) are settable.
    #[test]
    fn set_attr_modifiable_attrs_accepted() {
        let _guard = test_lock::acquire();
        setup();
        let h = create_object_from_attrs(SESSION_RW, aes_import_attrs()).unwrap();
        let updates: Vec<(u32, Vec<u8>)> = vec![
            (crate::native::keygen::CKA_LABEL, b"t6-label".to_vec()),
            (crate::native::keygen::CKA_ID, b"t6-id".to_vec()),
            (CKA_SIGN, vec![0x01]),
            (CKA_VERIFY, vec![0x01]),
            (CKA_ENCRYPT, vec![0x01]),
            (CKA_DECRYPT, vec![0x00]),
            (CKA_WRAP, vec![0x01]),
            (CKA_UNWRAP, vec![0x01]),
            (CKA_DERIVE, vec![0x01]),
            (CKA_ENCAPSULATE, vec![0x01]),
            (CKA_DECAPSULATE, vec![0x01]),
        ];
        assert_eq!(set_attribute_values_from_list(SESSION_RW, h, &updates), CKR_OK);
        assert_eq!(obj_attr(h, crate::native::keygen::CKA_LABEL).unwrap(), b"t6-label");
        assert_eq!(obj_attr(h, crate::native::keygen::CKA_ID).unwrap(), b"t6-id");
        assert_eq!(obj_bool(h, CKA_SIGN), Some(true));
        assert_eq!(obj_bool(h, CKA_DECRYPT), Some(false));
        assert_eq!(obj_bool(h, CKA_ENCAPSULATE), Some(true));
    }

    /// WP-6 remediation — §4.8 Table 13: `C_SetAttributeValue` must reject
    /// a malformed (non-multiple-of-4) `CKA_ALLOWED_MECHANISMS` value the
    /// same way `C_CreateObject`'s `validate_create_template` already
    /// does. Before this fix, the mutation path accepted any byte length
    /// and stored it verbatim, silently mis-parsed later by
    /// `check_mechanism_allowed`'s `chunks_exact(4)`.
    #[test]
    fn set_attr_allowed_mechanisms_rejects_malformed_length() {
        let _guard = test_lock::acquire();
        setup();
        let h = create_object_from_attrs(SESSION_RW, aes_import_attrs()).unwrap();
        // A length that is not a whole number of CK_MECHANISM_TYPE entries.
        // S9 (2026-08-13): the element width is the exported ABI's, so the
        // literal byte count here must be derived from it, not hardcoded to
        // the 4 this test previously assumed.
        let ragged = crate::state::MECHANISM_TYPE_SIZE + 3;
        let malformed: Vec<(u32, Vec<u8>)> = vec![(CKA_ALLOWED_MECHANISMS, vec![0u8; ragged])];
        assert_eq!(
            set_attribute_values_from_list(SESSION_RW, h, &malformed),
            CKR_ATTRIBUTE_VALUE_INVALID
        );
        assert!(
            obj_attr(h, CKA_ALLOWED_MECHANISMS).is_none(),
            "the malformed value must not have been stored"
        );

        // A well-formed value (one whole mechanism) is still accepted.
        let packed: Vec<u8> = (CKM_AES_GCM as usize).to_le_bytes().to_vec();
        let well_formed: Vec<(u32, Vec<u8>)> = vec![(CKA_ALLOWED_MECHANISMS, packed.clone())];
        assert_eq!(set_attribute_values_from_list(SESSION_RW, h, &well_formed), CKR_OK);
        assert_eq!(obj_attr(h, CKA_ALLOWED_MECHANISMS), Some(packed));
    }

    /// §4.1.3 read-only loop — every server-managed attr is refused with
    /// CKR_ATTRIBUTE_READ_ONLY and the object stays untouched.
    #[test]
    fn set_attr_read_only_matrix() {
        let _guard = test_lock::acquire();
        setup();
        let h = create_object_from_attrs(SESSION_RW, aes_import_attrs()).unwrap();
        let before = OBJECTS.with(|o| o.borrow().get(&h).cloned()).unwrap();
        for ro in [
            CKA_CLASS,
            CKA_KEY_TYPE,
            CKA_VALUE,
            CKA_UNIQUE_ID,
            CKA_LOCAL,
            CKA_KEY_GEN_MECHANISM,
            CKA_ALWAYS_SENSITIVE,
            CKA_NEVER_EXTRACTABLE,
            CKA_TRUSTED,
            CKA_SEED,
            CKA_PARAMETER_SET,
            CKA_CHECK_VALUE,
        ] {
            let updates = vec![(ro, vec![0x01, 0x02, 0x03, 0x04])];
            assert_eq!(
                set_attribute_values_from_list(SESSION_RW, h, &updates),
                CKR_ATTRIBUTE_READ_ONLY,
                "attr 0x{ro:x} must be read-only"
            );
        }
        let after = OBJECTS.with(|o| o.borrow().get(&h).cloned()).unwrap();
        assert_eq!(before, after, "rejected sets must not mutate the object");
    }

    /// §4.1.1 Table 12 one-way transitions: SENSITIVE FALSE→TRUE ok (history
    /// attrs untouched), TRUE→FALSE refused; EXTRACTABLE TRUE→FALSE ok,
    /// FALSE→TRUE refused.
    #[test]
    fn set_attr_one_way_transitions() {
        let _guard = test_lock::acquire();
        setup();
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_SENSITIVE, false);
        store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        let h = create_object_from_attrs(SESSION_RW, attrs).unwrap();

        // FALSE→TRUE: legal; ALWAYS_SENSITIVE (history) must NOT change.
        let rv = set_attribute_values_from_list(SESSION_RW, h, &[(CKA_SENSITIVE, vec![0x01])]);
        assert_eq!(rv, CKR_OK);
        assert_eq!(obj_bool(h, CKA_SENSITIVE), Some(true));
        assert_eq!(obj_bool(h, CKA_ALWAYS_SENSITIVE), Some(false), "history attr untouched");

        // TRUE→FALSE: refused.
        let rv = set_attribute_values_from_list(SESSION_RW, h, &[(CKA_SENSITIVE, vec![0x00])]);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY);
        assert_eq!(obj_bool(h, CKA_SENSITIVE), Some(true));

        // EXTRACTABLE TRUE→FALSE: legal; NEVER_EXTRACTABLE history untouched.
        let rv = set_attribute_values_from_list(SESSION_RW, h, &[(CKA_EXTRACTABLE, vec![0x00])]);
        assert_eq!(rv, CKR_OK);
        assert_eq!(obj_bool(h, CKA_EXTRACTABLE), Some(false));
        assert_eq!(obj_bool(h, CKA_NEVER_EXTRACTABLE), Some(false), "history attr untouched");

        // FALSE→TRUE: refused.
        let rv = set_attribute_values_from_list(SESSION_RW, h, &[(CKA_EXTRACTABLE, vec![0x01])]);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY);
        assert_eq!(obj_bool(h, CKA_EXTRACTABLE), Some(false));
    }

    /// §5.7.6 quality bar — a template mixing a valid set with an invalid one
    /// must leave the object completely unmodified (all-or-nothing).
    #[test]
    fn set_attr_all_or_nothing_on_mixed_template() {
        let _guard = test_lock::acquire();
        setup();
        let h = create_object_from_attrs(SESSION_RW, aes_import_attrs()).unwrap();
        let updates: Vec<(u32, Vec<u8>)> = vec![
            (crate::native::keygen::CKA_LABEL, b"should-not-stick".to_vec()),
            (CKA_CLASS, CKO_PUBLIC_KEY.to_le_bytes().to_vec()), // read-only
        ];
        assert_eq!(
            set_attribute_values_from_list(SESSION_RW, h, &updates),
            CKR_ATTRIBUTE_READ_ONLY
        );
        assert_eq!(
            obj_attr(h, crate::native::keygen::CKA_LABEL),
            None,
            "valid entry of a failed template must not be applied"
        );
    }

    /// §4.1.3 — CKA_MODIFIABLE=FALSE → CKR_ACTION_PROHIBITED.
    #[test]
    fn set_attr_unmodifiable_object_prohibited() {
        let _guard = test_lock::acquire();
        setup();
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_MODIFIABLE, false);
        let h = create_object_from_attrs(SESSION_RW, attrs).unwrap();
        let updates = vec![(crate::native::keygen::CKA_LABEL, b"x".to_vec())];
        assert_eq!(
            set_attribute_values_from_list(SESSION_RW, h, &updates),
            CKR_ACTION_PROHIBITED
        );
    }

    /// §5.6 — modifying a token object from a R/O session → CKR_SESSION_READ_ONLY;
    /// session objects stay modifiable from R/O sessions.
    #[test]
    fn set_attr_token_object_needs_rw_session() {
        let _guard = test_lock::acquire();
        setup();
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_TOKEN, true);
        let h_token = create_object_from_attrs(SESSION_RW, attrs).unwrap();
        let updates = vec![(crate::native::keygen::CKA_LABEL, b"x".to_vec())];
        assert_eq!(
            set_attribute_values_from_list(SESSION_RO, h_token, &updates),
            CKR_SESSION_READ_ONLY
        );
        // Session object: fine from the R/O session.
        let h_sess = create_object_from_attrs(SESSION_RO, aes_import_attrs()).unwrap();
        assert_eq!(set_attribute_values_from_list(SESSION_RO, h_sess, &updates), CKR_OK);
    }

    /// T3 — cross-slot handles are invalid for mutation too.
    #[test]
    fn set_attr_cross_slot_handle_invalid() {
        let _guard = test_lock::acquire();
        setup();
        crate::state::ensure_slot(9);
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                SESSION_SLOT9,
                crate::state::SessionState { slot_id: 9, rw_session: true },
            );
        });
        let h = create_object_from_attrs(SESSION_RW, aes_import_attrs()).unwrap();
        let updates = vec![(crate::native::keygen::CKA_LABEL, b"x".to_vec())];
        assert_eq!(
            set_attribute_values_from_list(SESSION_SLOT9, h, &updates),
            CKR_OBJECT_HANDLE_INVALID
        );
    }

    // ── C_CopyObject ─────────────────────────────────────────────────────

    /// Basic clone: same attributes, fresh handle, fresh CKA_UNIQUE_ID.
    #[test]
    fn copy_object_clones_with_fresh_identity() {
        let _guard = test_lock::acquire();
        setup();
        let mut attrs = aes_import_attrs();
        attrs.insert(crate::native::keygen::CKA_LABEL, b"orig".to_vec());
        let h_src = create_object_from_attrs(SESSION_RW, attrs).unwrap();
        let h_copy = copy_object_from_attrs(SESSION_RW, h_src, Attributes::new()).unwrap();
        assert_ne!(h_src, h_copy, "fresh handle");
        // Attribute equality, modulo the server-regenerated identity.
        assert_eq!(obj_attr(h_copy, CKA_VALUE), obj_attr(h_src, CKA_VALUE));
        assert_eq!(
            obj_attr(h_copy, crate::native::keygen::CKA_LABEL).unwrap(),
            b"orig"
        );
        let uid_src = obj_attr(h_src, CKA_UNIQUE_ID).unwrap();
        let uid_copy = obj_attr(h_copy, CKA_UNIQUE_ID).unwrap();
        assert_eq!(uid_copy.len(), 36, "canonical 36-char UUID unique id");
        assert_ne!(uid_src, uid_copy, "copy must not carry the source's CKA_UNIQUE_ID");
    }

    /// §4.1.2-3 — the copy template may strengthen security but never weaken
    /// it; history attrs carry over unchanged.
    #[test]
    fn copy_template_strengthen_ok_weaken_rejected() {
        let _guard = test_lock::acquire();
        setup();
        // Source: non-sensitive, extractable.
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_SENSITIVE, false);
        store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        let h_weak = create_object_from_attrs(SESSION_RW, attrs).unwrap();

        // Strengthening: SENSITIVE FALSE→TRUE allowed; history stays FALSE.
        let mut tmpl = Attributes::new();
        store_bool(&mut tmpl, CKA_SENSITIVE, true);
        let h_copy = copy_object_from_attrs(SESSION_RW, h_weak, tmpl).unwrap();
        assert_eq!(obj_bool(h_copy, CKA_SENSITIVE), Some(true));
        assert_eq!(
            obj_bool(h_copy, CKA_ALWAYS_SENSITIVE),
            Some(false),
            "copying cannot improve history"
        );

        // Weakening: source SENSITIVE=TRUE, template FALSE → refused.
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_SENSITIVE, true);
        store_bool(&mut attrs, CKA_EXTRACTABLE, false);
        let h_strong = create_object_from_attrs(SESSION_RW, attrs).unwrap();
        let mut tmpl = Attributes::new();
        store_bool(&mut tmpl, CKA_SENSITIVE, false);
        assert_eq!(
            copy_object_from_attrs(SESSION_RW, h_strong, tmpl).unwrap_err(),
            CKR_ATTRIBUTE_READ_ONLY
        );
        // Weakening: EXTRACTABLE FALSE→TRUE → refused.
        let mut tmpl = Attributes::new();
        store_bool(&mut tmpl, CKA_EXTRACTABLE, true);
        assert_eq!(
            copy_object_from_attrs(SESSION_RW, h_strong, tmpl).unwrap_err(),
            CKR_ATTRIBUTE_READ_ONLY
        );
        // Server-managed attrs equally refused in a copy template.
        let mut tmpl = Attributes::new();
        tmpl.insert(CKA_UNIQUE_ID, b"forged".to_vec());
        assert_eq!(
            copy_object_from_attrs(SESSION_RW, h_strong, tmpl).unwrap_err(),
            CKR_ATTRIBUTE_READ_ONLY
        );
    }

    /// §4.1.3 — CKA_COPYABLE=FALSE → CKR_ACTION_PROHIBITED.
    #[test]
    fn copy_uncopyable_object_prohibited() {
        let _guard = test_lock::acquire();
        setup();
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_COPYABLE, false);
        let h = create_object_from_attrs(SESSION_RW, attrs).unwrap();
        assert_eq!(
            copy_object_from_attrs(SESSION_RW, h, Attributes::new()).unwrap_err(),
            CKR_ACTION_PROHIBITED
        );
    }

    /// §5.7.2 — a R/O session cannot produce a token-object copy; flipping
    /// CKA_TOKEN to FALSE in the template makes the copy legal again.
    #[test]
    fn copy_token_object_needs_rw_session() {
        let _guard = test_lock::acquire();
        setup();
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_TOKEN, true);
        let h = create_object_from_attrs(SESSION_RW, attrs).unwrap();
        assert_eq!(
            copy_object_from_attrs(SESSION_RO, h, Attributes::new()).unwrap_err(),
            CKR_SESSION_READ_ONLY
        );
        let mut tmpl = Attributes::new();
        store_bool(&mut tmpl, CKA_TOKEN, false);
        let h_copy = copy_object_from_attrs(SESSION_RO, h, tmpl).unwrap();
        assert_eq!(obj_bool(h_copy, CKA_TOKEN), Some(false));
    }

    /// Test-only: flip slot 0's login state directly (no real SO PIN was
    /// ever set via C_InitToken in this module's `setup()`), mirroring
    /// `session_is_so`'s read of `TOKEN_STORE`.
    fn set_so_logged_in(so: bool) {
        crate::state::ensure_slot(0);
        crate::state::TOKEN_STORE.with(|ts| {
            if let Some(t) = ts.borrow_mut().get_mut(&0) {
                t.login_state = if so { crate::state::LoginState::SO } else { crate::state::LoginState::Public };
            }
        });
    }

    /// WP-5 remediation — §4.1.1 Table 12 / §4.6 Table 19 footnote:
    /// `C_CopyObject` must mirror `C_CreateObject`'s SO-only gate on
    /// `CKA_TRUSTED`, in both directions:
    /// - an SO session's EXPLICIT `CKA_TRUSTED=TRUE` in the copy template
    ///   must be honored (previously rejected for every session, SO
    ///   included);
    /// - a non-SO session's explicit `CKA_TRUSTED=TRUE` must still be
    ///   rejected (unchanged behavior, still correct);
    /// - omitting `CKA_TRUSTED` from the template must NOT silently carry
    ///   TRUE over from the source for a non-SO copy — it must be forced
    ///   to FALSE.
    #[test]
    fn copy_trusted_requires_so_both_explicit_and_inherited() {
        let _guard = test_lock::acquire();
        setup();
        set_so_logged_in(true);
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_TRUSTED, true);
        let h_trusted = create_object_from_attrs(SESSION_RW, attrs).unwrap();
        assert_eq!(obj_bool(h_trusted, CKA_TRUSTED), Some(true));

        // SO explicitly re-asserting CKA_TRUSTED=TRUE in the copy template
        // must succeed (was wrongly rejected for every session before).
        let mut tmpl = Attributes::new();
        store_bool(&mut tmpl, CKA_TRUSTED, true);
        let h_so_explicit = copy_object_from_attrs(SESSION_RW, h_trusted, tmpl).unwrap();
        assert_eq!(obj_bool(h_so_explicit, CKA_TRUSTED), Some(true));

        // SO omitting CKA_TRUSTED from the template: carries over as TRUE.
        let h_so_omitted = copy_object_from_attrs(SESSION_RW, h_trusted, Attributes::new()).unwrap();
        assert_eq!(obj_bool(h_so_omitted, CKA_TRUSTED), Some(true));

        set_so_logged_in(false);

        // Non-SO explicit CKA_TRUSTED=TRUE: still rejected.
        let mut tmpl = Attributes::new();
        store_bool(&mut tmpl, CKA_TRUSTED, true);
        assert_eq!(
            copy_object_from_attrs(SESSION_RW, h_trusted, tmpl).unwrap_err(),
            CKR_ATTRIBUTE_READ_ONLY
        );

        // Non-SO omitting CKA_TRUSTED: must NOT silently inherit TRUE —
        // this is the gap. Forced to FALSE instead.
        let h_non_so_omitted = copy_object_from_attrs(SESSION_RW, h_trusted, Attributes::new()).unwrap();
        assert_eq!(
            obj_bool(h_non_so_omitted, CKA_TRUSTED),
            Some(false),
            "non-SO copy must not silently inherit CKA_TRUSTED=TRUE from the source"
        );
    }

    /// WP-5 remediation — identity-field respoofing guard: a non-SO copy of
    /// a CKA_TRUSTED=TRUE object must not be able to rewrite identity
    /// attributes (CKA_ID here) in the same template, even though CKA_ID
    /// is ordinarily freely copy-mutable and CKA_TRUSTED itself is never
    /// touched by this template. An SO session doing the identical copy
    /// is unaffected.
    #[test]
    fn copy_trusted_source_blocks_identity_field_changes_for_non_so() {
        let _guard = test_lock::acquire();
        setup();
        set_so_logged_in(true);
        let mut attrs = aes_import_attrs();
        store_bool(&mut attrs, CKA_TRUSTED, true);
        let h_trusted = create_object_from_attrs(SESSION_RW, attrs).unwrap();

        set_so_logged_in(false);
        let mut tmpl = Attributes::new();
        tmpl.insert(crate::native::keygen::CKA_ID, b"respoofed-id".to_vec());
        assert_eq!(
            copy_object_from_attrs(SESSION_RW, h_trusted, tmpl).unwrap_err(),
            CKR_ATTRIBUTE_READ_ONLY,
            "non-SO must not be able to change CKA_ID on a copy of a trusted object"
        );

        set_so_logged_in(true);
        let mut tmpl = Attributes::new();
        tmpl.insert(crate::native::keygen::CKA_ID, b"so-relabel".to_vec());
        let h_relabeled = copy_object_from_attrs(SESSION_RW, h_trusted, tmpl).unwrap();
        assert_eq!(
            obj_attr(h_relabeled, crate::native::keygen::CKA_ID),
            Some(b"so-relabel".to_vec()),
            "SO may still relabel a trusted object's identity fields on copy"
        );
    }

    /// T3 — copying a foreign slot's object: handle invalid.
    #[test]
    fn copy_cross_slot_handle_invalid() {
        let _guard = test_lock::acquire();
        setup();
        crate::state::ensure_slot(9);
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                SESSION_SLOT9,
                crate::state::SessionState { slot_id: 9, rw_session: true },
            );
        });
        let h = create_object_from_attrs(SESSION_RW, aes_import_attrs()).unwrap();
        assert_eq!(
            copy_object_from_attrs(SESSION_SLOT9, h, Attributes::new()).unwrap_err(),
            CKR_OBJECT_HANDLE_INVALID
        );
    }

    // ── C_GetObjectSize ──────────────────────────────────────────────────

    /// Size is > 0 and grows with attribute payload (label added).
    #[test]
    fn get_object_size_sane_and_monotonic() {
        let _guard = test_lock::acquire();
        setup();
        let h = create_object_from_attrs(SESSION_RW, aes_import_attrs()).unwrap();
        let mut size1: u32 = 0;
        assert_eq!(C_GetObjectSize(SESSION_RW, h, &mut size1), CKR_OK);
        assert!(size1 > 0, "estimate must be non-zero");

        let updates = vec![(crate::native::keygen::CKA_LABEL, vec![b'L'; 100])];
        assert_eq!(set_attribute_values_from_list(SESSION_RW, h, &updates), CKR_OK);
        let mut size2: u32 = 0;
        assert_eq!(C_GetObjectSize(SESSION_RW, h, &mut size2), CKR_OK);
        assert!(
            size2 >= size1 + 100,
            "size must grow with the 100-byte label (was {size1}, now {size2})"
        );

        // Unknown handle → CKR_OBJECT_HANDLE_INVALID; NULL out-param → ARGUMENTS_BAD.
        let mut sz: u32 = 0;
        assert_eq!(C_GetObjectSize(SESSION_RW, 0xDEAD_BEEF, &mut sz), CKR_OBJECT_HANDLE_INVALID);
        assert_eq!(C_GetObjectSize(SESSION_RW, h, std::ptr::null_mut()), CKR_ARGUMENTS_BAD);
    }

    // ── C_SetPIN ─────────────────────────────────────────────────────────

    const PIN_SLOT: u32 = 0x77;
    const PIN_SESSION_RW: u32 = 0x5436_2001;
    const PIN_SESSION_RO: u32 = 0x5436_2002;

    fn pin_call(
        session: u32,
        old: &str,
        new: &str,
    ) -> u32 {
        let mut old_b = old.as_bytes().to_vec();
        let mut new_b = new.as_bytes().to_vec();
        C_SetPIN(
            session,
            old_b.as_mut_ptr(),
            old_b.len() as u32,
            new_b.as_mut_ptr(),
            new_b.len() as u32,
        )
    }

    fn login(session: u32, user_type: u32, pin: &str) -> u32 {
        let mut pin_b = pin.as_bytes().to_vec();
        C_Login(session, user_type, pin_b.as_mut_ptr(), pin_b.len() as u32)
    }

    /// Full lifecycle on a dedicated slot: init token → SO PIN rotate →
    /// InitPIN → user PIN rotate → old PINs refused → len-range → R/O
    /// session → uninitialized-user-PIN case.
    #[test]
    fn set_pin_lifecycle() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        crate::state::ensure_slot(PIN_SLOT);
        // Fresh token (C_InitToken refuses while sessions are open on the slot).
        SESSIONS.with(|s| {
            s.borrow_mut().retain(|_, ss| ss.slot_id != PIN_SLOT);
        });
        let mut so_pin = b"so-pin-77".to_vec();
        let mut label = b"t6-setpin".to_vec();
        label.resize(32, b' ');
        assert_eq!(
            C_InitToken(PIN_SLOT, so_pin.as_mut_ptr(), so_pin.len() as u32, label.as_mut_ptr()),
            CKR_OK
        );
        SESSIONS.with(|s| {
            let mut store = s.borrow_mut();
            store.insert(
                PIN_SESSION_RW,
                crate::state::SessionState { slot_id: PIN_SLOT, rw_session: true },
            );
            store.insert(
                PIN_SESSION_RO,
                crate::state::SessionState { slot_id: PIN_SLOT, rw_session: false },
            );
        });

        // Public session, user PIN never initialized → CKR_USER_PIN_NOT_INITIALIZED.
        assert_eq!(pin_call(PIN_SESSION_RW, "anything", "new-pin-1"), CKR_USER_PIN_NOT_INITIALIZED);

        // R/O session refused outright (checked before PIN verification).
        assert_eq!(pin_call(PIN_SESSION_RO, "so-pin-77", "so-pin-88"), CKR_SESSION_READ_ONLY);
        // Drop the R/O session so CKU_SO login is not blocked by
        // CKR_SESSION_READ_ONLY_EXISTS (§5.6 SO-login exclusivity).
        SESSIONS.with(|s| {
            s.borrow_mut().remove(&PIN_SESSION_RO);
        });

        // SO session: rotate the SO PIN.
        assert_eq!(login(PIN_SESSION_RW, CKU_SO, "so-pin-77"), CKR_OK);
        // Wrong old PIN.
        assert_eq!(pin_call(PIN_SESSION_RW, "wrong-old", "so-pin-88"), CKR_PIN_INCORRECT);
        // New PIN out of the advertised bounds.
        assert_eq!(pin_call(PIN_SESSION_RW, "so-pin-77", "ab"), CKR_PIN_LEN_RANGE);
        assert_eq!(
            pin_call(PIN_SESSION_RW, "so-pin-77", &"x".repeat(257)),
            CKR_PIN_LEN_RANGE
        );
        // Legal rotation.
        assert_eq!(pin_call(PIN_SESSION_RW, "so-pin-77", "so-pin-88"), CKR_OK);
        // Set the user PIN while SO, then verify rotation as the user.
        let mut user_pin = b"user-pin-1".to_vec();
        assert_eq!(
            C_InitPIN(PIN_SESSION_RW, user_pin.as_mut_ptr(), user_pin.len() as u32),
            CKR_OK
        );
        assert_eq!(C_Logout(PIN_SESSION_RW), CKR_OK);
        // Old SO PIN no longer works; the new one does.
        assert_eq!(login(PIN_SESSION_RW, CKU_SO, "so-pin-77"), CKR_PIN_INCORRECT);
        assert_eq!(login(PIN_SESSION_RW, CKU_SO, "so-pin-88"), CKR_OK);
        assert_eq!(C_Logout(PIN_SESSION_RW), CKR_OK);

        // User session: rotate the user PIN.
        assert_eq!(login(PIN_SESSION_RW, CKU_USER, "user-pin-1"), CKR_OK);
        assert_eq!(pin_call(PIN_SESSION_RW, "user-pin-1", "user-pin-2"), CKR_OK);
        assert_eq!(C_Logout(PIN_SESSION_RW), CKR_OK);
        assert_eq!(login(PIN_SESSION_RW, CKU_USER, "user-pin-1"), CKR_PIN_INCORRECT);
        assert_eq!(login(PIN_SESSION_RW, CKU_USER, "user-pin-2"), CKR_OK);
        assert_eq!(C_Logout(PIN_SESSION_RW), CKR_OK);

        // §5.6.7 table — a PUBLIC R/W session also changes the user PIN.
        assert_eq!(pin_call(PIN_SESSION_RW, "user-pin-2", "user-pin-3"), CKR_OK);
        assert_eq!(login(PIN_SESSION_RW, CKU_USER, "user-pin-3"), CKR_OK);
        assert_eq!(C_Logout(PIN_SESSION_RW), CKR_OK);

        // NULL PINs → CKR_ARGUMENTS_BAD; unknown session → handle invalid.
        assert_eq!(
            C_SetPIN(PIN_SESSION_RW, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0),
            CKR_ARGUMENTS_BAD
        );
        assert_eq!(pin_call(0xBAD_5E55, "user-pin-3", "user-pin-4"), CKR_SESSION_HANDLE_INVALID);
    }

    /// T6 — C_InitPIN enforces the same advertised bounds.
    #[test]
    fn init_pin_len_range() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        crate::state::ensure_slot(PIN_SLOT);
        let mut short = b"ab".to_vec();
        // Bounds are checked before session/login state, so a R/W session
        // suffices to observe the code.
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                PIN_SESSION_RW,
                crate::state::SessionState { slot_id: PIN_SLOT, rw_session: true },
            );
        });
        assert_eq!(
            C_InitPIN(PIN_SESSION_RW, short.as_mut_ptr(), short.len() as u32),
            CKR_PIN_LEN_RANGE
        );
    }

    // ── C_SeedRandom ─────────────────────────────────────────────────────

    /// §5.14 — external seeding unsupported → CKR_RANDOM_SEED_NOT_SUPPORTED.
    #[test]
    fn seed_random_returns_seed_not_supported() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        let mut seed = [0u8; 16];
        assert_eq!(
            C_SeedRandom(SESSION_RW, seed.as_mut_ptr(), 16),
            CKR_RANDOM_SEED_NOT_SUPPORTED
        );
    }
}

#[cfg(test)]
mod return_code_ffi_tests {
    //! S4 — return-code precision: wrap-family handle codes, AES-KW unwrap
    //! codes, operate-stage session validation, digest one-shot-after-update,
    //! and the minor template/ciphertext code fixes.
    use super::*;
    use crate::native::test_lock;

    /// High fixed handles, disjoint from the other ffi test modules and the
    /// `native::*` allocators.
    const SESSION: u32 = 0x5334_1001;
    /// Session bound to a slot with no token state — `session_logged_in` is
    /// false, so CKA_PRIVATE objects are invisible (§4.4 login gate).
    const LOGGED_OUT_SESSION: u32 = 0x5334_1002;
    const BOGUS_SESSION: u32 = 0x5334_1FFF;
    const NO_SUCH_KEY: u32 = 0x5334_2FFF;

    fn setup() {
        crate::state::set_initialized(true);
        SESSIONS.with(|s| {
            let mut m = s.borrow_mut();
            m.insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true });
            m.insert(
                LOGGED_OUT_SESSION,
                crate::state::SessionState { slot_id: 77, rw_session: true },
            );
        });
        // Slot 0 token must not be logged in for the login-gate tests.
        TOKEN_STORE.with(|ts| ts.borrow_mut().remove(&77));
    }

    /// Install an AES secret key directly in the object store.
    fn install_key(handle: u32, len: usize, flags: &[(u32, bool)]) {
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, vec![0x42u8; len]);
            store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
            for &(attr, v) in flags {
                store_bool(&mut attrs, attr, v);
            }
            o.borrow_mut().insert(handle, attrs);
        });
    }

    fn kw_mech() -> [usize; 3] {
        [CKM_AES_KEY_WRAP as usize, 0, 0]
    }

    fn wrap(session: u32, h_wrap: u32, h_key: u32, out: &mut [u8], out_len: &mut u32) -> u32 {
        let mut mech = kw_mech();
        C_WrapKey(
            session,
            mech.as_mut_ptr() as *mut u8,
            h_wrap,
            h_key,
            if out.is_empty() { std::ptr::null_mut() } else { out.as_mut_ptr() },
            out_len,
        )
    }

    fn unwrap_key(session: u32, h_unwrap: u32, wrapped: &mut [u8]) -> (u32, u32) {
        let mut mech = kw_mech();
        let mut h_new: u32 = 0;
        let rv = C_UnwrapKey(
            session,
            mech.as_mut_ptr() as *mut u8,
            h_unwrap,
            wrapped.as_mut_ptr(),
            wrapped.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut h_new,
        );
        (rv, h_new)
    }

    // ── Wrap-family handle codes ────────────────────────────────────────────

    /// §5.18.2 — missing wrapping key → CKR_WRAPPING_KEY_HANDLE_INVALID, not
    /// CKR_KEY_FUNCTION_NOT_PERMITTED.
    #[test]
    fn wrap_missing_wrapping_key_handle_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let h_tgt = 0x5334_0010;
        install_key(h_tgt, 16, &[(CKA_EXTRACTABLE, true)]);
        let mut len: u32 = 0;
        assert_eq!(
            wrap(SESSION, NO_SUCH_KEY, h_tgt, &mut [], &mut len),
            CKR_WRAPPING_KEY_HANDLE_INVALID,
        );
    }

    /// §5.18.2 — wrapping key exists but CKA_WRAP=FALSE →
    /// CKR_KEY_FUNCTION_NOT_PERMITTED (checked AFTER handle validity).
    #[test]
    fn wrap_not_permitted_when_cka_wrap_false() {
        let _guard = test_lock::acquire();
        setup();
        let (h_wrap, h_tgt) = (0x5334_0011, 0x5334_0012);
        install_key(h_wrap, 16, &[(CKA_WRAP, false)]);
        install_key(h_tgt, 16, &[(CKA_EXTRACTABLE, true)]);
        let mut len: u32 = 0;
        assert_eq!(
            wrap(SESSION, h_wrap, h_tgt, &mut [], &mut len),
            CKR_KEY_FUNCTION_NOT_PERMITTED,
        );
    }

    /// §5.18.2 — missing target key → CKR_KEY_HANDLE_INVALID, not
    /// CKR_KEY_UNEXTRACTABLE.
    #[test]
    fn wrap_missing_target_key_handle_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let h_wrap = 0x5334_0013;
        install_key(h_wrap, 16, &[(CKA_WRAP, true)]);
        let mut len: u32 = 0;
        assert_eq!(
            wrap(SESSION, h_wrap, NO_SUCH_KEY, &mut [], &mut len),
            CKR_KEY_HANDLE_INVALID,
        );
    }

    /// §5.18.2 — target EXISTS but CKA_EXTRACTABLE=FALSE →
    /// CKR_KEY_UNEXTRACTABLE.
    #[test]
    fn wrap_unextractable_target() {
        let _guard = test_lock::acquire();
        setup();
        let (h_wrap, h_tgt) = (0x5334_0014, 0x5334_0015);
        install_key(h_wrap, 16, &[(CKA_WRAP, true)]);
        install_key(h_tgt, 16, &[(CKA_EXTRACTABLE, false)]);
        let mut len: u32 = 0;
        assert_eq!(
            wrap(SESSION, h_wrap, h_tgt, &mut [], &mut len),
            CKR_KEY_UNEXTRACTABLE,
        );
    }

    /// §4.4 login gate — a CKA_PRIVATE wrapping key is invisible to a
    /// logged-out session: CKR_WRAPPING_KEY_HANDLE_INVALID (handle class),
    /// never CKR_KEY_FUNCTION_NOT_PERMITTED (which would leak existence).
    #[test]
    fn wrap_private_wrapping_key_logged_out() {
        let _guard = test_lock::acquire();
        setup();
        let (h_wrap, h_tgt) = (0x5334_0016, 0x5334_0017);
        install_key(h_wrap, 16, &[(CKA_WRAP, true), (CKA_PRIVATE, true)]);
        install_key(h_tgt, 16, &[(CKA_EXTRACTABLE, true)]);
        let mut len: u32 = 0;
        assert_eq!(
            wrap(LOGGED_OUT_SESSION, h_wrap, h_tgt, &mut [], &mut len),
            CKR_WRAPPING_KEY_HANDLE_INVALID,
        );
    }

    /// §5.18.4 — missing unwrapping key → CKR_UNWRAPPING_KEY_HANDLE_INVALID.
    #[test]
    fn unwrap_missing_unwrapping_key_handle_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let mut wrapped = [0u8; 24];
        let (rv, _) = unwrap_key(SESSION, NO_SUCH_KEY, &mut wrapped);
        assert_eq!(rv, CKR_UNWRAPPING_KEY_HANDLE_INVALID);
    }

    /// §5.18.5 — missing base key in C_DeriveKey → CKR_KEY_HANDLE_INVALID,
    /// not CKR_KEY_FUNCTION_NOT_PERMITTED.
    #[test]
    fn derive_missing_base_key_handle_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let mut mech: [usize; 3] = [CKM_BIP32_MASTER_DERIVE as usize, 0, 0];
        let mut h_new: u32 = 0;
        assert_eq!(
            C_DeriveKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                NO_SUCH_KEY,
                std::ptr::null_mut(),
                0,
                &mut h_new,
            ),
            CKR_KEY_HANDLE_INVALID,
        );
    }

    /// PKCS#11 v3.2 §6.43.3 — CKM_CONCATENATE_BASE_AND_KEY over the FFI ABI:
    /// pParameter is a CK_OBJECT_HANDLE (the second key); the derived value is
    /// base.CKA_VALUE ‖ second.CKA_VALUE. Proves the FFI marshalling + the new
    /// dispatch arm + the unified secret-key finalization all cooperate — the
    /// PKCS#11-conformance counterpart to the native::concatenate_keys tests.
    #[test]
    fn concatenate_base_and_key_ffi_produces_summed_length() {
        let _guard = test_lock::acquire();
        setup();
        let (h_base, h_second) = (0x5334_0031, 0x5334_0032);
        // Both keys must permit derivation (base: generic §5.18.5 gate;
        // second: the new arm's own check).
        install_key(h_base, 4, &[(CKA_DERIVE, true)]);
        install_key(h_second, 8, &[(CKA_DERIVE, true)]);
        let second_word: usize = h_second as usize;
        let mut mech: [usize; 3] = [
            CKM_CONCATENATE_BASE_AND_KEY as usize,
            &second_word as *const usize as usize,
            std::mem::size_of::<usize>(),
        ];
        let mut h_new: u32 = 0;
        let rv = unsafe {
            C_DeriveKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                h_base,
                std::ptr::null_mut(),
                0,
                &mut h_new,
            )
        };
        assert_eq!(rv, CKR_OK);
        let out = get_object_value(h_new).expect("derived key has a value");
        assert_eq!(out.len(), 12, "4 (base) + 8 (second) = 12 bytes");
    }

    /// HKDF salt-as-key (CKF_HKDF_SALT_KEY): the salt must be sourced from the
    /// salt key's CKA_VALUE. Proven by equivalence — HKDF with salt supplied
    /// as raw DATA `S` and HKDF with salt supplied as a KEY whose CKA_VALUE is
    /// `S` must produce byte-identical output. That's the keyed dual-PRF
    /// combiner form, HMAC(salt_key.value, ikm).
    #[test]
    fn hkdf_salt_as_key_equals_salt_as_data() {
        let _guard = test_lock::acquire();
        setup();
        let (h_ikm, h_salt) = (0x5334_0051, 0x5334_0052);
        // Base (IKM) and a salt key whose value is a known salt string.
        let salt_bytes: [u8; 8] = [0x53, 0x41, 0x4c, 0x54, 0x30, 0x31, 0x32, 0x33];
        for (h, val) in [(h_ikm, &b"input-keying-material"[..]), (h_salt, &salt_bytes[..])] {
            OBJECTS.with(|o| {
                let mut attrs = Attributes::new();
                attrs.insert(CKA_VALUE, val.to_vec());
                store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_bool(&mut attrs, CKA_DERIVE, true);
                o.borrow_mut().insert(h, attrs);
            });
        }
        // CK_HKDF_PARAMS = [flags(expand@bit8), prf, saltType, pSalt,
        // ulSaltLen, hSaltKey, pInfo, ulInfoLen]. b_expand=1, SHA-256, no info.
        let derive = |salt_type: u32, p_salt: usize, salt_len: usize, h_salt_key: usize| -> Vec<u8> {
            let params: [usize; 8] = [
                0x100,
                CKM_SHA256 as usize,
                salt_type as usize,
                p_salt,
                salt_len,
                h_salt_key,
                0,
                0,
            ];
            let mut mech: [usize; 3] = [
                CKM_HKDF_DERIVE as usize,
                params.as_ptr() as usize,
                std::mem::size_of::<[usize; 8]>(),
            ];
            let mut h_new: u32 = 0;
            let rv = unsafe {
                C_DeriveKey(
                    SESSION,
                    mech.as_mut_ptr() as *mut u8,
                    h_ikm,
                    std::ptr::null_mut(),
                    0,
                    &mut h_new,
                )
            };
            assert_eq!(rv, CKR_OK);
            get_object_value(h_new).unwrap()
        };
        let via_data = derive(
            CKF_HKDF_SALT_DATA,
            salt_bytes.as_ptr() as usize,
            salt_bytes.len(),
            0,
        );
        let via_key = derive(CKF_HKDF_SALT_KEY, 0, 0, h_salt as usize);
        assert_eq!(via_key, via_data, "salt-as-key must key HMAC on the salt key's CKA_VALUE");
        assert_eq!(via_key.len(), 32);
    }

    /// Digest key derivation over the FFI ABI (§6.22): derived value =
    /// SHA-256(base.CKA_VALUE). Base value "abc" → the canonical SHA-256 KAT.
    #[test]
    fn sha256_key_derivation_ffi_matches_known_answer() {
        let _guard = test_lock::acquire();
        setup();
        let h_base = 0x5334_0041;
        // install a key whose value is exactly b"abc".
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, b"abc".to_vec());
            store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
            store_bool(&mut attrs, CKA_DERIVE, true);
            o.borrow_mut().insert(h_base, attrs);
        });
        let mut mech: [usize; 3] = [CKM_SHA256_KEY_DERIVATION as usize, 0, 0];
        let mut h_new: u32 = 0;
        let rv = unsafe {
            C_DeriveKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                h_base,
                std::ptr::null_mut(),
                0,
                &mut h_new,
            )
        };
        assert_eq!(rv, CKR_OK);
        let expect: Vec<u8> = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        [i * 2..i * 2 + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(get_object_value(h_new).unwrap(), expect);
    }

    /// The second key must carry CKA_DERIVE — else CKR_KEY_FUNCTION_NOT_PERMITTED
    /// (the arm gates the appended key, not just the base).
    #[test]
    fn concatenate_base_and_key_ffi_rejects_non_derivable_second() {
        let _guard = test_lock::acquire();
        setup();
        let (h_base, h_second) = (0x5334_0033, 0x5334_0034);
        install_key(h_base, 4, &[(CKA_DERIVE, true)]);
        install_key(h_second, 8, &[(CKA_DERIVE, false)]);
        let second_word: usize = h_second as usize;
        let mut mech: [usize; 3] = [
            CKM_CONCATENATE_BASE_AND_KEY as usize,
            &second_word as *const usize as usize,
            std::mem::size_of::<usize>(),
        ];
        let mut h_new: u32 = 0;
        let rv = unsafe {
            C_DeriveKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                h_base,
                std::ptr::null_mut(),
                0,
                &mut h_new,
            )
        };
        assert_eq!(rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
    }

    /// F1 — the legacy bare BIP32 codepoints (0x105B/0x105C) must still be
    /// ACCEPTED at C_DeriveKey dispatch as deprecated aliases: with a valid
    /// base key and an empty template they must reach the BIP32 arm (which
    /// rejects the missing CKA_EC_PARAMS with CKR_TEMPLATE_INCONSISTENT)
    /// rather than fall through to CKR_MECHANISM_INVALID.
    #[test]
    fn bip32_legacy_codepoints_accepted_at_dispatch() {
        let _guard = test_lock::acquire();
        setup();
        const H_SEED: u32 = 0x5334_3001;
        install_key(H_SEED, 32, &[(CKA_DERIVE, true)]);
        for legacy in [
            CKM_BIP32_MASTER_DERIVE_LEGACY,
            CKM_BIP32_CHILD_DERIVE_LEGACY,
            CKM_BIP32_MASTER_DERIVE,
            CKM_BIP32_CHILD_DERIVE,
        ] {
            let mut mech: [usize; 3] = [legacy as usize, 0, 0];
            let mut h_new: u32 = 0;
            assert_eq!(
                C_DeriveKey(
                    SESSION,
                    mech.as_mut_ptr() as *mut u8,
                    H_SEED,
                    std::ptr::null_mut(),
                    0,
                    &mut h_new,
                ),
                CKR_TEMPLATE_INCONSISTENT,
                "mech {legacy:#010x} did not reach the BIP32 dispatch arm"
            );
        }
    }

    // ── SP 800-108 KBKDF PRF policy (§6.26) ─────────────────────────────────

    /// PKCS#11 v3.2 §6.26 — the SP 800-108 PRF must be a keyed-MAC
    /// mechanism. Bare hashes (CKM_SHA256 etc.) and unknown mechanisms must
    /// fail CKR_MECHANISM_PARAM_INVALID in BOTH counter and feedback modes
    /// (regression: they used to silently default to HMAC-SHA256).
    #[test]
    fn sp800_108_bare_hash_prf_rejected() {
        let key = [0x42u8; 32];
        for prf in [
            CKM_SHA256,
            CKM_SHA384,
            CKM_SHA512,
            CKM_SHA3_256,
            CKM_SHA3_512,
            0xdead_beef,
        ] {
            assert_eq!(
                sp800_108_counter_kbkdf(prf, &key, &[], 32),
                Err(CKR_MECHANISM_PARAM_INVALID),
                "counter KBKDF accepted non-keyed-MAC PRF {prf:#x}"
            );
            assert_eq!(
                sp800_108_feedback_kbkdf(prf, &key, &[], &[], 32),
                Err(CKR_MECHANISM_PARAM_INVALID),
                "feedback KBKDF accepted non-keyed-MAC PRF {prf:#x}"
            );
        }
    }

    /// CKM_SHA384_HMAC PRF output matches an independently built
    /// counter-mode reference (legacy default fixed input: 32-bit BE
    /// counter prefix, nothing else), and differs from the HMAC-SHA256
    /// output for identical inputs — pinning that the digest is actually
    /// switched rather than silently defaulted.
    #[test]
    fn sp800_108_sha384_hmac_matches_reference() {
        use hmac::{Hmac, Mac};
        let key = [0x42u8; 32];
        let derived = sp800_108_counter_kbkdf(CKM_SHA384_HMAC, &key, &[], 32).unwrap();
        let mut reference = Vec::new();
        let mut i: u32 = 1;
        while reference.len() < 32 {
            let mut mac = <Hmac<sha2::Sha384> as Mac>::new_from_slice(&key).unwrap();
            mac.update(&i.to_be_bytes());
            reference.extend_from_slice(&mac.finalize().into_bytes());
            i += 1;
        }
        reference.truncate(32);
        assert_eq!(derived, reference);

        let derived_256 = sp800_108_counter_kbkdf(CKM_SHA256_HMAC, &key, &[], 32).unwrap();
        assert_ne!(derived, derived_256, "SHA-384 PRF produced the SHA-256 KO");
    }

    // ── AES-KW unwrap codes ─────────────────────────────────────────────────

    /// RFC 3394 integrity-check failure → CKR_WRAPPED_KEY_INVALID (was
    /// CKR_FUNCTION_FAILED); valid round-trip still succeeds.
    #[test]
    fn aes_kw_tampered_wrapped_key_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let (h_kek, h_tgt) = (0x5334_0020, 0x5334_0021);
        install_key(h_kek, 16, &[(CKA_WRAP, true), (CKA_UNWRAP, true)]);
        install_key(h_tgt, 16, &[(CKA_EXTRACTABLE, true)]);

        let mut wrapped = [0u8; 24];
        let mut len = wrapped.len() as u32;
        assert_eq!(wrap(SESSION, h_kek, h_tgt, &mut wrapped, &mut len), CKR_OK);
        assert_eq!(len, 24);

        // Untampered control: unwrap succeeds.
        let (rv, h_new) = unwrap_key(SESSION, h_kek, &mut wrapped.clone());
        assert_eq!(rv, CKR_OK);
        assert_ne!(h_new, 0);

        // Tamper one ciphertext byte → RFC 3394 IV check fails.
        wrapped[5] ^= 0xFF;
        let (rv, _) = unwrap_key(SESSION, h_kek, &mut wrapped);
        assert_eq!(rv, CKR_WRAPPED_KEY_INVALID);
    }

    /// §5.18.4 — wrapped data too short (< 24) or not a semiblock multiple →
    /// CKR_WRAPPED_KEY_LEN_RANGE (was CKR_ARGUMENTS_BAD).
    #[test]
    fn aes_kw_bad_length_wrapped_key_len_range() {
        let _guard = test_lock::acquire();
        setup();
        let h_kek = 0x5334_0022;
        install_key(h_kek, 16, &[(CKA_UNWRAP, true)]);

        let mut short = [0u8; 16]; // < 3 semiblocks
        let (rv, _) = unwrap_key(SESSION, h_kek, &mut short);
        assert_eq!(rv, CKR_WRAPPED_KEY_LEN_RANGE);

        let mut ragged = [0u8; 27]; // not a multiple of 8
        let (rv, _) = unwrap_key(SESSION, h_kek, &mut ragged);
        assert_eq!(rv, CKR_WRAPPED_KEY_LEN_RANGE);
    }

    // ── Operate-stage session validation (§5.2 priority) ────────────────────

    /// A bogus session handle on the operate-stage calls →
    /// CKR_SESSION_HANDLE_INVALID, ranked above
    /// CKR_OPERATION_NOT_INITIALIZED.
    #[test]
    fn operate_stage_bogus_session_handle_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        let data = [0u8; 4];

        assert_eq!(
            C_Sign(BOGUS_SESSION, data.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), &mut len),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_Verify(BOGUS_SESSION, data.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), 64),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_Encrypt(BOGUS_SESSION, data.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), &mut len),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_Decrypt(BOGUS_SESSION, data.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), &mut len),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_Digest(BOGUS_SESSION, data.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), &mut len),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_DigestUpdate(BOGUS_SESSION, data.as_ptr() as *mut u8, 4),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_DigestFinal(BOGUS_SESSION, buf.as_mut_ptr(), &mut len),
            CKR_SESSION_HANDLE_INVALID,
        );
        let mut h: u32 = 0;
        let mut n: u32 = 0;
        assert_eq!(
            C_FindObjects(BOGUS_SESSION, &mut h, 1, &mut n),
            CKR_SESSION_HANDLE_INVALID,
        );
    }

    // ── Digest one-shot after Update (§5.13) ────────────────────────────────

    /// C_Digest while the op is in its multi-part phase →
    /// CKR_OPERATION_ACTIVE; the multi-part op stays alive and completes.
    #[test]
    fn digest_one_shot_after_update_operation_active() {
        let _guard = test_lock::acquire();
        setup();
        let mut mech: [usize; 3] = [CKM_SHA256 as usize, 0, 0];
        assert_eq!(C_DigestInit(SESSION, mech.as_mut_ptr() as *mut u8), CKR_OK);
        let data = b"part one";
        assert_eq!(
            C_DigestUpdate(SESSION, data.as_ptr() as *mut u8, data.len() as u32),
            CKR_OK,
        );

        let mut out = [0u8; 32];
        let mut out_len: u32 = 32;
        assert_eq!(
            C_Digest(SESSION, data.as_ptr() as *mut u8, data.len() as u32, out.as_mut_ptr(), &mut out_len),
            CKR_OPERATION_ACTIVE,
        );

        // The multi-part op is still active and finishes normally.
        assert_eq!(C_DigestFinal(SESSION, out.as_mut_ptr(), &mut out_len), CKR_OK);
        use sha2::Digest;
        let expected = sha2::Sha256::digest(data);
        assert_eq!(&out[..], expected.as_slice());

        // After Final the one-shot API works again.
        let mut out_len: u32 = 32;
        assert_eq!(C_DigestInit(SESSION, mech.as_mut_ptr() as *mut u8), CKR_OK);
        assert_eq!(
            C_Digest(SESSION, data.as_ptr() as *mut u8, data.len() as u32, out.as_mut_ptr(), &mut out_len),
            CKR_OK,
        );
        assert_eq!(&out[..], expected.as_slice());
    }

    // ── Minor precision codes ───────────────────────────────────────────────

    /// §6.27.2 — CKM_AES_KEY_GEN without CKA_VALUE_LEN →
    /// CKR_TEMPLATE_INCOMPLETE (no silent 16-byte default).
    #[test]
    fn aes_keygen_missing_value_len_template_incomplete() {
        let _guard = test_lock::acquire();
        setup();
        let mut mech: [usize; 3] = [CKM_AES_KEY_GEN as usize, 0, 0];
        let mut h_key: u32 = 0;
        assert_eq!(
            C_GenerateKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                std::ptr::null_mut(),
                0,
                &mut h_key,
            ),
            CKR_TEMPLATE_INCOMPLETE,
        );
    }

    /// §5.18.9 — C_DecapsulateKey with a ciphertext of the wrong length for
    /// the key's parameter set → CKR_ENCRYPTED_DATA_INVALID (was
    /// CKR_ARGUMENTS_BAD).
    #[test]
    fn decapsulate_wrong_ciphertext_len_encrypted_data_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let h_prv = 0x5334_0030;
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, vec![0u8; 1632]); // ML-KEM-512 dk size
            store_ulong(&mut attrs, CKA_CLASS, CKO_PRIVATE_KEY);
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_ML_KEM);
            store_bool(&mut attrs, CKA_DECAPSULATE, true);
            store_param_set(&mut attrs, CKP_ML_KEM_512);
            o.borrow_mut().insert(h_prv, attrs);
        });
        let mut mech: [usize; 3] = [CKM_ML_KEM as usize, 0, 0];
        let mut ct = [0u8; 10]; // ML-KEM-512 expects 768
        let mut h_new: u32 = 0;
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                h_prv,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                ct.len() as u32,
                &mut h_new,
            ),
            CKR_ENCRYPTED_DATA_INVALID,
        );
    }

    /// S5 (compliance-audit P-10) — C_EncapsulateKey / C_DecapsulateKey on
    /// a non-ML-KEM key (AES, with the KEM usage flags forced on so the
    /// permission check passes) → CKR_KEY_TYPE_INCONSISTENT.
    #[test]
    fn encap_decap_on_aes_key_key_type_inconsistent() {
        let _guard = test_lock::acquire();
        setup();
        let h_aes = 0x5334_0031;
        install_key(h_aes, 32, &[(CKA_ENCAPSULATE, true), (CKA_DECAPSULATE, true)]);
        let mut mech: [usize; 3] = [CKM_ML_KEM as usize, 0, 0];
        let mut ct = [0u8; 1088];
        let mut ct_len: u32 = ct.len() as u32;
        let mut h_new: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                h_aes,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut ct_len,
                &mut h_new,
            ),
            CKR_KEY_TYPE_INCONSISTENT,
        );
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                h_aes,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                ct.len() as u32,
                &mut h_new,
            ),
            CKR_KEY_TYPE_INCONSISTENT,
        );
    }

    /// S5 (compliance-audit P-10) — an ML-KEM object with no
    /// CKA_PARAMETER_SET no longer silently defaults to ML-KEM-768:
    /// CKR_TEMPLATE_INCOMPLETE. Keygen always stores a param set since S3,
    /// so the broken object is hand-built in the store.
    #[test]
    fn encap_decap_without_param_set_template_incomplete() {
        let _guard = test_lock::acquire();
        setup();
        let h_kem = 0x5334_0032;
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, vec![0u8; 1184]); // ML-KEM-768 ek size
            store_ulong(&mut attrs, CKA_CLASS, CKO_PUBLIC_KEY);
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_ML_KEM);
            store_bool(&mut attrs, CKA_ENCAPSULATE, true);
            store_bool(&mut attrs, CKA_DECAPSULATE, true);
            // Deliberately NO store_param_set().
            o.borrow_mut().insert(h_kem, attrs);
        });
        let mut mech: [usize; 3] = [CKM_ML_KEM as usize, 0, 0];
        let mut ct = [0u8; 1088];
        let mut ct_len: u32 = ct.len() as u32;
        let mut h_new: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                h_kem,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut ct_len,
                &mut h_new,
            ),
            CKR_TEMPLATE_INCOMPLETE,
        );
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                h_kem,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                ct.len() as u32,
                &mut h_new,
            ),
            CKR_TEMPLATE_INCOMPLETE,
        );
    }
}

#[cfg(test)]
mod pqc_vendor_kem_ffi_tests {
    //! BSI TR-02102-1 §2.4.1/§2.4.2 — FrodoKEM / Classic McEliece reachable
    //! through the raw PKCS#11 C-ABI (`C_GenerateKeyPair` /
    //! `C_EncapsulateKey` / `C_DecapsulateKey`), not just the native Rust
    //! API KMIP uses. The crypto itself is already exhaustively verified
    //! (600/600 official FrodoKEM KAT vectors, 40/40 Classic McEliece `oqs`
    //! cross-validation trials — see `native::encrypt`'s test module); these
    //! tests instead prove the C-ABI *glue* — template parsing, the
    //! buffer-probe convention, key-type/parameter-set gating, and object
    //! allocation — actually reaches that already-verified crypto.
    use super::*;
    use crate::native::test_lock;

    /// High fixed handles, disjoint from the other ffi test modules and the
    /// `native::*` allocators.
    const SESSION: u32 = 0x7770_1001;

    /// The generated private keys are CKA_PRIVATE=TRUE (matching ML-KEM/
    /// ML-DSA above), so `can_access_object` (state.rs §4.4) requires the
    /// session's token to be logged in — otherwise every decapsulate call
    /// sees CKR_KEY_HANDLE_INVALID via `check_key_usage`, not a crypto
    /// error. Stamp slot 0's TOKEN_STORE entry as logged-in directly
    /// (rather than a real C_InitToken/C_Login PIN flow, which other ffi
    /// test modules also don't use for the same reason: minimal fixture).
    fn setup() {
        crate::state::set_initialized(true);
        SESSIONS.with(|s| {
            s.borrow_mut().insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true });
        });
        TOKEN_STORE.with(|ts| {
            ts.borrow_mut()
                .entry(0)
                .or_insert_with(|| crate::state::TokenState {
                    slot_id: 0,
                    initialized: true,
                    label: [0u8; 32],
                    login_state: crate::state::LoginState::User,
                    so_pin_salt: [0u8; 16],
                    so_pin_hash: [0u8; 32],
                    user_pin_salt: None,
                    user_pin_hash: None,
                })
                .login_state = crate::state::LoginState::User;
        });
    }

    fn obj_attr(handle: u32, attr_type: u32) -> Option<Vec<u8>> {
        OBJECTS.with(|o| o.borrow().get(&handle).and_then(|a| a.get(&attr_type).cloned()))
    }

    /// One-attribute CK_ATTRIBUTE template:
    /// `[type, &value, sizeof(CK_ULONG)]`, matching this crate's
    /// `[usize; 3]`-per-attribute convention (see
    /// `get_attr_ulong`/`absorb_template_attrs`).
    fn ps_template(ps: &u32) -> [usize; 3] {
        // A real LP64 caller sends `sizeof(CK_ULONG)` — 8 bytes — for a
        // CK_ULONG-valued attribute, not 4. This helper used to declare 4,
        // which modelled a 32-bit caller on a 64-bit ABI and only "worked"
        // because get_attr_ulong ignored ulValueLen entirely. It now widens
        // the caller's u32 into an owned native word. Leaked deliberately:
        // the template must outlive this call and a unit test's address space
        // is the right lifetime for three words.
        let v: &'static crate::ck_abi::CK_ULONG =
            Box::leak(Box::new(*ps as crate::ck_abi::CK_ULONG));
        [
            CKA_PARAMETER_SET as usize,
            v as *const crate::ck_abi::CK_ULONG as usize,
            core::mem::size_of::<crate::ck_abi::CK_ULONG>(),
        ]
    }

    fn mech(m: u32) -> [usize; 3] {
        [m as usize, 0, 0]
    }

    /// Full round trip through the raw C-ABI: generate a keypair, probe the
    /// required ciphertext length (NULL `pCiphertext`, the standard PKCS#11
    /// two-call convention), encapsulate, decapsulate, and confirm both
    /// sides land on the same shared secret.
    fn round_trip(keygen_mech: u32, kem_mech: u32, ps: u32, expected_ss_len: usize) {
        let _guard = test_lock::acquire();
        setup();

        let ps_val = ps;
        let mut pub_tpl = ps_template(&ps_val);
        let mut prv_tpl = ps_template(&ps_val);
        let mut kg_mech = mech(keygen_mech);
        let mut h_pub: u32 = 0;
        let mut h_prv: u32 = 0;
        assert_eq!(
            C_GenerateKeyPair(
                SESSION,
                kg_mech.as_mut_ptr() as *mut u8,
                pub_tpl.as_mut_ptr() as *mut u8,
                1,
                prv_tpl.as_mut_ptr() as *mut u8,
                1,
                &mut h_pub,
                &mut h_prv,
            ),
            CKR_OK,
            "C_GenerateKeyPair"
        );
        assert_ne!(h_pub, 0);
        assert_ne!(h_prv, 0);

        // Probe: NULL pCiphertext returns the required buffer length.
        let mut kem_mech_words = mech(kem_mech);
        let mut ct_len: u32 = 0;
        let mut h_ss1: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem_mech_words.as_mut_ptr() as *mut u8,
                h_pub,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut ct_len,
                &mut h_ss1,
            ),
            CKR_OK,
            "C_EncapsulateKey length probe"
        );
        assert!(ct_len > 0);

        let mut ct = vec![0u8; ct_len as usize];
        let mut actual_ct_len = ct_len;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem_mech_words.as_mut_ptr() as *mut u8,
                h_pub,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut actual_ct_len,
                &mut h_ss1,
            ),
            CKR_OK,
            "C_EncapsulateKey"
        );
        assert_eq!(actual_ct_len, ct_len);

        let mut h_ss2: u32 = 0;
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                kem_mech_words.as_mut_ptr() as *mut u8,
                h_prv,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                ct_len,
                &mut h_ss2,
            ),
            CKR_OK,
            "C_DecapsulateKey"
        );

        let ss1 = obj_attr(h_ss1, CKA_VALUE).expect("encapsulate secret object");
        let ss2 = obj_attr(h_ss2, CKA_VALUE).expect("decapsulate secret object");
        assert_eq!(ss1, ss2, "encapsulator and decapsulator must derive the same shared secret");
        assert_eq!(ss1.len(), expected_ss_len);

        // PKCS#11 v3.2 §6.8.2 Table 103 — CKA_VALUE_LEN is the "Length in bytes
        // of key value". The decapsulate arm stored the CIPHERTEXT length here
        // until 2026-08-13 (FrodoKEM-640-SHAKE: 9720 for a 16-byte secret), so
        // this assertion is what fails if anyone reintroduces that.
        for (h, side) in [(h_ss1, "encapsulate"), (h_ss2, "decapsulate")] {
            let vlen = get_object_attr_u32(h, CKA_VALUE_LEN)
                .unwrap_or_else(|| panic!("{side}: CKA_VALUE_LEN must exist")) as usize;
            assert_eq!(
                vlen, expected_ss_len,
                "{side}: CKA_VALUE_LEN must be the SHARED SECRET length, not the ciphertext length"
            );
            assert_eq!(
                vlen,
                obj_attr(h, CKA_VALUE).unwrap().len(),
                "{side}: CKA_VALUE_LEN must equal len(CKA_VALUE)"
            );
            assert_ne!(vlen, ct_len as usize, "{side}: CKA_VALUE_LEN must not be the ciphertext length");
        }
    }

    /// One-attribute CKA_VALUE_LEN template, the shape callers actually send.
    fn value_len_template(v: &u32) -> [usize; 3] {
        // A real LP64 caller sends `sizeof(CK_ULONG)` — 8 bytes — for a
        // CK_ULONG-valued attribute, not 4. This helper used to declare 4,
        // which modelled a 32-bit caller on a 64-bit ABI and only "worked"
        // because get_attr_ulong ignored ulValueLen entirely. It now widens
        // the caller's u32 into an owned native word. Leaked deliberately:
        // the template must outlive this call and a unit test's address space
        // is the right lifetime for three words.
        let w: &'static crate::ck_abi::CK_ULONG =
            Box::leak(Box::new(*v as crate::ck_abi::CK_ULONG));
        [
            CKA_VALUE_LEN as usize,
            w as *const crate::ck_abi::CK_ULONG as usize,
            core::mem::size_of::<crate::ck_abi::CK_ULONG>(),
        ]
    }

    /// PKCS#11 v3.2 §4.1.1 rule 5 — a caller CKA_VALUE_LEN that contradicts the
    /// CKA_VALUE the mechanism contributes is CKR_TEMPLATE_INCONSISTENT, and
    /// §5.18.8/§5.18.9 require the call to "fail and return without creating any
    /// key object". Uses the ciphertext length as the bogus value: exactly the
    /// value the engine itself used to store.
    #[test]
    fn kem_conflicting_template_value_len_template_inconsistent() {
        let _guard = test_lock::acquire();
        setup();
        let ps_val = CKP_FRODOKEM_640_SHAKE;
        let mut pub_tpl = ps_template(&ps_val);
        let mut prv_tpl = ps_template(&ps_val);
        let mut kg_mech = mech(CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN);
        let (mut h_pub, mut h_prv) = (0u32, 0u32);
        assert_eq!(
            C_GenerateKeyPair(
                SESSION,
                kg_mech.as_mut_ptr() as *mut u8,
                pub_tpl.as_mut_ptr() as *mut u8,
                1,
                prv_tpl.as_mut_ptr() as *mut u8,
                1,
                &mut h_pub,
                &mut h_prv,
            ),
            CKR_OK
        );

        let mut kem_mech = mech(CKM_PQCTODAY_FRODOKEM_ENCAPSULATE);
        let mut ct_len: u32 = 0;
        let mut h_ss: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem_mech.as_mut_ptr() as *mut u8,
                h_pub,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut ct_len,
                &mut h_ss,
            ),
            CKR_OK
        );
        let mut ct = vec![0u8; ct_len as usize];
        let mut n = ct_len;

        // Conflicting value (the ciphertext length) on ENCAPSULATE.
        let bogus = ct_len;
        let mut bad_tpl = value_len_template(&bogus);
        let mut h_bad: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem_mech.as_mut_ptr() as *mut u8,
                h_pub,
                bad_tpl.as_mut_ptr() as *mut u8,
                1,
                ct.as_mut_ptr(),
                &mut n,
                &mut h_bad,
            ),
            CKR_TEMPLATE_INCONSISTENT,
            "encapsulate must reject a CKA_VALUE_LEN that contradicts CKA_VALUE"
        );
        assert_eq!(h_bad, 0, "§5.18.8 — no key object may be created");

        // Matching value (§4.1.1 rule 6) must succeed on ENCAPSULATE.
        let good: u32 = 16; // FrodoKEM-640 shared secret
        let mut good_tpl = value_len_template(&good);
        let mut n2 = ct_len;
        let mut h_ok: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem_mech.as_mut_ptr() as *mut u8,
                h_pub,
                good_tpl.as_mut_ptr() as *mut u8,
                1,
                ct.as_mut_ptr(),
                &mut n2,
                &mut h_ok,
            ),
            CKR_OK,
            "a CKA_VALUE_LEN that restates the contributed value must be accepted"
        );
        assert_eq!(get_object_attr_u32(h_ok, CKA_VALUE_LEN), Some(good));

        // Same two cases on DECAPSULATE, using the ciphertext just produced.
        let mut h_bad_d: u32 = 0;
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                kem_mech.as_mut_ptr() as *mut u8,
                h_prv,
                bad_tpl.as_mut_ptr() as *mut u8,
                1,
                ct.as_mut_ptr(),
                ct_len,
                &mut h_bad_d,
            ),
            CKR_TEMPLATE_INCONSISTENT,
            "decapsulate must reject a CKA_VALUE_LEN that contradicts CKA_VALUE"
        );
        assert_eq!(h_bad_d, 0, "§5.18.9 — no key object may be created");
        let mut h_ok_d: u32 = 0;
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                kem_mech.as_mut_ptr() as *mut u8,
                h_prv,
                good_tpl.as_mut_ptr() as *mut u8,
                1,
                ct.as_mut_ptr(),
                ct_len,
                &mut h_ok_d,
            ),
            CKR_OK
        );
        assert_eq!(get_object_attr_u32(h_ok_d, CKA_VALUE_LEN), Some(good));
        assert_eq!(obj_attr(h_ok_d, CKA_VALUE).unwrap().len(), good as usize);
    }

    #[test]
    fn frodokem_976_aes_round_trip() {
        round_trip(
            CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN,
            CKM_PQCTODAY_FRODOKEM_ENCAPSULATE,
            CKP_FRODOKEM_976_AES,
            24,
        );
    }

    #[test]
    fn frodokem_640_shake_round_trip() {
        round_trip(
            CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN,
            CKM_PQCTODAY_FRODOKEM_ENCAPSULATE,
            CKP_FRODOKEM_640_SHAKE,
            16,
        );
    }

    /// FrodoKEM-1344-AES specifically — the parameter set the hub's PKCS#11
    /// playground showcases. Not previously covered (only 976-aes/640-shake
    /// were); this was the gap that let the wasm shadow-stack overflow for
    /// FrodoKEM's own encapsulate/decapsulate go unnoticed (native tests
    /// don't have a wasm stack limit, so they never would have caught it —
    /// this test exists for algorithmic coverage, not the stack-size bug).
    #[test]
    fn frodokem_1344_aes_round_trip() {
        round_trip(
            CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN,
            CKM_PQCTODAY_FRODOKEM_ENCAPSULATE,
            CKP_FRODOKEM_1344_AES,
            32,
        );
    }

    /// `#[ignore]`: a single mceliece6688128 keygen (Goppa code generation)
    /// takes minutes in an unoptimized debug build — too slow for every CI
    /// run. Run manually with `cargo test --release -- --ignored
    /// classic_mceliece_6688128_round_trip` (release mode is fast).
    #[test]
    #[ignore = "mceliece6688128 keygen is minutes-slow in debug builds — see doc comment"]
    fn classic_mceliece_6688128_round_trip() {
        round_trip(
            CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN,
            CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE,
            CKP_CLASSIC_MCELIECE_6688128,
            32,
        );
    }

    /// PKCS#11 v3.2 §6.x — CKA_PARAMETER_SET is a REQUIRED keygen template
    /// attribute for both vendor KEMs, same convention as ML-KEM/ML-DSA.
    #[test]
    fn keygen_missing_parameter_set_template_incomplete() {
        let _guard = test_lock::acquire();
        setup();
        for keygen_mech in
            [CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN, CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN]
        {
            let mut kg_mech = mech(keygen_mech);
            let mut h_pub: u32 = 0;
            let mut h_prv: u32 = 0;
            assert_eq!(
                C_GenerateKeyPair(
                    SESSION,
                    kg_mech.as_mut_ptr() as *mut u8,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &mut h_pub,
                    &mut h_prv,
                ),
                CKR_TEMPLATE_INCOMPLETE,
                "mech {keygen_mech:#x}"
            );
        }
    }

    /// Classic McEliece is scoped to `mceliece6688128` only (implementation
    /// plan Phase 0.5) — any other CKA_PARAMETER_SET value is rejected, not
    /// silently coerced.
    #[test]
    fn classic_mceliece_keygen_wrong_parameter_set_attribute_value_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let bogus_ps: u32 = 0x9999;
        let mut pub_tpl = ps_template(&bogus_ps);
        let mut kg_mech = mech(CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN);
        let mut h_pub: u32 = 0;
        let mut h_prv: u32 = 0;
        assert_eq!(
            C_GenerateKeyPair(
                SESSION,
                kg_mech.as_mut_ptr() as *mut u8,
                pub_tpl.as_mut_ptr() as *mut u8,
                1,
                std::ptr::null_mut(),
                0,
                &mut h_pub,
                &mut h_prv,
            ),
            CKR_ATTRIBUTE_VALUE_INVALID,
        );
    }

    /// Neither vendor KEM has a deterministic (CKA_SEED) keygen path —
    /// `frodo-kem` doesn't expose a keygen-from-seed entry point, and
    /// scoping Classic McEliece's cross-validation to the random path keeps
    /// its evidence honest (implementation plan Phase 0.8). A caller-supplied
    /// CKA_SEED must be rejected, not silently ignored.
    #[test]
    fn keygen_rejects_seed() {
        let _guard = test_lock::acquire();
        setup();
        let ps_frodo = CKP_FRODOKEM_976_AES;
        let seed = [0u8; 32];
        let seed_tpl: [usize; 3] = [CKA_SEED as usize, seed.as_ptr() as usize, seed.len()];
        for (keygen_mech, ps) in [
            (CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN, ps_frodo),
            (CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN, CKP_CLASSIC_MCELIECE_6688128),
        ] {
            let mut pub_tpl = ps_template(&ps);
            let mut prv_tpl = seed_tpl;
            let mut kg_mech = mech(keygen_mech);
            let mut h_pub: u32 = 0;
            let mut h_prv: u32 = 0;
            assert_eq!(
                C_GenerateKeyPair(
                    SESSION,
                    kg_mech.as_mut_ptr() as *mut u8,
                    pub_tpl.as_mut_ptr() as *mut u8,
                    1,
                    prv_tpl.as_mut_ptr() as *mut u8,
                    1,
                    &mut h_pub,
                    &mut h_prv,
                ),
                CKR_ATTRIBUTE_VALUE_INVALID,
                "mech {keygen_mech:#x}"
            );
        }
    }

    /// S5-equivalent (mirrors `encap_decap_on_aes_key_key_type_inconsistent`
    /// for ML-KEM) — encapsulate/decapsulate on a key of the wrong PQC
    /// vendor KEM family → CKR_KEY_TYPE_INCONSISTENT, not a crypto attempt.
    ///
    /// `#[ignore]`: builds a real mceliece6688128 keypair first — minutes-slow
    /// in an unoptimized debug build. Run manually with `cargo test --release
    /// -- --ignored encapsulate_on_wrong_key_family` (release mode is fast).
    #[test]
    #[ignore = "mceliece6688128 keygen is minutes-slow in debug builds — see doc comment"]
    fn encapsulate_on_wrong_key_family_key_type_inconsistent() {
        let _guard = test_lock::acquire();
        setup();

        let h_mceliece_pub = {
            let ps_val = CKP_CLASSIC_MCELIECE_6688128;
            let mut pub_tpl = ps_template(&ps_val);
            let mut prv_tpl = ps_template(&ps_val);
            let mut kg_mech = mech(CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN);
            let mut h_pub: u32 = 0;
            let mut h_prv: u32 = 0;
            assert_eq!(
                C_GenerateKeyPair(
                    SESSION,
                    kg_mech.as_mut_ptr() as *mut u8,
                    pub_tpl.as_mut_ptr() as *mut u8,
                    1,
                    prv_tpl.as_mut_ptr() as *mut u8,
                    1,
                    &mut h_pub,
                    &mut h_prv,
                ),
                CKR_OK
            );
            h_pub
        };

        // A Classic McEliece key used with the FrodoKEM mechanism.
        let mut kem_mech = mech(CKM_PQCTODAY_FRODOKEM_ENCAPSULATE);
        let mut ct_len: u32 = 0;
        let mut h_ss: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem_mech.as_mut_ptr() as *mut u8,
                h_mceliece_pub,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut ct_len,
                &mut h_ss,
            ),
            CKR_KEY_TYPE_INCONSISTENT,
        );
    }

    /// §5.18.9-equivalent — a ciphertext of the wrong length for the vendor
    /// KEM's parameter set → CKR_ENCRYPTED_DATA_INVALID.
    ///
    /// `#[ignore]`: builds a real mceliece6688128 keypair first — minutes-slow
    /// in an unoptimized debug build. Run manually with `cargo test --release
    /// -- --ignored pqc_vendor_kem_ffi_tests::decapsulate_wrong_ciphertext_len`
    /// (release mode is fast).
    #[test]
    #[ignore = "mceliece6688128 keygen is minutes-slow in debug builds — see doc comment"]
    fn decapsulate_wrong_ciphertext_len_encrypted_data_invalid() {
        let _guard = test_lock::acquire();
        setup();
        let ps_val = CKP_CLASSIC_MCELIECE_6688128;
        let mut pub_tpl = ps_template(&ps_val);
        let mut prv_tpl = ps_template(&ps_val);
        let mut kg_mech = mech(CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN);
        let mut h_pub: u32 = 0;
        let mut h_prv: u32 = 0;
        assert_eq!(
            C_GenerateKeyPair(
                SESSION,
                kg_mech.as_mut_ptr() as *mut u8,
                pub_tpl.as_mut_ptr() as *mut u8,
                1,
                prv_tpl.as_mut_ptr() as *mut u8,
                1,
                &mut h_pub,
                &mut h_prv,
            ),
            CKR_OK
        );

        let mut kem_mech = mech(CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE);
        let mut ct = [0u8; 10]; // mceliece6688128 expects 208
        let mut h_ss: u32 = 0;
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                kem_mech.as_mut_ptr() as *mut u8,
                h_prv,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                ct.len() as u32,
                &mut h_ss,
            ),
            CKR_ENCRYPTED_DATA_INVALID,
        );
    }
}

#[cfg(test)]
mod token_info_tests {
    //! T2 (audit H-15) — C_GetTokenInfo is dynamic: flags derive from real
    //! token state, session counters from the live session table, and the
    //! label is per-instance. The byte layout of CK_TOKEN_INFO (160 bytes,
    //! 32-bit CK_ULONG ABI) is pinned by `token_info_byte_layout_unchanged`.
    use super::*;
    use crate::native::test_lock;

    fn reset_engine() {
        let _ = C_Finalize(std::ptr::null_mut());
        assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    }

    /// Call C_GetTokenInfo(0) into a 4-byte-aligned 160-byte buffer (the
    /// impl writes the CK_ULONG fields through a `*mut u32`).
    fn get_token_info() -> [u8; 160] {
        let mut words = [0u32; 40];
        assert_eq!(C_GetTokenInfo(0, words.as_mut_ptr() as *mut u8), CKR_OK);
        let mut buf = [0u8; 160];
        for (i, w) in words.iter().enumerate() {
            buf[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        buf
    }

    fn u32_at(buf: &[u8; 160], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

    fn flags_of(buf: &[u8; 160]) -> u32 {
        u32_at(buf, 96)
    }

    /// H-15 — CKF_TOKEN_INITIALIZED / CKF_USER_PIN_INITIALIZED follow the
    /// real TokenState; CKF_WRITE_PROTECTED is never set. WS-11 (2026-08-28)
    /// — CKF_RESTORE_KEY_NOT_NEEDED is now always on (parity with the C++
    /// engine, which has always set it unconditionally).
    #[test]
    fn flags_reflect_token_and_pin_state() {
        let _guard = test_lock::acquire();
        reset_engine();
        // Fresh built-in token: uninitialized, no user PIN — but login is
        // still required for private objects, so CKF_LOGIN_REQUIRED is on.
        assert_eq!(
            flags_of(&get_token_info()),
            CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED
        );

        TOKEN_STORE.with(|ts| {
            ts.borrow_mut().get_mut(&0).unwrap().initialized = true;
        });
        assert_eq!(
            flags_of(&get_token_info()),
            CKF_RNG | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_TOKEN_INITIALIZED
        );

        TOKEN_STORE.with(|ts| {
            let mut store = ts.borrow_mut();
            let t = store.get_mut(&0).unwrap();
            t.user_pin_salt = Some([0u8; 16]);
            t.user_pin_hash = Some([0u8; 32]);
        });
        let flags = flags_of(&get_token_info());
        assert_eq!(
            flags,
            CKF_RNG
                | CKF_LOGIN_REQUIRED
                | CKF_RESTORE_KEY_NOT_NEEDED
                | CKF_TOKEN_INITIALIZED
                | CKF_USER_PIN_INITIALIZED
        );
        assert_eq!(flags & CKF_WRITE_PROTECTED, 0, "token must not claim write protection");

        // PIN cleared (C_InitToken does this) → flag drops again.
        TOKEN_STORE.with(|ts| {
            let mut store = ts.borrow_mut();
            let t = store.get_mut(&0).unwrap();
            t.user_pin_salt = None;
            t.user_pin_hash = None;
        });
        assert_eq!(flags_of(&get_token_info()) & CKF_USER_PIN_INITIALIZED, 0);
    }

    /// H-15 — CKF_LOGIN_REQUIRED must tell the truth about enforcement.
    /// Even on a PIN-less token, `can_access_object` denies a
    /// CKA_PRIVATE=TRUE object to a logged-out session — so the flag and
    /// the enforcement decision must agree (both "login required").
    #[test]
    fn login_required_flag_matches_can_access_object_enforcement() {
        let _guard = test_lock::acquire();
        reset_engine();
        let mut h_session = 0u32;
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut h_session,
            ),
            CKR_OK
        );
        let mut attrs = Attributes::new();
        crate::state::store_bool(&mut attrs, CKA_PRIVATE, true);
        let denied = !crate::state::can_access_object(h_session, &attrs);
        let flag_set = flags_of(&get_token_info()) & CKF_LOGIN_REQUIRED != 0;
        assert_eq!(
            denied, flag_set,
            "CKF_LOGIN_REQUIRED ({flag_set}) must match private-object \
             enforcement (denied={denied})"
        );
        assert!(denied, "private object must be inaccessible while logged out");
        assert_eq!(C_CloseSession(h_session), CKR_OK);
    }

    /// Label setter round-trip + §5.5 32-byte space padding + truncation.
    #[test]
    fn label_setter_round_trip_and_padding() {
        let _guard = test_lock::acquire();
        reset_engine();
        // Default label preserved from the pre-T2 implementation.
        assert_eq!(
            crate::native::session::get_token_label().unwrap(),
            crate::state::DEFAULT_TOKEN_LABEL
        );
        let buf = get_token_info();
        assert_eq!(&buf[0..13], b"SoftHSM3-Rust");
        assert!(buf[13..32].iter().all(|&b| b == 0x20), "label must be space-padded");

        crate::native::session::set_token_label("pqctoday-instance-A").unwrap();
        assert_eq!(
            crate::native::session::get_token_label().unwrap(),
            "pqctoday-instance-A"
        );
        let buf = get_token_info();
        assert_eq!(&buf[0..19], b"pqctoday-instance-A");
        assert!(buf[19..32].iter().all(|&b| b == 0x20), "label must be space-padded");

        // Over-long labels truncate at 32 bytes.
        crate::native::session::set_token_label(
            "0123456789012345678901234567890123456789",
        )
        .unwrap();
        assert_eq!(
            crate::native::session::get_token_label().unwrap(),
            "01234567890123456789012345678901"
        );
    }

    /// ulSessionCount @104 / ulRwSessionCount @112 track open/close live.
    #[test]
    fn session_counters_track_open_close() {
        let _guard = test_lock::acquire();
        reset_engine();
        let buf = get_token_info();
        assert_eq!(u32_at(&buf, 104), 0, "fresh engine: no sessions");
        assert_eq!(u32_at(&buf, 112), 0, "fresh engine: no rw sessions");

        let (mut rw, mut ro) = (0u32, 0u32);
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut rw,
            ),
            CKR_OK
        );
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut ro,
            ),
            CKR_OK
        );
        let buf = get_token_info();
        assert_eq!(u32_at(&buf, 104), 2);
        assert_eq!(u32_at(&buf, 112), 1);

        assert_eq!(C_CloseSession(rw), CKR_OK);
        let buf = get_token_info();
        assert_eq!(u32_at(&buf, 104), 1);
        assert_eq!(u32_at(&buf, 112), 0);
        assert_eq!(C_CloseSession(ro), CKR_OK);
    }

    /// Byte-layout regression — every static field sits at the same offset
    /// (and keeps the same value) as the pre-T2 implementation; only the
    /// state-derived values changed. The JS/wasm side reads this struct at
    /// fixed offsets, so this layout is ABI.
    #[test]
    fn token_info_byte_layout_unchanged() {
        let _guard = test_lock::acquire();
        reset_engine();
        let buf = get_token_info();

        // label[32] @0 (default), manufacturerID[32] @32, model[16] @64,
        // serialNumber[16] @80 — all blank-padded.
        assert_eq!(&buf[0..13], b"SoftHSM3-Rust");
        let mut manufacturer = [0x20u8; 32];
        manufacturer[..15].copy_from_slice(b"SoftHSM project");
        assert_eq!(&buf[32..64], &manufacturer);
        let mut model = [0x20u8; 16];
        model[..8].copy_from_slice(b"PQCToday");
        assert_eq!(&buf[64..80], &model);
        let mut serial = [0x20u8; 16];
        serial[..4].copy_from_slice(b"0001");
        assert_eq!(&buf[80..96], &serial);

        // flags @96 — equals the single-point-of-truth derivation.
        let token = TOKEN_STORE.with(|ts| ts.borrow().get(&0).cloned()).unwrap();
        assert_eq!(u32_at(&buf, 96), crate::state::token_info_flags(&token));

        // ulMaxSessionCount @100 / ulMaxRwSessionCount @108 — unbounded.
        assert_eq!(u32_at(&buf, 100), CK_UNAVAILABLE_INFORMATION);
        assert_eq!(u32_at(&buf, 108), CK_UNAVAILABLE_INFORMATION);
        // ulMaxPinLen @116 / ulMinPinLen @120 — unchanged values.
        assert_eq!(u32_at(&buf, 116), 256);
        assert_eq!(u32_at(&buf, 120), 4);
        // Memory fields @124..140 — CK_UNAVAILABLE_INFORMATION, not fakes.
        for off in [124usize, 128, 132, 136] {
            assert_eq!(u32_at(&buf, off), CK_UNAVAILABLE_INFORMATION, "offset {off}");
        }
        // hardwareVersion @140-141 = 3.2, firmwareVersion @142-143 = 0.1.
        assert_eq!((buf[140], buf[141]), (3, 2));
        assert_eq!((buf[142], buf[143]), (0, 1));
        // utcTime[16] @144 — blank (no CKF_CLOCK_ON_TOKEN).
        assert!(buf[144..160].iter().all(|&b| b == 0x20));
    }
}

#[cfg(test)]
mod multi_slot_scoping_tests {
    //! T3 (audit: multi-slot FindObjects scoping) — objects belong to the
    //! token (slot) of the session that created them. Enumeration
    //! (C_FindObjects) and by-handle access are scoped to the session's
    //! slot. The engine boots single-slot; `state::ensure_slot` is the
    //! multi-slot activation hook used here to bring slot 1 online.
    use super::*;
    use crate::native::test_lock;

    fn reset_engine() {
        let _ = C_Finalize(std::ptr::null_mut());
        assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    }

    fn open(slot: u32) -> u32 {
        let mut h = 0u32;
        assert_eq!(
            C_OpenSession(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut h,
            ),
            CKR_OK,
            "open session on slot {slot}"
        );
        h
    }

    /// Public (non-private) AES-shaped object created through the session
    /// choke point, so it carries the session's slot tag.
    fn create_object(session: u32, label: &[u8]) -> u32 {
        let mut attrs = Attributes::new();
        attrs.insert(CKA_VALUE, vec![0x42u8; 32]);
        store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
        attrs.insert(crate::native::keygen::CKA_LABEL, label.to_vec());
        crate::state::allocate_handle_owned(session, attrs)
    }

    fn find_all(session: u32) -> Vec<u32> {
        assert_eq!(C_FindObjectsInit(session, std::ptr::null_mut(), 0), CKR_OK);
        let mut handles = [0u32; 64];
        let mut n = 0u32;
        assert_eq!(C_FindObjects(session, handles.as_mut_ptr(), 64, &mut n), CKR_OK);
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        handles[..n as usize].to_vec()
    }

    /// FindObjects from a slot-1 session must not see slot-0 objects and
    /// vice versa; each session enumerates exactly its own token's objects.
    #[test]
    fn find_objects_is_token_scoped() {
        let _guard = test_lock::acquire();
        reset_engine();
        crate::state::ensure_slot(1);
        let s0 = open(0);
        let s1 = open(1);

        let h0 = create_object(s0, b"slot0-obj");
        let h1 = create_object(s1, b"slot1-obj");

        let found0 = find_all(s0);
        assert!(found0.contains(&h0), "slot-0 session must see its object");
        assert!(
            !found0.contains(&h1),
            "slot-0 session must NOT see slot-1's object"
        );

        let found1 = find_all(s1);
        assert!(found1.contains(&h1), "slot-1 session must see its object");
        assert!(
            !found1.contains(&h0),
            "slot-1 session must NOT see slot-0's object"
        );

        assert_eq!(C_CloseSession(s0), CKR_OK);
        assert_eq!(C_CloseSession(s1), CKR_OK);
    }

    /// Strict §2.4/§4.4 handle scoping — handles are token-scoped: using a
    /// handle that belongs to another slot's token fails with
    /// CKR_OBJECT_HANDLE_INVALID on by-handle access (GetAttributeValue,
    /// DestroyObject), while same-slot access succeeds.
    #[test]
    fn cross_slot_handle_is_invalid() {
        let _guard = test_lock::acquire();
        reset_engine();
        crate::state::ensure_slot(1);
        let s0 = open(0);
        let s1 = open(1);
        let h0 = create_object(s0, b"slot0-only");

        // Same-slot by-handle access works (empty template → pure gate).
        assert_eq!(C_GetAttributeValue(s0, h0, std::ptr::null_mut(), 0), CKR_OK);
        // Cross-slot: the handle is treated as invalid.
        assert_eq!(
            C_GetAttributeValue(s1, h0, std::ptr::null_mut(), 0),
            CKR_OBJECT_HANDLE_INVALID
        );
        assert_eq!(C_DestroyObject(s1, h0), CKR_OBJECT_HANDLE_INVALID);
        // The object survives the foreign destroy attempt.
        assert_eq!(C_DestroyObject(s0, h0), CKR_OK);

        assert_eq!(C_CloseSession(s0), CKR_OK);
        assert_eq!(C_CloseSession(s1), CKR_OK);
    }

    /// Legacy/untagged records (no CKA_PRIV_SLOT_ID — e.g. objects created
    /// before T3 or injected without a session context) belong to slot 0,
    /// the primary token: visible there, invisible elsewhere.
    #[test]
    fn untagged_objects_default_to_slot_zero() {
        let _guard = test_lock::acquire();
        reset_engine();
        crate::state::ensure_slot(1);
        let s0 = open(0);
        let s1 = open(1);

        // Library-scoped creation without a session context.
        let mut attrs = Attributes::new();
        attrs.insert(CKA_VALUE, vec![0x24u8; 16]);
        store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
        let h = crate::state::allocate_handle(attrs);

        assert!(find_all(s0).contains(&h), "primary token owns untagged objects");
        assert!(!find_all(s1).contains(&h), "slot 1 must not see them");

        assert_eq!(C_CloseSession(s0), CKR_OK);
        assert_eq!(C_CloseSession(s1), CKR_OK);
    }
}

#[cfg(test)]
mod multipart_sign_verify_ffi_tests {
    //! T4 (audit: multi-part sign gap) — C_SignUpdate / C_SignFinal /
    //! C_VerifyUpdate / C_VerifyFinal: Update×N + Final equivalence with the
    //! one-shot handlers, the §5.2/§5.13/§5.15 state-machine matrix, the
    //! spec-pinned single-part-only code (CKR_OPERATION_NOT_INITIALIZED —
    //! see `multipart_op_mech`), and cancel/close cleanup.
    use super::*;
    use crate::native::test_lock;

    /// High fixed handles, disjoint from the other ffi test modules.
    const SESSION: u32 = 0x5434_1001;
    const BOGUS_SESSION: u32 = 0x5434_1FFF;
    const HMAC_KEY: u32 = 0x5434_2001;
    const HMAC_KEY_BYTES: [u8; 32] = [0x6b; 32];

    fn setup() {
        crate::state::set_initialized(true);
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                SESSION,
                crate::state::SessionState { slot_id: 0, rw_session: true },
            );
        });
        // Clean slate for the op state under test.
        SIGN_STATE.with(|s| s.borrow_mut().remove(&SESSION));
        VERIFY_STATE.with(|s| s.borrow_mut().remove(&SESSION));
        SIGN_MULTIPART_ACC.with(|s| s.borrow_mut().remove(&SESSION));
        VERIFY_MULTIPART_ACC.with(|s| s.borrow_mut().remove(&SESSION));
        // Public generic-secret HMAC key (no login gate).
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, HMAC_KEY_BYTES.to_vec());
            store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
            store_bool(&mut attrs, CKA_SIGN, true);
            store_bool(&mut attrs, CKA_VERIFY, true);
            o.borrow_mut().insert(HMAC_KEY, attrs);
        });
    }

    fn sign_init(sess: u32, mech: u32, key: u32) -> u32 {
        let mut m: [usize; 3] = [mech as usize, 0, 0];
        C_SignInit(sess, m.as_mut_ptr() as *mut u8, key)
    }

    fn verify_init(sess: u32, mech: u32, key: u32) -> u32 {
        let mut m: [usize; 3] = [mech as usize, 0, 0];
        C_VerifyInit(sess, m.as_mut_ptr() as *mut u8, key)
    }

    fn s_update(sess: u32, part: &[u8]) -> u32 {
        C_SignUpdate(sess, part.as_ptr() as *mut u8, part.len() as u32)
    }

    fn v_update(sess: u32, part: &[u8]) -> u32 {
        C_VerifyUpdate(sess, part.as_ptr() as *mut u8, part.len() as u32)
    }

    /// C_SignFinal via the §5.2 two-call convention (size query, then fetch).
    fn sign_final_vec(sess: u32) -> Result<Vec<u8>, u32> {
        let mut len: u32 = 0;
        let rv = C_SignFinal(sess, std::ptr::null_mut(), &mut len);
        if rv != CKR_OK {
            return Err(rv);
        }
        let mut buf = vec![0u8; len as usize];
        let rv = C_SignFinal(sess, buf.as_mut_ptr(), &mut len);
        if rv != CKR_OK {
            return Err(rv);
        }
        buf.truncate(len as usize);
        Ok(buf)
    }

    fn one_shot_sign(sess: u32, mech: u32, key: u32, msg: &[u8]) -> Vec<u8> {
        assert_eq!(sign_init(sess, mech, key), CKR_OK);
        let mut buf = vec![0u8; 1024];
        let mut len: u32 = 1024;
        let rv = C_Sign(sess, msg.as_ptr() as *mut u8, msg.len() as u32, buf.as_mut_ptr(), &mut len);
        assert_eq!(rv, CKR_OK, "one-shot C_Sign mech 0x{mech:x}: 0x{rv:x}");
        buf.truncate(len as usize);
        buf
    }

    fn one_shot_verify(sess: u32, mech: u32, key: u32, msg: &[u8], sig: &[u8]) -> u32 {
        assert_eq!(verify_init(sess, mech, key), CKR_OK);
        C_Verify(
            sess,
            msg.as_ptr() as *mut u8,
            msg.len() as u32,
            sig.as_ptr() as *mut u8,
            sig.len() as u32,
        )
    }

    fn multipart_sign(sess: u32, mech: u32, key: u32, parts: &[&[u8]]) -> Vec<u8> {
        assert_eq!(sign_init(sess, mech, key), CKR_OK);
        for p in parts {
            assert_eq!(s_update(sess, p), CKR_OK);
        }
        sign_final_vec(sess).expect("multi-part sign final")
    }

    fn multipart_verify(sess: u32, mech: u32, key: u32, parts: &[&[u8]], sig: &[u8]) -> u32 {
        assert_eq!(verify_init(sess, mech, key), CKR_OK);
        for p in parts {
            assert_eq!(v_update(sess, p), CKR_OK);
        }
        C_VerifyFinal(sess, sig.as_ptr() as *mut u8, sig.len() as u32)
    }

    // ── Update×N + Final == one-shot (HMAC, byte-equal) ─────────────────────

    /// HMAC SHA-256/384/512: multi-part MAC over several split patterns
    /// (whole / ragged / empty leading+trailing parts) is byte-equal to the
    /// one-shot C_Sign, and VerifyUpdate/Final accepts each MAC.
    #[test]
    fn hmac_update_final_byte_equal_one_shot() {
        let _guard = test_lock::acquire();
        setup();
        let msg = b"multi-part message under test, longer than one block boundary";
        for mech in [CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC] {
            let expected = one_shot_sign(SESSION, mech, HMAC_KEY, msg);
            let splits: [&[&[u8]]; 3] = [
                &[&msg[..]],
                &[&msg[..3], &msg[3..17], &msg[17..]],
                &[&[], &msg[..], &[]],
            ];
            for parts in splits {
                let sig = multipart_sign(SESSION, mech, HMAC_KEY, parts);
                assert_eq!(sig, expected, "mech 0x{mech:x} split mismatch");
                assert_eq!(
                    multipart_verify(SESSION, mech, HMAC_KEY, parts, &sig),
                    CKR_OK,
                    "mech 0x{mech:x} multi-part verify"
                );
            }
        }
    }

    /// HMAC-SHA-256 Update/Final cross-checked against the `hmac` crate
    /// one-shot over the same key and message.
    #[test]
    fn hmac_update_final_matches_hmac_crate() {
        let _guard = test_lock::acquire();
        setup();
        let msg = b"cross-check against RustCrypto hmac";
        let sig = multipart_sign(
            SESSION,
            CKM_SHA256_HMAC,
            HMAC_KEY,
            &[&msg[..10], &msg[10..]],
        );
        use hmac::Mac;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&HMAC_KEY_BYTES).unwrap();
        mac.update(msg);
        assert_eq!(sig, mac.finalize().into_bytes().to_vec());
    }

    // ── §5.13/§5.15 sequencing: one-shot after Update ───────────────────────

    /// C_Sign while the sign op is in its multi-part phase →
    /// CKR_OPERATION_ACTIVE; the accumulated parts are NOT consumed and the
    /// op completes correctly. Same matrix for Verify.
    #[test]
    fn one_shot_after_update_operation_active_acc_preserved() {
        let _guard = test_lock::acquire();
        setup();
        let expected = one_shot_sign(SESSION, CKM_SHA256_HMAC, HMAC_KEY, b"part one and two");

        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(SESSION, b"part one"), CKR_OK);
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        assert_eq!(
            C_Sign(SESSION, buf.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_ACTIVE,
        );
        // Accumulator intact — finish the op and compare.
        assert_eq!(s_update(SESSION, b" and two"), CKR_OK);
        assert_eq!(sign_final_vec(SESSION).unwrap(), expected);

        // Verify side.
        assert_eq!(verify_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(v_update(SESSION, b"part one"), CKR_OK);
        assert_eq!(
            C_Verify(
                SESSION,
                buf.as_ptr() as *mut u8,
                4,
                expected.as_ptr() as *mut u8,
                expected.len() as u32,
            ),
            CKR_OPERATION_ACTIVE,
        );
        assert_eq!(v_update(SESSION, b" and two"), CKR_OK);
        assert_eq!(
            C_VerifyFinal(SESSION, expected.as_ptr() as *mut u8, expected.len() as u32),
            CKR_OK,
        );
    }

    /// An empty C_SignUpdate part still enters the multi-part phase (one-shot
    /// blocked) and C_SignFinal then signs the empty message.
    #[test]
    fn empty_update_enters_multipart_phase() {
        let _guard = test_lock::acquire();
        setup();
        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(SESSION, &[]), CKR_OK);
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        assert_eq!(
            C_Sign(SESSION, buf.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_ACTIVE,
        );
        use hmac::Mac;
        let mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&HMAC_KEY_BYTES)
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();
        assert_eq!(sign_final_vec(SESSION).unwrap(), mac);
    }

    // ── Update/Final without Init ───────────────────────────────────────────

    /// §5.13.3/§5.13.4, §5.15.3/§5.15.4 — Update/Final without Init →
    /// CKR_OPERATION_NOT_INITIALIZED; bogus session handle outranks it
    /// (operate-stage require_session!, round-1 S4).
    #[test]
    fn update_final_without_init_or_session() {
        let _guard = test_lock::acquire();
        setup();
        let data = [0u8; 4];
        let mut len: u32 = 64;
        let mut buf = [0u8; 64];

        assert_eq!(s_update(SESSION, &data), CKR_OPERATION_NOT_INITIALIZED);
        assert_eq!(
            C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_NOT_INITIALIZED,
        );
        assert_eq!(v_update(SESSION, &data), CKR_OPERATION_NOT_INITIALIZED);
        assert_eq!(
            C_VerifyFinal(SESSION, buf.as_mut_ptr(), 32),
            CKR_OPERATION_NOT_INITIALIZED,
        );

        assert_eq!(
            C_SignUpdate(BOGUS_SESSION, data.as_ptr() as *mut u8, 4),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_SignFinal(BOGUS_SESSION, buf.as_mut_ptr(), &mut len),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_VerifyUpdate(BOGUS_SESSION, data.as_ptr() as *mut u8, 4),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_VerifyFinal(BOGUS_SESSION, buf.as_mut_ptr(), 32),
            CKR_SESSION_HANDLE_INVALID,
        );
    }

    /// C_SignFinal/C_VerifyFinal with no preceding Update signs/verifies the
    /// empty message (legal per §5.13.4).
    #[test]
    fn final_without_updates_uses_empty_message() {
        let _guard = test_lock::acquire();
        setup();
        use hmac::Mac;
        let mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&HMAC_KEY_BYTES)
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();

        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(sign_final_vec(SESSION).unwrap(), mac);

        assert_eq!(verify_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(
            C_VerifyFinal(SESSION, mac.as_ptr() as *mut u8, mac.len() as u32),
            CKR_OK,
        );
    }

    // ── §5.2 two-call convention on C_SignFinal ─────────────────────────────

    /// Size query (NULL output) and CKR_BUFFER_TOO_SMALL both leave the
    /// multi-part op active; the retry completes with the correct MAC, after
    /// which the op is consumed.
    #[test]
    fn sign_final_buffer_too_small_preserves_state() {
        let _guard = test_lock::acquire();
        setup();
        let msg = b"two-call convention";
        let expected = one_shot_sign(SESSION, CKM_SHA256_HMAC, HMAC_KEY, msg);

        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(SESSION, msg), CKR_OK);

        // Size query: op untouched.
        let mut len: u32 = 0;
        assert_eq!(C_SignFinal(SESSION, std::ptr::null_mut(), &mut len), CKR_OK);
        assert_eq!(len, 32);

        // Short buffer: CKR_BUFFER_TOO_SMALL, required size reported, op alive.
        let mut short = [0u8; 5];
        let mut len: u32 = 5;
        assert_eq!(
            C_SignFinal(SESSION, short.as_mut_ptr(), &mut len),
            CKR_BUFFER_TOO_SMALL,
        );
        assert_eq!(len, 32);

        // Retry with an adequate buffer succeeds and matches the one-shot.
        let mut buf = vec![0u8; 32];
        let mut len: u32 = 32;
        assert_eq!(C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len), CKR_OK);
        assert_eq!(buf, expected);

        // The successful Final consumed the op.
        let mut len: u32 = 32;
        assert_eq!(
            C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_NOT_INITIALIZED,
        );
    }

    // ── Single-part-only mechanisms ─────────────────────────────────────────

    /// C_SignUpdate / C_SignFinal on an op whose mechanism is single-part-only
    /// → CKR_OPERATION_NOT_INITIALIZED (the §5.13.3 return list has no
    /// CKR_MECHANISM_INVALID / CKR_FUNCTION_NOT_SUPPORTED; see
    /// `multipart_op_mech`), and the active op is terminated (a fresh
    /// C_SignInit succeeds immediately afterwards).
    #[test]
    fn single_part_only_mech_returns_spec_code_and_terminates() {
        let _guard = test_lock::acquire();
        setup();
        let data = [0u8; 4];
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        // 0x1 = CKM_RSA_PKCS (raw, digest-less — value from pkcs11t.h; the
        // constant is not defined in constants.rs).
        const CKM_RSA_PKCS_RAW: u32 = 0x0000_0001;
        // Genuinely single-part: raw RSA/ECDSA (caller supplies the digest) and
        // the stateful HSS/XMSS schemes. Pure ML-DSA / SLH-DSA / EdDSA are NOT
        // listed — they gained multi-part buffering (sign_mech_supports_multipart).
        for mech in [CKM_RSA_PKCS_RAW, CKM_ECDSA, CKM_HSS, CKM_XMSS] {
            // SignUpdate path.
            assert_eq!(sign_init(SESSION, mech, HMAC_KEY), CKR_OK, "mech 0x{mech:x}");
            assert_eq!(
                s_update(SESSION, &data),
                CKR_OPERATION_NOT_INITIALIZED,
                "SignUpdate mech 0x{mech:x}"
            );
            // The op was terminated — a new Init is not CKR_OPERATION_ACTIVE.
            assert_eq!(sign_init(SESSION, mech, HMAC_KEY), CKR_OK, "re-init 0x{mech:x}");
            // SignFinal path terminates too.
            assert_eq!(
                C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len),
                CKR_OPERATION_NOT_INITIALIZED,
                "SignFinal mech 0x{mech:x}"
            );
            assert!(!SIGN_STATE.with(|s| s.borrow().contains_key(&SESSION)));

            // Verify side.
            assert_eq!(verify_init(SESSION, mech, HMAC_KEY), CKR_OK);
            assert_eq!(
                v_update(SESSION, &data),
                CKR_OPERATION_NOT_INITIALIZED,
                "VerifyUpdate mech 0x{mech:x}"
            );
            assert_eq!(verify_init(SESSION, mech, HMAC_KEY), CKR_OK);
            assert_eq!(
                C_VerifyFinal(SESSION, buf.as_mut_ptr(), 32),
                CKR_OPERATION_NOT_INITIALIZED,
                "VerifyFinal mech 0x{mech:x}"
            );
            assert!(!VERIFY_STATE.with(|s| s.borrow().contains_key(&SESSION)));
        }
    }

    // ── Cancel / close cleanup ──────────────────────────────────────────────

    /// C_SessionCancel CKF_SIGN (0x800) / CKF_VERIFY (0x2000) clears the op
    /// state AND the new accumulators.
    #[test]
    fn session_cancel_clears_multipart_accumulators() {
        let _guard = test_lock::acquire();
        setup();
        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(SESSION, b"doomed"), CKR_OK);
        assert_eq!(C_SessionCancel(SESSION, 0x800), CKR_OK);
        assert!(!SIGN_MULTIPART_ACC.with(|s| s.borrow().contains_key(&SESSION)));
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        assert_eq!(
            C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_NOT_INITIALIZED,
        );

        assert_eq!(verify_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(v_update(SESSION, b"doomed"), CKR_OK);
        assert_eq!(C_SessionCancel(SESSION, 0x2000), CKR_OK);
        assert!(!VERIFY_MULTIPART_ACC.with(|s| s.borrow().contains_key(&SESSION)));
        assert_eq!(
            C_VerifyFinal(SESSION, buf.as_mut_ptr(), 32),
            CKR_OPERATION_NOT_INITIALIZED,
        );
    }

    /// C_CloseSession terminates in-flight multi-part sign/verify ops and
    /// drops their accumulators.
    #[test]
    fn close_session_clears_multipart_accumulators() {
        let _guard = test_lock::acquire();
        setup();
        let doomed: u32 = 0x5434_1002;
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                doomed,
                crate::state::SessionState { slot_id: 0, rw_session: true },
            );
        });
        assert_eq!(sign_init(doomed, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(doomed, b"bye"), CKR_OK);
        assert_eq!(verify_init(doomed, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(v_update(doomed, b"bye"), CKR_OK);

        assert_eq!(C_CloseSession(doomed), CKR_OK);
        assert!(!SIGN_STATE.with(|s| s.borrow().contains_key(&doomed)));
        assert!(!VERIFY_STATE.with(|s| s.borrow().contains_key(&doomed)));
        assert!(!SIGN_MULTIPART_ACC.with(|s| s.borrow().contains_key(&doomed)));
        assert!(!VERIFY_MULTIPART_ACC.with(|s| s.borrow().contains_key(&doomed)));
    }

    // ── VerifyFinal failure codes (same as one-shot) ────────────────────────

    /// C_VerifyFinal returns CKR_SIGNATURE_INVALID for a tampered MAC and
    /// CKR_SIGNATURE_LEN_RANGE for a wrong-length one, exactly like the
    /// one-shot C_Verify.
    #[test]
    fn verify_final_signature_invalid_and_len_range() {
        let _guard = test_lock::acquire();
        setup();
        let msg = b"verify failure codes";
        let mut mac = one_shot_sign(SESSION, CKM_SHA256_HMAC, HMAC_KEY, msg);

        mac[0] ^= 0xFF;
        assert_eq!(
            multipart_verify(SESSION, CKM_SHA256_HMAC, HMAC_KEY, &[&msg[..]], &mac),
            CKR_SIGNATURE_INVALID,
        );
        mac[0] ^= 0xFF;

        assert_eq!(
            multipart_verify(SESSION, CKM_SHA256_HMAC, HMAC_KEY, &[&msg[..]], &mac[..31]),
            CKR_SIGNATURE_LEN_RANGE,
        );
    }

    // ── Hash-composite RSA / ECDSA ──────────────────────────────────────────

    /// RSA + ECDSA hash-composite mechanisms through a real logged-in session:
    /// PKCS#1 v1.5 multi-part == one-shot byte-equal (deterministic), PSS and
    /// ECDSA multi-part signatures verify (one-shot and multi-part), in both
    /// sign→verify directions.
    #[test]
    fn rsa_ecdsa_hash_composite_multipart() {
        let _guard = test_lock::acquire();
        use crate::native::keygen::{generate_ecdsa_keypair, generate_rsa_keypair, EccCurve};
        use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
        let _ = finalize();
        init().unwrap();
        let sess = bootstrap_default_token(0, "so", "user", "t4-multipart").unwrap();

        let msg = b"hash-composite multi-part message";
        let parts: [&[u8]; 3] = [&msg[..5], &[], &msg[5..]];

        // RSA PKCS#1 v1.5 — deterministic: byte-equal with the one-shot.
        let (rsa_pub, rsa_prv) = generate_rsa_keypair(sess, 2048, b"t4-rsa", "t4-rsa").unwrap();
        for mech in [CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS] {
            let expected = one_shot_sign(sess, mech, rsa_prv, msg);
            let sig = multipart_sign(sess, mech, rsa_prv, &parts);
            assert_eq!(sig, expected, "PKCS#1 v1.5 mech 0x{mech:x} not byte-equal");
            assert_eq!(
                multipart_verify(sess, mech, rsa_pub, &parts, &sig),
                CKR_OK,
                "multi-part verify mech 0x{mech:x}"
            );
        }

        // RSA-PSS — randomized salt: verify-validates in both directions.
        let pss_sig = multipart_sign(sess, CKM_SHA256_RSA_PKCS_PSS, rsa_prv, &parts);
        assert_eq!(
            one_shot_verify(sess, CKM_SHA256_RSA_PKCS_PSS, rsa_pub, msg, &pss_sig),
            CKR_OK,
            "one-shot verify of multi-part PSS signature"
        );
        let pss_one_shot = one_shot_sign(sess, CKM_SHA256_RSA_PKCS_PSS, rsa_prv, msg);
        assert_eq!(
            multipart_verify(sess, CKM_SHA256_RSA_PKCS_PSS, rsa_pub, &parts, &pss_one_shot),
            CKR_OK,
            "multi-part verify of one-shot PSS signature"
        );

        // ECDSA (hashed) — randomized k: verify-validates in both directions.
        let (ec_pub, ec_prv) =
            generate_ecdsa_keypair(sess, EccCurve::P256, b"t4-ec", "t4-ec").unwrap();
        let ec_sig = multipart_sign(sess, CKM_ECDSA_SHA256, ec_prv, &parts);
        assert_eq!(
            one_shot_verify(sess, CKM_ECDSA_SHA256, ec_pub, msg, &ec_sig),
            CKR_OK,
            "one-shot verify of multi-part ECDSA signature"
        );
        let ec_one_shot = one_shot_sign(sess, CKM_ECDSA_SHA256, ec_prv, msg);
        assert_eq!(
            multipart_verify(sess, CKM_ECDSA_SHA256, ec_pub, &parts, &ec_one_shot),
            CKR_OK,
            "multi-part verify of one-shot ECDSA signature"
        );
        // SHA-3 composite (T1 widened): multi-part sign → multi-part verify.
        let ec_sig3 = multipart_sign(sess, CKM_ECDSA_SHA3_256, ec_prv, &parts);
        assert_eq!(
            multipart_verify(sess, CKM_ECDSA_SHA3_256, ec_pub, &parts, &ec_sig3),
            CKR_OK,
            "SHA3-composite ECDSA multi-part round-trip"
        );

        close_session(sess).unwrap();
    }
}

// ----------------------------------------------------------------------------
// T5 — Message-based AEAD streaming tests (C_EncryptMessageBegin/Next,
// C_DecryptMessageBegin/Next)
// ----------------------------------------------------------------------------
//
// CK_GCM_MESSAGE_PARAMS embeds WASM32 4-byte pointers and cannot be built in
// native 64-bit tests, so these tests drive `message_begin_core` /
// `encrypt_message_next_core` / `decrypt_message_next_core` — everything
// below the params-parsing wrappers — with real pointers, plus the real
// C_MessageEncryptInit / C_SessionCancel / C_CloseSession entry points.
#[cfg(test)]
mod message_stream_ffi_tests {
    use super::*;
    use crate::native::test_lock;

    const KEY_HANDLE: u32 = 0x5435_0002;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn install_gcm_key(key: &[u8]) {
        crate::state::set_initialized(true);
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, key.to_vec());
            attrs.insert(CKA_ENCRYPT, vec![1]);
            attrs.insert(CKA_DECRYPT, vec![1]);
            o.borrow_mut().insert(KEY_HANDLE, attrs);
        });
    }

    fn install_session(h: u32) {
        SESSIONS.with(|s| {
            s.borrow_mut()
                .insert(h, crate::state::SessionState { slot_id: 0, rw_session: true });
        });
    }

    fn init_msg_op(session: u32, encrypt: bool) {
        let mech = [CKM_AES_GCM, 0u32, 0u32];
        let rv = if encrypt {
            C_MessageEncryptInit(session, mech.as_ptr() as *mut u8, KEY_HANDLE)
        } else {
            C_MessageDecryptInit(session, mech.as_ptr() as *mut u8, KEY_HANDLE)
        };
        assert_eq!(rv, CKR_OK);
    }

    /// Split `data` into parts of `sizes` (cycled; 0 yields an explicit
    /// empty part).
    fn split<'a>(data: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
        let mut parts: Vec<&[u8]> = Vec::new();
        let mut off = 0;
        let mut i = 0;
        while off < data.len() {
            let n = sizes[i % sizes.len()].min(data.len() - off);
            parts.push(&data[off..off + n]);
            off += n;
            i += 1;
        }
        if parts.is_empty() {
            parts.push(&data[..0]);
        }
        parts
    }

    /// Drive Begin + one Next per part (size query first, then copy-out).
    /// Returns (ciphertext, tag).
    fn msg_encrypt(
        session: u32,
        iv: &[u8],
        aad: &[u8],
        tag_bits: u32,
        parts: &[&[u8]],
    ) -> Result<(Vec<u8>, Vec<u8>), u32> {
        let rv = message_begin_core(session, iv, aad, tag_bits, true);
        if rv != CKR_OK {
            return Err(rv);
        }
        let mut out = Vec::new();
        let mut tag = vec![0u8; (tag_bits / 8) as usize];
        for (i, part) in parts.iter().enumerate() {
            let end = i == parts.len() - 1;
            let mut need: u32 = 0;
            let rv = unsafe {
                encrypt_message_next_core(
                    session,
                    part.as_ptr(),
                    part.len() as u32,
                    std::ptr::null_mut(),
                    &mut need,
                    end,
                    std::ptr::null_mut(),
                )
            };
            if rv != CKR_OK {
                return Err(rv);
            }
            assert_eq!(need as usize, part.len(), "encrypt size query is exact");
            let mut buf = vec![0u8; need as usize];
            let mut len = need;
            let rv = unsafe {
                encrypt_message_next_core(
                    session,
                    part.as_ptr(),
                    part.len() as u32,
                    buf.as_mut_ptr(),
                    &mut len,
                    end,
                    tag.as_mut_ptr(),
                )
            };
            if rv != CKR_OK {
                return Err(rv);
            }
            out.extend_from_slice(&buf[..len as usize]);
        }
        Ok((out, tag))
    }

    /// Drive decrypt Begin/Next. Asserts the verify-then-release contract:
    /// intermediate parts emit ZERO bytes; the final part emits the whole
    /// message only after the tag verifies.
    fn msg_decrypt(
        session: u32,
        iv: &[u8],
        aad: &[u8],
        tag_bits: u32,
        parts: &[&[u8]],
        tag: &[u8],
    ) -> Result<Vec<u8>, u32> {
        let rv = message_begin_core(session, iv, aad, tag_bits, false);
        if rv != CKR_OK {
            return Err(rv);
        }
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut out = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let end = i == parts.len() - 1;
            let mut need: u32 = 0;
            let rv = unsafe {
                decrypt_message_next_core(
                    session,
                    part.as_ptr(),
                    part.len() as u32,
                    std::ptr::null_mut(),
                    &mut need,
                    end,
                    std::ptr::null(),
                )
            };
            if rv != CKR_OK {
                return Err(rv);
            }
            if end {
                assert_eq!(need as usize, total, "final size query = whole message");
            }
            let mut buf = vec![0u8; need as usize];
            let mut len = need;
            let rv = unsafe {
                decrypt_message_next_core(
                    session,
                    part.as_ptr(),
                    part.len() as u32,
                    buf.as_mut_ptr(),
                    &mut len,
                    end,
                    tag.as_ptr(),
                )
            };
            if rv != CKR_OK {
                return Err(rv);
            }
            if !end {
                assert_eq!(len, 0, "no plaintext may be released before the tag verifies");
            }
            out.extend_from_slice(&buf[..len as usize]);
        }
        Ok(out)
    }

    const CHUNKINGS: &[&[usize]] = &[&[1], &[16], &[7, 13], &[5, 0, 9], &[64]];

    /// Chunked == one-shot: SP 800-38D KATs (McGrew–Viega TC4 with AAD and
    /// 12-byte IV; TC5 with 8-byte IV → §7.1 J0 derivation; TC3 without
    /// AAD) across 1-byte / block-aligned / odd / empty-part chunkings and
    /// 96/128-bit tags, plus the decrypt round-trip for each combination.
    #[test]
    fn message_stream_matches_kats_chunked() {
        let _guard = test_lock::acquire();
        let session = 0x5435_1001;
        let key = hex("feffe9928665731c6d6a8f9467308308");
        install_gcm_key(&key);
        install_session(session);
        init_msg_op(session, true);
        init_msg_op(session, false);

        let pt_full = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let cases = [
            // (iv, aad, pt, ct, tag)
            (
                hex("cafebabefacedbaddecaf888"),
                Vec::new(),
                pt_full.clone(),
                hex(
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                     21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                ),
                hex("4d5c2af327cd64a62cf35abd2ba6fab4"),
            ),
            (
                hex("cafebabefacedbaddecaf888"),
                aad.clone(),
                pt_full[..60].to_vec(),
                hex(
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                     21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                ),
                hex("5bc94fbc3221a5db94fae95ae7121a47"),
            ),
            (
                hex("cafebabefacedbad"), // 64-bit IV
                aad.clone(),
                pt_full[..60].to_vec(),
                hex(
                    "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423\
                     73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
                ),
                hex("3612d2e79e3b0785561be14aaca2fccb"),
            ),
        ];
        for (iv, aad, pt, ct, tag) in &cases {
            for sizes in CHUNKINGS {
                for tag_bits in [128u32, 96] {
                    let tag_bytes = (tag_bits / 8) as usize;
                    let (got_ct, got_tag) =
                        msg_encrypt(session, iv, aad, tag_bits, &split(pt, sizes)).unwrap();
                    assert_eq!(&got_ct, ct, "sizes={sizes:?} tag_bits={tag_bits}");
                    assert_eq!(got_tag, tag[..tag_bytes], "sizes={sizes:?} tag_bits={tag_bits}");

                    let got_pt = msg_decrypt(
                        session,
                        iv,
                        aad,
                        tag_bits,
                        &split(ct, sizes),
                        &tag[..tag_bytes],
                    )
                    .unwrap();
                    assert_eq!(&got_pt, pt, "sizes={sizes:?} tag_bits={tag_bits}");
                }
            }
        }
        C_MessageEncryptFinal(session);
        C_MessageDecryptFinal(session);
        let _ = C_CloseSession(session);
    }

    /// Streaming output must byte-match the independent one-shot `aes-gcm`
    /// crate for AES-256, including a many-part message (512 × 64 B). The
    /// O(n) bound itself is pinned deterministically by
    /// `crypto::multipart::tests::gcm_msg_streaming_is_single_pass` via the
    /// keystream-block counter (no flaky wall-clock assertion needed).
    #[test]
    fn message_stream_matches_one_shot_crate_many_parts() {
        let _guard = test_lock::acquire();
        let session = 0x5435_1002;
        let key = [0x42u8; 32];
        install_gcm_key(&key);
        install_session(session);
        init_msg_op(session, true);
        init_msg_op(session, false);

        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit as GcmKeyInit};
        let iv = [0x24u8; 12];
        let aad = b"stream header";
        let pt: Vec<u8> = (0..512usize * 64).map(|i| (i * 31 % 251) as u8).collect();
        let mut one_shot = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(aes_gcm::Nonce::from_slice(&iv), Payload { msg: &pt, aad })
            .unwrap();
        let one_shot_tag = one_shot.split_off(one_shot.len() - 16);

        let parts: Vec<&[u8]> = pt.chunks(64).collect();
        assert_eq!(parts.len(), 512);
        let (ct, tag) = msg_encrypt(session, &iv, aad, 128, &parts).unwrap();
        assert_eq!(ct, one_shot);
        assert_eq!(tag, one_shot_tag);

        let ct_parts: Vec<&[u8]> = ct.chunks(64).collect();
        let round = msg_decrypt(session, &iv, aad, 128, &ct_parts, &tag).unwrap();
        assert_eq!(round, pt);

        C_MessageEncryptFinal(session);
        C_MessageDecryptFinal(session);
        let _ = C_CloseSession(session);
    }

    /// Tampered tag → CKR_ENCRYPTED_DATA_INVALID, the caller's buffer is
    /// untouched (no unauthenticated plaintext escapes), and the message
    /// op is terminated.
    #[test]
    fn message_decrypt_tampered_tag_releases_nothing() {
        let _guard = test_lock::acquire();
        let session = 0x5435_1003;
        let key = [0x11u8; 16];
        install_gcm_key(&key);
        install_session(session);
        init_msg_op(session, true);
        init_msg_op(session, false);

        let iv = [7u8; 12];
        let pt = b"the magic words are squeamish ossifrage";
        let (ct, mut tag) = msg_encrypt(session, &iv, b"aad", 128, &[pt]).unwrap();
        tag[0] ^= 0x80;

        assert_eq!(message_begin_core(session, &iv, b"aad", 128, false), CKR_OK);
        // Feed in two parts; the first must release nothing.
        let (a, b) = ct.split_at(10);
        let mut len: u32 = ct.len() as u32;
        let mut buf = vec![0xAAu8; ct.len()];
        let rv = unsafe {
            decrypt_message_next_core(
                session, a.as_ptr(), a.len() as u32, buf.as_mut_ptr(), &mut len, false,
                std::ptr::null(),
            )
        };
        assert_eq!(rv, CKR_OK);
        assert_eq!(len, 0);
        let mut len: u32 = ct.len() as u32;
        let rv = unsafe {
            decrypt_message_next_core(
                session, b.as_ptr(), b.len() as u32, buf.as_mut_ptr(), &mut len, true,
                tag.as_ptr(),
            )
        };
        assert_eq!(rv, CKR_ENCRYPTED_DATA_INVALID);
        assert!(buf.iter().all(|&x| x == 0xAA), "caller buffer must stay untouched");
        // The withheld plaintext was zeroized and the message terminated.
        MESSAGE_DECRYPT_STATE.with(|s| {
            let m = s.borrow();
            let c = m.get(&session).unwrap();
            assert!(!c.in_message);
            assert!(c.plaintext_acc.is_empty());
            assert!(c.stream.is_none());
        });

        // Untampered round-trip on the same op still works afterwards.
        tag[0] ^= 0x80;
        let parts: Vec<&[u8]> = ct.chunks(13).collect();
        assert_eq!(msg_decrypt(session, &iv, b"aad", 128, &parts, &tag).unwrap(), pt);

        C_MessageEncryptFinal(session);
        C_MessageDecryptFinal(session);
        let _ = C_CloseSession(session);
    }

    /// §5.2 two-call convention on the FINAL part: a NULL-output size query
    /// must not consume state — repeating it returns the same size, and the
    /// copy-out call still succeeds.
    #[test]
    fn message_decrypt_final_size_query_does_not_consume() {
        let _guard = test_lock::acquire();
        let session = 0x5435_1004;
        let key = [0x33u8; 32];
        install_gcm_key(&key);
        install_session(session);
        init_msg_op(session, true);
        init_msg_op(session, false);

        let iv = [1u8; 12];
        let pt = b"forty-two bytes of extremely secret text!";
        let (ct, tag) = msg_encrypt(session, &iv, &[], 96, &[pt]).unwrap();

        assert_eq!(message_begin_core(session, &iv, &[], 96, false), CKR_OK);
        let (a, b) = ct.split_at(17);
        let mut len = 64u32;
        let mut buf = vec![0u8; 64];
        let rv = unsafe {
            decrypt_message_next_core(
                session, a.as_ptr(), a.len() as u32, buf.as_mut_ptr(), &mut len, false,
                std::ptr::null(),
            )
        };
        assert_eq!((rv, len), (CKR_OK, 0));
        // Two size queries in a row — neither consumes.
        for _ in 0..2 {
            let mut need = 0u32;
            let rv = unsafe {
                decrypt_message_next_core(
                    session, b.as_ptr(), b.len() as u32, std::ptr::null_mut(), &mut need, true,
                    tag.as_ptr(),
                )
            };
            assert_eq!((rv, need as usize), (CKR_OK, pt.len()));
        }
        // CKR_BUFFER_TOO_SMALL must not consume either.
        let mut small = 3u32;
        let rv = unsafe {
            decrypt_message_next_core(
                session, b.as_ptr(), b.len() as u32, buf.as_mut_ptr(), &mut small, true,
                tag.as_ptr(),
            )
        };
        assert_eq!((rv, small as usize), (CKR_BUFFER_TOO_SMALL, pt.len()));
        // The real copy-out still succeeds.
        let mut len = buf.len() as u32;
        let rv = unsafe {
            decrypt_message_next_core(
                session, b.as_ptr(), b.len() as u32, buf.as_mut_ptr(), &mut len, true,
                tag.as_ptr(),
            )
        };
        assert_eq!(rv, CKR_OK);
        assert_eq!(&buf[..len as usize], pt);

        C_MessageEncryptFinal(session);
        C_MessageDecryptFinal(session);
        let _ = C_CloseSession(session);
    }

    /// C_SessionCancel CKF_MESSAGE_ENCRYPT (0x2) / CKF_MESSAGE_DECRYPT
    /// (0x4) and C_CloseSession clear the message state (zeroized wipe);
    /// the next part call reports CKR_OPERATION_NOT_INITIALIZED.
    #[test]
    fn message_cancel_and_close_clear_state() {
        let _guard = test_lock::acquire();
        let session = 0x5435_1005;
        let key = [0x55u8; 16];
        install_gcm_key(&key);
        install_session(session);
        let iv = [2u8; 12];
        let part = [9u8; 8];
        let mut len = 16u32;
        let mut buf = [0u8; 16];

        // Mid-message cancel of the encrypt op.
        init_msg_op(session, true);
        assert_eq!(message_begin_core(session, &iv, &[], 128, true), CKR_OK);
        let rv = unsafe {
            encrypt_message_next_core(
                session, part.as_ptr(), part.len() as u32, buf.as_mut_ptr(), &mut len, false,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rv, CKR_OK);
        assert_eq!(C_SessionCancel(session, 0x2), CKR_OK);
        assert!(MESSAGE_ENCRYPT_STATE.with(|s| !s.borrow().contains_key(&session)));
        let rv = unsafe {
            encrypt_message_next_core(
                session, part.as_ptr(), part.len() as u32, buf.as_mut_ptr(), &mut len, true,
                buf.as_mut_ptr(),
            )
        };
        assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);

        // Mid-message cancel of the decrypt op.
        init_msg_op(session, false);
        assert_eq!(message_begin_core(session, &iv, &[], 128, false), CKR_OK);
        let rv = unsafe {
            decrypt_message_next_core(
                session, part.as_ptr(), part.len() as u32, buf.as_mut_ptr(), &mut len, false,
                std::ptr::null(),
            )
        };
        assert_eq!(rv, CKR_OK);
        assert_eq!(C_SessionCancel(session, 0x4), CKR_OK);
        assert!(MESSAGE_DECRYPT_STATE.with(|s| !s.borrow().contains_key(&session)));
        let rv = unsafe {
            decrypt_message_next_core(
                session, part.as_ptr(), part.len() as u32, buf.as_mut_ptr(), &mut len, true,
                buf.as_ptr(),
            )
        };
        assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);

        // C_CloseSession mid-message clears both directions too.
        install_session(session);
        init_msg_op(session, true);
        init_msg_op(session, false);
        assert_eq!(message_begin_core(session, &iv, &[], 128, true), CKR_OK);
        assert_eq!(message_begin_core(session, &iv, &[], 128, false), CKR_OK);
        assert_eq!(C_CloseSession(session), CKR_OK);
        assert!(MESSAGE_ENCRYPT_STATE.with(|s| !s.borrow().contains_key(&session)));
        assert!(MESSAGE_DECRYPT_STATE.with(|s| !s.borrow().contains_key(&session)));
        let rv = unsafe {
            encrypt_message_next_core(
                session, part.as_ptr(), part.len() as u32, buf.as_mut_ptr(), &mut len, false,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED);
    }
}

#[cfg(test)]
mod profile_object_ffi_tests {
    //! PKCS#11 Profiles v3.2 §3 — the token's built-in CKO_PROFILE object
    //! (state::init_profile_objects): findable without login, immutable,
    //! non-copyable, non-destroyable, never client-creatable.
    use super::*;
    use crate::native::test_lock;

    const SESSION: u32 = 0x5439_1001;

    fn setup() {
        crate::state::set_initialized(true);
        crate::state::ensure_slot(0);
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                SESSION,
                crate::state::SessionState { slot_id: 0, rw_session: true },
            );
        });
    }

    fn find_by_class(session: u32, class: u32) -> Vec<u32> {
        // §5.7.7 makes find matching "an exact byte-for-byte match", and a
        // CK_OBJECT_CLASS is a CK_ULONG — 8 bytes on LP64. This helper
        // declared 4, which is a 32-bit caller's template, and stopped
        // matching the moment the profile object started storing its
        // CKA_CLASS at native width like every other object.
        let class_native = class as crate::ck_abi::CK_ULONG;
        let tmpl: [usize; 3] = [
            CKA_CLASS as usize,
            &class_native as *const crate::ck_abi::CK_ULONG as usize,
            core::mem::size_of::<crate::ck_abi::CK_ULONG>(),
        ];
        assert_eq!(
            C_FindObjectsInit(session, tmpl.as_ptr() as *mut u8, 1),
            CKR_OK
        );
        let mut handles = [0u32; 8];
        let mut count = 0u32;
        assert_eq!(
            C_FindObjects(session, handles.as_mut_ptr(), 8, &mut count),
            CKR_OK
        );
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        handles[..count as usize].to_vec()
    }

    /// The Baseline Provider profile object is present at slot creation,
    /// findable WITHOUT login (public object), and carries the right
    /// CKA_PROFILE_ID.
    #[test]
    fn baseline_profile_object_is_public_and_findable() {
        let _guard = test_lock::acquire();
        setup();
        // WS-11 Phase 1 widened this engine's claim from Baseline-only to
        // Baseline+Extended+Authentication+Public-Certificates (see
        // state::supported_profiles) — one CKO_PROFILE object per claim.
        let found = find_by_class(SESSION, CKO_PROFILE);
        assert_eq!(found.len(), 4, "one CKO_PROFILE object per claimed profile");
        let mut ids: Vec<u32> = found
            .iter()
            .map(|h| {
                let profile_id = OBJECTS
                    .with(|o| o.borrow().get(h).and_then(|a| a.get(&CKA_PROFILE_ID).cloned()))
                    .expect("CKA_PROFILE_ID present");
                u32::from_le_bytes([profile_id[0], profile_id[1], profile_id[2], profile_id[3]])
            })
            .collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            vec![
                CKP_BASELINE_PROVIDER,
                CKP_EXTENDED_PROVIDER,
                CKP_AUTHENTICATION_TOKEN,
                CKP_PUBLIC_CERTIFICATES_TOKEN,
            ]
        );
    }

    /// A client can never create its own CKO_PROFILE object — identity is
    /// entirely token-computed (validate_create_template).
    #[test]
    fn client_cannot_create_profile_object() {
        let _guard = test_lock::acquire();
        setup();
        let mut attrs = Attributes::new();
        store_ulong(&mut attrs, CKA_CLASS, CKO_PROFILE);
        store_ulong(&mut attrs, CKA_PROFILE_ID, CKP_EXTENDED_PROVIDER);
        assert_eq!(
            create_object_from_attrs(SESSION, attrs),
            Err(CKR_ATTRIBUTE_READ_ONLY)
        );
    }

    /// The profile object is immutable, non-copyable, and non-destroyable.
    #[test]
    fn profile_object_is_fully_read_only() {
        let _guard = test_lock::acquire();
        setup();
        let h = find_by_class(SESSION, CKO_PROFILE)[0];

        // C_SetAttributeValue: CKA_MODIFIABLE=FALSE → CKR_ACTION_PROHIBITED.
        let updates: Vec<(u32, Vec<u8>)> = vec![(crate::native::keygen::CKA_LABEL, b"x".to_vec())];
        assert_eq!(
            set_attribute_values_from_list(SESSION, h, &updates),
            CKR_ACTION_PROHIBITED
        );

        // C_CopyObject: CKA_COPYABLE=FALSE → CKR_ACTION_PROHIBITED.
        assert_eq!(
            copy_object_from_attrs(SESSION, h, Attributes::new()),
            Err(CKR_ACTION_PROHIBITED)
        );

        // C_DestroyObject: CKA_DESTROYABLE=FALSE → CKR_ACTION_PROHIBITED.
        assert_eq!(C_DestroyObject(SESSION, h), CKR_ACTION_PROHIBITED);
        assert!(
            OBJECTS.with(|o| o.borrow().contains_key(&h)),
            "the profile object must survive the rejected destroy"
        );
    }
}

#[cfg(test)]
mod finalize_object_persistence_ffi_tests {
    //! WS-11 gap: production `C_Finalize` used to unconditionally clear
    //! every object in `OBJECTS`, including token objects and the
    //! built-in `CKO_PROFILE` marker — the same non-conformance
    //! `profile_object_ffi_tests` documents C_InitToken already respects
    //! via CKA_DESTROYABLE. These tests call the real `_C_*` FFI
    //! (not `test_lock`'s reset helper) so they exercise production
    //! `C_Finalize` exactly as a browser session does.
    use super::*;

    // native::keygen re-exports these from constants.rs as private imports
    // (fine for that module's own use, not for an outside caller) — local
    // copies rather than fighting visibility for a handful of test-only
    // values. CKA_ID and CKO_DATA have no `pub` copy anywhere else in this
    // crate at all; values per pkcs11t-canonical-v3.2.h.
    const CKA_ID: u32 = 0x0000_0102;
    const CKA_KEY_TYPE: u32 = 0x0000_0100;
    const CKA_VALUE: u32 = 0x0000_0011;
    const CKA_LABEL: u32 = 0x0000_0003;
    const CKK_GENERIC_SECRET: u32 = 0x0000_0010;
    const CKO_DATA: u32 = 0x0000_0000;

    fn boot_and_login() -> (u32, u32) {
        assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
        crate::state::ensure_slot(0);
        let so_pin = b"12345678";
        assert_eq!(
            C_InitToken(0, so_pin.as_ptr() as *mut u8, so_pin.len() as u32, [0u8; 32].as_mut_ptr()),
            CKR_OK
        );
        let mut h_session = 0u32;
        assert_eq!(
            C_OpenSession(0, 0x00000004 | 0x00000002, std::ptr::null_mut(), std::ptr::null_mut(), &mut h_session),
            CKR_OK
        );
        // §5.6.1 — the token has no user PIN yet after a fresh C_InitToken;
        // it must be set by the SO before a USER can log in (same sequence
        // hub-side hsm_openUserSession follows: SO login -> C_InitPIN ->
        // logout -> USER login).
        assert_eq!(C_Login(h_session, 0, so_pin.as_ptr() as *mut u8, so_pin.len() as u32), CKR_OK);
        let user_pin = b"user1234";
        assert_eq!(C_InitPIN(h_session, user_pin.as_ptr() as *mut u8, user_pin.len() as u32), CKR_OK);
        assert_eq!(C_Logout(h_session), CKR_OK);
        assert_eq!(C_Login(h_session, 1, user_pin.as_ptr() as *mut u8, user_pin.len() as u32), CKR_OK);
        (0, h_session)
    }

    /// A CKA_TOKEN=TRUE object created before Finalize is still findable,
    /// by the SAME handle, after Finalize -> Initialize -> a fresh session.
    #[test]
    fn token_object_survives_finalize_initialize_cycle() {
        let _guard = crate::native::test_lock::acquire();
        let (slot_id, h_session) = boot_and_login();

        let id_bytes = b"persist-probe";
        let value_bytes = [0x42u8; 16];
        let class = CKO_SECRET_KEY;
        let key_type = CKK_GENERIC_SECRET;
        let attrs: Vec<(u32, *const u8, usize)> = vec![
            (CKA_CLASS, &class as *const _ as *const u8, std::mem::size_of_val(&class)),
            (CKA_KEY_TYPE, &key_type as *const _ as *const u8, std::mem::size_of_val(&key_type)),
            (CKA_TOKEN, [1u8].as_ptr(), 1),
            (CKA_ID, id_bytes.as_ptr(), id_bytes.len()),
            (CKA_VALUE, value_bytes.as_ptr(), value_bytes.len()),
        ];
        let tmpl: Vec<usize> = attrs
            .iter()
            .flat_map(|(t, p, l)| [*t as usize, *p as usize, *l])
            .collect();
        let mut h_object = 0u32;
        assert_eq!(
            C_CreateObject(h_session, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h_object),
            CKR_OK
        );
        assert!(h_object > 0);

        assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
        assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
        let mut h_session2 = 0u32;
        assert_eq!(
            C_OpenSession(slot_id, 0x00000004, std::ptr::null_mut(), std::ptr::null_mut(), &mut h_session2),
            CKR_OK
        );

        let still_there = OBJECTS.with(|o| o.borrow().contains_key(&h_object));
        assert!(still_there, "token object must survive Finalize/Initialize (PKCS#11 v3.2 §5.4.1/§5.4.2)");

        let id_type = CKA_ID;
        let tmpl2: [usize; 3] = [id_type as usize, id_bytes.as_ptr() as usize, id_bytes.len()];
        assert_eq!(C_FindObjectsInit(h_session2, tmpl2.as_ptr() as *mut u8, 1), CKR_OK);
        let mut handles = [0u32; 4];
        let mut count = 0u32;
        assert_eq!(C_FindObjects(h_session2, handles.as_mut_ptr(), 4, &mut count), CKR_OK);
        assert_eq!(C_FindObjectsFinal(h_session2), CKR_OK);
        assert_eq!(count, 1, "the surviving token object must be findable post-reload");
        assert_eq!(handles[0], h_object, "its handle must not have changed");
    }

    /// A session object (CKA_TOKEN default/FALSE) does NOT survive
    /// Finalize -- only token objects are exempted from the wipe.
    #[test]
    fn session_object_does_not_survive_finalize() {
        let _guard = crate::native::test_lock::acquire();
        let (_slot_id, h_session) = boot_and_login();

        let value_bytes = [0x99u8; 16];
        let class = CKO_SECRET_KEY;
        let key_type = CKK_GENERIC_SECRET;
        let attrs: Vec<(u32, *const u8, usize)> = vec![
            (CKA_CLASS, &class as *const _ as *const u8, std::mem::size_of_val(&class)),
            (CKA_KEY_TYPE, &key_type as *const _ as *const u8, std::mem::size_of_val(&key_type)),
            (CKA_VALUE, value_bytes.as_ptr(), value_bytes.len()),
        ];
        let tmpl: Vec<usize> = attrs
            .iter()
            .flat_map(|(t, p, l)| [*t as usize, *p as usize, *l])
            .collect();
        let mut h_object = 0u32;
        assert_eq!(
            C_CreateObject(h_session, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h_object),
            CKR_OK
        );

        assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);

        assert!(
            !OBJECTS.with(|o| o.borrow().contains_key(&h_object)),
            "a session object must NOT survive C_Finalize"
        );
    }

    /// NEXT_HANDLE must not reset across Finalize: a surviving token
    /// object's handle must never be reissued to a freshly-created object.
    #[test]
    fn handle_counter_does_not_collide_after_finalize() {
        let _guard = crate::native::test_lock::acquire();
        let (slot_id, h_session) = boot_and_login();

        let class = CKO_DATA;
        let label = b"survivor";
        let attrs: Vec<(u32, *const u8, usize)> = vec![
            (CKA_CLASS, &class as *const _ as *const u8, std::mem::size_of_val(&class)),
            (CKA_TOKEN, [1u8].as_ptr(), 1),
            (CKA_LABEL, label.as_ptr(), label.len()),
        ];
        let tmpl: Vec<usize> = attrs
            .iter()
            .flat_map(|(t, p, l)| [*t as usize, *p as usize, *l])
            .collect();
        let mut h_survivor = 0u32;
        assert_eq!(
            C_CreateObject(h_session, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h_survivor),
            CKR_OK
        );

        assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
        assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
        let mut h_session2 = 0u32;
        assert_eq!(
            C_OpenSession(slot_id, 0x00000004, std::ptr::null_mut(), std::ptr::null_mut(), &mut h_session2),
            CKR_OK
        );

        let label2 = b"newcomer";
        let attrs2: Vec<(u32, *const u8, usize)> = vec![
            (CKA_CLASS, &class as *const _ as *const u8, std::mem::size_of_val(&class)),
            (CKA_LABEL, label2.as_ptr(), label2.len()),
        ];
        let tmpl2: Vec<usize> = attrs2
            .iter()
            .flat_map(|(t, p, l)| [*t as usize, *p as usize, *l])
            .collect();
        let mut h_newcomer = 0u32;
        assert_eq!(
            C_CreateObject(h_session2, tmpl2.as_ptr() as *mut u8, attrs2.len() as u32, &mut h_newcomer),
            CKR_OK
        );

        assert_ne!(h_newcomer, h_survivor, "the new object must not reuse the surviving object's handle");
        assert!(
            OBJECTS.with(|o| o.borrow().contains_key(&h_survivor)),
            "the survivor must still be intact, not silently overwritten by the collision"
        );
    }
}

#[cfg(test)]
mod rsa_pkcs_wrap_ffi_tests {
    //! WS-11 Phase 1 — mechanism_info advertised CKF_WRAP|CKF_UNWRAP for
    //! CKM_RSA_PKCS with no dispatch arm behind it (Extended Provider,
    //! EXT-M-1-32). Proves the real round trip, both key sizes the widened
    //! 512-16384 range now spans at its edges.
    use super::*;
    use crate::native::test_lock;

    /// A real, USER-logged-in session — needed because the wrapping key
    /// pair's private half is CKA_PRIVATE=TRUE, invisible to
    /// can_access_object without a login (unlike profile_object_ffi_tests'
    /// setup(), which only ever touches public objects). Same
    /// C_InitToken -> SO login -> C_InitPIN -> logout -> USER login
    /// sequence as finalize_object_persistence_ffi_tests::boot_and_login,
    /// duplicated locally per this file's existing per-module test-helper
    /// convention.
    fn setup_session() -> u32 {
        assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
        crate::state::ensure_slot(0);
        let so_pin = b"12345678";
        assert_eq!(
            C_InitToken(0, so_pin.as_ptr() as *mut u8, so_pin.len() as u32, [0u8; 32].as_mut_ptr()),
            CKR_OK
        );
        let mut session = 0u32;
        assert_eq!(
            C_OpenSession(0, 0x00000004 | 0x00000002, std::ptr::null_mut(), std::ptr::null_mut(), &mut session),
            CKR_OK
        );
        assert_eq!(C_Login(session, 0, so_pin.as_ptr() as *mut u8, so_pin.len() as u32), CKR_OK);
        let user_pin = b"user1234";
        assert_eq!(C_InitPIN(session, user_pin.as_ptr() as *mut u8, user_pin.len() as u32), CKR_OK);
        assert_eq!(C_Logout(session), CKR_OK);
        assert_eq!(C_Login(session, 1, user_pin.as_ptr() as *mut u8, user_pin.len() as u32), CKR_OK);
        session
    }

    fn wrap_unwrap_round_trip(rsa_bits: u32) {
        let _guard = test_lock::acquire();
        let session = setup_session();

        // native::keygen::generate_rsa_keypair deliberately stays scoped to
        // 2048-4096 (its own tested boundary, unrelated to this test — see
        // its rsa_invalid_bits_returns_err test) even though mechanism_info
        // now advertises 512-16384 for the raw FFI C_GenerateKeyPair
        // dispatch this fixes wrap/unwrap for; this helper is only used at
        // rsa_bits values within its own supported range.
        let (h_pub, h_priv) =
            crate::native::keygen::generate_rsa_keypair(session, rsa_bits, b"wrap-kek", "wrap-kek")
                .expect("RSA keygen for the wrapping key pair");

        let h_secret = crate::native::keygen::generate_aes_key(session, 256, b"payload", "payload")
            .expect("AES-256 payload key");
        // CKM_RSA_PKCS wraps the RAW key value (§6.7) — must fit the
        // PKCS1v15 padding envelope (modulus_bytes - 11), true for AES-256
        // (32 bytes) against every RSA size this test exercises.
        assert_eq!(crate::state::set_object_attr_checked(h_secret, CKA_EXTRACTABLE, vec![1]), Ok(()));

        let mech: [usize; 3] = [CKM_RSA_PKCS as usize, 0, 0];
        let mut wrapped_len = 0u32;
        assert_eq!(
            C_WrapKey(
                session,
                mech.as_ptr() as *mut u8,
                h_pub,
                h_secret,
                std::ptr::null_mut(),
                &mut wrapped_len
            ),
            CKR_OK
        );
        assert_eq!(wrapped_len as usize, rsa_bits as usize / 8, "PKCS1v15-wrapped output is one modulus wide");
        let mut wrapped = vec![0u8; wrapped_len as usize];
        assert_eq!(
            C_WrapKey(session, mech.as_ptr() as *mut u8, h_pub, h_secret, wrapped.as_mut_ptr(), &mut wrapped_len),
            CKR_OK
        );

        let class = CKO_SECRET_KEY;
        let key_type = CKK_AES;
        let attrs: Vec<(u32, *const u8, usize)> = vec![
            (CKA_CLASS, &class as *const _ as *const u8, std::mem::size_of_val(&class)),
            (CKA_KEY_TYPE, &key_type as *const _ as *const u8, std::mem::size_of_val(&key_type)),
        ];
        let tmpl: Vec<usize> =
            attrs.iter().flat_map(|(t, p, l)| [*t as usize, *p as usize, *l]).collect();
        let mut h_unwrapped = 0u32;
        assert_eq!(
            C_UnwrapKey(
                session,
                mech.as_ptr() as *mut u8,
                h_priv,
                wrapped.as_mut_ptr(),
                wrapped.len() as u32,
                tmpl.as_ptr() as *mut u8,
                attrs.len() as u32,
                &mut h_unwrapped
            ),
            CKR_OK
        );

        let original = OBJECTS
            .with(|o| o.borrow().get(&h_secret).and_then(|a| a.get(&CKA_VALUE).cloned()))
            .expect("original AES key value present");
        let round_tripped = OBJECTS
            .with(|o| o.borrow().get(&h_unwrapped).and_then(|a| a.get(&CKA_VALUE).cloned()))
            .expect("unwrapped AES key value present");
        assert_eq!(round_tripped, original, "unwrapped key must equal the original 32-byte AES value");
    }

    #[test]
    fn rsa_2048_pkcs_wrap_unwrap_round_trips_aes256() {
        wrap_unwrap_round_trip(2048);
    }

    /// The 512-16384 range mechanism_info now advertises for
    /// CKM_RSA_PKCS_KEY_PAIR_GEN is backed by the raw FFI dispatch
    /// (C_GenerateKeyPair's own CKA_MODULUS_BITS check), independent of
    /// native::keygen::generate_rsa_keypair's separate 2048-4096 scope.
    #[test]
    fn ffi_keygen_honors_the_widened_512_to_16384_range() {
        let _guard = test_lock::acquire();
        let session = setup_session();

        let mech: [usize; 3] = [CKM_RSA_PKCS_KEY_PAIR_GEN as usize, 0, 0];
        // CKA_MODULUS_BITS is a CK_ULONG — get_attr_ulong strictly requires
        // ulValueLen == sizeof(CK_ULONG) (native width, 8 bytes on this
        // 64-bit host) and returns None (not an error) on any other length,
        // which the keygen dispatch's own `.unwrap_or(2048)` then silently
        // papers over. A raw u32 (4 bytes) here would fail width-matching
        // and default to 2048 regardless of the value supplied, making both
        // assertions below pass for the wrong reason.
        let bits: usize = 512;
        let pub_attrs: Vec<(u32, *const u8, usize)> = vec![(
            CKA_MODULUS_BITS,
            &bits as *const _ as *const u8,
            std::mem::size_of_val(&bits),
        )];
        let pub_tmpl: Vec<usize> =
            pub_attrs.iter().flat_map(|(t, p, l)| [*t as usize, *p as usize, *l]).collect();
        let mut h_pub = 0u32;
        let mut h_priv = 0u32;
        assert_eq!(
            C_GenerateKeyPair(
                session,
                mech.as_ptr() as *mut u8,
                pub_tmpl.as_ptr() as *mut u8,
                pub_attrs.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut h_pub,
                &mut h_priv,
            ),
            CKR_OK,
            "512-bit RSA keygen must succeed now that mechanism_info advertises it"
        );

        let too_small: usize = 256;
        let bad_attrs: Vec<(u32, *const u8, usize)> = vec![(
            CKA_MODULUS_BITS,
            &too_small as *const _ as *const u8,
            std::mem::size_of_val(&too_small),
        )];
        let bad_tmpl: Vec<usize> =
            bad_attrs.iter().flat_map(|(t, p, l)| [*t as usize, *p as usize, *l]).collect();
        let mut h_pub2 = 0u32;
        let mut h_priv2 = 0u32;
        assert_ne!(
            C_GenerateKeyPair(
                session,
                mech.as_ptr() as *mut u8,
                bad_tmpl.as_ptr() as *mut u8,
                bad_attrs.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut h_pub2,
                &mut h_priv2,
            ),
            CKR_OK,
            "below-512-bit RSA keygen must still be rejected"
        );
    }
}

#[cfg(test)]
mod find_objects_ordering_ffi_tests {
    //! WS-11 Phase 1 (D3) — §5.7.8 specifies no C_FindObjects result order,
    //! but OBJECTS is a HashMap, so iteration order used to be arbitrary.
    //! CERT-M-1-32 assumes application objects surface before the token's
    //! own CKO_PROFILE markers; this proves that ordering is now stable
    //! across repeated runs, not a one-off pass.
    use super::*;
    use crate::native::test_lock;

    // See finalize_object_persistence_ffi_tests' identical comment: these
    // are private re-exports in native::keygen, not reachable from here.
    const CKA_LABEL: u32 = 0x0000_0003;
    const CKO_DATA: u32 = 0x0000_0000;

    #[test]
    fn application_objects_precede_profile_objects_and_order_is_stable() {
        let _guard = test_lock::acquire();
        crate::state::set_initialized(true);
        crate::state::ensure_slot(0);
        let session = 0x5439_3001;
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                session,
                crate::state::SessionState { slot_id: 0, rw_session: true },
            );
        });

        // Two public CKO_DATA objects, created in a known order.
        let mut app_handles = Vec::new();
        for label in [b"first".as_slice(), b"second".as_slice()] {
            let class = CKO_DATA;
            let attrs: Vec<(u32, *const u8, usize)> = vec![
                (CKA_CLASS, &class as *const _ as *const u8, std::mem::size_of_val(&class)),
                (CKA_TOKEN, [1u8].as_ptr(), 1),
                (CKA_LABEL, label.as_ptr(), label.len()),
            ];
            let tmpl: Vec<usize> =
                attrs.iter().flat_map(|(t, p, l)| [*t as usize, *p as usize, *l]).collect();
            let mut h = 0u32;
            assert_eq!(
                C_CreateObject(session, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h),
                CKR_OK
            );
            app_handles.push(h);
        }

        // Find everything public and token-resident: the 2 CKO_DATA objects
        // plus this build's 4 CKO_PROFILE markers.
        let tmpl: [usize; 3] = [CKA_TOKEN as usize, [1u8].as_ptr() as usize, 1];
        assert_eq!(C_FindObjectsInit(session, tmpl.as_ptr() as *mut u8, 1), CKR_OK);
        let mut handles = [0u32; 8];
        let mut count = 0u32;
        assert_eq!(C_FindObjects(session, handles.as_mut_ptr(), 8, &mut count), CKR_OK);
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        assert_eq!(count, 6, "2 application objects + 4 profile objects");

        let found = &handles[..count as usize];
        assert_eq!(
            &found[..2],
            app_handles.as_slice(),
            "application objects must sort first, by creation order"
        );
        for h in &found[2..] {
            let class = OBJECTS
                .with(|o| crate::state::get_object_attr_u32_from(o.borrow().get(h).unwrap(), CKA_CLASS));
            assert_eq!(class, Some(CKO_PROFILE), "everything after must be a profile marker");
        }

        // Repeat: order must be identical, not merely "profiles last" by luck.
        assert_eq!(C_FindObjectsInit(session, tmpl.as_ptr() as *mut u8, 1), CKR_OK);
        let mut handles2 = [0u32; 8];
        let mut count2 = 0u32;
        assert_eq!(C_FindObjects(session, handles2.as_mut_ptr(), 8, &mut count2), CKR_OK);
        assert_eq!(C_FindObjectsFinal(session), CKR_OK);
        assert_eq!(&handles[..count as usize], &handles2[..count2 as usize], "order must be stable across repeated finds");
    }
}

#[cfg(test)]
mod generic_prehash_mech_ffi_tests {
    //! PKCS#11 v3.2 §6.67.7/§6.69.7 — the GENERIC pre-hash mechanisms
    //! (CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA) end-to-end through the real
    //! FFI sign/verify path: CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash parsing,
    //! remap onto the hash-specific mechanism, and the negative-param cases.
    use super::*;
    use crate::native::test_lock;

    /// ML-DSA private keys are CKA_PRIVATE — unlike the other ffi test
    /// modules (which use public HMAC/AES keys and can hand-insert a bare
    /// SessionState), this needs a REAL logged-in user session. Mirrors
    /// `native::parity::fresh_session` / the bootstrap pattern used by
    /// every native::* sign/keygen test.
    fn setup() -> (u32, u32, u32) {
        let _ = crate::native::session::finalize();
        crate::native::session::init().unwrap();
        let session =
            crate::native::session::bootstrap_default_token(0, "so", "user", "prehash-test")
                .unwrap();
        SIGN_STATE.with(|s| s.borrow_mut().remove(&session));
        VERIFY_STATE.with(|s| s.borrow_mut().remove(&session));
        let (pub_h, priv_h) = crate::native::generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"t", "t")
            .expect("ml-dsa-65 keygen");
        (session, pub_h, priv_h)
    }

    /// Build a CK_MECHANISM(CKM_HASH_ML_DSA, &CK_HASH_SIGN_ADDITIONAL_CONTEXT)
    /// pair at native width, matching the `[usize; N]` convention the rest
    /// of this test suite uses for the wasm32-shaped struct layout.
    fn hash_mech(base: u32, hash: u32) -> ([usize; 3], [usize; 4]) {
        let ctx: [usize; 4] = [0 /* CKH_HEDGE_PREFERRED */, 0, 0, hash as usize];
        let usz = std::mem::size_of::<usize>();
        let m: [usize; 3] = [base as usize, 0, 4 * usz];
        (m, ctx)
    }

    #[test]
    fn generic_hash_ml_dsa_sign_verify_round_trip() {
        let _guard = test_lock::acquire();
        let (session, pub_h, priv_h) = setup();
        let msg = b"generic pre-hash ML-DSA end-to-end";

        let (mut m, ctx) = hash_mech(CKM_HASH_ML_DSA, CKM_SHA256);
        m[1] = ctx.as_ptr() as usize;
        assert_eq!(C_SignInit(session, m.as_mut_ptr() as *mut u8, priv_h), CKR_OK);
        let mut sig = vec![0u8; 8192];
        let mut sig_len = sig.len() as u32;
        assert_eq!(
            C_Sign(session, msg.as_ptr() as *mut u8, msg.len() as u32, sig.as_mut_ptr(), &mut sig_len),
            CKR_OK
        );
        sig.truncate(sig_len as usize);

        let (mut m2, ctx2) = hash_mech(CKM_HASH_ML_DSA, CKM_SHA256);
        m2[1] = ctx2.as_ptr() as usize;
        assert_eq!(C_VerifyInit(session, m2.as_mut_ptr() as *mut u8, pub_h), CKR_OK);
        assert_eq!(
            C_Verify(session, msg.as_ptr() as *mut u8, msg.len() as u32, sig.as_ptr() as *mut u8, sig.len() as u32),
            CKR_OK
        );

        // Interop: a signature made via the GENERIC mechanism verifies
        // under the SPECIFIC mechanism name too (remap makes them the same
        // internal mech_type).
        let mut m3: [usize; 3] = [CKM_HASH_ML_DSA_SHA256 as usize, 0, 0];
        assert_eq!(C_VerifyInit(session, m3.as_mut_ptr() as *mut u8, pub_h), CKR_OK);
        assert_eq!(
            C_Verify(session, msg.as_ptr() as *mut u8, msg.len() as u32, sig.as_ptr() as *mut u8, sig.len() as u32),
            CKR_OK
        );
    }

    #[test]
    fn generic_hash_slh_dsa_requires_the_hash_param() {
        let _guard = test_lock::acquire();
        let (session, _pub_h, priv_h) = setup();
        // No parameter at all — the generic mechanism cannot select a digest.
        let mut m: [usize; 3] = [CKM_HASH_SLH_DSA as usize, 0, 0];
        assert_eq!(
            C_SignInit(session, m.as_mut_ptr() as *mut u8, priv_h),
            CKR_MECHANISM_PARAM_INVALID
        );
    }

    #[test]
    fn generic_hash_ml_dsa_rejects_unknown_hash_value() {
        let _guard = test_lock::acquire();
        let (session, _pub_h, priv_h) = setup();
        // 0xdead_beef names no real digest mechanism.
        let (mut m, ctx) = hash_mech(CKM_HASH_ML_DSA, 0xdead_beef);
        m[1] = ctx.as_ptr() as usize;
        assert_eq!(
            C_SignInit(session, m.as_mut_ptr() as *mut u8, priv_h),
            CKR_MECHANISM_PARAM_INVALID
        );
    }

    #[test]
    fn generic_hash_ml_dsa_rejects_shake_as_hash_value() {
        let _guard = test_lock::acquire();
        let (session, _pub_h, priv_h) = setup();
        // SHAKE128 has no standalone digest CKM_ identifier — only reachable
        // via its own dedicated CKM_HASH_ML_DSA_SHAKE128 mechanism.
        let (mut m, ctx) = hash_mech(CKM_HASH_ML_DSA, CKM_HASH_ML_DSA_SHAKE128);
        m[1] = ctx.as_ptr() as usize;
        assert_eq!(
            C_SignInit(session, m.as_mut_ptr() as *mut u8, priv_h),
            CKR_MECHANISM_PARAM_INVALID
        );
    }
}

#[cfg(test)]
mod ecdh_cofactor_ffi_tests {
    //! PKCS#11 v3.2 §6.3.18, Table 79 ("ECDH with cofactor: Allowed Key
    //! Types") restricts CKM_ECDH1_COFACTOR_DERIVE to CKK_EC — unlike plain
    //! ECDH (§6.3.17, Table 78), which also allows CKK_EC_MONTGOMERY
    //! (X25519/X448). Exercises the real C_DeriveKey FFI path (not the
    //! mechanism-agnostic native::agree helper, which has no way to select
    //! cofactor mode at all) to confirm the gate added 2026-07-25.
    use super::*;
    use crate::native::keygen::{generate_ecdh_keypair, generate_x25519_keypair, EccCurve};
    use crate::native::test_lock;
    use crate::state::{get_ec_point_sec1, get_object_value};

    fn setup() -> u32 {
        let _ = crate::native::session::finalize();
        crate::native::session::init().unwrap();
        crate::native::session::bootstrap_default_token(0, "so", "user", "ecdh-cofactor-test").unwrap()
    }

    /// Native-width CK_MECHANISM(mechanism, &CK_ECDH1_DERIVE_PARAMS) pair,
    /// matching the `[usize; N]` convention this file's own C_DeriveKey ECDH
    /// branch reads (`kdf, ulSharedDataLen, pSharedData, ulPublicDataLen,
    /// pPublicData`, all native-width per that code's own comment).
    fn ecdh_mech(mechanism: u32, peer_public: &[u8]) -> ([usize; 3], [usize; 5]) {
        let params: [usize; 5] = [
            1, /* CKD_NULL */
            0,
            0,
            peer_public.len(),
            peer_public.as_ptr() as usize,
        ];
        let m: [usize; 3] = [mechanism as usize, 0 /* filled by caller */, std::mem::size_of::<[usize; 5]>()];
        (m, params)
    }

    /// Minimal derived-key template: generic secret, 32 bytes, extractable —
    /// matches the shape `C_DeriveKey`'s ECDH branch expects (CKA_VALUE_LEN
    /// drives `key_len`; the class/type/extractable trio lets the resulting
    /// object be created and read back). Inlined per-test rather than
    /// factored into a helper: the attribute-value locals must live in the
    /// SAME stack frame as `tmpl` (`CK_ATTRIBUTE.pValue` points at them, and
    /// a `macro_rules!` expansion is hygienic in Rust — `let` bindings it
    /// introduces are not visible to hand-written code after the
    /// invocation, unlike a C macro).

    #[test]
    fn cofactor_derive_rejected_for_x25519_key() {
        let _guard = test_lock::acquire();
        let session = setup();
        let (_pub_a, priv_a) = generate_x25519_keypair(session, b"a", "a").unwrap();
        let (pub_b, _priv_b) = generate_x25519_keypair(session, b"b", "b").unwrap();
        let peer_pub = get_object_value(pub_b).unwrap(); // X25519 public = raw 32-byte point

        let (mut m, mut params) = ecdh_mech(CKM_ECDH1_COFACTOR_DERIVE, &peer_pub);
        m[1] = params.as_mut_ptr() as usize;
        let class: u32 = CKO_SECRET_KEY;
        let key_type: u32 = CKK_GENERIC_SECRET;
        let extractable: u8 = 1; // CK_TRUE
        let value_len: u32 = 32;
        let mut tmpl: [usize; 12] = [
            CKA_CLASS as usize, &class as *const u32 as usize, std::mem::size_of::<u32>(),
            CKA_KEY_TYPE as usize, &key_type as *const u32 as usize, std::mem::size_of::<u32>(),
            CKA_EXTRACTABLE as usize, &extractable as *const u8 as usize, std::mem::size_of::<u8>(),
            CKA_VALUE_LEN as usize, &value_len as *const u32 as usize, std::mem::size_of::<u32>(),
        ];
        let mut key_handle: u32 = 0;
        let rv = C_DeriveKey(
            session,
            m.as_mut_ptr() as *mut u8,
            priv_a,
            tmpl.as_mut_ptr() as *mut u8,
            4,
            &mut key_handle,
        );
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT, "cofactor mode is not valid for CKK_EC_MONTGOMERY (Table 79)");
    }

    #[test]
    fn standard_derive_still_works_for_x25519_key() {
        // Regression guard: the new gate must not have broken the valid,
        // already-working CKM_ECDH1_DERIVE path for the same key type.
        let _guard = test_lock::acquire();
        let session = setup();
        let (_pub_a, priv_a) = generate_x25519_keypair(session, b"c", "c").unwrap();
        let (pub_b, _priv_b) = generate_x25519_keypair(session, b"d", "d").unwrap();
        let peer_pub = get_object_value(pub_b).unwrap();

        let (mut m, mut params) = ecdh_mech(CKM_ECDH1_DERIVE, &peer_pub);
        m[1] = params.as_mut_ptr() as usize;
        let class: u32 = CKO_SECRET_KEY;
        let key_type: u32 = CKK_GENERIC_SECRET;
        let extractable: u8 = 1; // CK_TRUE
        let value_len: u32 = 32;
        let mut tmpl: [usize; 12] = [
            CKA_CLASS as usize, &class as *const u32 as usize, std::mem::size_of::<u32>(),
            CKA_KEY_TYPE as usize, &key_type as *const u32 as usize, std::mem::size_of::<u32>(),
            CKA_EXTRACTABLE as usize, &extractable as *const u8 as usize, std::mem::size_of::<u8>(),
            CKA_VALUE_LEN as usize, &value_len as *const u32 as usize, std::mem::size_of::<u32>(),
        ];
        let mut key_handle: u32 = 0;
        let rv = C_DeriveKey(
            session,
            m.as_mut_ptr() as *mut u8,
            priv_a,
            tmpl.as_mut_ptr() as *mut u8,
            4,
            &mut key_handle,
        );
        assert_eq!(rv, CKR_OK, "plain ECDH1_DERIVE must still succeed for CKK_EC_MONTGOMERY (Table 78)");
    }

    #[test]
    fn cofactor_derive_still_works_for_p256_key() {
        // The valid case (CKK_EC) must be unaffected by the new gate.
        let _guard = test_lock::acquire();
        let session = setup();
        let (_pub_a, priv_a) = generate_ecdh_keypair(session, EccCurve::P256, b"e", "e").unwrap();
        let (pub_b, _priv_b) = generate_ecdh_keypair(session, EccCurve::P256, b"f", "f").unwrap();
        let peer_pub = get_ec_point_sec1(pub_b).unwrap();

        let (mut m, mut params) = ecdh_mech(CKM_ECDH1_COFACTOR_DERIVE, &peer_pub);
        m[1] = params.as_mut_ptr() as usize;
        let class: u32 = CKO_SECRET_KEY;
        let key_type: u32 = CKK_GENERIC_SECRET;
        let extractable: u8 = 1; // CK_TRUE
        let value_len: u32 = 32;
        let mut tmpl: [usize; 12] = [
            CKA_CLASS as usize, &class as *const u32 as usize, std::mem::size_of::<u32>(),
            CKA_KEY_TYPE as usize, &key_type as *const u32 as usize, std::mem::size_of::<u32>(),
            CKA_EXTRACTABLE as usize, &extractable as *const u8 as usize, std::mem::size_of::<u8>(),
            CKA_VALUE_LEN as usize, &value_len as *const u32 as usize, std::mem::size_of::<u32>(),
        ];
        let mut key_handle: u32 = 0;
        let rv = C_DeriveKey(
            session,
            m.as_mut_ptr() as *mut u8,
            priv_a,
            tmpl.as_mut_ptr() as *mut u8,
            4,
            &mut key_handle,
        );
        assert_eq!(rv, CKR_OK, "cofactor mode must remain valid for CKK_EC (P-256)");
    }
}

#[cfg(test)]
mod rsa_sign_verify_recover_tests {
    //! PKCS#11 v3.2 §5.13 C_SignRecover/C_VerifyRecover, added 2026-07-25.
    //! `CKM_RSA_PKCS` round-trips through this crate's own machinery
    //! (regular Sign for the SignRecover half, since it's the identical
    //! RSASSA-PKCS1-v1_5 primitive; a hand-decoded EMSA-PKCS1-v1_5 padding
    //! block for VerifyRecover). `CKM_RSA_X_509` is checked byte-exact
    //! against real NIST ACVP `RSA-SignaturePrimitive-2.0` vectors
    //! (`rust/kat/rsa-signature-primitive-acvp.json`, 90 cases across 6
    //! groups, 12 deliberately out-of-range negative cases) — this is the
    //! RSASP1/RSAVP1 primitive verbatim, so it's a genuine third-party KAT,
    //! not a self-consistency round trip.
    use super::*;
    use crate::native::test_lock;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::{BigUint, RsaPrivateKey};

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex in KAT fixture"))
            .collect()
    }

    // ── CKM_RSA_X_509 vs real NIST ACVP RSASP1/RSAVP1 vectors ──────────────

    #[test]
    fn x509_sign_recover_matches_acvp_signature_primitive() {
        let doc_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/kat/rsa-signature-primitive-acvp.json"
        ))
        .expect("read rsa-signature-primitive-acvp.json");
        let doc: serde_json::Value = serde_json::from_str(&doc_str).expect("parse KAT JSON");
        let mut n_pass = 0;
        let mut n_reject = 0;
        for group in doc["testGroups"].as_array().unwrap() {
            for t in group["tests"].as_array().unwrap() {
                let n = BigUint::from_bytes_be(&hex_decode(t["n"].as_str().unwrap()));
                let e = BigUint::from_bytes_be(&hex_decode(t["e"].as_str().unwrap()));
                let d = BigUint::from_bytes_be(&hex_decode(t["d"].as_str().unwrap()));
                let p = BigUint::from_bytes_be(&hex_decode(t["p"].as_str().unwrap()));
                let q = BigUint::from_bytes_be(&hex_decode(t["q"].as_str().unwrap()));
                let sk = RsaPrivateKey::from_components(n, e, d, vec![p, q])
                    .expect("assemble RSA priv key from ACVP n/e/d/p/q");
                let sk_bytes = sk.to_pkcs8_der().expect("pkcs8 der").as_bytes().to_vec();
                let message = hex_decode(t["message"].as_str().unwrap());
                let test_passed = t["testPassed"].as_bool().unwrap();

                let result = rsa_x509_sign_recover(&sk_bytes, &message);
                if test_passed {
                    let want = hex_decode(t["signature"].as_str().unwrap());
                    assert_eq!(
                        result,
                        Ok(want),
                        "tcId {} sign-recover mismatch",
                        t["tcId"]
                    );
                    n_pass += 1;
                } else {
                    // 12 deliberately out-of-range cases (message representative
                    // >= modulus) — the crate's own rsa_decrypt rejects these;
                    // must not silently succeed.
                    assert!(
                        result.is_err(),
                        "tcId {} should have been rejected (message representative >= n)",
                        t["tcId"]
                    );
                    n_reject += 1;
                }
            }
        }
        assert_eq!(n_pass, 78, "expected 78 passing ACVP RSASP1 vectors (90 total - 12 negative)");
        assert_eq!(n_reject, 12, "expected 12 deliberately out-of-range ACVP vectors");
    }

    #[test]
    fn x509_verify_recover_matches_acvp_signature_primitive() {
        let doc_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/kat/rsa-signature-primitive-acvp.json"
        ))
        .expect("read rsa-signature-primitive-acvp.json");
        let doc: serde_json::Value = serde_json::from_str(&doc_str).expect("parse KAT JSON");
        let mut n = 0;
        for group in doc["testGroups"].as_array().unwrap() {
            for t in group["tests"].as_array().unwrap() {
                if !t["testPassed"].as_bool().unwrap() {
                    continue; // no signature to recover-verify for the negative cases
                }
                let n_bytes = hex_decode(t["n"].as_str().unwrap());
                let e_bytes = hex_decode(t["e"].as_str().unwrap());
                let signature = hex_decode(t["signature"].as_str().unwrap());
                let message = hex_decode(t["message"].as_str().unwrap());

                let recovered = rsa_x509_verify_recover(&n_bytes, &e_bytes, &signature)
                    .unwrap_or_else(|rv| panic!("tcId {} verify-recover failed: rv={rv:#x}", t["tcId"]));
                assert_eq!(recovered, message, "tcId {} recovered message mismatch", t["tcId"]);
                n += 1;
            }
        }
        assert_eq!(n, 78, "expected 78 verify-recover checks (the 78 passing sign vectors)");
    }

    // ── CKM_RSA_PKCS: reuses the engine's own regular-sign primitive for the
    // sign-recover half (they're the identical operation per PKCS#11 v3.2
    // Table 39), so this is a real round trip through independently-written
    // sign vs. verify-recover code, not the same function checked against
    // itself twice. ──────────────────────────────────────────────────────

    #[test]
    fn pkcs_sign_recover_then_verify_recover_round_trip() {
        let _guard = test_lock::acquire();
        let mut rng = rand::rngs::OsRng;
        let sk = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        use rsa::traits::PublicKeyParts;
        let pk = rsa::RsaPublicKey::from(&sk);
        let sk_bytes = sk.to_pkcs8_der().expect("pkcs8 der").as_bytes().to_vec();
        let n_bytes = pk.n().to_bytes_be();
        let e_bytes = pk.e().to_bytes_be();

        let msg = b"recover-mode PKCS#1 v1.5 test message";
        let sig = sign_rsa(CKM_RSA_PKCS, &sk_bytes, msg, None).expect("sign-recover (raw RSASP1+PKCS1v15 pad)");
        let recovered =
            rsa_pkcs_verify_recover(&n_bytes, &e_bytes, &sig).expect("verify-recover should decode the padding");
        assert_eq!(recovered, msg, "recovered message must equal the original");
    }

    #[test]
    fn pkcs_verify_recover_rejects_corrupted_signature() {
        let _guard = test_lock::acquire();
        let mut rng = rand::rngs::OsRng;
        let sk = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        use rsa::traits::PublicKeyParts;
        let pk = rsa::RsaPublicKey::from(&sk);
        let sk_bytes = sk.to_pkcs8_der().expect("pkcs8 der").as_bytes().to_vec();
        let n_bytes = pk.n().to_bytes_be();
        let e_bytes = pk.e().to_bytes_be();

        let msg = b"tamper test";
        let mut sig = sign_rsa(CKM_RSA_PKCS, &sk_bytes, msg, None).expect("sign-recover");
        let last = sig.len() - 1;
        sig[last] ^= 0x01; // flip one bit -> must not decode to a valid EMSA-PKCS1-v1_5 block
        assert_eq!(
            rsa_pkcs_verify_recover(&n_bytes, &e_bytes, &sig),
            Err(CKR_SIGNATURE_INVALID),
            "a corrupted signature must never recover a message"
        );
    }

    // ── Full C-ABI round trip (Init -> Recover, single-part, via the real
    // C_SignRecoverInit/C_SignRecover/C_VerifyRecoverInit/C_VerifyRecover
    // entry points, not the bare helper functions above) ───────────────────

    #[test]
    fn full_c_abi_sign_recover_verify_recover_round_trip() {
        let _guard = test_lock::acquire();
        let _ = crate::native::session::finalize();
        crate::native::session::init().unwrap();
        let session =
            crate::native::session::bootstrap_default_token(0, "so", "user", "recover-abi-test").unwrap();
        let (pub_h, priv_h) =
            crate::native::generate_rsa_keypair(session, 2048, b"recover-test", "recover-test").unwrap();
        // CKA_SIGN_RECOVER/CKA_VERIFY_RECOVER default to CK_FALSE (unset) per
        // PKCS#11 v3.2 (like CKA_SIGN itself) -- generate_rsa_keypair doesn't
        // request them, so set them directly for this test, matching what a
        // real caller would do via the keygen template.
        OBJECTS.with(|o| {
            let mut m = o.borrow_mut();
            store_bool(m.get_mut(&priv_h).unwrap(), CKA_SIGN_RECOVER, true);
            store_bool(m.get_mut(&pub_h).unwrap(), CKA_VERIFY_RECOVER, true);
        });

        let mut mech: [usize; 3] = [CKM_RSA_PKCS as usize, 0, 0];
        assert_eq!(C_SignRecoverInit(session, mech.as_mut_ptr() as *mut u8, priv_h), CKR_OK);

        let msg = b"full C-ABI sign-recover round trip";
        let mut sig_len: u32 = 0;
        // Length query first (NULL output buffer) -- must not consume the op.
        assert_eq!(
            C_SignRecover(session, msg.as_ptr() as *mut u8, msg.len() as u32, std::ptr::null_mut(), &mut sig_len),
            CKR_OK
        );
        assert_eq!(sig_len, 256, "2048-bit key -> 256-byte signature");
        let mut sig = vec![0u8; sig_len as usize];
        assert_eq!(
            C_SignRecover(session, msg.as_ptr() as *mut u8, msg.len() as u32, sig.as_mut_ptr(), &mut sig_len),
            CKR_OK
        );

        // Operation must be OVER after one Recover call (§5.13.6, single-part-only) --
        // a second call must see CKR_OPERATION_NOT_INITIALIZED, not CKR_OK.
        let mut probe_len: u32 = 0;
        assert_eq!(
            C_SignRecover(session, msg.as_ptr() as *mut u8, msg.len() as u32, std::ptr::null_mut(), &mut probe_len),
            CKR_OPERATION_NOT_INITIALIZED
        );

        let mut mech2: [usize; 3] = [CKM_RSA_PKCS as usize, 0, 0];
        assert_eq!(C_VerifyRecoverInit(session, mech2.as_mut_ptr() as *mut u8, pub_h), CKR_OK);
        let mut data_len: u32 = 0;
        assert_eq!(
            C_VerifyRecover(session, sig.as_mut_ptr(), sig.len() as u32, std::ptr::null_mut(), &mut data_len),
            CKR_OK
        );
        let mut recovered = vec![0u8; data_len as usize];
        assert_eq!(
            C_VerifyRecover(session, sig.as_mut_ptr(), sig.len() as u32, recovered.as_mut_ptr(), &mut data_len),
            CKR_OK
        );
        assert_eq!(recovered, msg, "full C-ABI round trip must recover the original message");
    }

    #[test]
    fn sign_recover_init_rejects_key_without_sign_recover_attribute() {
        // Regression guard for the CKA_SIGN_RECOVER gate itself: a freshly
        // generated key (attribute unset, defaults CK_FALSE) must be refused.
        let _guard = test_lock::acquire();
        let _ = crate::native::session::finalize();
        crate::native::session::init().unwrap();
        let session =
            crate::native::session::bootstrap_default_token(0, "so", "user", "recover-gate-test").unwrap();
        let (_pub_h, priv_h) =
            crate::native::generate_rsa_keypair(session, 2048, b"no-recover", "no-recover").unwrap();
        let mut mech: [usize; 3] = [CKM_RSA_PKCS as usize, 0, 0];
        assert_eq!(
            C_SignRecoverInit(session, mech.as_mut_ptr() as *mut u8, priv_h),
            CKR_KEY_FUNCTION_NOT_PERMITTED
        );
    }

    #[test]
    fn sign_recover_init_rejects_unsupported_mechanism() {
        let _guard = test_lock::acquire();
        let _ = crate::native::session::finalize();
        crate::native::session::init().unwrap();
        let session =
            crate::native::session::bootstrap_default_token(0, "so", "user", "recover-mech-test").unwrap();
        let (_pub_h, priv_h) =
            crate::native::generate_rsa_keypair(session, 2048, b"mech-test", "mech-test").unwrap();
        OBJECTS.with(|o| {
            store_bool(o.borrow_mut().get_mut(&priv_h).unwrap(), CKA_SIGN_RECOVER, true);
        });
        // CKM_SHA256_RSA_PKCS is a real, supported RSA sign mechanism -- just
        // not one of the two (RSA_PKCS/RSA_X_509) recovery permits.
        let mut mech: [usize; 3] = [CKM_SHA256_RSA_PKCS as usize, 0, 0];
        assert_eq!(
            C_SignRecoverInit(session, mech.as_mut_ptr() as *mut u8, priv_h),
            CKR_MECHANISM_INVALID
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operation-evidence wrappers (crate::oplog).
//
// Each exported entry point is a thin wrapper around the `*_impl` function that
// holds the real body. The bodies are left untouched on purpose: they have many
// early returns, and restructuring working PKCS#11 code around a log statement
// is a bad trade. This mirrors exactly what the C++ engine does for the same
// three call families.
//
// The records use the SAME grammar the C++ engine emits, so one consumer
// (pqctoday-sandbox/tests/_evidence.sh) parses both engines without knowing
// which produced a line. C_Sign carries no mechanism or key of its own -- the
// session holds those -- so a consumer joins it to the preceding C_SignInit on
// (pid, sess).
//
// Every wrapper is guarded by `oplog::enabled()`, which is a single relaxed
// load when SOFTHSM3_OP_LOG is unset. That matters here more than in the C++
// engine: hsm-perf-bench drives this crate at ~62k signs/sec, and its published
// numbers must come from a logging-off run.
// ─────────────────────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_SignInit)]
pub fn C_SignInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    // Read the mechanism and key identity BEFORE dispatch: a failed init can
    // tear down session state, and the key identity is most wanted on exactly
    // those records.
    let logging = crate::oplog::enabled();
    let mech = if logging && !p_mechanism.is_null() {
        unsafe { ck_param::mech(p_mechanism).mechanism }
    } else {
        0
    };
    let key_fields = if logging {
        crate::oplog::key_fields(h_key, mech)
    } else {
        String::new()
    };

    let rv = C_SignInit_impl(h_session, p_mechanism, h_key);

    if logging {
        crate::oplog::emit(
            "C_SignInit",
            &format!(
                "sess={} mech={} mech_id=0x{:08x} {} rv={} rv_id=0x{:08x}",
                h_session,
                crate::oplog::mech_name(mech),
                mech,
                key_fields,
                crate::oplog::rv_name(rv),
                rv
            ),
        );
    }
    rv
}

#[wasm_bindgen(js_name = _C_Sign)]
pub fn C_Sign(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    let rv = C_Sign_impl(h_session, p_data, ul_data_len, p_signature, pul_signature_len);

    if crate::oplog::enabled() {
        // probe=1 marks the mandatory PKCS#11 length-query call (p_signature
        // null) that every caller makes before the real one. A consumer
        // counting signatures must skip those rather than double every count.
        let out = if pul_signature_len.is_null() {
            0
        } else {
            unsafe { *pul_signature_len }
        };
        crate::oplog::emit(
            "C_Sign",
            &format!(
                "sess={} in={} out={} probe={} rv={} rv_id=0x{:08x}",
                h_session,
                ul_data_len,
                out,
                if p_signature.is_null() { 1 } else { 0 },
                crate::oplog::rv_name(rv),
                rv
            ),
        );
    }
    rv
}

#[wasm_bindgen(js_name = _C_SignFinal)]
pub fn C_SignFinal(h_session: u32, p_signature: *mut u8, pul_signature_len: *mut u32) -> u32 {
    let rv = C_SignFinal_impl(h_session, p_signature, pul_signature_len);

    if crate::oplog::enabled() {
        // C_SignUpdate is deliberately NOT recorded: it produces no signature,
        // and instrumenting it would emit one line per chunk of a large input
        // for no added evidence.
        let out = if pul_signature_len.is_null() {
            0
        } else {
            unsafe { *pul_signature_len }
        };
        crate::oplog::emit(
            "C_SignFinal",
            &format!(
                "sess={} out={} probe={} rv={} rv_id=0x{:08x}",
                h_session,
                out,
                if p_signature.is_null() { 1 } else { 0 },
                crate::oplog::rv_name(rv),
                rv
            ),
        );
    }
    rv
}

#[wasm_bindgen(js_name = _C_GenerateKeyPair)]
pub fn C_GenerateKeyPair(
    h_session: u32,
    p_mechanism: *mut u8,
    p_public_key_template: *mut u8,
    ul_public_key_attribute_count: u32,
    p_private_key_template: *mut u8,
    ul_private_key_attribute_count: u32,
    ph_public_key: *mut u32,
    ph_private_key: *mut u32,
) -> u32 {
    let rv = C_GenerateKeyPair_impl(
        h_session,
        p_mechanism,
        p_public_key_template,
        ul_public_key_attribute_count,
        p_private_key_template,
        ul_private_key_attribute_count,
        ph_public_key,
        ph_private_key,
    );

    if crate::oplog::enabled() {
        let mech = if p_mechanism.is_null() {
            0
        } else {
            unsafe { ck_param::mech(p_mechanism).mechanism }
        };
        // Read back from the PRIVATE key, and only on success: the custody
        // attributes are what "generated in-HSM, non-extractable" means, and
        // they exist only once the object does.
        let h_priv = if rv == CKR_OK && !ph_private_key.is_null() {
            unsafe { *ph_private_key }
        } else {
            0
        };
        let (key_fields, custody) = if h_priv != 0 {
            (
                crate::oplog::key_fields(h_priv, mech),
                crate::oplog::key_custody_fields(h_priv),
            )
        } else {
            (
                "key=- keytype=- paramset=-".to_string(),
                "extractable=- sensitive=- never_extractable=- always_sensitive=- local=-"
                    .to_string(),
            )
        };
        let h_pub = if rv == CKR_OK && !ph_public_key.is_null() {
            unsafe { *ph_public_key }
        } else {
            0
        };
        crate::oplog::emit(
            "C_GenerateKeyPair",
            &format!(
                "sess={} mech={} mech_id=0x{:08x} {} {} hpub={} hpriv={} rv={} rv_id=0x{:08x}",
                h_session,
                crate::oplog::mech_name(mech),
                mech,
                key_fields,
                custody,
                h_pub,
                h_priv,
                crate::oplog::rv_name(rv),
                rv
            ),
        );
    }
    rv
}

#[wasm_bindgen(js_name = _C_EncapsulateKey)]
pub fn C_EncapsulateKey(
    h_session: u32,
    p_mechanism: *mut u8,
    h_key: u32,
    p_template: *mut u8,
    ul_attribute_count: u32,
    p_ciphertext: *mut u8,
    pul_ciphertext_len: *mut u32,
    ph_key: *mut u32,
) -> u32 {
    let logging = crate::oplog::enabled();
    let mech = if logging && !p_mechanism.is_null() {
        unsafe { ck_param::mech(p_mechanism).mechanism }
    } else {
        0
    };
    let key_fields = if logging {
        crate::oplog::key_fields(h_key, mech)
    } else {
        String::new()
    };

    let rv = C_EncapsulateKey_impl(
        h_session,
        p_mechanism,
        h_key,
        p_template,
        ul_attribute_count,
        p_ciphertext,
        pul_ciphertext_len,
        ph_key,
    );

    if logging {
        let ct = if pul_ciphertext_len.is_null() {
            0
        } else {
            unsafe { *pul_ciphertext_len }
        };
        crate::oplog::emit(
            "C_EncapsulateKey",
            &format!(
                "sess={} mech={} mech_id=0x{:08x} {} ct={} probe={} rv={} rv_id=0x{:08x}",
                h_session,
                crate::oplog::mech_name(mech),
                mech,
                key_fields,
                ct,
                if p_ciphertext.is_null() { 1 } else { 0 },
                crate::oplog::rv_name(rv),
                rv
            ),
        );
    }
    rv
}

#[wasm_bindgen(js_name = _C_DecapsulateKey)]
pub fn C_DecapsulateKey(
    h_session: u32,
    p_mechanism: *mut u8,
    h_private_key: u32,
    p_template: *mut u8,
    ul_attribute_count: u32,
    p_ciphertext: *mut u8,
    ul_ciphertext_len: u32,
    ph_key: *mut u32,
) -> u32 {
    let logging = crate::oplog::enabled();
    let mech = if logging && !p_mechanism.is_null() {
        unsafe { ck_param::mech(p_mechanism).mechanism }
    } else {
        0
    };
    let key_fields = if logging {
        crate::oplog::key_fields(h_private_key, mech)
    } else {
        String::new()
    };

    let rv = C_DecapsulateKey_impl(
        h_session,
        p_mechanism,
        h_private_key,
        p_template,
        ul_attribute_count,
        p_ciphertext,
        ul_ciphertext_len,
        ph_key,
    );

    if logging {
        // No probe field: decapsulation takes the ciphertext by value and has
        // no length-query form to distinguish.
        crate::oplog::emit(
            "C_DecapsulateKey",
            &format!(
                "sess={} mech={} mech_id=0x{:08x} {} ct={} rv={} rv_id=0x{:08x}",
                h_session,
                crate::oplog::mech_name(mech),
                mech,
                key_fields,
                ul_ciphertext_len,
                crate::oplog::rv_name(rv),
                rv
            ),
        );
    }
    rv
}

// ── ECDH-as-KEM FFI tests (2026-08-13 C++-parity implementation) ─────────────
#[cfg(test)]
mod ecdh_kem_ffi_tests {
    use super::*;
    use crate::native::test_lock;

    // High fixed handles to avoid colliding with parallel native tests that
    // allocate via NEXT_HANDLE / NEXT_SESSION_HANDLE (same convention as
    // multipart_ffi_tests above).
    const SESSION: u32 = 0x4D50_2001;
    const H_PUB: u32 = 0x4D50_2002;
    const H_PRV: u32 = 0x4D50_2003;

    fn setup() {
        // §5.4 — entry points are gated by `require_init!()`; flip the
        // lifecycle flag directly (tests hold `test_lock`, so this cannot
        // race the lifecycle dance of the `native::*` tests).
        crate::state::set_initialized(true);
        SESSIONS.with(|s| {
            s.borrow_mut()
                .insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true });
        });
    }

    /// Install a static EC keypair shaped exactly like CKM_EC_KEY_PAIR_GEN's
    /// output: DER-wrapped CKA_EC_POINT on the public, raw big-endian scalar
    /// CKA_VALUE on the private, CURVE_* in the param set.
    fn install_ec_keypair(curve: u32) {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let mut rng = OsRng;
        macro_rules! gen_ec {
            ($c:ident) => {{
                let sk = $c::SecretKey::random(&mut rng);
                (
                    sk.to_bytes().to_vec(),
                    sk.public_key().to_encoded_point(false).as_bytes().to_vec(),
                )
            }};
        }
        let (scalar, point): (Vec<u8>, Vec<u8>) = match curve {
            CURVE_P256 => gen_ec!(p256),
            CURVE_P384 => gen_ec!(p384),
            CURVE_P521 => gen_ec!(p521),
            _ => unreachable!("unsupported test curve"),
        };
        OBJECTS.with(|o| {
            let mut store = o.borrow_mut();
            let mut pub_attrs = Attributes::new();
            store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
            store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC);
            store_param_set(&mut pub_attrs, curve);
            store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
            pub_attrs.insert(CKA_EC_POINT, der_wrap_ec_point(&point));
            store.insert(H_PUB, pub_attrs);
            let mut prv_attrs = Attributes::new();
            store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
            store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC);
            store_param_set(&mut prv_attrs, curve);
            store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
            prv_attrs.insert(CKA_VALUE, scalar);
            store.insert(H_PRV, prv_attrs);
        });
    }

    /// encapsulate → decapsulate: secrets match, and the ciphertext is
    /// E1 (2026-08-13) — this used to assert byte-shape identity with the
    /// C++ engine's encapsulateECDH, i.e. a DER OCTET STRING wrapping the
    /// uncompressed SEC1 point. §6.3.17 mandates the RAW value, and mutual
    /// agreement between the two engines is not a defence — the spec
    /// footnotes exactly this hazard. The expectations below now pin the
    /// mandated raw form; the DER-wrapped form is still ACCEPTED on
    /// decapsulation (asserted at the end of this function), which is what
    /// keeps anything already deployed working.
    fn roundtrip(curve: u32, expected_ct_len: usize, point_len: usize) {
        setup();
        install_ec_keypair(curve);
        let mut mech: [usize; 3] = [CKM_ECDH1_DERIVE as usize, 0, 0];
        let mut ct_len: u32 = 0;
        let mut h_ss_e: u32 = 0;
        // NULL-output size query first (§5.2 convention).
        let rv = C_EncapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PUB,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut ct_len,
            &mut h_ss_e,
        );
        assert_eq!(rv, CKR_OK, "size query: 0x{rv:x}");
        assert_eq!(ct_len as usize, expected_ct_len, "advertised ciphertext length");
        let mut ct = vec![0u8; ct_len as usize];
        let rv = C_EncapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PUB,
            std::ptr::null_mut(),
            0,
            ct.as_mut_ptr(),
            &mut ct_len,
            &mut h_ss_e,
        );
        assert_eq!(rv, CKR_OK, "encapsulate: 0x{rv:x}");
        // C++ wire-format cross-check (SoftHSM_kem.cpp emits ephPub->getQ(),
        // the CKA_EC_POINT DER encoding).
        // E1 — the ciphertext IS the raw uncompressed SEC1 point.
        assert_eq!(ct.len(), point_len, "raw uncompressed SEC1 point length");
        assert_eq!(ct[0], 0x04, "uncompressed SEC1 point marker");
        let inner = ct.clone();
        let ss_e = get_object_value(h_ss_e).expect("encapsulated secret stored");
        let mut h_ss_d: u32 = 0;
        let rv = C_DecapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PRV,
            std::ptr::null_mut(),
            0,
            ct.as_mut_ptr(),
            ct_len,
            &mut h_ss_d,
        );
        assert_eq!(rv, CKR_OK, "decapsulate: 0x{rv:x}");
        let ss_d = get_object_value(h_ss_d).expect("decapsulated secret stored");
        assert_eq!(ss_e, ss_d, "both sides must derive the same shared secret");
        assert_eq!(ss_e.len(), (point_len - 1) / 2, "raw X-coordinate shared secret");

        // E1 — the tolerant reader is KEPT: the historical DER-wrapped form
        // must still decapsulate to the same secret.
        let mut raw = {
            let mut der = vec![0x04u8];
            if inner.len() < 0x80 {
                der.push(inner.len() as u8);
            } else {
                der.push(0x81);
                der.push(inner.len() as u8);
            }
            der.extend_from_slice(&inner);
            der
        };
        let mut h_ss_r: u32 = 0;
        let rv = C_DecapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PRV,
            std::ptr::null_mut(),
            0,
            raw.as_mut_ptr(),
            raw.len() as u32,
            &mut h_ss_r,
        );
        assert_eq!(rv, CKR_OK, "raw-SEC1 decapsulate: 0x{rv:x}");
        assert_eq!(get_object_value(h_ss_r).unwrap(), ss_e);

        // §6.8.2 Table 103 — CKA_VALUE_LEN is the length of CKA_VALUE, on both
        // sides, with no template supplied.
        for (h, side) in [(h_ss_e, "encapsulate"), (h_ss_d, "decapsulate")] {
            assert_eq!(
                value_len_of(h),
                ss_e.len(),
                "{side}: CKA_VALUE_LEN must equal the shared-secret length"
            );
        }
    }

    /// CKA_VALUE_LEN of an object, as a usize.
    fn value_len_of(handle: u32) -> usize {
        get_object_attr_u32(handle, CKA_VALUE_LEN)
            .expect("CKA_VALUE_LEN must be set on a KEM-produced key") as usize
    }

    fn value_len_template(v: &u32) -> [usize; 3] {
        // A real LP64 caller sends `sizeof(CK_ULONG)` — 8 bytes — for a
        // CK_ULONG-valued attribute, not 4. This helper used to declare 4,
        // which modelled a 32-bit caller on a 64-bit ABI and only "worked"
        // because get_attr_ulong ignored ulValueLen entirely. It now widens
        // the caller's u32 into an owned native word. Leaked deliberately:
        // the template must outlive this call and a unit test's address space
        // is the right lifetime for three words.
        let w: &'static crate::ck_abi::CK_ULONG =
            Box::leak(Box::new(*v as crate::ck_abi::CK_ULONG));
        [
            CKA_VALUE_LEN as usize,
            w as *const crate::ck_abi::CK_ULONG as usize,
            core::mem::size_of::<crate::ck_abi::CK_ULONG>(),
        ]
    }

    /// PKCS#11 v3.2 §6.3.17 — unlike the fixed-length KEMs, CKM_ECDH1_DERIVE
    /// "truncates the result according to … the CKA_VALUE_LEN attribute of the
    /// template. (The truncation removes bytes from the leading end of the
    /// secret value.)", and §6.3.17 routes C_Encapsulate/DecapsulateKey through
    /// that same EC Derive. Both sides must truncate identically or the peers
    /// end up with different keys.
    #[test]
    fn ecdh_as_kem_template_value_len_truncates_both_sides() {
        let _guard = test_lock::acquire();
        setup();
        install_ec_keypair(CURVE_P256);
        let mut mech: [usize; 3] = [CKM_ECDH1_DERIVE as usize, 0, 0];
        let want: u32 = 16; // half of the 32-byte P-256 X coordinate
        let mut tpl = value_len_template(&want);

        let mut ct_len: u32 = 2 + 65;
        let mut ct = vec![0u8; ct_len as usize];
        let mut h_e: u32 = 0;
        let rv = C_EncapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PUB,
            tpl.as_mut_ptr() as *mut u8,
            1,
            ct.as_mut_ptr(),
            &mut ct_len,
            &mut h_e,
        );
        assert_eq!(rv, CKR_OK, "encapsulate with CKA_VALUE_LEN: 0x{rv:x}");
        let ss_e = get_object_value(h_e).unwrap();
        assert_eq!(ss_e.len(), want as usize, "§6.3.17 truncation");
        assert_eq!(value_len_of(h_e), want as usize);

        let mut h_d: u32 = 0;
        let rv = C_DecapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PRV,
            tpl.as_mut_ptr() as *mut u8,
            1,
            ct.as_mut_ptr(),
            ct_len,
            &mut h_d,
        );
        assert_eq!(rv, CKR_OK, "decapsulate with CKA_VALUE_LEN: 0x{rv:x}");
        assert_eq!(get_object_value(h_d).unwrap(), ss_e, "both peers must agree after truncation");
        assert_eq!(value_len_of(h_d), want as usize);

        // Untruncated run must yield the full 32 bytes ENDING in the same 16 —
        // proves the truncation removed bytes from the LEADING end (§6.3.17).
        let mut h_full: u32 = 0;
        let rv = C_DecapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PRV,
            std::ptr::null_mut(),
            0,
            ct.as_mut_ptr(),
            ct_len,
            &mut h_full,
        );
        assert_eq!(rv, CKR_OK);
        let full = get_object_value(h_full).unwrap();
        assert_eq!(full.len(), 32);
        assert_eq!(&full[16..], &ss_e[..], "truncation must keep the trailing bytes");
    }

    /// §6.3.17 truncation cannot LENGTHEN a secret, so an over-long
    /// CKA_VALUE_LEN falls back to §4.1.1 rule 5 → CKR_TEMPLATE_INCONSISTENT,
    /// with no key object created (§5.18.8/§5.18.9).
    #[test]
    fn ecdh_as_kem_oversized_template_value_len_template_inconsistent() {
        let _guard = test_lock::acquire();
        setup();
        install_ec_keypair(CURVE_P256);
        let mut mech: [usize; 3] = [CKM_ECDH1_DERIVE as usize, 0, 0];
        let want: u32 = 64; // > the 32-byte P-256 shared secret
        let mut tpl = value_len_template(&want);
        let mut ct_len: u32 = 2 + 65;
        let mut ct = vec![0u8; ct_len as usize];
        let mut h_e: u32 = 0;
        assert_eq!(
            C_EncapsulateKey_impl(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                H_PUB,
                tpl.as_mut_ptr() as *mut u8,
                1,
                ct.as_mut_ptr(),
                &mut ct_len,
                &mut h_e,
            ),
            CKR_TEMPLATE_INCONSISTENT
        );
        assert_eq!(h_e, 0, "no key object may be created");

        // Produce a valid ciphertext, then try the same on decapsulate.
        let mut ct_len2: u32 = 2 + 65;
        let mut h_ok: u32 = 0;
        assert_eq!(
            C_EncapsulateKey_impl(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                H_PUB,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut ct_len2,
                &mut h_ok,
            ),
            CKR_OK
        );
        let mut h_d: u32 = 0;
        assert_eq!(
            C_DecapsulateKey_impl(
                SESSION,
                mech.as_mut_ptr() as *mut u8,
                H_PRV,
                tpl.as_mut_ptr() as *mut u8,
                1,
                ct.as_mut_ptr(),
                ct_len2,
                &mut h_d,
            ),
            CKR_TEMPLATE_INCONSISTENT
        );
        assert_eq!(h_d, 0, "no key object may be created");
    }

    #[test]
    fn ecdh_as_kem_roundtrip_p256() {
        let _guard = test_lock::acquire();
        roundtrip(CURVE_P256, 65, 65);
    }

    #[test]
    fn ecdh_as_kem_roundtrip_p384() {
        let _guard = test_lock::acquire();
        roundtrip(CURVE_P384, 97, 97);
    }

    #[test]
    fn ecdh_as_kem_roundtrip_p521() {
        let _guard = test_lock::acquire();
        roundtrip(CURVE_P521, 133, 133);
    }

    /// N5 — CKA_ALLOWED_MECHANISMS excluding CKM_ECDH1_DERIVE must block
    /// both KEM directions with CKR_MECHANISM_INVALID (§4.8 Table 13).
    #[test]
    fn ecdh_as_kem_blocked_by_allowed_mechanisms() {
        let _guard = test_lock::acquire();
        setup();
        install_ec_keypair(CURVE_P256);
        OBJECTS.with(|o| {
            let mut store = o.borrow_mut();
            for h in [H_PUB, H_PRV] {
                store
                    .get_mut(&h)
                    .unwrap()
                    .insert(CKA_ALLOWED_MECHANISMS, (CKM_ML_KEM as usize).to_le_bytes().to_vec());
            }
        });
        let mut mech: [usize; 3] = [CKM_ECDH1_DERIVE as usize, 0, 0];
        let mut ct_len: u32 = 0;
        let mut h_ss: u32 = 0;
        let rv = C_EncapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PUB,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut ct_len,
            &mut h_ss,
        );
        assert_eq!(rv, CKR_MECHANISM_INVALID, "encapsulate must be blocked");
        let mut dummy_ct = vec![0u8; 67];
        let rv = C_DecapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PRV,
            std::ptr::null_mut(),
            0,
            dummy_ct.as_mut_ptr(),
            67,
            &mut h_ss,
        );
        assert_eq!(rv, CKR_MECHANISM_INVALID, "decapsulate must be blocked");
    }

    /// N5 — the FrodoKEM / Classic-McEliece vendor arms previously returned
    /// before the shared CKA_ALLOWED_MECHANISMS check; they must now enforce
    /// it too. The check fires before any key material or parameter set is
    /// touched, so a minimal restricted object suffices.
    #[test]
    fn vendor_kem_arms_enforce_allowed_mechanisms() {
        let _guard = test_lock::acquire();
        setup();
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            store_ulong(&mut attrs, CKA_CLASS, CKO_PUBLIC_KEY);
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_PQCTODAY_FRODOKEM);
            store_bool(&mut attrs, CKA_ENCAPSULATE, true);
            store_bool(&mut attrs, CKA_DECAPSULATE, true);
            attrs.insert(CKA_ALLOWED_MECHANISMS, (CKM_ML_KEM as usize).to_le_bytes().to_vec());
            o.borrow_mut().insert(H_PUB, attrs);
        });
        let mut mech: [usize; 3] = [CKM_PQCTODAY_FRODOKEM_ENCAPSULATE as usize, 0, 0];
        let mut ct_len: u32 = 0;
        let mut h_ss: u32 = 0;
        let rv = C_EncapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PUB,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut ct_len,
            &mut h_ss,
        );
        assert_eq!(rv, CKR_MECHANISM_INVALID, "vendor encapsulate must be blocked");
        let mut dummy_ct = vec![0u8; 16];
        let rv = C_DecapsulateKey_impl(
            SESSION,
            mech.as_mut_ptr() as *mut u8,
            H_PUB,
            std::ptr::null_mut(),
            0,
            dummy_ct.as_mut_ptr(),
            16,
            &mut h_ss,
        );
        assert_eq!(rv, CKR_MECHANISM_INVALID, "vendor decapsulate must be blocked");
    }
}

/// CKA_VALUE_LEN on ML-KEM-produced shared-secret keys (PKCS#11 v3.2 §6.68.5 +
/// §6.8.2 Table 103 + §4.1.1 rules 5/6). The FrodoKEM / Classic-McEliece and
/// ECDH arms are covered in `pqc_vendor_kem_ffi_tests` / `ecdh_kem_ffi_tests`;
/// this module closes the ML-KEM corner of the same invariant.
#[cfg(test)]
mod mlkem_value_len_ffi_tests {
    use super::*;
    use crate::native::test_lock;

    const SESSION: u32 = 0x4D50_3001;

    fn setup() {
        crate::state::set_initialized(true);
        SESSIONS.with(|s| {
            s.borrow_mut()
                .insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true });
        });
        TOKEN_STORE.with(|ts| {
            ts.borrow_mut()
                .entry(0)
                .or_insert_with(|| crate::state::TokenState {
                    slot_id: 0,
                    initialized: true,
                    label: [0u8; 32],
                    login_state: crate::state::LoginState::User,
                    so_pin_salt: [0u8; 16],
                    so_pin_hash: [0u8; 32],
                    user_pin_salt: None,
                    user_pin_hash: None,
                })
                .login_state = crate::state::LoginState::User;
        });
    }

    fn obj_attr(handle: u32, attr_type: u32) -> Option<Vec<u8>> {
        OBJECTS.with(|o| o.borrow().get(&handle).and_then(|a| a.get(&attr_type).cloned()))
    }

    fn value_len_of(handle: u32) -> usize {
        get_object_attr_u32(handle, CKA_VALUE_LEN).expect("CKA_VALUE_LEN must be set") as usize
    }

    fn ulong_template(t: u32, v: &u32) -> [usize; 3] {
        // A real LP64 caller sends `sizeof(CK_ULONG)` — 8 bytes — for a
        // CK_ULONG-valued attribute, not 4. This helper used to declare 4,
        // which modelled a 32-bit caller on a 64-bit ABI and only "worked"
        // because get_attr_ulong ignored ulValueLen entirely. It now widens
        // the caller's u32 into an owned native word. Leaked deliberately:
        // the template must outlive this call and a unit test's address space
        // is the right lifetime for three words.
        let w: &'static crate::ck_abi::CK_ULONG =
            Box::leak(Box::new(*v as crate::ck_abi::CK_ULONG));
        [
            t as usize,
            w as *const crate::ck_abi::CK_ULONG as usize,
            core::mem::size_of::<crate::ck_abi::CK_ULONG>(),
        ]
    }

    /// Generate an ML-KEM keypair for `ps` and return (public, private) handles.
    fn keypair(ps: u32) -> (u32, u32) {
        let ps_val = ps;
        let mut pub_tpl = ulong_template(CKA_PARAMETER_SET, &ps_val);
        let mut prv_tpl = ulong_template(CKA_PARAMETER_SET, &ps_val);
        let mut kg = [CKM_ML_KEM_KEY_PAIR_GEN as usize, 0usize, 0usize];
        let (mut h_pub, mut h_prv) = (0u32, 0u32);
        assert_eq!(
            C_GenerateKeyPair(
                SESSION,
                kg.as_mut_ptr() as *mut u8,
                pub_tpl.as_mut_ptr() as *mut u8,
                1,
                prv_tpl.as_mut_ptr() as *mut u8,
                1,
                &mut h_pub,
                &mut h_prv,
            ),
            CKR_OK,
            "CKM_ML_KEM_KEY_PAIR_GEN"
        );
        (h_pub, h_prv)
    }

    /// §6.68.5 — the mechanism "contributes the result as the CKA_VALUE
    /// attribute of the new key"; §6.8.2 Table 103 defines CKA_VALUE_LEN as the
    /// "Length in bytes of key value". FIPS 203 fixes that at 32 bytes for every
    /// ML-KEM parameter set — never the (768/1088/1568-byte) ciphertext length.
    fn value_len_round_trip(ps: u32, expected_ct_len: u32) {
        setup();
        let (h_pub, h_prv) = keypair(ps);
        let mut kem = [CKM_ML_KEM as usize, 0usize, 0usize];
        let mut ct_len: u32 = 0;
        let mut h_e: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem.as_mut_ptr() as *mut u8,
                h_pub,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut ct_len,
                &mut h_e,
            ),
            CKR_OK
        );
        assert_eq!(ct_len, expected_ct_len);
        let mut ct = vec![0u8; ct_len as usize];
        let mut n = ct_len;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem.as_mut_ptr() as *mut u8,
                h_pub,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut n,
                &mut h_e,
            ),
            CKR_OK
        );
        let mut h_d: u32 = 0;
        assert_eq!(
            C_DecapsulateKey(
                SESSION,
                kem.as_mut_ptr() as *mut u8,
                h_prv,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                ct_len,
                &mut h_d,
            ),
            CKR_OK
        );
        for (h, side) in [(h_e, "encapsulate"), (h_d, "decapsulate")] {
            assert_eq!(value_len_of(h), 32, "{side}: FIPS 203 shared secret is 32 bytes");
            assert_eq!(
                value_len_of(h),
                obj_attr(h, CKA_VALUE).unwrap().len(),
                "{side}: CKA_VALUE_LEN must equal len(CKA_VALUE)"
            );
            assert_ne!(
                value_len_of(h),
                ct_len as usize,
                "{side}: CKA_VALUE_LEN must not be the ciphertext length"
            );
        }
    }

    #[test]
    fn ml_kem_512_value_len_is_secret_len() {
        let _guard = test_lock::acquire();
        value_len_round_trip(CKP_ML_KEM_512, 768);
    }

    #[test]
    fn ml_kem_768_value_len_is_secret_len() {
        let _guard = test_lock::acquire();
        value_len_round_trip(CKP_ML_KEM_768, 1088);
    }

    #[test]
    fn ml_kem_1024_value_len_is_secret_len() {
        let _guard = test_lock::acquire();
        value_len_round_trip(CKP_ML_KEM_1024, 1568);
    }

    /// §4.1.1 rule 5 (conflicting) / rule 6 (restating) applied to CKM_ML_KEM,
    /// whose §6.68.5 definition offers no length knob at all.
    #[test]
    fn ml_kem_template_value_len_conflict_and_match() {
        let _guard = test_lock::acquire();
        setup();
        let (h_pub, h_prv) = keypair(CKP_ML_KEM_768);
        let mut kem = [CKM_ML_KEM as usize, 0usize, 0usize];
        let mut ct = vec![0u8; 1088];
        let mut n: u32 = 1088;
        let mut h_ref: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                kem.as_mut_ptr() as *mut u8,
                h_pub,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut n,
                &mut h_ref,
            ),
            CKR_OK
        );

        let bogus: u32 = 16;
        let mut bad = ulong_template(CKA_VALUE_LEN, &bogus);
        let good: u32 = 32;
        let mut ok = ulong_template(CKA_VALUE_LEN, &good);

        for (tpl, want_rv, label) in [
            (bad.as_mut_ptr(), CKR_TEMPLATE_INCONSISTENT, "conflicting"),
            (ok.as_mut_ptr(), CKR_OK, "restating"),
        ] {
            let mut n2: u32 = 1088;
            let mut h_e: u32 = 0;
            assert_eq!(
                C_EncapsulateKey(
                    SESSION,
                    kem.as_mut_ptr() as *mut u8,
                    h_pub,
                    tpl as *mut u8,
                    1,
                    ct.as_mut_ptr(),
                    &mut n2,
                    &mut h_e,
                ),
                want_rv,
                "encapsulate with a {label} CKA_VALUE_LEN"
            );
            let mut h_d: u32 = 0;
            assert_eq!(
                C_DecapsulateKey(
                    SESSION,
                    kem.as_mut_ptr() as *mut u8,
                    h_prv,
                    tpl as *mut u8,
                    1,
                    ct.as_mut_ptr(),
                    1088,
                    &mut h_d,
                ),
                want_rv,
                "decapsulate with a {label} CKA_VALUE_LEN"
            );
            if want_rv == CKR_OK {
                assert_eq!(value_len_of(h_e), 32);
                assert_eq!(value_len_of(h_d), 32);
            } else {
                // §5.18.8/§5.18.9 — no key object on failure.
                assert_eq!(h_e, 0);
                assert_eq!(h_d, 0);
            }
        }
    }
}

/// PKCS#11 v3.2 conformance remediation suite (2026-08-13) — see the module's
/// own docs. Kept in its own file because it is large and grows per item;
/// `#[path]` keeps `use super::*` resolving to THIS module's private helpers,
/// exactly like the other `*_ffi_tests` modules above.
#[cfg(test)]
#[path = "conformance_v32_tests.rs"]
mod conformance_v32_tests;

// ── Mechanism-parameter struct widths (2026-08-13) ──────────────────────────
//
// Three defects in one day shared a single wrong belief: that the fields of a
// caller-supplied CK_* parameter struct are 4 bytes wide. They are CK_ULONG /
// CK_BYTE_PTR, which are 4 bytes on wasm32 and 8 on LP64 — so every one of
// them was invisible in the browser and wrong in the native library. These
// tests pin the layouts that were being misread.
#[cfg(test)]
mod param_struct_width_tests {
    use super::*;
    use std::mem::size_of;

    /// A CK_MECHANISM in the engine's packed `[type, pParameter, ulParameterLen]`
    /// form — what ck_abi::xlate_mech hands the entry points.
    fn packed_mech(mech: u32, param: *const u8, len: usize) -> [usize; 3] {
        [mech as usize, param as usize, len]
    }

    /// PKCS#11 v3.2 §6.3.7 CK_EDDSA_PARAMS at native layout.
    #[repr(C)]
    struct CkEddsaParams {
        ph_flag: u8, // CK_BBOOL — ONE byte
        ul_context_data_len: usize,
        p_context_data: *const u8,
    }

    /// phFlag is a CK_BBOOL. Reading four bytes for it pulled in the padding
    /// that follows, so a caller that set phFlag = CK_FALSE without zeroing
    /// the struct could be silently switched to Ed25519**ph**.
    #[test]
    fn eddsa_ph_flag_reads_one_byte_not_four() {
        // Guard the premise: there IS padding after phFlag to read into.
        assert!(size_of::<CkEddsaParams>() >= 3 * size_of::<usize>());

        // A caller-shaped struct whose phFlag byte is CK_FALSE but whose
        // padding bytes are dirty — exactly what an un-memset stack struct
        // looks like.
        let mut raw = vec![0xABu8; size_of::<CkEddsaParams>()];
        raw[0] = 0; // phFlag = CK_FALSE
        let m = packed_mech(CKM_EDDSA, raw.as_ptr(), raw.len());
        assert!(
            !unsafe { eddsa_ph_flag(m.as_ptr() as *const u8) },
            "CK_FALSE with dirty padding must stay pure EdDSA"
        );

        // CK_TRUE is still honoured.
        raw[0] = 1;
        let m = packed_mech(CKM_EDDSA, raw.as_ptr(), raw.len());
        assert!(unsafe { eddsa_ph_flag(m.as_ptr() as *const u8) }, "CK_TRUE selects the PH variant");

        // The little-endian 32-bit phFlag the wasm/TS callers write keeps
        // working in both states.
        let mut le32 = vec![0u8; size_of::<CkEddsaParams>()];
        le32[0..4].copy_from_slice(&1u32.to_le_bytes());
        let m = packed_mech(CKM_EDDSA, le32.as_ptr(), le32.len());
        assert!(unsafe { eddsa_ph_flag(m.as_ptr() as *const u8) });
        le32[0..4].copy_from_slice(&0u32.to_le_bytes());
        let m = packed_mech(CKM_EDDSA, le32.as_ptr(), le32.len());
        assert!(!unsafe { eddsa_ph_flag(m.as_ptr() as *const u8) });

        // No parameter at all is not pre-hashed either.
        let m = packed_mech(CKM_EDDSA, std::ptr::null(), 0);
        assert!(!unsafe { eddsa_ph_flag(m.as_ptr() as *const u8) });
    }

    /// The vendor KMAC parameter block's first field is a POINTER. Read as a
    /// u32 on LP64 it kept only the low half and was then dereferenced, so
    /// this asserts the layout the reader now assumes — a pointer-width first
    /// field followed by two CK_ULONGs, 12 B on wasm32 and 24 B on LP64.
    #[test]
    fn kmac_params_are_pointer_width() {
        #[repr(C)]
        struct CkKmacParams {
            p_customization: *const u8,
            ul_customization_len: usize,
            ul_output_len: usize,
        }
        assert_eq!(size_of::<CkKmacParams>(), 3 * size_of::<usize>());
        // The old reader's 12-byte assumption only holds where a pointer is
        // 4 bytes; asserting it here means a 64-bit build can never silently
        // go back to it.
        if size_of::<usize>() == 8 {
            assert_ne!(size_of::<CkKmacParams>(), 12);
        }
    }

    /// End-to-end through the ported parser: the half-sized
    /// `CK_MAC_GENERAL_PARAMS` the old length guard accepted is now refused.
    ///
    /// Old guard: `if p_param == 0 || param_len < usz` — but the *read* was
    /// `*(p_param as *const u32)`, so on LP64 a caller supplying 4 bytes got
    /// past a guard written for the read that was there before it, and the
    /// engine took the CK_ULONG's top four bytes from beyond the buffer.
    #[test]
    fn mac_general_params_refuse_a_half_sized_parameter() {
        let mech = CKM_SHA256_HMAC_GENERAL;

        // A full, well-formed parameter is accepted and read at native width.
        let full = 16usize.to_ne_bytes();
        let m = packed_mech(mech, full.as_ptr(), full.len());
        assert_eq!(
            unsafe { parse_sign_mech_params(m.as_ptr() as *const u8, mech) },
            Ok((16u32.to_le_bytes().to_vec(), false)),
        );

        // Half of one, which is what a 32-bit caller's struct looks like.
        let half = 16u32.to_ne_bytes();
        let m = packed_mech(mech, half.as_ptr(), half.len());
        if size_of::<usize>() == 8 {
            assert_eq!(
                unsafe { parse_sign_mech_params(m.as_ptr() as *const u8, mech) },
                Err(CKR_MECHANISM_PARAM_INVALID),
                "require_len must reject a half-sized CK_MAC_GENERAL_PARAMS \
                 rather than reading four bytes past the caller's buffer",
            );
        }
    }

    /// End-to-end through the ported parser: the KMAC customization pointer
    /// survives at full width and the customization string comes back intact.
    /// The old reading kept the pointer's low half and dereferenced it.
    #[test]
    fn kmac_customization_pointer_survives_at_full_width() {
        let custom = b"tenant-7".to_vec();
        // pCustomization / ulCustomizationLen / ulOutputLen at native width.
        let mut param = vec![0u8; 3 * size_of::<usize>()];
        let w = size_of::<usize>();
        param[0..w].copy_from_slice(&(custom.as_ptr() as usize).to_ne_bytes());
        param[w..2 * w].copy_from_slice(&custom.len().to_ne_bytes());
        param[2 * w..3 * w].copy_from_slice(&32usize.to_ne_bytes());

        let m = packed_mech(CKM_KMAC_128, param.as_ptr(), param.len());
        let (ctx, det) =
            unsafe { parse_sign_mech_params(m.as_ptr() as *const u8, CKM_KMAC_128) }.unwrap();
        assert!(!det);
        // ctx = LE u32 output length, then the customization bytes verbatim.
        assert_eq!(&ctx[0..4], &32u32.to_le_bytes());
        assert_eq!(&ctx[4..], &custom[..]);
    }

    /// End-to-end through the ported parser: the counter block is the
    /// caller's, not the caller's shifted four bytes right.
    #[test]
    fn aes_ctr_counter_block_is_the_callers() {
        let cb: Vec<u8> = (0xa0u8..0xb0).collect();
        let w = size_of::<usize>();
        let mut param = vec![0u8; w + 16];
        param[0..w].copy_from_slice(&128usize.to_ne_bytes());
        param[w..w + 16].copy_from_slice(&cb);
        let (got, bits) = unsafe { parse_aes_ctr_params(param.as_ptr(), param.len()) }.unwrap();
        assert_eq!(bits, 128);
        assert_eq!(got, cb, "cb comes from the ABI offset, not from a literal 4");

        // The pre-844ed27 struct — a 20-byte buffer with cb at offset 4 — is
        // now TooShort on LP64 rather than being read as if it were valid.
        if w == 8 {
            let mut old_shaped = vec![0u8; 20];
            old_shaped[0..4].copy_from_slice(&128u32.to_ne_bytes());
            old_shaped[4..20].copy_from_slice(&cb);
            assert_eq!(
                unsafe { parse_aes_ctr_params(old_shaped.as_ptr(), old_shaped.len()) },
                Err(CKR_MECHANISM_PARAM_INVALID),
            );
        }
    }

    /// "typedef CK_ULONG CK_MAC_GENERAL_PARAMS" — one CK_ULONG, so the
    /// parameter is 8 bytes on LP64, not 4.
    #[test]
    fn mac_general_params_is_one_ck_ulong() {
        assert_eq!(size_of::<crate::ck_abi::CK_ULONG>(), size_of::<usize>());
    }

    // ── get_attr_ulong: the template-side twin of the same bug class ──────
    //
    // Every test below is written so that it FAILS against the pre-2026-08-14
    // body, which was:
    //
    //     let val_ptr = *ptr.add(i * 3 + 1) as *const u32;
    //     if !val_ptr.is_null() { return Some(read_unaligned(val_ptr)); }
    //
    // — a fixed four-byte read with `ulValueLen` never consulted. The old
    // reading is reconstructed inline in each test and asserted to differ, so
    // the evidence does not depend on anyone remembering what it used to say.

    /// Build a packed `CK_ATTRIBUTE` array: three words per entry
    /// (`type`, `pValue`, `ulValueLen`), which is the layout `get_attr_ulong`
    /// strides over.
    fn packed_template(entries: &[(u32, *const u8, usize)]) -> Vec<usize> {
        let mut v = Vec::with_capacity(entries.len() * 3);
        for &(t, p, len) in entries {
            v.push(t as usize);
            v.push(p as usize);
            v.push(len);
        }
        v
    }

    /// The old reading, reconstructed: four bytes from `pValue`, no length
    /// check. Used only to demonstrate the divergence.
    unsafe fn old_get_attr_ulong(template: *mut u8, count: u32, attr_type: u32) -> Option<u32> {
        let ptr = template as *mut usize;
        for i in 0..count {
            if *ptr.add((i * 3) as usize) as u32 == attr_type {
                let val_ptr = *ptr.add((i * 3 + 1) as usize) as *const u32;
                if !val_ptr.is_null() {
                    return Some(std::ptr::read_unaligned(val_ptr));
                }
            }
        }
        None
    }

    /// **The reported defect.** A caller supplying a one-byte `pValue` got a
    /// four-byte read: three bytes of whatever followed it in the caller's
    /// address space, assembled into a "key type" the caller never wrote.
    ///
    /// The buffer here places `0x07` where the attribute points and `ff ff ff`
    /// immediately after it, so the old body's answer is deterministic —
    /// `Some(0xffffff07)` on little-endian — and demonstrably not the caller's
    /// value.
    #[test]
    fn get_attr_ulong_refuses_a_short_value_instead_of_reading_past_it() {
        let buf: [u8; 4] = [0x07, 0xff, 0xff, 0xff];
        let tpl = packed_template(&[(CKA_KEY_TYPE, buf.as_ptr(), 1)]);
        let p = tpl.as_ptr() as *mut u8;

        let old = unsafe { old_get_attr_ulong(p, 1, CKA_KEY_TYPE) };
        assert_eq!(
            old,
            Some(u32::from_ne_bytes(buf)),
            "precondition: the old body reads all four bytes, ulValueLen=1 notwithstanding",
        );

        assert_eq!(
            unsafe { crate::crypto::handlers::get_attr_ulong(p, 1, CKA_KEY_TYPE) },
            None,
            "ulValueLen=1 is not a CK_ULONG; the attribute must read as absent, \
             not as three bytes of the caller's neighbouring memory",
        );
    }

    /// The zero-length form — how a caller asks C_GetAttributeValue to SIZE an
    /// attribute, and a shape the engine must never take a value from. The old
    /// body dereferenced `pValue` regardless.
    #[test]
    fn get_attr_ulong_refuses_a_zero_length_value() {
        let buf = 0xdeadbeefu32.to_ne_bytes();
        let tpl = packed_template(&[(CKA_VALUE_LEN, buf.as_ptr(), 0)]);
        let p = tpl.as_ptr() as *mut u8;

        assert_eq!(unsafe { old_get_attr_ulong(p, 1, CKA_VALUE_LEN) }, Some(0xdeadbeef));
        assert_eq!(
            unsafe { crate::crypto::handlers::get_attr_ulong(p, 1, CKA_VALUE_LEN) },
            None,
        );
    }

    /// An over-long value is equally not a `CK_ULONG`. Sixteen bytes is what a
    /// caller who passed a struct, or a byte-array attribute, would present;
    /// the old body silently took its first four.
    #[test]
    fn get_attr_ulong_refuses_an_over_long_value() {
        let buf = [0x11u8; 16];
        let tpl = packed_template(&[(CKA_VALUE_LEN, buf.as_ptr(), 16)]);
        let p = tpl.as_ptr() as *mut u8;

        assert_eq!(unsafe { old_get_attr_ulong(p, 1, CKA_VALUE_LEN) }, Some(0x11111111));
        assert_eq!(
            unsafe { crate::crypto::handlers::get_attr_ulong(p, 1, CKA_VALUE_LEN) },
            None,
        );
    }

    /// A well-formed `CK_ULONG` attribute is read at the target's **native**
    /// width. The value's top half is non-zero, so the old four-byte read
    /// loses it: `get_attr_ulong_native` returns the whole word where the old
    /// body could only ever return the low one.
    #[test]
    fn get_attr_ulong_reads_the_whole_ck_ulong() {
        let w = size_of::<crate::ck_abi::CK_ULONG>();
        assert_eq!(w, size_of::<usize>());

        // 0x0000_0005_0000_0001 on LP64 — low half 1, top half 5.
        let value: usize = if w == 8 { (5usize << 32) | 1 } else { 1 };
        let buf = value.to_ne_bytes();
        let tpl = packed_template(&[(CKA_PARAMETER_SET, buf.as_ptr(), w)]);
        let p = tpl.as_ptr() as *mut u8;

        assert_eq!(
            unsafe { crate::crypto::handlers::get_attr_ulong_native(p, 1, CKA_PARAMETER_SET) },
            Some(value),
            "the reader must take sizeof(CK_ULONG) bytes, not four",
        );

        if w == 8 {
            // The old body could not distinguish this word from a bare 1.
            assert_eq!(unsafe { old_get_attr_ulong(p, 1, CKA_PARAMETER_SET) }, Some(1));
            assert_ne!(
                unsafe { crate::crypto::handlers::get_attr_ulong_native(p, 1, CKA_PARAMETER_SET) },
                Some(1),
            );
        }

        // The narrowing wrapper is the engine's internal 32-bit view and is
        // documented as such — it agrees with the low half by design.
        assert_eq!(
            unsafe { crate::crypto::handlers::get_attr_ulong(p, 1, CKA_PARAMETER_SET) },
            Some(1),
        );
    }

    // ── §6.66.6: "This mechanism does not have a parameter" ──────────────
    //
    // The two key-pair-generation arms used to read a one-word mechanism
    // parameter as a fallback for the parameter set, AT DIFFERENT WIDTHS —
    // u32 in the XMSS arm, native usize in the XMSSMT arm — for a struct that
    // exists in neither pkcs11t.h nor the canonical OASIS header. The spec
    // settles it by saying there is no parameter, so both reads are gone and
    // both arms resolve through one function that cannot see a mechanism.

    /// A one-attribute template naming a parameter set, at native width.
    fn ps_only(attr: u32, ps: crate::ck_abi::CK_ULONG) -> ([usize; 3], Box<crate::ck_abi::CK_ULONG>)
    {
        let boxed = Box::new(ps);
        let tpl = [
            attr as usize,
            &*boxed as *const crate::ck_abi::CK_ULONG as usize,
            size_of::<crate::ck_abi::CK_ULONG>(),
        ];
        (tpl, boxed)
    }

    /// The resolver takes no mechanism pointer at all — which is the point —
    /// and both arms reach the same answer for the same template. XMSS and
    /// XMSSMT differ only in which legacy vendor attribute and which default
    /// they are given.
    #[test]
    fn xmss_keygen_param_set_comes_only_from_the_public_template() {
        // Absent everywhere ⇒ the arm's own documented default, and the two
        // arms disagree ONLY in that default.
        assert_eq!(
            unsafe {
                xmss_keygen_param_set(
                    core::ptr::null_mut(),
                    0,
                    CKA_XMSS_PARAM_SET,
                    CKP_XMSS_SHA2_10_256,
                )
            },
            CKP_XMSS_SHA2_10_256,
        );
        assert_eq!(
            unsafe {
                xmss_keygen_param_set(
                    core::ptr::null_mut(),
                    0,
                    CKA_XMSSMT_PARAM_SET,
                    CKP_XMSSMT_SHA2_20_2_256,
                )
            },
            CKP_XMSSMT_SHA2_20_2_256,
        );

        // The STANDARD attribute wins.
        let (mut tpl, _keep) =
            ps_only(CKA_PARAMETER_SET, CKP_XMSS_SHA2_16_256 as crate::ck_abi::CK_ULONG);
        assert_eq!(
            unsafe {
                xmss_keygen_param_set(
                    tpl.as_mut_ptr() as *mut u8,
                    1,
                    CKA_XMSS_PARAM_SET,
                    CKP_XMSS_SHA2_10_256,
                )
            },
            CKP_XMSS_SHA2_16_256,
        );
        // Same template, XMSSMT arm's parameters: same answer. The two arms
        // can no longer disagree about a template, because there is only one
        // reader and it has no width choice left to make.
        assert_eq!(
            unsafe {
                xmss_keygen_param_set(
                    tpl.as_mut_ptr() as *mut u8,
                    1,
                    CKA_XMSSMT_PARAM_SET,
                    CKP_XMSSMT_SHA2_20_2_256,
                )
            },
            CKP_XMSS_SHA2_16_256,
        );

        // The legacy vendor attribute is still accepted as an input fallback.
        let (mut vt, _keep2) =
            ps_only(CKA_XMSS_PARAM_SET, CKP_XMSS_SHAKE_10_256 as crate::ck_abi::CK_ULONG);
        assert_eq!(
            unsafe {
                xmss_keygen_param_set(
                    vt.as_mut_ptr() as *mut u8,
                    1,
                    CKA_XMSS_PARAM_SET,
                    CKP_XMSS_SHA2_10_256,
                )
            },
            CKP_XMSS_SHAKE_10_256,
        );
    }

    /// End-to-end on the fast arm: a mechanism parameter is **ignored**.
    ///
    /// The mechanism carries a word naming a parameter set this token does not
    /// implement. Before 2026-08-14 the XMSS arm read that word and answered
    /// `CKR_PARAMETER_SET_NOT_SUPPORTED`; §6.66.6 says the mechanism has no
    /// parameter, so the correct outcome is that the word is not looked at and
    /// the template's absent parameter set falls to the token's default.
    #[test]
    fn xmss_keygen_ignores_a_mechanism_parameter() {
        // Hardcodes slot_id=0, which needs test_lock's reset guarantee (a
        // slot really does exist, uninitialized) now that C_Finalize no
        // longer wipes TOKEN_STORE — see test_lock's own doc comment.
        let _guard = crate::native::test_lock::acquire();
        // Other tests in this binary share the process, so the library may
        // already be initialised — both answers are correct here.
        let rv_init = C_Initialize(core::ptr::null_mut());
        assert!(
            rv_init == CKR_OK || rv_init == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize: {rv_init:#x}",
        );
        let mut sess: u32 = 0;
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut sess,
            ),
            CKR_OK,
        );

        // A parameter word naming a code no XMSS parameter set uses.
        let bogus: crate::ck_abi::CK_ULONG = 0x0000_dead;
        let mut m = packed_mech(
            CKM_XMSS_KEY_PAIR_GEN,
            &bogus as *const crate::ck_abi::CK_ULONG as *const u8,
            size_of::<crate::ck_abi::CK_ULONG>(),
        );

        let (mut h_pub, mut h_prv) = (0u32, 0u32);
        let rv = C_GenerateKeyPair(
            sess,
            m.as_mut_ptr() as *mut u8,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
            &mut h_pub,
            &mut h_prv,
        );
        assert_eq!(
            rv, CKR_OK,
            "the mechanism parameter must not be read; before the fix this \
             word was taken as the parameter set and the call failed with \
             CKR_PARAMETER_SET_NOT_SUPPORTED",
        );
        assert_eq!(
            get_object_attr_u32(h_pub, CKA_PARAMETER_SET),
            Some(CKP_XMSS_SHA2_10_256),
            "with no CKA_PARAMETER_SET in the template the token's default \
             applies — not something recovered from pParameter",
        );
    }

    // ── CK_BIP32_CHILD_DERIVE_PARAMS: pNext is FIRST ────────────────────
    //
    // Adjudication, 2026-08-14. BIP32 is a PQCToday vendor extension
    // (CKM_VENDOR_DEFINED | 0x105c) and appears nowhere in the OASIS header or
    // the v3.2 text, so `src/lib/pkcs11/pkcs11t.h:2139` is the only definition
    // there is — and the C++ engine already implements exactly it. This engine
    // read two u32s at offsets 0 and 4, taking pNext as flags. The header
    // wins; these tests pin that.

    /// The declared layout is the header's, on both ABIs.
    #[test]
    fn bip32_child_derive_layout_matches_the_header() {
        use crate::ck_param::{bip32_child_derive as b, offset_at, size_at};
        // LP64: pNext 0, flags 8, index 16, sizeof 24.
        assert_eq!(offset_at(b::LAYOUT.fields, b::P_NEXT, 8), 0);
        assert_eq!(offset_at(b::LAYOUT.fields, b::FLAGS, 8), 8);
        assert_eq!(offset_at(b::LAYOUT.fields, b::INDEX, 8), 16);
        assert_eq!(size_at(b::LAYOUT.fields, 8), 24);
        // wasm32/ILP32: 0, 4, 8, sizeof 12 — NOT the 8 bytes the hub's
        // buildBIP32ChildDeriveParams currently emits.
        assert_eq!(offset_at(b::LAYOUT.fields, b::P_NEXT, 4), 0);
        assert_eq!(offset_at(b::LAYOUT.fields, b::FLAGS, 4), 4);
        assert_eq!(offset_at(b::LAYOUT.fields, b::INDEX, 4), 8);
        assert_eq!(size_at(b::LAYOUT.fields, 4), 12);
    }

    /// End-to-end: `flags` and `index` come from words one and two, and a
    /// non-NULL `pNext` — which the old reading consumed as those two fields —
    /// changes nothing about the derived child.
    #[test]
    fn bip32_child_derive_reads_flags_and_index_past_pnext() {
        use crate::crypto::HDCurve;

        // Hardcodes slot_id=0, which needs test_lock's reset guarantee (a
        // slot really does exist, uninitialized) now that C_Finalize no
        // longer wipes TOKEN_STORE — see test_lock's own doc comment.
        let _guard = crate::native::test_lock::acquire();
        let rv_init = C_Initialize(core::ptr::null_mut());
        assert!(rv_init == CKR_OK || rv_init == CKR_CRYPTOKI_ALREADY_INITIALIZED);
        let mut sess: u32 = 0;
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut sess,
            ),
            CKR_OK,
        );

        // secp256k1 = 1.3.132.0.10.
        let ec_params: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];

        // The parent node, supplied directly rather than derived, so this test
        // is about the parameter struct and nothing else. A generic-secret
        // object keeps it out of the private-object login gate; the BIP32
        // child path reads the base key's CKA_VALUE and CKA_BIP32_CHAIN_CODE
        // and does not look at the class.
        let master_priv: Vec<u8> = (1u8..=32).collect();
        let master_cc: Vec<u8> = (0x40u8..0x60).collect();
        let cls = CKO_SECRET_KEY as crate::ck_abi::CK_ULONG;
        let kt = CKK_GENERIC_SECRET as crate::ck_abi::CK_ULONG;
        let yes: u8 = 1;
        let w = size_of::<crate::ck_abi::CK_ULONG>();
        let mut base_tpl: Vec<usize> = Vec::new();
        for (t, p, l) in [
            (CKA_CLASS, &cls as *const _ as *const u8, w),
            (CKA_KEY_TYPE, &kt as *const _ as *const u8, w),
            (CKA_VALUE, master_priv.as_ptr(), master_priv.len()),
            (CKA_BIP32_CHAIN_CODE, master_cc.as_ptr(), master_cc.len()),
            (CKA_DERIVE, &yes as *const u8, 1),
        ] {
            base_tpl.extend_from_slice(&[t as usize, p as usize, l]);
        }
        let mut h_master: u32 = 0;
        assert_eq!(
            C_CreateObject(sess, base_tpl.as_mut_ptr() as *mut u8, 5, &mut h_master),
            CKR_OK,
        );

        let mut derive_tpl: Vec<usize> = Vec::new();
        for (t, p, l) in [
            (CKA_EC_PARAMS, ec_params.as_ptr(), ec_params.len()),
            (CKA_DERIVE, &yes as *const u8, 1),
        ] {
            derive_tpl.extend_from_slice(&[t as usize, p as usize, l]);
        }

        // The header's struct, with a deliberately NON-NULL pNext. It is never
        // dereferenced; it is there so that the old reading — flags from word
        // 0, index from word 1 — produces something unmistakably different.
        const FAKE_NEXT: usize = 0x0000_0001_0000_0002;
        const WANT_INDEX: u32 = 7;
        let mut param: Vec<usize> = vec![FAKE_NEXT, 0 /* flags: not hardened */, WANT_INDEX as usize];
        let mut m_child = packed_mech(
            CKM_BIP32_CHILD_DERIVE,
            param.as_mut_ptr() as *const u8,
            param.len() * size_of::<usize>(),
        );
        let mut h_child: u32 = 0;
        assert_eq!(
            C_DeriveKey(
                sess,
                m_child.as_mut_ptr() as *mut u8,
                h_master,
                derive_tpl.as_mut_ptr() as *mut u8,
                2,
                &mut h_child,
            ),
            CKR_OK,
        );
        let got = get_object_value(h_child).expect("child private value");

        let (want, _) =
            crate::crypto::derive_child_node(&master_priv, &master_cc, WANT_INDEX, false, HDCurve::Secp256k1)
                .expect("reference child");
        assert_eq!(
            got, want,
            "flags must be read at word 1 and index at word 2, past pNext",
        );

        // What the pre-2026-08-14 reading would have produced from this exact
        // buffer: flags = pNext's low word (2, non-zero ⇒ HARDENED) and
        // index = pNext's high word (1).
        let (old_reading, _) =
            crate::crypto::derive_child_node(&master_priv, &master_cc, 1, true, HDCurve::Secp256k1)
                .expect("old-reading child");
        assert_ne!(
            got, old_reading,
            "the two readings must be distinguishable, or this test proves nothing",
        );

        // A buffer too short for the header's struct is refused, as C++ does.
        let mut short = [0usize; 2];
        let mut m_short = packed_mech(
            CKM_BIP32_CHILD_DERIVE,
            short.as_mut_ptr() as *const u8,
            2 * size_of::<usize>(),
        );
        let mut h_bad: u32 = 0;
        assert_eq!(
            C_DeriveKey(
                sess,
                m_short.as_mut_ptr() as *mut u8,
                h_master,
                derive_tpl.as_mut_ptr() as *mut u8,
                2,
                &mut h_bad,
            ),
            CKR_ARGUMENTS_BAD,
            "the hub playground's 8-byte two-word struct is not this struct",
        );
    }

    /// The `i * 3` stride is ABI-correct and stays: an attribute in the third
    /// slot of a four-entry template is still found, and the entries before it
    /// (one of them malformed) do not derail the walk.
    #[test]
    fn get_attr_ulong_stride_reaches_a_later_entry() {
        let w = size_of::<usize>();
        let bad = [0xaau8; 2];
        let kt = (CKK_AES as usize).to_ne_bytes();
        let vl = (32usize).to_ne_bytes();
        let tpl = packed_template(&[
            (CKA_CLASS, bad.as_ptr(), 2),      // wrong length — skipped
            (CKA_TOKEN, core::ptr::null(), w), // null pValue — skipped
            (CKA_KEY_TYPE, kt.as_ptr(), w),
            (CKA_VALUE_LEN, vl.as_ptr(), w),
        ]);
        let p = tpl.as_ptr() as *mut u8;

        assert_eq!(unsafe { crate::crypto::handlers::get_attr_ulong(p, 4, CKA_CLASS) }, None);
        assert_eq!(unsafe { crate::crypto::handlers::get_attr_ulong(p, 4, CKA_TOKEN) }, None);
        assert_eq!(
            unsafe { crate::crypto::handlers::get_attr_ulong(p, 4, CKA_KEY_TYPE) },
            Some(CKK_AES),
        );
        assert_eq!(
            unsafe { crate::crypto::handlers::get_attr_ulong(p, 4, CKA_VALUE_LEN) },
            Some(32),
        );
    }
}
