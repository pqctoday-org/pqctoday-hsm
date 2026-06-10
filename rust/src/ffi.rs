#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::constants::*;
use crate::crypto::*;
use crate::slh_dsa_keygen;
use crate::state::*;

use rand::SeedableRng;
use rand::rngs::OsRng;

/// ACVP-aware RNG selection macro.
/// In ACVP mode, uses the persistent ChaCha20Rng from thread-local state
/// so the counter advances across operations (matching C++ OpenSSL behaviour).
/// In normal mode, uses OsRng for non-deterministic randomness.
///
/// Implementation: `take()` extracts the RNG from thread-local into a local
/// variable, runs $body inline (NOT in a closure — so `return` works normally),
/// then restores the advanced RNG back to thread-local. If $body exits via
/// `return` (error paths), the RNG is lost but `C_Initialize` recreates it.
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
            // Restore the (now-advanced) RNG back to thread-local state
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
    // Zeroize all key material (CKA_VALUE) before clearing object store
    OBJECTS.with(|o| {
        let mut store = o.borrow_mut();
        for attrs in store.values_mut() {
            if let Some(val) = attrs.get_mut(&CKA_VALUE) {
                val.zeroize();
            }
        }
        store.clear();
    });
    NEXT_HANDLE.with(|h| *h.borrow_mut() = 100);
    SIGN_STATE.with(|s| s.borrow_mut().clear());
    VERIFY_STATE.with(|s| s.borrow_mut().clear());
    VERIFY_SIG_STATE.with(|s| s.borrow_mut().clear());
    ENCRYPT_STATE.with(|s| s.borrow_mut().clear());
    DECRYPT_STATE.with(|s| s.borrow_mut().clear());
    // Message-based AEAD state holds raw key bytes — zeroize before drop.
    MESSAGE_ENCRYPT_STATE.with(|s| {
        let mut m = s.borrow_mut();
        for ctx in m.values_mut() {
            ctx.key.zeroize();
        }
        m.clear();
    });
    MESSAGE_DECRYPT_STATE.with(|s| {
        let mut m = s.borrow_mut();
        for ctx in m.values_mut() {
            ctx.key.zeroize();
        }
        m.clear();
    });
    DIGEST_STATE.with(|s| s.borrow_mut().clear());
    FIND_STATE.with(|s| s.borrow_mut().clear());
    MESSAGE_SIGN_ACC.with(|s| s.borrow_mut().clear());
    MESSAGE_VERIFY_ACC.with(|s| s.borrow_mut().clear());
    ACVP_RNG.with(|r| *r.borrow_mut() = None);
    SESSIONS.with(|s| s.borrow_mut().clear());
    TOKEN_STORE.with(|ts| ts.borrow_mut().clear());
    crate::state::set_initialized(false);
    CKR_OK
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

    // Hash PIN with PBKDF2
    let mut salt = [0u8; 16];
    if getrandom::getrandom(&mut salt).is_err() {
        return CKR_GENERAL_ERROR;
    }
    let pin_bytes = unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) };
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

    if success { CKR_OK } else { CKR_SLOT_ID_INVALID }
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
        let handle = NEXT_SESSION_HANDLE.with(|h| {
            let current = *h.borrow();
            *h.borrow_mut() = current + 1;
            current
        });
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
            ctx.key.zeroize();
        }
    });
    MESSAGE_DECRYPT_STATE.with(|s| {
        if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
            ctx.key.zeroize();
        }
    });
    DIGEST_STATE.with(|s| s.borrow_mut().remove(&h_session));
    FIND_STATE.with(|s| s.borrow_mut().remove(&h_session));
    MESSAGE_SIGN_ACC.with(|s| s.borrow_mut().remove(&h_session));
    MESSAGE_VERIFY_ACC.with(|s| s.borrow_mut().remove(&h_session));
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
    }
    if flags & 0x800 != 0 {
        SIGN_STATE.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x2000 != 0 {
        VERIFY_STATE.with(|s| s.borrow_mut().remove(&h_session));
        VERIFY_SIG_STATE.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x40 != 0 {
        FIND_STATE.with(|s| s.borrow_mut().remove(&h_session));
    }
    if flags & 0x2 != 0 {
        MESSAGE_ENCRYPT_STATE.with(|s| {
            if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
                ctx.key.zeroize();
            }
        });
    }
    if flags & 0x4 != 0 {
        MESSAGE_DECRYPT_STATE.with(|s| {
            if let Some(mut ctx) = s.borrow_mut().remove(&h_session) {
                ctx.key.zeroize();
            }
        });
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
    ul_username_len: u32,
) -> u32 {
    require_init!();
    if ul_username_len > 0 {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    C_Login(h_session, user_type, p_pin, ul_pin_len)
}

#[wasm_bindgen(js_name = _C_Login)]
pub fn C_Login(h_session: u32, user_type: u32, p_pin: *mut u8, ul_pin_len: u32) -> u32 {
    require_init!();
    if p_pin.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let session = match SESSIONS.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(s) => s,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let slot_id = session.slot_id;

    if user_type == CKU_SO && !session.rw_session {
        return CKR_SESSION_READ_ONLY_EXISTS;
    }

    let token_opt = TOKEN_STORE.with(|ts| ts.borrow().get(&slot_id).cloned());
    let token = if let Some(t) = token_opt {
        t
    } else {
        return CKR_GENERAL_ERROR;
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
            let has_ro = SESSIONS.with(|s| {
                s.borrow()
                    .values()
                    .any(|sess| sess.slot_id == slot_id && !sess.rw_session)
            });
            if has_ro {
                return CKR_SESSION_READ_ONLY_EXISTS;
            }

            let pin_bytes = unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) };
            if hash_pin(pin_bytes, &token.so_pin_salt) != token.so_pin_hash {
                return CKR_PIN_INCORRECT;
            }
            TOKEN_STORE.with(|ts| {
                if let Some(mut t) = ts.borrow_mut().get_mut(&slot_id) {
                    t.login_state = LoginState::SO;
                }
            });
        }
        CKU_USER => {
            if token.login_state == LoginState::User {
                return CKR_USER_ALREADY_LOGGED_IN;
            }
            if token.login_state == LoginState::SO {
                return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
            }
            if token.user_pin_hash.is_none() || token.user_pin_salt.is_none() {
                return CKR_USER_PIN_NOT_INITIALIZED;
            }
            let pin_bytes = unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) };
            if let (Some(salt), Some(hash)) = (&token.user_pin_salt, &token.user_pin_hash) {
                if hash_pin(pin_bytes, salt) != *hash {
                    return CKR_PIN_INCORRECT;
                }
            } else {
                return CKR_USER_PIN_NOT_INITIALIZED;
            }
            TOKEN_STORE.with(|ts| {
                if let Some(mut t) = ts.borrow_mut().get_mut(&slot_id) {
                    t.login_state = LoginState::User;
                }
            });
        }
        _ => return CKR_USER_TYPE_INVALID,
    }
    CKR_OK
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
        CKR_OK
    } else {
        CKR_USER_NOT_LOGGED_IN
    }
}

#[wasm_bindgen(js_name = _C_InitPIN)]
pub fn C_InitPIN(h_session: u32, p_pin: *mut u8, ul_pin_len: u32) -> u32 {
    require_init!();
    if p_pin.is_null() {
        return CKR_ARGUMENTS_BAD;
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
    let mut success = false;
    let mut not_logged_in = false;
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
            let pin_bytes = unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) };
            token.user_pin_hash = Some(hash_pin(pin_bytes, &salt));
            token.user_pin_salt = Some(salt);
            success = true;
        }
    });
    if not_logged_in {
        return CKR_USER_NOT_LOGGED_IN;
    }
    if success { CKR_OK } else { CKR_GENERAL_ERROR }
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
    unsafe {
        std::ptr::write_bytes(p_info, 0x20, 160);
        write_fixed_str(p_info, 0, "SoftHSM3-Rust", 32);
        write_fixed_str(p_info, 32, "SoftHSM project", 32);
        write_fixed_str(p_info, 64, "PQCToday", 16);
        write_fixed_str(p_info, 80, "0001", 16);

        let ptr = p_info as *mut u32;
        // CKF_RNG (0x1) | CKF_LOGIN_REQUIRED (0x4) | CKF_USER_PIN_INITIALIZED
        // (0x8) | CKF_TOKEN_INITIALIZED (0x400). The former value 0x0004040D
        // ALSO set CKF_USER_PIN_LOCKED (0x40000), which made conformant clients
        // refuse to attempt login — that bit is now cleared (PKCS#11 v3.2 §5.5).
        let _ = &token; // slot validated above
        *ptr.add(24) = 0x0000_040D;
        *ptr.add(25) = 256;
        *ptr.add(26) = 1;
        *ptr.add(27) = 256;
        *ptr.add(28) = 1;
        *ptr.add(29) = 256;
        *ptr.add(30) = 4;
        *p_info.add(140) = 3;
        *p_info.add(141) = 2;
        *p_info.add(142) = 0;
        *p_info.add(143) = 1;
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_GetMechanismInfo)]
pub fn C_GetMechanismInfo(_slot_id: u32, mech_type: u32, p_info: *mut u8) -> u32 {
    require_init!();
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
pub fn mechanism_info(mech_type: u32) -> Option<(u32, u32, u32)> {
    let info = match mech_type {
        CKM_RSA_PKCS_KEY_PAIR_GEN => (2048, 4096, 0x00010000u32),
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => (2048, 4096, 0x00000800 | 0x00002000),
        CKM_RSA_PKCS_OAEP => (2048, 4096, 0x00000100 | 0x00000200),
        CKM_ML_KEM_KEY_PAIR_GEN => (512, 1024, 0x00010000),
        CKM_ML_KEM => (512, 1024, 0x10000000 | 0x20000000),
        CKM_ML_DSA_KEY_PAIR_GEN => (44, 87, 0x00010000),
        // CKF_SIGN | CKF_VERIFY | CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY —
        // C_MessageSign/Verify* are implemented for these (pkcs11t.h 0x8/0x10).
        CKM_ML_DSA => (44, 87, 0x00000800 | 0x00002000 | 0x0008 | 0x0010),
        CKM_SLH_DSA_KEY_PAIR_GEN => (128, 256, 0x00010000),
        CKM_SLH_DSA => (128, 256, 0x00000800 | 0x00002000 | 0x0008 | 0x0010),
        CKM_SHA256 | CKM_SHA384 | CKM_SHA512 | CKM_SHA3_256 | CKM_SHA3_512 => (0, 0, 0x00000400),
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
        | CKM_SHA3_512_HMAC => (16, 64, 0x00000800 | 0x00002000),
        CKM_SHA256_HMAC_GENERAL
        | CKM_SHA384_HMAC_GENERAL
        | CKM_SHA512_HMAC_GENERAL
        | CKM_SHA3_256_HMAC_GENERAL
        | CKM_SHA3_512_HMAC_GENERAL => (16, 64, 0x00000800 | 0x00002000),
        CKM_KMAC_128 | CKM_KMAC_256 => (16, 64, 0x00000800 | 0x00002000),
        CKM_GENERIC_SECRET_KEY_GEN => (1, 512, 0x00008000),
        CKM_EC_KEY_PAIR_GEN => (256, 384, 0x00010000),
        CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
            (256, 384, 0x00000800 | 0x00002000)
        }
        CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE => (256, 384, 0x00080000),
        CKM_EC_EDWARDS_KEY_PAIR_GEN => (255, 255, 0x00010000),
        CKM_EDDSA => (255, 255, 0x00000800 | 0x00002000),
        // PKCS#11 v3.2 §6.7 — Montgomery-curve key pair generation (X25519=255-bit, X448=448-bit)
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN => (255, 448, 0x00010000),
        // PKCS#11 v3.2 §6.7 — Montgomery key derivation (X25519 or X448)
        CKM_EC_MONTGOMERY_KEY_DERIVE => (255, 448, 0x00080000),
        CKM_AES_KEY_GEN => (16, 32, 0x00008000),
        // AES-GCM additionally has C_EncryptMessage/C_DecryptMessage support
        // (CKF_MESSAGE_ENCRYPT 0x2 | CKF_MESSAGE_DECRYPT 0x4, pkcs11t.h).
        CKM_AES_GCM => (16, 32, 0x00000100 | 0x00000200 | 0x0002 | 0x0004),
        CKM_AES_CBC_PAD | CKM_AES_CBC | CKM_AES_ECB => {
            (16, 32, 0x00000100 | 0x00000200)
        }
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
        | CKM_HASH_ML_DSA_SHAKE256 => (44, 87, 0x00000800 | 0x00002000),
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
        | CKM_HASH_SLH_DSA_SHAKE256 => (128, 256, 0x00000800 | 0x00002000),
        // ECDSA-SHA3 variants
        CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256 | CKM_ECDSA_SHA3_384 | CKM_ECDSA_SHA3_512 => {
            (256, 384, 0x00000800 | 0x00002000)
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
        CKM_ECDSA => (256, 521, 0x00000800 | 0x00002000),
        // Ed25519ph (pkcs11t.h CKM_EDDSA_PH 0x80001057)
        CKM_EDDSA_PH => (255, 255, 0x00000800 | 0x00002000),
        // Parametrized pre-hash mechanisms (hash chosen via param, §6.67.7/§6.69.7)
        CKM_HASH_ML_DSA => (44, 87, 0x00000800 | 0x00002000),
        CKM_HASH_SLH_DSA => (128, 256, 0x00000800 | 0x00002000),
        // Stateful hash-based signatures (§6.14/§6.66) — sign on the private
        // key only while it has leaves remaining; verify is stateless
        CKM_HSS_KEY_PAIR_GEN | CKM_XMSS_KEY_PAIR_GEN | CKM_XMSSMT_KEY_PAIR_GEN => {
            (0, 0, 0x00010000)
        }
        CKM_HSS | CKM_XMSS | CKM_XMSSMT => (0, 0, 0x00000800 | 0x00002000),
        // Vendor Keccak-256 digest (Ethereum address derivation)
        CKM_KECCAK_256 => (0, 0, 0x00000400),
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
}

// ── Key Generation ───────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_GenerateKeyPair)]
pub fn C_GenerateKeyPair(
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
        let mech_type = *(p_mechanism as *const u32);
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

                with_rng!(rng, {
                    match ps {
                        CKP_ML_KEM_512 => {
                            let (dk, ek) = ml_kem::MlKem512::generate(&mut rng);
                            pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                            prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                        }
                        CKP_ML_KEM_768 => {
                            let (dk, ek) = ml_kem::MlKem768::generate(&mut rng);
                            pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                            prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                        }
                        CKP_ML_KEM_1024 => {
                            let (dk, ek) = ml_kem::MlKem1024::generate(&mut rng);
                            pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
                            prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
                        }
                        _ => return CKR_ARGUMENTS_BAD,
                    }
                });
                // CKA_PUBLIC_KEY_INFO (SPKI) — PKCS#11 v3.2 §4.14
                if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
                    let spki = match ps {
                        CKP_ML_KEM_512 => build_mlkem512_spki(&pk_bytes),
                        CKP_ML_KEM_768 => build_mlkem768_spki(&pk_bytes),
                        CKP_ML_KEM_1024 => build_mlkem1024_spki(&pk_bytes),
                        _ => Vec::new(),
                    };
                    if !spki.is_empty() {
                        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
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

                match ps {
                    CKP_ML_DSA_44 => {
                        let mut rng = rand::rngs::OsRng;
                        match fips204::ml_dsa_44::try_keygen_with_rng(&mut rng) {
                            Ok((vk, sk)) => {
                                pub_attrs.insert(
                                    CKA_VALUE,
                                    fips204::traits::SerDes::into_bytes(vk).to_vec(),
                                );
                                prv_attrs.insert(
                                    CKA_VALUE,
                                    fips204::traits::SerDes::into_bytes(sk).to_vec(),
                                );
                            }
                            Err(_) => return CKR_FUNCTION_FAILED,
                        }
                    }
                    CKP_ML_DSA_65 => {
                        let mut rng = rand::rngs::OsRng;
                        match fips204::ml_dsa_65::try_keygen_with_rng(&mut rng) {
                            Ok((vk, sk)) => {
                                pub_attrs.insert(
                                    CKA_VALUE,
                                    fips204::traits::SerDes::into_bytes(vk).to_vec(),
                                );
                                prv_attrs.insert(
                                    CKA_VALUE,
                                    fips204::traits::SerDes::into_bytes(sk).to_vec(),
                                );
                            }
                            Err(_) => return CKR_FUNCTION_FAILED,
                        }
                    }
                    CKP_ML_DSA_87 => {
                        let mut rng = rand::rngs::OsRng;
                        match fips204::ml_dsa_87::try_keygen_with_rng(&mut rng) {
                            Ok((vk, sk)) => {
                                pub_attrs.insert(
                                    CKA_VALUE,
                                    fips204::traits::SerDes::into_bytes(vk).to_vec(),
                                );
                                prv_attrs.insert(
                                    CKA_VALUE,
                                    fips204::traits::SerDes::into_bytes(sk).to_vec(),
                                );
                            }
                            Err(_) => return CKR_FUNCTION_FAILED,
                        }
                    }
                    _ => return CKR_ARGUMENTS_BAD,
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
                        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
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

                match ps {
                    CKP_SLH_DSA_SHA2_128S => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_sha2_128s::try_keygen_with_rng,
                            16,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHAKE_128S => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_shake_128s::try_keygen_with_rng,
                            16,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHA2_128F => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_sha2_128f::try_keygen_with_rng,
                            16,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHAKE_128F => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_shake_128f::try_keygen_with_rng,
                            16,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHA2_192S => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_sha2_192s::try_keygen_with_rng,
                            24,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHAKE_192S => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_shake_192s::try_keygen_with_rng,
                            24,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHA2_192F => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_sha2_192f::try_keygen_with_rng,
                            24,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHAKE_192F => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_shake_192f::try_keygen_with_rng,
                            24,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHA2_256S => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_sha2_256s::try_keygen_with_rng,
                            32,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHAKE_256S => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_shake_256s::try_keygen_with_rng,
                            32,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHA2_256F => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_sha2_256f::try_keygen_with_rng,
                            32,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    CKP_SLH_DSA_SHAKE_256F => {
                        slh_dsa_keygen!(
                            fips205::slh_dsa_shake_256f::try_keygen_with_rng,
                            32,
                            pub_attrs,
                            prv_attrs
                        )
                    }
                    _ => return CKR_ARGUMENTS_BAD,
                }
                // CKA_PUBLIC_KEY_INFO (SPKI) — PKCS#11 v3.2 §4.14
                if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
                    let spki = build_slhdsa_spki(ps, &pk_bytes);
                    if !spki.is_empty() {
                        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
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
                if !(2048..=4096).contains(&bits) {
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
                let ec_params = get_attr_bytes(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_EC_PARAMS,
                );
                let is_p521 = ec_params
                    .as_ref()
                    .is_some_and(|b| b.len() >= 7 && b[b.len() - 1] == 0x23);

                let is_p384 = ec_params
                    .as_ref()
                    .is_some_and(|b| b.len() >= 7 && b[b.len() - 1] == 0x22);

                let is_secp256k1 = ec_params
                    .as_ref()
                    .is_some_and(|b| b.len() >= 7 && b[b.len() - 1] == 0x0a);

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
                finalize_private_key_attrs(&mut prv_attrs);
                compute_kcv(&mut pub_attrs);
                compute_kcv(&mut prv_attrs);
                *ph_public_key = allocate_handle_owned(_h_session, pub_attrs);
                *ph_private_key = allocate_handle_owned(_h_session, prv_attrs);
                CKR_OK
            }

            CKM_EC_EDWARDS_KEY_PAIR_GEN => {
                let sk = with_rng!(rng, { ed25519_dalek::SigningKey::generate(&mut rng) });
                let vk = sk.verifying_key();

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
                let vk_bytes = vk.to_bytes().to_vec();
                prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
                pub_attrs.insert(CKA_VALUE, vk_bytes.clone());
                // SubjectPublicKeyInfo DER for Ed25519 (32-byte key)
                // 30 2a 30 05 06 03 2b6570 03 22 00 <32 bytes>
                let spki = build_ed25519_spki(&vk_bytes);
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
                let is_x448 = oid_bytes
                    .as_ref()
                    .and_then(|b| b.last().copied())
                    .map(|last| last == 0x6f)
                    .unwrap_or(false);

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
                    pub_attrs.insert(CKA_VALUE, pk_bytes.clone());
                    prv_attrs.insert(CKA_VALUE, sk_bytes);
                    let spki = build_x448_spki(&pk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                    // PKCS#11 v3.2 §6.7 — CKA_EC_PARAMS required on CKK_EC_MONTGOMERY keys;
                    // store DER OID for id-X448 (RFC 8410, OID 1.3.101.111 = 06 03 2b 65 6f)
                    let oid_x448: Vec<u8> = vec![0x06, 0x03, 0x2b, 0x65, 0x6f];
                    pub_attrs.insert(CKA_EC_PARAMS, oid_x448.clone());
                    prv_attrs.insert(CKA_EC_PARAMS, oid_x448);
                    // PKCS#11 v3.2 §6.7 — CKA_EC_POINT: DER OCTET STRING wrapping raw 56-byte public key
                    let mut ec_point_x448 = Vec::with_capacity(2 + pk_bytes.len());
                    ec_point_x448.push(0x04u8); // DER OCTET STRING tag
                    ec_point_x448.push(pk_bytes.len() as u8); // 0x38 = 56
                    ec_point_x448.extend_from_slice(&pk_bytes);
                    pub_attrs.insert(CKA_EC_POINT, ec_point_x448);
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
                    pub_attrs.insert(CKA_VALUE, pk_bytes.clone());
                    prv_attrs.insert(CKA_VALUE, sk_bytes);
                    let spki = build_x25519_spki(&pk_bytes);
                    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
                    // PKCS#11 v3.2 §6.7 — CKA_EC_PARAMS required on CKK_EC_MONTGOMERY keys;
                    // store DER OID for id-X25519 (RFC 8410, OID 1.3.101.110 = 06 03 2b 65 6e)
                    let oid_x25519: Vec<u8> = vec![0x06, 0x03, 0x2b, 0x65, 0x6e];
                    pub_attrs.insert(CKA_EC_PARAMS, oid_x25519.clone());
                    prv_attrs.insert(CKA_EC_PARAMS, oid_x25519);
                    // PKCS#11 v3.2 §6.7 — CKA_EC_POINT: DER OCTET STRING wrapping raw 32-byte public key
                    let mut ec_point_x25519 = Vec::with_capacity(2 + pk_bytes.len());
                    ec_point_x25519.push(0x04u8); // DER OCTET STRING tag
                    ec_point_x25519.push(pk_bytes.len() as u8); // 0x20 = 32
                    ec_point_x25519.extend_from_slice(&pk_bytes);
                    pub_attrs.insert(CKA_EC_POINT, ec_point_x25519);
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
                // CK_MECHANISM layout (WASM32): mechType(4) + pParameter(4) + ulParameterLen(4)
                // CK_HSS_KEY_PAIR_GEN_PARAMS: ulLevels(4) + ulLmsParamSet[8](32) + ulLmotsParamSet[8](32) = 68B
                let p_param_ptr = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                let param_len = *(p_mechanism.add(8) as *const u32);
                if p_param_ptr.is_null() || param_len < 68 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let levels = *p_param_ptr as usize;
                if levels == 0 || levels > 8 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let lms_params: Vec<u32> = (0..levels).map(|i| *p_param_ptr.add(1 + i)).collect();
                let lmots_params: Vec<u32> =
                    (0..levels).map(|i| *p_param_ptr.add(1 + 8 + i)).collect();

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
                prv_attrs.insert(CKA_STATEFUL_KEY_STATE, priv_bytes);
                prv_attrs.insert(CKA_LEAF_INDEX, 0u64.to_le_bytes().to_vec());
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
                // CK_MECHANISM layout: mechType(4) + pParameter(4) + ulParameterLen(4)
                let p_param_ptr = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                let param_len = *(p_mechanism.add(8) as *const u32);
                let mut param_code = 0;
                if !p_param_ptr.is_null() && param_len >= 4 {
                    // Typical PKCS11 may pass CK_XMSS_PARAMS struct. For now, read the first word
                    param_code = *p_param_ptr;
                }

                let mut xmss_param = get_attr_ulong(
                    p_public_key_template,
                    ul_public_key_attribute_count,
                    CKA_XMSS_PARAM_SET,
                )
                .unwrap_or(param_code);

                if xmss_param == 0 {
                    xmss_param = CKP_XMSS_SHA2_10_256;
                }

                let (pub_bytes, priv_bytes) =
                    match crate::crypto::xmss_bridge::xmss_keygen(xmss_param) {
                        Ok(pair) => pair,
                        Err(_) => return CKR_FUNCTION_FAILED,
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
                store_ulong(&mut pub_attrs, CKA_XMSS_PARAM_SET, xmss_param);
                store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_XMSS_KEY_PAIR_GEN);
                store_bool(&mut pub_attrs, CKA_TOKEN, false);
                store_bool(&mut pub_attrs, CKA_PRIVATE, false);
                store_bool(&mut pub_attrs, CKA_VERIFY, true);
                store_bool(&mut pub_attrs, CKA_LOCAL, true);
                store_bool(&mut pub_attrs, CKA_EXTRACTABLE, true);
                pub_attrs.insert(CKA_VALUE, pub_bytes);
                // Private key attributes
                store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_XMSS);
                store_ulong(&mut prv_attrs, CKA_XMSS_PARAM_SET, xmss_param);
                store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_XMSS_KEY_PAIR_GEN);
                store_bool(&mut prv_attrs, CKA_TOKEN, false);
                store_bool(&mut prv_attrs, CKA_PRIVATE, true);
                store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
                store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
                store_bool(&mut prv_attrs, CKA_SIGN, true);
                // XMSS capacity = 2^H from the parameter set (PKCS#11 v3.2 §6.15).
                // Tracked under the vendor attribute CKA_XMSS_KEYS_REMAINING, separate from CKA_HSS_KEYS_REMAINING.
                let xmss_max_sigs = crate::crypto::xmss_bridge::xmss_param_max_sigs(xmss_param);
                store_ulong(&mut pub_attrs, CKA_XMSS_KEYS_REMAINING, xmss_max_sigs);
                store_ulong(&mut prv_attrs, CKA_XMSS_KEYS_REMAINING, xmss_max_sigs);
                store_bool(&mut prv_attrs, CKA_LOCAL, true);
                prv_attrs.insert(CKA_STATEFUL_KEY_STATE, priv_bytes);
                prv_attrs.insert(CKA_LEAF_INDEX, 0u64.to_le_bytes().to_vec());
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

            _ => CKR_MECHANISM_INVALID,
        }
    }
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
    if ph_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        match mech_type {
            CKM_AES_KEY_GEN => {
                let key_len =
                    get_attr_ulong(p_template, ul_count, CKA_VALUE_LEN).unwrap_or(16) as usize;
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
                if key_len == 0 || key_len > 512 {
                    return CKR_ARGUMENTS_BAD;
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

#[wasm_bindgen(js_name = _C_EncapsulateKey)]
pub fn C_EncapsulateKey(
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

    if ph_key.is_null() || pul_ciphertext_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // PKCS#11 v3.2 §5.18.8 — the key must permit encapsulation.
    if let Err(rv) = check_key_usage(_h_session, h_key, CKA_ENCAPSULATE) {
        return rv;
    }
    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_ML_KEM {
            return CKR_MECHANISM_INVALID;
        }

        let ps = get_object_param_set(h_key);
        let ct_len: u32 = match ps {
            CKP_ML_KEM_512 => 768,
            CKP_ML_KEM_768 | 0 => 1088,
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

        let pub_key_bytes = match get_object_value(h_key) {
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
                let mut ss_attrs = HashMap::new();
                ss_attrs.insert(CKA_VALUE, ss.as_slice().to_vec());
                store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
                store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
                store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss.as_slice().len() as u32);
                store_bool(&mut ss_attrs, CKA_TOKEN, false);   // PKCS#11 v3.2 §4.1 default
                store_bool(&mut ss_attrs, CKA_PRIVATE, false); // PKCS#11 v3.2 §4.1 default
                store_bool(&mut ss_attrs, CKA_LOCAL, false); // PKCS#11 v3.2 §5.18.8 — KEM keys are not locally generated
                store_ulong(&mut ss_attrs, CKA_KEY_GEN_MECHANISM, CKM_ML_KEM); // PKCS#11 v3.2 §4.3
                absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
                // PKCS#11 v3.2 §5.18.8: unconditionally CK_FALSE for encapsulated keys
                store_bool(&mut ss_attrs, CKA_ALWAYS_SENSITIVE, false);
                store_bool(&mut ss_attrs, CKA_NEVER_EXTRACTABLE, false);
                *ph_key = allocate_handle_owned(_h_session, ss_attrs);
            }};
        }

        with_rng!(rng, {
            match ps {
                CKP_ML_KEM_512 => encap!(ml_kem::MlKem512, &mut rng),
                CKP_ML_KEM_768 | 0 => encap!(ml_kem::MlKem768, &mut rng),
                CKP_ML_KEM_1024 => encap!(ml_kem::MlKem1024, &mut rng),
                _ => return CKR_ARGUMENTS_BAD,
            }
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DecapsulateKey)]
pub fn C_DecapsulateKey(
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

    if ph_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // PKCS#11 v3.2 §5.18.9 — the key must permit decapsulation.
    if let Err(rv) = check_key_usage(_h_session, h_private_key, CKA_DECAPSULATE) {
        return rv;
    }
    unsafe {
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_ML_KEM {
            return CKR_MECHANISM_INVALID;
        }

        let ps = get_object_param_set(h_private_key);
        let expected_ct: u32 = match ps {
            CKP_ML_KEM_512 => 768,
            CKP_ML_KEM_768 | 0 => 1088,
            CKP_ML_KEM_1024 => 1568,
            _ => return CKR_ARGUMENTS_BAD,
        };
        if ul_ciphertext_len != expected_ct {
            return CKR_ARGUMENTS_BAD;
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
                let mut ss_attrs = HashMap::new();
                ss_attrs.insert(CKA_VALUE, ss.as_slice().to_vec());
                store_ulong(&mut ss_attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut ss_attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
                store_bool(&mut ss_attrs, CKA_EXTRACTABLE, true);
                store_bool(&mut ss_attrs, CKA_SENSITIVE, false);
                store_ulong(&mut ss_attrs, CKA_VALUE_LEN, ss.as_slice().len() as u32);
                store_bool(&mut ss_attrs, CKA_TOKEN, false);   // PKCS#11 v3.2 §4.1 default
                store_bool(&mut ss_attrs, CKA_PRIVATE, false); // PKCS#11 v3.2 §4.1 default
                store_bool(&mut ss_attrs, CKA_LOCAL, false); // PKCS#11 v3.2 §5.18.9 — KEM keys are not locally generated
                store_ulong(&mut ss_attrs, CKA_KEY_GEN_MECHANISM, CKM_ML_KEM); // PKCS#11 v3.2 §4.3
                absorb_template_attrs(&mut ss_attrs, _p_template, _ul_attribute_count);
                // PKCS#11 v3.2 §5.18.9: unconditionally CK_FALSE for decapsulated keys
                store_bool(&mut ss_attrs, CKA_ALWAYS_SENSITIVE, false);
                store_bool(&mut ss_attrs, CKA_NEVER_EXTRACTABLE, false);
                *ph_key = allocate_handle_owned(_h_session, ss_attrs);
            }};
        }

        match ps {
            CKP_ML_KEM_512 => decap!(ml_kem::MlKem512),
            CKP_ML_KEM_768 | 0 => decap!(ml_kem::MlKem768),
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
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *mut u8;
                let val_len_ptr = tmpl_ptr.add((i * 3 + 2) as usize);
                // Block CKA_VALUE (and other sensitive material) for sensitive or
                // non-extractable private/secret keys → CKR_ATTRIBUTE_SENSITIVE.
                if attr_type == CKA_VALUE && (sensitive || !extractable) {
                    *val_len_ptr = 0xFFFFFFFF; // CK_UNAVAILABLE_INFORMATION
                    had_sensitive = true;
                    continue;
                }
                if let Some(val) = obj_attrs.get(&attr_type) {
                    if val_ptr.is_null() {
                        *val_len_ptr = val.len() as u32;
                    } else if *val_len_ptr >= val.len() as u32 {
                        std::ptr::copy_nonoverlapping(val.as_ptr(), val_ptr, val.len());
                        *val_len_ptr = val.len() as u32;
                    } else {
                        // §5.7.5 — record, set length, keep processing the rest.
                        *val_len_ptr = val.len() as u32;
                        had_small = true;
                    }
                } else {
                    // §5.7.5 — attribute not present → CK_UNAVAILABLE_INFORMATION.
                    *val_len_ptr = 0xFFFFFFFF;
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
        let tmpl_ptr = p_template as *mut u32;
        let mut new_attrs = HashMap::new();
        for i in 0..count {
            let attr_type = *tmpl_ptr.add((i * 3) as usize);
            let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
            let val_len = *tmpl_ptr.add((i * 3 + 2) as usize);
            if !val_ptr.is_null() && val_len > 0 {
                let mut v = vec![0u8; val_len as usize];
                std::ptr::copy_nonoverlapping(val_ptr, v.as_mut_ptr(), val_len as usize);
                new_attrs.insert(attr_type, v);
            }
        }
        // PKCS#11 v3.2 §4.1.1 — template validation (required attrs, value
        // sanity, class/type consistency) before any object is created.
        if let Err(rv) = validate_create_template(&new_attrs) {
            return rv;
        }
        // PKCS#11 v3.2 §5.6 — a token object (CKA_TOKEN=TRUE) may only be
        // created from a read/write session. Session objects are allowed in R/O.
        if read_bool_attr(&new_attrs, CKA_TOKEN) && !crate::state::session_is_rw(_h_session) {
            return CKR_SESSION_READ_ONLY;
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
        // PKCS#11 v3.2 §4.3 — CKA_LOCAL=FALSE is mandatory for imported objects;
        // override any caller-provided value since this is a server-managed attribute.
        store_bool(&mut new_attrs, CKA_LOCAL, false);
        // PKCS#11 v3.2 §4.3 — CKA_KEY_GEN_MECHANISM = CKM_UNAVAILABLE_INFORMATION for imported keys
        if !new_attrs.contains_key(&CKA_KEY_GEN_MECHANISM) {
            store_ulong(
                &mut new_attrs,
                CKA_KEY_GEN_MECHANISM,
                CKM_UNAVAILABLE_INFORMATION,
            );
        }
        // Set CKA_ALWAYS_SENSITIVE + CKA_NEVER_EXTRACTABLE if CKA_SENSITIVE is present
        if new_attrs.contains_key(&CKA_SENSITIVE) {
            finalize_private_key_attrs(&mut new_attrs);
        }
        // Compute CKA_CHECK_VALUE (KCV) — PKCS#11 v3.2
        compute_kcv(&mut new_attrs);
        *ph_object = allocate_handle_owned(_h_session, new_attrs);
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
    let removed = OBJECTS.with(|objs| {
        let mut store = objs.borrow_mut();
        if let Some(mut attrs) = store.remove(&h_object) {
            // Zeroize key material before deallocation (RS-02)
            if let Some(val) = attrs.get_mut(&CKA_VALUE) {
                val.zeroize();
            }
            true
        } else {
            false
        }
    });
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
    let attrs = match OBJECTS.with(|o| o.borrow().get(&h_key).cloned()) {
        Some(a) => a,
        None => return Err(CKR_KEY_HANDLE_INVALID),
    };
    if !crate::state::can_access_object(h_session, &attrs) {
        return Err(CKR_KEY_HANDLE_INVALID);
    }
    if !read_bool_attr(&attrs, usage_attr) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    Ok(())
}

#[wasm_bindgen(js_name = _C_SignInit)]
pub fn C_SignInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
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
        let mut mech_type = *(p_mechanism as *const u32);
        // Parse CK_EDDSA_PARAMS: if phFlag is set, use internal CKM_EDDSA_PH
        if mech_type == CKM_EDDSA {
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
            if !p_param.is_null() && ul_param_len >= 4 {
                let ph_flag = *(p_param as *const u32);
                if ph_flag != 0 {
                    mech_type = CKM_EDDSA_PH;
                }
            }
        }
        // Parse CK_SIGN_ADDITIONAL_CONTEXT for SLH-DSA (FIPS 205 §9.2 + §10)
        // CK_SIGN_ADDITIONAL_CONTEXT — ML-DSA + SLH-DSA, pure and pre-hash
        // (PKCS#11 v3.2 §6.67/§6.69). Overlong ctx / bad hedge value → error.
        let (slh_ctx, slh_det) = if takes_sign_additional_ctx(mech_type) {
            match parse_sign_additional_ctx(p_mechanism) {
                Ok(v) => v,
                Err(rv) => return rv,
            }
        } else if mech_type == CKM_SHA256_RSA_PKCS_PSS {
            // CK_RSA_PKCS_PSS_PARAMS (wasm32, 12 B): hashAlg, mgf, sLen.
            // §6.4.5 — params are caller-authoritative; hashAlg/mgf must match
            // the mechanism's digest. Absent params keep legacy defaults.
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param != 0 && param_len >= 12 {
                let pp = p_param as *const u8;
                let hash_alg = std::ptr::read_unaligned(pp as *const u32);
                let mgf = std::ptr::read_unaligned((pp as *const u32).add(1));
                let s_len = std::ptr::read_unaligned((pp as *const u32).add(2));
                if hash_alg != CKM_SHA256 || mgf != CKG_MGF1_SHA256 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // carried to C_Sign/C_Verify in the ctx vec (LE u32)
                (s_len.to_le_bytes().to_vec(), false)
            } else {
                (Vec::new(), false)
            }
        } else if mech_type == CKM_KMAC_128 || mech_type == CKM_KMAC_256 {
            // Vendor KMAC params (wasm32, 12 B): pCustomization(u32),
            // ulCustomizationLen(u32), ulOutputLen(u32). Absent → defaults.
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param != 0 && param_len >= 12 {
                let pp = p_param as *const u8;
                let s_ptr = std::ptr::read_unaligned(pp as *const u32);
                let s_len = std::ptr::read_unaligned((pp as *const u32).add(1)) as usize;
                let out_len = std::ptr::read_unaligned((pp as *const u32).add(2));
                if out_len > 1024 || s_len > 1024 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let mut v = out_len.to_le_bytes().to_vec();
                if s_ptr != 0 && s_len > 0 {
                    v.extend_from_slice(std::slice::from_raw_parts(s_ptr as *const u8, s_len));
                }
                (v, false)
            } else {
                (Vec::new(), false)
            }
        } else if let Some((_, digest_len)) = hmac_general_base(mech_type) {
            // CK_MAC_GENERAL_PARAMS = single CK_ULONG ulMacLength (§6.x).
            // 1..=digest_len; carried to C_Sign/C_Verify in the ctx vec (LE).
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param == 0 || param_len < 4 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            let mac_len = std::ptr::read_unaligned(p_param as *const u32);
            if mac_len == 0 || mac_len as usize > digest_len {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            (mac_len.to_le_bytes().to_vec(), false)
        } else {
            (Vec::new(), false)
        };
        SIGN_STATE.with(|s| {
            s.borrow_mut()
                .insert(h_session, (mech_type, h_key, slh_ctx, slh_det));
        });
    }
    CKR_OK
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
unsafe fn parse_sign_additional_ctx(p_mechanism: *const u8) -> Result<(Vec<u8>, bool), u32> {
    // CK_MECHANISM layout (WASM32): mechType(4) + pParameter(4) + ulParameterLen(4)
    let p_param = *(p_mechanism.add(4) as *const u32);
    let param_len = *(p_mechanism.add(8) as *const u32);
    if p_param == 0 || param_len < 12 {
        return Ok((Vec::new(), false));
    }
    let p_param = p_param as *const u8;
    let hedge = *(p_param as *const u32);
    let ctx_ptr = *((p_param as *const u32).add(1));
    let ctx_len = *((p_param as *const u32).add(2)) as usize;
    // CKH_HEDGE_PREFERRED(0) / CKH_HEDGE_REQUIRED(1) both sign hedged here
    // (hedging is always available); CKH_DETERMINISTIC_REQUIRED(2) selects
    // the deterministic variant.
    let deterministic = match hedge {
        0 | 1 => false,
        x if x == CKH_DETERMINISTIC_REQUIRED => true,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    };
    if ctx_len > 255 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let context = if ctx_ptr != 0 && ctx_len > 0 {
        std::slice::from_raw_parts(ctx_ptr as *const u8, ctx_len).to_vec()
    } else {
        Vec::new()
    };
    Ok((context, deterministic))
}

#[wasm_bindgen(js_name = _C_Sign)]
pub fn C_Sign(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    require_init!();
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

        // ── LMS / HSS stateful sign — separate path (uses CKA_STATEFUL_KEY_STATE) ───
        if mech == CKM_HSS || mech == CKM_XMSS {
            let priv_bytes = match get_object_attr_bytes(hkey, CKA_STATEFUL_KEY_STATE) {
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
                    get_object_attr_u32(hkey, CKA_XMSS_PARAM_SET).unwrap_or(CKP_XMSS_SHA2_10_256);
                match crate::crypto::xmss_bridge::xmss_sign(xmss_param, &priv_bytes, msg) {
                    Ok((sig, updated_sk)) => match update_fn(&updated_sk) {
                        Ok(_) => Ok(sig),
                        Err(_) => Err(CKR_FUNCTION_FAILED),
                    },
                    Err(e) => Err(e),
                }
            } else {
                let lms_param = get_object_attr_u32(hkey, CKA_LMS_PARAM_SET).unwrap_or(0x05);
                crate::crypto::lms::hss_sign(lms_param, &priv_bytes, msg, &mut update_fn)
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
                    // key state, then emit the signature.
                    if let Some(ref new_priv_bytes) = new_state {
                        set_object_attr_bytes(hkey, CKA_STATEFUL_KEY_STATE, new_priv_bytes.clone());

                        if mech == CKM_HSS {
                            // HSS: increment leaf index (managed externally; hss library handles internal state)
                            let old_idx = get_object_attr_u64(hkey, CKA_LEAF_INDEX).unwrap_or(0);
                            set_object_attr_bytes(
                                hkey,
                                CKA_LEAF_INDEX,
                                (old_idx + 1).to_le_bytes().to_vec(),
                            );
                            // HSS: decrement CKA_HSS_KEYS_REMAINING by 1 per sign (PKCS#11 v3.2 §6.14)
                            if let Some(mut remaining) =
                                get_object_attr_u32(hkey, CKA_HSS_KEYS_REMAINING)
                            {
                                if remaining > 0 {
                                    remaining -= 1;
                                    set_object_attr_bytes(
                                        hkey,
                                        CKA_HSS_KEYS_REMAINING,
                                        remaining.to_le_bytes().to_vec(),
                                    );
                                }
                            }
                        } else {
                            // XMSS: derive remaining from the updated signing key state.
                            // The xmss crate stores the leaf index as big-endian bytes at offset 4
                            // inside the serialised signing key. Reading it directly is more accurate
                            // than a simple -1 decrement (the crate may skip leaves internally).
                            let xmss_param = get_object_attr_u32(hkey, CKA_XMSS_PARAM_SET)
                                .unwrap_or(CKP_XMSS_SHA2_10_256);
                            let remaining = crate::crypto::xmss_bridge::xmss_keys_remaining(
                                xmss_param,
                                new_priv_bytes,
                            );
                            set_object_attr_bytes(
                                hkey,
                                CKA_XMSS_KEYS_REMAINING,
                                remaining.to_le_bytes().to_vec(),
                            );
                        }
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
            | CKM_SHA3_512_HMAC => sign_hmac(eff_mech, &sk_bytes, eff_msg),
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
            CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => {
                let pss_salt = if eff_mech == CKM_SHA256_RSA_PKCS_PSS && ctx_bytes.len() >= 4 {
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
        let mut mech_type = *(p_mechanism as *const u32);
        // Parse CK_EDDSA_PARAMS: if phFlag is set, use internal CKM_EDDSA_PH
        if mech_type == CKM_EDDSA {
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
            if !p_param.is_null() && ul_param_len >= 4 {
                let ph_flag = *(p_param as *const u32);
                if ph_flag != 0 {
                    mech_type = CKM_EDDSA_PH;
                }
            }
        }
        // Parse CK_SIGN_ADDITIONAL_CONTEXT for SLH-DSA (context string, FIPS 205 §9.2)
        // CK_SIGN_ADDITIONAL_CONTEXT — ML-DSA + SLH-DSA, pure and pre-hash
        // (PKCS#11 v3.2 §6.67/§6.69). Overlong ctx / bad hedge value → error.
        let (slh_ctx, slh_det) = if takes_sign_additional_ctx(mech_type) {
            match parse_sign_additional_ctx(p_mechanism) {
                Ok(v) => v,
                Err(rv) => return rv,
            }
        } else if mech_type == CKM_SHA256_RSA_PKCS_PSS {
            // CK_RSA_PKCS_PSS_PARAMS (wasm32, 12 B): hashAlg, mgf, sLen.
            // §6.4.5 — params are caller-authoritative; hashAlg/mgf must match
            // the mechanism's digest. Absent params keep legacy defaults.
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param != 0 && param_len >= 12 {
                let pp = p_param as *const u8;
                let hash_alg = std::ptr::read_unaligned(pp as *const u32);
                let mgf = std::ptr::read_unaligned((pp as *const u32).add(1));
                let s_len = std::ptr::read_unaligned((pp as *const u32).add(2));
                if hash_alg != CKM_SHA256 || mgf != CKG_MGF1_SHA256 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // carried to C_Sign/C_Verify in the ctx vec (LE u32)
                (s_len.to_le_bytes().to_vec(), false)
            } else {
                (Vec::new(), false)
            }
        } else if mech_type == CKM_KMAC_128 || mech_type == CKM_KMAC_256 {
            // Vendor KMAC params (wasm32, 12 B): pCustomization(u32),
            // ulCustomizationLen(u32), ulOutputLen(u32). Absent → defaults.
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param != 0 && param_len >= 12 {
                let pp = p_param as *const u8;
                let s_ptr = std::ptr::read_unaligned(pp as *const u32);
                let s_len = std::ptr::read_unaligned((pp as *const u32).add(1)) as usize;
                let out_len = std::ptr::read_unaligned((pp as *const u32).add(2));
                if out_len > 1024 || s_len > 1024 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let mut v = out_len.to_le_bytes().to_vec();
                if s_ptr != 0 && s_len > 0 {
                    v.extend_from_slice(std::slice::from_raw_parts(s_ptr as *const u8, s_len));
                }
                (v, false)
            } else {
                (Vec::new(), false)
            }
        } else if let Some((_, digest_len)) = hmac_general_base(mech_type) {
            // CK_MAC_GENERAL_PARAMS = single CK_ULONG ulMacLength (§6.x).
            // 1..=digest_len; carried to C_Sign/C_Verify in the ctx vec (LE).
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param == 0 || param_len < 4 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            let mac_len = std::ptr::read_unaligned(p_param as *const u32);
            if mac_len == 0 || mac_len as usize > digest_len {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            (mac_len.to_le_bytes().to_vec(), false)
        } else {
            (Vec::new(), false)
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
        if mech == CKM_HSS || mech == CKM_XMSS {
            let pub_bytes = match get_object_value(hkey) {
                Some(v) => v,
                None => return CKR_KEY_TYPE_INCONSISTENT,
            };
            let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
            let sig_bytes = std::slice::from_raw_parts(p_signature, ul_signature_len as usize);
            let ok = if mech == CKM_XMSS {
                let xmss_param =
                    get_object_attr_u32(hkey, CKA_XMSS_PARAM_SET).unwrap_or(CKP_XMSS_SHA2_10_256);
                crate::crypto::xmss_bridge::xmss_verify(xmss_param, &pub_bytes, msg, sig_bytes)
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
        let pk_bytes = get_object_value(hkey).unwrap_or_default();
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
            | CKM_SHA3_512_HMAC => verify_hmac(eff_mech, &pk_bytes, eff_msg, sig_bytes),
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
            CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => {
                match get_rsa_public_components(hkey) {
                    Some((n, e)) => {
                        let pss_salt =
                            if eff_mech == CKM_SHA256_RSA_PKCS_PSS && ctx_bytes.len() >= 4 {
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
    unsafe {
        if p_mechanism.is_null() || p_signature.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.12.4 — key handle, visibility, and CKA_VERIFY permission.
        if let Err(rv) = check_key_usage(h_session, h_key, CKA_VERIFY) {
            return rv;
        }
        let mut mech_type = *(p_mechanism as *const u32);
        if mech_type == CKM_EDDSA {
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
            if !p_param.is_null() && ul_param_len >= 4 {
                let ph_flag = *(p_param as *const u32);
                if ph_flag != 0 {
                    mech_type = CKM_EDDSA_PH;
                }
            }
        }
        // CK_SIGN_ADDITIONAL_CONTEXT — ML-DSA + SLH-DSA, pure and pre-hash
        // (PKCS#11 v3.2 §6.67/§6.69). Overlong ctx / bad hedge value → error.
        let (slh_ctx, slh_det) = if takes_sign_additional_ctx(mech_type) {
            match parse_sign_additional_ctx(p_mechanism) {
                Ok(v) => v,
                Err(rv) => return rv,
            }
        } else if mech_type == CKM_SHA256_RSA_PKCS_PSS {
            // CK_RSA_PKCS_PSS_PARAMS (wasm32, 12 B): hashAlg, mgf, sLen.
            // §6.4.5 — params are caller-authoritative; hashAlg/mgf must match
            // the mechanism's digest. Absent params keep legacy defaults.
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param != 0 && param_len >= 12 {
                let pp = p_param as *const u8;
                let hash_alg = std::ptr::read_unaligned(pp as *const u32);
                let mgf = std::ptr::read_unaligned((pp as *const u32).add(1));
                let s_len = std::ptr::read_unaligned((pp as *const u32).add(2));
                if hash_alg != CKM_SHA256 || mgf != CKG_MGF1_SHA256 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // carried to C_Sign/C_Verify in the ctx vec (LE u32)
                (s_len.to_le_bytes().to_vec(), false)
            } else {
                (Vec::new(), false)
            }
        } else if mech_type == CKM_KMAC_128 || mech_type == CKM_KMAC_256 {
            // Vendor KMAC params (wasm32, 12 B): pCustomization(u32),
            // ulCustomizationLen(u32), ulOutputLen(u32). Absent → defaults.
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param != 0 && param_len >= 12 {
                let pp = p_param as *const u8;
                let s_ptr = std::ptr::read_unaligned(pp as *const u32);
                let s_len = std::ptr::read_unaligned((pp as *const u32).add(1)) as usize;
                let out_len = std::ptr::read_unaligned((pp as *const u32).add(2));
                if out_len > 1024 || s_len > 1024 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let mut v = out_len.to_le_bytes().to_vec();
                if s_ptr != 0 && s_len > 0 {
                    v.extend_from_slice(std::slice::from_raw_parts(s_ptr as *const u8, s_len));
                }
                (v, false)
            } else {
                (Vec::new(), false)
            }
        } else if let Some((_, digest_len)) = hmac_general_base(mech_type) {
            // CK_MAC_GENERAL_PARAMS = single CK_ULONG ulMacLength (§6.x).
            // 1..=digest_len; carried to C_Sign/C_Verify in the ctx vec (LE).
            let p_param = *(p_mechanism.add(4) as *const u32);
            let param_len = *(p_mechanism.add(8) as *const u32);
            if p_param == 0 || param_len < 4 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            let mac_len = std::ptr::read_unaligned(p_param as *const u32);
            if mac_len == 0 || mac_len as usize > digest_len {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            (mac_len.to_le_bytes().to_vec(), false)
        } else {
            (Vec::new(), false)
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

/// Parse CK_RSA_PKCS_OAEP_PARAMS (wasm32, 20 B: hashAlg, mgf, source,
/// pSourceData, ulSourceDataLen) → (hashAlg, mgf, label). Absent/short param
/// keeps the legacy default (SHA-256, MGF1-SHA256, no label).
unsafe fn parse_oaep_params(p_param: *const u8, ul_param_len: u32) -> Result<(u32, u32, Vec<u8>), u32> {
    if p_param.is_null() || ul_param_len < 4 {
        return Ok((CKM_SHA256, CKG_MGF1_SHA256, Vec::new()));
    }
    let hash_alg = std::ptr::read_unaligned(p_param as *const u32);
    if ul_param_len < 20 {
        return Ok((hash_alg, 0, Vec::new()));
    }
    let mgf = std::ptr::read_unaligned((p_param as *const u32).add(1));
    let source = std::ptr::read_unaligned((p_param as *const u32).add(2));
    let src_ptr = std::ptr::read_unaligned((p_param as *const u32).add(3));
    let src_len = std::ptr::read_unaligned((p_param as *const u32).add(4)) as usize;
    let label = if src_ptr != 0 && src_len > 0 {
        // §6.4.4 — only CKZ_DATA_SPECIFIED carries a label.
        if source != CKZ_DATA_SPECIFIED {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        std::slice::from_raw_parts(src_ptr as *const u8, src_len).to_vec()
    } else {
        Vec::new()
    };
    Ok((hash_alg, mgf, label))
}

// ── Encrypt/Decrypt ─────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = _C_EncryptInit)]
pub fn C_EncryptInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
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
        let mech_type = *(p_mechanism as *const u32);
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);

        let (iv, aad, tag_bits) = match mech_type {
            CKM_AES_GCM => {
                // CK_GCM_PARAMS (24 bytes, WASM32):
                //   pIv(u32 ptr)   + ulIvLen(u32)   + ulIvBits(u32)
                //   pAAD(u32 ptr)  + ulAADLen(u32)  + ulTagBits(u32)
                if p_param.is_null() || ul_param_len < 24 {
                    return CKR_ARGUMENTS_BAD;
                }
                let gcm = p_param as *const u32;
                let iv_ptr  = *gcm        as usize as *const u8;
                let iv_len  = *gcm.add(1) as usize;
                let iv_bits = *gcm.add(2);
                let aad_ptr = *gcm.add(3) as usize as *const u8;
                let aad_len = *gcm.add(4) as usize;
                let tag_bits = *gcm.add(5);
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
                // CK_AES_CTR_PARAMS: ulCounterBits(CK_ULONG=4) + cb[16] = 20 bytes
                if p_param.is_null() || ul_param_len < 20 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // PKCS#11 v3.2 §6.27.6 — ulCounterBits ∈ 1..=128; the counter
                // wraps within the low ulCounterBits. Engine restriction:
                // byte-granular widths only (8,16,…,128).
                let counter_bits = *(p_param as *const u32);
                if counter_bits == 0 || counter_bits > 128 || counter_bits % 8 != 0 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // cb is at offset 4 (after ulCounterBits)
                let counter_block = std::slice::from_raw_parts(p_param.add(4), 16).to_vec();
                // tag_bits doubles as the mechanism's bits parameter: GCM tag
                // bits / CTR counter bits (see EncryptCtx).
                (counter_block, Vec::new(), counter_bits)
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
            CKM_CHACHA20_POLY1305 => {
                // CK_SALSA20_CHACHA20_POLY1305_PARAMS (WASM32, 16 bytes):
                //   pNonce(u32 ptr) + ulNonceLen(u32) + pAAD(u32 ptr) + ulAADLen(u32)
                if p_param.is_null() || ul_param_len < 16 {
                    return CKR_ARGUMENTS_BAD;
                }
                let nonce_ptr = *(p_param as *const u32) as usize as *const u8;
                let nonce_len = *((p_param as *const u32).add(1)) as usize;
                let aad_ptr   = *((p_param as *const u32).add(2)) as usize as *const u8;
                let aad_len   = *((p_param as *const u32).add(3)) as usize;
                if nonce_len != 12 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                let nonce = std::slice::from_raw_parts(nonce_ptr, nonce_len).to_vec();
                let aad = if !aad_ptr.is_null() && aad_len > 0 {
                    std::slice::from_raw_parts(aad_ptr, aad_len).to_vec()
                } else {
                    Vec::new()
                };
                (nonce, aad, 0)
            }
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
                },
            );
        });
    }
    CKR_OK
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
    let (mech_type, key_handle, iv, aad, tag_bits) =
        (ctx.mech_type, ctx.key_handle, ctx.iv, ctx.aad, ctx.tag_bits);
    let key_bytes = match get_object_value(key_handle) {
        Some(v) => v,
        None => return CKR_ARGUMENTS_BAD,
    };

    unsafe {
        let plaintext = std::slice::from_raw_parts(p_data, ul_data_len as usize);
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
        let mech_type = *(p_mechanism as *const u32);
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);

        let (iv, aad, tag_bits) = match mech_type {
            CKM_AES_GCM => {
                // CK_GCM_PARAMS (24 bytes, WASM32):
                //   pIv(u32 ptr)   + ulIvLen(u32)   + ulIvBits(u32)
                //   pAAD(u32 ptr)  + ulAADLen(u32)  + ulTagBits(u32)
                if p_param.is_null() || ul_param_len < 24 {
                    return CKR_ARGUMENTS_BAD;
                }
                let gcm = p_param as *const u32;
                let iv_ptr  = *gcm        as usize as *const u8;
                let iv_len  = *gcm.add(1) as usize;
                let iv_bits = *gcm.add(2);
                let aad_ptr = *gcm.add(3) as usize as *const u8;
                let aad_len = *gcm.add(4) as usize;
                let tag_bits = *gcm.add(5);
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
                // CK_AES_CTR_PARAMS: ulCounterBits(CK_ULONG=4) + cb[16] = 20 bytes
                if p_param.is_null() || ul_param_len < 20 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // PKCS#11 v3.2 §6.27.6 — ulCounterBits ∈ 1..=128; the counter
                // wraps within the low ulCounterBits. Engine restriction:
                // byte-granular widths only (8,16,…,128).
                let counter_bits = *(p_param as *const u32);
                if counter_bits == 0 || counter_bits > 128 || counter_bits % 8 != 0 {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                // cb is at offset 4 (after ulCounterBits)
                let counter_block = std::slice::from_raw_parts(p_param.add(4), 16).to_vec();
                // tag_bits doubles as the mechanism's bits parameter: GCM tag
                // bits / CTR counter bits (see EncryptCtx).
                (counter_block, Vec::new(), counter_bits)
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
    let (mech_type, key_handle, iv, aad, tag_bits) =
        (ctx.mech_type, ctx.key_handle, ctx.iv, ctx.aad, ctx.tag_bits);
    let key_bytes = match get_object_value(key_handle) {
        Some(v) => v,
        None => return CKR_ARGUMENTS_BAD,
    };

    unsafe {
        let ciphertext =
            std::slice::from_raw_parts(p_encrypted_data, ul_encrypted_data_len as usize);
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
    // PKCS#11 v3.2 §5.12 — a digest operation is already active on this session.
    if DIGEST_STATE.with(|s| s.borrow().contains_key(&h_session)) {
        return CKR_OPERATION_ACTIVE;
    }
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        use sha2::Digest;
        let ctx = match mech_type {
            CKM_SHA256 => DigestCtx::Sha256(sha2::Sha256::new()),
            CKM_SHA384 => DigestCtx::Sha384(sha2::Sha384::new()),
            CKM_SHA512 => DigestCtx::Sha512(sha2::Sha512::new()),
            CKM_SHA3_256 => DigestCtx::Sha3_256(sha3::Sha3_256::new()),
            CKM_SHA3_512 => DigestCtx::Sha3_512(sha3::Sha3_512::new()),
            CKM_KECCAK_256 => DigestCtx::Keccak256(Vec::new()),
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
    use sha2::Digest;
    let has_state = DIGEST_STATE.with(|s| s.borrow().contains_key(&h_session));
    if !has_state {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
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
                }
            }
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_DigestFinal)]
pub fn C_DigestFinal(h_session: u32, p_digest: *mut u8, pul_digest_len: *mut u32) -> u32 {
    require_init!();
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
        let hash = match ctx {
            DigestCtx::Sha256(h) => h.finalize().to_vec(),
            DigestCtx::Sha384(h) => h.finalize().to_vec(),
            DigestCtx::Sha512(h) => h.finalize().to_vec(),
            DigestCtx::Sha3_256(h) => h.finalize().to_vec(),
            DigestCtx::Sha3_512(h) => h.finalize().to_vec(),
            DigestCtx::Keccak256(buf) => crate::crypto::keccak::keccak256_finalize(&buf).to_vec(),
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
    let mut match_attrs: Vec<(u32, Vec<u8>)> = Vec::new();
    unsafe {
        if !p_template.is_null() && ul_count > 0 && ul_count <= 65536 {
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..ul_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
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
    let matching = OBJECTS.with(|objs| {
        objs.borrow()
            .iter()
            .filter(|(_, attrs)| {
                // PKCS#11 v3.2 §4.4 — private objects (CKA_PRIVATE=TRUE) are
                // invisible to sessions whose token is not logged in.
                crate::state::can_access_object(h_session, attrs)
                    && match_attrs
                        .iter()
                        .all(|(typ, val)| attrs.get(typ) == Some(val))
            })
            .map(|(handle, _)| *handle)
            .collect::<Vec<u32>>()
    });
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

/// Parse CK_PRF_DATA_PARAM[] (wasm32: type u32, pValue u32, ulValueLen u32).
/// `key_len` is the requested DKM length in bytes (used to encode [L]).
unsafe fn parse_sp800_108_segments(
    p_segs: *const u32,
    num_segs: usize,
    key_len: usize,
) -> Result<Vec<Sp800Seg>, u32> {
    let mut out = Vec::new();
    if p_segs.is_null() {
        return Ok(out);
    }
    for i in 0..num_segs.min(64) {
        let seg_type = *p_segs.add(i * 3);
        let val_ptr = *p_segs.add(i * 3 + 1) as usize as *const u8;
        let val_len = *p_segs.add(i * 3 + 2) as usize;
        match seg_type {
            t if t == CK_SP800_108_ITERATION_VARIABLE => {
                // pValue → CK_SP800_108_COUNTER_FORMAT { bLittleEndian: CK_BBOOL,
                // ulWidthInBits: CK_ULONG } (wasm32: 1 byte + 3 pad + 4).
                if val_ptr.is_null() || val_len < 8 {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let le = *val_ptr != 0;
                let width_bits =
                    std::ptr::read_unaligned(val_ptr.add(4) as *const u32);
                if !matches!(width_bits, 8 | 16 | 24 | 32) {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                out.push(Sp800Seg::Counter(le, (width_bits / 8) as usize));
            }
            t if t == CK_SP800_108_DKM_LENGTH => {
                // pValue → CK_SP800_108_DKM_LENGTH_FORMAT { method: CK_ULONG,
                // bLittleEndian: CK_BBOOL, ulWidthInBits: CK_ULONG }
                // (wasm32: 4 + 1 + 3 pad + 4 = 12).
                if val_ptr.is_null() || val_len < 12 {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let method = std::ptr::read_unaligned(val_ptr as *const u32);
                if method != CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let le = *val_ptr.add(4) != 0;
                let width_bits =
                    std::ptr::read_unaligned(val_ptr.add(8) as *const u32);
                if !matches!(width_bits, 8 | 16 | 32 | 64) {
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let l_bits = (key_len as u64) * 8;
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
        let mech_type = *(p_mechanism as *const u32);
        let key_len =
            get_attr_ulong(p_template, ul_attribute_count, CKA_VALUE_LEN).unwrap_or(32) as usize;

        // PKCS#11 v3.2 §5.18: for key-based derivation, verify CKA_DERIVE on the base key.
        // PBKDF2 uses h_base_key=0 (password in params), so skip the check for that case.
        if h_base_key != 0 {
            let can_derive = OBJECTS.with(|o| {
                o.borrow()
                    .get(&h_base_key)
                    .map(|attrs| read_bool_attr(attrs, CKA_DERIVE))
                    .unwrap_or(false)
            });
            if !can_derive {
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
        }

        if mech_type == CKM_BIP32_MASTER_DERIVE || mech_type == CKM_BIP32_CHILD_DERIVE {
            let mut attrs = std::collections::HashMap::new();
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..ul_attribute_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize);
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
                    }
                    vec![]
                });
                if parent_chain_code.is_empty() {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }

                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                // CK_BIP32_CHILD_DERIVE_PARAMS layout (TS buildBIP32ChildDeriveParams):
                //   offset 0: flags (CK_ULONG — non-zero = hardened)
                //   offset 4: index (CK_ULONG — child index, 0-based, no hardened bit)
                let flags = *p_param.add(0);
                let index = *p_param.add(1);

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
            attrs.insert(CKA_BIP32_CHAIN_CODE, chain_code);

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
            // ── ECDH ────────────────────────────────────────────────────────
            CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE | CKM_EC_MONTGOMERY_KEY_DERIVE => {
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                // CK_ECDH1_DERIVE_PARAMS: [kdf, ulSharedDataLen, pSharedData, ulPublicDataLen, pPublicData]
                let peer_pk_len = *p_param.add(3) as usize;
                let peer_pk_ptr = *p_param.add(4) as usize as *const u8;
                if peer_pk_ptr.is_null() || peer_pk_len == 0 {
                    return CKR_ARGUMENTS_BAD;
                }
                let peer_pk_raw = std::slice::from_raw_parts(peer_pk_ptr, peer_pk_len);
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
                let kdf = *p_param.add(0);
                let shared_data_len = *p_param.add(1) as usize;
                let shared_data_ptr = *p_param.add(2) as usize as *const u8;
                let shared_data = if !shared_data_ptr.is_null() && shared_data_len > 0 {
                    std::slice::from_raw_parts(shared_data_ptr, shared_data_len)
                } else {
                    &[]
                };

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
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                // CK_PKCS5_PBKD2_PARAMS2: [saltSource, pSaltData, ulSaltDataLen, iterations, prf,
                //                           pPrfData, ulPrfDataLen, pPassword, ulPasswordLen]
                let salt_ptr = *p_param.add(1) as usize as *const u8;
                let salt_len = *p_param.add(2) as usize;
                let iterations = *p_param.add(3);
                if iterations < 1000 {
                    return CKR_ARGUMENTS_BAD;
                }
                let prf = *p_param.add(4);
                let pass_ptr = *p_param.add(7) as usize as *const u8;
                let pass_len = *p_param.add(8) as usize;
                let salt = if !salt_ptr.is_null() && salt_len > 0 {
                    std::slice::from_raw_parts(salt_ptr, salt_len)
                } else {
                    &[]
                };
                let pass = if !pass_ptr.is_null() && pass_len > 0 {
                    std::slice::from_raw_parts(pass_ptr, pass_len)
                } else {
                    &[]
                };
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
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                // CK_HKDF_PARAMS: bExtract(b0), bExpand(b1), pad(b2-3), prf(4), saltType(8),
                //                  pSalt(12), ulSaltLen(16), hSaltKey(20), pInfo(24), ulInfoLen(28)
                let first_word = *p_param.add(0);
                let b_expand = ((first_word >> 8) & 0xFF) != 0;
                let prf = *p_param.add(1);
                let salt_type = *p_param.add(2);
                let salt_ptr = *p_param.add(3) as usize as *const u8;
                let salt_len = *p_param.add(4) as usize;
                let info_ptr = *p_param.add(6) as usize as *const u8;
                let info_len = *p_param.add(7) as usize;
                let salt_opt =
                    if salt_type == CKF_HKDF_SALT_DATA && !salt_ptr.is_null() && salt_len > 0 {
                        Some(std::slice::from_raw_parts(salt_ptr, salt_len))
                    } else {
                        None
                    };
                let info = if !info_ptr.is_null() && info_len > 0 {
                    std::slice::from_raw_parts(info_ptr, info_len)
                } else {
                    &[]
                };
                let mut out = vec![0u8; key_len];
                if b_expand {
                    match prf {
                        CKM_SHA384 => {
                            let hk = hkdf::Hkdf::<sha2::Sha384>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                        CKM_SHA512 => {
                            let hk = hkdf::Hkdf::<sha2::Sha512>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                        CKM_SHA3_256 => {
                            let hk = hkdf::Hkdf::<sha3::Sha3_256>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                        CKM_SHA3_512 => {
                            let hk = hkdf::Hkdf::<sha3::Sha3_512>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
                        _ => {
                            // CKM_SHA256 default
                            let hk = hkdf::Hkdf::<sha2::Sha256>::new(salt_opt, &ikm);
                            if hk.expand(info, &mut out).is_err() {
                                return CKR_FUNCTION_FAILED;
                            }
                        }
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
                        CKM_SHA384 => hkdf_extract!(sha2::Sha384),
                        CKM_SHA512 => hkdf_extract!(sha2::Sha512),
                        CKM_SHA3_256 => hkdf_extract!(sha3::Sha3_256),
                        CKM_SHA3_512 => hkdf_extract!(sha3::Sha3_512),
                        _ => hkdf_extract!(sha2::Sha256), // CKM_SHA256 default
                    }
                }
                out
            }

            // ── SP 800-108 Counter KBKDF ─────────────────────────────────────
            CKM_SP800_108_COUNTER_KDF => {
                use hmac::{Hmac, Mac};
                let base_key = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                let prf_type = *p_param.add(0);
                let num_segs = *p_param.add(1) as usize;
                let p_segs = *p_param.add(2) as usize as *const u32;
                // SP 800-108 §4.1 / PKCS#11 §6.x — process the data params IN
                // ORDER. Supported segment types: ITERATION_VARIABLE (counter
                // at caller-specified width/endianness), DKM_LENGTH ([L]
                // field), BYTE_ARRAY (fixed input). Legacy default when no
                // ITERATION_VARIABLE is present: 32-bit BE counter prefix.
                let segs = match parse_sp800_108_segments(p_segs, num_segs, key_len) {
                    Ok(s) => s,
                    Err(rv) => return rv,
                };
                macro_rules! kbkdf_counter {
                    ($HmacType:ty) => {{
                        let mut out = Vec::new();
                        let mut counter: u32 = 1;
                        while out.len() < key_len {
                            let mut mac = match <$HmacType>::new_from_slice(&base_key) {
                                Ok(m) => m,
                                Err(_) => return CKR_FUNCTION_FAILED,
                            };
                            for piece in sp800_108_iter_input(&segs, counter) {
                                mac.update(&piece);
                            }
                            out.extend_from_slice(&mac.finalize().into_bytes());
                            counter += 1;
                        }
                        out.truncate(key_len);
                        out
                    }};
                }
                match prf_type {
                    CKM_SHA384 => kbkdf_counter!(Hmac<sha2::Sha384>),
                    CKM_SHA512 => kbkdf_counter!(Hmac<sha2::Sha512>),
                    CKM_SHA3_256 => kbkdf_counter!(Hmac<sha3::Sha3_256>),
                    CKM_SHA3_512 => kbkdf_counter!(Hmac<sha3::Sha3_512>),
                    _ => kbkdf_counter!(Hmac<sha2::Sha256>), // SHA-256 default
                }
            }

            // ── SP 800-108 Feedback KBKDF ────────────────────────────────────
            CKM_SP800_108_FEEDBACK_KDF => {
                use hmac::{Hmac, Mac};
                let base_key = match get_object_value(h_base_key) {
                    Some(v) => v,
                    None => return CKR_ARGUMENTS_BAD,
                };
                let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u32;
                if p_param.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                let prf_type = *p_param.add(0);
                let num_segs = *p_param.add(1) as usize;
                let p_segs = *p_param.add(2) as usize as *const u32;
                let iv_len = *p_param.add(3) as usize;
                let iv_ptr = *p_param.add(4) as usize as *const u8;
                let iv = if !iv_ptr.is_null() && iv_len > 0 {
                    std::slice::from_raw_parts(iv_ptr, iv_len).to_vec()
                } else {
                    Vec::new()
                };
                // SP 800-108 §4.2 — ordered data params: optional counter at
                // caller width/endianness, [L] field, byte arrays. K(0) = IV.
                let segs = match parse_sp800_108_segments(p_segs, num_segs, key_len) {
                    Ok(s) => s,
                    Err(rv) => return rv,
                };
                // K(i) = PRF(base_key, K(i-1) || [i] || fixed || [L])
                macro_rules! kbkdf_feedback {
                    ($HmacType:ty) => {{
                        let mut k_prev = iv.clone();
                        let mut out = Vec::new();
                        let mut counter: u32 = 1;
                        while out.len() < key_len {
                            let mut mac = match <$HmacType>::new_from_slice(&base_key) {
                                Ok(m) => m,
                                Err(_) => return CKR_FUNCTION_FAILED,
                            };
                            mac.update(&k_prev);
                            // Feedback mode: an absent ITERATION_VARIABLE means
                            // NO counter (unlike counter mode), so only emit the
                            // explicitly-requested segments here.
                            for piece in sp800_108_feedback_input(&segs, counter) {
                                mac.update(&piece);
                            }
                            k_prev = mac.finalize().into_bytes().to_vec();
                            out.extend_from_slice(&k_prev);
                            counter += 1;
                        }
                        out.truncate(key_len);
                        out
                    }};
                }
                match prf_type {
                    CKM_SHA384 => kbkdf_feedback!(Hmac<sha2::Sha384>),
                    CKM_SHA512 => kbkdf_feedback!(Hmac<sha2::Sha512>),
                    CKM_SHA3_256 => kbkdf_feedback!(Hmac<sha3::Sha3_256>),
                    CKM_SHA3_512 => kbkdf_feedback!(Hmac<sha3::Sha3_512>),
                    _ => kbkdf_feedback!(Hmac<sha2::Sha256>),
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
        let mech_type = *(p_mechanism as *const u32);
        let is_kwp = mech_type == CKM_AES_KEY_WRAP_KWP || mech_type == CKM_AES_KEY_WRAP_PAD;
        let is_aes_wrap = mech_type == CKM_AES_KEY_WRAP || is_kwp;
        let is_rsa_oaep = mech_type == CKM_RSA_PKCS_OAEP;
        if !is_aes_wrap && !is_rsa_oaep {
            return CKR_MECHANISM_INVALID;
        }

        // Check CKA_WRAP on wrapping key
        let can_wrap = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_wrapping_key)
                .map(|attrs| read_bool_attr(attrs, CKA_WRAP))
                .unwrap_or(false)
        });
        if !can_wrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        // Check CKA_EXTRACTABLE on target key
        let extractable = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| read_bool_attr(attrs, CKA_EXTRACTABLE))
                .unwrap_or(false)
        });
        if !extractable {
            return CKR_KEY_UNEXTRACTABLE;
        }

        let wrapping_key = match get_object_value(h_wrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let key_to_wrap = match get_object_value(h_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };

        let wrapped = if is_rsa_oaep {
            // RSA-OAEP wrapping — encrypt key value with RSA public key.
            // Full CK_RSA_PKCS_OAEP_PARAMS (§6.4.4): hash, MGF, label.
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
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
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        let is_kwp = mech_type == CKM_AES_KEY_WRAP_KWP || mech_type == CKM_AES_KEY_WRAP_PAD;
        let is_aes_wrap = mech_type == CKM_AES_KEY_WRAP || is_kwp;
        let is_rsa_oaep = mech_type == CKM_RSA_PKCS_OAEP;
        if !is_aes_wrap && !is_rsa_oaep {
            return CKR_MECHANISM_INVALID;
        }

        // Check CKA_UNWRAP on unwrapping key
        let can_unwrap = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_unwrapping_key)
                .map(|attrs| read_bool_attr(attrs, CKA_UNWRAP))
                .unwrap_or(false)
        });
        if !can_unwrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        let unwrapping_key = match get_object_value(h_unwrapping_key) {
            Some(v) => v,
            None => return CKR_ARGUMENTS_BAD,
        };
        let wrapped_data = std::slice::from_raw_parts(p_wrapped_key, ul_wrapped_key_len as usize);

        let key_value = if is_rsa_oaep {
            // RSA-OAEP unwrapping — decrypt wrapped key with RSA private key.
            // Full CK_RSA_PKCS_OAEP_PARAMS (§6.4.4): hash, MGF, label.
            let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
            let ul_param_len = *(p_mechanism.add(8) as *const u32);
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
        } else if is_kwp {
            use aes::cipher::generic_array::GenericArray;
            // AES-KWP (RFC 5649) — supports arbitrary-length data
            if wrapped_data.len() < 16 {
                return CKR_ARGUMENTS_BAD;
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
                Err(_) => return CKR_FUNCTION_FAILED,
            }
        } else {
            use aes::cipher::generic_array::GenericArray;
            // AES-KW (RFC 3394)
            if wrapped_data.len() < 24 {
                return CKR_ARGUMENTS_BAD;
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
                return CKR_FUNCTION_FAILED;
            }
            buf
        };
        let key_len = key_value.len() as u32;

        // Parse template attributes (if provided)
        let mut attrs = HashMap::new();
        if !p_template.is_null() && ul_attribute_count > 0 {
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..ul_attribute_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize);
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
        if !attrs.contains_key(&CKA_VALUE_LEN) {
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
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }

        // Parse CK_GCM_PARAMS from mechanism parameter
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);
        if p_param.is_null() || ul_param_len < 20 {
            return CKR_ARGUMENTS_BAD;
        }
        let gcm = p_param as *const u32;
        let iv_ptr = *gcm as usize as *const u8;
        let iv_len = *gcm.add(1) as usize;
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

        // Check CKA_WRAP on wrapping key
        let can_wrap = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_wrapping_key)
                .map(|attrs| read_bool_attr(attrs, CKA_WRAP))
                .unwrap_or(false)
        });
        if !can_wrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        // Check CKA_EXTRACTABLE on target key
        let extractable = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_key)
                .map(|attrs| read_bool_attr(attrs, CKA_EXTRACTABLE))
                .unwrap_or(false)
        });
        if !extractable {
            return CKR_KEY_UNEXTRACTABLE;
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
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = *(p_mechanism as *const u32);
        if mech_type != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }

        // Parse CK_GCM_PARAMS from mechanism parameter
        let p_param = *(p_mechanism.add(4) as *const u32) as usize as *const u8;
        let ul_param_len = *(p_mechanism.add(8) as *const u32);
        if p_param.is_null() || ul_param_len < 20 {
            return CKR_ARGUMENTS_BAD;
        }
        let gcm = p_param as *const u32;
        let iv_ptr = *gcm as usize as *const u8;
        let iv_len = *gcm.add(1) as usize;
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

        // Check CKA_UNWRAP on unwrapping key
        let can_unwrap = OBJECTS.with(|o| {
            o.borrow()
                .get(&h_unwrapping_key)
                .map(|attrs| read_bool_attr(attrs, CKA_UNWRAP))
                .unwrap_or(false)
        });
        if !can_unwrap {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
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
            let tmpl_ptr = p_template as *mut u32;
            for i in 0..ul_attribute_count {
                let attr_type = *tmpl_ptr.add((i * 3) as usize);
                let val_ptr = *tmpl_ptr.add((i * 3 + 1) as usize) as usize as *const u8;
                let val_len = *tmpl_ptr.add((i * 3 + 2) as usize);
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
        if !attrs.contains_key(&CKA_VALUE_LEN) {
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

#[wasm_bindgen(js_name = _C_SignUpdate)]
pub fn C_SignUpdate(_h_session: u32, _p_part: *mut u8, _ul_part_len: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SignFinal)]
pub fn C_SignFinal(_h_session: u32, _p_signature: *mut u8, _pul_signature_len: *mut u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_VerifyUpdate)]
pub fn C_VerifyUpdate(_h_session: u32, _p_part: *mut u8, _ul_part_len: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_VerifyFinal)]
pub fn C_VerifyFinal(_h_session: u32, _p_signature: *mut u8, _ul_signature_len: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
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
pub fn C_GetSessionValidationFlags(_h_session: u32, _type: u32, _p_flags: *mut u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
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
/// "PKCS 11" version 3.2. wasm constraint: exported functions are not
/// addressable as C function pointers in linear memory, so pFunctionList
/// points to a CK_VERSION{3,2} header only; symbol binding happens in the
/// JS shim (each `_C_*` export), which is the function table for every
/// real consumer of this engine. CK_INTERFACE (wasm32, 12 B):
/// pInterfaceName, pFunctionList, flags.
#[wasm_bindgen(js_name = _C_GetInterfaceList)]
pub fn C_GetInterfaceList(p_interfaces_list: *mut u8, pul_count: *mut u32) -> u32 {
    require_init!();
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
#[wasm_bindgen(js_name = _C_GetInterface)]
pub fn C_GetInterface(
    p_interface_name: *mut u8,
    p_version: *mut u8,
    pp_interface: *mut u32,
    _flags: u32,
) -> u32 {
    require_init!();
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
pub fn C_GetSlotInfo(_slot_id: u32, p_info: *mut u8) -> u32 {
    require_init!();
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

// §5.13 — signatures-with-recovery: not provided by this token.
#[wasm_bindgen(js_name = _C_SignRecoverInit)]
pub fn C_SignRecoverInit(_h_session: u32, _p_mechanism: *mut u8, _h_key: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}
#[wasm_bindgen(js_name = _C_SignRecover)]
pub fn C_SignRecover(
    _h_session: u32,
    _p_data: *mut u8,
    _ul_data_len: u32,
    _p_signature: *mut u8,
    _pul_signature_len: *mut u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}
#[wasm_bindgen(js_name = _C_VerifyRecoverInit)]
pub fn C_VerifyRecoverInit(_h_session: u32, _p_mechanism: *mut u8, _h_key: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}
#[wasm_bindgen(js_name = _C_VerifyRecover)]
pub fn C_VerifyRecover(
    _h_session: u32,
    _p_signature: *mut u8,
    _ul_signature_len: u32,
    _p_data: *mut u8,
    _pul_data_len: *mut u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

// §5.16 — dual-function cryptographic operations: not provided.
#[wasm_bindgen(js_name = _C_DigestEncryptUpdate)]
pub fn C_DigestEncryptUpdate(
    _h_session: u32,
    _p_part: *mut u8,
    _ul_part_len: u32,
    _p_encrypted_part: *mut u8,
    _pul_encrypted_part_len: *mut u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}
#[wasm_bindgen(js_name = _C_DecryptDigestUpdate)]
pub fn C_DecryptDigestUpdate(
    _h_session: u32,
    _p_encrypted_part: *mut u8,
    _ul_encrypted_part_len: u32,
    _p_part: *mut u8,
    _pul_part_len: *mut u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}
#[wasm_bindgen(js_name = _C_SignEncryptUpdate)]
pub fn C_SignEncryptUpdate(
    _h_session: u32,
    _p_part: *mut u8,
    _ul_part_len: u32,
    _p_encrypted_part: *mut u8,
    _pul_encrypted_part_len: *mut u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}
#[wasm_bindgen(js_name = _C_DecryptVerifyUpdate)]
pub fn C_DecryptVerifyUpdate(
    _h_session: u32,
    _p_encrypted_part: *mut u8,
    _ul_encrypted_part_len: u32,
    _p_part: *mut u8,
    _pul_part_len: *mut u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SetPIN)]
pub fn C_SetPIN(
    _h_session: u32,
    _p_old_pin: *mut u8,
    _ul_old_len: u32,
    _p_new_pin: *mut u8,
    _ul_new_len: u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_CopyObject)]
pub fn C_CopyObject(
    _h_session: u32,
    _h_object: u32,
    _p_template: *mut u8,
    _ul_count: u32,
    _ph_new_object: *mut u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_GetObjectSize)]
pub fn C_GetObjectSize(_h_session: u32, _h_object: u32, _pul_size: *mut u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_SetAttributeValue)]
pub fn C_SetAttributeValue(
    _h_session: u32,
    _h_object: u32,
    _p_template: *mut u8,
    _ul_count: u32,
) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

#[wasm_bindgen(js_name = _C_DigestKey)]
pub fn C_DigestKey(_h_session: u32, _h_key: u32) -> u32 {
    require_init!();
    CKR_FUNCTION_NOT_SUPPORTED
}

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
    // WASM getrandom is OS-backed; external seeding is not supported
    CKR_FUNCTION_NOT_SUPPORTED
}

// ============================================================================
// PKCS#11 v3.0 Message Encryption
// ============================================================================

fn parse_gcm_msg_params(p: *mut u8) -> Result<(Vec<u8>, *mut u8, u32), u32> {
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    unsafe {
        let p_iv = *(p as *const u32) as usize as *mut u8;
        let ul_iv_len = *(p.add(4) as *const u32);
        let iv_gen = *(p.add(12) as *const u32);
        let p_tag = *(p.add(16) as *const u32) as usize as *mut u8;
        let ul_tag_bits = *(p.add(20) as *const u32);

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
        let mech_type = *(p_mechanism as *const u32);
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
            iv: Vec::new(),
            aad: Vec::new(),
            tag_bits: 0,
            payload_acc: Vec::new(),
        };

        if is_encrypt {
            MESSAGE_ENCRYPT_STATE.with(|s| s.borrow_mut().insert(h_session, ctx));
        } else {
            MESSAGE_DECRYPT_STATE.with(|s| s.borrow_mut().insert(h_session, ctx));
        }

        CKR_OK
    }
}

pub fn aes_gcm_exec(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    payload: &[u8],
    is_encrypt: bool,
    p_tag: *mut u8,
    tag_bits: u32,
) -> Result<Vec<u8>, u32> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::Aead};

    let tag_bytes = (tag_bits / 8) as usize;
    let nonce = GenericArray::from_slice(iv);
    let payload_aead = aes_gcm::aead::Payload {
        msg: payload,
        aad: aad,
    };

    if key.len() == 16 {
        let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
        if is_encrypt {
            match cipher.encrypt(nonce, payload_aead) {
                Ok(out) => {
                    if out.len() < tag_bytes {
                        return Err(CKR_GENERAL_ERROR);
                    }
                    let ct_len = out.len() - 16;
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            out[ct_len..ct_len + tag_bytes].as_ptr(),
                            p_tag,
                            tag_bytes,
                        );
                    }
                    Ok(out[0..ct_len].to_vec())
                }
                Err(_) => Err(CKR_GENERAL_ERROR),
            }
        } else {
            let mut combined = payload.to_vec();
            if tag_bytes > 0 {
                unsafe {
                    let tag_slice = std::slice::from_raw_parts(p_tag, tag_bytes);
                    combined.extend_from_slice(tag_slice);
                }
            }
            let dec_payload = aes_gcm::aead::Payload {
                msg: &combined,
                aad: aad,
            };
            match cipher.decrypt(nonce, dec_payload) {
                Ok(plain) => Ok(plain),
                Err(_) => Err(CKR_ENCRYPTED_DATA_INVALID),
            }
        }
    } else if key.len() == 32 {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        if is_encrypt {
            match cipher.encrypt(nonce, payload_aead) {
                Ok(out) => {
                    if out.len() < tag_bytes {
                        return Err(CKR_GENERAL_ERROR);
                    }
                    let ct_len = out.len() - 16;
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            out[ct_len..ct_len + tag_bytes].as_ptr(),
                            p_tag,
                            tag_bytes,
                        );
                    }
                    Ok(out[0..ct_len].to_vec())
                }
                Err(_) => Err(CKR_GENERAL_ERROR),
            }
        } else {
            let mut combined = payload.to_vec();
            if tag_bytes > 0 {
                unsafe {
                    let tag_slice = std::slice::from_raw_parts(p_tag, tag_bytes);
                    combined.extend_from_slice(tag_slice);
                }
            }
            let dec_payload = aes_gcm::aead::Payload {
                msg: &combined,
                aad: aad,
            };
            match cipher.decrypt(nonce, dec_payload) {
                Ok(plain) => Ok(plain),
                Err(_) => Err(CKR_ENCRYPTED_DATA_INVALID),
            }
        }
    } else {
        Err(CKR_KEY_SIZE_RANGE)
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
    let ctx = match MESSAGE_ENCRYPT_STATE.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if ctx.in_message {
        return CKR_OPERATION_ACTIVE;
    }

    unsafe {
        if p_ciphertext.is_null() {
            *pul_ciphertext_len = ul_plaintext_len;
            return CKR_OK;
        }
        if *pul_ciphertext_len < ul_plaintext_len {
            *pul_ciphertext_len = ul_plaintext_len;
            return CKR_BUFFER_TOO_SMALL;
        }

        let (iv, p_tag, tag_bits) = match parse_gcm_msg_params(p_parameter) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let aad = std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize);
        let plain = std::slice::from_raw_parts(p_plaintext, ul_plaintext_len as usize);

        match aes_gcm_exec(&ctx.key, &iv, aad, plain, true, p_tag, tag_bits) {
            Ok(ct) => {
                std::ptr::copy_nonoverlapping(ct.as_ptr(), p_ciphertext, ct.len());
                *pul_ciphertext_len = ct.len() as u32;
                CKR_OK
            }
            Err(e) => e,
        }
    }
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
    let mut state_map_guard = MESSAGE_ENCRYPT_STATE.with(|s| s.borrow_mut().clone());
    let ctx = match state_map_guard.get_mut(&h_session) {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if ctx.in_message {
        return CKR_OPERATION_ACTIVE;
    }

    unsafe {
        let (iv, _p_tag, tag_bits) = match parse_gcm_msg_params(p_parameter) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let aad =
            std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize).to_vec();

        MESSAGE_ENCRYPT_STATE.with(|s| {
            let mut store = s.borrow_mut();
            if let Some(c) = store.get_mut(&h_session) {
                c.in_message = true;
                c.iv = iv;
                c.aad = aad;
                c.tag_bits = tag_bits;
                c.payload_acc.clear();
            }
        });
    }
    CKR_OK
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
    let ctx = match MESSAGE_ENCRYPT_STATE.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if !ctx.in_message {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    unsafe {
        if p_ciphertext_part.is_null() {
            *pul_ciphertext_part_len = ul_plaintext_part_len;
            return CKR_OK;
        }
        if *pul_ciphertext_part_len < ul_plaintext_part_len {
            *pul_ciphertext_part_len = ul_plaintext_part_len;
            return CKR_BUFFER_TOO_SMALL;
        }

        MESSAGE_ENCRYPT_STATE.with(|s| {
            if let Some(c) = s.borrow_mut().get_mut(&h_session) {
                let plain_chunk =
                    std::slice::from_raw_parts(p_plaintext_part, ul_plaintext_part_len as usize);
                c.payload_acc.extend_from_slice(plain_chunk);
            }
        });

        if (flags & 0x00000001) != 0
        /* CKF_END_OF_MESSAGE */
        {
            let final_ctx =
                match MESSAGE_ENCRYPT_STATE.with(|s| s.borrow().get(&h_session).cloned()) {
                    Some(s) => s,
                    None => return CKR_OPERATION_NOT_INITIALIZED,
                };
            let p_tag = if p_parameter.is_null() {
                return CKR_ARGUMENTS_BAD;
            } else {
                *(p_parameter.add(16) as *const u32) as usize as *mut u8
            };

            match aes_gcm_exec(
                &final_ctx.key,
                &final_ctx.iv,
                &final_ctx.aad,
                &final_ctx.payload_acc,
                true,
                p_tag,
                final_ctx.tag_bits,
            ) {
                Ok(full_ct) => {
                    let chunk_start = full_ct.len() - ul_plaintext_part_len as usize;
                    std::ptr::copy_nonoverlapping(
                        full_ct[chunk_start..].as_ptr(),
                        p_ciphertext_part,
                        ul_plaintext_part_len as usize,
                    );
                    *pul_ciphertext_part_len = ul_plaintext_part_len;

                    MESSAGE_ENCRYPT_STATE.with(|s| {
                        if let Some(st) = s.borrow_mut().get_mut(&h_session) {
                            st.in_message = false;
                        }
                    });
                    CKR_OK
                }
                Err(e) => {
                    MESSAGE_ENCRYPT_STATE.with(|s| {
                        if let Some(st) = s.borrow_mut().get_mut(&h_session) {
                            st.in_message = false;
                        }
                    });
                    e
                }
            }
        } else {
            let intermediate_ctx =
                match MESSAGE_ENCRYPT_STATE.with(|s| s.borrow().get(&h_session).cloned()) {
                    Some(s) => s,
                    None => return CKR_OPERATION_NOT_INITIALIZED,
                };
            let mut fake_tag = vec![0u8; (intermediate_ctx.tag_bits / 8) as usize];
            match aes_gcm_exec(
                &intermediate_ctx.key,
                &intermediate_ctx.iv,
                &intermediate_ctx.aad,
                &intermediate_ctx.payload_acc,
                true,
                fake_tag.as_mut_ptr(),
                intermediate_ctx.tag_bits,
            ) {
                Ok(full_ct) => {
                    let chunk_start = full_ct.len() - ul_plaintext_part_len as usize;
                    std::ptr::copy_nonoverlapping(
                        full_ct[chunk_start..].as_ptr(),
                        p_ciphertext_part,
                        ul_plaintext_part_len as usize,
                    );
                    *pul_ciphertext_part_len = ul_plaintext_part_len;
                    CKR_OK
                }
                Err(e) => e,
            }
        }
    }
}

#[wasm_bindgen(js_name = _C_MessageEncryptFinal)]
pub fn C_MessageEncryptFinal(h_session: u32) -> u32 {
    require_init!();
    MESSAGE_ENCRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
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
    let ctx = match MESSAGE_DECRYPT_STATE.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if ctx.in_message {
        return CKR_OPERATION_ACTIVE;
    }

    unsafe {
        if p_plaintext.is_null() {
            *pul_plaintext_len = ul_ciphertext_len;
            return CKR_OK;
        }
        if *pul_plaintext_len < ul_ciphertext_len {
            *pul_plaintext_len = ul_ciphertext_len;
            return CKR_BUFFER_TOO_SMALL;
        }

        let (iv, p_tag, tag_bits) = match parse_gcm_msg_params(p_parameter) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let aad = std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize);
        let ct = std::slice::from_raw_parts(p_ciphertext, ul_ciphertext_len as usize);

        match aes_gcm_exec(&ctx.key, &iv, aad, ct, false, p_tag, tag_bits) {
            Ok(plain) => {
                std::ptr::copy_nonoverlapping(plain.as_ptr(), p_plaintext, plain.len());
                *pul_plaintext_len = plain.len() as u32;
                CKR_OK
            }
            Err(e) => e,
        }
    }
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
    let mut state_map_guard = MESSAGE_DECRYPT_STATE.with(|s| s.borrow_mut().clone());
    let ctx = match state_map_guard.get_mut(&h_session) {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if ctx.in_message {
        return CKR_OPERATION_ACTIVE;
    }

    unsafe {
        let (iv, _p_tag, tag_bits) = match parse_gcm_msg_params(p_parameter) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let aad =
            std::slice::from_raw_parts(p_associated_data, ul_associated_data_len as usize).to_vec();

        MESSAGE_DECRYPT_STATE.with(|s| {
            let mut store = s.borrow_mut();
            if let Some(c) = store.get_mut(&h_session) {
                c.in_message = true;
                c.iv = iv;
                c.aad = aad;
                c.tag_bits = tag_bits;
                c.payload_acc.clear();
            }
        });
    }
    CKR_OK
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
    let ctx = match MESSAGE_DECRYPT_STATE.with(|s| s.borrow().get(&h_session).cloned()) {
        Some(c) => c,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if !ctx.in_message {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    unsafe {
        if p_plaintext_part.is_null() {
            *pul_plaintext_part_len = ul_ciphertext_part_len;
            return CKR_OK;
        }
        if *pul_plaintext_part_len < ul_ciphertext_part_len {
            *pul_plaintext_part_len = ul_ciphertext_part_len;
            return CKR_BUFFER_TOO_SMALL;
        }

        MESSAGE_DECRYPT_STATE.with(|s| {
            if let Some(c) = s.borrow_mut().get_mut(&h_session) {
                let ct_chunk =
                    std::slice::from_raw_parts(p_ciphertext_part, ul_ciphertext_part_len as usize);
                c.payload_acc.extend_from_slice(ct_chunk);
            }
        });

        if (flags & 0x00000001) != 0
        /* CKF_END_OF_MESSAGE */
        {
            let final_ctx =
                match MESSAGE_DECRYPT_STATE.with(|s| s.borrow().get(&h_session).cloned()) {
                    Some(s) => s,
                    None => return CKR_OPERATION_NOT_INITIALIZED,
                };
            let p_tag = if p_parameter.is_null() {
                return CKR_ARGUMENTS_BAD;
            } else {
                *(p_parameter.add(16) as *const u32) as usize as *mut u8
            };

            match aes_gcm_exec(
                &final_ctx.key,
                &final_ctx.iv,
                &final_ctx.aad,
                &final_ctx.payload_acc,
                false,
                p_tag,
                final_ctx.tag_bits,
            ) {
                Ok(full_pt) => {
                    let chunk_start = full_pt.len() - ul_ciphertext_part_len as usize;
                    std::ptr::copy_nonoverlapping(
                        full_pt[chunk_start..].as_ptr(),
                        p_plaintext_part,
                        ul_ciphertext_part_len as usize,
                    );
                    *pul_plaintext_part_len = ul_ciphertext_part_len;
                    MESSAGE_DECRYPT_STATE.with(|s| {
                        if let Some(st) = s.borrow_mut().get_mut(&h_session) {
                            st.in_message = false;
                        }
                    });
                    CKR_OK
                }
                Err(e) => {
                    MESSAGE_DECRYPT_STATE.with(|s| {
                        if let Some(st) = s.borrow_mut().get_mut(&h_session) {
                            st.in_message = false;
                        }
                    });
                    e
                }
            }
        } else {
            let intermediate_ctx =
                match MESSAGE_DECRYPT_STATE.with(|s| s.borrow().get(&h_session).cloned()) {
                    Some(s) => s,
                    None => return CKR_OPERATION_NOT_INITIALIZED,
                };
            let mut fake_tag = vec![0u8; (intermediate_ctx.tag_bits / 8) as usize];
            match aes_gcm_exec(
                &intermediate_ctx.key,
                &intermediate_ctx.iv,
                &intermediate_ctx.aad,
                &intermediate_ctx.payload_acc,
                true,
                fake_tag.as_mut_ptr(),
                intermediate_ctx.tag_bits,
            ) {
                Ok(full_pt_like) => {
                    let chunk_start = full_pt_like.len() - ul_ciphertext_part_len as usize;
                    std::ptr::copy_nonoverlapping(
                        full_pt_like[chunk_start..].as_ptr(),
                        p_plaintext_part,
                        ul_ciphertext_part_len as usize,
                    );
                    *pul_plaintext_part_len = ul_ciphertext_part_len;
                    CKR_OK
                }
                Err(e) => e,
            }
        }
    }
}

#[wasm_bindgen(js_name = _C_MessageDecryptFinal)]
pub fn C_MessageDecryptFinal(h_session: u32) -> u32 {
    require_init!();
    MESSAGE_DECRYPT_STATE.with(|s| s.borrow_mut().remove(&h_session));
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
        let mut param = vec![0u8; 20];
        param[0..4].copy_from_slice(&128u32.to_ne_bytes());
        param[4..20].copy_from_slice(iv);
        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: param.as_mut_ptr(),
            ulParameterLen: 20,
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
        let mut param = vec![0u8; 20];
        param[0..4].copy_from_slice(&128u32.to_ne_bytes());
        param[4..20].copy_from_slice(iv);
        let mut mech = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: param.as_mut_ptr(),
            ulParameterLen: 20,
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
            EncryptCtx { mech_type, key_handle: KEY_HANDLE, iv, aad, tag_bits, multipart: None },
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
        let mut need: u32 = 0;
        let part = [0u8; 4];
        assert_eq!(
            C_EncryptUpdate(0x4D50_1003, part.as_ptr() as *mut u8, 4, std::ptr::null_mut(), &mut need),
            CKR_OPERATION_NOT_INITIALIZED,
        );
        assert_eq!(
            C_DecryptFinal(0x4D50_1003, std::ptr::null_mut(), &mut need),
            CKR_OPERATION_NOT_INITIALIZED,
        );
    }

    #[test]
    fn update_short_buffer_keeps_operation_alive() {
        let _guard = test_lock::acquire();
        let session = 0x4D50_1004;
        install_aes_key(&[0x42u8; 16]);
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
