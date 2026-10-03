//! C1 — per-connection PKCS#11 application contexts.
//!
//! PKCS#11 v3.2 §5.6 scopes login state to an *application*: "all sessions an
//! application has with a token have a shared login state", and
//! `C_CloseAllSessions` "closes all sessions an application has with a token".
//! A C caller that loads the library is one application, so a server that
//! hosts many clients in one process (the KMIP listener) used to make every
//! client share ONE login state: a security officer on one connection and a
//! normal user on another could not be logged in at the same time
//! (`CKR_USER_ANOTHER_ALREADY_LOGGED_IN`, 0x104).
//!
//! A context is one such application. The engine keeps:
//!
//! * the **default context** ([`DEFAULT_CONTEXT`], id 0), which every native
//!   C / WASM / remoting caller is in implicitly. Its login state is still
//!   `TokenState::login_state`, and with no other context present it behaves
//!   exactly as before C1;
//! * any number of **connection contexts**, created by a server after it has
//!   authenticated a connection ([`create_context`]), holding immutable
//!   connection metadata ([`ContextMeta`]) and their own per-slot login state.
//!   Sessions opened inside one ([`open_session`]) carry its id in
//!   `SessionState::context`; every login check resolves the session's
//!   context. [`destroy_context`] closes all of its sessions.
//!
//! Each context obeys the v3.2 rules on its own (one role at a time, no R/O
//! session while its SO is logged in, and so on). Different contexts are
//! independent, as different applications are.
//!
//! ## Private handles across contexts
//!
//! §5.6.10: after `C_Logout` the application's handles to private objects
//! "become invalid (even if a user is later logged back into the token, those
//! handles remain invalid)". The engine implements that by re-keying private
//! token objects under fresh handles and moving their durable rows
//! (`state::invalidate_private_handles_on_slot`, K0B-R2-02). Object handles
//! are global, so doing that while ANOTHER context is still logged in as the
//! normal user would invalidate that context's handles too, and its next
//! write would recreate the row under the old handle (a duplicate).
//!
//! The rule is therefore (any login counts, SO included: an admin context
//! logged in as SO holds handles to the records it is staging):
//!
//! * a logout when no other context on the slot is logged in re-keys exactly
//!   as before (and clears every pending mark, below);
//! * a logout while another context IS logged in re-keys nothing. It
//!   destroys only this context's private session objects and marks the
//!   context *pending* on that slot. Its old private handles are unusable at
//!   once, because a logged-out context cannot reach private objects;
//! * a pending context may not log in again on that slot while another
//!   context is still logged in (`CKR_USER_TOO_MANY_TYPES`), because that
//!   would revive its old handles. The re-key that clears the mark runs when
//!   the last login on the slot ends.
//!
//! No handle is ever encoded or aliased, so nothing can collide with a value
//! `NEXT_HANDLE` will mint later: the only handles that change are re-keyed
//! by the existing monotonic allocator.
//!
//! Lock order: `SESSIONS` shards are always released before `TOKEN_STORE`;
//! `TOKEN_STORE` → `REGISTRY` when both are held. `OBJECTS` is never taken
//! while either is held.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use lazy_static::lazy_static;

use crate::constants::*;
use crate::state::{LoginState, TokenState, SESSIONS};

/// Identifier of an application context. `0` is the default context.
pub type ContextId = u64;

/// The implicit context of every native C / WASM / remoting caller.
pub const DEFAULT_CONTEXT: ContextId = 0;

/// Connection metadata attached when a context is created. It is immutable:
/// there is no API that changes it after [`create_context`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextMeta {
    /// The role the server assigned to the authenticated peer.
    pub role: String,
    /// SHA-256 of the peer's TLS client certificate (DER).
    pub client_cert_sha256: [u8; 32],
    /// The listener that accepted the connection (name or bound address).
    pub listener: String,
    /// An optional caller-supplied correlation id for audit records.
    pub correlation: Option<String>,
}

struct ContextRecord {
    meta: ContextMeta,
    /// Per-slot login state; an absent slot is `Public`.
    logins: HashMap<u32, LoginState>,
    /// Set by [`destroy_context`] before it closes the sessions, so no new
    /// session can be opened into a context that is going away.
    closing: bool,
}

#[derive(Default)]
pub(crate) struct Registry {
    contexts: HashMap<ContextId, ContextRecord>,
    /// slot → contexts that logged out as USER while another context held a
    /// USER login (see the module doc). Includes the default context.
    pending: HashMap<u32, HashSet<ContextId>>,
}

lazy_static! {
    static ref REGISTRY: Mutex<Registry> = Mutex::new(Registry::default());
}

static NEXT_CONTEXT: AtomicU64 = AtomicU64::new(1);

pub(crate) fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

impl Registry {
    /// Login state of `ctx` on `token`'s slot.
    pub(crate) fn login(&self, token: &TokenState, ctx: ContextId) -> LoginState {
        if ctx == DEFAULT_CONTEXT {
            return token.login_state;
        }
        self.contexts
            .get(&ctx)
            .and_then(|r| r.logins.get(&token.slot_id).copied())
            .unwrap_or(LoginState::Public)
    }

    pub(crate) fn set_login(&mut self, token: &mut TokenState, ctx: ContextId, state: LoginState) {
        if ctx == DEFAULT_CONTEXT {
            token.login_state = state;
            return;
        }
        if let Some(r) = self.contexts.get_mut(&ctx) {
            if state == LoginState::Public {
                r.logins.remove(&token.slot_id);
            } else {
                r.logins.insert(token.slot_id, state);
            }
        }
    }

    /// True if any context other than `ctx` is logged in (any role) on the slot.
    pub(crate) fn other_logged_in(&self, token: &TokenState, ctx: ContextId) -> bool {
        if ctx != DEFAULT_CONTEXT && token.login_state != LoginState::Public {
            return true;
        }
        self.contexts
            .iter()
            .any(|(id, r)| *id != ctx && r.logins.contains_key(&token.slot_id))
    }

    /// True if any context (default included) is logged in on the slot.
    pub(crate) fn any_logged_in(&self, token: &TokenState) -> bool {
        token.login_state != LoginState::Public
            || self.contexts.values().any(|r| r.logins.contains_key(&token.slot_id))
    }

    pub(crate) fn is_pending(&self, slot: u32, ctx: ContextId) -> bool {
        self.pending.get(&slot).is_some_and(|s| s.contains(&ctx))
    }

    /// Reset every connection context's login on `slot` (C_InitToken).
    pub(crate) fn reset_slot(&mut self, slot: u32) {
        for r in self.contexts.values_mut() {
            r.logins.remove(&slot);
        }
        self.pending.remove(&slot);
    }
}

/// What a logout must do to private handles after the login state flipped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LogoutAction {
    /// Re-key every private token object on the slot (pre-C1 behaviour).
    Rekey,
    /// Destroy only this context's private session objects; no re-key.
    Deferred,
}

/// Flip `ctx` to Public on `token`'s slot and decide the handle action.
/// Returns `None` if `ctx` was not logged in. The second value is true when
/// no context on the slot remains logged in (the unlocked master key may be
/// cleared). Caller holds `TOKEN_STORE`; this takes `REGISTRY`.
pub(crate) fn logout_locked(token: &mut TokenState, ctx: ContextId) -> Option<(LogoutAction, bool)> {
    let mut reg = registry();
    if reg.login(token, ctx) == LoginState::Public {
        return None;
    }
    reg.set_login(token, ctx, LoginState::Public);
    let slot = token.slot_id;
    let action = if reg.any_logged_in(token) {
        reg.pending.entry(slot).or_default().insert(ctx);
        LogoutAction::Deferred
    } else {
        reg.pending.remove(&slot);
        LogoutAction::Rekey
    };
    Some((action, !reg.any_logged_in(token)))
}

/// Apply a [`LogoutAction`] (outside every state lock).
pub(crate) fn apply_logout(slot: u32, ctx: ContextId, action: LogoutAction, none_left: bool) {
    match action {
        LogoutAction::Rekey => crate::state::invalidate_private_handles_on_slot(slot),
        LogoutAction::Deferred => {
            let mine: HashSet<u32> = SESSIONS
                .keys_where(|_, ss| ss.slot_id == slot && ss.context == ctx)
                .into_iter()
                .collect();
            crate::state::destroy_private_session_objects_of(slot, &mine);
        }
    }
    if none_left {
        crate::store::clear_unlocked_master_key(slot);
    }
}

/// Context of a live session; the default context for an unknown handle.
pub fn session_context(h_session: u32) -> ContextId {
    SESSIONS
        .shard(h_session)
        .get(&h_session)
        .map(|ss| ss.context)
        .unwrap_or(DEFAULT_CONTEXT)
}

/// Login state of the session's context on the session's slot. `None` for an
/// unknown session or slot.
pub fn session_login_state(h_session: u32) -> Option<LoginState> {
    let (slot, ctx) = SESSIONS
        .shard(h_session)
        .get(&h_session)
        .map(|ss| (ss.slot_id, ss.context))?;
    crate::state::TOKEN_STORE.with(|ts| {
        let store = ts.borrow();
        let token = store.get(&slot)?;
        Some(registry().login(token, ctx))
    })
}

/// Create a connection context. Call it after the connection is
/// authenticated (e.g. after the mTLS handshake). The metadata never changes.
pub fn create_context(meta: ContextMeta) -> ContextId {
    let id = NEXT_CONTEXT.fetch_add(1, Ordering::Relaxed);
    registry().contexts.insert(
        id,
        ContextRecord {
            meta,
            logins: HashMap::new(),
            closing: false,
        },
    );
    id
}

/// True if `ctx` exists and is not being destroyed.
pub fn context_is_live(ctx: ContextId) -> bool {
    ctx == DEFAULT_CONTEXT || registry().contexts.get(&ctx).is_some_and(|r| !r.closing)
}

/// Metadata of a connection context (`None` for the default context or an
/// unknown id).
pub fn context_meta(ctx: ContextId) -> Option<ContextMeta> {
    registry().contexts.get(&ctx).map(|r| r.meta.clone())
}

/// Metadata of the context a session belongs to (`None` for a session in the
/// default context, or an unknown session).
pub fn session_context_meta(h_session: u32) -> Option<ContextMeta> {
    let ctx = SESSIONS.shard(h_session).get(&h_session).map(|ss| ss.context)?;
    context_meta(ctx)
}

/// Open a session on `slot` inside `ctx`, with `C_OpenSession`'s rules and
/// return codes. `CKR_ARGUMENTS_BAD` if the context does not exist or is
/// being destroyed.
pub fn open_session(ctx: ContextId, slot_id: u32, flags: u32) -> Result<u32, u32> {
    let mut h = 0u32;
    let rv = crate::ffi::open_session_in_context(slot_id, flags, ctx, &mut h);
    if rv != CKR_OK {
        return Err(rv);
    }
    // destroy_context may have started between the check inside
    // open_session_in_context and the insert; it would then miss this session.
    if !context_is_live(ctx) {
        let _ = crate::ffi::C_CloseSession(h);
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(h)
}

/// `Ok(())` if `h_session` is a live session of `ctx`; otherwise
/// `CKR_SESSION_HANDLE_INVALID`. A server calls this before acting on a
/// session handle a client sent it, so one connection cannot drive another's
/// session.
pub fn check_session(ctx: ContextId, h_session: u32) -> Result<(), u32> {
    match SESSIONS.shard(h_session).get(&h_session) {
        Some(ss) if ss.context == ctx => Ok(()),
        _ => Err(CKR_SESSION_HANDLE_INVALID),
    }
}

/// Live sessions of `ctx`, all slots.
pub fn context_sessions(ctx: ContextId) -> Vec<u32> {
    SESSIONS.keys_where(|_, ss| ss.context == ctx)
}

/// Destroy a connection context: close every one of its sessions (which ends
/// its logins with the usual handle rules), then forget it. Idempotent; a
/// no-op for the default context, which cannot be destroyed.
pub fn destroy_context(ctx: ContextId) {
    if ctx == DEFAULT_CONTEXT {
        return;
    }
    {
        let mut reg = registry();
        match reg.contexts.get_mut(&ctx) {
            Some(r) => r.closing = true,
            None => return,
        }
    }
    for h in context_sessions(ctx) {
        let _ = crate::ffi::C_CloseSession(h);
    }
    // A login with no session left is impossible through the API (closing the
    // last session on a slot resets it), but end any that remain through the
    // normal logout path so the handle rules and master-key clearing apply.
    let slots: Vec<u32> = registry()
        .contexts
        .get(&ctx)
        .map(|r| r.logins.keys().copied().collect())
        .unwrap_or_default();
    for slot in slots {
        let outcome = crate::state::TOKEN_STORE.with(|ts| {
            let mut store = ts.borrow_mut();
            store.get_mut(&slot).and_then(|t| logout_locked(t, ctx))
        });
        if let Some((action, none_left)) = outcome {
            apply_logout(slot, ctx, action, none_left);
        }
    }
    let mut reg = registry();
    reg.contexts.remove(&ctx);
    for set in reg.pending.values_mut() {
        set.remove(&ctx);
    }
}

/// Drop every connection context (C_Finalize; every session is already gone).
pub(crate) fn clear_all() {
    let mut reg = registry();
    reg.contexts.clear();
    reg.pending.clear();
}

/// Ids of the live connection contexts (diagnostics and tests).
pub fn context_ids() -> Vec<ContextId> {
    registry().contexts.keys().copied().collect()
}

/// Number of live connection contexts (diagnostics and tests).
pub fn context_count() -> usize {
    registry().contexts.len()
}

/// RAII owner of a connection context: destroys it when dropped, so every
/// exit path of a connection handler (normal end, TLS error, panic unwind,
/// shutdown) closes the context's sessions.
pub struct ContextGuard {
    id: ContextId,
}

impl ContextGuard {
    pub fn new(meta: ContextMeta) -> Self {
        ContextGuard { id: create_context(meta) }
    }

    pub fn id(&self) -> ContextId {
        self.id
    }
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        destroy_context(self.id);
    }
}
