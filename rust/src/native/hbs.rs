//! Hash-based signatures (HSS/LMS, RFC 8554) — the stateful sign-and-advance
//! core, shared between `ffi::C_Sign` (PKCS#11 wasm32 ABI) and
//! `native::sign` (typed Rust API for the KMIP server).
//!
//! This is the single source of truth for leaf-index advance-and-persist.
//! HSS/LMS is a **one-time-signature** scheme: reusing a leaf index breaks
//! its security property outright. Before this module existed, the
//! advance-and-persist logic lived only inline inside `ffi::C_Sign`; the
//! `native::sign` path (which the KMIP server uses) had no HSS arm at all.
//! Two independent copies of "how to safely advance a leaf" would risk
//! drift between them — this module exists so there is exactly one.
//!
//! ## Two-phase prepare/commit
//!
//! `sign_prepare` computes the signature and the would-be next private-key
//! state but does **not** persist it. `sign_commit` persists. This
//! preserves `ffi::C_Sign`'s PKCS#11 v3.2 §5.2 requirement: a stateful key's
//! leaf MUST NOT be consumed until the caller's output buffer is known to
//! be adequate, so a `CKR_BUFFER_TOO_SMALL` retry re-signs the same
//! (unadvanced) leaf deterministically. `native::sign` has no output
//! buffer — it calls `sign_prepare` then `sign_commit` back-to-back.

use crate::constants::{
    CKA_HSS_LMS_TYPES, CKA_KEYS_REMAINING, CKA_PRIV_LEAF_INDEX, CKA_LMS_PARAM_SET,
    CKA_PRIV_STATEFUL_KEY_STATE, CKR_FUNCTION_FAILED, CKR_KEY_TYPE_INCONSISTENT,
};
use crate::state::{
    get_object_attr_bytes, get_object_attr_u32, get_object_attr_u64, set_object_attrs_bytes_batch,
};

/// Total one-time signatures of an HSS scheme: ∏ 2^H over its levels' LMS
/// types (RFC 8554 §6), saturating. Unknown types contribute nothing.
pub fn hss_capacity(lms_types: &[u32]) -> u64 {
    lms_types
        .iter()
        .filter_map(|p| crate::crypto::lms::lms_param_max_leaves(*p))
        .fold(1u64, |acc, leaves| acc.saturating_mul(leaves))
}

/// The per-level LMS types an HSS private key carries in CKA_HSS_LMS_TYPES
/// (CK_ULONG array), if it has them.
fn lms_types_of(handle: u32) -> Option<Vec<u32>> {
    let word = crate::ck_param::WORD;
    let b = get_object_attr_bytes(handle, CKA_HSS_LMS_TYPES)?;
    if b.is_empty() || b.len() % word != 0 {
        return None;
    }
    Some(b.chunks_exact(word).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
}

/// A computed HSS/LMS signature plus the not-yet-persisted next private-key
/// state needed to commit it. Dropping this without calling [`sign_commit`]
/// leaves the key object completely unchanged (the leaf was never consumed).
pub(crate) struct Prepared {
    pub signature: Vec<u8>,
    new_priv_state: Vec<u8>,
}

/// Compute an HSS/LMS signature over `msg` using the key at `handle`.
/// Does **not** mutate the object's stored state — call [`sign_commit`]
/// once the caller has verified it can actually deliver the signature.
pub(crate) fn sign_prepare(handle: u32, msg: &[u8]) -> Result<Prepared, u32> {
    let priv_bytes =
        get_object_attr_bytes(handle, CKA_PRIV_STATEFUL_KEY_STATE).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let lms_param = get_object_attr_u32(handle, CKA_LMS_PARAM_SET).unwrap_or(0x05);

    let mut new_state: Option<Vec<u8>> = None;
    let mut update_fn = |new_priv: &[u8]| -> Result<(), ()> {
        new_state = Some(new_priv.to_vec());
        Ok(())
    };
    let signature = crate::crypto::lms::hss_sign(lms_param, &priv_bytes, msg, &mut update_fn)?;
    // hss_sign only returns Ok(_) after firing update_fn (see its own
    // callback_fired bookkeeping) — but stay honest rather than unwrap.
    let new_priv_state = new_state.ok_or(CKR_FUNCTION_FAILED)?;
    Ok(Prepared { signature, new_priv_state })
}

/// Persist the state change from a [`Prepared`] signature: rotate the
/// stored private-key state, advance the leaf index, and decrement the
/// remaining-signatures counter (PKCS#11 v3.2 §6.14). Call exactly once
/// per `Prepared` value that is actually delivered to the caller.
///
/// All three fields are ONE logical state transition ("this leaf was
/// consumed") and are written via [`set_object_attrs_bytes_batch`] in a
/// single coalesced call — both the in-memory update (one `OBJECTS` lock
/// instead of three) and, when a durable store is configured, the disk
/// write are atomic across all three fields. Three separate writes would
/// let a crash between them leave disk and memory disagreeing about which
/// leaf was last used, which is exactly the one-time-signature reuse
/// hazard this module exists to prevent.
pub(crate) fn sign_commit(handle: u32, prepared: &Prepared) {
    let mut changes = vec![(CKA_PRIV_STATEFUL_KEY_STATE, prepared.new_priv_state.clone())];
    let old_idx = get_object_attr_u64(handle, CKA_PRIV_LEAF_INDEX).unwrap_or(0);
    changes.push((CKA_PRIV_LEAF_INDEX, (old_idx + 1).to_le_bytes().to_vec()));
    // CKA_KEYS_REMAINING (hss.md private key table): min(remaining, 2^32-1)
    // at CK_ULONG width. It was rewritten as 4 bytes, so after the first
    // signature a 64-bit caller read a 4-byte CK_ULONG. Recomputed from the
    // capacity and the leaf index when the key records its levels (so a tree
    // above 2^32 stays at the cap until it really drops below it); keys
    // without CKA_HSS_LMS_TYPES (imported, or generated before it was stored)
    // count down from the stored value.
    if get_object_attr_bytes(handle, CKA_KEYS_REMAINING).is_some() {
        let remaining = match lms_types_of(handle) {
            Some(types) => hss_capacity(&types).saturating_sub(old_idx + 1),
            None => (get_object_attr_u32(handle, CKA_KEYS_REMAINING).unwrap_or(0) as u64).saturating_sub(1),
        };
        changes.push((
            CKA_KEYS_REMAINING,
            crate::crypto::xmss_bridge::keys_remaining_attr_bytes(remaining),
        ));
    }
    set_object_attrs_bytes_batch(handle, &changes);
}
