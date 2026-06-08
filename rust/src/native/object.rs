//! Object lifecycle + attribute queries — typed wrappers around the
//! `state::*` typed object storage (which already accepts typed args).
//!
//! Implementation lands in Phase 7b commit 7.

use super::CkRv;

/// Destroy an object by handle. Wraps `ffi::C_DestroyObject`. After this
/// call the handle is invalid; subsequent ops return
/// `CKR_OBJECT_HANDLE_INVALID`.
pub fn destroy_object(_session: u32, _handle: u32) -> Result<(), CkRv> {
    unimplemented!("native::object::destroy_object — Phase 7b commit 7")
}

/// Look up an object handle by `CKA_ID`. Returns `Ok(None)` if no object
/// matches. Used by the KMIP `Sqlite`/`Memory` store layer to recover
/// the session-scoped `CK_OBJECT_HANDLE` from the stable `CKA_ID` it
/// persists per KMIP UID.
///
/// Wraps `ffi::C_FindObjectsInit` + `ffi::C_FindObjects` +
/// `ffi::C_FindObjectsFinal`.
pub fn find_by_cka_id(_session: u32, _cka_id: &[u8]) -> Result<Option<u32>, CkRv> {
    unimplemented!("native::object::find_by_cka_id — Phase 7b commit 7")
}

/// Read a single attribute. Returns `None` if the attribute is absent OR
/// the object's policy marks it sensitive (`CKA_SENSITIVE = true` on
/// private-key material).
///
/// For known-sized scalar attrs (`CKA_KEY_TYPE`, `CKA_CLASS`,
/// `CKA_PARAMETER_SET`, …) the caller decodes the returned bytes as a
/// `u32` (little-endian, matching the engine's storage convention).
pub fn get_attribute(_session: u32, _handle: u32, _attr_type: u32) -> Option<Vec<u8>> {
    unimplemented!("native::object::get_attribute — Phase 7b commit 7")
}

/// Read a single `u32` attribute. Convenience over [`get_attribute`].
pub fn get_attribute_u32(_session: u32, _handle: u32, _attr_type: u32) -> Option<u32> {
    unimplemented!("native::object::get_attribute_u32 — Phase 7b commit 7")
}

/// Read a boolean attribute. Convenience over [`get_attribute`].
pub fn get_attribute_bool(_session: u32, _handle: u32, _attr_type: u32) -> Option<bool> {
    unimplemented!("native::object::get_attribute_bool — Phase 7b commit 7")
}
