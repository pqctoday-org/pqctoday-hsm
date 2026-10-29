// SPDX-License-Identifier: AGPL-3.0-only
//! Typed WASM adapters for the EXISTING protected-replication operations.
//!
//! Only requests, encrypted packages, signed receipts and object handles cross
//! this boundary. Enrollment, key eligibility, policies, parsing, replay and
//! atomic installation remain in the same engine code used by the native ABI.
//! Payload representation is governed by the engine's enrolled policy profile.

use crate::constants::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

fn initialized() -> Result<(), u32> {
    if crate::state::is_initialized() {
        Ok(())
    } else {
        Err(CKR_CRYPTOKI_NOT_INITIALIZED)
    }
}

/// Public recovery result. Neither accessor can return private material.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct InstalledReplica {
    handle: u32,
    receipt: Vec<u8>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl InstalledReplica {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
    pub fn handle(&self) -> u32 {
        self.handle
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
    pub fn receipt(&self) -> Vec<u8> {
        self.receipt.clone()
    }
}

/// Explicit opt-in, as required by the existing educational profile.
/// This selects the profile; it does not enroll a token or authorize a key.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = pqctodaySelectEducationalReplicationProfile))]
pub fn select_educational_profile() -> Result<(), u32> {
    initialized()?;
    super::select_educational_profile();
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = pqctodayClearReplicationProfile))]
pub fn clear_profile() {
    super::clear_profile();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = pqctodayCreateReplicationPackage))]
pub fn create_package(session: u32, key: u32, request: &[u8]) -> Result<Vec<u8>, u32> {
    initialized()?;
    super::create_replication_package(session, key, request)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = pqctodayImportReplicationPackage))]
pub fn import_package(session: u32, package: &[u8]) -> Result<InstalledReplica, u32> {
    initialized()?;
    let (handle, receipt) = super::import_replication_package(session, package, &[])?;
    Ok(InstalledReplica { handle, receipt })
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = pqctodayCloneKey))]
pub fn clone_key(
    source_session: u32,
    source_key: u32,
    destination_session: u32,
    request: &[u8],
) -> Result<InstalledReplica, u32> {
    initialized()?;
    let (handle, receipt) = super::clone_key(
        source_session,
        source_key,
        destination_session,
        request,
        &[],
    )?;
    Ok(InstalledReplica { handle, receipt })
}
