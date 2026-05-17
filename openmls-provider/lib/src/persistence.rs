//! HSM-backed checkpointing for OpenMLS group state.
//!
//! [`openmls_memory_storage::MemoryStorage`] is, structurally, a
//! `RwLock<HashMap<Vec<u8>, Vec<u8>>>` (the `values` field is `pub`).
//! That makes the entire MLS-StorageProvider state a flat K/V map that
//! we can snapshot to a single PKCS#11 `CKO_DATA` token object.
//!
//! ## Why a snapshot, not per-key PKCS#11 writes
//!
//! `openmls_traits::storage::StorageProvider` has 57 methods. Wiring
//! every one through PKCS#11 directly would be ~1000 lines of mechanical
//! boilerplate AND would put a `C_FindObjects` + `C_GetAttributeValue`
//! on the hot path of every MLS protocol step. Real production deployments
//! use a write-through cache anyway. The snapshot approach gets us
//! durable HSM-backed persistence at a fraction of the engineering cost.
//!
//! ## Usage
//!
//! ```no_run
//! use openmls_pqctoday_crypto::{HsmConfig, PqcTodayProvider};
//!
//! let cfg = HsmConfig::new("/path/to/libsofthsmv3.so").with_pin("1234");
//!
//! // First boot: starts fresh, or restores from the HSM if a snapshot
//! // was written under this label by a previous run.
//! let provider = PqcTodayProvider::with_persistence(&cfg, "alice-group-state")
//!     .expect("open provider with HSM-backed storage");
//!
//! // ... drive an MlsGroup through `&provider` ...
//!
//! // Checkpoint to the HSM at any logical save point.
//! provider.persist().expect("snapshot to HSM");
//!
//! // After process exit and a re-launch, `with_persistence(..., same label)`
//! // brings the group state back exactly as it was at the last `persist`.
//! ```
//!
//! ## Wire format of the snapshot blob
//!
//! ```text
//! ┌────────┬─────────┬──────────────────────────────────────────┐
//! │ "PQSM" │ ver (1) │     count (u64 BE)                       │
//! ├────────┴─────────┴──────────────────────────────────────────┤
//! │  per entry: k_len (u64 BE) ‖ v_len (u64 BE) ‖ k ‖ v         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! Magic + version let us evolve the snapshot format without colliding
//! with any other `CKO_DATA` object on the token.

use std::collections::HashMap;
use std::sync::RwLock;

use openmls_memory_storage::MemoryStorage;

use crate::backend::PkcsOps;
use crate::error::PqcTodayError;

const SNAPSHOT_MAGIC: &[u8; 4] = b"PQSM"; // pqctoday storage
const SNAPSHOT_VERSION: u8 = 1;

fn encode_snapshot(values: &HashMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    let mut total_bytes = 4 + 1 + 8;
    for (k, v) in values.iter() {
        total_bytes += 8 + 8 + k.len() + v.len();
    }
    let mut out = Vec::with_capacity(total_bytes);
    out.extend_from_slice(SNAPSHOT_MAGIC);
    out.push(SNAPSHOT_VERSION);
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for (k, v) in values.iter() {
        out.extend_from_slice(&(k.len() as u64).to_be_bytes());
        out.extend_from_slice(&(v.len() as u64).to_be_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

fn decode_snapshot(bytes: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, PqcTodayError> {
    if bytes.len() < 13 || &bytes[..4] != SNAPSHOT_MAGIC || bytes[4] != SNAPSHOT_VERSION {
        return Err(PqcTodayError::MalformedKeyHandle); // re-using closest-fitting variant
    }
    let count = u64::from_be_bytes(bytes[5..13].try_into().unwrap()) as usize;
    let mut map = HashMap::with_capacity(count);
    let mut offset = 13;
    for _ in 0..count {
        if offset + 16 > bytes.len() {
            return Err(PqcTodayError::MalformedKeyHandle);
        }
        let k_len = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
        let v_len =
            u64::from_be_bytes(bytes[offset + 8..offset + 16].try_into().unwrap()) as usize;
        offset += 16;
        if offset + k_len + v_len > bytes.len() {
            return Err(PqcTodayError::MalformedKeyHandle);
        }
        let k = bytes[offset..offset + k_len].to_vec();
        offset += k_len;
        let v = bytes[offset..offset + v_len].to_vec();
        offset += v_len;
        map.insert(k, v);
    }
    Ok(map)
}

/// Restore a `MemoryStorage` from the HSM snapshot at `label`, or return
/// a fresh empty `MemoryStorage` if no snapshot exists yet.
pub fn restore_or_new(ops: &dyn PkcsOps, label: &str) -> Result<MemoryStorage, PqcTodayError> {
    let bytes = match ops.snapshot_read(label)? {
        Some(b) => b,
        None => return Ok(MemoryStorage::default()),
    };
    let map = decode_snapshot(&bytes)?;
    Ok(MemoryStorage {
        values: RwLock::new(map),
    })
}

/// Snapshot `storage` to the HSM as a `CKO_DATA` token object with
/// `CKA_LABEL = label`. If an object with that label already exists,
/// it is destroyed and re-created (PKCS#11 has no atomic CAS on
/// `CKA_VALUE` across all module vendors, so destroy+create is the
/// portable shape).
pub fn snapshot(
    storage: &MemoryStorage,
    ops: &dyn PkcsOps,
    label: &str,
) -> Result<(), PqcTodayError> {
    let bytes = {
        let guard = storage
            .values
            .read()
            .map_err(|_| PqcTodayError::NotInitialised)?;
        encode_snapshot(&guard)
    };
    ops.snapshot_write(label, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip_via_in_memory_map() {
        let mut map = HashMap::new();
        map.insert(b"alice".to_vec(), b"value-a".to_vec());
        map.insert(b"bob".to_vec(), vec![0xff; 1024]);
        map.insert(vec![], b"empty key".to_vec());

        let bytes = encode_snapshot(&map);
        let recovered = decode_snapshot(&bytes).unwrap();
        assert_eq!(recovered, map);
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(decode_snapshot(bad).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let mut map = HashMap::new();
        map.insert(b"k".to_vec(), b"v".to_vec());
        let mut bytes = encode_snapshot(&map);
        bytes.pop();
        assert!(decode_snapshot(&bytes).is_err());
    }
}
