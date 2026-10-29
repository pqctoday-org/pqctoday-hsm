//! Session-only educational provisioning/orchestration for the browser adapter.
//! Reuses the existing test manufacturing CA, enrollment, policies and ceremony.
//! All slots are NEW; no existing token or key is reinitialized or rebound.
use super::{Profile, asn1, host_verify, records};
use crate::{constants::*, native, state};
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[derive(Clone)]
struct Original {
    public: u32,
    private: u32,
    key_type: u32,
    parameter_set: u32,
    unique_id: String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct ProtectedKey {
    public_handle: u32,
    private_handle: u32,
    key_type: u32,
    parameter_set: u32,
    receipt: Vec<u8>,
    session_handle: u32,
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl ProtectedKey {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
    pub fn public_handle(&self) -> u32 {
        self.public_handle
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
    pub fn private_handle(&self) -> u32 {
        self.private_handle
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
    pub fn key_type(&self) -> u32 {
        self.key_type
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
    pub fn parameter_set(&self) -> u32 {
        self.parameter_set
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
    pub fn receipt(&self) -> Vec<u8> {
        self.receipt.clone()
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter))]
    pub fn session_handle(&self) -> u32 {
        self.session_handle
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct ProtectedBackupLab {
    sessions: Vec<u32>,
    device_ids: Vec<[u8; 32]>,
    domain: [u8; 32],
    seed_policy: [u8; 48],
    expanded_policy: [u8; 48],
    originals: HashMap<u32, Original>,
    requests: HashMap<[u8; 48], Vec<u8>>,
}

// Close only this lab's sessions on setup failure or explicit disposal.
struct Sessions(Vec<u32>);
impl Drop for Sessions {
    fn drop(&mut self) {
        for s in &self.0 {
            let _ = native::logout(*s);
            let _ = native::close_session(*s);
        }
    }
}
impl Drop for ProtectedBackupLab {
    fn drop(&mut self) {
        for (index, s) in self.sessions.iter().enumerate() {
            // A reset can reuse numeric session handles. Never log out a
            // replacement token merely because it inherited the old number.
            if self.owns_session(index) {
                let _ = native::logout(*s);
                let _ = native::close_session(*s);
            }
        }
    }
}

impl ProtectedBackupLab {
    fn owns_session(&self, index: usize) -> bool {
        state::session_slot(self.sessions[index])
            .and_then(|slot| super::evidence::platform_device_id(slot).ok())
            .as_ref() == self.device_ids.get(index)
    }

    fn validate_sessions(&self) -> Result<(), u32> {
        if !state::is_initialized() { return Err(CKR_CRYPTOKI_NOT_INITIALIZED); }
        super::require_profile()?;
        if !(0..self.sessions.len()).all(|i| self.owns_session(i)) {
            return Err(CKR_SESSION_HANDLE_INVALID);
        }
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl ProtectedBackupLab {
    /// Explicit session-only demo enrollment. No CA private key leaves Rust.
    /// PINs are supplied by the caller; this never logs into existing slots.
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
    pub fn new(so_pin: &str, user_pin: &str) -> Result<Self, u32> {
        if !state::is_initialized() {
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
        }
        super::require_profile()?;
        if so_pin.len() < 4 || user_pin.len() < 4 || so_pin.len() > 255 || user_pin.len() > 255 {
            return Err(CKR_PIN_LEN_RANGE);
        }
        let start = state::TOKEN_STORE
            .with(|ts| ts.borrow().keys().max().copied().unwrap_or(0))
            .checked_add(1)
            .ok_or(CKR_DEVICE_MEMORY)?;
        let end = start.checked_add(3).ok_or(CKR_DEVICE_MEMORY)?;
        let now = super::now_unix();
        let mut ca = super::test_ca::TestManufacturingCa::new(now)?;
        let mut so = Sessions(Vec::new());
        let mut slots = Vec::new();
        for slot in start..end {
            // Refuse to reset existing state even if the caller retries setup.
            if state::TOKEN_STORE.with(|ts| ts.borrow().contains_key(&slot)) {
                return Err(CKR_ACTION_PROHIBITED);
            }
            state::ensure_slot(slot);
            native::init_token(slot, so_pin, "PQC EDUCATIONAL BACKUP")?;
            let s = native::open_session_so(slot, so_pin)?;
            so.0.push(s);
            native::init_pin(s, user_pin)?;
            let csr = super::begin_device_enrollment(s)?;
            let cert = ca.issue_device(&csr, now)?;
            let crl = ca.crl(now.saturating_sub(10), now + 7 * 86400)?;
            super::complete_device_enrollment(s, ca.root_der(), &cert, &crl)?;
            super::issue_function_certificates(s)?;
            slots.push(slot);
        }
        for a in &so.0 {
            for b in &so.0 {
                if a != b {
                    super::enroll_crl(
                        *a,
                        &super::own_device_crl(*b)?,
                        Some(&super::device_certificate(*b)?),
                    )?;
                }
            }
        }
        let domain = super::random32()?;
        let peers =
            so.0.iter()
                .map(|s| super::device_id(*s))
                .collect::<Result<Vec<_>, _>>()?;
        let mut mechs = vec![CKM_ML_KEM, CKM_ML_DSA];
        mechs.sort_unstable();
        let policy = |hash| {
            records::build_policy_with_constraint(
                domain,
                [true; 3],
                peers.clone(),
                now.saturating_sub(60),
                now + 7 * 86400,
                16,
                mechs.clone(),
                false,
                hash,
            )
        };
        let seed_der = policy(super::pqc_seed::profile_hash())?;
        let expanded_der = policy(super::sha384(b""))?;
        let mut seed_policy = [0; 48];
        let mut expanded_policy = [0; 48];
        for s in &so.0 {
            seed_policy = super::enroll_policy(*s, &seed_der)?;
            expanded_policy = super::enroll_policy(*s, &expanded_der)?;
        }
        drop(so);
        let mut users = Sessions(Vec::new());
        for slot in slots {
            users.0.push(native::open_session(slot, user_pin)?);
        }
        let sessions = std::mem::take(&mut users.0);
        Ok(Self {
            sessions,
            device_ids: peers,
            domain,
            seed_policy,
            expanded_policy,
            originals: HashMap::new(),
            requests: HashMap::new(),
        })
    }

    /// 0=ML-KEM-768, 1=ML-DSA-65. Uses standard C_GenerateKeyPair, not a new generator.
    pub fn generate(&mut self, algorithm: u32) -> Result<ProtectedKey, u32> {
        self.validate_sessions()?;
        let (mech, kt, ps, pu, pr) = match algorithm {
            0 => (
                CKM_ML_KEM_KEY_PAIR_GEN,
                CKK_ML_KEM,
                CKP_ML_KEM_768,
                CKA_ENCAPSULATE,
                CKA_DECAPSULATE,
            ),
            1 => (
                CKM_ML_DSA_KEY_PAIR_GEN,
                CKK_ML_DSA,
                CKP_ML_DSA_65,
                CKA_VERIFY,
                CKA_SIGN,
            ),
            _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED),
        };
        let ul = |v: u32| (v as usize).to_le_bytes().to_vec();
        let public = vec![
            (CKA_TOKEN, vec![1]),
            (CKA_PARAMETER_SET, ul(ps)),
            (pu, vec![1]),
        ];
        let private = vec![
            (CKA_TOKEN, vec![1]),
            (CKA_SENSITIVE, vec![1]),
            (CKA_EXTRACTABLE, vec![0]),
            (CKA_COPYABLE, vec![0]),
            (CKA_MODIFIABLE, vec![0]),
            (pr, vec![1]),
            (
                CKA_PQCTODAY_REPLICATION_POLICY_ID,
                self.seed_policy.to_vec(),
            ),
        ];
        let template = |attrs: &Vec<(u32, Vec<u8>)>| {
            attrs
                .iter()
                .flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()])
                .collect::<Vec<_>>()
        };
        let pt = template(&public);
        let st = template(&private);
        let mut m = [mech as usize, 0, 0];
        let (mut p, mut s) = (0, 0);
        let rv = crate::ffi::C_GenerateKeyPair(
            self.sessions[0],
            m.as_mut_ptr() as *mut u8,
            pt.as_ptr() as *mut u8,
            public.len() as u32,
            st.as_ptr() as *mut u8,
            private.len() as u32,
            &mut p,
            &mut s,
        );
        if rv != CKR_OK {
            return Err(rv);
        }
        let uid = String::from_utf8(
            native::get_attribute(self.sessions[0], s, CKA_UNIQUE_ID).ok_or(CKR_DEVICE_ERROR)?,
        )
        .map_err(|_| CKR_DEVICE_ERROR)?;
        self.originals.insert(
            s,
            Original {
                public: p,
                private: s,
                key_type: kt,
                parameter_set: ps,
                unique_id: uid,
            },
        );
        Ok(ProtectedKey {
            public_handle: p,
            private_handle: s,
            key_type: kt,
            parameter_set: ps,
            receipt: Vec::new(),
            session_handle: self.sessions[0],
        })
    }

    /// Backup a key generated by THIS lab. Representation comes from the
    /// destination policy; neither mutable CSV labels nor a key prefix is used.
    pub fn backup(&mut self, key: u32, seed: bool) -> Result<Vec<u8>, u32> {
        self.validate_sessions()?;
        if !self.originals.contains_key(&key) {
            return Err(CKR_KEY_HANDLE_INVALID);
        }
        let dst = self.sessions[if seed { 1 } else { 2 }];
        let policy = if seed {
            &self.seed_policy
        } else {
            &self.expanded_policy
        };
        let challenge = super::issue_source_challenge(self.sessions[0])?;
        let request = super::begin_receive(
            dst,
            asn1::Operation::OfflineBackup,
            &challenge,
            &self.domain,
            policy,
        )?;
        let package = super::create_replication_package(self.sessions[0], key, &request)?;
        self.requests.insert(super::sha384(&package), request);
        Ok(package)
    }

    /// Verify package, recover atomically, verify receipt, and prove identity
    /// with an independently retained original public key. No secret readback.
    pub fn recover(&self, package: &[u8]) -> Result<ProtectedKey, u32> {
        self.validate_sessions()?;
        if package.len() > super::package::MAX_PACKAGE_DER {
            return Err(CKR_DATA_LEN_RANGE);
        }
        let parsed: asn1::ReplicationPackage =
            asn1::decode_strict(package, super::package::MAX_PACKAGE_DER)?;
        let hash = super::sha384(package);
        let request = self.requests.get(&hash).ok_or(CKR_ACTION_PROHIBITED)?;
        let original = self
            .originals
            .values()
            .find(|o| o.unique_id == parsed.tbs.header.source_unique_id)
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        let index = if parsed.tbs.header.destination_policy.as_bytes() == self.seed_policy {
            1
        } else if parsed.tbs.header.destination_policy.as_bytes() == self.expanded_policy {
            2
        } else {
            return Err(CKR_ACTION_PROHIBITED);
        };
        let session = self.sessions[index];
        let (handle, receipt) = super::import_replication_package(session, package, &[])?;
        host_verify::verify_receipt(
            &receipt,
            package,
            request,
            &super::trust_inputs(
                state::session_slot(self.sessions[0]).ok_or(CKR_SESSION_HANDLE_INVALID)?,
            ),
            super::now_unix(),
            Profile::Educational,
        )
        .map_err(|_| CKR_ACTION_PROHIBITED)?;
        let spki =
            native::get_attribute(session, handle, CKA_PUBLIC_KEY_INFO).ok_or(CKR_DEVICE_ERROR)?;
        let original_spki =
            native::get_attribute(self.sessions[0], original.private, CKA_PUBLIC_KEY_INFO)
                .ok_or(CKR_DEVICE_ERROR)?;
        if spki != original_spki {
            return Err(CKR_ENCRYPTED_DATA_INVALID);
        }
        if original.key_type == CKK_ML_KEM {
            let (ciphertext, expected) =
                native::encapsulate(self.sessions[0], original.public, CKM_ML_KEM)?;
            let expected = zeroize::Zeroizing::new(expected);
            let actual = zeroize::Zeroizing::new(native::decapsulate(
                session,
                handle,
                CKM_ML_KEM,
                &ciphertext,
            )?);
            if actual.as_slice() != expected.as_slice() {
                return Err(CKR_ENCRYPTED_DATA_INVALID);
            }
        } else {
            let signature = native::sign(
                session,
                handle,
                CKM_ML_DSA,
                b"protected-backup recovery identity",
            )?;
            if !native::verify(
                self.sessions[0],
                original.public,
                CKM_ML_DSA,
                b"protected-backup recovery identity",
                &signature,
            )? {
                return Err(CKR_ENCRYPTED_DATA_INVALID);
            }
        }
        let lineage = native::get_attribute(session, handle, CKA_PQCTODAY_REPLICATION_LINEAGE_ID)
            .ok_or(CKR_DEVICE_ERROR)?;
        let slot = state::session_slot(session).ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let publics = state::OBJECTS.with(|objects| {
            objects
                .borrow()
                .iter()
                .filter_map(|(h, p)| {
                    (state::object_slot_of(p) == slot
                        && state::get_object_attr_u32_from(p, CKA_CLASS) == Some(CKO_PUBLIC_KEY)
                        && p.get(&CKA_PQCTODAY_REPLICATION_LINEAGE_ID) == Some(&lineage)
                        && p.get(&CKA_PUBLIC_KEY_INFO) == Some(&spki))
                    .then_some(*h)
                })
                .collect::<Vec<_>>()
        });
        if publics.len() != 1 {
            return Err(CKR_DEVICE_ERROR);
        }
        Ok(ProtectedKey {
            public_handle: publics[0],
            private_handle: handle,
            key_type: original.key_type,
            parameter_set: original.parameter_set,
            receipt,
            session_handle: session,
        })
    }
}
