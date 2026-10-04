//! FHE browser matrix — FHE plan §7 (P0A/P3 "candidate platform matrix").
//!
//! Exports the token's OWN TFHE derivation (`replication::fhe_tfhe`, the code
//! the PKCS#11 mechanisms run) to JavaScript, so a desktop browser can be
//! checked against the §5.5 known-answer vector `client-key-kat-v1` and timed.
//! Only fixed public test seeds go in; only a SHA-256 or a decrypted test
//! value comes out. No token object or token secret is reachable from here.
//!
//! Built only with `educational-fhe` on wasm32 (`scripts/build-fhe-browser-kat.sh`);
//! no shipped bundle enables that feature.

use tfhe::prelude::*;
use tfhe::safe_serialization::safe_serialize;
use wasm_bindgen::prelude::*;

fn seed32(seed: &[u8]) -> Result<[u8; 32], JsValue> {
    seed.try_into().map_err(|_| JsValue::from_str("seed must be exactly 32 bytes"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The derived `Seed(u128)` as 32 hex digits (big-endian).
#[wasm_bindgen(js_name = fheDerivedSeedHex)]
pub fn fhe_derived_seed_hex(seed: &[u8]) -> Result<String, JsValue> {
    let s = crate::replication::fhe_tfhe::derive_tfhe_seed(&seed32(seed)?);
    Ok(format!("{s:032x}"))
}

/// `"<len>:<sha256 hex>"` of the safe-serialized client key for `seed`.
#[wasm_bindgen(js_name = fheClientKeyKat)]
pub fn fhe_client_key_kat(seed: &[u8]) -> Result<String, JsValue> {
    use sha2::Digest;
    let ck = crate::replication::fhe_tfhe::client_key_for(&seed32(seed)?);
    let mut buf = Vec::new();
    safe_serialize(&ck, &mut buf, 1 << 32).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(format!("{}:{}", buf.len(), hex(&sha2::Sha256::digest(&buf))))
}

/// Homomorphic `a + b` on `FheUint8` under a fresh server key from `seed`'s
/// client key; returns the decrypted sum. Exercises server-key generation and
/// one PBS-bearing operation in the browser (the costly part of the budget).
#[wasm_bindgen(js_name = fheAddU8)]
pub fn fhe_add_u8(seed: &[u8], a: u8, b: u8) -> Result<u8, JsValue> {
    let ck = crate::replication::fhe_tfhe::client_key_for(&seed32(seed)?);
    tfhe::set_server_key(tfhe::ServerKey::new(&ck));
    let x = tfhe::FheUint8::encrypt(a, &ck);
    let y = tfhe::FheUint8::encrypt(b, &ck);
    let sum: u8 = (&x + &y).decrypt(&ck);
    Ok(sum)
}

/// §6.6 P0A memory spike: the public export the token's
/// `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` produces, built the same way
/// (`fhe_tfhe::derive_public`): the safe-serialized `CompressedServerKey`
/// (`kind = 0`) or `CompactPublicKey` (`kind = 1`) for `seed`'s client key,
/// under the same 64 MiB limit. Returned as one owned buffer, so JavaScript
/// receives exactly one copy across the WASM/JS boundary.
#[wasm_bindgen(js_name = fhePublicExport)]
pub fn fhe_public_export(seed: &[u8], kind: u32) -> Result<Vec<u8>, JsValue> {
    let ck = crate::replication::fhe_tfhe::client_key_for(&seed32(seed)?);
    let limit = crate::replication::fhe_tfhe::MAX_PUBLIC_OBJECT as u64;
    let mut blob = Vec::new();
    let r = match kind {
        0 => safe_serialize(&tfhe::CompressedServerKey::new(&ck), &mut blob, limit),
        1 => safe_serialize(&tfhe::CompactPublicKey::new(&ck), &mut blob, limit),
        _ => return Err(JsValue::from_str("kind must be 0 (server key) or 1 (public key)")),
    };
    r.map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(blob)
}

// ── §6.6 P0A snapshot-recovery KAT ─────────────────────────────────────────
// A worker is disposable; the page owns persistence. These two functions let
// the browser test the whole path with the token's OWN snapshot code
// (`state_snapshot`): build a small fixed token state and snapshot it, then in
// a fresh instance restore it and report what came back. Only fixed test
// values are used; nothing here touches a real token.

const SNAP_KAT_LABEL: &[u8] = b"snap-kat-key";
// Not in constants.rs (the engine never reads CKA_LABEL by id); PKCS#11 §4.4.
const CKA_LABEL: u32 = 0x0000_0003;

fn snap_kat_value() -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(SNAP_KAT_LABEL).to_vec()
}

/// Builds slot 0 (initialized, logged in as User) holding one token object (an
/// AES-256 key with a fixed value) and one session object, then returns
/// `serialize_token_state()`.
#[wasm_bindgen(js_name = snapKatCreate)]
pub fn snap_kat_create() -> Vec<u8> {
    use crate::constants::*;
    use crate::state::{pad_label_32, LoginState, TokenState, NEXT_HANDLE, OBJECTS, TOKEN_STORE};
    use std::sync::atomic::Ordering::Relaxed;
    TOKEN_STORE.with(|ts| {
        let mut s = ts.borrow_mut();
        s.clear();
        s.insert(
            0,
            TokenState {
                slot_id: 0,
                initialized: true,
                label: pad_label_32("snap-kat"),
                login_state: LoginState::User, // must come back as Public
                so_pin_salt: [7u8; 16],
                so_pin_hash: [8u8; 32],
                user_pin_salt: Some([9u8; 16]),
                user_pin_hash: Some([10u8; 32]),
            },
        );
    });
    let mut key = crate::crypto::handlers::Attributes::new();
    key.insert(CKA_CLASS, CKO_SECRET_KEY.to_le_bytes().to_vec());
    key.insert(CKA_KEY_TYPE, CKK_AES.to_le_bytes().to_vec());
    key.insert(CKA_TOKEN, vec![1]);
    key.insert(CKA_LABEL, SNAP_KAT_LABEL.to_vec());
    key.insert(CKA_VALUE, snap_kat_value());
    let mut sess = crate::crypto::handlers::Attributes::new();
    sess.insert(CKA_TOKEN, vec![0]);
    sess.insert(CKA_VALUE, vec![9, 9]);
    OBJECTS.with(|o| {
        let mut o = o.borrow_mut();
        o.clear();
        let hk = NEXT_HANDLE.fetch_add(1, Relaxed);
        let hs = NEXT_HANDLE.fetch_add(1, Relaxed);
        o.insert(hk, key);
        o.insert(hs, sess);
    });
    crate::state_snapshot::serialize_token_state()
}

/// Restores `blob` into this instance and returns
/// `"<key handle>:<sha256(key value)>:<tokens>:<token objects>:<session objects>:<login public>:<next handle > key handle>:<profile objects>"`.
/// Restore re-creates the token's built-in `CKO_PROFILE` objects (Profiles v3.2
/// §3), so they are counted apart from the token objects the snapshot carried.
/// A truncated or corrupt blob is refused with an error.
#[wasm_bindgen(js_name = snapKatRestore)]
pub fn snap_kat_restore(blob: &[u8]) -> Result<String, JsValue> {
    use crate::constants::*;
    use crate::state::{LoginState, NEXT_HANDLE, OBJECTS, TOKEN_STORE};
    use sha2::Digest;
    crate::state_snapshot::deserialize_token_state(blob)
        .map_err(|code| JsValue::from_str(&format!("snapshot refused: CKR 0x{code:08x}")))?;
    let tokens = TOKEN_STORE.with(|ts| ts.borrow().len());
    let public = TOKEN_STORE.with(|ts| {
        ts.borrow().get(&0).map_or(false, |t| matches!(t.login_state, LoginState::Public) && t.initialized)
    });
    let (mut handle, mut sha, mut tok, mut sess, mut prof) = (0u32, String::new(), 0usize, 0usize, 0usize);
    OBJECTS.with(|o| {
        for (h, a) in o.borrow().iter() {
            if a.get(&CKA_CLASS).map_or(false, |v| v == &CKO_PROFILE.to_le_bytes()) {
                prof += 1;
            } else if a.get(&CKA_TOKEN).map_or(false, |v| v == &[1]) {
                tok += 1;
            } else {
                sess += 1;
            }
            if a.get(&CKA_LABEL).map_or(false, |l| l == SNAP_KAT_LABEL) {
                handle = *h;
                sha = hex(&sha2::Sha256::digest(a.get(&CKA_VALUE).cloned().unwrap_or_default()));
            }
        }
    });
    let next_ok = NEXT_HANDLE.load(std::sync::atomic::Ordering::Relaxed) > handle;
    Ok(format!("{handle}:{sha}:{tokens}:{tok}:{sess}:{public}:{next_ok}:{prof}"))
}
