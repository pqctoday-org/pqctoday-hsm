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
