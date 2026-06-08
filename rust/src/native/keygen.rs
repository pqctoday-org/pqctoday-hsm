//! Key generation — typed wrappers around the engine's keygen logic.
//!
//! Each function takes typed args (parameter set as `u32`, `CKA_ID` /
//! label as `&[u8]` / `&str`), constructs the engine-internal
//! `Attributes` map directly via `state::*` helpers, calls the existing
//! typed crypto primitives (`fips204::*` / `fips205::*` / `ml_kem::*`),
//! and returns handle(s). No CK_ATTRIBUTE template marshalling.
//!
//! Implementation mirrors `ffi::C_GenerateKeyPair`'s per-mechanism arm:
//! same attribute defaults (`CKA_CLASS`, `CKA_KEY_TYPE`, etc.), same
//! crypto crate calls, same SPKI builder, same
//! `finalize_private_key_attrs` + `compute_kcv` finalisation. The
//! difference is **how the caller's CKA_ID + CKA_LABEL get in**: the C
//! ABI absorbs them via `absorb_template_attrs(template_ptr, count)`;
//! `native::*` accepts them as typed args and inserts them directly,
//! avoiding the wasm32-only attribute-template ABI.
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.

use std::collections::HashMap;

use super::CkRv;
use crate::constants::*;
use crate::crypto::{ALGO_ML_DSA, ALGO_ML_KEM, ALGO_SLH_DSA};
use crate::crypto::handlers::{
    build_mldsa44_spki, build_mldsa65_spki, build_mldsa87_spki, build_mlkem512_spki,
    build_mlkem768_spki, build_mlkem1024_spki, build_slhdsa_spki, Attributes,
};
use crate::state::{
    allocate_handle, compute_kcv, finalize_private_key_attrs, store_algo_family, store_bool,
    store_param_set, store_ulong,
};

/// `CKA_LABEL` — PKCS#11 v3.2 standard attribute (not in the engine's
/// `constants` module because the engine never reads it; it's
/// caller-supplied bookkeeping). Codepoint per pkcs11t.h.
pub const CKA_LABEL: u32 = 0x0000_0003;

/// `CKA_ID` — PKCS#11 v3.2 standard attribute. Codepoint per pkcs11t.h.
pub const CKA_ID: u32 = 0x0000_0102;

// ── ML-KEM ──────────────────────────────────────────────────────────────────

/// Generate an ML-KEM keypair. `parameter_set` ∈
/// {`CKP_ML_KEM_512`, `CKP_ML_KEM_768`, `CKP_ML_KEM_1024`}. Returns
/// `(public_handle, private_handle)`.
///
/// **Pre-condition**: `session` must be a valid R/W user session
/// (see [`super::session::open_session`]).
pub fn generate_ml_kem_keypair(
    _session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    use ml_kem::{EncodedSizeUser, KemCore};

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    // PKCS#11 v3.2 defaults — mirrors ffi::C_GenerateKeyPair @ ML-KEM arm.
    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_ML_KEM, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_ML_KEM, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN);
    // ML-KEM-specific flags: encapsulate / decapsulate, NOT sign / verify.
    store_bool(&mut pub_attrs, CKA_VERIFY, false);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_SIGN, false);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);

    // Caller bookkeeping.
    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    // Crypto keygen.
    let mut rng = rand::rngs::OsRng;
    match parameter_set {
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
        _ => return Err(CKR_ARGUMENTS_BAD),
    }

    // SPKI — PKCS#11 v3.2 §4.14.
    if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
        let spki = match parameter_set {
            CKP_ML_KEM_512 => build_mlkem512_spki(&pk_bytes),
            CKP_ML_KEM_768 => build_mlkem768_spki(&pk_bytes),
            CKP_ML_KEM_1024 => build_mlkem1024_spki(&pk_bytes),
            _ => Vec::new(),
        };
        if !spki.is_empty() {
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
        }
    }

    finalize_and_register(pub_attrs, prv_attrs)
}

// ── ML-DSA ──────────────────────────────────────────────────────────────────

/// Generate an ML-DSA keypair. `parameter_set` ∈
/// {`CKP_ML_DSA_44`, `CKP_ML_DSA_65`, `CKP_ML_DSA_87`}.
pub fn generate_ml_dsa_keypair(
    _session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_ML_DSA, CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_ML_DSA, CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN);
    // ML-DSA: sign / verify, NOT encapsulate / decapsulate.
    store_bool(&mut pub_attrs, CKA_VERIFY, true);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
    store_bool(&mut prv_attrs, CKA_SIGN, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    let mut rng = rand::rngs::OsRng;
    match parameter_set {
        CKP_ML_DSA_44 => match fips204::ml_dsa_44::try_keygen_with_rng(&mut rng) {
            Ok((vk, sk)) => {
                pub_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(vk).to_vec());
                prv_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(sk).to_vec());
            }
            Err(_) => return Err(CKR_FUNCTION_FAILED),
        },
        CKP_ML_DSA_65 => match fips204::ml_dsa_65::try_keygen_with_rng(&mut rng) {
            Ok((vk, sk)) => {
                pub_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(vk).to_vec());
                prv_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(sk).to_vec());
            }
            Err(_) => return Err(CKR_FUNCTION_FAILED),
        },
        CKP_ML_DSA_87 => match fips204::ml_dsa_87::try_keygen_with_rng(&mut rng) {
            Ok((vk, sk)) => {
                pub_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(vk).to_vec());
                prv_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(sk).to_vec());
            }
            Err(_) => return Err(CKR_FUNCTION_FAILED),
        },
        _ => return Err(CKR_ARGUMENTS_BAD),
    }

    if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
        let spki = match parameter_set {
            CKP_ML_DSA_44 => build_mldsa44_spki(&pk_bytes),
            CKP_ML_DSA_65 => build_mldsa65_spki(&pk_bytes),
            CKP_ML_DSA_87 => build_mldsa87_spki(&pk_bytes),
            _ => Vec::new(),
        };
        if !spki.is_empty() {
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
        }
    }

    finalize_and_register(pub_attrs, prv_attrs)
}

// ── SLH-DSA ─────────────────────────────────────────────────────────────────

/// Generate an SLH-DSA keypair. `parameter_set` ∈
/// {`CKP_SLH_DSA_SHA2_128S`, …, `CKP_SLH_DSA_SHAKE_256F`} — 12 variants.
pub fn generate_slh_dsa_keypair(
    _session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    use fips205::traits::SerDes;

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_SLH_DSA, CKK_SLH_DSA, CKM_SLH_DSA_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_SLH_DSA, CKK_SLH_DSA, CKM_SLH_DSA_KEY_PAIR_GEN);
    store_bool(&mut pub_attrs, CKA_VERIFY, true);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
    store_bool(&mut prv_attrs, CKA_SIGN, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    let mut rng = rand::rngs::OsRng;
    match parameter_set {
        CKP_SLH_DSA_SHA2_128S => slh_keygen!(fips205::slh_dsa_sha2_128s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_128S => slh_keygen!(fips205::slh_dsa_shake_128s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_128F => slh_keygen!(fips205::slh_dsa_sha2_128f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_128F => slh_keygen!(fips205::slh_dsa_shake_128f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_192S => slh_keygen!(fips205::slh_dsa_sha2_192s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_192S => slh_keygen!(fips205::slh_dsa_shake_192s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_192F => slh_keygen!(fips205::slh_dsa_sha2_192f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_192F => slh_keygen!(fips205::slh_dsa_shake_192f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_256S => slh_keygen!(fips205::slh_dsa_sha2_256s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_256S => slh_keygen!(fips205::slh_dsa_shake_256s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_256F => slh_keygen!(fips205::slh_dsa_sha2_256f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_256F => slh_keygen!(fips205::slh_dsa_shake_256f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        _ => return Err(CKR_ARGUMENTS_BAD),
    }

    if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
        let spki = build_slhdsa_spki(parameter_set, &pk_bytes);
        if !spki.is_empty() {
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
        }
    }

    finalize_and_register(pub_attrs, prv_attrs)
}

// ── Classical (deferred to commit 6 per docs/NATIVE_API.md §9) ──────────────

pub fn generate_rsa_keypair(
    _session: u32, _bits: u32, _cka_id: &[u8], _label: &str,
) -> Result<(u32, u32), CkRv> {
    unimplemented!("native::keygen::generate_rsa_keypair — Phase 7b commit 6")
}
pub fn generate_ecdsa_keypair(
    _session: u32, _curve_oid: &[u8], _cka_id: &[u8], _label: &str,
) -> Result<(u32, u32), CkRv> {
    unimplemented!("native::keygen::generate_ecdsa_keypair — Phase 7b commit 6")
}
pub fn generate_aes_key(
    _session: u32, _bits: u32, _cka_id: &[u8], _label: &str,
) -> Result<u32, CkRv> {
    unimplemented!("native::keygen::generate_aes_key — Phase 7b commit 6")
}
pub fn generate_generic_secret(
    _session: u32, _bits: u32, _cka_id: &[u8], _label: &str,
) -> Result<u32, CkRv> {
    unimplemented!("native::keygen::generate_generic_secret — Phase 7b commit 6")
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Shared public-key attribute defaults — matches the
/// `ffi::C_GenerateKeyPair` body for all three PQC families.
fn set_common_pub_attrs(
    attrs: &mut Attributes,
    parameter_set: u32,
    algo_family: u32,
    key_type: u32,
    keygen_mechanism: u32,
) {
    store_param_set(attrs, parameter_set);
    store_algo_family(attrs, algo_family);
    store_ulong(attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(attrs, CKA_KEY_TYPE, key_type);
    store_ulong(attrs, CKA_PARAMETER_SET, parameter_set);
    store_ulong(attrs, CKA_KEY_GEN_MECHANISM, keygen_mechanism);
    store_bool(attrs, CKA_TOKEN, false);
    store_bool(attrs, CKA_PRIVATE, false);
    store_bool(attrs, CKA_ENCRYPT, false);
    store_bool(attrs, CKA_WRAP, false);
    store_bool(attrs, CKA_DERIVE, false);
    store_bool(attrs, CKA_LOCAL, true);
}

fn set_common_prv_attrs(
    attrs: &mut Attributes,
    parameter_set: u32,
    algo_family: u32,
    key_type: u32,
    keygen_mechanism: u32,
) {
    store_param_set(attrs, parameter_set);
    store_algo_family(attrs, algo_family);
    store_ulong(attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(attrs, CKA_KEY_TYPE, key_type);
    store_ulong(attrs, CKA_PARAMETER_SET, parameter_set);
    store_ulong(attrs, CKA_KEY_GEN_MECHANISM, keygen_mechanism);
    store_bool(attrs, CKA_TOKEN, false);
    store_bool(attrs, CKA_PRIVATE, true);
    store_bool(attrs, CKA_SENSITIVE, true);
    store_bool(attrs, CKA_EXTRACTABLE, false);
    store_bool(attrs, CKA_DECRYPT, false);
    store_bool(attrs, CKA_UNWRAP, false);
    store_bool(attrs, CKA_DERIVE, false);
    store_bool(attrs, CKA_LOCAL, true);
}

fn insert_id_and_label(attrs: &mut Attributes, cka_id: &[u8], label: &str) {
    if !cka_id.is_empty() {
        attrs.insert(CKA_ID, cka_id.to_vec());
    }
    if !label.is_empty() {
        attrs.insert(CKA_LABEL, label.as_bytes().to_vec());
    }
}

/// Finalise attribute maps (private-key flags + KCV) and allocate
/// engine object handles. Mirrors the tail of each `ffi::C_GenerateKeyPair`
/// arm.
fn finalize_and_register(
    mut pub_attrs: Attributes,
    mut prv_attrs: Attributes,
) -> Result<(u32, u32), CkRv> {
    finalize_private_key_attrs(&mut prv_attrs);
    compute_kcv(&mut pub_attrs);
    compute_kcv(&mut prv_attrs);
    let pub_h = allocate_handle(pub_attrs);
    let prv_h = allocate_handle(prv_attrs);
    Ok((pub_h, prv_h))
}

/// SLH-DSA keygen — wraps the `fips205::*::try_keygen_with_rng` calls
/// with the same shape so the per-variant match stays a single line.
/// `$func` is the fully-qualified keygen path; `$rng` is `OsRng`;
/// `$pub_attrs` / `$prv_attrs` are the maps to populate with `CKA_VALUE`.
macro_rules! slh_keygen {
    ($func:path, $rng:ident, $pub_attrs:expr, $prv_attrs:expr) => {{
        match $func(&mut $rng) {
            Ok((vk, sk)) => {
                $pub_attrs.insert(CKA_VALUE, vk.into_bytes().to_vec());
                $prv_attrs.insert(CKA_VALUE, sk.into_bytes().to_vec());
            }
            Err(_) => return Err(CKR_FUNCTION_FAILED),
        }
    }};
}
use slh_keygen;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
    use crate::state::get_object_value;
    use crate::native::test_lock;

    fn fresh_session() -> u32 {
        let _ = finalize();
        init().unwrap();
        bootstrap_default_token(0, "so", "user", "pqctoday-test").unwrap()
    }

    /// ML-KEM-768 keygen produces a valid keypair. FIPS 203 §7.4 — the
    /// encapsulation key is 1184 bytes.
    #[test]
    fn ml_kem_768_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01\x02\x03", "kem-test").unwrap();
        assert!(pub_h > 0 && prv_h > 0 && pub_h != prv_h);

        let pub_value = get_object_value(pub_h).expect("public key CKA_VALUE");
        assert_eq!(pub_value.len(), 1184, "FIPS 203 §7.4 ML-KEM-768 ek = 1184 bytes");
        let prv_value = get_object_value(prv_h).expect("private key CKA_VALUE");
        assert_eq!(prv_value.len(), 2400, "FIPS 203 §7.4 ML-KEM-768 dk = 2400 bytes");

        close_session(session).unwrap();
    }

    /// ML-KEM-1024: FIPS 203 §7.4 — ek = 1568 bytes, dk = 3168 bytes.
    #[test]
    fn ml_kem_1024_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_1024, b"\x01", "kem1024").unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 1568);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 3168);
        close_session(session).unwrap();
    }

    /// ML-DSA-65: FIPS 204 §5 — verification key = 1952 bytes,
    /// signing key = 4032 bytes.
    #[test]
    fn ml_dsa_65_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\xaa\xbb", "sig-test").unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 1952, "FIPS 204 §5 ML-DSA-65 vk");
        assert_eq!(get_object_value(prv_h).unwrap().len(), 4032, "FIPS 204 §5 ML-DSA-65 sk");
        close_session(session).unwrap();
    }

    /// ML-DSA-87: FIPS 204 §5 — vk = 2592, sk = 4896.
    #[test]
    fn ml_dsa_87_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_87, b"\x01", "ml-dsa-87").unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 2592);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 4896);
        close_session(session).unwrap();
    }

    /// SLH-DSA-SHA2-128F: FIPS 205 §10 — pk = 32, sk = 64 bytes.
    #[test]
    fn slh_dsa_sha2_128f_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_slh_dsa_keypair(
            session,
            CKP_SLH_DSA_SHA2_128F,
            b"\x01",
            "slh-test",
        )
        .unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 32, "FIPS 205 §10 SLH-DSA-128 pk");
        assert_eq!(get_object_value(prv_h).unwrap().len(), 64, "FIPS 205 §10 SLH-DSA-128 sk");
        close_session(session).unwrap();
    }

    /// SLH-DSA-SHA2-256S: pk = 64, sk = 128 bytes.
    #[test]
    fn slh_dsa_sha2_256s_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_slh_dsa_keypair(
            session,
            CKP_SLH_DSA_SHA2_256S,
            b"\x02",
            "slh-256",
        )
        .unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 64);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 128);
        close_session(session).unwrap();
    }

    /// Bad parameter set → CKR_ARGUMENTS_BAD.
    #[test]
    fn ml_kem_invalid_parameter_set_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let result = generate_ml_kem_keypair(session, 0xDEADBEEF, b"\x01", "x");
        assert!(matches!(result, Err(CKR_ARGUMENTS_BAD)));
        close_session(session).unwrap();
    }

    /// CKA_ID + CKA_LABEL are stored and retrievable.
    #[test]
    fn caller_supplied_id_and_label_are_stored() {
        use crate::state::get_object_attr_bytes;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let cka_id = b"unique-key-id-12345";
        let label = "my-ml-dsa-key";
        let (pub_h, _) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, cka_id, label).unwrap();

        let stored_id = get_object_attr_bytes(pub_h, CKA_ID).expect("CKA_ID stored");
        assert_eq!(stored_id, cka_id);
        let stored_label = get_object_attr_bytes(pub_h, CKA_LABEL).expect("CKA_LABEL stored");
        assert_eq!(stored_label, label.as_bytes());

        close_session(session).unwrap();
    }
}
