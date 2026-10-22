// SPDX-License-Identifier: AGPL-3.0-only
//
//! Composite keys on the typed native surface — PKCS#11 v3.3 working draft
//! (`working/doc/spec/comp_kem.md`, `comp_sig.md`, OASIS PKCS 11 TC commit
//! 9ef73f9). The engine still reports Cryptoki 3.2.0 (root `CLAUDE.md`).
//!
//! The FFI arms of `C_GenerateKeyPair`, `C_CreateObject`, `C_Sign`,
//! `C_Verify`, `C_EncapsulateKey` and `C_DecapsulateKey` already implement
//! `CKM_COMP_KEM_KEY_PAIR_GEN`, `CKM_COMP_KEM`, `CKM_COMP_SIG_KEY_PAIR_GEN`,
//! `CKM_COMP_SIG` and `CKM_COMP_SIG_EXTERNAL_HASH`. `ffi` is not built for
//! `wasm32-unknown-unknown`, and the KMIP server drives the engine through
//! `native::*` on every target, so this module is the same behaviour for
//! typed callers: one object per composite key (never two component
//! handles), the per-set facts from `native::composite`, the key layout and
//! import checks from `native::composite_key`, the operations from
//! `native::composite_kem` / `native::composite_sig`.
//!
//! Every operation runs through the native isolation gate
//! (`state::with_object_checked`), checks the key's usage flag, its
//! `CKA_ALLOWED_MECHANISMS`, its class and key type, and that its parameter
//! set is one this engine supports. Private key bytes are copied out of the
//! object store into `Zeroizing` buffers and never returned; a KEM shared
//! secret leaves only as a new key object (`*_to_handle` in
//! `native::encrypt`).
//!
//! `native::sign_pqc` / `verify_pqc` / `sign` / `verify` and
//! `native::encapsulate` / `decapsulate` route the composite mechanisms
//! here, so a native caller uses composites exactly as it uses ML-DSA and
//! ML-KEM.

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::composite::{
    kem_params, sig_params, CompositeFamily, CompositeKemParams, CompositeSigParams,
};
use super::composite_key;
use super::keygen::{alloc_in_session_slot, insert_id_and_label};
use super::CkRv;
use crate::constants::*;
use crate::crypto::handlers::Attributes;
use crate::state::{
    check_mechanism_allowed_from, compute_kcv, finalize_private_key_attrs,
    get_object_attr_u32_from, get_object_value_from, read_bool_attr, resolve_session_access,
    store_bool, store_ulong, with_object_checked,
};

/// `true` for the three composite-signature and composite-KEM operation
/// mechanisms this module serves.
pub fn is_composite_mechanism(mechanism: u32) -> bool {
    matches!(mechanism, CKM_COMP_SIG | CKM_COMP_SIG_EXTERNAL_HASH | CKM_COMP_KEM)
}

/// The key-pair generation mechanism of a composite key type
/// (comp_kem.md / comp_sig.md "key pair generation").
fn keygen_mechanism(family: CompositeFamily) -> u32 {
    match family {
        CompositeFamily::Kem => CKM_COMP_KEM_KEY_PAIR_GEN,
        CompositeFamily::Sig => CKM_COMP_SIG_KEY_PAIR_GEN,
    }
}

/// Generate a composite key pair: one `CKK_COMP_KEM` / `CKK_COMP_SIG`
/// public object and one private object, both carrying `cka_id` and
/// `label`. The same attributes as `ffi::C_GenerateKeyPair`'s
/// CKM_COMP_KEM_KEY_PAIR_GEN / CKM_COMP_SIG_KEY_PAIR_GEN arm with empty
/// templates: CKA_VALUE `mlPK ‖ tradPK` / `mlSeed ‖ tradSK`, the composite
/// SPKI as CKA_PUBLIC_KEY_INFO on both, a sensitive and non-extractable
/// private key.
///
/// `key_type` is `CKK_COMP_KEM` or `CKK_COMP_SIG` (anything else is
/// `CKR_KEY_TYPE_INCONSISTENT`), `ckp` its `CKP_COMP_*` value. An unknown
/// set or a set this token does not support (the brainpool sets until the
/// engine has those curves) is `CKR_PARAMETER_SET_NOT_SUPPORTED`, as in the
/// FFI arm. Returns `(public_handle, private_handle)`.
pub fn generate_keypair(
    session: u32,
    key_type: u32,
    ckp: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    let family = CompositeFamily::from_key_type(key_type).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let mechanism = keygen_mechanism(family);
    let logging = crate::oplog::enabled();
    let ring = crate::behaviour::enabled();
    let t0 = (logging || ring).then(std::time::Instant::now);
    let result = generate_keypair_inner(session, key_type, ckp, mechanism, cka_id, label);
    if logging || ring {
        let dur = crate::behaviour::elapsed_us(t0);
        super::keygen::emit_generate_key_pair(session, mechanism, ckp, &result, dur, logging, ring);
    }
    result
}

fn generate_keypair_inner(
    session: u32,
    key_type: u32,
    ckp: u32,
    mechanism: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    resolve_session_access(session)?;
    let layout = composite_key::supported_layout(key_type, ckp, CKR_PARAMETER_SET_NOT_SUPPORTED)?;
    let (pk, sk) = composite_key::generate(&layout)?;
    let (mut pub_attrs, mut prv_attrs) = composite_key::key_pair_attrs(&layout, pk, sk, mechanism);
    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);
    finalize_private_key_attrs(&mut prv_attrs);
    compute_kcv(&mut pub_attrs);
    compute_kcv(&mut prv_attrs);
    let pub_h = alloc_in_session_slot(session, pub_attrs);
    let prv_h = alloc_in_session_slot(session, prv_attrs);
    Ok((pub_h, prv_h))
}

/// Import an existing composite key: `class` is `CKO_PUBLIC_KEY` (`value`
/// = `mlPK ‖ tradPK`) or `CKO_PRIVATE_KEY` (`value` = `mlSeed ‖ tradSK`).
/// The value goes through the same `C_CreateObject` check as the FFI
/// (`composite_key::check_imported_key`: both halves derived or validated,
/// the composite SPKI stored as CKA_PUBLIC_KEY_INFO, an ECPrivateKey carrying
/// its publicKey field normalised). Imported provenance per PKCS#11 v3.2
/// §4.3/§4.9/§4.10, as `keygen::register_ml_dsa_private_key`: CKA_LOCAL
/// false, no key-generation mechanism, never "always sensitive" or "never
/// extractable"; a private key stays sensitive.
#[allow(clippy::too_many_arguments)]
pub fn register_key(
    session: u32,
    class: u32,
    key_type: u32,
    ckp: u32,
    value: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    resolve_session_access(session)?;
    let family = CompositeFamily::from_key_type(key_type).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let kem = family == CompositeFamily::Kem;
    let private = match class {
        CKO_PRIVATE_KEY => true,
        CKO_PUBLIC_KEY => false,
        _ => return Err(CKR_TEMPLATE_INCONSISTENT),
    };
    let mut attrs: Attributes = HashMap::new();
    store_ulong(&mut attrs, CKA_CLASS, class);
    store_ulong(&mut attrs, CKA_KEY_TYPE, key_type);
    store_ulong(&mut attrs, CKA_PARAMETER_SET, ckp);
    crate::state::store_param_set(&mut attrs, ckp);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_DERIVE, false);
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    if private {
        store_bool(&mut attrs, CKA_PRIVATE, true);
        store_bool(&mut attrs, CKA_SENSITIVE, true);
        store_bool(&mut attrs, CKA_EXTRACTABLE, false);
        store_bool(&mut attrs, CKA_DECRYPT, false);
        store_bool(&mut attrs, CKA_UNWRAP, false);
        store_bool(&mut attrs, CKA_SIGN, !kem);
        store_bool(&mut attrs, CKA_DECAPSULATE, kem);
    } else {
        store_bool(&mut attrs, CKA_PRIVATE, false);
        store_bool(&mut attrs, CKA_ENCRYPT, false);
        store_bool(&mut attrs, CKA_WRAP, false);
        store_bool(&mut attrs, CKA_VERIFY, !kem);
        store_bool(&mut attrs, CKA_ENCAPSULATE, kem);
    }
    attrs.insert(CKA_VALUE, value.to_vec());
    insert_id_and_label(&mut attrs, cka_id, label);
    if let Err(rv) = composite_key::check_imported_key(Some(class), &mut attrs) {
        // The refused value never reaches the object store; wipe our copy.
        if let Some(v) = attrs.get_mut(&CKA_VALUE) {
            zeroize::Zeroize::zeroize(v);
        }
        return Err(rv);
    }
    if private {
        finalize_private_key_attrs(&mut attrs);
        // Imported: never generated in this token (§4.9/§4.10).
        store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
        store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);
    }
    compute_kcv(&mut attrs);
    Ok(alloc_in_session_slot(session, attrs))
}

/// What one composite operation reads from its key object, under one
/// isolation-gated borrow.
struct KeyView {
    usable: bool,
    mech_ok: Result<(), CkRv>,
    class: Option<u32>,
    key_type: Option<u32>,
    ckp: Option<u32>,
    value: Option<Zeroizing<Vec<u8>>>,
}

fn read_key(session: u32, handle: u32, usage: u32, mechanism: u32) -> Result<KeyView, CkRv> {
    let access = resolve_session_access(session)?;
    with_object_checked(&access, handle, |attrs| KeyView {
        usable: read_bool_attr(attrs, usage),
        mech_ok: check_mechanism_allowed_from(attrs, mechanism),
        class: get_object_attr_u32_from(attrs, CKA_CLASS),
        key_type: get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
        ckp: get_object_attr_u32_from(attrs, CKA_PARAMETER_SET),
        value: get_object_value_from(attrs).map(Zeroizing::new),
    })
}

/// The composite-signature set of a key used under `CKM_COMP_SIG` /
/// `CKM_COMP_SIG_EXTERNAL_HASH`, with the FFI's codes (`ffi::comp_sig_key_params`):
/// usage flag false → `CKR_KEY_FUNCTION_NOT_PERMITTED`; mechanism outside
/// CKA_ALLOWED_MECHANISMS → its code; not a `CKK_COMP_SIG` object of the
/// right class, or no supported CKA_PARAMETER_SET → `CKR_KEY_TYPE_INCONSISTENT`.
fn sig_key(
    session: u32,
    handle: u32,
    mechanism: u32,
    sign: bool,
) -> Result<(&'static CompositeSigParams, Zeroizing<Vec<u8>>), CkRv> {
    let (usage, class) = if sign { (CKA_SIGN, CKO_PRIVATE_KEY) } else { (CKA_VERIFY, CKO_PUBLIC_KEY) };
    let k = read_key(session, handle, usage, mechanism)?;
    if !k.usable {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    k.mech_ok?;
    if k.key_type != Some(CKK_COMP_SIG) || k.class != Some(class) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let p = k.ckp.and_then(sig_params).filter(|p| p.supported).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    Ok((p, k.value.ok_or(CKR_KEY_TYPE_INCONSISTENT)?))
}

/// The composite-KEM set of a key used under `CKM_COMP_KEM`, with the FFI's
/// codes (`ffi::comp_kem_key_params`): a key without CKA_PARAMETER_SET is
/// `CKR_TEMPLATE_INCOMPLETE`, an unsupported set
/// `CKR_PARAMETER_SET_NOT_SUPPORTED`.
fn kem_key(
    session: u32,
    handle: u32,
    decapsulate: bool,
) -> Result<(&'static CompositeKemParams, Zeroizing<Vec<u8>>), CkRv> {
    let (usage, class) =
        if decapsulate { (CKA_DECAPSULATE, CKO_PRIVATE_KEY) } else { (CKA_ENCAPSULATE, CKO_PUBLIC_KEY) };
    let k = read_key(session, handle, usage, CKM_COMP_KEM)?;
    if !k.usable {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    k.mech_ok?;
    if k.key_type != Some(CKK_COMP_KEM) || k.class != Some(class) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let p = kem_params(k.ckp.ok_or(CKR_TEMPLATE_INCOMPLETE)?).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    if !p.supported {
        return Err(CKR_PARAMETER_SET_NOT_SUPPORTED);
    }
    Ok((p, k.value.ok_or(CKR_KEY_TYPE_INCONSISTENT)?))
}

/// `C_Sign` with `CKM_COMP_SIG` (`data` = M) or `CKM_COMP_SIG_EXTERNAL_HASH`
/// (`data` = PH(M), whose length `composite_sig` checks). `ctx` is the
/// `CK_SIGN_ADDITIONAL_CONTEXT` context (at most 255 bytes, else
/// `CKR_MECHANISM_PARAM_INVALID`); `deterministic` is
/// `CKH_DETERMINISTIC_REQUIRED`, refused with `CKR_MECHANISM_PARAM_INVALID`
/// for a set that cannot sign deterministically
/// (`composite_sig::deterministic_available`).
pub fn sign(
    session: u32,
    handle: u32,
    mechanism: u32,
    data: &[u8],
    ctx: &[u8],
    deterministic: bool,
) -> Result<Vec<u8>, CkRv> {
    if mechanism != CKM_COMP_SIG && mechanism != CKM_COMP_SIG_EXTERNAL_HASH {
        return Err(CKR_MECHANISM_INVALID);
    }
    let (p, sk) = sig_key(session, handle, mechanism, true)?;
    if mechanism == CKM_COMP_SIG {
        super::composite_sig::sign(p, &sk, data, ctx, deterministic)
    } else {
        super::composite_sig::sign_ph(p, &sk, data, ctx, deterministic)
    }
}

/// `C_Verify` with `CKM_COMP_SIG` / `CKM_COMP_SIG_EXTERNAL_HASH`. `Ok(())`
/// for a valid signature, `CKR_SIGNATURE_INVALID` /
/// `CKR_SIGNATURE_LEN_RANGE` otherwise (`composite_sig::verify_ph`).
pub fn verify(
    session: u32,
    handle: u32,
    mechanism: u32,
    data: &[u8],
    signature: &[u8],
    ctx: &[u8],
) -> Result<(), CkRv> {
    if mechanism != CKM_COMP_SIG && mechanism != CKM_COMP_SIG_EXTERNAL_HASH {
        return Err(CKR_MECHANISM_INVALID);
    }
    let (p, pk) = sig_key(session, handle, mechanism, false)?;
    if mechanism == CKM_COMP_SIG {
        super::composite_sig::verify(p, &pk, data, ctx, signature)
    } else {
        super::composite_sig::verify_ph(p, &pk, data, ctx, signature)
    }
}

/// `C_EncapsulateKey` with `CKM_COMP_KEM` → `(ct, ss)`, `ct = mlkemCT ‖
/// tradCT`, `ss` the 32-byte §3.4 combiner output. The secret is in a
/// `Zeroizing` buffer; `native::encapsulate_to_handle` registers it as a key
/// object without it leaving the crate.
pub fn encapsulate(session: u32, public_key_handle: u32) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CkRv> {
    let (p, pk) = kem_key(session, public_key_handle, false)?;
    super::composite_kem::encapsulate(session, p, &pk)
}

/// `C_DecapsulateKey` with `CKM_COMP_KEM` → the 32-byte §3.4 secret
/// (`composite_kem::decapsulate` for the failure semantics).
pub fn decapsulate(session: u32, private_key_handle: u32, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CkRv> {
    let (p, sk) = kem_key(session, private_key_handle, true)?;
    super::composite_kem::decapsulate(session, p, &sk, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::composite::{COMPOSITE_KEM_SETS, COMPOSITE_SIG_SETS};
    use crate::native::session::{bootstrap_default_token, finalize, init};
    use crate::native::test_lock;

    fn fresh_session() -> u32 {
        let _ = finalize();
        init().unwrap();
        bootstrap_default_token(0, "so", "user", "native-composite-test").unwrap()
    }

    /// Every supported set generates, signs/verifies or encapsulates/
    /// decapsulates through the typed surface, and the routed generic entry
    /// points (`native::sign_pqc`, `native::encapsulate_to_handle`, …) reach
    /// the same code. Unsupported (brainpool) sets are refused at keygen with
    /// the FFI's code.
    #[test]
    fn every_supported_set_round_trips_through_the_native_surface() {
        let _g = test_lock::acquire();
        let s = fresh_session();
        for p in COMPOSITE_SIG_SETS.iter() {
            let r = generate_keypair(s, CKK_COMP_SIG, p.ckp, b"cs", "cs");
            if !p.supported {
                assert_eq!(r, Err(CKR_PARAMETER_SET_NOT_SUPPORTED), "{}", p.name);
                continue;
            }
            let (hp, hk) = r.unwrap();
            let msg = b"composite native round trip";
            let sig = super::super::sign::sign_pqc(s, hk, CKM_COMP_SIG, msg, b"ctx", false, false, false, None)
                .unwrap_or_else(|e| panic!("{}: sign {e:#x}", p.name));
            assert!(p.signature_size().admits(sig.len()), "{}", p.name);
            super::super::sign::verify_pqc(s, hp, CKM_COMP_SIG, msg, &sig, b"ctx", false, false)
                .unwrap_or_else(|e| panic!("{}: verify {e:#x}", p.name));
            assert_eq!(
                super::super::sign::verify_pqc(s, hp, CKM_COMP_SIG, msg, &sig, b"ctX", false, false),
                Err(CKR_SIGNATURE_INVALID),
                "{}: another context",
                p.name
            );
            // `native::sign` / `verify` (no context) reach the same mechanism.
            let sig = super::super::sign::sign(s, hk, CKM_COMP_SIG, msg).unwrap();
            assert_eq!(super::super::sign::verify(s, hp, CKM_COMP_SIG, msg, &sig), Ok(true), "{}", p.name);
            // The public key is no signing key, nor the private one a verifier.
            assert_eq!(sign(s, hp, CKM_COMP_SIG, msg, &[], false), Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
            assert_eq!(verify(s, hk, CKM_COMP_SIG, msg, &sig, &[]), Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
            // The routed internal/external-µ interfaces do not exist for composites.
            assert_eq!(
                super::super::sign::sign_pqc(s, hk, CKM_COMP_SIG, msg, &[], false, true, false, None),
                Err(CKR_MECHANISM_PARAM_INVALID),
                "{}",
                p.name
            );
        }
        for p in COMPOSITE_KEM_SETS.iter() {
            let r = generate_keypair(s, CKK_COMP_KEM, p.ckp, b"ck", "ck");
            if !p.supported {
                assert_eq!(r, Err(CKR_PARAMETER_SET_NOT_SUPPORTED), "{}", p.name);
                continue;
            }
            let (hp, hk) = r.unwrap();
            let (ct, ss) = encapsulate(s, hp).unwrap_or_else(|e| panic!("{}: encaps {e:#x}", p.name));
            assert_eq!(ct.len(), p.ciphertext_size().bytes(), "{}", p.name);
            assert_eq!(decapsulate(s, hk, &ct).unwrap().as_slice(), ss.as_slice(), "{}", p.name);
            let (ct2, h_enc) =
                super::super::encrypt::encapsulate_to_handle(s, hp, CKM_COMP_KEM, b"ss", "ss", true, false).unwrap();
            let h_dec =
                super::super::encrypt::decapsulate_to_handle(s, hk, CKM_COMP_KEM, &ct2, b"ss", "ss", true, false)
                    .unwrap();
            let v = |h| super::super::object::get_attribute(s, h, CKA_VALUE).unwrap();
            assert_eq!(v(h_enc), v(h_dec), "{}", p.name);
            assert_eq!(v(h_enc).len(), 32, "{}", p.name);
            // Plain CKM_ML_KEM refuses the composite key.
            assert_eq!(
                super::super::encrypt::decapsulate(s, hk, CKM_ML_KEM, &ct),
                Err(CKR_KEY_TYPE_INCONSISTENT),
                "{}",
                p.name
            );
        }
    }

    /// Import is the FFI's `C_CreateObject` check: the private value
    /// re-derives the public key, a public value of the wrong length is
    /// refused, and the imported key works.
    #[test]
    fn register_key_checks_and_imports() {
        let _g = test_lock::acquire();
        let s = fresh_session();
        let p = COMPOSITE_KEM_SETS.iter().find(|p| p.supported).unwrap();
        let layout = composite_key::supported_layout(CKK_COMP_KEM, p.ckp, CKR_ATTRIBUTE_VALUE_INVALID).unwrap();
        let (pk, sk) = composite_key::generate(&layout).unwrap();
        let hk = register_key(s, CKO_PRIVATE_KEY, CKK_COMP_KEM, p.ckp, &sk, b"i", "i").unwrap();
        let hp = register_key(s, CKO_PUBLIC_KEY, CKK_COMP_KEM, p.ckp, &pk, b"i", "i").unwrap();
        let (ct, ss) = encapsulate(s, hp).unwrap();
        assert_eq!(decapsulate(s, hk, &ct).unwrap().as_slice(), ss.as_slice());
        assert_eq!(
            super::super::object::get_attribute(s, hp, CKA_PUBLIC_KEY_INFO),
            Some(composite_key::spki(p.oid, &pk))
        );
        assert_eq!(
            register_key(s, CKO_PUBLIC_KEY, CKK_COMP_KEM, p.ckp, &pk[..pk.len() - 1], b"i", "i"),
            Err(CKR_ATTRIBUTE_VALUE_INVALID)
        );
        assert_eq!(register_key(s, CKO_PUBLIC_KEY, CKK_ML_KEM, p.ckp, &pk, b"i", "i"), Err(CKR_KEY_TYPE_INCONSISTENT));
    }
}
