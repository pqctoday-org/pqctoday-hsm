//! Shared helpers used by every Plane-2 op handler. Lives outside any
//! one op file so all 12 handlers can share the audit-emission +
//! algorithm-string boilerplate without duplication.

use time::OffsetDateTime;

use crate::auditlog::{AuditEvent, EventPayload, KmipOpResult, Plane};
use crate::error::KmipError;
use crate::kmip30::KmipAlgorithm;

use super::deps::Deps;

/// Emit a `KmipResponseSent { OperationFailed }` audit event and return
/// the error unchanged. Every handler's error path goes through this so
/// the Hub UI always sees a paired Request/Response pair per
/// `correlation_id`.
pub fn fail_err(deps: &Deps, correlation_id: &str, op: &str, err: KmipError) -> KmipError {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: op.into(),
            result: KmipOpResult::OperationFailed {
                reason: format!("{:?}", err.result_reason()),
            },
            latency_ms: 0,
        },
    ));
    err
}

/// Emit a `KmipResponseSent { Success }` audit event.
pub fn emit_success(deps: &Deps, correlation_id: &str, op: &str) {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: op.into(),
            result: KmipOpResult::Success,
            latency_ms: 0,
        },
    ));
}

/// Emit a `KmipRequestReceived` audit event.
pub fn emit_request(deps: &Deps, correlation_id: &str, op: &str, summary: String) {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipRequestReceived {
            op: op.into(),
            request_summary: summary,
            client_cn: None,
        },
    ));
}

/// Emit a `Pkcs11Call` audit event. Phase 7 wires the actual softhsmrustv3
/// call alongside this emission; v0.1 just records the intent.
pub fn emit_pkcs11(
    deps: &Deps,
    correlation_id: &str,
    function: &str,
    mech: Option<u32>,
    rv: u32,
    rv_name: &str,
) {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Pkcs11,
        correlation_id,
        EventPayload::Pkcs11Call {
            function: function.into(),
            mechanism: mech.map(|m| format!("CKM_0x{m:04X}")),
            slot: Some(deps.config.pkcs11_slot),
            session: None,
            rv,
            rv_name: rv_name.into(),
            latency_ms: 0,
        },
    ));
}

/// Emit a `KmipObjectStateChanged` audit event (KMIP 3.0 §3.x lifecycle).
pub fn emit_state_change(
    deps: &Deps,
    correlation_id: &str,
    uid: &str,
    from: &str,
    to: &str,
    reason: &str,
) {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipObjectStateChanged {
            uid: uid.into(),
            from_state: from.into(),
            to_state: to.into(),
            reason: reason.into(),
        },
    ));
}

/// Canonical algorithm string used by the policy engine. Mirrors the
/// `KmipAlgorithm` enum variant names that appear in `policies/*.yaml`.
///
/// **Known v0.1 limitation:** classical algos return bare names
/// (`"ECDSA"`, `"RSA"`, `"AES"`) — no curve/size suffix. Phase 6's store
/// will add the `Cryptographic Parameters` attribute so the dispatcher
/// can produce `"ECDSA-P256"` / `"RSA-3072"` / `"AES-256"` from stored
/// metadata.
pub fn canonical_name(a: KmipAlgorithm) -> String {
    use KmipAlgorithm::*;
    match a {
        Aes => "AES",
        Rsa => "RSA",
        Ecdsa => "ECDSA",
        HmacSha256 => "HMAC-SHA-256",
        HmacSha384 => "HMAC-SHA-384",
        HmacSha512 => "HMAC-SHA-512",
        Ecdh => "ECDH",
        ChaCha20 => "ChaCha20",
        ChaCha20Poly1305 => "ChaCha20-Poly1305",
        MlKem512 => "ML-KEM-512",
        MlKem768 => "ML-KEM-768",
        MlKem1024 => "ML-KEM-1024",
        MlDsa44 => "ML-DSA-44",
        MlDsa65 => "ML-DSA-65",
        MlDsa87 => "ML-DSA-87",
        SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
        SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
        SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
        SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
        SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
        SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
        SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
        SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
        SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
        SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
        SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
    }
    .into()
}

/// State name string for the engine's `state` field — mirrors KMIP 3.0
/// `State` enum names verbatim.
/// Map a non-`Active` state to the spec-correct `ResultReason` for a
/// cryptographic op that requires `Active` (KMIP 3.0 §11 Result Reason):
///
/// - `Destroyed` / `DestroyedCompromised` → `ObjectArchived` (0x0d)
///   per Spec §6.1.19 — the object's material is gone.
/// - `Deactivated` / `Compromised` → `WrongKeyLifecycleState` (0x43)
///   per Spec §6.1.49 (Revoke) — the object exists but the FSM
///   forbids the requested op.
/// - `PreActive` → `WrongKeyLifecycleState` (0x43) — same family
///   (key isn't ready yet).
///
/// `Active` MUST NOT be passed; the helper returns
/// `WrongKeyLifecycleState` so a bug doesn't masquerade as a
/// successful response.
/// Pick the PKCS#11 mechanism for AES Encrypt / Decrypt off the key's
/// stored `BlockCipherMode`. KMIP 3.0 §11 `Block Cipher Mode` enum:
/// `CBC=1, ECB=2, PCBC=3, CFB=4, OFB=5, CTR=6, CMAC=7, CCM=8,
/// GCM=9, NIST_KEY_WRAP=10, ...`. Falls back to GCM (the only mode
/// our shim handled before) when the key carries no params.
pub fn aes_mechanism_for(
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> u32 {
    use softhsmrustv3::constants::{CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_ECB, CKM_AES_GCM};
    let bcm = cp.and_then(|c| c.block_cipher_mode);
    // KMIP 3.0 §11 `Padding Method` enum — codepoint 3 = `PKCS5`
    // (synonym for PKCS#7 for AES). With BlockCipherMode=CBC this
    // selects `CKM_AES_CBC_PAD`, which permits arbitrary-length
    // plaintext (the shim's CBC_PAD path adds PKCS#7 padding).
    let pad = cp.and_then(|c| c.padding_method);
    match (bcm, pad) {
        (Some(1), Some(3)) => CKM_AES_CBC_PAD,
        (Some(1), _) => CKM_AES_CBC,
        (Some(2), _) => CKM_AES_ECB,
        (Some(9), _) | (None, _) => CKM_AES_GCM,
        // Unimplemented modes (PCBC / CFB / OFB / CTR / wrap) fall
        // through to GCM which the shim already supports; callers can
        // upgrade `aes_mechanism_for` as the shim grows.
        _ => CKM_AES_GCM,
    }
}

/// Map a KMIP `CryptographicParameters` onto the shim's
/// [`softhsmrustv3::native::OaepParams`]. Returns `None` when the key
/// carries no params (callers should treat that as "use shim default
/// = SHA-256 / MGF1-SHA-256 / no label").
pub fn oaep_params_for(
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> Option<softhsmrustv3::native::OaepParams<'_>> {
    use crate::kmip30::HashingAlgorithm;
    use softhsmrustv3::native::OaepHash;
    let cp = cp?;
    let map_hash = |h: HashingAlgorithm| -> Option<OaepHash> {
        match h {
            HashingAlgorithm::Sha256 => Some(OaepHash::Sha256),
            HashingAlgorithm::Sha384 => Some(OaepHash::Sha384),
            HashingAlgorithm::Sha512 => Some(OaepHash::Sha512),
            _ => None,
        }
    };
    Some(softhsmrustv3::native::OaepParams {
        hash: cp.hashing_algorithm.and_then(map_hash),
        mgf_hash: cp.mask_generator_hashing_algorithm.and_then(map_hash),
        label: cp.p_source.as_deref(),
    })
}

/// All §3.x lifecycle-FSM rejections surface as
/// `WrongKeyLifecycleState` (0x43): the object exists, the request
/// is well-formed, but the FSM forbids the op given the current
/// state (PreActive / Deactivated / Compromised / Destroyed /
/// DestroyedCompromised).
///
/// `ObjectArchived` (0x0d) is **not** used here — per KMIP 3.0 §11
/// it's reserved for objects moved off-line by the `Archive` op
/// (§6.1.5) and needing `Recover` before use. OASIS CS-AC-M-8 pins
/// `WrongKeyLifecycleState` for `Sign` against a `Destroyed` key,
/// confirming the interpretation.
pub fn non_active_state_error(uid: &str, state: crate::kmip30::State) -> KmipError {
    KmipError::wrong_key_lifecycle_state(uid, state_name(state))
}

pub fn state_name(s: crate::kmip30::State) -> &'static str {
    use crate::kmip30::State::*;
    match s {
        PreActive => "PreActive",
        Active => "Active",
        Deactivated => "Deactivated",
        Compromised => "Compromised",
        Destroyed => "Destroyed",
        DestroyedCompromised => "DestroyedCompromised",
    }
}

// ── Phase 7b: KMIP ↔ softhsmrustv3 native API mapping ──────────────────────
//
// The Plane-3 sections of each op handler use these helpers to translate
// from KMIP types (`KmipAlgorithm`) to the engine's standard `CKM_*` /
// `CKP_*` codepoints that `softhsmrustv3::native::*` consumes.

/// Map a `KmipAlgorithm` to the engine's **standard PKCS#11 v3.2** sign
/// mechanism — what `softhsmrustv3::native::sign` / `verify` dispatch on.
///
/// Different from [`crate::kmip30::KmipAlgorithm::to_pkcs11_mech`] which
/// returns the **vendor** codepoints from the `pkcs11-mech-manifest.json`
/// (e.g. `CKM_PQCTODAY_ML_DSA_SIGN_VERIFY = 0x4036`). The native API
/// uses the standard codepoints (`CKM_ML_DSA = 0x1D`).
pub fn native_sign_mech(a: KmipAlgorithm) -> Option<u32> {
    use softhsmrustv3::constants as c;
    use KmipAlgorithm::*;
    Some(match a {
        MlDsa44 | MlDsa65 | MlDsa87 => c::CKM_ML_DSA,
        SlhDsaSha2_128s | SlhDsaSha2_128f | SlhDsaSha2_192s | SlhDsaSha2_192f
        | SlhDsaSha2_256s | SlhDsaSha2_256f | SlhDsaShake128s | SlhDsaShake128f
        | SlhDsaShake192s | SlhDsaShake192f | SlhDsaShake256s | SlhDsaShake256f => c::CKM_SLH_DSA,
        Rsa => c::CKM_SHA256_RSA_PKCS,
        Ecdsa => c::CKM_ECDSA_SHA256,
        HmacSha256 => c::CKM_SHA256_HMAC,
        HmacSha384 => c::CKM_SHA384_HMAC,
        HmacSha512 => c::CKM_SHA512_HMAC,
        _ => return None,
    })
}

/// Map a `KmipAlgorithm` to the engine's KEM mechanism.
pub fn native_kem_mech(a: KmipAlgorithm) -> Option<u32> {
    use softhsmrustv3::constants as c;
    use KmipAlgorithm::*;
    match a {
        MlKem512 | MlKem768 | MlKem1024 => Some(c::CKM_ML_KEM),
        _ => None,
    }
}

/// Map a `KmipAlgorithm` to the parameter-set codepoint (`CKP_*`) used
/// by `softhsmrustv3::native::generate_*_keypair`.
pub fn native_parameter_set(a: KmipAlgorithm) -> Option<u32> {
    use softhsmrustv3::constants as c;
    use KmipAlgorithm::*;
    Some(match a {
        MlKem512  => c::CKP_ML_KEM_512,
        MlKem768  => c::CKP_ML_KEM_768,
        MlKem1024 => c::CKP_ML_KEM_1024,
        MlDsa44   => c::CKP_ML_DSA_44,
        MlDsa65   => c::CKP_ML_DSA_65,
        MlDsa87   => c::CKP_ML_DSA_87,
        SlhDsaSha2_128s  => c::CKP_SLH_DSA_SHA2_128S,
        SlhDsaSha2_128f  => c::CKP_SLH_DSA_SHA2_128F,
        SlhDsaSha2_192s  => c::CKP_SLH_DSA_SHA2_192S,
        SlhDsaSha2_192f  => c::CKP_SLH_DSA_SHA2_192F,
        SlhDsaSha2_256s  => c::CKP_SLH_DSA_SHA2_256S,
        SlhDsaSha2_256f  => c::CKP_SLH_DSA_SHA2_256F,
        SlhDsaShake128s  => c::CKP_SLH_DSA_SHAKE_128S,
        SlhDsaShake128f  => c::CKP_SLH_DSA_SHAKE_128F,
        SlhDsaShake192s  => c::CKP_SLH_DSA_SHAKE_192S,
        SlhDsaShake192f  => c::CKP_SLH_DSA_SHAKE_192F,
        SlhDsaShake256s  => c::CKP_SLH_DSA_SHAKE_256S,
        SlhDsaShake256f  => c::CKP_SLH_DSA_SHAKE_256F,
        _ => return None,
    })
}

/// Find the engine handle matching a stored `pkcs11_cka_id` AND a KMIP
/// `ObjectType` (PrivateKey / PublicKey / SymmetricKey / SecretData).
///
/// Both halves of an asymmetric keypair share the same `CKA_ID` in
/// PKCS#11 convention, so plain `find_by_cka_id` is ambiguous — sign
/// needs the private handle, verify needs the public, encap needs
/// public, decap needs private. This helper filters
/// `find_all_by_cka_id` by `CKA_CLASS`.
pub fn find_handle_for_object(
    session: u32,
    cka_id: &[u8],
    object_type: crate::kmip30::ObjectType,
) -> Result<Option<u32>, u32> {
    use crate::kmip30::ObjectType;
    use softhsmrustv3::constants as c;
    let target_class = match object_type {
        ObjectType::PrivateKey => c::CKO_PRIVATE_KEY,
        ObjectType::PublicKey => c::CKO_PUBLIC_KEY,
        ObjectType::SymmetricKey | ObjectType::SecretData => c::CKO_SECRET_KEY,
        // PKCS#11 CKO_CERTIFICATE = 0x01, not exposed in softhsmrustv3 constants
        ObjectType::Certificate => 0x01,
        // KMIP-only object types — no PKCS#11 cryptoki class maps cleanly.
        // Surface as ItemNotFound by returning a sentinel that never
        // matches a real handle class (CKO_VENDOR_DEFINED start = 0x80000000).
        ObjectType::SplitKey
        | ObjectType::OpaqueObject
        | ObjectType::PgpKey
        | ObjectType::CertificateRequest
        | ObjectType::User
        | ObjectType::Group
        | ObjectType::PasswordCredential
        | ObjectType::DeviceCredential
        | ObjectType::OneTimePasswordCredential
        | ObjectType::HashedPasswordCredential => 0x80000000,
    };
    let handles = softhsmrustv3::native::find_all_by_cka_id(session, cka_id)?;
    for handle in handles {
        if let Some(class) = softhsmrustv3::native::get_attribute_u32(session, handle, c::CKA_CLASS)
        {
            if class == target_class {
                return Ok(Some(handle));
            }
        }
    }
    Ok(None)
}

/// Convert a `softhsmrustv3` `CK_RV` (`u32`) to a `KmipError`.
pub fn ck_rv_to_kmip_error(rv: u32, op: &str) -> KmipError {
    use softhsmrustv3::constants as c;
    match rv {
        c::CKR_KEY_FUNCTION_NOT_PERMITTED => {
            KmipError::permission_denied(format!("{op}: CKA_SIGN/CKA_ENCAPSULATE/etc. denied"))
        }
        c::CKR_OBJECT_HANDLE_INVALID => KmipError::not_found(&format!("{op}: object handle gone")),
        c::CKR_MECHANISM_INVALID => KmipError::failed(
            crate::error::ResultReason::OperationNotSupported,
            format!("{op}: mechanism not supported by the engine"),
        ),
        c::CKR_ARGUMENTS_BAD => KmipError::invalid_attribute_value(format!("{op}: bad arguments")),
        c::CKR_ENCRYPTED_DATA_INVALID => {
            KmipError::cryptographic_failure(format!("{op}: ciphertext authentication failed"))
        }
        _ => KmipError::cryptographic_failure(format!("{op}: CK_RV=0x{rv:08x}")),
    }
}
