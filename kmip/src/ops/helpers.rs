//! Shared helpers used by every Plane-2 op handler. Lives outside any
//! one op file so all 12 handlers can share the audit-emission +
//! algorithm-string boilerplate without duplication.

use time::OffsetDateTime;

use crate::auditlog::{AuditEvent, EventPayload, KmipOpResult, Plane};
use crate::error::KmipError;
use crate::kmip30::{KmipAlgorithm, UsageMask};

use super::deps::Deps;

/// KMIP 3.0 §11 `Cryptographic Usage Mask` enforcement (K12, audit K-9).
///
/// Before engine dispatch, every crypto op verifies the target object's
/// usage mask carries the bit the operation requires (spec Table 606:
/// Sign 0x01, Verify 0x02, Encrypt 0x04, Decrypt 0x08, MAC Generate
/// 0x80, MAC Verify 0x100). A present-but-missing bit fails with
/// `Incompatible Cryptographic Usage Mask` (0x29) — same reason code
/// `Check` (§6.1.7) pins for its mask comparison.
///
/// An **empty** mask is treated as unrestricted: Create / Register /
/// CreateKeyPair default to `UsageMask::empty()` when the client omits
/// the attribute (`usage_mask.unwrap_or_else(UsageMask::empty)`), and
/// the store cannot distinguish "absent" from "all bits clear" — both
/// persist as 0. Enforcing against 0 would brick every object created
/// without an explicit mask, so absence means "no restriction recorded",
/// mirroring how `Check` only tests the bits a client asks about.
pub fn enforce_usage_mask(
    deps: &Deps,
    correlation_id: &str,
    op: &str,
    obj: &crate::store::ObjectRecord,
    required: UsageMask,
) -> crate::error::Result<()> {
    if obj.usage_mask.is_empty() || obj.usage_mask.contains(required) {
        return Ok(());
    }
    Err(fail_err(
        deps,
        correlation_id,
        op,
        KmipError::failed(
            crate::error::ResultReason::IncompatibleCryptographicUsageMask,
            format!(
                "{op}: object's Cryptographic Usage Mask {:#x} lacks required bit {:#x}",
                obj.usage_mask.bits(),
                required.bits()
            ),
        ),
    ))
}

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

/// Emit a `Pkcs11Call` audit event.
///
/// K15 (compliance-audit B-8) — the record is emitted AFTER the engine
/// call executes, with the **real** return code and the **actual**
/// entry-point name (`native::sign`, `native::encrypt_with_key_bytes`,
/// …). Handlers that fall back to in-process crypto (no engine session
/// and no engine-resident handle) name the path `soft::*` so the audit
/// trail never claims an engine call that did not happen.
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

/// Audit-record name for a `CK_RV`. `CKR_OK` for 0; every other code
/// is rendered numerically (`CKR_0x…`) — we never guess a symbolic
/// name we can't verify.
pub fn ckr_display_name(rv: u32) -> String {
    if rv == 0 { "CKR_OK".to_string() } else { format!("CKR_0x{rv:08X}") }
}

/// K15 — emit a `Pkcs11Call` record for an **already-executed** native
/// call, taking rv straight from the call's `Result`. This is the only
/// honest emission order: the old pattern logged `rv=0 CKR_OK` before
/// the engine ran, so failed calls were recorded as successes.
pub fn emit_pkcs11_result<T>(
    deps: &Deps,
    correlation_id: &str,
    function: &str,
    mech: Option<u32>,
    result: &std::result::Result<T, u32>,
) {
    let rv = match result {
        Ok(_) => 0,
        Err(rv) => *rv,
    };
    emit_pkcs11(deps, correlation_id, function, mech, rv, &ckr_display_name(rv));
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
/// Spec-text name for a KMIP 3.0 §11 `Block Cipher Mode` codepoint —
/// used in `UnsupportedCryptographicParameters` messages so the client
/// sees the mode it asked for, not just a number. Codepoints verified
/// against `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`.
fn block_cipher_mode_name(v: u32) -> &'static str {
    match v {
        0x01 => "CBC",
        0x02 => "ECB",
        0x03 => "PCBC",
        0x04 => "CFB",
        0x05 => "OFB",
        0x06 => "CTR",
        0x07 => "CMAC",
        0x08 => "CCM",
        0x09 => "GCM",
        0x0a => "CBC-MAC",
        0x0b => "XTS",
        0x0c => "AESKeyWrapPadding",
        0x0d => "NISTKeyWrap",
        0x0e => "X9.102 AESKW",
        0x0f => "X9.102 TDKW",
        0x10 => "X9.102 AKW1",
        0x11 => "X9.102 AKW2",
        0x12 => "AEAD",
        _ => "unknown",
    }
}

/// Pick the PKCS#11 mechanism for AES Encrypt / Decrypt off the
/// effective `BlockCipherMode`. KMIP 3.0 §11 `Block Cipher Mode` enum
/// (verified against the tags-enums extract): `CBC=1, ECB=2, PCBC=3,
/// CFB=4, OFB=5, CTR=6, CMAC=7, CCM=8, GCM=9, ..., XTS=0x0b,
/// NISTKeyWrap=0x0d, ..., AEAD=0x12`.
///
/// **Total-or-failing (K6, compliance-audit B-2):** every mode either
/// maps to a mechanism the engine implements (CBC / CBC+PKCS5-pad /
/// ECB / CTR / GCM) or fails with
/// `UnsupportedCryptographicParameters (0x3e)` — the server never
/// silently substitutes another algorithm. Absent mode → GCM (the
/// documented default for AES keys created without parameters).
pub fn aes_mechanism_for(
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> Result<u32, KmipError> {
    use softhsmrustv3::constants::{
        CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTR, CKM_AES_ECB, CKM_AES_GCM,
    };
    let bcm = cp.and_then(|c| c.block_cipher_mode);
    // KMIP 3.0 §11 `Padding Method` enum — codepoint 3 = `PKCS5`
    // (synonym for PKCS#7 for AES). With BlockCipherMode=CBC this
    // selects `CKM_AES_CBC_PAD`, which permits arbitrary-length
    // plaintext (the shim's CBC_PAD path adds PKCS#7 padding).
    let pad = cp.and_then(|c| c.padding_method);
    Ok(match (bcm, pad) {
        (Some(1), Some(3)) => CKM_AES_CBC_PAD,
        (Some(1), _) => CKM_AES_CBC,
        (Some(2), _) => CKM_AES_ECB,
        (Some(6), _) => CKM_AES_CTR,
        (Some(9), _) | (None, _) => CKM_AES_GCM,
        (Some(other), _) => {
            return Err(KmipError::unsupported_cryptographic_parameters(format!(
                "AES Encrypt/Decrypt: Block Cipher Mode {} (0x{other:02x}) is not supported",
                block_cipher_mode_name(other),
            )));
        }
    })
}

// KMIP 3.0 §11 `Padding Method` codepoints — verified against
// `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`:
// 0x01=None, 0x02=OAEP, 0x03=PKCS5, 0x08=PKCS1 v1.5, 0x0a=PSS.
const PADDING_OAEP: u32 = 0x02;
const PADDING_PKCS1_V1_5: u32 = 0x08;
const PADDING_PSS: u32 = 0x0a;

/// Pick the PKCS#11 mechanism for RSA Encrypt / Decrypt off the
/// effective `PaddingMethod` (K6 — no silent substitution):
///
/// - absent → `CKM_RSA_PKCS_OAEP` — the documented server default
///   (OAEP/SHA-256, the only RSA encryption profile the OASIS Baseline
///   corpus exercises).
/// - `OAEP (0x02)` → `CKM_RSA_PKCS_OAEP`.
/// - `PKCS1 v1.5 (0x08)` → `UnsupportedCryptographicParameters (0x3e)`:
///   the engine's encrypt/decrypt dispatch (`native::encrypt_with_key_bytes`)
///   implements **no raw RSAES-PKCS1-v1_5 primitive** (only OAEP), so we
///   fail up-front instead of substituting OAEP. If the engine grows
///   `CKM_RSA_PKCS` encryption, this arm becomes `Ok(CKM_RSA_PKCS)`.
/// - anything else → `UnsupportedCryptographicParameters (0x3e)`.
pub fn rsa_encrypt_mechanism_for(
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> Result<u32, KmipError> {
    use softhsmrustv3::constants::CKM_RSA_PKCS_OAEP;
    match cp.and_then(|c| c.padding_method) {
        None | Some(PADDING_OAEP) => Ok(CKM_RSA_PKCS_OAEP),
        Some(PADDING_PKCS1_V1_5) => Err(KmipError::unsupported_cryptographic_parameters(
            "RSA Encrypt/Decrypt: Padding Method PKCS1 v1.5 (0x08) is not supported \
             (engine implements RSAES-OAEP only)",
        )),
        Some(other) => Err(KmipError::unsupported_cryptographic_parameters(format!(
            "RSA Encrypt/Decrypt: Padding Method 0x{other:02x} is not supported",
        ))),
    }
}

/// Map a KMIP `CryptographicParameters` onto the shim's
/// [`softhsmrustv3::native::OaepParams`]. Returns `Ok(None)` when the
/// key carries no params (callers should treat that as "use shim
/// default = SHA-256 / MGF1-SHA-256 / no label"); an **absent** hash
/// field inside present params likewise falls through to the shim's
/// SHA-256 default.
///
/// K6 (compliance-audit B-2): a hash the engine does NOT implement
/// (SHA-1, SHA-224, SHA3-*, …; `OaepHash` covers exactly
/// SHA-256/384/512) fails with
/// `UnsupportedCryptographicParameters (0x3e)` — never silently
/// downgraded to SHA-256.
pub fn oaep_params_for(
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> Result<Option<softhsmrustv3::native::OaepParams<'_>>, KmipError> {
    use crate::kmip30::HashingAlgorithm;
    use softhsmrustv3::native::OaepHash;
    let Some(cp) = cp else { return Ok(None) };
    let map_hash = |h: HashingAlgorithm| -> Result<OaepHash, KmipError> {
        match h {
            HashingAlgorithm::Sha256 => Ok(OaepHash::Sha256),
            HashingAlgorithm::Sha384 => Ok(OaepHash::Sha384),
            HashingAlgorithm::Sha512 => Ok(OaepHash::Sha512),
            other => Err(KmipError::unsupported_cryptographic_parameters(format!(
                "RSA-OAEP: Hashing Algorithm {other:?} is not supported \
                 (supported: SHA-256, SHA-384, SHA-512)",
            ))),
        }
    };
    Ok(Some(softhsmrustv3::native::OaepParams {
        hash: cp.hashing_algorithm.map(map_hash).transpose()?,
        mgf_hash: cp.mask_generator_hashing_algorithm.map(map_hash).transpose()?,
        label: cp.p_source.as_deref(),
    }))
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

/// Map a `KmipAlgorithm` + `CryptographicParameters` to the engine's
/// **standard PKCS#11 v3.2** sign mechanism — what
/// `softhsmrustv3::native::sign` / `verify` dispatch on.
///
/// Since K5 retired the pseudo-vendor 0x403x block,
/// [`crate::kmip30::KmipAlgorithm::to_pkcs11_mech`] returns the same
/// standard codepoints for the PQC families (`CKM_ML_DSA = 0x1D`, …).
/// This helper differs in that it consults `CryptographicParameters`
/// (KMIP 3.0 §6.1.{60,61} permit them on the request or as the
/// object's stored attribute) so classical RSA/ECDSA pick the exact
/// padding + hash mechanism.
///
/// K6 (compliance-audit B-2) — no silent substitution:
///
/// - RSA: `PaddingMethod` absent or `PKCS1 v1.5 (0x08)` → the
///   `CKM_SHA*_RSA_PKCS` family (PKCS#1 v1.5 is the documented sign
///   default); `PSS (0x0a)` → `CKM_SHA*_RSA_PKCS_PSS`; any other
///   padding → `UnsupportedCryptographicParameters (0x3e)`.
/// - RSA/ECDSA hash: absent → SHA-256 (documented default, matches
///   the pre-K6 behaviour the corpus pins); SHA-256/384/512 →
///   matching engine mechanism (SHA-384/512 since engine slice S6);
///   anything else (SHA-1, SHA-224, SHA3-*, …) → 0x3e.
/// - PSS salt length (K18, round-1 K6 residual): the KMIP 3.0
///   `Cryptographic Parameters` `Salt Length` field (0x420100) now
///   decodes; [`pss_salt_from_cp`] extracts it for PSS mechanisms and
///   the op handlers thread it through
///   `native::sign_with_pss_salt`/`verify_with_pss_salt`. Absent →
///   `None` → the engine keeps the RFC 8017 salt = hash-length default
///   (verify also accepts the maximal salt, see
///   `crypto::handlers::verify_rsa`).
/// - algorithms with no sign mechanism (AES, ML-KEM, …) →
///   `OperationNotSupported`.
pub fn native_sign_mech_with_params(
    a: KmipAlgorithm,
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> Result<u32, KmipError> {
    use crate::kmip30::HashingAlgorithm as H;
    use softhsmrustv3::constants as c;
    use KmipAlgorithm::*;
    let hash = cp.and_then(|p| p.hashing_algorithm);
    let unsupported_hash = |family: &str| {
        KmipError::unsupported_cryptographic_parameters(format!(
            "{family} Sign/Verify: Hashing Algorithm {:?} is not supported \
             (supported: SHA-256, SHA-384, SHA-512)",
            hash.expect("only called for present hash"),
        ))
    };
    Ok(match a {
        MlDsa44 | MlDsa65 | MlDsa87 => c::CKM_ML_DSA,
        SlhDsaSha2_128s | SlhDsaSha2_128f | SlhDsaSha2_192s | SlhDsaSha2_192f
        | SlhDsaSha2_256s | SlhDsaSha2_256f | SlhDsaShake128s | SlhDsaShake128f
        | SlhDsaShake192s | SlhDsaShake192f | SlhDsaShake256s | SlhDsaShake256f => c::CKM_SLH_DSA,
        Rsa => {
            let pss = match cp.and_then(|p| p.padding_method) {
                Some(PADDING_PSS) => true,
                // PKCS#1 v1.5 is the documented default when no padding
                // is supplied (matches pre-K6 behaviour + CS-AC-M-3).
                None | Some(PADDING_PKCS1_V1_5) => false,
                Some(other) => {
                    return Err(KmipError::unsupported_cryptographic_parameters(format!(
                        "RSA Sign/Verify: Padding Method 0x{other:02x} is not supported \
                         (supported: PKCS1 v1.5, PSS)",
                    )));
                }
            };
            match (hash.unwrap_or(H::Sha256), pss) {
                (H::Sha256, false) => c::CKM_SHA256_RSA_PKCS,
                (H::Sha384, false) => c::CKM_SHA384_RSA_PKCS,
                (H::Sha512, false) => c::CKM_SHA512_RSA_PKCS,
                (H::Sha256, true) => c::CKM_SHA256_RSA_PKCS_PSS,
                (H::Sha384, true) => c::CKM_SHA384_RSA_PKCS_PSS,
                (H::Sha512, true) => c::CKM_SHA512_RSA_PKCS_PSS,
                _ => return Err(unsupported_hash("RSA")),
            }
        }
        Ecdsa => match hash.unwrap_or(H::Sha256) {
            H::Sha256 => c::CKM_ECDSA_SHA256,
            H::Sha384 => c::CKM_ECDSA_SHA384,
            H::Sha512 => c::CKM_ECDSA_SHA512,
            _ => return Err(unsupported_hash("ECDSA")),
        },
        HmacSha256 => c::CKM_SHA256_HMAC,
        HmacSha384 => c::CKM_SHA384_HMAC,
        HmacSha512 => c::CKM_SHA512_HMAC,
        other => {
            return Err(KmipError::failed(
                crate::error::ResultReason::OperationNotSupported,
                format!("no native sign mechanism for {other:?}"),
            ));
        }
    })
}

/// K18 — extract the RSA-PSS salt length to pass to
/// `native::sign_with_pss_salt` / `verify_with_pss_salt`.
///
/// - `mech` is not a PSS variant, or the effective CP carries no
///   `Salt Length` → `Ok(None)` (KMIP 3.0 §11: CryptographicParameters
///   is a grab-bag — fields irrelevant to the operation are ignored,
///   not an error). `None` keeps the engine's §6.2 hash-length default.
/// - negative `Salt Length` → `InvalidField` (no valid encoding; the
///   wire type is a signed Integer but RFC 8017 sLen is a length).
/// - oversized salt (> emLen - hLen - 2) is NOT pre-validated here —
///   the engine's `rsa` crate rejects it at sign time
///   (`CKR_FUNCTION_FAILED` → `CryptographicFailure` via
///   [`ck_rv_to_kmip_error`]).
pub fn pss_salt_from_cp(
    mech: u32,
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> Result<Option<usize>, KmipError> {
    use softhsmrustv3::constants as c;
    let is_pss = matches!(
        mech,
        c::CKM_SHA256_RSA_PKCS_PSS | c::CKM_SHA384_RSA_PKCS_PSS | c::CKM_SHA512_RSA_PKCS_PSS
    );
    match (is_pss, cp.and_then(|p| p.salt_length)) {
        (true, Some(s)) if s < 0 => Err(KmipError::invalid_field(format!(
            "Salt Length {s} is negative — RSA-PSS salt length is a byte count"
        ))),
        (true, Some(s)) => Ok(Some(s as usize)),
        _ => Ok(None),
    }
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
///
/// Full mapping per `docs/COMPLIANCE_FIX_PLAN.md` K1 (findings B-3, K-3):
/// every `CKR_*` the engine emits deliberately maps to a specific
/// `ResultReason`; the catch-all is `GeneralFailure` (0x100), NOT
/// `CryptographicFailure` — only genuinely-cryptographic codes map to
/// `CryptographicFailure` (0x0a).
///
/// Handle-invalid codes (`CKR_OBJECT_HANDLE_INVALID`, `CKR_KEY_HANDLE_INVALID`,
/// `CKR_WRAPPING_KEY_HANDLE_INVALID`, `CKR_UNWRAPPING_KEY_HANDLE_INVALID`)
/// map to `KmipError::object_not_found` (`Object Not Found`, 0x37): a
/// vanished engine handle means the managed object backing the UID is gone.
pub fn ck_rv_to_kmip_error(rv: u32, op: &str) -> KmipError {
    use softhsmrustv3::constants as c;
    match rv {
        // ── Permission / capability ─────────────────────────────────
        c::CKR_KEY_FUNCTION_NOT_PERMITTED => {
            KmipError::permission_denied(format!("{op}: CKA_SIGN/CKA_ENCAPSULATE/etc. denied"))
        }
        // ── Missing managed object ──────────────────────────────────
        c::CKR_OBJECT_HANDLE_INVALID
        | c::CKR_KEY_HANDLE_INVALID
        | c::CKR_WRAPPING_KEY_HANDLE_INVALID
        | c::CKR_UNWRAPPING_KEY_HANDLE_INVALID => {
            KmipError::object_not_found(&format!("{op}: object handle gone"))
        }
        // ── Unsupported mechanism / parameters ──────────────────────
        c::CKR_MECHANISM_INVALID => KmipError::failed(
            crate::error::ResultReason::OperationNotSupported,
            format!("{op}: mechanism not supported by the engine"),
        ),
        c::CKR_MECHANISM_PARAM_INVALID => KmipError::unsupported_cryptographic_parameters(
            format!("{op}: mechanism parameters not supported"),
        ),
        // ── Malformed request fields ────────────────────────────────
        c::CKR_ARGUMENTS_BAD => KmipError::invalid_field(format!("{op}: bad arguments")),
        c::CKR_DATA_LEN_RANGE => {
            KmipError::invalid_field(format!("{op}: data length out of range"))
        }
        c::CKR_ENCRYPTED_DATA_LEN_RANGE => {
            KmipError::invalid_field(format!("{op}: ciphertext length out of range"))
        }
        c::CKR_WRAPPED_KEY_LEN_RANGE => {
            KmipError::invalid_field(format!("{op}: wrapped key length out of range"))
        }
        c::CKR_KEY_SIZE_RANGE => KmipError::invalid_field(format!("{op}: key size out of range")),
        c::CKR_KEY_TYPE_INCONSISTENT => {
            KmipError::invalid_field(format!("{op}: key type inconsistent with mechanism"))
        }
        // ── Template / attribute problems ───────────────────────────
        c::CKR_TEMPLATE_INCOMPLETE => {
            KmipError::invalid_attribute_value(format!("{op}: template incomplete"))
        }
        c::CKR_TEMPLATE_INCONSISTENT => {
            KmipError::invalid_attribute_value(format!("{op}: template inconsistent"))
        }
        c::CKR_ATTRIBUTE_VALUE_INVALID => {
            KmipError::invalid_attribute_value(format!("{op}: attribute value invalid"))
        }
        // ── Authentication ──────────────────────────────────────────
        c::CKR_PIN_INCORRECT
        | c::CKR_PIN_INVALID
        | c::CKR_PIN_LEN_RANGE
        | c::CKR_USER_PIN_NOT_INITIALIZED
        | c::CKR_USER_NOT_LOGGED_IN => KmipError::failed(
            crate::error::ResultReason::AuthenticationNotSuccessful,
            format!("{op}: PKCS#11 authentication failed (CK_RV=0x{rv:08x})"),
        ),
        // ── Genuinely cryptographic failures ────────────────────────
        c::CKR_ENCRYPTED_DATA_INVALID => {
            KmipError::cryptographic_failure(format!("{op}: ciphertext authentication failed"))
        }
        c::CKR_WRAPPED_KEY_INVALID => {
            KmipError::cryptographic_failure(format!("{op}: wrapped key invalid"))
        }
        c::CKR_SIGNATURE_INVALID => {
            KmipError::cryptographic_failure(format!("{op}: signature invalid"))
        }
        c::CKR_SIGNATURE_LEN_RANGE => {
            KmipError::cryptographic_failure(format!("{op}: signature length out of range"))
        }
        // The engine returns CKR_FUNCTION_FAILED for crypto-primitive
        // failures (OpenSSL-level errors), so it is cryptographic.
        c::CKR_FUNCTION_FAILED => {
            KmipError::cryptographic_failure(format!("{op}: cryptographic function failed"))
        }
        // ── Sensitivity / extractability ────────────────────────────
        c::CKR_ATTRIBUTE_SENSITIVE => {
            KmipError::sensitive(format!("{op}: attribute is sensitive"))
        }
        c::CKR_KEY_UNEXTRACTABLE => {
            KmipError::not_extractable(format!("{op}: key is unextractable"))
        }
        c::CKR_KEY_NOT_WRAPPABLE => {
            KmipError::not_extractable(format!("{op}: key is not wrappable"))
        }
        // ── Everything else (CKR_HOST_MEMORY, CKR_GENERAL_ERROR, …) ──
        _ => KmipError::general_failure(format!("{op}: CK_RV=0x{rv:08x}")),
    }
}

/// K8 — apply the client-requested `Key Format Type` to material the
/// server holds in `stored` format (KMIP 3.0 §6.1.23 Get / §6.1.22
/// Export, compliance-audit B-5). Conversion table:
///
/// - absent → stored format, material as-is
/// - requested == stored → as-is
/// - `Raw` ↔ `TransparentSymmetricKey` — same bytes, different §6.2.1
///   KeyMaterial wrapping (the wire encoder owns the shape)
/// - `PKCS#1` ↔ `PKCS#8` for RSA private keys — re-encoded via the
///   `rsa` crate (same DER round-trip Register already relies on)
/// - anything else → `Key Format Type Not Supported (0x10)`; the
///   material is NEVER silently re-labeled.
pub fn convert_key_format(
    stored: crate::kmip30::KeyFormatType,
    bytes: Vec<u8>,
    requested: Option<u32>,
    algorithm: KmipAlgorithm,
    object_type: crate::kmip30::ObjectType,
) -> Result<(crate::kmip30::KeyFormatType, Vec<u8>), KmipError> {
    use crate::kmip30::{KeyFormatType as F, ObjectType as O};
    let Some(code) = requested else {
        return Ok((stored, bytes));
    };
    let requested = F::from_wire_value(code).ok_or_else(|| {
        KmipError::key_format_type_not_supported(format!(
            "requested Key Format Type {code:#04x} is not a KMIP 3.0 codepoint"
        ))
    })?;
    if requested == stored {
        return Ok((stored, bytes));
    }
    match (stored, requested) {
        // Symmetric material: identical bytes, different KeyMaterial
        // wrapping on the wire.
        (F::Raw, F::TransparentSymmetricKey) | (F::TransparentSymmetricKey, F::Raw) => {
            Ok((requested, bytes))
        }
        // RSA private key DER re-encodings.
        (F::Pkcs8, F::Pkcs1) if algorithm == KmipAlgorithm::Rsa && object_type == O::PrivateKey => {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            use rsa::pkcs8::DecodePrivateKey;
            rsa::RsaPrivateKey::from_pkcs8_der(&bytes)
                .ok()
                .and_then(|k| k.to_pkcs1_der().ok())
                .map(|d| (requested, d.as_bytes().to_vec()))
                .ok_or_else(|| KmipError::key_format_type_not_supported(
                    "stored PKCS#8 material cannot be re-encoded as PKCS#1".to_string(),
                ))
        }
        (F::Pkcs1, F::Pkcs8) if algorithm == KmipAlgorithm::Rsa && object_type == O::PrivateKey => {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            use rsa::pkcs8::EncodePrivateKey;
            rsa::RsaPrivateKey::from_pkcs1_der(&bytes)
                .ok()
                .and_then(|k| k.to_pkcs8_der().ok())
                .map(|d| (requested, d.as_bytes().to_vec()))
                .ok_or_else(|| KmipError::key_format_type_not_supported(
                    "stored PKCS#1 material cannot be re-encoded as PKCS#8".to_string(),
                ))
        }
        _ => Err(KmipError::key_format_type_not_supported(format!(
            "cannot convert stored {stored:?} material to requested {requested:?}"
        ))),
    }
}

/// K16 — AES-KW wrap of the TTLV-encoded KeyValue under the wrap key
/// named by a request's `KeyWrappingSpecification`. Shared by `Get`
/// (§6.1.23, AX-M-2) and `Export` (§6.1.22) so both ops enforce the
/// same KEK lifecycle (Active) + usage-mask (WrapKey) gates and emit
/// the same wrapped shape; `op` names the caller for audit events.
pub fn wrap_key_value(
    deps: &Deps,
    op: &str,
    spec: &crate::kmip30::KeyWrappingSpec,
    key_material: &[u8],
    correlation_id: &str,
) -> crate::error::Result<Vec<u8>> {
    use crate::error::ResultReason;
    // §11 Wrapping Method — only `Encrypt` (0x01) is implemented.
    if spec.wrapping_method != 0x01 {
        return Err(fail_err(deps, correlation_id, op,
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Wrapping Method {:#x} not supported (only Encrypt)", spec.wrapping_method),
            )));
    }
    // §11 Block Cipher Mode — NISTKeyWrap (0x0d) selects AES-KW. Absent
    // CP defaults to NISTKeyWrap as well (the only supported wrap mode).
    let mode = spec
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.block_cipher_mode)
        .unwrap_or(0x0d);
    if mode != 0x0d {
        return Err(fail_err(deps, correlation_id, op,
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Block Cipher Mode {mode:#x} not supported for wrapping (only NISTKeyWrap)"),
            )));
    }
    let kek = resolve_kek(
        deps, op, &spec.encryption_key_uid,
        crate::kmip30::UsageMask::WRAP_KEY, "WrapKey",
        correlation_id,
    )?;
    // Wrap target: TTLV-encoded KeyValue (default TTLV Encoding Option);
    // TTLV framing pads to 8 bytes, satisfying AES-KW's input contract.
    let plaintext = crate::kmip30::ttlv_encode_key_value(key_material);
    // K15 — emit after the wrap call, with its real rv.
    let r = softhsmrustv3::native::aes_key_wrap(&kek, &plaintext);
    emit_pkcs11_result(deps, correlation_id, "native::aes_key_wrap",
        Some(softhsmrustv3::constants::CKM_AES_KEY_WRAP), &r);
    r.map_err(|rv| fail_err(deps, correlation_id, op,
        ck_rv_to_kmip_error(rv, &format!("{op}:wrap"))))
}

/// K17 — resolve a KEK by UID and gate it for a wrap-family operation:
/// the object must exist, be `Active` (§3.4 lifecycle), and carry the
/// direction-appropriate usage bit (§11 Cryptographic Usage Mask —
/// `WrapKey 0x10` for wrapping, `UnwrapKey 0x20` for unwrapping; the
/// bit values are pinned by the `attrs.rs` UsageMask tests). Returns
/// the raw KEK bytes via the same material tiers as Get:
/// Register-supplied bytes first, then the engine's `CKA_VALUE` behind
/// the stored CKA_ID (Create-generated KEKs live in the engine).
fn resolve_kek(
    deps: &Deps,
    op: &str,
    kek_uid: &str,
    required_usage: crate::kmip30::UsageMask,
    usage_name: &str,
    correlation_id: &str,
) -> crate::error::Result<Vec<u8>> {
    use crate::error::ResultReason;
    let kek_obj = deps
        .store
        .get(kek_uid)?
        .ok_or_else(|| fail_err(deps, correlation_id, op,
            KmipError::object_not_found(kek_uid)))?;
    if kek_obj.state != crate::kmip30::State::Active {
        return Err(fail_err(deps, correlation_id, op,
            non_active_state_error(kek_uid, kek_obj.state)));
    }
    if !kek_obj.usage_mask.contains(required_usage) {
        return Err(fail_err(deps, correlation_id, op,
            KmipError::permission_denied(
                format!("wrap key {kek_uid} lacks {usage_name} usage"),
            )));
    }
    match &kek_obj.key_material {
        Some(bytes) => Ok(bytes.clone()),
        None => deps
            .engine_session
            .and_then(|session| {
                softhsmrustv3::native::find_by_cka_id(session, &kek_obj.pkcs11_cka_id)
                    .ok()
                    .flatten()
                    .and_then(|h| {
                        softhsmrustv3::native::get_attribute(
                            session,
                            h,
                            softhsmrustv3::constants::CKA_VALUE,
                        )
                    })
            })
            .ok_or_else(|| {
                fail_err(deps, correlation_id, op,
                    KmipError::failed(
                        ResultReason::OperationNotSupported,
                        "wrap key has no exportable material".to_string(),
                    ))
            }),
    }
}

/// K17 — AES-KW unwrap of a Register KeyBlock's wrapped `KeyValue`
/// (§2.1.5 / §6.1.48: KeyWrappingData present on an inbound KeyBlock).
/// Reverse of [`wrap_key_value`] with the unwrap-direction gates: the
/// KEK must be `Active` and carry `UnwrapKey (0x20)` — NOT `WrapKey`.
/// Validates WrappingMethod=Encrypt + BlockCipherMode=NISTKeyWrap
/// (others → `UnsupportedCryptographicParameters 0x3e`), AES-KW-unwraps
/// (an integrity failure surfaces the engine's `CKR_WRAPPED_KEY_INVALID`
/// as `CryptographicFailure` via `ck_rv_to_kmip_error`), then decodes
/// the plaintext per §4.x `Encoding Option`: TTLV Encoding (the default
/// when absent) parses the `KeyValue { KeyMaterial }` structure the
/// wrap path emits; No Encoding returns the plaintext as raw material.
pub fn unwrap_key_value(
    deps: &Deps,
    op: &str,
    kwd: &crate::kmip30::KeyWrappingSpec,
    wrapped: &[u8],
    correlation_id: &str,
) -> crate::error::Result<Vec<u8>> {
    // MAC/Signature Key Information — we support Encrypt-method
    // wrapping only; there is no MAC/sign verification path.
    if kwd.mac_signature_key_information_present {
        return Err(fail_err(deps, correlation_id, op,
            KmipError::unsupported_cryptographic_parameters(
                "MAC/Signature Key Information is not supported (Encrypt-method wrapping only)",
            )));
    }
    // §11 Wrapping Method — only `Encrypt` (0x01).
    if kwd.wrapping_method != 0x01 {
        return Err(fail_err(deps, correlation_id, op,
            KmipError::unsupported_cryptographic_parameters(format!(
                "Wrapping Method {:#x} not supported (only Encrypt)", kwd.wrapping_method,
            ))));
    }
    // §11 Block Cipher Mode — NISTKeyWrap (0x0d) selects AES-KW;
    // absent CP defaults to it (the only supported wrap mode).
    let mode = kwd
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.block_cipher_mode)
        .unwrap_or(0x0d);
    if mode != 0x0d {
        return Err(fail_err(deps, correlation_id, op,
            KmipError::unsupported_cryptographic_parameters(format!(
                "Block Cipher Mode {mode:#x} not supported for unwrapping (only NISTKeyWrap)",
            ))));
    }
    let kek = resolve_kek(
        deps, op, &kwd.encryption_key_uid,
        crate::kmip30::UsageMask::UNWRAP_KEY, "UnwrapKey",
        correlation_id,
    )?;
    let r = softhsmrustv3::native::aes_key_unwrap(&kek, wrapped);
    emit_pkcs11_result(deps, correlation_id, "native::aes_key_unwrap",
        Some(softhsmrustv3::constants::CKM_AES_KEY_WRAP), &r);
    let plaintext = r.map_err(|rv| fail_err(deps, correlation_id, op,
        ck_rv_to_kmip_error(rv, &format!("{op}:unwrap"))))?;
    // §4.x Encoding Option — values verified from the "Encoding Option"
    // enum in kmip-spec-3.0-tags-enums.json: 0x01 No Encoding (raw key
    // material), 0x02 TTLV Encoding (the spec default when absent).
    match kwd.encoding_option {
        Some(0x01) => Ok(plaintext),
        None | Some(0x02) => crate::kmip30::ttlv_decode_key_value(&plaintext)
            .map_err(|e| fail_err(deps, correlation_id, op,
                KmipError::invalid_field(format!(
                    "unwrapped plaintext is not a TTLV KeyValue structure: {e}",
                )))),
        Some(other) => Err(fail_err(deps, correlation_id, op,
            KmipError::unsupported_cryptographic_parameters(format!(
                "Encoding Option {other:#x} is not a KMIP 3.0 codepoint",
            )))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ResultReason;
    use softhsmrustv3::constants as c;

    /// K1 — full CKR→ResultReason table per COMPLIANCE_FIX_PLAN.md.
    #[test]
    fn ckr_table_maps_to_expected_result_reasons() {
        let cases: &[(u32, ResultReason)] = &[
            (c::CKR_KEY_FUNCTION_NOT_PERMITTED, ResultReason::PermissionDenied),
            // Handle-invalid family → ObjectNotFound (K2 sweep): the
            // managed object backing the UID is gone from the engine.
            (c::CKR_OBJECT_HANDLE_INVALID, ResultReason::ObjectNotFound),
            (c::CKR_KEY_HANDLE_INVALID, ResultReason::ObjectNotFound),
            (c::CKR_WRAPPING_KEY_HANDLE_INVALID, ResultReason::ObjectNotFound),
            (c::CKR_UNWRAPPING_KEY_HANDLE_INVALID, ResultReason::ObjectNotFound),
            (c::CKR_MECHANISM_INVALID, ResultReason::OperationNotSupported),
            (c::CKR_MECHANISM_PARAM_INVALID, ResultReason::UnsupportedCryptographicParameters),
            (c::CKR_ARGUMENTS_BAD, ResultReason::InvalidField),
            (c::CKR_DATA_LEN_RANGE, ResultReason::InvalidField),
            (c::CKR_ENCRYPTED_DATA_LEN_RANGE, ResultReason::InvalidField),
            (c::CKR_WRAPPED_KEY_LEN_RANGE, ResultReason::InvalidField),
            (c::CKR_KEY_SIZE_RANGE, ResultReason::InvalidField),
            (c::CKR_KEY_TYPE_INCONSISTENT, ResultReason::InvalidField),
            (c::CKR_TEMPLATE_INCOMPLETE, ResultReason::InvalidAttributeValue),
            (c::CKR_TEMPLATE_INCONSISTENT, ResultReason::InvalidAttributeValue),
            (c::CKR_ATTRIBUTE_VALUE_INVALID, ResultReason::InvalidAttributeValue),
            (c::CKR_PIN_INCORRECT, ResultReason::AuthenticationNotSuccessful),
            (c::CKR_PIN_INVALID, ResultReason::AuthenticationNotSuccessful),
            (c::CKR_PIN_LEN_RANGE, ResultReason::AuthenticationNotSuccessful),
            (c::CKR_USER_PIN_NOT_INITIALIZED, ResultReason::AuthenticationNotSuccessful),
            (c::CKR_USER_NOT_LOGGED_IN, ResultReason::AuthenticationNotSuccessful),
            (c::CKR_ENCRYPTED_DATA_INVALID, ResultReason::CryptographicFailure),
            (c::CKR_WRAPPED_KEY_INVALID, ResultReason::CryptographicFailure),
            (c::CKR_SIGNATURE_INVALID, ResultReason::CryptographicFailure),
            (c::CKR_SIGNATURE_LEN_RANGE, ResultReason::CryptographicFailure),
            (c::CKR_FUNCTION_FAILED, ResultReason::CryptographicFailure),
            (c::CKR_ATTRIBUTE_SENSITIVE, ResultReason::Sensitive),
            (c::CKR_KEY_UNEXTRACTABLE, ResultReason::NotExtractable),
            (c::CKR_KEY_NOT_WRAPPABLE, ResultReason::NotExtractable),
            // Default arm → GeneralFailure (0x100), NOT CryptographicFailure.
            (c::CKR_HOST_MEMORY, ResultReason::GeneralFailure),
            (c::CKR_GENERAL_ERROR, ResultReason::GeneralFailure),
            (0xDEAD_BEEF, ResultReason::GeneralFailure),
        ];
        for &(rv, expected) in cases {
            let got = ck_rv_to_kmip_error(rv, "test").result_reason();
            assert_eq!(
                got, expected,
                "CK_RV=0x{rv:08x} mapped to {got:?}, expected {expected:?}"
            );
        }
    }

    // ── K6 — fail-or-exact mechanism selection (compliance-audit B-2) ──

    fn cp(
        mode: Option<u32>,
        pad: Option<u32>,
        hash: Option<crate::kmip30::HashingAlgorithm>,
    ) -> crate::kmip30::CryptographicParameters {
        crate::kmip30::CryptographicParameters {
            block_cipher_mode: mode,
            padding_method: pad,
            hashing_algorithm: hash,
            ..Default::default()
        }
    }

    #[test]
    fn aes_mechanism_supported_modes_map_exactly() {
        let cases: &[(Option<u32>, Option<u32>, u32)] = &[
            (Some(1), Some(3), c::CKM_AES_CBC_PAD),
            (Some(1), None, c::CKM_AES_CBC),
            (Some(2), None, c::CKM_AES_ECB),
            (Some(6), None, c::CKM_AES_CTR),
            (Some(9), None, c::CKM_AES_GCM),
            (None, None, c::CKM_AES_GCM), // documented absent-mode default
        ];
        for &(mode, pad, expected) in cases {
            let got = aes_mechanism_for(Some(&cp(mode, pad, None))).unwrap();
            assert_eq!(got, expected, "mode={mode:?} pad={pad:?}");
        }
        assert_eq!(aes_mechanism_for(None).unwrap(), c::CKM_AES_GCM);
    }

    #[test]
    fn aes_mechanism_unsupported_modes_fail_0x3e() {
        // PCBC, CFB, OFB, CMAC, CCM, CBC-MAC, XTS, AESKeyWrapPadding,
        // NISTKeyWrap, AEAD — all must fail, never fall through to GCM.
        for mode in [3u32, 4, 5, 7, 8, 0x0a, 0x0b, 0x0c, 0x0d, 0x12] {
            let err = aes_mechanism_for(Some(&cp(Some(mode), None, None)))
                .expect_err(&format!("mode 0x{mode:02x} must fail"));
            assert_eq!(
                err.result_reason(),
                ResultReason::UnsupportedCryptographicParameters,
                "mode 0x{mode:02x}"
            );
        }
    }

    #[test]
    fn rsa_encrypt_mechanism_padding_honored_or_rejected() {
        // Absent → documented OAEP default; OAEP (0x02) explicit.
        assert_eq!(rsa_encrypt_mechanism_for(None).unwrap(), c::CKM_RSA_PKCS_OAEP);
        assert_eq!(
            rsa_encrypt_mechanism_for(Some(&cp(None, Some(0x02), None))).unwrap(),
            c::CKM_RSA_PKCS_OAEP
        );
        // PKCS1 v1.5 (0x08): engine has no raw RSAES-PKCS1-v1_5 → 0x3e.
        assert_eq!(
            rsa_encrypt_mechanism_for(Some(&cp(None, Some(0x08), None)))
                .unwrap_err()
                .result_reason(),
            ResultReason::UnsupportedCryptographicParameters
        );
        // Anything else (e.g. Zeros=0x05, PSS=0x0a) → 0x3e.
        for pad in [0x01u32, 0x05, 0x0a] {
            assert_eq!(
                rsa_encrypt_mechanism_for(Some(&cp(None, Some(pad), None)))
                    .unwrap_err()
                    .result_reason(),
                ResultReason::UnsupportedCryptographicParameters,
                "pad 0x{pad:02x}"
            );
        }
    }

    #[test]
    fn oaep_params_unsupported_hash_fails_never_defaults() {
        use crate::kmip30::HashingAlgorithm as H;
        // Supported set passes through exactly.
        for h in [H::Sha256, H::Sha384, H::Sha512] {
            assert!(oaep_params_for(Some(&cp(None, None, Some(h)))).is_ok(), "{h:?}");
        }
        // SHA-1 / SHA-224 / SHA3-256 → 0x3e, not a SHA-256 substitute.
        for h in [H::Sha1, H::Sha224, H::Sha3256] {
            assert_eq!(
                oaep_params_for(Some(&cp(None, None, Some(h))))
                    .unwrap_err()
                    .result_reason(),
                ResultReason::UnsupportedCryptographicParameters,
                "{h:?}"
            );
        }
        // Absent CP / absent hash → engine SHA-256 default (documented).
        assert!(oaep_params_for(None).unwrap().is_none());
        let empty = cp(None, None, None);
        let p = oaep_params_for(Some(&empty)).unwrap().unwrap();
        assert!(p.hash.is_none() && p.mgf_hash.is_none());
        // Unsupported MGF hash also fails.
        let bad_mgf = crate::kmip30::CryptographicParameters {
            mask_generator_hashing_algorithm: Some(H::Sha1),
            ..Default::default()
        };
        assert_eq!(
            oaep_params_for(Some(&bad_mgf)).unwrap_err().result_reason(),
            ResultReason::UnsupportedCryptographicParameters
        );
    }

    #[test]
    fn sign_mech_hash_and_padding_honored() {
        use crate::kmip30::{HashingAlgorithm as H, KmipAlgorithm as A};
        let pkcs = |h| cp(None, Some(0x08), Some(h)); // PKCS1 v1.5
        let pss = |h| cp(None, Some(0x0a), Some(h)); // PSS
        // RSA — exact hash × padding matrix (SHA-384/512 since engine S6).
        let cases: &[(crate::kmip30::CryptographicParameters, u32)] = &[
            (pkcs(H::Sha256), c::CKM_SHA256_RSA_PKCS),
            (pkcs(H::Sha384), c::CKM_SHA384_RSA_PKCS),
            (pkcs(H::Sha512), c::CKM_SHA512_RSA_PKCS),
            (pss(H::Sha256), c::CKM_SHA256_RSA_PKCS_PSS),
            (pss(H::Sha384), c::CKM_SHA384_RSA_PKCS_PSS),
            (pss(H::Sha512), c::CKM_SHA512_RSA_PKCS_PSS),
        ];
        for (p, expected) in cases {
            assert_eq!(
                native_sign_mech_with_params(A::Rsa, Some(p)).unwrap(),
                *expected
            );
        }
        // Documented defaults: absent CP → PKCS1v1.5/SHA-256; absent hash
        // with PSS padding → PSS/SHA-256.
        assert_eq!(
            native_sign_mech_with_params(A::Rsa, None).unwrap(),
            c::CKM_SHA256_RSA_PKCS
        );
        assert_eq!(
            native_sign_mech_with_params(A::Rsa, Some(&cp(None, Some(0x0a), None))).unwrap(),
            c::CKM_SHA256_RSA_PKCS_PSS
        );
        // ECDSA hash variants.
        for (h, expected) in [
            (H::Sha256, c::CKM_ECDSA_SHA256),
            (H::Sha384, c::CKM_ECDSA_SHA384),
            (H::Sha512, c::CKM_ECDSA_SHA512),
        ] {
            assert_eq!(
                native_sign_mech_with_params(A::Ecdsa, Some(&cp(None, None, Some(h)))).unwrap(),
                expected
            );
        }
        assert_eq!(
            native_sign_mech_with_params(A::Ecdsa, None).unwrap(),
            c::CKM_ECDSA_SHA256
        );
    }

    #[test]
    fn sign_mech_unsupported_hash_or_padding_fails_0x3e() {
        use crate::kmip30::{HashingAlgorithm as H, KmipAlgorithm as A};
        // Unsupported hashes for RSA and ECDSA.
        for h in [H::Sha1, H::Sha224, H::Sha3512] {
            for a in [A::Rsa, A::Ecdsa] {
                assert_eq!(
                    native_sign_mech_with_params(a, Some(&cp(None, None, Some(h))))
                        .unwrap_err()
                        .result_reason(),
                    ResultReason::UnsupportedCryptographicParameters,
                    "{a:?} {h:?}"
                );
            }
        }
        // Unsupported RSA sign padding (OAEP makes no sense for sign).
        assert_eq!(
            native_sign_mech_with_params(A::Rsa, Some(&cp(None, Some(0x02), None)))
                .unwrap_err()
                .result_reason(),
            ResultReason::UnsupportedCryptographicParameters
        );
        // Algorithms without a sign mechanism stay OperationNotSupported.
        assert_eq!(
            native_sign_mech_with_params(A::Aes, None).unwrap_err().result_reason(),
            ResultReason::OperationNotSupported
        );
    }

    // ── K18 — pss_salt_from_cp ──────────────────────────────────────

    #[test]
    fn k18_pss_salt_from_cp_rules() {
        let with_salt = |s: i32| crate::kmip30::CryptographicParameters {
            padding_method: Some(PADDING_PSS),
            salt_length: Some(s),
            ..Default::default()
        };
        // PSS mech + salt → threaded verbatim (0 is a legal salt).
        for mech in [
            c::CKM_SHA256_RSA_PKCS_PSS,
            c::CKM_SHA384_RSA_PKCS_PSS,
            c::CKM_SHA512_RSA_PKCS_PSS,
        ] {
            assert_eq!(pss_salt_from_cp(mech, Some(&with_salt(0))).unwrap(), Some(0));
            assert_eq!(pss_salt_from_cp(mech, Some(&with_salt(20))).unwrap(), Some(20));
        }
        // Absent CP / absent salt → None (engine §6.2 default).
        assert_eq!(pss_salt_from_cp(c::CKM_SHA256_RSA_PKCS_PSS, None).unwrap(), None);
        assert_eq!(
            pss_salt_from_cp(
                c::CKM_SHA256_RSA_PKCS_PSS,
                Some(&crate::kmip30::CryptographicParameters::default()),
            )
            .unwrap(),
            None
        );
        // Salt on a non-PSS mechanism → ignored, never an error
        // (CryptographicParameters is a grab-bag per KMIP 3.0 §11).
        for mech in [c::CKM_SHA256_RSA_PKCS, c::CKM_ECDSA_SHA256, c::CKM_SHA256_HMAC] {
            assert_eq!(pss_salt_from_cp(mech, Some(&with_salt(20))).unwrap(), None);
        }
        // Negative salt on a PSS mech → InvalidField.
        assert_eq!(
            pss_salt_from_cp(c::CKM_SHA256_RSA_PKCS_PSS, Some(&with_salt(-1)))
                .unwrap_err()
                .result_reason(),
            ResultReason::InvalidField
        );
    }

    // ── K8 — convert_key_format ─────────────────────────────────────

    #[test]
    fn convert_key_format_rules() {
        use crate::kmip30::{KeyFormatType as F, KmipAlgorithm as A, ObjectType as O};
        let bytes = vec![0x42; 32];
        // Absent → stored format, bytes untouched.
        assert_eq!(
            convert_key_format(F::TransparentSymmetricKey, bytes.clone(), None, A::Aes, O::SymmetricKey).unwrap(),
            (F::TransparentSymmetricKey, bytes.clone()),
        );
        // Same as stored → as-is.
        assert_eq!(
            convert_key_format(F::Raw, bytes.clone(), Some(0x01), A::Aes, O::SymmetricKey).unwrap(),
            (F::Raw, bytes.clone()),
        );
        // Raw ↔ TransparentSymmetricKey — both directions, same bytes.
        assert_eq!(
            convert_key_format(F::Raw, bytes.clone(), Some(0x07), A::Aes, O::SymmetricKey).unwrap(),
            (F::TransparentSymmetricKey, bytes.clone()),
        );
        assert_eq!(
            convert_key_format(F::TransparentSymmetricKey, bytes.clone(), Some(0x01), A::Aes, O::SymmetricKey).unwrap(),
            (F::Raw, bytes.clone()),
        );
        // Unknown requested codepoint → 0x10.
        assert_eq!(
            convert_key_format(F::Raw, bytes.clone(), Some(0x0E), A::Aes, O::SymmetricKey)
                .unwrap_err().result_reason(),
            ResultReason::KeyFormatTypeNotSupported,
        );
        // Unsupported conversion → 0x10 (never silently re-labeled).
        assert_eq!(
            convert_key_format(F::Raw, bytes, Some(0x05), A::Aes, O::SymmetricKey)
                .unwrap_err().result_reason(),
            ResultReason::KeyFormatTypeNotSupported,
        );
    }

    #[test]
    fn convert_key_format_pkcs1_pkcs8_round_trip_for_rsa() {
        use crate::kmip30::{KeyFormatType as F, KmipAlgorithm as A, ObjectType as O};
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::EncodePrivateKey;
        let key = crate::ops::test_rsa_fixture::rsa_key();
        let pkcs1 = key.to_pkcs1_der().unwrap().as_bytes().to_vec();
        let pkcs8 = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        assert_eq!(
            convert_key_format(F::Pkcs1, pkcs1.clone(), Some(0x04), A::Rsa, O::PrivateKey).unwrap(),
            (F::Pkcs8, pkcs8.clone()),
        );
        assert_eq!(
            convert_key_format(F::Pkcs8, pkcs8.clone(), Some(0x03), A::Rsa, O::PrivateKey).unwrap(),
            (F::Pkcs1, pkcs1),
        );
        // Non-RSA / non-private objects don't get the DER paths.
        assert_eq!(
            convert_key_format(F::Pkcs8, pkcs8, Some(0x03), A::Rsa, O::PublicKey)
                .unwrap_err().result_reason(),
            ResultReason::KeyFormatTypeNotSupported,
        );
    }
}
