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
            mechanism: mech.map(ckm_name),
            slot: Some(deps.config.pkcs11_slot),
            session: None,
            rv,
            rv_name: rv_name.into(),
            latency_ms: 0,
        },
    ));
}

/// Best-effort friendly name for a PKCS#11 `CKM_*` mechanism, for the audit
/// trail. Maps the engine's OWN verified constants (no guessing) and falls back
/// to `CKM_0x{hex}` for anything unmapped — so the cross-plane audit reads
/// `CKM_ML_DSA_KEY_PAIR_GEN` instead of `CKM_0x001C`.
pub fn ckm_name(m: u32) -> String {
    use softhsmrustv3::constants as ck;
    let name = match m {
        ck::CKM_RSA_PKCS_KEY_PAIR_GEN => "CKM_RSA_PKCS_KEY_PAIR_GEN",
        ck::CKM_RSA_PKCS_OAEP => "CKM_RSA_PKCS_OAEP",
        ck::CKM_SHA256_RSA_PKCS => "CKM_SHA256_RSA_PKCS",
        ck::CKM_SHA384_RSA_PKCS => "CKM_SHA384_RSA_PKCS",
        ck::CKM_SHA512_RSA_PKCS => "CKM_SHA512_RSA_PKCS",
        ck::CKM_SHA256_RSA_PKCS_PSS => "CKM_SHA256_RSA_PKCS_PSS",
        ck::CKM_SHA384_RSA_PKCS_PSS => "CKM_SHA384_RSA_PKCS_PSS",
        ck::CKM_SHA512_RSA_PKCS_PSS => "CKM_SHA512_RSA_PKCS_PSS",
        ck::CKM_ML_KEM_KEY_PAIR_GEN => "CKM_ML_KEM_KEY_PAIR_GEN",
        ck::CKM_ML_KEM => "CKM_ML_KEM",
        ck::CKM_ML_DSA_KEY_PAIR_GEN => "CKM_ML_DSA_KEY_PAIR_GEN",
        ck::CKM_ML_DSA => "CKM_ML_DSA",
        ck::CKM_HASH_ML_DSA => "CKM_HASH_ML_DSA",
        ck::CKM_SLH_DSA_KEY_PAIR_GEN => "CKM_SLH_DSA_KEY_PAIR_GEN",
        ck::CKM_SLH_DSA => "CKM_SLH_DSA",
        ck::CKM_HASH_SLH_DSA => "CKM_HASH_SLH_DSA",
        ck::CKM_EC_KEY_PAIR_GEN => "CKM_EC_KEY_PAIR_GEN",
        ck::CKM_ECDSA => "CKM_ECDSA",
        ck::CKM_ECDSA_SHA256 => "CKM_ECDSA_SHA256",
        ck::CKM_ECDSA_SHA384 => "CKM_ECDSA_SHA384",
        ck::CKM_ECDSA_SHA512 => "CKM_ECDSA_SHA512",
        ck::CKM_AES_KEY_GEN => "CKM_AES_KEY_GEN",
        ck::CKM_AES_GCM => "CKM_AES_GCM",
        ck::CKM_AES_CBC => "CKM_AES_CBC",
        ck::CKM_AES_CBC_PAD => "CKM_AES_CBC_PAD",
        ck::CKM_AES_CTR => "CKM_AES_CTR",
        ck::CKM_AES_KEY_WRAP => "CKM_AES_KEY_WRAP",
        ck::CKM_SHA256 => "CKM_SHA256",
        ck::CKM_SHA384 => "CKM_SHA384",
        ck::CKM_SHA512 => "CKM_SHA512",
        ck::CKM_SHA256_HMAC => "CKM_SHA256_HMAC",
        ck::CKM_SHA384_HMAC => "CKM_SHA384_HMAC",
        ck::CKM_SHA512_HMAC => "CKM_SHA512_HMAC",
        _ => return format!("CKM_0x{m:04X}"),
    };
    name.to_string()
}

/// Audit-record name for a `CK_RV`. `CKR_OK` for 0; common codes get their
/// symbolic name; anything else is rendered numerically (`CKR_0x…`).
pub fn ckr_display_name(rv: u32) -> String {
    use softhsmrustv3::constants as ck;
    let name = match rv {
        0 => "CKR_OK",
        ck::CKR_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
        ck::CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        ck::CKR_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",
        ck::CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        ck::CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        _ => return format!("CKR_0x{rv:08X}"),
    };
    name.to_string()
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
        Ed25519 => "Ed25519",
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
        // CSD02 pre-hash Sign-time selectors (§11.12) — never a CreateKeyPair
        // target, only reachable via `CryptographicParameters.CryptographicAlgorithm`
        // on Sign/SignatureVerify. See the identical arms in
        // `ops/create_key_pair.rs::canonical_name`.
        HashSlhDsaSha2_128sWithSha256 => "Hash-SLH-DSA-SHA2-128s-with-SHA256",
        HashSlhDsaSha2_128fWithSha256 => "Hash-SLH-DSA-SHA2-128f-with-SHA256",
        HashSlhDsaSha2_192sWithSha512 => "Hash-SLH-DSA-SHA2-192s-with-SHA512",
        HashSlhDsaSha2_192fWithSha512 => "Hash-SLH-DSA-SHA2-192f-with-SHA512",
        HashSlhDsaSha2_256sWithSha512 => "Hash-SLH-DSA-SHA2-256s-with-SHA512",
        HashSlhDsaSha2_256fWithSha512 => "Hash-SLH-DSA-SHA2-256f-with-SHA512",
        HashSlhDsaShake128sWithShake128 => "Hash-SLH-DSA-SHAKE-128s-with-SHAKE128",
        HashSlhDsaShake128fWithShake128 => "Hash-SLH-DSA-SHAKE-128f-with-SHAKE128",
        HashSlhDsaShake192sWithShake256 => "Hash-SLH-DSA-SHAKE-192s-with-SHAKE256",
        HashSlhDsaShake192fWithShake256 => "Hash-SLH-DSA-SHAKE-192f-with-SHAKE256",
        HashSlhDsaShake256sWithShake256 => "Hash-SLH-DSA-SHAKE-256s-with-SHAKE256",
        HashSlhDsaShake256fWithShake256 => "Hash-SLH-DSA-SHAKE-256f-with-SHAKE256",
        HashMlDsa44WithSha512 => "Hash-ML-DSA-44-with-SHA512",
        HashMlDsa65WithSha512 => "Hash-ML-DSA-65-with-SHA512",
        HashMlDsa87WithSha512 => "Hash-ML-DSA-87-with-SHA512",
        X25519MlKem768 => "X25519MLKEM768",
        SecP256r1MlKem768 => "SecP256r1MLKEM768",
        SecP384r1MlKem1024 => "SecP384r1MLKEM1024",
        // BSI TR-02102-1 §2.4.1 — AES/SHAKE are both engine-executable
        // variants (see `to_pkcs11_mech`), but `kmip/policies/bsi-tr-02102.yaml`
        // and `policy/lint.rs::is_known_algorithm_name` only recognize the
        // bare `FrodoKEM-{640,976,1344}` form (no AES/SHAKE suffix) — both
        // variants of a level collapse to the same policy-facing name.
        FrodoKem640Aes | FrodoKem640Shake => "FrodoKEM-640",
        FrodoKem976Aes | FrodoKem976Shake => "FrodoKEM-976",
        FrodoKem1344Aes | FrodoKem1344Shake => "FrodoKEM-1344",
        // BSI TR-02102-1 §2.4.2.
        ClassicMcEliece6688128 => "Classic-McEliece-6688128",
        Hss => "HSS",
        // Matches `KmipAlgorithm::spec_name()`'s strings exactly.
        CompositeMlDsa44Rsa2048PssSha256 => "ML-DSA-44-RSA2048-PSS",
        CompositeMlDsa65EcdsaP256Sha512 => "ML-DSA-65-ECDSA-P256",
        CompositeMlDsa87EcdsaP384Sha512 => "ML-DSA-87-ECDSA-P384",
    }
    .into()
}

/// Curve/size-**qualified** algorithm name for policy evaluation, reconstructed
/// from the stored coarse [`KmipAlgorithm`] + its `cryptographic_length`. The
/// `KmipAlgorithm` enum collapses every EC curve to `Ecdsa`/`Ecdh` and every
/// RSA/AES size to one variant (`algos.rs:117`), so [`canonical_name`] alone
/// yields the bare `"ECDSA"`/`"RSA"`/`"AES"` — which never matches the
/// curve/size-qualified `from:`/allowlist/denylist entries the shipped policies
/// use (`pqc.yaml` `from: ECDSA-P256`, `cnsa-2.0.yaml` `ECDSA-P384`, …). This
/// reproduces the qualified form (`"ECDSA-P256"`, `"RSA-3072"`, `"AES-256"`) so
/// `algorithm_substitution` (and the auto-rekey path) actually fires on stored
/// keys. PQC + hash-based algorithms are already fully qualified by
/// `canonical_name`, so they pass through unchanged.
pub fn qualified_name(a: KmipAlgorithm, length: u32) -> String {
    use KmipAlgorithm::*;
    match a {
        Ecdsa => format!("ECDSA-P{}", ec_curve_bits(length)),
        // Montgomery curves collapse to `Ecdh` at the enum layer; when the
        // record carries the §6.7 mech-info length (255/448) they get their
        // own policy-facing names. Engine-native classical KEM keys currently
        // store length 0, so they fall through to `ECDH-P{P-curve}` — the
        // known `from:` collision the migration policies account for until the
        // Montgomery length is threaded onto the record (reassessment item).
        Ecdh => montgomery_name_for_len(length)
            .map(str::to_string)
            .unwrap_or_else(|| format!("ECDH-P{}", ec_curve_bits(length))),
        Rsa => format!("RSA-{}", if length == 0 { 2048 } else { length }),
        Aes => format!("AES-{}", if length == 0 { 256 } else { length }),
        other => canonical_name(other),
    }
}

/// Bit length a size-qualified CLASSICAL algorithm name implies —
/// `"AES-128"` → 128, `"RSA-3072"` → 3072, `"ECDSA-P384"` → 384. This is how
/// a policy default/substitution TARGET keeps its size on the label-only
/// path: the request template carries no `CryptographicLength`, so the
/// handlers derive it from the resolved string before generating material
/// (without this, a policy saying `AES-128` silently produced a 256-bit key
/// and `RSA-3072` a 2048-bit one). PQC names return `None` — their parameter
/// set encodes the size and the suffix is not a bit count (`ML-DSA-44`).
pub fn classical_length_from_name(name: &str) -> Option<u32> {
    let (family, suffix) = name.rsplit_once('-')?;
    let bits: u32 = suffix.trim_start_matches(['P', 'p']).parse().ok()?;
    match family {
        "AES" | "RSA" | "ECDSA" | "ECDH" => Some(bits),
        _ => None,
    }
}

/// Montgomery-curve policy name for a stored `Ecdh` key length — the §6.7
/// mech-info bit counts (255 → X25519, 448 → X448) distinguish the two
/// key-agreement curves from the NIST P-curves. `None` for any other length
/// (including the engine-native default of 0), so P-curve keys and
/// length-unset Montgomery keys keep the `ECDH-P{bits}` form.
fn montgomery_name_for_len(length: u32) -> Option<&'static str> {
    match length {
        255 => Some("X25519"),
        448 => Some("X448"),
        _ => None,
    }
}

/// Map a stored EC key length to its NIST curve bit-label (P-256 / P-384 /
/// P-521). Mirrors `create_key_pair::ecdsa_curve_from_length` (256/384/521).
fn ec_curve_bits(length: u32) -> u32 {
    match length {
        384 => 384,
        512 | 521 => 521,
        _ => 256,
    }
}

/// Curve/size-qualify a *bare* canonical algorithm STRING for policy
/// evaluation (Y3). The string counterpart to [`qualified_name`], used at the
/// Create / CreateKeyPair / Encrypt / Decrypt / MAC gates where the handler
/// has the coarse algorithm name (from the request template) plus its length,
/// but not a resolved [`KmipAlgorithm`] + record yet.
///
/// Before this fix those gates passed bare `"AES"`/`"RSA"`/`"ECDSA"`/`"ECDH"`,
/// so a policy allowlist entry `AES-256` (or denylist `AES-128`) never matched
/// and the rule was dead — simultaneously bricking `AES` Create (bare `AES` ∉
/// an `AES-256`-only allowlist) and letting `AES-128` through. Qualifying the
/// request means [`super::super::policy::rule::algo_matches`] can compare a
/// specific request against family-or-specific policy entries consistently.
///
/// PQC + hash-based + MAC names are already fully qualified upstream
/// (`canonical_name`), so they pass through unchanged. `None` length falls back
/// to the family default (AES-256 / RSA-2048 / P-256) — the same defaults
/// [`qualified_name`] uses.
pub fn qualify_algorithm_str(name: &str, key_length: Option<u32>) -> String {
    match name {
        "AES" => format!("AES-{}", key_length.filter(|&l| l != 0).unwrap_or(256)),
        "RSA" => format!("RSA-{}", key_length.filter(|&l| l != 0).unwrap_or(2048)),
        "ECDSA" => format!("ECDSA-P{}", ec_curve_bits(key_length.unwrap_or(256))),
        "ECDH" => key_length
            .and_then(montgomery_name_for_len)
            .map(str::to_string)
            .unwrap_or_else(|| format!("ECDH-P{}", ec_curve_bits(key_length.unwrap_or(256)))),
        _ => name.to_string(),
    }
}

/// Extract the KMIP custom/vendor attributes attached to a request into the
/// `{ bare_name → value }` map the policy engine consults (Y1).
///
/// KMIP carries policy-relevant classification tags as `x-`-prefixed Custom
/// attributes (e.g. `x-pqctoday-cnsa-classification`). The policy engine keys
/// on the bare name without the `x-` prefix (see
/// [`super::super::policy::request::PolicyRequest::custom_attrs`]); a
/// case-insensitive `x-` prefix is stripped here so a rule's
/// `attribute_name: pqctoday-cnsa-classification` matches. Non-`x-` custom
/// attributes are passed through verbatim.
///
/// Before this fix every op handler passed an empty map, so
/// `require_custom_attribute` (and the `exception_/triggered_by_custom_attribute`
/// escape/trigger hatches) could never see an attribute and permanently denied
/// their listed algorithms.
pub fn custom_attrs_from(attrs: &[crate::kmip30::Attribute]) -> std::collections::HashMap<String, String> {
    strip_x_prefixes(&raw_custom_attrs(attrs))
}

/// Collect the request's Custom attributes preserving their original (usually
/// `x-`-prefixed) names, for *persistence* onto the managed object. Register
/// stores attributes in this form so GetAttributes round-trips them verbatim
/// (BL-M-14); CreateKeyPair now does the same (Y1) so use-time policy gates can
/// read the classification back off the stored key. Typed (not `String`) so
/// an Integer/DateTime-valued custom attribute keeps its real wire type
/// through storage — see [`crate::kmip30::CustomAttributeValue`].
pub fn raw_custom_attrs(
    attrs: &[crate::kmip30::Attribute],
) -> std::collections::HashMap<String, crate::kmip30::CustomAttributeValue> {
    use crate::kmip30::Attribute;
    let mut m = std::collections::HashMap::new();
    for a in attrs {
        if let Attribute::Custom { name, value } = a {
            m.insert(name.clone(), value.clone());
        }
    }
    m
}

/// Normalise a stored custom-attribute map (whose keys keep the `x-` prefix) to
/// the bare-name form the policy engine keys on (Y1), stringifying each typed
/// value via [`crate::kmip30::CustomAttributeValue::as_policy_string`] — policy
/// YAML rules match on string patterns, so this is the one place the type
/// information intentionally collapses back to a string; the *stored* record
/// (`ObjectRecord.custom_attributes`) and the wire round-trip
/// (`GetAttributes`) stay typed. Used at use-time ops (Sign / Encrypt / …)
/// where the attributes come off the stored object, not the request.
pub fn strip_x_prefixes(
    raw: &std::collections::HashMap<String, crate::kmip30::CustomAttributeValue>,
) -> std::collections::HashMap<String, String> {
    raw.iter()
        .map(|(k, v)| {
            let bare = k
                .strip_prefix("x-")
                .or_else(|| k.strip_prefix("X-"))
                .unwrap_or(k);
            (bare.to_string(), v.as_policy_string())
        })
        .collect()
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

/// Part F §F7.3/F7.4 (rust-hsm-perf-bench-scenario-plan-07182026.md) —
/// the single choke point for owner-checked-by-UID object access.
/// Fetches `uid` and verifies the requester's identity matches the
/// object's recorded owner (`ObjectRecord::owner` — exact
/// `Option<String>` equality; see that field's doc for why this is not
/// a one-sided "no owner ⇒ public" rule). On ANY mismatch — missing
/// object OR wrong owner — calls `not_found()` for the error, so a
/// caller passes whatever "this UID doesn't exist" error THIS
/// operation already used before ownership existed (`Get` uses
/// `KmipError::object_not_found`, most others use the generic
/// `KmipError::not_found`) and gets the exact same code for "not
/// yours" — the anti-oracle property the user required (2026-07-18):
/// within any one operation, a foreign tenant's object is
/// indistinguishable from one that was never created.
pub(crate) fn authorize_object(
    deps: &super::deps::Deps,
    auth: &crate::server::auth::AuthContext,
    uid: &str,
    not_found: impl Fn() -> KmipError,
) -> std::result::Result<crate::store::ObjectRecord, KmipError> {
    let requester = auth.identity.as_ref().map(|i| i.username.clone());
    let obj = deps.store.get(uid)?.ok_or_else(&not_found)?;
    if obj.owner != requester {
        return Err(not_found());
    }
    Ok(obj)
}

/// Part F §F7.3 — stamp the creating identity onto a freshly-built
/// `ObjectRecord` BEFORE `store.put(...)`. `None` (Single mode / no
/// authenticated identity) stamps `owner: None`, matching every
/// existing test fixture and preserving today's behavior exactly.
pub(crate) fn stamp_owner(
    mut record: crate::store::ObjectRecord,
    auth: &crate::server::auth::AuthContext,
) -> crate::store::ObjectRecord {
    record.owner = auth.identity.as_ref().map(|i| i.username.clone());
    record
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
/// True for ML-DSA / SLH-DSA sign mechanisms (pure or pre-hash). These honor
/// the PQC interface knobs (Internal / External Mu / Deterministic / Context
/// String / Random) via `native::sign_pqc` instead of the classical
/// RSA-PSS-salt bridge.
pub fn is_pqc_sign_mech(mech: u32) -> bool {
    use softhsmrustv3::constants::{CKM_ML_DSA, CKM_SLH_DSA};
    mech == CKM_ML_DSA
        || mech == CKM_SLH_DSA
        || softhsmrustv3::crypto::is_prehash_ml_dsa(mech)
        || softhsmrustv3::crypto::is_prehash_slh_dsa(mech)
}

pub fn native_sign_mech_with_params(
    a: KmipAlgorithm,
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> Result<u32, KmipError> {
    use crate::kmip30::HashingAlgorithm as H;
    use softhsmrustv3::constants as c;
    use KmipAlgorithm::*;

    // CSD02 §11.12 pre-hash selectors (K23) — a client sets
    // `CryptographicParameters.CryptographicAlgorithm` to one of the 15
    // `Hash-ML-DSA-*-with-SHA512` / `Hash-SLH-DSA-*-with-*` values to invoke
    // FIPS 204/205's own pre-hash signing mode, alongside the stored key's
    // ordinary base algorithm (`a`) — these are Sign-time selectors, not a
    // second key type (see the enum variants' doc comment in algos.rs). Each
    // one names both a specific parameter set AND its one fixed hash (no
    // caller choice, unlike RSA/ECDSA's `HashingAlgorithm` below) — reject
    // a mismatch against the stored key's actual parameter set rather than
    // silently signing under the wrong one.
    if let Some(requested) = cp.and_then(|p| p.cryptographic_algorithm) {
        let prehash = match requested {
            HashMlDsa44WithSha512 => Some((MlDsa44, c::CKM_HASH_ML_DSA_SHA512)),
            HashMlDsa65WithSha512 => Some((MlDsa65, c::CKM_HASH_ML_DSA_SHA512)),
            HashMlDsa87WithSha512 => Some((MlDsa87, c::CKM_HASH_ML_DSA_SHA512)),
            HashSlhDsaSha2_128sWithSha256 => Some((SlhDsaSha2_128s, c::CKM_HASH_SLH_DSA_SHA256)),
            HashSlhDsaSha2_128fWithSha256 => Some((SlhDsaSha2_128f, c::CKM_HASH_SLH_DSA_SHA256)),
            HashSlhDsaSha2_192sWithSha512 => Some((SlhDsaSha2_192s, c::CKM_HASH_SLH_DSA_SHA512)),
            HashSlhDsaSha2_192fWithSha512 => Some((SlhDsaSha2_192f, c::CKM_HASH_SLH_DSA_SHA512)),
            HashSlhDsaSha2_256sWithSha512 => Some((SlhDsaSha2_256s, c::CKM_HASH_SLH_DSA_SHA512)),
            HashSlhDsaSha2_256fWithSha512 => Some((SlhDsaSha2_256f, c::CKM_HASH_SLH_DSA_SHA512)),
            HashSlhDsaShake128sWithShake128 => {
                Some((SlhDsaShake128s, c::CKM_HASH_SLH_DSA_SHAKE128))
            }
            HashSlhDsaShake128fWithShake128 => {
                Some((SlhDsaShake128f, c::CKM_HASH_SLH_DSA_SHAKE128))
            }
            HashSlhDsaShake192sWithShake256 => {
                Some((SlhDsaShake192s, c::CKM_HASH_SLH_DSA_SHAKE256))
            }
            HashSlhDsaShake192fWithShake256 => {
                Some((SlhDsaShake192f, c::CKM_HASH_SLH_DSA_SHAKE256))
            }
            HashSlhDsaShake256sWithShake256 => {
                Some((SlhDsaShake256s, c::CKM_HASH_SLH_DSA_SHAKE256))
            }
            HashSlhDsaShake256fWithShake256 => {
                Some((SlhDsaShake256f, c::CKM_HASH_SLH_DSA_SHAKE256))
            }
            _ => None,
        };
        if let Some((expected_base, mech)) = prehash {
            if a != expected_base {
                return Err(KmipError::unsupported_cryptographic_parameters(format!(
                    "Sign/Verify: CryptographicParameters.CryptographicAlgorithm \
                     {requested:?} requires a {expected_base:?} key, but this object \
                     is {a:?}",
                )));
            }
            return Ok(mech);
        }
    }

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
        // P1 (2026-07-05): pure EdDSA signs the message directly — no
        // caller-selectable hash parameter, unlike RSA/ECDSA above.
        Ed25519 => c::CKM_EDDSA,
        // HSS/LMS (RFC 8554) — no caller-selectable hash parameter either;
        // the hash family is fixed by the key's own LMS parameter set
        // (CKA_LMS_PARAM_SET), not by CryptographicParameters.
        Hss => c::CKM_HSS,
        other => {
            return Err(KmipError::failed(
                crate::error::ResultReason::OperationNotSupported,
                format!("no native sign mechanism for {other:?}"),
            ));
        }
    })
}

/// P0 (crypto-policy gaps plan) — the **single** "request → canonical
/// PKCS#11 `CKM_*` mechanism" resolver, accounting for the effective KMIP
/// `CryptographicParameters` (hash / block-cipher mode / padding), not just the
/// key algorithm. This is the identity the policy engine gates on, so a rule
/// means the same thing whether the request arrives via a standard KMIP op or
/// the PKCS#11 passthrough. It simply unifies the existing per-op resolvers
/// (`native_sign_mech_with_params`, `aes_mechanism_for`, `rsa_encrypt_mechanism_for`,
/// `KmipAlgorithm::to_pkcs11_mech`) — no new mechanism values are introduced.
///
/// Returns `None` when the (algorithm, op, params) triple has no resolvable
/// mechanism; the policy treats that as "not canonicalizable" (it still gates
/// on the algorithm), and the op handler's own resolver remains the authority
/// that errors on genuinely unsupported parameters.
pub fn canonical_mechanism(
    algo: KmipAlgorithm,
    op: crate::kmip30::PkcsOp,
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> Option<u32> {
    use crate::kmip30::PkcsOp::*;
    use KmipAlgorithm::*;
    match op {
        SignVerify => native_sign_mech_with_params(algo, cp).ok(),
        Encrypt | Decrypt => match algo {
            Aes => aes_mechanism_for(cp).ok(),
            Rsa => rsa_encrypt_mechanism_for(cp).ok(),
            // ML-KEM (encaps/decaps), ChaCha20 families, etc. are
            // parameter-agnostic at the mechanism level.
            _ => algo.to_pkcs11_mech(op),
        },
        // HMAC variants carry the hash in the algorithm itself; CMAC/KMAC
        // (no KMIP CryptographicAlgorithm) are handled in the CKM_* dialect
        // (plan P4), so fall through to the algorithm map here.
        Mac => algo.to_pkcs11_mech(Mac),
        KeyGen => algo.to_pkcs11_mech(KeyGen),
    }
}

/// P1 (crypto-policy gaps plan) — build the policy [`MechanismParams`] from the
/// effective KMIP `CryptographicParameters` + the canonical `CKM_*` (P0). This
/// is what the dispatcher hands the policy engine so mechanism/hash rules can
/// gate on the *mechanism*, not just the key algorithm. Pure projection: it
/// copies the already-decoded CP fields and resolves the canonical mechanism —
/// no values are minted here.
pub fn mechanism_params_from_cp(
    algo: KmipAlgorithm,
    op: crate::kmip30::PkcsOp,
    cp: Option<&crate::kmip30::CryptographicParameters>,
) -> crate::policy::MechanismParams {
    crate::policy::MechanismParams {
        hashing_algorithm: cp.and_then(|c| c.hashing_algorithm).map(|h| h as u32),
        block_cipher_mode: cp.and_then(|c| c.block_cipher_mode),
        padding_method: cp.and_then(|c| c.padding_method),
        mask_generator: cp.and_then(|c| c.mask_generator),
        tag_length: cp.and_then(|c| c.tag_length),
        salt_length: cp.and_then(|c| c.salt_length),
        deterministic: cp.and_then(|c| c.deterministic),
        internal: cp.and_then(|c| c.internal),
        external_mu: cp.and_then(|c| c.external_mu),
        canonical_mech: canonical_mechanism(algo, op, cp),
    }
}

/// P3 (crypto-policy gaps plan) — merge a policy [`crate::policy::CpOverride`]
/// over the request's effective `CryptographicParameters`. Each forced field
/// (hash / block-cipher mode / padding / deterministic) overrides the base; the
/// rest are preserved. Lets a policy transparently *mandate* a mechanism
/// (e.g. AES-GCM, RSA-OAEP-SHA256, deterministic ML-DSA) before the op resolves
/// the PKCS#11 mechanism. Codepoints are KMIP enum values (no re-encoding).
pub fn merge_cp_override(
    base: Option<&crate::kmip30::CryptographicParameters>,
    ov: &crate::policy::CpOverride,
) -> crate::kmip30::CryptographicParameters {
    let mut cp = base.cloned().unwrap_or_default();
    if let Some(h) = ov.hashing_algorithm {
        if let Some(ha) = crate::kmip30::HashingAlgorithm::from_wire_value(h) {
            cp.hashing_algorithm = Some(ha);
        }
    }
    if let Some(m) = ov.block_cipher_mode {
        cp.block_cipher_mode = Some(m);
    }
    if let Some(p) = ov.padding_method {
        cp.padding_method = Some(p);
    }
    if let Some(d) = ov.deterministic {
        cp.deterministic = Some(d);
    }
    // F-5 — MGF function / AEAD tag length / RSA-PSS salt length.
    if let Some(m) = ov.mask_generator {
        cp.mask_generator = Some(m);
    }
    if let Some(t) = ov.tag_length {
        cp.tag_length = Some(t);
    }
    if let Some(s) = ov.salt_length {
        cp.salt_length = Some(s);
    }
    cp
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
        FrodoKem640Aes | FrodoKem640Shake | FrodoKem976Aes
            | FrodoKem976Shake | FrodoKem1344Aes | FrodoKem1344Shake =>
            Some(c::CKM_PQCTODAY_FRODOKEM_ENCAPSULATE),
        ClassicMcEliece6688128 => Some(c::CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE),
        _ => None,
    }
}

/// Map a stored classical `Ecdh` object's `RecommendedCurve` to the engine
/// mechanism for `Encapsulate`/`Decapsulate` (2026-07-05, DHKEM). Per
/// PKCS#11 v3.2 §6.3.17, `CKM_ECDH1_DERIVE` covers the NIST Weierstrass
/// curves (P-256/P-384/P-521); X25519/X448 (Montgomery form) use the
/// distinct `CKM_EC_MONTGOMERY_KEY_DERIVE` mechanism instead — same
/// distinction `create_key_pair.rs`'s `Ecdh` branch already makes when
/// picking `generate_ecdh_keypair` vs `generate_x25519_keypair`/
/// `generate_x448_keypair`.
///
/// Deliberately does NOT fall back to a length-based guess the way
/// `qualified_name` does — `RecommendedCurve` is the only signal that
/// distinguishes X25519 (256 bits) from P-256 (also 256 bits) unambiguously.
pub fn classical_kem_mech(recommended_curve: Option<u32>) -> Option<u32> {
    use crate::kmip30::algos::recommended_curve as rc;
    use softhsmrustv3::constants as c;
    match recommended_curve {
        Some(rc::P_256) | Some(rc::P_384) | Some(rc::P_521) => Some(c::CKM_ECDH1_DERIVE),
        Some(rc::CURVE25519) | Some(rc::CURVE448) => Some(c::CKM_EC_MONTGOMERY_KEY_DERIVE),
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
        FrodoKem640Aes    => c::CKP_FRODOKEM_640_AES,
        FrodoKem640Shake  => c::CKP_FRODOKEM_640_SHAKE,
        FrodoKem976Aes    => c::CKP_FRODOKEM_976_AES,
        FrodoKem976Shake  => c::CKP_FRODOKEM_976_SHAKE,
        FrodoKem1344Aes   => c::CKP_FRODOKEM_1344_AES,
        FrodoKem1344Shake => c::CKP_FRODOKEM_1344_SHAKE,
        ClassicMcEliece6688128 => c::CKP_CLASSIC_MCELIECE_6688128,
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
        // Phase 3.3 — a Split Key part is a real engine `Generic Secret`
        // object (`native::split_key::split` registers it exactly like
        // `register_generic_secret_bytes`), same class as SecretData.
        ObjectType::SymmetricKey | ObjectType::SecretData | ObjectType::SplitKey => {
            c::CKO_SECRET_KEY
        }
        ObjectType::Certificate => c::CKO_CERTIFICATE,
        // KMIP-only object types — no PKCS#11 cryptoki class maps cleanly.
        // Surface as ItemNotFound by returning a sentinel that never
        // matches a real handle class (CKO_VENDOR_DEFINED start = 0x80000000).
        ObjectType::OpaqueObject
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
        c::CKR_PARAMETER_SET_NOT_SUPPORTED => KmipError::unsupported_cryptographic_parameters(
            format!("{op}: parameter set not supported by this engine"),
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
    auth: &crate::server::auth::AuthContext,
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
        auth, correlation_id,
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
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> crate::error::Result<Vec<u8>> {
    use crate::error::ResultReason;
    // P2.4 — the KEK is the *wrapping* object, so its resolution
    // failures carry the wrapping-specific KMIP 3.0 §11 reasons
    // (`Wrapping Object Not Found/Archived/Destroyed`, 0x42/0x40/0x41)
    // rather than the data object's generic `ObjectNotFound` (0x37) /
    // `WrongKeyLifecycleState` (0x43). The spec reserves these codes
    // precisely for KeyWrappingSpecification / KeyWrappingData KEK
    // resolution; verified against `kmip-spec-3.0-tags-enums.json`.
    //
    // Part F §F7.4 — the KEK is itself a by-UID key reference, so the
    // owner check applies here exactly like every other by-UID lookup:
    // a foreign tenant's KEK gets the SAME `Wrapping Object Not Found`
    // a genuinely missing KEK UID produces (anti-oracle). Without this,
    // any tenant could wrap/unwrap under another tenant's KEK by
    // guessing its UID.
    use crate::kmip30::State;
    let kek_obj = authorize_object(deps, auth, kek_uid, || {
        KmipError::wrapping_object_not_found(kek_uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, op, e))?;
    // Archived (off-line via the Archive op) takes precedence over the
    // lifecycle FSM — the material is unreachable until Recover.
    if kek_obj.archived {
        return Err(fail_err(deps, correlation_id, op,
            KmipError::wrapping_object_archived(kek_uid)));
    }
    if kek_obj.state != State::Active {
        // Destroyed KEK material is gone → the wrapping-specific
        // `Wrapping Object Destroyed`. Other non-Active states
        // (PreActive / Deactivated / Compromised) keep the generic
        // lifecycle reason — the spec has no wrapping-specific code
        // for those.
        if matches!(kek_obj.state, State::Destroyed | State::DestroyedCompromised) {
            return Err(fail_err(deps, correlation_id, op,
                KmipError::wrapping_object_destroyed(kek_uid)));
        }
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
            .resolve_tenant_session(auth.identity.as_ref())
            .ok()
            .and_then(|session| {
                // WP-4 remediation — class-aware, not the ambiguous
                // class-blind find_by_cka_id (low urgency in practice: the
                // AES-KW length check below already fails safe on a
                // wrong-class handle, but this keeps the pattern
                // consistent everywhere it's used).
                find_handle_for_object(session, &kek_obj.pkcs11_cka_id, kek_obj.object_type)
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
    auth: &crate::server::auth::AuthContext,
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
        auth, correlation_id,
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

/// Serialise every test (in any `ops::*` module) that touches a real
/// engine session. The engine's session/token state is process-global
/// (`lazy_static!`, not thread-local), and `cargo test` runs `#[test]`
/// fns on separate threads by default — so two engine-touching tests in
/// *different* files, each guarded only by a lock private to its own
/// module, can still race each other (one test's `session::finalize()`
/// invalidating a handle another test is mid-use with). This ONE shared
/// lock, used by every such module (`certify.rs`, `spki_verify.rs`, …),
/// is what actually prevents that.
#[cfg(test)]
pub(crate) fn engine_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
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
            (
                c::CKR_PARAMETER_SET_NOT_SUPPORTED,
                ResultReason::UnsupportedCryptographicParameters,
            ),
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
    fn canonical_mechanism_unifies_param_aware_resolution() {
        use crate::kmip30::{HashingAlgorithm, KmipAlgorithm::*, PkcsOp};
        // AES encrypt: block-cipher mode / padding → exact CKM_*.
        assert_eq!(
            canonical_mechanism(Aes, PkcsOp::Encrypt, Some(&cp(Some(9), None, None))),
            Some(c::CKM_AES_GCM)
        );
        assert_eq!(
            canonical_mechanism(Aes, PkcsOp::Encrypt, Some(&cp(Some(1), Some(3), None))),
            Some(c::CKM_AES_CBC_PAD)
        );
        // RSA sign: padding + hash → PSS vs PKCS1, hash-specific.
        assert_eq!(
            canonical_mechanism(
                Rsa,
                PkcsOp::SignVerify,
                Some(&cp(None, Some(0x0a), Some(HashingAlgorithm::Sha256)))
            ),
            Some(c::CKM_SHA256_RSA_PKCS_PSS)
        );
        assert_eq!(
            canonical_mechanism(
                Rsa,
                PkcsOp::SignVerify,
                Some(&cp(None, Some(0x08), Some(HashingAlgorithm::Sha384)))
            ),
            Some(c::CKM_SHA384_RSA_PKCS)
        );
        // PQC: parameter-agnostic at the mechanism level.
        assert_eq!(canonical_mechanism(MlDsa65, PkcsOp::SignVerify, None), Some(c::CKM_ML_DSA));
        assert_eq!(canonical_mechanism(MlKem768, PkcsOp::Encrypt, None), Some(c::CKM_ML_KEM));
    }

    #[test]
    fn merge_cp_override_applies_forced_fields() {
        use crate::kmip30::HashingAlgorithm;
        use crate::policy::CpOverride;
        // Base mode = CBC (0x01); a forcing rule mandates GCM (0x09).
        let base = cp(Some(0x01), None, None);
        let merged = merge_cp_override(
            Some(&base),
            &CpOverride { block_cipher_mode: Some(0x09), ..Default::default() },
        );
        assert_eq!(merged.block_cipher_mode, Some(0x09));
        // Force deterministic + hash onto an empty base.
        let merged2 = merge_cp_override(
            None,
            &CpOverride {
                deterministic: Some(true),
                hashing_algorithm: Some(0x06), // KMIP SHA-256
                ..Default::default()
            },
        );
        assert_eq!(merged2.deterministic, Some(true));
        assert_eq!(merged2.hashing_algorithm, Some(HashingAlgorithm::Sha256));
    }

    #[test]
    fn mechanism_params_projects_cp_and_resolves_canonical_mech() {
        use crate::kmip30::{HashingAlgorithm, KmipAlgorithm, PkcsOp};
        let c0 = crate::kmip30::CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::Sha256),
            padding_method: Some(0x0a), // PSS
            deterministic: Some(true),
            ..Default::default()
        };
        let mp = mechanism_params_from_cp(KmipAlgorithm::Rsa, PkcsOp::SignVerify, Some(&c0));
        assert_eq!(mp.hashing_algorithm, Some(0x06)); // KMIP SHA-256 codepoint
        assert_eq!(mp.padding_method, Some(0x0a));
        assert_eq!(mp.deterministic, Some(true));
        assert_eq!(mp.canonical_mech, Some(c::CKM_SHA256_RSA_PKCS_PSS));
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

    // ── P2.4 — Wrapping Object Not Found / Archived / Destroyed ─────
    //
    // `wrap_key_value` (Get K16) / `unwrap_key_value` (Register K17)
    // resolve the KEK by UID through `resolve_kek`. The wrapping object
    // carries the wrapping-specific KMIP 3.0 §11 reasons (0x42/0x40/
    // 0x41), not the data object's generic ObjectNotFound (0x37) /
    // WrongKeyLifecycleState (0x43).

    fn wrap_deps() -> Deps {
        use crate::auditlog::{AuditSink, RingSink};
        use crate::policy::{load_from_str, Engine};
        use crate::store::MemoryStore;
        use std::sync::Arc;
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, crate::ops::deps::DepsConfig::default())
    }

    fn put_kek(d: &Deps, uid: &str, state: crate::kmip30::State, archived: bool) {
        use crate::store::ObjectRecord;
        d.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: crate::kmip30::ObjectType::SymmetricKey,
            algorithm: crate::kmip30::KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: crate::kmip30::UsageMask::WRAP_KEY,
            state,
            archived,
            key_material: Some(vec![0x11; 32]),
            ..ObjectRecord::default()
        }).unwrap();
    }

    fn wrap_spec(kek_uid: &str) -> crate::kmip30::KeyWrappingSpec {
        crate::kmip30::KeyWrappingSpec {
            wrapping_method: 0x01,
            encryption_key_uid: kek_uid.into(),
            cryptographic_parameters: None,
            encoding_option: None,
            mac_signature_key_information_present: false,
        }
    }

    #[test]
    fn wrap_kek_missing_returns_wrapping_object_not_found() {
        let d = wrap_deps();
        let err = wrap_key_value(&d, "Get", &wrap_spec("nope"), &[0u8; 32], &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrappingObjectNotFound);
    }

    #[test]
    fn wrap_kek_archived_returns_wrapping_object_archived() {
        let d = wrap_deps();
        put_kek(&d, "kek", crate::kmip30::State::Active, true);
        let err = wrap_key_value(&d, "Get", &wrap_spec("kek"), &[0u8; 32], &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrappingObjectArchived);
    }

    #[test]
    fn wrap_kek_destroyed_returns_wrapping_object_destroyed() {
        let d = wrap_deps();
        put_kek(&d, "kek", crate::kmip30::State::Destroyed, false);
        let err = wrap_key_value(&d, "Get", &wrap_spec("kek"), &[0u8; 32], &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrappingObjectDestroyed);
    }

    #[test]
    fn wrap_kek_deactivated_keeps_generic_lifecycle_reason() {
        // Non-archived, non-destroyed but non-Active KEK keeps the
        // generic WrongKeyLifecycleState — the spec has no wrapping-
        // specific reason for Deactivated/Compromised/PreActive.
        let d = wrap_deps();
        put_kek(&d, "kek", crate::kmip30::State::Deactivated, false);
        let err = wrap_key_value(&d, "Get", &wrap_spec("kek"), &[0u8; 32], &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }
}
