//! K20 — KMIP 3.0 §6.1.18 **Derive Key** (op codepoint `0x05`).
//!
//! > "This request is used to derive a Symmetric Key or Secret Data
//! > object from keys or Secret Data objects that are already known to
//! > the key management system."
//!
//! ## Methods implemented (§11.15 Table 546)
//!
//! | Method | Construction (spec sentence) |
//! |---|---|
//! | `HMAC` (0x03)  | "derives a key by computing an HMAC over the derivation data" — single HMAC keyed by the base object; output truncated to Cryptographic Length |
//! | `HASH` (0x02)  | "derives a key by computing a hash over the derivation key or the derivation data" |
//! | `PBKDF2` (0x01)| PKCS#5 / RFC 2898 — password = base object material, Salt + Iteration Count from Derivation Parameters (§7.13 Table 465) |
//! | `NIST800-108-C` (0x05) | SP 800-108 KDF in Counter Mode — `K(i) = HMAC(K, [i]₂ ‖ DerivationData)`, 32-bit big-endian counter from 1 (same fixed-input convention as the engine's `CKM_SP800_108_COUNTER_KDF` legacy default, `rust/src/ffi.rs`) |
//!
//! `ENCRYPT` / `NIST800-108-F` / `NIST800-108-DPI` / `Asymmetric Key`
//! / `AWS Signature Version 4` / `HKDF` fail with `Operation Not
//! Supported` — one of the §6.1.18.1 Table 304 reasons — because this
//! stack has no honest backing for them at the KMIP layer.
//!
//! ## Key-material routing (K15 convention, compliance-audit B-9)
//!
//! - **Engine-resident base key** (no `key_material` in the KMIP
//!   store, engine session wired): the HMAC-family PRFs (HMAC /
//!   NIST800-108-C) run through `softhsmrustv3::native::sign` with
//!   `CKM_SHA{256,384,512}_HMAC` — the base key bytes never leave the
//!   engine. Audit names `native::sign`.
//! - **KMIP-store-only base key** (Register'd raw bytes): in-process
//!   `hmac` / `sha2` / `pbkdf2` crates. Audit names `soft::derive`.
//! - PBKDF2 / HASH need the raw base bytes (no engine primitive for
//!   "PBKDF2 over CKA_VALUE" / "digest of CKA_VALUE") — an
//!   engine-resident base without store material fails with
//!   `Key Value Not Present (0x13)` per Table 304.
//!
//! ## Links (§6.1.18)
//!
//! > "For the keys or Secret Data objects from which the key … is
//! > derived, the server SHALL create a Derived Object Link attribute
//! > pointing to the … object derived … For the … object derived as a
//! > result of this operation, the server SHALL create a Derivation
//! > Base Object Link attribute pointing to the keys or Secret Data
//! > objects from which the key … is derived."

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    DerivationMethod, DeriveKeyRequest, DeriveKeyResponse, HashingAlgorithm, KmipAlgorithm,
    ObjectType, State, UsageMask,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{
    emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err,
    state_name,
};

/// Links-map keys (canonical attribute names, §4.35.5 / §11; wire
/// tags `Derivation Object Link` 0x420192 / `Derived Object Link`
/// 0x420193 — `get_attributes::attributes_from_record` emits them).
const LINK_DERIVATION_BASE: &str = "DerivationBaseObjectLink";
const LINK_DERIVED_OBJECT: &str = "DerivedObjectLink";

pub fn derive_key(
    deps: &Deps,
    mut req: DeriveKeyRequest,
    correlation_id: &str,
) -> Result<DeriveKeyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "DeriveKey",
        format!(
            "object_type={:?} method={:?} bases={}",
            req.object_type,
            req.derivation_method,
            req.uids.len()
        ),
    );
    let fail = |e: KmipError| fail_err(deps, correlation_id, "DeriveKey", e);

    // §6.1.18 — "derive a Symmetric Key or Secret Data object".
    // Anything else → `Invalid Object Type` (Table 304).
    if req.object_type != ObjectType::SymmetricKey && req.object_type != ObjectType::SecretData {
        return Err(fail(KmipError::invalid_object_type(format!(
            "DeriveKey creates SymmetricKey | SecretData only; got {:?}",
            req.object_type
        ))));
    }

    // Table 302 — `Unique Identifier` is REQUIRED ("MAY be repeated").
    if req.uids.is_empty() {
        return Err(fail(KmipError::invalid_field(
            "DeriveKey requires at least one Unique Identifier (base object)",
        )));
    }

    // Resolve every base object; §6.1.18 gates apply to each:
    // exists (Object Not Found), Active (Wrong Key Lifecycle State),
    // and "the Derive Key bit set in the Cryptographic Usage Mask
    // attribute … If the operation is issued for an object that does
    // not have this bit set, then the server SHALL return an error"
    // (Incompatible Cryptographic Usage Mask, K12/audit K-9).
    let mut bases: Vec<ObjectRecord> = Vec::with_capacity(req.uids.len());
    for uid in &req.uids {
        let obj = deps
            .store
            .get(uid)?
            .ok_or_else(|| fail(KmipError::object_not_found(uid)))?;
        if obj.state != State::Active {
            return Err(fail(super::helpers::non_active_state_error(&obj.uid, obj.state)));
        }
        super::helpers::enforce_usage_mask(
            deps,
            correlation_id,
            "DeriveKey",
            &obj,
            UsageMask::DERIVE_KEY,
        )?;
        bases.push(obj);
    }

    // Plane-1 policy gate against the primary base object.
    {
        let stored_attrs = super::helpers::strip_x_prefixes(&bases[0].custom_attributes);
        let algo = super::helpers::qualified_name(bases[0].algorithm, bases[0].cryptographic_length);
        let mut p_req =
            PolicyRequest::minimal("DeriveKey", Some(&algo), started, correlation_id, &stored_attrs);
        p_req.state = Some(state_name(bases[0].state));
        p_req.target_uid = Some(&bases[0].uid);
        if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
            return Err(fail(KmipError::permission_denied(human)));
        }
    }

    // §7.13 — "Derivation data MAY either be explicitly provided by
    // the client with the Derivation Data field or implicitly provided
    // by providing the Unique Identifier of a Secret Data object. If
    // both are provided, then an error SHALL be returned."
    //
    // Interpretation (documented): the FIRST UID is the derivation
    // base (key or Secret Data password); ADDITIONAL Secret Data UIDs
    // supply implicit derivation data (concatenated in request order).
    let mut implicit_data: Option<Vec<u8>> = None;
    for extra in &bases[1..] {
        if extra.object_type != ObjectType::SecretData {
            return Err(fail(KmipError::invalid_field(format!(
                "DeriveKey: additional base object {} must be SecretData \
                 (implicit Derivation Data per §7.13); got {:?}",
                extra.uid, extra.object_type
            ))));
        }
        let material = extra.key_material.clone().ok_or_else(|| {
            fail(KmipError::key_value_not_present(format!(
                "SecretData {} carries no key material to use as Derivation Data",
                extra.uid
            )))
        })?;
        implicit_data.get_or_insert_with(Vec::new).extend_from_slice(&material);
    }
    let derivation_data: Option<Vec<u8>> =
        match (req.derivation_parameters.derivation_data.take(), implicit_data) {
            (Some(_), Some(_)) => {
                return Err(fail(KmipError::invalid_field(
                    "Derivation Data provided both explicitly and via a SecretData \
                     Unique Identifier — §7.13: \"If both are provided, then an \
                     error SHALL be returned\"",
                )));
            }
            (explicit, implicit) => explicit.or(implicit),
        };

    // K19 — §6.1.58 Set Defaults under the client template, then lift
    // the template attributes (same pipeline as Create).
    super::allocation_and_config::apply_object_defaults(
        deps,
        req.object_type,
        &[],
        &mut req.template_attribute,
    );
    let x = super::register_import_export::extract_attrs(&req.template_attribute);

    // §6.1.18 — "For all derivation methods, the client SHALL specify
    // the desired length … If a key is created, then the client SHALL
    // specify both its Cryptographic Length and Cryptographic
    // Algorithm." Missing → `Invalid Field` (Table 304).
    let length_bits = x.length.ok_or_else(|| {
        fail(KmipError::invalid_field(
            "DeriveKey requires CryptographicLength in Attributes (§6.1.18)",
        ))
    })?;
    if length_bits == 0 || length_bits % 8 != 0 {
        return Err(fail(KmipError::invalid_attribute(format!(
            "CryptographicLength must be a positive multiple of 8 bits; got {length_bits}"
        ))));
    }
    let len_bytes = (length_bits / 8) as usize;
    let derived_algorithm = match (x.algorithm, req.object_type) {
        (Some(a), _) => a,
        (None, ObjectType::SymmetricKey) => {
            return Err(fail(KmipError::invalid_field(
                "DeriveKey requires CryptographicAlgorithm for a SymmetricKey \
                 (§6.1.18: \"the length and algorithm SHALL always be specified \
                 for the creation of a symmetric key\")",
            )));
        }
        // SecretData — same sentinel convention as Register (§6.1.48):
        // CryptographicAlgorithm is not in the SecretData §11 attribute
        // table; the slot is never surfaced.
        (None, _) => KmipAlgorithm::Rsa,
    };

    // §11 Result Reason — duplicate `Name` → NonUniqueNameAttribute
    // (0x35), listed in Table 304 (same gate as Register / Create).
    if let Some(ref n) = x.name {
        let dup = deps
            .store
            .find(&|r| r.name.as_deref() == Some(n.as_str()))
            .unwrap_or_default();
        if !dup.is_empty() {
            return Err(fail(KmipError::non_unique_name_attribute(n)));
        }
    }

    let cp = req.derivation_parameters.cryptographic_parameters.as_ref();
    let request_hash = cp.and_then(|c| c.hashing_algorithm);
    let base = &bases[0];

    // Derive the raw output per the method's spec construction.
    let raw: Vec<u8> = match req.derivation_method {
        // §11.15 Table 546 — "This method derives a key by computing
        // an HMAC over the derivation data." §7.13 — "If a key is
        // derived using HMAC, then the attributes of the derivation
        // key provide enough information about the PRF, and the
        // Cryptographic Parameters are ignored."
        DerivationMethod::Hmac => {
            let data = derivation_data.as_deref().ok_or_else(|| {
                fail(KmipError::invalid_field(
                    "HMAC derivation requires Derivation Data (§7.13 Table 465)",
                ))
            })?;
            let hash = base_key_prf_hash(base)
                .ok_or_else(|| fail(KmipError::bad_cryptographic_parameters(format!(
                    "HMAC derivation: base key {} attributes identify no PRF \
                     (algorithm {:?}; §7.13 — Cryptographic Parameters are ignored)",
                    base.uid, base.algorithm
                ))))?;
            let out = hmac_prf(deps, correlation_id, base, hash)?(data)?;
            // §6.1.18 — "If the specified length exceeds the output of
            // the derivation method, then the server SHALL return an
            // error." Single HMAC ⇒ output = one hash block.
            take_prefix(out, len_bytes).map_err(&fail)?
        }

        // §11.15 Table 546 — "This method derives a key by computing a
        // hash over the derivation key or the derivation data." §7.13
        // — "The HASH derivation method REQUIRES either a derivation
        // key or derivation data" and "clients are REQUIRED to
        // indicate the hash algorithm inside Cryptographic Parameters".
        DerivationMethod::Hash => {
            let hash = request_hash.ok_or_else(|| {
                fail(KmipError::bad_cryptographic_parameters(
                    "HASH derivation requires Hashing Algorithm inside \
                     Cryptographic Parameters (§7.13)",
                ))
            })?;
            let input: Vec<u8> = match &derivation_data {
                Some(d) => d.clone(),
                None => base.key_material.clone().ok_or_else(|| {
                    fail(KmipError::key_value_not_present(format!(
                        "HASH derivation over the derivation key needs the base \
                         object's material; {} holds none the KMIP layer can read",
                        base.uid
                    )))
                })?,
            };
            let out = soft_digest(hash, &input).map_err(&fail)?;
            emit_pkcs11(deps, correlation_id, "soft::derive", None, 0, "CKR_OK");
            take_prefix(out, len_bytes).map_err(&fail)?
        }

        // §11.15 Table 546 — "This method is used to derive a
        // symmetric key from a password or pass phrase" per PKCS#5 /
        // RFC 2898. Table 465: Salt + Iteration Count REQUIRED.
        // PRF = HMAC with the Cryptographic Parameters hash; this
        // stack ships no SHA-1, so the PKCS#5 default PRF is upgraded
        // to HMAC-SHA-256 when the client names no hash (documented
        // deviation; SHA-1 requests fail honestly below).
        DerivationMethod::Pbkdf2 => {
            let salt = req.derivation_parameters.salt.as_deref().ok_or_else(|| {
                fail(KmipError::invalid_field(
                    "PBKDF2 derivation requires Salt (§7.13 Table 465)",
                ))
            })?;
            let iterations = req.derivation_parameters.iteration_count.ok_or_else(|| {
                fail(KmipError::invalid_field(
                    "PBKDF2 derivation requires Iteration Count (§7.13 Table 465)",
                ))
            })?;
            if iterations <= 0 {
                return Err(fail(KmipError::invalid_field(format!(
                    "PBKDF2 Iteration Count must be positive; got {iterations}"
                ))));
            }
            let password = base.key_material.as_deref().ok_or_else(|| {
                fail(KmipError::key_value_not_present(format!(
                    "PBKDF2 needs the base object's material as the password; \
                     {} holds none the KMIP layer can read",
                    base.uid
                )))
            })?;
            let hash = request_hash.unwrap_or(HashingAlgorithm::Sha256);
            let mut out = vec![0u8; len_bytes];
            match hash {
                HashingAlgorithm::Sha256 => {
                    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations as u32, &mut out)
                }
                HashingAlgorithm::Sha384 => {
                    pbkdf2::pbkdf2_hmac::<Sha384>(password, salt, iterations as u32, &mut out)
                }
                HashingAlgorithm::Sha512 => {
                    pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations as u32, &mut out)
                }
                other => {
                    return Err(fail(KmipError::unsupported_cryptographic_parameters(
                        format!("PBKDF2 PRF hash {other:?} not supported (SHA-256/384/512)"),
                    )));
                }
            }
            emit_pkcs11(deps, correlation_id, "soft::derive", None, 0, "CKR_OK");
            out
        }

        // §11.15 Table 546 — "This method derives a key by computing
        // the KDF in Counter Mode [SP800-108]." §7.13 — "For the NIST
        // SP 800-108 methods, Derivation Data is Label||{0x00}||
        // Context". Fixed-input convention: K(i) = HMAC(K, [i]₂ ‖
        // DerivationData) with a 32-bit big-endian counter from 1 —
        // identical to the engine's `CKM_SP800_108_COUNTER_KDF`
        // "legacy default … 32-bit BE counter prefix" (rust/src/ffi.rs)
        // and NIST CAVP's CTRLOCATION=BEFORE_FIXED / RLEN=32 layout.
        DerivationMethod::Nist800_108C => {
            let data = derivation_data.as_deref().ok_or_else(|| {
                fail(KmipError::invalid_field(
                    "NIST800-108-C derivation requires Derivation Data \
                     (Label||{0x00}||Context per §7.13)",
                ))
            })?;
            // PRF hash: request Cryptographic Parameters win, else the
            // base key's HMAC algorithm, else SHA-256 (engine parity).
            let hash = request_hash
                .or_else(|| base_key_prf_hash(base))
                .unwrap_or(HashingAlgorithm::Sha256);
            let prf = hmac_prf(deps, correlation_id, base, hash)?;
            let mut out: Vec<u8> = Vec::with_capacity(len_bytes);
            let mut counter: u32 = 1;
            while out.len() < len_bytes {
                let mut block_input = counter.to_be_bytes().to_vec();
                block_input.extend_from_slice(data);
                out.extend_from_slice(&prf(&block_input)?);
                counter += 1;
            }
            out.truncate(len_bytes);
            out
        }

        // §7.13 — Asymmetric Key agreement (ECDH / X25519 / X448). The base
        // object is the stored EC/ECDH PRIVATE key (engine-backed,
        // non-extractable); the peer's public key is the Derivation Data. The
        // engine computes the DH shared secret in-HSM (the private scalar never
        // leaves it); we take the requested length as the derived key material
        // (KMIP Usage-Guide truncation convention — a client wanting a KDF over
        // it chains a HASH/HMAC DeriveKey).
        DerivationMethod::AsymmetricKey => {
            let peer_public = derivation_data.as_deref().ok_or_else(|| {
                fail(KmipError::invalid_field(
                    "Asymmetric Key derivation requires the peer public key as \
                     Derivation Data (§7.13 Table 465)",
                ))
            })?;
            let session = deps.engine_session.ok_or_else(|| {
                fail(KmipError::failed(
                    ResultReason::CryptographicFailure,
                    "Asymmetric Key derivation requires an engine session".to_string(),
                ))
            })?;
            let handle = super::helpers::find_handle_for_object(
                session,
                &base.pkcs11_cka_id,
                ObjectType::PrivateKey,
            )
            .map_err(|rv| fail(super::helpers::ck_rv_to_kmip_error(rv, "DeriveKey:find")))?
            .ok_or_else(|| fail(KmipError::object_not_found(&base.uid)))?;
            let ss = softhsmrustv3::native::ecdh_agree(session, handle, peer_public)
                .map_err(|rv| fail(super::helpers::ck_rv_to_kmip_error(rv, "DeriveKey:ecdh_agree")))?;
            take_prefix(ss, len_bytes).map_err(&fail)?
        }

        // §6.1.18.1 Table 304 lists `Operation Not Supported` — the
        // honest reason for methods this stack cannot back (no engine
        // primitive reachable from the KMIP layer and no in-process
        // implementation): ENCRYPT, the SP 800-108 Feedback /
        // Double-Pipeline modes, AWS SigV4, and HKDF.
        other => {
            return Err(fail(KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Derivation Method {other:?} is not supported (K20: PBKDF2 | HASH | HMAC | NIST800-108-C)"),
            )));
        }
    };
    debug_assert_eq!(raw.len(), len_bytes);

    // ── Persist the derived object (full K11/K19 attribute pipeline) ──
    let uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
    let now = OffsetDateTime::now_utc();
    let initial_state = super::register_import_export::compute_initial_state(now, &x);
    let cka_id_bytes = Uuid::new_v4().as_bytes().to_vec();

    // Mirror Register's engine-import convention: HMAC-family
    // symmetric keys land as engine generic-secret objects (K9
    // machinery) so MAC / future derives can use the engine handle;
    // other derived material stays KMIP-store-held (same as Register'd
    // raw AES, which Encrypt serves from `key_material`).
    if let (Some(session), ObjectType::SymmetricKey) = (deps.engine_session, req.object_type) {
        if matches!(
            derived_algorithm,
            KmipAlgorithm::HmacSha256 | KmipAlgorithm::HmacSha384 | KmipAlgorithm::HmacSha512
        ) {
            let _ = softhsmrustv3::native::register_generic_secret_bytes(
                session,
                &raw,
                &cka_id_bytes,
                "kmip-derive",
            );
        }
    }

    // K-14 — KMIP §11 `Digest`: SHA-256 over the derived material
    // (Register convention for store-held bytes).
    let digest_value = Some(Sha256::digest(&raw).to_vec());

    let mut links: HashMap<String, String> = HashMap::new();
    // §6.1.18 — Derivation Base Object Link on the derived object,
    // pointing at the base. The links map holds one UID per link type;
    // the primary base is recorded (multi-base requests keep the
    // mirror DerivedObjectLink on EVERY base below).
    links.insert(LINK_DERIVATION_BASE.to_string(), base.uid.clone());

    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type: req.object_type,
        algorithm: derived_algorithm,
        cryptographic_length: length_bits,
        usage_mask: x.usage.unwrap_or_else(UsageMask::empty),
        state: initial_state,
        pkcs11_cka_id: cka_id_bytes,
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: x.activation_date,
        deactivation_date: x.deactivation_date,
        compromise_date: x.compromise_date,
        compromise_occurrence_date: x.compromise_date,
        process_start_date: x.process_start_date,
        protect_stop_date: x.protect_stop_date,
        usage_limits_total: x.usage_limits_total,
        usage_limits_remaining: x.usage_limits_total,
        usage_limits_unit: x.usage_limits_unit,
        application_specific_information: x.application_specific_information.clone(),
        last_change_date: Some(now),
        original_creation_date: Some(now),
        cryptographic_parameters: x.cryptographic_parameters.clone(),
        supersedes: None,
        name: x.name.clone(),
        links,
        custom_attributes: HashMap::new(),
        key_material: Some(raw),
        key_format_type: Some(0x01), // Raw — §6.2 KeyFormatType table
        digest_value,
        // KMIP §11 Fresh = True for server-generated objects.
        fresh: Some(true),
        ..ObjectRecord::default()
    })?;

    // §6.1.18 — "the server SHALL create a Derived Object Link
    // attribute pointing to the … object derived as a result of this
    // operation" on EVERY base object used for the derivation.
    for mut b in bases {
        b.links.insert(LINK_DERIVED_OBJECT.to_string(), uid.clone());
        b.last_change_date = Some(now);
        deps.store.update(b)?;
    }

    emit_success(deps, correlation_id, "DeriveKey");
    Ok(DeriveKeyResponse { uid })
}

/// §7.13 — "the attributes of the derivation key provide enough
/// information about the PRF": map the base object's algorithm (or its
/// stored CryptographicParameters attribute) to the HMAC hash.
fn base_key_prf_hash(base: &ObjectRecord) -> Option<HashingAlgorithm> {
    match base.algorithm {
        KmipAlgorithm::HmacSha256 => Some(HashingAlgorithm::Sha256),
        KmipAlgorithm::HmacSha384 => Some(HashingAlgorithm::Sha384),
        KmipAlgorithm::HmacSha512 => Some(HashingAlgorithm::Sha512),
        _ => base.cryptographic_parameters.as_ref().and_then(|cp| cp.hashing_algorithm),
    }
}

/// HMAC PRF over the base object, routed per the K15 convention:
/// engine-resident keys → `native::sign` with `CKM_SHA*_HMAC` (audit
/// `native::sign`); KMIP-store-only keys → in-process `hmac` crate
/// (audit `soft::derive`). Neither reachable → `Key Value Not Present`.
#[allow(clippy::type_complexity)]
fn hmac_prf<'a>(
    deps: &'a Deps,
    correlation_id: &'a str,
    base: &'a ObjectRecord,
    hash: HashingAlgorithm,
) -> Result<Box<dyn Fn(&[u8]) -> Result<Vec<u8>> + 'a>> {
    let fail = move |e: KmipError| fail_err(deps, correlation_id, "DeriveKey", e);
    match (&base.key_material, deps.engine_session) {
        (Some(key), _) => {
            let key = key.clone();
            Ok(Box::new(move |data: &[u8]| {
                let out = soft_hmac(hash, &key, data)?;
                emit_pkcs11(deps, correlation_id, "soft::derive", None, 0, "CKR_OK");
                Ok(out)
            }))
        }
        (None, Some(session)) => {
            use softhsmrustv3::constants as c;
            let mech = match hash {
                HashingAlgorithm::Sha256 => c::CKM_SHA256_HMAC,
                HashingAlgorithm::Sha384 => c::CKM_SHA384_HMAC,
                HashingAlgorithm::Sha512 => c::CKM_SHA512_HMAC,
                other => {
                    return Err(fail(KmipError::unsupported_cryptographic_parameters(
                        format!("HMAC PRF hash {other:?} not supported (SHA-256/384/512)"),
                    )));
                }
            };
            let handle = super::helpers::find_handle_for_object(
                session,
                &base.pkcs11_cka_id,
                base.object_type,
            )
            .map_err(|rv| fail(super::helpers::ck_rv_to_kmip_error(rv, "DeriveKey")))?
            .ok_or_else(|| fail(KmipError::object_not_found(&base.uid)))?;
            Ok(Box::new(move |data: &[u8]| {
                let r = softhsmrustv3::native::sign(session, handle, mech, data);
                emit_pkcs11_result(deps, correlation_id, "native::sign", Some(mech), &r);
                r.map_err(|rv| fail(super::helpers::ck_rv_to_kmip_error(rv, "DeriveKey")))
            }))
        }
        (None, None) => Err(fail(KmipError::key_value_not_present(format!(
            "base object {} holds no key material the KMIP layer can reach \
             (no store bytes, no engine session)",
            base.uid
        )))),
    }
}

fn soft_hmac(hash: HashingAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    macro_rules! mac {
        ($H:ty) => {{
            let mut h = <Hmac<$H> as Mac>::new_from_slice(key).map_err(|e| {
                KmipError::cryptographic_failure(format!("HMAC key: {e}"))
            })?;
            h.update(data);
            Ok(h.finalize().into_bytes().to_vec())
        }};
    }
    match hash {
        HashingAlgorithm::Sha256 => mac!(Sha256),
        HashingAlgorithm::Sha384 => mac!(Sha384),
        HashingAlgorithm::Sha512 => mac!(Sha512),
        other => Err(KmipError::unsupported_cryptographic_parameters(format!(
            "HMAC PRF hash {other:?} not supported (SHA-256/384/512)"
        ))),
    }
}

fn soft_digest(hash: HashingAlgorithm, data: &[u8]) -> std::result::Result<Vec<u8>, KmipError> {
    Ok(match hash {
        HashingAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashingAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashingAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        other => {
            return Err(KmipError::unsupported_cryptographic_parameters(format!(
                "HASH derivation hash {other:?} not supported (SHA-256/384/512)"
            )))
        }
    })
}

/// §6.1.18 — "If the specified length exceeds the output of the
/// derivation method, then the server SHALL return an error." For the
/// single-block methods (HASH / HMAC) the output is one hash block;
/// shorter requests truncate (KMIP 1.x→3.0 Usage Guide convention).
fn take_prefix(mut out: Vec<u8>, len_bytes: usize) -> std::result::Result<Vec<u8>, KmipError> {
    if len_bytes > out.len() {
        return Err(KmipError::invalid_attribute(format!(
            "Cryptographic Length {} bits exceeds the derivation method's output ({} bits)",
            len_bytes * 8,
            out.len() * 8
        )));
    }
    out.truncate(len_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, EventPayload, RingSink};
    use crate::kmip30::{Attribute, CryptographicParameters, DerivationParameters};
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    const OPEN_POLICY: &str = "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n";

    fn deps() -> (Arc<RingSink>, Deps) {
        let ring = Arc::new(RingSink::new(256));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(OPEN_POLICY, std::path::Path::new("<t>")).unwrap())
            .unwrap();
        let d = Deps::new(
            engine,
            Arc::new(MemoryStore::new()),
            sink,
            super::super::deps::DepsConfig::default(),
        );
        (ring, d)
    }

    fn put_base(
        d: &Deps,
        uid: &str,
        object_type: ObjectType,
        algorithm: KmipAlgorithm,
        material: Option<Vec<u8>>,
        usage: UsageMask,
        state: State,
    ) {
        d.store
            .put(ObjectRecord {
                uid: uid.into(),
                object_type,
                algorithm,
                cryptographic_length: material.as_ref().map_or(0, |m| m.len() as u32 * 8),
                usage_mask: usage,
                state,
                pkcs11_cka_id: vec![1, 2, 3],
                pkcs11_slot: 0,
                initial_date: OffsetDateTime::now_utc(),
                key_material: material,
                links: HashMap::new(),
                custom_attributes: HashMap::new(),
                ..ObjectRecord::default()
            })
            .unwrap();
    }

    fn aes_template(bits: u32) -> Vec<Attribute> {
        vec![
            Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
            Attribute::CryptographicLength(bits),
            Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
        ]
    }

    fn request(
        method: DerivationMethod,
        uids: Vec<&str>,
        dp: DerivationParameters,
        template: Vec<Attribute>,
    ) -> DeriveKeyRequest {
        DeriveKeyRequest {
            object_type: ObjectType::SymmetricKey,
            uids: uids.into_iter().map(String::from).collect(),
            derivation_method: method,
            derivation_parameters: dp,
            template_attribute: template,
        }
    }

    // ── Happy paths with KAT cross-checks ───────────────────────────

    /// HMAC method = single HMAC over the Derivation Data (Table 546).
    /// KAT: RFC 4231 test case 2 — HMAC-SHA-256("Jefe", "what do ya
    /// want for nothing?").
    #[test]
    fn hmac_method_matches_rfc4231_case2() {
        let (_r, d) = deps();
        put_base(&d, "b1", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"Jefe".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let resp = derive_key(&d, request(
            DerivationMethod::Hmac,
            vec!["b1"],
            DerivationParameters {
                derivation_data: Some(b"what do ya want for nothing?".to_vec()),
                ..Default::default()
            },
            aes_template(256),
        ), "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(
            hex::encode(rec.key_material.as_deref().unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(rec.algorithm, KmipAlgorithm::Aes);
        assert_eq!(rec.cryptographic_length, 256);
        assert_eq!(rec.key_format_type, Some(0x01));
        assert!(rec.digest_value.is_some());
        assert_eq!(rec.fresh, Some(true));
        assert_eq!(rec.state, State::PreActive);
    }

    /// HMAC output truncates to a shorter Cryptographic Length; a
    /// length beyond one hash block errors (§6.1.18 "specified length
    /// exceeds the output of the derivation method").
    #[test]
    fn hmac_method_truncates_and_rejects_overlong() {
        let (_r, d) = deps();
        put_base(&d, "b1", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"Jefe".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let dp = || DerivationParameters {
            derivation_data: Some(b"what do ya want for nothing?".to_vec()),
            ..Default::default()
        };
        let resp = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["b1"], dp(), aes_template(128),
        ), "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(
            hex::encode(rec.key_material.as_deref().unwrap()),
            "5bdcc146bf60754e6a042426089575c7" // first 16 bytes of the RFC 4231 MAC
        );
        let err = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["b1"], dp(), aes_template(512),
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidAttribute);
    }

    /// HASH method over the derivation key (no Derivation Data):
    /// KAT — SHA-256("abc") from FIPS 180 / `kat/sha/sha256-acvp.json`
    /// family.
    #[test]
    fn hash_method_over_base_key_matches_sha256_abc() {
        let (_r, d) = deps();
        put_base(&d, "b1", ObjectType::SecretData, KmipAlgorithm::Rsa,
                 Some(b"abc".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let resp = derive_key(&d, DeriveKeyRequest {
            object_type: ObjectType::SecretData,
            uids: vec!["b1".into()],
            derivation_method: DerivationMethod::Hash,
            derivation_parameters: DerivationParameters {
                cryptographic_parameters: Some(CryptographicParameters {
                    hashing_algorithm: Some(HashingAlgorithm::Sha256),
                    ..Default::default()
                }),
                ..Default::default()
            },
            template_attribute: vec![Attribute::CryptographicLength(256)],
        }, "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(
            hex::encode(rec.key_material.as_deref().unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(rec.object_type, ObjectType::SecretData);
    }

    /// HASH method without the §7.13-REQUIRED Cryptographic
    /// Parameters hash → Bad Cryptographic Parameters (Table 304).
    #[test]
    fn hash_method_requires_hashing_algorithm() {
        let (_r, d) = deps();
        put_base(&d, "b1", ObjectType::SymmetricKey, KmipAlgorithm::Aes,
                 Some(vec![0u8; 32]), UsageMask::DERIVE_KEY, State::Active);
        let err = derive_key(&d, request(
            DerivationMethod::Hash, vec!["b1"],
            DerivationParameters::default(), aes_template(128),
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::BadCryptographicParameters);
    }

    /// PBKDF2 KAT — RFC 7914 §11 (PBKDF2-HMAC-SHA-256, P="passwd",
    /// S="salt", c=1, dkLen=64).
    #[test]
    fn pbkdf2_matches_rfc7914_vector() {
        let (_r, d) = deps();
        put_base(&d, "pw", ObjectType::SecretData, KmipAlgorithm::Rsa,
                 Some(b"passwd".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let resp = derive_key(&d, request(
            DerivationMethod::Pbkdf2,
            vec!["pw"],
            DerivationParameters {
                cryptographic_parameters: Some(CryptographicParameters {
                    hashing_algorithm: Some(HashingAlgorithm::Sha256),
                    ..Default::default()
                }),
                salt: Some(b"salt".to_vec()),
                iteration_count: Some(1),
                ..Default::default()
            },
            aes_template(512),
        ), "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(
            hex::encode(rec.key_material.as_deref().unwrap()),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
    }

    /// PBKDF2 without Salt / Iteration Count → Invalid Field (Table
    /// 465 marks both "Yes if Derivation method is PBKDF2").
    #[test]
    fn pbkdf2_requires_salt_and_iteration_count() {
        let (_r, d) = deps();
        put_base(&d, "pw", ObjectType::SecretData, KmipAlgorithm::Rsa,
                 Some(b"passwd".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let err = derive_key(&d, request(
            DerivationMethod::Pbkdf2, vec!["pw"],
            DerivationParameters {
                iteration_count: Some(1),
                ..Default::default()
            },
            aes_template(128),
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
        let err = derive_key(&d, request(
            DerivationMethod::Pbkdf2, vec!["pw"],
            DerivationParameters {
                salt: Some(b"salt".to_vec()),
                ..Default::default()
            },
            aes_template(128),
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    /// SP 800-108 Counter Mode: a single-block request reduces to
    /// HMAC(K, 0x00000001 ‖ DerivationData) — pinned against the
    /// `hmac` crate directly so the counter encoding (32-bit BE,
    /// starting at 1, BEFORE the fixed input) is locked.
    #[test]
    fn nist_108_counter_single_block_equals_prefixed_hmac() {
        let (_r, d) = deps();
        let key = b"kbkdf-base-key-32-bytes-long!!!!".to_vec();
        let label_ctx = b"label\x00context".to_vec();
        put_base(&d, "kdk", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(key.clone()), UsageMask::DERIVE_KEY, State::Active);
        let resp = derive_key(&d, request(
            DerivationMethod::Nist800_108C,
            vec!["kdk"],
            DerivationParameters {
                derivation_data: Some(label_ctx.clone()),
                ..Default::default()
            },
            aes_template(256),
        ), "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();

        let mut input = 1u32.to_be_bytes().to_vec();
        input.extend_from_slice(&label_ctx);
        let expected = soft_hmac(HashingAlgorithm::Sha256, &key, &input).unwrap();
        assert_eq!(rec.key_material.as_deref().unwrap(), &expected[..]);
    }

    /// Counter mode is length-extensible: a 72-byte request spans
    /// three SHA-256 blocks, K(1)‖K(2)‖K(3) truncated.
    #[test]
    fn nist_108_counter_multi_block_concatenates_prf_blocks() {
        let (_r, d) = deps();
        let key = b"kbkdf-base-key".to_vec();
        let data = b"L\x00C".to_vec();
        put_base(&d, "kdk", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(key.clone()), UsageMask::DERIVE_KEY, State::Active);
        let resp = derive_key(&d, DeriveKeyRequest {
            object_type: ObjectType::SecretData,
            uids: vec!["kdk".into()],
            derivation_method: DerivationMethod::Nist800_108C,
            derivation_parameters: DerivationParameters {
                derivation_data: Some(data.clone()),
                ..Default::default()
            },
            template_attribute: vec![Attribute::CryptographicLength(72 * 8)],
        }, "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();

        let mut expected = Vec::new();
        for i in 1u32..=3 {
            let mut input = i.to_be_bytes().to_vec();
            input.extend_from_slice(&data);
            expected.extend_from_slice(
                &soft_hmac(HashingAlgorithm::Sha256, &key, &input).unwrap(),
            );
        }
        expected.truncate(72);
        assert_eq!(rec.key_material.as_deref().unwrap(), &expected[..]);
    }

    // ── Error matrix ─────────────────────────────────────────────────

    #[test]
    fn missing_length_or_algorithm_is_invalid_field() {
        let (_r, d) = deps();
        put_base(&d, "b1", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"k".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let dp = || DerivationParameters {
            derivation_data: Some(b"d".to_vec()),
            ..Default::default()
        };
        // No CryptographicLength.
        let err = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["b1"], dp(),
            vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes)],
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
        // SymmetricKey without CryptographicAlgorithm.
        let err = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["b1"], dp(),
            vec![Attribute::CryptographicLength(128)],
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    #[test]
    fn base_not_found_wrong_state_and_missing_mask() {
        let (_r, d) = deps();
        // Unknown UID → Object Not Found (0x37).
        let err = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["ghost"],
            DerivationParameters::default(), aes_template(128),
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectNotFound);
        // PreActive base → Wrong Key Lifecycle State (0x43).
        put_base(&d, "pre", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"k".to_vec()), UsageMask::DERIVE_KEY, State::PreActive);
        let err = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["pre"],
            DerivationParameters::default(), aes_template(128),
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
        // Mask without the Derive Key bit (§6.1.18: "SHALL only apply
        // to Managed Objects that have the Derive Key bit set") → 0x29.
        put_base(&d, "nomask", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"k".to_vec()), UsageMask::ENCRYPT, State::Active);
        let err = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["nomask"],
            DerivationParameters::default(), aes_template(128),
        ), "c").unwrap_err();
        assert_eq!(
            err.result_reason(),
            ResultReason::IncompatibleCryptographicUsageMask
        );
    }

    #[test]
    fn unsupported_methods_fail_with_operation_not_supported() {
        let (_r, d) = deps();
        put_base(&d, "b1", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"k".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        // NB: AsymmetricKey (ECDH agreement) is now SUPPORTED — it is exercised
        // by the ecdh_recommended_curve_e2e integration test, not here.
        for method in [
            DerivationMethod::Encrypt,
            DerivationMethod::Nist800_108F,
            DerivationMethod::Nist800_108Dpi,
            DerivationMethod::AwsSigV4,
            DerivationMethod::Hkdf,
        ] {
            let err = derive_key(&d, request(
                method, vec!["b1"],
                DerivationParameters {
                    derivation_data: Some(b"d".to_vec()),
                    ..Default::default()
                },
                aes_template(128),
            ), "c").unwrap_err();
            assert_eq!(
                err.result_reason(),
                ResultReason::OperationNotSupported,
                "{method:?} must fail OperationNotSupported"
            );
        }
    }

    #[test]
    fn invalid_target_object_type_is_rejected() {
        let (_r, d) = deps();
        put_base(&d, "b1", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"k".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let mut req = request(
            DerivationMethod::Hmac, vec!["b1"],
            DerivationParameters::default(), aes_template(128),
        );
        req.object_type = ObjectType::PrivateKey;
        let err = derive_key(&d, req, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidObjectType);
    }

    /// §7.13 — explicit Derivation Data + a SecretData UID providing
    /// it implicitly "SHALL" error.
    #[test]
    fn explicit_and_implicit_derivation_data_conflict() {
        let (_r, d) = deps();
        put_base(&d, "key", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"k".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        put_base(&d, "sd", ObjectType::SecretData, KmipAlgorithm::Rsa,
                 Some(b"implicit".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let err = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["key", "sd"],
            DerivationParameters {
                derivation_data: Some(b"explicit".to_vec()),
                ..Default::default()
            },
            aes_template(128),
        ), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    /// Implicit Derivation Data from a second SecretData base works
    /// and BOTH bases get the Derived Object Link.
    #[test]
    fn implicit_derivation_data_and_links_on_both_objects() {
        let (_r, d) = deps();
        put_base(&d, "key", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"Jefe".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        put_base(&d, "sd", ObjectType::SecretData, KmipAlgorithm::Rsa,
                 Some(b"what do ya want for nothing?".to_vec()),
                 UsageMask::DERIVE_KEY, State::Active);
        let resp = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["key", "sd"],
            DerivationParameters::default(), aes_template(256),
        ), "c").unwrap();

        // Same KAT as the explicit-data path (RFC 4231 case 2).
        let derived = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(
            hex::encode(derived.key_material.as_deref().unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // §6.1.18 — Derivation Base Object Link on the derived object…
        assert_eq!(
            derived.links.get(super::LINK_DERIVATION_BASE).map(String::as_str),
            Some("key")
        );
        // …and Derived Object Link on EVERY base object.
        for base_uid in ["key", "sd"] {
            let base = d.store.get(base_uid).unwrap().unwrap();
            assert_eq!(
                base.links.get(super::LINK_DERIVED_OBJECT),
                Some(&resp.uid),
                "{base_uid} must carry DerivedObjectLink"
            );
        }
    }

    /// GetAttributes surfaces both link attributes (K11 generic link
    /// emission picks the new keys up).
    #[test]
    fn links_surface_via_get_attributes() {
        let (_r, d) = deps();
        put_base(&d, "key", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"k".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let resp = derive_key(&d, request(
            DerivationMethod::Hmac, vec!["key"],
            DerivationParameters {
                derivation_data: Some(b"d".to_vec()),
                ..Default::default()
            },
            aes_template(128),
        ), "c").unwrap();

        let ga = super::super::get_attributes::get_attributes(
            &d,
            crate::kmip30::GetAttributesRequest { uid: resp.uid.clone(), attribute_references: vec![] },
            "c2",
        ).unwrap();
        assert!(ga.attributes.iter().any(|a| matches!(
            a, Attribute::DerivationBaseObjectLink(u) if u == "key"
        )), "derived object must surface Derivation Base Object Link");

        let ga = super::super::get_attributes::get_attributes(
            &d,
            crate::kmip30::GetAttributesRequest { uid: "key".into(), attribute_references: vec![] },
            "c3",
        ).unwrap();
        assert!(ga.attributes.iter().any(|a| matches!(
            a, Attribute::DerivedObjectLink(u) if u == &resp.uid
        )), "base object must surface Derived Object Link");
    }

    /// Soft path audits `soft::derive` (K15 honesty convention).
    #[test]
    fn soft_path_audits_soft_derive() {
        let (ring, d) = deps();
        put_base(&d, "key", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"k".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        derive_key(&d, request(
            DerivationMethod::Hmac, vec!["key"],
            DerivationParameters {
                derivation_data: Some(b"d".to_vec()),
                ..Default::default()
            },
            aes_template(128),
        ), "c").unwrap();
        let events = ring.snapshot();
        assert!(events.iter().any(|e| matches!(
            &e.event,
            EventPayload::Pkcs11Call { function, rv: 0, .. } if function == "soft::derive"
        )), "expected a soft::derive audit event");
    }

    /// End-to-end: a derived AES key is immediately usable by the
    /// Encrypt op (store-held material, same as Register'd raw AES).
    #[test]
    fn derived_aes_key_encrypts_via_ops() {
        let (_r, d) = deps();
        put_base(&d, "key", ObjectType::SymmetricKey, KmipAlgorithm::HmacSha256,
                 Some(b"base-secret".to_vec()), UsageMask::DERIVE_KEY, State::Active);
        let resp = derive_key(&d, request(
            DerivationMethod::Nist800_108C, vec!["key"],
            DerivationParameters {
                derivation_data: Some(b"aes\x00e2e".to_vec()),
                ..Default::default()
            },
            vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                // Past activation ⇒ Active immediately (compute_initial_state).
                Attribute::ActivationDate(
                    OffsetDateTime::now_utc().unix_timestamp() - 3600,
                ),
            ],
        ), "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(rec.state, State::Active);
        assert_eq!(rec.key_material.as_ref().map(|m| m.len()), Some(32));

        let enc = super::super::encrypt::encrypt(
            &d,
            crate::kmip30::EncryptRequest {
                uid: resp.uid.clone(),
                data: b"hello derived key".to_vec(),
                iv: Some(vec![0u8; 12]), // AES-GCM nonce
                ..Default::default()
            },
            "c-enc",
        ).unwrap();
        assert!(!enc.ciphertext.is_empty());
    }
}
