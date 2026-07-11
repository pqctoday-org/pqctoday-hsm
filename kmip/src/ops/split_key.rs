//! KMIP 3.0 §6.1.12 **Create Split Key** / §6.1.31 **Join Split Key**
//! (Phase 3.3).
//!
//! The engine has no secret-sharing primitive of its own to route
//! through in the usual "resolve UID → engine handle → native::*" way
//! for an EXISTING key — Create Split Key can also be asked to
//! generate a brand-new key first. Either way, this handler never
//! touches raw secret bytes itself: it resolves (or creates) an engine
//! handle, then calls `softhsmrustv3::native::split_key::{split,join}`,
//! which do the actual byte-level work (reading/writing `CKA_VALUE`
//! internally) and hand back only handles. See that module's doc
//! comment for the full security-model rationale.
//!
//! ## Plane mapping
//!
//! - **Plane 2** — resolve/create the source key's `ObjectRecord`,
//!   persist one `ObjectRecord` per share (Create) or one joined
//!   `ObjectRecord` (Join).
//! - **Plane 3** — `softhsmrustv3::native::split_key::split` / `join`,
//!   which call `native::keygen`'s object-registration helpers
//!   internally (real engine objects, not client-visible key material
//!   on the `ObjectRecord`).

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result};
use crate::kmip30::{
    Attribute, CreateSplitKeyRequest, CreateSplitKeyResponse, JoinSplitKeyRequest,
    JoinSplitKeyResponse, KmipAlgorithm, ObjectType, State,
};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{ck_rv_to_kmip_error, emit_request, emit_success, fail_err, find_handle_for_object};

use softhsmrustv3::crypto::split_key::{Gf256Polynomial, SplitKeyMethod};

fn method_from_wire(v: u32) -> Result<SplitKeyMethod> {
    match v {
        1 => Ok(SplitKeyMethod::Xor),
        2 => Ok(SplitKeyMethod::PolynomialGf65536),
        3 => Ok(SplitKeyMethod::PolynomialPrimeField),
        4 => Ok(SplitKeyMethod::PolynomialGf256),
        other => Err(KmipError::invalid_field(format!(
            "Split Key Method {other:#x} is not one of the four §11.54 values (1-4)"
        ))),
    }
}

fn method_to_wire(m: SplitKeyMethod) -> u32 {
    match m {
        SplitKeyMethod::Xor => 1,
        SplitKeyMethod::PolynomialGf65536 => 2,
        SplitKeyMethod::PolynomialPrimeField => 3,
        SplitKeyMethod::PolynomialGf256 => 4,
    }
}

fn polynomial_from_wire(v: u32) -> Result<Gf256Polynomial> {
    match v {
        1 => Ok(Gf256Polynomial::Polynomial283),
        2 => Ok(Gf256Polynomial::Polynomial285),
        other => Err(KmipError::invalid_field(format!(
            "Split Key Polynomial {other:#x} is not one of the two §11.55 values (1-2)"
        ))),
    }
}

fn polynomial_to_wire(p: Gf256Polynomial) -> u32 {
    match p {
        Gf256Polynomial::Polynomial283 => 1,
        Gf256Polynomial::Polynomial285 => 2,
    }
}

fn is_gf_method(m: SplitKeyMethod) -> bool {
    matches!(m, SplitKeyMethod::PolynomialGf256 | SplitKeyMethod::PolynomialGf65536)
}

// ── Create Split Key ─────────────────────────────────────────────────────

pub fn create_split_key(
    deps: &Deps,
    req: CreateSplitKeyRequest,
    correlation_id: &str,
) -> Result<CreateSplitKeyResponse> {
    emit_request(
        deps,
        correlation_id,
        "CreateSplitKey",
        format!(
            "object_type={:?} uid={:?} parts={} threshold={} method={:#x}",
            req.object_type, req.uid, req.split_key_parts, req.split_key_threshold, req.split_key_method
        ),
    );

    let session = deps.engine_session.ok_or_else(|| {
        fail_err(
            deps,
            correlation_id,
            "CreateSplitKey",
            KmipError::internal("CreateSplitKey requires a real engine session"),
        )
    })?;

    let method = method_from_wire(req.split_key_method)
        .map_err(|e| fail_err(deps, correlation_id, "CreateSplitKey", e))?;

    let polynomial_wire = req.attributes.iter().find_map(|a| match a {
        Attribute::SplitKeyPolynomial(v) => Some(*v),
        _ => None,
    });
    let polynomial = if is_gf_method(method) {
        Some(
            polynomial_wire
                .map(polynomial_from_wire)
                .unwrap_or(Ok(Gf256Polynomial::Polynomial283))
                .map_err(|e| fail_err(deps, correlation_id, "CreateSplitKey", e))?,
        )
    } else {
        None
    };

    if req.split_key_threshold < 1 || req.split_key_threshold > req.split_key_parts {
        return Err(fail_err(
            deps,
            correlation_id,
            "CreateSplitKey",
            KmipError::invalid_field("Split Key Threshold must be >= 1 and <= Split Key Parts"),
        ));
    }
    if method == SplitKeyMethod::Xor && req.split_key_parts != req.split_key_threshold {
        return Err(fail_err(
            deps,
            correlation_id,
            "CreateSplitKey",
            KmipError::invalid_field(
                "XOR requires Split Key Parts == Split Key Threshold (KMIP 3.0 §13.1)",
            ),
        ));
    }

    // Resolve the secret to split: an existing key (client-named UID —
    // "the attributes of the key take precedence" per §6.1.12), or
    // generate a fresh one from the request's Attributes.
    let (secret_handle, algorithm, length_bits) = match &req.uid {
        Some(uid) => {
            let obj = deps.store.get(uid)?.ok_or_else(|| {
                fail_err(deps, correlation_id, "CreateSplitKey", KmipError::not_found(uid))
            })?;
            let handle =
                find_handle_for_object(session, &obj.pkcs11_cka_id, obj.object_type)
                    .map_err(|rv| ck_rv_to_kmip_error(rv, "CreateSplitKey:find"))?
                    .ok_or_else(|| KmipError::not_found(uid))
                    .map_err(|e| fail_err(deps, correlation_id, "CreateSplitKey", e))?;
            (handle, obj.algorithm, obj.cryptographic_length)
        }
        None => {
            let algorithm = req.attributes.iter().find_map(|a| match a {
                Attribute::CryptographicAlgorithm(alg) => Some(*alg),
                _ => None,
            });
            let length_bits = req.attributes.iter().find_map(|a| match a {
                Attribute::CryptographicLength(n) => Some(*n),
                _ => None,
            });
            let length_bits = length_bits.ok_or_else(|| {
                fail_err(
                    deps,
                    correlation_id,
                    "CreateSplitKey",
                    KmipError::failed(
                        crate::error::ResultReason::MissingData,
                        "CreateSplitKey without a source Unique Identifier requires \
                         CryptographicLength to generate a new key",
                    ),
                )
            })?;
            let cka_id = Uuid::new_v4().as_bytes().to_vec();
            let handle = softhsmrustv3::native::generate_generic_secret(
                session,
                length_bits as u32,
                &cka_id,
                "kmip-create-split-key-source",
            )
            .map_err(|rv| ck_rv_to_kmip_error(rv, "CreateSplitKey:generate"))
            .map_err(|e| fail_err(deps, correlation_id, "CreateSplitKey", e))?;
            (handle, algorithm.unwrap_or(KmipAlgorithm::Aes), length_bits)
        }
    };

    let cka_id_prefix = Uuid::new_v4().as_bytes().to_vec();
    let shares = softhsmrustv3::native::split_key::split(
        session,
        secret_handle,
        req.split_key_parts,
        req.split_key_threshold,
        method,
        polynomial,
        &cka_id_prefix,
        "kmip-split-key-part",
    )
    .map_err(|rv| ck_rv_to_kmip_error(rv, "CreateSplitKey:split"))
    .map_err(|e| fail_err(deps, correlation_id, "CreateSplitKey", e))?;

    let now = OffsetDateTime::now_utc();
    let mut uids = Vec::with_capacity(shares.len());
    for (key_part_identifier, _handle) in shares {
        // Deterministic CKA_ID matching what `native::split_key::split`
        // registered each share under (prefix ++ index, big-endian) —
        // avoids a handle-to-CKA_ID lookup round-trip.
        let mut cka_id = cka_id_prefix.clone();
        cka_id.extend_from_slice(&key_part_identifier.to_be_bytes());

        let uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
        deps.store.put(ObjectRecord {
            uid: uid.clone(),
            object_type: ObjectType::SplitKey,
            algorithm,
            cryptographic_length: length_bits,
            usage_mask: crate::kmip30::UsageMask::empty(),
            state: State::PreActive,
            pkcs11_cka_id: cka_id,
            pkcs11_slot: deps.config.pkcs11_slot,
            initial_date: now,
            activation_date: None,
            supersedes: None,
            name: None,
            links: HashMap::new(),
            custom_attributes: HashMap::new(),
            key_material: None,
            key_format_type: None,
            split_key_parts: Some(req.split_key_parts),
            split_key_threshold: Some(req.split_key_threshold),
            split_key_method: Some(req.split_key_method),
            key_part_identifier: Some(key_part_identifier),
            split_key_polynomial: polynomial.map(polynomial_to_wire),
            protection_storage_mask: Some(0x01),
            lease_time: Some(3600),
            ..ObjectRecord::default()
        })?;
        uids.push(uid);
    }

    emit_success(deps, correlation_id, "CreateSplitKey");
    Ok(CreateSplitKeyResponse { uids })
}

// ── Join Split Key ────────────────────────────────────────────────────────

pub fn join_split_key(
    deps: &Deps,
    req: JoinSplitKeyRequest,
    correlation_id: &str,
) -> Result<JoinSplitKeyResponse> {
    emit_request(
        deps,
        correlation_id,
        "JoinSplitKey",
        format!("object_type={:?} uids={}", req.object_type, req.uids.len()),
    );

    let session = deps.engine_session.ok_or_else(|| {
        fail_err(
            deps,
            correlation_id,
            "JoinSplitKey",
            KmipError::internal("JoinSplitKey requires a real engine session"),
        )
    })?;

    if req.uids.is_empty() {
        return Err(fail_err(
            deps,
            correlation_id,
            "JoinSplitKey",
            KmipError::invalid_field("Join Split Key requires at least one Unique Identifier"),
        ));
    }

    let mut records = Vec::with_capacity(req.uids.len());
    for uid in &req.uids {
        let obj = deps.store.get(uid)?.ok_or_else(|| {
            fail_err(deps, correlation_id, "JoinSplitKey", KmipError::not_found(uid))
        })?;
        if obj.object_type != ObjectType::SplitKey {
            return Err(fail_err(
                deps,
                correlation_id,
                "JoinSplitKey",
                KmipError::invalid_object_type(format!(
                    "{uid} is not a Split Key object (got {:?})",
                    obj.object_type
                )),
            ));
        }
        records.push(obj);
    }

    // All named shares must genuinely belong to the same split (same
    // method/threshold/polynomial/algorithm/length) — mixing shares
    // from different Create Split Key calls must not silently succeed.
    let first = &records[0];
    let method_wire = first.split_key_method.ok_or_else(|| {
        fail_err(deps, correlation_id, "JoinSplitKey", KmipError::internal("share missing Split Key Method"))
    })?;
    let threshold = first.split_key_threshold.ok_or_else(|| {
        fail_err(deps, correlation_id, "JoinSplitKey", KmipError::internal("share missing Split Key Threshold"))
    })?;
    let polynomial_wire = first.split_key_polynomial;
    let algorithm = first.algorithm;
    let length_bits = first.cryptographic_length;
    for r in &records[1..] {
        if r.split_key_method != Some(method_wire)
            || r.split_key_threshold != Some(threshold)
            || r.split_key_polynomial != polynomial_wire
            || r.algorithm != algorithm
            || r.cryptographic_length != length_bits
        {
            return Err(fail_err(
                deps,
                correlation_id,
                "JoinSplitKey",
                KmipError::invalid_field(
                    "supplied Unique Identifiers are not all shares of the same Split Key",
                ),
            ));
        }
    }

    if (records.len() as u32) < threshold {
        return Err(fail_err(
            deps,
            correlation_id,
            "JoinSplitKey",
            KmipError::invalid_field(format!(
                "{} Unique Identifiers supplied, but this Split Key's Threshold is {threshold}",
                records.len()
            )),
        ));
    }

    let method = method_from_wire(method_wire).map_err(|e| fail_err(deps, correlation_id, "JoinSplitKey", e))?;
    let polynomial = polynomial_wire
        .map(polynomial_from_wire)
        .transpose()
        .map_err(|e| fail_err(deps, correlation_id, "JoinSplitKey", e))?;

    let mut shares = Vec::with_capacity(records.len());
    for r in &records {
        let key_part_identifier = r.key_part_identifier.ok_or_else(|| {
            fail_err(deps, correlation_id, "JoinSplitKey", KmipError::internal("share missing Key Part Identifier"))
        })?;
        let handle = find_handle_for_object(session, &r.pkcs11_cka_id, ObjectType::SplitKey)
            .map_err(|rv| ck_rv_to_kmip_error(rv, "JoinSplitKey:find"))
            .map_err(|e| fail_err(deps, correlation_id, "JoinSplitKey", e))?
            .ok_or_else(|| fail_err(deps, correlation_id, "JoinSplitKey", KmipError::not_found(&r.uid)))?;
        shares.push((key_part_identifier, handle));
    }

    let cka_id = Uuid::new_v4().as_bytes().to_vec();
    let joined_handle = softhsmrustv3::native::split_key::join(
        session,
        &shares,
        threshold,
        method,
        polynomial,
        (length_bits as usize).div_ceil(8),
        &cka_id,
        "kmip-join-split-key",
    )
    .map_err(|rv| ck_rv_to_kmip_error(rv, "JoinSplitKey:join"))
    .map_err(|e| fail_err(deps, correlation_id, "JoinSplitKey", e))?;
    let _ = joined_handle;

    let now = OffsetDateTime::now_utc();
    let uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type: req.object_type,
        algorithm,
        cryptographic_length: length_bits,
        usage_mask: crate::kmip30::UsageMask::empty(),
        state: State::PreActive,
        pkcs11_cka_id: cka_id,
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: None,
        supersedes: None,
        name: None,
        links: HashMap::new(),
        custom_attributes: HashMap::new(),
        key_material: None,
        key_format_type: None,
        protection_storage_mask: Some(0x01),
        lease_time: Some(3600),
        ..ObjectRecord::default()
    })?;

    emit_success(deps, correlation_id, "JoinSplitKey");
    Ok(JoinSplitKeyResponse { uid })
}
