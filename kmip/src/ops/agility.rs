//! The transparent auto-rekey transaction (crypto agility, "Phase 5") shared
//! by every rekey-on-use path — Sign, Encrypt, and Encapsulate.
//!
//! When the active policy substitutes a stored key's algorithm
//! ([`crate::policy::Decision::RekeyAndProceed`]), the calling op handler runs
//! this transaction and then re-issues its original operation against the
//! replacement key:
//!
//! 1. generate the replacement under the policy's target algorithm — the
//!    old key's `Name` is COPIED onto it (the label survives migration, so
//!    Locate-by-label and the Migration tab's cards follow the successor);
//! 2. activate the replacement (both halves for a pair);
//! 3. deactivate + supersede the old object (KMIP has no "Deprecated" state —
//!    the §3.2 Active→Deactivated transition is the superseded-key move),
//!    linked via `x-pqctoday-supersedes`;
//! 4. the CALLER re-issues its op against the new UID and stamps the
//!    `rekeyed { old, new }` info into its response.
//!
//! The re-issued op uses the substitution TARGET algorithm, so it cannot
//! re-substitute (no recursion) — the same invariant `rekey_and_sign`
//! documented before this module extracted the shared steps.

use time::OffsetDateTime;

use crate::auditlog::{AuditEvent, EventPayload, Plane};
use crate::error::Result;
use crate::kmip30::{ActivateRequest, Attribute, CreateKeyPairRequest, State, UsageMask};
use crate::store::ObjectRecord;

use super::deps::Deps;

/// UIDs of a freshly generated replacement key pair.
pub(crate) struct ReplacementPair {
    pub private_uid: String,
    pub public_uid: String,
}

/// Steps 1–2 for an ASYMMETRIC replacement: CreateKeyPair under
/// `new_algorithm` with `usage`, canonicalised as `op_canonical` for the
/// policy plane, then Activate both halves. The old record's Name rides on
/// the common attributes.
pub(crate) fn generate_replacement_pair(
    deps: &Deps,
    old: &ObjectRecord,
    new_algorithm: &str,
    usage: UsageMask,
    op_canonical: &str,
    correlation_id: &str,
) -> Result<ReplacementPair> {
    let new_alg = super::create_key_pair::parse_algorithm(new_algorithm)?;
    let mut common = vec![
        Attribute::CryptographicAlgorithm(new_alg),
        Attribute::CryptographicUsageMask(usage),
    ];
    if let Some(name) = &old.name {
        common.push(Attribute::Name(name.clone()));
    }
    let ckp = super::create_key_pair::create_key_pair(
        deps,
        CreateKeyPairRequest {
            common_attributes: common,
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        op_canonical,
        correlation_id,
    )?;
    super::activate::activate(
        deps,
        ActivateRequest { uid: ckp.private_key_uid.clone() },
        correlation_id,
    )?;
    super::activate::activate(
        deps,
        ActivateRequest { uid: ckp.public_key_uid.clone() },
        correlation_id,
    )?;
    Ok(ReplacementPair {
        private_uid: ckp.private_key_uid,
        public_uid: ckp.public_key_uid,
    })
}

/// Steps 1–2 for a SYMMETRIC replacement: Create under `new_algorithm`
/// (size derived from the qualified name — `AES-256` → 256), then Activate.
pub(crate) fn generate_replacement_symmetric(
    deps: &Deps,
    old: &ObjectRecord,
    new_algorithm: &str,
    correlation_id: &str,
) -> Result<String> {
    let new_alg = super::create_key_pair::parse_algorithm(new_algorithm)?;
    let mut attrs = vec![
        Attribute::CryptographicAlgorithm(new_alg),
        Attribute::CryptographicUsageMask(old.usage_mask),
    ];
    if let Some(bits) = super::helpers::classical_length_from_name(new_algorithm) {
        attrs.push(Attribute::CryptographicLength(bits));
    }
    if let Some(name) = &old.name {
        attrs.push(Attribute::Name(name.clone()));
    }
    let created = super::create::create(
        deps,
        crate::kmip30::CreateRequest {
            object_type: crate::kmip30::ObjectType::SymmetricKey,
            template_attribute: attrs,
        },
        correlation_id,
    )?;
    super::activate::activate(
        deps,
        ActivateRequest { uid: created.uid.clone() },
        correlation_id,
    )?;
    Ok(created.uid)
}

/// Step 3: deactivate + supersede the old object, pointing it at the
/// replacement's (private-key) UID, with the audit record naming the target
/// algorithm. Shared verbatim by every rekey path.
pub(crate) fn supersede_old(
    deps: &Deps,
    old: &ObjectRecord,
    replacement_uid: &str,
    new_algorithm: &str,
    correlation_id: &str,
) -> Result<()> {
    let mut old_rec = old.clone();
    let from_state = format!("{:?}", old_rec.state);
    old_rec.state = State::Deactivated;
    old_rec.supersedes = Some(replacement_uid.to_string());
    old_rec
        .links
        .insert("x-pqctoday-supersedes".to_string(), replacement_uid.to_string());
    // The KMIP `Name` is the APPLICATION's identifier and survives migration
    // unchanged (that IS the crypto-agility contract — the app keeps the same
    // handle before/after). The engine does NOT rewrite it; the old and new
    // objects are told apart by their real identity fields (UID, state, and the
    // `x-pqctoday-supersedes` link) in the keystore view.
    deps.store.update(old_rec)?;
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipObjectStateChanged {
            uid: old.uid.clone(),
            from_state,
            to_state: "Deactivated".into(),
            reason: format!("superseded by {replacement_uid} (agility rekey → {new_algorithm})"),
        },
    ));
    Ok(())
}
