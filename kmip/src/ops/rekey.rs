//! K21 — KMIP 3.0 §6.1.51 **Re-key** (op `0x04`) and §6.1.52 **Re-key
//! Key Pair** (op `0x1d`).
//!
//! > "This request is used to generate a replacement key for an
//! > existing symmetric key. It is analogous to the Create operation,
//! > except that attributes of the replacement key are copied from
//! > the existing key, with the exception of the attributes listed in
//! > Re-key Attribute Requirements." (§6.1.51; §6.1.52 says the same
//! > of Create Key Pair.)
//!
//! ## Attribute inheritance (Table 404 / Table 409)
//!
//! Everything copies from the existing object except:
//!
//! | Attribute | Action (spec sentence) |
//! |---|---|
//! | Initial Date | "Set to the current time" |
//! | Destroy / Compromise (Occurrence) Date, Revocation Reason | "Not set" |
//! | Unique Identifier(s) | "New value generated" |
//! | Usage Limits | "The Total value is copied from the existing key, and the Count value … is set to the Total value" — i.e. the replacement starts with a full budget (Table 409's clearer wording: "the Byte Count/Object Count values are set to the Total Bytes/Total Objects") |
//! | Name | "Set to the name(s) of the existing key; all Name attributes are removed from the existing key" |
//! | State | "Set based on attributes values, such as dates" |
//! | Digest | "Recomputed from the replacement key value" |
//! | Link | "Set to point to the existing key as the replaced key" |
//! | Last Change Date | "Set to current time" |
//! | Random Number Generator | "Set to the random number generator used for creating the new managed object. Not copied" — both report the honest `Unspecified` OsRng (see `get_attributes`) |
//!
//! **Precedence** (documented for K19 interplay): request `Attributes`
//! > inherited values > Set Defaults. The §6.1.58 Object Defaults are
//! NOT applied here at all — defaults only fill gaps, and inheritance
//! always supplies algorithm / length / usage mask from the existing
//! object, so there is never a gap for a default to fill.
//!
//! ## Offset date math (Table 403 / Table 408)
//!
//! No Offset ⇒ Activation / Process Start / Protect Stop /
//! Deactivation Dates are copied verbatim (§6.1.52 names only
//! Activation + Deactivation for the pair; the other two ride along
//! via the blanket inheritance). With Offset (Interval seconds):
//!
//! ```text
//! IT2 = now                                   (> IT1)
//! AT2 = IT2 + Offset
//! Process Start  = CT1 + (AT2 - AT1)          (Table 403 only)
//! Protect Stop   = TT1 + (AT2 - AT1)          (Table 403 only)
//! Deactivation   = DT1 + (AT2 - AT1)
//! ```
//!
//! The shift is only defined when the existing object has an
//! Activation Date (the table presumes "dates exist for the existing
//! key"); a date the existing object lacks stays unset, and when AT1
//! itself is missing the dependent dates are copied unshifted.
//!
//! ## Links (§6.1.51 / §6.1.52)
//!
//! > "For the existing key, the server SHALL create a Replacement
//! > Object Link attribute pointing to the replacement key. For the
//! > replacement key, the server SHALL create a Replaced Object Link
//! > attribute pointing to the existing key." (Per half for the pair.)
//!
//! ## Retiring the existing object
//!
//! §6.1.51 itself does not order a state transition, but Table 97
//! (`Deactivation Date` attribute rules) lists Re-key / Re-key Key
//! Pair among the operations that implicitly set Deactivation Date,
//! and "the replacement key takes over the name attribute of the
//! existing key" — the rotation convention is that the existing key
//! retires when its replacement activates. Implemented: when the
//! existing object carries no Deactivation Date, it is set to the
//! replacement's Activation Date (or `now` when the replacement has
//! none); if that instant has already arrived and the object is
//! Active, it transitions to Deactivated immediately (same field
//! writes as §6.1.14 Deactivate — see `lifecycle_and_protocol`).
//! PreActive originals keep their state: the §3.4 FSM has no
//! PreActive → Deactivated edge.
//!
//! ## Errors (Table 407 / §6.1.52.1)
//!
//! `Object Not Found` for an unknown UID; `Invalid Object Type` for a
//! non-SymmetricKey (Re-key) / non-key-pair-half (Re-key Key Pair)
//! target. A Deactivated / Compromised / Destroyed original fails
//! with `Wrong Key Lifecycle State (0x43)` — the table lists no
//! state-specific reason, but §11 defines 0x43 as "The key lifecycle
//! state is invalid for the operation", the truthful description
//! (same mapping CS-AC-M-8 pins for Sign against a Destroyed key).
//! PreActive and Active originals may be re-keyed: the spec imposes
//! no state precondition and Table 403 explicitly handles missing
//! dates.

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    ObjectType, PkcsOp, ReKeyKeyPairRequest, ReKeyKeyPairResponse, ReKeyRequest,
    ReKeyResponse, State,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{emit_request, emit_success, fail_err, state_name};
use super::register_import_export::ExtractedAttrs;

/// Links-map keys (canonical attribute names; wire tags `Replaced
/// Object Link` 0x42019b / `Replacement Object Link` 0x42019c —
/// `get_attributes::attributes_from_record` emits them).
const LINK_REPLACED_OBJECT: &str = "ReplacedObjectLink";
const LINK_REPLACEMENT_OBJECT: &str = "ReplacementObjectLink";

// ── Re-key (§6.1.51) ────────────────────────────────────────────────────────

pub fn rekey(deps: &Deps, req: ReKeyRequest, correlation_id: &str) -> Result<ReKeyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "ReKey",
        format!("uid={} offset={:?} attrs={}", req.uid, req.offset, req.template_attribute.len()),
    );
    let fail = |e: KmipError| fail_err(deps, correlation_id, "ReKey", e);

    let orig = deps
        .store
        .get(&req.uid)?
        .ok_or_else(|| fail(KmipError::object_not_found(&req.uid)))?;

    // §6.1.51 — "a replacement key for an existing symmetric key";
    // anything else → `Invalid Object Type` (Table 407).
    if orig.object_type != ObjectType::SymmetricKey {
        return Err(fail(KmipError::invalid_object_type(format!(
            "ReKey replaces a SymmetricKey; {} is {:?} \
             (use ReKeyKeyPair for asymmetric pairs)",
            orig.uid, orig.object_type
        ))));
    }
    gate_rekeyable_state(&orig).map_err(&fail)?;

    // Request `Attributes` override the inherited values (request >
    // inherited > defaults; see module doc for why §6.1.58 Set
    // Defaults never fire here).
    let x = super::register_import_export::extract_attrs(&req.template_attribute);
    let mut algo = x.algorithm.unwrap_or(orig.algorithm);
    let mut length = x.length.unwrap_or(orig.cryptographic_length);
    let usage = x.usage.unwrap_or(orig.usage_mask);

    // Plane-1 policy gate against the object being replaced. Unlike the
    // client-driven §6.1.51 ReKey (like-for-like), the crypto-agility engine
    // can SUBSTITUTE the replacement algorithm: a `Decision::RekeyAndProceed`
    // (e.g. AES-128 → AES-256) means the sweep-driven ReKey adopts the policy's
    // target. An explicit client-template algorithm still wins (request >
    // policy) — so we only consult the substitution when the client didn't
    // pin one.
    {
        let stored_attrs = super::helpers::strip_x_prefixes(&orig.custom_attributes);
        let algo_name = super::helpers::qualified_name(algo, length);
        let mut p_req =
            PolicyRequest::minimal("ReKey", Some(&algo_name), started, correlation_id, &stored_attrs);
        p_req.key_length = Some(length);
        p_req.usage_mask = Some(usage);
        p_req.state = Some(state_name(orig.state));
        p_req.name = orig.name.as_deref();
        p_req.current_object_algorithm = Some(&algo_name);
        p_req.target_uid = Some(&orig.uid);
        match deps.engine.evaluate(&p_req) {
            Decision::Deny { kmip_reason, human, .. } => {
                return Err(fail(KmipError::failed(kmip_reason.to_result_reason(), human)));
            }
            Decision::RekeyAndProceed { new_algorithm, .. } if x.algorithm.is_none() => {
                algo = super::create_key_pair::parse_algorithm(&new_algorithm).map_err(&fail)?;
                length = super::helpers::classical_length_from_name(&new_algorithm)
                    .unwrap_or(length);
            }
            _ => {}
        }
    }

    // Plane-3 — same keygen path as Create (§6.1.51: "analogous to
    // the Create operation").
    let mech = algo.to_pkcs11_mech(PkcsOp::KeyGen).ok_or_else(|| {
        fail(KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("symmetric algorithm {algo:?} has no KeyGen mechanism"),
        ))
    })?;
    let cka_id_bytes = Uuid::new_v4().as_bytes().to_vec();
    let digest_value = super::create::engine_generate_symmetric(
        deps,
        correlation_id,
        "ReKey",
        algo,
        Some(length),
        mech,
        &cka_id_bytes,
        usage,
    )
    .map_err(&fail)?;

    // ── Plane-2: build the replacement record ───────────────────────
    let now = OffsetDateTime::now_utc();
    let dates = replacement_dates(&orig, now, req.offset, DateTable::ReKey);
    let mut rec = inherited_replacement_base(&orig, now);
    rec.algorithm = algo;
    rec.cryptographic_length = length;
    rec.usage_mask = usage;
    rec.pkcs11_cka_id = cka_id_bytes;
    rec.digest_value = digest_value;
    apply_dates(&mut rec, &dates, &x, now);
    // Table 404 `Name` — "Set to the name(s) of the existing key";
    // an explicit request Name outranks the transfer (request >
    // inherited). Either way the existing key loses its names below.
    rec.name = x.name.clone().or_else(|| orig.name.clone());
    rec.links.insert(LINK_REPLACED_OBJECT.to_string(), orig.uid.clone());
    let new_uid = rec.uid.clone();
    deps.store.put(rec)?;

    // ── Mutate the existing key (link / names / retirement) ─────────
    let mut old = orig;
    retire_original(&mut old, &new_uid, dates.activation, now);
    deps.store.update(old)?;

    emit_success(deps, correlation_id, "ReKey");
    Ok(ReKeyResponse { uid: new_uid })
}

// ── Re-key Key Pair (§6.1.52) ───────────────────────────────────────────────

pub fn rekey_key_pair(
    deps: &Deps,
    req: ReKeyKeyPairRequest,
    correlation_id: &str,
) -> Result<ReKeyKeyPairResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "ReKeyKeyPair",
        format!(
            "uid={} offset={:?} common={} priv={} pub={}",
            req.uid,
            req.offset,
            req.common_attributes.len(),
            req.private_key_attributes.len(),
            req.public_key_attributes.len(),
        ),
    );
    let fail = |e: KmipError| fail_err(deps, correlation_id, "ReKeyKeyPair", e);

    // Table 410 — the UID "Determines the existing Asymmetric key
    // pair". The canonical handle is the private key (§6.1 preamble placeholder
    // order); a public-half UID is resolved to its pair mate via the
    // PrivateKeyLink so clients holding either half succeed.
    let target = deps
        .store
        .get(&req.uid)?
        .ok_or_else(|| fail(KmipError::object_not_found(&req.uid)))?;
    let (old_priv, old_pub) = match target.object_type {
        ObjectType::PrivateKey => {
            let pub_rec = pair_mate(deps, &target, "PublicKeyLink").map_err(&fail)?;
            (target, pub_rec)
        }
        ObjectType::PublicKey => {
            let priv_rec = pair_mate(deps, &target, "PrivateKeyLink").map_err(&fail)?;
            (priv_rec, target)
        }
        other => {
            return Err(fail(KmipError::invalid_object_type(format!(
                "ReKeyKeyPair replaces a PublicKey/PrivateKey pair; {} is {other:?} \
                 (use ReKey for symmetric keys)",
                req.uid
            ))));
        }
    };
    gate_rekeyable_state(&old_priv).map_err(&fail)?;
    gate_rekeyable_state(&old_pub).map_err(&fail)?;

    // §6.1.52 attribute baskets mirror Create Key Pair: Common merges
    // into both halves; the per-half baskets win nothing over Common
    // here — they are concatenated exactly like `create_key_pair`.
    let priv_attrs: Vec<_> = req
        .common_attributes
        .iter()
        .chain(req.private_key_attributes.iter())
        .cloned()
        .collect();
    let pub_attrs: Vec<_> = req
        .common_attributes
        .iter()
        .chain(req.public_key_attributes.iter())
        .cloned()
        .collect();
    let priv_x = super::register_import_export::extract_attrs(&priv_attrs);
    let pub_x = super::register_import_export::extract_attrs(&pub_attrs);

    // Request > inherited (per half; algorithm is pair-wide).
    let client_algo = priv_x.algorithm.or(pub_x.algorithm);
    let mut algo = client_algo.unwrap_or(old_priv.algorithm);
    // Request > inherited for the generation length too: an explicit
    // `CryptographicLength` in the re-key template drives the RSA modulus
    // size / ECDSA curve; otherwise the family default applies (as before).
    let mut key_length = priv_x.length.or(pub_x.length);
    // Set when the policy substituted the algorithm — the new records then take
    // the substituted length, NOT the old key's (which belonged to the old alg).
    let mut substituted = false;

    // Plane-1 policy gate against the private half being replaced. As with
    // ReKey, a `Decision::RekeyAndProceed` substitutes the replacement
    // algorithm (RSA-2048 → ML-DSA-44) when the client didn't pin one — this
    // is what makes the Migration sweep a series of real KMIP ReKeyKeyPair ops.
    {
        let stored_attrs = super::helpers::strip_x_prefixes(&old_priv.custom_attributes);
        let algo_name =
            super::helpers::qualified_name(old_priv.algorithm, old_priv.cryptographic_length);
        let mut p_req = PolicyRequest::minimal(
            "ReKeyKeyPair",
            Some(&algo_name),
            started,
            correlation_id,
            &stored_attrs,
        );
        p_req.state = Some(state_name(old_priv.state));
        p_req.name = old_priv.name.as_deref();
        p_req.current_object_algorithm = Some(&algo_name);
        p_req.target_uid = Some(&old_priv.uid);
        match deps.engine.evaluate(&p_req) {
            Decision::Deny { kmip_reason, human, .. } => {
                return Err(fail(KmipError::failed(kmip_reason.to_result_reason(), human)));
            }
            Decision::RekeyAndProceed { new_algorithm, .. } if client_algo.is_none() => {
                algo = super::create_key_pair::parse_algorithm(&new_algorithm).map_err(&fail)?;
                // A PQC target's parameter set fixes its size (length 0); only
                // classical targets carry a length suffix worth honoring. Either
                // way the OLD length must not carry over onto the new algorithm.
                key_length =
                    Some(super::helpers::classical_length_from_name(&new_algorithm).unwrap_or(0));
                substituted = true;
            }
            _ => {}
        }
    }

    // Plane-3 — same keygen path as Create Key Pair.
    let mech = algo.to_pkcs11_mech(PkcsOp::KeyGen).ok_or_else(|| {
        fail(KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("algorithm {algo:?} has no KeyGen mechanism"),
        ))
    })?;
    let generated = super::create_key_pair::engine_generate_keypair(
        deps,
        correlation_id,
        algo,
        key_length,
        mech,
        None, // rekey generates fresh material, never from a client seed
        old_priv.recommended_curve, // preserve the base object's RecommendedCurve (§4.16) — an X25519/X448/NIST ECDH key rekeys to the same curve
        pub_x.usage.unwrap_or(old_pub.usage_mask),
        priv_x.usage.unwrap_or(old_priv.usage_mask),
    )
    .map_err(&fail)?;

    // ── Plane-2: build both replacement records ─────────────────────
    let now = OffsetDateTime::now_utc();
    let priv_dates = replacement_dates(&old_priv, now, req.offset, DateTable::ReKeyKeyPair);
    let pub_dates = replacement_dates(&old_pub, now, req.offset, DateTable::ReKeyKeyPair);

    // When the policy substituted the algorithm, `key_length` holds the new
    // algorithm's size (0 for PQC) — that wins over the old key's length.
    let priv_length = priv_x
        .length
        .or(if substituted { key_length } else { None })
        .unwrap_or(old_priv.cryptographic_length);
    let pub_length = pub_x
        .length
        .or(if substituted { key_length } else { None })
        .unwrap_or(old_pub.cryptographic_length);

    let mut new_priv = inherited_replacement_base(&old_priv, now);
    new_priv.algorithm = algo;
    new_priv.cryptographic_length = priv_length;
    new_priv.usage_mask = priv_x.usage.unwrap_or(old_priv.usage_mask);
    new_priv.pkcs11_cka_id = generated.cka_id_priv;
    new_priv.digest_value = generated.digest_priv;
    new_priv.recommended_curve = old_priv.recommended_curve; // KMIP 3.0 §4.16 — curve survives rekey
    apply_dates(&mut new_priv, &priv_dates, &priv_x, now);
    new_priv.name = priv_x.name.clone().or_else(|| old_priv.name.clone());
    new_priv.links.insert(LINK_REPLACED_OBJECT.to_string(), old_priv.uid.clone());

    let mut new_pub = inherited_replacement_base(&old_pub, now);
    new_pub.algorithm = algo;
    new_pub.cryptographic_length = pub_length;
    new_pub.usage_mask = pub_x.usage.unwrap_or(old_pub.usage_mask);
    new_pub.pkcs11_cka_id = generated.cka_id_pub;
    new_pub.digest_value = generated.digest_pub;
    new_pub.recommended_curve = old_pub.recommended_curve; // KMIP 3.0 §4.16 — curve survives rekey
    apply_dates(&mut new_pub, &pub_dates, &pub_x, now);
    new_pub.name = pub_x.name.clone().or_else(|| old_pub.name.clone());
    new_pub.links.insert(LINK_REPLACED_OBJECT.to_string(), old_pub.uid.clone());

    // Pair cross-links between the NEW halves (same shape Create Key
    // Pair writes; AKLC-O-1 reads them back via GetAttributes).
    new_priv.links.insert("PublicKeyLink".to_string(), new_pub.uid.clone());
    new_pub.links.insert("PrivateKeyLink".to_string(), new_priv.uid.clone());

    let (new_priv_uid, new_pub_uid) = (new_priv.uid.clone(), new_pub.uid.clone());
    deps.store.put(new_priv)?;
    deps.store.put(new_pub)?;

    // ── Mutate both existing halves ─────────────────────────────────
    let mut old = old_priv;
    retire_original(&mut old, &new_priv_uid, priv_dates.activation, now);
    deps.store.update(old)?;
    let mut old = old_pub;
    retire_original(&mut old, &new_pub_uid, pub_dates.activation, now);
    deps.store.update(old)?;

    emit_success(deps, correlation_id, "ReKeyKeyPair");
    Ok(ReKeyKeyPairResponse {
        private_key_uid: new_priv_uid,
        public_key_uid: new_pub_uid,
    })
}

// ── Shared internals ────────────────────────────────────────────────────────

/// PreActive and Active objects may be re-keyed (the spec sets no
/// state precondition and Table 403 handles missing dates); retired /
/// compromised / destroyed objects fail with `Wrong Key Lifecycle
/// State` — see the module doc's error-table note.
fn gate_rekeyable_state(orig: &ObjectRecord) -> std::result::Result<(), KmipError> {
    match orig.state {
        State::PreActive | State::Active => Ok(()),
        other => Err(KmipError::failed(
            ResultReason::WrongKeyLifecycleState,
            format!(
                "UID {:?} is in {} — only a PreActive or Active object can be re-keyed",
                orig.uid,
                state_name(other)
            ),
        )),
    }
}

/// Resolve the other half of an existing key pair through the stored
/// pair link (`PublicKeyLink` on the private record / `PrivateKeyLink`
/// on the public record — written by Create Key Pair).
fn pair_mate(
    deps: &Deps,
    half: &ObjectRecord,
    link: &str,
) -> std::result::Result<ObjectRecord, KmipError> {
    let mate_uid = half.links.get(link).ok_or_else(|| {
        KmipError::invalid_field(format!(
            "ReKeyKeyPair: {} carries no {link} — not part of a complete key pair",
            half.uid
        ))
    })?;
    deps.store
        .get(mate_uid)?
        .ok_or_else(|| KmipError::object_not_found(mate_uid))
}

/// Table 404 / Table 409 — clone the existing record (blanket
/// attribute inheritance) then reset everything the spec says is NOT
/// copied. The caller assigns algorithm / length / usage / dates /
/// name / Digest / CKA_ID and the Replaced Object Link.
fn inherited_replacement_base(orig: &ObjectRecord, now: OffsetDateTime) -> ObjectRecord {
    let mut rec = orig.clone();
    // "Unique Identifier — New value generated".
    rec.uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
    // "Initial Date — Set to the current time"; Last Change Date too.
    rec.initial_date = now;
    rec.last_change_date = Some(now);
    rec.original_creation_date = Some(now);
    // "Destroy Date / Compromise Occurrence Date / Compromise Date /
    // Revocation Reason — Not set".
    rec.destroy_date = None;
    rec.compromise_date = None;
    rec.compromise_occurrence_date = None;
    rec.revocation_reason_code = None;
    rec.deactivation_reason_code = None;
    rec.rotate_date = None;
    // "Usage Limits — the Count value … is set to the Total value"
    // (fresh budget; Table 409's "Byte Count/Object Count values are
    // set to the Total" wording). The existing key's own remaining
    // count is left untouched.
    rec.usage_limits_remaining = rec.usage_limits_total;
    // Links describe the existing object's relations, not the
    // replacement's — "Link — Set to point to the existing key as the
    // replaced key" is the only one the spec creates (caller adds it,
    // plus the pair cross-links for Re-key Key Pair).
    rec.links = HashMap::new();
    // "Digest — Recomputed from the replacement key value" (caller);
    // fresh engine-generated material, no inherited bytes.
    rec.digest_value = None;
    rec.key_material = None;
    rec.key_value_present = None;
    // KMIP §11 Fresh = True for server-generated objects.
    rec.fresh = Some(true);
    // Plane-1 lineage marker (mirrors the RekeyAndProceed convention —
    // surfaced as the `x-pqctoday-supersedes` custom attribute).
    rec.supersedes = Some(orig.uid.clone());
    rec
}

/// Which Offset table applies: Table 403 (Re-key) also shifts Process
/// Start / Protect Stop; Table 408 (Re-key Key Pair) lists only
/// Initial / Activation / Deactivation, so the process window is
/// copied verbatim for the pair.
#[derive(Clone, Copy, PartialEq)]
enum DateTable {
    ReKey,
    ReKeyKeyPair,
}

struct ComputedDates {
    activation: Option<OffsetDateTime>,
    process_start: Option<OffsetDateTime>,
    protect_stop: Option<OffsetDateTime>,
    deactivation: Option<OffsetDateTime>,
}

/// §6.1.51 / §6.1.52 date semantics (module doc has the table). With
/// no Offset every date copies verbatim; with an Offset the
/// replacement activates at `IT2 + Offset` and the dependent dates
/// shift by `(AT2 - AT1)` when the existing object has an Activation
/// Date to anchor the delta.
fn replacement_dates(
    orig: &ObjectRecord,
    now: OffsetDateTime,
    offset: Option<u32>,
    table: DateTable,
) -> ComputedDates {
    match offset {
        // "If no Offset is specified, the Activation Date, Process
        // Start Date, Protect Stop Date and Deactivation Date values
        // are copied from the existing key."
        None => ComputedDates {
            activation: orig.activation_date,
            process_start: orig.process_start_date,
            protect_stop: orig.protect_stop_date,
            deactivation: orig.deactivation_date,
        },
        Some(off) => {
            // AT2 = IT2 + Offset, IT2 = now.
            let at2 = now + time::Duration::seconds(off as i64);
            // Delta is anchored on AT1; without one the dependent
            // dates copy unshifted (Table 403 presumes "dates exist").
            let shift = |d: Option<OffsetDateTime>| -> Option<OffsetDateTime> {
                match (d, orig.activation_date) {
                    (Some(d1), Some(at1)) => Some(d1 + (at2 - at1)),
                    (d1, None) => d1,
                    (None, _) => None,
                }
            };
            ComputedDates {
                activation: Some(at2),
                process_start: match table {
                    DateTable::ReKey => shift(orig.process_start_date),
                    DateTable::ReKeyKeyPair => orig.process_start_date,
                },
                protect_stop: match table {
                    DateTable::ReKey => shift(orig.protect_stop_date),
                    DateTable::ReKeyKeyPair => orig.protect_stop_date,
                },
                deactivation: shift(orig.deactivation_date),
            }
        }
    }
}

/// Write the computed dates onto the replacement (explicit request
/// dates outrank them — request > inherited) and derive the Table
/// 404 `State` — "Set based on attributes values, such as dates".
fn apply_dates(
    rec: &mut ObjectRecord,
    dates: &ComputedDates,
    x: &ExtractedAttrs,
    now: OffsetDateTime,
) {
    rec.activation_date = x.activation_date.or(dates.activation);
    rec.process_start_date = x.process_start_date.or(dates.process_start);
    rec.protect_stop_date = x.protect_stop_date.or(dates.protect_stop);
    rec.deactivation_date = x.deactivation_date.or(dates.deactivation);
    rec.state = if rec.deactivation_date.map_or(false, |t| t <= now) {
        State::Deactivated
    } else if rec.activation_date.map_or(false, |t| t <= now) {
        State::Active
    } else {
        State::PreActive
    };
}

/// §6.1.51 mutations on the EXISTING object: the Replacement Object
/// Link, the Table 404 Name removal ("all Name attributes are removed
/// from the existing key"), the Rotate Date stamp, and the retirement
/// rule from the module doc (Deactivation Date ← replacement's
/// Activation Date when unset; Active → Deactivated once due — the
/// same field writes as §6.1.14 Deactivate).
fn retire_original(
    old: &mut ObjectRecord,
    replacement_uid: &str,
    replacement_activation: Option<OffsetDateTime>,
    now: OffsetDateTime,
) {
    old.links
        .insert(LINK_REPLACEMENT_OBJECT.to_string(), replacement_uid.to_string());
    old.name = None;
    old.rotate_date = Some(now);
    old.last_change_date = Some(now);
    if old.deactivation_date.is_none() {
        old.deactivation_date = Some(replacement_activation.unwrap_or(now));
    }
    if old.state == State::Active && old.deactivation_date.map_or(false, |t| t <= now) {
        old.state = State::Deactivated;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{Attribute, KmipAlgorithm, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    const OPEN_POLICY: &str = "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n";

    fn deps() -> Deps {
        let ring = Arc::new(RingSink::new(128));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(OPEN_POLICY, std::path::Path::new("<t>")).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn put_aes(d: &Deps, uid: &str, state: State) -> ObjectRecord {
        let rec = ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT | UsageMask::DECRYPT,
            state,
            pkcs11_cka_id: vec![1, 2, 3],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::now_utc() - time::Duration::days(7),
            activation_date: if state == State::Active {
                Some(OffsetDateTime::now_utc() - time::Duration::days(6))
            } else {
                None
            },
            name: Some("legacy-aes".into()),
            usage_limits_total: Some(4096),
            usage_limits_remaining: Some(100),
            usage_limits_unit: Some(0x01),
            custom_attributes: {
                let mut m = HashMap::new();
                m.insert("x-team".to_string(), crate::kmip30::CustomAttributeValue::Text("blue".to_string()));
                m
            },
            fresh: Some(false),
            ..ObjectRecord::default()
        };
        d.store.put(rec.clone()).unwrap();
        rec
    }

    fn put_pair(d: &Deps) -> (String, String) {
        let now = OffsetDateTime::now_utc();
        let (priv_uid, pub_uid) = ("pair-priv".to_string(), "pair-pub".to_string());
        for (uid, ty, mask, link_k, link_v) in [
            (&priv_uid, ObjectType::PrivateKey, UsageMask::SIGN, "PublicKeyLink", &pub_uid),
            (&pub_uid, ObjectType::PublicKey, UsageMask::VERIFY, "PrivateKeyLink", &priv_uid),
        ] {
            d.store.put(ObjectRecord {
                uid: uid.clone(),
                object_type: ty,
                algorithm: KmipAlgorithm::MlDsa65,
                cryptographic_length: 0,
                usage_mask: mask,
                state: State::Active,
                pkcs11_cka_id: vec![7],
                pkcs11_slot: 0,
                initial_date: now - time::Duration::days(1),
                activation_date: Some(now - time::Duration::days(1)),
                name: Some(format!("{uid}-name")),
                links: {
                    let mut m = HashMap::new();
                    m.insert(link_k.to_string(), link_v.clone());
                    m
                },
                ..ObjectRecord::default()
            }).unwrap();
        }
        (priv_uid, pub_uid)
    }

    /// Table 404 inheritance matrix: algorithm / length / mask /
    /// custom attributes copied; fresh UID; links both directions;
    /// Name transferred to the replacement and removed from the
    /// original; Usage Limits Count reset to Total on the replacement.
    #[test]
    fn rekey_happy_path_inheritance_links_and_name_transfer() {
        let d = deps();
        put_aes(&d, "orig", State::Active);
        let resp = rekey(&d, ReKeyRequest {
            uid: "orig".into(), offset: None, template_attribute: vec![],
        }, "c").unwrap();
        assert_ne!(resp.uid, "orig", "Unique Identifier — new value generated");

        let new = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(new.algorithm, KmipAlgorithm::Aes);
        assert_eq!(new.cryptographic_length, 256);
        assert_eq!(new.usage_mask, UsageMask::ENCRYPT | UsageMask::DECRYPT);
        assert_eq!(
            new.custom_attributes.get("x-team"),
            Some(&crate::kmip30::CustomAttributeValue::Text("blue".to_string()))
        );
        // No Offset ⇒ Activation Date copied ⇒ replacement is Active.
        assert_eq!(new.state, State::Active);
        assert_eq!(new.fresh, Some(true));
        // Usage Limits: Total copied, Count = Total (Table 404/409).
        assert_eq!(new.usage_limits_total, Some(4096));
        assert_eq!(new.usage_limits_remaining, Some(4096));
        // "the replacement key takes over the name attribute".
        assert_eq!(new.name.as_deref(), Some("legacy-aes"));
        // §6.1.51 link pair.
        assert_eq!(new.links.get("ReplacedObjectLink").map(String::as_str), Some("orig"));

        let old = d.store.get("orig").unwrap().unwrap();
        assert_eq!(old.links.get("ReplacementObjectLink"), Some(&resp.uid));
        assert_eq!(old.name, None, "all Name attributes are removed from the existing key");
        // No Offset ⇒ replacement active now ⇒ original deactivates now.
        assert_eq!(old.state, State::Deactivated);
        assert!(old.deactivation_date.is_some());
    }

    /// Request `Attributes` override inherited values (request >
    /// inherited > defaults).
    #[test]
    fn rekey_request_attributes_override_inherited() {
        let d = deps();
        put_aes(&d, "orig", State::Active);
        let resp = rekey(&d, ReKeyRequest {
            uid: "orig".into(),
            offset: None,
            template_attribute: vec![
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::WRAP_KEY),
                Attribute::Name("rotated-aes".into()),
            ],
        }, "c").unwrap();
        let new = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(new.cryptographic_length, 128, "request length wins over inherited 256");
        assert_eq!(new.usage_mask, UsageMask::WRAP_KEY);
        assert_eq!(new.name.as_deref(), Some("rotated-aes"), "request Name wins");
        // The existing key STILL loses its names (Table 404).
        assert_eq!(d.store.get("orig").unwrap().unwrap().name, None);
    }

    /// Table 403 Offset math: AT2 = IT2 + Offset; DT shifts by
    /// (AT2 − AT1); the original stays Active until the replacement
    /// activates (its deactivation is scheduled, not immediate).
    #[test]
    fn rekey_offset_shifts_dates_and_defers_original_deactivation() {
        let d = deps();
        let now = OffsetDateTime::now_utc();
        let mut orig = put_aes(&d, "orig", State::Active);
        orig.deactivation_date = Some(now + time::Duration::days(30));
        d.store.update(orig.clone()).unwrap();

        let off = 3600u32; // replacement activates in an hour
        let resp = rekey(&d, ReKeyRequest {
            uid: "orig".into(), offset: Some(off), template_attribute: vec![],
        }, "c").unwrap();
        let new = d.store.get(&resp.uid).unwrap().unwrap();

        // AT2 = IT2 + Offset (IT2 = the re-key instant).
        let at2 = new.activation_date.expect("AT2 set");
        let expected_at2 = new.initial_date + time::Duration::seconds(off as i64);
        assert!((at2 - expected_at2).abs() < time::Duration::seconds(1));
        assert_eq!(new.state, State::PreActive, "AT2 is in the future");

        // DT2 = DT1 + (AT2 − AT1).
        let delta = at2 - orig.activation_date.unwrap();
        let dt2 = new.deactivation_date.expect("DT2 set");
        assert!((dt2 - (orig.deactivation_date.unwrap() + delta)).abs() < time::Duration::seconds(1));

        // The original keeps its own (earlier) Deactivation Date and
        // stays Active for now.
        let old = d.store.get("orig").unwrap().unwrap();
        assert_eq!(old.state, State::Active);
        assert_eq!(old.deactivation_date, orig.deactivation_date);
    }

    /// PreActive originals may be re-keyed; the un-dated replacement
    /// is PreActive too and the original is NOT force-deactivated
    /// (no PreActive → Deactivated edge in the §3.4 FSM).
    #[test]
    fn rekey_preactive_original_allowed() {
        let d = deps();
        put_aes(&d, "orig", State::PreActive);
        let resp = rekey(&d, ReKeyRequest {
            uid: "orig".into(), offset: None, template_attribute: vec![],
        }, "c").unwrap();
        assert_eq!(d.store.get(&resp.uid).unwrap().unwrap().state, State::PreActive);
        let old = d.store.get("orig").unwrap().unwrap();
        assert_eq!(old.state, State::PreActive, "no PreActive→Deactivated transition");
        assert!(old.deactivation_date.is_some(), "retirement is still scheduled");
        assert_eq!(old.links.get("ReplacementObjectLink"), Some(&resp.uid));
    }

    /// Error matrix per Table 407 + module-doc state rule.
    #[test]
    fn rekey_error_matrix() {
        let d = deps();
        // Object Not Found.
        let err = rekey(&d, ReKeyRequest {
            uid: "ghost".into(), offset: None, template_attribute: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectNotFound);
        // Invalid Object Type — ReKey on an asymmetric half.
        let (priv_uid, _) = put_pair(&d);
        let err = rekey(&d, ReKeyRequest {
            uid: priv_uid, offset: None, template_attribute: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidObjectType);
        // Wrong Key Lifecycle State — Deactivated original.
        put_aes(&d, "dead", State::Deactivated);
        let err = rekey(&d, ReKeyRequest {
            uid: "dead".into(), offset: None, template_attribute: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
        // Wrong Key Lifecycle State — Compromised original.
        put_aes(&d, "comp", State::Compromised);
        let err = rekey(&d, ReKeyRequest {
            uid: "comp".into(), offset: None, template_attribute: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }

    /// §6.1.52 — both halves replaced + linked both directions, names
    /// transferred per half, pair cross-links on the new halves.
    #[test]
    fn rekey_key_pair_links_both_halves() {
        let d = deps();
        let (priv_uid, pub_uid) = put_pair(&d);
        let resp = rekey_key_pair(&d, ReKeyKeyPairRequest {
            uid: priv_uid.clone(),
            offset: None,
            common_attributes: vec![],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
        }, "c").unwrap();

        let new_priv = d.store.get(&resp.private_key_uid).unwrap().unwrap();
        let new_pub = d.store.get(&resp.public_key_uid).unwrap().unwrap();
        assert_eq!(new_priv.object_type, ObjectType::PrivateKey);
        assert_eq!(new_pub.object_type, ObjectType::PublicKey);
        assert_eq!(new_priv.algorithm, KmipAlgorithm::MlDsa65);
        // Replaced links per half.
        assert_eq!(new_priv.links.get("ReplacedObjectLink"), Some(&priv_uid));
        assert_eq!(new_pub.links.get("ReplacedObjectLink"), Some(&pub_uid));
        // Pair cross-links between the NEW halves.
        assert_eq!(new_priv.links.get("PublicKeyLink"), Some(&resp.public_key_uid));
        assert_eq!(new_pub.links.get("PrivateKeyLink"), Some(&resp.private_key_uid));
        // Names transferred per half; originals stripped + linked.
        assert_eq!(new_priv.name.as_deref(), Some("pair-priv-name"));
        assert_eq!(new_pub.name.as_deref(), Some("pair-pub-name"));
        for (old_uid, new_uid) in [(&priv_uid, &resp.private_key_uid), (&pub_uid, &resp.public_key_uid)] {
            let old = d.store.get(old_uid).unwrap().unwrap();
            assert_eq!(old.name, None);
            assert_eq!(old.links.get("ReplacementObjectLink"), Some(new_uid));
            assert_eq!(old.state, State::Deactivated, "no Offset ⇒ retire now");
        }
    }

    /// Table 410 — a public-half UID resolves the pair via
    /// PrivateKeyLink; per-half attribute baskets apply per half.
    #[test]
    fn rekey_key_pair_accepts_public_half_uid_and_per_half_attrs() {
        let d = deps();
        let (priv_uid, pub_uid) = put_pair(&d);
        let resp = rekey_key_pair(&d, ReKeyKeyPairRequest {
            uid: pub_uid,
            offset: None,
            common_attributes: vec![],
            private_key_attributes: vec![Attribute::Name("new-priv".into())],
            public_key_attributes: vec![Attribute::Name("new-pub".into())],
        }, "c").unwrap();
        let new_priv = d.store.get(&resp.private_key_uid).unwrap().unwrap();
        let new_pub = d.store.get(&resp.public_key_uid).unwrap().unwrap();
        assert_eq!(new_priv.name.as_deref(), Some("new-priv"));
        assert_eq!(new_pub.name.as_deref(), Some("new-pub"));
        assert_eq!(new_priv.links.get("ReplacedObjectLink"), Some(&priv_uid));
    }

    /// Pair error matrix: not found / wrong type / wrong state.
    #[test]
    fn rekey_key_pair_error_matrix() {
        let d = deps();
        let err = rekey_key_pair(&d, ReKeyKeyPairRequest {
            uid: "ghost".into(), offset: None,
            common_attributes: vec![], private_key_attributes: vec![], public_key_attributes: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectNotFound);

        put_aes(&d, "sym", State::Active);
        let err = rekey_key_pair(&d, ReKeyKeyPairRequest {
            uid: "sym".into(), offset: None,
            common_attributes: vec![], private_key_attributes: vec![], public_key_attributes: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidObjectType);

        let (priv_uid, _) = put_pair(&d);
        let mut dead = d.store.get(&priv_uid).unwrap().unwrap();
        dead.state = State::Deactivated;
        d.store.update(dead).unwrap();
        let err = rekey_key_pair(&d, ReKeyKeyPairRequest {
            uid: priv_uid, offset: None,
            common_attributes: vec![], private_key_attributes: vec![], public_key_attributes: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }

    /// K19 interplay — Set Defaults do NOT override inherited values:
    /// a stored AES-128 default must not shrink the inherited 256.
    #[test]
    fn rekey_set_defaults_do_not_override_inheritance() {
        use crate::kmip30::{ObjectDefaults, SetDefaultsRequest};
        let d = deps();
        super::super::allocation_and_config::set_defaults(&d, SetDefaultsRequest {
            defaults_information: Some(vec![ObjectDefaults {
                object_types: vec![ObjectType::SymmetricKey],
                attributes: vec![
                    Attribute::CryptographicLength(128),
                    Attribute::CryptographicUsageMask(UsageMask::EXPORT),
                ],
            }]),
        }, "c").unwrap();
        put_aes(&d, "orig", State::Active);
        let resp = rekey(&d, ReKeyRequest {
            uid: "orig".into(), offset: None, template_attribute: vec![],
        }, "c").unwrap();
        let new = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(new.cryptographic_length, 256, "inherited length outranks the default");
        assert_eq!(new.usage_mask, UsageMask::ENCRYPT | UsageMask::DECRYPT);
    }
}
