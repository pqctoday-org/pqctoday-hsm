//! K3 — key attestation evidence (plan R2; spec §5.1; reviews K0B-R-01,
//! R-02, R-03).
//!
//! Container: the draft-ietf-rats-pkix-key-attestation-07 `Evidence` shape
//! (one signature block, signer identified by its attestation certificate,
//! `intermediateCertificates` = exactly the device issuer). Claims: the fixed
//! educational profile in the implementation notes §E, always emitted in one
//! canonical order with typed values, and recomputed by the engine from the
//! object — a caller supplies only the challenge.
//!
//! Signed bytes (spec edit E-01):
//! `"PQCToday Key Replication Evidence 1.0" || 0x00 || role || DER(TbsEvidence)`
//! with an empty ML-DSA context, so evidence produced for one role can never
//! verify in another.

use der::asn1::{Any, GeneralizedTime, ObjectIdentifier, OctetString};

use x509_cert::Certificate;

use super::asn1::{self, Evidence, ReportedClaim, ReportedElement, SignatureBlock, SignerIdentifier, TbsEvidence};
use super::oids::{self, Purpose};
use super::pki::{self, Reject, TrustInputs, ValidChain};
use super::{records, Profile};
use crate::constants::*;
use crate::crypto::handlers::Attributes;

pub const EVIDENCE_DOMAIN: &[u8] = b"PQCToday Key Replication Evidence 1.0";
pub const MAX_EVIDENCE_DER: usize = 32 * 1024;
/// Freshness window (spec §5.1) and tolerated host-clock skew into the future.
pub const FRESHNESS_SECS: u64 = 300;
pub const MAX_FUTURE_SKEW_SECS: u64 = 60;
pub const ENGINE_IDENTITY: &str = concat!("softhsmrustv3 ", env!("CARGO_PKG_VERSION"), " educational-replication");
pub const CUSTODY_SCOPE: &str = "software-token; educational test hierarchy; host clock; no hardware root";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EvidenceRole {
    Source = 0,
    Destination = 1,
    KeyAttestation = 2,
}

impl EvidenceRole {
    fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => EvidenceRole::Source,
            1 => EvidenceRole::Destination,
            2 => EvidenceRole::KeyAttestation,
            _ => return None,
        })
    }
}

/// Every claim the profile carries, typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceClaims {
    pub nonce: [u8; 32],
    pub role: EvidenceRole,
    pub transaction_id: Option<[u8; 32]>,
    pub domain_id: Option<[u8; 32]>,
    pub policy: Option<[u8; 48]>,
    pub device_id: [u8; 32],
    pub engine: String,
    pub custody_scope: String,
    pub issued_at: u64,
    pub key: KeyClaims,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyClaims {
    pub unique_id: String,
    /// SHA-384 of the key's DER SubjectPublicKeyInfo (absent for AES).
    pub public_hash: Option<[u8; 48]>,
    pub key_type: u32,
    /// `CKA_PARAMETER_SET` for ML-KEM/ML-DSA; the key length in bytes for AES.
    pub parameter_set: u32,
    pub sensitive: bool,
    pub extractable: bool,
    pub never_extractable: bool,
    pub local: bool,
    pub lineage: Option<[u8; 32]>,
    pub policy: Option<[u8; 48]>,
    pub provenance: Option<Vec<u8>>,
}

/// Recompute key claims from an object's attributes (never from the caller).
pub fn key_claims_from(attrs: &Attributes) -> Result<KeyClaims, u32> {
    let key_type = crate::state::get_object_attr_u32_from(attrs, CKA_KEY_TYPE).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let parameter_set = if key_type == CKK_AES {
        attrs.get(&CKA_VALUE).map(|v| v.len() as u32).unwrap_or(0)
    } else {
        crate::state::get_object_param_set_from(attrs)
    };
    let b = |t| crate::state::read_bool_attr(attrs, t);
    let fixed32 = |t| attrs.get(&t).and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let fixed48 = |t| attrs.get(&t).and_then(|v| <[u8; 48]>::try_from(v.as_slice()).ok());
    // A policy claim is reported only when the engine's binding marker agrees.
    let policy = match (fixed48(CKA_PQCTODAY_REPLICATION_POLICY_ID), fixed48(CKA_PRIV_REPL_BINDING)) {
        (Some(a), Some(b)) if a == b => Some(a),
        _ => None,
    };
    Ok(KeyClaims {
        unique_id: String::from_utf8(attrs.get(&CKA_UNIQUE_ID).cloned().unwrap_or_default()).map_err(|_| CKR_DEVICE_ERROR)?,
        public_hash: attrs.get(&CKA_PUBLIC_KEY_INFO).filter(|v| !v.is_empty()).map(|v| super::sha384(v)),
        key_type,
        parameter_set,
        sensitive: b(CKA_SENSITIVE),
        extractable: b(CKA_EXTRACTABLE),
        never_extractable: b(CKA_NEVER_EXTRACTABLE),
        local: b(CKA_LOCAL),
        lineage: fixed32(CKA_PQCTODAY_REPLICATION_LINEAGE_ID),
        policy,
        provenance: attrs.get(&CKA_PQCTODAY_REPLICATION_PROVENANCE).cloned(),
    })
}

fn any<T: der::EncodeValue + der::Tagged>(v: &T) -> Result<Any, u32> {
    Any::encode_from(v).map_err(|_| CKR_DEVICE_ERROR)
}

fn claim(oid: ObjectIdentifier, value: Any) -> ReportedClaim {
    ReportedClaim { claim_type: oid, value: Some(value) }
}

/// The canonical TBS for `c` (fixed element/claim order; absent optionals
/// omitted).
pub fn encode_tbs(c: &EvidenceClaims) -> Result<TbsEvidence, u32> {
    let mut tx = vec![
        claim(oids::EV_NONCE, any(&asn1::octets(&c.nonce))?),
        claim(oids::EV_ROLE, any(&(c.role as u32))?),
    ];
    if let Some(t) = c.transaction_id {
        tx.push(claim(oids::EV_TRANSACTION_ID, any(&asn1::octets(&t))?));
    }
    if let Some(d) = c.domain_id {
        tx.push(claim(oids::EV_DOMAIN_ID, any(&asn1::octets(&d))?));
    }
    if let Some(p) = c.policy {
        tx.push(claim(oids::EV_POLICY, any(&asn1::octets(&p))?));
    }
    tx.push(claim(oids::EV_SUITE, any(&oids::SUITE_V1)?));
    let issued = GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(c.issued_at)).map_err(|_| CKR_DEVICE_ERROR)?;
    let platform = vec![
        claim(oids::EV_DEVICE_ID, any(&asn1::octets(&c.device_id))?),
        claim(oids::EV_ENGINE, any(&c.engine)?),
        claim(oids::EV_CUSTODY_SCOPE, any(&c.custody_scope)?),
        claim(oids::EV_ISSUED_AT, any(&issued)?),
    ];
    let k = &c.key;
    let mut key = vec![claim(oids::EV_KEY_UNIQUE_ID, any(&k.unique_id)?)];
    if let Some(h) = k.public_hash {
        key.push(claim(oids::EV_KEY_PUBLIC_HASH, any(&asn1::octets(&h))?));
    }
    key.extend([
        claim(oids::EV_KEY_TYPE, any(&k.key_type)?),
        claim(oids::EV_KEY_PARAMETER_SET, any(&k.parameter_set)?),
        claim(oids::EV_KEY_SENSITIVE, any(&k.sensitive)?),
        claim(oids::EV_KEY_EXTRACTABLE, any(&k.extractable)?),
        claim(oids::EV_KEY_NEVER_EXTRACTABLE, any(&k.never_extractable)?),
        claim(oids::EV_KEY_LOCAL, any(&k.local)?),
    ]);
    if let Some(l) = k.lineage {
        key.push(claim(oids::EV_KEY_LINEAGE, any(&asn1::octets(&l))?));
    }
    if let Some(p) = k.policy {
        key.push(claim(oids::EV_KEY_POLICY, any(&asn1::octets(&p))?));
    }
    if let Some(p) = &k.provenance {
        key.push(claim(oids::EV_KEY_PROVENANCE, any(&asn1::octets(p))?));
    }
    Ok(TbsEvidence {
        version: 1,
        reported_elements: vec![
            ReportedElement { element_type: oids::EV_ELEMENT_TRANSACTION, claims: tx },
            ReportedElement { element_type: oids::EV_ELEMENT_PLATFORM, claims: platform },
            ReportedElement { element_type: oids::EV_ELEMENT_KEY, claims: key },
        ],
    })
}

/// Parse claims out of a TBS. Order/canonicality is enforced afterwards by
/// re-encoding and byte-comparing (so this may be lenient about order).
fn decode_claims(tbs: &TbsEvidence) -> Result<EvidenceClaims, Reject> {
    if tbs.version != 1 || tbs.reported_elements.len() != 3 {
        return Err(Reject("evidence shape"));
    }
    let find = |el: usize, oid: ObjectIdentifier| -> Option<&Any> {
        tbs.reported_elements[el].claims.iter().find(|c| c.claim_type == oid).and_then(|c| c.value.as_ref())
    };
    let oct = |a: Option<&Any>| -> Option<Vec<u8>> { a.and_then(|a| a.decode_as::<OctetString>().ok()).map(|o| o.as_bytes().to_vec()) };
    let f32 = |a| oct(a).and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let f48 = |a| oct(a).and_then(|v| <[u8; 48]>::try_from(v.as_slice()).ok());
    let u = |a: Option<&Any>| a.and_then(|a| a.decode_as::<u32>().ok());
    let bl = |a: Option<&Any>| a.and_then(|a| a.decode_as::<bool>().ok());
    let s = |a: Option<&Any>| a.and_then(|a| a.decode_as::<String>().ok());
    if tbs.reported_elements[0].element_type != oids::EV_ELEMENT_TRANSACTION
        || tbs.reported_elements[1].element_type != oids::EV_ELEMENT_PLATFORM
        || tbs.reported_elements[2].element_type != oids::EV_ELEMENT_KEY
    {
        return Err(Reject("evidence element order"));
    }
    let suite = find(0, oids::EV_SUITE).and_then(|a| a.decode_as::<ObjectIdentifier>().ok());
    if suite != Some(oids::SUITE_V1) {
        return Err(Reject("evidence suite"));
    }
    let issued_at = find(1, oids::EV_ISSUED_AT)
        .and_then(|a| a.decode_as::<GeneralizedTime>().ok())
        .map(|t| t.to_unix_duration().as_secs())
        .ok_or(Reject("issuedAt"))?;
    let key = KeyClaims {
        unique_id: s(find(2, oids::EV_KEY_UNIQUE_ID)).ok_or(Reject("key unique id"))?,
        public_hash: f48(find(2, oids::EV_KEY_PUBLIC_HASH)),
        key_type: u(find(2, oids::EV_KEY_TYPE)).ok_or(Reject("key type"))?,
        parameter_set: u(find(2, oids::EV_KEY_PARAMETER_SET)).ok_or(Reject("parameter set"))?,
        sensitive: bl(find(2, oids::EV_KEY_SENSITIVE)).ok_or(Reject("sensitive"))?,
        extractable: bl(find(2, oids::EV_KEY_EXTRACTABLE)).ok_or(Reject("extractable"))?,
        never_extractable: bl(find(2, oids::EV_KEY_NEVER_EXTRACTABLE)).ok_or(Reject("never extractable"))?,
        local: bl(find(2, oids::EV_KEY_LOCAL)).ok_or(Reject("local"))?,
        lineage: f32(find(2, oids::EV_KEY_LINEAGE)),
        policy: f48(find(2, oids::EV_KEY_POLICY)),
        provenance: oct(find(2, oids::EV_KEY_PROVENANCE)),
    };
    Ok(EvidenceClaims {
        nonce: f32(find(0, oids::EV_NONCE)).ok_or(Reject("nonce"))?,
        role: u(find(0, oids::EV_ROLE)).and_then(EvidenceRole::from_u32).ok_or(Reject("role"))?,
        transaction_id: f32(find(0, oids::EV_TRANSACTION_ID)),
        domain_id: f32(find(0, oids::EV_DOMAIN_ID)),
        policy: f48(find(0, oids::EV_POLICY)),
        device_id: f32(find(1, oids::EV_DEVICE_ID)).ok_or(Reject("device id"))?,
        engine: s(find(1, oids::EV_ENGINE)).ok_or(Reject("engine"))?,
        custody_scope: s(find(1, oids::EV_CUSTODY_SCOPE)).ok_or(Reject("custody scope"))?,
        issued_at,
        key,
    })
}

fn signed_bytes(role: EvidenceRole, tbs_der: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(EVIDENCE_DOMAIN.len() + 2 + tbs_der.len());
    m.extend_from_slice(EVIDENCE_DOMAIN);
    m.push(0);
    m.push(role as u8);
    m.extend_from_slice(tbs_der);
    m
}

/// Engine side: sign canonical evidence for `claims` with this slot's
/// attestation function key (`CKM_PQCTODAY_SIGN_KEY_ATTESTATION` semantics:
/// claims are engine-computed; only the nonce came from outside).
pub(crate) fn sign_evidence(slot: u32, claims: &EvidenceClaims) -> Result<Vec<u8>, u32> {
    evidence_der(slot, claims, true)
}

/// [`sign_evidence`]'s encoding with a zero placeholder signature of the
/// exact ML-DSA-65 length — for sizing only, never returned to a caller.
/// Every field has a fixed size for fixed inputs, so the length is exact.
pub(crate) fn evidence_der_unsigned(slot: u32, claims: &EvidenceClaims) -> Result<Vec<u8>, u32> {
    evidence_der(slot, claims, false)
}

fn evidence_der(slot: u32, claims: &EvidenceClaims, sign: bool) -> Result<Vec<u8>, u32> {
    if claims.nonce == [0u8; 32] {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let leaf_der = records::certificate(slot, Purpose::KeyAttestation).ok_or(CKR_ACTION_PROHIBITED)?;
    let dev_der = records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_ACTION_PROHIBITED)?;
    let leaf = pki::parse_cert(&leaf_der).map_err(|_| CKR_DEVICE_ERROR)?;
    let device = pki::parse_cert(&dev_der).map_err(|_| CKR_DEVICE_ERROR)?;
    if claims.device_id != pki::device_id_of(&device) {
        return Err(CKR_DEVICE_ERROR);
    }
    let tbs = encode_tbs(claims)?;
    let tbs_der = asn1::to_der(&tbs)?;
    let (_, sk) = records::function_secret(slot, Purpose::KeyAttestation).ok_or(CKR_ACTION_PROHIBITED)?;
    let sig = if sign { super::mldsa65_sign(&sk, &signed_bytes(claims.role, &tbs_der))? } else { vec![0u8; super::package::ML_DSA_65_SIG_LEN] };
    let ev = Evidence {
        tbs,
        signatures: vec![SignatureBlock {
            sid: SignerIdentifier { key_id: None, subject_public_key_info: None, certificate: Some(leaf) },
            signature_algorithm: asn1::ml_dsa_65_alg(),
            signature_value: asn1::octets(&sig),
        }],
        intermediate_certificates: Some(vec![device]),
    };
    let der = asn1::to_der(&ev)?;
    if der.len() > MAX_EVIDENCE_DER {
        return Err(CKR_DEVICE_ERROR);
    }
    Ok(der)
}

/// Platform claims for this slot at `now`.
pub(crate) fn platform_device_id(slot: u32) -> Result<[u8; 32], u32> {
    let dev = pki::parse_cert(&records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_ACTION_PROHIBITED)?)
        .map_err(|_| CKR_DEVICE_ERROR)?;
    Ok(pki::device_id_of(&dev))
}

/// K3 general key attestation: evidence about `h_key` bound to the
/// verifier's 32-byte `challenge`. The caller must be able to see the key.
pub fn attest_key(user_session: u32, h_key: u32, challenge: &[u8; 32]) -> Result<Vec<u8>, u32> {
    let (slot, claims) = attest_claims(user_session, h_key, challenge)?;
    let der = sign_evidence(slot, &claims)?;
    super::oplog_event("evidence", slot, &[("key_unique_id", claims.key.unique_id.clone()), ("role", "key-attestation".into())]);
    Ok(der)
}

/// Exact length of [`attest_key`]'s evidence (same checks; no signature, no
/// audit): every field has a fixed size for fixed inputs.
pub fn attest_key_len(user_session: u32, h_key: u32, challenge: &[u8; 32]) -> Result<usize, u32> {
    let (slot, claims) = attest_claims(user_session, h_key, challenge)?;
    evidence_der_unsigned(slot, &claims).map(|d| d.len())
}

fn attest_claims(user_session: u32, h_key: u32, challenge: &[u8; 32]) -> Result<(u32, EvidenceClaims), u32> {
    super::require_profile()?;
    let slot = super::require_user(user_session)?;
    if !super::enroll::hierarchy_ready(slot) {
        return Err(CKR_ACTION_PROHIBITED);
    }
    if !crate::state::can_access_handle(user_session, h_key) {
        return Err(CKR_KEY_HANDLE_INVALID);
    }
    let attrs = records::object_attrs(h_key).ok_or(CKR_KEY_HANDLE_INVALID)?;
    if crate::state::object_slot_of(&attrs) != slot {
        return Err(CKR_KEY_HANDLE_INVALID);
    }
    if *challenge == [0u8; 32] {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let claims = EvidenceClaims {
        nonce: *challenge,
        role: EvidenceRole::KeyAttestation,
        transaction_id: None,
        domain_id: None,
        policy: None,
        device_id: platform_device_id(slot)?,
        engine: ENGINE_IDENTITY.to_string(),
        custody_scope: CUSTODY_SCOPE.to_string(),
        issued_at: super::now_unix(),
        key: key_claims_from(&attrs)?,
    };
    Ok((slot, claims))
}

/// The result of a successful verification.
#[derive(Clone, Debug)]
pub struct VerifiedEvidence {
    pub claims: EvidenceClaims,
    pub chain: ValidChain,
}

/// Shared verification core (engine and host verifier both call this).
///
/// Strict DER; exactly one signature block whose signer is identified by its
/// attestation certificate; `intermediateCertificates` exactly the device
/// issuer; chain valid for key attestation; canonical claim profile; role,
/// nonce and freshness as expected; the device claim equals the signing
/// chain's device (K0B-R-03); domain-separated signature (K0B-R-01).
pub fn verify_evidence_core(
    der: &[u8],
    trust: &TrustInputs,
    now: u64,
    profile: Profile,
    expected_role: EvidenceRole,
    expected_nonce: &[u8; 32],
    window: Option<(u64, u64)>,
) -> Result<VerifiedEvidence, Reject> {
    if profile != Profile::Educational {
        // Every claim identifier is in the documentation arc.
        return Err(Reject("documentation OIDs outside educational profile"));
    }
    let ev: Evidence = asn1::decode_strict(der, MAX_EVIDENCE_DER).map_err(|_| Reject("evidence DER"))?;
    if ev.signatures.len() != 1 {
        return Err(Reject("signature block count"));
    }
    let sb = &ev.signatures[0];
    if sb.signature_algorithm != asn1::ml_dsa_65_alg() || sb.sid.key_id.is_some() || sb.sid.subject_public_key_info.is_some() {
        return Err(Reject("signer identifier"));
    }
    let leaf: Certificate = sb.sid.certificate.clone().ok_or(Reject("signer certificate"))?;
    let device = match ev.intermediate_certificates.as_deref() {
        Some([d]) => d.clone(),
        _ => return Err(Reject("intermediate certificates")),
    };
    let chain = pki::validate_chain(&[leaf, device], Purpose::KeyAttestation, trust, now, profile)?;
    let claims = decode_claims(&ev.tbs)?;
    let canonical = asn1::to_der(&encode_tbs(&claims).map_err(|_| Reject("claims re-encode"))?).map_err(|_| Reject("tbs"))?;
    let received = asn1::to_der(&ev.tbs).map_err(|_| Reject("tbs"))?;
    if canonical != received {
        return Err(Reject("non-canonical claim profile"));
    }
    if claims.role != expected_role {
        return Err(Reject("evidence role"));
    }
    if claims.nonce == [0u8; 32] || claims.nonce != *expected_nonce {
        return Err(Reject("nonce"));
    }
    // Freshness: against the host clock by default; against an explicit
    // window when the verifier holds a durable challenge reservation whose
    // lifetime IS the freshness bound (an offline backup imported days after
    // it was created).
    let fresh = match window {
        None => claims.issued_at <= now + MAX_FUTURE_SKEW_SECS && now.saturating_sub(claims.issued_at) <= FRESHNESS_SECS,
        Some((from, until)) => claims.issued_at + MAX_FUTURE_SKEW_SECS >= from && claims.issued_at <= until,
    };
    if !fresh {
        return Err(Reject("evidence not fresh"));
    }
    if claims.device_id != chain.device_id {
        return Err(Reject("device claim differs from signing chain"));
    }
    let pk = pki::mldsa65_public(&chain.leaf)?;
    if !super::mldsa65_verify(pk, &signed_bytes(claims.role, &received), sb.signature_value.as_bytes()) {
        return Err(Reject("evidence signature"));
    }
    Ok(VerifiedEvidence { claims, chain })
}
