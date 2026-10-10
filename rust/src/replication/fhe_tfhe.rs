//! FHE P2 — TFHE custody inside the token (P0B spec
//! `docs/proposals/pkcs11-ckm-pqctoday-fhe-proposal.md`, revision 2).
//!
//! Compiled only with the non-default `educational-fhe` feature. The seed
//! never leaves the engine: every operation derives the TFHE client-key seed
//! (§5.5), regenerates the client key, uses it and zeroizes both before
//! returning. Only public material, policy-checked plaintext, or a signed
//! HPKE-sealed release crosses the boundary.

use der::asn1::OctetString;
use der::Sequence;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::{ClientKey, CompactPublicKey, CompressedServerKey, ConfigBuilder, Seed};
use x509_cert::Certificate;
use zeroize::Zeroize;

use super::asn1;
use super::fhe::{self, FheType, PredicateKind};
use super::oids::Purpose;
use super::records;
use crate::constants::*;
use crate::crypto::handlers::Attributes;

pub const KDF_LABEL: &[u8] = b"pqctoday-fhe/tfhe-client-key-seed";
pub const PARAM_NAME_V1: &str = "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128";
pub const LIBRARY_V1: &str = "tfhe-rs 1.8.1 187fc0b9";
pub const MAX_DECRYPT_INPUT: usize = 4 * 1024 * 1024;
pub const MAX_PUBLIC_OBJECT: usize = 64 * 1024 * 1024;
pub const RELEASE_DOMAIN: &[u8] = b"PQCToday FHE Release 1.0";

pub const PUBLIC_KIND_COMPRESSED_SERVER_KEY: u32 = 1;
pub const PUBLIC_KIND_COMPACT_PUBLIC_KEY: u32 = 2;

fn config_v1() -> tfhe::Config {
    ConfigBuilder::default().use_dedicated_oprf_key(false).build()
}

// ── §5.5 seed derivation (generator version 1) ─────────────────────────────

fn lp(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// SP 800-108r1 counter mode, PRF HMAC-SHA-384, one block, first 16 bytes
/// big-endian → TFHE-rs `Seed(u128)`.
pub fn derive_tfhe_seed(seed: &[u8; 32]) -> u128 {
    use hmac::{Hmac, Mac};
    let context = lp(&[b"TFHE", PARAM_NAME_V1.as_bytes(), b"cfg:no-dedicated-oprf", b"client", b"v1"]);
    let mut mac = <Hmac<sha2::Sha384> as Mac>::new_from_slice(seed).expect("any key length");
    mac.update(&1u32.to_be_bytes());
    mac.update(KDF_LABEL);
    mac.update(&[0u8]);
    mac.update(&context);
    mac.update(&128u32.to_be_bytes());
    let mut block = mac.finalize().into_bytes();
    let mut first = [0u8; 16];
    first.copy_from_slice(&block[..16]);
    block.as_mut_slice().zeroize();
    u128::from_be_bytes(first)
}

/// The client key for a seed. Callers must drop it promptly; it is never
/// stored, cached or returned across the FFI.
pub fn client_key_for(seed: &[u8; 32]) -> ClientKey {
    let mut s = derive_tfhe_seed(seed);
    let ck = ClientKey::generate_with_seed(config_v1(), Seed(s));
    s.zeroize();
    ck
}

// ── Seed object access ─────────────────────────────────────────────────────

pub(crate) struct SeedObject {
    pub handle: u32,
    pub attrs: Attributes,
    pub seed: [u8; 32],
}

impl Drop for SeedObject {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Resolve and check an FHE seed for `mechanism` (§5.3 steps 1–2).
pub(crate) fn seed_object(session: u32, h: u32, mechanism: u32) -> Result<(u32, SeedObject), u32> {
    super::require_profile()?;
    let slot = super::require_user_rw(session)?;
    if !crate::state::can_access_handle(session, h) {
        return Err(CKR_KEY_HANDLE_INVALID);
    }
    let attrs = records::object_attrs(h).ok_or(CKR_KEY_HANDLE_INVALID)?;
    if crate::state::object_slot_of(&attrs) != slot {
        return Err(CKR_KEY_HANDLE_INVALID);
    }
    if crate::state::get_object_attr_u32_from(&attrs, CKA_KEY_TYPE) != Some(CKK_PQCTODAY_FHE) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let allowed = crate::state::parse_allowed_mechanisms(attrs.get(&CKA_ALLOWED_MECHANISMS).map(|v| v.as_slice()).unwrap_or(&[]));
    if !allowed.contains(&mechanism) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    let seed: [u8; 32] = attrs.get(&CKA_VALUE).and_then(|v| v.as_slice().try_into().ok()).ok_or(CKR_DEVICE_ERROR)?;
    Ok((slot, SeedObject { handle: h, attrs, seed }))
}

// ── §5.2 DERIVE_PUBLIC ─────────────────────────────────────────────────────

/// Derive fresh public material from the seed as a public SESSION object.
pub fn derive_public(session: u32, h_seed: u32, kind: u32) -> Result<u32, u32> {
    let (slot, so) = seed_object(session, h_seed, CKM_PQCTODAY_FHE_DERIVE_PUBLIC)?;
    if so.attrs.get(&CKA_PQCTODAY_FHE_SCHEME).map(|v| v.as_slice()) != Some(fhe::FHE_SCHEME_TFHE.as_bytes()) {
        // A streamed-CKKS seed uses parameter version 2 (fhe_ckks::mech).
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    if kind != PUBLIC_KIND_COMPRESSED_SERVER_KEY && kind != PUBLIC_KIND_COMPACT_PUBLIC_KEY {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let ck = client_key_for(&so.seed);
    let mut blob = Vec::new();
    let r = if kind == PUBLIC_KIND_COMPRESSED_SERVER_KEY {
        safe_serialize(&CompressedServerKey::new(&ck), &mut blob, MAX_PUBLIC_OBJECT as u64)
    } else {
        safe_serialize(&CompactPublicKey::new(&ck), &mut blob, MAX_PUBLIC_OBJECT as u64)
    };
    drop(ck);
    r.map_err(|_| CKR_DEVICE_MEMORY)?;
    let mut a: Attributes = Default::default();
    crate::state::store_ulong(&mut a, CKA_CLASS, CKO_PUBLIC_KEY);
    crate::state::store_ulong(&mut a, CKA_KEY_TYPE, CKK_PQCTODAY_FHE_PUBLIC);
    crate::state::store_bool(&mut a, CKA_TOKEN, false);
    crate::state::store_bool(&mut a, CKA_PRIVATE, false);
    crate::state::store_bool(&mut a, CKA_MODIFIABLE, false);
    crate::state::store_bool(&mut a, CKA_LOCAL, false);
    crate::state::store_ulong(&mut a, CKA_PQCTODAY_FHE_PUBLIC_KIND, kind);
    for t in [CKA_PQCTODAY_FHE_PARAM_HASH, CKA_PQCTODAY_FHE_LINEAGE_ID] {
        if let Some(v) = so.attrs.get(&t) {
            a.insert(t, v.clone());
        }
    }
    a.insert(CKA_VALUE, blob);
    let h = crate::state::commit_objects_atomically(session, vec![a], Vec::new())?[0];
    super::oplog_event("fhe_derive_public", slot, &[("kind", kind.to_string())]);
    Ok(h)
}

/// P0B §5.2 server-key / public-key manifest, signed by the application with
/// a token-resident, attested ML-DSA-65 key (`C_Sign(CKM_ML_DSA)`, empty
/// context). The blob itself is never signature input (F4).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FhePublicManifestV1 {
    pub lineage: OctetString,
    pub param_hash: OctetString,
    pub kind: u32,
    pub value_sha384: OctetString,
}

/// Manifest DER for a derived public object.
pub fn public_manifest(lineage: &[u8], param_hash: &[u8], kind: u32, value: &[u8]) -> Result<Vec<u8>, u32> {
    asn1::to_der(&FhePublicManifestV1 {
        lineage: asn1::octets(lineage),
        param_hash: asn1::octets(param_hash),
        kind,
        value_sha384: asn1::octets(&super::sha384(value)),
    })
}

// ── §5.3 DECRYPT ───────────────────────────────────────────────────────────

/// The engine-private decrypt counter (§6.4).
pub const CKA_PRIV_FHE_DECRYPT_COUNT: u32 = 0xFFFF_000C;

/// Decrypt result: either the owner output, or a signed sealed release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecryptOutput {
    Owner(Vec<u8>),
    Sealed(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FheReleaseTbs {
    pub lineage: OctetString,
    pub decrypt_policy_id: OctetString,
    pub recipient: OctetString,
    pub counter: u64,
    pub sealed_hash: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FheSealedReleaseV1 {
    pub enc: OctetString,
    pub ciphertext: OctetString,
    pub counter: u64,
    pub signature: OctetString,
    pub signer_chain: Vec<Certificate>,
}

/// A matched releasable type and its decrypted value.
struct Matched {
    ty: FheType,
}

fn type_header(ty: &FheType) -> [u8; 3] {
    let tag = if ty.type_name == "FheBool" { 0u8 } else { 1u8 };
    let w = ty.width_bits.to_be_bytes();
    [tag, w[0], w[1]]
}

fn output_len(ty: &FheType) -> usize {
    3 + (ty.width_bits as usize).div_ceil(8)
}

/// Rule 1: the first allowed type whose conformance parameters the input
/// satisfies. Shape only — never touches the key.
fn type_gate(policy: &fhe::FheDecryptPolicy, input: &[u8]) -> Option<Matched> {
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P;
    let lim = MAX_DECRYPT_INPUT as u64;
    macro_rules! conf {
        ($t:ty, $p:ty) => {
            safe_deserialize_conformant::<$t>(input, lim, &<$p>::from(P)).is_ok()
        };
    }
    for ty in &policy.allowed_output_types {
        if ty.param_set != 1 || ty.compressed_allowed {
            continue;
        }
        let ok = match (ty.type_name.as_str(), ty.width_bits) {
            ("FheBool", 1) => conf!(tfhe::FheBool, tfhe::FheBoolConformanceParams),
            ("FheUint2", 2) => conf!(tfhe::FheUint2, tfhe::FheUint2ConformanceParams),
            ("FheUint4", 4) => conf!(tfhe::FheUint4, tfhe::FheUint4ConformanceParams),
            ("FheUint8", 8) => conf!(tfhe::FheUint8, tfhe::FheUint8ConformanceParams),
            ("FheUint16", 16) => conf!(tfhe::FheUint16, tfhe::FheUint16ConformanceParams),
            ("FheUint32", 32) => conf!(tfhe::FheUint32, tfhe::FheUint32ConformanceParams),
            ("FheUint64", 64) => conf!(tfhe::FheUint64, tfhe::FheUint64ConformanceParams),
            _ => false,
        };
        if ok {
            return Some(Matched { ty: ty.clone() });
        }
    }
    None
}

fn decrypt_value(ty: &FheType, input: &[u8], ck: &ClientKey) -> Option<u64> {
    let lim = MAX_DECRYPT_INPUT as u64;
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P;
    macro_rules! dec {
        ($t:ty, $p:ty, $out:ty) => {{
            let ct = safe_deserialize_conformant::<$t>(input, lim, &<$p>::from(P)).ok()?;
            let v: $out = ct.decrypt(ck);
            Some(v as u64)
        }};
    }
    match ty.type_name.as_str() {
        "FheBool" => {
            let ct = safe_deserialize_conformant::<tfhe::FheBool>(input, lim, &tfhe::FheBoolConformanceParams::from(P)).ok()?;
            let v: bool = ct.decrypt(ck);
            Some(v as u64)
        }
        "FheUint2" => dec!(tfhe::FheUint2, tfhe::FheUint2ConformanceParams, u8),
        "FheUint4" => dec!(tfhe::FheUint4, tfhe::FheUint4ConformanceParams, u8),
        "FheUint8" => dec!(tfhe::FheUint8, tfhe::FheUint8ConformanceParams, u8),
        "FheUint16" => dec!(tfhe::FheUint16, tfhe::FheUint16ConformanceParams, u16),
        "FheUint32" => dec!(tfhe::FheUint32, tfhe::FheUint32ConformanceParams, u32),
        "FheUint64" => dec!(tfhe::FheUint64, tfhe::FheUint64ConformanceParams, u64),
        _ => None,
    }
}

pub(crate) fn refuse(slot: u32, why: &'static str) -> u32 {
    super::note_refusal(why);
    super::oplog_event("fhe_decrypt_refused", slot, &[("reason", format!("\"{why}\""))]);
    CKR_ACTION_PROHIBITED
}

/// `C_Decrypt(CKM_PQCTODAY_FHE_DECRYPT)`. `size_only` is the `pData == NULL`
/// call: shape-level type gate only, no decryption, no counter (§5.3 step 3).
pub fn decrypt(session: u32, h_seed: u32, recipient: &[u8; 48], input: &[u8], size_only: bool) -> Result<(usize, Option<DecryptOutput>), u32> {
    if super::fhe_ckks::mech::is_ckks_seed(h_seed) {
        return super::fhe_ckks::mech::decrypt(session, h_seed, recipient, input, size_only);
    }
    let (slot, so) = seed_object(session, h_seed, CKM_PQCTODAY_FHE_DECRYPT)?;
    if input.is_empty() || input.len() > MAX_DECRYPT_INPUT {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let pid = so.attrs.get(&CKA_PQCTODAY_FHE_DECRYPT_POLICY).cloned().ok_or(CKR_DEVICE_ERROR)?;
    let policy = fhe::find_decrypt_policy(slot, &pid).ok_or_else(|| refuse(slot, "decryption policy not enrolled"))?;
    let p = &policy.policy;
    let owner = *recipient == [0u8; 48];
    if size_only {
        let m = type_gate(p, input).ok_or_else(|| refuse(slot, "type gate"))?;
        return Ok((if owner { output_len(&m.ty) } else { 0 }, None));
    }
    // Step 4: reserve one unit of the counter durably, before any work.
    let used = so.attrs.get(&CKA_PRIV_FHE_DECRYPT_COUNT).and_then(|v| v.as_slice().try_into().ok()).map(u64::from_le_bytes).unwrap_or(0);
    if used >= p.max_decrypts as u64 {
        return Err(refuse(slot, "decrypt budget exhausted"));
    }
    let counter = used + 1;
    crate::state::commit_objects_atomically(session, Vec::new(), vec![(so.handle, vec![(CKA_PRIV_FHE_DECRYPT_COUNT, counter.to_le_bytes().to_vec())])])?;
    // Step 5: rule 5 (recipient), independent of the plaintext.
    if (owner && p.recipient_only) || (!owner && !p.recipients.iter().any(|r| r.as_bytes() == recipient)) {
        return Err(refuse(slot, "recipient not allowed"));
    }
    // Steps 6–7: type gate, never-release.
    let m = type_gate(p, input).ok_or_else(|| refuse(slot, "type gate"))?;
    if p.never_release.contains(&m.ty) {
        return Err(refuse(slot, "never-release type"));
    }
    // Step 8: decrypt with a regenerated, immediately dropped client key.
    let ck = client_key_for(&so.seed);
    let value = decrypt_value(&m.ty, input, &ck);
    drop(ck);
    let value = value.ok_or_else(|| refuse(slot, "type gate"))?;
    // Step 9: predicates.
    for pr in &p.predicates {
        let ok = match pr.kind {
            PredicateKind::MaxValue => value <= pr.bound,
            PredicateKind::MinValue => value >= pr.bound,
        };
        if !ok {
            return Err(refuse(slot, "predicate"));
        }
    }
    // Step 10: release.
    let mut plain = type_header(&m.ty).to_vec();
    let nbytes = (m.ty.width_bits as usize).div_ceil(8);
    plain.extend_from_slice(&value.to_le_bytes()[..nbytes.min(8)]);
    plain.resize(3 + nbytes, 0);
    super::oplog_event(
        "fhe_decrypt_released",
        slot,
        &[("policy", super::hex(&policy.id)), ("type", m.ty.type_name.clone()), ("counter", counter.to_string()), ("recipient", if owner { "owner".into() } else { super::hex(recipient) })],
    );
    if owner {
        return Ok((plain.len(), Some(DecryptOutput::Owner(plain))));
    }
    let sealed = seal_release(slot, &so.attrs, &policy.id, recipient, counter, &plain);
    plain.zeroize();
    let sealed = sealed?;
    Ok((sealed.len(), Some(DecryptOutput::Sealed(sealed))))
}

/// HPKE `info` AND `aad` of a sealed release (spec §5.3; amendment proposed
/// to rev 3: the 3-byte type header lives inside the authenticated plaintext,
/// because a recipient cannot know it before opening).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FheReleaseInfo {
    pub lineage: OctetString,
    pub decrypt_policy_id: OctetString,
    pub recipient: OctetString,
    pub counter: u64,
}

/// HPKE-seal the plaintext to the enrolled recipient and sign the release
/// with this device's receipt-signing function key (§5.3, amendment A2).
pub(crate) fn seal_release(slot: u32, attrs: &Attributes, policy_id: &[u8; 48], recipient: &[u8; 48], counter: u64, plain: &[u8]) -> Result<Vec<u8>, u32> {
    let lineage = attrs.get(&CKA_PQCTODAY_FHE_LINEAGE_ID).cloned().unwrap_or_default();
    let ek = recipient_key(slot, recipient).ok_or(CKR_ACTION_PROHIBITED)?;
    let info = asn1::to_der(&FheReleaseInfo {
        lineage: asn1::octets(&lineage),
        decrypt_policy_id: asn1::octets(policy_id),
        recipient: asn1::octets(recipient),
        counter,
    })?;
    let (enc, ct) = crate::native::hpke::seal_replication_v1(&ek, &info, &info, plain).map_err(|_| CKR_DEVICE_ERROR)?;
    let tbs = FheReleaseTbs {
        lineage: asn1::octets(&lineage),
        decrypt_policy_id: asn1::octets(policy_id),
        recipient: asn1::octets(recipient),
        counter,
        sealed_hash: asn1::octets(&super::sha384(&[enc.as_slice(), ct.as_slice()].concat())),
    };
    let (_, sk) = records::function_secret(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?;
    let sig = super::mldsa65_sign(&sk, &release_signed_bytes(&tbs)?)?;
    let chain = super::pki::chain_from_ders(&[
        records::certificate(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?,
        records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?,
    ])
    .map_err(|_| CKR_DEVICE_ERROR)?;
    asn1::to_der(&FheSealedReleaseV1 {
        enc: asn1::octets(&enc),
        ciphertext: asn1::octets(&ct),
        counter,
        signature: asn1::octets(&sig),
        signer_chain: chain,
    })
}

fn release_signed_bytes(tbs: &FheReleaseTbs) -> Result<Vec<u8>, u32> {
    let mut msg = RELEASE_DOMAIN.to_vec();
    msg.push(0);
    msg.extend_from_slice(&asn1::to_der(tbs)?);
    Ok(msg)
}

/// What a verified, opened release establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedRelease {
    pub signer_device_id: [u8; 32],
    pub counter: u64,
    /// The owner-format plaintext: 3-byte type header + LE value.
    pub plaintext: Vec<u8>,
}

/// Recipient side: verify the release signature and signer chain against
/// this token's trust inputs, check it is addressed to this token's
/// recovery key, bind it to the expected seed lineage and policy, then open
/// it inside the token.
pub fn open_release(session: u32, sealed: &[u8], lineage: &[u8; 32], policy_id: &[u8; 48]) -> Result<OpenedRelease, u32> {
    super::require_profile()?;
    let slot = super::require_user_rw(session)?;
    let r: FheSealedReleaseV1 = asn1::decode_strict(sealed, 64 * 1024)?;
    let trust = super::enroll::trust_inputs(slot);
    let chain = super::pki::validate_chain(&r.signer_chain, Purpose::ReceiptSigning, &trust, super::now_unix(), super::Profile::Educational)
        .map_err(|_| CKR_SIGNATURE_INVALID)?;
    let recovery = super::pki::parse_cert(&records::certificate(slot, Purpose::RecoveryRecipient).ok_or(CKR_DEVICE_ERROR)?).map_err(|_| CKR_DEVICE_ERROR)?;
    let me = super::pki::spki_hash(&recovery);
    let tbs = FheReleaseTbs {
        lineage: asn1::octets(lineage),
        decrypt_policy_id: asn1::octets(policy_id),
        recipient: asn1::octets(&me),
        counter: r.counter,
        sealed_hash: asn1::octets(&super::sha384(&[r.enc.as_bytes(), r.ciphertext.as_bytes()].concat())),
    };
    let pk = super::pki::mldsa65_public(&chain.leaf).map_err(|_| CKR_SIGNATURE_INVALID)?;
    if !super::mldsa65_verify(pk, &release_signed_bytes(&tbs)?, r.signature.as_bytes()) {
        return Err(CKR_SIGNATURE_INVALID);
    }
    let info = asn1::to_der(&FheReleaseInfo {
        lineage: asn1::octets(lineage),
        decrypt_policy_id: asn1::octets(policy_id),
        recipient: asn1::octets(&me),
        counter: r.counter,
    })?;
    let dk = records::recovery_secret_for(slot, &me).ok_or(CKR_DEVICE_ERROR)?;
    let plaintext = crate::native::hpke::open_replication_v1(&dk, r.enc.as_bytes(), &info, &info, r.ciphertext.as_bytes())?;
    Ok(OpenedRelease { signer_device_id: chain.device_id, counter: r.counter, plaintext })
}

/// Recipient ML-KEM-768 encapsulation key by SPKI hash, from the FHE
/// recipient certificates the SO enrolled (role 14).
fn recipient_key(slot: u32, spki_hash: &[u8; 48]) -> Option<Vec<u8>> {
    records::list(slot, ROLE_FHE_RECIPIENT).into_iter().find_map(|(_, a)| {
        let c = super::pki::parse_cert(records::value_bytes(&a)).ok()?;
        (super::pki::spki_hash(&c) == *spki_hash).then(|| super::pki::mlkem768_public(&c).ok().map(|k| k.to_vec())).flatten()
    })
}

/// Records role for an SO-enrolled FHE release recipient certificate.
pub const ROLE_FHE_RECIPIENT: u8 = 14;

/// SO enrollment of a third-party release recipient: an ML-KEM-768
/// recovery-recipient certificate of a device that chains to an enrolled
/// root. Returns the SPKI hash a decryption policy names.
pub fn enroll_fhe_recipient(so_session: u32, recipient_chain: &[Vec<u8>]) -> Result<[u8; 48], u32> {
    super::require_profile()?;
    let slot = super::require_so(so_session)?;
    let chain = super::pki::chain_from_ders(recipient_chain).map_err(|_| CKR_DATA_INVALID)?;
    let trust = super::enroll::trust_inputs(slot);
    let v = super::pki::validate_chain(&chain, Purpose::RecoveryRecipient, &trust, super::now_unix(), super::Profile::Educational)
        .map_err(|_| CKR_SIGNATURE_INVALID)?;
    let h = super::pki::spki_hash(&v.leaf);
    if recipient_key(slot, &h).is_none() {
        let der = recipient_chain[0].clone();
        let rec = records::new_record(ROLE_FHE_RECIPIENT, CKO_CERTIFICATE, "FHE release recipient certificate", der, Vec::new(), false);
        crate::state::commit_objects_atomically(so_session, vec![rec], Vec::new())?;
    }
    Ok(h)
}

// ── §5.4 ENCRYPT (test builds only) ────────────────────────────────────────

/// Encrypt an owner-output-format plaintext under the seed's client key.
/// TEST-ONLY (known-answer vectors); absent without `test-support`.
#[cfg(feature = "test-support")]
pub fn encrypt_for_test(session: u32, h_seed: u32, type_name: &str, value: u64) -> Result<Vec<u8>, u32> {
    let (_, so) = seed_object_any(session, h_seed)?;
    let ck = client_key_for(&so.seed);
    let mut out = Vec::new();
    let lim = MAX_DECRYPT_INPUT as u64;
    let r = match type_name {
        "FheBool" => safe_serialize(&tfhe::FheBool::encrypt(value != 0, &ck), &mut out, lim),
        "FheUint8" => safe_serialize(&tfhe::FheUint8::encrypt(value as u8, &ck), &mut out, lim),
        "FheUint16" => safe_serialize(&tfhe::FheUint16::encrypt(value as u16, &ck), &mut out, lim),
        "FheUint32" => safe_serialize(&tfhe::FheUint32::encrypt(value as u32, &ck), &mut out, lim),
        "FheUint64" => safe_serialize(&tfhe::FheUint64::encrypt(value, &ck), &mut out, lim),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    };
    r.map_err(|_| CKR_DEVICE_ERROR)?;
    Ok(out)
}

#[cfg(feature = "test-support")]
fn seed_object_any(session: u32, h: u32) -> Result<(u32, SeedObject), u32> {
    let slot = super::require_user_rw(session)?;
    let attrs = records::object_attrs(h).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let seed: [u8; 32] = attrs.get(&CKA_VALUE).and_then(|v| v.as_slice().try_into().ok()).ok_or(CKR_KEY_HANDLE_INVALID)?;
    Ok((slot, SeedObject { handle: h, attrs, seed }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §5.5 known-answer vector `client-key-kat-v1`.
    #[test]
    fn kat_client_key_v1() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(derive_tfhe_seed(&seed), 0xf6eb1c9a88a4442c8a7449536c3d12dc);
        let ck = client_key_for(&seed);
        let mut buf = Vec::new();
        safe_serialize(&ck, &mut buf, 1 << 32).unwrap();
        assert_eq!(buf.len(), 24_087);
        let h: String = super::super::sha256(&buf).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(h, "9f5d847e4d1121eef9d75fcc473e89ee5306523f9cb140384eba5aa85a55b77b");
    }
}

// ── C ABI dispatch helpers (P0B §5; called from ffi.rs) ────────────────────
//
// Parameter structs are read at the exported CK_ULONG width (usize: 4 bytes
// on wasm32, 8 on 64-bit native), exactly as the rest of ffi.rs reads
// CK_MECHANISM. A wrong length or version is CKR_MECHANISM_PARAM_INVALID.

pub(crate) const W: usize = std::mem::size_of::<usize>();

pub(crate) unsafe fn param_bytes<'a>(p: *const u8, len: usize, want: usize) -> Result<&'a [u8], u32> {
    if p.is_null() || len != want {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    Ok(std::slice::from_raw_parts(p, len))
}

pub(crate) fn ulong_at(b: &[u8], off: usize) -> usize {
    let mut v = [0u8; W];
    v.copy_from_slice(&b[off..off + W]);
    usize::from_le_bytes(v)
}

/// Raw CK_ATTRIBUTE triples → (type, value) pairs, bounded.
pub(crate) unsafe fn read_template(t: *mut u8, n: u32) -> Result<Vec<(u32, Vec<u8>)>, u32> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if t.is_null() || n > 64 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let p = t as *const usize;
    let mut out = Vec::new();
    for i in 0..n as usize {
        let ty = *p.add(i * 3) as u32;
        let vp = *p.add(i * 3 + 1) as *const u8;
        let vl = *p.add(i * 3 + 2);
        if vl > 4096 || (vl > 0 && vp.is_null()) {
            return Err(CKR_ARGUMENTS_BAD);
        }
        out.push((ty, if vl == 0 { Vec::new() } else { std::slice::from_raw_parts(vp, vl).to_vec() }));
    }
    Ok(out)
}

pub(crate) fn bool_of(v: &[u8]) -> Option<bool> {
    match v {
        [0] => Some(false),
        [1] => Some(true),
        _ => None,
    }
}

/// `C_GenerateKey(CKM_PQCTODAY_FHE_KEY_GEN)`. Template may set only
/// CKA_LABEL, CKA_ID and CKA_TOKEN=TRUE (§5.1).
///
/// # Safety
/// FFI pointers as for `C_GenerateKey`.
pub unsafe fn ffi_key_gen(session: u32, p_param: *const u8, param_len: usize, tmpl: *mut u8, n: u32) -> Result<u32, u32> {
    let b = param_bytes(p_param, param_len, 2 * W + 96)?;
    if ulong_at(b, 0) != 1 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let param_set = u32::try_from(ulong_at(b, W)).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    let rp: [u8; 48] = b[2 * W..2 * W + 48].try_into().unwrap();
    let dp: [u8; 48] = b[2 * W + 48..2 * W + 96].try_into().unwrap();
    let (mut label, mut id) = (None, None);
    for (t, v) in read_template(tmpl, n)? {
        match t {
            records::CKA_LABEL => label = Some(v),
            t if t == crate::native::CKA_ID => id = Some(v),
            CKA_TOKEN if bool_of(&v) == Some(true) => {}
            _ => return Err(CKR_TEMPLATE_INCONSISTENT),
        }
    }
    fhe::generate_fhe_seed(session, param_set, &rp, &dp, label.as_deref(), id.as_deref())
}

/// `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC)`. Template may only restate
/// the fixed derive template (§3) plus CKA_LABEL/CKA_ID (§5.2).
///
/// # Safety
/// FFI pointers as for `C_DeriveKey`.
pub unsafe fn ffi_derive_public(session: u32, base: u32, p_param: *const u8, param_len: usize, tmpl: *mut u8, n: u32) -> Result<u32, u32> {
    // Parameter version 2 (six CK_ULONGs): streamed CKKS material.
    if param_len == 6 * W {
        return super::fhe_ckks::mech::ffi_derive_public_v2(session, base, p_param, param_len, tmpl, n);
    }
    let b = param_bytes(p_param, param_len, 2 * W)?;
    if ulong_at(b, 0) != 1 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let kind = u32::try_from(ulong_at(b, W)).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    let ul = |v: &[u8]| (v.len() == W).then(|| ulong_at(v, 0) as u32);
    for (t, v) in read_template(tmpl, n)? {
        let ok = match t {
            records::CKA_LABEL => true,
            t if t == crate::native::CKA_ID => true,
            CKA_TOKEN | CKA_PRIVATE => bool_of(&v) == Some(false),
            CKA_CLASS => ul(&v) == Some(CKO_PUBLIC_KEY),
            CKA_KEY_TYPE => ul(&v) == Some(CKK_PQCTODAY_FHE_PUBLIC),
            _ => false,
        };
        if !ok {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
    }
    derive_public(session, base, kind)
}

/// Active single-part FHE decrypt/encrypt operations, by session.
#[derive(Clone, Copy)]
pub enum FheOp {
    Decrypt { key: u32, recipient: [u8; 48] },
    #[cfg(feature = "test-support")]
    Encrypt { key: u32 },
}

static FHE_OPS: std::sync::Mutex<Option<std::collections::HashMap<u32, FheOp>>> = std::sync::Mutex::new(None);

fn ops<R>(f: impl FnOnce(&mut std::collections::HashMap<u32, FheOp>) -> R) -> R {
    let mut g = FHE_OPS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Default::default))
}

pub fn active(session: u32) -> Option<FheOp> {
    ops(|m| m.get(&session).copied())
}

pub fn cancel(session: u32) -> bool {
    ops(|m| m.remove(&session).is_some())
}

/// `C_DecryptInit(CKM_PQCTODAY_FHE_DECRYPT)`: validates the key and records
/// the operation. Policy work happens in `C_Decrypt` (§5.3).
///
/// # Safety
/// FFI pointers as for `C_DecryptInit`.
pub unsafe fn ffi_decrypt_init(session: u32, key: u32, p_param: *const u8, param_len: usize) -> Result<(), u32> {
    let b = param_bytes(p_param, param_len, (W + 48).next_multiple_of(W))?;
    if ulong_at(b, 0) != 1 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let recipient: [u8; 48] = b[W..W + 48].try_into().unwrap();
    seed_object(session, key, CKM_PQCTODAY_FHE_DECRYPT)?;
    ops(|m| m.insert(session, FheOp::Decrypt { key, recipient }));
    Ok(())
}

/// `C_Decrypt` for an active FHE operation. NULL output = size query (the
/// operation stays active); too-small buffer keeps it active too (PKCS#11
/// §5.2); every other outcome ends it.
///
/// # Safety
/// FFI pointers as for `C_Decrypt`.
pub unsafe fn ffi_decrypt(session: u32, input: *const u8, in_len: u32, out: *mut u8, out_len: *mut u32) -> u32 {
    let Some(FheOp::Decrypt { key, recipient }) = active(session) else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    if out_len.is_null() || input.is_null() {
        cancel(session);
        return CKR_ARGUMENTS_BAD;
    }
    let data = std::slice::from_raw_parts(input, in_len as usize);
    if out.is_null() {
        return match decrypt(session, key, &recipient, data, true) {
            Ok((n, _)) => {
                *out_len = n as u32;
                CKR_OK
            }
            Err(e) => {
                cancel(session);
                e
            }
        };
    }
    let r = decrypt(session, key, &recipient, data, false);
    cancel(session);
    match r {
        Ok((n, Some(DecryptOutput::Owner(b) | DecryptOutput::Sealed(b)))) => {
            if (*out_len as usize) < n {
                // The counter unit is already spent: a caller must size first.
                *out_len = n as u32;
                return CKR_BUFFER_TOO_SMALL;
            }
            std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len());
            *out_len = b.len() as u32;
            CKR_OK
        }
        Ok(_) => CKR_DEVICE_ERROR,
        Err(e) => e,
    }
}

/// `C_EncryptInit(CKM_PQCTODAY_FHE_ENCRYPT)` — test builds only (§5.4).
///
/// # Safety
/// FFI pointers as for `C_EncryptInit`.
#[cfg(feature = "test-support")]
pub unsafe fn ffi_encrypt_init(session: u32, key: u32) -> Result<(), u32> {
    seed_object_any(session, key)?;
    ops(|m| m.insert(session, FheOp::Encrypt { key }));
    Ok(())
}

/// `C_Encrypt` for an active FHE test encryption: input is the owner-output
/// format (3-byte header + LE value).
///
/// # Safety
/// FFI pointers as for `C_Encrypt`.
#[cfg(feature = "test-support")]
pub unsafe fn ffi_encrypt(session: u32, input: *const u8, in_len: u32, out: *mut u8, out_len: *mut u32) -> u32 {
    let Some(FheOp::Encrypt { key }) = active(session) else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    if input.is_null() || out_len.is_null() || in_len < 4 {
        cancel(session);
        return CKR_ARGUMENTS_BAD;
    }
    let b = std::slice::from_raw_parts(input, in_len as usize);
    let width = u16::from_be_bytes([b[1], b[2]]);
    let mut v = [0u8; 8];
    let n = (b.len() - 3).min(8);
    v[..n].copy_from_slice(&b[3..3 + n]);
    let name = match (b[0], width) {
        (0, 1) => "FheBool",
        (1, 8) => "FheUint8",
        (1, 16) => "FheUint16",
        (1, 32) => "FheUint32",
        (1, 64) => "FheUint64",
        _ => {
            cancel(session);
            return CKR_DATA_INVALID;
        }
    };
    let ct = match encrypt_for_test(session, key, name, u64::from_le_bytes(v)) {
        Ok(c) => c,
        Err(e) => {
            cancel(session);
            return e;
        }
    };
    if out.is_null() {
        *out_len = ct.len() as u32;
        return CKR_OK;
    }
    if (*out_len as usize) < ct.len() {
        *out_len = ct.len() as u32;
        return CKR_BUFFER_TOO_SMALL;
    }
    cancel(session);
    std::ptr::copy_nonoverlapping(ct.as_ptr(), out, ct.len());
    *out_len = ct.len() as u32;
    CKR_OK
}
