//! FHE custody inside the token, scheme-neutral half (P0B spec
//! `docs/proposals/pkcs11-ckm-pqctoday-fhe-proposal.md`, revision 2).
//!
//! Compiled with `educational-ckks` (streamed CKKS, no TFHE-rs) and with
//! `educational-fhe` (which implies it and adds TFHE in `fhe_tfhe`). Holds
//! the seed-object access, the decrypt counter, the signed HPKE-sealed
//! release, recipient enrollment and the C ABI dispatch helpers both schemes
//! share. The seed never leaves the engine; only public material,
//! policy-checked plaintext, or a signed HPKE-sealed release crosses the
//! boundary.

use der::asn1::OctetString;
use der::Sequence;
use x509_cert::Certificate;
use zeroize::Zeroize;

use super::asn1;
use super::fhe;
use super::oids::Purpose;
use super::records;
use crate::constants::*;
use crate::crypto::handlers::Attributes;

pub const MAX_DECRYPT_INPUT: usize = 4 * 1024 * 1024;
pub const MAX_PUBLIC_OBJECT: usize = 64 * 1024 * 1024;
pub const RELEASE_DOMAIN: &[u8] = b"PQCToday FHE Release 1.0";

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
    let (attrs, seed) = take_seed(attrs).ok_or(CKR_DEVICE_ERROR)?;
    Ok((slot, SeedObject { handle: h, attrs, seed }))
}

/// Move the seed out of a cloned attribute map and zeroize the clone's copy
/// (Codex #6), so no `CKA_VALUE` copy outlives the operation.
fn take_seed(mut attrs: Attributes) -> Option<(Attributes, [u8; 32])> {
    let mut v = attrs.remove(&CKA_VALUE)?;
    let seed = v.as_slice().try_into().ok();
    v.zeroize();
    seed.map(|s| (attrs, s))
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
    #[cfg(feature = "educational-fhe")]
    {
        super::fhe_tfhe::decrypt_tfhe(session, h_seed, recipient, input, size_only)
    }
    #[cfg(not(feature = "educational-fhe"))]
    {
        Err(CKR_KEY_TYPE_INCONSISTENT)
    }
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
/// Upper bound on the length of `seal_release`'s output for a plaintext of
/// `plain_len` bytes (Codex #2): the same structure with fixed-size fields
/// (ML-KEM-768 encapsulation 1,088 B, AES-256-GCM tag 16 B, ML-DSA-65
/// signature 3,309 B) and the largest possible counter. Also refuses an
/// unknown recipient before any counter unit is spent.
pub(crate) fn sealed_len_bound(slot: u32, attrs: &Attributes, recipient: &[u8; 48], plain_len: usize) -> Result<usize, u32> {
    let _ = attrs;
    recipient_key(slot, recipient).ok_or(CKR_ACTION_PROHIBITED)?;
    let chain = super::pki::chain_from_ders(&[
        records::certificate(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?,
        records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?,
    ])
    .map_err(|_| CKR_DEVICE_ERROR)?;
    Ok(asn1::to_der(&FheSealedReleaseV1 {
        enc: asn1::octets(&[0u8; 1088]),
        ciphertext: asn1::octets(&vec![0u8; plain_len + 16]),
        counter: u64::MAX,
        signature: asn1::octets(&[0u8; 3309]),
        signer_chain: chain,
    })?
    .len())
}

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
    let (sig, chain) = receipt_sign(slot, &release_signed_bytes(&tbs)?)?;
    asn1::to_der(&FheSealedReleaseV1 {
        enc: asn1::octets(&enc),
        ciphertext: asn1::octets(&ct),
        counter,
        signature: asn1::octets(&sig),
        signer_chain: chain,
    })
}

/// Sign `msg` with the device's internal receipt-signing function key
/// (ML-DSA-65, empty context) and return the signature with its signer chain
/// `[receipt-signing certificate, device certificate]`.
pub(crate) fn receipt_sign(slot: u32, msg: &[u8]) -> Result<(Vec<u8>, Vec<Certificate>), u32> {
    let (_, mut sk) = records::function_secret(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?;
    let sig = super::mldsa65_sign(&sk, msg);
    sk.zeroize();
    let chain = super::pki::chain_from_ders(&[
        records::certificate(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?,
        records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?,
    ])
    .map_err(|_| CKR_DEVICE_ERROR)?;
    Ok((sig?, chain))
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

/// TFHE test encryption only (`fhe_tfhe::encrypt_for_test`).
#[cfg(all(feature = "educational-fhe", feature = "test-support"))]
pub(crate) fn seed_object_any(session: u32, h: u32) -> Result<(u32, SeedObject), u32> {
    let slot = super::require_user_rw(session)?;
    let attrs = records::object_attrs(h).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let (attrs, seed) = take_seed(attrs).ok_or(CKR_KEY_HANDLE_INVALID)?;
    Ok((slot, SeedObject { handle: h, attrs, seed }))
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
        let ty = u32::try_from(*p.add(i * 3)).map_err(|_| CKR_ATTRIBUTE_TYPE_INVALID)?;
        let vp = *p.add(i * 3 + 1) as *const u8;
        let vl = *p.add(i * 3 + 2);
        if vl > 4096 || (vl > 0 && vp.is_null()) {
            return Err(CKR_ARGUMENTS_BAD);
        }
        out.push((ty, if vl == 0 { Vec::new() } else { std::slice::from_raw_parts(vp, vl).to_vec() }));
    }
    Ok(out)
}

/// A template CK_ULONG of the native width that fits in 32 bits; wider
/// values are refused instead of truncated (Codex #10).
pub(crate) fn template_ulong(v: &[u8]) -> Option<u32> {
    (v.len() == W).then(|| u32::try_from(ulong_at(v, 0)).ok()).flatten()
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
    // Without TFHE-rs only streamed-CKKS parameter sets are registered for
    // generation; a TFHE set is refused like an unknown one.
    #[cfg(not(feature = "educational-fhe"))]
    if fhe::scheme_for(param_set) != Some(fhe::FHE_SCHEME_CKKS) {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
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
    // Parameter version 1: TFHE public material (TFHE-rs builds only).
    #[cfg(feature = "educational-fhe")]
    {
        super::fhe_tfhe::ffi_derive_public_v1(session, base, p_param, param_len, tmpl, n)
    }
    #[cfg(not(feature = "educational-fhe"))]
    {
        let _ = (session, base, tmpl, n);
        Err(CKR_MECHANISM_PARAM_INVALID)
    }
}


/// Active single-part FHE decrypt/encrypt operations, by session.
#[derive(Clone, Copy)]
pub enum FheOp {
    Decrypt { key: u32, recipient: [u8; 48] },
    #[cfg(all(feature = "educational-fhe", feature = "test-support"))]
    Encrypt { key: u32 },
}

static FHE_OPS: std::sync::Mutex<Option<std::collections::HashMap<u32, FheOp>>> = std::sync::Mutex::new(None);

pub(crate) fn ops<R>(f: impl FnOnce(&mut std::collections::HashMap<u32, FheOp>) -> R) -> R {
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
