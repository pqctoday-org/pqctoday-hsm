//! RFC 9180 HPKE over PKCS#11 primitives.
//!
//! Scope (v0.2): **DhKem25519 + HKDF-SHA256 + AES-128-GCM** only —
//! the suite used by `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
//! Other suites stay on the `hpke-rs` fallback in `crypto.rs`.
//!
//! Where each piece runs:
//!
//! | Step                              | Backend              |
//! | --------------------------------- | -------------------- |
//! | LabeledExtract / LabeledExpand    | PKCS#11 HMAC-SHA256  |
//! | DH (`Encap` / `Decap`)            | `CKM_ECDH1_DERIVE`   |
//! | Key Schedule (KAT-driven HKDF)    | PKCS#11 HMAC-SHA256  |
//! | Seal / Open AEAD                  | `CKM_AES_GCM`        |
//! | `DeriveKeyPair` base-point mul    | `x25519-dalek` (no-secret arithmetic) |
//!
//! The sk → pk derivation is intentionally not routed through PKCS#11.
//! For X25519 the base-point scalar multiplication produces the public
//! key, which is by definition non-secret; the operation reveals nothing
//! about the scalar. Real Diffie-Hellman (with a peer-provided public
//! point) runs inside the HSM in every code path.

use openmls_traits::types::{
    CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType,
    HpkeKemType, HpkeKeyPair, HpkePrivateKey, KemOutput,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::backend::PkcsOps;
use crate::error::PqcTodayError;

// RFC 9180 §7.1 / §7.2 constants for DhKem25519 + HKDF-SHA256 + AES-128-GCM.
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;
const NK: usize = 16; // AEAD key length
const NN: usize = 12; // AEAD nonce length
const NH: usize = 32; // HKDF-SHA256 output length
const NSECRET: usize = 32; // DHKEM(X25519) shared-secret length
const MODE_BASE: u8 = 0x00;

pub(crate) fn supports_pkcs11_path(cfg: &HpkeConfig) -> bool {
    matches!(cfg.0, HpkeKemType::DhKem25519)
        && matches!(cfg.1, HpkeKdfType::HkdfSha256)
        && matches!(cfg.2, HpkeAeadType::AesGcm128)
}

fn kem_suite_id() -> Vec<u8> {
    let mut v = b"KEM".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v
}

fn hpke_suite_id() -> Vec<u8> {
    let mut v = b"HPKE".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v.extend_from_slice(&KDF_ID.to_be_bytes());
    v.extend_from_slice(&AEAD_ID.to_be_bytes());
    v
}

// ── Primitives — routed through the PkcsOps trait ───────────────────────────

fn hmac_sha256(ops: &dyn PkcsOps, key: &[u8], data: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
    ops.hmac(HashType::Sha2_256, key, data)
}

fn hkdf_extract(ops: &dyn PkcsOps, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
    let zero_salt;
    let salt_ref = if salt.is_empty() {
        zero_salt = vec![0u8; NH];
        &zero_salt
    } else {
        salt
    };
    hmac_sha256(ops, salt_ref, ikm)
}

fn hkdf_expand(
    ops: &dyn PkcsOps,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, PqcTodayError> {
    let n = length.div_ceil(NH);
    if n > 255 {
        return Err(PqcTodayError::Hpke("HKDF expand length too large".into()));
    }
    let mut t_prev: Vec<u8> = Vec::new();
    let mut okm = Vec::with_capacity(length);
    for i in 1..=n as u8 {
        let mut block = Vec::with_capacity(t_prev.len() + info.len() + 1);
        block.extend_from_slice(&t_prev);
        block.extend_from_slice(info);
        block.push(i);
        t_prev = hmac_sha256(ops, prk, &block)?;
        okm.extend_from_slice(&t_prev);
    }
    okm.truncate(length);
    Ok(okm)
}

fn labeled_extract(
    ops: &dyn PkcsOps,
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<Vec<u8>, PqcTodayError> {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    hkdf_extract(ops, salt, &labeled_ikm)
}

fn labeled_expand(
    ops: &dyn PkcsOps,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, PqcTodayError> {
    let mut labeled_info = Vec::with_capacity(9 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    hkdf_expand(ops, prk, &labeled_info, length)
}

// ── DH ──────────────────────────────────────────────────────────────────────
//
// X25519 scalar-mult against a peer-provided point, executed inside the HSM
// via `CKM_ECDH1_DERIVE`. The derived value lands in a session-only
// generic-secret object whose `CKA_VALUE` we extract to feed into HKDF.

fn dh_in_hsm(ops: &dyn PkcsOps, sk: &[u8], peer_pk: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
    ops.ecdh_x25519(sk, peer_pk)
}

// ── DHKEM(X25519, HKDF-SHA256) — RFC 9180 §4.1 / §7.1 ────────────────────────

fn derive_keypair_x25519(
    ops: &dyn PkcsOps,
    ikm: &[u8],
) -> Result<([u8; 32], [u8; 32]), PqcTodayError> {
    let sid = kem_suite_id();
    let dkp_prk = labeled_extract(ops, &sid, &[], b"dkp_prk", ikm)?;
    let sk_bytes = labeled_expand(ops, &sid, &dkp_prk, b"sk", &[], 32)?;
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&sk_bytes);
    // Public key is non-secret base-point arithmetic — done in software.
    let sec = StaticSecret::from(sk);
    let pk = PublicKey::from(&sec).to_bytes();
    Ok((sk, pk))
}

fn extract_and_expand(
    ops: &dyn PkcsOps,
    dh: &[u8],
    kem_context: &[u8],
) -> Result<Vec<u8>, PqcTodayError> {
    let sid = kem_suite_id();
    let eae_prk = labeled_extract(ops, &sid, &[], b"eae_prk", dh)?;
    labeled_expand(ops, &sid, &eae_prk, b"shared_secret", kem_context, NSECRET)
}

fn encap(
    ops: &dyn PkcsOps,
    pk_r: &[u8; 32],
    ephemeral_ikm: &[u8],
) -> Result<([u8; 32], [u8; 32]), PqcTodayError> {
    // (shared_secret, enc)
    let (sk_e, pk_e) = derive_keypair_x25519(ops, ephemeral_ikm)?;
    let dh = dh_in_hsm(ops, &sk_e, pk_r)?;
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(&pk_e);
    kem_context.extend_from_slice(pk_r);
    let ss = extract_and_expand(ops, &dh, &kem_context)?;
    let mut out_ss = [0u8; 32];
    out_ss.copy_from_slice(&ss);
    Ok((out_ss, pk_e))
}

fn decap(ops: &dyn PkcsOps, enc: &[u8; 32], sk_r: &[u8; 32]) -> Result<[u8; 32], PqcTodayError> {
    let dh = dh_in_hsm(ops, sk_r, enc)?;
    let pk_r = PublicKey::from(&StaticSecret::from(*sk_r)).to_bytes();
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&pk_r);
    let ss = extract_and_expand(ops, &dh, &kem_context)?;
    let mut out_ss = [0u8; 32];
    out_ss.copy_from_slice(&ss);
    Ok(out_ss)
}

// ── Key Schedule — RFC 9180 §5.1, mode_base only ────────────────────────────

#[derive(Debug)]
struct Schedule {
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
}

fn key_schedule_base(
    ops: &dyn PkcsOps,
    shared_secret: &[u8],
    info: &[u8],
) -> Result<Schedule, PqcTodayError> {
    let sid = hpke_suite_id();
    let psk_id_hash = labeled_extract(ops, &sid, &[], b"psk_id_hash", b"")?;
    let info_hash = labeled_extract(ops, &sid, &[], b"info_hash", info)?;
    let mut ksctx = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ksctx.push(MODE_BASE);
    ksctx.extend_from_slice(&psk_id_hash);
    ksctx.extend_from_slice(&info_hash);
    let secret = labeled_extract(ops, &sid, shared_secret, b"secret", b"")?;
    let key = labeled_expand(ops, &sid, &secret, b"key", &ksctx, NK)?;
    let base_nonce = labeled_expand(ops, &sid, &secret, b"base_nonce", &ksctx, NN)?;
    let exporter_secret = labeled_expand(ops, &sid, &secret, b"exp", &ksctx, NH)?;
    Ok(Schedule {
        key,
        base_nonce,
        exporter_secret,
    })
}

// ── AEAD via PkcsOps ─────────────────────────────────────────────────────────

fn aead_seal(
    ops: &dyn PkcsOps,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, PqcTodayError> {
    ops.aead_encrypt(key, nonce, aad, pt)
}

fn aead_open(
    ops: &dyn PkcsOps,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, PqcTodayError> {
    ops.aead_decrypt(key, nonce, aad, ct)
}

// ── Public entry points ─────────────────────────────────────────────────────

fn fixed_32(b: &[u8]) -> Result<[u8; 32], PqcTodayError> {
    if b.len() != 32 {
        return Err(PqcTodayError::Hpke(format!(
            "expected 32-byte X25519 key, got {}",
            b.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}

pub(crate) fn derive_keypair(ops: &dyn PkcsOps, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    let (sk, pk) = derive_keypair_x25519(ops, ikm).map_err(CryptoError::from)?;
    Ok(HpkeKeyPair {
        private: HpkePrivateKey::from(sk.to_vec()),
        public: pk.to_vec(),
    })
}

pub(crate) fn seal(
    ops: &dyn PkcsOps,
    pk_r_bytes: &[u8],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    ephemeral_ikm: &[u8],
) -> Result<HpkeCiphertext, CryptoError> {
    let pk_r = fixed_32(pk_r_bytes).map_err(CryptoError::from)?;
    let (shared_secret, enc) = encap(ops, &pk_r, ephemeral_ikm).map_err(CryptoError::from)?;
    let sch = key_schedule_base(ops, &shared_secret, info).map_err(CryptoError::from)?;
    // Single-shot Seal: seq = 0 → nonce = base_nonce.
    let ct = aead_seal(ops, &sch.key, &sch.base_nonce, aad, pt).map_err(CryptoError::from)?;
    Ok(HpkeCiphertext {
        kem_output: enc.to_vec().into(),
        ciphertext: ct.into(),
    })
}

pub(crate) fn open(
    ops: &dyn PkcsOps,
    ciphertext: &HpkeCiphertext,
    sk_r_bytes: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let sk_r = fixed_32(sk_r_bytes).map_err(CryptoError::from)?;
    let enc = fixed_32(ciphertext.kem_output.as_slice()).map_err(CryptoError::from)?;
    let shared_secret = decap(ops, &enc, &sk_r).map_err(CryptoError::from)?;
    let sch = key_schedule_base(ops, &shared_secret, info).map_err(CryptoError::from)?;
    aead_open(
        ops,
        &sch.key,
        &sch.base_nonce,
        aad,
        ciphertext.ciphertext.as_slice(),
    )
    .map_err(CryptoError::from)
}

pub(crate) fn setup_sender_and_export(
    ops: &dyn PkcsOps,
    pk_r_bytes: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
    ephemeral_ikm: &[u8],
) -> Result<(KemOutput, ExporterSecret), CryptoError> {
    let pk_r = fixed_32(pk_r_bytes).map_err(CryptoError::from)?;
    let (shared_secret, enc) = encap(ops, &pk_r, ephemeral_ikm).map_err(CryptoError::from)?;
    let sch = key_schedule_base(ops, &shared_secret, info).map_err(CryptoError::from)?;
    let sid = hpke_suite_id();
    let exported = labeled_expand(
        ops,
        &sid,
        &sch.exporter_secret,
        b"sec",
        exporter_context,
        exporter_length,
    )
    .map_err(CryptoError::from)?;
    Ok((enc.to_vec(), ExporterSecret::from(exported)))
}

pub(crate) fn setup_receiver_and_export(
    ops: &dyn PkcsOps,
    enc_bytes: &[u8],
    sk_r_bytes: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
) -> Result<ExporterSecret, CryptoError> {
    let sk_r = fixed_32(sk_r_bytes).map_err(CryptoError::from)?;
    let enc = fixed_32(enc_bytes).map_err(CryptoError::from)?;
    let shared_secret = decap(ops, &enc, &sk_r).map_err(CryptoError::from)?;
    let sch = key_schedule_base(ops, &shared_secret, info).map_err(CryptoError::from)?;
    let sid = hpke_suite_id();
    let exported = labeled_expand(
        ops,
        &sid,
        &sch.exporter_secret,
        b"sec",
        exporter_context,
        exporter_length,
    )
    .map_err(CryptoError::from)?;
    Ok(ExporterSecret::from(exported))
}

#[allow(unused)]
pub(crate) const HASH_TYPE: HashType = HashType::Sha2_256;
