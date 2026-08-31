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

const NH: usize = 32; // HKDF-SHA256 output length
const MODE_BASE: u8 = 0x00;

/// Which KEM a suite uses. The two have different *shapes*, not just different
/// algorithms: DH derives a secret from a private scalar and a peer public key,
/// while X-Wing encapsulates — the sender produces a ciphertext and a secret
/// from the recipient's public key alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum KemKind {
    /// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §4.1.
    DhX25519,
    /// X-Wing = ML-KEM-768 + X25519 — draft-connolly-cfrg-xwing-kem.
    XWing,
}

/// A supported HPKE suite, as data. These were hard-coded constants for
/// ciphersuite 1; adding a second suite is the reason they are not any more.
#[derive(Clone, Copy)]
pub(crate) struct Suite {
    pub(crate) kem: KemKind,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    /// AEAD key length.
    nk: usize,
    /// AEAD nonce length.
    nn: usize,
    /// KEM shared-secret length.
    nsecret: usize,
    /// KEM ciphertext ("enc") length.
    pub(crate) nenc: usize,
    /// KEM public key length.
    pub(crate) npk: usize,
}

/// RFC 9180 §7.1–7.3 for the DH suite; draft-connolly-cfrg-xwing-kem §7 for
/// X-Wing, whose registered HPKE KEM id is 25722 (0x647a).
const DHKEM_X25519_SHA256_AES128: Suite = Suite {
    kem: KemKind::DhX25519,
    kem_id: 0x0020,
    kdf_id: 0x0001,
    aead_id: 0x0001,
    nk: 16,
    nn: 12,
    nsecret: 32,
    nenc: 32,
    npk: 32,
};

const XWING_SHA256_CHACHA20: Suite = Suite {
    kem: KemKind::XWing,
    kem_id: 0x647a,
    kdf_id: 0x0001,
    aead_id: 0x0003,
    nk: 32,
    nn: 12,
    nsecret: 32,
    nenc: 1120,
    npk: 1216,
};

/// The suite for this config, if we can run it on the HSM path.
pub(crate) fn select(cfg: &HpkeConfig) -> Option<Suite> {
    match (cfg.0, cfg.1, cfg.2) {
        (HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
            Some(DHKEM_X25519_SHA256_AES128)
        }
        (HpkeKemType::XWingKemDraft6, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
            Some(XWING_SHA256_CHACHA20)
        }
        _ => None,
    }
}


fn kem_suite_id(s: &Suite) -> Vec<u8> {
    let mut v = b"KEM".to_vec();
    v.extend_from_slice(&s.kem_id.to_be_bytes());
    v
}

fn hpke_suite_id(s: &Suite) -> Vec<u8> {
    let mut v = b"HPKE".to_vec();
    v.extend_from_slice(&s.kem_id.to_be_bytes());
    v.extend_from_slice(&s.kdf_id.to_be_bytes());
    v.extend_from_slice(&s.aead_id.to_be_bytes());
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
    su: &Suite,
    ikm: &[u8],
) -> Result<([u8; 32], [u8; 32]), PqcTodayError> {
    let sid = kem_suite_id(su);
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
    su: &Suite,
    dh: &[u8],
    kem_context: &[u8],
) -> Result<Vec<u8>, PqcTodayError> {
    let sid = kem_suite_id(su);
    let eae_prk = labeled_extract(ops, &sid, &[], b"eae_prk", dh)?;
    labeled_expand(ops, &sid, &eae_prk, b"shared_secret", kem_context, su.nsecret)
}

// ── X-Wing — draft-connolly-cfrg-xwing-kem §5 ────────────────────────────────
//
// §5.6: X-Wing satisfies the HPKE KEM interface directly. Encap() IS
// Encapsulate() and the serialize functions are the identity, so unlike DHKEM
// there is no extract-and-expand wrapper — the KEM's own output is the shared
// secret.

/// §5.3: SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel), label = 5c2e2f2f5e5c.
///
/// `pub(crate)` so `backend.rs`'s `CryptokiBackend::xwing_combine` — the only
/// place that builds the transcript and runs the combiner, via
/// `softhsmrustv3::native::derive::run_combiner` — can reuse this constant
/// instead of a second, driftable copy.
pub(crate) const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// §5.2: expandDecapsulationKey — SHAKE256(sk, 96) split into ML-KEM's
/// (d ‖ z) and the X25519 scalar. The private key IS the 32-byte seed.
fn xwing_expand(
    ops: &dyn PkcsOps,
    sk: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), PqcTodayError> {
    if sk.len() != 32 {
        return Err(PqcTodayError::Hpke(format!(
            "X-Wing decapsulation key must be 32 bytes, got {}",
            sk.len()
        )));
    }
    let expanded = ops.shake256(sk, 96)?;
    let mut sk_x = [0u8; 32];
    sk_x.copy_from_slice(&expanded[64..96]);
    Ok((expanded[0..64].to_vec(), sk_x))
}

fn xwing_encap(
    ops: &dyn PkcsOps,
    pk: &[u8],
    ephemeral_ikm: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
    // Length from the suite table, not a literal — the two cannot drift.
    if pk.len() != XWING_SHA256_CHACHA20.npk {
        return Err(PqcTodayError::Hpke(format!(
            "X-Wing encapsulation key must be {} bytes, got {}",
            XWING_SHA256_CHACHA20.npk,
            pk.len()
        )));
    }
    let (pk_m, pk_x) = pk.split_at(1184);

    let (ct_m, ss_m) = ops.ml_kem_encapsulate_to(pk_m)?;

    // §5.4: ek_X = random(32); ct_X = X25519(ek_X, base); ss_X = X25519(ek_X, pk_X).
    // The ephemeral scalar comes from the caller's ikm so the caller controls
    // the randomness source, matching the DH path.
    let mut ek_x = [0u8; 32];
    let seed = ops.shake256(ephemeral_ikm, 32)?;
    ek_x.copy_from_slice(&seed);
    let sec = StaticSecret::from(ek_x);
    let ct_x = PublicKey::from(&sec).to_bytes();
    let ss_x = dh_in_hsm(ops, &ek_x, pk_x)?;

    let ss = ops.xwing_combine(&ss_m, &ss_x, &ct_x, pk_x)?;
    let mut enc = Vec::with_capacity(1120);
    enc.extend_from_slice(&ct_m);
    enc.extend_from_slice(&ct_x);
    Ok((ss, enc))
}

fn xwing_decap(ops: &dyn PkcsOps, enc: &[u8], sk: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
    if enc.len() != XWING_SHA256_CHACHA20.nenc {
        return Err(PqcTodayError::Hpke(format!(
            "X-Wing ciphertext must be {} bytes, got {}",
            XWING_SHA256_CHACHA20.nenc,
            enc.len()
        )));
    }
    let (dz, sk_x) = xwing_expand(ops, sk)?;
    let (_pk_m, priv_handle) = ops.ml_kem_768_keygen_from_seed(&dz)?;

    let (ct_m, ct_x) = enc.split_at(1088);
    let ss_m = ops.ml_kem_decapsulate(priv_handle, ct_m)?;
    let ss_x = dh_in_hsm(ops, &sk_x, ct_x)?;
    let pk_x = PublicKey::from(&StaticSecret::from(sk_x)).to_bytes();

    ops.xwing_combine(&ss_m, &ss_x, ct_x, &pk_x)
}

/// Encapsulate. Returns `(shared_secret, enc)`.
fn encap(
    ops: &dyn PkcsOps,
    su: &Suite,
    pk_r: &[u8],
    ephemeral_ikm: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
    match su.kem {
        KemKind::XWing => xwing_encap(ops, pk_r, ephemeral_ikm),
        KemKind::DhX25519 => {
            let pk_r = fixed_32(pk_r)?;
            let (sk_e, pk_e) = derive_keypair_x25519(ops, su, ephemeral_ikm)?;
            let dh = dh_in_hsm(ops, &sk_e, &pk_r)?;
            let mut kem_context = Vec::with_capacity(64);
            kem_context.extend_from_slice(&pk_e);
            kem_context.extend_from_slice(&pk_r);
            let ss = extract_and_expand(ops, su, &dh, &kem_context)?;
            Ok((ss, pk_e.to_vec()))
        }
    }
}

fn decap(
    ops: &dyn PkcsOps,
    su: &Suite,
    enc: &[u8],
    sk_r: &[u8],
) -> Result<Vec<u8>, PqcTodayError> {
    match su.kem {
        KemKind::XWing => xwing_decap(ops, enc, sk_r),
        KemKind::DhX25519 => {
            let enc = fixed_32(enc)?;
            let sk_r = fixed_32(sk_r)?;
            let dh = dh_in_hsm(ops, &sk_r, &enc)?;
            let pk_r = PublicKey::from(&StaticSecret::from(sk_r)).to_bytes();
            let mut kem_context = Vec::with_capacity(64);
            kem_context.extend_from_slice(&enc);
            kem_context.extend_from_slice(&pk_r);
            extract_and_expand(ops, su, &dh, &kem_context)
        }
    }
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
    su: &Suite,
    shared_secret: &[u8],
    info: &[u8],
) -> Result<Schedule, PqcTodayError> {
    let sid = hpke_suite_id(su);
    let psk_id_hash = labeled_extract(ops, &sid, &[], b"psk_id_hash", b"")?;
    let info_hash = labeled_extract(ops, &sid, &[], b"info_hash", info)?;
    let mut ksctx = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ksctx.push(MODE_BASE);
    ksctx.extend_from_slice(&psk_id_hash);
    ksctx.extend_from_slice(&info_hash);
    let secret = labeled_extract(ops, &sid, shared_secret, b"secret", b"")?;
    let key = labeled_expand(ops, &sid, &secret, b"key", &ksctx, su.nk)?;
    let base_nonce = labeled_expand(ops, &sid, &secret, b"base_nonce", &ksctx, su.nn)?;
    let exporter_secret = labeled_expand(ops, &sid, &secret, b"exp", &ksctx, NH)?;
    Ok(Schedule {
        key,
        base_nonce,
        exporter_secret,
    })
}

// ── AEAD via PkcsOps ─────────────────────────────────────────────────────────

/// AEAD id 0x0003 is ChaCha20-Poly1305, which `aead_encrypt` does not cover —
/// that method is AES-GCM only. Routed to the HSM's ChaCha mechanism rather
/// than a software fallback.
fn aead_seal(
    ops: &dyn PkcsOps,
    su: &Suite,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, PqcTodayError> {
    if su.aead_id == 0x0003 {
        ops.chacha20_poly1305(true, key, nonce, aad, pt)
    } else {
        ops.aead_encrypt(key, nonce, aad, pt)
    }
}

fn aead_open(
    ops: &dyn PkcsOps,
    su: &Suite,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, PqcTodayError> {
    if su.aead_id == 0x0003 {
        ops.chacha20_poly1305(false, key, nonce, aad, ct)
    } else {
        ops.aead_decrypt(key, nonce, aad, ct)
    }
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

pub(crate) fn derive_keypair(
    ops: &dyn PkcsOps,
    su: &Suite,
    ikm: &[u8],
) -> Result<HpkeKeyPair, CryptoError> {
    match su.kem {
        KemKind::DhX25519 => {
            let (sk, pk) = derive_keypair_x25519(ops, su, ikm).map_err(CryptoError::from)?;
            Ok(HpkeKeyPair {
                private: HpkePrivateKey::from(sk.to_vec()),
                public: pk.to_vec(),
            })
        }
        KemKind::XWing => {
            // §5.6: DeriveKeyPair(ikm) = SHAKE256(ikm, 32) → GenerateKeyPairDerand.
            // The private key IS that 32-byte seed; the public key is derived
            // from it, never stored alongside it.
            let sk = ops.shake256(ikm, 32).map_err(CryptoError::from)?;
            let (dz, sk_x) = xwing_expand(ops, &sk).map_err(CryptoError::from)?;
            let (pk_m, _h) = ops
                .ml_kem_768_keygen_from_seed(&dz)
                .map_err(CryptoError::from)?;
            let pk_x = PublicKey::from(&StaticSecret::from(sk_x)).to_bytes();
            let mut pk = Vec::with_capacity(su.npk);
            pk.extend_from_slice(&pk_m);
            pk.extend_from_slice(&pk_x);
            Ok(HpkeKeyPair {
                private: HpkePrivateKey::from(sk),
                public: pk,
            })
        }
    }
}

pub(crate) fn seal(
    ops: &dyn PkcsOps,
    su: &Suite,
    pk_r_bytes: &[u8],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    ephemeral_ikm: &[u8],
) -> Result<HpkeCiphertext, CryptoError> {
    let (shared_secret, enc) =
        encap(ops, su, pk_r_bytes, ephemeral_ikm).map_err(CryptoError::from)?;
    let sch = key_schedule_base(ops, su, &shared_secret, info).map_err(CryptoError::from)?;
    // Single-shot Seal: seq = 0 → nonce = base_nonce.
    let ct =
        aead_seal(ops, su, &sch.key, &sch.base_nonce, aad, pt).map_err(CryptoError::from)?;
    Ok(HpkeCiphertext {
        kem_output: enc.into(),
        ciphertext: ct.into(),
    })
}

pub(crate) fn open(
    ops: &dyn PkcsOps,
    su: &Suite,
    ciphertext: &HpkeCiphertext,
    sk_r_bytes: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let shared_secret = decap(ops, su, ciphertext.kem_output.as_slice(), sk_r_bytes)
        .map_err(CryptoError::from)?;
    let sch = key_schedule_base(ops, su, &shared_secret, info).map_err(CryptoError::from)?;
    aead_open(
        ops,
        su,
        &sch.key,
        &sch.base_nonce,
        aad,
        ciphertext.ciphertext.as_slice(),
    )
    .map_err(CryptoError::from)
}

pub(crate) fn setup_sender_and_export(
    ops: &dyn PkcsOps,
    su: &Suite,
    pk_r_bytes: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
    ephemeral_ikm: &[u8],
) -> Result<(KemOutput, ExporterSecret), CryptoError> {
    let (shared_secret, enc) =
        encap(ops, su, pk_r_bytes, ephemeral_ikm).map_err(CryptoError::from)?;
    let sch = key_schedule_base(ops, su, &shared_secret, info).map_err(CryptoError::from)?;
    let sid = hpke_suite_id(su);
    let exported = labeled_expand(
        ops,
        &sid,
        &sch.exporter_secret,
        b"sec",
        exporter_context,
        exporter_length,
    )
    .map_err(CryptoError::from)?;
    Ok((enc, ExporterSecret::from(exported)))
}

pub(crate) fn setup_receiver_and_export(
    ops: &dyn PkcsOps,
    su: &Suite,
    enc_bytes: &[u8],
    sk_r_bytes: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
) -> Result<ExporterSecret, CryptoError> {
    let shared_secret = decap(ops, su, enc_bytes, sk_r_bytes).map_err(CryptoError::from)?;
    let sch = key_schedule_base(ops, su, &shared_secret, info).map_err(CryptoError::from)?;
    let sid = hpke_suite_id(su);
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
