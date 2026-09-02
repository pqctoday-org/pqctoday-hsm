//! RFC 9180 HPKE over PKCS#11 primitives.
//!
//! All four ciphersuites this crate declares in `supported_ciphersuites()`
//! now route their HPKE through the token via [`select`] below:
//! `DhKem25519`+AES-128-GCM (ciphersuite 1), `DhKem25519`+ChaCha20Poly1305
//! ("suite 3"), `DhKemP256`+AES-128-GCM, and X-Wing+ChaCha20Poly1305
//! (post-quantum). Any `HpkeConfig` `select()` doesn't recognize still
//! falls through to the `hpke-rs` software fallback in `crypto.rs`.
//!
//! Where each piece runs:
//!
//! | Step                              | Backend              |
//! | --------------------------------- | -------------------- |
//! | LabeledExtract / LabeledExpand    | PKCS#11 HMAC-SHA256  |
//! | DH (`Encap` / `Decap`)            | `CKM_ECDH1_DERIVE`   |
//! | Key Schedule (KAT-driven HKDF)    | PKCS#11 HMAC-SHA256  |
//! | Seal / Open AEAD                  | `CKM_AES_GCM` / `CKM_CHACHA20_POLY1305` |
//! | `DeriveKeyPair` public-key math   | `x25519-dalek` / `p256` (no-secret arithmetic) |
//!
//! The sk → pk derivation is intentionally not routed through PKCS#11.
//! For X25519 the base-point scalar multiplication, and for P-256 the
//! scalar-times-generator point multiplication, produce only the public
//! key, which is by definition non-secret; the operation reveals nothing
//! about the scalar. Real Diffie-Hellman (with a peer-provided public
//! point) runs inside the HSM in every code path.

use openmls_traits::types::{
    CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType,
    HpkeKemType, HpkeKeyPair, HpkePrivateKey, KemOutput,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::backend::PkcsOps;
use crate::error::PqcTodayError;

const NH: usize = 32; // HKDF-SHA256 output length
const MODE_BASE: u8 = 0x00;

/// Which KEM a suite uses. The two *shapes* are: DH derives a secret from a
/// private scalar and a peer public key (`DhX25519` and `DhP256` share this
/// shape, differing only in curve — see `encap`/`decap`/`derive_keypair`'s
/// `DhX25519 | DhP256` handling below), while X-Wing encapsulates — the
/// sender produces a ciphertext and a secret from the recipient's public key
/// alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum KemKind {
    /// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §4.1.
    DhX25519,
    /// DHKEM(P-256, HKDF-SHA256) — RFC 9180 §4.1 / §7.1, Table 2's
    /// `kem_id = 0x0010`. Same DH-KEM shape as `DhX25519`; the curve and
    /// point/scalar sizes are the only differences.
    DhP256,
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

/// `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` ("suite 3")'s HPKE
/// config. Identical KEM to `DHKEM_X25519_SHA256_AES128` above (same
/// `kem_id`, same `KemKind::DhX25519` — so `encap`/`decap`/`derive_keypair`
/// need no new arm at all for this suite); only the AEAD differs, and
/// `aead_seal`/`aead_open` below already dispatch `aead_id == 0x0003` to
/// `ops.chacha20_poly1305` (the same primitive the X-Wing suite's AEAD
/// already used). `nk`/`nn` match X-Wing's ChaCha20-Poly1305 parameters
/// exactly, since it's the same AEAD.
const DHKEM_X25519_SHA256_CHACHA20: Suite = Suite {
    kem: KemKind::DhX25519,
    kem_id: 0x0020,
    kdf_id: 0x0001,
    aead_id: 0x0003,
    nk: 32,
    nn: 12,
    nsecret: 32,
    nenc: 32,
    npk: 32,
};

/// `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`'s HPKE config. RFC 9180 §7.1
/// Table 2: DHKEM(P-256, HKDF-SHA256) `kem_id = 0x0010`, `Nsecret = 32`,
/// `Nenc = Npk = 65` (uncompressed SEC1 point), `Nsk = 32`.
const DHKEM_P256_SHA256_AES128: Suite = Suite {
    kem: KemKind::DhP256,
    kem_id: 0x0010,
    kdf_id: 0x0001,
    aead_id: 0x0001,
    nk: 16,
    nn: 12,
    nsecret: 32,
    nenc: 65,
    npk: 65,
};

/// The suite for this config, if we can run it on the HSM path.
pub(crate) fn select(cfg: &HpkeConfig) -> Option<Suite> {
    match (cfg.0, cfg.1, cfg.2) {
        (HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
            Some(DHKEM_X25519_SHA256_AES128)
        }
        (HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
            Some(DHKEM_X25519_SHA256_CHACHA20)
        }
        (HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
            Some(DHKEM_P256_SHA256_AES128)
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

// P-256 ECDH against a peer-provided point, executed inside the HSM via
// `CKM_ECDH1_DERIVE` (`backend.rs`'s `PkcsOps::ecdh_p256`) — the Weierstrass
// counterpart of `dh_in_hsm` above.
fn dh_p256_in_hsm(ops: &dyn PkcsOps, sk: &[u8], peer_pk: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
    ops.ecdh_p256(sk, peer_pk)
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

// ── DHKEM(P-256, HKDF-SHA256) — RFC 9180 §4.1 / §7.1 ─────────────────────────
//
// Same LabeledExtract/LabeledExpand + kem_context + ExtractAndExpand shape as
// DHKEM(X25519) above (both are `extract_and_expand`, unmodified, keyed off
// `su.kem_id` via `kem_suite_id`) — only the DH step (`dh_p256_in_hsm`, via
// `CKM_ECDH1_DERIVE` rather than X25519's Montgomery-ladder derive) and the
// point/scalar representation differ.

const P256_NSK: usize = 32;

/// RFC 9180 §7.1.3 `DeriveKeyPair` for a NIST curve — unlike X25519 (any
/// 32-byte string is already a valid Curve25519 scalar once the DH function
/// clamps it), a P-256 private key must be a nonzero integer strictly less
/// than the curve order, so the spec defines this as bounded rejection
/// sampling: expand a labeled candidate, mask its top byte with the curve's
/// `bitmask` (0xFF for P-256 — a no-op; P-256's order is close enough to
/// 2^256 that no bit-truncation is needed, unlike P-521's), and retry with
/// an incremented counter until the candidate lands in range.
/// `p256::SecretKey::from_slice` performs exactly that range check (nonzero,
/// `< order`) — the same class of non-secret, public-key-only arithmetic
/// `derive_keypair_x25519`'s base-point multiplication above already runs
/// outside the HSM, since only the *validity* of a candidate scalar is being
/// tested here, not a secret Diffie-Hellman exponentiation.
fn derive_keypair_p256(
    ops: &dyn PkcsOps,
    su: &Suite,
    ikm: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
    let sid = kem_suite_id(su);
    let dkp_prk = labeled_extract(ops, &sid, &[], b"dkp_prk", ikm)?;
    for counter in 0u16..256 {
        let candidate = labeled_expand(
            ops,
            &sid,
            &dkp_prk,
            b"candidate",
            &[counter as u8],
            P256_NSK,
        )?;
        // bitmask = 0xFF for P-256 (RFC 9180 §7.1.3): no bits masked.
        if let Ok(sk) = p256::SecretKey::from_slice(&candidate) {
            let pk_bytes = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
            return Ok((sk.to_bytes().to_vec(), pk_bytes));
        }
    }
    Err(PqcTodayError::Hpke(
        "P-256 DeriveKeyPair: no valid candidate scalar in 256 attempts".into(),
    ))
}

/// Recompute a P-256 public key from its private scalar. Pure public-key
/// arithmetic (no HSM, no secret exponentiation) — the P-256 analogue of
/// `PublicKey::from(&StaticSecret::from(sk_r))` in X25519's `decap` below.
fn p256_pk_from_sk(sk: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
    let sk = p256::SecretKey::from_slice(sk)
        .map_err(|_| PqcTodayError::Hpke("malformed P-256 private key".into()))?;
    Ok(sk.public_key().to_encoded_point(false).as_bytes().to_vec())
}

/// RFC 9180 §7.1.1 public-key validation for a NIST curve: the encoding must
/// be exactly `Npk` bytes, and the point itself must be on the curve and not
/// the identity ("point at infinity"). `p256::PublicKey::from_sec1_bytes`
/// enforces both the on-curve check and the non-identity invariant as part
/// of real SEC1 decoding — this doesn't hand-roll coordinate parsing.
fn validate_p256_point(su: &Suite, pk: &[u8]) -> Result<(), PqcTodayError> {
    if pk.len() != su.npk {
        return Err(PqcTodayError::Hpke(format!(
            "expected {}-byte P-256 public key, got {}",
            su.npk,
            pk.len()
        )));
    }
    p256::PublicKey::from_sec1_bytes(pk).map(|_| ()).map_err(|_| {
        PqcTodayError::Hpke(
            "invalid P-256 public key: not a valid point on the curve, or the identity point"
                .into(),
        )
    })
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
        KemKind::DhP256 => {
            validate_p256_point(su, pk_r)?;
            let (sk_e, pk_e) = derive_keypair_p256(ops, su, ephemeral_ikm)?;
            let dh = dh_p256_in_hsm(ops, &sk_e, pk_r)?;
            let mut kem_context = Vec::with_capacity(pk_e.len() + pk_r.len());
            kem_context.extend_from_slice(&pk_e);
            kem_context.extend_from_slice(pk_r);
            let ss = extract_and_expand(ops, su, &dh, &kem_context)?;
            Ok((ss, pk_e))
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
        KemKind::DhP256 => {
            validate_p256_point(su, enc)?;
            let dh = dh_p256_in_hsm(ops, sk_r, enc)?;
            let pk_r = p256_pk_from_sk(sk_r)?;
            let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
            kem_context.extend_from_slice(enc);
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
        KemKind::DhP256 => {
            let (sk, pk) = derive_keypair_p256(ops, su, ikm).map_err(CryptoError::from)?;
            Ok(HpkeKeyPair {
                private: HpkePrivateKey::from(sk),
                public: pk,
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

// ── HSM-vs-software HPKE routing boundary ────────────────────────────────────
//
// `select()` above is the ONLY gate deciding whether an `HpkeConfig` gets its
// private key material (and every intermediate secret) run through the token,
// or falls all the way through to `crypto.rs`'s `mk_hpke` — a fully
// independent, fully spec-correct, entirely in-process `hpke-rs`
// (RustCrypto backend) implementation with zero HSM involvement.
//
// This boundary is easy to shift by accident (a `Suite` typo, a dropped
// match arm) with nothing else in this crate's test suite noticing: a full
// MLS group round trip (`tests/openmls_contract.rs`) succeeds either way,
// because `mk_hpke` is not a stub — it is a real HPKE implementation, just
// not one that touches the token. These tests pin the boundary explicitly,
// per `HpkeConfig`, for every ciphersuite this crate's own
// `supported_ciphersuites()` declares — so it becomes a reviewed, deliberate
// change rather than a silent one in either direction. All four now assert
// `is_some()`: the "suite 3" and P-256 gaps
// `docs/gap-analysis-kmip-cacp-pkcs11-coverage-2026-08-30.md` ("Phase 2.1")
// tracked are closed — see `DHKEM_X25519_SHA256_CHACHA20` and
// `DHKEM_P256_SHA256_AES128` above.
#[cfg(test)]
mod hsm_routing_boundary_tests {
    use super::select;
    use openmls_traits::types::{
        HpkeAeadType as Aead, HpkeConfig, HpkeKdfType as Kdf, HpkeKemType as Kem,
    };

    /// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — the suite every
    /// `hpke_*` KAT/round-trip test in `tests/integration.rs` exercises.
    #[test]
    fn suite1_dhkem_x25519_aes128gcm_routes_through_hsm() {
        let cfg = HpkeConfig(Kem::DhKem25519, Kdf::HkdfSha256, Aead::AesGcm128);
        assert!(
            select(&cfg).is_some(),
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519's HPKE config must select \
             the HSM-backed Suite — this is the one config every existing HPKE KAT \
             test assumes is HSM-resident"
        );
    }

    /// `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` — the post-quantum
    /// suite `tests/openmls_contract.rs::mls_group_roundtrip_xwing_suite`
    /// and `tests/xwing_rust_engine.rs` exercise.
    #[test]
    fn xwing_suite_routes_through_hsm() {
        let cfg = HpkeConfig(Kem::XWingKemDraft6, Kdf::HkdfSha256, Aead::ChaCha20Poly1305);
        assert!(
            select(&cfg).is_some(),
            "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519's HPKE config must select \
             the HSM-backed Suite"
        );
    }

    /// `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` ("suite 3") is
    /// declared in `supported_ciphersuites()`; its record-layer AEAD already
    /// ran on the HSM (`self.ops.chacha20_poly1305` —
    /// `tests/openmls_contract.rs::mls_group_roundtrip_suite3_chacha20poly1305`
    /// proves that for Application/Handshake messages) before its HPKE did.
    /// `select()` now also matches this suite's `HpkeConfig` — same
    /// `DhKem25519` KEM as ciphersuite 1, `ChaCha20Poly1305` AEAD — so the
    /// private HPKE key used for this suite's Welcome-message
    /// `GroupSecrets` encryption and TreeKEM commit path (RFC 9420
    /// §5.4/§7.9) now touches the token exactly like the record-layer key
    /// does, closing the gap the previous version of this test pinned.
    #[test]
    fn suite3_dhkem_x25519_chacha20poly1305_routes_through_hsm() {
        let cfg = HpkeConfig(Kem::DhKem25519, Kdf::HkdfSha256, Aead::ChaCha20Poly1305);
        assert!(
            select(&cfg).is_some(),
            "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519's HPKE config must \
             select the HSM-backed Suite — this is the suite \
             tests/openmls_contract.rs::mls_group_roundtrip_suite3_chacha20poly1305 \
             exercises end to end"
        );
    }

    /// `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` is declared in
    /// `supported_ciphersuites()` and accepted by `supports()`. `select()`
    /// now has a `DhKemP256` arm (DHKEM(P-256, HKDF-SHA256) per RFC 9180
    /// §7.1, driven through `CKM_ECDH1_DERIVE` — see `backend.rs`'s
    /// `PkcsOps::ecdh_p256`), so the private key used for this suite's
    /// Welcome-message `GroupSecrets` encryption and TreeKEM commit path
    /// now touches the token, the same as its already-HSM-backed
    /// ECDSA-P256 signing and AES-128-GCM record layer.
    #[test]
    fn p256_suite_routes_through_hsm() {
        let cfg = HpkeConfig(Kem::DhKemP256, Kdf::HkdfSha256, Aead::AesGcm128);
        assert!(
            select(&cfg).is_some(),
            "MLS_128_DHKEMP256_AES128GCM_SHA256_P256's HPKE config must select the \
             HSM-backed Suite — this is the suite \
             tests/openmls_contract.rs::mls_group_roundtrip_p256_suite exercises end \
             to end"
        );
    }
}
