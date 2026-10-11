//! Allowlisted CKKS parameter sets (FHE spec §4 extended; plan §5.2). The
//! moduli, primitive roots and canonical key list are generated from the
//! pinned Lattigo v6.2.0 by the pqctoday-fhe oracle (`params_gen.rs`).

pub const KIND_RELIN: u8 = 1;
pub const KIND_GALOIS: u8 = 2;
pub const KIND_DENSE_TO_SPARSE: u8 = 3;
pub const KIND_SPARSE_TO_DENSE: u8 = 4;
/// Rotation key (E10): key-switching key from an old seed's secret to a new
/// seed's secret over the residual basis. Never part of `keys`; its KeyID
/// kind keeps its KDF contexts and `a` limbs apart from every key-set key.
pub const KIND_ROTATION: u8 = 5;

/// One evaluation key of the canonical key list. Its limb basis is
/// Q[0..=level_q] followed by P[0..=level_p].
#[derive(Clone, Copy, Debug)]
pub struct KeyDesc {
    pub kind: u8,
    pub gal_el: u64,
    pub level_q: usize,
    pub level_p: usize,
}

impl KeyDesc {
    pub fn limbs(&self) -> usize {
        self.level_q + self.level_p + 2
    }
    /// Gadget digits (Lattigo `BaseRNSDecompositionVectorSize`).
    pub fn dnum(&self) -> usize {
        (self.level_q + self.level_p + 1) / (self.level_p + 1)
    }
}

pub struct CkksParamSet {
    pub id: u32,
    pub name: &'static str,
    pub log_n: u32,
    pub q: &'static [u64],
    pub q_roots: &'static [u64],
    pub p: &'static [u64],
    pub p_roots: &'static [u64],
    /// Basis of the data owner's public key (Lattigo residual parameters).
    pub residual_q: &'static [u64],
    pub residual_q_roots: &'static [u64],
    pub residual_p: &'static [u64],
    pub residual_p_roots: &'static [u64],
    pub h: usize,
    pub ephemeral_h: usize,
    pub log_default_scale: u32,
    pub keys: &'static [KeyDesc],
}

impl CkksParamSet {
    pub fn n(&self) -> usize {
        1 << self.log_n
    }
    /// (modulus, primitive root) of limb `j` of key `k`.
    pub fn key_limb(&self, k: &KeyDesc, j: usize) -> Option<(u64, u64)> {
        if j <= k.level_q {
            Some((self.q[j], self.q_roots[j]))
        } else if j < k.limbs() {
            let i = j - k.level_q - 1;
            Some((self.p[i], self.p_roots[i]))
        } else {
            None
        }
    }
    pub fn pk_limbs(&self) -> usize {
        self.residual_q.len() + self.residual_p.len()
    }
    pub fn pk_limb(&self, j: usize) -> Option<(u64, u64)> {
        let nq = self.residual_q.len();
        if j < nq {
            Some((self.residual_q[j], self.residual_q_roots[j]))
        } else if j < self.pk_limbs() {
            Some((self.residual_p[j - nq], self.residual_p_roots[j - nq]))
        } else {
            None
        }
    }
}

/// Registry ID 2 is the Lattigo default bootstrappable set; ID 3 is the
/// META-BTS set for flooded third-party releases (E13, option O2b of
/// pqctoday-fhe docs/ckks/ckks-flooding-parameter-options-2026-10-11.md:
/// two bootstraps per refresh, scale 2^90, release over two primes); 0x8002
/// is an INSECURE N = 2^10 ring for fast tests only.
pub const CKKS_PARAM_SETS: &[&CkksParamSet] = &[&super::params_gen::PARAM_SET_2, &super::params_gen::PARAM_SET_32770, &super::params_gen::PARAM_SET_3];

pub fn find(id: u32) -> Option<&'static CkksParamSet> {
    CKKS_PARAM_SETS.iter().copied().find(|p| p.id == id)
}

/// The level the token decrypts at: 0 (the bottom prime q0, serialization
/// version 2) for the Lattigo default sets, 1 (q0·q1, 105 bits,
/// serialization version 3) for the META-BTS set, whose scale 2^90 does not
/// fit one prime.
pub fn release_level(ps: &CkksParamSet) -> usize {
    match ps.id {
        3 => 1,
        _ => 0,
    }
}

/// Largest policy `scaleLog2` a set accepts: 60 for a one-prime release (the
/// range of policy version 2 as first built), the set's own default scale
/// (2^90) for the two-prime release. The lower bound stays 20.
pub fn max_scale_log2(ps: &CkksParamSet) -> u8 {
    if release_level(ps) == 0 {
        60
    } else {
        ps.log_default_scale as u8
    }
}

/// log2 of B, the post-bootstrap noise bound of release-level coefficients
/// used to size decryption flooding (plan §4.6). Measured by the pqctoday-fhe
/// oracle (`noise` command, gate F record, E4 method: largest coefficient
/// error over the trials, rounded up to a whole bit); a parameter set without
/// a measurement has no flooding width and its sealed releases are refused.
pub fn noise_bound_log2(ps: &CkksParamSet) -> f64 {
    match ps.id {
        2 => NOISE_BOUND_LOG2_PS2,
        3 => NOISE_BOUND_LOG2_PS3,
        0x8002 => NOISE_BOUND_LOG2_PS32770,
        _ => f64::INFINITY,
    }
}
pub const NOISE_BOUND_LOG2_PS2: f64 = 10.0; // measured 2026-10-10: max 2^9.2 over 2 bootstraps, rounded up
/// Registry ID 3, measured 2026-10-11 with the spec generator (pqctoday-fhe
/// `oracle noise 3 30 10000 30`, results-gate-f/noise-3.json): max 2^34.77
/// over 30 bootstraps (median 2^33.98); the E4 rounding alone would give 35
/// with 0.23 bits of margin, and the E13 study's Lattigo-key run reached
/// 2^35.1, so 36 covers all 32 measured bootstraps by at least 0.9 bits.
pub const NOISE_BOUND_LOG2_PS3: f64 = 36.0;
pub const NOISE_BOUND_LOG2_PS32770: f64 = 12.0; // measured 2026-10-10: max 2^11.2 over 3 bootstraps, rounded up

/// Streamed CKKS generator version: carried in every key-set and rotation
/// descriptor. Version 1 is frozen (gate V): its registry, KDF contexts,
/// samplers, key lists and known answers are pinned in `freeze.rs`, and any
/// change to them is a new version, never an edit of version 1.
pub const GENERATOR_VERSION: u32 = 1;

/// `FheParamSetV1.config` for every CKKS set (generator version 1).
pub const CONFIG_V1: &str = "streamed-evk/v1: AES-256-CTR streams, HMAC-SHA-256 a-expansion, Gaussian CDT sigma 3.2 bound 19, fixed-weight ternary";

/// Canonical identity of a key in the generator's KDF contexts and
/// a-expansion (Codex #5): kind ‖ Galois element ‖ level Q ‖ level P,
/// big-endian (1 + 8 + 4 + 4 bytes). Never the key's list position.
pub fn key_id(k: &KeyDesc) -> [u8; 17] {
    let mut b = [0u8; 17];
    b[0] = k.kind;
    b[1..9].copy_from_slice(&k.gal_el.to_be_bytes());
    b[9..13].copy_from_slice(&(k.level_q as u32).to_be_bytes());
    b[13..17].copy_from_slice(&(k.level_p as u32).to_be_bytes());
    b
}

impl CkksParamSet {
    /// The public key as a pseudo-key of kind 0 over the residual basis.
    pub fn pk_desc(&self) -> KeyDesc {
        KeyDesc { kind: 0, gal_el: 0, level_q: self.residual_q.len() - 1, level_p: self.residual_p.len() - 1 }
    }
    /// The rotation key (E10) over the residual basis (the levels stored
    /// ciphertexts use): limb j has modulus `pk_limb(j)`.
    pub fn rotation_desc(&self) -> KeyDesc {
        KeyDesc { kind: KIND_ROTATION, gal_el: 0, level_q: self.residual_q.len() - 1, level_p: self.residual_p.len() - 1 }
    }
}

/// 20-byte fingerprint of a parameter set's registry entry, carried in the
/// canonical encoding's `commit` field (a vendored Lattigo has no git commit
/// of its own here): `param_hash` truncated.
pub fn fingerprint(ps: &CkksParamSet) -> [u8; 20] {
    param_hash(ps)[..20].try_into().unwrap()
}

/// SHA-256 over name, ring degree, every modulus and root, the secret weights
/// and the key list (`key_id` of each). Bound into every generator KDF context;
/// the pqctoday-fhe oracle computes the same value (`paramHash`).
pub fn param_hash(ps: &CkksParamSet) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(ps.name.as_bytes());
    h.update(ps.log_n.to_be_bytes());
    for list in [ps.q, ps.q_roots, ps.p, ps.p_roots, ps.residual_q, ps.residual_q_roots, ps.residual_p, ps.residual_p_roots] {
        h.update((list.len() as u32).to_be_bytes());
        list.iter().for_each(|v| h.update(v.to_be_bytes()));
    }
    h.update((ps.h as u32).to_be_bytes());
    h.update((ps.ephemeral_h as u32).to_be_bytes());
    for k in ps.keys {
        h.update(key_id(k));
    }
    h.finalize().into()
}
