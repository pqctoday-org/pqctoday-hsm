//! Allowlisted CKKS parameter sets (FHE spec §4 extended; plan §5.2). The
//! moduli, primitive roots and canonical key list are generated from the
//! pinned Lattigo v6.2.0 by the pqctoday-fhe oracle (`params_gen.rs`).

pub const KIND_RELIN: u8 = 1;
pub const KIND_GALOIS: u8 = 2;
pub const KIND_DENSE_TO_SPARSE: u8 = 3;
pub const KIND_SPARSE_TO_DENSE: u8 = 4;

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

/// Registry ID 2 is the Lattigo default bootstrappable set; 0x8002 is an
/// INSECURE N = 2^10 ring for fast tests only.
pub const CKKS_PARAM_SETS: &[&CkksParamSet] = &[&super::params_gen::PARAM_SET_2, &super::params_gen::PARAM_SET_32770];

pub fn find(id: u32) -> Option<&'static CkksParamSet> {
    CKKS_PARAM_SETS.iter().copied().find(|p| p.id == id)
}

/// Educational decryption noise flooding: uniform in [-2^FLOOD_LOG2, 2^FLOOD_LOG2]
/// added to every decrypted coefficient. Not a proven IND-CPA-D bound.
pub const FLOOD_LOG2: u32 = 20;

/// `FheParamSetV1.config` for every CKKS set (generator version 1).
pub const CONFIG_V1: &str = "streamed-evk/v1: AES-256-CTR streams, HMAC-SHA-256 a-expansion, Gaussian CDT sigma 3.2 bound 19, fixed-weight ternary";

/// 20-byte fingerprint of a parameter set's registry entry, carried in the
/// canonical encoding's `commit` field (a vendored Lattigo has no git commit
/// of its own here): SHA-256 over name, ring degree, every modulus, the
/// secret weights and the key list, truncated.
pub fn fingerprint(ps: &CkksParamSet) -> [u8; 20] {
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
        h.update([k.kind]);
        h.update(k.gal_el.to_be_bytes());
        h.update((k.level_q as u32).to_be_bytes());
        h.update((k.level_p as u32).to_be_bytes());
    }
    h.finalize()[..20].try_into().unwrap()
}
