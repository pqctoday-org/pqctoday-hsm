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
/// Dense-to-sparse key over the auxiliary primes of the set (registry ID 4,
/// OpenFHE `KeySwitchGenSparse`): the same key equation as
/// `KIND_DENSE_TO_SPARSE`, over Q[0..=level_q] followed by
/// `aux_p[0..=level_p]` instead of the set's P. Additive under generator
/// version 1: only key lists that name it use it.
pub const KIND_DENSE_TO_SPARSE_AUX: u8 = 6;

/// One evaluation key of the canonical key list. Its limb basis is
/// Q[0..=level_q] followed by P[0..=level_p] (`aux_p` for
/// `KIND_DENSE_TO_SPARSE_AUX`, see `CkksParamSet::key_p`).
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
    /// Auxiliary primes of `KIND_DENSE_TO_SPARSE_AUX` keys (registry ID 4);
    /// empty for the other sets, whose `param_hash` is then unchanged.
    pub aux_p: &'static [u64],
    pub aux_p_roots: &'static [u64],
    /// Library whose parameter set this is (`FheParamSetV1.library` and
    /// `.version`): lattigo 6.2.0 for IDs 2, 3 and 0x8002, openfhe 1.6.0 for ID 4.
    pub library: &'static str,
    pub library_version: &'static str,
    pub h: usize,
    pub ephemeral_h: usize,
    pub log_default_scale: u32,
    pub keys: &'static [KeyDesc],
}

impl CkksParamSet {
    pub fn n(&self) -> usize {
        1 << self.log_n
    }
    /// The P basis of key `k` and its primitive roots: the set's P, or the
    /// auxiliary primes for `KIND_DENSE_TO_SPARSE_AUX`.
    pub fn key_p(&self, k: &KeyDesc) -> (&'static [u64], &'static [u64]) {
        if k.kind == KIND_DENSE_TO_SPARSE_AUX {
            (self.aux_p, self.aux_p_roots)
        } else {
            (self.p, self.p_roots)
        }
    }
    /// (modulus, primitive root) of limb `j` of key `k`.
    pub fn key_limb(&self, k: &KeyDesc, j: usize) -> Option<(u64, u64)> {
        if j <= k.level_q {
            Some((self.q[j], self.q_roots[j]))
        } else if j < k.limbs() {
            let i = j - k.level_q - 1;
            let (p, roots) = self.key_p(k);
            Some((*p.get(i)?, *roots.get(i)?))
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
/// is an INSECURE N = 2^10 ring for fast tests only; ID 4 is the OpenFHE
/// v1.6.0 `match128` set (docs/ckks/ckks-openfhe-registry-entry-spec-2026-10-12.md
/// in pqctoday-fhe): OpenFHE's moduli and closed bootstrapping key list, owner
/// release only (`owner_release_only`).
pub const CKKS_PARAM_SETS: &[&CkksParamSet] =
    &[&super::params_gen::PARAM_SET_2, &super::params_gen::PARAM_SET_32770, &super::params_gen::PARAM_SET_3, &super::params_gen::PARAM_SET_4];

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
        // Registry ID 4 (OpenFHE): no bound has been measured. The refresh runs
        // in OpenFHE, and a bound measured through Lattigo's refresh says
        // nothing about it, so the entry carries none.
        4 => f64::INFINITY,
        _ => f64::INFINITY,
    }
}

/// True for a set without a measured flood bound: it releases to its owner
/// only, unflooded. The token refuses a third-party recipient and a flooded
/// release for it (policy parse and decryption, `fhe::parse_decrypt_policy`,
/// `mech::release_gate`). Registry IDs 2, 3 and 0x8002 have a bound and keep
/// their behaviour; a new set is owner-release-only until its bound is
/// measured and added to `noise_bound_log2`.
pub fn owner_release_only(ps: &CkksParamSet) -> bool {
    !noise_bound_log2(ps).is_finite()
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
/// and the key list (`key_id` of each), then the auxiliary primes and their
/// roots when the set has any. Bound into every generator KDF context;
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
    // Auxiliary primes (registry ID 4): hashed only when present, so the hash
    // of every earlier set is unchanged (generator version 1 stays frozen).
    if !ps.aux_p.is_empty() {
        for list in [ps.aux_p, ps.aux_p_roots] {
            h.update((list.len() as u32).to_be_bytes());
            list.iter().for_each(|v| h.update(v.to_be_bytes()));
        }
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registry ID 4 (OpenFHE v1.6.0 `match128`): the shape the pqctoday-fhe
    /// spec note states (docs/ckks/ckks-openfhe-registry-entry-spec-2026-10-12.md).
    #[test]
    fn registry_4_has_the_openfhe_shape() {
        let ps = find(4).expect("registry ID 4");
        assert_eq!((ps.log_n, ps.q.len(), ps.p.len(), ps.h, ps.ephemeral_h, ps.log_default_scale), (16, 26, 6, 192, 32, 52));
        assert_eq!((ps.library, ps.library_version), ("openfhe", "1.6.0"));
        // The public key spans the whole chain; the release is over the bottom prime.
        assert_eq!((ps.residual_q, ps.residual_p), (ps.q, ps.p));
        assert_eq!(ps.pk_limbs(), 32);
        assert_eq!(release_level(ps), 0);
        // 1 relinearization + 75 rotation + 1 conjugation + 2 sparse-encapsulation keys.
        assert_eq!(ps.keys.len(), 79);
        let count = |kind| ps.keys.iter().filter(|k| k.kind == kind).count();
        assert_eq!((count(KIND_RELIN), count(KIND_GALOIS), count(KIND_DENSE_TO_SPARSE_AUX), count(KIND_SPARSE_TO_DENSE), count(KIND_DENSE_TO_SPARSE)), (1, 76, 1, 1, 0));
        assert_eq!(ps.keys.last().unwrap().kind, KIND_SPARSE_TO_DENSE);
        // OpenFHE's partition of Q: ceil(26 / 6) = 5 digits of 6 towers.
        let relin = ps.keys[0];
        assert_eq!((relin.dnum(), relin.level_p + 1), (5, 6));
        // The dense-to-sparse key is one digit over Q[0] and the two auxiliary primes.
        let d2s = ps.keys.iter().find(|k| k.kind == KIND_DENSE_TO_SPARSE_AUX).unwrap();
        assert_eq!((d2s.dnum(), d2s.limbs()), (1, 3));
        assert_eq!(ps.key_limb(d2s, 0), Some((ps.q[0], ps.q_roots[0])));
        assert_eq!(ps.key_limb(d2s, 1), Some((ps.aux_p[0], ps.aux_p_roots[0])));
        assert_eq!(ps.key_limb(d2s, 2), Some((ps.aux_p[1], ps.aux_p_roots[1])));
        assert_eq!(ps.key_limb(d2s, 3), None);
        // Every modulus (chain, P, auxiliary) is distinct and NTT-friendly for the ring and the Montgomery layer.
        let all: Vec<u64> = ps.q.iter().chain(ps.p).chain(ps.aux_p).copied().collect();
        let mut sorted = all.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "moduli are distinct");
        assert!(all.iter().all(|&q| q % (2 * ps.n() as u64) == 1 && q <= u64::MAX / 6));
        // The key list has no repeat (KeyIDs are identities).
        let mut ids: Vec<[u8; 17]> = ps.keys.iter().map(key_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 79);
        // Only the new set has auxiliary primes, and only it hashes them.
        for other in CKKS_PARAM_SETS.iter().filter(|p| p.id != 4) {
            assert!(other.aux_p.is_empty() && other.aux_p_roots.is_empty(), "set {}", other.id);
            assert_eq!(other.library, "lattigo");
        }
    }

    /// A set without a measured flood bound is owner-release-only; the sets
    /// with a bound keep their behaviour.
    #[test]
    fn owner_release_only_is_exactly_the_sets_without_a_bound() {
        for ps in CKKS_PARAM_SETS {
            let measured = noise_bound_log2(ps).is_finite();
            assert_eq!(owner_release_only(ps), !measured, "set {}", ps.id);
            assert_eq!(owner_release_only(ps), ps.id == 4, "set {}", ps.id);
        }
    }
}
