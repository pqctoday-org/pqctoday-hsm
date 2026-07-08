// SPDX-License-Identifier: GPL-3.0-only
//
// G12 — Split Key secret sharing, implemented directly from KMIP 3.0
// §13.1 ("Split Key Algorithms"). PKCS#11 v3.2 has NO mechanism for
// this at all (verified directly against the spec text, not just the
// header — no Shamir / secret-sharing / threshold-scheme / key-split
// concept anywhere in it), so this lives here as a genuinely new
// vendor mechanism (`CKM_PQCTODAY_SPLIT_KEY`), not a gap-fill of an
// existing PKCS#11 capability.
//
// Four §11.54 "Split Key Method" values:
//
// - XOR (1): Parts MUST equal Threshold ("identical to Split Key
//   Threshold" — §13.1). Reconstruct by XORing all parts together.
// - Polynomial Sharing GF(2^16) (2): classic (t,n) Shamir sharing
//   [w1979] in GF(2^16), applied piecewise in 16-bit chunks when the
//   secret is longer than 16 bits.
// - Polynomial Sharing Prime Field (3): classic Shamir sharing over
//   GF(p) for a prime p > 2^L (L = secret bit length). This
//   implementation fixes p = 2^521 - 1 (the 13th Mersenne prime, the
//   same modulus NIST P-521 is built over) — large enough for any
//   symmetric key or reasonably-sized secret this server splits;
//   larger secrets are rejected rather than silently handled wrong.
// - Polynomial Sharing GF(2^8) (4): §13.1's prose only names THREE
//   methods ("the first one is based on XOR, and the other two are
//   based on polynomial secret sharing"), a genuine inconsistency
//   against §11.54's four-entry enum. But GF(2^8) is already fully
//   specified there as GF(2^16)'s base field (addition/subtraction =
//   XOR, multiplication/inversion per [FIPS197] §4.1/4.2) — so this
//   method is Shamir sharing performed directly in that same,
//   already-specified GF(2^8) field, one byte at a time, rather than
//   pairing bytes into GF(2^16) elements.
//
// GF(2^8) is parameterized by the client-selectable §4.63 "Split Key
// Polynomial" (§11.55): 283 = x^8+x^4+x^3+x+1 (the standard AES /
// [FIPS197] polynomial) or 285 = x^8+x^4+x^3+x^2+1 (§13.1's own worked
// example — "GF(2^8) ≈ 285 - x^8+x^4+x^3+x^2+1"). The multiply
// implementation is verified against [FIPS197]'s own published test
// vector ({57}·{83}={c1}, under polynomial 283) in this module's tests.

use num_bigint::{BigInt, BigUint, Sign};
use rand::RngCore;

/// KMIP 3.0 §11.54 Split Key Method Enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitKeyMethod {
    Xor,
    PolynomialGf65536,
    PolynomialPrimeField,
    PolynomialGf256,
}

/// KMIP 3.0 §11.55 Split Key Polynomial Enumeration — the irreducible
/// polynomial defining GF(2^8) (and, by extension, GF(2^16)). Only
/// meaningful for [`SplitKeyMethod::PolynomialGf256`] /
/// [`SplitKeyMethod::PolynomialGf65536`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf256Polynomial {
    /// x^8+x^4+x^3+x+1 (0x11B) — the standard AES / [FIPS197] polynomial.
    Polynomial283,
    /// x^8+x^4+x^3+x^2+1 (0x11D) — KMIP 3.0 §13.1's own worked example.
    Polynomial285,
}

impl Gf256Polynomial {
    /// The reduction byte: the polynomial's low 8 bits (the implicit
    /// x^8 term folds away during reduction).
    const fn reduction_byte(self) -> u8 {
        match self {
            Self::Polynomial283 => 0x1B,
            Self::Polynomial285 => 0x1D,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitKeyError {
    /// §2.2.8: Split Key Threshold SHALL be >= 1 and <= Split Key Parts.
    InvalidThreshold,
    /// XOR requires Parts == Threshold (§13.1: "identical to Split Key Threshold").
    XorPartsMustEqualThreshold,
    /// Join was given fewer than Threshold shares.
    InsufficientShares,
    /// Two supplied shares named the same index — Join can't proceed.
    DuplicateShareIndex,
    /// The secret doesn't fit under this server's fixed Prime Field modulus (2^521-1).
    SecretTooLargeForPrimeField,
    /// GF(2^8) supports at most 255 parts, GF(2^16) at most 65535.
    TooManyParts,
    /// A share's byte length didn't match what Join expected.
    MalformedShare,
}

// ── XOR (§11.54 value 1) ─────────────────────────────────────────────────

/// Split `secret` into exactly `parts` XOR shares (Parts == Threshold
/// is enforced by the caller — the KMIP-level Create Split Key
/// handler — per §13.1's "identical to Split Key Threshold").
/// Reconstructed by XORing every share together.
pub fn split_xor(secret: &[u8], parts: u32) -> Vec<Vec<u8>> {
    let n = parts as usize;
    let mut shares: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut running = secret.to_vec();
    for _ in 0..n.saturating_sub(1) {
        let mut share = vec![0u8; secret.len()];
        rand::rngs::OsRng.fill_bytes(&mut share);
        for (r, b) in running.iter_mut().zip(share.iter()) {
            *r ^= b;
        }
        shares.push(share);
    }
    // Last share makes the XOR of ALL shares equal the secret.
    shares.push(running);
    shares
}

pub fn join_xor(shares: &[Vec<u8>]) -> Vec<u8> {
    let len = shares.first().map(|s| s.len()).unwrap_or(0);
    let mut out = vec![0u8; len];
    for s in shares {
        for (o, b) in out.iter_mut().zip(s.iter()) {
            *o ^= b;
        }
    }
    out
}

// ── GF(2^8) arithmetic (§13.1) ────────────────────────────────────────────

/// GF(2^8) multiplication ([FIPS197] §4.1's peasant's-algorithm
/// construction), reducing modulo `poly`.
pub fn gf256_mul(mut a: u8, mut b: u8, poly: Gf256Polynomial) -> u8 {
    let mut product: u8 = 0;
    let reduction = poly.reduction_byte();
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= reduction;
        }
        b >>= 1;
    }
    product
}

/// GF(2^8) multiplicative inverse via brute-force search over the
/// field's 255 nonzero elements — cheap at this size, and avoids a
/// separate extended-Euclidean implementation over GF(2)[x].
fn gf256_inv(a: u8, poly: Gf256Polynomial) -> u8 {
    assert_ne!(a, 0, "GF(2^8) zero has no multiplicative inverse");
    (1u16..=255u16)
        .map(|b| b as u8)
        .find(|&b| gf256_mul(a, b, poly) == 1)
        .expect("GF(2^8) is a field — every nonzero element has an inverse")
}

/// Evaluate the degree-(threshold-1) polynomial with `secret_byte` as
/// the constant term at GF(2^8) point `x`, via Horner's method.
/// `coeffs` holds the threshold-1 random higher-order coefficients.
fn gf256_eval(secret_byte: u8, coeffs: &[u8], x: u8, poly: Gf256Polynomial) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = gf256_mul(acc ^ c, x, poly);
    }
    acc ^ secret_byte
}

/// Lagrange interpolation at x=0 over GF(2^8) points.
fn gf256_interpolate_at_zero(points: &[(u8, u8)], poly: Gf256Polynomial) -> u8 {
    let mut result = 0u8;
    for &(xi, yi) in points {
        let mut li = 1u8;
        for &(xj, _) in points {
            if xj != xi {
                let den = xi ^ xj; // xi - xj, char 2
                li = gf256_mul(li, gf256_mul(xj, gf256_inv(den, poly), poly), poly);
            }
        }
        result ^= gf256_mul(yi, li, poly);
    }
    result
}

/// Split `secret`, one byte at a time, using independent degree-
/// (threshold-1) polynomials per byte but the SAME x-coordinate (share
/// index) across every byte, so share `i` is one coherent byte string.
pub fn split_gf256(
    secret: &[u8],
    parts: u32,
    threshold: u32,
    poly: Gf256Polynomial,
) -> Result<Vec<(u8, Vec<u8>)>, SplitKeyError> {
    validate_threshold(parts, threshold)?;
    if parts == 0 || parts > 255 {
        return Err(SplitKeyError::TooManyParts);
    }
    // Per-byte random coefficients: (threshold-1) coefficients per byte of the secret.
    let coeffs_per_byte: Vec<Vec<u8>> = secret
        .iter()
        .map(|_| {
            let mut c = vec![0u8; (threshold.saturating_sub(1)) as usize];
            rand::rngs::OsRng.fill_bytes(&mut c);
            c
        })
        .collect();
    let mut shares = Vec::with_capacity(parts as usize);
    for x in 1..=(parts as u16) {
        let x = x as u8;
        let bytes: Vec<u8> = secret
            .iter()
            .zip(coeffs_per_byte.iter())
            .map(|(&b, coeffs)| gf256_eval(b, coeffs, x, poly))
            .collect();
        shares.push((x, bytes));
    }
    Ok(shares)
}

pub fn join_gf256(
    shares: &[(u8, Vec<u8>)],
    threshold: u32,
    poly: Gf256Polynomial,
) -> Result<Vec<u8>, SplitKeyError> {
    validate_shares(shares.iter().map(|(x, _)| *x as u32), threshold, shares.len())?;
    let len = shares.first().map(|(_, b)| b.len()).unwrap_or(0);
    if shares.iter().any(|(_, b)| b.len() != len) {
        return Err(SplitKeyError::MalformedShare);
    }
    let mut secret = Vec::with_capacity(len);
    for byte_idx in 0..len {
        let points: Vec<(u8, u8)> = shares.iter().map(|(x, b)| (*x, b[byte_idx])).collect();
        secret.push(gf256_interpolate_at_zero(&points, poly));
    }
    Ok(secret)
}

// ── GF(2^16) arithmetic — algebraic extension of GF(2^8) (§13.1) ────────

/// An element of GF(2^16) ≈ GF(2^8)[y]/(y²+y+m), represented as `(u,
/// v)` for the linear combination `uy+v` (§13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gf65536(u8, u8);

/// m = x^5+x^4+x^3+x = 0x3A (§13.1).
const GF65536_M: u8 = 0x3A;

impl Gf65536 {
    fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0, self.1 ^ other.1)
    }

    /// `(ry+s)(uy+v) = ((r+s)(u+v)+sv)y + (rum+sv)`.
    ///
    /// §13.1 actually PRINTS the constant term as `(ru + svm)`, but
    /// that's a transcription error in this working draft: expanding
    /// `(ry+s)(uy+v)` directly from the defining relation `y²=y+m`
    /// (from `y²+y+m=0`, char 2) gives constant term `rum+sv`, not
    /// `ru+svm` — verified two ways: (1) direct re-derivation from
    /// first principles below, (2) the spec's OWN inverse formula
    /// (`d = (u+v)v + mu²`) only makes `(uy+v)·(uy+v)⁻¹ = 1` hold
    /// under `rum+sv`, not the printed `ru+svm` — so the inverse
    /// formula (independently verified correct) and the multiply
    /// formula as printed are mutually inconsistent; this fixes the
    /// multiply side to match. Caught empirically: split→join failed
    /// to reconstruct under the printed formula until this fix.
    ///
    /// Derivation: `(ry+s)(uy+v) = ru·y² + (rv+su)y + sv`. Substitute
    /// `y² = y+m`: `= ru·y + rum + (rv+su)y + sv = (ru+rv+su)y +
    /// (rum+sv)`. The y-coefficient `ru+rv+su` equals the printed
    /// `(r+s)(u+v)+sv` after expansion (the two `sv` terms cancel via
    /// XOR) — that part of the printed formula IS correct.
    fn mul(self, other: Self, poly: Gf256Polynomial) -> Self {
        let (r, s) = (self.0, self.1);
        let (u, v) = (other.0, other.1);
        let new_u = gf256_mul(r ^ s, u ^ v, poly) ^ gf256_mul(s, v, poly);
        let rum = gf256_mul(gf256_mul(r, u, poly), GF65536_M, poly);
        let new_v = rum ^ gf256_mul(s, v, poly);
        Self(new_u, new_v)
    }

    /// `(uy+v)^-1 = u·d⁻¹y + (u+v)·d⁻¹, where d = (u+v)v + mu²` — §13.1.
    fn inv(self, poly: Gf256Polynomial) -> Self {
        let (u, v) = (self.0, self.1);
        let d = gf256_mul(u ^ v, v, poly) ^ gf256_mul(GF65536_M, gf256_mul(u, u, poly), poly);
        let d_inv = gf256_inv(d, poly);
        Self(gf256_mul(u, d_inv, poly), gf256_mul(u ^ v, d_inv, poly))
    }

    fn to_bytes(self) -> [u8; 2] {
        [self.0, self.1]
    }

    fn from_bytes(b: [u8; 2]) -> Self {
        Self(b[0], b[1])
    }
}

fn gf65536_eval(secret: Gf65536, coeffs: &[Gf65536], x: Gf65536, poly: Gf256Polynomial) -> Gf65536 {
    let mut acc = Gf65536(0, 0);
    for &c in coeffs.iter().rev() {
        acc = acc.add(c).mul(x, poly);
    }
    acc.add(secret)
}

fn gf65536_interpolate_at_zero(
    points: &[(Gf65536, Gf65536)],
    poly: Gf256Polynomial,
) -> Gf65536 {
    let mut result = Gf65536(0, 0);
    for &(xi, yi) in points {
        let mut li = Gf65536(0, 1); // multiplicative identity: 0*y + 1
        for &(xj, _) in points {
            if xj != xi {
                let den = xi.add(xj); // xi - xj, char 2
                li = li.mul(xj.mul(den.inv(poly), poly), poly);
            }
        }
        result = result.add(yi.mul(li, poly));
    }
    result
}

/// Split `secret` in 16-bit (2-byte) chunks. An odd-length secret's
/// final chunk is zero-padded on encode and truncated back on decode
/// (the caller supplies the true length to [`join_gf65536`]).
pub fn split_gf65536(
    secret: &[u8],
    parts: u32,
    threshold: u32,
    poly: Gf256Polynomial,
) -> Result<Vec<(u16, Vec<u8>)>, SplitKeyError> {
    validate_threshold(parts, threshold)?;
    if parts == 0 || parts > 65535 {
        return Err(SplitKeyError::TooManyParts);
    }
    let chunks: Vec<Gf65536> = secret
        .chunks(2)
        .map(|c| {
            let b = if c.len() == 2 { [c[0], c[1]] } else { [c[0], 0] };
            Gf65536::from_bytes(b)
        })
        .collect();
    let coeffs_per_chunk: Vec<Vec<Gf65536>> = chunks
        .iter()
        .map(|_| {
            (0..threshold.saturating_sub(1))
                .map(|_| {
                    let mut b = [0u8; 2];
                    rand::rngs::OsRng.fill_bytes(&mut b);
                    Gf65536::from_bytes(b)
                })
                .collect()
        })
        .collect();
    let mut shares = Vec::with_capacity(parts as usize);
    for x_u16 in 1..=(parts as u32) {
        let x_bytes = (x_u16 as u16).to_be_bytes();
        let x = Gf65536::from_bytes(x_bytes);
        let mut bytes = Vec::with_capacity(chunks.len() * 2);
        for (chunk, coeffs) in chunks.iter().zip(coeffs_per_chunk.iter()) {
            bytes.extend_from_slice(&gf65536_eval(*chunk, coeffs, x, poly).to_bytes());
        }
        shares.push((x_u16 as u16, bytes));
    }
    Ok(shares)
}

pub fn join_gf65536(
    shares: &[(u16, Vec<u8>)],
    threshold: u32,
    expected_len: usize,
    poly: Gf256Polynomial,
) -> Result<Vec<u8>, SplitKeyError> {
    validate_shares(shares.iter().map(|(x, _)| *x as u32), threshold, shares.len())?;
    let chunk_count = shares.first().map(|(_, b)| b.len() / 2).unwrap_or(0);
    if shares.iter().any(|(_, b)| b.len() != chunk_count * 2) {
        return Err(SplitKeyError::MalformedShare);
    }
    let mut secret = Vec::with_capacity(chunk_count * 2);
    for chunk_idx in 0..chunk_count {
        let points: Vec<(Gf65536, Gf65536)> = shares
            .iter()
            .map(|(x, b)| {
                let xi = Gf65536::from_bytes(x.to_be_bytes());
                let yi = Gf65536::from_bytes([b[chunk_idx * 2], b[chunk_idx * 2 + 1]]);
                (xi, yi)
            })
            .collect();
        secret.extend_from_slice(&gf65536_interpolate_at_zero(&points, poly).to_bytes());
    }
    secret.truncate(expected_len);
    Ok(secret)
}

// ── Prime Field arithmetic (§13.1) ───────────────────────────────────────

/// The fixed modulus: 2^521 - 1, the 13th Mersenne prime (the same
/// modulus NIST P-521's base field uses — a well-known, independently
/// verifiable constant). Large enough for any symmetric key or
/// reasonably-sized secret this server splits; §13.1 only requires "a
/// prime bigger than 2L" (L = the secret's bit length), so a single
/// sufficiently large fixed prime is spec-conformant without needing
/// runtime primality generation.
fn prime_field_modulus() -> BigUint {
    (BigUint::from(1u32) << 521u32) - BigUint::from(1u32)
}

fn random_biguint_below(bound: &BigUint) -> BigUint {
    let bytes_len = bound.bits().div_ceil(8) as usize;
    loop {
        let mut buf = vec![0u8; bytes_len];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let candidate = BigUint::from_bytes_be(&buf);
        if candidate < *bound {
            return candidate;
        }
    }
}

/// Modular inverse via the extended Euclidean algorithm.
fn mod_inverse(a: &BigUint, modulus: &BigUint) -> BigUint {
    let a = BigInt::from_biguint(Sign::Plus, a.clone());
    let m = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let (mut old_r, mut r) = (a, m.clone());
    let (mut old_s, mut s) = (BigInt::from(1), BigInt::from(0));
    while r != BigInt::from(0) {
        let q = &old_r / &r;
        let new_r = &old_r - &q * &r;
        old_r = r;
        r = new_r;
        let new_s = &old_s - &q * &s;
        old_s = s;
        s = new_s;
    }
    let result = ((old_s % &m) + &m) % &m;
    result.to_biguint().expect("non-negative after mod reduction")
}

fn sub_mod(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % modulus
    } else {
        modulus - ((b - a) % modulus)
    }
}

pub fn split_prime_field(
    secret: &[u8],
    parts: u32,
    threshold: u32,
) -> Result<Vec<(u32, Vec<u8>)>, SplitKeyError> {
    validate_threshold(parts, threshold)?;
    let p = prime_field_modulus();
    let secret_int = BigUint::from_bytes_be(secret);
    if secret_int >= p {
        return Err(SplitKeyError::SecretTooLargeForPrimeField);
    }
    let coeffs: Vec<BigUint> = (0..threshold.saturating_sub(1))
        .map(|_| random_biguint_below(&p))
        .collect();
    let mut shares = Vec::with_capacity(parts as usize);
    for x in 1..=parts {
        let x_big = BigUint::from(x);
        let mut acc = BigUint::from(0u32);
        for c in coeffs.iter().rev() {
            acc = (acc * &x_big + c) % &p;
        }
        let y = (acc * &x_big + &secret_int) % &p;
        shares.push((x, y.to_bytes_be()));
    }
    Ok(shares)
}

pub fn join_prime_field(
    shares: &[(u32, Vec<u8>)],
    threshold: u32,
    expected_len: usize,
) -> Result<Vec<u8>, SplitKeyError> {
    validate_shares(shares.iter().map(|(x, _)| *x), threshold, shares.len())?;
    let p = prime_field_modulus();
    let points: Vec<(BigUint, BigUint)> = shares
        .iter()
        .map(|(x, y)| (BigUint::from(*x), BigUint::from_bytes_be(y)))
        .collect();
    let mut result = BigUint::from(0u32);
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut num = BigUint::from(1u32);
        let mut den = BigUint::from(1u32);
        for (j, (xj, _)) in points.iter().enumerate() {
            if i != j {
                num = (&num * xj) % &p;
                let diff = sub_mod(xi, xj, &p);
                den = (&den * diff) % &p;
            }
        }
        let term = (yi * &num % &p) * mod_inverse(&den, &p) % &p;
        result = (result + term) % &p;
    }
    let mut out = result.to_bytes_be();
    if out.len() < expected_len {
        let mut padded = vec![0u8; expected_len - out.len()];
        padded.append(&mut out);
        out = padded;
    } else if out.len() > expected_len {
        // Leading bytes beyond expected_len must be zero — anything
        // else means the shares don't reconstruct the claimed secret.
        let (extra, rest) = out.split_at(out.len() - expected_len);
        if extra.iter().any(|&b| b != 0) {
            return Err(SplitKeyError::MalformedShare);
        }
        out = rest.to_vec();
    }
    Ok(out)
}

// ── Shared validation ────────────────────────────────────────────────────

fn validate_threshold(parts: u32, threshold: u32) -> Result<(), SplitKeyError> {
    if threshold < 1 || threshold > parts {
        return Err(SplitKeyError::InvalidThreshold);
    }
    Ok(())
}

fn validate_shares(
    indices: impl Iterator<Item = u32>,
    threshold: u32,
    count: usize,
) -> Result<(), SplitKeyError> {
    if count < threshold as usize {
        return Err(SplitKeyError::InsufficientShares);
    }
    let mut seen = std::collections::HashSet::new();
    for idx in indices {
        if !seen.insert(idx) {
            return Err(SplitKeyError::DuplicateShareIndex);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [FIPS197] itself publishes this exact product as a worked
    /// example ({57}·{83}={c1}) under the standard AES polynomial —
    /// the one genuinely external check available for this
    /// implementation (KMIP's split-key methods have no published
    /// NIST/IETF KATs of their own; [w1979] predates KAT culture).
    #[test]
    fn gf256_mul_matches_fips197_worked_example() {
        assert_eq!(gf256_mul(0x57, 0x83, Gf256Polynomial::Polynomial283), 0xc1);
    }

    #[test]
    fn gf256_mul_identity_and_zero() {
        for poly in [Gf256Polynomial::Polynomial283, Gf256Polynomial::Polynomial285] {
            for a in 0u8..=255 {
                assert_eq!(gf256_mul(a, 1, poly), a, "a*1 = a");
                assert_eq!(gf256_mul(a, 0, poly), 0, "a*0 = 0");
            }
        }
    }

    #[test]
    fn gf256_inv_round_trips_every_nonzero_element() {
        for poly in [Gf256Polynomial::Polynomial283, Gf256Polynomial::Polynomial285] {
            for a in 1u8..=255 {
                let inv = gf256_inv(a, poly);
                assert_eq!(gf256_mul(a, inv, poly), 1, "a * a^-1 must be 1 (a={a:#x})");
            }
        }
    }

    #[test]
    fn xor_split_then_join_reconstructs() {
        let secret = b"a 32-byte secret key material!!";
        let shares = split_xor(secret, 5);
        assert_eq!(shares.len(), 5);
        assert_eq!(join_xor(&shares), secret);
    }

    #[test]
    fn xor_needs_every_share_not_a_subset() {
        let secret = b"secret16bytes!!!";
        let shares = split_xor(secret, 4);
        // A proper subset must NOT reconstruct the secret (with
        // overwhelming probability — shares are random bytes).
        assert_ne!(join_xor(&shares[..3]), secret);
    }

    #[test]
    fn gf256_split_then_join_with_exact_threshold_reconstructs() {
        let secret = b"AES-256 key material, 32 bytes!";
        for poly in [Gf256Polynomial::Polynomial283, Gf256Polynomial::Polynomial285] {
            let shares = split_gf256(secret, 5, 3, poly).unwrap();
            assert_eq!(shares.len(), 5);
            let reconstructed = join_gf256(&shares[..3], 3, poly).unwrap();
            assert_eq!(reconstructed, secret);
            // Any 3-of-5 subset works, not just the first three.
            let subset = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
            assert_eq!(join_gf256(&subset, 3, poly).unwrap(), secret);
        }
    }

    #[test]
    fn gf256_join_below_threshold_fails_closed() {
        let secret = b"short";
        let shares = split_gf256(secret, 5, 3, Gf256Polynomial::Polynomial283).unwrap();
        let err = join_gf256(&shares[..2], 3, Gf256Polynomial::Polynomial283).unwrap_err();
        assert_eq!(err, SplitKeyError::InsufficientShares);
    }

    #[test]
    fn gf256_below_threshold_does_not_recover_secret() {
        // Real secrecy check: fewer-than-threshold shares must not
        // even PARTIALLY leak the secret when (incorrectly)
        // interpolated — output should differ from the real secret.
        let secret = b"topsecret";
        let shares = split_gf256(secret, 5, 4, Gf256Polynomial::Polynomial283).unwrap();
        let wrong = join_gf256(&shares[..3], 3, Gf256Polynomial::Polynomial283).unwrap();
        assert_ne!(wrong, secret);
    }

    /// Direct field-property check on the corrected multiply formula:
    /// `x * x⁻¹ = 1` (the multiplicative identity, `Gf65536(0,1)`) for
    /// a spread of elements — locks in the fix against a regression
    /// back to the spec's mistranscribed constant term.
    #[test]
    fn gf65536_inverse_is_a_genuine_multiplicative_inverse() {
        for poly in [Gf256Polynomial::Polynomial283, Gf256Polynomial::Polynomial285] {
            for (u, v) in [(0u8, 1u8), (1, 0), (1, 1), (0x3A, 0x57), (0xFF, 0x01), (0x80, 0x80)] {
                let x = Gf65536(u, v);
                let inv = x.inv(poly);
                assert_eq!(
                    x.mul(inv, poly),
                    Gf65536(0, 1),
                    "x * x^-1 must be the multiplicative identity (x=({u:#x},{v:#x}))",
                );
            }
        }
    }

    #[test]
    fn gf65536_below_threshold_does_not_recover_secret() {
        let secret = b"top secret 16by!";
        let shares = split_gf65536(secret, 5, 4, Gf256Polynomial::Polynomial283).unwrap();
        let wrong =
            join_gf65536(&shares[..3], 3, secret.len(), Gf256Polynomial::Polynomial283).unwrap();
        assert_ne!(wrong, secret);
    }

    #[test]
    fn gf65536_split_then_join_reconstructs_even_and_odd_length() {
        for secret in [&b"16-byte-secret!!"[..], &b"odd-length-17!!!x"[..]] {
            for poly in [Gf256Polynomial::Polynomial283, Gf256Polynomial::Polynomial285] {
                let shares = split_gf65536(secret, 5, 3, poly).unwrap();
                let reconstructed = join_gf65536(&shares[..3], 3, secret.len(), poly).unwrap();
                assert_eq!(reconstructed, secret);
            }
        }
    }

    #[test]
    fn gf65536_join_below_threshold_fails_closed() {
        let secret = b"a 16 byte secret";
        let shares = split_gf65536(secret, 5, 3, Gf256Polynomial::Polynomial283).unwrap();
        let err = join_gf65536(&shares[..2], 3, secret.len(), Gf256Polynomial::Polynomial283)
            .unwrap_err();
        assert_eq!(err, SplitKeyError::InsufficientShares);
    }

    #[test]
    fn prime_field_split_then_join_reconstructs() {
        let secret = b"a 32-byte AES-256 secret key!!!";
        let shares = split_prime_field(secret, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);
        let reconstructed = join_prime_field(&shares[..3], 3, secret.len()).unwrap();
        assert_eq!(reconstructed, secret);
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        assert_eq!(join_prime_field(&subset, 3, secret.len()).unwrap(), secret);
    }

    #[test]
    fn prime_field_join_below_threshold_fails_closed() {
        let secret = b"short secret";
        let shares = split_prime_field(secret, 5, 4).unwrap();
        let err = join_prime_field(&shares[..2], 4, secret.len()).unwrap_err();
        assert_eq!(err, SplitKeyError::InsufficientShares);
    }

    #[test]
    fn prime_field_below_threshold_does_not_recover_secret() {
        // With too few shares, interpolation produces a value from the
        // WRONG (lower-degree) polynomial. That's either a different
        // byte string, or — since it's effectively a random field
        // element — one so large it doesn't even fit the expected
        // length, which the malformed-share guard correctly rejects.
        // Either outcome proves the secret isn't recovered; only
        // "returns the real secret" would be a break.
        let secret = b"a real secret value";
        let shares = split_prime_field(secret, 5, 4).unwrap();
        match join_prime_field(&shares[..3], 3, secret.len()) {
            Ok(wrong) => assert_ne!(wrong, secret),
            Err(SplitKeyError::MalformedShare) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn prime_field_rejects_secret_too_large_for_the_fixed_modulus() {
        let huge = vec![0xFFu8; 128]; // 1024 bits > the 521-bit modulus
        let err = split_prime_field(&huge, 3, 2).unwrap_err();
        assert_eq!(err, SplitKeyError::SecretTooLargeForPrimeField);
    }

    #[test]
    fn invalid_threshold_rejected_by_every_method() {
        let secret = b"secret";
        assert_eq!(
            split_gf256(secret, 3, 0, Gf256Polynomial::Polynomial283).unwrap_err(),
            SplitKeyError::InvalidThreshold
        );
        assert_eq!(
            split_gf256(secret, 3, 4, Gf256Polynomial::Polynomial283).unwrap_err(),
            SplitKeyError::InvalidThreshold
        );
        assert_eq!(split_prime_field(secret, 3, 4).unwrap_err(), SplitKeyError::InvalidThreshold);
    }

    #[test]
    fn duplicate_share_index_rejected() {
        let secret = b"secret16bytes!!!";
        let shares = split_gf256(secret, 5, 3, Gf256Polynomial::Polynomial283).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        let err = join_gf256(&dup, 3, Gf256Polynomial::Polynomial283).unwrap_err();
        assert_eq!(err, SplitKeyError::DuplicateShareIndex);
    }
}
