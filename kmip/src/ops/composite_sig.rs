// SPDX-License-Identifier: AGPL-3.0-only
//
//! LAMPS composite signatures (draft-ietf-lamps-pq-composite-sigs-19) —
//! the independent message-representative cross-check, test builds only.
//!
//! ## Where composite signatures happen
//!
//! In the engine. A composite key is ONE `CKK_COMP_SIG` object (PKCS#11
//! v3.3 working draft, `comp_sig.md`); `Sign`, `SignatureVerify`, `Certify`
//! and `Validate` drive `CKM_COMP_SIG`, and the engine builds
//! `M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M)` and both component
//! signatures (`softhsmrustv3::native::composite_sig`). Every per-set fact
//! (OID, label, PH, components) is the engine table's
//! (`softhsmrustv3::native::composite`, via
//! `KmipAlgorithm::composite_params`). This crate holds no profile table
//! and verifies nothing itself (invariant 0a).
//!
//! This file used to hold a second, hand-kept table of eight profiles and a
//! two-handle signer/verifier built on it. That form is gone (one engine
//! object per composite key). What stays is a deliberately separate
//! construction of M' — from the draft text, with its own hashing — used by
//! tests to check the engine's composite signatures from the outside: the
//! ML-DSA half of an engine signature must verify, under plain `CKM_ML_DSA`
//! with the set's label as context, over the M' built here. A signer and a
//! verifier that read the same table agree with each other even when both
//! are wrong (the 2026-08-17 traditional-hash bug); this check does not
//! share the engine's M' code.

#[cfg(test)]
pub(crate) mod cross_check {
    use sha2::Digest as _;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use softhsmrustv3::native::composite::{CompositeSigParams, PreHash};

    /// draft-ietf-lamps-pq-composite-sigs-19 §2.2: the ASCII prefix
    /// "CompositeAlgorithmSignatures2025", typed from the draft rather than
    /// taken from the engine's constant.
    pub const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

    /// PH(M) per §6 (SHA-256, SHA-512, or SHAKE256 with 64 bytes of output).
    pub fn pre_hash(ph: PreHash, m: &[u8]) -> Vec<u8> {
        match ph {
            PreHash::Sha256 => sha2::Sha256::digest(m).to_vec(),
            PreHash::Sha512 => sha2::Sha512::digest(m).to_vec(),
            PreHash::Shake256_64 => {
                let mut h = sha3::Shake256::default();
                h.update(m);
                let mut out = vec![0u8; 64];
                h.finalize_xof().read(&mut out);
                out
            }
        }
    }

    /// `M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M)` (§2.2, §3.2 step 2).
    pub fn message_representative(p: &CompositeSigParams, ctx: &[u8], m: &[u8]) -> Vec<u8> {
        assert!(ctx.len() <= 255, "§3.2 step 1: ctx is at most 255 bytes");
        let mut out = PREFIX.to_vec();
        out.extend_from_slice(p.label);
        out.push(ctx.len() as u8);
        out.extend_from_slice(ctx);
        out.extend_from_slice(&pre_hash(p.pre_hash, m));
        out
    }

    /// Check the ML-DSA half of composite signature `s` over `m` (context
    /// `ctx`) against the ML-DSA half of composite public key `pk`
    /// (`mldsaPK ‖ tradPK`, §4.1): the half is imported as a plain ML-DSA
    /// public key and verified with `CKM_ML_DSA`, context = the set's label
    /// (§3.3 step 4), over [`message_representative`]. `Ok(())` when it
    /// verifies.
    pub fn verify_ml_dsa_half(
        session: u32,
        p: &CompositeSigParams,
        pk: &[u8],
        m: &[u8],
        ctx: &[u8],
        s: &[u8],
    ) -> Result<(), u32> {
        use softhsmrustv3::native;
        let (pk_len, sig_len) = (p.ml_dsa_public_key_len(), p.ml_dsa_signature_len());
        assert!(pk.len() > pk_len && s.len() > sig_len, "{}: composite lengths", p.name);
        let h = native::register_ml_dsa_public_key(session, p.ml_dsa, &pk[..pk_len], b"xcheck", "xcheck")?;
        let r = native::verify_pqc(
            session,
            h,
            softhsmrustv3::constants::CKM_ML_DSA,
            &message_representative(p, ctx, m),
            &s[..sig_len],
            p.label,
            false,
            false,
        );
        let _ = native::destroy_object(session, h);
        r
    }

    /// Standard base64 with padding (RFC 4648 §4), as the LAMPS vector files
    /// use; test fixtures only.
    pub fn b64(s: &str) -> Vec<u8> {
        let val = |c: u8| -> u32 {
            match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("not base64: {c:#x}"),
            }
        };
        let s = s.as_bytes();
        assert_eq!(s.len() % 4, 0, "base64 length");
        let mut out = Vec::with_capacity(s.len() / 4 * 3);
        for chunk in s.chunks(4) {
            let pad = chunk.iter().filter(|&&c| c == b'=').count();
            let mut n = 0u32;
            for &c in chunk {
                n = (n << 6) | if c == b'=' { 0 } else { val(c) };
            }
            let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
            out.extend_from_slice(&bytes[..3 - pad]);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::cross_check::*;
    use softhsmrustv3::native::composite::{sig_params, COMPOSITE_SIG_SETS};

    /// The LAMPS vectors' `m`/`ctx`, and the ML-DSA half of every supported
    /// set's upstream signature, checked with the M' built here — which
    /// proves this builder (prefix, label, length byte, PH) against the
    /// draft authors' implementation, not against the engine. A wrong label
    /// or prefix fails it (the sabotage arms below).
    #[test]
    fn independent_m_prime_matches_the_lamps_vectors() {
        let _g = crate::ops::helpers::engine_lock();
        use softhsmrustv3::native::session;
        let _ = session::finalize();
        session::init().unwrap();
        let s = session::bootstrap_default_token(0, "so", "user", "composite-xcheck").unwrap();
        let doc: serde_json::Value = serde_json::from_str(include_str!(
            "../../../rust/kat/pkcs11-v33/composite-sig/testvectors.json"
        ))
        .unwrap();
        let (m, ctx) = (b64(doc["m"].as_str().unwrap()), b64(doc["ctx"].as_str().unwrap()));
        let mut checked = 0;
        for v in doc["tests"].as_array().unwrap() {
            let id = v["tcId"].as_str().unwrap();
            let Some(p) = COMPOSITE_SIG_SETS.iter().find(|p| p.name == id) else { continue };
            if !p.supported {
                continue;
            }
            let pk = b64(v["pk"].as_str().unwrap());
            verify_ml_dsa_half(s, p, &pk, &m, &[], &b64(v["s"].as_str().unwrap())).unwrap_or_else(|e| panic!("{id}: s {e:#x}"));
            verify_ml_dsa_half(s, p, &pk, &m, &ctx, &b64(v["sWithContext"].as_str().unwrap()))
                .unwrap_or_else(|e| panic!("{id}: sWithContext {e:#x}"));
            // Sabotage: another set's label, or no context, must not verify.
            let other = sig_params(if p.ckp == 1 { 2 } else { 1 }).unwrap();
            let mut wrong = *p;
            wrong.label = other.label;
            assert!(verify_ml_dsa_half(s, &wrong, &pk, &m, &[], &b64(v["s"].as_str().unwrap())).is_err(), "{id}");
            assert!(verify_ml_dsa_half(s, p, &pk, &m, &[], &b64(v["sWithContext"].as_str().unwrap())).is_err(), "{id}");
            checked += 1;
        }
        assert_eq!(checked, COMPOSITE_SIG_SETS.iter().filter(|p| p.supported).count());
        let _ = session::finalize();
    }

    #[test]
    fn m_prime_layout() {
        let p = &COMPOSITE_SIG_SETS[0];
        let mp = message_representative(p, b"ab", b"msg");
        assert!(mp.starts_with(PREFIX));
        assert_eq!(&mp[PREFIX.len()..PREFIX.len() + p.label.len()], p.label);
        assert_eq!(mp[PREFIX.len() + p.label.len()], 2);
        assert_eq!(mp.len(), PREFIX.len() + p.label.len() + 1 + 2 + p.pre_hash.output_len());
    }
}
