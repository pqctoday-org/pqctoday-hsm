// SPDX-License-Identifier: GPL-3.0-only
//
//! `SecP384r1MLKEM1024` (TLS group `0x11ed`) as a rustls `SupportedKxGroup`.
//!
//! ## Why this file exists
//!
//! KMIP Profiles v3.0 CSD02 §3.3.3 requires a Quantum Safe Authentication
//! Suite server to support all three of `X25519MLKEM768`,
//! `SecP256r1MLKEM768` **and `SecP384r1MLKEM1024`**. rustls 0.23.40 ships the
//! first two but not the third: `0x11ed` has no `NamedGroup` variant, no entry
//! in `crypto::aws_lc_rs::kx_group`, and the generic `Hybrid` combinator the
//! other two are built from lives in a private module. Until it lands
//! upstream, offering only two of three made §3.3.3 partial and forced every
//! description of this server to say *measured against* the suite rather than
//! *conformant to* it.
//!
//! Nothing about the underlying cryptography was missing — only the wiring.
//! Both halves are public API (`kx_group::SECP384R1`, `kx_group::MLKEM1024`),
//! and the hybrid seams `ActiveKeyExchange::hybrid_component()` /
//! `complete_hybrid_component()` are public trait methods precisely so a
//! composed group can be built downstream. This is that composition.
//!
//! ## Wire format and combiner — the load-bearing details
//!
//! Verified against `draft-ietf-tls-ecdhe-mlkem` and cross-checked against
//! this repo's own independent implementation in `rust/src/native/hybrid.rs`
//! (which composes the same group at the PKCS#11 layer):
//!
//! - **Classical element first**, unlike `X25519MLKEM768`. Client share is
//!   `p384_pub ‖ mlkem_ek`, server share is `p384_eph ‖ mlkem_ct`, and the
//!   shared secret is `ss_p384 ‖ ss_mlkem`. `SecP256r1MLKEM768` orders it the
//!   same way; only `X25519MLKEM768` puts the post-quantum element first.
//!   Getting this backwards yields a handshake that completes locally against
//!   a peer making the same mistake and fails against everyone else, which is
//!   why the interop test against OpenSSL is the real gate, not self-consistency.
//! - **Pure concatenation, no KDF.** The TLS key schedule does the extraction.
//! - **Sizes**: P-384 uncompressed point 97 = 1 + 48 + 48; ML-KEM-1024
//!   encapsulation key 1568; ML-KEM-1024 ciphertext 1568. So a client share is
//!   1665 bytes and a server share is 1665 bytes (they coincide here, unlike
//!   the 768 groups where ek 1184 ≠ ct 1088).
//!
//! ## FIPS
//!
//! `fips()` follows the element that appears first, matching rustls's own
//! reasoning for the other hybrids: SP800-56C rev 2 permits `Z' = Z ‖ T` where
//! `Z` is the approved shared secret, so with the classical element first it is
//! the classical half that controls approval.

use std::boxed::Box;
use std::vec::Vec;

use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

/// IANA codepoint for `SecP384r1MLKEM1024` (draft-ietf-tls-ecdhe-mlkem).
/// Expressed via `NamedGroup::Unknown` because rustls 0.23 has no named
/// variant for it; the wire encoding is identical either way.
pub const SECP384R1MLKEM1024_CODEPOINT: u16 = 0x11ed;

/// Uncompressed P-384 point: `0x04` ‖ X(48) ‖ Y(48).
const SECP384R1_LEN: usize = 97;
/// ML-KEM-1024 encapsulation key (client share), FIPS 203 Table 3.
const MLKEM1024_ENCAP_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext (server share), FIPS 203 Table 3.
const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

fn name() -> NamedGroup {
    NamedGroup::Unknown(SECP384R1MLKEM1024_CODEPOINT)
}

/// Split a received share into `(classical, post_quantum)`.
///
/// Returns `None` on any length mismatch — a peer sending a wrong-sized share
/// is misbehaving, and silently accepting a truncated one would hand the
/// classical half a partial point.
fn split(share: &[u8], pq_len: usize) -> Option<(&[u8], &[u8])> {
    if share.len() != SECP384R1_LEN + pq_len {
        return None;
    }
    Some(share.split_at(SECP384R1_LEN))
}

/// Concatenate in wire order: classical first for this group.
fn concat(classical: &[u8], post_quantum: &[u8]) -> Vec<u8> {
    [classical, post_quantum].concat()
}

/// `SecP384r1MLKEM1024`, composed from the two public aws-lc-rs groups.
#[derive(Debug)]
pub struct SecP384r1MlKem1024;

/// The value to place in a `CryptoProvider`'s `kx_groups`.
pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &SecP384r1MlKem1024;

impl SecP384r1MlKem1024 {
    fn classical() -> &'static dyn SupportedKxGroup {
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1
    }

    fn post_quantum() -> &'static dyn SupportedKxGroup {
        rustls::crypto::aws_lc_rs::kx_group::MLKEM1024
    }
}

impl SupportedKxGroup for SecP384r1MlKem1024 {
    /// Client side: start both halves and offer the concatenated share.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = Self::classical().start()?;
        let post_quantum = Self::post_quantum().start()?;
        let combined_pub_key = concat(classical.pub_key(), post_quantum.pub_key());
        Ok(Box::new(ActiveSecP384r1MlKem1024 {
            classical,
            post_quantum,
            combined_pub_key,
        }))
    }

    /// Server side: the server never holds state between hello and share, so
    /// it completes both halves in one shot against the client's share.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (classical_share, post_quantum_share) =
            split(client_share, MLKEM1024_ENCAP_LEN).ok_or(INVALID_KEY_SHARE)?;

        let cl = Self::classical().start_and_complete(classical_share)?;
        let pq = Self::post_quantum().start_and_complete(post_quantum_share)?;

        Ok(CompletedKeyExchange {
            group: name(),
            pub_key: concat(&cl.pub_key, &pq.pub_key),
            secret: SharedSecret::from(
                concat(cl.secret.secret_bytes(), pq.secret.secret_bytes()).as_slice(),
            ),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        name()
    }

    fn fips(&self) -> bool {
        // Classical element first ⇒ the classical half controls approval.
        // See the module comment.
        Self::classical().fips()
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveSecP384r1MlKem1024 {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveSecP384r1MlKem1024 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let (classical_share, post_quantum_share) =
            split(peer_pub_key, MLKEM1024_CIPHERTEXT_LEN).ok_or(INVALID_KEY_SHARE)?;

        let cl = self.classical.complete(classical_share)?;
        let pq = self.post_quantum.complete(post_quantum_share)?;

        Ok(SharedSecret::from(
            concat(cl.secret_bytes(), pq.secret_bytes()).as_slice(),
        ))
    }

    /// Lets a server that does not know `0x11ed` select the bare P-384 half
    /// instead of failing the handshake. Mirrors rustls's own hybrids.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codepoint_and_name_match_iana() {
        assert_eq!(SECP384R1MLKEM1024_CODEPOINT, 0x11ed);
        assert_eq!(SECP384R1MLKEM1024.name(), NamedGroup::Unknown(0x11ed));
        // The wire encoding must be the raw codepoint — this is what a peer
        // matches on, and NamedGroup::Unknown must not add framing.
        assert_eq!(u16::from(SECP384R1MLKEM1024.name()), 0x11ed);
    }

    #[test]
    fn client_share_is_classical_then_post_quantum_at_the_expected_sizes() {
        let active = SECP384R1MLKEM1024.start().unwrap();
        let share = active.pub_key();
        assert_eq!(share.len(), SECP384R1_LEN + MLKEM1024_ENCAP_LEN);
        // Classical first: an uncompressed P-384 point starts with 0x04.
        assert_eq!(
            share[0], 0x04,
            "share must start with the uncompressed P-384 point, i.e. classical first"
        );
    }

    #[test]
    fn round_trips_against_itself() {
        // Self-consistency only — necessary, NOT sufficient. It cannot catch a
        // reversed combiner, since both sides would reverse it identically.
        // The real gate is the OpenSSL interop test; see
        // tests/secp384r1mlkem1024_interop.rs.
        let client = SECP384R1MLKEM1024.start().unwrap();
        let client_share = client.pub_key().to_vec();

        let server = SECP384R1MLKEM1024
            .start_and_complete(&client_share)
            .unwrap();
        assert_eq!(server.group, name());
        assert_eq!(
            server.pub_key.len(),
            SECP384R1_LEN + MLKEM1024_CIPHERTEXT_LEN
        );

        let client_secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(
            client_secret.secret_bytes(),
            server.secret.secret_bytes(),
            "both sides must derive the same shared secret"
        );
        // P-384 shared secret 48 + ML-KEM-1024 shared secret 32.
        assert_eq!(client_secret.secret_bytes().len(), 48 + 32);
    }

    #[test]
    fn rejects_wrong_sized_shares_instead_of_truncating() {
        let short = vec![0u8; SECP384R1_LEN + MLKEM1024_ENCAP_LEN - 1];
        assert!(SECP384R1MLKEM1024.start_and_complete(&short).is_err());
        let long = vec![0u8; SECP384R1_LEN + MLKEM1024_ENCAP_LEN + 1];
        assert!(SECP384R1MLKEM1024.start_and_complete(&long).is_err());

        let client = SECP384R1MLKEM1024.start().unwrap();
        let bad_server_share = vec![0u8; SECP384R1_LEN + MLKEM1024_CIPHERTEXT_LEN - 1];
        assert!(client.complete(&bad_server_share).is_err());
    }

    #[test]
    fn offers_the_classical_half_as_a_hybrid_component() {
        let active = SECP384R1MLKEM1024.start().unwrap();
        let (group, share) = active
            .hybrid_component()
            .expect("must offer the P-384 half so a peer without 0x11ed can still negotiate");
        assert_eq!(group, NamedGroup::secp384r1);
        assert_eq!(share.len(), SECP384R1_LEN);
    }

    #[test]
    fn is_tls13_only() {
        assert!(SECP384R1MLKEM1024.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!SECP384R1MLKEM1024.usable_for_version(ProtocolVersion::TLSv1_2));
    }
}
