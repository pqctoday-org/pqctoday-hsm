//! Plane 2 — KMIP 3.0 operation handlers.
//!
//! Each handler is one file (≤ ~250 LOC including tests + spec citations).
//! The set Phase 5 ships in this session:
//!
//! | File | KMIP 3.0 § | Op codepoint |
//! |---|---|---|
//! | [`activate`]          | 6.1.1  | 0x12 |
//! | [`create`]            | 6.1.8  | 0x01 |
//! | [`create_key_pair`]   | 6.1.11 | 0x02 |
//! | [`decrypt`]           | 6.1.15 | 0x20 |
//! | [`destroy`]           | 6.1.19 | 0x14 |
//! | [`encrypt`]           | 6.1.21 | 0x1f |
//! | [`get`]               | 6.1.23 | 0x0a |
//! | [`locate`]            | 6.1.32 | 0x08 |
//! | [`query`]             | 6.1.45 | 0x18 |
//! | [`revoke`]            | 6.1.49 | 0x13 |
//! | [`sign`]              | 6.1.60 | 0x21 |
//! | [`signature_verify`]  | 6.1.61 | 0x22 |
//!
//! All 12 v0.1 KMIP ops shipped. Shared helpers (audit emission, canonical
//! algorithm names) live in [`helpers`] so every op file stays focused on
//! its own KMIP semantics.
//!
//! Remaining 9 ops (Create, Get, Locate, Activate, Revoke, Destroy,
//! Encrypt, Decrypt, SignatureVerify) follow the same template:
//!
//! 1. Emit Plane-2 `KmipRequestReceived`.
//! 2. Pre-flight store lookup + lifecycle gate (per `docs/IMPLEMENTATION_PLAN.md` §3.4).
//! 3. Call `deps.engine.evaluate(&policy_request)`.
//! 4. Map `(KmipAlgorithm, PkcsOp) → CKM_*` via
//!    `KmipAlgorithm::to_pkcs11_mech` (Phase 3).
//! 5. Emit Plane-3 `Pkcs11Call`s; call the bridge (Phase 7 wires real
//!    softhsmrustv3 entries; v0.1 uses placeholders so tests run without
//!    a token).
//! 6. Persist any store mutations.
//! 7. Emit Plane-2 `KmipResponseSent`.
//!
//! Note: KMIP 3.0 does NOT add separate `Encapsulate` / `Decapsulate` ops.
//! ML-KEM encapsulation reuses `Encrypt`; ML-KEM decapsulation reuses
//! `Decrypt`. The handler branches on key algorithm.

pub mod activate;
pub mod allocation_and_config;
pub mod attribute_mutate;
pub mod create;
pub mod create_key_pair;
pub mod decrypt;
pub mod deps;
pub mod der_x509;
pub mod derive_key;
pub mod destroy;
pub mod encrypt;
pub mod get;
pub mod get_attribute_list;
pub mod get_attributes;
pub mod helpers;
pub mod interop;
pub mod lifecycle_and_protocol;
pub mod locate;
pub mod mac_and_hash;
pub mod query;
pub mod register_import_export;
pub mod rekey;
pub mod revoke;
pub mod rng_and_pkcs11;
pub mod session_and_auth;
pub mod sign;
pub mod signature_verify;
pub mod validate;
pub mod certify;

pub use deps::{Deps, DepsConfig};

/// K8 test fixture — the BL-M-9-30 Transparent RSA Private Key
/// components (OASIS corpus, 1024-bit), shared by the Register /
/// Get / Export / helper conversion tests. KMIP BigInteger padding
/// (leading zero bytes to an 8-byte multiple) is preserved exactly
/// as it appears on the wire.
#[cfg(test)]
pub(crate) mod test_rsa_fixture {
    use crate::codec::{encode, Tag, TtlvFrame, Value};
    use crate::kmip30::wire::tags;

    pub const MODULUS: &str = "0000000000000000930451c9ecd94f5bb9da17dd09381bd23be43eca8c7539f301fc8a8cd5d5274c3e7699dbdc711c97a7aa91e2c50a82bd0b1034f0df493dec16362427e58acce7f6ce0f9bcc617bbd8c90d0094a2703ba0d09eb19d1005f2fb265526aac75af32f8bc782cded2a57f811e03eaf67a944de5e78413dca8f232d074e6dcea4cec9f";
    pub const PRIVATE_EXPONENT: &str = "0b6a7d736199ea48a420e4537ca0c7c046784dcbeaa63baebc0bc132787449cde8d7cad0c0c863c0fefb06c3062befc50033ecf87b4e33a9be7bcbc8f1511ae215e80deb5d8af2bd31319d7821196640935a0cd67c94599579f2100d65e038831fdafb0dbe2bbdac00a696e67e756350e1c99ace11a36dabac3ed3e730960059";
    pub const PUBLIC_EXPONENT: &str = "0000000000010001";
    pub const P: &str = "0000000000000000ddf672fbcc5bda3d73affc4e791e0c03390224405d69ccaabc749faa0dcd4c2583c71dde8941a7b9aa030f52ef1451466c074d4d338fe677892acd9e10fd35bd";
    pub const Q: &str = "0000000000000000a98fbc3ed6b4c6f860f97165ac2f7bb6f2e2cb192a9abd49795be5bcf37d8ee69a6e169c24e5c32e4e7fa33265461407f952ba49e204818a2f785f113f922b8b";

    /// TTLV-encode the §6.2.1 `KeyMaterial` Structure exactly as the
    /// BL-M-9-30 Register request carries it (subset: the mandatory
    /// fields plus P/Q — `rsa` recomputes the CRT components).
    pub fn ttlv_key_material() -> Vec<u8> {
        let big = |tag: u32, hex_str: &str| {
            TtlvFrame::new(Tag(tag), Value::BigInteger(hex::decode(hex_str).unwrap()))
        };
        let frame = TtlvFrame::new(
            Tag(tags::KeyMaterial),
            Value::Structure(vec![
                big(tags::Modulus, MODULUS),
                big(tags::PrivateExponent, PRIVATE_EXPONENT),
                big(tags::PublicExponent, PUBLIC_EXPONENT),
                big(tags::PrimeP, P),
                big(tags::PrimeQ, Q),
            ]),
        );
        let mut buf = bytes::BytesMut::new();
        encode(&frame, &mut buf);
        buf.to_vec()
    }

    /// The same key as an `rsa::RsaPrivateKey` (for deriving PKCS#1 /
    /// PKCS#8 DER expectations in conversion tests).
    pub fn rsa_key() -> rsa::RsaPrivateKey {
        use rsa::BigUint;
        rsa::RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&hex::decode(MODULUS).unwrap()),
            BigUint::from_bytes_be(&hex::decode(PUBLIC_EXPONENT).unwrap()),
            BigUint::from_bytes_be(&hex::decode(PRIVATE_EXPONENT).unwrap()),
            vec![
                BigUint::from_bytes_be(&hex::decode(P).unwrap()),
                BigUint::from_bytes_be(&hex::decode(Q).unwrap()),
            ],
        )
        .expect("BL-M-9 fixture key is valid")
    }
}
