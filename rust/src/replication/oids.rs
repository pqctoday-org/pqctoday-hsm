//! Object identifiers for the replication service.
//!
//! Everything under `1.3.6.1.4.1.32473` is the RFC 5612 documentation PEN:
//! deliberately fake, never PQCToday-owned, accepted only while the explicit
//! educational profile is selected (spec §4.1; private-authority registry
//! `f2e5cfa175dba803dfafbe8fd1c78946658e9db0` §3). The `.3` evidence arc is the
//! registry's "reserved for disposable RATS evidence/claim fixtures" branch.

use der::oid::ObjectIdentifier;

/// FIPS 204 ML-DSA-65 (RFC 9881). Parameters MUST be absent.
pub const ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
/// FIPS 203 ML-KEM-768 (RFC 9935). Parameters MUST be absent.
pub const ML_KEM_768: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");

/// The documentation PEN subtree every non-educational validator rejects.
pub const DOCUMENTATION_PEN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473");

/// `id-pqctoday-key-replication-suite-mlkem768-mldsa65` (educational).
pub const SUITE_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.1.1");

/// Function-certificate purposes `.2.1`–`.2.6`, in registry order.
pub const PURPOSE_DEVICE_ISSUER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.2.1");
pub const PURPOSE_KEY_ATTESTATION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.2.2");
pub const PURPOSE_PACKAGE_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.2.3");
pub const PURPOSE_RECOVERY_RECIPIENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.2.4");
pub const PURPOSE_PEER_AUTHENTICATION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.2.5");
pub const PURPOSE_RECEIPT_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.2.6");

// ── Evidence profile (design note §E; review K0B-R-01/R-02) ─────────────────
// Element types.
pub const EV_ELEMENT_TRANSACTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.0.0");
pub const EV_ELEMENT_PLATFORM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.0.1");
pub const EV_ELEMENT_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.0.2");
// Transaction claims.
pub const EV_NONCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.0.0");
pub const EV_ROLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.0.1");
pub const EV_TRANSACTION_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.0.2");
pub const EV_DOMAIN_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.0.3");
pub const EV_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.0.4");
pub const EV_SUITE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.0.5");
// Platform claims.
pub const EV_DEVICE_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.1.0");
pub const EV_ENGINE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.1.1");
pub const EV_CUSTODY_SCOPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.1.2");
pub const EV_ISSUED_AT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.1.3");
// Key claims.
pub const EV_KEY_UNIQUE_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.0");
pub const EV_KEY_PUBLIC_HASH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.1");
pub const EV_KEY_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.2");
pub const EV_KEY_PARAMETER_SET: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.3");
pub const EV_KEY_SENSITIVE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.4");
pub const EV_KEY_EXTRACTABLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.5");
pub const EV_KEY_NEVER_EXTRACTABLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.6");
pub const EV_KEY_LOCAL: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.7");
pub const EV_KEY_LINEAGE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.8");
pub const EV_KEY_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.9");
pub const EV_KEY_PROVENANCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3.1.2.10");

/// True if `oid` lies in the RFC 5612 documentation subtree.
pub fn is_documentation_arc(oid: &ObjectIdentifier) -> bool {
    let prefix = DOCUMENTATION_PEN.as_bytes();
    let b = oid.as_bytes();
    b.len() >= prefix.len() && &b[..prefix.len()] == prefix
}

/// Function purposes (spec §4.2; `CKA_PQCTODAY_FUNCTION_PURPOSE` values).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Purpose {
    DeviceIssuer = 1,
    KeyAttestation = 2,
    PackageSigning = 3,
    RecoveryRecipient = 4,
    PeerAuthentication = 5,
    ReceiptSigning = 6,
}

impl Purpose {
    pub const LEAVES: [Purpose; 5] = [
        Purpose::KeyAttestation,
        Purpose::PackageSigning,
        Purpose::RecoveryRecipient,
        Purpose::PeerAuthentication,
        Purpose::ReceiptSigning,
    ];

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Purpose::DeviceIssuer,
            2 => Purpose::KeyAttestation,
            3 => Purpose::PackageSigning,
            4 => Purpose::RecoveryRecipient,
            5 => Purpose::PeerAuthentication,
            6 => Purpose::ReceiptSigning,
            _ => return None,
        })
    }

    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Purpose::DeviceIssuer => PURPOSE_DEVICE_ISSUER,
            Purpose::KeyAttestation => PURPOSE_KEY_ATTESTATION,
            Purpose::PackageSigning => PURPOSE_PACKAGE_SIGNING,
            Purpose::RecoveryRecipient => PURPOSE_RECOVERY_RECIPIENT,
            Purpose::PeerAuthentication => PURPOSE_PEER_AUTHENTICATION,
            Purpose::ReceiptSigning => PURPOSE_RECEIPT_SIGNING,
        }
    }

    /// The constrained mechanism a function private key's
    /// `CKA_ALLOWED_MECHANISMS` names. The recovery recipient decapsulates
    /// with ML-KEM only inside the import path; the rest sign only inside
    /// their engine operation.
    pub fn is_kem(self) -> bool {
        self == Purpose::RecoveryRecipient
    }

    pub fn label(self) -> &'static str {
        match self {
            Purpose::DeviceIssuer => "device issuer",
            Purpose::KeyAttestation => "key attestation",
            Purpose::PackageSigning => "package signing",
            Purpose::RecoveryRecipient => "recovery recipient",
            Purpose::PeerAuthentication => "peer authentication",
            Purpose::ReceiptSigning => "receipt signing",
        }
    }
}
