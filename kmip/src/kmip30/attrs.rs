//! KMIP 3.0 attribute model.
//!
//! KMIP objects carry a flat list of typed attributes ([`Attribute`]). Most
//! attributes correspond to specific TTLV tags from the OASIS extraction
//! (`spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`). The v0.1 op set
//! exercises the subset modelled here; the rest get hauled in by later
//! phases as needed.
//!
//! Each attribute variant carries the typed payload its TTLV encoding would
//! decode into; Phase 5 op handlers consume `Attribute` directly rather than
//! re-parsing TTLV.

use super::algos::KmipAlgorithm;

// ── UsageMask (KMIP 3.0 §4.x) ───────────────────────────────────────────────
//
// CryptographicUsageMask is a 32-bit flag field telling the HSM what an
// object may be used for. The bits are normative; we model them as a typed
// flag set so handler code can read `mask.contains(UsageMask::SIGN)` rather
// than poking at raw u32.

bitflags::bitflags! {
    /// `CryptographicUsageMask` — KMIP 3.0 §4 attribute encoding the set of
    /// PKCS#11-style operations a key is allowed to perform.
    ///
    /// The bit values match KMIP 1.x/2.x/3.x (stable across all spec revisions).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct UsageMask: u32 {
        const SIGN                = 0x0000_0001;
        const VERIFY              = 0x0000_0002;
        const ENCRYPT             = 0x0000_0004;
        const DECRYPT             = 0x0000_0008;
        const WRAP_KEY            = 0x0000_0010;
        const UNWRAP_KEY          = 0x0000_0020;
        const EXPORT              = 0x0000_0040;
        const MAC_GENERATE        = 0x0000_0080;
        const MAC_VERIFY          = 0x0000_0100;
        const DERIVE_KEY          = 0x0000_0200;
        const CONTENT_COMMITMENT  = 0x0000_0400;
        const KEY_AGREEMENT       = 0x0000_0800;
        const CERTIFICATE_SIGN    = 0x0000_1000;
        const CRL_SIGN            = 0x0000_2000;
        const GENERATE_CRYPTOGRAM = 0x0000_4000;
        const VALIDATE_CRYPTOGRAM = 0x0000_8000;
        const TRANSLATE_ENCRYPT   = 0x0001_0000;
        const TRANSLATE_DECRYPT   = 0x0002_0000;
        const TRANSLATE_WRAP      = 0x0004_0000;
        const TRANSLATE_UNWRAP    = 0x0008_0000;
        const AUTHENTICATE        = 0x0010_0000;
    }
}

// ── ObjectType (KMIP 3.0 §10.2 Object Type enum, wire-codepoint 0x42 0x00 0x57) ─

/// `Object Type` enum value. v0.1 covers the four types touched by the op
/// set; the spec has more (e.g. `Split Key`, `Opaque Object`) — add when an
/// op handler needs them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Certificate              = 0x01,
    SymmetricKey             = 0x02,
    PublicKey                = 0x03,
    PrivateKey               = 0x04,
    SplitKey                 = 0x05,
    SecretData               = 0x07,
    OpaqueObject             = 0x08,
    PgpKey                   = 0x09,
    CertificateRequest       = 0x0a,
    User                     = 0x0b,
    Group                    = 0x0c,
    PasswordCredential       = 0x0d,
    DeviceCredential         = 0x0e,
    OneTimePasswordCredential = 0x0f,
    HashedPasswordCredential = 0x10,
}

impl ObjectType {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }

    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::Certificate),
            0x02 => Some(Self::SymmetricKey),
            0x03 => Some(Self::PublicKey),
            0x04 => Some(Self::PrivateKey),
            0x05 => Some(Self::SplitKey),
            0x07 => Some(Self::SecretData),
            0x08 => Some(Self::OpaqueObject),
            0x09 => Some(Self::PgpKey),
            0x0a => Some(Self::CertificateRequest),
            0x0b => Some(Self::User),
            0x0c => Some(Self::Group),
            0x0d => Some(Self::PasswordCredential),
            0x0e => Some(Self::DeviceCredential),
            0x0f => Some(Self::OneTimePasswordCredential),
            0x10 => Some(Self::HashedPasswordCredential),
            _ => None,
        }
    }
}

// ── State (KMIP 3.0 lifecycle FSM; §10.2 State enum) ───────────────────────

/// KMIP managed-object lifecycle state.
///
/// Transitions in [`Self::can_transition_to`] mirror the FSM in
/// `docs/IMPLEMENTATION_PLAN.md` §3.4. Phase 6 ([`crate::store::lifecycle`])
/// owns the enforcement; this module just defines the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    PreActive    = 0x01,
    Active       = 0x02,
    Deactivated  = 0x03,
    Compromised  = 0x04,
    Destroyed    = 0x05,
    DestroyedCompromised = 0x06,
}

impl State {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }

    pub const fn from_wire_value(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::PreActive),
            0x02 => Some(Self::Active),
            0x03 => Some(Self::Deactivated),
            0x04 => Some(Self::Compromised),
            0x05 => Some(Self::Destroyed),
            0x06 => Some(Self::DestroyedCompromised),
            _ => None,
        }
    }

    /// `true` if `self → next` is a legal KMIP lifecycle transition per
    /// the FSM. Reference enforcement table; the store layer wraps this
    /// with audit logging when transitioning persisted objects.
    pub const fn can_transition_to(self, next: State) -> bool {
        use State::*;
        matches!(
            (self, next),
            (PreActive,   Active | Deactivated | Compromised | Destroyed)
                | (Active,       Deactivated | Compromised | Destroyed)
                | (Deactivated,  Compromised | Destroyed)
                | (Compromised,  DestroyedCompromised)
                | (Destroyed,    DestroyedCompromised)
        )
    }
}

// ── RevocationReason (KMIP 3.0 §10.2 Revocation Reason Code enum) ──────────

/// `Revocation Reason Code` — required field on `Revoke` op requests.
/// Subset shown is the one exercised by the v0.1 op set; spec has more.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    Unspecified           = 0x01,
    KeyCompromise         = 0x02,
    CaCompromise          = 0x03,
    AffiliationChanged    = 0x04,
    Superseded            = 0x05,
    CessationOfOperation  = 0x06,
    PrivilegeWithdrawn    = 0x07,
}

impl RevocationReason {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
}

// ── Attribute enum ──────────────────────────────────────────────────────────

/// One typed KMIP attribute. The variant carries the decoded payload its
/// TTLV value would yield, so op handlers can pattern-match without
/// re-touching the codec.
///
/// Variants are added on demand as new ops need them — keep the enum the
/// shape of the v0.1 op set rather than a faithful mirror of every KMIP
/// 3.0 attribute (the spec has ~50; we use ~10).
#[derive(Clone, Debug, PartialEq)]
pub enum Attribute {
    /// `Cryptographic Algorithm` (TTLV tag `0x420028`) — the algo this object
    /// represents. Required on every `Create` / `Create Key Pair`.
    CryptographicAlgorithm(KmipAlgorithm),

    /// `Cryptographic Length` (TTLV tag `0x42002a`) — bit length, e.g. 2048
    /// for RSA-2048, 256 for AES-256, ignored for ML-DSA-65 (the parameter
    /// set determines length).
    CryptographicLength(u32),

    /// `Cryptographic Usage Mask` (TTLV tag derived from spec extraction).
    CryptographicUsageMask(UsageMask),

    /// `Object Type` (TTLV tag `0x420057`). On a `Create` request this is
    /// implicit (= SymmetricKey or whichever type matches the op variant);
    /// on `Get` responses it's explicit.
    ObjectType(ObjectType),

    /// `State` (lifecycle FSM position).
    State(State),

    /// `Unique Identifier` (TTLV tag `0x420094`) — KMIP UID for the object.
    UniqueIdentifier(String),

    /// `Name` (the human-readable label). KMIP `Name` is a structure with
    /// type + value; for v0.1 we collapse to a single string.
    Name(String),

    /// Arbitrary key-value pair the platform tracks (e.g. `pqc-demo`).
    /// Mapped to KMIP `Custom Attribute` on the wire.
    Custom { name: String, value: String },

    // ── KMIP Profiles v3.0 §5.1.2 Baseline Server attributes ──────────
    //
    // The variants below cover every Object Attribute the Baseline Server
    // profile requires. Each carries the typed payload the wire codec
    // expects. Most map 1:1 to a typed field on `ObjectRecord`.

    /// `Initial Date` (0x420039) — DateTime as Unix epoch seconds.
    InitialDate(i64),
    /// `Activation Date` (0x420001).
    ActivationDate(i64),
    /// `Deactivation Date` (0x42002f).
    DeactivationDate(i64),
    /// `Destroy Date` (0x420033).
    DestroyDate(i64),
    /// `Compromise Date` (0x420020).
    CompromiseDate(i64),
    /// `Compromise Occurrence Date` (0x420021).
    CompromiseOccurrenceDate(i64),
    /// `Last Change Date` (0x420048).
    LastChangeDate(i64),
    /// `Original Creation Date` (0x4200bc).
    OriginalCreationDate(i64),
    /// `Process Start Date` (0x420067).
    ProcessStartDate(i64),
    /// `Protect Stop Date` (0x420068).
    ProtectStopDate(i64),
    /// `Rotate Date` (0x42016d).
    RotateDate(i64),

    /// Security posture booleans.
    Sensitive(bool),
    AlwaysSensitive(bool),
    Extractable(bool),
    NeverExtractable(bool),
    Fresh(bool),
    KeyValuePresent(bool),
    QuantumSafe(bool),
    RotateAutomatic(bool),

    /// Identity / description strings.
    ShortUniqueIdentifier(String),
    AlternativeName(String),
    Comment(String),
    Description(String),
    ContactInformation(String),
    ObjectClass(String),
    KeyValueLocation(String),
    X509CertificateIdentifier(String),
    X509CertificateIssuer(String),
    X509CertificateSubject(String),
    RotateName(String),

    /// Enum codepoints.
    CertificateType(u32),
    DigitalSignatureAlgorithm(u32),
    NistKeyType(u32),
    ProtectionLevel(u32),
    RevocationReasonCode(u32),
    DeactivationReasonCode(u32),
    KeyFormatType(u32),

    /// `Protection Storage Mask` (0x42015e) — Integer bit-flag mask
    /// indicating where the server stores material (`Software=0x01`,
    /// `Hardware=0x02`, `OnProcessor=0x04`, etc.). Defaulted to
    /// `Software` on freshly-created managed objects per Baseline
    /// expectations.
    ProtectionStorageMask(u32),
    /// `Public Key Link` (0x42019a) — UID reference to the public-key
    /// half of a key pair. Emitted by AKLC-O-1's CreateKeyPair flow
    /// on the private half so GetAttributes can return the link.
    PublicKeyLink(String),
    /// `Private Key Link` (0x420199) — UID reference to the private
    /// key half (mirror of PublicKeyLink, emitted on the public half).
    PrivateKeyLink(String),
    /// `Next Link` (0x420194) — UID reference to the next-generation
    /// key in a rotation chain. AX-M-1 step #1 sets it on a freshly
    /// rotated source key to point at its replacement.
    NextLink(String),
    /// `Previous Link` (0x420198) — UID reference to the previous-
    /// generation key (mirror of NextLink on the replacement).
    PreviousLink(String),
    /// `Group Link` (0x4201b3) — UID reference to a `Group` object
    /// that contains this managed object. SASED-M-3 step #0 pins a
    /// Locate filter by GroupLink.
    GroupLink(String),
    /// `Application Specific Information` (0x420004) Structure —
    /// `ApplicationNamespace` + `ApplicationData` text-string pair.
    /// TL-M-3 step #0 pins a Locate filter by both fields.
    ApplicationSpecificInformation { namespace: String, data: String },
    /// `Certificate Value` (0x42001e) — the DER bytes of the X.509
    /// certificate as supplied to Register / surfaced via Get.
    CertificateValue(Vec<u8>),
    /// `Certificate Subject CN` (0x420108) — server-extracted from the
    /// DER Subject Name's commonName RDN. Marked Read-Only per §11.
    CertificateSubjectCN(String),

    /// Integers.
    CertificateLength(i32),
    LeaseTime(u32),
    ProtectionPeriod(u32),
    RotateInterval(u32),
    RotateOffset(i32),
    RotateGeneration(i32),
    /// `Usage Limits` Structure — v0.1 carries just `Usage Limits Total`.
    UsageLimitsTotal(i64),

    /// `Cryptographic Parameters` Structure (KMIP 3.0 §11) — opaque
    /// per-key handshake parameters (RSA-OAEP padding + mask generator
    /// + label, MAC hash, etc.). Carried as an Attribute when the
    /// client supplies it inside a Register/Create `Attributes` bag.
    CryptographicParameters(crate::kmip30::ops::CryptographicParameters),
    /// `Digest` Structure (KMIP 3.0 §11) — server-computed digest over
    /// the key material. Profiles v3.0 §4.1.1 item 10 marks the value
    /// as variable; we emit SHA-256 (always available per the same
    /// item) and let the comparator skip the bytes.
    Digest(DigestAttribute),
    /// `Random Number Generator` Structure (KMIP 3.0 §11) — describes
    /// the RNG the server used to generate the material. Profiles
    /// v3.0 §4.1 Response Variations item 6 — fields are variable.
    RandomNumberGenerator(RngAttribute),
}

/// `Digest` attribute Structure (KMIP 3.0 §11 / §6.2.x). The Digest
/// covers the wire-form key material so a client can spot tampering;
/// the comparator treats the value as variable (§4.1.1 item 10).
#[derive(Clone, Debug, PartialEq)]
pub struct DigestAttribute {
    pub hashing_algorithm: crate::kmip30::HashingAlgorithm,
    pub digest_value: Vec<u8>,
    /// `KeyFormatType` sub-field — wire codepoint, optional.
    pub key_format_type: Option<u32>,
}

/// `Random Number Generator` attribute Structure (KMIP 3.0 §11).
/// Reports which RNG produced the key material. All sub-fields are
/// optional and value-variable per Profiles §4.1 RV item 6.
#[derive(Clone, Debug, PartialEq)]
pub struct RngAttribute {
    /// Wire tag `RNG Algorithm` (0x420149) — Enumeration. We default
    /// to `ANSIX9_31 = 0x02` to match the OASIS test expectation
    /// shape even though the spec lets us use any value.
    pub rng_algorithm: u32,
    pub cryptographic_algorithm: Option<KmipAlgorithm>,
    pub cryptographic_length: Option<u32>,
}

impl Attribute {
    /// Convenience constructor for the common `Create` request pattern of
    /// `(algorithm, length, usage)` tuples.
    pub fn for_create(algo: KmipAlgorithm, length: u32, usage: UsageMask) -> Vec<Self> {
        vec![
            Attribute::CryptographicAlgorithm(algo),
            Attribute::CryptographicLength(length),
            Attribute::CryptographicUsageMask(usage),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_mask_bit_values_are_stable() {
        // Sanity check — these are the values KMIP clients hard-code at the
        // wire level. Any change here is a wire-protocol break.
        assert_eq!(UsageMask::SIGN.bits(),        0x0000_0001);
        assert_eq!(UsageMask::ENCRYPT.bits(),     0x0000_0004);
        assert_eq!(UsageMask::KEY_AGREEMENT.bits(), 0x0000_0800);
    }

    #[test]
    fn usage_mask_set_operations() {
        let sign_and_verify = UsageMask::SIGN | UsageMask::VERIFY;
        assert!(sign_and_verify.contains(UsageMask::SIGN));
        assert!(sign_and_verify.contains(UsageMask::VERIFY));
        assert!(!sign_and_verify.contains(UsageMask::ENCRYPT));
        assert_eq!(sign_and_verify.bits(), 0x0000_0003);
    }

    #[test]
    fn object_type_round_trip() {
        for ot in [
            ObjectType::Certificate,
            ObjectType::SymmetricKey,
            ObjectType::PublicKey,
            ObjectType::PrivateKey,
            ObjectType::SecretData,
        ] {
            let v = ot.to_wire_value();
            assert_eq!(ObjectType::from_wire_value(v), Some(ot));
        }
    }

    #[test]
    fn state_round_trip() {
        for s in [
            State::PreActive, State::Active, State::Deactivated,
            State::Compromised, State::Destroyed, State::DestroyedCompromised,
        ] {
            let v = s.to_wire_value();
            assert_eq!(State::from_wire_value(v), Some(s));
        }
    }

    #[test]
    fn state_transitions_are_normal_forward() {
        // Pre-active can move to all of Active, Deactivated, Compromised,
        // Destroyed.
        assert!(State::PreActive.can_transition_to(State::Active));
        assert!(State::PreActive.can_transition_to(State::Deactivated));

        // Active → Deactivated → Destroyed is the textbook flow.
        assert!(State::Active.can_transition_to(State::Deactivated));
        assert!(State::Deactivated.can_transition_to(State::Destroyed));

        // Compromised → DestroyedCompromised is the forensic terminal.
        assert!(State::Compromised.can_transition_to(State::DestroyedCompromised));
    }

    #[test]
    fn state_transitions_reject_illegal_backwards_or_sideways_moves() {
        // Cannot go back to PreActive.
        assert!(!State::Active.can_transition_to(State::PreActive));
        // Cannot skip from Active straight to Destroyed without Deactivate?
        // KMIP allows it per §10.2 lifecycle — let's check.
        assert!(State::Active.can_transition_to(State::Destroyed));
        // But Active cannot become DestroyedCompromised without going
        // through Compromised first.
        assert!(!State::Active.can_transition_to(State::DestroyedCompromised));
        // Terminal: Destroyed can only go to DestroyedCompromised.
        assert!(!State::Destroyed.can_transition_to(State::Active));
    }

    #[test]
    fn attribute_for_create_helper_produces_expected_shape() {
        let attrs = Attribute::for_create(
            KmipAlgorithm::MlDsa65,
            0,   // length is parameter-set-driven for ML-DSA, conventionally 0
            UsageMask::SIGN | UsageMask::VERIFY,
        );
        assert_eq!(attrs.len(), 3);
        assert!(matches!(attrs[0], Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65)));
        assert!(matches!(attrs[1], Attribute::CryptographicLength(0)));
        assert!(matches!(
            attrs[2],
            Attribute::CryptographicUsageMask(m) if m.contains(UsageMask::SIGN) && m.contains(UsageMask::VERIFY)
        ));
    }
}
