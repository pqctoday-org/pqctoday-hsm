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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
/// Transitions in [`Self::can_transition_to`] are authoritative against the
/// KMIP 3.0 §3.2 numbered state diagram and the §6.1.19 Destroy constraint;
/// `docs/IMPLEMENTATION_PLAN.md` §3.4 mirrors the same edges. Phase 6
/// ([`crate::store::lifecycle`]) owns the enforcement; this module just
/// defines the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
    ///
    /// Edges are taken verbatim from the KMIP 3.0 §3.2 numbered state
    /// diagram (transitions cross-referenced in §4 Initial/Activation/
    /// Deactivation/Destroy/Compromise Date attribute rules) and the
    /// §6.1.19 Destroy constraint:
    ///
    /// - **PreActive** → {Active (t1 activation), Compromised (t3),
    ///   Destroyed (t2)} — there is **no** PreActive→Deactivated edge;
    ///   Deactivation is the §3.2 transition 6 (Active→Deactivated) only.
    /// - **Active** → {Deactivated (t6), Compromised (t5)} — **not**
    ///   Destroyed directly: §6.1.19 states "Objects SHALL only be
    ///   destroyed if they are in either Pre-Active or Deactivated state".
    /// - **Deactivated** → {Compromised (t8), Destroyed (t7)}.
    /// - **Compromised** → {DestroyedCompromised}.
    /// - **Destroyed** → {DestroyedCompromised (t10)}.
    /// - **DestroyedCompromised** → {} (terminal).
    pub const fn can_transition_to(self, next: State) -> bool {
        use State::*;
        matches!(
            (self, next),
            (PreActive,   Active | Compromised | Destroyed)
                | (Active,       Deactivated | Compromised)
                | (Deactivated,  Compromised | Destroyed)
                | (Compromised,  DestroyedCompromised)
                | (Destroyed,    DestroyedCompromised)
        )
    }
}

// ── RevocationReason (KMIP 3.0 §10.2 Revocation Reason Code enum) ──────────

/// `Revocation Reason Code` — required field on `Revoke` op requests.
/// CertificateHold/RemoveFromCrl/AaCompromise (0x08-0x0A) are new in CSD02
/// (Table 598 §11.50) — absent from CSD01. None of them join the
/// `KeyCompromise`/`CaCompromise` "Compromised" family the §3 state-machine
/// prose defines (verified against CSD02 §3 transitions #3/#5/#8/#10, which
/// name only Key Compromise / CA Compromise) — informational reason codes,
/// no new state-transition semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    Unspecified           = 0x01,
    KeyCompromise         = 0x02,
    CaCompromise          = 0x03,
    AffiliationChanged    = 0x04,
    Superseded            = 0x05,
    CessationOfOperation  = 0x06,
    PrivilegeWithdrawn    = 0x07,
    CertificateHold       = 0x08,
    RemoveFromCrl         = 0x09,
    AaCompromise          = 0x0a,
}

impl RevocationReason {
    pub const fn to_wire_value(self) -> u32 {
        self as u32
    }
}

/// The typed value of a client-set custom/vendor `Attribute` (KMIP §11's
/// generic `VendorIdentification` + `AttributeName` + `AttributeValue`
/// envelope). Found genuinely necessary, not speculative: the OASIS
/// TL-M-2/TL-M-3 conformance transcripts set `VendorAttribute2` as an
/// Integer and `VendorAttribute3` as a DateTime and expect `GetAttributes`
/// to round-trip the same wire type back — a bare `String` value silently
/// lost that (decoded to `""`, since the old decode arm only matched
/// `Value::TextString`). Covers the scalar TTLV primitive types actually
/// exercised by any known transcript; ByteString / Enumeration / BigInteger
/// / LongInteger custom-attribute values are not corpus-tested and fall
/// back to being dropped at decode (same graceful-degradation posture as
/// before this type existed), same as any other genuinely-unsupported
/// wire shape.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CustomAttributeValue {
    Text(String),
    /// Wire `Value::Integer` (i32) widened to i64 for one shared column
    /// with `DateTime` (also epoch seconds) — no precision is lost.
    Integer(i64),
    /// Epoch seconds, matching every other DateTime-typed `Attribute`
    /// variant's convention in this enum (see `ActivationDate` etc.).
    DateTime(i64),
    Boolean(bool),
}

impl CustomAttributeValue {
    /// Stringify for the policy-matching / legacy string-map surface
    /// (`helpers::strip_x_prefixes`, `helpers::custom_attrs_from`) —
    /// callers that only ever compared these as strings (policy YAML
    /// rules match on string patterns) keep working unchanged.
    pub fn as_policy_string(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::Integer(n) => n.to_string(),
            Self::DateTime(t) => t.to_string(),
            Self::Boolean(b) => b.to_string(),
        }
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

    /// `Cryptographic Domain Parameters` (TTLV tag `0x420029`) — KMIP 3.0 §4.16
    /// Structure carrying `Qlength` (Integer, `0x420073`) and `Recommended
    /// Curve` (Enumeration, `0x420075`). This is the standard, spec-compliant
    /// way to specify the curve on a `Create Key Pair` request — e.g. an X25519
    /// key is `CryptographicAlgorithm=ECDH` + this with
    /// `recommended_curve = CURVE25519 (0x45)`. Distinct from
    /// `Cryptographic Parameters` (`0x42002b`). Both members optional per Table 88.
    CryptographicDomainParameters {
        qlength: Option<u32>,
        recommended_curve: Option<u32>,
    },

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

    /// Arbitrary key-value pair the platform tracks (e.g. `pqc-demo`), OR
    /// a genuine client-set KMIP §11 vendor/custom `Attribute` (the
    /// `VendorIdentification` + `AttributeName` + `AttributeValue`
    /// envelope — e.g. the OASIS TL-M-2/TL-M-3 conformance transcripts'
    /// `Barcode`, `VendorAttribute1-3`). Both ride the same wire shape.
    Custom { name: String, value: CustomAttributeValue },

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
    /// KMIP 3.0 §4.5 — Structure of `{ Alternative Name Value,
    /// Alternative Name Type }`. Gap-remediation Phase H, Finding #11:
    /// `name_type` used to be discarded on decode and hardcoded to `1`
    /// (Uninterpreted Text String) on encode regardless of what the
    /// client actually set; now genuinely carried through.
    AlternativeName { value: String, name_type: u32 },
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
    /// `Object Group` (0x420056) — a group-membership label. KMIP's
    /// Object Group attribute is **multi-instance**: an object may
    /// belong to several groups, so it appears once per membership in
    /// an attribute list. Carries the group name (a `Name Reference`
    /// in the KMIP 3.0 `Object Groups` model — SASED-M-3 step #0 pins
    /// a Locate filter by it). Persisted onto the record at
    /// Create / Register and matched by Locate (any membership hits).
    ObjectGroup(String),
    /// `Derivation Base Object Link` (§4.35.5; wire tag `Derivation
    /// Object Link` 0x420192) — K20: on a derived Symmetric Key /
    /// Secret Data object, "expresses an association from a derived
    /// … object to the Managed Cryptographic Object(s) from which it
    /// was derived".
    DerivationBaseObjectLink(String),
    /// `Derived Object Link` (0x420193) — K20 mirror on the base
    /// object: §6.1.18 "the server SHALL create a Derived Object Link
    /// attribute pointing to the Symmetric Key or Secret Data object
    /// derived as a result of this operation".
    DerivedObjectLink(String),
    /// `Replaced Object Link` (0x42019b) — K21: on the replacement
    /// object created by Re-key / Re-key Key Pair, points at the
    /// existing (replaced) object: §6.1.51 "For the replacement key,
    /// the server SHALL create a Replaced Object Link attribute
    /// pointing to the existing key."
    ReplacedObjectLink(String),
    /// `Replacement Object Link` (0x42019c) — K21 mirror on the
    /// existing object: §6.1.51 "For the existing key, the server
    /// SHALL create a Replacement Object Link attribute pointing to
    /// the replacement key."
    ReplacementObjectLink(String),
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
    /// KMIP §4.64/§4.65/§4.66/§4.30/§4.63 — Phase 3.3 Split Key
    /// attributes. All read-only, client-set-once-at-creation.
    SplitKeyMethod(u32),
    SplitKeyParts(u32),
    SplitKeyThreshold(u32),
    KeyPartIdentifier(u32),
    /// §11.55 wire value (283/285) — only meaningful for the two
    /// GF(2^8)-based Split Key Methods.
    SplitKeyPolynomial(u32),
    ProtectionPeriod(u32),
    RotateInterval(u32),
    RotateOffset(i32),
    RotateGeneration(i32),
    /// `Usage Limits` Structure (KMIP 3.0 §11) — `Total` budget set at
    /// creation, remaining `Count` (server-decremented as protect ops
    /// consume the budget), and `Unit` (Byte = 0x01 / Object = 0x02).
    /// Count / Unit are optional on the wire; requests typically carry
    /// Total (+ Unit), responses carry all three when tracked.
    UsageLimits {
        total: i64,
        count: Option<i64>,
        unit: Option<u32>,
    },

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
    /// Wire tag `RNG Algorithm` — Enumeration per the spec's `RNG
    /// Algorithm` table: Unspecified 0x01, FIPS 186-2 0x02, DRBG 0x03,
    /// NRBG 0x04, ANSI X9.31 0x05, ANSI X9.62 0x06. The server reports
    /// `Unspecified` (0x01): the engine draws from the OS entropy pool
    /// (`OsRng`), not a managed DRBG. Replay-safe — the harness treats
    /// the structure as opaque (Profiles §4.1 RV item 6).
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
        // §3.2: Pre-Active can move to Active (t1), Compromised (t3), or
        // Destroyed (t2) — but NOT Deactivated (no such §3.2 edge;
        // Deactivation is transition 6, Active→Deactivated, only).
        assert!(State::PreActive.can_transition_to(State::Active));
        assert!(State::PreActive.can_transition_to(State::Destroyed));
        assert!(!State::PreActive.can_transition_to(State::Deactivated));

        // §3.2: Active → Deactivated (t6); then Deactivated → Destroyed (t7)
        // is the textbook flow. (Active → Destroyed directly is forbidden by
        // §6.1.19 — see state_transitions_reject_illegal_*.)
        assert!(State::Active.can_transition_to(State::Deactivated));
        assert!(State::Deactivated.can_transition_to(State::Destroyed));

        // Compromised → DestroyedCompromised is the forensic terminal.
        assert!(State::Compromised.can_transition_to(State::DestroyedCompromised));
    }

    #[test]
    fn state_transitions_reject_illegal_backwards_or_sideways_moves() {
        // Cannot go back to PreActive.
        assert!(!State::Active.can_transition_to(State::PreActive));
        // §6.1.19: "Objects SHALL only be destroyed if they are in either
        // Pre-Active or Deactivated state." Active → Destroyed is therefore
        // NOT a legal edge — an Active object must be Revoked/Deactivated
        // first. (§3.2 has no Active→Destroyed arrow; the only destroy
        // arrows are t2 PreActive→Destroyed and t7 Deactivated→Destroyed.)
        assert!(!State::Active.can_transition_to(State::Destroyed));
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
