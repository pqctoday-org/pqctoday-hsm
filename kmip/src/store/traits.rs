//! [`KeyStore`] — minimal surface needed by Phase 5 op handlers.
//!
//! Phase 6 will implement the SQLite-backed concrete store with full
//! lifecycle FSM enforcement (per `docs/IMPLEMENTATION_PLAN.md` §3.4).
//! This trait defines just the operations the ops need to compile + test
//! against; the in-memory implementation in [`super::MemoryStore`]
//! satisfies it for Phase 5 unit tests.

use crate::error::Result;
use crate::kmip30::{KmipAlgorithm, ObjectType, State, UsageMask};
use time::OffsetDateTime;

/// KMIP `Unique Identifier` — KMIP 3.0 §4.x. We use a `urn:pqctoday:obj:<uuid>`
/// shape; the dispatcher allocates one per Create / CreateKeyPair.
pub type Uid = String;

/// Serde adapter for [`UsageMask`] (a `bitflags` type with no derived serde) —
/// round-trips via the raw `u32` bits. Used by `ObjectRecord`'s D-1 full-record
/// JSON persistence.
mod usage_mask_bits {
    use super::UsageMask;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(m: &UsageMask, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(m.bits())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<UsageMask, D::Error> {
        let bits = u32::deserialize(d)?;
        Ok(UsageMask::from_bits_truncate(bits))
    }
}

/// One managed object as the store sees it. Key material itself stays in
/// `softhsmrustv3`; the store keeps the KMIP-level metadata + the stable
/// PKCS#11 `CKA_ID` we use to find the object back inside the token.
// `CryptographicParameters` carries optional `HashingAlgorithm` enums
// that don't implement `Eq` — drop the `Eq` bound; PartialEq is what
// the store-parity tests actually need.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ObjectRecord {
    pub uid: Uid,
    pub object_type: ObjectType,
    pub algorithm: KmipAlgorithm,
    pub cryptographic_length: u32,
    /// `UsageMask` is a `bitflags` type with no derived serde; persist it as its
    /// raw `u32` bits (D-1 full-record persistence).
    #[serde(with = "usage_mask_bits")]
    pub usage_mask: UsageMask,
    pub state: State,
    /// PKCS#11 `CKA_ID` (bytes). The bridge uses this with `C_FindObjects`
    /// to recover the session-scoped `CK_OBJECT_HANDLE` for the object.
    pub pkcs11_cka_id: Vec<u8>,
    /// Slot the object lives in. v0.1 is single-slot but the field is
    /// here so Phase 6 can grow into multi-slot without an API change.
    pub pkcs11_slot: u32,
    /// KMIP `Initial Date` (§4.x).
    pub initial_date: OffsetDateTime,
    /// KMIP `Activation Date` (§4.x) — set on `Activate`.
    pub activation_date: Option<OffsetDateTime>,
    /// Linked predecessor when this object was created by a Plane-1
    /// `RekeyAndProceed`. KMIP `Link` attribute (§4.x); the dispatcher
    /// also surfaces this via the `x-pqctoday-supersedes` custom attr.
    pub supersedes: Option<Uid>,
    /// KMIP `Name` (§4.x) — optional textual label set on Create. Used
    /// by Locate's Name filter and GetAttributes. None until a client
    /// sets one.
    pub name: Option<String>,
    /// KMIP `Link` attributes that point at other managed objects, keyed
    /// by `LinkType` (NextLink / PreviousLink / ParentLink / ChildLink /
    /// PreviousLink / DerivationBaseObjectLink / DerivedKeyLink /
    /// ReplacementObjectLink / ReplacedObjectLink — see KMIP 3.0 §4.x).
    /// v0.1 stores the raw tag-form name as the key (e.g. "NextLink")
    /// and the target UID string as the value, so AddAttribute on a
    /// `NextLink` round-trips correctly through OASIS test cases.
    pub links: std::collections::HashMap<String, String>,
    /// Arbitrary custom attributes carried per managed object (KMIP
    /// `Custom Attribute` family, x-* / y- names). Populated by
    /// AddAttribute / SetAttribute; surfaced by GetAttributes /
    /// GetAttributeList.
    pub custom_attributes: std::collections::HashMap<String, String>,
    /// KMIP `Object Group` (0x420056) memberships — **multi-instance**:
    /// an object may belong to several groups, so this is a list of
    /// group-name labels rather than a single value. Populated from the
    /// template at Create / Register and mutated by AddAttribute /
    /// DeleteAttribute; Locate's Object Group filter matches when ANY
    /// element equals the requested group (SASED-M-3 step #0). Empty =
    /// not a member of any group.
    pub object_groups: Vec<String>,
    /// Raw KMIP `Key Material` bytes (KMIP 3.0 §6.2 KeyBlock →
    /// KeyValue → KeyMaterial). Populated by Register / Import when
    /// a client-supplied key payload arrives; surfaced by Get / Export.
    /// `None` for objects created via Create / CreateKeyPair where the
    /// key bytes live exclusively inside the engine.
    pub key_material: Option<Vec<u8>>,

    /// Secondary engine `CKA_ID` for a hybrid KEM private key. A hybrid
    /// object is tied to TWO non-extractable PKCS#11 handles — one classical,
    /// one PQC. `pkcs11_cka_id` addresses the ML-KEM half; this addresses the
    /// classical (X25519 / ECDH) half. `None` for every non-hybrid object.
    /// Both handles stay in the engine, so `Get` refuses the private key via
    /// the existing `CKA_SENSITIVE` gate — hybrid material never reaches this
    /// layer. `#[serde(default)]` keeps pre-existing sqlite blobs readable.
    #[serde(default)]
    pub pkcs11_cka_id_secondary: Option<Vec<u8>>,

    /// KMIP 3.0 §4.16 — the `Recommended Curve` enumeration value chosen for an
    /// EC/ECDH key (e.g. `CURVE25519 = 0x45` for an X25519 key). Backs the
    /// standard `Cryptographic Domain Parameters` attribute (`0x420029`) that
    /// `GetAttributes` reports. `None` for non-EC objects. `#[serde(default)]`
    /// keeps pre-existing sqlite blobs readable.
    #[serde(default)]
    pub recommended_curve: Option<u32>,
    /// KMIP `Key Format Type` (§6.2) — `Raw`, `Opaque`, `X.509`,
    /// `PKCS#1`, `PKCS#8`, `TransparentSymmetricKey`, etc. Stored as
    /// the wire codepoint; v0.1 only needs `Raw` (0x01) for symmetric
    /// Register/Import flows but the field keeps the format honest
    /// when other formats land.
    pub key_format_type: Option<u32>,

    /// KMIP 3.0 §6.2 `SecretDataType` — the Enumeration carried by a
    /// `SecretData` managed object (Password = 0x01, Seed = 0x02). Only
    /// meaningful when `object_type == SecretData`; `None` renders as the
    /// `Password` default for back-compat (BL-M-4). ML-KEM
    /// Encapsulate/Decapsulate set this to `Seed` (0x02) so the derived
    /// shared secret round-trips as the OASIS PQC interop KATs expect.
    pub secret_data_type: Option<u32>,

    /// KMIP 3.0 WD19 §3.4 — the deterministic generation seed (ML-DSA ξ,
    /// ML-KEM d‖z, SLH-DSA seed) supplied to `CreateKeyPair`. Stored on
    /// the private-key record so `Get` with `KeyFormatType=SeedPrivateKey`
    /// can return the `{ Seed, Key }` KeyMaterial structure. `None` for
    /// randomly-generated (non-seeded) keys.
    pub pqc_seed: Option<Vec<u8>>,

    /// KMIP 3.0 §11 `Cryptographic Parameters` attached to the key.
    /// Drives the Plane-3 mechanism choice — most importantly the
    /// RSA-OAEP family (PaddingMethod / HashingAlgorithm / MaskGenerator
    /// / MaskGeneratorHashingAlgorithm / PSource), which Encrypt /
    /// Decrypt read off the *key* per §6.1.21 rather than off the
    /// request payload. Stored as the typed struct from
    /// [`crate::kmip30::CryptographicParameters`].
    pub cryptographic_parameters: Option<crate::kmip30::CryptographicParameters>,

    // ── Baseline Server profile (KMIP Profiles v3.0 §5.1.2) extension ──
    //
    // The fields below cover every Object Attribute the Baseline Server
    // profile requires (items a–jjj). Most are `Option<T>` since they
    // only carry a value once the corresponding lifecycle op fires
    // (Deactivate sets `deactivation_date`, Revoke sets `compromise_*`,
    // etc.) or once a client client explicitly sets them via
    // AddAttribute / SetAttribute.

    /// KMIP §4 `Last Change Date` — touched on every store update.
    pub last_change_date: Option<OffsetDateTime>,
    /// KMIP §4 `Original Creation Date` — defaults to `initial_date` for
    /// freshly-generated objects; may differ for Register / Import.
    pub original_creation_date: Option<OffsetDateTime>,
    /// KMIP §4 `Deactivation Date` — set on `Deactivate`.
    pub deactivation_date: Option<OffsetDateTime>,
    /// KMIP §4 `Destroy Date` — set on `Destroy`.
    pub destroy_date: Option<OffsetDateTime>,
    /// KMIP §4 `Compromise Date` — set on `Revoke` with `KeyCompromise` /
    /// `CACompromise` reason.
    pub compromise_date: Option<OffsetDateTime>,
    /// KMIP §4 `Compromise Occurrence Date` — set on `Revoke`; carries
    /// the client-supplied date if known.
    pub compromise_occurrence_date: Option<OffsetDateTime>,
    /// KMIP §4 `Process Start Date` / `Protect Stop Date` — optional
    /// time-window constraints clients may set via AddAttribute.
    pub process_start_date: Option<OffsetDateTime>,
    pub protect_stop_date: Option<OffsetDateTime>,
    /// KMIP §4 `Rotate Date` — set when a key is rotated via Re-key.
    pub rotate_date: Option<OffsetDateTime>,

    /// KMIP §4 `Sensitive` / `Always Sensitive` / `Extractable` /
    /// `Never Extractable` — security posture flags. Defaulted on
    /// Create / Register based on the object's algorithm + usage.
    pub sensitive: Option<bool>,
    pub always_sensitive: Option<bool>,
    pub extractable: Option<bool>,
    pub never_extractable: Option<bool>,
    /// KMIP §4 `Fresh` — true if the key was created locally with no
    /// prior history (Create / CreateKeyPair); false for Register.
    pub fresh: Option<bool>,
    /// KMIP §4 `Key Value Present` — true if the engine can return the
    /// key bytes (mirrors `key_material.is_some()`).
    pub key_value_present: Option<bool>,
    /// KMIP §4 `Quantum Safe` — true for PQC algorithms (ML-DSA, ML-KEM,
    /// SLH-DSA); false for classical RSA/ECDSA. Defaulted by Create.
    pub quantum_safe: Option<bool>,
    /// KMIP §4 `Rotate Automatic` — server-driven rotation toggle.
    pub rotate_automatic: Option<bool>,

    /// KMIP §4 `Short Unique Identifier` — abbreviated form of the UID
    /// (last 8 hex chars of the UUID portion). Generated lazily.
    pub short_unique_identifier: Option<String>,
    pub alternative_name: Option<String>,
    pub comment: Option<String>,
    pub description: Option<String>,
    pub contact_information: Option<String>,
    pub object_class: Option<String>,
    pub key_value_location: Option<String>,
    pub x509_certificate_identifier: Option<String>,
    pub x509_certificate_issuer: Option<String>,
    pub x509_certificate_subject: Option<String>,

    /// KMIP §11 `Certificate Type` — Enumeration codepoint (e.g. X.509
    /// = 0x01, PGP = 0x02). v0.1 stores the raw wire value.
    pub certificate_type: Option<u32>,
    pub certificate_length: Option<i32>,
    /// KMIP §6.2 / §11 — DER bytes of an X.509 / PGP Certificate
    /// supplied via Register. `certificate_length` mirrors the byte
    /// count; `certificate_subject_cn` is extracted server-side at
    /// Register time. All three travel together.
    pub certificate_value: Option<Vec<u8>>,
    pub certificate_subject_cn: Option<String>,
    /// KMIP §11 `Digital Signature Algorithm` — Enumeration codepoint.
    pub digital_signature_algorithm: Option<u32>,
    /// KMIP §11 `NIST Key Type` — Enumeration codepoint.
    pub nist_key_type: Option<u32>,
    /// KMIP §11 `Protection Level` — Enumeration codepoint.
    pub protection_level: Option<u32>,
    /// KMIP §6.1.49 `Revocation Reason Code` — set on `Revoke`.
    pub revocation_reason_code: Option<u32>,
    /// KMIP §6.1.14 `Deactivation Reason Code` — set on `Deactivate`.
    pub deactivation_reason_code: Option<u32>,

    /// KMIP §4 `Lease Time` — Interval seconds.
    pub lease_time: Option<u32>,
    /// KMIP §4 `Protection Period` — Interval seconds.
    pub protection_period: Option<u32>,
    pub rotate_interval: Option<u32>,
    pub rotate_offset: Option<i32>,
    /// KMIP §4 `Rotate Generation` — sequence counter.
    pub rotate_generation: Option<i32>,
    pub rotate_name: Option<String>,
    /// KMIP §4 `Random Number Generator` — Structure carrying RNG
    /// metadata. v0.1 stores nothing; this field exists so the
    /// attribute surface table is honest.
    pub random_number_generator_present: bool,
    /// KMIP §4 `Usage Limits` — Structure containing
    /// `UsageLimitsTotal` (the budget set at Register / Create time)
    /// and `UsageLimitsCount` (the remaining budget, deducted on
    /// each cryptographic op). CS-BC-M-7 pins a 16-byte total +
    /// per-Encrypt byte-count accounting against it.
    pub usage_limits_total: Option<i64>,
    pub usage_limits_remaining: Option<i64>,
    /// KMIP §11 `Usage Limits Unit` — Enumeration codepoint (Byte =
    /// 0x01, Object = 0x02). Captured from the client-supplied
    /// UsageLimits structure at Register time; the engine's
    /// per-Encrypt accounting deducts bytes, so Byte is the natural
    /// default when a budget exists without an explicit unit.
    pub usage_limits_unit: Option<u32>,
    /// KMIP §11 `Digest` — SHA-256 over the object's actual key
    /// material, computed once at creation (Register digests the
    /// supplied KeyMaterial / Certificate Value bytes; Create /
    /// CreateKeyPair hash the engine-held `CKA_VALUE` via
    /// `native::get_value_digest_sha256` without exporting it).
    /// `None` means no material was available — GetAttributes then
    /// OMITS the Digest attribute instead of fabricating one (K-14).
    pub digest_value: Option<Vec<u8>>,
    /// KMIP §11 `Application Specific Information` Structure —
    /// `(namespace, data)` pair. TL-M-3 step #0 finds objects by it.
    pub application_specific_information: Option<(String, String)>,
    /// Storage status — KMIP 3.0 §6.1.4 Archive / §6.1.47 Recover.
    /// `true` = Archival storage (§12.3 Storage Status Mask bit
    /// 0x02): the material is off-line, so Get and cryptographic
    /// operations fail with `ObjectArchived` (0x0d, §11: "The object
    /// SHALL be recovered from the archive before performing the
    /// operation") until Recover flips it back. Attributes remain
    /// readable. `false` = On-line storage (mask bit 0x01). Not a
    /// KMIP *attribute* — the spec only exposes it as the Locate
    /// Storage Status Mask filter (K22).
    pub archived: bool,
}

impl ObjectRecord {
    /// Helper for tests + handlers that only set the lifecycle-critical
    /// fields. Leaves every Baseline Server extension attribute at its
    /// natural default so call sites don't sprawl into 47-field literals.
    /// Production paths fill the rest via setter methods or
    /// AddAttribute / SetAttribute.
    pub fn baseline_defaults() -> BaselineDefaults {
        BaselineDefaults
    }
}

/// Marker struct used in `..ObjectRecord::baseline_defaults()` update
/// syntax — see [`ObjectRecord::baseline_defaults`].
pub struct BaselineDefaults;

impl From<BaselineDefaults> for ObjectRecord {
    fn from(_: BaselineDefaults) -> Self {
        ObjectRecord {
            uid: String::new(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 0,
            usage_mask: UsageMask::empty(),
            state: State::PreActive,
            pkcs11_cka_id: Vec::new(),
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,
            links: std::collections::HashMap::new(),
            custom_attributes: std::collections::HashMap::new(),
            object_groups: Vec::new(),
            key_material: None,
            pkcs11_cka_id_secondary: None,
            recommended_curve: None,
            key_format_type: None,
            secret_data_type: None,
            pqc_seed: None,
            cryptographic_parameters: None,
            last_change_date: None,
            original_creation_date: None,
            deactivation_date: None,
            destroy_date: None,
            compromise_date: None,
            compromise_occurrence_date: None,
            process_start_date: None,
            protect_stop_date: None,
            rotate_date: None,
            sensitive: None,
            always_sensitive: None,
            extractable: None,
            never_extractable: None,
            fresh: None,
            key_value_present: None,
            quantum_safe: None,
            rotate_automatic: None,
            short_unique_identifier: None,
            alternative_name: None,
            comment: None,
            description: None,
            contact_information: None,
            object_class: None,
            key_value_location: None,
            x509_certificate_identifier: None,
            x509_certificate_issuer: None,
            x509_certificate_subject: None,
            certificate_type: None,
            certificate_length: None,
            certificate_value: None,
            certificate_subject_cn: None,
            digital_signature_algorithm: None,
            nist_key_type: None,
            protection_level: None,
            revocation_reason_code: None,
            deactivation_reason_code: None,
            lease_time: None,
            protection_period: None,
            rotate_interval: None,
            rotate_offset: None,
            rotate_generation: None,
            rotate_name: None,
            random_number_generator_present: false,
            usage_limits_total: None,
            usage_limits_remaining: None,
            usage_limits_unit: None,
            digest_value: None,
            application_specific_information: None,
            archived: false,
        }
    }
}

impl Default for ObjectRecord {
    fn default() -> Self {
        BaselineDefaults.into()
    }
}

/// Minimum surface the Phase-5 op handlers call.
pub trait KeyStore: Send + Sync {
    /// Insert a freshly-created object. Errors on duplicate UID.
    fn put(&self, record: ObjectRecord) -> Result<()>;

    /// Look up by UID. `Ok(None)` for "not present".
    fn get(&self, uid: &str) -> Result<Option<ObjectRecord>>;

    /// Replace an object (lifecycle transition, supersedes link, etc.).
    /// Errors if the UID is unknown.
    fn update(&self, record: ObjectRecord) -> Result<()>;

    /// Delete by UID. Idempotent — succeeds even if the UID was absent.
    fn remove(&self, uid: &str) -> Result<()>;

    /// List all objects matching `predicate` (KMIP `Locate` op).
    fn find(&self, predicate: &dyn Fn(&ObjectRecord) -> bool) -> Result<Vec<ObjectRecord>>;
}
