//! [`PolicyRequest`] — the normalised view of an inbound KMIP operation
//! the [`super::Engine`] evaluates rules against.
//!
//! The engine is **deliberately ignorant of the wire layer**: the dispatcher
//! (Phase 5) converts a parsed KMIP request into a `PolicyRequest` before
//! calling `evaluate`. This keeps Plane 1 a pure library callable from:
//!
//! - the production TLS dispatcher (Phase 7),
//! - the Phase 8 compliance CLI (`pqctoday-kmip-compliance`),
//! - the Hub scenario UI (via the policy WASM facade — a future workstream).
//!
//! ## Algorithm naming
//!
//! `algorithm` is a canonical string (e.g. `"AES-256"`, `"ML-DSA-87"`,
//! `"ECDSA-P384"`). [`super::Algo::canonical_name`] is the source of truth.
//! Strings rather than the [`KmipAlgorithm`] enum because:
//!
//! 1. Policies must be able to reference parameterised variants that the
//!    enum does not distinguish (`Aes` vs `AES-128/192/256`, `Ecdsa` vs
//!    `ECDSA-P256/P384/P521`).
//! 2. Composite-sig OIDs (LAMPS draft-19: `ML-DSA-65-ED25519`) are not
//!    `KmipAlgorithm` variants — they live in policy land only.
//! 3. Lets policy authors stay ahead of the engine's algorithm enum.
//!
//! ## `op` field
//!
//! Opaque string matched against rule `ops`. Canonical names mirror the KMIP
//! op set: `"Create"`, `"CreateKeyPair"`, `"Sign"`, `"SignatureVerify"`,
//! `"Encrypt"`, `"Decrypt"`, `"Encapsulate"`, `"Decapsulate"`, `"Activate"`,
//! `"Revoke"`, `"Destroy"`, `"Get"`, `"Locate"`. The dispatcher is responsible
//! for aliasing (e.g. KMIP 3.0 reuses `Encrypt` for ML-KEM encapsulation, but
//! the dispatcher can pass `"Encapsulate"` to the engine for clearer policy
//! authoring).

use std::collections::HashMap;
use time::OffsetDateTime;

use super::super::kmip30::UsageMask;

/// The mechanism dimension of a request (KMIP 3.0 `CryptographicParameters`),
/// plus the resolved canonical PKCS#11 `CKM_*` mechanism. Populated by the
/// dispatcher from the *effective* CryptographicParameters the op already
/// computes (see `ops::helpers::mechanism_params_from_cp`); all-`None` for ops
/// that carry no parameters. Codepoints are the KMIP enum values
/// (HashingAlgorithm `0x420038`, BlockCipherMode `0x420013`, PaddingMethod
/// `0x42005f`, MaskGenerator `0x420054`) — never re-encoded here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MechanismParams {
    /// KMIP `Hashing Algorithm` enum value (e.g. SHA-256 = `0x06`).
    pub hashing_algorithm: Option<u32>,
    /// KMIP `Block Cipher Mode` enum value (e.g. GCM = `0x09`, CBC = `0x01`).
    pub block_cipher_mode: Option<u32>,
    /// KMIP `Padding Method` enum value (e.g. OAEP = `0x02`, PSS = `0x0a`).
    pub padding_method: Option<u32>,
    /// KMIP `Mask Generator` enum value (MGF1 = `0x01`).
    pub mask_generator: Option<u32>,
    /// KMIP `Tag Length` (AEAD auth-tag length, bytes).
    pub tag_length: Option<i32>,
    /// KMIP `Salt Length` (RSA-PSS sLen, bytes).
    pub salt_length: Option<i32>,
    /// WD19 PQC signing flags.
    pub deterministic: Option<bool>,
    pub internal: Option<bool>,
    pub external_mu: Option<bool>,
    /// Canonical PKCS#11 `CKM_*` mechanism this request resolves to
    /// (`ops::helpers::canonical_mechanism`). The bypass-proof enforcement key:
    /// the same value whether the request arrived via a standard op or the
    /// PKCS#11 passthrough.
    pub canonical_mech: Option<u32>,
}

/// Normalised request as seen by the policy engine. Borrowed where possible
/// — the engine never persists the request.
#[derive(Debug, Clone)]
pub struct PolicyRequest<'a> {
    /// Canonical op name. Matches rule `ops` lists.
    pub op: &'a str,

    /// Canonical algorithm string (e.g. `"AES-256"`, `"ML-DSA-87"`).
    /// `None` for ops that don't carry an algorithm (e.g. `Locate`,
    /// `Destroy` by UID without a managed object reference).
    pub algorithm: Option<&'a str>,

    /// Key length in bits — relevant to `min_key_length` rules.
    /// `None` if not applicable to this op or not known yet (e.g. `Create`
    /// before the dispatcher resolved the size).
    pub key_length: Option<u32>,

    /// `UsageMask` of the key being created / used. `None` for ops that
    /// don't touch usage flags.
    pub usage_mask: Option<UsageMask>,

    /// Lifecycle state of the target managed object — relevant to
    /// `lifecycle_state_gate` rules. `None` for `Create` (object doesn't
    /// exist yet) or ops that don't reference a state.
    pub state: Option<&'a str>,

    /// Algorithm of the stored object this op targets (for `Sign`, `Encrypt`,
    /// `Encapsulate`, `Decrypt`, `Decapsulate`, `Get`). Set by the dispatcher
    /// after looking up the KMIP `unique_identifier` in the store.
    ///
    /// When the engine's resolved algorithm (from substitution rules) differs
    /// from `current_object_algorithm`, the engine emits
    /// [`super::Decision::RekeyAndProceed`] instead of plain `Allow` — the
    /// dispatcher then plans the rekey transaction (Phase 5+).
    pub current_object_algorithm: Option<&'a str>,

    /// KMIP `unique_identifier` of the target object — surfaced in
    /// [`super::Decision::RekeyAndProceed`] so the dispatcher knows which
    /// object to rekey. `None` for ops that don't target an existing object.
    pub target_uid: Option<&'a str>,

    /// Custom attributes attached to the request (KMIP `x-*` namespace).
    /// Keys MUST be the bare name without the `x-` prefix (loader strips it).
    pub custom_attrs: &'a HashMap<String, String>,

    /// `Distinguished Name` of the TLS client cert that issued this request.
    /// `None` in dry-run / Hub UI evaluation mode.
    pub caller_cn: Option<&'a str>,

    /// "Now" — injected so tests can pin a deterministic clock. Production
    /// code passes `OffsetDateTime::now_utc()`.
    pub ts: OffsetDateTime,

    /// Correlation ID shared across Plane 1 / 2 / 3 audit entries.
    pub correlation_id: &'a str,

    /// Mechanism dimension (hash / mode / padding / MGF / tag / salt / PQC
    /// flags + canonical `CKM_*`). Default (all-`None`) for ops without
    /// CryptographicParameters; populated by the dispatcher otherwise. The
    /// mechanism/hash rule types (plan P2) read this.
    pub mechanism: MechanismParams,
}

impl<'a> PolicyRequest<'a> {
    /// Constructor for the minimum-info case: just `op` + `algorithm` + `ts`
    /// + `correlation_id`. Tests and UI dry-runs use this; production
    /// dispatcher fills in the optional fields.
    pub fn minimal(
        op: &'a str,
        algorithm: Option<&'a str>,
        ts: OffsetDateTime,
        correlation_id: &'a str,
        custom_attrs: &'a HashMap<String, String>,
    ) -> Self {
        Self {
            op,
            algorithm,
            key_length: None,
            usage_mask: None,
            state: None,
            current_object_algorithm: None,
            target_uid: None,
            custom_attrs,
            caller_cn: None,
            ts,
            correlation_id,
            mechanism: MechanismParams::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_constructor_sets_optionals_to_none() {
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal(
            "Sign",
            Some("ML-DSA-87"),
            OffsetDateTime::UNIX_EPOCH,
            "corr-1",
            &attrs,
        );
        assert_eq!(req.op, "Sign");
        assert_eq!(req.algorithm, Some("ML-DSA-87"));
        assert!(req.key_length.is_none());
        assert!(req.usage_mask.is_none());
        assert!(req.state.is_none());
        assert!(req.caller_cn.is_none());
        assert_eq!(req.correlation_id, "corr-1");
    }
}
