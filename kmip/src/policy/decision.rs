//! [`Decision`] — engine output for a single [`super::PolicyRequest`].
//!
//! Two outcomes:
//!
//! - `Allow { algorithm_override }` — request may proceed. If
//!   `algorithm_override` is `Some(canonical_name)`, the dispatcher MUST
//!   substitute it into the KMIP request before calling Plane 2. This is
//!   the load-bearing mechanism behind the headline demo: an application
//!   stays unchanged while the policy flips classical → PQC under it.
//!
//! - `Deny { kmip_reason, human, fired_rule_index }` — request rejected.
//!   The dispatcher MUST return a KMIP `OperationFailed` response with
//!   `result_reason = kmip_reason` and a human message taken from the
//!   rule's `reason:` field. `fired_rule_index` lets the audit log point
//!   at the exact rule (1-based, matching policy file line order).

use serde::{Deserialize, Serialize};

/// Subset of KMIP 3.0 `Result Reason` codes (§9.2.x) the Plane 1 engine
/// emits. The dispatcher passes these straight through to the response
/// builder. Full enum lives in [`crate::kmip30`]; this is the policy-engine
/// view because Plane 1 must compile + test without the full op layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenyReason {
    /// Generic policy refusal — `algorithm_denylist`, `algorithm_allowlist`,
    /// `temporal_cutoff`, `compliance_profile_gate`.
    PermissionDenied,
    /// `min_key_length` failed.
    InvalidCryptographicParameters,
    /// `lifecycle_state_gate` blocked an op against a non-Active object.
    ObjectArchived,
    /// `require_usage_mask` or `require_custom_attribute` failed at Create.
    InvalidAttributeValue,
    /// `max_key_age` exceeded.
    KeyExpired,
    /// Engine has no active policy and the default is deny-all.
    PolicyNotLoaded,
}

impl DenyReason {
    /// KMIP 3.0 §9.2 `ResultReason` this deny reason maps to. Every op
    /// handler used to discard `kmip_reason` entirely and hardcode
    /// `KmipError::permission_denied` for any `Decision::Deny`, collapsing
    /// all six reasons (and every rule that can fire each one) onto a
    /// single generic code — this is the mapping this module's own doc
    /// comment always claimed existed. `KeyExpired` and `PolicyNotLoaded`
    /// have no dedicated KMIP-spec reason, so they fall back to the
    /// closest existing codepoint rather than inventing a non-spec value.
    pub fn to_result_reason(self) -> crate::error::ResultReason {
        use crate::error::ResultReason;
        match self {
            DenyReason::PermissionDenied => ResultReason::PermissionDenied,
            DenyReason::InvalidCryptographicParameters => ResultReason::BadCryptographicParameters,
            DenyReason::ObjectArchived => ResultReason::ObjectArchived,
            DenyReason::InvalidAttributeValue => ResultReason::InvalidAttributeValue,
            // Closest existing spec concept to "this key has aged out":
            // the op requires a usable-for-this-purpose key and this one
            // no longer qualifies, echoing WrongKeyLifecycleState's own
            // "requires Active" framing.
            DenyReason::KeyExpired => ResultReason::WrongKeyLifecycleState,
            // Genuinely the best fit: "no policy loaded, default deny" IS
            // a permission denial from the client's perspective, and no
            // KMIP reason for "server misconfigured" exists.
            DenyReason::PolicyNotLoaded => ResultReason::PermissionDenied,
        }
    }
}

/// Mechanism parameters a policy *forces* onto a request (plan P3). The
/// dispatcher merges any `Some(_)` field into the effective KMIP
/// `CryptographicParameters` before resolving the PKCS#11 mechanism — so a
/// policy can transparently mandate e.g. AES-GCM, RSA-OAEP, or deterministic
/// ML-DSA with zero application change. Values are KMIP enum codepoints
/// (HashingAlgorithm / BlockCipherMode / PaddingMethod); `deterministic` is the
/// CSD02 PQC flag. Parallel to `Decision::Allow::algorithm_override`, but for
/// the mechanism dimension.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpOverride {
    pub hashing_algorithm: Option<u32>,
    pub block_cipher_mode: Option<u32>,
    pub padding_method: Option<u32>,
    pub deterministic: Option<bool>,
    /// F-5 — MGF function (KMIP `MaskGenerator` codepoint; MGF1 = `0x01`).
    pub mask_generator: Option<u32>,
    /// F-5 — AEAD authentication-tag length, bytes (KMIP `Tag Length`).
    pub tag_length: Option<i32>,
    /// F-5 — RSA-PSS salt length, bytes (KMIP `Salt Length`).
    pub salt_length: Option<i32>,
}

impl CpOverride {
    /// `true` when nothing is forced (used to keep `Allow.cp_override == None`).
    pub fn is_empty(&self) -> bool {
        self.hashing_algorithm.is_none()
            && self.block_cipher_mode.is_none()
            && self.padding_method.is_none()
            && self.deterministic.is_none()
            && self.mask_generator.is_none()
            && self.tag_length.is_none()
            && self.salt_length.is_none()
    }

    /// Merge `other` over `self`, per field, last-match-wins (mirrors the
    /// algorithm-resolution semantics: a later forcing rule overrides an
    /// earlier one for the same field; untouched fields are preserved).
    pub fn merge(&mut self, other: CpOverride) {
        if other.hashing_algorithm.is_some() {
            self.hashing_algorithm = other.hashing_algorithm;
        }
        if other.block_cipher_mode.is_some() {
            self.block_cipher_mode = other.block_cipher_mode;
        }
        if other.padding_method.is_some() {
            self.padding_method = other.padding_method;
        }
        if other.deterministic.is_some() {
            self.deterministic = other.deterministic;
        }
        if other.mask_generator.is_some() {
            self.mask_generator = other.mask_generator;
        }
        if other.tag_length.is_some() {
            self.tag_length = other.tag_length;
        }
        if other.salt_length.is_some() {
            self.salt_length = other.salt_length;
        }
    }
}

/// Outcome of [`super::Engine::evaluate`].
///
/// Three variants — the third is the agility engine's signature capability
/// over plain KMIP 3.0. KMIP 3.0 has no native way to declare "this Sign
/// request should silently produce a PQC signature even though the stored
/// key is classical." The agility engine fills that gap by emitting
/// [`Decision::RekeyAndProceed`] when policy's resolved algorithm differs
/// from the stored object's algorithm. The dispatcher (Phase 5) implements
/// the multi-op rekey transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Request may proceed. If `algorithm_override` is `Some(canonical)`,
    /// the dispatcher rewrites the KMIP request's `CryptographicAlgorithm`
    /// to that value before dispatching to the op handler. Used on `Create`/
    /// `CreateKeyPair` when policy substitutes the algorithm at key-generation
    /// time (cheap, no existing object to migrate).
    Allow {
        /// Canonical algorithm name to substitute, or `None` for pass-through.
        algorithm_override: Option<String>,
        /// Index of the rule that supplied the override (1-based) — `None`
        /// when no substitution fired.
        substituted_by_rule: Option<usize>,
        /// Mechanism parameters the policy forces (hash / mode / padding /
        /// deterministic). `None` when no forcing rule fired (plan P3).
        cp_override: Option<CpOverride>,
    },

    /// Policy says the request should proceed under a different algorithm
    /// than the stored object currently carries. Dispatcher MUST:
    ///
    /// 1. Generate a fresh keypair / key under `new_algorithm`.
    /// 2. Mark the original (`original_uid`) as `Deactivated` (KMIP 3.0
    ///    §11.56 State Enumeration has no "Deprecated" value — this is
    ///    the correct state and matches what `agility.rs` actually sets).
    /// 3. Link new ↔ old via the `x-pqctoday-supersedes` custom attribute
    ///    so verify-old-signature flows can still locate the predecessor.
    /// 4. Re-issue the original op against the new key handle.
    /// 5. Emit a `RekeyAndProceed` audit entry tying old + new UIDs to the
    ///    `correlation_id`.
    ///
    /// Phase 4.5 produces this decision; Phase 5 (op handlers) + Phase 6
    /// (store + lifecycle FSM) implement the orchestration.
    RekeyAndProceed {
        original_uid: String,
        from_algorithm: String,
        new_algorithm: String,
        /// 1-based index of the substitution rule that triggered the rekey.
        triggered_by_rule: usize,
        /// Human reason for the audit log (rule's `reason:` field).
        human: String,
    },

    /// Request denied. Dispatcher emits a KMIP `OperationFailed` response.
    Deny {
        /// KMIP `Result Reason` codepoint for the response.
        kmip_reason: DenyReason,
        /// Human-readable explanation pulled from the rule's `reason:` field.
        human: String,
        /// 1-based index of the rule that fired the Deny (matches policy
        /// file line order; suitable for surfacing in Hub UI tooltips).
        fired_rule_index: usize,
    },
}

impl Decision {
    /// Construct an unconditional Allow.
    pub fn allow() -> Self {
        Decision::Allow {
            algorithm_override: None,
            substituted_by_rule: None,
            cp_override: None,
        }
    }

    /// `true` if the decision permits the request to proceed.
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    /// `true` if the decision denies the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }

    /// `true` if the decision asks the dispatcher to rekey before proceeding.
    pub fn is_rekey(&self) -> bool {
        matches!(self, Decision::RekeyAndProceed { .. })
    }

    /// Canonical algorithm name the dispatcher should substitute, or `None`
    /// if no substitution applies (Allow with no override, or Deny).
    pub fn algorithm_override(&self) -> Option<&str> {
        match self {
            Decision::Allow {
                algorithm_override: Some(s),
                ..
            } => Some(s.as_str()),
            _ => None,
        }
    }

    /// Forced mechanism parameters the dispatcher should merge into the
    /// effective `CryptographicParameters` (plan P3), or `None`.
    pub fn cp_override(&self) -> Option<&CpOverride> {
        match self {
            Decision::Allow {
                cp_override: Some(ov),
                ..
            } => Some(ov),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_reason_maps_to_distinct_result_reasons_where_the_spec_allows() {
        use crate::error::ResultReason;
        // WP-1 remediation — every op handler used to discard `kmip_reason`
        // and hardcode `PermissionDenied`; this pins the mapping so that
        // regression can't silently return.
        assert_eq!(DenyReason::PermissionDenied.to_result_reason(), ResultReason::PermissionDenied);
        assert_eq!(
            DenyReason::InvalidCryptographicParameters.to_result_reason(),
            ResultReason::BadCryptographicParameters
        );
        assert_eq!(DenyReason::ObjectArchived.to_result_reason(), ResultReason::ObjectArchived);
        assert_eq!(
            DenyReason::InvalidAttributeValue.to_result_reason(),
            ResultReason::InvalidAttributeValue
        );
        assert_eq!(DenyReason::KeyExpired.to_result_reason(), ResultReason::WrongKeyLifecycleState);
        // No dedicated KMIP reason exists for a missing/unloaded policy —
        // this one legitimately stays generic, unlike the others above.
        assert_eq!(DenyReason::PolicyNotLoaded.to_result_reason(), ResultReason::PermissionDenied);
    }

    #[test]
    fn allow_default_no_override() {
        let d = Decision::allow();
        assert!(d.is_allow());
        assert!(!d.is_deny());
        assert_eq!(d.algorithm_override(), None);
    }

    #[test]
    fn allow_with_override_exposes_string() {
        let d = Decision::Allow {
            algorithm_override: Some("ML-KEM-1024".into()),
            substituted_by_rule: Some(3),
            cp_override: None,
        };
        assert_eq!(d.algorithm_override(), Some("ML-KEM-1024"));
    }

    #[test]
    fn deny_reports_denied_and_no_override() {
        let d = Decision::Deny {
            kmip_reason: DenyReason::PermissionDenied,
            human: "Algorithm not in FIPS allowlist".into(),
            fired_rule_index: 1,
        };
        assert!(d.is_deny());
        assert_eq!(d.algorithm_override(), None);
    }
}
