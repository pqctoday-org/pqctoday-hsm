//! Built-in rule types. Each variant of [`Rule`] is parameterised entirely
//! through YAML — no plugin-defined rule types in v0.1.
//!
//! ## Rule taxonomy
//!
//! Two families:
//!
//! - **Resolution rules** (Pass 1): `AlgorithmDefault`, `AlgorithmSubstitution`.
//!   Produce an `algorithm_override` that rewrites the request before Pass 2.
//!   Last match wins (later rules in the policy file have priority).
//!
//! - **Gating rules** (Pass 2): everything else. Each returns `Some(Deny)` to
//!   short-circuit or `None` to pass through. First deny wins.
//!
//! ## Adding a new rule type
//!
//! 1. Add a variant here with a `#[serde(rename = "<snake_case_name>")]`.
//! 2. Implement `check_pass2` (or `resolve_pass1` for resolution rules).
//! 3. Add the docs row in [`policies/README.md`](../../../policies/README.md).
//! 4. Add a unit test below with positive + negative + boundary cases.
//! 5. Bump `Policy::SCHEMA_VERSION` if the YAML shape adds a top-level field.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{decision::DenyReason, request::PolicyRequest};

/// One row in the policy file's `rules:` list. The `#[serde(tag = "type")]`
/// pattern matches the YAML shape exactly (see `policies/*.yaml`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Rule {
    // ── Resolution rules (Pass 1) ─────────────────────────────────────────
    /// When the request carries `algorithm = None` and `op ∈ ops`, supply
    /// `default_algorithm` as the resolved algorithm.
    ///
    /// **Demo backbone:** the application calls `CreateKeyPair { purpose:
    /// Sign }` with no algorithm in the template. Under a classical policy
    /// this defaults to `ECDSA-P384`; flip the policy and the same call
    /// returns an `ML-DSA-87` key with zero application changes.
    AlgorithmDefault {
        ops: Vec<String>,
        default_algorithm: String,
        reason: String,
    },

    /// When the request carries `algorithm == from` and `op ∈ ops`, rewrite
    /// to `to`. Use for hard-cutover migrations: every Sign request that
    /// arrives asking for `ECDSA-P256` is silently upgraded to `ML-DSA-65`.
    AlgorithmSubstitution {
        ops: Vec<String>,
        from: String,
        to: String,
        reason: String,
    },

    // ── Gating rules (Pass 2) ─────────────────────────────────────────────
    /// `op ∈ ops` AND `algorithm ∉ algorithms` → Deny.
    AlgorithmAllowlist {
        ops: Vec<String>,
        algorithms: Vec<String>,
        reason: String,
        #[serde(default)]
        effective_from: Option<TimeBound>,
        #[serde(default)]
        effective_until: Option<TimeBound>,
    },

    /// `op ∈ ops` AND `algorithm ∈ algorithms` → Deny.
    AlgorithmDenylist {
        ops: Vec<String>,
        algorithms: Vec<String>,
        reason: String,
        #[serde(default)]
        effective_from: Option<TimeBound>,
        #[serde(default)]
        effective_until: Option<TimeBound>,
        /// Skip this rule if request has `x-<name> == value`.
        #[serde(default)]
        exception_custom_attribute: Option<AttrPredicate>,
    },

    /// `algorithm == algorithm` AND `key_length < min_bits` → Deny.
    MinKeyLength {
        algorithm: String,
        min_bits: u32,
        reason: String,
    },

    /// `op ∈ ops` AND `(now - key.activated_at) > days` → Deny.
    /// Phase 4.5 stub — needs Phase 6 object store to expose key timestamps.
    /// Today this rule never fires; engine logs a warning at load.
    MaxKeyAgeDays {
        ops: Vec<String>,
        days: u32,
        reason: String,
    },

    /// Creating `algorithm` without all `flags` set → Deny.
    RequireUsageMask {
        algorithm: String,
        flags: Vec<String>,
        reason: String,
    },

    /// Creating any of `algorithms` without `x-<attribute_name>` set → Deny.
    RequireCustomAttribute {
        attribute_name: String,
        algorithms: Vec<String>,
        reason: String,
    },

    /// `now >= after` AND `op == op` AND request matches the class → Deny.
    /// `algorithm_class` is `"classical"` or `"pqc"`. Optional `algorithms`
    /// narrows to a specific subset.
    TemporalCutoff {
        op: String,
        algorithm_class: String,
        #[serde(default)]
        algorithms: Vec<String>,
        after: TimeBound,
        reason: String,
    },

    /// `op == op` AND `state ∉ allowed_states` → Deny.
    LifecycleStateGate {
        op: String,
        allowed_states: Vec<String>,
        reason: String,
    },

    /// During `effective` range, every `Sign`/`Create` op must use the
    /// composite `primary + secondary` algorithm. Phase 4.5: enforced as a
    /// `require_algorithm_equals` against a synthesised composite name.
    HybridDualSignRequirement {
        primary: String,
        secondary: String,
        effective_from: TimeBound,
        effective_until: TimeBound,
        ops_affected: Vec<String>,
        #[serde(default)]
        composite_oid: Option<String>,
        #[serde(default)]
        triggered_by_custom_attribute: Option<AttrPredicate>,
        reason: String,
    },

    /// Catch-all profile gate (`profile: FIPS-140-3 | CNSA-2.0 | NIS2 | ...`).
    /// Phase 4.5: documented as informational — actual profile enforcement
    /// is composed from the preceding allowlist/denylist rules. The variant
    /// exists so policies stay self-documenting and the Phase 8 compliance
    /// tool can cross-reference profile names back to their composing rules.
    ComplianceProfileGate {
        profile: String,
        ops: Vec<String>,
        reason: String,
    },
}

/// Either the literal string `"always"` or an ISO 8601 date `"YYYY-MM-DD"`.
/// Custom (de)serialize because `time::Date`'s default impl wants a struct
/// shape, not the bare ISO string the policy YAML uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimeBound {
    Always,
    At(time::Date),
}

impl TimeBound {
    /// `true` if `ts` is at-or-after this bound. `Always` matches every `ts`.
    pub fn matches_at_or_after(&self, ts: OffsetDateTime) -> bool {
        match self {
            TimeBound::Always => true,
            TimeBound::At(d) => ts.date() >= *d,
        }
    }

    /// `true` if `ts` is at-or-before this bound. `Always` matches every `ts`.
    pub fn matches_at_or_before(&self, ts: OffsetDateTime) -> bool {
        match self {
            TimeBound::Always => true,
            TimeBound::At(d) => ts.date() <= *d,
        }
    }

    /// Parse `"always"` or `"YYYY-MM-DD"` into a `TimeBound`.
    pub fn parse_str(s: &str) -> Result<Self, String> {
        if s == "always" {
            return Ok(TimeBound::Always);
        }
        // Accept "YYYY-MM-DD" and "YYYY-MM-DDTHH:MM:SSZ" (truncate to date).
        let date_part = s.split('T').next().unwrap_or(s);
        let parts: Vec<&str> = date_part.split('-').collect();
        if parts.len() != 3 {
            return Err(format!("expected YYYY-MM-DD or 'always', got {s:?}"));
        }
        let year: i32 = parts[0].parse().map_err(|e| format!("year: {e}"))?;
        let month_num: u8 = parts[1].parse().map_err(|e| format!("month: {e}"))?;
        let day: u8 = parts[2].parse().map_err(|e| format!("day: {e}"))?;
        let month = time::Month::try_from(month_num).map_err(|e| format!("month: {e}"))?;
        let date = time::Date::from_calendar_date(year, month, day)
            .map_err(|e| format!("date: {e}"))?;
        Ok(TimeBound::At(date))
    }
}

impl serde::Serialize for TimeBound {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            TimeBound::Always => serializer.serialize_str("always"),
            TimeBound::At(d) => {
                let s = format!(
                    "{:04}-{:02}-{:02}",
                    d.year(),
                    u8::from(d.month()),
                    d.day()
                );
                serializer.serialize_str(&s)
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for TimeBound {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        TimeBound::parse_str(&s).map_err(serde::de::Error::custom)
    }
}

/// `{ name: X, value: Y }` predicate against [`PolicyRequest::custom_attrs`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttrPredicate {
    pub name: String,
    pub value: String,
}

impl AttrPredicate {
    /// `true` if `req.custom_attrs[self.name] == self.value`.
    pub fn matches(&self, req: &PolicyRequest) -> bool {
        req.custom_attrs.get(&self.name).is_some_and(|v| v == &self.value)
    }
}

/// Output of a Pass-1 resolution rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Substitution {
    pub new_algorithm: String,
    pub reason: String,
}

/// Output of a Pass-2 gating rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatingDeny {
    pub kmip_reason: DenyReason,
    pub human: String,
}

impl Rule {
    /// Pass 1: try to resolve / substitute the request's algorithm.
    /// Returns `Some(Substitution)` for `AlgorithmDefault` /
    /// `AlgorithmSubstitution` when applicable; `None` for every other
    /// rule type and for non-matching resolution rules.
    pub fn resolve_pass1(
        &self,
        req: &PolicyRequest,
        current_algorithm: Option<&str>,
    ) -> Option<Substitution> {
        match self {
            Rule::AlgorithmDefault {
                ops,
                default_algorithm,
                reason,
            } if current_algorithm.is_none() && ops.iter().any(|o| o == req.op) => {
                Some(Substitution {
                    new_algorithm: default_algorithm.clone(),
                    reason: reason.clone(),
                })
            }
            Rule::AlgorithmSubstitution {
                ops,
                from,
                to,
                reason,
            } if current_algorithm == Some(from.as_str())
                && ops.iter().any(|o| o == req.op) =>
            {
                Some(Substitution {
                    new_algorithm: to.clone(),
                    reason: reason.clone(),
                })
            }
            _ => None,
        }
    }

    /// Pass 2: gating evaluation against the resolved request.
    /// `resolved_algorithm` is what came out of Pass 1.
    pub fn check_pass2(
        &self,
        req: &PolicyRequest,
        resolved_algorithm: Option<&str>,
    ) -> Option<GatingDeny> {
        match self {
            Rule::AlgorithmDefault { .. } | Rule::AlgorithmSubstitution { .. } => None,

            Rule::AlgorithmAllowlist {
                ops,
                algorithms,
                reason,
                effective_from,
                effective_until,
            } => {
                if !window_active(effective_from.as_ref(), effective_until.as_ref(), req.ts) {
                    return None;
                }
                if !ops.iter().any(|o| o == req.op) {
                    return None;
                }
                match resolved_algorithm {
                    None => None, // No algorithm to check yet (e.g. raw Locate)
                    Some(algo) if !algorithms.iter().any(|a| a == algo) => Some(GatingDeny {
                        kmip_reason: DenyReason::PermissionDenied,
                        human: reason.clone(),
                    }),
                    Some(_) => None,
                }
            }

            Rule::AlgorithmDenylist {
                ops,
                algorithms,
                reason,
                effective_from,
                effective_until,
                exception_custom_attribute,
            } => {
                if !window_active(effective_from.as_ref(), effective_until.as_ref(), req.ts) {
                    return None;
                }
                if !ops.iter().any(|o| o == req.op) {
                    return None;
                }
                if let Some(exc) = exception_custom_attribute.as_ref() {
                    if exc.matches(req) {
                        return None;
                    }
                }
                match resolved_algorithm {
                    Some(algo) if algorithms.iter().any(|a| a == algo) => Some(GatingDeny {
                        kmip_reason: DenyReason::PermissionDenied,
                        human: reason.clone(),
                    }),
                    _ => None,
                }
            }

            Rule::MinKeyLength {
                algorithm,
                min_bits,
                reason,
            } => match (resolved_algorithm, req.key_length) {
                (Some(algo), Some(bits)) if algo == algorithm && bits < *min_bits => {
                    Some(GatingDeny {
                        kmip_reason: DenyReason::InvalidCryptographicParameters,
                        human: reason.clone(),
                    })
                }
                _ => None,
            },

            // Stub — needs Phase 6 store to expose activated_at. Never fires
            // in Phase 4.5; documented behavior in loader's warnings.
            Rule::MaxKeyAgeDays { .. } => None,

            Rule::RequireUsageMask {
                algorithm,
                flags,
                reason,
            } => {
                if resolved_algorithm != Some(algorithm.as_str()) {
                    return None;
                }
                let Some(mask) = req.usage_mask else {
                    // Usage mask not supplied — at Create this should fail
                    // closed: the caller didn't declare the required flags.
                    return Some(GatingDeny {
                        kmip_reason: DenyReason::InvalidAttributeValue,
                        human: reason.clone(),
                    });
                };
                if usage_mask_has_all(mask, flags) {
                    None
                } else {
                    Some(GatingDeny {
                        kmip_reason: DenyReason::InvalidAttributeValue,
                        human: reason.clone(),
                    })
                }
            }

            Rule::RequireCustomAttribute {
                attribute_name,
                algorithms,
                reason,
            } => match resolved_algorithm {
                Some(algo)
                    if algorithms.iter().any(|a| a == algo)
                        && !req.custom_attrs.contains_key(attribute_name) =>
                {
                    Some(GatingDeny {
                        kmip_reason: DenyReason::InvalidAttributeValue,
                        human: reason.clone(),
                    })
                }
                _ => None,
            },

            Rule::TemporalCutoff {
                op,
                algorithm_class,
                algorithms,
                after,
                reason,
            } => {
                if req.op != op.as_str() {
                    return None;
                }
                if !after.matches_at_or_after(req.ts) {
                    return None;
                }
                let Some(algo) = resolved_algorithm else { return None; };
                if !algorithms.is_empty() && !algorithms.iter().any(|a| a == algo) {
                    return None;
                }
                if matches_class(algo, algorithm_class) {
                    Some(GatingDeny {
                        kmip_reason: DenyReason::PermissionDenied,
                        human: reason.clone(),
                    })
                } else {
                    None
                }
            }

            Rule::LifecycleStateGate {
                op,
                allowed_states,
                reason,
            } => {
                if req.op != op.as_str() {
                    return None;
                }
                match req.state {
                    Some(s) if !allowed_states.iter().any(|a| a == s) => Some(GatingDeny {
                        kmip_reason: DenyReason::ObjectArchived,
                        human: reason.clone(),
                    }),
                    _ => None,
                }
            }

            Rule::HybridDualSignRequirement {
                primary,
                secondary,
                effective_from,
                effective_until,
                ops_affected,
                triggered_by_custom_attribute,
                reason,
                ..
            } => {
                if !window_active(Some(effective_from), Some(effective_until), req.ts) {
                    return None;
                }
                if !ops_affected.iter().any(|o| o == req.op) {
                    return None;
                }
                if let Some(pred) = triggered_by_custom_attribute.as_ref() {
                    if !pred.matches(req) {
                        return None;
                    }
                }
                let composite = format!("{}-{}", primary, secondary.to_uppercase());
                let composite_alt =
                    format!("{}-{}", primary.to_uppercase(), secondary.to_uppercase());
                match resolved_algorithm {
                    Some(a) if a == composite || a == composite_alt => None,
                    _ => Some(GatingDeny {
                        kmip_reason: DenyReason::PermissionDenied,
                        human: reason.clone(),
                    }),
                }
            }

            // Catch-all profile gate is documentational in Phase 4.5; the
            // composing allowlist/denylist rules carry enforcement. Never
            // denies on its own — compliance tool in Phase 8 reads this
            // variant to map a policy back to its profile name.
            Rule::ComplianceProfileGate { .. } => None,
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

/// `true` if `ts` falls within `[from, until]`. Either bound may be absent.
///
/// Method-naming convention on [`TimeBound`]: `b.matches_at_or_after(ts)`
/// reads as "this bound matches a `ts` that is at-or-after it" — i.e.
/// `ts >= bound`. Window membership therefore is "ts ≥ from AND ts ≤ until".
fn window_active(
    from: Option<&TimeBound>,
    until: Option<&TimeBound>,
    ts: OffsetDateTime,
) -> bool {
    let after_ok = from.map_or(true, |b| b.matches_at_or_after(ts));
    let before_ok = until.map_or(true, |b| b.matches_at_or_before(ts));
    after_ok && before_ok
}

/// `true` if every `flag` is present in `mask`. Unknown flag names are
/// rejected (loader rejects them up-front, but defence in depth).
fn usage_mask_has_all(
    mask: super::super::kmip30::UsageMask,
    flags: &[String],
) -> bool {
    use super::super::kmip30::UsageMask as M;
    for f in flags {
        let bit = match f.as_str() {
            "Sign"               => M::SIGN,
            "Verify"             => M::VERIFY,
            "Encrypt"            => M::ENCRYPT,
            "Decrypt"            => M::DECRYPT,
            "WrapKey"            => M::WRAP_KEY,
            "UnwrapKey"          => M::UNWRAP_KEY,
            "Export"             => M::EXPORT,
            "MacGenerate"        => M::MAC_GENERATE,
            "MacVerify"          => M::MAC_VERIFY,
            "DeriveKey"          => M::DERIVE_KEY,
            "ContentCommitment"  => M::CONTENT_COMMITMENT,
            "KeyAgreement"       => M::KEY_AGREEMENT,
            "CertificateSign"    => M::CERTIFICATE_SIGN,
            "CrlSign"            => M::CRL_SIGN,
            "Authenticate"       => M::AUTHENTICATE,
            _ => return false,
        };
        if !mask.contains(bit) {
            return false;
        }
    }
    true
}

/// Crude algorithm classifier — `"classical"` or `"pqc"`. Conservative:
/// unknown names default to `"classical"` so a `temporal_cutoff` on
/// `classical` denies them by default after the cutoff (safe direction).
fn matches_class(algorithm: &str, class: &str) -> bool {
    let is_pqc = algorithm.starts_with("ML-KEM")
        || algorithm.starts_with("ML-DSA")
        || algorithm.starts_with("SLH-DSA")
        || algorithm.starts_with("HSS")
        || algorithm.starts_with("LMS")
        || algorithm.starts_with("XMSS")
        || algorithm.starts_with("Falcon");
    match class {
        "pqc" => is_pqc,
        "classical" => !is_pqc,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn req<'a>(op: &'a str, algo: Option<&'a str>, attrs: &'a HashMap<String, String>) -> PolicyRequest<'a> {
        PolicyRequest::minimal(op, algo, OffsetDateTime::UNIX_EPOCH, "corr-1", attrs)
    }

    #[test]
    fn allowlist_denies_unknown_algo() {
        let attrs = HashMap::new();
        let r = Rule::AlgorithmAllowlist {
            ops: vec!["Create".into()],
            algorithms: vec!["AES-256".into()],
            reason: "Not in allowlist".into(),
            effective_from: None,
            effective_until: None,
        };
        let deny = r.check_pass2(&req("Create", Some("RSA-2048"), &attrs), Some("RSA-2048"));
        assert!(deny.is_some());
        let allow = r.check_pass2(&req("Create", Some("AES-256"), &attrs), Some("AES-256"));
        assert!(allow.is_none());
    }

    #[test]
    fn denylist_with_exception_attribute() {
        let mut attrs = HashMap::new();
        attrs.insert("pqctoday-purpose".into(), "research".into());
        let r = Rule::AlgorithmDenylist {
            ops: vec!["Create".into()],
            algorithms: vec!["ML-DSA-65".into()],
            reason: "Pure PQC banned in migration window".into(),
            effective_from: None,
            effective_until: None,
            exception_custom_attribute: Some(AttrPredicate {
                name: "pqctoday-purpose".into(),
                value: "research".into(),
            }),
        };
        let allow = r.check_pass2(&req("Create", Some("ML-DSA-65"), &attrs), Some("ML-DSA-65"));
        assert!(allow.is_none(), "exception attribute should suppress deny");

        let empty = HashMap::new();
        let deny = r.check_pass2(&req("Create", Some("ML-DSA-65"), &empty), Some("ML-DSA-65"));
        assert!(deny.is_some());
    }

    #[test]
    fn min_key_length_boundary() {
        let attrs = HashMap::new();
        let r = Rule::MinKeyLength {
            algorithm: "RSA".into(),
            min_bits: 3072,
            reason: "FIPS 186-5".into(),
        };
        let mut req = req("Create", Some("RSA"), &attrs);
        req.key_length = Some(2048);
        assert!(r.check_pass2(&req, Some("RSA")).is_some());
        req.key_length = Some(3072);
        assert!(r.check_pass2(&req, Some("RSA")).is_none());
        req.key_length = Some(4096);
        assert!(r.check_pass2(&req, Some("RSA")).is_none());
    }

    #[test]
    fn algorithm_substitution_pass1() {
        let attrs = HashMap::new();
        let r = Rule::AlgorithmSubstitution {
            ops: vec!["CreateKeyPair".into()],
            from: "ECDSA-P256".into(),
            to: "ML-DSA-65".into(),
            reason: "Upgrade classical to PQC".into(),
        };
        let req = req("CreateKeyPair", Some("ECDSA-P256"), &attrs);
        let sub = r.resolve_pass1(&req, Some("ECDSA-P256")).expect("must substitute");
        assert_eq!(sub.new_algorithm, "ML-DSA-65");
    }

    #[test]
    fn algorithm_default_fires_when_no_algo() {
        let attrs = HashMap::new();
        let r = Rule::AlgorithmDefault {
            ops: vec!["CreateKeyPair".into()],
            default_algorithm: "ML-DSA-87".into(),
            reason: "PQC default for signing".into(),
        };
        let req = req("CreateKeyPair", None, &attrs);
        let sub = r.resolve_pass1(&req, None).expect("must default");
        assert_eq!(sub.new_algorithm, "ML-DSA-87");

        // Already-specified algorithm: default does NOT fire.
        let req2 = req;
        let _req2 = PolicyRequest { algorithm: Some("ECDSA-P256"), ..req2 };
        let no_sub = r.resolve_pass1(&_req2, Some("ECDSA-P256"));
        assert!(no_sub.is_none());
    }

    #[test]
    fn temporal_cutoff_pqc_after_date() {
        let attrs = HashMap::new();
        let r = Rule::TemporalCutoff {
            op: "Create".into(),
            algorithm_class: "classical".into(),
            algorithms: vec![],
            after: TimeBound::At(time::Date::from_calendar_date(2030, time::Month::January, 1).unwrap()),
            reason: "Post-2030 classical banned".into(),
        };
        let ts_pre = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(); // 2023
        let ts_post = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap(); // 2033
        let mut req = req("Create", Some("RSA"), &attrs);
        req.ts = ts_pre;
        assert!(r.check_pass2(&req, Some("RSA")).is_none(), "pre-cutoff allowed");
        req.ts = ts_post;
        assert!(r.check_pass2(&req, Some("RSA")).is_some(), "post-cutoff denied");
        // PQC algorithm doesn't match class=classical → not denied.
        assert!(r.check_pass2(&req, Some("ML-DSA-65")).is_none());
    }

    #[test]
    fn lifecycle_gate_blocks_non_active() {
        let attrs = HashMap::new();
        let r = Rule::LifecycleStateGate {
            op: "Sign".into(),
            allowed_states: vec!["Active".into()],
            reason: "Only Active keys may sign".into(),
        };
        let mut req = req("Sign", Some("ML-DSA-87"), &attrs);
        req.state = Some("Active");
        assert!(r.check_pass2(&req, Some("ML-DSA-87")).is_none());
        req.state = Some("Deactivated");
        assert!(r.check_pass2(&req, Some("ML-DSA-87")).is_some());
    }

    #[test]
    fn hybrid_dual_sign_demands_composite() {
        let attrs = HashMap::new();
        let r = Rule::HybridDualSignRequirement {
            primary: "ML-DSA-65".into(),
            secondary: "Ed25519".into(),
            effective_from: TimeBound::At(time::Date::from_calendar_date(2026, time::Month::January, 1).unwrap()),
            effective_until: TimeBound::At(time::Date::from_calendar_date(2029, time::Month::December, 31).unwrap()),
            ops_affected: vec!["Create".into()],
            composite_oid: None,
            triggered_by_custom_attribute: None,
            reason: "Composite required in migration window".into(),
        };
        let mut req = req("Create", Some("ML-DSA-65"), &attrs);
        req.ts = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(); // 2027
        // Pure ML-DSA-65 inside window → deny (composite required).
        assert!(r.check_pass2(&req, Some("ML-DSA-65")).is_some());
        // Composite name → allow.
        assert!(r.check_pass2(&req, Some("ML-DSA-65-ED25519")).is_none());
    }

    #[test]
    fn require_custom_attribute_at_create() {
        let mut attrs = HashMap::new();
        let r = Rule::RequireCustomAttribute {
            attribute_name: "pqctoday-cnsa-classification".into(),
            algorithms: vec!["ML-DSA-87".into()],
            reason: "CNSA classification required".into(),
        };
        let req1 = req("Create", Some("ML-DSA-87"), &attrs);
        assert!(r.check_pass2(&req1, Some("ML-DSA-87")).is_some());
        attrs.insert("pqctoday-cnsa-classification".into(), "TopSecret".into());
        let req2 = req("Create", Some("ML-DSA-87"), &attrs);
        assert!(r.check_pass2(&req2, Some("ML-DSA-87")).is_none());
    }
}
