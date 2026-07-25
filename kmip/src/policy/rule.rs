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

use super::{decision::CpOverride, decision::DenyReason, request::PolicyRequest};

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
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
        /// Case-insensitive glob (`*` / `?`) the request's key `Name` must
        /// match for this default to fire — the label-only agility contract:
        /// one policy maps key CLASSES (by label) to algorithms, so
        /// `name_pattern: "payments-*"` → AES-128 and the generic rule →
        /// AES-256 can coexist. Within Pass 0, name-patterned defaults are
        /// evaluated BEFORE generic ones (most-specific-wins), so authors
        /// don't have to order the YAML carefully. Absent = matches any name
        /// (including requests with no name).
        #[serde(default)]
        name_pattern: Option<String>,
    },

    /// When the request carries `algorithm == from` and `op ∈ ops`, rewrite
    /// to `to`. Use for hard-cutover migrations: every Sign request that
    /// arrives asking for `ECDSA-P256` is silently upgraded to `ML-DSA-65`.
    AlgorithmSubstitution {
        ops: Vec<String>,
        from: String,
        to: String,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
        /// Case-insensitive glob (`*` / `?`) the request's key `Name` must
        /// match for this substitution to fire — scopes a rekey rule to a
        /// key class (e.g. only `firmware-*` keys move to ML-DSA-44). Absent
        /// = matches any name (including requests with no name).
        #[serde(default)]
        name_pattern: Option<String>,
    },

    // ── Gating rules (Pass 2) ─────────────────────────────────────────────
    /// `op ∈ ops` AND `algorithm ∉ algorithms` → Deny.
    AlgorithmAllowlist {
        ops: Vec<String>,
        algorithms: Vec<String>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
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
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
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
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },

    /// `op ∈ ops` AND `(now - key.activated_at) > days` → Deny.
    /// `check_pass2` genuinely evaluates this against
    /// `PolicyRequest::object_activation_date`, which 5 op handlers
    /// (Decapsulate/Decrypt/Encapsulate/Encrypt/Sign) populate from the
    /// stored object's real Activation Date. Only fires for ops that
    /// target an already-activated key — `Create` and never-activated
    /// objects have no activation date to age out (see the loader's
    /// load-time warning for this rule).
    MaxKeyAgeDays {
        ops: Vec<String>,
        days: u32,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },

    /// Creating `algorithm` without all `flags` set → Deny.
    ///
    /// `ops` scopes the rule; when omitted it defaults to the four
    /// creation/ingress ops (`Create`, `CreateKeyPair`, `Register`, `Import`)
    /// — a mask requirement is a key-provenance gate, and firing it on use
    /// ops re-closed the Decrypt/Verify paths policies deliberately leave
    /// open (2026-07-04 gap audit).
    RequireUsageMask {
        algorithm: String,
        flags: Vec<String>,
        #[serde(default)]
        ops: Vec<String>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },

    /// Creating any of `algorithms` without `x-<attribute_name>` set → Deny.
    ///
    /// `ops` scopes the rule; when omitted it defaults to the four
    /// creation/ingress ops (`Create`, `CreateKeyPair`, `Register`, `Import`).
    /// Un-scoped, this rule denied EVERY op on an untagged key — including
    /// the Decrypt/Verify/Get paths the same policies promise stay open
    /// (2026-07-04 gap audit; the "CNSA 2.0 allows AES-256 but denies
    /// Encrypt/Decrypt" bug).
    RequireCustomAttribute {
        attribute_name: String,
        algorithms: Vec<String>,
        #[serde(default)]
        ops: Vec<String>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
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
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },

    /// `op == op` AND `state ∉ allowed_states` → Deny.
    LifecycleStateGate {
        op: String,
        allowed_states: Vec<String>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
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
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
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
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },

    // ── Mechanism-dimension gating rules (Pass 2) — crypto-policy gaps plan ──
    /// `op ∈ ops` AND the request's `Hashing Algorithm` ∉ `hashing_algorithms`
    /// → Deny. Names are KMIP `Hashing Algorithm` enum names ("SHA-256",
    /// "SHA-384", "SHA-512", "SHA3-256", …). Closes the hashing-agility gap
    /// (G1) on the gating side: e.g. forbid SHA-1, or FIPS-only SHA-2/3. A
    /// request with no hash carried (`mechanism.hashing_algorithm == None`) is
    /// not gated — irrelevant params are not an error (KMIP §11).
    HashAlgorithmAllowlist {
        ops: Vec<String>,
        hashing_algorithms: Vec<String>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
        #[serde(default)]
        effective_from: Option<TimeBound>,
        #[serde(default)]
        effective_until: Option<TimeBound>,
    },

    /// Constrain KMIP `CryptographicParameters` per op (G2/G4). Any *present*
    /// field whose value is not in its allowed set → Deny; an empty/omitted set
    /// leaves that field unconstrained. `algorithm` (optional) narrows the rule
    /// to one algorithm. Names are the KMIP enum names: `Block Cipher Mode`
    /// ("GCM", "CBC", "CCM", …) and `Padding Method` ("OAEP", "PSS", "PKCS1 v1.5",
    /// …). `require_deterministic` gates the WD19 PQC `Deterministic` flag.
    MechanismParameterConstraint {
        ops: Vec<String>,
        #[serde(default)]
        algorithm: Option<String>,
        #[serde(default)]
        allowed_block_cipher_modes: Vec<String>,
        #[serde(default)]
        allowed_padding_methods: Vec<String>,
        #[serde(default)]
        require_deterministic: Option<bool>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },

    /// Gate the MAC mechanism family (G1, MAC side). `op ∈ ops` AND the
    /// resolved algorithm ∉ `mac_algorithms` → Deny. Names are KMIP
    /// CryptographicAlgorithm names ("HMAC-SHA256", "HMAC-SHA384", …). KMAC has
    /// no KMIP codification → gate it via the `CKM_*` dialect (plan P4).
    MacMechanismPolicy {
        ops: Vec<String>,
        mac_algorithms: Vec<String>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },

    // ── Mechanism-dimension FORCING rule (plan P3) ────────────────────────
    /// Force mechanism parameters (the forcing counterpart to
    /// `MechanismParameterConstraint`). When `op ∈ ops` (and the resolved
    /// `algorithm` matches, if set), supply hash / block-cipher mode / padding
    /// / deterministic — the dispatcher merges them into the effective
    /// `CryptographicParameters`, so a policy can *mandate* AES-GCM,
    /// RSA-OAEP-SHA256, or deterministic ML-DSA transparently. Names are the
    /// KMIP enum names (verified maps). Emits a [`super::CpOverride`] from
    /// `resolve_cp`; never denies.
    MechanismParameterDefault {
        ops: Vec<String>,
        #[serde(default)]
        algorithm: Option<String>,
        #[serde(default)]
        hashing_algorithm: Option<String>,
        #[serde(default)]
        block_cipher_mode: Option<String>,
        #[serde(default)]
        padding_method: Option<String>,
        #[serde(default)]
        deterministic: Option<bool>,
        /// F-5 — MGF function name (e.g. `MGF1`) → KMIP `MaskGenerator` codepoint.
        #[serde(default)]
        mask_generator: Option<String>,
        /// F-5 — AEAD auth-tag length, bytes.
        #[serde(default)]
        tag_length: Option<i32>,
        /// F-5 — RSA-PSS salt length, bytes.
        #[serde(default)]
        salt_length: Option<i32>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },

    // ── PKCS#11 CKM_* mechanism dialect (plan P4) — gates the FULL PKCS#11
    // v3.2 mechanism surface, incl. mechanisms with no KMIP codification
    // (KMAC, KDFs). Gates on the request's *canonical* mechanism
    // (`PolicyRequest.mechanism.canonical_mech`, P0/P1), so a rule means the
    // same thing whether the request arrived via a standard KMIP op or the
    // PKCS#11 passthrough (§6.1.44) — bypass-proof by construction. Mechanisms
    // are PKCS#11 `CKM_*` names resolved from pkcs11t.h (via constants.rs). ──
    /// `op ∈ ops` AND the request's canonical `CKM_*` ∉ `mechanisms` → Deny.
    MechanismAllowlist {
        ops: Vec<String>,
        mechanisms: Vec<String>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
    },
    /// `op ∈ ops` AND the request's canonical `CKM_*` ∈ `mechanisms` → Deny.
    MechanismDenylist {
        ops: Vec<String>,
        mechanisms: Vec<String>,
        reason: String,
        /// Which framework clause this rule implements (e.g. "BSI TR-02102-1
        /// §2.1/§5.3"), for the Hub's rule-provenance UI. Purely descriptive —
        /// never read by `check_pass2`/`resolve_pass1`; absent when the
        /// policy author didn't cite one.
        #[serde(default)]
        clause: Option<String>,
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

/// Case-insensitive glob match for rule `name_pattern`s: `*` = any run
/// (including empty), `?` = any single character; everything else literal.
/// A rule WITH a pattern only fires when the request HAS a name that matches
/// — an unnamed request never satisfies a patterned rule.
pub(crate) fn name_pattern_matches(pattern: &str, name: Option<&str>) -> bool {
    let Some(name) = name else { return false };
    fn glob(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => glob(&p[1..], s) || (!s.is_empty() && glob(p, &s[1..])),
            (Some(b'?'), Some(_)) => glob(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => glob(&p[1..], &s[1..]),
            _ => false,
        }
    }
    glob(pattern.as_bytes(), name.as_bytes())
}

impl Rule {
    /// `true` when this is a resolution rule carrying a `name_pattern` — the
    /// engine's Pass 0 evaluates these BEFORE generic (un-patterned) defaults
    /// so the most specific rule wins regardless of YAML order.
    pub fn has_name_pattern(&self) -> bool {
        matches!(
            self,
            Rule::AlgorithmDefault { name_pattern: Some(_), .. }
                | Rule::AlgorithmSubstitution { name_pattern: Some(_), .. }
        )
    }

    /// Pass 0 (F-2): resolve `AlgorithmDefault` — fill the request's algorithm
    /// when the request specified none. The engine runs this BEFORE substitutions
    /// (the caller only invokes it while the algorithm is still unresolved), so a
    /// substitution always operates on the defaulted value regardless of the order
    /// defaults and substitutions appear in the policy. Returns `None` for every
    /// other rule type and for non-matching ops.
    pub fn resolve_default(&self, req: &PolicyRequest) -> Option<Substitution> {
        match self {
            Rule::AlgorithmDefault {
                ops,
                default_algorithm,
                reason,
                name_pattern,
                ..
            } if ops.iter().any(|o| op_matches(o, req.op))
                && name_pattern
                    .as_deref()
                    .is_none_or(|p| name_pattern_matches(p, req.name)) =>
            {
                Some(Substitution {
                    new_algorithm: default_algorithm.clone(),
                    reason: reason.clone(),
                })
            }
            _ => None,
        }
    }

    /// Pass 1: apply `AlgorithmSubstitution` — rewrite `from` → `to` when the
    /// (already default-resolved) algorithm matches `from`. Returns `None` for
    /// every other rule type and for non-matching substitutions.
    ///
    /// Hard-excludes "consumer ops" ([`is_consumer_op`]) regardless of what a
    /// rule's `ops:` list says (2026-07-05, classical-KEM crypto-agility
    /// design review). A consumer op operates on material a peer already
    /// fixed at an earlier point in time (`Decapsulate`'s ciphertext,
    /// `DeriveKey`'s peer public bytes, `Decrypt`'s ciphertext) — there is no
    /// "instead use algorithm X" available once that input already exists,
    /// and worse, letting a substitution match here would flag EVERY
    /// legitimate not-yet-migrated call as needing a rekey it can never
    /// execute, breaking ordinary decryption/decapsulation/derivation the
    /// moment such a rule went active. This must be an engine invariant, not
    /// a policy-authoring guideline — see `kmip/policies/README.md`
    /// "Consumer ops" and `loader.rs`'s matching load-time rejection.
    pub fn resolve_substitution(
        &self,
        req: &PolicyRequest,
        current_algorithm: Option<&str>,
    ) -> Option<Substitution> {
        if is_consumer_op(req.op) {
            return None;
        }
        match self {
            Rule::AlgorithmSubstitution {
                ops,
                from,
                to,
                reason,
                name_pattern,
                ..
            } if current_algorithm.is_some_and(|c| algo_matches(from, c))
                && ops.iter().any(|o| op_matches(o, req.op))
                && name_pattern
                    .as_deref()
                    .is_none_or(|p| name_pattern_matches(p, req.name)) =>
            {
                Some(Substitution {
                    new_algorithm: to.clone(),
                    reason: reason.clone(),
                })
            }
            _ => None,
        }
    }

    /// Pass 1b (plan P3): resolve forced mechanism parameters. Returns the
    /// `CpOverride` this rule mandates for the request, or `None`. Only
    /// `MechanismParameterDefault` produces one; the engine merges across rules
    /// (last-match-wins per field) and attaches the result to `Allow`.
    pub fn resolve_cp(
        &self,
        req: &PolicyRequest,
        resolved_algorithm: Option<&str>,
    ) -> Option<CpOverride> {
        match self {
            Rule::MechanismParameterDefault {
                ops,
                algorithm,
                hashing_algorithm,
                block_cipher_mode,
                padding_method,
                deterministic,
                mask_generator,
                tag_length,
                salt_length,
                ..
            } if ops.iter().any(|o| op_matches(o, req.op))
                && algorithm
                    .as_deref()
                    .map_or(true, |a| resolved_algorithm.is_some_and(|r| algo_matches(a, r))) =>
            {
                Some(CpOverride {
                    hashing_algorithm: hashing_algorithm.as_deref().and_then(hash_name_to_code),
                    block_cipher_mode: block_cipher_mode
                        .as_deref()
                        .and_then(block_cipher_mode_name_to_code),
                    padding_method: padding_method.as_deref().and_then(padding_method_name_to_code),
                    deterministic: *deterministic,
                    mask_generator: mask_generator.as_deref().and_then(mgf_name_to_code),
                    tag_length: *tag_length,
                    salt_length: *salt_length,
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
            Rule::AlgorithmDefault { .. }
            | Rule::AlgorithmSubstitution { .. }
            | Rule::MechanismParameterDefault { .. } => None,

            Rule::AlgorithmAllowlist {
                ops,
                algorithms,
                reason,
                effective_from,
                effective_until,
                ..
            } => {
                if !window_active(effective_from.as_ref(), effective_until.as_ref(), req.ts) {
                    return None;
                }
                if !ops.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                match resolved_algorithm {
                    None => None, // No algorithm to check yet (e.g. raw Locate)
                    Some(algo) if !algorithms.iter().any(|a| algo_matches(a, algo)) => {
                        Some(GatingDeny {
                            kmip_reason: DenyReason::PermissionDenied,
                            human: reason.clone(),
                        })
                    }
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
                ..
            } => {
                if !window_active(effective_from.as_ref(), effective_until.as_ref(), req.ts) {
                    return None;
                }
                if !ops.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                if let Some(exc) = exception_custom_attribute.as_ref() {
                    if exc.matches(req) {
                        return None;
                    }
                }
                match resolved_algorithm {
                    Some(algo) if algorithms.iter().any(|a| algo_matches(a, algo)) => {
                        Some(GatingDeny {
                            kmip_reason: DenyReason::PermissionDenied,
                            human: reason.clone(),
                        })
                    }
                    _ => None,
                }
            }

            Rule::MinKeyLength {
                algorithm,
                min_bits,
                reason,
                ..
            } => match (resolved_algorithm, req.key_length) {
                (Some(algo), Some(bits)) if algo_matches(algorithm, algo) && bits < *min_bits => {
                    Some(GatingDeny {
                        kmip_reason: DenyReason::InvalidCryptographicParameters,
                        human: reason.clone(),
                    })
                }
                _ => None,
            },

            // F-3 — deny when the target key is older than `days`. Fires only
            // when the dispatcher supplied the object's Activation Date (i.e. an
            // op that targets an activated key — Sign/Encrypt/…); an op with no
            // age reference (Create, or a never-activated object) can't be aged
            // out, so it passes.
            Rule::MaxKeyAgeDays { ops, days, reason, .. } => {
                if !ops.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                match req.object_activation_date {
                    Some(activated) if (req.ts - activated).whole_days() > i64::from(*days) => {
                        Some(GatingDeny {
                            kmip_reason: DenyReason::KeyExpired,
                            human: reason.clone(),
                        })
                    }
                    _ => None,
                }
            }

            Rule::RequireUsageMask {
                algorithm,
                flags,
                ops,
                reason,
                ..
            } => {
                if !scoped_op_matches(ops, req.op) {
                    return None;
                }
                if !resolved_algorithm.is_some_and(|a| algo_matches(algorithm, a)) {
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
                ops,
                reason,
                ..
            } => {
                if !scoped_op_matches(ops, req.op) {
                    return None;
                }
                match resolved_algorithm {
                    Some(algo)
                        if algorithms.iter().any(|a| algo_matches(a, algo))
                            && !req.custom_attrs.contains_key(attribute_name) =>
                    {
                        Some(GatingDeny {
                            kmip_reason: DenyReason::InvalidAttributeValue,
                            human: reason.clone(),
                        })
                    }
                    _ => None,
                }
            }

            Rule::TemporalCutoff {
                op,
                algorithm_class,
                algorithms,
                after,
                reason,
                ..
            } => {
                if !op_matches(op, req.op) {
                    return None;
                }
                if !after.matches_at_or_after(req.ts) {
                    return None;
                }
                let Some(algo) = resolved_algorithm else { return None; };
                if !algorithms.is_empty() && !algorithms.iter().any(|a| algo_matches(a, algo)) {
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
                ..
            } => {
                if !op_matches(op, req.op) {
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
                if !ops_affected.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                if let Some(pred) = triggered_by_custom_attribute.as_ref() {
                    if !pred.matches(req) {
                        return None;
                    }
                }
                // A dual-*signature* requirement only judges signature-capable
                // requests. Symmetric key creation (AES, ChaCha20, HMAC) in the
                // migration window must pass — otherwise a hybrid-window policy
                // silently bricks all AES Create (Y7/Y12). A request with no
                // resolved algorithm yet (e.g. bare Locate) likewise can't be a
                // composite signature and is left to other rules.
                match resolved_algorithm {
                    None => return None,
                    Some(a) if matches_class(a, "symmetric") => return None,
                    Some(_) => {}
                }
                // Composite name follows the KMIP 3.0 `CryptographicAlgorithm`
                // spelling — component names keep their spec casing (`Ed25519`,
                // per OASIS KMIP 3.0 §11 / RFC 8032; NOT `ED25519`). Match
                // case-insensitively so a request that spells the composite with
                // any casing still satisfies the mandate.
                let composite = format!("{}-{}", primary, secondary);
                match resolved_algorithm {
                    Some(a) if a.eq_ignore_ascii_case(&composite) => None,
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

            // ── Mechanism-dimension gating (crypto-policy gaps plan, P2) ──
            Rule::HashAlgorithmAllowlist {
                ops,
                hashing_algorithms,
                reason,
                effective_from,
                effective_until,
                ..
            } => {
                if !window_active(effective_from.as_ref(), effective_until.as_ref(), req.ts) {
                    return None;
                }
                if !ops.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                match req.mechanism.hashing_algorithm {
                    // No hash carried on this request → nothing to gate.
                    None => None,
                    Some(code)
                        if !hashing_algorithms
                            .iter()
                            .any(|n| hash_name_to_code(n) == Some(code)) =>
                    {
                        Some(GatingDeny {
                            kmip_reason: DenyReason::PermissionDenied,
                            human: reason.clone(),
                        })
                    }
                    Some(_) => None,
                }
            }

            Rule::MechanismParameterConstraint {
                ops,
                algorithm,
                allowed_block_cipher_modes,
                allowed_padding_methods,
                require_deterministic,
                reason,
                ..
            } => {
                if !ops.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                if let Some(a) = algorithm {
                    if !resolved_algorithm.is_some_and(|r| algo_matches(a, r)) {
                        return None;
                    }
                }
                let deny = || {
                    Some(GatingDeny {
                        kmip_reason: DenyReason::InvalidCryptographicParameters,
                        human: reason.clone(),
                    })
                };
                // A present field whose value isn't in its (non-empty) allowed
                // set → Deny. Empty set = unconstrained for that field.
                if !allowed_block_cipher_modes.is_empty() {
                    if let Some(mode) = req.mechanism.block_cipher_mode {
                        if !allowed_block_cipher_modes
                            .iter()
                            .any(|n| block_cipher_mode_name_to_code(n) == Some(mode))
                        {
                            return deny();
                        }
                    }
                }
                if !allowed_padding_methods.is_empty() {
                    if let Some(pad) = req.mechanism.padding_method {
                        if !allowed_padding_methods
                            .iter()
                            .any(|n| padding_method_name_to_code(n) == Some(pad))
                        {
                            return deny();
                        }
                    }
                }
                // require_deterministic = Some(true): the request's PQC
                // Deterministic flag MUST equal it (fail-closed if absent).
                if let Some(want) = require_deterministic {
                    if req.mechanism.deterministic != Some(*want) {
                        return deny();
                    }
                }
                None
            }

            Rule::MacMechanismPolicy {
                ops,
                mac_algorithms,
                reason,
                ..
            } => {
                if !ops.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                match resolved_algorithm {
                    None => None,
                    Some(algo) if !mac_algorithms.iter().any(|a| algo_matches(a, algo)) => {
                        Some(GatingDeny {
                            kmip_reason: DenyReason::PermissionDenied,
                            human: reason.clone(),
                        })
                    }
                    Some(_) => None,
                }
            }

            Rule::MechanismAllowlist {
                ops,
                mechanisms,
                reason,
                ..
            } => {
                if !ops.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                match req.mechanism.canonical_mech {
                    // Not canonicalizable (no mechanism resolved) → not gated.
                    None => None,
                    Some(code) if !mechanism_list_matches(mechanisms, code) => {
                        Some(GatingDeny {
                            kmip_reason: DenyReason::PermissionDenied,
                            human: reason.clone(),
                        })
                    }
                    Some(_) => None,
                }
            }

            Rule::MechanismDenylist {
                ops,
                mechanisms,
                reason,
                ..
            } => {
                if !ops.iter().any(|o| op_matches(o, req.op)) {
                    return None;
                }
                match req.mechanism.canonical_mech {
                    Some(code) if mechanism_list_matches(mechanisms, code) => {
                        Some(GatingDeny {
                            kmip_reason: DenyReason::PermissionDenied,
                            human: reason.clone(),
                        })
                    }
                    _ => None,
                }
            }
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

/// Ops a `require_usage_mask` / `require_custom_attribute` rule gates when the
/// policy author writes no `ops:` — the creation/ingress surface, where a key's
/// provenance metadata is established. `CreateKeyPair` prefix-matches every
/// `CreateKeyPair:<purpose>` refinement via [`op_matches`].
pub const DEFAULT_PROVENANCE_OPS: &[&str] = &["Create", "CreateKeyPair", "Register", "Import"];

/// Match a rule's optional `ops` scope: an explicit list gates exactly those
/// ops; an empty (omitted) list falls back to [`DEFAULT_PROVENANCE_OPS`].
fn scoped_op_matches(ops: &[String], req_op: &str) -> bool {
    if ops.is_empty() {
        DEFAULT_PROVENANCE_OPS.iter().any(|o| op_matches(o, req_op))
    } else {
        ops.iter().any(|o| op_matches(o, req_op))
    }
}

/// Match a policy rule's `op`/`ops` entry against a request's canonical op.
///
/// The dispatcher canonicalises `CreateKeyPair` into `CreateKeyPair:<purpose>`
/// (`CreateKeyPair:Sign` / `:Encrypt` / `:KeyAgreement`) so a policy can
/// discriminate KEM vs signing intent (see `dispatcher::canonical_create_key_pair_op`).
/// A policy that gates the bare family name `CreateKeyPair` must therefore match
/// every `CreateKeyPair:*` request — but `Create` (symmetric) must NOT be caught
/// by a `CreateKeyPair` gate, nor vice-versa.
///
/// Rules (Y2):
/// - exact string match → true (`CreateKeyPair:Sign` gate matches only that purpose);
/// - the request op is a colon-suffixed refinement of the rule op → true
///   (`CreateKeyPair` gate matches `CreateKeyPair:Sign`);
/// - otherwise false. `Create` never matches `CreateKeyPair:Sign` because
///   `"CreateKeyPair:Sign".strip_prefix("Create")` = `"KeyPair:Sign"`, which does
///   not begin with `':'`.
pub fn op_matches(rule_op: &str, req_op: &str) -> bool {
    rule_op == req_op
        || req_op
            .strip_prefix(rule_op)
            .is_some_and(|rest| rest.starts_with(':'))
}

/// "Consumer ops" (2026-07-05 design review, classical-KEM crypto-agility):
/// operations whose input was already fixed to a specific algorithm by an
/// earlier, possibly-much-earlier, possibly-different-party call —
/// `Decapsulate`'s ciphertext (fixed by a peer's `Encapsulate`), `DeriveKey`'s
/// peer public bytes (opaque, caller-supplied), `Decrypt`'s ciphertext (fixed
/// by an earlier `Encrypt`). Contrast "originator ops" (`Sign`, `Encapsulate`,
/// `Encrypt`, `Create`/`CreateKeyPair`) which produce fresh output each call
/// and so can coherently support `algorithm_substitution`. See
/// `resolve_substitution`'s doc comment for why this exclusion is a hard
/// engine invariant, not a policy-authoring convention.
pub fn is_consumer_op(op: &str) -> bool {
    matches!(op, "Decapsulate" | "DeriveKey" | "Decrypt")
}

/// Match a policy `algorithms` entry against a request's (qualified) algorithm.
///
/// Policies mix *family* names (`AES`, `RSA`, `ECDSA`, `ECDH`) and *qualified*
/// names (`AES-256`, `RSA-3072`, `ECDSA-P384`, `ML-DSA-87`). The dispatcher now
/// qualifies every request algorithm (Y3, `helpers::qualify_algorithm_str`), so
/// the request side is always specific; only the policy entry may be a family.
///
/// An entry *covers* a request when (Y3):
/// - it equals the request exactly (`AES-256` covers `AES-256`), or
/// - it is a family prefix and the request is a hyphen-suffixed member
///   (`AES` covers `AES-256`; `ECDSA` covers `ECDSA-P256`).
///
/// It does NOT match in the reverse direction: `AES-256` never covers a bare
/// `AES`, and `AES-128` never covers `AES-256`. Using the same predicate for
/// allowlists and denylists therefore gives the intuitive result in both:
/// denylisting `AES-128` leaves `AES-256` allowed; allowlisting the family
/// `AES` admits every AES size; denylisting the family `SLH-DSA` catches every
/// parameter set.
///
/// Case-insensitive (CACP A-grade review, 2026-07-03): algorithm names have no
/// case-significant vocabulary — nothing in this codebase distinguishes two
/// algorithms by case alone — but a policy author and a request builder
/// disagreeing on casing (e.g. a YAML rule's `ML-DSA-65-Ed25519` vs a caller's
/// `ML-DSA-65-ED25519`) used to make this comparison silently return `false`.
/// For a *gating* rule (`RequireUsageMask`, `AlgorithmDenylist`, …) that is a
/// fail-OPEN bug — the rule the author wrote simply never fires — not a
/// merely-cosmetic mismatch, so this normalizes case rather than requiring
/// exact-byte agreement.
pub fn algo_matches(policy_entry: &str, request_algo: &str) -> bool {
    if policy_entry.eq_ignore_ascii_case(request_algo) {
        return true;
    }
    // Family prefix: every algorithm name in this vocabulary is ASCII, so byte
    // indexing is safe and case-folding per byte is correct (no multi-byte /
    // Unicode-casing pitfalls to worry about).
    request_algo.len() > policy_entry.len()
        && request_algo.is_char_boundary(policy_entry.len())
        && request_algo[..policy_entry.len()].eq_ignore_ascii_case(policy_entry)
        && request_algo.as_bytes()[policy_entry.len()] == b'-'
}

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

/// KMIP `Hashing Algorithm` name → enum codepoint. Values verified against
/// `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (§11). Unknown → `None`
/// (the loader rejects unknown names up-front; this is defence in depth).
pub fn hash_name_to_code(name: &str) -> Option<u32> {
    Some(match name {
        "SHA-1" => 0x04,
        "SHA-224" => 0x05,
        "SHA-256" => 0x06,
        "SHA-384" => 0x07,
        "SHA-512" => 0x08,
        "SHA-512/224" => 0x0c,
        "SHA-512/256" => 0x0d,
        "SHA3-224" => 0x0e,
        "SHA3-256" => 0x0f,
        "SHA3-384" => 0x10,
        "SHA3-512" => 0x11,
        _ => return None,
    })
}

/// KMIP `Block Cipher Mode` name → enum codepoint (spec §11, verified).
pub fn block_cipher_mode_name_to_code(name: &str) -> Option<u32> {
    Some(match name {
        "CBC" => 0x01,
        "ECB" => 0x02,
        "CFB" => 0x04,
        "OFB" => 0x05,
        "CTR" => 0x06,
        "CMAC" => 0x07,
        "CCM" => 0x08,
        "GCM" => 0x09,
        "XTS" => 0x0b,
        _ => return None,
    })
}

/// F-5 — KMIP `Mask Generator` (MGF) name → enum codepoint (spec §11). Only MGF1
/// is defined in KMIP 3.0.
fn mgf_name_to_code(name: &str) -> Option<u32> {
    match name.to_ascii_uppercase().as_str() {
        "MGF1" => Some(0x01),
        _ => None,
    }
}

/// KMIP `Padding Method` name → enum codepoint (spec §11, verified).
pub fn padding_method_name_to_code(name: &str) -> Option<u32> {
    Some(match name {
        "None" => 0x01,
        "OAEP" => 0x02,
        "PKCS5" => 0x03,
        "PKCS1 v1.5" => 0x08,
        "X9.31" => 0x09,
        "PSS" => 0x0a,
        _ => return None,
    })
}

/// PKCS#11 `CKM_*` mechanism name → codepoint. Values come from
/// `softhsmrustv3::constants` (the in-repo mirror of `src/lib/pkcs11/pkcs11t.h`,
/// the source of truth per CLAUDE.md) — never hardcoded here. Curated to the
/// mechanisms relevant to policy gating: AES modes, RSA/ECDSA sign variants,
/// PQC, HMAC/KMAC, KDFs. Unknown → `None` (loader rejects unknown up-front).
/// NOTE: `CKM_KMAC_*` use the vendor-defined codepoint (`CKM_VENDOR_DEFINED |
/// 0x100`). Verified: KMIP/PKCS#11 v3.2 does NOT standardize KMAC (absent from
/// the canonical OASIS v3.2 `pkcs11t.h`), so vendor-defined is correct, and it
/// is consistent across `src/lib/pkcs11/pkcs11t.h` + `rust/src/constants.rs`.
pub fn ckm_name_to_code(name: &str) -> Option<u32> {
    use softhsmrustv3::constants as c;
    Some(match name {
        // Key-pair / key generation mechanisms (Y14 — these were missing, so a
        // lockdown allowlisting them contributed nothing).
        "CKM_ML_DSA_KEY_PAIR_GEN" => c::CKM_ML_DSA_KEY_PAIR_GEN,
        "CKM_ML_KEM_KEY_PAIR_GEN" => c::CKM_ML_KEM_KEY_PAIR_GEN,
        "CKM_SLH_DSA_KEY_PAIR_GEN" => c::CKM_SLH_DSA_KEY_PAIR_GEN,
        "CKM_EC_KEY_PAIR_GEN" => c::CKM_EC_KEY_PAIR_GEN,
        "CKM_AES_KEY_GEN" => c::CKM_AES_KEY_GEN,
        "CKM_RSA_PKCS_PSS" => c::CKM_RSA_PKCS_PSS,
        "CKM_RSA_PKCS" => c::CKM_RSA_PKCS,
        "CKM_AES_ECB" => c::CKM_AES_ECB,
        "CKM_AES_CBC" => c::CKM_AES_CBC,
        "CKM_AES_CBC_PAD" => c::CKM_AES_CBC_PAD,
        "CKM_AES_CTR" => c::CKM_AES_CTR,
        "CKM_AES_GCM" => c::CKM_AES_GCM,
        "CKM_RSA_PKCS_OAEP" => c::CKM_RSA_PKCS_OAEP,
        "CKM_SHA256_RSA_PKCS" => c::CKM_SHA256_RSA_PKCS,
        "CKM_SHA384_RSA_PKCS" => c::CKM_SHA384_RSA_PKCS,
        "CKM_SHA512_RSA_PKCS" => c::CKM_SHA512_RSA_PKCS,
        "CKM_SHA256_RSA_PKCS_PSS" => c::CKM_SHA256_RSA_PKCS_PSS,
        "CKM_SHA384_RSA_PKCS_PSS" => c::CKM_SHA384_RSA_PKCS_PSS,
        "CKM_SHA512_RSA_PKCS_PSS" => c::CKM_SHA512_RSA_PKCS_PSS,
        "CKM_ECDSA" => c::CKM_ECDSA,
        "CKM_ECDSA_SHA256" => c::CKM_ECDSA_SHA256,
        "CKM_ECDSA_SHA384" => c::CKM_ECDSA_SHA384,
        "CKM_ECDSA_SHA512" => c::CKM_ECDSA_SHA512,
        "CKM_ML_DSA" => c::CKM_ML_DSA,
        "CKM_ML_KEM" => c::CKM_ML_KEM,
        "CKM_SLH_DSA" => c::CKM_SLH_DSA,
        "CKM_SHA256_HMAC" => c::CKM_SHA256_HMAC,
        "CKM_SHA384_HMAC" => c::CKM_SHA384_HMAC,
        "CKM_SHA512_HMAC" => c::CKM_SHA512_HMAC,
        "CKM_KMAC_128" => c::CKM_KMAC_128,
        "CKM_KMAC_256" => c::CKM_KMAC_256,
        // W2.3 — broaden toward the full PKCS#11 v3.2 surface the engine
        // supports. Hashes:
        "CKM_SHA256" => c::CKM_SHA256,
        "CKM_SHA384" => c::CKM_SHA384,
        "CKM_SHA512" => c::CKM_SHA512,
        "CKM_SHA3_256" => c::CKM_SHA3_256,
        "CKM_SHA3_512" => c::CKM_SHA3_512,
        "CKM_SHA3_256_HMAC" => c::CKM_SHA3_256_HMAC,
        "CKM_SHA3_512_HMAC" => c::CKM_SHA3_512_HMAC,
        // ECDSA pre-hash SHA-3 variants + EdDSA (pure / pre-hash):
        "CKM_ECDSA_SHA3_224" => c::CKM_ECDSA_SHA3_224,
        "CKM_ECDSA_SHA3_256" => c::CKM_ECDSA_SHA3_256,
        "CKM_ECDSA_SHA3_384" => c::CKM_ECDSA_SHA3_384,
        "CKM_ECDSA_SHA3_512" => c::CKM_ECDSA_SHA3_512,
        "CKM_EDDSA" => c::CKM_EDDSA,
        "CKM_EDDSA_PH" => c::CKM_EDDSA_PH,
        // ChaCha20 family + AES key-wrap modes:
        "CKM_CHACHA20" => c::CKM_CHACHA20,
        "CKM_CHACHA20_POLY1305" => c::CKM_CHACHA20_POLY1305,
        "CKM_AES_KEY_WRAP" => c::CKM_AES_KEY_WRAP,
        "CKM_AES_KEY_WRAP_PAD" => c::CKM_AES_KEY_WRAP_PAD,
        "CKM_AES_KEY_WRAP_KWP" => c::CKM_AES_KEY_WRAP_KWP,
        // KDFs:
        "CKM_HKDF_DERIVE" => c::CKM_HKDF_DERIVE,
        "CKM_PKCS5_PBKD2" => c::CKM_PKCS5_PBKD2,
        "CKM_SP800_108_COUNTER_KDF" => c::CKM_SP800_108_COUNTER_KDF,
        "CKM_SP800_108_FEEDBACK_KDF" => c::CKM_SP800_108_FEEDBACK_KDF,
        _ => return None,
    })
}

/// Map a hash-qualified signing mechanism to its base mechanism *family* (Y14).
///
/// A Sign request canonicalises to a hash-qualified mechanism — e.g. RSA-PSS
/// over SHA-256 resolves to `CKM_SHA256_RSA_PKCS_PSS`, ECDSA over SHA-256 to
/// `CKM_ECDSA_SHA256`. A lockdown policy naturally allowlists the *family*
/// (`CKM_RSA_PKCS_PSS`, `CKM_ECDSA`), so without this mapping the specific
/// canonical mechanism was never on the list and legitimate RSA-PSS / ECDSA
/// signing was falsely denied. `mechanism_list_matches` treats a request as
/// matching a policy entry when the entry is either the exact mechanism or the
/// request's family. Returns `None` for a mechanism that is already a base
/// family (or has no family notion).
fn ckm_family(code: u32) -> Option<u32> {
    use softhsmrustv3::constants as c;
    Some(match code {
        x if x == c::CKM_SHA256_RSA_PKCS_PSS
            || x == c::CKM_SHA384_RSA_PKCS_PSS
            || x == c::CKM_SHA512_RSA_PKCS_PSS =>
        {
            c::CKM_RSA_PKCS_PSS
        }
        x if x == c::CKM_SHA256_RSA_PKCS
            || x == c::CKM_SHA384_RSA_PKCS
            || x == c::CKM_SHA512_RSA_PKCS =>
        {
            c::CKM_RSA_PKCS
        }
        x if x == c::CKM_ECDSA_SHA256
            || x == c::CKM_ECDSA_SHA384
            || x == c::CKM_ECDSA_SHA512 =>
        {
            c::CKM_ECDSA
        }
        _ => return None,
    })
}

// ── Value-lint predicates (WP2.1 / Y6) ───────────────────────────────────────
// These expose the engine's bounded vocabularies so the loader can reject a
// policy that references a name the engine will never match (a silent no-op —
// fail-open for denylists). Algorithm names are validated separately (see
// `lint::is_known_algorithm_name`) because a denylist may legitimately name a
// real-but-unimplemented algorithm.

/// `true` if `name` resolves to a PKCS#11 `CKM_*` the engine knows (Y6).
pub fn is_known_ckm_name(name: &str) -> bool {
    ckm_name_to_code(name).is_some()
}

/// `true` if `name` is a KMIP Hashing Algorithm the engine knows (Y6).
pub fn is_known_hash_name(name: &str) -> bool {
    hash_name_to_code(name).is_some()
}

/// `true` if `name` is a KMIP Block Cipher Mode the engine knows (Y6).
pub fn is_known_block_cipher_mode(name: &str) -> bool {
    block_cipher_mode_name_to_code(name).is_some()
}

/// `true` if `name` is a KMIP Padding Method the engine knows (Y6).
pub fn is_known_padding_method(name: &str) -> bool {
    padding_method_name_to_code(name).is_some()
}

/// `true` if `name` is a Mask Generator the engine knows (Y6).
pub fn is_known_mask_generator(name: &str) -> bool {
    mgf_name_to_code(name).is_some()
}

/// `true` if `class` is one of the three classifier classes (Y4/Y6).
pub fn is_known_algorithm_class(class: &str) -> bool {
    matches!(class, "pqc" | "symmetric" | "classical")
}

/// `true` if `flag` is a KMIP Cryptographic Usage Mask flag name (Y6).
/// Mirrors the names accepted by `usage_mask_has_all`.
pub fn is_known_usage_flag(flag: &str) -> bool {
    matches!(
        flag,
        "Sign" | "Verify" | "Encrypt" | "Decrypt" | "WrapKey" | "UnwrapKey"
            | "Export" | "MacGenerate" | "MacVerify" | "DeriveKey"
            | "ContentCommitment" | "KeyAgreement" | "CertificateSign"
            | "CrlSign" | "Authenticate"
    )
}

/// `true` if the request's canonical mechanism `code` matches any policy
/// mechanism name in `names` — exactly, or via [`ckm_family`] (Y14). Unknown
/// names in `names` contribute nothing (the Phase-2 loader lint rejects them).
fn mechanism_list_matches(names: &[String], code: u32) -> bool {
    names
        .iter()
        .filter_map(|n| ckm_name_to_code(n))
        .any(|entry| entry == code || ckm_family(code) == Some(entry))
}

/// Policy-grammar usage-flag name → `UsageMask` bit. The single source of
/// truth for flag naming, shared by `require_usage_mask` gating and the WASM
/// dry-run facade (WP4b) so a UI-supplied flag list resolves exactly like a
/// policy's `flags:` list. Unknown → `None`.
pub fn usage_flag_name_to_bit(name: &str) -> Option<super::super::kmip30::UsageMask> {
    use super::super::kmip30::UsageMask as M;
    Some(match name {
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
        _ => return None,
    })
}

/// `true` if every `flag` is present in `mask`. Unknown flag names are
/// rejected (loader rejects them up-front, but defence in depth).
fn usage_mask_has_all(
    mask: super::super::kmip30::UsageMask,
    flags: &[String],
) -> bool {
    for f in flags {
        let Some(bit) = usage_flag_name_to_bit(f) else {
            return false;
        };
        if !mask.contains(bit) {
            return false;
        }
    }
    true
}

/// Algorithm classifier over three disjoint classes: `"pqc"`, `"symmetric"`,
/// and `"classical"` (Y4).
///
/// The distinction matters for `temporal_cutoff`: a migration deadline that
/// bans `classical` public-key crypto after Q-day must NOT sweep up AES or
/// HMAC — symmetric primitives are quantum-safe (Grover only halves the
/// effective key strength, covered by moving to 256-bit keys) and IR 8547
/// scopes the deprecation to quantum-vulnerable *public-key* algorithms.
/// Before this fix `matches_class` treated everything non-PQC as classical,
/// so `pqc-migration-2030` silently banned AES-256 encryption from 2030.
///
/// - `pqc`       — ML-KEM / ML-DSA / SLH-DSA / LMS / HSS / XMSS / Falcon / HQC /
///                 BIKE / FrodoKEM / Classic-McEliece and composite PQC names.
/// - `symmetric` — AES / ChaCha20 / HMAC / KMAC / SHA (quantum-safe primitives).
/// - `classical` — quantum-vulnerable public-key: RSA / ECDSA / ECDH / DSA /
///                 DH / Ed25519 / Ed448 / X25519 / X448 (the deprecation target).
///
/// Unknown names fall into `classical` — the safe direction for a cutoff (a
/// name the engine can't place is treated as legacy and denied after Q-day).
fn matches_class(algorithm: &str, class: &str) -> bool {
    let is_pqc = algorithm.starts_with("ML-KEM")
        || algorithm.starts_with("ML-DSA")
        || algorithm.starts_with("SLH-DSA")
        || algorithm.starts_with("HSS")
        || algorithm.starts_with("LMS")
        || algorithm.starts_with("XMSS")
        || algorithm.starts_with("Falcon")
        || algorithm.starts_with("HQC")
        || algorithm.starts_with("BIKE")
        || algorithm.starts_with("FrodoKEM")
        || algorithm.starts_with("Classic-McEliece")
        // composite PQC names carry a PQC primary, e.g. ML-DSA-65-ED25519
        || algorithm.contains("ML-DSA")
        || algorithm.contains("ML-KEM")
        // hybrid KEMs spell the component without a hyphen (KMIP 3.0 WD19:
        // X25519MLKEM768, SecP256r1MLKEM768) — they carry a PQC component and
        // must not fall through to "classical" (2026-07-04 gap audit).
        || algorithm.contains("MLKEM");
    let is_symmetric = algorithm.starts_with("AES")
        || algorithm.starts_with("ChaCha20")
        || algorithm.starts_with("HMAC")
        || algorithm.starts_with("KMAC")
        || algorithm.starts_with("SHA");
    match class {
        "pqc" => is_pqc,
        "symmetric" => is_symmetric && !is_pqc,
        // classical = quantum-vulnerable public-key = not PQC and not symmetric.
        "classical" => !is_pqc && !is_symmetric,
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

    // ── Y2: op_matches — CreateKeyPair:<purpose> vs family names ──────────
    #[test]
    fn op_matches_truth_table() {
        // Exact matches.
        assert!(op_matches("Sign", "Sign"));
        assert!(op_matches("CreateKeyPair:Sign", "CreateKeyPair:Sign"));
        // Family gate matches every colon-suffixed purpose.
        assert!(op_matches("CreateKeyPair", "CreateKeyPair:Sign"));
        assert!(op_matches("CreateKeyPair", "CreateKeyPair:Encrypt"));
        assert!(op_matches("CreateKeyPair", "CreateKeyPair:KeyAgreement"));
        // A specific purpose gate does NOT match a different purpose.
        assert!(!op_matches("CreateKeyPair:Sign", "CreateKeyPair:Encrypt"));
        // `Create` (symmetric) must NOT be caught by CreateKeyPair traffic,
        // and vice-versa — the fail-open bug this whole change closes (Y2).
        assert!(!op_matches("Create", "CreateKeyPair:Sign"));
        assert!(!op_matches("CreateKeyPair", "Create"));
        assert!(!op_matches("Sign", "SignatureVerify"));
    }

    // ── Y3: algo_matches — family entries cover qualified requests ────────
    #[test]
    fn algo_matches_truth_table() {
        // Exact.
        assert!(algo_matches("AES-256", "AES-256"));
        assert!(algo_matches("ML-DSA-87", "ML-DSA-87"));
        // Family entry covers a qualified member (allowlist family / denylist family).
        assert!(algo_matches("AES", "AES-256"));
        assert!(algo_matches("AES", "AES-128"));
        assert!(algo_matches("ECDSA", "ECDSA-P256"));
        assert!(algo_matches("RSA", "RSA-3072"));
        assert!(algo_matches("SLH-DSA", "SLH-DSA-SHAKE-128f"));
        // A specific entry does NOT cover a different size — denylisting
        // AES-128 leaves AES-256 allowed.
        assert!(!algo_matches("AES-128", "AES-256"));
        // Never matches the reverse direction (a bare request under a
        // specific entry) — requests are always qualified post-Y3, so this
        // just documents the guarantee.
        assert!(!algo_matches("AES-256", "AES"));
        // Prefix that isn't a hyphen boundary must not match.
        assert!(!algo_matches("AES", "AESX"));
        // Exact family-name request matches its own family entry.
        assert!(algo_matches("LMS", "LMS"));
        // CACP A-grade review (2026-07-03): case-insensitive, both directions —
        // a policy author writing `Ed25519` must still gate a request that
        // arrives as `ED25519` (or `ed25519`). This used to silently return
        // false, making `RequireUsageMask`/denylist rules fail OPEN on a pure
        // casing mismatch — the exact bug behind the composite-Sign gap the
        // hub's engine-parity suite caught (hybrid-migration-window.yaml).
        assert!(algo_matches("ML-DSA-65-Ed25519", "ML-DSA-65-ED25519"));
        assert!(algo_matches("ML-DSA-65-ED25519", "ML-DSA-65-Ed25519"));
        assert!(algo_matches("aes", "AES-256"), "case-insensitive family prefix");
        // Still respects the hyphen-boundary rule under case-folding.
        assert!(!algo_matches("aes", "AESX"));
    }

    // ── Y4: three-way classifier (symmetric ≠ classical) ──────────────────
    #[test]
    fn matches_class_three_way() {
        // Symmetric primitives are their own class — NOT classical.
        assert!(matches_class("AES-256", "symmetric"));
        assert!(matches_class("HMAC-SHA-256", "symmetric"));
        assert!(matches_class("ChaCha20-Poly1305", "symmetric"));
        assert!(!matches_class("AES-256", "classical"));
        assert!(!matches_class("AES-256", "pqc"));
        // Classical = quantum-vulnerable public-key.
        assert!(matches_class("RSA-3072", "classical"));
        assert!(matches_class("ECDSA-P256", "classical"));
        assert!(matches_class("Ed25519", "classical"));
        assert!(!matches_class("RSA-3072", "symmetric"));
        // PQC.
        assert!(matches_class("ML-DSA-87", "pqc"));
        assert!(matches_class("ML-KEM-1024", "pqc"));
        assert!(!matches_class("ML-DSA-87", "classical"));
        // Composite PQC name classifies as pqc, not classical.
        assert!(matches_class("ML-DSA-65-ED25519", "pqc"));
        assert!(!matches_class("ML-DSA-65-ED25519", "classical"));
        // Unknown → classical (safe cutoff direction).
        assert!(matches_class("MysteryAlg", "classical"));
    }

    // ── P2: mechanism-dimension gating rules ──────────────────────────────
    #[test]
    fn hash_allowlist_denies_disallowed_hash() {
        let attrs = HashMap::new();
        let rule = Rule::HashAlgorithmAllowlist {
            ops: vec!["Sign".into()],
            hashing_algorithms: vec!["SHA-256".into(), "SHA-384".into()],
            reason: "approved hashes only".into(),
            effective_from: None,
            effective_until: None,
            clause: None,
        };
        // SHA-1 (0x04) → deny.
        let mut r = req("Sign", Some("RSA"), &attrs);
        r.mechanism.hashing_algorithm = Some(0x04);
        assert!(rule.check_pass2(&r, Some("RSA")).is_some());
        // SHA-256 (0x06) → allow.
        let mut r2 = req("Sign", Some("RSA"), &attrs);
        r2.mechanism.hashing_algorithm = Some(0x06);
        assert!(rule.check_pass2(&r2, Some("RSA")).is_none());
        // No hash carried → not gated (irrelevant param).
        assert!(rule.check_pass2(&req("Sign", Some("RSA"), &attrs), Some("RSA")).is_none());
        // Different op → not gated.
        let mut r4 = req("Encrypt", Some("RSA"), &attrs);
        r4.mechanism.hashing_algorithm = Some(0x04);
        assert!(rule.check_pass2(&r4, Some("RSA")).is_none());
    }

    #[test]
    fn mechanism_param_constraint_modes_and_padding() {
        let attrs = HashMap::new();
        let rule = Rule::MechanismParameterConstraint {
            ops: vec!["Encrypt".into()],
            algorithm: Some("AES".into()),
            allowed_block_cipher_modes: vec!["GCM".into(), "CCM".into()],
            allowed_padding_methods: vec![],
            require_deterministic: None,
            reason: "AEAD only".into(),
            clause: None,
        };
        // CBC (0x01) → deny.
        let mut r = req("Encrypt", Some("AES"), &attrs);
        r.mechanism.block_cipher_mode = Some(0x01);
        assert!(rule.check_pass2(&r, Some("AES")).is_some());
        // GCM (0x09) → allow.
        let mut r2 = req("Encrypt", Some("AES"), &attrs);
        r2.mechanism.block_cipher_mode = Some(0x09);
        assert!(rule.check_pass2(&r2, Some("AES")).is_none());
        // Rule scoped to AES → RSA request not gated.
        let mut r3 = req("Encrypt", Some("RSA"), &attrs);
        r3.mechanism.block_cipher_mode = Some(0x01);
        assert!(rule.check_pass2(&r3, Some("RSA")).is_none());
    }

    #[test]
    fn mechanism_param_constraint_requires_deterministic() {
        let attrs = HashMap::new();
        let rule = Rule::MechanismParameterConstraint {
            ops: vec!["Sign".into()],
            algorithm: None,
            allowed_block_cipher_modes: vec![],
            allowed_padding_methods: vec![],
            require_deterministic: Some(true),
            reason: "deterministic signing required".into(),
            clause: None,
        };
        // deterministic=true → allow.
        let mut r = req("Sign", Some("ML-DSA-65"), &attrs);
        r.mechanism.deterministic = Some(true);
        assert!(rule.check_pass2(&r, Some("ML-DSA-65")).is_none());
        // absent → deny (fail-closed).
        assert!(rule.check_pass2(&req("Sign", Some("ML-DSA-65"), &attrs), Some("ML-DSA-65")).is_some());
        // deterministic=false → deny.
        let mut r3 = req("Sign", Some("ML-DSA-65"), &attrs);
        r3.mechanism.deterministic = Some(false);
        assert!(rule.check_pass2(&r3, Some("ML-DSA-65")).is_some());
    }

    #[test]
    fn mac_mechanism_policy_gates_family() {
        let attrs = HashMap::new();
        let rule = Rule::MacMechanismPolicy {
            ops: vec!["MAC".into()],
            mac_algorithms: vec!["HMAC-SHA256".into(), "HMAC-SHA384".into()],
            reason: "approved MACs only".into(),
            clause: None,
        };
        assert!(rule
            .check_pass2(&req("MAC", Some("HMAC-SHA256"), &attrs), Some("HMAC-SHA256"))
            .is_none());
        assert!(rule
            .check_pass2(&req("MAC", Some("HMAC-MD5"), &attrs), Some("HMAC-MD5"))
            .is_some());
    }

    #[test]
    fn mechanism_param_default_forces_deterministic() {
        let attrs = HashMap::new();
        let rule = Rule::MechanismParameterDefault {
            ops: vec!["Sign".into()],
            algorithm: None,
            hashing_algorithm: None,
            block_cipher_mode: None,
            padding_method: None,
            deterministic: Some(true),
            mask_generator: None,
            tag_length: None,
            salt_length: None,
            reason: "force deterministic".into(),
            clause: None,
        };
        let cp = rule
            .resolve_cp(&req("Sign", Some("ML-DSA-65"), &attrs), Some("ML-DSA-65"))
            .expect("forcing rule fires");
        assert_eq!(cp.deterministic, Some(true));
        // Different op → no forcing.
        assert!(rule
            .resolve_cp(&req("Encrypt", Some("AES"), &attrs), Some("AES"))
            .is_none());
        // Gating rules never produce a CpOverride.
        assert!(Rule::MacMechanismPolicy {
            ops: vec!["MAC".into()],
            mac_algorithms: vec![],
            reason: "x".into(),
            clause: None,
        }
        .resolve_cp(&req("MAC", Some("HMAC-SHA256"), &attrs), Some("HMAC-SHA256"))
        .is_none());
    }

    #[test]
    fn mechanism_param_default_forces_aes_gcm_by_name() {
        let attrs = HashMap::new();
        let rule = Rule::MechanismParameterDefault {
            ops: vec!["Encrypt".into()],
            algorithm: Some("AES".into()),
            hashing_algorithm: None,
            block_cipher_mode: Some("GCM".into()),
            padding_method: None,
            deterministic: None,
            mask_generator: None,
            tag_length: None,
            salt_length: None,
            reason: "force AEAD".into(),
            clause: None,
        };
        let cp = rule
            .resolve_cp(&req("Encrypt", Some("AES"), &attrs), Some("AES"))
            .unwrap();
        assert_eq!(cp.block_cipher_mode, Some(0x09)); // KMIP GCM codepoint
        // Algorithm-scoped: RSA Encrypt is untouched.
        assert!(rule
            .resolve_cp(&req("Encrypt", Some("RSA"), &attrs), Some("RSA"))
            .is_none());
    }

    /// F-5 — a forcing rule can mandate MGF1, AEAD tag length, and PSS salt
    /// length, and they reach the resolved `CpOverride`.
    #[test]
    fn mechanism_param_default_forces_mgf_tag_salt() {
        let attrs = HashMap::new();
        let rule = Rule::MechanismParameterDefault {
            ops: vec!["Encrypt".into(), "Sign".into()],
            algorithm: None,
            hashing_algorithm: None,
            block_cipher_mode: None,
            padding_method: None,
            deterministic: None,
            mask_generator: Some("MGF1".into()),
            tag_length: Some(16),
            salt_length: Some(32),
            reason: "mandate MGF1 + 128-bit tag + 32-byte PSS salt".into(),
            clause: None,
        };
        let cp = rule
            .resolve_cp(&req("Encrypt", Some("RSA"), &attrs), Some("RSA"))
            .expect("forcing rule fires");
        assert_eq!(cp.mask_generator, Some(0x01)); // KMIP MGF1
        assert_eq!(cp.tag_length, Some(16));
        assert_eq!(cp.salt_length, Some(32));
        assert!(!cp.is_empty());
        // Unknown MGF name resolves to None (not silently 0).
        assert_eq!(mgf_name_to_code("MGF99"), None);
    }

    #[test]
    fn ckm_mechanism_dialect_gates_on_canonical_mech() {
        use softhsmrustv3::constants as c;
        let attrs = HashMap::new();
        // Denylist CKM_AES_CBC / ECB for Encrypt (no unauthenticated AES).
        let deny_rule = Rule::MechanismDenylist {
            ops: vec!["Encrypt".into()],
            mechanisms: vec!["CKM_AES_CBC".into(), "CKM_AES_ECB".into()],
            reason: "AEAD only".into(),
            clause: None,
        };
        let mut r = req("Encrypt", Some("AES"), &attrs);
        r.mechanism.canonical_mech = Some(c::CKM_AES_CBC);
        assert!(deny_rule.check_pass2(&r, Some("AES")).is_some());
        let mut r2 = req("Encrypt", Some("AES"), &attrs);
        r2.mechanism.canonical_mech = Some(c::CKM_AES_GCM);
        assert!(deny_rule.check_pass2(&r2, Some("AES")).is_none());
        // Allowlist: only the ML-DSA mechanism for Sign.
        let allow_rule = Rule::MechanismAllowlist {
            ops: vec!["Sign".into()],
            mechanisms: vec!["CKM_ML_DSA".into()],
            reason: "PQC signature mechanisms only".into(),
            clause: None,
        };
        let mut r3 = req("Sign", Some("ML-DSA-65"), &attrs);
        r3.mechanism.canonical_mech = Some(c::CKM_ML_DSA);
        assert!(allow_rule.check_pass2(&r3, Some("ML-DSA-65")).is_none());
        let mut r4 = req("Sign", Some("ECDSA"), &attrs);
        r4.mechanism.canonical_mech = Some(c::CKM_ECDSA_SHA256);
        assert!(allow_rule.check_pass2(&r4, Some("ECDSA")).is_some());
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
            clause: None,
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
            clause: None,
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
            clause: None,
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
            clause: None,
            name_pattern: None,
        };
        let req = req("CreateKeyPair", Some("ECDSA-P256"), &attrs);
        let sub = r.resolve_substitution(&req, Some("ECDSA-P256")).expect("must substitute");
        assert_eq!(sub.new_algorithm, "ML-DSA-65");
    }

    /// 2026-07-05 (classical-KEM crypto-agility design review) — a
    /// substitution rule that (mistakenly) targets a consumer op must never
    /// fire, even though its `ops:` list names the request's op exactly. The
    /// loader rejects such a rule at load time (see `lint.rs`); this pins the
    /// engine-level backstop for defense-in-depth.
    #[test]
    fn resolve_substitution_never_fires_on_consumer_ops() {
        let attrs = HashMap::new();
        for op in ["Decapsulate", "DeriveKey", "Decrypt"] {
            assert!(is_consumer_op(op), "{op} must be classified as a consumer op");
            let r = Rule::AlgorithmSubstitution {
                ops: vec![op.to_string()],
                from: "ECDH-P256".into(),
                to: "ML-KEM-1024".into(),
                reason: "should never fire".into(),
                clause: None,
                name_pattern: None,
            };
            let req = req(op, Some("ECDH-P256"), &attrs);
            assert!(
                r.resolve_substitution(&req, Some("ECDH-P256")).is_none(),
                "{op}: substitution must not fire even though ops/from/current_algorithm all match"
            );
        }
        // Sanity: Encapsulate (an originator op) with the identical shape
        // still substitutes normally — the exclusion is op-specific, not a
        // blanket regression.
        let r = Rule::AlgorithmSubstitution {
            ops: vec!["Encapsulate".into()],
            from: "ECDH-P256".into(),
            to: "ML-KEM-1024".into(),
            reason: "should fire".into(),
            clause: None,
            name_pattern: None,
        };
        let req = req("Encapsulate", Some("ECDH-P256"), &attrs);
        assert!(r.resolve_substitution(&req, Some("ECDH-P256")).is_some());
    }

    #[test]
    fn algorithm_default_fires_when_no_algo() {
        let attrs = HashMap::new();
        let r = Rule::AlgorithmDefault {
            ops: vec!["CreateKeyPair".into()],
            default_algorithm: "ML-DSA-87".into(),
            reason: "PQC default for signing".into(),
            clause: None,
            name_pattern: None,
        };
        let req = req("CreateKeyPair", None, &attrs);
        let sub = r.resolve_default(&req).expect("must default");
        assert_eq!(sub.new_algorithm, "ML-DSA-87");

        // Wrong op: default does NOT fire (the engine guards the None-algo
        // precondition; resolve_default only matches on ops).
        let req2 = req;
        let _req2 = PolicyRequest { op: "Encrypt", ..req2 };
        assert!(r.resolve_default(&_req2).is_none());
    }

    /// F-3 — `max_key_age_days` denies an op on a key older than `days`, allows a
    /// young key, and is inert when the age is unknown or the op isn't listed.
    #[test]
    fn max_key_age_days_enforced() {
        use time::Duration;
        let attrs = HashMap::new();
        let r = Rule::MaxKeyAgeDays {
            ops: vec!["Sign".into()],
            days: 90,
            reason: "key past 90-day rotation window".into(),
            clause: None,
        };
        let activated = OffsetDateTime::UNIX_EPOCH;
        let aged = |op: &'static str, age_days: i64, with_date: bool| {
            let mut q = PolicyRequest::minimal(
                op,
                Some("ML-DSA-87"),
                activated + Duration::days(age_days),
                "c-age",
                &attrs,
            );
            if with_date {
                q.object_activation_date = Some(activated);
            }
            q
        };

        // 100 days old, op listed, date known → DENY KeyExpired.
        let d = r.check_pass2(&aged("Sign", 100, true), Some("ML-DSA-87"));
        assert!(matches!(d, Some(g) if matches!(g.kmip_reason, DenyReason::KeyExpired)));
        // 30 days old → within window → allow.
        assert!(r.check_pass2(&aged("Sign", 30, true), Some("ML-DSA-87")).is_none());
        // Old but activation date unknown → cannot age out → allow.
        assert!(r.check_pass2(&aged("Sign", 100, false), Some("ML-DSA-87")).is_none());
        // Old but op not in the rule's `ops` → rule inert → allow.
        assert!(r.check_pass2(&aged("Encrypt", 100, true), Some("ML-DSA-87")).is_none());
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
            clause: None,
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
            clause: None,
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
            clause: None,
        };
        let mut req = req("Create", Some("ML-DSA-65"), &attrs);
        req.ts = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(); // 2027
        // Pure ML-DSA-65 inside window → deny (composite required).
        assert!(r.check_pass2(&req, Some("ML-DSA-65")).is_some());
        // KMIP 3.0-cased composite name → allow (canonical spelling).
        assert!(r.check_pass2(&req, Some("ML-DSA-65-Ed25519")).is_none());
        // Case-insensitive: the legacy uppercase spelling is still accepted.
        assert!(r.check_pass2(&req, Some("ML-DSA-65-ED25519")).is_none());
    }

    /// WP-C12 (composite/hybrid remediation plan) — the test above
    /// exercises `HybridDualSignRequirement` against a hand-typed string
    /// standing in for a composite algorithm name; this closes the loop
    /// against a REAL composite `KmipAlgorithm`'s own canonical name
    /// (`spec_name()`), confirming the rule's speculative string-match
    /// logic actually fires now that composite algorithms exist.
    #[test]
    fn hybrid_dual_sign_matches_real_composite_kmip_algorithm_canonical_name() {
        use crate::kmip30::KmipAlgorithm;

        let attrs = HashMap::new();
        let r = Rule::HybridDualSignRequirement {
            primary: "ML-DSA-65".into(),
            secondary: "ECDSA-P256".into(),
            effective_from: TimeBound::At(time::Date::from_calendar_date(2026, time::Month::January, 1).unwrap()),
            effective_until: TimeBound::At(time::Date::from_calendar_date(2029, time::Month::December, 31).unwrap()),
            ops_affected: vec!["CreateKeyPair".into()],
            composite_oid: None,
            triggered_by_custom_attribute: None,
            reason: "Composite required in migration window".into(),
            clause: None,
        };
        let mut req = req("CreateKeyPair", Some("ML-DSA-65"), &attrs);
        req.ts = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(); // 2027

        // Pure ML-DSA-65 inside the window → still denied (composite required).
        assert!(r.check_pass2(&req, Some("ML-DSA-65")).is_some());

        // The REAL CompositeMlDsa65EcdsaP256Sha512 variant's own
        // canonical name — not hand-typed — must satisfy the rule. This
        // is the exact string `create_key_pair.rs::canonical_name` /
        // `qualify_algorithm_str` (a no-op for composite names, see its
        // `_ => name.to_string()` fallthrough) hands to policy evaluation
        // for a real CreateKeyPair request.
        let composite_name = KmipAlgorithm::CompositeMlDsa65EcdsaP256Sha512.spec_name();
        assert_eq!(composite_name, "ML-DSA-65-ECDSA-P256");
        assert!(
            r.check_pass2(&req, Some(composite_name)).is_none(),
            "composite KmipAlgorithm canonical name {composite_name:?} must satisfy the rule"
        );

        // A DIFFERENT real composite algorithm (mismatched classical
        // half) must still be denied — this isn't "any composite passes".
        let wrong_composite = KmipAlgorithm::CompositeMlDsa87EcdsaP384Sha512.spec_name();
        assert!(r.check_pass2(&req, Some(wrong_composite)).is_some());
    }

    #[test]
    fn require_custom_attribute_at_create() {
        let mut attrs = HashMap::new();
        let r = Rule::RequireCustomAttribute {
            attribute_name: "pqctoday-cnsa-classification".into(),
            algorithms: vec!["ML-DSA-87".into()],
            ops: vec![],
            reason: "CNSA classification required".into(),
            clause: None,
        };
        let req1 = req("Create", Some("ML-DSA-87"), &attrs);
        assert!(r.check_pass2(&req1, Some("ML-DSA-87")).is_some());
        attrs.insert("pqctoday-cnsa-classification".into(), "TopSecret".into());
        let req2 = req("Create", Some("ML-DSA-87"), &attrs);
        assert!(r.check_pass2(&req2, Some("ML-DSA-87")).is_none());
    }

    // ── 2026-07-04 gap audit: provenance rules are creation-scoped ────────
    #[test]
    fn require_custom_attribute_default_scope_leaves_use_ops_open() {
        let attrs = HashMap::new(); // attribute deliberately missing
        let r = Rule::RequireCustomAttribute {
            attribute_name: "pqctoday-cnsa-classification".into(),
            algorithms: vec!["AES-256".into()],
            ops: vec![], // omitted → DEFAULT_PROVENANCE_OPS
            reason: "classification required".into(),
            clause: None,
        };
        // Creation/ingress ops: denied without the attribute.
        for op in ["Create", "CreateKeyPair:Encrypt", "Register", "Import"] {
            let rq = req(op, Some("AES-256"), &attrs);
            assert!(r.check_pass2(&rq, Some("AES-256")).is_some(), "{op} must deny");
        }
        // Use ops on an untagged (e.g. legacy) key: NOT this rule's business.
        for op in ["Encrypt", "Decrypt", "Sign", "SignatureVerify", "Get", "Decapsulate"] {
            let rq = req(op, Some("AES-256"), &attrs);
            assert!(r.check_pass2(&rq, Some("AES-256")).is_none(), "{op} must pass");
        }
    }

    #[test]
    fn require_custom_attribute_explicit_ops_override_default() {
        let attrs = HashMap::new();
        let r = Rule::RequireCustomAttribute {
            attribute_name: "pqctoday-purpose".into(),
            algorithms: vec!["ML-DSA-87".into()],
            ops: vec!["Sign".into()],
            reason: "purpose required to sign".into(),
            clause: None,
        };
        // Explicit scope gates exactly those ops — Create passes, Sign denies.
        let rq = req("Create", Some("ML-DSA-87"), &attrs);
        assert!(r.check_pass2(&rq, Some("ML-DSA-87")).is_none());
        let rq = req("Sign", Some("ML-DSA-87"), &attrs);
        assert!(r.check_pass2(&rq, Some("ML-DSA-87")).is_some());
    }

    #[test]
    fn require_usage_mask_default_scope_leaves_use_ops_open() {
        let attrs = HashMap::new();
        let r = Rule::RequireUsageMask {
            algorithm: "LMS".into(),
            flags: vec!["Sign".into(), "Verify".into()],
            ops: vec![],
            reason: "LMS keys must declare Sign+Verify".into(),
            clause: None,
        };
        // Create without a mask fails closed (unchanged behaviour).
        let rq = req("Create", Some("LMS"), &attrs);
        assert!(r.check_pass2(&rq, Some("LMS")).is_some());
        // A mask-less use request (dry-run, legacy verify) is out of scope.
        let rq = req("SignatureVerify", Some("LMS"), &attrs);
        assert!(r.check_pass2(&rq, Some("LMS")).is_none());
        // Create WITH the right mask passes.
        let mut rq = req("Create", Some("LMS"), &attrs);
        rq.usage_mask = Some(
            super::super::super::kmip30::UsageMask::SIGN
                | super::super::super::kmip30::UsageMask::VERIFY,
        );
        assert!(r.check_pass2(&rq, Some("LMS")).is_none());
    }

    #[test]
    fn matches_class_hybrid_kems_are_pqc() {
        // KMIP 3.0 WD19 hybrid KEM spellings carry no hyphen in the ML-KEM
        // component; they must classify as PQC, not fall through to classical.
        assert!(matches_class("X25519MLKEM768", "pqc"));
        assert!(matches_class("SecP256r1MLKEM768", "pqc"));
        assert!(!matches_class("X25519MLKEM768", "classical"));
    }
}
