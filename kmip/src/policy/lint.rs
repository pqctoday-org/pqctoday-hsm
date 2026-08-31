//! Value-level policy lint (WP2.1 / gap Y6).
//!
//! The loader's [`super::loader::first_unknown_rule_field`] catches unknown
//! *field keys*. This module catches unknown *values*: an algorithm / mechanism
//! / hash / op / state / mode / flag name that the engine will never match. A
//! typo in a **denylist** or **temporal_cutoff** is the dangerous case — the
//! rule silently becomes a no-op and the policy fails OPEN. A typo in an
//! **allowlist** is the opposite (over-broad deny) and is reported as a warning
//! unless `strict` is set.
//!
//! Severity policy (mirrors the remediation plan):
//! - unknown value in a *deny*-family position (denylist, temporal_cutoff,
//!   substitution `from`, mechanism_denylist) → **hard error** (fail-open risk);
//! - unknown value in an *allow*-family position (allowlist, defaults,
//!   substitution `to`, mechanism_allowlist) → **warning**, promoted to a hard
//!   error under `strict` (the local gate and the manager `/validate` run
//!   strict);
//! - unknown mechanism / hash / class / state / mode / usage-flag names are
//!   always hard errors regardless of position — those vocabularies are bounded
//!   by the engine, so an unknown one is unambiguously a typo/no-op;
//! - unknown **op** names (A5.1, 2026-08-28 audit) are likewise always hard
//!   errors regardless of position: an op typo disables the *entire rule*, so
//!   there is no allow-position lenient tier the way there is for algorithm
//!   names. A real-but-currently-ungated KMIP op (Certify, Validate,
//!   JoinSplitKey, Export, Query — the dispatcher never routes these through
//!   `evaluate`) gets a distinct message from an outright typo, but is
//!   rejected the same way: either way the rule can never fire.
//!
//! Algorithm names are special: a denylist may legitimately name a real but
//! *unimplemented* algorithm (e.g. `FrodoKEM-1344`) as defence-in-depth, so
//! [`is_known_algorithm_name`] validates against a curated registry of real
//! algorithm names (implemented **and** known-unimplemented), not just the
//! engine's `KmipAlgorithm` enum.

use super::rule::{
    is_known_algorithm_class, is_known_block_cipher_mode, is_known_but_ungated_op,
    is_known_ckm_name, is_known_hash_name, is_known_mask_generator, is_known_op,
    is_known_padding_method, is_known_usage_flag, Rule, Severity,
};

/// A lint finding: which rule, which field, the offending value, and whether it
/// is fatal at the current strictness.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_index: usize, // 1-based
    pub field: &'static str,
    pub value: String,
    pub fatal: bool,
    pub message: String,
}

/// Lint every rule's values. Returns all findings; the caller separates fatal
/// from advisory. `strict` promotes allow-position algorithm-name warnings to
/// fatal.
pub fn lint_rules(rules: &[Rule], strict: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let idx = i + 1;
        lint_one(idx, rule, strict, &mut out);
    }
    lint_warn_severity_sunsets(rules, &mut out);
    out
}

/// A1 (2026-08-28 gaps-remediation plan) — a `severity: warn` rule that will
/// never actually escalate to a deny looks like the first half of the
/// recommended deprecation pattern (the SAME condition written twice: `warn`
/// today, a dated `deny` copy later) with the second half forgotten.
/// Advisory, never fatal — a permanently warn-only rule is also a legitimate,
/// deliberate choice (e.g. "flag this forever, never actually ban it"), so
/// this is a nudge, not an error.
///
/// Deliberately coarse rather than matching the exact same condition
/// (`ops`/`algorithms`) across rules: any sibling rule of the SAME type
/// (`std::mem::discriminant`) at `severity: deny` counts as the escalation
/// path, and a rule's own dated `effective_from` counts too, for the one
/// type (`hash_algorithm_allowlist`, `algorithm_denylist`) that carries one.
/// Exact-condition matching would be more precise but is a much larger check
/// for a marginal accuracy gain on an advisory-only finding.
fn lint_warn_severity_sunsets(rules: &[Rule], out: &mut Vec<Finding>) {
    let has_dated_escalation = |r: &Rule| -> bool {
        matches!(
            r,
            Rule::AlgorithmDenylist { effective_from: Some(_), .. }
                | Rule::HashAlgorithmAllowlist { effective_from: Some(_), .. }
        )
    };
    for (i, rule) in rules.iter().enumerate() {
        if rule.severity() != Severity::Warn {
            continue;
        }
        if has_dated_escalation(rule) {
            continue;
        }
        let has_deny_sibling = rules
            .iter()
            .any(|other| std::mem::discriminant(other) == std::mem::discriminant(rule)
                && other.severity() == Severity::Deny);
        if has_deny_sibling {
            continue;
        }
        out.push(Finding {
            rule_index: i + 1,
            field: "severity",
            value: "warn".to_string(),
            fatal: false,
            message: "deprecation with no sunset — this warn-severity rule has neither its own \
                      dated escalation (effective_from) nor a sibling severity:deny rule of the \
                      same type; it will warn forever and never actually deny. If that's \
                      deliberate, ignore this; otherwise add the deny half of the pattern."
                .to_string(),
        });
    }
}

fn algo(idx: usize, field: &'static str, value: &str, fatal: bool, out: &mut Vec<Finding>) {
    if !is_known_algorithm_name(value) {
        out.push(Finding {
            rule_index: idx,
            field,
            value: value.to_string(),
            fatal,
            message: format!(
                "unknown algorithm name {value:?} — not a recognised KMIP/PQC algorithm; \
                 it will never match (a typo here silently disables the rule)"
            ),
        });
    }
}

/// Validate a single op string (A5.1). Always fatal, regardless of the
/// rule's allow/deny position — unlike an algorithm-name typo (which is only
/// dangerous in a deny position), an op-name typo silently disables the
/// *entire rule* no matter what it does, so there is no lenient tier.
fn lint_op(idx: usize, field: &'static str, value: &str, out: &mut Vec<Finding>) {
    if is_known_op(value) {
        return;
    }
    let message = if is_known_but_ungated_op(value) {
        format!(
            "{value:?} is a real KMIP operation, but the dispatcher never \
             evaluates it against the policy engine — this rule can never fire \
             for it (not a typo; a currently-ungated operation)"
        )
    } else {
        format!(
            "unknown operation {value:?} — not a recognised KMIP operation name; \
             it will never match (a typo here silently disables the rule)"
        )
    };
    out.push(Finding { rule_index: idx, field, value: value.to_string(), fatal: true, message });
}

/// [`lint_op`] over a rule's `ops`/`ops_affected` list.
fn lint_ops(idx: usize, field: &'static str, values: &[String], out: &mut Vec<Finding>) {
    for v in values {
        lint_op(idx, field, v, out);
    }
}

/// KMIP/CACP coverage gap-analysis Phase 0.4 (2026-08-28/30) — the
/// "known-name trap": these names are *valid* in their respective
/// dialects (recognised, not typos — `bounded()` passes them clean), but
/// the op-layer dispatch that would actually execute the mechanism/mode
/// they name doesn't exist yet. A policy referencing one loads
/// successfully and looks like it gates something, but the rule is
/// inert — not a security hole (the engine fails closed regardless of
/// policy for these), but a real risk that a compliance policy claims to
/// enforce a control that cannot fire, or that a future PR wiring one of
/// these up silently starts honoring an old, never-reviewed rule.
///
/// This list is a snapshot of the 2026-08-30 KMIP/CACP coverage audit —
/// remove an entry here in the same change that wires up its dispatch
/// (see kmip/src/ops/helpers.rs::aes_mechanism_for for the block-cipher
/// modes, kmip/src/ops/sign.rs's is_pqc_sign_mech/native_mech selection
/// for CKM_EDDSA_PH), not separately.
fn undispatched_block_cipher_mode_reason(name: &str) -> Option<&'static str> {
    match name {
        "CCM" | "XTS" | "OFB" | "CFB" => Some(
            "recognised, but ops/helpers.rs::aes_mechanism_for only dispatches \
             CBC/CBC_PAD/ECB/CTR/GCM today — this mode cannot execute yet \
             (KMIP/CACP coverage gap-analysis Phase 2, not yet wired)",
        ),
        _ => None,
    }
}

/// See [`undispatched_block_cipher_mode_reason`] — same trap, `CKM_*`
/// mechanism-name dialect. `CKM_EDDSA_PH` is the one entry: recognised by
/// `ckm_name_to_code`, but KMIP's Sign/SignatureVerify dispatch never
/// selects it (the engine/provider convention settled on plain
/// `CKM_EDDSA` + `CK_EDDSA_PARAMS` for both prehash and context modes —
/// see the 2026-08-30 EdDSA remediation commits).
fn undispatched_ckm_reason(name: &str) -> Option<&'static str> {
    match name {
        "CKM_EDDSA_PH" => Some(
            "recognised, but KMIP's Sign/SignatureVerify dispatch never selects this \
             mechanism — EdDSA prehash mode is requested through CKM_EDDSA's own \
             parameters, not by naming this mechanism (a rule gating it can never fire)",
        ),
        _ => None,
    }
}

/// Emits a non-fatal advisory `Finding` when `value` is a known name (not
/// a typo — call this only after the corresponding `bounded()` check
/// passed) but has no live dispatch path per `reason_fn`. Unlike
/// `bounded()`, never blocks policy load — see the module doc comment on
/// [`undispatched_block_cipher_mode_reason`] for why this is a warning,
/// not a hard error.
fn advise_if_undispatched(
    idx: usize,
    field: &'static str,
    value: &str,
    reason_fn: impl Fn(&str) -> Option<&'static str>,
    out: &mut Vec<Finding>,
) {
    if let Some(reason) = reason_fn(value) {
        out.push(Finding {
            rule_index: idx,
            field,
            value: value.to_string(),
            fatal: false,
            message: format!("{value:?} is a known-but-inert value: {reason}"),
        });
    }
}

fn bounded(
    idx: usize,
    field: &'static str,
    value: &str,
    ok: bool,
    kind: &str,
    out: &mut Vec<Finding>,
) {
    if !ok {
        out.push(Finding {
            rule_index: idx,
            field,
            value: value.to_string(),
            fatal: true, // bounded vocabularies: unknown is always a no-op
            message: format!("unknown {kind} {value:?} — not one the engine understands"),
        });
    }
}

fn lint_one(idx: usize, rule: &Rule, strict: bool, out: &mut Vec<Finding>) {
    match rule {
        Rule::AlgorithmDefault { ops, default_algorithm, .. } => {
            algo(idx, "default_algorithm", default_algorithm, strict, out);
            lint_ops(idx, "ops", ops, out);
        }
        Rule::AlgorithmSubstitution { ops, from, to, .. } => {
            // `from` is a deny-position match target → fatal; `to` is allow.
            algo(idx, "from", from, true, out);
            algo(idx, "to", to, strict, out);
            lint_ops(idx, "ops", ops, out);
            // 2026-07-05 (classical-KEM crypto-agility design review) —
            // consumer ops (Decapsulate/DeriveKey/Decrypt) can never
            // coherently execute a rekey: their input was already fixed to a
            // specific algorithm by an earlier, possibly different-party
            // call. The engine hard-excludes them at runtime regardless
            // (`rule::resolve_substitution`), but a rule naming one here is
            // always a policy-authoring mistake — reject it at load time
            // rather than let it silently do nothing forever. See
            // `rule::is_consumer_op` for the full rationale.
            for op in ops {
                if super::rule::is_consumer_op(op) {
                    out.push(Finding {
                        rule_index: idx,
                        field: "ops",
                        value: op.clone(),
                        fatal: true,
                        message: format!(
                            "algorithm_substitution targets consumer op {op:?} — \
                             Decapsulate/DeriveKey/Decrypt operate on material a peer \
                             already fixed to an algorithm; there is nothing to \
                             substitute, and the engine ignores this rule for that op \
                             (rejected here so it isn't mistaken for working)"
                        ),
                    });
                }
            }
        }
        Rule::AlgorithmAllowlist { ops, algorithms, .. } => {
            for a in algorithms {
                algo(idx, "algorithms", a, strict, out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::AlgorithmDenylist { ops, algorithms, .. } => {
            for a in algorithms {
                algo(idx, "algorithms", a, true, out); // fail-open if typo'd
            }
            lint_ops(idx, "ops", ops, out);
        }
        // No `ops` field on this rule (it gates by algorithm + key_length only).
        Rule::MinKeyLength { algorithm, .. } => algo(idx, "algorithm", algorithm, strict, out),
        Rule::RequireUsageMask { algorithm, flags, ops, .. } => {
            algo(idx, "algorithm", algorithm, strict, out);
            for f in flags {
                bounded(idx, "flags", f, is_known_usage_flag(f), "usage-mask flag", out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::RequireCustomAttribute { algorithms, ops, .. } => {
            for a in algorithms {
                algo(idx, "algorithms", a, strict, out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::TemporalCutoff { op, algorithm_class, algorithms, .. } => {
            bounded(
                idx,
                "algorithm_class",
                algorithm_class,
                is_known_algorithm_class(algorithm_class),
                "algorithm_class",
                out,
            );
            for a in algorithms {
                algo(idx, "algorithms", a, true, out); // narrows a deny → fatal
            }
            lint_op(idx, "op", op, out);
        }
        Rule::LifecycleStateGate { op, allowed_states, .. } => {
            for s in allowed_states {
                bounded(idx, "allowed_states", s, is_known_state(s), "lifecycle state", out);
            }
            lint_op(idx, "op", op, out);
        }
        Rule::HybridDualSignRequirement { primary, secondary, ops_affected, .. } => {
            algo(idx, "primary", primary, strict, out);
            algo(idx, "secondary", secondary, strict, out);
            lint_ops(idx, "ops_affected", ops_affected, out);
        }
        Rule::HashAlgorithmAllowlist { ops, hashing_algorithms, .. } => {
            for h in hashing_algorithms {
                bounded(idx, "hashing_algorithms", h, is_known_hash_name(h), "hash algorithm", out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::MechanismParameterConstraint {
            ops,
            algorithm,
            allowed_block_cipher_modes,
            allowed_padding_methods,
            ..
        } => {
            if let Some(a) = algorithm {
                algo(idx, "algorithm", a, strict, out);
            }
            for m in allowed_block_cipher_modes {
                bounded(idx, "allowed_block_cipher_modes", m, is_known_block_cipher_mode(m), "block cipher mode", out);
                advise_if_undispatched(idx, "allowed_block_cipher_modes", m, undispatched_block_cipher_mode_reason, out);
            }
            for p in allowed_padding_methods {
                bounded(idx, "allowed_padding_methods", p, is_known_padding_method(p), "padding method", out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::MechanismParameterDefault {
            ops,
            algorithm,
            hashing_algorithm,
            block_cipher_mode,
            padding_method,
            mask_generator,
            ..
        } => {
            if let Some(a) = algorithm {
                algo(idx, "algorithm", a, strict, out);
            }
            if let Some(h) = hashing_algorithm {
                bounded(idx, "hashing_algorithm", h, is_known_hash_name(h), "hash algorithm", out);
            }
            if let Some(m) = block_cipher_mode {
                bounded(idx, "block_cipher_mode", m, is_known_block_cipher_mode(m), "block cipher mode", out);
                advise_if_undispatched(idx, "block_cipher_mode", m, undispatched_block_cipher_mode_reason, out);
            }
            if let Some(p) = padding_method {
                bounded(idx, "padding_method", p, is_known_padding_method(p), "padding method", out);
            }
            if let Some(g) = mask_generator {
                bounded(idx, "mask_generator", g, is_known_mask_generator(g), "mask generator", out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::MacMechanismPolicy { ops, mac_algorithms, .. } => {
            // mac_mechanism_policy is an allowlist (only these MACs pass), so a
            // typo over-broadly DENIES rather than failing open → advisory.
            // Names are qualified algorithm names (HMAC-SHA-256).
            for a in mac_algorithms {
                algo(idx, "mac_algorithms", a, strict, out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::MechanismAllowlist { ops, mechanisms, .. } => {
            for m in mechanisms {
                bounded(idx, "mechanisms", m, is_known_ckm_name(m), "CKM_* mechanism", out);
                advise_if_undispatched(idx, "mechanisms", m, undispatched_ckm_reason, out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::MechanismDenylist { ops, mechanisms, .. } => {
            for m in mechanisms {
                bounded(idx, "mechanisms", m, is_known_ckm_name(m), "CKM_* mechanism", out);
                advise_if_undispatched(idx, "mechanisms", m, undispatched_ckm_reason, out);
            }
            lint_ops(idx, "ops", ops, out);
        }
        Rule::MaxKeyAgeDays { ops, .. } => lint_ops(idx, "ops", ops, out),
        Rule::ComplianceProfileGate { ops, .. } => lint_ops(idx, "ops", ops, out),
    }
}

/// Known KMIP 3.0 lifecycle state names (spec §3 State enum).
fn is_known_state(s: &str) -> bool {
    matches!(
        s,
        "PreActive" | "Active" | "Deactivated" | "Compromised" | "Destroyed"
            | "DestroyedCompromised"
    )
}

/// `true` if `name` is a recognised algorithm name — implemented **or** a real
/// but unimplemented PQC/classical algorithm a denylist may legitimately name.
///
/// Structure-aware where a family takes a suffix (AES-256, ECDSA-P384, RSA-3072,
/// SLH-DSA-SHAKE-128f), exact-match for fixed names. Deliberately curated: the
/// point is to catch typos (`AES-2566`, `ML-DSA-8`, `Falconn-512`), not to be a
/// crypto encyclopedia. Extend when a policy introduces a new real algorithm.
pub fn is_known_algorithm_name(name: &str) -> bool {
    // Bare families accepted with no suffix (they qualify at the gate).
    const BARE: &[&str] = &[
        "AES", "RSA", "ECDSA", "ECDH", "DSA", "DH", "DES", "3DES", "MD5", "SHA1",
        "ChaCha20", "ChaCha20-Poly1305", "LMS", "HSS", "XMSS", "XMSS-MT",
        "Ed25519", "Ed448", "X25519", "X448", "RSA-PKCS1-v1_5", "ECDSA-SHA1",
        // K6 hybrid KEMs (KMIP 3.0 CSD02).
        "X25519MLKEM768", "SecP256r1MLKEM768",
        // A6.2 (2026-08-28 gaps-remediation plan): SecP384r1MLKEM1024 — the
        // OpenSSL 3.6 hybrid interop group this workspace already exercises
        // elsewhere (`pqc-ev-test`), previously unnameable in a policy at all.
        "SecP384r1MLKEM1024",
        // A6.2: real-but-unimplemented algorithms a denylist must still be
        // able to name (same rationale as the existing DES/3DES entries —
        // "this engine can't generate it" is not "a policy can't ban it").
        // Brainpool curves (RFC 5639), named the way TLS/crypto tooling
        // conventionally does.
        "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
        // Camellia (RFC 3713) and ARIA (RFC 5794) — AES-alternative block ciphers.
        "Camellia", "ARIA",
        // China's SM2 (ECC signature/key-exchange) and SM4 (block cipher, GB/T 32907).
        "SM2", "SM4",
    ];
    if BARE.contains(&name) {
        return true;
    }
    // Hash names (used as algorithm names in some deny rules, e.g. SHA-256).
    if is_known_hash_name(name) {
        return true;
    }
    // Qualified / parameterised families.
    let known_prefixes_suffixes: &[(&str, fn(&str) -> bool)] = &[
        ("AES-", |s| matches!(s, "128" | "192" | "256")),
        ("RSA-", |s| s.parse::<u32>().is_ok()),
        ("ECDSA-P", |s| matches!(s, "256" | "384" | "521")),
        ("ECDH-P", |s| matches!(s, "256" | "384" | "521")),
        ("HMAC-SHA-", |s| matches!(s, "256" | "384" | "512")),
        ("HMAC-SHA3-", |s| matches!(s, "256" | "384" | "512")),
        ("ML-KEM-", |s| matches!(s, "512" | "768" | "1024")),
        ("ML-DSA-", is_ml_dsa_suffix),
        ("SLH-DSA-", is_slh_dsa_suffix),
        ("Falcon-", |s| matches!(s, "512" | "1024")),
        ("HQC-", |s| matches!(s, "128" | "192" | "256")),
        ("BIKE-", |s| matches!(s, "L1" | "L3" | "L5")),
        ("FrodoKEM-", |s| matches!(s, "640" | "976" | "1344")),
        ("Classic-McEliece-", |s| {
            matches!(s, "348864" | "460896" | "6688128" | "6960119" | "8192128")
        }),
    ];
    known_prefixes_suffixes
        .iter()
        .any(|(pfx, ok)| name.strip_prefix(pfx).is_some_and(|rest| ok(rest)))
}

/// ML-DSA suffix: a bare level (`44`/`65`/`87`) or a composite tail
/// (`65-Ed25519`, `87-ECDSA-P384`) LAMPS names use. The classical tail is
/// matched case-insensitively so the KMIP 3.0 spelling (`Ed25519`, per RFC 8032)
/// and the legacy uppercase (`ED25519`) both validate — the engine likewise
/// matches composites case-insensitively.
///
/// The tail set must stay a superset of what the real
/// `KmipAlgorithm::CompositeMlDsa*` variants produce via `spec_name()`
/// (draft-ietf-lamps-pq-composite-sigs-19 §6), or a legitimate composite
/// policy target would fail its own linter and the rule would be rejected.
/// Names carry no hash-function suffix — the LAMPS profile's hash choice is
/// baked into the OID and engine mechanism, not distinguished at the
/// policy-name layer.
///
/// `RSA3072-PSS` added 2026-08-18 with the .41 profile. It was missed at first:
/// the test guarding this set listed its three variants by hand, so it stayed
/// green while three of the seven real variants went unchecked. The test now
/// discovers variants by sweeping the vendor codepoint range, which is what
/// caught the omission — see
/// `known_algorithm_names_accepts_every_real_composite_sig_variant`.
fn is_ml_dsa_suffix(s: &str) -> bool {
    match s {
        "44" | "65" | "87" => true,
        // composite: <level>-<classical>
        _ => {
            let mut parts = s.splitn(2, '-');
            let level = parts.next().unwrap_or("");
            let tail = parts.next().unwrap_or("");
            matches!(level, "44" | "65" | "87") && is_ml_dsa_composite_tail(tail)
        }
    }
}

/// The classical half of an `ML-DSA-<level>-<tail>` LAMPS composite name —
/// factored out of [`is_ml_dsa_suffix`] so `rule::is_composite_algorithm_name`
/// (A6.1, 2026-08-28 gaps-remediation plan) can recognise a full composite
/// name without a second, hand-maintained copy of this tail set. Case-folded
/// (KMIP 3.0 spells it `Ed25519`; legacy policy YAML may spell it `ED25519`).
pub(crate) fn is_ml_dsa_composite_tail(tail: &str) -> bool {
    matches!(
        tail.to_ascii_uppercase().as_str(),
        "ED25519" | "ED448" | "ECDSA-P256" | "ECDSA-P384" | "ECDSA-P521"
            | "RSA2048-PSS" | "RSA3072-PSS" | "RSA4096-PSS"
    )
}

/// SLH-DSA suffix: `<hash>-<size><s|f>`, e.g. `SHA2-128s`, `SHAKE-256f`.
fn is_slh_dsa_suffix(s: &str) -> bool {
    let rest = match s.strip_prefix("SHA2-").or_else(|| s.strip_prefix("SHAKE-")) {
        Some(r) => r,
        None => return false,
    };
    matches!(
        rest,
        "128s" | "128f" | "192s" | "192f" | "256s" | "256f"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::rule::{Severity, TimeBound};

    #[test]
    fn known_algorithm_names_accepts_real_and_qualified() {
        for ok in [
            "AES", "AES-256", "RSA-3072", "ECDSA-P384", "ECDH-P256", "ML-KEM-1024",
            "ML-DSA-87", "ML-DSA-65-Ed25519", "ML-DSA-65-ED25519", "ML-DSA-87-ECDSA-P384",
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHAKE-256f", "HMAC-SHA-256", "LMS", "HSS", "XMSS", "XMSS-MT",
            "Falcon-1024", "HQC-192", "BIKE-L3", "FrodoKEM-1344", "Classic-McEliece-8192128",
            "Ed25519", "X25519", "SHA-256", "RSA-PKCS1-v1_5", "ECDSA-SHA1",
            "X25519MLKEM768", "SecP256r1MLKEM768",
            // A6.2 (2026-08-28 gaps-remediation plan).
            "SecP384r1MLKEM1024",
            "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
            "Camellia", "ARIA", "SM2", "SM4",
        ] {
            assert!(is_known_algorithm_name(ok), "should accept {ok}");
        }
    }

    /// The linter's accepted composite tail set must stay a superset of what
    /// the real `KmipAlgorithm::CompositeMlDsa*` variants actually produce.
    ///
    /// The names come from `spec_name()` rather than being hand-typed, and as
    /// of 2026-08-18 so does the VARIANT LIST: it is discovered by sweeping
    /// the vendor codepoint range and keeping whatever `is_composite_sig()`
    /// admits. The previous version sourced only the names that way while
    /// listing three variants literally, which is the same drift it set out to
    /// prevent — adding profiles .39/.40/.41/.48 left that list silently three
    /// short, and the test still passed.
    #[test]
    fn known_algorithm_names_accepts_every_real_composite_sig_variant() {
        use crate::kmip30::KmipAlgorithm;
        let composites: Vec<KmipAlgorithm> = (0x8000_0000u32..=0x8000_00ff)
            .filter_map(KmipAlgorithm::from_wire_value)
            .filter(|a| a.is_composite_sig())
            .collect();

        // Guard against the sweep silently finding nothing (e.g. if the
        // codepoint range moved), which would make the loop below vacuous.
        assert!(
            composites.len() >= 7,
            "expected at least the 7 implemented composite profiles, found {}",
            composites.len()
        );

        for a in composites {
            let name = a.spec_name();
            assert!(is_known_algorithm_name(name), "should accept {name}");
        }
    }

    #[test]
    fn known_algorithm_names_rejects_typos() {
        for bad in [
            "AES-2566", "ML-DSA-8", "Falconn-512", "ECDSA-P255", "RSA-", "ML-KEM-2048",
            "SLH-DSA-SHA2-300s", "FrodoKEM-999", "Classic-McEliece-1", "AESX",
        ] {
            assert!(!is_known_algorithm_name(bad), "should reject {bad}");
        }
    }

    fn deny_rule(algos: &[&str]) -> Rule {
        Rule::AlgorithmDenylist {
            ops: vec!["Create".into()],
            algorithms: algos.iter().map(|s| s.to_string()).collect(),
            reason: "t".into(),
            clause: None,
            effective_from: None,
            effective_until: None,
            exception_custom_attribute: None,
            severity: Severity::Deny,
        }
    }

    #[test]
    fn warn_severity_with_no_sunset_is_advisory_not_fatal() {
        let mut warn_only = deny_rule(&["RSA"]);
        if let Rule::AlgorithmDenylist { severity, .. } = &mut warn_only {
            *severity = Severity::Warn;
        }
        let findings = lint_rules(&[warn_only], false);
        let f = findings
            .iter()
            .find(|f| f.field == "severity")
            .expect("a sunset-less warn rule should be flagged");
        assert!(!f.fatal, "the sunset advisory must never be fatal");
        assert!(f.message.contains("no sunset"));
    }

    #[test]
    fn warn_severity_with_dated_escalation_is_not_flagged() {
        let mut warn_with_date = deny_rule(&["RSA"]);
        if let Rule::AlgorithmDenylist { severity, effective_from, .. } = &mut warn_with_date {
            *severity = Severity::Warn;
            *effective_from = Some(TimeBound::At(
                time::Date::from_calendar_date(2030, time::Month::January, 1).unwrap(),
            ));
        }
        let findings = lint_rules(&[warn_with_date], false);
        assert!(!findings.iter().any(|f| f.field == "severity"));
    }

    #[test]
    fn warn_severity_with_a_deny_sibling_of_the_same_type_is_not_flagged() {
        let mut warn_rule = deny_rule(&["RSA"]);
        if let Rule::AlgorithmDenylist { severity, .. } = &mut warn_rule {
            *severity = Severity::Warn;
        }
        let deny_sibling = deny_rule(&["ECDSA-P256"]); // different condition, same TYPE — still counts
        let findings = lint_rules(&[warn_rule, deny_sibling], false);
        assert!(!findings.iter().any(|f| f.field == "severity"));
    }

    fn allow_rule(algos: &[&str]) -> Rule {
        Rule::AlgorithmAllowlist {
            ops: vec!["Create".into()],
            algorithms: algos.iter().map(|s| s.to_string()).collect(),
            reason: "t".into(),
            clause: None,
            effective_from: None,
            effective_until: None,
        }
    }

    #[test]
    fn denylist_typo_is_fatal() {
        let findings = lint_rules(&[deny_rule(&["AES-256", "ML-DSA-8"])], false);
        let fatal: Vec<_> = findings.iter().filter(|f| f.fatal).collect();
        assert_eq!(fatal.len(), 1, "the ML-DSA-8 typo must be fatal in a denylist");
        assert_eq!(fatal[0].value, "ML-DSA-8");
    }

    #[test]
    fn allowlist_typo_is_advisory_then_strict_fatal() {
        let lenient = lint_rules(&[allow_rule(&["AES-256", "ML-KEM-2048"])], false);
        assert!(lenient.iter().all(|f| !f.fatal), "allowlist typo is advisory in lenient mode");
        assert_eq!(lenient.iter().filter(|f| f.value == "ML-KEM-2048").count(), 1);

        let strict = lint_rules(&[allow_rule(&["AES-256", "ML-KEM-2048"])], true);
        assert!(strict.iter().any(|f| f.fatal && f.value == "ML-KEM-2048"),
            "allowlist typo is fatal under strict");
    }

    #[test]
    fn unknown_mechanism_is_always_fatal() {
        let rule = Rule::MechanismAllowlist {
            ops: vec!["Sign".into()],
            mechanisms: vec!["CKM_RSA_PKCS_PSS".into(), "CKM_TYPO".into()],
            reason: "t".into(),
            clause: None,
        };
        let findings = lint_rules(&[rule], false);
        assert!(findings.iter().any(|f| f.fatal && f.value == "CKM_TYPO"),
            "an unknown CKM name is always fatal (bounded vocabulary)");
    }

    /// KMIP/CACP coverage gap-analysis Phase 0.4 (2026-08-30) — a
    /// known-but-inert mechanism name (recognised, but no live dispatch
    /// path) loads cleanly (not fatal, unlike a real typo) but surfaces a
    /// non-fatal advisory finding, distinguishable from both a typo and a
    /// clean bill of health.
    #[test]
    fn known_but_undispatched_mechanism_is_advisory_not_fatal() {
        let rule = Rule::MechanismDenylist {
            ops: vec!["Encrypt".into()],
            mechanisms: vec!["CKM_AES_GCM".into(), "CKM_EDDSA_PH".into()],
            reason: "t".into(),
            clause: None,
            severity: Severity::Deny,
        };
        let findings = lint_rules(&[rule], false);
        assert!(!findings.iter().any(|f| f.fatal),
            "a known-but-inert name must not block policy load");
        let advisory = findings.iter().find(|f| f.value == "CKM_EDDSA_PH")
            .expect("CKM_EDDSA_PH must surface an advisory finding");
        assert!(!advisory.fatal);
        assert!(advisory.message.contains("known-but-inert"));
        assert!(!findings.iter().any(|f| f.value == "CKM_AES_GCM"),
            "a genuinely live mechanism must not trigger the advisory");
    }

    #[test]
    fn known_but_undispatched_block_cipher_mode_is_advisory_not_fatal() {
        let rule = Rule::MechanismParameterConstraint {
            ops: vec!["Encrypt".into()],
            algorithm: None,
            allowed_block_cipher_modes: vec!["GCM".into(), "CCM".into()],
            allowed_padding_methods: vec![],
            require_deterministic: None,
            reason: "t".into(),
            clause: None,
            severity: Severity::Deny,
        };
        let findings = lint_rules(&[rule], false);
        assert!(!findings.iter().any(|f| f.fatal));
        assert!(findings.iter().any(|f| f.value == "CCM" && !f.fatal));
        assert!(!findings.iter().any(|f| f.value == "GCM"),
            "GCM is genuinely dispatched — must not trigger the advisory");
    }

    #[test]
    fn op_typo_is_always_fatal_regardless_of_rule_position() {
        // Allow-position rule (algorithm_default) — an algorithm typo here
        // would be advisory, but an OP typo must still be fatal: the whole
        // rule is disabled either way.
        let default_rule = Rule::AlgorithmDefault {
            ops: vec!["Sing".into()], // typo of "Sign"
            default_algorithm: "AES-256".into(),
            reason: "t".into(),
            clause: None,
            name_pattern: None,
        };
        let findings = lint_rules(&[default_rule], false);
        assert!(
            findings.iter().any(|f| f.fatal && f.field == "ops" && f.value == "Sing"),
            "an op typo must be fatal even in an allow-position rule"
        );

        // Deny-position rule too, and under strict — no lenient tier at all.
        let deny_rule = Rule::AlgorithmDenylist {
            ops: vec!["Encrypt".into(), "Decyrpt".into()], // typo of "Decrypt"
            algorithms: vec!["AES-256".into()],
            reason: "t".into(),
            clause: None,
            effective_from: None,
            effective_until: None,
            exception_custom_attribute: None,
            severity: Severity::Deny,
        };
        for strict in [false, true] {
            let findings = lint_rules(&[deny_rule.clone()], strict);
            assert!(
                findings.iter().any(|f| f.fatal && f.field == "ops" && f.value == "Decyrpt"),
                "op typo must be fatal under strict={strict}"
            );
        }
    }

    #[test]
    fn known_but_ungated_op_is_fatal_with_a_distinct_message() {
        let rule = Rule::TemporalCutoff {
            op: "Query".into(), // real KMIP op, never routed through evaluate()
            algorithm_class: "classical".into(),
            algorithms: vec![],
            after: TimeBound::Always,
            reason: "t".into(),
            clause: None,
            severity: Severity::Deny,
        };
        let findings = lint_rules(&[rule], false);
        let f = findings.iter().find(|f| f.field == "op").expect("Query should be flagged");
        assert!(f.fatal);
        assert!(f.message.contains("not policy-gated") || f.message.contains("never evaluates"),
            "message should distinguish 'ungated op' from a typo, got: {}", f.message);
    }

    #[test]
    fn colon_refined_op_validates_only_the_base_segment() {
        let rule = Rule::AlgorithmSubstitution {
            ops: vec!["CreateKeyPair:Sign".into(), "CreateKeyPair:SomeNewPurpose".into()],
            from: "ECDSA-P256".into(),
            to: "ML-DSA-65".into(),
            reason: "t".into(),
            clause: None,
            name_pattern: None,
        };
        let findings = lint_rules(&[rule], false);
        assert!(
            findings.iter().all(|f| f.field != "ops"),
            "a colon-refined op with a known base should not be flagged just because \
             the suffix after ':' is a novel refinement: {findings:?}"
        );
    }

    #[test]
    fn hybrid_dual_sign_ops_affected_is_linted() {
        let rule = Rule::HybridDualSignRequirement {
            primary: "ML-DSA-65".into(),
            secondary: "Ed25519".into(),
            effective_from: TimeBound::Always,
            effective_until: TimeBound::Always,
            ops_affected: vec!["Sign".into(), "Sing".into()],
            composite_oid: None,
            triggered_by_custom_attribute: None,
            reason: "t".into(),
            clause: None,
        };
        let findings = lint_rules(&[rule], false);
        assert!(findings.iter().any(|f| f.fatal && f.field == "ops_affected" && f.value == "Sing"));
    }

    #[test]
    fn max_key_age_days_ops_is_linted() {
        let rule = Rule::MaxKeyAgeDays {
            ops: vec!["Sign".into(), "Encrypy".into()],
            days: 90,
            reason: "t".into(),
            clause: None,
        };
        let findings = lint_rules(&[rule], false);
        assert!(findings.iter().any(|f| f.fatal && f.field == "ops" && f.value == "Encrypy"));
    }

    #[test]
    fn unknown_class_and_state_are_fatal() {
        let cutoff = Rule::TemporalCutoff {
            op: "Sign".into(),
            algorithm_class: "quantum".into(), // not pqc/symmetric/classical
            algorithms: vec![],
            after: TimeBound::Always,
            reason: "t".into(),
            clause: None,
            severity: Severity::Deny,
        };
        assert!(lint_rules(&[cutoff], false).iter().any(|f| f.fatal && f.value == "quantum"));

        let gate = Rule::LifecycleStateGate {
            op: "Sign".into(),
            allowed_states: vec!["Alive".into()], // not a KMIP state
            reason: "t".into(),
            clause: None,
        };
        assert!(lint_rules(&[gate], false).iter().any(|f| f.fatal && f.value == "Alive"));
    }
}
