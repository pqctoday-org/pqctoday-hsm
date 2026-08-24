//! Shared TLS posture for pqctoday-hsm's remote server surfaces (KMIP,
//! and — as of the PKCS#11 remoting program — the gRPC/REST PKCS#11
//! services).
//!
//! Extracted verbatim from `pqctoday-kmip`'s `server::listener` /
//! `server::secp384r1mlkem1024` (2026-08-24, `sandbox-bench-transport-arms-plan-08242026.md`
//! WP2) so a non-KMIP service can enforce the identical
//! KMIP 3.0 Profiles v3.0 §3.3 "Quantum Safe Authentication Suite" posture
//! without depending on the kmip crate. `pqctoday-kmip` is free to migrate
//! onto this crate later; that migration is not required for the services
//! that consume it today.
//!
//! **Wording rule** (carries over unchanged): every description of a
//! service built on [`quantum_safe_provider`] must say **measured against**
//! the Quantum Safe Authentication Suite, never **conformant to** it.

pub mod secp384r1mlkem1024;

pub use secp384r1mlkem1024::{SecP384r1MlKem1024, SECP384R1MLKEM1024, SECP384R1MLKEM1024_CODEPOINT};

use std::sync::Arc;

/// Which TLS posture a server enforces.
///
/// KMIP 3.0 Profiles §3.3 is not a preference — it is a set of SHALL / SHALL
/// NOT clauses. [`TlsProfile::QuantumSafe`] enforces them; [`TlsProfile::Permissive`]
/// is the historical rustls-defaults behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsProfile {
    /// rustls defaults: TLS 1.2 + 1.3, the full default suite and group lists.
    #[default]
    Permissive,
    /// §3.3 — TLS 1.3 only, §3.3.2 suites only, §3.3.3 hybrid ML-KEM groups only.
    QuantumSafe,
    /// **Measurement baseline only — not a deployment posture.**
    ///
    /// Identical to [`TlsProfile::QuantumSafe`] except the key exchange
    /// groups are classical. Exists because comparing `Permissive` against
    /// `QuantumSafe` varies the crypto PROVIDER (ring vs aws-lc-rs) as well
    /// as the group, corrupting any premium measurement; against this
    /// profile only the group changes.
    ClassicalBaseline,
}

impl TlsProfile {
    /// Parse a `--tls-profile` / `*_TLS_PROFILE` value. Accepts the same
    /// spellings as the KMIP server for operational consistency.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "permissive" => Ok(Self::Permissive),
            "quantum-safe" | "quantum_safe" => Ok(Self::QuantumSafe),
            "classical-baseline" | "classical_baseline" => Ok(Self::ClassicalBaseline),
            other => Err(format!(
                "unknown TLS profile {other:?} (expected 'permissive', 'quantum-safe' \
                 or 'classical-baseline')"
            )),
        }
    }
}

/// The §3.3 crypto provider: aws-lc-rs restricted to exactly the cipher
/// suites and key exchange groups the Quantum Safe Authentication Suite
/// permits. See [`crate::secp384r1mlkem1024`] for why `SecP384r1MLKEM1024`
/// is composed locally rather than taken from rustls directly.
pub fn quantum_safe_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs;
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::SECP256R1MLKEM768,
            SECP384R1MLKEM1024,
        ],
        ..aws_lc_rs::default_provider()
    }
}

/// [`quantum_safe_provider`] with the hybrid groups swapped for classical
/// ones — provider and suites unchanged, so a comparison isolates the group.
pub fn classical_baseline_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs;
    rustls::crypto::CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519, aws_lc_rs::kx_group::SECP256R1],
        ..quantum_safe_provider()
    }
}

/// Human-readable summary of what a profile enforces, for startup logs.
pub fn tls_profile_summary(profile: TlsProfile) -> String {
    match profile {
        TlsProfile::Permissive => {
            "permissive (rustls defaults: TLS1.2+1.3, default suites and groups)".to_string()
        }
        TlsProfile::ClassicalBaseline => {
            "classical-baseline (MEASUREMENT ONLY, not a deployment posture): \
             TLS1.3 only; same suites and provider as quantum-safe; groups \
             X25519, SecP256r1 — exists so a premium isolates the key \
             exchange group rather than the crypto provider"
                .to_string()
        }
        TlsProfile::QuantumSafe => {
            "quantum-safe (measured against KMIP 3.0 Profiles §3.3): TLS1.3 \
             only; suites TLS13_CHACHA20_POLY1305_SHA256, \
             TLS13_AES_256_GCM_SHA384; groups X25519MLKEM768, \
             SecP256r1MLKEM768, SecP384r1MLKEM1024"
                .to_string()
        }
    }
}

/// Install the `ring` crypto provider as rustls' process default. Applies to
/// [`TlsProfile::Permissive`] only — the quantum-safe profiles pass an
/// aws-lc-rs provider explicitly instead. Idempotent (first-call-wins).
pub fn install_permissive_default_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a rustls `ConfigBuilder<ServerConfig, WantsVerifier>` for `profile`.
/// The one place a server-side builder is created, so every TLS entry point
/// in a consuming service gets the same posture regardless of launch flags.
pub fn server_config_builder(
    profile: TlsProfile,
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>, String> {
    use rustls::ServerConfig;
    match profile {
        TlsProfile::Permissive => {
            install_permissive_default_provider();
            Ok(ServerConfig::builder())
        }
        TlsProfile::ClassicalBaseline => {
            ServerConfig::builder_with_provider(Arc::new(classical_baseline_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| format!("classical-baseline TLS setup: {e}"))
        }
        TlsProfile::QuantumSafe => {
            ServerConfig::builder_with_provider(Arc::new(quantum_safe_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| format!("quantum-safe TLS setup: {e}"))
        }
    }
}

/// The provider a client-side `ClientConfig` should pin for `profile`, so a
/// benchmark client can target one arm of a twin deployment precisely.
pub fn client_provider_for(profile: TlsProfile) -> rustls::crypto::CryptoProvider {
    match profile {
        TlsProfile::Permissive => rustls::crypto::ring::default_provider(),
        TlsProfile::QuantumSafe => quantum_safe_provider(),
        TlsProfile::ClassicalBaseline => classical_baseline_provider(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_safe_provider_offers_exactly_the_three_mandated_groups() {
        let provider = quantum_safe_provider();
        let names: Vec<u16> = provider.kx_groups.iter().map(|g| u16::from(g.name())).collect();
        assert!(names.contains(&0x11ec), "X25519MLKEM768 (0x11ec) missing");
        assert!(names.contains(&0x11eb), "SecP256r1MLKEM768 (0x11eb) missing");
        assert!(names.contains(&0x11ed), "SecP384r1MLKEM1024 (0x11ed) missing");
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn classical_baseline_swaps_only_the_groups() {
        let qs = quantum_safe_provider();
        let cb = classical_baseline_provider();
        assert_eq!(qs.cipher_suites.len(), cb.cipher_suites.len());
        assert_ne!(
            qs.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
            cb.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_accepts_documented_spellings() {
        assert_eq!(TlsProfile::parse("permissive"), Ok(TlsProfile::Permissive));
        assert_eq!(TlsProfile::parse("quantum-safe"), Ok(TlsProfile::QuantumSafe));
        assert_eq!(TlsProfile::parse("quantum_safe"), Ok(TlsProfile::QuantumSafe));
        assert_eq!(
            TlsProfile::parse("classical-baseline"),
            Ok(TlsProfile::ClassicalBaseline)
        );
        assert!(TlsProfile::parse("bogus").is_err());
    }
}
