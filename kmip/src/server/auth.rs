//! K14 — request authentication (KMIP 3.0 §8.1.2 `Authentication`,
//! §9.9 `Credential`).
//!
//! ## Modes
//!
//! - **Open-auth (default)** — no users configured
//!   (`DepsConfig::auth_users` empty). Every request passes and any
//!   `Authentication` header content is ignored. This is REQUIRED by
//!   the hermetic OASIS replay harness, which drives the default
//!   server config with credential-free transcripts.
//! - **Configured auth** — one or more `--auth-user
//!   <username>:<sha256hex>` entries. The dispatcher verifies the
//!   header's Credential(s) against the store; a request whose
//!   Authentication is absent, unsupported, or fails verification has
//!   every batch item failed with
//!   `Result Reason = Authentication Not Successful (0x03)` (§11.5).
//!   An mTLS-verified client certificate (see
//!   [`super::listener`]) also satisfies configured auth — its
//!   subject CN is the identity.
//!
//! ## Password storage
//!
//! Passwords are stored as **lowercase SHA-256 hex** of the UTF-8
//! password. This is deliberately minimal: `sha2` is already in the
//! tree and the store backs sandbox / conformance-profile testing. A
//! production credential store wants a memory-hard KDF (argon2id /
//! scrypt) with per-user salts — tracked as follow-up; we do not pull
//! a new heavy dependency into this slice.

use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::kmip30::Credential;

/// The authenticated principal a request acts as.
///
/// `Hash` (added for the Part F tenant registry,
/// rust-hsm-perf-bench-scenario-plan-07182026.md §F7) lets `Identity`
/// key a `HashMap` directly — one tenant token per authenticated
/// principal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    /// KMIP username (configured-auth) or mTLS client-cert subject CN.
    pub username: String,
}

/// A live `Login`-issued session, keyed by the ticket's `Ticket Value`
/// bytes in [`crate::ops::Deps::sessions`]. KMIP 3.0 §6.1.36: "allow
/// future requests to be authenticated using a ticket" — this is the
/// server-side half of that promise; `Logout` removes the entry,
/// `expires_at` (from the Login request's `Lease Time`, when supplied)
/// makes stale tickets stop working on their own.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub identity: Identity,
    pub expires_at: Option<OffsetDateTime>,
}

impl SessionRecord {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

/// Per-request authentication outcome the dispatcher threads to op
/// handlers (currently only `Login` consumes it).
#[derive(Clone, Debug, Default)]
pub struct AuthContext {
    /// `Some` when the request was positively authenticated (header
    /// credential verified, or mTLS client identity). `None` in
    /// open-auth mode for credential-free requests.
    pub identity: Option<Identity>,
}

impl AuthContext {
    /// Open-auth / anonymous context (no verified identity).
    pub fn open() -> Self {
        Self { identity: None }
    }
}

/// Verifies one §9.9 `Credential` against some backing store.
pub trait CredentialVerifier: Send + Sync {
    /// `Ok(identity)` when the credential authenticates a known
    /// principal; `Err(())` otherwise. The error is deliberately
    /// information-free — KMIP only speaks
    /// `Authentication Not Successful (0x03)` and we must not leak
    /// whether the username or the password was wrong.
    fn verify(&self, credential: &Credential) -> Result<Identity, ()>;
}

/// One configured user: username + lowercase SHA-256 hex of the
/// password (see module docs for why SHA-256 and not argon2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthUser {
    pub username: String,
    pub password_sha256: String,
}

impl AuthUser {
    /// Parse the CLI flag form `<username>:<sha256hex>` (e.g.
    /// `alice:2bb80d53...908f`). The hash must be exactly 64 hex
    /// digits; case is normalised to lowercase.
    pub fn parse_flag(s: &str) -> Result<Self, String> {
        let (username, hash) = s
            .split_once(':')
            .ok_or_else(|| format!("--auth-user {s:?}: expected <username>:<sha256hex>"))?;
        if username.is_empty() {
            return Err(format!("--auth-user {s:?}: empty username"));
        }
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "--auth-user {s:?}: password hash must be 64 hex chars (sha256), got {} chars",
                hash.len()
            ));
        }
        Ok(Self {
            username: username.to_string(),
            password_sha256: hash.to_ascii_lowercase(),
        })
    }
}

/// Lowercase SHA-256 hex of a UTF-8 string — the stored-password form.
pub fn sha256_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// [`CredentialVerifier`] backed by the static config user list
/// (`DepsConfig::auth_users`).
pub struct ConfigVerifier<'a> {
    users: &'a [AuthUser],
}

impl<'a> ConfigVerifier<'a> {
    pub fn new(users: &'a [AuthUser]) -> Self {
        Self { users }
    }
}

impl CredentialVerifier for ConfigVerifier<'_> {
    fn verify(&self, credential: &Credential) -> Result<Identity, ()> {
        match credential {
            Credential::UsernameAndPassword { username, password } => {
                // §9.9 Table 510 — Password is optional on the wire,
                // but a password-less credential can't authenticate
                // against a password store.
                let password = password.as_deref().ok_or(())?;
                let offered = sha256_hex(password);
                // Scan every user (no early break on username match)
                // so unknown-user and wrong-password take the same
                // path; the digest comparison itself is on fixed-width
                // hex strings.
                let mut matched: Option<&AuthUser> = None;
                for user in self.users {
                    if user.username == *username
                        && constant_time_eq(user.password_sha256.as_bytes(), offered.as_bytes())
                    {
                        matched = Some(user);
                    }
                }
                matched
                    .map(|u| Identity { username: u.username.clone() })
                    .ok_or(())
            }
            // A Ticket credential never verifies against the static
            // config user list — it's checked against the session
            // store instead (`dispatcher::authenticate_request`'s
            // separate ticket-lookup path, since this verifier only
            // has `&[AuthUser]`, not `Deps`).
            Credential::Ticket(_) => Err(()),
            // Decoded-but-unsupported credential types can never
            // verify (K14 supports Username and Password only).
            Credential::Unsupported { .. } => Err(()),
        }
    }
}

/// Constant-time byte-slice equality for the fixed-width (64-char)
/// hex digests. Length mismatch returns false without timing leak
/// concerns (lengths here are public).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Vec<AuthUser> {
        vec![
            AuthUser {
                username: "alice".into(),
                password_sha256: sha256_hex("correct horse"),
            },
            AuthUser {
                username: "bob".into(),
                password_sha256: sha256_hex("hunter2"),
            },
        ]
    }

    fn cred(user: &str, pass: &str) -> Credential {
        Credential::UsernameAndPassword {
            username: user.into(),
            password: Some(pass.into()),
        }
    }

    #[test]
    fn good_password_verifies_and_yields_identity() {
        let users = store();
        let v = ConfigVerifier::new(&users);
        let id = v.verify(&cred("alice", "correct horse")).expect("verifies");
        assert_eq!(id.username, "alice");
    }

    #[test]
    fn bad_password_fails() {
        let users = store();
        let v = ConfigVerifier::new(&users);
        assert!(v.verify(&cred("alice", "wrong")).is_err());
    }

    #[test]
    fn unknown_user_fails() {
        let users = store();
        let v = ConfigVerifier::new(&users);
        assert!(v.verify(&cred("mallory", "correct horse")).is_err());
    }

    #[test]
    fn passwordless_credential_fails() {
        let users = store();
        let v = ConfigVerifier::new(&users);
        let c = Credential::UsernameAndPassword {
            username: "alice".into(),
            password: None,
        };
        assert!(v.verify(&c).is_err());
    }

    #[test]
    fn unsupported_credential_type_fails() {
        let users = store();
        let v = ConfigVerifier::new(&users);
        // Device credential (0x02) — decoded, carried, never verifiable.
        assert!(v.verify(&Credential::Unsupported { credential_type: 0x02 }).is_err());
    }

    #[test]
    fn parse_flag_accepts_well_formed_entry() {
        let hash = sha256_hex("pw");
        let u = AuthUser::parse_flag(&format!("alice:{hash}")).unwrap();
        assert_eq!(u.username, "alice");
        assert_eq!(u.password_sha256, hash);
    }

    #[test]
    fn parse_flag_rejects_malformed_entries() {
        assert!(AuthUser::parse_flag("nocolon").is_err());
        assert!(AuthUser::parse_flag(":deadbeef").is_err());
        assert!(AuthUser::parse_flag("alice:tooshort").is_err());
        assert!(AuthUser::parse_flag(&format!("alice:{}", "zz".repeat(32))).is_err());
    }

    #[test]
    fn sha256_hex_known_vector() {
        // NIST FIPS 180-4 "abc" vector.
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
