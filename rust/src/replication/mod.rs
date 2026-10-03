//! K2–K4 PQCToday key hierarchy, key attestation and protected replication.
//!
//! **EDUCATIONAL SOFTWARE TOKEN ONLY.** Compiled only with the non-default
//! `educational-replication` feature and inert until a caller explicitly
//! selects the educational profile at runtime ([`select_educational_profile`]).
//! It uses the RFC 5612 documentation OID arc, a host-side test
//! manufacturing CA and the host clock; nothing here is hardware-backed,
//! production-identified or rollback-resistant. Every exported artefact must
//! be labelled `PQCTODAY EDUCATIONAL TEST ONLY` by its consumer.
//!
//! Normative inputs: `docs/proposals/pqctoday-key-replication-interface-1.0.md`
//! (K0B), as amended by the dispositions in
//! `docs/k0b-protocol-review-codex-2026-10-02.md` and the design decisions in
//! `docs/k2-k4-replication-implementation-notes-2026-10-02.md`.
//!
//! Layout:
//! - [`oids`], [`asn1`] — identifiers and DER structures;
//! - [`pki`] — certificate/CRL profiles and chain validation;
//! - [`records`] — engine-owned token objects holding hierarchy and ledger state;
//! - [`enroll`] — K2 device enrollment, function issuance, CRLs, policies;
//! - [`evidence`] — K3 key attestation (engine side);
//! - [`host_verify`] — K3/K4 host-side verifier over public bytes only;
//! - [`package`] — K4 create/import/clone, ledger, receipts;
//! - [`test_ca`] — the host-side test manufacturing CA (never token-resident);
//! - `abi` — the separately discovered `PQCTODAY_KEY_REPLICATION_1_0` list.

pub mod admin;
pub mod admin_host;
pub mod asn1;
pub mod enroll;
pub mod evidence;
pub mod fhe;
#[cfg(feature = "educational-fhe")]
pub mod fhe_tfhe;
pub mod host_verify;
pub mod oids;
pub mod package;
pub mod pki;
pub mod records;
pub mod test_ca;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod abi;

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

use crate::constants::*;

pub use enroll::*;
pub use evidence::attest_key;
pub use package::*;

/// Label every consumer must show next to exported artefacts (spec §4.1).
pub const EDUCATIONAL_LABEL: &str = "PQCTODAY EDUCATIONAL TEST ONLY";

// ── Profile (spec §4.1: configuration, never inferred from an input OID) ───

static PROFILE: AtomicU8 = AtomicU8::new(0);
const PROFILE_NONE: u8 = 0;
const PROFILE_EDUCATIONAL: u8 = 1;

/// Validator profile. There is no production profile with real OIDs yet
/// (G2); [`Profile::Production`] exists so validators can prove they reject
/// the documentation arc outside education.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Profile {
    Educational,
    Production,
}

/// Explicitly enable the educational profile for this process.
pub fn select_educational_profile() {
    PROFILE.store(PROFILE_EDUCATIONAL, Ordering::SeqCst);
}

/// Return to the default (no replication service available).
pub fn clear_profile() {
    PROFILE.store(PROFILE_NONE, Ordering::SeqCst);
}

pub fn educational_profile_selected() -> bool {
    PROFILE.load(Ordering::SeqCst) == PROFILE_EDUCATIONAL
}

pub(crate) fn require_profile() -> Result<(), u32> {
    if educational_profile_selected() {
        Ok(())
    } else {
        Err(CKR_FUNCTION_NOT_SUPPORTED)
    }
}

// ── Host clock (owner decision 7) ──────────────────────────────────────────

static CLOCK_OVERRIDE: AtomicU64 = AtomicU64::new(0);

/// Pin the host clock (seconds since the Unix epoch) for tests of expiry and
/// freshness; `None` returns to the real clock. Part of the non-shipping
/// educational feature only.
pub fn set_clock_override(unix_secs: Option<u64>) {
    CLOCK_OVERRIDE.store(unix_secs.unwrap_or(0), Ordering::SeqCst);
}

pub fn now_unix() -> u64 {
    match CLOCK_OVERRIDE.load(Ordering::SeqCst) {
        0 => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        t => t,
    }
}

// ── Crash injection (review K0B-R-09; spec §12 "every crash window") ───────

/// Points at which a test can abort an operation as a crash would: the
/// operation returns `CKR_DEVICE_ERROR` with exactly the durable state
/// written up to that point and nothing after it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CrashPoint {
    /// Source: package signed, before the cache/budget/challenge commit.
    CreateBeforeCommit,
    /// Destination: after the durable reservation.
    ImportAfterReserve,
    /// Destination: after decapsulation and decryption.
    ImportAfterDecrypt,
    /// Destination: objects and receipt staged, before the atomic commit.
    ImportBeforeCommit,
    /// Destination: after the atomic commit, before the handle/receipt return.
    ImportAfterCommit,
}

static CRASH_AT: Mutex<Option<CrashPoint>> = Mutex::new(None);

/// Arm (or disarm) one crash point; it fires once.
pub fn inject_crash(point: Option<CrashPoint>) {
    *CRASH_AT.lock().unwrap_or_else(|e| e.into_inner()) = point;
}

pub(crate) fn crash_check(point: CrashPoint) -> Result<(), u32> {
    let mut g = CRASH_AT.lock().unwrap_or_else(|e| e.into_inner());
    if *g == Some(point) {
        *g = None;
        return Err(CKR_DEVICE_ERROR);
    }
    Ok(())
}

// ── Crypto helpers (production randomness only) ────────────────────────────

pub(crate) fn sha384(data: &[u8]) -> [u8; 48] {
    use sha2::Digest;
    sha2::Sha384::digest(data).into()
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

/// 32 bytes from the OS RNG. Never the ACVP deterministic RNG.
pub(crate) fn random32() -> Result<[u8; 32], u32> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|_| CKR_DEVICE_ERROR)?;
    Ok(b)
}

pub(crate) fn mldsa65_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, u32> {
    crate::crypto::handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, sk, msg, &[], false)
        .map_err(|_| CKR_DEVICE_ERROR)
}

pub(crate) fn mldsa65_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    crate::crypto::handlers::verify_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, pk, msg, sig, &[]).is_ok()
}

/// Fresh ML-DSA-65 key pair `(pk, sk)` from a fresh 32-byte seed.
pub(crate) fn mldsa65_keygen() -> Result<(Vec<u8>, Vec<u8>), u32> {
    let xi = random32()?;
    crate::crypto::handlers::ml_dsa_keygen_from_seed(CKP_ML_DSA_65, &xi).ok_or(CKR_DEVICE_ERROR)
}

/// Fresh ML-KEM-768 key pair `(ek, dk)` from a fresh `d ‖ z`.
pub(crate) fn mlkem768_keygen() -> Result<(Vec<u8>, Vec<u8>), u32> {
    let mut dz = [0u8; 64];
    getrandom::getrandom(&mut dz).map_err(|_| CKR_DEVICE_ERROR)?;
    let r = crate::crypto::handlers::ml_kem_keygen_from_seed(CKP_ML_KEM_768, &dz)
        .ok_or(CKR_DEVICE_ERROR);
    zeroize::Zeroize::zeroize(&mut dz);
    r
}

/// Remove an object from the table (and the durable store) without the
/// caller-facing destroy rules. Used to undo a just-generated key whose
/// binding failed, before its handle is ever returned.
pub fn discard_object(handle: u32) {
    if handle == 0 {
        return;
    }
    let removed = crate::state::OBJECTS.with(|o| o.borrow_mut().remove(&handle));
    if let Some(mut attrs) = removed {
        let slot = crate::state::object_slot_of(&attrs);
        if let Some(v) = attrs.get_mut(&CKA_VALUE) {
            zeroize::Zeroize::zeroize(v);
        }
        if crate::store::is_persistent() {
            crate::store::persist_delete(slot, handle);
        }
    }
}

// ── Session/role helpers (spec §9 precedence 3–4) ──────────────────────────

pub(crate) fn session_slot_checked(h_session: u32) -> Result<u32, u32> {
    if !crate::state::is_initialized() {
        return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    crate::state::session_slot(h_session).ok_or(CKR_SESSION_HANDLE_INVALID)
}

/// SO-only operations: a user session gets CKR_USER_TYPE_INVALID, a public
/// session CKR_USER_NOT_LOGGED_IN.
pub(crate) fn require_so(h_session: u32) -> Result<u32, u32> {
    let slot = session_slot_checked(h_session)?;
    if crate::state::session_is_so(h_session) {
        if !crate::state::session_is_rw(h_session) {
            return Err(CKR_SESSION_READ_ONLY);
        }
        return Ok(slot);
    }
    if crate::state::session_user_logged_in(h_session) {
        return Err(CKR_USER_TYPE_INVALID);
    }
    Err(CKR_USER_NOT_LOGGED_IN)
}

/// Mutating user operations additionally need a R/W session (PKCS#11
/// §5.7; review K0B-R2-06): they create or update token objects.
pub(crate) fn require_user_rw(h_session: u32) -> Result<u32, u32> {
    let slot = require_user(h_session)?;
    if !crate::state::session_is_rw(h_session) {
        return Err(CKR_SESSION_READ_ONLY);
    }
    Ok(slot)
}

/// User operations (create/import/clone/attest): the SO cannot use a user's
/// key (spec §4).
pub(crate) fn require_user(h_session: u32) -> Result<u32, u32> {
    let slot = session_slot_checked(h_session)?;
    if crate::state::session_user_logged_in(h_session) {
        return Ok(slot);
    }
    if crate::state::session_is_so(h_session) {
        return Err(CKR_USER_TYPE_INVALID);
    }
    Err(CKR_USER_NOT_LOGGED_IN)
}

// ── Policy binding at key generation (spec §8; plan invariants 1–2) ────────

/// Extract a binding request from a raw generation template. Only
/// `CKA_PQCTODAY_REPLICATION_POLICY_ID` (exactly 48 bytes) may be named; the
/// three engine-computed attributes are refused.
///
/// # Safety
/// Same contract as `crypto::handlers::absorb_template_attrs`.
pub unsafe fn binding_request_from_template(template: *mut u8, count: u32) -> Result<Vec<u8>, u32> {
    use crate::crypto::handlers::{find_template_entry, template_has_replication_attr};
    for t in [
        CKA_PQCTODAY_REPLICATION_LINEAGE_ID,
        CKA_PQCTODAY_REPLICATION_PROVENANCE,
        CKA_PQCTODAY_FUNCTION_PURPOSE,
    ] {
        if find_template_entry(template, count, t).is_some() {
            return Err(CKR_ATTRIBUTE_READ_ONLY);
        }
    }
    debug_assert!(template_has_replication_attr(template, count));
    match find_template_entry(template, count, CKA_PQCTODAY_REPLICATION_POLICY_ID) {
        Some(v) if v.len() == 48 => Ok(v),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID),
    }
}

/// Bind a just-generated key to an enrolled policy, or fail (the FFI caller
/// then discards the key). Eligibility is opt-in and fixed at creation:
/// AES-128/192/256, ML-KEM-768 and ML-DSA-65 only, generated in this token
/// (`CKA_LOCAL`), token-resident, sensitive, non-extractable, non-copyable,
/// non-modifiable, non-derivable.
pub fn bind_generated_key(
    h_session: u32,
    mechanism: u32,
    h_private: u32,
    h_public: Option<u32>,
    policy_id: &[u8],
) -> Result<(), u32> {
    require_profile()?;
    let slot = require_user(h_session)?;
    let expected = match mechanism {
        CKM_AES_KEY_GEN => (CKO_SECRET_KEY, CKK_AES),
        CKM_ML_KEM_KEY_PAIR_GEN => (CKO_PRIVATE_KEY, CKK_ML_KEM),
        CKM_ML_DSA_KEY_PAIR_GEN => (CKO_PRIVATE_KEY, CKK_ML_DSA),
        _ => return Err(CKR_TEMPLATE_INCONSISTENT),
    };
    let policy = records::find_policy(slot, policy_id).ok_or(CKR_TEMPLATE_INCONSISTENT)?;
    let attrs = records::object_attrs(h_private).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let u32_of = |t| crate::state::get_object_attr_u32_from(&attrs, t);
    let b = |t| crate::state::read_bool_attr(&attrs, t);
    if (u32_of(CKA_CLASS), u32_of(CKA_KEY_TYPE)) != (Some(expected.0), Some(expected.1)) {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    match expected.1 {
        CKK_AES => {
            let len = attrs.get(&CKA_VALUE).map(|v| v.len()).unwrap_or(0);
            if ![16, 24, 32].contains(&len) {
                return Err(CKR_TEMPLATE_INCONSISTENT);
            }
        }
        CKK_ML_KEM if crate::state::get_object_param_set_from(&attrs) != CKP_ML_KEM_768 => {
            return Err(CKR_TEMPLATE_INCONSISTENT)
        }
        CKK_ML_DSA if crate::state::get_object_param_set_from(&attrs) != CKP_ML_DSA_65 => {
            return Err(CKR_TEMPLATE_INCONSISTENT)
        }
        _ => {}
    }
    if !b(CKA_TOKEN)
        || !b(CKA_SENSITIVE)
        || b(CKA_EXTRACTABLE)
        || b(CKA_COPYABLE)
        || b(CKA_MODIFIABLE)
        || !b(CKA_LOCAL)
        || b(CKA_DERIVE)
    {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    // Review K0B-R2-01: version 1's payload carries usage flags only, so a
    // key whose restriction templates would not survive replication is not
    // eligible — otherwise the replica would silently be less restricted
    // than the source (spec §8 "may not remove a source restriction").
    const RESTRICTIONS: [u32; 5] = [
        CKA_WRAP_TEMPLATE,
        CKA_UNWRAP_TEMPLATE,
        CKA_DERIVE_TEMPLATE,
        CKA_ENCAPSULATE_TEMPLATE,
        CKA_DECAPSULATE_TEMPLATE,
    ];
    let restricted = |a: &crate::crypto::handlers::Attributes| {
        RESTRICTIONS.iter().any(|t| a.get(t).map(|v| !v.is_empty()).unwrap_or(false))
            || crate::state::read_bool_attr(a, CKA_WRAP_WITH_TRUSTED)
    };
    if restricted(&attrs) || h_public.and_then(records::object_attrs).map(|p| restricted(&p)).unwrap_or(false) {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    let now = now_unix();
    let pol = records::parse_policy(&policy)?;
    // v1 key profiles take only the unconstrained policy profile; an FHE
    // profile policy can never bind an AES/ML-KEM/ML-DSA key (FHE P1).
    if pol.type_constraint_hash != sha384(b"") {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    if now < pol.not_before || now >= pol.not_after {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    // The key's ordinary operations are exactly the policy's allowlist
    // (spec §8: an empty list permits none). A template that asked for a
    // different list is inconsistent rather than silently overridden.
    let policy_mechs = crate::replication::records::encode_mechanisms(&pol.allowed_mechanisms);
    if let Some(existing) = attrs.get(&CKA_ALLOWED_MECHANISMS) {
        let mut have = crate::state::parse_allowed_mechanisms(existing);
        have.sort_unstable();
        if !existing.is_empty() && have != pol.allowed_mechanisms {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
    }
    let lineage = random32()?;
    let mut changes = vec![
        (CKA_PQCTODAY_REPLICATION_POLICY_ID, policy_id.to_vec()),
        (CKA_PQCTODAY_REPLICATION_LINEAGE_ID, lineage.to_vec()),
        (CKA_PRIV_REPL_BINDING, policy_id.to_vec()),
        (CKA_PRIV_REPL_BUDGET, pol.max_replicas.to_le_bytes().to_vec()),
        (CKA_ALLOWED_MECHANISMS, policy_mechs),
    ];
    let mut updates = vec![(h_private, std::mem::take(&mut changes))];
    if let Some(h_pub) = h_public {
        updates.push((
            h_pub,
            vec![(CKA_PQCTODAY_REPLICATION_LINEAGE_ID, lineage.to_vec())],
        ));
    }
    crate::state::commit_objects_atomically(h_session, Vec::new(), updates)?;
    oplog_event("bind", slot, &[("policy", hex(policy_id)), ("lineage", hex(&lineage))]);
    Ok(())
}

/// F16 audit: one `oplog` record per replication event, carrying public
/// identifiers and digests only — never key material, plaintext or a PIN.
pub(crate) fn oplog_event(op: &str, slot: u32, fields: &[(&str, String)]) {
    if !crate::oplog::enabled() {
        return;
    }
    let mut tail = format!("slot={slot} profile=educational");
    for (k, v) in fields {
        tail.push_str(&format!(" {k}={v}"));
    }
    crate::oplog::emit(&format!("replication_{op}"), &tail);
}

static LAST_REFUSAL: Mutex<Option<&'static str>> = Mutex::new(None);

/// Record a refusal reason (audit only — never returned to a caller).
pub(crate) fn note_refusal(reason: &'static str) {
    *LAST_REFUSAL.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason);
}

/// The most recent refusal reason in this process. Tests use it to prove a
/// negative case was refused for the reason it claims (review K0B-R2-07);
/// callers of the interface only ever see `CKR_ACTION_PROHIBITED`.
pub fn last_refusal() -> Option<&'static str> {
    *LAST_REFUSAL.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
