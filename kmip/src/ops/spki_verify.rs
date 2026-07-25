//! Engine-backed `SubjectPublicKeyInfo` signature verification — the
//! shared primitive Certify's CSR self-signature check (WP2) and
//! Validate's chain-link signature check (WP3) both build on.
//!
//! Given an arbitrary SPKI (from an inbound PKCS#10 CSR or a candidate
//! X.509 certificate — never a KMIP-managed object with an existing
//! engine handle), this imports it into the engine as a TRANSIENT
//! `CKO_PUBLIC_KEY` session object via the `register_*_public_key` family
//! (WP1a, `rust/src/native/keygen.rs`), runs `C_VerifyInit`/`C_Verify`
//! against it, and destroys the transient object on every exit path (an
//! RAII guard, not a happy-path-only cleanup) — a caller-supplied SPKI
//! never lingers in the engine's live object table.
//!
//! Per invariant 0a (`kmip` crate: DER/TTLV encoding + request
//! orchestration only, no cryptography — see the cert-ops plan's §0a/0b),
//! the only "crypto-shaped" code in this file is ASN.1 SIGNATURE
//! REFORMATTING: X.509 carries ECDSA signatures as a DER
//! `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279
//! §2.2.3); PKCS#11 expects fixed-width raw `r || s`. That is a byte
//! layout change on an already-computed signature, not a cryptographic
//! computation — `certify.rs::ecdsa_raw_to_der` already performs the
//! inverse conversion for issuance; [`ecdsa_der_to_raw`] here is that
//! same transform run backwards, over the identical `Ecdsa-Sig-Value`
//! shape.
//!
//! Unlike `validate.rs`/`certify.rs`, this module has no `native`-only
//! crypto backend (no `rcgen`, no `ring`) — it is pure `spki`/`der` plus
//! calls into `softhsmrustv3`, which already builds clean for
//! `wasm32-unknown-unknown`. It is declared unconditionally so it is
//! ready for wasm callers once WP4 removes the `native` gate from
//! Certify/Validate themselves.

use der::asn1::UintRef;
use der::{Decode, Encode, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::error::{KmipError, Result, ResultReason};

#[cfg(test)]
use super::deps::Deps;

/// The three-way verdict [`verify_with_spki`] returns — mirrors KMIP's
/// own Signature Verify / Validate contract (§6.1.63/§6.1.64): a
/// cryptographically negative result is not an error, and an algorithm
/// this server cannot evaluate is reported honestly rather than folded
/// into either `Valid` or `Invalid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpkiVerdict {
    Valid,
    Invalid,
    UnsupportedAlgorithm,
}

// Signature-algorithm OIDs. Mirrors `certify.rs`'s issuance-side table —
// see that file's module doc for the citations backing each value. Kept
// as a separate table (not `pub(crate)`-shared) because the two files
// read it in opposite directions: certify.rs picks an OID FROM an
// algorithm; this file picks a mechanism FROM an OID.
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
const OID_ML_DSA_44: &str = "2.16.840.1.101.3.4.3.17";
const OID_ML_DSA_65: &str = "2.16.840.1.101.3.4.3.18";
const OID_ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";
const OID_ED25519: &str = "1.3.101.112";

/// `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — the mirror
/// image of `certify.rs::EcdsaSigValue`.
#[derive(Sequence)]
struct EcdsaSigValue<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// Decode an X.509 DER ECDSA signature into PKCS#11's fixed-width raw
/// `r || s`, zero-padded to `field_width` bytes each half. See the
/// module doc's invariant-0a note: this is ASN.1 reformatting of an
/// already-computed signature, not a crypto computation.
fn ecdsa_der_to_raw(der_sig: &[u8], field_width: usize) -> Result<Vec<u8>> {
    let sig = EcdsaSigValue::from_der(der_sig).map_err(|e| {
        KmipError::failed(ResultReason::CryptographicFailure, format!("ECDSA signature DER: {e}"))
    })?;
    let (r, s) = (sig.r.as_bytes(), sig.s.as_bytes());
    if r.len() > field_width || s.len() > field_width {
        return Err(KmipError::failed(
            ResultReason::CryptographicFailure,
            format!("ECDSA signature INTEGER wider than the {field_width}-byte curve field"),
        ));
    }
    let mut out = vec![0u8; field_width * 2];
    out[field_width - r.len()..field_width].copy_from_slice(r);
    out[field_width * 2 - s.len()..].copy_from_slice(s);
    Ok(out)
}

fn der_err(e: der::Error) -> KmipError {
    KmipError::failed(ResultReason::CryptographicFailure, format!("DER encode: {e}"))
}

/// Which `register_*_public_key` import function to transiently register
/// `spki` under, plus the engine mechanism and (already-reformatted-if-
/// needed) signature bytes to verify with.
enum Plan {
    Rsa { mech: u32, sig: Vec<u8> },
    Ecdsa { mech: u32, sig: Vec<u8> },
    Ed25519 { mech: u32, sig: Vec<u8> },
    MlDsa { mech: u32, param_set: u32, sig: Vec<u8> },
}

fn plan_for(sig_alg: &AlgorithmIdentifierOwned, sig: &[u8]) -> Result<Option<Plan>> {
    use softhsmrustv3::constants as c;
    let oid = sig_alg.oid.to_string();
    Ok(Some(match oid.as_str() {
        OID_RSA_SHA256 => Plan::Rsa { mech: c::CKM_SHA256_RSA_PKCS, sig: sig.to_vec() },
        OID_ECDSA_SHA256 => {
            Plan::Ecdsa { mech: c::CKM_ECDSA_SHA256, sig: ecdsa_der_to_raw(sig, 32)? }
        }
        OID_ECDSA_SHA384 => {
            Plan::Ecdsa { mech: c::CKM_ECDSA_SHA384, sig: ecdsa_der_to_raw(sig, 48)? }
        }
        OID_ECDSA_SHA512 => {
            Plan::Ecdsa { mech: c::CKM_ECDSA_SHA512, sig: ecdsa_der_to_raw(sig, 66)? }
        }
        OID_ML_DSA_44 => {
            Plan::MlDsa { mech: c::CKM_ML_DSA, param_set: c::CKP_ML_DSA_44, sig: sig.to_vec() }
        }
        OID_ML_DSA_65 => {
            Plan::MlDsa { mech: c::CKM_ML_DSA, param_set: c::CKP_ML_DSA_65, sig: sig.to_vec() }
        }
        OID_ML_DSA_87 => {
            Plan::MlDsa { mech: c::CKM_ML_DSA, param_set: c::CKP_ML_DSA_87, sig: sig.to_vec() }
        }
        OID_ED25519 => Plan::Ed25519 { mech: c::CKM_EDDSA, sig: sig.to_vec() },
        _ => return Ok(None),
    }))
}

/// Destroys the transient engine object on drop — every exit path from
/// [`verify_with_spki`] (success, verify failure, or engine error) runs
/// this, not just the happy path.
struct DestroyOnDrop {
    session: u32,
    handle: u32,
}

impl Drop for DestroyOnDrop {
    fn drop(&mut self) {
        let _ = softhsmrustv3::native::destroy_object(self.session, self.handle);
    }
}

/// Verify `sig` over `msg` under `sig_alg`, using `spki` as the public
/// key — transiently imported into the engine and destroyed before this
/// returns. `Ok(SpkiVerdict::UnsupportedAlgorithm)` (not an `Err`) for a
/// `sig_alg` OID this server has no mechanism for, matching KMIP's
/// honest-degrade contract for Signature Verify / Validate.
///
/// Part F §F7 — `session` is the CALLER's already-resolved
/// `deps.resolve_tenant_session(...)` result (this helper has no auth
/// context of its own; reading the bare `deps.engine_session` field
/// here, as it did before, silently ignored tenancy). The key material
/// verified against is caller-supplied bytes, not a stored object — but
/// the transient import still creates (and destroys) an object inside
/// whatever token `session` names, so it must be the caller's own.
pub fn verify_with_spki(
    session: Option<u32>,
    spki: &SubjectPublicKeyInfoOwned,
    sig_alg: &AlgorithmIdentifierOwned,
    msg: &[u8],
    sig: &[u8],
) -> Result<SpkiVerdict> {
    use softhsmrustv3::constants::CKR_SIGNATURE_INVALID;

    let session = session.ok_or_else(|| {
        KmipError::failed(
            ResultReason::CryptographicFailure,
            "verify_with_spki: no engine session — cannot verify without key material",
        )
    })?;

    let plan = match plan_for(sig_alg, sig)? {
        Some(p) => p,
        None => return Ok(SpkiVerdict::UnsupportedAlgorithm),
    };

    let spki_der = spki.to_der().map_err(der_err)?;
    const TRANSIENT_ID: &[u8] = b"\x00";
    const TRANSIENT_LABEL: &str = "spki-verify-transient";

    let (mech, native_sig, import) = match &plan {
        Plan::Rsa { mech, sig } => (
            *mech,
            sig.clone(),
            softhsmrustv3::native::register_rsa_public_key_der(
                session,
                &spki_der,
                TRANSIENT_ID,
                TRANSIENT_LABEL,
            ),
        ),
        Plan::Ecdsa { mech, sig } => (
            *mech,
            sig.clone(),
            softhsmrustv3::native::register_ecdsa_public_key(
                session,
                &spki_der,
                TRANSIENT_ID,
                TRANSIENT_LABEL,
            ),
        ),
        Plan::Ed25519 { mech, sig } => (
            *mech,
            sig.clone(),
            softhsmrustv3::native::register_ed25519_public_key(
                session,
                &spki_der,
                TRANSIENT_ID,
                TRANSIENT_LABEL,
            ),
        ),
        Plan::MlDsa { mech, param_set, sig } => {
            let pk_bytes = spki.subject_public_key.raw_bytes();
            (
                *mech,
                sig.clone(),
                softhsmrustv3::native::register_ml_dsa_public_key(
                    session,
                    *param_set,
                    pk_bytes,
                    TRANSIENT_ID,
                    TRANSIENT_LABEL,
                ),
            )
        }
    };

    let handle =
        import.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "verify_with_spki:import"))?;
    let _guard = DestroyOnDrop { session, handle };

    let ok = if super::helpers::is_pqc_sign_mech(mech) {
        match softhsmrustv3::native::verify_pqc(session, handle, mech, msg, &native_sig, &[], false, false)
        {
            Ok(()) => true,
            Err(rv) if rv == CKR_SIGNATURE_INVALID => false,
            Err(rv) => return Err(super::helpers::ck_rv_to_kmip_error(rv, "verify_with_spki:verify")),
        }
    } else {
        softhsmrustv3::native::verify(session, handle, mech, msg, &native_sig)
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "verify_with_spki:verify"))?
    };

    Ok(if ok { SpkiVerdict::Valid } else { SpkiVerdict::Invalid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use der::oid::ObjectIdentifier;

    use crate::auditlog::{AuditSink, RingSink};
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps_with_session(session: u32) -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
            .with_engine_session(session)
    }

    /// Shared crate-wide lock (`ops::helpers::engine_lock`) — a lock
    /// private to this file's tests would only serialise against
    /// *itself*, not against `certify.rs`'s engine-touching tests running
    /// on another thread of the same `cargo test` binary, which still
    /// race on the engine's process-global session/token state.
    use super::super::helpers::engine_lock;

    fn fresh_session() -> (u32, std::sync::MutexGuard<'static, ()>) {
        use softhsmrustv3::native::session::{bootstrap_default_token, finalize, init};
        let guard = engine_lock();
        let _ = finalize();
        init().unwrap();
        let session = bootstrap_default_token(0, "so", "user", "spki-verify-test").unwrap();
        (session, guard)
    }

    fn alg_id(oid_str: &str) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned { oid: ObjectIdentifier::from_str(oid_str).unwrap(), parameters: None }
    }

    /// End-to-end ECDSA P-256: generate a real keypair in the engine,
    /// sign, export the real `CKA_PUBLIC_KEY_INFO` SPKI, DER-wrap the raw
    /// signature (mirroring what an X.509 cert / CSR actually carries),
    /// then verify through `verify_with_spki` exactly as Certify/Validate
    /// will call it.
    #[test]
    fn ecdsa_p256_valid_and_tampered_signature() {
        let (session, _guard) = fresh_session();
        let deps = deps_with_session(session);

        let (pub_h, prv_h) = softhsmrustv3::native::generate_ecdsa_keypair(
            session,
            softhsmrustv3::native::EccCurve::P256,
            b"\x01",
            "ecdsa-spki-verify-kat",
        )
        .unwrap();
        let msg = b"spki_verify KAT";
        let raw_sig = softhsmrustv3::native::sign(session, prv_h, softhsmrustv3::constants::CKM_ECDSA_SHA256, msg).unwrap();
        let der_sig = { // r || s (64B for P-256) -> DER Ecdsa-Sig-Value, the X.509 wire form.
            let (r, s) = raw_sig.split_at(raw_sig.len() / 2);
            EcdsaSigValue { r: UintRef::new(r).unwrap(), s: UintRef::new(s).unwrap() }.to_der().unwrap()
        };
        let spki_der = softhsmrustv3::native::get_attribute(session, pub_h, softhsmrustv3::constants::CKA_PUBLIC_KEY_INFO).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der).unwrap();
        let sig_alg = alg_id(OID_ECDSA_SHA256);

        let verdict = verify_with_spki(deps.engine_session, &spki, &sig_alg, msg, &der_sig).unwrap();
        assert_eq!(verdict, SpkiVerdict::Valid);

        let mut tampered = der_sig.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        // A flipped byte in the DER wrapper: either it fails to parse as
        // a valid Ecdsa-Sig-Value (CryptographicFailure) or it parses but
        // no longer verifies (Invalid) — either is an honest "not valid",
        // never a false Valid.
        match verify_with_spki(deps.engine_session, &spki, &sig_alg, msg, &tampered) {
            Ok(v) => assert_eq!(v, SpkiVerdict::Invalid),
            Err(e) => assert_eq!(e.result_reason(), ResultReason::CryptographicFailure),
        }

        softhsmrustv3::native::close_session(session).unwrap();
    }

    /// Unrecognized signature-algorithm OID → honest `UnsupportedAlgorithm`,
    /// never silently `Valid`/`Invalid`, and no engine session is touched.
    #[test]
    fn unsupported_algorithm_oid_is_honest_not_error() {
        let (session, _guard) = fresh_session();
        let deps = deps_with_session(session);

        let (pub_h, _) = softhsmrustv3::native::generate_ecdsa_keypair(
            session,
            softhsmrustv3::native::EccCurve::P256,
            b"\x01",
            "unsupported-alg-kat",
        )
        .unwrap();
        let spki_der = softhsmrustv3::native::get_attribute(session, pub_h, softhsmrustv3::constants::CKA_PUBLIC_KEY_INFO).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der).unwrap();
        // MD5-with-RSA (1.2.840.113549.1.1.4) — a real OID, deliberately
        // not in the supported table.
        let sig_alg = alg_id("1.2.840.113549.1.1.4");

        let verdict = verify_with_spki(deps.engine_session, &spki, &sig_alg, b"x", b"not a real signature").unwrap();
        assert_eq!(verdict, SpkiVerdict::UnsupportedAlgorithm);

        softhsmrustv3::native::close_session(session).unwrap();
    }

    /// No engine session wired → fails closed (`CryptographicFailure`),
    /// never a placeholder verify — this helper has no engine-less
    /// fallback path (unlike `signature_verify.rs`'s stored-object path,
    /// which only ever verifies against KMIP-managed keys).
    #[test]
    fn no_engine_session_fails_closed() {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        let deps = Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default());

        // A structurally-valid but arbitrary SPKI — never reached, since
        // the missing-session check happens before any parsing/import.
        let (session, _guard) = fresh_session();
        let (pub_h, _) = softhsmrustv3::native::generate_ecdsa_keypair(
            session,
            softhsmrustv3::native::EccCurve::P256,
            b"\x01",
            "no-session-kat",
        )
        .unwrap();
        let spki_der = softhsmrustv3::native::get_attribute(session, pub_h, softhsmrustv3::constants::CKA_PUBLIC_KEY_INFO).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der).unwrap();
        let sig_alg = alg_id(OID_ECDSA_SHA256);

        let err = verify_with_spki(deps.engine_session, &spki, &sig_alg, b"x", b"y").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::CryptographicFailure);
        softhsmrustv3::native::close_session(session).unwrap();
    }

    /// The transient import handle must not survive `verify_with_spki` —
    /// proves `DestroyOnDrop` actually runs, not just that it compiles.
    #[test]
    fn transient_object_is_destroyed_after_verify() {
        let (session, _guard) = fresh_session();
        let deps = deps_with_session(session);

        let (pub_h, prv_h) = softhsmrustv3::native::generate_ecdsa_keypair(
            session,
            softhsmrustv3::native::EccCurve::P256,
            b"\x01",
            "destroy-kat",
        )
        .unwrap();
        let msg = b"destroy-on-drop KAT";
        let raw_sig = softhsmrustv3::native::sign(session, prv_h, softhsmrustv3::constants::CKM_ECDSA_SHA256, msg).unwrap();
        let der_sig = {
            let (r, s) = raw_sig.split_at(raw_sig.len() / 2);
            EcdsaSigValue { r: UintRef::new(r).unwrap(), s: UintRef::new(s).unwrap() }.to_der().unwrap()
        };
        let spki_der = softhsmrustv3::native::get_attribute(session, pub_h, softhsmrustv3::constants::CKA_PUBLIC_KEY_INFO).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der).unwrap();
        let sig_alg = alg_id(OID_ECDSA_SHA256);

        // Transient imports use CKA_ID = TRANSIENT_ID = b"\x00", distinct
        // from this test's own b"\x01" keys, so a lookup by that ID
        // finding nothing after the call proves cleanup ran.
        verify_with_spki(deps.engine_session, &spki, &sig_alg, msg, &der_sig).unwrap();
        let leftover = softhsmrustv3::native::find_all_by_cka_id(session, b"\x00").unwrap();
        assert!(leftover.is_empty(), "transient verify object was not destroyed: {leftover:?}");

        softhsmrustv3::native::close_session(session).unwrap();
    }
}
