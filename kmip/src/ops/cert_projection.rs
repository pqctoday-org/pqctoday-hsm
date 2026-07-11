//! PKCS#11 v3.2 §4.6 — mirror a KMIP-managed certificate onto the engine as a
//! `CKO_CERTIFICATE` object, so a raw PKCS#11 client (strongSwan, the OpenSSL
//! provider) can find what KMIP issued/registered/imported.
//!
//! Split out of `certify.rs` (2026-07) — that module is `#[cfg(feature =
//! "native")]`-gated because its actual Certify/Re-certify issuance logic
//! depends on rcgen/aws_lc_rs, which don't cross-compile to wasm32. This one
//! function doesn't: it only touches `der_x509` (pure Rust, x509-parser) and
//! `softhsmrustv3::native`, both wasm32-safe, but `register_import_export.rs`
//! (Register/Import — ordinary KMIP ops, very much needed in the wasm build)
//! called it unconditionally, which made the wasm32 build fail to compile the
//! moment certificate support existed at all. Living in its own always-compiled
//! module lets `certify.rs` stay native-only while Register/Import work in
//! every build.

use super::deps::Deps;

/// KMIP remains authoritative for the certificate's lifecycle; this is a
/// best-effort projection — a failure here doesn't fail the KMIP operation
/// (same posture as the `CKA_ALLOWED_MECHANISMS` auto-restrict), since the
/// certificate is already correctly and durably stored in the KMIP record
/// either way. No engine session (e.g. crate unit tests) is a silent,
/// unaudited no-op — the common, expected case, not worth an audit event.
///
/// An engine session present but no Subject extracted
/// (`der_x509::extract_subject_der` returning empty) emits a
/// `Pkcs11Call`-shaped audit event instead of silently vanishing, so an
/// operator can tell this specific certificate's PKCS#11-side mirror never
/// materialized. In practice this only happens for genuinely unparseable
/// DER — a certificate that parses at all always yields a non-empty raw
/// Subject encoding (even an empty RDNSequence DER-encodes to a 2-byte
/// `30 00`, never zero bytes), so `register()`'s own parseability guard
/// means ordinary client-supplied DER can no longer reach this branch at
/// all; it remains a safety net for the server-generated paths
/// (`bootstrap_ca_certificate`, `Certify`, `Re-certify`), where hitting it
/// would indicate a real bug upstream.
pub(crate) fn project_certificate_to_engine(
    deps: &Deps,
    correlation_id: &str,
    op: &str,
    uid: &str,
    cert_der: &[u8],
    cka_id: &[u8],
    category: u32,
) {
    let Some(session) = deps.engine_session else {
        return;
    };
    let subject = super::der_x509::extract_subject_der(cert_der).unwrap_or_default();
    if subject.is_empty() {
        // No Subject extracted — nothing sane to project; KMIP's own copy
        // is still correct and unaffected. Worth flagging (unlike the "no
        // engine session" case above): in practice this means the DER
        // didn't parse at all (see this function's doc comment) — an
        // operator should be able to tell this certificate's engine
        // mirror silently never appeared.
        super::helpers::emit_pkcs11(
            deps,
            correlation_id,
            &format!("cert_projection::project_certificate_to_engine({op})"),
            None,
            0xFFFF_FFFF,
            &format!("skipped: no Subject extracted from {}-byte DER for {uid:?}", cert_der.len()),
        );
        return;
    }
    let issuer = super::der_x509::extract_issuer_der(cert_der).unwrap_or_default();
    let serial = super::der_x509::extract_serial_number(cert_der).unwrap_or_default();
    let r = softhsmrustv3::native::register_certificate(
        session, cert_der, &subject, &issuer, &serial, category, cka_id, "kmip-cert",
    );
    super::helpers::emit_pkcs11_result(
        deps,
        correlation_id,
        &format!("native::register_certificate({op})"),
        None,
        &r,
    );
}
