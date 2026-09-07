//! X.509 DER → KMIP §11 Certificate attribute extraction.
//!
//! KMIP 3.0 §11 mandates that the `Certificate Subject CN`,
//! `Certificate Length`, `Certificate Issuer CN` (and the rest of the
//! Certificate-Subject-* / Certificate-Issuer-* family) attributes are
//! server-derived from the `Certificate Value` DER bytes supplied via
//! Register / Import. PKCS#11 has no certificate-encoding capability —
//! it stores the DER as an opaque `CKA_VALUE` byte blob on a
//! `CKO_CERTIFICATE` object — so the parsing job lives here in the
//! KMIP crate.
//!
//! We use [`x509-parser`](https://docs.rs/x509-parser) (no-std-capable
//! RFC 5280 parser; MIT/Apache) instead of hand-rolled DER walking so
//! we get the full attribute surface in five-line helpers.

use der::Decode;
use x509_parser::prelude::*;

/// Extract the Subject Name commonName RDN value (OID 2.5.4.3) from
/// an X.509 DER blob. Returns `None` if the DER is malformed, has no
/// `CN` RDN, or the value isn't representable as UTF-8.
pub fn extract_subject_cn(der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok().map(String::from))
}

/// Raw DER encoding of the certificate's Subject `Name` field — PKCS#11
/// v3.2 §4.6.3 `CKA_SUBJECT` is defined as exactly this (not the CN
/// string). `x509_parser::X509Name` retains the raw bytes it was parsed
/// from, so this is a slice, not a re-encode.
pub fn extract_subject_der(der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    Some(cert.subject().as_raw().to_vec())
}

/// Raw DER encoding of the certificate's Issuer `Name` field — PKCS#11
/// v3.2 §4.6.3 `CKA_ISSUER`.
pub fn extract_issuer_der(der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    Some(cert.issuer().as_raw().to_vec())
}

/// Raw (big-endian, as encoded) serial number bytes — PKCS#11 v3.2 §4.6.3
/// `CKA_SERIAL_NUMBER` ("DER-encoding of the certificate serial number").
pub fn extract_serial_number(der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    Some(cert.raw_serial().to_vec())
}

/// True if `der` parses as a well-formed X.509 certificate (RFC 5280),
/// independent of whether it has an extractable Subject — a certificate
/// may legitimately carry an empty Subject with identity solely in a
/// critical `subjectAltName` (RFC 5280 §4.1.2.6). WP-7 remediation: used
/// by `Register` to reject genuinely malformed DER up front, distinct
/// from the "no Subject" signal the `extract_subject_*` helpers return
/// for a certificate that parses fine but has nothing to project onto
/// the engine.
pub fn is_parseable(der: &[u8]) -> bool {
    X509Certificate::from_der(der).is_ok()
}

/// True if `der` parses under the STRICT `x509_cert`/`der` crate parser —
/// the same one `certify.rs::resolve_ca` and Re-certify's existing-cert
/// load use, which enforces DER canonicality (X.690 §8.3.2) and rejects a
/// certificate whose serial number (or any other top-level INTEGER)
/// carries a redundant leading byte.
///
/// Added 2026-08-18 (composite-hybrid remediation plan, Phase 2a): before
/// this, `Register`/`Import` accepted anything [`is_parseable`] tolerated
/// (the LENIENT `x509_parser` crate), so a non-canonical certificate could
/// be successfully registered today and then refused — loudly, but with
/// no warning at accept time — the moment it was designated a CA or
/// touched by Re-certify. Checking both parsers up front makes Register/
/// Import's acceptance strictness match what the certificate will
/// eventually be held to, so a bad certificate is rejected at the point
/// an operator can still act on it, not two steps later.
pub fn is_canonical(der: &[u8]) -> bool {
    x509_cert::Certificate::from_der(der).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BL-M-10 Certificate DER (verbatim from the OASIS test fixture
    /// `BL-M-10-30.xml`). Subject Name → CN = "CN", total length = 1043 bytes.
    const BL_M_10_DER_HEX: &str = "3082040f308202f7a003020102020900e31cb99f91cb07ed300d06092a864886f70d01010b05003062310b3009060355040613024155310b3009060355040813025350310a3008060355040713014c310a3008060355040a13014f310b3009060355040b13024f55310b300906035504031302434e3114301206092a864886f70d0109011605456d61696c301e170d3130303530313036303831365a170d3132303433303036303831365a3062310b3009060355040613024155310b3009060355040813025350310a3008060355040713014c310a3008060355040a13014f310b3009060355040b13024f55310b300906035504031302434e3114301206092a864886f70d0109011605456d61696c30820122300d06092a864886f70d01010105000382010f003082010a0282010100e5b86a3cf3fb109c4622d94fa2883bf6d9098c95e1ba3344bcb50edbfba41741409b9b1931ad674d5164b833f1b1b84434bd8abddce2197f66539832f413cfff32e16cb7e67296525158cc58f085ef6ec87e15de0879534322f690d0766a5c4b0287daf50c5f84b9959ca19537609281ec2d2b3e626be9e94dbfc2cb3d75bd03d964e8379e2c5125817ff72dbee80d06a8d63e25842af38fa1aaf9e493a4ef436c1a3a4400cd4bbcd9d9bcf030d41290f3c3bfa829cff0fbf682453875cfc6b2ab5b6b3315c8281dc13f318aeeb0b05f81ea6042ffedd574b74043c33a11c2aaec2f4cf2a02e9dfd3417acdc43be26a1cf3de2463540cfa621e246de8879f9ef0203010001a381c73081c4301d0603551d0e041604144dd89a6ba988a08aa6f4a8ab5b532edea9338c2c3081940603551d2304818c30818980144dd89a6ba988a08aa6f4a8ab5b532edea9338c2ca166a4643062310b3009060355040613024155310b3009060355040813025350310a3008060355040713014c310a3008060355040a13014f310b3009060355040b13024f55310b300906035504031302434e3114301206092a864886f70d0109011605456d61696c820900e31cb99f91cb07ed300c0603551d13040530030101ff300d06092a864886f70d01010b05000382010100acda7b0c6df7e4f6507c0958f25f6b5e3bfb4de7a36f5c8aacf0664b2aec18ba2d5dda6ae35dfc103eadb1c39a0e4e3166c19eca4a35e96eb6092f74904e67a3a32e127a4f5dba655d16feeb260acb7b7245910e25e689074c057db1e17af58d8df303e5a1e881f72d46226863e2da9b4dc8f443cb5b5114e4c9e1867ce109b016a059a0b27ea3bf912f463e57fcf7b5237f124b787dfa74385cb97c400403e3362077749a8ffbe37cb2675e9db0278c6682b579622f6355acbf71fa968e68a78cf0d6a63a5a8cea8a9b97c8c482d91fa73ee76012e3dd8b379d5e4c132279b1d915c979c48e60e1454a2846e661d5659885c026a523bc613ab21db8b86f9096";

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    /// §4.6 Table 62 in two halves, against the real OASIS BL-M-10 fixture.
    ///
    /// "SHALL always have a value: **No**" — the fixture's Subject carries
    /// C/ST/L/O/OU/CN/Email and NOTHING else, so the other five components
    /// must come back EMPTY rather than as empty strings. Rendering an absent
    /// RDN as `""` would put a value on the wire that is not in the
    /// certificate, which is the `Digest` mistake in a different costume.
    #[test]
    fn absent_rdns_stay_absent_rather_than_becoming_empty_strings() {
        let bytes = hex_to_bytes(BL_M_10_DER_HEX);
        let n = extract_name_attributes(&bytes, NameSide::Subject).expect("parses");

        assert_eq!(n.cn, vec!["CN"]);
        assert_eq!(n.o, vec!["O"]);
        assert_eq!(n.ou, vec!["OU"]);
        assert_eq!(n.c, vec!["AU"]);
        assert_eq!(n.st, vec!["SP"]);
        assert_eq!(n.l, vec!["L"]);
        assert_eq!(n.email, vec!["Email"]);

        for (name, got) in [
            ("Certificate Subject UID", &n.uid),
            ("Certificate Subject Serial Number", &n.serial_number),
            ("Certificate Subject Title", &n.title),
            ("Certificate Subject DC", &n.dc),
            ("Certificate Subject DN Qualifier", &n.dn_qualifier),
        ] {
            assert!(got.is_empty(), "{name} is not in the certificate, so it must be absent — got {got:?}");
        }

        assert!(n.dn.is_some(), "a non-empty Name must render a Certificate Subject DN");
    }

    /// The Issuer side reads the Issuer Name, not the Subject Name. BL-M-10 is
    /// self-signed so the two agree; the point is that the side selector is
    /// wired at all, which a self-signed fixture alone cannot prove — hence
    /// the raw-DER comparison against the parser's own issuer slice.
    #[test]
    fn the_issuer_side_reads_the_issuer_name() {
        let bytes = hex_to_bytes(BL_M_10_DER_HEX);
        let issuer = extract_name_attributes(&bytes, NameSide::Issuer).expect("parses");
        assert_eq!(issuer.cn, vec!["CN"]);
        assert_eq!(extract_issuer_der(&bytes), extract_subject_der(&bytes), "BL-M-10 is self-signed");
    }

    /// A certificate whose Subject repeats `OU` twice and `DC` twice.
    ///
    /// Generated once with OpenSSL 3.6.3 and pinned as DER, NOT built in-test:
    /// `rcgen::DistinguishedName` stores entries in a `HashMap<DnType, _>`
    /// (rcgen 0.13.2 lib.rs:302), so it structurally cannot express a repeated
    /// RDN — a first attempt at this fixture silently kept only the LAST `OU`
    /// and would have "passed" a broken extractor into the tree.
    ///
    /// Subject: C=GB, O=PQCToday, OU=Engineering, OU=Cryptography,
    ///          CN=multi.example, DC=example, DC=com, title=Principal
    const MULTI_RDN_DER_HEX: &str = "3082043130820319a00302010202147a99c2d9f7ad1f783b1d06520bd5ebf03bb06103300d06092a864886f70d01010b05003081a7310b30090603550406130247423111300f060355040a0c08505143546f64617931143012060355040b0c0b456e67696e656572696e6731153013060355040b0c0c43727970746f6772617068793116301406035504030c0d6d756c74692e6578616d706c6531173015060a0992268993f22c64011916076578616d706c6531133011060a0992268993f22c6401191603636f6d31123010060355040c0c095072696e636970616c301e170d3236303930373039353230315a170d3336303930343039353230315a3081a7310b30090603550406130247423111300f060355040a0c08505143546f64617931143012060355040b0c0b456e67696e656572696e6731153013060355040b0c0c43727970746f6772617068793116301406035504030c0d6d756c74692e6578616d706c6531173015060a0992268993f22c64011916076578616d706c6531133011060a0992268993f22c6401191603636f6d31123010060355040c0c095072696e636970616c30820122300d06092a864886f70d01010105000382010f003082010a0282010100b5b1b727b571f2cb1bc7e3f45ae91dd55a26a1cfd77473166bcec127190ba769aaae6d5559bd23ccee09ec4437e081bcff94fd2d42a36765500f8c0e73fb03f2a2f53532a10c8f60d092a525f62df7f23fe0624dc3bbdb48bd34c366870f08fa4b0c338340edf3bb53150556ceb57e1d55ce48821fc674b5e8fd33008fac27ba5efbdd216b48e2058f5aa2eea0bbc25ecb25379f621341f50bcf63c4877459a1991d4fe551bfedb3a7e907d6d2645376be06b4f211f8692235243bf5ee2915ff0c6879e04648dc041e5f7121138e3d6f8b160f39e054ea444bac6263b41c0253ae08e725148a778076ea7c7cb445a526fa10d60a67ef13badec5dc34b71c89c50203010001a3533051301d0603551d0e04160414ae71a333ee522d26b738d4c1e2223a101d77284f301f0603551d23041830168014ae71a333ee522d26b738d4c1e2223a101d77284f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101007363723cfab1bb6aed846b7b8fe844907ce56d2a0b8f0cda218b79128cb3dea86d9a2639a83c89e13eda28e428f4f13172fe8e6f27bb582d656905a303662fa5e22faf1c9e10a13459b0fa8fd42947711e5e57a54afb9ee3c661109e97bfbea65c35d9af14dffc77c183956d0361335ba4f712b20f4980fc0a742d016551ed1a4f55949e63c3e067b1037b51fb11750377f35f7bf64323e7b022d722ad511f23ee45f3462ea41d3884dbcf6aa429de1567eaccce72daeb2adcf981b1d27c6992dc56589e3be55e153b41cd88d0dba6dfd74ba8511d02a4d50a999183780cbc2b8932ad535b37990efa7d04dc8aa4a7740bec552f5c74449d09892e309d74ea13";

    /// "Multiple instances permitted: **Yes**" (§4.6 Table 62) — a Name may
    /// legitimately carry two `OU`s, and repeated `DC`s are how domain
    /// components are written at all. A single `Option<String>` drops every
    /// instance but one, so this asserts they ALL survive, in certificate
    /// order.
    #[test]
    fn a_repeated_rdn_yields_every_instance_not_just_the_first() {
        let bytes = hex_to_bytes(MULTI_RDN_DER_HEX);
        let n = extract_name_attributes(&bytes, NameSide::Subject).expect("parses");

        assert_eq!(
            n.ou,
            vec!["Engineering".to_string(), "Cryptography".to_string()],
            "both Certificate Subject OU instances must survive, in certificate order"
        );
        assert_eq!(
            n.dc,
            vec!["example".to_string(), "com".to_string()],
            "both Certificate Subject DC instances must survive, in certificate order"
        );
        assert_eq!(n.cn, vec!["multi.example"]);
        assert_eq!(n.c, vec!["GB"]);
        assert_eq!(n.o, vec!["PQCToday"]);
        assert_eq!(n.title, vec!["Principal"]);
        assert!(n.email.is_empty(), "no emailAddress RDN in this certificate");
    }

    #[test]
    fn extracts_cn_from_bl_m_10_cert() {
        let bytes = hex_to_bytes(BL_M_10_DER_HEX);
        let cn = extract_subject_cn(&bytes);
        assert_eq!(cn.as_deref(), Some("CN"));
    }

    #[test]
    fn bl_m_10_cert_total_der_length_is_1043() {
        // KMIP `Certificate Length` = total DER byte count. BL-M-10
        // expects 1043. Sanity-check the fixture too — outer SEQUENCE
        // has length 0x040f = 1039 bytes content + 4 header = 1043.
        let bytes = hex_to_bytes(BL_M_10_DER_HEX);
        assert_eq!(bytes.len(), 1043);
    }

    #[test]
    fn returns_none_for_garbage() {
        assert_eq!(extract_subject_cn(&[]), None);
        assert_eq!(extract_subject_cn(&[0xff, 0x00]), None);
    }
}

// ── §4.6 Certificate Attributes ──────────────────────────────────────────
//
// KMIP 3.0 §4.6 defines 13 Subject and 13 Issuer attributes, "based on
// RFC2253". Its rules table (Table 62) settles two design questions that
// would otherwise be judgement calls:
//
//   * "SHALL always have a value: **No**" — an RDN absent from the
//     certificate means the attribute is ABSENT, not an empty string. Same
//     posture as `Digest`: never fabricate a value we did not derive.
//   * "Multiple instances permitted: **Yes**" — a Name may legitimately
//     carry two `OU`s or two `DC`s, so every component is a list. A single
//     `Option<String>` silently drops the second.
//
// One OID-keyed pass yields all 12 components for a side; the 13th (`DN`)
// is the whole Name rendered, which `X509Name`'s Display already does.

/// Which of the two Names in a certificate to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSide {
    Subject,
    Issuer,
}

pub use crate::kmip30::CertificateNames;

/// Extract every §4.6 component for one side of an X.509 certificate.
///
/// Returns `None` only when the DER does not parse at all; a certificate that
/// parses but carries an empty Name yields a default (all-empty) value, which
/// is a meaningful answer and not an error.
pub fn extract_name_attributes(der: &[u8], side: NameSide) -> Option<CertificateNames> {
    // `oid_registry` reaches us re-exported by x509-parser (lib.rs:164), so the
    // OID constants need no extra direct dependency.
    use x509_parser::oid_registry::{
        OID_DOMAIN_COMPONENT, OID_PKCS9_EMAIL_ADDRESS, OID_USERID, OID_X509_COMMON_NAME,
        OID_X509_COUNTRY_NAME, OID_X509_DN_QUALIFIER, OID_X509_LOCALITY_NAME,
        OID_X509_ORGANIZATIONAL_UNIT, OID_X509_ORGANIZATION_NAME, OID_X509_SERIALNUMBER,
        OID_X509_STATE_OR_PROVINCE_NAME, OID_X509_TITLE,
    };

    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let name = match side {
        NameSide::Subject => cert.subject(),
        NameSide::Issuer => cert.issuer(),
    };

    let mut out = CertificateNames::default();
    for attr in name.iter_attributes() {
        // A non-UTF-8 RDN (e.g. a BMPString we cannot faithfully render) is
        // skipped rather than lossily transcoded: §4.6 types these as Text
        // String, and inventing a replacement character would put a value on
        // the wire that is not in the certificate.
        let Ok(v) = attr.as_str() else { continue };
        let oid = attr.attr_type();
        let bucket = if *oid == OID_X509_COMMON_NAME {
            &mut out.cn
        } else if *oid == OID_X509_ORGANIZATION_NAME {
            &mut out.o
        } else if *oid == OID_X509_ORGANIZATIONAL_UNIT {
            &mut out.ou
        } else if *oid == OID_PKCS9_EMAIL_ADDRESS {
            &mut out.email
        } else if *oid == OID_X509_COUNTRY_NAME {
            &mut out.c
        } else if *oid == OID_X509_STATE_OR_PROVINCE_NAME {
            &mut out.st
        } else if *oid == OID_X509_LOCALITY_NAME {
            &mut out.l
        } else if *oid == OID_USERID {
            &mut out.uid
        } else if *oid == OID_X509_SERIALNUMBER {
            &mut out.serial_number
        } else if *oid == OID_X509_TITLE {
            &mut out.title
        } else if *oid == OID_DOMAIN_COMPONENT {
            &mut out.dc
        } else if *oid == OID_X509_DN_QUALIFIER {
            &mut out.dn_qualifier
        } else {
            // Any other RDN (SURNAME, GIVENNAME, …) has no §4.6 attribute.
            continue;
        };
        bucket.push(v.to_string());
    }

    let rendered = name.to_string();
    out.dn = if rendered.is_empty() { None } else { Some(rendered) };
    Some(out)
}

/// Both §4.6 Name projections for a certificate, as the record stores them.
///
/// Returns `(subject, issuer)`. Either side is `None` when the DER does not
/// parse, or when that Name is genuinely empty — RFC 5280 §4.1.2.6 permits an
/// empty Subject whose identity lives in a critical `subjectAltName`, and
/// §4.6 Table 62 ("SHALL always have a value: No") says that must project NO
/// attributes rather than twelve empty ones.
///
/// One call site shape for all three of Register, Certify and Re-certify —
/// Table 62's "When implicitly set" list — so the three cannot drift apart.
pub fn extract_certificate_names(der: &[u8]) -> (Option<CertificateNames>, Option<CertificateNames>) {
    let non_empty = |n: CertificateNames| if n.is_empty() { None } else { Some(n) };
    (
        extract_name_attributes(der, NameSide::Subject).and_then(non_empty),
        extract_name_attributes(der, NameSide::Issuer).and_then(non_empty),
    )
}
