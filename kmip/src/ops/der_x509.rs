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
