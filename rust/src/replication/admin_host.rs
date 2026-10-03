//! Host side of the admin interface (admin addendum §3.1, §3.6): build and
//! sign requests, and verify receipts, over public bytes only. The operator
//! host holds the admin-authority key; this module never touches a token.

use super::admin::{
    gtime, signed_bytes, AdminOperation, AdminSignedRequest, AdminTbsRequest, EnrollCrlOp, EnrollPolicyOp, IssueDeviceCrlOp, REQUEST_DOMAIN,
};
use super::asn1;
use crate::constants::*;

/// DER `AdminTbsRequest` for `op`.
pub fn tbs_request(
    device_id: &[u8; 32],
    admin_key_id: &[u8; 32],
    nonce: &[u8; 32],
    sequence: u64,
    issued_at: u64,
    op: &AdminOperation,
) -> Result<Vec<u8>, u32> {
    let mut tbs = AdminTbsRequest {
        version: 1,
        device_id: asn1::octets(device_id),
        admin_key_id: asn1::octets(admin_key_id),
        nonce: asn1::octets(nonce),
        sequence,
        issued_at: gtime(issued_at)?,
        enroll_crl: None,
        enroll_policy: None,
        rotate_recovery_key: None,
        issue_function_certs: None,
        issue_device_crl: None,
    };
    match op {
        AdminOperation::EnrollCrl { crl, issuer_device_cert } => {
            tbs.enroll_crl = Some(EnrollCrlOp { crl: asn1::octets(crl), issuer_device_cert: issuer_device_cert.as_deref().map(asn1::octets) })
        }
        AdminOperation::EnrollPolicy { policy } => tbs.enroll_policy = Some(EnrollPolicyOp { policy: asn1::octets(policy) }),
        AdminOperation::RotateRecoveryKey => tbs.rotate_recovery_key = Some(der::asn1::Null),
        AdminOperation::IssueFunctionCerts => tbs.issue_function_certs = Some(der::asn1::Null),
        AdminOperation::IssueDeviceCrl { revoke, retired_to_revoke, validity_seconds } => {
            let mut revoke = revoke.clone();
            revoke.sort();
            let mut retired = retired_to_revoke.clone();
            retired.sort();
            tbs.issue_device_crl = Some(IssueDeviceCrlOp {
                revoke,
                retired_to_revoke: retired.iter().map(|c| asn1::octets(c)).collect(),
                validity_seconds: *validity_seconds,
            })
        }
    }
    asn1::to_der(&tbs)
}

/// The exact bytes the admin authority signs (ML-DSA-65, empty context):
/// `"PQCToday Replication Admin 1.0" || 0x00 || tbs_der`.
pub fn request_signed_bytes(tbs_der: &[u8]) -> Vec<u8> {
    signed_bytes(REQUEST_DOMAIN, tbs_der)
}

/// DER `AdminSignedRequest` from a TBS and its 3309-byte signature.
pub fn signed_request(tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>, u32> {
    use der::Decode;
    let tbs = AdminTbsRequest::from_der(tbs_der).map_err(|_| CKR_DATA_INVALID)?;
    asn1::to_der(&AdminSignedRequest {
        tbs,
        signature_algorithm: super::pki::ml_dsa_65_alg(),
        signature: der::asn1::BitString::from_bytes(signature).map_err(|_| CKR_DATA_INVALID)?,
    })
}
