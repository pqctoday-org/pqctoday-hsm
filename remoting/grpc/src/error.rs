//! WP5a error-mapping contract, gRPC half: a `CkError` becomes a
//! `tonic::Status` carrying the exact `raw_ck_rv` in a typed detail
//! message, never a bare `INTERNAL`.

use pqctoday_pkcs11_remote_core::CkError;
use pqctoday_pkcs11_remote_proto::{Pkcs11Error, Pkcs11ErrorDetail};
use softhsmrustv3::constants::*;
use tonic::{Code, Status};

/// Classify a raw `CKR_*` value into the wire enum. Codes outside the
/// service's actual surface fall back to `PKCS11_ERROR_UNSPECIFIED` with
/// the raw value still attached — the acceptance suite (WP5a) asserts on
/// `raw_ck_rv`, never on this classification alone.
fn classify(rv: u32) -> Pkcs11Error {
    match rv {
        CKR_GENERAL_ERROR => Pkcs11Error::CkrGeneralError,
        CKR_FUNCTION_FAILED => Pkcs11Error::CkrFunctionFailed,
        CKR_ARGUMENTS_BAD => Pkcs11Error::CkrArgumentsBad,
        CKR_ATTRIBUTE_VALUE_INVALID => Pkcs11Error::CkrAttributeValueInvalid,
        CKR_KEY_TYPE_INCONSISTENT => Pkcs11Error::CkrKeyTypeInconsistent,
        CKR_KEY_FUNCTION_NOT_PERMITTED => Pkcs11Error::CkrKeyFunctionNotPermitted,
        CKR_MECHANISM_INVALID => Pkcs11Error::CkrMechanismInvalid,
        CKR_TEMPLATE_INCOMPLETE => Pkcs11Error::CkrTemplateIncomplete,
        CKR_SESSION_HANDLE_INVALID => Pkcs11Error::CkrSessionHandleInvalid,
        CKR_PIN_INCORRECT => Pkcs11Error::CkrPinIncorrect,
        CKR_SIGNATURE_INVALID => Pkcs11Error::CkrSignatureInvalid,
        _ => Pkcs11Error::Unspecified,
    }
}

/// The gRPC status code family for a `CKR_*` — chosen so the coarse HTTP/2
/// status is meaningful even before a client inspects the typed detail.
fn grpc_code(rv: u32) -> Code {
    match rv {
        CKR_SESSION_HANDLE_INVALID => Code::NotFound,
        CKR_PIN_INCORRECT => Code::PermissionDenied,
        CKR_ARGUMENTS_BAD | CKR_ATTRIBUTE_VALUE_INVALID | CKR_MECHANISM_INVALID
        | CKR_KEY_TYPE_INCONSISTENT | CKR_TEMPLATE_INCOMPLETE => Code::InvalidArgument,
        CKR_KEY_FUNCTION_NOT_PERMITTED => Code::PermissionDenied,
        _ => Code::Internal,
    }
}

pub fn to_status(err: CkError) -> Status {
    let raw = err.raw();
    let detail = Pkcs11ErrorDetail {
        code: classify(raw) as i32,
        raw_ck_rv: raw,
        message: err.to_string(),
    };
    // tonic 0.14 status details: encode the typed detail into the message
    // itself as `raw_ck_rv=0x...` so a client can parse it without a
    // richer error-details extension — keeps both transports' error
    // bodies inspectable the same way (see remoting/rest's JSON body,
    // which carries the same three fields).
    Status::new(
        grpc_code(raw),
        format!("{} (pkcs11_error={:?}, raw_ck_rv=0x{:08X})", detail.message, detail.code(), detail.raw_ck_rv),
    )
}
