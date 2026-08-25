//! WP5a error-mapping contract, REST half: a `CkError` becomes an HTTP
//! status + a JSON body carrying the exact `raw_ck_rv` — the same three
//! facts `remoting/grpc/src/error.rs` puts in `Pkcs11ErrorDetail`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pqctoday_pkcs11_remote_core::CkError;
use softhsmrustv3::constants::*;

use crate::dto::ErrorBody;

fn class_name(rv: u32) -> &'static str {
    match rv {
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",
        CKR_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",
        CKR_KEY_FUNCTION_NOT_PERMITTED => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        CKR_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        CKR_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
        _ => "PKCS11_ERROR_UNSPECIFIED",
    }
}

/// HTTP status family for a `CKR_*` — mirrors `remoting/grpc/src/error.rs::grpc_code`'s
/// classification (NotFound/PermissionDenied/InvalidArgument/Internal) at
/// the HTTP layer, so a case in the WP5a suite asserting "the same fault
/// surfaces the same way on both transports" is comparing like with like.
fn http_status(rv: u32) -> StatusCode {
    match rv {
        CKR_SESSION_HANDLE_INVALID => StatusCode::NOT_FOUND,
        CKR_PIN_INCORRECT => StatusCode::FORBIDDEN,
        CKR_ARGUMENTS_BAD | CKR_ATTRIBUTE_VALUE_INVALID | CKR_MECHANISM_INVALID
        | CKR_KEY_TYPE_INCONSISTENT | CKR_TEMPLATE_INCOMPLETE => StatusCode::BAD_REQUEST,
        CKR_KEY_FUNCTION_NOT_PERMITTED => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub struct ApiError(pub CkError);

impl From<CkError> for ApiError {
    fn from(e: CkError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let raw = self.0.raw();
        let body = ErrorBody { pkcs11_error: class_name(raw), raw_ck_rv: raw, message: self.0.to_string() };
        (http_status(raw), Json(body)).into_response()
    }
}
