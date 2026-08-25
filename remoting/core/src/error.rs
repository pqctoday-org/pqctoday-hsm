//! The CKR_* error-mapping contract (WP5a) — the property that stops the
//! gRPC/REST surfaces flattening engine semantics into a generic 500/INTERNAL.
//!
//! [`CkError`] wraps the exact `CkRv` (`u32`) the engine returned. Every
//! transport crate (`remoting/grpc`, `remoting/rest`) maps THIS type to its
//! own wire error representation — see each crate's `error.rs` — but the
//! numeric code and the classification below are shared, so a case in the
//! WP5a acceptance suite that asserts "gRPC surfaces raw_ck_rv == 0x70" and
//! "REST surfaces the same 0x70 in its JSON body" is asserting the same
//! fact through two independent encodings, not two independent guesses.

use softhsmrustv3::native::CkRv;

/// A PKCS#11 return code the verb layer produced, kept as the raw numeric
/// value (never re-encoded to a smaller enum internally) so a case can
/// always assert the exact spec codepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CkError(pub CkRv);

impl CkError {
    pub fn raw(self) -> u32 {
        self.0
    }

    /// Coarse classification for logging/metrics — NOT used for the
    /// acceptance suite's assertions, which compare `raw()` directly.
    pub fn class(self) -> &'static str {
        use softhsmrustv3::constants::*;
        match self.0 {
            CKR_SESSION_HANDLE_INVALID => "session-handle-invalid",
            CKR_PIN_INCORRECT => "pin-incorrect",
            CKR_ARGUMENTS_BAD => "arguments-bad",
            CKR_ATTRIBUTE_VALUE_INVALID => "attribute-value-invalid",
            CKR_MECHANISM_INVALID => "mechanism-invalid",
            CKR_KEY_TYPE_INCONSISTENT => "key-type-inconsistent",
            CKR_KEY_FUNCTION_NOT_PERMITTED => "key-function-not-permitted",
            CKR_TEMPLATE_INCOMPLETE => "template-incomplete",
            CKR_SIGNATURE_INVALID => "signature-invalid",
            CKR_FUNCTION_FAILED => "function-failed",
            CKR_GENERAL_ERROR => "general-error",
            _ => "other",
        }
    }
}

impl std::fmt::Display for CkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CKR 0x{:08X} ({})", self.0, self.class())
    }
}

impl std::error::Error for CkError {}

impl From<CkRv> for CkError {
    fn from(rv: CkRv) -> Self {
        CkError(rv)
    }
}
