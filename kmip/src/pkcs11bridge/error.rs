//! `BridgeError` — typed error wrapping PKCS#11 `CKR_*` return codes from the
//! `softhsmrustv3` engine.
//!
//! The engine returns `u32` return codes ([`CK_RV`] in the PKCS#11 ABI).
//! Wrapping them at this layer lets Phase 5 op handlers `?`-propagate without
//! caring about the raw codepoints.

use thiserror::Error;

/// PKCS#11 ABI return value (`CK_RV` in the spec).
pub type CkRv = u32;

/// PKCS#11 v3.2 §5.1 — `CKR_OK = 0`. Any non-zero return is an error.
pub const CKR_OK: CkRv = 0x0000_0000;

/// Errors produced by [`super::Session`] methods. Each variant carries the
/// raw `CK_RV` for forensic inspection; the high-level shape matches the
/// classes Phase 5 op handlers care about.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq, Hash)]
pub enum BridgeError {
    #[error("PKCS#11 returned CKR_GENERAL_ERROR (0x{0:08x})")]
    GeneralError(CkRv),

    #[error("PKCS#11 returned CKR_FUNCTION_FAILED (0x{0:08x})")]
    FunctionFailed(CkRv),

    #[error("PKCS#11 returned CKR_HOST_MEMORY (0x{0:08x})")]
    HostMemory(CkRv),

    #[error("PKCS#11 mechanism not recognised (CKR_MECHANISM_INVALID, 0x{0:08x})")]
    MechanismInvalid(CkRv),

    #[error("PKCS#11 mechanism parameter rejected (CKR_MECHANISM_PARAM_INVALID, 0x{0:08x})")]
    MechanismParamInvalid(CkRv),

    #[error("PKCS#11 object handle invalid (CKR_OBJECT_HANDLE_INVALID, 0x{0:08x})")]
    ObjectHandleInvalid(CkRv),

    #[error("PKCS#11 attribute template rejected (CKR_TEMPLATE_*, 0x{0:08x})")]
    TemplateError(CkRv),

    #[error("PKCS#11 signature verify failed (CKR_SIGNATURE_INVALID, 0x{0:08x})")]
    SignatureInvalid(CkRv),

    #[error("PKCS#11 output buffer too small (CKR_BUFFER_TOO_SMALL, 0x{0:08x})")]
    BufferTooSmall(CkRv),

    #[error("PKCS#11 session handle invalid or session not open (CKR_SESSION_*, 0x{0:08x})")]
    SessionInvalid(CkRv),

    #[error("PKCS#11 arguments rejected (CKR_ARGUMENTS_BAD, 0x{0:08x})")]
    ArgumentsBad(CkRv),

    /// Any return code not in the named-class set above.
    #[error("PKCS#11 returned unrecognised CKR (0x{0:08x})")]
    UnclassifiedCkr(CkRv),
}

impl BridgeError {
    /// Map a `CK_RV` to a [`BridgeError`]. `CKR_OK` is `Ok(())` rather than
    /// an error — the caller passes the raw `u32` and gets back a `Result`.
    pub fn from_ckr(rv: CkRv) -> Result<()> {
        if rv == CKR_OK {
            return Ok(());
        }
        Err(Self::classify(rv))
    }

    /// Classify a non-`OK` return code into a typed variant. Codepoint
    /// pinning kept inline (rather than importing `softhsmrustv3::constants`)
    /// so this error type can be read in isolation and so the codepoints are
    /// explicit at the place they're handled.
    #[inline]
    pub fn classify(rv: CkRv) -> Self {
        match rv {
            0x0000_0002 => Self::HostMemory(rv),
            0x0000_0005 => Self::GeneralError(rv),
            0x0000_0006 => Self::FunctionFailed(rv),
            0x0000_0007 => Self::ArgumentsBad(rv),
            0x0000_0070 => Self::MechanismInvalid(rv),
            0x0000_0071 => Self::MechanismParamInvalid(rv),
            0x0000_0082 => Self::ObjectHandleInvalid(rv),
            0x0000_0150 => Self::BufferTooSmall(rv),
            0x0000_00C0 => Self::SignatureInvalid(rv),
            0x0000_00D0 | 0x0000_00D1 => Self::TemplateError(rv),
            // CKR_SESSION_* range: 0x0000_00B0–0x0000_00BC per pkcs11t.h.
            0x0000_00B0..=0x0000_00BC => Self::SessionInvalid(rv),
            other => Self::UnclassifiedCkr(other),
        }
    }

    /// Underlying raw `CK_RV` for forensic logging.
    pub const fn raw(self) -> CkRv {
        match self {
            Self::HostMemory(v)
            | Self::GeneralError(v)
            | Self::FunctionFailed(v)
            | Self::MechanismInvalid(v)
            | Self::MechanismParamInvalid(v)
            | Self::ObjectHandleInvalid(v)
            | Self::TemplateError(v)
            | Self::SignatureInvalid(v)
            | Self::BufferTooSmall(v)
            | Self::SessionInvalid(v)
            | Self::ArgumentsBad(v)
            | Self::UnclassifiedCkr(v) => v,
        }
    }
}

/// Convenience alias for `Result<T, BridgeError>`.
pub type Result<T> = std::result::Result<T, BridgeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_round_trip() {
        assert_eq!(BridgeError::from_ckr(CKR_OK), Ok(()));
    }

    #[test]
    fn classify_named_codes() {
        assert!(matches!(BridgeError::classify(0x0000_0005), BridgeError::GeneralError(_)));
        assert!(matches!(BridgeError::classify(0x0000_0070), BridgeError::MechanismInvalid(_)));
        assert!(matches!(BridgeError::classify(0x0000_0082), BridgeError::ObjectHandleInvalid(_)));
        assert!(matches!(BridgeError::classify(0x0000_00C0), BridgeError::SignatureInvalid(_)));
    }

    #[test]
    fn classify_session_range() {
        // CKR_SESSION_HANDLE_INVALID is 0x0000_00B3 per pkcs11t.h.
        assert!(matches!(
            BridgeError::classify(0x0000_00B3),
            BridgeError::SessionInvalid(_)
        ));
        // Edges of the range.
        assert!(matches!(BridgeError::classify(0x0000_00B0), BridgeError::SessionInvalid(_)));
        assert!(matches!(BridgeError::classify(0x0000_00BC), BridgeError::SessionInvalid(_)));
        // Just outside the range.
        assert!(matches!(BridgeError::classify(0x0000_00BD), BridgeError::UnclassifiedCkr(_)));
    }

    #[test]
    fn raw_round_trips_through_classify() {
        for code in [0x0005, 0x0070, 0x0082, 0x00B3, 0x00C0, 0x00D0, 0x12345678] {
            let err = BridgeError::classify(code);
            assert_eq!(err.raw(), code);
        }
    }
}
