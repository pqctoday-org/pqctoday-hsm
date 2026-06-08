//! KMIP error type; maps to KMIP `ResultReason` enumeration on the wire.
//!
//! Phase 0 (bootstrap): minimal stub. Full variant set per
//! `docs/IMPLEMENTATION_PLAN.md` §6 Phase 3 (KMIP ResultReason codes).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KmipError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, KmipError>;
