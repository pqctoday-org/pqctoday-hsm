//! KMIP 3.0 §6.1.31 **Interop** operation — test-framework no-op.
//!
//! Carries `Begin` / `End` markers used by the OASIS conformance suite
//! to bracket test cases. No managed-object effect; the server just
//! returns `Success`. We still emit audit events so test runs are
//! traceable in the ring buffer.

use crate::error::Result;
use crate::kmip30::{InteropRequest, InteropResponse};

use super::deps::Deps;
use super::helpers::{emit_request, emit_success};

pub fn interop(
    deps: &Deps,
    req: InteropRequest,
    correlation_id: &str,
) -> Result<InteropResponse> {
    emit_request(
        deps,
        correlation_id,
        "Interop",
        format!("function={:?} id={}", req.function, req.identifier),
    );
    emit_success(deps, correlation_id, "Interop");
    Ok(InteropResponse)
}
