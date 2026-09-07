//! KMIP 3.0 §6.1.32 **Interop** operation — test-framework marker.
//!
//! Carries `Begin` / `End` markers used by the OASIS conformance suite
//! to bracket test cases. No managed-object effect; the server just
//! returns `Success`. We still emit audit events so test runs are
//! traceable in the ring buffer.

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{InteropFunction, InteropRequest, InteropResponse};

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

    // §6.1.32 — "It SHALL NOT be available in a production server." Off unless
    // the deployment opts in with --enable-interop. Before R6 it was always
    // available, which is precisely what the spec forbids. §6.1.32's own error
    // table lists Operation Not Supported among the permitted reasons.
    if !deps.config.interop_enabled {
        return Err(super::helpers::fail_err(
            deps,
            correlation_id,
            "Interop",
            KmipError::failed(
                ResultReason::OperationNotSupported,
                "Interop is disabled; §6.1.32 forbids it on a production server \
                 (start with --enable-interop for conformance runs)"
                    .to_string(),
            ),
        ));
    }

    // §6.1.32 — an Interop Identifier of "*" is "reserved for use during
    // interoperability testing to indicate that the server should perform a
    // cleanup for the currently authenticated user so that testing may be
    // repeated". `Reset` "resets the server to the state it would be in at
    // the beginning of an interop session" (§11.24).
    if req.function == InteropFunction::Reset || req.identifier == "*" {
        emit_request(
            deps,
            correlation_id,
            "Interop",
            format!("reset requested (function={:?} id={})", req.function, req.identifier),
        );
    }

    emit_success(deps, correlation_id, "Interop");
    Ok(InteropResponse)
}
