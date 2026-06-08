//! Lifecycle FSM enforcement — defense-in-depth at the store layer.
//!
//! Phase 5 op handlers already enforce lifecycle transitions at the
//! request handler (e.g. `Activate` checks `state == PreActive`). The
//! store layer adds a second gate so a bug in any handler can't silently
//! corrupt the FSM. The transition table lives on
//! [`crate::kmip30::State::can_transition_to`]; this module wraps it in a
//! `Result` shape for the store's `update` paths.
//!
//! Per `docs/IMPLEMENTATION_PLAN.md` §3.4:
//!
//! ```text
//! PreActive   → Active | Deactivated | Compromised | Destroyed
//! Active      → Deactivated | Compromised | Destroyed
//! Deactivated → Compromised | Destroyed
//! Compromised → DestroyedCompromised
//! Destroyed   → DestroyedCompromised
//! DestroyedCompromised → (terminal)
//! ```

use crate::error::{KmipError, Result};
use crate::kmip30::State;

/// `Ok(())` if `from → to` is a valid KMIP lifecycle transition (or a
/// no-op identity), `Err(KmipError::permission_denied)` otherwise.
///
/// Identity transitions (`from == to`) are permitted — store `update`
/// often re-writes a record without touching state.
pub fn enforce_transition(from: State, to: State) -> Result<()> {
    if from == to {
        return Ok(());
    }
    if from.can_transition_to(to) {
        Ok(())
    } else {
        Err(KmipError::permission_denied(format!(
            "lifecycle FSM rejects {from:?} → {to:?} (see IMPLEMENTATION_PLAN §3.4)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ResultReason;

    #[test]
    fn identity_transitions_allowed() {
        for s in [
            State::PreActive,
            State::Active,
            State::Deactivated,
            State::Compromised,
            State::Destroyed,
            State::DestroyedCompromised,
        ] {
            assert!(enforce_transition(s, s).is_ok(), "{s:?} → {s:?} should be Ok");
        }
    }

    #[test]
    fn pre_active_can_activate() {
        assert!(enforce_transition(State::PreActive, State::Active).is_ok());
    }

    #[test]
    fn active_to_destroyed_directly_allowed_by_spec() {
        // §3.4: Active → Destroyed is in the FSM table (skip Revoke).
        assert!(enforce_transition(State::Active, State::Destroyed).is_ok());
    }

    #[test]
    fn destroyed_terminal_except_compromised_promotion() {
        // Destroyed → DestroyedCompromised is the only legal forward move.
        assert!(enforce_transition(State::Destroyed, State::DestroyedCompromised).is_ok());
        // Everything else from Destroyed is denied.
        for s in [
            State::PreActive,
            State::Active,
            State::Deactivated,
            State::Compromised,
        ] {
            let err = enforce_transition(State::Destroyed, s).unwrap_err();
            assert_eq!(err.result_reason(), ResultReason::PermissionDenied);
        }
    }

    #[test]
    fn destroyed_compromised_is_truly_terminal() {
        for s in [
            State::PreActive,
            State::Active,
            State::Deactivated,
            State::Compromised,
            State::Destroyed,
        ] {
            let err = enforce_transition(State::DestroyedCompromised, s).unwrap_err();
            assert_eq!(err.result_reason(), ResultReason::PermissionDenied);
        }
    }

    #[test]
    fn deactivated_cannot_reactivate() {
        let err = enforce_transition(State::Deactivated, State::Active).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::PermissionDenied);
    }
}
