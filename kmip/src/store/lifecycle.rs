//! Lifecycle FSM enforcement — defense-in-depth at the store layer.
//!
//! Phase 5 op handlers already enforce lifecycle transitions at the
//! request handler (e.g. `Activate` checks `state == PreActive`). The
//! store layer adds a second gate so a bug in any handler can't silently
//! corrupt the FSM. The transition table lives on
//! [`crate::kmip30::State::can_transition_to`]; this module wraps it in a
//! `Result` shape for the store's `update` paths.
//!
//! Per KMIP 3.0 §3.2 (numbered state diagram) and §6.1.20 (Destroy
//! constraint), mirrored in `docs/IMPLEMENTATION_PLAN.md` §3.4:
//!
//! ```text
//! PreActive   → Active | Compromised | Destroyed       (no →Deactivated)
//! Active      → Deactivated | Compromised              (no →Destroyed)
//! Deactivated → Compromised | Destroyed
//! Compromised → DestroyedCompromised
//! Destroyed   → DestroyedCompromised
//! DestroyedCompromised → (terminal)
//! ```
//!
//! §6.1.19: "Objects SHALL only be destroyed if they are in either
//! Pre-Active or Deactivated state" — so Active→Destroyed is forbidden;
//! and §3.2 has no PreActive→Deactivated edge (Deactivation is the §3.2
//! transition 6, Active→Deactivated, only).

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
    fn active_to_destroyed_directly_rejected_per_6_1_19() {
        // KMIP 3.0 §6.1.19: "Objects SHALL only be destroyed if they are
        // in either Pre-Active or Deactivated state." An Active object must
        // be Revoked/Deactivated first; there is no §3.2 Active→Destroyed
        // arrow. The Destroy op handler already rejects this with
        // WrongKeyLifecycleState; the store FSM must agree.
        let err = enforce_transition(State::Active, State::Destroyed).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::PermissionDenied);
    }

    /// Exhaustive 6×6 transition matrix asserted against the KMIP 3.0 §3.2
    /// numbered state diagram and the §6.1.20 Destroy constraint. This is
    /// the regression guard: any future drift in
    /// [`State::can_transition_to`] (or [`enforce_transition`]) names the
    /// exact `(from, to)` cell that broke.
    ///
    /// `true` = legal edge per §3.2/§6.1.19; `false` = rejected. Identity
    /// cells (`from == to`) are the FSM's no-op convention and always Ok via
    /// `enforce_transition` (asserted separately below since
    /// `can_transition_to` itself returns `false` on identity).
    #[test]
    fn exhaustive_transition_matrix_matches_spec() {
        use State::*;
        // Column/row order MUST match `STATES` below.
        const STATES: [State; 6] =
            [PreActive, Active, Deactivated, Compromised, Destroyed, DestroyedCompromised];

        // ALLOWED[from][to] — spec-authoritative (KMIP 3.0 §3.2 + §6.1.19).
        // §3.2 transition numbers annotate the non-obvious legal cells.
        //                   to:  Pre    Act    Deact  Comp   Destr  DestrComp
        const ALLOWED: [[bool; 6]; 6] = [
            /* PreActive   */ [false, true,  false, true,  true,  false], // t1 Act, t3 Comp, t2 Destr; NOT Deactivated
            /* Active      */ [false, false, true,  true,  false, false], // t6 Deact, t5 Comp; NOT Destroyed (§6.1.19)
            /* Deactivated */ [false, false, false, true,  true,  false], // t8 Comp, t7 Destr; NOT reactivate
            /* Compromised */ [false, false, false, false, false, true ], // → DestroyedCompromised only
            /* Destroyed   */ [false, false, false, false, false, true ], // t10 → DestroyedCompromised only
            /* DestrComp   */ [false, false, false, false, false, false], // terminal
        ];

        for (i, &from) in STATES.iter().enumerate() {
            for (j, &to) in STATES.iter().enumerate() {
                let expected = ALLOWED[i][j];
                // 1) Raw predicate matches the matrix exactly.
                assert_eq!(
                    from.can_transition_to(to),
                    expected,
                    "can_transition_to: cell ({from:?} -> {to:?}) expected {expected}, \
                     spec authority KMIP 3.0 §3.2/§6.1.19",
                );
                // 2) enforce_transition agrees, with the identity no-op
                //    convention layered on top (from == to is always Ok).
                let enforce_ok = enforce_transition(from, to).is_ok();
                let expected_enforce = expected || (from == to);
                assert_eq!(
                    enforce_ok,
                    expected_enforce,
                    "enforce_transition: cell ({from:?} -> {to:?}) expected ok={expected_enforce}, \
                     spec authority KMIP 3.0 §3.2/§6.1.19 (identity is a no-op)",
                );
            }
        }
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

/// §4.67 transition 6 — the **date-driven** part of the state machine.
///
/// The FSM above is enforced on explicit transitions (Activate, Revoke,
/// Deactivate). What it did not do was let time move an object: an Active key
/// whose `Protect Stop Date` had passed still reported `State = Active`, even
/// though §4.67 transition 6 says reaching it moves the object to Deactivated
/// with `Deactivation Reason Code = Protect Stop Date`.
///
/// The functional consequence was already partly contained — `Encrypt` and
/// `Decrypt` refuse past the date — so this closes the reporting half: what
/// `Get Attributes` says about `State` now matches what the operations do.
///
/// Applied on read rather than by a background sweep, deliberately: a sweep
/// needs a scheduler, and every path that observes an object goes through the
/// store anyway. It is a pure function of the record and the clock, so it
/// cannot disagree with itself between callers.
///
/// Returns `Some((new_state, reason_code))` when time has moved the object,
/// `None` when it has not.
pub fn effective_state_for(
    r: &crate::store::ObjectRecord,
    now: time::OffsetDateTime,
) -> Option<(crate::kmip30::State, u32)> {
    use crate::kmip30::State;
    // Only an Active object can be moved by a date. A Compromised or
    // Destroyed object stays where it is — §4.67 permits only the listed
    // transitions, and "time passed" is not a route out of those.
    if r.state != State::Active {
        return None;
    }
    const REASON_DEACTIVATION_DATE: u32 = 0x02;
    const REASON_PROTECT_STOP_DATE: u32 = 0x03;
    if let Some(t) = r.deactivation_date {
        if now >= t {
            return Some((State::Deactivated, REASON_DEACTIVATION_DATE));
        }
    }
    if let Some(t) = r.protect_stop_date {
        if now >= t {
            return Some((State::Deactivated, REASON_PROTECT_STOP_DATE));
        }
    }
    None
}

#[cfg(test)]
mod date_transition_tests {
    use super::*;
    use crate::kmip30::State;
    use crate::store::ObjectRecord;
    use time::OffsetDateTime;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    /// §4.67 transition 6 — reaching Protect Stop Date moves an Active object
    /// to Deactivated with reason "Protect Stop Date" (0x03).
    ///
    /// Before this, `State` kept reporting Active indefinitely while
    /// Encrypt/Decrypt refused the same key — the operations and the reported
    /// state disagreed.
    #[test]
    fn protect_stop_date_deactivates_on_read() {
        let mut r = ObjectRecord::default();
        r.state = State::Active;
        r.protect_stop_date = Some(at(1_000));

        assert_eq!(effective_state_for(&r, at(999)), None, "before the date: unchanged");
        assert_eq!(
            effective_state_for(&r, at(1_000)),
            Some((State::Deactivated, 0x03)),
            "AT the date the transition has happened",
        );
        assert_eq!(effective_state_for(&r, at(5_000)), Some((State::Deactivated, 0x03)));
    }

    /// Deactivation Date is its own reason code (0x02), and takes precedence
    /// when both are set — it names the object's own scheduled deactivation.
    #[test]
    fn deactivation_date_reports_its_own_reason() {
        let mut r = ObjectRecord::default();
        r.state = State::Active;
        r.deactivation_date = Some(at(1_000));
        r.protect_stop_date = Some(at(2_000));
        assert_eq!(effective_state_for(&r, at(1_500)), Some((State::Deactivated, 0x02)));
    }

    /// Time is not a route out of the states §4.67 does not permit leaving.
    /// A Compromised object stays Compromised however long you wait.
    #[test]
    fn a_date_cannot_move_an_object_out_of_a_terminal_state() {
        for state in [State::Compromised, State::Destroyed, State::PreActive] {
            let mut r = ObjectRecord::default();
            r.state = state;
            r.protect_stop_date = Some(at(1_000));
            assert_eq!(
                effective_state_for(&r, at(9_999)),
                None,
                "{state:?} must not be moved by a date",
            );
        }
    }
}
