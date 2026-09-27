//! pqctoday-hsm: the `parallel` feature's process-wide core budget (src/par.rs).
//! Own test binary, so no other test shares the process-global budget counters.

use fips205::budget_stats;
use fips205::slh_dsa_sha2_128f as p;
use fips205::traits::{KeyGen, Signer};
use std::sync::Barrier;

const BUDGET: usize = 4;

#[test]
fn concurrent_signers_never_exceed_the_core_budget() {
    budget_stats::set_budget(BUDGET);
    let (_, sk) = p::KG::keygen_with_seeds(&[1u8; 16], &[2u8; 16], &[3u8; 16]);

    // Serial reference (FIPS205_THREADS=1 must mean: no extra thread at all).
    std::env::set_var("FIPS205_THREADS", "1");
    budget_stats::reset();
    let reference = sk.try_sign(b"message", b"ctx", false).unwrap();
    assert_eq!(budget_stats::peak_extra_threads(), 0, "FIPS205_THREADS=1 spawned a thread");
    std::env::remove_var("FIPS205_THREADS");

    // One caller alone takes every spare token: budget - 1 extra threads.
    budget_stats::reset();
    assert_eq!(sk.try_sign(b"message", b"ctx", false).unwrap(), reference);
    assert_eq!(budget_stats::max_in_use_at_grant(), BUDGET, "a lone caller should fill the budget");
    assert!((1..BUDGET).contains(&budget_stats::peak_extra_threads()));
    assert_eq!(budget_stats::in_use(), 0);

    // 8 concurrent callers (twice the budget), 4 signatures and 1 keygen each.
    budget_stats::reset();
    let start = Barrier::new(8);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                start.wait();
                for _ in 0..4 {
                    assert_eq!(sk.try_sign(b"message", b"ctx", false).unwrap(), reference);
                }
                let _ = p::KG::keygen_with_seeds(&[1u8; 16], &[2u8; 16], &[3u8; 16]);
            });
        }
    });
    // Extra threads are only granted while callers + extra threads fit the budget, so at
    // most budget - 1 of them can ever be alive, however many callers there are.
    assert!(
        budget_stats::max_in_use_at_grant() <= BUDGET,
        "a grant pushed callers + extra threads to {} > {BUDGET}",
        budget_stats::max_in_use_at_grant()
    );
    assert!(
        budget_stats::peak_extra_threads() < BUDGET,
        "{} extra threads alive at once (budget {BUDGET})",
        budget_stats::peak_extra_threads()
    );
    assert_eq!(budget_stats::in_use(), 0, "tokens leaked");
    assert_eq!(budget_stats::live_extra_threads(), 0);
}
