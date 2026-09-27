//! pqctoday-hsm: the in-memory tree cache (feature `tree-cache`) must not change a single
//! signature byte or state update. Own test binary: nothing else toggles the cache here.
#![cfg(feature = "tree-cache")]

use hbs_lms::{
    cache_clear, cache_set_enabled, cache_stats, keygen, sign, verify, HssParameter,
    LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_256,
};

type H = Sha256_256;

/// The cache switch and contents are process-global: run the sequences one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Signs `count` messages twice from the same key, cache on and cache off (upstream), and
/// requires identical signatures and identical updated private keys after every step.
fn same_sequence(params: &[HssParameter<H>], count: usize) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut seed = Seed::<H>::default();
    for (i, b) in seed.as_mut_slice().iter_mut().enumerate() {
        *b = (i * 13 + 7) as u8;
    }
    cache_clear();
    let (sk, vk) = keygen::<H>(params, &seed, None).unwrap();
    let (mut cached, mut reference) = (sk.as_slice().to_vec(), sk.as_slice().to_vec());
    for k in 0..count {
        let msg = [k as u8, 0x5a, 0xa5];
        cache_set_enabled(true);
        let mut next = Vec::new();
        let a = sign::<H>(&msg, &cached, &mut |s: &[u8]| {
            next = s.to_vec();
            Ok(())
        }, None)
        .unwrap();
        cached = next;
        cache_set_enabled(false);
        let mut next = Vec::new();
        let b = sign::<H>(&msg, &reference, &mut |s: &[u8]| {
            next = s.to_vec();
            Ok(())
        }, None)
        .unwrap();
        reference = next;
        cache_set_enabled(true);
        assert!(a.as_ref() == b.as_ref(), "signature {} differs", k);
        assert!(cached == reference, "updated key {} differs", k);
        assert!(verify::<H>(&msg, a.as_ref(), vk.as_slice()).is_ok());
    }
    assert!(cache_stats().0 > 0, "cache never used");
}

#[test]
fn lms_h10_cached_signatures_match_upstream() {
    same_sequence(&[HssParameter::new(LmotsAlgorithm::LmotsW4, LmsAlgorithm::LmsH10)], 24);
}

#[test]
fn hss_two_levels_cached_signatures_match_upstream_across_child_trees() {
    // 40 signatures under a 32-leaf child tree: crosses to the parent's next leaf and a
    // brand-new child tree (new I, new SEED) at signature 32.
    same_sequence(
        &[
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
        ],
        40,
    );
}
