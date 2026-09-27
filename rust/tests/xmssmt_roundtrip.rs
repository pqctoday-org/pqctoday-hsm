// Isolate the XMSS^MT bridge round-trip (keygen → serialize → sign → verify).
use softhsmrustv3::crypto::xmss_bridge;

#[test]
fn xmss_single_tree_roundtrip() {
    // CKP_XMSS_SHA2_10_256 = 0x01 in the single-tree namespace.
    use softhsmrustv3::constants::CKP_XMSS_SHA2_10_256;
    xmss_bridge::set_kat_seed_value(Some([3u8; 96]));
    let (pk, sk) = xmss_bridge::xmss_keygen(CKP_XMSS_SHA2_10_256).expect("xmss keygen failed");
    eprintln!("XMSS pk.len()={} sk.len()={}", pk.len(), sk.len());
    match xmss_bridge::xmss_sign(CKP_XMSS_SHA2_10_256, &sk, b"hello") {
        Ok((sig, _)) => {
            assert!(xmss_bridge::xmss_verify(CKP_XMSS_SHA2_10_256, &pk, b"hello", &sig));
            eprintln!("XMSS single-tree round-trip OK, sig.len()={}", sig.len());
        }
        Err(e) => panic!("XMSS single-tree xmss_sign failed RV={e}"),
    }
    xmss_bridge::set_kat_seed_value(None);
}

#[test]
fn xmssmt_20_2_256_roundtrip() {
    xmss_bridge::set_kat_seed_value(Some([7u8; 96]));
    let (pk, sk) = xmss_bridge::xmssmt_keygen(1).expect("xmssmt keygen failed");
    eprintln!("pk.len()={} sk.len()={}", pk.len(), sk.len());
    let (sig, new_sk) = match xmss_bridge::xmssmt_sign(1, &sk, b"hello") {
        Ok(v) => v,
        Err(e) => panic!("xmssmt_sign failed RV={e}"),
    };
    eprintln!("sig.len()={} new_sk.len()={}", sig.len(), new_sk.len());
    assert!(
        xmss_bridge::xmssmt_verify(1, &pk, b"hello", &sig),
        "xmssmt_verify rejected a valid signature"
    );
    xmss_bridge::set_kat_seed_value(None);
}

#[test]
fn xmssmt_20_2_192_roundtrip() {
    // Regression test for the 2026-09-04 fix: xmssmt_keygen hardcoded a
    // 96-byte seed for every parameter set, but the SP 800-208 XMSS^MT
    // *_192 family (params 33-40 SHA2, 49-56 SHAKE256) is n=24, needing a
    // 72-byte seed (SEED_LEN = 3*n) -- from_seed() rejected the wrong-length
    // seed outright, so every _192 keygen failed before this fix. Param 33
    // = XmssMtSha2_20_2_192, the fastest of the 16 affected sets (height 20).
    // The KAT seed is 96 bytes (same fixture the other tests use); the fix
    // is exactly that xmssmt_keygen now slices it down to the real 72
    // instead of feeding all 96 to from_seed().
    xmss_bridge::set_kat_seed_value(Some([11u8; 96]));
    let (pk, sk) = xmss_bridge::xmssmt_keygen(33)
        .expect("xmssmt keygen failed for the _192 (n=24) family");
    eprintln!("pk.len()={} sk.len()={}", pk.len(), sk.len());
    let (sig, new_sk) = match xmss_bridge::xmssmt_sign(33, &sk, b"hello") {
        Ok(v) => v,
        Err(e) => panic!("xmssmt_sign failed RV={e}"),
    };
    eprintln!("sig.len()={} new_sk.len()={}", sig.len(), new_sk.len());
    assert!(
        xmss_bridge::xmssmt_verify(33, &pk, b"hello", &sig),
        "xmssmt_verify rejected a valid signature"
    );
    xmss_bridge::set_kat_seed_value(None);
}
