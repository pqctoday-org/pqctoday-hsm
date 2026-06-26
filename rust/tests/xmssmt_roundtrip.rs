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
