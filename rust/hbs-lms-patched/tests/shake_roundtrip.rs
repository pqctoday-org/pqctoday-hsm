//! SP 800-208 SHAKE-256 round-trip + type-ID serialization checks for the
//! patched type-ID handling (see repo gap-analysis: hbs-lms finding).

use core::convert::TryInto;
use hbs_lms::*;

fn roundtrip<H: HashChain>(expect_lms_type: u32, expect_lmots_type: u32) {
    let params = [HssParameter::<H>::new(LmotsAlgorithm::LmotsW8, LmsAlgorithm::LmsH5)];
    let seed = Seed::<H>::default();
    let (mut sk, vk) = keygen::<H>(&params, &seed, None).expect("keygen");

    // public key embeds: u32be(L) || u32be(lms_type) || u32be(lmots_type) || ...
    let pk = vk.as_slice();
    let lms_type = u32::from_be_bytes(pk[4..8].try_into().unwrap());
    let lmots_type = u32::from_be_bytes(pk[8..12].try_into().unwrap());
    assert_eq!(lms_type, expect_lms_type, "LMS wire type id");
    assert_eq!(lmots_type, expect_lmots_type, "LMOTS wire type id");

    let msg = b"shake round trip";
    let mut update = |_new_state: &[u8]| -> Result<(), ()> { Ok(()) };
    let sig = sign::<H>(msg, sk.as_mut_slice(), &mut update, None).expect("sign");
    assert!(
        verify::<H>(msg, sig.as_ref(), pk).is_ok(),
        "verify round-trip"
    );
    // negative: flipped message must fail
    assert!(verify::<H>(b"other message!!!", sig.as_ref(), pk).is_err());
}

#[test]
fn sha256_n32_roundtrip_and_type_ids() {
    roundtrip::<Sha256_256>(0x05, 0x04);
}

#[test]
fn shake256_n32_roundtrip_and_type_ids() {
    roundtrip::<Shake256_256>(0x0F, 0x0C);
}

#[test]
fn shake256_n24_roundtrip_and_type_ids() {
    roundtrip::<Shake256_192>(0x14, 0x10);
}

#[test]
fn sha256_n24_roundtrip_and_type_ids() {
    roundtrip::<Sha256_192>(0x0A, 0x08);
}
