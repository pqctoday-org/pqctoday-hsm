//! Guards that must be evaluated with the library compiled as a dependency,
//! not with its unit-test `cfg(test)`. This is the shape of a shipped native
//! or WASM consumer.

#[cfg(not(feature = "acvp"))]
#[test]
fn normal_build_rejects_hpke_deterministic_encapsulation_seed() {
    use softhsmrustv3::constants::{
        CKM_SHA256, CKP_HPKE_KEM_ML_KEM_768, CKR_MECHANISM_PARAM_INVALID,
        CKZ_HPKE_AEAD_128_GCM, CKZ_HPKE_MODE_BASE,
    };
    use softhsmrustv3::native::hpke::{encapsulate, HpkeParams};

    let seed = [0x42u8; 32];
    let params = HpkeParams {
        kem_id: CKP_HPKE_KEM_ML_KEM_768,
        kdf_id: CKM_SHA256,
        aead_id: CKZ_HPKE_AEAD_128_GCM,
        mode: CKZ_HPKE_MODE_BASE,
        psk: &[],
        psk_id: &[],
        info: &[],
        sender_static_priv: None,
        sender_static_pub: None,
        ephemeral_seed: Some(&seed),
    };

    assert!(
        matches!(
            encapsulate(0, 0, &params, None),
            Err(CKR_MECHANISM_PARAM_INVALID)
        ),
        "a normal library build must reject the deterministic HPKE hook before accessing a key",
    );
}
