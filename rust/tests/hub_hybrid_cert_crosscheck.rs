// Independent cross-check for `native::keygen::register_ecdsa_public_key`
// (the pure-Rust SPKI decoder added for the KMIP Certify/Validate port).
//
// Every prior test for this function (see `native::keygen::tests::
// register_ecdsa_public_key_round_trips_p256_p384_p521`) is a same-codebase
// round trip: this engine's own encoder produces the SPKI, this engine's
// own decoder reads it back. That proves internal consistency, not
// interoperability -- a decoder bug that mirrors an encoder bug would still
// pass.
//
// This test instead embeds a fixture produced entirely OUTSIDE this crate:
// the hub webapp's real Hybrid Certificate Workshop code
// (`pqctoday-hub/src/components/PKILearning/modules/HybridCrypto/services/
// certBuilder.ts`, function `buildCompositeCert`) driven with a P-256
// keypair and ECDSA-SHA256 signature from Node's `node:crypto` WebCrypto
// (OpenSSL-backed -- a second, independent crypto implementation, sharing
// no code with either this Rust engine or the hub's own DER layer's
// assumptions about key encoding).
//
// Reproduction recipe (Node + tsx, run from the `pqctoday-hub` repo root
// so its tsconfig/node_modules resolve):
//
//   import { webcrypto } from 'node:crypto'
//   import { buildCompositeCert, type SignerFn } from
//     './src/components/PKILearning/modules/HybridCrypto/services/certBuilder'
//
//   const keyPair = await webcrypto.subtle.generateKey(
//     { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
//   const point = new Uint8Array(await webcrypto.subtle.exportKey('raw', keyPair.publicKey))
//   const ecSignerFn: SignerFn = async (tbs) =>
//     new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, tbs))
//   // buildCompositeCert also needs an ML-DSA-65 half; its bytes are
//   // irrelevant to this EC-only check, so a correctly-sized dummy keeps
//   // the real assembly code running end to end without touching the
//   // EC SPKI/signature path under test here.
//   const certDer = await buildCompositeCert(
//     point, new Uint8Array(1952), ecSignerFn, async () => new Uint8Array(3309),
//     '/CN=cross-check-p256')
//
// `TBS_HEX` below is the exact byte sequence `buildCompositeCert` passed to
// `ecSignerFn` (captured, not reconstructed). `SIG_RAW_R_S_HEX` is the exact
// 64-byte raw-r||s signature WebCrypto returned over it. `POINT_HEX` is the
// exact raw SEC1 uncompressed point WebCrypto exported.
//
// Rather than re-wrap `POINT_HEX` into an SPKI using this crate's own
// encoder (which would leave the encode side untested by anything but
// itself), this test locates the standalone `SubjectPublicKeyInfo` TLV the
// hub's TS code itself built and embedded inside the real TBSCertificate --
// a self-describing short-form DER SEQUENCE -- and feeds THAT literal slice
// to `register_ecdsa_public_key`. So both the encoder (TS) and the crypto
// (WebCrypto/OpenSSL) sides are fully external to this crate; only the
// decoder and the signature verification are this engine's own code.

use softhsmrustv3::constants::CKM_ECDSA_SHA256;
use softhsmrustv3::native::keygen::register_ecdsa_public_key;
use softhsmrustv3::native::session::{bootstrap_default_token, close_session, init};
use softhsmrustv3::native::sign::verify;

const POINT_HEX: &str = "\
04e1b31208d1640d21a592ced5a8c1592991ff379ee8fc41d45f61ef5b818c455187571e26ed850b3c473c1046\
2e7b6c2e038c8057fde18477ec796323a013d27e";

const SIG_RAW_R_S_HEX: &str = "\
2dc8378d7dbc00895bffa8b1fd0ac85f427110a6f009f0cc24a3780fd2d899afe0b811ffd4c40c37e39ca6d6b4\
cbbc5f25f4d8d3e4a6680d4f5e51da428025b2";

// The full TBSCertificate `buildCompositeCert` produced and asked
// `ecSignerFn` to sign, hex-encoded. Includes the real composite-format
// padding for the (irrelevant to this check) ML-DSA-65 dummy half, hence
// its size.
const TBS_HEX: &str = "\
308208b6a003020102021012fd123749a6e11008470ae1be4afdb7300a06082b0601050507062d301b31193017\
06035504030c1063726f73732d636865636b2d70323536301e170d3236303731303031313332375a170d323730\
3731303031313332375a301b3119301706035504030c1063726f73732d636865636b2d7032353630820826300a\
06082b0601050507062d0382081600308208113059301306072a8648ce3d020106082a8648ce3d030107034200\
04e1b31208d1640d21a592ced5a8c1592991ff379ee8fc41d45f61ef5b818c455187571e26ed850b3c473c1046\
2e7b6c2e038c8057fde18477ec796323a013d27e308207b2300b0609608648016503040312038207a100000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000a30d300b30090603551d1304023000";

fn hex_decode(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(clean.len() % 2, 0, "odd-length hex fixture");
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("invalid hex in fixture"))
        .collect()
}

/// Locate `prefix` in `haystack` and return the full DER TLV starting
/// there, reading a short-form (<128-byte) length octet. Panics if the
/// prefix isn't found or the length form isn't short-form -- both would
/// mean the fixture changed shape and this test needs to be regenerated,
/// not silently patched around.
fn extract_der_tlv<'a>(haystack: &'a [u8], prefix: &[u8]) -> &'a [u8] {
    let start = haystack
        .windows(prefix.len())
        .position(|w| w == prefix)
        .expect("fixture prefix not found in TBS -- regenerate the fixture");
    let len_octet = haystack[start + 1];
    assert!(len_octet < 0x80, "fixture uses long-form DER length -- update extract_der_tlv");
    let total = 2 + len_octet as usize;
    &haystack[start..start + total]
}

#[test]
fn hub_certbuilder_ecdsa_p256_verifies_against_rust_engine() {
    let point = hex_decode(POINT_HEX);
    let sig = hex_decode(SIG_RAW_R_S_HEX);
    let tbs = hex_decode(TBS_HEX);
    assert_eq!(point.len(), 65, "fixture point must be an uncompressed SEC1 P-256 point");
    assert_eq!(sig.len(), 64, "fixture signature must be raw r||s for P-256");

    // Pull the literal standalone SPKI TLV out of the real TBSCertificate
    // bytes -- this is the hub TS code's own DER, not anything re-encoded
    // by this crate.
    const SPKI_PREFIX: [u8; 24] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    ];
    let spki = extract_der_tlv(&tbs, &SPKI_PREFIX);
    assert_eq!(spki.len(), 91, "expected a 91-byte P-256 SPKI TLV");
    assert!(
        spki.ends_with(&point),
        "SPKI embedded in the real TBSCertificate must end with the independently-captured raw point"
    );

    init().expect("engine init failed");
    let session = bootstrap_default_token(0, "so", "user", "hub-crosscheck-token")
        .expect("bootstrap_default_token failed");

    let handle = register_ecdsa_public_key(session, spki, b"\x01", "hub-crosscheck-p256")
        .expect("register_ecdsa_public_key must accept the hub tool's real SPKI DER");

    let ok = verify(session, handle, CKM_ECDSA_SHA256, &tbs, &sig)
        .expect("verify must not error");
    assert!(
        ok,
        "a signature produced by the hub's real certBuilder.ts + Node WebCrypto (OpenSSL) \
         must verify against a key imported by this engine's own register_ecdsa_public_key"
    );

    // Negative control: flipping a signature bit must not verify -- proves
    // this isn't a vacuously-true check.
    let mut bad_sig = sig.clone();
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0xff;
    let bad_ok = verify(session, handle, CKM_ECDSA_SHA256, &tbs, &bad_sig)
        .expect("verify must not error");
    assert!(!bad_ok, "corrupted cross-implementation signature must NOT verify");

    close_session(session).expect("close_session failed");
}
