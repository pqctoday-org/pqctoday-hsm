//! Decapsulates the official Round-4 KAT vectors (`kmip/kat/classic-mceliece/`,
//! sourced and checksummed in P0-3) against this fork's own `decapsulate_boxed`,
//! for all 10 parameter sets, and asserts the recovered shared secret matches the
//! official `ss` field byte-for-byte — the decapsulate-primary KAT design from the
//! implementation plan §4.1 step 5 / §6 item 4, run here directly against the fork
//! ahead of the full `kmip/tests/classic_mceliece_kat.rs` wiring Phase 3 owns. Only
//! `count = 0` is checked per variant (all 10 vectors' `sk`/`ct`/`ss` triples are
//! independent inputs to the same decapsulate function, so one is sufficient to
//! prove the ported algorithm reproduces the official reference; the KAT files
//! carry 10 each in case a future revision wants more).

use std::fs;
use std::path::PathBuf;

fn kat_path(variant: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../kmip/kat/classic-mceliece/raw")
        .join(variant)
        .join("kat_kem.rsp")
}

struct Vector {
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Parse `count = 0`'s sk/ct/ss fields from a NIST-format `.rsp` file.
fn parse_first_vector(path: &PathBuf) -> Vector {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let mut sk = None;
    let mut ct = None;
    let mut ss = None;
    let mut in_first_block = false;

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("count = ") {
            if rest == "0" {
                in_first_block = true;
            } else if in_first_block {
                break; // moved past count=0's block
            }
            continue;
        }
        if !in_first_block {
            continue;
        }
        if let Some(v) = line.strip_prefix("sk = ") {
            sk = Some(hex_decode(v));
        } else if let Some(v) = line.strip_prefix("ct = ") {
            ct = Some(hex_decode(v));
        } else if let Some(v) = line.strip_prefix("ss = ") {
            ss = Some(hex_decode(v));
        }
    }

    Vector {
        sk: sk.unwrap_or_else(|| panic!("no sk in {path:?}")),
        ct: ct.unwrap_or_else(|| panic!("no ct in {path:?}")),
        ss: ss.unwrap_or_else(|| panic!("no ss in {path:?}")),
    }
}

macro_rules! kat_test {
    ($test_name:ident, $variant_dir:literal, $module:ident) => {
        #[test]
        fn $test_name() {
            use classic_mceliece_multi::$module::{CiphertextOwned, SecretKeyOwned};

            let v = parse_first_vector(&kat_path($variant_dir));
            assert_eq!(v.sk.len(), classic_mceliece_multi::$module::CRYPTO_SECRETKEYBYTES,
                "official sk length disagrees with this fork's CRYPTO_SECRETKEYBYTES for {}", $variant_dir);
            assert_eq!(v.ct.len(), classic_mceliece_multi::$module::CRYPTO_CIPHERTEXTBYTES,
                "official ct length disagrees with this fork's CRYPTO_CIPHERTEXTBYTES for {}", $variant_dir);
            assert_eq!(v.ss.len(), 32);

            let sk_arr: Box<[u8; classic_mceliece_multi::$module::CRYPTO_SECRETKEYBYTES]> =
                v.sk.into_boxed_slice().try_into().unwrap();
            let ct_arr: [u8; classic_mceliece_multi::$module::CRYPTO_CIPHERTEXTBYTES] =
                v.ct.try_into().unwrap();

            let sk = SecretKeyOwned::from(sk_arr);
            let ct = CiphertextOwned::from(ct_arr);

            let recovered = classic_mceliece_multi::$module::decapsulate_boxed(&ct, &sk);

            assert_eq!(
                recovered.as_array().as_slice(),
                v.ss.as_slice(),
                "decapsulated shared secret disagrees with the official KAT vector for {}",
                $variant_dir
            );
        }
    };
}

kat_test!(kat_mceliece348864, "mceliece348864", mceliece348864);
kat_test!(kat_mceliece348864f, "mceliece348864f", mceliece348864f);
kat_test!(kat_mceliece460896, "mceliece460896", mceliece460896);
kat_test!(kat_mceliece460896f, "mceliece460896f", mceliece460896f);
kat_test!(kat_mceliece6688128, "mceliece6688128", mceliece6688128);
kat_test!(kat_mceliece6688128f, "mceliece6688128f", mceliece6688128f);
kat_test!(kat_mceliece6960119, "mceliece6960119", mceliece6960119);
kat_test!(kat_mceliece6960119f, "mceliece6960119f", mceliece6960119f);
kat_test!(kat_mceliece8192128, "mceliece8192128", mceliece8192128);
kat_test!(kat_mceliece8192128f, "mceliece8192128f", mceliece8192128f);
