//! Gate V: the frozen streamed-CKKS generator (pqctoday-fhe
//! docs/ckks/ckks-streamed-evaluation-keys-plan-2026-10-10.md §5.3).
//!
//! Generator version 1 is frozen for registry IDs 2, 3, 0x8002 and 4 and for
//! the rotation key kind. Boards, exported key sets and published evidence rely on
//! its bytes, so nothing below may change while `params::GENERATOR_VERSION`
//! is 1. A change to the registry, a key list, a KDF label or context, a
//! sampler or a known-answer file is a new generator version: bump
//! `GENERATOR_VERSION`, keep version 1 reproducible (the plan's upgrade
//! policy), and add a new table here. A new parameter set under version 1 is
//! appended to the version 1 table with its own oracle KAT; existing rows are
//! never edited.
//!
//! The KAT files are the pqctoday-fhe oracle's output (Lattigo v6.2.0
//! reference spec, `oracle kat <id>`, rotation check `rotcheck kat`) for the
//! seed 00..1f; the unit and integration KAT tests check the generator
//! against them byte for byte. The test below checks the files, the registry
//! and the KDF against this table, so regenerating a KAT, editing the
//! registry or touching the KDF without a version bump fails.

/// One frozen parameter set.
pub struct FrozenSet {
    pub id: u32,
    pub name: &'static str,
    /// `params::param_hash` (SHA-256; bound into every KDF context).
    pub param_hash: &'static str,
    /// `CKA_PQCTODAY_FHE_PARAM_HASH` (SHA-384 of `FheParamSetV1`).
    pub fhe_param_hash: &'static str,
    /// SHA-256 over `params::key_id` of every key, in list order.
    pub key_list_sha256: &'static str,
    pub key_count: usize,
    pub kat_file: &'static str,
    /// SHA-256 of the KAT file's bytes.
    pub kat_sha256: &'static str,
    /// `Generator::kdf_fingerprint` for the seed 00..1f.
    pub kdf_fingerprint: &'static str,
}

/// The frozen rotation key kind (E10), checked on the test ring.
pub struct FrozenRotation {
    pub param_set: u32,
    /// `params::key_id(rotation_desc())`.
    pub key_id: &'static str,
    pub kat_file: &'static str,
    pub kat_sha256: &'static str,
}

pub struct FrozenGenerator {
    pub version: u32,
    /// HSM commit that froze this version (recorded in the plan's §5.3).
    pub frozen_at: &'static str,
    pub config: &'static str,
    pub kdf_labels: &'static [&'static str],
    pub kdf_prefix: &'static str,
    pub kdf_context_version: &'static str,
    pub a_expand_domain: &'static str,
    pub sets: &'static [FrozenSet],
    pub rotation: FrozenRotation,
}

pub const FROZEN: &[FrozenGenerator] = &[FrozenGenerator {
    version: 1,
    frozen_at: "the commit that added this table; pqctoday-fhe plan §5.3 records its hash",
    config: "streamed-evk/v1: AES-256-CTR streams, HMAC-SHA-256 a-expansion, Gaussian CDT sigma 3.2 bound 19, fixed-weight ternary",
    kdf_labels: &["secret", "sparse-secret", "a-seed", "pk-error", "error", "rotation-a-seed", "rotation-error"],
    kdf_prefix: "pqctoday-fhe/ckks/",
    kdf_context_version: "v1",
    a_expand_domain: "pqctoday-fhe/ckks/a/v1",
    sets: &[
        FrozenSet {
            id: 2,
            name: "CKKS_N16QP1546H192H32_LATTIGO_V6_2_0",
            param_hash: "218de3a2152ef7a92bfdba46dd832f8cadddc394c261405833683968757eaf52",
            fhe_param_hash: "a0207af476caa51414e8d46463318296299b150cdcde4cfaf048b455df650252a7257b5f9f4d8e6ece68cb992bfadf8b",
            key_list_sha256: "7e5248cd3d40f81aa958fd912eeb8916b54294fb174ac18259139eb63194a4bd",
            key_count: 51,
            kat_file: "fhe-ckks-kat-2.json",
            kat_sha256: "a63b0757c3a545063302377cf7e4218be07229b1cc6d9b34f555e1ddbc4de339",
            kdf_fingerprint: "41e71d76e389f63005b50f7fe3cacd72f312626c872898ee845777498ff90b8a",
        },
        FrozenSet {
            id: 0x8002,
            name: "CKKS_TEST_INSECURE_N10",
            param_hash: "d835b657d63e6c9c435114d0684874489251d9d90e02df952fa418b73aba1090",
            fhe_param_hash: "fc66fd6f8f4c01d12b65196db146ba8b376844608ef4e991b987992b00fb0ee97855166815044a20bf79a14275f23f93",
            key_list_sha256: "a1616d9260c45f48499d8eb4a9c6d37673a1a0fada848440af615db6e7c57d6b",
            key_count: 22,
            kat_file: "fhe-ckks-kat-32770.json",
            kat_sha256: "d63727b2276ed5b9401acf8d025ba911cd0ee965d5f9061f55d95e0864ab44f1",
            kdf_fingerprint: "71f57166bb94b8968ee7520315b6980a0de04dc2ea08a252ea7873c1fda5a2f8",
        },
        FrozenSet {
            id: 3,
            name: "CKKS_N16QP1468H192H32_METABTS2_LATTIGO_V6_2_0",
            param_hash: "0d92865700adcc8ec28ba1561079161118503fc798a7c04ad1b24addf2f24cba",
            fhe_param_hash: "89eedf447250eb3abd28feb751832b9981358fd5af72ac0078d8e8d08963670a6e41f943e051971beb3a4d0dc54bb0ed",
            key_list_sha256: "a65a994fea81e8c99f36667cac95567582cceae84e2371f7c804cd1a88e2dc9f",
            key_count: 51,
            kat_file: "fhe-ckks-kat-3.json",
            kat_sha256: "6470bc8e2eb3ec1f2cb2c881deb0c3b2cb8c252593f2498d2be12a95fc292372",
            kdf_fingerprint: "484966af1c6620198f6f26ec835d4883e8462c05c32a7ec0916dc9db868c8567",
        },
        // Appended under generator version 1 (additive: existing rows are untouched). The OpenFHE v1.6.0
        // `match128` set: OpenFHE's moduli and closed bootstrapping key list (79 keys), the dense-to-sparse
        // key over the auxiliary primes (key kind 6). Every value below was reproduced outside the engine: the param
        // hash, key-list hash and KDF fingerprint by the oracle (`oracle kat 4`, `oracle kdf-fingerprint 4`), the FheParamSetV1
        // hash by an independent DER encoder. pqctoday-fhe docs/ckks/ckks-openfhe-registry-entry-spec-2026-10-12.md.
        FrozenSet {
            id: 4,
            name: "CKKS_N16QP1720H192H32_OPENFHE_V1_6_0_MATCH128",
            param_hash: "f2bd4160132f114e1acacd168795f9dea1b3354f2e8caf8865beb8a6cdf676d4",
            fhe_param_hash: "edb9b44ed0622d08d2e0f58199ac948446c515fd469332338769647d021404d2b405195aead8de7083d9553ab4c95495",
            key_list_sha256: "b506a82af182b28f390255e7ec3dd83e4fb9ccc77b7083fc003d89b1bbe08bf8",
            key_count: 79,
            kat_file: "fhe-ckks-kat-4.json",
            kat_sha256: "8cff4290d0d915fdf065687e655208f8ac0fbd9abd0749975e0bc9ab0ad0fa0f",
            kdf_fingerprint: "239dbfa06378ec1479353710e2a91dc68a8c6f7ac851e2ac5a6a2484cee472bd",
        },
    ],
    rotation: FrozenRotation {
        param_set: 0x8002,
        key_id: "0500000000000000000000000100000000",
        kat_file: "fhe-ckks-rotation-kat-32770.json",
        kat_sha256: "afa8376dedf72f99e00617437a1f92f6b68fe7d08a829f68e1d06360dcca323b",
    },
}];

/// The table for `version`, if one exists.
pub fn frozen(version: u32) -> Option<&'static FrozenGenerator> {
    FROZEN.iter().find(|g| g.version == version)
}

/// The bytes of a frozen KAT file (compiled into the test build only, so the
/// check needs no working directory).
#[cfg(test)]
pub fn kat_bytes(file: &str) -> Option<&'static [u8]> {
    match file {
        "fhe-ckks-kat-2.json" => Some(include_bytes!("../../../kat/fhe-ckks-kat-2.json")),
        "fhe-ckks-kat-3.json" => Some(include_bytes!("../../../kat/fhe-ckks-kat-3.json")),
        "fhe-ckks-kat-32770.json" => Some(include_bytes!("../../../kat/fhe-ckks-kat-32770.json")),
        "fhe-ckks-kat-4.json" => Some(include_bytes!("../../../kat/fhe-ckks-kat-4.json")),
        "fhe-ckks-rotation-kat-32770.json" => Some(include_bytes!("../../../kat/fhe-ckks-rotation-kat-32770.json")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::{params, spec};
    use super::*;
    use sha2::Digest;

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn key_list_sha256(ps: &params::CkksParamSet) -> String {
        let mut h = sha2::Sha256::new();
        ps.keys.iter().for_each(|k| h.update(params::key_id(k)));
        hexs(&h.finalize())
    }

    /// Every difference between the code and the frozen table, as text.
    fn drift(g: &FrozenGenerator) -> Vec<String> {
        let mut bad = Vec::new();
        let mut eq = |what: String, got: String, want: &str| {
            if got != want {
                bad.push(format!("{what}: code {got}, frozen {want}"));
            }
        };
        eq("config".into(), params::CONFIG_V1.into(), g.config);
        eq("kdf labels".into(), spec::KDF_LABELS_V1.join(","), &g.kdf_labels.join(","));
        eq("kdf prefix".into(), String::from_utf8_lossy(spec::KDF_PREFIX).into(), g.kdf_prefix);
        eq("kdf context version".into(), String::from_utf8_lossy(spec::KDF_CONTEXT_VERSION).into(), g.kdf_context_version);
        eq("a-expansion domain".into(), String::from_utf8_lossy(spec::A_EXPAND_DOMAIN).into(), g.a_expand_domain);
        // Every registered set is frozen, and every frozen set is registered.
        let mut reg: Vec<u32> = params::CKKS_PARAM_SETS.iter().map(|p| p.id).collect();
        let mut fro: Vec<u32> = g.sets.iter().map(|s| s.id).collect();
        reg.sort();
        fro.sort();
        eq("registered sets".into(), format!("{reg:?}"), &format!("{fro:?}"));
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        for f in g.sets {
            let Some(ps) = params::find(f.id) else { continue };
            let id = f.id;
            eq(format!("set {id} name"), ps.name.into(), f.name);
            eq(format!("set {id} param_hash"), hexs(&params::param_hash(ps)), f.param_hash);
            eq(format!("set {id} fhe param hash"), hexs(&crate::replication::fhe::param_hash(id).unwrap()), f.fhe_param_hash);
            eq(format!("set {id} key list"), key_list_sha256(ps), f.key_list_sha256);
            eq(format!("set {id} key count"), ps.keys.len().to_string(), &f.key_count.to_string());
            let kat = kat_bytes(f.kat_file).expect("frozen KAT file compiled in");
            eq(format!("set {id} KAT file {}", f.kat_file), hexs(&sha2::Sha256::digest(kat)), f.kat_sha256);
            // The KAT names this registry entry.
            let j: serde_json::Value = serde_json::from_slice(kat).unwrap();
            eq(format!("set {id} KAT paramSet"), j["paramSet"].to_string(), &id.to_string());
            eq(format!("set {id} KAT paramHash"), j["paramHash"].as_str().unwrap_or("").into(), f.param_hash);
            eq(format!("set {id} KAT keyCount"), j["keyCount"].to_string(), &f.key_count.to_string());
            let generator = spec::Generator::new(ps, &seed);
            eq(format!("set {id} kdf fingerprint"), hexs(&generator.kdf_fingerprint()), f.kdf_fingerprint);
        }
        let r = &g.rotation;
        if let Some(ps) = params::find(r.param_set) {
            eq("rotation key id".into(), hexs(&params::key_id(&ps.rotation_desc())), r.key_id);
        }
        let kat = kat_bytes(r.kat_file).expect("frozen rotation KAT compiled in");
        eq(format!("rotation KAT file {}", r.kat_file), hexs(&sha2::Sha256::digest(kat)), r.kat_sha256);
        bad
    }

    /// Gate V: the code matches the frozen table of its generator version.
    #[test]
    fn generator_matches_frozen_table() {
        let g = frozen(params::GENERATOR_VERSION).unwrap_or_else(|| panic!("no frozen table for generator version {}", params::GENERATOR_VERSION));
        let bad = drift(g);
        assert!(bad.is_empty(), "generator version {} changed without a version bump:\n  {}", g.version, bad.join("\n  "));
    }

    /// The check can fail: a one-bit change to any frozen KAT file, or to a
    /// frozen param_hash or KDF fingerprint, is reported.
    #[test]
    fn freeze_check_detects_one_bit_changes() {
        let g = frozen(1).unwrap();
        for f in g.sets.iter().map(|s| s.kat_file).chain([g.rotation.kat_file]) {
            let mut b = kat_bytes(f).unwrap().to_vec();
            let want = hexs(&sha2::Sha256::digest(&b));
            let i = b.len() / 2;
            b[i] ^= 1;
            assert_ne!(hexs(&sha2::Sha256::digest(&b)), want, "{f}");
        }
        // A frozen value off by one bit is drift.
        let flip = |s: &str| {
            let mut v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
            v[0] ^= 1;
            hexs(&v)
        };
        let ps = params::find(3).unwrap();
        assert_ne!(hexs(&params::param_hash(ps)), flip(&hexs(&params::param_hash(ps))));
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let fp = hexs(&spec::Generator::new(ps, &seed).kdf_fingerprint());
        assert_ne!(fp, flip(&fp));
        // A different seed gives a different fingerprint (it is not constant).
        assert_ne!(fp, hexs(&spec::Generator::new(ps, &[9; 32]).kdf_fingerprint()));
    }
}
