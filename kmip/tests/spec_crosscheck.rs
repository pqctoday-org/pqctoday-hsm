//! KMIP 3.0 spec cross-check — validates the codec's tag + enum codepoints
//! against the NORMATIVE spec extract `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`
//! (itself extracted from `kmip-spec-v3.0.html` and sha256-pinned in the JSON).
//!
//! This is a *direct* cross-check: it parses every `pub const NAME: u32 = 0x…`
//! in the `tags` module and every wire-enum's discriminants from source, and
//! asserts each codepoint equals the spec's. (The 1358-vector OASIS byte
//! round-trip validates the codepoints *indirectly* — only for tags the corpus
//! exercises; this covers the whole table.)

use std::collections::{HashMap, HashSet};
use std::fs;

use serde::Deserialize;

#[derive(Deserialize)]
struct SpecExtract {
    tags: Vec<NamedCode>,
    enums: HashMap<String, Vec<NamedVal>>,
}
#[derive(Deserialize)]
struct NamedCode {
    name: String,
    codepoint: String,
}
#[derive(Deserialize)]
struct NamedVal {
    name: String,
    value: String,
}

/// Normalize a name for matching: lowercase, alphanumerics only. So
/// "Protocol Version Major" == "ProtocolVersionMajor", "ML-DSA-44" == "MlDsa44",
/// "IV Counter Nonce" == "IvCounterNonce", "PKCS#11 Function" == "Pkcs11Function".
fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn parse_hex(s: &str) -> Option<u32> {
    let s = s.trim().trim_end_matches(';').trim().replace('_', "");
    u32::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

fn load_spec() -> SpecExtract {
    let p = "spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json";
    serde_json::from_str(&fs::read_to_string(p).unwrap_or_else(|e| panic!("read {p}: {e}")))
        .expect("parse spec extract")
}

/// Parse `pub const NAME: u32 = 0x…;` lines from a source file.
fn parse_consts(src: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for line in src.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("pub const ") else { continue };
        let Some((name, after)) = rest.split_once(':') else { continue };
        let Some((_, val)) = after.split_once('=') else { continue };
        if let Some(v) = parse_hex(val) {
            out.push((name.trim().to_string(), v));
        }
    }
    out
}

#[test]
fn tag_codepoints_match_spec() {
    let spec = load_spec();
    // spec tag name (normalized) → codepoint
    let mut spec_tags: HashMap<String, u32> = HashMap::new();
    for t in &spec.tags {
        if t.name.contains("Reserved") {
            continue;
        }
        if let Some(v) = parse_hex(&t.codepoint) {
            spec_tags.insert(norm(&t.name), v);
        }
    }

    let src = fs::read_to_string("src/kmip30/wire.rs").expect("read wire.rs");
    let consts = parse_consts(&src);

    // Every valid spec codepoint (regardless of name) — for the bidirectional check.
    let spec_codepoints: HashSet<u32> =
        spec.tags.iter().filter_map(|t| parse_hex(&t.codepoint)).collect();
    // Documented post-3.0 / WD19 PQC extension + vendor ranges (not in the 3.0
    // normative table): a tag whose codepoint is neither a spec codepoint nor in
    // these ranges is a genuine error.
    let is_extension =
        |v: u32| (0x42_01c0..=0x42_01ff).contains(&v) || v >= 0x54_0000;
    // Canonical KMIP tags the token-scan EXTRACT missed (the `tags-enums.json`
    // generator dropped them). The codec value is the standard KMIP registry
    // value, independently asserted in unit tests — so this is an extract gap,
    // not a codec error. Keyed by (codec const name → codepoint).
    let extract_gaps: HashMap<&str, u32> = [
        // Extract has "Object Groups"=0x420166 but is missing the canonical
        // "Object Group"=0x420056 (stable since KMIP 1.0; verified in wire.rs tests).
        ("ObjectGroup", 0x42_0056u32),
    ]
    .into_iter()
    .collect();

    let mut matched = 0usize; // name + codepoint both match spec
    let mut name_variant = 0usize; // codepoint is a valid spec codepoint, name differs
    let mut extension = 0usize; // WD19 PQC / vendor
    let mut mismatches: Vec<String> = Vec::new();
    let mut variant_names: Vec<String> = Vec::new();
    let mut extension_names: Vec<String> = Vec::new();
    for (name, val) in &consts {
        match spec_tags.get(&norm(name)) {
            Some(&spec_val) if spec_val == *val => matched += 1,
            Some(&spec_val) => {
                mismatches.push(format!("{name}: codec 0x{val:06x} != spec 0x{spec_val:06x}"))
            }
            None if spec_codepoints.contains(val) => {
                name_variant += 1;
                variant_names.push(format!("{name}=0x{val:06x}"));
            }
            None if is_extension(*val) => {
                extension += 1;
                extension_names.push(format!("{name}=0x{val:06x}"));
            }
            None if extract_gaps.get(name.as_str()) == Some(val) => {
                name_variant += 1; // codec canonical; extract dropped the entry
                variant_names.push(format!("{name}=0x{val:06x} (extract gap)"));
            }
            None => mismatches.push(format!(
                "{name} = 0x{val:06x} — codepoint NOT in the spec table and not a known extension"
            )),
        }
    }

    eprintln!(
        "\nTAG cross-check vs KMIP 3.0 spec: {matched} name+codepoint match, \
         {name_variant} codepoint-valid name-variants, {extension} WD19/vendor extensions, \
         {} mismatched",
        mismatches.len()
    );
    if !variant_names.is_empty() {
        eprintln!("  name-variants (codepoint valid, codec name differs): {}", variant_names.join(", "));
    }
    if !extension_names.is_empty() {
        eprintln!("  extensions (not in 3.0 table): {}", extension_names.join(", "));
    }
    for m in &mismatches {
        eprintln!("  MISMATCH {m}");
    }
    assert!(
        mismatches.is_empty(),
        "{} codec tag constants disagree with the normative spec",
        mismatches.len()
    );
    assert!(matched > 100, "sanity: expected >100 spec-matched tags, got {matched}");
}

#[test]
fn enum_codepoints_match_spec() {
    let spec = load_spec();
    // spec enum name (normalized) → { value-name(normalized) → value }
    let mut spec_enums: HashMap<String, HashMap<String, u32>> = HashMap::new();
    for (ename, vals) in &spec.enums {
        let mut m = HashMap::new();
        for v in vals {
            if let Some(code) = parse_hex(&v.value) {
                m.insert(norm(&v.name), code);
            }
        }
        spec_enums.insert(norm(ename), m);
    }

    // Codebase enums to check: (source file, codebase enum name, spec enum name).
    // The codebase splits a few names (KmipAlgorithm = spec "Cryptographic
    // Algorithm"); map them explicitly.
    let targets: &[(&str, &str, &str)] = &[
        ("src/kmip30/ops.rs", "Operation", "Operation"),
        ("src/kmip30/attrs.rs", "ObjectType", "Object Type"),
        ("src/kmip30/attrs.rs", "State", "State"),
        ("src/kmip30/algos.rs", "KmipAlgorithm", "Cryptographic Algorithm"),
        ("src/kmip30/ops.rs", "HashingAlgorithm", "Hashing Algorithm"),
    ];

    let mut checked = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    let mut missing_enum: Vec<String> = Vec::new();
    let mut matched_variants: HashSet<String> = HashSet::new();

    for (file, code_enum, spec_enum) in targets {
        let Some(spec_vals) = spec_enums.get(&norm(spec_enum)) else {
            missing_enum.push(format!("{spec_enum} (not in spec extract)"));
            continue;
        };
        let src = fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file}: {e}"));
        // Parse ONLY this enum's own definition + its own `impl … to_wire_value`,
        // so same-named variants from OTHER enums in the file don't bleed in:
        //   - enum block discriminants  `Variant = 0x..`  (Operation/ObjectType/State/HashingAlgorithm)
        //   - to_wire_value match arms   `Variant => 0x..` (KmipAlgorithm's PQC values)
        let mut regions: Vec<&str> = Vec::new();
        if let Some(s) = src.find(&format!("enum {code_enum} {{")) {
            let b = &src[s..];
            regions.push(&b[..b.find("\n}").unwrap_or(b.len())]);
        }
        if let Some(s) = src.find(&format!("impl {code_enum} {{")) {
            let b = &src[s..];
            if let Some(ts) = b.find("fn to_wire_value") {
                let r = &b[ts..];
                regions.push(&r[..r.find("\n    }").unwrap_or(r.len().min(8000))]);
            }
        }
        if regions.is_empty() {
            missing_enum.push(format!("{code_enum} (no enum/impl block found in {file})"));
        }
        for region in regions {
            for line in region.lines() {
                let t = line.trim().trim_end_matches(',');
                let Some((lhs, rhs)) = t.split_once("=>").or_else(|| t.split_once('=')) else {
                    continue;
                };
                let var = lhs.trim();
                if var.is_empty() || !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                let Some(v) = parse_hex(rhs) else { continue };
                let nvar = norm(var);
                match spec_vals.get(&nvar) {
                    Some(&sv) if sv == v => {
                        checked += 1;
                        matched_variants.insert(nvar);
                    }
                    Some(&sv) => {
                        mismatches.push(format!("{code_enum}::{var} codec 0x{v:x} != spec 0x{sv:x}"))
                    }
                    None => {}
                }
            }
        }
    }

    // EXPLICIT PQC coverage: these MUST be present + matching, not silently
    // skipped. (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA.)
    let required_pqc = [
        "mlkem512", "mlkem768", "mlkem1024", "mldsa44", "mldsa65", "mldsa87",
        "slhdsasha2128s", "slhdsasha2128f", "slhdsasha2192s", "slhdsasha2256f",
        "slhdsashake128s", "slhdsashake256f",
    ];
    let missing_pqc: Vec<&str> =
        required_pqc.iter().copied().filter(|p| !matched_variants.contains(*p)).collect();
    eprintln!(
        "PQC algorithm coverage: {}/{} ML-KEM/ML-DSA/SLH-DSA values cross-checked vs spec",
        required_pqc.len() - missing_pqc.len(),
        required_pqc.len()
    );
    assert!(
        missing_pqc.is_empty(),
        "PQC algorithms NOT verified against the spec (missing/mismatched): {missing_pqc:?}"
    );

    eprintln!(
        "\nENUM cross-check vs KMIP 3.0 spec: {checked} variant values matched, {} mismatched",
        mismatches.len()
    );
    for m in &mismatches {
        eprintln!("  MISMATCH {m}");
    }
    for m in &missing_enum {
        eprintln!("  NOTE: {m}");
    }
    assert!(
        mismatches.is_empty(),
        "{} codec enum values disagree with the normative spec",
        mismatches.len()
    );
    assert!(checked > 50, "sanity: expected >50 spec-matched enum values, got {checked}");
}
