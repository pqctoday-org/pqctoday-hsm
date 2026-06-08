//! `extract-kmip-spec` — build-time tool that walks the OASIS KMIP 3.0 HTML
//! spec and emits a structured JSON file of Tags + Enumeration codepoints.
//!
//! Run on demand:
//!   `cargo run --bin extract-kmip-spec`
//!
//! Inputs:
//!   `spec/oasis-kmip-3.0/kmip-spec-v3.0.html`
//!
//! Outputs:
//!   `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`
//!
//! Strategy:
//!
//! The OASIS HTML is Word-converted: every table cell wraps its text in
//! deeply nested `<span>` elements (10+ levels). Tag codepoints look like
//! `420001` and enumeration values look like `00000001`, both rendered in
//! `font-family:"Courier 10 Pitch"`. Tag and enum tables share the same
//! two-column shape: `(name, codepoint)`.
//!
//! We walk the document in source order via `descendants()` and maintain a
//! running "current section heading" cursor. When we encounter a `<table>`,
//! every row whose second cell is a hex codepoint gets attributed to the
//! current heading.
//!
//! Classification per row:
//!   - second-cell text matches `^4[0-9a-fA-F]{5}$` (six hex chars starting
//!     with `4`) → KMIP **tag** (codepoint range `0x420000`–`0x4FFFFF`).
//!   - second-cell text matches `^0000[0-9a-fA-F]{4}$` (eight hex chars
//!     starting `0000`) → **enum value**; parent enum is the most recent
//!     section heading containing the word "Enumeration".
//!   - everything else: skipped (header rows, prose tables, ToC, etc.).
//!
//! Output JSON shape:
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "source_file": "spec/oasis-kmip-3.0/kmip-spec-v3.0.html",
//!   "source_sha256": "<sha256 of input file>",
//!   "extracted_at": "<ISO-8601 timestamp>",
//!   "tags": [
//!     {"name": "Activation Date", "codepoint": "0x420001"},
//!     ...
//!   ],
//!   "enums": {
//!     "Cryptographic Algorithm": [
//!       {"name": "DES", "value": "0x00000001"},
//!       ...
//!     ],
//!     ...
//!   },
//!   "stats": {
//!     "tag_count": <int>,
//!     "enum_count": <int>,
//!     "enum_value_count": <int>
//!   }
//! }
//! ```

use scraper::{Html, Node, Selector};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::process::ExitCode;

const SPEC_HTML: &str = "spec/oasis-kmip-3.0/kmip-spec-v3.0.html";
const OUTPUT_JSON: &str = "spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json";

#[derive(Serialize)]
struct TagEntry {
    name: String,
    codepoint: String,
}

#[derive(Serialize)]
struct EnumValue {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct Output {
    schema_version: u32,
    source_file: String,
    source_sha256: String,
    extracted_at: String,
    tags: Vec<TagEntry>,
    /// Enum name (from the section heading immediately preceding the table)
    /// → list of `(value name, hex codepoint)` pairs.
    enums: BTreeMap<String, Vec<EnumValue>>,
    stats: Stats,
}

#[derive(Serialize)]
struct Stats {
    tag_count: usize,
    enum_count: usize,
    enum_value_count: usize,
}

fn main() -> ExitCode {
    let html_path = Path::new(SPEC_HTML);
    let html_bytes = match std::fs::read(html_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {SPEC_HTML}: {e}");
            return ExitCode::from(2);
        }
    };
    let source_sha256 = hex_sha256(&html_bytes);
    let html_str = String::from_utf8_lossy(&html_bytes).into_owned();

    eprintln!(
        "[extract-kmip-spec] parsing {SPEC_HTML} ({} bytes, sha256={}...)",
        html_bytes.len(),
        &source_sha256[..16]
    );

    let doc = Html::parse_document(&html_str);
    let (tags, enums) = walk(&doc);

    let enum_value_count: usize = enums.values().map(|v| v.len()).sum();
    let stats = Stats {
        tag_count: tags.len(),
        enum_count: enums.len(),
        enum_value_count,
    };

    let out = Output {
        schema_version: 1,
        source_file: SPEC_HTML.into(),
        source_sha256,
        extracted_at: iso8601_now(),
        tags,
        enums,
        stats,
    };

    let json = match serde_json::to_string_pretty(&out) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: serialise: {e}");
            return ExitCode::from(3);
        }
    };
    if let Err(e) = std::fs::write(OUTPUT_JSON, format!("{json}\n")) {
        eprintln!("error: write {OUTPUT_JSON}: {e}");
        return ExitCode::from(4);
    }

    eprintln!(
        "[extract-kmip-spec] wrote {OUTPUT_JSON} — {} tags, {} enums, {} enum values",
        out.stats.tag_count, out.stats.enum_count, out.stats.enum_value_count
    );
    ExitCode::SUCCESS
}

/// Walk the parsed HTML in document order, tracking the most-recent section
/// heading so enum tables can be attributed to their parent enum.
fn walk(doc: &Html) -> (Vec<TagEntry>, BTreeMap<String, Vec<EnumValue>>) {
    let mut tags: Vec<TagEntry> = Vec::new();
    let mut enums: BTreeMap<String, Vec<EnumValue>> = BTreeMap::new();
    let mut seen_tag_names: HashSet<String> = HashSet::new();
    let mut current_heading: Option<String> = None;

    // Selectors used inside tables.
    let row_sel = Selector::parse("tr").unwrap();
    let cell_sel = Selector::parse("td").unwrap();

    // `descendants()` yields ego_tree NodeRef in pre-order (document order).
    for node_ref in doc.tree.nodes() {
        let node = node_ref.value();
        let Node::Element(elem) = node else {
            continue;
        };
        let name = elem.name();
        match name {
            "h1" | "h2" | "h3" | "h4" => {
                // Reconstruct an ElementRef to get .text().
                if let Some(eref) = scraper::ElementRef::wrap(node_ref) {
                    let text = element_plain_text(eref);
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        current_heading = Some(trimmed.to_string());
                    }
                }
            }
            "table" => {
                let Some(table) = scraper::ElementRef::wrap(node_ref) else {
                    continue;
                };
                for row in table.select(&row_sel) {
                    let cells: Vec<scraper::ElementRef> = row.select(&cell_sel).collect();
                    if cells.len() < 2 {
                        continue;
                    }
                    let row_name = element_plain_text(cells[0]).trim().to_string();
                    let cp_raw = element_plain_text(cells[1]).trim().to_string();
                    let cp = cp_raw.strip_prefix("0x").unwrap_or(&cp_raw).to_string();

                    if is_tag_codepoint(&cp) {
                        if row_name.is_empty() || seen_tag_names.contains(&row_name) {
                            continue;
                        }
                        seen_tag_names.insert(row_name.clone());
                        tags.push(TagEntry {
                            name: row_name,
                            codepoint: format!("0x{}", cp.to_lowercase()),
                        });
                    } else if is_enum_codepoint(&cp) {
                        if row_name.is_empty() {
                            continue;
                        }
                        let enum_name = current_heading
                            .as_deref()
                            .and_then(extract_enum_name)
                            .unwrap_or_else(|| "_unattributed".to_string());
                        enums.entry(enum_name).or_default().push(EnumValue {
                            name: row_name,
                            value: format!("0x{}", cp.to_lowercase()),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    (tags, enums)
}

/// `true` when the string is six hex chars and starts with `4`
/// (KMIP tag codepoint range `0x420000`–`0x4FFFFF`).
fn is_tag_codepoint(s: &str) -> bool {
    s.len() == 6 && s.chars().all(|c| c.is_ascii_hexdigit()) && s.starts_with('4')
}

/// `true` when the string is eight hex chars starting `0000`
/// (KMIP enumeration value range — typically `0x00000001` upward per enum).
fn is_enum_codepoint(s: &str) -> bool {
    s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit()) && s.starts_with("0000")
}

/// Heading text like `"10.2.5 Cryptographic Algorithm Enumeration"` →
/// `"Cryptographic Algorithm"`. Returns `None` for headings that don't look
/// like enumeration sections.
fn extract_enum_name(heading: &str) -> Option<String> {
    let h = heading.trim();
    let body = h.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ' ');
    let body = body.trim();
    let stripped = body
        .strip_suffix("Enumeration")
        .or_else(|| body.strip_suffix("Enumerations"))?;
    let name = stripped.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

/// Concatenate all descendant text nodes of an element.
fn element_plain_text(e: scraper::ElementRef) -> String {
    let mut s = String::new();
    for t in e.text() {
        s.push_str(t);
    }
    s
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Minimal ISO-8601 UTC timestamp using the `time` crate (already a dep).
fn iso8601_now() -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}
