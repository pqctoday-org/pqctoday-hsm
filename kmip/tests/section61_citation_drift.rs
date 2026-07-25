//! §6.1.x citation drift guard (2026-07-24 CSD02 migration).
//!
//! CSD02 inserted `Decapsulate`/`Encapsulate` early in the §6.1.x operation
//! numbering, shifting every operation section from §6.1.15 onward by one or
//! two relative to CSD01 — the baseline this codebase's ~300 `§6.1.N`
//! citations were originally written against. Those were re-based onto CSD02
//! numbering in one pass, matched by operation name rather than blind number
//! substitution: a citation was only rewritten when the CSD01 name for its
//! OWN cited number appeared in the surrounding 3-line block (the same test
//! this file runs) — a much weaker "any known op name within N characters"
//! heuristic was tried first and rejected after it produced real false
//! positives (e.g. matching "Ping" inside "Key Wrapping", or the ordinary
//! English word "hash" in "padding/hash" near an unrelated §6.1.61 Signature
//! Verify citation) — see the migration's own session notes.
//!
//! This test re-runs that exact detection rule going forward: wherever a
//! `§6.1.N` citation's surrounding block contains the CSD01 (pre-CSD02) name
//! for section N, CSD02 has renumbered that operation and the citation must
//! use the new number — the same class of drift the migration itself fixed.
//! It intentionally does NOT try to validate every citation in the codebase
//! (weaker heuristics for the harder cases risk false positives, same as the
//! migration's own experience) — narrower and reliable beats broad and noisy.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize)]
struct Section61Headings {
    csd01_operations: HashMap<String, String>,
    csd02_operations: HashMap<String, String>,
}

/// CSD01 §6.1.x number -> name, for ONLY the operations CSD02 actually
/// renumbered (same number, different name between the two tables).
/// Deliberately NOT hand-transcribed into Rust source: a hand-transcription
/// of this exact table done during the 2026-07-24 migration silently
/// dropped one entry (§6.1.19 Destroy) and shifted every subsequent entry
/// by one position — undetected until it produced bad citation-fix
/// candidates downstream. Both full tables are loaded from the checked-in
/// spec-derived JSON and diffed here instead, so there is nothing left to
/// transcribe incorrectly.
fn csd01_names_where_number_shifted(headings: &Section61Headings) -> HashMap<String, String> {
    headings
        .csd01_operations
        .iter()
        .filter(|(num, name)| headings.csd02_operations.get(*num) != Some(name))
        .map(|(num, name)| (num.rsplit('.').next().unwrap().to_string(), name.clone()))
        .collect()
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Every char-boundary-safe whole-word/phrase occurrence of `name` in
/// `text`, as (start, end-exclusive) indices into the normalized char
/// stream — not merely a substring of a longer identifier ("Get" must not
/// match inside "GetAttributeList"; "MAC" must not match inside a
/// hypothetical "MACRO"). Position tracking lets the boundary check happen
/// against the REAL characters immediately before/after the match, not just
/// the stripped-down normalized string (which has already discarded the
/// separators that would make a boundary check meaningful).
fn whole_name_occurrences(text: &str, name: &str) -> Vec<(usize, usize)> {
    let target = norm(name);
    if target.is_empty() {
        return Vec::new();
    }
    let mapped: Vec<(char, usize)> = text
        .char_indices()
        .filter(|(_, c)| c.is_ascii_alphanumeric())
        .map(|(i, c)| (c.to_ascii_lowercase(), i))
        .collect();
    let norm_chars: Vec<char> = mapped.iter().map(|(c, _)| *c).collect();
    let target_chars: Vec<char> = target.chars().collect();
    if target_chars.len() > norm_chars.len() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for start in 0..=(norm_chars.len() - target_chars.len()) {
        if norm_chars[start..start + target_chars.len()] != target_chars[..] {
            continue;
        }
        let end = start + target_chars.len() - 1;
        let before_ok = start == 0 || {
            let prev_byte = mapped[start].1;
            let text_before = &text[..prev_byte];
            !text_before.chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric())
        };
        let after_ok = end + 1 == mapped.len() || {
            let next_byte_start = mapped[end].1 + mapped[end].0.len_utf8();
            let text_after = &text[next_byte_start..];
            !text_after.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        };
        if before_ok && after_ok {
            hits.push((start, start + target_chars.len()));
        }
    }
    hits
}

/// `true` if `name` appears in `text` as a whole word/phrase AND that
/// occurrence isn't actually the leading words of a DIFFERENT, longer known
/// operation name starting at the same position — "Query" is a real whole
/// word inside "Query Asynchronous Requests" too (word-boundary-safe on its
/// own), but a §6.1.N citation next to that phrase means Query Asynchronous
/// Requests, not bare Query. `other_names` is every other CSD01 name in the
/// table (checked so a same-position, strictly-longer match rules the short
/// one out).
fn contains_whole_name(text: &str, name: &str, other_names: &[&str]) -> bool {
    let hits = whole_name_occurrences(text, name);
    if hits.is_empty() {
        return false;
    }
    for (start, end) in &hits {
        let shadowed = other_names.iter().any(|&other| {
            if other == name || other.len() <= name.len() {
                return false;
            }
            whole_name_occurrences(text, other)
                .iter()
                .any(|(os, oe)| *os == *start && *oe > *end)
        });
        if !shadowed {
            return true;
        }
    }
    false
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}
fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn load_headings() -> Section61Headings {
    let p = "spec/oasis-kmip-3.0/kmip-spec-3.0-section61-headings.json";
    let raw = fs::read_to_string(p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    serde_json::from_str(&raw).expect("parse section61 headings")
}

fn csd02_number_for_name(headings: &Section61Headings) -> HashMap<String, String> {
    headings
        .csd02_operations
        .iter()
        .map(|(num, name)| (norm(name), num.rsplit('.').next().unwrap().to_string()))
        .collect()
}

fn walk_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Line index (0-based) containing byte offset `off`.
fn line_index_for_offset(line_starts: &[usize], off: usize) -> usize {
    match line_starts.binary_search(&off) {
        Ok(i) => i,
        Err(i) => i.saturating_sub(1),
    }
}

#[test]
fn section61_citations_are_not_still_csd01_numbered() {
    let headings = load_headings();
    assert_eq!(headings.csd01_operations.len(), 62, "sanity: CSD01 §6.1.x has 62 operations");
    assert_eq!(headings.csd02_operations.len(), 64, "sanity: CSD02 §6.1.x has 64 operations");
    let csd01 = csd01_names_where_number_shifted(&headings);
    let csd02_num_for_name = csd02_number_for_name(&headings);
    let all_csd01_names: Vec<&str> = csd01.values().map(|s| s.as_str()).collect();

    let mut roots = vec!["src".to_string()];
    if Path::new("conformance/harness").exists() {
        roots.push("conformance/harness".to_string());
    }
    // The sibling wasm/ crate (bridge code, doc comments ported from kmip/'s
    // own) was missed by the original migration sweep — found only when a
    // real wasm rebuild regenerated its .d.ts bindings and the diff showed
    // a citation going the WRONG direction (§6.1.57 -> §6.1.55). Covered
    // here so that class of gap can't recur silently.
    if Path::new("../wasm/src").exists() {
        roots.push("../wasm/src".to_string());
    }
    let mut files = Vec::new();
    for root in &roots {
        walk_rs_files(Path::new(root), &mut files);
    }
    assert!(!files.is_empty(), "must find at least one .rs file to scan");

    let mut violations = Vec::new();
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else { continue };
        let lines: Vec<&str> = text.lines().collect();
        let mut line_starts = Vec::with_capacity(lines.len());
        {
            let mut acc = 0usize;
            for l in &lines {
                line_starts.push(acc);
                acc += l.len() + 1; // approximate; only used for block lookup below
            }
        }

        let bytes = text.as_bytes();
        let mut i = 0usize;
        while let Some(off) = text[i..].find("§6.1.") {
            let start = i + off;
            let digits_start = start + "§6.1.".len();
            let mut end = digits_start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end == digits_start {
                i = start + "§6.1.".len();
                continue;
            }
            let cited_num = &text[digits_start..end];
            i = end;

            let Some(old_name) = csd01.get(cited_num) else { continue };

            let li = line_index_for_offset(&line_starts, start);
            let block_lo = li.saturating_sub(1);
            let block_hi = (li + 2).min(lines.len());
            let block = lines[block_lo..block_hi].join("\n");

            if contains_whole_name(&block, old_name, &all_csd01_names) {
                let real_num = csd02_num_for_name
                    .get(&norm(old_name))
                    .unwrap_or_else(|| panic!("'{old_name}' not in CSD02 headings table"));
                if real_num != cited_num {
                    let ctx_start = floor_char_boundary(&text, start.saturating_sub(60));
                    let ctx_end = ceil_char_boundary(&text, (end + 60).min(text.len()));
                    violations.push(format!(
                        "{}: §6.1.{cited_num} '{old_name}' is CSD01 numbering — CSD02 renumbered \
                         it to §6.1.{real_num} — context: {:?}",
                        path.display(),
                        text[ctx_start..ctx_end].replace('\n', " ")
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "found {} §6.1.x citation(s) still using CSD01 numbering (the operation name in the \
         surrounding block matches CSD01's name for the cited number, not CSD02's) — rewrite to \
         the CSD02 section number:\n{}",
        violations.len(),
        violations.join("\n")
    );
}
