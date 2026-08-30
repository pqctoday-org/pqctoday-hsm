#!/usr/bin/env python3
"""Merge N sharded p11_diff JSON reports into one combined report.

Usage: merge-differential-shards.py <out_prefix> <shard1.json> [<shard2.json> ...]

Writes <out_prefix>.json and <out_prefix>.md, prints the combined summary,
and exits 0 iff every shard's divergences_uncovered is 0. This intentionally
does not try to reproduce every table the single-process report writes
(the "Attribute-set context" table is per-shard only, noted as such in the
merged Markdown) — it exists to make a --parallel run's pass/fail verdict
and findings list as legible as the sequential run's, not to be
byte-identical to it.
"""
import json
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    out_prefix = sys.argv[1]
    shard_paths = sys.argv[2:]

    shards = []
    for p in shard_paths:
        with open(p) as f:
            shards.append(json.load(f))

    summary = {
        "scenarios_run": 0, "scenarios_skipped": 0, "observations_compared": 0,
        "divergences_covered": 0, "divergences_uncovered": 0,
        "divergences_legal": 0, "divergences_known_defect": 0,
        "shard_count": len(shards),
    }
    findings = []
    exception_hits = {}  # id -> (status, hits)
    for sh in shards:
        s = sh["_summary"]
        for k in ("scenarios_run", "scenarios_skipped", "observations_compared",
                   "divergences_covered", "divergences_uncovered",
                   "divergences_legal", "divergences_known_defect"):
            summary[k] += s.get(k, 0)
        findings.extend(sh.get("findings", []))
        for x in sh.get("exception_usage", []):
            xid = x["id"]
            if xid not in exception_hits:
                exception_hits[xid] = {"id": xid, "status": x["status"], "hits": 0}
            exception_hits[xid]["hits"] += x.get("hits", 0)
    if shards:
        summary["cpp_engine"] = shards[0]["_summary"].get("cpp_engine", "")
        summary["rust_engine"] = shards[0]["_summary"].get("rust_engine", "")
        summary["exception_list"] = shards[0]["_summary"].get("exception_list", "")

    merged = {
        "_summary": summary,
        "findings": findings,
        "exception_usage": list(exception_hits.values()),
    }
    with open(out_prefix + ".json", "w") as f:
        json.dump(merged, f, indent=2)
        f.write("\n")

    uncovered = [f for f in findings if not f.get("exception_id")]
    covered_by_exc = {}
    for f in findings:
        xid = f.get("exception_id")
        if xid:
            covered_by_exc.setdefault(xid, []).append(f)

    with open(out_prefix + ".md", "w") as f:
        f.write("# Cross-engine differential report (merged, --parallel)\n\n")
        f.write(f"**C++ engine:** `{summary.get('cpp_engine', '')}`  \n")
        f.write(f"**Rust engine:** `{summary.get('rust_engine', '')}`  \n")
        f.write(f"**Exception list:** `{summary.get('exception_list', '')}`  \n")
        f.write(f"**Shards merged:** {summary['shard_count']}  \n\n")
        f.write("| | |\n|---|---|\n")
        f.write(f"| scenarios run | {summary['scenarios_run']} |\n")
        f.write(f"| observations compared | {summary['observations_compared']} |\n")
        f.write(f"| scenarios skipped (mechanism absent on one engine) | {summary['scenarios_skipped']} |\n")
        f.write(f"| divergences adjudicated legal | {summary['divergences_legal']} |\n")
        f.write(f"| divergences recorded as known defects | {summary['divergences_known_defect']} |\n")
        f.write(f"| divergences UNCOVERED | {summary['divergences_uncovered']} |\n\n")
        if uncovered:
            f.write("## Uncovered divergences\n\n| scenario | path | kind | C++ | Rust |\n|---|---|---|---|---|\n")
            for finding in uncovered:
                f.write(f"| {finding['scenario']} | `{finding['path']}` | {finding['kind']} "
                        f"| `{finding['cpp']}` | `{finding['rust']}` |\n")
            f.write("\n")
        f.write("_Note: the per-object attribute-set context table is per-shard only in "
                 "a --parallel run and is not reproduced here; see each shard's own "
                 "report under the workdir if you need it._\n\n")
        f.write("## Covered divergences by exception entry\n\n")
        f.write("| exception | status | observations |\n|---|---|---|\n")
        for xid, items in sorted(covered_by_exc.items()):
            status = items[0].get("status", "")
            f.write(f"| {xid} | {status} | {len(items)} |\n")
        f.write("\n")

    print("================================================================")
    print(" DIFFERENTIAL RESULT (merged across %d shard(s))" % summary["shard_count"])
    print("================================================================")
    print(f" scenarios run          : {summary['scenarios_run']} "
          f"({summary['scenarios_skipped']} skipped for absent mechanisms)")
    print(f" observations compared  : {summary['observations_compared']}")
    print(f" divergences, legal     : {summary['divergences_legal']}  (adjudicated permitted, with citation)")
    print(f" divergences, known defect: {summary['divergences_known_defect']} (recorded open non-conformance)")
    print(f" divergences, UNCOVERED : {summary['divergences_uncovered']}  <-- these fail the run")
    print("================================================================")
    print(f"\nreports: {out_prefix}.json  {out_prefix}.md")

    return 0 if summary["divergences_uncovered"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
