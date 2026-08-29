#!/usr/bin/env python3
"""Divergence guard between tests/acvp/ (this repo) and the hub's
src/data/acvp/ (pqctoday-hub) — WS-10 (2026-08-28) of the PKCS#11 HSM
playground remediation, item D-11/D-4.

Nothing related the two vector directories before this: a hub-side session
found 15 of this repo's 19 tests/acvp/*.json files had silently drifted
from the hub's own versions (different content, sometimes different
correctness) with nobody noticing, because there was no check comparing
them at all. This script is that check.

For every filename present in BOTH directories, compares content byte-
for-byte (parsed JSON equality, so key ordering doesn't spuriously fail
it). A divergence is either:
  - accepted: the filename is listed in ACCEPTED_DIVERGENCES below, with a
    citation explaining why the two intentionally differ (or why the hub
    side isn't authoritative yet).
  - a real finding: anything else. Exits 1, printing every unexempted
    divergence — the whole point is that these must be looked at, not
    silently tolerated the way the original 15 were.

Files present in only one directory are reported but do not fail the
check on their own — `tests/acvp/`'s 4 LMS files have no hub counterpart
at all (hub has no LMS/HSS ACVP test), and the hub may always be a step
ahead on newly-added vector files. Missing `_provenance` is reported
separately (informational) — full backfill is tracked, not gated here.

Usage:
    python3 scripts/check_acvp_vector_divergence.py [--check]
    HUB_REPO_PATH=/path/to/pqctoday-hub python3 scripts/check_acvp_vector_divergence.py

Mirrors the hub's own scripts/ci/check-wasm-provenance.ts pattern: a no-op
(exit 0) when the sibling repo isn't present, so this never blocks CI in a
checkout that doesn't have pqctoday-hub alongside it.
"""
import json
import os
import sys

CHECK = "--check" in sys.argv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HSM_ACVP_DIR = os.path.join(ROOT, "tests", "acvp")
HUB_REPO_PATH = os.environ.get(
    "HUB_REPO_PATH", os.path.join(os.path.dirname(ROOT), "pqctoday-hub")
)
HUB_ACVP_DIR = os.path.join(HUB_REPO_PATH, "src", "data", "acvp")

# Files this repo's tests/acvp/*.json is *known* to still diverge from the
# hub's copy, with why. Each entry needs a real citation — "not gotten to
# yet" is fine as long as it says so explicitly, per this check's whole
# purpose (an unexplained divergence is exactly what went unnoticed for 15
# files before this check existed).
#
# WS-10(c) (2026-08-28) closed out the 7 entries this dict used to carry
# (aesctr/aesgcm/aeskw/ecdsa_p384/ecdsa/eddsa/rsapss): the hub backfilled
# real _provenance (published-standard tier for the first 6, self-consistency
# for rsapss — no NIST ACVP-RSA-SigVer PSS vector matches either engine's
# supported hash families) and this repo re-synced from the hub, so they're
# identical now — nothing left to exempt.
#
# The 4 LMS files (lms_keygen_test/expected.json, lms_sigver_test/
# expected.json) have no hub counterpart at all — see WS-10(d): their
# schema exactly matches NIST ACVP-Server's real LMS keyGen/sigVer v1.0
# generation modules and their vsId/isSample markers are consistent with a
# genuine ACVP pull, but AFT-type seeds are randomized per generation with
# no stable public source to byte-match, and RFC 8554's own published
# vectors are HSS-shaped (not this file's plain LMS shape) so aren't a
# substitute. Provenance is backfilled documenting exactly this; see each
# file's own _provenance.note. They stay hsm-only (not an accepted
# divergence — there's no hub file to diverge from).
ACCEPTED_DIVERGENCES = {}


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    if not os.path.isdir(HUB_ACVP_DIR):
        print(
            f"skip (no sibling pqctoday-hub checkout at {HUB_REPO_PATH}) "
            "— divergence check is a no-op outside a paired checkout."
        )
        return 0

    hsm_files = {f for f in os.listdir(HSM_ACVP_DIR) if f.endswith(".json")}
    hub_files = {f for f in os.listdir(HUB_ACVP_DIR) if f.endswith(".json")}

    common = sorted(hsm_files & hub_files)
    hsm_only = sorted(hsm_files - hub_files)
    hub_only = sorted(hub_files - hsm_files)

    unexempted_divergences = []
    accepted_divergences = []
    identical = []
    missing_provenance = []

    for name in common:
        hsm_data = load_json(os.path.join(HSM_ACVP_DIR, name))
        hub_data = load_json(os.path.join(HUB_ACVP_DIR, name))
        if hsm_data == hub_data:
            identical.append(name)
        elif name in ACCEPTED_DIVERGENCES:
            accepted_divergences.append(name)
        else:
            unexempted_divergences.append(name)
        if "_provenance" not in hsm_data:
            missing_provenance.append(name)

    for name in hsm_only:
        data = load_json(os.path.join(HSM_ACVP_DIR, name))
        if "_provenance" not in data:
            missing_provenance.append(name)

    print(f"ACVP vector divergence check: {HSM_ACVP_DIR} vs {HUB_ACVP_DIR}\n")
    print(f"  identical:              {len(identical)}")
    print(f"  accepted divergence:    {len(accepted_divergences)}")
    for n in accepted_divergences:
        print(f"    - {n}: {ACCEPTED_DIVERGENCES[n]}")
    print(f"  hsm-only (no hub file): {len(hsm_only)} — {', '.join(hsm_only) or '(none)'}")
    print(f"  hub-only (not synced):  {len(hub_only)}")
    if hub_only:
        print(f"    {', '.join(hub_only)}")
    print(f"  missing _provenance:    {len(missing_provenance)} (informational, not gated)")
    if missing_provenance:
        print(f"    {', '.join(sorted(set(missing_provenance)))}")

    if unexempted_divergences:
        print(f"\n✗ UNEXEMPTED DIVERGENCE ({len(unexempted_divergences)} file(s)):")
        for n in unexempted_divergences:
            print(
                f"    - {n}: content differs from the hub's copy with no "
                f"entry in ACCEPTED_DIVERGENCES explaining why."
            )
        print(
            "\n  Either re-sync from the hub (if the hub's copy is now "
            "authoritative) or add an entry to ACCEPTED_DIVERGENCES with a "
            "real citation for why they're expected to differ."
        )
        return 1

    print("\n✓ no unexempted divergence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
