#!/usr/bin/env python3
"""Unit tests for scripts/check_public_boundary.py.

Fixtures are assembled from fragments so this file contains no literal match.
Run: python3 -m unittest tests/test_check_public_boundary.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_public_boundary as cpb  # noqa: E402

PRIVATE_REPO = "-".join(["pqctoday", "priv"])
HOME = "/".join(["", "Users", "alice", "x"])
SCRIPT = os.path.join(ROOT, "scripts", "check_public_boundary.py")


class Fixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def put(self, rel, content):
        full = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(content if isinstance(content, bytes) else content.encode())

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, SCRIPT, *args], cwd=self.dir, capture_output=True, text=True
        )


class CountingAndKeys(unittest.TestCase):
    def test_count_text_per_rule(self):
        text = "\n".join([f"see {PRIVATE_REPO}", "clean", f"again {PRIVATE_REPO}", f"at {HOME}/f"])
        self.assertEqual(cpb.count_text(text), {"private-repo": 2, "home-path": 1})

    def test_baseline_key(self):
        self.assertEqual(cpb.baseline_key("assets/index-D3FGcMe6.js"), "assets/index-#.js")
        self.assertEqual(cpb.baseline_key("data/rows_09302026.csv"), "data/rows_#.csv")
        self.assertEqual(cpb.baseline_key("data/rows_10012026_r2.csv"), "data/rows_#.csv")
        self.assertEqual(cpb.baseline_key("docs/plan-2026-09-08.md"), "docs/plan-2026-09-08.md")
        self.assertEqual(cpb.baseline_key("scripts/check_pkcs11_constants.py"), "scripts/check_pkcs11_constants.py")


class Scanning(Fixture):
    def test_scan_tree_ignores_binary_deps_and_self(self):
        self.put("a.txt", f"x {PRIVATE_REPO}\n")
        self.put("b.txt", "clean\n")
        self.put("c.dat", b"\x00\x01" + PRIVATE_REPO.encode())
        self.put("d.wasm", PRIVATE_REPO)
        self.put("node_modules/p/i.js", PRIVATE_REPO)
        self.put(".git/config", PRIVATE_REPO)
        self.put("scripts/public_boundary_baseline.json", PRIVATE_REPO)
        counts, skipped = cpb.scan_tree(self.dir)
        self.assertEqual(counts, {"a.txt": {"private-repo": 1}})
        self.assertEqual(skipped, [])

    def test_dated_copies_are_one_family_with_the_highest_count(self):
        self.put("data/rows_09302026.csv", f"{PRIVATE_REPO}\n{PRIVATE_REPO}\n")
        self.put("data/rows_10112026.csv", f"{PRIVATE_REPO}\n" * 3)
        counts, _ = cpb.scan_tree(self.dir)
        self.assertEqual(counts, {"data/rows_#.csv": {"private-repo": 3}})


class Comparing(unittest.TestCase):
    base = {"a.txt": {"private-repo": 2}, "gone.txt": {"home-path": 1}}

    def test_regressions(self):
        now = {"a.txt": {"private-repo": 3, "home-path": 1}, "new.txt": {"run-id": 1}}
        regressions, _ = cpb.compare(now, self.base)
        self.assertEqual(
            sorted(regressions),
            [("a.txt", "home-path", 0, 1), ("a.txt", "private-repo", 2, 3), ("new.txt", "run-id", 0, 1)],
        )

    def test_improved_and_ratchet(self):
        regressions, improved = cpb.compare({"a.txt": {"private-repo": 1}}, self.base)
        self.assertEqual(regressions, [])
        self.assertEqual(sorted(i[:2] for i in improved), [("a.txt", "private-repo"), ("gone.txt", "home-path")])
        self.assertEqual(
            cpb.ratchet({"a.txt": {"private-repo": 5}, "other.txt": {"run-id": 9}}, self.base),
            {"a.txt": {"private-repo": 2}},
        )


class CommandLine(Fixture):
    def test_full_cycle(self):
        self.put("a.txt", f"x {PRIVATE_REPO}\ny {PRIVATE_REPO}\n")
        b = ["--tree", ".", "--baseline", "base.json"]
        self.assertEqual(self.run_cli(*b, "--update-baseline").returncode, 2)
        self.assertEqual(self.run_cli(*b, "--update-baseline", "--allow-increase").returncode, 0)
        with open(os.path.join(self.dir, "base.json")) as handle:
            raw = handle.read()
        self.assertEqual(json.loads(raw)["files"], {"a.txt": {"private-repo": 2}})
        self.assertNotIn(PRIVATE_REPO, raw)
        self.assertEqual(self.run_cli(*b, "--mode", "enforce").returncode, 0)

        self.put("b.txt", f"leak {HOME}/f\n")
        enforced = self.run_cli(*b, "--mode", "enforce")
        self.assertEqual(enforced.returncode, 1)
        self.assertIn("home-path @ b.txt: 0 -> 1", enforced.stdout)
        self.assertNotIn("alice", enforced.stdout + enforced.stderr)
        self.assertEqual(self.run_cli(*b).returncode, 0)  # report mode never fails
        self.assertEqual(self.run_cli(*b, "--update-baseline").returncode, 1)  # cannot raise

        os.remove(os.path.join(self.dir, "b.txt"))
        self.put("a.txt", f"x {PRIVATE_REPO}\n")
        self.assertEqual(self.run_cli(*b, "--update-baseline").returncode, 0)
        with open(os.path.join(self.dir, "base.json")) as handle:
            self.assertEqual(json.load(handle)["files"], {"a.txt": {"private-repo": 1}})

    def test_missing_baseline(self):
        self.assertEqual(self.run_cli("--tree", ".", "--baseline", "nope.json").returncode, 2)


if __name__ == "__main__":
    unittest.main()
