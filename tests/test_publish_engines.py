#!/usr/bin/env python3
"""Unit tests for scripts/publish_engines.py.  Run: python3 -m unittest tests/test_publish_engines.py"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import publish_engines as pe  # noqa: E402

BUNDLES = pe.load_bundles()


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = pe.main(list(argv))
        except SystemExit as exc:  # argparse errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="engines-test-")
        self.src = os.path.join(self.tmp, "consumer")
        for b in BUNDLES:
            for entry in b["files"]:
                if entry.endswith("/"):
                    for n in ("a.js", "b.d.ts"):
                        self.put(entry + n, f"{b['name']}:{entry}{n}")
                else:
                    self.put(entry, f"{b['name']}:{entry}")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, rel, text):
        full = os.path.join(self.src, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as handle:
            handle.write(text)

    def package(self, out, *extra, tag="engines-1"):
        return run("package", "--from", self.src, "--out", out, "--tag", tag, "--commit-head", *extra)


class Declaration(unittest.TestCase):
    def test_declaration_is_sane(self):
        names = [b["name"] for b in BUNDLES]
        self.assertEqual(len(names), len(set(names)))
        for b in BUNDLES:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, b["buildScript"])), b["name"])
            self.assertTrue(b["files"])
        text = open(pe.BUNDLES_FILE).read().lower()
        for forbidden in ("-".join(["pqctoday", "priv"]), "/".join(["", "users", ""]), "-".join(["local", "evidence", "cache"])):
            self.assertNotIn(forbidden, text)


class Packaging(Base):
    def test_package_writes_release_files_and_uploads_nothing(self):
        out = os.path.join(self.tmp, "out")
        code, stdout, _ = self.package(out)
        self.assertEqual(code, 0)
        self.assertIn("Nothing was uploaded", stdout)
        manifest = json.load(open(os.path.join(out, "engines-manifest.json")))
        self.assertEqual(manifest["tag"], "engines-1")
        self.assertEqual(sorted(manifest["bundles"]), sorted(b["name"] for b in BUNDLES))
        sums = open(os.path.join(out, "SHA256SUMS")).read().splitlines()
        self.assertEqual(len(sums), len(BUNDLES) + 1)
        for b in manifest["bundles"].values():
            self.assertTrue(os.path.isfile(os.path.join(out, b["tarball"])))
            self.assertEqual(len(b["hsmCommit"]), 40)

    def test_output_is_byte_for_byte_reproducible(self):
        a, b = os.path.join(self.tmp, "a"), os.path.join(self.tmp, "b")
        self.assertEqual(self.package(a)[0], 0)
        self.assertEqual(self.package(b)[0], 0)
        for name in sorted(os.listdir(a)):
            self.assertEqual(open(os.path.join(a, name), "rb").read(), open(os.path.join(b, name), "rb").read(), name)

    def test_only_limits_the_bundles(self):
        out = os.path.join(self.tmp, "out")
        first = BUNDLES[0]["name"]
        self.assertEqual(self.package(out, "--only", first)[0], 0)
        self.assertEqual(list(json.load(open(os.path.join(out, "engines-manifest.json")))["bundles"]), [first])

    def test_refuses_bad_input(self):
        out = os.path.join(self.tmp, "out")
        self.assertEqual(self.package(out, tag="v1")[0], 2)  # tag shape
        self.assertEqual(run("package", "--from", self.src, "--out", out, "--tag", "engines-1")[0], 2)  # no commit
        bad = f"{BUNDLES[0]['name']}={'0' * 40}"
        self.assertEqual(run("package", "--from", self.src, "--out", out, "--tag", "engines-1", "--commit-head", "--commit", bad)[0], 2)
        os.remove(os.path.join(self.src, "public/wasm/strongswan.wasm"))  # declared file gone
        self.assertEqual(self.package(out)[0], 2)


class Verifying(Base):
    def setUp(self):
        super().setUp()
        self.out = os.path.join(self.tmp, "out")
        self.assertEqual(self.package(self.out)[0], 0)
        self.manifest = os.path.join(self.out, "engines-manifest.json")

    def test_untouched_release_and_tree_pass(self):
        self.assertEqual(run("verify", "--manifest", self.manifest, "--tarballs", self.out, "--tree", self.src)[0], 0)

    def test_a_changed_engine_file_is_named(self):
        victim = "public/wasm/strongswan.wasm"
        with open(os.path.join(self.src, victim), "ab") as handle:
            handle.write(b"x")
        code, stdout, _ = run("verify", "--manifest", self.manifest, "--tree", self.src)
        self.assertEqual(code, 1)
        self.assertIn(f"strongswan: {victim} changed", stdout)

    def test_a_missing_file_and_a_damaged_tarball_fail(self):
        os.remove(os.path.join(self.src, "public/wasm/strongswan.wasm"))
        self.assertEqual(run("verify", "--manifest", self.manifest, "--tree", self.src)[0], 1)
        manifest = json.load(open(self.manifest))
        tar_path = os.path.join(self.out, manifest["bundles"]["strongswan"]["tarball"])
        with open(tar_path, "ab") as handle:
            handle.write(b"junk")
        code, stdout, _ = run("verify", "--manifest", self.manifest, "--tarballs", self.out)
        self.assertEqual(code, 1)
        self.assertIn("strongswan: tarball", stdout)


if __name__ == "__main__":
    unittest.main()
