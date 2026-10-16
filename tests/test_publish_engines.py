#!/usr/bin/env python3
"""Unit tests for scripts/publish_engines.py.  Run: python3 -m unittest tests/test_publish_engines.py"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import engine_notices as en  # noqa: E402
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
            for entry in b["files"]:
                self.assertFalse(entry.endswith("/"), f"{b['name']}: folder entry {entry}")
        text = open(pe.BUNDLES_FILE).read().lower()
        for forbidden in ("-".join(["pqctoday", "priv"]), "/".join(["", "users", ""]), "-".join(["local", "evidence", "cache"])):
            self.assertNotIn(forbidden, text)


class FolderEntries(unittest.TestCase):
    def test_a_folder_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bundles.json")
            with open(path, "w") as handle:
                json.dump({"schema": 1, "bundles": [{"name": "x", "files": ["src/wasm/kmip/"]}]}, handle)
            with self.assertRaises(pe.ToolError):
                pe.load_bundles(path)


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

    def install(self):
        """Unpack every tarball into the consumer tree, as the consumer does."""
        manifest = json.load(open(self.manifest))
        for b in manifest["bundles"].values():
            with tarfile.open(os.path.join(self.out, b["tarball"]), "r:gz") as tar:
                tar.extractall(self.src, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))

    def test_untouched_release_and_tree_pass(self):
        self.install()
        self.assertEqual(run("verify", "--manifest", self.manifest, "--tarballs", self.out, "--tree", self.src)[0], 0)

    def test_a_tree_without_the_notices_fails(self):
        code, stdout, _ = run("verify", "--manifest", self.manifest, "--tree", self.src)
        self.assertEqual(code, 1)
        self.assertIn("public/licenses/engines/strongswan/THIRD-PARTY-NOTICES.txt missing", stdout)

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


class Notices(Base):
    """Every tarball carries the licence texts its contents require."""

    def setUp(self):
        super().setUp()
        self.out = os.path.join(self.tmp, "out")
        self.assertEqual(self.package(self.out)[0], 0)
        self.manifest = json.load(open(os.path.join(self.out, "engines-manifest.json")))

    def members(self, bundle):
        b = self.manifest["bundles"][bundle]
        with tarfile.open(os.path.join(self.out, b["tarball"]), "r:gz") as tar:
            return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}

    def notices_text(self, bundle):
        return self.members(bundle)[f"public/licenses/engines/{bundle}/THIRD-PARTY-NOTICES.txt"].decode()

    def test_every_tarball_has_notices_listed_in_the_manifest(self):
        for name, b in self.manifest["bundles"].items():
            members = self.members(name)
            self.assertIn(b["thirdPartyNotices"], members, name)
            self.assertTrue(any("/LICENSES/" in rel for rel in b["notices"]), name)
            for rel in b["notices"]:
                self.assertIn(rel, members, f"{name}: {rel}")
            self.assertIn(b["hsmCommit"], self.notices_text(name))

    def test_cpp_engine_carries_openssl_softhsm2_and_runtime_texts(self):
        text = self.notices_text("softhsm-cpp-engine")
        for needle in ("openssl-3.6.3.tar.gz", "Apache-2.0", "SURFnet bv", "Cisco Systems", "CC0-1.0", "Emscripten"):
            self.assertIn(needle, text)
        members = self.members("softhsm-cpp-engine")
        apache = members["public/licenses/engines/softhsm-cpp-engine/LICENSES/openssl/LICENSE.txt"].decode()
        self.assertIn("Apache License", apache)
        self.assertIn("Version 2.0", apache)

    def test_strongswan_carries_gpl_text_and_source_pointer(self):
        text = self.notices_text("strongswan")
        commit = self.manifest["bundles"]["strongswan"]["hsmCommit"]
        self.assertIn("GPL-2.0-or-later", text)
        self.assertIn("strongswan-6.0.5.tar.bz2", text)
        self.assertIn(f"/tree/{commit}", text)
        gpl = self.members("strongswan")["public/licenses/engines/strongswan/LICENSES/strongswan/COPYING"].decode()
        self.assertIn("GNU GENERAL PUBLIC LICENSE", gpl)
        self.assertIn("Version 2, June 1991", gpl)

    def test_rust_bundles_list_their_crates_and_mark_patched_ones(self):
        for name in ("softhsmrustv3-engine", "cacp-kmip"):
            text = self.notices_text(name)
            self.assertIn("Rust crates (", text)
            self.assertIn("fips204", text)
            self.assertIn("rust/fips204-patched/PATCHES.md", text)
            self.assertIn("wasm-bindgen", text)

    def test_openssl_studio_carries_gpl3_shims_patched_openssl_and_emscripten_crates(self):
        text = self.notices_text("openssl-pkcs11")
        commit = self.manifest["bundles"]["openssl-pkcs11"]["hsmCommit"]
        for needle in ("GPL-3.0-only", "Copyright (c) 2026 PQC Today, LLC", f"/tree/{commit}",
                       "openssl-3.6.3.tar.gz", "0001-apps_startup-register-pkcs11-provider.patch",
                       "pkcs11-provider", "src/vendor/pkcs11-provider/PATCHES.md", "OASIS", "Emscripten",
                       "target wasm32-unknown-emscripten", "rust/fips204-patched/PATCHES.md"):
            self.assertIn(needle, text)
        gpl = self.members("openssl-pkcs11")["public/licenses/engines/openssl-pkcs11/LICENSES/openssl-studio-shims/GPL-3.0-only.txt"].decode()
        self.assertIn("Version 3, 29 June 2007", gpl)

    def test_crate_target_is_per_bundle(self):
        by_name = {b["name"]: b for b in BUNDLES}
        self.assertEqual(en.bundle_target(by_name["softhsmrustv3-engine"]), "wasm32-unknown-unknown")
        self.assertEqual(en.bundle_target(by_name["openssl-pkcs11"]), "wasm32-unknown-emscripten")
        wrong = dict(by_name["openssl-pkcs11"], cargoTarget="wasm32-unknown-unknown")
        self.assertTrue(any("generated for" in p for p in en.check_bundle(wrong, en.load_components())))

    def test_incomplete_notices_refuse_to_package(self):
        bundle = {"name": "x", "files": ["a"], "notices": ["no-such-component"]}
        self.assertTrue(en.check_bundle(bundle, en.load_components()))
        self.assertTrue(en.check_bundle({"name": "y", "files": ["a"]}, en.load_components()))
        with self.assertRaises(en.NoticeError):
            en.render_bundle(bundle, "0" * 40)


class NoticeSources(unittest.TestCase):
    def test_committed_notice_sources_are_complete_and_current(self):
        # Fails when a crate list is stale against its Cargo.lock: regenerate with
        # `python3 scripts/engine_notices.py crates` in the Rust container.
        self.assertEqual(en.check_all(), [])


if __name__ == "__main__":
    unittest.main()
