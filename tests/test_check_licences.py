# SPDX-License-Identifier: AGPL-3.0-only
"""scripts/check_licences.py: own files say AGPL-3.0-only, third-party files are left alone."""
import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "check_licences", Path(__file__).resolve().parent.parent / "scripts" / "check_licences.py")
cl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cl)


def reader(files):
    return lambda p: files.get(p)


class Scan(unittest.TestCase):
    def test_own_agpl_file_passes_and_other_labels_fail(self):
        files = {
            "rust/src/a.rs": "// SPDX-License-Identifier: AGPL-3.0-only\n",
            "rust/src/b.rs": "// SPDX-License-Identifier: MIT\n",
            "kmip/src/c.rs": "// SPDX-License-Identifier: GPL-3.0-only\n",
        }
        problems, headerless = cl.scan(list(files), reader(files))
        self.assertEqual(sorted(p for _, p in problems), ["kmip/src/c.rs", "rust/src/b.rs"])
        self.assertEqual(headerless, [])

    def test_third_party_paths_and_foreign_copyright_are_skipped(self):
        files = {
            "rust/vendor/x/lib.rs": "// SPDX-License-Identifier: MIT\n",
            "src/lib/SoftHSM.cpp": "/*\n * Copyright (c) 2010 SURFnet bv\n */\n",
            "src/lib/pkcs11/pkcs11t.h": "/* Copyright (c) OASIS Open 2016 */\n",
            "openpgp/src/x.rs": "",
        }
        self.assertEqual(cl.scan(list(files), reader(files)), ([], []))

    def test_own_file_without_header_is_reported_as_headerless(self):
        files = {"rust/src/new.rs": "fn main() {}\n", "docs/notes.md": "no header needed\n"}
        self.assertEqual(cl.scan(list(files), reader(files)), ([], ["rust/src/new.rs"]))

    def test_own_copyright_line_does_not_make_a_file_third_party(self):
        files = {"scripts/p.c": "/* Copyright (C) 2026 PQC Today, LLC\n   SPDX-License-Identifier: Apache-2.0 */\n"}
        problems, _ = cl.scan(list(files), reader(files))
        self.assertEqual([p for _, p in problems], ["scripts/p.c"])


class Manifests(unittest.TestCase):
    def test_every_own_manifest_and_package_json_must_say_agpl(self):
        files = {p: 'license = "AGPL-3.0-only"\n' for p in cl.OWN_MANIFESTS}
        files["package.json"] = '  "license": "AGPL-3.0-only AND BSD-2-Clause",\n'
        self.assertEqual(cl.manifest_problems(reader(files)), [])
        files["kmip/Cargo.toml"] = 'license     = "MIT"\n'
        self.assertEqual([p for _, p in cl.manifest_problems(reader(files))], ["kmip/Cargo.toml"])


if __name__ == "__main__":
    unittest.main()
