# Copyright and licence

Copyright PQC Today, LLC, for the code written for this project.

That code is licensed under the GNU Affero General Public License, version 3
only (AGPL-3.0-only); see [LICENSE](LICENSE). If you run a changed version of
this software for other people over a network (for example the KMIP server or
the remoting services), the AGPL requires you to offer them its source code.

Versions published before 16 October 2026 were released under the licences
named in them at the time (BSD-2-Clause for the fork, MIT for the KMIP,
remoting and MLS crates, GPL-3.0-only for the TLS crate and the OpenSSL Studio
shims), and stay under those licences for whoever has them.

## Which files are under which licence

A file's own `SPDX-License-Identifier` or copyright notice decides. Files
without one are AGPL-3.0-only, except in the folders listed below.

**SoftHSM2 (BSD-2-Clause).** This repository is a fork of SoftHSM2 2.7.0. The
files that come from SoftHSM2 carry the SoftHSM2 copyright notice (.SE, SURFnet
or NLnet Labs) and stay under the BSD 2-Clause licence, also where PQC Today,
LLC changed them; the text is in [LICENSES/BSD-2-Clause.txt](LICENSES/BSD-2-Clause.txt).

**Third-party code, each under its own licence and notices** (not covered by
the AGPL grant or by any commercial licence from PQC Today, LLC):

- `rust/vendor/`: vendored crates (AWS-LC and others);
- `rust/*-patched/` and `rust/classic-mceliece-multi/`: changed copies of
  third-party crates, each with its licence files and change record;
- `src/vendor/`: pkcs11-provider (Apache-2.0) and the latchset files;
- `openpgp/`: openpgp-pkcs11 (LGPL-2.0-or-later);
- `openssh-pkcs11/`: OpenSSH-derived code (OpenSSH licence);
- `strongswan-pkcs11/` and the `strongswan*.patch` files: strongSwan
  (GPL-2.0-or-later);
- the other `*.patch` files: changes to third-party projects, under those
  projects' licences;
- `src/lib/pkcs11/pkcs11*.h` and `kmip/conformance/oasis_corpus/`: OASIS
  headers and test cases (OASIS notice);
- single files inside the tree: `src/bin/keyconv/base64.c` (ISC),
  `src/bin/win32/getopt.*` (NetBSD), `src/lib/test/AsymWrapUnwrapTests.*` and
  `src/lib/test/ForkTests.*` (Red Hat, BSD-2-Clause), `tests/json.hpp` (MIT),
  `cmake/modules/FindCppUnit.cmake` (BSL-1.0), `cmake/modules/FindSQLite3.cmake`;
- `engines/notices/texts/`: licence texts of the components built into the
  engine releases;
- test vectors from NIST ACVP and other standards bodies, under their
  publishers' terms (named in their folders).

The engine releases list everything compiled into each bundle, with full
licence texts, in `public/licenses/engines/<bundle>/` inside each tarball.

## Commercial licence

The AGPL lets anyone use, change, host and sell this software, as long as they
follow its terms, including sharing their changes with the people who use it.
If those terms do not fit your use, PQC Today, LLC can offer a commercial
licence for the parts it owns. Write to pqctoday@proton.me with
"Commercial licence" in the subject.

A commercial licence can only cover code PQC Today, LLC owns. It never covers
the SoftHSM2 files (they stay BSD-2-Clause, which already allows commercial
use) or the third-party parts listed above, and in particular not strongSwan
(GPL-2.0-or-later), openpgp-pkcs11 (LGPL-2.0-or-later) or TFHE-rs (its licence
and Zama's patents). No patent licence is given for third-party technology.
