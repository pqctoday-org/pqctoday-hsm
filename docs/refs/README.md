# Reference documents

This repository is public and carries **no third-party documents, only what
was extracted from them** (owner rule, 2026-10-15). The two exceptions are the
canonical OASIS PKCS #11 v3.2 headers, which carry the OASIS copyright and
IPR-policy notice in their first lines and are what the constant gate is
pinned to:

| File | Document | SHA-256 |
|---|---|---|
| `pkcs11t-canonical-v3.2.h` | Canonical type header, byte-identical to <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/pkcs11-v3.2/pkcs11t.h> | `95738fdcd9b5c9c73f55f9132aefa87354556cec1c46f681b8a2000b8b5dbccb` |
| `pkcs11f-canonical-v3.2.h` | Canonical function header, byte-identical to <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/pkcs11-v3.2/pkcs11f.h> | `3a205ff9a12247108193d124571fac88e38b59f1273e462baa1b5e00cd182fa0` |

`draft-ietf-hpke-pq-05.txt` is still in this directory pending a decision.

Every other document the code and docs cite is listed below with its publisher
URL and the SHA-256 of the exact copy the code was audited against. The same
data, machine-readable, is in [`third-party-documents.json`](third-party-documents.json).

## Restoring local copies

The paths below are gitignored, so a local copy can sit where the docs cite it
without being committed. To download and verify:

```bash
python3 docs/refs/fetch_refs.py --list    # recorded documents and local status
python3 docs/refs/fetch_refs.py           # download what is missing; refuses a SHA-256 mismatch
python3 docs/refs/fetch_refs.py --check   # verify local copies only (no network)
python3 docs/refs/fetch_refs.py --v33     # also restore the PKCS #11 v3.3 TC snapshot (git)
```

No build, test or gate step needs these files or the network. They are needed
only for optional work: reading the specification text, re-running the KMIP
tag/enum extractor (`kmip/tools/extract_kmip_spec.rs`), or the full
OASIS-zip half of `kmip/conformance/verify_corpus_provenance.py` (which
otherwise reports `PARTIAL` and still checks every transcript hash).

HTML pages: `docs.oasis-open.org` rewrites e-mail links in its HTML on each
request (CDN e-mail obfuscation), so a fresh `.html` download does not
reproduce the recorded SHA-256. `fetch_refs.py` refuses such a file unless
`--allow-html-drift` is given. The PDF, DOCX and ZIP files reproduce exactly
(all re-downloaded and matched on 2026-10-15). Byte-exact copies of all of
them are kept in the maintainers' private archive.

## PKCS #11 v3.2 — read all three, not just the specification

**The specification alone is not sufficient to audit this engine, and adjudicating against it alone produces wrong answers.** Version 3.2 moved material out of the base document into two companions, both of which it lists as *normative* references — meaning their content constitutes requirements of the specification.

| Local path (gitignored) | Document (publisher link) | Date | Bytes | SHA-256 |
|---|---|---|---|---|
| `docs/refs/pkcs11-profiles-v3.2-os.pdf` | [PKCS #11 Profiles Version 3.2 — OASIS Standard](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/os/pkcs11-profiles-v3.2-os.pdf) | 2026-06-03 | 530,083 | `4f1e15e3f727c9d07ec81f8bb1f4aa2db8e03b2e16385c8217fbf525f1864375` |
| `docs/refs/pkcs11-spec-v3.2-csd01.pdf` | [PKCS #11 Specification Version 3.2 — CSD01 (superseded)](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/pkcs11-spec-v3.2-csd01.pdf) | 2025-04-16 | 5,142,051 | `f30334792922cea2d0016585144985f3a298dcadeb156fc52aee5da835ca81c6` |
| `docs/refs/pkcs11-spec-v3.2-os.pdf` | [PKCS #11 Specification Version 3.2 — OASIS Standard](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.pdf) | 2026-06-03 | 6,540,028 | `78c4f4caa2604b8f6ed18faeed825db6e2d82a35a7d515231c96625a35bdc3db` |
| `docs/refs/pkcs11-ug-v3.2-cn01.pdf` | [PKCS #11 Usage Guide Version 3.2 — Committee Note 01](https://docs.oasis-open.org/pkcs11/pkcs11-ug/v3.2/cn01/pkcs11-ug-v3.2-cn01.pdf) | 2025-04-15 | 468,117 | `e72c3bd902b34006d68aa83aed82074000d3af1a3af8fc19ab82f1d0fe66ed90` |

The CSD01 draft is kept only for historical citations: several audits cite its
section, page and table numbers. The OS was verified content-identical to it
for the engine's surface (`docs/gap-analysis-rust-pkcs11-v3.2.md`).

### Why the Profiles document matters

Section 7 of the specification contains no technical requirement. It says an implementation is a conforming Provider **only if** it meets one or more provider profiles specified in the Profiles document. Two consequences:

- **The base specification mandates no mechanism, algorithm, curve or digest** — but the profiles differ, so read the one you claim. Baseline, Extended, Authentication Token and Public Certificates Token each state "Supports the following mechanisms: a. None specified"; HKDF TLS Token names `CKM_HKDF_DATA`; and **Complete Provider §5.2 condition 6 requires "Supports all mechanisms [PKCS11_Spec] Section 6."** So "this engine lacks mechanism X" is a product decision under the profiles this engine claims, and would be a conformance defect under Complete Provider — which is exactly why neither engine claims it.
- **A token declares conformance by publishing a `CKO_PROFILE` object.** Baseline Provider condition 4 requires one carrying `CKP_BASELINE_PROVIDER`. An engine that publishes none has not established conformance to anything.

### Why the Usage Guide matters

v3.2 moved the session-state model, the user/login model and the object-access matrix out of the specification body. The spec now says only that `CK_STATE` holds the session state *"as described in [PKCS11-UG]"*. Auditing session behaviour, login semantics or private-object access against the specification alone finds no governing text — and wrongly concludes the spec is silent on rules that are in fact binding.

Note the process asymmetry: the Usage Guide is a non-standards-track Committee Note that the Standard nevertheless cites normatively. That is easy to misread as "informative, therefore optional". It is not.

## PKCS #11 v3.3 — unpublished working draft, pinned by commit

There is **no published v3.3** on `docs.oasis-open.org` (checked 2026-08-28),
but the OASIS PKCS 11 TC's public git repository already carries v3.3 as its
working title (`working/doc/spec/Abstract.md`: `title: 'PKCS #11 Specification
Version 3.3'`; the `v3.3` URLs it names were placeholders that returned 404).
Until 2026-10-15 a snapshot of that working tree was vendored here as
`pkcs11-v3.3-draft-git-snapshot-20260828/`. It is now cited by commit instead:

- Repository: <https://github.com/oasis-tcs/pkcs11> (public TC repository; public
  feedback accepted under the OASIS Feedback License)
- Branch at snapshot time: `master`
- Commit: [`2b25dd8ed4a85d22937d8509bb296555cd329f43`](https://github.com/oasis-tcs/pkcs11/tree/2b25dd8ed4a85d22937d8509bb296555cd329f43) (2026-08-26T21:46:09+01:00)
- Snapshot taken: 2026-08-28
- Content: the removed snapshot was that commit's tree byte for byte
  (334 files, re-verified against a fresh fetch on 2026-10-15), minus
  the four `working/doc/*/Makefile` files.

A citation of the form `working/headers/pkcs11t.h:658 (commit 2b25dd8)` means
<https://github.com/oasis-tcs/pkcs11/blob/2b25dd8ed4a85d22937d8509bb296555cd329f43/working/headers/pkcs11t.h#L658>.
That is how `V33_CORRECTIONS` in `scripts/check_pkcs11_constants.py` cites
v3.3. To get a local tree: `python3 docs/refs/fetch_refs.py --v33`, or
`git clone https://github.com/oasis-tcs/pkcs11.git && git -C pkcs11 checkout 2b25dd8`.

This is not a stage document and has no publisher SHA-256 to check: it is a
live branch, and every fact in it may change before ratification. Its markdown
carries no section numbers, so cite v3.2 section and table numbers and use
v3.3 for prose only (see the root `CLAUDE.md`).

Notable post-3.2 commits on `master` up to the pin:

| Date | Commit | Change |
|---|---|---|
| 2026-04-08 | `b18801f` | Composite Signature support (#94) |
| 2026-05-06 | `9ceadc3` | Composite KEM support (#95): `CKM_COMP_KEM`, `working/doc/spec/comp_kem.md` |
| 2026-06-17 | `2824518` | Add output convention to `C_EncapsulateKey` (#108) |
| 2026-07-01 | `4197b43` | Update parameter names in DH spec (#110) |
| 2026-07-01 | `1c31190` | Convert Historical Mechanisms, Profiles and Usage Guide to markdown in-repo (#101) |
| 2026-07-29 | `25a1ece` | Attribute `KEYS_REMAINING` missing for XMSS keys (#115) |
| 2026-08-26 | `24f8e1a` | Document 32-bit limit for `CK_ULONG` values (#122) |
| 2026-08-26 | `2b25dd8` | Make explicit that big integers are nonempty (#116/#124) |

On mechanism enable/disable policy: the 2026-08-28 search of this tree found
nothing new in kind since v3.2: no "quantum-safe only" profile, no attribute
beside `CKA_ALLOWED_MECHANISMS`, no `C_DisableMechanism`-style function.
Deprecation stays textual. See [`../PKCS11_PROFILE_TRACEABILITY.md`](../PKCS11_PROFILE_TRACEABILITY.md).

## HPKE — RFC 9180

| Local path (gitignored) | Document (publisher link) | Date | Bytes | SHA-256 |
|---|---|---|---|---|
| `docs/refs/rfc9180-hpke.txt` | [RFC 9180, Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.txt) | 2022-02 | 192,749 | `f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6` |

`draft-ietf-hpke-pq-05.txt` (Internet-Draft, revision 05, 2026-07-06,
SHA-256 `c3afa398…1ac9c5d`, from <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.txt>)
is still committed here. It expires 2027-01-07 and is work in progress, so
re-check the datatracker before citing it as current.

## FrodoKEM and Classic McEliece

| Local path (gitignored) | Document (publisher link) | Date | Bytes | SHA-256 |
|---|---|---|---|---|
| `docs/refs/frodokem-standard-proposal-20250929.pdf` | [FrodoKEM standard proposal (ISO submission)](https://frodokem.org/files/FrodoKEM_standard_proposal_20250929.pdf) | 2025-09-29 | 641,404 | `8c15a94921be3e955ac89bf8ffa54df3f07ebf1b5230b370beff7e7268a5bf48` |
| `docs/refs/mceliece-spec-20221023.pdf` | [Classic McEliece: conservative code-based cryptography — cryptosystem specification](https://classic.mceliece.org/mceliece-spec-20221023.pdf) | 2022-10-23 | 249,199 | `dcc6878852ef8a00a7bedd859da661770cf85d2c3d9239e06d25e4a0d365fd12` |

## KMIP (OASIS)

See [`../../kmip/spec/README.md`](../../kmip/spec/README.md) for what each
document is used for. The extractions (`kmip-spec-3.0-tags-enums*.json`,
`kmip-spec-3.0-section61-headings.json`, `crossref/`) and the `.sha256`
sidecars stay committed under `kmip/spec/`.

| Local path (gitignored) | Document (publisher link) | Date | Bytes | SHA-256 |
|---|---|---|---|---|
| `kmip/spec/oasis-kmip-2.1/kmip-spec-v2.1-os.pdf` | [KMIP Specification Version 2.1 — OASIS Standard](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.pdf) | 2020-12-14 | 6,796,775 | `ca05f7baaf2a630fc047312aaa760030b91c3d36d214c1a85bbed8bcee0287b0` |
| `kmip/spec/oasis-kmip-3.0/kmip-profiles-v3.0-csd02.docx` | [KMIP Profiles Version 3.0 — CSD02 (current baseline)](https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.docx) | 2026-05-21 | 201,667 | `5383a3abfd42637a74caf0392dfeb4b78eba58552e977d5a82d4dd809e4d93f9` |
| `kmip/spec/oasis-kmip-3.0/kmip-profiles-v3.0-csd02.html` | [KMIP Profiles Version 3.0 — CSD02 (current baseline)](https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.html) | 2026-05-21 | 3,061,928 | `9ad7174f9c1113561f51cdec90163966aae3ce0335419e5db4e361b43eb7a15c` |
| `kmip/spec/oasis-kmip-3.0/kmip-profiles-v3.0-csd02.pdf` | [KMIP Profiles Version 3.0 — CSD02 (current baseline)](https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.pdf) | 2026-05-21 | 1,278,197 | `c1d9b92edae06b7bca888f3a45cdb21dee8b1c790922a9b3df0cbca12db7ade4` |
| `kmip/spec/oasis-kmip-3.0/kmip-profiles-v3.0-csd02.zip` | [KMIP Profiles Version 3.0 — CSD02 (current baseline)](https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.zip) | 2026-05-21 | 1,429,398 | `b60453bfb4c8c04703edd33ce9213801f9f204ef1a18a854aa288cad50f0b9fa` |
| `kmip/spec/oasis-kmip-3.0/kmip-profiles-v3.0.pdf` | [KMIP Profiles Version 3.0 — CSD01 (superseded)](https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd01/kmip-profiles-v3.0-csd01.pdf) | 2023-11-30 | 1,142,181 | `d2358da9fe9007ba3422d29f7df8c0fcfd4d137ab220011a4da31a1bb940136f` |
| `kmip/spec/oasis-kmip-3.0/kmip-profiles-v3.0.zip` | [KMIP Profiles Version 3.0 — CSD01 (superseded)](https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd01/kmip-profiles-v3.0-csd01.zip) | 2023-11-30 | 8,389,246 | `f3dfddba5b6a0e21cbb2dcc23c160705c523fcc9687bf15a29e62a1d0c2adb4a` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0-csd02.docx` | [KMIP Specification Version 3.0 — CSD02 (current baseline)](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.docx) | 2026-05-07 | 559,666 | `1936987c3a1a4502a3bcea7b17c4a4954e817e0f5e5c21ef0c1952f30b0f05e7` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0-csd02.html` | [KMIP Specification Version 3.0 — CSD02 (current baseline)](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.html) | 2026-05-07 | 19,266,598 | `c6277cc83a2505bdac75ab154355211085feeadad07c7de9ae20a19d6d4c7b74` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0-csd02.pdf` | [KMIP Specification Version 3.0 — CSD02 (current baseline)](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.pdf) | 2026-05-07 | 2,962,732 | `9043830d9ea39e6cb963faf9cdd0c74c6fb4b2ea29131e8c5b65f63a3ed271cb` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0-csd02.zip` | [KMIP Specification Version 3.0 — CSD02 (current baseline)](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.zip) | 2026-05-07 | 3,396,388 | `40bbded48585bf8040e4f171355d9616061232b7f41b969c5abd095a8f8fba6a` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0-wd19-clean.pdf` | [KMIP Specification Version 3.0 — Working Draft 19 (PQC Updates; superseded by CSD02)](https://groups.oasis-open.org/higherlogic/ws/public/download/72645/kmip-spec-v3.0-wd19-clean.pdf) | 2025-02-14 | 3,142,670 | `e2dc1991e0a5697637aab00cb31b4bbebc51a664f2c1f27f8225713a42ba4f4d` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0.docx` | [KMIP Specification Version 3.0 — CSD01 (superseded)](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd01/kmip-spec-v3.0-csd01.docx) | 2024-08-23 | 603,495 | `3a1413f03dd4444b356d225f6ed170f1d3354961c13cea61e1772739ba5a7a2e` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0.html` | [KMIP Specification Version 3.0 — CSD01 (superseded)](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd01/kmip-spec-v3.0-csd01.html) | 2024-08-23 | 19,055,347 | `4197ff9090e5dcc684854a0ffdd03e8c7af36a267b13a4554b524655aa06bb40` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0.pdf` | [KMIP Specification Version 3.0 — CSD01 (superseded)](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd01/kmip-spec-v3.0-csd01.pdf) | 2024-08-23 | 3,141,715 | `e95f0ed9a4becbcafea5f763ca66f6e3983dd241149aa1f80dc3d39d7120bea0` |
| `kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0.zip` | [KMIP Specification Version 3.0 — CSD01 (superseded)](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd01/kmip-spec-v3.0-csd01.zip) | 2024-08-23 | 3,496,808 | `528f1ea7a7f57aed1c83fdbfe9fcc15d3da519a97d9ddd8eb1200cbec8af25c2` |
| `kmip/spec/oasis-kmip-3.0/kmip-ug-v3.0/kmip-ug-v3.0.docx` | [KMIP Usage Guide Version 3.0 — Committee Note Draft 01](https://docs.oasis-open.org/kmip/kmip-ug/v3.0/cnd01/kmip-ug-v3.0-cnd01.docx) | 2026-06-18 | 608,090 | `c60c8b84c5a590c03f56b6709776ac50cddb0f16805527466041dcea1159b38a` |
| `kmip/spec/oasis-kmip-3.0/kmip-ug-v3.0/kmip-ug-v3.0.html` | [KMIP Usage Guide Version 3.0 — Committee Note Draft 01](https://docs.oasis-open.org/kmip/kmip-ug/v3.0/cnd01/kmip-ug-v3.0-cnd01.html) | 2026-06-18 | 544,012 | `3a9e211d4a1b804aeffa31057868772508e95461f676f80b81267341579ffeb2` |
| `kmip/spec/oasis-kmip-3.0/kmip-ug-v3.0/kmip-ug-v3.0.pdf` | [KMIP Usage Guide Version 3.0 — Committee Note Draft 01](https://docs.oasis-open.org/kmip/kmip-ug/v3.0/cnd01/kmip-ug-v3.0-cnd01.pdf) | 2026-06-18 | 1,097,859 | `7d3b3ecb720f372a3bf2b199b83d59b3ae2399425146dcdffe2f5008e041a1fa` |

## Refreshing

PKCS #11 moves faster than it looks: CSD01 to ratified Standard took roughly
seven months. Before citing any status, re-check the publisher:

- <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/>
- <https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/os/>
- <https://docs.oasis-open.org/pkcs11/pkcs11-ug/v3.2/>
- <https://docs.oasis-open.org/kmip/kmip-spec/v3.0/>

The OASIS member-only workspace is login-walled, so unpublished committee
drafts are not visible from here; "no newer version found" means none on the
public site. When a new revision is adopted, add it to
`third-party-documents.json` (path, URL, bytes, SHA-256) rather than
committing the document.

## License (attribution)

OASIS documents are © OASIS Open and distributed under the OASIS IPR Policy
(<https://www.oasis-open.org/policies-guidelines/ipr/>). RFC 9180 is © IETF
Trust. FrodoKEM and Classic McEliece specifications are © their authors.
