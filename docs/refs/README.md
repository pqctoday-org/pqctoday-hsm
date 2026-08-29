# Vendored reference documents

Authoritative copies of the standards this engine is audited against. Each was fetched from the publisher and its SHA-256 recorded here, so a future auditor can prove the local copy is the real document rather than a bot-block page or a stale draft.

## PKCS#11 v3.2 — read all three, not just the specification

**The specification alone is not sufficient to audit this engine, and adjudicating against it alone produces wrong answers.** Version 3.2 moved material out of the base document into two companions, both of which it lists as *normative* references — meaning their content constitutes requirements of the specification.

| File | Document | Stage | Date | SHA-256 |
|---|---|---|---|---|
| `pkcs11-spec-v3.2-os.pdf` | PKCS #11 Specification v3.2 | OASIS Standard | 2026-06-03 | `78c4f4ca…dc3db` |
| `pkcs11-profiles-v3.2-os.pdf` | PKCS #11 Profiles v3.2 | OASIS Standard | 2026-06-03 | `4f1e15e3…64375` |
| `pkcs11-ug-v3.2-cn01.pdf` | PKCS #11 Usage Guide v3.2 | Committee Note 01 | 2025-04-15 | `e72c3bd9…6ed90` |
| `pkcs11-spec-v3.2-csd01.pdf` | Specification v3.2 (superseded draft) | CSD01 | 2025-11-05 | historical only |
| `pkcs11t-canonical-v3.2.h` | Canonical type header | — | — | byte-identical to the OASIS OS include |
| `pkcs11f-canonical-v3.2.h` | Canonical function header | — | — | byte-identical to the OASIS OS include |

### Why the Profiles document matters

Section 7 of the specification contains no technical requirement. It says an implementation is a conforming Provider **only if** it meets one or more provider profiles specified in the Profiles document. Two consequences:

- **The base specification mandates no mechanism, algorithm, curve or digest** — but the profiles differ, so read the one you claim. Baseline, Extended, Authentication Token and Public Certificates Token each state "Supports the following mechanisms: a. None specified"; HKDF TLS Token names `CKM_HKDF_DATA`; and **Complete Provider §5.2 condition 6 requires "Supports all mechanisms [PKCS11_Spec] Section 6."** So "this engine lacks mechanism X" is a product decision under the profiles this engine claims, and would be a conformance defect under Complete Provider — which is exactly why neither engine claims it.
- **A token declares conformance by publishing a `CKO_PROFILE` object.** Baseline Provider condition 4 requires one carrying `CKP_BASELINE_PROVIDER`. An engine that publishes none has not established conformance to anything.

### Why the Usage Guide matters

v3.2 moved the session-state model, the user/login model and the object-access matrix out of the specification body. The spec now says only that `CK_STATE` holds the session state *"as described in [PKCS11-UG]"*. Auditing session behaviour, login semantics or private-object access against the specification alone finds no governing text — and wrongly concludes the spec is silent on rules that are in fact binding.

Note the process asymmetry: the Usage Guide is a non-standards-track Committee Note that the Standard nevertheless cites normatively. That is easy to misread as "informative, therefore optional". It is not.

## PKCS#11 v3.3 — unpublished, working-draft only

There is **no published v3.3** on `docs.oasis-open.org` as of 2026-08-28 —
but the OASIS PKCS 11 TC's public git repository (`github.com/oasis-tcs/pkcs11`,
`master` branch) already carries v3.3 as its working title
(`working/doc/spec/Abstract.md`). A snapshot of that working tree, pinned to
commit `2b25dd8` (2026-08-26), is vendored at
[`pkcs11-v3.3-draft-git-snapshot-20260828/`](pkcs11-v3.3-draft-git-snapshot-20260828/) —
see that directory's `PROVENANCE.md` before citing anything from it as fact.
Unlike the v3.2 table above, this is not a stage document with a SHA-256 to
verify against a publisher artifact; it is a live, mutable git branch, and
every fact in it is subject to change before ratification.

## Refreshing these

PKCS#11 moves faster than it looks — CSD01 to ratified Standard took roughly seven months. Before citing any status, re-check the publisher rather than trusting this table:

- `https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/`
- `https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/os/`
- `https://docs.oasis-open.org/pkcs11/pkcs11-ug/v3.2/`

The OASIS member-only workspace is login-walled, so unpublished committee drafts are not visible from here; "no newer version found" means none on the public site.
