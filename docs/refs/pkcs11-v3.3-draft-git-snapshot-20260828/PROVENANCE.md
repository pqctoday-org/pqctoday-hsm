# PKCS #11 v3.3 — working draft snapshot (2026-08-28)

**This is not a published OASIS stage document.** As of this date, no v3.3
CSD/CS/OS exists on `docs.oasis-open.org` (confirmed by the 2026-08-13
compliance audit's public-surface check, and re-confirmed here). What this
directory holds is a snapshot of the OASIS PKCS 11 TC's **live git working
tree** — the TC's actual source-of-truth repository for in-progress spec
text — which already targets v3.3 by name.

- Source: <https://github.com/oasis-tcs/pkcs11> (public TC repository; TC
  members contribute substantively, public feedback accepted under the
  OASIS Feedback License — see `CONTRIBUTING.md` in this snapshot)
- Branch: `master`
- Commit at snapshot time: `2b25dd8ed4a85d22937d8509bb296555cd329f43`
  (2026-08-26 21:46:09 +0100)
- Cloned/snapshotted: 2026-08-28
- `.git` history was **not** kept in this snapshot (working tree only); the
  commit SHA above is the pin for reproducing it via
  `git clone https://github.com/oasis-tcs/pkcs11.git && git checkout 2b25dd8`.

## Evidence this is genuinely v3.3, not just post-3.2 patches to 3.2

`working/doc/spec/Abstract.md` (front matter) reads:

```
title: 'PKCS #11 Specification Version 3.3'
...
<https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.3/pkcs11-spec-v3.3.pdf> (Authoritative)
<https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.3/pkcs11-spec-v3.3.html>
```

Those `v3.3` URLs 404 today — they are placeholders for a future publish,
not live documents. Treat every fact pulled from this snapshot as **subject
to change before ratification**, the same caveat that applied to the CSD01
draft that preceded the ratified v3.2 OS.

## Structure

- `working/doc/spec/` — base Specification working markdown (this is where
  the `v3.3` title lives)
- `working/doc/hist/` — Historical Mechanisms
- `working/doc/profiles/` — Profiles (+ `test-cases/`)
- `working/doc/ug/` — Usage Guide
- `working/headers/` — in-progress `pkcs11.h`/`pkcs11f.h`/`pkcs11t.h`
- `published/` — prior published stage snapshots the TC keeps in-repo
  (includes 3-01; does **not** include the 3.2 OS PDFs already vendored
  separately in this `docs/refs/` directory)

## Notable post-3.2 commits (master, in date order)

| Date | Commit | Change |
|---|---|---|
| 2026-06-17 | `2824518` | Add output convention to `C_EncapsulateKey` (#108) |
| 2026-07-01 | `4197b43` | Update parameter names in DH spec (#110) |
| 2026-07-01 | `1c31190` | Convert Historical Mechanisms, Profiles and Usage Guide to markdown in-repo (#101) |
| 2026-07-29 | `25a1ece` | Attribute `KEYS_REMAINING` missing for XMSS keys (#115) |
| 2026-08-26 | `24f8e1a` | Document 32-bit limit for `CK_ULONG` values (#122) |
| 2026-08-26 | `2b25dd8` | Make explicit that big integers are nonempty (#116/#124) |

Two earlier commits landed *before* the 2026-06-03 v3.2 OS date but concern
substantial new mechanisms — worth checking whether they made the v3.2 OS
text or are carrying into v3.3:

| Date | Commit | Change |
|---|---|---|
| 2026-04-08 | `b18801f` | Composite Signature support (#94) |
| 2026-05-06 | `9ceadc3` | Composite KEM support (#95) — `CKM_COMP_KEM`, `working/doc/spec/comp_kem.md` |

## Relevance to mechanism enable/disable and RSA/ECDSA vs. PQC-only policy

Searched this snapshot (`working/doc/**/*.md`) for anything new since v3.2
on mechanism deprecation or a runtime disable/policy mechanism. **Found
nothing new in kind** — no new `CKO_PROFILE` profile aimed at "quantum-safe
only", no new attribute alongside `CKA_ALLOWED_MECHANISMS`, no
`C_DisableMechanism`-style function. Deprecation in this draft, as in 3.2,
remains purely textual ("Note: X is deprecated") — e.g. `elliptic_curves.md`
(`CKF_EC_NAMEDCURVE`, `CKK_ECDSA`, `CKA_ECDSA_PARAMS`,
`CKM_ECDH_AES_KEY_WRAP`), `aes_key_wrap.md` (`CKM_AES_KEY_WRAP_PAD`),
`tls_1.2_mechanisms.md`. No RSA or ECDSA mechanism itself is marked
deprecated in this snapshot. The two spec-level levers documented in
[`../PKCS11_PROFILE_TRACEABILITY.md`](../../PKCS11_PROFILE_TRACEABILITY.md)
and the allow-mechanisms remediation plan — per-key `CKA_ALLOWED_MECHANISMS`
and simply not implementing/claiming a mechanism outside Complete Provider —
remain the only spec-sanctioned tools, unchanged in this v3.3 working text.
