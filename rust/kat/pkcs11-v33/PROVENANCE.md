# rust/kat/pkcs11-v33 — provenance

Data for the PKCS#11 v3.3 working-draft composites (composite ML-DSA and
composite ML-KEM). Read by `rust/src/native/composite.rs` and
`rust/src/native/composite_vectors.rs`. Fetched 2026-10-21. The repository
carries these data files and fact extracts only, never the draft documents.

## Test vectors (byte-identical to upstream)

| File | Upstream | Commit (date) | Entries | sha256 |
|---|---|---|---|---|
| `composite-kem/testvectors.json` | https://raw.githubusercontent.com/lamps-wg/draft-composite-kem/d77e75420034d826e14cbef0b779986511f114e9/src/testvectors.json | `d77e75420034d826e14cbef0b779986511f114e9` (2026-02-21) | 14: the 12 composite ML-KEM sets plus plain ML-KEM-768 and ML-KEM-1024. Fields `tcId, ek, dk, dk_pkcs8, c, k, x5c`; top-level `cacert`. | `1b8d80f3ce623f368466eda44820f8b82ca67c9955e213d212c997137ef9ff24` |
| `composite-sig/testvectors.json` | https://raw.githubusercontent.com/lamps-wg/draft-composite-sigs/f0627ab34acfe1aee0abce4bee91ed2b577eab76/src/testvectors.json | `f0627ab34acfe1aee0abce4bee91ed2b577eab76` (2026-01-07) | 21: the 18 composite ML-DSA sets plus plain ML-DSA-44/65/87. Fields `tcId, pk, sk, sk_pkcs8, s, sWithContext, x5c`; top-level message `m` and context `ctx`. | `a60f697f9fd94c3cd5e4501a40c4396d9a9ffc7cf0f8a1ddd87dedbb46a7abf0` |

Every entry is kept, including the four brainpool sets (run since the
engine gained brainpoolP256r1/P384r1, cargo feature `brainpool`) and the
plain ML-KEM / ML-DSA entries.

These are single known-answer vectors per set, written by the draft
authors, not by a certification body. They predate the current drafts
(composite-kem -23, composite-sigs -19); the OIDs, labels and signature
prefix were compared with the current drafts on 2026-10-21 and are
unchanged. Encapsulation and signing are randomised, so the vectors prove
decapsulation and verification only.

**Upstream licence.** Both repositories carry the same `license.txt`
(sha256 `df6e10567fa902dfe43d23fcfbb3ff2d1e9a01c2aca8f8cdc26b4f2773e92c2c`
at the commits above); their READMEs add no licence terms. It reads:

> Copyright (c) 2022 IETF Trust and the persons identified as the
> document authors. All rights reserved.
>
> This document is subject to BCP 78 and the IETF Trust's Legal
> Provisions Relating to IETF Documents
> (https://trustee.ietf.org/license-info) in effect on the date of
> publication of this document. Please review these documents
> carefully, as they describe your rights and restrictions with respect
> to this document. Code Components extracted from this document must
> include Simplified BSD License text as described in Section 4.e of
> the Trust Legal Provisions and are provided without warranty as
> described in the Simplified BSD License.

## Fact extracts (not byte copies)

| File | Source | Source sha256 |
|---|---|---|
| `pkcs11-v33-identifiers.json` | OASIS PKCS 11 TC, https://github.com/oasis-tcs/pkcs11 commit `9ef73f9f44ed8a240b05484427a0851ab36be251`, `working/headers/pkcs11t.h` | `765a28ac349d3cd940e5a90392fb9bc4a939151b29f63b5c156723c64f61f70e` |
| `composite-sigs-draft19-facts.json` | https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-19.txt (§2.2, §6, §6.1, Appendix A) | `b4ee04416efc26e7d8de7c740dc3848ffe8b8cc9dcd035ad9d4e33e18844ec83` |
| `composite-kem-draft23-facts.json` | https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-kem-23.txt (§3.4, §6, §6.1, Appendix A) | `aaaffdf5eca9cf8e2757e2fd4257a30536f2c6ead7c6eb24f542fcc8b28e26b8` |

Each extract repeats its provenance in a `_provenance` block.

## Refresh rule

When either draft becomes an RFC, or an upstream vector file changes
commit: re-run the coverage gate and the vector checks on the new file,
diff it against the pinned one, and adopt it only after they pass. Record
the new commit and sha256 here and in `CHANGELOG.md`. The tests check the
sha256 of both vector files, so an unrecorded change fails.
