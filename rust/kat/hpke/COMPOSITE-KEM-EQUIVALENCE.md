# Composite ML-KEM and the HPKE-PQ hybrid KEMs: measured, not read

Result (2026-11-03): for the three suites below, `CKM_COMP_KEM` (PKCS#11 v3.3
working draft, composite ML-KEM) and the HPKE-PQ hybrid KEM produce the **same
shared secret**, byte for byte, in both directions. The drafts describe one
function for these suites; this note records that the engine agrees.

| HPKE-PQ KEM | Composite parameter set | Label |
|---|---|---|
| MLKEM768-X25519 (0x647a) | `CKP_COMP_KEM_MLKEM768_X25519` | `5c2e2f2f5e5c` (`\.//^\`) |
| MLKEM768-P256 (0x0050) | `CKP_COMP_KEM_MLKEM768_ECDH_P256` | `MLKEM768-P256` |
| MLKEM1024-P384 (0x0051) | `CKP_COMP_KEM_MLKEM1024_ECDH_P384` | `MLKEM1024-P384` |

## What was run

Tests: `ffi::composite_kem_tests::p1_*` (`rust/src/composite_kem_tests.rs`).

1. **CFRG vectors through the composite KEM** (30: 10 per suite). A composite
   private key (`mlkemSeed(64) ‖ tradSK`) is assembled from the vector's
   published components; the engine derives the vector's own encapsulation key
   from it; `CKM_COMP_KEM` decapsulates the vector's ciphertext to the vector's
   `shared_secret`.
2. **X-Wing vectors** (3). The 32-byte seed is expanded with SHAKE256 as
   draft-connolly-cfrg-xwing-kem §5.2 specifies; the composite key is that
   expansion.
3. **Reverse direction** (30). A ciphertext produced by `CKM_COMP_KEM` (fresh
   randomness each time) is decapsulated by the engine's HPKE-PQ KEM code from
   the CFRG seed; the secrets are equal.

Vectors are in this directory (provenance in `PROVENANCE.md`); they come from
sources independent of this engine.

## Controls (so a pass means something)

In every comparison: a bit flipped in the ML-KEM part of the ciphertext still
returns a secret but not the vector's; a bit flipped in the traditional part is
refused or gives a different secret; the same private-key bytes are refused
under a different parameter set (90 control checks).

Mutation checks, run once and reverted: changing one byte of the P-256 label in
`native/composite.rs` fails the forward and reverse tests for that suite only
(X-Wing and P-384 still pass); changing it in `native/hpke.rs` fails the
reverse test only.

## Limits

- The private-key format differs and is bridged **in test code only**. HPKE-PQ
  derives keys from a 32-byte seed; a composite private key is the 64-byte
  ML-KEM seed followed by the traditional key. The CFRG vectors publish the
  expanded components, so no derivation is reimplemented for P-256/P-384.
- This covers key agreement. HPKE's KeySchedule, AEAD and Export are not part
  of `CKM_COMP_KEM`.
- Brainpool, X448, P-521 and RSA composite sets have no HPKE-PQ counterpart and
  are not covered.
- Draft revisions: composite-kem `-23`, hybrid-kems `-12`, concrete-hybrid-kems
  `-04`, xwing-kem `-11`. Both sides are drafts and can still change.
