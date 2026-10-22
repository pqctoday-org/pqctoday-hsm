# Composite vector validation evidence (V4, V5)

Evidence for the PKCS#11 v3.3 working-draft composites (composite ML-KEM,
composite ML-DSA). The engine's own tests (`rust/src/composite_kem_tests.rs`,
`rust/src/composite_sig_tests.rs`) run the LAMPS vectors in
`../composite-kem/` and `../composite-sig/` (provenance: `../PROVENANCE.md`).
The two checks here answer the questions those tests cannot answer alone:

- **V4: are the upstream vectors themselves right?** A vector that is wrong
  would make a correct engine look broken, or a wrong engine look right.
- **V5: does our encapsulation and signing agree with someone else's
  code?** Encapsulation and signing are randomised, so no known-answer test
  covers them; a round trip only shows the engine agrees with itself.

Both ran on 2026-10-21 on the build host, inside a throwaway
`python:3.12-slim-trixie` container, against the draft authors' reference
code pinned to the same commits as the vectors:

| Repository | Commit |
|---|---|
| https://github.com/lamps-wg/draft-composite-kem | `d77e75420034d826e14cbef0b779986511f114e9` |
| https://github.com/lamps-wg/draft-composite-sigs | `f0627ab34acfe1aee0abce4bee91ed2b577eab76` |

The reference code is third-party and was treated as untrusted: it ran only
in that container, and none of it is in this repository. The scripts here
are ours. `results/upstream_provenance.txt` lists the sha256 of the upstream
files used, `results/env.txt` the OpenSSL, Python and package versions
(V5 pins the packages to the versions V4 resolved, `v5/scripts/constraints.txt`).

The reference code reports `VERSION_IMPLEMENTED` as composite-kem -11 and
composite-sigs -09; the current drafts are -23 and -19. The OIDs, labels and
signature prefix are unchanged between those versions (compared on
2026-10-21), and V4's independent check below follows the current text.

## V4: the upstream vectors, checked by the reference code (`v4/`)

`v4/scripts/run_v4.sh` runs three checks; `v4/results/results.json` holds
every per-vector result and a summary.

| Check | What it proves | Result |
|---|---|---|
| KEM: reference `decap(c)` with the vector's `dk` equals `k` | the KEM vectors are what the authors' code computes | 12/12 composite, 2/2 plain ML-KEM |
| KEM: public key re-derived from `dk` equals `ek` | `dk` and `ek` are one key pair | 12/12 |
| KEM: `x5c` SPKI OID and key equal the set's OID and `ek`; certificate signed by `cacert` | the certificates match the vectors | 12/12, 12/12 |
| Signatures: reference `verify(s, m)` and `verify(sWithContext, m, ctx)` | the signature vectors verify under the authors' code | 18/18, 18/18, plain 3/3 |
| Signatures: `sWithContext` without `ctx` is rejected | the context really enters M' | 18/18 |
| Signatures: public key re-derived from `sk` equals `pk`; `x5c` SPKI and self-signature | key pair and certificate consistency | 18/18, 18/18, 18/18 |
| Independent (`indep_check.py`): one signature set (id-MLDSA65-ECDSA-P256-SHA512) and one KEM set (id-MLKEM768-X25519-SHA3-256) re-checked from the current draft text with the Python standard library and the OpenSSL command line, no reference code | the vectors agree with composite-sigs-19 and composite-kem-23, not only with the generator | both halves of `s` and `sWithContext` verify; `k` reproduced |

## V5: our output, checked by the reference code (`v5/`)

The engine generated, for each set, a fresh key pair; for each of the 18
signature sets two signatures over the vector file's `m` (without and with
its `ctx`), and for each of the 12 KEM sets one encapsulation and the
engine's shared secret. (First run 2026-10-21 over the 26 non-brainpool
sets; re-run the same day over all 30 once the engine had brainpoolP256r1
and brainpoolP384r1. The results here are the 30-set run.) The generator is the ignored test
`v5_fixture_generator` in `rust/src/composite_sig_tests.rs`. The reference
code then checked them (`v5/scripts/run_v5.sh`, results in
`v5/results/results.json`):

| Check | What it proves | Result |
|---|---|---|
| reference `verify(s, m)` under our `pk` | our CKM_COMP_SIG signing (M', label, both halves, serialisation) matches the draft authors' | 18/18 |
| reference `verify(sWithContext, m, ctx)` under our `pk` | the same, with a context | 18/18 |
| `sWithContext` without `ctx`, `s` with `ctx`, `s` over another message: rejected | the reference is not accepting everything | 18/18 each |
| reference `decap(c)` with our `dk` equals our `k` | our encapsulation and our combiner agree with the authors' | 12/12 |
| reference public key from our `dk` equals our `ek` | our key generation and serialisation agree | 12/12 |
| `c` with its last byte flipped: the reference does not return our `k` | the check can fail | 12/12 |

`v5/engine-signatures.json` is the public part of the V5 input (our
public keys and signatures, marked self-generated, never to be mistaken for
upstream vectors). The KEM half of the input holds the private keys and
shared secrets of throwaway keys and is not committed; its sha256 is recorded.

## Reference-code defect

At `d77e754` the KEM reference's `CompositeKEM.loadKeyPair` unpacks three
values (`a, _, b = self.deserializePrivateKey(private_bytes)`) from a
function that returns two (`mlkemSeed, tradSK`), so it raises for every
composite key: `ref_loadKeyPair_as_shipped` is 0/12 in V4 and 0/12 in V5.
Both runs use a three-line loader shim built from the reference's own
functions (split `dk` with its `deserializePrivateKey`, load each half with
the component `loadKeyPair`); `decap()` and the combiner are the reference's,
unchanged. The defect has not been reported upstream.

## Re-running

On a disposable host with Docker: clone both repositories at the commits
above into `up/kem` and `up/sigs`, then

```sh
docker run --rm -v "$PWD/up:/up:ro" -v "$PWD/v4/scripts:/v4:ro" -v "$PWD/out:/out" \
  python:3.12-slim-trixie sh /v4/run_v4.sh
```

and for V5 generate a fixture first
(`PQCTODAY_V5_FIXTURE_OUT=/path/v5-fixture.json cargo test --lib v5_fixture_generator -- --ignored`
in `rust/`), put it in `in/`, and mount `v5/scripts` as `/v5` and `in` as
`/in` for `run_v5.sh`. A refreshed upstream vector file is adopted only
after V4 passes on it again; record the refresh in
`../PROVENANCE.md` and the CHANGELOG.
