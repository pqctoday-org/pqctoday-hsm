# PQC interop replay corpus (vendored subset)

A structurally-complete subset of the **OASIS KMIP 3.0 PQC interop test
set** (`kmip-3-0-pqc-tests-03.zip`, 2025-02-26), driven through the real
release `pqctoday-kmip` server over TLS by
[`../harness/dispatcher_replay.py`](../harness/dispatcher_replay.py) and
gated in CI (job **KMIP PQC Interop Replay**).

Each transcript is replayed byte-exact: the server's TTLV responses must
match the recorded responses modulo volatile tags (timestamps, UIDs).

## Why a subset

The full set is 1452 transcripts (several MB) and the SLH-DSA "s"
(small-signature) `siggen` cases are slow to sign. This vendored subset
(42 transcripts) covers every **category** and every **response shape**
the server must produce, while staying fast enough for per-PR CI:

| Category | Coverage |
|----------|----------|
| keygen | ML-DSA 44/65/87, ML-KEM 512/768/1024, SLH-DSA SHA2-128f + SHAKE-128f — `Get` of `SeedPrivateKey` (`{Seed, Key}`) **and** `Raw` private/public |
| encapsulate | ML-KEM 512/768/1024 — ciphertext + `SecretData` (`SecretDataType=Seed`) round-trip |
| decapsulate | ML-KEM 512/768 — recovered shared secret round-trip |
| siggen | ML-DSA 44/65/87, SLH-DSA SHA2-128f — signature byte-exact |
| sigver | ML-DSA 44/65/87, SLH-DSA SHA2-128f — validity indicator |

## Replaying the full 1452-case corpus

Point the harness at a local checkout of the full set:

```bash
KMIP_REPLAY_CORPUS=/path/to/kmip-3-0-pqc-tests \
  python3 conformance/harness/dispatcher_replay.py
```

The harness cycles its listen port per test, so the full sweep runs
without exhausting `TIME_WAIT` slots.
