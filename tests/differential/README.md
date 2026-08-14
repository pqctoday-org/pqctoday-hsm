# Cross-engine differential harness

This repository ships two independent PKCS#11 v3.2 engines: the C++ one in `src/`
(`softhsmv3`) and the Rust one in `rust/` (`softhsmrustv3`). They are meant to
behave identically wherever the specification says what the behaviour is, and to
differ only where it does not.

Prose claims about that parity have gone stale twice, and the 2026-08-13 audit
found 24 documentation statements contradicting the code. This harness replaces
the prose. It drives both engines through the same call sequences and asserts
identical observable outcomes; every legal difference lives in
[`exceptions.json`](exceptions.json) with a justification and a spec citation,
and anything not listed there fails the run.

## Running it

```bash
./scripts/run-differential-harness.sh                 # build both engines, run everything
./scripts/run-differential-harness.sh --list          # list the scenarios
./scripts/run-differential-harness.sh --only bytes.   # one group
./scripts/run-differential-harness.sh --verbose       # also print the covered divergences
./scripts/run-differential-harness.sh --no-build      # reuse already-built engines
```

Reports land in `build_union/p11_diff_report.{md,json}`. The Markdown one is the
readable view; the JSON is for tooling. Exit code 0 means every divergence is
accounted for.

**The runner rebuilds both engines on purpose.** A stale library makes this
harness lie in the most convincing way possible. The very first run here was
against a Rust cdylib built six hours before the conformance merge, and it
confidently reported every Phase 1 security fix as missing — read-only sessions
unguarded, logout cosmetic, the wrap-template partition absent, the security
officer seeing private objects. All of it evaporated on rebuild. Use
`--no-build` only when you have just built both yourself.

## Why one process rather than two

The harness `dlopen`s both engines into a single process. That was not the
obvious choice — duplicate `C_*` symbols and conflicting OpenSSL state are the
standard reasons to prefer a two-process transcript comparison — so it was
settled by measurement before anything else was written:

- **No shared OpenSSL.** `otool -L` on the Rust cdylib lists `libSystem` and
  `libiconv` and nothing else; its cryptography is pure Rust. The C++ engine
  links `libssl`/`libcrypto` from `openssl@3`. There is exactly one OpenSSL in
  the process and only one engine touches it, so there is no shared library
  state to corrupt.
- **No symbol interposition.** Both images are opened `RTLD_NOW | RTLD_LOCAL`,
  and every call goes through that image's own `CK_FUNCTION_LIST` rather than a
  process-global symbol. A probe confirmed the two `C_Initialize` pointers are
  distinct, and both engines initialise, enumerate slots and answer `C_GetInfo`
  with their own identities in the same process.
- **The harness re-checks it at runtime.** Before any scenario runs it compares
  the two `C_Initialize` pointers and refuses to continue if they are equal.
  Without that guard, an interposition would silently turn every result below
  into a comparison of one engine with itself — a harness reporting perfect
  parity because it was talking to the same library twice.

The cost of two processes would have been a serialisation format for every
observation and a transcript differ, which is the same comparison logic with an
extra encoding step in front of it. Given the evidence above, that buys nothing.
If a future engine ever links its own OpenSSL, this decision must be revisited —
that is the trigger condition, and the pointer check is where it will surface.

## What it compares

For each of the 48 scenarios, both engines are driven through the identical
sequence and every observation is recorded as a `path -> value` pair. The two
recordings are then diffed field by field.

Observations are of three kinds:

- **Return codes**, spelled as `CKR_*` names rather than numbers.
- **Output bytes**, in one of three views. `BYTES` records the whole output and
  is used only where every input was fixed, so the two engines are computing the
  same function of the same data — a fixed AES key, a fixed IV, a fixed
  plaintext. `SHAPE` records length and encoding class, for outputs random in
  value but specified in framing (the ECDH-KEM ephemeral point). `LEN` records
  length alone, for outputs random in both. That last distinction matters: the
  first version of this harness recorded the first byte of an ML-KEM ciphertext
  and would have failed at random roughly one run in a hundred, and a flaky
  harness gets switched off.
- **Attribute sets.** Every object produced by every creation path is
  interrogated with the *same* 50-attribute probe, so "this engine does not set
  X" appears as a return-code difference rather than a silently missing row. For
  each attribute the harness records the return code, the length, an encoding
  classification, and — for attributes whose bytes are not engine-random — the
  value.

The encoding classification is the load-bearing idea for the Phase 3 work: the
exact bytes of a freshly generated key differ between engines by construction,
but the *encoding* must not. `RAW_EC_POINT_UNCOMPRESSED_P256` versus
`DER_OCTET_STRING` is a real finding; the 65 bytes themselves are noise.

**Three classes of attribute are deliberately not classified**, because running
an encoding classifier over random bytes produces a verdict that flips with the
leading byte and a flaky harness gets switched off. Each was found by the
harness failing intermittently on an otherwise identical series of runs:

- **Unstructured** — `CKA_UNIQUE_ID`, `CKA_CHECK_VALUE`, `CKA_ID`, `CKA_SEED`,
  `CKA_LABEL`, the dates. A Rust unique id beginning `'0'` reads as an ASN.1
  SEQUENCE tag; roughly one three-byte check value in 256 starts `0x30`.
- **Big integers** — the RSA modulus, exponents, primes and coefficient, and
  `CKA_PUBLIC_KEY_INFO`. Not classified, *and* their length is recorded rounded
  up to a multiple of eight: an RSA CRT exponent whose top byte is zero
  serialises as 127 bytes rather than 128, about one key in 256. The rounding
  still catches a truncated, empty or wrong-size value.
- **Random outputs** — anything recorded with `ByteView::LEN`.

Length and presence remain recorded for all three, which is where the meaning
actually is: a check value present versus absent, a modulus 256 bytes versus 0.

### Coverage

| group | what it drives |
|---|---|
| `env` | mechanism list (one observation per mechanism), mechanism info flags, library info, token info with flags decomposed bit by bit, interface list, `CKO_PROFILE` objects |
| `create` | the attribute set after **every** creation path: generate key, generate key pair (EC, Ed25519, X25519, RSA, ML-DSA, ML-KEM, SLH-DSA, XMSS), create object (secret and data), derive, unwrap, encapsulate, decapsulate |
| `encoding` | the Phase 3 byte formats — EC parameters, EC point forms, post-quantum private key bytes, KEM ciphertext framing, PKCS#8 wrapped-key format |
| `bytes` | deterministic outputs that must be byte-identical: SHA-256, SHA3-256, HMAC-SHA256, AES-ECB/CBC/CTR/GCM, AES key wrap |
| `errors` | the Phase 4 codes — bad slot ids, session-handle precedence, null-mechanism cancel, unsupported curve, missing domain parameters, find-objects arguments, context-specific login, profile-object creation, unwrap of garbage |
| `security` | the Phase 1 invariants observable through the API — one-way attribute rules, sensitive-value hiding, allowed-mechanism enforcement, read-only session refusals, logout handle invalidation, close-all-sessions login reset, security-officer access to private objects, wrap-template partition |

### What it does NOT cover

Stated plainly, because a harness whose boundaries are vague gets trusted past
them:

- **The Rust native API** (`rust/src/native/*`), which the KMIP server calls
  directly. This harness drives the Cryptoki C ABI only. That matters for one
  specific known residual: §C of the remediation plan records that Rust's native
  key generation still emits the DER-wrapped EC point form. On the Cryptoki
  surface the two engines now agree exactly — `CKA_EC_POINT` produced no finding
  at all — so **the residual is real but unreachable from here**. Closing it
  needs a second lane that drives `native/` directly and compares against this
  one. Nobody has built that.
- **On-disk storage, tenancy and persistence.** The C++ engine keeps token
  objects in a file store; the Rust engine is in-memory. Scenarios use session
  objects so this is normalised away rather than tested.
- **Threading, fork behaviour and performance.** Out of scope by design.
- **The KMIP server and the protocol wrappers.** A sibling effort.
- **Byte-identity anywhere an exception covers.** The exception list is the
  definition of where identity is not required.

## The exception list

[`exceptions.json`](exceptions.json) is the substance of this work. Each entry
carries an id, a match expression, a status, a one-line justification and,
where one exists, a spec citation.

Two statuses, and the difference is the point:

- **`legal`** — adjudicated against PKCS#11 v3.2 OS (03 June 2026), its Profiles
  and its Usage Guide. Permitted. It will not be fixed, and the citation says
  why not.
- **`defect`** — a known, still-open non-conformance in one engine, recorded so
  the harness has a stable baseline and a *new* divergence stands out. Not an
  excuse: a worklist item, each naming its plan item.

Matching is on `scenario`, `path`, `kind`, and optionally the `cpp` and `rust`
values, all globs supporting `*`, `?` and `|` alternation. The value matchers
exist because two divergences can share a path and be entirely different
questions — `CKA_KEY_GEN_MECHANISM` differing because Rust narrows
`CK_UNAVAILABLE_INFORMATION` to 32 bits is a defect; the same path differing
because Rust names the encapsulation mechanism is not. Without the value
matchers, an entry for one silently absolves the other.

**First match wins**, so entries are ordered most-specific first: exact scenario,
then scenario glob, then value-matched, then general path, then the
documentation-only entries.

### Three example entries

A legal one, where the specification is genuinely silent:

```json
{
  "id": "LEGAL-MECHANISM-SET",
  "status": "legal",
  "scenario": "env.mechanism_set",
  "path": "mech*",
  "justification": "The two engines advertise different mechanism sets (127 vs 116, 47 differences) and no profile THIS ENGINE CLAIMS requires any mechanism, so this is a product decision, not a conformance gap. Complete Provider does require all of them; neither engine claims it.",
  "citation": "PKCS #11 Profiles v3.2 OS: Baseline Provider, Complete Provider, Extended Provider, Authentication Token and Public Certificates Token each state 'Supports the following mechanisms: a. None specified.' Only the HKDF TLS Token profile names one."
}
```

A defect found by this harness and confirmed against an independent oracle:

```json
{
  "id": "DEFECT-RUST-AES-CTR-CIPHERTEXT",
  "status": "defect",
  "scenario": "bytes.aes_ctr",
  "path": "*ct.bytes",
  "justification": "AES-256-CTR over a fixed key, fixed counter block and fixed plaintext produces different ciphertext in the two engines, at BOTH 128-bit and 32-bit counter widths. An independent OpenSSL oracle agrees with C++, so Rust's CKM_AES_CTR is wrong. Found by this harness; not previously recorded anywhere.",
  "citation": "PKCS#11 v3.2 §6.28 CK_AES_CTR_PARAMS: cb is the full 128-bit initial counter block and ulCounterBits names how many of its low-order bits increment. Oracle: openssl enc -aes-256-ctr with the same key/IV matches the C++ output byte for byte."
}
```

A defect that needed the value matchers to state precisely:

```json
{
  "id": "DEFECT-RUST-KEY-GEN-MECHANISM-NARROWED",
  "status": "defect",
  "path": "*CKA_KEY_GEN_MECHANISM*",
  "cpp": "ffffffffffffffff",
  "rust": "ffffffff00000000",
  "justification": "Rust writes CK_UNAVAILABLE_INFORMATION as a 32-bit -1 zero-extended into eight bytes (0x00000000FFFFFFFF) where the LP64 ABI value is eight bytes of 0xFF. A caller comparing against CK_UNAVAILABLE_INFORMATION therefore sees mechanism 4294967295 instead. Same width-narrowing family as S9.",
  "citation": "PKCS#11 v3.2 §3.1: CK_UNAVAILABLE_INFORMATION is (~0UL); CK_ULONG is 'an unsigned value, at least 32 bits long' and is 8 bytes on LP64, which is what this ABI exports."
}
```

## When the harness fails

It names the scenario, the field, both values, and whether an exception covers
it. Then:

1. **Adjudicate against the specification**, not against the other engine.
   Mutual agreement between these two engines is not conformance — E1 in the
   remediation plan was exactly that case: both engines emitted the same
   non-conformant DER-wrapped ciphertext and interoperated happily.
2. **Add an entry** with `status: "legal"` and a citation, or `status: "defect"`
   naming the plan item and what must change.
3. **Do not widen an existing entry's glob** to make a finding disappear. That
   failure mode has already happened once here: a `*CKA_PRIVATE*` entry written
   for the `CKA_PRIVATE` default was silently absorbing `CKA_PRIVATE_EXPONENT`,
   which is a different question entirely. Anchor globs with the surrounding
   dots — `*.CKA_PRIVATE.*`.

The run also reports **exception entries that matched nothing**. Those are not
failures, but they deserve attention: an entry that stops matching usually means
the engines converged and the entry is stale. Two entries here were removed for
exactly that reason once the Rust engine was rebuilt. The six that permanently
match nothing use the scenario `__never_matches__` and are deliberate: they
record divergences that were considered and consciously left untested
(on-disk storage, XMSS state representation, PIN lockout, message-based signing
flags, build-flag-varying mechanism sets, KDF coverage), so a future engineer
knows they were thought about rather than forgotten.

## Proving the harness still detects

A harness that reports "all identical" without ever having caught anything is
worthless. Two ways to check it is alive:

**Drop an exception and watch the finding come back.**

```bash
./scripts/run-differential-harness.sh --no-build \
    --drop-exception DEFECT-RUST-AES-CTR-CIPHERTEXT --only bytes.aes_ctr
```

The entry is ignored for that run, the AES-CTR ciphertext difference becomes
uncovered, and the run exits non-zero.

**Check a known-live defect is still reported.** `--verbose` prints the covered
divergences grouped by entry, so any `defect`-status entry can be read back with
its observations. If a `defect` entry ever stops matching, either it was fixed
(delete it, and say so in the commit) or the scenario stopped running.

## Adding a scenario

Scenarios live in [`scenarios.inc`](scenarios.inc), one `add({...})` per
behaviour: id, group, description, the mechanisms it requires, whether it wants
a read/write session, whether the runner should log in, and the body.

A scenario that requires a mechanism one engine lacks records only the gate
result, so the diff is one legible line rather than a cascade of failures — and
that line is covered by `LEGAL-MECHANISM-SET`.

Record through the `Recorder`: `r.rv(path, rv)` for return codes, `r.num` /
`r.put` for scalars, `record_bytes(r, path, p, n, view)` for outputs, and
`record_attrs(e, r, prefix, session, object)` for an object's whole attribute
set. Paths beginning `_ctx.` are recorded for the report but never compared.
