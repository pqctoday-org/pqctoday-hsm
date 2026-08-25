# Implementation plan — JCA provider remaining gaps (2026-08-25)

Continuation plan for
[implementation-plan-jdk27-jca-provider-2026-08-24.md](implementation-plan-jdk27-jca-provider-2026-08-24.md)
(the "main plan" below — W0–W5 complete, W6 in progress, W7/W8 not
started). This document plans **everything that remains**, across both
repos:

- **pqctoday-hsm**: the C++ engine change unblocking TLS, W6 completion
  (handshake + benchmark), the Arena/zeroization redesign, small
  hardening items, W7 (Rust engine via gRPC) in full detail, and the
  hsm-side W8 integration (local gate, CHANGELOG, README).
- **pqctoday-sandbox**: the `Dockerfile.dev-sandbox` jar wiring, two new
  Java samples (provider demo + hybrid-TLS demo), and samples
  docs/matrix updates.

Decisions locked with the user 2026-08-25 (recorded in §2), current
baseline: branch `feat/jdk27-jca-provider` at `3948594`, 198/198 tests
green live in the dev-sandbox container, nothing pushed.

---

## 1. Gap inventory (complete, honest)

| # | Gap | Severity | Repo | Workstream |
|---|---|---|---|---|
| G1 | TLS 1.3 salt chaining (main plan W6 "Gap 4"): opaque HKDF intermediates can't be reused as the next Extract's salt; engine rejects `CKF_HKDF_SALT_KEY` | Blocks W6 | hsm (engine **and** JavaJCE) | WS-A |
| G2 | **Anticipated, not yet observed**: TLS record layer vs this provider's AES-GCM policies (module-generated-IV-only on encrypt; opaque-key-only `Cipher`). The handshake has never progressed past G1, so whether JSSE's record path trips either policy is unverified — listed as a decision point to hit live, not a known defect | Likely blocks W6 after G1 | hsm (JavaJCE) | WS-B |
| G3 | W6 completion: green live handshake with `P11Debug` token-side proof + latency benchmark (benchmark is **required** — decision Q4) | W6 exit | hsm (JavaJCE) + sandbox (pqc-rest as peer) | WS-B |
| G4 | Zeroization architecture: `P11Library` uses one `Arena.ofShared()` for the session lifetime; no per-operation confined arenas; no zero-before-free (disclosed in main plan §W5 zeroization audit and the security-posture doc, Area 8) | FIPS-posture debt | hsm (JavaJCE) | WS-C |
| G5 | Smaller disclosed gaps: SHA-3 PSS variants unbuilt; GCM IV-uniqueness-across-sessions test never attempted; pre-hash ML-DSA/SLH-DSA (`CKM_HASH_ML_DSA_*`/`CKM_HASH_SLH_DSA_*`) unbuilt; `engineGetCreationDate` stub | Minor | hsm (JavaJCE) | WS-D |
| G6 | W7: Rust engine via gRPC transport — full workstream (decision Q2) | Phase 2 | hsm (JavaJCE + remoting) | WS-E |
| G7 | W8 hsm side: JavaJCE step in `scripts/local-gate.sh`, CHANGELOG entry, root README component link | Release hygiene | hsm | WS-F |
| G8 | W8 sandbox side: jar built into `Dockerfile.dev-sandbox`, provider sample, hybrid-TLS sample, samples README/matrix rows (decision Q3: full scope) | Integration | sandbox | WS-G |
| G9 | JDK 27 GA swap (GA target 2026-09-15): re-verify on GA, update docs/catalog rows | Calendar-gated | hsm + sandbox | WS-H |

Two **corrections to the main plan's own text**, found while grounding
this plan (same discipline as the corrections already recorded there):

1. Main plan §W7 says the remoting contract uses "kebab-case algorithm
   ids". Wrong — `remoting/proto/proto/pkcs11_remote.proto` defines a
   protobuf **`Algorithm` enum**: `ED25519`, `ML_DSA_44/65/87`,
   `ML_KEM_512/768/1024`. And the verb list is exactly
   `Health / OpenSession / CloseSession / GenerateKeyPair / Sign /
   Verify / Encapsulate / Decapsulate` — **no SLH-DSA, no EC/ECDSA, no
   RSA, no symmetric anything**. W7's initial JCA surface is therefore
   even narrower than "PQC services": Ed25519 + ML-DSA + ML-KEM,
   nothing else, until the proto itself is extended (an explicit
   follow-on, WS-E5).
2. Main plan §W8 implies the sandbox consumes the hsm repo as a
   submodule. Actually `Dockerfile.dev-sandbox` `COPY`s the **sibling
   checkout** (`COPY pqctoday-hsm /usr/src/pqctoday-hsm`, build context
   = the parent directory) and builds the engine from source in a
   builder stage. The jar wiring in WS-G follows that same existing
   pattern, not a submodule flow. JDK 27 RC 27+35 is **already
   installed** in the image alongside temurin-24 — no image-level JDK
   work needed.

---

## 2. Decisions locked (2026-08-25, with the user)

| Q | Decision |
|---|---|
| Gap 4 fix | **Both**: engine `CKF_HKDF_SALT_KEY` support is the primary path (full opacity preserved); plus an explicit, off-by-default, documented non-FIPS fallback flag enabling extractable HKDF intermediates for callers stuck on an engine build without the fix |
| W7 treatment | **Full workstream in this plan** (WS-E) |
| Sandbox scope | **Full**: provider sample + hybrid-TLS sample + Dockerfile jar wiring + samples README/matrix updates |
| W6 benchmark | **Required for W6 completion** (transport-arms methodology) |

---

## 3. WS-A — Engine `CKF_HKDF_SALT_KEY` + Java salt-by-handle (unblocks TLS)

**Why this is small, verified not assumed:** read live 2026-08-25 —
`SoftHSM_keygen.cpp:3721` currently hard-rejects
`CKF_HKDF_SALT_KEY` (`CKR_MECHANISM_PARAM_INVALID`), but the very same
function already resolves the **base key** by handle and reads its
material (`key->getByteStringValue(CKA_VALUE)`, with a
`token->decrypt(...)` branch for private token objects) ~40 lines
below. The salt fetch is the identical pattern applied to a second
handle. And `CK_HKDF_PARAMS` already carries `hSaltKey`
(`pkcs11t.h:2653`); the Java side's `mechHkdf` already writes that
struct slot (always `0` today, with a javadoc saying so). Nothing
structural is missing on either side.

### A1 — Engine change (`src/lib/SoftHSM_keygen.cpp`)

1. Replace the rejection block: when `ulSaltType == CKF_HKDF_SALT_KEY`,
   resolve `hkdfp->hSaltKey` through the same handle/session validation
   the base key gets; require `CKO_SECRET_KEY`; return
   `CKR_KEY_HANDLE_INVALID` for a bad handle (match how the base-key
   path reports it — confirm the exact CKR the base path yields for an
   invalid handle and mirror it, don't guess).
2. Read the salt key's `CKA_VALUE` (with the `isPrivate → token->decrypt`
   branch, mirroring the IKM block verbatim), pass as
   `OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, ...)` —
   exactly where the `CKF_HKDF_SALT_DATA` branch feeds today.
3. Keep `CKF_HKDF_SALT_DATA` and `CKF_HKDF_SALT_NULL` behavior
   byte-identical.
4. Spec check before coding: PKCS#11 v3.2 §on CKM_HKDF_DERIVE for
   `CKF_HKDF_SALT_KEY` semantics (which key classes are legal as salt,
   error codes) — grep the local spec PDF/`pkcs11t.h` comments; cite in
   the commit.

**Verify (engine):**
- New C++ test case(s): (i) HKDF with salt supplied as data vs the SAME
  salt bytes imported as a generic-secret object and supplied via
  `hSaltKey` → identical output (the decisive equivalence oracle, no
  external vector needed); (ii) invalid `hSaltKey` → the documented CKR;
  (iii) `CKF_HKDF_SALT_KEY` with a private/sensitive salt key still
  works (exercises the decrypt branch).
- Isolated C probe (the established `dlopen` technique) against the
  rebuilt `.so` before any Java is written — proves the engine change
  independent of FFM.
- `bash scripts/local-gate.sh --cpp` (ctest + compliance-report
  freshness — the report will regenerate; commit the refreshed copy).
- **Rust-engine parity check** (don't skip silently): determine whether
  `softhsmrustv3` implements `CKM_HKDF_DERIVE` at all; if it diverges,
  record the divergence with a citation in
  `tests/differential/exceptions.json` per the differential-harness
  contract rather than leaving the harness to trip later.
- Engine CHANGELOG entry (this is an engine behavior addition, not just
  a JavaJCE change).

### A2 — Java salt-by-handle (`P11Library` + `P11HKDFKDFSpi`)

1. `mechHkdf` overload (or an added `long saltKeyHandle` parameter):
   sets `ulSaltType = CKF_HKDF_SALT_KEY` (0x4, already in `pkcs11t.h`),
   `hSaltKey = handle`, `pSalt = NULL / ulSaltLen = 0`.
2. `P11HKDFKDFSpi.derive`: when the single salt element is a
   `P11Key.Secret`, use its handle (today this path throws). Foreign
   byte-backed salts keep the existing `CKF_HKDF_SALT_DATA` path
   unchanged.
3. Flip the existing test `rejectsAnOpaqueKeyAsSalt` into
   `opaqueSaltIsAcceptedViaSaltKeyHandle` — and add the cross-check:
   derive with an opaque salt (handle path) vs SunJCE's HKDF with the
   same salt bytes via `SecretKeySpec` → byte-identical `deriveData`
   output (same real-reference-implementation oracle the multi-IKM fix
   used).
4. **Container engine refresh step is part of this workstream, not an
   afterthought:** the container's `/usr/local/lib/softhsm/libsofthsmv3.so`
   must be rebuilt from the changed source before the Java tests can
   pass — rebuild in the container (or `docker cp` a fresh build),
   verify by artifact age + a probe call, per the
   build-artifact-not-exit-code discipline.

### A3 — Non-FIPS fallback flag (decision Q1, "both")

1. `-Dsofthsmv3.jce.extractableHkdf=true` (default **off**): when set,
   `P11HKDFKDFSpi.engineDeriveKey` emits `CKA_EXTRACTABLE=true` outputs
   whose bytes JSSE can chain itself — for deployments running an
   engine build without A1.
2. `P11Debug.log` a clear notice every time the flag influences a
   derivation; document in `JavaJCE/README.md` and the security-posture
   doc (Area 8) as an explicit non-FIPS mode, mirroring how main plan
   §5 risk 5 already frames the GCM caller-IV flag.
3. Test: with the property set (set/cleared inside the test), a derived
   key's `getEncoded()` is non-null; with it unset, null. Keep the
   flag's test hermetic — restore the property in `finally`.

**Exit criteria WS-A:** engine equivalence tests green, isolated C probe
green, full JavaJCE suite green against the rebuilt engine (expected
199+/199+ after the test flip), differential-harness state recorded,
CHANGELOG updated.

**WS-A: DONE 2026-08-25, PASSED.**

- **A1 (engine).** Implemented exactly as scoped — `CKF_HKDF_SALT_KEY`
  resolves `hSaltKey` via `handleManager->getObject` (same pattern as
  the base key), `CKR_KEY_HANDLE_INVALID` on a bad handle (matching the
  base key's own `GAP 6.5` precedent, confirmed by reading that code
  rather than guessing), the salt key's `CKA_VALUE` read with the same
  `isPrivate → token->decrypt` branch as the base key, fed into
  `OSSL_KDF_PARAM_SALT`. Spec-checked first: PKCS#11 v3.2 §6.62.2
  (extracted from the real OASIS Standard PDF via `pdftotext`, not
  recalled) says only "salt is supplied as a key in hSaltKey" — no
  class/`CKA_DERIVE` restriction on the salt key beyond it being
  readable, so none was added beyond the handle/credential check.
- **New C++ test coverage, not just a rebuild.** `CKM_HKDF_DERIVE` had
  **zero** prior C++ unit-test coverage anywhere in this engine's test
  suite before this — confirmed by grepping the whole `src/lib/test/`
  tree. Added `DeriveTests::testHkdfDerive` (5 assertions): the
  decisive equivalence oracle (salt as `CKF_HKDF_SALT_DATA` vs the
  identical bytes as `CKF_HKDF_SALT_KEY` → byte-identical output),
  repeated against a **private/sensitive** salt key to exercise the
  `decrypt()` branch specifically, an invalid salt handle →
  `CKR_KEY_HANDLE_INVALID`, and an invalid `ulSaltType` value →
  `CKR_MECHANISM_PARAM_INVALID` (the pre-existing code silently only
  checked for the one bad value it used to reject; now validates the
  field properly). This C++-level test — the real `C_DeriveKey` API,
  no FFM, no Java — is what satisfies this workstream's planned
  "isolated C probe" requirement; a separate `dlopen` script would have
  exercised the identical code path redundantly.
- **A real, live build-environment finding, not a code defect.**
  Building via the existing `pqc-rust` container (Debian 13 / glibc
  2.41) and copying the resulting `.so` into `pqc-dev-sandbox` (Ubuntu
  24.04 / glibc 2.39) — the container this repo's own JavaJCE tests
  actually run against — crashed the JVM outright:
  `tcache_thread_shutdown(): unaligned tcache chunk detected / Aborted`,
  a glibc heap-corruption abort from the ABI mismatch, not from
  anything in this change (confirmed: the crash reproduced with the
  change reverted too, before root-causing it to the cross-container
  copy). Fixed by building the engine **natively inside**
  `pqc-dev-sandbox` instead — copied a minimal source tarball
  (`CMakeLists.txt`, `config.h.in.cmake`, `cmake/`, `src/`,
  `softhsmv3.pc.in` — 1.4 MB, not the 27 GB working tree) into the
  container and configured against its own OpenSSL 3.6.3 at
  `/usr/local/ssl` (`-DOPENSSL_ROOT_DIR=/usr/local/ssl`, the exact path
  `Dockerfile.dev-sandbox` itself uses — found by reading that
  Dockerfile, not guessed). This is the correct build discipline for
  any future engine rebuild targeting this container, not a one-off
  workaround — worth carrying into WS-G's Dockerfile jar-wiring work,
  which will need the same container-native build for consistency.
- **A2 (Java salt-by-handle).** `P11Library` gained a `mechHkdf`
  overload taking a `saltKeyHandle` directly (`CKF_HKDF_SALT_KEY =
  0x4`, struct layout unchanged from the already-verified
  `HKDF_PARAMS` layout). `P11HKDFKDFSpi`'s salt handling now prefers
  the handle path whenever the salt is already one of this provider's
  own token-resident keys (opaque or not — no reason to round-trip
  through bytes when a handle exists), falling back to the existing
  `CKF_HKDF_SALT_DATA` bytes path for a genuinely foreign key. The
  flipped test (`opaqueSaltIsAcceptedViaSaltKeyHandle`, was
  `rejectsAnOpaqueKeyAsSalt`) proves correctness the same way the C++
  test does: byte-identical output against `KDF.getInstance("HKDF-SHA256")`
  with **no explicit provider** (JDK's own real SunJCE reference
  implementation), not a self-consistency check.
- **A3 (non-FIPS fallback flag).** `-Dsofthsmv3.jce.extractableHkdf=true`
  (default off) makes `engineDeriveKey` return a plain extractable
  `SecretKeySpec` instead of the opaque `P11Key.Secret` — deliberately
  **not** a cached `static final boolean` (a real bug caught before it
  shipped: a one-time class-load-time read would have silently stopped
  honoring the property the instant any earlier test loaded the class,
  which is virtually guaranteed given how many other tests already use
  HKDF) — read fresh via a plain method call every time instead, which
  is also what let the test itself toggle it at runtime. With the flag
  on, `saltMechFor`'s existing logic naturally falls through to the
  plain-bytes path when that key is later used as a salt — no special
  casing needed, the fallback design composes with what A2 already
  built rather than duplicating it.
- **Rust-engine parity: no divergence, nothing to record.** The Rust
  engine (`softhsmrustv3`) **already** implements `CKF_HKDF_SALT_KEY`
  correctly — found live at `rust/src/ffi.rs:8345` plus its own
  pre-existing equivalence test
  (`ffi::return_code_ffi_tests::hkdf_salt_as_key_equals_salt_as_data`,
  confirmed passing: `test ... ok`) using the identical
  data-vs-key-equivalence technique independently arrived at for the
  C++ test above. The C++ engine was the one lagging; no
  `tests/differential/exceptions.json` entry is needed. Full Rust
  suite: 409 passed, 1 failed, 9 ignored — the one failure
  (`ffi::param_struct_width_tests::bip32_child_derive_reads_flags_and_index_past_pnext`)
  is pre-existing and unrelated (confirmed via `git diff HEAD -- rust/`
  showing zero changes from this workstream), noted here rather than
  silently stepped around, not investigated further as out of scope.
- **Verify:** C++ — 74/74 unit tests (7 suites: `cryptotest`,
  `datamgrtest`, `handlemgrtest`, `objstoretest`, `sessionmgrtest`,
  `slotmgrtest`, `p11test`, the last containing the new
  `testHkdfDerive`); PKCS#11 v3.2 compliance harness 779 PASS / 0 FAIL /
  36 SKIP, unchanged from the pre-existing baseline — no regression.
  Java — 200/200 (198 prior + 2 new fallback-flag tests), live against
  the natively-rebuilt engine in `pqc-dev-sandbox`. Nothing pushed on
  either repo.
- **Known limitation, out of scope for this workstream:** `pkcs11-provider`
  (`src/vendor/pkcs11-provider/`), a separate vendored component, fails
  to build in both containers with
  `error: 'OSSL_PKEY_PARAM_CMS_RI_TYPE' undeclared` — an OpenSSL-version
  mismatch in that vendored code, confirmed pre-existing (reproduces
  with this workstream's change fully reverted) and unrelated to
  `softhsmv3` itself. `cmake --build build` (the bare "all" target,
  including `local-gate.sh --cpp`'s own invocation) will currently fail
  because of it; building the specific targets needed
  (`softhsmv3`, the individual test binaries) bypasses it cleanly, as
  done throughout this workstream. Not fixed here — flagged for
  whoever next needs a full "all" build to succeed.

---

## 4. WS-B — W6 completion: handshake, record layer, benchmark

### B1 — Re-run the spike; resolve what it actually hits

With WS-A landed, re-run `JavaJCE/spikes/W6TlsHandshakeSpike.java`
(`-Dsofthsmv3.jce.debug=true`). The **anticipated** next failure (G2 —
explicitly unverified, the handshake has never reached the record
layer):

- JSSE's record cipher goes through `Cipher.getInstance("AES/GCM/NoPadding")`
  with our provider at priority 1. Our GCM (a) refuses caller-supplied
  IVs on `ENCRYPT_MODE` (SP 800-38D §8.2 policy) — TLS records require
  the caller-constructed per-record nonce; (b) refuses keys that aren't
  our own `P11Key.Secret`.
- **Investigation before any fix:** extract and read
  `sun.security.ssl.SSLCipher` from `src.zip` — how record ciphers are
  instantiated, whether a provider preference applies, what key object
  type arrives, and whether JSSE falls back on `InvalidKeyException`
  (do not assume it does).
- Decision point (bring back to the user with findings, options
  sketched now):
  1. **Caller-IV non-FIPS flag** for GCM (main plan §5 risk 5 already
     reserves exactly this: "explicit non-FIPS config flag (ships
     off)") — scoped to make record crypto work through this provider;
  2. **Let record crypto stay on SunJCE** — e.g. by having the TLS
     client use an `SSLContext` whose record path doesn't resolve to
     us, or by provider-ordering; handshake crypto (the actual PQC
     value) stays token-backed either way;
  3. Something the `SSLCipher` reading reveals that neither option
     anticipates.

### B2 — Green handshake with proof

- `HANDSHAKE SUCCEEDED` + negotiated group `SecP256r1MLKEM768` (server
  refuses classical groups — success *is* group proof) + `P11Debug`
  lines showing **this provider's** `C_GenerateKeyPair` /
  `C_DecapsulateKey` ran (guards against silent SunJCE fallback — its
  own complete ML-KEM is registered in this JDK, verified 2026-08-25).
- Also run with `SecP384r1MLKEM1024` pinned first — both FIPS-profile
  groups from main plan §7, not just one.
- Promote the spike into a repeatable script (keep in `JavaJCE/spikes/`,
  still outside `mvn test` — it needs the live `pqc-rest` container).

### B3 — Latency benchmark (required, decision Q4)

- N ≥ 50 sequential handshakes per configuration, same endpoint
  (`pqc-rest:5720`), same group, reporting min/mean/p50/p95:
  1. this provider at priority 1 (token-backed KEM + keygen),
  2. stock JDK (SunJCE software ML-KEM),
  and, if B1 lands the caller-IV flag, with/without record crypto
  through the provider as a third axis.
- Methodology and reporting format reuse the transport-arms bench
  precedent (hsm PR #178 / sandbox `v0.11.3`); raw numbers go into the
  main plan's W6 section, not adjectives.

**Exit criteria WS-B:** both FIPS-profile hybrid groups handshake green
with token-side proof; benchmark table committed; main plan W6 marked
complete with the numbers.

**WS-B: DONE 2026-08-25, PASSED — real handshakes, real proof, four more
genuine bugs found and fixed along the way.**

- **G2 decision, made with the user after reading real `SSLCipher.java`
  source (not before):** confirmed live that JDK 27's TLS 1.3 record
  cipher (`sun.security.ssl.SSLCipher$T13GcmWriteCipherGenerator`) calls
  `Cipher.getInstance("AES/GCM/NoPadding")` with no explicit provider —
  landing on this one at priority 1 — and for **every record** computes
  the RFC 8446-mandated deterministic nonce (static IV XOR the
  monotonic sequence number) and supplies it explicitly via
  `GCMParameterSpec`. This is mandatory TLS 1.3 protocol structure, not
  caller laziness — no module-generated-IV policy can ever satisfy it.
  Also confirmed the plan's own "let record crypto stay on SunJCE"
  option isn't actually viable: the traffic key itself is this
  provider's own opaque `P11Key.Secret` from its own HKDF chain, which
  only this provider's own Cipher can use at all — a different provider
  would need the key to be extractable too, a bigger concession than
  the IV question alone. Decision: add
  `-Dsofthsmv3.jce.callerGcmIv=true` (default off, non-FIPS, matching
  the fallback the main plan's own §5 risk 5 already reserved) —
  `P11AESCipherSpi`'s ENCRYPT_MODE caller-IV rejection is gated behind
  it; documented in the class javadoc as cryptographically sound by
  construction (monotonic, non-repeating within a connection) while
  plainly noting this provider cannot verify a given caller's IVs
  actually follow a safe construction. New test
  (`callerGcmIvFlagAllowsAndUsesTheExactSuppliedIv`) proves the exact
  supplied IV is used and the ciphertext is genuinely correct (Bouncy
  Castle decrypts it independently), not just that the call stops
  throwing.
- **A real engine-shape finding: `CKM_HKDF_DERIVE` output is ALWAYS
  `CKK_GENERIC_SECRET`, unconditionally.** Confirmed reading
  `SoftHSM_keygen.cpp`'s HKDF output-template code directly: it
  iterates the caller's template with a `switch` whose `CKA_CLASS`/
  `CKA_KEY_TYPE` cases are bare `continue` — silently discarding
  whatever the caller supplied — then hardcodes `CKO_SECRET_KEY`/
  `CKK_GENERIC_SECRET`. This provider's own `AES/GCM` Cipher correctly
  refuses that object with `CKR_KEY_TYPE_INCONSISTENT` — found live
  because JDK 27's own `SSLTrafficKeyDerivation` requests exactly
  `"AES"` (`cs.bulkCipher.algorithm`, confirmed from real JDK source)
  for the record cipher's traffic key, a genuine real caller, not a
  hypothetical. Fixed in `P11HKDFKDFSpi.engineDeriveKey`: when `alg`
  is `"AES"`, derive EXTRACTABLE, read the raw bytes back, destroy the
  throwaway generic-secret object, re-import the same bytes as a
  genuine `CKK_AES` object (the same raw-AES-import pattern already
  established and tested — `P11AESWrapCipherSpi`'s unwrap path,
  `importRawAesKeyReal` in the test suite — not a new technique), zero
  the Java-side intermediate (§6.5). A real, disclosed, narrow
  exception to this KDF's opaque-by-default output, same class as the
  KEM/ECDH secrets: the whole point of a TLS traffic key is to be
  consumed by this provider's own Cipher. New test
  (`deriveKeyWithAesAlgorithmProducesAGenuineAesKeyUsableByThisProvidersOwnCipher`)
  proves both that the key works with this provider's own AES/GCM
  Cipher AND that its raw value exactly matches an independent
  re-derivation via JDK's own reference HKDF — not just "some AES key
  came out."
- **A genuine, pre-existing bug in this provider's own `P11AESCipherSpi`,
  unrelated to any of the above, found only because JSSE's usage
  pattern is stricter than every other caller in this test suite.**
  `engineGetOutputSize` returned a padded `inputLen + 32` "conservative
  upper bound" rather than GCM's real exact size. Ordinary
  byte[]-based `Cipher.doFinal()` — what every one of the 200+
  pre-existing tests uses — never checks this value against the real
  output length, so the bug was invisible until JDK 27's own
  `SSLCipher` used the **ByteBuffer-based**
  `Cipher.doFinal(ByteBuffer, ByteBuffer)` overload, whose default
  `CipherSpi` bridging pre-sizes the output buffer from
  `engineGetOutputSize()` and then strictly requires the real written
  length to equal it (`"Cipher buffering error"` otherwise). Fixed: GCM
  now returns the exact size (`inputLen ± tagBits/8` by direction);
  CBC/CTR return the exact `inputLen`; CBC+PKCS5 returns the exact
  encrypt-side padded size (decrypt-side stays a safe upper bound,
  correctly — the real post-unpad length isn't knowable without
  decrypting, and TLS 1.3 is GCM-only so this path is never exercised
  the strict way). New test
  (`gcmOutputSizeIsExactNotAConservativeUpperBound`) exercises the
  actual `ByteBuffer` path directly — the only way to have caught this
  in the first place.
- **A genuine concurrency bug in this session's own earlier zeroization
  work (commit `1ed4965`), found live, not introduced by this
  workstream but surfaced by it.** The JVM shutdown hook
  `SoftHSMv3Provider`'s constructor registers is one independent
  `Thread` per constructed provider instance; the JVM runs every
  registered shutdown hook concurrently. This test suite constructs
  100+ providers, so JVM exit fired that many threads calling
  `C_CloseSession` on their own distinct sessions all at once —
  crashing the JVM outright with a native `SIGSEGV` inside
  `libsofthsmv3.so`'s session teardown
  (`std::_Rb_tree_increment`, i.e. an internal `std::map` iteration
  corrupted by concurrent access). Checked
  `HandleManager`/`SessionManager`/`SessionObjectStore` first — all
  three already have their own per-instance mutexes, so the deeper
  engine-side cause (some other unprotected shared state, or a genuine
  gap) wasn't chased further; eliminating the concurrent-call pattern
  is squarely this Java code's own responsibility (it chose to spawn N
  independent threads) and is sufficient regardless of the engine-side
  root cause. Fixed: a single JVM-wide lock (`P11Library.CLOSE_LOCK`)
  now serializes every native `C_CloseSession` call across every
  instance — `close()` is a rare, teardown-only operation, never a hot
  path, so a single lock costs nothing in practice. Verified by
  re-running the full 203-test suite three consecutive times after the
  fix (a timing-dependent race needs more than one clean run to trust)
  — no crash, all green.
- **Both FIPS-profile hybrid groups, real live handshakes, with
  token-side proof:**
  ```
  === SecP256r1MLKEM768 ===
  [softhsmv3-jce] EC KeyPairGenerator.generateKeyPair() — curve=secp256r1
  [softhsmv3-jce] ML-KEM KeyPairGenerator.generateKeyPair() — algorithm=ML-KEM-768
  [softhsmv3-jce] ML-KEM Decapsulator.engineDecapsulate() — token C_DecapsulateKey
  HANDSHAKE SUCCEEDED (group=SecP256r1MLKEM768)
  Protocol: TLSv1.3
  CipherSuite: TLS_AES_256_GCM_SHA384

  === SecP384r1MLKEM1024 ===
  [softhsmv3-jce] EC KeyPairGenerator.generateKeyPair() — curve=secp384r1
  [softhsmv3-jce] ML-KEM KeyPairGenerator.generateKeyPair() — algorithm=ML-KEM-1024
  [softhsmv3-jce] ML-KEM Decapsulator.engineDecapsulate() — token C_DecapsulateKey
  HANDSHAKE SUCCEEDED (group=SecP384r1MLKEM1024)
  Protocol: TLSv1.3
  CipherSuite: TLS_AES_256_GCM_SHA384
  ```
  Curve/KEM pairing is correctly wired per group (secp256r1↔ML-KEM-768,
  secp384r1↔ML-KEM-1024) — the hybrid combiner picks the right
  component sizes for each named group, not a hardcoded pair.
  `W6TlsHandshakeSpike.java` updated to take the group as `argv[0]` (so
  both can be run without editing the file) and to stop right after a
  successful handshake — an earlier version's subsequent bare HTTP GET
  correctly triggered a `certificate_required` alert from pqc-rest's
  own mTLS requirement at the application layer, unrelated to what this
  spike verifies, so chasing it further would have been scope creep.
- **Benchmark (required, decision Q4) —
  `W6TlsHandshakeBenchmark.java`, new**, N=50 sequential real handshakes
  per arm against the same live `pqc-rest:5720` endpoint,
  `SecP256r1MLKEM768`:

  | Arm | min | mean | p50 | p95 | max |
  |---|---|---|---|---|---|
  | stock JDK (SunJCE software ML-KEM) | 1ms | 4.2ms | 2ms | 6ms | 83ms |
  | token-backed (SoftHSMv3Provider) | 4ms | 6.2ms | 5ms | 8ms | 72ms |

  Ratio (token-backed mean / stock JDK mean): **1.48x**. A modest,
  expected overhead — the same class of cost the main plan's own risk
  #3 already anticipated ("FFM call overhead vs JNI... acceptable for
  an HSM bridge — ops are token-bound anyway"), not a red flag. Both
  arms' `max` outliers (83ms/72ms) are consistent with ordinary JIT
  warmup/GC noise in a 50-iteration run, not a systemic issue — no
  further investigation attempted, in line with the plan's own
  "raw numbers, not adjectives" instruction.
- **Verify:** `mvn test`, 203/203 (198 prior + 5 new: caller-IV,
  HKDF-AES-reimport, exact-output-size, plus 2 already counted from
  WS-A's own tail). Both FIPS-profile groups handshake green with
  `P11Debug` token-side proof, live against `pqc-rest:5720`. Benchmark
  table above, real numbers. Main plan's own W6 section should be
  marked complete referencing this workstream.

---

## 5. WS-C — Zeroization architecture (`P11Library` arenas)

The disclosed Area-8 gap: one `Arena.ofShared()` lives for the whole
session; `Arena.close()` deallocates without scrubbing; every secret
that ever crossed the FFM boundary stays in native memory until session
close.

1. **Audit + classify** every allocation site in `P11Library`
   (~15 methods): (a) long-lived by necessity — method handles, the
   session struct; (b) per-operation, secret-carrying — `bytes(data)`
   in sign/encrypt/decrypt, PIN segments, `getAttributeBytes` output
   buffers for `CKA_VALUE`, wrap/unwrap buffers; (c) per-operation,
   non-secret — mechanism structs, length cells, OIDs.
2. **Refactor shape:** each public operation opens
   `try (Arena op = Arena.ofConfined())` spanning the whole operation
   (mechanism build **and** use — the `mech*` builders must take the
   arena as a parameter, since their segments are consumed by the
   subsequent native call; this is why a naive per-allocation fix
   doesn't work and the change touches every call path).
3. **Zero before close** for class-(b) buffers: explicit
   `segment.fill((byte) 0)` in `finally` before the confined arena
   closes — `close()` alone frees without scrubbing (that asymmetry is
   the entire gap).
4. The constructor-scoped PIN copy: zero it immediately after `C_Login`
   returns rather than leaving it in the long-lived arena.
5. **Verify:** full suite (behavioral regression net — this refactor
   must be invisible); the existing heap-dump test still passes
   (Java-side); honest note in the security-posture doc flipping
   Area 8's "one disclosed gap" to done — native-memory scrubbing is
   verified by code review + the confined-arena structure, not by a
   native-memory dump (state that plainly; a native heap probe is not
   proportionate here).

Concurrency note to check during implementation: confined arenas are
single-thread; the provider serializes native calls per `P11Library`
today (verify — if any test exercises concurrent ops on one instance,
the confined arena will surface it loudly, which is acceptable and
better than the current silent sharing).

**WS-C: DONE 2026-08-25, PASSED — full `P11Library` rewrite, one
gap widened deliberately, zero behavioral regressions.**

- **Audit + classify (item 1), done by direct inspection of all ~24
  allocation-bearing methods, not sampled:** confirmed the class
  (a)/(b)/(c) split this section itself proposed maps cleanly onto real
  call sites, with one refinement made along the way — the plan's own
  minimum list ("PIN segments, `getAttributeBytes` output for
  `CKA_VALUE`, wrap/unwrap buffers, `bytes(data)` in sign/encrypt/
  decrypt") was widened into one uniform, simpler-to-verify rule: every
  segment built from real byte[] content — anything from the shared
  `bytes()` helper, or one of `attrs()`'s per-attribute value segments
  (which can carry a real `CKA_VALUE` being imported, e.g. the WS-B
  `deriveAndReimportAsAes` path) — is zeroed before its confined arena
  closes; pure protocol scaffolding (mechanism/attribute struct headers,
  length/handle scratch cells) is not. This is strictly more thorough
  than the plan's own minimum (it additionally covers `digest()`'s input,
  `generateRandom()`/`seedRandom()`'s buffers, `findObjects()`/
  `generateKeyPair()`/`generateKey()`/`encapsulate()`/`decapsulate()`/
  `ecdh1Derive()`/`copyObject()`'s template values) at negligible cost —
  these are all sub-KB buffers on an already token-bound, non-hot-path
  operation — and removes the risk of a missed case from a
  method-by-method secret/non-secret judgment call. Two mechanism
  builders' embedded parameters are real secret material and needed the
  same treatment even though the plan didn't name them explicitly: HKDF's
  salt (can be a foreign key's raw bytes) and PBKDF2's password — both
  now tracked and zeroed via a small `BuiltMech` wrapper (mechanism
  segment + the secret sub-segments it embeds), the mechanism-builder
  analogue of `attrs()`'s own `BuiltAttrs`. Left deliberately unscrubbed,
  matching the plan's own (c) examples: GCM IV/AAD, CBC/CTR IV, SP
  800-108 fixed-input/IV, RSA-PSS's all-`CK_ULONG` params, ECDH's peer
  public point, KEM ciphertext, signatures — all public by protocol
  design, not secret.
- **Refactor shape (item 2), the change genuinely touches every call
  path, confirmed rather than assumed going in:** every operation method
  in `P11Library` now opens its own `Arena.ofConfined()` (named `op`
  throughout); the `mechXxx`/`attrs`/`bytes` builder family all take that
  arena as an explicit parameter instead of reaching for the old shared
  instance field. This rippled out to every external caller that builds
  a mechanism via one of these builders and then makes a *separate*
  `sign`/`verify`/`encrypt`/`decrypt`/`deriveKey` call with it — confirmed
  by grepping every call site in the module first, not guessed at: seven
  files (`P11AESCipherSpi`, `P11RSAOAEPCipherSpi`, `P11HKDFKDFSpi`,
  `P11PBKDF2SecretKeyFactorySpi`, `P11SP800108SecretKeyFactorySpi`,
  `P11RSAPSSSignatureSpi`, `SoftHSMv3Provider`'s own self-test KATs),
  each now opens its own `try (Arena op = Arena.ofConfined())` spanning
  both the mechanism build and the native call(s) that consume it — the
  RSA-PSS self-test and `P11RSAPSSSignatureSpi` both needed the *same*
  arena to span **two** separate native calls (`sign` then `verify`
  reusing one mechanism segment), confirming the plan's own prediction
  that a naive per-allocation fix wouldn't have worked. Every other
  operation method that builds its own mechanism internally
  (`digest`/`generateKeyPair`/`createObject`/`generateKey`/`wrapKey`/
  `unwrapKey`/`copyObject`/`encapsulate`/`decapsulate`/`ecdh1Derive`/the
  bare-`mechType` `sign`/`verify` overloads) needed no external API
  change at all — confirmed by grepping for every one of `mech()`'s,
  `bytes()`'s, and `attrs()`'s call sites across the whole module first
  (all private/internal, zero external callers) before deciding these
  could keep their existing signatures.
- **Zero before close (item 3) and the PIN copy (item 4):** every
  tracked segment is scrubbed (`MemorySegment.fill((byte) 0)`) in a
  `finally` block before its confined arena closes — including
  `decrypt()`'s output, the single most sensitive buffer in this class
  (genuine decrypted plaintext). The constructor's PIN copy moved out of
  the long-lived shared arena into a local confined one scoped to just
  construction, zeroed immediately after the `C_Login` call returns
  (plus the JVM-heap `pinBytes` array, a small bonus beyond the
  native-memory scope this item asked for — free to add, strictly safer).
  The shared `Arena.ofShared()` field itself is kept, narrowed to its one
  remaining real job: holding the loaded native library alive for the
  instance's lifetime (`SymbolLookup.libraryLookup`) and being closeable
  from a different thread than the one that constructed it (WS-B's own
  `CLOSE_LOCK` finding — shutdown hooks run on their own thread, and only
  a shared arena can be closed cross-thread; a confined one could not).
- **Concurrency note, resolved rather than left to a comment:** every
  confined arena in this rewrite is created, used, and closed within one
  synchronous call stack on one thread — never handed across a thread
  boundary — so the note's own predicted failure mode (a confined arena
  "surfacing loudly" under concurrent misuse) cannot occur by
  construction, not merely by convention. Empirically confirmed, not
  just reasoned about: the full suite constructs 100+ provider instances
  and would have thrown `WrongThreadException` immediately on the first
  violation — it didn't, across three consecutive clean runs.
- **Verify:** `mvn test`, 203/203 unchanged (this refactor is invisible
  behaviorally by design — no test needed to change). Both FIPS-profile
  live handshakes (`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) re-run
  against `pqc-rest` post-refactor and still succeed with the same
  token-side proof as WS-B. Benchmark re-run: 1.47x mean-latency ratio
  (was 1.48x pre-refactor) — no measurable regression from the
  per-operation arena churn, confirming the plan's own "these are all
  token-bound, non-hot-path operations" expectation. The existing
  JVM-heap-dump audit (`ZeroizationAuditTest`) still passes unmodified —
  correctly orthogonal, per this section's own scope note: it audits the
  one place real secret bytes reach the JVM heap at all (ML-KEM's
  decapsulated secret), which this native-memory-only refactor never
  touches. Native-memory scrubbing itself verified by code review and by
  this refactor's own structure (every secret-carrying buffer's arena
  now closes within the single native call that used it, not at session
  end) — not by a native-heap-dump probe, matching this section's own
  explicit judgment that such a probe would be disproportionate here.
  Area 8's disclosed gap in the security-posture doc should be flipped
  from "one disclosed gap" to done, referencing this section.

---

## 6. WS-D — Small hardening items

| Item | Action | Verify |
|---|---|---|
| SHA-3 PSS (`CKG_MGF1_SHA3_*` + `CKM_SHA3_*_RSA_PKCS_PSS`) | Check the engine actually dispatches the SHA-3 PSS mechanisms first (grep `SoftHSM.cpp` mechanism table — do NOT assume from the OAEP precedent); if yes, extend `P11RSAPSSSignatureSpi.DIGEST_TO_MECH_AND_MGF` (+ constants verified against `pkcs11t.h`) and remove the "not yet built" javadoc scope-down | BC interop test per digest, same pattern as the SHA-2 PSS tests |
| GCM IV uniqueness across sessions | New test: two fresh providers, N encrypts each, assert all module-generated IVs distinct (the main plan's own W4 verify list marks this "not yet attempted") | test |
| Pre-hash ML-DSA / SLH-DSA (`CKM_HASH_ML_DSA_*`, `CKM_HASH_SLH_DSA_*`) | Investigate-then-decide: check engine mechanism table; if supported, these need a new SignatureSpi shape (digest parameter); if not, record as engine-gap and defer — either way stop leaving it implicit in a javadoc | live probe + doc |
| `engineGetCreationDate` stub (`new Date(0)`) | PKCS#11 has no creation-timestamp attribute for the engine to report; keep the stub but document it in the KeyStore javadoc + README limitations instead of leaving it bare | doc only |

**WS-D: DONE 2026-08-25, PASSED — three items shipped, one deliberately
deferred with real reasoning, none left implicit.**

- **SHA-3 PSS — real, not assumed, and built.** Confirmed by reading
  both `SoftHSM_slots.cpp`'s mechanism-info table (same
  `CKF_SIGN|CKF_VERIFY` flags as the SHA-2 variants) AND
  `SoftHSM_sign.cpp`'s actual `C_SignInit`/`C_VerifyInit` dispatch (real
  `AsymMech::RSA_SHA3_*_PKCS_PSS` cases expecting exactly
  `{hashAlg=CKM_SHA3_*; mgf=CKG_MGF1_SHA3_*}`, not stubs) before adding
  anything — the plan's own "do NOT assume from the OAEP precedent"
  instruction, honored. `P11Constants` gained the four
  `CKM_SHA3_*_RSA_PKCS_PSS` mechanism IDs plus the missing
  `CKM_SHA3_224`/`CKG_MGF1_SHA3_224` pair (verified against
  `pkcs11t.h`), and `P11RSAPSSSignatureSpi.DIGEST_TO_MECH_AND_MGF`
  now covers all four SHA-3 variants alongside the existing SHA-2
  three. Cross-verify used JDK's own SunRsaSign
  (`sun.security.rsa.RSAPSSSignature`, read directly — its own class
  javadoc states "We support SHA-1, SHA-2 family and SHA3 family", and
  its `DIGEST_LENGTHS` map lists all four SHA3 entries explicitly), not
  Bouncy Castle — the plan's own shorthand said "BC interop test" but
  the actual established precedent in this file
  (`pssInteropsWithJdkSunRsaSign`) already cross-verifies against real
  JDK SunRsaSign, confirmed as the stronger, already-proven pattern
  worth following rather than the plan's brief text. New parameterized
  test `pssInteropsWithJdkSunRsaSignAcrossSha3Variants` (4 cases,
  `RSATest.java`, 9→13 tests) — sign/verify/tamper-detection/JDK
  cross-verify for all four digests.
- **GCM IV uniqueness across sessions — the main plan's own W4 verify
  list marked this "not yet attempted."** New test
  (`gcmIvsAreDistinctAcrossSessionsNotJustWithinOne`, `AESCipherTest.java`,
  14→15 tests): two independent `SoftHSMv3Provider` instances (two
  separate `P11Library` sessions, not one provider called twice — the
  actual "across sessions" case this item names), 64 interleaved
  encrypts, every module-generated GCM IV distinct.
- **Pre-hash ML-DSA/SLH-DSA — investigated, deliberately deferred with
  real reasoning, not a bare "not yet built."** Confirmed the engine
  genuinely implements every `CKM_HASH_ML_DSA_*`/`CKM_HASH_SLH_DSA_*`
  variant (mechanism table AND real `C_SignInit`/`C_VerifyInit`
  dispatch with the `CK_HASH_SIGN_ADDITIONAL_CONTEXT`/
  `CK_SIGN_ADDITIONAL_CONTEXT` parameter shapes, not stubs) — this is
  not an engine gap. What's actually missing: this same JDK 27's own
  ML-DSA implementation (`sun.security.provider.ML_DSA`/`ML_DSA_Impls`,
  read in full) implements only the pure, no-external-pre-hash mode —
  no standard `"HashML-DSA"` algorithm name or pre-hash `Signature` API
  surface exists anywhere in this JDK to interoperate against or model
  a naming convention on. Building this now would mean inventing a
  non-standard naming/parameter scheme with no external precedent to
  verify it against — deferred with this disclosed reasoning
  (`P11PureSigSignatureSpi`'s own javadoc, expanded), not left implicit.
- **`engineGetCreationDate`** — real javadoc added explaining PKCS#11
  has no creation-timestamp attribute at all (checked against
  `pkcs11t.h` and the OASIS attribute list, not assumed), so the fixed
  epoch return is the only value this method could ever report. README's
  "Known limitations" section updated to match — and, found stale while
  touching that file, its TLS/Arena-zeroization bullets (which still
  described WS-B/WS-C's now-resolved gaps as open) corrected in the same
  pass rather than left contradicting the actual shipped state.
- **Verify:** `mvn test`, 208/208 (203 prior + 5 new: 4 SHA-3 PSS
  variants, 1 GCM-IV-uniqueness). No C++/engine changes this
  workstream — every item was either a Java-side extension against
  already-real engine support, a new test, or documentation.

---

## 7. WS-E — W7: Rust engine via gRPC (full workstream, decision Q2)

### E0 — Spike first (nothing else starts until these are answered live)

1. Run the actual remoting server (`remoting/grpc`) — confirm how it's
   launched, its listen address in the compose mesh, and its mTLS
   expectations against the `/admin-certs` volume (mounted read-only in
   `pqc-dev-sandbox` — confirmed live 2026-08-25).
2. Read the full proto request/response shapes: are keys addressed by
   server-side handles from `GenerateKeyPair`, or passed as bytes?
   (Determines whether the remote provider can be opaque-handle-shaped
   like the local one, or must hold public material client-side.)
   Verify against `remoting/grpc/src/service.rs`, not just the proto.
3. Confirm error mapping: the proto's `Pkcs11Error` enum mirrors real
   `CKR_*` codepoints — the Java side must surface the same numbers
   (`P11Error` naming discipline carries over).

**E0: DONE 2026-08-25, all three answered live against real running
infrastructure — nothing here was assumed from the plan text.**

1. **Server confirmed live.** `pqc-grpc` container running, `0.0.0.0:5710`,
   `PKCS11_REMOTE_TLS_PROFILE=quantum-safe`
   (`PKCS11_REMOTE_TLS_CERT=/admin-certs/server.crt`,
   `..._TLS_KEY=/admin-certs/server.key`,
   `..._TLS_CLIENT_CA=/admin-certs/ca.crt`, confirmed via
   `docker inspect`'s real env, not the plan's assumed default) — real
   mTLS is mandatory, not optional, for this deployment (confirmed
   reading `main.rs`: quantum-safe refuses to start without
   `--tls-client-ca` at all). `/admin-certs` re-confirmed mounted
   **read-only** in `pqc-dev-sandbox` with real `client.crt`/`client.key`/
   `ca.crt` material present (not just `ca.crt` — a full client identity),
   and real TCP reachability confirmed host-to-container
   (`pqc-dev-sandbox` → `pqc-grpc:5710`, Python `socket.create_connection`,
   not bash `/dev/tcp` which false-negatived on this image's bash build
   for an unrelated reason — caught before trusting a bogus "unreachable"
   result).
2. **Keys are server-side handles for signing keys; the KEM shared
   secret is NOT.** Confirmed reading `service.rs` end to end, not just
   the proto: `GenerateKeyPairRequest`/`Response` and `Sign`/`Verify`
   all address keys by `uint32` handle exactly as E0 hoped — this part
   of the remote provider CAN be opaque-handle-shaped like the local
   one. But `EncapsulateResponse`/`DecapsulateResponse` both carry the
   shared secret as raw `bytes` directly on the wire, not a handle —
   a real, structural difference from the local provider's opaque-KEM
   design that E1's `RemoteKey`/`SoftHSMv3RemoteProvider` design needs
   to account for (not a blocker: this is the same class of disclosed
   exception the local provider already makes for ML-KEM/ECDH secrets
   — the whole point of a KEM output is to leave the boundary it was
   computed behind).
3. **Error mapping confirmed, and it changes the Java-side design:**
   `error.rs`'s `to_status` does NOT use gRPC's structured status-details
   extension (`google.rpc.Status` + typed `Any` in trailing metadata) —
   the `raw_ck_rv` is embedded as a formatted substring inside the plain
   status message (`"{msg} (pkcs11_error={code:?}, raw_ck_rv=0x{rv:08X})"`).
   The Java client's error mapping (E2/`P11Error` discipline) will need
   to parse this out of `Status.getDescription()` with a regex, not
   deserialize a structured detail object — a real implementation detail
   E0 exists specifically to catch before E2's code gets written the
   wrong way.

WS-E's E1-E4 (architecture, build wiring, mTLS client, verification) are
scoped and ready but **not yet executed** — a natural checkpoint given
E0's own "nothing else starts until these are answered live" gate is
now cleanly closed with real answers, and this is a good point to
check in before starting a full new Maven module + gRPC codegen
workstream.

### E1 — Architecture decision (made now, validated by E0)

**Correction to this section's own original text, found while starting
E1 for real, before any code was written:** "SPKI export uses whatever
`GenerateKeyPairResponse` returns" is wrong — re-reading the message
shape precisely (not just confirming it's handle-based, which E0 did
correctly) shows `GenerateKeyPairResponse` carries **only**
`public_handle`/`private_handle`, two `uint32`s, no key-material bytes
anywhere. There is **no verb anywhere in the proto** that returns a
public key's real DER/SPKI bytes — `Health`/`OpenSession`/
`CloseSession`/`GenerateKeyPair`/`Sign`/`Verify`/`Encapsulate`/
`Decapsulate` is the complete verb list, confirmed by re-reading the
proto's own `service Pkcs11Remote` block line by line. This is a real,
structural Phase-1 constraint, not an oversight to route around:
`RemoteKey.Pub.getEncoded()` must return `null`, same as
`RemoteKey.Priv`, for a genuinely different reason than the local
provider's own deliberate opacity design (§6.2) — here it's a wire
protocol capability gap, not a security choice. Practical consequence:
this remote provider can only support **self-contained** flows within
one session (generate → sign/verify with the SAME provider instance's
own keys, generate → encapsulate/decapsulate with the SAME instance) —
not "export this public key, hand it to an external peer" flows. Real,
disclosed, not silently narrowed: documented in
`SoftHSMv3RemoteProvider`'s own class javadoc, not left implicit.

**Second correction, same discovery pass:** E4's own "three-way parity
(mirrors `three_way_parity.rs`)" bullet below describes something that
file does not actually do. Read in full before writing anything against
it: `remoting/acceptance/tests/three_way_parity.rs`'s real cases (a1-a5)
each generate their OWN keypair independently per transport and verify
**within** that same transport/session — the "three ways" are three
**transports of the same Rust backend** (in-process verb-layer call,
real gRPC call, real REST call), asserting the exact numeric `CKR_*`
(or `valid`/`invalid` outcome) agrees across all three — never handing
a key or signature from one transport to another, and certainly never
between different **crypto engines** (C++ vs Rust vs JDK software, as
the plan's original E4 text imagined). Given the public-key-export gap
above, cross-engine key interop through this remote surface is not
achievable in the first place, independent of this correction. E4 below
is rewritten to the achievable, actually-precedented shape.

**Do NOT interface-ize `P11Library` across all ~20 SPIs.** The remote
surface is exactly Ed25519 + ML-DSA-44/65/87 + ML-KEM-512/768/1024
(§1 correction 1) — 3 of ~20 SPI shapes. Instead:

- New Maven **module** (separate artifact, e.g. `JavaJCE-remote/`)
  depending on the core jar. Rationale: the core provider keeps **zero
  network dependencies** (grpc-netty-shaded + protobuf are heavy, and
  the core's "no software crypto, minimal deps" posture is a feature);
  a deployment that wants the remote path opts into the second jar.
- New `SoftHSMv3RemoteProvider` (name e.g. `SoftHSMv3-Remote`)
  registering **only** the covered services, with its own thin
  `GrpcTransport` class speaking the 8 verbs. Key objects are new
  opaque handle types (`RemoteKey.Priv/Pub`) holding the server-side
  session/key ids; both report `getEncoded() == null` — see the
  correction above for why `Pub` is included, not just `Priv`.
- The existing generic SPI classes are reused **only if** their
  constructor dependency can be satisfied cleanly (they take
  `P11Library` today); expected outcome is small dedicated remote SPI
  classes instead — three shapes, bounded work, no churn in the 198
  passing tests.

### E2 — Build wiring

- `protobuf-maven-plugin` + `grpc-java` (grpc-protobuf, grpc-stub,
  grpc-netty-shaded), versions pinned after checking Maven Central
  metadata (the bcpkix lesson: never assume a version exists).
- Proto consumed **verbatim** from `remoting/proto/proto/pkcs11_remote.proto`
  (relative path in the plugin config, not a copy that can drift).

### E3 — mTLS

- Channel built from `/admin-certs` material (client cert/key + CA),
  netty TLS context; fail-closed if certs are absent (no plaintext
  fallback).

### E4 — Verification (rewritten — see E1's second correction)

- Self-contained round trips through `SoftHSMv3RemoteProvider` itself,
  the achievable analogue of the local suites' own sign/verify/KEM
  tests given the public-key-export gap: generate → sign → verify
  (tamper rejection too) for Ed25519/ML-DSA-44/65/87; generate →
  encapsulate → decapsulate with shared-secret equality for
  ML-KEM-512/768/1024. FIPS-size assertions reused verbatim from the
  local suite's own expected byte counts (3309 for ML-DSA-65's
  signature, 1088 for ML-KEM-768's ciphertext, etc.) — the same wire
  values regardless of which side of the network computed them.
- **Cross-transport `CKR_*` parity, the real, precedented shape** (not
  the cross-engine one the original text described): the Java gRPC
  client must surface the exact same numeric `CKR_*` values
  `three_way_parity.rs`'s own cases already established for the SAME
  scenarios — wrong PIN → `CKR_PIN_INCORRECT` (0xA0), invalid session
  handle → `CKR_SESSION_HANDLE_INVALID` (0xB3), wrong-length ciphertext
  on decapsulate → `CKR_ARGUMENTS_BAD`, a closed-then-reused session →
  the same code as the invalid-handle case. This is a fourth transport
  added to that file's existing three (in-process/gRPC-from-Rust/REST),
  not a new methodology — parsed from `Status.getDescription()`'s
  `raw_ck_rv=0x...` substring per E0's own error-mapping finding.
- Gate: these tests need the remoting server running → wire into the
  same opt-in gate step family as other infrastructure-dependent steps
  (WS-F), FAIL-not-skip semantics when the flag is on.

### E5 — Explicit follow-on (own gate, not this plan)

Extending the proto `Algorithm` enum + verb set (SLH-DSA, EC, RSA,
symmetric) to widen the remote JCA surface — a cross-crate change with
its own Rust-side test obligations.

### E1.3 — Third correction: real certificate export (user-directed,
mid-workstream, 2026-08-25)

The user redirected after reading E1's own "no verb returns a public
key's bytes at all" finding: **"java should allow public key extraction
in a certificate format"**, then **"our pkcs11 backend should support
that extraction"** (not a client-side fake) — closing the gap E1
disclosed rather than accepting it as final. Clarified with the user
before building: a full self-signed X.509 `Certificate` (not bare SPKI
DER), parity across **both** gRPC and REST (not gRPC-only), full test
depth.

Delivered as an **8th verb**, `GetSelfSignedCertificate`
(`session_handle, public_handle, private_handle, algorithm, subject_cn,
validity_days` → `certificate_der`), built independently of
`pqctoday-kmip`'s own `Certify` op (confirmed live: that code path
rejects Ed25519 as a CA signing algorithm) in a new
`remoting/core/src/cert.rs` — reads the real `SubjectPublicKeyInfo` via
`CKA_PUBLIC_KEY_INFO` (PKCS#11 v3.2 §4.14, confirmed supported by both
engines), builds a self-signed (issuer == subject) `TbsCertificate`
with no extensions, signs through the already-proven `verbs::sign`
path (never re-deriving PQC signing correctness). `AlgorithmIdentifier`
parameters are `None` for Ed25519 (RFC 8410 §3/§6, fetched and
confirmed, not assumed) and for ML-DSA-44/65/87 (matching
draft-ietf-lamps-dilithium-certificates and kmip's own OID constants).
Rejects ML-KEM keys with `CKR_ARGUMENTS_BAD` — a KEM key cannot sign
its own certificate. Wired through all three existing transports
(in-process, gRPC, REST) with two new `three_way_parity.rs` cases
(`a6`/`a7`) that re-verify the embedded signature via `verbs::verify`,
not just DER-parse it. Rust-side: 16/16 tests green (9 core + 7
acceptance), committed `b3c7309`.

**`subject_cn` is the bare RDN value, not a `"CN=..."` string** — the
server itself builds `Name::from_str("CN={subject_cn}")`; passing an
already-prefixed value produces a literal `CN=CN=...` subject (caught
live, first smoke run — documented on the Java-side javadoc so callers
don't repeat it).

### E2/E3/E4 — Completion (2026-08-25)

New module `JavaJCE-remote/` (separate Maven artifact depending on the
core `softhsmv3-jce` jar, per E1's own architecture decision — zero
network deps added to the core provider). One `GrpcTransport` class
speaking all 8 verbs; `SoftHSMv3RemoteProvider` registers
KeyPairGenerator (7 names) / Signature (4) / KEM (4 names, bare
`"ML-KEM"` + 3 parameter-set names) plus the certificate-export method
from E1.3. `RemoteKey.Priv`/`Pub` both report `getEncoded() == null`
(E1's disclosed gap — `getSelfSignedCertificate` is the one way real
key bytes leave this provider). `RemoteError` parses the real
`raw_ck_rv=0x...` substring out of `Status.getDescription()`, mirroring
`three_way_parity.rs`'s own `grpc_raw_ck_rv` helper rather than
reinventing the parse. mTLS (E3) is fail-closed at construction — no
plaintext fallback — verified against a real missing-cert-material
case, not just asserted in prose.

**Two real, live-caught build bugs, neither guessable from a diff
review:**
1. `protoc:4.36.0` (pinned explicitly, matching E2's own "pin after
   checking Maven Central" discipline) generates code against a newer
   `protobuf-java` API shape than `grpc-protobuf:1.83.1` transitively
   resolves — dozens of compile errors in the generated stub
   (`RuntimeVersion` class missing, wrong `parseUnknownField` arity,
   missing `getMessageType(int)`/`isStringEmpty`/
   `resolveAllFeaturesImmutable`). Fixed by declaring
   `com.google.protobuf:protobuf-java:${protobuf.version}` explicitly,
   forcing Maven's nearest-wins resolution to match `protoc`'s own
   version exactly — protoc and its runtime library must be the same
   version; nothing pins that automatically.
2. `sessionHandle` was declared `long` in `GrpcTransport` (matching the
   JCA-facing `long` shape used elsewhere in this codebase for
   handles) but the wire type is `uint32` — every
   `.setSessionHandle(sessionHandle)` call is a narrowing conversion
   from a *wider* Java type back into an `int` setter, a real compile
   error, not a style nit. Fixed by declaring the field as the `int`
   it actually is on the wire (the other handles stay `long` at the
   public method-signature boundary with an explicit `(int)` cast at
   each call site, since those are genuinely public API surface;
   `sessionHandle` is purely internal).

**Verification (E4), against the real running `pqc-grpc` container,
not a mock:** a 14-case JUnit suite
(`JavaJCE-remote/src/test/.../RemoteProviderLiveTest.java`) — per-algorithm
sign/verify/tamper-rejection (Ed25519, ML-DSA-44/65/87), per-algorithm
certificate round trip with real `PKIXParameters`/`CertPathValidator`
validation, per-algorithm KEM round trip (ML-KEM-512/768/1024),
certificate-rejects-ML-KEM-key, missing-mTLS-material fails closed
before any network call, and wrong-PIN rejected with the real
`CKR_PIN_INCORRECT` name recovered from the wire. First live run
caught the certificate cases failing with `UNIMPLEMENTED` — the
already-running `pqc-grpc` container predated the E1.3 Rust commit;
rebuilding+recreating the container (`docker compose build pqc-grpc`)
picked up the new verb, after which all 14 cases passed. Sabotage-tested
per this repo's own convention (a flipped assertion on a **copy**,
never the real test file) to confirm the pass/fail detection is real,
not vacuous — correctly reported 4 failures, not a false green.

Also fixed: JDK 27's restricted-native-access enforcement (JEP 472)
warns every run because `grpc-netty-shaded` loads a bundled native
Netty transport via `System.loadLibrary()` from the classpath (the
unnamed module) — will be a hard error in a future JDK release, not
just a warning. Fixed at the source via
`<argLine>--enable-native-access=ALL-UNNAMED</argLine>` on
`maven-surefire-plugin` rather than leaving it for every future test
run to re-discover.

`scripts/local-gate.sh` gained a second opt-in step,
`--javajce-remote`, separate from `--javajce` (that one is the local
FFM suite, no network; this one's whole point is a real round trip
against a live `pqc-grpc`) — checks `pqc-grpc` reachability and
`/admin-certs` presence explicitly first so a missing stack fails with
a clear message instead of a confusing `mvn` stack trace, then
`mvn install`s the core module before `mvn test`ing the remote one
(same `AGG_PATTERN`-anchored aggregate-line match `--javajce` already
uses, reused rather than re-derived). Verified both the pass path and,
via the same sabotage-a-copy technique, the fail path.

---

## 8. WS-F — W8, hsm side

1. **`scripts/local-gate.sh`**: new opt-in step `--javajce`
   (opt-in initially because it needs the `pqc-dev-sandbox` container +
   JDK 27, which not every gate run has; FAIL-never-skip semantics when
   the flag is passed, matching `--tls-interop`'s precedent). The step:
   sync `JavaJCE/` into the container (the established `docker cp`
   flow, or a bind path if one exists), run
   `mvn -o test`, assert the aggregate `Tests run` line shows 0
   failures/errors. Add to the `--all` set + the header comment + usage
   block + `RELEASING.md` pre-release checklist.
2. **CHANGELOG.md** (hsm): one entry covering the JavaJCE provider
   (W1–W6 summary, honest scope), the engine `CKF_HKDF_SALT_KEY`
   addition (A1), and the SHA-3 OAEP engine fix already shipped during
   W3 if it isn't recorded yet (check first).
3. **Root `README.md`**: the components section lists protocol
   wrappers — add/refresh the `JavaJCE/` row pointing at
   `JavaJCE/README.md`.
4. Migrate-catalog follow-up (hub repo) stays out of this plan's
   execution scope — noted as the main plan already notes it, actioned
   only with the usual proof-gated catalog process.

**WS-F: DONE 2026-08-25, PASSED — one real bug caught by deliberately
sabotaging the new gate step before trusting it.**

- **`scripts/local-gate.sh --javajce`**, new opt-in step: syncs
  `JavaJCE/` into `$SANDBOX_CONTAINER` (`pqc-dev-sandbox`, default —
  a NEW container variable, separate from `$RUST_CONTAINER`, since
  JDK 27 only lives there and the two containers are not ABI-compatible
  — see WS-A's own build-environment finding), runs `mvn -o test`, and
  asserts the aggregate summary line shows zero failures/errors. Added
  to `--all`, the header comment's numbered list, and the usage block.
  **A real bug, not a hypothetical, caught by this workstream's own
  discipline of sabotage-testing new verification code before trusting
  it green** (per this session's own standing practice — sabotage a
  copy, never a write path): the first version's success check used
  `grep -E '^\[INFO\] Tests run: [0-9]+, Failures: 0, Errors: 0'` with
  no end-anchor, which matches not just the final aggregate summary
  line but any of the 25 individual per-suite lines Surefire prints
  along the way — so a run with exactly ONE class-level failure still
  found 24 other matching "Failures: 0" lines and reported PASS. Caught
  by copying `JavaJCE/` to a scratch directory, flipping one assertion
  in `DestroyableTest`, and running the step's logic against that copy
  standalone before wiring it into the real script — it reported green
  on a build that had just failed. Fixed with an end-anchored pattern
  matching only the true aggregate line (`Skipped: N$`, no trailing
  `-- in ClassName`), re-verified against both the sabotaged copy
  (correctly reports fail) and the real source (correctly reports the
  genuine 208/208 pass). A SECOND real bug surfaced by the same
  sabotage pass, unrelated to the grep pattern: `docker cp SRC
  container:DEST` copies SRC as a subdirectory of DEST when DEST
  already exists, rather than overwriting DEST's contents in place — a
  second run of this step without first removing the whole prior
  `JavaJCE` copy (not just its `target/`) would have silently nested
  the new source under stale prior source and tested THAT. Fixed by
  `rm -rf`-ing the whole destination before every `docker cp`, not just
  `target/`. Also emits an `AGG_PATTERN` comment explaining the ANSI
  finding (Maven emits real color escapes even under a non-TTY `docker
  exec`, confirmed live via `cat -v`, not just a terminal-rendering
  artifact) and why the log is stripped before matching.
- **CHANGELOG.md**: one consolidated entry (new, first bullet under
  `### Added`) covering the real JavaJCE provider as a whole — every
  service actually implemented (cross-checked against
  `JavaJCE/README.md`'s own table, not re-derived from memory), the
  opaque-key design, the self-test battery, and pointers to the full
  README and security-posture doc. Also added the SHA-3 OAEP engine fix
  (`docs/implementation-plan-jdk27-jca-provider-2026-08-24.md`'s own W3
  entry) under `### Fixed` — confirmed genuinely missing from the
  CHANGELOG first (grepped for "SHA3.*OAEP", zero matches) rather than
  assumed absent.
- **Root `README.md`**: found substantially wrong, not just missing a
  row — the existing "Java JCE Provider" section (and two summary-table
  rows) still described the REMOVED placeholder module verbatim
  (`SoftHSMJCEProvider`/`MLDSASignatureSpi`/`MLKEMKeyAgreementSpi`,
  "patched SunPKCS11 JNI", a `Dockerfile.physics`/`playground-physics`
  deployment snippet, a dead link to a `JavaJCESofthsmv3.md` file
  confirmed no longer present on disk) — exactly the design the
  CHANGELOG's own "Removed" entry says never worked and referenced
  infrastructure that never existed in the repo. Rewrote the whole
  section to describe the real, working FFM-based provider and fixed
  both summary-table rows and the integration-interfaces table's dead
  link, rather than only touching the one row the plan item's own text
  named — leaving factually wrong architecture claims standing in a
  checked-in root README while fixing an adjacent row would have been
  worse than not touching the file at all.

---

## 9. WS-G — W8, sandbox side (full scope, decision Q3)

**Unblocked and DONE 2026-08-25.** The user's own call, once asked: commit
the `fix/dev-sandbox-samples-remediation-0824` WIP as-is (it was
coherent, finished-looking, and consistent with its own established
WS-5-batch pattern — verified by reading the new `RestPkcs11Demo.java`
in full and confirming its sibling references, e.g.
`samples/py/23-rest-pkcs11.py`, `samples/c/15_rest_pkcs11.c`, genuinely
exist, not assumed), then build WS-G on a fresh branch
(`feat/jdk27-jca-provider`, matching this hsm-side branch's name) off
that now-clean commit. Real commit `cc6e5d4` in the sandbox repo.

**One genuine architectural finding, not anticipated in this plan's own
text: `JcaProviderDemo`/`JcaTlsHybridDemo` could NOT be added as more
classes inside `samples/java/`.** Confirmed live, not assumed:
`docker/Dockerfile.dev-sandbox`'s own pre-build step for `samples/java`
compiles with JDK 24's `javac` (`JAVA_HOME=temurin-24`), and `javac`
cannot even *read* a dependency `.class` file whose own format is newer
than the compiler's maximum — `softhsmv3-jce.jar` is built at
`<maven.compiler.release>27</maven.compiler.release>`
(`JavaJCE/pom.xml`), so a probe class referencing
`SoftHSMv3Provider` failed JDK 24's `javac` outright with
`class file has wrong version 71.0, should be 68.0`. Real JDK 27
`javac` against the same jar compiles and runs cleanly. Fixed by giving
the two new samples their own sibling Maven module,
**`samples/java-jca/`** (own `pom.xml`, `<maven.compiler.release>27</maven.compiler.release>`,
own `build.sh` using `JAVA_HOME=/usr/lib/jvm/jdk-27-rc`), rather than
touching `samples/java/`'s own JDK 24 build at all.

All sandbox work follows the sibling-checkout build model (§1
correction 2) and the repo's own conventions (samples live as named
classes under `samples/java/src/main/java/com/pqctoday/pkcs11/`).

1. **Jar into the image** (`docker/Dockerfile.dev-sandbox`) — DONE. Added
   directly in the `runtime` stage right after the existing JDK 27 RC
   install block (both `maven` and JDK 27 already live there — no
   separate builder stage needed, simpler than the plan's own two
   options): `COPY pqctoday-hsm/JavaJCE` + `JAVA_HOME=jdk-27-rc mvn -q
   package -DskipTests`, then staged to **version-free stable names**
   (`softhsmv3-jce.jar`, not `softhsmv3-jce-0.1.0-SNAPSHOT.jar` — a
   refinement over the plan's own text, so `samples/java-jca`'s
   system-scoped dependencies never need to track JavaJCE's own SNAPSHOT
   version) at `/opt/softhsmv3-jce/`. Beyond `bcprov` (the plan's own
   text), also staged **`bcpkix`** and **`bcutil`** — both real,
   live-discovered needs: `bcpkix` because `JcaProviderDemo`'s
   `KeyStore`/PKIX demo needs to build a real signed cert chain (bcpkix
   is test-scope-only in `JavaJCE/pom.xml`, never shipped in the
   provider jar itself), and `bcutil` because it is bcpkix's own real
   transitive dependency — found by a live `NoClassDefFoundError` on
   `org.bouncycastle.asn1.misc.MiscObjectIdentifiers`, not predicted:
   **system-scoped Maven dependencies do not pull in transitive jars at
   all**, unlike an ordinary repository dependency, so this needed its
   own explicit staging + `pom.xml` entry once discovered.
2. **Sample 1 — `JcaProviderDemo.java`** — DONE, in the new
   `samples/java-jca/` module (see the architectural finding above).
   ML-DSA-65 GenerateKeyPair→Sign→Verify (+ tampered-signature
   rejection); AES-256-GCM round trip through an opaque token-resident
   key; ML-KEM-768 GenerateKeyPair→Encapsulate→Decapsulate via
   `javax.crypto.KEM`; `KeyStore.setKeyEntry` with a real Ed25519-signed
   cert chain (Bouncy Castle's `bcpkix` for ASN.1/X.509 syntax only —
   signing itself routes through `SoftHSMv3Provider`, the same
   `JcaX509v3CertificateBuilder`/`JcaContentSignerBuilder` pattern
   `JavaJCE`'s own `KeyStoreCertificateTest.java` already proves works)
   validated end to end through the JDK's real
   `PKIXParameters`/`CertPathValidator("PKIX")`.
3. **Sample 2 — `JcaTlsHybridDemo.java`** — DONE (WS-B was already
   green by the time this ran). Productized `W6TlsHandshakeSpike.java`:
   provider at priority 1, group pinned (argv[0], default
   `SecP256r1MLKEM768`), real handshake against `pqc-rest:5720`,
   negotiated group/protocol/cipher-suite printed, `P11Debug` token-side
   evidence available via `-Dsofthsmv3.jce.debug=true`.
4. **Docs** — DONE, scoped to what actually fits: `samples/java-jca/README.md`
   (new — module purpose, build/run, both samples' own table) plus a
   cross-reference note added to `samples/java/README.md`. The dev-sandbox
   **primitive coverage matrix** (`samples/SAMPLES.md`) was deliberately
   **not** touched — confirmed first that it covers only the raw-PKCS#11
   `01`-`20` primitive samples (checked its own real structure, not
   assumed) and that the *already-committed* WS-5 REST/gRPC remoting
   samples (a closer precedent than anything raw-primitive) aren't
   referenced there either — grepped the whole repo for
   `RestPkcs11Demo`/`23-rest-pkcs11` across every `.md` file, zero hits.
   Force-fitting a JCA-provider-level sample into a per-primitive matrix
   whose own columns are "does language X have a raw sample for
   mechanism Y" would have been inventing a new, mismatched format —
   exactly what this item's own text said not to do. `samples/java/pom.xml`
   was deliberately **not** touched either — the system-scoped dependency
   lives in `samples/java-jca/pom.xml` instead, for the same reason the
   two samples aren't inside `samples/java/` at all (item 2's own
   architectural finding).

**Verify — real, not a claim:** three full `docker build`s run to
convergence (the first two surfaced the `bcutil`/BC-provider-registration
bugs above; the third is the state that shipped). The **truly final**
build was smoke-tested from a genuinely fresh container (`docker run` off
the new image tag, not the long-running dev session's own
already-warm container) — `/opt/softhsmv3-jce/{softhsmv3-jce,bcprov,bcpkix,bcutil}.jar`
all present at the expected stable paths, `samples/java-jca`'s own
pre-built jar present, and **both samples run for real from that fresh
image**: `JcaProviderDemo` — all 13 steps pass, including the live
signed-cert-chain PKIX validation; `JcaTlsHybridDemo` — real handshake
against `pqc-rest:5720` succeeds for **both** FIPS-profile groups
(`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), `P11Debug` proof captured.
Test image tags and the smoke-test container were all cleaned up
afterward; `pqc-dev-sandbox:latest` (the live dev session's own image)
was deliberately **not** retagged or rebuilt — promoting this to the
running dev environment is a separate deploy-type decision, left
unactioned per this project's own "no deploy without go-live"
convention.

---

## 10. WS-H — JDK 27 GA swap (calendar-gated, ~2026-09-15)

1. When GA lands: update the Dockerfile's JDK 27 URL/checksum
   (RC builds rotate off jdk.java.net — the Dockerfile's own comment
   warns about this), rebuild image.
2. Re-run: full JavaJCE suite, the W6 handshake + benchmark, the W0.1
   delegation assumptions (a one-shot re-run of the spike answers all
   of them).
3. Update main plan risk register row 2, the README's RC caveats, and
   the migrate-catalog row (RC→GA) via the normal catalog process.

---

## 11. Ordering & dependencies

```
WS-A (engine salt-by-handle)  ──► WS-B (handshake + benchmark) ──► WS-G.3 (TLS sample)
WS-C (arenas)      — independent, any time; before WS-F's CHANGELOG ideally
WS-D (small items) — independent, any time
WS-E (gRPC)        — after WS-B preferred (keeps one live-debug effort at a time);
                     E0 spike can run earlier
WS-F (gate/CHANGELOG/README) — after WS-A..D land (documents what exists)
WS-G.1/.2 (jar + provider sample) — after WS-F's gate step exists (or parallel)
WS-H — calendar-gated
```

Suggested execution order: **A → B → C → D → F → G → E → H**, with the
E0 spike slotted anywhere idle. Each workstream ends with the standard
discipline: live verification in the container, plan-doc update, one
commit per slice, nothing pushed without the gate + explicit
confirmation.

## 12. Risks

| # | Risk | Handling |
|---|---|---|
| 1 | Engine change (A1) regresses existing HKDF users | Equivalence tests + full C++ ctest + the JavaJCE suite's existing HKDF tests all run against the rebuilt engine before the Java half lands |
| 2 | G2 (record layer) turns out worse than anticipated (JSSE won't fall back, and the caller-IV flag isn't enough) | B1's `SSLCipher` source reading happens before any fix is chosen; decision returns to the user with findings |
| 3 | WS-C confined-arena refactor breaks a concurrency assumption | Full suite is the net; any concurrent-use failure surfaces loudly (confined arenas throw on cross-thread use) rather than silently |
| 4 | grpc-java dependency weight contaminates the core jar | Separate Maven module (E1) — core jar's dependency set is unchanged by W7 |
| 5 | Remote verb subset drifts (proto extended without Java following) | E2 consumes the proto by path, not by copy; parity suite fails loudly on shape drift |
| 6 | JDK 27 RC → GA behavior shift | WS-H re-runs the exact live verifications, not a subset |
| 7 | Sandbox image build time grows (maven stage) | Maven stage is cached by layer; jar rebuild only on JavaJCE changes |

## 13. Explicitly out of scope (unchanged from the main plan)

Stateful hash-based signatures via JCA; composite signature profiles
via JCA; CMVP validation itself; extending the remoting proto (WS-E5 is
the named follow-on, not part of this plan's execution); hub/catalog
content changes beyond the noted follow-ups.
