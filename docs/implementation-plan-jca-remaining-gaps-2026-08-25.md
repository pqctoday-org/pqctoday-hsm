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

---

## 6. WS-D — Small hardening items

| Item | Action | Verify |
|---|---|---|
| SHA-3 PSS (`CKG_MGF1_SHA3_*` + `CKM_SHA3_*_RSA_PKCS_PSS`) | Check the engine actually dispatches the SHA-3 PSS mechanisms first (grep `SoftHSM.cpp` mechanism table — do NOT assume from the OAEP precedent); if yes, extend `P11RSAPSSSignatureSpi.DIGEST_TO_MECH_AND_MGF` (+ constants verified against `pkcs11t.h`) and remove the "not yet built" javadoc scope-down | BC interop test per digest, same pattern as the SHA-2 PSS tests |
| GCM IV uniqueness across sessions | New test: two fresh providers, N encrypts each, assert all module-generated IVs distinct (the main plan's own W4 verify list marks this "not yet attempted") | test |
| Pre-hash ML-DSA / SLH-DSA (`CKM_HASH_ML_DSA_*`, `CKM_HASH_SLH_DSA_*`) | Investigate-then-decide: check engine mechanism table; if supported, these need a new SignatureSpi shape (digest parameter); if not, record as engine-gap and defer — either way stop leaving it implicit in a javadoc | live probe + doc |
| `engineGetCreationDate` stub (`new Date(0)`) | PKCS#11 has no creation-timestamp attribute for the engine to report; keep the stub but document it in the KeyStore javadoc + README limitations instead of leaving it bare | doc only |

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

### E1 — Architecture decision (made now, validated by E0)

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
  session/key ids; SPKI export uses whatever `GenerateKeyPairResponse`
  returns (E0 confirms).
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

### E4 — Verification

- Re-run the Ed25519/ML-DSA/ML-KEM slices of the existing suites
  parameterized over the remote provider (sign/verify round-trips,
  FIPS-size assertions, tamper rejection, KEM round-trip).
- **Three-way parity** (mirrors `three_way_parity.rs`): for each
  algorithm — C++-in-process signs → Rust-gRPC verifies; Rust-gRPC
  signs → JDK software verifies; JDK signs → C++ verifies (and the KEM
  equivalent: encapsulate on one, decapsulate on another where the
  wire format allows). Every cell either passes or gets a recorded,
  cited exception — no silent skips.
- Gate: these tests need the remoting server running → wire into the
  same opt-in gate step family as other infrastructure-dependent steps
  (WS-F), FAIL-not-skip semantics when the flag is on.

### E5 — Explicit follow-on (own gate, not this plan)

Extending the proto `Algorithm` enum + verb set (SLH-DSA, EC, RSA,
symmetric) to widen the remote JCA surface — a cross-crate change with
its own Rust-side test obligations.

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

---

## 9. WS-G — W8, sandbox side (full scope, decision Q3)

All sandbox work follows the sibling-checkout build model (§1
correction 2) and the repo's own conventions (samples live as named
classes under `samples/java/src/main/java/com/pqctoday/pkcs11/`).

1. **Jar into the image** (`docker/Dockerfile.dev-sandbox`):
   - In the existing `hsm-builder` stage (or a small dedicated stage
     `FROM` it): install maven, `mvn -q package -DskipTests` in
     `/usr/src/pqctoday-hsm/JavaJCE` using the image's JDK 27 RC
     (already present at `/usr/lib/jvm/jdk-27-rc` — confirmed in the
     Dockerfile 2026-08-25), producing `softhsmv3-jce-<v>.jar`.
   - `COPY --from=` the jar (+ the bcprov jar it needs on the
     classpath) into the final image at a stable path
     (`/opt/softhsmv3-jce/`), documented in the image's header comment.
   - Skip-tests at image build is correct here (tests need a live
     token + env); the gate step (WS-F) is where tests run.
   - Verify by the build-artifact discipline: image builds, jar present
     with expected name/size, a one-liner
     `java -cp ... MessageDigest.getInstance("SHA-256", new SoftHSMv3Provider())`
     smoke inside the fresh image — locally via OrbStack (amd64
     validation happens locally, never "requires a push").
2. **Sample 1 — `JcaProviderDemo.java`** ("24-jca-provider" in the
   main plan's numbering): consumes the installed jar through pure
   standard JCA — generate ML-DSA-65 keypair, sign/verify; AES-GCM
   round-trip; ML-KEM-768 encap/decap via `javax.crypto.KEM`; KeyStore
   `setKeyEntry` with a token-signed cert chain + PKIX validation (the
   showcase of what the raw-FFM `P11Ffm.java` sample deliberately does
   NOT abstract — the README contrast writes itself: P11Ffm teaches the
   PKCS#11 wire level, this teaches the drop-in JCA level).
3. **Sample 2 — `JcaTlsHybridDemo.java`** (dependent on WS-B): the
   spike's flow productized — provider at priority 1, groups pinned,
   handshake against `pqc-rest:5720`, printing the negotiated group and
   the `P11Debug` token-side evidence. Ships only after WS-B is green;
   until then the sample directory carries no half-working demo.
4. **Docs/matrix**: `samples/java/README.md` rows for both samples
   (what each proves, how to run); the dev-sandbox samples matrix rows
   (per the samples-audit conventions — check the matrix scope
   decisions in the 0824 audit doc before adding, don't invent a new
   format); `samples/java/pom.xml` gains the jar dependency via a
   system-scoped/local-repo reference consistent with how the sample
   build already resolves things (`build.sh` — check before choosing
   the mechanism).

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
