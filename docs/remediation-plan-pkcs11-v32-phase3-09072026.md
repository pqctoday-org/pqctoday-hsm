# PKCS#11 v3.2 — Phase 3 remediation plan (remaining gaps)

**Date:** 2026-09-07
**Branch:** `fix/pkcs11-d2-pkcs8-wire-format` (19 commits, unpushed) · PR #226 open for phase 1
**Predecessors:** `remediation-plan-pkcs11-v32-gaps-09062026.md` (phase 1, all 7 items done), `remediation-plan-pkcs11-v32-phase2-09072026.md` (phase 2, all items done except as recorded below)

---

## 0. Where things actually stand

All seven gaps in the original audit (`pkcs11-hsm-v32-compliance-audit-09062026.md`) are closed. The differential harness runs **65 scenarios / 10,065 observations / 0 uncovered**, with **11 known-defect divergences** all belonging to one entry. The mechanism ledger reports **C++ 166, Rust 172, C++-only set empty**.

What follows is everything I know to still be open. Three items are corrections to claims made earlier in this programme — including one of my own — and they are listed first because they change what the rest of the plan should do.

### 0.1 Correction: JavaJCE is **not** blocked

I reported the JavaJCE half of X1 as unverifiable because "no JDK exists on this machine or in the container". That was wrong. I checked the host and `$RUST_CONTAINER` (`pqc-rust`) and generalised from two negatives.

The project's Java toolchain lives in a **third** container, `pqc-dev-sandbox`, which is up and healthy and carries `/usr/lib/jvm/jdk-27-rc` alongside Temurin 24 and Maven 3.8.7. `local-gate.sh` already knows this: the `--javajce` step (`scripts/local-gate.sh:479-517`) `docker cp`s `JavaJCE/` into `$SANDBOX_CONTAINER:/tmp/hsm-javajce-gate`, exports `JAVA_HOME=/usr/lib/jvm/jdk-27-rc`, and runs `mvn -o test`. The pom targets `<maven.compiler.release>27</maven.compiler.release>`, which is why the default `JAVA_HOME` (Temurin 24) is not the one the gate uses.

So the JavaJCE work is **runnable in one command** and should never have been recorded as blocked. That is item §1.

### 0.2 Correction: `LEGAL-USAGE-FLAG-DEFAULT-RECOVER` contains two false statements

The H1 sweep verified every `citation` field. It did **not** verify the free prose in `justification` fields, and this entry's prose contains two claims that the code directly contradicts:

- It says the `CKF_*_RECOVER` mechanism-info flags "correctly stay unadvertised on both engines". Both engines advertise them: `SoftHSM_slots.cpp:977` and `:983` set `CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER` on `CKM_RSA_PKCS` and `CKM_RSA_X_509`, and `rust/src/ffi.rs:1384-1395` sets bits `0x1000 | 0x4000` on `CKM_RSA_PKCS`.
- It says "C3 removed its recovery path". C3 did the opposite. Its own comment at `SoftHSM_slots.cpp:967-971` explains that advertising *neither* flag "meant a caller doing the correct thing — checking the advertisement first — would never reach a working feature", and `C_SignRecoverInit`/`C_SignRecover` are fully implemented for RSA at `SoftHSM_sign.cpp:2185` and `:2247`.

There is no gap here — both engines advertise and implement it consistently. The **note** is the defect. It matters because a future reader would take "C++ overstates what its dispatch does" as a live worklist item and go looking for a bug that does not exist. That is item §4.

### 0.3 Correction: the `CKA_VALUE` defect's deferral reason is stale

`DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS` is deferred on the grounds that:

> "the per-type attribute sets the spec defines (CKA_MODULUS/CKA_PRIVATE_EXPONENT and the CRT set for RSA, CKA_EC_POINT/CKA_EC_PARAMS for EC) are not the engine's internal representation. Removing the attribute without first building those sets would make keys unusable rather than conformant."

**Those sets now exist.** `rust/src/ffi.rs:2684` and `:2711` insert `CKA_MODULUS` on both halves of a generated RSA key pair, with the exponents alongside, and the harness confirms it from the outside: `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` produce **no divergence at all** in `create.generate_key_pair.rsa2048`. The named blocker was removed by later work and nobody revisited the deferral.

The entry's scope description is also stale. It claims the residual covers "RSA public keys, RSA private keys and unwrapped EC private keys". The actual 11 observations are **8 on RSA** and **1 each on XMSS, XMSSMT and HSS**. EC is gone — the D-2 wire-format work removed it. That is item §3.

---

## 1. J1 — verify and land the JavaJCE half of X1

**Effort: S. This is the highest-value item per unit of work in the plan, because the code is already written and only needs running.**

The commit `6d607f39` added `P11ECExtraBitsGenParameterSpec` (a public `ECGenParameterSpec` subclass), a `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` constant in `P11Constants`, and mechanism selection in `P11ECKeyPairGeneratorSpi`. None of it has been compiled.

1. `bash scripts/local-gate.sh --javajce`. Expect either a clean run or a compile error in the three files touched — nothing else in the module was changed.
2. Add a test that actually exercises the new spec, not just the compile: generate with `new P11ECExtraBitsGenParameterSpec("secp384r1")`, read `CKA_KEY_GEN_MECHANISM` back off the private key, and assert it is `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` and **not** `CKM_EC_KEY_PAIR_GEN`. Assert the negative too: a plain `ECGenParameterSpec` on the same generator must yield `CKM_EC_KEY_PAIR_GEN`, or the flag could be stuck on and the test would still pass.
3. Assert the reset behaviour: `initialize(384, null)` after an extra-bits `initialize(spec)` must go back to the plain mechanism. That line exists precisely so a re-initialised generator cannot silently inherit the previous choice, and it is the kind of thing that only a test protects.

**Decision needed (D-J1): the POST.** `SoftHSMv3Provider`'s power-on self-test (`SoftHSMv3Provider.java:465`) hard-codes `CKM_EC_KEY_PAIR_GEN` for its pairwise consistency check. I left it alone when I could not test it. Now that it can be tested, should it gain a second pairwise check under the extra-bits mechanism? **Recommendation: no.** The POST runs on every provider load; a second keygen doubles its cost to prove something §1.2's test already proves, and a token that lacks the mechanism would fail provider construction rather than fail one operation. Better as a unit test than as a load-time gate.

---

## 2. O-1 — PQC private-key PKCS#8 inner encoding

**Effort: M for the investigation, unknown for the fix — deliberately not estimated, because the investigation decides whether there is one.**

Carried unresolved from phase 2 §9. D-2 fixed the `PrivateKeyInfo` encoding for EC, Edwards and Montgomery keys by matching OpenSSL 3.6.3 byte-for-byte. It deliberately left the PQC key types alone: `pkcs8_private_key_info` still emits the raw private key inside the OCTET STRING for `CKK_ML_DSA`, `CKK_ML_KEM` and `CKK_SLH_DSA` (`rust/src/ffi.rs`, the `CKM_ML_DSA | ...` arm).

The concern is specific and was observed, not theorised: during the PR #212 work OpenSSL's `private_key_to_pkcs8()` produced a nested `SEQUENCE { seed, expandedKey }` for ML-DSA-65. If that is the interoperable form, the engine's raw encoding diverges from OpenSSL for PQC exactly as it did for EC before D-2 — and the same class of silent BYOK failure follows.

1. **Establish ground truth first, in the same way D-2 did.** Generate one key of each PQC type with OpenSSL 3.6.3, dump the DER, and decode it by hand. Do not infer the structure from a draft; read the bytes. `openssl genpkey -algorithm ML-DSA-65 -out k.der -outform DER` then `openssl asn1parse -inform DER -in k.der`.
2. Cross-check against the current LAMPS drafts for ML-DSA, ML-KEM and SLH-DSA private-key encoding, which have been moving. Record the draft revision consulted, with a date — this is exactly the kind of citation that goes stale silently.
3. Only then decide. Three outcomes are possible and all are acceptable: the engine's form is right; the engine's form is wrong and must change; or the standards have not settled and the right action is to record the divergence in `exceptions.json` with the draft citation and revisit on a named trigger.
4. If it changes: same shape as D-2 — encoder, decoder, `.p8.der` fixtures under `rust/kat/pkcs8/`, and a round-trip test that fails on the pre-fix code.

**Decision needed (D-O1): does the C++ engine need the same treatment?** D-2 was Rust-only because the wire format defect was Rust-only. Whether C++ emits PKCS#8 for PQC private keys at all needs checking before this item's scope can be fixed.

---

## 3. E1 — retire or re-scope `DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS`

**Effort: S–M, and much smaller than the entry implies.** See §0.3: the blocker the deferral names no longer exists.

Rust carries `CKA_VALUE` on RSA public keys, RSA private keys and the three stateful-hash key types, where the class attribute tables define no such attribute. C++ answers `CKR_ATTRIBUTE_TYPE_INVALID`. 11 observations.

The fix is narrower than "stop storing keys that way". `CKA_VALUE` is Rust's internal storage representation and is read internally (e.g. `get_object_value` in `C_SignRecover`). What violates the spec is **exposing it through `C_GetAttributeValue`**, not holding it. So:

1. Filter `CKA_VALUE` out of the `C_GetAttributeValue` response for `CKO_PUBLIC_KEY` and `CKO_PRIVATE_KEY`, answering `CKR_ATTRIBUTE_TYPE_INVALID` with `CK_UNAVAILABLE_INFORMATION`, exactly as C++ does. Leave storage untouched.
2. **Prove the keys still work before and after** — this is the whole risk. Sign/verify, wrap/unwrap and the KMIP path all read the key internally; a filter applied in the wrong place breaks them. The regression test must be a functional round trip, not an attribute read.
3. For the three stateful-hash types, check separately: §6.65/§6.66 give HSS and XMSS a `CKA_VALUE` whose content is "Vendor defined", so for **those** classes the attribute may be legitimate and only RSA is the violation. Read the tables before filtering — this is the difference between a 2-line fix and a wrong one.
4. If it lands: delete the entry. If only RSA is fixed: re-scope it to the stateful-hash types, correct its stale claim about EC and unwrapped keys, and say what changed.

**Decision needed (D-E1): fix or re-defer?** It is a genuine non-conformance, now cheap for RSA. **Recommendation: fix the RSA half, adjudicate the stateful-hash half against the tables.** The alternative — leaving it — is defensible only if the note is rewritten, because its current reason is false.

---

## 4. H2 — verify the `justification` prose, not just the citations

**Effort: S, no code.** H1 verified all 31 `citation` fields and corrected 16. It did not read the free prose for factual claims, and §0.2 shows that prose can be wrong in a way that manufactures phantom worklist items.

1. Fix `LEGAL-USAGE-FLAG-DEFAULT-RECOVER`: delete the "C3 removed its recovery path" and "correctly stays unadvertised" claims, and replace them with what the code does, citing `SoftHSM_slots.cpp:977`, `:983` and `ffi.rs:1384`.
2. Fix `DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS`'s scope sentence regardless of what §3 decides — "unwrapped EC private keys" has been false since D-2 landed.
3. Read every remaining `justification` for claims **about this repository's code** (as opposed to about the specification) and check each against the source. Those are the ones that rot: a spec citation is wrong from the day it is written, but a code claim starts true and decays.
4. Stamp the pass, as H1 did, in `_citation_verification`.

---

## 5. X3 — extend the ledger to mechanism-info **flags**

**Effort: M. This is X2′'s unfinished half.**

X2′ made every `CKM_*` accountable per engine. It did not make each mechanism's `CK_MECHANISM_INFO` accountable — and that is where the two defects of this programme's last phase actually lived:

- `CKM_AES_CMAC` reported a 64-byte maximum key against C++'s 16–32, undetected because `LEGAL-MECHANISM-SET` excuses the path glob `mech*` wholesale.
- The `CKF_*_RECOVER` flags were mis-described for weeks in the one document that adjudicates them, and nothing could contradict it.

Extend `docs/pkcs11-mechanism-ledger.json` so an `implemented` row also carries `{min, max, flags}` per engine, parsed from the same two source files the checker already reads (`SoftHSM_slots.cpp`'s `C_GetMechanismInfo` switch and `ffi.rs`'s mechanism-info table). Fail when the two engines disagree on a mechanism **both** implement, unless the row carries an explicit adjudication. Then narrow `LEGAL-MECHANISM-SET`'s glob from `mech*` to the membership question it was actually written for, so mechanism-info divergences stop being invisible.

The parse is the hard part: C++ builds flags with `|`-expressions over named constants across fallthrough `case` labels, and Rust uses bare hex. Both are parseable but neither is trivial, and a parser that silently matches nothing is worse than no check. **Whatever is built must be sabotage-tested the way the X2′ checker was** — five deliberate breakages, each caught.

---

## 6. R1 — build-warning hygiene

**Effort: S.** `cargo build --lib` emits 43 warnings. Chasing four of them found a real defect this phase (`CKM_ECDSA_SHA1` could never verify), which is the argument for not leaving them.

- `der_wrap_ec_point` is reported dead but has a call site at `ffi.rs:23026`; the call is behind a `cfg` the default build excludes. Determine which, and either gate the function to match or remove it. Do not silence it with `#[allow]` before knowing which.
- The unused imports (`AtomicU32`, `crate::constants::*`, `rand::SeedableRng`, `OBJECTS`/`get_object_value`, `RefCell`, `p521::elliptic_curve::Field`) are almost certainly noise, but `get_object_value` is used elsewhere in the file — confirm each is genuinely unused in that module rather than mass-applying `cargo fix`.
- Consider `#![deny(unreachable_patterns)]` for the crate. That single lint is what surfaced the SHA-1 defect; making it an error stops the next one from accumulating quietly.

---

## 7. Two adjudications worth reopening

Neither is a defect today. Both were flagged during H1 as resting on weaker ground than their text implies, and both should be decided deliberately rather than inherited.

- **`LEGAL-EC-PARAMS-CURVE-NAME-VS-OID`.** §6.3.5–§6.3.8 each state "Note that keys defined by [RFC 8032] and [RFC 8410] are incompatible". `curveName` is the RFC 8032 form and the oID the RFC 8410 form. My reading — that the note concerns key material compatibility, not which encoding a token may *report* for the same key — is what keeps the entry legal, and it is a reading, not a quotation. Worth a second opinion before it hardens into precedent.
- **`LEGAL-OPTIONAL-ATTR-PUBLIC-KEY-INFO`.** Rust diverges from an explicit SHOULD (§6.1.3 for RSA private keys, §4.10 generally), not from silence. Implementing `CKA_PUBLIC_KEY_INFO` in Rust is a small, self-contained piece of work — the SubjectPublicKeyInfo is already derivable from what the engine stores. **Recommendation: implement it** and delete the exception, rather than keep adjudicating against a SHOULD.

---

## 8. Landing

Nothing on this branch is pushed and no push should happen without explicit confirmation.

1. `bash scripts/local-gate.sh --cpp --javajce --openssl-provider`. The core gate alone does not cover the C++ ctest, the JavaJCE suite or the vendored provider, and this branch has touched all three.
2. The gate writes `.gate-ok-<HEAD-sha>`; the pre-push hook verifies it. For this worktree, `AG_CONTAINER_ROOT=/ag/pqctoday-hsm/.worktrees/pkcs11-d2` must be set on **every** run.
3. **Decision needed (D-L1): one PR or two?** PR #226 (phase 1) is open and unreviewed. This branch's 19 commits are a separate, larger body of work that builds on it. Options: rebase and fold everything into #226; open a second PR stacked on it; or ask for #226 to be reviewed and merged first and then open one PR for phases 2–3. **Recommendation: the third.** #226 is small and self-contained, and a 19-commit PR that also carries phase 1 is much harder to review than two.

---

## 9. Sequencing

1. **§1 J1** — smallest, already-written, and it closes the one item currently reported as blocked.
2. **§4 H2** — no code, and it removes a phantom worklist item before anyone acts on it.
3. **§3 E1** — the only remaining live non-conformance.
4. **§6 R1** — cheap, and the lint pays for itself.
5. **§7** — decide the two adjudications; implement `CKA_PUBLIC_KEY_INFO` if that is the call.
6. **§5 X3** — the structural item; best after §3 and §7, when the mechanism-info picture is settled.
7. **§2 O-1** — largest and most uncertain; independent of everything else, so it can run in parallel or last.
8. **§8** — landing, only on explicit confirmation.

---

## 10. Verification standard (unchanged — it earned its keep again this phase)

- A regression test that **fails on the pre-fix binary** and passes after. This phase it caught `CKM_ECDSA_SHA1` on P-256, which was advertised and could never verify.
- Assert against an **independent** oracle — OpenSSL, RustCrypto, a published vector — never the engine against itself.
- Any `exceptions.json` edit quotes the sentence it relies on, with `file:line`. **New this phase:** the same applies to claims about *code*, which is what §0.2 and §0.3 are about.
- Section and table numbers come from `docs/refs/pkcs11-spec-v3.2-csd01.pdf`. The vendored v3.3 draft is prose only — its headings carry no numbers and its content has drifted.
- When two research passes disagree, resolve it from the primary source. This phase they disagreed on a table number and extracting the PDF's own text settled it.
- Sabotage-test any new gate check on a **copy** of the tree, never the working files.
- OpenSSL 3.6.3+ only. Full `scripts/local-gate.sh` before any push is proposed.

---

## 11. Decisions requested

| Ref | Question | Recommendation |
|---|---|---|
| **D-J1** | Should the JavaJCE POST gain an extra-bits pairwise check? | No — a unit test proves it without doubling every provider load. |
| **D-O1** | Does O-1's scope include the C++ engine, or is it Rust-only like D-2? | Determine by inspection first; do not assume Rust-only. |
| **D-E1** | Fix the `CKA_VALUE` exposure, or re-defer with an honest reason? | Fix the RSA half; adjudicate the stateful-hash half against §6.65/§6.66. |
| **D-P1** | Implement `CKA_PUBLIC_KEY_INFO` in Rust, or keep adjudicating against a SHOULD? | Implement it. |
| **D-L1** | One PR or two? | Two — get #226 reviewed and merged first. |

---

## 12. Execution log (2026-09-07)

### §1 J1 — JavaJCE: **done and genuinely verified**

`P11ECExtraBitsGenParameterSpec` compiles under JDK 27 and the full existing suite passes **274/274** unchanged. A new `ECExtraBitsTest` (8 cases) asserts against `CKA_KEY_GEN_MECHANISM` read back off the generated key — deliberately not against anything the provider says about itself, because both mechanisms produce an ordinary working EC key and a sign/verify test would pass identically whichever one ran. Every positive case is paired with its negative, so a flag stuck permanently on would still fail.

**Fails-pre-fix confirmed the hard way.** Run against an engine *with* the mechanism: 8/8 pass. Run against one *without*: 4 errors, `CKR_MECHANISM_INVALID (0x70)`, and exactly the four mechanism-agnostic cases still pass.

**Operational finding — the gate has a false green here.** `--javajce` runs `mvn` against the container's installed `/usr/local/lib/softhsm/libsofthsmv3.so`, which is dated **2026-09-01** and predates X1. The gate therefore validates today's Java against a months-old native engine, and will keep reporting green while the two drift apart. This is not specific to X1 — any engine-side change is invisible to that step. It needs fixing (§13).

For this verification the engine was built fresh inside `pqc-dev-sandbox` (it has cmake, g++ and OpenSSL 3.6.3) and installed to `/opt/x1-engine/`, a **separate path**; the shared container's library was deliberately not overwritten.

### §2 O-1 — PQC PKCS#8 inner encoding: **resolved, no code change**

Ground truth was established the way D-2's was — by reading bytes OpenSSL 3.6.3 actually produced, not by inferring from a draft. Seven keys generated and decoded:

| Family | What OpenSSL 3.6.3 emits |
|---|---|
| ML-DSA-44/65/87 | `SEQUENCE { OCTET STRING seed(32), OCTET STRING expandedKey(2560/4032/4896) }` |
| ML-KEM-512/768/1024 | `SEQUENCE { OCTET STRING seed(64), OCTET STRING expandedKey(1632/2400/3168) }` |
| SLH-DSA-SHA2-128s | **bare raw**, 64 bytes, no nested structure |

So OpenSSL's *emitted* form does differ from the engine's for ML-DSA and ML-KEM. That was the concern. But emission is not the interoperability question — acceptance is. Four candidate encodings were built by hand for ML-DSA-65 and ML-KEM-768 (bare raw as the engine emits; nested `OCTET STRING` expandedKey; `SEQUENCE{seed,key}`; `[0]` seed only) and fed back to OpenSSL:

- **All four are accepted**, and all four derive a **byte-identical public key**. The engine's form interoperates.
- For **SLH-DSA the engine's raw form is the only one accepted** — the nested `OCTET STRING` is *rejected*. The engine could not be doing anything else.

**The premise is falsified.** Phase 2 §9 suspected PQC "may diverge from OpenSSL exactly as it does for EC". EC was a genuine interop break — OpenSSL rejected the engine's output. This is not: OpenSSL reads the engine's PQC output and gets the right key.

One nuance to carry rather than act on: bare raw is not, strictly, one of the LAMPS draft's CHOICE alternatives (each is a TLV), so a stricter peer than OpenSSL could in principle reject it. Weighed against SLH-DSA *requiring* bare raw, and against changing a format that currently works, the answer is to leave it alone and record the finding. **No fix. O-1 closed.**

### §3 E1 — the `CKA_VALUE` picture is not what the exception says

The decision taken was "fix all five key types". Checking the specification first — before writing the filter — showed that would have been wrong for three of them, and that the exception misdescribes the defect in both directions.

`CKA_VALUE` **is** defined on the key-object attribute tables for ML-DSA, ML-KEM, SLH-DSA, EC, Edwards, Montgomery, DSA, HSS, XMSS and XMSS-MT. It is **not** defined for **RSA** — neither the RSA Public nor the RSA Private Key Object Attributes table has a row for it. RSA is the whole violation.

The three stateful-hash observations run the **other way**, which no one had checked:

| | C++ | Rust |
|---|---|---|
| HSS / XMSS / XMSS-MT private, `CKA_VALUE` | `CKR_ATTRIBUTE_SENSITIVE` | `CKR_ATTRIBUTE_TYPE_INVALID` |

C++ is **correct**: §6.65/§6.66 define `CKA_VALUE` for these keys with footnote 7 ("cannot be revealed if `CKA_SENSITIVE` is true"), and mandate `CKA_SENSITIVE`. Rust answers "the object does not possess such an attribute" about an attribute the specification defines for that class. Refusing it *harder*, as "fix all five" would have done, would have entrenched a violation rather than removed one.

Rust's answer is truthful about its own storage — per `LEGAL-XMSS-STATE-REPRESENTATION` it keeps stateful-hash state in engine-private vendor attributes, not in `CKA_VALUE` — so fixing it means **materialising** the attribute and gating it as sensitive. That is a representation change, not a filter, and it interacts with an existing adjudication. It is a separate item (§14), not part of E1.

**Revised E1 scope: RSA only** — which both offered options agreed on.
