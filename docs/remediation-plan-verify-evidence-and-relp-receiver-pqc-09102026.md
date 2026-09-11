# Remediation plan: verify-operation evidence gap + RELP receiver PQC verification

**Status: Gap 1 IMPLEMENTED 2026-09-10 (this commit).** Gap 2 (RELP receiver)
deliberately left as-is — the owner chose to leave the RELP receiver's
OpenSSL-version issue alone rather than upgrade it. Gap 3 (PR #235 human
review) remains open; it requires the owner, not more engineering. Written
2026-09-10 after the owner asked to write a remediation plan for two gaps
surfaced while closing out `pqctoday-cacp`'s WP9 (auth-attempt visibility,
appliance side): investigating the (now-fixed) gRPC/REST PKCS#11 evidence-log
mystery, and standing up the `validation/relp-receiver`/`validation/snmp-receiver`
rigs for real for the first time. Both gaps below are genuinely confirmed
against the current code (exact file:line citations), not assumed from the
earlier investigation's summary.

Gap 1 fix, as actually implemented: `native::verify`/`verify_with_pss_salt`/
`verify_pqc` (`rust/src/native/sign.rs`) and `ffi::C_VerifyInit`/`C_Verify`/
`C_VerifyFinal` (`rust/src/ffi.rs`) now follow the exact `_impl`-plus-wrapper
pattern Sign already uses, including deliberately replicating Sign's known
"double emission on `*Final`" quirk for parity rather than fixing it out of
scope. Along the way, `oplog::rv_name()` was missing `CKR_SIGNATURE_INVALID`
entirely (fell through to `CKR_UNKNOWN`) — the exact outcome this fix exists
to make visible — fixed in `rust/src/oplog.rs`. Covered by new/extended cases
in `rust/tests/oplog_evidence.rs` (ffi:: layer) and
`rust/tests/oplog_evidence_native.rs` (native:: layer), each asserting a
genuine signature logs `rv=CKR_OK` and a corrupted one logs
`rv=CKR_SIGNATURE_INVALID`, not silence. Full-suite regression check: `cargo
test --lib` in `rust/` (516 passed, 0 failed) and in `kmip/` (801 passed, 0
failed).

## Gap 1 (pqctoday-hsm) — `verify` operations leave no evidence, `sign`/`keygen`/`encapsulate`/`decapsulate` do

### What's confirmed

The evidence log (`SOFTHSM3_OP_LOG`, `oplog::emit`) instruments exactly six
operations today, at **both** layers:

- `ffi.rs`'s "Operation-evidence wrappers" block (`rust/src/ffi.rs:22932-23223`):
  `C_SignInit`, `C_Sign`, `C_SignFinal`, `C_GenerateKeyPair`, `C_EncapsulateKey`,
  `C_DecapsulateKey`. Each is a thin outer wrapper — the real logic lives in a
  same-named `_impl` function elsewhere in the file (e.g. `C_SignInit_impl` at
  line 6402) — that reads `oplog::enabled()` once, calls `_impl`, and emits.
- `native/sign.rs` and `native/keygen.rs`: `sign_with_pss_salt` (line 72),
  `sign_pqc` (line 350), `ml_kem_keypair`/`ml_dsa_keypair`/
  `generate_ed25519_keypair`, and `native/encrypt.rs`'s `encapsulate`/
  `decapsulate` — same impl-rename-plus-wrapper pattern, added by this
  session's `feat/auth-visibility-evidence-log` (PR #235).

**`C_VerifyInit`/`C_Verify`/`C_VerifyFinal` (`ffi.rs:7143`, `7195`, `13086`) have
no such wrapper — never did.** They are still single, directly-exported
`#[wasm_bindgen]` functions with no `_impl` split at all. Same story at the
`native::` layer: `verify`/`verify_with_pss_salt` (`native/sign.rs:224,242`)
and `verify_pqc` (`native/sign.rs:501`) call straight into
`crypto::handlers::verify_*` with no `oplog::emit` anywhere nearby (confirmed:
zero `oplog` hits in the file between lines 200 and 545). A key generated,
signed with, encapsulated, or decapsulated leaves a trail; the same key
**verified** leaves none — for KMIP, PKCS#11 remoting, and any other caller of
`native::verify*`, on every transport.

**This is a pre-existing, symmetric gap, not a regression from PR #235.**
`ffi.rs` also has a much larger v3.2 alternate-entry-point surface —
`C_SignMessage*`/`C_SignRecover*`/`C_SignEncryptUpdate` and their Verify
counterparts (`C_VerifyMessage*`/`C_VerifySignature*`/`C_VerifyRecover*`,
`C_VerifyUpdate`) — and **none of those are instrumented either, for sign or
verify**. That broader surface is **out of scope here**: the fix below brings
Verify's *core* three-function surface (`VerifyInit`/`Verify`/`VerifyFinal`) up
to parity with Sign's *core* three-function surface, nothing more — matching
the boundary the original design already drew, not inventing a new one.

### Why it matters

A verifier is exactly the thing an auditor or incident responder wants
evidence for — "did this box actually check that signature, and did it pass?"
— and today that question has no answer in the shared evidence log for either
crypto engine. It's a narrower version of the same category of gap the
auth-visibility work (PR #235) already fixed for authentication failures.

### Proposed fix

**`ffi.rs`** (mirrors `C_SignInit`/`C_Sign`/`C_SignFinal` exactly):

1. Rename the current `C_VerifyInit`/`C_Verify`/`C_VerifyFinal` bodies to
   `C_VerifyInit_impl`/`C_Verify_impl`/`C_VerifyFinal_impl`, dropping their
   `#[wasm_bindgen]` attributes (kept as plain internal `fn`s, same as
   `C_SignInit_impl` etc. today).
2. Add three new wrapper functions in the existing "Operation-evidence
   wrappers" block at the bottom of the file, same shape as their Sign
   counterparts:
   - `C_VerifyInit`: reads mechanism + `key_fields` before dispatch (same
     rationale as `C_SignInit`'s wrapper comment — a failed init can tear
     down session state), calls `_impl`, emits `C_VerifyInit` with
     `sess`/`mech`/`mech_id`/key fields/`rv`.
   - `C_Verify`: calls `_impl`, emits `C_Verify` with
     `sess`/`in`/`probe`/`rv` — no `out` field (verify has no output
     buffer to size-query, unlike `C_Sign`'s `probe=1` convention for a
     null `p_signature`; probe here should key off `p_data`/`p_signature`
     being non-null the same way, adjusted since there's no length-query
     phase for verify — confirm PKCS#11 v3.2 §5.15.2 doesn't define one
     before writing the real probe condition, don't assume it matches
     Sign's).
   - `C_VerifyFinal`: mirrors `C_SignFinal`'s wrapper, no `out` field for
     the same reason.
   - **`rv` derivation needs no special case for `CKR_SIGNATURE_INVALID`** —
     it already flows out of `_impl` as an ordinary return code (confirmed:
     `ffi.rs:7306` returns it as a plain `u32`, exactly like any other
     error code), so `oplog::rv_name(rv)` renders it correctly with zero
     extra logic, same as every other wrapper.
3. `C_VerifyUpdate` stays uninstrumented, by the same reasoning
   `C_SignUpdate`'s wrapper comment already gives (`ffi.rs:23010`-area):
   "it produces no signature, and instrumenting it would emit one line per
   chunk... for no added evidence" — verify's update calls carry no
   pass/fail result either.

**`native/sign.rs`** (mirrors `sign_with_pss_salt`/`sign_pqc` exactly):

1. `verify_with_pss_salt` (line 242): rename body to
   `verify_with_pss_salt_impl`, add a new public `verify_with_pss_salt`
   wrapper emitting the same synthetic paired `C_VerifyInit`+`C_Verify`
   records `sign_with_pss_salt` already emits for Sign (native has no
   separate init/verify phase split either). `rv` derivation:
   `Ok(true) → CKR_OK`, `Ok(false) → CKR_SIGNATURE_INVALID`, `Err(e) → e`.
2. `verify` (line 224) needs no change — it already just calls
   `verify_with_pss_salt(..., None, None)`, so it inherits the wrapper.
3. `verify_pqc` (line 501): same impl-rename-plus-wrapper treatment as
   `sign_pqc`. **Different `Result` shape to handle correctly**:
   `verify_pqc` returns `Result<(), CkRv>`, not `Result<bool, CkRv>` like
   `verify` — `crypto::handlers::verify_ml_dsa`/`verify_slh_dsa`
   (`crypto/handlers.rs:2558,2682`) signal an invalid signature via
   `Err(CKR_SIGNATURE_INVALID)`, not `Ok(false)`. So the `rv` derivation
   here is simply `Ok(()) → CKR_OK`, `Err(e) → e` — no `Ok(false)` arm
   exists or is needed, unlike step 1. Confirm this if implementing; the
   two verify paths use genuinely different conventions today and mixing
   them up would silently misreport CKR_OK on some rejected signatures.

### Testing

Mirror `rust/tests/oplog_evidence_native.rs`'s existing pattern (own
process, drives real `native::` calls, asserts the resulting `PQCEV`
records) with a new case: generate a keypair, sign, then verify **both a
genuine signature (expect `rv=CKR_OK`) and a corrupted one (expect
`rv=CKR_SIGNATURE_INVALID`)**, asserting both land in the evidence log with
the right `rv`/`rv_id`. Also extend the gRPC/REST-remoting live check this
session already did manually (open session, generate key, sign) with a
`verify` call, confirmed the same way against a real running binary, not
just the unit test — that's what caught the original sign/keygen gap in the
first place.

## Gap 2 (pqctoday-cacp) — RELP receiver can't verify the X25519MLKEM768 requirement it claims to enforce

### What's confirmed

`validation/relp-receiver` (fixed this session to actually run at all — wrong
Docker tag, missing `imrelp`/openssl-TLS packages) now proves basic RELP/TLS
delivery works, but its base image (`rsyslog/rsyslog:2026-04`, Ubuntu 24.04
"noble") ships **OpenSSL 3.0.13** (checked live: `openssl version` inside the
container). OpenSSL didn't gain ML-KEM/hybrid-group support
(`X25519MLKEM768`) until **3.5.0** (April 2025) — so this receiver's own
`tls.tlscfgcmd` can't even name that group; forcing it made rsyslogd log
`'Failed to added Command: Groups...'` and refuse to start at all, which is
why `rsyslog.conf`'s group restriction was removed rather than fixed in the
delivery-proof work. The appliance's own `omrelp` client still offers
`Groups=X25519MLKEM768:X25519` (`50-pqc-relp.conf`/`pqc-firstboot.sh`) — a
receiver that can't speak the hybrid group at all will simply fall back to
classical X25519, and nothing in the current rig can tell the difference.

**Confirmed via web search (2026-09-10), not assumed:** Debian 13 ("trixie")
ships OpenSSL 3.5.x as its default `openssl` package
(`packages.debian.org/source/trixie/openssl` shows `3.5.5-1~deb13u1` as of
2026-02-22, `3.5.6-1~deb13u1` as of 2026-05-04) — meaning a receiver built on
`debian:trixie-slim` + `apt install rsyslog rsyslog-relp rsyslog-openssl`
would get a system OpenSSL new enough to negotiate the hybrid group, with no
need to build OpenSSL from source (the appliance's own OpenSSL 3.6.3 minimum
was reached that way for a reason — see that repo's CLAUDE.md — but a
*receiver-side* verification rig has a lower bar: it only needs to *offer and
accept* the group name, not match the appliance's exact minimum version).

### Proposed fix

Replace `validation/relp-receiver/Dockerfile`'s base image
(`rsyslog/rsyslog:2026-04`) with a small `debian:trixie-slim`-based image
installing `rsyslog rsyslog-relp rsyslog-openssl` directly from apt (Debian's
official archive, not a PPA or backport — trixie is stable). Restore
`rsyslog.conf`'s `tls.tlscfgcmd="Groups=X25519MLKEM768"` restriction (the
whole point of R7b's name — "RELP delivered to receiver **requiring**
X25519MLKEM768" — currently unenforceable, silently weakened to "any group"
in the delivery-proof work this session). Re-verify live: confirm
`openssl version` inside the new container reports 3.5+, confirm a fresh RELP
delivery still succeeds with the group restriction back in place, and confirm
(as a negative control) that a client offering *only* classical X25519 gets
refused — that's the actual proof the restriction does something.

### Open question

Is this worth doing now, or is "delivery proven, hybrid-group enforcement
not" an acceptable resting state given `R14b`/`R8b` already prove the
appliance's *own* TLS stack offers `X25519MLKEM768` correctly elsewhere
(KMIP, the UI) — i.e., is RELP's receiver-side enforcement actually adding
information beyond what's already proven at the appliance boundary?

## Gap 3 (process, not code) — PR #235 has zero human review

Not a remediation item in the code sense — recorded here only because it
surfaced during this same investigation. `pqctoday-hsm` PR #235 (the
auth-visibility + evidence-log fix everything above builds on) was merged via
an explicit, owner-authorized `--admin` bypass of the required-review branch
protection, with 0 actual reviews. No action proposed here beyond flagging it
as available to revisit if anyone has review bandwidth later — it is not
blocking anything and the owner already made this call deliberately.

## Estimate

Gap 1: ~1 day (both layers, plus the new test and a live-verified re-run of
the gRPC/REST sign/verify probe this session already built). Gap 2: ~2-4
hours (Dockerfile swap + re-verify), contingent on the open question above.
