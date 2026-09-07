# Common persistence encoding for both engines — remediation plan

**Date:** 2026-09-07
**Problem:** the C++ and Rust engines persist objects in unrelated formats, with unequal protection at rest.
**Requirement:** one encoding model, **agile** — object structure may change, new attributes may be introduced, existing attributes may be extended.

---

## 1. Where we are

| | C++ engine | Rust engine |
|---|---|---|
| Store | SoftHSM2-inherited: **SQLite** (`object_store/DB.h` includes `sqlite3.h`) or a file/directory backend, chosen by `objectstore.backend` | Single flat blob, magic `SHR3SNP2` (`state_snapshot.rs`), opt-in via `SOFTHSMRUST_STATE_FILE` |
| Scope | Token objects | Token objects only (`CKA_TOKEN == 1`) — correct |
| Attributes saved | All, via the object store | **All** — `state_snapshot.rs:119-126` iterates every key in the attribute map and writes `(type, len, value)` |
| Sensitive material at rest | **Encrypted** with the token key (`SoftHSM_keygen.cpp:999`, `token->encrypt`), plaintext only when `CKA_PRIVATE=FALSE` | **Plaintext.** The code says so: *"unlike the C++ engine's token directory (PIN-derived encryption of sensitive attributes), this snapshot is plaintext at rest — a dev/test persistence surface, not production"* (`ffi.rs:358-361`) |

Two problems, and the second is the more urgent:

1. The formats are unrelated, so a token written by one engine cannot be read by the other.
2. **The Rust snapshot stores sensitive material unencrypted.** For stateful-hash keys this is sharpest: the key's value *is* its signing state, and its confidentiality and its anti-rewind protection are the same property.

---

## 2. Is there a standard? Yes — KMIP 3.0. Not PKCS#11.

**PKCS#11 is not a candidate, and this is not a judgement call.** §1 states that how Cryptoki provides isolation is *"beyond the scope of this document"* (`/tmp/p11os.txt:889`). v3.2 and v3.3 define an API and an attribute model and never a storage or wire encoding. PKCS#11 is *what we encode*, not *how*.

**KMIP 3.0 defines exactly the four things needed**, and we already implement much of it:

| Need | KMIP 3.0 | In-tree today |
|---|---|---|
| Container encoding | **TTLV** — Tag(3) · Type(1) · Length(4) · Value, plus JSON/XML encodings | `kmip/src/codec/{encode,decode}.rs` |
| Key material | **Key Block / Key Value / Key Format Type** (Raw, PKCS#1, PKCS#8, X.509, Transparent\*) | `kmip30/ops.rs:457` `KeyBlock`, `KeyFormatType` |
| Protection at rest | **Key Wrapping Data / Key Wrapping Specification** | Modelled in `error.rs`, `GetRequest` |
| Extension space | Tag range `0x54xxxx`, reserved by §11.57 for extensions | `kmip30/vendor_tags.rs`, append-only, with an allocation registry |

**Why KMIP is the *agile* choice, not merely a standard one:** the wrapping algorithm is **declared inside the data** (Key Wrapping Data names it per object). The at-rest cipher can therefore differ per object and change over time with no format revision — and the CACP policy engine already in this repo is the natural place to govern that choice.

Rejected alternatives: **PKCS#8/SPKI** covers key material only, no attributes or object metadata (we already use it as the wire format); **PKCS#12** is legacy, password-bound, and models certs+keys rather than PKCS#11 objects; **JWK** has poor PQC and stateful-hash coverage; **CBOR/COSE** is an encoding with no object model.

---

## 3. The agility requirement, answered honestly

Two of the three come free from TTLV. **One does not**, and pretending otherwise is how formats break.

### 3.1 New attributes may be introduced — **free, and already true of our decoder**

Every TTLV item carries its own length, so a reader that does not recognise a tag can skip exactly `Length` bytes. Our decoder is already built for this: `decode.rs:50` keeps the **raw 3-byte tag** (`Tag::from_be_bytes`) and rejects only unknown *item types*, never unknown *tags*.

### 3.2 Object structure may change — **free**

`Structure` items nest and carry a length covering their children, so new sub-fields inside an existing structure are skippable by the same rule.

### 3.3 Existing attributes may be extended — **NOT free. This is the one that needs discipline.**

TTLV lets a reader skip a tag it *does not know*. It does nothing for a tag it *does* know whose meaning changed. If an attribute's item type widens (`Integer` → `LongInteger`), or a `ByteString` gains internal structure, every existing reader that already parses that tag will misread it — silently, because the bytes still decode.

**The rule: never widen in place. Allocate a new tag.** Keep writing the old tag for existing readers through a transition, and let new readers prefer the new one. An append-only tag registry (which `vendor_tags.rs` already mandates: *"append-only, and MUST NOT collide"*) is what makes this enforceable.

### 3.4 The rule that actually matters with two engines: **preserve unknown tags on rewrite**

This is the sharpest hazard and it is easy to miss. With two engines that will inevitably run at different versions against the same store:

> If an **older** engine reads a store written by a **newer** one and writes it back, any attribute the older engine did not understand must survive the round trip.

Skipping an unknown tag on *read* is not enough. If the persistence layer maps TTLV into a typed record — as `ObjectRecord` in `store/traits.rs` does, a plain serde struct — everything not in that struct is **dropped on rewrite**, and the newer engine's data is silently destroyed by the older one.

**So the store must persist at the TTLV frame level and round-trip unrecognised frames verbatim**, not marshal through a typed struct. This is a design constraint on the implementation, not a property of KMIP.

### 3.5 Version the container

Carry an explicit format version, and refuse rather than reinterpret an unrecognised one. `state_snapshot.rs` already sets the precedent correctly: magic `SHR3SNP2`, with `MAGIC_V1` explicitly refused — *"old layout: refuse, do not reinterpret"*.

---

## 4. Work

### Phase 1 — close the security gap first *(independent of any format change)*

The plaintext-at-rest gap should not wait on a format migration. Wrap sensitive attribute values in the Rust snapshot under a key derived from the token PIN, matching what C++ already does. Same threat model, same protection; the format work can then proceed without a live exposure open.

### Phase 2 — define the encoding

1. Specify the object encoding: KMIP `Managed Object` + `Attributes`, with PKCS#11 attributes carried as KMIP attributes where a standard equivalent exists and as `0x54xxxx` vendor tags where not (engine-private stateful-hash state, leaf index, keys-remaining).
2. Specify at-rest protection as `Key Wrapping Data`, so the wrapping algorithm is per-object and declared.
3. Write the tag registry and the append-only discipline (§3.3), including the "new tag, never widen" rule.
4. Write the unknown-tag preservation rule (§3.4) as a **testable requirement**, not prose.

### Phase 3 — implement, Rust first

Rust already has the codec. Add a TTLV-framed store that preserves unknown frames, behind the existing opt-in env var, alongside the current snapshot rather than replacing it.

### Phase 4 — C++

**C++ has no TTLV codec** — confirmed, zero hits under `src/lib/`. That is the main new work, though TTLV is a simple encoding. It must land **alongside** the SoftHSM2 store, never replacing it: that store is shared with `softhsm2-util` and with tokens already on disk.

### Phase 5 — cross-engine conformance

The test that matters is not "each engine round-trips itself". It is:

- C++ writes → Rust reads → values identical, and vice versa.
- **Old reader, new writer**: a reader built without a newly-added tag must round-trip a blob containing it **without loss**. This is §3.4's requirement, and it is the one that will actually break in practice.
- Stateful-hash keys specifically: after any round trip the leaf index must never move backwards, and must not be client-writable. The anti-rewind property is the reason that state was moved into engine-private space; a format migration is exactly where it would be lost.

---

## 5. Risks

- **Stateful-hash state is the sharp edge.** `constants.rs:372-390` records that this state was moved into the engine-private range because a writable location let a client rewind the leaf index and reuse a one-time key. Any new format must preserve that, and the conformance test above must prove it.
- **The KMIP store today holds metadata only** — *"Key material itself stays in `softhsmrustv3`"* (`store/traits.rs`). This plan changes that split; it is not free reuse of what exists.
- **Two writers, one store** is a new failure mode. Until §3.4 is implemented and tested, an older engine can destroy a newer engine's attributes.
- **KMIP 3.0's own published status**: this repo tracks CSD01 plus later working drafts (see `kmip30/vendor_tags.rs` on the Encapsulate/Decapsulate additions). Pin the revision the format claims, as the PKCS#11 work does.

---

## 6. Decisions requested

| Ref | Question | Recommendation |
|---|---|---|
| **P-1** | Fix the Rust plaintext-at-rest gap now, independently of the format work? | **Yes.** It is a live exposure, the fix is self-contained, and it should not wait on a migration. |
| **P-2** | One store per engine in a common format, or a common **interchange** format with each engine keeping its own store? | Interchange is far cheaper and gets the portability benefit. A single shared store is the stronger goal but forces a TTLV codec and a store rewrite into C++. |
| **P-3** | Which KMIP revision does the format pin to? | The same one the server claims, recorded in the format header, refused rather than reinterpreted if unrecognised. |
| **P-4** | Does the C++ engine adopt this as its *primary* store eventually, or permanently alongside SoftHSM2's? | Alongside. `softhsm2-util` and existing on-disk tokens depend on the current one. |
