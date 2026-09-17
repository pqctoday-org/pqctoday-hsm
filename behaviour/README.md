# Behaviour event ring

One 8-byte record per crypto operation, from every producer on the appliance,
into one shared-memory ring file, for one out-of-process consumer (the
appliance's behaviour monitor). This directory holds what the producers share:

| File | Role |
|---|---|
| `ids.json` | **Source of truth** for every id byte in the record (surfaces, operations, algorithms, result classes) and the golden encoding vectors. Append-only: never renumber, never reuse. |
| `gen.py` | Regenerates `rust/src/behaviour/ids.rs` and `src/lib/common/BehaviourIds.h` from `ids.json`. `--check` exits 1 if either is stale; the Rust unit test `generated_tables_match_ids_json` runs that check. |

The producers:

| Producer | Where | Gate |
|---|---|---|
| Rust engine (`softhsmrustv3`) — PKCS#11 entry points and the `native::*` path the KMIP server and both remoting services call | `rust/src/behaviour/mod.rs` (writer), call sites in `rust/src/ffi.rs`, `rust/src/native/{sign,keygen,encrypt}.rs` | `PQC_BEHAVIOUR_RING` (path), `PQC_BEHAVIOUR_SRC` (`p11-local` default, `p11-remoting-grpc`, `p11-remoting-rest`) |
| C++ engine (SoftHSMv3) — the same entry points | `src/lib/common/BehaviourRing.{h,cpp}`, call sites in `src/lib/SoftHSM_{sign,keygen,kem}.cpp` | same two variables |
| KMIP server — one record per KMIP response, plus policy deny / warn / rekey / activation, TLS handshakes, admin routes | `kmip/src/auditlog/behaviour.rs` (audit-stream leg), `kmip/src/metrics.rs` | `PQC_BEHAVIOUR_RING` |
| Auth failures (KMIP credential, TLS handshake, remoting PIN) | `rust/src/authlog.rs` | `PQC_BEHAVIOUR_RING` |

Record and file layout, the producer/consumer protocol, and the reader rules
(what a consumer does with a slot whose sequence number is behind or ahead) are
specified once, in the module doc of `rust/src/behaviour/mod.rs`; `BehaviourRing.h`
restates the record. Both engines assert the golden vectors in `ids.json`, which
is what makes one ring readable regardless of which engine wrote a slot.

Unset variable ⇒ no ring is mapped and every producer's check is one load.
Never on when a benchmark measures.
