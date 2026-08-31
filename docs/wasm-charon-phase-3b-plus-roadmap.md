# strongSwan WASM charon — Phase 3b+ implementation roadmap

> **Superseded (2026-08-31).** This roadmap targeted
> `strongswan-wasm-v2-shims/`, which was deleted on this date — real
> feature work (RFC 7383 fragmentation, RFC 9370 multi-KE, CHILD_SA)
> landed in the sibling `strongswan-wasm-shims/` (v1) tree instead, and v2
> was never carried past its Phase 3a/3b/3c/3d stubs described below. Kept
> for historical/reference value only; do not use this as an active plan.
> See `docs/remediation-plan-provider-wrapper-coverage-gaps-2026-08-31.md`
> §4.4 for the deletion rationale.

**Status as of 2026-04-22**: Phase 1 (boot + library_init) and Phase 3a
(library-level validators for ML-DSA + ML-KEM recognition) shipped. The
WASM binary **does not yet run an IKE handshake**; `wasm_vpn_configure_json`
and `wasm_vpn_initiate` are stubs that emit `phase3 TODO`. The pqctoday-hub
VPN simulator drives the UI step animation from log-string heuristics, not
from real charon bus events.

This document is the plan to close that gap. It targets Phase 3b–3e; Phase
3f (rekey + retransmit scenarios) is optional follow-up.

---

## 0. Entry points and their current state

| Export | Location | Today | Phase to finish |
|---|---|---|---|
| `wasm_vpn_boot` | `charon_wasm_main.c` ~L130 | `library_init()` + plugin load + softhsmv3 probe | ✅ shipped |
| `wasm_vpn_pkcs11_probe` | ~L200 | Lists PQC mechanisms from the HSM | ✅ shipped |
| `wasm_vpn_ml_dsa_selftest` | ~L268 | Full PKCS#11 ML-DSA-65 sign+verify | ✅ shipped |
| `wasm_vpn_ml_kem_selftest` | ~L420 | ML-KEM-768 KAT loopback | ✅ shipped |
| `wasm_vpn_kem_alice_*` / `_bob_*` | ~L440 | Stepwise ML-KEM for cross-worker flow | ✅ shipped |
| `wasm_vpn_validate_proposal` | ~L610 | Charon `proposal_create_from_string()` | ✅ shipped (Phase 3a) |
| `wasm_vpn_validate_cert` | ~L645 | Charon `lib->creds->create(...X509, PEM)` | ✅ shipped (Phase 3a) |
| `wasm_vpn_list_key_exchanges` | ~L690 | Dump ML-KEM transform IDs 35/36/37 | ✅ shipped (Phase 3a) |
| **`wasm_vpn_configure_json`** | ~L575 | Stub `phase3 TODO` | **Phase 3b** |
| **`wasm_vpn_initiate`** | ~L585 | Stub `phase3 TODO` | **Phase 3c + 3d** |
| **`wasm_vpn_get_result`** | ~L595 | Returns `{"phase":"boot","status":"stub"}` | **Phase 3e** |

---

## 1. Phase 3b — Configuration ingestion

**Goal**: `wasm_vpn_configure_json(const char *json)` accepts a single JSON
blob covering everything charon needs to initiate or respond to an IKE_SA,
builds in-memory `peer_cfg_t` / `ike_cfg_t` / `child_cfg_t` / `auth_cfg_t`
structures, and registers a `pkcs11_creds_t` credential set rooted on the
softhsmv3 token. After this the WASM can *look up* a peer config by name
but still does not fire a handshake.

### 1.1 JSON schema

```jsonc
{
  "role": "initiator" | "responder",
  "local_id":  "CN=vpn-initiator@pqctoday",
  "remote_id": "CN=vpn-responder@pqctoday",

  "ike_proposal":  "aes256-sha256-mlkem768",
  "esp_proposal":  "aes256gcm16-noesn",

  "auth_method": "psk" | "pubkey",
  "psk":         "pqc-wasm-demo-key-2026",      // only if auth_method=psk
  "cert_pem":    "-----BEGIN CERTIFICATE-----\n...",  // only if pubkey
  "peer_cert_pem": "-----BEGIN CERTIFICATE-----\n...",

  "pkcs11": {
    "module": "static:softhsmv3",       // resolved by pkcs11_static.c
    "slot": 0,
    "pin": "1234",
    "cka_id_hex": "4b3c…20B",
    "key_type":   "ml-dsa-65" | "rsa-3072"
  },

  "local_ts":  ["10.0.0.0/24"],
  "remote_ts": ["10.0.1.0/24"],

  "mtu": 1500,
  "fragmentation": true,

  "mode": "classical" | "hybrid" | "pure-pqc"
}
```

### 1.2 Work breakdown

1. **Add `cJSON` (or jsmn) as a vendored dep** in `strongswan-wasm-v2-shims/`.
   Keep the footprint tiny; no dynamic allocation beyond what's already
   happening. Prefer `jsmn` — single-header, ~500 LOC, stack-only.
2. **Parse into an in-memory `struct wasm_vpn_cfg`** that mirrors the
   JSON 1:1. Validate every required field; emit structured errors via
   `wasm_vpn_emit("config_error", ...)`.
3. **Write `/etc/strongswan.d/wasm-vpn.conf`** into MEMFS with the
   minimal charon settings derived from the JSON (`charon.plugins.pkcs11.modules.softhsm`
   block, `charon.threads=1`, `charon.start-scripts` empty, etc.). Use
   `FS.writeFile` from Emscripten.
4. **Call `settings_t *s = settings_create(path)`** and install it as
   `lib->settings`. Re-init the plugin loader with the WASM-safe plugin
   list that picks up the new settings.
5. **Build the credentials set**:
   - Register `pkcs11_creds_t` created from the softhsmv3 slot.
   - If `cert_pem` is present, parse via `lib->creds->create(CRED_CERTIFICATE, CERT_X509, BUILD_BLOB_PEM, ...)`
     and add to a new `mem_cred_t`.
   - Wire both into `lib->credmgr->add_set(lib->credmgr, ...)`.
6. **Build `peer_cfg_t` / `ike_cfg_t` / `child_cfg_t`**:
   - `ike_cfg_create(...)` with host pair `(0.0.0.0, 0.0.0.0)` so the
     socket shim (Phase 3c) handles addressing.
   - `ike_cfg->add_proposal(proposal_create_from_string(PROTO_IKE, …))`.
   - `peer_cfg_create(...)` with identities from `local_id` / `remote_id`.
   - `auth_cfg_create(...)` with the right `AUTH_CLASS_PSK` or
     `AUTH_CLASS_PUBKEY` and cert identity.
   - `child_cfg_create(...)` + `child_cfg->add_proposal(...)` for ESP.
   - `peer_cfg->add_child_cfg(peer_cfg, child_cfg)`.
7. **Register the peer_cfg** in a module-level `backend_t` shim that
   responds to `backend->create_peer_cfg_enumerator`. This is needed so
   `charon->controller->initiate()` later can find it by name.
8. **Return 0 on success, non-zero on any parse/build failure**; emit
   `configure_ok` event with the peer-cfg name.

### 1.3 Files touched

- `strongswan-wasm-v2-shims/charon_wasm_main.c` (implement the function)
- `strongswan-wasm-v2-shims/wasm_vpn_cfg.{h,c}` (NEW — config struct + parser)
- `strongswan-wasm-v2-shims/mem_backend.{h,c}` (NEW — peer_cfg registrar)
- `strongswan-wasm-v2-shims/jsmn.h` (NEW — vendored)
- `scripts/build-strongswan-wasm-v2.sh` (add the 2 new .c files to the link)

### 1.4 Acceptance

A Node test (`strongswan-wasm-v2-shims/test-phase3b-config.mjs`) that:
- Boots the WASM.
- Sends a well-formed JSON blob.
- Queries `charon->backends->create_peer_cfg_enumerator()` (via a new
  helper export `wasm_vpn_has_peer_cfg(name)`) and confirms the named
  peer config exists.
- Sends a malformed blob (missing `ike_proposal`) and confirms
  `config_error` is emitted with the expected field name.

---

## 2. Phase 3c — Real IKE over SAB

**Goal**: Charon's sender/receiver packet path runs end to end between two
WASM instances (initiator worker + responder worker) over the existing
`socket_wasm.c` ring buffers. No state machine drive yet — this phase proves
raw IKE packets serialize, transit, and deserialize with the right
payloads.

### 2.1 The socket story

`socket_wasm.c` already plants a single `FAKE_SOCKFD=42` whose `read()` and
`write()` go through a pair of SharedArrayBuffer rings (one per direction).
Each WASM instance sees its counterpart through this fd. What's missing:

1. **Hook the socket plugin**: charon normally loads `socket-default` which
   opens UDP/500 and UDP/4500 via `socket(AF_INET, SOCK_DGRAM)`. Replace
   with a new `socket-wasm` plugin that returns `FAKE_SOCKFD`.
2. **Address-family shim**: `packet->get_source()` / `get_destination()`
   must return sensible `host_t *` values. Use fake `host_create_from_string("192.0.2.1", 500)`
   for initiator and `192.0.2.2` for responder. The SAB is the transport,
   the addresses are just labels.
3. **NAT-D calculation**: charon's NAT detection hashes IP+port. With fake
   addresses, `initiator` and `responder` will both compute stable values
   and NAT detection will show "no NAT" — correct.

### 2.2 Boot sequence (per worker)

```
wasm_vpn_boot()
  library_init()
  plugin_loader->load("pkcs11 x509 pubkey pkcs11 ...  socket-wasm")
  charon->bus->add_listener(our_listener)

wasm_vpn_configure_json(json)
  build peer_cfg, register in mem_backend

wasm_vpn_initiate()              # Phase 3d will implement this
  charon->controller->initiate(peer_cfg, child_cfg, null, ...)
```

### 2.3 What the sender does

Charon's `message.c` serializes an `IKE_SA_INIT` message: SA, KE, Ni,
optional NAT_DETECTION_*, fragmentation-supported. With our WASM
config:

- For **classical**: `KE` carries an ECP-256 public key.
- For **hybrid**: `KE` carries ECP-256; an `IKE_INTERMEDIATE` message
  follows with an `ADDITIONAL_KEY_EXCHANGE` payload carrying an ML-KEM-768
  encapsulation key (draft-ietf-ipsecme-ikev2-mlkem).
- For **pure-pqc**: `KE` carries an ML-KEM-768 encapsulation key (transform
  ID 36). Responder returns a `KE` with the ML-KEM ciphertext.

Charon already has all this logic — the library patch shipped the
`ML_KEM_{512,768,1024}` enum, and key_exchange.c has the callback table.
What we need:

- Confirm the WASM's `pkcs11_dh.c` (in our fork) reports
  `CKM_ML_KEM` as supported so charon's negotiation picks `ML_KEM_768` when
  the proposal offers it.
- Confirm the `ike_init` task hooks the KE payload correctly to
  `key_exchange->get_public_key()` where the `key_exchange_t` is backed by
  our pkcs11_kem.

### 2.4 Two-worker flow

```
Initiator worker                         Responder worker
────────────────                         ────────────────
wasm_vpn_boot()                          wasm_vpn_boot()
wasm_vpn_configure_json(init-json)       wasm_vpn_configure_json(resp-json)
wasm_vpn_initiate()                      (passive — waits on socket)
   |                                          |
   | charon builds IKE_SA_INIT ---SAB--->  charon parses IKE_SA_INIT
   |                                          charon builds response
   | charon parses response  <---SAB---     sends it
   |                                          |
   | (hybrid) build IKE_INTERMEDIATE ->     parses IKE_INTERMEDIATE
   |                                          responds with ML-KEM ct
   |                                          |
   | build IKE_AUTH (AUTH payload signed     parses AUTH via
   |   by ML-DSA/RSA through softhsmv3) ->    validate_cert + pkcs11
   |                                          checks identity, sends AUTH response
   |                                          |
   | parse AUTH response, authenticated <-
```

### 2.5 Files touched

- `strongswan-wasm-v2-shims/socket_wasm.c` (extend — currently a stub)
- `strongswan-wasm-v2-shims/plugin_socket_wasm.c` (NEW — plugin registration)
- `strongswan-wasm-v2-shims/charon_wasm_main.c` (register new plugin)
- `strongswan-wasm-v2-shims/bob-worker.mjs` (extend — today only handles KEM
  primitives; needs to handle IKE packet traffic)

### 2.6 Acceptance

- `test-phase3c-ike-init.mjs` — two-worker test that:
  1. Boots both; configures initiator as `initiator`, responder as `responder`.
  2. Initiator: `charon->sender->send(IKE_SA_INIT packet)`.
  3. Responder: verifies `bus->message` fires with the expected
     `IKE_SA_INIT_I`, correct proposal, KE payload size.
  4. Responder sends `IKE_SA_INIT_R`; initiator verifies receipt.
  5. For hybrid mode: same verification on `IKE_INTERMEDIATE_I` /
     `IKE_INTERMEDIATE_R` carrying `ADDITIONAL_KEY_EXCHANGE`.

---

## 3. Phase 3d — State-machine drive + event bridging

**Goal**: `wasm_vpn_initiate()` runs `charon->controller->initiate(...)` and
the state machine progresses to `IKE_AUTH` completion. Charon's `bus` events
stream out through `wasm_vpn_emit` so JS can display real-time progress.

### 3.1 Bus listener

Register a `listener_t` on `charon->bus` that forwards:

```c
static bool ike_updown(listener_t *this, ike_sa_t *ike_sa, bool up) {
    char buf[256];
    snprintf(buf, sizeof(buf), "{\"established\":%s,\"ike_spi_i\":\"%016llx\","
             "\"ike_spi_r\":\"%016llx\",\"proposal\":\"%s\"}",
             up ? "true" : "false",
             ike_sa->get_ike_sa_id(ike_sa)->get_initiator_spi(...),
             ike_sa->get_ike_sa_id(ike_sa)->get_responder_spi(...),
             proposal_to_str(ike_sa->get_proposal(ike_sa)));
    wasm_vpn_emit("ike_updown", buf);
    return TRUE;
}
```

Mirror for:
- `message()` — emit sanitized message type + direction (incoming/outgoing)
  on each IKE message.
- `authorize()` — emit the authenticated identity.
- `child_updown()` — emit child-SA establishment with negotiated transform.
- `alert()` — forward charon's error paths (`ALERT_PROPOSAL_MISMATCH_IKE`,
  `ALERT_LOCAL_AUTH_FAILED`, …).

### 3.2 ASYNCIFY considerations

Charon blocks on condvars during `IKE_SA_INIT` retransmit windows. With
ASYNCIFY + single-threaded execution, these blocks must yield back to JS.
`emscripten_sleep(0)` in the sender's retransmit loop already does this in
the current build. Verify the sleep call is reachable on the new code path
and extend to the authenticator threadpool (which we collapse to the
single thread via `charon.threads=1`).

### 3.3 The sender thread doesn't exist

Standard charon has `sender_t` running in its own thread pulling from a
queue. In our single-thread build, `sender_send()` must drain the queue
inline. Either:

- Patch `sender.c` to short-circuit when `charon.threads=1`, OR
- Call `charon->sender->send()` in the task-completion hook after every
  task (simpler, less invasive).

Recommendation: the second approach — less source modification.

### 3.4 Files touched

- `strongswan-wasm-v2-shims/charon_wasm_main.c` (bus listener + initiate impl)
- `strongswan-wasm-v2-shims/event_bridge.{h,c}` (NEW — JSON formatting helpers)

### 3.5 Acceptance

- `test-phase3d-ike-auth.mjs` — two-worker full handshake:
  1. PSK mode: classical, hybrid, pure-pqc × 2 (initiator, responder). 6 runs.
  2. Dual/pubkey mode (ML-DSA-65 certs): same 3 modes. 3 runs.
  3. Assert `ike_updown(up=true)` event fires on both sides.
  4. Assert negotiated transform matches expectation.
  5. Assert a cert-auth run populates the `authorize` event with the
     correct subject identity.
- Matches the sandbox's `/api/run/vpn/matrix` feature at parity.

---

## 4. Phase 3e — Structured result

**Goal**: `wasm_vpn_get_result()` returns a rich JSON capturing the real
outcome, replacing the static stub.

### 4.1 Result shape

```jsonc
{
  "phase": "completed" | "in_progress" | "failed",
  "role": "initiator" | "responder",
  "established": true,
  "timings": {
    "boot_ms":        12.4,
    "configure_ms":    1.2,
    "ike_init_rtt_ms": 42.0,
    "ike_auth_rtt_ms": 68.0,
    "total_ms":      124.8
  },
  "negotiated": {
    "ike_proposal":   "IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ML_KEM_768",
    "ike_group":      "ML_KEM_768",
    "esp_proposal":   "ESP:AES_GCM_16_256/NO_EXT_SEQ",
    "auth_method":    "ML-DSA-65",
    "auth_identity":  "CN=vpn-responder@pqctoday"
  },
  "payloads": {
    "ike_init_sent_bytes":     412,
    "ike_init_received_bytes": 408,
    "ike_intermediate_sent_bytes": 1520,   // hybrid/pqc only
    "ike_intermediate_received_bytes": 1496,
    "ike_auth_sent_bytes":     6212,       // ML-DSA-65 sig ~3309 B
    "ike_auth_received_bytes": 6180,
    "fragmentation_used":      true,
    "fragment_count_sent":     5
  },
  "spis": {
    "ike_spi_i": "a1b2c3d4e5f60708",
    "ike_spi_r": "1122334455667788",
    "esp_spi":   "cafe1234"
  },
  "hndl_risk": {
    "cert_chain_quantum_vulnerable": false,
    "ke_quantum_vulnerable":          false,
    "psk_used":                       false
  },
  "errors": []
}
```

### 4.2 Collection strategy

Pipe the bus listener's events into a static accumulator struct; dump it
as JSON at `get_result()` time. Keep the buffer at `static char[4096]`
(no dynamic alloc).

### 4.3 Files touched

- `strongswan-wasm-v2-shims/charon_wasm_main.c` (accumulator + formatter)

### 4.4 Acceptance

- `test-phase3e-result.mjs` — runs a handshake through Phase 3d, calls
  `wasm_vpn_get_result()`, and asserts:
  - `established === true`.
  - `negotiated.ike_group` reflects the selected mode.
  - `payloads.ike_auth_sent_bytes > 5000` in ML-DSA-65 cert-auth mode.

---

## 5. Cross-cutting concerns

### 5.1 Threading

Charon's `libhydra` expects 4–16 threads. We force `charon.threads=1`.
Verify no plugin tries to `thread_create()`:

- `kernel-netlink` — not loaded (IPsec SA install doesn't apply in-browser).
- `resolve` — not loaded (no DNS).
- `attr-sql` — not loaded.
- The remaining plugin set (`pem pkcs1 pkcs8 x509 pubkey openssl pkcs11
  random nonce sha2 aes gcm socket-wasm`) must be verified for zero
  `thread_create` calls.

Add a `-DNO_PTHREAD` guard in `charon_wasm_main.c` that wraps around the
plugin loader to abort on any `thread_create` attempt.

### 5.2 Plugin stubs required

A minimal set of no-op stubs is needed so the state machine doesn't
assert:

| Plugin | Status | What's needed |
|---|---|---|
| `kernel-netlink` | Not linked | Replace with `kernel-wasm` stub that accepts `add_sa`/`del_sa` and returns success without installing |
| `resolve` | Not linked | Skip. Use literal IPs in peer config |
| `revocation` | Not linked | Skip. CRL/OCSP lookup is out of scope |
| `eap-*` | Not linked | EAP auth not supported in-browser (yet) |
| `agent` | Not linked | ssh-agent not applicable |

### 5.3 Two-worker coordination

The SAB ring in `socket_wasm.c` handles bytes but not:

- **Message ID consistency**: charon uses monotonic message IDs; both sides
  must agree. Verify existing code handles cross-worker state
  initialization.
- **Retransmit timers**: charon uses `scheduler_t` to schedule
  retransmits. Under ASYNCIFY single-thread, the scheduler must be pumped
  by a JS-driven "tick" call — add `wasm_vpn_pump()` that advances
  charon's `scheduler->execute` queue once.
- **Dead-peer detection**: defer to Phase 3f.

### 5.4 OpenSSL provider

Charon's `openssl` plugin is currently linked. Verify it uses the
`openssl-wasm` static libcrypto without attempting system-wide
`libssl.so` loads.

---

## 6. Hub UI integration (Phase 3g — hub side)

After Phase 3e lands, update [VpnSimulationPanel.tsx](../../pqctoday-hub/src/components/Playground/hsm/VpnSimulationPanel.tsx):

1. Replace the `strongSwanEngine` JS mock with calls into `bridge-v2.ts`:
   `configureVpn(json)`, `initiateVpn()`, `getVpnResult()`.
2. Drive the step-counter from real `ike_updown` / `child_updown` events,
   not log-string heuristics.
3. Populate the handshake-diagram byte counts from `result.payloads.*`.
4. Populate the Fragmentation indicator from `result.payloads.fragmentation_used`.
5. Remove the "simulation" badges added by the scope-transparency pass.

Cross-worker coordination in the browser: main thread runs initiator;
[strongswan-v2-bob-worker.js](../../pqctoday-hub/public/wasm/strongswan-v2-bob-worker.js)
runs responder. Bob-worker today only handles KEM primitives — extend to
dispatch `wasm_vpn_configure_json` and `wasm_vpn_initiate` with the
responder role.

---

## 7. Effort estimate

| Phase | Scope | Estimate |
|---|---|---|
| 3b | Config ingestion + credentials + mem_backend | 1–2 days |
| 3c | Socket plugin + two-worker IKE message transit | 3–5 days |
| 3d | State-machine drive + bus event bridging | 2–3 days |
| 3e | Structured result collector | 1 day |
| Cross-cutting | Plugin stubs, threading audit, OpenSSL provider | 2 days |
| 3g | Hub UI migration off the JS mock | 1–2 days |
| **Total** | | **~10–15 days** |

---

## 8. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Charon calls `pthread_create` on a non-stubbed path | Medium | High | Audit with a link-time trap; fall back to `kernel-wasm` no-op |
| ASYNCIFY stack growth explodes | Medium | High | Profile with `-s ASYNCIFY_STACK_SIZE=65536` baseline, increase as needed |
| `message.c` parse assumes contiguous buffer; SAB wraparound breaks | Low | Medium | Serialize into a heap-allocated contiguous buffer before calling `message->parse()` |
| Responder-side peer-cfg selection fails (`no matching peer_cfg for traffic selector`) | Medium | Medium | Relax `local_ts` / `remote_ts` to `0.0.0.0/0` in v0; tighten once working |
| Two workers race on initial nonce | Low | Low | Use deterministic seeds in test harness; production non-issue |

---

## 9. Out of scope (Phase 3f / future)

- **Rekey** (`CREATE_CHILD_SA` with ML-KEM-768)
- **Retransmit + loss simulation** (drop N% of SAB writes)
- **MOBIKE** (`UPDATE_SA_ADDRESSES`)
- **EAP methods** (EAP-TLS, EAP-MSCHAPv2)
- **NAT-T** (UDP encapsulation — irrelevant in-browser)
- **Post-quantum AUTH payload** (beyond ML-DSA — e.g., composite sigs)

---

## 10. Deliverables checklist

- [ ] `wasm_vpn_cfg.{h,c}` — JSON → cfg struct
- [ ] `jsmn.h` — vendored JSON parser
- [ ] `mem_backend.{h,c}` — peer_cfg registrar
- [ ] `plugin_socket_wasm.c` — socket-wasm plugin
- [ ] `event_bridge.{h,c}` — bus listener + JSON formatter
- [ ] `charon_wasm_main.c` — replace 3 stub functions, register plugin + listener
- [ ] `bob-worker.mjs` — accept configure + initiate messages
- [ ] `scripts/build-strongswan-wasm-v2.sh` — extend link line
- [ ] `test-phase3b-config.mjs`
- [ ] `test-phase3c-ike-init.mjs`
- [ ] `test-phase3d-ike-auth.mjs`
- [ ] `test-phase3e-result.mjs`
- [ ] Hub: `bridge-v2.ts` helpers for configure/initiate/result
- [ ] Hub: `VpnSimulationPanel.tsx` real-event driver
- [ ] Hub: `strongswan-v2-bob-worker.js` extended for IKE traffic

---

## 11. How to pick up this plan

Start with **Phase 3b, step 1.2** (JSON parser). Drop `jsmn.h` into
`strongswan-wasm-v2-shims/`, scaffold `wasm_vpn_cfg.c` with the struct
definition, add one test that parses a minimal blob. That's a ~200-line,
half-day increment that unblocks everything else.
