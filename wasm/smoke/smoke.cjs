#!/usr/bin/env node
/*
 * smoke.cjs — proves the in-browser KMIP+PKCS#11 wasm bundle actually RUNS in a
 * JS host: it boots a softhsmrustv3 engine session inside wasm, decodes a real
 * OASIS KMIP 3.0 TTLV Request Message, dispatches it through the (server-less)
 * dispatcher, and encodes a TTLV Response Message back — the same
 * decode → dispatch → encode seam the TLS listener runs, minus the transport.
 *
 * Run (host node, the wasm is portable):  node wasm/smoke/smoke.cjs
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const { KmipPlayground } = require('../pkg_node/pqctoday_kmip_wasm.js');

const CORPUS = path.join(__dirname, '..', '..', 'kmip', 'conformance', 'oasis_corpus_bytes', 'pristine');
const readReq = (name) => new Uint8Array(fs.readFileSync(path.join(CORPUS, name)));

// KMIP 3.0 §6 — a Response Message is TTLV tag 0x42007B, type 0x01 (Structure).
const RESPONSE_MESSAGE_TAG = [0x42, 0x00, 0x7b, 0x01];
// KMIP TTLV for `ResultStatus = Success`: tag 0x42007F, type 0x05 (Enumeration),
// length 0x00000004, value 0x00000000 (ResultStatus::Success.to_wire_value()).
const RESULT_STATUS_SUCCESS = [0x42, 0x00, 0x7f, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
const hex = (u8, n = 8) => Buffer.from(u8.slice(0, n)).toString('hex');
const containsRun = (hay, needle) => {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
};

function expectResponseMessage(resp, label) {
  assert.ok(resp instanceof Uint8Array, `${label}: submit() returned a byte array`);
  assert.ok(resp.length > 8, `${label}: response is a non-empty TTLV frame (got ${resp.length} bytes)`);
  for (let i = 0; i < RESPONSE_MESSAGE_TAG.length; i++) {
    assert.strictEqual(resp[i], RESPONSE_MESSAGE_TAG[i],
      `${label}: top-level tag is ResponseMessage (0x42007B/Structure), got 0x${hex(resp, 4)}`);
  }
}

console.log('[smoke] instantiating KmipPlayground (boots softhsmrustv3 engine in wasm)…');
const pg = new KmipPlayground();
console.log('[smoke]   ✓ engine session bootstrapped inside wasm');

// ── Step 1 — Query (stateless): proves decode → dispatch → encode + that the
// handler read live server state (DepsConfig vendor identification). ─────────
console.log('[smoke] submitting OASIS Query request (QS-M-1-30)…');
const queryResp = pg.submit(readReq('QS-M-1-30__00__req.bin'));
expectResponseMessage(queryResp, 'Query');
assert.ok(containsRun(queryResp, RESULT_STATUS_SUCCESS),
  'Query: response carries ResultStatus = Success (the dispatcher handled the op, not an error frame)');
console.log(`[smoke]   ✓ Query → ${queryResp.length}-byte ResponseMessage, ResultStatus = Success`);

// ── Step 2 — Create a symmetric key: proves REAL key generation runs inside
// wasm through the engine (Plane 2 dispatcher → Plane 3 softhsmrustv3). ──────
console.log('[smoke] submitting OASIS Create (symmetric key) request (SKFF-M-1-30)…');
const createResp = pg.submit(readReq('SKFF-M-1-30__00__req.bin'));
expectResponseMessage(createResp, 'Create');
assert.ok(containsRun(createResp, RESULT_STATUS_SUCCESS),
  'Create: response carries ResultStatus = Success (the engine generated a real key in wasm)');
console.log(`[smoke]   ✓ Create → ${createResp.length}-byte ResponseMessage, ResultStatus = Success (real keygen in wasm)`);

// ── Step 3 — a malformed frame must NOT throw; it must come back as a
// well-formed ResponseMessage (mirrors the listener's wire-error path). ──────
console.log('[smoke] submitting a deliberately malformed frame…');
const garbageResp = pg.submit(new Uint8Array([0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]));
expectResponseMessage(garbageResp, 'Malformed');
console.log(`[smoke]   ✓ malformed input → ${garbageResp.length}-byte ResponseMessage (no exception)`);

// ── Step 4 — full PQC signature lifecycle via the high-level run_op API:
// CreateKeyPair(ML-DSA-65) → Activate → Sign → SignatureVerify. Proves the
// three planes (policy gate → KMIP ops → real ML-DSA crypto) end-to-end. ─────
const runOp = (spec) => JSON.parse(pg.run_op(JSON.stringify(spec)));

console.log('[smoke] CreateKeyPair ML-DSA-65 …');
const ckp = runOp({ op: 'CreateKeyPair', algorithm: 'ML-DSA-65' });
assert.ok(ckp.ok, `CreateKeyPair ok (status=${ckp.status}, msg=${ckp.message})`);
const privUid = ckp.summary.privateKeyUid, pubUid = ckp.summary.publicKeyUid;
assert.ok(privUid && pubUid, 'CreateKeyPair returned private + public UIDs');
assert.ok(Array.isArray(ckp.audit) && ckp.audit.length > 0, 'op emitted audit events across planes');
console.log(`[smoke]   ✓ keypair: priv=${privUid.slice(0, 24)}… pub=${pubUid.slice(0, 24)}… (${ckp.audit.length} audit events)`);

assert.ok(runOp({ op: 'Activate', uid: privUid }).ok, 'Activate private key');
assert.ok(runOp({ op: 'Activate', uid: pubUid }).ok, 'Activate public key');

console.log('[smoke] Sign with ML-DSA-65 …');
const sig = runOp({ op: 'Sign', uid: privUid, text: 'hello post-quantum world' });
assert.ok(sig.ok, `Sign ok (msg=${sig.message})`);
assert.ok(sig.summary.signatureLen > 2000, `ML-DSA-65 signature is real (~3309 bytes, got ${sig.summary.signatureLen})`);
console.log(`[smoke]   ✓ signature: ${sig.summary.signatureLen} bytes`);

console.log('[smoke] SignatureVerify …');
const ver = runOp({ op: 'SignatureVerify', uid: pubUid, text: 'hello post-quantum world', signature: sig.summary.signatureHex });
assert.ok(ver.ok, `Verify op ok (msg=${ver.message})`);
assert.ok(/Valid/.test(ver.summary.validity), `signature validates (got ${ver.summary.validity})`);
console.log(`[smoke]   ✓ verify: ${ver.summary.validity} — full ML-DSA-65 sign/verify roundtrip in wasm`);

// ── Step 5 — introspection surfaces the UI binds to. ────────────────────────
const objs = JSON.parse(pg.list_objects());
assert.ok(objs.length >= 2 && objs.some(o => o.algorithm === 'ML-DSA-65'), `keystore lists the ML-DSA-65 objects (${objs.length} total)`);
const pol = JSON.parse(pg.policy_status());
assert.ok(pol.active, 'a policy is active');
const audit = JSON.parse(pg.audit_snapshot(200));
assert.ok(audit.length > 0 && audit.every(e => e.plane && e.event), 'audit snapshot has plane-tagged events');
const tree = JSON.parse(decode(sig.responseWireHex));
console.log(`[smoke]   ✓ list_objects=${objs.length}, policy="${pol.name}", audit=${audit.length} events`);

// ── Step 6 — H1: a present-but-unknown algorithm must fail, not silently
// fall back to a default (which would test a different request than the UI
// shows). CreateKeyPair with an algorithm the engine doesn't implement.
console.log('[smoke] CreateKeyPair with an unimplemented algorithm (FrodoKEM-1344) …');
const bogus = runOp({ op: 'CreateKeyPair', algorithm: 'FrodoKEM-1344' });
assert.ok(!bogus.ok, 'unknown algorithm must produce a failed OpResult, not a silent default keypair');
assert.ok(/unknown algorithm/i.test(bogus.message || ''),
  `error names the unknown algorithm (got: ${bogus.message})`);
const objsAfter = JSON.parse(pg.list_objects());
assert.strictEqual(objsAfter.length, objs.length,
  'a rejected unknown-algorithm request creates no object');
console.log(`[smoke]   ✓ rejected: "${bogus.message}" (keystore unchanged at ${objsAfter.length})`);

console.log('\n[smoke] PASS — the KMIP+PKCS#11 control plane runs end-to-end in wasm.');

// decode helper: turn the hex response wire back into a TTLV tree via the wasm decoder.
function decode(hex) {
  const bytes = Uint8Array.from(hex.match(/../g).map(h => parseInt(h, 16)));
  return require('../pkg_node/pqctoday_kmip_wasm.js').decode_ttlv(bytes);
}
