// SLH-DSA keygen/sign timing for the softhsmrustv3 WASM engine under Node.
//
// Measurement tool for the KV260 hash-signature plan (owner decision
// 2026-09-24, item 1: do the per-package opt-level overrides speed up the
// wasm build?). It drives the engine through its PKCS#11 exports exactly as
// test_p11_conformance.js does (same wasm32 CK_ATTRIBUTE/CK_MECHANISM
// layouts), so a sign is C_SignInit + C_Sign on a token key.
//
// Usage: node bench_wasm_slh.js <pkg dir> [iters] [ckp,...]
//   <pkg dir> holds softhsmrustv3_bg.wasm + softhsmrustv3_bg.js
//             (wasm-bindgen --target bundler, i.e. what build-wasm-bundle.sh makes)
// Prints min/median keygen and sign ms per parameter set, and a short
// SHA-256 of the last public key so two builds can be compared for keygen
// output (signatures are hedged, so they differ run to run).

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const dir = path.resolve(process.argv[2] || 'pkg');
const iters = parseInt(process.argv[3] || '3', 10);
const sets = (process.argv[4] || '1,2,9')
  .split(',').map((s) => parseInt(s, 10));

const wasmBuf = fs.readFileSync(path.join(dir, 'softhsmrustv3_bg.wasm'));
const bg = require(path.join(dir, 'softhsmrustv3_bg.js'));
const inst = new WebAssembly.Instance(new WebAssembly.Module(wasmBuf), {
  './softhsmrustv3_bg.js': bg,
});
bg.__wbg_set_wasm(inst.exports);
const w = inst.exports;
const mem = () => w.memory;

const CKA = { CLASS: 0x000, KEY_TYPE: 0x100, VALUE: 0x011, PARAMETER_SET: 0x61d };
const CKO = { PUBLIC_KEY: 2, PRIVATE_KEY: 3 };
const CKK_SLH_DSA = 0x4b;
const CKM = { SLH_DSA_KEY_PAIR_GEN: 0x2d, SLH_DSA: 0x2e };
const NAMES = { 1: 'SLH-DSA-SHA2-128s', 2: 'SLH-DSA-SHAKE-128s', 3: 'SLH-DSA-SHA2-128f',
  4: 'SLH-DSA-SHAKE-128f', 5: 'SLH-DSA-SHA2-192s', 6: 'SLH-DSA-SHAKE-192s',
  9: 'SLH-DSA-SHA2-256s', 10: 'SLH-DSA-SHAKE-256s' };

const alloc = (n) => w._malloc(n);
const writeBytes = (p, b) => new Uint8Array(mem().buffer, p, b.length).set(b);
const readU32 = (p) => new Uint32Array(mem().buffer, p, 1)[0];
const writeU32 = (p, v) => { new Uint32Array(mem().buffer, p, 1)[0] = v; };
function buildTpl(attrs) {
  const ptr = alloc(attrs.length * 12 + attrs.length * 4 + 8);
  let d = ptr + attrs.length * 12;
  attrs.forEach((a, i) => {
    const v = new Uint8Array(new Uint32Array([a.ulong]).buffer);
    writeBytes(d, v);
    writeU32(ptr + i * 12, a.type); writeU32(ptr + i * 12 + 4, d); writeU32(ptr + i * 12 + 8, 4);
    d += 4;
  });
  return ptr;
}
function buildMech(m) { const p = alloc(12); writeU32(p, m); writeU32(p + 4, 0); writeU32(p + 8, 0); return p; }
function ok(label, rv) { if (rv !== 0) throw new Error(`${label} → 0x${rv.toString(16)}`); }

ok('C_Initialize', w._C_Initialize(0));
const so = new TextEncoder().encode('so-pin-1234');
const user = new TextEncoder().encode('user-pin-1234');
const pSo = alloc(so.length); writeBytes(pSo, so);
const pUser = alloc(user.length); writeBytes(pUser, user);
const label = new Uint8Array(32).fill(0x20); label.set(new TextEncoder().encode('bench'));
const pLabel = alloc(32); writeBytes(pLabel, label);
ok('C_InitToken', w._C_InitToken(0, pSo, so.length, pLabel));
const pH = alloc(4);
ok('C_OpenSession', w._C_OpenSession(0, 6, 0, 0, pH));
const hS = readU32(pH);
ok('C_Login(SO)', w._C_Login(hS, 0, pSo, so.length));
ok('C_InitPIN', w._C_InitPIN(hS, pUser, user.length));
ok('C_Logout', w._C_Logout(hS));
ok('C_Login(USER)', w._C_Login(hS, 1, pUser, user.length));

const msg = new TextEncoder().encode('hashsig wasm timing message');
const pMsg = alloc(msg.length); writeBytes(pMsg, msg);
const ms = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;
const min = (a) => Math.min(...a);
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];

for (const ps of sets) {
  const kg = [], sg = [];
  let pubHash = '';
  let prv = 0;
  for (let i = 0; i < iters; i++) {
    const pub = [{ type: CKA.CLASS, ulong: CKO.PUBLIC_KEY }, { type: CKA.KEY_TYPE, ulong: CKK_SLH_DSA },
      { type: CKA.PARAMETER_SET, ulong: ps }];
    const prvT = [{ type: CKA.CLASS, ulong: CKO.PRIVATE_KEY }, { type: CKA.KEY_TYPE, ulong: CKK_SLH_DSA },
      { type: CKA.PARAMETER_SET, ulong: ps }];
    const hPub = alloc(4), hPrv = alloc(4);
    const t0 = process.hrtime.bigint();
    ok('C_GenerateKeyPair', w._C_GenerateKeyPair(hS, buildMech(CKM.SLH_DSA_KEY_PAIR_GEN),
      buildTpl(pub), pub.length, buildTpl(prvT), prvT.length, hPub, hPrv));
    kg.push(ms(t0));
    prv = readU32(hPrv);
    // public key bytes (CKA_VALUE) as a keygen-output fingerprint
    const attr = alloc(12); writeU32(attr, CKA.VALUE); writeU32(attr + 4, 0); writeU32(attr + 8, 0);
    ok('C_GetAttributeValue', w._C_GetAttributeValue(hS, readU32(hPub), attr, 1));
    const len = readU32(attr + 8); const buf = alloc(len); writeU32(attr + 4, buf);
    ok('C_GetAttributeValue', w._C_GetAttributeValue(hS, readU32(hPub), attr, 1));
    pubHash = crypto.createHash('sha256').update(new Uint8Array(mem().buffer, buf, len)).digest('hex').slice(0, 12);
  }
  for (let i = 0; i < iters; i++) {
    // One C_Sign into a buffer large enough for any parameter set (49,856 B
    // max), so no length-query call is timed.
    const pLen = alloc(4); writeU32(pLen, 50000);
    const pSig = alloc(50000);
    const t0 = process.hrtime.bigint();
    ok('C_SignInit', w._C_SignInit(hS, buildMech(CKM.SLH_DSA), prv));
    ok('C_Sign', w._C_Sign(hS, pMsg, msg.length, pSig, pLen));
    sg.push(ms(t0));
  }
  console.log(`${(NAMES[ps] || ps).padEnd(20)} keygen min ${min(kg).toFixed(1).padStart(8)} med ${med(kg).toFixed(1).padStart(8)} ms | sign min ${min(sg).toFixed(1).padStart(8)} med ${med(sg).toFixed(1).padStart(8)} ms (n=${iters}) pk ${pubHash}`);
}
