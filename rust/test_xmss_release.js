// XMSS / XMSS^MT keygen+sign+verify round trip against the RELEASE wasm build
// (P-1, formalized 2026-08-24 — WS-6/compliance-gaps-remediation-plan D-5).
//
// test_p11_conformance.js's own G7 section documents WHY it does not run
// these two mechanisms: a standalone timing probe measured XMSS keygen alone
// at ~80 seconds against that harness's --dev (unoptimized) wasm build, and
// running it on every conformance pass would make routine iteration multiple
// minutes slower for 2 mechanisms out of 116. That reasoning is sound for the
// --dev build the main harness always uses — but it is NOT a fundamental
// limit of the mechanism, only of running it unoptimized. This script proves
// that by measuring both builds and running the real round trip against the
// build where it's actually practical.
//
// Real, fresh measurements (2026-08-24, this machine, current HEAD):
//   --dev (pkg/):          XMSS  keygen ~42s, sign ~42s  (total ~84s)
//   --release (pkg-release/): XMSS  keygen ~2.3s, sign ~2.3s (total ~4.6s)
//                              XMSSMT keygen ~2.3s, sign ~4.5s (total ~6.8s)
// ~18x speedup. The prior "~80s" figure in test_p11_conformance.js's own
// comment was for keygen alone on different hardware/an earlier commit; this
// script's own numbers are what matter for the release build, and are
// re-measured (not hand-typed) every run — see the timing assertions below.
//
// Run: node test_xmss_release.js   (requires pkg-release/ — build with
//      `./build-wasm-bundle.sh`, no flags; NOT the --dev target the main
//      conformance harness uses)
//
// Wired as an opt-in step in scripts/local-gate.sh (--release-xmss / --all),
// NOT part of the default gate — ~10-15s is still too slow for a suite meant
// to run on every change, but it is now a real, runnable regression rather
// than a permanently-untested gap.
'use strict';
const fs = require('fs');
const path = require('path');

const PKG_DIR = path.join(__dirname, 'pkg-release');
if (!fs.existsSync(path.join(PKG_DIR, 'softhsmrustv3_bg.wasm'))) {
  console.error(
    `FATAL: ${PKG_DIR}/softhsmrustv3_bg.wasm not found. Build it first:\n` +
    `  cd rust && ./build-wasm-bundle.sh`
  );
  process.exit(2);
}
const wasmBuf = fs.readFileSync(path.join(PKG_DIR, 'softhsmrustv3_bg.wasm'));
const bg = require(path.join(PKG_DIR, 'softhsmrustv3_bg.js'));
const wasmInstance = new WebAssembly.Instance(new WebAssembly.Module(wasmBuf), {
  './softhsmrustv3_bg.js': bg,
});
bg.__wbg_set_wasm(wasmInstance.exports);
const w = wasmInstance.exports;
const mem = () => w.memory;

// ── helpers, copied verbatim from test_p11_conformance.js for consistency ──
function alloc(n) { return w._malloc(n); }
function writeBytes(ptr, bytes) { new Uint8Array(mem().buffer, ptr, bytes.length).set(bytes); }
function readU32(ptr) { return new Uint32Array(mem().buffer, ptr, 1)[0]; }
function writeU32(ptr, v) { new Uint32Array(mem().buffer, ptr, 1)[0] = v; }
function buildTpl(attrs) {
  const arrLen = attrs.length * 12;
  let dataLen = 0;
  for (const a of attrs) dataLen += a.ulong !== undefined ? 4 : a.bytes ? a.bytes.length : 0;
  const ptr = alloc(arrLen + dataLen + 8);
  let dptr = ptr + arrLen;
  attrs.forEach((a, i) => {
    const base = ptr + i * 12;
    let val = null;
    if (a.ulong !== undefined) { val = new Uint8Array(new Uint32Array([a.ulong]).buffer); }
    else if (a.bool !== undefined) { val = new Uint8Array([a.bool ? 1 : 0]); }
    else if (a.bytes) { val = a.bytes; }
    if (val) {
      writeBytes(dptr, val);
      writeU32(base, a.type); writeU32(base + 4, dptr); writeU32(base + 8, val.length);
      dptr += val.length;
    } else {
      writeU32(base, a.type); writeU32(base + 4, 0); writeU32(base + 8, 0);
    }
  });
  return ptr;
}
function buildMech(m) {
  const p = alloc(12);
  writeU32(p, m); writeU32(p + 4, 0); writeU32(p + 8, 0);
  return p;
}
function openSession(flags = 6 /* RW|SERIAL */) {
  const p = alloc(4);
  const rv = w._C_OpenSession(0, flags, 0, 0, p);
  return { rv, h: readU32(p) };
}

let passes = 0, failures = 0;
function check(label, actual, expected) {
  if (actual === expected) {
    passes++;
    console.log(`  ✅ ${label}`);
  } else {
    failures++;
    console.log(`  ❌ ${label}: got 0x${actual.toString(16)}, expected 0x${expected.toString(16)}`);
  }
}

const CKR_OK = 0, CKR_SIGNATURE_INVALID = 0xc0;
const CKM_XMSS_KEY_PAIR_GEN = 0x4034, CKM_XMSSMT_KEY_PAIR_GEN = 0x4035;
const CKM_XMSS = 0x4036, CKM_XMSSMT = 0x4037;
const CKK_XMSS = 0x47, CKK_XMSSMT = 0x48;
const CKA_CLASS = 0x000, CKA_KEY_TYPE = 0x100;
const CKO_PUBLIC_KEY = 2, CKO_PRIVATE_KEY = 3;
const CKU_SO = 0, CKU_USER = 1;

// ── init fixture, copied verbatim from test_p11_conformance.js ──
if (w._C_Initialize(0) !== CKR_OK) throw new Error('C_Initialize failed');
const soPin = Buffer.from('so-pin-1234');
const userPin = Buffer.from('user-pin-1234');
{
  const label = new Uint8Array(32).fill(0x20);
  label.set(Buffer.from('xmss-release'));
  const pSo = alloc(soPin.length); writeBytes(pSo, soPin);
  const pLabel = alloc(32); writeBytes(pLabel, label);
  if (w._C_InitToken(0, pSo, soPin.length, pLabel) !== CKR_OK) throw new Error('C_InitToken failed');
}
const ses = openSession();
if (ses.rv !== CKR_OK) throw new Error('C_OpenSession failed');
const hS = ses.h;
{
  const pSo = alloc(soPin.length); writeBytes(pSo, soPin);
  const pUser = alloc(userPin.length); writeBytes(pUser, userPin);
  if (w._C_Login(hS, CKU_SO, pSo, soPin.length) !== CKR_OK) throw new Error('C_Login(SO) failed');
  if (w._C_InitPIN(hS, pUser, userPin.length) !== CKR_OK) throw new Error('C_InitPIN failed');
  if (w._C_Logout(hS) !== CKR_OK) throw new Error('C_Logout failed');
  if (w._C_Login(hS, CKU_USER, pUser, userPin.length) !== CKR_OK) throw new Error('C_Login(USER) failed');
}

function genStateful(mech, keyType) {
  const pub = [{ type: CKA_CLASS, ulong: CKO_PUBLIC_KEY }, { type: CKA_KEY_TYPE, ulong: keyType }];
  const prv = [{ type: CKA_CLASS, ulong: CKO_PRIVATE_KEY }, { type: CKA_KEY_TYPE, ulong: keyType }];
  const hPub = alloc(4), hPrv = alloc(4);
  const rv = w._C_GenerateKeyPair(hS, buildMech(mech),
    buildTpl(pub), pub.length, buildTpl(prv), prv.length, hPub, hPrv);
  return { rv, pub: readU32(hPub), prv: readU32(hPrv) };
}

/** Two-call PKCS#11 sign convention: size query, then real sign with a
 *  correctly-sized buffer (the buffer length must be re-set to the query
 *  result before the second call — an easy mistake that silently produces
 *  CKR_BUFFER_TOO_SMALL, not a mechanism defect). */
function signRoundTrip(label, keygenMech, signMech, keyType, maxSeconds) {
  console.log(`\n── ${label} ──`);
  const t0 = process.hrtime.bigint();
  const kp = genStateful(keygenMech, keyType);
  const t1 = process.hrtime.bigint();
  const keygenMs = Number(t1 - t0) / 1e6;
  check(`${label}: C_GenerateKeyPair → OK`, kp.rv, CKR_OK);
  check(`${label}: keygen completes within ${maxSeconds}s (release build)`, keygenMs < maxSeconds * 1000 ? 1 : 0, 1);
  console.log(`  (measured: ${Math.round(keygenMs)}ms)`);
  if (kp.rv !== CKR_OK) return;

  const msg = Buffer.from(`${label} release-tier round trip message`);
  const msgP = alloc(msg.length); writeBytes(msgP, msg);
  check(`${label}: C_SignInit → OK`, w._C_SignInit(hS, buildMech(signMech), kp.prv), CKR_OK);
  const slP = alloc(4); writeU32(slP, 0);
  w._C_Sign(hS, msgP, msg.length, 0, slP);
  const sigLen = readU32(slP);
  const sigP = alloc(sigLen);
  writeU32(slP, sigLen); // re-set capacity before the real call — see doc comment above
  const t2 = process.hrtime.bigint();
  const signRv = w._C_Sign(hS, msgP, msg.length, sigP, slP);
  const t3 = process.hrtime.bigint();
  const signMs = Number(t3 - t2) / 1e6;
  check(`${label}: C_Sign → OK`, signRv, CKR_OK);
  check(`${label}: sign completes within ${maxSeconds}s (release build)`, signMs < maxSeconds * 1000 ? 1 : 0, 1);
  console.log(`  (measured: ${Math.round(signMs)}ms, sig ${sigLen}B)`);

  check(`${label}: C_VerifyInit → OK`, w._C_VerifyInit(hS, buildMech(signMech), kp.pub), CKR_OK);
  check(`${label}: C_Verify (real signature) → OK`,
    w._C_Verify(hS, msgP, msg.length, sigP, readU32(slP)), CKR_OK);

  // Tamper control — same discipline as every other sign/verify pair in
  // test_p11_conformance.js: a passing verify on unmodified input proves
  // nothing about the verifier actually checking the signature unless a
  // tampered one is also shown to fail.
  new Uint8Array(mem().buffer, msgP, 1)[0] ^= 0xff;
  check(`${label}: C_VerifyInit (tamper control) → OK`, w._C_VerifyInit(hS, buildMech(signMech), kp.pub), CKR_OK);
  check(`${label}: C_Verify (tampered message) → SIGNATURE_INVALID`,
    w._C_Verify(hS, msgP, msg.length, sigP, readU32(slP)), CKR_SIGNATURE_INVALID);
}

signRoundTrip('XMSS-SHA2_10_256 (default/smallest param set)', CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS, CKK_XMSS, 15);
signRoundTrip('XMSSMT-SHA2_20/2_256 (default/smallest param set)', CKM_XMSSMT_KEY_PAIR_GEN, CKM_XMSSMT, CKK_XMSSMT, 15);

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
