// PKCS#11 v3.2 conformance harness for the softhsmrustv3 wasm engine.
// Table-driven negative-path matrix asserting EXACT CKR_* codes in spec
// priority order (§5.4/§5.12): not-initialized → session → key → operation
// → buffer. Seeded with regression tests for every fix from
// docs/gap-analysis-rust-pkcs11-v3.2.md (R1–R3.6, H-4, mixing guard).
//
// Run: node test_p11_conformance.js   (requires pkg/ built via wasm-pack)
'use strict';
const fs = require('fs');

// ── module load ──────────────────────────────────────────────────────────────
const wasmBuf = fs.readFileSync(__dirname + '/pkg/softhsmrustv3_bg.wasm');
const bg = require('./pkg/softhsmrustv3_bg.js');
const wasmInstance = new WebAssembly.Instance(new WebAssembly.Module(wasmBuf), {
  './softhsmrustv3_bg.js': bg,
});
bg.__wbg_set_wasm(wasmInstance.exports);
const w = wasmInstance.exports;
const mem = () => w.memory;

// ── constants (values from pkcs11t.h — the normative source) ─────────────────
const CKR = {
  OK: 0x00, ARGUMENTS_BAD: 0x07, ATTRIBUTE_READ_ONLY: 0x10, ATTRIBUTE_SENSITIVE: 0x11,
  ATTRIBUTE_TYPE_INVALID: 0x12, ATTRIBUTE_VALUE_INVALID: 0x13,
  DATA_LEN_RANGE: 0x21, ENCRYPTED_DATA_INVALID: 0x40,
  FUNCTION_NOT_PARALLEL: 0x55, FUNCTION_NOT_SUPPORTED: 0x54,
  KEY_HANDLE_INVALID: 0x60, KEY_FUNCTION_NOT_PERMITTED: 0x68, KEY_UNEXTRACTABLE: 0x6a,
  MECHANISM_INVALID: 0x70, MECHANISM_PARAM_INVALID: 0x71,
  OBJECT_HANDLE_INVALID: 0x82, OPERATION_ACTIVE: 0x90, OPERATION_NOT_INITIALIZED: 0x91,
  SESSION_HANDLE_INVALID: 0xb3, SESSION_PARALLEL_NOT_SUPPORTED: 0xb4,
  SESSION_READ_ONLY: 0xb5, SIGNATURE_INVALID: 0xc0, SIGNATURE_LEN_RANGE: 0xc1,
  TEMPLATE_INCOMPLETE: 0xd0, TEMPLATE_INCONSISTENT: 0xd1,
  BUFFER_TOO_SMALL: 0x150, CRYPTOKI_NOT_INITIALIZED: 0x190,
  CRYPTOKI_ALREADY_INITIALIZED: 0x191, NO_EVENT: 0x08,
};
const CKA = {
  CLASS: 0x000, TOKEN: 0x001, PRIVATE: 0x002, LABEL: 0x003, VALUE: 0x011,
  KEY_TYPE: 0x100, SENSITIVE: 0x103, ENCRYPT: 0x104, DECRYPT: 0x105,
  WRAP: 0x106, UNWRAP: 0x107, SIGN: 0x108, VERIFY: 0x10a, DERIVE: 0x10c,
  EXTRACTABLE: 0x162, LOCAL: 0x163, NEVER_EXTRACTABLE: 0x164, ALWAYS_SENSITIVE: 0x165,
  PARAMETER_SET: 0x61d, ENCAPSULATE: 0x633, DECAPSULATE: 0x634,
  VALUE_LEN: 0x161, MODULUS: 0x120, EC_PARAMS: 0x180, EC_POINT: 0x181,
};
const CKO = { DATA: 0, PUBLIC_KEY: 2, PRIVATE_KEY: 3, SECRET_KEY: 4 };
const CKK = { AES: 0x1f, GENERIC_SECRET: 0x10, ML_KEM: 0x49, ML_DSA: 0x4a, SLH_DSA: 0x4b, EC: 0x03 };
const CKM = {
  ML_KEM_KEY_PAIR_GEN: 0x0f, ML_KEM: 0x17, ML_DSA_KEY_PAIR_GEN: 0x1c, ML_DSA: 0x1d,
  SLH_DSA_KEY_PAIR_GEN: 0x2d, SLH_DSA: 0x2e, SHA256: 0x250, SHA256_HMAC: 0x251,
  SHA256_HMAC_GENERAL: 0x252, GENERIC_SECRET_KEY_GEN: 0x350,
  AES_KEY_GEN: 0x1080, AES_ECB: 0x1081, AES_CBC: 0x1082, AES_CBC_PAD: 0x1085,
  AES_CTR: 0x1086, AES_GCM: 0x1087, EC_KEY_PAIR_GEN: 0x1040, ECDSA: 0x1041,
  ECDSA_SHA3_512: 0x104a, CHACHA20_POLY1305: 0x4021,
};
const CKF = { RW_SESSION: 2, SERIAL_SESSION: 4 };
const CKP = { ML_DSA_65: 2, ML_KEM_768: 2 };
const CKU = { SO: 0, USER: 1 };

// ── helpers ──────────────────────────────────────────────────────────────────
let passes = 0, failures = 0;
function check(label, actual, expected) {
  if (actual === expected) { passes++; console.log(`  ✅ ${label}`); }
  else {
    failures++;
    console.log(`  ❌ ${label}: got 0x${actual.toString(16)}, expected 0x${expected.toString(16)}`);
  }
}
function section(t) { console.log(`\n── ${t} ──`); }

function alloc(n) { return w._malloc(n); }
function writeBytes(ptr, bytes) { new Uint8Array(mem().buffer, ptr, bytes.length).set(bytes); }
function readU32(ptr) { return new Uint32Array(mem().buffer, ptr, 1)[0]; }
function writeU32(ptr, v) { new Uint32Array(mem().buffer, ptr, 1)[0] = v; }

// CK_ATTRIBUTE[] — wasm32 layout: type u32, pValue u32, ulValueLen u32 (12 B each)
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
// CK_MECHANISM — wasm32: mechanism u32, pParameter u32, ulParameterLen u32
function buildMech(m, paramBytes) {
  const p = alloc(12);
  if (paramBytes) {
    const pp = alloc(paramBytes.length);
    writeBytes(pp, paramBytes);
    writeU32(p, m); writeU32(p + 4, pp); writeU32(p + 8, paramBytes.length);
  } else { writeU32(p, m); writeU32(p + 4, 0); writeU32(p + 8, 0); }
  return p;
}
// CK_GCM_PARAMS — wasm32 24 B: pIv, ulIvLen, ulIvBits, pAAD, ulAADLen, ulTagBits
function gcmParams(iv, aad, tagBits) {
  const ivPtr = iv ? alloc(iv.length) : 0;
  if (iv) writeBytes(ivPtr, iv);
  const aadPtr = aad ? alloc(aad.length) : 0;
  if (aad) writeBytes(aadPtr, aad);
  const b = new Uint32Array([ivPtr, iv ? iv.length : 0, iv ? iv.length * 8 : 0, aadPtr, aad ? aad.length : 0, tagBits]);
  return new Uint8Array(b.buffer);
}

function openSession(flags = CKF.RW_SESSION | CKF.SERIAL_SESSION) {
  const p = alloc(4);
  const rv = w._C_OpenSession(0, flags, 0, 0, p);
  return { rv, h: readU32(p) };
}
function genAes(hSession, extra = []) {
  const mech = buildMech(CKM.AES_KEY_GEN);
  const tpl = buildTpl([{ type: CKA.VALUE_LEN, ulong: 32 }, { type: CKA.ENCRYPT, bool: true },
    { type: CKA.DECRYPT, bool: true }, { type: CKA.WRAP, bool: true }, { type: CKA.UNWRAP, bool: true },
    { type: CKA.EXTRACTABLE, bool: true }, ...extra]);
  const hp = alloc(4);
  const rv = w._C_GenerateKey(hSession, mech, tpl, 6 + extra.length, hp);
  return { rv, h: readU32(hp) };
}
function genMlDsa(hSession, withPs = true) {
  const pub = [{ type: CKA.CLASS, ulong: CKO.PUBLIC_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.ML_DSA },
    { type: CKA.VERIFY, bool: true }];
  if (withPs) pub.push({ type: CKA.PARAMETER_SET, ulong: CKP.ML_DSA_65 });
  const prv = [{ type: CKA.CLASS, ulong: CKO.PRIVATE_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.ML_DSA },
    { type: CKA.SIGN, bool: true }];
  const hPub = alloc(4), hPrv = alloc(4);
  const rv = w._C_GenerateKeyPair(hSession, buildMech(CKM.ML_DSA_KEY_PAIR_GEN),
    buildTpl(pub), pub.length, buildTpl(prv), prv.length, hPub, hPrv);
  return { rv, pub: readU32(hPub), prv: readU32(hPrv) };
}

// ═════════════════════════════════════════════════════════════════════════════
section('R1.2 — initialization gate (§5.4/§5.6)');
check('C_GetSlotList before C_Initialize → CRYPTOKI_NOT_INITIALIZED',
  w._C_GetSlotList(0, 0, alloc(4)), CKR.CRYPTOKI_NOT_INITIALIZED);
check('C_Finalize before C_Initialize → CRYPTOKI_NOT_INITIALIZED',
  w._C_Finalize(0), CKR.CRYPTOKI_NOT_INITIALIZED);
check('C_Initialize → OK', w._C_Initialize(0), CKR.OK);
check('double C_Initialize → CRYPTOKI_ALREADY_INITIALIZED',
  w._C_Initialize(0), CKR.CRYPTOKI_ALREADY_INITIALIZED);

section('Token init (fixture — before any session, §5.7 C_InitToken)');
const soPin = new TextEncoder().encode('so-pin-1234');
const userPin = new TextEncoder().encode('user-pin-1234');
{
  const label = new Uint8Array(32).fill(0x20);
  label.set(new TextEncoder().encode('conformance'));
  const pSo = alloc(soPin.length); writeBytes(pSo, soPin);
  const pLabel = alloc(32); writeBytes(pLabel, label);
  check('C_InitToken → OK', w._C_InitToken(0, pSo, soPin.length, pLabel), CKR.OK);
}

section('R2.2 — session flags (§5.6)');
check('C_OpenSession without CKF_SERIAL_SESSION → SESSION_PARALLEL_NOT_SUPPORTED',
  openSession(CKF.RW_SESSION).rv, CKR.SESSION_PARALLEL_NOT_SUPPORTED);
const ses = openSession();
check('C_OpenSession(RW|SERIAL) → OK', ses.rv, CKR.OK);
const hS = ses.h;

section('Login fixture — SO sets user PIN, then User login (§4.4)');
{
  const pSo = alloc(soPin.length); writeBytes(pSo, soPin);
  const pUser = alloc(userPin.length); writeBytes(pUser, userPin);
  check('C_Login(SO) → OK', w._C_Login(hS, CKU.SO, pSo, soPin.length), CKR.OK);
  check('C_InitPIN(user) → OK', w._C_InitPIN(hS, pUser, userPin.length), CKR.OK);
  check('C_Logout → OK', w._C_Logout(hS), CKR.OK);
  check('C_Login(USER) → OK', w._C_Login(hS, CKU.USER, pUser, userPin.length), CKR.OK);
}

section('R2.1 — session-handle validation (§5.12 priority)');
check('C_GenerateKey with bogus session → SESSION_HANDLE_INVALID',
  genAes(0xdeadbeef).rv, CKR.SESSION_HANDLE_INVALID);
check('C_SignInit with bogus session → SESSION_HANDLE_INVALID',
  w._C_SignInit(0xdeadbeef, buildMech(CKM.ML_DSA), 1), CKR.SESSION_HANDLE_INVALID);
check('C_GenerateRandom with bogus session → SESSION_HANDLE_INVALID',
  w._C_GenerateRandom(0xdeadbeef, alloc(8), 8), CKR.SESSION_HANDLE_INVALID);

section('R2.4 — key-handle vs permission codes (§5.12.4)');
const aes = genAes(hS);
check('C_GenerateKey(AES-256) → OK', aes.rv, CKR.OK);
check('C_SignInit with nonexistent key → KEY_HANDLE_INVALID',
  w._C_SignInit(hS, buildMech(CKM.ML_DSA), 0x7fffffff), CKR.KEY_HANDLE_INVALID);
check('C_SignInit on AES key without CKA_SIGN → KEY_FUNCTION_NOT_PERMITTED',
  w._C_SignInit(hS, buildMech(CKM.SHA256_HMAC), aes.h), CKR.KEY_FUNCTION_NOT_PERMITTED);

section('R3.6 — CKA_PARAMETER_SET required for PQC keygen (§6.67.2)');
check('ML-DSA keygen WITH param set → OK', genMlDsa(hS, true).rv, CKR.OK);
check('ML-DSA keygen WITHOUT param set → TEMPLATE_INCOMPLETE', genMlDsa(hS, false).rv, CKR.TEMPLATE_INCOMPLETE);

section('R1.4 — GCM IV validation (§6.27.7)');
check('C_EncryptInit GCM with NULL/empty IV → MECHANISM_PARAM_INVALID',
  w._C_EncryptInit(hS, buildMech(CKM.AES_GCM, gcmParams(null, null, 128)), aes.h),
  CKR.MECHANISM_PARAM_INVALID);

section('H-4 — single-shot two-call convention (§5.2)');
const iv12 = new Uint8Array(12).fill(7);
check('C_EncryptInit GCM → OK',
  w._C_EncryptInit(hS, buildMech(CKM.AES_GCM, gcmParams(iv12, null, 128)), aes.h), CKR.OK);
const ptData = alloc(16); writeBytes(ptData, new Uint8Array(16).fill(0xab));
const lenP = alloc(4);
writeU32(lenP, 0);
check('C_Encrypt NULL-buffer length query → OK', w._C_Encrypt(hS, ptData, 16, 0, lenP), CKR.OK);
const needed = readU32(lenP);
const small = alloc(needed); writeU32(lenP, 4); // deliberately too small
check('C_Encrypt with too-small buffer → BUFFER_TOO_SMALL', w._C_Encrypt(hS, ptData, 16, small, lenP), CKR.BUFFER_TOO_SMALL);
writeU32(lenP, needed);
check('C_Encrypt retry after BUFFER_TOO_SMALL → OK (op preserved)', w._C_Encrypt(hS, ptData, 16, small, lenP), CKR.OK);
check('C_Encrypt after completion → OPERATION_NOT_INITIALIZED', w._C_Encrypt(hS, ptData, 16, small, lenP), CKR.OPERATION_NOT_INITIALIZED);

section('Mixing guard — one-shot after Update → OPERATION_ACTIVE (§5.2)');
check('C_EncryptInit CBC_PAD → OK',
  w._C_EncryptInit(hS, buildMech(CKM.AES_CBC_PAD, new Uint8Array(16)), aes.h), CKR.OK);
const upOut = alloc(64), upLen = alloc(4); writeU32(upLen, 64);
check('C_EncryptUpdate → OK', w._C_EncryptUpdate(hS, ptData, 16, upOut, upLen), CKR.OK);
writeU32(lenP, 64);
check('C_Encrypt after C_EncryptUpdate → OPERATION_ACTIVE', w._C_Encrypt(hS, ptData, 16, small, lenP), CKR.OPERATION_ACTIVE);
const finLen = alloc(4); writeU32(finLen, 64);
check('C_EncryptFinal still works → OK', w._C_EncryptFinal(hS, alloc(64), finLen), CKR.OK);

section('R2.5 — operation-active on re-init / find FSM (§5.10/§5.12)');
const mld = genMlDsa(hS, true);
check('C_SignInit(ML-DSA) → OK', w._C_SignInit(hS, buildMech(CKM.ML_DSA), mld.prv), CKR.OK);
check('second C_SignInit while active → OPERATION_ACTIVE', w._C_SignInit(hS, buildMech(CKM.ML_DSA), mld.prv), CKR.OPERATION_ACTIVE);
{ // drain via length query + sign
  const sl = alloc(4); writeU32(sl, 0);
  w._C_Sign(hS, ptData, 16, 0, sl);
  const sig = alloc(readU32(sl));
  check('C_Sign drains op → OK', w._C_Sign(hS, ptData, 16, sig, sl), CKR.OK);
}
check('C_FindObjectsFinal without init → OPERATION_NOT_INITIALIZED', w._C_FindObjectsFinal(hS), CKR.OPERATION_NOT_INITIALIZED);

section('H-5 — stateful sign / digest two-call (§5.2)');
check('C_DigestInit(SHA-256) → OK', w._C_DigestInit(hS, buildMech(CKM.SHA256)), CKR.OK);
const dl = alloc(4); writeU32(dl, 4);
check('C_DigestFinal too-small → BUFFER_TOO_SMALL', w._C_DigestFinal(hS, alloc(32), dl), CKR.BUFFER_TOO_SMALL);
writeU32(dl, 32);
check('C_DigestFinal retry → OK (op preserved)', w._C_DigestFinal(hS, alloc(32), dl), CKR.OK);

section('R1.3 — private-object visibility (§4.4)');
{
  // PRIVATE=TRUE objects must be invisible while the token is not logged in.
  w._C_Logout(hS);
  const tpl = buildTpl([
    { type: CKA.CLASS, ulong: CKO.SECRET_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.GENERIC_SECRET },
    { type: CKA.VALUE, bytes: new Uint8Array(32).fill(5) }, { type: CKA.PRIVATE, bool: true },
    { type: CKA.LABEL, bytes: new TextEncoder().encode('privobj') },
  ]);
  const hp = alloc(4);
  check('C_CreateObject(private secret) → OK', w._C_CreateObject(hS, tpl, 5, hp), CKR.OK);
  const hPriv = readU32(hp);
  const out = buildTpl([{ type: CKA.LABEL, bytes: new Uint8Array(16) }]);
  check('C_GetAttributeValue on private obj w/o login → OBJECT_HANDLE_INVALID',
    w._C_GetAttributeValue(hS, hPriv, out, 1), CKR.OBJECT_HANDLE_INVALID);
  check('C_DestroyObject on private obj w/o login → OBJECT_HANDLE_INVALID',
    w._C_DestroyObject(hS, hPriv), CKR.OBJECT_HANDLE_INVALID);
  // restore User login for the remaining sections
  const userPin = new TextEncoder().encode('user-pin-1234');
  const pUser = alloc(userPin.length); writeBytes(pUser, userPin);
  check('re-Login(USER) → OK', w._C_Login(hS, CKU.USER, pUser, userPin.length), CKR.OK);
}

section('H-11 — CKR_ATTRIBUTE_SENSITIVE (§5.7.5)');
{
  const tpl = buildTpl([
    { type: CKA.CLASS, ulong: CKO.SECRET_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.GENERIC_SECRET },
    { type: CKA.VALUE, bytes: new Uint8Array(32).fill(9) }, { type: CKA.SENSITIVE, bool: true },
  ]);
  const hp = alloc(4);
  check('C_CreateObject(sensitive secret) → OK', w._C_CreateObject(hS, tpl, 4, hp), CKR.OK);
  const out = buildTpl([{ type: CKA.VALUE, bytes: new Uint8Array(32) }]);
  check('C_GetAttributeValue(CKA_VALUE) on sensitive → ATTRIBUTE_SENSITIVE',
    w._C_GetAttributeValue(hS, readU32(hp), out, 1), CKR.ATTRIBUTE_SENSITIVE);
}

section('R1.5 — authenticated wrap AAD binding (§5.18.6/7)');
{
  const target = genAes(hS).h;
  const aad = new TextEncoder().encode('wrap-aad');
  const iv = new Uint8Array(12).fill(3);
  const aadPtr = alloc(aad.length); writeBytes(aadPtr, aad);
  const wl = alloc(4); writeU32(wl, 0);
  const mech = buildMech(CKM.AES_GCM, gcmParams(iv, null, 128));
  check('C_WrapKeyAuthenticated length query → OK',
    w._C_WrapKeyAuthenticated(hS, mech, aes.h, target, aadPtr, aad.length, 0, wl), CKR.OK);
  const wrapped = alloc(readU32(wl));
  check('C_WrapKeyAuthenticated → OK',
    w._C_WrapKeyAuthenticated(hS, mech, aes.h, target, aadPtr, aad.length, wrapped, wl), CKR.OK);
  const tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.AES }]);
  const hp = alloc(4);
  check('C_UnwrapKeyAuthenticated with SAME AAD → OK',
    w._C_UnwrapKeyAuthenticated(hS, mech, aes.h, wrapped, readU32(wl), tpl, 2, aadPtr, aad.length, hp), CKR.OK);
  const badAad = alloc(4); writeBytes(badAad, new Uint8Array([1, 2, 3, 4]));
  check('C_UnwrapKeyAuthenticated with WRONG AAD → ENCRYPTED_DATA_INVALID',
    w._C_UnwrapKeyAuthenticated(hS, mech, aes.h, wrapped, readU32(wl), tpl, 2, badAad, 4, hp), CKR.ENCRYPTED_DATA_INVALID);
}

section('ML-KEM — encap/decap usage + provenance (§5.18.8/9)');
{
  const pub = buildTpl([{ type: CKA.CLASS, ulong: CKO.PUBLIC_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.ML_KEM },
    { type: CKA.PARAMETER_SET, ulong: CKP.ML_KEM_768 }]);
  const prv = buildTpl([{ type: CKA.CLASS, ulong: CKO.PRIVATE_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.ML_KEM }]);
  const hPub = alloc(4), hPrv = alloc(4);
  check('ML-KEM keygen → OK',
    w._C_GenerateKeyPair(hS, buildMech(CKM.ML_KEM_KEY_PAIR_GEN), pub, 3, prv, 2, hPub, hPrv), CKR.OK);
  const ctLen = alloc(4); writeU32(ctLen, 0);
  const hSS = alloc(4);
  check('C_EncapsulateKey length query → OK',
    w._C_EncapsulateKey(hS, buildMech(CKM.ML_KEM), readU32(hPub), 0, 0, 0, ctLen, hSS), CKR.OK);
  const ct = alloc(readU32(ctLen));
  check('C_EncapsulateKey → OK',
    w._C_EncapsulateKey(hS, buildMech(CKM.ML_KEM), readU32(hPub), 0, 0, ct, ctLen, hSS), CKR.OK);
  // usage enforcement: encapsulate with the PRIVATE key (no CKA_ENCAPSULATE) must fail
  check('C_EncapsulateKey with private key → KEY_FUNCTION_NOT_PERMITTED',
    w._C_EncapsulateKey(hS, buildMech(CKM.ML_KEM), readU32(hPrv), 0, 0, ct, ctLen, hSS), CKR.KEY_FUNCTION_NOT_PERMITTED);
}

// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n════════ RESULT: ${passes} passed, ${failures} failed ════════`);
process.exit(failures === 0 ? 0 : 1);
