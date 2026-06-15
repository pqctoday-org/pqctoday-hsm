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
  FUNCTION_NOT_PARALLEL: 0x51, FUNCTION_NOT_SUPPORTED: 0x54,
  KEY_HANDLE_INVALID: 0x60, KEY_FUNCTION_NOT_PERMITTED: 0x68, KEY_UNEXTRACTABLE: 0x6a,
  MECHANISM_INVALID: 0x70, MECHANISM_PARAM_INVALID: 0x71,
  OBJECT_HANDLE_INVALID: 0x82, OPERATION_ACTIVE: 0x90, OPERATION_NOT_INITIALIZED: 0x91,
  SESSION_HANDLE_INVALID: 0xb3, SESSION_PARALLEL_NOT_SUPPORTED: 0xb4,
  SESSION_READ_ONLY: 0xb5, SIGNATURE_INVALID: 0xc0, SIGNATURE_LEN_RANGE: 0xc1,
  TEMPLATE_INCOMPLETE: 0xd0, TEMPLATE_INCONSISTENT: 0xd1,
  BUFFER_TOO_SMALL: 0x150, CRYPTOKI_NOT_INITIALIZED: 0x190,
  CRYPTOKI_ALREADY_INITIALIZED: 0x191, NO_EVENT: 0x08,
  UNWRAPPING_KEY_HANDLE_INVALID: 0xf0, WRAPPING_KEY_HANDLE_INVALID: 0x113,
  RANDOM_SEED_NOT_SUPPORTED: 0x120,
};
const CKA = {
  CLASS: 0x000, TOKEN: 0x001, PRIVATE: 0x002, LABEL: 0x003, UNIQUE_ID: 0x004, VALUE: 0x011,
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
  SHA256_HMAC_GENERAL: 0x252, SHA384_HMAC: 0x261, GENERIC_SECRET_KEY_GEN: 0x350,
  SP800_108_COUNTER_KDF: 0x3ac,
  AES_KEY_GEN: 0x1080, AES_ECB: 0x1081, AES_CBC: 0x1082, AES_CBC_PAD: 0x1085,
  AES_CTR: 0x1086, AES_GCM: 0x1087, AES_KEY_WRAP: 0x2109,
  EC_KEY_PAIR_GEN: 0x1040, ECDSA: 0x1041,
  ECDSA_SHA3_512: 0x104a, CHACHA20: 0x1226, CHACHA20_POLY1305: 0x4021,
  SHA384_RSA_PKCS: 0x41, SHA512_RSA_PKCS: 0x42,
  SHA384_RSA_PKCS_PSS: 0x44, SHA512_RSA_PKCS_PSS: 0x45,
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

// CK_TOKEN_INFO (wasm32) — label[32]@0, flags u32@96, ulSessionCount u32@104
function getTokenInfo(slot = 0) {
  const p = alloc(160);
  const rv = w._C_GetTokenInfo(slot, p);
  const u8 = new Uint8Array(mem().buffer, p, 160);
  const label = Buffer.from(u8.subarray(0, 32)).toString('latin1').trimEnd();
  const u32at = (off) => new Uint32Array(mem().buffer, p + off, 1)[0];
  return { rv, label, flags: u32at(96), sessionCount: u32at(104), rwSessionCount: u32at(112) };
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

section('T7 — TokenInfo flags BEFORE C_InitPIN (§5.5, round-2 regression)');
{
  // CKF_TOKEN_INITIALIZED (0x400) must be ON after C_InitToken, while
  // CKF_USER_PIN_INITIALIZED (0x8) must still be OFF: no user PIN exists yet.
  const ti = getTokenInfo();
  check('C_GetTokenInfo → OK', ti.rv, CKR.OK);
  check('CKF_TOKEN_INITIALIZED set after InitToken', ti.flags & 0x400, 0x400);
  check('CKF_USER_PIN_INITIALIZED still clear before InitPIN', ti.flags & 0x8, 0);
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

section('E1 — ML-DSA context string + hedge variant (§6.67, FIPS 204 §5.2)');
{
  // CK_SIGN_ADDITIONAL_CONTEXT (wasm32, 12 B): hedgeVariant, pContext, ulContextLen
  function signCtxParam(hedge, ctxBytes) {
    let ctxPtr = 0;
    if (ctxBytes && ctxBytes.length) { ctxPtr = alloc(ctxBytes.length); writeBytes(ctxPtr, ctxBytes); }
    return new Uint8Array(new Uint32Array([hedge, ctxPtr, ctxBytes ? ctxBytes.length : 0]).buffer);
  }
  const kp = genMlDsa(hS, true);
  const msg = alloc(24); writeBytes(msg, new TextEncoder().encode('ml-dsa context test msg!'));
  const ctxA = new TextEncoder().encode('app-context-A');
  const CKH_DETERMINISTIC_REQUIRED = 2;

  function signWith(param) {
    const rv1 = w._C_SignInit(hS, buildMech(CKM.ML_DSA, param), kp.prv);
    if (rv1 !== CKR.OK) return { rv: rv1 };
    const sl = alloc(4); writeU32(sl, 0);
    w._C_Sign(hS, msg, 24, 0, sl);
    const sig = alloc(readU32(sl));
    const rv2 = w._C_Sign(hS, msg, 24, sig, sl);
    return { rv: rv2, sig, len: readU32(sl) };
  }
  function verifyWith(param, sig, len) {
    const rv1 = w._C_VerifyInit(hS, buildMech(CKM.ML_DSA, param), kp.pub);
    if (rv1 !== CKR.OK) return rv1;
    return w._C_Verify(hS, msg, 24, sig, len);
  }

  const sA = signWith(signCtxParam(0, ctxA));
  check('sign with context A → OK', sA.rv, CKR.OK);
  check('verify with context A → OK', verifyWith(signCtxParam(0, ctxA), sA.sig, sA.len), CKR.OK);
  check('verify with EMPTY context → SIGNATURE_INVALID',
    verifyWith(null, sA.sig, sA.len), CKR.SIGNATURE_INVALID);
  check('verify with context B → SIGNATURE_INVALID',
    verifyWith(signCtxParam(0, new TextEncoder().encode('app-context-B')), sA.sig, sA.len), CKR.SIGNATURE_INVALID);

  // deterministic mode: two signatures over the same message must be identical
  const d1 = signWith(signCtxParam(CKH_DETERMINISTIC_REQUIRED, ctxA));
  const d2 = signWith(signCtxParam(CKH_DETERMINISTIC_REQUIRED, ctxA));
  check('deterministic sign #1 → OK', d1.rv, CKR.OK);
  const b1 = Buffer.from(new Uint8Array(mem().buffer, d1.sig, d1.len));
  const b2 = Buffer.from(new Uint8Array(mem().buffer, d2.sig, d2.len));
  check('deterministic signatures identical → true', b1.equals(b2) ? 1 : 0, 1);
  check('deterministic sig verifies → OK', verifyWith(signCtxParam(0, ctxA), d1.sig, d1.len), CKR.OK);

  // hedged: two signatures should differ (randomized)
  const h1 = signWith(signCtxParam(0, ctxA));
  const h2 = signWith(signCtxParam(0, ctxA));
  const hb1 = Buffer.from(new Uint8Array(mem().buffer, h1.sig, h1.len));
  const hb2 = Buffer.from(new Uint8Array(mem().buffer, h2.sig, h2.len));
  check('hedged signatures differ → true', hb1.equals(hb2) ? 0 : 1, 1);

  // ctx > 255 → MECHANISM_PARAM_INVALID at SignInit
  check('context >255 bytes → MECHANISM_PARAM_INVALID',
    w._C_SignInit(hS, buildMech(CKM.ML_DSA, signCtxParam(0, new Uint8Array(256))), kp.prv),
    CKR.MECHANISM_PARAM_INVALID);
  // unknown hedge variant → MECHANISM_PARAM_INVALID
  check('bad hedge variant → MECHANISM_PARAM_INVALID',
    w._C_SignInit(hS, buildMech(CKM.ML_DSA, signCtxParam(7, ctxA)), kp.prv),
    CKR.MECHANISM_PARAM_INVALID);
}

section('E9 — CKR_SIGNATURE_LEN_RANGE (§5.12.6)');
{
  const kp = genMlDsa(hS, true);
  const msg = alloc(8); writeBytes(msg, new Uint8Array(8).fill(1));
  check('VerifyInit → OK', w._C_VerifyInit(hS, buildMech(CKM.ML_DSA), kp.pub), CKR.OK);
  const shortSig = alloc(100);
  check('C_Verify with truncated signature → SIGNATURE_LEN_RANGE',
    w._C_Verify(hS, msg, 8, shortSig, 100), CKR.SIGNATURE_LEN_RANGE);
}

section('D4 — spec-mandated stubs');
check('C_GetFunctionStatus → FUNCTION_NOT_PARALLEL', w._C_GetFunctionStatus(hS), CKR.FUNCTION_NOT_PARALLEL);
check('C_CancelFunction → FUNCTION_NOT_PARALLEL', w._C_CancelFunction(hS), CKR.FUNCTION_NOT_PARALLEL);
check('C_WaitForSlotEvent(DONT_BLOCK) → NO_EVENT', w._C_WaitForSlotEvent(1, 0, 0), CKR.NO_EVENT);
check('C_WaitForSlotEvent(blocking) → FUNCTION_NOT_SUPPORTED', w._C_WaitForSlotEvent(0, 0, 0), CKR.FUNCTION_NOT_SUPPORTED);
check('C_SignRecoverInit → FUNCTION_NOT_SUPPORTED', w._C_SignRecoverInit(hS, 0, 0), CKR.FUNCTION_NOT_SUPPORTED);
// Dual-function ops are now IMPLEMENTED (not stubs): with neither a digest nor
// an encrypt operation active, C_DigestEncryptUpdate returns
// OPERATION_NOT_INITIALIZED (§5.16), not FUNCTION_NOT_SUPPORTED.
check('C_DigestEncryptUpdate (no active ops) → OPERATION_NOT_INITIALIZED', w._C_DigestEncryptUpdate(hS, 0, 0, 0, 0), CKR.OPERATION_NOT_INITIALIZED);

section('F1 — mechanism table reconciliation (R6.2)');
{
  // every advertised mechanism answerable
  const cntP = alloc(4); writeU32(cntP, 0);
  w._C_GetMechanismList(0, 0, cntP);
  const n = readU32(cntP);
  const listP = alloc(4 * n);
  w._C_GetMechanismList(0, listP, cntP);
  const mechs = Array.from(new Uint32Array(mem().buffer, listP, n));
  const info = alloc(12);
  const unanswerable = mechs.filter((m) => w._C_GetMechanismInfo(0, m, info) !== CKR.OK);
  check(`all ${n} advertised mechanisms answerable → 0 missing`, unanswerable.length, 0);
}

section('R3.1 — C_CreateObject template validation (§4.1.1)');
{
  const hp = alloc(4);
  // missing CKA_CLASS
  let tpl = buildTpl([{ type: CKA.KEY_TYPE, ulong: CKK.AES }, { type: CKA.VALUE, bytes: new Uint8Array(32) }]);
  check('no CKA_CLASS → TEMPLATE_INCOMPLETE', w._C_CreateObject(hS, tpl, 2, hp), CKR.TEMPLATE_INCOMPLETE);
  // missing CKA_KEY_TYPE on a key class
  tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY }, { type: CKA.VALUE, bytes: new Uint8Array(32) }]);
  check('key class without CKA_KEY_TYPE → TEMPLATE_INCOMPLETE', w._C_CreateObject(hS, tpl, 2, hp), CKR.TEMPLATE_INCOMPLETE);
  // secret key without CKA_VALUE
  tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.AES }]);
  check('secret key without CKA_VALUE → TEMPLATE_INCOMPLETE', w._C_CreateObject(hS, tpl, 2, hp), CKR.TEMPLATE_INCOMPLETE);
  // AES with bad length
  tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.AES },
    { type: CKA.VALUE, bytes: new Uint8Array(17) }]);
  check('AES key with 17-byte value → ATTRIBUTE_VALUE_INVALID', w._C_CreateObject(hS, tpl, 3, hp), CKR.ATTRIBUTE_VALUE_INVALID);
  // class/type inconsistency
  tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.PUBLIC_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.AES },
    { type: CKA.VALUE, bytes: new Uint8Array(32) }]);
  check('CKK_AES under CKO_PUBLIC_KEY → TEMPLATE_INCONSISTENT', w._C_CreateObject(hS, tpl, 3, hp), CKR.TEMPLATE_INCONSISTENT);
  // valid import still works
  tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.AES },
    { type: CKA.VALUE, bytes: new Uint8Array(32).fill(7) }, { type: CKA.EXTRACTABLE, bool: true }]);
  check('valid AES import → OK', w._C_CreateObject(hS, tpl, 4, hp), CKR.OK);
  // null ph_object
  check('null ph_object → ARGUMENTS_BAD', w._C_CreateObject(hS, tpl, 4, 0), CKR.ARGUMENTS_BAD);
}

section('E3 — GCM ulTagBits honored + validated (§6.27.7 / SP 800-38D §5.2.1.2)');
{
  const key = genAes(hS);
  const iv = new Uint8Array(12).fill(0x42);
  const pt = alloc(20); writeBytes(pt, new Uint8Array(20).fill(0x5a));
  // 96-bit tag: ciphertext must be 20 + 12 = 32 bytes (not 36)
  check('EncryptInit GCM tag=96 → OK',
    w._C_EncryptInit(hS, buildMech(CKM.AES_GCM, gcmParams(iv, null, 96)), key.h), CKR.OK);
  const lp = alloc(4); writeU32(lp, 0);
  check('length query → OK', w._C_Encrypt(hS, pt, 20, 0, lp), CKR.OK);
  check('ct length honors 96-bit tag (20+12)', readU32(lp), 32);
  const ct = alloc(32); writeU32(lp, 32);
  check('Encrypt(tag=96) → OK', w._C_Encrypt(hS, pt, 20, ct, lp), CKR.OK);
  // round-trip decrypt with matching tag bits
  check('DecryptInit GCM tag=96 → OK',
    w._C_DecryptInit(hS, buildMech(CKM.AES_GCM, gcmParams(iv, null, 96)), key.h), CKR.OK);
  const ptOut = alloc(32); const lp2 = alloc(4); writeU32(lp2, 32);
  check('Decrypt(tag=96) round-trip → OK', w._C_Decrypt(hS, ct, 32, ptOut, lp2), CKR.OK);
  check('plaintext length 20', readU32(lp2), 20);
  // corrupt tag → ENCRYPTED_DATA_INVALID
  check('DecryptInit again → OK',
    w._C_DecryptInit(hS, buildMech(CKM.AES_GCM, gcmParams(iv, null, 96)), key.h), CKR.OK);
  new Uint8Array(mem().buffer, ct + 31, 1)[0] ^= 0xff;
  writeU32(lp2, 32);
  check('Decrypt with corrupted truncated tag → ENCRYPTED_DATA_INVALID',
    w._C_Decrypt(hS, ct, 32, ptOut, lp2), CKR.ENCRYPTED_DATA_INVALID);
  // out-of-set tag bits rejected
  check('EncryptInit GCM tag=24 → MECHANISM_PARAM_INVALID',
    w._C_EncryptInit(hS, buildMech(CKM.AES_GCM, gcmParams(iv, null, 24)), key.h), CKR.MECHANISM_PARAM_INVALID);
  // ulIvBits contradiction rejected
  const badIvBits = gcmParams(iv, null, 128);
  new Uint32Array(badIvBits.buffer)[2] = 64; // ulIvBits=64 vs ulIvLen=12 (96 bits)
  check('GCM ulIvBits≠ulIvLen*8 → MECHANISM_PARAM_INVALID',
    w._C_EncryptInit(hS, buildMech(CKM.AES_GCM, badIvBits), key.h), CKR.MECHANISM_PARAM_INVALID);
}

section('E4 — AES-CTR ulCounterBits (§6.27.6)');
{
  const key = genAes(hS);
  // CK_AES_CTR_PARAMS: ulCounterBits(4) + cb[16]
  function ctrParams(bits, cb) {
    const b = new Uint8Array(20);
    new Uint32Array(b.buffer, 0, 1)[0] = bits;
    b.set(cb, 4);
    return b;
  }
  const cb = new Uint8Array(16); cb.fill(0xff); // counter at all-ones → wraps immediately
  const pt = alloc(48); writeBytes(pt, new Uint8Array(48).fill(0x11));
  // 32-bit counter: low 4 bytes wrap, high 12 bytes stay 0xff
  check('EncryptInit CTR counterBits=32 → OK',
    w._C_EncryptInit(hS, buildMech(CKM.AES_CTR, ctrParams(32, cb)), key.h), CKR.OK);
  const ct32 = alloc(48); const l1 = alloc(4); writeU32(l1, 48);
  check('Encrypt(ctr32) → OK', w._C_Encrypt(hS, pt, 48, ct32, l1), CKR.OK);
  // 128-bit counter: whole block wraps — different keystream after block 1
  check('EncryptInit CTR counterBits=128 → OK',
    w._C_EncryptInit(hS, buildMech(CKM.AES_CTR, ctrParams(128, cb)), key.h), CKR.OK);
  const ct128 = alloc(48); const l2 = alloc(4); writeU32(l2, 48);
  check('Encrypt(ctr128) → OK', w._C_Encrypt(hS, pt, 48, ct128, l2), CKR.OK);
  const a = Buffer.from(new Uint8Array(mem().buffer, ct32, 48));
  const b = Buffer.from(new Uint8Array(mem().buffer, ct128, 48));
  check('block 1 identical across widths', a.subarray(0, 16).equals(b.subarray(0, 16)) ? 1 : 0, 1);
  check('post-wrap blocks DIFFER between 32/128-bit widths', a.equals(b) ? 0 : 1, 1);
  // CTR round-trip with 32-bit width
  check('DecryptInit CTR counterBits=32 → OK',
    w._C_DecryptInit(hS, buildMech(CKM.AES_CTR, ctrParams(32, cb)), key.h), CKR.OK);
  const rt = alloc(48); const l3 = alloc(4); writeU32(l3, 48);
  check('Decrypt(ctr32) round-trip → OK', w._C_Decrypt(hS, ct32, 48, rt, l3), CKR.OK);
  check('round-trip matches plaintext',
    Buffer.from(new Uint8Array(mem().buffer, rt, 48)).equals(Buffer.from(new Uint8Array(48).fill(0x11))) ? 1 : 0, 1);
  // invalid counter bits
  check('CTR counterBits=0 → MECHANISM_PARAM_INVALID',
    w._C_EncryptInit(hS, buildMech(CKM.AES_CTR, ctrParams(0, cb)), key.h), CKR.MECHANISM_PARAM_INVALID);
  check('CTR counterBits=129 → MECHANISM_PARAM_INVALID',
    w._C_EncryptInit(hS, buildMech(CKM.AES_CTR, ctrParams(129, cb)), key.h), CKR.MECHANISM_PARAM_INVALID);
}

section('E8 — HMAC general-length (§6.x CK_MAC_GENERAL_PARAMS)');
{
  // generic secret with CKA_SIGN
  const tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY },
    { type: CKA.KEY_TYPE, ulong: CKK.GENERIC_SECRET },
    { type: CKA.VALUE, bytes: new Uint8Array(32).fill(0x77) },
    { type: CKA.SIGN, bool: true }, { type: CKA.VERIFY, bool: true }]);
  const hp = alloc(4);
  check('import HMAC key → OK', w._C_CreateObject(hS, tpl, 5, hp), CKR.OK);
  const hKey = readU32(hp);
  const macParam = new Uint8Array(new Uint32Array([16]).buffer); // ulMacLength=16
  const msg = alloc(10); writeBytes(msg, new Uint8Array(10).fill(2));
  check('SignInit SHA256_HMAC_GENERAL(16) → OK',
    w._C_SignInit(hS, buildMech(CKM.SHA256_HMAC_GENERAL, macParam), hKey), CKR.OK);
  const sl = alloc(4); writeU32(sl, 0);
  check('length query → OK', w._C_Sign(hS, msg, 10, 0, sl), CKR.OK);
  check('mac length = 16', readU32(sl), 16);
  const mac = alloc(16); writeU32(sl, 16);
  check('Sign → OK', w._C_Sign(hS, msg, 10, mac, sl), CKR.OK);
  check('VerifyInit GENERAL(16) → OK',
    w._C_VerifyInit(hS, buildMech(CKM.SHA256_HMAC_GENERAL, macParam), hKey), CKR.OK);
  check('Verify truncated MAC → OK', w._C_Verify(hS, msg, 10, mac, 16), CKR.OK);
  check('VerifyInit again → OK',
    w._C_VerifyInit(hS, buildMech(CKM.SHA256_HMAC_GENERAL, macParam), hKey), CKR.OK);
  check('Verify with wrong length (8) → SIGNATURE_LEN_RANGE',
    w._C_Verify(hS, msg, 10, mac, 8), CKR.SIGNATURE_LEN_RANGE);
  // out-of-range ulMacLength
  const badParam = new Uint8Array(new Uint32Array([33]).buffer);
  check('ulMacLength=33 > digest → MECHANISM_PARAM_INVALID',
    w._C_SignInit(hS, buildMech(CKM.SHA256_HMAC_GENERAL, badParam), hKey), CKR.MECHANISM_PARAM_INVALID);
}

section('E2 — RSA-PSS params validated (§6.4.5)');
{
  // bad mgf in CK_RSA_PKCS_PSS_PARAMS must be rejected at SignInit.
  // (Uses a dummy key handle — param validation precedes key-type checks
  // only for mechanism params parsed at init; key check runs first, so
  // generate a real RSA keypair is slow; instead use an AES key with SIGN.)
  const tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY },
    { type: CKA.KEY_TYPE, ulong: CKK.GENERIC_SECRET },
    { type: CKA.VALUE, bytes: new Uint8Array(32) }, { type: CKA.SIGN, bool: true }]);
  const hp = alloc(4);
  w._C_CreateObject(hS, tpl, 4, hp);
  const pssBad = new Uint8Array(new Uint32Array([CKM.SHA256, 99 /*bad mgf*/, 32]).buffer);
  check('PSS params with bad MGF → MECHANISM_PARAM_INVALID',
    w._C_SignInit(hS, buildMech(0x43 /*CKM_SHA256_RSA_PKCS_PSS*/, pssBad), readU32(hp)),
    CKR.MECHANISM_PARAM_INVALID);
}

section('R3.7/D2 — session-object lifecycle + SessionCancel (§4.4/§5.6)');
{
  // session object dies with its session; token object survives
  const s2 = openSession();
  check('second session opens → OK', s2.rv, CKR.OK);
  const mkTpl = (token) => buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY },
    { type: CKA.KEY_TYPE, ulong: CKK.GENERIC_SECRET },
    { type: CKA.VALUE, bytes: new Uint8Array(32).fill(0xcc) },
    { type: CKA.TOKEN, bool: token }, { type: CKA.EXTRACTABLE, bool: true }]);
  const hp1 = alloc(4), hp2 = alloc(4);
  check('create SESSION object in s2 → OK', w._C_CreateObject(s2.h, mkTpl(false), 5, hp1), CKR.OK);
  check('create TOKEN object in s2 → OK', w._C_CreateObject(s2.h, mkTpl(true), 5, hp2), CKR.OK);
  const hSess = readU32(hp1), hTok = readU32(hp2);
  check('close s2 → OK', w._C_CloseSession(s2.h), CKR.OK);
  const out = buildTpl([{ type: CKA.CLASS, bytes: new Uint8Array(4) }]);
  check('session object gone after close → OBJECT_HANDLE_INVALID',
    w._C_GetAttributeValue(hS, hSess, out, 1), CKR.OBJECT_HANDLE_INVALID);
  check('token object survives close → OK', w._C_GetAttributeValue(hS, hTok, out, 1), CKR.OK);

  // C_SessionCancel aborts a digest op
  check('DigestInit → OK', w._C_DigestInit(hS, buildMech(CKM.SHA256)), CKR.OK);
  check('SessionCancel(CKF_DIGEST) → OK', w._C_SessionCancel(hS, 0x400), CKR.OK);
  const dl2 = alloc(4); writeU32(dl2, 32);
  check('DigestFinal after cancel → OPERATION_NOT_INITIALIZED',
    w._C_DigestFinal(hS, alloc(32), dl2), CKR.OPERATION_NOT_INITIALIZED);
  check('SessionCancel(flags=0) → OK (cancels nothing)', w._C_SessionCancel(hS, 0), CKR.OK);
  check('SessionCancel bad session → SESSION_HANDLE_INVALID',
    w._C_SessionCancel(0xdead, 0x400), CKR.SESSION_HANDLE_INVALID);

  // C_CloseAllSessions: bad slot
  check('CloseAllSessions bad slot → SLOT_ID_INVALID', w._C_CloseAllSessions(99), 0x3);
}

// ═════════════════════════════════════════════════════════════════════════════
// Round-2 remediation regressions (T4/T5/T6 + F1/F2 spec re-sync).
// Every check below pins a behavior fixed in compliance round 2 so the JS/wasm
// ABI can never silently regress to the pre-remediation engine.
// ═════════════════════════════════════════════════════════════════════════════

section('Round-2 — keygen template + RNG codes (§5.16/§5.14)');
{
  // AES keygen without CKA_VALUE_LEN — key length is unknowable → 0xD0.
  const mech = buildMech(CKM.AES_KEY_GEN);
  const tpl = buildTpl([{ type: CKA.ENCRYPT, bool: true }]);
  const hp = alloc(4);
  check('C_GenerateKey(AES) without CKA_VALUE_LEN → TEMPLATE_INCOMPLETE',
    w._C_GenerateKey(hS, mech, tpl, 1, hp), CKR.TEMPLATE_INCOMPLETE);
  // §5.14 — the engine has no seedable DRBG: CKR_RANDOM_SEED_NOT_SUPPORTED.
  const seed = alloc(8); writeBytes(seed, new Uint8Array(8).fill(0x55));
  check('C_SeedRandom → RANDOM_SEED_NOT_SUPPORTED',
    w._C_SeedRandom(hS, seed, 8), CKR.RANDOM_SEED_NOT_SUPPORTED);
}

section('Round-2 — wrap/unwrap role-specific handle codes (§5.18)');
{
  const target = genAes(hS);
  check('fixture: target AES key → OK', target.rv, CKR.OK);
  // mechanism must be a valid wrap mechanism — the mechanism gate precedes
  // the handle gate, so a bogus handle under AES-GCM would report 0x70.
  const mech = buildMech(CKM.AES_KEY_WRAP);
  const wl = alloc(4); writeU32(wl, 0);
  check('C_WrapKey with bogus wrapping key → WRAPPING_KEY_HANDLE_INVALID',
    w._C_WrapKey(hS, mech, 0x7ffffff0, target.h, 0, wl), CKR.WRAPPING_KEY_HANDLE_INVALID);
  const tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY }, { type: CKA.KEY_TYPE, ulong: CKK.AES }]);
  const blob = alloc(48); const hp = alloc(4);
  check('C_UnwrapKey with bogus unwrapping key → UNWRAPPING_KEY_HANDLE_INVALID',
    w._C_UnwrapKey(hS, mech, 0x7ffffff0, blob, 48, tpl, 2, hp), CKR.UNWRAPPING_KEY_HANDLE_INVALID);
}

section('Round-2 — operate-stage session-handle gate (§5.12.1)');
{
  const data = alloc(16); writeBytes(data, new Uint8Array(16).fill(1));
  const outLen = alloc(4); writeU32(outLen, 0);
  check('C_Sign with bogus session → SESSION_HANDLE_INVALID',
    w._C_Sign(0xdeadbeef, data, 16, 0, outLen), CKR.SESSION_HANDLE_INVALID);
  check('C_Encrypt with bogus session → SESSION_HANDLE_INVALID',
    w._C_Encrypt(0xdeadbeef, data, 16, 0, outLen), CKR.SESSION_HANDLE_INVALID);
  const found = alloc(4), cnt = alloc(4);
  check('C_FindObjects with bogus session → SESSION_HANDLE_INVALID',
    w._C_FindObjects(0xdeadbeef, found, 1, cnt), CKR.SESSION_HANDLE_INVALID);
}

section('Round-2 — T6 object management (Set/GetAttr, size, copy, §4.4.1/§5.7)');
{
  const key = genAes(hS);
  check('fixture: AES key → OK', key.rv, CKR.OK);

  // C_SetAttributeValue works: set CKA_LABEL and read it back.
  const labelBytes = new TextEncoder().encode('round2-label');
  check('C_SetAttributeValue(CKA_LABEL) → OK',
    w._C_SetAttributeValue(hS, key.h, buildTpl([{ type: CKA.LABEL, bytes: labelBytes }]), 1), CKR.OK);
  {
    const out = buildTpl([{ type: CKA.LABEL, bytes: new Uint8Array(labelBytes.length) }]);
    check('read back CKA_LABEL → OK', w._C_GetAttributeValue(hS, key.h, out, 1), CKR.OK);
    const vp = readU32(out + 4), vl = readU32(out + 8);
    const got = Buffer.from(new Uint8Array(mem().buffer, vp, vl)).toString();
    check('CKA_LABEL round-trips byte-exact', got === 'round2-label' ? 1 : 0, 1);
  }
  // Read-only attribute → CKR_ATTRIBUTE_READ_ONLY (0x10).
  check('C_SetAttributeValue(CKA_CLASS) → ATTRIBUTE_READ_ONLY',
    w._C_SetAttributeValue(hS, key.h, buildTpl([{ type: CKA.CLASS, ulong: CKO.DATA }]), 1),
    CKR.ATTRIBUTE_READ_ONLY);

  // C_GetObjectSize returns a positive estimate.
  const szP = alloc(4); writeU32(szP, 0);
  check('C_GetObjectSize → OK', w._C_GetObjectSize(hS, key.h, szP), CKR.OK);
  check('object size > 0', readU32(szP) > 0 ? 1 : 0, 1);

  // CKA_UNIQUE_ID present on a generated object AND readable via the
  // canonical OASIS attribute type 0x4 (the F1 pkcs11t.h re-sync regression).
  function readUniqueId(h) {
    const probe = buildTpl([{ type: 0x4 /* CKA_UNIQUE_ID per pkcs11t.h */ }]);
    const rv1 = w._C_GetAttributeValue(hS, h, probe, 1);
    const len = readU32(probe + 8);
    if (rv1 !== CKR.OK || len === 0 || len === 0xffffffff) return { rv: rv1, id: null };
    const vp = alloc(len);
    writeU32(probe + 4, vp); writeU32(probe + 8, len);
    const rv2 = w._C_GetAttributeValue(hS, h, probe, 1);
    return { rv: rv2, id: Buffer.from(new Uint8Array(mem().buffer, vp, len)).toString() };
  }
  const uid = readUniqueId(key.h);
  check('CKA_UNIQUE_ID readable via attribute type 0x4 → OK', uid.rv, CKR.OK);
  check('CKA_UNIQUE_ID non-empty', uid.id && uid.id.length > 0 ? 1 : 0, 1);

  // C_CopyObject round-trip: copy exists, carries a FRESH CKA_UNIQUE_ID.
  const hCopyP = alloc(4);
  check('C_CopyObject → OK', w._C_CopyObject(hS, key.h, 0, 0, hCopyP), CKR.OK);
  const hCopy = readU32(hCopyP);
  const out = buildTpl([{ type: CKA.CLASS, bytes: new Uint8Array(4) }]);
  check('copy is a live object → OK', w._C_GetAttributeValue(hS, hCopy, out, 1), CKR.OK);
  const uidCopy = readUniqueId(hCopy);
  check('copy CKA_UNIQUE_ID readable → OK', uidCopy.rv, CKR.OK);
  check('copy received a FRESH CKA_UNIQUE_ID', uidCopy.id !== uid.id ? 1 : 0, 1);
}

section('Round-2 — dynamic TokenInfo (§5.5, T7)');
{
  const ti = getTokenInfo();
  check('C_GetTokenInfo → OK', ti.rv, CKR.OK);
  check('label matches C_InitToken value', ti.label === 'conformance' ? 1 : 0, 1);
  check('CKF_USER_PIN_INITIALIZED set after InitPIN', ti.flags & 0x8, 0x8);
  check('CKF_TOKEN_INITIALIZED set', ti.flags & 0x400, 0x400);
  check('ulSessionCount nonzero while a session is open', ti.sessionCount > 0 ? 1 : 0, 1);
  check('ulRwSessionCount nonzero (hS is R/W)', ti.rwSessionCount > 0 ? 1 : 0, 1);
}

section('Round-2 — C_SignUpdate/Final ≡ one-shot C_Sign (CKM_SHA256_HMAC)');
{
  const tpl = buildTpl([{ type: CKA.CLASS, ulong: CKO.SECRET_KEY },
    { type: CKA.KEY_TYPE, ulong: CKK.GENERIC_SECRET },
    { type: CKA.VALUE, bytes: new Uint8Array(32).fill(0x42) },
    { type: CKA.SIGN, bool: true }]);
  const hp = alloc(4);
  check('import HMAC key → OK', w._C_CreateObject(hS, tpl, 4, hp), CKR.OK);
  const hKey = readU32(hp);
  const msg = new Uint8Array(24).map((_, i) => i * 7 & 0xff);
  const msgP = alloc(24); writeBytes(msgP, msg);

  // one-shot
  check('SignInit (one-shot) → OK', w._C_SignInit(hS, buildMech(CKM.SHA256_HMAC), hKey), CKR.OK);
  const sl = alloc(4); writeU32(sl, 0);
  w._C_Sign(hS, msgP, 24, 0, sl);
  const sig1 = alloc(readU32(sl));
  check('C_Sign (one-shot) → OK', w._C_Sign(hS, msgP, 24, sig1, sl), CKR.OK);
  const oneShot = Buffer.from(new Uint8Array(mem().buffer, sig1, readU32(sl)));

  // multipart: 10-byte + 14-byte parts
  check('SignInit (multipart) → OK', w._C_SignInit(hS, buildMech(CKM.SHA256_HMAC), hKey), CKR.OK);
  check('C_SignUpdate part 1 → OK', w._C_SignUpdate(hS, msgP, 10), CKR.OK);
  check('C_SignUpdate part 2 → OK', w._C_SignUpdate(hS, msgP + 10, 14), CKR.OK);
  const sl2 = alloc(4); writeU32(sl2, 0);
  w._C_SignFinal(hS, 0, sl2);
  const sig2 = alloc(readU32(sl2));
  check('C_SignFinal → OK', w._C_SignFinal(hS, sig2, sl2), CKR.OK);
  const multi = Buffer.from(new Uint8Array(mem().buffer, sig2, readU32(sl2)));
  check('multipart HMAC byte-equals one-shot', oneShot.equals(multi) ? 1 : 0, 1);
}

section('Round-2 — mechanism table contents + FIPS ranges (F2/T8)');
{
  const cntP = alloc(4); writeU32(cntP, 0);
  check('C_GetMechanismList count query → OK', w._C_GetMechanismList(0, 0, cntP), CKR.OK);
  const n = readU32(cntP);
  const listP = alloc(4 * n);
  check('C_GetMechanismList → OK', w._C_GetMechanismList(0, listP, cntP), CKR.OK);
  const mechs = new Set(Array.from(new Uint32Array(mem().buffer, listP, n)));
  for (const [name, id] of [
    ['CKM_SHA384_RSA_PKCS 0x41', CKM.SHA384_RSA_PKCS],
    ['CKM_SHA512_RSA_PKCS 0x42', CKM.SHA512_RSA_PKCS],
    ['CKM_SHA384_RSA_PKCS_PSS 0x44', CKM.SHA384_RSA_PKCS_PSS],
    ['CKM_SHA512_RSA_PKCS_PSS 0x45', CKM.SHA512_RSA_PKCS_PSS],
    ['CKM_CHACHA20 0x1226', CKM.CHACHA20],
    ['CKM_CHACHA20_POLY1305 0x4021', CKM.CHACHA20_POLY1305],
  ]) {
    check(`mechanism list contains ${name}`, mechs.has(id) ? 1 : 0, 1);
  }
  // CKM_ML_KEM min/max are FIPS 203 ek byte sizes (800 = ML-KEM-512 … 1568 = ML-KEM-1024).
  const info = alloc(12);
  check('C_GetMechanismInfo(CKM_ML_KEM) → OK', w._C_GetMechanismInfo(0, CKM.ML_KEM, info), CKR.OK);
  check('ML-KEM ulMinKeySize = 800 (FIPS 203)', readU32(info), 800);
  check('ML-KEM ulMaxKeySize = 1568 (FIPS 203)', readU32(info + 4), 1568);
}

section('Round-2 — T5 message API ≡ one-shot GCM (§5.19)');
{
  const key = genAes(hS);
  check('fixture: AES key → OK', key.rv, CKR.OK);
  const iv = new Uint8Array(12).map((_, i) => i + 1);
  const pt = new Uint8Array(20).map((_, i) => 0xc0 + i);
  const ptP = alloc(20); writeBytes(ptP, pt);

  // one-shot reference: C_Encrypt GCM → ciphertext(20) || tag(16)
  check('C_EncryptInit GCM (reference) → OK',
    w._C_EncryptInit(hS, buildMech(CKM.AES_GCM, gcmParams(iv, null, 128)), key.h), CKR.OK);
  const refLenP = alloc(4); writeU32(refLenP, 0);
  w._C_Encrypt(hS, ptP, 20, 0, refLenP);
  const refLen = readU32(refLenP);
  const refP = alloc(refLen);
  check('C_Encrypt (reference) → OK', w._C_Encrypt(hS, ptP, 20, refP, refLenP), CKR.OK);
  check('reference output is ct(20)+tag(16)', readU32(refLenP), 36);
  const reference = Buffer.from(new Uint8Array(mem().buffer, refP, 36));

  // message path: Init → Begin → Next(12) → Next(8, END_OF_MESSAGE) → Final
  // CK_GCM_MESSAGE_PARAMS (wasm32, 24 B): pIv, ulIvLen, ulIvFixedBits,
  // ivGenerator (CKG_NO_GENERATE=0), pTag, ulTagBits
  const ivP = alloc(12); writeBytes(ivP, iv);
  const tagP = alloc(16);
  const gmp = alloc(24);
  new Uint32Array(mem().buffer, gmp, 6).set([ivP, 12, 0, 0, tagP, 128]);
  check('C_MessageEncryptInit GCM → OK',
    w._C_MessageEncryptInit(hS, buildMech(CKM.AES_GCM), key.h), CKR.OK);
  check('C_EncryptMessageBegin → OK', w._C_EncryptMessageBegin(hS, gmp, 24, 0, 0), CKR.OK);
  const out1 = alloc(12); const ol1 = alloc(4); writeU32(ol1, 12);
  check('C_EncryptMessageNext part 1 (12 B) → OK',
    w._C_EncryptMessageNext(hS, gmp, 24, ptP, 12, out1, ol1, 0), CKR.OK);
  const out2 = alloc(8); const ol2 = alloc(4); writeU32(ol2, 8);
  check('C_EncryptMessageNext part 2 (8 B, END_OF_MESSAGE) → OK',
    w._C_EncryptMessageNext(hS, gmp, 24, ptP + 12, 8, out2, ol2, 0x1), CKR.OK);
  check('C_MessageEncryptFinal → OK', w._C_MessageEncryptFinal(hS), CKR.OK);
  const streamed = Buffer.concat([
    Buffer.from(new Uint8Array(mem().buffer, out1, readU32(ol1))),
    Buffer.from(new Uint8Array(mem().buffer, out2, readU32(ol2))),
    Buffer.from(new Uint8Array(mem().buffer, tagP, 16)),
  ]);
  check('streamed ct+tag byte-equals one-shot GCM', streamed.equals(reference) ? 1 : 0, 1);
}

section('Round-2 — SP800-108 KBKDF PRF must be a keyed-MAC mechanism (§6.26)');
{
  const crypto = require('crypto');
  const baseVal = new Uint8Array(32).map((_, i) => (i * 11 + 3) & 0xff);
  const tpl = buildTpl([
    { type: CKA.CLASS, ulong: CKO.SECRET_KEY },
    { type: CKA.KEY_TYPE, ulong: CKK.GENERIC_SECRET },
    { type: CKA.VALUE, bytes: baseVal },
    { type: CKA.DERIVE, bool: true }]);
  const hp = alloc(4);
  check('import KBKDF base key → OK', w._C_CreateObject(hS, tpl, 4, hp), CKR.OK);
  const hBase = readU32(hp);

  // CK_SP800_108_KDF_PARAMS (wasm32, 12 B): prfType, ulNumberOfDataParams=0,
  // pDataParams=NULL — the engine's legacy default fixed-input is then a
  // 32-bit BE counter prefix and nothing else.
  const derive = (prf) => {
    const params = new Uint8Array(new Uint32Array([prf, 0, 0]).buffer);
    const dTpl = buildTpl([
      { type: CKA.CLASS, ulong: CKO.SECRET_KEY },
      { type: CKA.KEY_TYPE, ulong: CKK.GENERIC_SECRET },
      { type: CKA.VALUE_LEN, ulong: 32 }]);
    const hd = alloc(4); writeU32(hd, 0);
    const rv = w._C_DeriveKey(hS, buildMech(CKM.SP800_108_COUNTER_KDF, params), hBase, dTpl, 3, hd);
    return { rv, h: readU32(hd) };
  };
  const readValue = (h) => {
    const out = buildTpl([{ type: CKA.VALUE, bytes: new Uint8Array(32) }]);
    const rv = w._C_GetAttributeValue(hS, h, out, 1);
    return { rv, value: Buffer.from(new Uint8Array(mem().buffer, readU32(out + 4), readU32(out + 8))) };
  };

  // A bare hash is NOT a PRF (PKCS#11 v3.2 §6.26 — keyed-MAC mechanisms only).
  check('C_DeriveKey SP800-108 with bare CKM_SHA256 PRF → MECHANISM_PARAM_INVALID',
    derive(CKM.SHA256).rv, CKR.MECHANISM_PARAM_INVALID);

  // HMAC-SHA384 PRF byte-compares against an independent Node-crypto
  // counter-mode reference: KO = ⌈L/48⌉ blocks of HMAC-SHA384(K, BE32(i)).
  const r384 = derive(CKM.SHA384_HMAC);
  check('C_DeriveKey SP800-108 with CKM_SHA384_HMAC PRF → OK', r384.rv, CKR.OK);
  if (r384.rv === CKR.OK) {
    const got384 = readValue(r384.h);
    check('read SHA384-PRF derived CKA_VALUE → OK', got384.rv, CKR.OK);
    let ref = Buffer.alloc(0);
    for (let i = 1; ref.length < 32; i++) {
      const ctr = Buffer.alloc(4); ctr.writeUInt32BE(i);
      ref = Buffer.concat([ref,
        crypto.createHmac('sha384', Buffer.from(baseVal)).update(ctr).digest()]);
    }
    check('SHA384-PRF KBKDF byte-equals Node-crypto counter-mode reference',
      got384.value.equals(ref.subarray(0, 32)) ? 1 : 0, 1);

    // Cross-digest: identical inputs under HMAC-SHA256 must produce a
    // DIFFERENT KO (proves the digest is actually switched, not defaulted).
    const r256 = derive(CKM.SHA256_HMAC);
    check('C_DeriveKey SP800-108 with CKM_SHA256_HMAC PRF → OK', r256.rv, CKR.OK);
    if (r256.rv === CKR.OK) {
      const got256 = readValue(r256.h);
      check('read SHA256-PRF derived CKA_VALUE → OK', got256.rv, CKR.OK);
      check('SHA384-PRF output differs from SHA256-PRF output (no silent default)',
        got384.value.equals(got256.value) ? 0 : 1, 1);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n════════ RESULT: ${passes} passed, ${failures} failed ════════`);
process.exit(failures === 0 ? 0 : 1);
