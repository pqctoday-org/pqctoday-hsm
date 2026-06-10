// Focused test for R3.6 — CKA_PARAMETER_SET required on PQC keygen.
// Verifies ML-DSA C_GenerateKeyPair: succeeds with param set, returns
// CKR_TEMPLATE_INCOMPLETE (0xD0) without it.
const fs = require('fs');
const wasmBuf = fs.readFileSync(__dirname + '/pkg/softhsmrustv3_bg.wasm');
const bg = require('./pkg/softhsmrustv3_bg.js');
const wasmModule = new WebAssembly.Module(wasmBuf);
const wasmInstance = new WebAssembly.Instance(wasmModule, { './softhsmrustv3_bg.js': bg });
bg.__wbg_set_wasm(wasmInstance.exports);
const w = wasmInstance.exports;
const mem = () => w.memory;

const CKA_CLASS = 0, CKO_PUBLIC_KEY = 2, CKO_PRIVATE_KEY = 3, CKA_KEY_TYPE = 0x100;
const CKK_ML_DSA = 0x4a, CKA_PARAMETER_SET = 0x61d, CKA_SIGN = 0x108, CKA_VERIFY = 0x10a;
const CKM_ML_DSA_KEY_PAIR_GEN = 0x1c, CKP_ML_DSA_65 = 2;
const CKR_OK = 0, CKR_TEMPLATE_INCOMPLETE = 0xD0;

// write a 12-byte CK_ATTRIBUTE[] (wasm32: type u32, pValue u32 ptr, ulValueLen u32),
// ulong values stored inline after the array.
function buildTpl(attrs) {
  const arrLen = attrs.length * 12;
  let dataLen = 0; for (const a of attrs) if (a.ulong !== undefined) dataLen += 4;
  const ptr = w._malloc(arrLen + dataLen);
  let dptr = ptr + arrLen;
  const u32 = new Uint32Array(mem().buffer);
  attrs.forEach((a, i) => {
    const base = (ptr + i * 12) >> 2;
    if (a.ulong !== undefined) {
      new Uint32Array(mem().buffer, dptr, 1)[0] = a.ulong;
      u32[base] = a.type; u32[base + 1] = dptr; u32[base + 2] = 4;
      dptr += 4;
    } else { u32[base] = a.type; u32[base + 1] = 0; u32[base + 2] = 0; }
  });
  return ptr;
}
function buildMech(m) { const p = w._malloc(12); const u = new Uint32Array(mem().buffer, p, 3); u[0] = m; u[1] = 0; u[2] = 0; return p; }

w._C_Initialize(0);
const ses = w._malloc(4);
w._C_OpenSession(0, 0x06, 0, 0, ses);
const hSession = new Uint32Array(mem().buffer, ses, 1)[0];

const mech = buildMech(CKM_ML_DSA_KEY_PAIR_GEN);
const prvTpl = buildTpl([
  { type: CKA_CLASS, ulong: CKO_PRIVATE_KEY },
  { type: CKA_KEY_TYPE, ulong: CKK_ML_DSA },
  { type: CKA_SIGN, ulong: 1 },
]);

// Case 1: WITH CKA_PARAMETER_SET → expect CKR_OK
const pubTplOk = buildTpl([
  { type: CKA_CLASS, ulong: CKO_PUBLIC_KEY },
  { type: CKA_KEY_TYPE, ulong: CKK_ML_DSA },
  { type: CKA_VERIFY, ulong: 1 },
  { type: CKA_PARAMETER_SET, ulong: CKP_ML_DSA_65 },
]);
const hPub = w._malloc(4), hPrv = w._malloc(4);
const rvOk = w._C_GenerateKeyPair(hSession, mech, pubTplOk, 4, prvTpl, 3, hPub, hPrv);

// Case 2: WITHOUT CKA_PARAMETER_SET → expect CKR_TEMPLATE_INCOMPLETE
const pubTplNo = buildTpl([
  { type: CKA_CLASS, ulong: CKO_PUBLIC_KEY },
  { type: CKA_KEY_TYPE, ulong: CKK_ML_DSA },
  { type: CKA_VERIFY, ulong: 1 },
]);
const hPub2 = w._malloc(4), hPrv2 = w._malloc(4);
const rvNo = w._C_GenerateKeyPair(hSession, buildMech(CKM_ML_DSA_KEY_PAIR_GEN), pubTplNo, 3, prvTpl, 3, hPub2, hPrv2);

let pass = true;
if (rvOk === CKR_OK) console.log('✅ ML-DSA keygen WITH CKA_PARAMETER_SET → CKR_OK');
else { console.log(`❌ WITH param set → rv=0x${rvOk.toString(16)} (expected 0)`); pass = false; }
if (rvNo === CKR_TEMPLATE_INCOMPLETE) console.log('✅ ML-DSA keygen WITHOUT CKA_PARAMETER_SET → CKR_TEMPLATE_INCOMPLETE');
else { console.log(`❌ WITHOUT param set → rv=0x${rvNo.toString(16)} (expected 0xD0)`); pass = false; }
process.exit(pass ? 0 : 1);
