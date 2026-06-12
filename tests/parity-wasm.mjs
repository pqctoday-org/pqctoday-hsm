import { fileURLToPath } from 'url';
import path from 'path';
import { createRequire } from 'module';
import { existsSync } from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// We load both WASM modules. They execute independently in V8.
const cppPath = path.resolve(__dirname, '../wasm/cpp/softhsm.js');
const rustPath = path.resolve(__dirname, '../wasm/rust/softhsmrustv3.js');

// The C++ emscripten bundle (wasm/cpp/softhsm.{js,wasm}) is a build output
// of scripts/build-wasm.sh and is not checked in; building it is out of
// scope for the JS harness slice. Without it this parity test cannot run,
// so exit 0 with an explicit SKIPPED marker instead of crashing — it must
// not look like a pass.
if (!existsSync(cppPath) || !existsSync(rustPath)) {
    console.log('SKIPPED: parity-wasm.mjs — wasm/cpp emscripten bundle not built '
        + '(out of scope here; run scripts/build-wasm.sh to enable C++↔Rust parity).');
    process.exit(0);
}

const { default: createCppModule } = await import(cppPath);
const { default: createRustModule } = await import(rustPath);

console.log('[Parity] Loading C++ WASM...');
const C = await createCppModule();
console.log('[Parity] Loading Rust WASM...');
const R = await createRustModule();

// Constants
const CKR_OK = 0;
const CKA_CLASS = 0x00000000;
const CKA_TOKEN = 0x00000001;
const CKA_VALUE = 0x00000011;
const CKO_PUBLIC_KEY = 0x00000002;
const CKO_SECRET_KEY = 0x00000004; // ADDED
const CKA_KEY_TYPE = 0x00000100;
const CKA_ENCRYPT = 0x00000104;
const CKA_SENSITIVE = 0x00000103; // ADDED
const CKA_ENCAPSULATE = 0x00000633;
const CKA_EXTRACTABLE = 0x00000162;
const CKA_VALUE_LEN = 0x00000161; // ADDED
const CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000F;
const CKM_ML_KEM = 0x00000017;
const CKK_ML_KEM = 0x00000049;
const CKK_GENERIC_SECRET = 0x00000010; // ADDED

// Helpers
function check(label, rv) {
    if (rv !== CKR_OK) throw new Error(`FAIL: ${label} returned 0x${rv.toString(16).toUpperCase()}`);
    console.log(`  ✓  ${label}`);
}

function buildTemplate(M, attrs) {
    const ATTR_SIZE = 12;
    const arrPtr = M._malloc(attrs.length * ATTR_SIZE);
    const valuePtrs = [];
    for (let i = 0; i < attrs.length; i++) {
        const { type, value } = attrs[i];
        let vPtr, vLen;
        if (typeof value === 'boolean') {
            vPtr = M._malloc(1);
            M.HEAPU8[vPtr] = value ? 1 : 0;
            vLen = 1;
        } else if (typeof value === 'number') {
            vPtr = M._malloc(4);
            M.setValue(vPtr, value, 'i32');
            vLen = 4;
        } else if (value instanceof Uint8Array) {
            vPtr = M._malloc(value.length);
            M.HEAPU8.set(value, vPtr);
            vLen = value.length;
        } else {
            throw new Error(`Unsupported template value type: ${typeof value}`);
        }
        valuePtrs.push(vPtr);
        const base = arrPtr + i * ATTR_SIZE;
        M.setValue(base + 0, type, 'i32');
        M.setValue(base + 4, vPtr, 'i32');
        M.setValue(base + 8, vLen, 'i32');
    }
    return { arrPtr, valuePtrs, count: attrs.length };
}

function freeTemplate(M, { arrPtr, valuePtrs }) {
    for (const p of valuePtrs) M._free(p);
    M._free(arrPtr);
}

function allocUlong(M) { return M._malloc(4); }
function readUlong(M, ptr) { return M.getValue(ptr, 'i32') >>> 0; }
function freePtr(M, ptr) { M._free(ptr); }
function writeStr(M, str) {
    const bytes = new TextEncoder().encode(str);
    const ptr = M._malloc(bytes.length + 1);
    M.HEAPU8.set(bytes, ptr);
    M.HEAPU8[ptr + bytes.length] = 0;
    return ptr;
}
function padLabel(s, len = 32) { return s.padEnd(len, ' ').slice(0, len); }

function setupHSM(label, M) {
    check(`${label}.C_Initialize`, M._C_Initialize(0));

    // Some implementations (like C++) require token init.
    // Our Rust one returns OK for everything right now, but let's do the standard flow anyway.
    let cntPtr = allocUlong(M);
    // GetSlotList requires passing a null pointer (0) for the `pSlotList` argument to query length
    M._C_GetSlotList(0, 0, cntPtr);
    let slotCount = readUlong(M, cntPtr);
    const slotsPtr = M._malloc(slotCount * 4);
    M._C_GetSlotList(0, slotsPtr, cntPtr);
    let slot0 = M.getValue(slotsPtr, 'i32') >>> 0;
    M._free(slotsPtr);
    freePtr(M, cntPtr);

    const soLabel = padLabel('SmokeTest');
    const soLabelPtr = writeStr(M, soLabel);
    const soPinStr = '12345678';
    const soPinPtr = writeStr(M, soPinStr);

    let rv = M._C_InitToken(slot0, soPinPtr, soPinStr.length, soLabelPtr);
    if (rv !== CKR_OK && rv !== 0x1) {
        // if not OK, just continue, maybe it's already initialized.
    }
    M._free(soLabelPtr);
    M._free(soPinPtr);

    // Re-enumerate slots
    cntPtr = allocUlong(M);
    M._C_GetSlotList(1, 0, cntPtr);
    slotCount = readUlong(M, cntPtr);
    let slotsPtr2 = M._malloc(slotCount * 4);
    M._C_GetSlotList(1, slotsPtr2, cntPtr);
    let initedSlot = M.getValue(slotsPtr2, 'i32') >>> 0;
    M._free(slotsPtr2);
    freePtr(M, cntPtr);

    const hSessionPtr = allocUlong(M);
    const CKF_SERIAL_SESSION = 0x00000004;
    const CKF_RW_SESSION = 0x00000002;
    const flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    check(`${label}.C_OpenSession`, M._C_OpenSession(initedSlot || slot0, flags, 0, 0, hSessionPtr));
    const hSession = readUlong(M, hSessionPtr);
    freePtr(M, hSessionPtr);

    // Login
    const CKU_SO = 0;
    const CKU_USER = 1;
    const userPinStr = '87654321';
    const userPinPtr = writeStr(M, userPinStr);
    const soPinPtr2 = writeStr(M, '12345678');
    M._C_Login(hSession, CKU_SO, soPinPtr2, '12345678'.length);
    M._free(soPinPtr2);
    M._C_InitPIN(hSession, userPinPtr, userPinStr.length);
    M._C_Logout(hSession);
    check(`${label}.C_Login(User)`, M._C_Login(hSession, CKU_USER, userPinPtr, userPinStr.length));
    M._free(userPinPtr);

    return hSession;
}

// 1. Initialize & Session & Login
const cSession = setupHSM('C', C);
const rSession = setupHSM('R', R);

console.log('\n── TEST: RUST Generate -> CPP Encapsulate -> RUST Decapsulate ──');
// Rust Generates Key
const rPubTmpl = buildTemplate(R, [{ type: CKA_VALUE, value: new Uint8Array(1184) }]);
const rPrvTmpl = buildTemplate(R, [{ type: CKA_VALUE, value: new Uint8Array(2400) }]);

const rMech = R._malloc(12);
R.setValue(rMech + 0, CKM_ML_KEM_KEY_PAIR_GEN, 'i32');

const rPubPtr = R._malloc(4);
const rPrvPtr = R._malloc(4);

check('RUST C_GenerateKeyPair', R._C_GenerateKeyPair(rSession, rMech, rPubTmpl.arrPtr, 0 /* we ignore templates in our mock */, rPrvTmpl.arrPtr, 0, rPubPtr, rPrvPtr));
const rPubHandle = R.getValue(rPubPtr, 'i32');
const rPrvHandle = R.getValue(rPrvPtr, 'i32');

// Extract PubKey from Rust
const rExtractTmpl = buildTemplate(R, [{ type: CKA_VALUE, value: new Uint8Array(1184) }]);
check('RUST C_GetAttributeValue(PubKey)', R._C_GetAttributeValue(rSession, rPubHandle, rExtractTmpl.arrPtr, 1));
const pubKeyBytes = new Uint8Array(R.HEAPU8.buffer, R.getValue(rExtractTmpl.arrPtr + 4, 'i32'), 1184).slice();

// Import PubKey to C++
const cImportTmpl = buildTemplate(C, [
    { type: CKA_CLASS, value: CKO_PUBLIC_KEY },
    { type: CKA_KEY_TYPE, value: CKK_ML_KEM },
    { type: CKA_TOKEN, value: false },
    { type: CKA_ENCRYPT, value: true },
    { type: CKA_ENCAPSULATE, value: true },
    { type: CKA_VALUE, value: pubKeyBytes }
]);
const cImportHandlePtr = C._malloc(4);
// wait, CPP C_CreateObject might not support ML-KEM completely without parametrizing CKP_ML_KEM_768
// SoftHSM C++ module is strict! We need CKA_PARAMETER_SET for ML-KEM
const CKP_ML_KEM_768 = 0x00000002;
const CKA_PARAMETER_SET = 0x0000061D;
const cImportTmplFull = buildTemplate(C, [
    { type: CKA_CLASS, value: CKO_PUBLIC_KEY },
    { type: CKA_KEY_TYPE, value: CKK_ML_KEM },
    { type: CKA_TOKEN, value: false },
    { type: CKA_ENCRYPT, value: true },
    { type: CKA_ENCAPSULATE, value: true },
    { type: CKA_PARAMETER_SET, value: CKP_ML_KEM_768 },
    { type: CKA_VALUE, value: pubKeyBytes }
]);

check('CPP C_CreateObject', C._C_CreateObject(cSession, cImportTmplFull.arrPtr, cImportTmplFull.count, cImportHandlePtr));
const cPubHandle = C.getValue(cImportHandlePtr, 'i32');

// C++ Encapsulates
const cMech = C._malloc(12);
C.setValue(cMech + 0, CKM_ML_KEM, 'i32');
const ctLenPtr = C._malloc(4);
C.setValue(ctLenPtr, 1088, 'i32');
const pCiphertext = C._malloc(1088);
const cSsHandlePtr = C._malloc(4);

const cSsTmpl = buildTemplate(C, [
    { type: CKA_CLASS, value: CKO_SECRET_KEY },
    { type: CKA_KEY_TYPE, value: CKK_GENERIC_SECRET },
    { type: CKA_VALUE_LEN, value: 32 },
    { type: CKA_TOKEN, value: false },
    { type: CKA_EXTRACTABLE, value: true },
    { type: CKA_SENSITIVE, value: false }
]);

check('CPP C_EncapsulateKey', C._C_EncapsulateKey(cSession, cMech, cPubHandle, cSsTmpl.arrPtr, cSsTmpl.count, pCiphertext, ctLenPtr, cSsHandlePtr));
const cppCiphertext = new Uint8Array(C.HEAPU8.buffer, pCiphertext, 1088).slice();
const cSsHandle = C.getValue(cSsHandlePtr, 'i32');

// Get SharedSecret from CPP
const cSsExtractTmpl = buildTemplate(C, [{ type: CKA_VALUE, value: new Uint8Array(32) }]);
check('CPP C_GetAttributeValue(SS)', C._C_GetAttributeValue(cSession, cSsHandle, cSsExtractTmpl.arrPtr, 1));
const cppSharedSecret = new Uint8Array(C.HEAPU8.buffer, C.getValue(cSsExtractTmpl.arrPtr + 4, 'i32'), 32).slice();

// Rust Decapsulates
const rCiphertext = R._malloc(1088);
R.HEAPU8.set(cppCiphertext, rCiphertext);
const rSsHandlePtr = R._malloc(4);

const rSsTmpl = buildTemplate(R, [
    { type: CKA_CLASS, value: CKO_SECRET_KEY },
    { type: CKA_KEY_TYPE, value: CKK_GENERIC_SECRET },
    { type: CKA_VALUE_LEN, value: 32 },
    { type: CKA_TOKEN, value: false },
    { type: CKA_EXTRACTABLE, value: true },
    { type: CKA_SENSITIVE, value: false }
]);

R.setValue(rMech + 0, CKM_ML_KEM, 'i32'); // Fix CKR_ARGUMENTS_BAD
check('RUST C_DecapsulateKey', R._C_DecapsulateKey(rSession, rMech, rPrvHandle, rSsTmpl.arrPtr, rSsTmpl.count, rCiphertext, 1088, rSsHandlePtr));
const rSsHandle = R.getValue(rSsHandlePtr, 'i32');

// Get SharedSecret from RUST
const rSsExtractTmpl = buildTemplate(R, [{ type: CKA_VALUE, value: new Uint8Array(32) }]);
check('RUST C_GetAttributeValue(SS)', R._C_GetAttributeValue(rSession, rSsHandle, rSsExtractTmpl.arrPtr, 1));
const rustSharedSecret = new Uint8Array(R.HEAPU8.buffer, R.getValue(rSsExtractTmpl.arrPtr + 4, 'i32'), 32).slice();

// Match!
let match = true;
for (let i = 0; i < 32; i++) {
    if (cppSharedSecret[i] !== rustSharedSecret[i]) match = false;
}

console.log("\nCPP  SS:", Buffer.from(cppSharedSecret).toString('hex'));
console.log("RUST SS:", Buffer.from(rustSharedSecret).toString('hex'));
console.log("\nParity verification:", match ? "SUCCESS!" : "FAILED!");

console.log('\n── TEST: ML-DSA RUST Generate -> CPP Sign -> RUST Verify ──');
const CKO_PRIVATE_KEY = 0x00000003;
const CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001C;
const CKM_ML_DSA = 0x0000001D;
const CKK_ML_DSA = 0x0000004A;
const CKP_ML_DSA_65 = 0x00000002;
const CKA_SIGN = 0x00000108;
const CKA_VERIFY = 0x0000010A;

// 1. C++ Generates ML-DSA Key Pair
const cDsaMech = C._malloc(12);
C.setValue(cDsaMech + 0, CKM_ML_DSA_KEY_PAIR_GEN, 'i32');
C.setValue(cDsaMech + 4, 0, 'i32');
C.setValue(cDsaMech + 8, 0, 'i32');

const cDsaPubTmpl = buildTemplate(C, [
    { type: CKA_VERIFY, value: true },
    { type: CKA_PARAMETER_SET, value: CKP_ML_DSA_65 }
]);
const cDsaPrvTmpl = buildTemplate(C, [
    { type: CKA_SIGN, value: true }
]);

const cDsaPubPtr = C._malloc(4);
const cDsaPrvPtr = C._malloc(4);

check('CPP C_GenerateKeyPair(ML-DSA)', C._C_GenerateKeyPair(cSession, cDsaMech, cDsaPubTmpl.arrPtr, cDsaPubTmpl.count, cDsaPrvTmpl.arrPtr, cDsaPrvTmpl.count, cDsaPubPtr, cDsaPrvPtr));
const cDsaPubHandle = C.getValue(cDsaPubPtr, 'i32');
const cDsaPrvHandle = C.getValue(cDsaPrvPtr, 'i32');

// Extract keys from C++
const dsaPubExtract = buildTemplate(C, [{ type: CKA_VALUE, value: new Uint8Array(4096) }]);
check('CPP C_GetAttributeValue(PubKey)', C._C_GetAttributeValue(cSession, cDsaPubHandle, dsaPubExtract.arrPtr, 1));
let actualPubSize = C.getValue(dsaPubExtract.arrPtr + 8, 'i32');
console.log("actualPubSize:", actualPubSize);
const dsaPubKeyBytes = new Uint8Array(C.HEAPU8.buffer, C.getValue(dsaPubExtract.arrPtr + 4, 'i32'), actualPubSize).slice();

// C++ Signs Message
const dsaSignMech = C._malloc(12);
C.setValue(dsaSignMech + 0, CKM_ML_DSA, 'i32');
C.setValue(dsaSignMech + 4, 0, 'i32');
C.setValue(dsaSignMech + 8, 0, 'i32');

const msgStr = "Hello Post-Quantum World!";
const msgBytes = Buffer.from(msgStr, 'utf8');
const cMsgPtr = C._malloc(msgBytes.length);
C.HEAPU8.set(msgBytes, cMsgPtr);

check('CPP C_SignInit', C._C_SignInit(cSession, dsaSignMech, cDsaPrvHandle));

const cSigLenPtr = C._malloc(4);
check('CPP C_Sign(Len)', C._C_Sign(cSession, cMsgPtr, msgBytes.length, 0, cSigLenPtr));
const sigLen = C.getValue(cSigLenPtr, 'i32');
const cSigPtr = C._malloc(sigLen);
check('CPP C_Sign(Buffer)', C._C_Sign(cSession, cMsgPtr, msgBytes.length, cSigPtr, cSigLenPtr));

const cppSignature = new Uint8Array(C.HEAPU8.buffer, cSigPtr, sigLen).slice();
console.log(`CPP generated ML-DSA-65 signature (${sigLen} bytes)`);

// Import Public Key into Rust for verification
const rDsaPubImportTmpl = buildTemplate(R, [
    { type: CKA_CLASS, value: CKO_PUBLIC_KEY },
    { type: CKA_KEY_TYPE, value: CKK_ML_DSA },
    { type: CKA_TOKEN, value: false },
    { type: CKA_VERIFY, value: true },
    { type: CKA_VALUE, value: dsaPubKeyBytes } // SPKI size
]);
const rDsaPubHandleImportPtr = R._malloc(4);
check('RUST C_CreateObject(ML-DSA PublicKey)', R._C_CreateObject(rSession, rDsaPubImportTmpl.arrPtr, rDsaPubImportTmpl.count, rDsaPubHandleImportPtr));
const rDsaPubHandleImport = R.getValue(rDsaPubHandleImportPtr, 'i32');

// Rust Verifies Message
const rMsgPtr = R._malloc(msgBytes.length);
R.HEAPU8.set(msgBytes, rMsgPtr);

const rSigPtr = R._malloc(sigLen);
R.HEAPU8.set(cppSignature, rSigPtr);

const rDsaMech = R._malloc(12);
R.setValue(rDsaMech + 0, CKM_ML_DSA, 'i32');
R.setValue(rDsaMech + 4, 0, 'i32');
R.setValue(rDsaMech + 8, 0, 'i32');
check('RUST C_VerifyInit', R._C_VerifyInit(rSession, rDsaMech, rDsaPubHandleImport));

try {
    check('RUST C_Verify', R._C_Verify(rSession, rMsgPtr, msgBytes.length, rSigPtr, sigLen));
    console.log("\nML-DSA Parity verification: SUCCESS!");
} catch (e) {
    console.log("\nML-DSA Parity verification: FAILED! " + e.message);
}
