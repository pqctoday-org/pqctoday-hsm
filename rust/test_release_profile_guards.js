// Functional checks for the shipped-shape release WASM bundle.
//
// Run after `./build-wasm-bundle.sh` (without --acvp-test). This deliberately
// drives the raw PKCS#11 ABI rather than trusting only the build manifest: a
// non-null CK_C_INITIALIZE_ARGS.pReserved must be rejected in production.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PKG_DIR = path.join(__dirname, 'pkg-release');
const manifestPath = path.join(PKG_DIR, 'build-profile.json');
const wasmPath = path.join(PKG_DIR, 'softhsmrustv3_bg.wasm');
const gluePath = path.join(PKG_DIR, 'softhsmrustv3_bg.js');

for (const required of [manifestPath, wasmPath, gluePath]) {
  if (!fs.existsSync(required)) {
    console.error(`FATAL: missing ${required}; run ./build-wasm-bundle.sh first`);
    process.exit(2);
  }
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
if (manifest.profile !== 'release' || manifest.acvp_test_hooks !== false) {
  throw new Error(`unexpected shipped build manifest: ${JSON.stringify(manifest)}`);
}
if (!Array.isArray(manifest.features) || manifest.features.length !== 0) {
  throw new Error(`shipped build unexpectedly enables features: ${JSON.stringify(manifest.features)}`);
}

const wasmBuf = fs.readFileSync(wasmPath);
const wasmSha256 = crypto.createHash('sha256').update(wasmBuf).digest('hex');
if (manifest.wasm_sha256 !== wasmSha256) {
  throw new Error(
    `release manifest hash mismatch: manifest=${manifest.wasm_sha256}, artifact=${wasmSha256}`,
  );
}
const bg = require(gluePath);
const wasmInstance = new WebAssembly.Instance(new WebAssembly.Module(wasmBuf), {
  './softhsmrustv3_bg.js': bg,
});
bg.__wbg_set_wasm(wasmInstance.exports);
const w = wasmInstance.exports;

const CKR_OK = 0;
const CKR_ARGUMENTS_BAD = 0x00000007;
const initArgs = w._malloc(24); // six wasm32 CK_C_INITIALIZE_ARGS words
new Uint8Array(w.memory.buffer, initArgs, 24).fill(0);
new Uint32Array(w.memory.buffer, initArgs + 20, 1)[0] = w._malloc(1);

const seededRv = w._C_Initialize(initArgs);
if (seededRv !== CKR_ARGUMENTS_BAD) {
  throw new Error(
    `production C_Initialize accepted pReserved: got 0x${seededRv.toString(16)}, ` +
    `expected 0x${CKR_ARGUMENTS_BAD.toString(16)}`,
  );
}

const normalRv = w._C_Initialize(0);
if (normalRv !== CKR_OK) {
  throw new Error(`normal C_Initialize failed after rejection: 0x${normalRv.toString(16)}`);
}

console.log('PASS: release manifest disables ACVP hooks');
console.log('PASS: release manifest hash matches the WASM artifact');
console.log('PASS: release WASM rejects non-null C_Initialize.pReserved');
