/**
 * test-ecdsa-sha512.mjs — Unit test for CKM_ECDSA_SHA512 on P-256
 *
 * Tests: C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN, P-256) →
 *        C_SignInit(CKM_ECDSA_SHA512) → C_Sign →
 *        C_VerifyInit(CKM_ECDSA_SHA512) → C_Verify
 *
 * Usage: node tests/test-ecdsa-sha512.mjs
 */

import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import path from 'path'
import { createRequire } from 'module'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)
const rustBgJsPath = path.resolve(__dirname, '../rust/pkg/softhsmrustv3_bg.js')
const rustWasmPath = path.resolve(__dirname, '../rust/pkg/softhsmrustv3_bg.wasm')

// ── Load WASM (bundler-target pkg — mirror rust/test_p11_conformance.js) ────
const bg = require(rustBgJsPath)
const wasmBytes = readFileSync(rustWasmPath)
const wasmInstance = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes), {
    './softhsmrustv3_bg.js': bg,
})
bg.__wbg_set_wasm(wasmInstance.exports)
const wasm = wasmInstance.exports
const { _C_Initialize, _C_OpenSession, _C_GenerateKeyPair,
        _C_SignInit, _C_Sign, _C_VerifyInit, _C_Verify } = wasm

// ── Memory helpers ───────────────────────────────────────────────────────────
function malloc(size) { return wasm._malloc(size) >>> 0 }
function view() { return new DataView(wasm.memory.buffer) }
function heap() { return new Uint8Array(wasm.memory.buffer) }

function writeU32(ptr, val) { view().setUint32(ptr, val, true) }
function readU32(ptr)       { return view().getUint32(ptr, true) }
function writeBytes(ptr, bytes) { heap().set(bytes, ptr) }

/** Allocate a u32 output slot, return ptr. */
function allocU32() { const p = malloc(4); writeU32(p, 0); return p }

/** Build a CK_MECHANISM (12 bytes: mechType + pParam + ulParamLen). */
function buildMech(mechType) {
    const p = malloc(12)
    writeU32(p, mechType)
    writeU32(p + 4, 0)   // pParameter = NULL
    writeU32(p + 8, 0)   // ulParameterLen = 0
    return p
}

/**
 * Build a CK_ATTRIBUTE array.
 * attrs = [{ type, value }] where value is boolean | number | Uint8Array
 */
function buildTemplate(attrs) {
    const ATTR_SIZE = 12
    const arrPtr = malloc(attrs.length * ATTR_SIZE)
    for (let i = 0; i < attrs.length; i++) {
        const { type, value } = attrs[i]
        let vPtr, vLen
        if (typeof value === 'boolean') {
            vPtr = malloc(1)
            heap()[vPtr] = value ? 1 : 0
            vLen = 1
        } else if (typeof value === 'number') {
            vPtr = malloc(4)
            writeU32(vPtr, value)
            vLen = 4
        } else {
            vPtr = malloc(value.length)
            writeBytes(vPtr, value)
            vLen = value.length
        }
        const base = arrPtr + i * ATTR_SIZE
        writeU32(base, type)
        writeU32(base + 4, vPtr)
        writeU32(base + 8, vLen)
    }
    return { ptr: arrPtr, count: attrs.length }
}

function check(label, rv) {
    if (rv !== 0) throw new Error(`FAIL [${label}]: 0x${rv.toString(16).padStart(8, '0')}`)
    console.log(`  ✓  ${label}`)
}

// ── Constants ────────────────────────────────────────────────────────────────
const CKM_EC_KEY_PAIR_GEN = 0x1040
const CKM_ECDSA_SHA512    = 0x1046
const CKA_CLASS           = 0x00000000
const CKA_TOKEN           = 0x00000001
const CKA_PRIVATE         = 0x00000002
const CKA_EC_PARAMS       = 0x00000180
const CKA_SIGN            = 0x00000108
const CKA_VERIFY          = 0x0000010A
const CKA_EXTRACTABLE     = 0x00000162
const CKO_PUBLIC_KEY      = 2
const CKO_PRIVATE_KEY     = 3
const CKF_RW_SESSION      = 0x00000002
const CKF_SERIAL_SESSION  = 0x00000004

// P-256 OID (1.2.840.10045.3.1.7): 06 07 2a 86 48 ce 3d 03 01 07
const P256_OID = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])

// ── Test ─────────────────────────────────────────────────────────────────────
console.log('\n[test-ecdsa-sha512] CKM_ECDSA_SHA512 on P-256 — sign + verify round-trip\n')

// 1. Initialize
check('C_Initialize', _C_Initialize(0))

// 2. Open session
const phSession = allocU32()
check('C_OpenSession', _C_OpenSession(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, 0, 0, phSession))
const hSession = readU32(phSession)

// 3. Generate EC P-256 key pair
const pubTmpl = buildTemplate([
    { type: CKA_CLASS,     value: CKO_PUBLIC_KEY },
    { type: CKA_TOKEN,     value: false },
    { type: CKA_VERIFY,    value: true },
    { type: CKA_EC_PARAMS, value: P256_OID },
])
const prvTmpl = buildTemplate([
    { type: CKA_CLASS,      value: CKO_PRIVATE_KEY },
    { type: CKA_TOKEN,      value: false },
    // CKA_PRIVATE=FALSE: this harness never logs in, and the engine now
    // enforces §4.4 private-object invisibility (round-2 remediation).
    { type: CKA_PRIVATE,    value: false },
    { type: CKA_SIGN,       value: true },
    { type: CKA_EXTRACTABLE,value: false },
])
const mECGen  = buildMech(CKM_EC_KEY_PAIR_GEN)
const phPub   = allocU32()
const phPrv   = allocU32()
check('C_GenerateKeyPair(P-256)',
    _C_GenerateKeyPair(hSession, mECGen, pubTmpl.ptr, pubTmpl.count,
                       prvTmpl.ptr, prvTmpl.count, phPub, phPrv))
const hPub = readU32(phPub)
const hPrv = readU32(phPrv)

// 4. SignInit(CKM_ECDSA_SHA512)
const mSign = buildMech(CKM_ECDSA_SHA512)
check('C_SignInit(CKM_ECDSA_SHA512)', _C_SignInit(hSession, mSign, hPrv))

// 5. Sign — size query (pSignature = null = 0)
const msg = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05])
const pMsg    = malloc(msg.length); writeBytes(pMsg, msg)
const pSigLen = allocU32()
writeU32(pSigLen, 128)   // max buffer hint
check('C_Sign(size-query)', _C_Sign(hSession, pMsg, msg.length, 0, pSigLen))
const sigLen = readU32(pSigLen)
if (sigLen === 0 || sigLen > 128) throw new Error(`Unexpected sigLen=${sigLen}`)
console.log(`     sig buffer size = ${sigLen} bytes`)

// 6. Sign — actual. §5.2 two-call convention: the size query did NOT
// consume the operation, so we call C_Sign again directly (a re-init here
// would correctly fail with CKR_OPERATION_ACTIVE on the remediated engine).
const pSig = malloc(sigLen)
writeU32(pSigLen, sigLen)
check('C_Sign(actual)', _C_Sign(hSession, pMsg, msg.length, pSig, pSigLen))
const actualSigLen = readU32(pSigLen)
console.log(`     actual sig len  = ${actualSigLen} bytes`)

// 7. VerifyInit + Verify
const mVerify = buildMech(CKM_ECDSA_SHA512)
check('C_VerifyInit(CKM_ECDSA_SHA512)', _C_VerifyInit(hSession, mVerify, hPub))
check('C_Verify(CKM_ECDSA_SHA512)', _C_Verify(hSession, pMsg, msg.length, pSig, actualSigLen))

console.log('\n✅  All checks passed — CKM_ECDSA_SHA512 sign/verify OK\n')
