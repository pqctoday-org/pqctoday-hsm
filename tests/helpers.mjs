/**
 * helpers.mjs — Shared PKCS#11 v3.2 utilities for SoftHSMv3 WASM tests
 *
 * All functions take the WASM module M as first argument.
 * Templates use {type, value} format where value is boolean/number/Uint8Array.
 */
import { createRequire } from 'module'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import path from 'path'
const require = createRequire(import.meta.url)
const CK = require('../constants.js')

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const WASM_DIR = path.resolve(__dirname, '../wasm')

// ── Additional constants not (yet) in constants.js ──────────────────────────
const CKG_MGF1_SHA256 = 0x00000002
const CKG_MGF1_SHA384 = 0x00000003
const CKF_HKDF_SALT_DATA = 2
const CKS_PKCS5_PBKD2_SALT_SPECIFIED = 1
const CKP_PKCS5_PBKD2_HMAC_SHA512 = 0x00000006

// EC curve OIDs (DER-encoded)
const EC_OID = {
  'P-256': new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
  'P-384': new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
  Ed25519: new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70]),
}

// ── Utilities ───────────────────────────────────────────────────────────────

export function hexToBytes(hex) {
  const h = hex.length % 2 ? '0' + hex : hex
  const bytes = new Uint8Array(h.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.substr(i * 2, 2), 16)
  return bytes
}

export function bytesToHex(bytes, max = 0) {
  const arr = max > 0 ? bytes.slice(0, max) : bytes
  let s = ''
  for (const b of arr) s += b.toString(16).padStart(2, '0')
  if (max > 0 && bytes.length > max) s += '…'
  return s
}

// ── WASM Memory ─────────────────────────────────────────────────────────────

export function allocUlong(M) {
  return M._malloc(4)
}
export function readUlong(M, ptr) {
  return M.getValue(ptr, 'i32') >>> 0
}
export function freePtr(M, ptr) {
  M._free(ptr)
}
export function writeStr(M, str) {
  const bytes = new TextEncoder().encode(str)
  const ptr = M._malloc(bytes.length + 1)
  M.HEAPU8.set(bytes, ptr)
  M.HEAPU8[ptr + bytes.length] = 0
  return ptr
}
export function writeBytes(M, bytes) {
  const ptr = M._malloc(bytes.length)
  M.HEAPU8.set(bytes, ptr)
  return ptr
}
export function padLabel(s, len = 32) {
  return s.padEnd(len, ' ').slice(0, len)
}

// ── Templates ───────────────────────────────────────────────────────────────

/**
 * Build CK_ATTRIBUTE array in WASM heap.
 * attrs: [{type, value}] — value: boolean→CK_BBOOL(1B), number→CK_ULONG(4B), Uint8Array→raw
 */
export function buildTemplate(M, attrs) {
  const ATTR_SIZE = 12
  const arrPtr = M._malloc(attrs.length * ATTR_SIZE)
  const valuePtrs = []
  for (let i = 0; i < attrs.length; i++) {
    const { type, value } = attrs[i]
    let vPtr, vLen
    if (typeof value === 'boolean') {
      vPtr = M._malloc(1)
      M.HEAPU8[vPtr] = value ? 1 : 0
      vLen = 1
    } else if (typeof value === 'number') {
      vPtr = M._malloc(4)
      M.setValue(vPtr, value, 'i32')
      vLen = 4
    } else if (value instanceof Uint8Array) {
      vPtr = M._malloc(value.length)
      M.HEAPU8.set(value, vPtr)
      vLen = value.length
    } else {
      throw new Error(`Unsupported template value type: ${typeof value}`)
    }
    valuePtrs.push(vPtr)
    const base = arrPtr + i * ATTR_SIZE
    M.setValue(base + 0, type, 'i32')
    M.setValue(base + 4, vPtr, 'i32')
    M.setValue(base + 8, vLen, 'i32')
  }
  return { arrPtr, valuePtrs, count: attrs.length }
}

export function freeTemplate(M, tpl) {
  for (const p of tpl.valuePtrs) M._free(p)
  M._free(tpl.arrPtr)
}

// ── Mechanisms ──────────────────────────────────────────────────────────────

/** Build 12-byte CK_MECHANISM struct */
export function buildMech(M, type, paramPtr = 0, paramLen = 0) {
  const ptr = M._malloc(12)
  M.setValue(ptr + 0, type, 'i32')
  M.setValue(ptr + 4, paramPtr, 'i32')
  M.setValue(ptr + 8, paramLen, 'i32')
  return ptr
}

/** CK_GCM_PARAMS: pIv(4) ulIvLen(4) ulIvBits(4) pAAD(4) ulAADLen(4) ulTagBits(4) = 24B */
export function buildGCMParams(M, iv) {
  const ivPtr = writeBytes(M, iv)
  const ptr = M._malloc(24)
  M.setValue(ptr + 0, ivPtr, 'i32')
  M.setValue(ptr + 4, iv.length, 'i32')
  M.setValue(ptr + 8, iv.length * 8, 'i32')
  M.setValue(ptr + 12, 0, 'i32') // pAAD
  M.setValue(ptr + 16, 0, 'i32') // ulAADLen
  M.setValue(ptr + 20, 128, 'i32') // ulTagBits
  return { ptr, size: 24, ivPtr }
}

/** CK_AES_CTR_PARAMS: ulCounterBits(4) cb[16] = 20B */
export function buildCTRParams(M, iv, counterBits) {
  const ptr = M._malloc(20)
  M.setValue(ptr + 0, counterBits, 'i32')
  M.HEAPU8.set(iv.slice(0, 16), ptr + 4)
  return { ptr, size: 20 }
}

/** CK_RSA_PKCS_PSS_PARAMS: hashAlg(4) mgf(4) sLen(4) = 12B */
export function buildPSSParams(M, hashMech, mgf, sLen) {
  const ptr = M._malloc(12)
  M.setValue(ptr + 0, hashMech, 'i32')
  M.setValue(ptr + 4, mgf, 'i32')
  M.setValue(ptr + 8, sLen, 'i32')
  return { ptr, size: 12 }
}

// ── Check helper ────────────────────────────────────────────────────────────

export function check(label, rv) {
  if (rv !== CK.CKR_OK)
    throw new Error(`FAIL: ${label} returned 0x${rv.toString(16).toUpperCase()}`)
}

// ── HSM Lifecycle ───────────────────────────────────────────────────────────

/**
 * Full HSM init: Initialize → GetSlotList → InitToken → OpenSession → Login
 * Returns { hSession, slotId }
 */
export function initializeEngine(M, label = 'ACVP_Token', seed = null) {
  if (seed) {
    const seedPtr = writeBytes(M, seed)
    check('C_SeedRandom-pre', M._C_Initialize(0))
    // Note: C_SeedRandom isn't always available before session, seed is just for entropy
    M._free(seedPtr)
  } else {
    check('C_Initialize', M._C_Initialize(0))
  }

  // Get slots
  const cntPtr = allocUlong(M)
  check('C_GetSlotList(count)', M._C_GetSlotList(0, 0, cntPtr))
  const slotCount = readUlong(M, cntPtr)
  const slotsPtr = M._malloc(slotCount * 4)
  check('C_GetSlotList(fill)', M._C_GetSlotList(0, slotsPtr, cntPtr))
  const slot0 = M.getValue(slotsPtr, 'i32') >>> 0
  M._free(slotsPtr)
  freePtr(M, cntPtr)

  // Init token
  const soPin = '12345678'
  const soPinPtr = writeStr(M, soPin)
  const labelStr = padLabel(label)
  const labelPtr = writeStr(M, labelStr)
  M._C_InitToken(slot0, soPinPtr, soPin.length, labelPtr)
  M._free(labelPtr)
  M._free(soPinPtr)

  // Re-enumerate after init
  const cntPtr2 = allocUlong(M)
  check('C_GetSlotList(re-enum)', M._C_GetSlotList(1, 0, cntPtr2))
  const slotCount2 = readUlong(M, cntPtr2)
  const slotsPtr2 = M._malloc(slotCount2 * 4)
  check('C_GetSlotList(fill2)', M._C_GetSlotList(1, slotsPtr2, cntPtr2))
  const slotId = M.getValue(slotsPtr2, 'i32') >>> 0
  M._free(slotsPtr2)
  freePtr(M, cntPtr2)

  // Open session
  const hSessionPtr = allocUlong(M)
  const flags = CK.CKF_SERIAL_SESSION | CK.CKF_RW_SESSION
  check('C_OpenSession', M._C_OpenSession(slotId, flags, 0, 0, hSessionPtr))
  const hSession = readUlong(M, hSessionPtr)
  freePtr(M, hSessionPtr)

  // Login: SO → InitPIN → Logout → User login
  const soPinPtr2 = writeStr(M, '12345678')
  check('C_Login(SO)', M._C_Login(hSession, CK.CKU_SO, soPinPtr2, 8))
  M._free(soPinPtr2)
  const userPin = '87654321'
  const userPinPtr = writeStr(M, userPin)
  check('C_InitPIN', M._C_InitPIN(hSession, userPinPtr, userPin.length))
  check('C_Logout', M._C_Logout(hSession))
  check('C_Login(User)', M._C_Login(hSession, CK.CKU_USER, userPinPtr, userPin.length))
  M._free(userPinPtr)

  return { hSession, slotId }
}

export function finalizeEngine(M, hSession) {
  M._C_Logout(hSession)
  M._C_CloseSession(hSession)
  M._C_Finalize(0)
}

export function getMechanismSet(M, slotId) {
  const cntPtr = allocUlong(M)
  const rv = M._C_GetMechanismList(slotId, 0, cntPtr)
  if (rv !== CK.CKR_OK) {
    freePtr(M, cntPtr)
    return new Set()
  }
  const count = readUlong(M, cntPtr)
  const listPtr = M._malloc(count * 4)
  M._C_GetMechanismList(slotId, listPtr, cntPtr)
  const set = new Set()
  for (let i = 0; i < count; i++) set.add(M.getValue(listPtr + i * 4, 'i32') >>> 0)
  M._free(listPtr)
  freePtr(M, cntPtr)
  return set
}

// ── Key Import ──────────────────────────────────────────────────────────────

export function importAESKey(
  M,
  hSession,
  keyBytes,
  { encrypt = true, decrypt = true, wrap = true, unwrap = true, derive = true, extractable = true } = {}
) {
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_AES },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_ENCRYPT, value: encrypt },
    { type: CK.CKA_DECRYPT, value: decrypt },
    { type: CK.CKA_WRAP, value: wrap },
    { type: CK.CKA_UNWRAP, value: unwrap },
    { type: CK.CKA_DERIVE, value: derive },
    { type: CK.CKA_EXTRACTABLE, value: extractable },
    { type: CK.CKA_SENSITIVE, value: !extractable },
    { type: CK.CKA_VALUE, value: keyBytes },
    // Note: CKA_VALUE_LEN omitted — C++ rejects it in C_CreateObject (ck2 flag);
    // the value length is derived from CKA_VALUE byte length automatically.
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(AES)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

export function importHMACKey(M, hSession, keyBytes, { sign = true, verify = true } = {}) {
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_GENERIC_SECRET },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_SIGN, value: sign },
    { type: CK.CKA_VERIFY, value: verify },
    { type: CK.CKA_EXTRACTABLE, value: false },
    { type: CK.CKA_SENSITIVE, value: false },
    { type: CK.CKA_VALUE, value: keyBytes },
    // Note: CKA_VALUE_LEN omitted — C++ rejects it in C_CreateObject (ck2 flag);
    // the value length is derived from CKA_VALUE byte length automatically.
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(HMAC)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

export function importRSAPublicKey(
  M,
  hSession,
  modBytes,
  expBytes,
  { encrypt = true } = {}
) {
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_PUBLIC_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_RSA },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_ENCRYPT, value: encrypt },
    { type: CK.CKA_VERIFY, value: true },
    { type: CK.CKA_MODULUS, value: modBytes },
    { type: CK.CKA_PUBLIC_EXPONENT, value: expBytes },
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(RSA-Pub)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

export function importECPublicKey(M, hSession, qx, qy, curve = 'P-256') {
  const oid = EC_OID[curve]
  if (!oid) throw new Error(`Unsupported curve: ${curve}`)
  // CKA_EC_POINT = DER OCTET STRING wrapping 04 || x || y
  const pointLen = 1 + qx.length + qy.length // 04 + x + y
  const derPoint = new Uint8Array(2 + pointLen)
  derPoint[0] = 0x04 // OCTET STRING tag
  derPoint[1] = pointLen
  derPoint[2] = 0x04 // uncompressed
  derPoint.set(qx, 3)
  derPoint.set(qy, 3 + qx.length)
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_PUBLIC_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_EC },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_VERIFY, value: true },
    { type: CK.CKA_EC_PARAMS, value: oid },
    { type: CK.CKA_EC_POINT, value: derPoint },
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(EC-Pub)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

export function importMLDSAPublicKey(M, hSession, variant, pkBytes) {
  const ckp =
    variant === 44 ? CK.CKP_ML_DSA_44 : variant === 65 ? CK.CKP_ML_DSA_65 : CK.CKP_ML_DSA_87
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_PUBLIC_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_ML_DSA },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_VERIFY, value: true },
    { type: CK.CKA_PARAMETER_SET, value: ckp },
    { type: CK.CKA_VALUE, value: pkBytes },
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(ML-DSA-Pub)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

export function importMLKEMPrivateKey(M, hSession, variant, skBytes) {
  const ckp =
    variant === 512
      ? CK.CKP_ML_KEM_512
      : variant === 768
        ? CK.CKP_ML_KEM_768
        : CK.CKP_ML_KEM_1024
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_PRIVATE_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_ML_KEM },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_DECAPSULATE, value: true },
    { type: CK.CKA_EXTRACTABLE, value: true },         // required: KAT needs to use key for decapsulation
    { type: CK.CKA_SENSITIVE, value: false },          // PKCS#11 v3.2 — mandatory; false since EXTRACTABLE=true
    { type: CK.CKA_PARAMETER_SET, value: ckp },
    { type: CK.CKA_VALUE, value: skBytes },
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(ML-KEM-Priv)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

/** Import an ML-KEM encapsulation (public) key from raw `ek` bytes.
 *  Public keys are non-sensitive, so this lets the cross-engine check move a
 *  key without exporting any private material: the decap engine generates the
 *  pair and exports its public key, the encap engine imports it here. */
export function importMLKEMPublicKey(M, hSession, variant, pkBytes) {
  const ckp =
    variant === 512
      ? CK.CKP_ML_KEM_512
      : variant === 768
        ? CK.CKP_ML_KEM_768
        : CK.CKP_ML_KEM_1024
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_PUBLIC_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_ML_KEM },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_ENCAPSULATE, value: true },
    { type: CK.CKA_PARAMETER_SET, value: ckp },
    { type: CK.CKA_VALUE, value: pkBytes },
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(ML-KEM-Pub)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

// ── Key Generation ──────────────────────────────────────────────────────────

export function generateAESKey(
  M,
  hSession,
  bits = 256,
  { encrypt = true, decrypt = true, wrap = true, unwrap = true, derive = true, extractable = true } = {}
) {
  const tpl = buildTemplate(M, [
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_ENCRYPT, value: encrypt },
    { type: CK.CKA_DECRYPT, value: decrypt },
    { type: CK.CKA_WRAP, value: wrap },
    { type: CK.CKA_UNWRAP, value: unwrap },
    { type: CK.CKA_DERIVE, value: derive },
    { type: CK.CKA_EXTRACTABLE, value: extractable },
    { type: CK.CKA_SENSITIVE, value: !extractable },
    { type: CK.CKA_VALUE_LEN, value: bits / 8 },
  ])
  const mech = buildMech(M, CK.CKM_AES_KEY_GEN)
  const hPtr = allocUlong(M)
  check('C_GenerateKey(AES)', M._C_GenerateKey(hSession, mech, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  M._free(mech)
  freePtr(M, hPtr)
  return handle
}

function generateKeyPair(M, hSession, mechType, pubAttrs, privAttrs) {
  const mech = buildMech(M, mechType)
  const pubTpl = buildTemplate(M, pubAttrs)
  const prvTpl = buildTemplate(M, privAttrs)
  const hPubPtr = allocUlong(M)
  const hPrvPtr = allocUlong(M)
  check(
    `C_GenerateKeyPair(0x${mechType.toString(16)})`,
    M._C_GenerateKeyPair(
      hSession,
      mech,
      pubTpl.arrPtr,
      pubTpl.count,
      prvTpl.arrPtr,
      prvTpl.count,
      hPubPtr,
      hPrvPtr
    )
  )
  const pubHandle = readUlong(M, hPubPtr)
  const privHandle = readUlong(M, hPrvPtr)
  freeTemplate(M, pubTpl)
  freeTemplate(M, prvTpl)
  M._free(mech)
  freePtr(M, hPubPtr)
  freePtr(M, hPrvPtr)
  return { pubHandle, privHandle }
}

export function generateMLDSAKeyPair(M, hSession, variant) {
  const ckp =
    variant === 44 ? CK.CKP_ML_DSA_44 : variant === 65 ? CK.CKP_ML_DSA_65 : CK.CKP_ML_DSA_87
  return generateKeyPair(
    M,
    hSession,
    CK.CKM_ML_DSA_KEY_PAIR_GEN,
    [
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_VERIFY, value: true },
      { type: CK.CKA_PARAMETER_SET, value: ckp },
    ],
    [
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_SIGN, value: true },
      { type: CK.CKA_PARAMETER_SET, value: ckp },
    ]
  )
}

export function generateMLKEMKeyPair(M, hSession, variant) {
  const ckp =
    variant === 512
      ? CK.CKP_ML_KEM_512
      : variant === 768
        ? CK.CKP_ML_KEM_768
        : CK.CKP_ML_KEM_1024
  return generateKeyPair(
    M,
    hSession,
    CK.CKM_ML_KEM_KEY_PAIR_GEN,
    [
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_ENCRYPT, value: true },
      { type: CK.CKA_ENCAPSULATE, value: true },
      { type: CK.CKA_PARAMETER_SET, value: ckp },
    ],
    [
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_DECRYPT, value: true },
      { type: CK.CKA_DECAPSULATE, value: true },
      // CKA_SENSITIVE and CKA_EXTRACTABLE intentionally omitted: both engines enforce
      // SENSITIVE=true / EXTRACTABLE=false for private keys regardless of template values.
      // The shared secret (not the private key) is the object being extracted in the ACVP test.
      { type: CK.CKA_PARAMETER_SET, value: ckp },
    ]
  )
}

export function generateSLHDSAKeyPair(M, hSession, ckp) {
  return generateKeyPair(
    M,
    hSession,
    CK.CKM_SLH_DSA_KEY_PAIR_GEN,
    [
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_VERIFY, value: true },
      { type: CK.CKA_PARAMETER_SET, value: ckp },
    ],
    [
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_SIGN, value: true },
      { type: CK.CKA_PARAMETER_SET, value: ckp },
    ]
  )
}

export function generateEdDSAKeyPair(M, hSession, curve = 'Ed25519') {
  const oid = EC_OID[curve]
  return generateKeyPair(
    M,
    hSession,
    CK.CKM_EC_EDWARDS_KEY_PAIR_GEN,
    [
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_VERIFY, value: true },
      { type: CK.CKA_EC_PARAMS, value: oid },
    ],
    [
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_SIGN, value: true },
      // Note: CKA_EC_PARAMS omitted from private key template — C++ rejects it in
      // C_GenerateKeyPair (ck4 flag); curve is taken from the public key template.
    ]
  )
}

// ── Crypto Operations ───────────────────────────────────────────────────────

/** AES-GCM or AES-CBC decrypt */
export function aesDecrypt(M, hSession, handle, ct, iv, mode = 'gcm') {
  let mechPtr, extraPtrs = []
  if (mode === 'gcm') {
    const gcm = buildGCMParams(M, iv)
    mechPtr = buildMech(M, CK.CKM_AES_GCM, gcm.ptr, gcm.size)
    extraPtrs = [gcm.ptr, gcm.ivPtr]
  } else {
    // CBC — IV is the 16-byte param
    const ivPtr = writeBytes(M, iv)
    mechPtr = buildMech(M, CK.CKM_AES_CBC_PAD, ivPtr, iv.length)
    extraPtrs = [ivPtr]
  }
  check('C_DecryptInit', M._C_DecryptInit(hSession, mechPtr, handle))
  const ctPtr = writeBytes(M, ct)
  const outLen = ct.length + 32 // room for padding
  const outPtr = M._malloc(outLen)
  const outLenPtr = allocUlong(M)
  M.setValue(outLenPtr, outLen, 'i32')
  check('C_Decrypt', M._C_Decrypt(hSession, ctPtr, ct.length, outPtr, outLenPtr))
  const actualLen = readUlong(M, outLenPtr)
  const result = new Uint8Array(M.HEAPU8.buffer, outPtr, actualLen).slice()
  M._free(ctPtr)
  M._free(outPtr)
  freePtr(M, outLenPtr)
  M._free(mechPtr)
  for (const p of extraPtrs) M._free(p)
  return result
}

/** AES-CTR decrypt */
export function aesCtrDecrypt(M, hSession, handle, iv, counterBits, ct) {
  const ctr = buildCTRParams(M, iv, counterBits)
  const mechPtr = buildMech(M, CK.CKM_AES_CTR, ctr.ptr, ctr.size)
  check('C_DecryptInit(CTR)', M._C_DecryptInit(hSession, mechPtr, handle))
  const ctPtr = writeBytes(M, ct)
  const outPtr = M._malloc(ct.length + 16)
  const outLenPtr = allocUlong(M)
  M.setValue(outLenPtr, ct.length + 16, 'i32')
  check('C_Decrypt(CTR)', M._C_Decrypt(hSession, ctPtr, ct.length, outPtr, outLenPtr))
  const actualLen = readUlong(M, outLenPtr)
  const result = new Uint8Array(M.HEAPU8.buffer, outPtr, actualLen).slice()
  M._free(ctPtr)
  M._free(outPtr)
  freePtr(M, outLenPtr)
  M._free(mechPtr)
  M._free(ctr.ptr)
  return result
}

/** HMAC verify. mechType defaults to CKM_SHA256_HMAC */
export function hmacVerify(M, hSession, handle, msg, mac, mechType = CK.CKM_SHA256_HMAC) {
  const mechPtr = buildMech(M, mechType)
  check('C_VerifyInit(HMAC)', M._C_VerifyInit(hSession, mechPtr, handle))
  const msgPtr = writeBytes(M, msg)
  const macPtr = writeBytes(M, mac)
  const rv = M._C_Verify(hSession, msgPtr, msg.length, macPtr, mac.length)
  M._free(msgPtr)
  M._free(macPtr)
  M._free(mechPtr)
  return rv === CK.CKR_OK
}

/** RSA-PSS verify (text message — encoded with TextEncoder) */
export function rsaVerify(M, hSession, handle, textMsg, sig, mechType = CK.CKM_SHA256_RSA_PKCS_PSS) {
  // Build PSS params based on mechanism type
  let hashMech, mgf, sLen
  if (mechType === CK.CKM_SHA256_RSA_PKCS_PSS) {
    hashMech = CK.CKM_SHA256
    mgf = CKG_MGF1_SHA256
    sLen = 32
  } else if (mechType === CK.CKM_SHA384_RSA_PKCS_PSS) {
    hashMech = CK.CKM_SHA384
    mgf = CKG_MGF1_SHA384
    sLen = 48
  } else {
    hashMech = CK.CKM_SHA256
    mgf = CKG_MGF1_SHA256
    sLen = 32
  }
  const pss = buildPSSParams(M, hashMech, mgf, sLen)
  const mechPtr = buildMech(M, mechType, pss.ptr, pss.size)
  check('C_VerifyInit(RSA-PSS)', M._C_VerifyInit(hSession, mechPtr, handle))
  const msgBytes = new TextEncoder().encode(textMsg)
  const msgPtr = writeBytes(M, msgBytes)
  const sigPtr = writeBytes(M, sig)
  const rv = M._C_Verify(hSession, msgPtr, msgBytes.length, sigPtr, sig.length)
  M._free(msgPtr)
  M._free(sigPtr)
  M._free(mechPtr)
  M._free(pss.ptr)
  return rv === CK.CKR_OK
}

/** ECDSA verify (text message). mechType defaults to CKM_ECDSA_SHA256 */
export function ecdsaVerify(M, hSession, handle, textMsg, sig, mechType = CK.CKM_ECDSA_SHA256) {
  const mechPtr = buildMech(M, mechType)
  check('C_VerifyInit(ECDSA)', M._C_VerifyInit(hSession, mechPtr, handle))
  const msgBytes = new TextEncoder().encode(textMsg)
  const msgPtr = writeBytes(M, msgBytes)
  const sigPtr = writeBytes(M, sig)
  const rv = M._C_Verify(hSession, msgPtr, msgBytes.length, sigPtr, sig.length)
  M._free(msgPtr)
  M._free(sigPtr)
  M._free(mechPtr)
  return rv === CK.CKR_OK
}

/** ML-DSA verify with raw bytes (for SigVer KAT) */
export function verifyBytes(M, hSession, handle, msgBytes, sig, mechType = CK.CKM_ML_DSA) {
  const mechPtr = buildMech(M, mechType)
  check('C_VerifyInit', M._C_VerifyInit(hSession, mechPtr, handle))
  const msgPtr = writeBytes(M, msgBytes)
  const sigPtr = writeBytes(M, sig)
  const rv = M._C_Verify(hSession, msgPtr, msgBytes.length, sigPtr, sig.length)
  M._free(msgPtr)
  M._free(sigPtr)
  M._free(mechPtr)
  return rv === CK.CKR_OK
}

/** Generic sign (text message) */
export function sign(M, hSession, handle, textMsg, mechType = CK.CKM_ML_DSA) {
  const mechPtr = buildMech(M, mechType)
  check('C_SignInit', M._C_SignInit(hSession, mechPtr, handle))
  const msgBytes = new TextEncoder().encode(textMsg)
  const msgPtr = writeBytes(M, msgBytes)
  // Query signature length
  const sigLenPtr = allocUlong(M)
  check('C_Sign(len)', M._C_Sign(hSession, msgPtr, msgBytes.length, 0, sigLenPtr))
  const sigLen = readUlong(M, sigLenPtr)
  const sigPtr = M._malloc(sigLen)
  M.setValue(sigLenPtr, sigLen, 'i32')
  check('C_Sign', M._C_Sign(hSession, msgPtr, msgBytes.length, sigPtr, sigLenPtr))
  const actualLen = readUlong(M, sigLenPtr)
  const result = new Uint8Array(M.HEAPU8.buffer, sigPtr, actualLen).slice()
  M._free(msgPtr)
  M._free(sigPtr)
  freePtr(M, sigLenPtr)
  M._free(mechPtr)
  return result
}

/** Generic verify (text message) */
export function verify(M, hSession, handle, textMsg, sig, mechType = CK.CKM_ML_DSA) {
  const mechPtr = buildMech(M, mechType)
  check('C_VerifyInit', M._C_VerifyInit(hSession, mechPtr, handle))
  const msgBytes = new TextEncoder().encode(textMsg)
  const msgPtr = writeBytes(M, msgBytes)
  const sigPtr = writeBytes(M, sig)
  const rv = M._C_Verify(hSession, msgPtr, msgBytes.length, sigPtr, sig.length)
  M._free(msgPtr)
  M._free(sigPtr)
  M._free(mechPtr)
  return rv === CK.CKR_OK
}

/** SLH-DSA sign (text message) */
export function slhdsaSign(M, hSession, handle, textMsg) {
  return sign(M, hSession, handle, textMsg, CK.CKM_SLH_DSA)
}

/** SLH-DSA verify (text message) */
export function slhdsaVerify(M, hSession, handle, textMsg, sig) {
  return verify(M, hSession, handle, textMsg, sig, CK.CKM_SLH_DSA)
}

// ── SLH-DSA ACVP context/deterministic helpers ──────────────────────────────

/** Import an SLH-DSA public key (CKO_PUBLIC_KEY) for ACVP SigVer KATs. */
export function importSLHDSAPublicKey(M, hSession, ckp, pkBytes) {
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS,         value: CK.CKO_PUBLIC_KEY },
    { type: CK.CKA_KEY_TYPE,      value: CK.CKK_SLH_DSA },
    { type: CK.CKA_TOKEN,         value: false },
    { type: CK.CKA_VERIFY,        value: true },
    { type: CK.CKA_PARAMETER_SET, value: ckp },
    { type: CK.CKA_VALUE,         value: pkBytes },
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(SLH-DSA-Pub)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

/** Import an SLH-DSA private key (CKO_PRIVATE_KEY) for ACVP SigGen KATs. */
export function importSLHDSAPrivateKey(M, hSession, ckp, skBytes) {
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS,         value: CK.CKO_PRIVATE_KEY },
    { type: CK.CKA_KEY_TYPE,      value: CK.CKK_SLH_DSA },
    { type: CK.CKA_TOKEN,         value: false },
    { type: CK.CKA_SIGN,          value: true },
    { type: CK.CKA_EXTRACTABLE,   value: false },
    { type: CK.CKA_SENSITIVE,     value: true },
    { type: CK.CKA_PARAMETER_SET, value: ckp },
    { type: CK.CKA_VALUE,         value: skBytes },
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(SLH-DSA-Priv)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

/**
 * Build a CK_SIGN_ADDITIONAL_CONTEXT in WASM heap (PKCS#11 v3.2 §5.3).
 * Layout (12 bytes, WASM32): hedgeVariant(4) | pContext(4) | ulContextLen(4)
 * Returns { paramPtr, paramLen, allocPtrs } — caller must free allocPtrs after use.
 */
export function buildSlhDsaCtxParam(M, ctxBytes, deterministic = false) {
  const allocPtrs = []
  const paramPtr = M._malloc(CK.CK_SIGN_ADDITIONAL_CONTEXT_SIZE)
  allocPtrs.push(paramPtr)
  const hedge = deterministic ? CK.CKH_DETERMINISTIC_REQUIRED : CK.CKH_HEDGE_PREFERRED
  M.setValue(paramPtr + 0, hedge, 'i32')
  if (ctxBytes && ctxBytes.length > 0) {
    const ctxPtr = writeBytes(M, ctxBytes)
    allocPtrs.push(ctxPtr)
    M.setValue(paramPtr + 4, ctxPtr, 'i32')
    M.setValue(paramPtr + 8, ctxBytes.length, 'i32')
  } else {
    M.setValue(paramPtr + 4, 0, 'i32')
    M.setValue(paramPtr + 8, 0, 'i32')
  }
  return { paramPtr, paramLen: CK.CK_SIGN_ADDITIONAL_CONTEXT_SIZE, allocPtrs }
}

/**
 * SLH-DSA sign raw bytes with optional context + deterministic mode (FIPS 205 §9.2 / §10).
 * Uses C_SignInit + C_Sign with CK_SIGN_ADDITIONAL_CONTEXT parameter on CKM_SLH_DSA.
 */
export function slhdsaSignBytesCtx(M, hSession, handle, msgBytes, ctxBytes, deterministic = false) {
  const ctxParam = buildSlhDsaCtxParam(M, ctxBytes, deterministic)
  const mechPtr = buildMech(M, CK.CKM_SLH_DSA, ctxParam.paramPtr, ctxParam.paramLen)
  check('C_SignInit(SLH-DSA-ctx)', M._C_SignInit(hSession, mechPtr, handle))
  const msgPtr = writeBytes(M, msgBytes)
  const sigLenPtr = allocUlong(M)
  check('C_Sign(SLH-DSA-ctx,len)', M._C_Sign(hSession, msgPtr, msgBytes.length, 0, sigLenPtr))
  const sigLen = readUlong(M, sigLenPtr)
  const sigPtr = M._malloc(sigLen)
  M.setValue(sigLenPtr, sigLen, 'i32')
  check('C_Sign(SLH-DSA-ctx)', M._C_Sign(hSession, msgPtr, msgBytes.length, sigPtr, sigLenPtr))
  const actualLen = readUlong(M, sigLenPtr)
  const result = new Uint8Array(M.HEAPU8.buffer, sigPtr, actualLen).slice()
  ctxParam.allocPtrs.forEach((p) => M._free(p))
  M._free(mechPtr)
  M._free(msgPtr)
  M._free(sigPtr)
  freePtr(M, sigLenPtr)
  return result
}

/**
 * SLH-DSA verify raw bytes with optional context string (FIPS 205 §9.2).
 * Uses C_VerifyInit + C_Verify with CK_SIGN_ADDITIONAL_CONTEXT parameter on CKM_SLH_DSA.
 */
export function slhdsaVerifyBytesCtx(M, hSession, handle, msgBytes, sigBytes, ctxBytes) {
  const ctxParam = buildSlhDsaCtxParam(M, ctxBytes, false)
  const mechPtr = buildMech(M, CK.CKM_SLH_DSA, ctxParam.paramPtr, ctxParam.paramLen)
  check('C_VerifyInit(SLH-DSA-ctx)', M._C_VerifyInit(hSession, mechPtr, handle))
  const msgPtr = writeBytes(M, msgBytes)
  const sigPtr = writeBytes(M, sigBytes)
  const rv = M._C_Verify(hSession, msgPtr, msgBytes.length, sigPtr, sigBytes.length)
  ctxParam.allocPtrs.forEach((p) => M._free(p))
  M._free(mechPtr)
  M._free(msgPtr)
  M._free(sigPtr)
  return rv === CK.CKR_OK
}

/** EdDSA sign (text message) */
export function eddsaSign(M, hSession, handle, textMsg) {
  return sign(M, hSession, handle, textMsg, CK.CKM_EDDSA)
}

/** EdDSA verify (text message) */
export function eddsaVerify(M, hSession, handle, textMsg, sig) {
  return verify(M, hSession, handle, textMsg, sig, CK.CKM_EDDSA)
}

/** SHA digest. mechType defaults to CKM_SHA256 */
export function digest(M, hSession, data, mechType = CK.CKM_SHA256) {
  const mechPtr = buildMech(M, mechType)
  check('C_DigestInit', M._C_DigestInit(hSession, mechPtr))
  const dataPtr = writeBytes(M, data)
  const outLenPtr = allocUlong(M)
  // Query digest length
  check('C_Digest(len)', M._C_Digest(hSession, dataPtr, data.length, 0, outLenPtr))
  const digestLen = readUlong(M, outLenPtr)
  const outPtr = M._malloc(digestLen)
  M.setValue(outLenPtr, digestLen, 'i32')
  check('C_Digest', M._C_Digest(hSession, dataPtr, data.length, outPtr, outLenPtr))
  const actualLen = readUlong(M, outLenPtr)
  const result = new Uint8Array(M.HEAPU8.buffer, outPtr, actualLen).slice()
  M._free(dataPtr)
  M._free(outPtr)
  freePtr(M, outLenPtr)
  M._free(mechPtr)
  return result
}

// ── KEM Operations ──────────────────────────────────────────────────────────

/** Extract raw key value via C_GetAttributeValue(CKA_VALUE) */
export function extractKeyValue(M, hSession, handle) {
  const bufPtr = M._malloc(4096)
  const attrPtr = M._malloc(12)
  M.setValue(attrPtr + 0, CK.CKA_VALUE, 'i32')
  M.setValue(attrPtr + 4, bufPtr, 'i32')
  M.setValue(attrPtr + 8, 4096, 'i32')
  check('C_GetAttributeValue', M._C_GetAttributeValue(hSession, handle, attrPtr, 1))
  const len = readUlong(M, attrPtr + 8)
  const result = new Uint8Array(M.HEAPU8.buffer, bufPtr, len).slice()
  M._free(bufPtr)
  M._free(attrPtr)
  return result
}

/** ML-KEM encapsulate → { ciphertextBytes, secretHandle } */
export function encapsulate(M, hSession, pubHandle, variant) {
  const ssTpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_GENERIC_SECRET },
    { type: CK.CKA_VALUE_LEN, value: 32 },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_EXTRACTABLE, value: true },         // required: ACVP test extracts SS for comparison
    { type: CK.CKA_SENSITIVE, value: false },
    // Usage attrs — explicit per PKCS#11 v3.2 §4.3; SS is only extracted, never used for crypto ops
    { type: CK.CKA_ENCRYPT, value: false },
    { type: CK.CKA_DECRYPT, value: false },
    { type: CK.CKA_SIGN, value: false },
    { type: CK.CKA_VERIFY, value: false },
    { type: CK.CKA_WRAP, value: false },
    { type: CK.CKA_UNWRAP, value: false },
    { type: CK.CKA_DERIVE, value: false },
  ])
  const mechPtr = buildMech(M, CK.CKM_ML_KEM)
  const ctLenPtr = allocUlong(M)
  const hSSPtr = allocUlong(M)
  // Query ciphertext size
  check(
    'C_EncapsulateKey(size)',
    M._C_EncapsulateKey(hSession, mechPtr, pubHandle, ssTpl.arrPtr, ssTpl.count, 0, ctLenPtr, hSSPtr)
  )
  const ctLen = readUlong(M, ctLenPtr)
  const ctPtr = M._malloc(ctLen)
  M.setValue(ctLenPtr, ctLen, 'i32')
  check(
    'C_EncapsulateKey',
    M._C_EncapsulateKey(
      hSession,
      mechPtr,
      pubHandle,
      ssTpl.arrPtr,
      ssTpl.count,
      ctPtr,
      ctLenPtr,
      hSSPtr
    )
  )
  const secretHandle = readUlong(M, hSSPtr)
  const ciphertextBytes = new Uint8Array(M.HEAPU8.buffer, ctPtr, ctLen).slice()
  M._free(ctPtr)
  freePtr(M, ctLenPtr)
  freePtr(M, hSSPtr)
  M._free(mechPtr)
  freeTemplate(M, ssTpl)
  return { ciphertextBytes, secretHandle }
}

/** ML-KEM decapsulate → secretHandle */
export function decapsulate(M, hSession, privHandle, ct, variant) {
  const ssTpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_GENERIC_SECRET },
    { type: CK.CKA_VALUE_LEN, value: 32 },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_EXTRACTABLE, value: true },         // required: ACVP test extracts SS for comparison
    { type: CK.CKA_SENSITIVE, value: false },
    // Usage attrs — explicit per PKCS#11 v3.2 §4.3; SS is only extracted, never used for crypto ops
    { type: CK.CKA_ENCRYPT, value: false },
    { type: CK.CKA_DECRYPT, value: false },
    { type: CK.CKA_SIGN, value: false },
    { type: CK.CKA_VERIFY, value: false },
    { type: CK.CKA_WRAP, value: false },
    { type: CK.CKA_UNWRAP, value: false },
    { type: CK.CKA_DERIVE, value: false },
  ])
  const mechPtr = buildMech(M, CK.CKM_ML_KEM)
  const ctPtr = writeBytes(M, ct)
  const hSSPtr = allocUlong(M)
  check(
    'C_DecapsulateKey',
    M._C_DecapsulateKey(
      hSession,
      mechPtr,
      privHandle,
      ssTpl.arrPtr,
      ssTpl.count,
      ctPtr,
      ct.length,
      hSSPtr
    )
  )
  const secretHandle = readUlong(M, hSSPtr)
  M._free(ctPtr)
  freePtr(M, hSSPtr)
  M._free(mechPtr)
  freeTemplate(M, ssTpl)
  return secretHandle
}

// ── Key Wrapping ────────────────────────────────────────────────────────────

/** Wrap key → wrappedBytes */
export function wrapKey(M, hSession, mechType, wrappingHandle, targetHandle) {
  const mechPtr = buildMech(M, mechType)
  const lenPtr = allocUlong(M)
  // Query wrapped length
  check('C_WrapKey(len)', M._C_WrapKey(hSession, mechPtr, wrappingHandle, targetHandle, 0, lenPtr))
  const wrapLen = readUlong(M, lenPtr)
  const outPtr = M._malloc(wrapLen)
  M.setValue(lenPtr, wrapLen, 'i32')
  check(
    'C_WrapKey',
    M._C_WrapKey(hSession, mechPtr, wrappingHandle, targetHandle, outPtr, lenPtr)
  )
  const actualLen = readUlong(M, lenPtr)
  const result = new Uint8Array(M.HEAPU8.buffer, outPtr, actualLen).slice()
  M._free(outPtr)
  freePtr(M, lenPtr)
  M._free(mechPtr)
  return result
}

/** Unwrap key → handle */
export function unwrapKey(M, hSession, mechType, unwrappingHandle, wrapped, attrs) {
  const mechPtr = buildMech(M, mechType)
  const wrappedPtr = writeBytes(M, wrapped)
  const tpl = buildTemplate(M, attrs)
  const hPtr = allocUlong(M)
  check(
    'C_UnwrapKey',
    M._C_UnwrapKey(
      hSession,
      mechPtr,
      unwrappingHandle,
      wrappedPtr,
      wrapped.length,
      tpl.arrPtr,
      tpl.count,
      hPtr
    )
  )
  const handle = readUlong(M, hPtr)
  M._free(wrappedPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  M._free(mechPtr)
  return handle
}

// ── KDF Operations ──────────────────────────────────────────────────────────

/**
 * PBKDF2 derivation → raw key bytes
 * CK_PKCS5_PBKD2_PARAMS2 struct (36 bytes on 32-bit WASM):
 *   saltSource(4) pSaltSourceData(4) ulSaltSourceDataLen(4)
 *   iterations(4) prf(4) pPrfData(4) ulPrfDataLen(4)
 *   pPassword(4) ulPasswordLen(4)
 */
export function pbkdf2(M, hSession, password, salt, iterations, keyLen) {
  const saltPtr = writeBytes(M, salt)
  const pwdPtr = writeBytes(M, password)
  const paramsPtr = M._malloc(36)
  M.setValue(paramsPtr + 0, CKS_PKCS5_PBKD2_SALT_SPECIFIED, 'i32')
  M.setValue(paramsPtr + 4, saltPtr, 'i32')
  M.setValue(paramsPtr + 8, salt.length, 'i32')
  M.setValue(paramsPtr + 12, iterations, 'i32')
  M.setValue(paramsPtr + 16, CKP_PKCS5_PBKD2_HMAC_SHA512, 'i32')
  M.setValue(paramsPtr + 20, 0, 'i32') // pPrfData = NULL
  M.setValue(paramsPtr + 24, 0, 'i32') // ulPrfDataLen = 0
  M.setValue(paramsPtr + 28, pwdPtr, 'i32')
  M.setValue(paramsPtr + 32, password.length, 'i32')

  const mechPtr = buildMech(M, CK.CKM_PKCS5_PBKD2, paramsPtr, 36)
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_GENERIC_SECRET },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_EXTRACTABLE, value: true },
    { type: CK.CKA_SENSITIVE, value: false },
    { type: CK.CKA_VALUE_LEN, value: keyLen },
  ])
  const hPtr = allocUlong(M)
  // PBKDF2 uses hBaseKey=0 (no base key — password is in params)
  check('C_DeriveKey(PBKDF2)', M._C_DeriveKey(hSession, mechPtr, 0, tpl.arrPtr, tpl.count, hPtr))
  const derivedHandle = readUlong(M, hPtr)
  const result = extractKeyValue(M, hSession, derivedHandle)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  M._free(mechPtr)
  M._free(paramsPtr)
  M._free(saltPtr)
  M._free(pwdPtr)
  return result
}

/**
 * HKDF derivation → raw key bytes
 * CK_HKDF_PARAMS struct (32 bytes on 32-bit WASM):
 *   +0  bExtract(1) bExpand(1) padding(2)
 *   +4  prfHashMechanism(4) +8 ulSaltType(4)
 *   +12 pSalt(4) +16 ulSaltLen(4) +20 hSaltKey(4)
 *   +24 pInfo(4) +28 ulInfoLen(4)
 */
export function hkdf(M, hSession, ikmHandle, hashMech, extract, expand, salt, info, keyLen) {
  const saltPtr = writeBytes(M, salt)
  const infoPtr = writeBytes(M, info)
  const paramsPtr = M._malloc(32)
  M.HEAPU8.fill(0, paramsPtr, paramsPtr + 32)
  M.HEAPU8[paramsPtr + 0] = extract ? 1 : 0
  M.HEAPU8[paramsPtr + 1] = expand ? 1 : 0
  M.setValue(paramsPtr + 4, hashMech, 'i32')
  M.setValue(paramsPtr + 8, CKF_HKDF_SALT_DATA, 'i32')
  M.setValue(paramsPtr + 12, saltPtr, 'i32')
  M.setValue(paramsPtr + 16, salt.length, 'i32')
  M.setValue(paramsPtr + 20, 0, 'i32') // hSaltKey = 0
  M.setValue(paramsPtr + 24, infoPtr, 'i32')
  M.setValue(paramsPtr + 28, info.length, 'i32')

  const mechPtr = buildMech(M, CK.CKM_HKDF_DERIVE, paramsPtr, 32)
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_GENERIC_SECRET },
    { type: CK.CKA_TOKEN, value: false },
    { type: CK.CKA_EXTRACTABLE, value: true },
    { type: CK.CKA_SENSITIVE, value: false },
    { type: CK.CKA_VALUE_LEN, value: keyLen },
  ])
  const hPtr = allocUlong(M)
  check(
    'C_DeriveKey(HKDF)',
    M._C_DeriveKey(hSession, mechPtr, ikmHandle, tpl.arrPtr, tpl.count, hPtr)
  )
  const derivedHandle = readUlong(M, hPtr)
  const result = extractKeyValue(M, hSession, derivedHandle)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  M._free(mechPtr)
  M._free(paramsPtr)
  M._free(saltPtr)
  M._free(infoPtr)
  return result
}

// ── Engine loading ───────────────────────────────────────────────────────────

// Create an Emscripten-compatible shim around a wasm-bindgen module.
// Adds HEAPU8, setValue, getValue on top of the _C_ / _malloc / _free exports.
function shimWasmBindgen(mod, wasmMemory) {
  const shim = {}
  for (const [key, val] of Object.entries(mod)) {
    if (typeof val === 'function') shim[key] = val
  }
  shim.setValue = (ptr, val, type) => {
    const dv = new DataView(wasmMemory.buffer)
    if (type === 'i32') dv.setInt32(ptr, val, true)
    else if (type === 'i8') dv.setInt8(ptr, val)
  }
  shim.getValue = (ptr, type) => {
    const dv = new DataView(wasmMemory.buffer)
    if (type === 'i32') return dv.getInt32(ptr, true)
    else if (type === 'i8') return dv.getInt8(ptr)
    return 0
  }
  Object.defineProperty(shim, 'HEAPU8', {
    get() { return new Uint8Array(wasmMemory.buffer) },
  })
  shim._engineName = 'rust'
  return shim
}

// ── HSS / LMS helpers (RFC 8554 + SP 800-208) ──────────────────────────────

/**
 * Build a CK_HSS_KEY_PAIR_GEN_PARAMS struct in WASM heap (68 bytes on WASM32).
 * Layout: ulLevels(4) | ulLmsParamSet[8](32) | ulLmotsParamSet[8](32)
 * lmsParams / lmotsParams are arrays of up to 8 CKP_LMS_* / CKP_LMOTS_* values.
 * Returns { ptr, size } — caller must free ptr.
 */
export function buildHSSKeyGenParams(M, lmsParams, lmotsParams) {
  const levels = lmsParams.length
  if (levels < 1 || levels > 8) throw new Error(`HSS levels must be 1–8, got ${levels}`)
  const ptr = M._malloc(68)
  M.setValue(ptr + 0, levels, 'i32')
  for (let i = 0; i < 8; i++) {
    M.setValue(ptr + 4  + i * 4, i < lmsParams.length  ? lmsParams[i]  : 0, 'i32')
    M.setValue(ptr + 36 + i * 4, i < lmotsParams.length ? lmotsParams[i] : 0, 'i32')
  }
  return { ptr, size: 68 }
}

/**
 * Generate a single-level HSS key pair.
 * lmsParamSet / lmotsParamSet are single CKP_LMS_* / CKP_LMOTS_* values.
 * Returns { pubHandle, privHandle }.
 */
export function generateHSSKeyPair(M, hSession, lmsParamSet, lmotsParamSet) {
  const hssParams = buildHSSKeyGenParams(M, [lmsParamSet], [lmotsParamSet])
  const mech = buildMech(M, CK.CKM_HSS_KEY_PAIR_GEN, hssParams.ptr, hssParams.size)
  const pubTpl = buildTemplate(M, [
    { type: CK.CKA_CLASS,     value: CK.CKO_PUBLIC_KEY },
    { type: CK.CKA_KEY_TYPE,  value: CK.CKK_HSS },
    { type: CK.CKA_TOKEN,     value: false },
    { type: CK.CKA_VERIFY,    value: true },
  ])
  const prvTpl = buildTemplate(M, [
    { type: CK.CKA_CLASS,       value: CK.CKO_PRIVATE_KEY },
    { type: CK.CKA_KEY_TYPE,    value: CK.CKK_HSS },
    { type: CK.CKA_TOKEN,       value: false },
    { type: CK.CKA_SIGN,        value: true },
    { type: CK.CKA_EXTRACTABLE, value: false },
    { type: CK.CKA_SENSITIVE,   value: true },
  ])
  const hPubPtr = allocUlong(M)
  const hPrvPtr = allocUlong(M)
  check('C_GenerateKeyPair(HSS)', M._C_GenerateKeyPair(
    hSession, mech,
    pubTpl.arrPtr, pubTpl.count,
    prvTpl.arrPtr, prvTpl.count,
    hPubPtr, hPrvPtr
  ))
  const pubHandle  = readUlong(M, hPubPtr)
  const privHandle = readUlong(M, hPrvPtr)
  freeTemplate(M, pubTpl)
  freeTemplate(M, prvTpl)
  M._free(mech)
  M._free(hssParams.ptr)
  freePtr(M, hPubPtr)
  freePtr(M, hPrvPtr)
  return { pubHandle, privHandle }
}

/** Sign msgBytes with an HSS private key. Returns signature Uint8Array. */
export function hssSign(M, hSession, privHandle, msgBytes) {
  const mechPtr = buildMech(M, CK.CKM_HSS)
  check('C_SignInit(HSS)', M._C_SignInit(hSession, mechPtr, privHandle))
  M._free(mechPtr)
  const msgPtr = writeBytes(M, msgBytes)
  // HSS signatures are large — allocate generously (SLH-DSA max ~50 KB; HSS H=5 ~2.5 KB)
  const sigBufLen = 65536
  const sigPtr = M._malloc(sigBufLen)
  const sigLenPtr = allocUlong(M)
  M.setValue(sigLenPtr, sigBufLen, 'i32')
  check('C_Sign(HSS)', M._C_Sign(hSession, msgPtr, msgBytes.length, sigPtr, sigLenPtr))
  const sigLen = readUlong(M, sigLenPtr)
  const sig = new Uint8Array(M.HEAPU8.buffer, sigPtr, sigLen).slice()
  M._free(msgPtr)
  M._free(sigPtr)
  freePtr(M, sigLenPtr)
  return sig
}

/**
 * Verify an HSS signature.
 * Returns true on CKR_OK, false on CKR_SIGNATURE_INVALID, throws on other errors.
 */
export function hssVerify(M, hSession, pubHandle, msgBytes, sigBytes) {
  const mechPtr = buildMech(M, CK.CKM_HSS)
  check('C_VerifyInit(HSS)', M._C_VerifyInit(hSession, mechPtr, pubHandle))
  M._free(mechPtr)
  const msgPtr = writeBytes(M, msgBytes)
  const sigPtr = writeBytes(M, sigBytes)
  const rv = M._C_Verify(hSession, msgPtr, msgBytes.length, sigPtr, sigBytes.length)
  M._free(msgPtr)
  M._free(sigPtr)
  if (rv === CK.CKR_OK) return true
  if (rv === CK.CKR_SIGNATURE_INVALID) return false
  throw new Error(`C_Verify(HSS) failed: 0x${rv.toString(16)}`)
}

/**
 * Extract the raw public key bytes (CKA_VALUE) from an HSS public key object.
 * Returns Uint8Array.
 */
export function hssGetPublicKeyBytes(M, hSession, pubHandle) {
  return extractKeyValue(M, hSession, pubHandle)
}

/**
 * Import an HSS public key from raw bytes for verification (cross-engine check).
 * Uses C_CreateObject with CKK_HSS + CKA_VALUE + CKA_VERIFY=true.
 * CKA_HSS_* attributes have ck2|ck4 — they must NOT appear in the template.
 * Returns a key handle usable in C_VerifyInit / C_Verify.
 */
export function hssImportPublicKey(M, hSession, pubKeyBytes) {
  const tpl = buildTemplate(M, [
    { type: CK.CKA_CLASS,    value: CK.CKO_PUBLIC_KEY },
    { type: CK.CKA_KEY_TYPE, value: CK.CKK_HSS },
    { type: CK.CKA_TOKEN,    value: false },
    { type: CK.CKA_VERIFY,   value: true },
    { type: CK.CKA_VALUE,    value: pubKeyBytes },
  ])
  const hPtr = allocUlong(M)
  check('C_CreateObject(HSS-pub)', M._C_CreateObject(hSession, tpl.arrPtr, tpl.count, hPtr))
  const handle = readUlong(M, hPtr)
  freeTemplate(M, tpl)
  freePtr(M, hPtr)
  return handle
}

/**
 * Load a WASM engine and return an Emscripten-compatible module object.
 * @param {'cpp'|'rust'} engine — which WASM build to load
 * @returns {Promise<object>} M — unified API: _C_*, _malloc, _free, HEAPU8, setValue, getValue
 */
export async function loadEngine(engine) {
  if (engine === 'rust') {
    // wasm-pack 0.14 / wasm-bindgen 0.2.117 generates a split format:
    //   softhsmrustv3.js      — thin re-export with static WASM import (breaks Node.js)
    //   softhsmrustv3_bg.js   — all _C_* exports + __wbg_set_wasm()
    //   softhsmrustv3_bg.wasm — WASM binary (imports only from './softhsmrustv3_bg.js')
    // We initialise manually: import _bg.js, instantiate WASM with it as the import
    // object, then wire with __wbg_set_wasm — same behaviour as the old initSync path.
    const rustBgJsPath = path.resolve(WASM_DIR, 'rust/softhsmrustv3_bg.js')
    const rustWasmPath = path.resolve(WASM_DIR, 'rust/softhsmrustv3_bg.wasm')
    const wasmBytes = readFileSync(rustWasmPath)
    const bgMod = await import(rustBgJsPath)
    const wasmModule = new WebAssembly.Module(wasmBytes)
    const wasmInstance = new WebAssembly.Instance(wasmModule, { './softhsmrustv3_bg.js': bgMod })
    bgMod.__wbg_set_wasm(wasmInstance.exports)
    wasmInstance.exports.__wbindgen_start?.()
    return shimWasmBindgen(bgMod, wasmInstance.exports.memory)
  }
  // Default: C++ Emscripten module (already has HEAPU8, setValue, getValue)
  const cppJsPath = path.resolve(WASM_DIR, 'softhsm.js')
  const { default: createModule } = await import(cppJsPath)
  const M = await createModule()
  M._engineName = 'cpp'
  return M
}

// Re-export CK for convenience
export { CK }
