/**
 * c-get-function-list.mjs — PKCS#11 v3.2 §5.4.4 C_GetFunctionList
 *
 * The Rust engine's `_C_GetFunctionList` returns a CK_FUNCTION_LIST whose
 * fields are real WASM indirect-function-table indices — a caller
 * retrieves one with `table.get(idx)` and invokes it directly, the
 * standard way to call a funcref pulled from linear memory. This is a
 * fundamentally different mechanism from every other `_C_*` export (which
 * this whole test suite calls by name), so it needs its own dedicated
 * coverage: nothing else in this suite ever drives the engine through the
 * table instead of a named export.
 *
 * Rust-only: the C++ Emscripten engine's C_GetFunctionList returns a
 * genuine native-style function-pointer struct via a completely different
 * mechanism (no wasm-bindgen involved) and isn't affected by any of this.
 *
 * Usage: node tests/c-get-function-list.mjs
 */
import { loadEngine, CK } from './helpers.mjs'
import crypto from 'node:crypto'

const NAMES = [
  'C_Initialize', 'C_Finalize', 'C_GetInfo', 'C_GetFunctionList', 'C_GetSlotList',
  'C_GetSlotInfo', 'C_GetTokenInfo', 'C_GetMechanismList', 'C_GetMechanismInfo',
  'C_InitToken', 'C_InitPIN', 'C_SetPIN', 'C_OpenSession', 'C_CloseSession',
  'C_CloseAllSessions', 'C_GetSessionInfo', 'C_GetOperationState', 'C_SetOperationState',
  'C_Login', 'C_Logout', 'C_CreateObject', 'C_CopyObject', 'C_DestroyObject',
  'C_GetObjectSize', 'C_GetAttributeValue', 'C_SetAttributeValue', 'C_FindObjectsInit',
  'C_FindObjects', 'C_FindObjectsFinal', 'C_EncryptInit', 'C_Encrypt', 'C_EncryptUpdate',
  'C_EncryptFinal', 'C_DecryptInit', 'C_Decrypt', 'C_DecryptUpdate', 'C_DecryptFinal',
  'C_DigestInit', 'C_Digest', 'C_DigestUpdate', 'C_DigestKey', 'C_DigestFinal',
  'C_SignInit', 'C_Sign', 'C_SignUpdate', 'C_SignFinal', 'C_SignRecoverInit',
  'C_SignRecover', 'C_VerifyInit', 'C_Verify', 'C_VerifyUpdate', 'C_VerifyFinal',
  'C_VerifyRecoverInit', 'C_VerifyRecover', 'C_DigestEncryptUpdate', 'C_DecryptDigestUpdate',
  'C_SignEncryptUpdate', 'C_DecryptVerifyUpdate', 'C_GenerateKey', 'C_GenerateKeyPair',
  'C_WrapKey', 'C_UnwrapKey', 'C_DeriveKey', 'C_SeedRandom', 'C_GenerateRandom',
  'C_GetFunctionStatus', 'C_CancelFunction', 'C_WaitForSlotEvent',
]
if (NAMES.length !== 68) throw new Error(`expected 68 canonical v2.40 entries, got ${NAMES.length}`)

// C_GetFunctionStatus and C_CancelFunction are both spec-mandated (§5.21,
// legacy parallelism API) to unconditionally return CKR_FUNCTION_NOT_
// PARALLEL for every session — their compiled bodies are byte-identical,
// so a release build's identical-code-folding legitimately merges them
// into one table entry. Verified 2026-08-28: this is the only pair this
// happens to; any other collision is a real bug, not this known case.
const EXPECTED_SHARED_INDEX_PAIR = ['C_GetFunctionStatus', 'C_CancelFunction']

let failures = 0
const check = (label, cond) => {
  console.log(`${cond ? '✅' : '❌'} ${label}`)
  if (!cond) failures++
}

const M = await loadEngine('rust')
if (!M.__indirect_function_table) {
  console.log('SKIPPED: c-get-function-list.mjs — no __indirect_function_table on this ' +
    'engine (only the Rust wasm-bindgen build patches one in; see rust/patch_export_table.py).')
  process.exit(0)
}
const table = M.__indirect_function_table

// ── Structural checks ──────────────────────────────────────────────────

const ppPtr = M._malloc(4)
const rv0 = M._C_GetFunctionList(ppPtr) >>> 0
check('C_GetFunctionList(before C_Initialize) → CKR_OK (§5.4.4: legal before init)', rv0 === 0)

const structPtr = M.getValue(ppPtr, 'i32') >>> 0
const major = M.HEAPU8[structPtr]
const minor = M.HEAPU8[structPtr + 1]
check('CryptokiVersion = 3.2', major === 3 && minor === 2)

const indices = []
for (let i = 0; i < 68; i++) indices.push(M.getValue(structPtr + 2 + i * 4, 'i32') >>> 0)

check('no zero (NULL) table indices', indices.every((idx) => idx !== 0))

const dupCounts = new Map()
for (const idx of indices) dupCounts.set(idx, (dupCounts.get(idx) ?? 0) + 1)
const dupIndices = [...dupCounts.entries()].filter(([, count]) => count > 1)
const dupNamePairs = dupIndices.map(([idx]) => NAMES.filter((_, i) => indices[i] === idx).sort())
const onlyExpectedDup =
  dupNamePairs.length === 1 &&
  JSON.stringify(dupNamePairs[0]) === JSON.stringify([...EXPECTED_SHARED_INDEX_PAIR].sort())
check(
  `index collisions are exactly the known C_GetFunctionStatus/C_CancelFunction fold (found: ${JSON.stringify(dupNamePairs)})`,
  onlyExpectedDup || dupNamePairs.length === 0
)

check(
  'every table entry resolves to a callable function',
  indices.every((idx) => typeof table.get(idx) === 'function')
)

const ppPtr2 = M._malloc(4)
M._C_GetFunctionList(ppPtr2)
check('repeat call returns the same struct pointer (library-owned, cached)', M.getValue(ppPtr2, 'i32') >>> 0 === structPtr)

check('C_GetFunctionList(NULL) → CKR_ARGUMENTS_BAD', (M._C_GetFunctionList(0) >>> 0) === CK.CKR_ARGUMENTS_BAD)

M._free(ppPtr)
M._free(ppPtr2)

// ── Behavioral check: drive a full, real PKCS#11 session ENTIRELY through
// table.get(idx)(args) instead of a single named _C_* export, and cross-
// check a real cryptographic result (SHA-256) against an independent
// oracle — proving this isn't just "doesn't throw" but produces the
// actual correct engine behavior. ──

const idxOf = (name) => indices[NAMES.indexOf(name)]
const call = (name, ...args) => table.get(idxOf(name))(...args)
const writeStr = (s) => {
  const bytes = new TextEncoder().encode(s)
  const ptr = M._malloc(bytes.length)
  M.HEAPU8.set(bytes, ptr)
  return { ptr, len: bytes.length }
}

check('C_Initialize (via table)', (call('C_Initialize', 0) >>> 0) === 0)

const countPtr = M._malloc(4)
call('C_GetSlotList', 0, 0, countPtr)
const slotCount = M.getValue(countPtr, 'i32') >>> 0
const slotListPtr = M._malloc(4 * Math.max(slotCount, 1))
M.setValue(countPtr, slotCount, 'i32')
call('C_GetSlotList', 0, slotListPtr, countPtr)
const slot0 = M.getValue(slotListPtr, 'i32') >>> 0
check('C_GetSlotList (via table) found a slot', slotCount >= 1)

const soPin = writeStr('12345678')
const label = writeStr('SoftHSM3'.padEnd(32, ' '))
check('C_InitToken (via table)', (call('C_InitToken', slot0, soPin.ptr, soPin.len, label.ptr) >>> 0) === 0)

const hSessPtr = M._malloc(4)
check('C_OpenSession (via table)', (call('C_OpenSession', slot0, 0x00000006, 0, 0, hSessPtr) >>> 0) === 0)
const hSession = M.getValue(hSessPtr, 'i32') >>> 0

call('C_Login', hSession, 0, soPin.ptr, soPin.len) // CKU_SO
const userPin = writeStr('user1234')
check('C_InitPIN (via table)', (call('C_InitPIN', hSession, userPin.ptr, userPin.len) >>> 0) === 0)
call('C_Logout', hSession)
check('C_Login as USER (via table)', (call('C_Login', hSession, 1, userPin.ptr, userPin.len) >>> 0) === 0)

const mechPtr = M._malloc(12)
M.setValue(mechPtr, CK.CKM_SHA256, 'i32')
M.setValue(mechPtr + 4, 0, 'i32')
M.setValue(mechPtr + 8, 0, 'i32')
check('C_DigestInit (via table)', (call('C_DigestInit', hSession, mechPtr) >>> 0) === 0)

const msg = writeStr('abc')
const digestLenPtr = M._malloc(4)
call('C_Digest', hSession, msg.ptr, msg.len, 0, digestLenPtr)
const digestLen = M.getValue(digestLenPtr, 'i32') >>> 0
const digestPtr = M._malloc(digestLen)
const rvDigest = call('C_Digest', hSession, msg.ptr, msg.len, digestPtr, digestLenPtr) >>> 0
const digestHex = Buffer.from(M.HEAPU8.subarray(digestPtr, digestPtr + digestLen)).toString('hex')
const expectedHex = crypto.createHash('sha256').update('abc').digest('hex')
check('C_Digest("abc") via table → rv=OK', rvDigest === 0)
check('C_Digest("abc") via table matches independent SHA-256 oracle', digestHex === expectedHex)

call('C_CloseSession', hSession)
call('C_CloseAllSessions', slot0)
check('C_Finalize (via table)', (call('C_Finalize', 0) >>> 0) === 0)

console.log(`\n${failures === 0 ? '════════ RESULT: 0 failed ════════' : `════════ RESULT: ${failures} FAILED ════════`}`)
process.exit(failures === 0 ? 0 : 1)
