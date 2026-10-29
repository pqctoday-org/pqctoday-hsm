// Run against a real wasm-pack --target nodejs build with educational-replication.
// This checks the browser-facing exports and their refusal behavior, not a full
// browser ceremony or a successful recovery. No private material is exported.
const assert = require('node:assert/strict')
const path = require('node:path')

if (!process.argv[2]) throw new Error('Pass the built softhsmrustv3.js path')
const M = require(path.resolve(process.argv[2]))
const request = new Uint8Array(0)
const throwsCode = (fn, code) => assert.throws(fn, (error) => error === code)

throwsCode(() => M.pqctodaySelectEducationalReplicationProfile(), 0x190)
assert.equal(M._C_Initialize(0), 0)
try {
  throwsCode(() => M.pqctodayCreateReplicationPackage(0, 0, request), 0x54)
  M.pqctodaySelectEducationalReplicationProfile()
  throwsCode(() => M.pqctodayCreateReplicationPackage(0, 0, request), 0xb3)
  throwsCode(() => M.pqctodayImportReplicationPackage(0, request), 0xb3)
  throwsCode(() => M.pqctodayCloneKey(0, 0, 0, request), 0xb3)
  M.pqctodayClearReplicationProfile()
  throwsCode(() => M.pqctodayCreateReplicationPackage(0, 0, request), 0x54)
} finally {
  assert.equal(M._C_Finalize(0), 0)
}
console.log('Built WASM replication exports: initialization/profile/session refusals PASS')
