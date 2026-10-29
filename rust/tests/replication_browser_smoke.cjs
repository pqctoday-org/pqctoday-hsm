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
  M.pqctodaySelectEducationalReplicationProfile()
  const lab = new M.ProtectedBackupLab('demo-so-pin', 'demo-user-pin')
  try {
    for (const algorithm of [0, 1]) {
      const original = lab.generate(algorithm)
      try {
        const sizes = []
        for (const seed of [true, false]) {
          const pkg = lab.backup(original.private_handle, seed)
          sizes.push(pkg.length)
          const recovered = lab.recover(pkg)
          try {
            assert.equal(recovered.key_type, original.key_type)
            assert.equal(recovered.parameter_set, original.parameter_set)
            assert.notEqual(recovered.private_handle, original.private_handle)
            assert.ok(recovered.receipt.length > 0)
            const retry = lab.recover(pkg)
            assert.equal(retry.private_handle, recovered.private_handle)
            retry.free()
          } finally {
            recovered.free()
          }
          const bad = pkg.slice()
          bad[bad.length - 1] ^= 1
          throwsCode(() => lab.recover(bad), 0x1b)
        }
        assert.ok(sizes[0] < sizes[1])
      } finally {
        original.free()
      }
    }
  } finally {
    lab.free()
  }
} finally {
  assert.equal(M._C_Finalize(0), 0)
}
console.log('Built WASM replication: refusals and Seed/Expanded recovery identity/receipts/retry PASS (ML-KEM-768, ML-DSA-65)')
