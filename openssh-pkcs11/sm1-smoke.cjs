// SM1 smoke test: load sshd.wasm, run __wrap_main (via callMain), assert the
// PKCS#11 bring-up + provisioning + one host-key C_Sign happened in-instance.
const path = require('path')
const assert = require('assert')
const SERVER_JS = path.join(__dirname, 'dist', 'openssh-server.js')

let factory = require(SERVER_JS)
if (typeof factory !== 'function' && factory && typeof factory.default === 'function') {
  factory = factory.default
}

;(async () => {
  const events = []
  const DIST = path.join(__dirname, 'dist')
  const Module = await factory({
    noInitialRun: true,
    // emscripten glue requests its internal name 'sshd.wasm'; map to the renamed artifact.
    locateFile: (p) => (p.endsWith('.wasm') ? path.join(DIST, 'openssh-server.wasm') : path.join(DIST, p)),
    onHandshakeEvent: (type, payload) => {
      events.push({ type, payload })
      console.log('EVENT', type, payload)
    },
  })
  // __wrap_main is exported directly (native main() is GC'd). ASYNCIFY => Promise.
  let r = Module.ccall('__wrap_main', 'number', [], [], { async: true })
  if (r && typeof r.then === 'function') r = await r
  console.log('__wrap_main ->', r)

  const types = events.map((e) => e.type)
  console.log('TYPES:', types.join(' '))
  assert(types.includes('provisioned'), 'provisioned event missing')
  assert(types.includes('pkcs11_ready'), 'pkcs11_ready event missing')
  const sign = events.find((e) => e.type === 'host_key_sign')
  assert(sign, 'host_key_sign event missing')
  const sigLen = JSON.parse(sign.payload).sig_len
  assert(sigLen === 3309, 'wrong ML-DSA-65 sig_len: ' + sigLen)
  console.log('SM1 OK — host-key C_Sign produced', sigLen, 'bytes from the token')

  // SM2: a real in-process mlkem768x25519 + ssh-mldsa-65 handshake reached NEWKEYS
  const nk = events.find((e) => e.type === 'newkeys')
  assert(nk, 'newkeys event missing (KEX did not reach NEWKEYS)')
  const j = JSON.parse(nk.payload)
  assert(j.server === 1 && j.client === 1, 'both sides did not reach NEWKEYS: ' + nk.payload)
  console.log('SM2 PASS — real mlkem768x25519 KEX reached NEWKEYS (client+server)')
})().catch((e) => {
  console.error('SM1 FAIL:', e && e.message ? e.message : e)
  process.exit(1)
})
