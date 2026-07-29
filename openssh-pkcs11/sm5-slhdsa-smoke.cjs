// SM5 smoke test: same real in-process PKCS#11-backed SSH handshake as
// sm1-smoke.cjs (ML-DSA-65), but with the host key profile switched to
// SLH-DSA-SHA2-128s (draft-josefsson-ssh-sphincs-02) via set_handshake_config.
// Verifies the v0.18.0 backport actually works at runtime, not just that it
// compiles and links (that part was confirmed by the v0.19.0 toolchain rebuild).
const path = require('path')
const assert = require('assert')
const SERVER_JS = path.join(__dirname, 'dist', 'openssh-server.js')

const SLHDSA128S_SIG_LEN = 7856 // FIPS 205 §10 Table 2, raw signature bytes

let factory = require(SERVER_JS)
if (typeof factory !== 'function' && factory && typeof factory.default === 'function') {
  factory = factory.default
}

;(async () => {
  const events = []
  const DIST = path.join(__dirname, 'dist')
  const Module = await factory({
    noInitialRun: true,
    locateFile: (p) => (p.endsWith('.wasm') ? path.join(DIST, 'openssh-server.wasm') : path.join(DIST, p)),
    onHandshakeEvent: (type, payload) => {
      events.push({ type, payload })
      console.log('EVENT', type, payload)
    },
  })

  // Switch the host-key profile to SLH-DSA-SHA2-128s before __wrap_main runs.
  Module.ccall(
    'set_handshake_config',
    null,
    ['string', 'string'],
    ['mlkem768x25519-sha256', 'ssh-slh-dsa-sha2-128s']
  )

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
  assert(sigLen === SLHDSA128S_SIG_LEN, 'wrong SLH-DSA-SHA2-128s sig_len: ' + sigLen)
  console.log('SM5-SM1 OK — host-key C_Sign produced', sigLen, 'bytes from the token')

  const prov = events.find((e) => e.type === 'provider')
  assert(prov && JSON.parse(prov.payload).nkeys >= 1, 'provider returned no token keys (SM5-SM3)')

  const kexStart = events.find((e) => e.type === 'kex_start')
  assert(kexStart && JSON.parse(kexStart.payload).hostkey === 'ssh-slh-dsa-sha2-128s',
    'kex_start did not advertise ssh-slh-dsa-sha2-128s')

  const nk = events.find((e) => e.type === 'newkeys')
  assert(nk, 'newkeys event missing (KEX did not reach NEWKEYS)')
  const j = JSON.parse(nk.payload)
  assert(j.server === 1 && j.client === 1, 'both sides did not reach NEWKEYS: ' + nk.payload)
  assert(j.hostsign === 'C_Sign', 'host signature not via C_Sign: ' + nk.payload)
  console.log('SM5-SM3 OK — mlkem768x25519 KEX reached NEWKEYS; ssh-slh-dsa-sha2-128s host sign via token C_Sign')

  // sshkey_sign returns the SSH wire-format blob: string "ssh-slh-dsa-sha2-128s"
  // (4 + 21) + string signature (4 + 7856 raw) = 7885 bytes.
  const uks = events.find((e) => e.type === 'user_key_sign')
  assert(uks, 'user_key_sign event missing')
  const userSigLen = JSON.parse(uks.payload).user_sig_len
  assert(userSigLen === 4 + 21 + 4 + SLHDSA128S_SIG_LEN,
    'user-key C_Sign wrong wire size: ' + userSigLen)
  assert(events.some((e) => e.type === 'userauth_verified'), 'server did not verify the user signature')
  const ua = events.find((e) => e.type === 'userauth_success')
  assert(ua && JSON.parse(ua.payload).usersign === 'C_Sign', 'USERAUTH_SUCCESS via C_Sign missing')
  console.log('SM5-SM4 PASS — publickey userauth → USERAUTH_SUCCESS; SLH-DSA-SHA2-128s user key signed via token C_Sign')
})().catch((e) => {
  console.error('SM5 FAIL:', e && e.message ? e.message : e)
  process.exit(1)
})
