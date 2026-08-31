// SM6 smoke test: same real in-process PKCS#11-backed SSH handshake as
// sm1-smoke.cjs/sm5-slhdsa-smoke.cjs, generalized across every ML-DSA and
// SLH-DSA parameter set this connector implements (11 total: ML-DSA-44/65/87
// + 8 SLH-DSA sets -- see wasm-shims/sshd_wasm_main.c's HOSTKEY_VARIANTS
// table and patches/ssh-mldsa.c / patches/ssh-slhdsa.c for the byte-size
// citations). Requires a fresh WASM instance per variant (set_handshake_config
// only takes effect before __wrap_main runs), so this drives one factory()
// call per parameter set rather than sm1/sm5's single run.
//
// NOTE: this environment has no Emscripten toolchain (emcc), so this harness
// has been written but NOT executed here. It was instead verified via a
// native (non-WASM) port of the same drive_kex()/do_userauth() logic --
// native_paramsweep_test.c, run against the real native softhsmv3 build --
// which exercised all 11 of the same parameter sets end-to-end with the same
// KAT-length assertions this file uses. See CHANGELOG.md for that run's
// full results and byte-size sources. This file should be run for real the
// next time dist/ is rebuilt with emcc available, per STATUS.md.
const path = require('path')
const assert = require('assert')
const SERVER_JS = path.join(__dirname, 'dist', 'openssh-server.js')

// hostalg -> raw signature length (FIPS 204 Table 2 / FIPS 205 §11 Table 2,
// cross-checked against deps/openssl-src/openssl-3.6.3's own
// include/crypto/ml_dsa.h and crypto/slh_dsa/slh_params.c).
const VARIANTS = [
  { hostalg: 'ssh-mldsa-44', sigLen: 2420 },
  { hostalg: 'ssh-mldsa-65', sigLen: 3309 },
  { hostalg: 'ssh-mldsa-87', sigLen: 4627 },
  { hostalg: 'ssh-slh-dsa-sha2-128s', sigLen: 7856 },
  { hostalg: 'ssh-slh-dsa-sha2-128f', sigLen: 17088 },
  { hostalg: 'ssh-slh-dsa-shake-128s', sigLen: 7856 },
  { hostalg: 'ssh-slh-dsa-shake-128f', sigLen: 17088 },
  { hostalg: 'ssh-slh-dsa-sha2-256s', sigLen: 29792 },
  { hostalg: 'ssh-slh-dsa-sha2-256f', sigLen: 49856 },
  { hostalg: 'ssh-slh-dsa-shake-256s', sigLen: 29792 },
  { hostalg: 'ssh-slh-dsa-shake-256f', sigLen: 49856 },
]

let factory = require(SERVER_JS)
if (typeof factory !== 'function' && factory && typeof factory.default === 'function') {
  factory = factory.default
}

async function runOne({ hostalg, sigLen }) {
  const events = []
  const DIST = path.join(__dirname, 'dist')
  const Module = await factory({
    noInitialRun: true,
    locateFile: (p) => (p.endsWith('.wasm') ? path.join(DIST, 'openssh-server.wasm') : path.join(DIST, p)),
    onHandshakeEvent: (type, payload) => {
      events.push({ type, payload })
    },
  })

  Module.ccall(
    'set_handshake_config',
    null,
    ['string', 'string'],
    ['mlkem768x25519-sha256', hostalg]
  )

  let r = Module.ccall('__wrap_main', 'number', [], [], { async: true })
  if (r && typeof r.then === 'function') r = await r

  const types = events.map((e) => e.type)
  assert(types.includes('provisioned'), `${hostalg}: provisioned event missing`)
  assert(types.includes('pkcs11_ready'), `${hostalg}: pkcs11_ready event missing`)

  const sign = events.find((e) => e.type === 'host_key_sign')
  assert(sign, `${hostalg}: host_key_sign event missing`)
  const hostSigLen = JSON.parse(sign.payload).sig_len
  assert.strictEqual(hostSigLen, sigLen, `${hostalg}: wrong host sig_len: ${hostSigLen} (expected ${sigLen})`)

  const prov = events.find((e) => e.type === 'provider')
  assert(prov && JSON.parse(prov.payload).nkeys >= 1, `${hostalg}: provider returned no token keys`)

  const kexStart = events.find((e) => e.type === 'kex_start')
  assert(kexStart && JSON.parse(kexStart.payload).hostkey === hostalg,
    `${hostalg}: kex_start did not advertise ${hostalg}`)

  const nk = events.find((e) => e.type === 'newkeys')
  assert(nk, `${hostalg}: newkeys event missing (KEX did not reach NEWKEYS)`)
  const j = JSON.parse(nk.payload)
  assert(j.server === 1 && j.client === 1, `${hostalg}: both sides did not reach NEWKEYS: ${nk.payload}`)
  assert.strictEqual(j.hostsign, 'C_Sign', `${hostalg}: host signature not via C_Sign`)

  // sshkey_sign returns the SSH wire-format blob: string <hostalg> (4 + len)
  // + string signature (4 + sigLen raw).
  const uks = events.find((e) => e.type === 'user_key_sign')
  assert(uks, `${hostalg}: user_key_sign event missing`)
  const userSigLen = JSON.parse(uks.payload).user_sig_len
  const expectUserSigLen = 4 + hostalg.length + 4 + sigLen
  assert.strictEqual(userSigLen, expectUserSigLen,
    `${hostalg}: user-key C_Sign wrong wire size: ${userSigLen} (expected ${expectUserSigLen})`)
  assert(events.some((e) => e.type === 'userauth_verified'), `${hostalg}: server did not verify the user signature`)
  const ua = events.find((e) => e.type === 'userauth_success')
  assert(ua && JSON.parse(ua.payload).usersign === 'C_Sign', `${hostalg}: USERAUTH_SUCCESS via C_Sign missing`)

  console.log(`SM6 PASS — ${hostalg}: sig_len=${sigLen}, NEWKEYS + USERAUTH_SUCCESS via C_Sign`)
}

;(async () => {
  for (const v of VARIANTS) {
    await runOne(v)
  }
  console.log(`SM6 OK — ${VARIANTS.length} parameter sets verified end-to-end`)
})().catch((e) => {
  console.error('SM6 FAIL:', e && e.message ? e.message : e)
  process.exit(1)
})
