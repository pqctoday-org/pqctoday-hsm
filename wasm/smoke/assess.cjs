#!/usr/bin/env node
// assess.cjs — AGILITY SPIKE (plan W1 / risk R1): does flipping the policy change
// the behavior of an UNCHANGED operation? Creates a signing key with NO explicit
// algorithm under classical.yaml (→ policy default), then flips to pqc.yaml and
// re-signs the SAME key, expecting the engine to auto-rekey it to PQC.
const fs = require('fs')
const path = require('path')
const { KmipPlayground } = require('../pkg_node/pqctoday_kmip_wasm.js')

const POL = path.join(__dirname, '..', '..', 'kmip', 'policies')
const pg = new KmipPlayground()
const run = (s) => JSON.parse(pg.run_op(JSON.stringify(s)))
const load = (f) => JSON.parse(pg.load_policy(fs.readFileSync(path.join(POL, f), 'utf8')))
const p1 = (r) => (r.audit.find((e) => e.plane === 'p1') || {}).event || {}
const algoOf = (uid) => (JSON.parse(pg.list_objects()).find((o) => o.uid === uid) || {})
const L = console.log

L('## flip 1 — classical.yaml active')
L('load classical → ' + JSON.stringify(load('classical.yaml')))

L('\n## CreateKeyPair (intent=sign, NO explicit algorithm) — policy should default')
const ck = run({ op: 'CreateKeyPair', intent: 'sign' })
const priv = ck.summary.privateKeyUid, pub = ck.summary.publicKeyUid
L(`ok=${ck.ok}  p1.decision=${JSON.stringify(p1(ck).outcome || p1(ck).type)}  p1.algorithm=${p1(ck).algorithm}`)
L(`stored private key algorithm = ${algoOf(priv).algorithm}  (expect ECDSA under classical default)`)

run({ op: 'Activate', uid: priv }); run({ op: 'Activate', uid: pub })
const sig1 = run({ op: 'Sign', uid: priv, text: 'agility demo' })
L(`Sign under classical → ok=${sig1.ok} sigBytes=${sig1.summary.signatureLen} (ECDSA-P256 ≈ 70)`)

L('\n## flip 2 — pqc.yaml active (application code UNCHANGED)')
L('load pqc → ' + JSON.stringify(load('pqc.yaml')))

L('\n## re-Sign the SAME key — engine should RekeyAndProceed to ML-DSA-87')
const sig2 = run({ op: 'Sign', uid: priv, text: 'agility demo' })
L(`Sign under pqc → ok=${sig2.ok} status=${sig2.status} sigBytes=${sig2.summary.signatureLen}`)
L(`p1 event after flip = ${JSON.stringify(p1(sig2))}`)
L(`audit planes/types: ${sig2.audit.map((e) => `${e.plane}:${e.event.type}`).join(', ')}`)

L('\n## keystore after the flip — old key deprecated? new ML-DSA key present?')
JSON.parse(pg.list_objects()).forEach((o) =>
  L(`  ${o.state.padEnd(12)} ${o.algorithm.padEnd(10)} ${o.uid.slice(0, 30)}…`)
)

L('\n## boundary check — explicit ML-DSA under classical should be DENIED')
load('classical.yaml')
const denied = run({ op: 'CreateKeyPair', algorithm: 'ML-DSA-87' })
L(`CreateKeyPair ML-DSA-87 under classical → ok=${denied.ok} msg=${denied.message}`)
