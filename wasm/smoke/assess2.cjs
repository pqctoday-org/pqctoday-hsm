#!/usr/bin/env node
// assess2.cjs — confirm the rekey fix hypothesis: a substitution rule keyed on
// the COARSE stored name (`from: ECDSA`) should match the stored key and fire
// RekeyAndProceed, where the canonical `from: ECDSA-P256` does not.
const fs = require('fs'), path = require('path')
const { KmipPlayground } = require('../pkg_node/pqctoday_kmip_wasm.js')
const POL = path.join(__dirname, '..', '..', 'kmip', 'policies')
const pg = new KmipPlayground()
const run = (s) => JSON.parse(pg.run_op(JSON.stringify(s)))
const p1 = (r) => (r.audit.find((e) => e.plane === 'p1') || {}).event || {}
const L = console.log

pg.load_policy(fs.readFileSync(path.join(POL, 'classical.yaml'), 'utf8'))
const ck = run({ op: 'CreateKeyPair', intent: 'sign' })
const priv = ck.summary.privateKeyUid
run({ op: 'Activate', uid: priv })
L(`created+activated ECDSA key (default): ${priv.slice(0, 30)}…`)

// Inline PQC policy whose substitution `from:` uses the COARSE name the engine stores.
const coarsePqc = `
schema_version: 1
metadata: { name: pqc-coarse-demo, description: coarse-name rekey demo, authority: t, effective: "always" }
rules:
  - type: algorithm_default
    ops: ["CreateKeyPair:Sign"]
    default_algorithm: ML-DSA-87
    reason: "PQC signing default"
  - type: algorithm_substitution
    ops: [Sign]
    from: ECDSA
    to: ML-DSA-87
    reason: "Rekey classical ECDSA signing key to ML-DSA-87 at first use"
`
L('load inline pqc-coarse-demo (from: ECDSA) → ' + JSON.stringify(JSON.parse(pg.load_policy(coarsePqc))))

const sig = run({ op: 'Sign', uid: priv, text: 'rekey me' })
L(`\nSign same key under coarse pqc → ok=${sig.ok} status=${sig.status} sigBytes=${sig.summary.signatureLen}`)
L(`p1 event = ${JSON.stringify(p1(sig))}`)
L(`audit: ${sig.audit.map((e) => `${e.plane}:${e.event.type}`).join(', ')}`)
L('\nkeystore:')
JSON.parse(pg.list_objects()).forEach((o) => L(`  ${o.state.padEnd(12)} ${o.algorithm.padEnd(10)} ${o.uid.slice(0, 30)}…`))
