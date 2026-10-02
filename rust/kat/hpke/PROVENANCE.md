# rust/kat/hpke — provenance

Published reference vectors replayed by `rust/src/hpke_pq_vectors_tests.rs`. All were fetched on 2026-10-01 with `pqctoday-priv/scripts/fetch_resilient.py` from the pinned upstream commit shown. Every file except the ACVP subset is byte-identical to upstream.

| File | Upstream | sha256 |
|---|---|---|
| `hpke-pq-test-vectors.json` | https://raw.githubusercontent.com/hpkewg/hpke-pq/6433c8fce0b8b749dfc86c1095081a88698ccfab/test-vectors.json (draft-ietf-hpke-pq-05 Appendix A; official `draft-ietf-hpke-pq-05` tag) | `35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c` |
| `cfrg-concrete-hybrid-kems-test-vectors.json` | https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-concrete-hybrid-kems/e76e1939fb5bec71d3d6c206de20ca2c008f1f80/test-vectors.json | `08b47d9fe5c827f7ceb20dd10a59bc853a949d6eaf0ad835405e86d833f92bad` |
| `xwing-test-vectors.json` | https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/test-vectors.json | `409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d` |
| `jose-hpke-pq-pqt-01-vectors.json` | https://raw.githubusercontent.com/panva/draft-jose-hpke-pq-pqt/47a746533ebb94c4193ee6a4e2f76170a6790335/examples/jose-vectors.json (draft-ietf-jose-hpke-pq-pqt-01 Appendix A). The plaintext is the constant in that commit's `scripts/jwe.js`. | `97e5fd1c5bd417b3af3f8948e8c54914c7c9f544ad786182d18cf15a011bd2c0` |
| `acvp-shake256-aft-bytealigned.json` | **Subset** of https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SHAKE-256-FIPS202/internalProjection.json (upstream sha256 `a9348d17e009cad62a2baa70160353f5bca936a27116f60dd5811f39b91c6991`). Kept: the 41 AFT cases whose message and output lengths are whole bytes. Fields unchanged; a `_provenance` block is added. | `050a620e9590b35ddbe99329eb8d0ab5ea7a1f39b6d4cc61aab41f068b847a6f` |

**Independence.** These vectors come from four independent sources:
- the hpkewg Rust generator;
- the CFRG reference implementation;
- the X-Wing draft author;
- the JOSE draft author, using the `hpke` npm package on Node's native ML-KEM.

None of them shares code with this engine.

**Cross-check before the Rust implementation existed:** a Node reference model built on noble ML-KEM, hybrids and SHAKE256 reproduced all of these vectors (61/61 checks). It is in the Antigravity workspace at `hpke-jwe-evidence-10012026/refmodel/hpke_ref.mjs`.
