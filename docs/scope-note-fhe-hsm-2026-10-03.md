# Scope note 2026-10-03: KMIP/CACP lane, KV260 compute lane, FPGA phase 2, device topology

Status: **confirmed by the owner, 2026-10-03.** Both plans' decision tables point here (FHE plan D5, D6, D17; HSM plan K2 and decision 12). Source: owner answers relayed by the
coordinator session (44) and session e5 on 2026-10-03. They are quoted where quoted to me, and
It applies to both plans:
- the FHE wrapper plan (`docs/implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md`);
- the HSM key-hierarchy plan (`docs/implementation-plan-hsm-key-hierarchy-replication-attestation-2026-10-02.md`).

## What changes

| Decision | Before | After (proposed text) |
|---|---|---|
| FHE plan approval scope (header) | "Approval scope requested: P-1 and P0 only" | **P1–P2 approved** ("Approve P1-P2 (Recommended)"): TFHE custody mechanisms in the Rust engine. P1 still starts only after the HSM plan's K4 exit, which is unchanged |
| FHE D5 (KMIP) | "Out of scope for this plan. No KMIP claims" | **In scope as a later lane** (stages 2–5 below). Stage 1, the PKCS#11 work in both plans, makes no KMIP claims |
| HSM K2 (2a: engines and protocols) | "Rust engine only … KMIP/CACP out of scope" | **Rust engine first; KMIP/CACP in scope as a later lane** (stages 2–3). The C++ engine and the protocol wrappers stay out of scope |
| FHE D6 (acceleration) | "ARM only (§8). The FPGA track is parked" | **ARM (Cortex-A53/A55) first; FPGA as phase 2** ("a53 first - fpga as 2nd phase"). Nothing FPGA in stages 1–4; FPGA scope is written only when that phase starts |
| FHE §8 (server-side evaluation) | "Server-side FHE evaluation is out of scope" | **In scope as the untrusted-compute lane on the KV260** (stage 4). It is outside the HSM, never linked into the token, and does not change the custody boundary |

## The program, as confirmed ("Confirmed", five stages)

1. **Stage 1, now:** HSM plan K1–K4 (hierarchy, attestation, replication; session 7f), then FHE plan P1–P2 (TFHE custody mechanisms in the Rust engine). PKCS#11 only.
2. **Stage 2, KMIP TTLV PKCS#11 operations** in `pqctoday-hsm` ("kmip with ttlv pkcs11"). The HSM features of stage 1 are carried over KMIP's TTLV encoding. SO administration is also available over KMIP ("1: SO admin over KMIP too").
3. **Stage 3, CACP two-board test:** two i.MX 95 boards running the HSM, exercising the stage 1 features through CACP/KMIP.
4. **Stage 4, FHE on the KV260 as the untrusted compute server.** It runs on the A53 CPU first, in the order TFHE-rs → OpenFHE → Lattigo → fhe.rs, then a network service, a Hub live demo and a Yocto recipe. Keys stay in the HSM on the i.MX 95 boards, reached via CACP/KMIP. The KV260 never holds a secret key; it is the plans' "untrusted cloud".
5. **Stage 5, Hub badges "validated with CACP"** for flows that pass stage 3/4 evidence.

**Security-officer administration (owner, 2026-10-03: "Board-local root, rest over KMIP (Recommended)").**
- Root and trust-anchor enrollment and admin-key enrollment stay local on each board.
- CRL, policy and rotation updates may go over KMIP, signed.
- The SO PIN lives in a root-only local file.
- Per-connection application contexts (C1) are approved.

This supersedes the earlier "SO admin over KMIP: Everything" answer.

**Stage 4 key path (owner, 2026-10-03: "Data owner only (Recommended)").** The KV260 returns encrypted results to the data owner, who asks its HSM. The KV260 never calls the HSM. FHE plan §6.3 rule 4 is unchanged.

**Hub and validation boards (owner, verbatim):** "hub will be only wasm - i want to validate the flows with pqctoday-sandbox + pqctoday-fhe with kv260 + pqctoday-cacp with mx95 and m95pro - in the future will also use the ventuno q".
- The Hub runs only the WASM emulator.
- Flows are validated by evidence from three producers:
  - pqctoday-sandbox (reference libraries);
  - pqctoday-fhe on the KV260 (untrusted compute);
  - pqctoday-cacp on the i.MX 95 and i.MX 95 Pro (HSM boards).
- Ventuno Q is a later board.
- Evidence is labelled "software token on <board>" until K6 hardware roots exist.

**Device topology for the validation runs (owner, 2026-10-03, relayed by session 0e).**
- The data owner runs on the Mac: pqctoday-sandbox on the M4 Pro.
- The FHE compute server is the KV260: pqctoday-fhe, untrusted compute, no token.
- The custodian is the software token on the i.MX 95 (pqctoday-cacp). The backup custodian is the i.MX 95 Pro.
- Threshold is tested as **2-of-2** on the two boards ("simply test 2 out of 2"). The Hub badge states "2-of-2 (scenario shows 3-of-3)".
- Each run produces one end-to-end evidence record, with per-device parts (Hub `fhe-evidence.v1`).

## Not changed

- The custody boundary stays as it is: the seed is non-extractable, and decryption goes through the §6.3 policy rules.
- Pure-PQC Category 3 (D15) is unchanged.
- The order of HSM plan phases K-1 to K6 is unchanged, and so is decision 9 (hardware after software, i.MX 95 first).
- No KMIP or CACP claim is made for stage 1 evidence.
