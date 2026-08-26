// SPDX-License-Identifier: GPL-3.0-only
//
// vendor_mechanisms.h — Vendor-defined PKCS#11 mechanism and attribute constants
//
// These values are in the vendor range (0x80000000–0xFFFFFFFF) and extend
// PKCS#11 v3.2 with mechanisms that are not (yet) in the standard.
//
// Rust side: mirrored in rust/src/constants.rs
// TypeScript side: mirrored in the pqctoday-hub repo
// (src/wasm/softhsm/constants.ts THERE — that path does not exist in this
// repo; this repo's JS surface is constants.js at the repo root)

#pragma once

#include "pkcs11/pkcs11t.h"

// ── Vendor: Keccak-256 (G11 — Ethereum address derivation) ───────────────────
// Rust engine only. The C++ OpenSSL engine returns CKR_MECHANISM_INVALID for this.

#define CKM_KECCAK_256         0x80000010UL  /* vendor */

// ── Vendor: Split Key secret sharing (G12 — KMIP 3.0 §6.1.12/§6.1.31, §13.1) ─
// Rust engine only (KMIP server backend). PKCS#11 v3.2 has no mechanism for
// this at all — verified directly against the spec text, not a gap-fill.
// Covers all four §11.54 Split Key Method values (XOR / Prime Field /
// GF(2^16) / GF(2^8)); the method + parameters travel in the mechanism's
// native argument, not separate mechanism codepoints.

#define CKM_PQCTODAY_SPLIT_KEY 0x80000012UL  /* vendor */

// ── Vendor: ML-DSA external-µ signing (remediation R34, 2026-08-26) ─────────
// Stopgap for PKCS#11 v3.3's own upcoming external-µ mechanism —
// oasis-tcs/pkcs11#58, not yet ratified. See
// docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md for the
// full design rationale (why this preserves pure ML-DSA's security
// assumptions, why a vendor stopgap is industry-precedented).
//
// No new parameter struct: this mechanism reuses CK_SIGN_ADDITIONAL_CONTEXT
// verbatim (only hedgeVariant is meaningful; pContext/ulContextLen must be
// empty — context has no defined meaning once µ already exists, FIPS 204
// folds it in before the caller ever computes µ). The caller's 64-byte µ
// travels via the normal C_Sign/C_Verify data argument, exactly like
// CKM_HASH_ML_DSA's PHM and every other mechanism here — not embedded in
// the mechanism parameter.
//
// PQCTODAY-VENDOR-EXT-MU: remove this whole block, both engines' dispatch
// arms, and the provider's routing when this project adopts PKCS#11 v3.3
// natively. Search this exact tag project-wide to find every site.

#define CKM_PQCTODAY_ML_DSA_MU 0x80000013UL  /* vendor */

#define PQCTODAY_ML_DSA_MU_LEN 64  /* FIPS 204 Eq.(2): SHAKE256 output, fixed */

// ── Vendor: stateful key attributes ──────────────────────────────────────────
// Range: 0x80000101–0x80000105 (offset from CKM vendor range to avoid confusion)

#define CKA_STATEFUL_KEY_STATE 0x80000101UL  /* raw serialised private key blob */
#define CKA_LMS_PARAM_SET      0x80000102UL  /* CKP_LMS_SHA256_M32_H* value */
#define CKA_LMOTS_PARAM_SET    0x80000103UL  /* CKP_LMOTS_SHA256_N32_W* value */
#define CKA_XMSS_PARAM_SET     0x80000104UL  /* CKP_XMSS_* value */
#define CKA_LEAF_INDEX         0x80000105UL  /* current leaf index (CK_ULONG) */

// ── LMS parameter set values (IANA registry, RFC 8554 + SP 800-208) ─────────
// Used in CKA_LMS_PARAM_SET and CK_HSS_KEY_PAIR_GEN_PARAMS.ulLmsParamSet[].
// Values are the IANA "Leighton-Micali Signatures" type IDs.

#define CKP_LMS_SHA256_M32_H5   0x00000005UL
#define CKP_LMS_SHA256_M32_H10  0x00000006UL
#define CKP_LMS_SHA256_M32_H15  0x00000007UL
#define CKP_LMS_SHA256_M32_H20  0x00000008UL
#define CKP_LMS_SHA256_M32_H25  0x00000009UL
/* SP 800-208 §4 — SHA-256 with 24-byte (192-bit) truncated output */
#define CKP_LMS_SHA256_M24_H5   0x0000000AUL
#define CKP_LMS_SHA256_M24_H10  0x0000000BUL
#define CKP_LMS_SHA256_M24_H15  0x0000000CUL
#define CKP_LMS_SHA256_M24_H20  0x0000000DUL
#define CKP_LMS_SHA256_M24_H25  0x0000000EUL
/* SP 800-208 §4 — SHAKE-256 with 32-byte output */
#define CKP_LMS_SHAKE_M32_H5    0x0000000FUL
#define CKP_LMS_SHAKE_M32_H10   0x00000010UL
#define CKP_LMS_SHAKE_M32_H15   0x00000011UL
#define CKP_LMS_SHAKE_M32_H20   0x00000012UL
#define CKP_LMS_SHAKE_M32_H25   0x00000013UL
/* SP 800-208 §4 — SHAKE-256 with 24-byte output */
#define CKP_LMS_SHAKE_M24_H5    0x00000014UL
#define CKP_LMS_SHAKE_M24_H10   0x00000015UL
#define CKP_LMS_SHAKE_M24_H15   0x00000016UL
#define CKP_LMS_SHAKE_M24_H20   0x00000017UL
#define CKP_LMS_SHAKE_M24_H25   0x00000018UL

// ── LMOTS parameter set values (IANA registry, RFC 8554 + SP 800-208) ───────
// Used in CKA_LMOTS_PARAM_SET and CK_HSS_KEY_PAIR_GEN_PARAMS.ulLmotsParamSet[].

#define CKP_LMOTS_SHA256_N32_W1  0x00000001UL
#define CKP_LMOTS_SHA256_N32_W2  0x00000002UL
#define CKP_LMOTS_SHA256_N32_W4  0x00000003UL
#define CKP_LMOTS_SHA256_N32_W8  0x00000004UL
/* SP 800-208 §4 — SHA-256 N24 */
#define CKP_LMOTS_SHA256_N24_W1  0x00000005UL
#define CKP_LMOTS_SHA256_N24_W2  0x00000006UL
#define CKP_LMOTS_SHA256_N24_W4  0x00000007UL
#define CKP_LMOTS_SHA256_N24_W8  0x00000008UL
/* SP 800-208 §4 — SHAKE-256 N32 */
#define CKP_LMOTS_SHAKE_N32_W1   0x00000009UL
#define CKP_LMOTS_SHAKE_N32_W2   0x0000000AUL
#define CKP_LMOTS_SHAKE_N32_W4   0x0000000BUL
#define CKP_LMOTS_SHAKE_N32_W8   0x0000000CUL
/* SP 800-208 §4 — SHAKE-256 N24 */
#define CKP_LMOTS_SHAKE_N24_W1   0x0000000DUL
#define CKP_LMOTS_SHAKE_N24_W2   0x0000000EUL
#define CKP_LMOTS_SHAKE_N24_W4   0x0000000FUL
#define CKP_LMOTS_SHAKE_N24_W8   0x00000010UL

// ── Standard PKCS#11 v3.2 §6.65 (HSS) / §6.66 (XMSS) mechanisms ────────────────────

#define CKM_HSS_KEY_PAIR_GEN   0x00004032UL
#define CKM_HSS                0x00004033UL
#define CKM_XMSS_KEY_PAIR_GEN  0x00004034UL
#define CKM_XMSS               0x00004036UL

#define CKK_HSS                0x00000046UL
#define CKK_XMSS               0x00000047UL
#define CKK_XMSSMT             0x00000048UL

// Standard CKR extension
#define CKR_KEY_EXHAUSTED      0x00000203UL  /* PKCS#11 v3.2 §5.1 error code */

// ── HSS key generation parameters (CKM_HSS_KEY_PAIR_GEN mechanism parameter) ─

#define HSS_MAX_LEVELS 8

typedef struct CK_HSS_KEY_PAIR_GEN_PARAMS {
    CK_ULONG ulLevels;
    CK_ULONG ulLmsParamSet[HSS_MAX_LEVELS];
    CK_ULONG ulLmotsParamSet[HSS_MAX_LEVELS];
} CK_HSS_KEY_PAIR_GEN_PARAMS;

typedef CK_HSS_KEY_PAIR_GEN_PARAMS CK_PTR CK_HSS_KEY_PAIR_GEN_PARAMS_PTR;
