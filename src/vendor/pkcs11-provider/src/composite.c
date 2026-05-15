/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* ---------------------------------------------------------------------------
 * LAMPS composite-sig support for pqctoday's pkcs11-provider.
 *
 * Implements the orchestration layer for draft-ietf-lamps-pq-composite-sigs-19:
 * a composite signature is two underlying signatures over the same message
 * representative M', where:
 *
 *   M' = Prefix || Label || len(ctx) || ctx || PH(M)
 *
 *   mldsaSig    = ML-DSA.Sign(skPQ, M', mldsa_ctx=Label)
 *   classicalSig = Trad.Sign(skClassical, M')
 *
 *   output bytes = mldsaSig || classicalSig
 *
 * Both halves are softhsm-resident: the composite "key" is two pkcs11: URIs
 * referencing two separate PKCS#11 objects. softhsm has no composite
 * mechanism and doesn't need one — composite-ness lives entirely here.
 *
 * Profiles implemented (draft-19 §6):
 *   - id-MLDSA44-RSA2048-PSS-SHA256  (OID 1.3.6.1.5.5.7.6.37)
 *   - id-MLDSA65-ECDSA-P256-SHA512   (OID 1.3.6.1.5.5.7.6.45)
 *   - id-MLDSA87-ECDSA-P384-SHA512   (OID 1.3.6.1.5.5.7.6.49)
 *
 * Status: phase 2 of pqctoday-org/pqctoday-hsm#59 — M' helper and profile
 * registry are real / standards-compliant. keymgmt / decoder / signature
 * dispatch entries are scaffolded for phase 3.
 *
 * ML-DSA context wiring: softhsm already supports the FIPS 204 context
 * parameter via PKCS#11 v3.2 CK_ML_DSA_PARAMS.context (see
 * src/lib/crypto/OSSLMLDSA.cpp:339-344). The composite signer just sets
 * params.context = profile->signature_label, params.contextLen = strlen(...)
 * before calling existing p11prov_sign_pkcs11.
 * ------------------------------------------------------------------------- */

#include "provider.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

/* Fixed Prefix per draft-19 §2.2: ASCII "CompositeAlgorithmSignatures2025" */
static const unsigned char COMPOSITE_PREFIX[] = "CompositeAlgorithmSignatures2025";
#define COMPOSITE_PREFIX_LEN (sizeof(COMPOSITE_PREFIX) - 1) /* 32, strip NUL */

/* ML-DSA fixed signature lengths per FIPS 204 Table 1 / draft-19 §4.3 */
#define MLDSA_44_SIG_BYTES 2420
#define MLDSA_65_SIG_BYTES 3309
#define MLDSA_87_SIG_BYTES 4627

/* ML-DSA fixed public key lengths per FIPS 204 Table 1 */
#define MLDSA_44_PK_BYTES 1312
#define MLDSA_65_PK_BYTES 1952
#define MLDSA_87_PK_BYTES 2592

struct p11prov_composite_profile {
    /* Composite OID string, e.g. "1.3.6.1.5.5.7.6.45" */
    const char *composite_oid;
    /* Human-readable identifier per draft-19 §6, e.g. "id-MLDSA65-ECDSA-P256-SHA512" */
    const char *label;
    /* Signature label used in M' and as ML-DSA mldsa_ctx parameter
     * per draft-19 §2.2 / §3.2, e.g. "COMPSIG-MLDSA65-ECDSA-P256-SHA512" */
    const char *signature_label;
    /* Pre-hash function: NID_sha256 or NID_sha512 (see draft-19 §6) */
    int pre_hash_nid;
    /* PKCS#11 parameter set for the ML-DSA half */
    CK_ULONG mldsa_param_set;
    /* Fixed ML-DSA signature length used to split the composite signature
     * on the verify side per draft-19 §4.3 deserialization */
    size_t mldsa_sig_bytes;
    /* Fixed ML-DSA public-key length used to split the composite SPKI bytes */
    size_t mldsa_pk_bytes;
    /* OID of the classical signature algorithm to invoke at the EVP layer
     * (e.g. RSA-PSS, ECDSA-with-SHA512). Empty for Ed25519/Ed448 where the
     * AlgorithmIdentifier embeds the hash. */
    const char *classical_alg_oid;
};

static const struct p11prov_composite_profile p11prov_composite_profiles[] = {
    {
        .composite_oid = "1.3.6.1.5.5.7.6.37",
        .label = "id-MLDSA44-RSA2048-PSS-SHA256",
        .signature_label = "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
        .pre_hash_nid = NID_sha256,
        .mldsa_param_set = CKP_ML_DSA_44,
        .mldsa_sig_bytes = MLDSA_44_SIG_BYTES,
        .mldsa_pk_bytes = MLDSA_44_PK_BYTES,
        .classical_alg_oid = "1.2.840.113549.1.1.10", /* id-RSASSA-PSS */
    },
    {
        .composite_oid = "1.3.6.1.5.5.7.6.45",
        .label = "id-MLDSA65-ECDSA-P256-SHA512",
        .signature_label = "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
        .pre_hash_nid = NID_sha512,
        .mldsa_param_set = CKP_ML_DSA_65,
        .mldsa_sig_bytes = MLDSA_65_SIG_BYTES,
        .mldsa_pk_bytes = MLDSA_65_PK_BYTES,
        .classical_alg_oid = "1.2.840.10045.4.3.4", /* ecdsa-with-SHA512 */
    },
    {
        .composite_oid = "1.3.6.1.5.5.7.6.49",
        .label = "id-MLDSA87-ECDSA-P384-SHA512",
        .signature_label = "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
        .pre_hash_nid = NID_sha512,
        .mldsa_param_set = CKP_ML_DSA_87,
        .mldsa_sig_bytes = MLDSA_87_SIG_BYTES,
        .mldsa_pk_bytes = MLDSA_87_PK_BYTES,
        .classical_alg_oid = "1.2.840.10045.4.3.4", /* ecdsa-with-SHA512 */
    },
};

#define P11PROV_COMPOSITE_PROFILE_COUNT \
    (sizeof(p11prov_composite_profiles) / sizeof(p11prov_composite_profiles[0]))

/* Look up a composite profile by its OID string.
 * Returns NULL when no matching profile is registered. */
const struct p11prov_composite_profile *
p11prov_composite_profile_by_oid(const char *oid)
{
    if (oid == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < P11PROV_COMPOSITE_PROFILE_COUNT; i++) {
        if (strcmp(p11prov_composite_profiles[i].composite_oid, oid) == 0) {
            return &p11prov_composite_profiles[i];
        }
    }
    return NULL;
}

/* Compute the message representative M' per draft-19 §2.2:
 *
 *   M' = Prefix || Label || len(ctx) || ctx || PH(M)
 *
 * `msg`     — the to-be-signed message (TBS for a cert, transcript hash for TLS)
 * `msg_len` — length of `msg`
 * `ctx`     — application context bytes (may be NULL when ctx_len == 0)
 * `ctx_len` — length of ctx; MUST be ≤ 255 per draft-19 §2.2-3.5
 * `out`     — caller-allocated output buffer of at least
 *             COMPOSITE_PREFIX_LEN + strlen(label) + 1 + ctx_len + PH_size bytes
 * `out_sz`  — capacity of `out`; updated to actual M' length on success
 *
 * Returns 1 on success, 0 on failure (with `out_sz` undefined on failure).
 *
 * This function is the foundation that the composite signature dispatch and
 * verify dispatch share. It contains no crypto state — only the standard's
 * concatenation and pre-hash steps. Test coverage on the pqctoday-hub side
 * (certBuilder.test.ts) verifies byte-correctness against draft-19 Appendix D
 * worked examples; this C implementation must produce identical bytes.
 */
int p11prov_composite_build_mprime(
    const struct p11prov_composite_profile *profile,
    const unsigned char *msg, size_t msg_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char *out, size_t *out_sz)
{
    if (profile == NULL || msg == NULL || out == NULL || out_sz == NULL) {
        return 0;
    }
    if (ctx_len > 255) {
        /* draft-19 §2.2: len(ctx) is a single unsigned byte */
        return 0;
    }
    if (ctx_len > 0 && ctx == NULL) {
        return 0;
    }

    const EVP_MD *md = EVP_get_digestbynid(profile->pre_hash_nid);
    if (md == NULL) {
        return 0;
    }
    const size_t ph_size = (size_t)EVP_MD_get_size(md);
    const size_t label_len = strlen(profile->signature_label);
    const size_t needed = COMPOSITE_PREFIX_LEN + label_len + 1 + ctx_len + ph_size;
    if (*out_sz < needed) {
        return 0;
    }

    /* Compute PH(M) into the tail position of the output buffer */
    unsigned int ph_out_len = 0;
    unsigned char *ph_dst = out + COMPOSITE_PREFIX_LEN + label_len + 1 + ctx_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return 0;
    }
    int ok = EVP_DigestInit_ex(mdctx, md, NULL)
             && EVP_DigestUpdate(mdctx, msg, msg_len)
             && EVP_DigestFinal_ex(mdctx, ph_dst, &ph_out_len);
    EVP_MD_CTX_free(mdctx);
    if (!ok || (size_t)ph_out_len != ph_size) {
        return 0;
    }

    /* Lay down Prefix || Label || len(ctx) || ctx in front of PH(M) */
    size_t off = 0;
    memcpy(out + off, COMPOSITE_PREFIX, COMPOSITE_PREFIX_LEN);
    off += COMPOSITE_PREFIX_LEN;
    memcpy(out + off, profile->signature_label, label_len);
    off += label_len;
    out[off++] = (unsigned char)ctx_len;
    if (ctx_len > 0) {
        memcpy(out + off, ctx, ctx_len);
        off += ctx_len;
    }
    /* PH already written at off..off+ph_size by EVP_DigestFinal_ex */

    *out_sz = needed;
    return 1;
}

/* ---------------------------------------------------------------------------
 * Phase 3 of #59 — to be implemented in a follow-up commit. The functions
 * below are intentionally NOT YET wired into provider.c's dispatch tables;
 * adding them prematurely could cause OpenSSL to attempt loads/signs that
 * fail at runtime. The skeleton is here for design review; the actual code
 * lands when the integration tests in pqctoday-hub are ready to exercise
 * the full handshake path.
 *
 * Implementation plan:
 *
 *   p11prov_composite_decoder_*
 *     Accept a custom PEM block:
 *       -----BEGIN PQCTODAY COMPOSITE KEY-----
 *       profile: <signature_label>
 *       pq:        <pkcs11: URI>
 *       classical: <pkcs11: URI>
 *       -----END PQCTODAY COMPOSITE KEY-----
 *     Parse the two URIs, load each subkey via existing p11prov store/load
 *     paths, return a composite key handle holding both.
 *
 *   p11prov_composite_keymgmt_*
 *     Hold two P11PROV_OBJ pointers (pq_key, classical_key).
 *     free() releases both via existing p11prov_obj_free.
 *     has() returns SELECT_KEYPAIR when both are present.
 *     match() compares by composite OID + both subkey URIs.
 *
 *   p11prov_composite_sign_*
 *     digest_sign_init: stash TBS bytes
 *     digest_sign_final:
 *       1. Compute M' via p11prov_composite_build_mprime
 *       2. Set CK_ML_DSA_PARAMS.context = profile->signature_label,
 *          contextLen = strlen(signature_label)
 *       3. Call existing p11prov_sign_pkcs11(pq_key, &mldsa_mech, M') →
 *          softhsm C_Sign(CKM_ML_DSA) with context parameter
 *       4. Call existing p11prov_sign_pkcs11(classical_key, &classical_mech, M') →
 *          softhsm C_Sign(CKM_ECDSA / CKM_RSA_PKCS_PSS) without context
 *       5. Concatenate: out = mldsaSig || classicalSig (raw, no SEQUENCE)
 *
 *   p11prov_composite_verify_*
 *     Reverse of sign: split input at profile->mldsa_sig_bytes, verify each
 *     half via existing p11prov_verify_pkcs11, AND combine per draft-19 §3.3
 *     (must succeed only when BOTH halves verify).
 *
 *   p11prov_composite_<oid>_keymgmt_functions[] / signature_functions[] /
 *   decoder_functions[]
 *     One OSSL_DISPATCH array per composite OID, registered in provider.c's
 *     ADD_ALGO_EXT block (line 1486-1488 pattern).
 *
 * Until phase 3 lands, the provider continues to advertise the composite
 * sigalgs via tls.c (commit 59a2c26) but no composite key can be loaded
 * yet, so OpenSSL will never select these sigalgs in practice — they
 * appear in `openssl list` output only.
 * ------------------------------------------------------------------------- */
