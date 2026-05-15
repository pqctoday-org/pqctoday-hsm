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

/* ===========================================================================
 *                            Keymgmt (phase 3a)
 * ===========================================================================
 *
 * A composite key is simply two P11PROV_OBJ pointers — one for the PQ
 * subkey, one for the traditional subkey — plus a profile pointer telling
 * us which composite OID this is. softhsm holds the actual key material
 * for each subkey; we just orchestrate.
 *
 * Application code (e.g. tls_simulation_hsm.c) builds a composite key
 * programmatically via p11prov_composite_obj_new_from_subkeys, then hands
 * it to OpenSSL via the load dispatch.
 * ========================================================================= */

struct p11prov_composite_obj {
    P11PROV_CTX *provctx;
    const struct p11prov_composite_profile *profile;
    P11PROV_OBJ *pq_obj;
    P11PROV_OBJ *classical_obj;
};

typedef struct p11prov_composite_obj P11PROV_COMPOSITE_OBJ;

/* Build a composite key from two pre-loaded softhsm objects.
 * Takes a reference on each subkey via p11prov_obj_ref; caller retains
 * its own references on input.
 * Returns NULL on alloc failure. */
P11PROV_COMPOSITE_OBJ *p11prov_composite_obj_new_from_subkeys(
    P11PROV_CTX *provctx,
    const struct p11prov_composite_profile *profile,
    P11PROV_OBJ *pq_obj,
    P11PROV_OBJ *classical_obj)
{
    P11PROV_COMPOSITE_OBJ *obj;

    if (provctx == NULL || profile == NULL || pq_obj == NULL
        || classical_obj == NULL) {
        return NULL;
    }

    obj = OPENSSL_zalloc(sizeof(*obj));
    if (obj == NULL) {
        return NULL;
    }
    obj->provctx = provctx;
    obj->profile = profile;
    obj->pq_obj = p11prov_obj_ref(pq_obj);
    obj->classical_obj = p11prov_obj_ref(classical_obj);
    if (obj->pq_obj == NULL || obj->classical_obj == NULL) {
        p11prov_obj_free(obj->pq_obj);
        p11prov_obj_free(obj->classical_obj);
        OPENSSL_free(obj);
        return NULL;
    }
    return obj;
}

/* OSSL_FUNC_KEYMGMT_NEW: empty key (no subkeys yet). The application
 * builds populated composite keys via p11prov_composite_obj_new_from_subkeys
 * and passes them via OSSL_FUNC_KEYMGMT_LOAD.
 * Per-profile newctx is just NEW with the matching profile pointer cached
 * in the caller. */
static void *p11prov_composite_keymgmt_new_impl(
    void *provctx,
    const struct p11prov_composite_profile *profile)
{
    P11PROV_COMPOSITE_OBJ *obj = OPENSSL_zalloc(sizeof(*obj));
    if (obj == NULL) {
        return NULL;
    }
    obj->provctx = (P11PROV_CTX *)provctx;
    obj->profile = profile;
    return obj;
}

static void p11prov_composite_keymgmt_free(void *keydata)
{
    P11PROV_COMPOSITE_OBJ *obj = (P11PROV_COMPOSITE_OBJ *)keydata;
    if (obj == NULL) {
        return;
    }
    p11prov_obj_free(obj->pq_obj);
    p11prov_obj_free(obj->classical_obj);
    OPENSSL_free(obj);
}

/* OSSL_FUNC_KEYMGMT_LOAD takes (reference, reference_sz) where the
 * reference is whatever the decoder produced. Our convention: the
 * reference IS a pointer to a P11PROV_COMPOSITE_OBJ built by
 * p11prov_composite_obj_new_from_subkeys. The keymgmt takes ownership. */
static void *p11prov_composite_keymgmt_load(const void *reference,
                                            size_t reference_sz)
{
    P11PROV_COMPOSITE_OBJ *obj;

    if (reference == NULL || reference_sz != sizeof(obj)) {
        return NULL;
    }
    obj = *(P11PROV_COMPOSITE_OBJ **)reference;
    /* OSSL_FUNC_KEYMGMT_LOAD semantics: ownership transfers to keymgmt */
    *(P11PROV_COMPOSITE_OBJ **)reference = NULL;
    return obj;
}

/* OSSL_FUNC_KEYMGMT_HAS: keypair selection requires both subkeys; public
 * selection requires both public keys present. softhsm publishes
 * CKA_VALUE_LEN for ML-DSA pubkeys and the EC point for ECDSA, so as long
 * as both objects exist, we report ready. */
static int p11prov_composite_keymgmt_has(const void *keydata, int selection)
{
    const P11PROV_COMPOSITE_OBJ *obj = (const P11PROV_COMPOSITE_OBJ *)keydata;
    if (obj == NULL) {
        return 0;
    }
    if (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                     | OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                     | OSSL_KEYMGMT_SELECT_KEYPAIR)) {
        if (obj->pq_obj == NULL || obj->classical_obj == NULL) {
            return 0;
        }
    }
    return 1;
}

/* OSSL_FUNC_KEYMGMT_MATCH: composite keys match when both their profiles
 * agree and both subkey handles are the same softhsm object. */
static int p11prov_composite_keymgmt_match(const void *keydata1,
                                           const void *keydata2,
                                           int selection)
{
    const P11PROV_COMPOSITE_OBJ *a = (const P11PROV_COMPOSITE_OBJ *)keydata1;
    const P11PROV_COMPOSITE_OBJ *b = (const P11PROV_COMPOSITE_OBJ *)keydata2;

    if (a == NULL || b == NULL) {
        return 0;
    }
    if (a->profile != b->profile) {
        return 0;
    }
    if (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                     | OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                     | OSSL_KEYMGMT_SELECT_KEYPAIR)) {
        if (a->pq_obj == NULL || b->pq_obj == NULL
            || a->classical_obj == NULL || b->classical_obj == NULL) {
            return 0;
        }
        if (p11prov_obj_get_handle(a->pq_obj)
                != p11prov_obj_get_handle(b->pq_obj)
            || p11prov_obj_get_handle(a->classical_obj)
                   != p11prov_obj_get_handle(b->classical_obj)) {
            return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM *
p11prov_composite_keymgmt_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END,
    };
    (void)provctx;
    return params;
}

static int p11prov_composite_keymgmt_get_params(void *keydata,
                                                OSSL_PARAM params[])
{
    const P11PROV_COMPOSITE_OBJ *obj = (const P11PROV_COMPOSITE_OBJ *)keydata;
    OSSL_PARAM *p;
    int sec_bits;
    int max_size;

    if (obj == NULL || obj->profile == NULL) {
        return 0;
    }
    switch (obj->profile->mldsa_param_set) {
    case CKP_ML_DSA_44:
        sec_bits = 128;
        break;
    case CKP_ML_DSA_65:
        sec_bits = 192;
        break;
    case CKP_ML_DSA_87:
        sec_bits = 256;
        break;
    default:
        return 0;
    }
    /* Max composite signature size: PQ sig + maximum reasonable classical sig.
     * RSA-2048-PSS = 256 bytes, ECDSA-P256 DER ≤ 72, ECDSA-P384 DER ≤ 104.
     * Pick a safe upper bound for each profile. */
    max_size = (int)obj->profile->mldsa_sig_bytes + 256;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, sec_bits)) {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, sec_bits * 2)) {
        return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, max_size)) {
        return 0;
    }
    return 1;
}

/* Per-profile newctx wrappers — these are what OSSL_FUNC_KEYMGMT_NEW
 * dispatches to. Each profile gets its own OSSL_DISPATCH array. */
#define DEFINE_COMPOSITE_KEYMGMT_NEW(suffix, idx) \
    static void *p11prov_composite_##suffix##_keymgmt_new(void *provctx) \
    { \
        return p11prov_composite_keymgmt_new_impl( \
            provctx, &p11prov_composite_profiles[idx]); \
    }

DEFINE_COMPOSITE_KEYMGMT_NEW(mldsa44_rsa2048_pss, 0)
DEFINE_COMPOSITE_KEYMGMT_NEW(mldsa65_ecdsa_p256, 1)
DEFINE_COMPOSITE_KEYMGMT_NEW(mldsa87_ecdsa_p384, 2)
#undef DEFINE_COMPOSITE_KEYMGMT_NEW

#define COMPOSITE_KEYMGMT_DISPATCH(suffix) \
    static const OSSL_DISPATCH \
        p11prov_composite_##suffix##_keymgmt_functions[] = { \
            { OSSL_FUNC_KEYMGMT_NEW, \
              (void (*)(void))p11prov_composite_##suffix##_keymgmt_new }, \
            { OSSL_FUNC_KEYMGMT_FREE, \
              (void (*)(void))p11prov_composite_keymgmt_free }, \
            { OSSL_FUNC_KEYMGMT_LOAD, \
              (void (*)(void))p11prov_composite_keymgmt_load }, \
            { OSSL_FUNC_KEYMGMT_HAS, \
              (void (*)(void))p11prov_composite_keymgmt_has }, \
            { OSSL_FUNC_KEYMGMT_MATCH, \
              (void (*)(void))p11prov_composite_keymgmt_match }, \
            { OSSL_FUNC_KEYMGMT_GET_PARAMS, \
              (void (*)(void))p11prov_composite_keymgmt_get_params }, \
            { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, \
              (void (*)(void))p11prov_composite_keymgmt_gettable_params }, \
            { 0, NULL }, \
        }

COMPOSITE_KEYMGMT_DISPATCH(mldsa44_rsa2048_pss);
COMPOSITE_KEYMGMT_DISPATCH(mldsa65_ecdsa_p256);
COMPOSITE_KEYMGMT_DISPATCH(mldsa87_ecdsa_p384);
#undef COMPOSITE_KEYMGMT_DISPATCH

/* External dispatch tables consumed by provider.c's ADD_ALGO_EXT block.
 * Naming follows the existing p11prov_<algo>_keymgmt_functions convention. */
const OSSL_DISPATCH *
p11prov_composite_mldsa44_rsa2048_pss_keymgmt_dispatch(void)
{
    return p11prov_composite_mldsa44_rsa2048_pss_keymgmt_functions;
}
const OSSL_DISPATCH *
p11prov_composite_mldsa65_ecdsa_p256_keymgmt_dispatch(void)
{
    return p11prov_composite_mldsa65_ecdsa_p256_keymgmt_functions;
}
const OSSL_DISPATCH *
p11prov_composite_mldsa87_ecdsa_p384_keymgmt_dispatch(void)
{
    return p11prov_composite_mldsa87_ecdsa_p384_keymgmt_functions;
}

/* ===========================================================================
 * Signature dispatch (phase 3b) — to land in a follow-up commit.
 *
 * The signature CTX will hold two underlying P11PROV_SIG_CTXs (one per
 * subkey) plus an accumulating TBS buffer. At digest_sign_final time,
 * compute M' via p11prov_composite_build_mprime, call p11prov_sig_operate
 * on each underlying sigctx with M' as input, and concatenate the outputs.
 *
 * Per-profile underlying mechanisms:
 *   MLDSA44+RSA2048-PSS-SHA256:  CKM_ML_DSA (ctx=Label) + CKM_SHA256_RSA_PKCS_PSS
 *   MLDSA65+ECDSA-P256-SHA512:   CKM_ML_DSA (ctx=Label) + CKM_ECDSA_SHA512
 *   MLDSA87+ECDSA-P384-SHA512:   CKM_ML_DSA (ctx=Label) + CKM_ECDSA_SHA512
 *
 * The CKM_ML_DSA mechanism takes a CK_ML_DSA_PARAMS in pParameter with
 * context=profile->signature_label, contextLen=strlen(signature_label).
 * softhsm's OSSLMLDSA.cpp:339-344 reads this and forwards via
 * OSSL_SIGNATURE_PARAM_CONTEXT_STRING to OpenSSL's EVP_DigestSign.
 * ========================================================================= */
