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
#include "sig/signature.h"
#include "sig/internal.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
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

/* OpenSSL-side handshake for handing an already-built composite key to
 * EVP_PKEY_fromdata. Caller passes the P11PROV_COMPOSITE_OBJ pointer
 * (returned by p11prov_composite_obj_new_from_subkeys) inside an
 * OSSL_PARAM_OCTET_STRING with this name. The IMPORT dispatch consumes
 * the reference (transfers ownership into the keydata) and the resulting
 * EVP_PKEY can be passed to SSL_CTX_use_PrivateKey.
 *
 * The param name is namespaced under "pqctoday" so it never collides
 * with stock OpenSSL OSSL_PARAM names. */
#define P11PROV_COMPOSITE_PARAM_REFERENCE "pqctoday-composite-ref"

static const OSSL_PARAM *
p11prov_composite_keymgmt_import_types(int selection)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(P11PROV_COMPOSITE_PARAM_REFERENCE, NULL, 0),
        OSSL_PARAM_END,
    };
    (void)selection;
    return params;
}

static int p11prov_composite_keymgmt_import(void *keydata, int selection,
                                            const OSSL_PARAM params[])
{
    P11PROV_COMPOSITE_OBJ *dst = (P11PROV_COMPOSITE_OBJ *)keydata;
    const OSSL_PARAM *p;
    P11PROV_COMPOSITE_OBJ *src;
    size_t reflen;
    (void)selection;

    if (dst == NULL || params == NULL) {
        return RET_OSSL_ERR;
    }
    p = OSSL_PARAM_locate_const(params, P11PROV_COMPOSITE_PARAM_REFERENCE);
    if (p == NULL) {
        return RET_OSSL_ERR;
    }
    if (p->data_type != OSSL_PARAM_OCTET_STRING
        || p->data_size != sizeof(src)) {
        return RET_OSSL_ERR;
    }
    /* Caller stored a pointer-sized blob holding our pointer. */
    memcpy(&src, p->data, sizeof(src));
    reflen = p->data_size;
    (void)reflen;
    if (src == NULL || src->profile == NULL || src->pq_obj == NULL
        || src->classical_obj == NULL) {
        return RET_OSSL_ERR;
    }
    /* The dst was created with the per-profile NEW that cached the profile.
     * Confirm both sides agree before stealing the subkey refs. */
    if (dst->profile != src->profile) {
        return RET_OSSL_ERR;
    }
    /* Take ownership of the subkey refs. src is freed (without freeing the
     * refs we just stole). */
    if (dst->pq_obj != NULL) {
        p11prov_obj_free(dst->pq_obj);
    }
    if (dst->classical_obj != NULL) {
        p11prov_obj_free(dst->classical_obj);
    }
    dst->pq_obj = src->pq_obj;
    dst->classical_obj = src->classical_obj;
    src->pq_obj = NULL;
    src->classical_obj = NULL;
    OPENSSL_free(src);
    return RET_OSSL_OK;
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
    const OSSL_DISPATCH \
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
            { OSSL_FUNC_KEYMGMT_IMPORT, \
              (void (*)(void))p11prov_composite_keymgmt_import }, \
            { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, \
              (void (*)(void))p11prov_composite_keymgmt_import_types }, \
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
 *                       Signature dispatch (phase 3b)
 * ===========================================================================
 *
 * A composite signature operation maintains two underlying P11PROV_SIG_CTX
 * instances — one for the PQ half, one for the classical half — plus an
 * accumulating buffer for the to-be-signed message. At digest_sign_final /
 * digest_verify_final time, the orchestration:
 *
 *   1. Computes M' = Prefix || Label || len(ctx) || ctx || PH(accumulated_M)
 *      via p11prov_composite_build_mprime.
 *   2. Calls p11prov_sig_operate on each underlying sigctx with M' as the
 *      input. The ML-DSA sub-sigctx carries mldsa_params.pContext = Label
 *      (per draft-19 §3.2 mldsa_ctx=Label); the mldsa.c set_mechanism patch
 *      forwards this through to CK_MECHANISM.pParameter so softhsm sees it.
 *   3. Concatenates `mldsaSig || classicalSig` (draft-19 §4.3).
 *
 * Per-profile underlying mechanisms:
 *   MLDSA44+RSA2048-PSS-SHA256:  CKM_ML_DSA (ctx=Label) + CKM_SHA256_RSA_PKCS_PSS
 *   MLDSA65+ECDSA-P256-SHA512:   CKM_ML_DSA (ctx=Label) + CKM_ECDSA_SHA512
 *   MLDSA87+ECDSA-P384-SHA512:   CKM_ML_DSA (ctx=Label) + CKM_ECDSA_SHA512
 *
 * RSA-PSS-SHA256 takes a CK_RSA_PKCS_PSS_PARAMS in mechanism.pParameter
 * specifying the hash, MGF, and salt length (32 bytes per draft-19 §6).
 * ========================================================================= */

#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

struct p11prov_composite_sig_ctx {
    P11PROV_CTX *provctx;
    const struct p11prov_composite_profile *profile;
    CK_FLAGS operation; /* CKF_SIGN or CKF_VERIFY */

    /* The composite key currently bound to this operation. We don't ref-bump
     * it — sub-sigctxs hold their own refs on the individual subkeys via
     * p11prov_sig_op_init -> p11prov_obj_ref. */
    P11PROV_COMPOSITE_OBJ *composite_key;

    /* Two underlying sigctxs, one per component. Lazily allocated in
     * digest_sign_init / digest_verify_init. */
    P11PROV_SIG_CTX *pq_sigctx;
    P11PROV_SIG_CTX *classical_sigctx;

    /* RSA-PSS mechanism parameters live inside the ctx so the pointer
     * given to the token outlives C_SignInit. Used only for RSA-PSS
     * profiles; left zeroed for ECDSA/EdDSA profiles. */
    CK_RSA_PKCS_PSS_PARAMS classical_pss_params;

    /* Accumulating buffer for digest_sign_update / digest_verify_update.
     * The composite spec doesn't externalize the pre-hash, so we have
     * to keep the full message until digest_*_final. For TLS handshake
     * sizes this is well under 16 KB. */
    unsigned char *tbs_buf;
    size_t tbs_buf_len;
    size_t tbs_buf_cap;

    /* Application context (draft-19 §2.2 ctx parameter). Default empty.
     * MUST be ≤ 255 bytes (single-byte length encoding). */
    unsigned char *app_ctx;
    size_t app_ctx_len;
};

typedef struct p11prov_composite_sig_ctx P11PROV_COMPOSITE_SIG_CTX;

/* Per-profile newctx wrappers — one per OSSL_DISPATCH array. */
static void *p11prov_composite_sig_newctx_impl(
    void *provctx,
    const struct p11prov_composite_profile *profile)
{
    P11PROV_COMPOSITE_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)provctx;
    ctx->profile = profile;
    return ctx;
}

static void p11prov_composite_sig_freectx(void *vctx)
{
    P11PROV_COMPOSITE_SIG_CTX *ctx = (P11PROV_COMPOSITE_SIG_CTX *)vctx;
    if (ctx == NULL) {
        return;
    }
    /* p11prov_sig_freectx releases the per-sub-sigctx mldsa_params.pContext
     * heap (via OPENSSL_clear_free in signature.c lines 228-229), the key
     * ref, and the sigctx struct itself. */
    p11prov_sig_freectx(ctx->pq_sigctx);
    p11prov_sig_freectx(ctx->classical_sigctx);
    OPENSSL_clear_free(ctx->tbs_buf, ctx->tbs_buf_cap);
    OPENSSL_clear_free(ctx->app_ctx, ctx->app_ctx_len);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* Configure the ML-DSA sub-sigctx for this profile: paramset, ctx=Label, and
 * the mechanism (set up directly so we don't depend on mldsa.c's static
 * set_mechanism wrapper firing). Returns 1 on success, 0 on failure. */
static int composite_setup_pq_sigctx(P11PROV_COMPOSITE_SIG_CTX *ctx)
{
    P11PROV_SIG_CTX *sc = ctx->pq_sigctx;
    const size_t label_len = strlen(ctx->profile->signature_label);

    sc->mldsa_paramset = ctx->profile->mldsa_param_set;

    /* OPENSSL_memdup so this lifetime is independent of the profile table
     * (read-only string literal). p11prov_sig_freectx will OPENSSL_clear_free
     * it via signature.c:228-229. */
    sc->mldsa_params.pContext = OPENSSL_memdup(
        ctx->profile->signature_label, label_len);
    if (sc->mldsa_params.pContext == NULL) {
        return 0;
    }
    sc->mldsa_params.ulContextLen = label_len;
    sc->mldsa_params.hedgeVariant = CKH_HEDGE_PREFERRED;

    /* Configure the mechanism directly (CKM_ML_DSA + the params we just
     * populated). The mldsa.c patch (commit 9cc52e6) does the same check
     * but applies only when its own set_mechanism wrapper is called; we
     * set the mechanism here so it's ready for p11prov_sig_operate's
     * direct C_SignInit. */
    sc->mechanism.mechanism = CKM_ML_DSA;
    sc->mechanism.pParameter = &sc->mldsa_params;
    sc->mechanism.ulParameterLen = sizeof(sc->mldsa_params);
    return 1;
}

/* Configure the classical sub-sigctx for this profile. */
static int composite_setup_classical_sigctx(P11PROV_COMPOSITE_SIG_CTX *ctx)
{
    P11PROV_SIG_CTX *sc = ctx->classical_sigctx;
    CK_MECHANISM_TYPE classical_mech;

    /* Profile → underlying CKM_* mechanism. The HSM-side hash makes M' →
     * digest → sign atomic, so we pass M' as raw input. */
    if (ctx->profile->pre_hash_nid == NID_sha512
        && ctx->profile->mldsa_param_set == CKP_ML_DSA_65) {
        classical_mech = CKM_ECDSA_SHA512; /* MLDSA65+ECDSA-P256-SHA512 */
    } else if (ctx->profile->pre_hash_nid == NID_sha512
               && ctx->profile->mldsa_param_set == CKP_ML_DSA_87) {
        classical_mech = CKM_ECDSA_SHA512; /* MLDSA87+ECDSA-P384-SHA512 */
    } else if (ctx->profile->pre_hash_nid == NID_sha256
               && ctx->profile->mldsa_param_set == CKP_ML_DSA_44) {
        classical_mech = CKM_SHA256_RSA_PKCS_PSS; /* MLDSA44+RSA2048-PSS-SHA256 */
    } else {
        return 0; /* unknown profile combination */
    }

    sc->mechanism.mechanism = classical_mech;

    if (classical_mech == CKM_SHA256_RSA_PKCS_PSS) {
        /* draft-19 §6 specifies RSASSA-PSS with SHA-256, MGF1-SHA-256,
         * salt length = 32 bytes (= hash output). */
        ctx->classical_pss_params.hashAlg = CKM_SHA256;
        ctx->classical_pss_params.mgf = CKG_MGF1_SHA256;
        ctx->classical_pss_params.sLen = 32;
        sc->mechanism.pParameter = &ctx->classical_pss_params;
        sc->mechanism.ulParameterLen = sizeof(ctx->classical_pss_params);
    } else {
        sc->mechanism.pParameter = NULL;
        sc->mechanism.ulParameterLen = 0;
    }
    return 1;
}

/* Common init for digest_sign and digest_verify. operation = CKF_SIGN
 * or CKF_VERIFY. */
static int composite_digest_op_init(
    void *vctx, void *keydata, const OSSL_PARAM params[], CK_FLAGS operation)
{
    P11PROV_COMPOSITE_SIG_CTX *ctx = (P11PROV_COMPOSITE_SIG_CTX *)vctx;
    P11PROV_COMPOSITE_OBJ *key = (P11PROV_COMPOSITE_OBJ *)keydata;
    CK_RV rv;

    if (ctx == NULL || key == NULL) {
        return RET_OSSL_ERR;
    }
    if (key->profile != ctx->profile) {
        /* The composite key's profile MUST match the dispatch's profile —
         * otherwise OpenSSL has wired up the wrong dispatch. */
        return RET_OSSL_ERR;
    }
    if (key->pq_obj == NULL || key->classical_obj == NULL) {
        return RET_OSSL_ERR;
    }

    ctx->operation = operation;
    ctx->composite_key = key;

    /* Allocate PQ sub-sigctx */
    ctx->pq_sigctx = p11prov_sig_newctx(ctx->provctx, CKM_ML_DSA, NULL);
    if (ctx->pq_sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (!composite_setup_pq_sigctx(ctx)) {
        return RET_OSSL_ERR;
    }
    rv = p11prov_sig_op_init(ctx->pq_sigctx, key->pq_obj, operation, NULL);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    /* Allocate classical sub-sigctx. mechtype passed to p11prov_sig_newctx
     * is the family — set to actual mech via composite_setup_classical_sigctx. */
    ctx->classical_sigctx = p11prov_sig_newctx(
        ctx->provctx,
        ctx->profile->pre_hash_nid == NID_sha256 ? CKM_RSA_PKCS_PSS : CKM_ECDSA,
        NULL);
    if (ctx->classical_sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (!composite_setup_classical_sigctx(ctx)) {
        return RET_OSSL_ERR;
    }
    rv = p11prov_sig_op_init(ctx->classical_sigctx, key->classical_obj,
                             operation, NULL);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    /* Apply OpenSSL-side params (e.g. context-string for the composite
     * application ctx) if provided. */
    if (params != NULL) {
        const OSSL_PARAM *p =
            OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
        if (p != NULL) {
            size_t datalen;
            OPENSSL_clear_free(ctx->app_ctx, ctx->app_ctx_len);
            ctx->app_ctx = NULL;
            ctx->app_ctx_len = 0;
            if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->app_ctx, 0,
                                             &datalen)) {
                return RET_OSSL_ERR;
            }
            if (datalen > 255) {
                /* draft-19 §2.2-3.6 — ctx is single-byte length */
                OPENSSL_clear_free(ctx->app_ctx, datalen);
                ctx->app_ctx = NULL;
                return RET_OSSL_ERR;
            }
            ctx->app_ctx_len = datalen;
        }
    }
    return RET_OSSL_OK;
}

static int p11prov_composite_digest_sign_init(
    void *vctx, void *keydata, const OSSL_PARAM params[])
{
    return composite_digest_op_init(vctx, keydata, params, CKF_SIGN);
}

static int p11prov_composite_digest_verify_init(
    void *vctx, void *keydata, const OSSL_PARAM params[])
{
    return composite_digest_op_init(vctx, keydata, params, CKF_VERIFY);
}

static int p11prov_composite_digest_op_update(
    void *vctx, const unsigned char *data, size_t datalen)
{
    P11PROV_COMPOSITE_SIG_CTX *ctx = (P11PROV_COMPOSITE_SIG_CTX *)vctx;
    size_t need;

    if (ctx == NULL || data == NULL) {
        return RET_OSSL_ERR;
    }
    if (datalen == 0) {
        return RET_OSSL_OK;
    }
    need = ctx->tbs_buf_len + datalen;
    if (need < ctx->tbs_buf_len) {
        /* overflow */
        return RET_OSSL_ERR;
    }
    if (need > ctx->tbs_buf_cap) {
        size_t newcap = ctx->tbs_buf_cap == 0 ? 4096 : ctx->tbs_buf_cap;
        while (newcap < need) {
            if (newcap > SIZE_MAX / 2) {
                return RET_OSSL_ERR;
            }
            newcap *= 2;
        }
        unsigned char *nb = OPENSSL_realloc(ctx->tbs_buf, newcap);
        if (nb == NULL) {
            return RET_OSSL_ERR;
        }
        ctx->tbs_buf = nb;
        ctx->tbs_buf_cap = newcap;
    }
    memcpy(ctx->tbs_buf + ctx->tbs_buf_len, data, datalen);
    ctx->tbs_buf_len += datalen;
    return RET_OSSL_OK;
}

/* Build M' from the accumulated buffer + app_ctx and write it into an
 * OPENSSL_malloc'd buffer. Caller must OPENSSL_free. */
static int composite_compute_mprime(P11PROV_COMPOSITE_SIG_CTX *ctx,
                                    unsigned char **out, size_t *outlen)
{
    /* Worst case: 32 prefix + 64 label + 1 lenctx + 255 ctx + 64 PH = 416. */
    size_t cap = 32 + 80 + 1 + 255 + 64;
    unsigned char *buf = OPENSSL_malloc(cap);
    size_t sz = cap;

    if (buf == NULL) {
        return 0;
    }
    if (!p11prov_composite_build_mprime(ctx->profile, ctx->tbs_buf,
                                        ctx->tbs_buf_len, ctx->app_ctx,
                                        ctx->app_ctx_len, buf, &sz)) {
        OPENSSL_clear_free(buf, cap);
        return 0;
    }
    *out = buf;
    *outlen = sz;
    return 1;
}

static int p11prov_composite_digest_sign_final(
    void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    P11PROV_COMPOSITE_SIG_CTX *ctx = (P11PROV_COMPOSITE_SIG_CTX *)vctx;
    unsigned char *mprime = NULL;
    size_t mprime_len = 0;
    size_t total = 0;
    size_t pq_sig_size;
    size_t classical_sig_size;
    size_t classical_sig_max;
    int ret = RET_OSSL_ERR;
    CK_RV rv;

    if (ctx == NULL || siglen == NULL) {
        goto out;
    }

    pq_sig_size = ctx->profile->mldsa_sig_bytes;
    /* Classical max — RSA-2048 gives 256 bytes; ECDSA-P256 DER ≤ 72;
     * ECDSA-P384 DER ≤ 104. Use 256 as a safe upper bound. */
    classical_sig_max = 256;

    if (sig == NULL) {
        /* OpenSSL sizing query */
        *siglen = pq_sig_size + classical_sig_max;
        return RET_OSSL_OK;
    }
    if (sigsize < pq_sig_size + classical_sig_max) {
        /* Not enough room for worst case; let caller try with bigger buf. */
        *siglen = pq_sig_size + classical_sig_max;
        goto out;
    }

    if (!composite_compute_mprime(ctx, &mprime, &mprime_len)) {
        goto out;
    }

    /* Sign the PQ half — output starts at sig[0..pq_sig_size]. */
    rv = p11prov_sig_operate(ctx->pq_sigctx, sig, &pq_sig_size, pq_sig_size,
                             mprime, mprime_len);
    if (rv != CKR_OK) {
        goto out;
    }
    if (pq_sig_size != ctx->profile->mldsa_sig_bytes) {
        /* FIPS 204 fixed-length contract violated — composite verify can't
         * split the bytes correctly. */
        goto out;
    }

    /* Sign the classical half — output starts at sig[pq_sig_size]. */
    classical_sig_size = sigsize - pq_sig_size;
    rv = p11prov_sig_operate(ctx->classical_sigctx, sig + pq_sig_size,
                             &classical_sig_size, classical_sig_size, mprime,
                             mprime_len);
    if (rv != CKR_OK) {
        goto out;
    }

    total = pq_sig_size + classical_sig_size;
    *siglen = total;
    ret = RET_OSSL_OK;

out:
    OPENSSL_clear_free(mprime, mprime_len);
    return ret;
}

static int p11prov_composite_digest_verify_final(void *vctx,
                                                 const unsigned char *sig,
                                                 size_t siglen)
{
    P11PROV_COMPOSITE_SIG_CTX *ctx = (P11PROV_COMPOSITE_SIG_CTX *)vctx;
    unsigned char *mprime = NULL;
    size_t mprime_len = 0;
    size_t pq_len;
    size_t classical_len;
    int ret = RET_OSSL_ERR;
    CK_RV rv;

    if (ctx == NULL || sig == NULL) {
        goto out;
    }
    pq_len = ctx->profile->mldsa_sig_bytes;
    if (siglen <= pq_len) {
        /* draft-19 §4.3: PQ sig length is FIPS 204 fixed; anything ≤ that
         * length means there's no classical component. */
        goto out;
    }
    classical_len = siglen - pq_len;

    if (!composite_compute_mprime(ctx, &mprime, &mprime_len)) {
        goto out;
    }

    /* Verify PQ half. The PQ sub-sigctx was opened with operation = CKF_VERIFY
     * by composite_digest_op_init; p11prov_sig_operate dispatches to
     * p11prov_VerifyInit + C_Verify based on sigctx->operation. */
    rv = p11prov_sig_operate(ctx->pq_sigctx, (unsigned char *)sig, &pq_len,
                             pq_len, mprime, mprime_len);
    if (rv != CKR_OK) {
        goto out;
    }
    rv = p11prov_sig_operate(ctx->classical_sigctx,
                             (unsigned char *)(sig + pq_len), &classical_len,
                             classical_len, mprime, mprime_len);
    if (rv != CKR_OK) {
        goto out;
    }

    /* AND-combine per draft-19 §3.3 step 4: both halves must verify. */
    ret = RET_OSSL_OK;

out:
    OPENSSL_clear_free(mprime, mprime_len);
    return ret;
}

/* Settable / gettable ctx params. We accept OSSL_SIGNATURE_PARAM_CONTEXT_STRING
 * (the application context per draft-19 §2.2) before init or via init params. */
static const OSSL_PARAM *p11prov_composite_settable_ctx_params(
    void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_END,
    };
    (void)vctx;
    (void)provctx;
    return params;
}

static const OSSL_PARAM *p11prov_composite_gettable_ctx_params(
    void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    (void)vctx;
    (void)provctx;
    return params;
}

static int p11prov_composite_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    P11PROV_COMPOSITE_SIG_CTX *ctx = (P11PROV_COMPOSITE_SIG_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t datalen;

    if (ctx == NULL || params == NULL) {
        return RET_OSSL_OK;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        OPENSSL_clear_free(ctx->app_ctx, ctx->app_ctx_len);
        ctx->app_ctx = NULL;
        ctx->app_ctx_len = 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->app_ctx, 0,
                                         &datalen)) {
            return RET_OSSL_ERR;
        }
        if (datalen > 255) {
            OPENSSL_clear_free(ctx->app_ctx, datalen);
            ctx->app_ctx = NULL;
            return RET_OSSL_ERR;
        }
        ctx->app_ctx_len = datalen;
    }
    return RET_OSSL_OK;
}

static int p11prov_composite_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return RET_OSSL_OK;
}

/* Per-profile newctx wrappers */
#define DEFINE_COMPOSITE_SIG_NEW(suffix, idx) \
    static void *p11prov_composite_##suffix##_sig_newctx(void *provctx, \
                                                         const char *properties) \
    { \
        (void)properties; \
        return p11prov_composite_sig_newctx_impl( \
            provctx, &p11prov_composite_profiles[idx]); \
    }

DEFINE_COMPOSITE_SIG_NEW(mldsa44_rsa2048_pss, 0)
DEFINE_COMPOSITE_SIG_NEW(mldsa65_ecdsa_p256, 1)
DEFINE_COMPOSITE_SIG_NEW(mldsa87_ecdsa_p384, 2)
#undef DEFINE_COMPOSITE_SIG_NEW

/* Per-profile OSSL_DISPATCH tables for OSSL_OP_SIGNATURE */
#define COMPOSITE_SIG_DISPATCH(suffix) \
    const OSSL_DISPATCH \
        p11prov_composite_##suffix##_sig_functions[] = { \
            { OSSL_FUNC_SIGNATURE_NEWCTX, \
              (void (*)(void))p11prov_composite_##suffix##_sig_newctx }, \
            { OSSL_FUNC_SIGNATURE_FREECTX, \
              (void (*)(void))p11prov_composite_sig_freectx }, \
            { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, \
              (void (*)(void))p11prov_composite_digest_sign_init }, \
            { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, \
              (void (*)(void))p11prov_composite_digest_op_update }, \
            { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, \
              (void (*)(void))p11prov_composite_digest_sign_final }, \
            { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, \
              (void (*)(void))p11prov_composite_digest_verify_init }, \
            { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, \
              (void (*)(void))p11prov_composite_digest_op_update }, \
            { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, \
              (void (*)(void))p11prov_composite_digest_verify_final }, \
            { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, \
              (void (*)(void))p11prov_composite_set_ctx_params }, \
            { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, \
              (void (*)(void))p11prov_composite_settable_ctx_params }, \
            { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, \
              (void (*)(void))p11prov_composite_get_ctx_params }, \
            { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, \
              (void (*)(void))p11prov_composite_gettable_ctx_params }, \
            { 0, NULL }, \
        }

COMPOSITE_SIG_DISPATCH(mldsa44_rsa2048_pss);
COMPOSITE_SIG_DISPATCH(mldsa65_ecdsa_p256);
COMPOSITE_SIG_DISPATCH(mldsa87_ecdsa_p384);
#undef COMPOSITE_SIG_DISPATCH

/* External accessors used by provider.c's ADD_ALGO_EXT block. */
const OSSL_DISPATCH *
p11prov_composite_mldsa44_rsa2048_pss_sig_dispatch(void)
{
    return p11prov_composite_mldsa44_rsa2048_pss_sig_functions;
}
const OSSL_DISPATCH *
p11prov_composite_mldsa65_ecdsa_p256_sig_dispatch(void)
{
    return p11prov_composite_mldsa65_ecdsa_p256_sig_functions;
}
const OSSL_DISPATCH *
p11prov_composite_mldsa87_ecdsa_p384_sig_dispatch(void)
{
    return p11prov_composite_mldsa87_ecdsa_p384_sig_functions;
}
