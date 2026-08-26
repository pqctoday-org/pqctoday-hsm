/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/err.h"

/* See FIPS-204, 4. Parameter Sets */
#define ML_DSA_44_SK_SIZE 2560
#define ML_DSA_44_PK_SIZE 1312
#define ML_DSA_44_SIG_SIZE 2420
#define ML_DSA_65_SK_SIZE 4032
#define ML_DSA_65_PK_SIZE 1952
#define ML_DSA_65_SIG_SIZE 3309
#define ML_DSA_87_SK_SIZE 4896
#define ML_DSA_87_PK_SIZE 2592
#define ML_DSA_87_SIG_SIZE 4627

/* Remediation R34, PQCTODAY-VENDOR-EXT-MU: vendor mechanism for external-µ
 * signing, a stopgap for PKCS#11 v3.3's own upcoming native mechanism
 * (oasis-tcs/pkcs11#58, not yet ratified). Mirrors the numeric allocation
 * in src/lib/vendor_mechanisms.h (CKM_VENDOR_DEFINED | 0x13) -- kept as a
 * local #define here rather than a shared header, matching this
 * provider's own existing pattern for vendor mechanisms (e.g. mac.h's
 * CKM_KMAC_128). See
 * docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md for
 * the full design. Remove when this project adopts v3.3 natively. */
#define CKM_PQCTODAY_ML_DSA_MU (CKM_VENDOR_DEFINED | 0x00000013UL)

/* Remediation R38 (phase 8): PKCS#11 v3.2 has no SHAKE *digest* mechanism
 * codepoint to carry through `sigctx->digest` (only
 * CKM_SHAKE_128/256_KEY_DERIVATION, which are KDF mechanisms, not
 * digests) -- yet CKM_HASH_ML_DSA_SHAKE128/256 (§6.67.7) are real,
 * ratified mechanisms the engines already implement. digests.c's own
 * digest_map deliberately has no SHAKE entry (it also feeds
 * p11prov_digest_get_digest_size, whose fixed-length-digest contract a
 * variable-length XOF doesn't fit -- see the phase-8 plan's R38
 * grounding). So SHAKE128/256 are recognized HERE, before the shared
 * p11prov_sig_op_init() name lookup would reject them, using the two
 * KEY_DERIVATION constants purely as carrier sentinels matched by
 * set_mechanism()'s own switch below -- never passed to a real KDF. Live-
 * confirmed (PKCS11_PROVIDER_DEBUG) that `openssl dgst -shake128/-shake256
 * -sign` reaches this function with digest == "shake128"/"shake256"
 * lowercase; OPENSSL_strcasecmp (case-insensitive, matching every other
 * digest_map entry's own convention) also covers the OSSL_DIGEST_NAME_*
 * "SHAKE-128"/"SHAKE-256" spelling in case a non-CLI caller uses it. */
static CK_MECHANISM_TYPE mldsa_shake_sentinel(const char *digest)
{
    if (digest == NULL) {
        return CK_UNAVAILABLE_INFORMATION;
    }
    if (OPENSSL_strcasecmp(digest, "SHAKE128") == 0
        || OPENSSL_strcasecmp(digest, "SHAKE-128") == 0) {
        return CKM_SHAKE_128_KEY_DERIVATION;
    }
    if (OPENSSL_strcasecmp(digest, "SHAKE256") == 0
        || OPENSSL_strcasecmp(digest, "SHAKE-256") == 0) {
        return CKM_SHAKE_256_KEY_DERIVATION;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

DISPATCH_MLDSA_FN(sign_init);
DISPATCH_MLDSA_FN(sign);
DISPATCH_MLDSA_FN(verify_init);
DISPATCH_MLDSA_FN(verify);
DISPATCH_MLDSA_FN(digest_sign_init);
DISPATCH_MLDSA_FN(digest_sign_update);
DISPATCH_MLDSA_FN(digest_sign_final);
DISPATCH_MLDSA_FN(digest_verify_init);
DISPATCH_MLDSA_FN(digest_verify_update);
DISPATCH_MLDSA_FN(digest_verify_final);
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
DISPATCH_MLDSA_FN(sign_message_update);
DISPATCH_MLDSA_FN(sign_message_final);
DISPATCH_MLDSA_FN(verify_message_update);
DISPATCH_MLDSA_FN(verify_message_final);
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
DISPATCH_MLDSA_FN(get_ctx_params);
DISPATCH_MLDSA_FN(set_ctx_params);
DISPATCH_MLDSA_FN(gettable_ctx_params);
DISPATCH_MLDSA_FN(settable_ctx_params);

static CK_RV p11prov_mldsa_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    /* Remediation R34, PQCTODAY-VENDOR-EXT-MU. µ has no defined meaning
     * for a context string (FIPS 204 folds context into µ before the
     * caller ever computes it) -- reject rather than silently drop it. */
    if (sigctx->mldsa_external_mu) {
        if (sigctx->mldsa_params.pContext != NULL
            && sigctx->mldsa_params.ulContextLen > 0) {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "'context-string' has no meaning with 'mu' set");
            return CKR_ARGUMENTS_BAD;
        }
        sigctx->mechanism.mechanism = CKM_PQCTODAY_ML_DSA_MU;
        /* hedgeVariant is the only meaningful field; same "only plumb the
         * struct through when non-default" rule as CKM_ML_DSA below. */
        if (sigctx->mldsa_params.hedgeVariant != CKH_HEDGE_PREFERRED) {
            sigctx->mechanism.pParameter = &sigctx->mldsa_params;
            sigctx->mechanism.ulParameterLen = sizeof(sigctx->mldsa_params);
        } else {
            sigctx->mechanism.pParameter = NULL;
            sigctx->mechanism.ulParameterLen = 0;
        }
        return CKR_OK;
    }
    /* Remediation R35 (phase 7): PKCS#11 v3.2 §6.67.7 "HashML-DSA
     * Signature with hashing" -- CKM_HASH_ML_DSA_<hash> computes the
     * ENTIRE HashML-DSA spec, including hashing ON TOKEN; the data
     * passed in is the raw message M, exactly like plain CKM_ML_DSA.
     * (Not to be confused with the bare generic CKM_HASH_ML_DSA,
     * §6.67.6, which wants an already-hashed PHM -- a separate,
     * narrower gap, not addressed by this mapping.) sigctx->digest is
     * already populated by p11prov_sig_op_init from the caller's
     * EVP_DigestSignInit digest name; == 0 means none was given
     * (rsasig.c's own convention, reused here). */
    if (sigctx->digest != 0) {
        CK_MECHANISM_TYPE hash_mech;
        switch (sigctx->digest) {
        case CKM_SHA224:
            hash_mech = CKM_HASH_ML_DSA_SHA224;
            break;
        case CKM_SHA256:
            hash_mech = CKM_HASH_ML_DSA_SHA256;
            break;
        case CKM_SHA384:
            hash_mech = CKM_HASH_ML_DSA_SHA384;
            break;
        case CKM_SHA512:
            hash_mech = CKM_HASH_ML_DSA_SHA512;
            break;
        case CKM_SHA3_224:
            hash_mech = CKM_HASH_ML_DSA_SHA3_224;
            break;
        case CKM_SHA3_256:
            hash_mech = CKM_HASH_ML_DSA_SHA3_256;
            break;
        case CKM_SHA3_384:
            hash_mech = CKM_HASH_ML_DSA_SHA3_384;
            break;
        case CKM_SHA3_512:
            hash_mech = CKM_HASH_ML_DSA_SHA3_512;
            break;
        /* Remediation R38 (phase 8): these two never come from
         * p11prov_digest_get_by_name's digest_map (it has no SHAKE entry
         * -- see that gap's own note in digests.c) -- they arrive only
         * as the carrier sentinels mldsa_shake_sentinel() (above) sets in
         * digest_sign/verify_init, one layer earlier than every other
         * case in this switch. */
        case CKM_SHAKE_128_KEY_DERIVATION:
            hash_mech = CKM_HASH_ML_DSA_SHAKE128;
            break;
        case CKM_SHAKE_256_KEY_DERIVATION:
            hash_mech = CKM_HASH_ML_DSA_SHAKE256;
            break;
        default:
            P11PROV_raise(sigctx->provctx, CKR_MECHANISM_INVALID,
                          "Unsupported digest for HashML-DSA");
            return CKR_MECHANISM_INVALID;
        }
        sigctx->mechanism.mechanism = hash_mech;
        if (sigctx->mldsa_params.hedgeVariant != CKH_HEDGE_PREFERRED) {
            sigctx->mechanism.pParameter = &sigctx->mldsa_params;
            sigctx->mechanism.ulParameterLen = sizeof(sigctx->mldsa_params);
        } else {
            sigctx->mechanism.pParameter = NULL;
            sigctx->mechanism.ulParameterLen = 0;
        }
        return CKR_OK;
    }
    sigctx->mechanism.mechanism = CKM_ML_DSA;
    /* Per PKCS#11 v3.2 §6.67.5, CKM_ML_DSA takes an OPTIONAL
     * CK_SIGN_ADDITIONAL_CONTEXT parameter:
     *
     *   typedef struct CK_SIGN_ADDITIONAL_CONTEXT {
     *     CK_HEDGE_TYPE  hedgeVariant;
     *     CK_BYTE_PTR    pContext;
     *     CK_ULONG       ulContextLen;
     *   } CK_SIGN_ADDITIONAL_CONTEXT;
     *
     * "If no parameter is supplied the hedgeVariant will be
     *  CKH_HEDGE_PREFERRED, ulContextLen will be zero and pContext will
     *  be NULL."
     *
     * sigctx->mldsa_params is already typed CK_SIGN_ADDITIONAL_CONTEXT
     * (internal.h:43); p11prov_mldsa_set_ctx_params() populates its
     * fields from OSSL_SIGNATURE_PARAM_CONTEXT_STRING and
     * OSSL_SIGNATURE_PARAM_DETERMINISTIC.
     *
     * Plumb the struct through pParameter whenever the caller has
     * deviated from defaults — that is, set a context string OR
     * requested a non-default hedge variant. Without this, the token
     * (e.g. softhsm OSSLMLDSA.cpp:339-344) never sees either field and
     * always signs hedged-without-context.
     *
     * The struct lives in the sigctx and outlives C_SignInit, so the
     * pointer is safe. */
    if ((sigctx->mldsa_params.pContext != NULL
         && sigctx->mldsa_params.ulContextLen > 0)
        || sigctx->mldsa_params.hedgeVariant != CKH_HEDGE_PREFERRED) {
        sigctx->mechanism.pParameter = &sigctx->mldsa_params;
        sigctx->mechanism.ulParameterLen = sizeof(sigctx->mldsa_params);
    } else {
        sigctx->mechanism.pParameter = NULL;
        sigctx->mechanism.ulParameterLen = 0;
    }
    return CKR_OK;
}

static CK_RV p11prov_mldsa_sig_size(P11PROV_SIG_CTX *sigctx, size_t *siglen)
{
    switch (sigctx->mldsa_paramset) {
    case CKP_ML_DSA_44:
        *siglen = ML_DSA_44_SIG_SIZE;
        return CKR_OK;
    case CKP_ML_DSA_65:
        *siglen = ML_DSA_65_SIG_SIZE;
        return CKR_OK;
    case CKP_ML_DSA_87:
        *siglen = ML_DSA_87_SIG_SIZE;
        return CKR_OK;
    default:
        return CKR_GENERAL_ERROR;
    }
}

static CK_RV p11prov_mldsa_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                   size_t *siglen, size_t sigsize,
                                   unsigned char *tbs, size_t tbslen)
{
    CK_RV rv;

    rv = p11prov_mldsa_set_mechanism(sigctx);
    if (rv != CKR_OK) {
        return rv;
    }

    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static void *p11prov_mldsa_newctx(void *provctx, const char *properties,
                                  CK_ML_DSA_PARAMETER_SET_TYPE paramset)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_ML_DSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->mldsa_paramset = paramset;
    sigctx->fallback_operate = &p11prov_mldsa_operate;

    return sigctx;
}

static void *p11prov_mldsa_44_newctx(void *provctx, const char *properties)
{
    return p11prov_mldsa_newctx(provctx, properties, CKP_ML_DSA_44);
}

static void *p11prov_mldsa_65_newctx(void *provctx, const char *properties)
{
    return p11prov_mldsa_newctx(provctx, properties, CKP_ML_DSA_65);
}

static void *p11prov_mldsa_87_newctx(void *provctx, const char *properties)
{
    return p11prov_mldsa_newctx(provctx, properties, CKP_ML_DSA_87);
}

static int p11prov_mldsa_sign_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("mldsa sign init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_mldsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("mldsa sign (ctx=%p)", ctx);

    if (sig == NULL) {
        if (siglen == 0) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_mldsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_mldsa_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                                tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_mldsa_verify_init(void *ctx, void *provkey,
                                     const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("mldsa verify init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_mldsa_verify(void *ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("mldsa verify (ctx=%p)", ctx);

    ret = p11prov_mldsa_operate(sigctx, (unsigned char *)sig, NULL, siglen,
                                (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_mldsa_digest_sign_init(void *ctx, const char *digest,
                                          void *provkey,
                                          const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_MECHANISM_TYPE shake;
    CK_RV ret;

    P11PROV_debug(
        "mldsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)", ctx,
        digest ? digest : "<NULL>", provkey, params);

    /* Remediation R38: SHAKE128/256 would otherwise fail inside
     * p11prov_sig_op_init's own p11prov_digest_get_by_name lookup (no
     * digest_map entry) -- call it with digest=NULL to skip that lookup
     * (still does the real key/operation setup) and set the sentinel
     * ourselves, one layer earlier than the shared path handles it. */
    shake = mldsa_shake_sentinel(digest);
    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN,
                              shake == CK_UNAVAILABLE_INFORMATION ? digest
                                                                  : NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    if (shake != CK_UNAVAILABLE_INFORMATION) {
        sigctx->digest = shake;
    }

    sigctx->digest_op = true;

    return p11prov_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_mldsa_digest_sign_update(void *ctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("mldsa digest sign update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_mldsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_mldsa_digest_sign_final(void *ctx, unsigned char *sig,
                                           size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV rv;
    int ret;

    if (siglen == NULL) {
        return RET_OSSL_ERR;
    }
    *siglen = 0;

    P11PROV_debug("mldsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
                  "sigsize=%zu)",
                  ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (sig == NULL) {
        rv = p11prov_mldsa_sig_size(sigctx, siglen);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }
    if (sigsize == 0) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_digest_final(sigctx, sig, siglen, sigsize);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return RET_OSSL_OK;
}

static int p11prov_mldsa_digest_verify_init(void *ctx, const char *digest,
                                            void *provkey,
                                            const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_MECHANISM_TYPE shake;
    CK_RV ret;

    P11PROV_debug(
        "mldsa digest verify init (ctx=%p, digest=%s, key=%p, params=%p)",
        ctx, digest ? digest : "<NULL>", provkey, params);

    /* See digest_sign_init's own comment (remediation R38). */
    shake = mldsa_shake_sentinel(digest);
    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY,
                              shake == CK_UNAVAILABLE_INFORMATION ? digest
                                                                  : NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    if (shake != CK_UNAVAILABLE_INFORMATION) {
        sigctx->digest = shake;
    }

    sigctx->digest_op = true;

    return p11prov_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_mldsa_digest_verify_update(void *ctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("mldsa digest verify update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_mldsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_mldsa_digest_verify_final(void *ctx,
                                             const unsigned char *sig,
                                             size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    int ret;

    P11PROV_debug("mldsa digest verify final (ctx=%p, sig=%p, siglen=%zu)", ctx,
                  sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_digest_final(sigctx, (void *)sig, NULL, siglen);
    return ret;
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
static int p11prov_mldsa_sign_message_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    return p11prov_mldsa_digest_sign_update(ctx, data, datalen);
}

static int p11prov_mldsa_sign_message_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    return p11prov_mldsa_digest_sign_final(ctx, sig, siglen, sigsize);
}

static int p11prov_mldsa_verify_message_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    return p11prov_mldsa_digest_verify_update(ctx, data, datalen);
}

static int p11prov_mldsa_verify_message_final(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("mldsa message verify final (ctx=%p)", ctx);

    if (sigctx == NULL || sigctx->signature == NULL) {
        P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                      "Signature not available on context");
        return RET_OSSL_ERR;
    }

    return p11prov_mldsa_digest_verify_final(sigctx, sigctx->signature,
                                             sigctx->signature_len);
}
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

static const unsigned char der_ml_dsa_44_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x11
};

static const unsigned char der_ml_dsa_65_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x12
};

static const unsigned char der_ml_dsa_87_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x13
};

static int p11prov_mldsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("mldsa get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        CK_ULONG size = p11prov_obj_get_key_size(sigctx->key);
        switch (size) {
        case ML_DSA_44_SK_SIZE:
        case ML_DSA_44_PK_SIZE:
            ret = OSSL_PARAM_set_octet_string(p, der_ml_dsa_44_alg_id,
                                              sizeof(der_ml_dsa_44_alg_id));
            break;
        case ML_DSA_65_SK_SIZE:
        case ML_DSA_65_PK_SIZE:
            ret = OSSL_PARAM_set_octet_string(p, der_ml_dsa_65_alg_id,
                                              sizeof(der_ml_dsa_65_alg_id));
            break;
        case ML_DSA_87_SK_SIZE:
        case ML_DSA_87_PK_SIZE:
            ret = OSSL_PARAM_set_octet_string(p, der_ml_dsa_87_alg_id,
                                              sizeof(der_ml_dsa_87_alg_id));
            break;
        default:
            ret = RET_OSSL_ERR;
        }
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING
#define OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING "message-encoding"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MU
#define OSSL_SIGNATURE_PARAM_MU "mu"
#endif
#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

static int p11prov_mldsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("mldsa set ctx params (ctx=%p, params=%p)", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p) {
        size_t datalen;
        OPENSSL_clear_free(sigctx->mldsa_params.pContext,
                           sigctx->mldsa_params.ulContextLen);
        sigctx->mldsa_params.pContext = NULL;
        ret = OSSL_PARAM_get_octet_string(
            p, (void **)&sigctx->mldsa_params.pContext, 0, &datalen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        sigctx->mldsa_params.ulContextLen = datalen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p) {
        CK_HEDGE_TYPE hedge = CKH_HEDGE_PREFERRED;
        int deterministic;
        ret = OSSL_PARAM_get_int(p, &deterministic);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (deterministic == 0) {
            hedge = CKH_HEDGE_REQUIRED;
        } else if (deterministic == 1) {
            hedge = CKH_DETERMINISTIC_REQUIRED;
        } else {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Unsupported 'deterministic' value");
            return RET_OSSL_ERR;
        }
        sigctx->mldsa_params.hedgeVariant = hedge;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING);
    if (p) {
        int encode;
        ret = OSSL_PARAM_get_int(p, &encode);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (encode != 1) {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Unsupported 'message-encoding' parameter");
            return RET_OSSL_ERR;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU);
    if (p) {
        int mu;
        ret = OSSL_PARAM_get_int(p, &mu);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        /* Remediation R34, PQCTODAY-VENDOR-EXT-MU: mu=1 routes to the
         * vendor mechanism CKM_PQCTODAY_ML_DSA_MU (see
         * p11prov_mldsa_set_mechanism) instead of being rejected -- a
         * stopgap for PKCS#11 v3.3's own upcoming native external-µ
         * mechanism (oasis-tcs/pkcs11#58). The caller's 64-byte µ itself
         * travels via the normal sign/verify data argument, exactly like
         * OpenSSL's own convention for this parameter -- nothing extra
         * to capture here beyond the flag. */
        if (mu != 0 && mu != 1) {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Unsupported 'mu' parameter");
            return RET_OSSL_ERR;
        }
        sigctx->mldsa_external_mu = (mu == 1);
    }

#if defined(OSSL_SIGNATURE_PARAM_SIGNATURE)
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
    if (p) {
        OPENSSL_free(sigctx->signature);
        sigctx->signature = NULL;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&sigctx->signature, 0,
                                          &sigctx->signature_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
#endif

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mldsa_gettable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_mldsa_settable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, 0),
#if defined(OSSL_SIGNATURE_PARAM_SIGNATURE)
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#endif
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_mldsa_44_signature_functions[] = {
    DISPATCH_SIG_ELEM(mldsa_44, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(mldsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN, sign),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_FINAL, digest_verify_final),
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_UPDATE, sign_message_update),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_FINAL, sign_message_final),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_UPDATE, verify_message_update),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_FINAL, verify_message_final),
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
    DISPATCH_SIG_ELEM(mldsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa_65_signature_functions[] = {
    DISPATCH_SIG_ELEM(mldsa_65, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(mldsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN, sign),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_FINAL, digest_verify_final),
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_UPDATE, sign_message_update),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_FINAL, sign_message_final),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_UPDATE, verify_message_update),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_FINAL, verify_message_final),
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
    DISPATCH_SIG_ELEM(mldsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa_87_signature_functions[] = {
    DISPATCH_SIG_ELEM(mldsa_87, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(mldsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN, sign),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_FINAL, digest_verify_final),
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_UPDATE, sign_message_update),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_FINAL, sign_message_final),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_UPDATE, verify_message_update),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_FINAL, verify_message_final),
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
    DISPATCH_SIG_ELEM(mldsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};
