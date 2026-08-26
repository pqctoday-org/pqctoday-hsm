/* Copyright (C) 2026 pqctoday-hsm contributors
   SPDX-License-Identifier: Apache-2.0 */

/* SLH-DSA (FIPS 205) signature operations, one provider mechanism
 * (CKM_SLH_DSA) shared by all 12 parameter sets, distinguished by
 * CKA_PARAMETER_SET — modeled directly on sig/mldsa.c, which already
 * solved the CK_SIGN_ADDITIONAL_CONTEXT (context-string / hedge) mechanism
 * parameter plumbing that PKCS#11 v3.2 §6.68 (CKM_SLH_DSA) shares with
 * §6.67 (CKM_ML_DSA) — confirmed against the engine's own
 * SoftHSM_sign.cpp CKM_SLH_DSA case (parseSLHDSASignContext), not assumed
 * from ML-DSA's mechanism shape alone.
 *
 * Signature sizes below are fixed per FIPS 205 (Table 2) and were
 * cross-checked live against the real OpenSSL 3.6.3 native
 * implementation (genpkey + pkeyutl -sign for all 12 algorithms) during
 * development — not transcribed from the spec alone. */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/err.h"

#define SLH_DSA_128_SIG_SIZE 7856
#define SLH_DSA_128F_SIG_SIZE 17088
#define SLH_DSA_192S_SIG_SIZE 16224
#define SLH_DSA_192F_SIG_SIZE 35664
#define SLH_DSA_256S_SIG_SIZE 29792
#define SLH_DSA_256F_SIG_SIZE 49856

/* Remediation R38 (phase 8): see mldsa.c's own mldsa_shake_sentinel for
 * the full rationale -- identical need here for CKM_HASH_SLH_DSA_SHAKE128/
 * 256 (§6.69.7), duplicated per-file rather than shared, matching this
 * pair's existing HASH_MLDSA_CASE/HASH_SLHDSA_CASE convention. */
static CK_MECHANISM_TYPE slhdsa_shake_sentinel(const char *digest)
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

DISPATCH_SLHDSA_FN(sign_init);
DISPATCH_SLHDSA_FN(sign);
DISPATCH_SLHDSA_FN(verify_init);
DISPATCH_SLHDSA_FN(verify);
DISPATCH_SLHDSA_FN(digest_sign_init);
DISPATCH_SLHDSA_FN(digest_sign_update);
DISPATCH_SLHDSA_FN(digest_sign_final);
DISPATCH_SLHDSA_FN(digest_verify_init);
DISPATCH_SLHDSA_FN(digest_verify_update);
DISPATCH_SLHDSA_FN(digest_verify_final);
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
DISPATCH_SLHDSA_FN(sign_message_update);
DISPATCH_SLHDSA_FN(sign_message_final);
DISPATCH_SLHDSA_FN(verify_message_update);
DISPATCH_SLHDSA_FN(verify_message_final);
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
DISPATCH_SLHDSA_FN(get_ctx_params);
DISPATCH_SLHDSA_FN(set_ctx_params);
DISPATCH_SLHDSA_FN(gettable_ctx_params);
DISPATCH_SLHDSA_FN(settable_ctx_params);

static CK_RV p11prov_slhdsa_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    /* Remediation R36 (phase 7): PKCS#11 v3.2 §6.69.7 "HashSLH-DSA
     * Signature with hashing" -- CKM_HASH_SLH_DSA_<hash> computes the
     * ENTIRE HashSLH-DSA spec, including hashing ON TOKEN; data passed
     * in is the raw message M, exactly like plain CKM_SLH_DSA. See
     * mldsa.c's own p11prov_mldsa_set_mechanism (R35) for the full
     * rationale and why the bare generic CKM_HASH_SLH_DSA, §6.69.6,
     * PHM-input, is deliberately NOT handled here. */
    if (sigctx->digest != 0) {
        CK_MECHANISM_TYPE hash_mech;
        switch (sigctx->digest) {
        case CKM_SHA224:
            hash_mech = CKM_HASH_SLH_DSA_SHA224;
            break;
        case CKM_SHA256:
            hash_mech = CKM_HASH_SLH_DSA_SHA256;
            break;
        case CKM_SHA384:
            hash_mech = CKM_HASH_SLH_DSA_SHA384;
            break;
        case CKM_SHA512:
            hash_mech = CKM_HASH_SLH_DSA_SHA512;
            break;
        case CKM_SHA3_224:
            hash_mech = CKM_HASH_SLH_DSA_SHA3_224;
            break;
        case CKM_SHA3_256:
            hash_mech = CKM_HASH_SLH_DSA_SHA3_256;
            break;
        case CKM_SHA3_384:
            hash_mech = CKM_HASH_SLH_DSA_SHA3_384;
            break;
        case CKM_SHA3_512:
            hash_mech = CKM_HASH_SLH_DSA_SHA3_512;
            break;
        /* Remediation R38: carrier sentinels from slhdsa_shake_sentinel()
         * (above) -- see mldsa.c's identical case arms for the full
         * rationale. */
        case CKM_SHAKE_128_KEY_DERIVATION:
            hash_mech = CKM_HASH_SLH_DSA_SHAKE128;
            break;
        case CKM_SHAKE_256_KEY_DERIVATION:
            hash_mech = CKM_HASH_SLH_DSA_SHAKE256;
            break;
        default:
            P11PROV_raise(sigctx->provctx, CKR_MECHANISM_INVALID,
                          "Unsupported digest for HashSLH-DSA");
            return CKR_MECHANISM_INVALID;
        }
        sigctx->mechanism.mechanism = hash_mech;
        if (sigctx->slhdsa_params.hedgeVariant != CKH_HEDGE_PREFERRED) {
            sigctx->mechanism.pParameter = &sigctx->slhdsa_params;
            sigctx->mechanism.ulParameterLen = sizeof(sigctx->slhdsa_params);
        } else {
            sigctx->mechanism.pParameter = NULL;
            sigctx->mechanism.ulParameterLen = 0;
        }
        return CKR_OK;
    }
    sigctx->mechanism.mechanism = CKM_SLH_DSA;
    /* See mldsa.c's own p11prov_mldsa_set_mechanism for why the parameter
     * is only plumbed through when the caller deviated from defaults. */
    if ((sigctx->slhdsa_params.pContext != NULL
         && sigctx->slhdsa_params.ulContextLen > 0)
        || sigctx->slhdsa_params.hedgeVariant != CKH_HEDGE_PREFERRED) {
        sigctx->mechanism.pParameter = &sigctx->slhdsa_params;
        sigctx->mechanism.ulParameterLen = sizeof(sigctx->slhdsa_params);
    } else {
        sigctx->mechanism.pParameter = NULL;
        sigctx->mechanism.ulParameterLen = 0;
    }
    return CKR_OK;
}

static CK_RV p11prov_slhdsa_sig_size(P11PROV_SIG_CTX *sigctx, size_t *siglen)
{
    switch (sigctx->slhdsa_paramset) {
    case CKP_SLH_DSA_SHA2_128S:
    case CKP_SLH_DSA_SHAKE_128S:
        *siglen = SLH_DSA_128_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_128F:
    case CKP_SLH_DSA_SHAKE_128F:
        *siglen = SLH_DSA_128F_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_192S:
    case CKP_SLH_DSA_SHAKE_192S:
        *siglen = SLH_DSA_192S_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_192F:
    case CKP_SLH_DSA_SHAKE_192F:
        *siglen = SLH_DSA_192F_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_256S:
    case CKP_SLH_DSA_SHAKE_256S:
        *siglen = SLH_DSA_256S_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_256F:
    case CKP_SLH_DSA_SHAKE_256F:
        *siglen = SLH_DSA_256F_SIG_SIZE;
        return CKR_OK;
    default:
        return CKR_GENERAL_ERROR;
    }
}

static CK_RV p11prov_slhdsa_operate(P11PROV_SIG_CTX *sigctx,
                                    unsigned char *sig, size_t *siglen,
                                    size_t sigsize, unsigned char *tbs,
                                    size_t tbslen)
{
    CK_RV rv;

    rv = p11prov_slhdsa_set_mechanism(sigctx);
    if (rv != CKR_OK) {
        return rv;
    }

    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static void *p11prov_slhdsa_newctx(void *provctx, const char *properties,
                                   CK_SLH_DSA_PARAMETER_SET_TYPE paramset)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_SLH_DSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->slhdsa_paramset = paramset;
    sigctx->fallback_operate = &p11prov_slhdsa_operate;

    return sigctx;
}

#define SLHDSA_NEWCTX(suffix, paramset) \
    static void *p11prov_slhdsa_##suffix##_newctx(void *provctx, \
                                                   const char *properties) \
    { \
        return p11prov_slhdsa_newctx(provctx, properties, paramset); \
    }

SLHDSA_NEWCTX(sha2_128s, CKP_SLH_DSA_SHA2_128S)
SLHDSA_NEWCTX(shake_128s, CKP_SLH_DSA_SHAKE_128S)
SLHDSA_NEWCTX(sha2_128f, CKP_SLH_DSA_SHA2_128F)
SLHDSA_NEWCTX(shake_128f, CKP_SLH_DSA_SHAKE_128F)
SLHDSA_NEWCTX(sha2_192s, CKP_SLH_DSA_SHA2_192S)
SLHDSA_NEWCTX(shake_192s, CKP_SLH_DSA_SHAKE_192S)
SLHDSA_NEWCTX(sha2_192f, CKP_SLH_DSA_SHA2_192F)
SLHDSA_NEWCTX(shake_192f, CKP_SLH_DSA_SHAKE_192F)
SLHDSA_NEWCTX(sha2_256s, CKP_SLH_DSA_SHA2_256S)
SLHDSA_NEWCTX(shake_256s, CKP_SLH_DSA_SHAKE_256S)
SLHDSA_NEWCTX(sha2_256f, CKP_SLH_DSA_SHA2_256F)
SLHDSA_NEWCTX(shake_256f, CKP_SLH_DSA_SHAKE_256F)

static int p11prov_slhdsa_sign_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("slhdsa sign init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs,
                               size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("slhdsa sign (ctx=%p)", ctx);

    if (sig == NULL) {
        if (siglen == 0) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_slhdsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_slhdsa_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                                 tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_slhdsa_verify_init(void *ctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("slhdsa verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_verify(void *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("slhdsa verify (ctx=%p)", ctx);

    ret = p11prov_slhdsa_operate(sigctx, (unsigned char *)sig, NULL, siglen,
                                 (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_slhdsa_digest_sign_init(void *ctx, const char *digest,
                                           void *provkey,
                                           const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_MECHANISM_TYPE shake;
    CK_RV ret;

    P11PROV_debug(
        "slhdsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)",
        ctx, digest ? digest : "<NULL>", provkey, params);

    /* Remediation R38: see mldsa.c's digest_sign_init for the full
     * rationale -- SHAKE128/256 skip p11prov_sig_op_init's own digest
     * lookup and are set as sentinels here instead. */
    shake = slhdsa_shake_sentinel(digest);
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

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_digest_sign_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("slhdsa digest sign update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_slhdsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_slhdsa_digest_sign_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV rv;
    int ret;

    if (siglen == NULL) {
        return RET_OSSL_ERR;
    }
    *siglen = 0;

    P11PROV_debug("slhdsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
                  "sigsize=%zu)",
                  ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (sig == NULL) {
        rv = p11prov_slhdsa_sig_size(sigctx, siglen);
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

static int p11prov_slhdsa_digest_verify_init(void *ctx, const char *digest,
                                             void *provkey,
                                             const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_MECHANISM_TYPE shake;
    CK_RV ret;

    P11PROV_debug(
        "slhdsa digest verify init (ctx=%p, digest=%s, key=%p, params=%p)",
        ctx, digest ? digest : "<NULL>", provkey, params);

    /* See digest_sign_init's own comment (remediation R38). */
    shake = slhdsa_shake_sentinel(digest);
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

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_digest_verify_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug(
        "slhdsa digest verify update (ctx=%p, data=%p, datalen=%zu)", ctx,
        data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_slhdsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_slhdsa_digest_verify_final(void *ctx,
                                              const unsigned char *sig,
                                              size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    int ret;

    P11PROV_debug("slhdsa digest verify final (ctx=%p, sig=%p, siglen=%zu)",
                  ctx, sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_digest_final(sigctx, (void *)sig, NULL, siglen);
    return ret;
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
static int p11prov_slhdsa_sign_message_update(void *ctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    return p11prov_slhdsa_digest_sign_update(ctx, data, datalen);
}

static int p11prov_slhdsa_sign_message_final(void *ctx, unsigned char *sig,
                                             size_t *siglen, size_t sigsize)
{
    return p11prov_slhdsa_digest_sign_final(ctx, sig, siglen, sigsize);
}

static int p11prov_slhdsa_verify_message_update(void *ctx,
                                                const unsigned char *data,
                                                size_t datalen)
{
    return p11prov_slhdsa_digest_verify_update(ctx, data, datalen);
}

static int p11prov_slhdsa_verify_message_final(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("slhdsa message verify final (ctx=%p)", ctx);

    if (sigctx == NULL || sigctx->signature == NULL) {
        P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                      "Signature not available on context");
        return RET_OSSL_ERR;
    }

    return p11prov_slhdsa_digest_verify_final(sigctx, sigctx->signature,
                                              sigctx->signature_len);
}
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

/* AlgorithmIdentifier DER for OSSL_SIGNATURE_PARAM_ALGORITHM_ID, one per
 * parameter set — same NIST sigAlgs arc mldsa.c's der_ml_dsa_* tables use
 * (2.16.840.1.101.3.4.3.<n>), final arc octets 0x14-0x1f. OIDs
 * live-confirmed via `openssl list -signature-algorithms` against the real
 * 3.6.3 build (2.16.840.1.101.3.4.3.20 through .31, id-slh-dsa-sha2-128s
 * through id-slh-dsa-shake-256f in that exact order), not transcribed from
 * the spec alone.
 *
 * Deliberately keyed by CKA_PARAMETER_SET below, NOT by key size like
 * mldsa.c's get_ctx_params does for ML-DSA — SLH-DSA's SHA2 and SHAKE
 * variants at the same security level share identical key sizes (e.g.
 * SHA2-128s and SHAKE-128s are both 32-byte public keys), so size cannot
 * distinguish which OID applies; only the token's own parameter-set
 * attribute can. */
static const unsigned char der_slh_dsa_sha2_128s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x14
};
static const unsigned char der_slh_dsa_sha2_128f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x15
};
static const unsigned char der_slh_dsa_sha2_192s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x16
};
static const unsigned char der_slh_dsa_sha2_192f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x17
};
static const unsigned char der_slh_dsa_sha2_256s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x18
};
static const unsigned char der_slh_dsa_sha2_256f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x19
};
static const unsigned char der_slh_dsa_shake_128s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1a
};
static const unsigned char der_slh_dsa_shake_128f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1b
};
static const unsigned char der_slh_dsa_shake_192s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1c
};
static const unsigned char der_slh_dsa_shake_192f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1d
};
static const unsigned char der_slh_dsa_shake_256s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1e
};
static const unsigned char der_slh_dsa_shake_256f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1f
};

static int p11prov_slhdsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("slhdsa get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        CK_ULONG paramset = p11prov_obj_get_key_param_set(sigctx->key);
        switch (paramset) {
        case CKP_SLH_DSA_SHA2_128S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_128s_alg_id,
                sizeof(der_slh_dsa_sha2_128s_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_128F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_128f_alg_id,
                sizeof(der_slh_dsa_sha2_128f_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_192S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_192s_alg_id,
                sizeof(der_slh_dsa_sha2_192s_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_192F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_192f_alg_id,
                sizeof(der_slh_dsa_sha2_192f_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_256S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_256s_alg_id,
                sizeof(der_slh_dsa_sha2_256s_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_256F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_256f_alg_id,
                sizeof(der_slh_dsa_sha2_256f_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_128S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_128s_alg_id,
                sizeof(der_slh_dsa_shake_128s_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_128F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_128f_alg_id,
                sizeof(der_slh_dsa_shake_128f_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_192S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_192s_alg_id,
                sizeof(der_slh_dsa_shake_192s_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_192F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_192f_alg_id,
                sizeof(der_slh_dsa_shake_192f_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_256S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_256s_alg_id,
                sizeof(der_slh_dsa_shake_256s_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_256F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_256f_alg_id,
                sizeof(der_slh_dsa_shake_256f_alg_id));
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
#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

static int p11prov_slhdsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("slhdsa set ctx params (ctx=%p, params=%p)", sigctx,
                  params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p) {
        size_t datalen;
        OPENSSL_clear_free(sigctx->slhdsa_params.pContext,
                           sigctx->slhdsa_params.ulContextLen);
        sigctx->slhdsa_params.pContext = NULL;
        ret = OSSL_PARAM_get_octet_string(
            p, (void **)&sigctx->slhdsa_params.pContext, 0, &datalen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        sigctx->slhdsa_params.ulContextLen = datalen;
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
        sigctx->slhdsa_params.hedgeVariant = hedge;
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

static const OSSL_PARAM *p11prov_slhdsa_gettable_ctx_params(void *ctx,
                                                             void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_slhdsa_settable_ctx_params(void *ctx,
                                                             void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
#if defined(OSSL_SIGNATURE_PARAM_SIGNATURE)
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#endif
        OSSL_PARAM_END,
    };
    return params;
}

#define SLHDSA_SIG_FUNCTIONS(suffix) \
    const OSSL_DISPATCH p11prov_slhdsa_##suffix##_signature_functions[] = { \
        DISPATCH_SIG_ELEM(slhdsa_##suffix, NEWCTX, newctx), \
        DISPATCH_SIG_ELEM(sig, FREECTX, freectx), \
        DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx), \
        DISPATCH_SIG_ELEM(slhdsa, SIGN_INIT, sign_init), \
        DISPATCH_SIG_ELEM(slhdsa, SIGN, sign), \
        DISPATCH_SIG_ELEM(slhdsa, VERIFY_INIT, verify_init), \
        DISPATCH_SIG_ELEM(slhdsa, VERIFY, verify), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_SIGN_INIT, digest_sign_init), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_SIGN_UPDATE, digest_sign_update), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_SIGN_FINAL, digest_sign_final), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_VERIFY_INIT, digest_verify_init), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_VERIFY_UPDATE, \
                          digest_verify_update), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_VERIFY_FINAL, digest_verify_final), \
        _SLHDSA_SIG_FUNCTIONS_MESSAGE_ELEMS \
        DISPATCH_SIG_ELEM(slhdsa, GET_CTX_PARAMS, get_ctx_params), \
        DISPATCH_SIG_ELEM(slhdsa, GETTABLE_CTX_PARAMS, gettable_ctx_params), \
        DISPATCH_SIG_ELEM(slhdsa, SET_CTX_PARAMS, set_ctx_params), \
        DISPATCH_SIG_ELEM(slhdsa, SETTABLE_CTX_PARAMS, \
                          settable_ctx_params), \
        { 0, NULL }, \
    };

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
#define _SLHDSA_SIG_FUNCTIONS_MESSAGE_ELEMS \
    DISPATCH_SIG_ELEM(slhdsa, SIGN_MESSAGE_INIT, sign_init), \
    DISPATCH_SIG_ELEM(slhdsa, SIGN_MESSAGE_UPDATE, sign_message_update), \
    DISPATCH_SIG_ELEM(slhdsa, SIGN_MESSAGE_FINAL, sign_message_final), \
    DISPATCH_SIG_ELEM(slhdsa, VERIFY_MESSAGE_INIT, verify_init), \
    DISPATCH_SIG_ELEM(slhdsa, VERIFY_MESSAGE_UPDATE, verify_message_update), \
    DISPATCH_SIG_ELEM(slhdsa, VERIFY_MESSAGE_FINAL, verify_message_final),
#else
#define _SLHDSA_SIG_FUNCTIONS_MESSAGE_ELEMS
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

SLHDSA_SIG_FUNCTIONS(sha2_128s)
SLHDSA_SIG_FUNCTIONS(shake_128s)
SLHDSA_SIG_FUNCTIONS(sha2_128f)
SLHDSA_SIG_FUNCTIONS(shake_128f)
SLHDSA_SIG_FUNCTIONS(sha2_192s)
SLHDSA_SIG_FUNCTIONS(shake_192s)
SLHDSA_SIG_FUNCTIONS(sha2_192f)
SLHDSA_SIG_FUNCTIONS(shake_192f)
SLHDSA_SIG_FUNCTIONS(sha2_256s)
SLHDSA_SIG_FUNCTIONS(shake_256s)
SLHDSA_SIG_FUNCTIONS(sha2_256f)
SLHDSA_SIG_FUNCTIONS(shake_256f)
