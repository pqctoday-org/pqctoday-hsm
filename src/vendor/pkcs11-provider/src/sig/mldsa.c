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

/* Remediation R34, PQCTODAY-VENDOR-EXT-MU: mechanism for external-µ
 * signing. Adopted natively 2026-08-30 from the real PKCS#11 v3.3 working
 * draft's own CKM_ML_DSA_EXTERNAL_MU name and codepoint (still OASIS
 * status "proposed", not yet through final ballot -- double-check against
 * the final ratified v3.3 header once published). Mirrors the allocation
 * in src/lib/vendor_mechanisms.h -- kept as a local #define here rather
 * than a shared header, matching this provider's own existing pattern
 * for PKCS#11 mechanism constants (e.g. mac.h's CKM_KMAC_128). See
 * docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md for
 * the original design. */
#define CKM_ML_DSA_EXTERNAL_MU 0x0000403cUL

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
    /* Remediation item 5 (2026-08-30, risk-accepted): HASH-ML-DSA pre-hash
     * mode, set only by p11prov_hash_mldsa_newctx (never by plain
     * ML-DSA-44/65/87). Checked first and returns unconditionally --
     * phm_mode never falls through to the CKM_ML_DSA_EXTERNAL_MU / plain
     * CKM_ML_DSA / CKM_HASH_ML_DSA_<digest> "with hashing" branches below,
     * which are mutually exclusive with it by construction (a phm_mode
     * context is never also external_mu). Requires OSSL_SIGNATURE_PARAM_
     * DIGEST to have been set (p11prov_hash_mldsa_set_ctx_params below) so
     * the token knows which OID to embed in M' (PKCS#11 v3.2 SS6.67.6's
     * CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash field) -- the caller already
     * did the actual hashing themselves, following OpenSSL's own
     * documented (testing-only) message-encoding=0 pattern for pre-hash
     * ML-DSA (EVP_SIGNATURE-ML-DSA(7)). */
    if (sigctx->mldsa_phm_mode) {
        if (sigctx->digest == 0) {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "HASH-ML-DSA requires the 'digest' signature "
                          "parameter (the hash algorithm used to "
                          "pre-hash the message externally)");
            return CKR_ARGUMENTS_BAD;
        }
        sigctx->mldsa_hash_params.hedgeVariant =
            sigctx->mldsa_params.hedgeVariant;
        sigctx->mldsa_hash_params.pContext = sigctx->mldsa_params.pContext;
        sigctx->mldsa_hash_params.ulContextLen =
            sigctx->mldsa_params.ulContextLen;
        sigctx->mldsa_hash_params.hash = sigctx->digest;
        sigctx->mechanism.mechanism = CKM_HASH_ML_DSA;
        sigctx->mechanism.pParameter = &sigctx->mldsa_hash_params;
        sigctx->mechanism.ulParameterLen = sizeof(sigctx->mldsa_hash_params);
        return CKR_OK;
    }
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
        sigctx->mechanism.mechanism = CKM_ML_DSA_EXTERNAL_MU;
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
        /* Remediation R34, PQCTODAY-VENDOR-EXT-MU: mu=1 routes to
         * CKM_ML_DSA_EXTERNAL_MU (see p11prov_mldsa_set_mechanism) instead
         * of being rejected -- the real PKCS#11 v3.3 working draft's own
         * external-µ mechanism, adopted natively 2026-08-30. The caller's
         * 64-byte µ itself travels via the normal sign/verify data
         * argument, exactly like OpenSSL's own convention for this
         * parameter -- nothing extra to capture here beyond the flag. */
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

/* --------------------------------------------------------------------
 * HASH-ML-DSA: bare generic CKM_HASH_ML_DSA pre-hash family (remediation
 * item 5, 2026-08-30, risk-accepted -- see provider.h's
 * P11PROV_NAMES_HASH_ML_DSA comment for the full caveat quoted from
 * OpenSSL's own docs: this rests on EVP_SIGNATURE-ML-DSA(7)'s documented
 * testing-only message-encoding=0 escape hatch, not a stable production
 * contract).
 *
 * One provider algorithm, "HASH-ML-DSA", paramset-agnostic exactly like
 * sig/xmss.c's XMSS/XMSS^MT: the actual ML-DSA-44/65/87 parameter set is
 * resolved from the bound key at sign_init/verify_init time via
 * p11prov_obj_get_key_param_set() (the same accessor ML-DSA/SLH-DSA/
 * ML-KEM/XMSS already share), not baked into the algorithm's own
 * identity the way plain ML_DSA_44/65/87 above are.
 *
 * The caller must set the standard "digest" ctx param
 * (OSSL_SIGNATURE_PARAM_DIGEST -- the same one EVP_PKEY_CTX_set_
 * signature_md() sets for RSA/ECDSA/DSA raw signing) to the digest
 * algorithm they used to pre-hash the message externally; the bytes
 * handed to sign()/verify() as "tbs" ARE that digest, not a message to
 * be hashed here.
 *
 * SIGN_MESSAGE and DIGEST_SIGN streaming entry points are deliberately
 * not registered: the engine's CKM_HASH_ML_DSA dispatch
 * (SoftHSM_sign.cpp) is genuinely single-part only
 * (bAllowMultiPartOp=false -- the data argument to C_Sign/C_Verify IS
 * the complete PHM, nothing to stream), so this algorithm only supports
 * the plain one-shot EVP_PKEY_sign_init()+EVP_PKEY_sign() /
 * EVP_PKEY_verify_init()+EVP_PKEY_verify() calling convention, which
 * p11prov_mldsa_sign/verify (reused verbatim below) already implement
 * via a single p11prov_sig_operate() call. */

#ifndef OSSL_SIGNATURE_PARAM_DIGEST
#define OSSL_SIGNATURE_PARAM_DIGEST OSSL_PKEY_PARAM_DIGEST
#endif

DISPATCH_HASH_MLDSA_FN(newctx);
DISPATCH_HASH_MLDSA_FN(sign_init);
DISPATCH_HASH_MLDSA_FN(verify_init);
DISPATCH_HASH_MLDSA_FN(set_ctx_params);
DISPATCH_HASH_MLDSA_FN(settable_ctx_params);
DISPATCH_HASH_MLDSA_FN(query_key_types);

static void *p11prov_hash_mldsa_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_HASH_ML_DSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->mldsa_phm_mode = true;
    sigctx->fallback_operate = &p11prov_mldsa_operate;

    return sigctx;
}

static CK_RV hash_mldsa_bind_paramset(P11PROV_SIG_CTX *sigctx)
{
    CK_ULONG paramset = p11prov_obj_get_key_param_set(sigctx->key);

    if (paramset != CKP_ML_DSA_44 && paramset != CKP_ML_DSA_65
        && paramset != CKP_ML_DSA_87) {
        P11PROV_raise(sigctx->provctx, CKR_KEY_TYPE_INCONSISTENT,
                      "HASH-ML-DSA requires an ML-DSA-44/65/87 key");
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    sigctx->mldsa_paramset = paramset;
    return CKR_OK;
}

static int p11prov_hash_mldsa_sign_init(void *ctx, void *provkey,
                                        const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("hash_mldsa sign init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = hash_mldsa_bind_paramset(sigctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_hash_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_hash_mldsa_verify_init(void *ctx, void *provkey,
                                          const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("hash_mldsa verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = hash_mldsa_bind_paramset(sigctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_hash_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_hash_mldsa_set_ctx_params(void *ctx,
                                             const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("hash_mldsa set ctx params (ctx=%p, params=%p)", sigctx,
                  params);

    /* Reuse plain ML-DSA's ctx-params handling for context-string /
     * deterministic -- HASH-ML-DSA takes the same CK_SIGN_ADDITIONAL_
     * CONTEXT-shaped fields, repackaged into CK_HASH_SIGN_ADDITIONAL_
     * CONTEXT by p11prov_mldsa_set_mechanism's phm_mode branch. This
     * also accepts (and ignores, since Pure encoding is never applied in
     * phm_mode) message-encoding and mu -- harmless no-ops rather than
     * new failure modes for a caller that sets them out of habit. */
    ret = p11prov_mldsa_set_ctx_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        char digestname[64] = { 0 };
        char *namep = digestname;
        CK_MECHANISM_TYPE shake;

        ret = OSSL_PARAM_get_utf8_string(p, &namep, sizeof(digestname));
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        /* Same SHAKE128/256 carrier-sentinel need as the "with hashing"
         * digest_sign_init path above -- p11prov_digest_get_by_name's
         * digest_map has no SHAKE entry (see mldsa_shake_sentinel's own
         * header comment). */
        shake = mldsa_shake_sentinel(digestname);
        if (shake != CK_UNAVAILABLE_INFORMATION) {
            sigctx->digest = shake;
        } else {
            CK_MECHANISM_TYPE digest;
            CK_RV rv = p11prov_digest_get_by_name(digestname, &digest);
            if (rv != CKR_OK) {
                P11PROV_raise(sigctx->provctx, rv,
                              "Unsupported 'digest' for HASH-ML-DSA: %s",
                              digestname);
                return RET_OSSL_ERR;
            }
            sigctx->digest = digest;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hash_mldsa_settable_ctx_params(void *ctx,
                                                                 void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

/* Remediation item 5, real bug caught only by actually exercising the
 * explicit-fetch calling convention (EVP_SIGNATURE_fetch("HASH-ML-DSA",
 * ...) + EVP_PKEY_sign_init_ex2) that this bespoke, non-key-type-named
 * algorithm REQUIRES (there is no ctx-param "instance"-style override
 * for ML-DSA the way eddsa.c has for EdDSA -- see that file's own
 * p11prov_eddsa_instance_to_params). Without this, OpenSSL's own
 * evp_pkey_signature_init() (crypto/evp/signature.c) refuses the
 * operation with "signature type and key type incompatible": its
 * fallback compatibility check only accepts a fetched signature whose
 * OWN registered name equals the key's keymgmt name (or the keymgmt's
 * own default signature name) -- neither is ever "HASH-ML-DSA" for an
 * "ML-DSA-44/65/87" key. OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES is
 * OpenSSL's own real, documented mechanism for exactly this case (a
 * signature algorithm usable across multiple differently-named key
 * types) -- confirmed against the real vendored OpenSSL 3.6.3 source
 * (crypto/evp/signature.c's own query_key_types-vs-fallback branch),
 * not guessed. */
static const char **p11prov_hash_mldsa_query_key_types(void)
{
    static const char *key_types[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                                       NULL };
    return key_types;
}

const OSSL_DISPATCH p11prov_hash_mldsa_signature_functions[] = {
    DISPATCH_SIG_ELEM(hash_mldsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(hash_mldsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN, sign),
    DISPATCH_SIG_ELEM(hash_mldsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(mldsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(hash_mldsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(hash_mldsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_SIG_ELEM(hash_mldsa, QUERY_KEY_TYPES, query_key_types),
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
