/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* HSS/LMS (phase 4 R9) — CKM_HSS.
 *
 * The engine's own StatefulSignInit (SoftHSM_sign.cpp) explicitly disables
 * multi-part operation for CKM_HSS/XMSS/XMSSMT ("Stateful signatures are
 * 100% single-part (C_Sign only)"). This provider's two generic reuse
 * candidates for DIGEST_SIGN/VERIFY's streaming shape both assume
 * something HSS doesn't have:
 *
 *   - p11prov_sig_digest_update/final calls real C_SignUpdate/
 *     C_VerifyUpdate — unsupported for CKM_HSS (confirmed above).
 *   - P11PROV_SIG_CTX's fallback_digest path pre-hashes the message in
 *     SOFTWARE (EVP_DigestUpdate/Final) then signs the digest — correct
 *     for RSA/ECDSA-style "sign(digest)" algorithms, but wrong for a
 *     hash-internal algorithm like HSS/LMS, whose own RFC 8554 hashing
 *     must run over the untouched full message, not an externally
 *     pre-hashed 32-byte stand-in.
 *
 * So DIGEST_SIGN/VERIFY here accumulate the raw message in provider
 * memory across possibly-many update calls (mirroring composite.c's own
 * tbs_buf, built for the identical constraint under R7), then make ONE
 * p11prov_sig_operate call — the real C_Sign/C_Verify — at FINAL time.
 * A thin wrapper around P11PROV_SIG_CTX rather than a new field on that
 * widely-shared struct, same reasoning as composite.c's own wrapper.
 *
 * Both plain SIGN/VERIFY (openssl pkeyutl -sign, no -rawin — used by
 * this file's own harness proof) and DIGEST_SIGN/VERIFY (pkeyutl -sign
 * -rawin, per apps/pkeyutl.c's own EVP_DigestSignInit_ex(...,mdname=
 * NULL,...) call for -rawin — confirmed by reading that source, not
 * assumed; this corrects an earlier, wrong assumption in this project's
 * own R7 composite.c work that -rawin meant plain SIGN/VERIFY) reach the
 * one-shot accumulate-then-C_Sign path below either way.
 *
 * No CK_SIGN_ADDITIONAL_CONTEXT-style mechanism params — CKM_HSS takes
 * none (confirmed live: SoftHSM_sign.cpp's StatefulSignInit reads only
 * pMechanism->mechanism, never pParameter).
 *
 * Sizing queries (sig==NULL) never reach the token, and never depend on
 * the accumulated buffer: p11prov_sig_operate() itself rejects a NULL
 * sig outright (signature.c: "if (sig == NULL) return CKR_ARGUMENTS_
 * BAD;"), and OpenSSL's own EVP_DigestSign() one-shot wrapper (crypto/
 * evp/m_sigver.c) only calls DIGEST_SIGN_UPDATE when sigret != NULL —
 * so the *first* of pkeyutl -rawin's two EVP_DigestSign() calls (the
 * sizing query) always arrives at FINAL with an empty accumulator, real
 * message bytes only showing up on the second, real-sigret call. So,
 * matching ML-DSA's own p11prov_mldsa_sig_size()/CKP_ML_DSA_* table
 * precedent, sizing answers a fixed constant instead of touching the
 * token: HSS signature length depends only on (L, LMS, LM-OTS), never
 * on message length, and this provider currently only ever generates
 * the engine's single default combination (L=1, LMS_SHA256_N32_H5,
 * LMOTS_SHA256_N32_W8) — see HSS_L1_DEFAULT_SIG_SIZE below for the
 * RFC 8554 byte-accounting that produces 1296. */
#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/err.h"

/* RFC 8554 §4.3/§4.5/§4.6, engine default params (L=1, LMS_SHA256_N32_H5,
 * LMOTS_SHA256_N32_W8; n=32, h=5, w=8, p=34):
 *   LM-OTS sig = u32str(type) + C[n] + y[p][n]  = 4 + 32 + 34*32 = 1124
 *   LMS sig    = u32str(q) + ots_sig + u32str(type) + path[h][n]
 *              = 4 + 1124 + 4 + 5*32                          = 1292
 *   HSS sig    = u32str(Nspk=L-1=0) + lms_sig                 = 4 + 1292
 *              = 1296 */
#define HSS_L1_DEFAULT_SIG_SIZE 1296

struct p11prov_hss_ctx {
    P11PROV_CTX *provctx;
    P11PROV_SIG_CTX *sigctx;
    unsigned char *tbs_buf;
    size_t tbs_buf_len;
    size_t tbs_buf_cap;
};
typedef struct p11prov_hss_ctx P11PROV_HSS_CTX;

static void *p11prov_hss_sig_newctx(void *provctx, const char *properties)
{
    P11PROV_HSS_CTX *ctx;

    P11PROV_debug("hss sig newctx");

    ctx = OPENSSL_zalloc(sizeof(P11PROV_HSS_CTX));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)provctx;
    ctx->sigctx = p11prov_sig_newctx((P11PROV_CTX *)provctx, CKM_HSS,
                                     properties);
    if (ctx->sigctx == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

static void p11prov_hss_sig_freectx(void *vctx)
{
    P11PROV_HSS_CTX *ctx = (P11PROV_HSS_CTX *)vctx;

    P11PROV_debug("hss sig freectx (ctx:%p)", vctx);

    if (ctx == NULL) {
        return;
    }
    p11prov_sig_freectx(ctx->sigctx);
    OPENSSL_clear_free(ctx->tbs_buf, ctx->tbs_buf_cap);
    OPENSSL_free(ctx);
}

static int hss_accumulate(P11PROV_HSS_CTX *ctx, const unsigned char *data,
                          size_t datalen)
{
    size_t need;

    if (datalen == 0) {
        return RET_OSSL_OK;
    }
    need = ctx->tbs_buf_len + datalen;
    if (need < ctx->tbs_buf_len) {
        return RET_OSSL_ERR; /* overflow */
    }
    if (need > ctx->tbs_buf_cap) {
        size_t newcap = ctx->tbs_buf_cap == 0 ? 4096 : ctx->tbs_buf_cap;
        unsigned char *nb;
        while (newcap < need) {
            if (newcap > SIZE_MAX / 2) {
                return RET_OSSL_ERR;
            }
            newcap *= 2;
        }
        nb = OPENSSL_realloc(ctx->tbs_buf, newcap);
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

static int p11prov_hss_sign_init(void *vctx, void *provkey,
                                 const OSSL_PARAM params[])
{
    P11PROV_HSS_CTX *ctx = (P11PROV_HSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("hss sign init (ctx=%p, key=%p)", vctx, provkey);

    ret = p11prov_sig_op_init(ctx->sigctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    /* p11prov_sig_newctx() leaves mechanism.mechanism at the
     * CK_UNAVAILABLE_INFORMATION sentinel; every algorithm must set its
     * real mechanism before p11prov_sig_operate() (see ML-DSA's own
     * p11prov_mldsa_set_mechanism() for the established precedent). CKM_HSS
     * takes no CK_MECHANISM parameter, so this is the whole of it. */
    ctx->sigctx->mechanism.mechanism = CKM_HSS;
    return RET_OSSL_OK;
}

static int p11prov_hss_verify_init(void *vctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    P11PROV_HSS_CTX *ctx = (P11PROV_HSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("hss verify init (ctx=%p, key=%p)", vctx, provkey);

    ret = p11prov_sig_op_init(ctx->sigctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    ctx->sigctx->mechanism.mechanism = CKM_HSS;
    return RET_OSSL_OK;
}

/* Plain SIGN/VERIFY: the whole message arrives in one call, so sign
 * straight through with no accumulation needed. */
static int p11prov_hss_sign(void *vctx, unsigned char *sig, size_t *siglen,
                            size_t sigsize, const unsigned char *tbs,
                            size_t tbslen)
{
    P11PROV_HSS_CTX *ctx = (P11PROV_HSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("hss sign (ctx=%p)", vctx);

    if (sig == NULL) {
        if (siglen == NULL) {
            return RET_OSSL_ERR;
        }
        *siglen = HSS_L1_DEFAULT_SIG_SIZE;
        return RET_OSSL_OK;
    }

    ret = p11prov_sig_operate(ctx->sigctx, sig, siglen, sigsize,
                              (unsigned char *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_hss_verify(void *vctx, const unsigned char *sig,
                              size_t siglen, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_HSS_CTX *ctx = (P11PROV_HSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("hss verify (ctx=%p)", vctx);

    ret = p11prov_sig_operate(ctx->sigctx, (unsigned char *)sig, NULL, siglen,
                              (unsigned char *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

/* DIGEST_SIGN/VERIFY: pkeyutl -sign/-verify -rawin route here (see the
 * file-header comment for why -rawin means this, not plain SIGN/VERIFY
 * above). Accumulate raw bytes across update calls, one real C_Sign/
 * C_Verify at final time. */
static int p11prov_hss_digest_sign_init(void *vctx, const char *mdname,
                                        void *provkey,
                                        const OSSL_PARAM params[])
{
    (void)mdname; /* always NULL/ignored: HSS hashes internally */
    return p11prov_hss_sign_init(vctx, provkey, params);
}

static int p11prov_hss_digest_verify_init(void *vctx, const char *mdname,
                                          void *provkey,
                                          const OSSL_PARAM params[])
{
    (void)mdname;
    return p11prov_hss_verify_init(vctx, provkey, params);
}

static int p11prov_hss_digest_sign_update(void *vctx,
                                          const unsigned char *data,
                                          size_t datalen)
{
    P11PROV_HSS_CTX *ctx = (P11PROV_HSS_CTX *)vctx;

    P11PROV_debug("hss digest sign update (ctx=%p, datalen=%zu)", vctx,
                  datalen);

    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }
    return hss_accumulate(ctx, data, datalen);
}

/* Same accumulator serves both directions — verify's "update" phase
 * collects the same raw message bytes sign's does. */
static int p11prov_hss_digest_verify_update(void *vctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    return p11prov_hss_digest_sign_update(vctx, data, datalen);
}

static int p11prov_hss_digest_sign_final(void *vctx, unsigned char *sig,
                                         size_t *siglen, size_t sigsize)
{
    P11PROV_HSS_CTX *ctx = (P11PROV_HSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("hss digest sign final (ctx=%p, sig=%p, sigsize=%zu)", vctx,
                  sig, sigsize);

    if (ctx == NULL || siglen == NULL) {
        return RET_OSSL_ERR;
    }

    if (sig == NULL) {
        /* Sizing query: per the file-header comment, this arrives with
         * an empty accumulator (EVP_DigestSign()'s one-shot wrapper
         * skips UPDATE when sigret==NULL) and p11prov_sig_operate()
         * itself refuses a NULL sig outright — so answer from the fixed
         * RFC 8554 size, no token round trip. */
        *siglen = HSS_L1_DEFAULT_SIG_SIZE;
        return RET_OSSL_OK;
    }

    ret = p11prov_sig_operate(ctx->sigctx, sig, siglen, sigsize, ctx->tbs_buf,
                              ctx->tbs_buf_len);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_hss_digest_verify_final(void *vctx,
                                           const unsigned char *sig,
                                           size_t siglen)
{
    P11PROV_HSS_CTX *ctx = (P11PROV_HSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("hss digest verify final (ctx=%p, siglen=%zu)", vctx,
                  siglen);

    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_operate(ctx->sigctx, (unsigned char *)sig, NULL, siglen,
                              ctx->tbs_buf, ctx->tbs_buf_len);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_hss_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p11prov_hss_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,
      (void (*)(void))p11prov_hss_sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p11prov_hss_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p11prov_hss_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
      (void (*)(void))p11prov_hss_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p11prov_hss_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))p11prov_hss_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))p11prov_hss_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))p11prov_hss_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))p11prov_hss_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))p11prov_hss_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))p11prov_hss_digest_verify_final },
    { 0, NULL },
};
