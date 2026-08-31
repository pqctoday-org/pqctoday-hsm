/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* XMSS / XMSS^MT (remediation R41, phase 8) — CKM_XMSS / CKM_XMSSMT.
 *
 * REUSES sig/hss.c's own shape directly (the phase-6 note on R27 already
 * mandated reuse over copy, and the phase-8 plan's own R41 grounding
 * confirms it again) -- both are stateful, hash-based signature schemes
 * with the SAME operational constraints:
 *
 *   - Both engines' StatefulSignInit (SoftHSM_sign.cpp) explicitly disables
 *     multi-part operation for CKM_HSS/XMSS/XMSSMT ("Stateful signatures
 *     are 100% single-part (C_Sign only)") -- sig/hss.c's own file header
 *     already documents this for XMSS/XMSSMT too, so this is NOT
 *     re-derived here; it is the reason DIGEST_SIGN/VERIFY below
 *     accumulate in provider memory across update calls (mirroring
 *     composite.c's own tbs_buf under R7) rather than streaming real
 *     C_SignUpdate/C_VerifyUpdate calls.
 *   - No CK_*_ADDITIONAL_CONTEXT-style mechanism parameter: PKCS#11 v3.2
 *     SS6.66.6, verbatim, "This mechanism does not have a parameter" --
 *     the XMSS/XMSS^MT parameter set (RFC 8391 oid) travels on the KEY's
 *     own CKA_PARAMETER_SET, not a per-operation mechanism argument.
 *
 * Two mechanisms, not one: unlike HSS (a single "HSS" algorithm name, one
 * engine-documented default parameter set), XMSS and XMSS^MT are
 * registered as two separate signature algorithm names here (matching two
 * separate PKCS#11 mechanisms, CKM_XMSS/CKM_XMSSMT, and two separate key
 * types, CKK_XMSS/CKK_XMSSMT) -- p11prov_xmss_ctx carries an `is_mt` flag
 * set once at newctx time so the shared sign/verify/accumulate code stays
 * a single implementation.
 *
 * Sizing (sig==NULL queries) never touches the token, same reasoning as
 * HSS's own: XMSS/XMSS^MT signature length depends on the key's own
 * CKA_PARAMETER_SET (tree height, hash width, and — for MT — the number
 * of layers), computed by xmss_sig_size_for_key() (this file) from the
 * RFC 8391 SS4.2/SS4.2.3 formulas -- ported line-for-line from the Rust
 * engine's own get_sig_len() XMSS/XMSSMT arms (handlers.rs) so both
 * engines' size math stays provably in sync, same discipline sig/hss.c's
 * own lms_single_sig_len() already established for HSS. */
#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/err.h"

/* RFC 8391 IANA "XMSS" OID registry / SP 800-208 SS4. Bare hex to match
 * this project's C++ engine's own xmss_parse_oid() (params.c) convention
 * -- there is no canonical named CKP_XMSS_* table in the vendored
 * pkcs11t.h, only in the Rust engine's own constants.rs, whose exact
 * values these mirror (cross-checked against xmss_parse_oid /
 * xmssmt_parse_oid directly, not assumed identical). */
#define CKP_XMSS_SHA2_10_256 0x01UL
#define CKP_XMSS_SHA2_16_256 0x02UL
#define CKP_XMSS_SHA2_20_256 0x03UL
#define CKP_XMSS_SHAKE_10_256 0x07UL
#define CKP_XMSS_SHAKE_16_256 0x08UL
#define CKP_XMSS_SHAKE_20_256 0x09UL
#define CKP_XMSS_SHAKE256_16_256 0x11UL
#define CKP_XMSS_SHAKE256_20_256 0x12UL
#define CKP_XMSS_SHAKE256_10_192 0x13UL

#define CKP_XMSSMT_SHA2_20_2_256 0x01UL
#define CKP_XMSSMT_SHA2_20_4_256 0x02UL
#define CKP_XMSSMT_SHA2_40_2_256 0x03UL
#define CKP_XMSSMT_SHA2_40_4_256 0x04UL
#define CKP_XMSSMT_SHA2_40_8_256 0x05UL
#define CKP_XMSSMT_SHA2_60_3_256 0x06UL
#define CKP_XMSSMT_SHA2_60_6_256 0x07UL
#define CKP_XMSSMT_SHA2_60_12_256 0x08UL
#define CKP_XMSSMT_SHA2_20_2_512 0x09UL
#define CKP_XMSSMT_SHA2_40_2_512 0x0bUL
#define CKP_XMSSMT_SHA2_40_4_512 0x0cUL
#define CKP_XMSSMT_SHA2_40_8_512 0x0dUL
#define CKP_XMSSMT_SHA2_60_3_512 0x0eUL
#define CKP_XMSSMT_SHA2_60_6_512 0x0fUL
#define CKP_XMSSMT_SHA2_60_12_512 0x10UL
#define CKP_XMSSMT_SHAKE_20_2_256 0x11UL
#define CKP_XMSSMT_SHAKE_20_4_256 0x12UL
#define CKP_XMSSMT_SHAKE_40_2_256 0x13UL
#define CKP_XMSSMT_SHAKE_40_4_256 0x14UL
#define CKP_XMSSMT_SHAKE_40_8_256 0x15UL
#define CKP_XMSSMT_SHAKE_60_3_256 0x16UL
#define CKP_XMSSMT_SHAKE_60_6_256 0x17UL
#define CKP_XMSSMT_SHAKE_60_12_256 0x18UL

/* RFC 8391 SS4.2: sig = idx(4) + random(n) + WOTS+_sig(len*n) + auth_path(h*n).
 * w=16 Winternitz parameter throughout (the only value either engine's
 * xmss-reference vendoring supports) -- n=32 -> len=67 (SS3.1.1: len_1 =
 * ceil(8n/4) = 2n = 64, len_2 = floor(log2(len_1*15)/4)+1 = 3, len=67);
 * SHAKE256_10_192 is the one n=24 set SP 800-208 defines (len=51, h=10). */
static size_t xmss_sig_size(CK_ULONG param_set)
{
    size_t h;

    if (param_set == CKP_XMSS_SHAKE256_10_192) {
        return 4 + 24 + (51 + 10) * 24;
    }
    switch (param_set) {
    case CKP_XMSS_SHA2_16_256:
    case CKP_XMSS_SHAKE_16_256:
    case CKP_XMSS_SHAKE256_16_256:
        h = 16;
        break;
    case CKP_XMSS_SHA2_20_256:
    case CKP_XMSS_SHAKE_20_256:
    case CKP_XMSS_SHAKE256_20_256:
        h = 20;
        break;
    default:
        h = 10;
        break;
    }
    return 4 + 32 + 67 * 32 + h * 32;
}

/* RFC 8391 SS4.2.3: sig = idx_sig(ceil(h/8)) + random(n) + h*n [auth path
 * across all layers] + d*len*n [one WOTS+ sig per layer]. len=67 for
 * n=32, len=131 for n=64 (SS3.1.1, same w=16 as above). Only the n=32/256
 * variants are enumerated by name (matching the Rust engine's own
 * get_sig_len() XMSSMT arm exactly -- neither engine's own sizing table
 * names the SP 800-208 n=24 XMSSMT variants (oids 0x21-0x38, confirmed
 * against xmssmt_parse_oid), so this default-cases them to the (20,2,32)
 * shape same as Rust; a caller in that corner gets a size ESTIMATE
 * mismatch, not a wrong SIGNATURE -- PKCS#11's own two-call sizing idiom
 * (query, then real C_Sign) tolerates a low estimate via
 * CKR_BUFFER_TOO_SMALL retry). */
static size_t xmssmt_sig_size(CK_ULONG param_set)
{
    size_t h, d, n;

    switch (param_set) {
    case CKP_XMSSMT_SHA2_20_2_256:
    case CKP_XMSSMT_SHAKE_20_2_256:
        h = 20; d = 2; n = 32; break;
    case CKP_XMSSMT_SHA2_20_4_256:
    case CKP_XMSSMT_SHAKE_20_4_256:
        h = 20; d = 4; n = 32; break;
    case CKP_XMSSMT_SHA2_40_2_256:
    case CKP_XMSSMT_SHAKE_40_2_256:
        h = 40; d = 2; n = 32; break;
    case CKP_XMSSMT_SHA2_40_4_256:
    case CKP_XMSSMT_SHAKE_40_4_256:
        h = 40; d = 4; n = 32; break;
    case CKP_XMSSMT_SHA2_40_8_256:
    case CKP_XMSSMT_SHAKE_40_8_256:
        h = 40; d = 8; n = 32; break;
    case CKP_XMSSMT_SHA2_60_3_256:
    case CKP_XMSSMT_SHAKE_60_3_256:
        h = 60; d = 3; n = 32; break;
    case CKP_XMSSMT_SHA2_60_6_256:
    case CKP_XMSSMT_SHAKE_60_6_256:
        h = 60; d = 6; n = 32; break;
    case CKP_XMSSMT_SHA2_60_12_256:
    case CKP_XMSSMT_SHAKE_60_12_256:
        h = 60; d = 12; n = 32; break;
    case CKP_XMSSMT_SHA2_20_2_512:
        h = 20; d = 2; n = 64; break;
    case CKP_XMSSMT_SHA2_40_2_512:
        h = 40; d = 2; n = 64; break;
    case CKP_XMSSMT_SHA2_40_4_512:
        h = 40; d = 4; n = 64; break;
    case CKP_XMSSMT_SHA2_40_8_512:
        h = 40; d = 8; n = 64; break;
    case CKP_XMSSMT_SHA2_60_3_512:
        h = 60; d = 3; n = 64; break;
    case CKP_XMSSMT_SHA2_60_6_512:
        h = 60; d = 6; n = 64; break;
    case CKP_XMSSMT_SHA2_60_12_512:
        h = 60; d = 12; n = 64; break;
    default:
        h = 20; d = 2; n = 32; break;
    }
    size_t len = (n == 32) ? 67 : 131;
    return (h + 7) / 8 + n + h * n + d * len * n;
}

/* The one entry point sign/verify sizing and keymgmt.c's own
 * OSSL_PKEY_PARAM_MAX_SIZE actually call. Reads the key's own
 * CKA_PARAMETER_SET (p11prov_obj_get_key_param_set, the SAME generic
 * accessor ML-DSA/SLH-DSA/ML-KEM already use -- XMSS/XMSS^MT need no
 * XMSS-specific variant of it, PKCS#11 v3.2 SS6.66.6 mandates
 * CKA_PARAMETER_SET as the standard attribute, no legacy vendor-attribute
 * fallback needed on the provider side). Falls back to each family's own
 * default oid (matching the two engines' own keygen defaults) if a key
 * somehow has none -- defensive, not expected to fire for a key this
 * provider's own keymgmt generated. */
size_t xmss_sig_size_for_key(P11PROV_OBJ *key, bool is_mt)
{
    CK_ULONG param_set = p11prov_obj_get_key_param_set(key);

    if (is_mt) {
        if (param_set == CK_UNAVAILABLE_INFORMATION) {
            param_set = CKP_XMSSMT_SHA2_20_2_256;
        }
        return xmssmt_sig_size(param_set);
    }
    if (param_set == CK_UNAVAILABLE_INFORMATION) {
        param_set = CKP_XMSS_SHA2_10_256;
    }
    return xmss_sig_size(param_set);
}

struct p11prov_xmss_ctx {
    P11PROV_CTX *provctx;
    P11PROV_SIG_CTX *sigctx;
    bool is_mt;
    unsigned char *tbs_buf;
    size_t tbs_buf_len;
    size_t tbs_buf_cap;
};
typedef struct p11prov_xmss_ctx P11PROV_XMSS_CTX;

static void *xmss_sig_newctx(void *provctx, const char *properties,
                             bool is_mt)
{
    P11PROV_XMSS_CTX *ctx;

    P11PROV_debug("xmss sig newctx (is_mt=%d)", is_mt);

    ctx = OPENSSL_zalloc(sizeof(P11PROV_XMSS_CTX));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)provctx;
    ctx->is_mt = is_mt;
    ctx->sigctx = p11prov_sig_newctx((P11PROV_CTX *)provctx,
                                     is_mt ? CKM_XMSSMT : CKM_XMSS,
                                     properties);
    if (ctx->sigctx == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

static void *p11prov_xmss_sig_newctx(void *provctx, const char *properties)
{
    return xmss_sig_newctx(provctx, properties, false);
}

static void *p11prov_xmssmt_sig_newctx(void *provctx, const char *properties)
{
    return xmss_sig_newctx(provctx, properties, true);
}

static void p11prov_xmss_sig_freectx(void *vctx)
{
    P11PROV_XMSS_CTX *ctx = (P11PROV_XMSS_CTX *)vctx;

    P11PROV_debug("xmss sig freectx (ctx:%p)", vctx);

    if (ctx == NULL) {
        return;
    }
    p11prov_sig_freectx(ctx->sigctx);
    OPENSSL_clear_free(ctx->tbs_buf, ctx->tbs_buf_cap);
    OPENSSL_free(ctx);
}

/* Identical shape to sig/hss.c's own hss_accumulate() -- see that file's
 * header for why single-part accumulation, not a real C_SignUpdate/
 * C_VerifyUpdate stream, is the correct behavior for a stateful
 * hash-based signature scheme. */
static int xmss_accumulate(P11PROV_XMSS_CTX *ctx, const unsigned char *data,
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

static int p11prov_xmss_sign_init(void *vctx, void *provkey,
                                  const OSSL_PARAM params[])
{
    P11PROV_XMSS_CTX *ctx = (P11PROV_XMSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("xmss sign init (ctx=%p, key=%p, is_mt=%d)", vctx, provkey,
                  ctx ? ctx->is_mt : -1);

    ret = p11prov_sig_op_init(ctx->sigctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    /* PKCS#11 v3.2 SS6.66.6: "This mechanism does not have a parameter" --
     * the whole of it, same as CKM_HSS (sig/hss.c's own precedent). */
    ctx->sigctx->mechanism.mechanism = ctx->is_mt ? CKM_XMSSMT : CKM_XMSS;
    return RET_OSSL_OK;
}

static int p11prov_xmss_verify_init(void *vctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    P11PROV_XMSS_CTX *ctx = (P11PROV_XMSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("xmss verify init (ctx=%p, key=%p, is_mt=%d)", vctx,
                  provkey, ctx ? ctx->is_mt : -1);

    ret = p11prov_sig_op_init(ctx->sigctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    ctx->sigctx->mechanism.mechanism = ctx->is_mt ? CKM_XMSSMT : CKM_XMSS;
    return RET_OSSL_OK;
}

/* Plain SIGN/VERIFY: the whole message arrives in one call. */
static int p11prov_xmss_sign(void *vctx, unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs,
                             size_t tbslen)
{
    P11PROV_XMSS_CTX *ctx = (P11PROV_XMSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("xmss sign (ctx=%p)", vctx);

    if (sig == NULL) {
        if (siglen == NULL) {
            return RET_OSSL_ERR;
        }
        *siglen = xmss_sig_size_for_key(ctx->sigctx->key, ctx->is_mt);
        return RET_OSSL_OK;
    }

    ret = p11prov_sig_operate(ctx->sigctx, sig, siglen, sigsize,
                              (unsigned char *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_xmss_verify(void *vctx, const unsigned char *sig,
                               size_t siglen, const unsigned char *tbs,
                               size_t tbslen)
{
    P11PROV_XMSS_CTX *ctx = (P11PROV_XMSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("xmss verify (ctx=%p)", vctx);

    ret = p11prov_sig_operate(ctx->sigctx, (unsigned char *)sig, NULL, siglen,
                              (unsigned char *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

/* DIGEST_SIGN/VERIFY: pkeyutl -sign/-verify -rawin route here (see
 * sig/hss.c's own file-header comment for why -rawin means this, not
 * plain SIGN/VERIFY above). */
static int p11prov_xmss_digest_sign_init(void *vctx, const char *mdname,
                                         void *provkey,
                                         const OSSL_PARAM params[])
{
    (void)mdname; /* always NULL/ignored: XMSS hashes internally */
    return p11prov_xmss_sign_init(vctx, provkey, params);
}

static int p11prov_xmss_digest_verify_init(void *vctx, const char *mdname,
                                           void *provkey,
                                           const OSSL_PARAM params[])
{
    (void)mdname;
    return p11prov_xmss_verify_init(vctx, provkey, params);
}

static int p11prov_xmss_digest_sign_update(void *vctx,
                                           const unsigned char *data,
                                           size_t datalen)
{
    P11PROV_XMSS_CTX *ctx = (P11PROV_XMSS_CTX *)vctx;

    P11PROV_debug("xmss digest sign update (ctx=%p, datalen=%zu)", vctx,
                  datalen);

    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }
    return xmss_accumulate(ctx, data, datalen);
}

/* Same accumulator serves both directions — see sig/hss.c's identical
 * comment on its own twin. */
static int p11prov_xmss_digest_verify_update(void *vctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    return p11prov_xmss_digest_sign_update(vctx, data, datalen);
}

static int p11prov_xmss_digest_sign_final(void *vctx, unsigned char *sig,
                                          size_t *siglen, size_t sigsize)
{
    P11PROV_XMSS_CTX *ctx = (P11PROV_XMSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("xmss digest sign final (ctx=%p, sig=%p, sigsize=%zu)",
                  vctx, sig, sigsize);

    if (ctx == NULL || siglen == NULL) {
        return RET_OSSL_ERR;
    }

    if (sig == NULL) {
        /* Sizing query: same reasoning as sig/hss.c's own comment here --
         * EVP_DigestSign()'s one-shot wrapper skips UPDATE when
         * sigret==NULL, so this always arrives with an empty accumulator;
         * answer from the key's own real RFC 8391 size, no token round
         * trip. */
        *siglen = xmss_sig_size_for_key(ctx->sigctx->key, ctx->is_mt);
        return RET_OSSL_OK;
    }

    ret = p11prov_sig_operate(ctx->sigctx, sig, siglen, sigsize, ctx->tbs_buf,
                              ctx->tbs_buf_len);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_xmss_digest_verify_final(void *vctx,
                                            const unsigned char *sig,
                                            size_t siglen)
{
    P11PROV_XMSS_CTX *ctx = (P11PROV_XMSS_CTX *)vctx;
    CK_RV ret;

    P11PROV_debug("xmss digest verify final (ctx=%p, siglen=%zu)", vctx,
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

const OSSL_DISPATCH p11prov_xmss_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p11prov_xmss_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,
      (void (*)(void))p11prov_xmss_sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p11prov_xmss_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p11prov_xmss_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
      (void (*)(void))p11prov_xmss_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p11prov_xmss_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))p11prov_xmss_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))p11prov_xmss_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))p11prov_xmss_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))p11prov_xmss_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))p11prov_xmss_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))p11prov_xmss_digest_verify_final },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_xmssmt_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p11prov_xmssmt_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,
      (void (*)(void))p11prov_xmss_sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))p11prov_xmss_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p11prov_xmss_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
      (void (*)(void))p11prov_xmss_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))p11prov_xmss_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))p11prov_xmss_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))p11prov_xmss_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))p11prov_xmss_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))p11prov_xmss_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))p11prov_xmss_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))p11prov_xmss_digest_verify_final },
    { 0, NULL },
};
