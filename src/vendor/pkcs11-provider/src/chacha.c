/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* chacha.c -- CKM_CHACHA20 (bare stream cipher, PKCS#11 v3.2 SS6.21) and
 * CKM_CHACHA20_POLY1305 (AEAD, RFC 8439). Phase 5 R26.
 *
 * A separate file from cipher.c's AES machinery (as planned), but reusing
 * cipher.c's generic entry points (newctx/freectx/encrypt_init/
 * decrypt_init/update/final/skey_init, plus prep_mech's own CKM_CHACHA20/
 * CKM_CHACHA20_POLY1305 cases and the AEAD deferred-mechanism-parameter
 * machinery built for AES-GCM) via the SAME DISPATCH_TABLE_CIPHER_FN
 * macro AES uses -- that machinery had to become genuinely shared (not
 * AES-private) for GCM to work at all, per this item's own prerequisite
 * fix, so ChaCha20-Poly1305 is the second, not the first, user of it.
 *
 * Both mechanisms are fixed 256-bit key (CKK_CHACHA20), confirmed against
 * this engine's own OSSLChaCha20.cpp ("ChaCha20-Poly1305 only supports
 * 256-bit keys") and SoftHSM_cipher.cpp's CKM_CHACHA20 case (same key
 * type). CKM_CHACHA20's own CK_CHACHA20_PARAMS construction (splitting
 * OpenSSL's flat 16-byte counter[4]||nonce[12] IV into the two separate
 * pointers PKCS#11 wants) and CKM_CHACHA20_POLY1305's deferred AEAD
 * mechanism-parameter construction both live in cipher.c's own
 * p11prov_cipher_prep_mech() -- see that function's own comments. */
#include "provider.h"

#if SKEY_SUPPORT == 1

#include "cipher.h"
#include <string.h>

DISPATCH_CIPHER_FN(chacha20, dupctx);
DISPATCH_CIPHER_FN(chacha20, cipher);
DISPATCH_CIPHER_FN(chacha20, get_ctx_params);
DISPATCH_CIPHER_FN(chacha20, gettable_ctx_params);
DISPATCH_CIPHER_FN(chacha20, settable_ctx_params);
/* set_ctx_params deliberately NOT forward-declared here (unlike its
 * five siblings above): p11prov_cipher_family_set_ctx_params (cipher.c)
 * calls this across the file boundary, so it needs real external
 * linkage -- DISPATCH_CIPHER_FN's own forward-declaration form declares
 * static, and C's linkage rules make that permanent for the rest of
 * this translation unit even once the real (non-static-looking)
 * definition below is reached. The real definition, appearing before
 * its own use in the DISPATCH_TABLE_CIPHER_FN invocation at the bottom
 * of this file, is sufficient on its own. */

static int p11prov_chacha20_get_params(OSSL_PARAM params[], int size,
                                       int mode, CK_ULONG mechanism)
{
    int ciph_mode;
    int flags = mode & MODE_flags_mask;
    size_t keysize = size / 8; /* always 32 -- both mechanisms are 256-bit only */
    size_t blocksize;
    size_t ivsize;

    /* Switches on `mechanism` (the real CKM_* constant, passed through
     * unambiguously by DISPATCH_TABLE_CIPHER_FN's own macro parameter)
     * rather than decoding the `mode` bitmask -- MODE_poly1305's own
     * value embeds MODE_flag_aead, and `case MODE_poly1305:` matching
     * against `mode & MODE_modes_mask` needs exact-precedence care that
     * cost real debugging time to get right once already (see cipher.c's
     * own MODE_gcm case comment); keying off `mechanism` sidesteps that
     * whole class of bug entirely. */
    switch (mechanism) {
    case CKM_CHACHA20:
        /* CKM_CHACHA20: OpenSSL's own "ChaCha20" reports block_size=1
         * (matches this engine's own getBlockSize()) and a flat 16-byte
         * IV (counter[4] || nonce[12] -- see prep_mech's own comment). */
        ciph_mode = EVP_CIPH_STREAM_CIPHER;
        blocksize = 1;
        ivsize = 16;
        break;
    case CKM_CHACHA20_POLY1305:
        /* CKM_CHACHA20_POLY1305: block_size is NOT 16 -- see cipher.h's
         * own AEAD_DECRYPT_MAX_MSG_LEN comment for the full mechanism
         * (decrypt-only issue: encrypt streams ciphertext out
         * immediately and never needs this headroom; OpenSSL's own
         * EVP_DecryptFinal_ex hardcodes the buffer it gives final() to
         * exactly this value, with no per-message way to enlarge it).
         * RFC 8439's own nonce is a flat 12 bytes, no separate counter. */
        ciph_mode = EVP_CIPH_GCM_MODE; /* nearest existing AEAD constant */
        blocksize = AEAD_DECRYPT_MAX_MSG_LEN;
        ivsize = 12;
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return RET_OSSL_ERR;
    }

    return p11prov_cipher_get_params(params, ciph_mode, flags, keysize,
                                     blocksize, ivsize);
}

static void *p11prov_chacha20_dupctx(void *ctx)
{
    return NULL;
}

static int p11prov_chacha20_cipher(void *ctx, unsigned char *out,
                                   size_t *outl, size_t outsize,
                                   const unsigned char *in, size_t inl)
{
    return RET_OSSL_ERR;
}

static int p11prov_chacha20_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    OSSL_PARAM *p;
    int ret;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, cctx->keysize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p) {
        /* Real bug, caught live -- see cipher.c's own p11prov_aes_
         * get_ctx_params IVLEN comment for the full mechanism:
         * EVP_CIPHER_CTX_get_iv_length() calls THIS function to compute
         * the ivlen it then passes to encrypt_init/decrypt_init, so
         * gating on cctx->is_aead here always sees it false at that
         * critical first call (set later, by prep_mech). Key off
         * cctx->mech.mechanism (reliable from newctx() onward) for the
         * mechanism's own default instead; prefer the real negotiated
         * value once one exists (post-init). */
        size_t ivlen;
        if (cctx->mech.mechanism == CKM_CHACHA20_POLY1305) {
            ivlen = (cctx->is_aead && cctx->aead_ivlen > 0) ? cctx->aead_ivlen
                                                             : 12;
        } else {
            ivlen = 16;
        }
        ret = OSSL_PARAM_set_size_t(p, ivlen);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    /* is_aead (CHACHA20_POLY1305): the real nonce is aead_iv/aead_ivlen
     * (stashed by prep_mech's set_aead_iv() call, same as GCM). Stream
     * CHACHA20: the flat 16-byte counter||nonce blob lives in
     * chacha_iv_bytes, backing the CK_CHACHA20_PARAMS mech.pParameter
     * already points into (see prep_mech's own CKM_CHACHA20 case). */
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p) {
        if (cctx->is_aead) {
            ret = OSSL_PARAM_set_octet_string(p, cctx->aead_iv,
                                              cctx->aead_ivlen);
        } else {
            ret = OSSL_PARAM_set_octet_string(p, cctx->chacha_iv_bytes,
                                              sizeof(cctx->chacha_iv_bytes));
        }
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p) {
        if (cctx->is_aead) {
            ret = OSSL_PARAM_set_octet_string(p, cctx->aead_iv,
                                              cctx->aead_ivlen);
        } else {
            ret = OSSL_PARAM_set_octet_string(p, cctx->chacha_iv_bytes,
                                              sizeof(cctx->chacha_iv_bytes));
        }
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    if (cctx->is_aead) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p) {
            ret = OSSL_PARAM_set_octet_string(p, cctx->tag, cctx->taglen);
            if (ret != RET_OSSL_OK) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return RET_OSSL_ERR;
            }
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p) {
            ret = OSSL_PARAM_set_size_t(p, 16);
            if (ret != RET_OSSL_OK) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return RET_OSSL_ERR;
            }
        }
    }

    return RET_OSSL_OK;
}

int p11prov_chacha20_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;
    bool tag_consumed = false;
    int ret;

    ret = p11prov_cipher_aead_set_tag_param(ctx, params, &tag_consumed);
    if (ret != RET_OSSL_OK) {
        return ret;
    }
    if (tag_consumed) {
        return RET_OSSL_OK;
    }

    /* Neither mechanism has any other settable param (no padding, no
     * TLS legacy handling -- both stream-shaped, unlike AES-CBC) once
     * the tag is out of the way. */
    return RET_OSSL_OK;
}

static const OSSL_PARAM p11prov_chacha20_stream_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM p11prov_chacha20_poly1305_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *
p11prov_chacha20_gettable_ctx_params(void *vctx, void *provctx)
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;

    if (!ctx || ctx->mech.mechanism == CKM_CHACHA20) {
        return p11prov_chacha20_stream_gettable_ctx_params;
    }
    return p11prov_chacha20_poly1305_gettable_ctx_params;
}

static const OSSL_PARAM p11prov_chacha20_poly1305_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *
p11prov_chacha20_settable_ctx_params(void *vctx, void *provctx)
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;

    if (ctx && ctx->mech.mechanism == CKM_CHACHA20_POLY1305) {
        return p11prov_chacha20_poly1305_settable_ctx_params;
    }
    return NULL;
}

DISPATCH_TABLE_CIPHER_FN(chacha20, 256, stream, CKM_CHACHA20);
DISPATCH_TABLE_CIPHER_FN(chacha20, 256, poly1305, CKM_CHACHA20_POLY1305);

#endif /* SKEY_SUPPORT == 1 */
