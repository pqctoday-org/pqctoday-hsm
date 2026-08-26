/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"

#if SKEY_SUPPORT == 1

#include "cipher.h"
#include "openssl/prov_ssl.h"
#include "openssl/rand.h"
#include <string.h>

#define MAX_PADDING 256;
#define AESBLOCK 16 /* 128 bits for all AES modes */

/* cipher, X (as opposed to aes, X) forward declarations moved to
 * cipher.h as real (non-static) prototypes in phase 5 R26 -- chacha.c
 * reuses these definitions directly, so DISPATCH_CIPHER_FN's own static
 * forward-declaration form (correct for the aes-private ones below) can
 * no longer be used for them here. */
DISPATCH_CIPHER_FN(aes, dupctx);
DISPATCH_CIPHER_FN(aes, cipher);
DISPATCH_CIPHER_FN(aes, get_ctx_params);
DISPATCH_CIPHER_FN(aes, set_ctx_params);
DISPATCH_CIPHER_FN(aes, gettable_ctx_params);
DISPATCH_CIPHER_FN(aes, settable_ctx_params);

void *p11prov_cipher_newctx(void *provctx, int size, CK_ULONG mechanism)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    struct p11prov_cipher_ctx *cctx;

    P11PROV_debug("New Cipher context for mechanism %ld (key size: %d)",
                  mechanism, size);

    cctx = OPENSSL_zalloc(sizeof(struct p11prov_cipher_ctx));
    if (cctx == NULL) {
        return NULL;
    }

    cctx->provctx = ctx;
    cctx->mech.mechanism = mechanism;
    cctx->keysize = size / 8;

    /* OpenSSL Pads by default */
    cctx->pad = true;

    return cctx;
}

static const OSSL_PARAM cipher_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM *p11prov_cipher_gettable_params(void *provctx)
{
    return cipher_gettable_params;
}

static struct {
    const char *name;
    int flag;
} param_to_flag[] = {
    { OSSL_CIPHER_PARAM_AEAD, MODE_flag_aead },
    { OSSL_CIPHER_PARAM_CUSTOM_IV, MODE_flag_custom_iv },
    { OSSL_CIPHER_PARAM_CTS, MODE_flag_cts },
    { OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, MODE_flag_tls1_mb },
    { OSSL_CIPHER_PARAM_HAS_RAND_KEY, MODE_flag_rand_key },
    { NULL, 0 },
};

int p11prov_cipher_get_params(OSSL_PARAM params[], unsigned int mode,
                                     int flags, size_t keysize,
                                     size_t blocksize, size_t ivsize)
{
    OSSL_PARAM *p;
    int ret;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p) {
        ret = OSSL_PARAM_set_uint(p, mode);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    for (int i = 0; param_to_flag[i].name != NULL; i++) {
        p = OSSL_PARAM_locate(params, param_to_flag[i].name);
        if (p) {
            int flag = 0;
            if ((flags & param_to_flag[i].flag) != 0) {
                flag = 1;
            }
            ret = OSSL_PARAM_set_int(p, flag);
            if (ret != RET_OSSL_OK) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return RET_OSSL_ERR;
            }
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, keysize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, blocksize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, ivsize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_aes_get_params(OSSL_PARAM params[], int size, int mode,
                                  CK_ULONG mechanism)
{
    int ciph_mode = 0;
    int flags = mode & MODE_flags_mask;
    size_t keysize = size / 8;
    size_t blocksize = AESBLOCK;
    size_t ivsize = 16; /* 128 bits for all modes but ECB */

    switch (mode & MODE_modes_mask) {
    case MODE_ecb:
        ciph_mode = EVP_CIPH_ECB_MODE;
        break;
    case MODE_cbc:
        ciph_mode = EVP_CIPH_CBC_MODE;
        break;
    case MODE_ofb:
        ciph_mode = EVP_CIPH_OFB_MODE;
        break;
    case MODE_cfb:
        ciph_mode = EVP_CIPH_CFB_MODE;
        break;
    case MODE_ctr:
        ciph_mode = EVP_CIPH_CTR_MODE;
        break;
    case MODE_gcm & MODE_modes_mask:
        /* phase 5 R26 prerequisite: was missing entirely -- this whole
         * function returned RET_OSSL_ERR for GCM before, so even a
         * caller's basic EVP_CIPHER_fetch()-adjacent get_params query
         * failed, independent of GCM's own dead-registration bug in
         * provider.c. `& MODE_modes_mask` here matters: MODE_gcm's own
         * value already carries MODE_flag_aead, but the switch above
         * masks that bit off before comparing -- `case MODE_gcm:` alone
         * silently never matches (caught live, hard propquery fetch of
         * AES-256-GCM failing where a soft one had masked it). */
        ciph_mode = EVP_CIPH_GCM_MODE;
        ivsize = 12; /* conventional/recommended GCM IV length */
        /* decrypt-only issue -- see cipher.h's own AEAD_DECRYPT_MAX_
         * MSG_LEN comment for the full mechanism (encrypt streams
         * ciphertext out immediately and never needs this headroom). */
        blocksize = AEAD_DECRYPT_MAX_MSG_LEN;
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return RET_OSSL_ERR;
    }

    if (ciph_mode == EVP_CIPH_ECB_MODE) {
        ivsize = 0;
    }

    return p11prov_cipher_get_params(params, ciph_mode, flags, keysize,
                                     blocksize, ivsize);
};

void p11prov_cipher_freectx(void *ctx)
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;

    if (!cctx) {
        return;
    }

    if (cctx->session) {
        if (cctx->session_state == CIPHER_SESS_INITIALIZED) {
            /* Finalize any operation to avoid leaving a hanging
             * operation on this session. Ignore return errors here
             * intentionally as errors can be returned if the operation was
             * internally finalized because of a previous internal token
             * error state and, in any case, not much to be done. */
            CK_RV ret;
            CK_SESSION_HANDLE sess = p11prov_session_handle(cctx->session);
            if (cctx->operation == CKF_ENCRYPT) {
                ret = p11prov_EncryptInit(cctx->provctx, sess, NULL,
                                          CK_INVALID_HANDLE);
            } else {
                ret = p11prov_DecryptInit(cctx->provctx, sess, NULL,
                                          CK_INVALID_HANDLE);
            }
            if (ret != CKR_OK) {
                /* NSS softokn has a broken interface and is incapable of
                 * dropping operations on sessions returning a generic
                 * CKR_MECHANISM_PARAM_INVALID when the mechanism is set to
                 * NULL. Attempt to force cancellation via C_SessionCancel. */
                ret =
                    p11prov_SessionCancel(cctx->provctx, sess, cctx->operation);
            }
            if (ret != CKR_OK) {
                /* When this happens the session becomes broken as
                 * we can't initialize operations on it anymore */
                p11prov_session_mark_broken(cctx->session);
            }
            cctx->session_state = CIPHER_SESS_FINALIZED;
        }
        p11prov_return_session(cctx->session);
    }

    p11prov_obj_free(cctx->key);
    OPENSSL_clear_free(cctx->mech.pParameter, cctx->mech.ulParameterLen);
    OPENSSL_clear_free(cctx->tlsmac, cctx->tlsmacsize);
    OPENSSL_clear_free(cctx->aead_iv, cctx->aead_ivlen);
    OPENSSL_clear_free(cctx->aad, cctx->aadcap);
    OPENSSL_clear_free(cctx, sizeof(struct p11prov_cipher_ctx));
}

static void *p11prov_aes_dupctx(void *ctx)
{
    return NULL;
}

static int set_iv(struct p11prov_cipher_ctx *ctx, const unsigned char *iv,
                  size_t ivlen)
{
    /* Free parameter first, as OpenSSL apparently can "init" without
     * keys and just set the IV, and then re-init again with the IV
     * or even set the IV again via parameters ... */
    if (ctx->mech.pParameter) {
        OPENSSL_clear_free(ctx->mech.pParameter, ctx->mech.ulParameterLen);
        ctx->mech.pParameter = NULL;
        ctx->mech.ulParameterLen = 0;
    }
    /* If IV is null it means the app is either trying to clear a context
     * for reuse or did the initialization w/o IV and intends to init again
     * or pass the IV via params, ether way just bail out, the mech will
     * fail to initialize later if the application forgets to set the IV
     * and the mechanism requires it */
    if (iv != NULL && ivlen != 0) {
        ctx->mech.pParameter = OPENSSL_memdup(iv, ivlen);
        if (!ctx->mech.pParameter) {
            return CKR_HOST_MEMORY;
        }
        ctx->mech.ulParameterLen = ivlen;
    }
    return CKR_OK;
}

static int p11prov_aes_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
int p11prov_chacha20_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

/* Dispatches to the mechanism-family-specific set_ctx_params -- prep_mech
 * itself is shared across every cipher this provider registers, so it
 * cannot hardcode a single family's params function the way the old
 * AES-only code did (that hardcode is exactly why an AES-shaped
 * set_ctx_params was being run, harmlessly by accident, for every other
 * mechanism too -- harmless only because nothing else was registered
 * yet). */
static int p11prov_cipher_family_set_ctx_params(struct p11prov_cipher_ctx *ctx,
                                                const OSSL_PARAM params[])
{
    switch (ctx->mech.mechanism) {
    case CKM_CHACHA20:
    case CKM_CHACHA20_POLY1305:
        return p11prov_chacha20_set_ctx_params(ctx, params);
    default:
        return p11prov_aes_set_ctx_params(ctx, params);
    }
}

/* Starts (or restarts, for context reuse) this ctx's AEAD bookkeeping:
 * stash the IV, forget any AAD/tag left over from a prior operation on
 * the same ctx, and mark the mechanism parameter as not-yet-built. The
 * real CK_GCM_PARAMS/CK_SALSA20_CHACHA20_POLY1305_PARAMS can only be
 * built once all AAD has arrived -- see p11prov_cipher_ensure_session(). */
static CK_RV set_aead_iv(struct p11prov_cipher_ctx *ctx,
                         const unsigned char *iv, size_t ivlen)
{
    OPENSSL_clear_free(ctx->aead_iv, ctx->aead_ivlen);
    ctx->aead_iv = NULL;
    ctx->aead_ivlen = 0;
    OPENSSL_clear_free(ctx->aad, ctx->aadcap);
    ctx->aad = NULL;
    ctx->aadlen = 0;
    ctx->aadcap = 0;
    ctx->is_aead = true;
    ctx->aead_ready = false;
    ctx->taglen = 0;
    ctx->tag_set = false;

    if (iv != NULL && ivlen != 0) {
        ctx->aead_iv = OPENSSL_memdup(iv, ivlen);
        if (!ctx->aead_iv) {
            return CKR_HOST_MEMORY;
        }
        ctx->aead_ivlen = ivlen;
    }
    return CKR_OK;
}

static CK_RV p11prov_cipher_prep_mech(struct p11prov_cipher_ctx *ctx,
                                      const unsigned char *iv, size_t ivlen,
                                      const OSSL_PARAM params[])
{
    bool param_as_iv = false;
    CK_RV rv = CKR_OK;
    int ret;

    switch (ctx->mech.mechanism) {
    case CKM_AES_ECB:
        /* ECB has no ck params */
        break;

    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
    case CKM_AES_CTS:
        param_as_iv = true;
        break;

    case CKM_AES_CTR: {
        /* CK_AES_CTR_PARAMS{ulCounterBits, cb[16]} -- NOT a bare IV blob
         * (unlike CBC above); 128 matches OpenSSL's own CTR semantics
         * (the caller's whole 16-byte IV is the starting counter block,
         * incremented as one 128-bit big-endian value -- no separate
         * "counter width" concept on the OpenSSL side to preserve). */
        CK_AES_CTR_PARAMS ctr_params;

        if (iv == NULL || ivlen != 16) {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        OPENSSL_clear_free(ctx->mech.pParameter, ctx->mech.ulParameterLen);
        ctx->mech.pParameter = NULL;
        ctx->mech.ulParameterLen = 0;

        ctr_params.ulCounterBits = 128;
        memcpy(ctr_params.cb, iv, 16);
        ctx->mech.pParameter = OPENSSL_memdup(&ctr_params, sizeof(ctr_params));
        if (!ctx->mech.pParameter) {
            return CKR_HOST_MEMORY;
        }
        ctx->mech.ulParameterLen = sizeof(ctr_params);
        break;
    }

    case CKM_AES_OFB:
    case CKM_AES_CFB128:
    case CKM_AES_CFB1:
    case CKM_AES_CFB8:
        /* TODO -- unlike CTR/GCM (phase 5 R26 prerequisite), still
         * genuinely unimplemented: none of these were in this item's
         * own scope.
         *
         * remediation R32 (2026-08-26): checked both engines directly --
         * neither implements OFB or any CFB* variant (SoftHSM.cpp's
         * symmetric dispatch handles exactly ECB/CBC/CBC_PAD/CTR/GCM/
         * CHACHA20/CHACHA20_POLY1305; the Rust engine has no trace of
         * them either). This stub therefore fronts mechanisms that do
         * not exist behind it -- finishing it here would still return
         * CKR_MECHANISM_INVALID (or worse, a confusing failure further
         * down) with no engine to actually drive. Implementing these for
         * real needs engine work FIRST, in both engines, with their own
         * test suites, before this provider-side stub is worth touching
         * again. */
        return CKR_MECHANISM_INVALID;

    case CKM_AES_GCM:
    case CKM_CHACHA20_POLY1305:
        /* AAD hasn't arrived yet (see set_aead_iv()'s own comment) --
         * the mechanism parameter is built later, in
         * p11prov_cipher_ensure_session(). */
        rv = set_aead_iv(ctx, iv, ivlen);
        if (rv != CKR_OK) {
            return rv;
        }
        break;

    case CKM_CHACHA20: {
        /* CK_CHACHA20_PARAMS wants the counter and nonce as two separate
         * pointers; OpenSSL's own EVP_chacha20 IV convention (see
         * OSSLChaCha20.cpp's own comment, confirmed against this
         * engine's own parseChaCha20Params()) packs them as one flat
         * 16-byte blob: counter[4] || nonce[12]. chacha_iv_bytes is a
         * fixed field on ctx (not separately allocated) so its lifetime
         * trivially matches the pointers a CK_CHACHA20_PARAMS built from
         * it needs to keep pointing at. */
        CK_CHACHA20_PARAMS chacha_params;

        if (iv == NULL || ivlen != 16) {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        OPENSSL_clear_free(ctx->mech.pParameter, ctx->mech.ulParameterLen);
        ctx->mech.pParameter = NULL;
        ctx->mech.ulParameterLen = 0;

        memcpy(ctx->chacha_iv_bytes, iv, 16);
        chacha_params.pBlockCounter = &ctx->chacha_iv_bytes[0];
        chacha_params.blockCounterBits = 32;
        chacha_params.pNonce = &ctx->chacha_iv_bytes[4];
        chacha_params.ulNonceBits = 96;
        ctx->mech.pParameter =
            OPENSSL_memdup(&chacha_params, sizeof(chacha_params));
        if (!ctx->mech.pParameter) {
            return CKR_HOST_MEMORY;
        }
        ctx->mech.ulParameterLen = sizeof(chacha_params);
        break;
    }

    default:
        return CKR_MECHANISM_INVALID;
    }

    if (param_as_iv) {
        rv = set_iv(ctx, iv, ivlen);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    ret = p11prov_cipher_family_set_ctx_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return CKR_OK;
}

static CK_RV p11prov_cipher_op_init(void *ctx, void *keydata, CK_FLAGS op,
                                    const unsigned char *iv, size_t ivlen,
                                    const OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_RV rv;

    rv = p11prov_ctx_status(cctx->provctx);
    if (rv != CKR_OK) {
        return rv;
    }

    cctx->operation = op;

    rv = p11prov_cipher_prep_mech(cctx, iv, ivlen, params);
    if (rv != CKR_OK) {
        return rv;
    }

    /* If keydata is NULL, it means the application will pass the key later,
     * this is allowed in legacy initialization, so skip full init until we
     * have all the pieces. */
    if (key) {
        cctx->key = p11prov_obj_ref(key);
        if (cctx->key == NULL) {
            return CKR_KEY_NEEDED;
        }
    }

    return CKR_OK;
}

/* Builds the real CK_GCM_PARAMS / CK_SALSA20_CHACHA20_POLY1305_PARAMS
 * from whatever prep_mech stashed (IV) plus whatever AAD has accumulated
 * via update(out=NULL) calls since -- see set_aead_iv()'s own comment
 * for why this can't happen any earlier. No-op once already done (or for
 * a non-AEAD ctx), so callers can call this unconditionally. */
static CK_RV p11prov_cipher_finish_aead_mech(struct p11prov_cipher_ctx *ctx)
{
    if (!ctx->is_aead || ctx->aead_ready) {
        return CKR_OK;
    }
    if (ctx->aead_ivlen == 0) {
        /* Same stance the C++ engine's own SoftHSM_cipher.cpp takes for
         * CKM_AES_GCM's ulIvLen==0 case: reject rather than let the
         * token substitute an unsafe default. */
        return CKR_MECHANISM_PARAM_INVALID;
    }

    OPENSSL_clear_free(ctx->mech.pParameter, ctx->mech.ulParameterLen);
    ctx->mech.pParameter = NULL;
    ctx->mech.ulParameterLen = 0;

    switch (ctx->mech.mechanism) {
    case CKM_AES_GCM: {
        CK_GCM_PARAMS *p = OPENSSL_zalloc(sizeof(CK_GCM_PARAMS));
        if (!p) {
            return CKR_HOST_MEMORY;
        }
        p->pIv = ctx->aead_iv;
        p->ulIvLen = ctx->aead_ivlen;
        p->ulIvBits = ctx->aead_ivlen * 8;
        p->pAAD = ctx->aadlen ? ctx->aad : NULL;
        p->ulAADLen = ctx->aadlen;
        p->ulTagBits = 128; /* fixed 16-byte tag -- matches this engine */
        ctx->mech.pParameter = p;
        ctx->mech.ulParameterLen = sizeof(*p);
        break;
    }
    case CKM_CHACHA20_POLY1305: {
        CK_SALSA20_CHACHA20_POLY1305_PARAMS *p;

        if (ctx->aead_ivlen != 12) {
            /* RFC 8439 -- this engine rejects anything else too. */
            return CKR_MECHANISM_PARAM_INVALID;
        }
        p = OPENSSL_zalloc(sizeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS));
        if (!p) {
            return CKR_HOST_MEMORY;
        }
        p->pNonce = ctx->aead_iv;
        p->ulNonceLen = ctx->aead_ivlen;
        p->pAAD = ctx->aadlen ? ctx->aad : NULL;
        p->ulAADLen = ctx->aadlen;
        ctx->mech.pParameter = p;
        ctx->mech.ulParameterLen = sizeof(*p);
        break;
    }
    default:
        return CKR_MECHANISM_INVALID;
    }

    ctx->aead_ready = true;
    return CKR_OK;
}

static CK_RV p11prov_cipher_session_init(struct p11prov_cipher_ctx *cctx)
{
    CK_RV rv;

    if (cctx->tlsver != 0 && cctx->mech.mechanism == CKM_AES_CBC_PAD) {
        /* In the special TLS mode we handle de-padding and mac extraction
         * outside the pkcs11 module to conform to what OpenSSL does */
        cctx->mech.mechanism = CKM_AES_CBC;
    }

    rv = p11prov_try_session_ref(cctx->key, cctx->mech.mechanism, true, false,
                                 &cctx->session);
    if (rv != CKR_OK) {
        return rv;
    }

    switch (cctx->operation) {
    case CKF_ENCRYPT:
        rv = p11prov_EncryptInit(
            cctx->provctx, p11prov_session_handle(cctx->session), &cctx->mech,
            p11prov_obj_get_handle(cctx->key));
        break;
    case CKF_DECRYPT:
        rv = p11prov_DecryptInit(
            cctx->provctx, p11prov_session_handle(cctx->session), &cctx->mech,
            p11prov_obj_get_handle(cctx->key));
        break;
    default:
        rv = CKR_GENERAL_ERROR;
    }

    if (rv == CKR_OK) {
        cctx->session_state = CIPHER_SESS_INITIALIZED;
    }

    return rv;
}

/* The one entry point update()/final() actually call to get a live
 * session: finishes the deferred AEAD mechanism parameter first (a
 * no-op for a non-AEAD ctx, or one already finished), then does the
 * real session/EncryptInit-DecryptInit as before. */
static CK_RV p11prov_cipher_ensure_session(struct p11prov_cipher_ctx *cctx)
{
    CK_RV rv;

    if (cctx->session) {
        return CKR_OK;
    }
    rv = p11prov_cipher_finish_aead_mech(cctx);
    if (rv != CKR_OK) {
        return rv;
    }
    return p11prov_cipher_session_init(cctx);
}

static int p11prov_cipher_legacy_init(void *ctx, CK_FLAGS op,
                                      const unsigned char *key, size_t keylen,
                                      const unsigned char *iv, size_t ivlen,
                                      const OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    P11PROV_OBJ *skey = NULL;
    CK_RV rv;

    rv = p11prov_ctx_status(cctx->provctx);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    if (key != NULL && keylen > 0) {
        /* The only way to fulfill this request is by importing the key
         * in the token as a session object. Phase 5 R26: this function
         * is shared across every cipher family now (not AES-only), so
         * the key type has to follow cctx->mech.mechanism -- already
         * set by newctx() before this ever runs -- rather than a
         * hardcoded CKK_AES that would import CHACHA20 key bytes under
         * the wrong type and make the engine's own type check
         * (SoftHSM_cipher.cpp: CKM_CHACHA20/_POLY1305 both require
         * CKK_CHACHA20) reject it. */
        CK_KEY_TYPE key_type;
        switch (cctx->mech.mechanism) {
        case CKM_CHACHA20:
        case CKM_CHACHA20_POLY1305:
            key_type = CKK_CHACHA20;
            break;
        default:
            key_type = CKK_AES;
            break;
        }
        skey = p11prov_obj_import_secret_key(cctx->provctx, key_type, key,
                                             keylen);
        if (!skey) {
            return RET_OSSL_ERR;
        }
    }

    rv = p11prov_cipher_op_init(ctx, skey, op, iv, ivlen, params);

    p11prov_obj_free(skey);

    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

int p11prov_cipher_encrypt_init(void *ctx, const unsigned char *key,
                                       size_t keylen, const unsigned char *iv,
                                       size_t ivlen, const OSSL_PARAM params[])
{
    P11PROV_debug("encrypt init (ctx=%p, key=%p, iv=%p, params=%p)", ctx, key,
                  iv, params);

    return p11prov_cipher_legacy_init(ctx, CKF_ENCRYPT, key, keylen, iv, ivlen,
                                      params);
}

int p11prov_cipher_decrypt_init(void *ctx, const unsigned char *key,
                                       size_t keylen, const unsigned char *iv,
                                       size_t ivlen, const OSSL_PARAM params[])
{
    P11PROV_debug("decrypt init (ctx=%p, key=%p, iv=%p, params=%p)", ctx, key,
                  iv, params);

    return p11prov_cipher_legacy_init(ctx, CKF_DECRYPT, key, keylen, iv, ivlen,
                                      params);
}

int p11prov_cipher_encrypt_skey_init(void *ctx, void *keydata,
                                            const unsigned char *iv,
                                            size_t ivlen,
                                            const OSSL_PARAM params[])
{
    CK_RV rv;

    P11PROV_debug("encrypt skey init (ctx=%p, key=%p, params=%p)", ctx, keydata,
                  params);

    rv = p11prov_cipher_op_init(ctx, keydata, CKF_ENCRYPT, iv, ivlen, params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

int p11prov_cipher_decrypt_skey_init(void *ctx, void *keydata,
                                            const unsigned char *iv,
                                            size_t ivlen,
                                            const OSSL_PARAM params[])
{
    CK_RV rv;

    P11PROV_debug("decrypt skey init (ctx=%p, key=%p, params=%p)", ctx, keydata,
                  params);

    rv = p11prov_cipher_op_init(ctx, keydata, CKF_DECRYPT, iv, ivlen, params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

/* This function needs to be executed in constant time */
static CK_RV tlsunpad(struct p11prov_cipher_ctx *cctx, unsigned char *out,
                      CK_ULONG inlen, CK_ULONG *outlen)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_ULONG overhead = cctx->tlsmacsize + 1; /* mac size + padlen byte */
    CK_ULONG maxcheck = MAX_PADDING;
    CK_ULONG padsize = out[inlen - 1];
    CK_ULONG olen = inlen;
    CK_ULONG pass;

    /* Remove explicit IV for TLS 1.1 and 1.2 */
    if (cctx->tlsver != 0x301) {
        /* This is a bad interface as it make it seem that
         * the returned output buffer is incorrectly pointing
         * at the IV and not the data, but OpenSSL will in turn
         * offset the buffer later, based on knowledge that this
         * cipher return a length that excludes the IV from the
         * count. */
        out += AESBLOCK;
        olen = inlen - AESBLOCK;
    }

    /* olen is public known so can be checked normally */
    if (olen < overhead) {
        return CKR_BUFFER_TOO_SMALL;
    }

    if (olen < cctx->tlsmacsize) {
        return CKR_BUFFER_TOO_SMALL;
    }

    if (maxcheck > olen) {
        maxcheck = olen;
    }

    /* olen must not be smaller than padsize + overhead */
    pass = ~constant_smaller_mask(olen, overhead + padsize);

    /* creates a mask so that we check only the padding bytes
     * without revealing the padding length in a conditional.
     * mask is 0xff when i < padsize, and 0 otherwise, allowing
     * us to scan the whole buffer while really only testing for
     * equality only the padding part, as the xoring with non-pad
     * data is ignored my the empty mask. We skip checking the
     * last value itself as that is always == padsize */
    for (int i = 0; i < maxcheck - 1; i++) {
        unsigned char mask = constant_smaller_mask(i, padsize);
        unsigned char data = out[olen - i - 2];

        pass &= ~(mask & (padsize ^ data));
    }

    /* renormalize to a CK_ULONG */
    pass = constant_equal_mask(pass, 0xff);

    if (cctx->tlsmacsize > 0) {
        unsigned char randmac[EVP_MAX_MD_SIZE];
        size_t mac_pos = olen - cctx->tlsmacsize - (pass & (padsize + 1));
        size_t mac_area = 0;
        int err = RET_OSSL_ERR;

        /* allocate space for the mac */
        cctx->tlsmac = OPENSSL_zalloc(cctx->tlsmacsize);
        if (!cctx->tlsmac) {
            return CKR_GENERAL_ERROR;
        }

        /* random mac we return if something is wrong */
        err = RAND_bytes_ex(p11prov_ctx_get_libctx(cctx->provctx), randmac,
                            sizeof(randmac), 0);
        if (err != RET_OSSL_OK) {
            return CKR_GENERAL_ERROR;
        }

        /* olen and mac size are public data, so we can do this
         * assignment without bothering with constant time */
        if (olen > cctx->tlsmacsize + 256) {
            mac_area = olen - cctx->tlsmacsize - 256;
        }

        for (size_t i = mac_area; i < olen; i++) {
            for (int j = 0; j < cctx->tlsmacsize; j++) {
                unsigned char mask =
                    ~constant_smaller_mask(i, mac_pos)
                    & constant_smaller_mask(i, mac_pos + cctx->tlsmacsize)
                    & constant_equal_mask(i, j + mac_pos);
                cctx->tlsmac[j] |= out[i] & mask;
            }
        }

        /* on depadding failure overwrite with random data */
        for (int j = 0; j < cctx->tlsmacsize; j++) {
            cctx->tlsmac[j] =
                constant_select_byte_mask(cctx->tlsmac[j], randmac[j], pass);
        }

        rv = CKR_OK;
    } else {
        /* no MAC to check just return the result */
        if (pass + 1 == 0) {
            rv = CKR_OK;
        }
    }

    *outlen = olen - cctx->tlsmacsize - (pass & (padsize + 1));
    return rv;
}

/* Grows ctx->aad and appends `in` -- OpenSSL's own EVP AEAD convention
 * for delivering associated data is one or more update(out=NULL) calls,
 * so a single call is not assumed. */
static CK_RV aad_append(struct p11prov_cipher_ctx *ctx,
                        const unsigned char *in, size_t inl)
{
    unsigned char *newbuf;

    if (inl == 0) {
        return CKR_OK;
    }
    newbuf = OPENSSL_realloc(ctx->aad, ctx->aadlen + inl);
    if (!newbuf) {
        return CKR_HOST_MEMORY;
    }
    memcpy(newbuf + ctx->aadlen, in, inl);
    ctx->aad = newbuf;
    ctx->aadlen += inl;
    ctx->aadcap = ctx->aadlen;
    return CKR_OK;
}

int p11prov_cipher_update(void *ctx, unsigned char *out, size_t *outl,
                                 size_t outsize, const unsigned char *in,
                                 size_t inl)
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    CK_SESSION_HANDLE session_handle;
    CK_ULONG outlen = outsize;
    CK_ULONG inlen = inl;
    CK_RV rv;

    /* out==NULL is OpenSSL's own convention for "this call's `in` is
     * associated data, not plaintext/ciphertext" -- PKCS#11's own GCM/
     * CHACHA20_POLY1305 mechanisms need the COMPLETE AAD baked into the
     * mechanism parameter at C_EncryptInit/DecryptInit time, which is
     * why that call is deferred to ensure_session() below rather than
     * happening eagerly in prep_mech -- see set_aead_iv()'s comment.
     * Handled before anything session-related so an AAD-only call never
     * triggers the real token init early. */
    if (out == NULL) {
        if (!cctx->is_aead) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return RET_OSSL_ERR;
        }
        if (cctx->aead_ready) {
            /* AAD arriving after real data/session init is out of the
             * EVP AEAD contract -- reject loudly rather than silently
             * drop it from the mechanism (matching this project's own
             * "reject loudly, don't silently degrade" R10/F36-6
             * pattern). */
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return RET_OSSL_ERR;
        }
        rv = aad_append(cctx, in, inl);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
        *outl = 0;
        return RET_OSSL_OK;
    }

    if (cctx->tlsver != 0) {
        /* Special OpenSSL layering violating mode.
         * A single update is a full record.
         * Inputs need to be consistent with stricter requirements */
        if (!in || in != out || outsize < inl || !cctx->pad) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
    }

    if (!cctx->session) {
        rv = p11prov_cipher_ensure_session(cctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }
    session_handle = p11prov_session_handle(cctx->session);

    switch (cctx->operation) {
    case CKF_ENCRYPT:
        if (cctx->tlsver != 0) {
            size_t padsize = AESBLOCK - (inl % AESBLOCK);
            unsigned char padval = (unsigned char)(padsize - 1);

            if (outsize < inl + padsize) {
                rv = CKR_BUFFER_TOO_SMALL;
                P11PROV_raise(cctx->provctx, rv, "Output buffer too small");
                return RET_OSSL_ERR;
            }
            inlen += padsize;
            if ((inlen % AESBLOCK) != 0) {
                rv = CKR_ARGUMENTS_BAD;
                P11PROV_raise(cctx->provctx, rv, "Invalid input buffer size");
                return RET_OSSL_ERR;
            }
            /* add the padding, relies on in == out and therefore enough
             * space available in the buffer */
            memset(&out[inl], padval, padsize);

            /* in TLS mode we must use single shot encryption to properly
             * auto-finalize the session as OpenSSL won't */
            rv = p11prov_Encrypt(cctx->provctx, session_handle, (void *)in,
                                 inlen, out, &outlen);

            cctx->session_state = CIPHER_SESS_FINALIZED;
            /* unconditionally return the session */
            p11prov_return_session(cctx->session);
            cctx->session = NULL;
        } else {
            rv = p11prov_EncryptUpdate(cctx->provctx, session_handle,
                                       (void *)in, inlen, out, &outlen);
        }
        break;
    case CKF_DECRYPT:
        if (cctx->tlsver != 0) {
            if ((inlen % AESBLOCK) != 0) {
                rv = CKR_ARGUMENTS_BAD;
                P11PROV_raise(cctx->provctx, rv, "Invalid input buffer size");
                return RET_OSSL_ERR;
            }
            /* in TLS mode we must use single shot decryption to properly
             * auto-finalize the session as OpenSSL won't */
            rv = p11prov_Decrypt(cctx->provctx, session_handle, (void *)in,
                                 inlen, out, &outlen);

            cctx->session_state = CIPHER_SESS_FINALIZED;
            /* unconditionally return the session */
            p11prov_return_session(cctx->session);
            cctx->session = NULL;

            if (rv != CKR_OK) {
                P11PROV_raise(cctx->provctx, rv, "Decryption failure");
                return RET_OSSL_ERR;
            }
            /* remove padding and fill in tlsmac as needed */
            if (cctx->tlsmac) {
                OPENSSL_clear_free(cctx->tlsmac, cctx->tlsmacsize);
                cctx->tlsmac = NULL;
            }

            /* Assumes inlen = outlen on correct decryption */
            rv = tlsunpad(cctx, out, inlen, &outlen);
        } else {
            rv = p11prov_DecryptUpdate(cctx->provctx, session_handle,
                                       (void *)in, inlen, out, &outlen);
        }
        break;
    default:
        rv = CKR_GENERAL_ERROR;
    }

    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    *outl = outlen;
    return RET_OSSL_OK;
}

/* AEAD encrypt final: C_EncryptFinal's own output is ciphertext-tail
 * followed by the trailing tag, concatenated (this engine's own
 * OSSLEVPSymmetricAlgorithm::encryptFinal does `encryptedData += tag`) --
 * but the EVP caller expects final() to hand back ONLY the ciphertext
 * tail via the normal out/outl, and to retrieve the tag separately,
 * later, via get_ctx_params(AEAD_TAG). So this runs EncryptFinal into an
 * internal scratch buffer and splits the trailing 16 bytes off into
 * cctx->tag before copying the rest to the caller's own buffer. */
static CK_RV p11prov_cipher_aead_encrypt_final(struct p11prov_cipher_ctx *cctx,
                                               unsigned char *out,
                                               size_t *outl, size_t outsize)
{
    unsigned char *scratch;
    CK_ULONG scratchlen;
    CK_RV rv;

    scratchlen = outsize + 16;
    scratch = OPENSSL_malloc(scratchlen);
    if (!scratch) {
        return CKR_HOST_MEMORY;
    }

    rv = p11prov_EncryptFinal(cctx->provctx,
                              p11prov_session_handle(cctx->session), scratch,
                              &scratchlen);
    if (rv != CKR_OK) {
        OPENSSL_clear_free(scratch, outsize + 16);
        return rv;
    }
    if (scratchlen < 16) {
        /* The token returned less than a whole tag -- something is
         * fundamentally wrong (wrong mechanism reaching here, or a
         * token bug); refuse rather than hand back a truncated tag. */
        OPENSSL_clear_free(scratch, outsize + 16);
        return CKR_GENERAL_ERROR;
    }

    cctx->taglen = 16;
    memcpy(cctx->tag, scratch + (scratchlen - 16), 16);

    *outl = scratchlen - 16;
    if (*outl > outsize) {
        OPENSSL_clear_free(scratch, outsize + 16);
        return CKR_BUFFER_TOO_SMALL;
    }
    if (*outl > 0) {
        memcpy(out, scratch, *outl);
    }
    OPENSSL_clear_free(scratch, outsize + 16);
    return CKR_OK;
}

/* AEAD decrypt final: forwards the caller's own set_ctx_params(AEAD_TAG)
 * value to the token as one more DecryptUpdate chunk right before
 * DecryptFinal -- this engine's own decryptUpdate withholds whatever
 * it was most recently given until Final decides whether those bytes
 * were "more ciphertext" or "the trailing tag" (see this engine's own
 * OSSLEVPSymmetricAlgorithm::decryptUpdate comment), so appending the
 * tag this way and then calling Final is exactly the shape it expects.
 * Any plaintext bytes the token had been withholding from the real
 * ciphertext (because it couldn't yet rule out them being the tag) are
 * released by this same DecryptUpdate call and must be surfaced to the
 * caller here, ahead of whatever DecryptFinal itself returns. */
static CK_RV p11prov_cipher_aead_decrypt_final(struct p11prov_cipher_ctx *cctx,
                                               unsigned char *out,
                                               size_t *outl, size_t outsize)
{
    CK_SESSION_HANDLE sess = p11prov_session_handle(cctx->session);
    CK_ULONG released = outsize;
    CK_ULONG finallen;
    CK_RV rv;

    if (!cctx->tag_set) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = p11prov_DecryptUpdate(cctx->provctx, sess, cctx->tag,
                               (CK_ULONG)cctx->taglen, out, &released);
    if (rv != CKR_OK) {
        return rv;
    }
    if (released > outsize) {
        return CKR_BUFFER_TOO_SMALL;
    }

    finallen = outsize - released;
    rv = p11prov_DecryptFinal(cctx->provctx, sess, out + released, &finallen);
    if (rv != CKR_OK) {
        return rv;
    }

    *outl = released + finallen;
    return CKR_OK;
}

int p11prov_cipher_final(void *ctx, unsigned char *out, size_t *outl,
                                size_t outsize)
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    CK_ULONG outlen = outsize;
    CK_RV rv;

    if (!cctx->session) {
        /* AEAD with zero real update() calls (e.g. AAD-only / empty
         * plaintext) never triggered ensure_session(); do it here so
         * that edge case still produces a real, verified tag rather
         * than erroring out on a case a non-AEAD cipher never hits. */
        if (!cctx->is_aead) {
            return RET_OSSL_ERR;
        }
        rv = p11prov_cipher_ensure_session(cctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    if (cctx->is_aead) {
        switch (cctx->operation) {
        case CKF_ENCRYPT:
            rv = p11prov_cipher_aead_encrypt_final(cctx, out, outl, outsize);
            break;
        case CKF_DECRYPT:
            rv = p11prov_cipher_aead_decrypt_final(cctx, out, outl, outsize);
            break;
        default:
            rv = CKR_GENERAL_ERROR;
        }

        cctx->session_state = CIPHER_SESS_FINALIZED;
        p11prov_return_session(cctx->session);
        cctx->session = NULL;

        return rv == CKR_OK ? RET_OSSL_OK : RET_OSSL_ERR;
    }

    switch (cctx->operation) {
    case CKF_ENCRYPT:
        rv = p11prov_EncryptFinal(
            cctx->provctx, p11prov_session_handle(cctx->session), out, &outlen);
        break;
    case CKF_DECRYPT:
        rv = p11prov_DecryptFinal(
            cctx->provctx, p11prov_session_handle(cctx->session), out, &outlen);
        break;
    default:
        rv = CKR_GENERAL_ERROR;
    }

    cctx->session_state = CIPHER_SESS_FINALIZED;
    /* unconditionally return session here as well */
    p11prov_return_session(cctx->session);
    cctx->session = NULL;

    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    *outl = outlen;
    return RET_OSSL_OK;
}

static int p11prov_aes_cipher(void *ctx, unsigned char *out, size_t *outl,
                              size_t outsize, const unsigned char *in,
                              size_t inl)
{
    return RET_OSSL_ERR;
}

static int p11prov_aes_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    size_t ivsize = 16; /* 128 bits for all modes but ECB */
    OSSL_PARAM *p;
    int ret;

    /* Real bug, caught live: EVP_CIPHER_CTX_get_iv_length() (evp_lib.c)
     * calls THIS get_ctx_params(IVLEN) to compute the ivlen it then
     * passes to encrypt_init/decrypt_init -- i.e. this runs BEFORE
     * prep_mech's own set_aead_iv() has ever set is_aead/aead_ivlen, so
     * gating on cctx->is_aead here always sees it false/zero at that
     * critical first call, silently reporting the wrong length (this
     * provider's own generic 16 instead of GCM's real 12) with no error
     * anywhere -- confirmed live via PKCS11_PROVIDER_DEBUG tracing
     * aead_ivlen arriving at prep_mech as 16, not 12. cctx->mech.
     * mechanism is reliably set from newctx() before any of this runs,
     * so key off that for the mechanism's own default; once a real
     * negotiated IV exists (post-init), prefer reporting that instead,
     * in case a caller ever uses a non-default GCM IV length. */
    if (cctx->mech.mechanism == CKM_AES_ECB) {
        ivsize = 0;
    } else if (cctx->mech.mechanism == CKM_AES_GCM) {
        ivsize = (cctx->is_aead && cctx->aead_ivlen > 0) ? cctx->aead_ivlen
                                                          : 12;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, ivsize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p) {
        int pad = 0;
        if (cctx->pad) {
            pad = 1;
        }
        ret = OSSL_PARAM_set_uint(p, pad);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    /* is_aead: mech.pParameter is a CK_GCM_PARAMS struct once built (or
     * NULL before that), never raw IV bytes -- the real IV lives in
     * aead_iv/aead_ivlen (stashed by set_aead_iv() in prep_mech). */
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p) {
        if (cctx->is_aead) {
            ret = OSSL_PARAM_set_octet_string(p, cctx->aead_iv,
                                              cctx->aead_ivlen);
        } else {
            ret = OSSL_PARAM_set_octet_string(p, cctx->mech.pParameter,
                                              cctx->mech.ulParameterLen);
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
            ret = OSSL_PARAM_set_octet_string(p, cctx->mech.pParameter,
                                              cctx->mech.ulParameterLen);
        }
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    /* Encrypt: the real tag, filled in by p11prov_cipher_aead_encrypt_
     * final() after C_EncryptFinal. Decrypt: OSSL_CIPHER_PARAM_AEAD_TAG
     * is a set-only param on the decrypt side per OpenSSL's own
     * convention (the caller supplies the expected tag, never reads it
     * back), so this simply hands back whatever's in cctx->tag -- empty/
     * zero before an encrypt-final has run, matching every other
     * EVP AEAD implementation's own "ask before final, get nothing
     * meaningful" behavior. */
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

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p) {
        int num = 0;
        ret = OSSL_PARAM_set_uint(p, num);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p) {
        size_t keylen = cctx->keysize;
        ret = OSSL_PARAM_set_size_t(p, keylen);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p) {
        ret = OSSL_PARAM_set_octet_ptr(p, cctx->tlsmac, cctx->tlsmacsize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

/* Shared by p11prov_aes_set_ctx_params and p11prov_chacha20_set_ctx_params
 * (chacha.c). OSSL_CIPHER_PARAM_AEAD_TAG on decrypt is the caller
 * supplying the tag to verify -- the NORMAL AEAD decrypt calling
 * sequence is init -> update(ciphertext...) -> set_ctx_params(tag) ->
 * final(), so by the time this arrives the session is very often
 * already live (update() already ran ensure_session()); it must not be
 * rejected by any "already instantiated" guard the way other cipher
 * params correctly are. On encrypt, AEAD_TAG is set-only in the other
 * direction in some callers' conventions (requesting a specific tag
 * length before the real one exists) -- this provider always produces
 * a fixed 16-byte tag, so a set here on the encrypt side is accepted
 * only if it matches that length, and otherwise ignored (no real
 * request has ever arrived through this path so far). */
int p11prov_cipher_aead_set_tag_param(struct p11prov_cipher_ctx *ctx,
                                             const OSSL_PARAM params[],
                                             bool *consumed)
{
    const OSSL_PARAM *p;

    *consumed = false;
    if (!ctx->is_aead) {
        return RET_OSSL_OK;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (!p) {
        return RET_OSSL_OK;
    }
    *consumed = true;
    if (p->data_size == 0 || p->data_size > sizeof(ctx->tag)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return RET_OSSL_ERR;
    }
    if (ctx->operation == CKF_DECRYPT) {
        memcpy(ctx->tag, p->data, p->data_size);
        ctx->taglen = p->data_size;
        ctx->tag_set = true;
    }
    return RET_OSSL_OK;
}

static int p11prov_aes_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;
    const OSSL_PARAM *p;
    bool tag_consumed = false;
    int ret;

    ret = p11prov_cipher_aead_set_tag_param(ctx, params, &tag_consumed);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    if (ctx->session != NULL) {
        /* A tag-only call (the common decrypt-side case, arriving after
         * update() has already made the session live) is fully handled
         * above -- nothing below this point ever applies to it, so it
         * must not be rejected by this guard. */
        if (tag_consumed) {
            return RET_OSSL_OK;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_ALREADY_INSTANTIATED);
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p) {
        unsigned int pad;
        int ret = OSSL_PARAM_get_uint(p, &pad);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return RET_OSSL_ERR;
        }
        if (pad > 1) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            return RET_OSSL_ERR;
        }
        ctx->pad = pad == 1;

        switch (ctx->mech.mechanism) {
        case CKM_AES_CBC:
            if (ctx->pad) {
                ctx->mech.mechanism = CKM_AES_CBC_PAD;
            }
            break;

        case CKM_AES_CBC_PAD:
            if (!ctx->pad) {
                ctx->mech.mechanism = CKM_AES_CBC;
            }
            break;

        default:
            if (ctx->pad) {
                /* FIXME: we need to do our padding as there is no _PAD mode
                 * for non CBC modes in PKCS#11 */
                ERR_raise(ERR_LIB_PROV,
                          PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
                return RET_OSSL_ERR;
            }
        }
    }

    if (ctx->mech.mechanism == CKM_AES_CTS) {
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE);
        if (p) {
            const char *mode;
            int ret = OSSL_PARAM_get_utf8_ptr(p, &mode);
            if (ret != RET_OSSL_OK) {
                CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
                P11PROV_raise(ctx->provctx, rv, "Invalid mode parameter");
                return RET_OSSL_ERR;
            }
            /* Currently only CS1 is supported */
            if (strcmp(mode, OSSL_CIPHER_CTS_MODE_CS1) != 0) {
                CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
                P11PROV_raise(ctx->provctx, rv, "Unsupported mode: %s", mode);
                return RET_OSSL_ERR;
            }
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p) {
        CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
        unsigned int version;
        int ret = OSSL_PARAM_get_uint(p, &version);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx->provctx, rv, "Invalid TLS Version parameter");
            return RET_OSSL_ERR;
        }
        switch (version) {
        case 0x301: /* TLS 1.0 */
        case 0x302: /* TLS 1.1 */
        case 0x303: /* TLS 1.2 */
            ctx->tlsver = version;
            break;
        default:
            P11PROV_raise(ctx->provctx, rv, "Unsupported TLS Version");
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p) {
        CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
        size_t macsize;
        int ret = OSSL_PARAM_get_size_t(p, &macsize);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx->provctx, rv, "Invalid TLS MAC Size parameter");
            return RET_OSSL_ERR;
        }
        if (macsize > EVP_MAX_MD_SIZE) {
            P11PROV_raise(ctx->provctx, rv, "Invalid TLS Mac Size");
            return RET_OSSL_ERR;
        }
        ctx->tlsmacsize = macsize;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM p11prov_aes_generic_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_TLS_MAC, NULL, 0),
    OSSL_PARAM_END
};

/* phase 5 R26 prerequisite: AES-GCM's own gettable params -- was missing
 * entirely (CKM_AES_GCM wasn't even in p11prov_aes_gettable_ctx_params's
 * switch, so this returned NULL, and the generic array above has no
 * AEAD_TAG entry regardless). */
static const OSSL_PARAM p11prov_aes_gcm_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_aes_gettable_ctx_params(void *vctx,
                                                         void *provctx)
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;

    if (!ctx) {
        /* There are some cases where openssl will ask for context
         * parameters but will pass NULL for the context, for now
         * we return the generic parameters, but in future we may
         * need to allocate shim functions for each cipher in their
         * dispatch table if it becomes important to return different
         * results for each cipher */
        return p11prov_aes_generic_gettable_ctx_params;
    }

    switch (ctx->mech.mechanism) {
    case CKM_AES_ECB:
    case CKM_AES_CBC_PAD:
    case CKM_AES_OFB:
    case CKM_AES_CFB128:
    case CKM_AES_CFB1:
    case CKM_AES_CFB8:
    case CKM_AES_CTR:
    case CKM_AES_CTS:
        return p11prov_aes_generic_gettable_ctx_params;
    case CKM_AES_GCM:
        return p11prov_aes_gcm_gettable_ctx_params;
    }
    return NULL;
}

#define GENERIC_SETTABLE_CTX_PARAMS() \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL)
/* Supported by OpenSSL but not here:
 * OSSL_CIPHER_PARAM_NUM (uint)
 * OSSL_CIPHER_PARAM_USE_BITS (uint)
 */

static const OSSL_PARAM p11prov_aes_generic_settable_ctx_params[] = {
    GENERIC_SETTABLE_CTX_PARAMS(),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM p11prov_aes_cts_settable_ctx_params[] = {
    GENERIC_SETTABLE_CTX_PARAMS(),
    OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0), OSSL_PARAM_END
};

/* phase 5 R26 prerequisite */
static const OSSL_PARAM p11prov_aes_gcm_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_aes_settable_ctx_params(void *vctx,
                                                         void *provctx)
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;
    if (!ctx) {
        /* See the explanation in p11prov_aes_gettable_ctx_params() for
         * why we handle this case this way */
        return p11prov_aes_generic_settable_ctx_params;
    }
    switch (ctx->mech.mechanism) {
    case CKM_AES_ECB:
    case CKM_AES_CBC_PAD:
    case CKM_AES_OFB:
    case CKM_AES_CFB128:
    case CKM_AES_CFB1:
    case CKM_AES_CFB8:
    case CKM_AES_CTR:
        return p11prov_aes_generic_settable_ctx_params;
    case CKM_AES_CTS:
        return p11prov_aes_cts_settable_ctx_params;
    case CKM_AES_GCM:
        return p11prov_aes_gcm_settable_ctx_params;
    case CKM_AES_CCM:
        return p11prov_aes_generic_settable_ctx_params;
    }
    return NULL;
}

DISPATCH_TABLE_CIPHER_FN(aes, 128, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cbc, CKM_AES_CBC_PAD);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cbc, CKM_AES_CBC_PAD);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cbc, CKM_AES_CBC_PAD);
DISPATCH_TABLE_CIPHER_FN(aes, 128, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 128, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cts, CKM_AES_CTS);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cts, CKM_AES_CTS);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cts, CKM_AES_CTS);

DISPATCH_TABLE_CIPHER_FN(aes, 128, gcm, CKM_AES_GCM);
DISPATCH_TABLE_CIPHER_FN(aes, 192, gcm, CKM_AES_GCM);
DISPATCH_TABLE_CIPHER_FN(aes, 256, gcm, CKM_AES_GCM);

/* remediation R32 (2026-08-26): these three dispatch tables register a
 * DISPATCH_TABLE_CIPHER_FN for CKM_AES_CCM the same way every other
 * mechanism here does, but CCM's own registration in provider.c is
 * dead: neither the C++ engine (SoftHSM.cpp's symmetric dispatch has
 * no CKM_AES_CCM case) nor the Rust engine implements it, so any real
 * call routes to CKR_MECHANISM_INVALID at the engine boundary
 * regardless of what this table sets up. Left in place (not stripped)
 * deliberately: removing dead-but-harmless vendored dispatch tables
 * would churn upstream-diff surface for zero behavior change; the
 * comment carries the knowledge at near-zero risk instead. Real CCM
 * support needs engine work first (both engines, own test suites) --
 * and note PKCS#11's CK_CCM_PARAMS needs the total data length up
 * front, which collides with the streaming EVP API harder than GCM's
 * AAD-timing wrinkle (phase-6 R30) did. */
DISPATCH_TABLE_CIPHER_FN(aes, 128, ccm, CKM_AES_CCM);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ccm, CKM_AES_CCM);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ccm, CKM_AES_CCM);

#endif
