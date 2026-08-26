/* Copyright (C) 2026 SoftHSMv3 Contributors
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "digests.h"
#include <string.h>

/* R8 (OSSL_OP_MAC), phase-4 plan: token HMAC in bytes-in mode.
 *
 * Registered as a single generic "HMAC" algorithm, matching OpenSSL's
 * own default-provider convention (confirmed live:
 * `openssl list -mac-algorithms -provider default` shows one bare
 * "HMAC" name, not one name per digest) — the underlying digest
 * arrives at runtime via OSSL_MAC_PARAM_DIGEST (the same param
 * `openssl mac -digest SHA256 HMAC` sets), not baked into the
 * algorithm's registered name. A first attempt registered one
 * pre-bound name per digest (HMAC-SHA2-256 etc., modeled on
 * digests.c's own per-variant DISPATCH pattern) — that is a
 * legitimate, real algorithm identity per NIST/IANA naming, but it is
 * NOT what the standard `mac HMAC -digest ...` CLI invocation resolves
 * to, so it could never be reached by the exact command line the R8
 * plan's own proof step names; confirmed live via
 * `openssl list -mac-algorithms`, which showed the per-digest names
 * registered `@ pkcs11` correctly, while `mac HMAC -digest SHA256`
 * still silently resolved to `HMAC @ default` — zero engine-log
 * activity is what caught it, not a wrong output value (HMAC-SHA256 is
 * deterministic, so both providers produce byte-identical output
 * regardless of which one actually ran — output equality alone proves
 * nothing here, matching this whole project's standing R13 discipline).
 *
 * The key can arrive via init()'s own key/keylen args, via
 * OSSL_MAC_PARAM_KEY in either init()'s or a later set_ctx_params()
 * call's params[] — rather than guess which path openssl's own `mac`
 * app and EVP_MAC_init use, this stores whichever key (and whichever
 * digest choice) arrives first and defers the actual C_SignInit to the
 * first update() call, once both are certainly known. */

struct p11prov_mac_ctx {
    P11PROV_CTX *provctx;
    CK_MECHANISM_TYPE mechtype; /* CKM_SHA*_HMAC, chosen via set_digest */
    size_t mac_size;

    P11PROV_SESSION *session;
    P11PROV_OBJ *key;

    unsigned char *keybuf;
    size_t keylen;

    bool signinit_done;
};

typedef struct p11prov_mac_ctx P11PROV_MAC_CTX;

static CK_MECHANISM_TYPE hmac_mech_for_digest(CK_MECHANISM_TYPE digest_mech)
{
    switch (digest_mech) {
    case CKM_SHA_1:
        return CKM_SHA_1_HMAC;
    case CKM_SHA256:
        return CKM_SHA256_HMAC;
    case CKM_SHA384:
        return CKM_SHA384_HMAC;
    case CKM_SHA512:
        return CKM_SHA512_HMAC;
    default:
        return CK_UNAVAILABLE_INFORMATION;
    }
}

static void *p11prov_hmac_mac_newctx(void *provctx)
{
    P11PROV_MAC_CTX *macctx = OPENSSL_zalloc(sizeof(P11PROV_MAC_CTX));

    if (macctx == NULL) {
        return NULL;
    }
    macctx->provctx = (P11PROV_CTX *)provctx;
    macctx->mechtype = CK_UNAVAILABLE_INFORMATION;
    return macctx;
}

static void p11prov_mac_freectx(void *vctx)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;

    P11PROV_debug("mac freectx %p", vctx);

    if (macctx == NULL) {
        return;
    }
    p11prov_obj_free(macctx->key);
    p11prov_return_session(macctx->session);
    OPENSSL_clear_free(macctx->keybuf, macctx->keylen);
    OPENSSL_clear_free(macctx, sizeof(P11PROV_MAC_CTX));
}

static int mac_set_key(P11PROV_MAC_CTX *macctx, const unsigned char *key,
                       size_t keylen)
{
    OPENSSL_clear_free(macctx->keybuf, macctx->keylen);
    macctx->keybuf = OPENSSL_memdup(key, keylen);
    if (macctx->keybuf == NULL) {
        macctx->keylen = 0;
        return RET_OSSL_ERR;
    }
    macctx->keylen = keylen;
    return RET_OSSL_OK;
}

static int mac_set_digest(P11PROV_MAC_CTX *macctx, const char *digestname)
{
    CK_MECHANISM_TYPE digest_mech = CK_UNAVAILABLE_INFORMATION;
    CK_MECHANISM_TYPE hmac_mech;
    size_t digest_size = 0;
    CK_RV ret;

    ret = p11prov_digest_get_by_name(digestname, &digest_mech);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "Unknown MAC digest '%s'",
                      digestname);
        return RET_OSSL_ERR;
    }
    hmac_mech = hmac_mech_for_digest(digest_mech);
    if (hmac_mech == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(macctx->provctx, CKR_MECHANISM_INVALID,
                      "Digest '%s' has no matching HMAC mechanism in this "
                      "provider",
                      digestname);
        return RET_OSSL_ERR;
    }
    p11prov_digest_get_digest_size(digest_mech, &digest_size);
    macctx->mechtype = hmac_mech;
    macctx->mac_size = digest_size;
    return RET_OSSL_OK;
}

static int p11prov_mac_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    const OSSL_PARAM *p;

    P11PROV_debug("mac set ctx params %p", vctx);

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p != NULL) {
        char digestname[64] = { 0 };
        char *namep = digestname;

        if (OSSL_PARAM_get_utf8_string(p, &namep, sizeof(digestname))
            != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
        if (mac_set_digest(macctx, digestname) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            return RET_OSSL_ERR;
        }
        if (mac_set_key(macctx, p->data, p->data_size) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mac_settable_ctx_params(void *vctx,
                                                         void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_mac_init(void *vctx, const unsigned char *key,
                            size_t keylen, const OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;

    P11PROV_debug("mac init %p key=%p keylen=%zu", vctx, (const void *)key,
                  keylen);

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (key != NULL) {
        if (mac_set_key(macctx, key, keylen) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }
    return p11prov_mac_set_ctx_params(vctx, params);
}

static int mac_ensure_signinit(P11PROV_MAC_CTX *macctx)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_SESSION_HANDLE sess;
    CK_MECHANISM mechanism = { 0 };
    CK_OBJECT_HANDLE hkey;
    CK_RV ret;

    if (macctx->signinit_done) {
        return RET_OSSL_OK;
    }
    if (macctx->keybuf == NULL) {
        P11PROV_raise(macctx->provctx, CKR_KEY_INDIGESTIBLE,
                      "MAC key was never set");
        return RET_OSSL_ERR;
    }
    if (macctx->mechtype == CK_UNAVAILABLE_INFORMATION) {
        /* No OSSL_MAC_PARAM_DIGEST arrived — default to SHA2-256,
         * matching the default provider's own HMAC default digest. */
        if (mac_set_digest(macctx, "SHA2-256") != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    ret = p11prov_get_session(macctx->provctx, &slotid, NULL, NULL,
                              macctx->mechtype, NULL, NULL, false, false,
                              &macctx->session);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "Failed to open new session");
        return RET_OSSL_ERR;
    }
    sess = p11prov_session_handle(macctx->session);

    macctx->key = p11prov_create_mac_key(macctx->provctx, macctx->session,
                                         macctx->keybuf, macctx->keylen);
    if (macctx->key == NULL) {
        return RET_OSSL_ERR;
    }
    hkey = p11prov_obj_get_handle(macctx->key);

    mechanism.mechanism = macctx->mechtype;
    ret = p11prov_SignInit(macctx->provctx, sess, &mechanism, hkey);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "C_SignInit failed");
        return RET_OSSL_ERR;
    }
    macctx->signinit_done = true;
    return RET_OSSL_OK;
}

static int p11prov_mac_update(void *vctx, const unsigned char *data,
                              size_t datalen)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    CK_SESSION_HANDLE sess;
    CK_RV ret;

    P11PROV_debug("mac update %p len=%zu", vctx, datalen);

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (mac_ensure_signinit(macctx) != RET_OSSL_OK) {
        return RET_OSSL_ERR;
    }
    if (datalen == 0) {
        return RET_OSSL_OK;
    }

    sess = p11prov_session_handle(macctx->session);
    ret = p11prov_SignUpdate(macctx->provctx, sess, (CK_BYTE_PTR)data,
                             datalen);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "C_SignUpdate failed");
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_mac_final(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    CK_SESSION_HANDLE sess;
    CK_ULONG siglen;
    CK_RV ret;

    P11PROV_debug("mac final %p outsize=%zu", vctx, outsize);

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (mac_ensure_signinit(macctx) != RET_OSSL_OK) {
        return RET_OSSL_ERR;
    }
    if (outsize < macctx->mac_size) {
        P11PROV_raise(macctx->provctx, CKR_BUFFER_TOO_SMALL,
                      "MAC output buffer too small");
        return RET_OSSL_ERR;
    }

    sess = p11prov_session_handle(macctx->session);
    siglen = macctx->mac_size;
    ret = p11prov_SignFinal(macctx->provctx, sess, out, &siglen);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "C_SignFinal failed");
        return RET_OSSL_ERR;
    }
    *outl = siglen;
    return RET_OSSL_OK;
}

static int p11prov_hmac_mac_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    /* Static, digest-independent max: SHA2-512's 64 bytes. The real,
     * digest-specific size is only known once OSSL_MAC_PARAM_DIGEST has
     * been set (mac_set_digest) and is reported via get_ctx_params in a
     * live context, not this static, context-free get_params. */
    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL) {
        if (OSSL_PARAM_set_size_t(p, 64) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mac_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_mac_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    OSSL_PARAM *p;

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL) {
        size_t size = macctx->mac_size != 0 ? macctx->mac_size : 64;
        if (OSSL_PARAM_set_size_t(p, size) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mac_gettable_ctx_params(void *vctx,
                                                         void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_hmac_mac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p11prov_hmac_mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))p11prov_mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))p11prov_mac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))p11prov_mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))p11prov_mac_final },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_set_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_settable_ctx_params },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))p11prov_hmac_mac_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mac_gettable_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_get_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_gettable_ctx_params },
    { 0, NULL },
};
