/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "platform/endian.h"
#include <string.h>
#include <openssl/kdf.h>

struct p11prov_kdf_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;

    int mode;
    CK_MECHANISM_TYPE hash_mech;
    CK_ULONG salt_type;
    uint8_t *salt;
    size_t saltlen;
    uint8_t *info;
    size_t infolen;
    uint8_t *prefix;
    uint8_t *label;
    uint8_t *data;
    size_t prefixlen;
    size_t labellen;
    size_t datalen;

    P11PROV_SESSION *session;

    bool is_tls13_kdf;
};
typedef struct p11prov_kdf_ctx P11PROV_KDF_CTX;

DISPATCH_HKDF_FN(newctx);
DISPATCH_HKDF_FN(freectx);
DISPATCH_HKDF_FN(reset);
DISPATCH_HKDF_FN(derive);
DISPATCH_HKDF_FN(set_ctx_params);
DISPATCH_HKDF_FN(settable_ctx_params);
DISPATCH_HKDF_FN(get_ctx_params);
DISPATCH_HKDF_FN(gettable_ctx_params);
#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
DISPATCH_HKDF_FN(set_skey);
DISPATCH_HKDF_FN(derive_skey);
#endif

static void *p11prov_hkdf_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_KDF_CTX *hkdfctx;
    CK_RV ret;

    P11PROV_debug("hkdf newctx");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    hkdfctx = OPENSSL_zalloc(sizeof(P11PROV_KDF_CTX));
    if (hkdfctx == NULL) {
        return NULL;
    }

    hkdfctx->provctx = ctx;

    return hkdfctx;
}

static void p11prov_hkdf_freectx(void *ctx)
{
    P11PROV_debug("hkdf freectx (ctx:%p)", ctx);

    p11prov_hkdf_reset(ctx);
    OPENSSL_free(ctx);
}

static void p11prov_hkdf_reset(void *ctx)
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    /* save provider context */
    void *provctx = hkdfctx->provctx;

    P11PROV_debug("hkdf reset (ctx:%p)", ctx);

    /* free all allocated resources */
    p11prov_obj_free(hkdfctx->key);
    if (hkdfctx->session) {
        p11prov_return_session(hkdfctx->session);
        hkdfctx->session = NULL;
    }

    OPENSSL_clear_free(hkdfctx->salt, hkdfctx->saltlen);
    OPENSSL_clear_free(hkdfctx->info, hkdfctx->infolen);
    OPENSSL_clear_free(hkdfctx->prefix, hkdfctx->prefixlen);
    OPENSSL_clear_free(hkdfctx->label, hkdfctx->labellen);
    OPENSSL_clear_free(hkdfctx->data, hkdfctx->datalen);

    /* zero all */
    memset(hkdfctx, 0, sizeof(*hkdfctx));

    /* restore defaults */
    hkdfctx->provctx = provctx;
}

/* The mechanism is used only to ensure the token can perform the request
 * operation, for the HKDF case it doesn't really matter whether the
 * CKM_HKDF_DERIVE or the CKM_HKDF_DATA mechanisms are requested, any token
 * that supports one SHOULD support the other too */
/* provctx/session taken directly (not a P11PROV_KDF_CTX*) so this is
 * reusable by KBKDF's own, differently-shaped context struct (phase 5
 * R22) — was HKDF-only before, three call sites updated below. */
static CK_RV inner_pkcs11_key(P11PROV_CTX *provctx, P11PROV_SESSION **session,
                              CK_MECHANISM_TYPE mech_type, const uint8_t *key,
                              size_t keylen, P11PROV_OBJ **keyobj)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_RV ret;

    if (*session == NULL) {
        ret = p11prov_get_session(provctx, &slotid, NULL, NULL, mech_type,
                                  NULL, NULL, false, false, session);
        if (ret != CKR_OK) {
            return ret;
        }
    }
    if (*session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    *keyobj = p11prov_create_secret_key(provctx, *session, true, (void *)key,
                                        keylen);
    if (*keyobj == NULL) {
        return CKR_KEY_HANDLE_INVALID;
    }
    return CKR_OK;
}

static int inner_extract_key_value(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                                   CK_OBJECT_HANDLE dkey_handle,
                                   unsigned char *key, size_t keylen)
{
    CK_ULONG key_size;
    struct fetch_attrs attrs[1];
    int num = 0;
    CK_RV ret;

    P11PROV_debug("HKDF derived key handle: %lu", dkey_handle);
    FA_SET_BUF_VAL(attrs, num, CKA_VALUE, key, keylen, true);
    ret = p11prov_fetch_attributes(ctx, session, dkey_handle, attrs, num);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx, ret, "Failed to retrieve derived key");
        return ret;
    }
    FA_GET_LEN(attrs, 0, key_size);
    if (key_size != keylen) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(ctx, ret, "Expected derived key of len %zu, but got %lu",
                      keylen, key_size);
        return ret;
    }

    return CKR_OK;
}

static int inner_derive_key(P11PROV_CTX *ctx, P11PROV_OBJ *key,
                            P11PROV_SESSION **session, CK_MECHANISM *mechanism,
                            CK_KEY_TYPE key_type, size_t keylen,
                            CK_OBJECT_HANDLE *dkey_handle)
{
    CK_OBJECT_CLASS class = CK_UNAVAILABLE_INFORMATION;
    CK_BBOOL val_false = CK_FALSE;
    CK_BBOOL val_true = CK_TRUE;
    CK_ULONG key_size = keylen;
    CK_ATTRIBUTE key_template[6] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
    };
    CK_ULONG key_tmpl_len = 0;
    CK_RV ret;

    if (mechanism->mechanism == CKM_HKDF_DERIVE
        || mechanism->mechanism == CKM_SP800_108_COUNTER_KDF
        || mechanism->mechanism == CKM_SP800_108_FEEDBACK_KDF) {
        /* SP800-108 (phase 5 R22) reuses HKDF_DERIVE's own output shape:
         * a generic secret key, session-only, non-sensitive+extractable
         * so the classic derive() API can read its bytes back — matches
         * the engine's own CKM_SP800_108_*_KDF handler (SoftHSM_
         * keygen.cpp), which hardcodes CKK_GENERIC_SECRET regardless of
         * the caller-supplied CKA_KEY_TYPE, same as it does for HKDF. */
        class = CKO_SECRET_KEY;
        key_tmpl_len = 6;
    } else if (mechanism->mechanism == CKM_HKDF_DATA) {
        class = CKO_DATA;
        key_tmpl_len = 3;
    } else {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(ctx, ret, "Invalid mechanism type: %lu",
                      mechanism->mechanism);
        return ret;
    }

    return p11prov_derive_key(key, mechanism, key_template, key_tmpl_len,
                              session, dkey_handle);
}

static int p11prov_hkdf_format_params(P11PROV_KDF_CTX *hkdfctx,
                                      CK_HKDF_PARAMS *params)
{
    if (hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
        || hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
        params->bExtract = CK_TRUE;
    } else {
        params->bExtract = CK_FALSE;
    }
    if (hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
        || hkdfctx->mode == EVP_KDF_HKDF_MODE_EXPAND_ONLY) {
        params->bExpand = CK_TRUE;
    } else {
        params->bExpand = CK_FALSE;
    }
    if (hkdfctx->hash_mech) {
        params->prfHashMechanism = hkdfctx->hash_mech;
    } else {
        return CKR_ARGUMENTS_BAD;
    }
    if (hkdfctx->salt_type == 0) {
        params->ulSaltType = CKF_HKDF_SALT_NULL;
    } else if (hkdfctx->salt_type == CKF_HKDF_SALT_DATA) {
        params->ulSaltType = CKF_HKDF_SALT_DATA;
        params->pSalt = hkdfctx->salt;
        params->ulSaltLen = hkdfctx->saltlen;
    }
    if (hkdfctx->info) {
        params->pInfo = hkdfctx->info;
        params->ulInfoLen = hkdfctx->infolen;
    }

    return CKR_OK;
}

static int p11prov_hkdf_derive(void *ctx, unsigned char *key, size_t keylen,
                               const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_HKDF_PARAMS ck_params = { 0 };
    CK_MECHANISM mechanism = {
        .mechanism = CKM_HKDF_DATA,
        .pParameter = &ck_params,
        .ulParameterLen = sizeof(ck_params),
    };
    CK_OBJECT_HANDLE dkey_handle;
    CK_RV ret;
    int err;

    P11PROV_debug("hkdf derive (ctx:%p, key:%p[%zu], params:%p)", ctx, key,
                  keylen, params);

    err = p11prov_hkdf_set_ctx_params(ctx, params);
    if (err != RET_OSSL_OK) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return err;
    }

    if (hkdfctx->key == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    ret = p11prov_hkdf_format_params(hkdfctx, &ck_params);
    if (ret != CKR_OK) {
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return RET_OSSL_ERR;
    }

    ret = inner_derive_key(hkdfctx->provctx, hkdfctx->key, &hkdfctx->session,
                           &mechanism, CK_UNAVAILABLE_INFORMATION, keylen,
                           &dkey_handle);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = inner_extract_key_value(hkdfctx->provctx, hkdfctx->session,
                                  dkey_handle, key, keylen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
static int p11prov_hkdf_set_skey(void *ctx, void *skeydata,
                                 const char *paramname)
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)skeydata;

    if (strcmp(paramname, OSSL_KDF_PARAM_KEY)) {
        /* ignore anything but a "key" param */
        return RET_OSSL_OK;
    }

    p11prov_obj_free(hkdfctx->key);
    hkdfctx->key = p11prov_obj_ref(key);

    return RET_OSSL_OK;
}

static void *p11prov_hkdf_derive_skey(void *ctx, const char *key_type,
                                      void *provctx,
                                      OSSL_FUNC_skeymgmt_import_fn *import,
                                      size_t keylen, const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_HKDF_PARAMS ck_params = { 0 };
    CK_MECHANISM mechanism = {
        .mechanism = CKM_HKDF_DERIVE,
        .pParameter = &ck_params,
        .ulParameterLen = sizeof(ck_params),
    };
    CK_KEY_TYPE keytype;
    CK_OBJECT_HANDLE dkey_handle;
    P11PROV_OBJ *dkey_object = NULL;
    CK_RV ret;
    int err;

    P11PROV_debug("hkdf derive (ctx:%p, key_type:%s, params:%p)", ctx, key_type,
                  params);

    err = p11prov_hkdf_set_ctx_params(ctx, params);
    if (err != RET_OSSL_OK) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return NULL;
    }

    if (hkdfctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return NULL;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return NULL;
    }

    ret = p11prov_hkdf_format_params(hkdfctx, &ck_params);
    if (ret != CKR_OK) {
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return RET_OSSL_ERR;
    }

    keytype = p11prov_get_key_type_from_string(key_type);
    if (keytype == CK_UNAVAILABLE_INFORMATION) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Unknown key type: %s", key_type);
        return NULL;
    }

    ret = inner_derive_key(hkdfctx->provctx, hkdfctx->key, &hkdfctx->session,
                           &mechanism, keytype, keylen, &dkey_handle);
    if (ret != CKR_OK) {
        return NULL;
    }

    ret = p11prov_obj_from_handle(hkdfctx->provctx, hkdfctx->session,
                                  dkey_handle, &dkey_object);
    if (ret != CKR_OK) {
        return NULL;
    }

    return dkey_object;
}
#endif

/* ref: RFC 8446 - 7.1 Key Schedule
 * Citation:
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)
 *
 *   Where HkdfLabel is specified as:
 *
 *     struct {
 *         uint16 length = Length;
 *         opaque label<7..255> = "tls13 " + Label;
 *         opaque context<0..255> = Context;
 *     } HkdfLabel;
 */
#define TLS13_HL_KEY_SIZE 2
#define TLS13_HL_KEY_MAX_LENGTH 65535
#define TLS13_HL_LABEL_SIZE 1
#define TLS13_HL_LABEL_MAX_LENGTH 255
#define TLS13_HL_CONTEXT_SIZE 1
#define TLS13_HL_CONTEXT_MAX_LENGTH 255
#define TLS13_HKDF_LABEL_MAX_SIZE \
    (TLS13_HL_KEY_SIZE + TLS13_HL_LABEL_SIZE + TLS13_HL_LABEL_MAX_LENGTH \
     + TLS13_HL_CONTEXT_SIZE + TLS13_HL_CONTEXT_MAX_LENGTH)

static CK_RV
p11prov_tls13_expand_label(P11PROV_KDF_CTX *hkdfctx, P11PROV_OBJ *keyobj,
                           uint8_t *prefix, size_t prefixlen, uint8_t *label,
                           size_t labellen, uint8_t *data, size_t datalen,
                           size_t keylen, CK_MECHANISM_TYPE mech_type,
                           CK_KEY_TYPE key_type, CK_OBJECT_HANDLE *dkey_handle)
{
    CK_HKDF_PARAMS params = {
        .bExtract = CK_FALSE,
        .bExpand = CK_TRUE,
        .prfHashMechanism = hkdfctx->hash_mech,
        .ulSaltType = 0,
        .pSalt = NULL,
        .ulSaltLen = 0,
        .hSaltKey = CK_INVALID_HANDLE,
    };
    CK_MECHANISM mechanism = {
        .mechanism = mech_type,
        .pParameter = &params,
        .ulParameterLen = sizeof(params),
    };
    uint8_t info[TLS13_HKDF_LABEL_MAX_SIZE];
    size_t i;
    uint16_t keysize;
    CK_RV ret;

    P11PROV_debug(
        "tls13 expand label (prefix:%p[%zu], label:%p[%zu], data:%p[%zu])",
        prefix, prefixlen, label, labellen, data, datalen);

    if (prefix == NULL || prefixlen == 0 || label == NULL || labellen == 0
        || (prefixlen + labellen > TLS13_HL_LABEL_MAX_LENGTH)
        || (datalen > 0 && data == NULL) || (datalen == 0 && data != NULL)
        || (datalen > TLS13_HL_CONTEXT_MAX_LENGTH)
        || (keylen > TLS13_HL_KEY_MAX_LENGTH)) {
        return CKR_ARGUMENTS_BAD;
    }

    params.pInfo = info;
    params.ulInfoLen = 2 + 1 + prefixlen + labellen + 1 + datalen;
    if (params.ulInfoLen > TLS13_HKDF_LABEL_MAX_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    i = 0;
    keysize = htobe16(keylen);
    memcpy(&info[i], &keysize, sizeof(keysize));
    i += sizeof(keysize);
    info[i] = prefixlen + labellen;
    i += 1;
    memcpy(&info[i], prefix, prefixlen);
    i += prefixlen;
    memcpy(&info[i], label, labellen);
    i += labellen;
    info[i] = datalen;
    i += 1;
    if (datalen > 0) {
        memcpy(&info[i], data, datalen);
        i += datalen;
    }
    if (params.ulInfoLen != i) {
        OPENSSL_cleanse(params.pInfo, TLS13_HKDF_LABEL_MAX_SIZE);
        return CKR_HOST_MEMORY;
    }

    ret = inner_derive_key(hkdfctx->provctx, keyobj, &hkdfctx->session,
                           &mechanism, key_type, keylen, dkey_handle);

    OPENSSL_cleanse(params.pInfo, params.ulInfoLen);
    return ret;
}

static CK_RV p11prov_tls13_derive_secret(P11PROV_KDF_CTX *hkdfctx,
                                         P11PROV_OBJ *keyobj, size_t keylen,
                                         CK_MECHANISM_TYPE mech_type,
                                         CK_KEY_TYPE key_type,
                                         CK_OBJECT_HANDLE *dkey_handle)
{
    P11PROV_OBJ *zerokey = NULL;
    CK_HKDF_PARAMS params = {
        .bExtract = CK_TRUE,
        .bExpand = CK_FALSE,
        .prfHashMechanism = hkdfctx->hash_mech,
        .ulSaltType = CKF_HKDF_SALT_DATA,
        .hSaltKey = CK_INVALID_HANDLE,
        .pInfo = NULL,
        .ulInfoLen = 0,
    };
    CK_MECHANISM mechanism = {
        .mechanism = mech_type,
        .pParameter = &params,
        .ulParameterLen = sizeof(params),
    };
    uint8_t saltbuf[EVP_MAX_MD_SIZE] = { 0 };
    uint8_t zerobuf[EVP_MAX_MD_SIZE] = { 0 };
    size_t saltlen;
    size_t hashlen;
    CK_RV ret;

    ret = p11prov_digest_get_digest_size(hkdfctx->hash_mech, &hashlen);
    if (ret != CKR_OK) {
        return ret;
    }
    saltlen = hashlen;

    if (hkdfctx->salt) {
        P11PROV_OBJ *ek = NULL;
        unsigned char info[hashlen];
        const char *mdname;
        data_buffer digest_data[1] = { 0 }; /* intentionally empty */
        data_buffer digest = { .data = info, .length = hashlen };
        CK_OBJECT_HANDLE skey_handle;

        /* OpenSSL special cases this in an odd way and regenerates a hash as
         * if an empty message was received. */
        ret = p11prov_digest_get_name(hkdfctx->hash_mech, &mdname);
        if (ret != CKR_OK) {
            return ret;
        }

        ret = p11prov_digest_util(hkdfctx->provctx, mdname, NULL, digest_data,
                                  &digest);
        if (ret != CKR_OK) {
            return ret;
        }

        /* In OpenSSL the salt is used as the derivation key */
        ret = inner_pkcs11_key(hkdfctx->provctx, &hkdfctx->session,
                               CKM_HKDF_DATA, hkdfctx->salt, hkdfctx->saltlen,
                               &ek);
        if (ret != CKR_OK) {
            return ret;
        }

        ret = p11prov_tls13_expand_label(
            hkdfctx, ek, hkdfctx->prefix, hkdfctx->prefixlen, hkdfctx->label,
            hkdfctx->labellen, info, hashlen, hashlen, CKM_HKDF_DATA,
            CK_UNAVAILABLE_INFORMATION, &skey_handle);
        p11prov_obj_free(ek);
        if (ret != CKR_OK) {
            return ret;
        }

        ret = inner_extract_key_value(hkdfctx->provctx, hkdfctx->session,
                                      skey_handle, saltbuf, saltlen);
        if (ret != CKR_OK) {
            return ret;
        }
    }

    params.pSalt = saltbuf;
    params.ulSaltLen = saltlen;

    if (!keyobj) {
        ret = inner_pkcs11_key(hkdfctx->provctx, &hkdfctx->session, mech_type,
                               zerobuf, hashlen, &zerokey);
        if (ret != CKR_OK) {
            return ret;
        }
        keyobj = zerokey;
    }

    ret = inner_derive_key(hkdfctx->provctx, keyobj, &hkdfctx->session,
                           &mechanism, key_type, keylen, dkey_handle);

    p11prov_obj_free(zerokey);
    return ret;
}

static int p11prov_tls13_kdf_derive(void *ctx, unsigned char *key,
                                    size_t keylen, const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_OBJECT_HANDLE dkey_handle;
    CK_RV ret;

    P11PROV_debug("tls13 hkdf derive (ctx:%p, key:%p[%zu], params:%p)", ctx,
                  key, keylen, params);

    ret = p11prov_hkdf_set_ctx_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return RET_OSSL_ERR;
    }

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    switch (hkdfctx->mode) {
    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        if (hkdfctx->key == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return RET_OSSL_ERR;
        }
        ret = p11prov_tls13_expand_label(
            hkdfctx, hkdfctx->key, hkdfctx->prefix, hkdfctx->prefixlen,
            hkdfctx->label, hkdfctx->labellen, hkdfctx->data, hkdfctx->datalen,
            keylen, CKM_HKDF_DATA, CK_UNAVAILABLE_INFORMATION, &dkey_handle);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        /* key can be null here */
        ret = p11prov_tls13_derive_secret(
            hkdfctx, hkdfctx->key, keylen, CKM_HKDF_DATA,
            CK_UNAVAILABLE_INFORMATION, &dkey_handle);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        break;
    default:
        return RET_OSSL_ERR;
    }

    ret = inner_extract_key_value(hkdfctx->provctx, hkdfctx->session,
                                  dkey_handle, key, keylen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
static void *p11prov_tls13_kdf_derive_skey(void *ctx, const char *key_type,
                                           void *provctx,
                                           OSSL_FUNC_skeymgmt_import_fn *import,
                                           size_t keylen,
                                           const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_KEY_TYPE keytype;
    CK_OBJECT_HANDLE dkey_handle;
    P11PROV_OBJ *dkey_object = NULL;
    CK_RV ret;
    int err;

    P11PROV_debug("tls13 kdf derive_skey (ctx:%p, key_type:%s, params:%p)", ctx,
                  key_type, params);

    err = p11prov_hkdf_set_ctx_params(ctx, params);
    if (err != RET_OSSL_OK) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return NULL;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return NULL;
    }

    keytype = p11prov_get_key_type_from_string(key_type);
    if (keytype == CK_UNAVAILABLE_INFORMATION) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Unknown key type");
        return NULL;
    }

    switch (hkdfctx->mode) {
    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        if (hkdfctx->key == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto done;
        }
        ret = p11prov_tls13_expand_label(
            hkdfctx, hkdfctx->key, hkdfctx->prefix, hkdfctx->prefixlen,
            hkdfctx->label, hkdfctx->labellen, hkdfctx->data, hkdfctx->datalen,
            keylen, CKM_HKDF_DERIVE, keytype, &dkey_handle);
        if (ret != CKR_OK) {
            goto done;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        /* key can be null here */
        ret =
            p11prov_tls13_derive_secret(hkdfctx, hkdfctx->key, keylen,
                                        CKM_HKDF_DERIVE, keytype, &dkey_handle);
        if (ret != CKR_OK) {
            goto done;
        }
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        goto done;
    }

    ret = p11prov_obj_from_handle(hkdfctx->provctx, hkdfctx->session,
                                  dkey_handle, &dkey_object);
    if (ret != CKR_OK) {
        /* dkey_object will be NULL */
    }

done:
    return dkey_object;
}
#endif

static int p11prov_hkdf_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("hkdf set ctx params (ctx=%p, params=%p)", hkdfctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    /* params common to HKDF and TLS13_KDF first */

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        rv = p11prov_digest_get_by_name(digest, &hkdfctx->hash_mech);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set digest to %lu", hkdfctx->hash_mech);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if (p) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (OPENSSL_strcasecmp(p->data, "EXTRACT_AND_EXPAND") == 0) {
                hkdfctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            } else if (OPENSSL_strcasecmp(p->data, "EXTRACT_ONLY") == 0) {
                hkdfctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            } else if (OPENSSL_strcasecmp(p->data, "EXPAND_ONLY") == 0) {
                hkdfctx->mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            } else {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return RET_OSSL_ERR;
            }
        } else {
            ret = OSSL_PARAM_get_int(p, &hkdfctx->mode);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        switch (hkdfctx->mode) {
        case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
            break;
        case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
            break;
        case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set mode to mode:%d", hkdfctx->mode);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p) {
        const void *secret = NULL;
        size_t secret_len;

        ret = OSSL_PARAM_get_octet_string_ptr(p, &secret, &secret_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        /* Create Session and key from key material */
        p11prov_obj_free(hkdfctx->key);
        ret = inner_pkcs11_key(hkdfctx->provctx, &hkdfctx->session,
                               CKM_HKDF_DERIVE, secret, secret_len,
                               &hkdfctx->key);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p) {
        OPENSSL_clear_free(hkdfctx->salt, hkdfctx->saltlen);
        hkdfctx->salt = NULL;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&hkdfctx->salt, 0,
                                          &hkdfctx->saltlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        hkdfctx->salt_type = CKF_HKDF_SALT_DATA;
        P11PROV_debug("set salt (len:%lu)", hkdfctx->saltlen);
    }

    if (hkdfctx->is_tls13_kdf) {

        if (hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return RET_OSSL_ERR;
        }

        OPENSSL_clear_free(hkdfctx->info, hkdfctx->infolen);
        hkdfctx->info = NULL;
        hkdfctx->infolen = 0;

        p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PREFIX);
        if (p) {
            OPENSSL_clear_free(hkdfctx->prefix, hkdfctx->prefixlen);
            hkdfctx->prefix = NULL;
            hkdfctx->prefixlen = 0;
            ret = OSSL_PARAM_get_octet_string(p, (void **)&hkdfctx->prefix, 0,
                                              &hkdfctx->prefixlen);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL);
        if (p) {
            OPENSSL_clear_free(hkdfctx->label, hkdfctx->labellen);
            hkdfctx->label = NULL;
            hkdfctx->labellen = 0;
            ret = OSSL_PARAM_get_octet_string(p, (void **)&hkdfctx->label, 0,
                                              &hkdfctx->labellen);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DATA);
        if (p) {
            OPENSSL_clear_free(hkdfctx->data, hkdfctx->datalen);
            hkdfctx->data = NULL;
            hkdfctx->datalen = 0;
            ret = OSSL_PARAM_get_octet_string(p, (void **)&hkdfctx->data, 0,
                                              &hkdfctx->datalen);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
    if (p) {
        OPENSSL_clear_free(hkdfctx->info, hkdfctx->infolen);
        hkdfctx->info = NULL;
        hkdfctx->infolen = 0;
    }
    /* can be multiple parameters, which will be all concatenated */
    for (; p; p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO)) {
        uint8_t *ptr;
        size_t len;

        if (p->data_size == 0 || p->data == NULL) {
            return RET_OSSL_ERR;
        }

        len = hkdfctx->infolen + p->data_size;
        ptr = OPENSSL_realloc(hkdfctx->info, len);
        if (ptr == NULL) {
            OPENSSL_clear_free(hkdfctx->info, hkdfctx->infolen);
            hkdfctx->info = NULL;
            hkdfctx->infolen = 0;
            return RET_OSSL_ERR;
        }
        memcpy(ptr + hkdfctx->infolen, p->data, p->data_size);
        hkdfctx->info = ptr;
        hkdfctx->infolen = len;
        P11PROV_debug("set info (len:%lu)", hkdfctx->infolen);
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hkdf_settable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_hkdf_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    OSSL_PARAM *p;

    P11PROV_debug("hkdf get ctx params (ctx=%p, params=%p)", hkdfctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p) {
        size_t ret_size = 0;
        if (hkdfctx->mode != EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
            ret_size = SIZE_MAX;
        } else {
            CK_RV rv;

            rv = p11prov_digest_get_digest_size(hkdfctx->hash_mech, &ret_size);
            if (rv != CKR_OK) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                return RET_OSSL_ERR;
            }
        }
        if (ret_size != 0) {
            return OSSL_PARAM_set_size_t(p, ret_size);
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hkdf_gettable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_hkdf_kdf_functions[] = {
    DISPATCH_HKDF_ELEM(hkdf, NEWCTX, newctx),
    DISPATCH_HKDF_ELEM(hkdf, FREECTX, freectx),
    DISPATCH_HKDF_ELEM(hkdf, RESET, reset),
    DISPATCH_HKDF_ELEM(hkdf, DERIVE, derive),
    DISPATCH_HKDF_ELEM(hkdf, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, GETTABLE_CTX_PARAMS, gettable_ctx_params),
#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
    DISPATCH_HKDF_ELEM(hkdf, SET_SKEY, set_skey),
    DISPATCH_HKDF_ELEM(hkdf, DERIVE_SKEY, derive_skey),
#endif
    { 0, NULL },
};

static void *p11prov_tls13_kdf_newctx(void *provctx)
{
    P11PROV_KDF_CTX *ctx = (P11PROV_KDF_CTX *)p11prov_hkdf_newctx(provctx);
    ctx->is_tls13_kdf = true;
    return ctx;
}

static const OSSL_PARAM *p11prov_tls13_kdf_settable_ctx_params(void *ctx,
                                                               void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PREFIX, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_DATA, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_tls13_kdf_functions[] = {
    DISPATCH_HKDF_ELEM(tls13_kdf, NEWCTX, newctx),
    DISPATCH_HKDF_ELEM(hkdf, FREECTX, freectx),
    DISPATCH_HKDF_ELEM(hkdf, RESET, reset),
    DISPATCH_HKDF_ELEM(tls13_kdf, DERIVE, derive),
    DISPATCH_HKDF_ELEM(hkdf, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_HKDF_ELEM(tls13_kdf, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, GETTABLE_CTX_PARAMS, gettable_ctx_params),
#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
    DISPATCH_HKDF_ELEM(hkdf, SET_SKEY, set_skey),
    DISPATCH_HKDF_ELEM(tls13_kdf, DERIVE_SKEY, derive_skey),
#endif
    { 0, NULL },
};

/* ===========================================================================
 *  PBKDF2 (phase 4 R10) — CKM_PKCS5_PBKD2, C_DeriveKey-based, no base key.
 *
 * Unlike HKDF, PBKDF2 needs no input-key-material object: the password
 * travels directly in CK_PKCS5_PBKD2_PARAMS2, and the engine's own
 * C_DeriveKey (SoftHSM_keygen.cpp) special-cases CKM_PKCS5_PBKD2 BEFORE
 * validating hBaseKey — confirmed by reading that dispatch, not assumed:
 * the mechanism switch admits it, then an early `if (mechanism ==
 * CKM_PKCS5_PBKD2)` block runs before any base-key object lookup. So this
 * calls p11prov_DeriveKey directly (hBaseKey = CK_INVALID_HANDLE) rather
 * than reusing HKDF's p11prov_derive_key, which requires and dereferences
 * a real P11PROV_OBJ key handle this operation has no equivalent of.
 * ===========================================================================
 */

struct p11prov_pbkdf2_ctx {
    P11PROV_CTX *provctx;
    uint8_t *pass;
    size_t passlen;
    uint8_t *salt;
    size_t saltlen;
    uint64_t iter;
    CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
    P11PROV_SESSION *session;
};
typedef struct p11prov_pbkdf2_ctx P11PROV_PBKDF2_CTX;

static void *p11prov_pbkdf2_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_PBKDF2_CTX *pctx;
    CK_RV ret;

    P11PROV_debug("pbkdf2 newctx");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    pctx = OPENSSL_zalloc(sizeof(P11PROV_PBKDF2_CTX));
    if (pctx == NULL) {
        return NULL;
    }
    pctx->provctx = ctx;
    /* draft-19-unrelated default: PKCS#5 v2.0's own RFC 8018 default PRF
     * is HMAC-SHA1 when OSSL_KDF_PARAM_DIGEST is never set, matching the
     * default provider's own PBKDF2 behavior. */
    pctx->prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
    return pctx;
}

static void p11prov_pbkdf2_freectx(void *ctx)
{
    P11PROV_PBKDF2_CTX *pctx = (P11PROV_PBKDF2_CTX *)ctx;

    P11PROV_debug("pbkdf2 freectx (ctx:%p)", ctx);

    if (pctx == NULL) {
        return;
    }
    if (pctx->session) {
        p11prov_return_session(pctx->session);
    }
    OPENSSL_clear_free(pctx->pass, pctx->passlen);
    OPENSSL_clear_free(pctx->salt, pctx->saltlen);
    OPENSSL_free(pctx);
}

static void p11prov_pbkdf2_reset(void *ctx)
{
    P11PROV_PBKDF2_CTX *pctx = (P11PROV_PBKDF2_CTX *)ctx;
    P11PROV_CTX *provctx;

    P11PROV_debug("pbkdf2 reset (ctx:%p)", ctx);

    if (pctx == NULL) {
        return;
    }
    provctx = pctx->provctx;
    if (pctx->session) {
        p11prov_return_session(pctx->session);
    }
    OPENSSL_clear_free(pctx->pass, pctx->passlen);
    OPENSSL_clear_free(pctx->salt, pctx->saltlen);
    memset(pctx, 0, sizeof(*pctx));
    pctx->provctx = provctx;
    pctx->prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
}

static int p11prov_pbkdf2_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_PBKDF2_CTX *pctx = (P11PROV_PBKDF2_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("pbkdf2 set ctx params (ctx=%p, params=%p)", pctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD);
    if (p) {
        OPENSSL_clear_free(pctx->pass, pctx->passlen);
        pctx->pass = NULL;
        pctx->passlen = 0;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&pctx->pass, 0,
                                          &pctx->passlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p) {
        OPENSSL_clear_free(pctx->salt, pctx->saltlen);
        pctx->salt = NULL;
        pctx->saltlen = 0;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&pctx->salt, 0,
                                          &pctx->saltlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER);
    if (p) {
        uint64_t iter;
        ret = OSSL_PARAM_get_uint64(p, &iter);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (iter == 0 || iter > (uint64_t)ULONG_MAX) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_ITERATION_COUNT);
            return RET_OSSL_ERR;
        }
        pctx->iter = iter;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_MECHANISM_TYPE hash_mech;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        rv = p11prov_digest_get_by_name(digest, &hash_mech);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        switch (hash_mech) {
        case CKM_SHA_1:
            pctx->prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
            break;
        case CKM_SHA224:
            pctx->prf = CKP_PKCS5_PBKD2_HMAC_SHA224;
            break;
        case CKM_SHA256:
            pctx->prf = CKP_PKCS5_PBKD2_HMAC_SHA256;
            break;
        case CKM_SHA384:
            pctx->prf = CKP_PKCS5_PBKD2_HMAC_SHA384;
            break;
        case CKM_SHA512:
            pctx->prf = CKP_PKCS5_PBKD2_HMAC_SHA512;
            break;
        default:
            /* Engine-supported PRFs only (SoftHSM_keygen.cpp's own PRF
             * switch) — anything else would fail at C_DeriveKey time
             * with a less clear error, reject it here instead. */
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set prf to %lu", (unsigned long)pctx->prf);
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_pbkdf2_settable_ctx_params(void *ctx,
                                                             void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_pbkdf2_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;

    if (params == NULL) {
        return RET_OSSL_OK;
    }
    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p) {
        return OSSL_PARAM_set_size_t(p, SIZE_MAX);
    }
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_pbkdf2_gettable_ctx_params(void *ctx,
                                                             void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_pbkdf2_derive(void *ctx, unsigned char *key, size_t keylen,
                                 const OSSL_PARAM params[])
{
    P11PROV_PBKDF2_CTX *pctx = (P11PROV_PBKDF2_CTX *)ctx;
    CK_PKCS5_PBKD2_PARAMS2 ck_params = { 0 };
    CK_MECHANISM mechanism = {
        .mechanism = CKM_PKCS5_PBKD2,
        .pParameter = &ck_params,
        .ulParameterLen = sizeof(ck_params),
    };
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL val_false = CK_FALSE;
    CK_BBOOL val_true = CK_TRUE;
    CK_ULONG key_size = keylen;
    CK_ATTRIBUTE key_template[6] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
    };
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_HANDLE dkey_handle = CK_INVALID_HANDLE;
    struct fetch_attrs attrs[1];
    int num = 0;
    CK_ULONG got_size;
    CK_RV ret;
    int err;

    P11PROV_debug("pbkdf2 derive (ctx:%p, key:%p[%zu], params:%p)", ctx, key,
                  keylen, params);

    err = p11prov_pbkdf2_set_ctx_params(ctx, params);
    if (err != RET_OSSL_OK) {
        return err;
    }

    if (pctx->pass == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_PASS);
        return RET_OSSL_ERR;
    }
    if (pctx->iter == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_ITERATION_COUNT);
        return RET_OSSL_ERR;
    }
    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    ck_params.saltSource = CKZ_SALT_SPECIFIED;
    ck_params.pSaltSourceData = pctx->salt;
    ck_params.ulSaltSourceDataLen = (CK_ULONG)pctx->saltlen;
    ck_params.iterations = (CK_ULONG)pctx->iter;
    ck_params.prf = pctx->prf;
    ck_params.pPassword = (CK_UTF8CHAR *)pctx->pass;
    ck_params.ulPasswordLen = (CK_ULONG)pctx->passlen;

    if (pctx->session == NULL) {
        /* reqlogin=true: C_DeriveKey's write-authorization check
         * (SoftHSM_keygen.cpp's haveWrite) rejects a session-object
         * create from an unauthenticated session with CKR_USER_NOT_
         * LOGGED_IN — reproduced live even for the pre-existing, already-
         * working HKDF derive path under the same bare conditions (no
         * prior operation on the session), so this is a general
         * C_DeriveKey requirement, not a PBKDF2-specific one HKDF's own
         * false/false session-acquisition call happens to duck only
         * because its real callers (e.g. TLS handshakes) already have a
         * logged-in session by the time HKDF runs. */
        ret = p11prov_get_session(pctx->provctx, &slotid, NULL, NULL,
                                  CKM_PKCS5_PBKD2, NULL, NULL, true, false,
                                  &pctx->session);
        if (ret != CKR_OK) {
            P11PROV_raise(pctx->provctx, ret, "Failed to acquire session");
            return RET_OSSL_ERR;
        }
    }

    ret = p11prov_DeriveKey(pctx->provctx, p11prov_session_handle(pctx->session),
                            &mechanism, CK_INVALID_HANDLE, key_template, 6,
                            &dkey_handle);
    if (ret != CKR_OK) {
        P11PROV_raise(pctx->provctx, ret, "PBKDF2 C_DeriveKey failed");
        return RET_OSSL_ERR;
    }

    FA_SET_BUF_VAL(attrs, num, CKA_VALUE, key, keylen, true);
    ret = p11prov_fetch_attributes(pctx->provctx, pctx->session, dkey_handle,
                                   attrs, num);
    if (ret != CKR_OK) {
        P11PROV_raise(pctx->provctx, ret, "Failed to retrieve derived key");
        return RET_OSSL_ERR;
    }
    FA_GET_LEN(attrs, 0, got_size);
    if (got_size != keylen) {
        P11PROV_raise(pctx->provctx, CKR_GENERAL_ERROR,
                      "Expected derived key of len %zu, but got %lu", keylen,
                      got_size);
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_pbkdf2_kdf_functions[] = {
    DISPATCH_HKDF_ELEM(pbkdf2, NEWCTX, newctx),
    DISPATCH_HKDF_ELEM(pbkdf2, FREECTX, freectx),
    DISPATCH_HKDF_ELEM(pbkdf2, RESET, reset),
    DISPATCH_HKDF_ELEM(pbkdf2, DERIVE, derive),
    DISPATCH_HKDF_ELEM(pbkdf2, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_HKDF_ELEM(pbkdf2, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_HKDF_ELEM(pbkdf2, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_HKDF_ELEM(pbkdf2, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    { 0, NULL },
};

/* ===========================================================================
 *  KBKDF / SP 800-108 Counter + Feedback (phase 5 R22) —
 *  CKM_SP800_108_COUNTER_KDF / CKM_SP800_108_FEEDBACK_KDF, C_DeriveKey-
 *  based with a real base-key object (unlike PBKDF2, like HKDF) — reuses
 *  inner_pkcs11_key/inner_derive_key/inner_extract_key_value, extended
 *  above to accept these two mechanisms with HKDF_DERIVE's own output
 *  shape (the engine hardcodes CKK_GENERIC_SECRET for all three anyway).
 *
 *  The OSSL_PARAM <-> CK_PRF_DATA_PARAM[] mapping below is grounded in
 *  the C++ engine's OWN CKM_SP800_108_*_KDF handlers (SoftHSM_keygen.cpp,
 *  read directly, not guessed) — which themselves derive via OpenSSL's
 *  own "KBKDF" fetch, so the shape this file's caller-facing side
 *  produces is provably the one the token-side software actually reads
 *  on the other end of C_DeriveKey:
 *    OSSL_KDF_PARAM_MODE "COUNTER"/"FEEDBACK"   -> mechanism choice
 *    OSSL_KDF_PARAM_MAC "HMAC"/"CMAC"           -> prfType family
 *    OSSL_KDF_PARAM_DIGEST (HMAC) / _CIPHER (CMAC) -> prfType mechanism
 *    OSSL_KDF_PARAM_KEY                          -> base key object
 *    OSSL_KDF_PARAM_SALT (fixed input)           -> one CK_SP800_108_
 *                                                    BYTE_ARRAY entry
 *    OSSL_KDF_PARAM_KBKDF_R (COUNTER only)       -> CK_SP800_108_
 *                                                    ITERATION_VARIABLE /
 *                                                    CK_SP800_108_
 *                                                    COUNTER_FORMAT
 *    OSSL_KDF_PARAM_SEED (FEEDBACK only)         -> CK_SP800_108_
 *                                                    FEEDBACK_KDF_PARAMS.
 *                                                    pIV directly (its
 *                                                    own struct field,
 *                                                    not the data-params
 *                                                    array — matches the
 *                                                    engine's own struct)
 *
 *  CMAC's own OSSL_KDF_PARAM_CIPHER name is validated, not forwarded:
 *  the engine always derives its actual CMAC cipher choice from the
 *  imported base key's OWN byte length (SoftHSM_keygen.cpp's own
 *  switch(kbkIKM.size())), via plain CKM_AES_CMAC regardless of which
 *  AES-CBC variant name a caller sends — forwarding a mismatched name
 *  would silently diverge from what actually runs, so anything that
 *  isn't a plain AES-*-CBC name is rejected up front instead.
 *
 *  OSSL_KDF_PARAM_KBKDF_USE_L / _USE_SEPARATOR are deliberately NOT
 *  settable here: the engine's own KBKDF call never sets either (so the
 *  token side always gets OpenSSL KBKDF's own default for both,
 *  regardless of what a caller of THIS provider might ask for), and
 *  DKM_LENGTH / KEY_HANDLE data-param types are silently skipped by the
 *  engine's own parser ("DKM_LENGTH, KEY_HANDLE not supported — skip",
 *  its own comment) — accepting either from a caller here would create
 *  exactly the silent-divergence hazard R10/F36-6 already established
 *  this project rejects loudly instead of accepting-and-ignoring.
 * ===========================================================================
 */

#define KBKDF_MODE_COUNTER 1
#define KBKDF_MODE_FEEDBACK 2

struct p11prov_kbkdf_ctx {
    P11PROV_CTX *provctx;
    P11PROV_OBJ *key;
    P11PROV_SESSION *session;
    int mode;
    bool use_cmac;
    CK_MECHANISM_TYPE prf_mech;
    uint8_t *salt;
    size_t saltlen;
    uint8_t *seed;
    size_t seedlen;
    CK_ULONG r_bits;
};
typedef struct p11prov_kbkdf_ctx P11PROV_KBKDF_CTX;

static CK_MECHANISM_TYPE kbkdf_hmac_mech_for_digest(CK_MECHANISM_TYPE digest)
{
    /* Matches the engine's own ckmHmacPrfToDigestName() table exactly —
     * deliberately no SHA-1 entry (unlike PBKDF2, which does have one):
     * this project's own SP800-108 handler simply never wires it up. */
    switch (digest) {
    case CKM_SHA224:
        return CKM_SHA224_HMAC;
    case CKM_SHA256:
        return CKM_SHA256_HMAC;
    case CKM_SHA384:
        return CKM_SHA384_HMAC;
    case CKM_SHA512:
        return CKM_SHA512_HMAC;
    case CKM_SHA3_224:
        return CKM_SHA3_224_HMAC;
    case CKM_SHA3_256:
        return CKM_SHA3_256_HMAC;
    case CKM_SHA3_384:
        return CKM_SHA3_384_HMAC;
    case CKM_SHA3_512:
        return CKM_SHA3_512_HMAC;
    default:
        return CK_UNAVAILABLE_INFORMATION;
    }
}

static void *p11prov_kbkdf_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_KBKDF_CTX *kctx;
    CK_RV ret;

    P11PROV_debug("kbkdf newctx");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    kctx = OPENSSL_zalloc(sizeof(P11PROV_KBKDF_CTX));
    if (kctx == NULL) {
        return NULL;
    }
    kctx->provctx = ctx;
    /* SP800-108's own default counter width when CK_SP800_108_ITERATION_
     * VARIABLE is absent — matches the engine's own default. */
    kctx->r_bits = 32;
    return kctx;
}

static void p11prov_kbkdf_freectx(void *ctx)
{
    P11PROV_KBKDF_CTX *kctx = (P11PROV_KBKDF_CTX *)ctx;

    P11PROV_debug("kbkdf freectx (ctx:%p)", ctx);

    if (kctx == NULL) {
        return;
    }
    p11prov_obj_free(kctx->key);
    if (kctx->session) {
        p11prov_return_session(kctx->session);
    }
    OPENSSL_clear_free(kctx->salt, kctx->saltlen);
    OPENSSL_clear_free(kctx->seed, kctx->seedlen);
    OPENSSL_free(kctx);
}

static void p11prov_kbkdf_reset(void *ctx)
{
    P11PROV_KBKDF_CTX *kctx = (P11PROV_KBKDF_CTX *)ctx;
    P11PROV_CTX *provctx;

    P11PROV_debug("kbkdf reset (ctx:%p)", ctx);

    if (kctx == NULL) {
        return;
    }
    provctx = kctx->provctx;
    p11prov_obj_free(kctx->key);
    if (kctx->session) {
        p11prov_return_session(kctx->session);
    }
    OPENSSL_clear_free(kctx->salt, kctx->saltlen);
    OPENSSL_clear_free(kctx->seed, kctx->seedlen);
    memset(kctx, 0, sizeof(*kctx));
    kctx->provctx = provctx;
    kctx->r_bits = 32;
}

static int p11prov_kbkdf_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_KBKDF_CTX *kctx = (P11PROV_KBKDF_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("kbkdf set ctx params (ctx=%p, params=%p)", kctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if (p) {
        const char *mode = NULL;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &mode);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (OPENSSL_strcasecmp(mode, "COUNTER") == 0) {
            kctx->mode = KBKDF_MODE_COUNTER;
        } else if (OPENSSL_strcasecmp(mode, "FEEDBACK") == 0) {
            kctx->mode = KBKDF_MODE_FEEDBACK;
        } else {
            /* "DOUBLE_PIPELINE" and friends: the engine implements only
             * Counter and Feedback (SoftHSM_keygen.cpp's own mechanism
             * switch has no double-pipeline case) — reject rather than
             * silently mapping to something the token can't do. */
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MAC);
    if (p) {
        const char *mac = NULL;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &mac);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (OPENSSL_strcasecmp(mac, "HMAC") == 0) {
            kctx->use_cmac = false;
        } else if (OPENSSL_strcasecmp(mac, "CMAC") == 0) {
            kctx->use_cmac = true;
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MAC);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_MECHANISM_TYPE digest_mech;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        rv = p11prov_digest_get_by_name(digest, &digest_mech);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        kctx->prf_mech = kbkdf_hmac_mech_for_digest(digest_mech);
        if (kctx->prf_mech == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CIPHER);
    if (p) {
        const char *cipher = NULL;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &cipher);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (OPENSSL_strcasecmp(cipher, "AES-128-CBC") != 0
            && OPENSSL_strcasecmp(cipher, "AES-192-CBC") != 0
            && OPENSSL_strcasecmp(cipher, "AES-256-CBC") != 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CIPHER);
            return RET_OSSL_ERR;
        }
        kctx->prf_mech = CKM_AES_CMAC;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p) {
        OPENSSL_clear_free(kctx->salt, kctx->saltlen);
        kctx->salt = NULL;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&kctx->salt, 0,
                                          &kctx->saltlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED);
    if (p) {
        OPENSSL_clear_free(kctx->seed, kctx->seedlen);
        kctx->seed = NULL;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&kctx->seed, 0,
                                          &kctx->seedlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_R);
    if (p) {
        int r;

        ret = OSSL_PARAM_get_int(p, &r);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (r <= 0 || r > 64) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return RET_OSSL_ERR;
        }
        kctx->r_bits = (CK_ULONG)r;
    }

    /* Deliberately rejected rather than silently accepted-and-ignored —
     * see this section's own header comment for why. */
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_L);
    if (p) {
        int use_l = 1;

        ret = OSSL_PARAM_get_int(p, &use_l);
        if (ret == RET_OSSL_OK && !use_l) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return RET_OSSL_ERR;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR);
    if (p) {
        int use_sep = 1;

        ret = OSSL_PARAM_get_int(p, &use_sep);
        if (ret == RET_OSSL_OK && !use_sep) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p) {
        const void *secret = NULL;
        size_t secret_len;
        CK_RV rv;

        ret = OSSL_PARAM_get_octet_string_ptr(p, &secret, &secret_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        /* reqlogin=true, acquired here (before inner_pkcs11_key's own
         * internal, non-logged-in session acquisition can run first and
         * claim the slot) — C_DeriveKey's write-authorization check
         * (SoftHSM_keygen.cpp's haveWrite) rejects a session-object
         * create from an unauthenticated session with CKR_USER_NOT_
         * LOGGED_IN. This is the exact same general C_DeriveKey
         * requirement R10 found and fixed for PBKDF2 (see that item's
         * own comment on p11prov_pbkdf2_derive, a few hundred lines
         * above) — HKDF's own bare inner_pkcs11_key call only avoids it
         * in practice because its real callers (TLS handshakes) always
         * have an already-logged-in session from an earlier operation;
         * a KBKDF call as the first operation in a session does not. */
        if (kctx->session == NULL) {
            CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
            CK_MECHANISM_TYPE login_mech = kctx->mode == KBKDF_MODE_FEEDBACK
                                               ? CKM_SP800_108_FEEDBACK_KDF
                                               : CKM_SP800_108_COUNTER_KDF;

            rv = p11prov_get_session(kctx->provctx, &slotid, NULL, NULL,
                                     login_mech, NULL, NULL, true, true,
                                     &kctx->session);
            if (rv != CKR_OK) {
                P11PROV_raise(kctx->provctx, rv,
                              "Failed to get PKCS#11 session");
                return RET_OSSL_ERR;
            }
        }

        p11prov_obj_free(kctx->key);
        kctx->key = NULL;
        rv = inner_pkcs11_key(kctx->provctx, &kctx->session,
                              CKM_SP800_108_COUNTER_KDF, secret, secret_len,
                              &kctx->key);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_kbkdf_settable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_R, NULL),
        OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_L, NULL),
        OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_kbkdf_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;

    if (params == NULL) {
        return RET_OSSL_OK;
    }
    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p) {
        return OSSL_PARAM_set_size_t(p, SIZE_MAX);
    }
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_kbkdf_gettable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_kbkdf_derive(void *ctx, unsigned char *key, size_t keylen,
                                const OSSL_PARAM params[])
{
    P11PROV_KBKDF_CTX *kctx = (P11PROV_KBKDF_CTX *)ctx;
    CK_SP800_108_KDF_PARAMS counter_params = { 0 };
    CK_SP800_108_FEEDBACK_KDF_PARAMS feedback_params = { 0 };
    CK_PRF_DATA_PARAM data_params[2];
    CK_ULONG num_data_params = 0;
    CK_SP800_108_COUNTER_FORMAT counter_fmt;
    CK_MECHANISM mechanism = { 0 };
    CK_OBJECT_HANDLE dkey_handle;
    CK_RV ret;
    int err;

    P11PROV_debug("kbkdf derive (ctx:%p, key:%p[%zu], params:%p)", ctx, key,
                  keylen, params);

    err = p11prov_kbkdf_set_ctx_params(ctx, params);
    if (err != RET_OSSL_OK) {
        return err;
    }

    if (kctx->key == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }
    if (kctx->mode == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        return RET_OSSL_ERR;
    }
    if (kctx->prf_mech == 0 || kctx->prf_mech == CK_UNAVAILABLE_INFORMATION) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MAC);
        return RET_OSSL_ERR;
    }
    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    if (kctx->salt != NULL && kctx->saltlen > 0) {
        data_params[num_data_params].type = CK_SP800_108_BYTE_ARRAY;
        data_params[num_data_params].pValue = kctx->salt;
        data_params[num_data_params].ulValueLen = (CK_ULONG)kctx->saltlen;
        num_data_params++;
    }

    if (kctx->mode == KBKDF_MODE_COUNTER) {
        counter_fmt.bLittleEndian = CK_FALSE;
        counter_fmt.ulWidthInBits = kctx->r_bits;
        data_params[num_data_params].type = CK_SP800_108_ITERATION_VARIABLE;
        data_params[num_data_params].pValue = &counter_fmt;
        data_params[num_data_params].ulValueLen = sizeof(counter_fmt);
        num_data_params++;

        counter_params.prfType = kctx->prf_mech;
        counter_params.ulNumberOfDataParams = num_data_params;
        counter_params.pDataParams = data_params;
        counter_params.ulAdditionalDerivedKeys = 0;
        counter_params.pAdditionalDerivedKeys = NULL;

        mechanism.mechanism = CKM_SP800_108_COUNTER_KDF;
        mechanism.pParameter = &counter_params;
        mechanism.ulParameterLen = sizeof(counter_params);
    } else {
        feedback_params.prfType = kctx->prf_mech;
        feedback_params.ulNumberOfDataParams = num_data_params;
        feedback_params.pDataParams = data_params;
        feedback_params.pIV = kctx->seed;
        feedback_params.ulIVLen = (CK_ULONG)kctx->seedlen;
        feedback_params.ulAdditionalDerivedKeys = 0;
        feedback_params.pAdditionalDerivedKeys = NULL;

        mechanism.mechanism = CKM_SP800_108_FEEDBACK_KDF;
        mechanism.pParameter = &feedback_params;
        mechanism.ulParameterLen = sizeof(feedback_params);
    }

    ret = inner_derive_key(kctx->provctx, kctx->key, &kctx->session,
                           &mechanism, CKK_GENERIC_SECRET, keylen,
                           &dkey_handle);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = inner_extract_key_value(kctx->provctx, kctx->session, dkey_handle,
                                  key, keylen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_kbkdf_kdf_functions[] = {
    DISPATCH_HKDF_ELEM(kbkdf, NEWCTX, newctx),
    DISPATCH_HKDF_ELEM(kbkdf, FREECTX, freectx),
    DISPATCH_HKDF_ELEM(kbkdf, RESET, reset),
    DISPATCH_HKDF_ELEM(kbkdf, DERIVE, derive),
    DISPATCH_HKDF_ELEM(kbkdf, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_HKDF_ELEM(kbkdf, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_HKDF_ELEM(kbkdf, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_HKDF_ELEM(kbkdf, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    { 0, NULL },
};
