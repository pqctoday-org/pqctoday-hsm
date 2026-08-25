/*
 * Copyright (c) 2026 SoftHSMv3 Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "provider.h"
#include <string.h>

#ifndef CKM_ML_KEM
#define CKM_ML_KEM 0x00000017UL
#endif

/* CMS_RECIPINFO_KEM = 5 (openssl/cms.h). Defined here to avoid pulling in
 * the full CMS header from inside a provider. */
#ifndef CMS_RECIPINFO_KEM
#define CMS_RECIPINFO_KEM 5
#endif

typedef struct p11prov_kem_ctx {
    P11PROV_CTX *provctx;
    P11PROV_OBJ *key;
    CK_MECHANISM_TYPE mechtype;
    P11PROV_SESSION *session;
} P11PROV_KEM_CTX;

static void *p11prov_kem_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_KEM_CTX *kemctx;

    kemctx = OPENSSL_zalloc(sizeof(P11PROV_KEM_CTX));
    if (kemctx == NULL) {
        return NULL;
    }

    kemctx->provctx = ctx;
    kemctx->mechtype = CKM_ML_KEM;
    return kemctx;
}

static void p11prov_kem_freectx(void *ctx)
{
    P11PROV_KEM_CTX *kemctx = (P11PROV_KEM_CTX *)ctx;

    if (kemctx == NULL) {
        return;
    }

    p11prov_obj_free(kemctx->key);
    p11prov_return_session(kemctx->session);
    OPENSSL_free(kemctx);
}

static int p11prov_kem_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    P11PROV_KEM_CTX *kemctx = (P11PROV_KEM_CTX *)ctx;
    (void)params;

    if (kemctx == NULL || provkey == NULL) {
        return 0;
    }

    p11prov_obj_free(kemctx->key);
    kemctx->key = p11prov_obj_ref((P11PROV_OBJ *)provkey);
    
    return 1;
}

static int p11prov_kem_encapsulate(void *ctx, unsigned char *out, size_t *outlen,
                                   unsigned char *secret, size_t *secretlen)
{
    P11PROV_KEM_CTX *kemctx = (P11PROV_KEM_CTX *)ctx;
    CK_RV ret;
    CK_MECHANISM mech = { kemctx->mechtype, NULL, 0 };
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE hKey;
    CK_OBJECT_HANDLE hSecretHandle = CK_INVALID_HANDLE;

    if (kemctx->key == NULL) {
        return 0;
    }

    if (kemctx->session == NULL) {
        ret = p11prov_try_session_ref(kemctx->key, kemctx->mechtype, false, false, &kemctx->session);
        if (ret != CKR_OK || kemctx->session == NULL) {
            return 0;
        }
    }

    session = p11prov_session_handle(kemctx->session);
    hKey = p11prov_obj_get_handle(kemctx->key);

    /* 
     * PKCS#11 v3.2 C_EncapsulateKey Size querying:
     * If out is NULL, returns required length of ciphertext in outlen
     */
    if (out == NULL) {
        CK_ULONG ctlen = 0;
        ret = p11prov_EncapsulateKey(kemctx->provctx, session, &mech, hKey, NULL, 0, NULL, &ctlen, &hSecretHandle);
        if (ret != CKR_OK) {
            P11PROV_raise(kemctx->provctx, ret, "Failed to query KEM encapsulation sizes");
            return 0;
        }
        *outlen = ctlen;
        return 1;
    }

    /* Actually Encapsulate */
    CK_ULONG out_len_ck = *outlen;
    CK_ATTRIBUTE ts[3];
    CK_ULONG tlen = 0;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;

    ts[0].type = CKA_CLASS;
    ts[0].pValue = &class;
    ts[0].ulValueLen = sizeof(class);
    ts[1].type = CKA_KEY_TYPE;
    ts[1].pValue = &type;
    ts[1].ulValueLen = sizeof(type);
    ts[2].type = CKA_EXTRACTABLE;
    ts[2].pValue = &extractable;
    ts[2].ulValueLen = sizeof(extractable);
    tlen = 3;

    ret = p11prov_EncapsulateKey(kemctx->provctx, session, &mech, hKey, ts, tlen, out, &out_len_ck, &hSecretHandle);
    if (ret != CKR_OK) {
        P11PROV_raise(kemctx->provctx, ret, "C_EncapsulateKey failed");
        return 0;
    }
    *outlen = out_len_ck;

    /* Now extract the secret value from the returned token session object */
    if (secret != NULL) {
        CK_ATTRIBUTE get_ts[] = {
            { CKA_VALUE, NULL, 0 }
        };
        
        ret = p11prov_GetAttributeValue(kemctx->provctx, session, hSecretHandle, get_ts, 1);
        if (ret != CKR_OK) {
            p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
            P11PROV_raise(kemctx->provctx, ret, "Failed to query KEM secret size");
            return 0;
        }

        if (get_ts[0].ulValueLen > *secretlen) {
            p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
            P11PROV_raise(kemctx->provctx, CKR_BUFFER_TOO_SMALL, "KEM secretlen buffer too small");
            return 0;
        }

        get_ts[0].pValue = secret;
        ret = p11prov_GetAttributeValue(kemctx->provctx, session, hSecretHandle, get_ts, 1);
        if (ret != CKR_OK) {
            p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
            P11PROV_raise(kemctx->provctx, ret, "Failed to retrieve KEM secret value");
            return 0;
        }
        *secretlen = get_ts[0].ulValueLen;
    }

    p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
    return 1;
}

static int p11prov_kem_decapsulate(void *ctx, unsigned char *out, size_t *outlen,
                                   const unsigned char *in, size_t inlen)
{
    P11PROV_KEM_CTX *kemctx = (P11PROV_KEM_CTX *)ctx;
    CK_RV ret;
    CK_MECHANISM mech = { kemctx->mechtype, NULL, 0 };
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE hKey;
    CK_OBJECT_HANDLE hSecretHandle = CK_INVALID_HANDLE;

    if (kemctx->key == NULL) {
        return 0;
    }

    if (kemctx->session == NULL) {
        ret = p11prov_try_session_ref(kemctx->key, kemctx->mechtype, false, false, &kemctx->session);
        if (ret != CKR_OK || kemctx->session == NULL) {
            return 0;
        }
    }

    /* Out handles the shared secret, in handles the ciphertext */

    /* If out is NULL, query the size of the shared secret */
    /* But unfortunately, PKCS11 C_DecapsulateKey requires generating an object first! */
    /* OpenSSL expects us to just return the max size of the secret if out == NULL */
    /* ML-KEM shared secrets are exactly 32 bytes */
    if (out == NULL) {
        *outlen = 32;
        return 1;
    }

    session = p11prov_session_handle(kemctx->session);
    hKey = p11prov_obj_get_handle(kemctx->key);

    CK_ATTRIBUTE ts[3];
    CK_ULONG tlen = 0;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;

    ts[0].type = CKA_CLASS;
    ts[0].pValue = &class;
    ts[0].ulValueLen = sizeof(class);
    ts[1].type = CKA_KEY_TYPE;
    ts[1].pValue = &type;
    ts[1].ulValueLen = sizeof(type);
    ts[2].type = CKA_EXTRACTABLE;
    ts[2].pValue = &extractable;
    ts[2].ulValueLen = sizeof(extractable);
    tlen = 3;

    ret = p11prov_DecapsulateKey(kemctx->provctx, session, &mech, hKey, ts, tlen, (unsigned char*)in, inlen, &hSecretHandle);
    if (ret != CKR_OK) {
        P11PROV_raise(kemctx->provctx, ret, "C_DecapsulateKey failed");
        return 0;
    }

    /* Extract the secret value */
    CK_ATTRIBUTE get_ts[] = {
        { CKA_VALUE, NULL, 0 }
    };
    
    ret = p11prov_GetAttributeValue(kemctx->provctx, session, hSecretHandle, get_ts, 1);
    if (ret != CKR_OK) {
        p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
        P11PROV_raise(kemctx->provctx, ret, "Failed to query KEM decapsulated secret size");
        return 0;
    }

    if (get_ts[0].ulValueLen > *outlen) {
        p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
        P11PROV_raise(kemctx->provctx, CKR_BUFFER_TOO_SMALL, "KEM secret output buffer too small");
        return 0;
    }

    get_ts[0].pValue = out;
    ret = p11prov_GetAttributeValue(kemctx->provctx, session, hSecretHandle, get_ts, 1);
    if (ret != CKR_OK) {
        p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
        P11PROV_raise(kemctx->provctx, ret, "Failed to retrieve KEM decapsulated secret value");
        return 0;
    }
    *outlen = get_ts[0].ulValueLen;

    p11prov_DestroyObject(kemctx->provctx, session, hSecretHandle);
    return 1;
}

/* Umbrella table kept for internal use; per-variant tables are what the
 * provider registers so each variant name gets its own namemap identity and
 * can be found by EVP_KEM_fetch(libctx, "ML-KEM-768", ...). */
const OSSL_DISPATCH p11prov_mlkem_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))p11prov_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))p11prov_kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))p11prov_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))p11prov_kem_decapsulate },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem512_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))p11prov_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))p11prov_kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))p11prov_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))p11prov_kem_decapsulate },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem768_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))p11prov_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))p11prov_kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))p11prov_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))p11prov_kem_decapsulate },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem1024_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))p11prov_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))p11prov_kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))p11prov_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))p11prov_kem_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))p11prov_kem_decapsulate },
    { 0, NULL },
};

/* ─── ML-KEM keymgmt (minimal — supports OSSL_STORE load + pkey -pubout) ──────
 * Mirrors the ML-DSA pattern in keymgmt.c. Generation is performed via direct
 * C_GenerateKeyPair in the hub's worker; this surface only needs to materialize
 * objects loaded from OSSL_STORE and export the public key bytes.
 * ML-KEM key sizes (FIPS 203): pub 800/1184/1568, ct 768/1088/1568 bytes.
 */

#ifndef OSSL_KEYMGMT_SELECT_PUBLIC_KEY
#define OSSL_KEYMGMT_SELECT_PUBLIC_KEY 0x01
#endif
#ifndef OSSL_KEYMGMT_SELECT_PRIVATE_KEY
#define OSSL_KEYMGMT_SELECT_PRIVATE_KEY 0x02
#endif
#ifndef ML_KEM_512_CT_SIZE
#define ML_KEM_512_CT_SIZE 768
#define ML_KEM_768_CT_SIZE 1088
#define ML_KEM_1024_CT_SIZE 1568
#endif

static void *p11prov_mlkem_keymgmt_new_fn(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_RV ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) return NULL;
    return p11prov_obj_new(provctx, CK_UNAVAILABLE_INFORMATION,
                           CK_P11PROV_IMPORTED_HANDLE,
                           CK_UNAVAILABLE_INFORMATION);
}

static void p11prov_mlkem_keymgmt_free_fn(void *key)
{
    p11prov_obj_free((P11PROV_OBJ *)key);
}

static void *p11prov_mlkem_keymgmt_load_fn(const void *reference, size_t sz)
{
    return p11prov_obj_from_typed_reference(reference, sz, CKK_ML_KEM);
}

static int p11prov_mlkem_keymgmt_has_fn(const void *keydata, int selection)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    if (key == NULL) return RET_OSSL_ERR;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (p11prov_obj_get_class(key) != CKO_PRIVATE_KEY) return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_mlkem_keymgmt_match_fn(const void *kd1, const void *kd2,
                                          int selection)
{
    P11PROV_OBJ *k1 = (P11PROV_OBJ *)kd1;
    P11PROV_OBJ *k2 = (P11PROV_OBJ *)kd2;
    int cmp_type = OBJ_CMP_KEY_TYPE;
    if (k1 == k2) return RET_OSSL_OK;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) cmp_type |= OBJ_CMP_KEY_PUBLIC;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) cmp_type |= OBJ_CMP_KEY_PRIVATE;
    return p11prov_obj_key_cmp(k1, k2, CKK_ML_KEM, cmp_type);
}

static int p11prov_mlkem_keymgmt_get_params_fn(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_ULONG param_set;
    OSSL_PARAM *p;
    int ret;

    if (key == NULL) return RET_OSSL_ERR;
    param_set = p11prov_obj_get_key_param_set(key);

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        CK_ULONG bits = p11prov_obj_get_key_bit_size(key);
        if (bits == 0) return RET_OSSL_ERR;
        ret = OSSL_PARAM_set_int(p, bits);
        if (ret != RET_OSSL_OK) return ret;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p) {
        int secbits = 0;
        switch (param_set) {
        case CKP_ML_KEM_512:  secbits = 128; break;
        case CKP_ML_KEM_768:  secbits = 192; break;
        case CKP_ML_KEM_1024: secbits = 256; break;
        }
        if (secbits == 0) return RET_OSSL_ERR;
        ret = OSSL_PARAM_set_int(p, secbits);
        if (ret != RET_OSSL_OK) return ret;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p) {
        int ctsize = 0;
        switch (param_set) {
        case CKP_ML_KEM_512:  ctsize = ML_KEM_512_CT_SIZE; break;
        case CKP_ML_KEM_768:  ctsize = ML_KEM_768_CT_SIZE; break;
        case CKP_ML_KEM_1024: ctsize = ML_KEM_1024_CT_SIZE; break;
        }
        if (ctsize == 0) return RET_OSSL_ERR;
        ret = OSSL_PARAM_set_int(p, ctsize);
        if (ret != RET_OSSL_OK) return ret;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        CK_ATTRIBUTE *pub;
        if (p->data_type != OSSL_PARAM_OCTET_STRING) return RET_OSSL_ERR;
        pub = p11prov_obj_get_attr(key, CKA_VALUE);
        if (!pub) return RET_OSSL_ERR;
        p->return_size = pub->ulValueLen;
        if (p->data) {
            if (p->data_size < pub->ulValueLen) return RET_OSSL_ERR;
            memcpy(p->data, pub->pValue, pub->ulValueLen);
            p->data_size = pub->ulValueLen;
        }
    }
    /* Tell OpenSSL's CMS layer that this key uses KEMRecipientInfo (RFC 9629).
     * ossl_cms_pkey_get_ri_type() checks this param first; without it the
     * heuristic fallback (EVP_PKEY_encapsulate_init on an HSM private key)
     * fails and cms -decrypt reports "no matching recipient". */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_CMS_RI_TYPE);
    if (p) {
        ret = OSSL_PARAM_set_int(p, CMS_RECIPINFO_KEM);
        if (ret != RET_OSSL_OK) return ret;
    }
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mlkem_keymgmt_gettable_params_fn(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_CMS_RI_TYPE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_mlkem_keymgmt_export_fn(void *keydata, int selection,
                                           OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx;
    CK_OBJECT_CLASS class;

    if (key == NULL) return RET_OSSL_ERR;
    ctx = p11prov_obj_get_prov_ctx(key);
    class = p11prov_obj_get_class(key);

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) return RET_OSSL_ERR;

    /* Only export public-key bytes when the object itself is a public key.
     * Private-key objects have CKA_VALUE = private key bytes; calling
     * p11prov_obj_export_public_key on them returns garbage, which breaks
     * the cert↔key match in OpenSSL's cms -decrypt KEMRecipientInfo path. */
    if (class == CKO_PUBLIC_KEY && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        return p11prov_obj_export_public_key(key, CKK_ML_KEM, true, false,
                                             cb_fn, cb_arg);
    }
    return RET_OSSL_ERR;
}

static const OSSL_PARAM *p11prov_mlkem_keymgmt_export_types_fn(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) return types;
    return NULL;
}

/* Shared keymgmt table (umbrella — kept for internal use).
 * Per-variant aliases below are what OpenSSL's algorithm fetch machinery
 * needs: each variant must be registered under its own name so that
 * EVP_KEYMGMT_fetch(libctx, "ML-KEM-768", propq) and the
 * evp_keymgmt_fetch_from_prov() fallback in store_result.c both find a
 * pkcs11-provider keymgmt directly under the exact name "ML-KEM-768".
 * The umbrella "ML-KEM:ML-KEM-512:ML-KEM-768:ML-KEM-1024" single entry
 * does not satisfy the prov-constrained lookup used in the fallback loop. */
const OSSL_DISPATCH p11prov_mlkem_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p11prov_mlkem_keymgmt_new_fn },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p11prov_mlkem_keymgmt_free_fn },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p11prov_mlkem_keymgmt_load_fn },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p11prov_mlkem_keymgmt_has_fn },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p11prov_mlkem_keymgmt_match_fn },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_get_params_fn },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_gettable_params_fn },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p11prov_mlkem_keymgmt_export_fn },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))p11prov_mlkem_keymgmt_export_types_fn },
    { 0, NULL },
};

/* Per-variant aliases — same function pointers, separate symbols so each
 * variant gets its own entry in the OpenSSL method store keyed by name. */
const OSSL_DISPATCH p11prov_mlkem512_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p11prov_mlkem_keymgmt_new_fn },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p11prov_mlkem512_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p11prov_mlkem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
      (void (*)(void))p11prov_common_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))p11prov_common_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p11prov_mlkem_keymgmt_free_fn },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p11prov_mlkem_keymgmt_load_fn },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p11prov_mlkem_keymgmt_has_fn },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p11prov_mlkem_keymgmt_match_fn },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_get_params_fn },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_gettable_params_fn },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p11prov_mlkem_keymgmt_export_fn },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))p11prov_mlkem_keymgmt_export_types_fn },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem768_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p11prov_mlkem_keymgmt_new_fn },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p11prov_mlkem768_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p11prov_mlkem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
      (void (*)(void))p11prov_common_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))p11prov_common_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p11prov_mlkem_keymgmt_free_fn },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p11prov_mlkem_keymgmt_load_fn },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p11prov_mlkem_keymgmt_has_fn },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p11prov_mlkem_keymgmt_match_fn },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_get_params_fn },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_gettable_params_fn },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p11prov_mlkem_keymgmt_export_fn },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))p11prov_mlkem_keymgmt_export_types_fn },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem1024_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p11prov_mlkem_keymgmt_new_fn },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p11prov_mlkem1024_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p11prov_mlkem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
      (void (*)(void))p11prov_common_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))p11prov_common_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p11prov_mlkem_keymgmt_free_fn },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p11prov_mlkem_keymgmt_load_fn },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p11prov_mlkem_keymgmt_has_fn },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))p11prov_mlkem_keymgmt_match_fn },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_get_params_fn },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_gettable_params_fn },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p11prov_mlkem_keymgmt_export_fn },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))p11prov_mlkem_keymgmt_export_types_fn },
    { 0, NULL },
};
