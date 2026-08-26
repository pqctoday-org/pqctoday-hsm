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

    /* R15 — server role: materialize the peer's public key onto a real
     * slot BEFORE any session lookup keyed by that slot. A freshly
     * imported/mock peer key (see mock_pub_mlkem_key /
     * p11prov_mlkem_keymgmt_set_params_fn) has slotid ==
     * CK_UNAVAILABLE_INFORMATION until p11prov_obj_get_handle triggers
     * its lazy on-token materialization — but p11prov_try_session_ref
     * reads the object's CURRENT slotid to validate the mechanism
     * against that slot (p11prov_check_mechanism), and CK_UNAVAILABLE_
     * INFORMATION never matches a real slot's id, so it silently fails
     * with CKR_MECHANISM_INVALID before ever reaching the object's own
     * materialization step. Live-traced: p11prov_kem_init succeeds and
     * is reached with the correctly populated object, but this function
     * returned 0 here with zero log output, immediately after — every
     * existing decapsulate-exercising test never hit this ordering
     * issue because its key was always already materialized (a real
     * token object from keygen), never a fresh mock. Getting the handle
     * first — same as decapsulate already does a few lines below in
     * this same file — fixes the ordering for both.  */
    hKey = p11prov_obj_get_handle(kemctx->key);

    if (kemctx->session == NULL) {
        ret = p11prov_try_session_ref(kemctx->key, kemctx->mechtype, false, false, &kemctx->session);
        if (ret != CKR_OK || kemctx->session == NULL) {
            return 0;
        }
    }

    session = p11prov_session_handle(kemctx->session);

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
        /* R15: encapsulate's size-query must report BOTH output sizes —
         * the ciphertext (outlen, above) AND the shared secret
         * (secretlen) — matching FIPS 203's fixed 32-byte ML-KEM shared
         * secret (same constant p11prov_kem_decapsulate uses a few
         * lines below for its own size query). Leaving secretlen
         * untouched left it at the caller's zero-initialized default;
         * OpenSSL's ssl_encapsulate() (ssl/s3_lib.c) treats pmslen==0
         * as a hard failure even though ctlen was already correct —
         * live-traced: the PKCS#11 call itself succeeded (ctlen=1088,
         * CKR_OK) and this was still the reason the handshake failed. */
        if (secretlen != NULL) {
            *secretlen = 32;
        }
        return 1;
    }

    /* Actually Encapsulate */
    CK_ULONG out_len_ck = *outlen;
    CK_ATTRIBUTE ts[4];
    CK_ULONG tlen = 0;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;
    CK_BBOOL not_private = CK_FALSE;

    ts[0].type = CKA_CLASS;
    ts[0].pValue = &class;
    ts[0].ulValueLen = sizeof(class);
    ts[1].type = CKA_KEY_TYPE;
    ts[1].pValue = &type;
    ts[1].ulValueLen = sizeof(type);
    ts[2].type = CKA_EXTRACTABLE;
    ts[2].pValue = &extractable;
    ts[2].ulValueLen = sizeof(extractable);
    /* R15: the C++ engine defaults CKA_PRIVATE to true when a template
     * omits it, requiring a login this session was never given (server
     * role: no private-key op of its own precedes this, unlike every
     * existing decapsulate-exercising test, which happens to always run
     * after a keygen/URI-decode that already logged the token in — the
     * identical omission there is a latent bug too, just never
     * triggered). Live-observed via a real handshake before this line
     * was added. */
    ts[3].type = CKA_PRIVATE;
    ts[3].pValue = &not_private;
    ts[3].ulValueLen = sizeof(not_private);
    tlen = 4;

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

    CK_ATTRIBUTE ts[4];
    CK_ULONG tlen = 0;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;
    CK_BBOOL not_private = CK_FALSE;

    ts[0].type = CKA_CLASS;
    ts[0].pValue = &class;
    ts[0].ulValueLen = sizeof(class);
    ts[1].type = CKA_KEY_TYPE;
    ts[1].pValue = &type;
    ts[1].ulValueLen = sizeof(type);
    ts[2].type = CKA_EXTRACTABLE;
    ts[2].pValue = &extractable;
    ts[2].ulValueLen = sizeof(extractable);
    /* R15 consistency fix: same CKA_PRIVATE-defaults-true omission as
     * encapsulate's template above — latent here too (masked by every
     * existing test running after a login-requiring keygen/decode). */
    ts[3].type = CKA_PRIVATE;
    ts[3].pValue = &not_private;
    ts[3].ulValueLen = sizeof(not_private);
    tlen = 4;

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
    void *k = p11prov_obj_new(provctx, CK_UNAVAILABLE_INFORMATION,
                              CK_P11PROV_IMPORTED_HANDLE,
                              CK_UNAVAILABLE_INFORMATION);
    return k;
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
    /* R5 prerequisite #1: TLS reads a key's share via
     * EVP_PKEY_get1_encoded_public_key, which is this param — only EC
     * keymgmt had it before (keymgmt.c); ML-KEM's own public bytes ARE the
     * encoded form, no point-compression step needed, so this is really
     * just PUB_KEY under TLS's expected name. Unlike the PUB_KEY branch
     * above (which reads CKA_VALUE off `key` directly and is only correct
     * when `key` is already public-class), TLS holds the generated
     * PRIVATE object — so this walks to the associated public object
     * first via p11prov_obj_get_associated, the same borrowed-reference
     * accessor p11prov_obj_get_ed_pub_key (objects.c) already uses for
     * exactly this walk; p11prov_common_gen sets the association at
     * keygen time (p11prov_obj_set_associated), so it is already cached
     * here with no extra PKCS#11 round trip and nothing to free. */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p) {
        CK_ATTRIBUTE *pub;
        P11PROV_OBJ *pub_obj = key;

        if (p->data_type != OSSL_PARAM_OCTET_STRING) return RET_OSSL_ERR;
        if (p11prov_obj_get_class(key) == CKO_PRIVATE_KEY) {
            P11PROV_OBJ *assoc = p11prov_obj_get_associated(key);
            if (assoc) {
                pub_obj = assoc;
            }
        }
        pub = p11prov_obj_get_attr(pub_obj, CKA_VALUE);
        if (!pub) return RET_OSSL_ERR;
        p->return_size = pub->ulValueLen;
        if (p->data) {
            if (p->data_size < pub->ulValueLen) return RET_OSSL_ERR;
            memcpy(p->data, pub->pValue, pub->ulValueLen);
            p->data_size = pub->ulValueLen;
        }
    }
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mlkem_keymgmt_gettable_params_fn(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_CMS_RI_TYPE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

/* R5 prerequisite #2: was "class == CKO_PUBLIC_KEY" strictly, refusing a
 * private-class object even when only public params were selected — unlike
 * ML-DSA's export (keymgmt.c's p11prov_mldsa_export), which allows any
 * class through under the same selection-only-has-public-bits condition.
 * The old comment here worried that calling p11prov_obj_export_public_key
 * on a private object "returns garbage" — checked live and by reading
 * get_public_attrs (objects.c): for CKO_PRIVATE_KEY it already walks to
 * the associated CKO_PUBLIC_KEY object via p11prov_obj_find_associated
 * before reading CKA_VALUE, exactly the same fallback ML-DSA's export
 * already relies on. Needed so TLS key-share export
 * (OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, get_params below) can work on the
 * private object TLS actually holds after ephemeral keygen — see R5. */
#define MLKEM_PUBLIC_PARAMS \
    (OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
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

    if (class == CKO_PUBLIC_KEY || (selection & ~MLKEM_PUBLIC_PARAMS) == 0) {
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

/* R15 — server role: import a peer's raw public share (arrives as plain
 * octet-string bytes from a TLS ClientHello, not any existing token
 * object) so C_EncapsulateKey has something to operate on. Modeled on
 * keymgmt.c's p11prov_mldsa_import — the actual work (attribute template
 * construction, spec-size validation, lazy on-token materialization at
 * the point a real handle is first requested) lives in objects.c's
 * prep_mlkem_find / p11prov_store_mlkem_public_key, reached generically
 * through p11prov_obj_import_key. Scoped to the public-key case only:
 * ML-KEM private keys already exist via the R3b keygen path, so import
 * only needs to cover the one new case TLS's server role actually needs. */
static int p11prov_mlkem_keymgmt_import_fn(void *keydata, int selection,
                                           const OSSL_PARAM params[],
                                           CK_ML_KEM_PARAMETER_SET_TYPE param_set)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_RV rv;

    P11PROV_debug("mlkem import %p", key);

    if (!key) {
        return RET_OSSL_ERR;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0) {
        P11PROV_raise(p11prov_obj_get_prov_ctx(key), CKR_KEY_INDIGESTIBLE,
                      "ML-KEM import only supports the public key (server "
                      "peer-share role) — private keys come from keygen");
        return RET_OSSL_ERR;
    }

    rv = p11prov_obj_import_key(key, CKK_ML_KEM, CKO_PUBLIC_KEY, param_set,
                                params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

/* R15 — server role, the actual missing piece: TLS 1.3's server-side
 * key_share processing does NOT call keymgmt IMPORT to receive the
 * client's public share. Traced directly against the real OpenSSL 3.6.3
 * source (ssl/statem/extensions_srvr.c:tls_accept_ksgroup ->
 * ssl/t1_lib.c:tls13_set_encoded_pub_key ->
 * crypto/evp/p_lib.c:EVP_PKEY_set1_encoded_public_key): for a
 * provider-native key it calls EVP_PKEY_set_octet_string_param(pkey,
 * OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, ...), which dispatches to the
 * keymgmt's plain OSSL_FUNC_KEYMGMT_SET_PARAMS — a generic function that
 * fills in an ALREADY-EXISTING key object (the one gen_init/gen just
 * built as an empty parameters-only placeholder), not IMPORT (which is
 * for constructing a brand-new object and explicitly refuses to run on
 * one that already has a class set — p11prov_obj_import_key's own "Non
 * empty object" guard). No keymgmt in this whole provider registered
 * SET_PARAMS before this — likely also affects EC/ECDH's own server
 * role, not just ML-KEM, though that's a separate finding, not chased
 * here. Populates the mock object's attrs directly rather than routing
 * through p11prov_obj_import_key, for exactly the reason above. */
static int p11prov_mlkem_keymgmt_set_params_fn(void *keydata,
                                               const OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    const OSSL_PARAM *p;
    CK_ATTRIBUTE value_attr = { 0 };
    CK_ATTRIBUTE pset_attr = { 0 };
    CK_ULONG key_size;
    CK_ULONG param_set;
    CK_RV rv;

    if (!key) {
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (!p) {
        /* Nothing relevant in this params[] batch; not an error — other
         * keymgmts' SET_PARAMS handlers behave the same way for params
         * they don't recognize. */
        return RET_OSSL_OK;
    }
    if (p->data == NULL || p->data_size == 0) {
        P11PROV_raise(p11prov_obj_get_prov_ctx(key), CKR_KEY_INDIGESTIBLE,
                      "Empty ML-KEM encoded public key");
        return RET_OSSL_ERR;
    }
    key_size = p11prov_obj_get_key_size(key);
    if (p->data_size != key_size) {
        P11PROV_raise(p11prov_obj_get_prov_ctx(key), CKR_KEY_INDIGESTIBLE,
                      "Unexpected ML-KEM public key size %zu (expected %lu)",
                      p->data_size, (unsigned long)key_size);
        return RET_OSSL_ERR;
    }

    /* Mock object from gen(): class/type/param_set/size already set
     * (mock_pub_mlkem_key), no attrs yet — add the two the rest of this
     * provider's ML-KEM code expects to find (prep_mlkem_find /
     * p11prov_store_mlkem_public_key both read CKA_VALUE + CKA_
     * PARAMETER_SET off the object directly). */
    value_attr.type = CKA_VALUE;
    value_attr.pValue = OPENSSL_memdup(p->data, p->data_size);
    if (!value_attr.pValue) {
        return RET_OSSL_ERR;
    }
    value_attr.ulValueLen = p->data_size;

    param_set = p11prov_obj_get_key_param_set(key);
    pset_attr.type = CKA_PARAMETER_SET;
    pset_attr.pValue = OPENSSL_memdup(&param_set, sizeof(param_set));
    if (!pset_attr.pValue) {
        OPENSSL_free(value_attr.pValue);
        return RET_OSSL_ERR;
    }
    pset_attr.ulValueLen = sizeof(param_set);

    rv = p11prov_obj_add_attr(key, &value_attr);
    if (rv != CKR_OK) {
        OPENSSL_free(value_attr.pValue);
        OPENSSL_free(pset_attr.pValue);
        return RET_OSSL_ERR;
    }
    rv = p11prov_obj_add_attr(key, &pset_attr);
    if (rv != CKR_OK) {
        OPENSSL_free(pset_attr.pValue);
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mlkem_keymgmt_settable_params_fn(void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    return settable;
}

static int p11prov_mlkem512_import(void *keydata, int selection,
                                   const OSSL_PARAM params[])
{
    return p11prov_mlkem_keymgmt_import_fn(keydata, selection, params,
                                           CKP_ML_KEM_512);
}

static int p11prov_mlkem768_import(void *keydata, int selection,
                                   const OSSL_PARAM params[])
{
    return p11prov_mlkem_keymgmt_import_fn(keydata, selection, params,
                                           CKP_ML_KEM_768);
}

static int p11prov_mlkem1024_import(void *keydata, int selection,
                                    const OSSL_PARAM params[])
{
    return p11prov_mlkem_keymgmt_import_fn(keydata, selection, params,
                                           CKP_ML_KEM_1024);
}

static const OSSL_PARAM *p11prov_mlkem_keymgmt_import_types_fn(int selection)
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
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p11prov_mlkem512_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))p11prov_mlkem_keymgmt_import_types_fn },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_set_params_fn },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_settable_params_fn },
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
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p11prov_mlkem768_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))p11prov_mlkem_keymgmt_import_types_fn },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_set_params_fn },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_settable_params_fn },
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
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p11prov_mlkem1024_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))p11prov_mlkem_keymgmt_import_types_fn },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_set_params_fn },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
      (void (*)(void))p11prov_mlkem_keymgmt_settable_params_fn },
    { 0, NULL },
};
