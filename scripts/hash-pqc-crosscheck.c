/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* hash-pqc-crosscheck: verification-only helper for the OpenSSL-provider
 * remediation item 5 (HashML-DSA / HashSLH-DSA pre-hash family). Drives
 * the raw PKCS#11 C_* API directly against an engine .so (same technique
 * as generic-hash-mldsa-probe.c, which already independently confirmed
 * the engine's own bare CKM_HASH_ML_DSA/CKM_HASH_SLH_DSA mechanisms are
 * spec-conformant). This tool's own job is different: it creates
 * TOKEN-persistent keys with a fixed CKA_ID so a SEPARATE process (the
 * OpenSSL pkcs11-provider, addressing the same object via a pkcs11: URI)
 * can sign/verify against the exact same keypair, enabling a genuine
 * cross-process, cross-implementation signature interchange check --
 * "does a signature this raw engine call produces verify under the
 * OpenSSL provider's own new HASH-ML-DSA/HASH-SLH-DSA algorithm, and
 * vice versa" -- which a single-process self-check can't demonstrate.
 *
 * Modes (first two argv after engine.so/token-label):
 *   genkeys                         -- create both keypairs (idempotent
 *                                       per fresh token; run once)
 *   sign-mldsa   <digest-name>      -- PHM = digest(FIXED_MESSAGE) via
 *                                       that digest, sign with bare
 *                                       CKM_HASH_ML_DSA, print sig hex
 *   verify-mldsa <digest-name> <sig-hex>
 *   sign-slhdsa  <digest-name>
 *   verify-slhdsa <digest-name> <sig-hex>
 *
 * digest-name is one of: SHA256, SHA384, SHA512, SHA3-256 (matches
 * OSSLMLDSA.cpp/OSSLSLHDSA.cpp's own getPreHashInfo() names for the
 * PKCS#11 CKM_SHA* constant it maps to).
 *
 * CKA_ID: 0x10 for the ML-DSA-65 keypair, 0x20 for the SLH-DSA-SHA3-256
 * keypair -- arbitrary but fixed, so a pkcs11: URI
 * (id=%10 / id=%20) addresses the same object from any process sharing
 * this arena's token directory. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/evp.h>
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"

static CK_FUNCTION_LIST_PTR fl;

static const unsigned char FIXED_MESSAGE[] =
    "item-5 cross-check message: shared between the raw PKCS#11 engine "
    "call and the OpenSSL pkcs11-provider HASH-ML-DSA/HASH-SLH-DSA path";

static CK_MECHANISM_TYPE digest_mech_for_name(const char *name)
{
    if (strcasecmp(name, "SHA256") == 0 || strcasecmp(name, "SHA2-256") == 0) {
        return CKM_SHA256;
    }
    if (strcasecmp(name, "SHA384") == 0 || strcasecmp(name, "SHA2-384") == 0) {
        return CKM_SHA384;
    }
    if (strcasecmp(name, "SHA512") == 0 || strcasecmp(name, "SHA2-512") == 0) {
        return CKM_SHA512;
    }
    if (strcasecmp(name, "SHA3-256") == 0) {
        return CKM_SHA3_256;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

static const EVP_MD *evp_md_for_name(const char *name)
{
    if (strcasecmp(name, "SHA256") == 0 || strcasecmp(name, "SHA2-256") == 0) {
        return EVP_sha256();
    }
    if (strcasecmp(name, "SHA384") == 0 || strcasecmp(name, "SHA2-384") == 0) {
        return EVP_sha384();
    }
    if (strcasecmp(name, "SHA512") == 0 || strcasecmp(name, "SHA2-512") == 0) {
        return EVP_sha512();
    }
    if (strcasecmp(name, "SHA3-256") == 0) {
        return EVP_sha3_256();
    }
    return NULL;
}

static void hex_encode(const unsigned char *in, size_t len, char *out)
{
    static const char hexch[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hexch[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hexch[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}

static size_t hex_decode(const char *in, unsigned char *out, size_t outcap)
{
    size_t len = strlen(in) / 2;
    if (len > outcap) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        sscanf(in + 2 * i, "%2x", &b);
        out[i] = (unsigned char)b;
    }
    return len;
}

static CK_OBJECT_HANDLE find_obj(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS class,
                                 CK_BYTE id)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_ID, &id, sizeof(id) },
    };
    CK_OBJECT_HANDLE handle = 0;
    CK_ULONG count = 0;
    if (fl->C_FindObjectsInit(sess, tmpl, 2) != CKR_OK) {
        return 0;
    }
    fl->C_FindObjects(sess, &handle, 1, &count);
    fl->C_FindObjectsFinal(sess);
    if (count != 1) {
        return 0;
    }
    return handle;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr,
               "usage: %s <engine.so> <token-label> genkeys\n"
               "       %s <engine.so> <token-label> sign-mldsa|sign-slhdsa "
               "<digest> \n"
               "       %s <engine.so> <token-label> verify-mldsa|"
               "verify-slhdsa <digest> <sig-hex>\n",
               argv[0], argv[0], argv[0]);
        return 2;
    }
    const char *engine_path = argv[1];
    const char *token_label = argv[2];
    const char *mode = argv[3];

    void *handle = dlopen(engine_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen(%s): %s\n", engine_path, dlerror());
        return 1;
    }
    CK_C_GetFunctionList getlist =
        (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    if (!getlist || getlist(&fl) != CKR_OK) {
        fprintf(stderr, "failed to get function list\n");
        return 1;
    }
    if (fl->C_Initialize(NULL) != CKR_OK) {
        fprintf(stderr, "C_Initialize failed\n");
        return 1;
    }

    CK_SLOT_ID slots[16];
    CK_ULONG nslots = 16;
    if (fl->C_GetSlotList(CK_TRUE, slots, &nslots) != CKR_OK) {
        fprintf(stderr, "C_GetSlotList failed\n");
        return 1;
    }

    CK_SLOT_ID found_slot = (CK_SLOT_ID)-1;
    for (CK_ULONG s = 0; s < nslots; s++) {
        CK_TOKEN_INFO tinfo;
        if (fl->C_GetTokenInfo(slots[s], &tinfo) != CKR_OK) {
            continue;
        }
        char label[33];
        memcpy(label, tinfo.label, 32);
        label[32] = '\0';
        for (int i = 31; i >= 0 && label[i] == ' '; i--) {
            label[i] = '\0';
        }
        if (strcmp(label, token_label) == 0) {
            found_slot = slots[s];
            break;
        }
    }
    if (found_slot == (CK_SLOT_ID)-1) {
        fprintf(stderr, "token '%s' not found\n", token_label);
        return 1;
    }

    CK_SESSION_HANDLE sess;
    if (fl->C_OpenSession(found_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL, NULL, &sess)
        != CKR_OK) {
        fprintf(stderr, "C_OpenSession failed\n");
        return 1;
    }
    if (fl->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4) != CKR_OK) {
        fprintf(stderr, "C_Login failed\n");
        return 1;
    }

    if (strcmp(mode, "genkeys") == 0) {
        CK_BBOOL ck_true = CK_TRUE;
        CK_BYTE mldsa_id = 0x10;
        CK_KEY_TYPE mldsa_kt = CKK_ML_DSA;
        CK_ULONG mldsa_paramset = CKP_ML_DSA_65;
        CK_ATTRIBUTE mldsa_pub_tmpl[] = {
            { CKA_KEY_TYPE, &mldsa_kt, sizeof(mldsa_kt) },
            { CKA_PARAMETER_SET, &mldsa_paramset, sizeof(mldsa_paramset) },
            { CKA_VERIFY, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
            { CKA_ID, &mldsa_id, sizeof(mldsa_id) },
        };
        CK_ATTRIBUTE mldsa_priv_tmpl[] = {
            { CKA_KEY_TYPE, &mldsa_kt, sizeof(mldsa_kt) },
            { CKA_PARAMETER_SET, &mldsa_paramset, sizeof(mldsa_paramset) },
            { CKA_SIGN, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
            { CKA_ID, &mldsa_id, sizeof(mldsa_id) },
            { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        };
        CK_MECHANISM mldsa_keygen_mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE mldsa_pub, mldsa_priv;
        CK_RV rv = fl->C_GenerateKeyPair(sess, &mldsa_keygen_mech,
                                         mldsa_pub_tmpl, 5, mldsa_priv_tmpl, 6,
                                         &mldsa_pub, &mldsa_priv);
        if (rv != CKR_OK) {
            fprintf(stderr, "ML-DSA C_GenerateKeyPair rv=%lu\n",
                   (unsigned long)rv);
            return 1;
        }

        CK_BYTE slhdsa_id = 0x20;
        CK_KEY_TYPE slhdsa_kt = CKK_SLH_DSA;
        CK_ULONG slhdsa_paramset = CKP_SLH_DSA_SHA2_128S;
        CK_ATTRIBUTE slhdsa_pub_tmpl[] = {
            { CKA_KEY_TYPE, &slhdsa_kt, sizeof(slhdsa_kt) },
            { CKA_PARAMETER_SET, &slhdsa_paramset, sizeof(slhdsa_paramset) },
            { CKA_VERIFY, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
            { CKA_ID, &slhdsa_id, sizeof(slhdsa_id) },
        };
        CK_ATTRIBUTE slhdsa_priv_tmpl[] = {
            { CKA_KEY_TYPE, &slhdsa_kt, sizeof(slhdsa_kt) },
            { CKA_PARAMETER_SET, &slhdsa_paramset, sizeof(slhdsa_paramset) },
            { CKA_SIGN, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
            { CKA_ID, &slhdsa_id, sizeof(slhdsa_id) },
            { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        };
        CK_MECHANISM slhdsa_keygen_mech = { CKM_SLH_DSA_KEY_PAIR_GEN, NULL,
                                            0 };
        CK_OBJECT_HANDLE slhdsa_pub, slhdsa_priv;
        rv = fl->C_GenerateKeyPair(sess, &slhdsa_keygen_mech, slhdsa_pub_tmpl,
                                   5, slhdsa_priv_tmpl, 6, &slhdsa_pub,
                                   &slhdsa_priv);
        if (rv != CKR_OK) {
            fprintf(stderr, "SLH-DSA C_GenerateKeyPair rv=%lu\n",
                   (unsigned long)rv);
            return 1;
        }
        printf("genkeys OK (mldsa id=0x10, slhdsa id=0x20)\n");
        return 0;
    }

    int is_mldsa = (strcmp(mode, "sign-mldsa") == 0
                    || strcmp(mode, "verify-mldsa") == 0);
    int is_sign =
        (strcmp(mode, "sign-mldsa") == 0 || strcmp(mode, "sign-slhdsa") == 0);
    if (strcmp(mode, "sign-mldsa") && strcmp(mode, "verify-mldsa")
        && strcmp(mode, "sign-slhdsa") && strcmp(mode, "verify-slhdsa")) {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    if (argc < 5) {
        fprintf(stderr, "missing <digest> argument\n");
        return 2;
    }
    const char *digest_name = argv[4];
    CK_MECHANISM_TYPE digest_mech = digest_mech_for_name(digest_name);
    const EVP_MD *md = evp_md_for_name(digest_name);
    if (digest_mech == CK_UNAVAILABLE_INFORMATION || md == NULL) {
        fprintf(stderr, "unsupported digest %s\n", digest_name);
        return 2;
    }

    unsigned char phm[64];
    unsigned int phm_len = 0;
    if (!EVP_Digest(FIXED_MESSAGE, sizeof(FIXED_MESSAGE) - 1, phm, &phm_len,
                    md, NULL)) {
        fprintf(stderr, "EVP_Digest failed\n");
        return 1;
    }

    CK_BYTE id = is_mldsa ? 0x10 : 0x20;
    CK_MECHANISM_TYPE generic = is_mldsa ? CKM_HASH_ML_DSA : CKM_HASH_SLH_DSA;
    CK_HASH_SIGN_ADDITIONAL_CONTEXT hctx = { CKH_HEDGE_PREFERRED, NULL, 0,
                                             digest_mech };
    CK_MECHANISM mech = { generic, &hctx, sizeof(hctx) };

    if (is_sign) {
        CK_OBJECT_HANDLE priv = find_obj(sess, CKO_PRIVATE_KEY, id);
        if (priv == 0) {
            fprintf(stderr, "private key id=0x%02x not found (run genkeys "
                           "first)\n",
                   id);
            return 1;
        }
        if (fl->C_SignInit(sess, &mech, priv) != CKR_OK) {
            fprintf(stderr, "C_SignInit failed\n");
            return 1;
        }
        unsigned char sig[65536];
        CK_ULONG siglen = sizeof(sig);
        CK_RV rv = fl->C_Sign(sess, phm, phm_len, sig, &siglen);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_Sign rv=%lu\n", (unsigned long)rv);
            return 1;
        }
        char hex[131072];
        hex_encode(sig, siglen, hex);
        printf("%s\n", hex);
        return 0;
    } else {
        if (argc < 6) {
            fprintf(stderr, "missing <sig-hex> argument\n");
            return 2;
        }
        CK_OBJECT_HANDLE pub = find_obj(sess, CKO_PUBLIC_KEY, id);
        if (pub == 0) {
            fprintf(stderr, "public key id=0x%02x not found (run genkeys "
                           "first)\n",
                   id);
            return 1;
        }
        unsigned char sig[65536];
        size_t siglen = hex_decode(argv[5], sig, sizeof(sig));
        if (siglen == 0) {
            fprintf(stderr, "bad sig-hex\n");
            return 2;
        }
        if (fl->C_VerifyInit(sess, &mech, pub) != CKR_OK) {
            fprintf(stderr, "C_VerifyInit failed\n");
            return 1;
        }
        CK_RV rv = fl->C_Verify(sess, phm, phm_len, sig, (CK_ULONG)siglen);
        if (rv != CKR_OK) {
            printf("VERIFY FAILED (rv=0x%lx)\n", (unsigned long)rv);
            return 1;
        }
        printf("VERIFY OK\n");
        return 0;
    }
}
