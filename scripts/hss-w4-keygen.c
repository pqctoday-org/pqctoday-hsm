/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* hss-w4-keygen: phase-5 R25 test helper. Generates an HSS/LMS keypair
 * with EXPLICIT, non-default CK_HSS_KEY_PAIR_GEN_PARAMS (LMOTS_SHA256_
 * N32_W4 -- the Rust engine's own default, distinct from the C++ engine's
 * documented default of W8) directly via C_GenerateKeyPair, as TOKEN
 * objects on an already-initialized token.
 *
 * Needed because this provider's own HSS keymgmt has no gen_set_params
 * surface to request a non-default parameter set (R25's plan explicitly
 * chose not to grow one for this) -- going straight to the raw PKCS#11
 * API is smaller, and the resulting key still flows through the provider
 * normally for every later load/sign/verify step, so this tool's own job
 * ends at keygen. Used to prove sig/hss.c's hss_sig_size() genuinely
 * computes a DIFFERENT, per-parameter-set signature length (2352 bytes
 * for W4 vs 1296 for the W8 default) rather than returning a constant
 * that happens to be right once. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"

#define CKK_HSS_VAL 0x00000046UL
#define CKM_HSS_KEY_PAIR_GEN_VAL 0x00004032UL
#define HSS_MAX_LEVELS 8
#define CKP_LMS_SHA256_M32_H5_VAL 0x00000005UL
#define CKP_LMOTS_SHA256_N32_W4_VAL 0x00000003UL

typedef struct CK_HSS_KEY_PAIR_GEN_PARAMS {
    CK_ULONG ulLevels;
    CK_ULONG ulLmsParamSet[HSS_MAX_LEVELS];
    CK_ULONG ulLmotsParamSet[HSS_MAX_LEVELS];
} CK_HSS_KEY_PAIR_GEN_PARAMS;

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <engine.so> <token-label>\n", argv[0]);
        return 2;
    }
    const char *engine_path = argv[1];
    const char *token_label = argv[2];

    void *handle = dlopen(engine_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen(%s): %s\n", engine_path, dlerror());
        return 1;
    }
    CK_C_GetFunctionList getlist =
        (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    if (!getlist) {
        fprintf(stderr, "no C_GetFunctionList in %s\n", engine_path);
        return 1;
    }
    CK_FUNCTION_LIST_PTR fl;
    CK_RV rv = getlist(&fl);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetFunctionList rv=%lu\n", (unsigned long)rv);
        return 1;
    }
    rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize rv=%lu\n", (unsigned long)rv);
        return 1;
    }

    CK_SLOT_ID slots[16];
    CK_ULONG nslots = 16;
    rv = fl->C_GetSlotList(CK_TRUE, slots, &nslots);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetSlotList rv=%lu\n", (unsigned long)rv);
        return 1;
    }

    for (CK_ULONG s = 0; s < nslots; s++) {
        CK_TOKEN_INFO tinfo;
        if (fl->C_GetTokenInfo(slots[s], &tinfo) != CKR_OK)
            continue;
        char label[33];
        memcpy(label, tinfo.label, 32);
        label[32] = '\0';
        for (int i = 31; i >= 0 && label[i] == ' '; i--)
            label[i] = '\0';
        if (strcmp(label, token_label) != 0)
            continue;

        CK_SESSION_HANDLE sess;
        rv = fl->C_OpenSession(slots[s], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL, NULL, &sess);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_OpenSession rv=%lu\n", (unsigned long)rv);
            return 1;
        }
        rv = fl->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_Login rv=%lu\n", (unsigned long)rv);
            return 1;
        }

        CK_HSS_KEY_PAIR_GEN_PARAMS hss_params;
        memset(&hss_params, 0, sizeof(hss_params));
        hss_params.ulLevels = 1;
        hss_params.ulLmsParamSet[0] = CKP_LMS_SHA256_M32_H5_VAL;
        hss_params.ulLmotsParamSet[0] = CKP_LMOTS_SHA256_N32_W4_VAL;
        CK_MECHANISM mech = { CKM_HSS_KEY_PAIR_GEN_VAL, &hss_params,
                              sizeof(hss_params) };

        CK_BBOOL ck_true = CK_TRUE;
        CK_KEY_TYPE kt = CKK_HSS_VAL;
        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_VERIFY, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_SIGN, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        };
        CK_OBJECT_HANDLE pub, priv;
        rv = fl->C_GenerateKeyPair(sess, &mech, pub_tmpl, 3, priv_tmpl, 3,
                                   &pub, &priv);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_GenerateKeyPair rv=%lu\n", (unsigned long)rv);
            return 1;
        }

        fl->C_CloseSession(sess);
        fl->C_Finalize(NULL);
        return 0;
    }

    fprintf(stderr, "token '%s' not found\n", token_label);
    fl->C_Finalize(NULL);
    return 1;
}
