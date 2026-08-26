/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* hss-pubkey-dump: phase-4 R9 test helper. Writes the raw CKA_VALUE
 * (RFC 8554 HSS wire-format public key bytes) of the sole CKK_HSS public
 * key object on a token to a file, via direct PKCS#11 calls.
 *
 * Needed because, unlike every other algorithm this harness cross-checks
 * (`openssl pkey -pubin -pubout` via the provider's SPKI encoder), HSS has
 * no SPKI encoder in the pkcs11-provider — only a PrivateKeyInfo PEM one
 * (this project's harness doesn't need public-key PEM anywhere else, so
 * one wasn't built for it). Going straight to the PKCS#11 API sidesteps
 * that gap rather than building an encoder no other test needs, and
 * doubles as an independent path to the same bytes lms-xdr-verify.c's
 * cross-check consumes — not derived through the pkcs11-provider at all. */
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

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <engine.so> <token-label> <outfile>\n",
                argv[0]);
        return 2;
    }
    const char *engine_path = argv[1];
    const char *token_label = argv[2];
    const char *outfile = argv[3];

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
        rv = fl->C_OpenSession(slots[s], CKF_SERIAL_SESSION, NULL, NULL,
                               &sess);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_OpenSession rv=%lu\n", (unsigned long)rv);
            return 1;
        }

        CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
        CK_KEY_TYPE kt = CKK_HSS_VAL;
        CK_ATTRIBUTE tmpl[2] = {
            { CKA_CLASS, &cls, sizeof(cls) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
        };
        rv = fl->C_FindObjectsInit(sess, tmpl, 2);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_FindObjectsInit rv=%lu\n", (unsigned long)rv);
            return 1;
        }
        CK_OBJECT_HANDLE objs[2];
        CK_ULONG nobjs = 0;
        rv = fl->C_FindObjects(sess, objs, 2, &nobjs);
        fl->C_FindObjectsFinal(sess);
        if (rv != CKR_OK || nobjs != 1) {
            fprintf(stderr,
                    "expected exactly 1 HSS public key on token '%s', "
                    "found %lu (or more)\n",
                    token_label, (unsigned long)nobjs);
            return 1;
        }
        CK_OBJECT_HANDLE obj = objs[0];

        CK_ATTRIBUTE val = { CKA_VALUE, NULL_PTR, 0 };
        rv = fl->C_GetAttributeValue(sess, obj, &val, 1);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_GetAttributeValue(size) rv=%lu\n",
                    (unsigned long)rv);
            return 1;
        }
        unsigned char *buf = malloc(val.ulValueLen);
        val.pValue = buf;
        rv = fl->C_GetAttributeValue(sess, obj, &val, 1);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_GetAttributeValue(data) rv=%lu\n",
                    (unsigned long)rv);
            return 1;
        }

        FILE *f = fopen(outfile, "wb");
        if (!f) {
            perror(outfile);
            return 1;
        }
        fwrite(buf, 1, val.ulValueLen, f);
        fclose(f);
        free(buf);
        fl->C_CloseSession(sess);
        fl->C_Finalize(NULL);
        return 0;
    }

    fprintf(stderr, "token '%s' not found\n", token_label);
    fl->C_Finalize(NULL);
    return 1;
}
