/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* hss-fallback-fixture: phase-6 R29 test helper. Creates a PUBLIC HSS
 * key object via direct C_CreateObject with a real, valid CKA_VALUE but
 * WITHOUT the official CKA_HSS_LEVELS/LMS_TYPE/LMOTS_TYPE attributes --
 * simulating the one case R25's own three-step fallback chain
 * (official attrs -> parse CKA_VALUE -> 1296 constant) had no fixture
 * to test against: a pre-R25-engine or imported key.
 *
 * Deliberately built from a W4 (non-default) key's own exported pubkey
 * bytes, not the C++ engine's own W8 default -- a W4 key's real
 * signature (2352 bytes) differs from the old hardcoded
 * HSS_L1_DEFAULT_SIG_SIZE fallback-of-last-resort (1296). If the
 * provider's sizing for THIS object came from that stale last-resort
 * constant instead of genuinely parsing the self-describing HSS wire
 * format out of CKA_VALUE, a real W4 signature would not verify against
 * it -- so a successful verify here is real evidence the parse-from-
 * CKA_VALUE leg of the fallback chain works, not a coincidence of both
 * paths agreeing on the same default. */
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
        fprintf(stderr,
                "usage: %s <engine.so> <token-label> <pubkey-cka-value-file>\n"
                "  creates a public HSS key object on the token holding "
                "the given raw CKA_VALUE bytes, WITHOUT the official "
                "CKA_HSS_LEVELS/LMS_TYPE/LMOTS_TYPE attrs\n",
                argv[0]);
        return 2;
    }
    const char *engine_path = argv[1];
    const char *token_label = argv[2];
    const char *pubkeyfile = argv[3];

    FILE *f = fopen(pubkeyfile, "rb");
    if (!f) {
        perror(pubkeyfile);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long pklen = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *pk = malloc(pklen);
    if (fread(pk, 1, pklen, f) != (size_t)pklen) {
        fprintf(stderr, "short read on %s\n", pubkeyfile);
        return 1;
    }
    fclose(f);

    void *handle = dlopen(engine_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen(%s): %s\n", engine_path, dlerror());
        return 1;
    }
    CK_C_GetFunctionList getlist =
        (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
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

        CK_BBOOL ck_true = CK_TRUE;
        CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
        CK_KEY_TYPE kt = CKK_HSS_VAL;
        /* No CKA_HSS_LEVELS/LMS_TYPE/LMOTS_TYPE here -- that omission
         * is the whole point of this fixture. */
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS, &cls, sizeof(cls) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
            { CKA_VERIFY, &ck_true, sizeof(ck_true) },
            { CKA_VALUE, pk, (CK_ULONG)pklen },
        };
        CK_OBJECT_HANDLE obj;
        rv = fl->C_CreateObject(sess, tmpl, 5, &obj);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_CreateObject rv=%lu\n", (unsigned long)rv);
            return 1;
        }
        printf("created: handle=%lu (no official HSS attrs)\n",
               (unsigned long)obj);

        fl->C_CloseSession(sess);
        fl->C_Finalize(NULL);
        return 0;
    }
    fprintf(stderr, "token '%s' not found\n", token_label);
    fl->C_Finalize(NULL);
    return 1;
}
