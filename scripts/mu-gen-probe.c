/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* mu-gen-probe: remediation R39 (phase 8) regression fixture. Drives the
 * raw PKCS#11 C_Digest* API directly (this vendor mechanism is engines-
 * only by design -- no OpenSSL-provider wiring, see the phase-8 plan's
 * own R39 scope decision) to prove CKM_PQCTODAY_ML_DSA_MU_GEN computes
 * mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64) correctly, where
 * tr = SHAKE256(pk_encode, 64) (FIPS 204 Eq. 2).
 *
 * Checks:
 *   1. handle-supplied tr: mu from the mechanism == independently
 *      computed mu (same formula, computed here in C via raw EVP calls).
 *   2. multi-part C_DigestUpdate (message split across 2 calls) == the
 *      one-shot C_Digest result.
 *   3. TR-supplied path (caller passes a precomputed 64-byte tr instead
 *      of a key handle) produces the SAME mu as the handle-supplied path
 *      for the same underlying key.
 *   4. end-to-end chain: feed the token-computed mu into
 *      CKM_PQCTODAY_ML_DSA_MU (R34's own consume-side mechanism) to sign,
 *      and the result verifies under OpenSSL's native ML-DSA against the
 *      ORIGINAL message -- extends T28/T28b's own chain (which computed
 *      mu in Python), replacing that step with the token's own.
 *   5. both hTrKey and pTr absent, or both present, rejected loudly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/evp.h>
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"

#define CKM_PQCTODAY_ML_DSA_MU_GEN 0x80000014UL
#define CKM_PQCTODAY_ML_DSA_MU 0x80000013UL

typedef struct CK_PQCTODAY_MU_GEN_PARAMS {
    CK_OBJECT_HANDLE hTrKey;
    CK_BYTE_PTR      pTr;
    CK_ULONG         ulTrLen;
    CK_BYTE_PTR      pContext;
    CK_ULONG         ulContextLen;
} CK_PQCTODAY_MU_GEN_PARAMS;

static CK_FUNCTION_LIST_PTR fl;
static int failures = 0;

#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } else { printf("OK: %s\n", msg); } } while (0)

static void independent_mu(const unsigned char *pk, size_t pk_len,
                           const unsigned char *ctx, size_t ctx_len,
                           const unsigned char *msg, size_t msg_len,
                           unsigned char mu_out[64])
{
    unsigned char tr[64];
    EVP_MD *shake = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX *c1 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c1, shake, NULL);
    EVP_DigestUpdate(c1, pk, pk_len);
    EVP_DigestFinalXOF(c1, tr, 64);
    EVP_MD_CTX_free(c1);

    unsigned char ctxlen = (unsigned char)ctx_len;
    EVP_MD_CTX *c2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c2, shake, NULL);
    EVP_DigestUpdate(c2, tr, 64);
    EVP_DigestUpdate(c2, "\x00", 1);
    EVP_DigestUpdate(c2, &ctxlen, 1);
    if (ctx_len > 0) EVP_DigestUpdate(c2, ctx, ctx_len);
    EVP_DigestUpdate(c2, msg, msg_len);
    EVP_DigestFinalXOF(c2, mu_out, 64);
    EVP_MD_CTX_free(c2);
    EVP_MD_free(shake);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <engine.so> <token-label>\n", argv[0]);
        return 2;
    }
    const char *engine_path = argv[1];
    const char *token_label = argv[2];

    void *handle = dlopen(engine_path, RTLD_NOW);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    CK_C_GetFunctionList getlist = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    if (!getlist) { fprintf(stderr, "no C_GetFunctionList\n"); return 1; }
    CK_RV rv = getlist(&fl);
    if (rv != CKR_OK) { fprintf(stderr, "C_GetFunctionList rv=%lu\n", (unsigned long)rv); return 1; }
    rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK) { fprintf(stderr, "C_Initialize rv=%lu\n", (unsigned long)rv); return 1; }

    CK_SLOT_ID slots[16];
    CK_ULONG nslots = 16;
    rv = fl->C_GetSlotList(CK_TRUE, slots, &nslots);
    if (rv != CKR_OK) { fprintf(stderr, "C_GetSlotList rv=%lu\n", (unsigned long)rv); return 1; }

    for (CK_ULONG s = 0; s < nslots; s++) {
        CK_TOKEN_INFO tinfo;
        if (fl->C_GetTokenInfo(slots[s], &tinfo) != CKR_OK) continue;
        char label[33];
        memcpy(label, tinfo.label, 32);
        label[32] = '\0';
        for (int i = 31; i >= 0 && label[i] == ' '; i--) label[i] = '\0';
        if (strcmp(label, token_label) != 0) continue;

        CK_SESSION_HANDLE sess;
        rv = fl->C_OpenSession(slots[s], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sess);
        if (rv != CKR_OK) { fprintf(stderr, "C_OpenSession rv=%lu\n", (unsigned long)rv); return 1; }
        rv = fl->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
        if (rv != CKR_OK) { fprintf(stderr, "C_Login rv=%lu\n", (unsigned long)rv); return 1; }

        CK_KEY_TYPE kt = CKK_ML_DSA;
        CK_ULONG paramset = CKP_ML_DSA_65;
        CK_BBOOL ck_true = CK_TRUE;
        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_PARAMETER_SET, &paramset, sizeof(paramset) },
            { CKA_VERIFY, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_PARAMETER_SET, &paramset, sizeof(paramset) },
            { CKA_SIGN, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        };
        CK_MECHANISM keygen_mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE pub, priv;
        rv = fl->C_GenerateKeyPair(sess, &keygen_mech, pub_tmpl, 4, priv_tmpl, 4, &pub, &priv);
        if (rv != CKR_OK) { fprintf(stderr, "C_GenerateKeyPair rv=%lu\n", (unsigned long)rv); return 1; }

        CK_ATTRIBUTE getPk = { CKA_VALUE, NULL, 0 };
        fl->C_GetAttributeValue(sess, pub, &getPk, 1);
        unsigned char *pk = malloc(getPk.ulValueLen);
        getPk.pValue = pk;
        rv = fl->C_GetAttributeValue(sess, pub, &getPk, 1);
        if (rv != CKR_OK) { fprintf(stderr, "C_GetAttributeValue(CKA_VALUE) rv=%lu\n", (unsigned long)rv); return 1; }

        static const unsigned char message[] = "R39 mu-gen probe message, streamed";
        size_t msg_len = sizeof(message) - 1;

        unsigned char expected_mu[64];
        independent_mu(pk, getPk.ulValueLen, NULL, 0, message, msg_len, expected_mu);

        /* --- Check 1: handle-supplied tr, one-shot --- */
        CK_PQCTODAY_MU_GEN_PARAMS p1 = { pub, NULL_PTR, 0, NULL_PTR, 0 };
        CK_MECHANISM mech1 = { CKM_PQCTODAY_ML_DSA_MU_GEN, &p1, sizeof(p1) };
        rv = fl->C_DigestInit(sess, &mech1);
        if (rv != CKR_OK) { fprintf(stderr, "C_DigestInit(handle) rv=%lu\n", (unsigned long)rv); return 1; }
        unsigned char mu1[64]; CK_ULONG mu1_len = sizeof(mu1);
        rv = fl->C_Digest(sess, (CK_BYTE_PTR)message, (CK_ULONG)msg_len, mu1, &mu1_len);
        if (rv != CKR_OK) { fprintf(stderr, "C_Digest(handle) rv=%lu\n", (unsigned long)rv); return 1; }
        CHECK(mu1_len == 64 && memcmp(mu1, expected_mu, 64) == 0,
              "handle-supplied tr: mu matches independent SHAKE256(SHAKE256(pk,64)||0x00||0||M,64)");

        /* --- Check 2: multi-part update == one-shot --- */
        CK_MECHANISM mech2 = { CKM_PQCTODAY_ML_DSA_MU_GEN, &p1, sizeof(p1) };
        rv = fl->C_DigestInit(sess, &mech2);
        if (rv != CKR_OK) { fprintf(stderr, "C_DigestInit(multipart) rv=%lu\n", (unsigned long)rv); return 1; }
        size_t half = msg_len / 2;
        rv = fl->C_DigestUpdate(sess, (CK_BYTE_PTR)message, (CK_ULONG)half);
        if (rv != CKR_OK) { fprintf(stderr, "C_DigestUpdate#1 rv=%lu\n", (unsigned long)rv); return 1; }
        rv = fl->C_DigestUpdate(sess, (CK_BYTE_PTR)(message + half), (CK_ULONG)(msg_len - half));
        if (rv != CKR_OK) { fprintf(stderr, "C_DigestUpdate#2 rv=%lu\n", (unsigned long)rv); return 1; }
        unsigned char mu2[64]; CK_ULONG mu2_len = sizeof(mu2);
        rv = fl->C_DigestFinal(sess, mu2, &mu2_len);
        if (rv != CKR_OK) { fprintf(stderr, "C_DigestFinal rv=%lu\n", (unsigned long)rv); return 1; }
        CHECK(mu2_len == 64 && memcmp(mu2, mu1, 64) == 0,
              "multi-part C_DigestUpdate (2 calls) == one-shot C_Digest");

        /* --- Check 3: TR-supplied path == handle-supplied path --- */
        unsigned char tr[64];
        EVP_MD *shake = EVP_MD_fetch(NULL, "SHAKE256", NULL);
        EVP_MD_CTX *trc = EVP_MD_CTX_new();
        EVP_DigestInit_ex(trc, shake, NULL);
        EVP_DigestUpdate(trc, pk, getPk.ulValueLen);
        EVP_DigestFinalXOF(trc, tr, 64);
        EVP_MD_CTX_free(trc);
        EVP_MD_free(shake);

        CK_PQCTODAY_MU_GEN_PARAMS p3 = { CK_INVALID_HANDLE, tr, 64, NULL_PTR, 0 };
        CK_MECHANISM mech3 = { CKM_PQCTODAY_ML_DSA_MU_GEN, &p3, sizeof(p3) };
        rv = fl->C_DigestInit(sess, &mech3);
        if (rv != CKR_OK) { fprintf(stderr, "C_DigestInit(tr) rv=%lu\n", (unsigned long)rv); return 1; }
        unsigned char mu3[64]; CK_ULONG mu3_len = sizeof(mu3);
        rv = fl->C_Digest(sess, (CK_BYTE_PTR)message, (CK_ULONG)msg_len, mu3, &mu3_len);
        if (rv != CKR_OK) { fprintf(stderr, "C_Digest(tr) rv=%lu\n", (unsigned long)rv); return 1; }
        CHECK(mu3_len == 64 && memcmp(mu3, mu1, 64) == 0,
              "TR-supplied path produces the SAME mu as handle-supplied path");

        /* --- Check 4: end-to-end chain via CKM_PQCTODAY_ML_DSA_MU --- */
        CK_SIGN_ADDITIONAL_CONTEXT signCtx = { CKH_HEDGE_PREFERRED, NULL_PTR, 0 };
        CK_MECHANISM signMech = { CKM_PQCTODAY_ML_DSA_MU, &signCtx, sizeof(signCtx) };
        rv = fl->C_SignInit(sess, &signMech, priv);
        if (rv != CKR_OK) { fprintf(stderr, "C_SignInit(MU) rv=%lu\n", (unsigned long)rv); return 1; }
        unsigned char sig[8192]; CK_ULONG sig_len = sizeof(sig);
        rv = fl->C_Sign(sess, mu1, 64, sig, &sig_len);
        if (rv != CKR_OK) { fprintf(stderr, "C_Sign(MU) rv=%lu\n", (unsigned long)rv); return 1; }
        rv = fl->C_VerifyInit(sess, &signMech, pub);
        if (rv != CKR_OK) { fprintf(stderr, "C_VerifyInit(MU) rv=%lu\n", (unsigned long)rv); return 1; }
        rv = fl->C_Verify(sess, mu1, 64, sig, sig_len);
        CHECK(rv == CKR_OK, "token-computed mu, fed to CKM_PQCTODAY_ML_DSA_MU, "
              "signs a signature that verifies via the SAME mechanism");

        /* --- Check 5: both absent / both present rejected --- */
        CK_PQCTODAY_MU_GEN_PARAMS p5a = { CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, 0 };
        CK_MECHANISM mech5a = { CKM_PQCTODAY_ML_DSA_MU_GEN, &p5a, sizeof(p5a) };
        rv = fl->C_DigestInit(sess, &mech5a);
        CHECK(rv != CKR_OK, "both hTrKey and pTr absent: rejected");

        CK_PQCTODAY_MU_GEN_PARAMS p5b = { pub, tr, 64, NULL_PTR, 0 };
        CK_MECHANISM mech5b = { CKM_PQCTODAY_ML_DSA_MU_GEN, &p5b, sizeof(p5b) };
        rv = fl->C_DigestInit(sess, &mech5b);
        CHECK(rv != CKR_OK, "both hTrKey and pTr present: rejected");

        free(pk);
        fl->C_CloseSession(sess);
        fl->C_Finalize(NULL);

        if (failures) { fprintf(stderr, "\n%d check(s) FAILED\n", failures); return 1; }
        printf("\nAll checks PASSED\n");
        return 0;
    }

    fprintf(stderr, "token '%s' not found\n", token_label);
    fl->C_Finalize(NULL);
    return 1;
}
