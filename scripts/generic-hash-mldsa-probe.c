/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* generic-hash-mldsa-probe: remediation R37 (phase 8) permanent regression
 * fixture (started as a step-1 live-confirm diagnostic; promoted once the
 * fix landed, per the phase-8 plan's own instruction). PKCS#11 v3.2
 * SS6.67.6/SS6.69.6 define the bare generic CKM_HASH_ML_DSA/CKM_HASH_SLH_DSA
 * mechanisms to take an ALREADY-HASHED PHM as their data argument (not a
 * raw message) -- distinct from the ten hash-specific CKM_HASH_*_<hash>
 * mechanisms (SS6.67.7/SS6.69.7), which hash the message ON TOKEN. Neither
 * generic mechanism is reachable through the OpenSSL provider (nothing
 * routes to it by design -- see mldsa.c/slhdsa.c's own set_mechanism), so
 * this drives the raw PKCS#11 C_* API directly against an engine .so,
 * bypassing the provider entirely -- same reason hss-w4-keygen.c exists.
 *
 * The bug this caught (both engines, before the fix): parseMLDSASignContext/
 * parseSLHDSASignContext's own CK_HASH_SIGN_ADDITIONAL_CONTEXT branch --
 * which fires ONLY for the bare generic mechanism -- set preHash=true,
 * meaning OSSLMLDSA::sign()/verify() (and the SLH-DSA twin) hashed the
 * caller's ALREADY-HASHED PHM a SECOND time before building
 * M' = 0x01||ctx||OID||H(...). Confirmed live before the fix (both engines
 * showed the identical double-hash symptom); the original phase-8 grounding
 * had guessed a DIFFERENT bug for the C++ engine ("pure path", no encoding
 * at all) from a static read that missed parseMLDSASignContext's own side
 * effect -- this probe is what caught the actual behavior.
 *
 * Per algorithm family, cross-checks against the SAME (message,
 * PHM=SHA256(message)) pair and the SAME keypair:
 *   sigA = Sign(generic mechanism, data=PHM)         -- the mechanism under test
 *   sigB = Sign(SHA256-specific mechanism, data=message) -- proven-correct oracle
 *   sigC = Sign(plain mechanism, data=PHM)            -- "pure path" bug detector
 *
 * Conformant: sigA verifies under the SHA256-specific mechanism's own
 * verify fed the ORIGINAL message (both mechanisms are defined to produce
 * verify-interchangeable signatures for PHM=H(M) -- the strongest available
 * oracle here, since OpenSSL has no HashML-DSA/HashSLH-DSA at all).
 * "Pure path" bug: sigA verifies under the plain mechanism fed PHM
 * directly. "Double-hash" bug: sigA verifies under the SHA256-specific
 * mechanism fed PHM as if PHM were "the message" (computes SHA256(PHM)
 * internally).
 *
 * Also asserts: a wrong-length PHM is rejected loudly (not silently
 * truncated/padded), and multi-part (C_SignUpdate) is rejected -- the
 * generic mechanism is genuinely single-part only (remediation R37 also
 * fixed bAllowMultiPartOp for it, which had wrongly been true). */
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

static CK_FUNCTION_LIST_PTR fl;

static CK_RV do_sign(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE priv,
                     CK_MECHANISM_TYPE mech_type, void *param,
                     CK_ULONG param_len, const unsigned char *data,
                     size_t data_len, unsigned char *sig, CK_ULONG *sig_len)
{
    CK_MECHANISM mech = { mech_type, param, param_len };
    CK_RV rv = fl->C_SignInit(sess, &mech, priv);
    if (rv != CKR_OK) {
        return rv;
    }
    return fl->C_Sign(sess, (CK_BYTE_PTR)data, (CK_ULONG)data_len, sig,
                      sig_len);
}

static CK_RV do_verify(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE pub,
                       CK_MECHANISM_TYPE mech_type, void *param,
                       CK_ULONG param_len, const unsigned char *data,
                       size_t data_len, unsigned char *sig, CK_ULONG sig_len)
{
    CK_MECHANISM mech = { mech_type, param, param_len };
    CK_RV rv = fl->C_VerifyInit(sess, &mech, pub);
    if (rv != CKR_OK) {
        return rv;
    }
    return fl->C_Verify(sess, (CK_BYTE_PTR)data, (CK_ULONG)data_len, sig,
                        sig_len);
}

/* One algorithm family's full check set. mldsa=1 for ML-DSA, 0 for SLH-DSA. */
static int check_family(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE pub,
                        CK_OBJECT_HANDLE priv, int mldsa)
{
    const char *fam = mldsa ? "ML-DSA" : "SLH-DSA";
    CK_MECHANISM_TYPE generic = mldsa ? CKM_HASH_ML_DSA : CKM_HASH_SLH_DSA;
    CK_MECHANISM_TYPE specific =
        mldsa ? CKM_HASH_ML_DSA_SHA256 : CKM_HASH_SLH_DSA_SHA256;
    CK_MECHANISM_TYPE plain = mldsa ? CKM_ML_DSA : CKM_SLH_DSA;
    int failures = 0;

    unsigned char message[64];
    snprintf((char *)message, sizeof(message),
            "R37 probe message for Hash%s generic mechanism", fam);
    size_t message_len = strlen((char *)message);

    unsigned char phm[32];
    unsigned int phm_len = 0;
    if (!EVP_Digest(message, message_len, phm, &phm_len, EVP_sha256(), NULL)
        || phm_len != 32) {
        fprintf(stderr, "[%s] EVP_Digest(SHA256) failed\n", fam);
        return 1;
    }

    CK_HASH_SIGN_ADDITIONAL_CONTEXT hctx = { CKH_HEDGE_PREFERRED, NULL, 0,
                                             CKM_SHA256 };
    CK_SIGN_ADDITIONAL_CONTEXT ctx = { CKH_HEDGE_PREFERRED, NULL, 0 };

    unsigned char sigA[65536], sigB[65536];
    CK_ULONG sigA_len = sizeof(sigA), sigB_len = sizeof(sigB);
    CK_RV rv;

    rv = do_sign(sess, priv, generic, &hctx, sizeof(hctx), phm, phm_len,
                sigA, &sigA_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[%s] sigA (generic, data=PHM) C_Sign rv=%lu\n", fam,
               (unsigned long)rv);
        return 1;
    }

    rv = do_sign(sess, priv, specific, &ctx, sizeof(ctx), message,
                message_len, sigB, &sigB_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[%s] sigB (specific, data=message) C_Sign rv=%lu\n",
               fam, (unsigned long)rv);
        return 1;
    }

    /* Conformant oracle: sigA must verify as a proper Hash<fam>-SHA256
     * signature of the ORIGINAL message. */
    rv = do_verify(sess, pub, specific, &ctx, sizeof(ctx), message,
                   message_len, sigA, sigA_len);
    if (rv != CKR_OK) {
        fprintf(stderr,
               "[%s] FAIL: sigA does not verify under %s-SHA256(message) "
               "-- generic mechanism is NOT spec-conformant (rv=0x%lx)\n",
               fam, fam, (unsigned long)rv);
        failures++;
    } else {
        printf("[%s] OK: sigA verifies under the SHA256-specific "
              "mechanism's own verify (conformant)\n",
              fam);
    }

    /* "Pure path" bug detector: sigA must NOT verify as a plain signature
     * over the raw PHM bytes. */
    rv = do_verify(sess, pub, plain, &ctx, sizeof(ctx), phm, phm_len, sigA,
                   sigA_len);
    if (rv == CKR_OK) {
        fprintf(stderr,
               "[%s] FAIL: sigA verifies under plain %s(PHM) -- 'pure "
               "path' bug present\n",
               fam, fam);
        failures++;
    }

    /* "Double-hash" bug detector: sigA must NOT verify under the
     * SHA256-specific mechanism fed PHM as if PHM were "the message". */
    rv = do_verify(sess, pub, specific, &ctx, sizeof(ctx), phm, phm_len,
                   sigA, sigA_len);
    if (rv == CKR_OK) {
        fprintf(stderr,
               "[%s] FAIL: sigA verifies under %s-SHA256(PHM) -- "
               "'double-hash' bug present\n",
               fam, fam);
        failures++;
    }

    /* Self-consistency: AsymVerifyInit's own copy of the generic-mechanism
     * handling must agree with what AsymSignInit produced. */
    rv = do_verify(sess, pub, generic, &hctx, sizeof(hctx), phm, phm_len,
                   sigA, sigA_len);
    if (rv != CKR_OK) {
        fprintf(stderr,
               "[%s] FAIL: sigA does not verify under the SAME generic "
               "mechanism (sign/verify disagree, rv=0x%lx)\n",
               fam, (unsigned long)rv);
        failures++;
    } else {
        printf("[%s] OK: sigA self-verifies under the generic mechanism\n",
              fam);
    }

    /* Wrong-length PHM must be rejected loudly, not silently
     * truncated/padded. SHA256 PHM is 32 bytes; feed 16. */
    unsigned char short_sig[65536];
    CK_ULONG short_sig_len = sizeof(short_sig);
    rv = do_sign(sess, priv, generic, &hctx, sizeof(hctx), phm, 16,
                short_sig, &short_sig_len);
    if (rv == CKR_OK) {
        fprintf(stderr,
               "[%s] FAIL: wrong-length (16-byte) PHM was accepted -- must "
               "be rejected\n",
               fam);
        failures++;
    } else {
        printf("[%s] OK: wrong-length PHM rejected (rv=0x%lx)\n", fam,
              (unsigned long)rv);
    }

    /* Multi-part must be rejected -- the generic mechanism is genuinely
     * single-part only (remediation R37 fixed bAllowMultiPartOp for it). */
    CK_MECHANISM mech = { generic, &hctx, sizeof(hctx) };
    rv = fl->C_SignInit(sess, &mech, priv);
    if (rv != CKR_OK) {
        fprintf(stderr, "[%s] C_SignInit (for multi-part check) rv=%lu\n",
               fam, (unsigned long)rv);
        return 1;
    }
    rv = fl->C_SignUpdate(sess, phm, phm_len);
    if (rv == CKR_OK) {
        fprintf(stderr,
               "[%s] FAIL: C_SignUpdate succeeded on the generic mechanism "
               "-- must be single-part only\n",
               fam);
        failures++;
        /* Drain the operation so the session isn't left in a broken state
         * for subsequent checks. */
        unsigned char drain[65536];
        CK_ULONG drain_len = sizeof(drain);
        fl->C_SignFinal(sess, drain, &drain_len);
    } else {
        printf("[%s] OK: C_SignUpdate rejected on the generic mechanism "
              "(rv=0x%lx)\n",
              fam, (unsigned long)rv);
    }

    return failures;
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
        if (fl->C_GetTokenInfo(slots[s], &tinfo) != CKR_OK) {
            continue;
        }
        char label[33];
        memcpy(label, tinfo.label, 32);
        label[32] = '\0';
        for (int i = 31; i >= 0 && label[i] == ' '; i--) {
            label[i] = '\0';
        }
        if (strcmp(label, token_label) != 0) {
            continue;
        }

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

        CK_KEY_TYPE mldsa_kt = CKK_ML_DSA;
        CK_ULONG mldsa_paramset = CKP_ML_DSA_65;
        CK_ATTRIBUTE mldsa_pub_tmpl[] = {
            { CKA_KEY_TYPE, &mldsa_kt, sizeof(mldsa_kt) },
            { CKA_PARAMETER_SET, &mldsa_paramset, sizeof(mldsa_paramset) },
            { CKA_VERIFY, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        };
        CK_ATTRIBUTE mldsa_priv_tmpl[] = {
            { CKA_KEY_TYPE, &mldsa_kt, sizeof(mldsa_kt) },
            { CKA_PARAMETER_SET, &mldsa_paramset, sizeof(mldsa_paramset) },
            { CKA_SIGN, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        };
        CK_MECHANISM mldsa_keygen_mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE mldsa_pub, mldsa_priv;
        rv = fl->C_GenerateKeyPair(sess, &mldsa_keygen_mech, mldsa_pub_tmpl,
                                   4, mldsa_priv_tmpl, 4, &mldsa_pub,
                                   &mldsa_priv);
        if (rv != CKR_OK) {
            fprintf(stderr, "ML-DSA C_GenerateKeyPair rv=%lu\n",
                   (unsigned long)rv);
            return 1;
        }

        CK_KEY_TYPE slhdsa_kt = CKK_SLH_DSA;
        CK_ULONG slhdsa_paramset = CKP_SLH_DSA_SHA2_128S;
        CK_ATTRIBUTE slhdsa_pub_tmpl[] = {
            { CKA_KEY_TYPE, &slhdsa_kt, sizeof(slhdsa_kt) },
            { CKA_PARAMETER_SET, &slhdsa_paramset, sizeof(slhdsa_paramset) },
            { CKA_VERIFY, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        };
        CK_ATTRIBUTE slhdsa_priv_tmpl[] = {
            { CKA_KEY_TYPE, &slhdsa_kt, sizeof(slhdsa_kt) },
            { CKA_PARAMETER_SET, &slhdsa_paramset, sizeof(slhdsa_paramset) },
            { CKA_SIGN, &ck_true, sizeof(ck_true) },
            { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        };
        CK_MECHANISM slhdsa_keygen_mech = { CKM_SLH_DSA_KEY_PAIR_GEN, NULL,
                                            0 };
        CK_OBJECT_HANDLE slhdsa_pub, slhdsa_priv;
        rv = fl->C_GenerateKeyPair(sess, &slhdsa_keygen_mech, slhdsa_pub_tmpl,
                                   4, slhdsa_priv_tmpl, 4, &slhdsa_pub,
                                   &slhdsa_priv);
        if (rv != CKR_OK) {
            fprintf(stderr, "SLH-DSA C_GenerateKeyPair rv=%lu\n",
                   (unsigned long)rv);
            return 1;
        }

        int failures = 0;
        failures += check_family(sess, mldsa_pub, mldsa_priv, 1);
        failures += check_family(sess, slhdsa_pub, slhdsa_priv, 0);

        fl->C_CloseSession(sess);
        fl->C_Finalize(NULL);

        if (failures) {
            fprintf(stderr, "\n%d check(s) FAILED\n", failures);
            return 1;
        }
        printf("\nAll checks PASSED\n");
        return 0;
    }

    fprintf(stderr, "token '%s' not found\n", token_label);
    fl->C_Finalize(NULL);
    return 1;
}
