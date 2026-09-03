/* keygen_pkcs11_key.c — minimal, dependency-free PKCS#11 C-API keygen
 * helper: provisions a token-persistent ML-DSA, SLH-DSA, Ed448, or Ed25519
 * keypair with a caller-chosen CKA_ID/CKA_LABEL, for test_pkcs11_conn.c (or
 * any other strongswan-pkcs11 test) to find via BUILD_PKCS11_KEYID.
 *
 * dlopen()s the target PKCS#11 module directly and hand-rolls the handful
 * of CK_FUNCTION_LIST entries it needs (v2.01+ layout, unchanged since),
 * so it has no dependency on this repo's pkcs11.h/pkcs11t.h or any
 * strongSwan headers — only a working PKCS#11 v3.2 module (softhsmv3) and
 * dlopen/dlsym.
 *
 * Build: cc -O0 -g -o keygen_pkcs11_key keygen_pkcs11_key.c -ldl
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>

typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_BBOOL;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_USER_TYPE;
#define CK_TRUE 1
#define CKF_SERIAL_SESSION 0x00000004
#define CKF_RW_SESSION 0x00000002
#define CKU_USER 1
#define CKO_PUBLIC_KEY 2
#define CKO_PRIVATE_KEY 3
#define CKA_CLASS 0x00000000
#define CKA_TOKEN 0x00000001
#define CKA_LABEL 0x00000003
#define CKA_ID 0x00000102
#define CKA_SIGN 0x00000108
#define CKA_VERIFY 0x0000010A
#define CKA_KEY_TYPE 0x00000100
/* PKCS#11 v3.2 §6.66.2 / §6.60.2 — see src/lib/pkcs11/pkcs11t.h (source of
 * truth for this repo, per CLAUDE.md) for the full canonical list. */
#define CKA_PARAMETER_SET 0x0000061dUL
#define CKK_SLH_DSA 0x4bUL
#define CKK_ML_DSA 0x4aUL
#define CKM_SLH_DSA_KEY_PAIR_GEN 0x0000002dUL
#define CKM_ML_DSA_KEY_PAIR_GEN 0x0000001cUL
#define CKP_ML_DSA_44 0x00000001UL
#define CKP_ML_DSA_65 0x00000002UL
#define CKP_ML_DSA_87 0x00000003UL
#define CKP_SLH_DSA_SHA2_128S 0x00000001UL
#define CKP_SLH_DSA_SHA2_192S 0x00000005UL
#define CKP_SLH_DSA_SHA2_256S 0x00000009UL
/* CKK_EC_EDWARDS/CKM_EC_EDWARDS_KEY_PAIR_GEN/CKA_EC_PARAMS (PKCS#11 v3.2
 * §2.3.7 / §6.66) — used for Ed448/Ed25519 below, distinct from
 * ML-DSA/SLH-DSA: curve selected via CKA_EC_PARAMS, not CKA_PARAMETER_SET. */
#define CKK_EC_EDWARDS 0x00000040UL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN 0x00001055UL
#define CKA_EC_PARAMS 0x00000180UL

typedef struct { CK_ATTRIBUTE_TYPE type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_MECHANISM_TYPE mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct {
    unsigned char label[32];
    unsigned char manufacturerID[32]; unsigned char model[16]; unsigned char serialNumber[16];
    CK_FLAGS flags; CK_ULONG ulMaxSessionCount; CK_ULONG ulSessionCount; CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount; CK_ULONG ulMaxPinLen; CK_ULONG ulMinPinLen; CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory; CK_ULONG ulTotalPrivateMemory; CK_ULONG ulFreePrivateMemory;
    unsigned char hardwareVersion[2]; unsigned char firmwareVersion[2]; unsigned char utcTime[16];
} CK_TOKEN_INFO;

static char *trim(unsigned char *s, int n) {
    static char buf[64];
    int i = n; while (i > 0 && s[i-1] == ' ') i--;
    memcpy(buf, s, i); buf[i] = 0; return buf;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
            "usage: %s <module.so> <token-label> <pin> <keyid-hex> "
            "[paramset:128s|192s|256s|mldsa44|mldsa65|mldsa87|ed448|ed25519] "
            "[label]\n",
            argv[0]);
        return 2;
    }
    const char *modpath = argv[1];
    const char *tokenlabel = argv[2];
    const char *pin = argv[3];
    const char *keyid_hex = argv[4];
    const char *paramset_s = argc > 5 ? argv[5] : "128s";
    const char *objlabel = argc > 6 ? argv[6] : "pkcs11-test-key";

    void *h = dlopen(modpath, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }
    void *getlist = dlsym(h, "C_GetFunctionList");
    if (!getlist) { fprintf(stderr, "no C_GetFunctionList\n"); return 1; }

    /* CK_FUNCTION_LIST layout: CK_VERSION version; then function pointers,
     * in the standardized order (unchanged since PKCS#11 v2.01). We only
     * need a prefix of it. */
    struct CK_FUNCTION_LIST {
        struct { unsigned char major, minor; } version;
        CK_RV (*C_Initialize)(void*);
        CK_RV (*C_Finalize)(void*);
        CK_RV (*C_GetInfo)(void*);
        CK_RV (*C_GetFunctionList)(void*);
        CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID*, CK_ULONG*);
        CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, void*);
        CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO*);
        CK_RV (*C_GetMechanismList)(CK_SLOT_ID, void*, CK_ULONG*);
        CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, void*);
        CK_RV (*C_InitToken)(CK_SLOT_ID, unsigned char*, CK_ULONG, unsigned char*);
        CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG);
        CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG);
        CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
        CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
        CK_RV (*C_CloseAllSessions)(CK_SLOT_ID);
        CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE, void*);
        CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE, void*, CK_ULONG*);
        CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE, void*, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
        CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, unsigned char*, CK_ULONG);
        CK_RV (*C_Logout)(CK_SESSION_HANDLE);
        CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
        CK_RV (*C_CopyObject)(void);
        CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
        CK_RV (*C_GetObjectSize)(void);
        CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
        CK_RV (*C_SetAttributeValue)(void);
        CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
        CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
        CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
        CK_RV (*C_EncryptInit)(void); CK_RV (*C_Encrypt)(void); CK_RV (*C_EncryptUpdate)(void); CK_RV (*C_EncryptFinal)(void);
        CK_RV (*C_DecryptInit)(void); CK_RV (*C_Decrypt)(void); CK_RV (*C_DecryptUpdate)(void); CK_RV (*C_DecryptFinal)(void);
        CK_RV (*C_DigestInit)(void); CK_RV (*C_Digest)(void); CK_RV (*C_DigestUpdate)(void); CK_RV (*C_DigestKey)(void); CK_RV (*C_DigestFinal)(void);
        CK_RV (*C_SignInit)(void); CK_RV (*C_Sign)(void); CK_RV (*C_SignUpdate)(void); CK_RV (*C_SignFinal)(void); CK_RV (*C_SignRecoverInit)(void); CK_RV (*C_SignRecover)(void);
        CK_RV (*C_VerifyInit)(void); CK_RV (*C_Verify)(void); CK_RV (*C_VerifyUpdate)(void); CK_RV (*C_VerifyFinal)(void); CK_RV (*C_VerifyRecoverInit)(void); CK_RV (*C_VerifyRecover)(void);
        CK_RV (*C_DigestEncryptUpdate)(void); CK_RV (*C_DecryptDigestUpdate)(void);
        CK_RV (*C_SignEncryptUpdate)(void); CK_RV (*C_DecryptVerifyUpdate)(void);
        CK_RV (*C_GenerateKey)(void);
        CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
    } *fl = NULL;

    CK_RV (*C_GetFunctionList)(struct CK_FUNCTION_LIST**) = (CK_RV (*)(struct CK_FUNCTION_LIST**))getlist;
    CK_RV rv = C_GetFunctionList(&fl);
    if (rv != 0) { fprintf(stderr, "C_GetFunctionList rv=%lu\n", rv); return 1; }

    rv = fl->C_Initialize(NULL);
    if (rv != 0) { fprintf(stderr, "C_Initialize rv=%lu\n", rv); return 1; }

    CK_SLOT_ID slots[32]; CK_ULONG n = 32;
    rv = fl->C_GetSlotList(1, slots, &n);
    if (rv != 0) { fprintf(stderr, "C_GetSlotList rv=%lu\n", rv); return 1; }

    CK_SLOT_ID target = (CK_SLOT_ID)-1;
    for (CK_ULONG i = 0; i < n; i++) {
        CK_TOKEN_INFO ti; memset(&ti, 0, sizeof(ti));
        if (fl->C_GetTokenInfo(slots[i], &ti) != 0) continue;
        if (strcmp(trim(ti.label, 32), tokenlabel) == 0) { target = slots[i]; break; }
    }
    if (target == (CK_SLOT_ID)-1) { fprintf(stderr, "token '%s' not found among %lu slots\n", tokenlabel, n); return 1; }

    CK_SESSION_HANDLE sess;
    rv = fl->C_OpenSession(target, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sess);
    if (rv != 0) { fprintf(stderr, "C_OpenSession rv=%lu\n", rv); return 1; }
    rv = fl->C_Login(sess, CKU_USER, (unsigned char*)pin, (CK_ULONG)strlen(pin));
    if (rv != 0) { fprintf(stderr, "C_Login rv=%lu\n", rv); return 1; }

    int hexlen = (int)strlen(keyid_hex);
    unsigned char keyid[64]; int keyid_len = hexlen / 2;
    for (int i = 0; i < keyid_len; i++) {
        unsigned int b; sscanf(keyid_hex + 2*i, "%2x", &b); keyid[i] = (unsigned char)b;
    }

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
    int is_mldsa = (strncmp(paramset_s, "mldsa", 5) == 0);
    int is_ed448 = (strcmp(paramset_s, "ed448") == 0);
    int is_ed25519 = (strcmp(paramset_s, "ed25519") == 0);
    int is_edwards = is_ed448 || is_ed25519;
    CK_KEY_TYPE ktype = is_edwards ? CKK_EC_EDWARDS : is_mldsa ? CKK_ML_DSA : CKK_SLH_DSA;
    CK_MECHANISM_TYPE kpMechType = is_edwards ? CKM_EC_EDWARDS_KEY_PAIR_GEN :
                                    is_mldsa ? CKM_ML_DSA_KEY_PAIR_GEN : CKM_SLH_DSA_KEY_PAIR_GEN;
    CK_BBOOL bTrue = CK_TRUE;
    CK_ULONG paramSet = 0;
    /* RFC 8410 id-Ed448/id-Ed25519 OIDs (1.3.101.113 / 1.3.101.112),
     * DER-encoded — this connector's canonical CKA_EC_PARAMS encoding for
     * Ed448/Ed25519 (matches strongswan-pkcs11/pkcs11_public_key.c's
     * ed448_ec_params_oid/ed25519_ec_params_oid). Only used when
     * is_edwards; ML-DSA/SLH-DSA keep using CKA_PARAMETER_SET. */
    unsigned char ed448_oid[] = { 0x06, 0x03, 0x2b, 0x65, 0x71 };
    unsigned char ed25519_oid[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
    if (is_edwards) {
        /* no CKA_PARAMETER_SET for CKK_EC_EDWARDS — curve is in CKA_EC_PARAMS */
    } else if (is_mldsa) {
        paramSet = (strcmp(paramset_s, "mldsa87") == 0) ? CKP_ML_DSA_87 :
                   (strcmp(paramset_s, "mldsa65") == 0) ? CKP_ML_DSA_65 : CKP_ML_DSA_44;
    } else {
        paramSet = (strcmp(paramset_s, "256s") == 0) ? CKP_SLH_DSA_SHA2_256S :
                   (strcmp(paramset_s, "192s") == 0) ? CKP_SLH_DSA_SHA2_192S : CKP_SLH_DSA_SHA2_128S;
    }

    /* CKA_EC_PARAMS goes on the PUBLIC key template only: the engine's
     * P11Attribute checks table (P11Objects.cpp) registers CKA_EC_PARAMS
     * with `ck3` (caller-settable at C_GenerateKeyPair) on the Edwards
     * public-key object but `ck4|ck6` (MUST NOT be specified when
     * generated — it derives/copies it internally, see generateED() in
     * SoftHSM_keygen.cpp) on the private-key object. Including it in
     * privTmpl fails C_GenerateKeyPair with CKR_ATTRIBUTE_READ_ONLY. */
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { 0, NULL, 0 }, /* set below: CKA_EC_PARAMS (Ed448) or CKA_PARAMETER_SET */
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_ID, keyid, (CK_ULONG)keyid_len },
        { CKA_LABEL, (void*)objlabel, (CK_ULONG)strlen(objlabel) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { 0, NULL, 0 }, /* set below for ML-DSA/SLH-DSA only: CKA_PARAMETER_SET */
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_ID, keyid, (CK_ULONG)keyid_len },
        { CKA_LABEL, (void*)objlabel, (CK_ULONG)strlen(objlabel) },
    };
    CK_ULONG privCount = 7;
    if (is_edwards) {
        pubTmpl[3].type = CKA_EC_PARAMS;
        pubTmpl[3].pValue = is_ed448 ? (void*)ed448_oid : (void*)ed25519_oid;
        pubTmpl[3].ulValueLen = is_ed448 ? sizeof(ed448_oid) : sizeof(ed25519_oid);
        /* drop the unused slot 3 from privTmpl by shifting the remaining
         * attributes down and shrinking the count passed to
         * C_GenerateKeyPair. */
        privTmpl[3] = privTmpl[4]; privTmpl[4] = privTmpl[5]; privTmpl[5] = privTmpl[6];
        privCount = 6;
    } else {
        pubTmpl[3].type = CKA_PARAMETER_SET; pubTmpl[3].pValue = &paramSet; pubTmpl[3].ulValueLen = sizeof(paramSet);
        privTmpl[3].type = CKA_PARAMETER_SET; privTmpl[3].pValue = &paramSet; privTmpl[3].ulValueLen = sizeof(paramSet);
    }
    CK_MECHANISM mech = { kpMechType, NULL, 0 };
    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    rv = fl->C_GenerateKeyPair(sess, &mech, pubTmpl, 7, privTmpl, privCount, &hPub, &hPriv);
    if (rv != 0) { fprintf(stderr, "C_GenerateKeyPair rv=%lu\n", rv); return 1; }

    printf("OK: generated %s keypair, CKA_ID=%s, pub handle=%lu priv handle=%lu\n",
        paramset_s, keyid_hex, (unsigned long)hPub, (unsigned long)hPriv);
    return 0;
}
