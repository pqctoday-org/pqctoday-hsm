/*
 * test_pkcs11_ed25519ctx.c — real functional test of RFC 8032 Ed25519ctx
 * signing/verification against the SAME PKCS#11 module
 * (build-native/src/lib/libsofthsmv3.dylib, i.e. this repo's softhsmv3
 * engine) this connector's pkcs11_private_key.c/pkcs11_public_key.c target
 * for their KEY_ED25519/SIGN_ED25519 wiring — but, unlike
 * test_pkcs11_conn.c, driven via RAW PKCS#11 C-API calls
 * (C_SignInit/C_Sign/C_VerifyInit/C_Verify with CKM_EDDSA + a real non-empty
 * CK_EDDSA_PARAMS context), not through strongSwan's private_key_t/
 * public_key_t abstraction. Same dependency-free dlopen/dlsym technique as
 * keygen_pkcs11_key.c and test_pkcs11_kem.c's raw_pkcs11_login() — no
 * strongSwan headers, no this repo's pkcs11.h/pkcs11t.h.
 *
 * WHY RAW PKCS#11 AND NOT private_key_t.sign()/verify(): strongSwan's own
 * signature_scheme_t (src/libstrongswan/credentials/keys/public_key.h,
 * patched by ../../strongswan-pqc.patch) has SIGN_ED25519 but NO
 * "SIGN_ED25519_CTX" value, and no params type carrying an RFC 8032 context
 * string for EdDSA the way rsa_pss_params_t carries salt length for
 * SIGN_RSA_EMSA_PSS. pkcs11_signature_scheme_to_mech()'s SIGN_ED25519 arm
 * (pkcs11_private_key.c) therefore always builds CK_EDDSA_PARAMS with an
 * EMPTY context — the only EdDSA variant reachable through
 * private_key_t.sign()/public_key_t.verify() (and hence through real IKEv2
 * peer authentication) is plain Ed25519, exactly like Ed448 before it. That
 * is a real, load-bearing scope boundary of strongSwan's own credential
 * API, not a bug in this connector or in the engine — see tests/README.md's
 * "Known gaps" section for the full explanation, and item 5 of the
 * fix/strongswan-ed25519 task this file was added for.
 *
 * What THIS file proves instead: the underlying softhsmv3 module (the same
 * module pkcs11_manager_create() loads for the connector, per
 * settings.conf's plugins.pkcs11.modules.<name>.path) correctly implements
 * RFC 8032 Ed25519ctx end-to-end — CK_EDDSA_PARAMS.ulContextDataLen/
 * pContextData genuinely change the signature (not silently ignored), a
 * wrong context is genuinely rejected, and a real independent oracle
 * (OpenSSL 3.6's own `pkeyutl -pkeyopt instance:Ed25519ctx`) agrees with
 * both outcomes — mirroring exactly how B1/T39/T39b verified the Rust
 * engine's own Ed25519ctx fix (rust/src/ffi.rs's
 * ed25519ctx_ffi_dispatch_cross_checks_against_openssl test) and how
 * tests/README.md's existing Ed448 section cross-checks against OpenSSL.
 * This closes the honest, provable half of "wire Ed25519ctx" — the engine
 * genuinely supports it — while leaving the strongSwan-API gap precisely
 * documented rather than silently worked around.
 *
 * Build:
 *   cc -O0 -g -o test_pkcs11_ed25519ctx strongswan-pkcs11/tests/test_pkcs11_ed25519ctx.c -ldl
 *
 * Run (reuses the SAME token + Ed25519 keypair test_pkcs11_conn.c's own
 * worked example provisions at CKA_ID 08 — see tests/README.md):
 *
 *   ./test_pkcs11_ed25519ctx <module.so> <token-label> <pin> <keyid-hex> \
 *       [out-dir]
 *
 * If out-dir is given, writes pub.der/msg.bin/sig_good.bin/ctx.txt/
 * wrong_ctx.txt there for an independent `openssl pkeyutl` cross-check (see
 * tests/README.md for the exact commands and last-confirmed transcript).
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
typedef CK_BYTE *CK_BYTE_PTR;
#define CK_TRUE 1
#define CK_FALSE 0
#define CKF_SERIAL_SESSION 0x00000004
#define CKF_RW_SESSION 0x00000002
#define CKU_USER 1
#define CKO_PUBLIC_KEY 2
#define CKO_PRIVATE_KEY 3
#define CKA_CLASS 0x00000000UL
#define CKA_ID 0x00000102UL
#define CKA_EC_POINT 0x00000181UL
#define CKR_OK 0x00000000UL
/* PKCS#11 v3.2 §6.3.7/§6.3.16 — CKM_EDDSA / CK_EDDSA_PARAMS. */
#define CKM_EDDSA 0x00001057UL

typedef struct { CK_ATTRIBUTE_TYPE type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_MECHANISM_TYPE mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
/* PKCS#11 v3.2 §6.3.16 Table 74 — natural C struct layout, same as every
 * real CK_EDDSA_PARAMS producer/consumer in this repo (see
 * src/lib/SoftHSM_sign.cpp's parseEdDSAParams() and rust/src/ffi.rs's
 * ck_param::eddsa layout comment for the same three fields). */
typedef struct { CK_BBOOL phFlag; CK_ULONG ulContextDataLen; CK_BYTE_PTR pContextData; } CK_EDDSA_PARAMS;

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

/* CK_FUNCTION_LIST v2.01+ prefix layout, same truncation convention as
 * keygen_pkcs11_key.c/test_pkcs11_kem.c in this directory — only the
 * entries actually called below get real signatures. */
struct CK_FUNCTION_LIST {
    struct { unsigned char major, minor; } version;
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_GetInfo)(void*);
    CK_RV (*C_GetFunctionList)(void*);
    CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID*, CK_ULONG*);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, void*);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO*);
    CK_RV (*C_GetMechanismList)(void);
    CK_RV (*C_GetMechanismInfo)(void);
    CK_RV (*C_InitToken)(void);
    CK_RV (*C_InitPIN)(void);
    CK_RV (*C_SetPIN)(void);
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_CloseAllSessions)(void);
    CK_RV (*C_GetSessionInfo)(void);
    CK_RV (*C_GetOperationState)(void);
    CK_RV (*C_SetOperationState)(void);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, unsigned char*, CK_ULONG);
    CK_RV (*C_Logout)(void);
    CK_RV (*C_CreateObject)(void);
    CK_RV (*C_CopyObject)(void);
    CK_RV (*C_DestroyObject)(void);
    CK_RV (*C_GetObjectSize)(void);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    CK_RV (*C_SetAttributeValue)(void);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*C_EncryptInit)(void); CK_RV (*C_Encrypt)(void); CK_RV (*C_EncryptUpdate)(void); CK_RV (*C_EncryptFinal)(void);
    CK_RV (*C_DecryptInit)(void); CK_RV (*C_Decrypt)(void); CK_RV (*C_DecryptUpdate)(void); CK_RV (*C_DecryptFinal)(void);
    CK_RV (*C_DigestInit)(void); CK_RV (*C_Digest)(void); CK_RV (*C_DigestUpdate)(void); CK_RV (*C_DigestKey)(void); CK_RV (*C_DigestFinal)(void);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG*);
} *fl_full = NULL;

/* A SECOND, differently-truncated view of the same table, reaching further
 * (through C_Verify) — CK_FUNCTION_LIST is one fixed struct in the real
 * module; declaring two C-side prefixes of different lengths and pointing
 * both at the same dlsym()'d table is safe (same technique as this
 * directory's other raw tests use a single truncated prefix — this file
 * just needs a longer one). */
struct CK_FUNCTION_LIST_EXT {
    struct { unsigned char major, minor; } version;
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_GetInfo)(void*);
    CK_RV (*C_GetFunctionList)(void*);
    CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID*, CK_ULONG*);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, void*);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO*);
    CK_RV (*C_GetMechanismList)(void);
    CK_RV (*C_GetMechanismInfo)(void);
    CK_RV (*C_InitToken)(void);
    CK_RV (*C_InitPIN)(void);
    CK_RV (*C_SetPIN)(void);
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_CloseAllSessions)(void);
    CK_RV (*C_GetSessionInfo)(void);
    CK_RV (*C_GetOperationState)(void);
    CK_RV (*C_SetOperationState)(void);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, unsigned char*, CK_ULONG);
    CK_RV (*C_Logout)(void);
    CK_RV (*C_CreateObject)(void);
    CK_RV (*C_CopyObject)(void);
    CK_RV (*C_DestroyObject)(void);
    CK_RV (*C_GetObjectSize)(void);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    CK_RV (*C_SetAttributeValue)(void);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*C_EncryptInit)(void); CK_RV (*C_Encrypt)(void); CK_RV (*C_EncryptUpdate)(void); CK_RV (*C_EncryptFinal)(void);
    CK_RV (*C_DecryptInit)(void); CK_RV (*C_Decrypt)(void); CK_RV (*C_DecryptUpdate)(void); CK_RV (*C_DecryptFinal)(void);
    CK_RV (*C_DigestInit)(void); CK_RV (*C_Digest)(void); CK_RV (*C_DigestUpdate)(void); CK_RV (*C_DigestKey)(void); CK_RV (*C_DigestFinal)(void);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG*);
    CK_RV (*C_SignUpdate)(void); CK_RV (*C_SignFinal)(void); CK_RV (*C_SignRecoverInit)(void); CK_RV (*C_SignRecover)(void);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
} *fl = NULL;

static int write_file(const char *dir, const char *name, const unsigned char *buf, size_t len)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "fopen(%s) failed\n", path); return 1; }
    fwrite(buf, 1, len, f);
    fclose(f);
    return 0;
}

/* Minimal DER SubjectPublicKeyInfo for a raw 32-byte Ed25519 point (RFC
 * 8410 §4): SEQUENCE { SEQUENCE { OID id-Ed25519 } BIT STRING raw }. */
static size_t build_ed25519_spki(const unsigned char *raw32, unsigned char *out)
{
    static const unsigned char alg[] = {
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 /* SEQ { OID 1.3.101.112 } */
    };
    unsigned char bitstring[34];
    bitstring[0] = 0x00; /* 0 unused bits */
    memcpy(bitstring + 1, raw32, 32);
    size_t bs_len = 33;
    size_t inner_len = sizeof(alg) + 2 + bs_len; /* alg + BIT STRING TLV */
    size_t off = 0;
    out[off++] = 0x30; /* outer SEQUENCE */
    out[off++] = (unsigned char)inner_len;
    memcpy(out + off, alg, sizeof(alg)); off += sizeof(alg);
    out[off++] = 0x03; /* BIT STRING */
    out[off++] = (unsigned char)bs_len;
    memcpy(out + off, bitstring, bs_len); off += bs_len;
    return off;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <module.so> <token-label> <pin> <keyid-hex> [out-dir]\n", argv[0]);
        return 2;
    }
    const char *modpath = argv[1];
    const char *tokenlabel = argv[2];
    const char *pin = argv[3];
    const char *keyid_hex = argc > 4 ? argv[4] : "08";
    const char *outdir = argc > 5 ? argv[5] : NULL;

    void *h = dlopen(modpath, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }
    void *getlist = dlsym(h, "C_GetFunctionList");
    if (!getlist) { fprintf(stderr, "no C_GetFunctionList\n"); return 1; }

    CK_RV (*C_GetFunctionList)(struct CK_FUNCTION_LIST_EXT**) =
        (CK_RV (*)(struct CK_FUNCTION_LIST_EXT**))getlist;
    CK_RV rv = C_GetFunctionList(&fl);
    if (rv != CKR_OK) { fprintf(stderr, "C_GetFunctionList rv=%lu\n", rv); return 1; }

    rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK) { fprintf(stderr, "C_Initialize rv=%lu\n", rv); return 1; }

    CK_SLOT_ID slots[32]; CK_ULONG n = 32;
    rv = fl->C_GetSlotList(1, slots, &n);
    if (rv != CKR_OK) { fprintf(stderr, "C_GetSlotList rv=%lu\n", rv); return 1; }

    CK_SLOT_ID target = (CK_SLOT_ID)-1;
    for (CK_ULONG i = 0; i < n; i++) {
        CK_TOKEN_INFO ti; memset(&ti, 0, sizeof(ti));
        if (fl->C_GetTokenInfo(slots[i], &ti) != 0) continue;
        if (strcmp(trim(ti.label, 32), tokenlabel) == 0) { target = slots[i]; break; }
    }
    if (target == (CK_SLOT_ID)-1) { fprintf(stderr, "token '%s' not found among %lu slots\n", tokenlabel, n); return 1; }

    CK_SESSION_HANDLE sess;
    rv = fl->C_OpenSession(target, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sess);
    if (rv != CKR_OK) { fprintf(stderr, "C_OpenSession rv=%lu\n", rv); return 1; }
    rv = fl->C_Login(sess, CKU_USER, (unsigned char*)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK && rv != 0x100 /* CKR_USER_ALREADY_LOGGED_IN */) {
        fprintf(stderr, "C_Login rv=%lu\n", rv); return 1;
    }

    int hexlen = (int)strlen(keyid_hex);
    unsigned char keyid[64]; int keyid_len = hexlen / 2;
    for (int i = 0; i < keyid_len; i++) {
        unsigned int b; sscanf(keyid_hex + 2*i, "%2x", &b); keyid[i] = (unsigned char)b;
    }

    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY, pubClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_ID, keyid, (CK_ULONG)keyid_len },
    };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_ID, keyid, (CK_ULONG)keyid_len },
    };
    CK_OBJECT_HANDLE hPriv = 0, hPub = 0, found_objs[1]; CK_ULONG found_count = 0;

    rv = fl->C_FindObjectsInit(sess, privTmpl, 2);
    if (rv != CKR_OK) { fprintf(stderr, "C_FindObjectsInit(priv) rv=%lu\n", rv); return 1; }
    rv = fl->C_FindObjects(sess, found_objs, 1, &found_count);
    fl->C_FindObjectsFinal(sess);
    if (rv != CKR_OK || found_count != 1) {
        fprintf(stderr, "private Ed25519 key (CKA_ID=%s) not found on token — provision it first "
                "with keygen_pkcs11_key (paramset 'ed25519')\n", keyid_hex);
        return 1;
    }
    hPriv = found_objs[0];

    rv = fl->C_FindObjectsInit(sess, pubTmpl, 2);
    if (rv != CKR_OK) { fprintf(stderr, "C_FindObjectsInit(pub) rv=%lu\n", rv); return 1; }
    rv = fl->C_FindObjects(sess, found_objs, 1, &found_count);
    fl->C_FindObjectsFinal(sess);
    if (rv != CKR_OK || found_count != 1) {
        fprintf(stderr, "public Ed25519 key (CKA_ID=%s) not found on token\n", keyid_hex);
        return 1;
    }
    hPub = found_objs[0];

    /* Read the raw 32-byte public point for the OpenSSL cross-check. */
    unsigned char pubpoint[32];
    CK_ATTRIBUTE ptAttr[] = { { CKA_EC_POINT, pubpoint, sizeof(pubpoint) } };
    rv = fl->C_GetAttributeValue(sess, hPub, ptAttr, 1);
    if (rv != CKR_OK || ptAttr[0].ulValueLen != 32) {
        fprintf(stderr, "C_GetAttributeValue(CKA_EC_POINT) rv=%lu len=%lu\n",
                rv, (unsigned long)ptAttr[0].ulValueLen);
        return 1;
    }

    static unsigned char msg[] = "strongswan-pkcs11 Ed25519ctx connector test payload";
    static unsigned char ctx[] = "strongswan-pkcs11-ctx";       /* non-empty, real context */
    static unsigned char wrong_ctx[] = "different-context-str"; /* same length class, different bytes */
    unsigned char sig[64]; CK_ULONG sig_len;
    int failures = 0;

    /* --- Positive case: sign under CKM_EDDSA + non-empty context, verify
     * under the SAME context. --- */
    {
        CK_EDDSA_PARAMS params = { CK_FALSE, sizeof(ctx) - 1, ctx };
        CK_MECHANISM mech = { CKM_EDDSA, &params, sizeof(params) };
        sig_len = sizeof(sig);
        rv = fl->C_SignInit(sess, &mech, hPriv);
        if (rv != CKR_OK) { fprintf(stderr, "[Ed25519ctx] C_SignInit rv=%lu\n", rv); return 1; }
        rv = fl->C_Sign(sess, msg, (CK_ULONG)(sizeof(msg) - 1), sig, &sig_len);
        if (rv != CKR_OK) { fprintf(stderr, "[Ed25519ctx] C_Sign rv=%lu\n", rv); return 1; }
        printf("[Ed25519ctx] C_Sign OK: signature length = %lu bytes (context=\"%s\", %lu bytes)\n",
               (unsigned long)sig_len, ctx, (unsigned long)(sizeof(ctx) - 1));
        if (sig_len != 64) {
            printf("[Ed25519ctx] FAIL: expected 64-byte R||S signature (RFC 8032 §5.1.6), got %lu\n",
                   (unsigned long)sig_len);
            failures++;
        }

        rv = fl->C_VerifyInit(sess, &mech, hPub);
        if (rv != CKR_OK) { fprintf(stderr, "[Ed25519ctx] C_VerifyInit rv=%lu\n", rv); return 1; }
        rv = fl->C_Verify(sess, msg, (CK_ULONG)(sizeof(msg) - 1), sig, sig_len);
        if (rv != CKR_OK) {
            printf("[Ed25519ctx] FAIL: C_Verify rejected a genuine signature under its own context (rv=%lu)\n", rv);
            failures++;
        } else {
            printf("[Ed25519ctx] C_Verify OK: genuine signature verified under its own context\n");
        }

        /* Negative control A: WRONG context must be rejected — proves the
         * context is actually bound into the signature, not silently
         * ignored (the exact class of bug T39b fixed in the Rust engine). */
        {
            CK_EDDSA_PARAMS bad_params = { CK_FALSE, sizeof(wrong_ctx) - 1, wrong_ctx };
            CK_MECHANISM bad_mech = { CKM_EDDSA, &bad_params, sizeof(bad_params) };
            rv = fl->C_VerifyInit(sess, &bad_mech, hPub);
            if (rv != CKR_OK) { fprintf(stderr, "[Ed25519ctx] C_VerifyInit(wrong ctx) rv=%lu\n", rv); return 1; }
            rv = fl->C_Verify(sess, msg, (CK_ULONG)(sizeof(msg) - 1), sig, sig_len);
            if (rv == CKR_OK) {
                printf("[Ed25519ctx] FAIL: verify ACCEPTED the signature under the WRONG context "
                       "(context is being ignored)\n");
                failures++;
            } else {
                printf("[Ed25519ctx] negative control OK: wrong-context verify correctly rejected (rv=%lu)\n", rv);
            }
        }

        /* Negative control B: same (correct) context, corrupted signature
         * byte — the usual sabotage check every other case in this test
         * suite runs. */
        {
            unsigned char bad_sig[64];
            memcpy(bad_sig, sig, sig_len);
            bad_sig[0] ^= 0xFF;
            rv = fl->C_VerifyInit(sess, &mech, hPub);
            if (rv != CKR_OK) { fprintf(stderr, "[Ed25519ctx] C_VerifyInit(corrupt) rv=%lu\n", rv); return 1; }
            rv = fl->C_Verify(sess, msg, (CK_ULONG)(sizeof(msg) - 1), bad_sig, sig_len);
            if (rv == CKR_OK) {
                printf("[Ed25519ctx] FAIL: verify ACCEPTED a corrupted signature\n");
                failures++;
            } else {
                printf("[Ed25519ctx] negative control OK: corrupted signature correctly rejected (rv=%lu)\n", rv);
            }
        }

        if (outdir) {
            unsigned char spki[64];
            size_t spki_len = build_ed25519_spki(pubpoint, spki);
            write_file(outdir, "ed25519ctx_pub.der", spki, spki_len);
            write_file(outdir, "ed25519ctx_msg.bin", msg, sizeof(msg) - 1);
            write_file(outdir, "ed25519ctx_sig.bin", sig, sig_len);
            write_file(outdir, "ed25519ctx_ctx.txt", ctx, sizeof(ctx) - 1);
            write_file(outdir, "ed25519ctx_wrong_ctx.txt", wrong_ctx, sizeof(wrong_ctx) - 1);
            printf("[Ed25519ctx] wrote pub/msg/sig/ctx files to %s for independent OpenSSL cross-check\n",
                   outdir);
        }
    }

    printf("\n==================================================\n");
    printf("%d test(s), %d failure(s)\n", 1, failures ? 1 : 0);
    return failures ? 1 : 0;
}
