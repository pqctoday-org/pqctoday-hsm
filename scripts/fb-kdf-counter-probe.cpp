/* fb-kdf-counter-probe — standalone native verification for the
 * CKM_SP800_108_FEEDBACK_KDF "no explicit CK_SP800_108_COUNTER" fix
 * (SoftHSM_keygen.cpp, 2026-09 remediation) — the companion to
 * dp-kdf-counter-probe.cpp's CKM_SP800_108_DOUBLE_PIPELINE_KDF check.
 *
 * Background: the Double-Pipeline fix's own investigation flagged, but did
 * not verify, that CKM_SP800_108_FEEDBACK_KDF might have the same defect
 * for a different reason — it used to delegate entirely to OpenSSL's own
 * KBKDF provider (mode=FEEDBACK), which has no parameter able to omit the
 * counter at all (core_names.h defines only "r"/"use-l"/"use-separator"
 * for that provider — "r" is the counter's WIDTH, not whether one is
 * present). Confirmed by direct EVP_KDF probing against an independent
 * from-spec NIST SP 800-108 §5.2 Python/HMAC reference: OpenSSL's output
 * matched the WITH-counter reference even when no "r" param was set at
 * all. Fixed by hand-rolling the round loop on EVP_MAC instead, same
 * pattern as the Double-Pipeline handler.
 *
 * Talks directly to the C++ engine's PKCS#11 C_* API (dlopen'd
 * libsofthsmv3.dylib/.so) — same dlopen approach as
 * dp-kdf-counter-probe.cpp, bypassing the OpenSSL provider layer entirely.
 *
 * Imports a FIXED, known base key via C_CreateObject (bytes 0x00..0x1f —
 * same convention as dp-kdf-counter-probe.cpp) and a fixed 32-byte IV (all
 * 0xAA — the feedback-mode K(0)), then runs CKM_SP800_108_FEEDBACK_KDF
 * (HMAC-SHA256 PRF) twice:
 *   - NOCTR: CK_PRF_DATA_PARAM = [ CK_SP800_108_BYTE_ARRAY only ] — the
 *     call shape this fix changes.
 *   - WITHCTR: CK_PRF_DATA_PARAM = [ CK_SP800_108_COUNTER(32-bit BE),
 *     CK_SP800_108_BYTE_ARRAY ] — the call shape this fix must NOT change
 *     (regression check against a before/after build).
 * Expected output post-fix (verified against an independent from-spec
 * Python/HMAC reference and against the Rust engine's own
 * sp800_108_run_feedback, rust/src/ffi.rs):
 *   NOCTR   2f212b9460b36ecf305bb9bd0167d5924f69f373777bccaa41ea20e7be3e9ff3502b1558c53274b6d6f86e7a75fe1c3d
 *   WITHCTR ec922ed633021239588e4614713b68453204a506da44b79843fbad149c0e0713302bc7469dd8377f75f7aab82aee3ef1
 *
 * Usage: fb_kdf_counter_probe <engine.so/.dylib> <workdir>
 * Output: two lines, "NOCTR <hex>" and "WITHCTR <hex>", or "FAIL <where> <rv>". */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <string>
#include <cstdint>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "src/lib/pkcs11/pkcs11.h"

#ifndef CKM_SP800_108_FEEDBACK_KDF
#define CKM_SP800_108_FEEDBACK_KDF 0x000003adUL
#endif

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    printf("%s ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static void fail(const char *where, CK_RV rv)
{
    fprintf(stderr, "FAIL %s rv=0x%08lx\n", where, (unsigned long)rv);
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <engine.so> <workdir>\n", argv[0]);
        return 2;
    }
    std::string enginePath = argv[1];
    std::string workdir = argv[2];

    std::string setup = "rm -rf '" + workdir + "' && mkdir -p '" + workdir + "/tokens'";
    if (system(setup.c_str()) != 0) { fprintf(stderr, "FAIL workdir setup\n"); return 1; }
    std::string confPath = workdir + "/softhsm2.conf";
    FILE *f = fopen(confPath.c_str(), "w");
    if (!f) { fprintf(stderr, "FAIL conf write\n"); return 1; }
    fprintf(f, "directories.tokendir = %s/tokens/\n", workdir.c_str());
    fprintf(f, "objectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n");
    fprintf(f, "log.backend = file\nlog.file = %s/softhsm2.log\n", workdir.c_str());
    fclose(f);
    setenv("SOFTHSM2_CONF", confPath.c_str(), 1);

    void *handle = dlopen(enginePath.c_str(), RTLD_NOW);
    if (!handle) { fprintf(stderr, "FAIL dlopen %s\n", dlerror()); return 1; }
    CK_C_GetFunctionList pfn = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    if (!pfn) { fprintf(stderr, "FAIL dlsym C_GetFunctionList\n"); return 1; }
    CK_FUNCTION_LIST_PTR fl = NULL_PTR;
    pfn(&fl);
    if (!fl) { fprintf(stderr, "FAIL null function list\n"); return 1; }

    CK_RV rv = fl->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) fail("C_Initialize", rv);

    CK_SLOT_ID slots[10];
    CK_ULONG slotCount = 10;
    rv = fl->C_GetSlotList(CK_FALSE, slots, &slotCount);
    if (rv != CKR_OK || slotCount == 0) fail("C_GetSlotList", rv);

    CK_UTF8CHAR label[32]; memset(label, ' ', 32); memcpy(label, "fbkdfprobe", 10);
    rv = fl->C_InitToken(slots[0], (CK_UTF8CHAR_PTR)"5678", 4, label);
    if (rv != CKR_OK) fail("C_InitToken", rv);

    CK_SESSION_HANDLE hSess = 0;
    rv = fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSess);
    if (rv != CKR_OK) fail("C_OpenSession", rv);

    rv = fl->C_Login(hSess, CKU_SO, (CK_UTF8CHAR_PTR)"5678", 4);
    if (rv != CKR_OK) fail("C_Login(SO)", rv);
    rv = fl->C_InitPIN(hSess, (CK_UTF8CHAR_PTR)"1234", 4);
    if (rv != CKR_OK) fail("C_InitPIN", rv);
    rv = fl->C_Logout(hSess);
    if (rv != CKR_OK) fail("C_Logout", rv);
    rv = fl->C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    if (rv != CKR_OK) fail("C_Login(USER)", rv);

    // Fixed, known 32-byte base key: 0x00,0x01,...,0x1f (matches the
    // independent Python/HMAC reference byte-for-byte).
    CK_BYTE baseKeyBytes[32];
    for (int i = 0; i < 32; i++) baseKeyBytes[i] = (CK_BYTE)i;

    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genType = CKK_GENERIC_SECRET;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &genType, sizeof(genType) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_DERIVE, &bTrue, sizeof(bTrue) },
        { CKA_VALUE, baseKeyBytes, sizeof(baseKeyBytes) },
    };
    CK_OBJECT_HANDLE hBase = 0;
    rv = fl->C_CreateObject(hSess, baseTmpl, 8, &hBase);
    if (rv != CKR_OK) fail("C_CreateObject(base)", rv);

    // Fixed input — matches the independent Python/HMAC reference exactly.
    CK_BYTE fixedInput[] = "fb-kdf-probe-fixed-input";
    CK_ULONG fixedInputLen = (CK_ULONG)(sizeof(fixedInput) - 1);

    // IV / seed K(0): 32 bytes of 0xAA — matches the reference too.
    CK_BYTE iv[32];
    memset(iv, 0xAA, sizeof(iv));

    CK_ULONG derivedLen = 48; // matches the reference's output length
    CK_ATTRIBUTE deriveTmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &genType, sizeof(genType) },
        { CKA_VALUE_LEN, &derivedLen, sizeof(derivedLen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
    };

    // --- NO CK_SP800_108_COUNTER at all — the call shape this probe checks ---
    {
        CK_PRF_DATA_PARAM prfParams[] = {
            { CK_SP800_108_BYTE_ARRAY, fixedInput, fixedInputLen },
        };
        CK_SP800_108_FEEDBACK_KDF_PARAMS fbParams = {
            CKM_SHA256_HMAC, 1, prfParams,
            (CK_ULONG)sizeof(iv), iv,
            0, NULL_PTR
        };
        CK_MECHANISM mech = { CKM_SP800_108_FEEDBACK_KDF, &fbParams, sizeof(fbParams) };
        CK_OBJECT_HANDLE hDerived = 0;
        rv = fl->C_DeriveKey(hSess, &mech, hBase, deriveTmpl, 7, &hDerived);
        if (rv != CKR_OK) fail("C_DeriveKey(NOCTR)", rv);

        CK_ATTRIBUTE getVal = { CKA_VALUE, NULL_PTR, 0 };
        rv = fl->C_GetAttributeValue(hSess, hDerived, &getVal, 1);
        if (rv != CKR_OK) fail("C_GetAttributeValue(NOCTR,size)", rv);
        unsigned char *buf = (unsigned char *)malloc(getVal.ulValueLen);
        getVal.pValue = buf;
        rv = fl->C_GetAttributeValue(hSess, hDerived, &getVal, 1);
        if (rv != CKR_OK) fail("C_GetAttributeValue(NOCTR,value)", rv);
        print_hex("NOCTR", buf, getVal.ulValueLen);
        free(buf);
    }

    // --- Explicit CK_SP800_108_COUNTER (regression check — must remain
    //     byte-identical to before the fix, and must match the WITH_COUNTER
    //     independent reference) ---
    {
        CK_SP800_108_COUNTER_FORMAT counterFmt = { CK_FALSE /* big-endian */, 32 };
        CK_PRF_DATA_PARAM prfParams[] = {
            { CK_SP800_108_COUNTER, &counterFmt, sizeof(counterFmt) },
            { CK_SP800_108_BYTE_ARRAY, fixedInput, fixedInputLen },
        };
        CK_SP800_108_FEEDBACK_KDF_PARAMS fbParams = {
            CKM_SHA256_HMAC, 2, prfParams,
            (CK_ULONG)sizeof(iv), iv,
            0, NULL_PTR
        };
        CK_MECHANISM mech = { CKM_SP800_108_FEEDBACK_KDF, &fbParams, sizeof(fbParams) };
        CK_OBJECT_HANDLE hDerived = 0;
        rv = fl->C_DeriveKey(hSess, &mech, hBase, deriveTmpl, 7, &hDerived);
        if (rv != CKR_OK) fail("C_DeriveKey(WITHCTR)", rv);

        CK_ATTRIBUTE getVal = { CKA_VALUE, NULL_PTR, 0 };
        rv = fl->C_GetAttributeValue(hSess, hDerived, &getVal, 1);
        if (rv != CKR_OK) fail("C_GetAttributeValue(WITHCTR,size)", rv);
        unsigned char *buf = (unsigned char *)malloc(getVal.ulValueLen);
        getVal.pValue = buf;
        rv = fl->C_GetAttributeValue(hSess, hDerived, &getVal, 1);
        if (rv != CKR_OK) fail("C_GetAttributeValue(WITHCTR,value)", rv);
        print_hex("WITHCTR", buf, getVal.ulValueLen);
        free(buf);
    }

    fl->C_Finalize(NULL_PTR);
    return 0;
}
