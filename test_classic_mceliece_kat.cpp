/*
 * test_classic_mceliece_kat.cpp — Validate Classic McEliece decapsulation
 * against the official NIST Round-4 KAT vectors, for all 10 parameter sets.
 *
 * Implementation plan §5.5(a) (docs/implementation-plan-classic-mceliece-
 * all-parameter-sets-2026-09-08.md): decapsulate-only, mirroring the Rust
 * fork's own classic-mceliece-multi/tests/kat_verification.rs and
 * FrodoKEM's frodokem_kat.rs precedent — Classic McEliece's own
 * encapsulate draws non-deterministic randomness for the error vector `e`,
 * so encapsulate is not KAT-checkable here; decapsulate against a known
 * (ct, sk) pair recovering the known ss is definitive proof of correctness
 * against the reference implementation, independent of internal
 * self-consistency (which src/lib/test/ClassicMcElieceTests.cpp already
 * covers via keygen->encaps->decaps).
 *
 * Ad-hoc executable, not a CppUnit suite addition (precedent:
 * test_acvp_lms_sigver.cpp — neither ML-KEM nor any other PQC algorithm has
 * a "Tests.cpp" file under src/lib/crypto/test/; cryptotest's SOURCES list
 * covers only pre-PQC classical algorithms).
 *
 * Build: g++ -o test_classic_mceliece_kat test_classic_mceliece_kat.cpp -ldl -I src/lib/pkcs11 -std=c++17
 * Run:   ./test_classic_mceliece_kat [path to built libsofthsmv3.so]
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "src/lib/pkcs11/pkcs11.h"

// Vendor extension constants — src/lib/vendor_mechanisms.h (kept in sync by
// hand here since that header pulls in the engine's own config.h, which
// this ad-hoc build does not configure).
#define CKK_PQCTODAY_CLASSIC_MCELIECE              0x80000002UL
#define CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE  0x80000004UL
#define CKP_CLASSIC_MCELIECE_6688128  0x1UL
#define CKP_CLASSIC_MCELIECE_348864   0x2UL
#define CKP_CLASSIC_MCELIECE_348864F  0x3UL
#define CKP_CLASSIC_MCELIECE_460896   0x4UL
#define CKP_CLASSIC_MCELIECE_460896F  0x5UL
#define CKP_CLASSIC_MCELIECE_6688128F 0x6UL
#define CKP_CLASSIC_MCELIECE_6960119  0x7UL
#define CKP_CLASSIC_MCELIECE_6960119F 0x8UL
#define CKP_CLASSIC_MCELIECE_8192128  0x9UL
#define CKP_CLASSIC_MCELIECE_8192128F 0xAUL

static int unhex(const std::string& hex, std::vector<unsigned char>& out) {
    if (hex.size() % 2 != 0) return -1;
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        unsigned int b;
        if (sscanf(hex.c_str() + 2 * i, "%02x", &b) != 1) return -1;
        out[i] = (unsigned char)b;
    }
    return (int)out.size();
}

struct KatVector {
    int count;
    std::vector<unsigned char> sk;
    std::vector<unsigned char> ct;
    std::vector<unsigned char> ss;
};

// kmip/kat/classic-mceliece/raw/<dir>/kat_kem.rsp — plain "key = HEXVALUE"
// blocks separated by blank lines, one field per line (# comment lines and
// the leading "seed"/"pk" fields are ignored here; only sk/ct/ss matter for
// the decapsulate-only design above).
static std::vector<KatVector> parseKatFile(const std::string& path) {
    std::vector<KatVector> vectors;
    std::ifstream f(path);
    if (!f) return vectors;

    KatVector cur;
    cur.count = -1;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
        std::string val = line.substr(eq + 1);
        size_t start = val.find_first_not_of(" \t");
        val = (start == std::string::npos) ? "" : val.substr(start);

        if (key == "count") {
            if (cur.count >= 0) vectors.push_back(cur);
            cur = KatVector();
            cur.count = atoi(val.c_str());
        } else if (key == "sk") {
            unhex(val, cur.sk);
        } else if (key == "ct") {
            unhex(val, cur.ct);
        } else if (key == "ss") {
            unhex(val, cur.ss);
        }
    }
    if (cur.count >= 0) vectors.push_back(cur);
    return vectors;
}

struct Variant {
    const char* dir;
    CK_ULONG ps;
};

static const Variant VARIANTS[] = {
    { "mceliece348864",   CKP_CLASSIC_MCELIECE_348864   },
    { "mceliece348864f",  CKP_CLASSIC_MCELIECE_348864F  },
    { "mceliece460896",   CKP_CLASSIC_MCELIECE_460896   },
    { "mceliece460896f",  CKP_CLASSIC_MCELIECE_460896F  },
    { "mceliece6688128",  CKP_CLASSIC_MCELIECE_6688128  },
    { "mceliece6688128f", CKP_CLASSIC_MCELIECE_6688128F },
    { "mceliece6960119",  CKP_CLASSIC_MCELIECE_6960119  },
    { "mceliece6960119f", CKP_CLASSIC_MCELIECE_6960119F },
    { "mceliece8192128",  CKP_CLASSIC_MCELIECE_8192128  },
    { "mceliece8192128f", CKP_CLASSIC_MCELIECE_8192128F },
};

int main(int argc, char** argv) {
    const char* libPath = (argc > 1) ? argv[1] : "./build/src/lib/libsofthsmv3.so";

    system("rm -rf /tmp/softhsm-mceliece-kat && mkdir -p /tmp/softhsm-mceliece-kat/tokens");
    FILE* f = fopen("/tmp/softhsm-mceliece-kat/softhsm2.conf", "w");
    fprintf(f, "directories.tokendir = /tmp/softhsm-mceliece-kat/tokens/\n"
               "objectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n");
    fclose(f);
    setenv("SOFTHSM2_CONF", "/tmp/softhsm-mceliece-kat/softhsm2.conf", 1);

    void* handle = dlopen(libPath, RTLD_NOW);
    if (!handle) { printf("[FAIL] dlopen(%s): %s\n", libPath, dlerror()); return 1; }

    // C_EncapsulateKey/C_DecapsulateKey are PKCS#11 v3.2 additions, absent
    // from the legacy CK_FUNCTION_LIST (built with CK_PKCS11_2_0_ONLY in
    // pkcs11.h) that C_GetFunctionList returns for v2.40 backward
    // compatibility — the v3.2 struct comes from C_GetInterface instead
    // (mirroring SoftHSM::computeSupportedProfiles' own lookup pattern,
    // src/lib/SoftHSM_objects.cpp).
    typedef CK_RV (*CK_C_GetInterfaceFn)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS);
    CK_C_GetInterfaceFn getInterface = (CK_C_GetInterfaceFn)dlsym(handle, "C_GetInterface");
    if (!getInterface) { printf("[FAIL] dlsym(C_GetInterface): %s\n", dlerror()); return 1; }

    CK_VERSION v32 = { 3, 2 };
    CK_INTERFACE_PTR iface = NULL_PTR;
    CK_RV rvInit = getInterface((CK_UTF8CHAR_PTR)"PKCS 11", &v32, &iface, 0);
    if (rvInit != CKR_OK || iface == NULL_PTR || iface->pFunctionList == NULL_PTR) {
        printf("[FAIL] C_GetInterface(\"PKCS 11\", 3.2): rv=0x%08lX\n", (unsigned long)rvInit);
        return 1;
    }
    CK_FUNCTION_LIST_3_2_PTR fl = (CK_FUNCTION_LIST_3_2_PTR)iface->pFunctionList;
    fl->C_Initialize(NULL_PTR);

    CK_SLOT_ID slots[10];
    CK_ULONG ulCount = 10;
    fl->C_GetSlotList(CK_FALSE, slots, &ulCount);
    CK_UTF8CHAR label[32];
    memset(label, ' ', 32);
    memcpy(label, "mceliece-kat", 12);
    fl->C_InitToken(slots[0], (CK_UTF8CHAR_PTR)"5678", 4, label);

    CK_SESSION_HANDLE hSess;
    fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSess);
    fl->C_Login(hSess, CKU_SO, (CK_UTF8CHAR_PTR)"5678", 4);
    fl->C_InitPIN(hSess, (CK_UTF8CHAR_PTR)"1234", 4);
    fl->C_Logout(hSess);
    fl->C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);

    printf("Classic McEliece KAT decapsulation — official NIST Round-4 vectors\n\n");

    int total = 0, pass = 0, fail = 0, skip = 0;

    for (const Variant& variant : VARIANTS) {
        std::string path = std::string("kmip/kat/classic-mceliece/raw/") + variant.dir + "/kat_kem.rsp";
        std::vector<KatVector> vectors = parseKatFile(path);
        if (vectors.empty()) {
            printf("[SKIP] %-16s could not read/parse %s\n", variant.dir, path.c_str());
            skip++;
            continue;
        }

        int variantPass = 0, variantFail = 0;
        for (KatVector& v : vectors) {
            total++;

            CK_OBJECT_CLASS prkClass = CKO_PRIVATE_KEY;
            CK_KEY_TYPE keyType = CKK_PQCTODAY_CLASSIC_MCELIECE;
            CK_BBOOL bTrue = CK_TRUE;
            CK_BBOOL bFalse = CK_FALSE;
            CK_ULONG ps = variant.ps;
            CK_ATTRIBUTE prkT[] = {
                { CKA_CLASS, &prkClass, sizeof(prkClass) },
                { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
                { CKA_TOKEN, &bFalse, sizeof(bFalse) },
                { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
                { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
                { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
                { CKA_DECAPSULATE, &bTrue, sizeof(bTrue) },
                { CKA_PARAMETER_SET, &ps, sizeof(ps) },
                { CKA_VALUE, v.sk.data(), (CK_ULONG)v.sk.size() },
            };
            CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
            CK_RV rv = fl->C_CreateObject(hSess, prkT, sizeof(prkT) / sizeof(CK_ATTRIBUTE), &hPrk);
            if (rv != CKR_OK) {
                printf("[FAIL] %-16s count=%-3d C_CreateObject rv=0x%08lX\n", variant.dir, v.count, (unsigned long)rv);
                fail++; variantFail++;
                continue;
            }

            CK_MECHANISM mech = { CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE, NULL_PTR, 0 };
            CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
            CK_ATTRIBUTE secretT[] = {
                { CKA_CLASS, &secretClass, sizeof(secretClass) },
                { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
            };
            CK_OBJECT_HANDLE hSecret = CK_INVALID_HANDLE;
            rv = fl->C_DecapsulateKey(hSess, &mech, hPrk,
                    secretT, sizeof(secretT) / sizeof(CK_ATTRIBUTE),
                    v.ct.data(), (CK_ULONG)v.ct.size(), &hSecret);
            fl->C_DestroyObject(hSess, hPrk);
            if (rv != CKR_OK) {
                printf("[FAIL] %-16s count=%-3d C_DecapsulateKey rv=0x%08lX\n", variant.dir, v.count, (unsigned long)rv);
                fail++; variantFail++;
                continue;
            }

            unsigned char recovered[64];
            CK_ATTRIBUTE getVal[] = { { CKA_VALUE, recovered, sizeof(recovered) } };
            rv = fl->C_GetAttributeValue(hSess, hSecret, getVal, 1);
            fl->C_DestroyObject(hSess, hSecret);
            if (rv != CKR_OK || getVal[0].ulValueLen != v.ss.size() ||
                memcmp(recovered, v.ss.data(), v.ss.size()) != 0) {
                printf("[FAIL] %-16s count=%-3d recovered ss does not match KAT (rv=0x%08lX)\n",
                       variant.dir, v.count, (unsigned long)rv);
                fail++; variantFail++;
                continue;
            }

            pass++; variantPass++;
        }

        printf("[%s] %-16s %d/%zu KAT vectors matched\n",
               variantFail == 0 ? "PASS" : "FAIL", variant.dir, variantPass, vectors.size());
    }

    printf("\n============================================================\n");
    printf("Classic McEliece KAT Results: %d total, %d MATCH, %d MISMATCH, %d SKIP\n",
           total, pass, fail, skip);
    printf("============================================================\n");

    fl->C_Finalize(NULL_PTR);
    return (fail > 0 || skip > 0) ? 1 : 0;
}
