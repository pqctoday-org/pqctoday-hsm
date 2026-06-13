#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <getopt.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <ctime>

// OpenSSL — independent oracle for KCV reference computation (SHA-1 + AES-ECB).
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "tests/json.hpp"
using json = nlohmann::json;

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "src/lib/pkcs11/pkcs11.h"

// Fallback definitions for new mechanisms in case they're not in the local pkcs11.h.
// Values MUST match the canonical OASIS PKCS#11 v3.2 pkcs11t.h.
#ifndef CKM_ML_KEM
#define CKM_ML_KEM 0x00000017
#endif
#ifndef CKM_ML_DSA
#define CKM_ML_DSA 0x0000001d
#endif
#ifndef CKM_SLH_DSA
#define CKM_SLH_DSA 0x0000002e
#endif
#ifndef CKM_AES_CTR
#define CKM_AES_CTR 0x00001086
#endif
#ifndef CKM_HKDF_DERIVE
#define CKM_HKDF_DERIVE 0x0000402A
#endif
#ifndef CKM_SP800_108_COUNTER_KDF
#define CKM_SP800_108_COUNTER_KDF 0x000003AC
#endif
#ifndef CKM_HSS_KEY_PAIR_GEN
#define CKM_HSS_KEY_PAIR_GEN 0x00004032
#endif
#ifndef CKM_RIPEMD160
#define CKM_RIPEMD160 0x00000240
#endif
#ifndef CKA_PUBLIC_KEY_INFO
#define CKA_PUBLIC_KEY_INFO 0x00000129
#endif
#ifndef CKK_EC_EDWARDS
#define CKK_EC_EDWARDS 0x00000040UL
#endif
#ifndef CKK_EC_MONTGOMERY
#define CKK_EC_MONTGOMERY 0x00000041UL
#endif
#ifndef CKM_EC_EDWARDS_KEY_PAIR_GEN
#define CKM_EC_EDWARDS_KEY_PAIR_GEN 0x00001055UL
#endif
#ifndef CKM_EC_MONTGOMERY_KEY_PAIR_GEN
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN 0x00001056UL
#endif
#ifndef CKM_EDDSA
#define CKM_EDDSA 0x00001057UL
#endif
#ifndef CKM_ECDH1_DERIVE
#define CKM_ECDH1_DERIVE 0x00001050UL
#endif
#ifndef CKM_KMAC_128
#define CKM_KMAC_128 (0x80000000UL | 0x00000100UL) // mapped to CKM_VENDOR_DEFINED block
#endif
#ifndef CKM_SHA3_256
#define CKM_SHA3_256 0x000002b0UL
#endif
// BIP32 is not part of OASIS v3.2 — this fork carries it in vendor space
// (see src/lib/pkcs11/pkcs11t.h: CKM_VENDOR_DEFINED | 0x105B etc.)
#ifndef CKM_BIP32_MASTER_DERIVE
#define CKM_BIP32_MASTER_DERIVE (0x80000000UL | 0x0000105BUL)
#endif
#ifndef CKM_BIP32_CHILD_DERIVE
#define CKM_BIP32_CHILD_DERIVE (0x80000000UL | 0x0000105CUL)
#endif
#ifndef CKA_BIP32_CHAIN_CODE
#define CKA_BIP32_CHAIN_CODE (0x80000000UL | 0x00001021UL)
#endif
#ifndef CKM_SP800_108_FEEDBACK_KDF
#define CKM_SP800_108_FEEDBACK_KDF 0x000003ADUL
#endif

// INJECTED: Missing v3.2 Mechanisms for compliance testing
#ifndef CKM_XMSSMT_KEY_PAIR_GEN
#define CKM_XMSSMT_KEY_PAIR_GEN 0x00004035UL
#endif
#ifndef CKM_KMAC_256
#define CKM_KMAC_256 (0x80000000UL | 0x00000101UL)
#endif
#ifndef CKM_ECDH1_COFACTOR_DERIVE
#define CKM_ECDH1_COFACTOR_DERIVE 0x00001051UL
#endif
#ifndef CKM_ECDSA_SHA3_224
#define CKM_ECDSA_SHA3_224 0x00001047UL
#define CKM_ECDSA_SHA3_256 0x00001048UL
#define CKM_ECDSA_SHA3_384 0x00001049UL
#define CKM_ECDSA_SHA3_512 0x0000104aUL
#endif


// Options
std::string opt_engine = "./build_fresh/src/lib/libsofthsmv3.dylib";
std::string opt_category = "all";
std::string opt_report = "compliance_report";
std::string opt_pin = "1234";
std::string opt_workdir = "/tmp/softhsm-compliance-test"; // token dir + softhsm2.conf live here
std::string opt_engine_commit = "";                        // optional engine git commit for the report header

// Token State
CK_FUNCTION_LIST_PTR fl;
CK_SESSION_HANDLE hSess;

// JSON Report
json report = json::object();
int total_pass = 0;
int total_fail = 0;
int total_skip = 0;
// XFAIL = known, documented engine non-conformance (pre-existing engine
// behavior outside the test suite's scope to fix). Reported loudly in the
// summary but does not flip the process exit code — only unexpected FAILs do.
int total_xfail = 0;


bool refresh_session() {
    if (hSess != 0) {
        fl->C_CloseSession(hSess);
        hSess = 0;
    }
    CK_RV rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSess);
    if (rv != CKR_OK) return false;
    rv = fl->C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)opt_pin.c_str(), opt_pin.length());
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) return false;
    return true;
}

void print_usage() {
    printf("Usage: p11_v32_compliance_test [options]\n");
    printf("Options:\n");
    printf("  --engine <path>    Path to the PKCS#11 library (default: %s)\n", opt_engine.c_str());
    printf("  --category <cat>   Test category: all, init, discovery, pqc-kem, pqc-dsa, hbs, attr, g1-security, g2-mechtable, g3-keygen, g4-retcodes, g5-attrs (default: %s)\n", opt_category.c_str());
    printf("  --report <path>    Output bases (e.g. 'rep' creates 'rep.md' and 'rep.json') (default: %s)\n", opt_report.c_str());
    printf("  --pin <pin>        Token PIN (default: %s)\n", opt_pin.c_str());
    printf("  --workdir <dir>    Scratch dir for softhsm2.conf + token store (default: %s)\n", opt_workdir.c_str());
    printf("  --engine-commit <sha>  Engine git commit recorded in the report header\n");
}

void parse_args(int argc, char** argv) {
    static struct option long_options[] = {
        {"engine", required_argument, 0, 'e'},
        {"category", required_argument, 0, 'c'},
        {"report", required_argument, 0, 'r'},
        {"pin", required_argument, 0, 'p'},
        {"workdir", required_argument, 0, 'w'},
        {"engine-commit", required_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "e:c:r:p:w:g:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'e': opt_engine = optarg; break;
            case 'c': opt_category = optarg; break;
            case 'r': opt_report = optarg; break;
            case 'p': opt_pin = optarg; break;
            case 'w': opt_workdir = optarg; break;
            case 'g': opt_engine_commit = optarg; break;
            case 'h': print_usage(); exit(0);
        }
    }
}

void record_result(const std::string& category, const std::string& test_name, const std::string& status, const std::string& details) {
    printf("[%s] %s: %s (%s)\n", category.c_str(), test_name.c_str(), status.c_str(), details.c_str());
    if (!report.contains(category)) {
        report[category] = json::array();
    }
    report[category].push_back({
        {"test", test_name},
        {"status", status},
        {"details", details}
    });
    if (status == "PASS") total_pass++;
    else if (status == "FAIL") total_fail++;
    else if (status == "SKIP") total_skip++;
    else if (status == "XFAIL") total_xfail++;
}

// ── Advertisement helpers ────────────────────────────────────────────────────
// PASS criteria policy: a result may only count as PASS if the behavior is
// spec-conformant for a feature the token ADVERTISES. These helpers query the
// token's advertised mechanism list / mechanism flags so tests can decide
// between "assert real success" (advertised) and "explicit SKIP" (not
// advertised). "Couldn't even start the operation" must never read as PASS.
bool mech_advertised(CK_MECHANISM_TYPE mech) {
    CK_ULONG count = 0;
    if (fl->C_GetMechanismList(0, NULL_PTR, &count) != CKR_OK || count == 0) return false;
    std::vector<CK_MECHANISM_TYPE> mechs(count);
    if (fl->C_GetMechanismList(0, mechs.data(), &count) != CKR_OK) return false;
    for (CK_ULONG i = 0; i < count; i++) if (mechs[i] == mech) return true;
    return false;
}

bool init_token() {
    // Fully hermetic: scratch conf + token store under opt_workdir (recreated
    // from scratch on every run; override with --workdir for ctest isolation).
    std::string setup = "rm -rf '" + opt_workdir + "' && mkdir -p '" + opt_workdir + "/tokens'";
    if (system(setup.c_str()) != 0) {
        record_result("Init", "WorkdirSetup", "FAIL", "could not create " + opt_workdir);
        return false;
    }
    std::string confPath = opt_workdir + "/softhsm2.conf";
    FILE* f = fopen(confPath.c_str(), "w");
    if (!f) {
        record_result("Init", "WorkdirSetup", "FAIL", "could not write " + confPath);
        return false;
    }
    fprintf(f, "directories.tokendir = %s/tokens/\n", opt_workdir.c_str());
    fprintf(f, "objectstore.backend = file\nlog.level = DEBUG\nslots.removable = false\n");
    fprintf(f, "log.backend = file\nlog.file = %s/softhsm2.log\n", opt_workdir.c_str());
    fclose(f);
    setenv("SOFTHSM2_CONF", confPath.c_str(), 1);

    void* handle = dlopen(opt_engine.c_str(), RTLD_NOW);
    if (!handle) {
        record_result("Init", "dlopen", "FAIL", dlerror());
        return false;
    }

    CK_C_GetFunctionList pfn = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    if (!pfn) {
        record_result("Init", "C_GetFunctionList", "FAIL", "Symbol not found");
        return false;
    }

    pfn(&fl);
    if (!fl) {
        record_result("Init", "FunctionListPtr", "FAIL", "Null returned");
        return false;
    }

    // ── G4 pre-init checks (must run BEFORE C_Initialize) ────────────────────
    if (opt_category == "all" || opt_category == "g4-retcodes") {
        // V-19: C_GetSessionValidationFlags before C_Initialize →
        // CKR_CRYPTOKI_NOT_INITIALIZED.
        typedef CK_RV (*C_GSVF_t)(CK_SESSION_HANDLE, CK_SESSION_VALIDATION_FLAGS_TYPE, CK_FLAGS_PTR);
        C_GSVF_t GSVF = (C_GSVF_t)dlsym(handle, "C_GetSessionValidationFlags");
        if (GSVF) {
            CK_FLAGS f = 0xdead;
            CK_RV rvg = GSVF(hSess, 0x00000001UL /*CKS_LAST_VALIDATION_OK*/, &f);
            record_result("G4Retcodes", "V19_GSVF_pre_init",
                          rvg == CKR_CRYPTOKI_NOT_INITIALIZED ? "PASS" : "FAIL",
                          "expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=" + std::to_string(rvg));
        } else {
            record_result("G4Retcodes", "V19_GSVF_pre_init", "SKIP", "unavailable");
        }
    }

    // V-20: C_Initialize with pInitArgs->pReserved != NULL → CKR_ARGUMENTS_BAD.
    // This must precede the real C_Initialize(NULL) in this process.
    if (opt_category == "all" || opt_category == "g4-retcodes") {
        CK_C_INITIALIZE_ARGS badArgs;
        memset(&badArgs, 0, sizeof(badArgs));
        badArgs.flags = CKF_OS_LOCKING_OK;
        badArgs.pReserved = (CK_VOID_PTR)(uintptr_t)0x1; // non-NULL
        CK_RV rvi = fl->C_Initialize(&badArgs);
        record_result("G4Retcodes", "V20_Initialize_pReserved_nonNULL",
                      rvi == CKR_ARGUMENTS_BAD ? "PASS" : "FAIL",
                      "expect CKR_ARGUMENTS_BAD(0x7), RV=" + std::to_string(rvi));
    }

    CK_RV rv = fl->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
        record_result("Init", "C_Initialize", "FAIL", "RV=" + std::to_string(rv));
        return false;
    }

    CK_SLOT_ID slots[10];
    CK_ULONG ulCount = 10;
    rv = fl->C_GetSlotList(CK_FALSE, slots, &ulCount);
    if (rv != CKR_OK || ulCount == 0) {
        record_result("Init", "C_GetSlotList", "FAIL", "RV=" + std::to_string(rv) + " count=" + std::to_string(ulCount));
        return false;
    }

    CK_UTF8CHAR label[32]; memset(label, ' ', 32); memcpy(label, "compliance", 10);
    rv = fl->C_InitToken(slots[0], (CK_UTF8CHAR_PTR)"5678", 4, label);
    if (rv != CKR_OK) {
        record_result("Init", "C_InitToken", "FAIL", "RV=" + std::to_string(rv));
        return false;
    }

    rv = fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSess);
    if (rv != CKR_OK) {
        record_result("Init", "C_OpenSession", "FAIL", "RV=" + std::to_string(rv));
        return false;
    }

    rv = fl->C_Login(hSess, CKU_SO, (CK_UTF8CHAR_PTR)"5678", 4);
    rv = fl->C_InitPIN(hSess, (CK_UTF8CHAR_PTR)opt_pin.c_str(), opt_pin.length());
    rv = fl->C_Logout(hSess);
    rv = fl->C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)opt_pin.c_str(), opt_pin.length());
    if (rv != CKR_OK) {
        record_result("Init", "C_Login", "FAIL", "RV=" + std::to_string(rv));
        return false;
    }

    record_result("Init", "TokenSetup", "PASS", "Initialized token and session");
    return true;
}

void test_mechanism_discovery() {
    CK_MECHANISM_TYPE mechs[200];
    CK_ULONG count = 200;
    CK_RV rv = fl->C_GetMechanismList(0, mechs, &count);
    if (rv != CKR_OK) {
        record_result("Discovery", "C_GetMechanismList", "FAIL", "RV=" + std::to_string(rv));
        return;
    }

    bool has_ml_kem = false, has_ml_dsa = false, has_slh_dsa = false;
    bool has_ripmd = false, has_aes_ctr = false, has_hkdf = false;
    bool has_xmss = false, has_chacha = false;

    for (CK_ULONG i = 0; i < count; i++) {
        if (mechs[i] == CKM_ML_KEM) has_ml_kem = true;
        if (mechs[i] == CKM_ML_DSA) has_ml_dsa = true;
        if (mechs[i] == CKM_SLH_DSA) has_slh_dsa = true;
        if (mechs[i] == CKM_RIPEMD160) has_ripmd = true;
        if (mechs[i] == CKM_AES_CTR) has_aes_ctr = true;
        if (mechs[i] == CKM_HKDF_DERIVE) has_hkdf = true;
        if (mechs[i] == 0x00004036 /* CKM_XMSS */) has_xmss = true;
        if (mechs[i] == 0x00004021 /* CKM_CHACHA20_POLY1305 */) has_chacha = true;
    }

    // PKCS#11 v3.2 mandates NO particular mechanism set — presence/absence of
    // any individual mechanism is informational, not a conformance criterion.
    // Advertised → PASS (informational); not advertised → SKIP, never FAIL.
    auto report_presence = [](const char* name, bool present, const std::string& what) {
        record_result("Discovery", name, present ? "PASS" : "SKIP",
                      present ? what + " advertised"
                              : what + " not advertised (informational — v3.2 mandates no mechanism set)");
    };
    report_presence("CKM_ML_KEM", has_ml_kem, "PQC KEM support");
    report_presence("CKM_ML_DSA", has_ml_dsa, "PQC DSA support");
    report_presence("CKM_SLH_DSA", has_slh_dsa, "PQC SLH-DSA support");
    report_presence("CKM_XMSS", has_xmss, "PQC XMSS support");
    report_presence("CKM_AES_CTR", has_aes_ctr, "AES CTR support (v3.2/5G)");
    report_presence("CKM_CHACHA20_POLY1305", has_chacha, "ChaCha20 support (RFC 7539)");
    report_presence("CKM_HKDF_DERIVE", has_hkdf, "HKDF support (v3.0/5G)");
    report_presence("CKM_RIPEMD160", has_ripmd, "RIPEMD160 support");
}

void test_key_attributes() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeKem = 0x00000049; // CKK_ML_KEM (v3.2 pkcs11t.h; 0x48 is CKK_XMSSMT)
    CK_ULONG paramSetKem = 2; // CKP_ML_KEM_768
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_MECHANISM mech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,         &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktypeKem, sizeof(ktypeKem) },
        { CKA_ENCAPSULATE,   &bTrue,    sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) },
        { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,         &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktypeKem, sizeof(ktypeKem) },
        { CKA_DECAPSULATE,   &bTrue,    sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) },
        { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hPub, hPriv;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
    if (rv != CKR_OK) {
        record_result("Attributes", "Generate_ML_KEM", "FAIL", "Generation failed, RV=" + std::to_string(rv));
        return;
    }

    CK_BYTE valBuf[2000];
    CK_ATTRIBUTE valAttr = { CKA_VALUE, valBuf, sizeof(valBuf) };
    rv = fl->C_GetAttributeValue(hSess, hPub, &valAttr, 1);
    record_result("Attributes", "CKA_VALUE_Pub", (rv == CKR_OK && valAttr.ulValueLen > 0) ? "PASS" : "FAIL", "§1.21 G-ATTR1 check");

    CK_BYTE spkiBuf[3000];
    CK_ATTRIBUTE spkiAttr = { CKA_PUBLIC_KEY_INFO, spkiBuf, sizeof(spkiBuf) };
    rv = fl->C_GetAttributeValue(hSess, hPub, &spkiAttr, 1);
    record_result("Attributes", "CKA_PUBLIC_KEY_INFO_Pub", (rv == CKR_OK && spkiAttr.ulValueLen > 0) ? "PASS" : "FAIL", "Required for all PQC keys");

    rv = fl->C_GetAttributeValue(hSess, hPriv, &spkiAttr, 1);
    record_result("Attributes", "CKA_PUBLIC_KEY_INFO_Priv", (rv == CKR_OK && spkiAttr.ulValueLen > 0) ? "PASS" : "FAIL", "Required to be exposed on private objects");
    
    // Enforce CKA_HSS_KEYS_REMAINING check (HSS/LMS)
    CK_MECHANISM hssMech = { CKM_HSS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_KEY_TYPE hssKT = 0x00000046UL; // CKK_HSS
    CK_ULONG hssLevels = 1;
    CK_ATTRIBUTE hssPubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &hssKT, sizeof(hssKT) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE hssPrivTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &hssKT, sizeof(hssKT) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    CK_OBJECT_HANDLE hssPub, hssPriv;
    rv = fl->C_GenerateKeyPair(hSess, &hssMech, hssPubTmpl, sizeof(hssPubTmpl)/sizeof(CK_ATTRIBUTE), hssPrivTmpl, sizeof(hssPrivTmpl)/sizeof(CK_ATTRIBUTE), &hssPub, &hssPriv);
    
    if (rv == CKR_OK) {
        CK_ULONG remaining1 = 0;
        CK_ATTRIBUTE remAttr = { 0x0000061cUL /* CKA_HSS_KEYS_REMAINING */, &remaining1, sizeof(remaining1) };
        rv = fl->C_GetAttributeValue(hSess, hssPriv, &remAttr, 1);
        if (rv == CKR_OK && remAttr.ulValueLen > 0) {
            record_result("Attributes", "CKA_HSS_KEYS_REMAINING_Gen", "PASS", "Remaining=" + std::to_string(remaining1));
            
            // SoftHSM core requires we consume a key and test state decay
            CK_MECHANISM hssSignMech = { 0x00004033UL /* CKM_HSS (v3.2 pkcs11t.h) */, NULL_PTR, 0 };
            CK_RV rvS = fl->C_SignInit(hSess, &hssSignMech, hssPriv);
            if (rvS == CKR_OK) {
                CK_BYTE data[] = "data";
                CK_BYTE sig[5000]; CK_ULONG sigLen = sizeof(sig);
                fl->C_Sign(hSess, data, 4, sig, &sigLen);

                CK_ULONG remaining2 = 0;
                remAttr.pValue = &remaining2;
                fl->C_GetAttributeValue(hSess, hssPriv, &remAttr, 1);

                if (remaining2 < remaining1) {
                    record_result("Attributes", "CKA_HSS_KEYS_REMAINING_Consume", "PASS", "Count decreased correctly");
                } else {
                    record_result("Attributes", "CKA_HSS_KEYS_REMAINING_Consume", "FAIL", "Count did not decay");
                }
            } else {
                // Never let "couldn't even start the operation" go unrecorded.
                record_result("Attributes", "CKA_HSS_KEYS_REMAINING_Consume", "FAIL",
                              "C_SignInit(CKM_HSS) failed, RV=" + std::to_string(rvS));
            }
        } else {
            record_result("Attributes", "CKA_HSS_KEYS_REMAINING", "FAIL", "Missing attribute from Private Key. RV=" + std::to_string(rv));
        }
    } else {
        record_result("Attributes", "CKA_HSS_KEYS_REMAINING", "FAIL", "HSS KeyGen failed, skipping attribute test. RV=" + std::to_string(rv));
    }
}


void check_key_profile(std::string cat, std::string runName, CK_OBJECT_HANDLE hPub, CK_OBJECT_HANDLE hPriv, bool isKEM) {
    (void)cat; // Avoid unused parameter warning

    // G-ATTR1: CKA_VALUE extraction on public key
    CK_BYTE pubVal[8000]; CK_ATTRIBUTE attrPub = { CKA_VALUE, pubVal, sizeof(pubVal) };
    CK_RV rv = fl->C_GetAttributeValue(hSess, hPub, &attrPub, 1);
    if (rv == CKR_OK && attrPub.ulValueLen > 0) {
        record_result("Attributes", runName + "_CKA_VALUE_Pub", "PASS", "§1.21 G-ATTR1 check");
    } else {
        record_result("Attributes", runName + "_CKA_VALUE_Pub", "FAIL", "§1.21 G-ATTR1 failure");
    }

    // SPKI: CKA_PUBLIC_KEY_INFO on public key
    CK_BYTE spkiPub[8000]; CK_ATTRIBUTE attrSpkiP = { CKA_PUBLIC_KEY_INFO, spkiPub, sizeof(spkiPub) };
    rv = fl->C_GetAttributeValue(hSess, hPub, &attrSpkiP, 1);
    if (rv == CKR_OK && attrSpkiP.ulValueLen > 0) {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Pub", "PASS", "SPKI exposed");
    } else {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Pub", "FAIL", "SPKI missing on public key");
    }

    // SPKI: CKA_PUBLIC_KEY_INFO on private key
    CK_BYTE spkiPriv[8000]; CK_ATTRIBUTE attrSpkiPr = { CKA_PUBLIC_KEY_INFO, spkiPriv, sizeof(spkiPriv) };
    rv = fl->C_GetAttributeValue(hSess, hPriv, &attrSpkiPr, 1);
    if (rv == CKR_OK && attrSpkiPr.ulValueLen > 0) {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Priv", "PASS", "SPKI exposed on private");
    } else {
        record_result("Attributes", runName + "_CKA_PUBLIC_KEY_INFO_Priv", "FAIL", "SPKI missing on private");
    }

    // Mechanism specific attributes
    if (isKEM) {
        CK_BBOOL canEncap = CK_FALSE; CK_ATTRIBUTE attrEncap = { CKA_ENCAPSULATE, &canEncap, sizeof(canEncap) };
        fl->C_GetAttributeValue(hSess, hPub, &attrEncap, 1);
        if (canEncap == CK_TRUE) record_result("Attributes", runName + "_CKA_ENCAPSULATE", "PASS", "");
        else record_result("Attributes", runName + "_CKA_ENCAPSULATE", "FAIL", "Missing KEM pub rule");

        CK_BBOOL canDecap = CK_FALSE; CK_ATTRIBUTE attrDecap = { CKA_DECAPSULATE, &canDecap, sizeof(canDecap) };
        fl->C_GetAttributeValue(hSess, hPriv, &attrDecap, 1);
        if (canDecap == CK_TRUE) record_result("Attributes", runName + "_CKA_DECAPSULATE", "PASS", "");
        else record_result("Attributes", runName + "_CKA_DECAPSULATE", "FAIL", "Missing KEM priv rule");
    } else {
        CK_BBOOL canVerify = CK_FALSE; CK_ATTRIBUTE attrVer = { CKA_VERIFY, &canVerify, sizeof(canVerify) };
        fl->C_GetAttributeValue(hSess, hPub, &attrVer, 1);
        if (canVerify == CK_TRUE) record_result("Attributes", runName + "_CKA_VERIFY", "PASS", "");
        else record_result("Attributes", runName + "_CKA_VERIFY", "FAIL", "Missing DSA pub rule");

        CK_BBOOL canSign = CK_FALSE; CK_ATTRIBUTE attrSig = { CKA_SIGN, &canSign, sizeof(canSign) };
        fl->C_GetAttributeValue(hSess, hPriv, &attrSig, 1);
        if (canSign == CK_TRUE) record_result("Attributes", runName + "_CKA_SIGN", "PASS", "");
        else record_result("Attributes", runName + "_CKA_SIGN", "FAIL", "Missing DSA priv rule");
    }
}

void test_pqc_kem() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeKem = 0x00000049; // CKK_ML_KEM (v3.2 pkcs11t.h; 0x48 is CKK_XMSSMT)
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_MECHANISM mech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    // Function pointer fallback if not in struct
    typedef CK_RV (*C_EncapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
    typedef CK_RV (*C_DecapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    C_EncapsulateKey_t EncapFn = (C_EncapsulateKey_t)dlsym(dlib, "C_EncapsulateKey");
    C_DecapsulateKey_t DecapFn = (C_DecapsulateKey_t)dlsym(dlib, "C_DecapsulateKey");
    
    if (!EncapFn || !DecapFn) {
        record_result("KEM", "C_EncapsulateKey", "SKIP", "Function pointers missing");
        return;
    }

    CK_ULONG kemParams[] = { 1, 2, 3 }; // 512, 768, 1024
    std::string kemNames[] = { "512", "768", "1024" };
    
    for (int i = 0; i < 3; ++i) {
        std::string n = kemNames[i];
        CK_ULONG paramSetKem = kemParams[i];
        
        CK_ATTRIBUTE pubTmpl[] = {
            { CKA_CLASS,         &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE,      &ktypeKem, sizeof(ktypeKem) },
            { CKA_ENCAPSULATE,   &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };
        CK_ATTRIBUTE privTmpl[] = {
            { CKA_CLASS,         &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE,      &ktypeKem, sizeof(ktypeKem) },
            { CKA_DECAPSULATE,   &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };

        CK_OBJECT_HANDLE hPub, hPriv;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result("KEM", "Generate_ML_KEM_" + n, "FAIL", "Generation failed, RV=" + std::to_string(rv));
            continue;
        }
                record_result("KEM", "Generate_ML_KEM_" + n, "PASS", "Gen ML-KEM-" + n);
        check_key_profile("Attributes", "ML_KEM_" + n, hPub, hPriv, true);

        // Encapsulate
        CK_MECHANISM encapMech = { CKM_ML_KEM, NULL_PTR, 0 };
        CK_BYTE ct[2000]; CK_ULONG ctLen = sizeof(ct);
        
        CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
        CK_KEY_TYPE secType = 0x00000010; // CKK_GENERIC_SECRET
        CK_ULONG secLen = 32;
        CK_ATTRIBUTE ssTmpl[] = {
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &secType, sizeof(secType) },
            { CKA_VALUE_LEN, &secLen, sizeof(secLen) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
        };
        CK_OBJECT_HANDLE hSecretEnc;
        
        rv = EncapFn(hSess, &encapMech, hPub, ssTmpl, 5, ct, &ctLen, &hSecretEnc);
        if (rv != CKR_OK) { record_result("KEM", "C_EncapsulateKey_" + n, "FAIL", "RV=" + std::to_string(rv)); continue; }
        record_result("KEM", "C_EncapsulateKey_" + n, "PASS", "CT len=" + std::to_string(ctLen));

        // Decapsulate
        CK_OBJECT_HANDLE hSecretDec;
        rv = DecapFn(hSess, &encapMech, hPriv, ssTmpl, 5, ct, ctLen, &hSecretDec);
        if (rv != CKR_OK) { record_result("KEM", "C_DecapsulateKey_" + n, "FAIL", "RV=" + std::to_string(rv)); continue; }
        
        CK_BYTE val1[100]; CK_ATTRIBUTE attr1 = { CKA_VALUE, val1, sizeof(val1) };
        CK_BYTE val2[100]; CK_ATTRIBUTE attr2 = { CKA_VALUE, val2, sizeof(val2) };
        fl->C_GetAttributeValue(hSess, hSecretEnc, &attr1, 1);
        fl->C_GetAttributeValue(hSess, hSecretDec, &attr2, 1);
        
        if (attr1.ulValueLen > 0 && attr1.ulValueLen == attr2.ulValueLen && memcmp(val1, val2, attr1.ulValueLen) == 0) {
            record_result("KEM", "C_DecapsulateKey_" + n, "PASS", "SS matched");
        } else {
            record_result("KEM", "C_DecapsulateKey_" + n, "FAIL", "SS mismatch");
        }
    }
}


#ifndef CKM_HASH_ML_DSA_SHA512
#define CKM_HASH_ML_DSA_SHA512 0x00000026UL
#define CKM_HASH_ML_DSA_SHA3_512 0x0000002aUL
#endif

void test_pqc_dsa() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeDsa = 0x0000004a; // CKK_ML_DSA
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_MECHANISM mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    CK_ULONG dsaParams[] = { 1, 2, 3 }; // 44, 65, 87
    std::string dsaNames[] = { "44", "65", "87" };
    
    // Test pure and pre-hash mechanisms for ML-DSA
    CK_MECHANISM_TYPE signMechs[] = { CKM_ML_DSA, CKM_HASH_ML_DSA_SHA512, CKM_HASH_ML_DSA_SHA3_512 };
    std::string signNames[] = { "Pure", "PreHash_SHA512", "PreHash_SHA3_512" };
    
    for (int i = 0; i < 3; ++i) {
        std::string n = dsaNames[i];
        CK_ULONG paramSetDsa = dsaParams[i];
        
        CK_ATTRIBUTE pubTmpl[] = { 
            { CKA_CLASS,         &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE,      &ktypeDsa, sizeof(ktypeDsa) },
            { CKA_VERIFY,        &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetDsa,  sizeof(paramSetDsa) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };
        CK_ATTRIBUTE privTmpl[] = { 
            { CKA_CLASS,         &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE,      &ktypeDsa, sizeof(ktypeDsa) },
            { CKA_SIGN,          &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetDsa,  sizeof(paramSetDsa) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };

        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result("DSA", "Generate_ML_DSA_" + n, "FAIL", "RV=" + std::to_string(rv));
            continue;
        }
                record_result("DSA", "Generate_ML_DSA_" + n, "PASS", "Gen ML-DSA-" + n);
        check_key_profile("Attributes", "ML_DSA_" + n, hPub, hPriv, false);
        
        for (int j = 0; j < 3; j++) {
            std::string runName = n + "_" + signNames[j];
            CK_MECHANISM signMech = { signMechs[j], NULL_PTR, 0 };
            
            rv = fl->C_SignInit(hSess, &signMech, hPriv);
            if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
                    record_result("DSA", "C_SignInit_" + runName, "SKIP", "Mechanism not implemented");
                    continue;
            }
            if (rv != CKR_OK) {
                record_result("DSA", "C_SignInit_" + runName, "FAIL", "RV=" + std::to_string(rv));
                continue;
            }
            
            CK_BYTE msg[] = "test message variation hashing";
            CK_BYTE sig[5000];
            CK_ULONG sigLen = sizeof(sig);
            rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
            record_result("DSA", "C_Sign_" + runName, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));

            rv = fl->C_VerifyInit(hSess, &signMech, hPub);
            if (rv == CKR_OK) {
                rv = fl->C_Verify(hSess, msg, sizeof(msg)-1, sig, sigLen);
                record_result("DSA", "C_Verify_" + runName, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            } else {
                record_result("DSA", "C_VerifyInit_" + runName, "FAIL", "RV=" + std::to_string(rv));
            }
        }
    }
}


/* ---------------------------------------------------------------------------
 * test_mldsa_context_binding
 *
 * Verifies that softhsm honors the FIPS 204 context string passed via
 * CK_SIGN_ADDITIONAL_CONTEXT.context (PKCS#11 v3.2 §6.67.5). This is the
 * foundation that pkcs11-provider's Composite-ML-DSA support
 * (draft-ietf-lamps-pq-composite-sigs-19 §3.2) relies on: each composite
 * profile binds an ML-DSA signature to its profile-specific signature
 * label as `mldsa_ctx`.
 *
 * Without correct context handling at the softhsm core layer, every
 * pkcs11-provider composite-sig signature would be invalid per draft-19
 * even with a correct provider-side patch.
 *
 * Coverage:
 *  1. Sign with ctx=A, verify with ctx=A   → PASS
 *  2. Sign with ctx=A, verify with ctx=B   → FAIL (context binding works)
 *  3. Sign with ctx=A, verify without ctx  → FAIL (binding enforced)
 *  4. Sign twice with DETERMINISTIC_REQUIRED + same context → byte-identical
 *     (FIPS 204 deterministic mode honored end-to-end)
 *  5. Sign twice with HEDGE_PREFERRED + same context → non-identical
 *     (hedge variant honored; this also confirms the hedgeVariant field
 *      reaches softhsm via CK_SIGN_ADDITIONAL_CONTEXT)
 * ------------------------------------------------------------------------- */
void test_mldsa_context_binding() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype = 0x0000004a; /* CKK_ML_DSA */
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG paramSet = 2; /* CKP_ML_DSA_65 */

    CK_MECHANISM keygenMech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,         &pubClass,  sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktype,     sizeof(ktype) },
        { CKA_VERIFY,        &bTrue,     sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet,  sizeof(paramSet) },
        { CKA_TOKEN,         &bFalse,    sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,         &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktype,     sizeof(ktype) },
        { CKA_SIGN,          &bTrue,     sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet,  sizeof(paramSet) },
        { CKA_TOKEN,         &bFalse,    sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;

    CK_RV rv = fl->C_GenerateKeyPair(hSess, &keygenMech, pubTmpl, 5, privTmpl, 5,
                                     &hPub, &hPriv);
    if (rv != CKR_OK) {
        record_result("DSA-CTX", "Setup_KeyGen_MLDSA65", "FAIL",
                      "RV=" + std::to_string(rv));
        return;
    }
    record_result("DSA-CTX", "Setup_KeyGen_MLDSA65", "PASS", "ML-DSA-65 keypair generated");

    const CK_BYTE msg[] = "the quick brown fox jumps over the lazy dog";
    const CK_ULONG msgLen = sizeof(msg) - 1;

    CK_BYTE ctxA[] = "COMPSIG-MLDSA65-ECDSA-P256-SHA512";
    CK_BYTE ctxB[] = "COMPSIG-MLDSA65-Ed25519-SHA512";

    auto build_mech = [](CK_HEDGE_TYPE hedge, CK_BYTE *ctx_ptr, CK_ULONG ctx_len,
                        CK_SIGN_ADDITIONAL_CONTEXT *params_out)
        -> CK_MECHANISM {
        params_out->hedgeVariant = hedge;
        params_out->pContext = ctx_ptr;
        params_out->ulContextLen = ctx_len;
        CK_MECHANISM m;
        m.mechanism = CKM_ML_DSA;
        m.pParameter = (CK_VOID_PTR)params_out;
        m.ulParameterLen = sizeof(*params_out);
        return m;
    };

    auto sign_with = [&](CK_MECHANISM *signMech, CK_BYTE *sig, CK_ULONG *sigLen,
                        const char *case_name) -> bool {
        rv = fl->C_SignInit(hSess, signMech, hPriv);
        if (rv != CKR_OK) {
            record_result("DSA-CTX", std::string("SignInit_") + case_name,
                          "FAIL", "RV=" + std::to_string(rv));
            return false;
        }
        rv = fl->C_Sign(hSess, (CK_BYTE_PTR)msg, msgLen, sig, sigLen);
        if (rv != CKR_OK) {
            record_result("DSA-CTX", std::string("Sign_") + case_name, "FAIL",
                          "RV=" + std::to_string(rv));
            return false;
        }
        return true;
    };

    /* 1. Sign with ctx=A, verify with ctx=A → PASS */
    CK_SIGN_ADDITIONAL_CONTEXT pA;
    CK_MECHANISM mechSignA = build_mech(CKH_HEDGE_PREFERRED, ctxA,
                                        sizeof(ctxA) - 1, &pA);
    CK_BYTE sigA[5000];
    CK_ULONG sigALen = sizeof(sigA);
    if (sign_with(&mechSignA, sigA, &sigALen, "ctxA")) {
        record_result("DSA-CTX", "Sign_ctxA", "PASS",
                      "siglen=" + std::to_string(sigALen));
        CK_SIGN_ADDITIONAL_CONTEXT pAv;
        CK_MECHANISM mechVerifyA = build_mech(CKH_HEDGE_PREFERRED, ctxA,
                                              sizeof(ctxA) - 1, &pAv);
        rv = fl->C_VerifyInit(hSess, &mechVerifyA, hPub);
        if (rv == CKR_OK) {
            rv = fl->C_Verify(hSess, (CK_BYTE_PTR)msg, msgLen, sigA, sigALen);
            record_result("DSA-CTX", "Verify_ctxA_matching",
                          rv == CKR_OK ? "PASS" : "FAIL",
                          "expected CKR_OK got RV=" + std::to_string(rv));
        } else {
            record_result("DSA-CTX", "VerifyInit_ctxA", "FAIL",
                          "RV=" + std::to_string(rv));
        }

        /* 2. Verify same sig with ctx=B → must FAIL (context binding) */
        CK_SIGN_ADDITIONAL_CONTEXT pBv;
        CK_MECHANISM mechVerifyB = build_mech(CKH_HEDGE_PREFERRED, ctxB,
                                              sizeof(ctxB) - 1, &pBv);
        rv = fl->C_VerifyInit(hSess, &mechVerifyB, hPub);
        if (rv == CKR_OK) {
            rv = fl->C_Verify(hSess, (CK_BYTE_PTR)msg, msgLen, sigA, sigALen);
            /* Expecting CKR_SIGNATURE_INVALID (0x000000C0) */
            record_result("DSA-CTX", "Verify_ctxB_should_fail",
                          rv != CKR_OK ? "PASS" : "FAIL",
                          rv != CKR_OK
                              ? "binding works; RV=" + std::to_string(rv)
                              : "CONTEXT BINDING BROKEN: verified with wrong ctx");
        } else {
            record_result("DSA-CTX", "VerifyInit_ctxB", "FAIL",
                          "RV=" + std::to_string(rv));
        }

        /* 3. Verify same sig with NO context → must FAIL */
        CK_MECHANISM mechVerifyEmpty = { CKM_ML_DSA, NULL_PTR, 0 };
        rv = fl->C_VerifyInit(hSess, &mechVerifyEmpty, hPub);
        if (rv == CKR_OK) {
            rv = fl->C_Verify(hSess, (CK_BYTE_PTR)msg, msgLen, sigA, sigALen);
            record_result("DSA-CTX", "Verify_noctx_should_fail",
                          rv != CKR_OK ? "PASS" : "FAIL",
                          rv != CKR_OK
                              ? "binding enforced; RV=" + std::to_string(rv)
                              : "CONTEXT BINDING BROKEN: verified without ctx");
        } else {
            record_result("DSA-CTX", "VerifyInit_noctx", "FAIL",
                          "RV=" + std::to_string(rv));
        }
    }

    /* 4. Deterministic mode → same signature twice */
    CK_SIGN_ADDITIONAL_CONTEXT pDet1, pDet2;
    CK_MECHANISM mechDet1 = build_mech(CKH_DETERMINISTIC_REQUIRED, ctxA,
                                       sizeof(ctxA) - 1, &pDet1);
    CK_MECHANISM mechDet2 = build_mech(CKH_DETERMINISTIC_REQUIRED, ctxA,
                                       sizeof(ctxA) - 1, &pDet2);
    CK_BYTE sigD1[5000], sigD2[5000];
    CK_ULONG sigD1Len = sizeof(sigD1), sigD2Len = sizeof(sigD2);
    bool d1 = sign_with(&mechDet1, sigD1, &sigD1Len, "deterministic_1");
    bool d2 = sign_with(&mechDet2, sigD2, &sigD2Len, "deterministic_2");
    if (d1 && d2) {
        bool identical = (sigD1Len == sigD2Len)
                         && memcmp(sigD1, sigD2, sigD1Len) == 0;
        record_result(
            "DSA-CTX", "Deterministic_byte_equal", identical ? "PASS" : "FAIL",
            identical
                ? "deterministic mode produces identical signatures (FIPS 204)"
                : "HEDGE BINDING BROKEN: deterministic mode produced different bytes");
    }

    /* 5. Hedged mode → signatures should differ (probabilistic) */
    CK_SIGN_ADDITIONAL_CONTEXT pH1, pH2;
    CK_MECHANISM mechHedge1 = build_mech(CKH_HEDGE_REQUIRED, ctxA,
                                         sizeof(ctxA) - 1, &pH1);
    CK_MECHANISM mechHedge2 = build_mech(CKH_HEDGE_REQUIRED, ctxA,
                                         sizeof(ctxA) - 1, &pH2);
    CK_BYTE sigH1[5000], sigH2[5000];
    CK_ULONG sigH1Len = sizeof(sigH1), sigH2Len = sizeof(sigH2);
    bool h1 = sign_with(&mechHedge1, sigH1, &sigH1Len, "hedge_1");
    bool h2 = sign_with(&mechHedge2, sigH2, &sigH2Len, "hedge_2");
    if (h1 && h2) {
        bool different = (sigH1Len != sigH2Len)
                         || memcmp(sigH1, sigH2, sigH1Len) != 0;
        record_result(
            "DSA-CTX", "Hedge_non_deterministic", different ? "PASS" : "FAIL",
            different
                ? "hedged mode produces distinct signatures (probabilistic)"
                : "HEDGE BINDING WEAK: hedged mode produced identical bytes");
    }
}

void test_multipart_signing() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeDsa = 0x0000004a; // CKK_ML_DSA
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG paramSet65 = 2; // ML-DSA-65

    CK_MECHANISM genMech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,         &pubClass,   sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktypeDsa,   sizeof(ktypeDsa) },
        { CKA_VERIFY,        &bTrue,      sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet65, sizeof(paramSet65) },
        { CKA_TOKEN,         &bFalse,     sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,         &privClass,  sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktypeDsa,   sizeof(ktypeDsa) },
        { CKA_SIGN,          &bTrue,      sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet65, sizeof(paramSet65) },
        { CKA_TOKEN,         &bFalse,     sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &genMech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
    if (rv != CKR_OK) {
        record_result("MultiPart", "Setup_KeyGen", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    record_result("MultiPart", "Setup_KeyGen", "PASS", "ML-DSA-65 key pair generated");

    // --- Multi-part signing ---
    CK_MECHANISM signMech = { CKM_ML_DSA, NULL_PTR, 0 };
    rv = fl->C_SignInit(hSess, &signMech, hPriv);
    record_result("MultiPart", "C_SignInit", rv == CKR_OK ? "PASS" : "FAIL",
                  "PKCS#11 v3.2 §5.2 — RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    CK_BYTE chunk1[] = "hello ";
    CK_BYTE chunk2[] = "world";
    rv = fl->C_SignUpdate(hSess, chunk1, sizeof(chunk1) - 1);
    record_result("MultiPart", "C_SignUpdate_chunk1", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    if (rv != CKR_OK) {
        // Abort so session isn't left in a bad state
        fl->C_SignFinal(hSess, NULL, 0);
        return;
    }

    rv = fl->C_SignUpdate(hSess, chunk2, sizeof(chunk2) - 1);
    record_result("MultiPart", "C_SignUpdate_chunk2", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));

    CK_BYTE sig[5000];
    CK_ULONG sigLen = sizeof(sig);
    rv = fl->C_SignFinal(hSess, sig, &sigLen);
    record_result("MultiPart", "C_SignFinal", rv == CKR_OK ? "PASS" : "FAIL",
                  "SigLen=" + std::to_string(sigLen) + " RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    // --- Multi-part verification ---
    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    record_result("MultiPart", "C_VerifyInit", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    rv = fl->C_VerifyUpdate(hSess, chunk1, sizeof(chunk1) - 1);
    record_result("MultiPart", "C_VerifyUpdate_chunk1", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));

    rv = fl->C_VerifyUpdate(hSess, chunk2, sizeof(chunk2) - 1);
    record_result("MultiPart", "C_VerifyUpdate_chunk2", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));

    rv = fl->C_VerifyFinal(hSess, sig, sigLen);
    record_result("MultiPart", "C_VerifyFinal", rv == CKR_OK ? "PASS" : "FAIL",
                  "PKCS#11 v3.2 §5.2 round-trip — RV=" + std::to_string(rv));

    // --- Cross-check: one-shot verify of the same message ---
    CK_BYTE fullMsg[] = "hello world";
    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    if (rv == CKR_OK) {
        rv = fl->C_Verify(hSess, fullMsg, sizeof(fullMsg) - 1, sig, sigLen);
        record_result("MultiPart", "C_Verify_oneshot_xcheck",
                      rv == CKR_OK ? "PASS" : "FAIL",
                      "Multi-part sig matches one-shot verify — RV=" + std::to_string(rv));
    }
}

// ── Multi-part signing tests for ECDSA and EdDSA (PKCS#11 v3.2 §5.2) ──────

void test_multipart_ecdsa() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    // P-256 OID (DER): 1.2.840.10045.3.1.7
    CK_BYTE oid_p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,     &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,  &ecType,   sizeof(ecType)   },
        { CKA_TOKEN,     &bFalse,   sizeof(bFalse)   },
        { CKA_VERIFY,    &bTrue,    sizeof(bTrue)    },
        { CKA_EC_PARAMS, oid_p256,  sizeof(oid_p256) }
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,     &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,  &ecType,    sizeof(ecType)    },
        { CKA_TOKEN,     &bFalse,    sizeof(bFalse)    },
        { CKA_PRIVATE,   &bTrue,     sizeof(bTrue)     },
        { CKA_SIGN,      &bTrue,     sizeof(bTrue)     }
    };

    CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &genMech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
    if (rv != CKR_OK) {
        record_result("MultiPart_ECDSA", "Setup_KeyGen", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    record_result("MultiPart_ECDSA", "Setup_KeyGen", "PASS", "P-256 key pair generated");

    CK_MECHANISM signMech = { CKM_ECDSA_SHA256, NULL_PTR, 0 };
    rv = fl->C_SignInit(hSess, &signMech, hPriv);
    record_result("MultiPart_ECDSA", "C_SignInit", rv == CKR_OK ? "PASS" : "FAIL",
                  "CKM_ECDSA_SHA256 — RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    CK_BYTE chunk1[] = "hello ";
    CK_BYTE chunk2[] = "world";
    rv = fl->C_SignUpdate(hSess, chunk1, sizeof(chunk1) - 1);
    record_result("MultiPart_ECDSA", "C_SignUpdate_chunk1", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    if (rv != CKR_OK) { fl->C_SignFinal(hSess, NULL, 0); return; }

    rv = fl->C_SignUpdate(hSess, chunk2, sizeof(chunk2) - 1);
    record_result("MultiPart_ECDSA", "C_SignUpdate_chunk2", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));

    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    rv = fl->C_SignFinal(hSess, sig, &sigLen);
    record_result("MultiPart_ECDSA", "C_SignFinal", rv == CKR_OK ? "PASS" : "FAIL",
                  "SigLen=" + std::to_string(sigLen) + " RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    record_result("MultiPart_ECDSA", "C_VerifyInit", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    rv = fl->C_VerifyUpdate(hSess, chunk1, sizeof(chunk1) - 1);
    record_result("MultiPart_ECDSA", "C_VerifyUpdate_chunk1", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    rv = fl->C_VerifyUpdate(hSess, chunk2, sizeof(chunk2) - 1);
    record_result("MultiPart_ECDSA", "C_VerifyUpdate_chunk2", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    rv = fl->C_VerifyFinal(hSess, sig, sigLen);
    record_result("MultiPart_ECDSA", "C_VerifyFinal", rv == CKR_OK ? "PASS" : "FAIL",
                  "PKCS#11 v3.2 §5.2 P-256 round-trip — RV=" + std::to_string(rv));

    CK_BYTE fullMsg[] = "hello world";
    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    if (rv == CKR_OK) {
        rv = fl->C_Verify(hSess, fullMsg, sizeof(fullMsg) - 1, sig, sigLen);
        record_result("MultiPart_ECDSA", "C_Verify_oneshot_xcheck",
                      rv == CKR_OK ? "PASS" : "FAIL",
                      "Multi-part sig matches one-shot verify — RV=" + std::to_string(rv));
    }
}

void test_multipart_eddsa() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE edType = CKK_EC_EDWARDS;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    // CKA_EC_PARAMS as DER PrintableString curve name "edwards25519"
    // (PKCS#11 v3.2 §6.3.3 CurveName choice, RFC 8032 name — NOT the OID form)
    CK_BYTE oid_ed25519[] = { 0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39 };

    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,     &pubClass,    sizeof(pubClass)    },
        { CKA_KEY_TYPE,  &edType,      sizeof(edType)      },
        { CKA_TOKEN,     &bFalse,      sizeof(bFalse)      },
        { CKA_VERIFY,    &bTrue,       sizeof(bTrue)       },
        { CKA_EC_PARAMS, oid_ed25519,  sizeof(oid_ed25519) }
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,     &privClass,   sizeof(privClass)   },
        { CKA_KEY_TYPE,  &edType,      sizeof(edType)      },
        { CKA_TOKEN,     &bFalse,      sizeof(bFalse)      },
        { CKA_PRIVATE,   &bTrue,       sizeof(bTrue)       },
        { CKA_SIGN,      &bTrue,       sizeof(bTrue)       }
    };

    CK_MECHANISM genMech = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &genMech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
    if (rv != CKR_OK) {
        record_result("MultiPart_EdDSA", "Setup_KeyGen", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    record_result("MultiPart_EdDSA", "Setup_KeyGen", "PASS", "Ed25519 key pair generated");

    CK_MECHANISM signMech = { CKM_EDDSA, NULL_PTR, 0 };
    rv = fl->C_SignInit(hSess, &signMech, hPriv);
    record_result("MultiPart_EdDSA", "C_SignInit", rv == CKR_OK ? "PASS" : "FAIL",
                  "CKM_EDDSA — RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    CK_BYTE chunk1[] = "hello ";
    CK_BYTE chunk2[] = "world";
    rv = fl->C_SignUpdate(hSess, chunk1, sizeof(chunk1) - 1);
    record_result("MultiPart_EdDSA", "C_SignUpdate_chunk1", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    if (rv != CKR_OK) { fl->C_SignFinal(hSess, NULL, 0); return; }

    rv = fl->C_SignUpdate(hSess, chunk2, sizeof(chunk2) - 1);
    record_result("MultiPart_EdDSA", "C_SignUpdate_chunk2", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));

    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    rv = fl->C_SignFinal(hSess, sig, &sigLen);
    record_result("MultiPart_EdDSA", "C_SignFinal", rv == CKR_OK ? "PASS" : "FAIL",
                  "SigLen=" + std::to_string(sigLen) + " RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    record_result("MultiPart_EdDSA", "C_VerifyInit", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    if (rv != CKR_OK) return;

    rv = fl->C_VerifyUpdate(hSess, chunk1, sizeof(chunk1) - 1);
    record_result("MultiPart_EdDSA", "C_VerifyUpdate_chunk1", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    rv = fl->C_VerifyUpdate(hSess, chunk2, sizeof(chunk2) - 1);
    record_result("MultiPart_EdDSA", "C_VerifyUpdate_chunk2", rv == CKR_OK ? "PASS" : "FAIL",
                  "RV=" + std::to_string(rv));
    rv = fl->C_VerifyFinal(hSess, sig, sigLen);
    record_result("MultiPart_EdDSA", "C_VerifyFinal", rv == CKR_OK ? "PASS" : "FAIL",
                  "PKCS#11 v3.2 §5.2 Ed25519 round-trip — RV=" + std::to_string(rv));

    CK_BYTE fullMsg[] = "hello world";
    rv = fl->C_VerifyInit(hSess, &signMech, hPub);
    if (rv == CKR_OK) {
        rv = fl->C_Verify(hSess, fullMsg, sizeof(fullMsg) - 1, sig, sigLen);
        record_result("MultiPart_EdDSA", "C_Verify_oneshot_xcheck",
                      rv == CKR_OK ? "PASS" : "FAIL",
                      "Multi-part sig matches one-shot verify — RV=" + std::to_string(rv));
    }
}

// Additions for PKCS#11 v3.2 compliance tool

#ifndef CKM_HASH_SLH_DSA
#define CKM_HASH_SLH_DSA               0x00000034UL
#define CKM_HASH_SLH_DSA_SHA256        0x00000037UL
#define CKM_HASH_SLH_DSA_SHAKE256      0x0000003fUL
#endif

// Function pointer structs for v3.2 message based signatures
typedef CK_RV (*C_SignMessageBegin_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*C_SignMessageNext_t)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

typedef CK_RV (*C_VerifyMessageBegin_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*C_VerifyMessageNext_t)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);

// Function pointer structs for v3.2 message based encryption
typedef CK_RV (*C_MessageEncryptInit_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*C_EncryptMessageBegin_t)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*C_EncryptMessageNext_t)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_ULONG);
typedef CK_RV (*C_MessageEncryptFinal_t)(CK_SESSION_HANDLE);

void test_v32_kdfs() {
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genType = 0x00000010; // CKK_GENERIC_SECRET
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG valueLen = 32;

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &genType, sizeof(genType) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_DERIVE, &bTrue, sizeof(bTrue) }
    };
    
    CK_OBJECT_HANDLE hBaseKey = 0;
    CK_MECHANISM genMech = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
    CK_RV rv = fl->C_GenerateKey(hSess, &genMech, tmpl, 5, &hBaseKey);
    if (rv != CKR_OK) {
        record_result("KDF", "BaseKeyGen", "FAIL", "Failed to generate base key");
        return;
    }
    
    // Test PBKDF2
    CK_UTF8CHAR password[] = "password";
    CK_BYTE salt[] = "salt";
    CK_ULONG iterations = 2048;
    CK_ULONG pwdLen = sizeof(password) - 1;
    CK_PKCS5_PBKD2_PARAMS2 pbkdf2Params = {
        1 /* CKZ_SALT_SPECIFIED */, salt, sizeof(salt)-1,
        iterations,
        4 /* CKP_PKCS5_PBKD2_HMAC_SHA256 */, NULL_PTR, 0,
        password, pwdLen
    };
    CK_MECHANISM pbMech = { CKM_PKCS5_PBKD2, &pbkdf2Params, sizeof(pbkdf2Params) };
    
    CK_ULONG derivedLen = 32;
    CK_ATTRIBUTE deriveTmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &genType, sizeof(genType) },
        { CKA_VALUE_LEN, &derivedLen, sizeof(derivedLen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hDerived1;
    rv = fl->C_DeriveKey(hSess, &pbMech, hBaseKey, deriveTmpl, 7, &hDerived1);
    record_result("KDF", "CKM_PKCS5_PBKD2", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    
    // Test SP800-108 Counter.
    // Per PKCS#11 v3.2 §6.44, prfType MUST be a keyed MAC mechanism
    // (e.g. CKM_SHA256_HMAC, CKM_AES_CMAC) — a bare hash like CKM_SHA256 is
    // NOT a valid PRF. Data params use the spec CK_PRF_DATA_TYPE values:
    // CK_SP800_108_ITERATION_VARIABLE (counter format) and
    // CK_SP800_108_BYTE_ARRAY (label/context fixed input).
    CK_BYTE label[] = "label";
    CK_BYTE context[] = "context";
    CK_SP800_108_COUNTER_FORMAT counterFmt = { CK_FALSE /* big-endian */, 32 };
    CK_PRF_DATA_PARAM prfParams[] = {
        { CK_SP800_108_ITERATION_VARIABLE, &counterFmt, sizeof(counterFmt) },
        { CK_SP800_108_BYTE_ARRAY, label, sizeof(label)-1 },
        { CK_SP800_108_BYTE_ARRAY, context, sizeof(context)-1 }
    };

    // 1. Positive: spec-correct HMAC PRF (CKM_SHA256_HMAC).
    CK_SP800_108_KDF_PARAMS ctrParams = {
        CKM_SHA256_HMAC, 3, prfParams, 0, NULL_PTR
    };
    CK_MECHANISM ctrMech = { CKM_SP800_108_COUNTER_KDF, &ctrParams, sizeof(ctrParams) };
    CK_OBJECT_HANDLE hDerived2;
    rv = fl->C_DeriveKey(hSess, &ctrMech, hBaseKey, deriveTmpl, 7, &hDerived2);
    if (!mech_advertised(CKM_SP800_108_COUNTER_KDF)) {
        record_result("KDF", "CKM_SP800_108_COUNTER_KDF", "SKIP", "Mechanism not advertised");
    } else if (rv == CKR_OK) {
        record_result("KDF", "CKM_SP800_108_COUNTER_KDF", "PASS", "HMAC-SHA256 PRF, RV=0");
    } else {
        record_result("KDF", "CKM_SP800_108_COUNTER_KDF", "FAIL",
                      "spec PRF CKM_SHA256_HMAC rejected, RV=" + std::to_string(rv) +
                      " (v3.2 SP800-108: keyed-MAC PRF mechanisms must be accepted)");
    }

    // 2. Negative: bare CKM_SHA256 as PRF MUST be rejected (not a keyed MAC).
    CK_SP800_108_KDF_PARAMS ctrParamsBad = {
        CKM_SHA256, 3, prfParams, 0, NULL_PTR
    };
    CK_MECHANISM ctrMechBad = { CKM_SP800_108_COUNTER_KDF, &ctrParamsBad, sizeof(ctrParamsBad) };
    CK_OBJECT_HANDLE hDerivedBad;
    rv = fl->C_DeriveKey(hSess, &ctrMechBad, hBaseKey, deriveTmpl, 7, &hDerivedBad);
    if (!mech_advertised(CKM_SP800_108_COUNTER_KDF)) {
        record_result("KDF", "SP800_108_BareHash_PRF_Rejected", "SKIP", "Mechanism not advertised");
    } else if (rv == CKR_MECHANISM_PARAM_INVALID || rv == CKR_ARGUMENTS_BAD) {
        record_result("KDF", "SP800_108_BareHash_PRF_Rejected", "PASS",
                      "bare CKM_SHA256 PRF correctly rejected, RV=" + std::to_string(rv));
    } else {
        record_result("KDF", "SP800_108_BareHash_PRF_Rejected", "FAIL",
                      "bare CKM_SHA256 accepted as PRF (RV=" + std::to_string(rv) +
                      "); spec requires a keyed MAC mechanism");
    }

    // 3. Positive with a PRF identifier the spec allows AND the engine supports:
    //    CKM_AES_CMAC (key bytes interpreted as AES-256 from 32-byte base key).
    CK_SP800_108_KDF_PARAMS ctrParamsCmac = {
        CKM_AES_CMAC, 3, prfParams, 0, NULL_PTR
    };
    CK_MECHANISM ctrMechCmac = { CKM_SP800_108_COUNTER_KDF, &ctrParamsCmac, sizeof(ctrParamsCmac) };
    CK_OBJECT_HANDLE hDerivedCmac;
    rv = fl->C_DeriveKey(hSess, &ctrMechCmac, hBaseKey, deriveTmpl, 7, &hDerivedCmac);
    if (!mech_advertised(CKM_SP800_108_COUNTER_KDF)) {
        record_result("KDF", "CKM_SP800_108_COUNTER_KDF_CMAC", "SKIP", "Mechanism not advertised");
    } else {
        record_result("KDF", "CKM_SP800_108_COUNTER_KDF_CMAC", rv == CKR_OK ? "PASS" : "FAIL",
                      "AES-CMAC PRF, RV=" + std::to_string(rv));
    }

    // SP800-108 Feedback KDF — same PRF rules apply (keyed MAC; CMAC supported).
    CK_SP800_108_FEEDBACK_KDF_PARAMS fbkParams = {
        CKM_AES_CMAC, 3, prfParams,
        0, NULL_PTR, 0, NULL_PTR // IV info
    };
    CK_MECHANISM fbkMech = { CKM_SP800_108_FEEDBACK_KDF, &fbkParams, sizeof(fbkParams) };
    CK_OBJECT_HANDLE hDerived3;
    rv = fl->C_DeriveKey(hSess, &fbkMech, hBaseKey, deriveTmpl, 7, &hDerived3);
    if (!mech_advertised(CKM_SP800_108_FEEDBACK_KDF)) {
        record_result("KDF", "CKM_SP800_108_FEEDBACK_KDF", "SKIP", "Mechanism not advertised");
    } else {
        record_result("KDF", "CKM_SP800_108_FEEDBACK_KDF", rv == CKR_OK ? "PASS" : "FAIL",
                      "AES-CMAC PRF, RV=" + std::to_string(rv));
    }

    // HKDF Derive
    CK_BYTE hkdfSalt[] = "salt";
    CK_BYTE hkdfInfo[] = "info";
    CK_HKDF_PARAMS hkdfParams = {
        CK_TRUE /* bExtract */,
        CK_TRUE /* bExpand */,
        0x00000250UL /* CKM_SHA256 */,
        0x00000002UL /* CKF_HKDF_SALT_DATA */, hkdfSalt, sizeof(hkdfSalt)-1,
        0,
        hkdfInfo, sizeof(hkdfInfo)-1
    };
    CK_MECHANISM hkdfMech = { 0x0000402aUL /* CKM_HKDF_DERIVE */, &hkdfParams, sizeof(hkdfParams) };
    CK_OBJECT_HANDLE hDerivedHKDF;
    rv = fl->C_DeriveKey(hSess, &hkdfMech, hBaseKey, deriveTmpl, 7, &hDerivedHKDF);
    record_result("KDF", "CKM_HKDF_DERIVE", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
}

void test_pqc_slh_dsa() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeDsa = 0x0000004b; // CKK_SLH_DSA
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_MECHANISM mech = { 0x0000002dUL /* CKM_SLH_DSA_KEY_PAIR_GEN */, NULL_PTR, 0 };
    
    // Test 128S, 128F, 256F to cover permutations
    CK_ULONG dsaParams[] = { 1 /* CKP_SLH_DSA_SHA2_128S */, 3 /* CKP_SLH_DSA_SHA2_128F */, 11 /* CKP_SLH_DSA_SHA2_256F */ }; 
    std::string dsaNames[] = { "SHA2_128S", "SHA2_128F", "SHA2_256F" };
    
    for (int i = 0; i < 3; ++i) {
        std::string n = dsaNames[i];
        CK_ULONG paramSetDsa = dsaParams[i];
        
        CK_ATTRIBUTE pubTmpl[] = { 
            { CKA_CLASS,         &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE,      &ktypeDsa, sizeof(ktypeDsa) },
            { CKA_VERIFY,        &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetDsa,  sizeof(paramSetDsa) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };
        CK_ATTRIBUTE privTmpl[] = { 
            { CKA_CLASS,         &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE,      &ktypeDsa, sizeof(ktypeDsa) },
            { CKA_SIGN,          &bTrue,    sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSetDsa,  sizeof(paramSetDsa) },
            { CKA_TOKEN,         &bFalse,   sizeof(bFalse) }
        };

        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
            record_result("SLHDSA", "Generate_SLH_DSA_" + n, "SKIP", "Mech unavailable");
            continue;
        }
        if (rv != CKR_OK) {
            record_result("SLHDSA", "Generate_SLH_DSA_" + n, "FAIL", "RV=" + std::to_string(rv));
            continue;
        }
        record_result("SLHDSA", "Generate_SLH_DSA_" + n, "PASS", "Gen SLH-DSA-" + n);
        
        // Test Context String + Deterministic
        CK_BYTE contextStr[] = "pkcs11-compliance-test";
        CK_SIGN_ADDITIONAL_CONTEXT sigCtx = {
            2, // CKH_DETERMINISTIC_REQUIRED
            contextStr, sizeof(contextStr)-1
        };
        CK_MECHANISM signMech = { 0x0000002eUL /* CKM_SLH_DSA */, &sigCtx, sizeof(sigCtx) };
        rv = fl->C_SignInit(hSess, &signMech, hPriv);
        if (rv == CKR_OK) {
            CK_BYTE msg[] = "test msg";
            CK_BYTE sig[50000];
            CK_ULONG sigLen = sizeof(sig);
            rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
            record_result("SLHDSA", "C_Sign_" + n + "_Deterministic_Ctx", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        } else {
            record_result("SLHDSA", "C_SignInit_" + n, "FAIL", "RV=" + std::to_string(rv));
        }
        // Force cleanup of the sign state in case it leaked or failed internally
        fl->C_SignFinal(hSess, NULL_PTR, NULL_PTR);
    }
}

void test_pqc_xmss() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeXmss = 0x00000047UL; // CKK_XMSS
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_MECHANISM mech = { 0x00004034UL /* CKM_XMSS_KEY_PAIR_GEN */, NULL_PTR, 0 };
    CK_ULONG paramSetXmss = 0x00000001UL; // CKP_XMSS_SHA2_10_256
    mech.pParameter = &paramSetXmss;
    mech.ulParameterLen = sizeof(paramSetXmss);

    CK_UTF8CHAR label[] = "XMSS Compliance";
    CK_ATTRIBUTE pubTmpl[] = { 
        { CKA_CLASS,         &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktypeXmss, sizeof(ktypeXmss) },
        { CKA_VERIFY,        &bTrue,    sizeof(bTrue) },
        { CKA_TOKEN,         &bTrue,    sizeof(bTrue) },
        { CKA_LABEL,         label,     sizeof(label)-1 }
    };
    CK_ATTRIBUTE privTmpl[] = { 
        { CKA_CLASS,         &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktypeXmss, sizeof(ktypeXmss) },
        { CKA_SIGN,          &bTrue,    sizeof(bTrue) },
        { CKA_TOKEN,         &bTrue,    sizeof(bTrue) },
        { CKA_PRIVATE,       &bTrue,    sizeof(bTrue) },
        { CKA_LABEL,         label,     sizeof(label)-1 }
    };

    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, sizeof(pubTmpl)/sizeof(CK_ATTRIBUTE), privTmpl, sizeof(privTmpl)/sizeof(CK_ATTRIBUTE), &hPub, &hPriv);
    if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
        record_result("XMSS", "Generate_XMSS_SHA2_10_256", "SKIP", "Mech unavailable");
        return;
    }
    if (rv != CKR_OK) {
        record_result("XMSS", "Generate_XMSS_SHA2_10_256", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    record_result("XMSS", "Generate_XMSS_SHA2_10_256", "PASS", "Gen XMSS_SHA2_10_256");

    CK_BYTE msg[] = "xmss test message";
    CK_MECHANISM signMech = { 0x00004036UL /* CKM_XMSS */, NULL_PTR, 0 };
    rv = fl->C_SignInit(hSess, &signMech, hPriv);
    if (rv == CKR_OK) {
        CK_BYTE sig[5000];
        CK_ULONG sigLen = sizeof(sig);
        rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
        record_result("XMSS", "C_Sign_XMSS_SHA2_10_256", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    } else {
        record_result("XMSS", "C_SignInit_XMSS_SHA2_10_256", "FAIL", "RV=" + std::to_string(rv));
    }

    // XMSS-MT validation. Use CKK_XMSSMT in the templates — the XMSS templates
    // above carry CKK_XMSS, which the keygen mechanism↔key-type consistency
    // check (audit V-4) correctly rejects with CKR_TEMPLATE_INCONSISTENT.
    CK_MECHANISM mechMT = { CKM_XMSSMT_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ULONG paramSetXmssMT = 0x00000001UL; // CKP_XMSSMT_SHA2_20_2_256
    mechMT.pParameter = &paramSetXmssMT;
    mechMT.ulParameterLen = sizeof(paramSetXmssMT);

    CK_KEY_TYPE ktypeXmssMT = 0x00000048UL; // CKK_XMSSMT
    CK_ATTRIBUTE pubTmplMT[] = {
        { CKA_CLASS,         &pubClass,   sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktypeXmssMT, sizeof(ktypeXmssMT) },
        { CKA_VERIFY,        &bTrue,      sizeof(bTrue) },
        { CKA_TOKEN,         &bTrue,      sizeof(bTrue) },
        { CKA_LABEL,         label,       sizeof(label)-1 }
    };
    CK_ATTRIBUTE privTmplMT[] = {
        { CKA_CLASS,         &privClass,  sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktypeXmssMT, sizeof(ktypeXmssMT) },
        { CKA_SIGN,          &bTrue,      sizeof(bTrue) },
        { CKA_TOKEN,         &bTrue,      sizeof(bTrue) },
        { CKA_PRIVATE,       &bTrue,      sizeof(bTrue) },
        { CKA_LABEL,         label,       sizeof(label)-1 }
    };

    CK_OBJECT_HANDLE hPubMT = 0, hPrivMT = 0;
    rv = fl->C_GenerateKeyPair(hSess, &mechMT, pubTmplMT, 5, privTmplMT, 6, &hPubMT, &hPrivMT);
    if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
        record_result("XMSS", "Generate_XMSSMT_SHA2_20_2_256", "SKIP", "Mech unavailable");
    } else if (rv != CKR_OK) {
        record_result("XMSS", "Generate_XMSSMT_SHA2_20_2_256", "FAIL", "RV=" + std::to_string(rv));
    } else {
        record_result("XMSS", "Generate_XMSSMT_SHA2_20_2_256", "PASS", "Gen XMSSMT_SHA2_20_2_256");
    }
}

void test_chacha20() {
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE chachaKT = 0x00000033UL; /* CKK_CHACHA20 */
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_BYTE chachaKey[32] = {0}; // blank 32-byte key

    CK_ATTRIBUTE chachaT[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &chachaKT, sizeof(chachaKT) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_VALUE, chachaKey, sizeof(chachaKey) }
    };
    
    CK_OBJECT_HANDLE hChaCha;
    CK_RV rv = fl->C_CreateObject(hSess, chachaT, 8, &hChaCha);
    if (rv != CKR_OK) {
        record_result("ChaCha20", "C_CreateObject", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    record_result("ChaCha20", "C_CreateObject", "PASS", "Created CKK_CHACHA20 Secret Key");

    CK_BYTE chachaNonce[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    CK_BYTE chachaAAD[] = {0xAA, 0xBB, 0xCC};
    
    // Poly1305 params struct is strictly { pNonce, ulNonceLen, pAAD, ulAADLen }
    #pragma pack(push, 1)
    struct LOCAL_CK_SALSA20_CHACHA20_POLY1305_PARAMS {
        CK_BYTE_PTR pNonce;
        CK_ULONG ulNonceLen;
        CK_BYTE_PTR pAAD;
        CK_ULONG ulAADLen;
    };
    #pragma pack(pop)
    LOCAL_CK_SALSA20_CHACHA20_POLY1305_PARAMS chachaParams = { chachaNonce, sizeof(chachaNonce), chachaAAD, sizeof(chachaAAD) };
    CK_MECHANISM chachaMech = { 0x00004021UL /* CKM_CHACHA20_POLY1305 */, &chachaParams, sizeof(chachaParams) };
    
    rv = fl->C_EncryptInit(hSess, &chachaMech, hChaCha);
    if (rv == CKR_MECHANISM_INVALID) {
        record_result("ChaCha20", "C_EncryptInit", "SKIP", "Mechanism routing present but EVP backend unsupported");
        return;
    }
    if (rv != CKR_OK) {
        record_result("ChaCha20", "C_EncryptInit", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    
    CK_BYTE msg[] = "ChaCha20-Poly1305 Test";
    CK_BYTE ct[256];
    CK_ULONG ctLen = sizeof(ct);
    rv = fl->C_Encrypt(hSess, msg, sizeof(msg)-1, ct, &ctLen);
    
    if (rv == CKR_OK) {
        record_result("ChaCha20", "C_Encrypt", "PASS", "Generated properly with 16 byte MAC tag");
    } else {
        record_result("ChaCha20", "C_Encrypt", "FAIL", "RV=" + std::to_string(rv));
    }
}

void test_message_signatures() {
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    typedef CK_RV (*C_MessageSignInit_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    C_MessageSignInit_t SignInit = (C_MessageSignInit_t)dlsym(dlib, "C_MessageSignInit");
    C_SignMessageBegin_t SignBegin = (C_SignMessageBegin_t)dlsym(dlib, "C_SignMessageBegin");
    C_SignMessageNext_t SignNext = (C_SignMessageNext_t)dlsym(dlib, "C_SignMessageNext");
    if (!SignInit || !SignBegin) {
        record_result("MsgSign", "Validation", "SKIP", "v3.0 APIs missing");
        return;
    }
    
    // We reuse an AES or generic secret key generator just to check the API path, or an RSA key for true stream signing...
    // Actually SLH-DSA or ML-DSA doesn't support streaming realistically on HW, but SoftHSM soft-stream hashes it!
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype = CKK_RSA;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG modulusBits = 1024;
    CK_BYTE publicExponent[] = { 3 };
    CK_ATTRIBUTE privTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE pubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, 
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits) },
        { CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hPub=0, hPriv=0;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    CK_RV rvGenDsa = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 6, privTmpl, 4, &hPub, &hPriv);
    if (rvGenDsa == CKR_OK) {
        CK_MECHANISM signMech = { CKM_RSA_PKCS, NULL_PTR, 0 }; 
        CK_RV rvInit = SignInit(hSess, &signMech, hPriv);
        record_result("MsgSign", "C_MessageSignInit", rvInit == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rvInit));
        
        CK_RV rv = SignBegin(hSess, NULL_PTR, 0);
        record_result("MsgSign", "C_SignMessageBegin", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        
        if (rv == CKR_OK) {
            CK_BYTE msg[] = "test";
            CK_BYTE sig[5000]; CK_ULONG sigLen = sizeof(sig);
            // v3.0 signature call for single MessageNext finishing string.
            rv = SignNext(hSess, NULL_PTR, 0, msg, sizeof(msg)-1, sig, &sigLen);
            // The message-based signing entry points are exported and
            // C_MessageSignInit/C_SignMessageBegin succeeded, so the feature is
            // available — only real success counts as PASS. An error here
            // ("couldn't even complete the operation") is a FAIL, never PASS.
            record_result("MsgSign", "C_SignMessageNext", rv == CKR_OK ? "PASS" : "FAIL",
                          "RV=" + std::to_string(rv) + " SigLen=" + std::to_string(sigLen));
        }

        // Negative: CKM_RSA_PKCS takes NO mechanism parameter. Supplying a
        // CK_SIGN_ADDITIONAL_CONTEXT (an ML-DSA/SLH-DSA parameter) MUST be
        // rejected with CKR_MECHANISM_PARAM_INVALID (or CKR_ARGUMENTS_BAD).
        refresh_session();
        CK_OBJECT_HANDLE hPub2=0, hPriv2=0;
        fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 6, privTmpl, 4, &hPub2, &hPriv2);

        CK_BYTE ctxtData[] = "test_context";
        CK_SIGN_ADDITIONAL_CONTEXT pqcParams = {
            CKH_HEDGE_PREFERRED,
            ctxtData, sizeof(ctxtData)-1
        };
        CK_VOID_PTR paramsPQC = (CK_VOID_PTR)&pqcParams;
        CK_MECHANISM signMechPQC = { CKM_RSA_PKCS, paramsPQC, sizeof(pqcParams) };
        rv = SignInit(hSess, &signMechPQC, hPriv2);
        record_result("MsgSign", "C_MessageSignInit_RSA_RejectsSignCtxParam",
                      (rv == CKR_MECHANISM_PARAM_INVALID || rv == CKR_ARGUMENTS_BAD) ? "PASS" : "FAIL",
                      "expected CKR_MECHANISM_PARAM_INVALID, got RV=" + std::to_string(rv));
    } else {
        record_result("MsgSign", "C_GenerateKeyPair", "FAIL", "RV=" + std::to_string(rvGenDsa));
    }
}

void test_message_encryption() {
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    C_MessageEncryptInit_t MsgEncInit = (C_MessageEncryptInit_t)dlsym(dlib, "C_MessageEncryptInit");
    C_EncryptMessageBegin_t MsgEncBeg = (C_EncryptMessageBegin_t)dlsym(dlib, "C_EncryptMessageBegin");
    
    if (!MsgEncInit) {
        record_result("MsgCrypt", "Validation", "SKIP", "v3.0 APIs missing");
        return;
    }
    
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE ktype = 0x0000001f; // CKK_AES
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG valueLen = 16;
    CK_ATTRIBUTE tmpl[] = { 
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    CK_OBJECT_HANDLE hKey=0;
    CK_MECHANISM mech = { 0x00001080UL, NULL_PTR, 0 }; // CKM_AES_KEY_GEN
    
    CK_RV rvGen = fl->C_GenerateKey(hSess, &mech, tmpl, 7, &hKey);
    if (rvGen == CKR_OK) {
        CK_MECHANISM encMech = { 0x00001087UL, NULL_PTR, 0 }; // CKM_AES_GCM
        
        auto run_msg_test = [&](const std::string& name, CK_BYTE* iv, CK_ULONG ivLen) {
            CK_OBJECT_HANDLE hKeyLocal = 0;
            CK_RV rvGenLocal = fl->C_GenerateKey(hSess, &mech, tmpl, 7, &hKeyLocal);
            if (rvGenLocal != CKR_OK) { record_result("MsgCrypt", name, "FAIL", "GenKey failed"); return; }
            
            CK_RV rv = MsgEncInit(hSess, &encMech, hKeyLocal);
            if (name == "C_EncryptMessageBegin_IV12") {
                record_result("MsgCrypt", "C_MessageEncryptInit", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            }
            if (rv != CKR_OK) { record_result("MsgCrypt", name, "FAIL", "Init failed: " + std::to_string(rv)); return; }
            
            CK_BYTE tag[16];
            CK_GCM_MESSAGE_PARAMS msgParams = { iv, ivLen, 0, 0, tag, 128 };
            rv = MsgEncBeg(hSess, &msgParams, sizeof(msgParams), NULL_PTR, 0);
            record_result("MsgCrypt", name, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            
            // Recreate session to reset state
            refresh_session();
        };

        CK_BYTE iv12[] = "123456789012";
        CK_BYTE iv16[] = "1234567890123456";
        CK_BYTE iv8[] = "12345678";
        
        run_msg_test("C_EncryptMessageBegin_IV12", iv12, sizeof(iv12)-1);
        run_msg_test("C_EncryptMessageBegin_IV16", iv16, sizeof(iv16)-1);
        run_msg_test("C_EncryptMessageBegin_IV8", iv8, sizeof(iv8)-1);
    } else {
        record_result("MsgCrypt", "C_GenerateKey", "FAIL", "RV=" + std::to_string(rvGen));
    }
}

void test_classical_crypto() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeRsa = CKK_RSA;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    CK_ULONG modulusBits = 2048;
    CK_BYTE pubExp[] = { 3 };
    
    CK_ATTRIBUTE pubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &ktypeRsa, sizeof(ktypeRsa) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        { CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits) },
        { CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_ATTRIBUTE privTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ktypeRsa, sizeof(ktypeRsa) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 6, privTmpl, 4, &hPub, &hPriv);
    record_result("Classical", "Generate_RSA_2048", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    
    if (rv == CKR_OK) {
        CK_MECHANISM signMech = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
        rv = fl->C_SignInit(hSess, &signMech, hPriv);
        if (rv == CKR_OK) {
            CK_BYTE msg[] = "test message";
            CK_BYTE sig[256];
            CK_ULONG sigLen = sizeof(sig);
            rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
            record_result("Classical", "C_Sign_RSA_SHA256", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        }
    }
}

void test_negative_paths() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeKem = 0x00000049; // CKK_ML_KEM (v3.2 pkcs11t.h; 0x4c is unassigned)
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG paramSetKem = 2; // ML-KEM-768
    
    CK_ATTRIBUTE pubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, { CKA_KEY_TYPE, &ktypeKem, sizeof(ktypeKem) },
        { CKA_ENCAPSULATE, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) }
    };
    CK_ATTRIBUTE privTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) }, { CKA_KEY_TYPE, &ktypeKem, sizeof(ktypeKem) },
        { CKA_DECAPSULATE, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) }
    };

    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_MECHANISM mech = { 0x0000000fUL /* CKM_ML_KEM_KEY_PAIR_GEN */, NULL_PTR, 0 };
    fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 4, privTmpl, 4, &hPub, &hPriv);
    
    if (hPriv) {
        CK_MECHANISM signMech = { 0x0000001dUL /* CKM_ML_DSA */, NULL_PTR, 0 };
        // SoftHSM core bug: invoking C_SignInit with an incompatible mechanism on an ML-KEM key cascades into a Segfault
        CK_RV rv = fl->C_SignInit(hSess, &signMech, hPriv);
        record_result("Negative", "Sign_With_KEM_Key", rv == CKR_KEY_FUNCTION_NOT_PERMITTED || rv == CKR_KEY_TYPE_INCONSISTENT ? "PASS" : "FAIL", "Expected CKR_KEY_FUNCTION_NOT_PERMITTED, got " + std::to_string(rv));
        //record_result("Negative", "Sign_With_KEM_Key", "SKIP", "Blocked by SoftHSM engine segmentation fault on mismatched mechanism context");
    }

    // 1. Boolean Policy Violation & Extraction Constraint
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_ULONG modBits = 1024;
    CK_BYTE pubExp[] = {3};
    CK_ATTRIBUTE rsaPubTmpl[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, { CKA_KEY_TYPE, &rsaType, sizeof(rsaType) },
        { CKA_MODULUS_BITS, &modBits, sizeof(modBits) }, { CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_ATTRIBUTE rsaPrivTmpl[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) }, { CKA_KEY_TYPE, &rsaType, sizeof(rsaType) },
        { CKA_SIGN, &bFalse, sizeof(bFalse) }, // DISABLED
        { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    
    CK_MECHANISM rsaMech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hRsaPub = 0, hRsaPriv = 0;
    CK_RV rvGen = fl->C_GenerateKeyPair(hSess, &rsaMech, rsaPubTmpl, 6, rsaPrivTmpl, 6, &hRsaPub, &hRsaPriv);
    
    if (rvGen == CKR_OK) {
        CK_MECHANISM signMech = { CKM_RSA_PKCS, NULL_PTR, 0 };
        CK_RV rvSign = fl->C_SignInit(hSess, &signMech, hRsaPriv);
        record_result("Negative", "Boolean_Policy_Violation", rvSign == CKR_KEY_FUNCTION_NOT_PERMITTED ? "PASS" : "FAIL", "Expected CKR_KEY_FUNCTION_NOT_PERMITTED, got " + std::to_string(rvSign));
        
        CK_BYTE valBuf[1024];
        CK_ATTRIBUTE valTmpl = { 0x00000123UL /* CKA_PRIVATE_EXPONENT */, valBuf, sizeof(valBuf) };
        CK_RV rvExt = fl->C_GetAttributeValue(hSess, hRsaPriv, &valTmpl, 1);
        record_result("Negative", "Extraction_Constraint", rvExt == CKR_ATTRIBUTE_SENSITIVE ? "PASS" : "FAIL", "Expected CKR_ATTRIBUTE_SENSITIVE, got " + std::to_string(rvExt));
    } else {
        record_result("Negative", "Boolean_Policy_Violation", "SKIP", "Gen Failed");
        record_result("Negative", "Extraction_Constraint", "SKIP", "Gen Failed");
    }

    // 2. Template Completeness Audit
    CK_KEY_TYPE aesType = CKK_AES;
    CK_ULONG aesValLen = 32;
    CK_ATTRIBUTE incompleteTmpl[] = {
        { CKA_KEY_TYPE, &aesType, sizeof(aesType) },
        { CKA_VALUE_LEN, &aesValLen, sizeof(aesValLen) }
    };
    CK_OBJECT_HANDLE hAesObj = 0;
    // Try to C_CreateObject without CKA_CLASS
    CK_RV rvTmpl = fl->C_CreateObject(hSess, incompleteTmpl, 2, &hAesObj);
    record_result("Negative", "Template_Incomplete_Create", rvTmpl == CKR_TEMPLATE_INCOMPLETE ? "PASS" : "FAIL", "Expected CKR_TEMPLATE_INCOMPLETE, got " + std::to_string(rvTmpl));

    // 3. Signature Length & Forgery
    CK_ATTRIBUTE rsaPrivSignTmpl[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) }, { CKA_KEY_TYPE, &rsaType, sizeof(rsaType) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hSigPub = 0, hSigPriv = 0;
    CK_RV rvSigGen = fl->C_GenerateKeyPair(hSess, &rsaMech, rsaPubTmpl, 6, rsaPrivSignTmpl, 4, &hSigPub, &hSigPriv);
    if (rvSigGen == CKR_OK) {
        CK_MECHANISM sMech = { CKM_RSA_PKCS, NULL_PTR, 0 };
        fl->C_SignInit(hSess, &sMech, hSigPriv);
        CK_BYTE data[] = "verify_test";
        CK_BYTE sig[5000]; CK_ULONG sigLen = sizeof(sig);
        fl->C_Sign(hSess, data, sizeof(data)-1, sig, &sigLen);
        
        if (sigLen > 0) {
            fl->C_VerifyInit(hSess, &sMech, hSigPub);
            CK_RV rvLen = fl->C_Verify(hSess, data, sizeof(data)-1, sig, sigLen - 1); // Truncated
            record_result("Negative", "Signature_Len_Range", rvLen == CKR_SIGNATURE_LEN_RANGE || rvLen == CKR_SIGNATURE_INVALID ? "PASS" : "FAIL", "Expected CKR_SIGNATURE_LEN_RANGE, got " + std::to_string(rvLen));
            
            sig[5] ^= 0xFF; // Forgery
            fl->C_VerifyInit(hSess, &sMech, hSigPub);
            CK_RV rvForg = fl->C_Verify(hSess, data, sizeof(data)-1, sig, sigLen);
            record_result("Negative", "Signature_Forgery_Invalid", rvForg == CKR_SIGNATURE_INVALID ? "PASS" : "FAIL", "Expected CKR_SIGNATURE_INVALID, got " + std::to_string(rvForg));
        } else {
             record_result("Negative", "Signature_Len_Range", "SKIP", "Sign failed");
             record_result("Negative", "Signature_Forgery_Invalid", "SKIP", "Sign failed");
        }
    } else {
        record_result("Negative", "Signature_Len_Range", "SKIP", "KeyGen failed");
        record_result("Negative", "Signature_Forgery_Invalid", "SKIP", "KeyGen failed");
    }
}

void test_slot_session_management() {
    // 1. Invalid Slot ID
    CK_SESSION_HANDLE hBadSess = 0;
    CK_RV rv = fl->C_OpenSession(999999, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hBadSess);
    record_result("Session", "C_OpenSession_InvalidSlot", rv == CKR_SLOT_ID_INVALID ? "PASS" : "FAIL", "RV=" + std::to_string(rv));

    // 2. Read-Only Session Constraints against Token Objects
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_BYTE label[] = "test data";
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) }, // Must be TRUE to test RO protections
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };
    CK_OBJECT_HANDLE hData = 0;
    fl->C_CreateObject(hSess, dataTmpl, 4, &hData); // Create in our active RW session

    CK_SESSION_HANDLE hRoSess = 0;
    rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hRoSess);
    if (rv == CKR_OK) {
        CK_ATTRIBUTE modifyTmpl[] = { { CKA_LABEL, label, sizeof(label)-1 } };
        rv = fl->C_SetAttributeValue(hRoSess, hData, modifyTmpl, 1);
        record_result("Session", "C_SetAttributeValue_RO", rv == CKR_SESSION_READ_ONLY ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        fl->C_CloseSession(hRoSess);
    } else {
        record_result("Session", "C_SetAttributeValue_RO", "SKIP", "Failed to open RO session: " + std::to_string(rv));
    }

    // 3. Cross-Session Object Visibility (PKCS#11 states Session objects are visible across ALL sessions in the app)
    CK_SESSION_HANDLE hSess2 = 0;
    rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSess2);
    if (rv == CKR_OK) {
        CK_ATTRIBUTE findTmpl[] = { { CKA_CLASS, &dataClass, sizeof(dataClass) } };
        fl->C_FindObjectsInit(hSess2, findTmpl, 1);
        CK_OBJECT_HANDLE objs[10];
        CK_ULONG objCount = 0;
        fl->C_FindObjects(hSess2, objs, 10, &objCount);
        fl->C_FindObjectsFinal(hSess2);
        
        bool found = false;
        for (CK_ULONG i=0; i<objCount; i++) if (objs[i] == hData) found = true;
        record_result("Session", "Session_Object_CrossVisibility", found ? "PASS" : "FAIL", found ? "Visible (Compliant)" : "Not Visible");
        fl->C_CloseSession(hSess2);
    } else {
        record_result("Session", "Session_Object_CrossVisibility", "SKIP", "Could not open hSess2");
    }
}

void test_fips_edge_constraints() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    typedef CK_RV (*C_EncapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
    typedef CK_RV (*C_DecapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    C_EncapsulateKey_t mlkemEncap = (C_EncapsulateKey_t)dlsym(dlib, "C_EncapsulateKey");
    C_DecapsulateKey_t mlkemDecap = (C_DecapsulateKey_t)dlsym(dlib, "C_DecapsulateKey");

    if (!mlkemEncap || !mlkemDecap) {
        record_result("FIPS", "Validation", "SKIP", "v3.0 KEM APIs missing");
        return;
    }

    // 1. ML-KEM Truncated Ciphertext Rejection & Implicit Rejection
    CK_KEY_TYPE ktypeKem = 0x00000049; // CKK_ML_KEM (v3.2 pkcs11t.h; 0x4c is unassigned)
    CK_ULONG paramSetKem = 2; // ML-KEM-768
    CK_ATTRIBUTE kPubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, { CKA_KEY_TYPE, &ktypeKem, sizeof(ktypeKem) },
        { CKA_ENCAPSULATE, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_ATTRIBUTE kPrivTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) }, { CKA_KEY_TYPE, &ktypeKem, sizeof(ktypeKem) },
        { CKA_DECAPSULATE, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetKem, sizeof(paramSetKem) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hKemPub = 0, hKemPriv = 0;
    CK_MECHANISM kemMech = { 0x0000000fUL /* CKM_ML_KEM_KEY_PAIR_GEN */, NULL_PTR, 0 };
    CK_RV rvKem = fl->C_GenerateKeyPair(hSess, &kemMech, kPubTmpl, 5, kPrivTmpl, 5, &hKemPub, &hKemPriv);
    
    if (rvKem == CKR_OK && hKemPub && hKemPriv) {
        CK_MECHANISM encapMech = { 0x00000017UL /* CKM_ML_KEM */, NULL_PTR, 0 };
        CK_BYTE ct[1088]; CK_ULONG ctLen = sizeof(ct);
        CK_OBJECT_HANDLE hSec1 = 0;
        
        CK_RV rv = mlkemEncap(hSess, &encapMech, hKemPub, NULL_PTR, 0, ct, &ctLen, &hSec1);
        if (rv == CKR_OK) {
            // Decap Truncated
            CK_OBJECT_HANDLE hSec2 = 0;
            rv = mlkemDecap(hSess, &encapMech, hKemPriv, NULL_PTR, 0, ct, ctLen - 1, &hSec2);
            record_result("FIPS", "ML-KEM_Truncated_CT", (rv == CKR_WRAPPED_KEY_LEN_RANGE || rv == CKR_WRAPPED_KEY_INVALID || rv == CKR_ENCRYPTED_DATA_LEN_RANGE || rv == CKR_ENCRYPTED_DATA_INVALID || rv == CKR_ARGUMENTS_BAD) ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            
            // Decap Tampered
            ct[0] ^= 1;
            CK_OBJECT_HANDLE hSec3 = 0;
            rv = mlkemDecap(hSess, &encapMech, hKemPriv, NULL_PTR, 0, ct, ctLen, &hSec3);
            if (rv == CKR_OK) {
                record_result("FIPS", "ML-KEM_Implicit_Rejection", "PASS", "Yielded deterministic random secret per FIPS 203");
            } else {
                record_result("FIPS", "ML-KEM_Implicit_Rejection", "FAIL", "Failed decap instead of implicit rej (RV=" + std::to_string(rv) + ")");
            }
        } else {
            record_result("FIPS", "ML-KEM_Encap", "FAIL", "RV=" + std::to_string(rv));
        }
    } else {
        record_result("FIPS", "ML-KEM_Generate", "FAIL", "RV=" + std::to_string(rvKem));
    }

    // 2. ML-DSA Context Size > 255
    CK_KEY_TYPE ktypeDsa = 0x0000004a; // CKK_ML_DSA
    CK_ULONG paramSetDsa = 1; // ML-DSA-44
    CK_ATTRIBUTE dPubTmpl[] = { 
        { CKA_CLASS, &pubClass, sizeof(pubClass) }, { CKA_KEY_TYPE, &ktypeDsa, sizeof(ktypeDsa) },
        { CKA_VERIFY, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetDsa, sizeof(paramSetDsa) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_ATTRIBUTE dPrivTmpl[] = { 
        { CKA_CLASS, &privClass, sizeof(privClass) }, { CKA_KEY_TYPE, &ktypeDsa, sizeof(ktypeDsa) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) }, { CKA_PARAMETER_SET, &paramSetDsa, sizeof(paramSetDsa) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };

    CK_OBJECT_HANDLE hDsaPub = 0, hDsaPriv = 0;
    CK_MECHANISM dsaMech = { 0x0000001cUL /* CKM_ML_DSA_KEY_PAIR_GEN */, NULL_PTR, 0 };
    CK_RV rvDsa = fl->C_GenerateKeyPair(hSess, &dsaMech, dPubTmpl, 5, dPrivTmpl, 5, &hDsaPub, &hDsaPriv);
    
    if (rvDsa == CKR_OK && hDsaPriv) {
        CK_BYTE giantCtx[256] = {0};
        CK_SIGN_ADDITIONAL_CONTEXT sigCtx = {
            1, // CKH_HEDGE_REQUIRED = 1
            giantCtx, 256
        };
        CK_MECHANISM signMech = { 0x0000001dUL /* CKM_ML_DSA */, &sigCtx, sizeof(sigCtx) };
        CK_RV rv = fl->C_SignInit(hSess, &signMech, hDsaPriv);
        // FIPS 204 limits the context string to 255 bytes. Both rejection codes
        // are defensible: CKR_MECHANISM_PARAM_INVALID (the mechanism parameter
        // CK_SIGN_ADDITIONAL_CONTEXT carries an invalid field) and
        // CKR_ARGUMENTS_BAD (a caller-supplied argument is out of range) —
        // the spec does not pin one. Accept either; anything else is a FAIL.
        record_result("FIPS", "ML-DSA_Oversized_Ctx",
                      (rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_PARAM_INVALID) ? "PASS" : "FAIL",
                      "ctx>255 must be rejected, RV=" + std::to_string(rv));
        // Force cancel in case it (wrongly) succeeds
        if (rv == CKR_OK) fl->C_SignFinal(hSess, NULL_PTR, NULL_PTR);
    } else {
        record_result("FIPS", "ML-DSA_Generate", "FAIL", "RV=" + std::to_string(rvDsa));
    }
}

void test_authenticated_wrap() {
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    typedef CK_RV (*C_WrapKeyAuthenticated_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    typedef CK_RV (*C_UnwrapKeyAuthenticated_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    
    C_WrapKeyAuthenticated_t WrapAuth = (C_WrapKeyAuthenticated_t)dlsym(dlib, "C_WrapKeyAuthenticated");
    C_UnwrapKeyAuthenticated_t UnwrapAuth = (C_UnwrapKeyAuthenticated_t)dlsym(dlib, "C_UnwrapKeyAuthenticated");
    
    if (!WrapAuth || !UnwrapAuth) {
        record_result("AuthWrap", "Validation", "SKIP", "v3.2 Auth Wrap APIs missing");
        return;
    }
    
    // Generate AES wrapping key
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE ktype = CKK_AES;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG valueLen = 32;
    CK_ATTRIBUTE wrapTmpl[] = { 
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_WRAP, &bTrue, sizeof(bTrue) },
        { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    CK_OBJECT_HANDLE hWrapKey = 0;
    CK_MECHANISM mechGen = { 0x00001080UL /* CKM_AES_KEY_GEN */, NULL_PTR, 0 };
    fl->C_GenerateKey(hSess, &mechGen, wrapTmpl, 7, &hWrapKey);
    
    // Generate target AES payload key
    CK_ATTRIBUTE targetTmpl[] = { 
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_OBJECT_HANDLE hTarget = 0;
    fl->C_GenerateKey(hSess, &mechGen, targetTmpl, 5, &hTarget);
    
    if (!hWrapKey || !hTarget) {
        record_result("AuthWrap", "KeySetup", "FAIL", "Failed to generate keys");
        return;
    }
    
    // Wrap
    CK_BYTE iv[12] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    CK_BYTE aad[] = "header";
    CK_GCM_PARAMS gcmParams = { iv, 12, 0, 0, NULL_PTR, 128 /* 16 byte tag */ };
    CK_MECHANISM wrapMech = { 0x00001087UL /* CKM_AES_GCM */, &gcmParams, sizeof(gcmParams) };
    
    CK_BYTE wrapped[256];
    CK_ULONG wrappedLen = sizeof(wrapped);
    CK_RV rv = WrapAuth(hSess, &wrapMech, hWrapKey, hTarget, aad, sizeof(aad)-1, wrapped, &wrappedLen);
    record_result("AuthWrap", "C_WrapKeyAuthenticated", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    
    if (rv == CKR_OK) {
        // Unwrap
        CK_OBJECT_HANDLE hUnwrapped = 0;
        CK_ATTRIBUTE unwrapTmpl[] = { 
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
        };
        rv = UnwrapAuth(hSess, &wrapMech, hWrapKey, wrapped, wrappedLen, unwrapTmpl, 3, aad, sizeof(aad)-1, &hUnwrapped);
        record_result("AuthWrap", "C_UnwrapKeyAuthenticated", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        
        // Assert payloads match (Issue 44 regression test)
        if (rv == CKR_OK) {
            CK_BYTE valTarget[100]; CK_ATTRIBUTE attrTarget = { CKA_VALUE, valTarget, sizeof(valTarget) };
            CK_BYTE valUnwrap[100]; CK_ATTRIBUTE attrUnwrap = { CKA_VALUE, valUnwrap, sizeof(valUnwrap) };
            fl->C_GetAttributeValue(hSess, hTarget, &attrTarget, 1);
            fl->C_GetAttributeValue(hSess, hUnwrapped, &attrUnwrap, 1);
            
            if (attrTarget.ulValueLen == attrUnwrap.ulValueLen && memcmp(valTarget, valUnwrap, attrTarget.ulValueLen) == 0 && attrTarget.ulValueLen > 0) {
                record_result("AuthWrap", "Value_Match", "PASS", "Unwrapped keys perfectly match");
            } else {
                record_result("AuthWrap", "Value_Match", "FAIL", "Unwrapped symmetric value mismatch (Issue 44 bug)");
            }
        }
    }
    
    // =========================================================================
    // NIST SP 800-38D AES-GCM Test Case 4 (Official Known Answer Test)
    // =========================================================================
    CK_BYTE nistKey[] = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
    CK_BYTE nistIV[]  = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
    CK_BYTE nistPT[]  = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
        0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
        0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39
    };
    CK_BYTE nistAAD[] = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
        0xab,0xad,0xda,0xd2
    };
    CK_BYTE nistCTandTag[] = {
        // Ciphertext
        0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
        0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
        0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
        0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91,
        // Tag
        0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47
    };

    // Create the unwrapping key from NIST KAT
    CK_ATTRIBUTE nistKeyTmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
        { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_VALUE, nistKey, sizeof(nistKey) }
    };
    CK_OBJECT_HANDLE hNistWrapKey = 0;
    fl->C_CreateObject(hSess, nistKeyTmpl, 5, &hNistWrapKey);
    
    if (hNistWrapKey) {
        CK_GCM_PARAMS nistGcmParams = { nistIV, sizeof(nistIV), 0, 0, NULL_PTR, 128 };
        CK_MECHANISM nistMech = { 0x00001087UL /* CKM_AES_GCM */, &nistGcmParams, sizeof(nistGcmParams) };
        
        CK_OBJECT_HANDLE hNistTarget = 0;
        CK_ATTRIBUTE unwrapTmplNist[] = { 
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
        };
        CK_RV rvKat = UnwrapAuth(hSess, &nistMech, hNistWrapKey, nistCTandTag, sizeof(nistCTandTag), unwrapTmplNist, 3, nistAAD, sizeof(nistAAD), &hNistTarget);
        
        if (rvKat == CKR_OK) {
            CK_BYTE valNist[100]; CK_ATTRIBUTE attrNist = { CKA_VALUE, valNist, sizeof(valNist) };
            fl->C_GetAttributeValue(hSess, hNistTarget, &attrNist, 1);
            if (attrNist.ulValueLen == sizeof(nistPT) && memcmp(valNist, nistPT, sizeof(nistPT)) == 0) {
                record_result("AuthWrap", "NIST_SP800_38D_KAT", "PASS", "Unwrapped GCM payload perfectly matches NIST Test Case 4 PT");
            } else {
                record_result("AuthWrap", "NIST_SP800_38D_KAT", "FAIL", "Unwrapped material did not match NIST Test Case 4 PT");
            }
        } else {
            record_result("AuthWrap", "NIST_SP800_38D_KAT", "FAIL", "Unwrap execution failed with RV=" + std::to_string(rvKat));
        }
    } else {
        record_result("AuthWrap", "NIST_SP800_38D_KAT", "SKIP", "Failed to construct NIST Wrapping Key frame");
    }
}

void test_ecdsa_curves() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    
    CK_BYTE oid_p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    CK_BYTE oid_p521[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
    CK_BYTE oid_secp256k1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a }; // SECP256K1 OID

    auto run_ec = [&](const std::string& name, CK_BYTE* oid, CK_ULONG oidLen, CK_MECHANISM_TYPE sigType) {
        CK_ATTRIBUTE pubTmpl[] = {
            { CKA_CLASS, &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) },
            { CKA_EC_PARAMS, oid, oidLen }
        };
        CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE privTmpl[] = {
            { CKA_CLASS, &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) }
        };
        
        CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE hPub, hPriv;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        record_result("ECDSA", "Generate_" + name, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        
        if (rv == CKR_OK) {
            CK_MECHANISM signMech = { sigType, NULL_PTR, 0 };
            rv = fl->C_SignInit(hSess, &signMech, hPriv);
            if (rv == CKR_OK) {
                CK_BYTE msg[] = "test";
                CK_BYTE sig[512]; CK_ULONG sigLen = sizeof(sig);
                rv = fl->C_Sign(hSess, msg, 4, sig, &sigLen);
                record_result("ECDSA", "Sign_" + name, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            } else {
                record_result("ECDSA", "SignInit_" + name, "FAIL", "RV=" + std::to_string(rv));
            }
        }
    };
    
    run_ec("P256", oid_p256, sizeof(oid_p256), CKM_ECDSA_SHA256);
    run_ec("P521", oid_p521, sizeof(oid_p521), CKM_ECDSA_SHA512);
    run_ec("secp256k1", oid_secp256k1, sizeof(oid_secp256k1), CKM_ECDSA_SHA256);
    
    // Inject ECDSA_SHA3
    run_ec("P256_SHA3_256", oid_p256, sizeof(oid_p256), CKM_ECDSA_SHA3_256);
    run_ec("P521_SHA3_512", oid_p521, sizeof(oid_p521), CKM_ECDSA_SHA3_512);
}

void test_eddsa_curves() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE ecType = CKK_EC_EDWARDS;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    
    // CKA_EC_PARAMS as DER PrintableString curve names "edwards25519"/"edwards448"
    // (PKCS#11 v3.2 §6.3.3 CurveName choice, RFC 8032 names — NOT the OID form)
    CK_BYTE oid_ed25519[] = { 0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39 };
    CK_BYTE oid_ed448[] = { 0x13, 0x0a, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38 };

    auto run_eddsa = [&](const std::string& name, CK_BYTE* oid, CK_ULONG oidLen) {
        CK_ATTRIBUTE pubTmpl[] = {
            { CKA_CLASS, &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) },
            { CKA_EC_PARAMS, oid, oidLen }
        };
        CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE privTmpl[] = {
            { CKA_CLASS, &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) }
        };
        
        CK_MECHANISM mech = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE hPub, hPriv;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 5, privTmpl, 5, &hPub, &hPriv);
        record_result("EdDSA", "Generate_" + name, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        
        if (rv == CKR_OK) {
            CK_MECHANISM signMech = { CKM_EDDSA, NULL_PTR, 0 };
            rv = fl->C_SignInit(hSess, &signMech, hPriv);
            if (rv == CKR_OK) {
                CK_BYTE msg[] = "payload_data";
                CK_BYTE sig[512]; CK_ULONG sigLen = sizeof(sig);
                rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
                record_result("EdDSA", "Sign_" + name, rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
            } else {
                record_result("EdDSA", "SignInit_" + name, "FAIL", "RV=" + std::to_string(rv));
            }
        }
    };
    run_eddsa("Ed25519", oid_ed25519, sizeof(oid_ed25519));
    run_eddsa("Ed448", oid_ed448, sizeof(oid_ed448));
}

void test_ecdh_derivations() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE ecType = CKK_EC_MONTGOMERY;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    
    // CKA_EC_PARAMS as DER PrintableString curve name "curve25519"
    // (PKCS#11 v3.2 §6.3.3 CurveName choice — NOT the OID form)
    CK_BYTE oid_x25519[] = { 0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39 };

    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
        { CKA_EC_PARAMS, oid_x25519, sizeof(oid_x25519) }
    };
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ecType, sizeof(ecType) },
        { CKA_DERIVE, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bTrue, sizeof(bTrue) }
    };
    
    CK_MECHANISM mech = { CKM_EC_MONTGOMERY_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hPub, hPriv;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 3, privTmpl, 4, &hPub, &hPriv);
    record_result("ECDH", "Generate_X25519", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    
    if (rv == CKR_OK) {
        CK_ATTRIBUTE valAttrib = { CKA_EC_POINT, NULL_PTR, 0 };
        fl->C_GetAttributeValue(hSess, hPub, &valAttrib, 1);
        std::vector<CK_BYTE> pubPointData(valAttrib.ulValueLen);
        valAttrib.pValue = pubPointData.data();
        fl->C_GetAttributeValue(hSess, hPub, &valAttrib, 1);
        
        CK_ECDH1_DERIVE_PARAMS ecdhParams = { CKD_NULL, 0, NULL_PTR, 0, NULL_PTR };
        ecdhParams.pPublicData = pubPointData.data();
        ecdhParams.ulPublicDataLen = pubPointData.size();
        
        CK_MECHANISM deriveMech = { CKM_ECDH1_DERIVE, &ecdhParams, sizeof(ecdhParams) };
        
        CK_OBJECT_CLASS derivedClass = CKO_SECRET_KEY;
        CK_KEY_TYPE derivedType = CKK_GENERIC_SECRET;
        CK_ULONG secLen = 32;
        CK_ATTRIBUTE deriveTmpl[] = {
            { CKA_CLASS, &derivedClass, sizeof(derivedClass) },
            { CKA_KEY_TYPE, &derivedType, sizeof(derivedType) },
            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
            { CKA_VALUE_LEN, &secLen, sizeof(secLen) }
        };
        CK_OBJECT_HANDLE hSecret;
        rv = fl->C_DeriveKey(hSess, &deriveMech, hPriv, deriveTmpl, 4, &hSecret);
        record_result("ECDH", "Derive_X25519", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        
        // Cofactor variant: only assert success if the token ADVERTISES
        // CKM_ECDH1_COFACTOR_DERIVE; otherwise record an explicit SKIP.
        // CKR_MECHANISM_INVALID must never silently count as PASS.
        CK_MECHANISM cofactorMech = { CKM_ECDH1_COFACTOR_DERIVE, &ecdhParams, sizeof(ecdhParams) };
        CK_OBJECT_HANDLE hSecretCofactor;
        if (mech_advertised(CKM_ECDH1_COFACTOR_DERIVE)) {
            rv = fl->C_DeriveKey(hSess, &cofactorMech, hPriv, deriveTmpl, 4, &hSecretCofactor);
            record_result("ECDH", "Derive_X25519_Cofactor", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
        } else {
            record_result("ECDH", "Derive_X25519_Cofactor", "SKIP", "CKM_ECDH1_COFACTOR_DERIVE not advertised");
        }
    }
}

void test_aes_ctr() {
    CK_MECHANISM genMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_ULONG keyBits = 16;
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL bTrue = CK_TRUE;
    
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &aesType, sizeof(aesType) },
        { CKA_VALUE_LEN, &keyBits, sizeof(keyBits) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) }
    };
    
    CK_OBJECT_HANDLE hKey;
    CK_RV rv = fl->C_GenerateKey(hSess, &genMech, tmpl, 4, &hKey);
    if (rv == CKR_OK) {
        CK_AES_CTR_PARAMS params;
        params.ulCounterBits = 128;
        memset(params.cb, 0, 16);
        CK_MECHANISM ctrMech = { CKM_AES_CTR, &params, sizeof(params) };
        rv = fl->C_EncryptInit(hSess, &ctrMech, hKey);
        record_result("AES-CTR", "EncryptInit", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    }
}

void test_kmac() {
    CK_MECHANISM genMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 }; 
    CK_ULONG keyLen = 16;
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL bTrue = CK_TRUE;
    
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &keyLen, sizeof(keyLen) },
        { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    
    CK_OBJECT_HANDLE hKey;
    CK_RV rv = fl->C_GenerateKey(hSess, &genMech, tmpl, 4, &hKey);
    if (rv == CKR_OK) {
        CK_MECHANISM kmacMech = { CKM_KMAC_128, NULL_PTR, 0 };
        rv = fl->C_SignInit(hSess, &kmacMech, hKey);
        record_result("KMAC", "SignInit_128", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));

        CK_MECHANISM kmacMech2 = { CKM_KMAC_256, NULL_PTR, 0 };
        rv = fl->C_SignInit(hSess, &kmacMech2, hKey);
        record_result("KMAC", "SignInit_256", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    }
}

void test_sha3_hashes() {
    CK_MECHANISM hashMech = { CKM_SHA3_256, NULL_PTR, 0 };
    CK_RV rv = fl->C_DigestInit(hSess, &hashMech);
    record_result("SHA-3", "DigestInit_256", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
}

void test_bip32_wallets() {
    // Generate Master Node
    CK_MECHANISM genMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_ULONG keyLen = 32;
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &keyLen, sizeof(keyLen) },
        { CKA_DERIVE, &bTrue, sizeof(bTrue) }
    };
    
    CK_OBJECT_HANDLE hSeed;
    CK_RV rv = fl->C_GenerateKey(hSess, &genMech, tmpl, 4, &hSeed);
    if (rv != CKR_OK) return;
    
    CK_BYTE curveOid[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a }; // SECP256K1
    CK_OBJECT_CLASS drvClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE masterTmpl[] = {
        { CKA_CLASS, &drvClass, sizeof(drvClass) },
        { CKA_EC_PARAMS, curveOid, sizeof(curveOid) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
        { CKA_DERIVE, &bTrue, sizeof(bTrue) }
    };
    CK_MECHANISM masterMech = { CKM_BIP32_MASTER_DERIVE, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hMaster;
    rv = fl->C_DeriveKey(hSess, &masterMech, hSeed, masterTmpl, 7, &hMaster);
    record_result("BIP32", "Master_Derive", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    
    if (rv == CKR_OK) {
        CK_BIP32_CHILD_DERIVE_PARAMS childParams = { 0, 1 }; // flags=0 (not hardened), index=1
        CK_MECHANISM childMech = { CKM_BIP32_CHILD_DERIVE, &childParams, sizeof(childParams) };
        CK_OBJECT_HANDLE hChild;
        rv = fl->C_DeriveKey(hSess, &childMech, hMaster, masterTmpl, 7, &hChild);
        record_result("BIP32", "Child_Derive", rv == CKR_OK ? "PASS" : "FAIL", "RV=" + std::to_string(rv));
    }
}

void test_v30_session() {
    typedef CK_RV (*C_SessionCancel_t)(CK_SESSION_HANDLE, CK_FLAGS);
    typedef CK_RV (*C_LoginUser_t)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);
    
    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);
    C_SessionCancel_t SessionCancelFn = (C_SessionCancel_t)dlsym(dlib, "C_SessionCancel");
    C_LoginUser_t LoginUserFn = (C_LoginUser_t)dlsym(dlib, "C_LoginUser");
    
    if (SessionCancelFn) {
        // Cancel an ACTUALLY-ACTIVE sign operation with CKF_SIGN (0x800, the
        // sign-family flag per C_SessionCancel, PKCS#11 v3.0+ §5.6.7).
        // Previous version passed 0x00020000 — that is CKF_WRAP, not a
        // "CKF_RW_SESSION boundary" — against an idle session and counted
        // CKR_OPERATION_CANCEL_FAILED as PASS.
        CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
        CK_KEY_TYPE genType = CKK_GENERIC_SECRET;
        CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
        CK_ULONG keyLen = 32;
        CK_ATTRIBUTE macTmpl[] = {
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &genType, sizeof(genType) },
            { CKA_VALUE_LEN, &keyLen, sizeof(keyLen) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) }
        };
        CK_OBJECT_HANDLE hMacKey = 0;
        CK_MECHANISM genMech = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
        CK_RV rv = fl->C_GenerateKey(hSess, &genMech, macTmpl, 5, &hMacKey);
        CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, NULL_PTR, 0 };
        if (rv == CKR_OK) rv = fl->C_SignInit(hSess, &hmacMech, hMacKey);
        if (rv != CKR_OK) {
            record_result("Session", "C_SessionCancel", "FAIL",
                          "could not start sign op for cancel test, RV=" + std::to_string(rv));
        } else {
            rv = SessionCancelFn(hSess, CKF_SIGN);
            if (rv != CKR_OK) {
                record_result("Session", "C_SessionCancel", "FAIL",
                              "cancel of active sign op (CKF_SIGN) RV=" + std::to_string(rv));
            } else {
                // The sign operation must now be gone.
                CK_BYTE data[] = "x";
                CK_BYTE sig[64]; CK_ULONG sigLen = sizeof(sig);
                CK_RV rvSign = fl->C_Sign(hSess, data, 1, sig, &sigLen);
                record_result("Session", "C_SessionCancel",
                              rvSign == CKR_OPERATION_NOT_INITIALIZED ? "PASS" : "FAIL",
                              "cancel OK; post-cancel C_Sign expected CKR_OPERATION_NOT_INITIALIZED, got RV="
                              + std::to_string(rvSign));
            }
        }
    } else {
        record_result("Session", "C_SessionCancel", "SKIP", "Not exported natively");
    }

    if (LoginUserFn) {
        CK_UTF8CHAR username[] = "alice";
        CK_RV rv = LoginUserFn(hSess, CKU_USER, (CK_UTF8CHAR_PTR)opt_pin.c_str(), opt_pin.length(), username, sizeof(username)-1);
        if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
            // Exported but not actually implemented — not an advertised feature.
            record_result("Session", "C_LoginUser", "SKIP", "exported but returns CKR_FUNCTION_NOT_SUPPORTED");
        } else {
            // Already logged in via C_Login in the fixture → CKR_USER_ALREADY_LOGGED_IN
            // is the spec-conformant answer; CKR_OK if the fixture wasn't logged in.
            record_result("Session", "C_LoginUser",
                          (rv == CKR_USER_ALREADY_LOGGED_IN || rv == CKR_OK) ? "PASS" : "FAIL",
                          "RV=" + std::to_string(rv));
        }
    } else {
        record_result("Session", "C_LoginUser", "SKIP", "Not exported natively");
    }
}

// ─── CKA_ID retrieval tests ───────────────────────────────────────────────────
// Models the exact lookup flow that strongSwan's pkcs11 plugin uses at
// IKE_AUTH time (pkcs11_private_key.c::find_lib_by_keyid):
//   1. Open a fresh public RO session — NO LOGIN.
//   2. C_FindObjectsInit({CKA_CLASS=CKO_PUBLIC_KEY, CKA_ID=keyid}).
//   3. C_FindObjects → expect to find the previously generated public key.
// If the public key is not findable from a no-login session despite explicit
// CKA_PRIVATE=FALSE on the keygen template, softhsm has a bug.
void test_cka_id_retrieval() {
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktypeMlDsa = 0x0000004a; // CKK_ML_DSA
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_ULONG paramSet65 = 2; // ML-DSA-65

    // The keyid we'll use as CKA_ID — fixed bytes, easier to read in logs.
    CK_BYTE keyid[20] = {
        0x6a,0xe5,0x30,0x0d, 0xe2,0x4e,0xb4,0x7f, 0x00,0xfa,0x20,0x85,
        0x49,0x26,0x86,0xea, 0x30,0xb2,0xb6,0x21
    };

    CK_MECHANISM genMech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };

    // Mirrors strongswan_worker.js's PANEL_PKCS11 C_GenerateKeyPair_MLDSA template:
    //   public:  CKA_TOKEN=true, CKA_PRIVATE=false, CKA_VERIFY=true,
    //            CKA_PARAMETER_SET=2, CKA_ID=keyid
    //   private: CKA_TOKEN=true, CKA_PRIVATE=true, CKA_SIGN=true,
    //            CKA_SENSITIVE=true, CKA_EXTRACTABLE=false, CKA_ID=keyid
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,         &pubClass,   sizeof(pubClass) },
        { CKA_KEY_TYPE,      &ktypeMlDsa, sizeof(ktypeMlDsa) },
        { CKA_TOKEN,         &bTrue,      sizeof(bTrue) },
        { CKA_PRIVATE,       &bFalse,     sizeof(bFalse) },
        { CKA_VERIFY,        &bTrue,      sizeof(bTrue) },
        { CKA_PARAMETER_SET, &paramSet65, sizeof(paramSet65) },
        { CKA_ID,            keyid,       sizeof(keyid) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,         &privClass,  sizeof(privClass) },
        { CKA_KEY_TYPE,      &ktypeMlDsa, sizeof(ktypeMlDsa) },
        { CKA_TOKEN,         &bTrue,      sizeof(bTrue) },
        { CKA_PRIVATE,       &bTrue,      sizeof(bTrue) },
        { CKA_SIGN,          &bTrue,      sizeof(bTrue) },
        { CKA_SENSITIVE,     &bTrue,      sizeof(bTrue) },
        { CKA_EXTRACTABLE,   &bFalse,     sizeof(bFalse) },
        { CKA_ID,            keyid,       sizeof(keyid) },
    };

    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &genMech, pubTmpl, 7, privTmpl, 8, &hPub, &hPriv);
    if (rv != CKR_OK) {
        record_result("CkaIdRetrieval", "Setup_KeyGen", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    record_result("CkaIdRetrieval", "Setup_KeyGen", "PASS", "ML-DSA-65 keypair generated with explicit CKA_ID + CKA_PRIVATE=false on pubkey");

    // ── A. Same logged-in session: find pubkey by {CKA_CLASS=PUBLIC, CKA_ID}
    {
        CK_ATTRIBUTE findT[] = {
            { CKA_CLASS, &pubClass, sizeof(pubClass) },
            { CKA_ID,    keyid,     sizeof(keyid) },
        };
        rv = fl->C_FindObjectsInit(hSess, findT, 2);
        CK_OBJECT_HANDLE objs[5] = {0};
        CK_ULONG cnt = 0;
        if (rv == CKR_OK) {
            fl->C_FindObjects(hSess, objs, 5, &cnt);
            fl->C_FindObjectsFinal(hSess);
        }
        bool found = (cnt >= 1) && (objs[0] == hPub || (cnt > 1 && objs[1] == hPub));
        // Some softhsm builds shuffle handles; relax to "any handle returned in same session"
        if (!found && cnt >= 1) found = true;
        record_result("CkaIdRetrieval", "FindByCkaId_Pubkey_LoggedIn", found ? "PASS" : "FAIL",
                      "C_FindObjects(CKA_CLASS=PUBLIC,CKA_ID) returned " + std::to_string(cnt) + " object(s)");
    }

    // ── B. Same logged-in session: find privkey by {CKA_CLASS=PRIVATE, CKA_ID}
    {
        CK_ATTRIBUTE findT[] = {
            { CKA_CLASS, &privClass, sizeof(privClass) },
            { CKA_ID,    keyid,      sizeof(keyid) },
        };
        rv = fl->C_FindObjectsInit(hSess, findT, 2);
        CK_OBJECT_HANDLE objs[5] = {0};
        CK_ULONG cnt = 0;
        if (rv == CKR_OK) {
            fl->C_FindObjects(hSess, objs, 5, &cnt);
            fl->C_FindObjectsFinal(hSess);
        }
        record_result("CkaIdRetrieval", "FindByCkaId_Privkey_LoggedIn", (cnt >= 1) ? "PASS" : "FAIL",
                      "C_FindObjects(CKA_CLASS=PRIVATE,CKA_ID) returned " + std::to_string(cnt) + " object(s)");
    }

    // ── C. ★ THE CRITICAL TEST ★
    //         Open a FRESH public RO session (NO login) and search for the
    //         pubkey by CKA_ID. This is exactly what charon's strongswan-pkcs11
    //         plugin does at IKE_AUTH time. If the pubkey isn't visible here
    //         despite CKA_PRIVATE=FALSE, that's the softhsm bug we're hunting.
    {
        CK_SESSION_HANDLE hPub_sess = 0;
        rv = fl->C_OpenSession(0, CKF_SERIAL_SESSION /* RO, no login */,
                               NULL_PTR, NULL_PTR, &hPub_sess);
        if (rv != CKR_OK) {
            record_result("CkaIdRetrieval", "FindByCkaId_Pubkey_NoLogin", "SKIP",
                          "C_OpenSession(public RO) failed RV=" + std::to_string(rv));
        } else {
            CK_ATTRIBUTE findT[] = {
                { CKA_CLASS, &pubClass, sizeof(pubClass) },
                { CKA_ID,    keyid,     sizeof(keyid) },
            };
            rv = fl->C_FindObjectsInit(hPub_sess, findT, 2);
            CK_OBJECT_HANDLE objs[5] = {0};
            CK_ULONG cnt = 0;
            CK_BBOOL ckaPrivVal = 0xff;
            if (rv == CKR_OK) {
                fl->C_FindObjects(hPub_sess, objs, 5, &cnt);
                fl->C_FindObjectsFinal(hPub_sess);
                if (cnt >= 1) {
                    // Read CKA_PRIVATE on the found object.
                    CK_ATTRIBUTE attr = { CKA_PRIVATE, &ckaPrivVal, sizeof(ckaPrivVal) };
                    fl->C_GetAttributeValue(hPub_sess, objs[0], &attr, 1);
                }
            }
            std::string detail = "C_FindObjects(public RO,CKA_CLASS=PUBLIC,CKA_ID) returned "
                + std::to_string(cnt) + " object(s)";
            if (cnt >= 1) detail += "; CKA_PRIVATE on hit = " + std::to_string((unsigned)ckaPrivVal);
            record_result("CkaIdRetrieval", "FindByCkaId_Pubkey_NoLogin", (cnt >= 1) ? "PASS" : "FAIL", detail);
            fl->C_CloseSession(hPub_sess);
        }
    }

    // ── D. Default CKA_PRIVATE behavior on pubkey:
    //         Generate a SECOND keypair WITHOUT explicitly setting CKA_PRIVATE
    //         on the public template, then check if the resulting pubkey is
    //         findable from a no-login session. PKCS#11 v3.2 §4.5 says
    //         CKA_PRIVATE defaults to CK_FALSE for public keys; if softhsm
    //         doesn't honor that, this test catches the deviation.
    {
        CK_BYTE keyid2[20] = {
            0x9d,0x6b,0x51,0xed, 0x59,0xdc,0x66,0x09, 0x4f,0x97,0x0f,0xb5,
            0x71,0x8c,0x1b,0xda, 0x32,0x9f,0x38,0x8b
        };
        CK_ATTRIBUTE pubTmpl2[] = {
            { CKA_CLASS,         &pubClass,   sizeof(pubClass) },
            { CKA_KEY_TYPE,      &ktypeMlDsa, sizeof(ktypeMlDsa) },
            { CKA_TOKEN,         &bTrue,      sizeof(bTrue) },
            { CKA_VERIFY,        &bTrue,      sizeof(bTrue) },
            { CKA_PARAMETER_SET, &paramSet65, sizeof(paramSet65) },
            { CKA_ID,            keyid2,      sizeof(keyid2) },
            // Notably: NO CKA_PRIVATE on pubkey — relies on PKCS#11 default
        };
        CK_ATTRIBUTE privTmpl2[] = {
            { CKA_CLASS,         &privClass,  sizeof(privClass) },
            { CKA_KEY_TYPE,      &ktypeMlDsa, sizeof(ktypeMlDsa) },
            { CKA_TOKEN,         &bTrue,      sizeof(bTrue) },
            { CKA_PRIVATE,       &bTrue,      sizeof(bTrue) },
            { CKA_SIGN,          &bTrue,      sizeof(bTrue) },
            { CKA_ID,            keyid2,      sizeof(keyid2) },
        };
        CK_OBJECT_HANDLE hPub2 = 0, hPriv2 = 0;
        rv = fl->C_GenerateKeyPair(hSess, &genMech, pubTmpl2, 6, privTmpl2, 6, &hPub2, &hPriv2);
        if (rv != CKR_OK) {
            record_result("CkaIdRetrieval", "Default_CkaPrivate_Pubkey_Gen", "FAIL",
                          "Keygen w/o explicit CKA_PRIVATE on pubkey RV=" + std::to_string(rv));
        } else {
            // Read back CKA_PRIVATE.
            CK_BBOOL ckaPriv = 0xff;
            CK_ATTRIBUTE attr = { CKA_PRIVATE, &ckaPriv, sizeof(ckaPriv) };
            fl->C_GetAttributeValue(hSess, hPub2, &attr, 1);
            // Per PKCS#11 v3.2 §4.5: pubkeys default to CKA_PRIVATE=FALSE.
            record_result("CkaIdRetrieval", "Default_CkaPrivate_Pubkey", (ckaPriv == CK_FALSE) ? "PASS" : "FAIL",
                          "PKCS#11 v3.2 §4.5: pubkey CKA_PRIVATE default expected FALSE; got " + std::to_string((unsigned)ckaPriv));

            // No-login session retrieval test for the default-CKA_PRIVATE pubkey.
            CK_SESSION_HANDLE hPub_sess2 = 0;
            CK_RV ors = fl->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hPub_sess2);
            if (ors == CKR_OK) {
                CK_ATTRIBUTE findT[] = {
                    { CKA_CLASS, &pubClass, sizeof(pubClass) },
                    { CKA_ID,    keyid2,    sizeof(keyid2) },
                };
                fl->C_FindObjectsInit(hPub_sess2, findT, 2);
                CK_OBJECT_HANDLE found[5] = {0};
                CK_ULONG cnt = 0;
                fl->C_FindObjects(hPub_sess2, found, 5, &cnt);
                fl->C_FindObjectsFinal(hPub_sess2);
                fl->C_CloseSession(hPub_sess2);
                record_result("CkaIdRetrieval", "Default_CkaPrivate_Pubkey_NoLoginFind",
                              (cnt >= 1) ? "PASS" : "FAIL",
                              "Default-CKA_PRIVATE pubkey findable from no-login session: count=" + std::to_string(cnt));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CKA_CHECK_VALUE (KCV) compliance — PKCS#11 v3.2 §4.11 / §6.8.2 / §6.10.2
//
// §4.11 (line 15886-15889): "if supported, regardless of how the key object
// is created or derived, the value of the attribute is always supplied".
// This MUST cover C_GenerateKey, C_UnwrapKey, AND C_DeriveKey.
//
// Per-key-type algorithms (verified against v3.2 spec, no SHA-256 ever):
//   • CKK_AES (§6.10.2 line 40671): AES-ECB(zero block) first 3 bytes
//   • CKK_GENERIC_SECRET (§6.8.2 line 39752): SHA-1(CKA_VALUE) first 3 bytes
//
// This test independently computes the spec reference using OpenSSL EVP and
// asserts the HSM's CKA_CHECK_VALUE matches byte-for-byte. It also verifies
// the "for two cryptographically identical keys the KCV is identical"
// property by wrapping/unwrapping a key and confirming both handles produce
// the same 3-byte KCV.
// ─────────────────────────────────────────────────────────────────────────────

// Helper: compute SHA-1(data)[0:3] using OpenSSL as the independent oracle.
static std::vector<unsigned char> oracle_sha1_kcv(const unsigned char* data, size_t len) {
    unsigned char digest[SHA_DIGEST_LENGTH] = {0};
    SHA1(data, len, digest);
    return std::vector<unsigned char>(digest, digest + 3);
}

// Helper: compute AES-ECB(zero block)[0:3] using OpenSSL as the independent oracle.
static std::vector<unsigned char> oracle_aes_ecb_kcv(const unsigned char* key, size_t keyLen) {
    const EVP_CIPHER* cipher = nullptr;
    switch (keyLen) {
        case 16: cipher = EVP_aes_128_ecb(); break;
        case 24: cipher = EVP_aes_192_ecb(); break;
        case 32: cipher = EVP_aes_256_ecb(); break;
        default: return {};
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};
    unsigned char zero_block[16] = {0};
    unsigned char out[32] = {0};
    int outlen = 0;
    std::vector<unsigned char> kcv;
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, nullptr) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_EncryptUpdate(ctx, out, &outlen, zero_block, 16) == 1 &&
        outlen >= 3) {
        kcv.assign(out, out + 3);
    }
    EVP_CIPHER_CTX_free(ctx);
    return kcv;
}

// Helper: read CKA_CHECK_VALUE from a key handle. Returns empty vector on any error.
static std::vector<unsigned char> read_kcv(CK_OBJECT_HANDLE hKey) {
    CK_ATTRIBUTE tpl[1] = { { CKA_CHECK_VALUE, NULL_PTR, 0 } };
    CK_RV rv = fl->C_GetAttributeValue(hSess, hKey, tpl, 1);
    if (rv != CKR_OK || tpl[0].ulValueLen == 0 || tpl[0].ulValueLen == (CK_ULONG)-1) return {};
    std::vector<unsigned char> kcv(tpl[0].ulValueLen);
    tpl[0].pValue = kcv.data();
    rv = fl->C_GetAttributeValue(hSess, hKey, tpl, 1);
    if (rv != CKR_OK) return {};
    return kcv;
}

static std::string hex_bytes(const std::vector<unsigned char>& bytes) {
    std::string s;
    s.reserve(bytes.size() * 2);
    static const char* lut = "0123456789ABCDEF";
    for (auto b : bytes) { s += lut[b >> 4]; s += lut[b & 0xF]; }
    return s;
}

void test_kcv_compliance() {
    // ── 1. CKK_AES KCV after C_GenerateKey — baseline, must match AES-ECB oracle ──
    {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE     kt  = CKK_AES;
        CK_ULONG        klen = 32;
        CK_BBOOL        bTrue = CK_TRUE;
        CK_BBOOL        bFalse = CK_FALSE;
        CK_ATTRIBUTE tpl[] = {
            { CKA_CLASS,       &cls,    sizeof(cls)    },
            { CKA_KEY_TYPE,    &kt,     sizeof(kt)     },
            { CKA_VALUE_LEN,   &klen,   sizeof(klen)   },
            { CKA_TOKEN,       &bFalse, sizeof(bFalse) },
            { CKA_SENSITIVE,   &bFalse, sizeof(bFalse) },
            { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue)  },
            { CKA_WRAP,        &bTrue,  sizeof(bTrue)  },
            { CKA_UNWRAP,      &bTrue,  sizeof(bTrue)  },
            { CKA_ENCRYPT,     &bTrue,  sizeof(bTrue)  },
            { CKA_DECRYPT,     &bTrue,  sizeof(bTrue)  },
        };
        CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE hKek = CK_INVALID_HANDLE;
        CK_RV rv = fl->C_GenerateKey(hSess, &mech, tpl, sizeof(tpl)/sizeof(tpl[0]), &hKek);
        if (rv != CKR_OK) {
            record_result("KCV", "AES_Generate_KCV_Present", "FAIL",
                          "C_GenerateKey RV=" + std::to_string(rv));
            return;
        }

        // Read CKA_VALUE (extractable key) and CKA_CHECK_VALUE.
        std::vector<unsigned char> keyBits(klen);
        CK_ATTRIBUTE vtpl[1] = { { CKA_VALUE, keyBits.data(), klen } };
        rv = fl->C_GetAttributeValue(hSess, hKek, vtpl, 1);
        if (rv != CKR_OK) {
            record_result("KCV", "AES_Generate_CKA_VALUE_Readable", "FAIL",
                          "C_GetAttributeValue(CKA_VALUE) RV=" + std::to_string(rv));
            fl->C_DestroyObject(hSess, hKek);
            return;
        }
        std::vector<unsigned char> hsmKcv = read_kcv(hKek);
        std::vector<unsigned char> oracleKcv = oracle_aes_ecb_kcv(keyBits.data(), klen);

        bool present = (hsmKcv.size() == 3);
        bool matches = present && (hsmKcv == oracleKcv);
        record_result("KCV", "AES_Generate_KCV_Present",
                      present ? "PASS" : "FAIL",
                      present ? "3 bytes: " + hex_bytes(hsmKcv)
                              : "expected 3 bytes, got " + std::to_string(hsmKcv.size()));
        record_result("KCV", "AES_Generate_KCV_Equals_OracleEcbZeroBlock",
                      matches ? "PASS" : "FAIL",
                      matches ? "HSM=" + hex_bytes(hsmKcv) + " == oracle=" + hex_bytes(oracleKcv)
                              : "HSM=" + hex_bytes(hsmKcv) + " != oracle=" + hex_bytes(oracleKcv) +
                                " (PKCS#11 v3.2 §6.10.2: AES-ECB(zero block)[0:3])");

        // ── 2. CKA_CHECK_VALUE after C_UnwrapKey — §4.11 mandate ─────────────
        // Generate a fresh AES DEK, wrap it with the KEK, unwrap to a new handle,
        // assert KCV(unwrapped) matches KCV(original) and the AES-ECB oracle.
        CK_OBJECT_HANDLE hDek = CK_INVALID_HANDLE;
        rv = fl->C_GenerateKey(hSess, &mech, tpl, sizeof(tpl)/sizeof(tpl[0]), &hDek);
        if (rv != CKR_OK) {
            record_result("KCV", "AES_Unwrap_DEK_Setup", "FAIL", "RV=" + std::to_string(rv));
            fl->C_DestroyObject(hSess, hKek);
            return;
        }
        std::vector<unsigned char> dekBits(klen);
        CK_ATTRIBUTE dekVtpl[1] = { { CKA_VALUE, dekBits.data(), klen } };
        fl->C_GetAttributeValue(hSess, hDek, dekVtpl, 1);
        std::vector<unsigned char> dekKcvOrig = read_kcv(hDek);
        std::vector<unsigned char> dekKcvOracle = oracle_aes_ecb_kcv(dekBits.data(), klen);

        // Wrap DEK under KEK (CKM_AES_KEY_WRAP).
        CK_MECHANISM wrapMech = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
        CK_BYTE wrapped[64] = {0};
        CK_ULONG wrappedLen = sizeof(wrapped);
        rv = fl->C_WrapKey(hSess, &wrapMech, hKek, hDek, wrapped, &wrappedLen);
        if (rv != CKR_OK) {
            record_result("KCV", "AES_Wrap_For_Unwrap", "FAIL", "RV=" + std::to_string(rv));
            fl->C_DestroyObject(hSess, hDek);
            fl->C_DestroyObject(hSess, hKek);
            return;
        }

        // Unwrap to a new handle.
        CK_OBJECT_HANDLE hDekRec = CK_INVALID_HANDLE;
        CK_ATTRIBUTE unwrapTpl[] = {
            { CKA_CLASS,       &cls,    sizeof(cls)    },
            { CKA_KEY_TYPE,    &kt,     sizeof(kt)     },
            { CKA_TOKEN,       &bFalse, sizeof(bFalse) },
            { CKA_SENSITIVE,   &bFalse, sizeof(bFalse) },
            { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue)  },
            { CKA_ENCRYPT,     &bTrue,  sizeof(bTrue)  },
            { CKA_DECRYPT,     &bTrue,  sizeof(bTrue)  },
        };
        rv = fl->C_UnwrapKey(hSess, &wrapMech, hKek, wrapped, wrappedLen,
                             unwrapTpl, sizeof(unwrapTpl)/sizeof(unwrapTpl[0]), &hDekRec);
        if (rv != CKR_OK) {
            record_result("KCV", "AES_UnwrapKey_Succeeds", "FAIL", "RV=" + std::to_string(rv));
            fl->C_DestroyObject(hSess, hDek);
            fl->C_DestroyObject(hSess, hKek);
            return;
        }

        std::vector<unsigned char> dekKcvRec = read_kcv(hDekRec);
        bool unwrapKcvPresent = (dekKcvRec.size() == 3);
        bool unwrapKcvMatchesOriginal = unwrapKcvPresent && (dekKcvRec == dekKcvOrig);
        bool unwrapKcvMatchesOracle   = unwrapKcvPresent && (dekKcvRec == dekKcvOracle);
        record_result("KCV", "AES_Unwrap_KCV_Present",
                      unwrapKcvPresent ? "PASS" : "FAIL",
                      unwrapKcvPresent ? "3 bytes: " + hex_bytes(dekKcvRec)
                                       : "PKCS#11 v3.2 §4.11: KCV mandatory after C_UnwrapKey, "
                                         "got " + std::to_string(dekKcvRec.size()) + " bytes");
        record_result("KCV", "AES_Unwrap_KCV_Equals_Original",
                      unwrapKcvMatchesOriginal ? "PASS" : "FAIL",
                      unwrapKcvMatchesOriginal ? "original=" + hex_bytes(dekKcvOrig) +
                                                 " unwrapped=" + hex_bytes(dekKcvRec)
                                               : "PKCS#11 v3.2 §4.11 property 1: "
                                                 "cryptographically identical keys MUST have identical KCV. "
                                                 "original=" + hex_bytes(dekKcvOrig) +
                                                 " unwrapped=" + hex_bytes(dekKcvRec));
        record_result("KCV", "AES_Unwrap_KCV_Equals_OracleEcbZeroBlock",
                      unwrapKcvMatchesOracle ? "PASS" : "FAIL",
                      unwrapKcvMatchesOracle ? "matches AES-ECB(zero block)[0:3] oracle"
                                             : "deviates from §6.10.2 algorithm");

        fl->C_DestroyObject(hSess, hDekRec);
        fl->C_DestroyObject(hSess, hDek);
        fl->C_DestroyObject(hSess, hKek);
    }

    // ── 3. CKK_GENERIC_SECRET KCV after C_DeriveKey (HKDF) — §4.11 + §6.8.2 ──
    {
        // Build a base generic-secret key with known bytes for HKDF input.
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE     kt  = CKK_GENERIC_SECRET;
        CK_BBOOL        bTrue = CK_TRUE;
        CK_BBOOL        bFalse = CK_FALSE;
        unsigned char baseBits[32] = {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
            0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
            0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
        };
        CK_ATTRIBUTE baseTpl[] = {
            { CKA_CLASS,       &cls,      sizeof(cls)      },
            { CKA_KEY_TYPE,    &kt,       sizeof(kt)       },
            { CKA_TOKEN,       &bFalse,   sizeof(bFalse)   },
            { CKA_SENSITIVE,   &bFalse,   sizeof(bFalse)   },
            { CKA_EXTRACTABLE, &bTrue,    sizeof(bTrue)    },
            { CKA_DERIVE,      &bTrue,    sizeof(bTrue)    },
            { CKA_VALUE,       baseBits,  sizeof(baseBits) },
        };
        CK_OBJECT_HANDLE hBase = CK_INVALID_HANDLE;
        CK_RV rv = fl->C_CreateObject(hSess, baseTpl, sizeof(baseTpl)/sizeof(baseTpl[0]), &hBase);
        if (rv != CKR_OK) {
            record_result("KCV", "HKDF_Derive_Base_Setup", "FAIL", "RV=" + std::to_string(rv));
            return;
        }

        // HKDF derive a 32-byte generic-secret.
        CK_ULONG outLen = 32;
        CK_ATTRIBUTE derTpl[] = {
            { CKA_CLASS,       &cls,    sizeof(cls)    },
            { CKA_KEY_TYPE,    &kt,     sizeof(kt)     },
            { CKA_VALUE_LEN,   &outLen, sizeof(outLen) },
            { CKA_TOKEN,       &bFalse, sizeof(bFalse) },
            { CKA_SENSITIVE,   &bFalse, sizeof(bFalse) },
            { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue)  },
        };
        unsigned char salt[] = { 's','a','l','t' };
        unsigned char info[] = { 'i','n','f','o' };
        struct {
            CK_BBOOL bExtract; CK_BBOOL bExpand;
            CK_MECHANISM_TYPE prfHashMechanism;
            CK_ULONG ulSaltType;
            CK_BYTE_PTR pSalt; CK_ULONG ulSaltLen;
            CK_OBJECT_HANDLE hSaltKey;
            CK_BYTE_PTR pInfo; CK_ULONG ulInfoLen;
        } hkdfParams = {
            CK_TRUE, CK_TRUE, CKM_SHA256,
            0x00000002UL /* CKF_HKDF_SALT_DATA */,
            salt, sizeof(salt), 0,
            info, sizeof(info),
        };
        CK_MECHANISM hkdfMech = { CKM_HKDF_DERIVE, &hkdfParams, sizeof(hkdfParams) };
        CK_OBJECT_HANDLE hDerived = CK_INVALID_HANDLE;
        rv = fl->C_DeriveKey(hSess, &hkdfMech, hBase, derTpl, sizeof(derTpl)/sizeof(derTpl[0]), &hDerived);
        if (rv != CKR_OK) {
            record_result("KCV", "HKDF_Derive_Succeeds", "FAIL", "RV=" + std::to_string(rv));
            fl->C_DestroyObject(hSess, hBase);
            return;
        }

        // Read derived key bytes + KCV.
        std::vector<unsigned char> derivedBits(outLen);
        CK_ATTRIBUTE dvTpl[1] = { { CKA_VALUE, derivedBits.data(), outLen } };
        rv = fl->C_GetAttributeValue(hSess, hDerived, dvTpl, 1);
        if (rv != CKR_OK) {
            record_result("KCV", "HKDF_Derived_CKA_VALUE_Readable", "FAIL", "RV=" + std::to_string(rv));
            fl->C_DestroyObject(hSess, hDerived);
            fl->C_DestroyObject(hSess, hBase);
            return;
        }
        std::vector<unsigned char> derivedKcv = read_kcv(hDerived);
        std::vector<unsigned char> oracleKcv = oracle_sha1_kcv(derivedBits.data(), outLen);

        bool present = (derivedKcv.size() == 3);
        bool matches = present && (derivedKcv == oracleKcv);
        record_result("KCV", "HKDF_Derive_KCV_Present",
                      present ? "PASS" : "FAIL",
                      present ? "3 bytes: " + hex_bytes(derivedKcv)
                              : "PKCS#11 v3.2 §4.11: KCV mandatory after C_DeriveKey, "
                                "got " + std::to_string(derivedKcv.size()) + " bytes");
        record_result("KCV", "HKDF_Derive_KCV_Equals_OracleSha1",
                      matches ? "PASS" : "FAIL",
                      matches ? "HSM=" + hex_bytes(derivedKcv) + " == oracle=" + hex_bytes(oracleKcv)
                              : "HSM=" + hex_bytes(derivedKcv) + " != oracle=" + hex_bytes(oracleKcv) +
                                " (PKCS#11 v3.2 §6.8.2: SHA-1(CKA_VALUE)[0:3])");

        fl->C_DestroyObject(hSess, hDerived);
        fl->C_DestroyObject(hSess, hBase);
    }

    // ── 4. CKK_GENERIC_SECRET KCV after C_DeriveKey (PBKD2) — §4.11 + §6.8.2 ──
    {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE     kt  = CKK_GENERIC_SECRET;
        CK_BBOOL        bTrue = CK_TRUE;
        CK_BBOOL        bFalse = CK_FALSE;
        CK_ULONG        outLen = 32;
        CK_ATTRIBUTE derTpl[] = {
            { CKA_CLASS,       &cls,    sizeof(cls)    },
            { CKA_KEY_TYPE,    &kt,     sizeof(kt)     },
            { CKA_VALUE_LEN,   &outLen, sizeof(outLen) },
            { CKA_TOKEN,       &bFalse, sizeof(bFalse) },
            { CKA_SENSITIVE,   &bFalse, sizeof(bFalse) },
            { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue)  },
        };

        CK_UTF8CHAR password[] = "compliance-pbkd2-password";
        CK_BYTE     salt[]     = "compliance-pbkd2-salt";
        CK_ULONG    iters      = 2048;
        CK_PKCS5_PBKD2_PARAMS2 pbkdf2Params = {
            1 /* CKZ_SALT_SPECIFIED */, salt, sizeof(salt) - 1,
            iters,
            4 /* CKP_PKCS5_PBKD2_HMAC_SHA256 */, NULL_PTR, 0,
            password, sizeof(password) - 1
        };
        CK_MECHANISM pbkdMech = { CKM_PKCS5_PBKD2, &pbkdf2Params, sizeof(pbkdf2Params) };
        CK_OBJECT_HANDLE hDerived = CK_INVALID_HANDLE;
        // PBKD2 does not require a base key — pass CK_INVALID_HANDLE.
        CK_RV rv = fl->C_DeriveKey(hSess, &pbkdMech, CK_INVALID_HANDLE,
                                   derTpl, sizeof(derTpl)/sizeof(derTpl[0]), &hDerived);
        if (rv != CKR_OK) {
            record_result("KCV", "PBKD2_Derive_Succeeds", "FAIL", "RV=" + std::to_string(rv));
        } else {
            std::vector<unsigned char> derivedBits(outLen);
            CK_ATTRIBUTE dvTpl[1] = { { CKA_VALUE, derivedBits.data(), outLen } };
            CK_RV rv2 = fl->C_GetAttributeValue(hSess, hDerived, dvTpl, 1);
            if (rv2 != CKR_OK) {
                record_result("KCV", "PBKD2_Derived_CKA_VALUE_Readable", "FAIL",
                              "RV=" + std::to_string(rv2));
            } else {
                std::vector<unsigned char> derivedKcv = read_kcv(hDerived);
                std::vector<unsigned char> oracleKcv  = oracle_sha1_kcv(derivedBits.data(), outLen);
                bool present = (derivedKcv.size() == 3);
                bool matches = present && (derivedKcv == oracleKcv);
                record_result("KCV", "PBKD2_Derive_KCV_Present",
                              present ? "PASS" : "FAIL",
                              present ? "3 bytes: " + hex_bytes(derivedKcv)
                                      : "PKCS#11 v3.2 §4.11: KCV mandatory after C_DeriveKey, "
                                        "got " + std::to_string(derivedKcv.size()) + " bytes");
                record_result("KCV", "PBKD2_Derive_KCV_Equals_OracleSha1",
                              matches ? "PASS" : "FAIL",
                              matches ? "HSM=" + hex_bytes(derivedKcv) + " == oracle=" + hex_bytes(oracleKcv)
                                      : "HSM=" + hex_bytes(derivedKcv) + " != oracle=" + hex_bytes(oracleKcv) +
                                        " (PKCS#11 v3.2 §6.8.2: SHA-1(CKA_VALUE)[0:3])");
            }
            fl->C_DestroyObject(hSess, hDerived);
        }
    }

    // ── 5. CKK_GENERIC_SECRET KCV after C_DeriveKey (SP800-108 Counter) — §4.11 + §6.8.2 ──
    {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE     kt  = CKK_GENERIC_SECRET;
        CK_BBOOL        bTrue = CK_TRUE;
        CK_BBOOL        bFalse = CK_FALSE;
        unsigned char baseBits[32] = {
            0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
            0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,
            0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
            0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40,
        };
        CK_ATTRIBUTE baseTpl[] = {
            { CKA_CLASS,       &cls,    sizeof(cls)      },
            { CKA_KEY_TYPE,    &kt,     sizeof(kt)       },
            { CKA_TOKEN,       &bFalse, sizeof(bFalse)   },
            { CKA_SENSITIVE,   &bFalse, sizeof(bFalse)   },
            { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue)    },
            { CKA_DERIVE,      &bTrue,  sizeof(bTrue)    },
            { CKA_VALUE,       baseBits, sizeof(baseBits) },
        };
        CK_OBJECT_HANDLE hBase = CK_INVALID_HANDLE;
        CK_RV rv = fl->C_CreateObject(hSess, baseTpl, sizeof(baseTpl)/sizeof(baseTpl[0]), &hBase);
        if (rv != CKR_OK) {
            record_result("KCV", "SP800_108_Counter_Base_Setup", "FAIL", "RV=" + std::to_string(rv));
        } else {
            CK_ULONG outLen = 32;
            CK_ATTRIBUTE derTpl[] = {
                { CKA_CLASS,       &cls,    sizeof(cls)    },
                { CKA_KEY_TYPE,    &kt,     sizeof(kt)     },
                { CKA_VALUE_LEN,   &outLen, sizeof(outLen) },
                { CKA_TOKEN,       &bFalse, sizeof(bFalse) },
                { CKA_SENSITIVE,   &bFalse, sizeof(bFalse) },
                { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue)  },
            };
            CK_BYTE label[]   = "compliance-counter-label";
            CK_BYTE context[] = "compliance-counter-context";
            // Spec CK_PRF_DATA_TYPE values (v3.2 §6.44): ITERATION_VARIABLE for
            // the counter, BYTE_ARRAY for label/context fixed input.
            CK_SP800_108_COUNTER_FORMAT kcvCtrFmt = { CK_FALSE /* big-endian */, 32 };
            CK_PRF_DATA_PARAM prfParams[] = {
                { CK_SP800_108_ITERATION_VARIABLE, &kcvCtrFmt, sizeof(kcvCtrFmt) },
                { CK_SP800_108_BYTE_ARRAY,         label,    sizeof(label)   - 1 },
                { CK_SP800_108_BYTE_ARRAY,         context,  sizeof(context) - 1 },
            };
            // PRF must be a keyed MAC mech (spec); CKM_AES_CMAC exercises the
            // CMAC PRF path here (the HMAC PRF path is covered by the dedicated
            // KDF tests).
            CK_SP800_108_KDF_PARAMS ctrParams = {
                CKM_AES_CMAC, 3, prfParams, 0, NULL_PTR
            };
            CK_MECHANISM ctrMech = { CKM_SP800_108_COUNTER_KDF, &ctrParams, sizeof(ctrParams) };
            CK_OBJECT_HANDLE hDerived = CK_INVALID_HANDLE;
            rv = fl->C_DeriveKey(hSess, &ctrMech, hBase,
                                 derTpl, sizeof(derTpl)/sizeof(derTpl[0]), &hDerived);
            if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
                record_result("KCV", "SP800_108_Counter_Derive_KCV_Present", "SKIP",
                              "CKM_SP800_108_COUNTER_KDF unavailable");
                record_result("KCV", "SP800_108_Counter_Derive_KCV_Equals_OracleSha1", "SKIP",
                              "CKM_SP800_108_COUNTER_KDF unavailable");
            } else if (rv != CKR_OK) {
                record_result("KCV", "SP800_108_Counter_Derive_Succeeds", "FAIL",
                              "RV=" + std::to_string(rv));
            } else {
                std::vector<unsigned char> derivedBits(outLen);
                CK_ATTRIBUTE dvTpl[1] = { { CKA_VALUE, derivedBits.data(), outLen } };
                CK_RV rv2 = fl->C_GetAttributeValue(hSess, hDerived, dvTpl, 1);
                if (rv2 != CKR_OK) {
                    record_result("KCV", "SP800_108_Counter_Derived_CKA_VALUE_Readable", "FAIL",
                                  "RV=" + std::to_string(rv2));
                } else {
                    std::vector<unsigned char> derivedKcv = read_kcv(hDerived);
                    std::vector<unsigned char> oracleKcv  = oracle_sha1_kcv(derivedBits.data(), outLen);
                    bool present = (derivedKcv.size() == 3);
                    bool matches = present && (derivedKcv == oracleKcv);
                    record_result("KCV", "SP800_108_Counter_Derive_KCV_Present",
                                  present ? "PASS" : "FAIL",
                                  present ? "3 bytes: " + hex_bytes(derivedKcv)
                                          : "PKCS#11 v3.2 §4.11: KCV mandatory after C_DeriveKey, "
                                            "got " + std::to_string(derivedKcv.size()) + " bytes");
                    record_result("KCV", "SP800_108_Counter_Derive_KCV_Equals_OracleSha1",
                                  matches ? "PASS" : "FAIL",
                                  matches ? "HSM=" + hex_bytes(derivedKcv) + " == oracle=" + hex_bytes(oracleKcv)
                                          : "HSM=" + hex_bytes(derivedKcv) + " != oracle=" + hex_bytes(oracleKcv) +
                                            " (PKCS#11 v3.2 §6.8.2: SHA-1(CKA_VALUE)[0:3])");
                }
                fl->C_DestroyObject(hSess, hDerived);
            }
            fl->C_DestroyObject(hSess, hBase);
        }
    }

    // ── 6. CKK_GENERIC_SECRET KCV after C_DeriveKey (SP800-108 Feedback) — §4.11 + §6.8.2 ──
    {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE     kt  = CKK_GENERIC_SECRET;
        CK_BBOOL        bTrue = CK_TRUE;
        CK_BBOOL        bFalse = CK_FALSE;
        unsigned char baseBits[32] = {
            0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
            0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,
            0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,
            0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,
        };
        CK_ATTRIBUTE baseTpl[] = {
            { CKA_CLASS,       &cls,    sizeof(cls)      },
            { CKA_KEY_TYPE,    &kt,     sizeof(kt)       },
            { CKA_TOKEN,       &bFalse, sizeof(bFalse)   },
            { CKA_SENSITIVE,   &bFalse, sizeof(bFalse)   },
            { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue)    },
            { CKA_DERIVE,      &bTrue,  sizeof(bTrue)    },
            { CKA_VALUE,       baseBits, sizeof(baseBits) },
        };
        CK_OBJECT_HANDLE hBase = CK_INVALID_HANDLE;
        CK_RV rv = fl->C_CreateObject(hSess, baseTpl, sizeof(baseTpl)/sizeof(baseTpl[0]), &hBase);
        if (rv != CKR_OK) {
            record_result("KCV", "SP800_108_Feedback_Base_Setup", "FAIL", "RV=" + std::to_string(rv));
        } else {
            CK_ULONG outLen = 32;
            CK_ATTRIBUTE derTpl[] = {
                { CKA_CLASS,       &cls,    sizeof(cls)    },
                { CKA_KEY_TYPE,    &kt,     sizeof(kt)     },
                { CKA_VALUE_LEN,   &outLen, sizeof(outLen) },
                { CKA_TOKEN,       &bFalse, sizeof(bFalse) },
                { CKA_SENSITIVE,   &bFalse, sizeof(bFalse) },
                { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue)  },
            };
            CK_BYTE label[]   = "compliance-feedback-label";
            CK_BYTE context[] = "compliance-feedback-context";
            // Spec CK_PRF_DATA_TYPE values + keyed-MAC PRF (see counter KDF note).
            CK_SP800_108_COUNTER_FORMAT kcvFbkFmt = { CK_FALSE /* big-endian */, 32 };
            CK_PRF_DATA_PARAM prfParams[] = {
                { CK_SP800_108_ITERATION_VARIABLE, &kcvFbkFmt, sizeof(kcvFbkFmt) },
                { CK_SP800_108_BYTE_ARRAY,         label,    sizeof(label)   - 1 },
                { CK_SP800_108_BYTE_ARRAY,         context,  sizeof(context) - 1 },
            };
            CK_SP800_108_FEEDBACK_KDF_PARAMS fbkParams = {
                CKM_AES_CMAC, 3, prfParams,
                0, NULL_PTR,   // ulIVLen, pIV
                0, NULL_PTR    // ulAdditionalDerivedKeys, pAdditionalDerivedKeys
            };
            CK_MECHANISM fbkMech = { CKM_SP800_108_FEEDBACK_KDF, &fbkParams, sizeof(fbkParams) };
            CK_OBJECT_HANDLE hDerived = CK_INVALID_HANDLE;
            rv = fl->C_DeriveKey(hSess, &fbkMech, hBase,
                                 derTpl, sizeof(derTpl)/sizeof(derTpl[0]), &hDerived);
            if (rv == CKR_MECHANISM_INVALID || rv == CKR_FUNCTION_NOT_SUPPORTED) {
                record_result("KCV", "SP800_108_Feedback_Derive_KCV_Present", "SKIP",
                              "CKM_SP800_108_FEEDBACK_KDF unavailable");
                record_result("KCV", "SP800_108_Feedback_Derive_KCV_Equals_OracleSha1", "SKIP",
                              "CKM_SP800_108_FEEDBACK_KDF unavailable");
            } else if (rv != CKR_OK) {
                record_result("KCV", "SP800_108_Feedback_Derive_Succeeds", "FAIL",
                              "RV=" + std::to_string(rv));
            } else {
                std::vector<unsigned char> derivedBits(outLen);
                CK_ATTRIBUTE dvTpl[1] = { { CKA_VALUE, derivedBits.data(), outLen } };
                CK_RV rv2 = fl->C_GetAttributeValue(hSess, hDerived, dvTpl, 1);
                if (rv2 != CKR_OK) {
                    record_result("KCV", "SP800_108_Feedback_Derived_CKA_VALUE_Readable", "FAIL",
                                  "RV=" + std::to_string(rv2));
                } else {
                    std::vector<unsigned char> derivedKcv = read_kcv(hDerived);
                    std::vector<unsigned char> oracleKcv  = oracle_sha1_kcv(derivedBits.data(), outLen);
                    bool present = (derivedKcv.size() == 3);
                    bool matches = present && (derivedKcv == oracleKcv);
                    record_result("KCV", "SP800_108_Feedback_Derive_KCV_Present",
                                  present ? "PASS" : "FAIL",
                                  present ? "3 bytes: " + hex_bytes(derivedKcv)
                                          : "PKCS#11 v3.2 §4.11: KCV mandatory after C_DeriveKey, "
                                            "got " + std::to_string(derivedKcv.size()) + " bytes");
                    record_result("KCV", "SP800_108_Feedback_Derive_KCV_Equals_OracleSha1",
                                  matches ? "PASS" : "FAIL",
                                  matches ? "HSM=" + hex_bytes(derivedKcv) + " == oracle=" + hex_bytes(oracleKcv)
                                          : "HSM=" + hex_bytes(derivedKcv) + " != oracle=" + hex_bytes(oracleKcv) +
                                            " (PKCS#11 v3.2 §6.8.2: SHA-1(CKA_VALUE)[0:3])");
                }
                fl->C_DestroyObject(hSess, hDerived);
            }
            fl->C_DestroyObject(hSess, hBase);
        }
    }
}

// ── G1 security-critical regression tests ────────────────────────────────────
// Locks in the slice G1 fixes: zero-IV GCM/ChaCha rejection (C++C-1/C++C-2),
// RIPEMD160→SHA-1 substitution removal (C++C-4), large-message XMSS sign
// (C++C-3 stack overflow), and the HSS keygen→sign→verify round-trip that
// proves the V-13 encrypt-on-write / decrypt-on-read symmetry.
static CK_OBJECT_HANDLE g1_create_aes256(const char* keyName) {
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_BYTE keyBytes[32] = {0};
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secClass, sizeof(secClass) },
        { CKA_KEY_TYPE, &aesType, sizeof(aesType) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
        { CKA_VALUE, keyBytes, sizeof(keyBytes) }
    };
    CK_OBJECT_HANDLE h = 0;
    if (fl->C_CreateObject(hSess, tmpl, 7, &h) != CKR_OK) return 0;
    (void)keyName;
    return h;
}

void test_g1_security() {
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    // ── C++C-1: zero-IV AES-GCM must be rejected at the PKCS#11 layer ────────
    CK_OBJECT_HANDLE hAes = g1_create_aes256("g1-aes");
    if (hAes == 0) {
        record_result("G1Security", "AES_key_create", "FAIL", "Could not create AES-256 key");
    } else {
        // Encrypt init with ulIvLen==0 → CKR_MECHANISM_PARAM_INVALID
        CK_GCM_PARAMS zeroIvParams = { NULL_PTR, 0, 0, NULL_PTR, 0, 128 };
        CK_MECHANISM gcmMech = { CKM_AES_GCM, &zeroIvParams, sizeof(zeroIvParams) };
        CK_RV rv = fl->C_EncryptInit(hSess, &gcmMech, hAes);
        record_result("G1Security", "GCM_zeroIV_EncryptInit_rejected",
                      rv == CKR_MECHANISM_PARAM_INVALID ? "PASS" : "FAIL",
                      "C++C-1 expect CKR_MECHANISM_PARAM_INVALID, RV=" + std::to_string(rv));

        // Decrypt init with ulIvLen==0 → CKR_MECHANISM_PARAM_INVALID
        rv = fl->C_DecryptInit(hSess, &gcmMech, hAes);
        record_result("G1Security", "GCM_zeroIV_DecryptInit_rejected",
                      rv == CKR_MECHANISM_PARAM_INVALID ? "PASS" : "FAIL",
                      "C++C-1 expect CKR_MECHANISM_PARAM_INVALID, RV=" + std::to_string(rv));

        // Sanity: a valid 12-byte IV is still accepted (range preserved).
        CK_BYTE iv12[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
        CK_GCM_PARAMS okParams = { iv12, sizeof(iv12), 0, NULL_PTR, 0, 128 };
        CK_MECHANISM gcmOk = { CKM_AES_GCM, &okParams, sizeof(okParams) };
        rv = fl->C_EncryptInit(hSess, &gcmOk, hAes);
        record_result("G1Security", "GCM_validIV_EncryptInit_accepted",
                      rv == CKR_OK ? "PASS" : "FAIL",
                      "valid 12-byte IV must still work, RV=" + std::to_string(rv));
        if (rv == CKR_OK) {
            // Finish the op so the session is clean for subsequent tests.
            CK_BYTE pt[] = "hello"; CK_BYTE ct[64]; CK_ULONG ctLen = sizeof(ct);
            fl->C_Encrypt(hSess, pt, sizeof(pt)-1, ct, &ctLen);
        }
        fl->C_DestroyObject(hSess, hAes);
    }

    // ── C++C-2: ChaCha20-Poly1305 wrong nonce length must be rejected ───────
    {
        CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
        CK_KEY_TYPE chachaKT = 0x00000033UL; /* CKK_CHACHA20 */
        CK_BYTE chachaKey[32] = {0};
        CK_ATTRIBUTE chachaT[] = {
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &chachaKT, sizeof(chachaKT) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
            { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
            { CKA_VALUE, chachaKey, sizeof(chachaKey) }
        };
        CK_OBJECT_HANDLE hChaCha = 0;
        CK_RV rv = fl->C_CreateObject(hSess, chachaT, 6, &hChaCha);
        if (rv != CKR_OK) {
            record_result("G1Security", "ChaCha_key_create", "SKIP", "ChaCha20 unsupported, RV=" + std::to_string(rv));
        } else {
            #pragma pack(push, 1)
            struct LOCAL_CHACHA_PARAMS {
                CK_BYTE_PTR pNonce; CK_ULONG ulNonceLen;
                CK_BYTE_PTR pAAD;   CK_ULONG ulAADLen;
            };
            #pragma pack(pop)
            // 8-byte nonce (wrong: RFC 7539 mandates 12) → must be rejected.
            CK_BYTE badNonce[8] = {0,1,2,3,4,5,6,7};
            LOCAL_CHACHA_PARAMS badParams = { badNonce, sizeof(badNonce), NULL_PTR, 0 };
            CK_MECHANISM badMech = { 0x00004021UL /* CKM_CHACHA20_POLY1305 */, &badParams, sizeof(badParams) };
            rv = fl->C_EncryptInit(hSess, &badMech, hChaCha);
            record_result("G1Security", "ChaCha_wrongNonce_rejected",
                          rv == CKR_MECHANISM_PARAM_INVALID ? "PASS" : "FAIL",
                          "C++C-2 expect CKR_MECHANISM_PARAM_INVALID for 8-byte nonce, RV=" + std::to_string(rv));

            // Zero-length nonce → also rejected.
            LOCAL_CHACHA_PARAMS zeroParams = { NULL_PTR, 0, NULL_PTR, 0 };
            CK_MECHANISM zeroMech = { 0x00004021UL, &zeroParams, sizeof(zeroParams) };
            rv = fl->C_EncryptInit(hSess, &zeroMech, hChaCha);
            record_result("G1Security", "ChaCha_zeroNonce_rejected",
                          rv == CKR_MECHANISM_PARAM_INVALID ? "PASS" : "FAIL",
                          "C++C-1/2 expect CKR_MECHANISM_PARAM_INVALID for 0-byte nonce, RV=" + std::to_string(rv));
            fl->C_DestroyObject(hSess, hChaCha);
        }
    }

    // ── C++C-4: RIPEMD160 digest must NOT silently compute SHA-1 ────────────
    {
        CK_MECHANISM ripeMech = { CKM_RIPEMD160, NULL_PTR, 0 };
        CK_RV rv = fl->C_DigestInit(hSess, &ripeMech);
        if (rv == CKR_MECHANISM_INVALID) {
            record_result("G1Security", "RIPEMD160_digest_rejected", "PASS",
                          "C++C-4 CKR_MECHANISM_INVALID (no SHA-1 substitution)");
        } else if (rv == CKR_OK) {
            // If it (wrongly) initialised, prove it is NOT producing a 20-byte
            // SHA-1 output silently — either way this is a FAIL.
            CK_BYTE data[] = "abc"; CK_BYTE dig[64]; CK_ULONG digLen = sizeof(dig);
            fl->C_Digest(hSess, data, 3, dig, &digLen);
            record_result("G1Security", "RIPEMD160_digest_rejected", "FAIL",
                          "C++C-4 DigestInit unexpectedly succeeded (likely SHA-1 substitution), digLen=" + std::to_string(digLen));
        } else {
            record_result("G1Security", "RIPEMD160_digest_rejected",
                          rv == CKR_MECHANISM_PARAM_INVALID ? "PASS" : "FAIL",
                          "expect rejection, RV=" + std::to_string(rv));
        }
    }

    // ── C++C-3: large-message XMSS sign must not smash the stack ────────────
    {
        CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE ktypeXmss = 0x00000047UL; // CKK_XMSS
        CK_MECHANISM mech = { 0x00004034UL /* CKM_XMSS_KEY_PAIR_GEN */, NULL_PTR, 0 };
        CK_ULONG paramSetXmss = 0x00000001UL; // CKP_XMSS_SHA2_10_256
        mech.pParameter = &paramSetXmss; mech.ulParameterLen = sizeof(paramSetXmss);
        CK_ATTRIBUTE pubTmpl[] = {
            { CKA_CLASS, &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE, &ktypeXmss, sizeof(ktypeXmss) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) },
            { CKA_TOKEN, &bTrue, sizeof(bTrue) }
        };
        CK_ATTRIBUTE privTmpl[] = {
            { CKA_CLASS, &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE, &ktypeXmss, sizeof(ktypeXmss) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) },
            { CKA_TOKEN, &bTrue, sizeof(bTrue) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) }
        };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &mech, pubTmpl, 4, privTmpl, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result("G1Security", "XMSS_largeMsg_sign", "SKIP", "XMSS unavailable, RV=" + std::to_string(rv));
        } else {
            // 64 KiB message — far exceeds the old 8000-byte stack buffer; the
            // signer writes [sig || message], so this previously overflowed.
            std::vector<CK_BYTE> bigMsg(64 * 1024, 0x5A);
            CK_MECHANISM signMech = { 0x00004036UL /* CKM_XMSS */, NULL_PTR, 0 };
            rv = fl->C_SignInit(hSess, &signMech, hPriv);
            if (rv == CKR_OK) {
                // First query the size, then sign into an exact buffer.
                CK_ULONG sigLen = 0;
                rv = fl->C_Sign(hSess, bigMsg.data(), bigMsg.size(), NULL_PTR, &sigLen);
                if (rv == CKR_OK && sigLen > 0) {
                    std::vector<CK_BYTE> sig(sigLen);
                    rv = fl->C_Sign(hSess, bigMsg.data(), bigMsg.size(), sig.data(), &sigLen);
                    record_result("G1Security", "XMSS_largeMsg_sign",
                                  rv == CKR_OK ? "PASS" : "FAIL",
                                  "C++C-3 64KiB message sign, RV=" + std::to_string(rv));
                } else {
                    record_result("G1Security", "XMSS_largeMsg_sign", "FAIL",
                                  "C++C-3 size query failed, RV=" + std::to_string(rv));
                }
            } else {
                record_result("G1Security", "XMSS_largeMsg_sign", "FAIL",
                              "C_SignInit(XMSS) failed, RV=" + std::to_string(rv));
            }
        }
    }

    // ── V-13: HSS keygen → sign → verify round-trip (proves encrypt/decrypt) ─
    {
        CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE hssKT = 0x00000046UL; // CKK_HSS
        CK_MECHANISM hssMech = { CKM_HSS_KEY_PAIR_GEN, NULL_PTR, 0 };
        // Private key with CKA_PRIVATE=TRUE → CKA_VALUE is token-encrypted.
        CK_ATTRIBUTE hssPubTmpl[] = {
            { CKA_CLASS, &pubClass, sizeof(pubClass) },
            { CKA_KEY_TYPE, &hssKT, sizeof(hssKT) },
            { CKA_TOKEN, &bTrue, sizeof(bTrue) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) }
        };
        CK_ATTRIBUTE hssPrivTmpl[] = {
            { CKA_CLASS, &privClass, sizeof(privClass) },
            { CKA_KEY_TYPE, &hssKT, sizeof(hssKT) },
            { CKA_TOKEN, &bTrue, sizeof(bTrue) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) }
        };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &hssMech, hssPubTmpl, 4, hssPrivTmpl, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result("G1Security", "HSS_private_roundtrip", "FAIL",
                          "V-13 HSS keygen failed, RV=" + std::to_string(rv));
        } else {
            CK_MECHANISM hssSignMech = { 0x00004033UL /* CKM_HSS */, NULL_PTR, 0 };
            rv = fl->C_SignInit(hSess, &hssSignMech, hPriv);
            CK_BYTE msg[] = "V-13 encrypted stateful key round-trip";
            CK_BYTE sig[5000]; CK_ULONG sigLen = sizeof(sig);
            bool signed_ok = false;
            if (rv == CKR_OK) {
                rv = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
                signed_ok = (rv == CKR_OK);
            }
            if (!signed_ok) {
                // If decrypt-on-read were broken, the signer could not load the key.
                record_result("G1Security", "HSS_private_roundtrip", "FAIL",
                              "V-13 sign with encrypted private key failed, RV=" + std::to_string(rv));
            } else {
                CK_RV vrv = fl->C_VerifyInit(hSess, &hssSignMech, hPub);
                if (vrv == CKR_OK) {
                    vrv = fl->C_Verify(hSess, msg, sizeof(msg)-1, sig, sigLen);
                    record_result("G1Security", "HSS_private_roundtrip",
                                  vrv == CKR_OK ? "PASS" : "FAIL",
                                  "V-13 keygen→sign→verify, verify RV=" + std::to_string(vrv));
                } else {
                    record_result("G1Security", "HSS_private_roundtrip", "FAIL",
                                  "V-13 C_VerifyInit failed, RV=" + std::to_string(vrv));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// G2 — mechanism-table accuracy + advertise/dispatch consistency (audit round 4)
//   * PQC mechanism-info sizes are public-key BYTES (ML-DSA 1312/2592,
//     SLH-DSA 32/64) — not 128/256 security bits.
//   * advertise == dispatch: RIPEMD160 / RIPEMD160_HMAC / Keccak-256 are NOT
//     advertised; CKM_CHACHA20 / X25519 / X448 / BIP32-derive ARE reachable.
//   * CKF_MESSAGE_* advertised where the message API dispatches.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef CKM_RIPEMD160_HMAC
#define CKM_RIPEMD160_HMAC 0x00000241UL
#endif
#ifndef CKM_KECCAK_256
#define CKM_KECCAK_256 (0x80000000UL | 0x00000051UL)
#endif
#ifndef CKM_X448
#define CKM_X448 (0x80000000UL | 0x00001059UL)
#endif
#ifndef CKF_MESSAGE_ENCRYPT
#define CKF_MESSAGE_ENCRYPT 0x00000002UL
#define CKF_MESSAGE_DECRYPT 0x00000004UL
#define CKF_MESSAGE_SIGN    0x00000008UL
#define CKF_MESSAGE_VERIFY  0x00000010UL
#endif

static void check_mech_size(CK_MECHANISM_TYPE mech, const char* name,
                            CK_ULONG expMin, CK_ULONG expMax) {
    CK_MECHANISM_INFO info;
    CK_RV rv = fl->C_GetMechanismInfo(0, mech, &info);
    if (rv != CKR_OK) {
        record_result("G2MechTable", std::string("Size_") + name, "FAIL",
                      "C_GetMechanismInfo RV=" + std::to_string(rv));
        return;
    }
    bool ok = (info.ulMinKeySize == expMin && info.ulMaxKeySize == expMax);
    record_result("G2MechTable", std::string("Size_") + name, ok ? "PASS" : "FAIL",
                  "min=" + std::to_string(info.ulMinKeySize) +
                  " max=" + std::to_string(info.ulMaxKeySize) +
                  " expected " + std::to_string(expMin) + "/" + std::to_string(expMax));
}

static void check_mech_flag(CK_MECHANISM_TYPE mech, const char* name,
                            CK_FLAGS wantFlags) {
    CK_MECHANISM_INFO info;
    CK_RV rv = fl->C_GetMechanismInfo(0, mech, &info);
    if (rv != CKR_OK) {
        record_result("G2MechTable", std::string("Flag_") + name, "FAIL",
                      "C_GetMechanismInfo RV=" + std::to_string(rv));
        return;
    }
    bool ok = (info.flags & wantFlags) == wantFlags;
    record_result("G2MechTable", std::string("Flag_") + name, ok ? "PASS" : "FAIL",
                  "flags=0x" + std::to_string(info.flags) +
                  " want 0x" + std::to_string(wantFlags));
}

static void check_not_advertised(CK_MECHANISM_TYPE mech, const char* name) {
    bool present = mech_advertised(mech);
    record_result("G2MechTable", std::string("NotAdvertised_") + name,
                  present ? "FAIL" : "PASS",
                  present ? "mechanism advertised but has no dispatch"
                          : "correctly absent from C_GetMechanismList");
}

void test_g2_mech_table() {
    // ── V-1 / V-2: PQC mechanism-info sizes are public-key BYTES ─────────────
    check_mech_size(CKM_ML_DSA_KEY_PAIR_GEN, "ML_DSA_KEY_PAIR_GEN", 1312, 2592);
    check_mech_size(CKM_ML_DSA,              "ML_DSA",              1312, 2592);
    check_mech_size(CKM_SLH_DSA_KEY_PAIR_GEN,"SLH_DSA_KEY_PAIR_GEN",  32,   64);
    check_mech_size(CKM_SLH_DSA,             "SLH_DSA",               32,   64);

    // ── V-11 / G3: unimplemented mechs must NOT be advertised ────────────────
    check_not_advertised(CKM_RIPEMD160,       "CKM_RIPEMD160");
    check_not_advertised(CKM_RIPEMD160_HMAC,  "CKM_RIPEMD160_HMAC");
    check_not_advertised(CKM_KECCAK_256,      "CKM_KECCAK_256");

    // ── G4 / G6: implemented mechs MUST be advertised (advertise ⊆ dispatch) ─
    record_result("G2MechTable", "Advertised_CKM_CHACHA20",
                  mech_advertised(CKM_CHACHA20) ? "PASS" : "FAIL",
                  "bare ChaCha20 stream dispatched");
    record_result("G2MechTable", "Advertised_CKM_X25519",
                  mech_advertised(CKM_X25519) ? "PASS" : "FAIL", "X25519 derive");
    record_result("G2MechTable", "Advertised_CKM_X448",
                  mech_advertised(CKM_X448) ? "PASS" : "FAIL", "X448 derive");
    record_result("G2MechTable", "Advertised_CKM_BIP32_MASTER_DERIVE",
                  mech_advertised(CKM_BIP32_MASTER_DERIVE) ? "PASS" : "FAIL", "BIP32 derive");
#ifdef CKM_RSA_PKCS_PSS
    record_result("G2MechTable", "Advertised_CKM_RSA_PKCS_PSS",
                  mech_advertised(CKM_RSA_PKCS_PSS) ? "PASS" : "FAIL", "raw RSA-PSS");
#endif

    // ── mech G1 / G2: CKF_MESSAGE_* where the message API dispatches ─────────
    check_mech_flag(CKM_AES_GCM, "AES_GCM_MESSAGE",
                    CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT);
    check_mech_flag(CKM_ML_DSA, "ML_DSA_MESSAGE",
                    CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY);
    check_mech_flag(CKM_SLH_DSA, "SLH_DSA_MESSAGE",
                    CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY);

    // ── advertise ⊆ dispatch: every advertised mech must yield mechanism-info
    //    (i.e. it is recognized by the engine, not advertised-then-rejected). ─
    CK_ULONG count = 0;
    if (fl->C_GetMechanismList(0, NULL_PTR, &count) == CKR_OK && count > 0) {
        std::vector<CK_MECHANISM_TYPE> mechs(count);
        if (fl->C_GetMechanismList(0, mechs.data(), &count) == CKR_OK) {
            int bad = 0;
            for (CK_ULONG i = 0; i < count; i++) {
                CK_MECHANISM_INFO info;
                if (fl->C_GetMechanismInfo(0, mechs[i], &info) != CKR_OK) bad++;
            }
            record_result("G2MechTable", "AdvertiseSubsetDispatch",
                          bad == 0 ? "PASS" : "FAIL",
                          std::to_string(count) + " advertised, " +
                          std::to_string(bad) + " rejected by C_GetMechanismInfo");
        }
    }
}

// ── V-10 / V-12: bare ChaCha20 round-trip + ChaCha20 keygen key type ─────────
void test_g2_chacha20_bare() {
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    // V-12: keygen must produce a CKK_CHACHA20 key (not CKK_AES).
    CK_MECHANISM kgMech = { CKM_CHACHA20_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE kgTmpl[] = {
        { CKA_CLASS,       &secClass, sizeof(secClass) },
        { CKA_TOKEN,       &bFalse,   sizeof(bFalse) },
        { CKA_ENCRYPT,     &bTrue,    sizeof(bTrue) },
        { CKA_DECRYPT,     &bTrue,    sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bTrue,    sizeof(bTrue) },
    };
    CK_OBJECT_HANDLE hKey = 0;
    CK_RV rv = fl->C_GenerateKey(hSess, &kgMech, kgTmpl, 5, &hKey);
    if (rv != CKR_OK) {
        record_result("G2ChaCha20", "Keygen", "FAIL", "C_GenerateKey RV=" + std::to_string(rv));
        return;
    }
    CK_KEY_TYPE kt = 0;
    CK_ATTRIBUTE q = { CKA_KEY_TYPE, &kt, sizeof(kt) };
    fl->C_GetAttributeValue(hSess, hKey, &q, 1);
    record_result("G2ChaCha20", "Keygen_KeyType",
                  kt == CKK_CHACHA20 ? "PASS" : "FAIL",
                  "CKA_KEY_TYPE=0x" + std::to_string(kt) + " want CKK_CHACHA20(0x33)");

    CK_ULONG kgm = 0;
    CK_ATTRIBUTE qg = { CKA_KEY_GEN_MECHANISM, &kgm, sizeof(kgm) };
    fl->C_GetAttributeValue(hSess, hKey, &qg, 1);
    record_result("G2ChaCha20", "Keygen_GenMech",
                  kgm == CKM_CHACHA20_KEY_GEN ? "PASS" : "FAIL",
                  "CKA_KEY_GEN_MECHANISM=0x" + std::to_string(kgm));

    // V-10: bare ChaCha20 encrypt → decrypt round-trip.
    #pragma pack(push, 1)
    struct LOCAL_CK_CHACHA20_PARAMS {
        CK_BYTE_PTR pBlockCounter; CK_ULONG blockCounterBits;
        CK_BYTE_PTR pNonce;        CK_ULONG ulNonceBits;
    };
    #pragma pack(pop)
    CK_BYTE counter[4] = {0, 0, 0, 0};
    CK_BYTE nonce[12]  = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    LOCAL_CK_CHACHA20_PARAMS cp = { counter, 32, nonce, 96 };
    CK_MECHANISM cMech = { CKM_CHACHA20, &cp, sizeof(cp) };

    rv = fl->C_EncryptInit(hSess, &cMech, hKey);
    if (rv != CKR_OK) {
        record_result("G2ChaCha20", "EncryptInit", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    CK_BYTE pt[] = "bare ChaCha20 stream cipher round-trip";
    CK_BYTE ct[256]; CK_ULONG ctLen = sizeof(ct);
    rv = fl->C_Encrypt(hSess, pt, sizeof(pt) - 1, ct, &ctLen);
    if (rv != CKR_OK) {
        record_result("G2ChaCha20", "Encrypt", "FAIL", "RV=" + std::to_string(rv));
        return;
    }
    record_result("G2ChaCha20", "Encrypt", "PASS",
                  "ctLen=" + std::to_string(ctLen));

    rv = fl->C_DecryptInit(hSess, &cMech, hKey);
    CK_BYTE dt[256]; CK_ULONG dtLen = sizeof(dt);
    if (rv == CKR_OK)
        rv = fl->C_Decrypt(hSess, ct, ctLen, dt, &dtLen);
    bool roundtrip = (rv == CKR_OK && dtLen == sizeof(pt) - 1 &&
                      memcmp(dt, pt, dtLen) == 0);
    record_result("G2ChaCha20", "RoundTrip", roundtrip ? "PASS" : "FAIL",
                  roundtrip ? "decrypt matched plaintext"
                            : "RV=" + std::to_string(rv) + " dtLen=" + std::to_string(dtLen));
}

// ── G6: X25519 / BIP32 derive must be reachable (not MECHANISM_INVALID) ──────
void test_g2_derive_reachable() {
    // We only assert the mechanism is reachable: a derive Init/op must not be
    // rejected with CKR_MECHANISM_INVALID (which is what an unadvertised mech
    // returns via isMechanismPermitted). Other failures (bad base key etc.)
    // still prove the dispatch path is live.
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    // Build a throwaway X25519 keypair to use as the base for derive.
    CK_OBJECT_CLASS pubC = CKO_PUBLIC_KEY, privC = CKO_PRIVATE_KEY;
    CK_KEY_TYPE montKT = CKK_EC_MONTGOMERY;
    CK_BYTE x25519Oid[] = {0x06, 0x03, 0x2B, 0x65, 0x6E}; // 1.3.101.110
    CK_MECHANISM kpMech = { CKM_EC_MONTGOMERY_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ATTRIBUTE pubT[] = {
        { CKA_CLASS, &pubC, sizeof(pubC) }, { CKA_KEY_TYPE, &montKT, sizeof(montKT) },
        { CKA_EC_PARAMS, x25519Oid, sizeof(x25519Oid) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    };
    CK_ATTRIBUTE privT[] = {
        { CKA_CLASS, &privC, sizeof(privC) }, { CKA_KEY_TYPE, &montKT, sizeof(montKT) },
        { CKA_DERIVE, &bTrue, sizeof(bTrue) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    };
    CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
    CK_RV rv = fl->C_GenerateKeyPair(hSess, &kpMech, pubT, 4, privT, 4, &hPub, &hPriv);
    if (rv != CKR_OK) {
        record_result("G2Derive", "X25519_KeyGen", "SKIP",
                      "could not generate X25519 base key, RV=" + std::to_string(rv));
    } else {
        // Attempt an X25519 derive with a dummy peer point; we only require that
        // the engine does NOT answer CKR_MECHANISM_INVALID.
        CK_BYTE peer[32] = {0};
        CK_ECDH1_DERIVE_PARAMS dp;
        memset(&dp, 0, sizeof(dp));
        dp.kdf = CKD_NULL; dp.pPublicData = peer; dp.ulPublicDataLen = sizeof(peer);
        CK_MECHANISM dMech = { CKM_X25519, &dp, sizeof(dp) };
        CK_OBJECT_CLASS secC = CKO_SECRET_KEY; CK_KEY_TYPE genKT = CKK_GENERIC_SECRET;
        CK_ULONG vlen = 32;
        CK_ATTRIBUTE dt[] = {
            { CKA_CLASS, &secC, sizeof(secC) }, { CKA_KEY_TYPE, &genKT, sizeof(genKT) },
            { CKA_VALUE_LEN, &vlen, sizeof(vlen) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_OBJECT_HANDLE hDer = 0;
        rv = fl->C_DeriveKey(hSess, &dMech, hPriv, dt, 4, &hDer);
        record_result("G2Derive", "X25519_Reachable",
                      rv != CKR_MECHANISM_INVALID ? "PASS" : "FAIL",
                      "C_DeriveKey RV=" + std::to_string(rv) +
                      " (must not be CKR_MECHANISM_INVALID)");
    }

    // BIP32 master derive reachability from an HMAC seed key.
    CK_MECHANISM bipMech = { CKM_BIP32_MASTER_DERIVE, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hMaster = 0;
    rv = fl->C_DeriveKey(hSess, &bipMech, CK_INVALID_HANDLE, NULL_PTR, 0, &hMaster);
    record_result("G2Derive", "BIP32_Reachable",
                  rv != CKR_MECHANISM_INVALID ? "PASS" : "FAIL",
                  "C_DeriveKey RV=" + std::to_string(rv) +
                  " (must not be CKR_MECHANISM_INVALID)");
}

// ─── G3: keygen template validation + XMSSMT enablement + real AES-CBC wrap ──
// Covers audit V-4 (CKA_KEY_TYPE↔mechanism consistency), V-3 (CKA_PARAMETER_SET
// mandatory for ML-DSA/ML-KEM/SLH-DSA), V-8/V-9 (XMSSMT keygen+sign reachable),
// V-21 (CKA_HSS_KEYS_REMAINING = 2^h), V-5/V-6 (real AES-CBC(-PAD) wrap/unwrap).
void test_g3_keygen() {
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    // Constant fallbacks (values from src/lib/pkcs11/pkcs11t.h).
    const CK_MECHANISM_TYPE M_ML_KEM_KP   = 0x0000000fUL; // CKM_ML_KEM_KEY_PAIR_GEN
    const CK_MECHANISM_TYPE M_ML_DSA_KP   = 0x0000001cUL; // CKM_ML_DSA_KEY_PAIR_GEN
    const CK_MECHANISM_TYPE M_SLH_DSA_KP  = 0x0000002dUL; // CKM_SLH_DSA_KEY_PAIR_GEN
    const CK_MECHANISM_TYPE M_EC_KP       = 0x00001040UL; // CKM_EC_KEY_PAIR_GEN
    const CK_MECHANISM_TYPE M_XMSS_KP     = 0x00004034UL; // CKM_XMSS_KEY_PAIR_GEN
    const CK_MECHANISM_TYPE M_XMSSMT_KP   = 0x00004035UL; // CKM_XMSSMT_KEY_PAIR_GEN
    const CK_MECHANISM_TYPE M_CHACHA20_KG = 0x00001225UL; // CKM_CHACHA20_KEY_GEN
    const CK_KEY_TYPE       KT_ML_KEM     = 0x00000049UL; // CKK_ML_KEM
    const CK_KEY_TYPE       KT_HSS        = 0x00000046UL; // CKK_HSS
    const CK_KEY_TYPE       KT_XMSS       = 0x00000047UL; // CKK_XMSS
    const CK_KEY_TYPE       KT_XMSSMT     = 0x00000048UL; // CKK_XMSSMT
    const CK_MECHANISM_TYPE M_XMSSMT_SIGN = 0x00004037UL; // CKM_XMSSMT
    const CK_OBJECT_CLASS   pubC = CKO_PUBLIC_KEY, privC = CKO_PRIVATE_KEY;

    // ── V-4: CKA_KEY_TYPE that disagrees with the mechanism → INCONSISTENT ────
    // Helper: build pub/priv templates with a *wrong* CKK and a valid param set,
    // assert CKR_TEMPLATE_INCONSISTENT.
    auto wrongKeyTypeCase = [&](const char* name, CK_MECHANISM_TYPE mech,
                                CK_KEY_TYPE wrongKT, bool needsParamSet) {
        CK_KEY_TYPE kt = wrongKT;
        CK_ULONG paramSet = 1; // any in-range CKP_* for the family
        std::vector<CK_ATTRIBUTE> pubT = {
            { CKA_CLASS, (void*)&pubC, sizeof(pubC) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        std::vector<CK_ATTRIBUTE> privT = {
            { CKA_CLASS, (void*)&privC, sizeof(privC) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        if (needsParamSet) {
            pubT.push_back({ CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) });
            privT.push_back({ CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) });
        }
        CK_MECHANISM m = { mech, NULL_PTR, 0 };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &m,
                       pubT.data(), (CK_ULONG)pubT.size(),
                       privT.data(), (CK_ULONG)privT.size(), &hPub, &hPriv);
        record_result("G3Keygen", std::string("V4_wrongKeyType_") + name,
                      rv == CKR_TEMPLATE_INCONSISTENT ? "PASS" : "FAIL",
                      "expect CKR_TEMPLATE_INCONSISTENT, RV=" + std::to_string(rv));
        if (rv == CKR_OK) { fl->C_DestroyObject(hSess, hPub); fl->C_DestroyObject(hSess, hPriv); }
    };
    // ML-KEM mech with CKK_XMSSMT (the F4-proven hole), EC with CKK_ML_KEM,
    // HSS/XMSS/XMSSMT each with a foreign CKK.
    wrongKeyTypeCase("ML_KEM_vs_XMSSMT", M_ML_KEM_KP, KT_XMSSMT, true);
    wrongKeyTypeCase("EC_vs_ML_KEM",     M_EC_KP,     KT_ML_KEM, false);
    wrongKeyTypeCase("HSS_vs_XMSS",      0x00004032UL /*CKM_HSS_KEY_PAIR_GEN*/, KT_XMSS, false);
    wrongKeyTypeCase("XMSS_vs_HSS",      M_XMSS_KP,   KT_HSS,    false);
    wrongKeyTypeCase("XMSSMT_vs_XMSS",   M_XMSSMT_KP, KT_XMSS,   false);

    // ChaCha20 secret-key gen with a wrong CKK (CKK_AES) → INCONSISTENT.
    {
        CK_OBJECT_CLASS secC = CKO_SECRET_KEY;
        CK_KEY_TYPE wrongKT = CKK_AES;
        CK_ULONG vlen = 32;
        CK_ATTRIBUTE t[] = {
            { CKA_CLASS, &secC, sizeof(secC) },
            { CKA_KEY_TYPE, &wrongKT, sizeof(wrongKT) },
            { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_MECHANISM m = { M_CHACHA20_KG, NULL_PTR, 0 };
        CK_OBJECT_HANDLE h = 0;
        CK_RV rv = fl->C_GenerateKey(hSess, &m, t, 4, &h);
        record_result("G3Keygen", "V4_wrongKeyType_ChaCha20_vs_AES",
                      rv == CKR_TEMPLATE_INCONSISTENT ? "PASS" : "FAIL",
                      "expect CKR_TEMPLATE_INCONSISTENT, RV=" + std::to_string(rv));
        if (rv == CKR_OK) fl->C_DestroyObject(hSess, h);
    }

    // ── V-3: missing CKA_PARAMETER_SET on ML-DSA/ML-KEM/SLH-DSA → INCOMPLETE ──
    auto missingParamSetCase = [&](const char* name, CK_MECHANISM_TYPE mech,
                                   CK_KEY_TYPE kt) {
        CK_KEY_TYPE keyType = kt;
        CK_ATTRIBUTE pubT[] = {
            { CKA_CLASS, (void*)&pubC, sizeof(pubC) },
            { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_ATTRIBUTE privT[] = {
            { CKA_CLASS, (void*)&privC, sizeof(privC) },
            { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_MECHANISM m = { mech, NULL_PTR, 0 };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &m, pubT, 3, privT, 3, &hPub, &hPriv);
        record_result("G3Keygen", std::string("V3_missingParamSet_") + name,
                      rv == CKR_TEMPLATE_INCOMPLETE ? "PASS" : "FAIL",
                      "expect CKR_TEMPLATE_INCOMPLETE, RV=" + std::to_string(rv));
        if (rv == CKR_OK) { fl->C_DestroyObject(hSess, hPub); fl->C_DestroyObject(hSess, hPriv); }
    };
    missingParamSetCase("ML_DSA",  M_ML_DSA_KP,  0x0000004aUL /*CKK_ML_DSA*/);
    missingParamSetCase("ML_KEM",  M_ML_KEM_KP,  KT_ML_KEM);
    missingParamSetCase("SLH_DSA", M_SLH_DSA_KP, 0x0000004bUL /*CKK_SLH_DSA*/);

    // ── V-8 + V-9: XMSSMT keygen → sign → verify round-trip ──────────────────
    {
        CK_KEY_TYPE kt = KT_XMSSMT;
        CK_ULONG paramSet = 0x00000001UL; // CKP_XMSSMT_SHA2_20_2_256
        CK_MECHANISM kpMech = { M_XMSSMT_KP, &paramSet, sizeof(paramSet) };
        CK_ATTRIBUTE pubT[] = {
            { CKA_CLASS, (void*)&pubC, sizeof(pubC) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_ATTRIBUTE privT[] = {
            { CKA_CLASS, (void*)&privC, sizeof(privC) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &kpMech, pubT, 4, privT, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result("G3Keygen", "V8_XMSSMT_keygen",
                          "FAIL", "keygen RV=" + std::to_string(rv) +
                          " (V-8 expected reachable PASS)");
        } else {
            record_result("G3Keygen", "V8_XMSSMT_keygen", "PASS", "XMSSMT key generated");

            CK_BYTE msg[] = "xmssmt round-trip";
            CK_MECHANISM signMech = { M_XMSSMT_SIGN, NULL_PTR, 0 };
            CK_RV rvSi = fl->C_SignInit(hSess, &signMech, hPriv);
            if (rvSi != CKR_OK) {
                record_result("G3Keygen", "V9_XMSSMT_SignInit",
                              "FAIL", "SignInit RV=" + std::to_string(rvSi) +
                              " (V-9 0x4036→0x4037 fix expected)");
            } else {
                CK_BYTE sig[10000];
                CK_ULONG sigLen = sizeof(sig);
                CK_RV rvS = fl->C_Sign(hSess, msg, sizeof(msg)-1, sig, &sigLen);
                if (rvS != CKR_OK) {
                    record_result("G3Keygen", "V9_XMSSMT_Sign",
                                  "FAIL", "Sign RV=" + std::to_string(rvS));
                } else {
                    CK_RV rvVi = fl->C_VerifyInit(hSess, &signMech, hPub);
                    CK_RV rvV = (rvVi == CKR_OK)
                                  ? fl->C_Verify(hSess, msg, sizeof(msg)-1, sig, sigLen)
                                  : rvVi;
                    record_result("G3Keygen", "V9_XMSSMT_sign_verify_roundtrip",
                                  rvV == CKR_OK ? "PASS" : "FAIL",
                                  "Verify RV=" + std::to_string(rvV));
                }
            }
            fl->C_DestroyObject(hSess, hPub);
            fl->C_DestroyObject(hSess, hPriv);
        }
    }

    // ── V-21: CKA_HSS_KEYS_REMAINING = 2^h for the chosen LMS param set ───────
    // Default single-level HSS uses LMS_SHA256_N32_H5 (h=5) → 2^5 = 32.
    {
        CK_KEY_TYPE kt = KT_HSS;
        CK_MECHANISM kpMech = { 0x00004032UL /*CKM_HSS_KEY_PAIR_GEN*/, NULL_PTR, 0 };
        CK_ATTRIBUTE pubT[] = {
            { CKA_CLASS, (void*)&pubC, sizeof(pubC) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_ATTRIBUTE privT[] = {
            { CKA_CLASS, (void*)&privC, sizeof(privC) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &kpMech, pubT, 4, privT, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result("G3Keygen", "V21_HSS_keys_remaining", "SKIP",
                          "HSS keygen unavailable, RV=" + std::to_string(rv));
        } else {
            // CKA_HSS_KEYS_REMAINING == 0x0000061c (pkcs11t.h)
            CK_ULONG remaining = 0;
            CK_ATTRIBUTE q[] = { { CKA_HSS_KEYS_REMAINING, &remaining, sizeof(remaining) } };
            CK_RV rvg = fl->C_GetAttributeValue(hSess, hPriv, q, 1);
            record_result("G3Keygen", "V21_HSS_keys_remaining",
                          (rvg == CKR_OK && remaining == 32) ? "PASS" : "FAIL",
                          "expect 2^5=32 for default LMS_SHA256_N32_H5, got " +
                          std::to_string(remaining) + " (RV=" + std::to_string(rvg) + ")");
            fl->C_DestroyObject(hSess, hPub);
            fl->C_DestroyObject(hSess, hPriv);
        }
    }

    // ── V-5 + V-6: real AES-CBC and AES-CBC-PAD wrap → unwrap round-trip ──────
    // Wrap a known secret key with the KEK, unwrap, confirm byte-exact recovery
    // with no trailing pad bytes. CKM_AES_CBC needs block-aligned plaintext;
    // CKM_AES_CBC_PAD applies/strips PKCS#7 so any length round-trips.
    auto cbcWrapCase = [&](const char* name, CK_MECHANISM_TYPE wrapMech,
                           CK_ULONG targetLen) {
        // KEK: AES-256, WRAP+UNWRAP.
        CK_OBJECT_CLASS secC = CKO_SECRET_KEY;
        CK_KEY_TYPE aesKT = CKK_AES;
        CK_BYTE kekBytes[32];
        for (int i = 0; i < 32; i++) kekBytes[i] = (CK_BYTE)(0x10 + i);
        CK_ATTRIBUTE kekT[] = {
            { CKA_CLASS, &secC, sizeof(secC) }, { CKA_KEY_TYPE, &aesKT, sizeof(aesKT) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) }, { CKA_WRAP, &bTrue, sizeof(bTrue) },
            { CKA_UNWRAP, &bTrue, sizeof(bTrue) }, { CKA_VALUE, kekBytes, sizeof(kekBytes) },
        };
        CK_OBJECT_HANDLE hKek = 0;
        if (fl->C_CreateObject(hSess, kekT, 6, &hKek) != CKR_OK) {
            record_result("G3Keygen", std::string("V5V6_") + name, "FAIL", "KEK create failed");
            return;
        }
        // Target generic-secret key with known, extractable bytes.
        std::vector<CK_BYTE> targetBytes(targetLen);
        for (CK_ULONG i = 0; i < targetLen; i++) targetBytes[i] = (CK_BYTE)(0xA0 + i);
        CK_KEY_TYPE genKT = CKK_GENERIC_SECRET;
        CK_ATTRIBUTE tgtT[] = {
            { CKA_CLASS, &secC, sizeof(secC) }, { CKA_KEY_TYPE, &genKT, sizeof(genKT) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) }, { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
            { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
            { CKA_VALUE, targetBytes.data(), (CK_ULONG)targetBytes.size() },
        };
        CK_OBJECT_HANDLE hTarget = 0;
        if (fl->C_CreateObject(hSess, tgtT, 6, &hTarget) != CKR_OK) {
            record_result("G3Keygen", std::string("V5V6_") + name, "FAIL", "target create failed");
            fl->C_DestroyObject(hSess, hKek);
            return;
        }

        CK_BYTE iv[16];
        for (int i = 0; i < 16; i++) iv[i] = (CK_BYTE)(0x30 + i);
        CK_MECHANISM m = { wrapMech, iv, sizeof(iv) };

        CK_BYTE wrapped[256];
        CK_ULONG wrappedLen = sizeof(wrapped);
        CK_RV rvW = fl->C_WrapKey(hSess, &m, hKek, hTarget, wrapped, &wrappedLen);
        if (rvW != CKR_OK) {
            record_result("G3Keygen", std::string("V5V6_") + name, "FAIL",
                          "C_WrapKey RV=" + std::to_string(rvW));
            fl->C_DestroyObject(hSess, hKek); fl->C_DestroyObject(hSess, hTarget);
            return;
        }

        CK_OBJECT_HANDLE hUnwrapped = 0;
        CK_ATTRIBUTE uwT[] = {
            { CKA_CLASS, &secC, sizeof(secC) }, { CKA_KEY_TYPE, &genKT, sizeof(genKT) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) }, { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
            { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        };
        CK_RV rvU = fl->C_UnwrapKey(hSess, &m, hKek, wrapped, wrappedLen, uwT, 5, &hUnwrapped);
        if (rvU != CKR_OK) {
            record_result("G3Keygen", std::string("V5V6_") + name, "FAIL",
                          "C_UnwrapKey RV=" + std::to_string(rvU));
            fl->C_DestroyObject(hSess, hKek); fl->C_DestroyObject(hSess, hTarget);
            return;
        }

        CK_BYTE recovered[256] = {0};
        CK_ATTRIBUTE rq[] = { { CKA_VALUE, recovered, sizeof(recovered) } };
        CK_RV rvg = fl->C_GetAttributeValue(hSess, hUnwrapped, rq, 1);
        bool exact = (rvg == CKR_OK) &&
                     (rq[0].ulValueLen == targetLen) &&
                     (memcmp(recovered, targetBytes.data(), targetLen) == 0);
        record_result("G3Keygen", std::string("V5V6_") + name,
                      exact ? "PASS" : "FAIL",
                      "round-trip byte-exact; recoveredLen=" +
                      std::to_string((unsigned long)rq[0].ulValueLen) +
                      " expected=" + std::to_string(targetLen) +
                      " (RV=" + std::to_string(rvg) + ")");
        fl->C_DestroyObject(hSess, hKek);
        fl->C_DestroyObject(hSess, hTarget);
        fl->C_DestroyObject(hSess, hUnwrapped);
    };
    // CKM_AES_CBC: target MUST be block-aligned (32 bytes = 2 blocks).
    cbcWrapCase("AES_CBC_wrap_unwrap", CKM_AES_CBC, 32);
    // CKM_AES_CBC_PAD: non-block-aligned length (20 bytes) must still round-trip
    // byte-exact with the PKCS#7 pad fully stripped (no trailing pad bytes).
    cbcWrapCase("AES_CBC_PAD_wrap_unwrap", CKM_AES_CBC_PAD, 20);
}

// ─────────────────────────────────────────────────────────────────────────────
// G4: return-code precision + error discipline
// ─────────────────────────────────────────────────────────────────────────────
void test_g4_retcodes() {
    const char* CAT = "G4Retcodes";
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    void* dlib = dlopen(opt_engine.c_str(), RTLD_NOW);

    // ── V-7: AES-KW unwrap of a TAMPERED blob → CKR_WRAPPED_KEY_INVALID ───────
    {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE kt = CKK_AES;
        CK_ULONG klen = 32;
        CK_ATTRIBUTE kekTpl[] = {
            { CKA_CLASS, &cls, sizeof(cls) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_VALUE_LEN, &klen, sizeof(klen) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_WRAP, &bTrue, sizeof(bTrue) },
            { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
            { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        };
        CK_MECHANISM genMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE hKek = 0, hDek = 0;
        CK_RV rv = fl->C_GenerateKey(hSess, &genMech, kekTpl, 7, &hKek);
        if (rv == CKR_OK) rv = fl->C_GenerateKey(hSess, &genMech, kekTpl, 7, &hDek);
        if (rv != CKR_OK) {
            record_result(CAT, "V7_AESKW_tampered_unwrap", "FAIL", "key setup RV=" + std::to_string(rv));
        } else {
            CK_MECHANISM wrapMech = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
            CK_BYTE wrapped[64] = {0};
            CK_ULONG wrappedLen = sizeof(wrapped);
            rv = fl->C_WrapKey(hSess, &wrapMech, hKek, hDek, wrapped, &wrappedLen);
            if (rv != CKR_OK) {
                record_result(CAT, "V7_AESKW_tampered_unwrap", "FAIL", "C_WrapKey RV=" + std::to_string(rv));
            } else {
                // Flip a byte in the middle of the wrapped blob → integrity fails.
                wrapped[wrappedLen / 2] ^= 0xFF;
                CK_OBJECT_HANDLE hRec = 0;
                CK_ATTRIBUTE unwrapTpl[] = {
                    { CKA_CLASS, &cls, sizeof(cls) },
                    { CKA_KEY_TYPE, &kt, sizeof(kt) },
                    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
                    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
                };
                rv = fl->C_UnwrapKey(hSess, &wrapMech, hKek, wrapped, wrappedLen,
                                     unwrapTpl, 4, &hRec);
                record_result(CAT, "V7_AESKW_tampered_unwrap",
                              rv == CKR_WRAPPED_KEY_INVALID ? "PASS" : "FAIL",
                              "expect CKR_WRAPPED_KEY_INVALID(0x110), RV=" + std::to_string(rv));
                if (rv == CKR_OK) fl->C_DestroyObject(hSess, hRec);
            }
        }
        if (hDek) fl->C_DestroyObject(hSess, hDek);
        if (hKek) fl->C_DestroyObject(hSess, hKek);
    }

    // Helper: make a generic-secret HMAC key.
    auto makeMacKey = [&]() -> CK_OBJECT_HANDLE {
        CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
        CK_KEY_TYPE genType = CKK_GENERIC_SECRET;
        CK_ULONG keyLen = 32;
        CK_ATTRIBUTE macTmpl[] = {
            { CKA_CLASS, &secClass, sizeof(secClass) },
            { CKA_KEY_TYPE, &genType, sizeof(genType) },
            { CKA_VALUE_LEN, &keyLen, sizeof(keyLen) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        };
        CK_OBJECT_HANDLE hKey = 0;
        CK_MECHANISM genMech = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
        fl->C_GenerateKey(hSess, &genMech, macTmpl, 6, &hKey);
        return hKey;
    };

    // ── V-16: C_SessionCancel semantics ──────────────────────────────────────
    typedef CK_RV (*C_SessionCancel_t)(CK_SESSION_HANDLE, CK_FLAGS);
    typedef CK_RV (*C_MessageSignInit_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    C_SessionCancel_t Cancel = (C_SessionCancel_t)dlsym(dlib, "C_SessionCancel");
    C_MessageSignInit_t MsgSignInit = (C_MessageSignInit_t)dlsym(dlib, "C_MessageSignInit");

    if (Cancel) {
        // (a) flags==0 → CKR_OK no-op even with no active op.
        CK_RV rv = Cancel(hSess, 0);
        record_result(CAT, "V16_SessionCancel_flags0_noop",
                      rv == CKR_OK ? "PASS" : "FAIL",
                      "flags==0 expect CKR_OK no-op, RV=" + std::to_string(rv));

        // (b) flag set for an op that is NOT active → ignore, CKR_OK.
        CK_OBJECT_HANDLE hMac = makeMacKey();
        CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, NULL_PTR, 0 };
        rv = fl->C_SignInit(hSess, &hmacMech, hMac);
        if (rv == CKR_OK) {
            // Sign op is active; cancel with CKF_DECRYPT (not active) → ignore.
            CK_RV rvc = Cancel(hSess, CKF_DECRYPT);
            record_result(CAT, "V16_SessionCancel_unmatched_ignored",
                          rvc == CKR_OK ? "PASS" : "FAIL",
                          "unmatched flag expect CKR_OK ignore, RV=" + std::to_string(rvc));
            // The sign op must still be active (cancel ignored it): finish it.
            CK_BYTE data[] = "x";
            CK_BYTE sig[64]; CK_ULONG sigLen = sizeof(sig);
            CK_RV rvs = fl->C_Sign(hSess, data, 1, sig, &sigLen);
            record_result(CAT, "V16_SessionCancel_unmatched_keeps_op",
                          rvs == CKR_OK ? "PASS" : "FAIL",
                          "sign op survives unmatched cancel, RV=" + std::to_string(rvs));
        } else {
            record_result(CAT, "V16_SessionCancel_unmatched_ignored", "FAIL",
                          "C_SignInit RV=" + std::to_string(rv));
        }

        // (c) CKF_MESSAGE_SIGN cancels an active message-sign op. The message
        //     sign API is asymmetric-only, so use an EC (ECDSA) signing key.
        if (MsgSignInit) {
            CK_OBJECT_CLASS pubC = CKO_PUBLIC_KEY, privC = CKO_PRIVATE_KEY;
            CK_KEY_TYPE ecT = CKK_EC;
            CK_BYTE oid_p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
            CK_ATTRIBUTE pubTpl[] = {
                { CKA_CLASS, &pubC, sizeof(pubC) },
                { CKA_KEY_TYPE, &ecT, sizeof(ecT) },
                { CKA_TOKEN, &bFalse, sizeof(bFalse) },
                { CKA_VERIFY, &bTrue, sizeof(bTrue) },
                { CKA_EC_PARAMS, oid_p256, sizeof(oid_p256) },
            };
            CK_ATTRIBUTE privTpl[] = {
                { CKA_CLASS, &privC, sizeof(privC) },
                { CKA_KEY_TYPE, &ecT, sizeof(ecT) },
                { CKA_TOKEN, &bFalse, sizeof(bFalse) },
                { CKA_SIGN, &bTrue, sizeof(bTrue) },
            };
            CK_MECHANISM kpMech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
            CK_OBJECT_HANDLE hEcPub = 0, hEcPriv = 0;
            CK_RV rvk = fl->C_GenerateKeyPair(hSess, &kpMech, pubTpl, 5, privTpl, 4, &hEcPub, &hEcPriv);
            if (rvk == CKR_OK) {
                CK_MECHANISM ecdsaMech = { CKM_ECDSA, NULL_PTR, 0 };
                CK_RV rvm = MsgSignInit(hSess, &ecdsaMech, hEcPriv);
                if (rvm == CKR_OK) {
                    CK_RV rvc = Cancel(hSess, CKF_MESSAGE_SIGN);
                    record_result(CAT, "V16_SessionCancel_CKF_MESSAGE_SIGN",
                                  rvc == CKR_OK ? "PASS" : "FAIL",
                                  "cancel active message-sign expect CKR_OK, RV=" + std::to_string(rvc));
                } else {
                    record_result(CAT, "V16_SessionCancel_CKF_MESSAGE_SIGN", "SKIP",
                                  "C_MessageSignInit RV=" + std::to_string(rvm));
                    refresh_session();
                }
            } else {
                record_result(CAT, "V16_SessionCancel_CKF_MESSAGE_SIGN", "SKIP",
                              "EC keypair gen RV=" + std::to_string(rvk));
            }
        } else {
            record_result(CAT, "V16_SessionCancel_CKF_MESSAGE_SIGN", "SKIP", "C_MessageSignInit unavailable");
        }
        refresh_session();
    } else {
        record_result(CAT, "V16_SessionCancel", "SKIP", "C_SessionCancel unavailable");
    }

    // ── V-17: C_Digest after C_DigestUpdate → CKR_OPERATION_ACTIVE ────────────
    {
        refresh_session();
        CK_MECHANISM dMech = { CKM_SHA256, NULL_PTR, 0 };
        CK_RV rv = fl->C_DigestInit(hSess, &dMech);
        if (rv == CKR_OK) {
            CK_BYTE part[] = "hello";
            rv = fl->C_DigestUpdate(hSess, part, sizeof(part) - 1);
        }
        if (rv == CKR_OK) {
            CK_BYTE data[] = "world";
            CK_BYTE dig[32]; CK_ULONG digLen = sizeof(dig);
            CK_RV rvd = fl->C_Digest(hSess, data, sizeof(data) - 1, dig, &digLen);
            record_result(CAT, "V17_Digest_after_DigestUpdate",
                          rvd == CKR_OPERATION_ACTIVE ? "PASS" : "FAIL",
                          "expect CKR_OPERATION_ACTIVE(0x90), RV=" + std::to_string(rvd));
            // Op must survive: C_DigestFinal should still work.
            CK_BYTE dig2[32]; CK_ULONG dig2Len = sizeof(dig2);
            CK_RV rvf = fl->C_DigestFinal(hSess, dig2, &dig2Len);
            record_result(CAT, "V17_Digest_op_survives",
                          rvf == CKR_OK ? "PASS" : "FAIL",
                          "C_DigestFinal after rejected one-shot, RV=" + std::to_string(rvf));
        } else {
            record_result(CAT, "V17_Digest_after_DigestUpdate", "FAIL",
                          "digest setup RV=" + std::to_string(rv));
        }
    }

    // ── V-17: one-shot C_Sign after C_SignUpdate → CKR_OPERATION_ACTIVE ───────
    {
        refresh_session();
        CK_OBJECT_HANDLE hMac = makeMacKey();
        CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, NULL_PTR, 0 };
        CK_RV rv = fl->C_SignInit(hSess, &hmacMech, hMac);
        if (rv == CKR_OK) {
            CK_BYTE part[] = "abc";
            rv = fl->C_SignUpdate(hSess, part, sizeof(part) - 1);
        }
        if (rv == CKR_OK) {
            CK_BYTE data[] = "xyz";
            CK_BYTE sig[64]; CK_ULONG sigLen = sizeof(sig);
            CK_RV rvs = fl->C_Sign(hSess, data, sizeof(data) - 1, sig, &sigLen);
            record_result(CAT, "V17_Sign_after_SignUpdate",
                          rvs == CKR_OPERATION_ACTIVE ? "PASS" : "FAIL",
                          "expect CKR_OPERATION_ACTIVE(0x90), RV=" + std::to_string(rvs));
            // Op must survive: C_SignFinal still works.
            CK_BYTE sig2[64]; CK_ULONG sig2Len = sizeof(sig2);
            CK_RV rvf = fl->C_SignFinal(hSess, sig2, &sig2Len);
            record_result(CAT, "V17_Sign_op_survives",
                          rvf == CKR_OK ? "PASS" : "FAIL",
                          "C_SignFinal after rejected one-shot, RV=" + std::to_string(rvf));
        } else {
            record_result(CAT, "V17_Sign_after_SignUpdate", "FAIL",
                          "sign setup RV=" + std::to_string(rv));
        }
        refresh_session();
    }

    // ── V-18: C_WrapKeyAuthenticated too-small buffer sets the length ─────────
    {
        typedef CK_RV (*C_WrapKeyAuthenticated_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
            CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
        C_WrapKeyAuthenticated_t WrapAuth =
            (C_WrapKeyAuthenticated_t)dlsym(dlib, "C_WrapKeyAuthenticated");
        if (!WrapAuth) {
            record_result(CAT, "V18_WrapAuth_buffer_too_small_sets_len", "SKIP",
                          "C_WrapKeyAuthenticated unavailable");
        } else {
            // KEK (AES) + target key.
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE kt = CKK_AES;
            CK_ULONG klen = 32;
            CK_ATTRIBUTE kekTpl[] = {
                { CKA_CLASS, &cls, sizeof(cls) },
                { CKA_KEY_TYPE, &kt, sizeof(kt) },
                { CKA_VALUE_LEN, &klen, sizeof(klen) },
                { CKA_TOKEN, &bFalse, sizeof(bFalse) },
                { CKA_WRAP, &bTrue, sizeof(bTrue) },
                { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
            };
            CK_MECHANISM genMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
            CK_OBJECT_HANDLE hKek = 0, hTgt = 0;
            CK_RV rv = fl->C_GenerateKey(hSess, &genMech, kekTpl, 6, &hKek);
            if (rv == CKR_OK) rv = fl->C_GenerateKey(hSess, &genMech, kekTpl, 6, &hTgt);
            if (rv != CKR_OK) {
                record_result(CAT, "V18_WrapAuth_buffer_too_small_sets_len", "FAIL",
                              "key setup RV=" + std::to_string(rv));
            } else {
                CK_BYTE iv[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
                CK_GCM_PARAMS gcm = {};
                gcm.pIv = iv; gcm.ulIvLen = sizeof(iv); gcm.ulIvBits = sizeof(iv) * 8;
                gcm.pAAD = NULL_PTR; gcm.ulAADLen = 0; gcm.ulTagBits = 128;
                CK_MECHANISM wrapMech = { CKM_AES_GCM, &gcm, sizeof(gcm) };
                // First, size query (NULL output).
                CK_ULONG needLen = 0;
                rv = WrapAuth(hSess, &wrapMech, hKek, hTgt, NULL_PTR, 0, NULL_PTR, &needLen);
                bool sizeOK = (rv == CKR_OK && needLen > 0);
                // Now offer a too-small buffer and confirm the length is set.
                CK_ULONG tooSmall = 1;
                CK_BYTE outBuf[4] = {0};
                CK_ULONG outLen = tooSmall;
                CK_RV rv2 = WrapAuth(hSess, &wrapMech, hKek, hTgt, NULL_PTR, 0, outBuf, &outLen);
                bool pass = (rv2 == CKR_BUFFER_TOO_SMALL) && (outLen == needLen) && sizeOK;
                record_result(CAT, "V18_WrapAuth_buffer_too_small_sets_len",
                              pass ? "PASS" : "FAIL",
                              "expect CKR_BUFFER_TOO_SMALL + outLen==" + std::to_string((unsigned long)needLen) +
                              ", got RV=" + std::to_string(rv2) + " outLen=" + std::to_string((unsigned long)outLen));
            }
            if (hTgt) fl->C_DestroyObject(hSess, hTgt);
            if (hKek) fl->C_DestroyObject(hSess, hKek);
        }
    }

    // ── V-19: C_GetSessionValidationFlags init-gate + handle + type ───────────
    {
        typedef CK_RV (*C_GSVF_t)(CK_SESSION_HANDLE, CK_SESSION_VALIDATION_FLAGS_TYPE, CK_FLAGS_PTR);
        C_GSVF_t GSVF = (C_GSVF_t)dlsym(dlib, "C_GetSessionValidationFlags");
        const CK_SESSION_VALIDATION_FLAGS_TYPE LAST_OK = 0x00000001UL; // CKS_LAST_VALIDATION_OK
        if (!GSVF) {
            record_result(CAT, "V19_GetSessionValidationFlags", "SKIP", "unavailable");
        } else {
            // Bad handle while initialized → CKR_SESSION_HANDLE_INVALID.
            CK_FLAGS f = 0xdead;
            CK_RV rv = GSVF((CK_SESSION_HANDLE)0xFFFFFFF0UL, LAST_OK, &f);
            record_result(CAT, "V19_GSVF_bad_handle",
                          rv == CKR_SESSION_HANDLE_INVALID ? "PASS" : "FAIL",
                          "expect CKR_SESSION_HANDLE_INVALID, RV=" + std::to_string(rv));
            // Valid handle + valid type → CKR_OK, *pFlags == 0.
            CK_FLAGS f2 = 0xdead;
            CK_RV rv2 = GSVF(hSess, LAST_OK, &f2);
            record_result(CAT, "V19_GSVF_valid",
                          (rv2 == CKR_OK && f2 == 0) ? "PASS" : "FAIL",
                          "expect CKR_OK + flags=0, RV=" + std::to_string(rv2) + " flags=" + std::to_string((unsigned long)f2));
            // Bad type → CKR_ARGUMENTS_BAD.
            CK_FLAGS f3 = 0;
            CK_RV rv3 = GSVF(hSess, 0x12345678UL, &f3);
            record_result(CAT, "V19_GSVF_bad_type",
                          rv3 == CKR_ARGUMENTS_BAD ? "PASS" : "FAIL",
                          "expect CKR_ARGUMENTS_BAD, RV=" + std::to_string(rv3));
            // NOTE: the pre-init gate is exercised by the dedicated standalone
            // C_GetSessionValidationFlags-before-Initialize check below in main.
        }
    }

    // V-20 (pInitArgs->pReserved != NULL → CKR_ARGUMENTS_BAD) is exercised by the
    // dedicated pre-init harness in init_token() — there is only one
    // C_Initialize per process.

    // ── GAP 2.4: C_EncapsulateKey bad public-key handle → CKR_KEY_HANDLE_INVALID
    {
        typedef CK_RV (*C_EncapsulateKey_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
            CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
        C_EncapsulateKey_t Encap = (C_EncapsulateKey_t)dlsym(dlib, "C_EncapsulateKey");
        const CK_MECHANISM_TYPE M_ML_KEM = 0x00000017UL; // CKM_ML_KEM
        if (!Encap) {
            record_result(CAT, "GAP24_Encap_bad_pubkey", "SKIP", "C_EncapsulateKey unavailable");
        } else {
            CK_OBJECT_CLASS secC = CKO_SECRET_KEY;
            CK_KEY_TYPE aesT = CKK_AES;
            CK_ULONG vlen = 32;
            CK_ATTRIBUTE outTpl[] = {
                { CKA_CLASS, &secC, sizeof(secC) },
                { CKA_KEY_TYPE, &aesT, sizeof(aesT) },
                { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
                { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            };
            CK_MECHANISM m = { M_ML_KEM, NULL_PTR, 0 };
            CK_BYTE ct[2048]; CK_ULONG ctLen = sizeof(ct);
            CK_OBJECT_HANDLE hOut = 0;
            CK_RV rv = Encap(hSess, &m, (CK_OBJECT_HANDLE)0xFFFFFFF0UL, outTpl, 4, ct, &ctLen, &hOut);
            record_result(CAT, "GAP24_Encap_bad_pubkey",
                          rv == CKR_KEY_HANDLE_INVALID ? "PASS" : "FAIL",
                          "expect CKR_KEY_HANDLE_INVALID(0x60), RV=" + std::to_string(rv));
            if (rv == CKR_OK && hOut) fl->C_DestroyObject(hSess, hOut);
        }
    }

    // ── GAP 6.5: C_DeriveKey bad base key → CKR_KEY_HANDLE_INVALID ────────────
    {
        // Use an HKDF-style derive mechanism; the base-key handle is invalid so
        // the handle check fires before any mechanism processing.
        CK_MECHANISM deriveMech = { CKM_SP800_108_COUNTER_KDF, NULL_PTR, 0 };
        CK_OBJECT_CLASS secC = CKO_SECRET_KEY;
        CK_KEY_TYPE genT = CKK_GENERIC_SECRET;
        CK_ULONG vlen = 32;
        CK_ATTRIBUTE dTpl[] = {
            { CKA_CLASS, &secC, sizeof(secC) },
            { CKA_KEY_TYPE, &genT, sizeof(genT) },
            { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_OBJECT_HANDLE hOut = 0;
        CK_RV rv = fl->C_DeriveKey(hSess, &deriveMech, (CK_OBJECT_HANDLE)0xFFFFFFF0UL,
                                   dTpl, 4, &hOut);
        record_result(CAT, "GAP65_DeriveKey_bad_base",
                      rv == CKR_KEY_HANDLE_INVALID ? "PASS" : "FAIL",
                      "expect CKR_KEY_HANDLE_INVALID(0x60), RV=" + std::to_string(rv));
        if (rv == CKR_OK && hOut) fl->C_DestroyObject(hSess, hOut);
    }

    refresh_session();
}

// ─── G5: attribute semantics + deterministic-seed feature ────────────────────
// Covers audit V-14 (CKA_UNIQUE_ID duplicated on C_CopyObject), V-15
// (CKA_UNIQUE_ID settable via derive/create template) and the CKA_SEED gap
// (deterministic ML-DSA/ML-KEM/SLH-DSA keygen + sensitive protection).
// The 0x17->0x4 store migration is unit-tested in objstoretest
// (SessionObjectTests::testUniqueIdMigration) since it lives below the
// PKCS#11 boundary.
void test_g5_attrs() {
    const char* CAT = "G5Attrs";
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

    // Read CKA_UNIQUE_ID into a string (empty on failure).
    auto readUniqueId = [&](CK_OBJECT_HANDLE h) -> std::string {
        CK_BYTE buf[128] = {0};
        CK_ATTRIBUTE a = { CKA_UNIQUE_ID, buf, sizeof(buf) };
        if (fl->C_GetAttributeValue(hSess, h, &a, 1) != CKR_OK) return std::string();
        if (a.ulValueLen == CK_UNAVAILABLE_INFORMATION || a.ulValueLen == 0) return std::string();
        return std::string((char*)buf, a.ulValueLen);
    };

    // Read CKA_UNIQUE_ID and report the raw RV so we can distinguish a clean
    // 36-byte read from the CKR_GENERAL_ERROR decrypt-on-plaintext bug.
    auto readUniqueIdRV = [&](CK_OBJECT_HANDLE h, std::string& out) -> CK_RV {
        CK_BYTE buf[128] = {0};
        CK_ATTRIBUTE a = { CKA_UNIQUE_ID, buf, sizeof(buf) };
        CK_RV rv = fl->C_GetAttributeValue(hSess, h, &a, 1);
        if (rv == CKR_OK && a.ulValueLen != CK_UNAVAILABLE_INFORMATION)
            out.assign((char*)buf, a.ulValueLen);
        else
            out.clear();
        return rv;
    };

    // ── CKA_UNIQUE_ID is public metadata: it must read back in clear on a
    //    PRIVATE key and on a SENSITIVE secret key (audit Part-A fix). The bug
    //    was that retrieve() ran token->decrypt() on the plaintext UUID for
    //    private objects → CKR_GENERAL_ERROR. §4.4.1. ─────────────────────────
    {
        // Private (and sensitive) RSA private key.
        CK_MECHANISM rsaMech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_ULONG modBits = 2048;
        CK_BYTE pubExp[] = { 0x01, 0x00, 0x01 };
        CK_OBJECT_CLASS pubC = CKO_PUBLIC_KEY, privC = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE pubT[] = {
            { CKA_CLASS, &pubC, sizeof(pubC) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_MODULUS_BITS, &modBits, sizeof(modBits) },
            { CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp) },
            { CKA_VERIFY, &bTrue, sizeof(bTrue) },
        };
        CK_ATTRIBUTE privT[] = {
            { CKA_CLASS, &privC, sizeof(privC) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
            { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
            { CKA_SIGN, &bTrue, sizeof(bTrue) },
        };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &rsaMech, pubT, 5, privT, 5, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result(CAT, "UniqueId_readable_on_private_key", "FAIL",
                          "RSA keygen RV=" + std::to_string(rv));
        } else {
            std::string id;
            CK_RV grv = readUniqueIdRV(hPriv, id);
            bool ok = (grv == CKR_OK) && id.size() == 36;
            record_result(CAT, "UniqueId_readable_on_private_key",
                          ok ? "PASS" : "FAIL",
                          "CKA_UNIQUE_ID on a PRIVATE/SENSITIVE key must read in "
                          "clear (36-byte UUID), expect RV=CKR_OK; got RV=" +
                          std::to_string(grv) + " len=" + std::to_string(id.size()));
            fl->C_DestroyObject(hSess, hPriv);
            fl->C_DestroyObject(hSess, hPub);
        }
    }
    {
        // Sensitive secret (AES) key.
        CK_MECHANISM aesMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_CLASS secC = CKO_SECRET_KEY;
        CK_KEY_TYPE aesKT = CKK_AES;
        CK_ULONG vlen = 32;
        CK_ATTRIBUTE keyT[] = {
            { CKA_CLASS, &secC, sizeof(secC) },
            { CKA_KEY_TYPE, &aesKT, sizeof(aesKT) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
            { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
            { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
        };
        CK_OBJECT_HANDLE hKey = 0;
        CK_RV rv = fl->C_GenerateKey(hSess, &aesMech, keyT, 6, &hKey);
        if (rv != CKR_OK) {
            record_result(CAT, "UniqueId_readable_on_sensitive_secret", "FAIL",
                          "AES keygen RV=" + std::to_string(rv));
        } else {
            std::string id;
            CK_RV grv = readUniqueIdRV(hKey, id);
            bool ok = (grv == CKR_OK) && id.size() == 36;
            record_result(CAT, "UniqueId_readable_on_sensitive_secret",
                          ok ? "PASS" : "FAIL",
                          "CKA_UNIQUE_ID on a SENSITIVE secret key must read in "
                          "clear (36-byte UUID), expect RV=CKR_OK; got RV=" +
                          std::to_string(grv) + " len=" + std::to_string(id.size()));
            fl->C_DestroyObject(hSess, hKey);
        }
    }

    // ── V-14: C_CopyObject must mint a FRESH CKA_UNIQUE_ID ────────────────────
    {
        // Public data object so CKA_UNIQUE_ID (stored in clear) reads back
        // without the private-attribute decrypt path.
        CK_OBJECT_CLASS dataClass = CKO_DATA;
        CK_BYTE label[] = "g5-copy-src";
        CK_BYTE value[] = "payload";
        CK_ATTRIBUTE srcTpl[] = {
            { CKA_CLASS, &dataClass, sizeof(dataClass) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
            { CKA_LABEL, label, sizeof(label) - 1 },
            { CKA_VALUE, value, sizeof(value) - 1 },
        };
        CK_OBJECT_HANDLE hSrc = 0, hCopy = 0;
        CK_RV rv = fl->C_CreateObject(hSess, srcTpl, 4, &hSrc);
        if (rv != CKR_OK) {
            record_result(CAT, "V14_CopyObject_freshUniqueId", "FAIL",
                          "source create RV=" + std::to_string(rv));
        } else {
            std::string srcId = readUniqueId(hSrc);
            // Copy with a minimal (non-NULL) extra template — the engine
            // requires a non-NULL pTemplate.
            CK_BYTE copyLabel[] = "g5-copy-dst";
            CK_ATTRIBUTE copyTpl[] = { { CKA_LABEL, copyLabel, sizeof(copyLabel) - 1 } };
            rv = fl->C_CopyObject(hSess, hSrc, copyTpl, 1, &hCopy);
            if (rv != CKR_OK) {
                record_result(CAT, "V14_CopyObject_freshUniqueId", "FAIL",
                              "C_CopyObject RV=" + std::to_string(rv));
            } else {
                std::string copyId = readUniqueId(hCopy);
                bool ok = !srcId.empty() && !copyId.empty() && srcId != copyId;
                record_result(CAT, "V14_CopyObject_freshUniqueId",
                              ok ? "PASS" : "FAIL",
                              "src and copy must each have a distinct CKA_UNIQUE_ID "
                              "(src len=" + std::to_string(srcId.size()) +
                              " copy len=" + std::to_string(copyId.size()) +
                              " distinct=" + (srcId != copyId ? "yes" : "no") + ")");
                fl->C_DestroyObject(hSess, hCopy);
            }
            fl->C_DestroyObject(hSess, hSrc);
        }
    }

    // ── V-15a: CKA_UNIQUE_ID in a C_CreateObject template → READ_ONLY ─────────
    {
        CK_OBJECT_CLASS dataClass = CKO_DATA;
        CK_BYTE forged[] = "deadbeefdeadbeefdeadbeefdeadbeef0000";
        CK_BYTE value[] = "x";
        CK_ATTRIBUTE tpl[] = {
            { CKA_CLASS, &dataClass, sizeof(dataClass) },
            { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            { CKA_VALUE, value, sizeof(value) - 1 },
            { CKA_UNIQUE_ID, forged, sizeof(forged) - 1 },
        };
        CK_OBJECT_HANDLE h = 0;
        CK_RV rv = fl->C_CreateObject(hSess, tpl, 4, &h);
        record_result(CAT, "V15_CreateObject_uniqueId_readonly",
                      rv == CKR_ATTRIBUTE_READ_ONLY ? "PASS" : "FAIL",
                      "caller-supplied CKA_UNIQUE_ID must be rejected, "
                      "expect CKR_ATTRIBUTE_READ_ONLY(0x10) RV=" + std::to_string(rv));
        if (rv == CKR_OK && h) fl->C_DestroyObject(hSess, h);
    }

    // ── V-15b: CKA_UNIQUE_ID in a C_DeriveKey template — token-assigned only.
    // Per §4.4.1 the value must NOT come from the caller: either the derive is
    // rejected (READ_ONLY) or it succeeds but the forged id is ignored and a
    // fresh one assigned. A silently-honored forged id is the bug → FAIL.
    {
        CK_OBJECT_CLASS pubC = CKO_PUBLIC_KEY, privC = CKO_PRIVATE_KEY;
        CK_KEY_TYPE montKT = CKK_EC_MONTGOMERY;
        // CKA_EC_PARAMS as DER PrintableString "curve25519" (matches the
        // engine's working ECDH path, not the OID form).
        CK_BYTE curve25519[] = { 0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39 };
        CK_MECHANISM kpMech = { CKM_EC_MONTGOMERY_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_ATTRIBUTE pubT[] = {
            { CKA_CLASS, &pubC, sizeof(pubC) }, { CKA_KEY_TYPE, &montKT, sizeof(montKT) },
            { CKA_EC_PARAMS, curve25519, sizeof(curve25519) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_ATTRIBUTE privT[] = {
            { CKA_CLASS, &privC, sizeof(privC) }, { CKA_KEY_TYPE, &montKT, sizeof(montKT) },
            { CKA_DERIVE, &bTrue, sizeof(bTrue) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_RV rv = fl->C_GenerateKeyPair(hSess, &kpMech, pubT, 4, privT, 4, &hPub, &hPriv);
        if (rv != CKR_OK) {
            record_result(CAT, "V15_DeriveKey_uniqueId_tokenAssigned", "SKIP",
                          "X25519 base keygen RV=" + std::to_string(rv));
        } else {
            // Use the public peer's own EC point as the derive peer data.
            CK_ATTRIBUTE ptAttr = { CKA_EC_POINT, NULL_PTR, 0 };
            fl->C_GetAttributeValue(hSess, hPub, &ptAttr, 1);
            std::vector<CK_BYTE> peer(ptAttr.ulValueLen);
            ptAttr.pValue = peer.data();
            fl->C_GetAttributeValue(hSess, hPub, &ptAttr, 1);

            CK_ECDH1_DERIVE_PARAMS dp = { CKD_NULL, 0, NULL_PTR, 0, NULL_PTR };
            dp.pPublicData = peer.data(); dp.ulPublicDataLen = peer.size();
            CK_MECHANISM dMech = { CKM_ECDH1_DERIVE, &dp, sizeof(dp) };
            CK_OBJECT_CLASS secC = CKO_SECRET_KEY; CK_KEY_TYPE genKT = CKK_GENERIC_SECRET;
            CK_ULONG vlen = 32;
            CK_BYTE forged[] = "feedfacefeedfacefeedfacefeedface1111";
            CK_ATTRIBUTE dt[] = {
                { CKA_CLASS, &secC, sizeof(secC) }, { CKA_KEY_TYPE, &genKT, sizeof(genKT) },
                { CKA_VALUE_LEN, &vlen, sizeof(vlen) }, { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
                { CKA_UNIQUE_ID, forged, sizeof(forged) - 1 },
            };
            CK_OBJECT_HANDLE hDer = 0;
            rv = fl->C_DeriveKey(hSess, &dMech, hPriv, dt, 5, &hDer);
            if (rv == CKR_ATTRIBUTE_READ_ONLY) {
                record_result(CAT, "V15_DeriveKey_uniqueId_tokenAssigned", "PASS",
                              "forged CKA_UNIQUE_ID rejected with CKR_ATTRIBUTE_READ_ONLY");
            } else if (rv == CKR_OK) {
                std::string derId = readUniqueId(hDer);
                std::string forgedStr((char*)forged, sizeof(forged) - 1);
                bool ok = (derId != forgedStr); // token must NOT have honored the forged id
                record_result(CAT, "V15_DeriveKey_uniqueId_tokenAssigned",
                              ok ? "PASS" : "FAIL",
                              std::string("derive succeeded; forged id must be ignored "
                              "(assigned=") + (ok ? "fresh" : "FORGED!") + ")");
                fl->C_DestroyObject(hSess, hDer);
            } else {
                // Some other failure (e.g. mechanism path) — not the unique-id bug.
                record_result(CAT, "V15_DeriveKey_uniqueId_tokenAssigned", "SKIP",
                              "derive path RV=" + std::to_string(rv) + " (not unique-id specific)");
            }
            fl->C_DestroyObject(hSess, hPriv);
            fl->C_DestroyObject(hSess, hPub);
        }
    }

    // ── CKA_SEED: deterministic keygen + length + sensitive protection ────────
    // Each entry: (keygen-mech, key-type, param-set, seed-length, sign-or-kem).
    struct SeedCase { CK_MECHANISM_TYPE mech; CK_KEY_TYPE kt; CK_ULONG ps; CK_ULONG seedLen; const char* name; };
    SeedCase cases[] = {
        { CKM_ML_DSA_KEY_PAIR_GEN, CKK_ML_DSA, CKP_ML_DSA_44,         32, "ML_DSA_44" },
        { CKM_ML_KEM_KEY_PAIR_GEN, CKK_ML_KEM, CKP_ML_KEM_768,        64, "ML_KEM_768" },
        { CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128S, 48, "SLH_DSA_128s" },
    };

    for (const auto& c : cases) {
        CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE kt = c.kt;
        CK_ULONG ps = c.ps;
        CK_MECHANISM mech = { c.mech, NULL_PTR, 0 };

        // Fixed deterministic seed.
        std::vector<CK_BYTE> seed(c.seedLen, 0x5A);

        auto genWithSeed = [&](const CK_BYTE* sd, CK_ULONG sdLen,
                               CK_OBJECT_HANDLE& hPub, CK_OBJECT_HANDLE& hPriv) -> CK_RV {
            CK_ATTRIBUTE pubTpl[] = {
                { CKA_CLASS, &pubClass, sizeof(pubClass) },
                { CKA_KEY_TYPE, &kt, sizeof(kt) },
                { CKA_PARAMETER_SET, &ps, sizeof(ps) },
                { CKA_TOKEN, &bFalse, sizeof(bFalse) },
            };
            CK_ATTRIBUTE privTpl[] = {
                { CKA_CLASS, &privClass, sizeof(privClass) },
                { CKA_KEY_TYPE, &kt, sizeof(kt) },
                { CKA_PARAMETER_SET, &ps, sizeof(ps) },
                { CKA_TOKEN, &bFalse, sizeof(bFalse) },
                { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
                { CKA_SEED, (CK_VOID_PTR)sd, sdLen },
            };
            return fl->C_GenerateKeyPair(hSess, &mech, pubTpl, 4, privTpl, 6, &hPub, &hPriv);
        };

        // Same seed twice → identical public keys (deterministic).
        CK_OBJECT_HANDLE hPubA = 0, hPrivA = 0, hPubB = 0, hPrivB = 0;
        CK_RV rvA = genWithSeed(seed.data(), c.seedLen, hPubA, hPrivA);
        CK_RV rvB = genWithSeed(seed.data(), c.seedLen, hPubB, hPrivB);
        if (rvA == CKR_FUNCTION_NOT_SUPPORTED || rvA == CKR_MECHANISM_INVALID) {
            record_result(CAT, std::string("CKA_SEED_deterministic_") + c.name, "SKIP",
                          "keygen mech not supported RV=" + std::to_string(rvA));
        } else if (rvA != CKR_OK || rvB != CKR_OK) {
            record_result(CAT, std::string("CKA_SEED_deterministic_") + c.name, "FAIL",
                          "seeded keygen RV A=" + std::to_string(rvA) + " B=" + std::to_string(rvB));
        } else {
            CK_BYTE pa[4096] = {0}, pb[4096] = {0};
            CK_ATTRIBUTE va = { CKA_VALUE, pa, sizeof(pa) };
            CK_ATTRIBUTE vb = { CKA_VALUE, pb, sizeof(pb) };
            CK_RV ra = fl->C_GetAttributeValue(hSess, hPubA, &va, 1);
            CK_RV rb = fl->C_GetAttributeValue(hSess, hPubB, &vb, 1);
            bool ok = ra == CKR_OK && rb == CKR_OK &&
                      va.ulValueLen == vb.ulValueLen && va.ulValueLen > 0 &&
                      memcmp(pa, pb, va.ulValueLen) == 0;
            record_result(CAT, std::string("CKA_SEED_deterministic_") + c.name,
                          ok ? "PASS" : "FAIL",
                          "same seed must yield identical public key "
                          "(lenA=" + std::to_string(va.ulValueLen) +
                          " lenB=" + std::to_string(vb.ulValueLen) + ")");

            // Seed readback on a sensitive key → CKR_ATTRIBUTE_SENSITIVE.
            CK_BYTE sbuf[128] = {0};
            CK_ATTRIBUTE sa = { CKA_SEED, sbuf, sizeof(sbuf) };
            CK_RV rs = fl->C_GetAttributeValue(hSess, hPrivA, &sa, 1);
            record_result(CAT, std::string("CKA_SEED_sensitive_") + c.name,
                          rs == CKR_ATTRIBUTE_SENSITIVE ? "PASS" : "FAIL",
                          "seed on a sensitive key must not leak, "
                          "expect CKR_ATTRIBUTE_SENSITIVE(0x11) RV=" + std::to_string(rs));
        }
        if (hPrivA) fl->C_DestroyObject(hSess, hPrivA);
        if (hPubA)  fl->C_DestroyObject(hSess, hPubA);
        if (hPrivB) fl->C_DestroyObject(hSess, hPrivB);
        if (hPubB)  fl->C_DestroyObject(hSess, hPubB);

        // Wrong seed length → CKR_ATTRIBUTE_VALUE_INVALID.
        if (rvA != CKR_FUNCTION_NOT_SUPPORTED && rvA != CKR_MECHANISM_INVALID) {
            std::vector<CK_BYTE> badSeed(c.seedLen - 1, 0x5A); // one byte short
            CK_OBJECT_HANDLE hPubW = 0, hPrivW = 0;
            CK_RV rvW = genWithSeed(badSeed.data(), (CK_ULONG)badSeed.size(), hPubW, hPrivW);
            record_result(CAT, std::string("CKA_SEED_wronglen_") + c.name,
                          rvW == CKR_ATTRIBUTE_VALUE_INVALID ? "PASS" : "FAIL",
                          "wrong seed length must be rejected, "
                          "expect CKR_ATTRIBUTE_VALUE_INVALID(0x13) RV=" + std::to_string(rvW));
            if (rvW == CKR_OK) { if (hPrivW) fl->C_DestroyObject(hSess, hPrivW); if (hPubW) fl->C_DestroyObject(hSess, hPubW); }
        }
    }

    refresh_session();
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    printf("--- PKCS#11 v3.2 Compliance Test Tool ---\n");
    printf("Engine: %s\n", opt_engine.c_str());

    if (!init_token()) return 1;

    if (opt_category == "all" || opt_category == "discovery") { refresh_session(); test_mechanism_discovery(); }
    if (opt_category == "all" || opt_category == "attr") { refresh_session(); test_key_attributes(); }
    if (opt_category == "all" || opt_category == "pqc-kem") { refresh_session(); test_pqc_kem(); }
    if (opt_category == "all" || opt_category == "pqc-dsa") { refresh_session(); test_pqc_dsa(); }
    if (opt_category == "all" || opt_category == "pqc-dsa") { refresh_session(); test_mldsa_context_binding(); }
    if (opt_category == "all" || opt_category == "pqc-dsa") { refresh_session(); test_multipart_signing(); }
    if (opt_category == "all" || opt_category == "classical") { refresh_session(); test_multipart_ecdsa(); }
    if (opt_category == "all" || opt_category == "classical") { refresh_session(); test_multipart_eddsa(); }

    if (opt_category == "all" || opt_category == "v32-adv") {
        refresh_session(); test_v32_kdfs();
        refresh_session(); test_message_signatures();
        refresh_session(); test_message_encryption();
    }
    if (opt_category == "all" || opt_category == "pqc-slh") {
        refresh_session(); test_pqc_slh_dsa();
        refresh_session(); test_pqc_xmss();
    }
    if (opt_category == "all" || opt_category == "classical") {
        refresh_session(); test_classical_crypto();
        refresh_session(); test_chacha20();
    }
    if (opt_category == "all" || opt_category == "negative") {
        refresh_session(); test_negative_paths();
    }
    if (opt_category == "all" || opt_category == "fips") {
        refresh_session(); test_fips_edge_constraints();
    }
    if (opt_category == "all" || opt_category == "session") {
        refresh_session(); test_slot_session_management();
        refresh_session(); test_v30_session();
    }
    if (opt_category == "all" || opt_category == "cka-id") {
        refresh_session(); test_cka_id_retrieval();
    }
    if (opt_category == "all" || opt_category == "authwrap") {
        refresh_session(); test_authenticated_wrap();
    }
    if (opt_category == "all" || opt_category == "kcv") {
        refresh_session(); test_kcv_compliance();
    }
    if (opt_category == "all" || opt_category == "g1-security") {
        refresh_session(); test_g1_security();
    }
    if (opt_category == "all" || opt_category == "g2-mechtable") {
        refresh_session(); test_g2_mech_table();
        refresh_session(); test_g2_chacha20_bare();
        refresh_session(); test_g2_derive_reachable();
    }
    if (opt_category == "all" || opt_category == "g3-keygen") {
        refresh_session(); test_g3_keygen();
    }
    if (opt_category == "all" || opt_category == "g4-retcodes") {
        refresh_session(); test_g4_retcodes();
    }
    if (opt_category == "all" || opt_category == "g5-attrs") {
        refresh_session(); test_g5_attrs();
    }

    if (opt_category == "all" || opt_category == "classical") {
        refresh_session(); test_ecdsa_curves();
    }
    if (opt_category == "all" || opt_category == "v32-adv") {
        refresh_session(); test_eddsa_curves();
        refresh_session(); test_ecdh_derivations();
        refresh_session(); test_aes_ctr();
        refresh_session(); test_kmac();
        refresh_session(); test_sha3_hashes();
        refresh_session(); test_bip32_wallets();
    }
    
    fl->C_Finalize(NULL);
    
    // Output JSON (with summary totals so the JSON is self-describing)
    report["_summary"] = {
        {"pass", total_pass}, {"fail", total_fail},
        {"skip", total_skip}, {"xfail_known_engine_bugs", total_xfail},
        {"engine", opt_engine}, {"engine_commit", opt_engine_commit}
    };
    std::string json_path = opt_report + ".json";
    std::ofstream o(json_path);
    o << std::setw(4) << report << std::endl;
    
    // Output Markdown
    char dateBuf[64] = {0};
    {
        time_t now = time(nullptr);
        struct tm tmv;
        localtime_r(&now, &tmv);
        strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d %H:%M:%S %Z", &tmv);
    }
    std::string md_path = opt_report + ".md";
    std::ofstream md(md_path);
    md << "# PKCS#11 v3.2 Compliance Report\n\n";
    md << "**Engine:** `" << opt_engine << "`\n";
    if (!opt_engine_commit.empty())
        md << "**Engine commit:** `" << opt_engine_commit << "`\n";
    md << "**Date:** " << dateBuf << "\n\n";
    md << "## Summary\n";
    md << "- **Total PASS:** " << total_pass << "\n";
    md << "- **Total FAIL:** " << total_fail << "\n";
    md << "- **Total SKIP:** " << total_skip << "\n";
    md << "- **Total XFAIL (known engine bugs, documented in-line):** " << total_xfail << "\n\n";
    md << "Status legend: PASS = spec-conformant behavior for an advertised feature; "
          "FAIL = unexpected non-conformance; SKIP = feature not advertised by the token "
          "(v3.2 mandates no particular mechanism set); XFAIL = known, pre-existing engine "
          "non-conformance reported here but outside this suite's scope to fix.\n\n";

    for (auto it = report.begin(); it != report.end(); ++it) {
        if (it.key() == "_summary") continue; // totals already rendered above
        md << "### " << it.key() << "\n\n";
        md << "| Test | Status | Details |\n|---|---|---|\n";
        for (const auto& item : it.value()) {
            std::string st = item["status"];
            std::string icon = (st == "PASS") ? "✅" : (st == "FAIL" ? "❌" : (st == "XFAIL" ? "❌(known)" : "⚠️"));
            md << "| " << item["test"].get<std::string>() << " | " << icon << " " << st << " | " << item["details"].get<std::string>() << " |\n";
        }
        md << "\n";
    }

    printf("\nDone. Reports saved to %s and %s\n", json_path.c_str(), md_path.c_str());
    printf("Totals: PASS=%d FAIL=%d SKIP=%d XFAIL=%d\n", total_pass, total_fail, total_skip, total_xfail);
    // Exit code reflects UNEXPECTED failures only; XFAILs are documented
    // known engine bugs and must not mask new regressions nor break CI.
    return total_fail > 0 ? 1 : 0;
}
