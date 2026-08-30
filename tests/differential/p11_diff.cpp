// ============================================================================
// p11_diff — cross-engine differential harness for pqctoday-hsm
// ============================================================================
//
// Drives BOTH PKCS#11 engines in this repository through identical call
// sequences and asserts identical observable outcomes:
//
//   * the return code of every call,
//   * the output bytes of every operation that produces them,
//   * the full attribute set of every object produced.
//
// Every difference that is *legal* must be listed in exceptions.json with a
// one-line justification and, where one exists, a spec citation. A difference
// that is not listed fails the run. That inversion is the point: prose parity
// claims in this repository have gone stale twice, and the 2026-08-13 audit
// found 24 documentation statements contradicting the code. Recorded data
// rots visibly; prose rots silently.
//
// DESIGN — one process, two dlopen'd engines. See README.md for the evidence.
//   - The C++ engine is a shared library linking OpenSSL 3.
//   - The Rust engine is a cdylib exporting the same C ABI (rust/src/ck_abi.rs)
//     and linking NO OpenSSL at all (`otool -L` shows libSystem + libiconv).
//   - Both are opened RTLD_LOCAL and every call goes through that image's own
//     CK_FUNCTION_LIST, so the duplicate C_* symbols never interpose.
//   Measured, not assumed: the harness asserts the two C_Initialize pointers
//   differ before it does anything else (see load_engine).
//
// Build/run: scripts/run-differential-harness.sh
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <functional>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <dlfcn.h>
#include <getopt.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "src/lib/pkcs11/pkcs11.h"

#include "tests/json.hpp"
using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Fallbacks — values MUST match the canonical OASIS PKCS#11 v3.2 pkcs11t.h.
// ---------------------------------------------------------------------------
#ifndef CKA_ENCAPSULATE
#define CKA_ENCAPSULATE 0x00000633UL
#endif
#ifndef CKA_DECAPSULATE
#define CKA_DECAPSULATE 0x00000634UL
#endif
#ifndef CKA_PARAMETER_SET
#define CKA_PARAMETER_SET 0x0000061dUL
#endif
#ifndef CKA_SEED
#define CKA_SEED 0x00000637UL
#endif
#ifndef CKA_PROFILE_ID
#define CKA_PROFILE_ID 0x00000601UL
#endif
#ifndef CKO_PROFILE
#define CKO_PROFILE 0x00000009UL
#endif
#ifndef CKK_ML_DSA
#define CKK_ML_DSA 0x0000004aUL
#endif
#ifndef CKK_ML_KEM
#define CKK_ML_KEM 0x00000049UL
#endif
#ifndef CKP_BASELINE_PROVIDER
#define CKP_BASELINE_PROVIDER 0x00000001UL
#endif

typedef CK_RV (*fn_EncapsulateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                                   CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR,
                                   CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*fn_DecapsulateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                                   CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG,
                                   CK_OBJECT_HANDLE_PTR);

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------
struct Engine {
    std::string          name;
    std::string          path;
    void*                h  = nullptr;
    CK_FUNCTION_LIST_PTR fl = nullptr;
    fn_EncapsulateKey    Encapsulate = nullptr;
    fn_DecapsulateKey    Decapsulate = nullptr;
    std::set<CK_MECHANISM_TYPE> mechs;
    CK_SLOT_ID           slot = 0;
    CK_SESSION_HANDLE    sess = CK_INVALID_HANDLE;
};

static Engine  gCpp, gRust;
static std::string opt_cpp_engine, opt_rust_engine;
static std::string opt_workdir  = "build_union/p11_diff_workdir";
static std::string opt_report   = "p11_diff_report";
static std::string opt_exceptions = "tests/differential/exceptions.json";
static std::string opt_only;      // substring filter on scenario id
static std::string opt_drop_exception; // demonstration: ignore one entry by id
static bool        opt_verbose  = false;
// --shard I/N — round-robin partition of gScenarios (index % N == I) so N
// worker processes can split the run across cores. Each shard dlopens BOTH
// engines fresh and runs independently (see the single-process rationale
// in tests/differential/README.md — that rationale is per-PROCESS, not
// per-run, so N processes each honouring it is the safe way to add
// parallelism without threading either engine, which neither this harness
// nor either engine has ever been asserted safe for). -1 means unsharded
// (run everything, the historical default).
static int opt_shard_index = -1;
static int opt_shard_count = 1;

static const char* SO_PIN   = "12345678";
static const char* USER_PIN = "1234";

// ---------------------------------------------------------------------------
// Name tables — a diff nobody can read gets ignored, so everything numeric that
// reaches the report is spelled.
// ---------------------------------------------------------------------------
struct NamePair { CK_ULONG v; const char* n; };

static const NamePair kRvNames[] = {
    {0x00000000, "CKR_OK"},
    {0x00000001, "CKR_CANCEL"},
    {0x00000002, "CKR_HOST_MEMORY"},
    {0x00000003, "CKR_SLOT_ID_INVALID"},
    {0x00000005, "CKR_GENERAL_ERROR"},
    {0x00000006, "CKR_FUNCTION_FAILED"},
    {0x00000007, "CKR_ARGUMENTS_BAD"},
    {0x00000008, "CKR_NO_EVENT"},
    {0x00000009, "CKR_NEED_TO_CREATE_THREADS"},
    {0x0000000a, "CKR_CANT_LOCK"},
    {0x00000010, "CKR_ATTRIBUTE_READ_ONLY"},
    {0x00000011, "CKR_ATTRIBUTE_SENSITIVE"},
    {0x00000012, "CKR_ATTRIBUTE_TYPE_INVALID"},
    {0x00000013, "CKR_ATTRIBUTE_VALUE_INVALID"},
    {0x0000001b, "CKR_ACTION_PROHIBITED"},
    {0x00000020, "CKR_DATA_INVALID"},
    {0x00000021, "CKR_DATA_LEN_RANGE"},
    {0x00000030, "CKR_DEVICE_ERROR"},
    {0x00000031, "CKR_DEVICE_MEMORY"},
    {0x00000032, "CKR_DEVICE_REMOVED"},
    {0x00000040, "CKR_ENCRYPTED_DATA_INVALID"},
    {0x00000041, "CKR_ENCRYPTED_DATA_LEN_RANGE"},
    {0x00000042, "CKR_AEAD_DECRYPT_FAILED"},
    {0x00000050, "CKR_FUNCTION_CANCELED"},
    {0x00000051, "CKR_FUNCTION_NOT_PARALLEL"},
    {0x00000054, "CKR_FUNCTION_NOT_SUPPORTED"},
    {0x00000060, "CKR_KEY_HANDLE_INVALID"},
    {0x00000062, "CKR_KEY_SIZE_RANGE"},
    {0x00000063, "CKR_KEY_TYPE_INCONSISTENT"},
    {0x00000064, "CKR_KEY_NOT_NEEDED"},
    {0x00000065, "CKR_KEY_CHANGED"},
    {0x00000066, "CKR_KEY_NEEDED"},
    {0x00000067, "CKR_KEY_INDIGESTIBLE"},
    {0x00000068, "CKR_KEY_FUNCTION_NOT_PERMITTED"},
    {0x00000069, "CKR_KEY_NOT_WRAPPABLE"},
    {0x0000006a, "CKR_KEY_UNEXTRACTABLE"},
    {0x00000070, "CKR_MECHANISM_INVALID"},
    {0x00000071, "CKR_MECHANISM_PARAM_INVALID"},
    {0x00000082, "CKR_OBJECT_HANDLE_INVALID"},
    {0x00000090, "CKR_OPERATION_ACTIVE"},
    {0x00000091, "CKR_OPERATION_NOT_INITIALIZED"},
    {0x000000a0, "CKR_PIN_INCORRECT"},
    {0x000000a1, "CKR_PIN_INVALID"},
    {0x000000a2, "CKR_PIN_LEN_RANGE"},
    {0x000000a3, "CKR_PIN_EXPIRED"},
    {0x000000a4, "CKR_PIN_LOCKED"},
    {0x000000b0, "CKR_SESSION_CLOSED"},
    {0x000000b3, "CKR_SESSION_HANDLE_INVALID"},
    {0x000000b4, "CKR_SESSION_PARALLEL_NOT_SUPPORTED"},
    {0x000000b5, "CKR_SESSION_READ_ONLY"},
    {0x000000b6, "CKR_SESSION_EXISTS"},
    {0x000000b7, "CKR_SESSION_READ_ONLY_EXISTS"},
    {0x000000b8, "CKR_SESSION_READ_WRITE_SO_EXISTS"},
    {0x000000c0, "CKR_SIGNATURE_INVALID"},
    {0x000000c1, "CKR_SIGNATURE_LEN_RANGE"},
    {0x000000d0, "CKR_TEMPLATE_INCOMPLETE"},
    {0x000000d1, "CKR_TEMPLATE_INCONSISTENT"},
    {0x000000e0, "CKR_TOKEN_NOT_PRESENT"},
    {0x000000e1, "CKR_TOKEN_NOT_RECOGNIZED"},
    {0x000000e2, "CKR_TOKEN_WRITE_PROTECTED"},
    {0x000000f0, "CKR_UNWRAPPING_KEY_HANDLE_INVALID"},
    {0x00000100, "CKR_USER_ALREADY_LOGGED_IN"},
    {0x00000101, "CKR_USER_NOT_LOGGED_IN"},
    {0x00000102, "CKR_USER_PIN_NOT_INITIALIZED"},
    {0x00000103, "CKR_USER_TYPE_INVALID"},
    {0x00000104, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"},
    {0x00000105, "CKR_USER_TOO_MANY_TYPES"},
    {0x00000110, "CKR_WRAPPED_KEY_INVALID"},
    {0x00000112, "CKR_WRAPPED_KEY_LEN_RANGE"},
    {0x00000113, "CKR_WRAPPING_KEY_HANDLE_INVALID"},
    {0x00000114, "CKR_WRAPPING_KEY_SIZE_RANGE"},
    {0x00000115, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"},
    {0x00000120, "CKR_RANDOM_SEED_NOT_SUPPORTED"},
    {0x00000121, "CKR_RANDOM_NO_RNG"},
    {0x00000130, "CKR_DOMAIN_PARAMS_INVALID"},
    {0x00000140, "CKR_CURVE_NOT_SUPPORTED"},
    {0x00000150, "CKR_BUFFER_TOO_SMALL"},
    {0x00000160, "CKR_SAVED_STATE_INVALID"},
    {0x00000170, "CKR_INFORMATION_SENSITIVE"},
    {0x00000180, "CKR_STATE_UNSAVEABLE"},
    {0x00000190, "CKR_CRYPTOKI_NOT_INITIALIZED"},
    {0x00000191, "CKR_CRYPTOKI_ALREADY_INITIALIZED"},
    {0x000001a0, "CKR_MUTEX_BAD"},
    {0x000001a1, "CKR_MUTEX_NOT_LOCKED"},
    {0x000001b5, "CKR_OPERATION_CANCEL_FAILED"},
    {0x000001b6, "CKR_KEY_EXHAUSTED"},
    {0x000001b8, "CKR_PENDING"},
    {0x000001b9, "CKR_SESSION_ASYNC_NOT_SUPPORTED"},
    {0x000001c0, "CKR_SEED_RANDOM_REQUIRED"},
    {0x000001c1, "CKR_PARAMETER_SET_NOT_SUPPORTED"},
};

static const NamePair kAttrNames[] = {
    {CKA_CLASS, "CKA_CLASS"},
    {CKA_TOKEN, "CKA_TOKEN"},
    {CKA_PRIVATE, "CKA_PRIVATE"},
    {CKA_LABEL, "CKA_LABEL"},
    {CKA_UNIQUE_ID, "CKA_UNIQUE_ID"},
    {CKA_APPLICATION, "CKA_APPLICATION"},
    {CKA_VALUE, "CKA_VALUE"},
    {CKA_OBJECT_ID, "CKA_OBJECT_ID"},
    {CKA_KEY_TYPE, "CKA_KEY_TYPE"},
    {CKA_ID, "CKA_ID"},
    {CKA_SENSITIVE, "CKA_SENSITIVE"},
    {CKA_ENCRYPT, "CKA_ENCRYPT"},
    {CKA_DECRYPT, "CKA_DECRYPT"},
    {CKA_WRAP, "CKA_WRAP"},
    {CKA_UNWRAP, "CKA_UNWRAP"},
    {CKA_SIGN, "CKA_SIGN"},
    {CKA_SIGN_RECOVER, "CKA_SIGN_RECOVER"},
    {CKA_VERIFY, "CKA_VERIFY"},
    {CKA_VERIFY_RECOVER, "CKA_VERIFY_RECOVER"},
    {CKA_DERIVE, "CKA_DERIVE"},
    {CKA_START_DATE, "CKA_START_DATE"},
    {CKA_END_DATE, "CKA_END_DATE"},
    {CKA_MODULUS, "CKA_MODULUS"},
    {CKA_MODULUS_BITS, "CKA_MODULUS_BITS"},
    {CKA_PUBLIC_EXPONENT, "CKA_PUBLIC_EXPONENT"},
    {CKA_PRIVATE_EXPONENT, "CKA_PRIVATE_EXPONENT"},
    {CKA_PRIME_1, "CKA_PRIME_1"},
    {CKA_PRIME_2, "CKA_PRIME_2"},
    {CKA_EXPONENT_1, "CKA_EXPONENT_1"},
    {CKA_EXPONENT_2, "CKA_EXPONENT_2"},
    {CKA_COEFFICIENT, "CKA_COEFFICIENT"},
    {CKA_VALUE_LEN, "CKA_VALUE_LEN"},
    {CKA_EXTRACTABLE, "CKA_EXTRACTABLE"},
    {CKA_LOCAL, "CKA_LOCAL"},
    {CKA_NEVER_EXTRACTABLE, "CKA_NEVER_EXTRACTABLE"},
    {CKA_ALWAYS_SENSITIVE, "CKA_ALWAYS_SENSITIVE"},
    {CKA_KEY_GEN_MECHANISM, "CKA_KEY_GEN_MECHANISM"},
    {CKA_MODIFIABLE, "CKA_MODIFIABLE"},
    {CKA_COPYABLE, "CKA_COPYABLE"},
    {CKA_DESTROYABLE, "CKA_DESTROYABLE"},
    {CKA_EC_PARAMS, "CKA_EC_PARAMS"},
    {CKA_EC_POINT, "CKA_EC_POINT"},
    {CKA_ALWAYS_AUTHENTICATE, "CKA_ALWAYS_AUTHENTICATE"},
    {CKA_WRAP_WITH_TRUSTED, "CKA_WRAP_WITH_TRUSTED"},
    {CKA_TRUSTED, "CKA_TRUSTED"},
    {CKA_CHECK_VALUE, "CKA_CHECK_VALUE"},
    {CKA_PUBLIC_KEY_INFO, "CKA_PUBLIC_KEY_INFO"},
    {CKA_PARAMETER_SET, "CKA_PARAMETER_SET"},
    {CKA_SEED, "CKA_SEED"},
    {CKA_ENCAPSULATE, "CKA_ENCAPSULATE"},
    {CKA_DECAPSULATE, "CKA_DECAPSULATE"},
    {CKA_PROFILE_ID, "CKA_PROFILE_ID"},
    {CKA_ALLOWED_MECHANISMS, "CKA_ALLOWED_MECHANISMS"},
};

static std::string rv_name(CK_RV rv) {
    for (const auto& p : kRvNames) if (p.v == rv) return p.n;
    char buf[32]; snprintf(buf, sizeof buf, "CKR_0x%08lx", (unsigned long)rv);
    return buf;
}
static std::string attr_name(CK_ATTRIBUTE_TYPE t) {
    for (const auto& p : kAttrNames) if (p.v == t) return p.n;
    char buf[32]; snprintf(buf, sizeof buf, "CKA_0x%08lx", (unsigned long)t);
    return buf;
}

// Mechanism names — only the ones scenarios actually reference plus the
// full-list diff needs a generic fallback.
static std::string mech_name(CK_MECHANISM_TYPE m) {
    static const NamePair t[] = {
        {0x00000000, "CKM_RSA_PKCS_KEY_PAIR_GEN"}, {0x00000001, "CKM_RSA_PKCS"},
        {0x00000003, "CKM_RSA_X_509"}, {0x00000005, "CKM_MD5_RSA_PKCS"},
        {0x00000006, "CKM_SHA1_RSA_PKCS"}, {0x00000009, "CKM_RSA_PKCS_OAEP"},
        {0x0000000d, "CKM_RSA_PKCS_PSS"}, {0x0000000e, "CKM_SHA1_RSA_PKCS_PSS"},
        {0x0000000f, "CKM_ML_KEM_KEY_PAIR_GEN"}, {0x00000017, "CKM_ML_KEM"},
        {0x0000001c, "CKM_ML_DSA_KEY_PAIR_GEN"}, {0x0000001d, "CKM_ML_DSA"},
        {0x0000001f, "CKM_HASH_ML_DSA"}, {0x0000002d, "CKM_SLH_DSA_KEY_PAIR_GEN"},
        {0x0000002e, "CKM_SLH_DSA"}, {0x00000220, "CKM_SHA_1"},
        {0x00000250, "CKM_SHA256"}, {0x00000251, "CKM_SHA256_HMAC"},
        {0x00000260, "CKM_SHA384"}, {0x00000270, "CKM_SHA512"},
        {0x000002b0, "CKM_SHA3_256"}, {0x00000350, "CKM_GENERIC_SECRET_KEY_GEN"},
        {0x000003ac, "CKM_SP800_108_COUNTER_KDF"},
        {0x00001040, "CKM_EC_KEY_PAIR_GEN"}, {0x00001041, "CKM_ECDSA"},
        {0x00001050, "CKM_ECDH1_DERIVE"}, {0x00001051, "CKM_ECDH1_COFACTOR_DERIVE"},
        {0x00001055, "CKM_EC_EDWARDS_KEY_PAIR_GEN"},
        {0x00001056, "CKM_EC_MONTGOMERY_KEY_PAIR_GEN"}, {0x00001057, "CKM_EDDSA"},
        {0x00001080, "CKM_AES_KEY_GEN"}, {0x00001081, "CKM_AES_ECB"},
        {0x00001082, "CKM_AES_CBC"}, {0x00001085, "CKM_AES_CBC_PAD"},
        {0x00001086, "CKM_AES_CTR"}, {0x00001087, "CKM_AES_GCM"},
        {0x00002109, "CKM_AES_KEY_WRAP"}, {0x0000210a, "CKM_AES_KEY_WRAP_PAD"},
        {0x0000210b, "CKM_AES_KEY_WRAP_KWP"},
        {0x00004021, "CKM_HKDF_KEY_GEN"}, {0x0000402a, "CKM_HKDF_DERIVE"},
        {0x00004032, "CKM_HSS_KEY_PAIR_GEN"}, {0x00004033, "CKM_HSS"},
        {0x00004034, "CKM_XMSS_KEY_PAIR_GEN"}, {0x00004035, "CKM_XMSSMT_KEY_PAIR_GEN"},
        {0x00004036, "CKM_XMSS"}, {0x00004037, "CKM_XMSSMT"},
    };
    for (const auto& p : t) if (p.v == m) return p.n;
    char buf[40];
    if (m & 0x80000000UL) snprintf(buf, sizeof buf, "CKM_VENDOR|0x%08lx", (unsigned long)(m & 0x7fffffffUL));
    else                  snprintf(buf, sizeof buf, "CKM_0x%08lx", (unsigned long)m);
    return buf;
}

// ---------------------------------------------------------------------------
// Recorder — an ordered path -> value map. Every scenario writes into one of
// these; the comparator diffs two of them.
// ---------------------------------------------------------------------------
struct Recorder {
    std::vector<std::string>            order;
    std::map<std::string, std::string>  vals;

    void put(const std::string& path, const std::string& v) {
        if (!vals.count(path)) order.push_back(path);
        vals[path] = v;
    }
    void rv(const std::string& path, CK_RV r) { put(path + ".rv", rv_name(r)); }
    void num(const std::string& path, unsigned long long n) {
        put(path, std::to_string(n));
    }
    bool has(const std::string& p) const { return vals.count(p) != 0; }
};

static std::string to_hex(const CK_BYTE* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 0xf]; }
    return s;
}

// FNV-1a — a stable short fingerprint for long byte strings whose exact value
// is not comparable across engines but whose *stability* within one engine is
// still worth recording in the report for a human reading two runs.
static std::string fingerprint(const CK_BYTE* p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    char buf[32]; snprintf(buf, sizeof buf, "fnv:%016llx", (unsigned long long)h);
    return buf;
}

// Encoding classification. This is the load-bearing abstraction for Phase 3:
// the exact bytes of a freshly generated key differ between engines by
// construction, but the *encoding* must not.
static std::string classify(const CK_BYTE* p, size_t n) {
    if (n == 0) return "EMPTY";
    // Raw uncompressed EC points, before the DER check — a DER-wrapped P-256
    // point is 67 bytes, a raw one 65, so the lengths never collide.
    if (p[0] == 0x04) {
        if (n == 65)  return "RAW_EC_POINT_UNCOMPRESSED_P256";
        if (n == 97)  return "RAW_EC_POINT_UNCOMPRESSED_P384";
        if (n == 133) return "RAW_EC_POINT_UNCOMPRESSED_P521";
        if (n == 133) return "RAW_EC_POINT_UNCOMPRESSED_P521";
        if (n >= 2 && p[1] == n - 2)                       return "DER_OCTET_STRING";
        if (n >= 3 && p[1] == 0x81 && p[2] == n - 3)       return "DER_OCTET_STRING_LONG";
        if (n >= 4 && p[1] == 0x82 &&
            ((size_t)p[2] << 8 | p[3]) == n - 4)           return "DER_OCTET_STRING_LONG2";
    }
    if (p[0] == 0x30) {
        if (n >= 2 && p[1] == n - 2)                 return "DER_SEQUENCE";
        if (n >= 3 && p[1] == 0x81 && p[2] == n - 3) return "DER_SEQUENCE_LONG";
        if (n >= 4 && p[1] == 0x82 &&
            ((size_t)p[2] << 8 | p[3]) == n - 4)     return "DER_SEQUENCE_LONG2";
        return "DER_SEQUENCE_MALFORMED_LEN";
    }
    if (p[0] == 0x06 && n >= 2 && p[1] == n - 2) return "DER_OID";
    if (p[0] == 0x0c && n >= 2 && p[1] == n - 2) return "DER_UTF8STRING";
    if (p[0] == 0x13 && n >= 2 && p[1] == n - 2) return "DER_PRINTABLESTRING";
    if (n == 32) return "RAW_32";
    if (n == 56) return "RAW_56";
    if (n == 57) return "RAW_57";
    return "RAW";
}

// Attributes whose byte value is engine-random by construction (key material,
// engine-minted identifiers). For these the harness records return code,
// length and encoding class — never the bytes, which would guarantee a
// meaningless diff on every run.
static bool is_opaque_attr(CK_ATTRIBUTE_TYPE t) {
    switch (t) {
        case CKA_VALUE: case CKA_EC_POINT: case CKA_MODULUS:
        case CKA_PRIVATE_EXPONENT: case CKA_PRIME_1: case CKA_PRIME_2:
        case CKA_EXPONENT_1: case CKA_EXPONENT_2: case CKA_COEFFICIENT:
        case CKA_CHECK_VALUE: case CKA_UNIQUE_ID: case CKA_SEED:
        case CKA_PUBLIC_KEY_INFO: case CKA_START_DATE: case CKA_END_DATE:
            return true;
        default: return false;
    }
}

// Attributes with no internal structure: an identifier, a checksum or a date.
// Their bytes are not an encoding of anything, so classifying them is noise.
static bool is_unstructured_attr(CK_ATTRIBUTE_TYPE t) {
    switch (t) {
        case CKA_UNIQUE_ID: case CKA_CHECK_VALUE: case CKA_ID:
        case CKA_SEED: case CKA_START_DATE: case CKA_END_DATE:
        case CKA_LABEL: case CKA_APPLICATION:
            return true;
        default: return false;
    }
}

// Big-integer attributes. Their byte length varies by one with the random
// key — an RSA CRT exponent whose top byte happens to be zero serialises as
// 127 bytes rather than 128, roughly one key in 256 — so the exact length is
// not a cross-engine observable. It is recorded rounded up to a multiple of
// eight, which is stable across keys and still catches a truncated, empty or
// wrong-modulus-size value. Found the hard way: the harness failed on
// CKA_EXPONENT_1.len 127 vs 128 on one run in a series that was otherwise
// identical.
static bool is_bignum_attr(CK_ATTRIBUTE_TYPE t) {
    switch (t) {
        case CKA_MODULUS: case CKA_PUBLIC_EXPONENT: case CKA_PRIVATE_EXPONENT:
        case CKA_PRIME_1: case CKA_PRIME_2: case CKA_EXPONENT_1:
        case CKA_EXPONENT_2: case CKA_COEFFICIENT: case CKA_PUBLIC_KEY_INFO:
            return true;
        default: return false;
    }
}

// The canonical attribute probe. Every object produced by every creation path
// is interrogated with the SAME list, so "this engine does not set X" shows up
// as a return-code difference rather than as a silently missing row.
static const CK_ATTRIBUTE_TYPE kProbe[] = {
    CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL, CKA_UNIQUE_ID, CKA_MODIFIABLE,
    CKA_COPYABLE, CKA_DESTROYABLE, CKA_KEY_TYPE, CKA_ID, CKA_START_DATE, CKA_END_DATE,
    CKA_DERIVE, CKA_LOCAL, CKA_KEY_GEN_MECHANISM, CKA_SENSITIVE, CKA_ENCRYPT,
    CKA_DECRYPT, CKA_SIGN, CKA_SIGN_RECOVER, CKA_VERIFY, CKA_VERIFY_RECOVER,
    CKA_WRAP, CKA_UNWRAP, CKA_EXTRACTABLE, CKA_ALWAYS_SENSITIVE,
    CKA_NEVER_EXTRACTABLE, CKA_WRAP_WITH_TRUSTED, CKA_TRUSTED, CKA_CHECK_VALUE,
    CKA_VALUE_LEN, CKA_VALUE, CKA_ALWAYS_AUTHENTICATE, CKA_MODULUS,
    CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_PRIVATE_EXPONENT, CKA_PRIME_1,
    CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT,
    CKA_EC_PARAMS, CKA_EC_POINT, CKA_PARAMETER_SET, CKA_SEED,
    CKA_ENCAPSULATE, CKA_DECAPSULATE, CKA_PUBLIC_KEY_INFO, CKA_ALLOWED_MECHANISMS,
};

// ---------------------------------------------------------------------------
// record_attrs — the heart of coverage priority #1.
// ---------------------------------------------------------------------------
static void record_attrs(Engine& e, Recorder& r, const std::string& prefix,
                         CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o) {
    if (o == CK_INVALID_HANDLE) { r.put(prefix + ".object", "NONE"); return; }
    std::vector<std::string> present;
    for (CK_ATTRIBUTE_TYPE t : kProbe) {
        std::string an = attr_name(t);
        CK_ATTRIBUTE a = { t, NULL_PTR, 0 };
        CK_RV rv = e.fl->C_GetAttributeValue(s, o, &a, 1);
        r.put(prefix + "." + an + ".rv", rv_name(rv));
        if (rv != CKR_OK) continue;
        present.push_back(an);
        if (a.ulValueLen == (CK_ULONG)-1) { r.put(prefix + "." + an, "UNAVAILABLE"); continue; }
        if (is_bignum_attr(t))
            r.num(prefix + "." + an + ".len_rounded8",
                  (unsigned long long)((a.ulValueLen + 7) / 8 * 8));
        else
            r.num(prefix + "." + an + ".len", (unsigned long long)a.ulValueLen);
        std::vector<CK_BYTE> buf(a.ulValueLen ? a.ulValueLen : 1);
        a.pValue = buf.data();
        CK_RV rv2 = e.fl->C_GetAttributeValue(s, o, &a, 1);
        if (rv2 != CKR_OK) { r.put(prefix + "." + an + ".fetch", rv_name(rv2)); continue; }
        // Unstructured attributes are not classified. Running the encoding
        // classifier over an identity string or a three-byte checksum produces
        // a verdict that flips with the leading byte — a Rust unique id
        // beginning '0' reads as an ASN.1 SEQUENCE tag, and roughly one check
        // value in 256 starts 0x30 by chance. That made the harness fail at
        // random, and a flaky harness gets switched off. Length is still
        // recorded, which is the observable that actually carries meaning here
        // (a 3-byte check value present versus absent).
        // A big integer is not an encoding either: a 128-byte private exponent
        // whose first byte happens to be 0x30 classifies as an ASN.1 SEQUENCE,
        // which is the same random-byte trap as the check value above.
        if (!is_unstructured_attr(t) && !is_bignum_attr(t))
            r.put(prefix + "." + an + ".enc", classify(buf.data(), a.ulValueLen));
        if (is_opaque_attr(t)) {
            // Value intentionally not compared — see is_opaque_attr.
            r.put(prefix + "." + an + ".value", "<opaque>");
        } else if (a.ulValueLen <= 64) {
            r.put(prefix + "." + an + ".value", to_hex(buf.data(), a.ulValueLen));
        } else {
            r.put(prefix + "." + an + ".value", fingerprint(buf.data(), a.ulValueLen));
        }
    }
    std::string joined;
    for (size_t i = 0; i < present.size(); i++) { if (i) joined += ","; joined += present[i]; }
    r.put(prefix + "._ctx.attrs_present", joined);
    r.num(prefix + "._ctx.attrs_present_count", present.size());
}

// ---------------------------------------------------------------------------
// Small helpers used across scenarios
// ---------------------------------------------------------------------------
static CK_BBOOL bTrue  = CK_TRUE;
static CK_BBOOL bFalse = CK_FALSE;

#define ATTR(t, p, l) { (t), (CK_VOID_PTR)(p), (CK_ULONG)(l) }

// A fixed, non-random AES-256 key so that ciphertexts ARE comparable byte for
// byte. Random keys make output bytes incomparable; fixed keys make them the
// strongest check in the harness.
static CK_BYTE kFixedAes[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static CK_BYTE kFixedIv[16] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
};
static CK_BYTE kPlain32[32] = {
    'p','k','c','s','1','1','-','d','i','f','f','e','r','e','n','t',
    'i','a','l','-','h','a','r','n','e','s','s','-','0','8','1','3'
};
// DER OID for prime256v1 / P-256 — 06 08 2A 86 48 CE 3D 03 01 07
static CK_BYTE kOidP256[] = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
// DER OID for Ed25519 (RFC 8410) — 06 03 2B 65 70
static CK_BYTE kOidEd25519[] = {0x06,0x03,0x2b,0x65,0x70};
// DER OID for X25519 (RFC 8410) — 06 03 2B 65 6E
static CK_BYTE kOidX25519[] = {0x06,0x03,0x2b,0x65,0x6e};
// DER OID for brainpoolP256r1 — deliberately a curve neither engine implements.
static CK_BYTE kOidBrainpool[] = {0x06,0x09,0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07};

static CK_OBJECT_CLASS clSecret  = CKO_SECRET_KEY;
static CK_OBJECT_CLASS clPublic  = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS clPrivate = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS clData    = CKO_DATA;
static CK_KEY_TYPE     ktAes     = CKK_AES;
static CK_KEY_TYPE     ktGeneric = CKK_GENERIC_SECRET;
static CK_ULONG        len32     = 32;
static CK_ULONG        len16     = 16;

// How much of a byte output is comparable across engines.
//
//   BYTES — the whole output. Only valid when every input was fixed, so the
//           two engines are computing the same function of the same data.
//   SHAPE — length plus encoding class. For outputs that are random in value
//           but whose FRAMING is specified (the ECDH-KEM ephemeral point).
//   LEN   — length only. For outputs that are random in both value and first
//           byte; recording anything more would make the harness flaky, and a
//           flaky harness gets switched off.
enum class ByteView { BYTES, SHAPE, LEN };

static void record_bytes(Recorder& r, const std::string& path,
                         const CK_BYTE* p, size_t n, ByteView view) {
    r.num(path + ".len", (unsigned long long)n);
    if (n == 0) return;
    if (view == ByteView::BYTES) {
        r.put(path + ".enc", classify(p, n));
        r.put(path + ".bytes", to_hex(p, n));
    } else if (view == ByteView::SHAPE) {
        r.put(path + ".enc", classify(p, n));
        r.put(path + ".first_byte", to_hex(p, 1));
    }
}

// ---------------------------------------------------------------------------
// Scenario registry
// ---------------------------------------------------------------------------
struct Scenario {
    std::string id;
    std::string group;
    std::string description;
    std::vector<CK_MECHANISM_TYPE> requires_mechs;
    // rw==false → the scenario is run in a read-only session (S7 coverage).
    bool rw = true;
    bool login = true;
    std::function<void(Engine&, Recorder&, CK_SESSION_HANDLE)> run;
};

static std::vector<Scenario> gScenarios;
static void add(Scenario s) { gScenarios.push_back(std::move(s)); }

#include "scenarios.inc"

// ---------------------------------------------------------------------------
// Exception list
// ---------------------------------------------------------------------------
// An entry has one of two statuses, and the difference matters:
//
//   "legal"  — adjudicated against the specification: the divergence is
//              permitted, and the citation says why. It will never be fixed.
//   "defect" — a KNOWN, still-open non-conformance in one engine, recorded so
//              the harness has a stable baseline. It is not an excuse; it is a
//              worklist item with an owner named in the justification.
//
// Anything matching NEITHER fails the run. That is the whole mechanism: a new
// divergence cannot be introduced without someone writing a sentence about it.
struct Exception_ {
    std::string id, scenario, path, kind, status, justification, citation;
    // Why this entry can never match, for the entries that never can. An
    // adjudication about a divergence the probe cannot see — on-disk storage,
    // PIN lockout, build-flag-dependent mechanism sets — is worth writing down
    // and is not the same thing as an entry that HAS gone stale. Both used to
    // be reported under one heading reading "either the engines converged and
    // the entry is stale, or its scenario did not run", which meant six
    // permanent, deliberate entries sat in the stale list forever and trained
    // the reader to skip it. An entry scoped to __never_matches__ must now
    // declare this, and is listed separately.
    std::string unobservable;
    // Value matchers. Two divergences can share a path and be entirely
    // different questions — CKA_KEY_GEN_MECHANISM differing because Rust
    // narrows CK_UNAVAILABLE_INFORMATION to 32 bits is a defect; the same
    // path differing because Rust names the encapsulation mechanism is not.
    // Without these an entry for one silently absolves the other.
    std::string cpp_value = "*", rust_value = "*";
    int hits = 0;
};
static std::vector<Exception_> gExceptions;

// Minimal glob: '*' matches any run of characters, '?' any single one.
static bool glob(const std::string& pat, const std::string& s) {
    size_t p = 0, t = 0, star = std::string::npos, mark = 0;
    while (t < s.size()) {
        if (p < pat.size() && (pat[p] == '?' || pat[p] == s[t])) { p++; t++; }
        else if (p < pat.size() && pat[p] == '*') { star = p++; mark = t; }
        else if (star != std::string::npos) { p = star + 1; t = ++mark; }
        else return false;
    }
    while (p < pat.size() && pat[p] == '*') p++;
    return p == pat.size();
}

// '|' separates alternatives, so one entry can cover a family of attributes
// without being split into near-identical copies.
static bool glob_alt(const std::string& pat, const std::string& s) {
    size_t i = 0;
    while (i <= pat.size()) {
        size_t j = pat.find('|', i);
        if (j == std::string::npos) j = pat.size();
        if (glob(pat.substr(i, j - i), s)) return true;
        if (j == pat.size()) break;
        i = j + 1;
    }
    return false;
}

static void load_exceptions(const std::string& file) {
    std::ifstream in(file);
    if (!in) { fprintf(stdout, "FATAL: cannot open exception list %s\n", file.c_str()); exit(2); }
    json j; in >> j;
    for (const auto& e : j.at("entries")) {
        Exception_ x;
        x.id            = e.at("id").get<std::string>();
        x.scenario      = e.value("scenario", "*");
        x.path          = e.value("path", "*");
        x.kind          = e.value("kind", "*");
        x.cpp_value     = e.value("cpp", "*");
        x.rust_value    = e.value("rust", "*");
        x.status        = e.at("status").get<std::string>();
        if (x.status != "legal" && x.status != "defect") {
            fprintf(stdout, "FATAL: exception %s has status '%s'; only 'legal' or 'defect' are allowed\n",
                    x.id.c_str(), x.status.c_str());
            exit(2);
        }
        x.justification = e.at("justification").get<std::string>();
        x.citation      = e.value("citation", "");
        x.unobservable  = e.value("unobservable", "");
        if (x.scenario == "__never_matches__" && x.unobservable.empty()) {
            fprintf(stdout, "FATAL: exception %s is scoped to __never_matches__ but declares no "
                            "'unobservable' reason. Say why the probe cannot see it, or give it a "
                            "real scenario glob.\n", x.id.c_str());
            exit(2);
        }
        if (!x.unobservable.empty() && x.scenario != "__never_matches__") {
            fprintf(stdout, "FATAL: exception %s declares 'unobservable' but is scoped to '%s'. An "
                            "entry that CAN match must not claim it cannot.\n",
                    x.id.c_str(), x.scenario.c_str());
            exit(2);
        }
        if (!opt_drop_exception.empty() && x.id == opt_drop_exception) {
            fprintf(stdout, "[demo] exception %s DROPPED for this run\n", x.id.c_str());
            continue;
        }
        gExceptions.push_back(std::move(x));
    }
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------
struct Finding {
    std::string scenario, path, kind, cpp, rust, exception_id, status, justification, citation;
};
static std::vector<Finding> gFindings;

// Attribute-set context: for every object the harness probed, which attributes
// each engine possesses. Not a finding — the individual differences are already
// findings — but it is the single most legible view of "what does this object
// look like on each side", so it goes in the report.
struct CtxEntry { std::string scenario, prefix, cpp, rust; };
static std::vector<CtxEntry> gCtx;

// Total observations compared — the denominator the divergence counts sit over.
static size_t gCompared = 0;

static Exception_* match_exception(const Finding& f) {
    for (auto& x : gExceptions)
        if (glob_alt(x.scenario, f.scenario) && glob_alt(x.path, f.path) &&
            glob_alt(x.kind, f.kind) &&
            glob_alt(x.cpp_value, f.cpp) && glob_alt(x.rust_value, f.rust))
            return &x;
    return nullptr;
}

// ---------------------------------------------------------------------------
// Engine loading and token setup
// ---------------------------------------------------------------------------
static bool load_engine(Engine& e, const std::string& path, const std::string& name) {
    e.name = name; e.path = path;
    e.h = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!e.h) { fprintf(stdout, "FATAL: dlopen %s: %s\n", path.c_str(), dlerror()); return false; }
    CK_C_GetFunctionList gfl = (CK_C_GetFunctionList)dlsym(e.h, "C_GetFunctionList");
    if (!gfl) { fprintf(stdout, "FATAL: %s exports no C_GetFunctionList\n", path.c_str()); return false; }
    if (gfl(&e.fl) != CKR_OK || !e.fl) { fprintf(stdout, "FATAL: %s C_GetFunctionList failed\n", name.c_str()); return false; }
    e.Encapsulate = (fn_EncapsulateKey)dlsym(e.h, "C_EncapsulateKey");
    e.Decapsulate = (fn_DecapsulateKey)dlsym(e.h, "C_DecapsulateKey");
    return true;
}

static bool setup_token(Engine& e) {
    CK_RV rv = e.fl->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        fprintf(stdout, "FATAL: %s C_Initialize -> %s\n", e.name.c_str(), rv_name(rv).c_str());
        return false;
    }
    CK_ULONG n = 0;
    if (e.fl->C_GetSlotList(CK_FALSE, NULL_PTR, &n) != CKR_OK || n == 0) {
        fprintf(stdout, "FATAL: %s has no slots\n", e.name.c_str()); return false;
    }
    std::vector<CK_SLOT_ID> ids(n);
    e.fl->C_GetSlotList(CK_FALSE, ids.data(), &n);
    e.slot = ids[0];

    // Normalise the starting state: both engines get a token initialised with
    // the SAME SO PIN, user PIN and label. Without this the diff would be
    // dominated by setup noise rather than engine behaviour.
    CK_UTF8CHAR label[32];
    memset(label, ' ', 32);
    memcpy(label, "P11DIFF", 7);
    rv = e.fl->C_InitToken(e.slot, (CK_UTF8CHAR_PTR)SO_PIN, strlen(SO_PIN), label);
    if (rv != CKR_OK) {
        fprintf(stdout, "FATAL: %s C_InitToken -> %s\n", e.name.c_str(), rv_name(rv).c_str());
        return false;
    }
    CK_SESSION_HANDLE so = CK_INVALID_HANDLE;
    rv = e.fl->C_OpenSession(e.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &so);
    if (rv != CKR_OK) { fprintf(stdout, "FATAL: %s SO OpenSession -> %s\n", e.name.c_str(), rv_name(rv).c_str()); return false; }
    rv = e.fl->C_Login(so, CKU_SO, (CK_UTF8CHAR_PTR)SO_PIN, strlen(SO_PIN));
    if (rv != CKR_OK) { fprintf(stdout, "FATAL: %s SO Login -> %s\n", e.name.c_str(), rv_name(rv).c_str()); return false; }
    rv = e.fl->C_InitPIN(so, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN));
    if (rv != CKR_OK) { fprintf(stdout, "FATAL: %s C_InitPIN -> %s\n", e.name.c_str(), rv_name(rv).c_str()); return false; }
    e.fl->C_Logout(so);
    e.fl->C_CloseSession(so);

    CK_ULONG mn = 0;
    if (e.fl->C_GetMechanismList(e.slot, NULL_PTR, &mn) == CKR_OK && mn) {
        std::vector<CK_MECHANISM_TYPE> ms(mn);
        e.fl->C_GetMechanismList(e.slot, ms.data(), &mn);
        e.mechs.insert(ms.begin(), ms.end());
    }
    return true;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------
static void run_scenario(const Scenario& sc, Engine& e, Recorder& r) {
    // Mechanism gate. A scenario whose mechanism one engine lacks records only
    // the gate result, so the diff is exactly one legible line rather than a
    // cascade of failures.
    bool ok = true;
    for (CK_MECHANISM_TYPE m : sc.requires_mechs) {
        bool have = e.mechs.count(m) != 0;
        r.put("require." + mech_name(m), have ? "present" : "ABSENT");
        if (!have) ok = false;
    }
    if (!ok) { r.put("status", "SKIPPED_MECHANISM_ABSENT"); return; }

    CK_FLAGS flags = CKF_SERIAL_SESSION | (sc.rw ? CKF_RW_SESSION : 0);
    CK_SESSION_HANDLE s = CK_INVALID_HANDLE;
    CK_RV rv = e.fl->C_OpenSession(e.slot, flags, NULL_PTR, NULL_PTR, &s);
    if (rv != CKR_OK) { r.put("status", "OPEN_SESSION_FAILED:" + rv_name(rv)); return; }
    if (sc.login) {
        rv = e.fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            r.put("status", "LOGIN_FAILED:" + rv_name(rv));
            e.fl->C_CloseSession(s);
            return;
        }
    }
    r.put("status", "RAN");
    sc.run(e, r, s);
    e.fl->C_Logout(s);
    e.fl->C_CloseSession(s);
    // Close every session on the slot so no scenario can leak login state into
    // the next one. (Whether that resets login state is itself a C6 behaviour
    // the harness covers in a dedicated scenario.)
    e.fl->C_CloseAllSessions(e.slot);
}

static void compare(const Scenario& sc, const Recorder& a, const Recorder& b) {
    std::set<std::string> paths;
    for (const auto& p : a.order) paths.insert(p);
    for (const auto& p : b.order) paths.insert(p);
    // Preserve C++'s recording order first, then any Rust-only tail.
    std::vector<std::string> ordered;
    std::set<std::string> seen;
    for (const auto& p : a.order) { ordered.push_back(p); seen.insert(p); }
    for (const auto& p : b.order) if (!seen.count(p)) ordered.push_back(p);

    for (const auto& p : ordered) {
        // "_ctx." paths are recorded for the human reading the report and are
        // deliberately NOT compared: they are summaries of observations that
        // are already compared individually, so comparing them again would
        // make one attribute difference report twice and, worse, would need an
        // exception entry whose scope is "any attribute at all".
        if (p.find("._ctx.attrs_present") != std::string::npos &&
            p.find("_count") == std::string::npos) {
            CtxEntry ce;
            ce.scenario = sc.id;
            ce.prefix   = p.substr(0, p.find("._ctx."));
            ce.cpp      = a.vals.count(p) ? a.vals.at(p) : "";
            ce.rust     = b.vals.count(p) ? b.vals.at(p) : "";
            if (ce.cpp != ce.rust) gCtx.push_back(ce);
        }
        if (p.rfind("_ctx.", 0) == 0 || p.find("._ctx.") != std::string::npos) continue;
        gCompared++;
        bool ha = a.vals.count(p), hb = b.vals.count(p);
        Finding f;
        f.scenario = sc.id; f.path = p;
        if (ha && hb) {
            if (a.vals.at(p) == b.vals.at(p)) continue;
            f.kind = "value_differs";
            f.cpp = a.vals.at(p); f.rust = b.vals.at(p);
        } else if (ha) {
            f.kind = "cpp_only"; f.cpp = a.vals.at(p); f.rust = "<absent>";
        } else {
            f.kind = "rust_only"; f.cpp = "<absent>"; f.rust = b.vals.at(p);
        }
        Exception_* x = match_exception(f);
        if (x) { x->hits++; f.exception_id = x->id; f.status = x->status;
                 f.justification = x->justification; f.citation = x->citation; }
        gFindings.push_back(std::move(f));
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
// Written BEFORE anything is printed: a run piped into `head` takes SIGPIPE
// partway through the console listing, and a report that only exists when
// nobody truncated the output is not a report.
static void write_files(int ran, int skipped, size_t covered, size_t uncovered);

static void write_reports(int ran, int skipped) {
    size_t covered = 0, uncovered = 0, legal = 0, defect = 0;
    for (const auto& f : gFindings) {
        if (f.exception_id.empty()) { uncovered++; continue; }
        covered++;
        (f.status == "defect" ? defect : legal)++;
    }
    write_files(ran, skipped, covered, uncovered);

    printf("\n");
    printf("================================================================\n");
    printf(" DIFFERENTIAL RESULT\n");
    printf("================================================================\n");
    printf(" scenarios run          : %d (%d skipped for absent mechanisms)\n", ran, skipped);
    printf(" observations compared  : %zu\n", gCompared);
    printf(" divergences, legal     : %zu  (adjudicated permitted, with citation)\n", legal);
    printf(" divergences, known defect: %zu (recorded open non-conformance)\n", defect);
    printf(" divergences, UNCOVERED : %zu  <-- these fail the run\n", uncovered);
    printf("================================================================\n\n");

    if (uncovered) {
        printf("UNCOVERED DIVERGENCES — each of these is either a real defect or a\n");
        printf("missing exception entry. Neither may be left unresolved.\n\n");
        const size_t kConsoleCap = 80;
        size_t shown = 0;
        std::string last;
        for (const auto& f : gFindings) {
            if (!f.exception_id.empty()) continue;
            if (shown++ >= kConsoleCap) continue;
            if (f.scenario != last) { printf("  ── scenario: %s\n", f.scenario.c_str()); last = f.scenario; }
            printf("     %-8s %s\n", f.kind.c_str(), f.path.c_str());
            printf("        cpp  : %s\n", f.cpp.c_str());
            printf("        rust : %s\n", f.rust.c_str());
        }
        if (uncovered > kConsoleCap)
            printf("\n  … %zu more; the complete list is in %s.md and %s.json\n",
                   uncovered - kConsoleCap, opt_report.c_str(), opt_report.c_str());
        printf("\n");
    }

    if (opt_verbose && covered) {
        printf("COVERED DIVERGENCES (grouped by exception entry)\n\n");
        std::map<std::string, std::vector<const Finding*>> byX;
        for (const auto& f : gFindings) if (!f.exception_id.empty()) byX[f.exception_id].push_back(&f);
        for (const auto& kv : byX) {
            printf("  [%s] (%s) %zu observation(s)\n", kv.first.c_str(),
                   kv.second.front()->status.c_str(), kv.second.size());
            printf("      why: %s\n", kv.second.front()->justification.c_str());
            if (!kv.second.front()->citation.empty())
                printf("      cite: %s\n", kv.second.front()->citation.c_str());
            for (const auto* f : kv.second)
                printf("      - %s / %s : cpp=%s rust=%s\n", f->scenario.c_str(), f->path.c_str(),
                       f->cpp.c_str(), f->rust.c_str());
            printf("\n");
        }
    }

    std::vector<const Exception_*> unused, unobservable;
    for (const auto& x : gExceptions) {
        if (x.hits != 0) continue;
        (x.unobservable.empty() ? unused : unobservable).push_back(&x);
    }
    if (!unobservable.empty()) {
        printf("STANDING ADJUDICATIONS, DELIBERATELY UNOBSERVABLE (%zu) — these do not\n",
               unobservable.size());
        printf("match because no probe can see them, and each says why. Not stale:\n");
        for (const auto* x : unobservable)
            printf("  - %-42s %s\n", x->id.c_str(), x->unobservable.c_str());
        printf("\n");
    }
    if (!unused.empty()) {
        printf("EXCEPTION ENTRIES THAT MATCHED NOTHING (%zu) — the engines converged\n", unused.size());
        printf("and the entry is stale, or its scenario did not run. DELETE a stale\n");
        printf("entry; do not leave it as cover for a divergence that no longer exists:\n");
        for (const auto* x : unused) printf("  - %s\n", x->id.c_str());
        printf("\n");
    }

    printf("reports: %s.json  %s.md\n", opt_report.c_str(), opt_report.c_str());
}

static void write_files(int ran, int skipped, size_t covered, size_t uncovered) {
    size_t legal = 0, defect = 0;
    for (const auto& f : gFindings)
        if (!f.exception_id.empty()) (f.status == "defect" ? defect : legal)++;
    // JSON
    json j;
    j["_summary"] = {
        {"scenarios_run", ran}, {"scenarios_skipped", skipped},
        {"observations_compared", gCompared},
        {"divergences_covered", covered}, {"divergences_uncovered", uncovered},
        {"divergences_legal", legal}, {"divergences_known_defect", defect},
        {"cpp_engine", gCpp.path}, {"rust_engine", gRust.path},
        {"exception_list", opt_exceptions},
        {"dropped_exception", opt_drop_exception},
    };
    for (const auto& f : gFindings) {
        j["findings"].push_back({
            {"scenario", f.scenario}, {"path", f.path}, {"kind", f.kind},
            {"cpp", f.cpp}, {"rust", f.rust},
            {"exception_id", f.exception_id}, {"status", f.status},
            {"justification", f.justification},
            {"citation", f.citation},
        });
    }
    for (const auto& x : gExceptions)
        j["exception_usage"].push_back({{"id", x.id}, {"status", x.status}, {"hits", x.hits}});
    { std::ofstream o(opt_report + ".json"); o << std::setw(2) << j << std::endl; }

    // Markdown
    std::ofstream md(opt_report + ".md");
    md << "# Cross-engine differential report\n\n";
    md << "**C++ engine:** `" << gCpp.path << "`  \n";
    md << "**Rust engine:** `" << gRust.path << "`  \n";
    md << "**Exception list:** `" << opt_exceptions << "`  \n";
    if (!opt_drop_exception.empty())
        md << "**Exception deliberately dropped for this run:** `" << opt_drop_exception << "`  \n";
    md << "\n| | |\n|---|---|\n";
    md << "| scenarios run | " << ran << " |\n";
    md << "| observations compared | " << gCompared << " |\n";
    md << "| scenarios skipped (mechanism absent on one engine) | " << skipped << " |\n";
    md << "| divergences adjudicated legal | " << legal << " |\n";
    md << "| divergences recorded as known defects | " << defect << " |\n";
    md << "| divergences UNCOVERED | " << uncovered << " |\n\n";
    if (uncovered) {
        md << "## Uncovered divergences\n\n| scenario | path | kind | C++ | Rust |\n|---|---|---|---|---|\n";
        for (const auto& f : gFindings) if (f.exception_id.empty())
            md << "| " << f.scenario << " | `" << f.path << "` | " << f.kind
               << " | `" << f.cpp << "` | `" << f.rust << "` |\n";
        md << "\n";
    }
    if (!gCtx.empty()) {
        md << "## Attribute-set context\n\n";
        md << "For every object whose attribute set differs, which attributes each engine\n";
        md << "possesses. Context, not findings — every entry here is also reported\n";
        md << "individually above or covered by an exception.\n\n";
        md << "| scenario | object | present only on C++ | present only on Rust |\n|---|---|---|---|\n";
        for (const auto& c : gCtx) {
            auto split = [](const std::string& v) {
                std::set<std::string> out; size_t i = 0;
                while (i < v.size()) { size_t j = v.find(',', i);
                    if (j == std::string::npos) j = v.size();
                    if (j > i) out.insert(v.substr(i, j - i)); i = j + 1; }
                return out;
            };
            auto A = split(c.cpp), B = split(c.rust);
            std::string onlyA, onlyB;
            for (const auto& x : A) if (!B.count(x)) { if (!onlyA.empty()) onlyA += ", "; onlyA += x; }
            for (const auto& x : B) if (!A.count(x)) { if (!onlyB.empty()) onlyB += ", "; onlyB += x; }
            md << "| " << c.scenario << " | `" << c.prefix << "` | " << (onlyA.empty() ? "—" : onlyA)
               << " | " << (onlyB.empty() ? "—" : onlyB) << " |\n";
        }
        md << "\n";
    }

    md << "## Covered divergences by exception entry\n\n";
    std::map<std::string, size_t> counts;
    for (const auto& f : gFindings) if (!f.exception_id.empty()) counts[f.exception_id]++;
    md << "| exception | status | observations | justification | citation |\n|---|---|---|---|---|\n";
    for (const auto& x : gExceptions)
        md << "| " << x.id << " | " << x.status << " | " << counts[x.id] << " | "
           << x.justification << " | " << x.citation << " |\n";
    md << "\n";
}

// ---------------------------------------------------------------------------
static void usage() {
    printf("p11_diff — cross-engine PKCS#11 differential harness\n\n");
    printf("  --cpp-engine <path>    C++ engine shared library (required)\n");
    printf("  --rust-engine <path>   Rust engine cdylib (required)\n");
    printf("  --workdir <dir>        hermetic token store + softhsm2.conf\n");
    printf("  --report <prefix>      report prefix (writes .json and .md)\n");
    printf("  --exceptions <file>    exception list (default tests/differential/exceptions.json)\n");
    printf("  --only <substr>        run only scenarios whose id contains substr\n");
    printf("  --drop-exception <id>  ignore one exception entry — proves the harness still detects\n");
    printf("  --list                 list scenarios and exit\n");
    printf("  --verbose              print covered divergences too\n");
}

int main(int argc, char** argv) {
    bool list_only = false;
    static struct option lo[] = {
        {"cpp-engine", required_argument, 0, 1},
        {"rust-engine", required_argument, 0, 2},
        {"workdir", required_argument, 0, 3},
        {"report", required_argument, 0, 4},
        {"exceptions", required_argument, 0, 5},
        {"only", required_argument, 0, 6},
        {"drop-exception", required_argument, 0, 7},
        {"verbose", no_argument, 0, 8},
        {"list", no_argument, 0, 9},
        {"shard", required_argument, 0, 10},
        {"help", no_argument, 0, 'h'},
        {0,0,0,0}
    };
    int c, idx;
    while ((c = getopt_long(argc, argv, "h", lo, &idx)) != -1) {
        switch (c) {
            case 1: opt_cpp_engine = optarg; break;
            case 2: opt_rust_engine = optarg; break;
            case 3: opt_workdir = optarg; break;
            case 4: opt_report = optarg; break;
            case 5: opt_exceptions = optarg; break;
            case 6: opt_only = optarg; break;
            case 7: opt_drop_exception = optarg; break;
            case 8: opt_verbose = true; break;
            case 9: list_only = true; break;
            case 10: {
                std::string v = optarg;
                size_t slash = v.find('/');
                if (slash == std::string::npos) {
                    fprintf(stdout, "FATAL: --shard wants I/N, e.g. --shard 2/8\n");
                    return 2;
                }
                opt_shard_index = atoi(v.substr(0, slash).c_str());
                opt_shard_count = atoi(v.substr(slash + 1).c_str());
                if (opt_shard_count < 1 || opt_shard_index < 0 || opt_shard_index >= opt_shard_count) {
                    fprintf(stdout, "FATAL: --shard %s out of range (want 0 <= I < N)\n", v.c_str());
                    return 2;
                }
                break;
            }
            default: usage(); return 2;
        }
    }

    register_scenarios();

    if (list_only) {
        printf("%-40s %-16s %s\n", "SCENARIO", "GROUP", "DESCRIPTION");
        for (const auto& s : gScenarios)
            printf("%-40s %-16s %s\n", s.id.c_str(), s.group.c_str(), s.description.c_str());
        printf("\n%zu scenarios\n", gScenarios.size());
        return 0;
    }
    if (opt_cpp_engine.empty() || opt_rust_engine.empty()) { usage(); return 2; }

    load_exceptions(opt_exceptions);

    // Hermetic workdir — the C++ engine keeps token objects on disk and reads
    // its configuration from SOFTHSM2_CONF; the Rust engine keeps everything in
    // memory and ignores both. That asymmetry is itself an exception entry.
    std::string setup = "rm -rf '" + opt_workdir + "' && mkdir -p '" + opt_workdir + "/tokens'";
    if (system(setup.c_str()) != 0) { fprintf(stdout, "FATAL: cannot create %s\n", opt_workdir.c_str()); return 2; }
    std::string conf = opt_workdir + "/softhsm2.conf";
    { FILE* f = fopen(conf.c_str(), "w");
      if (!f) { fprintf(stdout, "FATAL: cannot write %s\n", conf.c_str()); return 2; }
      fprintf(f, "directories.tokendir = %s/tokens/\n", opt_workdir.c_str());
      fprintf(f, "objectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n");
      fclose(f); }
    setenv("SOFTHSM2_CONF", conf.c_str(), 1);

    // The C++ engine is built with LOG_TO_STDERR (it is ON whenever BUILD_TESTS
    // is), and the attribute probe deliberately asks every object for every
    // attribute — which the engine logs at debug level thousands of times. That
    // noise is engine output, not harness output, so it goes to its own file.
    // Everything the harness itself says goes to stdout.
    std::string elog = opt_workdir + "/engine-stderr.log";
    printf("engine stderr -> %s\n", elog.c_str());
    if (!freopen(elog.c_str(), "w", stderr))
        printf("WARNING: could not redirect engine stderr\n");

    if (!load_engine(gCpp, opt_cpp_engine, "cpp")) return 2;
    if (!load_engine(gRust, opt_rust_engine, "rust")) return 2;

    // The single-process design's load-bearing assumption, asserted rather than
    // assumed: the two images' C_* symbols must not have interposed.
    if ((void*)gCpp.fl->C_Initialize == (void*)gRust.fl->C_Initialize) {
        fprintf(stdout, "FATAL: the two engines resolved to the SAME C_Initialize — dynamic\n"
                        "       symbol interposition has occurred and every result below would\n"
                        "       be a comparison of one engine with itself. Refusing to run.\n");
        return 2;
    }
    printf("engine images distinct: cpp C_Initialize=%p rust C_Initialize=%p\n",
           (void*)gCpp.fl->C_Initialize, (void*)gRust.fl->C_Initialize);

    if (!setup_token(gCpp))  return 2;
    if (!setup_token(gRust)) return 2;
    printf("cpp  mechanisms: %zu\n", gCpp.mechs.size());
    printf("rust mechanisms: %zu\n", gRust.mechs.size());

    // Filter by --only (substring) and --shard (round-robin on the GLOBAL
    // index, before filtering by --only, so a shard's membership doesn't
    // shift depending on what --only happens to also be set to).
    std::vector<const Scenario*> queue;
    for (size_t i = 0; i < gScenarios.size(); i++) {
        if (opt_shard_index >= 0 && (int)(i % opt_shard_count) != opt_shard_index) continue;
        const auto& sc = gScenarios[i];
        if (!opt_only.empty() && sc.id.find(opt_only) == std::string::npos) continue;
        queue.push_back(&sc);
    }

    int ran = 0, skipped = 0;
    size_t total = queue.size();
    for (size_t qi = 0; qi < total; qi++) {
        const Scenario& sc = *queue[qi];
        // Progress, printed and FLUSHED before the scenario runs — this is
        // what shows which scenario a hang is stuck in, not just what
        // finished before it. Prefixed so a sharded run's interleaved
        // stdout (each worker on its own fd, not actually interleaved
        // character-by-character, but still worth a stable prefix) reads
        // unambiguously in a merged log.
        std::string prefix = (opt_shard_index >= 0)
            ? ("shard " + std::to_string(opt_shard_index) + "/" + std::to_string(opt_shard_count) + " ")
            : "";
        printf("%s[%zu/%zu] %-42s running...", prefix.c_str(), qi + 1, total, sc.id.c_str());
        fflush(stdout);
        auto t0 = std::chrono::steady_clock::now();

        Recorder ra, rb;
        run_scenario(sc, gCpp, ra);
        run_scenario(sc, gRust, rb);
        if (ra.vals.count("status") && ra.vals.at("status") == "SKIPPED_MECHANISM_ABSENT" &&
            rb.vals.count("status") && rb.vals.at("status") == "SKIPPED_MECHANISM_ABSENT") skipped++;
        else ran++;
        compare(sc, ra, rb);

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        printf("\r%s[%zu/%zu] %-42s cpp=%-28s rust=%-28s (%lldms)\n", prefix.c_str(), qi + 1, total,
               sc.id.c_str(),
               ra.vals.count("status") ? ra.vals.at("status").c_str() : "?",
               rb.vals.count("status") ? rb.vals.at("status").c_str() : "?",
               (long long)ms);
        fflush(stdout);
    }

    gCpp.fl->C_Finalize(NULL_PTR);
    gRust.fl->C_Finalize(NULL_PTR);

    write_reports(ran, skipped);

    size_t uncovered = 0;
    for (const auto& f : gFindings) if (f.exception_id.empty()) uncovered++;
    return uncovered ? 1 : 0;
}
