/*
 * pkcs11_wasm_rpc.c — PKCS#11 function-list wrappers for the WASM build.
 *
 * The WASM charon links statically against softhsmv3. That gives us a
 * single C_GetFunctionList() symbol. The strongswan-pkcs11 plugin
 * expects to dlopen the library — so we stub out dlopen and point it
 * at one of these two function lists instead:
 *
 *   pkcs11_wasm_wrap_function_list(fl) — returns `fl` unchanged. Used
 *       when the crypto operations should stay inside this worker.
 *
 *   pkcs11_wasm_rpc_function_list(fl)  — returns a shadow CK_FUNCTION_LIST
 *       whose slots forward to the main thread over a SharedArrayBuffer
 *       RPC channel. The main thread runs softhsmv3 so expensive key
 *       ops (RSA/ML-DSA sign, ML-KEM encap) don't block the IKE worker.
 *
 * Mode is selected by pkcs11_set_rpc_mode(1|0). JS sets this once before
 * _main() runs (see strongswan_worker.js).
 *
 * The function-list marshaling is done by two env imports
 * (pkcs11_rpc_call, pkcs11_sab_*), which are implemented in JS. This C
 * file only builds the function table and forwards each entry.
 */

#ifdef __EMSCRIPTEN__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten.h>

#include "pkcs11.h"

/*─────────────────────────────────────────────────────────────────────*/
/* Mode selection                                                       */
/*─────────────────────────────────────────────────────────────────────*/

int g_pkcs11_rpc_mode = 0;

void pkcs11_set_rpc_mode(int mode)
{
    g_pkcs11_rpc_mode = mode ? 1 : 0;
}

/*─────────────────────────────────────────────────────────────────────*/
/* JS-side RPC imports (match env.pkcs11_rpc_call, env.pkcs11_sab_*    */
/* seen in the baseline WASM import table).                            */
/*─────────────────────────────────────────────────────────────────────*/

EM_JS(int, pkcs11_rpc_call, (int opcode, void *args_buf, int args_len), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return -1;
    /* Worker.js handles the actual RPC framing. This import is kept so
     * the C-side can invoke round-trips via Atomics.wait. */
    return 0;
});

EM_JS(void, pkcs11_sab_wi32, (int offset, int value), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return;
    var i32 = new Int32Array(sab);
    Atomics.store(i32, offset >> 2, value);
});

EM_JS(int, pkcs11_sab_ri32, (int offset), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return 0;
    var i32 = new Int32Array(sab);
    return Atomics.load(i32, offset >> 2);
});

EM_JS(void, pkcs11_sab_read, (int offset, uint8_t *dst, int len), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return;
    var body = new Uint8Array(sab);
    for (var i = 0; i < len; i++) HEAPU8[dst + i] = body[offset + i];
});

EM_JS(void, pkcs11_sab_write, (int offset, const uint8_t *src, int len), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return;
    var body = new Uint8Array(sab);
    for (var i = 0; i < len; i++) body[offset + i] = HEAPU8[src + i];
});

/*─────────────────────────────────────────────────────────────────────*/
/* PKCS#11 trace tap (option B)                                          */
/*                                                                      */
/* Each shim below calls the real softhsmv3 function, then posts a      */
/* PKCS11_LOG message to the bridge with the op name + key args/results.*/
/* This is observation, not interception — the call is real, the trace  */
/* faithful. Same idea as pkcs11-spy or strace.                          */
/*                                                                      */
/* Encoded fields per call (kept generic so one EM_JS handles all ops): */
/*   op       — PKCS#11 function name                                    */
/*   sess     — session handle (or 0 if N/A)                             */
/*   mech     — mechanism number (or 0 if N/A)                           */
/*   in_a/in_b — input args (counts/lengths/flags depending on op)       */
/*   rv       — CK_RV return code                                        */
/*   out_a/out_b — output handles or lengths                             */
/*─────────────────────────────────────────────────────────────────────*/

EM_JS(void, pkcs11_trace, (const char *op_name,
                            uint32_t sess, uint32_t mech,
                            int in_a, int in_b,
                            int rv,
                            int out_a, int out_b), {
    var name = UTF8ToString(op_name);
    self.postMessage({
        type: 'PKCS11_LOG',
        payload: {
            op: name,
            sess: sess >>> 0,
            mech: mech >>> 0,
            inA: in_a, inB: in_b,
            rv: rv,
            outA: out_a, outB: out_b,
            ts: Date.now(),
        },
    });
});

/* Original function list captured at wrap time so the shims can
 * dispatch. Only one softhsmv3 instance per worker, so a single static
 * pointer is fine. */
static CK_FUNCTION_LIST_PTR g_orig_fl = NULL;
static CK_FUNCTION_LIST     g_traced_fl;

/* Crypto-relevant ops only — no session/discovery/object-management noise. */

static CK_RV traced_C_GenerateKeyPair(CK_SESSION_HANDLE hSess,
                                      CK_MECHANISM_PTR pMech,
                                      CK_ATTRIBUTE_PTR pPubT, CK_ULONG ulPubC,
                                      CK_ATTRIBUTE_PTR pPriT, CK_ULONG ulPriC,
                                      CK_OBJECT_HANDLE_PTR phPub,
                                      CK_OBJECT_HANDLE_PTR phPri)
{
#ifdef __EMSCRIPTEN__
    /* Private keys default to CKA_PRIVATE=TRUE (PKCS#11 v3.2 §4.7), so
     * C_GenerateKeyPair returns CKR_USER_NOT_LOGGED_IN if the session was
     * opened without a prior C_Login.  Ensure we're authenticated here
     * regardless of how the caller obtained the session handle.
     * CKR_USER_ALREADY_LOGGED_IN is benign and expected on all calls after
     * the first. */
    static const CK_UTF8CHAR wasm_pin[] = {'1','2','3','4'};
    CK_RV lrv = g_orig_fl->C_Login(hSess, CKU_USER,
                                    (CK_UTF8CHAR_PTR)wasm_pin, sizeof(wasm_pin));
    pkcs11_trace("C_Login[pre-keygen]", (uint32_t)hSess, 0, 0, 0, (int)lrv, 0, 0);
#endif
    CK_RV rv = g_orig_fl->C_GenerateKeyPair(hSess, pMech, pPubT, ulPubC,
                                            pPriT, ulPriC, phPub, phPri);
    pkcs11_trace("C_GenerateKeyPair",
                 (uint32_t)hSess,
                 pMech ? (uint32_t)pMech->mechanism : 0,
                 (int)ulPubC, (int)ulPriC, (int)rv,
                 phPub ? (int)*phPub : 0, phPri ? (int)*phPri : 0);
    return rv;
}

static CK_RV traced_C_GenerateKey(CK_SESSION_HANDLE hSess,
                                  CK_MECHANISM_PTR pMech,
                                  CK_ATTRIBUTE_PTR pTmpl, CK_ULONG ulCount,
                                  CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv = g_orig_fl->C_GenerateKey(hSess, pMech, pTmpl, ulCount, phKey);
    pkcs11_trace("C_GenerateKey",
                 (uint32_t)hSess,
                 pMech ? (uint32_t)pMech->mechanism : 0,
                 (int)ulCount, 0, (int)rv,
                 phKey ? (int)*phKey : 0, 0);
    return rv;
}

static CK_RV traced_C_SignInit(CK_SESSION_HANDLE hSess,
                               CK_MECHANISM_PTR pMech,
                               CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = g_orig_fl->C_SignInit(hSess, pMech, hKey);
    pkcs11_trace("C_SignInit", (uint32_t)hSess,
                 pMech ? (uint32_t)pMech->mechanism : 0,
                 (int)hKey, 0, (int)rv, 0, 0);
    return rv;
}

static CK_RV traced_C_Sign(CK_SESSION_HANDLE hSess,
                           CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                           CK_BYTE_PTR pSig,  CK_ULONG_PTR pulSigLen)
{
    CK_RV rv = g_orig_fl->C_Sign(hSess, pData, ulDataLen, pSig, pulSigLen);
    pkcs11_trace("C_Sign", (uint32_t)hSess, 0,
                 (int)ulDataLen, 0, (int)rv,
                 pulSigLen ? (int)*pulSigLen : 0, 0);
    return rv;
}

static CK_RV traced_C_VerifyInit(CK_SESSION_HANDLE hSess,
                                 CK_MECHANISM_PTR pMech,
                                 CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = g_orig_fl->C_VerifyInit(hSess, pMech, hKey);
    pkcs11_trace("C_VerifyInit", (uint32_t)hSess,
                 pMech ? (uint32_t)pMech->mechanism : 0,
                 (int)hKey, 0, (int)rv, 0, 0);
    return rv;
}

static CK_RV traced_C_Verify(CK_SESSION_HANDLE hSess,
                             CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                             CK_BYTE_PTR pSig,  CK_ULONG ulSigLen)
{
    CK_RV rv = g_orig_fl->C_Verify(hSess, pData, ulDataLen, pSig, ulSigLen);
    pkcs11_trace("C_Verify", (uint32_t)hSess, 0,
                 (int)ulDataLen, (int)ulSigLen, (int)rv, 0, 0);
    return rv;
}

static CK_RV traced_C_DigestInit(CK_SESSION_HANDLE hSess,
                                 CK_MECHANISM_PTR pMech)
{
    CK_RV rv = g_orig_fl->C_DigestInit(hSess, pMech);
    pkcs11_trace("C_DigestInit", (uint32_t)hSess,
                 pMech ? (uint32_t)pMech->mechanism : 0,
                 0, 0, (int)rv, 0, 0);
    return rv;
}

static CK_RV traced_C_Digest(CK_SESSION_HANDLE hSess,
                             CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                             CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_RV rv = g_orig_fl->C_Digest(hSess, pData, ulDataLen, pDigest, pulDigestLen);
    pkcs11_trace("C_Digest", (uint32_t)hSess, 0,
                 (int)ulDataLen, 0, (int)rv,
                 pulDigestLen ? (int)*pulDigestLen : 0, 0);
    return rv;
}

static CK_RV traced_C_DeriveKey(CK_SESSION_HANDLE hSess,
                                CK_MECHANISM_PTR pMech,
                                CK_OBJECT_HANDLE hBaseKey,
                                CK_ATTRIBUTE_PTR pTmpl, CK_ULONG ulCount,
                                CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv = g_orig_fl->C_DeriveKey(hSess, pMech, hBaseKey,
                                      pTmpl, ulCount, phKey);
    pkcs11_trace("C_DeriveKey", (uint32_t)hSess,
                 pMech ? (uint32_t)pMech->mechanism : 0,
                 (int)hBaseKey, (int)ulCount, (int)rv,
                 phKey ? (int)*phKey : 0, 0);
    return rv;
}

static CK_RV traced_C_EncryptInit(CK_SESSION_HANDLE hSess,
                                  CK_MECHANISM_PTR pMech,
                                  CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = g_orig_fl->C_EncryptInit(hSess, pMech, hKey);
    pkcs11_trace("C_EncryptInit", (uint32_t)hSess,
                 pMech ? (uint32_t)pMech->mechanism : 0,
                 (int)hKey, 0, (int)rv, 0, 0);
    return rv;
}

static CK_RV traced_C_Encrypt(CK_SESSION_HANDLE hSess,
                              CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                              CK_BYTE_PTR pEnc,  CK_ULONG_PTR pulEncLen)
{
    CK_RV rv = g_orig_fl->C_Encrypt(hSess, pData, ulDataLen, pEnc, pulEncLen);
    pkcs11_trace("C_Encrypt", (uint32_t)hSess, 0,
                 (int)ulDataLen, 0, (int)rv,
                 pulEncLen ? (int)*pulEncLen : 0, 0);
    return rv;
}

static CK_RV traced_C_DecryptInit(CK_SESSION_HANDLE hSess,
                                  CK_MECHANISM_PTR pMech,
                                  CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = g_orig_fl->C_DecryptInit(hSess, pMech, hKey);
    pkcs11_trace("C_DecryptInit", (uint32_t)hSess,
                 pMech ? (uint32_t)pMech->mechanism : 0,
                 (int)hKey, 0, (int)rv, 0, 0);
    return rv;
}

static CK_RV traced_C_Decrypt(CK_SESSION_HANDLE hSess,
                              CK_BYTE_PTR pEnc,  CK_ULONG ulEncLen,
                              CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv = g_orig_fl->C_Decrypt(hSess, pEnc, ulEncLen, pData, pulDataLen);
    pkcs11_trace("C_Decrypt", (uint32_t)hSess, 0,
                 (int)ulEncLen, 0, (int)rv,
                 pulDataLen ? (int)*pulDataLen : 0, 0);
    return rv;
}

static CK_RV traced_C_GenerateRandom(CK_SESSION_HANDLE hSess,
                                     CK_BYTE_PTR pBuf, CK_ULONG ulLen)
{
    CK_RV rv = g_orig_fl->C_GenerateRandom(hSess, pBuf, ulLen);
    pkcs11_trace("C_GenerateRandom", (uint32_t)hSess, 0,
                 (int)ulLen, 0, (int)rv, 0, 0);
    return rv;
}

/*─────────────────────────────────────────────────────────────────────*/
/* pkcs11_wasm_wrap_function_list                                       */
/*                                                                      */
/* Builds a shadow function list with trace shims for the high-value   */
/* ops we want surfaced in the Diagnostic Boundary panel (open/close   */
/* session, login/logout, keypair gen, attribute reads, object finds). */
/* Other entries pass through unchanged from the underlying softhsmv3. */
/* Note: ML-KEM C_EncapsulateKey / C_DecapsulateKey are PKCS#11 v3.2   */
/* and aren't in this v2.40 CK_FUNCTION_LIST struct — strongSwan's    */
/* pkcs11_kem.c calls them directly via extern symbols, so those are   */
/* traced at the call site in pkcs11_kem.c, not here.                  */
/*─────────────────────────────────────────────────────────────────────*/

CK_FUNCTION_LIST_PTR pkcs11_wasm_wrap_function_list(CK_FUNCTION_LIST_PTR fl)
{
    if (!fl) return NULL;
    g_orig_fl = fl;
    memcpy(&g_traced_fl, fl, sizeof(g_traced_fl));
    g_traced_fl.C_GenerateKeyPair = traced_C_GenerateKeyPair;
    g_traced_fl.C_GenerateKey     = traced_C_GenerateKey;
    g_traced_fl.C_SignInit        = traced_C_SignInit;
    g_traced_fl.C_Sign            = traced_C_Sign;
    g_traced_fl.C_VerifyInit      = traced_C_VerifyInit;
    g_traced_fl.C_Verify          = traced_C_Verify;
    g_traced_fl.C_DigestInit      = traced_C_DigestInit;
    g_traced_fl.C_Digest          = traced_C_Digest;
    g_traced_fl.C_DeriveKey       = traced_C_DeriveKey;
    g_traced_fl.C_EncryptInit     = traced_C_EncryptInit;
    g_traced_fl.C_Encrypt         = traced_C_Encrypt;
    g_traced_fl.C_DecryptInit     = traced_C_DecryptInit;
    g_traced_fl.C_Decrypt         = traced_C_Decrypt;
    g_traced_fl.C_GenerateRandom  = traced_C_GenerateRandom;
    return &g_traced_fl;
}

/*─────────────────────────────────────────────────────────────────────*/
/* pkcs11_wasm_C_GetFunctionList                                        */
/*                                                                      */
/* Drop-in replacement for softhsmv3's C_GetFunctionList. Calls the     */
/* real one to get the raw function table, then runs it through         */
/* pkcs11_wasm_wrap_function_list so callers receive the traced shadow */
/* instead of the raw table. Exported and registered by the worker's   */
/* dlsym('C_GetFunctionList') stub so the strongswan-pkcs11 plugin     */
/* (which goes through dlopen + dlsym, not direct linking) gets the    */
/* traced list. Without this wrapper, only pkcs11_kem.c's direct       */
/* C_EncapsulateKey / C_DecapsulateKey traces appeared — every other    */
/* crypto op went through the unwrapped fl from pkcs11_library.c.      */
/*─────────────────────────────────────────────────────────────────────*/

extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);

CK_RV pkcs11_wasm_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFl)
{
    if (!ppFl) return CKR_ARGUMENTS_BAD;
    CK_FUNCTION_LIST_PTR raw = NULL;
    CK_RV rv = C_GetFunctionList(&raw);
    if (rv != CKR_OK || !raw) return rv;
    *ppFl = pkcs11_wasm_wrap_function_list(raw);
    return CKR_OK;
}

/*─────────────────────────────────────────────────────────────────────*/
/* pkcs11_wasm_rpc_function_list                                        */
/*                                                                      */
/* When rpcMode=true on the panel side. Currently identical to the     */
/* wrap path (no real cross-worker RPC — see CHANGELOG known issues);   */
/* using the same traced shadow list so tracing works in both modes.   */
/*─────────────────────────────────────────────────────────────────────*/

CK_FUNCTION_LIST_PTR pkcs11_wasm_rpc_function_list(CK_FUNCTION_LIST_PTR fl)
{
    return pkcs11_wasm_wrap_function_list(fl);
}

/* Public hook so pkcs11_kem.c can emit traces for the v3.2 KEM ops
 * (C_EncapsulateKey / C_DecapsulateKey) it calls via extern. */
void wasm_pkcs11_trace_kem(const char *op_name,
                           uint32_t sess, uint32_t mech,
                           int in_a, int in_b,
                           int rv,
                           int out_a, int out_b)
{
    pkcs11_trace(op_name, sess, mech, in_a, in_b, rv, out_a, out_b);
}

#endif /* __EMSCRIPTEN__ */
