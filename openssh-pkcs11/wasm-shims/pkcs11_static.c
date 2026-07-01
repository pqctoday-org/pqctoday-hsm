/*
 * pkcs11_static.c — Static softhsmv3 linker shim for OpenSSH WASM build.
 *
 * OpenSSH's ssh-pkcs11.c calls dlopen("libsofthsmv3.so") at runtime.
 * In the WASM build there is no dynamic linker; softhsmv3 is statically
 * linked into the same binary.  This file intercepts the dlopen/dlsym/dlclose
 * calls made by ssh-pkcs11.c and routes them directly to the linked-in
 * C_GetFunctionList symbol.
 *
 * Pattern mirrors strongSwan's pkcs11_library.c SOFTHSM_STATIC_LINKED path.
 * Guard: only compiled when -DSOFTHSM_STATIC_LINKED and __EMSCRIPTEN__.
 */

#if defined(__EMSCRIPTEN__) && defined(SOFTHSM_STATIC_LINKED)

#include "includes.h"
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include "pkcs11.h"   /* CK_RV, CK_FUNCTION_LIST_PTR_PTR (softhsm headers, on the build -I path) */

/* Forward-declare softhsmv3's function-list entry point. */
extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/* ── PKCS#11 trace tap ────────────────────────────────────────────────────────
 * OpenSSH's provider gets its CK_FUNCTION_LIST through dlsym("C_GetFunctionList")
 * below. We hand back a WRAPPED list: a copy of softhsm's real list with the
 * provider-path entries (login, object lookup, signing) replaced by thin wrappers
 * that emit a "pkcs11" UI event, then delegate to the real function. This makes
 * the playground's PKCS#11 panel show the genuine calls — including the C_Sign
 * that proves the private key never leaves the token — without touching the
 * generated OpenSSH source. wasm_emit_event is the same EM_JS hook the handshake
 * driver uses (defined in sshd_wasm_main.c, linked into this binary). */
extern void wasm_emit_event(const char *type, const char *payload);

static CK_FUNCTION_LIST *p11_real = NULL;   /* softhsm's real list */
static CK_FUNCTION_LIST  p11_wrapped;       /* copy with tapped entries */

static void trace_emit(const char *json) { wasm_emit_event("pkcs11", json); }

static CK_RV tap_C_Login(CK_SESSION_HANDLE s, CK_USER_TYPE ut, CK_UTF8CHAR_PTR pin, CK_ULONG plen) {
    char j[96];
    snprintf(j, sizeof j, "{\"op\":\"C_Login\",\"userType\":%lu}", (unsigned long)ut);
    trace_emit(j);
    return p11_real->C_Login(s, ut, pin, plen);
}
static CK_RV tap_C_FindObjectsInit(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    char j[96];
    snprintf(j, sizeof j, "{\"op\":\"C_FindObjectsInit\",\"attrs\":%lu}", (unsigned long)n);
    trace_emit(j);
    return p11_real->C_FindObjectsInit(s, t, n);
}
static CK_RV tap_C_FindObjects(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR o, CK_ULONG max, CK_ULONG_PTR n) {
    CK_RV rv = p11_real->C_FindObjects(s, o, max, n);
    char j[96];
    snprintf(j, sizeof j, "{\"op\":\"C_FindObjects\",\"found\":%lu,\"rv\":%lu}",
             (unsigned long)(n ? *n : 0), (unsigned long)rv);
    trace_emit(j);
    return rv;
}
static CK_RV tap_C_GetAttributeValue(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    CK_RV rv = p11_real->C_GetAttributeValue(s, o, t, n);
    char j[112];
    snprintf(j, sizeof j, "{\"op\":\"C_GetAttributeValue\",\"attrs\":%lu,\"rv\":%lu}",
             (unsigned long)n, (unsigned long)rv);
    trace_emit(j);
    return rv;
}
static CK_RV tap_C_SignInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k) {
    char j[112];
    snprintf(j, sizeof j, "{\"op\":\"C_SignInit\",\"mech\":%lu,\"key\":%lu}",
             (unsigned long)(m ? m->mechanism : 0), (unsigned long)k);
    trace_emit(j);
    return p11_real->C_SignInit(s, m, k);
}
static CK_RV tap_C_Sign(CK_SESSION_HANDLE s, CK_BYTE_PTR d, CK_ULONG dlen, CK_BYTE_PTR sig, CK_ULONG_PTR slen) {
    CK_RV rv = p11_real->C_Sign(s, d, dlen, sig, slen);
    char j[144];
    /* pSignature == NULL is the length-query call; otherwise the real signing. */
    snprintf(j, sizeof j, "{\"op\":\"C_Sign\",\"dataLen\":%lu,\"sigLen\":%lu,\"query\":%d,\"rv\":%lu}",
             (unsigned long)dlen, (unsigned long)(slen ? *slen : 0), sig ? 0 : 1, (unsigned long)rv);
    trace_emit(j);
    return rv;
}

/* Build (once) and return the wrapped function list. */
static CK_RV wrapped_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pp) {
    if (p11_real == NULL) {
        CK_RV rv = C_GetFunctionList(&p11_real);
        if (rv != CKR_OK) return rv;
        p11_wrapped = *p11_real;                 /* copy all real entries */
        p11_wrapped.C_Login            = tap_C_Login;
        p11_wrapped.C_FindObjectsInit  = tap_C_FindObjectsInit;
        p11_wrapped.C_FindObjects      = tap_C_FindObjects;
        p11_wrapped.C_GetAttributeValue= tap_C_GetAttributeValue;
        p11_wrapped.C_SignInit         = tap_C_SignInit;
        p11_wrapped.C_Sign             = tap_C_Sign;
    }
    if (pp) *pp = &p11_wrapped;
    return CKR_OK;
}

/* There is no .so to load in WASM (softhsm is statically linked), and softhsm has
 * no involvement in the dynamic-linker "handle" that dlopen() normally returns.
 * Rather than fabricate a magic constant, hand back the REAL, statically-linked
 * C_GetFunctionList address as the handle: it is a genuine non-NULL pointer that
 * ssh-pkcs11.c only ever passes opaquely back to dlsym(). dlsym() then returns that
 * same real entry point — so the caller gets softhsm's actual C_GetFunctionList. */
void *dlopen(const char *filename, int flags) {
    (void)flags;
    /* Accept any name that looks like softhsmv3. Hand back the WRAPPED entry
     * point as the opaque handle so the provider's calls flow through the trace
     * tap (and on to softhsm's real functions). */
    if (filename &&
        (strstr(filename, "softhsm") || strstr(filename, "libpkcs11"))) {
        return (void *)wrapped_GetFunctionList;
    }
    /* For anything else (e.g. OpenSSL providers loaded by pkcs11-provider)
     * return NULL — they are not needed in the WASM build. */
    return NULL;
}

void *dlsym(void *handle, const char *symbol) {
    if (handle == (void *)wrapped_GetFunctionList &&
        symbol && strcmp(symbol, "C_GetFunctionList") == 0) {
        return (void *)wrapped_GetFunctionList;
    }
    return NULL;
}

int dlclose(void *handle) {
    (void)handle;
    return 0;
}

/* NOTE: dlerror() is intentionally NOT defined here — emscripten's libc already
 * provides it (and pulls it in unconditionally), so defining our own causes a
 * wasm-ld "duplicate symbol: dlerror". ssh-pkcs11.c only calls dlerror() on the
 * dlopen/dlsym failure paths, which our shim never takes for the softhsm provider. */

#endif /* __EMSCRIPTEN__ && SOFTHSM_STATIC_LINKED */
