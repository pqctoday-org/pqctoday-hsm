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
#include "pkcs11.h"   /* CK_RV, CK_FUNCTION_LIST_PTR_PTR (softhsm headers, on the build -I path) */

/* Forward-declare softhsmv3's function-list entry point. */
extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/* There is no .so to load in WASM (softhsm is statically linked), and softhsm has
 * no involvement in the dynamic-linker "handle" that dlopen() normally returns.
 * Rather than fabricate a magic constant, hand back the REAL, statically-linked
 * C_GetFunctionList address as the handle: it is a genuine non-NULL pointer that
 * ssh-pkcs11.c only ever passes opaquely back to dlsym(). dlsym() then returns that
 * same real entry point — so the caller gets softhsm's actual C_GetFunctionList. */
void *dlopen(const char *filename, int flags) {
    (void)flags;
    /* Accept any name that looks like softhsmv3 */
    if (filename &&
        (strstr(filename, "softhsm") || strstr(filename, "libpkcs11"))) {
        return (void *)C_GetFunctionList;
    }
    /* For anything else (e.g. OpenSSL providers loaded by pkcs11-provider)
     * return NULL — they are not needed in the WASM build. */
    return NULL;
}

void *dlsym(void *handle, const char *symbol) {
    if (handle == (void *)C_GetFunctionList &&
        symbol && strcmp(symbol, "C_GetFunctionList") == 0) {
        return (void *)C_GetFunctionList;
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
