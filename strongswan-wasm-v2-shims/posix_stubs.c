/*
 * posix_stubs.c — Stubs for POSIX functions absent from Emscripten sysroot.
 *
 * strongSwan links code paths that are never reached in the WASM build
 * (kernel-netlink plugin, fork-based privsep, DNS-based SRV lookups, etc.).
 * Emscripten's sysroot doesn't provide every POSIX function these reference,
 * and a missing symbol at link time fails the whole build.  These no-op
 * stubs satisfy the linker for symbols whose runtime callsites we don't
 * exercise in WASM.
 *
 * If any of these stubs is actually called at runtime, it returns a benign
 * error — safer than silent corruption.  Extend as new linker gaps surface.
 */

#ifdef __EMSCRIPTEN__
#include <stddef.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <grp.h>

/* initgroups — privsep path in charon (not reached in WASM) */
int initgroups(const char *user, gid_t group) {
    (void)user; (void)group;
    return 0;
}

/* setgroups — privsep */
int setgroups(size_t size, const gid_t *list) {
    (void)size; (void)list;
    return 0;
}

/* res_init / res_query / res_search — DNS SRV lookup for charon peer
 * discovery.  Not used by our WASM config (peer IPs are explicit). */
int res_init(void) { return 0; }

int res_query(const char *dname, int class, int type,
              unsigned char *answer, int anslen) {
    (void)dname; (void)class; (void)type; (void)answer; (void)anslen;
    errno = ENONET;
    return -1;
}

int res_search(const char *dname, int class, int type,
               unsigned char *answer, int anslen) {
    return res_query(dname, class, type, answer, anslen);
}

/* pthread_kill provided by emscripten 5.0.7 libc — stub removed to avoid
 * duplicate symbol at link time. */

/* Reserved: add charon-specific stubs as we discover linker gaps in Phase 1.
 *
 * Prior revisions defined _wasm_free_array_entry here as a 3-arg wrapper for
 * array_callback_t calls that cast 1-arg `free` via (void*). That shim is no
 * longer needed now that the build uses -sEMULATE_FUNCTION_POINTER_CASTS=1,
 * which auto-generates adapter thunks for every mismatched indirect call. */

#endif /* __EMSCRIPTEN__ */
