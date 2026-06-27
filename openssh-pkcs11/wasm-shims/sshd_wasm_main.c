/*
 * sshd_wasm_main.c — Privsep-free sshd entry point for WASM build.
 *
 * OpenSSH's real sshd_main() calls fork(), useradd, PAM, PTY allocation,
 * and setuid — none of which exist in WASM.  This replacement:
 *
 *   1. Initialises softhsmv3 PKCS#11 via the static C_GetFunctionList path.
 *   2. Loads the host key object handle from token (CKA_ID = "sshd-host-key").
 *   3. Runs a single SSH transport handshake over the SAB socket shim:
 *        SSH_MSG_KEXINIT  →  ML-KEM-768 + X25519 hybrid KEX  →  SSH_MSG_NEWKEYS
 *        →  SSH_MSG_USERAUTH_REQUEST (publickey, ssh-mldsa-65)
 *        →  SSH_MSG_USERAUTH_SUCCESS
 *   4. Posts "WASM demo: authentication successful — shell unavailable" to the
 *      client, then sends SSH_MSG_DISCONNECT.
 *   5. Exits; the JS worker receives the "done" message and updates the UI.
 *
 * Guarded by -DWASM_SSHD_MAIN; the native sshd build is unaffected.
 *
 * NOTE: This file replaces the linker-level sshd_main() symbol via:
 *   -Wl,--wrap,sshd_main (Emscripten LDFLAGS in build-wasm.sh)
 * The original sshd_main is still compiled but never called.
 */

#ifdef WASM_OPENSSH
#ifdef WASM_SSHD_MAIN

#include "includes.h"
#include <emscripten.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>

/* softhsmv3 PKCS#11 — statically linked */
#include "pkcs11.h"
extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);

/* NOTE: OpenSSH internal headers (ssh2.h/packet.h/kex.h/sshkey.h/ssh_api.h/...) are
 * NOT included for SM1 — it is pure PKCS#11. They pull <sys/queue.h> which is absent
 * from the emscripten sysroot in a standalone shim compile. SM2 (the KEX driver) will
 * re-add the specific headers it needs (ssh_api.h, kex.h, sshkey.h) with the right
 * openbsd-compat include path. */

/* NOTE: getpwnam/getpwuid stubs removed — emscripten musl already provides them
 * (they collided: wasm-ld "duplicate symbol"). SM1 never calls them; if SM2's auth
 * path needs a fake pw entry, reintroduce via -Wl,--wrap,getpwnam, not a strong def. */

/* ── JS callback: emit handshake event to UI ─────────────────────────────── */
EM_JS(void, wasm_emit_event, (const char *type, const char *payload), {
    if (typeof Module.onHandshakeEvent === 'function') {
        Module.onHandshakeEvent(UTF8ToString(type), UTF8ToString(payload));
    }
});

/* ── softhsmv3 PKCS#11 (statically linked) ───────────────────────────────── */
static CK_FUNCTION_LIST *g_p11      = NULL;
static CK_SESSION_HANDLE  g_session = CK_INVALID_HANDLE;
static CK_SLOT_ID         g_slot    = 0;
static CK_OBJECT_HANDLE   g_host_key = CK_INVALID_HANDLE;

/* ML-DSA constants — confirmed against src/lib/pkcs11 headers; guards are belt-and-suspenders. */
#ifndef CKM_ML_DSA_KEY_PAIR_GEN
#define CKM_ML_DSA_KEY_PAIR_GEN 0x0000001cUL
#endif
#ifndef CKM_ML_DSA
#define CKM_ML_DSA 0x0000001dUL
#endif
#ifndef CKK_ML_DSA
#define CKK_ML_DSA 0x0000004aUL
#endif
#ifndef CKA_PARAMETER_SET
#define CKA_PARAMETER_SET 0x0000061dUL
#endif
#ifndef CKP_ML_DSA_65
#define CKP_ML_DSA_65 0x00000002UL
#endif
#ifndef CKF_TOKEN_INITIALIZED
#define CKF_TOKEN_INITIALIZED 0x00000400UL
#endif
#ifndef CKU_SO
#define CKU_SO 0UL
#endif

#define SM1_SO_PIN   "12345678"
#define SM1_USER_PIN "1234"

static void emit_rv(const char *ctx, CK_RV rv) {
    char buf[96];
    snprintf(buf, sizeof buf, "%s rv=0x%lx", ctx, (unsigned long)rv);
    wasm_emit_event("error", buf);
}

/* Bring up softhsm in this WASM instance: init lib + token, set PINs, USER login. */
static int pkcs11_bootstrap(void) {
    CK_RV rv;
    CK_FUNCTION_LIST *p11 = NULL;
    rv = C_GetFunctionList(&p11);
    if (rv != CKR_OK) { emit_rv("C_GetFunctionList", rv); return -1; }
    g_p11 = p11;

    rv = p11->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) { emit_rv("C_Initialize", rv); return -1; }

    CK_SLOT_ID slots[16]; CK_ULONG nslots = 16;
    rv = p11->C_GetSlotList(CK_FALSE, slots, &nslots);
    if (rv != CKR_OK || nslots == 0) { emit_rv("C_GetSlotList", rv); return -1; }
    { char b[48]; snprintf(b, sizeof b, "{\"slots\":%lu}", (unsigned long)nslots); wasm_emit_event("slots", b); }

    CK_UTF8CHAR label[32];
    memset(label, ' ', sizeof label);
    memcpy(label, "pqc-sshd", 8);
    rv = p11->C_InitToken(slots[0], (CK_UTF8CHAR_PTR)SM1_SO_PIN, strlen(SM1_SO_PIN), label);
    if (rv != CKR_OK) { emit_rv("C_InitToken", rv); return -1; }

    /* Re-enumerate; pick the first INITIALIZED token slot (softhsm-wasm may renumber). */
    nslots = 16;
    rv = p11->C_GetSlotList(CK_FALSE, slots, &nslots);
    if (rv != CKR_OK) { emit_rv("C_GetSlotList(2)", rv); return -1; }
    int found = 0;
    for (CK_ULONG i = 0; i < nslots; i++) {
        CK_TOKEN_INFO ti;
        if (p11->C_GetTokenInfo(slots[i], &ti) == CKR_OK && (ti.flags & CKF_TOKEN_INITIALIZED)) {
            g_slot = slots[i]; found = 1; break;
        }
    }
    if (!found) { wasm_emit_event("error", "no initialized slot after C_InitToken"); return -1; }
    { char b[48]; snprintf(b, sizeof b, "{\"slot\":%lu}", (unsigned long)g_slot); wasm_emit_event("slot", b); }

    rv = p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &g_session);
    if (rv != CKR_OK) { emit_rv("C_OpenSession", rv); return -1; }
    rv = p11->C_Login(g_session, CKU_SO, (CK_UTF8CHAR_PTR)SM1_SO_PIN, strlen(SM1_SO_PIN));
    if (rv != CKR_OK) { emit_rv("C_Login(SO)", rv); return -1; }
    rv = p11->C_InitPIN(g_session, (CK_UTF8CHAR_PTR)SM1_USER_PIN, strlen(SM1_USER_PIN));
    if (rv != CKR_OK) { emit_rv("C_InitPIN", rv); return -1; }
    rv = p11->C_Logout(g_session);
    if (rv != CKR_OK) { emit_rv("C_Logout", rv); return -1; }
    rv = p11->C_Login(g_session, CKU_USER, (CK_UTF8CHAR_PTR)SM1_USER_PIN, strlen(SM1_USER_PIN));
    if (rv != CKR_OK) { emit_rv("C_Login(USER)", rv); return -1; }

    wasm_emit_event("token_ready", "token initialized + USER logged in");
    return 0;
}

/* Provision an ML-DSA-65 host key (CKA_ID="sshd-host-key") into the open token. */
static int sm1_provision(void) {
    CK_OBJECT_CLASS pub_cls  = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS priv_cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE     kt        = CKK_ML_DSA;
    CK_ULONG        pset      = CKP_ML_DSA_65;
    CK_BBOOL        yes       = CK_TRUE;
    CK_BBOOL        no        = CK_FALSE;
    static const CK_BYTE host_id[] = { 's','s','h','d','-','h','o','s','t','-','k','e','y' };

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_CLASS,         &pub_cls, sizeof pub_cls },
        { CKA_KEY_TYPE,      &kt,      sizeof kt      },
        { CKA_TOKEN,         &yes,     sizeof yes     },
        { CKA_VERIFY,        &yes,     sizeof yes     },
        { CKA_PARAMETER_SET, &pset,    sizeof pset    },
        { CKA_ID,            (void*)host_id, sizeof host_id },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_CLASS,       &priv_cls, sizeof priv_cls },
        { CKA_KEY_TYPE,    &kt,       sizeof kt       },
        { CKA_TOKEN,       &yes,      sizeof yes      },
        { CKA_PRIVATE,     &yes,      sizeof yes      },
        { CKA_SIGN,        &yes,      sizeof yes      },
        { CKA_EXTRACTABLE, &no,       sizeof no       },
        { CKA_ID,          (void*)host_id, sizeof host_id },
    };
    CK_MECHANISM gen = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
    CK_RV rv = g_p11->C_GenerateKeyPair(g_session, &gen,
        pub_tmpl,  sizeof pub_tmpl  / sizeof pub_tmpl[0],
        priv_tmpl, sizeof priv_tmpl / sizeof priv_tmpl[0],
        &hPub, &hPriv);
    if (rv != CKR_OK) { emit_rv("C_GenerateKeyPair", rv); return -1; }
    wasm_emit_event("provisioned", "{\"key\":\"sshd-host-key\"}");
    return 0;
}

/* Find the private host key by CKA_ID -> g_host_key. */
static int pkcs11_find_host_key(void) {
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    static const CK_BYTE host_id[] = { 's','s','h','d','-','h','o','s','t','-','k','e','y' };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof cls },
        { CKA_ID,    (void*)host_id, sizeof host_id },
    };
    CK_ULONG count = 0;
    g_p11->C_FindObjectsInit(g_session, tmpl, 2);
    g_p11->C_FindObjects(g_session, &g_host_key, 1, &count);
    g_p11->C_FindObjectsFinal(g_session);
    if (count == 0) { wasm_emit_event("error", "host key not found on token"); return -1; }
    wasm_emit_event("pkcs11_ready", "host key found on token");
    return 0;
}

/* SM1 proof: one single-part ML-DSA C_Sign with the token host key. */
static int sm1_prove_sign(void) {
    CK_MECHANISM mech = { CKM_ML_DSA, NULL_PTR, 0 };
    CK_BYTE data[32]; memset(data, 0xA5, sizeof data);
    CK_RV rv = g_p11->C_SignInit(g_session, &mech, g_host_key);
    if (rv != CKR_OK) { emit_rv("C_SignInit", rv); return -1; }
    CK_ULONG slen = 0;
    rv = g_p11->C_Sign(g_session, data, sizeof data, NULL_PTR, &slen);
    if (rv != CKR_OK) { emit_rv("C_Sign(size)", rv); return -1; }
    CK_BYTE *sig = (CK_BYTE *)malloc(slen ? slen : 1);
    rv = g_p11->C_Sign(g_session, data, sizeof data, sig, &slen);
    if (rv != CKR_OK) { free(sig); emit_rv("C_Sign", rv); return -1; }
    char buf[64]; snprintf(buf, sizeof buf, "{\"sig_len\":%lu}", (unsigned long)slen);
    wasm_emit_event("host_key_sign", buf);
    free(sig);
    return 0;
}

/* ── Privsep-free WASM entry: wraps main() (sshd.c:1287; no `sshd_main` symbol). ──
 * SM1 scope: bring up softhsm in-instance, provision an ML-DSA-65 host key, find it,
 * and prove ONE host-key C_Sign. No KEX/transport yet (that's SM2+). The native main()
 * is reachable as __real_main() but is never called (it fork/execv's into sshd-session). */
int __wrap_main(int argc, char **argv) {
    (void)argc; (void)argv;

    wasm_emit_event("start", "sshd WASM starting");
    if (pkcs11_bootstrap() != 0)     return 1;
    if (sm1_provision() != 0)        return 1;
    if (pkcs11_find_host_key() != 0) return 1;
    if (sm1_prove_sign() != 0)       return 1;
    wasm_emit_event("done", "{\"connection_ok\":false,\"note\":\"SM1 ok\"}");
    return 0;
}

#endif /* WASM_SSHD_MAIN */
#endif /* WASM_OPENSSH */
