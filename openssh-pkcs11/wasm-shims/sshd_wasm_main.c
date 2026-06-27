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

/* SM2: OpenSSH KEX driver headers. These pull <sys/queue.h>; resolved because this
 * shim is now compiled via the Makefile's .c.o rule (same CFLAGS as packet.o), not a
 * standalone emcc. ssh_api.c is the privsep-free single-process embedding of the KEX
 * state machine (mirrors regress/unittests/kex/test_kex.c). */
#include "ssh_api.h"
#include "sshkey.h"
#include "ssherr.h"
#include "kex.h"
#include "myproposal.h"
#include "ssh-pkcs11.h"   /* pkcs11_add_provider — SM3 host key from the token */
#include "packet.h"       /* sshpkt_* — SM4 userauth exchange */
#include "sshbuf.h"
#include "ssh2.h"         /* SSH2_MSG_USERAUTH_REQUEST / _SUCCESS */

/* WASM: the PKCS#11 provider is STATICALLY linked (no .so to nlist/mmap-scan), so
 * route OpenSSH's lib_contains_symbol() pre-check (misc.c) to an always-OK stub via
 * -Wl,--wrap,lib_contains_symbol. dlopen()/dlsym() are handled by pkcs11_static.c. */
int __wrap_lib_contains_symbol(const char *path, const char *s) { (void)path; (void)s; return 0; }

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

/* ── SM2: in-process mlkem768x25519 KEX to NEWKEYS ────────────────────────────
 * Mirrors regress/unittests/kex/test_kex.c (do_send_and_receive / run_kex): drive a
 * real OpenSSH client + server in ONE process via ssh_api.c, pumping framed output
 * from one side into the other's input until both reach NEWKEYS. SM2 uses an IN-MEMORY
 * ML-DSA-65 host key (sshkey_generate); SM3 swaps the server's sign to PKCS#11 C_Sign. */
static int sm2_pump(struct ssh *from, struct ssh *to) {
    u_char type;
    for (;;) {
        int r = ssh_packet_next(from, &type);              /* ssh_api.c:255 */
        if (r != 0) { emit_rv("ssh_packet_next", (CK_RV)r); return -1; }
        if (type != 0) return 0;                            /* delivered a msg; let caller swap sides */
        size_t len; const u_char *buf = ssh_output_ptr(from, &len);   /* ssh_api.c:313 */
        if (len == 0) return 0;
        if ((r = ssh_output_consume(from, len)) != 0 ||
            (r = ssh_input_append(to, buf, len)) != 0) { emit_rv("pump io", (CK_RV)r); return -1; }
    }
}

/* Move all queued output bytes from one side's transport into the other's input. */
static void deliver_all(struct ssh *from, struct ssh *to) {
    size_t len;
    const u_char *buf;
    while ((buf = ssh_output_ptr(from, &len)) != NULL && len > 0) {
        ssh_input_append(to, buf, len);
        ssh_output_consume(from, len);
    }
}

/* SM4 (Option b): real publickey userauth to USERAUTH_SUCCESS.
 * REAL OpenSSH: the RFC 4252 signed-data format, the signature (sshkey_sign ->
 * pkcs11_sign_mldsa -> C_Sign; user key never leaves the token), and the verify
 * (sshkey_verify). DRIVEN here (not auth2.c's loop, which needs PAM/privsep/accounts
 * that don't exist in a browser): the request/success message orchestration and a
 * minimal "is this the authorized key" accept policy. SERVICE_REQUEST is skipped
 * (no crypto value); the same token key is used for the user role as the host role. */
static int do_userauth(struct ssh *client, struct ssh *server, struct sshkey *authkey) {
    struct sshbuf *b = NULL;
    u_char *sig = NULL, *pkblob = NULL, *rsig = NULL, have_sig = 0, type = 0;
    size_t slen = 0, pklen = 0, rsiglen = 0, skip = 0;
    char *user = NULL, *service = NULL, *method = NULL, *alg = NULL;
    struct sshkey *recv_key = NULL;
    int r, g, ret = -1;
    const char *U = "pqcuser", *SVC = "ssh-connection", *M = "publickey", *A = "ssh-mldsa-65";

    if ((b = sshbuf_new()) == NULL) { wasm_emit_event("error", "userauth sshbuf_new"); return -1; }

    /* client: assemble the signed data exactly as sshconnect2.c does, sign via C_Sign. */
    if ((r = sshbuf_put_stringb(b, client->kex->session_id)) != 0) { emit_rv("ua put session_id", (CK_RV)r); goto out; }
    skip = sshbuf_len(b);
    if ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
        (r = sshbuf_put_cstring(b, U)) != 0 ||
        (r = sshbuf_put_cstring(b, SVC)) != 0 ||
        (r = sshbuf_put_cstring(b, M)) != 0 ||
        (r = sshbuf_put_u8(b, 1)) != 0 ||
        (r = sshbuf_put_cstring(b, A)) != 0 ||
        (r = sshkey_puts(authkey, b)) != 0) { emit_rv("ua assemble", (CK_RV)r); goto out; }
    if ((r = sshkey_sign(authkey, &sig, &slen, sshbuf_ptr(b), sshbuf_len(b),
        A, NULL, NULL, client->compat)) != 0) { emit_rv("ua sshkey_sign", (CK_RV)r); goto out; }
    { char e[64]; snprintf(e, sizeof e, "{\"user_sig_len\":%zu}", slen); wasm_emit_event("user_key_sign", e); }
    if ((r = sshbuf_put_string(b, sig, slen)) != 0) { emit_rv("ua append sig", (CK_RV)r); goto out; }
    if ((r = sshbuf_consume(b, skip + 1)) != 0) { emit_rv("ua consume", (CK_RV)r); goto out; }
    if ((r = sshpkt_start(client, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
        (r = sshpkt_putb(client, b)) != 0 ||
        (r = sshpkt_send(client)) != 0) { emit_rv("ua send request", (CK_RV)r); goto out; }
    deliver_all(client, server);

    /* server: receive USERAUTH_REQUEST, verify the signature with real sshkey_verify. */
    for (g = 0; g < 8; g++) { if ((r = ssh_packet_next(server, &type)) != 0) { emit_rv("ua srv next", (CK_RV)r); goto out; } if (type != 0) break; }
    if (type != SSH2_MSG_USERAUTH_REQUEST) { char e[48]; snprintf(e, sizeof e, "{\"got_type\":%d}", type); wasm_emit_event("error", e); goto out; }
    if ((r = sshpkt_get_cstring(server, &user, NULL)) != 0 ||
        (r = sshpkt_get_cstring(server, &service, NULL)) != 0 ||
        (r = sshpkt_get_cstring(server, &method, NULL)) != 0 ||
        (r = sshpkt_get_u8(server, &have_sig)) != 0 ||
        (r = sshpkt_get_cstring(server, &alg, NULL)) != 0 ||
        (r = sshpkt_get_string(server, &pkblob, &pklen)) != 0 ||
        (r = sshpkt_get_string(server, &rsig, &rsiglen)) != 0) { emit_rv("ua parse", (CK_RV)r); goto out; }
    if ((r = sshkey_from_blob(pkblob, pklen, &recv_key)) != 0) { emit_rv("ua from_blob", (CK_RV)r); goto out; }
    sshbuf_reset(b);
    if ((r = sshbuf_put_stringb(b, server->kex->session_id)) != 0 ||
        (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
        (r = sshbuf_put_cstring(b, user)) != 0 ||
        (r = sshbuf_put_cstring(b, service)) != 0 ||
        (r = sshbuf_put_cstring(b, method)) != 0 ||
        (r = sshbuf_put_u8(b, 1)) != 0 ||
        (r = sshbuf_put_cstring(b, alg)) != 0 ||
        (r = sshkey_puts(recv_key, b)) != 0) { emit_rv("ua rebuild", (CK_RV)r); goto out; }
    if ((r = sshkey_verify(recv_key, rsig, rsiglen, sshbuf_ptr(b), sshbuf_len(b),
        alg, server->compat, NULL)) != 0) { emit_rv("ua sshkey_verify", (CK_RV)r); goto out; }
    if (!sshkey_equal_public(recv_key, authkey)) { wasm_emit_event("error", "ua key not authorized"); goto out; }
    wasm_emit_event("userauth_verified", "{\"method\":\"publickey\",\"alg\":\"ssh-mldsa-65\",\"verify\":\"sshkey_verify\"}");
    if ((r = sshpkt_start(server, SSH2_MSG_USERAUTH_SUCCESS)) != 0 ||
        (r = sshpkt_send(server)) != 0) { emit_rv("ua send success", (CK_RV)r); goto out; }
    deliver_all(server, client);

    /* client: receive USERAUTH_SUCCESS. */
    type = 0;
    for (g = 0; g < 8; g++) { if ((r = ssh_packet_next(client, &type)) != 0) { emit_rv("ua cli next", (CK_RV)r); goto out; } if (type != 0) break; }
    if (type != SSH2_MSG_USERAUTH_SUCCESS) { char e[48]; snprintf(e, sizeof e, "{\"got_type\":%d}", type); wasm_emit_event("error", e); goto out; }
    wasm_emit_event("userauth_success", "{\"user\":\"pqcuser\",\"method\":\"publickey\",\"usersign\":\"C_Sign\"}");
    ret = 0;
out:
    sshbuf_free(b); free(sig); free(pkblob); free(rsig);
    free(user); free(service); free(method); free(alg);
    sshkey_free(recv_key);
    return ret;
}

static int drive_kex(void) {
    struct ssh *client = NULL, *server = NULL;
    struct sshkey **keys = NULL, *hostkey = NULL, *pub = NULL;
    char **labels = NULL;
    struct kex_params kp;
    char *base[PROPOSAL_MAX] = { KEX_CLIENT };
    int nkeys, i, r;

    /* SM3 (the crux): fetch the TOKEN's ML-DSA-65 host key as a PKCS#11-backed (EXT)
     * sshkey via OpenSSH's REAL provider path (pkcs11_add_provider -> dlopen-static
     * shim -> softhsm). The server's KEX host-key signature then runs through OpenSSH's
     * own sshkey_sign -> pkcs11_sign -> pkcs11_sign_mldsa -> C_Sign: the private key
     * never leaves the token. Provider id "softhsm" matches the dlopen-static shim. */
    /* MUST run before pkcs11_add_provider: it TAILQ_INIT()s pkcs11_providers/pkcs11_keys.
     * Without it the registry head is zeroed; the record-key INSERT writes through a NULL
     * tqh_last — which segfaults on native but silently corrupts in WASM (address 0 is
     * writable), leaving the list empty so pkcs11_lookup_key fails at sign time. */
    pkcs11_init(0);
    nkeys = pkcs11_add_provider("softhsm", SM1_USER_PIN, &keys, &labels);
    if (nkeys <= 0) { emit_rv("pkcs11_add_provider", (CK_RV)(long)nkeys); return -1; }
    { char b[48]; snprintf(b, sizeof b, "{\"nkeys\":%d}", nkeys); wasm_emit_event("provider", b); }
    for (i = 0; i < nkeys; i++) {
        if (keys[i] != NULL && keys[i]->type == KEY_MLDSA_65) { hostkey = keys[i]; break; }
    }
    if (hostkey == NULL) { wasm_emit_event("error", "no ML-DSA-65 key returned by token"); return -1; }
    if ((r = sshkey_from_private(hostkey, &pub)) != 0) { emit_rv("sshkey_from_private", (CK_RV)r); return -1; }

    memset(&kp, 0, sizeof kp);
    memcpy(kp.proposal, base, sizeof base);
    kp.proposal[PROPOSAL_KEX_ALGS] = "mlkem768x25519-sha256";
    kp.proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = "ssh-mldsa-65";

    if ((r = ssh_init(&client, 0, &kp)) != 0) { emit_rv("ssh_init(client)", (CK_RV)r); return -1; }
    if ((r = ssh_init(&server, 1, &kp)) != 0) { emit_rv("ssh_init(server)", (CK_RV)r); return -1; }
    if ((r = ssh_add_hostkey(server, hostkey)) != 0) { emit_rv("ssh_add_hostkey(server)", (CK_RV)r); return -1; }
    if ((r = ssh_add_hostkey(client, pub)) != 0)     { emit_rv("ssh_add_hostkey(client)", (CK_RV)r); return -1; }

    wasm_emit_event("kex_start",
        "{\"kex\":\"mlkem768x25519-sha256\",\"hostkey\":\"ssh-mldsa-65\",\"sign\":\"C_Sign\"}");
    int guard = 0;
    while ((!server->kex->done || !client->kex->done) && guard++ < 64) {
        if (sm2_pump(server, client) != 0) return -1;
        if (sm2_pump(client, server) != 0) return -1;
    }
    if (server->kex->done && client->kex->done) {
        /* Server reached NEWKEYS: its exchange-hash signature was produced by the token's
         * C_Sign and verified by the client under the host public key. */
        wasm_emit_event("newkeys", "{\"server\":1,\"client\":1,\"hostsign\":\"C_Sign\"}");
        /* SM4: continue into real publickey userauth. Same token key serves the user role
         * (its signature also via C_Sign), proving BOTH host- and user-auth are HSM-backed. */
        return do_userauth(client, server, hostkey);
    }
    wasm_emit_event("error", "kex did not converge");
    return -1;
}

/* ── Privsep-free WASM entry: wraps main() (sshd.c:1287; no `sshd_main` symbol). ──
 * SM1: bring up softhsm in-instance, provision an ML-DSA-65 host key, prove ONE C_Sign.
 * SM2: drive a real in-process mlkem768x25519 handshake to NEWKEYS (in-memory host key).
 * The native main() is reachable as __real_main() but never called (it fork/execv's). */
int __wrap_main(int argc, char **argv) {
    (void)argc; (void)argv;

    wasm_emit_event("start", "sshd WASM starting");
    if (pkcs11_bootstrap() != 0)     return 1;   /* SM1: init token + SO/USER login */
    if (sm1_provision() != 0)        return 1;   /* SM1: ML-DSA-65 host key on the token */
    if (pkcs11_find_host_key() != 0) return 1;
    if (sm1_prove_sign() != 0)       return 1;   /* SM1: prove one direct C_Sign */
    /* Finalize our bootstrap session: OpenSSH's pkcs11_add_provider runs its own
     * C_Initialize and treats CKR_CRYPTOKI_ALREADY_INITIALIZED as fatal. The file-backed
     * token (objectstore.backend=file) persists the provisioned host key across finalize. */
    if (g_p11) g_p11->C_Finalize(NULL_PTR);
    if (drive_kex() != 0)            return 1;   /* SM3 KEX host-sign + SM4 userauth via C_Sign */
    wasm_emit_event("done", "{\"connection_ok\":true,\"note\":\"SM4 ok\"}");
    return 0;
}

#endif /* WASM_SSHD_MAIN */
#endif /* WASM_OPENSSH */
