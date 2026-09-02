/*
 * test_pkcs11_kem.c — real functional test of the strongswan-pkcs11
 * connector's ML-KEM-768 key EXCHANGE path (pkcs11_kem.c), the one PQC
 * mechanism this connector implements that test_pkcs11_conn.c does not
 * cover. strongSwan models key exchange through a different interface
 * than signing/verification — key_exchange_t (crypto/key_exchange.h),
 * not private_key_t/public_key_t — created via
 * lib->crypto->create_ke(lib->crypto, ML_KEM_768), which resolves to
 * this connector's pkcs11_kem_create() because that's the only KE(...)
 * provider registered when only the "pkcs11" plugin is loaded (see
 * PLUGIN_REGISTER(KE, pkcs11_kem_create) / PLUGIN_PROVIDE(KE,
 * ML_KEM_768) in pkcs11_plugin.c).
 *
 * Prior to this file, this connector's ONLY evidence for ML-KEM-768 key
 * exchange was a manually browser-verified WASM handshake (see
 * ../../strongswan-wasm-shims/STATUS.md) — not automated, not runnable
 * from the command line.
 *
 * This drives the exact call sequence key_exchange_t's own header comment
 * documents for a real IKEv2 KE payload exchange between two peers:
 *
 *   Initiator                  Responder
 *   get_public_key()
 *                               set_public_key()
 *                               get_public_key()
 *   set_public_key()
 *   get_shared_secret()
 *                               get_shared_secret()
 *
 * — two independently-created pkcs11_kem_t instances (via two separate
 * lib->crypto->create_ke() calls, simulating the two IKEv2 peers), each
 * driving a real C_GenerateKeyPair / C_EncapsulateKey / C_DecapsulateKey
 * against the real softhsmv3 token (genuine PKCS#11 v3.2 KEM dispatch,
 * not a simulation). The correctness property under test is that both
 * sides land on the byte-identical 32-byte shared secret — plus a
 * negative control (one corrupted byte in what the responder sends back)
 * that proves the exchange is actually using the real key material: a
 * constant/no-op implementation would still "pass" the positive case,
 * but only a real KEM decapsulation produces a *different* secret when
 * fed a corrupted ciphertext (ML-KEM's FO-transform implicit-rejection
 * property: decapsulation of a bad ciphertext does not error, it
 * silently returns a different, deterministic-looking secret — so the
 * negative control asserts a MISMATCH, not a call failure).
 *
 * Build (against a strongSwan 6.0.7 tree with strongswan-pkcs11.patch +
 * strongswan-pqc*.patch applied — see this directory's README.md for the
 * full worked example, identical bootstrap to test_pkcs11_conn.c):
 *
 *   SS=/path/to/patched/strongswan-6.0.7
 *   cc -g -O0 -I$SS/src/libstrongswan -I$SS \
 *      -DHAVE_CONFIG_H -include $SS/config.h \
 *      -c test_pkcs11_kem.c -o test_pkcs11_kem.o
 *   cc -g -O0 test_pkcs11_kem.o -L$SS/src/libstrongswan/.libs -lstrongswan \
 *      -Wl,-rpath,$SS/src/libstrongswan/.libs -ldl -o test_pkcs11_kem
 *
 * Two real, load-bearing prerequisites this test's own investigation
 * turned up, neither obvious from the key_exchange_t header alone:
 *
 * 1. settings.conf MUST set `plugins.pkcs11.use_dh = yes`. pkcs11_plugin.c
 *    only adds its `f_pqc` feature block — which is where BOTH
 *    `PLUGIN_PROVIDE(KE, ML_KEM_768)` AND the per-type ML-DSA/SLH-DSA
 *    PRIVKEY/PUBKEY entries live — under that flag (mirroring upstream's
 *    existing "opt in to PKCS#11-backed DH/KE" gate). test_pkcs11_conn.c
 *    never needed this because its BUILD_PKCS11_KEYID lookup goes through
 *    the *unconditionally* registered generic `PLUGIN_PROVIDE(PRIVKEY,
 *    KEY_ANY)` (f_privkey) builder instead — but `lib->crypto->create_ke()`
 *    has no such generic fallback; ML_KEM_768 is reachable *only* via the
 *    gated `f_pqc` KE registration. Without `use_dh = yes`,
 *    crypto_factory's create_ke() silently returns NULL (no registered
 *    entry for ML_KEM_768 at all) — pkcs11_kem_create() is never even
 *    called, so this fails with zero diagnostic output.
 *
 * 2. The token must already be in a *logged-in* state before
 *    lib->crypto->create_ke() runs. ML-KEM private keys are CKA_PRIVATE by
 *    default (PKCS#11 v3.2 §6.68.3 + §4.7), so C_GenerateKeyPair on a
 *    public (not-logged-in) session fails CKR_USER_NOT_LOGGED_IN.
 *    pkcs11_kem.c's find_token() only calls C_Login on the __EMSCRIPTEN__
 *    build (see its own comment) — on native builds it opens a plain
 *    C_OpenSession with no login at all, relying on the token's login
 *    state already being established elsewhere. That's not a native-path
 *    bug so much as a real-deployment assumption: in an actual IKEv2
 *    daemon, the token is already logged in from connecting the peer's
 *    own PKCS#11-backed authentication key (pkcs11_private_key.c's
 *    login(), via a SHARED_PIN credential) before any KE payload is
 *    negotiated on the same token — PKCS#11 login state is per
 *    token-per-application (shared across all of an application's
 *    sessions to that token, PKCS#11 v3.2 §5.6.1), not per-session, so it
 *    persists into whatever session find_token() opens later. This test
 *    reproduces that real precondition faithfully with a raw C_Login
 *    (raw_pkcs11_login() below) on a session it keeps open for the
 *    process lifetime, rather than special-casing pkcs11_kem.c itself.
 *
 * Run:
 *
 *   ./test_pkcs11_kem <module.so> <token-label> <pin> \
 *       <plugindir-colon-list> pkcs11 <settings.conf>
 *
 * <module.so>/<token-label>/<pin> are used only for this test's own
 * pre-login step (see raw_pkcs11_login()) — pkcs11_kem_create() itself
 * takes no module/slot/keyid parameters at all: it finds its own token by
 * enumerating every module registered from settings.conf's
 * plugins.pkcs11.modules.* section for one whose slot supports
 * CKM_ML_KEM, via pkcs11_kem.c's find_token(). No key provisioning is
 * needed beyond an initialized token — pkcs11_kem_create() generates its
 * own ML-KEM keypair on the fly, unlike the signature path's
 * pre-provisioned CKA_ID lookup.
 */
#include <library.h>
#include <crypto/key_exchange.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

/* FIPS 203 ML-KEM-768 shared secret is always 32 bytes. */
#define ML_KEM_768_SECRET_LEN 32

/*
 * Minimal, dependency-free raw PKCS#11 C_Login — same technique and same
 * truncated CK_FUNCTION_LIST-prefix trick as keygen_pkcs11_key.c in this
 * directory (v2.01+ function-pointer layout, unchanged since; no
 * dependency on this repo's pkcs11.h or any strongSwan header). Logs in
 * once, on a session it deliberately leaves open — closing the last
 * session an application holds to a token drops that token's login state
 * (PKCS#11 v3.2 §5.6.1), and find_token() opens further sessions of its
 * own later, so this session must outlive the whole test run. Returns
 * TRUE on success (including CKR_USER_ALREADY_LOGGED_IN, in case some
 * earlier plugin activity already logged in).
 */
static bool raw_pkcs11_login(const char *modpath, const char *tokenlabel, const char *pin)
{
    typedef unsigned long CK_ULONG_;
    typedef CK_ULONG_ CK_RV_;
    typedef CK_ULONG_ CK_SLOT_ID_;
    typedef CK_ULONG_ CK_SESSION_HANDLE_;
    typedef CK_ULONG_ CK_FLAGS_;
    typedef CK_ULONG_ CK_USER_TYPE_;
    typedef struct {
        unsigned char label[32];
        unsigned char manufacturerID[32]; unsigned char model[16]; unsigned char serialNumber[16];
        CK_FLAGS_ flags; CK_ULONG_ ulMaxSessionCount; CK_ULONG_ ulSessionCount; CK_ULONG_ ulMaxRwSessionCount;
        CK_ULONG_ ulRwSessionCount; CK_ULONG_ ulMaxPinLen; CK_ULONG_ ulMinPinLen; CK_ULONG_ ulTotalPublicMemory;
        CK_ULONG_ ulFreePublicMemory; CK_ULONG_ ulTotalPrivateMemory; CK_ULONG_ ulFreePrivateMemory;
        unsigned char hardwareVersion[2]; unsigned char firmwareVersion[2]; unsigned char utcTime[16];
    } CK_TOKEN_INFO_;
    struct func_list {
        struct { unsigned char major, minor; } version;
        CK_RV_ (*C_Initialize)(void*);
        CK_RV_ (*C_Finalize)(void*);
        CK_RV_ (*C_GetInfo)(void*);
        CK_RV_ (*C_GetFunctionList)(void*);
        CK_RV_ (*C_GetSlotList)(unsigned char, CK_SLOT_ID_*, CK_ULONG_*);
        CK_RV_ (*C_GetSlotInfo)(CK_SLOT_ID_, void*);
        CK_RV_ (*C_GetTokenInfo)(CK_SLOT_ID_, CK_TOKEN_INFO_*);
        CK_RV_ (*C_GetMechanismList)(void);
        CK_RV_ (*C_GetMechanismInfo)(void);
        CK_RV_ (*C_InitToken)(void);
        CK_RV_ (*C_InitPIN)(void);
        CK_RV_ (*C_SetPIN)(void);
        CK_RV_ (*C_OpenSession)(CK_SLOT_ID_, CK_FLAGS_, void*, void*, CK_SESSION_HANDLE_*);
        CK_RV_ (*C_CloseSession)(CK_SESSION_HANDLE_);
        CK_RV_ (*C_CloseAllSessions)(void);
        CK_RV_ (*C_GetSessionInfo)(void);
        CK_RV_ (*C_GetOperationState)(void);
        CK_RV_ (*C_SetOperationState)(void);
        CK_RV_ (*C_Login)(CK_SESSION_HANDLE_, CK_USER_TYPE_, unsigned char*, CK_ULONG_);
    } *fl = NULL;
    static const CK_ULONG_ CKR_OK_ = 0, CKR_CRYPTOKI_ALREADY_INITIALIZED_ = 0x191,
                            CKR_USER_ALREADY_LOGGED_IN_ = 0x100;
    static const CK_ULONG_ CKF_SERIAL_SESSION_ = 4, CKF_RW_SESSION_ = 2, CKU_USER_ = 1;

    void *h = dlopen(modpath, RTLD_NOW);
    if (!h)
    {
        fprintf(stderr, "raw_pkcs11_login: dlopen(%s) failed: %s\n", modpath, dlerror());
        return FALSE;
    }
    CK_RV_ (*get_list)(struct func_list**) =
        (CK_RV_ (*)(struct func_list**))dlsym(h, "C_GetFunctionList");
    if (!get_list || get_list(&fl) != CKR_OK_)
    {
        fprintf(stderr, "raw_pkcs11_login: C_GetFunctionList failed\n");
        return FALSE;
    }
    CK_RV_ rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK_ && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED_)
    {
        fprintf(stderr, "raw_pkcs11_login: C_Initialize rv=%lu\n", rv);
        return FALSE;
    }

    CK_SLOT_ID_ slots[32]; CK_ULONG_ n = 32;
    rv = fl->C_GetSlotList(1, slots, &n);
    if (rv != CKR_OK_)
    {
        fprintf(stderr, "raw_pkcs11_login: C_GetSlotList rv=%lu\n", rv);
        return FALSE;
    }
    CK_SLOT_ID_ target = (CK_SLOT_ID_)-1;
    for (CK_ULONG_ i = 0; i < n; i++)
    {
        CK_TOKEN_INFO_ ti;
        if (fl->C_GetTokenInfo(slots[i], &ti) != CKR_OK_) continue;
        int len = 32;
        while (len > 0 && ti.label[len - 1] == ' ') len--;
        if ((int)strlen(tokenlabel) == len && memcmp(ti.label, tokenlabel, len) == 0)
        {
            target = slots[i];
            break;
        }
    }
    if (target == (CK_SLOT_ID_)-1)
    {
        fprintf(stderr, "raw_pkcs11_login: token '%s' not found\n", tokenlabel);
        return FALSE;
    }

    CK_SESSION_HANDLE_ sess;
    rv = fl->C_OpenSession(target, CKF_SERIAL_SESSION_ | CKF_RW_SESSION_, NULL, NULL, &sess);
    if (rv != CKR_OK_)
    {
        fprintf(stderr, "raw_pkcs11_login: C_OpenSession rv=%lu\n", rv);
        return FALSE;
    }
    /* Deliberately not closed — see function comment. */
    rv = fl->C_Login(sess, CKU_USER_, (unsigned char*)pin, (CK_ULONG_)strlen(pin));
    if (rv != CKR_OK_ && rv != CKR_USER_ALREADY_LOGGED_IN_)
    {
        fprintf(stderr, "raw_pkcs11_login: C_Login rv=%lu\n", rv);
        return FALSE;
    }
    printf("raw_pkcs11_login: token '%s' logged in (session %lu kept open for the "
           "process lifetime so find_token()'s later sessions inherit login state)\n",
           tokenlabel, (unsigned long)sess);
    return TRUE;
}

/*
 * Runs one full two-peer ML-KEM-768 exchange. If `corrupt` is TRUE, flips
 * one byte of the responder's ciphertext before handing it to the
 * initiator — the negative control. Returns 0 on the expected outcome
 * (secrets match iff !corrupt), 1 otherwise.
 */
static int run_exchange(bool corrupt, const char *label)
{
    key_exchange_t *ke_i = NULL, *ke_r = NULL;
    chunk_t pub_i = chunk_empty;    /* initiator's ML-KEM encapsulation key */
    chunk_t ct_r = chunk_empty;     /* responder's ciphertext (its get_public_key() output) */
    chunk_t secret_i = chunk_empty;
    chunk_t secret_r = chunk_empty;
    int rc = 1;

    ke_i = lib->crypto->create_ke(lib->crypto, ML_KEM_768);
    if (!ke_i)
    {
        printf("[%s] FAIL: create_ke(ML_KEM_768) returned NULL for initiator\n", label);
        goto out;
    }
    ke_r = lib->crypto->create_ke(lib->crypto, ML_KEM_768);
    if (!ke_r)
    {
        printf("[%s] FAIL: create_ke(ML_KEM_768) returned NULL for responder\n", label);
        goto out;
    }
    printf("[%s] two independent pkcs11_kem_t instances created (method=%N)\n",
           label, key_exchange_method_names, ke_i->get_method(ke_i));

    /* Initiator: real C_GenerateKeyPair (CKM_ML_KEM_KEY_PAIR_GEN), returns pubkey. */
    if (!ke_i->get_public_key(ke_i, &pub_i))
    {
        printf("[%s] FAIL: initiator get_public_key() failed\n", label);
        goto out;
    }
    printf("[%s] initiator get_public_key() OK: %d bytes (expect 1184)\n",
           label, (int)pub_i.len);

    /* Responder: receives initiator's pubkey, immediately encapsulates
     * (real C_CreateObject + C_EncapsulateKey against the initiator's
     * public key value) — pkcs11_kem.c's set_public_key() does this
     * eagerly so get_public_key() can return the ciphertext right after. */
    if (!ke_r->set_public_key(ke_r, pub_i))
    {
        printf("[%s] FAIL: responder set_public_key(initiator pubkey) failed\n", label);
        goto out;
    }
    if (!ke_r->get_public_key(ke_r, &ct_r))
    {
        printf("[%s] FAIL: responder get_public_key() (ciphertext) failed\n", label);
        goto out;
    }
    printf("[%s] responder set_public_key()+get_public_key() OK: ciphertext %d bytes (expect 1088)\n",
           label, (int)ct_r.len);

    if (!ke_r->get_shared_secret(ke_r, &secret_r))
    {
        printf("[%s] FAIL: responder get_shared_secret() failed\n", label);
        goto out;
    }
    printf("[%s] responder get_shared_secret() OK: %d bytes\n", label, (int)secret_r.len);

    if (corrupt)
    {
        if (ct_r.len == 0)
        {
            printf("[%s] FAIL: empty ciphertext, cannot corrupt\n", label);
            goto out;
        }
        ct_r.ptr[0] ^= 0xFF;
        printf("[%s] negative control: flipped byte 0 of the responder's ciphertext\n", label);
    }

    /* Initiator: receives (possibly corrupted) ciphertext, real
     * C_DecapsulateKey using its own private key handle. */
    if (!ke_i->set_public_key(ke_i, ct_r))
    {
        printf("[%s] FAIL: initiator set_public_key(ciphertext) failed\n", label);
        goto out;
    }
    if (!ke_i->get_shared_secret(ke_i, &secret_i))
    {
        printf("[%s] FAIL: initiator get_shared_secret() (decapsulate) failed\n", label);
        goto out;
    }
    printf("[%s] initiator get_shared_secret() OK: %d bytes\n", label, (int)secret_i.len);

    if (secret_i.len != ML_KEM_768_SECRET_LEN || secret_r.len != ML_KEM_768_SECRET_LEN)
    {
        printf("[%s] FAIL: unexpected shared secret length (initiator=%d responder=%d, expected %d)\n",
               label, (int)secret_i.len, (int)secret_r.len, ML_KEM_768_SECRET_LEN);
        goto out;
    }

    bool equal = chunk_equals(secret_i, secret_r);
    if (corrupt)
    {
        if (equal)
        {
            printf("[%s] FAIL: corrupted ciphertext still produced a MATCHING shared secret "
                   "(exchange is not using real key material)\n", label);
            goto out;
        }
        printf("[%s] negative control OK: corrupted ciphertext produced a MISMATCHED shared secret\n",
               label);
    }
    else
    {
        if (!equal)
        {
            printf("[%s] FAIL: initiator and responder shared secrets DO NOT MATCH\n", label);
            goto out;
        }
        printf("[%s] positive case OK: initiator and responder shared secrets are byte-identical\n",
               label);
    }

    printf("[%s] PASS\n", label);
    rc = 0;

out:
    chunk_free(&pub_i);
    chunk_free(&ct_r);
    chunk_free(&secret_i);
    chunk_free(&secret_r);
    if (ke_i) ke_i->destroy(ke_i);
    if (ke_r) ke_r->destroy(ke_r);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 7)
    {
        fprintf(stderr,
            "usage: %s <module.so> <token-label> <pin> "
            "<plugindir-colon-list> <plugin-names> <settings.conf>\n",
            argv[0]);
        return 2;
    }
    const char *modpath = argv[1];
    const char *tokenlabel = argv[2];
    const char *pin = argv[3];
    /* No config-module-name / slot-id args for the plugin-loading half —
     * pkcs11_kem_create() finds its own token (see the file header
     * comment above). */
    const char *plugindir = argv[4];
    const char *pluginnames = argv[5];
    const char *settings = argv[6];

    library_init((char*)settings, "test_pkcs11_kem");
    {
        /* plugindir is a colon-separated list of directories to search. */
        char *dirs = strdup(plugindir);
        char *tok = strtok(dirs, ":");
        while (tok)
        {
            lib->plugins->add_path(lib->plugins, tok);
            tok = strtok(NULL, ":");
        }
        free(dirs);
    }
    if (!lib->plugins->load(lib->plugins, (char*)pluginnames))
    {
        fprintf(stderr, "plugin load failed (plugindir=%s plugins=%s)\n", plugindir, pluginnames);
        library_deinit();
        return 1;
    }

    /* Establish the token's logged-in state before touching create_ke() —
     * see the file header comment (prerequisite 2) for why this is
     * necessary and why it faithfully represents a real deployment
     * rather than papering over a bug. */
    if (!raw_pkcs11_login(modpath, tokenlabel, pin))
    {
        fprintf(stderr, "pre-login failed, aborting\n");
        lib->plugins->unload(lib->plugins);
        library_deinit();
        return 1;
    }

    int failures = 0;
    failures += run_exchange(FALSE, "ML-KEM-768 positive");
    failures += run_exchange(TRUE, "ML-KEM-768 negative-control");

    lib->plugins->unload(lib->plugins);
    library_deinit();

    printf("\n==================================================\n");
    printf("%d test(s), %d failure(s)\n", 2, failures);
    return failures ? 1 : 0;
}
