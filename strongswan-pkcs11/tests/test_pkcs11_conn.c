/*
 * test_pkcs11_conn.c — real functional test of the strongswan-pkcs11
 * connector's PQC/PQ-adjacent authentication path (ML-DSA-44/65/87,
 * SLH-DSA-SHA2-128s/192s/256s, and Ed448), added because none of it —
 * least of all SLH-DSA, registered in pkcs11_plugin.c since the
 * ML-KEM-512/1024 + SLH-DSA-registration commit but never exercised by
 * any test — had a single automated test anywhere in this repo. The only
 * prior evidence for this connector's PQC auth was a manually
 * browser-verified WASM IKEv2 handshake (ML-DSA-65 cert auth only; see
 * ../../strongswan-wasm-shims/STATUS.md), documented but not repeatable
 * from the command line and not covering SLH-DSA or Ed448 at all.
 *
 * This exercises exactly the credential-layer call sequence real IKEv2
 * peer authentication uses: lib->creds->create(CRED_PRIVATE_KEY, ...,
 * BUILD_PKCS11_*, ...) to connect to a token-resident key via the real
 * pkcs11_private_key_connect() in pkcs11_private_key.c, then
 * private_key_t.sign() (CKM_ML_DSA / CKM_SLH_DSA / CKM_EDDSA via a real
 * C_Sign on the real softhsmv3 module) and public_key_t.verify() (real
 * C_Verify) — genuine PKCS#11 dispatch, not a simulation — plus a
 * negative control that a corrupted signature is correctly rejected.
 *
 * Build (against a strongSwan 6.0.7 tree with strongswan-pkcs11.patch +
 * strongswan-pqc*.patch applied, per strongswan-pkcs11.patch's own
 * header and ../../regen-strongswan-pkcs11-patch.sh):
 *
 *   SS=/path/to/patched/strongswan-6.0.7
 *   cc -g -O0 -I$SS/src/libstrongswan -I$SS \
 *      -DHAVE_CONFIG_H -include $SS/config.h \
 *      -c test_pkcs11_conn.c -o test_pkcs11_conn.o
 *   cc -g -O0 test_pkcs11_conn.o -L$SS/src/libstrongswan/.libs -lstrongswan \
 *      -Wl,-rpath,$SS/src/libstrongswan/.libs -o test_pkcs11_conn
 *
 * Run (provision keys first with keygen_pkcs11_key.c — see this
 * directory's README.md for the full worked example):
 *
 *   ./test_pkcs11_conn <config-module-name> <slot-id> \
 *       <pkcs11-plugin-dir> pkcs11 <settings.conf>
 *
 * <config-module-name> is the name under settings.conf's
 * plugins.pkcs11.modules.<name>.path stanza (NOT the raw .so path —
 * pkcs11_private_key_connect()'s find_lib() matches on this configured
 * name, since the module must already be registered via
 * pkcs11_manager_create() reading that config section before any
 * BUILD_PKCS11_MODULE lookup can find it).
 */
#include <library.h>
#include <credentials/keys/private_key.h>
#include <credentials/keys/public_key.h>
#include <credentials/sets/mem_cred.h>
#include <stdio.h>
#include <string.h>

static int run_one(const char *module, int slot, const char *keyid_hex,
                    key_type_t expect_type, signature_scheme_t scheme,
                    const char *label)
{
    chunk_t keyid = chunk_from_hex(chunk_from_str((char*)keyid_hex), NULL);
    private_key_t *priv;
    public_key_t *pub;
    chunk_t data = chunk_from_str("strongswan-pkcs11 connector test payload");
    chunk_t sig = chunk_empty;
    int rc = 1;

    priv = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
                               BUILD_PKCS11_MODULE, module,
                               BUILD_PKCS11_SLOT, slot,
                               BUILD_PKCS11_KEYID, keyid,
                               BUILD_END);
    if (!priv)
    {
        printf("[%s] FAIL: pkcs11_private_key_connect returned NULL\n", label);
        goto out_keyid;
    }
    if (priv->get_type(priv) != expect_type)
    {
        printf("[%s] FAIL: unexpected key_type %N (expected %N)\n", label,
               key_type_names, priv->get_type(priv), key_type_names, expect_type);
        goto out_priv;
    }
    printf("[%s] connected: key_type=%N, keysize=%d bits\n", label,
           key_type_names, priv->get_type(priv), priv->get_keysize(priv));

    /* Real C_Sign through the token. */
    if (!priv->sign(priv, scheme, NULL, data, &sig))
    {
        printf("[%s] FAIL: private_key_t.sign() failed (real C_Sign via token)\n", label);
        goto out_priv;
    }
    printf("[%s] C_Sign OK: signature length = %d bytes\n", label, (int)sig.len);

    pub = priv->get_public_key(priv);
    if (!pub)
    {
        printf("[%s] FAIL: get_public_key() returned NULL\n", label);
        goto out_sig;
    }
    /* Real C_Verify through the token. */
    if (!pub->verify(pub, scheme, NULL, data, sig))
    {
        printf("[%s] FAIL: public_key_t.verify() rejected a genuine signature (real C_Verify)\n", label);
        goto out_pub;
    }
    printf("[%s] C_Verify OK: genuine signature verified\n", label);

    /* Negative control: corrupt one byte and confirm verify correctly rejects it. */
    {
        chunk_t bad = chunk_clone(sig);
        bad.ptr[0] ^= 0xFF;
        if (pub->verify(pub, scheme, NULL, data, bad))
        {
            printf("[%s] FAIL: verify() accepted a corrupted signature\n", label);
            chunk_free(&bad);
            goto out_pub;
        }
        printf("[%s] negative control OK: corrupted signature correctly rejected\n", label);
        chunk_free(&bad);
    }

    printf("[%s] PASS\n", label);
    rc = 0;

out_pub:
    pub->destroy(pub);
out_sig:
    chunk_free(&sig);
out_priv:
    priv->destroy(priv);
out_keyid:
    chunk_free(&keyid);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 6)
    {
        fprintf(stderr,
            "usage: %s <config-module-name> <slot-id> <plugindir-colon-list> "
            "<plugin-names> <settings.conf>\n", argv[0]);
        return 2;
    }
    const char *module = argv[1];
    int slot = atoi(argv[2]);
    const char *plugindir = argv[3];
    const char *pluginnames = argv[4];
    const char *settings = argv[5];

    library_init((char*)settings, "test_pkcs11_conn");
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

    /* login() (pkcs11_private_key.c) sources the token PIN from a
     * SHARED_PIN credential owned by the key's ID_KEY_ID identity — an
     * owner-less shared key does NOT match (mem_cred's shared_filter
     * requires has_owner() > ID_MATCH_NONE whenever an owner is queried),
     * so register one PIN per CKA_ID used below. */
    mem_cred_t *creds = mem_cred_create();
    {
        const char *ids[] = {"01", "02", "03", "04", "05", "06", "07"};
        for (size_t i = 0; i < countof(ids); i++)
        {
            chunk_t k = chunk_from_hex(chunk_from_str((char*)ids[i]), NULL);
            identification_t *kid = identification_create_from_encoding(ID_KEY_ID, k);
            creds->add_shared(creds, shared_key_create(SHARED_PIN,
                               chunk_clone(chunk_from_str("1234"))), kid, NULL);
            chunk_free(&k);
        }
    }
    lib->credmgr->add_set(lib->credmgr, &creds->set);

    /* CKA_ID assignment matches this directory's README.md worked example
     * and keygen_pkcs11_key.c invocations: 01/02/03 = SLH-DSA-SHA2
     * 128s/256s/192s, 04/05/06 = ML-DSA-44/65/87, 07 = Ed448. */
    int failures = 0;
    failures += run_one(module, slot, "01", KEY_SLH_DSA_SHA2_128S,
                         SIGN_SLH_DSA_SHA2_128S, "SLH-DSA-SHA2-128s");
    failures += run_one(module, slot, "02", KEY_SLH_DSA_SHA2_256S,
                         SIGN_SLH_DSA_SHA2_256S, "SLH-DSA-SHA2-256s");
    failures += run_one(module, slot, "03", KEY_SLH_DSA_SHA2_192S,
                         SIGN_SLH_DSA_SHA2_192S, "SLH-DSA-SHA2-192s");
    failures += run_one(module, slot, "04", KEY_ML_DSA_44,
                         SIGN_ML_DSA_44, "ML-DSA-44");
    failures += run_one(module, slot, "05", KEY_ML_DSA_65,
                         SIGN_ML_DSA_65, "ML-DSA-65");
    failures += run_one(module, slot, "06", KEY_ML_DSA_87,
                         SIGN_ML_DSA_87, "ML-DSA-87");
    failures += run_one(module, slot, "07", KEY_ED448,
                         SIGN_ED448, "Ed448");

    lib->credmgr->remove_set(lib->credmgr, &creds->set);
    creds->destroy(creds);
    lib->plugins->unload(lib->plugins);
    library_deinit();

    printf("\n==================================================\n");
    printf("%d test(s), %d failure(s)\n", 7, failures);
    return failures ? 1 : 0;
}
