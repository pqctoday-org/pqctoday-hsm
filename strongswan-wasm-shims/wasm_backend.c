/*
 * wasm_backend.c — C-level config backend for the strongSwan WASM build.
 *
 * In a normal charon deployment the backend (stroke / vici / swanctl)
 * feeds IKE and peer configs to the daemon. The WASM build has no unix
 * socket — so JS injects a strongswan.conf *and* this C shim exposes:
 *
 *   wasm_setup_config(mode)        : pre-registers default IKE/peer cfgs
 *                                    + PSK credentials (read from env
 *                                    WASM_PSK). Called once from
 *                                    libcharon's _main() under
 *                                    __EMSCRIPTEN__ guards.
 *
 *   wasm_get_peer_by_name(this,n)  : backend_t::get_peer_cfg_by_name
 *   wasm_create_peer_enum(this,...)  : backend_t::create_peer_cfg_enumerator
 *   wasm_create_ike_enum (this,...)  : backend_t::create_ike_cfg_enumerator
 *
 *   wasm_set_proposal_mode(mode)   : 0 = classical (AES/ECP256)
 *                                    1 = pure PQC  (ML-KEM-768)
 *                                    2 = hybrid    (ML-KEM-768 + ECP256)
 *
 *   wasm_set_auth_mode(mode)       : 0 = PSK (default)
 *                                    1 = PUBKEY (ML-DSA cert auth)
 *
 *   wasm_initiate()                : kick off IKE_SA_INIT for the
 *                                    "charon-initiator" peer_cfg.
 *
 * Signatures match the baseline WASM exports exactly (see Appendix B of
 * the task brief).
 */

#ifdef __EMSCRIPTEN__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <daemon.h>
#include <library.h>
#include <utils/debug.h>
#include <config/backend.h>
#include <config/peer_cfg.h>
#include <config/ike_cfg.h>
#include <config/child_cfg.h>
#include <collections/linked_list.h>
#include <collections/enumerator.h>
#include <credentials/auth_cfg.h>
#include <credentials/sets/mem_cred.h>
#include <selectors/traffic_selector.h>

/*─────────────────────────────────────────────────────────────────────*/
/* Globals                                                             */
/*─────────────────────────────────────────────────────────────────────*/

/* Proposal-selection mode (0=classical, 1=pure-pqc, 2=hybrid). Read by
 * wasm_setup_config() to pick which proposal strings to bake into the
 * IKE cfg. */
int wasm_proposal_mode = 0;

void wasm_set_proposal_mode(int mode)
{
    wasm_proposal_mode = mode;
}

/* Auth-class mode: 0 = PSK (default), 1 = PUBKEY (ML-DSA cert).
 * Set via wasm_set_auth_mode() before _main() is called. When 1,
 * wasm_setup_config() uses AUTH_CLASS_PUBKEY and loads the local cert
 * from the worker FS (written by the panel's generateCertsViaWorker). */
int wasm_auth_mode = 0;

void wasm_set_auth_mode(int mode)
{
    wasm_auth_mode = mode;
}

/* Linked list of peer_cfg_t owned by this backend. */
static linked_list_t *peer_cfgs = NULL;

/* Backend singleton. */
typedef struct {
    backend_t public;
} wasm_backend_t;
static wasm_backend_t *wasm_backend = NULL;

/*─────────────────────────────────────────────────────────────────────*/
/* backend_t vtable                                                    */
/*─────────────────────────────────────────────────────────────────────*/

peer_cfg_t *wasm_get_peer_by_name(backend_t *this, char *name)
{
    enumerator_t *e;
    peer_cfg_t *cfg, *found = NULL;

    if (!peer_cfgs || !name) return NULL;
    e = peer_cfgs->create_enumerator(peer_cfgs);
    while (e->enumerate(e, &cfg))
    {
        if (streq(cfg->get_name(cfg), name))
        {
            found = cfg->get_ref(cfg);
            break;
        }
    }
    e->destroy(e);
    return found;
}

enumerator_t *wasm_create_peer_enum(backend_t *this,
                                    identification_t *me,
                                    identification_t *other)
{
    if (!peer_cfgs) return enumerator_create_empty();
    return peer_cfgs->create_enumerator(peer_cfgs);
}

CALLBACK(ike_cfg_filter, bool,
    void *data, enumerator_t *orig, va_list args)
{
    peer_cfg_t *peer_cfg;
    ike_cfg_t **out;

    VA_ARGS_VGET(args, out);

    while (orig->enumerate(orig, &peer_cfg))
    {
        *out = peer_cfg->get_ike_cfg(peer_cfg);
        return TRUE;
    }
    return FALSE;
}

enumerator_t *wasm_create_ike_enum(backend_t *this,
                                   host_t *me, host_t *other)
{
    /* find_ike_cfg() (config/backends/backend_manager.c) drives this on
     * the responder when an IKE_SA_INIT request arrives — no peer_cfg has
     * been chosen yet because IDs only show up in IKE_AUTH, so charon
     * picks the ike_cfg first by host match (me/other vs the cfg's
     * local/remote), then negotiates proposals from it.
     *
     * Earlier this returned enumerator_create_empty() with a comment
     * claiming "the responder branch is driven by peer_cfgs directly" —
     * that's wrong. With no ike_cfg returned here, find_ike_cfg fails
     * even when peer_cfgs is populated, the responder logs
     * "no IKE config found for 192.168.0.2...192.168.0.1" and replies
     * NO_PROPOSAL_CHOSEN.
     *
     * Project each peer_cfg to its ike_cfg via enumerator_create_filter
     * — same pattern as pkcs11_creds.c::certs_filter. The me/other args
     * are unused here; charon's backend_manager handles host-match
     * filtering after we return the candidates. */
    if (!peer_cfgs) return enumerator_create_empty();
    return enumerator_create_filter(
        peer_cfgs->create_enumerator(peer_cfgs),
        ike_cfg_filter, NULL, NULL);
}

/*─────────────────────────────────────────────────────────────────────*/
/* wasm_setup_config — builds default peer + IKE cfgs from env vars    */
/*─────────────────────────────────────────────────────────────────────*/

static const char *proposal_ike_classical = "aes256-sha256-ecp256";
static const char *proposal_ike_pqc       = "aes256-sha256-mlkem768";
/* RFC 9370 multi-KE hybrid: ML-KEM-768 is the IKE_SA_INIT key exchange,
 * ECP-256 runs as Additional Key Exchange 1 in a real IKE_INTERMEDIATE
 * round. 6.0.5 parses the ke1_ prefix via additional_key_exchange_parser
 * (key_exchange.c, registered in key_exchange_init). The previous string
 * "...mlkem768-ecp256" merely offered both as KE alternatives. */
static const char *proposal_ike_hybrid    = "aes256-sha256-mlkem768-ke1_ecp256";
static const char *proposal_esp           = "aes256-sha256";

/* Implemented in kernel_wasm.c — registers the Tier A stub kernel_ipsec_t
 * backend so CHILD_SA SPI allocation / SA install succeed without a kernel. */
extern void wasm_kernel_register(void);

void wasm_setup_config(int unused)
{
    peer_cfg_t *peer_cfg;
    ike_cfg_t *ike_cfg;
    child_cfg_t *child_cfg;
    auth_cfg_t *auth_local, *auth_remote;
    peer_cfg_create_t peer_data;
    ike_cfg_create_t  ike_data;
    child_cfg_create_t child_data;
    const char *ike_prop;
    const char *psk_env;
    mem_cred_t *creds;
    certificate_t *my_cert = NULL;

    /* Lazy-init backend + storage. */
    if (!peer_cfgs) peer_cfgs = linked_list_create();

    /* Register the Tier A stub kernel_ipsec_t backend UNCONDITIONALLY and
     * FIRST. It used to be registered only inside the WASM_CHILDSA=1 branch
     * below, which raced the env-var plumbing: if JS set WASM_CHILDSA after
     * (or re-ran) setup, the initiator hit "unable to allocate SPI from
     * kernel" because kernel_interface_t::get_spi returns NOT_SUPPORTED
     * while this->ipsec is NULL (kernel_interface.c:177-186 — no KERNEL_NET
     * backend is needed for the SPI path). The stub is harmless when the
     * IKE_SA is childless, so always register it before any peer_cfg exists
     * and thus before any CHILD_CREATE task can possibly run on either
     * worker. wasm_kernel_register() is idempotent. */
    wasm_kernel_register();

    switch (wasm_proposal_mode)
    {
        case 1: ike_prop = proposal_ike_pqc;       break;
        case 2: ike_prop = proposal_ike_hybrid;    break;
        default: ike_prop = proposal_ike_classical; break;
    }

    /* IKE config — local/remote addresses depend on the worker's role.
     * The JS worker sets WASM_ROLE = "initiator" | "responder" before main();
     * we hard-code 192.168.0.1 / 192.168.0.2 to match bridge.ts's SAB-based
     * UDP loopback. Without explicit addresses, charon aborts IKE_SA_INIT
     * with "unable to resolve 0.0.0.0". */
    memset(&ike_data, 0, sizeof(ike_data));
    ike_data.version     = IKEV2;
    {
        const char *role_env = getenv("WASM_ROLE");
        if (role_env && !strcmp(role_env, "initiator")) {
            ike_data.local  = "192.168.0.1";
            ike_data.remote = "192.168.0.2";
        } else {
            /* responder (or unset → default to responder) */
            ike_data.local  = "192.168.0.2";
            ike_data.remote = "192.168.0.1";
        }
    }
    ike_data.local_port  = 500;
    ike_data.remote_port = 500;
    /* Childless IKE_SA per RFC 6023: by default skip the piggybacked
     * CHILD_SA in IKE_AUTH. The hub can opt in to a real CHILD_SA
     * negotiation via WASM_CHILDSA=1 — the Tier A stub kernel backend
     * (kernel_wasm.c) is always registered (top of this function) so
     * get_spi/add_sa/add_policy succeed, and CHILDLESS_NEVER makes the
     * CHILD_SA negotiate in IKE_AUTH. */
    {
        const char *childsa_env = getenv("WASM_CHILDSA");
        if (childsa_env && !strcmp(childsa_env, "1"))
        {
            ike_data.childless = CHILDLESS_NEVER;
        }
        else
        {
            ike_data.childless = CHILDLESS_FORCE;
        }
    }
    /* IKEv2 fragmentation (RFC 7383): enabled by default so large
     * IKE_AUTH/IKE_INTERMEDIATE messages (ML-DSA certs, ML-KEM payloads)
     * split per charon.fragment_size from the hub's strongswan.conf.
     * Opt out via WASM_FRAGMENTATION=no. */
    {
        const char *frag_env = getenv("WASM_FRAGMENTATION");
        if (frag_env && !strcmp(frag_env, "no"))
        {
            ike_data.fragmentation = FRAGMENTATION_NO;
        }
        else
        {
            ike_data.fragmentation = FRAGMENTATION_YES;
        }
    }
    ike_cfg = ike_cfg_create(&ike_data);
    ike_cfg->add_proposal(ike_cfg, proposal_create_from_string(PROTO_IKE,
                                                               (char *)ike_prop));

    /* Peer config. (Childless behavior is set on ike_cfg_create_t above.) */
    memset(&peer_data, 0, sizeof(peer_data));
    /* CERT_ALWAYS_SEND so the X.509 (with ML-DSA pubkey) is included in the
     * IKE_AUTH payload — without it the peer can't get our pubkey, signature
     * verification fails, and IKE_AUTH returns AUTH_FAILED. CERT_SEND_IF_ASKED
     * (default) only sends when peer included a CERTREQ, which doesn't happen
     * in our self-signed setup. Always-send is correct for dual-auth ML-DSA. */
    peer_data.cert_policy = (wasm_auth_mode == 1) ? CERT_ALWAYS_SEND : CERT_SEND_IF_ASKED;
    peer_data.unique      = UNIQUE_NO;
    peer_data.keyingtries = 1;
    peer_cfg = peer_cfg_create("wasm", ike_cfg, &peer_data);

    if (wasm_auth_mode == 1)
    {
        /* Pubkey auth — ML-DSA cert loaded from worker FS.
         * Cert path is role-dependent; written by generateCertsViaWorker
         * before the daemon starts. charon's strongswan-pkcs11 plugin
         * finds the matching private key via CKA_ID = cert SKID. */
        const char *role_env2 = getenv("WASM_ROLE");
        const char *local_cert_path =
            (role_env2 && !strcmp(role_env2, "initiator"))
                ? "/etc/ipsec.d/certs/initiator.crt"
                : "/etc/ipsec.d/certs/responder.crt";

        my_cert = lib->creds->create(lib->creds,
            CRED_CERTIFICATE, CERT_X509,
            BUILD_FROM_FILE, local_cert_path,
            BUILD_END);

        /* Load the PEER's cert as a trust anchor so the responder accepts
         * the initiator's self-signed cert (and vice versa). Without this,
         * IKE_AUTH succeeds locally (we sign) but the peer rejects our cert
         * with AUTH_FAILED because it doesn't trust the signer. */
        const char *peer_cert_path =
            (role_env2 && !strcmp(role_env2, "initiator"))
                ? "/etc/ipsec.d/certs/responder.crt"
                : "/etc/ipsec.d/certs/initiator.crt";
        certificate_t *peer_cert = lib->creds->create(lib->creds,
            CRED_CERTIFICATE, CERT_X509,
            BUILD_FROM_FILE, peer_cert_path,
            BUILD_END);
        if (peer_cert)
        {
            mem_cred_t *peer_creds = mem_cred_create();
            /* trusted=TRUE → counts as a CA anchor for trust-chain validation
             * of the peer's self-signed cert. */
            peer_creds->add_cert(peer_creds, TRUE, peer_cert);
            lib->credmgr->add_set(lib->credmgr, &peer_creds->set);
            DBG1(DBG_CFG, "WASM: loaded peer cert from %s as trust anchor",
                 peer_cert_path);
        }
        else
        {
            DBG1(DBG_CFG, "WASM: FAILED to load peer cert from %s — IKE_AUTH will fail",
                 peer_cert_path);
        }

        /* Build local + remote identities. If WASM_LOCAL_KEYID / WASM_REMOTE_KEYID
         * env vars are set (hex string, no prefix), use ID_KEY_ID. This makes
         * charon's credential_manager.c::get_private hit the ID_KEY_ID fast path
         * (get_private_by_keyid → find_lib_by_keyid by CKA_ID), bypassing the
         * cert→pubkey→fingerprint chain that does not work reliably for ML-DSA
         * in this WASM build. The hex bytes must match the CKA_ID set on the
         * private key in the panel softhsm at keygen time.
         *
         * Format passed to identification_create_from_string: "@#<hex>". The
         * '@' tells strongSwan it's not a DN; '#' tells it the rest is hex
         * bytes for ID_KEY_ID. See identification.c:2107-2114. */
        char id_buf[128];
        const char *local_keyid_env  = getenv("WASM_LOCAL_KEYID");
        const char *remote_keyid_env = getenv("WASM_REMOTE_KEYID");

        /* CRITICAL: Explicitly load the PKCS#11 private key into a mem_cred
         * set. Upstream strongswan-pkcs11's credential set returns
         * enumerator_create_empty for create_private_enumerator (see
         * pkcs11_creds.c:241), so credmgr's get_private_by_keyid path
         * always returns NULL unless the private key has been pre-loaded
         * via lib->creds->create(BUILD_PKCS11_KEYID,...) and inserted into
         * a mem_cred. In real deployments this is done by stroke/vici/nm
         * config plugins; in WASM we have neither, so do it inline here.
         *
         * Without this, IKE_AUTH always fails with "no private key found".
         */
        if (local_keyid_env && *local_keyid_env)
        {
            size_t hex_len = strlen(local_keyid_env);
            if (hex_len >= 2 && (hex_len % 2) == 0)
            {
                size_t bin_len = hex_len / 2;
                u_char *bin = malloc(bin_len);
                for (size_t b = 0; b < bin_len; b++)
                {
                    unsigned int byte;
                    if (sscanf(local_keyid_env + b * 2, "%2x", &byte) != 1)
                    {
                        bin[b] = 0;
                    }
                    else
                    {
                        bin[b] = (u_char)byte;
                    }
                }
                chunk_t keyid_chunk = chunk_create(bin, bin_len);
                private_key_t *pkcs11_priv = lib->creds->create(lib->creds,
                    CRED_PRIVATE_KEY, KEY_ANY,
                    BUILD_PKCS11_KEYID, keyid_chunk,
                    BUILD_END);
                free(bin);
                if (pkcs11_priv)
                {
                    mem_cred_t *priv_creds = mem_cred_create();
                    priv_creds->add_key(priv_creds, pkcs11_priv);
                    lib->credmgr->add_set(lib->credmgr, &priv_creds->set);
                    DBG1(DBG_CFG, "WASM: loaded PKCS#11 private key for keyid %s into mem_cred",
                         local_keyid_env);
                }
                else
                {
                    DBG1(DBG_CFG, "WASM: FAILED to load PKCS#11 private key for keyid %s — IKE_AUTH will fail",
                         local_keyid_env);
                }
            }
        }

        auth_local = auth_cfg_create();
        auth_local->add(auth_local, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
        if (my_cert)
            auth_local->add(auth_local, AUTH_RULE_SUBJECT_CERT, my_cert);
        if (local_keyid_env && *local_keyid_env)
        {
            snprintf(id_buf, sizeof(id_buf), "@#%s", local_keyid_env);
            auth_local->add(auth_local, AUTH_RULE_IDENTITY,
                            identification_create_from_string(id_buf));
            DBG1(DBG_CFG, "WASM: local identity = ID_KEY_ID @#%s", local_keyid_env);
        }
        else
        {
            auth_local->add(auth_local, AUTH_RULE_IDENTITY,
                            identification_create_from_string("%any"));
        }
        peer_cfg->add_auth_cfg(peer_cfg, auth_local, TRUE);

        auth_remote = auth_cfg_create();
        auth_remote->add(auth_remote, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
        if (remote_keyid_env && *remote_keyid_env)
        {
            snprintf(id_buf, sizeof(id_buf), "@#%s", remote_keyid_env);
            auth_remote->add(auth_remote, AUTH_RULE_IDENTITY,
                             identification_create_from_string(id_buf));
            DBG1(DBG_CFG, "WASM: remote identity = ID_KEY_ID @#%s", remote_keyid_env);
        }
        else
        {
            auth_remote->add(auth_remote, AUTH_RULE_IDENTITY,
                             identification_create_from_string("%any"));
        }
        peer_cfg->add_auth_cfg(peer_cfg, auth_remote, FALSE);
    }
    else
    {
        /* PSK auth (default). */
        auth_local = auth_cfg_create();
        auth_local->add(auth_local, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
        auth_local->add(auth_local, AUTH_RULE_IDENTITY,
                        identification_create_from_string("%any"));
        peer_cfg->add_auth_cfg(peer_cfg, auth_local, TRUE);

        auth_remote = auth_cfg_create();
        auth_remote->add(auth_remote, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
        auth_remote->add(auth_remote, AUTH_RULE_IDENTITY,
                         identification_create_from_string("%any"));
        peer_cfg->add_auth_cfg(peer_cfg, auth_remote, FALSE);
    }

    memset(&child_data, 0, sizeof(child_data));
    child_data.mode = MODE_TUNNEL;
    child_data.start_action = ACTION_NONE;
    child_cfg = child_cfg_create("wasm-child", &child_data);
    child_cfg->add_proposal(child_cfg, proposal_create_from_string(PROTO_ESP,
                                                                   (char *)proposal_esp));

    /* Role-aware traffic selectors. Without any configured TS the child_cfg's
     * traffic_selector_list_t is empty, so the responder's narrowing in
     * child_cfg_select_ts() (child_cfg.c) intersects the initiator's TSi/TSr
     * against an empty set and yields zero selectors → charon logs
     * "traffic selectors ... unacceptable" and replies N(TS_UNACCEPTABLE).
     * Mirror how stroke/vici derive TS from leftsubnet/rightsubnet: local TS
     * is our own /32, remote TS is the peer's /32 (matching the hard-coded
     * ike_cfg addresses above), all protocols, all ports. The initiator
     * proposes exactly these, and the responder's mirrored config accepts
     * them as an exact (non-narrowed) match. */
    {
        const char *ts_role = getenv("WASM_ROLE");
        bool ts_initiator = (ts_role && !strcmp(ts_role, "initiator"));
        char *local_cidr  = ts_initiator ? "192.168.0.1/32" : "192.168.0.2/32";
        char *remote_cidr = ts_initiator ? "192.168.0.2/32" : "192.168.0.1/32";
        traffic_selector_t *ts_local =
            traffic_selector_create_from_cidr(local_cidr, 0, 0, 65535);
        traffic_selector_t *ts_remote =
            traffic_selector_create_from_cidr(remote_cidr, 0, 0, 65535);

        if (ts_local)
        {
            child_cfg->add_traffic_selector(child_cfg, TRUE, ts_local);
        }
        if (ts_remote)
        {
            child_cfg->add_traffic_selector(child_cfg, FALSE, ts_remote);
        }
        DBG1(DBG_CFG, "WASM: child_cfg traffic selectors local=%s remote=%s",
             local_cidr, remote_cidr);
    }

    peer_cfg->add_child_cfg(peer_cfg, child_cfg);

    peer_cfgs->insert_last(peer_cfgs, peer_cfg);

    DBG1(DBG_CFG, "WASM: registered static config (role=%s, local=%s, remote=%s)",
         getenv("WASM_ROLE") ? getenv("WASM_ROLE") : "responder",
         ike_data.local, ike_data.remote);

    /* Register the backend the first time. */
    if (!wasm_backend)
    {
        wasm_backend = malloc(sizeof(*wasm_backend));
        memset(wasm_backend, 0, sizeof(*wasm_backend));
        wasm_backend->public.get_peer_cfg_by_name =
            (peer_cfg_t *(*)(backend_t *, char *))wasm_get_peer_by_name;
        wasm_backend->public.create_peer_cfg_enumerator =
            (enumerator_t *(*)(backend_t *, identification_t *,
                               identification_t *))wasm_create_peer_enum;
        wasm_backend->public.create_ike_cfg_enumerator =
            (enumerator_t *(*)(backend_t *, host_t *, host_t *))
                wasm_create_ike_enum;
        charon->backends->add_backend(charon->backends, &wasm_backend->public);
    }

    /* Pre-register PSK from the WASM_PSK env var (PSK mode only).
     *
     * mem_cred->add_shared() takes a varargs list of identity owners
     * terminated by NULL. Passing just NULL makes the PSK unowned, which
     * fails credmgr lookups like "PSK for 192.168.0.1 - %any" because the
     * lookup tries to match the requested owners against the PSK's owners.
     * Add a "%any" identity owner so the PSK matches any peer pair. */
    if (wasm_auth_mode == 0)
    {
        psk_env = getenv("WASM_PSK");
        if (psk_env && *psk_env)
        {
            creds = mem_cred_create();
            creds->add_shared(creds,
                shared_key_create(SHARED_IKE,
                    chunk_clone(chunk_create((u_char *)psk_env, strlen(psk_env)))),
                identification_create_from_string("%any"),
                NULL);
            lib->credmgr->add_set(lib->credmgr, &creds->set);
        }
    }

}

/*─────────────────────────────────────────────────────────────────────*/
/* wasm_initiate — trigger IKE_SA_INIT on the responder                */
/*─────────────────────────────────────────────────────────────────────*/

void wasm_initiate(int unused)
{
    peer_cfg_t *peer_cfg;
    enumerator_t *e;
    child_cfg_t *child_cfg = NULL;
    enumerator_t *ce;

    /* Idempotent retry — guarantees the stub kernel is in place before the
     * CHILD_CREATE task this initiate() queues can call get_spi, even if an
     * earlier registration attempt ran before charon->kernel existed. */
    wasm_kernel_register();

    if (!peer_cfgs) return;
    e = peer_cfgs->create_enumerator(peer_cfgs);
    if (!e->enumerate(e, &peer_cfg))
    {
        e->destroy(e);
        return;
    }
    peer_cfg = peer_cfg->get_ref(peer_cfg);
    e->destroy(e);

    ce = peer_cfg->create_child_cfg_enumerator(peer_cfg);
    if (ce->enumerate(ce, &child_cfg))
    {
        child_cfg = child_cfg->get_ref(child_cfg);
    }
    ce->destroy(ce);

    if (child_cfg)
    {
        charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
                                     NULL, NULL, 0, 0, FALSE);
    }
    else
    {
        peer_cfg->destroy(peer_cfg);
    }
}

#endif /* __EMSCRIPTEN__ */
