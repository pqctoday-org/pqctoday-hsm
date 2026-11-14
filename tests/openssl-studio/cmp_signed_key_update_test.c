/* SPDX-License-Identifier: AGPL-3.0-only */
#include "cmp_simulation.c"
#include <openssl/cmperr.h>

static int make_key(const char *algorithm, const char *path) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, algorithm);
    BIO *bio = BIO_new_file(path, "w");
    int ok = key != NULL && bio != NULL
        && PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    BIO_free(bio); EVP_PKEY_free(key); return ok;
}
static int passed(char *json) {
    int ok = json != NULL && strstr(json, "\"ok\":true") != NULL;
    if (!ok && json != NULL) fprintf(stderr, "%s\n", json);
    free(json); return ok;
}
static int signer_cert(const char *keypath, const char *path, int expired, int signing_usage) {
    X509 *ca = load_x509_pem("ca.pem"), *cert = X509_new();
    EVP_PKEY *ca_key = load_pkey_pem("ca.key"), *key = load_pkey_pem(keypath);
    X509_NAME *name = X509_NAME_new();
    ASN1_BIT_STRING *usage = ASN1_BIT_STRING_new();
    X509_EXTENSION *ext = NULL;
    int ok = 0;
    if (ca == NULL || cert == NULL || ca_key == NULL || key == NULL || name == NULL || usage == NULL) goto end;
    if (!X509_set_version(cert, 2) || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 50)
        || !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"fictional-renewal-signer", -1, -1, 0)
        || !X509_set_subject_name(cert, name)
        || !X509_set_issuer_name(cert, X509_get_subject_name(ca))
        || !X509_set_pubkey(cert, key)
        || X509_gmtime_adj(X509_getm_notBefore(cert), -3600) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(cert), expired ? -60 : 3600) == NULL
        || !ASN1_BIT_STRING_set_bit(usage, signing_usage ? 0 : 2, 1)) goto end;
    ext = X509V3_EXT_i2d(NID_key_usage, 1, usage);
    if (ext == NULL || !X509_add_ext(cert, ext, -1)
        || !X509_sign(cert, ca_key, NULL) || !write_x509_pem(path, cert)) goto end;
    ok = 1;
end:
    X509_EXTENSION_free(ext); ASN1_BIT_STRING_free(usage); X509_NAME_free(name);
    X509_free(ca); X509_free(cert); EVP_PKEY_free(ca_key); EVP_PKEY_free(key);
    return ok;
}
static X509 *rogue_ca;
static EVP_PKEY *rogue_key;
static int check_server_pin, server_pin_rejected;
static OSSL_CMP_MSG *boundary_transfer(OSSL_CMP_CTX *client, const OSSL_CMP_MSG *req) {
    if (check_server_pin) {
        OSSL_CMP_SRV_CTX *server = OSSL_CMP_CTX_get_transfer_cb_arg(client);
        int verified = OSSL_CMP_validate_msg(OSSL_CMP_SRV_CTX_get0_cmp_ctx(server), req);
        server_pin_rejected = !verified
            && ERR_GET_REASON(ERR_peek_last_error()) == CMP_R_SRVCERT_DOES_NOT_VALIDATE_MSG;
        ERR_clear_error();
    }
    return transfer_cb(client, req);
}
static OSSL_CMP_PKISI *issue_wrong_ca(OSSL_CMP_SRV_CTX *server,
    const OSSL_CMP_MSG *req, int id, const OSSL_CRMF_MSG *crm,
    const X509_REQ *p10, X509 **out, STACK_OF(X509) **chain, STACK_OF(X509) **pubs) {
    OSSL_CMP_PKISI *status = process_key_update_request(server, req, id, crm, p10, out, chain, pubs);
    if (*out != NULL
        && (!X509_set_issuer_name(*out, X509_get_subject_name(rogue_ca))
            || !X509_sign(*out, rogue_key, NULL))) {
        OSSL_CMP_PKISI_free(status);
        return NULL;
    }
    return status;
}
/* Exercise the server pin directly, bypassing the exported wrapper's preflight.
 * The other signer is mathematically valid and issued by the same fictional CA.
 * The wrong-issuer case retains the requested key and trusted outer CMP signer.
 */
static int server_boundary(const char *mode) {
    srv_state_t state = {0};
    OSSL_CMP_CTX *client = NULL, *peer;
    OSSL_CMP_SRV_CTX *server = NULL;
    X509 *pinned = NULL, *presented = NULL, *old = NULL, *issued = NULL;
    EVP_PKEY *presented_key = NULL, *newkey = NULL;
    X509_STORE *trust = NULL;
    int other = strcmp(mode, "server-other-signer") == 0;
    int wrong_ca = strcmp(mode, "server-wrong-issued-ca") == 0;
    int expected = !other && !wrong_ca, ok = 0, failure = -1;
    check_server_pin = other; server_pin_rejected = 0;
    state.ca_cert = load_x509_pem("ca.pem"); state.ca_key = load_pkey_pem("ca.key");
    state.authorized_prior = load_x509_pem("old.pem"); state.key_update = 2;
    pinned = load_x509_pem("sign.pem");
    presented = load_x509_pem(other ? "other.pem" : "sign.pem");
    presented_key = load_pkey_pem(other ? "other.key" : "sign.key");
    old = load_x509_pem("old.pem"); newkey = load_pkey_pem("new.key");
    server = OSSL_CMP_SRV_CTX_new(NULL, NULL); client = OSSL_CMP_CTX_new(NULL, NULL);
    trust = X509_STORE_new();
    if (state.ca_cert == NULL || state.ca_key == NULL || state.authorized_prior == NULL
        || pinned == NULL || presented == NULL || presented_key == NULL || old == NULL
        || newkey == NULL || server == NULL || client == NULL || trust == NULL) goto end;
    if (wrong_ca) {
        if (!passed(generate_mock_ca_root("ML-DSA-65", "/CN=fictional-untrusted-ca",
                "rogue.key", "rogue.pem", 1))) goto end;
        rogue_ca = load_x509_pem("rogue.pem"); rogue_key = load_pkey_pem("rogue.key");
        if (rogue_ca == NULL || rogue_key == NULL) goto end;
    }
    if (!OSSL_CMP_SRV_CTX_init(server, &state,
            wrong_ca ? issue_wrong_ca : process_key_update_request,
            NULL, NULL, NULL, process_key_update_confirmation, NULL)
        || !OSSL_CMP_SRV_CTX_set_accept_encrcert_popo(server, 1)) goto end;
    peer = OSSL_CMP_SRV_CTX_get0_cmp_ctx(server);
    if (!OSSL_CMP_CTX_set1_cert(peer, state.ca_cert) || !OSSL_CMP_CTX_set1_pkey(peer, state.ca_key)
        || !OSSL_CMP_CTX_set1_srvCert(peer, pinned)
        || !OSSL_CMP_CTX_set1_cert(client, presented) || !OSSL_CMP_CTX_set1_pkey(client, presented_key)
        || !OSSL_CMP_CTX_set1_srvCert(client, state.ca_cert) || !OSSL_CMP_CTX_set1_oldCert(client, old)
        || !OSSL_CMP_CTX_set1_subjectName(client, X509_get_subject_name(old))
        || !OSSL_CMP_CTX_set0_newPkey(client, 1, newkey)) goto end;
    newkey = NULL;
    if (!X509_STORE_add_cert(trust, state.ca_cert) || !OSSL_CMP_CTX_set0_trustedStore(client, trust)) goto end;
    trust = NULL;
    if (!OSSL_CMP_CTX_set_certConf_cb(client, OSSL_CMP_certConf_cb)
        || !OSSL_CMP_CTX_set_certConf_cb_arg(client, OSSL_CMP_CTX_get0_trustedStore(client))
        || !OSSL_CMP_CTX_set_option(client, OSSL_CMP_OPT_POPO_METHOD, OSSL_CRMF_POPO_KEYENC)
        || !OSSL_CMP_CTX_set_transfer_cb(client, boundary_transfer)
        || !OSSL_CMP_CTX_set_transfer_cb_arg(client, server)) goto end;
    issued = OSSL_CMP_exec_KUR_ses(client);
    failure = OSSL_CMP_CTX_get_failInfoCode(client);
    ok = expected ? issued != NULL && state.confirmation_accepted
                  : issued == NULL && !state.confirmation_accepted;
    if (other) ok = ok && state.pending == NULL && server_pin_rejected && failure != 0;
    if (wrong_ca) ok = ok && state.pending != NULL;
end:
    printf("{\"case\":\"%s\",\"passed\":%s,\"issued\":%s,\"confirmation_accepted\":%d,\"failure_info\":%d}\n",
        mode, ok ? "true" : "false", issued ? "true" : "false", state.confirmation_accepted, failure);
    X509_free(issued); X509_free(old); X509_free(pinned); X509_free(presented);
    X509_free(state.pending); X509_free(state.authorized_prior); X509_free(state.ca_cert);
    EVP_PKEY_free(state.ca_key); EVP_PKEY_free(presented_key); EVP_PKEY_free(newkey);
    OSSL_CMP_CTX_free(client); OSSL_CMP_SRV_CTX_free(server); X509_STORE_free(trust);
    X509_free(rogue_ca); EVP_PKEY_free(rogue_key); rogue_ca = NULL; rogue_key = NULL;
    remove("rogue.key");
    return ok;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "valid";
    const char *key = "new.key", *signkey = "sign.key", *pin = "sign.pem", *prior = "old.pem";
    const char *profile = "MLKEM768-MLDSA65-explicit-confirm-v1";
    const char *subject = "/CN=fictional-renewal";
    char *result;
    int actual, expected = strcmp(mode, "valid") == 0, ok;
    if (!passed(generate_mock_ca_root("ML-DSA-65", "/CN=fictional-ca", "ca.key", "ca.pem", 1))
        || !make_key("ML-KEM-768", "old.key") || !make_key("ML-KEM-768", "new.key")
        || !make_key("ML-DSA-65", "sign.key") || !make_key("ML-DSA-65", "other.key")
        || !signer_cert("sign.key", "sign.pem", strcmp(mode,"expired-signer") == 0,
            strcmp(mode,"wrong-usage") != 0)
        || !signer_cert("other.key", "other.pem", 0, 1)
        || !passed(execute_cmp_simulation("old.key", "/CN=fictional-renewal", "sample",
            "sample-secret", "ca.pem", "ca.key", "old.pem"))) return 2;
    if (strncmp(mode, "server-", 7) == 0) {
        ok = server_boundary(mode);
        remove("old.key"); remove("new.key"); remove("sign.key"); remove("other.key"); remove("ca.key");
        return ok ? 0 : 1;
    }
    if (strcmp(mode,"wrong-pin") == 0) pin = "other.pem";
    if (strcmp(mode,"wrong-signing-key") == 0) signkey = "other.key";
    if (strcmp(mode,"same-key") == 0) key = "old.key";
    if (strcmp(mode,"wrong-profile") == 0) profile = "unsupported-profile";
    if (strcmp(mode,"wrong-subject") == 0) subject = "/CN=unrelated-identity";
    if (strcmp(mode,"wrong-prior") == 0) {
        if (!passed(execute_cmp_simulation("old.key", "/CN=fictional-other", "sample",
            "sample-secret", "ca.pem", "ca.key", "other-old.pem"))) return 3;
        prior = "other-old.pem";
    }
    result = execute_cmp_key_update_v2(key, "old.pem", prior, "sign.pem", signkey, pin,
        subject, "ca.pem", "ca.key", "renewed.pem", profile);
    actual = result != NULL && strstr(result, "\"ok\":true") != NULL;
    ok = actual == expected;
    if (expected) ok = ok && strstr(result, "\"confirmationAccepted\":true") != NULL;
    else { BIO *output = BIO_new_file("renewed.pem", "r"); ok = ok && output == NULL; BIO_free(output); }
    if (!ok && result != NULL) fprintf(stderr, "%s\n", result);
    printf("{\"case\":\"%s\",\"passed\":%s,\"success\":%s}\n", mode, ok ? "true" : "false", actual ? "true" : "false");
    free(result);
    remove("old.key"); remove("new.key"); remove("sign.key"); remove("other.key"); remove("ca.key");
    return ok ? 0 : 1;
}
