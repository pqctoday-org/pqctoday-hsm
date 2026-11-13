/* SPDX-License-Identifier: AGPL-3.0-only */
/* Acceptance harness: fictional keys; actual CMP server/client. */
#include "crypto/cmp/cmp_local.h"
#include "cmp_simulation.c"

typedef struct {
    srv_state_t base;
    X509 *authorized, *pending;
    int confirmed, request_seen, reply_seen, conf_seen, final_seen;
    const char *fault;
    OSSL_CMP_SRV_CTX *server;
    OSSL_CMP_MSG *saved_confirmation;
} test_state;

static OSSL_CMP_PKISI *issue_update(OSSL_CMP_SRV_CTX *server,
    const OSSL_CMP_MSG *req, int id, const OSSL_CRMF_MSG *crm,
    const X509_REQ *p10, X509 **out, STACK_OF(X509) **chain,
    STACK_OF(X509) **pubs)
{
    test_state *s = OSSL_CMP_SRV_CTX_get0_custom_ctx(server);
    OSSL_CRMF_CERTID *old = crm == NULL ? NULL : OSSL_CRMF_MSG_get0_regCtrl_oldCertID(crm);
    OSSL_CMP_PKISI *result;
    if (old == NULL || s->authorized == NULL
        || X509_NAME_cmp(OSSL_CRMF_CERTID_get0_issuer(old), X509_get_issuer_name(s->authorized)) != 0
        || ASN1_INTEGER_cmp(OSSL_CRMF_CERTID_get0_serialNumber(old), X509_get0_serialNumber(s->authorized)) != 0)
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
            1 << OSSL_CMP_PKIFAILUREINFO_badCertId, "unknown prior certificate");
    result = process_cert_request(server, req, id, crm, p10, out, chain, pubs);
    if (*out != NULL && X509_up_ref(*out)) s->pending = *out;
    return result;
}
static int confirm_update(OSSL_CMP_SRV_CTX *server, const OSSL_CMP_MSG *req,
    int id, const ASN1_OCTET_STRING *hash, const OSSL_CMP_PKISI *status)
{
    test_state *s = OSSL_CMP_SRV_CTX_get0_custom_ctx(server);
    ASN1_OCTET_STRING *expected;
    EVP_MD *md = NULL;
    int fallback = 0, ok;
    (void)req;
    if (id != OSSL_CMP_CERTREQID || s->pending == NULL || s->confirmed
        || (status != NULL && ossl_cmp_pkisi_get_status(status) != OSSL_CMP_PKISTATUS_accepted))
        return 0;
    expected = X509_digest_sig(s->pending, &md, &fallback);
    ok = expected != NULL && ASN1_OCTET_STRING_cmp(expected, hash) == 0;
    ASN1_OCTET_STRING_free(expected);
    EVP_MD_free(md);
    if (ok) s->confirmed = 1;
    return ok;
}
static OSSL_CMP_MSG *wire_copy(const OSSL_CMP_MSG *m, const char *file)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    OSSL_CMP_MSG *copy;
    int n = i2d_OSSL_CMP_MSG(m, &der);
    FILE *f;
    if (n <= 0) return NULL;
    if (file != NULL && (f = fopen(file, "wb")) != NULL) {
        fwrite(der, 1, n, f); fclose(f);
    }
    p = der; copy = d2i_OSSL_CMP_MSG(NULL, &p, n);
    OPENSSL_free(der);
    return copy;
}
static OSSL_CMP_MSG *wire_transfer(OSSL_CMP_CTX *client, const OSSL_CMP_MSG *req)
{
    test_state *s = OSSL_CMP_CTX_get_transfer_cb_arg(client);
    OSSL_CMP_MSG *in, *out, *copy;
    int type = OSSL_CMP_MSG_get_bodytype(req);
    in = wire_copy(req, type == OSSL_CMP_PKIBODY_KUR ? "kur.der" : "certconf.der");
    if (in == NULL) return NULL;
    if (type == OSSL_CMP_PKIBODY_KUR) {
        s->request_seen++;
        if (strcmp(s->fault, "wrong-key") == 0)
            OSSL_CMP_CTX_set0_newPkey(client, 1, EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768"));
    }
    if (type == OSSL_CMP_PKIBODY_CERTCONF) {
        OSSL_CMP_CERTSTATUS *cs = sk_OSSL_CMP_CERTSTATUS_value(in->body->value.certConf, 0);
        s->conf_seen++;
        if (strcmp(s->fault, "missing-confirmation") == 0) { OSSL_CMP_MSG_free(in); return NULL; }
        if (strcmp(s->fault, "wrong-hash") == 0) cs->certHash->data[0] ^= 1;
        if (strcmp(s->fault, "rejected-confirmation") == 0) {
            OSSL_CMP_PKISI_free(cs->statusInfo);
            cs->statusInfo = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, 0, "rejected");
        }
        if (strcmp(s->fault, "wrong-request-id") == 0) ASN1_INTEGER_set(cs->certReqId, 99);
        if (strcmp(s->fault, "wrong-transaction") == 0) in->header->transactionID->data[0] ^= 1;
        if (strcmp(s->fault, "wrong-nonce") == 0) in->header->recipNonce->data[0] ^= 1;
        if (!ossl_cmp_msg_protect(client, in)) { OSSL_CMP_MSG_free(in); return NULL; }
        s->saved_confirmation = wire_copy(in, NULL);
    }
    out = OSSL_CMP_SRV_process_request(s->server, in);
    OSSL_CMP_MSG_free(in);
    if (out == NULL) return NULL;
    type = OSSL_CMP_MSG_get_bodytype(out);
    if (type == OSSL_CMP_PKIBODY_KUP) {
        OSSL_CMP_CERTRESPONSE *r = sk_OSSL_CMP_CERTRESPONSE_value(out->body->value.kup->response, 0);
        if (r->certifiedKeyPair != NULL) {
            if (r->certifiedKeyPair->certOrEncCert->type != OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT
                || ossl_cmp_asn1_get_int(out->header->pvno) != OSSL_CMP_PVNO_3
                || ossl_cmp_hdr_has_implicitConfirm(out->header)) {
                OSSL_CMP_MSG_free(out); return NULL;
            }
            s->reply_seen++;
        }
    }
    if (type == OSSL_CMP_PKIBODY_PKICONF) s->final_seen++;
    if (type == OSSL_CMP_PKIBODY_KUP && strcmp(s->fault, "altered-envelope") == 0) {
        unsigned char *bytes = NULL;
        const unsigned char *cursor;
        int n = i2d_OSSL_CMP_MSG(out, &bytes), hits = 0;
        OSSL_CMP_MSG *changed = NULL;
        for (int i = 0; i + 1092 <= n; i++) {
            if (bytes[i] == 4 && bytes[i+1] == 0x82 && bytes[i+2] == 4 && bytes[i+3] == 0x40) {
                bytes[i+4] ^= 1; hits++;
            }
        }
        cursor = bytes;
        if (hits == 1) changed = d2i_OSSL_CMP_MSG(NULL, &cursor, n);
        OPENSSL_free(bytes);
        OSSL_CMP_MSG_free(out);
        if (changed == NULL) return NULL;
        out = changed;
        if (!ossl_cmp_msg_protect(OSSL_CMP_SRV_CTX_get0_cmp_ctx(s->server), out)) {
            OSSL_CMP_MSG_free(out); return NULL;
        }
    }
    if (type == OSSL_CMP_PKIBODY_KUP && strcmp(s->fault, "truncated-envelope") == 0) {
        unsigned char *bytes = NULL;
        const unsigned char *cursor;
        int n = i2d_OSSL_CMP_MSG(out, &bytes);
        cursor = bytes;
        copy = n > 1 ? d2i_OSSL_CMP_MSG(NULL, &cursor, n - 1) : NULL;
        OPENSSL_free(bytes); OSSL_CMP_MSG_free(out);
        return copy;
    }
    copy = wire_copy(out, type == OSSL_CMP_PKIBODY_KUP ? "kup.der" : "pkiconf.der");
    OSSL_CMP_MSG_free(out);
    return copy;
}
static X509 *make_old(X509 *ca, EVP_PKEY *cakey, EVP_PKEY *key, long serial)
{
    X509 *cert = X509_new();
    X509_NAME *name = X509_NAME_new();
    if (cert == NULL || name == NULL) return NULL;
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"fictional-renewal", -1, -1, 0);
    X509_set_version(cert, 2); ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_set_subject_name(cert, name); X509_NAME_free(name);
    X509_set_issuer_name(cert, X509_get_subject_name(ca));
    X509_gmtime_adj(X509_getm_notBefore(cert), -60); X509_gmtime_adj(X509_getm_notAfter(cert), 86400);
    if (!X509_set_pubkey(cert, key) || !X509_sign(cert, cakey, NULL)) { X509_free(cert); return NULL; }
    return cert;
}
int main(int argc, char **argv)
{
    test_state s = {0};
    OSSL_CMP_CTX *client = NULL, *inner;
    EVP_PKEY *key = NULL, *oldkey = NULL;
    X509 *old = NULL, *issued = NULL;
    X509_STORE *trust = NULL;
    char *result;
    int success, expect, ok = 0;
    s.fault = argc > 1 ? argv[1] : "valid";
    result = generate_mock_ca_root("ML-DSA-65", "/CN=fictional-cmp-ca", "ca.key", "ca.pem", 1);
    if (result == NULL || strstr(result, "true") == NULL) goto end;
    free(result);
    s.base.ca_cert = load_x509_pem("ca.pem"); s.base.ca_key = load_pkey_pem("ca.key");
    key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    oldkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    if (key == NULL || oldkey == NULL || s.base.ca_cert == NULL || s.base.ca_key == NULL) goto end;
    old = make_old(s.base.ca_cert, s.base.ca_key, oldkey, 2);
    s.authorized = make_old(s.base.ca_cert, s.base.ca_key, oldkey, strcmp(s.fault, "wrong-old-certificate") == 0 ? 3 : 2);
    s.server = OSSL_CMP_SRV_CTX_new(NULL, NULL);
    if (old == NULL || s.authorized == NULL || s.server == NULL) goto end;
    if (!OSSL_CMP_SRV_CTX_init(s.server, &s, issue_update, NULL, NULL, NULL,
        strcmp(s.fault, "missing-callback") == 0 ? NULL : confirm_update, NULL)) goto end;
    if (strcmp(s.fault, "default-off") != 0 && !OSSL_CMP_SRV_CTX_set_accept_encrcert_popo(s.server, 1)) goto end;
    OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(s.server, 1);
    inner = OSSL_CMP_SRV_CTX_get0_cmp_ctx(s.server);
    if (!OSSL_CMP_CTX_set1_secretValue(inner, (unsigned char *)"fictional-secret", 16)
        || !OSSL_CMP_CTX_set1_referenceValue(inner, (unsigned char *)"fictional-client", 16)
        || !OSSL_CMP_CTX_set1_subjectName(inner, X509_get_subject_name(s.base.ca_cert))) goto end;
    client = OSSL_CMP_CTX_new(NULL, NULL);
    trust = X509_STORE_new();
    if (client == NULL || trust == NULL || !X509_STORE_add_cert(trust, s.base.ca_cert)) goto end;
    if (!OSSL_CMP_CTX_set0_trustedStore(client, trust)) goto end;
    trust = NULL;
    if (!OSSL_CMP_CTX_set1_srvCert(client, s.base.ca_cert)
        || !OSSL_CMP_CTX_set1_oldCert(client, old)
        || !OSSL_CMP_CTX_set1_subjectName(client, X509_get_subject_name(old))
        || !OSSL_CMP_CTX_set1_secretValue(client, (unsigned char *)"fictional-secret", 16)
        || !OSSL_CMP_CTX_set1_referenceValue(client, (unsigned char *)"fictional-client", 16)
        || !OSSL_CMP_CTX_set0_newPkey(client, 1, key)) goto end;
    key = NULL;
    if (!OSSL_CMP_CTX_set_option(client, OSSL_CMP_OPT_POPO_METHOD, OSSL_CRMF_POPO_KEYENC)
        || !OSSL_CMP_CTX_set_option(client, OSSL_CMP_OPT_IMPLICIT_CONFIRM, 1)
        || !OSSL_CMP_CTX_set_transfer_cb(client, wire_transfer)
        || !OSSL_CMP_CTX_set_transfer_cb_arg(client, &s)) goto end;
    issued = OSSL_CMP_exec_KUR_ses(client);
    success = issued != NULL && s.confirmed && s.final_seen == 1;
    expect = strcmp(s.fault, "valid") == 0;
    ok = expect ? success && s.request_seen == 1 && s.reply_seen == 1 && s.conf_seen == 1 : !success && !s.confirmed && s.final_seen == 0;
    if (strcmp(s.fault,"wrong-key") == 0 || strcmp(s.fault,"altered-envelope") == 0 || strcmp(s.fault,"truncated-envelope") == 0)
        ok = ok && s.reply_seen == 1 && s.conf_seen == 0;
    if (strcmp(s.fault,"wrong-hash") == 0 || strcmp(s.fault,"wrong-request-id") == 0
        || strcmp(s.fault,"wrong-transaction") == 0 || strcmp(s.fault,"wrong-nonce") == 0
        || strcmp(s.fault,"missing-confirmation") == 0 || strcmp(s.fault,"rejected-confirmation") == 0)
        ok = ok && s.reply_seen == 1 && s.conf_seen == 1;
    if (strcmp(s.fault,"default-off") == 0 || strcmp(s.fault,"missing-callback") == 0 || strcmp(s.fault,"wrong-old-certificate") == 0)
        ok = ok && s.reply_seen == 0 && s.conf_seen == 0;
    if (expect && ok && s.saved_confirmation != NULL) {
        OSSL_CMP_MSG *replay = OSSL_CMP_SRV_process_request(s.server, s.saved_confirmation);
        if (replay != NULL && OSSL_CMP_MSG_get_bodytype(replay) == OSSL_CMP_PKIBODY_PKICONF) ok = 0;
        OSSL_CMP_MSG_free(replay);
    }
    printf("{\"case\":\"%s\",\"passed\":%s,\"issued\":%s,\"confirmation_accepted\":%d,\"kur\":%d,\"encrypted_kup\":%d,\"certconf\":%d,\"pkiconf\":%d}\n",
        s.fault, ok ? "true" : "false", issued ? "true" : "false", s.confirmed, s.request_seen, s.reply_seen, s.conf_seen, s.final_seen);
end:
    if (!ok) ERR_print_errors_fp(stderr);
    OSSL_CMP_MSG_free(s.saved_confirmation); X509_free(issued); X509_free(s.pending);
    OSSL_CMP_CTX_free(client); OSSL_CMP_SRV_CTX_free(s.server); X509_STORE_free(trust);
    X509_free(old); X509_free(s.authorized); X509_free(s.base.ca_cert);
    EVP_PKEY_free(s.base.ca_key); EVP_PKEY_free(key); EVP_PKEY_free(oldkey);
    remove("ca.key"); remove("ca.pem");
    return ok ? 0 : 1;
}
