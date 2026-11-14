/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * cmp_simulation.c — In-process CMP client ↔ CMP server bridge.
 *
 * Mirrors the pattern in tls_simulation.c: both ends of a CMP exchange run in
 * the same WASM process, connected via OSSL_CMP_CTX_set_transfer_cb instead of
 * memory BIOs. The server is a real OSSL_CMP_SRV_CTX with a custom
 * process_cert_request callback that ACTUALLY ISSUES the certificate (parses
 * the CRMF cert template, builds an X509, signs it with the CA's ML-DSA-65
 * key) — NOT an echo of a pre-canned cert like OpenSSL's apps/lib/cmp_mock_srv.c.
 *
 * Exposed:
 *   static char *execute_cmp_operation(const char *ee_key_path,
 *                                const char *subject_dn,
 *                                const char *reference,
 *                                const char *secret,
 *                                const char *ca_cert_path,
 *                                const char *ca_key_path,
 *                                const char *out_cert_path);
 *
 * Returns a malloc'd JSON string: { "ok": bool, "transcript": [...], "error": "..." }.
 * Issued cert PEM is written to `out_cert_path` on the WASM FS; JS reads it back.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

/* ------------------------------------------------------------------------- *
 * Transcript / log buffer (resettable per call, JSON-safe)
 * ------------------------------------------------------------------------- */

#define LOG_CAP 16384
static char g_log[LOG_CAP];
static size_t g_log_used;

static void log_reset(void) {
    g_log[0] = '\0';
    g_log_used = 0;
}

static void log_json_escape_append(const char *s) {
    while (*s && g_log_used + 2 < LOG_CAP - 1) {
        unsigned char c = (unsigned char)*s++;
        if (c == '"' || c == '\\') {
            g_log[g_log_used++] = '\\';
            g_log[g_log_used++] = (char)c;
        } else if (c == '\n') {
            if (g_log_used + 2 < LOG_CAP - 1) {
                g_log[g_log_used++] = '\\';
                g_log[g_log_used++] = 'n';
            }
        } else if (c < 0x20) {
            char esc[8];
            int n = snprintf(esc, sizeof(esc), "\\u%04x", c);
            if (g_log_used + (size_t)n < LOG_CAP - 1) {
                memcpy(g_log + g_log_used, esc, (size_t)n);
                g_log_used += (size_t)n;
            }
        } else {
            g_log[g_log_used++] = (char)c;
        }
    }
    g_log[g_log_used] = '\0';
}

/* Append a single transcript entry. JSON array elements; caller manages commas. */
static int g_first_entry = 1;
static void log_event(const char *side, const char *event, const char *fmt, ...) {
    char detail[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);

    if (g_log_used + 64 + strlen(side) + strlen(event) + strlen(detail) >= LOG_CAP) return;
    if (!g_first_entry) {
        g_log[g_log_used++] = ',';
    }
    g_first_entry = 0;
    /* {"side":"...","event":"...","detail":"..."} */
    int n = snprintf(g_log + g_log_used, LOG_CAP - g_log_used,
                     "{\"side\":\"%s\",\"event\":\"%s\",\"detail\":\"", side, event);
    if (n < 0) return;
    g_log_used += (size_t)n;
    log_json_escape_append(detail);
    if (g_log_used + 3 < LOG_CAP) {
        g_log[g_log_used++] = '"';
        g_log[g_log_used++] = '}';
        g_log[g_log_used] = '\0';
    }
}

static void log_openssl_err(const char *where) {
    unsigned long e;
    char ebuf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, ebuf, sizeof(ebuf));
        log_event(where, "openssl_err", "%s", ebuf);
    }
}

/* ------------------------------------------------------------------------- *
 * PEM helpers
 * ------------------------------------------------------------------------- */

static X509 *load_x509_pem(const char *path) {
    BIO *b = BIO_new_file(path, "r");
    if (!b) return NULL;
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    return x;
}

static EVP_PKEY *load_pkey_pem(const char *path) {
    BIO *b = BIO_new_file(path, "r");
    if (!b) return NULL;
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    return k;
}

static int write_x509_pem(const char *path, X509 *cert) {
    BIO *b = BIO_new_file(path, "w");
    if (!b) return 0;
    int ok = PEM_write_bio_X509(b, cert);
    BIO_free(b);
    return ok;
}

/* ------------------------------------------------------------------------- *
 * Server-side: real issuance callback
 * ------------------------------------------------------------------------- */

typedef struct {
    X509 *ca_cert;
    EVP_PKEY *ca_key;
    X509 *authorized_prior;
    X509 *pending;
    int key_update;
    int confirmation_accepted;
} srv_state_t;

/*
 * process_cert_request — invoked by OSSL_CMP_SRV_process_request when the
 * server is handed an IR/CR/KUR. We extract the CertTemplate from the CRMF,
 * build a fresh X509 with the requested subject + pubkey, sign with the CA
 * key, and return it via *certOut. Returns NULL on success (status implied
 * "accepted"); a non-NULL OSSL_CMP_PKISI on rejection.
 */
static OSSL_CMP_PKISI *process_cert_request(OSSL_CMP_SRV_CTX *srv_ctx,
                                            const OSSL_CMP_MSG *cert_req,
                                            ossl_unused int certReqId,
                                            const OSSL_CRMF_MSG *crm,
                                            const X509_REQ *p10cr,
                                            X509 **certOut,
                                            STACK_OF(X509) **chainOut,
                                            STACK_OF(X509) **caPubs) {
    (void)cert_req;
    (void)p10cr;
    (void)chainOut;
    (void)caPubs;
    srv_state_t *st = (srv_state_t *)OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx);
    if (!st || !st->ca_cert || !st->ca_key) {
        log_event("server", "error", "missing CA materials");
        return NULL;
    }
    log_event("server", "cert_request_cb", "received CRMF, building cert from template");

    *certOut = NULL;
    X509 *new_cert = NULL;

    if (crm == NULL) {
        log_event("server", "error", "no CRMF in request");
        return NULL;
    }
    OSSL_CRMF_CERTTEMPLATE *tmpl = OSSL_CRMF_MSG_get0_tmpl(crm);
    if (!tmpl) {
        log_event("server", "error", "no cert template");
        return NULL;
    }

    X509_PUBKEY *req_pub = OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl);
    const X509_NAME *req_subj = OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl);
    if (!req_pub) {
        log_event("server", "error", "template has no publicKey");
        return NULL;
    }
    X509_NAME *subject = NULL;
    if (req_subj) {
        subject = X509_NAME_dup((X509_NAME *)req_subj);
        char sbuf[256];
        X509_NAME_oneline((X509_NAME *)req_subj, sbuf, sizeof(sbuf));
        log_event("server", "template_subject", "%s", sbuf);
    } else {
        subject = X509_NAME_new();
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
                                   (const unsigned char *)"Workshop EE (default)", -1, -1, 0);
        log_event("server", "template_subject", "(empty — using default CN=Workshop EE)");
    }

    new_cert = X509_new();
    if (!new_cert) {
        X509_NAME_free(subject);
        log_event("server", "error", "X509_new failed");
        log_openssl_err("server");
        return NULL;
    }

    unsigned char serial_bytes[8];
    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
        if (st->key_update) {
            X509_NAME_free(subject);
            X509_free(new_cert);
            log_event("server", "error", "certificate serial randomness unavailable");
            log_openssl_err("server");
            return NULL;
        }
        memset(serial_bytes, 0x42, sizeof(serial_bytes));
    }
    serial_bytes[0] &= 0x7f;
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    BIGNUM *bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
    BN_to_ASN1_INTEGER(bn, serial);
    BN_free(bn);
    X509_set_serialNumber(new_cert, serial);
    char serhex[20] = {0};
    for (int i = 0; i < 8; i++) snprintf(serhex + i * 2, 3, "%02x", serial_bytes[i]);
    log_event("server", "assigned_serial", "0x%s", serhex);
    ASN1_INTEGER_free(serial);

    X509_set_version(new_cert, 2);
    X509_set_issuer_name(new_cert, X509_get_subject_name(st->ca_cert));
    X509_set_subject_name(new_cert, subject);
    X509_NAME_free(subject);

    X509_gmtime_adj(X509_getm_notBefore(new_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(new_cert), 60L * 60L * 24L * 365L);

    EVP_PKEY *req_pkey = X509_PUBKEY_get0(req_pub);
    if (!req_pkey) {
        X509_free(new_cert);
        log_event("server", "error", "X509_PUBKEY_get0 failed");
        log_openssl_err("server");
        return NULL;
    }
    if (X509_set_pubkey(new_cert, req_pkey) != 1) {
        X509_free(new_cert);
        log_event("server", "error", "X509_set_pubkey failed");
        log_openssl_err("server");
        return NULL;
    }

    if (X509_sign(new_cert, st->ca_key, NULL) == 0) {
        X509_free(new_cert);
        log_event("server", "error", "X509_sign failed");
        log_openssl_err("server");
        return NULL;
    }
    log_event("server", "signed", "issued cert signed with CA ML-DSA-65 key");

    *certOut = new_cert;
    /* IMPORTANT: cmp_server.c:277-278 treats a NULL return from this callback
     * as failure and aborts the whole exchange (response goes out unprotected,
     * client errors with "missing protection"). For SUCCESS we must return a
     * non-NULL PKISI with status=accepted. */
    OSSL_CMP_PKISI *ok_si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_accepted, 0, NULL);
    if (!ok_si) {
        log_event("server", "error", "OSSL_CMP_STATUSINFO_new(accepted) failed");
        log_openssl_err("server");
    }
    return ok_si;
}

/* The fictional request identity is authorized for this separately supplied prior
 * certificate. A request cannot authorize itself by naming an issuer/serial.
 */
static OSSL_CMP_PKISI *process_key_update_request(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req, int id, const OSSL_CRMF_MSG *crm,
    const X509_REQ *p10, X509 **out, STACK_OF(X509) **chain,
    STACK_OF(X509) **pubs) {
    srv_state_t *st = OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx);
    OSSL_CRMF_CERTID *prior = crm == NULL ? NULL : OSSL_CRMF_MSG_get0_regCtrl_oldCertID(crm);
    OSSL_CRMF_CERTTEMPLATE *tmpl = crm == NULL ? NULL : OSSL_CRMF_MSG_get0_tmpl(crm);
    OSSL_CMP_PKISI *status;

    if (st == NULL || st->authorized_prior == NULL || prior == NULL || tmpl == NULL
        || OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl) == NULL
        || X509_NAME_cmp(OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl),
               X509_get_subject_name(st->authorized_prior)) != 0
        || OSSL_CMP_MSG_get_bodytype(req) != OSSL_CMP_KUR
        || X509_NAME_cmp(OSSL_CRMF_CERTID_get0_issuer(prior),
               X509_get_issuer_name(st->authorized_prior)) != 0
        || ASN1_INTEGER_cmp(OSSL_CRMF_CERTID_get0_serialNumber(prior),
               X509_get0_serialNumber(st->authorized_prior)) != 0) {
        log_event("server", "rejected", "prior certificate is not authorized for the sample identity");
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
            1 << OSSL_CMP_PKIFAILUREINFO_badCertId, "unauthorized prior certificate");
    }
    status = process_cert_request(srv_ctx, req, id, crm, p10, out, chain, pubs);
    if (status != NULL && *out != NULL) {
        if (!X509_up_ref(*out)) {
            OSSL_CMP_PKISI_free(status);
            return NULL;
        }
        X509_free(st->pending);
        st->pending = *out;
        log_event("server", "proof_pending", "issued certificate will be encrypted; possession is not yet established");
    }
    return status;
}

static int process_key_update_confirmation(OSSL_CMP_SRV_CTX *srv_ctx,
    const OSSL_CMP_MSG *req, int id, const ASN1_OCTET_STRING *hash,
    const OSSL_CMP_PKISI *status) {
    srv_state_t *st = OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx);
    ASN1_OCTET_STRING *expected = NULL;
    EVP_MD *digest = NULL;
    int fallback = 0, ok;
    (void)req;
    (void)status; /* The opt-in core path rejects explicit non-accepted status. */

    if (st == NULL || st->pending == NULL || st->confirmation_accepted
        || id != 0 || hash == NULL) {
        log_event("server", "confirmation_rejected", "missing, repeated or rejected certificate confirmation");
        return 0;
    }
    expected = X509_digest_sig(st->pending, &digest, &fallback);
    ok = expected != NULL && ASN1_OCTET_STRING_cmp(expected, hash) == 0;
    ASN1_OCTET_STRING_free(expected);
    EVP_MD_free(digest);
    if (!ok) {
        log_event("server", "confirmation_rejected", "certificate hash did not match the pending issued certificate");
        return 0;
    }
    st->confirmation_accepted = 1;
    log_event("server", "confirmation_accepted", "explicit certificate hash matches; new-key possession established for this sample");
    return 1;
}

/* ------------------------------------------------------------------------- *
 * In-process transfer callback (client → server, no sockets)
 * ------------------------------------------------------------------------- */

static OSSL_CMP_MSG *transfer_cb(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req) {
    OSSL_CMP_SRV_CTX *srv_ctx = (OSSL_CMP_SRV_CTX *)OSSL_CMP_CTX_get_transfer_cb_arg(ctx);
    if (!srv_ctx) return NULL;
    log_event("client", "send", "transmitting PKIMessage to server (in-process)");
    OSSL_CMP_MSG *resp = OSSL_CMP_SRV_process_request(srv_ctx, req);
    log_event("client", "recv", resp ? "received PKIMessage response" : "no response from server");
    return resp;
}

/* ------------------------------------------------------------------------- *
 * Public: generate ML-DSA-65 self-signed CA root (bypasses CLI req -x509,
 * which breaks on ML-DSA because apps/req.c defaults to SHA256 hash-then-sign
 * and ML-DSA refuses non-NULL md). Writes key + cert PEMs to the given paths.
 * Returns malloc'd JSON: { "ok": bool, "error": "..." }.
 * ------------------------------------------------------------------------- */

char *generate_mock_ca_root(const char *alg_name,
                            const char *subject_dn,
                            const char *key_out_path,
                            const char *cert_out_path,
                            int days) {
    int ok = 0;
    const char *err = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    BIO *kbio = NULL, *cbio = NULL;

    /* 1. Keygen via EVP API (no MD parameter, ML-DSA-friendly). */
    pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg_name);
    if (!pkey) { err = "EVP_PKEY_Q_keygen failed"; goto done; }

    /* 2. Write private key as PEM. */
    kbio = BIO_new_file(key_out_path, "w");
    if (!kbio) { err = "open key file failed"; goto done; }
    if (PEM_write_bio_PrivateKey(kbio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        err = "PEM_write_bio_PrivateKey failed"; goto done;
    }

    /* 3. Build a self-signed v3 cert. */
    cert = X509_new();
    if (!cert) { err = "X509_new failed"; goto done; }
    X509_set_version(cert, 2);

    ASN1_INTEGER *sn = ASN1_INTEGER_new();
    ASN1_INTEGER_set(sn, 1);
    X509_set_serialNumber(cert, sn);
    ASN1_INTEGER_free(sn);

    name = X509_NAME_new();
    const char *p = subject_dn;
    if (*p == '/') p++;
    while (*p) {
        const char *eq = strchr(p, '=');
        if (!eq) break;
        char attr[64]; size_t alen = (size_t)(eq - p);
        if (alen >= sizeof(attr)) alen = sizeof(attr) - 1;
        memcpy(attr, p, alen); attr[alen] = '\0';
        const char *vs = eq + 1; const char *ve = strchr(vs, '/');
        size_t vl = ve ? (size_t)(ve - vs) : strlen(vs);
        char val[256]; if (vl >= sizeof(val)) vl = sizeof(val) - 1;
        memcpy(val, vs, vl); val[vl] = '\0';
        X509_NAME_add_entry_by_txt(name, attr, MBSTRING_UTF8,
                                   (const unsigned char *)val, -1, -1, 0);
        if (!ve) break;
        p = ve + 1;
    }
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);

    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * (long)days);

    X509_set_pubkey(cert, pkey);

    /* CA basic constraints + keyUsage for a proper CA root. */
    {
        BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
        bc->ca = 1;
        X509_EXTENSION *ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
        BASIC_CONSTRAINTS_free(bc);

        ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
        /* The fictional CMP CA also signs protocol response messages. */
        ASN1_BIT_STRING_set_bit(ku, 0, 1); /* digitalSignature */
        ASN1_BIT_STRING_set_bit(ku, 5, 1);
        ASN1_BIT_STRING_set_bit(ku, 6, 1);
        ext = X509V3_EXT_i2d(NID_key_usage, 1, ku);
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
        ASN1_BIT_STRING_free(ku);
    }

    /* 4. Self-sign with NULL md — ML-DSA wants no hash. */
    if (X509_sign(cert, pkey, NULL) == 0) {
        err = "X509_sign (self) failed"; goto done;
    }

    /* 5. Write cert PEM. */
    cbio = BIO_new_file(cert_out_path, "w");
    if (!cbio) { err = "open cert file failed"; goto done; }
    if (PEM_write_bio_X509(cbio, cert) != 1) {
        err = "PEM_write_bio_X509 failed"; goto done;
    }

    ok = 1;
done:
    if (kbio) BIO_free(kbio);
    if (cbio) BIO_free(cbio);
    if (name) X509_NAME_free(name);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);

    char *out = (char *)malloc(256);
    if (!out) return NULL;
    if (ok) snprintf(out, 256, "{\"ok\":true}");
    else    snprintf(out, 256, "{\"ok\":false,\"error\":\"%s\"}", err ? err : "unknown");
    return out;
}

/* ------------------------------------------------------------------------- *
 * Public entry point
 * ------------------------------------------------------------------------- */

static char *execute_cmp_operation(const char *ee_key_path,
                             const char *subject_dn,
                             const char *reference,
                             const char *secret,
                             const char *ca_cert_path,
                             const char *ca_key_path,
                             const char *out_cert_path,
                             const char *old_cert_path,
                             const char *authorized_prior_path,
                             int key_update,
                             const char *signer_cert_path,
                             const char *signer_key_path,
                             const char *authorized_signer_path) {
    log_reset();
    g_first_entry = 1;

    int ok = 0;
    const char *err_short = NULL;
    X509 *ca_cert = NULL;
    EVP_PKEY *ca_key = NULL;
    EVP_PKEY *ee_key = NULL;
    X509_NAME *subj = NULL;
    X509_STORE *trust = NULL;
    OSSL_CMP_CTX *cctx = NULL;
    OSSL_CMP_SRV_CTX *sctx = NULL;
    X509 *issued = NULL;
    X509 *old_cert = NULL;
    X509 *signer_cert = NULL, *authorized_signer = NULL;
    EVP_PKEY *signer_key = NULL;
    srv_state_t srv_state = {0};

    log_event("client", "start", key_update ? "in-process CMP KUR with encrypted certificate and explicit confirmation" : "in-process CMP IR simulation");
    srv_state.key_update = key_update;
    if (key_update) {
        remove(out_cert_path);
        old_cert = load_x509_pem(old_cert_path);
        srv_state.authorized_prior = load_x509_pem(authorized_prior_path);
        if (old_cert == NULL || srv_state.authorized_prior == NULL) {
            err_short = "load prior certificate or server authorization failed";
            goto done;
        }
    }

    ca_cert = load_x509_pem(ca_cert_path);
    if (!ca_cert) {
        err_short = "load CA cert failed";
        log_event("client", "error", "load CA cert %s", ca_cert_path);
        log_openssl_err("client");
        goto done;
    }
    ca_key = load_pkey_pem(ca_key_path);
    if (!ca_key) {
        err_short = "load CA key failed";
        log_event("client", "error", "load CA key %s", ca_key_path);
        log_openssl_err("client");
        goto done;
    }
    if (key_update == 2) {
        signer_cert = load_x509_pem(signer_cert_path);
        signer_key = load_pkey_pem(signer_key_path);
        authorized_signer = load_x509_pem(authorized_signer_path);
        if (signer_cert == NULL || signer_key == NULL || authorized_signer == NULL
            || X509_cmp(signer_cert, authorized_signer) != 0
            || !EVP_PKEY_is_a(signer_key, "ML-DSA-65")
            || X509_check_private_key(signer_cert, signer_key) != 1
            || X509_check_issued(ca_cert, signer_cert) != X509_V_OK
            || X509_verify(signer_cert, X509_get0_pubkey(ca_cert)) != 1
            || X509_cmp_time(X509_get0_notBefore(signer_cert), NULL) >= 0
            || X509_cmp_time(X509_get0_notAfter(signer_cert), NULL) <= 0
            || X509_get_ext_by_NID(signer_cert, NID_key_usage, -1) < 0
            || (X509_get_key_usage(signer_cert) & KU_DIGITAL_SIGNATURE) == 0) {
            err_short = "renewal signer must match the authorized, valid ML-DSA-65 signing certificate and key";
            goto done;
        }
    }
    ee_key = load_pkey_pem(ee_key_path);
    if (!ee_key) {
        err_short = "load EE key failed";
        log_event("client", "error", "load EE key %s", ee_key_path);
        log_openssl_err("client");
        goto done;
    }
    log_event("client", "loaded", "EE key + mock CA materials");

    sctx = OSSL_CMP_SRV_CTX_new(NULL, NULL);
    if (!sctx) {
        err_short = "OSSL_CMP_SRV_CTX_new failed";
        log_event("server", "error", "OSSL_CMP_SRV_CTX_new");
        log_openssl_err("server");
        goto done;
    }
    srv_state.ca_cert = ca_cert;
    srv_state.ca_key = ca_key;
    if (OSSL_CMP_SRV_CTX_init(sctx, &srv_state,
                              key_update ? process_key_update_request : process_cert_request,
                              NULL, NULL, NULL,
                              key_update ? process_key_update_confirmation : NULL, NULL) != 1) {
        err_short = "OSSL_CMP_SRV_CTX_init failed";
        log_event("server", "error", "OSSL_CMP_SRV_CTX_init");
        log_openssl_err("server");
        goto done;
    }
    OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(sctx, !key_update);
    if (key_update && !OSSL_CMP_SRV_CTX_set_accept_encrcert_popo(sctx, 1)) {
        err_short = "enable encrypted-certificate proof failed";
        goto done;
    }
    OSSL_CMP_SRV_CTX_set_send_unprotected_errors(sctx, 1);
    /* Accept RAVERIFIED POP — required for ML-KEM (and other non-signing key)
     * enrollment, where the client cannot sign the CRMF as proof-of-possession.
     * In production this requires an out-of-band trust path (e.g. an RA that
     * vetted the request); for this workshop the in-process server is the RA. */
    OSSL_CMP_SRV_CTX_set_accept_raverified(sctx, !key_update);
    {
        OSSL_CMP_CTX *srv_inner = OSSL_CMP_SRV_CTX_get0_cmp_ctx(sctx);
        if (srv_inner && key_update == 2) {
            if (!OSSL_CMP_CTX_set1_cert(srv_inner, ca_cert)
                || !OSSL_CMP_CTX_set1_pkey(srv_inner, ca_key)
                || !OSSL_CMP_CTX_set1_srvCert(srv_inner, authorized_signer)) {
                err_short = "configure signed renewal server failed";
                goto done;
            }
        } else if (srv_inner) {
            /* PBM-MAC only. Setting cert+pkey here would make libcrypto prefer
             * signature-based protection — that path tries to sign the IP
             * header with ML-DSA via EVP_DigestSign + a default md, ML-DSA
             * refuses, the response goes out unprotected, the client rejects
             * with "missing protection". So: just the shared secret here. */
            OSSL_CMP_CTX_set1_secretValue(srv_inner,
                                          (const unsigned char *)secret, (int)strlen(secret));
            OSSL_CMP_CTX_set1_referenceValue(srv_inner,
                                             (const unsigned char *)reference, (int)strlen(reference));
            /* When the server builds a response header, ossl_cmp_hdr_init picks
             * the sender DN from ctx->cert → ctx->oldCert → ctx->p10CSR →
             * ctx->subjectName (cmp_hdr.c:282-284). Since we deliberately left
             * cert/oldCert/p10CSR NULL, we set subjectName to the CA's subject
             * so the response sender matches what the client (which has srvCert
             * set) expects — otherwise the client rejects with
             * "unexpected sender". */
            OSSL_CMP_CTX_set1_subjectName(srv_inner, X509_get_subject_name(ca_cert));
        }
    }
    log_event("server", "configured", key_update == 2
        ? "separate renewal signer pinned; CA signs responses; explicit certificate confirmation required"
        : "PBM-MAC secret wired, sender DN aligned to CA subject, cert_request_cb installed");

    cctx = OSSL_CMP_CTX_new(NULL, NULL);
    if (!cctx) {
        err_short = "OSSL_CMP_CTX_new failed";
        log_event("client", "error", "OSSL_CMP_CTX_new");
        log_openssl_err("client");
        goto done;
    }
    /* Set srvCert: gives the client (a) a trust anchor for response validation
     * and (b) a recipient DN for outgoing requests. The server is configured
     * to use the same CA-cert subject as its sender (see srv_inner subjectName
     * below) so the sender check passes. */
    OSSL_CMP_CTX_set1_srvCert(cctx, ca_cert);
    if (key_update == 2) {
        if (!OSSL_CMP_CTX_set1_cert(cctx, signer_cert)
            || !OSSL_CMP_CTX_set1_pkey(cctx, signer_key)) {
            err_short = "configure separate renewal signer failed";
            goto done;
        }
    } else {
        OSSL_CMP_CTX_set1_secretValue(cctx, (const unsigned char *)secret, (int)strlen(secret));
        OSSL_CMP_CTX_set1_referenceValue(cctx, (const unsigned char *)reference, (int)strlen(reference));
    }

    subj = X509_NAME_new();
    {
        const char *p = subject_dn;
        if (*p == '/') p++;
        while (*p) {
            const char *eq = strchr(p, '=');
            if (!eq) break;
            char attr[64];
            size_t alen = (size_t)(eq - p);
            if (alen >= sizeof(attr)) alen = sizeof(attr) - 1;
            memcpy(attr, p, alen);
            attr[alen] = '\0';
            const char *vstart = eq + 1;
            const char *vend = strchr(vstart, '/');
            size_t vlen = vend ? (size_t)(vend - vstart) : strlen(vstart);
            char val[256];
            if (vlen >= sizeof(val)) vlen = sizeof(val) - 1;
            memcpy(val, vstart, vlen);
            val[vlen] = '\0';
            X509_NAME_add_entry_by_txt(subj, attr, MBSTRING_UTF8,
                                       (const unsigned char *)val, -1, -1, 0);
            if (!vend) break;
            p = vend + 1;
        }
    }
    OSSL_CMP_CTX_set1_subjectName(cctx, subj);

    if (key_update) {
        EVP_PKEY *prior_key = X509_get0_pubkey(old_cert);
        if (!EVP_PKEY_is_a(ee_key, "ML-KEM-768") || prior_key == NULL
            || EVP_PKEY_eq(ee_key, prior_key) != 0
            || X509_check_issued(ca_cert, srv_state.authorized_prior) != X509_V_OK
            || X509_verify(srv_state.authorized_prior, X509_get0_pubkey(ca_cert)) != 1
            || !OSSL_CMP_CTX_set1_oldCert(cctx, old_cert)
            || !OSSL_CMP_CTX_set_option(cctx, OSSL_CMP_OPT_POPO_METHOD, OSSL_CRMF_POPO_KEYENC)) {
            err_short = "key update requires a fresh ML-KEM-768 key and valid authorized prior certificate";
            goto done;
        }
        log_event("client", "popo", "keyEncipherment subsequentMessage=encrCert selected; explicit confirmation required");
    } else {
    /* Detect whether the EE key can sign. ML-KEM (and any other pure KEM) has
     * no signing capability, so the OSSL_CRMF_POPO_SIGNATURE default would
     * fail at request-build time. For non-signing keys, accept the cert via
     * raVerified — the server's accept_raverified flag below tells it to
     * trust the request without verifying POP. (For real production CMP with
     * KEM keys, the right choice is encrCert POP per RFC 9810; we exercise
     * that round trip separately in the workshop's "encap/decap" panel.) */
    {
        int can_sign = 0;
        if (EVP_PKEY_is_a(ee_key, "ML-KEM-512")
            || EVP_PKEY_is_a(ee_key, "ML-KEM-768")
            || EVP_PKEY_is_a(ee_key, "ML-KEM-1024")
            || EVP_PKEY_is_a(ee_key, "X25519")
            || EVP_PKEY_is_a(ee_key, "X448")) {
            can_sign = 0;
        } else {
            can_sign = 1;
        }
        if (can_sign) {
            OSSL_CMP_CTX_set_option(cctx, OSSL_CMP_OPT_POPO_METHOD,
                                    OSSL_CRMF_POPO_SIGNATURE);
            log_event("client", "popo", "signature POP selected (signing key)");
        } else {
            OSSL_CMP_CTX_set_option(cctx, OSSL_CMP_OPT_POPO_METHOD,
                                    OSSL_CRMF_POPO_RAVERIFIED);
            /* Server must accept RAVERIFIED — set below before exec_IR_ses. */
            log_event("client", "popo", "raVerified POP selected (KEM key, can't sign)");
        }
    }

    }

    OSSL_CMP_CTX_set0_newPkey(cctx, 1, ee_key);
    ee_key = NULL;

    trust = X509_STORE_new();
    X509_STORE_add_cert(trust, ca_cert);
    OSSL_CMP_CTX_set0_trustedStore(cctx, trust);
    trust = NULL;

    OSSL_CMP_CTX_set_transfer_cb(cctx, transfer_cb);
    OSSL_CMP_CTX_set_transfer_cb_arg(cctx, sctx);

    /* Ask the server to grant IMPLICIT_CONFIRM in the IR, so the exchange ends
     * after the IP and we don't follow up with certConf / pkiconf. The server
     * is already configured with OSSL_CMP_SRV_CTX_set_grant_implicit_confirm,
     * but it only grants when the CLIENT request header asks for it
     * (cmp_server.c:282-288). Without this we'd need a process_certConf
     * callback on the server too — easier to just skip the round trip. */
    OSSL_CMP_CTX_set_option(cctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM, !key_update);
    log_event("client", "configured", key_update ? "CTX ready; implicit confirmation disabled" : "CTX ready; implicit confirmation requested");

    log_event("client", key_update ? "kur_send" : "ir_send",
        key_update ? "calling OSSL_CMP_exec_KUR_ses" : "calling OSSL_CMP_exec_IR_ses");
    issued = key_update ? OSSL_CMP_exec_KUR_ses(cctx) : OSSL_CMP_exec_IR_ses(cctx);
    if (!issued) {
        int s = OSSL_CMP_CTX_get_status(cctx);
        err_short = key_update ? "CMP key update failed" : "OSSL_CMP_exec_IR_ses returned NULL";
        log_event("client", "error", key_update ? "exec_KUR_ses NULL, status=%d" : "exec_IR_ses NULL, status=%d", s);
        log_openssl_err("client");
        goto done;
    }
    if (key_update && !srv_state.confirmation_accepted) {
        err_short = "server did not accept explicit certificate confirmation";
        goto done;
    }
    log_event("client", "validated", key_update ? "encrypted KUP recovered and validated; certConf accepted and PKIConfirm received" : "IP response validated against trust store");

    if (!write_x509_pem(out_cert_path, issued)) {
        err_short = "write issued cert failed";
        log_event("client", "error", "write cert to %s", out_cert_path);
        log_openssl_err("client");
        goto done;
    }
    log_event("client", "wrote_cert", "issued cert PEM at %s", out_cert_path);
    ok = 1;

done:
    if (key_update && !ok) remove(out_cert_path);
    X509_free(signer_cert);
    X509_free(authorized_signer);
    EVP_PKEY_free(signer_key);
    X509_free(old_cert);
    X509_free(srv_state.authorized_prior);
    X509_free(srv_state.pending);
    if (issued) X509_free(issued);
    if (cctx) OSSL_CMP_CTX_free(cctx);
    if (sctx) OSSL_CMP_SRV_CTX_free(sctx);
    if (subj) X509_NAME_free(subj);
    if (trust) X509_STORE_free(trust);
    if (ee_key) EVP_PKEY_free(ee_key);
    if (ca_key) EVP_PKEY_free(ca_key);
    if (ca_cert) X509_free(ca_cert);

    /* Build final JSON: { "ok": bool, "error": "...", "transcript": [...], "certPath": "..." } */
    size_t needed = strlen(g_log) + strlen(out_cert_path) + 512;
    char *out = (char *)malloc(needed);
    if (!out) return NULL;
    if (key_update && ok) {
        snprintf(out, needed,
            "{\"ok\":true,\"operation\":\"KUR\",\"proofVerified\":true,\"confirmationAccepted\":true,\"certPath\":\"%s\",\"transcript\":[%s]}",
            out_cert_path, g_log);
    } else if (ok) {
        snprintf(out, needed,
                 "{\"ok\":true,\"certPath\":\"%s\",\"transcript\":[%s]}",
                 out_cert_path, g_log);
    } else {
        snprintf(out, needed,
                 "{\"ok\":false,\"error\":\"%s\",\"transcript\":[%s]}",
                 err_short ? err_short : "unknown", g_log);
    }
    return out;
}

/* Keep the original initial-enrollment ABI and behavior. */
char *execute_cmp_simulation(const char *ee_key_path, const char *subject_dn,
    const char *reference, const char *secret, const char *ca_cert_path,
    const char *ca_key_path, const char *out_cert_path) {
    return execute_cmp_operation(ee_key_path, subject_dn, reference, secret,
        ca_cert_path, ca_key_path, out_cert_path, NULL, NULL, 0, NULL, NULL, NULL);
}

char *execute_cmp_key_update(const char *ee_key_path, const char *old_cert_path,
    const char *authorized_prior_path, const char *subject_dn,
    const char *reference, const char *secret, const char *ca_cert_path,
    const char *ca_key_path, const char *out_cert_path) {
    if (ee_key_path == NULL || old_cert_path == NULL || authorized_prior_path == NULL
        || subject_dn == NULL || reference == NULL || secret == NULL
        || ca_cert_path == NULL || ca_key_path == NULL || out_cert_path == NULL
        || strchr(out_cert_path, '"') != NULL || strchr(out_cert_path, '\\') != NULL) {
        const char *error = "{\"ok\":false,\"error\":\"invalid key-update arguments\"}";
        char *result = malloc(strlen(error) + 1);
        if (result != NULL) strcpy(result, error);
        return result;
    }
    return execute_cmp_operation(ee_key_path, subject_dn, reference, secret,
        ca_cert_path, ca_key_path, out_cert_path, old_cert_path, authorized_prior_path, 1,
        NULL, NULL, NULL);
}

/* Additive signed-renewal contract. The legacy exports retain their meaning. */
char *execute_cmp_key_update_v2(const char *ee_key_path, const char *old_cert_path,
    const char *authorized_prior_path, const char *signer_cert_path,
    const char *signer_key_path, const char *authorized_signer_path,
    const char *subject_dn, const char *ca_cert_path, const char *ca_key_path,
    const char *out_cert_path, const char *profile) {
    if (ee_key_path == NULL || old_cert_path == NULL || authorized_prior_path == NULL
        || signer_cert_path == NULL || signer_key_path == NULL || authorized_signer_path == NULL
        || subject_dn == NULL || ca_cert_path == NULL || ca_key_path == NULL
        || out_cert_path == NULL || profile == NULL
        || strcmp(profile, "MLKEM768-MLDSA65-explicit-confirm-v1") != 0
        || strchr(out_cert_path, '"') != NULL || strchr(out_cert_path, '\\') != NULL) {
        const char *error = "{\"ok\":false,\"error\":\"invalid signed key-update arguments or profile\"}";
        char *result = malloc(strlen(error) + 1);
        if (result != NULL) strcpy(result, error);
        return result;
    }
    return execute_cmp_operation(ee_key_path, subject_dn, NULL, NULL,
        ca_cert_path, ca_key_path, out_cert_path, old_cert_path, authorized_prior_path, 2,
        signer_cert_path, signer_key_path, authorized_signer_path);
}
