/* SPDX-License-Identifier: AGPL-3.0-only */
#include "cmp_simulation.c"

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
