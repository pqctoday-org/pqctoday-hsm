/* SPDX-License-Identifier: AGPL-3.0-only */
#include "cmp_simulation.c"
static int keyfile(const char *algorithm, const char *path) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, algorithm);
    BIO *bio = BIO_new_file(path, "w");
    int ok = key != NULL && bio != NULL && PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    BIO_free(bio); EVP_PKEY_free(key); return ok;
}
static int good(char *result) {
    int ok = result != NULL && strstr(result, "\"ok\":true") != NULL;
    if (!ok && result != NULL) fprintf(stderr, "%s\n", result);
    free(result); return ok;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "valid";
    const char *newpath = "new.key", *authorized = "old.pem";
    char *result;
    int ok, expected = strcmp(mode,"valid") == 0;
    if (!good(generate_mock_ca_root("ML-DSA-65", "/CN=fictional-ca", "ca.key", "ca.pem", 1))
        || !keyfile("ML-KEM-768", "old.key") || !keyfile("ML-KEM-768", "new.key")) return 2;
    if (!good(execute_cmp_simulation("old.key", "/CN=fictional-renewal", "sample", "sample-secret", "ca.pem", "ca.key", "old.pem"))) return 3;
    if (strcmp(mode,"ir-signature") == 0) {
        if (!keyfile("ED25519", "sign.key")) return 4;
        ok = good(execute_cmp_simulation("sign.key", "/CN=fictional-signing", "sample", "sample-secret", "ca.pem", "ca.key", "sign.pem"));
        printf("{\"case\":\"ir-signature\",\"passed\":%s}\n", ok ? "true" : "false"); return ok ? 0 : 1;
    }
    if (strcmp(mode,"wrong-prior") == 0) {
        if (!good(execute_cmp_simulation("old.key", "/CN=fictional-other", "sample", "sample-secret", "ca.pem", "ca.key", "other.pem"))) return 5;
        authorized = "other.pem";
    }
    if (strcmp(mode,"same-key") == 0) newpath = "old.key";
    if (strcmp(mode,"missing-key") == 0) newpath = "missing.key";
    if (strcmp(mode,"wrong-algorithm") == 0) {
        if (!keyfile("ML-DSA-65", "sign.key")) return 6;
        newpath = "sign.key";
    }
    result = execute_cmp_key_update(newpath, "old.pem", authorized, "/CN=fictional-renewal", "sample", "sample-secret", "ca.pem", "ca.key", "renewed.pem");
    ok = result != NULL && strstr(result, "\"ok\":true") != NULL;
    printf("%s\n", result == NULL ? "null" : result);
    if (expected) ok = ok && strstr(result,"\"confirmationAccepted\":true") != NULL && strstr(result,"\"operation\":\"KUR\"") != NULL;
    else ok = !ok && fopen("renewed.pem", "r") == NULL;
    free(result);
    printf("{\"case\":\"%s\",\"passed\":%s}\n", mode, ok ? "true" : "false");
    remove("old.key"); remove("new.key"); remove("ca.key"); remove("sign.key");
    return ok ? 0 : 1;
}
