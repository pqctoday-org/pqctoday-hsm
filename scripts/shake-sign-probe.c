/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* shake-sign-probe: remediation R38 (phase 8) test helper.
 *
 * Exists because BOTH standard CLI surfaces refuse to drive a SHAKE128/256
 * pre-hash signature, for reasons unrelated to this provider (confirmed
 * live before writing this probe, see the phase-8 plan's own R38 section):
 *   - `openssl dgst -shake128/-shake256 -sign` reaches this provider's
 *     digest_sign_init fine, but apps/dgst.c itself then hard-refuses with
 *     "Signing key cannot be specified for XOF" -- an application-level
 *     check, not a core EVP or provider one.
 *   - `openssl pkeyutl -sign -digest shake256` refuses even earlier with
 *     "-digest (prehash) is not supported with ML-DSA-65" -- pkeyutl's own
 *     algorithm allowlist for -digest doesn't know about ML-DSA at all.
 * Both are call-site restrictions in the openssl(1) app itself; the raw
 * EVP_DigestSign* API this probe drives directly has neither check, and
 * IS what T29/T30's own `dgst -sha256` cases exercise underneath their
 * CLI wrapper -- this probe reaches the identical provider code path
 * (p11prov_mldsa_digest_sign_init / p11prov_slhdsa_digest_sign_init),
 * just without the app-level gate in the way.
 *
 * Two operations:
 *   sign   propq key_uri digest msg_file sig_out_file
 *   verify propq key_uri digest msg_file sig_file
 * digest is "SHAKE128" or "SHAKE256". key_uri must be a bare pkcs11: URI
 * (sign needs the private key, verify the public key) -- same convention
 * composite-sig-probe.c already established.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/store.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

static EVP_PKEY *load_key(const char *uri, const char *propq)
{
    OSSL_STORE_CTX *store;
    EVP_PKEY *pkey = NULL;

    store = OSSL_STORE_open_ex(uri, NULL, propq, NULL, NULL, NULL, NULL, NULL);
    if (!store) {
        return NULL;
    }
    while (!OSSL_STORE_eof(store)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(store);
        if (!info) {
            break;
        }
        int type = OSSL_STORE_INFO_get_type(info);
        if (type == OSSL_STORE_INFO_PKEY) {
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
        } else if (type == OSSL_STORE_INFO_PUBKEY) {
            pkey = OSSL_STORE_INFO_get1_PUBKEY(info);
        }
        OSSL_STORE_INFO_free(info);
        if (pkey) {
            break;
        }
    }
    OSSL_STORE_close(store);
    return pkey;
}

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long sz;

    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc < 7) {
        fprintf(stderr,
               "usage: %s sign|verify propq key_uri digest msg_file "
               "sig_file\n",
               argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *propq = argv[2];
    const char *key_uri = argv[3];
    const char *digest = argv[4];
    const char *msg_file = argv[5];
    const char *sig_file = argv[6];

    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (!prov) {
        ERR_print_errors_fp(stderr);
        return 2;
    }

    EVP_PKEY *pkey = load_key(key_uri, propq);
    if (!pkey) {
        fprintf(stderr, "failed to load key %s\n", key_uri);
        ERR_print_errors_fp(stderr);
        return 2;
    }

    size_t msglen = 0;
    unsigned char *msg = read_file(msg_file, &msglen);
    if (!msg) {
        fprintf(stderr, "failed to read %s\n", msg_file);
        EVP_PKEY_free(pkey);
        return 2;
    }

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int rc = 0;

    if (strcmp(mode, "sign") == 0) {
        if (EVP_DigestSignInit_ex(mctx, &pctx, digest, NULL, propq, pkey,
                                  NULL)
            != 1) {
            fprintf(stderr, "EVP_DigestSignInit_ex failed\n");
            ERR_print_errors_fp(stderr);
            rc = 2;
            goto out;
        }
        size_t siglen = 0;
        if (EVP_DigestSign(mctx, NULL, &siglen, msg, msglen) != 1) {
            fprintf(stderr, "EVP_DigestSign (size query) failed\n");
            ERR_print_errors_fp(stderr);
            rc = 2;
            goto out;
        }
        unsigned char *sig = malloc(siglen);
        if (!sig
            || EVP_DigestSign(mctx, sig, &siglen, msg, msglen) != 1) {
            fprintf(stderr, "EVP_DigestSign failed\n");
            ERR_print_errors_fp(stderr);
            free(sig);
            rc = 2;
            goto out;
        }
        FILE *out = fopen(sig_file, "wb");
        if (!out || fwrite(sig, 1, siglen, out) != siglen) {
            fprintf(stderr, "failed to write %s\n", sig_file);
            rc = 2;
        }
        if (out) {
            fclose(out);
        }
        free(sig);
    } else if (strcmp(mode, "verify") == 0) {
        size_t siglen = 0;
        unsigned char *sig = read_file(sig_file, &siglen);
        if (!sig) {
            fprintf(stderr, "failed to read %s\n", sig_file);
            rc = 2;
            goto out;
        }
        if (EVP_DigestVerifyInit_ex(mctx, &pctx, digest, NULL, propq, pkey,
                                    NULL)
            != 1) {
            fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
            ERR_print_errors_fp(stderr);
            free(sig);
            rc = 2;
            goto out;
        }
        int r = EVP_DigestVerify(mctx, sig, siglen, msg, msglen);
        free(sig);
        if (r != 1) {
            fprintf(stderr, "VERIFY FAILED r=%d\n", r);
            rc = 1;
            goto out;
        }
        printf("VERIFY OK\n");
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        rc = 2;
    }

out:
    free(msg);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}
