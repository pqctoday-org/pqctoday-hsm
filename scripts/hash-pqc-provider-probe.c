/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* hash-pqc-provider-probe: remediation item 5 (2026-08-30) verification
 * helper. Exercises this provider's NEW "HASH-ML-DSA"/"HASH-SLH-DSA"
 * algorithms (sig/mldsa.c's p11prov_hash_mldsa_*, sig/slhdsa.c's
 * p11prov_hash_slhdsa_*) via the real EVP_SIGNATURE_fetch + one-shot
 * EVP_PKEY_sign/verify API -- these algorithms deliberately have no
 * DIGEST_SIGN_INIT/UPDATE/FINAL entry points (the underlying bare
 * CKM_HASH_ML_DSA/CKM_HASH_SLH_DSA mechanism is genuinely single-part
 * only), so `openssl pkeyutl`'s own digest-then-sign convenience paths
 * can't reach them; this probe calls the plain sign_init/sign +
 * OSSL_SIGNATURE_PARAM_DIGEST ctx-param convention directly, exactly the
 * calling contract these two algorithms are designed around (see
 * mldsa.c's own top-of-block comment for HASH-ML-DSA).
 *
 * Usage:
 *   sign   <family> propq key_uri digest phm-hex
 *   verify <family> propq key_uri digest phm-hex sig-hex
 * family is "HASH-ML-DSA" or "HASH-SLH-DSA". key_uri is a bare pkcs11:
 * URI (sign needs the private key, verify the public key). phm-hex is
 * the ALREADY-HASHED message (the caller is responsible for having
 * pre-hashed it with the same `digest` externally -- that's the whole
 * point of this algorithm). Prints the signature as hex (sign) or
 * "VERIFY OK"/"VERIFY FAILED" (verify). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/store.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>

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

static size_t hex_decode(const char *in, unsigned char *out, size_t outcap)
{
    size_t len = strlen(in) / 2;
    if (len > outcap) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        sscanf(in + 2 * i, "%2x", &b);
        out[i] = (unsigned char)b;
    }
    return len;
}

static void hex_encode(const unsigned char *in, size_t len, char *out)
{
    static const char hexch[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hexch[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hexch[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}

int main(int argc, char **argv)
{
    if (argc < 6) {
        fprintf(stderr,
               "usage: %s sign|verify family propq key_uri digest phm-hex "
               "[sig-hex]\n",
               argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *family = argv[2];
    const char *propq = argv[3];
    const char *key_uri = argv[4];
    const char *digest = argv[5];
    if (argc < 7) {
        fprintf(stderr, "missing phm-hex\n");
        return 2;
    }
    const char *phm_hex = argv[6];

    if (!OSSL_PROVIDER_load(NULL, "pkcs11")) {
        ERR_print_errors_fp(stderr);
        return 2;
    }
    OSSL_PROVIDER_load(NULL, "default");

    EVP_PKEY *pkey = load_key(key_uri, propq);
    if (!pkey) {
        fprintf(stderr, "failed to load key %s\n", key_uri);
        ERR_print_errors_fp(stderr);
        return 2;
    }

    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, family, propq);
    if (!sig) {
        fprintf(stderr, "EVP_SIGNATURE_fetch(%s) failed\n", family);
        ERR_print_errors_fp(stderr);
        return 2;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, propq);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        ERR_print_errors_fp(stderr);
        return 2;
    }

    unsigned char phm[64];
    size_t phm_len = hex_decode(phm_hex, phm, sizeof(phm));
    if (phm_len == 0) {
        fprintf(stderr, "bad phm-hex\n");
        return 2;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_SIGNATURE_PARAM_DIGEST, (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_end();

    int rc;
    if (strcmp(mode, "sign") == 0) {
        rc = EVP_PKEY_sign_init_ex2(pctx, sig, params);
        if (rc != 1) {
            fprintf(stderr, "EVP_PKEY_sign_init_ex2 failed\n");
            ERR_print_errors_fp(stderr);
            return 2;
        }
        unsigned char sigbuf[65536];
        size_t siglen = sizeof(sigbuf);
        rc = EVP_PKEY_sign(pctx, sigbuf, &siglen, phm, phm_len);
        if (rc != 1) {
            fprintf(stderr, "EVP_PKEY_sign failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
        char hex[131072];
        hex_encode(sigbuf, siglen, hex);
        printf("%s\n", hex);
        return 0;
    } else if (strcmp(mode, "verify") == 0) {
        if (argc < 8) {
            fprintf(stderr, "missing sig-hex\n");
            return 2;
        }
        unsigned char sigbuf[65536];
        size_t siglen = hex_decode(argv[7], sigbuf, sizeof(sigbuf));
        if (siglen == 0) {
            fprintf(stderr, "bad sig-hex\n");
            return 2;
        }
        rc = EVP_PKEY_verify_init_ex2(pctx, sig, params);
        if (rc != 1) {
            fprintf(stderr, "EVP_PKEY_verify_init_ex2 failed\n");
            ERR_print_errors_fp(stderr);
            return 2;
        }
        rc = EVP_PKEY_verify(pctx, sigbuf, siglen, phm, phm_len);
        if (rc != 1) {
            printf("VERIFY FAILED\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
        printf("VERIFY OK\n");
        return 0;
    }
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
}
