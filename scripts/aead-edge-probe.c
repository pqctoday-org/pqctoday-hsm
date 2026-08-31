/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* aead-edge-probe: phase-6 R30 test helper. Purpose-built for the two
 * AEAD decrypt edge cases R26 left honestly undone rather than folding
 * them into aead-probe.c's own happy-path+sabotage shape:
 *
 *   1. Over-AEAD_DECRYPT_MAX_MSG_LEN messages: encrypt must still
 *      succeed (no ceiling on that side -- ciphertext streams out via
 *      update() immediately, R26's own finding), but decrypt must fail
 *      CLEANLY -- a real EVP-level failure the caller can act on, never
 *      a crash, never a truncated-but-"successful" plaintext. This
 *      tool reports exactly which call failed, which aead-probe.c's
 *      own generic "DecryptFinal FAILED (tag verify failed)" message
 *      would mischaracterize (written for the sabotage case, not a
 *      buffer-capacity failure).
 *   2. AAD-only / empty-plaintext: the ensure_session()-from-final()
 *      path (cipher.c) written for a zero-update()-calls AEAD op was
 *      never actually exercised by anything before this item.
 *
 * Build this one with a sanitizer where available (see CMakeLists.txt)
 * -- it is deliberately probing a buffer-size boundary the provider
 * itself computes, so a silent one-byte overrun is exactly the kind of
 * bug a plain run could miss by not crashing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

static unsigned char *hex2bin(const char *hex, size_t *outlen)
{
    size_t len = strlen(hex) / 2;
    unsigned char *buf = malloc(len ? len : 1);
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &buf[i]);
    }
    *outlen = len;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr,
                "usage: %s <cipher> <key-hex> <iv-hex> <aad-hex-or-empty> "
                "<msg-len-bytes> <provider> <expect: decrypt-ok|decrypt-fail>\n",
                argv[0]);
        return 2;
    }
    const char *cipher_name = argv[1];
    size_t keylen, ivlen, aadlen;
    unsigned char *key = hex2bin(argv[2], &keylen);
    unsigned char *iv = hex2bin(argv[3], &ivlen);
    unsigned char *aad = NULL;
    if (strlen(argv[4]) > 0) {
        aad = hex2bin(argv[4], &aadlen);
    } else {
        aadlen = 0;
    }
    long msglen = atol(argv[5]);
    const char *provider = argv[6];
    const char *expect = argv[7];
    int expect_ok = strcmp(expect, "decrypt-ok") == 0;

    unsigned char *msg = malloc(msglen ? (size_t)msglen : 1);
    for (long i = 0; i < msglen; i++) {
        /* deterministic, not random -- reproducible on failure */
        msg[i] = (unsigned char)(i & 0xFF);
    }

    if (!OSSL_PROVIDER_load(NULL, provider)) {
        fprintf(stderr, "failed to load provider %s\n", provider);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    OSSL_PROVIDER_load(NULL, "default");

    char propq[64];
    snprintf(propq, sizeof(propq), "provider=%s", provider);

    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, cipher_name, propq);
    if (!cipher) {
        fprintf(stderr, "EVP_CIPHER_fetch(%s, %s) failed\n", cipher_name,
                propq);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Ciphertext can legitimately be as large as plaintext plus a small
     * cipher-specific margin; give it generous headroom rather than
     * trying to compute the exact bound (this tool is not the thing
     * under test for over-allocating). */
    size_t cap = (size_t)msglen + 4096;
    unsigned char *ct = malloc(cap);
    unsigned char *pt = malloc(cap);
    int ctlen, len;
    unsigned char tag[16];

    /* ---- ENCRYPT (always expected to succeed -- no ceiling here) ---- */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        fprintf(stderr, "ENCRYPT FAILED at Init -- unexpected, encrypt has no ceiling\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (aadlen > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
        fprintf(stderr, "ENCRYPT FAILED at AAD update\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    len = 0;
    if (msglen > 0 && EVP_EncryptUpdate(ctx, ct, &len, msg, msglen) != 1) {
        fprintf(stderr, "ENCRYPT FAILED at data update (msglen=%ld) -- "
                        "unexpected, encrypt has no ceiling\n",
                msglen);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    ctlen = len;
    if (EVP_EncryptFinal_ex(ctx, ct + ctlen, &len) != 1) {
        fprintf(stderr, "ENCRYPT FAILED at Final\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    ctlen += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "ENCRYPT FAILED at GET_TAG\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("encrypt OK: msglen=%ld ctlen=%d\n", msglen, ctlen);
    EVP_CIPHER_CTX_free(ctx);

    /* ---- DECRYPT (outcome depends on `expect`) ---- */
    ctx = EVP_CIPHER_CTX_new();
    int ptlen = 0;
    int decrypt_failed_at = 0; /* 0=nowhere yet, 1=init, 2=aad, 3=data-update, 4=final */
    if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        decrypt_failed_at = 1;
    }
    if (!decrypt_failed_at && aadlen > 0
        && EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
        decrypt_failed_at = 2;
    }
    if (!decrypt_failed_at && msglen > 0) {
        if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen) != 1) {
            decrypt_failed_at = 3;
        } else {
            ptlen = len;
        }
    }
    if (!decrypt_failed_at) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag);
        if (EVP_DecryptFinal_ex(ctx, pt + ptlen, &len) != 1) {
            decrypt_failed_at = 4;
        } else {
            ptlen += len;
        }
    }

    if (decrypt_failed_at == 0) {
        /* Decrypt reported success end to end -- verify it actually is. */
        if (ptlen != msglen || (msglen > 0 && memcmp(pt, msg, msglen) != 0)) {
            fprintf(stderr,
                    "DECRYPT CLAIMED SUCCESS BUT PLAINTEXT IS WRONG "
                    "(ptlen=%d msglen=%ld) -- this is worse than a clean "
                    "failure, it is silent corruption\n",
                    ptlen, msglen);
            return 1;
        }
        printf("decrypt OK: plaintext matches original (%d bytes)\n", ptlen);
        if (!expect_ok) {
            fprintf(stderr,
                    "EXPECTATION MISMATCH: expected decrypt-fail, got a "
                    "genuinely correct decrypt instead\n");
            return 1;
        }
    } else {
        const char *where[] = { "", "Init", "AAD update", "data update",
                                "Final" };
        printf("decrypt FAILED cleanly at %s (process alive, no crash, "
               "no silent output)\n",
               where[decrypt_failed_at]);
        if (expect_ok) {
            fprintf(stderr,
                    "EXPECTATION MISMATCH: expected decrypt-ok, got a clean "
                    "failure at %s instead\n",
                    where[decrypt_failed_at]);
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return 0;
}
