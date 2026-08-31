/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* aead-probe: phase-5 R26 test helper. Exercises the full EVP AEAD
 * workflow (encrypt with AAD, decrypt+verify, both tag- and ciphertext-
 * tamper rejection) for CKM_AES_GCM / CKM_CHACHA20_POLY1305 through this
 * provider.
 *
 * Needed because `openssl enc` (the CLI subcommand every other cipher
 * case in this harness uses) refuses AEAD ciphers outright ("AEAD
 * ciphers not supported") -- a long-standing, unrelated limitation of
 * that specific CLI subcommand, not of this provider or of OpenSSL's
 * EVP AEAD support in general. Going straight to the EVP_CIPHER API
 * (EVP_EncryptUpdate/Final + EVP_CTRL_AEAD_GET_TAG/SET_TAG) sidesteps
 * that gap the same way skey-flow-probe.c and hss-pubkey-dump.c
 * sidestep their own CLI gaps.
 *
 * Uses a HARD propquery ("provider=<name>", no leading "?") deliberately
 * -- a soft one ("?provider=pkcs11") let this provider's own registered
 * "ChaCha20-Poly1305"/"AES-256-GCM" silently lose to the default
 * provider's identically-named implementation during EVP_CIPHER_fetch(),
 * which cost real debugging time to catch (the R22 "openssl kdf" CLI
 * trap all over again, one layer down): every run "succeeded" and even
 * cross-checked byte-identical against software, because it secretly
 * WAS software the whole time. A hard propquery makes that failure mode
 * loud (EVP_CIPHER_fetch itself fails) instead of silent. */
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
    if (argc != 7) {
        fprintf(stderr,
                "usage: %s <cipher-name> <key-hex> <iv-hex> "
                "<aad-hex-or-empty> <msg-file> <provider-name>\n"
                "  relies on OPENSSL_CONF/SOFTHSM2_CONF already pointing "
                "at the arena, same as every openssl CLI call in this "
                "harness\n",
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
    const char *msgfile = argv[5];
    const char *provider = argv[6];

    FILE *f = fopen(msgfile, "rb");
    if (!f) {
        perror(msgfile);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long msglen = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *msg = malloc(msglen ? msglen : 1);
    if (fread(msg, 1, msglen, f) != (size_t)msglen) {
        fprintf(stderr, "short read on %s\n", msgfile);
        return 1;
    }
    fclose(f);

    if (!OSSL_PROVIDER_load(NULL, provider)) {
        fprintf(stderr, "failed to load provider %s\n", provider);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    /* pkcs11-provider needs the default provider loaded alongside it for
     * some of its own internal fallback fetches (matches every arena's
     * own openssl.cnf, which activates both). */
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

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ct[8192];
    int ctlen = 0, len;
    unsigned char tag[16];

    /* ---- ENCRYPT ---- */
    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        fprintf(stderr, "EncryptInit failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (aadlen > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
        fprintf(stderr, "EncryptUpdate(AAD) failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_EncryptUpdate(ctx, ct, &len, msg, msglen) != 1) {
        fprintf(stderr, "EncryptUpdate(data) failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    ctlen = len;
    if (EVP_EncryptFinal_ex(ctx, ct + ctlen, &len) != 1) {
        fprintf(stderr, "EncryptFinal failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    ctlen += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "GET_TAG failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("encrypt OK: ctlen=%d tag=", ctlen);
    for (int i = 0; i < 16; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");
    EVP_CIPHER_CTX_free(ctx);

    /* ---- DECRYPT (correct tag) ---- */
    ctx = EVP_CIPHER_CTX_new();
    unsigned char pt[8192];
    int ptlen;
    if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        fprintf(stderr, "DecryptInit failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (aadlen > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
        fprintf(stderr, "DecryptUpdate(AAD) failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen) != 1) {
        fprintf(stderr, "DecryptUpdate(data) failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    ptlen = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) {
        fprintf(stderr, "SET_TAG failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_DecryptFinal_ex(ctx, pt + ptlen, &len) != 1) {
        fprintf(stderr, "DecryptFinal FAILED (tag verify failed)\n");
        return 1;
    }
    ptlen += len;
    if (ptlen != msglen || memcmp(pt, msg, msglen) != 0) {
        fprintf(stderr, "PLAINTEXT MISMATCH after decrypt\n");
        return 1;
    }
    printf("decrypt OK: plaintext matches original (%d bytes), tag verified\n",
           ptlen);
    EVP_CIPHER_CTX_free(ctx);

    /* ---- sabotage: tampered tag must be rejected ---- */
    ctx = EVP_CIPHER_CTX_new();
    unsigned char badtag[16];
    memcpy(badtag, tag, 16);
    badtag[0] ^= 0xFF;
    EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL);
    if (aadlen > 0) {
        EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen);
    }
    EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen);
    ptlen = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, badtag);
    if (EVP_DecryptFinal_ex(ctx, pt + ptlen, &len) == 1) {
        fprintf(stderr, "SABOTAGE FAIL: tampered tag was ACCEPTED\n");
        return 1;
    }
    printf("sabotage OK: tampered tag correctly rejected\n");
    EVP_CIPHER_CTX_free(ctx);

    /* ---- sabotage: tampered ciphertext must be rejected ---- */
    if (ctlen > 0) {
        ctx = EVP_CIPHER_CTX_new();
        unsigned char badct[8192];
        memcpy(badct, ct, ctlen);
        badct[0] ^= 0xFF;
        EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL);
        if (aadlen > 0) {
            EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen);
        }
        EVP_DecryptUpdate(ctx, pt, &len, badct, ctlen);
        ptlen = len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag);
        if (EVP_DecryptFinal_ex(ctx, pt + ptlen, &len) == 1) {
            fprintf(stderr,
                    "SABOTAGE FAIL: tampered ciphertext was ACCEPTED\n");
            return 1;
        }
        printf("sabotage OK: tampered ciphertext correctly rejected\n");
        EVP_CIPHER_CTX_free(ctx);
    }

    EVP_CIPHER_free(cipher);
    return 0;
}
