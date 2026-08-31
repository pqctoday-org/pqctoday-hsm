/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* aes-xts-probe: OpenSSL-provider remediation item (2026-08-30) test
 * helper for CKM_AES_XTS's own OSSL_OP_CIPHER registration ("AES-128-XTS"
 * / "AES-256-XTS" -- OpenSSL defines no 192-bit XTS variant, since XTS
 * combines two AES keys: "AES-128-XTS" needs 256 raw bits, "AES-256-XTS"
 * needs 512).
 *
 * Exercises, for both key sizes:
 *   1. A multi-call streaming round trip (a block-aligned prefix update,
 *      THEN a separate final update that is itself non-block-aligned)
 *      -- deliberately forcing genuine ciphertext stealing at a real
 *      streaming boundary, not just a single one-shot call that happens
 *      to be non-block-aligned. The final call is deliberately LARGER
 *      than one AES block (not just non-aligned) -- confirmed live,
 *      against OpenSSL's own default-provider AES-XTS with zero PKCS#11
 *      involvement, that a final call SHORTER than one block fails
 *      (providers/implementations/ciphers/cipher_aes_xts.c's own
 *      aes_xts_stream_update rejects it: `error:1C800066: cipher
 *      operation failed`), matching the exact wording of OpenSSL's own
 *      docs.openssl.org/3.6/man7/EVP_CIPHER-AES/ ("the last call may use
 *      non-multiple input LARGER than one block") -- "larger than one
 *      block" is load-bearing, not incidental phrasing: ciphertext
 *      stealing swaps the last TWO blocks together, so the final call
 *      needs enough bytes to contain both halves of that swap in one
 *      shot; a sub-block final call has nothing to swap against.
 *   2. Cross-check against an INDEPENDENT reference: a second
 *      EVP_CIPHER_CTX fetched from the plain "default" provider (no
 *      propquery), fed the exact same full-width key and tweak. If the
 *      double-width raw key material were being split into its two
 *      AES-XTS sub-keys incorrectly anywhere in the provider/engine
 *      pipeline, ciphertext would differ from this oracle even though
 *      the token's own round trip might still "work" self-consistently.
 *
 * A HARD propquery ("provider=pkcs11") selects this provider's own
 * registration for the token-backed context; the reference context
 * explicitly requests "provider=default" so the same two fetches can
 * never silently collide. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/err.h>

static int g_failures = 0;

static void fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    ERR_print_errors_fp(stderr);
    g_failures++;
}

/* Encrypts `msg` (msglen bytes) under `cipher_name`/`propq` with tweak
 * `iv`, splitting the update into a block-aligned prefix (msglen -
 * tail_len bytes) followed by a separate final update of exactly
 * tail_len bytes (0 < tail_len < 16) -- the two-call shape that
 * genuinely exercises ciphertext stealing at a real streaming boundary.
 * Returns output length, or -1 on failure. */
static int xts_encrypt_split(const char *cipher_name, const char *propq,
                             const unsigned char *key, size_t keylen,
                             const unsigned char *iv,
                             const unsigned char *msg, int msglen,
                             int tail_len, unsigned char *out, int outcap)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, cipher_name, propq);
    EVP_CIPHER_CTX *ctx;
    int len, outlen = 0;
    int prefix_len = msglen - tail_len;

    if (!cipher) {
        fail("EVP_CIPHER_fetch(%s, %s) failed", cipher_name, propq);
        return -1;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        fail("[%s] encrypt Init failed", propq);
        goto err;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (prefix_len > 0) {
        if (EVP_EncryptUpdate(ctx, out, &len, msg, prefix_len) != 1) {
            fail("[%s] encrypt Update (block-aligned prefix, %d bytes) failed",
                 propq, prefix_len);
            goto err;
        }
        outlen += len;
    }
    if (EVP_EncryptUpdate(ctx, out + outlen, &len, msg + prefix_len, tail_len)
        != 1) {
        fail("[%s] encrypt Update (sub-block final chunk, %d bytes) failed "
             "-- ciphertext stealing did not work",
             propq, tail_len);
        goto err;
    }
    outlen += len;
    if (EVP_EncryptFinal_ex(ctx, out + outlen, &len) != 1) {
        fail("[%s] encrypt Final failed", propq);
        goto err;
    }
    outlen += len;
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return outlen;

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return -1;
}

static int xts_decrypt_split(const char *cipher_name, const char *propq,
                             const unsigned char *key, size_t keylen,
                             const unsigned char *iv,
                             const unsigned char *ct, int ctlen,
                             int tail_len, unsigned char *out, int outcap)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, cipher_name, propq);
    EVP_CIPHER_CTX *ctx;
    int len, outlen = 0;
    int prefix_len = ctlen - tail_len;

    if (!cipher) {
        fail("EVP_CIPHER_fetch(%s, %s) failed", cipher_name, propq);
        return -1;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        fail("[%s] decrypt Init failed", propq);
        goto err;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (prefix_len > 0) {
        if (EVP_DecryptUpdate(ctx, out, &len, ct, prefix_len) != 1) {
            fail("[%s] decrypt Update (block-aligned prefix, %d bytes) failed",
                 propq, prefix_len);
            goto err;
        }
        outlen += len;
    }
    if (EVP_DecryptUpdate(ctx, out + outlen, &len, ct + prefix_len, tail_len)
        != 1) {
        fail("[%s] decrypt Update (sub-block final chunk, %d bytes) failed "
             "-- ciphertext stealing did not work",
             propq, tail_len);
        goto err;
    }
    outlen += len;
    if (EVP_DecryptFinal_ex(ctx, out + outlen, &len) != 1) {
        fail("[%s] decrypt Final failed", propq);
        goto err;
    }
    outlen += len;
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return outlen;

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return -1;
}

static int run_case(const char *cipher_name, const char *pkcs11_propq,
                    int keybytes)
{
    unsigned char key[64];
    unsigned char iv[16]; /* Data Unit Sequence Number (tweak) */
    unsigned char msg[53]; /* 2 full 16-byte blocks (prefix) + a 21-byte
                            * tail: the tail is deliberately >1 block (not
                            * just non-aligned) -- see this file's own
                            * header for why a final call SHORTER than one
                            * block does not work for genuine multi-call
                            * XTS streaming. */
    unsigned char ct_token[128], ct_ref[128];
    unsigned char pt_back[128];
    int tail_len = 21;
    int ctlen_token, ctlen_ref, ptlen;

    printf("-- %s (total key material = %d bytes) --\n", cipher_name,
           keybytes);

    if (RAND_bytes(key, keybytes) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        fail("RAND_bytes failed");
        return 0;
    }
    for (size_t i = 0; i < sizeof(msg); i++) {
        msg[i] = (unsigned char)(i * 7 + 1); /* deterministic, reproducible */
    }

    ctlen_token = xts_encrypt_split(cipher_name, pkcs11_propq, key, keybytes,
                                    iv, msg, sizeof(msg), tail_len, ct_token,
                                    sizeof(ct_token));
    if (ctlen_token < 0) {
        return 0;
    }
    printf("   token encrypt OK (streamed: %zu-byte prefix + %d-byte "
           "ciphertext-stealing tail): %zu -> %d bytes\n",
           sizeof(msg) - tail_len, tail_len, sizeof(msg), ctlen_token);

    /* Independent oracle: same key/tweak/message, default (software)
     * provider -- and DELIBERATELY the exact same two-call split shape
     * as the token path above, not a single one-shot call. Confirmed
     * live (a standalone throwaway test against provider=default with
     * zero PKCS#11 involvement) that real AES-XTS ciphertext at the
     * stealing boundary is genuinely shape-dependent: encrypting the
     * identical key+tweak+message in one call vs. a 32+21 split produces
     * DIFFERENT (though each independently correct and round-trippable)
     * ciphertext bytes from byte 32 onward -- a one-shot reference here
     * would have produced a false "DIFFERS" failure having nothing to do
     * with the double-width key question this probe actually checks. */
    ctlen_ref = xts_encrypt_split(cipher_name, "provider=default", key,
                                  keybytes, iv, msg, sizeof(msg), tail_len,
                                  ct_ref, sizeof(ct_ref));
    if (ctlen_ref < 0) {
        return 0;
    }

    if (ctlen_ref != ctlen_token
        || memcmp(ct_ref, ct_token, ctlen_ref) != 0) {
        fail("token ciphertext DIFFERS from OpenSSL's own independent "
             "software AES-XTS oracle (same key+tweak+message) -- the "
             "double-width key material is not being split into its two "
             "AES-XTS sub-keys the same way (token %d bytes, oracle %d "
             "bytes)",
             ctlen_token, ctlen_ref);
        return 0;
    }
    printf("   token ciphertext byte-identical to OpenSSL's own "
           "independent software AES-XTS (%d bytes) -- double-width key "
           "split confirmed correct\n",
           ctlen_ref);

    /* Decrypt back through the token (same split shape) and confirm the
     * plaintext round-trips, including across the ciphertext-stealing
     * boundary. */
    ptlen = xts_decrypt_split(cipher_name, pkcs11_propq, key, keybytes, iv,
                              ct_token, ctlen_token, tail_len, pt_back,
                              sizeof(pt_back));
    if (ptlen < 0) {
        return 0;
    }
    if ((size_t)ptlen != sizeof(msg) || memcmp(pt_back, msg, sizeof(msg)) != 0) {
        fail("token decrypt CLAIMED success but plaintext is WRONG "
             "(ptlen=%d expected=%zu) -- worse than a clean failure",
             ptlen, sizeof(msg));
        return 0;
    }
    printf("   token decrypt OK: plaintext matches original across the "
           "ciphertext-stealing boundary (%d bytes)\n",
           ptlen);
    return 1;
}

int main(int argc, char **argv)
{
    const char *provider = argc > 1 ? argv[1] : "pkcs11";
    char propq[64];
    int all_ok = 1;

    if (!OSSL_PROVIDER_load(NULL, provider)) {
        fprintf(stderr, "failed to load provider %s\n", provider);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    OSSL_PROVIDER_load(NULL, "default");
    snprintf(propq, sizeof(propq), "provider=%s", provider);

    /* AES-128-XTS: 256 raw bits (two AES-128 sub-keys). */
    all_ok &= run_case("AES-128-XTS", propq, 32);
    /* AES-256-XTS: 512 raw bits (two AES-256 sub-keys). */
    all_ok &= run_case("AES-256-XTS", propq, 64);

    if (g_failures > 0 || !all_ok) {
        fprintf(stderr, "\nAES-XTS PROBE: %d failure(s)\n", g_failures);
        return 1;
    }
    printf("\nAES-XTS PROBE: all cases passed\n");
    return 0;
}
