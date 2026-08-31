/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* aes-wrap-probe: OpenSSL-provider remediation item (2026-08-30) test
 * helper for CKM_AES_KEY_WRAP / CKM_AES_KEY_WRAP_KWP -- neither had ANY
 * OSSL_OP_CIPHER registration before this item (grep across cipher.c/h
 * found nothing "WRAP"-shaped at all). Exercises the genuinely different
 * dispatch shape this mechanism family needed (see cipher.c's own
 * p11prov_aes_wrap_update() comment: C_WrapKey/C_UnwrapKey key-object
 * semantics, not C_Encrypt/C_Decrypt -- this engine's C_GetMechanismInfo
 * advertises CKF_WRAP|CKF_UNWRAP only for all three PKCS#11 mechanism
 * IDs, never CKF_ENCRYPT|CKF_DECRYPT):
 *
 *   - wrap+unwrap round trip for all three AES key sizes (128/192/256),
 *     for both "AES-*-WRAP" (RFC 3394, plain) and "AES-*-WRAP-PAD"
 *     (RFC 5649, padded -- backed by CKM_AES_KEY_WRAP_KWP)
 *   - WRAP-PAD is additionally exercised with a non-8-byte-aligned
 *     payload length (30 bytes), the one property that actually
 *     distinguishes RFC 5649 from plain RFC 3394 wrap
 *   - a tampered wrapped blob must be REJECTED, not silently accepted --
 *     RFC 3394/5649 both bake an integrity check into the construction
 *     itself (no separate MAC), and this proves it is genuinely
 *     enforced end to end through the token, not silently ignored
 *
 * A HARD propquery ("provider=pkcs11", no leading "?") is used
 * throughout -- both "AES-256-WRAP" and "AES-256-WRAP-PAD" (and their
 * OID aliases) are ALSO registered by OpenSSL's own default provider, so
 * a soft propquery would let this provider's own registration silently
 * lose the EVP_CIPHER_fetch() race, exactly the trap T27b/T27d's own
 * comments in scripts/test-openssl-provider.sh already document for
 * AES-GCM/ChaCha20-Poly1305. */
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

/* Returns 1 if wrap+unwrap round-tripped correctly and a tamper attempt
 * was cleanly rejected; 0 on any real failure. */
static int run_case(const char *cipher_name, const char *propq,
                    int kek_bytes, int payload_bytes)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char kek[32];
    unsigned char *payload = NULL, *wrapped = NULL, *unwrapped = NULL;
    int wrapped_cap, unwrapped_cap;
    int wlen = 0, ulen = 0, len;
    int ok = 0;

    printf("-- %s (KEK=%d bytes, payload=%d bytes) --\n", cipher_name,
           kek_bytes, payload_bytes);

    if (RAND_bytes(kek, kek_bytes) != 1) {
        fail("RAND_bytes(KEK) failed");
        return 0;
    }
    payload = malloc(payload_bytes);
    if (RAND_bytes(payload, payload_bytes) != 1) {
        fail("RAND_bytes(payload) failed");
        goto done;
    }

    cipher = EVP_CIPHER_fetch(NULL, cipher_name, propq);
    if (!cipher) {
        fail("EVP_CIPHER_fetch(%s, %s) failed", cipher_name, propq);
        goto done;
    }

    /* ---- WRAP (encrypt direction) ---- */
    wrapped_cap = payload_bytes + 64;
    wrapped = malloc(wrapped_cap);
    ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex2(ctx, cipher, kek, NULL, NULL) != 1) {
        fail("wrap EncryptInit failed");
        goto done;
    }
    if (EVP_EncryptUpdate(ctx, wrapped, &len, payload, payload_bytes) != 1) {
        fail("wrap EncryptUpdate failed");
        goto done;
    }
    wlen = len;
    if (EVP_EncryptFinal_ex(ctx, wrapped + wlen, &len) != 1) {
        fail("wrap EncryptFinal failed");
        goto done;
    }
    wlen += len;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    printf("   wrap OK: %d -> %d bytes\n", payload_bytes, wlen);

    /* ---- UNWRAP (decrypt direction) -- must recover the exact payload ---- */
    unwrapped_cap = wlen + 64;
    unwrapped = malloc(unwrapped_cap);
    ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex2(ctx, cipher, kek, NULL, NULL) != 1) {
        fail("unwrap DecryptInit failed");
        goto done;
    }
    if (EVP_DecryptUpdate(ctx, unwrapped, &len, wrapped, wlen) != 1) {
        fail("unwrap DecryptUpdate failed (round trip did not work at all)");
        goto done;
    }
    ulen = len;
    if (EVP_DecryptFinal_ex(ctx, unwrapped + ulen, &len) != 1) {
        fail("unwrap DecryptFinal failed (round trip did not work at all)");
        goto done;
    }
    ulen += len;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    if (ulen != payload_bytes || memcmp(unwrapped, payload, payload_bytes) != 0) {
        fail("unwrap CLAIMED success but recovered key material is WRONG "
             "(ulen=%d expected=%d) -- worse than a clean failure",
             ulen, payload_bytes);
        goto done;
    }
    printf("   unwrap OK: recovered key material matches original (%d bytes)\n",
           ulen);

    /* ---- Tamper: RFC 3394/5649's own built-in integrity check must
     * genuinely reject a corrupted wrapped blob, not silently unwrap it
     * into garbage. Flip a byte roughly in the middle of the ciphertext
     * (avoids only ever touching the same semiblock every run). ---- */
    {
        unsigned char *tampered = malloc(wlen);
        memcpy(tampered, wrapped, wlen);
        tampered[wlen / 2] ^= 0xFF;

        ctx = EVP_CIPHER_CTX_new();
        int tamper_rejected = 0;
        if (EVP_DecryptInit_ex2(ctx, cipher, kek, NULL, NULL) != 1) {
            tamper_rejected = 1; /* rejected at init is fine too */
        } else if (EVP_DecryptUpdate(ctx, unwrapped, &len, tampered, wlen) != 1) {
            tamper_rejected = 1;
        } else {
            int tulen = len;
            if (EVP_DecryptFinal_ex(ctx, unwrapped + tulen, &len) != 1) {
                tamper_rejected = 1;
            } else {
                tulen += len;
                /* Extremely unlucky case: decrypt "succeeded" but must
                 * not silently produce output that still matches the
                 * real payload -- that would mean the flip landed on a
                 * byte the construction doesn't actually cover, which
                 * would itself be a genuine integrity-check gap. */
                if (tulen == payload_bytes
                    && memcmp(unwrapped, payload, payload_bytes) == 0) {
                    fail("tampered wrapped blob was accepted AND still "
                         "decoded to the correct payload -- integrity "
                         "check is not covering this byte");
                } else {
                    fail("tampered wrapped blob was accepted and produced "
                         "DIFFERENT garbage output instead of being "
                         "rejected -- integrity check is not enforced");
                }
            }
        }
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
        free(tampered);

        if (tamper_rejected) {
            printf("   tampered wrapped blob correctly rejected (RFC "
                   "3394/5649 integrity check enforced)\n");
            ok = 1;
        }
    }

done:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (cipher) {
        EVP_CIPHER_free(cipher);
    }
    free(payload);
    free(wrapped);
    free(unwrapped);
    return ok;
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

    /* Plain RFC 3394 WRAP: block-aligned (multiple of 8, >=16) payload. */
    all_ok &= run_case("AES-128-WRAP", propq, 16, 32);
    all_ok &= run_case("AES-192-WRAP", propq, 24, 32);
    all_ok &= run_case("AES-256-WRAP", propq, 32, 32);

    /* RFC 5649 WRAP-PAD (CKM_AES_KEY_WRAP_KWP): one block-aligned payload
     * and one deliberately NOT a multiple of 8 -- the one property that
     * actually distinguishes RFC 5649 from plain RFC 3394 wrap. */
    all_ok &= run_case("AES-128-WRAP-PAD", propq, 16, 32);
    all_ok &= run_case("AES-128-WRAP-PAD", propq, 16, 30);
    all_ok &= run_case("AES-192-WRAP-PAD", propq, 24, 32);
    all_ok &= run_case("AES-192-WRAP-PAD", propq, 24, 30);
    all_ok &= run_case("AES-256-WRAP-PAD", propq, 32, 32);
    all_ok &= run_case("AES-256-WRAP-PAD", propq, 32, 30);

    if (g_failures > 0 || !all_ok) {
        fprintf(stderr, "\nAES-WRAP PROBE: %d failure(s)\n", g_failures);
        return 1;
    }
    printf("\nAES-WRAP PROBE: all cases passed\n");
    return 0;
}
