/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _CIPHER_H
#define _CIPHER_H

/* Phase 5 R26. This engine's own CKM_AES_GCM/CKM_CHACHA20_POLY1305
 * decrypt (SoftHSM_cipher.cpp) never releases plaintext until the tag
 * is verified -- a correct security design (never hand back
 * unauthenticated data) -- and releases the WHOLE message at once once
 * it is. OpenSSL's own EVP_DecryptFinal_ex (crypto/evp/evp_enc.c)
 * hardcodes the buffer it gives a provider's final() callback to
 * EVP_CIPHER_CTX_get_block_size(ctx) -- confirmed by reading that
 * source directly, not guessed -- with no per-message way to enlarge
 * it, so the two designs collide for any message whose full plaintext
 * doesn't fit in one declared block. Reporting this generous-but-fixed
 * value as AEAD decrypt's own block_size (real work: cipher.c's own
 * p11prov_aes_get_params GCM case, chacha.c's own poly1305 case) is the
 * chosen (user, 2026-08-26) accommodation: it makes ordinary messages
 * work through the standard update()/final() API, at the honest cost of
 * a hard ceiling -- anything larger fails cleanly with
 * CKR_BUFFER_TOO_SMALL, not silent truncation or corruption. */
#define AEAD_DECRYPT_MAX_MSG_LEN 65536

/* Shared by every cipher.c/chacha.c OSSL_OP_CIPHER implementation --
 * moved here (was cipher.c-private) in phase 5 R26 so chacha.c's own
 * mechanism-specific get_ctx_params/set_ctx_params/dupctx/cipher/
 * get_params functions, wired through the SAME DISPATCH_TABLE_CIPHER_FN
 * macro AES uses below, can see the same fields the shared generic
 * newctx/freectx/update/final/prep_mech (cipher.c) already operate on. */
struct p11prov_cipher_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;
    int keysize;

    bool pad;

    CK_MECHANISM mech;
    CK_FLAGS operation;

    P11PROV_SESSION *session;
    enum {
        CIPHER_SESS_UNUSED,
        CIPHER_SESS_INITIALIZED,
        CIPHER_SESS_FINALIZED,
    } session_state;

    /* OpenSSL violates layering separation and decided
     * to process AES CBC MAC/padding handling in TLS 1.x < 1.3
     * in the lower cipher layer, so we have to do it here as well
     * for compatibility ... */
    unsigned int tlsver;
    size_t tlsmacsize;
    unsigned char *tlsmac;

    /* Phase 5 R26 prerequisite (AES-GCM was previously dead code, never
     * reachable): AEAD state (GCM, CHACHA20_POLY1305). PKCS#11's
     * C_EncryptInit/C_DecryptInit needs the COMPLETE AAD up front, baked
     * into the mechanism parameter -- but OpenSSL's own EVP convention
     * delivers AAD via zero or more update(out=NULL) calls made AFTER
     * encrypt_init/decrypt_init has already returned. So for an AEAD
     * mechanism, prep_mech only stashes the IV here and sets is_aead;
     * the real CK_GCM_PARAMS/CK_SALSA20_CHACHA20_POLY1305_PARAMS
     * construction (and the real C_EncryptInit/C_DecryptInit call) is
     * deferred to p11prov_cipher_ensure_session(), invoked from the
     * first REAL (non-NULL-out) update() or from final() if there was
     * none -- by which point all AAD has necessarily already arrived. */
    bool is_aead;
    bool aead_ready;
    unsigned char *aead_iv;
    size_t aead_ivlen;
    unsigned char *aad;
    size_t aadlen;
    size_t aadcap;
    /* Encrypt: filled in from C_EncryptFinal's own trailing bytes, for
     * get_ctx_params(AEAD_TAG) to hand back. Decrypt: filled in from the
     * caller's own set_ctx_params(AEAD_TAG) (the expected tag to
     * verify), forwarded to the token as one extra DecryptUpdate right
     * before DecryptFinal -- this engine's own decryptUpdate withholds
     * whatever it was most recently given until Final decides whether
     * those bytes were "more ciphertext" or "the trailing tag", so
     * appending the tag this way and then calling Final is exactly the
     * shape it expects. */
    unsigned char tag[16];
    size_t taglen;
    bool tag_set;

    /* CKM_CHACHA20 (stream, not AEAD): backing bytes for the
     * CK_CHACHA20_PARAMS pBlockCounter/pNonce pointers set in
     * prep_mech's own CKM_CHACHA20 case -- see that case's comment. */
    unsigned char chacha_iv_bytes[16];
};

/* Generic entry points, shared verbatim across every cipher family that
 * uses DISPATCH_TABLE_CIPHER_FN (cipher.c's own AES tables and chacha.c's
 * CHACHA20/CHACHA20_POLY1305 tables) -- defined once in cipher.c. */
void *p11prov_cipher_newctx(void *provctx, int size, CK_ULONG mechanism);
void p11prov_cipher_freectx(void *ctx);
int p11prov_cipher_encrypt_init(void *ctx, const unsigned char *key,
                                size_t keylen, const unsigned char *iv,
                                size_t ivlen, const OSSL_PARAM params[]);
int p11prov_cipher_decrypt_init(void *ctx, const unsigned char *key,
                                size_t keylen, const unsigned char *iv,
                                size_t ivlen, const OSSL_PARAM params[]);
int p11prov_cipher_update(void *ctx, unsigned char *out, size_t *outl,
                          size_t outsize, const unsigned char *in,
                          size_t inl);
int p11prov_cipher_final(void *ctx, unsigned char *out, size_t *outl,
                         size_t outsize);
int p11prov_cipher_encrypt_skey_init(void *ctx, void *keydata,
                                     const unsigned char *iv, size_t ivlen,
                                     const OSSL_PARAM params[]);
int p11prov_cipher_decrypt_skey_init(void *ctx, void *keydata,
                                     const unsigned char *iv, size_t ivlen,
                                     const OSSL_PARAM params[]);
int p11prov_cipher_get_params(OSSL_PARAM params[], unsigned int mode,
                              int flags, size_t keysize, size_t blocksize,
                              size_t ivsize);
const OSSL_PARAM *p11prov_cipher_gettable_params(void *provctx);
/* AEAD-tag set_ctx_params handling, shared by AES-GCM (cipher.c) and
 * CHACHA20_POLY1305 (chacha.c) -- see its own definition's comment. */
int p11prov_cipher_aead_set_tag_param(struct p11prov_cipher_ctx *ctx,
                                      const OSSL_PARAM params[],
                                      bool *consumed);

#define MODE_modes_mask 0x00FF
#define MODE_flags_mask 0xFF00

#define MODE_flag_aead 0x0100
#define MODE_flag_custom_iv 0x0200
#define MODE_flag_cts 0x0400
#define MODE_flag_tls1_mb 0x0800
#define MODE_flag_rand_key 0x1000

#define MODE_ecb 0x01
#define MODE_cbc 0x02
#define MODE_ofb 0x04
#define MODE_cfb 0x08
#define MODE_cfb1 MODE_cfb
#define MODE_cfb8 MODE_cfb
#define MODE_ctr 0x10
#define MODE_gcm 0x20 | MODE_flag_aead
#define MODE_ccm 0x40 | MODE_flag_aead
#define MODE_cts MODE_flag_cts | MODE_cbc
#define MODE_stream 0x80
#define MODE_poly1305 0x81 | MODE_flag_aead

#define DISPATCH_CIPHER_FN(alg, name) \
    DECL_DISPATCH_FUNC(cipher, p11prov_##alg, name)

#define DISPATCH_TABLE_CIPHER_FN(cipher, size, mode, mechanism) \
    static void *p11prov_##cipher##size##mode##_newctx(void *provctx) \
    { \
        return p11prov_cipher_newctx(provctx, size, mechanism); \
    } \
    static int p11prov_##cipher##size##mode##_get_params(OSSL_PARAM params[]) \
    { \
        return p11prov_##cipher##_get_params(params, size, MODE_##mode, \
                                             mechanism); \
    } \
    const OSSL_DISPATCH p11prov_##cipher##size##mode##_cipher_functions[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX, \
          (void (*)(void))p11prov_##cipher##size##mode##_newctx }, \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p11prov_cipher_freectx }, \
        { OSSL_FUNC_CIPHER_DUPCTX, \
          (void (*)(void))p11prov_##cipher##_dupctx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, \
          (void (*)(void))p11prov_cipher_encrypt_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, \
          (void (*)(void))p11prov_cipher_decrypt_init }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p11prov_cipher_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p11prov_cipher_final }, \
        { OSSL_FUNC_CIPHER_CIPHER, \
          (void (*)(void))p11prov_##cipher##_cipher }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS, \
          (void (*)(void))p11prov_##cipher##size##mode##_get_params }, \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, \
          (void (*)(void))p11prov_##cipher##_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, \
          (void (*)(void))p11prov_##cipher##_set_ctx_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, \
          (void (*)(void))p11prov_cipher_gettable_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, \
          (void (*)(void))p11prov_##cipher##_gettable_ctx_params }, \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, \
          (void (*)(void))p11prov_##cipher##_settable_ctx_params }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT, \
          (void (*)(void))p11prov_cipher_encrypt_skey_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT, \
          (void (*)(void))p11prov_cipher_decrypt_skey_init }, \
        OSSL_DISPATCH_END \
    };

extern const OSSL_DISPATCH p11prov_aes128ecb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192ecb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256ecb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cbc_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cbc_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cbc_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128ofb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192ofb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256ofb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb1_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb1_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb1_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb8_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb8_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb8_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128ctr_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192ctr_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256ctr_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cts_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cts_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cts_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128gcm_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192gcm_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256gcm_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128ccm_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192ccm_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256ccm_cipher_functions[];

extern const OSSL_DISPATCH p11prov_chacha20256stream_cipher_functions[];
extern const OSSL_DISPATCH p11prov_chacha20256poly1305_cipher_functions[];

#endif /* _CIPHER_H */
