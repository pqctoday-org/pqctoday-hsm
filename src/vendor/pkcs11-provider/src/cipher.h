/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _CIPHER_H
#define _CIPHER_H

/* Phase 5 R26 / phase 6 R30. This engine's own CKM_AES_GCM/CKM_
 * CHACHA20_POLY1305 decrypt (SoftHSM_cipher.cpp) never releases
 * plaintext until the tag is verified -- a correct security design
 * (never hand back unauthenticated data) -- and releases the WHOLE
 * message at once once it is. OpenSSL's own EVP_DecryptFinal_ex
 * (crypto/evp/evp_enc.c) hardcodes the buffer it gives a provider's
 * final() callback to EVP_CIPHER_CTX_get_block_size(ctx) -- confirmed
 * by reading that source directly, not guessed -- with no per-message
 * way to enlarge it, so the two designs collide for any message whose
 * full plaintext doesn't fit in one declared block. Reporting a
 * generous-but-fixed value as AEAD decrypt's own block_size (real
 * work: cipher.c's own p11prov_aes_get_params GCM case, chacha.c's own
 * poly1305 case) is the chosen (user, 2026-08-26) accommodation: it
 * makes ordinary messages work through the standard update()/final()
 * API, at the honest cost of a hard ceiling -- anything larger fails
 * cleanly with CKR_BUFFER_TOO_SMALL, not silent truncation or
 * corruption.
 *
 * R30 found (live, via PKCS#11's own two-pass CKR_BUFFER_TOO_SMALL
 * convention: the failing call reports the buffer size it actually
 * needed) that the USABLE plaintext ceiling is this constant MINUS 16
 * (the tag length), not equal to it -- both engines' own AEAD decrypt
 * need one tag's worth of headroom beyond the real plaintext they
 * release, just at different call points (ChaCha20-Poly1305 reports it
 * needing msglen+taglen bytes at the tag-carrying DecryptUpdate call;
 * AES-GCM instead needs the full outsize at DecryptFinal, after
 * DecryptUpdate itself returns 0 -- same net effect via two different
 * internal shapes, confirmed by tracing both live rather than assuming
 * they'd match). AEAD_DECRYPT_MAX_MSG_LEN is therefore the DECLARED
 * block_size, deliberately larger than the promised usable ceiling by
 * a safety margin (64 bytes -- covers the observed 16-byte tag
 * overhead with room to spare for anything else not yet observed);
 * AEAD_DECRYPT_MAX_PLAINTEXT_LEN is the actual promise made to
 * callers. Do not use AEAD_DECRYPT_MAX_MSG_LEN as if it were the
 * usable ceiling -- messages at exactly that size will fail. */
#define AEAD_DECRYPT_MAX_PLAINTEXT_LEN 65536
#define AEAD_DECRYPT_MAX_MSG_LEN (AEAD_DECRYPT_MAX_PLAINTEXT_LEN + 64)

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

    /* Remediation item 1 (2026-08-30): CCM (CKM_AES_CCM), unlike GCM/
     * ChaCha20-Poly1305, needs the caller's TOTAL data length declared up
     * front in CK_CCM_PARAMS.ulDataLen (PKCS#11 v3.2 SS6.16.4 / RFC 3610's
     * own CBC-MAC construction bakes the length into the very first
     * block) -- a genuine mismatch with OpenSSL's own streaming
     * update()/final() EVP convention, which never promises the total
     * length until the LAST real update() call. Declared here from the
     * length of the FIRST real (non-AAD) update() call -- the same point
     * GCM's own CK_GCM_PARAMS gets built, in
     * p11prov_cipher_finish_aead_mech() -- covering the single-Update-
     * call pattern this provider's own AEAD callers (and every AEAD test
     * in this project's harness) already use. ccm_fed tracks bytes
     * actually handed to a real Encrypt/DecryptUpdate call since; a
     * caller genuinely splitting CCM data across more than one real
     * update() call would silently commit to the wrong ulDataLen, so
     * p11prov_cipher_update() rejects that loudly instead of producing
     * corrupt output. Unused (stays 0) for every other mechanism. */
    size_t ccm_datalen;
    size_t ccm_fed;

    /* CKM_CHACHA20 (stream, not AEAD): backing bytes for the
     * CK_CHACHA20_PARAMS pBlockCounter/pNonce pointers set in
     * prep_mech's own CKM_CHACHA20 case -- see that case's comment. */
    unsigned char chacha_iv_bytes[16];

    /* AES Key Wrap remediation item (2026-08-30): CKM_AES_KEY_WRAP/_KWP.
     * OpenSSL's own AES-WRAP ciphers do all their real work in a single
     * OSSL_FUNC_CIPHER_UPDATE call ("Multiple calls to update are not
     * allowed, since the algorithm relies on all fields being present" --
     * confirmed against providers/implementations/ciphers/
     * cipher_aes_wrp.c) and leave FINAL a pure no-op; wrap_done enforces
     * the same single-call contract here. See p11prov_aes_wrap_update()'s
     * own comment for why this mechanism family needs an entirely
     * different backing call (C_WrapKey/C_UnwrapKey, not C_EncryptInit/
     * C_EncryptUpdate/C_EncryptFinal) than every other cipher in this
     * file. Unused (stays false) for every other mechanism. */
    bool wrap_done;
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
/* AES-XTS remediation item (2026-08-30): cipher-registration only (the
 * CKK_AES_XTS double-width key-type/keymgmt concern is separate -- see
 * objects.c's own p11prov_obj_import_secret_key() comment). Streams like
 * CBC/CTS (arbitrary chunks straight through to C_EncryptUpdate/
 * C_DecryptUpdate, with the final chunk allowed to be shorter than a
 * block -- ciphertext stealing happens inside the real OpenSSL
 * EVP_aes_*_xts() cipher the engine calls, confirmed by reading
 * OSSLEVPSymmetricAlgorithm::encryptUpdate/Final directly: neither
 * function imposes any block-alignment check of its own), so it reuses
 * DISPATCH_TABLE_CIPHER_FN unchanged -- no AEAD, no CTS flag (XTS's own
 * stealing is unconditional, unlike CBC-CS's selectable cts_mode). */
#define MODE_xts 0x03
/* AES Key Wrap remediation item (2026-08-30): CKM_AES_KEY_WRAP (plain,
 * RFC 3394) and CKM_AES_KEY_WRAP_KWP (padded, RFC 5649 -- also used for
 * the deprecated CKM_AES_KEY_WRAP_PAD spelling; SoftHSM_keygen.cpp treats
 * both mechanism IDs as the exact same construction). Neither is a
 * streaming mode -- see p11prov_aes_wrap_update()'s own comment -- so
 * these use DISPATCH_TABLE_CIPHER_WRAP_FN, not DISPATCH_TABLE_CIPHER_FN. */
#define MODE_wrap 0x05
#define MODE_wrappad 0x06

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

/* AES Key Wrap remediation item (2026-08-30). Identical to
 * DISPATCH_TABLE_CIPHER_FN except UPDATE/FINAL point at the wrap-mode
 * pair (p11prov_aes_wrap_update/p11prov_aes_wrap_final, cipher.c) instead
 * of the generic streaming p11prov_cipher_update/p11prov_cipher_final --
 * see MODE_wrap/MODE_wrappad's own comment above and
 * p11prov_aes_wrap_update()'s own comment in cipher.c for why AES-WRAP
 * needs a genuinely different backing call than every other cipher this
 * file registers. Every other dispatch entry (newctx, init, dupctx,
 * get/set_ctx_params, ...) is shared verbatim with the streaming macro,
 * since key import and operation bookkeeping work identically either
 * way. */
#define DISPATCH_TABLE_CIPHER_WRAP_FN(cipher, size, mode, mechanism) \
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
        { OSSL_FUNC_CIPHER_UPDATE, \
          (void (*)(void))p11prov_aes_wrap_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p11prov_aes_wrap_final }, \
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

/* AES-XTS remediation item (2026-08-30): no 192-bit variant -- OpenSSL
 * itself only defines AES-128-XTS/AES-256-XTS (XTS combines two AES keys,
 * so each name's *total* key material is double its number: 256 bits =
 * two AES-128 keys, 512 bits = two AES-256 keys). */
extern const OSSL_DISPATCH p11prov_aes128xts_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256xts_cipher_functions[];

/* AES Key Wrap remediation item (2026-08-30): "wrap" registrations use
 * CKM_AES_KEY_WRAP (RFC 3394, plain); "wrappad" registrations use
 * CKM_AES_KEY_WRAP_KWP (RFC 5649, padded) for OpenSSL's "*-WRAP-PAD"
 * names -- see MODE_wrap/MODE_wrappad's own comment above for why a
 * single mechanism ID covers both the KWP and deprecated PAD spellings. */
extern const OSSL_DISPATCH p11prov_aes128wrap_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192wrap_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256wrap_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128wrappad_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192wrappad_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256wrappad_cipher_functions[];

extern const OSSL_DISPATCH p11prov_chacha20256stream_cipher_functions[];
extern const OSSL_DISPATCH p11prov_chacha20256poly1305_cipher_functions[];

#endif /* _CIPHER_H */
