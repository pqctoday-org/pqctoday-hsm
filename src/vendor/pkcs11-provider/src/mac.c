/* Copyright (C) 2026 SoftHSMv3 Contributors
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "digests.h"
#include <string.h>

/* R8 (OSSL_OP_MAC), phase-4 plan: token HMAC in bytes-in mode.
 *
 * Registered as a single generic "HMAC" algorithm, matching OpenSSL's
 * own default-provider convention (confirmed live:
 * `openssl list -mac-algorithms -provider default` shows one bare
 * "HMAC" name, not one name per digest) — the underlying digest
 * arrives at runtime via OSSL_MAC_PARAM_DIGEST (the same param
 * `openssl mac -digest SHA256 HMAC` sets), not baked into the
 * algorithm's registered name. A first attempt registered one
 * pre-bound name per digest (HMAC-SHA2-256 etc., modeled on
 * digests.c's own per-variant DISPATCH pattern) — that is a
 * legitimate, real algorithm identity per NIST/IANA naming, but it is
 * NOT what the standard `mac HMAC -digest ...` CLI invocation resolves
 * to, so it could never be reached by the exact command line the R8
 * plan's own proof step names; confirmed live via
 * `openssl list -mac-algorithms`, which showed the per-digest names
 * registered `@ pkcs11` correctly, while `mac HMAC -digest SHA256`
 * still silently resolved to `HMAC @ default` — zero engine-log
 * activity is what caught it, not a wrong output value (HMAC-SHA256 is
 * deterministic, so both providers produce byte-identical output
 * regardless of which one actually ran — output equality alone proves
 * nothing here, matching this whole project's standing R13 discipline).
 *
 * The key can arrive via init()'s own key/keylen args, via
 * OSSL_MAC_PARAM_KEY in either init()'s or a later set_ctx_params()
 * call's params[] — rather than guess which path openssl's own `mac`
 * app and EVP_MAC_init use, this stores whichever key (and whichever
 * digest choice) arrives first and defers the actual C_SignInit to the
 * first update() call, once both are certainly known. */

/* Phase 5 R23: CMAC and KMAC-128/256 join HMAC as real OSSL_OP_MAC
 * implementations, plus OSSL_FUNC_MAC_INIT_SKEY for all three (an R24
 * finding — a correctly-derived, correctly-opaque EVP_SKEY had nothing
 * in this provider that could consume it natively; HMAC never having
 * registered init_skey since R8 was the gap). */
/* WS-3/G2: AES-GMAC (CKM_AES_GMAC, PKCS#11 v3.2 §6.13.6) joins the other
 * three as a real OSSL_OP_MAC implementation — this file's own gap the
 * 2026-08-31 validation sweep found via `grep -rl GMAC
 * src/vendor/pkcs11-provider/src/` returning nothing, even though both
 * engines have supported CKM_AES_GMAC since WS-8. Unlike CMAC/KMAC, GMAC
 * needs a caller-supplied IV (there is no sensible default, same
 * reasoning HMAC's digest default does NOT apply here — an IV, unlike a
 * digest choice, must never be silently substituted: see this file's own
 * mac_ensure_signinit for the hard requirement and the security note on
 * IV reuse there). */
enum p11prov_mac_algo {
    MAC_ALGO_HMAC = 0,
    MAC_ALGO_CMAC,
    MAC_ALGO_KMAC128,
    MAC_ALGO_KMAC256,
    MAC_ALGO_GMAC,
};

struct p11prov_mac_ctx {
    P11PROV_CTX *provctx;
    enum p11prov_mac_algo algo;
    CK_MECHANISM_TYPE mechtype; /* CKM_SHA*_HMAC / CKM_AES_CMAC / CKM_KMAC_* /
                                 * CKM_AES_GMAC */
    size_t mac_size;

    P11PROV_SESSION *session;
    P11PROV_OBJ *key;
    bool key_is_skey; /* true: macctx->key is a caller-owned SKEY object
                       * (init_skey) — never created/destroyed here. */

    unsigned char *keybuf;
    size_t keylen;

    /* GMAC only: the caller-supplied IV (OSSL_MAC_PARAM_IV), forwarded
     * as CK_GCM_PARAMS.pIv/ulIvLen at C_SignInit time. */
    unsigned char *ivbuf;
    size_t ivlen;

    bool signinit_done;
};

typedef struct p11prov_mac_ctx P11PROV_MAC_CTX;

static CK_MECHANISM_TYPE hmac_mech_for_digest(CK_MECHANISM_TYPE digest_mech)
{
    switch (digest_mech) {
    case CKM_SHA_1:
        return CKM_SHA_1_HMAC;
    case CKM_SHA224:
        return CKM_SHA224_HMAC;
    case CKM_SHA256:
        return CKM_SHA256_HMAC;
    case CKM_SHA384:
        return CKM_SHA384_HMAC;
    case CKM_SHA512:
        return CKM_SHA512_HMAC;
    /* Remediation item 3 (2026-08-30 OpenSSL-provider gap audit): the
     * generic "HMAC" algorithm registers fine and is reachable with ANY
     * digest name via OSSL_MAC_PARAM_DIGEST, but this switch only ever
     * mapped the four digests above to their _HMAC mechanism -- every
     * other digest this engine actually advertises an _HMAC mechanism
     * for (values confirmed against src/lib/pkcs11/pkcs11t.h, not
     * guessed) fell through to CK_UNAVAILABLE_INFORMATION below. */
    case CKM_SHA512_224:
        return CKM_SHA512_224_HMAC;
    case CKM_SHA512_256:
        return CKM_SHA512_256_HMAC;
    case CKM_SHA3_224:
        return CKM_SHA3_224_HMAC;
    case CKM_SHA3_256:
        return CKM_SHA3_256_HMAC;
    case CKM_SHA3_384:
        return CKM_SHA3_384_HMAC;
    case CKM_SHA3_512:
        return CKM_SHA3_512_HMAC;
    default:
        return CK_UNAVAILABLE_INFORMATION;
    }
}

static void *mac_newctx_common(void *provctx, enum p11prov_mac_algo algo)
{
    P11PROV_MAC_CTX *macctx = OPENSSL_zalloc(sizeof(P11PROV_MAC_CTX));

    if (macctx == NULL) {
        return NULL;
    }
    macctx->provctx = (P11PROV_CTX *)provctx;
    macctx->algo = algo;
    macctx->mechtype = CK_UNAVAILABLE_INFORMATION;
    switch (algo) {
    case MAC_ALGO_CMAC:
        macctx->mechtype = CKM_AES_CMAC;
        break;
    case MAC_ALGO_KMAC128:
        macctx->mechtype = CKM_KMAC_128;
        macctx->mac_size = 32; /* fixed — see this file's own header
                                * comment on why KMAC's variable output
                                * length and customization string are
                                * not honored here. */
        break;
    case MAC_ALGO_KMAC256:
        macctx->mechtype = CKM_KMAC_256;
        macctx->mac_size = 64;
        break;
    case MAC_ALGO_GMAC:
        macctx->mechtype = CKM_AES_GMAC;
        /* mac_size stays 0 until OSSL_MAC_PARAM_CIPHER is set (mirrors
         * CMAC above) — see mac_set_gmac_cipher() and
         * mac_ensure_signinit()'s own requirement check. */
        break;
    case MAC_ALGO_HMAC:
    default:
        break;
    }
    return macctx;
}

static void *p11prov_hmac_mac_newctx(void *provctx)
{
    return mac_newctx_common(provctx, MAC_ALGO_HMAC);
}

static void *p11prov_cmac_mac_newctx(void *provctx)
{
    return mac_newctx_common(provctx, MAC_ALGO_CMAC);
}

static void *p11prov_kmac128_mac_newctx(void *provctx)
{
    return mac_newctx_common(provctx, MAC_ALGO_KMAC128);
}

static void *p11prov_kmac256_mac_newctx(void *provctx)
{
    return mac_newctx_common(provctx, MAC_ALGO_KMAC256);
}

static void *p11prov_gmac_mac_newctx(void *provctx)
{
    return mac_newctx_common(provctx, MAC_ALGO_GMAC);
}

static void p11prov_mac_freectx(void *vctx)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;

    P11PROV_debug("mac freectx %p", vctx);

    if (macctx == NULL) {
        return;
    }
    /* Both the raw-bytes-import path and init_skey take their own
     * p11prov_obj_ref (skeymgmt.c's own AES/GENERIC-SECRET keydata is a
     * P11PROV_OBJ*, refcounted the same way everywhere else in this
     * provider), so this free is unconditional and symmetric either
     * way — never a double-free against the caller's own EVP_SKEY_free,
     * which drops a SEPARATE reference. */
    p11prov_obj_free(macctx->key);
    p11prov_return_session(macctx->session);
    OPENSSL_clear_free(macctx->keybuf, macctx->keylen);
    /* GMAC's IV is not secret, but zeroing on free is free and matches
     * this file's own convention for every other caller-supplied buffer. */
    OPENSSL_clear_free(macctx->ivbuf, macctx->ivlen);
    OPENSSL_clear_free(macctx, sizeof(P11PROV_MAC_CTX));
}

static int mac_set_key(P11PROV_MAC_CTX *macctx, const unsigned char *key,
                       size_t keylen)
{
    OPENSSL_clear_free(macctx->keybuf, macctx->keylen);
    macctx->keybuf = OPENSSL_memdup(key, keylen);
    if (macctx->keybuf == NULL) {
        macctx->keylen = 0;
        return RET_OSSL_ERR;
    }
    macctx->keylen = keylen;
    return RET_OSSL_OK;
}

static int mac_set_digest(P11PROV_MAC_CTX *macctx, const char *digestname)
{
    CK_MECHANISM_TYPE digest_mech = CK_UNAVAILABLE_INFORMATION;
    CK_MECHANISM_TYPE hmac_mech;
    size_t digest_size = 0;
    CK_RV ret;

    ret = p11prov_digest_get_by_name(digestname, &digest_mech);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "Unknown MAC digest '%s'",
                      digestname);
        return RET_OSSL_ERR;
    }
    hmac_mech = hmac_mech_for_digest(digest_mech);
    if (hmac_mech == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(macctx->provctx, CKR_MECHANISM_INVALID,
                      "Digest '%s' has no matching HMAC mechanism in this "
                      "provider",
                      digestname);
        return RET_OSSL_ERR;
    }
    p11prov_digest_get_digest_size(digest_mech, &digest_size);
    macctx->mechtype = hmac_mech;
    macctx->mac_size = digest_size;
    return RET_OSSL_OK;
}

/* CMAC's own OSSL_MAC_PARAM_CIPHER name is validated, not forwarded to
 * the token: the engine always derives its actual CMAC cipher choice
 * from the imported base key's OWN byte length (SoftHSM_sign.cpp's own
 * kMacMechTable row for CKM_AES_CMAC has no per-cipher-variant split —
 * a single mechanism, `CryptoFactory`'s own `OSSLCMACAES` picks the AES
 * variant from the key it's handed), via plain CKM_AES_CMAC regardless
 * of which AES-CBC name a caller sends. Forwarding a mismatched name
 * would silently diverge from what actually runs — same reasoning, same
 * three accepted names, as R22's own KBKDF-CMAC handling. CMAC's own
 * output is always one AES block (16 bytes) regardless of key size. */
static int mac_set_cipher(P11PROV_MAC_CTX *macctx, const char *ciphername)
{
    if (OPENSSL_strcasecmp(ciphername, "AES-128-CBC") != 0
        && OPENSSL_strcasecmp(ciphername, "AES-192-CBC") != 0
        && OPENSSL_strcasecmp(ciphername, "AES-256-CBC") != 0) {
        P11PROV_raise(macctx->provctx, CKR_MECHANISM_INVALID,
                      "Cipher '%s' is not a plain AES-CBC name this "
                      "provider's CMAC can validate against the token's "
                      "own CKM_AES_CMAC",
                      ciphername);
        return RET_OSSL_ERR;
    }
    macctx->mechtype = CKM_AES_CMAC;
    macctx->mac_size = 16;
    return RET_OSSL_OK;
}

/* GMAC (CKM_AES_GMAC, PKCS#11 v3.2 §6.13.6) twin of mac_set_cipher()
 * above: the engine derives the actual AES variant from the imported
 * key's own byte length (SoftHSM_sign.cpp's kMacMechTable row for
 * CKM_AES_GMAC — CKK_AES, no CKK_GENERIC_SECRET alternative — and
 * OSSLGMAC::init's own switch on key->getBitLen(); rust/src/ffi.rs's
 * CKM_AES_GMAC sign/verify arms are keyed the same way), via plain
 * CKM_AES_GMAC regardless of which AES-GCM cipher name a caller sends —
 * so this only validates the name is a real AES-GCM name and, like the
 * default provider's own GMAC, requires ONE be set at all (confirmed
 * live: `openssl mac -macopt hexkey:... -macopt hexiv:... GMAC` with no
 * -cipher fails against the DEFAULT provider too — "invalid key
 * length" — because the default implementation has no key to infer a
 * variant from until a cipher name arrives). GMAC's natural tag is
 * always one AES block (16 bytes, SP800-38D) regardless of key size —
 * same as CMAC — before any caller truncation via OSSL_MAC_PARAM_SIZE. */
static int mac_set_gmac_cipher(P11PROV_MAC_CTX *macctx, const char *ciphername)
{
    if (OPENSSL_strcasecmp(ciphername, "AES-128-GCM") != 0
        && OPENSSL_strcasecmp(ciphername, "AES-192-GCM") != 0
        && OPENSSL_strcasecmp(ciphername, "AES-256-GCM") != 0) {
        P11PROV_raise(macctx->provctx, CKR_MECHANISM_INVALID,
                      "Cipher '%s' is not a plain AES-GCM name this "
                      "provider's GMAC can validate against the token's "
                      "own CKM_AES_GMAC",
                      ciphername);
        return RET_OSSL_ERR;
    }
    macctx->mac_size = 16;
    return RET_OSSL_OK;
}

/* GMAC's IV (OSSL_MAC_PARAM_IV): unlike HMAC's digest, there is no
 * sensible default this provider can substitute — GCM/GMAC's whole
 * authentication guarantee depends on the (key, IV) pair never
 * repeating (NIST SP 800-38D §8.3), so silently picking one (e.g. all-
 * zero) would be a real security defect, not a convenience. The caller
 * MUST supply it; mac_ensure_signinit() enforces that at C_SignInit
 * time. This provider does not generate or manage IVs across calls —
 * it is a thin passthrough of whatever the caller sets, same trust
 * boundary as every other MAC key/param in this file. */
static int mac_set_iv(P11PROV_MAC_CTX *macctx, const unsigned char *iv,
                      size_t ivlen)
{
    OPENSSL_clear_free(macctx->ivbuf, macctx->ivlen);
    macctx->ivbuf = OPENSSL_memdup(iv, ivlen);
    if (macctx->ivbuf == NULL) {
        macctx->ivlen = 0;
        return RET_OSSL_ERR;
    }
    macctx->ivlen = ivlen;
    return RET_OSSL_OK;
}

static int p11prov_mac_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    const OSSL_PARAM *p;

    P11PROV_debug("mac set ctx params %p", vctx);

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p != NULL) {
        char digestname[64] = { 0 };
        char *namep = digestname;

        if (OSSL_PARAM_get_utf8_string(p, &namep, sizeof(digestname))
            != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
        if (mac_set_digest(macctx, digestname) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CIPHER);
    if (p != NULL) {
        char ciphername[32] = { 0 };
        char *namep = ciphername;

        if (OSSL_PARAM_get_utf8_string(p, &namep, sizeof(ciphername))
            != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
        if (macctx->algo == MAC_ALGO_GMAC) {
            if (mac_set_gmac_cipher(macctx, ciphername) != RET_OSSL_OK) {
                return RET_OSSL_ERR;
            }
        } else if (mac_set_cipher(macctx, ciphername) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    /* GMAC's IV — see mac_set_iv()'s own comment on why this has no
     * default and must be a thin passthrough. */
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_IV);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            return RET_OSSL_ERR;
        }
        if (mac_set_iv(macctx, p->data, p->data_size) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    /* KMAC's own customization string S and variable output length are
     * not honorable — the engine's OSSLKMACAlgorithm always uses an
     * empty S and a fixed size per variant (OSSLKMAC.h: KMAC-128 -> 32,
     * KMAC-256 -> 64, confirmed by reading it directly, not assumed).
     * Reject a caller's attempt to set either to something else, rather
     * than silently keeping the token's own fixed behavior while
     * claiming to have honored the request. */
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CUSTOM);
    if (p != NULL) {
        if (p->data_size != 0) {
            P11PROV_raise(macctx->provctx, CKR_MECHANISM_PARAM_INVALID,
                          "This provider's KMAC has no way to pass a "
                          "customization string to the token — only an "
                          "empty one is honorable");
            return RET_OSSL_ERR;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL && (macctx->algo == MAC_ALGO_KMAC128
                      || macctx->algo == MAC_ALGO_KMAC256)) {
        size_t want;

        if (OSSL_PARAM_get_size_t(p, &want) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
        if (want != macctx->mac_size) {
            P11PROV_raise(macctx->provctx, CKR_MECHANISM_PARAM_INVALID,
                          "This provider's KMAC output length is fixed "
                          "at %zu bytes by the token — %zu is not "
                          "honorable",
                          macctx->mac_size, want);
            return RET_OSSL_ERR;
        }
    }

    /* Unlike KMAC's fixed output length above, GMAC's tag genuinely IS
     * truncatable — both engines honor CK_GCM_PARAMS.ulTagBits directly
     * (SoftHSM_sign.cpp's applyGmacParams, rust/src/ffi.rs's CKM_AES_GMAC
     * arms), same as PKCS#11 v3.2 §6.13.6 itself allows (1-128 bits, in
     * 8-bit steps — the underlying token additionally requires a whole
     * number of bytes, matching NIST SP 800-38D's own recommended tag
     * lengths). Requires OSSL_MAC_PARAM_CIPHER to have already set the
     * natural 16-byte size (same ordering CMAC's own SIZE handling would
     * need, but CMAC never allows truncation at all). */
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL && macctx->algo == MAC_ALGO_GMAC) {
        size_t want;

        if (OSSL_PARAM_get_size_t(p, &want) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
        if (want == 0 || want > 16) {
            P11PROV_raise(macctx->provctx, CKR_MECHANISM_PARAM_INVALID,
                          "This provider's GMAC tag length must be 1-16 "
                          "bytes — %zu is not honorable",
                          want);
            return RET_OSSL_ERR;
        }
        macctx->mac_size = want;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            return RET_OSSL_ERR;
        }
        if (mac_set_key(macctx, p->data, p->data_size) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mac_settable_ctx_params(void *vctx,
                                                         void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_CUSTOM, NULL, 0),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_IV, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_mac_init(void *vctx, const unsigned char *key,
                            size_t keylen, const OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;

    P11PROV_debug("mac init %p key=%p keylen=%zu", vctx, (const void *)key,
                  keylen);

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (key != NULL) {
        if (mac_set_key(macctx, key, keylen) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }
    return p11prov_mac_set_ctx_params(vctx, params);
}

static int mac_ensure_signinit(P11PROV_MAC_CTX *macctx)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_SESSION_HANDLE sess;
    CK_MECHANISM mechanism = { 0 };
    CK_OBJECT_HANDLE hkey;
    CK_RV ret;

    if (macctx->signinit_done) {
        return RET_OSSL_OK;
    }
    if (!macctx->key_is_skey && macctx->keybuf == NULL) {
        P11PROV_raise(macctx->provctx, CKR_KEY_INDIGESTIBLE,
                      "MAC key was never set");
        return RET_OSSL_ERR;
    }
    if (macctx->algo == MAC_ALGO_HMAC
        && macctx->mechtype == CK_UNAVAILABLE_INFORMATION) {
        /* No OSSL_MAC_PARAM_DIGEST arrived — default to SHA2-256,
         * matching the default provider's own HMAC default digest. */
        if (mac_set_digest(macctx, "SHA2-256") != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }
    if (macctx->algo == MAC_ALGO_CMAC && macctx->mac_size == 0) {
        /* CMAC has no sensible default cipher (unlike HMAC's digest) —
         * the AES key size is intrinsic to the key, not guessable. */
        P11PROV_raise(macctx->provctx, CKR_MECHANISM_PARAM_INVALID,
                      "CMAC requires OSSL_MAC_PARAM_CIPHER to be set");
        return RET_OSSL_ERR;
    }
    if (macctx->algo == MAC_ALGO_GMAC) {
        if (macctx->mac_size == 0) {
            /* Same reasoning as CMAC above — no sensible default cipher
             * name, the AES key size is intrinsic to the key. */
            P11PROV_raise(macctx->provctx, CKR_MECHANISM_PARAM_INVALID,
                          "GMAC requires OSSL_MAC_PARAM_CIPHER to be set");
            return RET_OSSL_ERR;
        }
        if (macctx->ivbuf == NULL || macctx->ivlen == 0) {
            /* SECURITY: GMAC/GCM's authentication guarantee depends
             * entirely on the (key, IV) pair never repeating (NIST SP
             * 800-38D §8.3) — this provider refuses to invent one
             * (e.g. all-zero) rather than ship a silent nonce-reuse
             * trap. The caller (and, transitively, whatever generated
             * the caller's IV) is solely responsible for IV uniqueness
             * per key; this provider neither generates nor tracks IVs
             * across calls. */
            P11PROV_raise(macctx->provctx, CKR_MECHANISM_PARAM_INVALID,
                          "GMAC requires OSSL_MAC_PARAM_IV to be set");
            return RET_OSSL_ERR;
        }
    }

    ret = p11prov_get_session(macctx->provctx, &slotid, NULL, NULL,
                              macctx->mechtype, NULL, NULL, false, false,
                              &macctx->session);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "Failed to open new session");
        return RET_OSSL_ERR;
    }
    sess = p11prov_session_handle(macctx->session);

    /* init_skey already supplied a real, existing token key object —
     * nothing to create, and the raw bytes were never seen. */
    if (!macctx->key_is_skey) {
        macctx->key = p11prov_create_mac_key(
            macctx->provctx, macctx->session,
            (macctx->algo == MAC_ALGO_CMAC || macctx->algo == MAC_ALGO_GMAC)
                ? CKK_AES
                : CKK_GENERIC_SECRET,
            macctx->keybuf, macctx->keylen);
        if (macctx->key == NULL) {
            return RET_OSSL_ERR;
        }
    }
    hkey = p11prov_obj_get_handle(macctx->key);

    mechanism.mechanism = macctx->mechtype;
    if (macctx->algo == MAC_ALGO_GMAC) {
        /* CK_GCM_PARAMS (PKCS#11 v3.2 §6.13.6 for GMAC, struct shared
         * with CKM_AES_GCM's own §6.13.4) — pAAD/ulAADLen are left NULL/0
         * on purpose: GMAC's authenticated input is the C_Sign/
         * C_SignUpdate data itself, not a separate AAD field inside this
         * struct (confirmed against both engines: SoftHSM_sign.cpp's
         * applyGmacParams() reads only pIv/ulIvLen/ulTagBits from it, and
         * rust/src/ck_param.rs's own gcm layout comment on the sign path
         * matches). ulIvBits is set for completeness/spec-conformance
         * even though neither engine reads it (both derive the IV length
         * from ulIvLen). */
        CK_GCM_PARAMS gcm_params = { 0 };

        gcm_params.pIv = macctx->ivbuf;
        gcm_params.ulIvLen = macctx->ivlen;
        gcm_params.ulIvBits = macctx->ivlen * 8;
        gcm_params.ulTagBits = macctx->mac_size * 8;
        mechanism.pParameter = &gcm_params;
        mechanism.ulParameterLen = sizeof(gcm_params);
        ret = p11prov_SignInit(macctx->provctx, sess, &mechanism, hkey);
        if (ret != CKR_OK) {
            P11PROV_raise(macctx->provctx, ret, "C_SignInit failed");
            return RET_OSSL_ERR;
        }
        macctx->signinit_done = true;
        return RET_OSSL_OK;
    }
    ret = p11prov_SignInit(macctx->provctx, sess, &mechanism, hkey);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "C_SignInit failed");
        return RET_OSSL_ERR;
    }
    macctx->signinit_done = true;
    return RET_OSSL_OK;
}

/* OSSL_FUNC_MAC_INIT_SKEY (phase 5 R23, an R24 finding): `provkey` is
 * this provider's own SKEYMGMT keydata — for AES/GENERIC-SECRET
 * (skeymgmt.c) that IS a P11PROV_OBJ*, the exact same object type this
 * file already signs with, confirmed by reading skeymgmt.c's own
 * generate/import functions directly (they return P11PROV_OBJ* as their
 * void* keydata). No raw bytes ever cross into this function — the key
 * stays opaque end to end, closing the gap R24's probe found (a
 * correctly-derived, correctly-opaque EVP_SKEY had nothing in this
 * provider that could consume it natively). */
static int p11prov_mac_init_skey(void *vctx, void *provkey,
                                 const OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    P11PROV_OBJ *keyobj = (P11PROV_OBJ *)provkey;
    CK_KEY_TYPE want_type;
    CK_KEY_TYPE got_type;

    P11PROV_debug("mac init_skey %p key=%p", vctx, provkey);

    if (macctx == NULL || keyobj == NULL) {
        return RET_OSSL_ERR;
    }

    want_type = (macctx->algo == MAC_ALGO_CMAC || macctx->algo == MAC_ALGO_GMAC)
                    ? CKK_AES
                    : CKK_GENERIC_SECRET;
    got_type = p11prov_obj_get_key_type(keyobj);
    if (got_type != want_type) {
        P11PROV_raise(macctx->provctx, CKR_KEY_TYPE_INCONSISTENT,
                      "SKEY key type 0x%lx does not match what this MAC "
                      "needs (0x%lx)",
                      (unsigned long)got_type, (unsigned long)want_type);
        return RET_OSSL_ERR;
    }

    p11prov_obj_free(macctx->key);
    macctx->key = p11prov_obj_ref(keyobj);
    if (macctx->key == NULL) {
        return RET_OSSL_ERR;
    }
    macctx->key_is_skey = true;

    return p11prov_mac_set_ctx_params(vctx, params);
}

static int p11prov_mac_update(void *vctx, const unsigned char *data,
                              size_t datalen)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    CK_SESSION_HANDLE sess;
    CK_RV ret;

    P11PROV_debug("mac update %p len=%zu", vctx, datalen);

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (mac_ensure_signinit(macctx) != RET_OSSL_OK) {
        return RET_OSSL_ERR;
    }
    if (datalen == 0) {
        return RET_OSSL_OK;
    }

    sess = p11prov_session_handle(macctx->session);
    ret = p11prov_SignUpdate(macctx->provctx, sess, (CK_BYTE_PTR)data,
                             datalen);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "C_SignUpdate failed");
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_mac_final(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    CK_SESSION_HANDLE sess;
    CK_ULONG siglen;
    CK_RV ret;

    P11PROV_debug("mac final %p outsize=%zu", vctx, outsize);

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (mac_ensure_signinit(macctx) != RET_OSSL_OK) {
        return RET_OSSL_ERR;
    }
    if (outsize < macctx->mac_size) {
        P11PROV_raise(macctx->provctx, CKR_BUFFER_TOO_SMALL,
                      "MAC output buffer too small");
        return RET_OSSL_ERR;
    }

    sess = p11prov_session_handle(macctx->session);
    siglen = macctx->mac_size;
    ret = p11prov_SignFinal(macctx->provctx, sess, out, &siglen);
    if (ret != CKR_OK) {
        P11PROV_raise(macctx->provctx, ret, "C_SignFinal failed");
        return RET_OSSL_ERR;
    }
    *outl = siglen;
    return RET_OSSL_OK;
}

static int p11prov_hmac_mac_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    /* Static, digest-independent max: SHA2-512's 64 bytes. The real,
     * digest-specific size is only known once OSSL_MAC_PARAM_DIGEST has
     * been set (mac_set_digest) and is reported via get_ctx_params in a
     * live context, not this static, context-free get_params. */
    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL) {
        if (OSSL_PARAM_set_size_t(p, 64) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mac_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

/* CMAC/KMAC-128/KMAC-256 each have one fixed size (unlike HMAC's
 * digest-dependent one), so their own static get_params reports it
 * exactly rather than a generic upper bound. */
static int mac_get_params_fixed(OSSL_PARAM params[], size_t size)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL) {
        if (OSSL_PARAM_set_size_t(p, size) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }
    return RET_OSSL_OK;
}

static int p11prov_cmac_mac_get_params(OSSL_PARAM params[])
{
    return mac_get_params_fixed(params, 16);
}

static int p11prov_kmac128_mac_get_params(OSSL_PARAM params[])
{
    return mac_get_params_fixed(params, 32);
}

static int p11prov_kmac256_mac_get_params(OSSL_PARAM params[])
{
    return mac_get_params_fixed(params, 64);
}

/* GMAC's natural (untruncated) tag is 16 bytes — this static,
 * context-free get_params reports that default the same way CMAC's own
 * does above; the real, possibly-truncated size (OSSL_MAC_PARAM_SIZE) is
 * only known once a live context exists, and is reported by
 * p11prov_mac_get_ctx_params below. */
static int p11prov_gmac_mac_get_params(OSSL_PARAM params[])
{
    return mac_get_params_fixed(params, 16);
}

static int p11prov_mac_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)vctx;
    OSSL_PARAM *p;

    if (macctx == NULL) {
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL) {
        size_t size = macctx->mac_size != 0 ? macctx->mac_size : 64;
        if (OSSL_PARAM_set_size_t(p, size) != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mac_gettable_ctx_params(void *vctx,
                                                         void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_hmac_mac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p11prov_hmac_mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))p11prov_mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))p11prov_mac_init },
    { OSSL_FUNC_MAC_INIT_SKEY, (void (*)(void))p11prov_mac_init_skey },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))p11prov_mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))p11prov_mac_final },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_set_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_settable_ctx_params },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))p11prov_hmac_mac_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mac_gettable_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_get_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_gettable_ctx_params },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_cmac_mac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p11prov_cmac_mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))p11prov_mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))p11prov_mac_init },
    { OSSL_FUNC_MAC_INIT_SKEY, (void (*)(void))p11prov_mac_init_skey },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))p11prov_mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))p11prov_mac_final },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_set_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_settable_ctx_params },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))p11prov_cmac_mac_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mac_gettable_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_get_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_gettable_ctx_params },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_kmac128_mac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p11prov_kmac128_mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))p11prov_mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))p11prov_mac_init },
    { OSSL_FUNC_MAC_INIT_SKEY, (void (*)(void))p11prov_mac_init_skey },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))p11prov_mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))p11prov_mac_final },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_set_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_settable_ctx_params },
    { OSSL_FUNC_MAC_GET_PARAMS,
      (void (*)(void))p11prov_kmac128_mac_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mac_gettable_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_get_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_gettable_ctx_params },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_kmac256_mac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p11prov_kmac256_mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))p11prov_mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))p11prov_mac_init },
    { OSSL_FUNC_MAC_INIT_SKEY, (void (*)(void))p11prov_mac_init_skey },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))p11prov_mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))p11prov_mac_final },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_set_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_settable_ctx_params },
    { OSSL_FUNC_MAC_GET_PARAMS,
      (void (*)(void))p11prov_kmac256_mac_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mac_gettable_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_get_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_gettable_ctx_params },
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_gmac_mac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))p11prov_gmac_mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))p11prov_mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))p11prov_mac_init },
    { OSSL_FUNC_MAC_INIT_SKEY, (void (*)(void))p11prov_mac_init_skey },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))p11prov_mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))p11prov_mac_final },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_set_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_settable_ctx_params },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))p11prov_gmac_mac_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,
      (void (*)(void))p11prov_mac_gettable_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,
      (void (*)(void))p11prov_mac_get_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))p11prov_mac_gettable_ctx_params },
    { 0, NULL },
};
