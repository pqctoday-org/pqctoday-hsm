/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* skey-flow-probe: phase-5 R24 (F36-3) test helper. Answers the
 * question OpenSSL 3.6's new EVP_SKEY opaque-key API raised and phases
 * 1-4 never probed: does a token-resident secret genuinely stay
 * token-resident end-to-end through generate -> KDF-derive -> consume,
 * or does its raw material leak into software somewhere along the way?
 *
 * Three checks, in order:
 *   1. EVP_SKEY_generate() over this provider's AES/GENERIC-SECRET
 *      SKEYMGMT (skeymgmt.c) actually creates a token object, not a
 *      software one — EVP_SKEY_get0_provider_name() must read "pkcs11".
 *   2. EVP_KDF_derive_SKEY() over HKDF (kdf.c already implements
 *      SET_SKEY/DERIVE_SKEY, gated on OSSL_FUNC_KDF_DERIVE_SKEY —
 *      confirmed present in this build by reading kdf.c directly, not
 *      assumed) produces a derived key that ALSO stays on-token, and
 *      is CRYPTOGRAPHICALLY CORRECT: known input bytes are imported as
 *      an SKEY, derived through HKDF entirely inside the token, then
 *      consumed by EVP_MAC_init_SKEY (HMAC) without ever exporting the
 *      intermediate derived-key-material — the resulting MAC is
 *      compared against an independently-computed, pure-software
 *      HKDF+HMAC of the SAME known input, salt, info, and digest. A
 *      match proves the opaque chain is correct without ever seeing
 *      the DKM in the clear; disagreement would mean either the
 *      derive or the consume step is wrong.
 *   3. TLS13-KDF gets the same derive_SKEY existence+opacity check
 *      (lighter than HKDF's — HKDF-Expand-Label's prefix/label/data
 *      shape isn't independently cross-checked here, just that it
 *      derives, stays opaque, and the resulting key is usable).
 *   4. Negative control: PBKDF2 (R10) deliberately has no SET_SKEY/
 *      DERIVE_SKEY (no base-key-object concept — its secret travels as
 *      a literal password in CK_PKCS5_PBKD2_PARAMS2) — confirm
 *      EVP_KDF_derive_SKEY cleanly fails against it rather than
 *      silently degrading to something wrong.
 *
 * Run under PKCS11_PROVIDER_DEBUG (provider-side dispatch trace) and
 * SOFTHSM2_CONF log.level=DEBUG (engine-side C_DeriveKey/C_GenerateKey/
 * C_Sign trace) — the caller's shell wrapper greps both afterward for
 * real token participation, the same R13 discipline every other live
 * proof in this project's harness uses. */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

static const unsigned char KNOWN_SECRET[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const unsigned char SALT[8] = { 's', 'a', 'l', 't', '0', '1', '2', '3' };
static const unsigned char INFO[8] = { 'i', 'n', 'f', 'o', '0', '1', '2', '3' };
static const unsigned char MESSAGE[] = "skey-flow-probe test message";

/* ── check 1: plain EVP_SKEY_generate over pkcs11 SKEYMGMT ────────────── */
static int check_generate(const char *skeymgmtname)
{
    OSSL_PARAM params[2];
    size_t keylen = 32;
    EVP_SKEY *skey;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_SKEY_PARAM_KEY_LENGTH,
                                            &keylen);
    params[1] = OSSL_PARAM_construct_end();

    skey = EVP_SKEY_generate(NULL, skeymgmtname, "?provider=pkcs11", params);
    if (!skey) {
        fprintf(stderr, "  EVP_SKEY_generate(%s) returned NULL\n",
                skeymgmtname);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    const char *prov = EVP_SKEY_get0_provider_name(skey);
    const char *keyid = EVP_SKEY_get0_key_id(skey);
    printf("  %-14s generate: provider=%s key_id=%s\n", skeymgmtname,
           prov ? prov : "(null)", keyid ? keyid : "(null)");

    int ok = prov && strcmp(prov, "pkcs11") == 0 && keyid
             && strncmp(keyid, "pkcs11:", 7) == 0;
    EVP_SKEY_free(skey);
    return ok ? 0 : 1;
}

/* ── independent, pure-software HKDF + HMAC of the SAME known inputs ──── */
static int software_expected_mac(unsigned char *out, size_t *outlen)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    unsigned char dkm[32];
    OSSL_PARAM kparams[5];
    OSSL_PARAM mparams[2];
    int rv = 1;

    kdf = EVP_KDF_fetch(NULL, "HKDF", "provider=default");
    if (!kdf) {
        fprintf(stderr, "  software HKDF fetch failed\n");
        goto done;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) goto done;

    kparams[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                  "SHA256", 0);
    kparams[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)KNOWN_SECRET, sizeof(KNOWN_SECRET));
    kparams[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   (void *)SALT, sizeof(SALT));
    kparams[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                   (void *)INFO, sizeof(INFO));
    kparams[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, dkm, sizeof(dkm), kparams) <= 0) {
        fprintf(stderr, "  software HKDF derive failed\n");
        goto done;
    }

    mac = EVP_MAC_fetch(NULL, "HMAC", "provider=default");
    if (!mac) goto done;
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx) goto done;

    mparams[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    mparams[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(mctx, dkm, sizeof(dkm), mparams) <= 0) goto done;
    if (EVP_MAC_update(mctx, MESSAGE, sizeof(MESSAGE) - 1) <= 0) goto done;
    if (EVP_MAC_final(mctx, out, outlen, EVP_MAX_MD_SIZE) <= 0) goto done;

    rv = 0;
done:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return rv;
}

/* ── check 2/3: token-side derive_SKEY chain, opaque end to end ───────── */
static int check_derive_skey_chain(const char *kdfname, int full_crosscheck)
{
    EVP_SKEY *input_skey = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    EVP_SKEYMGMT *out_mgmt = NULL;
    EVP_SKEY *derived = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM kparams[6];
    OSSL_PARAM mparams[2];
    unsigned char token_mac[EVP_MAX_MD_SIZE];
    unsigned char sw_mac[EVP_MAX_MD_SIZE];
    size_t token_mac_len = 0, sw_mac_len = 0;
    int rv = 1;

    input_skey = EVP_SKEY_import_raw_key(NULL, "GENERIC-SECRET",
                                         (unsigned char *)KNOWN_SECRET,
                                         sizeof(KNOWN_SECRET),
                                         "?provider=pkcs11");
    if (!input_skey) {
        fprintf(stderr, "  [%s] import known secret as SKEY failed\n",
                kdfname);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    kdf = EVP_KDF_fetch(NULL, kdfname, "?provider=pkcs11");
    if (!kdf) {
        fprintf(stderr, "  [%s] fetch failed\n", kdfname);
        goto done;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) goto done;

    if (EVP_KDF_CTX_set_SKEY(kctx, input_skey, OSSL_KDF_PARAM_KEY) <= 0) {
        fprintf(stderr, "  [%s] EVP_KDF_CTX_set_SKEY failed\n", kdfname);
        ERR_print_errors_fp(stderr);
        goto done;
    }

    /* R31 correction (2026-08-26): the comment this replaced claimed
     * EXTRACT_ONLY needed just a salt, "without needing a full
     * HKDF-Expand-Label prefix/label/data triple" — that was the actual
     * source of the "TLS13-KDF derive_SKEY returned NULL" anomaly this
     * probe's own header flagged as unexplained. It's wrong:
     * p11prov_tls13_derive_secret() (kdf.c) — EXTRACT_ONLY's own
     * implementation — internally converts the caller's salt into a
     * derivation key via a p11prov_tls13_expand_label() sub-call (TLS
     * 1.3's Derive-Secret is itself built from HKDF-Expand-Label, RFC
     * 8446 §7.1), which unconditionally requires prefix+label and
     * rejects a NULL/empty pair. That internal call is legitimate
     * behavior, not a mode-routing bug — the live debug trace "reaching
     * p11prov_tls13_expand_label" while in the EXTRACT_ONLY branch (which
     * a prior investigation read as evidence of the WRONG branch running)
     * is exactly this expected sub-call. Supply a real prefix/label pair
     * (TLS 1.3's own "tls13 " prefix and "derived" label, the exact pair
     * used between the Early and Handshake Secret stages of the real key
     * schedule) so this check actually exercises and verifies the derive,
     * not just its existence. */
    if (strcmp(kdfname, "TLS13-KDF") == 0) {
        static const unsigned char tls13_prefix[] = "tls13 ";
        static const unsigned char tls13_label[] = "derived";
        kparams[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                      "SHA256", 0);
        kparams[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE,
                                                       "EXTRACT_ONLY", 0);
        kparams[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                       (void *)SALT,
                                                       sizeof(SALT));
        kparams[3] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PREFIX, (void *)tls13_prefix,
            sizeof(tls13_prefix) - 1);
        kparams[4] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_LABEL, (void *)tls13_label,
            sizeof(tls13_label) - 1);
        kparams[5] = OSSL_PARAM_construct_end();
    } else {
        kparams[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                      "SHA256", 0);
        kparams[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                       (void *)SALT,
                                                       sizeof(SALT));
        kparams[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                       (void *)INFO,
                                                       sizeof(INFO));
        kparams[3] = OSSL_PARAM_construct_end();
    }

    out_mgmt = EVP_SKEYMGMT_fetch(NULL, "GENERIC-SECRET", "?provider=pkcs11");
    if (!out_mgmt) {
        fprintf(stderr, "  [%s] EVP_SKEYMGMT_fetch(GENERIC-SECRET) failed\n",
                kdfname);
        goto done;
    }

    derived = EVP_KDF_derive_SKEY(kctx, out_mgmt, "GENERIC-SECRET",
                                  "?provider=pkcs11", 32, kparams);
    if (!derived) {
        fprintf(stderr, "  [%s] EVP_KDF_derive_SKEY returned NULL\n",
                kdfname);
        ERR_print_errors_fp(stderr);
        goto done;
    }

    const char *dprov = EVP_SKEY_get0_provider_name(derived);
    const char *dkeyid = EVP_SKEY_get0_key_id(derived);
    printf("  [%s] derived SKEY: provider=%s key_id=%s\n", kdfname,
           dprov ? dprov : "(null)", dkeyid ? dkeyid : "(null)");
    if (!dprov || strcmp(dprov, "pkcs11") != 0 || !dkeyid
        || strncmp(dkeyid, "pkcs11:", 7) != 0) {
        fprintf(stderr, "  [%s] derived SKEY is not token-resident\n",
                kdfname);
        goto done;
    }
    printf("  [%s] derive_SKEY PASSED (key stays token-resident)\n", kdfname);

    mac = EVP_MAC_fetch(NULL, "HMAC", "?provider=pkcs11");
    if (!mac) {
        fprintf(stderr, "  [%s] token HMAC fetch failed\n", kdfname);
        goto done;
    }
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx) goto done;

    mparams[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    mparams[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init_SKEY(mctx, derived, mparams) <= 0) {
        fprintf(stderr,
                "  [%s] EVP_MAC_init_SKEY(derived) failed — this is a "
                "SEPARATE gap from derive_SKEY (which just PASSED above): "
                "mac.c's HMAC implementation has never registered "
                "OSSL_FUNC_MAC_INIT_SKEY, only the classic raw-bytes INIT, "
                "so EVP_MAC_init_SKEY's own precondition check (ctx->meth->"
                "init_skey != NULL, crypto/evp/mac_lib.c) fails before "
                "reaching any provider code\n",
                kdfname);
        ERR_print_errors_fp(stderr);
        goto done;
    }
    if (EVP_MAC_update(mctx, MESSAGE, sizeof(MESSAGE) - 1) <= 0) goto done;
    if (EVP_MAC_final(mctx, token_mac, &token_mac_len, sizeof(token_mac))
        <= 0)
        goto done;

    printf("  [%s] chained-consume (EVP_MAC_init_SKEY) succeeded, %zu-byte "
           "MAC produced entirely opaque\n",
           kdfname, token_mac_len);

    if (!full_crosscheck) {
        rv = 0;
        goto done;
    }

    if (software_expected_mac(sw_mac, &sw_mac_len) != 0) {
        fprintf(stderr, "  [%s] software cross-check computation failed\n",
                kdfname);
        goto done;
    }

    if (token_mac_len != sw_mac_len
        || memcmp(token_mac, sw_mac, token_mac_len) != 0) {
        fprintf(stderr,
                "  [%s] MISMATCH: opaque token chain != independent "
                "software HKDF+HMAC of the same known inputs\n",
                kdfname);
        goto done;
    }
    printf("  [%s] cross-check PASSED: opaque token chain byte-identical to "
           "independent software HKDF+HMAC of the same known input/salt/"
           "info/digest\n",
           kdfname);

    rv = 0;
done:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    EVP_SKEY_free(derived);
    EVP_SKEYMGMT_free(out_mgmt);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    EVP_SKEY_free(input_skey);
    return rv;
}

/* ── negative control: PBKDF2 (R10) must NOT support derive_SKEY ──────── */
static int check_pbkdf2_has_no_derive_skey(void)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    EVP_SKEYMGMT *mgmt;
    EVP_SKEY *derived;
    int rv = 1;

    kdf = EVP_KDF_fetch(NULL, "PBKDF2", "?provider=pkcs11");
    if (!kdf) {
        fprintf(stderr, "  PBKDF2 fetch itself failed (unexpected)\n");
        return 1;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    mgmt = EVP_SKEYMGMT_fetch(NULL, "GENERIC-SECRET", "?provider=pkcs11");

    ERR_set_mark();
    derived = EVP_KDF_derive_SKEY(kctx, mgmt, "GENERIC-SECRET",
                                  "?provider=pkcs11", 32, NULL);
    ERR_pop_to_mark();

    if (derived) {
        fprintf(stderr,
                "  PBKDF2 EVP_KDF_derive_SKEY unexpectedly SUCCEEDED — R10's "
                "documented scoping (no SET_SKEY/DERIVE_SKEY) has changed\n");
        EVP_SKEY_free(derived);
    } else {
        printf("  PBKDF2 EVP_KDF_derive_SKEY correctly fails (no base-key "
               "concept — R10's scoping confirmed still accurate)\n");
        rv = 0;
    }

    EVP_SKEYMGMT_free(mgmt);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return rv;
}

int main(void)
{
    int failures = 0;

    printf("=== check 1: EVP_SKEY_generate over pkcs11 SKEYMGMT ===\n");
    failures += check_generate("AES");
    failures += check_generate("GENERIC-SECRET");

    printf("=== check 2: HKDF derive_SKEY -> HMAC init_SKEY, opaque chain, "
           "cross-checked vs software ===\n");
    failures += check_derive_skey_chain("HKDF", 1);

    printf("=== check 3: TLS13-KDF derive_SKEY -> HMAC init_SKEY, opaque "
           "chain (existence + opacity only) ===\n");
    failures += check_derive_skey_chain("TLS13-KDF", 0);

    printf("=== check 4: PBKDF2 negative control (no derive_SKEY, R10's own "
           "scoping) ===\n");
    failures += check_pbkdf2_has_no_derive_skey();

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nAll checks PASSED\n");
    return 0;
}
