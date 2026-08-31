/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* lms-xdr-verify: phase-4 R9 cross-implementation proof. Verifies an
 * HSS-token-produced signature using OpenSSL 3.6.3's OWN, independent,
 * from-scratch LMS implementation — never the pkcs11-provider, never the
 * engine's own C_Verify. "Token signs, an unrelated implementation
 * verifies" is the actual point of this check (see the phase-4 plan's R9
 * section) — self-consistency between an engine's C_Sign and its own
 * C_Verify would not catch a signer that's wrong in a way its own
 * verifier is equally wrong about.
 *
 * Two format transforms are required, both because this tool talks to
 * OpenSSL's BARE-LMS support, while the engine speaks HSS (RFC 8554
 * §6.1/§6.2 — HSS always wraps LMS, even at L=1):
 *   - pubkey: HSS is u32str(L=1) || LMS_pubkey (60 bytes here); OpenSSL's
 *     "xdr" LMS decoder (providers/implementations/encode_decode/
 *     decode_lmsxdr2key.c) expects the bare 56-byte LMS_pubkey with no
 *     L-prefix — confirmed by reading that decoder's own BIO_read(4)
 *     header-length logic, not assumed.
 *   - signature: HSS is u32str(Nspk=L-1=0) || LMS_sig (1296 bytes here);
 *     ossl_lms_sig_verify() (crypto/lms/lms_verify.c) expects the bare
 *     1292-byte LMS_sig. Passing the full 1296-byte HSS signature against
 *     a bare-LMS key decodes without error but verifies FALSE — this
 *     tool auto-strips both wrappers by length so that mistake (made,
 *     and caught, while building this) can't recur silently.
 *
 * Also non-obvious, both confirmed by reading OpenSSL's own source rather
 * than assumed from the RSA/EC-shaped EVP_PKEY_verify_init family:
 *   - Native LMS registers OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT (the
 *     one-call "message" family for hash-internal algorithms), not
 *     VERIFY_INIT or DIGEST_VERIFY_INIT — use
 *     EVP_PKEY_verify_message_init(), not EVP_PKEY_verify_init() or
 *     EVP_DigestVerifyInit_ex().
 *   - The "xdr" input type is registered with no "structure=" property
 *     (providers/decoders.inc: DECODER("LMS", xdr, lms, yes)), so the
 *     standard PEM->DER OSSL_STORE auto-detect chain pkeyutl/pkey use
 *     never reaches it — hence this tool calls OSSL_DECODER_CTX_new_for_
 *     pkey() directly with input_type="xdr" rather than shelling out to
 *     the openssl CLI.
 *
 * Phase 5 R25: pubkey length is fixed at 56 bytes (60 HSS-wrapped)
 * regardless of parameter set — LM-OTS type only affects SIGNATURE size,
 * never the public key — so the pubkey-side dispatch below is unchanged.
 * The signature length used to be asserted against a single hardcoded
 * pair (1296/1292, the L=1/H5/W8 default); now the expected bare-LMS
 * signature length is computed from the (lms_type, lmots_type) already
 * sitting in the first 8 bytes of the decoded LMS public key itself (RFC
 * 8554 §5.3), via the same RFC 8554/SP 800-208 table this session ported
 * into the provider's own sig/hss.c hss_sig_size() and the Rust engine's
 * handlers.rs lms_single_sig_len() — so a signature of any parameter set
 * either engine can produce is recognized, not just the one default. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/err.h>

#define HSS_L1_PUBKEY_LEN 60  /* u32str(L=1) + LMS_pubkey(56) */
#define LMS_PUBKEY_LEN 56

static uint32_t read_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* RFC 8554 §5.4 LMS/LM-OTS type -> (n, h)/(n, w, p), IANA "Leighton-Micali
 * Signatures" registry (RFC 8554 + SP 800-208) — same table as
 * sig/hss.c's lms_single_sig_len() / handlers.rs's lms_single_sig_len(). */
static size_t lms_single_sig_len(uint32_t lms_type, uint32_t lmots_type)
{
    size_t n, h, p;

    switch (lms_type) {
    case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
    case 0x0F: case 0x10: case 0x11: case 0x12: case 0x13:
        n = 32;
        break;
    case 0x0A: case 0x0B: case 0x0C: case 0x0D: case 0x0E:
    case 0x14: case 0x15: case 0x16: case 0x17: case 0x18:
        n = 24;
        break;
    default:
        n = 32;
        break;
    }

    switch (lmots_type) {
    case 0x01: case 0x09: p = 265; break;
    case 0x02: case 0x0A: p = 133; break;
    case 0x03: case 0x0B: p = 67; break;
    case 0x04: case 0x0C: p = 34; break;
    case 0x05: case 0x0D: p = 200; break;
    case 0x06: case 0x0E: p = 101; break;
    case 0x07: case 0x0F: p = 51; break;
    case 0x08: case 0x10: p = 26; break;
    default: p = 67; break;
    }

    switch (lms_type) {
    case 0x05: case 0x0A: case 0x0F: case 0x14: h = 5; break;
    case 0x06: case 0x0B: case 0x10: case 0x15: h = 10; break;
    case 0x07: case 0x0C: case 0x11: case 0x16: h = 15; break;
    case 0x08: case 0x0D: case 0x12: case 0x17: h = 20; break;
    case 0x09: case 0x0E: case 0x13: case 0x18: h = 25; break;
    default: h = 5; break;
    }

    size_t lmots_sig_len = 4 + n + p * n;
    return 4 + lmots_sig_len + 4 + h * n;
}

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)sz);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "short read on %s\n", path);
        exit(2);
    }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr,
                "usage: %s <hss-pubkey-cka-value-file> <msg-file> "
                "<hss-sigfile>\n"
                "  pubkey file: raw CKA_VALUE of an HSS public key object "
                "(60 bytes, L=1)\n"
                "  sigfile: raw output of pkeyutl -sign against the HSS "
                "private key (1296 bytes)\n",
                argv[0]);
        return 2;
    }

    size_t pklen, msglen, siglen;
    unsigned char *pk_hss = read_file(argv[1], &pklen);
    unsigned char *msg = read_file(argv[2], &msglen);
    unsigned char *sig_hss = read_file(argv[3], &siglen);

    unsigned char *pk_lms;
    size_t pk_lms_len;
    if (pklen == HSS_L1_PUBKEY_LEN) {
        pk_lms = pk_hss + 4;
        pk_lms_len = LMS_PUBKEY_LEN;
    } else if (pklen == LMS_PUBKEY_LEN) {
        pk_lms = pk_hss;
        pk_lms_len = LMS_PUBKEY_LEN;
    } else {
        fprintf(stderr,
                "pubkey file is %zu bytes, expected %d (HSS L=1) or %d "
                "(bare LMS)\n",
                pklen, HSS_L1_PUBKEY_LEN, LMS_PUBKEY_LEN);
        return 2;
    }

    /* pk_lms[0:4]=lms_type, pk_lms[4:8]=lmots_type (RFC 8554 §5.3) --
     * the expected bare-LMS signature length for THIS key's own
     * parameter set, not a single hardcoded default. */
    uint32_t lms_type = read_be32(pk_lms);
    uint32_t lmots_type = read_be32(pk_lms + 4);
    size_t expect_lms_sig_len = lms_single_sig_len(lms_type, lmots_type);
    size_t expect_hss_sig_len = 4 + expect_lms_sig_len; /* u32str(Nspk=0) */

    unsigned char *sig_lms;
    size_t sig_lms_len;
    if (siglen == expect_hss_sig_len) {
        sig_lms = sig_hss + 4;
        sig_lms_len = expect_lms_sig_len;
    } else if (siglen == expect_lms_sig_len) {
        sig_lms = sig_hss;
        sig_lms_len = expect_lms_sig_len;
    } else {
        fprintf(stderr,
                "sigfile is %zu bytes, expected %zu (HSS L=1, lms_type=%u "
                "lmots_type=%u) or %zu (bare LMS)\n",
                siglen, expect_hss_sig_len, lms_type, lmots_type,
                expect_lms_sig_len);
        return 2;
    }

    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey, "xdr", NULL, "LMS", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL,
        NULL);
    if (!dctx) {
        fprintf(stderr, "OSSL_DECODER_CTX_new_for_pkey failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    const unsigned char *p = pk_lms;
    size_t plen = pk_lms_len;
    int ok = OSSL_DECODER_from_data(dctx, &p, &plen);
    OSSL_DECODER_CTX_free(dctx);
    if (!ok || pkey == NULL) {
        fprintf(stderr, "OSSL_DECODER_from_data failed to produce a key\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_verify_message_init(pctx, NULL, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_init failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    int rc = EVP_PKEY_verify(pctx, sig_lms, sig_lms_len, msg, msglen);
    if (rc < 0) {
        ERR_print_errors_fp(stderr);
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return rc == 1 ? 0 : 1;
}
