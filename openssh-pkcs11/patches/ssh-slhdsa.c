/*
 * ssh-slhdsa.c -- SLH-DSA-SHA2-128s key type for OpenSSH
 *
 * Implements draft-josefsson-ssh-sphincs-02 (November 2025)
 * https://datatracker.ietf.org/doc/draft-josefsson-ssh-sphincs/
 *
 * s3. Public Key Algorithms
 *   "ssh-slh-dsa-sha2-128s" -- SLH-DSA-SHA2-128S (NIST Category 1, small sigs)
 *
 * s4. Public Key Format
 *   string  "ssh-slh-dsa-sha2-128s"
 *   string  key     (32 raw bytes; SLH-DSA.KeyGen pk per FIPS 205 §9.1)
 *
 * s5. Signature Algorithm
 *   Pure SLH-DSA (FIPS 205 §9.2). Context string always empty.
 *   NOTE: signing is PKCS#11-only (ssh-pkcs11.c:pkcs11_sign_slhdsa).
 *
 * s6. Signature Format
 *   string  "ssh-slh-dsa-sha2-128s"
 *   string  signature   (7856 raw bytes; FIPS 205 §11 Table 2)
 *
 * s8. Verification Algorithm
 *   Step 1: Reject if sig length != 7856 bytes for SLH-DSA-SHA2-128S.
 *   Step 2: Verify per FIPS 205 §9.3, pure SLH-DSA, empty context.
 */

#include "includes.h"
#include <stddef.h>
#include <string.h>

#include <openssl/evp.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"

/* FIPS 205 §11 Table 2 -- SLH-DSA-SHA2-128s */
#define SSH_SLHDSA128S_PK_SZ  32
#define SSH_SLHDSA128S_SIG_SZ 7856

static void
slhdsa128s_cleanup(struct sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static int
slhdsa128s_equal(const struct sshkey *a, const struct sshkey *b)
{
	u_char pka[SSH_SLHDSA128S_PK_SZ], pkb[SSH_SLHDSA128S_PK_SZ];
	size_t la = sizeof(pka), lb = sizeof(pkb);

	if (a->pkey == NULL || b->pkey == NULL)
		return 0;
	if (!EVP_PKEY_get_raw_public_key(a->pkey, pka, &la) ||
	    !EVP_PKEY_get_raw_public_key(b->pkey, pkb, &lb))
		return 0;
	if (la != SSH_SLHDSA128S_PK_SZ || lb != SSH_SLHDSA128S_PK_SZ)
		return 0;
	return timingsafe_bcmp(pka, pkb, SSH_SLHDSA128S_PK_SZ) == 0;
}

/*
 * s4: Serialize public key -- write raw key bytes as SSH string.
 * The algorithm name string is written by the sshkey layer before this.
 */
static int
slhdsa128s_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	u_char raw[SSH_SLHDSA128S_PK_SZ];
	size_t len = sizeof(raw);

	if (key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!EVP_PKEY_get_raw_public_key(key->pkey, raw, &len))
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (len != SSH_SLHDSA128S_PK_SZ)
		return SSH_ERR_INVALID_FORMAT;
	return sshbuf_put_string(b, raw, len);
}

/*
 * s4: Deserialize public key.
 * Validates exactly SSH_SLHDSA128S_PK_SZ bytes, imports via OpenSSL 3.5+.
 */
static int
slhdsa128s_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	const u_char *pk;
	size_t pklen;
	int r;

	if ((r = sshbuf_get_string_direct(b, &pk, &pklen)) != 0)
		return r;
	/* s8 step 1: reject if length does not match SLH-DSA-SHA2-128s */
	if (pklen != SSH_SLHDSA128S_PK_SZ)
		return SSH_ERR_KEY_LENGTH;
	EVP_PKEY_free(key->pkey);
	if ((key->pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "SLH-DSA-SHA2-128s",
	    NULL, pk, pklen)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

static int
slhdsa128s_copy_public(const struct sshkey *from, struct sshkey *to)
{
	u_char raw[SSH_SLHDSA128S_PK_SZ];
	size_t len = sizeof(raw);

	if (from->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!EVP_PKEY_get_raw_public_key(from->pkey, raw, &len))
		return SSH_ERR_LIBCRYPTO_ERROR;
	EVP_PKEY_free(to->pkey);
	if ((to->pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "SLH-DSA-SHA2-128s",
	    NULL, raw, len)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

/*
 * s8. Verification Algorithm
 *
 * Step 1: Reject if sig length != SSH_SLHDSA128S_SIG_SZ (7856).
 * Step 2: Verify pure SLH-DSA, empty context (OpenSSL 3.5+).
 *
 * Wire format (s6):
 *   string  "ssh-slh-dsa-sha2-128s"
 *   string  signature   (7856 bytes)
 *
 * SLH-DSA hashes internally (like ML-DSA / Ed25519), so use EVP_DigestVerify
 * rather than EVP_PKEY_verify (which bypasses the internal hash and always
 * returns failure for stateless hash-based schemes).
 */
static int
slhdsa128s_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen,
    const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	struct sshbuf	*b = NULL;
	char		*ktype = NULL;
	const u_char	*sigblob;
	size_t		 slen;
	EVP_MD_CTX	*md_ctx = NULL;
	int		 r = SSH_ERR_INTERNAL_ERROR;

	if (detailsp != NULL)
		*detailsp = NULL;
	if (key == NULL || key->pkey == NULL || sig == NULL || siglen == 0 ||
	    data == NULL || datalen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	/* s6: parse wire format */
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0)
		goto out;
	if (strcmp(ktype, "ssh-slh-dsa-sha2-128s") != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if ((r = sshbuf_get_string_direct(b, &sigblob, &slen)) != 0)
		goto out;
	/* s8 step 1: reject wrong signature length */
	if (slen != SSH_SLHDSA128S_SIG_SZ) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* s8 step 2: verify pure SLH-DSA, empty context. */
	if ((md_ctx = EVP_MD_CTX_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, key->pkey) != 1 ||
	    EVP_DigestVerify(md_ctx, sigblob, slen, data, datalen) != 1) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	r = 0;
out:
	sshbuf_free(b);
	free(ktype);
	EVP_MD_CTX_free(md_ctx);
	return r;
}

static const struct sshkey_impl_funcs slhdsa128s_funcs = {
	NULL,			/* size */
	NULL,			/* alloc */
	slhdsa128s_cleanup,
	slhdsa128s_equal,
	slhdsa128s_serialize_public,
	slhdsa128s_deserialize_public,
	NULL,			/* serialize_private */
	NULL,			/* deserialize_private */
	NULL,			/* generate */
	slhdsa128s_copy_public,
	NULL,			/* sign -- PKCS#11 only */
	slhdsa128s_verify,
};

const struct sshkey_impl sshkey_slhdsa_sha2_128s_impl = {
	"ssh-slh-dsa-sha2-128s",	/* name */
	"SLHDSA128S",			/* shortname */
	"ssh-slh-dsa-sha2-128s",	/* sigalg */
	KEY_SLH_DSA_SHA2_128S,		/* type */
	0,				/* nid */
	0,				/* cert */
	0,				/* sigonly */
	0,				/* keybits */
	&slhdsa128s_funcs,
};
