/*
 * ssh-mldsa.c -- ML-DSA-44/65/87 key types for OpenSSH
 *
 * Implements draft-sfluhrer-ssh-mldsa-08 (28 August 2026)
 * https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/
 *
 * s3. Public Key Algorithms
 *   "ssh-mldsa-44", "ssh-mldsa-65", "ssh-mldsa-87" -- NIST Cat 2, 3, 5.
 *   This file implements all three.
 *
 * s4. Public Key Format
 *   string  "ssh-mldsa-{44,65,87}"
 *   string  key         (raw ML-DSA.KeyGen pk, FIPS 204 s7.2)
 *
 * s5. Signature Algorithm
 *   Pure ML-DSA (FIPS 204 s5.2). Context string always empty.
 *   Hedged or deterministic mode acceptable; both interoperable.
 *   NOTE: signing is PKCS#11-only (ssh-pkcs11.c:pkcs11_sign_mldsa).
 *
 * s6. Signature Format
 *   string  "ssh-mldsa-{44,65,87}"
 *   string  signature   (raw bytes)
 *
 * s7. Verification Algorithm
 *   Step 1: Reject if sig length does not match the parameter set.
 *   Step 2: Verify per FIPS 204 s5.3, pure ML-DSA, empty context.
 *
 * Public key / signature byte lengths (FIPS 204, verified against the
 * vendored OpenSSL 3.6.3 source this connector builds against --
 * deps/openssl-src/openssl-3.6.3/include/crypto/ml_dsa.h -- and cross-checked
 * against the draft's own Section 4/6 wire-format tables):
 *
 *   ML-DSA-44:  pk=1312  sig=2420
 *   ML-DSA-65:  pk=1952  sig=3309
 *   ML-DSA-87:  pk=2592  sig=4627
 */

#include "includes.h"
#include <stddef.h>
#include <string.h>

#include <openssl/evp.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"

/*
 * DEFINE_MLDSA_IMPL(tag, type_const, ossl_name, ssh_name, short_name,
 *                   pk_sz, sig_sz)
 *
 * Generates one complete ML-DSA sshkey_impl (cleanup/equal/serialize/
 * deserialize/copy/verify + funcs + impl struct), parametrized on key size
 * instead of hardcoding ML-DSA-65's constants. Every expansion follows
 * EXACTLY the pattern the original ML-DSA-65-only file used -- this macro
 * only removes the duplication of copy/pasting that pattern three times.
 */
#define DEFINE_MLDSA_IMPL(tag, type_const, ossl_name, ssh_name, short_name, pk_sz, sig_sz) \
									\
static void								\
tag ## _cleanup(struct sshkey *k)					\
{									\
	EVP_PKEY_free(k->pkey);					\
	k->pkey = NULL;							\
}									\
									\
static int								\
tag ## _equal(const struct sshkey *a, const struct sshkey *b)		\
{									\
	u_char pka[pk_sz], pkb[pk_sz];					\
	size_t la = sizeof(pka), lb = sizeof(pkb);			\
									\
	if (a->pkey == NULL || b->pkey == NULL)			\
		return 0;						\
	if (!EVP_PKEY_get_raw_public_key(a->pkey, pka, &la) ||		\
	    !EVP_PKEY_get_raw_public_key(b->pkey, pkb, &lb))		\
		return 0;						\
	if (la != pk_sz || lb != pk_sz)				\
		return 0;						\
	return timingsafe_bcmp(pka, pkb, pk_sz) == 0;			\
}									\
									\
/* s4: Serialize public key -- write raw key bytes as SSH string. The	\
 * algorithm name string is written by the sshkey layer before this. */\
static int								\
tag ## _serialize_public(const struct sshkey *key, struct sshbuf *b,	\
    enum sshkey_serialize_rep opts)					\
{									\
	u_char raw[pk_sz];						\
	size_t len = sizeof(raw);					\
									\
	(void)opts;							\
	if (key->pkey == NULL)						\
		return SSH_ERR_INVALID_ARGUMENT;			\
	if (!EVP_PKEY_get_raw_public_key(key->pkey, raw, &len))	\
		return SSH_ERR_LIBCRYPTO_ERROR;			\
	if (len != pk_sz)						\
		return SSH_ERR_INVALID_FORMAT;				\
	return sshbuf_put_string(b, raw, len);				\
}									\
									\
/* s4: Deserialize public key. Validates exactly pk_sz bytes, imports	\
 * via OpenSSL 3.3+. */							\
static int								\
tag ## _deserialize_public(const char *ktype, struct sshbuf *b,	\
    struct sshkey *key)						\
{									\
	const u_char *pk;						\
	size_t pklen;							\
	int r;								\
									\
	(void)ktype;							\
	if ((r = sshbuf_get_string_direct(b, &pk, &pklen)) != 0)	\
		return r;						\
	/* s7 step 1: reject if length does not match this parameter set */\
	if (pklen != pk_sz)						\
		return SSH_ERR_KEY_LENGTH;				\
	EVP_PKEY_free(key->pkey);					\
	if ((key->pkey = EVP_PKEY_new_raw_public_key_ex(NULL, ossl_name, \
	    NULL, pk, pklen)) == NULL)					\
		return SSH_ERR_LIBCRYPTO_ERROR;			\
	return 0;							\
}									\
									\
static int								\
tag ## _copy_public(const struct sshkey *from, struct sshkey *to)	\
{									\
	u_char raw[pk_sz];						\
	size_t len = sizeof(raw);					\
									\
	if (from->pkey == NULL)					\
		return SSH_ERR_INVALID_ARGUMENT;			\
	if (!EVP_PKEY_get_raw_public_key(from->pkey, raw, &len))	\
		return SSH_ERR_LIBCRYPTO_ERROR;			\
	EVP_PKEY_free(to->pkey);					\
	if ((to->pkey = EVP_PKEY_new_raw_public_key_ex(NULL, ossl_name, \
	    NULL, raw, len)) == NULL)					\
		return SSH_ERR_LIBCRYPTO_ERROR;			\
	return 0;							\
}									\
									\
/*									\
 * s7. Verification Algorithm						\
 *									\
 * Step 1: Reject if sig length != sig_sz.				\
 * Step 2: Verify pure ML-DSA, empty context (OpenSSL 3.3+).		\
 *									\
 * Wire format (s6):							\
 *   string  ssh_name						\
 *   string  signature   (sig_sz bytes)				\
 */									\
static int								\
tag ## _verify(const struct sshkey *key,				\
    const u_char *sig, size_t siglen,					\
    const u_char *data, size_t datalen,				\
    const char *alg, u_int compat,					\
    struct sshkey_sig_details **detailsp)				\
{									\
	struct sshbuf	*b = NULL;					\
	char		*ktype = NULL;					\
	const u_char	*sigblob;					\
	size_t		 slen;						\
	EVP_MD_CTX	*md_ctx = NULL;					\
	int		 r = SSH_ERR_INTERNAL_ERROR;			\
									\
	(void)alg; (void)compat;					\
	if (detailsp != NULL)						\
		*detailsp = NULL;					\
	if (key == NULL || key->pkey == NULL || sig == NULL || siglen == 0 ||\
	    data == NULL || datalen == 0)				\
		return SSH_ERR_INVALID_ARGUMENT;			\
	if ((b = sshbuf_from(sig, siglen)) == NULL)			\
		return SSH_ERR_ALLOC_FAIL;				\
	/* s6: parse wire format */					\
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0)		\
		goto out;						\
	if (strcmp(ktype, ssh_name) != 0) {				\
		r = SSH_ERR_KEY_TYPE_MISMATCH;				\
		goto out;						\
	}								\
	if ((r = sshbuf_get_string_direct(b, &sigblob, &slen)) != 0)	\
		goto out;						\
	/* s7 step 1: reject wrong signature length */		\
	if (slen != sig_sz) {						\
		r = SSH_ERR_SIGNATURE_INVALID;				\
		goto out;						\
	}								\
	/* s7 step 2: verify pure ML-DSA, empty context. ML-DSA hashes	\
	 * internally (like Ed25519), so use EVP_DigestVerify rather	\
	 * than EVP_PKEY_verify (which skips the internal hash). */	\
	if ((md_ctx = EVP_MD_CTX_new()) == NULL) {			\
		r = SSH_ERR_ALLOC_FAIL;				\
		goto out;						\
	}								\
	if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, key->pkey) != 1 ||\
	    EVP_DigestVerify(md_ctx, sigblob, slen, data, datalen) != 1) {\
		r = SSH_ERR_SIGNATURE_INVALID;				\
		goto out;						\
	}								\
	r = 0;								\
out:									\
	sshbuf_free(b);							\
	free(ktype);							\
	EVP_MD_CTX_free(md_ctx);					\
	return r;							\
}									\
									\
static const struct sshkey_impl_funcs tag ## _funcs = {		\
	NULL,			/* size */				\
	NULL,			/* alloc */				\
	tag ## _cleanup,						\
	tag ## _equal,							\
	tag ## _serialize_public,					\
	tag ## _deserialize_public,					\
	NULL,			/* serialize_private */		\
	NULL,			/* deserialize_private */		\
	NULL,			/* generate */				\
	tag ## _copy_public,						\
	NULL,			/* sign -- PKCS#11 only */		\
	tag ## _verify,							\
};									\
									\
const struct sshkey_impl sshkey_ ## tag ## _impl = {			\
	ssh_name,		/* name */				\
	short_name,		/* shortname */				\
	ssh_name,		/* sigalg */				\
	type_const,		/* type */				\
	0,			/* nid */				\
	0,			/* cert */				\
	0,			/* sigonly */				\
	0,			/* keybits */				\
	& tag ## _funcs,						\
};

/* FIPS 204 Table 2 (verified against deps/openssl-src/openssl-3.6.3's own
 * ml_dsa.h and draft-sfluhrer-ssh-mldsa-08 s4/s6): */
DEFINE_MLDSA_IMPL(mldsa44, KEY_MLDSA_44, "ML-DSA-44", "ssh-mldsa-44", "MLDSA44", 1312, 2420)
DEFINE_MLDSA_IMPL(mldsa65, KEY_MLDSA_65, "ML-DSA-65", "ssh-mldsa-65", "MLDSA65", 1952, 3309)
DEFINE_MLDSA_IMPL(mldsa87, KEY_MLDSA_87, "ML-DSA-87", "ssh-mldsa-87", "MLDSA87", 2592, 4627)
