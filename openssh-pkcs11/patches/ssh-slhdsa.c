/*
 * ssh-slhdsa.c -- SLH-DSA key types for OpenSSH
 *
 * Implements draft-josefsson-ssh-sphincs-02 (6 May 2026)
 * https://datatracker.ietf.org/doc/draft-josefsson-ssh-sphincs/
 *
 * s3. Public Key Algorithms
 *   This file implements 8 of the engine's 12 supported FIPS 205 parameter
 *   sets -- every one the draft defines a standalone (non-hybrid) SSH wire
 *   name for:
 *
 *     ssh-slh-dsa-sha2-128s    ssh-slh-dsa-shake-128s
 *     ssh-slh-dsa-sha2-128f    ssh-slh-dsa-shake-128f
 *     ssh-slh-dsa-sha2-256s    ssh-slh-dsa-shake-256s
 *     ssh-slh-dsa-sha2-256f    ssh-slh-dsa-shake-256f
 *
 *   NOT implemented here: SHA2/SHAKE-192s/192f. draft-josefsson-ssh-sphincs-02
 *   Section 4 does not define standalone names for these -- its own 192-bit
 *   table entries (ssh-slh-dsa-{sha2,shake}-192-24) are a DIFFERENT parameter
 *   family from NIST SP 800-230 IDP ("Additional SLH-DSA Parameter Sets for
 *   Limited Signature Use Cases": pk=48, sig=7752 bytes) that this engine
 *   does not implement -- it is not an alias for the standard FIPS 205
 *   192s/192f sets (pk=48, sig=16224/35664; SoftHSM_slots.cpp:1252-1273).
 *   Confirmed against the draft's own Section 10 IANA table (both live
 *   fetches of -02, 2026-08-31); no standalone 192s/192f name exists in any
 *   published revision (00/01/02) of this draft. Adding these two parameter
 *   sets would require inventing an SSH algorithm name the draft doesn't
 *   specify, which this connector deliberately does not do.
 *
 * s4. Public Key Format
 *   string  <algorithm name>
 *   string  key     (raw SLH-DSA.KeyGen pk, FIPS 205 s9.1)
 *
 * s5. Signature Algorithm
 *   Pure SLH-DSA (FIPS 205 s9.2). Context string always empty.
 *   NOTE: signing is PKCS#11-only (ssh-pkcs11.c:pkcs11_sign_slhdsa).
 *
 * s6. Signature Format
 *   string  <algorithm name>
 *   string  signature   (raw bytes; FIPS 205 s11 Table 2)
 *
 * s8. Verification Algorithm
 *   Step 1: Reject if sig length does not match the parameter set.
 *   Step 2: Verify per FIPS 205 s9.3, pure SLH-DSA, empty context.
 *
 * Public key / signature byte lengths (FIPS 205 s11 Table 2, verified
 * against the vendored OpenSSL 3.6.3 source this connector builds against --
 * deps/openssl-src/openssl-3.6.3/crypto/slh_dsa/slh_params.c -- SHA2 and
 * SHAKE variants of the same size class share identical pk/sig sizes):
 *
 *   128s:  pk=32  sig=7856     128f:  pk=32  sig=17088
 *   256s:  pk=64  sig=29792    256f:  pk=64  sig=49856
 */

#include "includes.h"
#include <stddef.h>
#include <string.h>

#include <openssl/evp.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"

/*
 * DEFINE_SLHDSA_IMPL(tag, type_const, ossl_name, ssh_name, short_name,
 *                    pk_sz, sig_sz)
 *
 * Generates one complete SLH-DSA sshkey_impl, parametrized on key size and
 * OpenSSL algorithm name instead of hardcoding SLH-DSA-SHA2-128s's
 * constants. Follows EXACTLY the pattern the original single-parameter-set
 * file used.
 */
#define DEFINE_SLHDSA_IMPL(tag, type_const, ossl_name, ssh_name, short_name, pk_sz, sig_sz) \
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
 * via OpenSSL 3.5+. */							\
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
	/* s8 step 1: reject if length does not match this parameter set */\
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
 * s8. Verification Algorithm						\
 *									\
 * Step 1: Reject if sig length != sig_sz.				\
 * Step 2: Verify pure SLH-DSA, empty context (OpenSSL 3.5+).		\
 *									\
 * Wire format (s6):							\
 *   string  ssh_name						\
 *   string  signature   (sig_sz bytes)				\
 *									\
 * SLH-DSA hashes internally (like ML-DSA / Ed25519), so use		\
 * EVP_DigestVerify rather than EVP_PKEY_verify (which bypasses the	\
 * internal hash and always returns failure for stateless hash-based	\
 * schemes).								\
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
	/* s8 step 1: reject wrong signature length */		\
	if (slen != sig_sz) {						\
		r = SSH_ERR_SIGNATURE_INVALID;				\
		goto out;						\
	}								\
	/* s8 step 2: verify pure SLH-DSA, empty context. */		\
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

/* FIPS 205 s11 Table 2 (verified against
 * deps/openssl-src/openssl-3.6.3/crypto/slh_dsa/slh_params.c and
 * draft-josefsson-ssh-sphincs-02 s4/s6/s10): */
DEFINE_SLHDSA_IMPL(slhdsa_sha2_128s,  KEY_SLH_DSA_SHA2_128S,  "SLH-DSA-SHA2-128s",  "ssh-slh-dsa-sha2-128s",  "SLHDSA-SHA2-128S",  32, 7856)
DEFINE_SLHDSA_IMPL(slhdsa_sha2_128f,  KEY_SLH_DSA_SHA2_128F,  "SLH-DSA-SHA2-128f",  "ssh-slh-dsa-sha2-128f",  "SLHDSA-SHA2-128F",  32, 17088)
DEFINE_SLHDSA_IMPL(slhdsa_shake_128s, KEY_SLH_DSA_SHAKE_128S, "SLH-DSA-SHAKE-128s", "ssh-slh-dsa-shake-128s", "SLHDSA-SHAKE-128S", 32, 7856)
DEFINE_SLHDSA_IMPL(slhdsa_shake_128f, KEY_SLH_DSA_SHAKE_128F, "SLH-DSA-SHAKE-128f", "ssh-slh-dsa-shake-128f", "SLHDSA-SHAKE-128F", 32, 17088)
DEFINE_SLHDSA_IMPL(slhdsa_sha2_256s,  KEY_SLH_DSA_SHA2_256S,  "SLH-DSA-SHA2-256s",  "ssh-slh-dsa-sha2-256s",  "SLHDSA-SHA2-256S",  64, 29792)
DEFINE_SLHDSA_IMPL(slhdsa_sha2_256f,  KEY_SLH_DSA_SHA2_256F,  "SLH-DSA-SHA2-256f",  "ssh-slh-dsa-sha2-256f",  "SLHDSA-SHA2-256F",  64, 49856)
DEFINE_SLHDSA_IMPL(slhdsa_shake_256s, KEY_SLH_DSA_SHAKE_256S, "SLH-DSA-SHAKE-256s", "ssh-slh-dsa-shake-256s", "SLHDSA-SHAKE-256S", 64, 29792)
DEFINE_SLHDSA_IMPL(slhdsa_shake_256f, KEY_SLH_DSA_SHAKE_256F, "SLH-DSA-SHAKE-256f", "ssh-slh-dsa-shake-256f", "SLHDSA-SHAKE-256F", 64, 49856)
