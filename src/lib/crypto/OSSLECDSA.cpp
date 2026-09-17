/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLECDSA.cpp

 OpenSSL ECDSA asymmetric algorithm implementation — EVP_PKEY throughout (OpenSSL 3.x)
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECDSA.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "OSSLECKeyPair.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/ecdsa.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <string.h>

// Helper: convert OpenSSL DER-encoded ECDSA_SIG to raw r||s (PKCS#11 format)
static bool derToRawSig(const unsigned char* der, size_t derLen,
                        unsigned char* raw, size_t orderLen)
{
	const unsigned char* p = der;
	ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &p, (long)derLen);
	if (sig == NULL)
		return false;

	const BIGNUM* bn_r = NULL;
	const BIGNUM* bn_s = NULL;
	ECDSA_SIG_get0(sig, &bn_r, &bn_s);

	memset(raw, 0, 2 * orderLen);
	BN_bn2bin(bn_r, raw + orderLen - BN_num_bytes(bn_r));
	BN_bn2bin(bn_s, raw + 2 * orderLen - BN_num_bytes(bn_s));
	ECDSA_SIG_free(sig);
	return true;
}

// Helper: convert raw r||s (PKCS#11 format) to DER-encoded ECDSA_SIG
// Returns DER buffer (caller must OPENSSL_free) and sets derLen. Returns NULL on error.
static unsigned char* rawSigToDer(const unsigned char* raw, size_t orderLen, size_t* derLen)
{
	ECDSA_SIG* sig = ECDSA_SIG_new();
	if (sig == NULL)
		return NULL;

	BIGNUM* bn_r = BN_bin2bn(raw, orderLen, NULL);
	BIGNUM* bn_s = BN_bin2bn(raw + orderLen, orderLen, NULL);
	if (bn_r == NULL || bn_s == NULL || !ECDSA_SIG_set0(sig, bn_r, bn_s))
	{
		BN_free(bn_r);
		BN_free(bn_s);
		ECDSA_SIG_free(sig);
		return NULL;
	}

	unsigned char* der = NULL;
	int len = i2d_ECDSA_SIG(sig, &der);
	ECDSA_SIG_free(sig);
	if (len <= 0)
		return NULL;

	*derLen = (size_t)len;
	return der;
}

// Signing functions
bool OSSLECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	const EVP_MD* md = NULL;

	if (mechanism != AsymMech::ECDSA)
	{
		switch (mechanism)
		{
			case AsymMech::ECDSA_SHA1:     md = EVP_sha1();     break;
			case AsymMech::ECDSA_SHA224:   md = EVP_sha224();   break;
			case AsymMech::ECDSA_SHA256:   md = EVP_sha256();   break;
			case AsymMech::ECDSA_SHA384:   md = EVP_sha384();   break;
			case AsymMech::ECDSA_SHA512:   md = EVP_sha512();   break;
			case AsymMech::ECDSA_SHA3_224: md = EVP_sha3_224(); break;
			case AsymMech::ECDSA_SHA3_256: md = EVP_sha3_256(); break;
			case AsymMech::ECDSA_SHA3_384: md = EVP_sha3_384(); break;
			case AsymMech::ECDSA_SHA3_512: md = EVP_sha3_512(); break;
			default:
				ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
				return false;
		}
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLECPrivateKey* pk = (OSSLECPrivateKey*) privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");
		return false;
	}

	size_t orderLen = pk->getOrderLength();
	if (orderLen == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}

	// Perform the signature operation — result is DER SEQUENCE{r, s}
	ByteString derSig;

	if (md == NULL)
	{
		// Raw ECDSA: sign the pre-hashed bytes directly via EVP_PKEY_sign
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL)
		{
			ERROR_MSG("ECDSA EVP_PKEY_CTX_new failed");
			return false;
		}
		if (EVP_PKEY_sign_init(ctx) <= 0)
		{
			ERROR_MSG("ECDSA sign init failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		size_t derLen = 0;
		// Query required output size
		if (EVP_PKEY_sign(ctx, NULL, &derLen,
		                  dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("ECDSA sign size query failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		derSig.resize(derLen);
		if (EVP_PKEY_sign(ctx, &derSig[0], &derLen,
		                  dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("ECDSA sign failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		EVP_PKEY_CTX_free(ctx);
		derSig.resize(derLen);
	}
	else
	{
		// Hash-then-sign via EVP_DigestSign
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		if (ctx == NULL)
		{
			ERROR_MSG("ECDSA EVP_MD_CTX_new failed");
			return false;
		}
		if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) <= 0)
		{
			ERROR_MSG("ECDSA DigestSign init failed (0x%08X)", ERR_get_error());
			EVP_MD_CTX_free(ctx);
			return false;
		}
		size_t derLen = 0;
		if (EVP_DigestSign(ctx, NULL, &derLen,
		                   dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("ECDSA DigestSign size query failed (0x%08X)", ERR_get_error());
			EVP_MD_CTX_free(ctx);
			return false;
		}
		derSig.resize(derLen);
		if (EVP_DigestSign(ctx, &derSig[0], &derLen,
		                   dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("ECDSA DigestSign failed (0x%08X)", ERR_get_error());
			EVP_MD_CTX_free(ctx);
			return false;
		}
		EVP_MD_CTX_free(ctx);
		derSig.resize(derLen);
	}

	// Convert DER SEQUENCE{r,s} → raw r||s (PKCS#11 format)
	signature.resize(2 * orderLen);
	if (!derToRawSig(derSig.const_byte_str(), derSig.size(), &signature[0], orderLen))
	{
		ERROR_MSG("ECDSA DER to raw signature conversion failed");
		return false;
	}
	return true;
}

bool OSSLECDSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			 const void* param, const size_t paramLen)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
		return false;
	m_signMsg.wipe();
	return true;
}

bool OSSLECDSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
		return false;
	m_signMsg += dataToSign;
	return true;
}

bool OSSLECDSA::signFinal(ByteString& signature)
{
	PrivateKey* pk   = currentPrivateKey;
	AsymMech::Type m = currentMechanism;
	if (!AsymmetricAlgorithm::signFinal(signature))
		return false;
	bool ok = sign(pk, m_signMsg, signature, m);
	m_signMsg.wipe();
	return ok;
}

// Verification functions
bool OSSLECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	const EVP_MD* md = NULL;

	if (mechanism != AsymMech::ECDSA)
	{
		switch (mechanism)
		{
			case AsymMech::ECDSA_SHA1:     md = EVP_sha1();     break;
			case AsymMech::ECDSA_SHA224:   md = EVP_sha224();   break;
			case AsymMech::ECDSA_SHA256:   md = EVP_sha256();   break;
			case AsymMech::ECDSA_SHA384:   md = EVP_sha384();   break;
			case AsymMech::ECDSA_SHA512:   md = EVP_sha512();   break;
			case AsymMech::ECDSA_SHA3_224: md = EVP_sha3_224(); break;
			case AsymMech::ECDSA_SHA3_256: md = EVP_sha3_256(); break;
			case AsymMech::ECDSA_SHA3_384: md = EVP_sha3_384(); break;
			case AsymMech::ECDSA_SHA3_512: md = EVP_sha3_512(); break;
			default:
				ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
				return false;
		}
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLECPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLECPublicKey* pk = (OSSLECPublicKey*) publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");
		return false;
	}

	size_t orderLen = pk->getOrderLength();
	if (orderLen == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	if (signature.size() != 2 * orderLen)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}

	// Convert raw r||s → DER SEQUENCE{r,s}
	size_t derLen = 0;
	unsigned char* derSig = rawSigToDer(signature.const_byte_str(), orderLen, &derLen);
	if (derSig == NULL)
	{
		ERROR_MSG("ECDSA raw to DER signature conversion failed");
		return false;
	}

	int ret;

	if (md == NULL)
	{
		// Raw ECDSA: verify the pre-hashed bytes
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL)
		{
			ERROR_MSG("ECDSA EVP_PKEY_CTX_new failed");
			OPENSSL_free(derSig);
			return false;
		}
		if (EVP_PKEY_verify_init(ctx) <= 0)
		{
			ERROR_MSG("ECDSA verify init failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			OPENSSL_free(derSig);
			return false;
		}
		ret = EVP_PKEY_verify(ctx, derSig, derLen,
		                      originalData.const_byte_str(), originalData.size());
		EVP_PKEY_CTX_free(ctx);
	}
	else
	{
		// Hash-then-verify
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		if (ctx == NULL)
		{
			ERROR_MSG("ECDSA EVP_MD_CTX_new failed");
			OPENSSL_free(derSig);
			return false;
		}
		if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) <= 0)
		{
			ERROR_MSG("ECDSA DigestVerify init failed (0x%08X)", ERR_get_error());
			EVP_MD_CTX_free(ctx);
			OPENSSL_free(derSig);
			return false;
		}
		ret = EVP_DigestVerify(ctx, derSig, derLen,
		                       originalData.const_byte_str(), originalData.size());
		EVP_MD_CTX_free(ctx);
	}

	OPENSSL_free(derSig);

	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("ECDSA verify failed (0x%08X)", ERR_get_error());
		return false;
	}
	return true;
}

bool OSSLECDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			   const void* param, const size_t paramLen)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
		return false;
	m_verifyMsg.wipe();
	return true;
}

bool OSSLECDSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
		return false;
	m_verifyMsg += originalData;
	return true;
}

bool OSSLECDSA::verifyFinal(const ByteString& signature)
{
	PublicKey*     pk = currentPublicKey;
	AsymMech::Type m  = currentMechanism;
	if (!AsymmetricAlgorithm::verifyFinal(signature))
		return false;
	bool ok = verify(pk, m_verifyMsg, signature, m);
	m_verifyMsg.wipe();
	return ok;
}

// Encryption functions
bool OSSLECDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support encryption");
	return false;
}

// Decryption functions
bool OSSLECDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support decryption");
	return false;
}

// Key factory
// FIPS 186-5 A.2.2, "Key Pair Generation Using Extra Random Bits": draw
// len(n)+64 random bits, reduce modulo (n-1) and add 1. PKCS#11 v3.2 exposes
// this as CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS — a mechanism distinct from
// CKM_EC_KEY_PAIR_GEN precisely because the two differ in how the private
// scalar is drawn. This mirrors the Rust engine's ec_extra_bits_scalar()
// (rust/src/ffi.rs) so both engines build the key by the same construction.
//
// OpenSSL exposes no knob for the generation method, so the scalar is drawn
// here and the key assembled from (group, private, public) via
// EVP_PKEY_fromdata. The public point has to be supplied explicitly:
// fromdata will not derive it from the private scalar.
static EVP_PKEY* ecGenerateKeyExtraBits(int nid, const char* curve_name)
{
	EVP_PKEY*       pkey      = NULL;
	EC_GROUP*       grp       = NULL;
	BN_CTX*         bnctx     = NULL;
	const BIGNUM*   order     = NULL;
	BIGNUM*         nMinus1   = NULL;
	BIGNUM*         c         = NULL;
	BIGNUM*         d         = NULL;
	EC_POINT*       pubPt     = NULL;
	unsigned char*  rndBits   = NULL;
	unsigned char*  pubBuf    = NULL;
	size_t          pubLen    = 0;
	size_t          rndLen    = 0;
	int             orderBits = 0;
	OSSL_PARAM_BLD* bld       = NULL;
	OSSL_PARAM*     params    = NULL;
	EVP_PKEY_CTX*   ctx       = NULL;

	grp = EC_GROUP_new_by_curve_name(nid);
	if (grp == NULL)
	{
		ERROR_MSG("Failed to load EC group for extra-bits key generation");
		goto done;
	}

	order = EC_GROUP_get0_order(grp);
	if (order == NULL || BN_is_zero(order))
	{
		ERROR_MSG("EC group has no usable order for extra-bits key generation");
		goto done;
	}
	orderBits = BN_num_bits(order);

	// len(n) + 64 bits, rounded up to whole bytes
	rndLen  = (size_t)((orderBits + 64 + 7) / 8);
	rndBits = (unsigned char*) OPENSSL_malloc(rndLen);
	bnctx   = BN_CTX_new();
	nMinus1 = BN_new();
	d       = BN_secure_new();
	if (rndBits == NULL || bnctx == NULL || nMinus1 == NULL || d == NULL)
	{
		ERROR_MSG("Out of memory in extra-bits EC key generation");
		goto done;
	}

	if (RAND_bytes(rndBits, (int)rndLen) != 1)
	{
		ERROR_MSG("RAND_bytes failed in extra-bits EC key generation");
		goto done;
	}

	c = BN_bin2bn(rndBits, (int)rndLen, NULL);
	if (c == NULL)
	{
		ERROR_MSG("Failed to import random bits in extra-bits EC key generation");
		goto done;
	}

	// d = (c mod (n-1)) + 1, so 1 <= d <= n-1
	if (BN_copy(nMinus1, order) == NULL ||
	    BN_sub_word(nMinus1, 1) != 1 ||
	    BN_mod(d, c, nMinus1, bnctx) != 1 ||
	    BN_add_word(d, 1) != 1)
	{
		ERROR_MSG("Scalar reduction failed in extra-bits EC key generation");
		goto done;
	}

	// Q = d * G
	pubPt = EC_POINT_new(grp);
	if (pubPt == NULL || EC_POINT_mul(grp, pubPt, d, NULL, NULL, bnctx) != 1)
	{
		ERROR_MSG("Failed to compute the public point in extra-bits EC key generation");
		goto done;
	}

	pubLen = EC_POINT_point2oct(grp, pubPt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
	if (pubLen == 0)
	{
		ERROR_MSG("Failed to size the public point in extra-bits EC key generation");
		goto done;
	}
	pubBuf = (unsigned char*) OPENSSL_malloc(pubLen);
	if (pubBuf == NULL ||
	    EC_POINT_point2oct(grp, pubPt, POINT_CONVERSION_UNCOMPRESSED, pubBuf, pubLen, bnctx) != pubLen)
	{
		ERROR_MSG("Failed to encode the public point in extra-bits EC key generation");
		goto done;
	}

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL ||
	    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0) != 1 ||
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d) != 1 ||
	    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pubBuf, pubLen) != 1)
	{
		ERROR_MSG("Failed to build key parameters in extra-bits EC key generation");
		goto done;
	}
	params = OSSL_PARAM_BLD_to_param(bld);
	ctx    = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (params == NULL || ctx == NULL ||
	    EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
	{
		ERROR_MSG("EVP_PKEY_fromdata failed in extra-bits EC key generation (0x%08X)", ERR_get_error());
		pkey = NULL;
		goto done;
	}

done:
	if (ctx     != NULL) EVP_PKEY_CTX_free(ctx);
	if (params  != NULL) OSSL_PARAM_free(params);
	if (bld     != NULL) OSSL_PARAM_BLD_free(bld);
	if (pubBuf  != NULL) OPENSSL_free(pubBuf);
	if (pubPt   != NULL) EC_POINT_free(pubPt);
	if (d       != NULL) BN_clear_free(d);
	if (c       != NULL) BN_clear_free(c);
	if (nMinus1 != NULL) BN_free(nMinus1);
	if (rndBits != NULL) OPENSSL_clear_free(rndBits, rndLen);
	if (bnctx   != NULL) BN_CTX_free(bnctx);
	if (grp     != NULL) EC_GROUP_free(grp);

	return pkey;
}

bool OSSLECDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) || (parameters == NULL))
		return false;

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDSA key generation");
		return false;
	}

	ECParameters* params = (ECParameters*) parameters;

	// Determine the curve short name from DER-encoded ECParameters
	EC_GROUP* grp = OSSL::byteString2grp(params->getEC());
	if (grp == NULL)
	{
		ERROR_MSG("Failed to decode EC group for ECDSA key generation");
		return false;
	}
	int nid = EC_GROUP_get_curve_name(grp);
	const char* curve_name = OBJ_nid2sn(nid);
	EC_GROUP_free(grp);

	if (curve_name == NULL)
	{
		ERROR_MSG("Failed to get curve name for ECDSA key generation");
		return false;
	}

	// CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS draws the private scalar itself
	// (FIPS 186-5 A.2.2) rather than letting the provider choose a method
	if (params->getUseExtraBits())
	{
		EVP_PKEY* xpkey = ecGenerateKeyExtraBits(nid, curve_name);
		if (xpkey == NULL)
			return false;

		OSSLECKeyPair* xkp = new OSSLECKeyPair();
		((OSSLECPublicKey*) xkp->getPublicKey())->setFromOSSL(xpkey);
		((OSSLECPrivateKey*) xkp->getPrivateKey())->setFromOSSL(xpkey);
		*ppKeyPair = xkp;
		EVP_PKEY_free(xpkey);
		return true;
	}

	// Generate the key-pair via EVP_PKEY_CTX
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to instantiate EVP_PKEY_CTX for EC key generation");
		return false;
	}

	OSSL_PARAM keygen_params[2];
	keygen_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
	                                                     (char*)curve_name, 0);
	keygen_params[1] = OSSL_PARAM_construct_end();

	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_params(ctx, keygen_params) <= 0 ||
	    EVP_PKEY_generate(ctx, &pkey) <= 0)
	{
		ERROR_MSG("ECDSA key generation failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// Create an asymmetric key-pair object to return
	OSSLECKeyPair* kp = new OSSLECKeyPair();

	((OSSLECPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLECPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

unsigned long OSSLECDSA::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long OSSLECDSA::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool OSSLECDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) || (serialisedData.size() == 0))
		return false;

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLECKeyPair* kp = new OSSLECKeyPair();

	bool rv = true;

	if (!((ECPublicKey*) kp->getPublicKey())->deserialise(dPub))
		rv = false;

	if (!((ECPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
		rv = false;

	if (!rv)
	{
		delete kp;
		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool OSSLECDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) || (serialisedData.size() == 0))
		return false;

	OSSLECPublicKey* pub = new OSSLECPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLECDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) || (serialisedData.size() == 0))
		return false;

	OSSLECPrivateKey* priv = new OSSLECPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLECDSA::newPublicKey()
{
	return (PublicKey*) new OSSLECPublicKey();
}

PrivateKey* OSSLECDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLECPrivateKey();
}

AsymmetricParameters* OSSLECDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLECDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
		return false;

	ECParameters* params = new ECParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;

	return true;
}
#endif
