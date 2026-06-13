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
 OSSLSLHDSA.cpp

 OpenSSL SLH-DSA (FIPS 205) asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLSLHDSA.h"
#include "SLHDSAParameters.h"
#include "OSSLSLHDSAKeyPair.h"
#include "OSSLSLHDSAPublicKey.h"
#include "OSSLSLHDSAPrivateKey.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

// ─── Pre-hash support (FIPS 205 §10.1, HashSLH-DSA) ─────────────────────────

// DER-encoded AlgorithmIdentifier for each hash (same OIDs as HashML-DSA).
// SHA-2/SHA-3: SEQUENCE { OID, NULL }  (15 bytes)
// SHAKE:       SEQUENCE { OID }        (13 bytes, absent parameters)
static const unsigned char SLHDSA_ALGID_SHA224[]   = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04, 0x05,0x00
};
static const unsigned char SLHDSA_ALGID_SHA256[]   = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01, 0x05,0x00
};
static const unsigned char SLHDSA_ALGID_SHA384[]   = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02, 0x05,0x00
};
static const unsigned char SLHDSA_ALGID_SHA512[]   = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03, 0x05,0x00
};
static const unsigned char SLHDSA_ALGID_SHA3_224[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x07, 0x05,0x00
};
static const unsigned char SLHDSA_ALGID_SHA3_256[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x08, 0x05,0x00
};
static const unsigned char SLHDSA_ALGID_SHA3_384[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x09, 0x05,0x00
};
static const unsigned char SLHDSA_ALGID_SHA3_512[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0a, 0x05,0x00
};
static const unsigned char SLHDSA_ALGID_SHAKE128[] = {
	0x30,0x0b, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0b
};
static const unsigned char SLHDSA_ALGID_SHAKE256[] = {
	0x30,0x0b, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0c
};

struct SLHDSAPreHashInfo
{
	const char*           evpName;
	const unsigned char*  algIdDer;
	size_t                algIdDerLen;
	size_t                digestLen;
	bool                  isXof;
	mutable EVP_MD*       md;  // lazily fetched and cached
};

static const SLHDSAPreHashInfo* getSLHDSAPreHashInfo(HashAlgo::Type hashAlg)
{
	// SHAKE output lengths per FIPS 205: SHAKE128 → 32 bytes, SHAKE256 → 64 bytes
	static const SLHDSAPreHashInfo table[] = {
		{ "SHA2-224",  SLHDSA_ALGID_SHA224,    15, 28, false, NULL },
		{ "SHA2-256",  SLHDSA_ALGID_SHA256,    15, 32, false, NULL },
		{ "SHA2-384",  SLHDSA_ALGID_SHA384,    15, 48, false, NULL },
		{ "SHA2-512",  SLHDSA_ALGID_SHA512,    15, 64, false, NULL },
		{ "SHA3-224",  SLHDSA_ALGID_SHA3_224,  15, 28, false, NULL },
		{ "SHA3-256",  SLHDSA_ALGID_SHA3_256,  15, 32, false, NULL },
		{ "SHA3-384",  SLHDSA_ALGID_SHA3_384,  15, 48, false, NULL },
		{ "SHA3-512",  SLHDSA_ALGID_SHA3_512,  15, 64, false, NULL },
		{ "SHAKE128",  SLHDSA_ALGID_SHAKE128,  13, 32, true,  NULL },
		{ "SHAKE256",  SLHDSA_ALGID_SHAKE256,  13, 64, true,  NULL },
	};

	switch (hashAlg)
	{
		case HashAlgo::SHA224:   return &table[0];
		case HashAlgo::SHA256:   return &table[1];
		case HashAlgo::SHA384:   return &table[2];
		case HashAlgo::SHA512:   return &table[3];
		case HashAlgo::SHA3_224: return &table[4];
		case HashAlgo::SHA3_256: return &table[5];
		case HashAlgo::SHA3_384: return &table[6];
		case HashAlgo::SHA3_512: return &table[7];
		case HashAlgo::SHAKE128: return &table[8];
		case HashAlgo::SHAKE256: return &table[9];
		default: return NULL;
	}
}

// Free lazily-cached EVP_MD* objects — called from C_Finalize (CR-03)
void OSSLSLHDSA_cleanupPreHashCache()
{
	static const HashAlgo::Type allAlgs[] = {
		HashAlgo::SHA224, HashAlgo::SHA256, HashAlgo::SHA384, HashAlgo::SHA512,
		HashAlgo::SHA3_224, HashAlgo::SHA3_256, HashAlgo::SHA3_384, HashAlgo::SHA3_512,
		HashAlgo::SHAKE128, HashAlgo::SHAKE256
	};
	for (auto alg : allAlgs)
	{
		const SLHDSAPreHashInfo* info = getSLHDSAPreHashInfo(alg);
		if (info && info->md)
		{
			EVP_MD_free(info->md);
			info->md = NULL;
		}
	}
}

// Build HashSLH-DSA message: M' = 0x01 || len(ctx) || ctx || OID || PH(M)
// per FIPS 205 §10.1
static bool buildSLHDSAPreHashMsg(const ByteString& message,
                                   const SLHDSA_SIGN_PARAMS* params,
                                   ByteString& encoded)
{
	const SLHDSAPreHashInfo* info = getSLHDSAPreHashInfo(params->hashAlg);
	if (!info)
	{
		ERROR_MSG("Unknown hash algorithm for pre-hash SLH-DSA");
		return false;
	}

	// Hash the message. Lazily fetch and cache EVP_MD* (static lifetime, no free needed).
	unsigned char digest[64];  // max: SHA-512 / SHAKE256 = 64 bytes
	if (info->md == NULL)
	{
		info->md = EVP_MD_fetch(NULL, info->evpName, NULL);
		if (info->md == NULL)
		{
			ERROR_MSG("EVP_MD_fetch(%s) failed", info->evpName);
			return false;
		}
	}

	if (info->isXof)
	{
		// SHAKE requires EVP_DigestFinalXOF for fixed-length output
		EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
		if (!mdctx)
		{
			OPENSSL_cleanse(digest, sizeof(digest));
			return false;
		}
		bool ok = EVP_DigestInit_ex(mdctx, info->md, NULL) &&
		          EVP_DigestUpdate(mdctx, message.const_byte_str(), message.size()) &&
		          EVP_DigestFinalXOF(mdctx, digest, info->digestLen);
		EVP_MD_CTX_free(mdctx);
		if (!ok)
		{
			OPENSSL_cleanse(digest, sizeof(digest));
			ERROR_MSG("SHAKE hash failed for pre-hash SLH-DSA");
			return false;
		}
	}
	else
	{
		unsigned int dLen = 0;
		if (!EVP_Digest(message.const_byte_str(), message.size(),
		                digest, &dLen, info->md, NULL))
		{
			OPENSSL_cleanse(digest, sizeof(digest));
			ERROR_MSG("Hash failed for pre-hash SLH-DSA (%s)", info->evpName);
			return false;
		}
	}

	// Build M' = 0x01 || len(ctx) || ctx || AlgId_DER || H(M)
	// Overflow guard: contextLen <= 255, algIdDerLen <= 15, digestLen <= 64 (max 336).
	size_t totalLen = 1 + 1;
	if (params->contextLen > SIZE_MAX - totalLen) { OPENSSL_cleanse(digest, sizeof(digest)); return false; }
	totalLen += params->contextLen;
	if (info->algIdDerLen > SIZE_MAX - totalLen) { OPENSSL_cleanse(digest, sizeof(digest)); return false; }
	totalLen += info->algIdDerLen;
	if (info->digestLen > SIZE_MAX - totalLen) { OPENSSL_cleanse(digest, sizeof(digest)); return false; }
	totalLen += info->digestLen;
	encoded.resize(totalLen);
	size_t off = 0;
	encoded[off++] = 0x01;  // pre-hash domain separator (FIPS 205 §10.1)
	encoded[off++] = (unsigned char)params->contextLen;
	if (params->contextLen > 0)
	{
		memcpy(&encoded[off], params->context, params->contextLen);
		off += params->contextLen;
	}
	memcpy(&encoded[off], info->algIdDer, info->algIdDerLen);
	off += info->algIdDerLen;
	memcpy(&encoded[off], digest, info->digestLen);
	OPENSSL_cleanse(digest, sizeof(digest));

	return true;
}

// Check if mechanism is a supported SLH-DSA family mechanism
static bool isSLHDSAMechanism(AsymMech::Type mech)
{
	switch (mech)
	{
		case AsymMech::SLHDSA:
		case AsymMech::HASH_SLHDSA:
		case AsymMech::HASH_SLHDSA_SHA224:
		case AsymMech::HASH_SLHDSA_SHA256:
		case AsymMech::HASH_SLHDSA_SHA384:
		case AsymMech::HASH_SLHDSA_SHA512:
		case AsymMech::HASH_SLHDSA_SHA3_224:
		case AsymMech::HASH_SLHDSA_SHA3_256:
		case AsymMech::HASH_SLHDSA_SHA3_384:
		case AsymMech::HASH_SLHDSA_SHA3_512:
		case AsymMech::HASH_SLHDSA_SHAKE128:
		case AsymMech::HASH_SLHDSA_SHAKE256:
			return true;
		default:
			return false;
	}
}

// Map CKP_SLH_DSA_* → OpenSSL name string (used only in generateKeyPair)
static const char* slhdsaParamSetToName(CK_ULONG ps)
{
	switch (ps)
	{
		case CKP_SLH_DSA_SHA2_128S:  return "slh-dsa-sha2-128s";
		case CKP_SLH_DSA_SHAKE_128S: return "slh-dsa-shake-128s";
		case CKP_SLH_DSA_SHA2_128F:  return "slh-dsa-sha2-128f";
		case CKP_SLH_DSA_SHAKE_128F: return "slh-dsa-shake-128f";
		case CKP_SLH_DSA_SHA2_192S:  return "slh-dsa-sha2-192s";
		case CKP_SLH_DSA_SHAKE_192S: return "slh-dsa-shake-192s";
		case CKP_SLH_DSA_SHA2_192F:  return "slh-dsa-sha2-192f";
		case CKP_SLH_DSA_SHAKE_192F: return "slh-dsa-shake-192f";
		case CKP_SLH_DSA_SHA2_256S:  return "slh-dsa-sha2-256s";
		case CKP_SLH_DSA_SHAKE_256S: return "slh-dsa-shake-256s";
		case CKP_SLH_DSA_SHA2_256F:  return "slh-dsa-sha2-256f";
		case CKP_SLH_DSA_SHAKE_256F: return "slh-dsa-shake-256f";
		default:                     return NULL;
	}
}

// ─── Signing ─────────────────────────────────────────────────────────────────

bool OSSLSLHDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
                      ByteString& signature, const AsymMech::Type mechanism,
                      const void* param, const size_t paramLen)
{
	if (!isSLHDSAMechanism(mechanism))
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (!privateKey->isOfType(OSSLSLHDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied for SLH-DSA sign");
		return false;
	}

	OSSLSLHDSAPrivateKey* pk = (OSSLSLHDSAPrivateKey*)privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL SLH-DSA private key");
		return false;
	}

	// For pre-hash mechanisms: build M' = 0x01 || len(ctx) || ctx || OID || H(M)
	const unsigned char* signData;
	size_t signDataLen;
	ByteString preHashMsg;

	const SLHDSA_SIGN_PARAMS* slhdsaParams = NULL;
	if (param != NULL && paramLen == sizeof(SLHDSA_SIGN_PARAMS))
		slhdsaParams = (const SLHDSA_SIGN_PARAMS*)param;

	if (slhdsaParams && slhdsaParams->preHash)
	{
		if (!buildSLHDSAPreHashMsg(dataToSign, slhdsaParams, preHashMsg))
			return false;
		signData    = preHashMsg.const_byte_str();
		signDataLen = preHashMsg.size();
	}
	else
	{
		signData    = dataToSign.const_byte_str();
		signDataLen = dataToSign.size();
	}

	size_t sigLen = pk->getOutputLength();
	signature.resize(sigLen);

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) { ERROR_MSG("EVP_MD_CTX_new failed"); return false; }

	// Build OSSL_PARAM array for context string (FIPS 205 §9.2) and
	// deterministic mode (FIPS 205 §10). Must be built BEFORE EVP_DigestSignInit_ex
	// so the params are passed directly to slh_dsa_digest_signverify_init.
	OSSL_PARAM osslParams[3];
	int nParams = 0;
	int deterministic = 0;
	if (slhdsaParams)
	{
		if (slhdsaParams->contextLen > 0)
		{
			osslParams[nParams++] = OSSL_PARAM_construct_octet_string(
				OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
				(void*)slhdsaParams->context, slhdsaParams->contextLen);
		}
		if (slhdsaParams->deterministic)
		{
			deterministic = 1;
			osslParams[nParams++] = OSSL_PARAM_construct_int(
				OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
		}
	}
	osslParams[nParams] = OSSL_PARAM_construct_end();

	EVP_PKEY_CTX* pkeyCtx = NULL;
	if (!EVP_DigestSignInit_ex(ctx, &pkeyCtx, NULL, NULL, NULL, pkey,
	                           nParams > 0 ? osslParams : NULL))
	{
		ERROR_MSG("SLH-DSA sign init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}

	if (!EVP_DigestSign(ctx, &signature[0], &sigLen, signData, signDataLen))
	{
		ERROR_MSG("SLH-DSA sign failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	signature.resize(sigLen);
	return true;
}

bool OSSLSLHDSA::signInit(PrivateKey* pk, const AsymMech::Type mech,
                           const void* param, const size_t paramLen)
{
	if (!AsymmetricAlgorithm::signInit(pk, mech, param, paramLen)) return false;
	m_signMsg.wipe();
	m_hasSignParams = (param != NULL && paramLen == sizeof(SLHDSA_SIGN_PARAMS));
	if (m_hasSignParams) memcpy(&m_signParams, param, sizeof(SLHDSA_SIGN_PARAMS));
	return true;
}

bool OSSLSLHDSA::signUpdate(const ByteString& data)
{
	if (!AsymmetricAlgorithm::signUpdate(data)) return false;
	m_signMsg += data;
	return true;
}

bool OSSLSLHDSA::signFinal(ByteString& signature)
{
	PrivateKey* pk   = currentPrivateKey;
	AsymMech::Type m = currentMechanism;
	if (!AsymmetricAlgorithm::signFinal(signature)) return false;
	bool ok = sign(pk, m_signMsg, signature, m,
	               m_hasSignParams ? &m_signParams : NULL,
	               m_hasSignParams ? sizeof(m_signParams) : 0);
	m_signMsg.wipe();
	return ok;
}

// ─── Verification ────────────────────────────────────────────────────────────

bool OSSLSLHDSA::verify(PublicKey* publicKey, const ByteString& originalData,
                        const ByteString& signature, const AsymMech::Type mechanism,
                        const void* param, const size_t paramLen)
{
	if (!isSLHDSAMechanism(mechanism))
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (!publicKey->isOfType(OSSLSLHDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied for SLH-DSA verify");
		return false;
	}

	OSSLSLHDSAPublicKey* pk = (OSSLSLHDSAPublicKey*)publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL SLH-DSA public key");
		return false;
	}

	// For pre-hash: rebuild M' and verify against that
	const unsigned char* verifyData;
	size_t verifyDataLen;
	ByteString preHashMsg;

	const SLHDSA_SIGN_PARAMS* slhdsaParams = NULL;
	if (param != NULL && paramLen == sizeof(SLHDSA_SIGN_PARAMS))
		slhdsaParams = (const SLHDSA_SIGN_PARAMS*)param;

	if (slhdsaParams && slhdsaParams->preHash)
	{
		if (!buildSLHDSAPreHashMsg(originalData, slhdsaParams, preHashMsg))
			return false;
		verifyData    = preHashMsg.const_byte_str();
		verifyDataLen = preHashMsg.size();
	}
	else
	{
		verifyData    = originalData.const_byte_str();
		verifyDataLen = originalData.size();
	}

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) { ERROR_MSG("EVP_MD_CTX_new failed"); return false; }

	// Build OSSL_PARAM for context string (FIPS 205 §9.2). Pass directly to
	// EVP_DigestVerifyInit_ex so slh_dsa_digest_signverify_init receives them.
	OSSL_PARAM osslParams[2];
	int nParams = 0;
	if (slhdsaParams && slhdsaParams->contextLen > 0)
	{
		osslParams[nParams++] = OSSL_PARAM_construct_octet_string(
			OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
			(void*)slhdsaParams->context, slhdsaParams->contextLen);
	}
	osslParams[nParams] = OSSL_PARAM_construct_end();

	EVP_PKEY_CTX* pkeyCtx = NULL;
	if (!EVP_DigestVerifyInit_ex(ctx, &pkeyCtx, NULL, NULL, NULL, pkey,
	                             nParams > 0 ? osslParams : NULL))
	{
		ERROR_MSG("SLH-DSA verify init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}

	int ret = EVP_DigestVerify(ctx,
	                           signature.const_byte_str(), signature.size(),
	                           verifyData, verifyDataLen);
	EVP_MD_CTX_free(ctx);
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("SLH-DSA verify failed (0x%08X)", ERR_get_error());
		return false;
	}
	return true;
}

bool OSSLSLHDSA::verifyInit(PublicKey* pk, const AsymMech::Type mech,
                             const void* param, const size_t paramLen)
{
	if (!AsymmetricAlgorithm::verifyInit(pk, mech, param, paramLen)) return false;
	m_verifyMsg.wipe();
	m_hasVerifyParams = (param != NULL && paramLen == sizeof(SLHDSA_SIGN_PARAMS));
	if (m_hasVerifyParams) memcpy(&m_verifyParams, param, sizeof(SLHDSA_SIGN_PARAMS));
	return true;
}

bool OSSLSLHDSA::verifyUpdate(const ByteString& data)
{
	if (!AsymmetricAlgorithm::verifyUpdate(data)) return false;
	m_verifyMsg += data;
	return true;
}

bool OSSLSLHDSA::verifyFinal(const ByteString& signature)
{
	PublicKey* pk    = currentPublicKey;
	AsymMech::Type m = currentMechanism;
	ByteString dummy;
	if (!AsymmetricAlgorithm::verifyFinal(dummy)) return false;
	bool ok = verify(pk, m_verifyMsg, signature, m,
	                 m_hasVerifyParams ? &m_verifyParams : NULL,
	                 m_hasVerifyParams ? sizeof(m_verifyParams) : 0);
	m_verifyMsg.wipe();
	return ok;
}

// ─── Encryption / decryption (not supported) ─────────────────────────────────

bool OSSLSLHDSA::encrypt(PublicKey* /*pk*/, const ByteString& /*data*/,
                          ByteString& /*enc*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("SLH-DSA does not support encryption");
	return false;
}

bool OSSLSLHDSA::decrypt(PrivateKey* /*pk*/, const ByteString& /*enc*/,
                          ByteString& /*data*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("SLH-DSA does not support decryption");
	return false;
}

// ─── Key factory ─────────────────────────────────────────────────────────────

bool OSSLSLHDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
                                  AsymmetricParameters* parameters, RNG* /*rng*/)
{
	if (ppKeyPair == NULL || parameters == NULL) return false;

	if (!parameters->areOfType(SLHDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for SLH-DSA key generation");
		return false;
	}

	SLHDSAParameters* params = (SLHDSAParameters*)parameters;
	const char* keyName = slhdsaParamSetToName(params->getParameterSet());
	if (keyName == NULL)
	{
		ERROR_MSG("Unknown SLH-DSA parameter set %lu", params->getParameterSet());
		return false;
	}

	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, keyName, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_PKEY_CTX_new_from_name(%s) failed (0x%08X)", keyName, ERR_get_error());
		return false;
	}
	if (EVP_PKEY_keygen_init(ctx) != 1)
	{
		ERROR_MSG("SLH-DSA keygen init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Deterministic generation from a caller-supplied seed
	// (FIPS 205 SK.seed||SK.prf||PK.seed, 3n B). The provider rejects an
	// out-of-range length here.
	const ByteString& seed = params->getSeed();
	if (seed.size() != 0)
	{
		OSSL_PARAM seedParams[2];
		seedParams[0] = OSSL_PARAM_construct_octet_string(
			OSSL_PKEY_PARAM_SLH_DSA_SEED, (void*)seed.const_byte_str(), seed.size());
		seedParams[1] = OSSL_PARAM_construct_end();
		if (EVP_PKEY_CTX_set_params(ctx, seedParams) != 1)
		{
			ERROR_MSG("SLH-DSA seed param rejected (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
	}

	if (EVP_PKEY_keygen(ctx, &pkey) != 1)
	{
		ERROR_MSG("SLH-DSA keygen failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	OSSLSLHDSAKeyPair* kp = new OSSLSLHDSAKeyPair();
	((OSSLSLHDSAPublicKey*)kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLSLHDSAPrivateKey*)kp->getPrivateKey())->setFromOSSL(pkey);
	EVP_PKEY_free(pkey);

	*ppKeyPair = kp;
	return true;
}

unsigned long OSSLSLHDSA::getMinKeySize()
{
	return 128;  // SHA2-128s / SHAKE-128s security strength
}

unsigned long OSSLSLHDSA::getMaxKeySize()
{
	return 256;  // SHA2-256f / SHAKE-256f security strength
}

bool OSSLSLHDSA::deriveKey(SymmetricKey** /*ppKey*/, PublicKey* /*pub*/, PrivateKey* /*priv*/)
{
	ERROR_MSG("SLH-DSA does not support key derivation");
	return false;
}

bool OSSLSLHDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString dPub  = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLSLHDSAKeyPair* kp = new OSSLSLHDSAKeyPair();
	bool rv = true;
	if (!((SLHDSAPublicKey*)kp->getPublicKey())->deserialise(dPub))    rv = false;
	if (!((SLHDSAPrivateKey*)kp->getPrivateKey())->deserialise(dPriv)) rv = false;
	if (!rv) { delete kp; return false; }
	*ppKeyPair = kp;
	return true;
}

bool OSSLSLHDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;
	OSSLSLHDSAPublicKey* pub = new OSSLSLHDSAPublicKey();
	if (!pub->deserialise(serialisedData)) { delete pub; return false; }
	*ppPublicKey = pub;
	return true;
}

bool OSSLSLHDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;
	OSSLSLHDSAPrivateKey* priv = new OSSLSLHDSAPrivateKey();
	if (!priv->deserialise(serialisedData)) { delete priv; return false; }
	*ppPrivateKey = priv;
	return true;
}

bool OSSLSLHDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if (ppParams == NULL || serialisedData.size() == 0) return false;
	SLHDSAParameters* params = new SLHDSAParameters();
	if (!params->deserialise(serialisedData)) { delete params; return false; }
	*ppParams = params;
	return true;
}

PublicKey* OSSLSLHDSA::newPublicKey()
{
	return (PublicKey*) new OSSLSLHDSAPublicKey();
}

PrivateKey* OSSLSLHDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLSLHDSAPrivateKey();
}

AsymmetricParameters* OSSLSLHDSA::newParameters()
{
	return (AsymmetricParameters*) new SLHDSAParameters();
}
