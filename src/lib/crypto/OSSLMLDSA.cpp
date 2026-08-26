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
 OSSLMLDSA.cpp

 OpenSSL ML-DSA (FIPS 204) asymmetric algorithm implementation
 Supports: context string, hedging control, HashML-DSA pre-hash (PKCS#11 v3.2)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLMLDSA.h"
#include "MLDSAParameters.h"
#include "OSSLMLDSAKeyPair.h"
#include "OSSLMLDSAPublicKey.h"
#include "OSSLMLDSAPrivateKey.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>
#include "../vendor_mechanisms.h"  // PQCTODAY_ML_DSA_MU_LEN (remediation R34)

// ─── Pre-hash support (FIPS 204 §5.4, HashML-DSA) ──────────────────────────

struct PreHashInfo
{
	const char* evpName;
	const unsigned char* algIdDer;
	size_t algIdDerLen;
	size_t digestLen;
	bool isXof;
	mutable EVP_MD* md;  // cached after first EVP_MD_fetch; NULL until first use
};

// DER-encoded AlgorithmIdentifier for each hash: SEQUENCE { OID [, NULL] }
// SHA-2/SHA-3: SEQUENCE { OID, NULL }  (15 bytes)
// SHAKE:       SEQUENCE { OID }        (13 bytes, absent parameters)
static const unsigned char ALGID_SHA224[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04, 0x05,0x00
};
static const unsigned char ALGID_SHA256[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01, 0x05,0x00
};
static const unsigned char ALGID_SHA384[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02, 0x05,0x00
};
static const unsigned char ALGID_SHA512[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03, 0x05,0x00
};
static const unsigned char ALGID_SHA3_224[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x07, 0x05,0x00
};
static const unsigned char ALGID_SHA3_256[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x08, 0x05,0x00
};
static const unsigned char ALGID_SHA3_384[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x09, 0x05,0x00
};
static const unsigned char ALGID_SHA3_512[] = {
	0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0a, 0x05,0x00
};
static const unsigned char ALGID_SHAKE128[] = {
	0x30,0x0b, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0b
};
static const unsigned char ALGID_SHAKE256[] = {
	0x30,0x0b, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0c
};

static const PreHashInfo* getPreHashInfo(HashAlgo::Type hashAlg)
{
	// SHAKE output lengths per FIPS 204: SHAKE128 → 32 bytes, SHAKE256 → 64 bytes
	// md is lazily populated on first use; NULL here means "not yet fetched".
	static const PreHashInfo table[] = {
		{ "SHA2-224",  ALGID_SHA224,    15, 28, false, NULL },
		{ "SHA2-256",  ALGID_SHA256,    15, 32, false, NULL },
		{ "SHA2-384",  ALGID_SHA384,    15, 48, false, NULL },
		{ "SHA2-512",  ALGID_SHA512,    15, 64, false, NULL },
		{ "SHA3-224",  ALGID_SHA3_224,  15, 28, false, NULL },
		{ "SHA3-256",  ALGID_SHA3_256,  15, 32, false, NULL },
		{ "SHA3-384",  ALGID_SHA3_384,  15, 48, false, NULL },
		{ "SHA3-512",  ALGID_SHA3_512,  15, 64, false, NULL },
		{ "SHAKE128",  ALGID_SHAKE128,  13, 32, true,  NULL },
		{ "SHAKE256",  ALGID_SHAKE256,  13, 64, true,  NULL },
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
void OSSLMLDSA_cleanupPreHashCache()
{
	static const HashAlgo::Type allAlgs[] = {
		HashAlgo::SHA224, HashAlgo::SHA256, HashAlgo::SHA384, HashAlgo::SHA512,
		HashAlgo::SHA3_224, HashAlgo::SHA3_256, HashAlgo::SHA3_384, HashAlgo::SHA3_512,
		HashAlgo::SHAKE128, HashAlgo::SHAKE256
	};
	for (auto alg : allAlgs)
	{
		const PreHashInfo* info = getPreHashInfo(alg);
		if (info && info->md)
		{
			EVP_MD_free(info->md);
			info->md = NULL;
		}
	}
}

// Build HashML-DSA encoding: M' = 0x01 || len(ctx) || ctx || OID || PH(M)
// per FIPS 204 §5.4
// Build M' = 0x01 || contextLen || context || AlgId_DER || digest, from an
// ALREADY-COMPUTED digest of the given length (caller must have already
// validated digestLen against info->digestLen -- see the two call sites).
// Split out of buildPreHashEncoding (remediation R37, phase 8) so the bare
// generic CKM_HASH_ML_DSA mechanism (PKCS#11 v3.2 §6.67.6 -- caller supplies
// an already-hashed PHM directly, must NOT be hashed again) can share this
// encoding step without buildPreHashEncoding's own internal EVP_Digest call.
static bool buildMPrimeFromDigest(const unsigned char* digest, size_t digestLen,
                                  const PreHashInfo* info,
                                  const MLDSA_SIGN_PARAMS* params,
                                  ByteString& encoded)
{
	// Overflow guard: contextLen <= 255, algIdDerLen <= 15, digestLen <= 64 (max 336).
	size_t totalLen = 1 + 1;
	if (params->contextLen > SIZE_MAX - totalLen) return false;
	totalLen += params->contextLen;
	if (info->algIdDerLen > SIZE_MAX - totalLen) return false;
	totalLen += info->algIdDerLen;
	if (digestLen > SIZE_MAX - totalLen) return false;
	totalLen += digestLen;
	encoded.resize(totalLen);
	size_t off = 0;
	encoded[off++] = 0x01;  // pre-hash domain separator
	encoded[off++] = (unsigned char)params->contextLen;
	if (params->contextLen > 0)
	{
		memcpy(&encoded[off], params->context, params->contextLen);
		off += params->contextLen;
	}
	memcpy(&encoded[off], info->algIdDer, info->algIdDerLen);
	off += info->algIdDerLen;
	memcpy(&encoded[off], digest, digestLen);
	return true;
}

static bool buildPreHashEncoding(const ByteString& message,
                                 const MLDSA_SIGN_PARAMS* params,
                                 ByteString& encoded)
{
	const PreHashInfo* info = getPreHashInfo(params->hashAlg);
	if (!info)
	{
		ERROR_MSG("Unknown hash algorithm for pre-hash ML-DSA");
		return false;
	}

	// Hash the message with the specified algorithm.
	// Lazily fetch and cache EVP_MD* — the table is static so the pointer lives
	// for the entire program lifetime and does not need to be freed.
	unsigned char digest[64]; // max: SHA-512 / SHAKE256 = 64 bytes
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
			ERROR_MSG("SHAKE hash failed for pre-hash ML-DSA");
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
			ERROR_MSG("Hash failed for pre-hash ML-DSA (%s)", info->evpName);
			return false;
		}
	}

	bool ok = buildMPrimeFromDigest(digest, info->digestLen, info, params, encoded);
	OPENSSL_cleanse(digest, sizeof(digest));
	return ok;
}

// PKCS#11 v3.2 §6.67.6, bare generic CKM_HASH_ML_DSA: dataToSign IS the PHM
// (already hashed by the caller) -- build M' directly, no internal hashing.
// Loudly rejects a wrong-length PHM rather than truncating/padding.
static bool buildMPrimeFromPHM(const ByteString& phm,
                               const MLDSA_SIGN_PARAMS* params,
                               ByteString& encoded)
{
	const PreHashInfo* info = getPreHashInfo(params->hashAlg);
	if (!info)
	{
		ERROR_MSG("Unknown hash algorithm for generic HashML-DSA");
		return false;
	}
	if (phm.size() != info->digestLen)
	{
		ERROR_MSG("CKM_HASH_ML_DSA: PHM length %zu does not match %s digest "
		         "length %zu", phm.size(), info->evpName, info->digestLen);
		return false;
	}
	return buildMPrimeFromDigest(phm.const_byte_str(), phm.size(), info, params, encoded);
}

// Check if mechanism is an ML-DSA family mechanism
static bool isMLDSAMechanism(AsymMech::Type mech)
{
	switch (mech)
	{
		case AsymMech::MLDSA:
		case AsymMech::HASH_MLDSA:
		case AsymMech::HASH_MLDSA_SHA224:
		case AsymMech::HASH_MLDSA_SHA256:
		case AsymMech::HASH_MLDSA_SHA384:
		case AsymMech::HASH_MLDSA_SHA512:
		case AsymMech::HASH_MLDSA_SHA3_224:
		case AsymMech::HASH_MLDSA_SHA3_256:
		case AsymMech::HASH_MLDSA_SHA3_384:
		case AsymMech::HASH_MLDSA_SHA3_512:
		case AsymMech::HASH_MLDSA_SHAKE128:
		case AsymMech::HASH_MLDSA_SHAKE256:
		case AsymMech::MLDSA_EXTERNAL_MU:  // remediation R34, PQCTODAY-VENDOR-EXT-MU
			return true;
		default:
			return false;
	}
}

// ─── Signing ────────────────────────────────────────────────────────────────

bool OSSLMLDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
                     ByteString& signature, const AsymMech::Type mechanism,
                     const void* param, const size_t paramLen)
{
	if (!isMLDSAMechanism(mechanism))
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (!privateKey->isOfType(OSSLMLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied for ML-DSA sign");
		return false;
	}

	OSSLMLDSAPrivateKey* pk = (OSSLMLDSAPrivateKey*)privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL ML-DSA private key");
		return false;
	}

	// Parse ML-DSA parameters (context string, hedging, pre-hash)
	const MLDSA_SIGN_PARAMS* mldsaParams = NULL;
	if (param != NULL && paramLen == sizeof(MLDSA_SIGN_PARAMS))
		mldsaParams = (const MLDSA_SIGN_PARAMS*)param;

	// Remediation R34, PQCTODAY-VENDOR-EXT-MU: dataToSign is the caller's
	// 64-byte µ (FIPS 204 Eq. 2), not a message — validated here, not left
	// to OpenSSL's own length assumptions.
	bool isExternalMu = (mechanism == AsymMech::MLDSA_EXTERNAL_MU);
	if (isExternalMu && dataToSign.size() != PQCTODAY_ML_DSA_MU_LEN)
	{
		ERROR_MSG("CKM_PQCTODAY_ML_DSA_MU requires exactly %u bytes of µ (got %zu)",
			PQCTODAY_ML_DSA_MU_LEN, dataToSign.size());
		return false;
	}

	// For pre-hash mechanisms: hash message and build encoded M'
	const unsigned char* signData;
	size_t signDataLen;
	ByteString preHashEncoded;
	bool useRawEncoding = false;

	if (mldsaParams && mldsaParams->preHash)
	{
		if (!buildPreHashEncoding(dataToSign, mldsaParams, preHashEncoded))
			return false;
		signData = preHashEncoded.const_byte_str();
		signDataLen = preHashEncoded.size();
		useRawEncoding = true;
	}
	else if (mldsaParams && mldsaParams->phmInput)
	{
		// Remediation R37 (phase 8): bare generic CKM_HASH_ML_DSA -- dataToSign
		// IS the PHM already, never hash it again.
		if (!buildMPrimeFromPHM(dataToSign, mldsaParams, preHashEncoded))
			return false;
		signData = preHashEncoded.const_byte_str();
		signDataLen = preHashEncoded.size();
		useRawEncoding = true;
	}
	else
	{
		signData = dataToSign.const_byte_str();
		signDataLen = dataToSign.size();
	}

	// Pre-size the output buffer to the maximum signature length
	size_t sigLen = pk->getOutputLength();
	signature.resize(sigLen);

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_MD_CTX_new failed");
		return false;
	}

	// Capture EVP_PKEY_CTX to set signature parameters
	EVP_PKEY_CTX* pkeyCtx = NULL;
	if (!EVP_DigestSignInit(ctx, &pkeyCtx, NULL, NULL, pkey))
	{
		ERROR_MSG("ML-DSA sign init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}

	// Set OpenSSL signature parameters (context, hedging, encoding mode)
	if (mldsaParams)
	{
		OSSL_PARAM osslParams[4];  // max: DETERMINISTIC + one-of{MESSAGE_ENCODING,MU} + terminator
		int nParams = 0;
		int deterministic = 0;
		int msgEncoding = 1;  // 1 = pure message (default)
		int mu = 1;

		// Hedging control: CKH_DETERMINISTIC_REQUIRED → set deterministic=1
		if (mldsaParams->deterministic)
		{
			deterministic = 1;
			osslParams[nParams++] = OSSL_PARAM_construct_int(
				OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
		}

		// Context string — only for pure ML-DSA (pre-hash embeds context in M')
		if (mldsaParams->contextLen > 0 && !useRawEncoding)
		{
			osslParams[nParams++] = OSSL_PARAM_construct_octet_string(
				OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
				(void*)mldsaParams->context, mldsaParams->contextLen);
		}

		// Pre-hash: tell OpenSSL input is already pre-encoded M'
		if (useRawEncoding)
		{
			msgEncoding = 0;  // 0 = raw / pre-encoded
			osslParams[nParams++] = OSSL_PARAM_construct_int(
				OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &msgEncoding);
		}

		// External-µ (remediation R34, PQCTODAY-VENDOR-EXT-MU): tell OpenSSL
		// the input IS µ already, skip its own H(tr‖M') computation entirely.
		// Mutually exclusive with useRawEncoding (different mechanisms).
		if (isExternalMu)
		{
			osslParams[nParams++] = OSSL_PARAM_construct_int(
				OSSL_SIGNATURE_PARAM_MU, &mu);
		}

		if (nParams > 0)
		{
			osslParams[nParams] = OSSL_PARAM_construct_end();
			if (!EVP_PKEY_CTX_set_params(pkeyCtx, osslParams))
			{
				ERROR_MSG("Failed to set ML-DSA sign params (0x%08X)",
				          ERR_get_error());
				EVP_MD_CTX_free(ctx);
				return false;
			}
		}
	}

	if (!EVP_DigestSign(ctx, &signature[0], &sigLen, signData, signDataLen))
	{
		ERROR_MSG("ML-DSA sign failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	signature.resize(sigLen);
	return true;
}

bool OSSLMLDSA::signInit(PrivateKey* pk, const AsymMech::Type mech,
                          const void* param, const size_t paramLen)
{
	if (!AsymmetricAlgorithm::signInit(pk, mech, param, paramLen)) return false;
	m_signMsg.wipe();
	m_hasSignParams = (param != NULL && paramLen == sizeof(MLDSA_SIGN_PARAMS));
	if (m_hasSignParams) memcpy(&m_signParams, param, sizeof(MLDSA_SIGN_PARAMS));
	return true;
}

bool OSSLMLDSA::signUpdate(const ByteString& data)
{
	if (!AsymmetricAlgorithm::signUpdate(data)) return false;
	m_signMsg += data;
	return true;
}

bool OSSLMLDSA::signFinal(ByteString& signature)
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

bool OSSLMLDSA::verify(PublicKey* publicKey, const ByteString& originalData,
                       const ByteString& signature, const AsymMech::Type mechanism,
                       const void* param, const size_t paramLen)
{
	if (!isMLDSAMechanism(mechanism))
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}
	if (!publicKey->isOfType(OSSLMLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied for ML-DSA verify");
		return false;
	}

	OSSLMLDSAPublicKey* pk = (OSSLMLDSAPublicKey*)publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL ML-DSA public key");
		return false;
	}

	// Parse ML-DSA parameters
	const MLDSA_SIGN_PARAMS* mldsaParams = NULL;
	if (param != NULL && paramLen == sizeof(MLDSA_SIGN_PARAMS))
		mldsaParams = (const MLDSA_SIGN_PARAMS*)param;

	// Remediation R34, PQCTODAY-VENDOR-EXT-MU — see sign()'s own comment.
	bool isExternalMu = (mechanism == AsymMech::MLDSA_EXTERNAL_MU);
	if (isExternalMu && originalData.size() != PQCTODAY_ML_DSA_MU_LEN)
	{
		ERROR_MSG("CKM_PQCTODAY_ML_DSA_MU requires exactly %u bytes of µ (got %zu)",
			PQCTODAY_ML_DSA_MU_LEN, originalData.size());
		return false;
	}

	// For pre-hash mechanisms: hash message and build encoded M'
	const unsigned char* verifyData;
	size_t verifyDataLen;
	ByteString preHashEncoded;
	bool useRawEncoding = false;

	if (mldsaParams && mldsaParams->preHash)
	{
		if (!buildPreHashEncoding(originalData, mldsaParams, preHashEncoded))
			return false;
		verifyData = preHashEncoded.const_byte_str();
		verifyDataLen = preHashEncoded.size();
		useRawEncoding = true;
	}
	else if (mldsaParams && mldsaParams->phmInput)
	{
		// Remediation R37 (phase 8): see sign()'s identical comment.
		if (!buildMPrimeFromPHM(originalData, mldsaParams, preHashEncoded))
			return false;
		verifyData = preHashEncoded.const_byte_str();
		verifyDataLen = preHashEncoded.size();
		useRawEncoding = true;
	}
	else
	{
		verifyData = originalData.const_byte_str();
		verifyDataLen = originalData.size();
	}

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_MD_CTX_new failed");
		return false;
	}

	// Capture EVP_PKEY_CTX to set signature parameters
	EVP_PKEY_CTX* pkeyCtx = NULL;
	if (!EVP_DigestVerifyInit(ctx, &pkeyCtx, NULL, NULL, pkey))
	{
		ERROR_MSG("ML-DSA verify init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}

	// Set OpenSSL signature parameters (context, encoding mode)
	// Note: deterministic flag is irrelevant for verification
	if (mldsaParams)
	{
		OSSL_PARAM osslParams[4];  // max: CONTEXT_STRING + one-of{MESSAGE_ENCODING,MU} + terminator
		int nParams = 0;
		int msgEncoding = 1;
		int mu = 1;

		// Context string — only for pure ML-DSA
		if (mldsaParams->contextLen > 0 && !useRawEncoding)
		{
			osslParams[nParams++] = OSSL_PARAM_construct_octet_string(
				OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
				(void*)mldsaParams->context, mldsaParams->contextLen);
		}

		// Pre-hash: raw M'
		if (useRawEncoding)
		{
			msgEncoding = 0;
			osslParams[nParams++] = OSSL_PARAM_construct_int(
				OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &msgEncoding);
		}

		// External-µ (remediation R34, PQCTODAY-VENDOR-EXT-MU) — see sign()'s
		// own comment.
		if (isExternalMu)
		{
			osslParams[nParams++] = OSSL_PARAM_construct_int(
				OSSL_SIGNATURE_PARAM_MU, &mu);
		}

		if (nParams > 0)
		{
			osslParams[nParams] = OSSL_PARAM_construct_end();
			if (!EVP_PKEY_CTX_set_params(pkeyCtx, osslParams))
			{
				ERROR_MSG("Failed to set ML-DSA verify params (0x%08X)",
				          ERR_get_error());
				EVP_MD_CTX_free(ctx);
				return false;
			}
		}
	}

	int ret = EVP_DigestVerify(ctx,
	                           signature.const_byte_str(), signature.size(),
	                           verifyData, verifyDataLen);
	EVP_MD_CTX_free(ctx);
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("ML-DSA verify failed (0x%08X)", ERR_get_error());
		return false;
	}
	return true;
}

bool OSSLMLDSA::verifyInit(PublicKey* pk, const AsymMech::Type mech,
                            const void* param, const size_t paramLen)
{
	if (!AsymmetricAlgorithm::verifyInit(pk, mech, param, paramLen)) return false;
	m_verifyMsg.wipe();
	m_hasVerifyParams = (param != NULL && paramLen == sizeof(MLDSA_SIGN_PARAMS));
	if (m_hasVerifyParams) memcpy(&m_verifyParams, param, sizeof(MLDSA_SIGN_PARAMS));
	return true;
}

bool OSSLMLDSA::verifyUpdate(const ByteString& data)
{
	if (!AsymmetricAlgorithm::verifyUpdate(data)) return false;
	m_verifyMsg += data;
	return true;
}

bool OSSLMLDSA::verifyFinal(const ByteString& signature)
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

bool OSSLMLDSA::encrypt(PublicKey* /*pk*/, const ByteString& /*data*/,
                         ByteString& /*enc*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("ML-DSA does not support encryption");
	return false;
}

bool OSSLMLDSA::decrypt(PrivateKey* /*pk*/, const ByteString& /*enc*/,
                         ByteString& /*data*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("ML-DSA does not support decryption");
	return false;
}

// ─── Key factory ─────────────────────────────────────────────────────────────

bool OSSLMLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
                                 AsymmetricParameters* parameters, RNG* /*rng*/)
{
	if (ppKeyPair == NULL || parameters == NULL) return false;

	if (!parameters->areOfType(MLDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-DSA key generation");
		return false;
	}

	MLDSAParameters* params = (MLDSAParameters*)parameters;
	const char* keyName;
	switch (params->getParameterSet())
	{
		case CKP_ML_DSA_44: keyName = "ml-dsa-44"; break;
		case CKP_ML_DSA_65: keyName = "ml-dsa-65"; break;
		case CKP_ML_DSA_87: keyName = "ml-dsa-87"; break;
		default:
			ERROR_MSG("Unknown ML-DSA parameter set %lu", params->getParameterSet());
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
		ERROR_MSG("ML-DSA keygen init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Deterministic generation from a caller-supplied seed (FIPS 204 xi, 32 B).
	// OpenSSL 3.5+ derives the key reproducibly when the "seed" param is set
	// before keygen; an out-of-range length is rejected by the provider here.
	const ByteString& seed = params->getSeed();
	if (seed.size() != 0)
	{
		OSSL_PARAM seedParams[2];
		seedParams[0] = OSSL_PARAM_construct_octet_string(
			OSSL_PKEY_PARAM_ML_DSA_SEED, (void*)seed.const_byte_str(), seed.size());
		seedParams[1] = OSSL_PARAM_construct_end();
		if (EVP_PKEY_CTX_set_params(ctx, seedParams) != 1)
		{
			ERROR_MSG("ML-DSA seed param rejected (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
	}

	if (EVP_PKEY_keygen(ctx, &pkey) != 1)
	{
		ERROR_MSG("ML-DSA keygen failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	OSSLMLDSAKeyPair* kp = new OSSLMLDSAKeyPair();
	((OSSLMLDSAPublicKey*)kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLMLDSAPrivateKey*)kp->getPrivateKey())->setFromOSSL(pkey);
	EVP_PKEY_free(pkey);

	*ppKeyPair = kp;
	return true;
}

unsigned long OSSLMLDSA::getMinKeySize()
{
	return 128;  // ML-DSA-44 security strength
}

unsigned long OSSLMLDSA::getMaxKeySize()
{
	return 256;  // ML-DSA-87 security strength
}

bool OSSLMLDSA::deriveKey(SymmetricKey** /*ppKey*/, PublicKey* /*pub*/, PrivateKey* /*priv*/)
{
	ERROR_MSG("ML-DSA does not support key derivation");
	return false;
}

bool OSSLMLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString dPub  = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLMLDSAKeyPair* kp = new OSSLMLDSAKeyPair();
	bool rv = true;
	if (!((MLDSAPublicKey*)kp->getPublicKey())->deserialise(dPub))   rv = false;
	if (!((MLDSAPrivateKey*)kp->getPrivateKey())->deserialise(dPriv)) rv = false;
	if (!rv) { delete kp; return false; }
	*ppKeyPair = kp;
	return true;
}

bool OSSLMLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;
	OSSLMLDSAPublicKey* pub = new OSSLMLDSAPublicKey();
	if (!pub->deserialise(serialisedData)) { delete pub; return false; }
	*ppPublicKey = pub;
	return true;
}

bool OSSLMLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;
	OSSLMLDSAPrivateKey* priv = new OSSLMLDSAPrivateKey();
	if (!priv->deserialise(serialisedData)) { delete priv; return false; }
	*ppPrivateKey = priv;
	return true;
}

bool OSSLMLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if (ppParams == NULL || serialisedData.size() == 0) return false;
	MLDSAParameters* params = new MLDSAParameters();
	if (!params->deserialise(serialisedData)) { delete params; return false; }
	*ppParams = params;
	return true;
}

PublicKey* OSSLMLDSA::newPublicKey()
{
	return (PublicKey*) new OSSLMLDSAPublicKey();
}

PrivateKey* OSSLMLDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLMLDSAPrivateKey();
}

AsymmetricParameters* OSSLMLDSA::newParameters()
{
	return (AsymmetricParameters*) new MLDSAParameters();
}
