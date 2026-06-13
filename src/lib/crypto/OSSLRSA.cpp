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
 OSSLRSA.cpp

 OpenSSL RSA asymmetric algorithm implementation — EVP_PKEY_CTX throughout (OpenSSL 3.x)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLRSA.h"
#include "OSSLUtil.h"
#include "CryptoFactory.h"
#include "RSAParameters.h"
#include "OSSLRSAKeyPair.h"
#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

// Constructor
OSSLRSA::OSSLRSA()
{
	pCurrentHash = NULL;
	pSecondHash = NULL;
	sLen = 0;
}

// Destructor
OSSLRSA::~OSSLRSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}

	if (pSecondHash != NULL)
	{
		delete pSecondHash;
	}
}

// Signing functions
bool OSSLRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		   ByteString& signature, const AsymMech::Type mechanism,
		   const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::RSA_PKCS)
	{
		// Raw PKCS #1 v1.5 sign — caller provides DigestInfo-wrapped data
		if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		OSSLRSAPrivateKey* osslKey = (OSSLRSAPrivateKey*) privateKey;
		size_t allowedLen = osslKey->getN().size() - 11;

		if (dataToSign.size() > allowedLen)
		{
			ERROR_MSG("Data to sign exceeds maximum for PKCS #1 signature");
			return false;
		}

		EVP_PKEY* pkey = osslKey->getOSSLKey();
		if (pkey == NULL)
		{
			ERROR_MSG("Could not get the OpenSSL private key");
			return false;
		}

		size_t sigLen = osslKey->getN().size();
		signature.resize(sigLen);

		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL ||
		    EVP_PKEY_sign_init(ctx) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
		    EVP_PKEY_sign(ctx, &signature[0], &sigLen,
		                  dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("PKCS #1 sign failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		EVP_PKEY_CTX_free(ctx);
		signature.resize(sigLen);
		return true;
	}
	else if (mechanism == AsymMech::RSA_PKCS_PSS)
	{
		const RSA_PKCS_PSS_PARAMS* pssParam = (RSA_PKCS_PSS_PARAMS*) param;

		if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		if (pssParam == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS))
		{
			ERROR_MSG("Invalid parameters supplied");
			return false;
		}

		const EVP_MD* hash = NULL;
		size_t allowedLen;

		switch (pssParam->hashAlg)
		{
		case HashAlgo::SHA1:   hash = EVP_sha1();   allowedLen = 20; break;
		case HashAlgo::SHA224: hash = EVP_sha224(); allowedLen = 28; break;
		case HashAlgo::SHA256: hash = EVP_sha256(); allowedLen = 32; break;
		case HashAlgo::SHA384: hash = EVP_sha384(); allowedLen = 48; break;
		case HashAlgo::SHA512: hash = EVP_sha512(); allowedLen = 64; break;
		default: return false;
		}

		OSSLRSAPrivateKey* osslKey = (OSSLRSAPrivateKey*) privateKey;

		if (dataToSign.size() != allowedLen)
		{
			ERROR_MSG("Data to sign does not match expected (%d) for RSA PSS", (int)allowedLen);
			return false;
		}

		size_t sParamLen = pssParam->sLen;
		if (sParamLen > ((privateKey->getBitLength()+6)/8-2-allowedLen))
		{
			ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
				  (unsigned long)sParamLen, privateKey->getBitLength());
			return false;
		}

		EVP_PKEY* pkey = osslKey->getOSSLKey();
		if (pkey == NULL)
		{
			ERROR_MSG("Could not get the OpenSSL private key");
			return false;
		}

		size_t sigLen = osslKey->getN().size();
		signature.resize(sigLen);

		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL ||
		    EVP_PKEY_sign_init(ctx) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
		    EVP_PKEY_CTX_set_signature_md(ctx, hash) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, (int)pssParam->sLen) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, hash) <= 0 ||
		    EVP_PKEY_sign(ctx, &signature[0], &sigLen,
		                  dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("RSA PSS sign failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		EVP_PKEY_CTX_free(ctx);
		signature.resize(sigLen);
		return true;
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Raw RSA — caller provides full modulus-size input
		if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		OSSLRSAPrivateKey* osslKey = (OSSLRSAPrivateKey*) privateKey;

		if (dataToSign.size() != osslKey->getN().size())
		{
			ERROR_MSG("Size of data to sign does not match the modulus size");
			return false;
		}

		EVP_PKEY* pkey = osslKey->getOSSLKey();
		if (pkey == NULL)
		{
			ERROR_MSG("Could not get the OpenSSL private key");
			return false;
		}

		size_t sigLen = osslKey->getN().size();
		signature.resize(sigLen);

		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL ||
		    EVP_PKEY_sign_init(ctx) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0 ||
		    EVP_PKEY_sign(ctx, &signature[0], &sigLen,
		                  dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("Raw RSA sign failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		EVP_PKEY_CTX_free(ctx);
		signature.resize(sigLen);
		return true;
	}
	else
	{
		// Call default implementation (hashing multi-step path)
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, param, paramLen);
	}
}

bool OSSLRSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
		       const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	HashAlgo::Type hash1 = HashAlgo::Unknown;
	HashAlgo::Type hash2 = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			hash1 = HashAlgo::MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SHA3_224_PKCS:
			hash1 = HashAlgo::SHA3_224;
			break;
		case AsymMech::RSA_SHA3_256_PKCS:
			hash1 = HashAlgo::SHA3_256;
			break;
		case AsymMech::RSA_SHA3_384_PKCS:
			hash1 = HashAlgo::SHA3_384;
			break;
		case AsymMech::RSA_SHA3_512_PKCS:
			hash1 = HashAlgo::SHA3_512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA1 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-20))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-28))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-32))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-48))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-64))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SHA3_224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA3_224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA3_224)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-28))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA3_224;
			break;
		case AsymMech::RSA_SHA3_256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA3_256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA3_256)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-32))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA3_256;
			break;
		case AsymMech::RSA_SHA3_384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA3_384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA3_384)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-48))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA3_384;
			break;
		case AsymMech::RSA_SHA3_512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA3_512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA3_512)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-64))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA3_512;
			break;
		case AsymMech::RSA_SSL:
			hash1 = HashAlgo::MD5;
			hash2 = HashAlgo::SHA1;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash1);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if (hash2 != HashAlgo::Unknown)
	{
		pSecondHash = CryptoFactory::i()->getHashAlgorithm(hash2);

		if (pSecondHash == NULL || !pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;

			if (pSecondHash != NULL)
			{
				delete pSecondHash;
				pSecondHash = NULL;
			}

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
		}
	}

	return true;
}

bool OSSLRSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if ((pSecondHash != NULL) && !pSecondHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		delete pSecondHash;
		pSecondHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLRSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	OSSLRSAPrivateKey* pk = (OSSLRSAPrivateKey*) currentPrivateKey;
	AsymMech::Type mechanism = currentMechanism;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString firstHash, secondHash;

	bool bFirstResult = pCurrentHash->hashFinal(firstHash);
	bool bSecondResult = (pSecondHash != NULL) ? pSecondHash->hashFinal(secondHash) : true;

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (pSecondHash != NULL)
	{
		delete pSecondHash;
		pSecondHash = NULL;
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	ByteString digest = firstHash + secondHash;

	// Resize the data block for the signature to the modulus size of the key
	signature.resize(pk->getN().size());

	// Determine the EVP_MD and whether PSS is needed
	bool isPSS = false;
	const EVP_MD* hash = NULL;
	int nid = NID_undef;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:    nid = NID_md5;    break;
		case AsymMech::RSA_SHA1_PKCS:   nid = NID_sha1;   break;
		case AsymMech::RSA_SHA224_PKCS: nid = NID_sha224; break;
		case AsymMech::RSA_SHA256_PKCS: nid = NID_sha256; break;
		case AsymMech::RSA_SHA384_PKCS: nid = NID_sha384; break;
		case AsymMech::RSA_SHA512_PKCS: nid = NID_sha512; break;
		case AsymMech::RSA_SHA3_224_PKCS: nid = NID_sha3_224; break;
		case AsymMech::RSA_SHA3_256_PKCS: nid = NID_sha3_256; break;
		case AsymMech::RSA_SHA3_384_PKCS: nid = NID_sha3_384; break;
		case AsymMech::RSA_SHA3_512_PKCS: nid = NID_sha3_512; break;
		case AsymMech::RSA_SHA1_PKCS_PSS:   isPSS = true; hash = EVP_sha1();   break;
		case AsymMech::RSA_SHA224_PKCS_PSS: isPSS = true; hash = EVP_sha224(); break;
		case AsymMech::RSA_SHA256_PKCS_PSS: isPSS = true; hash = EVP_sha256(); break;
		case AsymMech::RSA_SHA384_PKCS_PSS: isPSS = true; hash = EVP_sha384(); break;
		case AsymMech::RSA_SHA512_PKCS_PSS: isPSS = true; hash = EVP_sha512(); break;
		case AsymMech::RSA_SHA3_224_PKCS_PSS: isPSS = true; hash = EVP_sha3_224(); break;
		case AsymMech::RSA_SHA3_256_PKCS_PSS: isPSS = true; hash = EVP_sha3_256(); break;
		case AsymMech::RSA_SHA3_384_PKCS_PSS: isPSS = true; hash = EVP_sha3_384(); break;
		case AsymMech::RSA_SHA3_512_PKCS_PSS: isPSS = true; hash = EVP_sha3_512(); break;
		case AsymMech::RSA_SSL:         nid = NID_md5_sha1; break;
		default: break;
	}

	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");
		return false;
	}

	size_t sigLen = signature.size();
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	bool rv = false;

	if (ctx == NULL || EVP_PKEY_sign_init(ctx) <= 0)
	{
		ERROR_MSG("EVP_PKEY_sign_init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (isPSS)
	{
		rv = (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) > 0 &&
		      EVP_PKEY_CTX_set_signature_md(ctx, hash) > 0 &&
		      EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, (int)sLen) > 0 &&
		      EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, hash) > 0 &&
		      EVP_PKEY_sign(ctx, &signature[0], &sigLen,
		                    &digest[0], digest.size()) > 0);
	}
	else
	{
		const EVP_MD* md = EVP_get_digestbynid(nid);
		rv = (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
		      (md == NULL || EVP_PKEY_CTX_set_signature_md(ctx, md) > 0) &&
		      EVP_PKEY_sign(ctx, &signature[0], &sigLen,
		                    &digest[0], digest.size()) > 0);
	}

	if (!rv)
		ERROR_MSG("RSA sign failed (0x%08X)", ERR_get_error());

	EVP_PKEY_CTX_free(ctx);
	signature.resize(sigLen);

	return rv;
}

// Verification functions
bool OSSLRSA::verify(PublicKey* publicKey, const ByteString& originalData,
		     const ByteString& signature, const AsymMech::Type mechanism,
		     const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::RSA_PKCS)
	{
		// PKCS #1 v1.5 verification: recover DigestInfo and compare to originalData
		if (!publicKey->isOfType(OSSLRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;
		EVP_PKEY* pkey = osslKey->getOSSLKey();
		if (pkey == NULL)
		{
			ERROR_MSG("Could not get the OpenSSL public key");
			return false;
		}

		size_t nSize = osslKey->getN().size();
		ByteString recovered;
		recovered.resize(nSize);
		size_t recoveredLen = nSize;

		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL ||
		    EVP_PKEY_verify_recover_init(ctx) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
		    EVP_PKEY_verify_recover(ctx, &recovered[0], &recoveredLen,
		                           signature.const_byte_str(), signature.size()) <= 0)
		{
			ERROR_MSG("RSA PKCS verify recover failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		EVP_PKEY_CTX_free(ctx);
		recovered.resize(recoveredLen);

		return (originalData == recovered);
	}
	else if (mechanism == AsymMech::RSA_PKCS_PSS)
	{
		const RSA_PKCS_PSS_PARAMS* pssParam = (RSA_PKCS_PSS_PARAMS*) param;

		if (pssParam == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS))
		{
			ERROR_MSG("Invalid parameters supplied");
			return false;
		}

		if (!publicKey->isOfType(OSSLRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;

		const EVP_MD* hash = NULL;
		size_t allowedLen;

		switch (pssParam->hashAlg)
		{
		case HashAlgo::SHA1:   hash = EVP_sha1();   allowedLen = 20; break;
		case HashAlgo::SHA224: hash = EVP_sha224(); allowedLen = 28; break;
		case HashAlgo::SHA256: hash = EVP_sha256(); allowedLen = 32; break;
		case HashAlgo::SHA384: hash = EVP_sha384(); allowedLen = 48; break;
		case HashAlgo::SHA512: hash = EVP_sha512(); allowedLen = 64; break;
		default: return false;
		}

		if (originalData.size() != allowedLen)
			return false;

		size_t sParamLen = pssParam->sLen;
		if (sParamLen > ((osslKey->getBitLength()+6)/8-2-allowedLen))
		{
			ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
				  (unsigned long)sParamLen, osslKey->getBitLength());
			return false;
		}

		EVP_PKEY* pkey = osslKey->getOSSLKey();
		if (pkey == NULL)
		{
			ERROR_MSG("Could not get the OpenSSL public key");
			return false;
		}

		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		bool rv = (ctx != NULL &&
		           EVP_PKEY_verify_init(ctx) > 0 &&
		           EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) > 0 &&
		           EVP_PKEY_CTX_set_signature_md(ctx, hash) > 0 &&
		           EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, (int)pssParam->sLen) > 0 &&
		           EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, hash) > 0 &&
		           EVP_PKEY_verify(ctx, signature.const_byte_str(), signature.size(),
		                           originalData.const_byte_str(), originalData.size()) == 1);
		EVP_PKEY_CTX_free(ctx);
		return rv;
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Raw RSA verification: recover the data and compare
		if (!publicKey->isOfType(OSSLRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;
		EVP_PKEY* pkey = osslKey->getOSSLKey();
		if (pkey == NULL)
		{
			ERROR_MSG("Could not get the OpenSSL public key");
			return false;
		}

		size_t nSize = osslKey->getN().size();
		ByteString recovered;
		recovered.resize(nSize);
		size_t recoveredLen = nSize;

		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL ||
		    EVP_PKEY_verify_recover_init(ctx) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0 ||
		    EVP_PKEY_verify_recover(ctx, &recovered[0], &recoveredLen,
		                           signature.const_byte_str(), signature.size()) <= 0)
		{
			ERROR_MSG("Raw RSA verify recover failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		EVP_PKEY_CTX_free(ctx);
		recovered.resize(recoveredLen);

		return (originalData == recovered);
	}
	else
	{
		// Call the generic function (hashing multi-step path)
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, param, paramLen);
	}
}

bool OSSLRSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			 const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	HashAlgo::Type hash1 = HashAlgo::Unknown;
	HashAlgo::Type hash2 = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			hash1 = HashAlgo::MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SHA3_224_PKCS:
			hash1 = HashAlgo::SHA3_224;
			break;
		case AsymMech::RSA_SHA3_256_PKCS:
			hash1 = HashAlgo::SHA3_256;
			break;
		case AsymMech::RSA_SHA3_384_PKCS:
			hash1 = HashAlgo::SHA3_384;
			break;
		case AsymMech::RSA_SHA3_512_PKCS:
			hash1 = HashAlgo::SHA3_512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA1 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-20))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-28))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-32))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-48))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-64))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SHA3_224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA3_224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA3_224)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-28))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA3_224;
			break;
		case AsymMech::RSA_SHA3_256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA3_256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA3_256)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-32))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA3_256;
			break;
		case AsymMech::RSA_SHA3_384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA3_384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA3_384)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-48))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA3_384;
			break;
		case AsymMech::RSA_SHA3_512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA3_512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA3_512)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-64))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA3_512;
			break;
		case AsymMech::RSA_SSL:
			hash1 = HashAlgo::MD5;
			hash2 = HashAlgo::SHA1;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash1);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if (hash2 != HashAlgo::Unknown)
	{
		pSecondHash = CryptoFactory::i()->getHashAlgorithm(hash2);

		if (pSecondHash == NULL || !pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;

			if (pSecondHash != NULL)
			{
				delete pSecondHash;
				pSecondHash = NULL;
			}

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
		}
	}

	return true;
}

bool OSSLRSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if ((pSecondHash != NULL) && !pSecondHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		delete pSecondHash;
		pSecondHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool OSSLRSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	OSSLRSAPublicKey* pk = (OSSLRSAPublicKey*) currentPublicKey;
	AsymMech::Type mechanism = currentMechanism;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString firstHash, secondHash;

	bool bFirstResult = pCurrentHash->hashFinal(firstHash);
	bool bSecondResult = (pSecondHash != NULL) ? pSecondHash->hashFinal(secondHash) : true;

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (pSecondHash != NULL)
	{
		delete pSecondHash;
		pSecondHash = NULL;
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	ByteString digest = firstHash + secondHash;

	// Determine the EVP_MD and whether PSS is needed
	bool isPSS = false;
	const EVP_MD* hash = NULL;
	int nid = NID_undef;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:    nid = NID_md5;    break;
		case AsymMech::RSA_SHA1_PKCS:   nid = NID_sha1;   break;
		case AsymMech::RSA_SHA224_PKCS: nid = NID_sha224; break;
		case AsymMech::RSA_SHA256_PKCS: nid = NID_sha256; break;
		case AsymMech::RSA_SHA384_PKCS: nid = NID_sha384; break;
		case AsymMech::RSA_SHA512_PKCS: nid = NID_sha512; break;
		case AsymMech::RSA_SHA3_224_PKCS: nid = NID_sha3_224; break;
		case AsymMech::RSA_SHA3_256_PKCS: nid = NID_sha3_256; break;
		case AsymMech::RSA_SHA3_384_PKCS: nid = NID_sha3_384; break;
		case AsymMech::RSA_SHA3_512_PKCS: nid = NID_sha3_512; break;
		case AsymMech::RSA_SHA1_PKCS_PSS:   isPSS = true; hash = EVP_sha1();   break;
		case AsymMech::RSA_SHA224_PKCS_PSS: isPSS = true; hash = EVP_sha224(); break;
		case AsymMech::RSA_SHA256_PKCS_PSS: isPSS = true; hash = EVP_sha256(); break;
		case AsymMech::RSA_SHA384_PKCS_PSS: isPSS = true; hash = EVP_sha384(); break;
		case AsymMech::RSA_SHA512_PKCS_PSS: isPSS = true; hash = EVP_sha512(); break;
		case AsymMech::RSA_SHA3_224_PKCS_PSS: isPSS = true; hash = EVP_sha3_224(); break;
		case AsymMech::RSA_SHA3_256_PKCS_PSS: isPSS = true; hash = EVP_sha3_256(); break;
		case AsymMech::RSA_SHA3_384_PKCS_PSS: isPSS = true; hash = EVP_sha3_384(); break;
		case AsymMech::RSA_SHA3_512_PKCS_PSS: isPSS = true; hash = EVP_sha3_512(); break;
		case AsymMech::RSA_SSL:         nid = NID_md5_sha1; break;
		default: break;
	}

	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");
		return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	bool rv = false;

	if (ctx == NULL || EVP_PKEY_verify_init(ctx) <= 0)
	{
		ERROR_MSG("EVP_PKEY_verify_init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (isPSS)
	{
		rv = (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) > 0 &&
		      EVP_PKEY_CTX_set_signature_md(ctx, hash) > 0 &&
		      EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, (int)sLen) > 0 &&
		      EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, hash) > 0 &&
		      EVP_PKEY_verify(ctx, signature.const_byte_str(), signature.size(),
		                      &digest[0], digest.size()) == 1);
	}
	else
	{
		const EVP_MD* md = EVP_get_digestbynid(nid);
		rv = (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
		      (md == NULL || EVP_PKEY_CTX_set_signature_md(ctx, md) > 0) &&
		      EVP_PKEY_verify(ctx, signature.const_byte_str(), signature.size(),
		                      &digest[0], digest.size()) == 1);
	}

	if (!rv) ERROR_MSG("RSA verify failed (0x%08X)", ERR_get_error());

	EVP_PKEY_CTX_free(ctx);

	return rv;
}

bool OSSLRSA::verifyRecover(PublicKey* publicKey, const ByteString& signature, ByteString& data, const AsymMech::Type mechanism, const void* /*param*/, const size_t /*paramLen*/)
{
	if (!publicKey->isOfType(OSSLRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;
	EVP_PKEY* pkey = osslKey->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");
		return false;
	}

	size_t nSize = osslKey->getN().size();
	data.resize(nSize);
	size_t recoveredLen = nSize;

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL || EVP_PKEY_verify_recover_init(ctx) <= 0)
	{
		ERROR_MSG("EVP_PKEY_verify_recover_init failed (0x%08X)", ERR_get_error());
		if (ctx) EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (mechanism == AsymMech::RSA_PKCS)
	{
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
		    EVP_PKEY_verify_recover(ctx, &data[0], &recoveredLen, signature.const_byte_str(), signature.size()) <= 0)
		{
			ERROR_MSG("RSA PKCS verify recover failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
	}
	else if (mechanism == AsymMech::RSA)
	{
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0 ||
		    EVP_PKEY_verify_recover(ctx, &data[0], &recoveredLen, signature.const_byte_str(), signature.size()) <= 0)
		{
			ERROR_MSG("Raw RSA verify recover failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
	}
	else
	{
		ERROR_MSG("Invalid mechanism supplied for verifyRecover");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);
	data.resize(recoveredLen);

	return true;
}

// Encryption functions
bool OSSLRSA::encrypt(PublicKey* publicKey, const ByteString& data,
		      ByteString& encryptedData, const AsymMech::Type padding)
{
	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLRSAPublicKey* osslKey = (OSSLRSAPublicKey*) publicKey;
	EVP_PKEY* pkey = osslKey->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");
		return false;
	}

	size_t nSize = osslKey->getN().size();
	int osslPadding = 0;

	if (padding == AsymMech::RSA_PKCS)
	{
		if (data.size() > nSize - 11)
		{
			ERROR_MSG("Too much data supplied for RSA PKCS #1 encryption");
			return false;
		}
		osslPadding = RSA_PKCS1_PADDING;
	}
	else if (padding == AsymMech::RSA_PKCS_OAEP ||
	         padding == AsymMech::RSA_PKCS_OAEP_SHA224 ||
	         padding == AsymMech::RSA_PKCS_OAEP_SHA256 ||
	         padding == AsymMech::RSA_PKCS_OAEP_SHA384 ||
	         padding == AsymMech::RSA_PKCS_OAEP_SHA512)
	{
		// OAEP overhead: 2*hashLen + 2; SHA-1=42, SHA-256=66, SHA-384=98, SHA-512=130
		osslPadding = RSA_PKCS1_OAEP_PADDING;
	}
	else if (padding == AsymMech::RSA)
	{
		if (data.size() != nSize)
		{
			ERROR_MSG("Incorrect amount of input data supplied for raw RSA encryption");
			return false;
		}
		osslPadding = RSA_NO_PADDING;
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);
		return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL || EVP_PKEY_encrypt_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, osslPadding) <= 0)
	{
		ERROR_MSG("RSA encrypt init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Set OAEP hash and MGF if not default SHA-1
	if (padding == AsymMech::RSA_PKCS_OAEP_SHA224 ||
	    padding == AsymMech::RSA_PKCS_OAEP_SHA256 ||
	    padding == AsymMech::RSA_PKCS_OAEP_SHA384 ||
	    padding == AsymMech::RSA_PKCS_OAEP_SHA512)
	{
		const EVP_MD* md = NULL;
		switch (padding) {
			case AsymMech::RSA_PKCS_OAEP_SHA224: md = EVP_sha224(); break;
			case AsymMech::RSA_PKCS_OAEP_SHA256: md = EVP_sha256(); break;
			case AsymMech::RSA_PKCS_OAEP_SHA384: md = EVP_sha384(); break;
			case AsymMech::RSA_PKCS_OAEP_SHA512: md = EVP_sha512(); break;
			default: break;
		}
		if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
		{
			ERROR_MSG("Failed to set OAEP hash (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
	}

	// Query output size, then encrypt
	size_t outLen = 0;
	if (EVP_PKEY_encrypt(ctx, NULL, &outLen,
	                     data.const_byte_str(), data.size()) <= 0)
	{
		ERROR_MSG("RSA encrypt size query failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	encryptedData.resize(outLen);
	if (EVP_PKEY_encrypt(ctx, &encryptedData[0], &outLen,
	                     data.const_byte_str(), data.size()) <= 0)
	{
		ERROR_MSG("RSA public key encryption failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);
	encryptedData.resize(outLen);

	return true;
}

// Decryption functions
bool OSSLRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
		      ByteString& data, const AsymMech::Type padding)
{
	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLRSAPrivateKey* osslKey = (OSSLRSAPrivateKey*) privateKey;
	EVP_PKEY* pkey = osslKey->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");
		return false;
	}

	size_t nSize = osslKey->getN().size();

	// Check the input size
	if (encryptedData.size() != nSize)
	{
		ERROR_MSG("Invalid amount of input data supplied for RSA decryption");
		return false;
	}

	int osslPadding = 0;

	switch (padding)
	{
		case AsymMech::RSA_PKCS:             osslPadding = RSA_PKCS1_PADDING;      break;
		case AsymMech::RSA_PKCS_OAEP:
		case AsymMech::RSA_PKCS_OAEP_SHA224:
		case AsymMech::RSA_PKCS_OAEP_SHA256:
		case AsymMech::RSA_PKCS_OAEP_SHA384:
		case AsymMech::RSA_PKCS_OAEP_SHA512: osslPadding = RSA_PKCS1_OAEP_PADDING; break;
		case AsymMech::RSA:                  osslPadding = RSA_NO_PADDING;          break;
		default:
			ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);
			return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL || EVP_PKEY_decrypt_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, osslPadding) <= 0)
	{
		ERROR_MSG("RSA decrypt init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Set OAEP hash and MGF if not default SHA-1
	if (padding == AsymMech::RSA_PKCS_OAEP_SHA224 ||
	    padding == AsymMech::RSA_PKCS_OAEP_SHA256 ||
	    padding == AsymMech::RSA_PKCS_OAEP_SHA384 ||
	    padding == AsymMech::RSA_PKCS_OAEP_SHA512)
	{
		const EVP_MD* md = NULL;
		switch (padding) {
			case AsymMech::RSA_PKCS_OAEP_SHA224: md = EVP_sha224(); break;
			case AsymMech::RSA_PKCS_OAEP_SHA256: md = EVP_sha256(); break;
			case AsymMech::RSA_PKCS_OAEP_SHA384: md = EVP_sha384(); break;
			case AsymMech::RSA_PKCS_OAEP_SHA512: md = EVP_sha512(); break;
			default: break;
		}
		if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
		{
			ERROR_MSG("Failed to set OAEP hash (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
	}

	// Query output size, then decrypt
	size_t outLen = 0;
	if (EVP_PKEY_decrypt(ctx, NULL, &outLen,
	                     encryptedData.const_byte_str(), encryptedData.size()) <= 0)
	{
		ERROR_MSG("RSA decrypt size query failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	data.resize(outLen);
	if (EVP_PKEY_decrypt(ctx, &data[0], &outLen,
	                     encryptedData.const_byte_str(), encryptedData.size()) <= 0)
	{
		ERROR_MSG("RSA private key decryption failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);
	data.resize(outLen);

	return true;
}

// Key factory
bool OSSLRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) || (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(RSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for RSA key generation");
		return false;
	}

	RSAParameters* params = (RSAParameters*) parameters;

	if (params->getBitLength() < getMinKeySize() || params->getBitLength() > getMaxKeySize())
	{
		ERROR_MSG("This RSA key size (%lu) is not supported", params->getBitLength());
		return false;
	}

	if (params->getBitLength() < 1024)
	{
		WARNING_MSG("Using an RSA key size < 1024 bits is not recommended");
	}

	// Retrieve the desired public exponent
	unsigned long e = params->getE().long_val();

	// Check the public exponent
	if ((e == 0) || (e % 2 != 1))
	{
		ERROR_MSG("Invalid RSA public exponent %d", e);
		return false;
	}

	// Build key generation parameters
	unsigned int bits = params->getBitLength();
	BIGNUM* bn_e = OSSL::byteString2bn(params->getE());
	if (bn_e == NULL)
	{
		ERROR_MSG("Failed to convert RSA public exponent");
		return false;
	}

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
	{
		BN_free(bn_e);
		return false;
	}

	if (!OSSL_PARAM_BLD_push_uint(bld, OSSL_PKEY_PARAM_RSA_BITS, bits) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e))
	{
		OSSL_PARAM_BLD_free(bld);
		BN_free(bn_e);
		return false;
	}

	OSSL_PARAM* gen_params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);
	BN_free(bn_e);

	if (gen_params == NULL)
		return false;

	// Generate the key-pair via EVP_PKEY_CTX
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to instantiate EVP_PKEY_CTX for RSA key generation");
		OSSL_PARAM_free(gen_params);
		return false;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_params(ctx, gen_params) <= 0 ||
	    EVP_PKEY_generate(ctx, &pkey) <= 0)
	{
		ERROR_MSG("RSA key generation failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		OSSL_PARAM_free(gen_params);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(gen_params);

	// Create an asymmetric key-pair object to return
	OSSLRSAKeyPair* kp = new OSSLRSAKeyPair();

	((OSSLRSAPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLRSAPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

unsigned long OSSLRSA::getMinKeySize()
{
#ifdef WITH_FIPS
	return 1024;
#else
	return 512;
#endif
}

unsigned long OSSLRSA::getMaxKeySize()
{
	return 16384;
}

bool OSSLRSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLRSAKeyPair* kp = new OSSLRSAKeyPair();

	bool rv = true;

	if (!((RSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((RSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
	{
		rv = false;
	}

	if (!rv)
	{
		delete kp;
		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool OSSLRSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLRSAPublicKey* pub = new OSSLRSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLRSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLRSAPrivateKey* priv = new OSSLRSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLRSA::newPublicKey()
{
	return (PublicKey*) new OSSLRSAPublicKey();
}

PrivateKey* OSSLRSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLRSAPrivateKey();
}

AsymmetricParameters* OSSLRSA::newParameters()
{
	return (AsymmetricParameters*) new RSAParameters();
}

bool OSSLRSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	RSAParameters* params = new RSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;

	return true;
}
