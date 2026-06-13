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
 OSSLMLKEM.cpp

 OpenSSL ML-KEM (FIPS 203) key encapsulation mechanism implementation.
 Uses EVP_PKEY_encapsulate / EVP_PKEY_decapsulate (OpenSSL 3.3+).
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLMLKEM.h"
#include "MLKEMParameters.h"
#include "OSSLMLKEMKeyPair.h"
#include "OSSLMLKEMPublicKey.h"
#include "OSSLMLKEMPrivateKey.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

// ─── KEM operations ───────────────────────────────────────────────────────────

// Encapsulate: generate (ciphertext, sharedSecret) using the public key.
// Per FIPS 203 §6.1 and PKCS#11 v3.2 §5.20.
bool OSSLMLKEM::encapsulate(PublicKey* publicKey,
                             ByteString& ciphertext,
                             ByteString& sharedSecret)
{
	if (!publicKey->isOfType(OSSLMLKEMPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied for ML-KEM encapsulate");
		return false;
	}

	OSSLMLKEMPublicKey* pk = (OSSLMLKEMPublicKey*)publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL ML-KEM public key");
		return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_PKEY_CTX_new failed (0x%08X)", ERR_get_error());
		return false;
	}

	if (EVP_PKEY_encapsulate_init(ctx, NULL) != 1)
	{
		ERROR_MSG("EVP_PKEY_encapsulate_init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Query output lengths
	size_t ctLen = 0;
	size_t ssLen = 0;
	if (EVP_PKEY_encapsulate(ctx, NULL, &ctLen, NULL, &ssLen) != 1)
	{
		ERROR_MSG("EVP_PKEY_encapsulate (size query) failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	ciphertext.resize(ctLen);
	sharedSecret.resize(ssLen);

	if (EVP_PKEY_encapsulate(ctx, &ciphertext[0], &ctLen, &sharedSecret[0], &ssLen) != 1)
	{
		ERROR_MSG("EVP_PKEY_encapsulate failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);

	// Trim in case OpenSSL returned smaller actual lengths
	ciphertext.resize(ctLen);
	sharedSecret.resize(ssLen);
	return true;
}

// Decapsulate: recover sharedSecret from (privateKey, ciphertext).
// Per FIPS 203 §6.3 — implicit rejection produces a pseudo-random output
// rather than a distinguishable error. OpenSSL handles this internally.
bool OSSLMLKEM::decapsulate(PrivateKey* privateKey,
                             const ByteString& ciphertext,
                             ByteString& sharedSecret)
{
	if (!privateKey->isOfType(OSSLMLKEMPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied for ML-KEM decapsulate");
		return false;
	}

	OSSLMLKEMPrivateKey* pk = (OSSLMLKEMPrivateKey*)privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();
	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL ML-KEM private key");
		return false;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("EVP_PKEY_CTX_new failed (0x%08X)", ERR_get_error());
		return false;
	}

	if (EVP_PKEY_decapsulate_init(ctx, NULL) != 1)
	{
		ERROR_MSG("EVP_PKEY_decapsulate_init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Shared secret is always 32 bytes for all ML-KEM variants (FIPS 203 §6.1)
	size_t ssLen = 32;
	sharedSecret.resize(ssLen);

	if (EVP_PKEY_decapsulate(ctx,
	                         &sharedSecret[0], &ssLen,
	                         ciphertext.const_byte_str(), ciphertext.size()) != 1)
	{
		ERROR_MSG("EVP_PKEY_decapsulate failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);
	sharedSecret.resize(ssLen);
	return true;
}

// ─── Sign / Verify / Encrypt / Decrypt (not applicable to ML-KEM) ────────────

bool OSSLMLKEM::sign(PrivateKey* /*pk*/, const ByteString& /*data*/,
                     ByteString& /*sig*/, const AsymMech::Type /*mech*/,
                     const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("ML-KEM does not support signing");
	return false;
}

bool OSSLMLKEM::signInit(PrivateKey* /*pk*/, const AsymMech::Type /*mech*/,
                          const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("ML-KEM does not support signing");
	return false;
}

bool OSSLMLKEM::signUpdate(const ByteString& /*data*/)
{
	ERROR_MSG("ML-KEM does not support signing");
	return false;
}

bool OSSLMLKEM::signFinal(ByteString& /*sig*/)
{
	ERROR_MSG("ML-KEM does not support signing");
	return false;
}

bool OSSLMLKEM::verify(PublicKey* /*pk*/, const ByteString& /*data*/,
                       const ByteString& /*sig*/, const AsymMech::Type /*mech*/,
                       const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("ML-KEM does not support verification");
	return false;
}

bool OSSLMLKEM::verifyInit(PublicKey* /*pk*/, const AsymMech::Type /*mech*/,
                            const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("ML-KEM does not support verification");
	return false;
}

bool OSSLMLKEM::verifyUpdate(const ByteString& /*data*/)
{
	ERROR_MSG("ML-KEM does not support verification");
	return false;
}

bool OSSLMLKEM::verifyFinal(const ByteString& /*sig*/)
{
	ERROR_MSG("ML-KEM does not support verification");
	return false;
}

bool OSSLMLKEM::encrypt(PublicKey* /*pk*/, const ByteString& /*data*/,
                         ByteString& /*enc*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("ML-KEM does not support encryption");
	return false;
}

bool OSSLMLKEM::decrypt(PrivateKey* /*pk*/, const ByteString& /*enc*/,
                         ByteString& /*data*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("ML-KEM does not support decryption");
	return false;
}

bool OSSLMLKEM::deriveKey(SymmetricKey** /*ppKey*/, PublicKey* /*pub*/, PrivateKey* /*priv*/)
{
	ERROR_MSG("ML-KEM does not support key derivation (use encapsulate/decapsulate)");
	return false;
}

// ─── Key factory ─────────────────────────────────────────────────────────────

bool OSSLMLKEM::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
                                 AsymmetricParameters* parameters, RNG* /*rng*/)
{
	if (ppKeyPair == NULL || parameters == NULL) return false;

	if (!parameters->areOfType(MLKEMParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-KEM key generation");
		return false;
	}

	MLKEMParameters* params = (MLKEMParameters*)parameters;
	const char* keyName = OSSLMLKEMPublicKey::paramSetToName(params->getParameterSet());
	if (keyName == NULL)
	{
		ERROR_MSG("Unknown ML-KEM parameter set %lu", params->getParameterSet());
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
		ERROR_MSG("ML-KEM keygen init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Deterministic generation from a caller-supplied seed (FIPS 203 d||z,
	// 64 B). The provider rejects an out-of-range length here.
	const ByteString& seed = params->getSeed();
	if (seed.size() != 0)
	{
		OSSL_PARAM seedParams[2];
		seedParams[0] = OSSL_PARAM_construct_octet_string(
			OSSL_PKEY_PARAM_ML_KEM_SEED, (void*)seed.const_byte_str(), seed.size());
		seedParams[1] = OSSL_PARAM_construct_end();
		if (EVP_PKEY_CTX_set_params(ctx, seedParams) != 1)
		{
			ERROR_MSG("ML-KEM seed param rejected (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
	}

	if (EVP_PKEY_keygen(ctx, &pkey) != 1)
	{
		ERROR_MSG("ML-KEM keygen failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	OSSLMLKEMKeyPair* kp = new OSSLMLKEMKeyPair();
	((OSSLMLKEMPublicKey*)kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLMLKEMPrivateKey*)kp->getPrivateKey())->setFromOSSL(pkey);
	EVP_PKEY_free(pkey);

	*ppKeyPair = kp;
	return true;
}

unsigned long OSSLMLKEM::getMinKeySize()
{
	return 128;  // ML-KEM-512 security strength
}

unsigned long OSSLMLKEM::getMaxKeySize()
{
	return 256;  // ML-KEM-1024 security strength
}

bool OSSLMLKEM::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString dPub  = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLMLKEMKeyPair* kp = new OSSLMLKEMKeyPair();
	bool rv = true;
	if (!((MLKEMPublicKey*)kp->getPublicKey())->deserialise(dPub))   rv = false;
	if (!((MLKEMPrivateKey*)kp->getPrivateKey())->deserialise(dPriv)) rv = false;
	if (!rv) { delete kp; return false; }
	*ppKeyPair = kp;
	return true;
}

bool OSSLMLKEM::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;
	OSSLMLKEMPublicKey* pub = new OSSLMLKEMPublicKey();
	if (!pub->deserialise(serialisedData)) { delete pub; return false; }
	*ppPublicKey = pub;
	return true;
}

bool OSSLMLKEM::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;
	OSSLMLKEMPrivateKey* priv = new OSSLMLKEMPrivateKey();
	if (!priv->deserialise(serialisedData)) { delete priv; return false; }
	*ppPrivateKey = priv;
	return true;
}

bool OSSLMLKEM::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if (ppParams == NULL || serialisedData.size() == 0) return false;
	MLKEMParameters* params = new MLKEMParameters();
	if (!params->deserialise(serialisedData)) { delete params; return false; }
	*ppParams = params;
	return true;
}

PublicKey* OSSLMLKEM::newPublicKey()
{
	return (PublicKey*) new OSSLMLKEMPublicKey();
}

PrivateKey* OSSLMLKEM::newPrivateKey()
{
	return (PrivateKey*) new OSSLMLKEMPrivateKey();
}

AsymmetricParameters* OSSLMLKEM::newParameters()
{
	return (AsymmetricParameters*) new MLKEMParameters();
}
