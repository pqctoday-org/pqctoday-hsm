/*
 * OpenSSL AES-GMAC (CKM_AES_GMAC) implementation. WS-8 (2026-08-30).
 *
 * PKCS#11 v3.2 §6.13.6: "GMAC is a special case of GCM that authenticates
 * only the Additional Authenticated Data ... pData points to the AAD. GMAC
 * does not use plaintext or ciphertext." OpenSSL exposes this directly as
 * the EVP_MAC "GMAC" (OSSL_MAC_NAME_GMAC), taking a "cipher" (e.g.
 * "aes-128-gcm") and "iv" param — verified byte-for-byte against a real
 * ACVP-AES-GMAC-1.0 vector via the openssl(1) mac CLI before writing this
 * (the MAC's input data IS the AAD, matching the spec text above).
 */

#include "config.h"
#include "OSSLGMAC.h"
#include "log.h"
#include <openssl/err.h>
#include <openssl/core_names.h>

OSSLGMAC::OSSLGMAC() : curCTX(NULL)
{
}

OSSLGMAC::~OSSLGMAC()
{
	if (curCTX != NULL)
		EVP_MAC_CTX_free(curCTX);
}

bool OSSLGMAC::setIV(const ByteString& iv)
{
	gmacIV = iv;
	return true;
}

// The natural (untruncated) GMAC tag is always 16 bytes (SP800-38D), tied to
// the cipher's block size, not the key size. PKCS#11 v3.2 §6.13.6's
// ulTagBits is not optional the way *_HMAC_GENERAL is — every CKM_AES_GMAC
// call carries one — so (unlike OSSLKMAC, which uses the base class's
// "cannot honour truncation" default) this must actually accept it.
bool OSSLGMAC::setTruncatedMacSize(size_t bytes)
{
	if (bytes == 0 || bytes > getMacSize())
		return false;
	truncatedMacSize = bytes;
	return true;
}

size_t OSSLGMAC::getMacSize() const
{
	return 16;
}

bool OSSLGMAC::init(const SymmetricKey* key)
{
	const char* cipherName;
	switch (key->getBitLen())
	{
		case 128: cipherName = "aes-128-gcm"; break;
		case 192: cipherName = "aes-192-gcm"; break;
		case 256: cipherName = "aes-256-gcm"; break;
		default:
			ERROR_MSG("OSSLGMAC: unsupported AES key size %lu bits", key->getBitLen());
			return false;
	}
	if (gmacIV.size() == 0)
	{
		ERROR_MSG("OSSLGMAC: setIV() was not called (or called with an empty IV) before init");
		return false;
	}

	EVP_MAC* mac = EVP_MAC_fetch(NULL, "GMAC", NULL);
	if (mac == NULL)
	{
		ERROR_MSG("EVP_MAC_fetch failed for GMAC");
		return false;
	}
	curCTX = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);
	if (curCTX == NULL)
	{
		ERROR_MSG("Failed to allocate EVP_MAC_CTX");
		return false;
	}

	OSSL_PARAM params[3];
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, const_cast<char*>(cipherName), 0);
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV,
	                (void*)gmacIV.const_byte_str(), gmacIV.size());
	params[2] = OSSL_PARAM_construct_end();

	if (EVP_MAC_init(curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), params) != 1)
	{
		ERROR_MSG("EVP_MAC_init(GMAC) failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}
	return true;
}

bool OSSLGMAC::signInit(const SymmetricKey* key)
{
	if (!MacAlgorithm::signInit(key)) return false;
	return init(key);
}

bool OSSLGMAC::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign)) return false;
	if (dataToSign.size() == 0) return true;

	if (EVP_MAC_update(curCTX, dataToSign.const_byte_str(), dataToSign.size()) != 1)
	{
		ERROR_MSG("EVP_MAC_update(GMAC) failed");
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}
	return true;
}

bool OSSLGMAC::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature)) return false;

	size_t outSize = getOutputMacSize();
	signature.resize(outSize);
	size_t outLen = 0;
	if (EVP_MAC_final(curCTX, &signature[0], &outLen, outSize) != 1)
	{
		ERROR_MSG("EVP_MAC_final(GMAC) failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}
	signature.resize(outLen);
	EVP_MAC_CTX_free(curCTX);
	curCTX = NULL;
	return true;
}

bool OSSLGMAC::verifyInit(const SymmetricKey* key)
{
	if (!MacAlgorithm::verifyInit(key)) return false;
	return init(key);
}

bool OSSLGMAC::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData)) return false;
	if (originalData.size() == 0) return true;

	if (EVP_MAC_update(curCTX, originalData.const_byte_str(), originalData.size()) != 1)
	{
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}
	return true;
}

bool OSSLGMAC::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature)) return false;

	size_t outSize = getOutputMacSize();
	ByteString macResult;
	macResult.resize(outSize);
	size_t outLen = 0;

	if (EVP_MAC_final(curCTX, &macResult[0], &outLen, outSize) != 1)
	{
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}
	EVP_MAC_CTX_free(curCTX);
	curCTX = NULL;

	macResult.resize(outLen);
	return macResult == signature;
}
