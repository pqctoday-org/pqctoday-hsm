/*
 * Copyright (c) 2024
 * All rights reserved.
 *
 * OpenSSL KMAC algorithm implementation
 */

#include "config.h"
#include "OSSLKMAC.h"
#include "log.h"
#include <openssl/err.h>
#include <openssl/core_names.h>

OSSLKMACAlgorithm::OSSLKMACAlgorithm(const char* name, size_t defaultSize)
	: curCTX(NULL), macName(name), macSize(defaultSize)
{
}

OSSLKMACAlgorithm::~OSSLKMACAlgorithm()
{
	if (curCTX != NULL)
		EVP_MAC_CTX_free(curCTX);
}

// NIST SP 800-185 §4.3: KMAC128(K, X, L, S) / KMAC256(K, X, L, S). L and S
// are inputs to the computation, so both go to EVP_MAC_init. Before E16
// (2026-09-25) only OSSL_MAC_PARAM_SIZE was set, fixed at construction to
// 32/64 bytes, and S was never passed: every KMAC this engine produced or
// verified was KMAC(K, X, 256|512, ""), whatever the caller asked for.
bool OSSLKMACAlgorithm::setKmacParams(size_t outputLen, const ByteString& inCustomization)
{
	if (curCTX != NULL) return false;  // must precede signInit/verifyInit
	if (outputLen > 0) macSize = outputLen;
	customization = inCustomization;
	return true;
}

bool OSSLKMACAlgorithm::initCtx(const SymmetricKey* key)
{
	EVP_MAC *mac = EVP_MAC_fetch(NULL, macName, NULL);
	if (mac == NULL) {
		ERROR_MSG("EVP_MAC_fetch failed for %s", macName);
		return false;
	}

	curCTX = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);

	if (curCTX == NULL) {
		ERROR_MSG("Failed to allocate EVP_MAC_CTX");
		return false;
	}

	OSSL_PARAM params[3];
	int n = 0;
	params[n++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &macSize);
	if (customization.size() > 0)
	{
		params[n++] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM,
			(void*)customization.const_byte_str(), customization.size());
	}
	params[n] = OSSL_PARAM_construct_end();

	if (EVP_MAC_init(curCTX, key->getKeyBits().const_byte_str(), key->getKeyBits().size(), params) != 1)
	{
		ERROR_MSG("EVP_MAC_init failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}

	return true;
}

bool OSSLKMACAlgorithm::signInit(const SymmetricKey* key)
{
	if (!MacAlgorithm::signInit(key)) return false;
	return initCtx(key);
}

bool OSSLKMACAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign)) return false;
	if (dataToSign.size() == 0) return true;

	if (EVP_MAC_update(curCTX, dataToSign.const_byte_str(), dataToSign.size()) != 1)
	{
		ERROR_MSG("EVP_MAC_update failed");
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}

	return true;
}

bool OSSLKMACAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature)) return false;

	size_t outLen = 0;
	if (EVP_MAC_final(curCTX, NULL, &outLen, 0) != 1) {
		ERROR_MSG("EVP_MAC_final failed to get length");
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}

	signature.resize(macSize);
	if (EVP_MAC_final(curCTX, &signature[0], &outLen, macSize) != 1)
	{
		ERROR_MSG("EVP_MAC_final failed");
		EVP_MAC_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}

	signature.resize(outLen);
	EVP_MAC_CTX_free(curCTX);
	curCTX = NULL;
	return true;
}

bool OSSLKMACAlgorithm::verifyInit(const SymmetricKey* key)
{
	if (!MacAlgorithm::verifyInit(key)) return false;
	return initCtx(key);
}

bool OSSLKMACAlgorithm::verifyUpdate(const ByteString& originalData)
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

bool OSSLKMACAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature)) return false;

	ByteString macResult;
	macResult.resize(macSize);
	size_t outLen = 0;

	if (EVP_MAC_final(curCTX, &macResult[0], &outLen, macSize) != 1)
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

size_t OSSLKMACAlgorithm::getMacSize() const
{
	return macSize;
}
