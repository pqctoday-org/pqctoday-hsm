/*
 * Copyright (c) 2024
 * All rights reserved.
 *
 * OpenSSL KMAC algorithm implementation
 */

#ifndef _SOFTHSM_V2_OSSLKMAC_H
#define _SOFTHSM_V2_OSSLKMAC_H

#include "config.h"
#include "MacAlgorithm.h"
#include <openssl/evp.h>

class OSSLKMACAlgorithm : public MacAlgorithm
{
public:
	OSSLKMACAlgorithm(const char* name, size_t defaultSize);
	virtual ~OSSLKMACAlgorithm();

	virtual bool signInit(const SymmetricKey* key);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	virtual bool verifyInit(const SymmetricKey* key);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(ByteString& signature);

	virtual size_t getMacSize() const;

	virtual bool setKmacParams(size_t outputLen, const ByteString& customization);

protected:
	// EVP_MAC_init with OSSL_MAC_PARAM_SIZE (= L) and, when set,
	// OSSL_MAC_PARAM_CUSTOM (= S) — shared by signInit and verifyInit.
	bool initCtx(const SymmetricKey* key);

	EVP_MAC_CTX* curCTX;
	const char* macName;
	size_t macSize;
	ByteString customization;
};

class OSSLKMAC128 : public OSSLKMACAlgorithm
{
public:
	OSSLKMAC128() : OSSLKMACAlgorithm("KMAC-128", 32) {}
};

class OSSLKMAC256 : public OSSLKMACAlgorithm
{
public:
	OSSLKMAC256() : OSSLKMACAlgorithm("KMAC-256", 64) {}
};

#endif // !_SOFTHSM_V2_OSSLKMAC_H

