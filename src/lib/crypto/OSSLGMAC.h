/*
 * OpenSSL AES-GMAC (CKM_AES_GMAC, PKCS#11 v3.2 §6.13.6) implementation.
 * WS-8 (2026-08-30).
 */

#ifndef _SOFTHSM_V2_OSSLGMAC_H
#define _SOFTHSM_V2_OSSLGMAC_H

#include "config.h"
#include "MacAlgorithm.h"
#include <openssl/evp.h>

class OSSLGMAC : public MacAlgorithm
{
public:
	OSSLGMAC();
	virtual ~OSSLGMAC();

	virtual bool signInit(const SymmetricKey* key);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	virtual bool verifyInit(const SymmetricKey* key);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(ByteString& signature);

	virtual bool setIV(const ByteString& iv);
	virtual bool setTruncatedMacSize(size_t bytes);

	virtual size_t getMacSize() const;

protected:
	EVP_MAC_CTX* curCTX;
	ByteString gmacIV;

private:
	bool init(const SymmetricKey* key);
};

#endif // !_SOFTHSM_V2_OSSLGMAC_H
