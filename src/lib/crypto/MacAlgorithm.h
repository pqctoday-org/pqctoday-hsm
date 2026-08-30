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
 MacAlgorithm.h

 Base class for MAC algorithm classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MACALGORITHM_H
#define _SOFTHSM_V2_MACALGORITHM_H

#include <string>
#include "config.h"
#include "SymmetricKey.h"
#include "RNG.h"

struct MacAlgo
{
	enum Type
	{
		Unknown,
		HMAC_MD5,
		HMAC_RIPEMD160,
		HMAC_SHA1,
		HMAC_SHA224,
		HMAC_SHA256,
		HMAC_SHA384,
		HMAC_SHA512,
		HMAC_SHA3_224,
		HMAC_SHA3_256,
		HMAC_SHA3_384,
		HMAC_SHA3_512,
		CMAC_DES,
		CMAC_AES,
		KMAC_128,
		KMAC_256
	};
};

class MacAlgorithm
{
public:
	// Base constructors
	MacAlgorithm();

	// Destructor
	virtual ~MacAlgorithm() { }

	// Signing functions
	virtual bool signInit(const SymmetricKey* key);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verifyInit(const SymmetricKey* key);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(ByteString& signature);

	// Key
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();
	virtual void recycleKey(SymmetricKey* toRecycle);

	// Return the MAC size
	virtual size_t getMacSize() const = 0;

	// General-length ("_HMAC_GENERAL") MAC support.
	//
	// PKCS#11 v3.2 §6.20.3 and its per-hash siblings (§6.22.3 for SHA-256,
	// §6.23.3 SHA-384, §6.24.3 SHA-512) define a second mechanism per HMAC
	// that takes a CK_MAC_GENERAL_PARAMS giving the desired output length in
	// bytes: "Signatures (MACs) produced by this mechanism will be taken from
	// the start of the full 32-byte HMAC output."
	//
	// Request a truncated output of @p bytes. Returns false when this
	// implementation cannot honour truncation (the base class default) or the
	// length is out of range, so a caller can never silently receive — or
	// silently verify against — a full-length MAC where a short one was asked
	// for. Must be called before signInit()/verifyInit().
	virtual bool setTruncatedMacSize(size_t bytes);

	// Effective output length: the accepted truncated length if one was set,
	// otherwise the algorithm's natural MAC size.
	size_t getOutputMacSize() const;

protected:
	// The current key
	const SymmetricKey* currentKey;

	// Requested truncated MAC length in bytes; 0 means full-length output.
	size_t truncatedMacSize;

private:
	// The current operation
	enum
	{
		NONE,
		SIGN,
		VERIFY
	} 
	currentOperation;
};

#endif // !_SOFTHSM_V2_MACALGORITHM_H

