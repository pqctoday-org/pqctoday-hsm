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
 OSSLEDDSA.h

 OpenSSL EDDSA asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLEDDSA_H
#define _SOFTHSM_V2_OSSLEDDSA_H

#include "config.h"
#include "AsymmetricAlgorithm.h"
#include "ByteString.h"
#include <openssl/evp.h>

class OSSLEDDSA : public AsymmetricAlgorithm
{
public:
	// Destructor
	virtual ~OSSLEDDSA() { }

	// Signing functions
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(const ByteString& signature);

	// Encryption functions
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding);

	// Decryption functions
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding);

	// Key factory
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();
	virtual bool deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey);
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData);
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData);
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData);
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();
	virtual AsymmetricParameters* newParameters();

private:
	// WS-1.3 (2026-08-29): resolve a key length + AsymMech + optional
	// CK_EDDSA_PARAMS into the OpenSSL EdDSA "instance" name (RFC 8032's five
	// schemes) and the context string to hand it. Shared by sign() and
	// verify() so the two can never disagree about which scheme a given
	// parameter set means.
	//
	// Returns false when the combination has no RFC 8032 scheme — e.g. a
	// non-empty context on pure Ed25519, which Table 73 does not define and
	// OpenSSL rejects outright.
	static bool resolveInstance(size_t orderLen, AsymMech::Type mechanism,
	                            const void* param, size_t paramLen,
	                            const char*& instance,
	                            const unsigned char*& context, size_t& contextLen);

	ByteString m_signMsg;
	ByteString m_verifyMsg;
	EDDSA_SIGN_PARAMS m_signParams;
	EDDSA_SIGN_PARAMS m_verifyParams;
	bool m_hasSignParams = false;
	bool m_hasVerifyParams = false;
};

#endif // !_SOFTHSM_V2_OSSLEDDSA_H

