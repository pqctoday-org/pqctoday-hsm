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
 OSSLClassicMcEliece.h

 Classic McEliece (BSI TR-02102-1 §2.4.2) key encapsulation mechanism
 implementation, backed by liboqs's C API directly — the "OSSL" prefix is
 kept for file-pattern consistency (see OSSLClassicMcEliecePublicKey.h),
 but this is a documented, deliberate exception to the engine's EVP-only
 rule (implementation plan decision D-2): `oqs-provider` dropped Classic
 McEliece in 0.8.0+, so no OpenSSL-EVP route exists for it at all.

 Provides key-pair generation, encapsulation, and decapsulation for all 10
 parameter sets. Sign/verify and encrypt/decrypt are not applicable, same
 as OSSLMLKEM.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLCLASSICMCELIECE_H
#define _SOFTHSM_V2_OSSLCLASSICMCELIECE_H

#include "config.h"
#include "AsymmetricAlgorithm.h"
#include "cryptoki.h"

class OSSLClassicMcEliece : public AsymmetricAlgorithm
{
public:
	virtual ~OSSLClassicMcEliece() { }

	// ─── KEM operations (Classic McEliece specific) ─────────────────────────

	// Encapsulate: given a public key, produce a ciphertext and shared secret.
	virtual bool encapsulate(PublicKey* publicKey,
	                         ByteString& ciphertext,
	                         ByteString& sharedSecret);

	// Decapsulate: given a private key and a received ciphertext, recover
	// the shared secret.
	virtual bool decapsulate(PrivateKey* privateKey,
	                         const ByteString& ciphertext,
	                         ByteString& sharedSecret);

	// ─── Key factory ────────────────────────────────────────────────────────

	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair,
	                              AsymmetricParameters* parameters,
	                              RNG* rng = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData);
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData);
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData);
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();
	virtual AsymmetricParameters* newParameters();

	// Map a CKP_CLASSIC_MCELIECE_* value to liboqs's own algorithm name
	// string (OQS_KEM_alg_classic_mceliece_*), or NULL if unrecognised.
	static const char* paramSetToOqsName(CK_ULONG ps);

	// ─── Not applicable to Classic McEliece ─────────────────────────────────

	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign,
	                  ByteString& signature, const AsymMech::Type mechanism,
	                  const void* param = NULL, const size_t paramLen = 0);
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
	                      const void* param = NULL, const size_t paramLen = 0);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	virtual bool verify(PublicKey* publicKey, const ByteString& originalData,
	                    const ByteString& signature, const AsymMech::Type mechanism,
	                    const void* param = NULL, const size_t paramLen = 0);
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
	                        const void* param = NULL, const size_t paramLen = 0);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(const ByteString& signature);

	virtual bool encrypt(PublicKey* publicKey, const ByteString& data,
	                     ByteString& encryptedData, const AsymMech::Type padding);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
	                     ByteString& data, const AsymMech::Type padding);

	virtual bool deriveKey(SymmetricKey** ppSymmetricKey,
	                       PublicKey* publicKey, PrivateKey* privateKey);
};

#endif // !_SOFTHSM_V2_OSSLCLASSICMCELIECE_H
