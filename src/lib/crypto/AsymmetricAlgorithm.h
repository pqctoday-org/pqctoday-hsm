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
 AsymmetricAlgorithm.h

 Base class for asymmetric algorithm classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ASYMMETRICALGORITHM_H
#define _SOFTHSM_V2_ASYMMETRICALGORITHM_H

#include "config.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricParameters.h"
#include "HashAlgorithm.h"
#include "PublicKey.h"
#include "PrivateKey.h"
#include "RNG.h"
#include "SymmetricKey.h"

struct AsymAlgo
{
        enum Type
	{
		Unknown,
		RSA,
		DSA,
		DH,
		ECDH,
		ECDSA,
		EDDSA,
		MLDSA,    // ML-DSA (FIPS 204)
		SLHDSA,   // SLH-DSA (FIPS 205)
		MLKEM     // ML-KEM (FIPS 203)
        };
};

struct AsymMech
{
	enum Type
	{
		Unknown,
		RSA,
		RSA_MD5_PKCS,
		RSA_PKCS,
		RSA_PKCS_OAEP,
		RSA_PKCS_OAEP_SHA224,
		RSA_PKCS_OAEP_SHA256,
		RSA_PKCS_OAEP_SHA384,
		RSA_PKCS_OAEP_SHA512,
		RSA_PKCS_OAEP_SHA3_224,
		RSA_PKCS_OAEP_SHA3_256,
		RSA_PKCS_OAEP_SHA3_384,
		RSA_PKCS_OAEP_SHA3_512,
		RSA_SHA1_PKCS,
		RSA_SHA224_PKCS,
		RSA_SHA256_PKCS,
		RSA_SHA384_PKCS,
		RSA_SHA512_PKCS,
		RSA_PKCS_PSS,
		RSA_SHA1_PKCS_PSS,
		RSA_SHA224_PKCS_PSS,
		RSA_SHA256_PKCS_PSS,
		RSA_SHA384_PKCS_PSS,
		RSA_SHA512_PKCS_PSS,
		RSA_SHA3_224_PKCS,      // CKM_SHA3_224_RSA_PKCS (PKCS#11 v3.2 §2.1.13)
		RSA_SHA3_256_PKCS,      // CKM_SHA3_256_RSA_PKCS
		RSA_SHA3_384_PKCS,      // CKM_SHA3_384_RSA_PKCS
		RSA_SHA3_512_PKCS,      // CKM_SHA3_512_RSA_PKCS
		RSA_SHA3_224_PKCS_PSS,  // CKM_SHA3_224_RSA_PKCS_PSS
		RSA_SHA3_256_PKCS_PSS,  // CKM_SHA3_256_RSA_PKCS_PSS
		RSA_SHA3_384_PKCS_PSS,  // CKM_SHA3_384_RSA_PKCS_PSS
		RSA_SHA3_512_PKCS_PSS,  // CKM_SHA3_512_RSA_PKCS_PSS
		RSA_SSL,
		DSA,
		DSA_SHA1,
		DSA_SHA224,
		DSA_SHA256,
		DSA_SHA384,
		DSA_SHA512,
		ECDSA,
		ECDSA_SHA1,
		ECDSA_SHA224,
		ECDSA_SHA256,
		ECDSA_SHA384,
		ECDSA_SHA512,
		ECDSA_SHA3_224,     // CKM_ECDSA_SHA3_224 (PKCS#11 v3.2 §6.3)
		ECDSA_SHA3_256,     // CKM_ECDSA_SHA3_256
		ECDSA_SHA3_384,     // CKM_ECDSA_SHA3_384
		ECDSA_SHA3_512,     // CKM_ECDSA_SHA3_512
		EDDSA,
		EDDSA_PH,           // Ed25519ph pre-hash signing (OpenSSL "Ed25519ph")
		MLDSA,              // CKM_ML_DSA pure-message sign/verify (FIPS 204)
		HASH_MLDSA,         // CKM_HASH_ML_DSA (generic, hash in param)
		HASH_MLDSA_SHA224,  // CKM_HASH_ML_DSA_SHA224
		HASH_MLDSA_SHA256,  // CKM_HASH_ML_DSA_SHA256
		HASH_MLDSA_SHA384,  // CKM_HASH_ML_DSA_SHA384
		HASH_MLDSA_SHA512,  // CKM_HASH_ML_DSA_SHA512
		HASH_MLDSA_SHA3_224,// CKM_HASH_ML_DSA_SHA3_224
		HASH_MLDSA_SHA3_256,// CKM_HASH_ML_DSA_SHA3_256
		HASH_MLDSA_SHA3_384,// CKM_HASH_ML_DSA_SHA3_384
		HASH_MLDSA_SHA3_512,// CKM_HASH_ML_DSA_SHA3_512
		HASH_MLDSA_SHAKE128,// CKM_HASH_ML_DSA_SHAKE128
		HASH_MLDSA_SHAKE256,// CKM_HASH_ML_DSA_SHAKE256
		// Deliberately OUTSIDE the [MLDSA, HASH_MLDSA_SHAKE256] range check
		// in SoftHSM_sign.cpp's applyPerMessageParam — this mechanism does
		// not support C_MessageSign/Verify* (remediation R34,
		// PQCTODAY-VENDOR-EXT-MU).
		MLDSA_EXTERNAL_MU,  // CKM_ML_DSA_EXTERNAL_MU
		SLHDSA,              // CKM_SLH_DSA pure-message sign/verify (FIPS 205)
		HASH_SLHDSA,         // CKM_HASH_SLH_DSA (generic, hash in param)
		HASH_SLHDSA_SHA224,  // CKM_HASH_SLH_DSA_SHA224
		HASH_SLHDSA_SHA256,  // CKM_HASH_SLH_DSA_SHA256
		HASH_SLHDSA_SHA384,  // CKM_HASH_SLH_DSA_SHA384
		HASH_SLHDSA_SHA512,  // CKM_HASH_SLH_DSA_SHA512
		HASH_SLHDSA_SHA3_224,// CKM_HASH_SLH_DSA_SHA3_224
		HASH_SLHDSA_SHA3_256,// CKM_HASH_SLH_DSA_SHA3_256
		HASH_SLHDSA_SHA3_384,// CKM_HASH_SLH_DSA_SHA3_384
		HASH_SLHDSA_SHA3_512,// CKM_HASH_SLH_DSA_SHA3_512
		HASH_SLHDSA_SHAKE128,// CKM_HASH_SLH_DSA_SHAKE128
		HASH_SLHDSA_SHAKE256 // CKM_HASH_SLH_DSA_SHAKE256
	};
};

struct AsymRSAMGF
{
	enum Type
	{
		Unknown,
		MGF1_SHA1,
		MGF1_SHA224,
		MGF1_SHA256,
		MGF1_SHA384,
		MGF1_SHA512,
		MGF1_SHA3_224,  // CKG_MGF1_SHA3_224 (PKCS#11 v3.2)
		MGF1_SHA3_256,  // CKG_MGF1_SHA3_256
		MGF1_SHA3_384,  // CKG_MGF1_SHA3_384
		MGF1_SHA3_512   // CKG_MGF1_SHA3_512
	};
};

struct RSA_PKCS_PSS_PARAMS
{
	HashAlgo::Type hashAlg;
	AsymRSAMGF::Type mgf;
	size_t sLen;
};

// ML-DSA sign/verify parameters (PKCS#11 v3.2, FIPS 204)
// Inline 255-byte context buffer avoids dangling pointers from Session::setParameters memcpy.
struct MLDSA_SIGN_PARAMS
{
	bool deterministic;          // CKH_DETERMINISTIC_REQUIRED → true
	bool hedgeRequired;          // CKH_HEDGE_REQUIRED → true
	bool preHash;                // true for CKM_HASH_ML_DSA_<hash> mechanisms
	                              // (§6.67.7 -- hash the message ON TOKEN)
	bool phmInput;               // remediation R37 (phase 8): true for the
	                              // bare generic CKM_HASH_ML_DSA (§6.67.6) --
	                              // dataToSign IS an already-hashed PHM, not
	                              // a message; never both this and preHash.
	HashAlgo::Type hashAlg;      // hash algorithm (when preHash or phmInput)
	size_t contextLen;           // 0-255
	unsigned char context[255];  // FIPS 204 max context length
};

// EdDSA sign/verify parameters (PKCS#11 v3.2 §6.3.14 Table 73 / RFC 8032).
//
// Carries what CK_EDDSA_PARAMS supplies, resolved into this engine's own
// representation. Inline 255-byte context buffer for the same reason the
// ML-DSA/SLH-DSA structs use one: Session::setParameters memcpy's the struct,
// so a pointer into the caller's CK_EDDSA_PARAMS would dangle by the time
// C_Sign runs.
//
// Added 2026-08-29 (WS-1.3). Until then CK_EDDSA_PARAMS was declared in
// pkcs11t.h and read by nothing: AsymSignInit's CKM_EDDSA case left param
// NULL and a guard rejected any non-NULL pParameter outright, so a conforming
// caller asking for Ed25519ph the standard way was refused, and RFC 8032
// context strings were unreachable in either direction.
struct EDDSA_SIGN_PARAMS
{
	bool hasParams;              // caller supplied a CK_EDDSA_PARAMS at all
	bool preHash;                // CK_EDDSA_PARAMS.phFlag
	size_t contextLen;           // 0-255 (v3.2 §6.3.16 bounds it explicitly)
	unsigned char context[255];
};

// SLH-DSA sign/verify parameters (PKCS#11 v3.2, FIPS 205)
// Inline 255-byte context buffer avoids dangling pointers from Session::setParameters memcpy.
struct SLHDSA_SIGN_PARAMS
{
	bool deterministic;          // CKH_DETERMINISTIC_REQUIRED → true (FIPS 205 §10)
	bool preHash;                // true for CKM_HASH_SLH_DSA_<hash> mechanisms
	                              // (§6.69.7 -- hash the message ON TOKEN)
	bool phmInput;               // remediation R37 (phase 8): true for the
	                              // bare generic CKM_HASH_SLH_DSA (§6.69.6) --
	                              // dataToSign IS an already-hashed PHM, not
	                              // a message; never both this and preHash.
	HashAlgo::Type hashAlg;      // hash algorithm (when preHash or phmInput)
	size_t contextLen;           // 0-255
	unsigned char context[255];  // FIPS 205 max context length
};

class AsymmetricAlgorithm
{
public:
	// Base constructors
	AsymmetricAlgorithm();

	// Destructor
	virtual ~AsymmetricAlgorithm() { }

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
	virtual bool verifyRecover(PublicKey* publicKey, const ByteString& signature, ByteString& data, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0) { return false; }

	// Encryption functions
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding) = 0;

	// Decryption functions
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding) = 0;

	// Wrap/Unwrap keys
	bool wrapKey(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding);
	bool unwrapKey(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding);

	// Key factory
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL) = 0;
	virtual unsigned long getMinKeySize() = 0;
	virtual unsigned long getMaxKeySize() = 0;
	virtual bool generateParameters(AsymmetricParameters** ppParams, void* parameters = NULL, RNG* rng = NULL);
	virtual bool deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey);
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData) = 0;
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData) = 0;
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData) = 0;
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);
	virtual PublicKey* newPublicKey() = 0;
	virtual PrivateKey* newPrivateKey() = 0;
	virtual AsymmetricParameters* newParameters();

	// Key recycling -- override these functions in a derived class if you need to perform specific cleanup
	virtual void recycleKeyPair(AsymmetricKeyPair* toRecycle);
	virtual void recycleParameters(AsymmetricParameters* toRecycle);
	virtual void recyclePublicKey(PublicKey* toRecycle);
	virtual void recyclePrivateKey(PrivateKey* toRecycle);
	virtual void recycleSymmetricKey(SymmetricKey* toRecycle);

protected:
	PublicKey* currentPublicKey;
	PrivateKey* currentPrivateKey;

	AsymMech::Type currentMechanism;
	AsymMech::Type currentPadding;

private:
	enum
	{
		NONE,
		SIGN,
		VERIFY
	}
	currentOperation;

	bool isWrappingMech(AsymMech::Type padding);
};

#endif // !_SOFTHSM_V2_ASYMMETRICALGORITHM_H

