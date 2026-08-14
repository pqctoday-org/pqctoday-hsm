/*
 * Copyright (c) 2022 NLnet Labs
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
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
 SoftHSM_keygen.cpp

 PKCS#11 key generation, wrapping/unwrapping, derivation:
 C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey.
 Key-generation helpers: generateGeneric, generateAES, generateRSA, generateEC,
 generateED, generateMLDSA, generateSLHDSA, generateMLKEM.
 Derivation helpers: deriveECDH, deriveEDDSA, deriveSymmetric.
 Key-material helpers: getRSA/EC/ED/MLDSA/SLHDSA/MLKEMPrivateKey/PublicKey,
 getECDH/EDDHPublicKey, getSymmetricKey, setRSA/EC/EDPrivateKey.
 Mechanism-param helpers: MechParamCheckRSAPKCSOAEP, MechParamCheckRSAAESKEYWRAP.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OpLog.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "CryptoFactory.h"
#include "AsymmetricAlgorithm.h"
#include "SymmetricAlgorithm.h"
#include "AESKey.h"
#include "DerUtil.h"
#include "RNG.h"
#include "RSAParameters.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "ECParameters.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"
#include "MLDSAPublicKey.h"
#include "MLDSAPrivateKey.h"
#include "MLDSAParameters.h"
#include "SLHDSAPublicKey.h"
#include "SLHDSAPrivateKey.h"
#include "SLHDSAParameters.h"
#include "OSSLMLDSAPublicKey.h"
#include "OSSLMLDSAPrivateKey.h"
#include "OSSLSLHDSAPublicKey.h"
#include "OSSLSLHDSAPrivateKey.h"
#include "MLKEMPublicKey.h"
#include "MLKEMPrivateKey.h"
#include "MLKEMParameters.h"
#include "OSSLMLKEMPublicKey.h"
#include "OSSLMLKEMPrivateKey.h"
#include "OSSLMLKEM.h"
#include "OSSLRSAPublicKey.h"
#include "OSSLECPublicKey.h"
#include "OSSLEDPublicKey.h"
#include "OSSLECDH.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

extern "C" {
#include "stateful/hash-sigs/hss.h"
#include "stateful/xmss-reference/xmss_core.h"
#include "stateful/xmss-reference/xmss.h"
#include "stateful/xmss-reference/params.h"
#include "stateful/kat_randombytes.h"
}
#include <openssl/params.h>
#include <vector>
#include "cryptoki.h"
#include "vendor_mechanisms.h"
#include "P11Attributes.h"
#include "P11Objects.h"
#include "HDWalletDerivation.h"
#include "SlotManager.h"
#include "odd.h"

// Compute asymmetric key check value: SHA-256(keyValue) → first 3 bytes.
// Used for RSA, EC, EdDSA, ML-DSA, ML-KEM, SLH-DSA public and private keys.
static ByteString computeAsymKCV(const ByteString& keyValue)
{
	HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA256);
	if (hash == NULL) return ByteString("");
	ByteString digest;
	bool ok = hash->hashInit() && hash->hashUpdate(keyValue) && hash->hashFinal(digest);
	CryptoFactory::i()->recycleHashAlgorithm(hash);
	if (!ok || digest.size() < 3) return ByteString("");
	return digest.substr(0, 3);
}

// Compute secret-key check value per PKCS#11 v3.2 §4.11 / §4.10.2:
//   • CKK_AES → AES-ECB(zero block)[0:3]   (matches AESKey::getKeyCheckValue)
//   • other symmetric key types → SHA-256(keyBits)[0:3]   (matches SymmetricKey::getKeyCheckValue)
// §4.11 mandates KCV "regardless of how the key object is created or derived" —
// used by C_UnwrapKey + C_DeriveKey (HKDF, SP800-108, PBKD2) to populate
// CKA_CHECK_VALUE consistently with C_GenerateKey.
// Non-static (declared in SoftHSMHelpers.h) since the 2026-08-13 S11
// remediation: C_EncapsulateKey / C_DecapsulateKey need the same computation.
ByteString computeSecretKeyKCV(CK_KEY_TYPE keyType, const ByteString& keyBits)
{
	if (keyBits.size() == 0) return ByteString("");
	if (keyType == CKK_AES)
	{
		AESKey aesKey(keyBits.size() * 8);
		aesKey.setKeyBits(keyBits);
		return aesKey.getKeyCheckValue();
	}
	SymmetricKey symKey;
	symKey.setKeyBits(keyBits);
	symKey.setBitLen(keyBits.size() * 8);
	return symKey.getKeyCheckValue();
}

// KDF helpers: map PKCS#11 v3.2 CKD_* identifiers to OpenSSL digest names (for X9.63 KDF)
static const char* ckdToDigestName(CK_ULONG kdf)
{
	switch (kdf)
	{
		case CKD_SHA1_KDF:    return "SHA-1";
		case CKD_SHA256_KDF:  return "SHA2-256";
		case CKD_SHA384_KDF:  return "SHA2-384";
		case CKD_SHA512_KDF:  return "SHA2-512";
		case CKD_SHA3_256_KDF: return "SHA3-256"; // PKCS#11 v3.2 §5.2.12
		case CKD_SHA3_512_KDF: return "SHA3-512"; // PKCS#11 v3.2 §5.2.12
		default:               return nullptr;
	}
}

// KDF helper: map PKCS#11 v3.2 CKM_SHA* mechanism → OpenSSL digest name (for HKDF PRF)
static const char* ckmToDigestName(CK_MECHANISM_TYPE mech)
{
	switch (mech)
	{
		case CKM_SHA_1:    return "SHA-1";
		case CKM_SHA256:   return "SHA2-256";
		case CKM_SHA384:   return "SHA2-384";
		case CKM_SHA512:   return "SHA2-512";
		case CKM_SHA3_256: return "SHA3-256";
		case CKM_SHA3_384: return "SHA3-384";
		case CKM_SHA3_512: return "SHA3-512";
		default:           return nullptr;
	}
}

// SP 800-108 KDF helper: map a keyed-MAC HMAC PRF mechanism → OpenSSL digest name.
// PKCS#11 v3.2 §6.26 (SP800-108 KDF): prfType is a CK_SP800_108_PRF_TYPE and MUST
// be a mechanism supporting keyed MAC (e.g. CKM_SHA256_HMAC, CKM_AES_CMAC).
// Bare hash mechanisms (CKM_SHA256 et al.) are NOT valid PRFs and map to nullptr,
// causing the caller to return CKR_MECHANISM_PARAM_INVALID.
// (CKM_AES_CMAC is handled separately at the call sites.)
static const char* ckmHmacPrfToDigestName(CK_MECHANISM_TYPE mech)
{
	switch (mech)
	{
		case CKM_SHA224_HMAC:   return "SHA2-224";
		case CKM_SHA256_HMAC:   return "SHA2-256";
		case CKM_SHA384_HMAC:   return "SHA2-384";
		case CKM_SHA512_HMAC:   return "SHA2-512";
		case CKM_SHA3_224_HMAC: return "SHA3-224";
		case CKM_SHA3_256_HMAC: return "SHA3-256";
		case CKM_SHA3_384_HMAC: return "SHA3-384";
		case CKM_SHA3_512_HMAC: return "SHA3-512";
		default:                return nullptr;
	}
}

// Encode a public EVP_PKEY as SubjectPublicKeyInfo DER (for CKA_PUBLIC_KEY_INFO per PKCS#11 v3.2 §4.14)
static ByteString spkiFromPkey(EVP_PKEY* pkey)
{
	ByteString spki;
	if (pkey == nullptr) return spki;
	int len = i2d_PUBKEY(pkey, nullptr);
	if (len <= 0) return spki;
	spki.resize(len);
	unsigned char* p = &spki[0];
	i2d_PUBKEY(pkey, &p);
	return spki;
}

// Map an LMS parameter set (IANA / draft-mcgrew lms_algorithm_type) to its
// Merkle tree height h (audit V-21). The registry lays the H5/H10/H15/H20/H25
// variants out in dense runs of 5 within each (hash,n) group:
//   0x05-0x09 SHA256_N32, 0x0A-0x0E SHA256_N24,
//   0x0F-0x13 SHAKE_N32,  0x14-0x18 SHAKE_N24
// so height = 5 * (((type - 5) % 5) + 1). Returns 0 for unknown types.
static unsigned lmsTreeHeight(param_set_t lmsType)
{
	unsigned t = (unsigned)lmsType;
	if (t < 0x05 || t > 0x18) return 0;
	return 5u * (((t - 0x05u) % 5u) + 1u);
}

// Number of one-time signatures (and hence remaining signatures at generation)
// for an HSS key = product over all levels of 2^h_i, where h_i is the LMS tree
// height of level i (RFC 8554 §2: an L-level HSS key signs 2^(h_1+...+h_L)
// messages). Saturates at CK_ULONG max for very tall trees.
static CK_ULONG hssTotalSignatures(unsigned levels, const param_set_t* lmType)
{
	unsigned totalHeight = 0;
	for (unsigned i = 0; i < levels; ++i)
	{
		unsigned h = lmsTreeHeight(lmType[i]);
		if (h == 0) return 0; // unknown LMS type
		totalHeight += h;
	}
	if (totalHeight >= sizeof(CK_ULONG) * 8)
		return (CK_ULONG)-1; // saturate
	return ((CK_ULONG)1) << totalHeight;
}

// Extract and strictly validate CKA_PARAMETER_SET from a PQC keygen template
// (audit V-3). The spec requires CKA_PARAMETER_SET on ML-DSA/SLH-DSA/ML-KEM
// keygen — it MUST NOT silently default. Errors:
//   • absent                     → CKR_TEMPLATE_INCOMPLETE
//   • present with wrong size    → CKR_ATTRIBUTE_VALUE_INVALID
//   • present with invalid value → CKR_ATTRIBUTE_VALUE_INVALID
// validMin/validMax bound the accepted CKP_* range for the family (the CKP_*
// enums are dense per pkcs11t.h §CKP).
static CK_RV extractParameterSet(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                 CK_ULONG validMin, CK_ULONG validMax,
                                 CK_ULONG& parameterSetOut)
{
	bool found = false;
	CK_ULONG parameterSet = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		if (pTemplate[i].type != CKA_PARAMETER_SET)
			continue;
		found = true;
		if (pTemplate[i].ulValueLen != sizeof(CK_ULONG) || pTemplate[i].pValue == NULL_PTR)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		parameterSet = *(CK_ULONG*)pTemplate[i].pValue;
		break;
	}
	if (!found)
		return CKR_TEMPLATE_INCOMPLETE;
	if (parameterSet < validMin || parameterSet > validMax)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	parameterSetOut = parameterSet;
	return CKR_OK;
}

// SLH-DSA security parameter n (bytes) per parameter set; the deterministic
// keygen seed is SK.seed||SK.prf||PK.seed = 3n bytes (FIPS 205).
static size_t slhdsaSeedN(CK_ULONG paramSet)
{
	switch (paramSet)
	{
		case CKP_SLH_DSA_SHA2_128S: case CKP_SLH_DSA_SHAKE_128S:
		case CKP_SLH_DSA_SHA2_128F: case CKP_SLH_DSA_SHAKE_128F:
			return 16;
		case CKP_SLH_DSA_SHA2_192S: case CKP_SLH_DSA_SHAKE_192S:
		case CKP_SLH_DSA_SHA2_192F: case CKP_SLH_DSA_SHAKE_192F:
			return 24;
		case CKP_SLH_DSA_SHA2_256S: case CKP_SLH_DSA_SHAKE_256S:
		case CKP_SLH_DSA_SHA2_256F: case CKP_SLH_DSA_SHAKE_256F:
			return 32;
		default:
			return 0;
	}
}

// Extract an optional CKA_SEED from a keygen template for deterministic PQC
// key generation. Absent → seedOut is left empty (random keygen). Present but
// wrong length for the family/param-set → CKR_ATTRIBUTE_VALUE_INVALID
// (audit object 4.3 / crypto 5.6). expectedLen is the required byte length:
//   ML-DSA xi = 32, ML-KEM d||z = 64, SLH-DSA SK.seed||SK.prf||PK.seed = 3n.
static CK_RV extractSeed(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         size_t expectedLen, ByteString& seedOut)
{
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		if (pTemplate[i].type != CKA_SEED)
			continue;
		if (pTemplate[i].pValue == NULL_PTR || pTemplate[i].ulValueLen != expectedLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		seedOut = ByteString((unsigned char*)pTemplate[i].pValue, pTemplate[i].ulValueLen);
		return CKR_OK;
	}
	seedOut.wipe();
	return CKR_OK;
}

// Generate a secret key or a domain parameter set using the specified mechanism
CK_RV SoftHSM::C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR && ulCount != 0) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept DSA and DH parameters
	// and symmetric ciphers
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	switch (pMechanism->mechanism)
	{
#ifndef WITH_FIPS
		case CKM_CHACHA20_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_CHACHA20;
			break;
		case CKM_AES_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_AES;
			break;
		case CKM_GENERIC_SECRET_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_GENERIC_SECRET;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Extract information from the template that is needed to create the object.
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = true;
	extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_DOMAIN_PARAMETERS)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (pMechanism->mechanism == CKM_AES_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_AES))
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_GENERIC_SECRET_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_GENERIC_SECRET))
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_CHACHA20_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_CHACHA20))
		return CKR_TEMPLATE_INCONSISTENT;

	// Check authorization
	CK_RV rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}


	// Generate AES / ChaCha20 secret key. Both use the generateAES path but the
	// key type and CKA_KEY_GEN_MECHANISM differ — pass the mechanism through so
	// ChaCha20 keys are CKK_CHACHA20 with CKM_CHACHA20_KEY_GEN, not mislabeled
	// as AES (audit V-12).
	if (pMechanism->mechanism == CKM_AES_KEY_GEN || pMechanism->mechanism == CKM_CHACHA20_KEY_GEN)
	{
		return this->generateAES(hSession, pTemplate, ulCount, phKey, isOnToken, isPrivate,
		                         pMechanism->mechanism);
	}

	// Generate generic secret key
	if (pMechanism->mechanism == CKM_GENERIC_SECRET_KEY_GEN)
	{
		return this->generateGeneric(hSession, pTemplate, ulCount, phKey, isOnToken, isPrivate);
	}

	return CKR_GENERAL_ERROR;
}

// Generate a key-pair using the specified mechanism
CK_RV SoftHSM::C_GenerateKeyPair
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	CK_RV rv = generateKeyPairImpl(hSession, pMechanism,
	                               pPublicKeyTemplate, ulPublicKeyAttributeCount,
	                               pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
	                               phPublicKey, phPrivateKey);

	if (OpLog::enabled())
	{
		const CK_MECHANISM_TYPE mech = (pMechanism != NULL_PTR) ? pMechanism->mechanism : 0;

		// Read back from the private key, and only on success: the custody
		// attributes are what "generated in-HSM, non-extractable" means, and
		// they only exist once the object does.
		const bool haveKey = (rv == CKR_OK && phPrivateKey != NULL_PTR &&
		                      *phPrivateKey != CK_INVALID_HANDLE);
		const std::string keyFields = haveKey
			? opLogKeyFields(hSession, *phPrivateKey, mech)
			: std::string("key=- keytype=- paramset=-");
		const std::string custody = haveKey
			? opLogKeyCustodyFields(hSession, *phPrivateKey)
			: std::string("extractable=- sensitive=- never_extractable=- always_sensitive=- local=-");

		OpLog::emit("C_GenerateKeyPair",
		            "sess=%lu mech=%s mech_id=0x%08lx %s %s hpub=%lu hpriv=%lu rv=%s rv_id=0x%08lx",
		            (unsigned long)hSession,
		            OpLog::mechName(mech), (unsigned long)mech,
		            keyFields.c_str(), custody.c_str(),
		            (unsigned long)(phPublicKey  != NULL_PTR ? *phPublicKey  : CK_INVALID_HANDLE),
		            (unsigned long)(phPrivateKey != NULL_PTR ? *phPrivateKey : CK_INVALID_HANDLE),
		            OpLog::rvName(rv), (unsigned long)rv);
	}

	return rv;
}

CK_RV SoftHSM::generateKeyPairImpl
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pPublicKeyTemplate == NULL_PTR && ulPublicKeyAttributeCount != 0) return CKR_ARGUMENTS_BAD;
	if (pPrivateKeyTemplate == NULL_PTR && ulPrivateKeyAttributeCount != 0) return CKR_ARGUMENTS_BAD;
	if (phPublicKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phPrivateKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept RSA, DSA, EC and DH key pair generation.
	CK_KEY_TYPE keyType;
	switch (pMechanism->mechanism)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			keyType = CKK_RSA;
			break;
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			keyType = CKK_EC;
			break;
#endif
#ifdef WITH_EDDSA
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			keyType = CKK_EC_EDWARDS;
			break;
		case CKM_EC_MONTGOMERY_KEY_PAIR_GEN:
			keyType = CKK_EC_MONTGOMERY;
			break;
#endif
		case CKM_ML_DSA_KEY_PAIR_GEN:
			keyType = CKK_ML_DSA;
			break;
		case CKM_SLH_DSA_KEY_PAIR_GEN:
			keyType = CKK_SLH_DSA;
			break;
		case CKM_ML_KEM_KEY_PAIR_GEN:
			keyType = CKK_ML_KEM;
			break;
		case CKM_HSS_KEY_PAIR_GEN:
			keyType = CKK_HSS;
			break;
		case CKM_XMSS_KEY_PAIR_GEN:
			keyType = CKK_XMSS;
			break;
		case CKM_XMSSMT_KEY_PAIR_GEN:
			keyType = CKK_XMSSMT;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	CK_CERTIFICATE_TYPE dummy;

	// Extract information from the public key template that is needed to create the object.
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL ispublicKeyToken = CK_FALSE;
	CK_BBOOL ispublicKeyPrivate = CK_FALSE;
	bool isPublicKeyImplicit = true;
	extractObjectInformation(pPublicKeyTemplate, ulPublicKeyAttributeCount, publicKeyClass, keyType, dummy, ispublicKeyToken, ispublicKeyPrivate, isPublicKeyImplicit);

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (publicKeyClass != CKO_PUBLIC_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN && keyType != CKK_EC_EDWARDS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_MONTGOMERY_KEY_PAIR_GEN && keyType != CKK_EC_MONTGOMERY)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN && keyType != CKK_ML_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN && keyType != CKK_SLH_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_ML_KEM_KEY_PAIR_GEN && keyType != CKK_ML_KEM)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_HSS_KEY_PAIR_GEN && keyType != CKK_HSS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_XMSS_KEY_PAIR_GEN && keyType != CKK_XMSS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_XMSSMT_KEY_PAIR_GEN && keyType != CKK_XMSSMT)
		return CKR_TEMPLATE_INCONSISTENT;

	// Extract information from the private key template that is needed to create the object.
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isprivateKeyToken = CK_FALSE;
	CK_BBOOL isprivateKeyPrivate = CK_TRUE;
	bool isPrivateKeyImplicit = true;
	extractObjectInformation(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, privateKeyClass, keyType, dummy, isprivateKeyToken, isprivateKeyPrivate, isPrivateKeyImplicit);

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (privateKeyClass != CKO_PRIVATE_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN && keyType != CKK_EC_EDWARDS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_MONTGOMERY_KEY_PAIR_GEN && keyType != CKK_EC_MONTGOMERY)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN && keyType != CKK_ML_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN && keyType != CKK_SLH_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_ML_KEM_KEY_PAIR_GEN && keyType != CKK_ML_KEM)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_HSS_KEY_PAIR_GEN && keyType != CKK_HSS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_XMSS_KEY_PAIR_GEN && keyType != CKK_XMSS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_XMSSMT_KEY_PAIR_GEN && keyType != CKK_XMSSMT)
		return CKR_TEMPLATE_INCONSISTENT;

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), ispublicKeyToken || isprivateKeyToken, ispublicKeyPrivate || isprivateKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Generate RSA keys
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
	{
			return this->generateRSA(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}


	// Generate EC (Weierstrass curve) keys
	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN)
	{
			return this->generateEC(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate Edwards / Montgomery keys
	if (pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN ||
	    pMechanism->mechanism == CKM_EC_MONTGOMERY_KEY_PAIR_GEN)
	{
			return this->generateED(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate ML-DSA keys (FIPS 204)
	if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN)
	{
		return this->generateMLDSA(hSession,
			pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			phPublicKey, phPrivateKey,
			ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate SLH-DSA keys (FIPS 205)
	if (pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN)
	{
		return this->generateSLHDSA(hSession,
			pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			phPublicKey, phPrivateKey,
			ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate ML-KEM keys (FIPS 203)
	if (pMechanism->mechanism == CKM_ML_KEM_KEY_PAIR_GEN)
	{
		return this->generateMLKEM(hSession,
			pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			phPublicKey, phPrivateKey,
			ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Scaffolded Stateful Signature implementations (PKCS#11 v3.2)
	// These mechanisms correctly map the keyType to CKK_HSS / CKK_XMSS.
	// The C wrapper factories (StatefulKeyPair) wrap the native hash-sigs and
	// xmss-reference C libraries for cross-validation generation logic.
	if (pMechanism->mechanism == CKM_HSS_KEY_PAIR_GEN || 
	    pMechanism->mechanism == CKM_XMSS_KEY_PAIR_GEN ||
		pMechanism->mechanism == CKM_XMSSMT_KEY_PAIR_GEN)
	{
		CK_RV rv = CKR_OK;
		
		std::vector<unsigned char> priv_key_vec(100000, 0); // Max safe buffer for HSS/LMS
		std::vector<unsigned char> pub_key_vec(256, 0);
		unsigned char* priv_key = priv_key_vec.data();
		unsigned char* pub_key = pub_key_vec.data();
		CK_ULONG priv_len = 0;
		CK_ULONG pub_len = 0;
		
		CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE keyType = 0;
		CK_ULONG remainingSigs = 32;
		const CK_ATTRIBUTE_TYPE ATTR_CKA_HSS_KEYS_REMAINING = 0x0000061cUL;
		
		CK_ULONG parameterSet = 0x00000001UL;
		if (pMechanism->mechanism == CKM_XMSS_KEY_PAIR_GEN || pMechanism->mechanism == CKM_XMSSMT_KEY_PAIR_GEN) {
			// W4 (2026-08-13). PKCS#11 v3.2 §6.66.6: "This mechanism does not
			// have a parameter", and the mechanism generates key pairs "using an
			// oid, as specified in the CKA_PARAMETER_SET attribute of the
			// template for the public key."
			//
			// This code used to read pMechanism->pParameter — the one place the
			// spec says carries nothing — and DISCARD the standard attribute
			// (the ck4 skip in the template loops below), so a caller who asked
			// for XMSS-SHA2_16_256 through CKA_PARAMETER_SET silently received a
			// 10_256 key, with CKR_OK. Anything in pParameter is now ignored.
			const CK_ULONG* pubPs = NULL_PTR;
			for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; ++i) {
				if (pPublicKeyTemplate[i].type != CKA_PARAMETER_SET) continue;
				if (pPublicKeyTemplate[i].pValue == NULL_PTR ||
				    pPublicKeyTemplate[i].ulValueLen != sizeof(CK_ULONG))
					return CKR_ATTRIBUTE_VALUE_INVALID;
				pubPs = (const CK_ULONG*)pPublicKeyTemplate[i].pValue;
			}
			// The attribute is mandatory at generation, so its absence is
			// CKR_TEMPLATE_INCOMPLETE rather than a silent default.
			if (pubPs == NULL_PTR) return CKR_TEMPLATE_INCOMPLETE;
			parameterSet = *pubPs;

			// Both halves are stamped with the same oid below, so a private
			// template naming a different one cannot be satisfied (§4.1.1 rule 5).
			for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; ++i) {
				if (pPrivateKeyTemplate[i].type != CKA_PARAMETER_SET) continue;
				if (pPrivateKeyTemplate[i].pValue == NULL_PTR ||
				    pPrivateKeyTemplate[i].ulValueLen != sizeof(CK_ULONG))
					return CKR_ATTRIBUTE_VALUE_INVALID;
				if (*(const CK_ULONG*)pPrivateKeyTemplate[i].pValue != parameterSet)
					return CKR_TEMPLATE_INCONSISTENT;
			}
		}

		if (pMechanism->mechanism == CKM_XMSS_KEY_PAIR_GEN) {
			keyType = CKK_XMSS; // 0x00000047UL
			xmss_params params;
			// §6.66 refusal code: the engine already uses
			// CKR_PARAMETER_SET_NOT_SUPPORTED correctly for ML-DSA/ML-KEM/SLH-DSA;
			// XMSS returned CKR_FUNCTION_FAILED, which says nothing about the oid.
			if (xmss_parse_oid(&params, parameterSet)) return CKR_PARAMETER_SET_NOT_SUPPORTED;
			// xmss_keypair writes [OID(4) || core_key], so buffers need OID_LEN extra
			priv_key_vec.resize(XMSS_OID_LEN + params.sk_bytes);
			pub_key_vec.resize(XMSS_OID_LEN + params.pk_bytes);
			priv_key = priv_key_vec.data();
			pub_key = pub_key_vec.data();

			// Check for NIST KAT deterministic seed (48-byte AES-256-CTR-DRBG)
			const char* kat_hex = getenv("SOFTHSM_XMSS_KAT_SEED_HEX");
			if (kat_hex && strlen(kat_hex) >= 96) {
				unsigned char kat_entropy[48];
				for (int i = 0; i < 48; i++) {
					unsigned int b;
					sscanf(kat_hex + 2*i, "%02x", &b);
					kat_entropy[i] = (unsigned char)b;
				}
				randombytes_kat_init(kat_entropy);
			}

			int ret = xmss_keypair(pub_key, priv_key, parameterSet);

			// Disable KAT DRBG after keygen (return to OpenSSL RAND_bytes)
			if (kat_hex && strlen(kat_hex) >= 96) {
				randombytes_kat_disable();
			}

			if (ret != 0) return CKR_FUNCTION_FAILED;
			pub_len = XMSS_OID_LEN + params.pk_bytes;
			priv_len = XMSS_OID_LEN + params.sk_bytes;
		}
		else if (pMechanism->mechanism == CKM_XMSSMT_KEY_PAIR_GEN) {
			keyType = CKK_XMSSMT; // 0x00000048UL
			xmss_params params;
			if (xmssmt_parse_oid(&params, parameterSet)) return CKR_PARAMETER_SET_NOT_SUPPORTED;
			// xmssmt_keypair writes [OID(4) || core_key]
			priv_key_vec.resize(XMSS_OID_LEN + params.sk_bytes);
			pub_key_vec.resize(XMSS_OID_LEN + params.pk_bytes);
			priv_key = priv_key_vec.data();
			pub_key = pub_key_vec.data();

			int ret = xmssmt_keypair(pub_key, priv_key, parameterSet);
			if (ret != 0) return CKR_FUNCTION_FAILED;
			pub_len = XMSS_OID_LEN + params.pk_bytes;
			priv_len = XMSS_OID_LEN + params.sk_bytes;
		}
		else if (pMechanism->mechanism == CKM_HSS_KEY_PAIR_GEN) {
			keyType = CKK_HSS;

			// Parse HSS Params
			unsigned hss_levels = 1;
			param_set_t lm_type[8] = { LMS_SHA256_N32_H5 };       // IANA 0x05
			param_set_t lm_ots_type[8] = { LMOTS_SHA256_N32_W8 }; // IANA 0x04
			if (pMechanism->pParameter && pMechanism->ulParameterLen >= sizeof(CK_HSS_KEY_PAIR_GEN_PARAMS)) {
				CK_HSS_KEY_PAIR_GEN_PARAMS* hP = (CK_HSS_KEY_PAIR_GEN_PARAMS*)pMechanism->pParameter;
				hss_levels = hP->ulLevels;
				if (hss_levels > 8) return CKR_MECHANISM_PARAM_INVALID;
				for (unsigned i = 0; i < hss_levels; ++i) {
					lm_type[i] = hP->ulLmsParamSet[i];
					lm_ots_type[i] = hP->ulLmotsParamSet[i];
				}
			}

			pub_len = hss_get_public_key_len(hss_levels, lm_type, lm_ots_type);
			priv_len = hss_get_private_key_len(hss_levels, lm_type, lm_ots_type);
			if (pub_len == 0 || priv_len == 0) return CKR_FUNCTION_FAILED;

			// CKA_HSS_KEYS_REMAINING = total OTS signatures available =
			// 2^(sum of LMS tree heights) (audit V-21). Reject unknown LMS types.
			remainingSigs = hssTotalSignatures(hss_levels, lm_type);
			if (remainingSigs == 0) return CKR_MECHANISM_PARAM_INVALID;

			priv_key_vec.resize(priv_len);
			pub_key_vec.resize(pub_len);
			priv_key = priv_key_vec.data();
			pub_key = pub_key_vec.data();

			auto hss_rng = [](void *out, size_t len) -> bool {
				unsigned char *buf = (unsigned char *)out;
				randombytes(buf, len);
				return true;
			};

			const char* kat_hex = getenv("SOFTHSM_XMSS_KAT_SEED_HEX");
			if (kat_hex && strlen(kat_hex) >= 96) {
				unsigned char kat_entropy[48];
				for (int i = 0; i < 48; i++) {
					unsigned int b;
					sscanf(kat_hex + 2*i, "%02x", &b);
					kat_entropy[i] = (unsigned char)b;
				}
				randombytes_kat_init(kat_entropy);
			}

			struct hss_extra_info info;
			hss_init_extra_info(&info);

			bool bOK = hss_generate_private_key(
				hss_rng,
				hss_levels,
				lm_type, lm_ots_type,
				NULL, priv_key,
				pub_key, pub_len,
				NULL, 0,
				&info
			);

			if (kat_hex && strlen(kat_hex) >= 96) {
				randombytes_kat_disable();
			}

			if (!bOK) return CKR_FUNCTION_FAILED;
		}
		
		const CK_ATTRIBUTE_TYPE CKA_PARAMETER_SET_M = 0x0000061dUL;
		
		const CK_ULONG maxAttribs = 64;
		
		// --- PUBLIC KEY ---
		// NOTE: CKA_VALUE and CKA_PARAMETER_SET have ck4 (MUST NOT be in template
		// during OBJECT_OP_GENERATE). We set them post-create on the OSObject.
		CK_ATTRIBUTE pubAttribs[maxAttribs];
		CK_ULONG pubCount = 0;
		pubAttribs[pubCount] = { CKA_CLASS, &pubClass, sizeof(pubClass) }; pubCount++;
		pubAttribs[pubCount] = { CKA_KEY_TYPE, &keyType, sizeof(keyType) }; pubCount++;
		pubAttribs[pubCount] = { CKA_TOKEN, &ispublicKeyToken, sizeof(ispublicKeyToken) }; pubCount++;
		pubAttribs[pubCount] = { CKA_PRIVATE, &ispublicKeyPrivate, sizeof(ispublicKeyPrivate) }; pubCount++;

		if (ulPublicKeyAttributeCount > (maxAttribs - pubCount)) return CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; ++i) {
			switch (pPublicKeyTemplate[i].type) {
				case CKA_CLASS: case CKA_TOKEN: case CKA_PRIVATE: case CKA_KEY_TYPE:
				case CKA_VALUE: case CKA_PARAMETER_SET_M: // ck4: skip during generate
					continue;
				default: pubAttribs[pubCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK) {
			rv = this->CreateObject(hSession, pubAttribs, pubCount, phPublicKey, OBJECT_OP_GENERATE);
		}

		// --- PRIVATE KEY ---
		CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
		CK_ULONG privCount = 0;
		CK_ATTRIBUTE privAttribs[maxAttribs];
		privAttribs[privCount] = { CKA_CLASS, &privClass, sizeof(privClass) }; privCount++;
		privAttribs[privCount] = { CKA_KEY_TYPE, &keyType, sizeof(keyType) }; privCount++;
		privAttribs[privCount] = { CKA_TOKEN, &isprivateKeyToken, sizeof(isprivateKeyToken) }; privCount++;
		privAttribs[privCount] = { CKA_PRIVATE, &isprivateKeyPrivate, sizeof(isprivateKeyPrivate) }; privCount++;
		
		if (ulPrivateKeyAttributeCount > (maxAttribs - privCount)) return CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; ++i) {
			switch (pPrivateKeyTemplate[i].type) {
				case CKA_CLASS: case CKA_TOKEN: case CKA_PRIVATE: case CKA_KEY_TYPE:
				case CKA_VALUE: case CKA_PARAMETER_SET_M: // ck4: skip during generate
					continue;
				default: privAttribs[privCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, privAttribs, privCount, phPrivateKey, OBJECT_OP_GENERATE);

		// Post-create: set ck4 attributes (CKA_VALUE, CKA_PARAMETER_SET, etc.)
		// directly on the OSObject, bypassing P11Attribute::update() checks.
		if (rv == CKR_OK) {
			OSObject* osPub = (OSObject*)handleManager->getObject(*phPublicKey);
			OSObject* osPriv = (OSObject*)handleManager->getObject(*phPrivateKey);
			
			ByteString pubValue(pub_key, pub_len);
			ByteString privPlain(priv_key, priv_len);

			// V-13: like every other private key type, encrypt the private
			// CKA_VALUE with the token key when CKA_PRIVATE=TRUE. The stateful
			// sign path decrypts it symmetrically before use.
			Token* token = session->getToken();
			ByteString privValue;
			if (isprivateKeyPrivate && token != NULL)
			{
				// token->encrypt() returns false (and wipes privValue) on an
				// RNG/AES failure without throwing. Committing the empty result
				// would silently store a corrupt private CKA_VALUE that only
				// fails at first use, so abort and tear down BOTH half-created
				// keys instead.
				if (!token->encrypt(privPlain, privValue))
				{
					handleManager->destroyObject(*phPrivateKey);
					if (osPriv) osPriv->destroyObject();
					handleManager->destroyObject(*phPublicKey);
					if (osPub) osPub->destroyObject();
					return CKR_FUNCTION_FAILED;
				}
			}
			else
				privValue = privPlain;

			if (osPub && osPub->startTransaction()) {
				bool bOK = osPub->setAttribute(CKA_LOCAL, true);
				bOK = bOK && osPub->setAttribute(CKA_KEY_GEN_MECHANISM, pMechanism->mechanism);
				osPub->setAttribute(CKA_VALUE, pubValue);
				if (pMechanism->mechanism == CKM_XMSS_KEY_PAIR_GEN || pMechanism->mechanism == CKM_XMSSMT_KEY_PAIR_GEN) {
					osPub->setAttribute(CKA_PARAMETER_SET_M, (unsigned long)parameterSet);
				}
				if (pMechanism->mechanism == CKM_HSS_KEY_PAIR_GEN) {
					osPub->setAttribute(ATTR_CKA_HSS_KEYS_REMAINING, (unsigned long)remainingSigs);
				}
				osPub->commitTransaction();
			}
			if (osPriv && osPriv->startTransaction()) {
				bool bOK = osPriv->setAttribute(CKA_LOCAL, true);
				bOK = bOK && osPriv->setAttribute(CKA_KEY_GEN_MECHANISM, pMechanism->mechanism);
				osPriv->setAttribute(CKA_VALUE, privValue);
				if (pMechanism->mechanism == CKM_XMSS_KEY_PAIR_GEN || pMechanism->mechanism == CKM_XMSSMT_KEY_PAIR_GEN) {
					osPriv->setAttribute(CKA_PARAMETER_SET_M, (unsigned long)parameterSet);
				}
				if (pMechanism->mechanism == CKM_HSS_KEY_PAIR_GEN) {
					osPriv->setAttribute(ATTR_CKA_HSS_KEYS_REMAINING, (unsigned long)remainingSigs);
				}
				osPriv->commitTransaction();
			}
		}
		return rv;
	}

	return CKR_GENERAL_ERROR;
}


// PKCS#7 padding
size_t SoftHSM::RFC5652Pad(ByteString &keydata, size_t blocksize)
{
	size_t wrappedlen = keydata.size();
	auto padbytes = blocksize - (wrappedlen % blocksize);
	if(padbytes == 0)
		padbytes += blocksize;

	keydata.resize(wrappedlen + padbytes);
	memset(&keydata[wrappedlen], static_cast<char>(padbytes), padbytes);
	return keydata.size();
}


// CKM_AES_KEY_WRAP unpadding
size_t SoftHSM::RFC3394Pad(ByteString &keydata)
{
	size_t wrappedlen = keydata.size();

	// [PKCS#11 v2.40, 2.14.3 AES Key Wrap]
	// A key whose length is not a multiple of the AES Key Wrap block
	// size (8 bytes) will be zero padded to fit.
	auto alignment = wrappedlen % 8;
	if (alignment != 0)
	{
		keydata.resize(wrappedlen + 8 - alignment);
		memset(&keydata[wrappedlen], 0, 8 - alignment);
	}
	return keydata.size();
}

// PKCS#7 padding
bool SoftHSM::RFC5652Unpad(ByteString &padded, size_t blocksize)
{
	auto wrappedlen = padded.size();

	if( wrappedlen % blocksize != 0)
	{
		DEBUG_MSG("padded buffer length %d is not a multiple of %d", wrappedlen, blocksize);
		return false;
	}

	auto padbyte = padded[wrappedlen-1];

	if( padbyte == 0 || padbyte > blocksize )
	{
		DEBUG_MSG("invalid padbyte value %d, larger than blocksize %d", padbyte, blocksize);
		return false;
	}

	for(auto i = wrappedlen-padbyte; i<wrappedlen; i++)
	{
		if( padded[i] != padbyte )
		{
			DEBUG_MSG("invalid padding byte %d at position %d", padded[i], i);
			return false;
		}
	}

	padded.resize(wrappedlen - padbyte); // forget padding
	return true;
}

// CKM_AES_KEY_WRAP padding
inline bool SoftHSM::RFC3394Unpad(ByteString &)
{
	// there is no unpadding operation, as the padding
	// does not contain any padding length info
	return true;
}


// Internal: Wrap blob using symmetric key
CK_RV SoftHSM::WrapKeySym
(
	CK_MECHANISM_PTR pMechanism,
	Token* token,
	OSObject* wrapKey,
	ByteString& keydata,
	ByteString& wrapped
)
{
	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymWrap::Type mode = SymWrap::Unknown;
	size_t bb = 8;
	size_t blocksize = 0;
	auto wrappedlen = keydata.size();

	switch(pMechanism->mechanism) {
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			wrappedlen = RFC3394Pad(keydata);
			if ((wrappedlen < 16) || ((wrappedlen % 8) != 0))
				return CKR_KEY_SIZE_RANGE;
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP_PAD;
			break;
#endif
		// CKM_AES_CBC / CKM_AES_CBC_PAD: real AES-CBC key wrap with the caller's
		// IV (audit V-5/V-6). These do NOT use the AES-KW SymWrap path — that
		// silently substituted RFC 3394 key-wrap (ignoring the IV) and, for
		// CBC_PAD, double-padded (PKCS#7 then KWP), corrupting round-tripped
		// keys. Handled separately below via the block-cipher encrypt path.
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
			algo = SymAlgo::AES;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* wrappingkey = new SymmetricKey();

	if (getSymmetricKey(wrappingkey, token, wrapKey) != CKR_OK)
	{
		cipher->recycleKey(wrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	wrappingkey->setBitLen(wrappingkey->getKeyBits().size() * bb);

	ByteString iv;
	ByteString encryptedFinal;

	if (pMechanism->mechanism == CKM_AES_CBC || pMechanism->mechanism == CKM_AES_CBC_PAD)
	{
		// Real AES-CBC wrap (audit V-5/V-6): encrypt the key bytes with the
		// supplied 16-byte IV. CKM_AES_CBC requires block-aligned plaintext
		// (no padding); CKM_AES_CBC_PAD applies PKCS#7 padding so any length
		// round-trips byte-exact through the matching unwrap.
		if (pMechanism->pParameter == NULL_PTR || pMechanism->ulParameterLen != 16)
		{
			cipher->recycleKey(wrappingkey);
			CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
			return CKR_MECHANISM_PARAM_INVALID;
		}
		iv.resize(16);
		memcpy(&iv[0], pMechanism->pParameter, 16);

		bool padding = (pMechanism->mechanism == CKM_AES_CBC_PAD);
		if (!padding && (keydata.size() == 0 || (keydata.size() % 16) != 0))
		{
			cipher->recycleKey(wrappingkey);
			CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
			return CKR_KEY_SIZE_RANGE;
		}

		ByteString encryptedData;
		if (!cipher->encryptInit(wrappingkey, SymMode::CBC, iv, padding) ||
		    !cipher->encryptUpdate(keydata, encryptedData) ||
		    !cipher->encryptFinal(encryptedFinal))
		{
			cipher->recycleKey(wrappingkey);
			CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
			return CKR_GENERAL_ERROR;
		}
		wrapped = encryptedData + encryptedFinal;
	}
	else
	{
		// Wrap the key (AES-KW / AES-KWP)
		if (!cipher->wrapKey(wrappingkey, mode, keydata, wrapped))
		{
			cipher->recycleKey(wrappingkey);
			CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
			return CKR_GENERAL_ERROR;
		}
	}

	cipher->recycleKey(wrappingkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	return CKR_OK;
}

// Internal: Wrap blob using asymmetric key
CK_RV SoftHSM::WrapKeyAsym
(
	CK_MECHANISM_PTR pMechanism,
	Token* token,
	OSObject* wrapKey,
	ByteString& keydata,
	ByteString& wrapped
)
{
	const size_t bb = 8;
	AsymAlgo::Type algo = AsymAlgo::Unknown;
	AsymMech::Type mech = AsymMech::Unknown;

	CK_ULONG modulus_length;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			algo = AsymAlgo::RSA;
			if (!wrapKey->attributeExists(CKA_MODULUS_BITS))
				return CKR_GENERAL_ERROR;
			modulus_length = wrapKey->getUnsignedLongValue(CKA_MODULUS_BITS, 0);
			// adjust key bit length
			modulus_length /= bb;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mech = AsymMech::RSA_PKCS;
			// RFC 3447 section 7.2.1
			if (keydata.size() > modulus_length - 11)
				return CKR_KEY_SIZE_RANGE;
			break;

		case CKM_RSA_PKCS_OAEP:
			mech = AsymMech::RSA_PKCS_OAEP;
			// SHA-1 is the only supported option
			// PKCS#11 2.40 draft 2 section 2.1.8: input length <= k-2-2hashLen
			if (keydata.size() > modulus_length - 2 - 2 * 160 / 8)
				return CKR_KEY_SIZE_RANGE;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* cipher = CryptoFactory::i()->getAsymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	PublicKey* publicKey = cipher->newPublicKey();
	if (publicKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			if (getRSAPublicKey((RSAPublicKey*)publicKey, token, wrapKey) != CKR_OK)
			{
				cipher->recyclePublicKey(publicKey);
				CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
				return CKR_GENERAL_ERROR;
			}
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	// Wrap the key
	if (!cipher->wrapKey(publicKey, keydata, wrapped, mech))
	{
		cipher->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	cipher->recyclePublicKey(publicKey);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);

	return CKR_OK;
}

// Internal: Wrap with mechanism RSA_AES_KEY_WRAP
CK_RV SoftHSM::WrapMechRsaAesKw
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	Token *token,
	OSObject *wrapKey,
	ByteString &keydata,
	ByteString &wrapped
)
{
	CK_RV rv = CKR_OK;
	ByteString wrapped_1; // buffer for the wrapped AES key;
	ByteString wrapped_2; // buffer for the wrapped target key;
	CK_RSA_AES_KEY_WRAP_PARAMS_PTR params = (CK_RSA_AES_KEY_WRAP_PARAMS_PTR)pMechanism->pParameter;
	CK_ULONG emphKeyLen = params->ulAESKeyBits / 8;
	CK_OBJECT_HANDLE hEmphKey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS emphKeyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE emphKeyType = CKK_AES;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	// Ephemeral AES key for RSA-AES key wrapping (session-only, destroyed immediately after use).
	// CKA_EXTRACTABLE=TRUE is intentional: the key is used only during this wrap operation
	// and is destroyed at function exit. CKA_SENSITIVE is not set because the key lifetime
	// is bounded to this function scope.
	CK_ATTRIBUTE emph_temp[] = {
		{CKA_CLASS, &emphKeyClass, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, &emphKeyType, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
		{CKA_WRAP, &bTrue, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &bTrue, sizeof(CK_BBOOL)},
		{CKA_VALUE_LEN, &emphKeyLen, sizeof(CK_ULONG)}
	};

	// Generates temporary random AES key of ulAESKeyBits length.
	rv = this->generateAES(hSession, emph_temp, sizeof(emph_temp)/sizeof(CK_ATTRIBUTE), &hEmphKey, bFalse, bTrue);
	if (rv != CKR_OK)
	{
		// Remove secret that may have been created already when the function fails.
		if (hEmphKey != CK_INVALID_HANDLE)
		{
		    OSObject *emphKey = (OSObject *)handleManager->getObject(hEmphKey);
		    handleManager->destroyObject(hEmphKey);
		    if(emphKey) emphKey->destroyObject();
		    hEmphKey = CK_INVALID_HANDLE;
		}
		return rv;
	}

	OSObject *emphKey = (OSObject *)handleManager->getObject(hEmphKey);
	if (emphKey == NULL_PTR || !emphKey->isValid())
	{
		rv = CKR_FUNCTION_FAILED;
		handleManager->destroyObject(hEmphKey);
		if(emphKey) emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		return rv;
	}

	CK_MECHANISM emphMech = {CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0};
	// Wraps the target key with the temporary AES key using CKM_AES_KEY_WRAP_PAD (RFC5649).
	rv = SoftHSM::WrapKeySym(&emphMech, token, emphKey, keydata, wrapped_2);
	if (rv != CKR_OK)
	{
		handleManager->destroyObject(hEmphKey);
		emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		return rv;
	}

	// Get the AES emph key data
	ByteString emphkeydata;
	ByteString emphKeyValue = emphKey->getByteStringValue(CKA_VALUE);
	// token->decrypt() returns false (output wiped) on AES/not-logged-in failure;
	// the recovered AES key feeds the outer RSA-OAEP wrap, so a failure must abort
	// rather than wrap with empty/garbage key material.
	if (!token->decrypt(emphKeyValue, emphkeydata))
	{
		handleManager->destroyObject(hEmphKey);
		emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		emphkeydata.wipe();
		emphKeyValue.wipe();
		return CKR_GENERAL_ERROR;
	}

	// Remove the emph key handle.
	handleManager->destroyObject(hEmphKey);
	emphKey->destroyObject();
	hEmphKey = CK_INVALID_HANDLE;

	CK_MECHANISM oaepMech = {CKM_RSA_PKCS_OAEP, params->pOAEPParams, sizeof(CK_RSA_PKCS_OAEP_PARAMS)};
	// Wraps the AES emph key with the wrapping RSA key using CKM_RSA_PKCS_OAEP with parameters of OAEPParams.
	rv = SoftHSM::WrapKeyAsym(&oaepMech, token, wrapKey, emphkeydata, wrapped_1);

	// Zeroizes the temporary AES emph key
	emphkeydata.wipe();
	emphKeyValue.wipe();

	if (rv != CKR_OK)
	{
		return rv;
	}

	// Concatenates two wrapped keys and outputs the concatenated blob.
	wrapped = wrapped_1 + wrapped_2;

	return rv;
}


// Wrap the specified key using the specified wrapping key and mechanism
CK_RV SoftHSM::C_WrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hWrappingKey,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulWrappedKeyLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	CK_RV rv;
	// Check the mechanism, only accept advanced AES key wrapping and RSA
	switch(pMechanism->mechanism)
	{
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
#endif
		case CKM_RSA_PKCS:
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
		case CKM_RSA_PKCS_OAEP:
			rv = MechParamCheckRSAPKCSOAEP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			break;
		case CKM_RSA_AES_KEY_WRAP:
			rv = MechParamCheckRSAAESKEYWRAP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			break;
		case CKM_AES_CBC:
	        case CKM_AES_CBC_PAD:
			if (pMechanism->pParameter == NULL_PTR ||
                            pMechanism->ulParameterLen != 16)
                                return CKR_ARGUMENTS_BAD;
                        break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the wrapping key handle (§2.4: scoped to this session's slot).
	OSObject *wrapKey = (OSObject *)handleManager->getObject(hWrappingKey, session->getSlot()->getSlotID());
	if (wrapKey == NULL_PTR || !wrapKey->isValid()) return CKR_WRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isWrapKeyOnToken = wrapKey->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isWrapKeyPrivate = wrapKey->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials for the wrapping key
	rv = haveRead(session->getState(), isWrapKeyOnToken, isWrapKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check wrapping key class and type
	if ((pMechanism->mechanism == CKM_AES_KEY_WRAP || pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD) && wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP || pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) &&
		wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PUBLIC_KEY)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP || pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) &&
		wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_AES_CBC || pMechanism->mechanism == CKM_AES_CBC_PAD) && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	// Check if the wrapping key can be used for wrapping
	if (wrapKey->getBooleanValue(CKA_WRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the wrapping key
	if (!isMechanismPermitted(wrapKey, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;

	// Check the to be wrapped key handle (§2.4: scoped to this session's slot).
	OSObject *key = (OSObject *)handleManager->getObject(hKey, session->getSlot()->getSlotID());
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials for the to be wrapped key
	rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check if the to be wrapped key can be wrapped
	if (key->getBooleanValue(CKA_EXTRACTABLE, false) == false)
		return CKR_KEY_UNEXTRACTABLE;
	if (key->getBooleanValue(CKA_WRAP_WITH_TRUSTED, false) && wrapKey->getBooleanValue(CKA_TRUSTED, false) == false)
		return CKR_KEY_NOT_WRAPPABLE;

	// Check the class
	CK_OBJECT_CLASS keyClass = key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
	if (keyClass != CKO_SECRET_KEY && keyClass != CKO_PRIVATE_KEY)
		return CKR_KEY_NOT_WRAPPABLE;
	// CKM_RSA_PKCS and CKM_RSA_PKCS_OAEP can be used only on SECRET keys: PKCS#11 2.40 draft 2 section 2.1.6 PKCS #1 v1.5 RSA & section 2.1.8 PKCS #1 RSA OAEP
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP) && keyClass != CKO_SECRET_KEY)
		return CKR_KEY_NOT_WRAPPABLE;

	// Verify the wrap template attribute
	if (wrapKey->attributeExists(CKA_WRAP_TEMPLATE))
	{
		OSAttribute attr = wrapKey->getAttribute(CKA_WRAP_TEMPLATE);

		if (attr.isAttributeMapAttribute())
		{
			typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> attrmap_type;

			const attrmap_type& map = attr.getAttributeMapValue();

			for (attrmap_type::const_iterator it = map.begin(); it != map.end(); ++it)
			{
				// PKCS#11 v3.2 §5.18.3: "If any attribute mismatch occurs on an
				// attempt to wrap a key then the function SHALL return
				// CKR_KEY_HANDLE_INVALID." Both sites returned
				// CKR_KEY_NOT_WRAPPABLE until the 2026-08-13 remediation (S2).
				if (!key->attributeExists(it->first))
				{
					return CKR_KEY_HANDLE_INVALID;
				}

				OSAttribute keyAttr = key->getAttribute(it->first);
				ByteString v1, v2;
				if (!keyAttr.peekValue(v1) || !it->second.peekValue(v2))
				{
					return CKR_KEY_HANDLE_INVALID;
				}

				// A private object stores its byte-string attributes encrypted
				// under the token key (P11Attribute::updateAttr), so the raw
				// stored bytes never equal the plaintext bytes the application
				// put in CKA_WRAP_TEMPLATE. Comparing them directly made the
				// partition mechanism reject EVERY private key, including the
				// ones it was configured to allow — §5.18.3 requires that "if
				// all attributes match ... then the wrap will proceed".
				// CKA_UNIQUE_ID, CKA_CHECK_VALUE and CKA_PUBLIC_KEY_INFO are
				// the three byte-string attributes whose P11Attribute::retrieve
				// overrides deliberately ignore the private flag, so they are
				// stored in clear and must not be decrypted here.
				if (isKeyPrivate && keyAttr.isByteStringAttribute() && v1.size() != 0 &&
				    it->first != CKA_UNIQUE_ID && it->first != CKA_CHECK_VALUE &&
				    it->first != CKA_PUBLIC_KEY_INFO)
				{
					ByteString plain;
					if (!token->decrypt(v1, plain))
						return CKR_GENERAL_ERROR;
					v1 = plain;
				}

				if (v1 != v2)
				{
					return CKR_KEY_HANDLE_INVALID;
				}
			}
		}
	}

	// Get the key data to encrypt
	ByteString keydata;
	if (keyClass == CKO_SECRET_KEY)
	{
		if (isKeyPrivate)
		{
			bool bOK = token->decrypt(key->getByteStringValue(CKA_VALUE), keydata);
			if (!bOK) return CKR_GENERAL_ERROR;
		}
		else
		{
			keydata = key->getByteStringValue(CKA_VALUE);
		}
	}
	else
	{
		CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

		// PQC key types: read CKA_VALUE directly — the stored value is
		// already the serialised key material.  This avoids the
		// newPrivateKey → PKCS8Encode() round-trip which can fail in
		// the WASM build when OpenSSL cannot re-encode PQC keys.
		if (keyType == CKK_ML_KEM || keyType == CKK_ML_DSA || keyType == CKK_SLH_DSA)
		{
			if (isKeyPrivate)
			{
				bool bOK = token->decrypt(key->getByteStringValue(CKA_VALUE), keydata);
				if (!bOK) return CKR_GENERAL_ERROR;
			}
			else
			{
				keydata = key->getByteStringValue(CKA_VALUE);
			}
		}
		else
		{
			// Classical key types: use PKCS#8 encoding
			AsymAlgo::Type alg = AsymAlgo::Unknown;
			switch (keyType) {
				case CKK_RSA:
					alg = AsymAlgo::RSA;
					break;
#ifdef WITH_ECC
				case CKK_EC:
					alg = AsymAlgo::ECDSA;
					break;
#endif
#ifdef WITH_EDDSA
				case CKK_EC_EDWARDS:
					alg = AsymAlgo::EDDSA;
					break;
#endif
				default:
					return CKR_KEY_NOT_WRAPPABLE;
			}
			AsymmetricAlgorithm* asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(alg);
			if (asymCrypto == NULL)
				return CKR_GENERAL_ERROR;
			PrivateKey* privateKey = asymCrypto->newPrivateKey();
			if (privateKey == NULL)
			{
				CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
				return CKR_HOST_MEMORY;
			}
			switch (keyType) {
				case CKK_RSA:
					rv = getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key);
					break;
#ifdef WITH_ECC
				case CKK_EC:
					rv = getECPrivateKey((ECPrivateKey*)privateKey, token, key);
					break;
#endif
#ifdef WITH_EDDSA
				case CKK_EC_EDWARDS:
					rv = getEDPrivateKey((EDPrivateKey*)privateKey, token, key);
					break;
#endif
			}
			if (rv != CKR_OK)
			{
				asymCrypto->recyclePrivateKey(privateKey);
				CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
				return CKR_GENERAL_ERROR;
			}
			keydata = privateKey->PKCS8Encode();
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		}
	}
	if (keydata.size() == 0)
		return CKR_KEY_NOT_WRAPPABLE;

	keyClass = wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
	ByteString wrapped;

	if (pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP)
	{
		rv = WrapMechRsaAesKw(hSession, pMechanism, token, wrapKey, keydata, wrapped);
		if (rv != CKR_OK)
		{
			return rv;
		}
	}
	else
	{
		if (keyClass == CKO_SECRET_KEY)
			rv = SoftHSM::WrapKeySym(pMechanism, token, wrapKey, keydata, wrapped);
		else
			rv = SoftHSM::WrapKeyAsym(pMechanism, token, wrapKey, keydata, wrapped);
		if (rv != CKR_OK)
			return rv;
	}

	if (pWrappedKey != NULL) {
		if (*pulWrappedKeyLen >= wrapped.size())
			memcpy(pWrappedKey, wrapped.byte_str(), wrapped.size());
		else
			rv = CKR_BUFFER_TOO_SMALL;
	}

	*pulWrappedKeyLen = wrapped.size();
	return rv;
}

// Internal: Unwrap blob using symmetric key
CK_RV SoftHSM::UnwrapKeySym
(
	CK_MECHANISM_PTR pMechanism,
	ByteString& wrapped,
	Token* token,
	OSObject* unwrapKey,
	ByteString& keydata
)
{
	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymWrap::Type mode = SymWrap::Unknown;
	size_t bb = 8;

	switch(pMechanism->mechanism) {
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP_PAD;
			break;
#endif
		// CKM_AES_CBC / CKM_AES_CBC_PAD: real AES-CBC unwrap matching the
		// WrapKeySym CBC path (audit V-5/V-6). Decryption with the IV happens
		// below, not via the AES-KW SymWrap path.
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
			algo = SymAlgo::AES;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* unwrappingkey = new SymmetricKey();

	if (getSymmetricKey(unwrappingkey, token, unwrapKey) != CKR_OK)
	{
		cipher->recycleKey(unwrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	unwrappingkey->setBitLen(unwrappingkey->getKeyBits().size() * bb);

	ByteString iv;
	ByteString decryptedFinal;
	CK_RV rv = CKR_OK;

	if (pMechanism->mechanism == CKM_AES_CBC || pMechanism->mechanism == CKM_AES_CBC_PAD)
	{
		// Real AES-CBC unwrap with the caller's 16-byte IV. CKM_AES_CBC_PAD
		// strips PKCS#7 padding; CKM_AES_CBC returns the block-aligned bytes
		// verbatim — byte-exact with the wrap.
		if (pMechanism->pParameter == NULL_PTR || pMechanism->ulParameterLen != 16)
		{
			cipher->recycleKey(unwrappingkey);
			CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
			return CKR_MECHANISM_PARAM_INVALID;
		}
		iv.resize(16);
		memcpy(&iv[0], pMechanism->pParameter, 16);

		bool padding = (pMechanism->mechanism == CKM_AES_CBC_PAD);
		if (wrapped.size() == 0 || (wrapped.size() % 16) != 0)
		{
			cipher->recycleKey(unwrappingkey);
			CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
			return CKR_WRAPPED_KEY_LEN_RANGE;
		}

		ByteString decryptedData;
		if (!cipher->decryptInit(unwrappingkey, SymMode::CBC, iv, padding) ||
		    !cipher->decryptUpdate(wrapped, decryptedData) ||
		    !cipher->decryptFinal(decryptedFinal))
		{
			cipher->recycleKey(unwrappingkey);
			CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
			// V-7: a decrypt/padding failure on the wrapped blob is an integrity
			// failure of the wrapped key, not an internal error.
			return CKR_WRAPPED_KEY_INVALID;
		}
		keydata = decryptedData + decryptedFinal;
	}
	else
	{
		// Unwrap the key (AES-KW / AES-KWP). V-7: an AES-KW/KWP integrity-check
		// failure on the wrapped blob must be reported as CKR_WRAPPED_KEY_INVALID.
		if (!cipher->unwrapKey(unwrappingkey, mode, wrapped, keydata))
			rv = CKR_WRAPPED_KEY_INVALID;
	}

	cipher->recycleKey(unwrappingkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	return rv;
}

// Internal: Unwrap blob using asymmetric key
CK_RV SoftHSM::UnwrapKeyAsym
(
	CK_MECHANISM_PTR pMechanism,
	ByteString& wrapped,
	Token* token,
	OSObject* unwrapKey,
	ByteString& keydata
)
{
	CK_RV rv = CKR_OK;
	// Get the symmetric algorithm matching the mechanism
	AsymAlgo::Type algo = AsymAlgo::Unknown;
	AsymMech::Type mode = AsymMech::Unknown;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			algo = AsymAlgo::RSA;
			mode = AsymMech::RSA_PKCS;
			break;

		case CKM_RSA_PKCS_OAEP:
			algo = AsymAlgo::RSA;
			mode = AsymMech::RSA_PKCS_OAEP;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	AsymmetricAlgorithm* cipher = CryptoFactory::i()->getAsymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	PrivateKey* unwrappingkey = cipher->newPrivateKey();
	if (unwrappingkey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			if (getRSAPrivateKey((RSAPrivateKey*)unwrappingkey, token, unwrapKey) != CKR_OK)
			{
				cipher->recyclePrivateKey(unwrappingkey);
				CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
				return CKR_GENERAL_ERROR;
			}
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	// GAP 1.6: pre-check the wrapped-blob length. RSA ciphertext is exactly the
	// modulus byte length; a mismatch is a malformed wrapped key and must be
	// reported as CKR_WRAPPED_KEY_LEN_RANGE rather than a generic decrypt error.
	{
		size_t modBytes = ((RSAPrivateKey*)unwrappingkey)->getOutputLength();
		if (modBytes != 0 && wrapped.size() != modBytes)
		{
			cipher->recyclePrivateKey(unwrappingkey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
			return CKR_WRAPPED_KEY_LEN_RANGE;
		}
	}

	// Unwrap the key. V-7: an RSA decrypt failure on the wrapped blob (bad
	// PKCS#1 / OAEP integrity) must be reported as CKR_WRAPPED_KEY_INVALID.
	if (!cipher->unwrapKey(unwrappingkey, wrapped, keydata, mode))
		rv = CKR_WRAPPED_KEY_INVALID;
	cipher->recyclePrivateKey(unwrappingkey);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
	return rv;
}

// Internal: Unwrap with mechanism RSA_AES_KEY_WRAP
CK_RV SoftHSM::UnwrapMechRsaAesKw
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	Token *token,
	OSObject *unwrapKey,
	ByteString &wrapped,
	ByteString &keydata
)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_HANDLE hEmphKey = CK_INVALID_HANDLE;
	CK_RSA_AES_KEY_WRAP_PARAMS_PTR params = (CK_RSA_AES_KEY_WRAP_PARAMS_PTR)pMechanism->pParameter;
	ByteString emphkeydata;
	ByteString modulus;
	ByteString modulusValue = unwrapKey->getByteStringValue(CKA_MODULUS);

	CK_BBOOL isUnwrapKeyPrivate = unwrapKey->getBooleanValue(CKA_PRIVATE, true);
	if(isUnwrapKeyPrivate)
	{
		// token->decrypt() returns false (output wiped) on AES/not-logged-in failure;
		// modulus.size() below splits the wrapped blob, so a failure must abort rather
		// than compute a bogus split from an empty modulus.
		if (!token->decrypt(modulusValue, modulus))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = modulusValue;
	}

	CK_ULONG ulWrappedKeyLen = wrapped.size();
	CK_ULONG wrappedLen1 = modulus.size();
	if (wrappedLen1 > ulWrappedKeyLen)
		return CKR_WRAPPED_KEY_LEN_RANGE;
	CK_ULONG wrappedLen2 = ulWrappedKeyLen - wrappedLen1;

	ByteString wrapped_1(&wrapped[0], wrappedLen1); // the wrapped AES key
	CK_MECHANISM oaepMech = {CKM_RSA_PKCS_OAEP, params->pOAEPParams, sizeof(CK_RSA_PKCS_OAEP_PARAMS)};

	// Un-wraps the temporary AES key from the first part with the private RSA key using CKM_RSA_PKCS_OAEP.
	rv = UnwrapKeyAsym(&oaepMech, wrapped_1, token, unwrapKey, emphkeydata);
	if (rv != CKR_OK)
	{
		emphkeydata.wipe();
		return rv;
	}

	CK_OBJECT_CLASS emphKeyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE emphKeyType = CKK_AES;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE emph_temp[] = {
		{CKA_CLASS, &emphKeyClass, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, &emphKeyType, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
		{CKA_UNWRAP, &bTrue, sizeof(CK_BBOOL)}
	};

	// Create the temporary AES object using C_CreateObject
	rv = this->CreateObject(hSession, emph_temp, sizeof(emph_temp) / sizeof(CK_ATTRIBUTE), &hEmphKey, OBJECT_OP_UNWRAP);
	if (rv != CKR_OK)
	{
		// Remove secret that may have been created already when the function fails.
		if (hEmphKey != CK_INVALID_HANDLE)
		{
			OSObject *emphKey = (OSObject *)handleManager->getObject(hEmphKey);
			handleManager->destroyObject(hEmphKey);
			if(emphKey) emphKey->destroyObject();
			hEmphKey = CK_INVALID_HANDLE;
		}
		emphkeydata.wipe();
		return rv;
	}

	// Store the attributes of emphkey
	OSObject *emphKey = (OSObject *)handleManager->getObject(hEmphKey);
	if (emphKey == NULL_PTR || !emphKey->isValid())
	{
		rv = CKR_FUNCTION_FAILED;
		handleManager->destroyObject(hEmphKey);
		if(emphKey) emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		emphkeydata.wipe();
		return rv;
	}

	if (emphKey->startTransaction())
	{
		bool bOK = true;
		// Common Attributes
		bOK = bOK && emphKey->setAttribute(CKA_LOCAL, false);
		// Common Secret Key Attributes
		bOK = bOK && emphKey->setAttribute(CKA_ALWAYS_SENSITIVE, false);
		bOK = bOK && emphKey->setAttribute(CKA_NEVER_EXTRACTABLE, false);
		// Secret Attributes. token->encrypt() returns false (wiping the output)
		// on RNG/AES failure without throwing; fold its result into bOK so a
		// failure aborts the transaction below instead of committing an empty
		// CKA_VALUE.
		ByteString emphKeyValue;
		bOK = bOK && token->encrypt(emphkeydata, emphKeyValue);
		bOK = bOK && emphKey->setAttribute(CKA_VALUE, emphKeyValue);

		if (bOK)
		{
			bOK = emphKey->commitTransaction();
		}
		else
		{
			emphKey->abortTransaction();
		}

		// Zeroizes the temporary AES key.
		emphkeydata.wipe();
		emphKeyValue.wipe();

		if (!bOK)
		{
			rv = CKR_FUNCTION_FAILED;
			handleManager->destroyObject(hEmphKey);
			emphKey->destroyObject();
			hEmphKey = CK_INVALID_HANDLE;
			return rv;
		}
	}
	else
	{
		rv = CKR_FUNCTION_FAILED;
		emphkeydata.wipe();
		handleManager->destroyObject(hEmphKey);
		emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		return rv;
	}

	ByteString wrapped_2(&wrapped[wrappedLen1], wrappedLen2); // the wrapped target key
	CK_MECHANISM emphMech = {CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0};

	// Un-wraps the target key from the second part with the temporary AES key using CKM_AES_KEY_WRAP_PAD (RFC5649)
	rv = UnwrapKeySym(&emphMech, wrapped_2, token, emphKey, keydata);

	// remove the emphkey handle
	handleManager->destroyObject(hEmphKey);
	emphKey->destroyObject();
	hEmphKey = CK_INVALID_HANDLE;

	return rv;
}

// Unwrap the specified key using the specified unwrapping key
CK_RV SoftHSM::C_UnwrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR hKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pWrappedKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (hKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	CK_RV rv;
	// Check the mechanism
	switch(pMechanism->mechanism)
	{
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			if ((ulWrappedKeyLen < 24) || ((ulWrappedKeyLen % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			if ((ulWrappedKeyLen < 16) || ((ulWrappedKeyLen % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
		case CKM_RSA_PKCS:
			// Input length checks needs to be done later when unwrapping key is known
			break;
		case CKM_RSA_PKCS_OAEP:
			rv = MechParamCheckRSAPKCSOAEP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			break;
		case CKM_RSA_AES_KEY_WRAP:
			rv = MechParamCheckRSAAESKEYWRAP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			break;

		case CKM_AES_CBC:
	        case CKM_AES_CBC_PAD:
			// Ciphertext must be a non-empty multiple of the AES block size (16 bytes).
			// CKM_AES_CBC_PAD always carries at least one full PKCS#7 pad block;
			// CKM_AES_CBC requires the plaintext to have been block-aligned.
			if ((ulWrappedKeyLen < 16) || ((ulWrappedKeyLen % 16) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// IV is mandatory and must be exactly one AES block (16 bytes).
			if (pMechanism->pParameter == NULL_PTR ||
                            pMechanism->ulParameterLen != 16)
				return CKR_ARGUMENTS_BAD;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the unwrapping key handle (§2.4: scoped to this session's slot).
	OSObject *unwrapKey = (OSObject *)handleManager->getObject(hUnwrappingKey, session->getSlot()->getSlotID());
	if (unwrapKey == NULL_PTR || !unwrapKey->isValid()) return CKR_UNWRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isUnwrapKeyOnToken = unwrapKey->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isUnwrapKeyPrivate = unwrapKey->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	rv = haveRead(session->getState(), isUnwrapKeyOnToken, isUnwrapKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check unwrapping key class and type
	if ((pMechanism->mechanism == CKM_AES_KEY_WRAP || pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD) && unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP || pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) &&
		unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP || pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) &&
		unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_AES_CBC || pMechanism->mechanism == CKM_AES_CBC_PAD) && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	// Check if the unwrapping key can be used for unwrapping
	if (unwrapKey->getBooleanValue(CKA_UNWRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the unwrap key
	if (!isMechanismPermitted(unwrapKey, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = false;
	rv = extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
	{
		ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_PRIVATE_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	// Key type will be handled at object creation

	// Check authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Build unwrapped key template
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_ULONG secretAttribsCount = 4;

	// PKCS#11 v3.2 §4.11: CKA_CHECK_VALUE is auto-computed for secret keys.
	// The application MAY suppress KCV generation by supplying a no-value
	// (0-length) CKA_CHECK_VALUE in the template. A non-empty supplied value
	// is rejected (we don't support template-side KCV verification, matching
	// generateAES/generateGeneric behavior).
	bool checkValue = true;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				continue;
			default:
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	// Apply the unwrap template
	if (unwrapKey->attributeExists(CKA_UNWRAP_TEMPLATE))
	{
		OSAttribute unwrapAttr = unwrapKey->getAttribute(CKA_UNWRAP_TEMPLATE);

		if (unwrapAttr.isAttributeMapAttribute())
		{
			typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> attrmap_type;

			const attrmap_type& map = unwrapAttr.getAttributeMapValue();

			for (attrmap_type::const_iterator it = map.begin(); it != map.end(); ++it)
			{
				CK_ATTRIBUTE* attr = NULL;
				for (CK_ULONG i = 0; i < secretAttribsCount; ++i)
				{
					if (it->first == secretAttribs[i].type)
					{
						if (attr != NULL)
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
						attr = &secretAttribs[i];
						ByteString value;
						it->second.peekValue(value);
						if (attr->ulValueLen != value.size())
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
						if (memcmp(attr->pValue, value.const_byte_str(), value.size()) != 0)
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
					}
				}
				if (attr == NULL)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
			}
		}
	}

	*hKey = CK_INVALID_HANDLE;

	// Unwrap the key
	ByteString wrapped(pWrappedKey, ulWrappedKeyLen);
	ByteString keydata;

	if (pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP)
	{
		rv = UnwrapMechRsaAesKw(hSession, pMechanism, token, unwrapKey, wrapped, keydata);
		if (rv != CKR_OK)
		{
			return rv;
		}
	}
	else
	{
		if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_SECRET_KEY)
			rv = UnwrapKeySym(pMechanism, wrapped, token, unwrapKey, keydata);
		else if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_PRIVATE_KEY)
			rv = UnwrapKeyAsym(pMechanism, wrapped, token, unwrapKey, keydata);
		else
			rv = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
		if (rv != CKR_OK)
			return rv;
	}

	// Create the secret object using C_CreateObject
	rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, hKey, OBJECT_OP_UNWRAP);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*hKey);
		if (osobject == NULL_PTR || !osobject->isValid())
        {
			rv = CKR_FUNCTION_FAILED;
        }
		else if (osobject->startTransaction())
		{
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);

			// Common Secret Key Attributes
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);

			// Secret Attributes
			if (objClass == CKO_SECRET_KEY)
			{
				ByteString value;
				if (isPrivate)
					// Fold token->encrypt()'s bool result into bOK: on RNG/AES
					// failure it wipes `value` without throwing, and committing
					// the empty CKA_VALUE would silently corrupt the key.
					bOK = bOK && token->encrypt(keydata, value);
				else
					value = keydata;
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				// PKCS#11 v3.2 §4.11: KCV "SHALL be supplied … regardless of
				// how the key object is created or derived" → covers C_UnwrapKey.
				// KCV is always stored in clear, computed over the plaintext
				// key bits (NOT the token-encrypted blob).
				if (checkValue)
				{
					ByteString kcv = computeSecretKeyKCV(keyType, keydata);
					if (kcv.size() == 3)
						bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
			}
			else if (keyType == CKK_RSA)
			{
				bOK = bOK && setRSAPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#ifdef WITH_ECC
			else if (keyType == CKK_EC)
			{
				bOK = bOK && setECPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif
#ifdef WITH_EDDSA
			else if (keyType == CKK_EC_EDWARDS)
			{
				bOK = bOK && setEDPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif
			else
				bOK = false;

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		}
		else
			rv = CKR_FUNCTION_FAILED;
	}

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*hKey != CK_INVALID_HANDLE)
		{
			OSObject* obj = (OSObject*)handleManager->getObject(*hKey);
			handleManager->destroyObject(*hKey);
			if (obj) obj->destroyObject();
			*hKey = CK_INVALID_HANDLE;
		}

	}

	return rv;
}

// ─────────────────────────────────────────────────────────────────────────────
// G5: PKCS#11 v3.2 authenticated key wrap / unwrap (CKM_AES_GCM only)
//
// Identical to C_WrapKey / C_UnwrapKey except:
//   • an additional pAssociatedData / ulAssociatedDataLen parameter is
//     authenticated (but not encrypted) by the AEAD mechanism
//   • only CKM_AES_GCM is supported (AES-KW does not provide native AAD)
//   • wrapped format: ciphertext ‖ tag  (tag length = ulTagBits/8)
//
// AES secret key wrapping only; private key wrapping is not supported
// (add PKCS8Encode / setXXXPrivateKey paths to extend in future).
// ─────────────────────────────────────────────────────────────────────────────

CK_RV SoftHSM::C_WrapKeyAuthenticated
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hWrappingKey,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pAssociatedData,
	CK_ULONG ulAssociatedDataLen,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR || pulWrappedKeyLen == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pMechanism->mechanism != CKM_AES_GCM) return CKR_MECHANISM_INVALID;
	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_AES_GCM_PARAMS))
		return CKR_ARGUMENTS_BAD;
	CK_AES_GCM_PARAMS* gcmParam = reinterpret_cast<CK_AES_GCM_PARAMS*>(pMechanism->pParameter);
	if (gcmParam->pIv == NULL_PTR || gcmParam->ulIvLen == 0) return CKR_ARGUMENTS_BAD;
	size_t tagLen = gcmParam->ulTagBits / 8;
	if (tagLen == 0 || tagLen > 16) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Validate wrapping key (§2.4: scoped to this session's slot).
	OSObject* wrapKey = (OSObject*)handleManager->getObject(hWrappingKey, session->getSlot()->getSlotID());
	if (wrapKey == NULL_PTR || !wrapKey->isValid()) return CKR_WRAPPING_KEY_HANDLE_INVALID;
	if (wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (wrapKey->getBooleanValue(CKA_WRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	{
		CK_BBOOL onTok = wrapKey->getBooleanValue(CKA_TOKEN, false);
		CK_BBOOL priv  = wrapKey->getBooleanValue(CKA_PRIVATE, true);
		CK_RV rv2 = haveRead(session->getState(), onTok, priv);
		if (rv2 != CKR_OK) return rv2;
	}

	// Validate key-to-be-wrapped (§2.4: scoped to this session's slot).
	OSObject* key = (OSObject*)handleManager->getObject(hKey, session->getSlot()->getSlotID());
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;
	{
		CK_OBJECT_CLASS kc = key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
		if (kc != CKO_SECRET_KEY && kc != CKO_PRIVATE_KEY)
			return CKR_KEY_NOT_WRAPPABLE;
	}
	if (key->getBooleanValue(CKA_EXTRACTABLE, false) == false) return CKR_KEY_UNEXTRACTABLE;
	if (key->getBooleanValue(CKA_WRAP_WITH_TRUSTED, false) &&
	    wrapKey->getBooleanValue(CKA_TRUSTED, false) == false)
		return CKR_KEY_NOT_WRAPPABLE;
	{
		CK_BBOOL onTok = key->getBooleanValue(CKA_TOKEN, false);
		CK_BBOOL priv  = key->getBooleanValue(CKA_PRIVATE, true);
		CK_RV rv2 = haveRead(session->getState(), onTok, priv);
		if (rv2 != CKR_OK) return rv2;
	}

	// Extract raw key bytes
	ByteString keydata;
	{
		CK_BBOOL isPriv = key->getBooleanValue(CKA_PRIVATE, true);
		if (isPriv)
		{
			if (!token->decrypt(key->getByteStringValue(CKA_VALUE), keydata))
				return CKR_GENERAL_ERROR;
		}
		else
		{
			keydata = key->getByteStringValue(CKA_VALUE);
		}
	}
	if (keydata.size() == 0) return CKR_KEY_NOT_WRAPPABLE;

	// Size-query path: return output length without performing crypto.
	if (pWrappedKey == NULL_PTR)
	{
		*pulWrappedKeyLen = static_cast<CK_ULONG>(keydata.size() + tagLen);
		keydata.wipe();
		return CKR_OK;
	}

	// Load the AES wrapping key
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (cipher == NULL) { keydata.wipe(); return CKR_MECHANISM_INVALID; }
	SymmetricKey* aesKey = new SymmetricKey();
	if (getSymmetricKey(aesKey, token, wrapKey) != CKR_OK)
	{
		keydata.wipe();
		cipher->recycleKey(aesKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}
	aesKey->setBitLen(aesKey->getKeyBits().size() * 8);

	// AES-GCM encrypt: ciphertext || tag
	// padding=false, counterBits=0 for GCM; tag length passed as tagBytes (7th arg).
	ByteString iv(gcmParam->pIv, gcmParam->ulIvLen);
	ByteString aad;
	if (pAssociatedData != NULL_PTR && ulAssociatedDataLen > 0)
		aad = ByteString(pAssociatedData, ulAssociatedDataLen);

	if (!cipher->encryptInit(aesKey, SymMode::GCM, iv, false, 0, aad, tagLen))
	{
		keydata.wipe();
		cipher->recycleKey(aesKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	ByteString cipherOut, tagOut;
	bool ok = cipher->encryptUpdate(keydata, cipherOut) && cipher->encryptFinal(tagOut);
	keydata.wipe();  // clear plaintext key material regardless of outcome
	cipher->recycleKey(aesKey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	if (!ok) return CKR_FUNCTION_FAILED;

	ByteString wrapped = cipherOut + tagOut;
	// V-18: honour the two-call convention — set the required length on the
	// CKR_BUFFER_TOO_SMALL path (mirrors the NULL size-query path above).
	if (*pulWrappedKeyLen < wrapped.size())
	{
		*pulWrappedKeyLen = static_cast<CK_ULONG>(wrapped.size());
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(pWrappedKey, wrapped.byte_str(), wrapped.size());
	*pulWrappedKeyLen = static_cast<CK_ULONG>(wrapped.size());
	return CKR_OK;
}

CK_RV SoftHSM::C_UnwrapKeyAuthenticated
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_BYTE_PTR pAssociatedData,
	CK_ULONG ulAssociatedDataLen,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pWrappedKey == NULL_PTR || phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR && ulAttributeCount != 0) return CKR_ARGUMENTS_BAD;
	if (pMechanism->mechanism != CKM_AES_GCM) return CKR_MECHANISM_INVALID;
	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_AES_GCM_PARAMS))
		return CKR_ARGUMENTS_BAD;
	CK_AES_GCM_PARAMS* gcmParam = reinterpret_cast<CK_AES_GCM_PARAMS*>(pMechanism->pParameter);
	if (gcmParam->pIv == NULL_PTR || gcmParam->ulIvLen == 0) return CKR_ARGUMENTS_BAD;
	size_t tagLen = gcmParam->ulTagBits / 8;
	if (tagLen == 0 || tagLen > 16) return CKR_ARGUMENTS_BAD;
	if (ulWrappedKeyLen <= tagLen) return CKR_WRAPPED_KEY_LEN_RANGE;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Validate unwrapping key (§2.4: scoped to this session's slot).
	OSObject* unwrapKey = (OSObject*)handleManager->getObject(hUnwrappingKey, session->getSlot()->getSlotID());
	if (unwrapKey == NULL_PTR || !unwrapKey->isValid()) return CKR_UNWRAPPING_KEY_HANDLE_INVALID;
	if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (unwrapKey->getBooleanValue(CKA_UNWRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	{
		CK_BBOOL onTok = unwrapKey->getBooleanValue(CKA_TOKEN, false);
		CK_BBOOL priv  = unwrapKey->getBooleanValue(CKA_PRIVATE, true);
		CK_RV rv2 = haveRead(session->getState(), onTok, priv);
		if (rv2 != CKR_OK) return rv2;
	}

	// Parse template to determine destination object class
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummyCert;
	bool isImplicit = false;
	{
		CK_RV rv2 = extractObjectInformation(pTemplate, ulAttributeCount,
		                                      objClass, keyType, dummyCert,
		                                      isOnToken, isPrivate, isImplicit);
		if (rv2 != CKR_OK) return rv2;
	}
	if (objClass != CKO_SECRET_KEY && objClass != CKO_PRIVATE_KEY) return CKR_ATTRIBUTE_VALUE_INVALID;

	// Authorization check for creating the new object
	{
		CK_RV rv2 = haveWrite(session->getState(), isOnToken, isPrivate);
		if (rv2 != CKR_OK) return rv2;
	}

	// Load the AES unwrapping key
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;
	SymmetricKey* aesKey = new SymmetricKey();
	if (getSymmetricKey(aesKey, token, unwrapKey) != CKR_OK)
	{
		cipher->recycleKey(aesKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}
	aesKey->setBitLen(aesKey->getKeyBits().size() * 8);

	// AES-GCM decrypt: pWrappedKey = ciphertext ‖ tag
	ByteString iv(gcmParam->pIv, gcmParam->ulIvLen);
	ByteString aad;
	if (pAssociatedData != NULL_PTR && ulAssociatedDataLen > 0)
		aad = ByteString(pAssociatedData, ulAssociatedDataLen);

	// padding=false, counterBits=0 for GCM; tag length passed as tagBytes (7th arg).
	if (!cipher->decryptInit(aesKey, SymMode::GCM, iv, false, 0, aad, tagLen))
	{
		cipher->recycleKey(aesKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	// Pass ciphertext ‖ tag as a single buffer (OSSL AEAD layer splits internally)
	ByteString aeadBuf(pWrappedKey, ulWrappedKeyLen);
	ByteString keydata, discarded;
	bool ok = cipher->decryptUpdate(aeadBuf, keydata) && cipher->decryptFinal(discarded);
	cipher->recycleKey(aesKey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	if (!ok) { keydata.wipe(); return CKR_WRAPPED_KEY_INVALID; } // auth tag mismatch
	
	// Fix Issue 44: OSSLEVPSymmetricAlgorithm dumps the entire AES-GCM plaintext in decryptFinal
	keydata = discarded;
	discarded.wipe();

	// Build the secret-key creation template (mirrors C_UnwrapKey pattern)
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS,    &objClass,  sizeof(objClass)  },
		{ CKA_TOKEN,    &isOnToken, sizeof(isOnToken)  },
		{ CKA_PRIVATE,  &isPrivate, sizeof(isPrivate)  },
		{ CKA_KEY_TYPE, &keyType,   sizeof(keyType)    }
	};
	CK_ULONG secretAttribsCount = 4;
	if (ulAttributeCount > (maxAttribs - secretAttribsCount))
	{
		keydata.wipe(); // plaintext key material must be zeroed before early return
		return CKR_TEMPLATE_INCONSISTENT;
	}
	for (CK_ULONG i = 0; i < ulAttributeCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS: case CKA_TOKEN: case CKA_PRIVATE: case CKA_KEY_TYPE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	*phKey = CK_INVALID_HANDLE;
	CK_RV rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_UNWRAP);
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid())
		{
			rv = CKR_FUNCTION_FAILED;
		}
		else if (osobject->startTransaction())
		{
			bool bOK = true;
			bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);
			if (objClass == CKO_SECRET_KEY)
			{
				ByteString value;
				if (isPrivate)
					// Fold token->encrypt()'s bool result into bOK: a failure
					// wipes `value` without throwing; committing the empty
					// CKA_VALUE would silently corrupt the key.
					bOK = bOK && token->encrypt(keydata, value);
				else
					value = keydata;
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
				value.wipe();
			}
#ifdef WITH_ECC
			else if (keyType == CKK_EC)
			{
				bOK = bOK && setECPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif
#ifdef WITH_EDDSA
			else if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY)
			{
				bOK = bOK && setEDPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif
			else
			{
				bOK = false;
			}
			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();
			if (!bOK) rv = CKR_FUNCTION_FAILED;
		}
		else
		{
			rv = CKR_FUNCTION_FAILED;
		}
	}
	keydata.wipe();  // clear decrypted plaintext key material

	if (rv != CKR_OK && *phKey != CK_INVALID_HANDLE)
	{
		OSObject* obj = (OSObject*)handleManager->getObject(*phKey);
		handleManager->destroyObject(*phKey);
		if (obj) obj->destroyObject();
		*phKey = CK_INVALID_HANDLE;
	}
	return rv;
}

// Derive a key from the specified base key
CK_RV SoftHSM::C_DeriveKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept DH and ECDH derive
	switch (pMechanism->mechanism)
	{
		case CKM_ECDH1_DERIVE:
		case CKM_ECDH1_COFACTOR_DERIVE:
		case CKM_X25519:
		case CKM_X448:
#endif
		case CKM_PKCS5_PBKD2:
		case CKM_AES_ECB_ENCRYPT_DATA:
		case CKM_AES_CBC_ENCRYPT_DATA:
		case CKM_CONCATENATE_DATA_AND_BASE:
		case CKM_CONCATENATE_BASE_AND_DATA:
		case CKM_CONCATENATE_BASE_AND_KEY:
		case CKM_HKDF_DERIVE:
		case CKM_SP800_108_COUNTER_KDF:
		case CKM_SP800_108_FEEDBACK_KDF:
		case CKM_BIP32_MASTER_DERIVE:
		case CKM_BIP32_CHILD_DERIVE:
		// SHAKE-256 as an extendable-output function, per PKCS#11 v3.2 §2.x.
		// Added for X-Wing (draft-connolly-cfrg-xwing-kem), whose decapsulation
		// key is a 32-byte seed expanded to 96 bytes: 64 for ML-KEM's
		// KeyGen_internal(d, z) and 32 for the X25519 scalar. Without this the
		// expansion has to happen outside the token, which would put private
		// key derivation in software while claiming an HSM-backed key.
		case CKM_SHAKE_256_KEY_DERIVATION:
			break;

		default:
			ERROR_MSG("Invalid mechanism");
			return CKR_MECHANISM_INVALID;
	}

	// Handle CKM_PKCS5_PBKD2 early — password is in params; no base key required
	if (pMechanism->mechanism == CKM_PKCS5_PBKD2)
	{
		if (pMechanism->pParameter == NULL_PTR ||
		    pMechanism->ulParameterLen != sizeof(CK_PKCS5_PBKD2_PARAMS2))
		{
			ERROR_MSG("CKM_PKCS5_PBKD2 requires CK_PKCS5_PBKD2_PARAMS2");
			return CKR_ARGUMENTS_BAD;
		}
		CK_PKCS5_PBKD2_PARAMS2* pbkdp = (CK_PKCS5_PBKD2_PARAMS2*)pMechanism->pParameter;
		if (pbkdp->saltSource != CKZ_SALT_SPECIFIED)
		{
			ERROR_MSG("CKM_PKCS5_PBKD2: only CKZ_SALT_SPECIFIED is supported");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (pbkdp->pPassword == NULL_PTR || pbkdp->iterations == 0)
		{
			ERROR_MSG("CKM_PKCS5_PBKD2: invalid password or iteration count");
			return CKR_ARGUMENTS_BAD;
		}

		// Map PRF to OpenSSL digest
		const EVP_MD* pbkdMd = NULL;
		switch (pbkdp->prf)
		{
			case CKP_PKCS5_PBKD2_HMAC_SHA1:   pbkdMd = EVP_sha1();   break;
			case CKP_PKCS5_PBKD2_HMAC_SHA224:  pbkdMd = EVP_sha224(); break;
			case CKP_PKCS5_PBKD2_HMAC_SHA256:  pbkdMd = EVP_sha256(); break;
			case CKP_PKCS5_PBKD2_HMAC_SHA384:  pbkdMd = EVP_sha384(); break;
			case CKP_PKCS5_PBKD2_HMAC_SHA512:  pbkdMd = EVP_sha512(); break;
			default:
				ERROR_MSG("CKM_PKCS5_PBKD2: unsupported PRF 0x%08lx", (unsigned long)pbkdp->prf);
				return CKR_MECHANISM_PARAM_INVALID;
		}

		// Extract CKA_VALUE_LEN from template
		CK_ULONG pbkdKeyLen = 0;
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			if (pTemplate[i].type == CKA_VALUE_LEN &&
			    pTemplate[i].pValue != NULL_PTR &&
			    pTemplate[i].ulValueLen == sizeof(CK_ULONG))
			{
				pbkdKeyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			}
		}
		if (pbkdKeyLen == 0 || pbkdKeyLen > 512)
		{
			ERROR_MSG("CKM_PKCS5_PBKD2: CKA_VALUE_LEN missing or out of range");
			return CKR_TEMPLATE_INCOMPLETE;
		}

		// Derive the key material via PBKDF2
		ByteString pbkdKey;
		pbkdKey.resize(pbkdKeyLen);
		if (PKCS5_PBKDF2_HMAC(
		        (const char*)pbkdp->pPassword, (int)pbkdp->ulPasswordLen,
		        (const unsigned char*)pbkdp->pSaltSourceData, (int)pbkdp->ulSaltSourceDataLen,
		        (int)pbkdp->iterations, pbkdMd, (int)pbkdKeyLen,
		        pbkdKey.byte_str()) != 1)
		{
			ERROR_MSG("PKCS5_PBKDF2_HMAC failed (0x%08X)", ERR_get_error());
			return CKR_FUNCTION_FAILED;
		}

		// Get the token for object storage
		Token* pbkdToken = session->getToken();
		if (pbkdToken == NULL) return CKR_GENERAL_ERROR;

		// Extract storage flags from template
		CK_BBOOL pbkdOnToken = CK_FALSE;
		CK_BBOOL pbkdPrivate = CK_TRUE;
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			if (pTemplate[i].type == CKA_TOKEN && pTemplate[i].pValue != NULL_PTR)
				pbkdOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
			if (pTemplate[i].type == CKA_PRIVATE && pTemplate[i].pValue != NULL_PTR)
				pbkdPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
		}

		// Check write authorization
		CK_RV pbkdRv = haveWrite(session->getState(), pbkdOnToken, pbkdPrivate);
		if (pbkdRv != CKR_OK)
		{
			if (pbkdRv == CKR_USER_NOT_LOGGED_IN)
				INFO_MSG("User is not authorized");
			if (pbkdRv == CKR_SESSION_READ_ONLY)
				INFO_MSG("Session is read-only");
			return pbkdRv;
		}

		// Build object attribute list
		const CK_ULONG pbkdMaxAttribs = 32;
		CK_OBJECT_CLASS pbkdObjClass = CKO_SECRET_KEY;
		CK_KEY_TYPE pbkdKeyType = CKK_GENERIC_SECRET;
		CK_ATTRIBUTE pbkdAttribs[pbkdMaxAttribs] = {
			{ CKA_CLASS,    &pbkdObjClass, sizeof(pbkdObjClass) },
			{ CKA_TOKEN,    &pbkdOnToken,  sizeof(pbkdOnToken)  },
			{ CKA_PRIVATE,  &pbkdPrivate,  sizeof(pbkdPrivate)  },
			{ CKA_KEY_TYPE, &pbkdKeyType,  sizeof(pbkdKeyType)  },
		};
		CK_ULONG pbkdAttribsCount = 4;
		bool pbkdCheckValue = true;
		for (CK_ULONG i = 0; i < ulCount && pbkdAttribsCount < pbkdMaxAttribs; i++)
		{
			switch (pTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				case CKA_CHECK_VALUE:
					if (pTemplate[i].ulValueLen > 0)
					{
						INFO_MSG("CKM_PKCS5_PBKD2: CKA_CHECK_VALUE must be a no-value (0 length) entry");
						return CKR_ATTRIBUTE_VALUE_INVALID;
					}
					pbkdCheckValue = false;
					continue;
				default:
					pbkdAttribs[pbkdAttribsCount++] = pTemplate[i];
					break;
			}
		}

		pbkdRv = CreateObject(hSession, pbkdAttribs, pbkdAttribsCount, phKey, OBJECT_OP_GENERATE);
		if (pbkdRv != CKR_OK) return pbkdRv;

		OSObject* pbkdObj = (OSObject*)handleManager->getObject(*phKey);
		if (pbkdObj == NULL_PTR || !pbkdObj->isValid()) return CKR_FUNCTION_FAILED;
		if (!pbkdObj->startTransaction()) return CKR_FUNCTION_FAILED;

		bool pbkdOK = true;
		pbkdOK = pbkdOK && pbkdObj->setAttribute(CKA_LOCAL, false);
		CK_ULONG pbkdGenMech = (CK_ULONG)CKM_PKCS5_PBKD2;
		pbkdOK = pbkdOK && pbkdObj->setAttribute(CKA_KEY_GEN_MECHANISM, pbkdGenMech);
		bool pbkdAlwaysSens = pbkdObj->getBooleanValue(CKA_SENSITIVE, false);
		pbkdOK = pbkdOK && pbkdObj->setAttribute(CKA_ALWAYS_SENSITIVE, pbkdAlwaysSens);
		bool pbkdNeverExtract = !pbkdObj->getBooleanValue(CKA_EXTRACTABLE, false);
		pbkdOK = pbkdOK && pbkdObj->setAttribute(CKA_NEVER_EXTRACTABLE, pbkdNeverExtract);

		SymmetricKey pbkdSymKey;
		pbkdSymKey.setKeyBits(pbkdKey);
		pbkdSymKey.setBitLen(pbkdKeyLen);
		ByteString pbkdValue;
		if (pbkdPrivate)
			// Fold encrypt() into pbkdOK: false (output wiped) on RNG/AES/not-logged-in
			// failure must abort, not commit an empty CKA_VALUE.
			pbkdOK = pbkdOK && pbkdToken->encrypt(pbkdSymKey.getKeyBits(), pbkdValue);
		else
			pbkdValue = pbkdSymKey.getKeyBits();
		pbkdOK = pbkdOK && pbkdObj->setAttribute(CKA_VALUE, pbkdValue);

		// PKCS#11 v3.2 §4.11: KCV mandatory regardless of creation path (incl. derive).
		if (pbkdCheckValue)
		{
			ByteString pbkdKcv = computeSecretKeyKCV(pbkdKeyType, pbkdSymKey.getKeyBits());
			if (pbkdKcv.size() == 3)
				pbkdOK = pbkdOK && pbkdObj->setAttribute(CKA_CHECK_VALUE, pbkdKcv);
		}

		if (pbkdOK)
			pbkdObj->commitTransaction();
		else
			pbkdObj->abortTransaction();

		if (!pbkdOK)
		{
			handleManager->destroyObject(*phKey);
			*phKey = CK_INVALID_HANDLE;
			return CKR_FUNCTION_FAILED;
		}
		return CKR_OK;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle (§2.4: scoped to this session's slot).
	// GAP 6.5: an invalid base key handle is CKR_KEY_HANDLE_INVALID per the
	// C_DeriveKey return-code list, not CKR_OBJECT_HANDLE_INVALID.
	OSObject *key = (OSObject *)handleManager->getObject(hBaseKey, session->getSlot()->getSlotID());
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	CK_RV rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check if key can be used for derive
	if (!key->getBooleanValue(CKA_DERIVE, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;

	if (pMechanism->mechanism == CKM_BIP32_MASTER_DERIVE || pMechanism->mechanism == CKM_BIP32_CHILD_DERIVE)
	{
		std::string curveOid;
		ByteString rawOid;
		bool foundCurve = false;
		for (CK_ULONG i = 0; i < ulCount; i++) {
			if (pTemplate[i].type == CKA_EC_PARAMS && pTemplate[i].pValue != NULL_PTR) {
				rawOid = ByteString((unsigned char*)pTemplate[i].pValue, pTemplate[i].ulValueLen);
				curveOid = rawOid.hex_str();
				foundCurve = true;
				break;
			}
		}
		if (!foundCurve) return CKR_TEMPLATE_INCOMPLETE;

		ByteString privKeyBytes, chainCodeBytes;
		bool deriveOk = false;

		if (pMechanism->mechanism == CKM_BIP32_MASTER_DERIVE) {
			ByteString seed;
			if (isKeyPrivate) {
				if (!token->decrypt(key->getByteStringValue(CKA_VALUE), seed)) return CKR_GENERAL_ERROR;
			} else {
				seed = key->getByteStringValue(CKA_VALUE);
			}

			deriveOk = HDWalletDerivation::deriveMasterNode(seed, curveOid, privKeyBytes, chainCodeBytes);
			seed.wipe();
		} else {
			if (pMechanism->pParameter == NULL_PTR || pMechanism->ulParameterLen != sizeof(CK_BIP32_CHILD_DERIVE_PARAMS)) {
				return CKR_ARGUMENTS_BAD;
			}
			CK_BIP32_CHILD_DERIVE_PARAMS* params = (CK_BIP32_CHILD_DERIVE_PARAMS*)pMechanism->pParameter;
			
			ByteString parentPriv;
			if (isKeyPrivate) {
				if (!token->decrypt(key->getByteStringValue(CKA_VALUE), parentPriv)) return CKR_GENERAL_ERROR;
			} else {
				parentPriv = key->getByteStringValue(CKA_VALUE);
			}
			
			ByteString parentChainCode = key->getByteStringValue(CKA_BIP32_CHAIN_CODE);
			if (parentChainCode.size() == 0) return CKR_KEY_TYPE_INCONSISTENT;

			deriveOk = HDWalletDerivation::deriveChildNode(parentPriv, parentChainCode, params->index, params->flags != 0, curveOid, privKeyBytes, chainCodeBytes);
			parentPriv.wipe();
		}

		if (!deriveOk) {
			privKeyBytes.wipe(); chainCodeBytes.wipe();
			return CKR_FUNCTION_FAILED;
		}

		// Save the object
		CK_OBJECT_CLASS objCko = CKO_PRIVATE_KEY;
		CK_KEY_TYPE objCkk = CKK_EC;
		CK_BBOOL objFalse = CK_FALSE;
		CK_BBOOL objTrue = CK_TRUE;
		
		const CK_ULONG maxAttr = 32;
		CK_ATTRIBUTE drvAttr[maxAttr] = {
			{ CKA_CLASS, &objCko, sizeof(objCko) },
			{ CKA_KEY_TYPE, &objCkk, sizeof(objCkk) },
			{ CKA_TOKEN, &objFalse, sizeof(objFalse) },
			{ CKA_PRIVATE, &objTrue, sizeof(objTrue) },
			{ CKA_SENSITIVE, &objTrue, sizeof(objTrue) },
			{ CKA_EXTRACTABLE, &objFalse, sizeof(objFalse) }
		};
		CK_ULONG drvCount = 6;
		
		for (CK_ULONG i = 0; i < ulCount && drvCount < maxAttr; i++) {
			switch (pTemplate[i].type) {
				case CKA_CLASS: case CKA_KEY_TYPE: case CKA_VALUE: case CKA_BIP32_CHAIN_CODE:
				case CKA_TOKEN: case CKA_PRIVATE: case CKA_SENSITIVE: case CKA_EXTRACTABLE:
					continue;
				default:
					drvAttr[drvCount++] = pTemplate[i];
					break;
			}
		}

		CK_RV rv2 = CreateObject(hSession, drvAttr, drvCount, phKey, OBJECT_OP_GENERATE);
		if (rv2 != CKR_OK) {
			privKeyBytes.wipe(); chainCodeBytes.wipe();
			return rv2;
		}
		
		OSObject* nObj = (OSObject*)handleManager->getObject(*phKey);
		if (nObj == NULL_PTR || !nObj->isValid() || !nObj->startTransaction()) {
			privKeyBytes.wipe(); chainCodeBytes.wipe();
			return CKR_FUNCTION_FAILED;
		}

		bool svOk = nObj->setAttribute(CKA_LOCAL, false);
		svOk = svOk && nObj->setAttribute(CKA_KEY_GEN_MECHANISM, pMechanism->mechanism);
		
		ByteString encVal;
		if (token->encrypt(privKeyBytes, encVal)) {
			svOk = svOk && nObj->setAttribute(CKA_VALUE, encVal);
		} else svOk = false;
		
		svOk = svOk && nObj->setAttribute(CKA_BIP32_CHAIN_CODE, chainCodeBytes);
		svOk = svOk && nObj->setAttribute(CKA_EC_PARAMS, rawOid);
		
#ifdef WITH_ECC
		// Set OpenSSL structural keys natively if CKK_EC. setECPrivateKey() returns
		// false if token->encrypt() fails (output wiped); fold into svOk so the derive
		// aborts rather than committing empty key material.
		svOk = svOk && setECPrivateKey(nObj, privKeyBytes, token, true);
#endif

		if (svOk) nObj->commitTransaction(); else nObj->abortTransaction();
		privKeyBytes.wipe(); chainCodeBytes.wipe();
		
		if (!svOk) {
			handleManager->destroyObject(*phKey);
			*phKey = CK_INVALID_HANDLE;
			return CKR_FUNCTION_FAILED;
		}
		return CKR_OK;
	}

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
    bool isImplicit = pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY ||
			// SHAKE-256 KD defaults to a generic secret like the concatenate
			// family, but unlike them it still REQUIRES CKA_VALUE_LEN: an XOF
			// has no natural output length to fall back on, so "no length
			// given" is a template error rather than something to infer.
			pMechanism->mechanism == CKM_SHAKE_256_KEY_DERIVATION;
    if (isImplicit) {
        // PKCS#11 2.40 section 2.31.5: if no key type is provided then the key produced by this mechanism will
        // be a generic secret key
        objClass = CKO_SECRET_KEY;
        keyType = CKK_GENERIC_SECRET;
    }
    rv = extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);
    if (rv != CKR_OK) {
        ERROR_MSG("Mandatory attribute not present in template");
        return rv;
    }

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (keyType != CKK_GENERIC_SECRET &&
	    keyType != CKK_AES)
		return CKR_TEMPLATE_INCONSISTENT;

	// Check authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}


#if defined(WITH_ECC) || defined(WITH_EDDSA)
	// Derive ECDH secret (standard and cofactor variants, and Edwards curves)
	if (pMechanism->mechanism == CKM_ECDH1_DERIVE || pMechanism->mechanism == CKM_ECDH1_COFACTOR_DERIVE ||
	    pMechanism->mechanism == CKM_X25519 || pMechanism->mechanism == CKM_X448)
	{
		// Check key class and type
		if (key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY)
			return CKR_KEY_TYPE_INCONSISTENT;
#ifdef WITH_ECC
		else if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) == CKK_EC)
			return this->deriveECDH(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
#endif
#ifdef WITH_EDDSA
		else if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) == CKK_EC_EDWARDS ||
		         key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) == CKK_EC_MONTGOMERY)
			return this->deriveEDDSA(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
#endif
		else
			return CKR_KEY_TYPE_INCONSISTENT;
	}
#endif

	// SP 800-108 Counter KDF (PKCS#11 v3.2 §2.44.1, CKM_SP800_108_COUNTER_KDF = 0x000003ac)
	if (pMechanism->mechanism == CKM_SP800_108_COUNTER_KDF)
	{
		if (pMechanism->pParameter == NULL_PTR ||
		    pMechanism->ulParameterLen != sizeof(CK_SP800_108_KDF_PARAMS))
		{
			ERROR_MSG("CKM_SP800_108_COUNTER_KDF requires CK_SP800_108_KDF_PARAMS");
			return CKR_ARGUMENTS_BAD;
		}
		CK_SP800_108_KDF_PARAMS* kp = (CK_SP800_108_KDF_PARAMS*)pMechanism->pParameter;

		// Map prfType to OpenSSL MAC name + digest/cipher name
		bool kbkUseCmac = (kp->prfType == CKM_AES_CMAC);
		const char* kbkMacName = kbkUseCmac ? "CMAC" : "HMAC";
		const char* kbkDigestName = nullptr;
		if (!kbkUseCmac)
		{
			kbkDigestName = ckmHmacPrfToDigestName(kp->prfType);
			if (kbkDigestName == nullptr)
			{
				ERROR_MSG("CKM_SP800_108_COUNTER_KDF: PRF 0x%08lx is not a keyed-MAC mechanism", (unsigned long)kp->prfType);
				return CKR_MECHANISM_PARAM_INVALID;
			}
		}

		// Determine output key length from template CKA_VALUE_LEN
		CK_ULONG kbkKeyLen = 0;
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			if (pTemplate[i].type == CKA_VALUE_LEN &&
			    pTemplate[i].pValue != NULL_PTR &&
			    pTemplate[i].ulValueLen == sizeof(CK_ULONG))
			{
				kbkKeyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			}
		}
		if (kbkKeyLen == 0 || kbkKeyLen > 512)
		{
			ERROR_MSG("CKM_SP800_108_COUNTER_KDF: CKA_VALUE_LEN missing or out of range (got %lu)", (unsigned long)kbkKeyLen);
			return CKR_TEMPLATE_INCOMPLETE;
		}

		// Retrieve base key (Ki) — decrypt if stored privately
		ByteString kbkIKM;
		if (isKeyPrivate)
		{
			if (!token->decrypt(key->getByteStringValue(CKA_VALUE), kbkIKM))
				return CKR_GENERAL_ERROR;
		}
		else
		{
			kbkIKM = key->getByteStringValue(CKA_VALUE);
		}

		// For CMAC: select AES cipher variant based on key size
		const char* kbkCipherName = nullptr;
		if (kbkUseCmac)
		{
			switch (kbkIKM.size())
			{
				case 16: kbkCipherName = "AES-128-CBC"; break;
				case 24: kbkCipherName = "AES-192-CBC"; break;
				case 32: kbkCipherName = "AES-256-CBC"; break;
				default:
					ERROR_MSG("CKM_SP800_108_COUNTER_KDF: unsupported CMAC key size %lu bytes", (unsigned long)kbkIKM.size());
					return CKR_KEY_SIZE_RANGE;
			}
		}

		// Parse CK_PRF_DATA_PARAM array:
		//   CK_SP800_108_BYTE_ARRAY → append to fixed-input label/context buffer
		//   CK_SP800_108_ITERATION_VARIABLE → extract counter width (default 32 bits)
		ByteString kbkFixedInput;
		int kbkCounterBits = 32;
		for (CK_ULONG i = 0; i < kp->ulNumberOfDataParams; i++)
		{
			CK_PRF_DATA_PARAM* dp = &kp->pDataParams[i];
			switch (dp->type)
			{
				case CK_SP800_108_BYTE_ARRAY:
					if (dp->pValue != NULL_PTR && dp->ulValueLen > 0)
						kbkFixedInput += ByteString((CK_BYTE_PTR)dp->pValue, dp->ulValueLen);
					break;
				case CK_SP800_108_ITERATION_VARIABLE:
					if (dp->pValue != NULL_PTR && dp->ulValueLen == sizeof(CK_SP800_108_COUNTER_FORMAT))
					{
						CK_SP800_108_COUNTER_FORMAT* cf = (CK_SP800_108_COUNTER_FORMAT*)dp->pValue;
						if (cf->ulWidthInBits > 0 && cf->ulWidthInBits <= 64)
							kbkCounterBits = (int)cf->ulWidthInBits;
					}
					break;
				default:
					break; // DKM_LENGTH, KEY_HANDLE not supported — skip
			}
		}

		// Derive via OpenSSL KBKDF counter mode
		ByteString kbkOut;
		kbkOut.resize(kbkKeyLen);
		{
			static const char kbkModeStr[] = "COUNTER";
			EVP_KDF* kbkAlgo = EVP_KDF_fetch(NULL, "KBKDF", NULL);
			if (kbkAlgo == NULL)
			{
				ERROR_MSG("EVP_KDF_fetch KBKDF failed: 0x%08X", ERR_get_error());
				return CKR_FUNCTION_FAILED;
			}
			EVP_KDF_CTX* kbkctx = EVP_KDF_CTX_new(kbkAlgo);
			EVP_KDF_free(kbkAlgo);
			if (kbkctx == NULL)
			{
				ERROR_MSG("EVP_KDF_CTX_new KBKDF failed");
				return CKR_FUNCTION_FAILED;
			}

			OSSL_PARAM kbkParams[8];
			int kpi = 0;
			kbkParams[kpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE,
			                        const_cast<char*>(kbkModeStr), 0);
			kbkParams[kpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
			                        const_cast<char*>(kbkMacName), 0);
			if (!kbkUseCmac)
				kbkParams[kpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
				                        const_cast<char*>(kbkDigestName), 0);
			else
				kbkParams[kpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER,
				                        const_cast<char*>(kbkCipherName), 0);
			kbkParams[kpi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
			                        kbkIKM.byte_str(), kbkIKM.size());
			if (kbkFixedInput.size() > 0)
				kbkParams[kpi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
				                        kbkFixedInput.byte_str(), kbkFixedInput.size());
			kbkParams[kpi++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_R, &kbkCounterBits);
			kbkParams[kpi] = OSSL_PARAM_construct_end();

			int kbkRet = EVP_KDF_derive(kbkctx, kbkOut.byte_str(), kbkKeyLen, kbkParams);
			EVP_KDF_CTX_free(kbkctx);
			if (kbkRet <= 0)
			{
				ERROR_MSG("EVP_KDF_derive KBKDF failed: 0x%08X", ERR_get_error());
				return CKR_FUNCTION_FAILED;
			}
		}

		// Build output key object (mirrors HKDF handler)
		CK_BBOOL kbkOnToken = CK_FALSE;
		CK_BBOOL kbkPrivate = CK_TRUE;
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			if (pTemplate[i].type == CKA_TOKEN && pTemplate[i].pValue != NULL_PTR)
				kbkOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
			if (pTemplate[i].type == CKA_PRIVATE && pTemplate[i].pValue != NULL_PTR)
				kbkPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
		}

		CK_RV kbkRv = haveWrite(session->getState(), kbkOnToken, kbkPrivate);
		if (kbkRv != CKR_OK)
		{
			if (kbkRv == CKR_USER_NOT_LOGGED_IN) INFO_MSG("User is not authorized");
			if (kbkRv == CKR_SESSION_READ_ONLY)  INFO_MSG("Session is read-only");
			return kbkRv;
		}

		const CK_ULONG kbkMaxAttribs = 32;
		CK_OBJECT_CLASS kbkObjClass = CKO_SECRET_KEY;
		CK_KEY_TYPE     kbkKeyType  = CKK_GENERIC_SECRET;
		CK_ATTRIBUTE kbkAttribs[kbkMaxAttribs] = {
			{ CKA_CLASS,    &kbkObjClass, sizeof(kbkObjClass) },
			{ CKA_TOKEN,    &kbkOnToken,  sizeof(kbkOnToken)  },
			{ CKA_PRIVATE,  &kbkPrivate,  sizeof(kbkPrivate)  },
			{ CKA_KEY_TYPE, &kbkKeyType,  sizeof(kbkKeyType)  },
		};
		CK_ULONG kbkAttribsCount = 4;
		bool kbkCheckValue = true;
		for (CK_ULONG i = 0; i < ulCount && kbkAttribsCount < kbkMaxAttribs; i++)
		{
			switch (pTemplate[i].type)
			{
				case CKA_CLASS: case CKA_TOKEN: case CKA_PRIVATE:
				case CKA_KEY_TYPE: continue;
				case CKA_CHECK_VALUE:
					if (pTemplate[i].ulValueLen > 0)
					{
						INFO_MSG("CKM_SP800_108_COUNTER_KDF: CKA_CHECK_VALUE must be a no-value (0 length) entry");
						return CKR_ATTRIBUTE_VALUE_INVALID;
					}
					kbkCheckValue = false;
					continue;
				default: kbkAttribs[kbkAttribsCount++] = pTemplate[i]; break;
			}
		}

		kbkRv = CreateObject(hSession, kbkAttribs, kbkAttribsCount, phKey, OBJECT_OP_GENERATE);
		if (kbkRv != CKR_OK) return kbkRv;

		OSObject* kbkObj = (OSObject*)handleManager->getObject(*phKey);
		if (kbkObj == NULL_PTR || !kbkObj->isValid()) return CKR_FUNCTION_FAILED;
		if (!kbkObj->startTransaction()) return CKR_FUNCTION_FAILED;

		bool kbkOK = true;
		kbkOK = kbkOK && kbkObj->setAttribute(CKA_LOCAL, false);
		CK_ULONG kbkGenMech = (CK_ULONG)CKM_SP800_108_COUNTER_KDF;
		kbkOK = kbkOK && kbkObj->setAttribute(CKA_KEY_GEN_MECHANISM, kbkGenMech);
		bool kbkAlwaysSens   = kbkObj->getBooleanValue(CKA_SENSITIVE, false);
		kbkOK = kbkOK && kbkObj->setAttribute(CKA_ALWAYS_SENSITIVE, kbkAlwaysSens);
		bool kbkNeverExtract = !kbkObj->getBooleanValue(CKA_EXTRACTABLE, false);
		kbkOK = kbkOK && kbkObj->setAttribute(CKA_NEVER_EXTRACTABLE, kbkNeverExtract);

		SymmetricKey kbkSymKey;
		kbkSymKey.setKeyBits(kbkOut);
		kbkSymKey.setBitLen(kbkKeyLen * 8);
		ByteString kbkValue;
		if (kbkPrivate)
			// Fold the bool result in: a token->encrypt() failure wipes
			// kbkValue without throwing, so committing it would corrupt the key.
			kbkOK = kbkOK && token->encrypt(kbkSymKey.getKeyBits(), kbkValue);
		else
			kbkValue = kbkSymKey.getKeyBits();
		kbkOK = kbkOK && kbkObj->setAttribute(CKA_VALUE, kbkValue);

		// PKCS#11 v3.2 §4.11: KCV mandatory regardless of creation path (incl. derive).
		if (kbkCheckValue)
		{
			ByteString kbkKcv = computeSecretKeyKCV(kbkKeyType, kbkSymKey.getKeyBits());
			if (kbkKcv.size() == 3)
				kbkOK = kbkOK && kbkObj->setAttribute(CKA_CHECK_VALUE, kbkKcv);
		}

		if (kbkOK)
			kbkObj->commitTransaction();
		else
			kbkObj->abortTransaction();

		if (!kbkOK)
		{
			handleManager->destroyObject(*phKey);
			*phKey = CK_INVALID_HANDLE;
			return CKR_FUNCTION_FAILED;
		}
		return CKR_OK;
	}

	// SP 800-108 Feedback KDF (PKCS#11 v3.2 §2.44.2, CKM_SP800_108_FEEDBACK_KDF = 0x000003ad)
	if (pMechanism->mechanism == CKM_SP800_108_FEEDBACK_KDF)
	{
		if (pMechanism->pParameter == NULL_PTR ||
		    pMechanism->ulParameterLen != sizeof(CK_SP800_108_FEEDBACK_KDF_PARAMS))
		{
			ERROR_MSG("CKM_SP800_108_FEEDBACK_KDF requires CK_SP800_108_FEEDBACK_KDF_PARAMS");
			return CKR_ARGUMENTS_BAD;
		}
		CK_SP800_108_FEEDBACK_KDF_PARAMS* fp = (CK_SP800_108_FEEDBACK_KDF_PARAMS*)pMechanism->pParameter;

		// Map prfType to OpenSSL MAC + digest/cipher name (same as COUNTER_KDF)
		bool fbkUseCmac = (fp->prfType == CKM_AES_CMAC);
		const char* fbkMacName = fbkUseCmac ? "CMAC" : "HMAC";
		const char* fbkDigestName = nullptr;
		if (!fbkUseCmac)
		{
			fbkDigestName = ckmHmacPrfToDigestName(fp->prfType);
			if (fbkDigestName == nullptr)
			{
				ERROR_MSG("CKM_SP800_108_FEEDBACK_KDF: PRF 0x%08lx is not a keyed-MAC mechanism", (unsigned long)fp->prfType);
				return CKR_MECHANISM_PARAM_INVALID;
			}
		}

		// Determine output key length from template CKA_VALUE_LEN
		CK_ULONG fbkKeyLen = 0;
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			if (pTemplate[i].type == CKA_VALUE_LEN &&
			    pTemplate[i].pValue != NULL_PTR &&
			    pTemplate[i].ulValueLen == sizeof(CK_ULONG))
			{
				fbkKeyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			}
		}
		if (fbkKeyLen == 0 || fbkKeyLen > 512)
		{
			ERROR_MSG("CKM_SP800_108_FEEDBACK_KDF: CKA_VALUE_LEN missing or out of range (got %lu)", (unsigned long)fbkKeyLen);
			return CKR_TEMPLATE_INCOMPLETE;
		}

		// Retrieve base key (Ki) — decrypt if stored privately
		ByteString fbkIKM;
		if (isKeyPrivate)
		{
			if (!token->decrypt(key->getByteStringValue(CKA_VALUE), fbkIKM))
				return CKR_GENERAL_ERROR;
		}
		else
		{
			fbkIKM = key->getByteStringValue(CKA_VALUE);
		}

		// For CMAC: select AES cipher variant based on key size
		const char* fbkCipherName = nullptr;
		if (fbkUseCmac)
		{
			switch (fbkIKM.size())
			{
				case 16: fbkCipherName = "AES-128-CBC"; break;
				case 24: fbkCipherName = "AES-192-CBC"; break;
				case 32: fbkCipherName = "AES-256-CBC"; break;
				default:
					ERROR_MSG("CKM_SP800_108_FEEDBACK_KDF: unsupported CMAC key size %lu bytes", (unsigned long)fbkIKM.size());
					return CKR_KEY_SIZE_RANGE;
			}
		}

		// Parse CK_PRF_DATA_PARAM array for BYTE_ARRAY label/context data
		ByteString fbkFixedInput;
		for (CK_ULONG i = 0; i < fp->ulNumberOfDataParams; i++)
		{
			CK_PRF_DATA_PARAM* dp = &fp->pDataParams[i];
			if (dp->type == CK_SP800_108_BYTE_ARRAY && dp->pValue != NULL_PTR && dp->ulValueLen > 0)
				fbkFixedInput += ByteString((CK_BYTE_PTR)dp->pValue, dp->ulValueLen);
		}

		// Derive via OpenSSL KBKDF feedback mode
		ByteString fbkOut;
		fbkOut.resize(fbkKeyLen);
		{
			static const char fbkModeStr[] = "FEEDBACK";
			EVP_KDF* fbkAlgo = EVP_KDF_fetch(NULL, "KBKDF", NULL);
			if (fbkAlgo == NULL)
			{
				ERROR_MSG("EVP_KDF_fetch KBKDF failed: 0x%08X", ERR_get_error());
				return CKR_FUNCTION_FAILED;
			}
			EVP_KDF_CTX* fbkctx = EVP_KDF_CTX_new(fbkAlgo);
			EVP_KDF_free(fbkAlgo);
			if (fbkctx == NULL)
			{
				ERROR_MSG("EVP_KDF_CTX_new KBKDF failed");
				return CKR_FUNCTION_FAILED;
			}

			OSSL_PARAM fbkParams[9];
			int fpi = 0;
			fbkParams[fpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE,
			                        const_cast<char*>(fbkModeStr), 0);
			fbkParams[fpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
			                        const_cast<char*>(fbkMacName), 0);
			if (!fbkUseCmac)
				fbkParams[fpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
				                        const_cast<char*>(fbkDigestName), 0);
			else
				fbkParams[fpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER,
				                        const_cast<char*>(fbkCipherName), 0);
			fbkParams[fpi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
			                        fbkIKM.byte_str(), fbkIKM.size());
			if (fbkFixedInput.size() > 0)
				fbkParams[fpi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
				                        fbkFixedInput.byte_str(), fbkFixedInput.size());
			// Optional IV/seed for feedback mode (PKCS#11 v3.2 §2.44.2 fp->pIV)
			if (fp->pIV != NULL_PTR && fp->ulIVLen > 0)
				fbkParams[fpi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED,
				                        fp->pIV, (size_t)fp->ulIVLen);
			fbkParams[fpi] = OSSL_PARAM_construct_end();

			int fbkRet = EVP_KDF_derive(fbkctx, fbkOut.byte_str(), fbkKeyLen, fbkParams);
			EVP_KDF_CTX_free(fbkctx);
			if (fbkRet <= 0)
			{
				ERROR_MSG("EVP_KDF_derive KBKDF feedback failed: 0x%08X", ERR_get_error());
				return CKR_FUNCTION_FAILED;
			}
		}

		// Build output key object (mirrors COUNTER_KDF handler)
		CK_BBOOL fbkOnToken = CK_FALSE;
		CK_BBOOL fbkPrivate = CK_TRUE;
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			if (pTemplate[i].type == CKA_TOKEN && pTemplate[i].pValue != NULL_PTR)
				fbkOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
			if (pTemplate[i].type == CKA_PRIVATE && pTemplate[i].pValue != NULL_PTR)
				fbkPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
		}

		CK_RV fbkRv = haveWrite(session->getState(), fbkOnToken, fbkPrivate);
		if (fbkRv != CKR_OK)
		{
			if (fbkRv == CKR_USER_NOT_LOGGED_IN) INFO_MSG("User is not authorized");
			if (fbkRv == CKR_SESSION_READ_ONLY)  INFO_MSG("Session is read-only");
			return fbkRv;
		}

		const CK_ULONG fbkMaxAttribs = 32;
		CK_OBJECT_CLASS fbkObjClass = CKO_SECRET_KEY;
		CK_KEY_TYPE     fbkKeyType  = CKK_GENERIC_SECRET;
		CK_ATTRIBUTE fbkAttribs[fbkMaxAttribs] = {
			{ CKA_CLASS,    &fbkObjClass, sizeof(fbkObjClass) },
			{ CKA_TOKEN,    &fbkOnToken,  sizeof(fbkOnToken)  },
			{ CKA_PRIVATE,  &fbkPrivate,  sizeof(fbkPrivate)  },
			{ CKA_KEY_TYPE, &fbkKeyType,  sizeof(fbkKeyType)  },
		};
		CK_ULONG fbkAttribsCount = 4;
		bool fbkCheckValue = true;
		for (CK_ULONG i = 0; i < ulCount && fbkAttribsCount < fbkMaxAttribs; i++)
		{
			switch (pTemplate[i].type)
			{
				case CKA_CLASS: case CKA_TOKEN: case CKA_PRIVATE:
				case CKA_KEY_TYPE: continue;
				case CKA_CHECK_VALUE:
					if (pTemplate[i].ulValueLen > 0)
					{
						INFO_MSG("CKM_SP800_108_FEEDBACK_KDF: CKA_CHECK_VALUE must be a no-value (0 length) entry");
						return CKR_ATTRIBUTE_VALUE_INVALID;
					}
					fbkCheckValue = false;
					continue;
				default: fbkAttribs[fbkAttribsCount++] = pTemplate[i]; break;
			}
		}

		fbkRv = CreateObject(hSession, fbkAttribs, fbkAttribsCount, phKey, OBJECT_OP_GENERATE);
		if (fbkRv != CKR_OK) return fbkRv;

		OSObject* fbkObj = (OSObject*)handleManager->getObject(*phKey);
		if (fbkObj == NULL_PTR || !fbkObj->isValid()) return CKR_FUNCTION_FAILED;
		if (!fbkObj->startTransaction()) return CKR_FUNCTION_FAILED;

		bool fbkOK = true;
		fbkOK = fbkOK && fbkObj->setAttribute(CKA_LOCAL, false);
		CK_ULONG fbkGenMech = (CK_ULONG)CKM_SP800_108_FEEDBACK_KDF;
		fbkOK = fbkOK && fbkObj->setAttribute(CKA_KEY_GEN_MECHANISM, fbkGenMech);
		bool fbkAlwaysSens   = fbkObj->getBooleanValue(CKA_SENSITIVE, false);
		fbkOK = fbkOK && fbkObj->setAttribute(CKA_ALWAYS_SENSITIVE, fbkAlwaysSens);
		bool fbkNeverExtract = !fbkObj->getBooleanValue(CKA_EXTRACTABLE, false);
		fbkOK = fbkOK && fbkObj->setAttribute(CKA_NEVER_EXTRACTABLE, fbkNeverExtract);

		SymmetricKey fbkSymKey;
		fbkSymKey.setKeyBits(fbkOut);
		fbkSymKey.setBitLen(fbkKeyLen * 8);
		ByteString fbkValue;
		if (fbkPrivate)
			// Fold the bool result in: a token->encrypt() failure wipes
			// fbkValue without throwing; committing it would corrupt the key.
			fbkOK = fbkOK && token->encrypt(fbkSymKey.getKeyBits(), fbkValue);
		else
			fbkValue = fbkSymKey.getKeyBits();
		fbkOK = fbkOK && fbkObj->setAttribute(CKA_VALUE, fbkValue);

		// PKCS#11 v3.2 §4.11: KCV mandatory regardless of creation path (incl. derive).
		if (fbkCheckValue)
		{
			ByteString fbkKcv = computeSecretKeyKCV(fbkKeyType, fbkSymKey.getKeyBits());
			if (fbkKcv.size() == 3)
				fbkOK = fbkOK && fbkObj->setAttribute(CKA_CHECK_VALUE, fbkKcv);
		}

		if (fbkOK)
			fbkObj->commitTransaction();
		else
			fbkObj->abortTransaction();

		if (!fbkOK)
		{
			handleManager->destroyObject(*phKey);
			*phKey = CK_INVALID_HANDLE;
			return CKR_FUNCTION_FAILED;
		}
		return CKR_OK;
	}

	// HKDF derive (PKCS#11 v3.0+ §2.43, CKM_HKDF_DERIVE = 0x0000402a)
	if (pMechanism->mechanism == CKM_HKDF_DERIVE)
	{
		if (pMechanism->pParameter == NULL_PTR ||
		    pMechanism->ulParameterLen != sizeof(CK_HKDF_PARAMS))
		{
			ERROR_MSG("CKM_HKDF_DERIVE requires CK_HKDF_PARAMS");
			return CKR_ARGUMENTS_BAD;
		}
		CK_HKDF_PARAMS* hkdfp = (CK_HKDF_PARAMS*)pMechanism->pParameter;

		if (!hkdfp->bExtract && !hkdfp->bExpand)
		{
			ERROR_MSG("CKM_HKDF_DERIVE: at least one of bExtract/bExpand must be true");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (hkdfp->ulSaltType == CKF_HKDF_SALT_KEY)
		{
			ERROR_MSG("CKM_HKDF_DERIVE: CKF_HKDF_SALT_KEY not supported");
			return CKR_MECHANISM_PARAM_INVALID;
		}

		// Map PRF hash mechanism to OpenSSL digest name
		const char* hkdfDigest = ckmToDigestName(hkdfp->prfHashMechanism);
		if (hkdfDigest == nullptr)
		{
			ERROR_MSG("CKM_HKDF_DERIVE: unsupported PRF 0x%08lx", (unsigned long)hkdfp->prfHashMechanism);
			return CKR_MECHANISM_PARAM_INVALID;
		}

		// Determine output key length from template CKA_VALUE_LEN
		CK_ULONG hkdfKeyLen = 0;
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			if (pTemplate[i].type == CKA_VALUE_LEN &&
			    pTemplate[i].pValue != NULL_PTR &&
			    pTemplate[i].ulValueLen == sizeof(CK_ULONG))
			{
				hkdfKeyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			}
		}
		if (hkdfKeyLen == 0 || hkdfKeyLen > 512)
		{
			ERROR_MSG("CKM_HKDF_DERIVE: CKA_VALUE_LEN missing or out of range");
			return CKR_TEMPLATE_INCOMPLETE;
		}

		// Retrieve base key IKM (decrypt if private)
		ByteString hkdfIKM;
		if (isKeyPrivate)
		{
			if (!token->decrypt(key->getByteStringValue(CKA_VALUE), hkdfIKM))
				return CKR_GENERAL_ERROR;
		}
		else
		{
			hkdfIKM = key->getByteStringValue(CKA_VALUE);
		}

		// Determine HKDF mode
		int hkdfMode;
		if (hkdfp->bExtract && hkdfp->bExpand)
			hkdfMode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
		else if (hkdfp->bExtract)
			hkdfMode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
		else
			hkdfMode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

		// Derive via HKDF
		ByteString hkdfOut;
		hkdfOut.resize(hkdfKeyLen);
		{
			EVP_KDF* hkdfAlgo = EVP_KDF_fetch(NULL, "HKDF", NULL);
			if (hkdfAlgo == NULL)
			{
				ERROR_MSG("EVP_KDF_fetch HKDF failed: 0x%08X", ERR_get_error());
				return CKR_FUNCTION_FAILED;
			}
			EVP_KDF_CTX* hkctx = EVP_KDF_CTX_new(hkdfAlgo);
			EVP_KDF_free(hkdfAlgo);
			if (hkctx == NULL)
			{
				ERROR_MSG("EVP_KDF_CTX_new HKDF failed");
				return CKR_FUNCTION_FAILED;
			}

			OSSL_PARAM hkdfParams[6];
			int hpi = 0;
			hkdfParams[hpi++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &hkdfMode);
			hkdfParams[hpi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
			                        const_cast<char*>(hkdfDigest), 0);
			hkdfParams[hpi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
			                        hkdfIKM.byte_str(), hkdfIKM.size());
			if (hkdfp->ulSaltType == CKF_HKDF_SALT_DATA &&
			    hkdfp->pSalt != NULL_PTR && hkdfp->ulSaltLen > 0)
				hkdfParams[hpi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
				                        hkdfp->pSalt, (size_t)hkdfp->ulSaltLen);
			if (hkdfp->pInfo != NULL_PTR && hkdfp->ulInfoLen > 0)
				hkdfParams[hpi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
				                        hkdfp->pInfo, (size_t)hkdfp->ulInfoLen);
			hkdfParams[hpi] = OSSL_PARAM_construct_end();

			int hkdfRet = EVP_KDF_derive(hkctx, hkdfOut.byte_str(), hkdfKeyLen, hkdfParams);
			EVP_KDF_CTX_free(hkctx);
			if (hkdfRet <= 0)
			{
				ERROR_MSG("EVP_KDF_derive HKDF failed: 0x%08X", ERR_get_error());
				return CKR_FUNCTION_FAILED;
			}
		}

		// Build output key object (mirror PBKDF2 pattern)
		CK_BBOOL hkdfOnToken = CK_FALSE;
		CK_BBOOL hkdfPrivate = CK_TRUE;
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			if (pTemplate[i].type == CKA_TOKEN && pTemplate[i].pValue != NULL_PTR)
				hkdfOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
			if (pTemplate[i].type == CKA_PRIVATE && pTemplate[i].pValue != NULL_PTR)
				hkdfPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
		}

		CK_RV hkdfRv = haveWrite(session->getState(), hkdfOnToken, hkdfPrivate);
		if (hkdfRv != CKR_OK)
		{
			if (hkdfRv == CKR_USER_NOT_LOGGED_IN) INFO_MSG("User is not authorized");
			if (hkdfRv == CKR_SESSION_READ_ONLY)  INFO_MSG("Session is read-only");
			return hkdfRv;
		}

		const CK_ULONG hkdfMaxAttribs = 32;
		CK_OBJECT_CLASS hkdfObjClass = CKO_SECRET_KEY;
		CK_KEY_TYPE     hkdfKeyType  = CKK_GENERIC_SECRET;
		CK_ATTRIBUTE hkdfAttribs[hkdfMaxAttribs] = {
			{ CKA_CLASS,    &hkdfObjClass, sizeof(hkdfObjClass) },
			{ CKA_TOKEN,    &hkdfOnToken,  sizeof(hkdfOnToken)  },
			{ CKA_PRIVATE,  &hkdfPrivate,  sizeof(hkdfPrivate)  },
			{ CKA_KEY_TYPE, &hkdfKeyType,  sizeof(hkdfKeyType)  },
		};
		CK_ULONG hkdfAttribsCount = 4;
		bool hkdfCheckValue = true;
		for (CK_ULONG i = 0; i < ulCount && hkdfAttribsCount < hkdfMaxAttribs; i++)
		{
			switch (pTemplate[i].type)
			{
				case CKA_CLASS: case CKA_TOKEN: case CKA_PRIVATE:
				case CKA_KEY_TYPE: continue;
				case CKA_CHECK_VALUE:
					if (pTemplate[i].ulValueLen > 0)
					{
						INFO_MSG("CKM_HKDF_DERIVE: CKA_CHECK_VALUE must be a no-value (0 length) entry");
						return CKR_ATTRIBUTE_VALUE_INVALID;
					}
					hkdfCheckValue = false;
					continue;
				default: hkdfAttribs[hkdfAttribsCount++] = pTemplate[i]; break;
			}
		}

		hkdfRv = CreateObject(hSession, hkdfAttribs, hkdfAttribsCount, phKey, OBJECT_OP_GENERATE);
		if (hkdfRv != CKR_OK) return hkdfRv;

		OSObject* hkdfObj = (OSObject*)handleManager->getObject(*phKey);
		if (hkdfObj == NULL_PTR || !hkdfObj->isValid()) return CKR_FUNCTION_FAILED;
		if (!hkdfObj->startTransaction()) return CKR_FUNCTION_FAILED;

		bool hkdfOK = true;
		hkdfOK = hkdfOK && hkdfObj->setAttribute(CKA_LOCAL, false);
		CK_ULONG hkdfGenMech = (CK_ULONG)CKM_HKDF_DERIVE;
		hkdfOK = hkdfOK && hkdfObj->setAttribute(CKA_KEY_GEN_MECHANISM, hkdfGenMech);
		bool hkdfAlwaysSens    = hkdfObj->getBooleanValue(CKA_SENSITIVE, false);
		hkdfOK = hkdfOK && hkdfObj->setAttribute(CKA_ALWAYS_SENSITIVE, hkdfAlwaysSens);
		bool hkdfNeverExtract  = !hkdfObj->getBooleanValue(CKA_EXTRACTABLE, false);
		hkdfOK = hkdfOK && hkdfObj->setAttribute(CKA_NEVER_EXTRACTABLE, hkdfNeverExtract);

		SymmetricKey hkdfSymKey;
		hkdfSymKey.setKeyBits(hkdfOut);
		hkdfSymKey.setBitLen(hkdfKeyLen * 8);
		ByteString hkdfValue;
		if (hkdfPrivate)
			// Fold the bool result in: a token->encrypt() failure wipes
			// hkdfValue without throwing; committing it would corrupt the key.
			hkdfOK = hkdfOK && token->encrypt(hkdfSymKey.getKeyBits(), hkdfValue);
		else
			hkdfValue = hkdfSymKey.getKeyBits();
		hkdfOK = hkdfOK && hkdfObj->setAttribute(CKA_VALUE, hkdfValue);

		// PKCS#11 v3.2 §4.11: KCV mandatory regardless of creation path (incl. derive).
		if (hkdfCheckValue)
		{
			ByteString hkdfKcv = computeSecretKeyKCV(hkdfKeyType, hkdfSymKey.getKeyBits());
			if (hkdfKcv.size() == 3)
				hkdfOK = hkdfOK && hkdfObj->setAttribute(CKA_CHECK_VALUE, hkdfKcv);
		}

		if (hkdfOK)
			hkdfObj->commitTransaction();
		else
			hkdfObj->abortTransaction();

		if (!hkdfOK)
		{
			handleManager->destroyObject(*phKey);
			*phKey = CK_INVALID_HANDLE;
			return CKR_FUNCTION_FAILED;
		}
		return CKR_OK;
	}

	// Derive symmetric secret
	if (pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE ||
	    pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
	    pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY ||
	    pMechanism->mechanism == CKM_SHAKE_256_KEY_DERIVATION)
	{
		// Check key class and type
		CK_KEY_TYPE baseKeyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);
		if (key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA &&
		    baseKeyType != CKK_AES)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA &&
		    baseKeyType != CKK_AES)
			return CKR_KEY_TYPE_INCONSISTENT;

		return this->deriveSymmetric(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
	}

	return CKR_MECHANISM_INVALID;
}

CK_RV SoftHSM::generateGeneric
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t keyLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				keyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// CKA_VALUE_LEN must be specified
	if (keyLen == 0)
	{
		INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Check keyLen
	if (keyLen < 1 || keyLen > MAX_GENERIC_KEY_LEN_BYTES)
	{
		INFO_MSG("bad generic key length");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Generate the secret key
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;
	ByteString key;
	if (!rng->generateRandom(key, keyLen)) return CKR_GENERAL_ERROR;

        CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				keyAttribs[keyAttribsCount++] = pTemplate[i];
				break;
		}
	}

	if (rv == CKR_OK)
		rv = CreateObject(hSession, keyAttribs, keyAttribsCount, phKey, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_GENERIC_SECRET_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// Generic Secret Key Attributes
			ByteString value;
			ByteString kcv;
			SymmetricKey symKey;
			symKey.setKeyBits(key);
			symKey.setBitLen(keyLen);
			if (isPrivate)
			{
				// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
				// failure must abort the transaction, not commit empty key material.
				bOK = bOK && token->encrypt(symKey.getKeyBits(), value);
			}
			else
			{
				value = symKey.getKeyBits();
			}
			// KCV is always stored in clear — PKCS#11 v3.2 §4.10.2
			kcv = symKey.getKeyCheckValue();
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate an AES secret key
CK_RV SoftHSM::generateAES
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate,
	CK_MECHANISM_TYPE keyGenMech)
{
	*phKey = CK_INVALID_HANDLE;

	// ChaCha20 keys are CKK_CHACHA20 (PKCS#11 v3.2), 256-bit only. AES keys are
	// CKK_AES with 128/192/256-bit lengths. The two diverge only in key type,
	// CKA_KEY_GEN_MECHANISM, and the allowed length set (audit V-12).
	const bool isChaCha = (keyGenMech == CKM_CHACHA20_KEY_GEN);

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t keyLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				keyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	if (isChaCha)
	{
		// ChaCha20 keys are fixed 256-bit. CKA_VALUE_LEN is optional; default
		// to 32 bytes, but if supplied it must be exactly 32.
		if (keyLen == 0)
			keyLen = 32;
		if (keyLen != 32)
		{
			INFO_MSG("ChaCha20 keys must be 32 bytes");
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}
	else
	{
		// CKA_VALUE_LEN must be specified
		if (keyLen == 0)
		{
			INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
			return CKR_TEMPLATE_INCOMPLETE;
		}

		// keyLen must be 16, 24, or 32
		if (keyLen != AES_KEY_BYTES_128 && keyLen != AES_KEY_BYTES_192 && keyLen != AES_KEY_BYTES_256)
		{
			INFO_MSG("bad AES key length");
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	// Generate the secret key
	AESKey* key = new AESKey(keyLen * 8);
	SymmetricAlgorithm* aes = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (aes == NULL)
	{
		ERROR_MSG("Could not get SymmetricAlgorithm");
		delete key;
		return CKR_GENERAL_ERROR;
	}
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL)
	{
		ERROR_MSG("Could not get RNG");
		aes->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(aes);
		return CKR_GENERAL_ERROR;
	}
	if (!aes->generateKey(*key, rng))
	{
		ERROR_MSG("Could not generate AES secret key");
		aes->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(aes);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = isChaCha ? CKK_CHACHA20 : CKK_AES;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) 
        {
			rv = CKR_FUNCTION_FAILED;
		} 
        else if (osobject->startTransaction()) 
        {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)keyGenMech;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// AES Secret Key Attributes
			ByteString value;
			ByteString kcv;
			if (isPrivate)
			{
				// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
				// failure must abort the transaction, not commit empty key material.
				bOK = bOK && token->encrypt(key->getKeyBits(), value);
			}
			else
			{
				value = key->getKeyBits();
			}
			// KCV is always stored in clear — PKCS#11 v3.2 §4.10.2
			kcv = key->getKeyCheckValue();
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	aes->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(aes);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DES secret key

// Generate a DES2 secret key

// Generate a DES3 secret key

// Generate an RSA key pair
CK_RV SoftHSM::generateRSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate
)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: bitlen and public exponent
	size_t bitLen = 0;
	ByteString exponent("010001");
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_MODULUS_BITS:
				if (pPublicKeyTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_MODULUS_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				bitLen = *(CK_ULONG*)pPublicKeyTemplate[i].pValue;
				break;
			case CKA_PUBLIC_EXPONENT:
				exponent = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// CKA_MODULUS_BITS must be specified to be able to generate a key pair.
	if (bitLen == 0) {
		INFO_MSG("Missing CKA_MODULUS_BITS in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	RSAParameters p;
	p.setE(exponent);
	p.setBitLength(bitLen);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (rsa == NULL)
		return CKR_GENERAL_ERROR;
	if (!rsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return CKR_GENERAL_ERROR;
	}

	RSAPublicKey* pub = (RSAPublicKey*) kp->getPublicKey();
	RSAPrivateKey* priv = (RSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_RSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PUBLIC_EXPONENT:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// RSA Public Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				if (isPublicKeyPrivate)
				{
					// token->encrypt() returns false (wiping the output) on RNG/AES/
					// not-logged-in failure without throwing; fold into bOK so a failure
					// aborts the transaction instead of committing empty key material.
					bOK = bOK && token->encrypt(pub->getN(), modulus);
					bOK = bOK && token->encrypt(pub->getE(), publicExponent);
				}
				else
				{
					modulus = pub->getN();
					publicExponent = pub->getE();
				}
				bOK = bOK && osobject->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && osobject->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
				// CKA_CHECK_VALUE: SHA-256(modulus) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(modulus);
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}

				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString rsa_spki = spkiFromPkey(((OSSLRSAPublicKey*)pub)->getOSSLKey());
					if (rsa_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, rsa_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_RSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// RSA Private Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				ByteString privateExponent;
				ByteString prime1;
				ByteString prime2;
				ByteString exponent1;
				ByteString exponent2;
				ByteString coefficient;
				if (isPrivateKeyPrivate)
				{
					// token->encrypt() returns false (wiping the output) on RNG/AES/
					// not-logged-in failure without throwing; fold into bOK so a failure
					// aborts the transaction instead of committing empty key material.
					bOK = bOK && token->encrypt(priv->getN(), modulus);
					bOK = bOK && token->encrypt(priv->getE(), publicExponent);
					bOK = bOK && token->encrypt(priv->getD(), privateExponent);
					bOK = bOK && token->encrypt(priv->getP(), prime1);
					bOK = bOK && token->encrypt(priv->getQ(), prime2);
					bOK = bOK && token->encrypt(priv->getDP1(), exponent1);
					bOK = bOK && token->encrypt(priv->getDQ1(), exponent2);
					bOK = bOK && token->encrypt(priv->getPQ(), coefficient);
				}
				else
				{
					modulus = priv->getN();
					publicExponent = priv->getE();
					privateExponent = priv->getD();
					prime1 = priv->getP();
					prime2 = priv->getQ();
					exponent1 =  priv->getDP1();
					exponent2 = priv->getDQ1();
					coefficient = priv->getPQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && osobject->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
				bOK = bOK && osobject->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
				bOK = bOK && osobject->setAttribute(CKA_PRIME_1, prime1);
				bOK = bOK && osobject->setAttribute(CKA_PRIME_2, prime2);
				bOK = bOK && osobject->setAttribute(CKA_EXPONENT_1,exponent1);
				bOK = bOK && osobject->setAttribute(CKA_EXPONENT_2, exponent2);
				bOK = bOK && osobject->setAttribute(CKA_COEFFICIENT, coefficient);
				// CKA_CHECK_VALUE: SHA-256(modulus) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(modulus);
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}

				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString rsa_priv_spki = spkiFromPkey(((OSSLRSAPublicKey*)pub)->getOSSLKey());
					if (rsa_priv_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, rsa_priv_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(rsa, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}


CK_RV SoftHSM::generateEC
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	ECParameters p;
	p.setEC(params);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* ec = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ec == NULL) return CKR_GENERAL_ERROR;
	if (!ec->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);
		return CKR_GENERAL_ERROR;
	}

	ECPublicKey* pub = (ECPublicKey*) kp->getPublicKey();
	ECPrivateKey* priv = (ECPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_EC;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// EC Public Key Attributes
				ByteString point;
				if (isPublicKeyPrivate)
				{
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/
					// not-logged-in failure must abort, not commit empty key material.
					bOK = bOK && token->encrypt(pub->getQ(), point);
				}
				else
				{
					point = pub->getQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_POINT, point);
				// CKA_CHECK_VALUE: SHA-256(EC point) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(pub->getQ());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}

				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString ec_spki = spkiFromPkey(((OSSLECPublicKey*)pub)->getOSSLKey());
					if (ec_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, ec_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_EC;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// EC Private Key Attributes
				ByteString group;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(priv->getEC(), group);
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(priv->getD(), value);
				}
				else
				{
					group = priv->getEC();
					value = priv->getD();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_PARAMS, group);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
				// CKA_CHECK_VALUE: SHA-256(private scalar) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(priv->getD());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString ec_priv_spki = spkiFromPkey(((OSSLECPublicKey*)pub)->getOSSLKey());
					if (ec_priv_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, ec_priv_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(ec, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

// Generate an EDDSA key pair
CK_RV SoftHSM::generateED
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Determine the key type from the public key template (Edwards vs Montgomery)
	CK_KEY_TYPE edKeyType = CKK_EC_EDWARDS;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (pPublicKeyTemplate[i].type == CKA_KEY_TYPE)
		{
			edKeyType = *(CK_KEY_TYPE*)pPublicKeyTemplate[i].pValue;
			break;
		}
	}
	CK_ULONG edKeyGenMech = (edKeyType == CKK_EC_MONTGOMERY)
		? (CK_ULONG)CKM_EC_MONTGOMERY_KEY_PAIR_GEN
		: (CK_ULONG)CKM_EC_EDWARDS_KEY_PAIR_GEN;

	// Set the parameters
	ECParameters p;
	p.setEC(params);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* ec = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (ec == NULL) return CKR_GENERAL_ERROR;
	if (!ec->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);
		return CKR_GENERAL_ERROR;
	}

	EDPublicKey* pub = (EDPublicKey*) kp->getPublicKey();
	EDPrivateKey* priv = (EDPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = edKeyType;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,edKeyGenMech);

				// EDDSA / Montgomery Public Key Attributes
				ByteString value;
				if (isPublicKeyPrivate)
				{
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(pub->getA(), value);
				}
				else
				{
					value = pub->getA();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_POINT, value);
				// CKA_CHECK_VALUE: SHA-256(public point) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(pub->getA());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString ed_spki = spkiFromPkey(((OSSLEDPublicKey*)pub)->getOSSLKey());
					if (ed_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, ed_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = edKeyType;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,edKeyGenMech);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// EDDSA / Montgomery Private Key Attributes
				ByteString group;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(priv->getEC(), group);
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(priv->getK(), value);
				}
				else
				{
					group = priv->getEC();
					value = priv->getK();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_PARAMS, group);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
				// CKA_CHECK_VALUE: SHA-256(private scalar) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(priv->getK());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString ed_priv_spki = spkiFromPkey(((OSSLEDPublicKey*)pub)->getOSSLKey());
					if (ed_priv_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, ed_priv_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(ec, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

// Generate an ML-DSA key pair (FIPS 204, PKCS#11 v3.2)

CK_RV SoftHSM::generateMLDSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: CKA_PARAMETER_SET selects the ML-DSA variant.
	// Mandatory per spec — no silent default (audit V-3).
	CK_ULONG parameterSet = 0;
	{
		CK_RV psrv = extractParameterSet(pPublicKeyTemplate, ulPublicKeyAttributeCount,
		                                 CKP_ML_DSA_44, CKP_ML_DSA_87, parameterSet);
		if (psrv != CKR_OK) return psrv;
	}

	// Optional deterministic-keygen seed (FIPS 204 xi, 32 bytes), supplied on
	// the private-key template. Absent → random keygen; present-but-wrong-len
	// → CKR_ATTRIBUTE_VALUE_INVALID (audit CKA_SEED gap).
	ByteString seed;
	{
		CK_RV srv = extractSeed(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, 32, seed);
		if (srv != CKR_OK) return srv;
	}

	// E7 (2026-08-13). §6.67.4 lists CKA_SEED among the attributes
	// CKM_ML_DSA_KEY_PAIR_GEN CONTRIBUTES to the new private key, so it must be
	// present on a randomly generated key too — this engine only ever persisted
	// a caller-supplied one. FIPS 204 keygen is seed-derived anyway, so the
	// engine now draws xi itself and publishes it, which is what makes the
	// contribution real rather than nominal.
	bool seedContributed = false;
	if (seed.size() == 0)
	{
		RNG* seedRng = CryptoFactory::i()->getRNG();
		if (seedRng == NULL) return CKR_GENERAL_ERROR;
		if (!seedRng->generateRandom(seed, 32)) return CKR_GENERAL_ERROR;
		seedContributed = true;
	}

	// Set the parameters
	MLDSAParameters p;
	p.setParameterSet(parameterSet);
	p.setSeed(seed);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* mldsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
	if (mldsa == NULL) return CKR_GENERAL_ERROR;
	if (!mldsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate ML-DSA key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return CKR_GENERAL_ERROR;
	}

	MLDSAPublicKey* pub = (MLDSAPublicKey*) kp->getPublicKey();
	MLDSAPrivateKey* priv = (MLDSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_ML_DSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, publicKeyAttribs, publicKeyAttribsCount, phPublicKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_ML_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				// ML-DSA Public Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)pub->getParameterSet());
				ByteString pubValue;
				if (isPublicKeyPrivate)
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(pub->getValue(), pubValue);
				else
					pubValue = pub->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, pubValue);
				// CKA_CHECK_VALUE: SHA-256(plaintext) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(pub->getValue());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString mldsa_spki = spkiFromPkey(((OSSLMLDSAPublicKey*)pub)->getOSSLKey());
					if (mldsa_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, mldsa_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_ML_DSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PARAMETER_SET: // ck4: set directly after CreateObject
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, privateKeyAttribs, privateKeyAttribsCount, phPrivateKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_ML_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// ML-DSA Private Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)priv->getParameterSet());
				ByteString privValue;
				if (isPrivateKeyPrivate)
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(priv->getValue(), privValue);
				else
					privValue = priv->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, privValue);
				// CKA_CHECK_VALUE: SHA-256(plaintext) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(priv->getValue());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// E7: publish the mechanism's CKA_SEED contribution. Stored
				// exactly like CKA_VALUE — encrypted at rest on a private
				// object, matching P11AttrSeed::updateAttr — and only when the
				// engine drew it, since a caller-supplied seed already reached
				// the object through the template.
				if (seedContributed)
				{
					ByteString seedValue;
					if (isPrivateKeyPrivate)
						bOK = bOK && token->encrypt(seed, seedValue);
					else
						seedValue = seed;
					bOK = bOK && osobject->setAttribute(CKA_SEED, seedValue);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString mldsa_priv_spki = spkiFromPkey(((OSSLMLDSAPublicKey*)pub)->getOSSLKey());
					if (mldsa_priv_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, mldsa_priv_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(mldsa, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

// Generate an SLH-DSA key pair (FIPS 205, PKCS#11 v3.2)

CK_RV SoftHSM::generateSLHDSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: CKA_PARAMETER_SET selects the SLH-DSA variant.
	// Mandatory per spec — no silent default (audit V-3).
	CK_ULONG parameterSet = 0;
	{
		CK_RV psrv = extractParameterSet(pPublicKeyTemplate, ulPublicKeyAttributeCount,
		                                 CKP_SLH_DSA_SHA2_128S, CKP_SLH_DSA_SHAKE_256F, parameterSet);
		if (psrv != CKR_OK) return psrv;
	}

	// Optional deterministic-keygen seed (FIPS 205 SK.seed||SK.prf||PK.seed,
	// 3n bytes), supplied on the private-key template. Absent → random keygen;
	// present-but-wrong-len → CKR_ATTRIBUTE_VALUE_INVALID.
	ByteString seed;
	{
		CK_RV srv = extractSeed(pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
		                        3 * slhdsaSeedN(parameterSet), seed);
		if (srv != CKR_OK) return srv;
	}

	// Set the parameters
	SLHDSAParameters p;
	p.setParameterSet(parameterSet);
	p.setSeed(seed);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* slhdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);
	if (slhdsa == NULL) return CKR_GENERAL_ERROR;
	if (!slhdsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate SLH-DSA key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
		return CKR_GENERAL_ERROR;
	}

	SLHDSAPublicKey* pub = (SLHDSAPublicKey*) kp->getPublicKey();
	SLHDSAPrivateKey* priv = (SLHDSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_SLH_DSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, publicKeyAttribs, publicKeyAttribsCount, phPublicKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_SLH_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				// SLH-DSA Public Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)pub->getParameterSet());
				ByteString pubValue;
				if (isPublicKeyPrivate)
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(pub->getValue(), pubValue);
				else
					pubValue = pub->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, pubValue);
				// CKA_CHECK_VALUE: SHA-256(plaintext) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(pub->getValue());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString slhdsa_spki = spkiFromPkey(((OSSLSLHDSAPublicKey*)pub)->getOSSLKey());
					if (slhdsa_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, slhdsa_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_SLH_DSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PARAMETER_SET: // ck4: set directly after CreateObject
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, privateKeyAttribs, privateKeyAttribsCount, phPrivateKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_SLH_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// SLH-DSA Private Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)priv->getParameterSet());
				ByteString privValue;
				if (isPrivateKeyPrivate)
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(priv->getValue(), privValue);
				else
					privValue = priv->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, privValue);
				// CKA_CHECK_VALUE: SHA-256(plaintext) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(priv->getValue());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString slhdsa_priv_spki = spkiFromPkey(((OSSLSLHDSAPublicKey*)pub)->getOSSLKey());
					if (slhdsa_priv_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, slhdsa_priv_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(slhdsa, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

// Generate a DH key pair

CK_RV SoftHSM::deriveECDH
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	if ((pMechanism->pParameter == NULL_PTR) ||
	    (pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)))
	{
		DEBUG_MSG("pParameter must be of type CK_ECDH1_DERIVE_PARAMS");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	// Accept CKD_NULL and ANSI X9.63 KDF variants; reject all others (PKCS#11 v3.2 §2.3.5 + §5.2.12)
	{
		CK_ULONG kdfCheck = CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf;
		if (kdfCheck != CKD_NULL && kdfCheck != CKD_SHA1_KDF &&
		    kdfCheck != CKD_SHA256_KDF && kdfCheck != CKD_SHA384_KDF &&
		    kdfCheck != CKD_SHA512_KDF &&
		    kdfCheck != CKD_SHA3_256_KDF && kdfCheck != CKD_SHA3_512_KDF)
		{
			DEBUG_MSG("Unsupported KDF type 0x%08lx", (unsigned long)kdfCheck);
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (kdfCheck == CKD_NULL &&
		    ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen != 0) ||
		     (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData != NULL_PTR)))
		{
			DEBUG_MSG("Shared data not allowed when kdf is CKD_NULL");
			return CKR_MECHANISM_PARAM_INVALID;
		}
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen == 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData == NULL_PTR))
	{
		DEBUG_MSG("there must be a public data");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length
	// byteLen == 0 impiles return max size the ECC can derive
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			break;
#ifndef WITH_FIPS
		case CKK_DES:
			if (byteLen != 0 && byteLen != 8)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0 or 8");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 8;
			break;
#endif
		case CKK_DES2:
			if (byteLen != 0 && byteLen != 16)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0 or 16");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 16;
			break;
		case CKK_DES3:
			if (byteLen != 0 && byteLen != 24)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0 or 24");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 24;
			break;
		case CKK_AES:
			if (byteLen != 0 && byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0, 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Get the base key handle (§2.4: scoped to this session's slot).
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey, session->getSlot()->getSlotID());
	if (baseKey == NULL || !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the ECDH algorithm handler
	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);
	if (ecdh == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = ecdh->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_HOST_MEMORY;
	}
	if (getECPrivateKey((ECPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		ecdh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_GENERAL_ERROR;
	}

	ByteString publicData;
	publicData.resize(CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	memcpy(&publicData[0],
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData,
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	PublicKey* publicKey = ecdh->newPublicKey();
	if (publicKey == NULL)
	{
		ecdh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_HOST_MEMORY;
	}
	if (getECDHPublicKey((ECPublicKey*)publicKey, (ECPrivateKey*)privateKey, publicData) != CKR_OK)
	{
		ecdh->recyclePrivateKey(privateKey);
		ecdh->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret (use cofactor mode when CKM_ECDH1_COFACTOR_DERIVE)
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (pMechanism->mechanism == CKM_ECDH1_COFACTOR_DERIVE)
	{
		if (!((OSSLECDH*)ecdh)->deriveKeyWithCofactor(&secret, publicKey, privateKey))
			rv = CKR_GENERAL_ERROR;
	}
	else
	{
		if (!ecdh->deriveKey(&secret, publicKey, privateKey))
			rv = CKR_GENERAL_ERROR;
	}
	ecdh->recyclePrivateKey(privateKey);
	ecdh->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false))
			{
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true))
			{
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString secretValue = secret->getKeyBits();
			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			// Apply ANSI X9.63 KDF if requested (PKCS#11 v3.2 §2.3.5)
			{
				CK_ULONG kdf = CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf;
				if (kdf != CKD_NULL)
				{
					const char* digestName = ckdToDigestName(kdf);
					if (digestName == nullptr)
					{
						DEBUG_MSG("ckdToDigestName: unknown KDF");
						bOK = false;
					}
					else
					{
						CK_BYTE_PTR  pSharedData   = CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData;
						CK_ULONG ulSharedDataLen   = CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen;
						size_t kdfOutLen           = (byteLen > 0) ? byteLen : secretValue.size();
						EVP_KDF* kdfAlgo = EVP_KDF_fetch(NULL, "X963KDF", NULL);
						if (kdfAlgo == NULL)
						{
							DEBUG_MSG("EVP_KDF_fetch X963KDF failed: 0x%08X", ERR_get_error());
							bOK = false;
						}
						else
						{
							EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdfAlgo);
							EVP_KDF_free(kdfAlgo);
							if (kctx == NULL)
							{
								DEBUG_MSG("EVP_KDF_CTX_new failed");
								bOK = false;
							}
							else
							{
								OSSL_PARAM kdfParams[4];
								int pi = 0;
								kdfParams[pi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
								                      const_cast<char*>(digestName), 0);
								kdfParams[pi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
								                      secretValue.byte_str(), secretValue.size());
								if (pSharedData != NULL_PTR && ulSharedDataLen > 0)
									kdfParams[pi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
									                      pSharedData, (size_t)ulSharedDataLen);
								kdfParams[pi] = OSSL_PARAM_construct_end();
								ByteString kdfOut;
								kdfOut.resize(kdfOutLen);
								if (EVP_KDF_derive(kctx, kdfOut.byte_str(), kdfOutLen, kdfParams) <= 0)
								{
									DEBUG_MSG("EVP_KDF_derive X963KDF failed: 0x%08X", ERR_get_error());
									bOK = false;
								}
								else
								{
									secretValue = kdfOut;
									checkValue  = false; // KCV not meaningful for KDF-derived keys
								}
								EVP_KDF_CTX_free(kctx);
							}
						}
					}
				}
			}

			// For generic and AES keys:
			// default to return max size available.
			if (byteLen == 0)
			{
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						byteLen = secretValue.size();
						break;
					case CKK_AES:
						if (secretValue.size() >= 32)
							byteLen = 32;
						else if (secretValue.size() >= 24)
							byteLen = 24;
						else
							byteLen = 16;
				}
			}

			if (byteLen > secretValue.size())
			{
				INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the leading end
				if (byteLen < secretValue.size())
					secretValue.split(secretValue.size() - byteLen);

				// Fix the odd parity for DES
				if (keyType == CKK_DES ||
				    keyType == CKK_DES2 ||
				    keyType == CKK_DES3)
				{
					for (size_t i = 0; i < secretValue.size(); i++)
					{
						secretValue[i] = odd_parity[secretValue[i]];
					}
				}

				// Get the KCV
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}

				if (isPrivate)
				{
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(secretValue, value);
				}
				else
				{
					value = secretValue;
				}
				// KCV is always stored in clear — PKCS#11 v3.2 §4.10.2
				kcv = plainKCV;
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	ecdh->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}


// Generate a DSA key pair
#ifdef WITH_EDDSA
CK_RV SoftHSM::deriveEDDSA
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// PKCS#11 v3.2 §6.3.18, Table 79 ("ECDH with cofactor: Allowed Key
	// Types") restricts CKM_ECDH1_COFACTOR_DERIVE to CKK_EC — unlike plain
	// ECDH (§6.3.17, Table 78), which allows both CKK_EC and
	// CKK_EC_MONTGOMERY. This function is only ever reached for
	// CKK_EC_MONTGOMERY/CKK_EC_EDWARDS base keys (see the CKA_KEY_TYPE
	// dispatch in C_DeriveKey), so the cofactor variant is never valid here.
	if (pMechanism->mechanism == CKM_ECDH1_COFACTOR_DERIVE)
	{
		DEBUG_MSG("CKM_ECDH1_COFACTOR_DERIVE is not valid for CKK_EC_MONTGOMERY/CKK_EC_EDWARDS keys (PKCS#11 v3.2 Table 79)");
		return CKR_KEY_TYPE_INCONSISTENT;
	}

	if ((pMechanism->pParameter == NULL_PTR) ||
	    (pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)))
	{
		DEBUG_MSG("pParameter must be of type CK_ECDH1_DERIVE_PARAMS");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	// Accept CKD_NULL and ANSI X9.63 KDF variants; reject all others (PKCS#11 v3.2 §2.3.5 + §5.2.12)
	{
		CK_ULONG kdfCheck = CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf;
		if (kdfCheck != CKD_NULL && kdfCheck != CKD_SHA1_KDF &&
		    kdfCheck != CKD_SHA256_KDF && kdfCheck != CKD_SHA384_KDF &&
		    kdfCheck != CKD_SHA512_KDF &&
		    kdfCheck != CKD_SHA3_256_KDF && kdfCheck != CKD_SHA3_512_KDF)
		{
			DEBUG_MSG("Unsupported KDF type 0x%08lx", (unsigned long)kdfCheck);
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (kdfCheck == CKD_NULL &&
		    ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen != 0) ||
		     (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData != NULL_PTR)))
		{
			DEBUG_MSG("Shared data not allowed when kdf is CKD_NULL");
			return CKR_MECHANISM_PARAM_INVALID;
		}
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen == 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData == NULL_PTR))
	{
		DEBUG_MSG("there must be a public data");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length
	// byteLen == 0 impiles return max size the ECC can derive
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			break;
		case CKK_AES:
			if (byteLen != 0 && byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0, 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Get the base key handle (§2.4: scoped to this session's slot).
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey, session->getSlot()->getSlotID());
	if (baseKey == NULL || !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the EDDSA algorithm handler
	AsymmetricAlgorithm* eddsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (eddsa == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = eddsa->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_HOST_MEMORY;
	}
	if (getEDPrivateKey((EDPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		eddsa->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_GENERAL_ERROR;
	}

	ByteString publicData;
	publicData.resize(CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	memcpy(&publicData[0],
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData,
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	PublicKey* publicKey = eddsa->newPublicKey();
	if (publicKey == NULL)
	{
		eddsa->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_HOST_MEMORY;
	}
	if (getEDDHPublicKey((EDPublicKey*)publicKey, (EDPrivateKey*)privateKey, publicData) != CKR_OK)
	{
		eddsa->recyclePrivateKey(privateKey);
		eddsa->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (!eddsa->deriveKey(&secret, publicKey, privateKey))
		rv = CKR_GENERAL_ERROR;
	eddsa->recyclePrivateKey(privateKey);
	eddsa->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false))
			{
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true))
			{
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString secretValue = secret->getKeyBits();
			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			// Apply ANSI X9.63 KDF if requested (PKCS#11 v3.2 §2.3.5)
			{
				CK_ULONG kdf = CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf;
				if (kdf != CKD_NULL)
				{
					const char* digestName = ckdToDigestName(kdf);
					if (digestName == nullptr)
					{
						DEBUG_MSG("ckdToDigestName: unknown KDF");
						bOK = false;
					}
					else
					{
						CK_BYTE_PTR  pSharedData   = CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData;
						CK_ULONG ulSharedDataLen   = CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen;
						size_t kdfOutLen           = (byteLen > 0) ? byteLen : secretValue.size();
						EVP_KDF* kdfAlgo = EVP_KDF_fetch(NULL, "X963KDF", NULL);
						if (kdfAlgo == NULL)
						{
							DEBUG_MSG("EVP_KDF_fetch X963KDF failed: 0x%08X", ERR_get_error());
							bOK = false;
						}
						else
						{
							EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdfAlgo);
							EVP_KDF_free(kdfAlgo);
							if (kctx == NULL)
							{
								DEBUG_MSG("EVP_KDF_CTX_new failed");
								bOK = false;
							}
							else
							{
								OSSL_PARAM kdfParams[4];
								int pi = 0;
								kdfParams[pi++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
								                      const_cast<char*>(digestName), 0);
								kdfParams[pi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
								                      secretValue.byte_str(), secretValue.size());
								if (pSharedData != NULL_PTR && ulSharedDataLen > 0)
									kdfParams[pi++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
									                      pSharedData, (size_t)ulSharedDataLen);
								kdfParams[pi] = OSSL_PARAM_construct_end();
								ByteString kdfOut;
								kdfOut.resize(kdfOutLen);
								if (EVP_KDF_derive(kctx, kdfOut.byte_str(), kdfOutLen, kdfParams) <= 0)
								{
									DEBUG_MSG("EVP_KDF_derive X963KDF failed: 0x%08X", ERR_get_error());
									bOK = false;
								}
								else
								{
									secretValue = kdfOut;
									checkValue  = false; // KCV not meaningful for KDF-derived keys
								}
								EVP_KDF_CTX_free(kctx);
							}
						}
					}
				}
			}

			// For generic and AES keys:
			// default to return max size available.
			if (byteLen == 0)
			{
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						byteLen = secretValue.size();
						break;
					case CKK_AES:
						if (secretValue.size() >= 32)
							byteLen = 32;
						else if (secretValue.size() >= 24)
							byteLen = 24;
						else
							byteLen = 16;
				}
			}

			if (byteLen > secretValue.size())
			{
				INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the leading end
				if (byteLen < secretValue.size())
					secretValue.split(secretValue.size() - byteLen);

				// Get the KCV
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}

				if (isPrivate)
				{
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(secretValue, value);
				}
				else
				{
					value = secretValue;
				}
				// KCV is always stored in clear — PKCS#11 v3.2 §4.10.2
				kcv = plainKCV;
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	eddsa->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}
#endif

// Derive an symmetric secret
CK_RV SoftHSM::deriveSymmetric
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE_PTR phOtherKey = CK_INVALID_HANDLE;
	OSObject *otherKey = NULL_PTR;

	// Every mechanism handled here historically carried a parameter, so this
	// check was unconditional. SHAKE-256 KD legitimately has none — its only
	// input is the base key and CKA_VALUE_LEN — so it is exempt rather than
	// being made to pass an empty parameter it has no use for.
	if (pMechanism->pParameter == NULL_PTR &&
	    pMechanism->mechanism != CKM_SHAKE_256_KEY_DERIVATION)
	{
		DEBUG_MSG("pParameter must be supplied");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	ByteString data;

	if (pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA &&
		 pMechanism->ulParameterLen == sizeof(CK_KEY_DERIVATION_STRING_DATA))
	{
		CK_BYTE_PTR pData = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->pData;
		CK_ULONG ulLen = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->ulLen;
		if (ulLen == 0 || pData == NULL_PTR)
		{
			DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (ulLen % 16 != 0)
		{
			DEBUG_MSG("The data must be a multiple of 16 bytes long");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(ulLen);
		memcpy(&data[0],
		       pData,
		       ulLen);
	}
	else if ((pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA) &&
		 pMechanism->ulParameterLen == sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS))
	{
		CK_BYTE_PTR pData = CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->pData;
		CK_ULONG length = CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->length;
		if (length == 0 || pData == NULL_PTR)
		{
			DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (length % 16 != 0)
		{
			DEBUG_MSG("The data must be a multiple of 16 bytes long");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(length);
		memcpy(&data[0],
		       pData,
		       length);
	}
	else if ((pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA) &&
		 pMechanism->ulParameterLen == sizeof(CK_KEY_DERIVATION_STRING_DATA))
	{
		CK_BYTE_PTR pData = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->pData;
		CK_ULONG length = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->ulLen;
		if (length == 0 || pData == NULL_PTR)
		{
			DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(length);
		memcpy(&data[0],
		       pData,
               length);
	}
	else if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY &&
		 pMechanism->ulParameterLen == sizeof(CK_OBJECT_HANDLE))
	{
		phOtherKey = CK_OBJECT_HANDLE_PTR(pMechanism->pParameter);
		if (phOtherKey == CK_INVALID_HANDLE)
		{
			DEBUG_MSG("There must be handle in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		DEBUG_MSG("(0x%08X) Other key handle is (0x%08X)", phOtherKey, *phOtherKey);
	}
	else if (pMechanism->mechanism == CKM_SHAKE_256_KEY_DERIVATION)
	{
		// No parameter, and `data` stays empty — the XOF consumes the base key
		// value alone. The strict form (a non-NULL parameter is an error) is
		// enforced in the derivation branch itself, not here, so that a caller
		// passing junk gets a specific message rather than this generic one.
	}
	else
	{
		DEBUG_MSG("pParameter is invalid");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract another key
	if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY) {
		// Check the key handle (§2.4: scoped to this session's slot).
		otherKey = (OSObject *)handleManager->getObject(*phOtherKey, session->getSlot()->getSlotID());
		if (otherKey == NULL_PTR || !otherKey->isValid()) return CKR_OBJECT_HANDLE_INVALID;
		if (otherKey->getBooleanValue(CKA_PRIVATE, true)) {
			bool bOK = token->decrypt(otherKey->getByteStringValue(CKA_VALUE), data);
			if (!bOK) return CKR_GENERAL_ERROR;
		} else {
			data = otherKey->getByteStringValue(CKA_VALUE);
		}
	}

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length if it specified or a mechanism is not one of misc mechanisms
	if (byteLen > 0 || (pMechanism->mechanism != CKM_CONCATENATE_DATA_AND_BASE &&
			pMechanism->mechanism != CKM_CONCATENATE_BASE_AND_DATA &&
			pMechanism->mechanism != CKM_CONCATENATE_BASE_AND_KEY)) {
		switch (keyType) {
			case CKK_GENERIC_SECRET:
				if (byteLen == 0) {
					INFO_MSG("CKA_VALUE_LEN must be set");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				break;
			case CKK_AES:
				if (byteLen != 16 && byteLen != 24 && byteLen != 32) {
					INFO_MSG("CKA_VALUE_LEN must be 16, 24, or 32");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				break;
			default:
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	switch(pMechanism->mechanism) {
		case CKM_AES_ECB_ENCRYPT_DATA:
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
		case CKM_AES_CBC_ENCRYPT_DATA:
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			iv.resize(16);
			memcpy(&iv[0],
			       &(CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->iv[0]),
			       16);
			break;
	    case CKM_CONCATENATE_DATA_AND_BASE:
	    case CKM_CONCATENATE_BASE_AND_DATA:
	    case CKM_CONCATENATE_BASE_AND_KEY:
	    case CKM_SHAKE_256_KEY_DERIVATION:
	        break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Check the key handle (§2.4: scoped to this session's slot).
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey, session->getSlot()->getSlotID());
	if (baseKey == NULL_PTR || !baseKey->isValid()) return CKR_OBJECT_HANDLE_INVALID;

    // Get the data
    ByteString secretValue;

    // SHAKE-256 KD joins this branch rather than the cipher branch below: like
    // the concatenate family it works on the base key's raw value, it just
    // squeezes it through an XOF instead of appending to it.
    if (pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY ||
			pMechanism->mechanism == CKM_SHAKE_256_KEY_DERIVATION) {
        // Get the key data
        ByteString keydata;

        // Get the CKA_PRIVATE attribute, when the attribute is not present use default false
        bool isKeyPrivate = baseKey->getBooleanValue(CKA_PRIVATE, false);
        if (isKeyPrivate)
        {
            bool bOK = token->decrypt(baseKey->getByteStringValue(CKA_VALUE), keydata);
            if (!bOK) return CKR_GENERAL_ERROR;
        }
        else
        {
            keydata = baseKey->getByteStringValue(CKA_VALUE);
        }

        if (pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE) {
			secretValue += data;
			secretValue += keydata;
		} else if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
				pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY) {
			secretValue += keydata;
			secretValue += data;
		} else if (pMechanism->mechanism == CKM_SHAKE_256_KEY_DERIVATION) {
			// SHAKE-256 XOF over the base key value, squeezed to CKA_VALUE_LEN.
			//
			// Unlike the concatenate family this needs an explicit length: an
			// XOF has no natural digest size, so byteLen == 0 is a template
			// error rather than something to infer from the inputs.
			if (byteLen == 0) {
				INFO_MSG("CKM_SHAKE_256_KEY_DERIVATION requires CKA_VALUE_LEN");
				return CKR_TEMPLATE_INCOMPLETE;
			}
			// Any mechanism parameter is a caller mistake, not something to
			// quietly ignore — this KDF takes none.
			if (pMechanism->pParameter != NULL_PTR || pMechanism->ulParameterLen != 0) {
				INFO_MSG("CKM_SHAKE_256_KEY_DERIVATION takes no mechanism parameter");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			EVP_MD_CTX* xof = EVP_MD_CTX_new();
			if (xof == NULL) return CKR_HOST_MEMORY;

			std::vector<unsigned char> out(byteLen);
			// EVP_DigestFinalXOF, not EVP_DigestFinal_ex: the latter would
			// emit SHAKE-256's nominal 32-byte digest and silently ignore the
			// requested length, which for X-Wing's 96-byte expansion would
			// produce a short key that still looked like a success.
			if (EVP_DigestInit_ex(xof, EVP_shake256(), NULL) != 1 ||
			    EVP_DigestUpdate(xof, keydata.const_byte_str(), keydata.size()) != 1 ||
			    EVP_DigestFinalXOF(xof, out.data(), byteLen) != 1)
			{
				EVP_MD_CTX_free(xof);
				ERROR_MSG("SHAKE-256 key derivation failed");
				return CKR_FUNCTION_FAILED;
			}
			EVP_MD_CTX_free(xof);

			secretValue.resize(byteLen);
			memcpy(&secretValue[0], out.data(), byteLen);
			OPENSSL_cleanse(out.data(), out.size());
        } else {
        	return CKR_MECHANISM_INVALID;
        }

        // If the CKA_VALUE_LEN attribute is not present use computed size
        if (byteLen == 0) {
            byteLen = data.size() + keydata.size();
            CK_RV rv = checkKeyLength(keyType, byteLen);
            if (rv != CKR_OK) {
            	return rv;
            }
        }
	} else {
        SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
        if (cipher == NULL) return CKR_MECHANISM_INVALID;

        SymmetricKey* secretkey = new SymmetricKey();

        if (getSymmetricKey(secretkey, token, baseKey) != CKR_OK)
        {
            cipher->recycleKey(secretkey);
            CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
            return CKR_GENERAL_ERROR;
        }

        // adjust key bit length
        secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

        // Initialize encryption
        if (!cipher->encryptInit(secretkey, mode, iv, padding)) {
            cipher->recycleKey(secretkey);
            CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
            return CKR_MECHANISM_INVALID;
        }

        // Encrypt the data
        if (!cipher->encryptUpdate(data, secretValue)) {
            cipher->recycleKey(secretkey);
            CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
            return CKR_GENERAL_ERROR;
        }

        // Finalize encryption
        ByteString encryptedFinal;
        if (!cipher->encryptFinal(encryptedFinal)) {
            cipher->recycleKey(secretkey);
            CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
            return CKR_GENERAL_ERROR;
        }
        cipher->recycleKey(secretkey);
        CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
        secretValue += encryptedFinal;
    }

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	CK_RV rv = CKR_OK;
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY) {
				// [PKCS#11 v2.40, 2.31.3]
				// If either of the two original keys has its CKA_SENSITIVE attribute
				// set to CK_TRUE, so does the derived key.  If not, then the derived
				// key’s CKA_SENSITIVE attribute is set either from the supplied template
				// or from a default value.
				bool bSensitive = baseKey->getBooleanValue(CKA_SENSITIVE, true) ||
								  otherKey->getBooleanValue(CKA_SENSITIVE, true);
				if (bSensitive) {
					bOK = bOK && osobject->setAttribute(CKA_SENSITIVE, true);
				}
				// If either of the two original keys has its CKA_EXTRACTABLE attribute
				// set to CK_FALSE, so does the derived key.  If not, then the derived
				// key’s CKA_EXTRACTABLE attribute is set either from the supplied template
				// or from a default value.
				bool bExtractable = baseKey->getBooleanValue(CKA_EXTRACTABLE, true) &&
									otherKey->getBooleanValue(CKA_EXTRACTABLE, true);
				if (!bExtractable) {
					bOK = bOK && osobject->setAttribute(CKA_EXTRACTABLE, false);
				}
				// The derived key’s CKA_ALWAYS_SENSITIVE attribute is set to CK_TRUE
				// if and only if both of the original keys have their CKA_ALWAYS_SENSITIVE
				// attributes set to CK_TRUE.
				bool bAlwaysSensitive = baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false) &&
										otherKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				// The derived key’s CKA_NEVER_EXTRACTABLE attribute is set to CK_TRUE
				// if and only if both of the original keys have their CKA_NEVER_EXTRACTABLE
				// attributes set to CK_TRUE
				bool bNeverExtractable = baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, false) &&
										 otherKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bNeverExtractable);
			}
			else if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
				 pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE)
			{
				// [PKCS#11 v2.40, 2.31.4-2.31.7]
				// If the base key has its CKA_SENSITIVE attribute set to CK_TRUE, so does the derived key.
				// If not, then the derived key’s CKA_SENSITIVE attribute is set either from the supplied
				// template or from a default value.
				if (baseKey->getBooleanValue(CKA_SENSITIVE, true)) {
					bOK = bOK && osobject->setAttribute(CKA_SENSITIVE, true);
				}
				// If the base key has its CKA_EXTRACTABLE attribute set to CK_FALSE, so does the derived key.
				// If not, then the derived key’s CKA_EXTRACTABLE attribute is set either from the supplied
				// template or from a default value.
				if (!baseKey->getBooleanValue(CKA_EXTRACTABLE, false)) {
					bOK = bOK && osobject->setAttribute(CKA_EXTRACTABLE, false);
				}
				// The derived key’s CKA_ALWAYS_SENSITIVE attribute is set to CK_TRUE if and only
				// if the base key has its CKA_ALWAYS_SENSITIVE attribute set to CK_TRUE.
				bool bAlwaysSensitive = baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				// The derived key’s CKA_NEVER_EXTRACTABLE attribute is set to CK_TRUE if and only
				// if the base key has its CKA_NEVER_EXTRACTABLE attribute set to CK_TRUE.
				bool bNeverExtractable = baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, false);
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
			} else {
				if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false)) {
					bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
					bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				} else {
					bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
				}
				if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true)) {
					bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
					bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
				} else {
					bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);
				}
			}

			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			if (byteLen > secretValue.size())
			{
				INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the trailing end
				if (byteLen < secretValue.size())
					secretValue.resize(byteLen);

				// Get the KCV
				SymmetricKey* secret = new SymmetricKey();
				secret->setKeyBits(secretValue);
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}
				delete secret;

				if (isPrivate)
				{
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(secretValue, value);
				}
				else
				{
					value = secretValue;
				}
				// KCV is always stored in clear — PKCS#11 v3.2 §4.10.2
				kcv = plainKCV;
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}


CK_RV SoftHSM::getRSAPrivateKey(RSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_MODULUS), modulus);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PUBLIC_EXPONENT), publicExponent);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIVATE_EXPONENT), privateExponent);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME_1), prime1);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME_2), prime2);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EXPONENT_1), exponent1);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EXPONENT_2), exponent2);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_COEFFICIENT), coefficient);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key->getByteStringValue(CKA_MODULUS);
		publicExponent = key->getByteStringValue(CKA_PUBLIC_EXPONENT);
		privateExponent = key->getByteStringValue(CKA_PRIVATE_EXPONENT);
		prime1 = key->getByteStringValue(CKA_PRIME_1);
		prime2 = key->getByteStringValue(CKA_PRIME_2);
		exponent1 =  key->getByteStringValue(CKA_EXPONENT_1);
		exponent2 = key->getByteStringValue(CKA_EXPONENT_2);
		coefficient = key->getByteStringValue(CKA_COEFFICIENT);
	}

	privateKey->setN(modulus);
	privateKey->setE(publicExponent);
	privateKey->setD(privateExponent);
	privateKey->setP(prime1);
	privateKey->setQ(prime2);
	privateKey->setDP1(exponent1);
	privateKey->setDQ1(exponent2);
	privateKey->setPQ(coefficient);

	return CKR_OK;
}

CK_RV SoftHSM::getRSAPublicKey(RSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// RSA Public Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_MODULUS), modulus);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PUBLIC_EXPONENT), publicExponent);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key->getByteStringValue(CKA_MODULUS);
		publicExponent = key->getByteStringValue(CKA_PUBLIC_EXPONENT);
	}

	publicKey->setN(modulus);
	publicKey->setE(publicExponent);

	return CKR_OK;
}

CK_RV SoftHSM::getECPrivateKey(ECPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setEC(group);
	privateKey->setD(value);

	return CKR_OK;
}

CK_RV SoftHSM::getECPublicKey(ECPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Public Key Attributes
	ByteString group;
	ByteString point;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_POINT), point);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		point = key->getByteStringValue(CKA_EC_POINT);
	}

	publicKey->setEC(group);
	publicKey->setQ(point);

	return CKR_OK;
}

CK_RV SoftHSM::getEDPrivateKey(EDPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EDDSA Private Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setEC(group);
	privateKey->setK(value);

	return CKR_OK;
}

CK_RV SoftHSM::getEDPublicKey(EDPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Public Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_POINT), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_EC_POINT);
	}

	publicKey->setEC(group);
	publicKey->setA(value);

	return CKR_OK;
}



CK_RV SoftHSM::getMLDSAPrivateKey(MLDSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-DSA Private Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (PKCS#8 DER)
	CK_ULONG parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, CKK_VENDOR_DEFINED);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setParameterSet(parameterSet);
	privateKey->setValue(value);

	return CKR_OK;
}

CK_RV SoftHSM::getMLDSAPublicKey(MLDSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-DSA Public Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (raw pub key bytes)
	CK_ULONG parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, CKK_VENDOR_DEFINED);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	publicKey->setParameterSet(parameterSet);
	publicKey->setValue(value);

	return CKR_OK;
}

CK_RV SoftHSM::getSLHDSAPrivateKey(SLHDSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// SLH-DSA Private Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (PKCS#8 DER)
	CK_ULONG parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, CKK_VENDOR_DEFINED);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setParameterSet(parameterSet);
	privateKey->setValue(value);

	return CKR_OK;
}

CK_RV SoftHSM::getSLHDSAPublicKey(SLHDSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// SLH-DSA Public Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (raw pub key bytes)
	CK_ULONG parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, CKK_VENDOR_DEFINED);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	publicKey->setParameterSet(parameterSet);
	publicKey->setValue(value);

	return CKR_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-KEM (FIPS 203, PKCS#11 v3.2) — key helpers
// ─────────────────────────────────────────────────────────────────────────────


CK_RV SoftHSM::generateMLKEM
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: CKA_PARAMETER_SET selects the ML-KEM variant.
	// Mandatory per spec — no silent default (audit V-3).
	CK_ULONG parameterSet = 0;
	{
		CK_RV psrv = extractParameterSet(pPublicKeyTemplate, ulPublicKeyAttributeCount,
		                                 CKP_ML_KEM_512, CKP_ML_KEM_1024, parameterSet);
		if (psrv != CKR_OK) return psrv;
	}

	// Optional deterministic-keygen seed (FIPS 203 d||z, 64 bytes), supplied on
	// the private-key template. Absent → random keygen; present-but-wrong-len
	// → CKR_ATTRIBUTE_VALUE_INVALID.
	ByteString seed;
	{
		CK_RV srv = extractSeed(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, 64, seed);
		if (srv != CKR_OK) return srv;
	}

	// E7: §6.68.4 makes CKA_SEED (d||z, 64 bytes) a contribution of
	// CKM_ML_KEM_KEY_PAIR_GEN — see the ML-DSA path above.
	bool seedContributed = false;
	if (seed.size() == 0)
	{
		RNG* seedRng = CryptoFactory::i()->getRNG();
		if (seedRng == NULL) return CKR_GENERAL_ERROR;
		if (!seedRng->generateRandom(seed, 64)) return CKR_GENERAL_ERROR;
		seedContributed = true;
	}

	// Set the parameters
	MLKEMParameters p;
	p.setParameterSet(parameterSet);
	p.setSeed(seed);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* mlkem = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);
	if (mlkem == NULL) return CKR_GENERAL_ERROR;
	if (!mlkem->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate ML-KEM key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_GENERAL_ERROR;
	}

	MLKEMPublicKey* pub = (MLKEMPublicKey*) kp->getPublicKey();
	MLKEMPrivateKey* priv = (MLKEMPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_ML_KEM;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, publicKeyAttribs, publicKeyAttribsCount, phPublicKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_ML_KEM_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				// PKCS#11 v3.2: C_GenerateKeyPair sets CKA_ENCAPSULATE=true for public key
				bOK = bOK && osobject->setAttribute(CKA_ENCAPSULATE, true);

				// ML-KEM Public Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)pub->getParameterSet());
				ByteString pubValue;
				if (isPublicKeyPrivate)
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(pub->getValue(), pubValue);
				else
					pubValue = pub->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, pubValue);
				// CKA_CHECK_VALUE: SHA-256(plaintext) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(pub->getValue());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString mlkem_spki = spkiFromPkey(((OSSLMLKEMPublicKey*)pub)->getOSSLKey());
					if (mlkem_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, mlkem_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_ML_KEM;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PARAMETER_SET: // ck4: set directly after CreateObject
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, privateKeyAttribs, privateKeyAttribsCount, phPrivateKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_ML_KEM_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				// PKCS#11 v3.2: C_GenerateKeyPair sets CKA_DECAPSULATE=true for private key
				bOK = bOK && osobject->setAttribute(CKA_DECAPSULATE, true);

				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// ML-KEM Private Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)priv->getParameterSet());
				ByteString privValue;
				if (isPrivateKeyPrivate)
					// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
					// failure must abort the transaction, not commit empty key material.
					bOK = bOK && token->encrypt(priv->getValue(), privValue);
				else
					privValue = priv->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, privValue);
				// CKA_CHECK_VALUE: SHA-256(plaintext) → 3 bytes
				{
					ByteString kcv = computeAsymKCV(priv->getValue());
					// CKA_CHECK_VALUE stored in clear — not sensitive per PKCS#11 v3.2 §4.10.2
					bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);
				}
				// E7: publish the mechanism's CKA_SEED contribution (§6.68.4,
				// d||z). Stored exactly like CKA_VALUE — encrypted at rest on a
				// private object — and only when the engine drew it, since a
				// caller-supplied seed already reached the object via the template.
				if (seedContributed)
				{
					ByteString seedValue;
					if (isPrivateKeyPrivate)
						bOK = bOK && token->encrypt(seed, seedValue);
					else
						seedValue = seed;
					bOK = bOK && osobject->setAttribute(CKA_SEED, seedValue);
				}
				// PKCS#11 v3.2 §4.14 — CKA_PUBLIC_KEY_INFO: SubjectPublicKeyInfo DER (always public)
				{
					ByteString mlkem_priv_spki = spkiFromPkey(((OSSLMLKEMPublicKey*)pub)->getOSSLKey());
					if (mlkem_priv_spki.size() > 0)
						bOK = bOK && osobject->setAttribute(CKA_PUBLIC_KEY_INFO, mlkem_priv_spki);
				}

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(mlkem, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

CK_RV SoftHSM::getECDHPublicKey(ECPublicKey* publicKey, ECPrivateKey* privateKey, ByteString& pubData)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setEC(privateKey->getEC());

	// Set value
	ByteString data = getECDHPubData(pubData);
	publicKey->setQ(data);

	return CKR_OK;
}

CK_RV SoftHSM::getEDDHPublicKey(EDPublicKey* publicKey, EDPrivateKey* privateKey, ByteString& pubData)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setEC(privateKey->getEC());

	// Set value
	ByteString data = getECDHPubData(pubData);
	publicKey->setA(data);

	return CKR_OK;
}

// ECDH pubData can be in RAW or DER format.
// Need to convert RAW as SoftHSM uses DER.
ByteString SoftHSM::getECDHPubData(ByteString& pubData)
{
	size_t len = pubData.size();
	size_t controlOctets = 2;
	if (len == 32 || len == 56 || len == 65 || len == 97 || len == 133)
	{
		// Raw: Length matches the public key size of:
		// EDDSA: X25519, X448
		// ECDSA: P-256, P-384, or P-521
		controlOctets = 0;
	}
	else if (len < controlOctets || pubData[0] != 0x04)
	{
		// Raw: Too short or does not start with 0x04
		controlOctets = 0;
	}
	else if (pubData[1] < 0x80)
	{
		// Raw: Length octet does not match remaining data length
		if (pubData[1] != (len - controlOctets)) controlOctets = 0;
	}
	else
	{
		size_t lengthOctets = pubData[1] & 0x7F;
		controlOctets += lengthOctets;

		if (controlOctets >= len)
		{
			// Raw: Too short
			controlOctets = 0;
		}
		else
		{
			ByteString length(&pubData[2], lengthOctets);

			if (length.long_val() != (len - controlOctets))
			{
				// Raw: Length octets does not match remaining data length
				controlOctets = 0;
			}
		}
	}

	// DER format
	if (controlOctets != 0) return pubData;

	return DERUTIL::raw2Octet(pubData);
}



CK_RV SoftHSM::getSymmetricKey(SymmetricKey* skey, Token* token, OSObject* key)
{
	if (skey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	ByteString keybits;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), keybits))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		keybits = key->getByteStringValue(CKA_VALUE);
	}

	skey->setKeyBits(keybits);

	return CKR_OK;
}

bool SoftHSM::setRSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (rsa == NULL)
		return false;
	PrivateKey* priv = rsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		rsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return false;
	}
	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	bool bOK = true;
	if (isPrivate)
	{
		// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
		// failure must fail the load, not store empty key material under CKA_*.
		bOK = bOK && token->encrypt(((RSAPrivateKey*)priv)->getN(), modulus);
		bOK = bOK && token->encrypt(((RSAPrivateKey*)priv)->getE(), publicExponent);
		bOK = bOK && token->encrypt(((RSAPrivateKey*)priv)->getD(), privateExponent);
		bOK = bOK && token->encrypt(((RSAPrivateKey*)priv)->getP(), prime1);
		bOK = bOK && token->encrypt(((RSAPrivateKey*)priv)->getQ(), prime2);
		bOK = bOK && token->encrypt(((RSAPrivateKey*)priv)->getDP1(), exponent1);
		bOK = bOK && token->encrypt(((RSAPrivateKey*)priv)->getDQ1(), exponent2);
		bOK = bOK && token->encrypt(((RSAPrivateKey*)priv)->getPQ(), coefficient);
	}
	else
	{
		modulus = ((RSAPrivateKey*)priv)->getN();
		publicExponent = ((RSAPrivateKey*)priv)->getE();
		privateExponent = ((RSAPrivateKey*)priv)->getD();
		prime1 = ((RSAPrivateKey*)priv)->getP();
		prime2 = ((RSAPrivateKey*)priv)->getQ();
		exponent1 =  ((RSAPrivateKey*)priv)->getDP1();
		exponent2 = ((RSAPrivateKey*)priv)->getDQ1();
		coefficient = ((RSAPrivateKey*)priv)->getPQ();
	}
	bOK = bOK && key->setAttribute(CKA_MODULUS, modulus);
	bOK = bOK && key->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
	bOK = bOK && key->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
	bOK = bOK && key->setAttribute(CKA_PRIME_1, prime1);
	bOK = bOK && key->setAttribute(CKA_PRIME_2, prime2);
	bOK = bOK && key->setAttribute(CKA_EXPONENT_1,exponent1);
	bOK = bOK && key->setAttribute(CKA_EXPONENT_2, exponent2);
	bOK = bOK && key->setAttribute(CKA_COEFFICIENT, coefficient);

	rsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

	return bOK;
}



bool SoftHSM::setECPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	// Raw scalar path: hardware HSM flows (e.g. GSMA SUCI) wrap the raw 32-byte (P-256)
	// or 48-byte (P-384) private scalar directly under AES-KEY-WRAP / AES-GCM without a
	// PKCS#8 envelope.  Detect by size (never >48 for supported curves) and the absence
	// of a DER SEQUENCE header (0x30).  CKA_EC_PARAMS must be in the unwrap template and
	// is already stored on the object via C_CreateObject; only CKA_VALUE needs setting.
	bool isRawScalar = (ber.size() == 32 || ber.size() == 48) &&
	                   (ber.size() == 0 || ber.const_byte_str()[0] != 0x30);
	if (isRawScalar)
	{
		ByteString value;
		if (isPrivate)
		{
			// token->encrypt() returns false (output wiped) on RNG/AES/not-logged-in
			// failure; fail the load rather than store an empty CKA_VALUE.
			if (!token->encrypt(ber, value))
				return false;
		}
		else
			value = ber;
		return key->setAttribute(CKA_VALUE, value);
	}

	AsymmetricAlgorithm* ecc = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ecc == NULL)
		return false;
	PrivateKey* priv = ecc->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		ecc->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	bool bOK = true;
	if (isPrivate)
	{
		// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
		// failure must fail the load, not store empty key material under CKA_*.
		bOK = bOK && token->encrypt(((ECPrivateKey*)priv)->getEC(), group);
		bOK = bOK && token->encrypt(((ECPrivateKey*)priv)->getD(), value);
	}
	else
	{
		group = ((ECPrivateKey*)priv)->getEC();
		value = ((ECPrivateKey*)priv)->getD();
	}
	bOK = bOK && key->setAttribute(CKA_EC_PARAMS, group);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	ecc->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);

	return bOK;
}

bool SoftHSM::setEDPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* ecc = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (ecc == NULL)
		return false;
	PrivateKey* priv = ecc->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		ecc->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	bool bOK = true;
	if (isPrivate)
	{
		// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
		// failure must fail the load, not store empty key material under CKA_*.
		bOK = bOK && token->encrypt(((EDPrivateKey*)priv)->getEC(), group);
		bOK = bOK && token->encrypt(((EDPrivateKey*)priv)->getK(), value);
	}
	else
	{
		group = ((EDPrivateKey*)priv)->getEC();
		value = ((EDPrivateKey*)priv)->getK();
	}
	bOK = bOK && key->setAttribute(CKA_EC_PARAMS, group);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	ecc->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);

	return bOK;
}


CK_RV SoftHSM::MechParamCheckRSAPKCSOAEP(CK_MECHANISM_PTR pMechanism)
{
	// This is a programming error
	if (pMechanism->mechanism != CKM_RSA_PKCS_OAEP) {
		ERROR_MSG("MechParamCheckRSAPKCSOAEP called on wrong mechanism");
		return CKR_GENERAL_ERROR;
	}

	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
	{
		ERROR_MSG("pParameter must be of type CK_RSA_PKCS_OAEP_PARAMS");
		return CKR_ARGUMENTS_BAD;
	}

	CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;

	// Validate hash algorithm and matching MGF
	bool validCombo = false;
	if (params->hashAlg == CKM_SHA_1    && params->mgf == CKG_MGF1_SHA1)    validCombo = true;
	if (params->hashAlg == CKM_SHA224   && params->mgf == CKG_MGF1_SHA224)  validCombo = true;
	if (params->hashAlg == CKM_SHA256   && params->mgf == CKG_MGF1_SHA256)  validCombo = true;
	if (params->hashAlg == CKM_SHA384   && params->mgf == CKG_MGF1_SHA384)  validCombo = true;
	if (params->hashAlg == CKM_SHA512   && params->mgf == CKG_MGF1_SHA512)  validCombo = true;
	if (!validCombo)
	{
		ERROR_MSG("Invalid hashAlg/mgf combination for RSA-OAEP");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->source != CKZ_DATA_SPECIFIED)
	{
		ERROR_MSG("source must be CKZ_DATA_SPECIFIED");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pSourceData != NULL)
	{
		ERROR_MSG("pSourceData must be NULL");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->ulSourceDataLen != 0)
	{
		ERROR_MSG("ulSourceDataLen must be 0");
		return CKR_ARGUMENTS_BAD;
	}
	return CKR_OK;
}


CK_RV SoftHSM::MechParamCheckRSAAESKEYWRAP(CK_MECHANISM_PTR pMechanism)
{
	// This is a programming error
	if (pMechanism->mechanism != CKM_RSA_AES_KEY_WRAP) {
		ERROR_MSG("MechParamCheckRSAAESKEYWRAP called on wrong mechanism");
		return CKR_GENERAL_ERROR;
	}
	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_RSA_AES_KEY_WRAP_PARAMS))
	{
		ERROR_MSG("pParameter must be of type CK_RSA_AES_KEY_WRAP_PARAMS");
		return CKR_ARGUMENTS_BAD;
	}

	CK_RSA_AES_KEY_WRAP_PARAMS_PTR params = (CK_RSA_AES_KEY_WRAP_PARAMS_PTR)pMechanism->pParameter;
	if (params->ulAESKeyBits != 128 && params->ulAESKeyBits != 192 && params->ulAESKeyBits != 256)
	{
		ERROR_MSG("length of the temporary AES key in bits can be only 128, 192 or 256");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams == NULL_PTR)
	{
		ERROR_MSG("pOAEPParams must be of type CK_RSA_PKCS_OAEP_PARAMS");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams->mgf < 1UL || params->pOAEPParams->mgf > 5UL)
	{
		ERROR_MSG("mgf not supported");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams->source != CKZ_DATA_SPECIFIED)
	{
		ERROR_MSG("source must be CKZ_DATA_SPECIFIED");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams->pSourceData != NULL)
	{
		ERROR_MSG("pSourceData must be NULL");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams->ulSourceDataLen != 0)
	{
		ERROR_MSG("ulSourceDataLen must be 0");
		return CKR_ARGUMENTS_BAD;
	}

	return CKR_OK;
}


