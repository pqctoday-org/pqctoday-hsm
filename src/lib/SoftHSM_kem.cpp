/*
 * Copyright (c) 2022 NLnet Labs
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
 SoftHSM_kem.cpp

 PKCS#11 v3.2 KEM operations: C_EncapsulateKey, C_DecapsulateKey.
 Also contains getMLKEMPrivateKey / getMLKEMPublicKey helpers.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "CryptoFactory.h"
#include "cryptoki.h"
#include "MLKEMPublicKey.h"
#include "MLKEMPrivateKey.h"
#include "MLKEMParameters.h"
#include "OSSLMLKEMPublicKey.h"
#include "OSSLMLKEMPrivateKey.h"
#include "OSSLMLKEM.h"
#include "P11Attributes.h"
#include "P11Objects.h"
// ECDH-as-KEM (2026-07-25 remediation) — CKM_ECDH1_DERIVE under
// C_EncapsulateKey/C_DecapsulateKey, PKCS#11 v3.2 §6.3.17 Table 78. Was
// previously CKR_MECHANISM_INVALID here (this file only ever accepted
// CKM_ML_KEM); needed so a caller can build the classical half of a hybrid
// KEM against this engine using only real, existing PKCS#11 mechanisms --
// there is no dedicated PKCS#11 "hybrid KEM" mechanism, in this engine or
// in the spec itself (draft-ietf-tls-ecdhe-mlkem groups are combined by
// the CALLER, via CKM_CONCATENATE_BASE_AND_KEY over two ordinary KEMs).
#include "ECParameters.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"

CK_RV SoftHSM::getMLKEMPrivateKey(MLKEMPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-KEM Private Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (PKCS#8 DER)
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

CK_RV SoftHSM::getMLKEMPublicKey(MLKEMPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-KEM Public Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (raw ek bytes)
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

// Generate an ML-KEM key pair (FIPS 203, PKCS#11 v3.2)

// ─────────────────────────────────────────────────────────────────────────────
// C_EncapsulateKey / C_DecapsulateKey  (PKCS#11 v3.2 §5.20)
// ─────────────────────────────────────────────────────────────────────────────

CK_RV SoftHSM::C_EncapsulateKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hPublicKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_BYTE_PTR pCiphertext,
	CK_ULONG_PTR pulCiphertextLen,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulCiphertextLen == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	if (pMechanism->mechanism == CKM_ECDH1_DERIVE)
		return this->encapsulateECDH(hSession, hPublicKey, pTemplate, ulAttributeCount, pCiphertext, pulCiphertextLen, phKey);

	// Only CKM_ML_KEM is supported (besides CKM_ECDH1_DERIVE above)
	if (pMechanism->mechanism != CKM_ML_KEM)
	{
		ERROR_MSG("C_EncapsulateKey: unsupported mechanism %lu", pMechanism->mechanism);
		return CKR_MECHANISM_INVALID;
	}

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Get the public key object
	// GAP 2.4: an invalid encapsulation (public) key handle is
	// CKR_KEY_HANDLE_INVALID per §5.18.8, not CKR_OBJECT_HANDLE_INVALID.
	OSObject* keyObj = (OSObject*)handleManager->getObject(hPublicKey, session->getSlot()->getSlotID());
	if (keyObj == NULL_PTR || !keyObj->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = keyObj->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = keyObj->getBooleanValue(CKA_PRIVATE, false);

	// Check user credentials
	CK_RV rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK) return rv;

	// Check capability
	if (!keyObj->getBooleanValue(CKA_ENCAPSULATE, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check key type
	if (keyObj->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PUBLIC_KEY ||
	    keyObj->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_ML_KEM)
		return CKR_KEY_TYPE_INCONSISTENT;

	// Load the ML-KEM algorithm
	AsymmetricAlgorithm* mlkem = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);
	if (mlkem == NULL) return CKR_MECHANISM_INVALID;

	// Reconstruct the public key
	PublicKey* publicKey = mlkem->newPublicKey();
	if (publicKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_HOST_MEMORY;
	}
	if (getMLKEMPublicKey((MLKEMPublicKey*)publicKey, token, keyObj) != CKR_OK)
	{
		mlkem->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_GENERAL_ERROR;
	}

	// Determine the expected ciphertext length from the parameter set
	MLKEMPublicKey* mlkemPub = (MLKEMPublicKey*)publicKey;
	CK_ULONG expectedCtLen = (CK_ULONG)mlkemPub->getCiphertextLength();

	// Size query: pCiphertext is NULL
	if (pCiphertext == NULL_PTR)
	{
		*pulCiphertextLen = expectedCtLen;
		mlkem->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_OK;
	}

	// Buffer size check
	if (*pulCiphertextLen < expectedCtLen)
	{
		*pulCiphertextLen = expectedCtLen;
		mlkem->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_BUFFER_TOO_SMALL;
	}

	// Perform encapsulation
	ByteString ciphertext;
	ByteString sharedSecret;
	if (!((OSSLMLKEM*)mlkem)->encapsulate(publicKey, ciphertext, sharedSecret))
	{
		mlkem->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_GENERAL_ERROR;
	}

	// Write ciphertext to caller's buffer
	memcpy(pCiphertext, ciphertext.const_byte_str(), ciphertext.size());
	*pulCiphertextLen = (CK_ULONG)ciphertext.size();

	mlkem->recyclePublicKey(publicKey);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);

	// Create the shared-secret key object from pTemplate
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	if (pTemplate == NULL_PTR && ulAttributeCount > 0)
		return CKR_ARGUMENTS_BAD;
	rv = extractObjectInformation(pTemplate, ulAttributeCount, objClass, keyType, dummy, isOnToken, isPrivate, true);
	if (rv != CKR_OK && rv != CKR_TEMPLATE_INCOMPLETE)
	{
		ERROR_MSG("C_EncapsulateKey: extractObjectInformation failed");
		return rv;
	}

	if (objClass != CKO_SECRET_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	// Check write authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK) return rv;

	// Build attribute list for the new secret key
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS,    &objClass,  sizeof(objClass)  },
		{ CKA_TOKEN,    &isOnToken, sizeof(isOnToken)  },
		{ CKA_PRIVATE,  &isPrivate, sizeof(isPrivate)  },
		{ CKA_KEY_TYPE, &keyType,   sizeof(keyType)    },
	};
	CK_ULONG secretAttribsCount = 4;

	if (ulAttributeCount > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < ulAttributeCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			// Already extracted by extractObjectInformation — skip, don't reject
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			// CKA_VALUE must not be caller-supplied for encapsulated keys
			case CKA_VALUE:
				return CKR_ATTRIBUTE_VALUE_INVALID;
			default:
				if (secretAttribsCount >= maxAttribs)
					return CKR_TEMPLATE_INCONSISTENT;
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);
	if (rv != CKR_OK) return rv;

	OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
	if (osobject == NULL_PTR || !osobject->isValid())
		return CKR_FUNCTION_FAILED;

	if (!osobject->startTransaction())
		return CKR_FUNCTION_FAILED;

	bool bOK = true;
	// PKCS#11 v3.2 §5.18.8: encapsulated keys are not locally generated
	bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);
	bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
	bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);

	// Store the shared secret as CKA_VALUE (encrypted if isPrivate)
	ByteString storedValue;
	if (isPrivate)
		// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
		// failure must abort, not commit an empty CKA_VALUE shared secret.
		bOK = bOK && token->encrypt(sharedSecret, storedValue);
	else
		storedValue = sharedSecret;
	bOK = bOK && osobject->setAttribute(CKA_VALUE, storedValue);
	sharedSecret.wipe();
	storedValue.wipe();

	if (bOK)
		bOK = osobject->commitTransaction();
	else
		osobject->abortTransaction();

	if (!bOK)
	{
		OSObject* osk = (OSObject*)handleManager->getObject(*phKey);
		handleManager->destroyObject(*phKey);
		if (osk) osk->destroyObject();
		*phKey = CK_INVALID_HANDLE;
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV SoftHSM::C_DecapsulateKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hPrivateKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_BYTE_PTR pCiphertext,
	CK_ULONG ulCiphertextLen,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pCiphertext == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulCiphertextLen == 0) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	if (pMechanism->mechanism == CKM_ECDH1_DERIVE)
		return this->decapsulateECDH(hSession, hPrivateKey, pTemplate, ulAttributeCount, pCiphertext, ulCiphertextLen, phKey);

	// Only CKM_ML_KEM is supported (besides CKM_ECDH1_DERIVE above)
	if (pMechanism->mechanism != CKM_ML_KEM)
	{
		ERROR_MSG("C_DecapsulateKey: unsupported mechanism %lu", pMechanism->mechanism);
		return CKR_MECHANISM_INVALID;
	}

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Get the private key object
	// GAP 2.4: an invalid decapsulation (private) key handle is
	// CKR_UNWRAPPING_KEY_HANDLE_INVALID per §5.18.9, not CKR_OBJECT_HANDLE_INVALID.
	OSObject* keyObj = (OSObject*)handleManager->getObject(hPrivateKey, session->getSlot()->getSlotID());
	if (keyObj == NULL_PTR || !keyObj->isValid()) return CKR_UNWRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = keyObj->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = keyObj->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	CK_RV rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK) return rv;

	// Check capability
	if (!keyObj->getBooleanValue(CKA_DECAPSULATE, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check key type
	if (keyObj->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY ||
	    keyObj->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_ML_KEM)
		return CKR_KEY_TYPE_INCONSISTENT;

	// Load the ML-KEM algorithm
	AsymmetricAlgorithm* mlkem = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);
	if (mlkem == NULL) return CKR_MECHANISM_INVALID;

	// Reconstruct the private key
	PrivateKey* privateKey = mlkem->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_HOST_MEMORY;
	}
	if (getMLKEMPrivateKey((MLKEMPrivateKey*)privateKey, token, keyObj) != CKR_OK)
	{
		mlkem->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_GENERAL_ERROR;
	}

	// Perform decapsulation
	ByteString ciphertext;
	ciphertext.resize(ulCiphertextLen);
	memcpy(&ciphertext[0], pCiphertext, ulCiphertextLen);

	ByteString sharedSecret;
	if (!((OSSLMLKEM*)mlkem)->decapsulate(privateKey, ciphertext, sharedSecret))
	{
		mlkem->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		if (ulCiphertextLen != 768 && ulCiphertextLen != 1088 && ulCiphertextLen != 1568)
			return CKR_WRAPPED_KEY_LEN_RANGE;
		return CKR_WRAPPED_KEY_INVALID;
	}

	mlkem->recyclePrivateKey(privateKey);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);

	// Create the shared-secret key object from pTemplate
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	if (pTemplate == NULL_PTR && ulAttributeCount > 0)
		return CKR_ARGUMENTS_BAD;
	rv = extractObjectInformation(pTemplate, ulAttributeCount, objClass, keyType, dummy, isOnToken, isPrivate, true);
	if (rv != CKR_OK && rv != CKR_TEMPLATE_INCOMPLETE)
	{
		ERROR_MSG("C_DecapsulateKey: extractObjectInformation failed");
		return rv;
	}

	if (objClass != CKO_SECRET_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	// Check write authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK) return rv;

	// Build attribute list for the new secret key
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS,    &objClass,  sizeof(objClass)  },
		{ CKA_TOKEN,    &isOnToken, sizeof(isOnToken)  },
		{ CKA_PRIVATE,  &isPrivate, sizeof(isPrivate)  },
		{ CKA_KEY_TYPE, &keyType,   sizeof(keyType)    },
	};
	CK_ULONG secretAttribsCount = 4;

	if (ulAttributeCount > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < ulAttributeCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			// Already extracted by extractObjectInformation — skip, don't reject
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			// CKA_VALUE must not be caller-supplied for decapsulated keys
			case CKA_VALUE:
				return CKR_ATTRIBUTE_VALUE_INVALID;
			default:
				if (secretAttribsCount >= maxAttribs)
					return CKR_TEMPLATE_INCONSISTENT;
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);
	if (rv != CKR_OK) return rv;

	OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
	if (osobject == NULL_PTR || !osobject->isValid())
		return CKR_FUNCTION_FAILED;

	if (!osobject->startTransaction())
		return CKR_FUNCTION_FAILED;

	bool bOK = true;
	// PKCS#11 v3.2 §5.18.9: decapsulated keys are not locally generated
	bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);
	bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
	bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);

	// Store the shared secret as CKA_VALUE (encrypted if isPrivate)
	ByteString storedValue;
	if (isPrivate)
		// Fold token->encrypt() into bOK: false (output wiped) on RNG/AES/not-logged-in
		// failure must abort, not commit an empty CKA_VALUE shared secret.
		bOK = bOK && token->encrypt(sharedSecret, storedValue);
	else
		storedValue = sharedSecret;
	bOK = bOK && osobject->setAttribute(CKA_VALUE, storedValue);
	sharedSecret.wipe();
	storedValue.wipe();

	if (bOK)
		bOK = osobject->commitTransaction();
	else
		osobject->abortTransaction();

	if (!bOK)
	{
		OSObject* osk = (OSObject*)handleManager->getObject(*phKey);
		handleManager->destroyObject(*phKey);
		if (osk) osk->destroyObject();
		*phKey = CK_INVALID_HANDLE;
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// ECDH-as-KEM (2026-07-25) — CKM_ECDH1_DERIVE under C_EncapsulateKey /
// C_DecapsulateKey (PKCS#11 v3.2 §6.3.17 Table 78: "When this mechanism is
// used in C_EncapsulateKey and C_DecapsulateKey ... an ephemeral key pair
// is generated"). Both CKK_EC and CKK_EC_MONTGOMERY are valid key types
// here (unlike CKM_ECDH1_COFACTOR_DERIVE's Table 79, which is CKK_EC only
// — see the 2026-07-25 cofactor fix elsewhere in this repo). No cofactor
// variant is offered here, matching CKM_ML_KEM's own C_EncapsulateKey,
// which likewise only ever exposed the non-cofactor mechanism.
// ─────────────────────────────────────────────────────────────────────────────

CK_RV SoftHSM::encapsulateECDH
(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hPublicKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_BYTE_PTR pCiphertext,
	CK_ULONG_PTR pulCiphertextLen,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Get the peer's public key object
	// GAP 2.4: an invalid encapsulation (public) key handle is
	// CKR_KEY_HANDLE_INVALID per §5.18.8, not CKR_OBJECT_HANDLE_INVALID.
	OSObject* keyObj = (OSObject*)handleManager->getObject(hPublicKey, session->getSlot()->getSlotID());
	if (keyObj == NULL_PTR || !keyObj->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = keyObj->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = keyObj->getBooleanValue(CKA_PRIVATE, false);

	CK_RV rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK) return rv;

	if (!keyObj->getBooleanValue(CKA_ENCAPSULATE, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	CK_ULONG peerKeyType = keyObj->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);
	if (keyObj->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PUBLIC_KEY ||
	    (peerKeyType != CKK_EC && peerKeyType != CKK_EC_MONTGOMERY))
		return CKR_KEY_TYPE_INCONSISTENT;

	// Peer's raw public point — PKCS#11 v3.2 Table 78 stores this under
	// CKA_EC_POINT for BOTH CKK_EC and CKK_EC_MONTGOMERY (confirmed against
	// this engine's own keygen code, which writes CKA_EC_POINT for both).
	ByteString peerPointRaw = keyObj->getByteStringValue(CKA_EC_POINT);
	ByteString peerPoint;
	if (isKeyPrivate)
	{
		if (!token->decrypt(peerPointRaw, peerPoint))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		peerPoint = peerPointRaw;
	}

	ByteString ecParams = keyObj->getByteStringValue(CKA_EC_PARAMS);
	if (ecParams.size() == 0)
		return CKR_KEY_TYPE_INCONSISTENT;

	ECParameters ecp;
	ecp.setEC(ecParams);

	bool isMontgomery = (peerKeyType == CKK_EC_MONTGOMERY);
	AsymAlgo::Type keygenAlgoType = isMontgomery ? AsymAlgo::EDDSA : AsymAlgo::ECDSA;
	AsymAlgo::Type deriveAlgoType = isMontgomery ? AsymAlgo::EDDSA : AsymAlgo::ECDH;

	// Generate the ephemeral key pair (§6.3.17: one fresh pair per encapsulation).
	AsymmetricAlgorithm* keygen = CryptoFactory::i()->getAsymmetricAlgorithm(keygenAlgoType);
	if (keygen == NULL) return CKR_GENERAL_ERROR;

	AsymmetricKeyPair* ephemeral = NULL;
	if (!keygen->generateKeyPair(&ephemeral, &ecp))
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(keygen);
		return CKR_GENERAL_ERROR;
	}

	AsymmetricAlgorithm* deriveEngine = CryptoFactory::i()->getAsymmetricAlgorithm(deriveAlgoType);
	if (deriveEngine == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(keygen);
		return CKR_GENERAL_ERROR;
	}

	ByteString ephemeralPoint;
	SymmetricKey* secret = NULL;
	bool ok = true;
	if (isMontgomery)
	{
		EDPrivateKey* ephPriv = (EDPrivateKey*)ephemeral->getPrivateKey();
		EDPublicKey* ephPub = (EDPublicKey*)ephemeral->getPublicKey();
		ephemeralPoint = ephPub->getA();
		PublicKey* peerPub = deriveEngine->newPublicKey();
		if (peerPub == NULL) ok = false;
		if (ok && getEDDHPublicKey((EDPublicKey*)peerPub, ephPriv, peerPoint) != CKR_OK) ok = false;
		if (ok && !deriveEngine->deriveKey(&secret, peerPub, ephPriv)) ok = false;
		if (peerPub) deriveEngine->recyclePublicKey(peerPub);
	}
	else
	{
		ECPrivateKey* ephPriv = (ECPrivateKey*)ephemeral->getPrivateKey();
		ECPublicKey* ephPub = (ECPublicKey*)ephemeral->getPublicKey();
		ephemeralPoint = ephPub->getQ();
		PublicKey* peerPub = deriveEngine->newPublicKey();
		if (peerPub == NULL) ok = false;
		if (ok && getECDHPublicKey((ECPublicKey*)peerPub, ephPriv, peerPoint) != CKR_OK) ok = false;
		if (ok && !deriveEngine->deriveKey(&secret, peerPub, ephPriv)) ok = false;
		if (peerPub) deriveEngine->recyclePublicKey(peerPub);
	}

	CryptoFactory::i()->recycleAsymmetricAlgorithm(keygen);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(deriveEngine);

	if (!ok || secret == NULL)
	{
		if (secret) delete secret;
		return CKR_GENERAL_ERROR;
	}

	CK_ULONG expectedCtLen = (CK_ULONG)ephemeralPoint.size();

	// Size query: pCiphertext is NULL
	if (pCiphertext == NULL_PTR)
	{
		*pulCiphertextLen = expectedCtLen;
		delete secret;
		return CKR_OK;
	}

	// Buffer size check
	if (*pulCiphertextLen < expectedCtLen)
	{
		*pulCiphertextLen = expectedCtLen;
		delete secret;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Write ciphertext (the ephemeral public key) to caller's buffer
	memcpy(pCiphertext, ephemeralPoint.const_byte_str(), ephemeralPoint.size());
	*pulCiphertextLen = expectedCtLen;

	ByteString sharedSecret = secret->getKeyBits();
	delete secret;

	// Create the shared-secret key object from pTemplate — identical shape
	// to the CKM_ML_KEM path above.
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	if (pTemplate == NULL_PTR && ulAttributeCount > 0)
		return CKR_ARGUMENTS_BAD;
	rv = extractObjectInformation(pTemplate, ulAttributeCount, objClass, keyType, dummy, isOnToken, isPrivate, true);
	if (rv != CKR_OK && rv != CKR_TEMPLATE_INCOMPLETE)
	{
		ERROR_MSG("encapsulateECDH: extractObjectInformation failed");
		return rv;
	}

	if (objClass != CKO_SECRET_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK) return rv;

	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS,    &objClass,  sizeof(objClass)  },
		{ CKA_TOKEN,    &isOnToken, sizeof(isOnToken)  },
		{ CKA_PRIVATE,  &isPrivate, sizeof(isPrivate)  },
		{ CKA_KEY_TYPE, &keyType,   sizeof(keyType)    },
	};
	CK_ULONG secretAttribsCount = 4;

	if (ulAttributeCount > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < ulAttributeCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			case CKA_VALUE:
				return CKR_ATTRIBUTE_VALUE_INVALID;
			default:
				if (secretAttribsCount >= maxAttribs)
					return CKR_TEMPLATE_INCONSISTENT;
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);
	if (rv != CKR_OK) return rv;

	OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
	if (osobject == NULL_PTR || !osobject->isValid())
		return CKR_FUNCTION_FAILED;

	if (!osobject->startTransaction())
		return CKR_FUNCTION_FAILED;

	bool bOK = true;
	// PKCS#11 v3.2 §5.18.8: encapsulated keys are not locally generated
	bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);
	bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
	bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);

	ByteString storedValue;
	if (isPrivate)
		bOK = bOK && token->encrypt(sharedSecret, storedValue);
	else
		storedValue = sharedSecret;
	bOK = bOK && osobject->setAttribute(CKA_VALUE, storedValue);
	sharedSecret.wipe();
	storedValue.wipe();

	if (bOK)
		bOK = osobject->commitTransaction();
	else
		osobject->abortTransaction();

	if (!bOK)
	{
		OSObject* osk = (OSObject*)handleManager->getObject(*phKey);
		handleManager->destroyObject(*phKey);
		if (osk) osk->destroyObject();
		*phKey = CK_INVALID_HANDLE;
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV SoftHSM::decapsulateECDH
(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hPrivateKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_BYTE_PTR pCiphertext,
	CK_ULONG ulCiphertextLen,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Get the private key object
	// GAP 2.4: an invalid decapsulation (private) key handle is
	// CKR_UNWRAPPING_KEY_HANDLE_INVALID per §5.18.9, not CKR_OBJECT_HANDLE_INVALID.
	OSObject* keyObj = (OSObject*)handleManager->getObject(hPrivateKey, session->getSlot()->getSlotID());
	if (keyObj == NULL_PTR || !keyObj->isValid()) return CKR_UNWRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = keyObj->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = keyObj->getBooleanValue(CKA_PRIVATE, true);

	CK_RV rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK) return rv;

	if (!keyObj->getBooleanValue(CKA_DECAPSULATE, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	CK_ULONG ourKeyType = keyObj->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);
	if (keyObj->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY ||
	    (ourKeyType != CKK_EC && ourKeyType != CKK_EC_MONTGOMERY))
		return CKR_KEY_TYPE_INCONSISTENT;

	bool isMontgomery = (ourKeyType == CKK_EC_MONTGOMERY);
	AsymAlgo::Type deriveAlgoType = isMontgomery ? AsymAlgo::EDDSA : AsymAlgo::ECDH;

	AsymmetricAlgorithm* deriveEngine = CryptoFactory::i()->getAsymmetricAlgorithm(deriveAlgoType);
	if (deriveEngine == NULL) return CKR_GENERAL_ERROR;

	ByteString peerPoint;
	peerPoint.resize(ulCiphertextLen);
	memcpy(&peerPoint[0], pCiphertext, ulCiphertextLen);

	SymmetricKey* secret = NULL;
	bool ok = true;
	if (isMontgomery)
	{
		EDPrivateKey* ourPriv = (EDPrivateKey*)deriveEngine->newPrivateKey();
		if (ourPriv == NULL) ok = false;
		if (ok && getEDPrivateKey(ourPriv, token, keyObj) != CKR_OK) ok = false;
		PublicKey* peerPub = NULL;
		if (ok)
		{
			peerPub = deriveEngine->newPublicKey();
			if (peerPub == NULL) ok = false;
		}
		if (ok && getEDDHPublicKey((EDPublicKey*)peerPub, ourPriv, peerPoint) != CKR_OK) ok = false;
		if (ok && !deriveEngine->deriveKey(&secret, peerPub, ourPriv)) ok = false;
		if (peerPub) deriveEngine->recyclePublicKey(peerPub);
		if (ourPriv) deriveEngine->recyclePrivateKey(ourPriv);
	}
	else
	{
		ECPrivateKey* ourPriv = (ECPrivateKey*)deriveEngine->newPrivateKey();
		if (ourPriv == NULL) ok = false;
		if (ok && getECPrivateKey(ourPriv, token, keyObj) != CKR_OK) ok = false;
		PublicKey* peerPub = NULL;
		if (ok)
		{
			peerPub = deriveEngine->newPublicKey();
			if (peerPub == NULL) ok = false;
		}
		if (ok && getECDHPublicKey((ECPublicKey*)peerPub, ourPriv, peerPoint) != CKR_OK) ok = false;
		if (ok && !deriveEngine->deriveKey(&secret, peerPub, ourPriv)) ok = false;
		if (peerPub) deriveEngine->recyclePublicKey(peerPub);
		if (ourPriv) deriveEngine->recyclePrivateKey(ourPriv);
	}

	CryptoFactory::i()->recycleAsymmetricAlgorithm(deriveEngine);

	if (!ok || secret == NULL)
	{
		if (secret) delete secret;
		return CKR_WRAPPED_KEY_INVALID;
	}

	ByteString sharedSecret = secret->getKeyBits();
	delete secret;

	// Create the shared-secret key object from pTemplate — identical shape
	// to the CKM_ML_KEM path above.
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	if (pTemplate == NULL_PTR && ulAttributeCount > 0)
		return CKR_ARGUMENTS_BAD;
	rv = extractObjectInformation(pTemplate, ulAttributeCount, objClass, keyType, dummy, isOnToken, isPrivate, true);
	if (rv != CKR_OK && rv != CKR_TEMPLATE_INCOMPLETE)
	{
		ERROR_MSG("decapsulateECDH: extractObjectInformation failed");
		return rv;
	}

	if (objClass != CKO_SECRET_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK) return rv;

	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS,    &objClass,  sizeof(objClass)  },
		{ CKA_TOKEN,    &isOnToken, sizeof(isOnToken)  },
		{ CKA_PRIVATE,  &isPrivate, sizeof(isPrivate)  },
		{ CKA_KEY_TYPE, &keyType,   sizeof(keyType)    },
	};
	CK_ULONG secretAttribsCount = 4;

	if (ulAttributeCount > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < ulAttributeCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			case CKA_VALUE:
				return CKR_ATTRIBUTE_VALUE_INVALID;
			default:
				if (secretAttribsCount >= maxAttribs)
					return CKR_TEMPLATE_INCONSISTENT;
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);
	if (rv != CKR_OK) return rv;

	OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
	if (osobject == NULL_PTR || !osobject->isValid())
		return CKR_FUNCTION_FAILED;

	if (!osobject->startTransaction())
		return CKR_FUNCTION_FAILED;

	bool bOK = true;
	// PKCS#11 v3.2 §5.18.9: decapsulated keys are not locally generated
	bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);
	bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
	bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);

	ByteString storedValue;
	if (isPrivate)
		bOK = bOK && token->encrypt(sharedSecret, storedValue);
	else
		storedValue = sharedSecret;
	bOK = bOK && osobject->setAttribute(CKA_VALUE, storedValue);
	sharedSecret.wipe();
	storedValue.wipe();

	if (bOK)
		bOK = osobject->commitTransaction();
	else
		osobject->abortTransaction();

	if (!bOK)
	{
		OSObject* osk = (OSObject*)handleManager->getObject(*phKey);
		handleManager->destroyObject(*phKey);
		if (osk) osk->destroyObject();
		*phKey = CK_INVALID_HANDLE;
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

