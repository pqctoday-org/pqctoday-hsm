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
 SoftHSM_cipher.cpp

 PKCS#11 encryption/decryption: SymEncryptInit, AsymEncryptInit, C_EncryptInit,
 C_Encrypt, C_EncryptUpdate, C_EncryptFinal, SymDecryptInit, AsymDecryptInit,
 C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "CryptoFactory.h"
#include "cryptoki.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "SymmetricAlgorithm.h"
#include "AESKey.h"

static bool isSymMechanism(CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL_PTR) return false;

	switch(pMechanism->mechanism) {
		case CKM_AES_ECB:
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
		case CKM_AES_CTR:
		case CKM_AES_XTS:
		case CKM_AES_GCM:
		case CKM_AES_OFB:
		case CKM_AES_CFB1:
		case CKM_AES_CFB8:
		case CKM_AES_CFB128:
		case CKM_AES_CCM:
		case CKM_CHACHA20_POLY1305:
		case CKM_CHACHA20:
			return true;
		default:
			return false;
	}
}

// Parse CK_CHACHA20_PARAMS into the 16-byte IV that OpenSSL's EVP_chacha20
// expects: counter (4 bytes, little-endian) || nonce (12 bytes). PKCS#11 v3.2
// §6.21 defines a 32-bit block counter and a 96-bit nonce for bare ChaCha20.
// Shared by SymEncryptInit and SymDecryptInit so both stay in lock-step.
static CK_RV parseChaCha20Params(CK_MECHANISM_PTR pMechanism, ByteString& iv)
{
	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_CHACHA20_PARAMS))
	{
		DEBUG_MSG("CKM_CHACHA20 requires CK_CHACHA20_PARAMS");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	CK_CHACHA20_PARAMS_PTR p = CK_CHACHA20_PARAMS_PTR(pMechanism->pParameter);

	// 32-bit block counter, 96-bit nonce — the only layout EVP_chacha20 accepts.
	if (p->blockCounterBits != 32 || p->ulNonceBits != 96)
	{
		DEBUG_MSG("CKM_CHACHA20 requires a 32-bit counter and 96-bit nonce");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if (p->pNonce == NULL_PTR)
	{
		DEBUG_MSG("CKM_CHACHA20 pNonce is NULL");
		return CKR_ARGUMENTS_BAD;
	}

	iv.resize(16);
	// Counter: 4 bytes. A NULL pBlockCounter means start at zero (per spec).
	if (p->pBlockCounter != NULL_PTR)
		memcpy(&iv[0], p->pBlockCounter, 4);
	else
		memset(&iv[0], 0, 4);
	memcpy(&iv[4], p->pNonce, 12);
	return CKR_OK;
}

// SymAlgorithm version of C_EncryptInit
CK_RV SoftHSM::SymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_ENCRYPT lets an Encrypt init pair with an already-active
	// Digest/Sign op for C_DigestEncryptUpdate / C_SignEncryptUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_ENCRYPT, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_ENCRYPT);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	size_t counterBits = 0;
	ByteString aad;
	size_t tagBytes = 0;
	size_t dataLen = 0;
	switch(pMechanism->mechanism) {
		case CKM_AES_ECB:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
		case CKM_AES_CBC:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("CBC mode requires a 16-byte init vector");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_CBC_PAD:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("CBC mode requires a 16-byte init vector");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_CTR:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CTR;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS))
			{
				DEBUG_MSG("CTR mode requires a counter block");
				return CKR_ARGUMENTS_BAD;
			}
			counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
			if (counterBits == 0 || counterBits > 128)
			{
				DEBUG_MSG("Invalid ulCounterBits");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
			break;
		case CKM_AES_OFB:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::OFB;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("OFB mode requires a 16-byte init vector");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_CFB1:
		case CKM_AES_CFB8:
		case CKM_AES_CFB128:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = pMechanism->mechanism == CKM_AES_CFB1 ? SymMode::CFB1
			     : pMechanism->mechanism == CKM_AES_CFB8 ? SymMode::CFB8
			     : SymMode::CFB128;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("CFB mode requires a 16-byte init vector");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_CCM:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CCM;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_CCM_PARAMS))
			{
				DEBUG_MSG("CCM mode requires CK_CCM_PARAMS");
				return CKR_ARGUMENTS_BAD;
			}
			{
				CK_CCM_PARAMS_PTR ccmp = CK_CCM_PARAMS_PTR(pMechanism->pParameter);
				// RFC 3610 / SP800-38C: nonce length N and tag length T are both
				// tied to L (the length-field size) via N = 15 - L, so OpenSSL
				// derives L directly from ulNonceLen once EVP_CTRL_CCM_SET_IVLEN
				// is called — the valid nonce range is 7..13 bytes (L = 2..8).
				if (ccmp->ulNonceLen < 7 || ccmp->ulNonceLen > 13)
				{
					DEBUG_MSG("CCM ulNonceLen must be 7..13 bytes");
					return CKR_MECHANISM_PARAM_INVALID;
				}
				if (ccmp->pNonce == NULL_PTR)
				{
					DEBUG_MSG("CCM pNonce is NULL");
					return CKR_ARGUMENTS_BAD;
				}
				if (ccmp->ulAADLen > 0 && ccmp->pAAD == NULL_PTR)
				{
					DEBUG_MSG("CCM pAAD is NULL with non-zero ulAADLen");
					return CKR_ARGUMENTS_BAD;
				}
				if (ccmp->ulMACLen != 4 && ccmp->ulMACLen != 6 && ccmp->ulMACLen != 8 &&
				    ccmp->ulMACLen != 10 && ccmp->ulMACLen != 12 && ccmp->ulMACLen != 14 &&
				    ccmp->ulMACLen != 16)
				{
					DEBUG_MSG("Invalid CCM ulMACLen");
					return CKR_MECHANISM_PARAM_INVALID;
				}
				iv.resize(ccmp->ulNonceLen);
				memcpy(&iv[0], ccmp->pNonce, ccmp->ulNonceLen);
				aad.resize(ccmp->ulAADLen);
				if (ccmp->ulAADLen > 0)
					memcpy(&aad[0], ccmp->pAAD, ccmp->ulAADLen);
				tagBytes = ccmp->ulMACLen;
				dataLen = ccmp->ulDataLen;
			}
			break;
		case CKM_AES_XTS:
			// PKCS#11 v3.2 §6.15.4: CKK_AES_XTS keys only (never plain CKK_AES).
			if (keyType != CKK_AES_XTS)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::XTS;
			// Single parameter: a 16-byte Data Unit Sequence Number (the tweak).
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("XTS mode requires a 16-byte Data Unit Sequence Number");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_GCM:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::GCM;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
			{
				DEBUG_MSG("GCM mode requires parameters");
				return CKR_ARGUMENTS_BAD;
			}
			// A zero-length IV would cause the OSSL layer to substitute a
			// fixed all-zero nonce, producing catastrophic nonce reuse. Reject
			// it here per the spec (ulIvLen >= 1).
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen == 0)
			{
				DEBUG_MSG("GCM ulIvLen is zero");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			// Validate embedded pointers before dereferencing
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen > 0 &&
			    CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv == NULL_PTR)
			{
				DEBUG_MSG("GCM pIv is NULL with non-zero ulIvLen");
				return CKR_ARGUMENTS_BAD;
			}
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0 &&
			    CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD == NULL_PTR)
			{
				DEBUG_MSG("GCM pAAD is NULL with non-zero ulAADLen");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen > 0)
				memcpy(&iv[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
			aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0)
				memcpy(&aad[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			tagBytes = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
			if (tagBytes > 128 || tagBytes % 8 != 0)
			{
				DEBUG_MSG("Invalid ulTagBits value");
				return CKR_ARGUMENTS_BAD;
			}
			tagBytes = tagBytes / 8;
			break;
		case CKM_CHACHA20_POLY1305:
			if (keyType != CKK_CHACHA20)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::CHACHA;
			mode = SymMode::CHACHA_POLY1305;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS))
			{
				DEBUG_MSG("CHACHA20_POLY1305 mode requires parameters");
				return CKR_ARGUMENTS_BAD;
			}
			// ChaCha20-Poly1305 requires a 96-bit (12-byte) nonce per RFC 7539.
			// A zero-length nonce would let the OSSL layer substitute a fixed
			// all-zero nonce (catastrophic reuse); enforce the exact length.
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen != 12)
			{
				DEBUG_MSG("CHACHA20_POLY1305 ulNonceLen must be 12 bytes");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen > 0 &&
			    CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->pNonce == NULL_PTR)
			{
				DEBUG_MSG("CHACHA20_POLY1305 pNonce is NULL with non-zero ulNonceLen");
				return CKR_ARGUMENTS_BAD;
			}
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0 &&
			    CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->pAAD == NULL_PTR)
			{
				DEBUG_MSG("CHACHA20_POLY1305 pAAD is NULL with non-zero ulAADLen");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen);
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen > 0)
				memcpy(&iv[0], CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->pNonce, CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen);
			aad.resize(CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0)
				memcpy(&aad[0], CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			tagBytes = 16;
			break;
		case CKM_CHACHA20:
			// Bare ChaCha20 stream cipher (audit V-10). Keys are CKK_CHACHA20,
			// the same key type generated by CKM_CHACHA20_KEY_GEN.
			if (keyType != CKK_CHACHA20)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::CHACHA;
			mode = SymMode::CHACHA;
			{
				CK_RV rvp = parseChaCha20Params(pMechanism, iv);
				if (rvp != CKR_OK) return rvp;
			}
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();

	if (getSymmetricKey(secretkey, token, key) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize encryption
	if (!cipher->encryptInit(secretkey, mode, iv, padding, counterBits, aad, tagBytes, dataLen))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_ENCRYPT);
	session->setSymmetricCryptoOp(cipher);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(secretkey);

	return CKR_OK;
}

// AsymAlgorithm version of C_EncryptInit
CK_RV SoftHSM::AsymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_ENCRYPT lets an Encrypt init pair with an already-active
	// Digest/Sign op for C_DigestEncryptUpdate / C_SignEncryptUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_ENCRYPT, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_ENCRYPT);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism;
	bool isRSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			mechanism = AsymMech::RSA_PKCS;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			mechanism = AsymMech::RSA;
			isRSA = true;
			break;
		case CKM_RSA_PKCS_OAEP:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			rv = MechParamCheckRSAPKCSOAEP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			{
				CK_RSA_PKCS_OAEP_PARAMS_PTR oaepP = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;
				switch (oaepP->hashAlg) {
					case CKM_SHA224:   mechanism = AsymMech::RSA_PKCS_OAEP_SHA224;   break;
					case CKM_SHA256:   mechanism = AsymMech::RSA_PKCS_OAEP_SHA256;   break;
					case CKM_SHA384:   mechanism = AsymMech::RSA_PKCS_OAEP_SHA384;   break;
					case CKM_SHA512:   mechanism = AsymMech::RSA_PKCS_OAEP_SHA512;   break;
					case CKM_SHA3_224: mechanism = AsymMech::RSA_PKCS_OAEP_SHA3_224; break;
					case CKM_SHA3_256: mechanism = AsymMech::RSA_PKCS_OAEP_SHA3_256; break;
					case CKM_SHA3_384: mechanism = AsymMech::RSA_PKCS_OAEP_SHA3_384; break;
					case CKM_SHA3_512: mechanism = AsymMech::RSA_PKCS_OAEP_SHA3_512; break;
					default:           mechanism = AsymMech::RSA_PKCS_OAEP;          break;
				}
			}
			isRSA = true;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PublicKey* publicKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		return CKR_MECHANISM_INVALID;
        }

	session->setOpType(SESSION_OP_ENCRYPT);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setPublicKey(publicKey);

	return CKR_OK;
}

// Initialise encryption using the specified object and mechanism
CK_RV SoftHSM::C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	// C2 (2026-08-13) — §5.8.1 and its siblings: "C_EncryptInit can be called with
	// pMechanism set to NULL_PTR to terminate an active encryption operation. If an
	// active operation ... cannot be cancelled, CKR_OPERATION_CANCEL_FAILED must
	// be returned." CKR_ARGUMENTS_BAD, which this used to answer, is neither of
	// the two permitted results. C_SessionCancel already implements the
	// per-family cancel semantics (and the initialisation and session-handle
	// checks that outrank this one), so the cancel form routes into it.
	if (pMechanism == NULL_PTR) return C_SessionCancel(hSession, CKF_ENCRYPT);

	if (isSymMechanism(pMechanism))
		return SymEncryptInit(hSession, pMechanism, hKey);
	else
		return AsymEncryptInit(hSession, pMechanism, hKey);
}

// SymAlgorithm version of C_Encrypt
static CK_RV SymEncrypt(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	// V-17: a one-shot C_Encrypt after C_EncryptUpdate must report CKR_OPERATION_ACTIVE
	// without destroying the multi-part op (the caller can still C_EncryptFinal).
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Check data size
	CK_ULONG maxSize = ulDataLen + cipher->getTagBytes();
	if (cipher->isBlockCipher())
	{
		CK_ULONG remainder = ulDataLen % cipher->getBlockSize();
		if (cipher->getPaddingMode() == false && remainder != 0)
		{
			session->resetOp();
			return CKR_DATA_LEN_RANGE;
		}

		// Round up to block size
		if (remainder != 0)
		{
			maxSize = ulDataLen + cipher->getBlockSize() - remainder;
		}
		else if (cipher->getPaddingMode() == true)
		{
			maxSize = ulDataLen + cipher->getBlockSize();
		}
	}
	if (!cipher->checkMaximumBytes(ulDataLen))
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}

	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulEncryptedDataLen < maxSize)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);
	ByteString encryptedData;

	// Encrypt the data
	if (!cipher->encryptUpdate(data, encryptedData))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Finalize encryption
	ByteString encryptedFinal;
	if (!cipher->encryptFinal(encryptedFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	encryptedData += encryptedFinal;
	encryptedData.resize(maxSize);

	memcpy(pEncryptedData, encryptedData.byte_str(), encryptedData.size());
	*pulEncryptedDataLen = encryptedData.size();

	session->resetOp();
	return CKR_OK;
}

// AsymAlgorithm version of C_Encrypt
static CK_RV AsymEncrypt(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	// V-17: a one-shot C_Encrypt after C_EncryptUpdate must report CKR_OPERATION_ACTIVE
	// without destroying the multi-part op (the caller can still C_EncryptFinal).
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Size of the encrypted data
	CK_ULONG size = publicKey->getOutputLength();

	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulEncryptedDataLen < size)
	{
		*pulEncryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data;
	ByteString encryptedData;

	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (mechanism == AsymMech::RSA) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);

	// Encrypt the data
	if (!asymCrypto->encrypt(publicKey,data,encryptedData,mechanism))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (encryptedData.size() != size)
	{
		ERROR_MSG("The size of the encrypted data differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pEncryptedData, encryptedData.byte_str(), size);
	*pulEncryptedDataLen = size;

	session->resetOp();
	return CKR_OK;
}

// Perform a single operation encryption operation in the specified session
CK_RV SoftHSM::C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((pData == NULL_PTR) || (pulEncryptedDataLen == NULL_PTR))
	{
		// Fix issue 585
		session->resetOp();

		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymEncrypt(session, pData, ulDataLen,
				  pEncryptedData, pulEncryptedDataLen);
	else
		return AsymEncrypt(session, pData, ulDataLen,
				   pEncryptedData, pulEncryptedDataLen);
}

// SymAlgorithm version of C_EncryptUpdate. Shared with the §5.13 dual-function
// updates via SoftHSM::symEncryptUpdateRaw — it inspects only the symmetric
// cipher context, never the session op type.
CK_RV SoftHSM::symEncryptUpdateRaw(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	size_t blockSize = cipher->getBlockSize();
	size_t remainingSize = cipher->getBufferSize();
	// Guard against integer overflow before adding ulDataLen + remainingSize.
	if (ulDataLen > (~(CK_ULONG)0 - (CK_ULONG)remainingSize))
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}
	CK_ULONG maxSize = ulDataLen + (CK_ULONG)remainingSize;
	if (cipher->isBlockCipher())
	{
		CK_ULONG nrOfBlocks = (ulDataLen + (CK_ULONG)remainingSize) / (CK_ULONG)blockSize;
		maxSize = nrOfBlocks * (CK_ULONG)blockSize;
	}
	if (!cipher->checkMaximumBytes(ulDataLen))
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}

	// Check data size
	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulEncryptedDataLen < maxSize)
	{
		DEBUG_MSG("ulDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x",
			  ulDataLen, *pulEncryptedDataLen, blockSize, remainingSize, maxSize);
		*pulEncryptedDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);
	ByteString encryptedData;

	// Encrypt the data
	if (!cipher->encryptUpdate(data, encryptedData))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	DEBUG_MSG("ulDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x  encryptedData.size(): %#5x",
		  ulDataLen, *pulEncryptedDataLen, blockSize, remainingSize, maxSize, encryptedData.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulEncryptedDataLen < encryptedData.size())
	{
		session->resetOp();
		ERROR_MSG("EncryptUpdate returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
			  *pulEncryptedDataLen, encryptedData.size());
		return CKR_GENERAL_ERROR;
	}

	if (encryptedData.size() > 0)
	{
		memcpy(pEncryptedData, encryptedData.byte_str(), encryptedData.size());
	}
	*pulEncryptedDataLen = encryptedData.size();

	// V-17: a multi-part op is now in progress; a subsequent one-shot C_Encrypt
	// must be rejected with CKR_OPERATION_ACTIVE rather than silently allowed.
	session->setAllowSinglePartOp(false);

	return CKR_OK;
}

// Feed data to the running encryption operation in a session
CK_RV SoftHSM::C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((pData == NULL_PTR) || (pulEncryptedDataLen == NULL_PTR))
	{
		session->resetOp();

		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return symEncryptUpdateRaw(session, pData, ulDataLen,
				  pEncryptedData, pulEncryptedDataLen);
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
}

// SymAlgorithm version of C_EncryptFinal
static CK_RV SymEncryptFinal(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	size_t remainingSize = cipher->getBufferSize() + cipher->getTagBytes();
	CK_ULONG size = remainingSize;
	if (cipher->isBlockCipher())
	{
		size_t blockSize = cipher->getBlockSize();
		bool isPadding = cipher->getPaddingMode();
		if ((remainingSize % blockSize) != 0 && !isPadding)
		{
			session->resetOp();
			DEBUG_MSG("Remaining buffer size is not an integral of the block size. Block size: %#2x  Remaining size: %#2x",
				  blockSize, remainingSize);
			return CKR_DATA_LEN_RANGE;
		}
		// when padding: an integral of the block size that is longer than the remaining data.
		size = isPadding ? ((remainingSize + blockSize) / blockSize) * blockSize : remainingSize;
	}

	// Give required output buffer size.
	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = size;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulEncryptedDataLen < size)
	{
		DEBUG_MSG("output buffer size: %#5x  size: %#5x",
			  *pulEncryptedDataLen, size);
		*pulEncryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Finalize encryption
	ByteString encryptedFinal;
	if (!cipher->encryptFinal(encryptedFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	DEBUG_MSG("output buffer size: %#2x  size: %#2x  encryptedFinal.size(): %#2x",
		  *pulEncryptedDataLen, size, encryptedFinal.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulEncryptedDataLen < encryptedFinal.size())
	{
		session->resetOp();
		ERROR_MSG("EncryptFinal returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
			  *pulEncryptedDataLen, encryptedFinal.size());
		return CKR_GENERAL_ERROR;
	}

	if (encryptedFinal.size() > 0)
	{
		memcpy(pEncryptedData, encryptedFinal.byte_str(), encryptedFinal.size());
	}
	*pulEncryptedDataLen = encryptedFinal.size();

	// Release only the encrypt half; a dual digest/sign partner (if any) survives.
	session->endOpFamily(SESSION_OP_ENCRYPT);
	return CKR_OK;
}

// Finalise the encryption operation
CK_RV SoftHSM::C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Github issue #469, check NULL_PTR on pulEncryptedDataLen
	if (pulEncryptedDataLen == NULL)
	{
		session->resetOp();
		return CKR_ARGUMENTS_BAD;
	}

	// Accept a standalone encrypt op or the encrypt half of a §5.13 dual-function
	// op (a digest/sign partner may have been finalised first, leaving op no
	// longer == SESSION_OP_ENCRYPT while the cipher context is still live).
	if (session->getOpType() != SESSION_OP_ENCRYPT && session->getSymmetricCryptoOp() == NULL)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymEncryptFinal(session, pEncryptedData, pulEncryptedDataLen);
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
}

// SymAlgorithm version of C_DecryptInit
CK_RV SoftHSM::SymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_DECRYPT lets a Decrypt init pair with an already-active
	// Digest/Verify op for C_DecryptDigestUpdate / C_DecryptVerifyUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_DECRYPT, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_DECRYPT);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	size_t counterBits = 0;
	ByteString aad;
	size_t tagBytes = 0;
	size_t dataLen = 0;
	switch(pMechanism->mechanism) {
		case CKM_AES_ECB:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
		case CKM_AES_CBC:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("CBC mode requires a 16-byte init vector");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_CBC_PAD:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("CBC mode requires a 16-byte init vector");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_CTR:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CTR;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS))
			{
				DEBUG_MSG("CTR mode requires a counter block");
				return CKR_ARGUMENTS_BAD;
			}
			counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
			if (counterBits == 0 || counterBits > 128)
			{
				DEBUG_MSG("Invalid ulCounterBits");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
			break;
		case CKM_AES_OFB:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::OFB;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("OFB mode requires a 16-byte init vector");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_CFB1:
		case CKM_AES_CFB8:
		case CKM_AES_CFB128:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = pMechanism->mechanism == CKM_AES_CFB1 ? SymMode::CFB1
			     : pMechanism->mechanism == CKM_AES_CFB8 ? SymMode::CFB8
			     : SymMode::CFB128;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("CFB mode requires a 16-byte init vector");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_CCM:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CCM;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_CCM_PARAMS))
			{
				DEBUG_MSG("CCM mode requires CK_CCM_PARAMS");
				return CKR_ARGUMENTS_BAD;
			}
			{
				CK_CCM_PARAMS_PTR ccmp = CK_CCM_PARAMS_PTR(pMechanism->pParameter);
				// RFC 3610 / SP800-38C: nonce length N and tag length T are both
				// tied to L (the length-field size) via N = 15 - L, so OpenSSL
				// derives L directly from ulNonceLen once EVP_CTRL_CCM_SET_IVLEN
				// is called — the valid nonce range is 7..13 bytes (L = 2..8).
				if (ccmp->ulNonceLen < 7 || ccmp->ulNonceLen > 13)
				{
					DEBUG_MSG("CCM ulNonceLen must be 7..13 bytes");
					return CKR_MECHANISM_PARAM_INVALID;
				}
				if (ccmp->pNonce == NULL_PTR)
				{
					DEBUG_MSG("CCM pNonce is NULL");
					return CKR_ARGUMENTS_BAD;
				}
				if (ccmp->ulAADLen > 0 && ccmp->pAAD == NULL_PTR)
				{
					DEBUG_MSG("CCM pAAD is NULL with non-zero ulAADLen");
					return CKR_ARGUMENTS_BAD;
				}
				if (ccmp->ulMACLen != 4 && ccmp->ulMACLen != 6 && ccmp->ulMACLen != 8 &&
				    ccmp->ulMACLen != 10 && ccmp->ulMACLen != 12 && ccmp->ulMACLen != 14 &&
				    ccmp->ulMACLen != 16)
				{
					DEBUG_MSG("Invalid CCM ulMACLen");
					return CKR_MECHANISM_PARAM_INVALID;
				}
				iv.resize(ccmp->ulNonceLen);
				memcpy(&iv[0], ccmp->pNonce, ccmp->ulNonceLen);
				aad.resize(ccmp->ulAADLen);
				if (ccmp->ulAADLen > 0)
					memcpy(&aad[0], ccmp->pAAD, ccmp->ulAADLen);
				tagBytes = ccmp->ulMACLen;
				dataLen = ccmp->ulDataLen;
			}
			break;
		case CKM_AES_XTS:
			// PKCS#11 v3.2 §6.15.4: CKK_AES_XTS keys only (never plain CKK_AES).
			if (keyType != CKK_AES_XTS)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::XTS;
			// Single parameter: a 16-byte Data Unit Sequence Number (the tweak).
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != 16)
			{
				DEBUG_MSG("XTS mode requires a 16-byte Data Unit Sequence Number");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], pMechanism->pParameter, 16);
			break;
		case CKM_AES_GCM:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::GCM;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
			{
				DEBUG_MSG("GCM mode requires parameters");
				return CKR_ARGUMENTS_BAD;
			}
			// A zero-length IV would cause the OSSL layer to substitute a
			// fixed all-zero nonce, producing catastrophic nonce reuse. Reject
			// it here per the spec (ulIvLen >= 1).
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen == 0)
			{
				DEBUG_MSG("GCM ulIvLen is zero");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			// Validate embedded pointers before dereferencing
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen > 0 &&
			    CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv == NULL_PTR)
			{
				DEBUG_MSG("GCM pIv is NULL with non-zero ulIvLen");
				return CKR_ARGUMENTS_BAD;
			}
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0 &&
			    CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD == NULL_PTR)
			{
				DEBUG_MSG("GCM pAAD is NULL with non-zero ulAADLen");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen > 0)
				memcpy(&iv[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
			aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0)
				memcpy(&aad[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			tagBytes = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
			if (tagBytes > 128 || tagBytes % 8 != 0)
			{
				DEBUG_MSG("Invalid ulTagBits value");
				return CKR_ARGUMENTS_BAD;
			}
			tagBytes = tagBytes / 8;
			break;
		case CKM_CHACHA20_POLY1305:
			if (keyType != CKK_CHACHA20)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::CHACHA;
			mode = SymMode::CHACHA_POLY1305;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS))
			{
				DEBUG_MSG("CHACHA20_POLY1305 mode requires parameters");
				return CKR_ARGUMENTS_BAD;
			}
			// ChaCha20-Poly1305 requires a 96-bit (12-byte) nonce per RFC 7539.
			// A zero-length nonce would let the OSSL layer substitute a fixed
			// all-zero nonce (catastrophic reuse); enforce the exact length.
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen != 12)
			{
				DEBUG_MSG("CHACHA20_POLY1305 ulNonceLen must be 12 bytes");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen > 0 &&
			    CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->pNonce == NULL_PTR)
			{
				DEBUG_MSG("CHACHA20_POLY1305 pNonce is NULL with non-zero ulNonceLen");
				return CKR_ARGUMENTS_BAD;
			}
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0 &&
			    CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->pAAD == NULL_PTR)
			{
				DEBUG_MSG("CHACHA20_POLY1305 pAAD is NULL with non-zero ulAADLen");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen);
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen > 0)
				memcpy(&iv[0], CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->pNonce, CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulNonceLen);
			aad.resize(CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			if (CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0)
				memcpy(&aad[0], CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			tagBytes = 16;
			break;
		case CKM_CHACHA20:
			// Bare ChaCha20 stream cipher (audit V-10), symmetric with encrypt.
			if (keyType != CKK_CHACHA20)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::CHACHA;
			mode = SymMode::CHACHA;
			{
				CK_RV rvp = parseChaCha20Params(pMechanism, iv);
				if (rvp != CKR_OK) return rvp;
			}
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();

	if (getSymmetricKey(secretkey, token, key) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize decryption
	if (!cipher->decryptInit(secretkey, mode, iv, padding, counterBits, aad, tagBytes, dataLen))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_DECRYPT);
	session->setSymmetricCryptoOp(cipher);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(secretkey);

	return CKR_OK;
}

// AsymAlgorithm version of C_DecryptInit
CK_RV SoftHSM::AsymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_DECRYPT lets a Decrypt init pair with an already-active
	// Digest/Verify op for C_DecryptDigestUpdate / C_DecryptVerifyUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_DECRYPT, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_DECRYPT);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	bool isRSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			mechanism = AsymMech::RSA_PKCS;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			mechanism = AsymMech::RSA;
			isRSA = true;
			break;
		case CKM_RSA_PKCS_OAEP:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			rv = MechParamCheckRSAPKCSOAEP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			{
				CK_RSA_PKCS_OAEP_PARAMS_PTR oaepP = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;
				switch (oaepP->hashAlg) {
					case CKM_SHA224:   mechanism = AsymMech::RSA_PKCS_OAEP_SHA224;   break;
					case CKM_SHA256:   mechanism = AsymMech::RSA_PKCS_OAEP_SHA256;   break;
					case CKM_SHA384:   mechanism = AsymMech::RSA_PKCS_OAEP_SHA384;   break;
					case CKM_SHA512:   mechanism = AsymMech::RSA_PKCS_OAEP_SHA512;   break;
					case CKM_SHA3_224: mechanism = AsymMech::RSA_PKCS_OAEP_SHA3_224; break;
					case CKM_SHA3_256: mechanism = AsymMech::RSA_PKCS_OAEP_SHA3_256; break;
					case CKM_SHA3_384: mechanism = AsymMech::RSA_PKCS_OAEP_SHA3_384; break;
					case CKM_SHA3_512: mechanism = AsymMech::RSA_PKCS_OAEP_SHA3_512; break;
					default:           mechanism = AsymMech::RSA_PKCS_OAEP;          break;
				}
			}
			isRSA = true;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PrivateKey* privateKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		return CKR_MECHANISM_INVALID;
        }

	// Check if re-authentication is required
	if (key->getBooleanValue(CKA_ALWAYS_AUTHENTICATE, false))
	{
		session->setReAuthentication(true);
	}

	session->setOpType(SESSION_OP_DECRYPT);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setPrivateKey(privateKey);

	return CKR_OK;
}

// Initialise decryption using the specified object
CK_RV SoftHSM::C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	// C2 (2026-08-13) — §5.8.1 and its siblings: "C_DecryptInit can be called with
	// pMechanism set to NULL_PTR to terminate an active decryption operation. If an
	// active operation ... cannot be cancelled, CKR_OPERATION_CANCEL_FAILED must
	// be returned." CKR_ARGUMENTS_BAD, which this used to answer, is neither of
	// the two permitted results. C_SessionCancel already implements the
	// per-family cancel semantics (and the initialisation and session-handle
	// checks that outrank this one), so the cancel form routes into it.
	if (pMechanism == NULL_PTR) return C_SessionCancel(hSession, CKF_DECRYPT);

	if (isSymMechanism(pMechanism))
		return SymDecryptInit(hSession, pMechanism, hKey);
	else
		return AsymDecryptInit(hSession, pMechanism, hKey);
}

// SymAlgorithm version of C_Decrypt
static CK_RV SymDecrypt(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	// V-17: a one-shot C_Decrypt after C_DecryptUpdate must report CKR_OPERATION_ACTIVE
	// without destroying the multi-part op (the caller can still C_DecryptFinal).
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Check encrypted data size
	if (cipher->isBlockCipher() && ulEncryptedDataLen % cipher->getBlockSize() != 0)
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}
	if (!cipher->checkMaximumBytes(ulEncryptedDataLen))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (pData == NULL_PTR)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < ulEncryptedDataLen)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString encryptedData(pEncryptedData, ulEncryptedDataLen);
	ByteString data;

	// Decrypt the data
	if (!cipher->decryptUpdate(encryptedData,data))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}

	// Finalize decryption
	ByteString dataFinal;
	if (!cipher->decryptFinal(dataFinal))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}
	data += dataFinal;
	if (data.size() > ulEncryptedDataLen)
	{
		data.resize(ulEncryptedDataLen);
	}

	if (data.size() != 0)
	{
		memcpy(pData, data.byte_str(), data.size());
	}
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;

}

// AsymAlgorithm version of C_Decrypt
static CK_RV AsymDecrypt(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	// V-17: a one-shot C_Decrypt after C_DecryptUpdate must report CKR_OPERATION_ACTIVE
	// without destroying the multi-part op (the caller can still C_DecryptFinal).
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the data
	CK_ULONG size = privateKey->getOutputLength();
	if (pData == NULL_PTR)
	{
		*pulDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < size)
	{
		*pulDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString encryptedData(pEncryptedData, ulEncryptedDataLen);
	ByteString data;

	// Decrypt the data
	if (!asymCrypto->decrypt(privateKey,encryptedData,data,mechanism))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}

	// Check size
	if (data.size() > size)
	{
		ERROR_MSG("The size of the decrypted data exceeds the size of the mechanism");
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}
	if (data.size() != 0)
	{
		memcpy(pData, data.byte_str(), data.size());
	}
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;

}

// Perform a single operation decryption in the given session
CK_RV SoftHSM::C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((pEncryptedData == NULL_PTR) || (pulDataLen == NULL_PTR))
	{
		session->resetOp();

		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymDecrypt(session, pEncryptedData, ulEncryptedDataLen,
				  pData, pulDataLen);
	else
		return AsymDecrypt(session, pEncryptedData, ulEncryptedDataLen,
				   pData, pulDataLen);
}

// SymAlgorithm version of C_DecryptUpdate
// SymAlgorithm version of C_DecryptUpdate. Shared with the §5.13 dual-function
// updates via SoftHSM::symDecryptUpdateRaw — it inspects only the symmetric
// cipher context, never the session op type.
CK_RV SoftHSM::symDecryptUpdateRaw(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted data size
	size_t blockSize = cipher->getBlockSize();
	size_t remainingSize = cipher->getBufferSize();
	CK_ULONG maxSize;
	if (ulEncryptedDataLen > ~(CK_ULONG)0 - remainingSize)
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}
	maxSize = ulEncryptedDataLen + remainingSize;
	if (cipher->isBlockCipher())
	{
		// There must always be one block left in padding mode if next operation is DecryptFinal.
		// To guarantee that one byte is removed in padding mode when the number of blocks is calculated.
		size_t paddingAdjustByte = cipher->getPaddingMode() ? 1 : 0;
		int nrOfBlocks = (ulEncryptedDataLen + remainingSize - paddingAdjustByte) / blockSize;
		maxSize = nrOfBlocks * blockSize;
	}
	if (!cipher->checkMaximumBytes(ulEncryptedDataLen))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	// Give required output buffer size.
	if (pData == NULL_PTR)
	{
		*pDataLen = maxSize;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pDataLen < maxSize)
	{
		DEBUG_MSG("Output buffer too short   ulEncryptedDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x",
			  ulEncryptedDataLen, *pDataLen, blockSize, remainingSize, maxSize);
		*pDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pEncryptedData, ulEncryptedDataLen);
	ByteString decryptedData;

	// Decrypt the data
	if (!cipher->decryptUpdate(data, decryptedData))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}
	DEBUG_MSG("ulEncryptedDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x  decryptedData.size(): %#5x",
		  ulEncryptedDataLen, *pDataLen, blockSize, remainingSize, maxSize, decryptedData.size());

	// Check output size from crypto. Unrecoverable error if too large.
	if (*pDataLen < decryptedData.size())
	{
		session->resetOp();
		ERROR_MSG("DecryptUpdate returning too much data. Length of output data buffer is %i but %i bytes was returned by the decrypt.",
				*pDataLen, decryptedData.size());
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (decryptedData.size() > 0)
	{
		memcpy(pData, decryptedData.byte_str(), decryptedData.size());
	}
	*pDataLen = decryptedData.size();

	// V-17: a multi-part op is now in progress; a subsequent one-shot C_Decrypt
	// must be rejected with CKR_OPERATION_ACTIVE rather than silently allowed.
	session->setAllowSinglePartOp(false);

	return CKR_OK;
}


// Feed data to the running decryption operation in a session
CK_RV SoftHSM::C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((pEncryptedData == NULL_PTR) || (pDataLen == NULL_PTR))
	{
		session->resetOp();

		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return symDecryptUpdateRaw(session, pEncryptedData, ulEncryptedDataLen,
				  pData, pDataLen);
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV SymDecryptFinal(Session* session, CK_BYTE_PTR pDecryptedData, CK_ULONG_PTR pulDecryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted data size
	size_t remainingSize = cipher->getBufferSize();
	CK_ULONG size = remainingSize;
	if (cipher->isBlockCipher())
	{
		size_t blockSize = cipher->getBlockSize();
		if (remainingSize % blockSize != 0)
		{
			session->resetOp();
			DEBUG_MSG("Remaining data length is not an integral of the block size. Block size: %#2x  Remaining size: %#2x",
				   blockSize, remainingSize);
			return CKR_ENCRYPTED_DATA_LEN_RANGE;
		}
		// It is at least one padding byte. If no padding the all remains will be returned.
		size_t paddingAdjustByte = cipher->getPaddingMode() ? 1 : 0;
		size = remainingSize - paddingAdjustByte;
	}

	// Give required output buffer size.
	if (pDecryptedData == NULL_PTR)
	{
		*pulDecryptedDataLen = size;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulDecryptedDataLen < size)
	{
		DEBUG_MSG("output buffer size: %#5x  size: %#5x",
			  *pulDecryptedDataLen, size);
		*pulDecryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Finalize decryption
	ByteString decryptedFinal;
	if (!cipher->decryptFinal(decryptedFinal))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}
	DEBUG_MSG("output buffer size: %#2x  size: %#2x  decryptedFinal.size(): %#2x",
		  *pulDecryptedDataLen, size, decryptedFinal.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulDecryptedDataLen < decryptedFinal.size())
	{
		session->resetOp();
		ERROR_MSG("DecryptFinal returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
			  *pulDecryptedDataLen, decryptedFinal.size());
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (decryptedFinal.size() > 0)
	{
		memcpy(pDecryptedData, decryptedFinal.byte_str(), decryptedFinal.size());
	}
	*pulDecryptedDataLen = decryptedFinal.size();

	// Release only the decrypt half; a dual digest/verify partner (if any) survives.
	session->endOpFamily(SESSION_OP_DECRYPT);
	return CKR_OK;
}

// Finalise the decryption operation
CK_RV SoftHSM::C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Github issue #469, check NULL_PTR on pDataLen
	if (pDataLen == NULL)
	{
		session->resetOp();
		return CKR_ARGUMENTS_BAD;
	}

	// Accept a standalone decrypt op or the decrypt half of a §5.13 dual-function
	// op (its digest/verify partner may have been finalised first).
	if (session->getOpType() != SESSION_OP_DECRYPT && session->getSymmetricCryptoOp() == NULL)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymDecryptFinal(session, pData, pDataLen);
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
}

// ── PKCS#11 v3.0: message-based AEAD (AES-GCM per-message IV + AAD) ─────────────────────────
//
// Session state machine:
//   C_MessageEncryptInit()           → SESSION_OP_MESSAGE_ENCRYPT (0x15)
//     C_EncryptMessage()             → one-shot per-message AEAD, stays in MESSAGE_ENCRYPT
//     C_EncryptMessageBegin()        → → SESSION_OP_MESSAGE_ENCRYPT_BEGIN (0x17)
//       C_EncryptMessageNext(part)   → streaming chunk(s)
//       C_EncryptMessageNext(END)    → final chunk + tag → back to MESSAGE_ENCRYPT
//   C_MessageEncryptFinal()          → SESSION_OP_NONE
//
// C_MessageDecryptInit / C_DecryptMessage / C_DecryptMessageBegin / C_DecryptMessageNext /
// C_MessageDecryptFinal are symmetric using 0x16 / 0x18.
//
// Key persistence across messages: the AES key bytes are stored in session->param as a
// GcmMsgCtx struct.  resetOp() frees param at MessageEncryptFinal/MessageDecryptFinal.
// Each one-shot message creates and destroys its own cipher context without touching param.
// The streaming cipher (Begin→Next→END) is stored in session->symmetricCryptoOp; it is
// torn down by the caller after the END chunk and param survives for the next message.

// ─── Context struct stored in session param ──────────────────────────────────
static const size_t GCM_MSG_KEY_MAX = 32; // AES-256 max

struct GcmMsgCtx
{
	CK_ULONG keyLen;
	uint8_t  keyData[GCM_MSG_KEY_MAX];
	CK_ULONG accumCipherLen; // total ciphertext fed by intermediate DecryptMessageNext calls
};

// ─── IV generation helper ────────────────────────────────────────────────────
static CK_RV generateGcmIv(CK_GCM_MESSAGE_PARAMS* p)
{
	switch (p->ivGenerator)
	{
	case CKG_NO_GENERATE:
		// Caller provides IV — validate it is present.
		if (p->pIv == NULL_PTR || p->ulIvLen == 0)
			return CKR_ARGUMENTS_BAD;
		return CKR_OK;

	case CKG_GENERATE:
	case CKG_GENERATE_RANDOM:
	case CKG_GENERATE_COUNTER:
	case CKG_GENERATE_COUNTER_XOR:
		// For all generate variants, fill with random bytes.
		// Counter-mode IV generation (fixed prefix + incrementing counter) can be
		// layered on top by the application; softhsmv3 generates a fresh random IV
		// unconditionally for any of the three "generate" variants.
		break;

	default:
		return CKR_MECHANISM_PARAM_INVALID;
	}

	if (p->pIv == NULL_PTR || p->ulIvLen == 0)
		return CKR_ARGUMENTS_BAD;

	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;

	ByteString iv;
	if (!rng->generateRandom(iv, p->ulIvLen))
		return CKR_GENERAL_ERROR;

	memcpy(p->pIv, iv.byte_str(), p->ulIvLen);
	return CKR_OK;
}

// ─── One-shot AES-GCM encrypt ───────────────────────────────────────────────
// Output: pCiphertext receives the encrypted bytes (same length as plaintext).
//         pParam->pTag receives the authentication tag.
// Size-query: pass pCiphertext == NULL_PTR; *pulCiphertextLen is set and CKR_OK returned.
static CK_RV aesgcmEncryptOneShot(
	const uint8_t* keyData, size_t keyLen,
	const ByteString& iv, const ByteString& aad, size_t tagBytes,
	CK_BYTE_PTR pPlain, CK_ULONG ulPlainLen,
	CK_BYTE_PTR pCipher, CK_ULONG_PTR pulCipherLen,
	uint8_t* pTag)
{
	if (pCipher == NULL_PTR) {
		*pulCipherLen = ulPlainLen;
		return CKR_OK;
	}
	if (*pulCipherLen < ulPlainLen) {
		*pulCipherLen = ulPlainLen;
		return CKR_BUFFER_TOO_SMALL;
	}

	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* symKey = new SymmetricKey();
	symKey->setKeyBits(ByteString(keyData, keyLen));
	symKey->setBitLen(keyLen * 8);

	if (!cipher->encryptInit(symKey, SymMode::GCM, iv, false, 0, aad, tagBytes)) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	ByteString plain(pPlain, ulPlainLen);
	ByteString cipherOut;
	ByteString finalPart;

	if (!cipher->encryptUpdate(plain, cipherOut)) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}
	if (!cipher->encryptFinal(finalPart)) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// GCM: cipherOut has the ciphertext bytes; finalPart has the tag.
	if (cipherOut.size() != ulPlainLen || finalPart.size() != tagBytes) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	memcpy(pCipher, cipherOut.byte_str(), cipherOut.size());
	*pulCipherLen = (CK_ULONG)cipherOut.size();
	if (pTag) memcpy(pTag, finalPart.byte_str(), tagBytes);

	cipher->recycleKey(symKey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	return CKR_OK;
}

// ─── One-shot AES-GCM decrypt ───────────────────────────────────────────────
// pTag is the expected authentication tag (from CK_GCM_MESSAGE_PARAMS.pTag on decryption).
// Size-query: pass pPlain == NULL_PTR.
static CK_RV aesgcmDecryptOneShot(
	const uint8_t* keyData, size_t keyLen,
	const ByteString& iv, const ByteString& aad, size_t tagBytes,
	const uint8_t* pTag,
	CK_BYTE_PTR pCipher, CK_ULONG ulCipherLen,
	CK_BYTE_PTR pPlain, CK_ULONG_PTR pulPlainLen)
{
	if (pPlain == NULL_PTR) {
		*pulPlainLen = ulCipherLen;
		return CKR_OK;
	}
	if (*pulPlainLen < ulCipherLen) {
		*pulPlainLen = ulCipherLen;
		return CKR_BUFFER_TOO_SMALL;
	}

	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* symKey = new SymmetricKey();
	symKey->setKeyBits(ByteString(keyData, keyLen));
	symKey->setBitLen(keyLen * 8);

	if (!cipher->decryptInit(symKey, SymMode::GCM, iv, false, 0, aad, tagBytes)) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	// The OSSL GCM decrypt layer expects ciphertext + tag concatenated in the input buffer.
	// Build: aeadBuf = pCipher || pTag
	ByteString aeadBuf(pCipher, ulCipherLen);
	aeadBuf += ByteString(pTag, tagBytes);

	ByteString plainOut;
	ByteString finalPart;

	if (!cipher->decryptUpdate(aeadBuf, plainOut)) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_ENCRYPTED_DATA_INVALID;
	}
	if (!cipher->decryptFinal(finalPart)) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_ENCRYPTED_DATA_INVALID;
	}

	plainOut += finalPart;
	if (plainOut.size() > ulCipherLen) plainOut.resize(ulCipherLen);

	memcpy(pPlain, plainOut.byte_str(), plainOut.size());
	*pulPlainLen = (CK_ULONG)plainOut.size();

	cipher->recycleKey(symKey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	return CKR_OK;
}

// ─── MsgAesGcmInit — shared between C_MessageEncryptInit and C_MessageDecryptInit ──────────
CK_RV SoftHSM::MsgAesGcmInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey, CK_ATTRIBUTE_TYPE requiredAttr, int opType)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pMechanism->mechanism != CKM_AES_GCM) return CKR_MECHANISM_INVALID;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, requiredAttr, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_KEY_TYPE_INCONSISTENT;

	// Extract raw AES key bytes
	SymmetricKey skey;
	rv = getSymmetricKey(&skey, token, key);
	if (rv != CKR_OK) return rv;

	const ByteString& bits = skey.getKeyBits();
	if (bits.size() == 0 || bits.size() > GCM_MSG_KEY_MAX)
		return CKR_KEY_SIZE_RANGE;

	GcmMsgCtx ctx;
	ctx.keyLen = (CK_ULONG)bits.size();
	memcpy(ctx.keyData, bits.const_byte_str(), bits.size());
	ctx.accumCipherLen = 0;

	if (!session->setParameters(&ctx, sizeof(ctx)))
		return CKR_HOST_MEMORY;

	session->setOpType(opType);
	return CKR_OK;
}

// ─── C_MessageEncryptInit ────────────────────────────────────────────────────
CK_RV SoftHSM::C_MessageEncryptInit(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	// C2 (2026-08-13) — §5.8.1 and its siblings: "C_MessageEncryptInit can be called with
	// pMechanism set to NULL_PTR to terminate an active message-based encryption operation. If an
	// active operation ... cannot be cancelled, CKR_OPERATION_CANCEL_FAILED must
	// be returned." CKR_ARGUMENTS_BAD, which this used to answer, is neither of
	// the two permitted results. C_SessionCancel already implements the
	// per-family cancel semantics (and the initialisation and session-handle
	// checks that outrank this one), so the cancel form routes into it.
	if (pMechanism == NULL_PTR) return C_SessionCancel(hSession, CKF_MESSAGE_ENCRYPT);

	return MsgAesGcmInit(hSession, pMechanism, hKey, CKA_ENCRYPT, SESSION_OP_MESSAGE_ENCRYPT);
}

// ─── C_EncryptMessage ────────────────────────────────────────────────────────
// One-shot per-message AES-GCM encrypt. pParameter must be CK_GCM_MESSAGE_PARAMS*.
// On success the session stays in SESSION_OP_MESSAGE_ENCRYPT.
CK_RV SoftHSM::C_EncryptMessage(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
	CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen,
	CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pParameter == NULL_PTR || ulParameterLen != sizeof(CK_GCM_MESSAGE_PARAMS))
		return CKR_ARGUMENTS_BAD;
	if (pPlaintext == NULL_PTR || pulCiphertextLen == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	size_t ctxLen;
	GcmMsgCtx* ctx = (GcmMsgCtx*)session->getParameters(ctxLen);
	if (ctx == NULL || ctxLen < sizeof(GcmMsgCtx)) return CKR_OPERATION_NOT_INITIALIZED;

	CK_GCM_MESSAGE_PARAMS* p = (CK_GCM_MESSAGE_PARAMS*)pParameter;
	if (p->pTag == NULL_PTR || p->ulTagBits == 0 || p->ulTagBits > 128 || p->ulTagBits % 8 != 0)
		return CKR_MECHANISM_PARAM_INVALID;

	CK_RV rv = generateGcmIv(p);
	if (rv != CKR_OK) return rv;

	ByteString iv(p->pIv, p->ulIvLen);
	ByteString aad(pAssociatedData, ulAssociatedDataLen);
	size_t tagBytes = p->ulTagBits / 8;

	return aesgcmEncryptOneShot(ctx->keyData, (size_t)ctx->keyLen,
		iv, aad, tagBytes,
		pPlaintext, ulPlaintextLen,
		pCiphertext, pulCiphertextLen,
		(uint8_t*)p->pTag);
	// session op type stays MESSAGE_ENCRYPT — caller may send more messages
}

// ─── C_EncryptMessageBegin ───────────────────────────────────────────────────
// Commits IV and AAD for streaming encrypt; transitions to MESSAGE_ENCRYPT_BEGIN.
CK_RV SoftHSM::C_EncryptMessageBegin(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pParameter == NULL_PTR || ulParameterLen != sizeof(CK_GCM_MESSAGE_PARAMS))
		return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	size_t ctxLen;
	GcmMsgCtx* ctx = (GcmMsgCtx*)session->getParameters(ctxLen);
	if (ctx == NULL || ctxLen < sizeof(GcmMsgCtx)) return CKR_OPERATION_NOT_INITIALIZED;

	CK_GCM_MESSAGE_PARAMS* p = (CK_GCM_MESSAGE_PARAMS*)pParameter;
	if (p->pTag == NULL_PTR || p->ulTagBits == 0 || p->ulTagBits > 128 || p->ulTagBits % 8 != 0)
		return CKR_MECHANISM_PARAM_INVALID;

	CK_RV rv = generateGcmIv(p);
	if (rv != CKR_OK) return rv;

	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* symKey = new SymmetricKey();
	symKey->setKeyBits(ByteString(ctx->keyData, ctx->keyLen));
	symKey->setBitLen((size_t)ctx->keyLen * 8);

	ByteString iv(p->pIv, p->ulIvLen);
	ByteString aad(pAssociatedData, ulAssociatedDataLen);
	size_t tagBytes = p->ulTagBits / 8;

	if (!cipher->encryptInit(symKey, SymMode::GCM, iv, false, 0, aad, tagBytes)) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	// Store cipher + key in session (without touching param / GcmMsgCtx)
	// setSymmetricCryptoOp takes ownership of cipher; setSymmetricKey transfers ownership to cipher.
	session->setSymmetricCryptoOp(cipher);
	session->setSymmetricKey(symKey);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(false);
	session->setOpType(SESSION_OP_MESSAGE_ENCRYPT_BEGIN);
	return CKR_OK;
}

// ─── C_EncryptMessageNext ────────────────────────────────────────────────────
// Intermediate call (pParameter == NULL, !(flags & CKF_END_OF_MESSAGE)): feed a chunk.
// Final call (flags & CKF_END_OF_MESSAGE): finalize encryption and write tag to pParameter.
CK_RV SoftHSM::C_EncryptMessageNext(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen,
	CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen,
	CK_FLAGS flags)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pPlaintextPart == NULL_PTR || pulCiphertextPartLen == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_ENCRYPT_BEGIN)
		return CKR_OPERATION_NOT_INITIALIZED;

	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL) return CKR_OPERATION_NOT_INITIALIZED;

	bool isLast = (flags & CKF_END_OF_MESSAGE) != 0;

	if (!isLast) {
		// Intermediate chunk: pass to encryptUpdate
		if (pCiphertextPart == NULL_PTR) {
			*pulCiphertextPartLen = ulPlaintextPartLen;
			return CKR_OK;
		}
		if (*pulCiphertextPartLen < ulPlaintextPartLen) {
			*pulCiphertextPartLen = ulPlaintextPartLen;
			return CKR_BUFFER_TOO_SMALL;
		}
		ByteString plain(pPlaintextPart, ulPlaintextPartLen);
		ByteString cipherOut;
		if (!cipher->encryptUpdate(plain, cipherOut)) {
			session->resetOp();
			return CKR_GENERAL_ERROR;
		}
		if (cipherOut.size() > 0) memcpy(pCiphertextPart, cipherOut.byte_str(), cipherOut.size());
		*pulCiphertextPartLen = (CK_ULONG)cipherOut.size();
		return CKR_OK;
	}

	// Final chunk: pParameter must be CK_GCM_MESSAGE_PARAMS* (for pTag output)
	if (pParameter == NULL_PTR || ulParameterLen != sizeof(CK_GCM_MESSAGE_PARAMS))
		return CKR_ARGUMENTS_BAD;
	CK_GCM_MESSAGE_PARAMS* p = (CK_GCM_MESSAGE_PARAMS*)pParameter;
	if (p->pTag == NULL_PTR) return CKR_ARGUMENTS_BAD;

	size_t tagBytes = cipher->getTagBytes();

	// GCM: ciphertext length == plaintext length (no padding).
	// Check buffer BEFORE invoking the cipher so caller can retry with a
	// larger buffer without losing the streaming cipher state.
	CK_ULONG needLen = (CK_ULONG)ulPlaintextPartLen;
	if (pCiphertextPart == NULL_PTR) {
		*pulCiphertextPartLen = needLen;
		return CKR_OK; // cipher preserved; caller retries with a real buffer
	}
	if (*pulCiphertextPartLen < needLen) {
		*pulCiphertextPartLen = needLen;
		return CKR_BUFFER_TOO_SMALL; // cipher preserved; caller retries
	}

	ByteString plain(pPlaintextPart, ulPlaintextPartLen);
	ByteString cipherOut;
	ByteString finalPart;

	if (!cipher->encryptUpdate(plain, cipherOut)) {
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	if (!cipher->encryptFinal(finalPart)) {
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Strict tag length assertion — backend must produce exactly tagBytes.
	if (finalPart.size() != tagBytes) {
		session->setSymmetricCryptoOp(NULL);
		session->setOpType(SESSION_OP_MESSAGE_ENCRYPT);
		return CKR_GENERAL_ERROR;
	}

	if (cipherOut.size() > 0) memcpy(pCiphertextPart, cipherOut.byte_str(), cipherOut.size());
	*pulCiphertextPartLen = (CK_ULONG)cipherOut.size();
	memcpy(p->pTag, finalPart.byte_str(), tagBytes);

	// Tear down streaming cipher; GcmMsgCtx in param survives for the next message
	session->setSymmetricCryptoOp(NULL); // recycles cipher + key
	session->setOpType(SESSION_OP_MESSAGE_ENCRYPT);
	return CKR_OK;
}

// ─── C_MessageEncryptFinal ───────────────────────────────────────────────────
CK_RV SoftHSM::C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	// Accept _BEGIN state too: caller may call Final to abandon a streaming message
	// (i.e., after EncryptMessageBegin but before a CKF_END_OF_MESSAGE Next).
	CK_ULONG opType = session->getOpType();
	if (opType != SESSION_OP_MESSAGE_ENCRYPT &&
	    opType != SESSION_OP_MESSAGE_ENCRYPT_BEGIN)
		return CKR_OPERATION_NOT_INITIALIZED;
	session->resetOp(); // frees GcmMsgCtx param + any leftover cipher
	return CKR_OK;
}

// ─── C_MessageDecryptInit ────────────────────────────────────────────────────
CK_RV SoftHSM::C_MessageDecryptInit(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	// C2 (2026-08-13) — §5.8.1 and its siblings: "C_MessageDecryptInit can be called with
	// pMechanism set to NULL_PTR to terminate an active message-based decryption operation. If an
	// active operation ... cannot be cancelled, CKR_OPERATION_CANCEL_FAILED must
	// be returned." CKR_ARGUMENTS_BAD, which this used to answer, is neither of
	// the two permitted results. C_SessionCancel already implements the
	// per-family cancel semantics (and the initialisation and session-handle
	// checks that outrank this one), so the cancel form routes into it.
	if (pMechanism == NULL_PTR) return C_SessionCancel(hSession, CKF_MESSAGE_DECRYPT);

	return MsgAesGcmInit(hSession, pMechanism, hKey, CKA_DECRYPT, SESSION_OP_MESSAGE_DECRYPT);
}

// ─── C_DecryptMessage ────────────────────────────────────────────────────────
// One-shot per-message AES-GCM decrypt. pParameter must be CK_GCM_MESSAGE_PARAMS*.
// pParameter->pTag holds the authentication tag to verify.
CK_RV SoftHSM::C_DecryptMessage(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
	CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen,
	CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pParameter == NULL_PTR || ulParameterLen != sizeof(CK_GCM_MESSAGE_PARAMS))
		return CKR_ARGUMENTS_BAD;
	if (pCiphertext == NULL_PTR || pulPlaintextLen == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	size_t ctxLen;
	GcmMsgCtx* ctx = (GcmMsgCtx*)session->getParameters(ctxLen);
	if (ctx == NULL || ctxLen < sizeof(GcmMsgCtx)) return CKR_OPERATION_NOT_INITIALIZED;

	CK_GCM_MESSAGE_PARAMS* p = (CK_GCM_MESSAGE_PARAMS*)pParameter;
	if (p->pIv == NULL_PTR || p->ulIvLen == 0)
		return CKR_MECHANISM_PARAM_INVALID;
	if (p->pTag == NULL_PTR || p->ulTagBits == 0 || p->ulTagBits > 128 || p->ulTagBits % 8 != 0)
		return CKR_MECHANISM_PARAM_INVALID;

	ByteString iv(p->pIv, p->ulIvLen);
	ByteString aad(pAssociatedData, ulAssociatedDataLen);
	size_t tagBytes = p->ulTagBits / 8;

	return aesgcmDecryptOneShot(ctx->keyData, (size_t)ctx->keyLen,
		iv, aad, tagBytes,
		(const uint8_t*)p->pTag,
		pCiphertext, ulCiphertextLen,
		pPlaintext, pulPlaintextLen);
	// session op type stays MESSAGE_DECRYPT — caller may send more messages
}

// ─── C_DecryptMessageBegin ───────────────────────────────────────────────────
// Commits IV and AAD for streaming decrypt; transitions to MESSAGE_DECRYPT_BEGIN.
// pParameter->pTag is not used at Begin time; it is provided at the final Next call.
CK_RV SoftHSM::C_DecryptMessageBegin(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pParameter == NULL_PTR || ulParameterLen != sizeof(CK_GCM_MESSAGE_PARAMS))
		return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	size_t ctxLen;
	GcmMsgCtx* ctx = (GcmMsgCtx*)session->getParameters(ctxLen);
	if (ctx == NULL || ctxLen < sizeof(GcmMsgCtx)) return CKR_OPERATION_NOT_INITIALIZED;

	CK_GCM_MESSAGE_PARAMS* p = (CK_GCM_MESSAGE_PARAMS*)pParameter;
	if (p->pIv == NULL_PTR || p->ulIvLen == 0)
		return CKR_MECHANISM_PARAM_INVALID;
	if (p->ulTagBits == 0 || p->ulTagBits > 128 || p->ulTagBits % 8 != 0)
		return CKR_MECHANISM_PARAM_INVALID;

	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* symKey = new SymmetricKey();
	symKey->setKeyBits(ByteString(ctx->keyData, ctx->keyLen));
	symKey->setBitLen((size_t)ctx->keyLen * 8);

	ByteString iv(p->pIv, p->ulIvLen);
	ByteString aad(pAssociatedData, ulAssociatedDataLen);
	size_t tagBytes = p->ulTagBits / 8;

	if (!cipher->decryptInit(symKey, SymMode::GCM, iv, false, 0, aad, tagBytes)) {
		cipher->recycleKey(symKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	ctx->accumCipherLen = 0; // reset for new streaming message
	session->setSymmetricCryptoOp(cipher);
	session->setSymmetricKey(symKey);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(false);
	session->setOpType(SESSION_OP_MESSAGE_DECRYPT_BEGIN);
	return CKR_OK;
}

// ─── C_DecryptMessageNext ────────────────────────────────────────────────────
// Intermediate call (!(flags & CKF_END_OF_MESSAGE)): accumulate ciphertext chunk.
// GCM requires all ciphertext + tag before plaintext can be released (AEAD guarantee).
// The OSSL layer buffers internally; decryptUpdate returns nothing for GCM.
// Final call (flags & CKF_END_OF_MESSAGE): pParameter must supply the auth tag in pTag.
//   Internally this call feeds the tag concatenated with remaining ciphertext and finalises.
CK_RV SoftHSM::C_DecryptMessageNext(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen,
	CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen,
	CK_FLAGS flags)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pulPlaintextPartLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_DECRYPT_BEGIN)
		return CKR_OPERATION_NOT_INITIALIZED;

	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL) return CKR_OPERATION_NOT_INITIALIZED;

	size_t ctxLen;
	GcmMsgCtx* ctx = (GcmMsgCtx*)session->getParameters(ctxLen);
	if (ctx == NULL || ctxLen < sizeof(GcmMsgCtx)) return CKR_OPERATION_NOT_INITIALIZED;

	bool isLast = (flags & CKF_END_OF_MESSAGE) != 0;

	if (!isLast) {
		// Intermediate chunk: feed to decryptUpdate.
		// GCM buffers all data internally; plaintext is not available until the final call.
		if (pCiphertextPart != NULL_PTR && ulCiphertextPartLen > 0) {
			ByteString cipherChunk(pCiphertextPart, ulCiphertextPartLen);
			ByteString dummy;
			if (!cipher->decryptUpdate(cipherChunk, dummy)) {
				session->resetOp();
				return CKR_ENCRYPTED_DATA_INVALID;
			}
			// Guard against CK_ULONG overflow (relevant on 32-bit / WASM targets).
			// GCM messages exceeding ~4 GB are rejected by OpenSSL anyway, but be explicit.
			if (ulCiphertextPartLen > (~(CK_ULONG)0) - ctx->accumCipherLen) {
				session->resetOp();
				return CKR_DATA_LEN_RANGE;
			}
			ctx->accumCipherLen += (CK_ULONG)ulCiphertextPartLen;
		}
		*pulPlaintextPartLen = 0;
		return CKR_OK;
	}

	// Final: pParameter must be CK_GCM_MESSAGE_PARAMS* with pTag set
	if (pParameter == NULL_PTR || ulParameterLen != sizeof(CK_GCM_MESSAGE_PARAMS))
		return CKR_ARGUMENTS_BAD;
	CK_GCM_MESSAGE_PARAMS* p = (CK_GCM_MESSAGE_PARAMS*)pParameter;
	if (p->pTag == NULL_PTR) return CKR_ARGUMENTS_BAD;

	size_t tagBytes = cipher->getTagBytes();

	// GCM: plaintext length = total accumulated ciphertext (all intermediate chunks + this chunk).
	// This is known before running decryptFinal, so the buffer check can precede the crypto,
	// leaving the cipher context intact for a retry if the buffer is too small.
	CK_ULONG thisCipherLen = (pCiphertextPart != NULL_PTR) ? (CK_ULONG)ulCiphertextPartLen : 0;
	if (thisCipherLen > (~(CK_ULONG)0) - ctx->accumCipherLen) {
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}
	CK_ULONG totalPlain = ctx->accumCipherLen + thisCipherLen;

	if (pPlaintextPart == NULL_PTR) {
		*pulPlaintextPartLen = totalPlain;
		return CKR_OK; // cipher preserved; caller retries with a real buffer
	}
	if (*pulPlaintextPartLen < totalPlain) {
		*pulPlaintextPartLen = totalPlain;
		return CKR_BUFFER_TOO_SMALL; // cipher preserved; caller retries
	}

	// Feed any final ciphertext chunk; then append tag so OSSL can verify it.
	// OSSL GCM decryptFinal reads the last tagBytes from the AEAD buffer as the tag.
	if (pCiphertextPart != NULL_PTR && ulCiphertextPartLen > 0) {
		ByteString cipherChunk(pCiphertextPart, ulCiphertextPartLen);
		ByteString dummy;
		if (!cipher->decryptUpdate(cipherChunk, dummy)) {
			session->resetOp();
			return CKR_ENCRYPTED_DATA_INVALID;
		}
	}
	// Feed tag as the final input so OSSL can extract and verify it via decryptFinal
	ByteString tagBuf((const uint8_t*)p->pTag, tagBytes);
	ByteString dummy2;
	if (!cipher->decryptUpdate(tagBuf, dummy2)) {
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}

	ByteString plainOut;
	if (!cipher->decryptFinal(plainOut)) {
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}

	CK_ULONG plainLen = (CK_ULONG)plainOut.size();
	if (plainLen > 0) memcpy(pPlaintextPart, plainOut.byte_str(), plainLen);
	*pulPlaintextPartLen = plainLen;

	// Tear down streaming cipher; GcmMsgCtx in param survives for the next message.
	// Reset accumCipherLen so Begin→Next→End for the next message starts from zero.
	ctx->accumCipherLen = 0;
	session->setSymmetricCryptoOp(NULL);
	session->setOpType(SESSION_OP_MESSAGE_DECRYPT);
	return CKR_OK;
}

// ─── C_MessageDecryptFinal ───────────────────────────────────────────────────
CK_RV SoftHSM::C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	// Accept _BEGIN state too: caller may call Final to abandon a streaming message
	// (i.e., after DecryptMessageBegin but before a CKF_END_OF_MESSAGE Next).
	CK_ULONG opType = session->getOpType();
	if (opType != SESSION_OP_MESSAGE_DECRYPT &&
	    opType != SESSION_OP_MESSAGE_DECRYPT_BEGIN)
		return CKR_OPERATION_NOT_INITIALIZED;
	session->resetOp(); // frees GcmMsgCtx param + any leftover cipher
	return CKR_OK;
}


