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
 SoftHSM_digest.cpp

 PKCS#11 digest (hash) operations: C_DigestInit, C_Digest, C_DigestUpdate,
 C_DigestKey, C_DigestFinal.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "HandleManager.h"
#include "SessionManager.h"
#include "CryptoFactory.h"
#include "cryptoki.h"
#include "HashAlgorithm.h"
#include "vendor_mechanisms.h"

CK_RV SoftHSM::C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// C2 (2026-08-13) — §5.8.1 and its siblings: "C_DigestInit can be called with
	// pMechanism set to NULL_PTR to terminate an active message-digesting operation. If an
	// active operation ... cannot be cancelled, CKR_OPERATION_CANCEL_FAILED must
	// be returned." CKR_ARGUMENTS_BAD, which this used to answer, is neither of
	// the two permitted results. C_SessionCancel already implements the
	// per-family cancel semantics (and the initialisation and session-handle
	// checks that outrank this one), so the cancel form routes into it.
	if (pMechanism == NULL_PTR) return C_SessionCancel(hSession, CKF_DIGEST);

	std::shared_ptr<Session> sessionGuard; Session* session;
	// SESSION_OP_DIGEST lets a Digest init pair with an already-active
	// Encrypt/Decrypt op for C_DigestEncryptUpdate / C_DecryptDigestUpdate (§5.13).
	CK_RV rv = acquireSession(hSession, sessionGuard, session, SESSION_OP_DIGEST);
	if (rv != CKR_OK) return rv;

	// Get the mechanism
	HashAlgo::Type algo = HashAlgo::Unknown;
	switch(pMechanism->mechanism) {
#ifndef WITH_FIPS
		case CKM_MD5:
			algo = HashAlgo::MD5;
			break;
#endif
		case CKM_RIPEMD160:
#ifdef WITH_RIPEMD160
			// Native builds load the OpenSSL legacy provider in
			// OSSLCryptoFactory, so RIPEMD-160 is a genuine digest here (G-DA-X).
			algo = HashAlgo::RIPEMD160;
			break;
#else
			// WASM / no-legacy build: the legacy provider is absent, so there is
			// no RIPEMD-160 backend. The previous code fell through into
			// CKM_SHA_1, silently computing a 20-byte SHA-1 digest labelled
			// RIPEMD-160 (G1). Reject rather than substitute another hash.
			return CKR_MECHANISM_INVALID;
#endif
		case CKM_SHA_1:
			algo = HashAlgo::SHA1;
			break;
		case CKM_SHA224:
			algo = HashAlgo::SHA224;
			break;
		case CKM_SHA256:
			algo = HashAlgo::SHA256;
			break;
		case CKM_SHA384:
			algo = HashAlgo::SHA384;
			break;
		case CKM_SHA512:
			algo = HashAlgo::SHA512;
			break;
		case CKM_SHA3_224:
			algo = HashAlgo::SHA3_224;
			break;
		case CKM_SHA3_256:
			algo = HashAlgo::SHA3_256;
			break;
		case CKM_SHA3_384:
			algo = HashAlgo::SHA3_384;
			break;
		case CKM_SHA3_512:
			algo = HashAlgo::SHA3_512;
			break;
		case CKM_KECCAK_256:
			// G11 — Keccak-256 is implemented in the Rust engine only (tiny-keccak).
			// The C++ OpenSSL engine does not support non-standard Keccak padding.
			return CKR_MECHANISM_INVALID;
		default:
			return CKR_MECHANISM_INVALID;
	}
	HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(algo);
	if (hash == NULL) return CKR_MECHANISM_INVALID;

	// Initialize hashing
	if (hash->hashInit() == false)
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return CKR_GENERAL_ERROR;
	}

	session->setOpType(SESSION_OP_DIGEST);
	session->setDigestOp(hash);
	session->setHashAlgo(algo);
	// V-17: track single-part eligibility; cleared once C_DigestUpdate/C_DigestKey
	// feeds data, so a later one-shot C_Digest is rejected with CKR_OPERATION_ACTIVE.
	session->setAllowSinglePartOp(true);

	return CKR_OK;
}

// Digest the specified data in a one-pass operation and return the resulting digest
CK_RV SoftHSM::C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulDigestLen == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Defense-in-depth: even with the op type matching, the digest context must
	// be live. A §5.13 dual op whose digest half was already finalised could
	// otherwise reach the getHashSize() deref below on a NULL context.
	if (session->getDigestOp() == NULL) return CKR_OPERATION_NOT_INITIALIZED;

	// V-17: C_Digest must be a single-part call. If C_DigestUpdate/C_DigestKey has
	// already fed data, reject the one-shot with CKR_OPERATION_ACTIVE rather than
	// silently digesting update||data. The multi-part op is left intact for C_DigestFinal.
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Return size
	CK_ULONG size = session->getDigestOp()->getHashSize();
	if (pDigest == NULL_PTR)
	{
		*pulDigestLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDigestLen < size)
	{
		*pulDigestLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Digest the data
	if (session->getDigestOp()->hashUpdate(data) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the digest
	ByteString digest;
	if (session->getDigestOp()->hashFinal(digest) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (digest.size() != size)
	{
		ERROR_MSG("The size of the digest differ from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pDigest, digest.byte_str(), size);
	*pulDigestLen = size;

	session->resetOp();

	return CKR_OK;
}

// Update a running digest operation
CK_RV SoftHSM::C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Defense-in-depth: the digest context must be live (a §5.13 dual op whose
	// digest half was finalised first could otherwise deref a NULL context).
	if (session->getDigestOp() == NULL) return CKR_OPERATION_NOT_INITIALIZED;

	// Get the data
	ByteString data(pPart, ulPartLen);

	// Digest the data
	if (session->getDigestOp()->hashUpdate(data) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// V-17: data has been fed multi-part; a later one-shot C_Digest is now invalid.
	session->setAllowSinglePartOp(false);

	return CKR_OK;
}

// Update a running digest operation by digesting a secret key with the specified handle
CK_RV SoftHSM::C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DIGEST) return CKR_OPERATION_NOT_INITIALIZED;

	// Defense-in-depth: the digest context must be live before we hashUpdate it.
	if (session->getDigestOp() == NULL) return CKR_OPERATION_NOT_INITIALIZED;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle (§2.4: scoped to this session's slot).
	OSObject *key = (OSObject *)handleManager->getObject(hObject, session->getSlot()->getSlotID());
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		// CKR_USER_NOT_LOGGED_IN is not a valid return code for this function,
		// so we use CKR_GENERAL_ERROR.
		return CKR_GENERAL_ERROR;
	}

	// Whitelist
	HashAlgo::Type algo = session->getHashAlgo();
	if (algo != HashAlgo::SHA1 &&
	    algo != HashAlgo::SHA224 &&
	    algo != HashAlgo::SHA256 &&
	    algo != HashAlgo::SHA384 &&
	    algo != HashAlgo::SHA512)
	{
		// Parano...
		if (!key->getBooleanValue(CKA_EXTRACTABLE, false))
			return CKR_KEY_INDIGESTIBLE;
		if (key->getBooleanValue(CKA_SENSITIVE, false))
			return CKR_KEY_INDIGESTIBLE;
	}

	// Get value
	if (!key->attributeExists(CKA_VALUE))
		return CKR_KEY_INDIGESTIBLE;
	ByteString keybits;
	if (isPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), keybits))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		keybits = key->getByteStringValue(CKA_VALUE);
	}

	// Digest the value
	if (session->getDigestOp()->hashUpdate(keybits) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// V-17: data has been fed multi-part; a later one-shot C_Digest is now invalid.
	session->setAllowSinglePartOp(false);

	return CKR_OK;
}

// Finalise the digest operation in the specified session and return the digest
CK_RV SoftHSM::C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulDigestLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Accept either a standalone digest op (op == SESSION_OP_DIGEST) or the
	// digest half of a §5.13 dual-function op (digestOp still live while the
	// cipher half is the nominal active op). Either way the digest context
	// must be present.
	if (session->getDigestOp() == NULL) return CKR_OPERATION_NOT_INITIALIZED;

	// Return size
	CK_ULONG size = session->getDigestOp()->getHashSize();
	if (pDigest == NULL_PTR)
	{
		*pulDigestLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDigestLen < size)
	{
		*pulDigestLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the digest
	ByteString digest;
	if (session->getDigestOp()->hashFinal(digest) == false)
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (digest.size() != size)
	{
		ERROR_MSG("The size of the digest differ from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pDigest, digest.byte_str(), size);
	*pulDigestLen = size;

	// Release only the digest half; a dual cipher partner (if any) survives.
	session->endOpFamily(SESSION_OP_DIGEST);

	return CKR_OK;
}


