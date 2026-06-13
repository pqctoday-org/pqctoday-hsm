/*
 * Copyright (c) 2022 NLnet Labs
 * Copyright (c) 2010 SURFnet bv
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 SoftHSM.cpp

 The implementation of the SoftHSM's main class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "Configuration.h"
#include "SimpleConfigLoader.h"
#include "MutexFactory.h"
#include "SecureMemoryRegistry.h"
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
#include "cryptoki.h"
#include "SoftHSM.h"
#include "osmutex.h"
#include "SessionManager.h"
#include "SessionObjectStore.h"
#include "HandleManager.h"
#include "P11Objects.h"
#include "odd.h"

// CKC_OPENPGP was in PKCS#11 2.x but removed from v3.2 headers.
#ifndef CKC_OPENPGP
#define CKC_OPENPGP 0x00000003UL
#endif

#if defined(WITH_OPENSSL)
#include "OSSLCryptoFactory.h"
#else
#include "BotanCryptoFactory.h"
#endif

#include <stdlib.h>
#include <algorithm>
#include <stdexcept>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

// Named constants shared across SoftHSM split translation units.
#include "SoftHSMHelpers.h"

// ---------------------------------------------------------------------------
// Session acquisition helpers (H2)
// ---------------------------------------------------------------------------

// Returns true when initialising newOp is permitted while activeOp is already
// running, because the two together form one of the four §5.13 dual-function
// pairings: Digest+Encrypt, Decrypt+Digest, Sign+Encrypt, Decrypt+Verify.
// Any other combination (notably a second op of the same family) is rejected,
// preserving the strict single-op CKR_OPERATION_ACTIVE contract.
bool SoftHSM::isComplementaryDualOp(int activeOp, int newOp)
{
	switch (activeOp)
	{
		case SESSION_OP_DIGEST:
			// C_DigestInit already done → allow Encrypt or Decrypt init.
			return newOp == SESSION_OP_ENCRYPT || newOp == SESSION_OP_DECRYPT;
		case SESSION_OP_SIGN:
			return newOp == SESSION_OP_ENCRYPT;
		case SESSION_OP_VERIFY:
			return newOp == SESSION_OP_DECRYPT;
		case SESSION_OP_ENCRYPT:
			// Cipher init already done → allow the digest/sign companion.
			return newOp == SESSION_OP_DIGEST || newOp == SESSION_OP_SIGN;
		case SESSION_OP_DECRYPT:
			return newOp == SESSION_OP_DIGEST || newOp == SESSION_OP_VERIFY;
		default:
			return false;
	}
}

CK_RV SoftHSM::acquireSession(CK_SESSION_HANDLE hSession,
                               std::shared_ptr<Session>& outGuard,
                               Session*& outSession,
                               int incomingOp)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	outGuard   = handleManager->getSessionShared(hSession);
	outSession = outGuard.get();
	if (outSession == NULL) return CKR_SESSION_HANDLE_INVALID;
	int activeOp = outSession->getOpType();
	if (activeOp != SESSION_OP_NONE &&
	    !(incomingOp != SESSION_OP_NONE && isComplementaryDualOp(activeOp, incomingOp)))
		return CKR_OPERATION_ACTIVE;
	return CKR_OK;
}

CK_RV SoftHSM::acquireSessionToken(CK_SESSION_HANDLE hSession,
                                    std::shared_ptr<Session>& outGuard,
                                    Session*& outSession,
                                    Token*& outToken,
                                    int incomingOp)
{
	CK_RV rv = acquireSession(hSession, outGuard, outSession, incomingOp);
	if (rv != CKR_OK) return rv;
	outToken = outSession->getToken();
	if (outToken == NULL) return CKR_GENERAL_ERROR;
	return CKR_OK;
}

CK_RV SoftHSM::acquireSessionTokenKey(CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hKey,
                                       CK_ATTRIBUTE_TYPE usageAttr,
                                       CK_MECHANISM_PTR pMechanism,
                                       std::shared_ptr<Session>& outGuard,
                                       Session*& outSession,
                                       Token*& outToken,
                                       OSObject*& outKey,
                                       int incomingOp)
{
	CK_RV rv = acquireSessionToken(hSession, outGuard, outSession, outToken, incomingOp);
	if (rv != CKR_OK) return rv;
	outKey = (OSObject*)handleManager->getObject(hKey);
	if (outKey == NULL_PTR || !outKey->isValid()) return CKR_OBJECT_HANDLE_INVALID;
	CK_BBOOL isOnToken = outKey->getBooleanValue(CKA_TOKEN,   false);
	CK_BBOOL isPrivate = outKey->getBooleanValue(CKA_PRIVATE, true);
	rv = haveRead(outSession->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		return rv;
	}
	if (!outKey->getBooleanValue(usageAttr, false)) return CKR_KEY_FUNCTION_NOT_PERMITTED;
	if (pMechanism != NULL_PTR && !isMechanismPermitted(outKey, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;
	return CKR_OK;
}

void SoftHSM::cleanupKeyPair(AsymmetricAlgorithm* algo,
                              AsymmetricKeyPair* kp,
                              Token* /*token*/,
                              CK_OBJECT_HANDLE_PTR phPublicKey,
                              CK_OBJECT_HANDLE_PTR phPrivateKey,
                              CK_RV rv)
{
	algo->recycleKeyPair(kp);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(algo);

	if (rv != CKR_OK)
	{
		if (*phPrivateKey != CK_INVALID_HANDLE)
		{
			OSObject* ospriv = (OSObject*)handleManager->getObject(*phPrivateKey);
			handleManager->destroyObject(*phPrivateKey);
			if (ospriv) ospriv->destroyObject();
			*phPrivateKey = CK_INVALID_HANDLE;
		}
		if (*phPublicKey != CK_INVALID_HANDLE)
		{
			OSObject* ospub = (OSObject*)handleManager->getObject(*phPublicKey);
			handleManager->destroyObject(*phPublicKey);
			if (ospub) ospub->destroyObject();
			*phPublicKey = CK_INVALID_HANDLE;
		}
	}
}

// Initialise the one-and-only instance

#ifdef HAVE_CXX11

std::unique_ptr<MutexFactory> MutexFactory::instance(nullptr);
std::unique_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(nullptr);
#if defined(WITH_OPENSSL)
std::unique_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(nullptr);
#else
std::unique_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(nullptr);
#endif
std::unique_ptr<SoftHSM> SoftHSM::instance(nullptr);

#else

std::auto_ptr<MutexFactory> MutexFactory::instance(NULL);
std::auto_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(NULL);
#if defined(WITH_OPENSSL)
std::auto_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(NULL);
#else
std::auto_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(NULL);
#endif
std::auto_ptr<SoftHSM> SoftHSM::instance(NULL);

#endif


/*****************************************************************************
 Implementation of SoftHSM class specific functions
 *****************************************************************************/
void resetMutexFactoryCallbacks()
{
	// Reset MutexFactory callbacks to our versions
	MutexFactory::i()->setCreateMutex(OSCreateMutex);
	MutexFactory::i()->setDestroyMutex(OSDestroyMutex);
	MutexFactory::i()->setLockMutex(OSLockMutex);
	MutexFactory::i()->setUnlockMutex(OSUnlockMutex);
}


// Return the one-and-only instance
SoftHSM* SoftHSM::i()
{
	if (!instance.get())
	{
		instance.reset(new SoftHSM());
	}
	else if(instance->detectFork())
	{
		if (Configuration::i()->getBool("library.reset_on_fork", false))
		{
			/* It is important to first clear the singleton
			 * instance, and then fill it again, so make sure
			 * the old instance is first destroyed as some
			 * static structures are erased in the destructor.
			 */
			instance.reset(NULL);
			instance.reset(new SoftHSM());
		}
	}

	return instance.get();
}

void SoftHSM::reset()
{
	if (instance.get())
		instance.reset();
}

// Constructor
SoftHSM::SoftHSM()
{
	isInitialised = false;
	isRemovable = false;
	sessionObjectStore = NULL;
	objectStore = NULL;
	slotManager = NULL;
	sessionManager = NULL;
	handleManager = NULL;
	resetMutexFactoryCallbacks();
#ifdef _WIN32
	forkID = _getpid();
#else
	forkID = getpid();
#endif
}

// Destructor
SoftHSM::~SoftHSM()
{
	if (handleManager != NULL) delete handleManager;
	handleManager = NULL;
	if (sessionManager != NULL) delete sessionManager;
	sessionManager = NULL;
	if (slotManager != NULL) delete slotManager;
	slotManager = NULL;
	if (objectStore != NULL) delete objectStore;
	objectStore = NULL;
	if (sessionObjectStore != NULL) delete sessionObjectStore;
	sessionObjectStore = NULL;

	mechanisms_table.clear();
	supportedMechanisms.clear();

	isInitialised = false;

	resetMutexFactoryCallbacks();
}

// Seed the random number generator with new data
CK_RV SoftHSM::C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pSeed == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the RNG
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;

	// Seed the RNG
	ByteString seed(pSeed, ulSeedLen);
	rng->seed(seed);

	return CKR_OK;
}

// Generate the specified amount of random data
CK_RV SoftHSM::C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pRandomData == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the RNG
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;

	// Generate random data
	ByteString randomData;
	if (!rng->generateRandom(randomData, ulRandomLen)) return CKR_GENERAL_ERROR;

	// Return random data
	if (ulRandomLen != 0)
	{
		memcpy(pRandomData, randomData.byte_str(), ulRandomLen);
	}

	return CKR_OK;
}

// Legacy function
CK_RV SoftHSM::C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_PARALLEL;
}

// Legacy function
CK_RV SoftHSM::C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return CKR_FUNCTION_NOT_PARALLEL;
}

// Wait or poll for a slot event on the specified slot
CK_RV SoftHSM::C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR /*pSlot*/, CK_VOID_PTR /*pReserved*/)
{
	if (!(flags & CKF_DONT_BLOCK)) return CKR_FUNCTION_NOT_SUPPORTED;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// SoftHSM slots don't change after it's initialised. With the
	// exception of when a slot is initialised and then getSlotList() is
	// called. However, at this point the caller has been updated with the
	// new slot list already so no event needs to be triggered.
	return CKR_NO_EVENT;
}

bool SoftHSM::isMechanismPermitted(OSObject* key, CK_MECHANISM_TYPE mechanism)
{
	std::list<CK_MECHANISM_TYPE> mechs = supportedMechanisms;
	/* First check if the algorithm is enabled in the global configuration */
	auto it = std::find(mechs.begin(), mechs.end(), mechanism);
	if (it == mechs.end())
		return false;

	/* If we have object, consult also its allowed mechanisms */
	if (key) {
		OSAttribute attribute = key->getAttribute(CKA_ALLOWED_MECHANISMS);
		std::set<CK_MECHANISM_TYPE> allowed = attribute.getMechanismTypeSetValue();

		/* empty allow list means we allowing everything that is built-in */
		if (allowed.empty()) {
			return true;
		}
		return allowed.find(mechanism) != allowed.end();
	} else {
		return true;
	}
}

bool SoftHSM::detectFork(void) {
#ifdef _WIN32
	return forkID != _getpid();
#else
	return forkID != getpid();
#endif
}
