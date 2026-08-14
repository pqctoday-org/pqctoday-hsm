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
#include "OpLog.h"
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

// C3 (2026-08-13): the OpenPGP certificate type was carried at 0x00000003, an
// UNASSIGNED OASIS codepoint below CKC_VENDOR_DEFINED — squatting a value the
// standard may allocate to something else. PKCS#11 v3.2 removed CKC_OPENPGP,
// and §2 reserves 0x80000000 upwards for vendors, so this fork's OpenPGP
// certificate type now lives there. Applications that used the old value get
// CKR_ATTRIBUTE_VALUE_INVALID, which is the correct answer for a codepoint this
// library does not define.
#ifndef CKC_OPENPGP
#define CKC_OPENPGP (CKC_VENDOR_DEFINED | 0x00000003UL)
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
#include <time.h>
#include <openssl/rand.h>
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
	// §2.4: resolve the key handle scoped to the calling session's slot — a handle minted
	// on another token must not be reachable here (cross-token reach -> handle invalid).
	outKey = (OSObject*)handleManager->getObject(hKey, outSession->getSlot()->getSlotID());
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

std::string SoftHSM::opLogKeyFields(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey,
                                    CK_MECHANISM_TYPE mech)
{
	static const char* unresolved = "key=- keytype=- paramset=-";

	if (handleManager == NULL) return unresolved;

	// The guard is taken and released entirely inside this function, before the
	// caller dispatches into the real operation, so it never overlaps the guard
	// that operation takes for itself.
	auto guard = handleManager->getSessionShared(hSession);
	Session* session = guard.get();
	if (session == NULL || session->getSlot() == NULL) return unresolved;

	OSObject* obj = (OSObject*)handleManager->getObject(hKey, session->getSlot()->getSlotID());
	if (obj == NULL || !obj->isValid()) return unresolved;

	// Every byte-string attribute of a private object -- CKA_LABEL included --
	// is stored encrypted at rest (P11Attribute::updateAttr). Reading it raw
	// yields the ciphertext, so private keys must be decrypted through the token
	// exactly as C_GetAttributeValue does. Decryption needs the token key, so it
	// fails when nobody is logged in; that reports "-" rather than ciphertext.
	ByteString label = obj->getByteStringValue(CKA_LABEL);
	if (label.size() > 0 && obj->getBooleanValue(CKA_PRIVATE, true))
	{
		Token* token = session->getToken();
		ByteString plain;
		if (token != NULL && token->decrypt(label, plain)) label = plain;
		else                                               label.wipe();
	}
	const std::string labelStr = (label.size() > 0)
		? OpLog::value(label.const_byte_str(), label.size())
		: std::string("-");

	const CK_KEY_TYPE keyType = obj->getUnsignedLongValue(CKA_KEY_TYPE, CK_UNAVAILABLE_INFORMATION);

	// CKA_PARAMETER_SET is absent on classical keys; "-" rather than a bogus 0.
	std::string paramSetStr = "-";
	if (obj->attributeExists(CKA_PARAMETER_SET))
	{
		const unsigned long ps = obj->getUnsignedLongValue(CKA_PARAMETER_SET, 0);
		paramSetStr = OpLog::paramSetName(mech, ps);
	}

	std::string out = "key=";
	out += labelStr;
	out += " keytype=";
	out += (keyType == CK_UNAVAILABLE_INFORMATION) ? "-" : OpLog::keyTypeName(keyType);
	out += " paramset=";
	out += paramSetStr;
	return out;
}

std::string SoftHSM::opLogKeyCustodyFields(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	static const char* unresolved =
		"extractable=- sensitive=- never_extractable=- always_sensitive=- local=-";

	if (handleManager == NULL) return unresolved;

	auto guard = handleManager->getSessionShared(hSession);
	Session* session = guard.get();
	if (session == NULL || session->getSlot() == NULL) return unresolved;

	OSObject* obj = (OSObject*)handleManager->getObject(hKey, session->getSlot()->getSlotID());
	if (obj == NULL || !obj->isValid()) return unresolved;

	// Each attribute is reported as "-" when absent rather than defaulted, so a
	// consumer can tell "the token says false" from "the token never said".
	struct { const char* name; CK_ATTRIBUTE_TYPE type; } fields[] = {
		{ "extractable",       CKA_EXTRACTABLE       },
		{ "sensitive",         CKA_SENSITIVE         },
		{ "never_extractable", CKA_NEVER_EXTRACTABLE },
		{ "always_sensitive",  CKA_ALWAYS_SENSITIVE  },
		{ "local",             CKA_LOCAL             },
	};

	std::string out;
	for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
	{
		if (i > 0) out += ' ';
		out += fields[i].name;
		out += '=';
		if (!obj->attributeExists(fields[i].type))
			out += '-';
		else
			out += obj->getBooleanValue(fields[i].type, false) ? "true" : "false";
	}
	return out;
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

// Intentionally leaked at process exit (LeakingPtr) so the PKCS#11 module
// survives C++ static-destruction ordering and stays valid for late atexit
// callbacks from OpenSSL provider teardown (C_CloseSession / C_Finalize).
// reset() still frees, so explicit teardown (C_Finalize, fork) does not leak.
LeakingPtr<MutexFactory> MutexFactory::instance(NULL);
LeakingPtr<SecureMemoryRegistry> SecureMemoryRegistry::instance(NULL);
#if defined(WITH_OPENSSL)
LeakingPtr<OSSLCryptoFactory> OSSLCryptoFactory::instance(NULL);
#else
LeakingPtr<BotanCryptoFactory> BotanCryptoFactory::instance(NULL);
#endif
LeakingPtr<SoftHSM> SoftHSM::instance(NULL);


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
		else
		{
			/* Default: fork-tolerant semantics (CK_INTERFACE Table 11).
			 * The child keeps its copy-on-write copy of every session,
			 * handle, login state and session object, which is what the
			 * flag promises.
			 *
			 * The Standard says nothing about the one thing that copy
			 * makes dangerous: the child also inherits the deterministic
			 * random-generator state, so without intervention two
			 * children of one parent emit IDENTICAL streams — repeated
			 * ECDSA nonces, hence recoverable private keys, with no
			 * visible symptom. OpenSSL 3.x does detect forks and reseed,
			 * but that is a property of how the linked libcrypto was
			 * built (it can be compiled out), not of this engine. Making
			 * the reseed explicit here turns the guarantee into one this
			 * code owns and can be tested for.
			 *
			 * RAND_poll() pulls fresh operating-system entropy; the pid
			 * and clock are mixed in with an entropy estimate of zero,
			 * as a distinguishing nonce rather than a claimed source. */
			instance->reseedAfterFork();
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

	// C2 (2026-08-13) — session-handle precedence. The session-handle error
	// class takes precedence over argument and capability codes, so the handle
	// is validated BEFORE the buffer argument; this used to answer
	// CKR_ARGUMENTS_BAD to a call that named a session that does not exist.
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (pSeed == NULL_PTR) return CKR_ARGUMENTS_BAD;

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

	// C2 (2026-08-13) — session-handle precedence. The session-handle error
	// class takes precedence over argument and capability codes, so the handle
	// is validated BEFORE the buffer argument; this used to answer
	// CKR_ARGUMENTS_BAD to a call that named a session that does not exist.
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if (pRandomData == NULL_PTR) return CKR_ARGUMENTS_BAD;

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
	// C2 — §5.4 makes C_Initialize, C_GetFunctionList, C_GetInterfaceList and
	// C_GetInterface the ONLY functions callable before initialisation, so the
	// initialisation check outranks the capability check on flags. This tested
	// flags first and answered CKR_FUNCTION_NOT_SUPPORTED to a pre-init caller.
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!(flags & CKF_DONT_BLOCK)) return CKR_FUNCTION_NOT_SUPPORTED;

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

// Called once per detected fork on the fork-tolerant path. Idempotent by way of
// the forkID update: subsequent calls in the same process no longer detect a
// fork, so the reseed happens once, before the child's first random draw (every
// C_* entry point reaches this through SoftHSM::i()).
void SoftHSM::reseedAfterFork(void)
{
	RAND_poll();

	struct {
		long pid;
		long long tick;
		const void* self;
	} nonce;
#ifdef _WIN32
	nonce.pid = (long)_getpid();
#else
	nonce.pid = (long)getpid();
#endif
	nonce.tick = (long long)time(NULL);
	nonce.self = (const void*)this;
	RAND_add(&nonce, (int)sizeof(nonce), 0.0);

#ifdef _WIN32
	forkID = _getpid();
#else
	forkID = getpid();
#endif
}

bool SoftHSM::detectFork(void) {
#ifdef _WIN32
	return forkID != _getpid();
#else
	return forkID != getpid();
#endif
}
