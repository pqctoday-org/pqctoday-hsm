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
 SoftHSM_slots.cpp

 PKCS#11 slot and token management: C_Initialize, C_Finalize, C_GetInfo,
 C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, prepareSupportedMechanisms,
 C_GetMechanismList, C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OpLog.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "SessionManager.h"
#include "SessionObjectStore.h"
#include "CryptoFactory.h"
#include "SimpleConfigLoader.h"
#include <stdexcept>
#include "SimpleConfigLoader.h"
#include "MutexFactory.h"
#include "SecureMemoryRegistry.h"
#include "cryptoki.h"
#include "SlotManager.h"
#include "odd.h"
#include "vendor_mechanisms.h"

#if defined(WITH_OPENSSL)
#include "OSSLCryptoFactory.h"
#else
#include "BotanCryptoFactory.h"
#endif

#include <cstdlib>

// Set by an atexit() handler so C_Finalize can tell it is being called during
// process teardown. The pkcs11-provider unloads us from OpenSSL's OPENSSL_cleanup
// (an atexit handler), which calls C_Finalize. By then OpenSSL's own globals
// (RAND method locks, EVP fetch tables) are already being freed, so any teardown
// that reaches back into OpenSSL — RAND_set_rand_method, EVP_MD_free, provider
// unload via CryptoFactory::reset — dereferences freed state and crashes.
//
// SoftHSM is initialised AFTER OpenSSL, so this handler is registered after
// OpenSSL's cleanup and therefore runs BEFORE it (atexit is LIFO). When the
// provider's C_Finalize then runs, the flag is already set and we skip the
// OpenSSL-touching teardown — the OS reclaims everything at exit. This is the
// companion to the LeakingPtr singleton-lifetime fix (see LeakingPtr.h).
static bool g_processExiting = false;
static void softhsm_mark_exiting() { g_processExiting = true; }

/*****************************************************************************
 Implementation of PKCS #11 functions
 *****************************************************************************/

// PKCS #11 initialisation function
CK_RV SoftHSM::C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_C_INITIALIZE_ARGS_PTR args;

	// Register the process-teardown sentinel once. Done here (after OpenSSL is
	// up) so it runs before OpenSSL's atexit cleanup — see g_processExiting.
	static bool exitHandlerRegistered = false;
	if (!exitHandlerRegistered)
	{
		atexit(softhsm_mark_exiting);
		exitHandlerRegistered = true;
	}

	// Check if PKCS#11 is already initialized
	if (isInitialised)
	{
		WARNING_MSG("SoftHSM is already initialized");
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}

	// Do we have any arguments?
	if (pInitArgs != NULL_PTR)
	{
		args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

		// Per PKCS#11, pInitArgs->pReserved SHALL be NULL_PTR; a non-NULL value
		// is CKR_ARGUMENTS_BAD (V-20).  The previous build dereferenced any
		// pReserved >= 4096 as an ACVP test-seed struct, which both violates the
		// spec and is a crash/UB risk on arbitrary caller pointers.  The ACVP
		// deterministic-seed backdoor is now compiled out by default and only
		// reachable behind WITH_ACVP_SEED for the conformance harness.
		if (args->pReserved != NULL_PTR)
		{
#ifdef WITH_ACVP_SEED
			// Guarded ACVP seed injection — NOT part of a normal build.
			// pReserved points to {CK_ULONG seedPtr, CK_ULONG seedLen(==32)}.
			if ((uintptr_t)args->pReserved >= 4096)
			{
				CK_ULONG* acvpArgs = (CK_ULONG*)args->pReserved;
				if (acvpArgs[0] != 0 && acvpArgs[1] == 32)
				{
					extern void OSSLRNG_enableACVP(unsigned char* seed);
					OSSLRNG_enableACVP((unsigned char*)(uintptr_t)acvpArgs[0]);
				}
				else
				{
					ERROR_MSG("pReserved must be NULL_PTR (or valid ACVP args under WITH_ACVP_SEED)");
					return CKR_ARGUMENTS_BAD;
				}
			}
			else
			{
				ERROR_MSG("pReserved must be set to NULL_PTR");
				return CKR_ARGUMENTS_BAD;
			}
#else
			ERROR_MSG("pInitArgs->pReserved must be set to NULL_PTR");
			return CKR_ARGUMENTS_BAD;
#endif
		}

		// Can we spawn our own threads?
		// if (args->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
		// {
		//	DEBUG_MSG("Cannot create threads if CKF_LIBRARY_CANT_CREATE_OS_THREADS is set");
		//	return CKR_NEED_TO_CREATE_THREADS;
		// }

		// Are we not supplied with mutex functions?
		if
		(
			args->CreateMutex == NULL_PTR &&
			args->DestroyMutex == NULL_PTR &&
			args->LockMutex == NULL_PTR &&
			args->UnlockMutex == NULL_PTR
		)
		{
			// Can we use our own mutex functions?
			if (args->flags & CKF_OS_LOCKING_OK)
			{
				// Use our own mutex functions.
				resetMutexFactoryCallbacks();
				MutexFactory::i()->enable();
			}
			else
			{
				// The external application is not using threading
				MutexFactory::i()->disable();
			}
		}
		else
		{
			// We must have all mutex functions
			if
			(
				args->CreateMutex == NULL_PTR ||
				args->DestroyMutex == NULL_PTR ||
				args->LockMutex == NULL_PTR ||
				args->UnlockMutex == NULL_PTR
			)
			{
				ERROR_MSG("Not all mutex functions are supplied");
				return CKR_ARGUMENTS_BAD;
			}

			// We could use our own mutex functions if the flag is set,
			// but we use the external functions in both cases.

			// Load the external mutex functions
			MutexFactory::i()->setCreateMutex(args->CreateMutex);
			MutexFactory::i()->setDestroyMutex(args->DestroyMutex);
			MutexFactory::i()->setLockMutex(args->LockMutex);
			MutexFactory::i()->setUnlockMutex(args->UnlockMutex);
			MutexFactory::i()->enable();
		}
	}
	else
	{
		// No concurrent access by multiple threads
		MutexFactory::i()->disable();
	}

	// Initiate SecureMemoryRegistry
	if (SecureMemoryRegistry::i() == NULL)
	{
		ERROR_MSG("Could not load the SecureMemoryRegistry");
		return CKR_GENERAL_ERROR;
	}

	// Build the CryptoFactory
	if (CryptoFactory::i() == NULL)
	{
		ERROR_MSG("Could not load the CryptoFactory");
		return CKR_GENERAL_ERROR;
	}

#ifdef WITH_FIPS
	// Check the FIPS status
	if (!CryptoFactory::i()->getFipsSelfTestStatus())
	{
		ERROR_MSG("The FIPS self test failed");
		return CKR_FIPS_SELF_TEST_FAILED;
	}
#endif

	// (Re)load the configuration
	if (!Configuration::i()->reload(SimpleConfigLoader::i()))
	{
		ERROR_MSG("Could not load the configuration");
		return CKR_GENERAL_ERROR;
	}

	// Configure the log level
	if (!setLogLevel(Configuration::i()->getString("log.level", DEFAULT_LOG_LEVEL)))
	{
		ERROR_MSG("Could not set the log level");
		return CKR_GENERAL_ERROR;
	}

	// Open the operation-evidence log if SOFTHSM3_OP_LOG names a sink. Runtime
	// gated on purpose (see OpLog.h): the shipped binary and the binary evidence
	// is collected from must be the same binary.
	OpLog::init();

	// Configure object store storage backend used by all tokens.
	if (!ObjectStoreToken::selectBackend(Configuration::i()->getString("objectstore.backend", DEFAULT_OBJECTSTORE_BACKEND)))
	{
		ERROR_MSG("Could not set the storage backend");
		return CKR_GENERAL_ERROR;
	}

	sessionObjectStore = new SessionObjectStore();

	// Load the object store
	objectStore = new ObjectStore(Configuration::i()->getString("directories.tokendir", DEFAULT_TOKENDIR),
		Configuration::i()->getInt("objectstore.umask", DEFAULT_UMASK));
	if (!objectStore->isValid())
	{
		WARNING_MSG("Could not load the object store");
		delete objectStore;
		objectStore = NULL;
		delete sessionObjectStore;
		sessionObjectStore = NULL;
		return CKR_GENERAL_ERROR;
	}

	// Load the enabled list of algorithms
	prepareSupportedMechanisms(mechanisms_table);

	isRemovable = Configuration::i()->getBool("slots.removable", false);

	// Load the slot manager
	slotManager = new SlotManager(objectStore);

	// Load the session manager
	sessionManager = new SessionManager();

	// Load the handle manager
	handleManager = new HandleManager();

	// Set the state to initialised
	isInitialised = true;

	return CKR_OK;
}

// PKCS #11 finalisation function
CK_RV SoftHSM::C_Finalize(CK_VOID_PTR pReserved)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Must be set to NULL_PTR in this version of PKCS#11
	if (pReserved != NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Close the evidence sink before the teardown branch below, so a run that
	// ends via process exit still leaves a properly closed, complete log.
	OpLog::shutdown();

	// During process teardown (OpenSSL's atexit cleanup unloading the provider),
	// OpenSSL's globals are already being freed. The cleanup below reaches back
	// into OpenSSL (RAND_set_rand_method, EVP_MD_free, provider unload), which
	// would dereference freed state and crash. Skip it — the OS reclaims all of
	// it at exit. See g_processExiting and LeakingPtr.h.
	if (g_processExiting)
	{
		isInitialised = false;
		return CKR_OK;
	}

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
	CryptoFactory::reset();
	SecureMemoryRegistry::reset();

	// Clean up ACVP deterministic PRNG state if active
	extern void OSSLRNG_disableACVP();
	OSSLRNG_disableACVP();

	// Free lazily-cached EVP_MD* objects from pre-hash tables (CR-03)
	extern void OSSLMLDSA_cleanupPreHashCache();
	extern void OSSLSLHDSA_cleanupPreHashCache();
	OSSLMLDSA_cleanupPreHashCache();
	OSSLSLHDSA_cleanupPreHashCache();

	isInitialised = false;

	supportedMechanisms.clear();

	SoftHSM::reset();
	return CKR_OK;
}

// Return information about the PKCS #11 module
CK_RV SoftHSM::C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	memset(pInfo->manufacturerID, ' ', 32);
	memcpy(pInfo->manufacturerID, "SoftHSM", 7);
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', 32);
#ifdef WITH_FIPS
	memcpy(pInfo->libraryDescription, "Implementation of PKCS11+FIPS", 29);
#else
	memcpy(pInfo->libraryDescription, "Implementation of PKCS11", 24);
#endif
	pInfo->libraryVersion.major = VERSION_MAJOR;
	pInfo->libraryVersion.minor = VERSION_MINOR;

	return CKR_OK;
}

// Return a list of available slots
CK_RV SoftHSM::C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	return slotManager->getSlotList(objectStore, tokenPresent, pSlotList, pulCount);
}

// Return information about a slot
CK_RV SoftHSM::C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv;
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	rv = slot->getSlotInfo(pInfo);
	if (rv != CKR_OK) {
		return rv;
	}

	if (isRemovable) {
		pInfo->flags |= CKF_REMOVABLE_DEVICE;
	}

	return CKR_OK;
}

// Return information about a token in a slot
CK_RV SoftHSM::C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	Token* token = slot->getToken();
	if (token == NULL)
	{
		return CKR_TOKEN_NOT_PRESENT;
	}

	return token->getTokenInfo(pInfo);
}

void SoftHSM::prepareSupportedMechanisms(std::map<std::string, CK_MECHANISM_TYPE> &t)
{
	// Hash algorithms (SHA-1, SHA-2 + SHA-3)
#ifndef WITH_FIPS
	// MD5 digest is accepted by C_DigestInit in non-FIPS builds; advertise it
	// so C_GetMechanismList matches dispatch (audit G5).
	t["CKM_MD5"]			= CKM_MD5;
#endif
#ifdef WITH_RIPEMD160
	// RIPEMD-160 digest: native builds load the OpenSSL legacy provider, so
	// C_DigestInit dispatches it (G-DA-X). The WASM/no-legacy build omits this
	// (advertise == dispatch — C_DigestInit returns CKR_MECHANISM_INVALID, G1).
	t["CKM_RIPEMD160"]		= CKM_RIPEMD160;
#endif
	t["CKM_SHA_1"]			= CKM_SHA_1;
	t["CKM_SHA224"]			= CKM_SHA224;
	t["CKM_SHA256"]			= CKM_SHA256;
	t["CKM_SHA384"]			= CKM_SHA384;
	t["CKM_SHA512"]			= CKM_SHA512;
	t["CKM_SHA3_224"]		= CKM_SHA3_224;
	t["CKM_SHA3_256"]		= CKM_SHA3_256;
	t["CKM_SHA3_384"]		= CKM_SHA3_384;
	t["CKM_SHA3_512"]		= CKM_SHA3_512;

	// HMAC (SHA-1, SHA-2 + SHA-3)
#ifndef WITH_FIPS
	// MD5-HMAC dispatches via resolveMacMech() in non-FIPS builds (audit G5).
	t["CKM_MD5_HMAC"]		= CKM_MD5_HMAC;
#endif
#ifdef WITH_RIPEMD160
	// HMAC-RIPEMD-160 dispatches via kMacMechTable on native builds (G-DA-X);
	// absent (== rejected) on the WASM/no-legacy build (advertise == dispatch).
	t["CKM_RIPEMD160_HMAC"]		= CKM_RIPEMD160_HMAC;
#endif
	t["CKM_SHA_1_HMAC"]		= CKM_SHA_1_HMAC;
	t["CKM_SHA224_HMAC"]		= CKM_SHA224_HMAC;
	t["CKM_SHA256_HMAC"]		= CKM_SHA256_HMAC;
	t["CKM_SHA384_HMAC"]		= CKM_SHA384_HMAC;
	t["CKM_SHA512_HMAC"]		= CKM_SHA512_HMAC;
	t["CKM_SHA3_224_HMAC"]		= CKM_SHA3_224_HMAC;
	t["CKM_SHA3_256_HMAC"]		= CKM_SHA3_256_HMAC;
	t["CKM_SHA3_384_HMAC"]		= CKM_SHA3_384_HMAC;
	t["CKM_SHA3_512_HMAC"]		= CKM_SHA3_512_HMAC;

	// PBKDF2 (PKCS#11 v3.2 §5.7.3.1)
	t["CKM_PKCS5_PBKD2"]		= CKM_PKCS5_PBKD2;

	// HKDF (PKCS#11 v3.0+ §2.43)
	t["CKM_HKDF_DERIVE"]		= CKM_HKDF_DERIVE;
	t["CKM_HKDF_DATA"]		= CKM_HKDF_DATA;

	// NIST SP 800-108 KBKDFs (PKCS#11 v3.2 §2.44)
	t["CKM_SP800_108_COUNTER_KDF"]	= CKM_SP800_108_COUNTER_KDF;
	t["CKM_SP800_108_FEEDBACK_KDF"]	= CKM_SP800_108_FEEDBACK_KDF;
	// SHAKE-256 as an XOF-based KDF. Needed by X-Wing, whose 32-byte
	// decapsulation key expands to 96 bytes of ML-KEM + X25519 key material.
	t["CKM_SHAKE_256_KEY_DERIVATION"]	= CKM_SHAKE_256_KEY_DERIVATION;

	// RSA
	t["CKM_RSA_PKCS_KEY_PAIR_GEN"]	= CKM_RSA_PKCS_KEY_PAIR_GEN;
	t["CKM_RSA_PKCS"]		= CKM_RSA_PKCS;
	t["CKM_RSA_X_509"]		= CKM_RSA_X_509;
#ifndef WITH_FIPS
	// MD5-RSA-PKCS dispatches in non-FIPS builds (audit G5).
	t["CKM_MD5_RSA_PKCS"]		= CKM_MD5_RSA_PKCS;
#endif
#ifdef WITH_RAW_PSS
	// Raw RSA-PSS (CKM_RSA_PKCS_PSS) is accepted by Sign/Verify Init and
	// GetMechanismInfo; advertise it so C_GetMechanismList matches (audit G4).
	t["CKM_RSA_PKCS_PSS"]		= CKM_RSA_PKCS_PSS;
#endif
	t["CKM_SHA1_RSA_PKCS"]		= CKM_SHA1_RSA_PKCS;
	t["CKM_RSA_PKCS_OAEP"]		= CKM_RSA_PKCS_OAEP;
	t["CKM_RSA_AES_KEY_WRAP"]	= CKM_RSA_AES_KEY_WRAP;
	t["CKM_SHA224_RSA_PKCS"]	= CKM_SHA224_RSA_PKCS;
	t["CKM_SHA256_RSA_PKCS"]	= CKM_SHA256_RSA_PKCS;
	t["CKM_SHA384_RSA_PKCS"]	= CKM_SHA384_RSA_PKCS;
	t["CKM_SHA512_RSA_PKCS"]	= CKM_SHA512_RSA_PKCS;
	t["CKM_SHA1_RSA_PKCS_PSS"]	= CKM_SHA1_RSA_PKCS_PSS;
	t["CKM_SHA224_RSA_PKCS_PSS"]	= CKM_SHA224_RSA_PKCS_PSS;
	t["CKM_SHA256_RSA_PKCS_PSS"]	= CKM_SHA256_RSA_PKCS_PSS;
	t["CKM_SHA384_RSA_PKCS_PSS"]	= CKM_SHA384_RSA_PKCS_PSS;
	t["CKM_SHA512_RSA_PKCS_PSS"]	= CKM_SHA512_RSA_PKCS_PSS;
	t["CKM_SHA3_224_RSA_PKCS"]	= CKM_SHA3_224_RSA_PKCS;
	t["CKM_SHA3_256_RSA_PKCS"]	= CKM_SHA3_256_RSA_PKCS;
	t["CKM_SHA3_384_RSA_PKCS"]	= CKM_SHA3_384_RSA_PKCS;
	t["CKM_SHA3_512_RSA_PKCS"]	= CKM_SHA3_512_RSA_PKCS;
	t["CKM_SHA3_224_RSA_PKCS_PSS"]	= CKM_SHA3_224_RSA_PKCS_PSS;
	t["CKM_SHA3_256_RSA_PKCS_PSS"]	= CKM_SHA3_256_RSA_PKCS_PSS;
	t["CKM_SHA3_384_RSA_PKCS_PSS"]	= CKM_SHA3_384_RSA_PKCS_PSS;
	t["CKM_SHA3_512_RSA_PKCS_PSS"]	= CKM_SHA3_512_RSA_PKCS_PSS;

	// AES (DES/DES3 removed)
	t["CKM_GENERIC_SECRET_KEY_GEN"]	= CKM_GENERIC_SECRET_KEY_GEN;
	t["CKM_AES_KEY_GEN"]		= CKM_AES_KEY_GEN;
	t["CKM_AES_ECB"]		= CKM_AES_ECB;
	t["CKM_AES_CBC"]		= CKM_AES_CBC;
	t["CKM_AES_CBC_PAD"]		= CKM_AES_CBC_PAD;
	t["CKM_AES_CTR"]		= CKM_AES_CTR;
	t["CKM_AES_GCM"]		= CKM_AES_GCM;
	t["CKM_AES_KEY_WRAP"]		= CKM_AES_KEY_WRAP;
#ifdef HAVE_AES_KEY_WRAP_PAD
	t["CKM_AES_KEY_WRAP_PAD"]	= CKM_AES_KEY_WRAP_PAD;
#endif
	t["CKM_AES_ECB_ENCRYPT_DATA"]	= CKM_AES_ECB_ENCRYPT_DATA;
	t["CKM_AES_CBC_ENCRYPT_DATA"]	= CKM_AES_CBC_ENCRYPT_DATA;
	t["CKM_AES_CMAC"]		= CKM_AES_CMAC;

	// ChaCha20 — bare stream (CKM_CHACHA20) and AEAD (CKM_CHACHA20_POLY1305)
	// are both dispatched (audit V-10 fixed by implementing the bare stream).
	t["CKM_CHACHA20_KEY_GEN"]	= CKM_CHACHA20_KEY_GEN;
	t["CKM_CHACHA20_POLY1305"]	= CKM_CHACHA20_POLY1305;
	t["CKM_CHACHA20"]		= CKM_CHACHA20;

	// KMAC
	t["CKM_KMAC_128"]		= CKM_KMAC_128;
	t["CKM_KMAC_256"]		= CKM_KMAC_256;

	// ECDSA + ECDH (DSA and DH PKCS removed)
	t["CKM_EC_KEY_PAIR_GEN"]	= CKM_EC_KEY_PAIR_GEN;
	t["CKM_ECDSA"]			= CKM_ECDSA;
	t["CKM_ECDSA_SHA1"]		= CKM_ECDSA_SHA1;
	t["CKM_ECDSA_SHA224"]		= CKM_ECDSA_SHA224;
	t["CKM_ECDSA_SHA256"]		= CKM_ECDSA_SHA256;
	t["CKM_ECDSA_SHA384"]		= CKM_ECDSA_SHA384;
	t["CKM_ECDSA_SHA512"]		= CKM_ECDSA_SHA512;
	t["CKM_ECDSA_SHA3_224"]		= CKM_ECDSA_SHA3_224;
	t["CKM_ECDSA_SHA3_256"]		= CKM_ECDSA_SHA3_256;
	t["CKM_ECDSA_SHA3_384"]		= CKM_ECDSA_SHA3_384;
	t["CKM_ECDSA_SHA3_512"]		= CKM_ECDSA_SHA3_512;
	t["CKM_ECDH1_DERIVE"]		= CKM_ECDH1_DERIVE;
	t["CKM_ECDH1_COFACTOR_DERIVE"]	= CKM_ECDH1_COFACTOR_DERIVE;

	// Montgomery X25519/X448 derive + BIP32 hierarchical derive (audit G6).
	// These are handled by the C_DeriveKey switch but were absent from the
	// advertised table, so isMechanismPermitted always rejected them. Values
	// are now vendor-spaced post-F1 (CKM_VENDOR_DEFINED | …).
	t["CKM_X25519"]			= CKM_X25519;
	t["CKM_X448"]			= CKM_X448;
	t["CKM_BIP32_MASTER_DERIVE"]	= CKM_BIP32_MASTER_DERIVE;
	t["CKM_BIP32_CHILD_DERIVE"]	= CKM_BIP32_CHILD_DERIVE;

	// EdDSA / Montgomery
	t["CKM_EC_EDWARDS_KEY_PAIR_GEN"]    = CKM_EC_EDWARDS_KEY_PAIR_GEN;
	t["CKM_EC_MONTGOMERY_KEY_PAIR_GEN"] = CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
	t["CKM_EDDSA"]			= CKM_EDDSA;
	t["CKM_EDDSA_PH"]		= CKM_EDDSA_PH;

	// ML-DSA (FIPS 204, PKCS#11 v3.2)
	t["CKM_ML_DSA_KEY_PAIR_GEN"]	= CKM_ML_DSA_KEY_PAIR_GEN;
	t["CKM_ML_DSA"]			= CKM_ML_DSA;
	t["CKM_HASH_ML_DSA"]		= CKM_HASH_ML_DSA;
	t["CKM_HASH_ML_DSA_SHA224"]	= CKM_HASH_ML_DSA_SHA224;
	t["CKM_HASH_ML_DSA_SHA256"]	= CKM_HASH_ML_DSA_SHA256;
	t["CKM_HASH_ML_DSA_SHA384"]	= CKM_HASH_ML_DSA_SHA384;
	t["CKM_HASH_ML_DSA_SHA512"]	= CKM_HASH_ML_DSA_SHA512;
	t["CKM_HASH_ML_DSA_SHA3_224"]	= CKM_HASH_ML_DSA_SHA3_224;
	t["CKM_HASH_ML_DSA_SHA3_256"]	= CKM_HASH_ML_DSA_SHA3_256;
	t["CKM_HASH_ML_DSA_SHA3_384"]	= CKM_HASH_ML_DSA_SHA3_384;
	t["CKM_HASH_ML_DSA_SHA3_512"]	= CKM_HASH_ML_DSA_SHA3_512;
	t["CKM_HASH_ML_DSA_SHAKE128"]	= CKM_HASH_ML_DSA_SHAKE128;
	t["CKM_HASH_ML_DSA_SHAKE256"]	= CKM_HASH_ML_DSA_SHAKE256;
	// External-µ (remediation R34, PQCTODAY-VENDOR-EXT-MU) — stopgap for
	// PKCS#11 v3.3's own upcoming native mechanism (oasis-tcs/pkcs11#58).
	t["CKM_PQCTODAY_ML_DSA_MU"]	= CKM_PQCTODAY_ML_DSA_MU;
	// Token-side µ generation (remediation R39, phase 8, PQCTODAY-VENDOR-EXT-MU)
	// — the PRODUCE half of external-µ; a C_Digest-family mechanism, not sign/verify.
	t["CKM_PQCTODAY_ML_DSA_MU_GEN"] = CKM_PQCTODAY_ML_DSA_MU_GEN;

	// SLH-DSA (FIPS 205, PKCS#11 v3.2)
	t["CKM_SLH_DSA_KEY_PAIR_GEN"]	= CKM_SLH_DSA_KEY_PAIR_GEN;
	t["CKM_SLH_DSA"]		= CKM_SLH_DSA;
	t["CKM_HASH_SLH_DSA"]          = CKM_HASH_SLH_DSA;
	t["CKM_HASH_SLH_DSA_SHA224"]   = CKM_HASH_SLH_DSA_SHA224;
	t["CKM_HASH_SLH_DSA_SHA256"]   = CKM_HASH_SLH_DSA_SHA256;
	t["CKM_HASH_SLH_DSA_SHA384"]   = CKM_HASH_SLH_DSA_SHA384;
	t["CKM_HASH_SLH_DSA_SHA512"]   = CKM_HASH_SLH_DSA_SHA512;
	t["CKM_HASH_SLH_DSA_SHA3_224"] = CKM_HASH_SLH_DSA_SHA3_224;
	t["CKM_HASH_SLH_DSA_SHA3_256"] = CKM_HASH_SLH_DSA_SHA3_256;
	t["CKM_HASH_SLH_DSA_SHA3_384"] = CKM_HASH_SLH_DSA_SHA3_384;
	t["CKM_HASH_SLH_DSA_SHA3_512"] = CKM_HASH_SLH_DSA_SHA3_512;
	t["CKM_HASH_SLH_DSA_SHAKE128"] = CKM_HASH_SLH_DSA_SHAKE128;
	t["CKM_HASH_SLH_DSA_SHAKE256"] = CKM_HASH_SLH_DSA_SHAKE256;

	// ML-KEM (FIPS 203, PKCS#11 v3.2)
	t["CKM_ML_KEM_KEY_PAIR_GEN"]	= CKM_ML_KEM_KEY_PAIR_GEN;
	t["CKM_ML_KEM"]			= CKM_ML_KEM;

	// LMS / HSS stateful hash-based signatures (G10)
	// CKM_HSS / CKM_HSS_KEY_PAIR_GEN are standard PKCS#11 v3.2 §6.65
	t["CKM_HSS_KEY_PAIR_GEN"]	= CKM_HSS_KEY_PAIR_GEN;
	t["CKM_HSS"]			= CKM_HSS;
	t["CKM_XMSS_KEY_PAIR_GEN"]      = 0x00004034;
	t["CKM_XMSSMT_KEY_PAIR_GEN"]    = 0x00004035;
	t["CKM_XMSS"]                   = 0x00004036;
	t["CKM_XMSSMT"]                 = 0x00004037;

	// CKM_KECCAK_256 is NOT advertised: C_DigestInit returns
	// CKR_MECHANISM_INVALID for it (Rust engine only). Advertising it would be
	// advertise-without-dispatch (audit G3).

	t["CKM_CONCATENATE_DATA_AND_BASE"] = CKM_CONCATENATE_DATA_AND_BASE;
	t["CKM_CONCATENATE_BASE_AND_DATA"] = CKM_CONCATENATE_BASE_AND_DATA;
	t["CKM_CONCATENATE_BASE_AND_KEY"] = CKM_CONCATENATE_BASE_AND_KEY;

	supportedMechanisms.clear();
	for (auto it = t.begin(); it != t.end(); ++it)
	{
		supportedMechanisms.push_back(it->second);
	}

	/* Check configuration for supported algorithms */
	std::string mechs = Configuration::i()->getString("slots.mechanisms", "ALL");
	if (mechs != "ALL")
	{
		bool negative = (mechs[0] == '-');
		size_t pos = 0, prev = 0;
		if (negative)
		{
			/* Skip the minus sign */
			prev = 1;
		}
		else
		{
			/* For positive list, we remove everything */
			supportedMechanisms.clear();
		}
		std::string token;
		do
		{
			pos = mechs.find(",", prev);
			if (pos == std::string::npos) pos = mechs.length();
			token = mechs.substr(prev, pos - prev);
			CK_MECHANISM_TYPE mechanism;
			try
			{
				mechanism = t.at(token);
				if (!negative)
					supportedMechanisms.push_back(mechanism);
				else
					supportedMechanisms.remove(mechanism);
			}
			catch (const std::out_of_range& e)
			{
				WARNING_MSG("Unknown mechanism provided: %s", token.c_str());
			}
			prev = pos + 1;
		}
		while (pos < mechs.length() && prev < mechs.length());
	}

	nrSupportedMechanisms = supportedMechanisms.size();
}

// Return the list of supported mechanisms for a given slot
CK_RV SoftHSM::C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	if (pMechanismList == NULL_PTR)
	{
		*pulCount = nrSupportedMechanisms;

		return CKR_OK;
	}

	if (*pulCount < nrSupportedMechanisms)
	{
		*pulCount = nrSupportedMechanisms;

		return CKR_BUFFER_TOO_SMALL;
	}

	*pulCount = nrSupportedMechanisms;

	int i = 0;
	auto it = supportedMechanisms.cbegin();
	for (; it != supportedMechanisms.cend(); it++, i++)
	{
		pMechanismList[i] = *it;
	}

	return CKR_OK;
}

// Return more information about a mechanism for a given slot
CK_RV SoftHSM::C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	unsigned long rsaMinSize, rsaMaxSize;
#ifdef WITH_ECC
	unsigned long ecdsaMinSize, ecdsaMaxSize;
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
	unsigned long ecdhMinSize = 0, ecdhMaxSize = 0;
	unsigned long eddsaMinSize = 0, eddsaMaxSize = 0;
#endif

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}
	if (!isMechanismPermitted(NULL, type))
		return CKR_MECHANISM_INVALID;

	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (rsa != NULL)
	{
		rsaMinSize = rsa->getMinKeySize();
		rsaMaxSize = rsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);



#ifdef WITH_ECC
	AsymmetricAlgorithm* ecdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ecdsa != NULL)
	{
		ecdsaMinSize = ecdsa->getMinKeySize();
		ecdsaMaxSize = ecdsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);

	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);
	if (ecdh != NULL)
	{
		ecdhMinSize = ecdh->getMinKeySize();
		ecdhMaxSize = ecdh->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
#endif

#ifdef WITH_EDDSA
	AsymmetricAlgorithm* eddsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (eddsa != NULL)
	{
		eddsaMinSize = eddsa->getMinKeySize();
		eddsaMaxSize = eddsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
	CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
#endif
	pInfo->flags = 0;	// initialize flags
	switch (type)
	{
#ifndef WITH_FIPS
		case CKM_MD5:
#endif
#ifdef WITH_RIPEMD160
		case CKM_RIPEMD160:
#endif
		case CKM_SHA_1:
		case CKM_SHA224:
		case CKM_SHA256:
		case CKM_SHA384:
		case CKM_SHA512:
		case CKM_SHA3_224:
		case CKM_SHA3_256:
		case CKM_SHA3_384:
		case CKM_SHA3_512:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;
#ifndef WITH_FIPS
		case CKM_MD5_HMAC:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
#ifdef WITH_RIPEMD160
		case CKM_RIPEMD160_HMAC:
			pInfo->ulMinKeySize = 20;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
		case CKM_SHA_1_HMAC:
			pInfo->ulMinKeySize = 20;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA224_HMAC:
			pInfo->ulMinKeySize = 28;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA256_HMAC:
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA384_HMAC:
			pInfo->ulMinKeySize = 48;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA512_HMAC:
			pInfo->ulMinKeySize = 64;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA3_224_HMAC:
			pInfo->ulMinKeySize = 28;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA3_256_HMAC:
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA3_384_HMAC:
			pInfo->ulMinKeySize = 48;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA3_512_HMAC:
			pInfo->ulMinKeySize = 64;
			pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		// C3 (2026-08-13): each mechanism flag is DEFINED as "the mechanism can
		// be used with function F". C_SignRecoverInit / C_VerifyRecoverInit
		// explicitly accept exactly these two mechanisms (SoftHSM_sign.cpp), so
		// advertising neither CKF_SIGN_RECOVER nor CKF_VERIFY_RECOVER meant a
		// caller doing the correct thing — checking the advertisement first —
		// would never reach a working feature.
		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP |
			               CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER;
			break;
		case CKM_RSA_X_509:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT |
			               CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER;
			break;
#ifndef WITH_FIPS
		case CKM_MD5_RSA_PKCS:
#endif
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA224_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
#endif
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA224_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_SHA3_224_RSA_PKCS:
		case CKM_SHA3_256_RSA_PKCS:
		case CKM_SHA3_384_RSA_PKCS:
		case CKM_SHA3_512_RSA_PKCS:
		case CKM_SHA3_224_RSA_PKCS_PSS:
		case CKM_SHA3_256_RSA_PKCS_PSS:
		case CKM_SHA3_384_RSA_PKCS_PSS:
		case CKM_SHA3_512_RSA_PKCS_PSS:
			// CKF_MESSAGE_SIGN/VERIFY: the message sign API delegates to
			// AsymSignInit, which accepts these RSA mechanisms (audit mech G2).
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY |
			               CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY;
			break;
		case CKM_RSA_PKCS_OAEP:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
			break;
		case CKM_GENERIC_SECRET_KEY_GEN:
			pInfo->ulMinKeySize = 1;
			pInfo->ulMaxKeySize = UNLIMITED_KEY_SIZE;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_AES_KEY_GEN:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_AES_CBC_PAD:
			pInfo->flags = CKF_UNWRAP | CKF_WRAP;
			/* FALLTHROUGH */
		case CKM_AES_CBC:
			// Real AES-CBC(-PAD) key wrap AND unwrap are implemented
			// (audit V-5/V-6), so advertise both directions to match
			// the C_WrapKey/C_UnwrapKey dispatch.
			pInfo->flags |= CKF_WRAP | CKF_UNWRAP;
			/* FALLTHROUGH */
		case CKM_AES_ECB:
		case CKM_AES_CTR:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags |= CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_AES_GCM:
			// The message API (C_MessageEncryptInit / C_MessageDecryptInit)
			// dispatches AES-GCM, so advertise CKF_MESSAGE_ENCRYPT/DECRYPT
			// (audit mech G1).
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags |= CKF_ENCRYPT | CKF_DECRYPT |
			                CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT;
			break;
		case CKM_CHACHA20_KEY_GEN:
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_CHACHA20_POLY1305:
		case CKM_CHACHA20:
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_AES_KEY_WRAP:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = UNLIMITED_KEY_SIZE;
			pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			pInfo->ulMinKeySize = 1;
			pInfo->ulMaxKeySize = UNLIMITED_KEY_SIZE;
			pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;
#endif
		case CKM_RSA_AES_KEY_WRAP:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;

		case CKM_AES_ECB_ENCRYPT_DATA:
		case CKM_AES_CBC_ENCRYPT_DATA:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DERIVE;
			break;
		case CKM_AES_CMAC:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_KMAC_128:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = UNLIMITED_KEY_SIZE;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_KMAC_256:
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = UNLIMITED_KEY_SIZE;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = ecdsaMinSize;
			pInfo->ulMaxKeySize = ecdsaMaxSize;
#define CKF_EC_COMMOM	(CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS)
			pInfo->flags = CKF_GENERATE_KEY_PAIR | CKF_EC_COMMOM;
			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
		case CKM_ECDSA_SHA3_224:
		case CKM_ECDSA_SHA3_256:
		case CKM_ECDSA_SHA3_384:
		case CKM_ECDSA_SHA3_512:
			// CKF_MESSAGE_SIGN/VERIFY: the message sign API delegates to
			// AsymSignInit, which accepts ECDSA mechanisms (audit mech G2).
			pInfo->ulMinKeySize = ecdsaMinSize;
			pInfo->ulMaxKeySize = ecdsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_EC_COMMOM |
			               CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY;
			break;
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
		case CKM_ECDH1_DERIVE:
			// N3 remediation 2026-08-13: plain ECDH1 is also dispatched by
			// C_EncapsulateKey/C_DecapsulateKey (SoftHSM_kem.cpp, PKCS#11
			// v3.2 §6.3.17 Table 78) — advertise it, mirroring the
			// CKM_ML_KEM entry below. The cofactor variant stays derive-only.
			pInfo->ulMinKeySize = ecdhMinSize ? ecdhMinSize : eddsaMinSize;
			pInfo->ulMaxKeySize = ecdhMaxSize ? ecdhMaxSize : eddsaMaxSize;
			pInfo->flags = CKF_DERIVE | CKF_ENCAPSULATE | CKF_DECAPSULATE;
			break;
		case CKM_ECDH1_COFACTOR_DERIVE:
			pInfo->ulMinKeySize = ecdhMinSize ? ecdhMinSize : eddsaMinSize;
			pInfo->ulMaxKeySize = ecdhMaxSize ? ecdhMaxSize : eddsaMaxSize;
			pInfo->flags = CKF_DERIVE;
			break;
#endif
		// Montgomery X25519/X448 + BIP32 derive (audit mech G6). These are
		// dispatched by C_DeriveKey but were unreachable because the advertised
		// table omitted them (isMechanismPermitted rejected them).
		case CKM_X25519:
		case CKM_X448:
		case CKM_BIP32_MASTER_DERIVE:
		case CKM_BIP32_CHILD_DERIVE:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DERIVE;
			break;
#ifdef WITH_EDDSA
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = eddsaMinSize;
			pInfo->ulMaxKeySize = eddsaMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_EC_MONTGOMERY_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = eddsaMinSize;
			pInfo->ulMaxKeySize = eddsaMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_EDDSA:
			pInfo->ulMinKeySize = eddsaMinSize;
			pInfo->ulMaxKeySize = eddsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_EDDSA_PH:
			pInfo->ulMinKeySize = 255;
			pInfo->ulMaxKeySize = 255;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
		// ML-DSA (FIPS 204) — ulMin/MaxKeySize are public-key BYTES per
		// PKCS#11 v3.2 §6.67: ML-DSA-44 pk=1312, ML-DSA-87 pk=2592 (audit V-1).
		case CKM_ML_DSA_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 1312;
			pInfo->ulMaxKeySize = 2592;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_ML_DSA:
		case CKM_HASH_ML_DSA:
		case CKM_HASH_ML_DSA_SHA224:
		case CKM_HASH_ML_DSA_SHA256:
		case CKM_HASH_ML_DSA_SHA384:
		case CKM_HASH_ML_DSA_SHA512:
		case CKM_HASH_ML_DSA_SHA3_224:
		case CKM_HASH_ML_DSA_SHA3_256:
		case CKM_HASH_ML_DSA_SHA3_384:
		case CKM_HASH_ML_DSA_SHA3_512:
		case CKM_HASH_ML_DSA_SHAKE128:
		case CKM_HASH_ML_DSA_SHAKE256:
			// CKF_MESSAGE_SIGN/VERIFY: the message API (C_MessageSignInit)
			// delegates to AsymSignInit which accepts ML-DSA (audit mech G2).
			pInfo->ulMinKeySize = 1312;
			pInfo->ulMaxKeySize = 2592;
			pInfo->flags = CKF_SIGN | CKF_VERIFY |
			               CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY;
			break;
		// External-µ (remediation R34, PQCTODAY-VENDOR-EXT-MU) — CKF_SIGN |
		// CKF_VERIFY only, no C_MessageSign/Verify* support for this vendor
		// mechanism.
		case CKM_PQCTODAY_ML_DSA_MU:
			pInfo->ulMinKeySize = 1312;
			pInfo->ulMaxKeySize = 2592;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		// µ generation (remediation R39, phase 8, PQCTODAY-VENDOR-EXT-MU) —
		// a digest-family mechanism (C_Digest/C_DigestUpdate/C_DigestFinal),
		// same shape as the plain hash mechanisms above. Key size N/A, same
		// as those.
		case CKM_PQCTODAY_ML_DSA_MU_GEN:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;
		// SLH-DSA (FIPS 205) — ulMin/MaxKeySize are public-key BYTES per
		// PKCS#11 v3.2 §6.69: pk = 2n, n = 16..32 → 32..64 bytes (audit V-2).
		case CKM_SLH_DSA_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = 64;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_SLH_DSA:
		case CKM_HASH_SLH_DSA:
		case CKM_HASH_SLH_DSA_SHA224:
		case CKM_HASH_SLH_DSA_SHA256:
		case CKM_HASH_SLH_DSA_SHA384:
		case CKM_HASH_SLH_DSA_SHA512:
		case CKM_HASH_SLH_DSA_SHA3_224:
		case CKM_HASH_SLH_DSA_SHA3_256:
		case CKM_HASH_SLH_DSA_SHA3_384:
		case CKM_HASH_SLH_DSA_SHA3_512:
		case CKM_HASH_SLH_DSA_SHAKE128:
		case CKM_HASH_SLH_DSA_SHAKE256:
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = 64;
			pInfo->flags = CKF_SIGN | CKF_VERIFY |
			               CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY;
			break;
		// ML-KEM (FIPS 203) — sizes are encapsulation key bytes (not security bits)
		// ML-KEM-512=800B, ML-KEM-768=1184B, ML-KEM-1024=1568B
		case CKM_ML_KEM_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 800;
			pInfo->ulMaxKeySize = 1568;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_ML_KEM:
			pInfo->ulMinKeySize = 800;
			pInfo->ulMaxKeySize = 1568;
			pInfo->flags = CKF_ENCAPSULATE | CKF_DECAPSULATE;
			break;
		// LMS / HSS stateful hash-based signatures (G10)
		// Standard PKCS#11 v3.2 §6.65 entries (HSS + keygen)
		case CKM_HSS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_HSS:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case 0x00004034: // CKM_XMSS_KEY_PAIR_GEN
		case 0x00004035: // CKM_XMSSMT_KEY_PAIR_GEN
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case 0x00004036: // CKM_XMSS
		case 0x00004037: // CKM_XMSSMT
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		// CKM_KECCAK_256 removed: not dispatched (Rust engine only) — audit G3.
	    case CKM_CONCATENATE_DATA_AND_BASE:
	    case CKM_CONCATENATE_BASE_AND_DATA:
	    case CKM_CONCATENATE_BASE_AND_KEY:
	        pInfo->ulMinKeySize = 1;
	        pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
	        pInfo->flags = CKF_DERIVE;
	        break;
	    case CKM_PKCS5_PBKD2:
	    case CKM_HKDF_DERIVE:
	    case CKM_HKDF_DATA:
	    case CKM_SP800_108_COUNTER_KDF:
	    case CKM_SP800_108_FEEDBACK_KDF:
	    case CKM_SHAKE_256_KEY_DERIVATION:
	        pInfo->ulMinKeySize = 1;
	        pInfo->ulMaxKeySize = MAX_HMAC_KEY_BYTES;
	        pInfo->flags = CKF_DERIVE;
	        break;
		default:
			DEBUG_MSG("The selected mechanism is not supported");
			return CKR_MECHANISM_INVALID;
			break;
	}

	return CKR_OK;
}

// Initialise the token in the specified slot
CK_RV SoftHSM::C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL)
	{
		return CKR_SLOT_ID_INVALID;
	}

	// Check if any session is open with this token.
	if (sessionManager->haveSession(slotID))
	{
		return CKR_SESSION_EXISTS;
	}

	// Check the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_INCORRECT;

	ByteString soPIN(pPin, ulPinLen);

	return slot->initToken(soPIN, pLabel);
}

// Initialise the user PIN
CK_RV SoftHSM::C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// The SO must be logged in
	if (session->getState() != CKS_RW_SO_FUNCTIONS) return CKR_USER_NOT_LOGGED_IN;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	ByteString userPIN(pPin, ulPinLen);

	return token->initUserPIN(userPIN);
}

// Change the PIN
CK_RV SoftHSM::C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_RV rv = CKR_OK;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the new PINs
	if (pOldPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pNewPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (ulNewLen < MIN_PIN_LEN || ulNewLen > MAX_PIN_LEN) return CKR_PIN_LEN_RANGE;

	ByteString oldPIN(pOldPin, ulOldLen);
	ByteString newPIN(pNewPin, ulNewLen);

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	switch (session->getState())
	{
		case CKS_RW_PUBLIC_SESSION:
		case CKS_RW_USER_FUNCTIONS:
			rv = token->setUserPIN(oldPIN, newPIN);
			break;
		case CKS_RW_SO_FUNCTIONS:
			rv = token->setSOPIN(oldPIN, newPIN);
			break;
		default:
			return CKR_SESSION_READ_ONLY;
	}

	return rv;
}


