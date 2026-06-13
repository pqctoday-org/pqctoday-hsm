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
 SecureDataManager.h

 The secure data manager main class. Every token instance has a secure data
 manager instance member that is used to decrypt and encrypt sensitive object
 attributes such as key material. The secure data manager maintains a key blob
 containing a 256-bit AES key that is used in this decryption and encryption
 process. The key blob itself is encrypted using a PBE derived key that is
 derived from the user PIN and a PBE key that is derived from the SO PIN. It
 is up to the token to enforce access control based on which user is logged
 in; authentication using the SO PIN is required to be able to change the
 user PIN. The master key that is used to decrypt/encrypt sensitive attributes
 is stored in memory under a mask that is changed every time the key is used.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SECUREDATAMANAGER_H
#define _SOFTHSM_V2_SECUREDATAMANAGER_H

#include "config.h"
#include "ByteString.h"
#include "log.h"
#include "AESKey.h"
#include "RNG.h"
#include "SymmetricAlgorithm.h"
#include "MutexFactory.h"

/**
 * @brief Manages the per-token master key used to protect sensitive PKCS#11 object attributes.
 *
 * Every Token instance owns one SecureDataManager.  It holds a 256-bit AES
 * master key in masked form (XOR'd against a heap-allocated random mask).
 * The master key is wrapped twice — once under a PBKDF2-SHA256 key derived
 * from the SO PIN and once from the User PIN — and stored as opaque blobs that
 * are persisted on-disk with the token.
 *
 * Thread safety: encrypt/decrypt/login/logout are serialised by @c dataMgrMutex.
 * Each operation creates a fresh per-call AES instance so no crypto state is shared.
 */
class SecureDataManager
{
public:
	/**
	 * @brief Construct a blank SecureDataManager for a newly created token.
	 *
	 * Call setSOPIN() to initialise the first key blob before the token is usable.
	 */
	SecureDataManager();

	/**
	 * @brief Construct a SecureDataManager by loading existing PIN blobs from storage.
	 * @param soPINBlob    Encrypted master key wrapped under the SO PIN.
	 * @param userPINBlob  Encrypted master key wrapped under the User PIN.
	 */
	SecureDataManager(const ByteString& soPINBlob, const ByteString& userPINBlob);

	/** @brief Destructor — securely wipes the masked key and mask from memory. */
	virtual ~SecureDataManager();

	/**
	 * @brief Set (or change) the SO PIN and re-wrap the master key.
	 *
	 * Requires either a blank SecureDataManager (first-time init) or that the SO
	 * has already logged in via loginSO().
	 * @param soPIN  Raw SO PIN bytes.
	 * @return true on success; false if not authorised or crypto failure.
	 */
	bool setSOPIN(const ByteString& soPIN);

	/**
	 * @brief Set (or change) the User PIN and re-wrap the master key.
	 *
	 * Requires either the SO or the User to be currently logged in.
	 * @param userPIN  Raw User PIN bytes.
	 * @return true on success; false if not authorised or crypto failure.
	 */
	bool setUserPIN(const ByteString& userPIN);

	/**
	 * @brief Authenticate as Security Officer and unlock the master key.
	 * @param soPIN  Raw SO PIN bytes supplied by the caller.
	 * @return true if the PIN is correct and the master key was unwrapped.
	 */
	bool loginSO(const ByteString& soPIN);
	/** @return true if the SO is currently logged in. */
	bool isSOLoggedIn();

	/**
	 * @brief Authenticate as the normal User and unlock the master key.
	 * @param userPIN  Raw User PIN bytes supplied by the caller.
	 * @return true if the PIN is correct and the master key was unwrapped.
	 */
	bool loginUser(const ByteString& userPIN);
	/** @return true if the User is currently logged in. */
	bool isUserLoggedIn();

	/**
	 * @brief Verify SO PIN without changing login state (used before PIN change).
	 * @param soPIN  PIN to check.
	 * @return true if the PIN matches the stored SO blob.
	 */
	bool reAuthenticateSO(const ByteString& soPIN);

	/**
	 * @brief Verify User PIN without changing login state (used before PIN change).
	 * @param userPIN  PIN to check.
	 * @return true if the PIN matches the stored User blob.
	 */
	bool reAuthenticateUser(const ByteString& userPIN);

	/** @brief Log out all users and re-mask the master key. */
	void logout();

	/**
	 * @brief Decrypt an attribute value previously encrypted by encrypt().
	 *
	 * The master key must be unlocked (SO or User logged in).
	 * @param encrypted  Cipher-text blob (IV prepended by encrypt()).
	 * @param plaintext  Output buffer receiving the recovered plain-text.
	 * @return true on success.
	 *
	 * [[nodiscard]]: this is the choke point behind Token::decrypt(); ignoring the
	 * result lets garbage/empty plaintext flow into key material.
	 */
	[[nodiscard]] bool decrypt(const ByteString& encrypted, ByteString& plaintext);

	/**
	 * @brief Encrypt an attribute value using the master key.
	 *
	 * The master key must be unlocked (SO or User logged in).
	 * @param plaintext  Data to protect.
	 * @param encrypted  Output buffer receiving IV + cipher-text.
	 * @return true on success.
	 *
	 * [[nodiscard]]: this is the choke point behind Token::encrypt(); ignoring the
	 * result lets garbage/empty cipher-text be committed as key material.
	 */
	[[nodiscard]] bool encrypt(const ByteString& plaintext, ByteString& encrypted);

	/** @return The SO PIN-encrypted master key blob for persistent storage. */
	ByteString getSOPINBlob();

	/** @return The User PIN-encrypted master key blob for persistent storage. */
	ByteString getUserPINBlob();

private:
	// Initialise the object
	void initObject();

	// Generic login function
	bool login(const ByteString& passphrase, const ByteString& encryptedKey);

	// Generic re-authentication function
	bool reAuthenticate(const ByteString& passphrase, const ByteString& encryptedKey);

	// Generic function for creating an encrypted version of the key from the specified passphrase
	bool pbeEncryptKey(const ByteString& passphrase, ByteString& encryptedKey);

	// Unmask the key
	void unmask(ByteString& key);

	// Remask the key
	void remask(ByteString& key);

	// The user PIN encrypted key
	ByteString userEncryptedKey;

	// The SO PIN encrypted key
	ByteString soEncryptedKey;

	// Which users are logged in
	bool soLoggedIn;
	bool userLoggedIn;

	// The masked version of the actual key
	ByteString maskedKey;

	// The "magic" data used to detect if a PIN was likely to be correct
	ByteString magic;

	// The mask; this is not a stack member but a heap member. This
	// hopefully ensures that the mask ends up in a memory location
	// that is not logically linked to the masked key
	ByteString* mask;

	// Random number generator instance
	RNG* rng;

	// Mutex
	Mutex* dataMgrMutex;
};

#endif // !_SOFTHSM_V2_SECUREDATAMANAGER_H

