/*
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
 Session.h

 This class represents a single session
 *****************************************************************************/

#include "CryptoFactory.h"
#include "Session.h"

// Constructor
Session::Session(Slot* inSlot, bool inIsReadWrite, bool inIsAsync, CK_VOID_PTR inPApplication, CK_NOTIFY inNotify)
{
	slot = inSlot;
	token = slot->getToken();
	isReadWrite = inIsReadWrite;
	isAsyncSession = inIsAsync;
	hSession = CK_INVALID_HANDLE;
	pApplication = inPApplication;
	notify = inNotify;
	operation = SESSION_OP_NONE;
	dualOp1 = SESSION_OP_NONE;
	dualOp2 = SESSION_OP_NONE;
	findOp = NULL;
	digestOp = NULL;
	hashAlgo = HashAlgo::Unknown;
	macOp = NULL;
	asymmetricCryptoOp = NULL;
	symmetricCryptoOp = NULL;
	mechanism = AsymMech::Unknown;
	reAuthentication = false;
	allowSinglePartOp = false;
	allowMultiPartOp = false;
	publicKey = NULL;
	privateKey = NULL;
	symmetricKey = NULL;
	param = NULL;
	paramLen = 0;
	signKeyHandle = CK_INVALID_HANDLE;
	verifyKeyHandle = CK_INVALID_HANDLE;
}

// Constructor
Session::Session()
{
	slot = NULL;
	token = NULL;
	isReadWrite = false;
	isAsyncSession = false;
	hSession = CK_INVALID_HANDLE;
	pApplication = NULL;
	notify = NULL;
	operation = SESSION_OP_NONE;
	dualOp1 = SESSION_OP_NONE;
	dualOp2 = SESSION_OP_NONE;
	findOp = NULL;
	digestOp = NULL;
	hashAlgo = HashAlgo::Unknown;
	macOp = NULL;
	asymmetricCryptoOp = NULL;
	symmetricCryptoOp = NULL;
	mechanism = AsymMech::Unknown;
	reAuthentication = false;
	allowSinglePartOp = false;
	allowMultiPartOp = false;
	publicKey = NULL;
	privateKey = NULL;
	symmetricKey = NULL;
	param = NULL;
	paramLen = 0;
	signKeyHandle = CK_INVALID_HANDLE;
	verifyKeyHandle = CK_INVALID_HANDLE;
}

// Destructor
Session::~Session()
{
	resetOp();
}

// Get session info
CK_RV Session::getInfo(CK_SESSION_INFO_PTR pInfo)
{
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	pInfo->slotID = slot->getSlotID();

	pInfo->state = getState();
	pInfo->flags = CKF_SERIAL_SESSION;
	if (isRW())
	{
		pInfo->flags |= CKF_RW_SESSION;
	}
	if (isAsync())
	{
		pInfo->flags |= CKF_ASYNC_SESSION;
	}
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}

// Is a read and write session
bool Session::isRW()
{
	return isReadWrite;
}

// Is an asynchronous session 
bool Session::isAsync()
{
	return isAsyncSession;
}

// Get session state
CK_STATE Session::getState()
{
	if (token->isSOLoggedIn())
	{
		return CKS_RW_SO_FUNCTIONS;
	}

	if (token->isUserLoggedIn())
	{
		if (isRW())
		{
			return CKS_RW_USER_FUNCTIONS;
		}
		else
		{
			return CKS_RO_USER_FUNCTIONS;
		}
	}

	if (isRW())
	{
		return CKS_RW_PUBLIC_SESSION;
	}
	else
	{
		return CKS_RO_PUBLIC_SESSION;
	}
}

void Session::setHandle(CK_SESSION_HANDLE inHSession)
{
	hSession = inHSession;
}

CK_SESSION_HANDLE Session::getHandle()
{
	return hSession;
}

// Return the slot that the session is connected to
Slot* Session::getSlot()
{
	return slot;
}

// Return the token that the session is connected to
Token* Session::getToken()
{
	return token;
}

// Returns true for the five crypto families that can take part in a §5.13
// dual-function operation, and which endOpFamily() knows how to release.
static bool isDualOpFamily(int op)
{
	return op == SESSION_OP_DIGEST  || op == SESSION_OP_ENCRYPT ||
	       op == SESSION_OP_DECRYPT || op == SESSION_OP_SIGN    ||
	       op == SESSION_OP_VERIFY;
}

// Set the operation type
void Session::setOpType(int inOperation)
{
	// Detect the formation of a §5.13 dual-function op: a complementary second
	// Init while a first crypto family is already active. Record both families
	// so endOpFamily() can advance `operation` to the survivor when the first
	// half finalises. (The actual pairing legality is enforced earlier by
	// SoftHSM::isComplementaryDualOp(); here we only need to remember the two.)
	if (isDualOpFamily(operation) && isDualOpFamily(inOperation) &&
	    operation != inOperation)
	{
		dualOp1 = operation;
		dualOp2 = inOperation;
	}
	else if (inOperation != operation)
	{
		// Any other transition (single-op init, state-machine move, reset)
		// clears the dual-op record so a stale pairing can't leak forward.
		dualOp1 = SESSION_OP_NONE;
		dualOp2 = SESSION_OP_NONE;
	}

	operation = inOperation;
}

// Get the operation type
int Session::getOpType()
{
	return operation;
}

// Reset the operations
void Session::resetOp()
{
	// Always clear the message accumulation buffer so a subsequent
	// C_VerifySignatureUpdate / C_VerifySignatureFinal sequence starts fresh.
	msgBuffer.wipe();

	if (param != NULL)
	{
		// Securely wipe param in case it contains key material (e.g. GcmMsgCtx)
		memset(param, 0, paramLen);
		free(param);
		param = NULL;
		paramLen = 0;
	}

	// Each crypto-context member is released independently rather than via an
	// else-if chain, because a §5.13 dual-function operation keeps two contexts
	// live at once (e.g. a digest op plus a symmetric-cipher op). The old
	// else-if chain would free only the first non-NULL context and leak the
	// rest. findOp remains exclusive — it never coexists with a crypto context.
	if (findOp != NULL)
	{
		findOp->recycle();
		findOp = NULL;
	}

	if (digestOp != NULL)
	{
		CryptoFactory::i()->recycleHashAlgorithm(digestOp);
		digestOp = NULL;
	}

	if (asymmetricCryptoOp != NULL)
	{
		if (publicKey != NULL)
		{
			asymmetricCryptoOp->recyclePublicKey(publicKey);
			publicKey = NULL;
		}
		if (privateKey != NULL)
		{
			asymmetricCryptoOp->recyclePrivateKey(privateKey);
			privateKey = NULL;
		}
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymmetricCryptoOp);
		asymmetricCryptoOp = NULL;
	}

	// symmetricKey is shared between a symmetric-cipher op and a MAC op, but a
	// dual-function pairing never combines those two families, so exactly one
	// owner recycles it.
	if (symmetricCryptoOp != NULL)
	{
		if (symmetricKey != NULL)
		{
			symmetricCryptoOp->recycleKey(symmetricKey);
			symmetricKey = NULL;
		}
		CryptoFactory::i()->recycleSymmetricAlgorithm(symmetricCryptoOp);
		symmetricCryptoOp = NULL;
	}

	if (macOp != NULL)
	{
		if (symmetricKey != NULL)
		{
			macOp->recycleKey(symmetricKey);
			symmetricKey = NULL;
		}
		CryptoFactory::i()->recycleMacAlgorithm(macOp);
		macOp = NULL;
	}

	operation = SESSION_OP_NONE;
	dualOp1 = SESSION_OP_NONE;
	dualOp2 = SESSION_OP_NONE;
	reAuthentication = false;
}

// Release only the crypto context(s) for one operation family. During a §5.13
// dual-function operation two contexts are live at once; the *Final functions
// call this so finishing one half leaves the other half intact for its own
// Final. After releasing the requested family, `operation` is advanced to the
// surviving family (the dual partner recorded at init time) if a context
// remains, else SESSION_OP_NONE — matching the single-op resetOp() contract
// when there is no dual partner. Advancing (rather than leaving `operation`
// stale at the just-freed family) is what stops a finalised half's Update /
// one-shot entry points from passing their getOpType() guard and dereferencing
// the now-NULL context.
void Session::endOpFamily(int family)
{
	switch (family)
	{
		case SESSION_OP_DIGEST:
			if (digestOp != NULL)
			{
				CryptoFactory::i()->recycleHashAlgorithm(digestOp);
				digestOp = NULL;
			}
			break;

		case SESSION_OP_ENCRYPT:
		case SESSION_OP_DECRYPT:
			// Symmetric ciphers own symmetricCryptoOp (+ symmetricKey); asym
			// ciphers own asymmetricCryptoOp (+ its keys). A dual op only ever
			// pairs a symmetric cipher with a digest/sign/verify half, but
			// release whichever cipher context is live for completeness.
			if (symmetricCryptoOp != NULL)
			{
				if (symmetricKey != NULL)
				{
					symmetricCryptoOp->recycleKey(symmetricKey);
					symmetricKey = NULL;
				}
				CryptoFactory::i()->recycleSymmetricAlgorithm(symmetricCryptoOp);
				symmetricCryptoOp = NULL;
			}
			else if (asymmetricCryptoOp != NULL)
			{
				if (publicKey != NULL)  { asymmetricCryptoOp->recyclePublicKey(publicKey);  publicKey = NULL; }
				if (privateKey != NULL) { asymmetricCryptoOp->recyclePrivateKey(privateKey); privateKey = NULL; }
				CryptoFactory::i()->recycleAsymmetricAlgorithm(asymmetricCryptoOp);
				asymmetricCryptoOp = NULL;
			}
			break;

		case SESSION_OP_SIGN:
		case SESSION_OP_VERIFY:
			// Asymmetric signer/verifier owns asymmetricCryptoOp (+ keys); an
			// HMAC signer owns macOp (+ symmetricKey). Dual ops only use the
			// asymmetric variant, but handle both.
			if (asymmetricCryptoOp != NULL)
			{
				if (publicKey != NULL)  { asymmetricCryptoOp->recyclePublicKey(publicKey);  publicKey = NULL; }
				if (privateKey != NULL) { asymmetricCryptoOp->recyclePrivateKey(privateKey); privateKey = NULL; }
				CryptoFactory::i()->recycleAsymmetricAlgorithm(asymmetricCryptoOp);
				asymmetricCryptoOp = NULL;
			}
			else if (macOp != NULL)
			{
				if (symmetricKey != NULL)
				{
					macOp->recycleKey(symmetricKey);
					symmetricKey = NULL;
				}
				CryptoFactory::i()->recycleMacAlgorithm(macOp);
				macOp = NULL;
			}
			break;

		default:
			// Unknown family: fall back to a full reset.
			resetOp();
			return;
	}

	// If no crypto context remains live the operation is fully done; clear the
	// slate exactly like resetOp(). Otherwise a dual partner survives, so
	// advance `operation` to the surviving family (the partner recorded when
	// the dual op formed) — never leave it pointing at the family we just
	// freed, or the freed half's Update/one-shot would pass its getOpType()
	// guard and deref a NULL context.
	if (digestOp == NULL && symmetricCryptoOp == NULL && asymmetricCryptoOp == NULL && macOp == NULL)
	{
		msgBuffer.wipe();
		if (param != NULL)
		{
			memset(param, 0, paramLen);
			free(param);
			param = NULL;
			paramLen = 0;
		}
		operation = SESSION_OP_NONE;
		dualOp1 = SESSION_OP_NONE;
		dualOp2 = SESSION_OP_NONE;
		reAuthentication = false;
	}
	else
	{
		// A context survives: pick the surviving family. The dual op recorded
		// its two families (dualOp1/dualOp2); the survivor is whichever is not
		// the one being released. Fall back to leaving `operation` unchanged
		// only if no dual pairing was recorded (shouldn't happen for a real
		// dual-survivor, but stay defensive rather than guess a wrong family).
		int survivor = SESSION_OP_NONE;
		if (dualOp1 == family && dualOp2 != SESSION_OP_NONE)
			survivor = dualOp2;
		else if (dualOp2 == family && dualOp1 != SESSION_OP_NONE)
			survivor = dualOp1;

		if (survivor != SESSION_OP_NONE)
			operation = survivor;
		// The dual pairing is now half-consumed; the survivor is a plain
		// single op from here on. Clear the record so its own Final/reset
		// behaves like an ordinary single-op teardown.
		dualOp1 = SESSION_OP_NONE;
		dualOp2 = SESSION_OP_NONE;
	}
}

void Session::setFindOp(FindOperation *inFindOp)
{
	if (findOp != NULL) {
		delete findOp;
	}
	findOp = inFindOp;
}

FindOperation *Session::getFindOp()
{
	return findOp;
}

// Set the digesting operator
void Session::setDigestOp(HashAlgorithm* inDigestOp)
{
	if (digestOp != NULL)
	{
		CryptoFactory::i()->recycleHashAlgorithm(digestOp);
	}

	digestOp = inDigestOp;
}

// Get the digesting operator
HashAlgorithm* Session::getDigestOp()
{
	return digestOp;
}

void Session::setHashAlgo(HashAlgo::Type inHashAlgo)
{
	hashAlgo = inHashAlgo;
}

HashAlgo::Type Session::getHashAlgo()
{
	return hashAlgo;
}

// Set the MACing operator
void Session::setMacOp(MacAlgorithm *inMacOp)
{
	if (macOp != NULL)
	{
		setSymmetricKey(NULL);
		CryptoFactory::i()->recycleMacAlgorithm(macOp);
	}

	macOp = inMacOp;
}

// Get the MACing operator
MacAlgorithm *Session::getMacOp()
{
	return macOp;
}

void Session::setAsymmetricCryptoOp(AsymmetricAlgorithm *inAsymmetricCryptoOp)
{
	if (asymmetricCryptoOp != NULL)
	{
		setPublicKey(NULL);
		setPrivateKey(NULL);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymmetricCryptoOp);
	}

	asymmetricCryptoOp = inAsymmetricCryptoOp;
}

AsymmetricAlgorithm *Session::getAsymmetricCryptoOp()
{
	return asymmetricCryptoOp;
}

void Session::setSymmetricCryptoOp(SymmetricAlgorithm *inSymmetricCryptoOp)
{
	if (symmetricCryptoOp != NULL)
	{
		setSymmetricKey(NULL);
		CryptoFactory::i()->recycleSymmetricAlgorithm(symmetricCryptoOp);
	}

	symmetricCryptoOp = inSymmetricCryptoOp;
}

SymmetricAlgorithm *Session::getSymmetricCryptoOp()
{
	return symmetricCryptoOp;
}

void Session::setMechanism(AsymMech::Type inMechanism)
{
	mechanism = inMechanism;
}

AsymMech::Type Session::getMechanism()
{
	return mechanism;
}

bool Session::setParameters(void* inParam, size_t inParamLen)
{
	if (inParam == NULL || inParamLen == 0) return false;

	// Try-and-swap: allocate first so the old param is preserved on OOM.
	void* newParam = malloc(inParamLen);
	if (newParam == NULL)
		return false;

	memcpy(newParam, inParam, inParamLen);

	if (param != NULL)
		free(param);

	param = newParam;
	paramLen = inParamLen;
	return true;
}

void* Session::getParameters(size_t& inParamLen)
{
	inParamLen = paramLen;
	return param;
}

void Session::setReAuthentication(bool inReAuthentication)
{
	reAuthentication = inReAuthentication;
}

bool Session::getReAuthentication()
{
	return reAuthentication;
}

void Session::setAllowMultiPartOp(bool inAllowMultiPartOp)
{
	allowMultiPartOp = inAllowMultiPartOp;
}

bool Session::getAllowMultiPartOp()
{
	return allowMultiPartOp;
}

void Session::setAllowSinglePartOp(bool inAllowSinglePartOp)
{
	allowSinglePartOp = inAllowSinglePartOp;
}

bool Session::getAllowSinglePartOp()
{
	return allowSinglePartOp;
}

void Session::setPublicKey(PublicKey* inPublicKey)
{
	if (asymmetricCryptoOp == NULL)
		return;

	if (publicKey != NULL)
	{
		asymmetricCryptoOp->recyclePublicKey(publicKey);
	}

	publicKey = inPublicKey;
}

PublicKey* Session::getPublicKey()
{
	return publicKey;
}

void Session::setPrivateKey(PrivateKey* inPrivateKey)
{
	if (asymmetricCryptoOp == NULL)
		return;

	if (privateKey != NULL)
	{
		asymmetricCryptoOp->recyclePrivateKey(privateKey);
	}

	privateKey = inPrivateKey;
}

PrivateKey* Session::getPrivateKey()
{
	return privateKey;
}

void Session::setSymmetricKey(SymmetricKey* inSymmetricKey)
{
	if (symmetricKey != NULL)
	{
		if (macOp) {
			macOp->recycleKey(symmetricKey);
		} else if (symmetricCryptoOp) {
			symmetricCryptoOp->recycleKey(symmetricKey);
		} else {
			return;
		}
	}

	symmetricKey = inSymmetricKey;
}

SymmetricKey* Session::getSymmetricKey()
{
	return symmetricKey;
}

// Append bytes to the message accumulation buffer (C_VerifySignatureUpdate)
void Session::appendToMsgBuffer(const CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (pPart != NULL && ulPartLen > 0)
		msgBuffer += ByteString(pPart, ulPartLen);
}

// Return the accumulated message (C_VerifySignatureFinal)
const ByteString& Session::getMsgBuffer() const
{
	return msgBuffer;
}

// Clear the accumulation buffer (called by C_VerifySignatureInit and resetOp)
void Session::clearMsgBuffer()
{
	msgBuffer.wipe();
}

void Session::setSignKeyHandle(CK_OBJECT_HANDLE hKey)
{
	signKeyHandle = hKey;
}

CK_OBJECT_HANDLE Session::getSignKeyHandle()
{
	return signKeyHandle;
}

void Session::setVerifyKeyHandle(CK_OBJECT_HANDLE hKey)
{
	verifyKeyHandle = hKey;
}

CK_OBJECT_HANDLE Session::getVerifyKeyHandle()
{
	return verifyKeyHandle;
}
