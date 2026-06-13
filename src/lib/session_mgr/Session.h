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

#ifndef _SOFTHSM_V2_SESSION_H
#define _SOFTHSM_V2_SESSION_H

#include "ByteString.h"
#include "Slot.h"
#include "FindOperation.h"
#include "HashAlgorithm.h"
#include "MacAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "SymmetricAlgorithm.h"
#include "Token.h"
#include "cryptoki.h"

#define SESSION_OP_NONE			0x0
#define SESSION_OP_FIND			0x1
#define SESSION_OP_ENCRYPT		0x2
#define SESSION_OP_DECRYPT		0x3
#define SESSION_OP_DIGEST		0x4
#define SESSION_OP_SIGN			0x5
#define SESSION_OP_VERIFY		0x6
#define SESSION_OP_DIGEST_ENCRYPT	0x7
#define SESSION_OP_DECRYPT_DIGEST	0x8
#define SESSION_OP_SIGN_ENCRYPT		0x9
#define SESSION_OP_DECRYPT_VERIFY	0x10
#define SESSION_OP_MESSAGE_SIGN		0x11  // PKCS#11 v3.0: active after C_MessageSignInit
#define SESSION_OP_MESSAGE_VERIFY	0x12  // PKCS#11 v3.0: active after C_MessageVerifyInit
#define SESSION_OP_MESSAGE_SIGN_BEGIN	0x13  // PKCS#11 v3.2: between C_SignMessageBegin and C_SignMessageNext
#define SESSION_OP_MESSAGE_VERIFY_BEGIN	0x14  // PKCS#11 v3.2: between C_VerifyMessageBegin and C_VerifyMessageNext
#define SESSION_OP_MESSAGE_ENCRYPT	0x15  // PKCS#11 v3.0: active after C_MessageEncryptInit
#define SESSION_OP_MESSAGE_DECRYPT	0x16  // PKCS#11 v3.0: active after C_MessageDecryptInit
#define SESSION_OP_MESSAGE_ENCRYPT_BEGIN 0x17 // PKCS#11 v3.0: between C_EncryptMessageBegin and C_EncryptMessageNext
#define SESSION_OP_MESSAGE_DECRYPT_BEGIN 0x18 // PKCS#11 v3.0: between C_DecryptMessageBegin and C_DecryptMessageNext
#define SESSION_OP_VERIFY_SIGNATURE	0x19  // PKCS#11 v3.2: after C_VerifySignatureInit (pre-bound signature)
#define SESSION_OP_SIGN_RECOVER		0x1A  // PKCS#11 v3.2: C_SignRecoverInit / C_SignRecover
#define SESSION_OP_VERIFY_RECOVER	0x1B  // PKCS#11 v3.2: C_VerifyRecoverInit / C_VerifyRecover

class Session
{
public:
	Session(Slot* inSlot, bool inIsReadWrite, bool inIsAsync, CK_VOID_PTR inPApplication, CK_NOTIFY inNotify);

	// Destructor
	virtual ~Session();

	// Slot and token
	Slot* getSlot();
	Token* getToken();

	// Session properties
	CK_RV getInfo(CK_SESSION_INFO_PTR pInfo);
	bool isRW();
	CK_STATE getState();
	bool isAsync();
	void setHandle(CK_SESSION_HANDLE inHSession);
	CK_SESSION_HANDLE getHandle();

	// Operations
	int getOpType();
	void setOpType(int inOperation);
	void resetOp();

	// Release only the crypto contexts belonging to one operation family
	// (one of SESSION_OP_DIGEST / _ENCRYPT / _DECRYPT / _SIGN / _VERIFY).
	// Used by the *Final functions so that, during a §5.13 dual-function
	// operation, finishing one half does not tear down the other half that
	// the caller still needs to finalise. When no complementary context
	// remains live this is equivalent to resetOp() (operation → NONE);
	// otherwise operation is left pointing at the surviving family.
	void endOpFamily(int family);

	// Find
	void setFindOp(FindOperation *inFindOp);
	FindOperation *getFindOp();

	// Digest
	void setDigestOp(HashAlgorithm* inDigestOp);
	HashAlgorithm* getDigestOp();
	void setHashAlgo(HashAlgo::Type inHashAlgo);
	HashAlgo::Type getHashAlgo();

	// Mac
	void setMacOp(MacAlgorithm* inMacOp);
	MacAlgorithm* getMacOp();

	// Asymmetric Crypto
	void setAsymmetricCryptoOp(AsymmetricAlgorithm* inAsymmetricCryptoOp);
	AsymmetricAlgorithm* getAsymmetricCryptoOp();

	// Symmetric Crypto
	void setSymmetricCryptoOp(SymmetricAlgorithm* inSymmetricCryptoOp);
	SymmetricAlgorithm* getSymmetricCryptoOp();

	void setMechanism(AsymMech::Type inMechanism);
	AsymMech::Type getMechanism();

	bool setParameters(void* inParam, size_t inParamLen);
	void* getParameters(size_t& inParamLen);

	void setReAuthentication(bool inReAuthentication);
	bool getReAuthentication();

	void setAllowMultiPartOp(bool inAllowMultiPartOp);
	bool getAllowMultiPartOp();

	void setAllowSinglePartOp(bool inAllowSinglePartOp);
	bool getAllowSinglePartOp();

	void setPublicKey(PublicKey* inPublicKey);
	PublicKey* getPublicKey();

	void setPrivateKey(PrivateKey* inPrivateKey);
	PrivateKey* getPrivateKey();

	void setSymmetricKey(SymmetricKey* inSymmetricKey);
	SymmetricKey* getSymmetricKey();

	// Message accumulation buffer — used by C_VerifySignatureUpdate to collect
	// data before C_VerifySignatureFinal calls the one-shot verify.
	// Cleared unconditionally by resetOp().
	void appendToMsgBuffer(const CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
	const ByteString& getMsgBuffer() const;
	void clearMsgBuffer();

	void setSignKeyHandle(CK_OBJECT_HANDLE hKey);
	CK_OBJECT_HANDLE getSignKeyHandle();

	void setVerifyKeyHandle(CK_OBJECT_HANDLE hKey);
	CK_OBJECT_HANDLE getVerifyKeyHandle();

private:
	// Constructor
	Session();

	// Slot and token
	Slot* slot;
	Token* token;

	// Application data (not in use)
	CK_VOID_PTR pApplication;
	CK_NOTIFY notify;

	// Session properties
	bool isReadWrite;
	bool isAsyncSession;
	CK_SESSION_HANDLE hSession;

	// Operations
	int operation;

	// §5.13 dual-function op tracking. When a complementary second Init forms a
	// dual op (e.g. EncryptInit then DigestInit), dualOp1/dualOp2 record the two
	// live families so endOpFamily() can advance `operation` to the surviving
	// family when one half is finalised. Both SESSION_OP_NONE when no dual op.
	int dualOp1;
	int dualOp2;

	// Find
	FindOperation *findOp;

	// Digest
	HashAlgorithm* digestOp;
	HashAlgo::Type hashAlgo;

	// Mac
	MacAlgorithm* macOp;

	// Asymmetric Crypto
	AsymmetricAlgorithm* asymmetricCryptoOp;

	// Symmetric Crypto
	SymmetricAlgorithm* symmetricCryptoOp;

	AsymMech::Type mechanism;
	void* param;
	size_t paramLen;
	bool reAuthentication;
	bool allowMultiPartOp;
	bool allowSinglePartOp;
	PublicKey* publicKey;
	PrivateKey* privateKey;

	// Symmetric Crypto
	SymmetricKey* symmetricKey;

	CK_OBJECT_HANDLE signKeyHandle;
	CK_OBJECT_HANDLE verifyKeyHandle;

	// Pre-bound verify message accumulation (C_VerifySignatureUpdate / Final)
	ByteString msgBuffer;
};

#endif // !_SOFTHSM_V2_SESSION_H
