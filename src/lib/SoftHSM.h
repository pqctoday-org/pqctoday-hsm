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
 SoftHSM.h

 This is the main class of the SoftHSM; it has the PKCS #11 interface and
 dispatches all calls to the relevant components of the SoftHSM. The SoftHSM
 class is a singleton implementation.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "cryptoki.h"
#include "SessionObjectStore.h"
#include "ObjectStore.h"
#include "SessionManager.h"
#include "SlotManager.h"
#include "HandleManager.h"
#include <memory>

// Forward declarations — full definitions are only needed in SoftHSM.cpp where
// these types are used in downcasts. Keeping them out of the header reduces
// coupling and avoids cascading recompilation when key class implementations
// change (fixes maintainability gap Md2).
class RSAPublicKey;
class RSAPrivateKey;
class ECPublicKey;
class ECPrivateKey;
class EDPublicKey;
class EDPrivateKey;
class MLDSAPublicKey;
class MLDSAPrivateKey;
class SLHDSAPublicKey;
class SLHDSAPrivateKey;
class MLKEMPublicKey;
class MLKEMPrivateKey;

class SoftHSM
{
public:
	// Return the one-and-only instance
	static SoftHSM* i();

	// This will destroy the one-and-only instance.
	static void reset();

	// Destructor
	virtual ~SoftHSM();

	// PKCS #11 functions
	CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
	CK_RV C_Finalize(CK_VOID_PTR pReserved);
	CK_RV C_GetInfo(CK_INFO_PTR pInfo);
	CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
	CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
	CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
	CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
	CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
	CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
	CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
	CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
	CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession);
	CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
	CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
	CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
	CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
	CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
	CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
	CK_RV C_Logout(CK_SESSION_HANDLE hSession);
	// PKCS#11 v3.0 session management (G6)
	CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen);
	CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags);
	CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
	CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
	CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
	CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
	CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
	CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
	CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
	CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
	CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
	CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
	CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
	CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
	CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
	CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen);
	CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen);
	CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
	CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
	CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
	CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
	CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
	CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	CK_RV StatefulSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
	CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
	CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
	CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
	CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	// PKCS#11 v3.0 one-shot message signing (ML-DSA, SLH-DSA)
	CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession);
	CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
	CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession);
	// PKCS#11 v3.2 streaming message signing (two-step commit-then-sign)
	CK_RV C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen);
	CK_RV C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen);
	CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
	// PKCS#11 v3.0 message-based AEAD encryption (AES-GCM per-message IV + AAD)
	CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen);
	CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen);
	CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags);
	CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession);
	CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen);
	CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen);
	CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags);
	CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession);
	// PKCS#11 v3.2 pre-bound signature verification (G4)
	CK_RV C_VerifySignatureInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
	CK_RV C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen);
	CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
	CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE hSession);
	// PKCS#11 v3.2 §5.6.11 session validation flags (V-19)
	CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession, CK_SESSION_VALIDATION_FLAGS_TYPE type, CK_FLAGS_PTR pFlags);
	CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
	CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
	CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen);
	CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
	CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
	CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
	CK_RV C_GenerateKeyPair
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate,
		CK_ULONG ulPublicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_ULONG ulPrivateKeyAttributeCount,
		CK_OBJECT_HANDLE_PTR phPublicKey,
		CK_OBJECT_HANDLE_PTR phPrivateKey
	);
	CK_RV C_WrapKey
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG_PTR pulWrappedKeyLen
	);
	CK_RV C_UnwrapKey
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hUnwrappingKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG ulWrappedKeyLen,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR hKey
	);
	CK_RV C_DeriveKey
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hBaseKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phKey
	);
	// PKCS#11 v3.2 authenticated key wrap/unwrap with AAD (G5)
	CK_RV C_WrapKeyAuthenticated(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
	CK_RV C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_OBJECT_HANDLE_PTR phKey);
	CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
	CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
	CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
	CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);
	CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

	// PKCS#11 v3.2 — KEM functions (ML-KEM, FIPS 203)
	CK_RV C_EncapsulateKey
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hPublicKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount,
		CK_BYTE_PTR pCiphertext,
		CK_ULONG_PTR pulCiphertextLen,
		CK_OBJECT_HANDLE_PTR phKey
	);
	CK_RV C_DecapsulateKey
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hPrivateKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount,
		CK_BYTE_PTR pCiphertext,
		CK_ULONG ulCiphertextLen,
		CK_OBJECT_HANDLE_PTR phKey
	);

private:
	// Constructor
	SoftHSM();

	// The one-and-only instance
#ifdef HAVE_CXX11
	static std::unique_ptr<SoftHSM> instance;
#else
	static std::auto_ptr<SoftHSM> instance;
#endif

	// Is the SoftHSM PKCS #11 library initialised?
	bool isInitialised;
	bool isRemovable;

	SessionObjectStore* sessionObjectStore;
	ObjectStore* objectStore;
	SlotManager* slotManager;
	SessionManager* sessionManager;
	HandleManager* handleManager;

	// A list with the supported mechanisms
	std::map<std::string, CK_MECHANISM_TYPE> mechanisms_table;
	std::list<CK_MECHANISM_TYPE> supportedMechanisms;
	CK_ULONG nrSupportedMechanisms;

	int forkID;

	// Encrypt/Decrypt variants
	CK_RV SymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV AsymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV SymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV AsymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	// Message AEAD init shared helper (stores AES key bytes in session param)
	CK_RV MsgAesGcmInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey, CK_ATTRIBUTE_TYPE requiredAttr, int opType);

	// Sign/Verify variants
	CK_RV MacSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV StatefulSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV AsymSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV MacVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV StatefulVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	CK_RV StatefulVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
	CK_RV AsymVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

	// Key generation
	CK_RV generateAES
	(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phKey,
		CK_BBOOL isOnToken,
		CK_BBOOL isPrivate,
		CK_MECHANISM_TYPE keyGenMech = CKM_AES_KEY_GEN
	);
	CK_RV generateRSA
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
	);
	CK_RV generateEC
	(
		CK_SESSION_HANDLE hSession,
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
	);
	CK_RV generateED
	(
		CK_SESSION_HANDLE hSession,
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
	);
	CK_RV generateMLDSA
	(
		CK_SESSION_HANDLE hSession,
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
	);
	CK_RV generateSLHDSA
	(
		CK_SESSION_HANDLE hSession,
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
	);
	CK_RV generateGeneric
	(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phKey,
		CK_BBOOL isOnToken,
		CK_BBOOL isPrivate
	);
#ifdef WITH_ECC
	CK_RV deriveECDH
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hBaseKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phKey,
		CK_KEY_TYPE keyType,
		CK_BBOOL isOnToken,
		CK_BBOOL isPrivate
	);
#endif
#ifdef WITH_EDDSA
	CK_RV deriveEDDSA
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hBaseKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phKey,
		CK_KEY_TYPE keyType,
		CK_BBOOL isOnToken,
		CK_BBOOL isPrivate
	);
#endif
	CK_RV deriveSymmetric
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hBaseKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phKey,
		CK_KEY_TYPE keyType,
		CK_BBOOL isOnToken,
		CK_BBOOL isPrivate
	);
	CK_RV CreateObject
	(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject,
		int op
	);

	CK_RV getRSAPrivateKey(RSAPrivateKey* privateKey, Token* token, OSObject* key);
	CK_RV getRSAPublicKey(RSAPublicKey* publicKey, Token* token, OSObject* key);
	CK_RV getECPrivateKey(ECPrivateKey* privateKey, Token* token, OSObject* key);
	CK_RV getECPublicKey(ECPublicKey* publicKey, Token* token, OSObject* key);
	CK_RV getEDPrivateKey(EDPrivateKey* privateKey, Token* token, OSObject* key);
	CK_RV getEDPublicKey(EDPublicKey* publicKey, Token* token, OSObject* key);
	CK_RV getMLDSAPrivateKey(MLDSAPrivateKey* privateKey, Token* token, OSObject* key);
	CK_RV getMLDSAPublicKey(MLDSAPublicKey* publicKey, Token* token, OSObject* key);
	CK_RV getSLHDSAPrivateKey(SLHDSAPrivateKey* privateKey, Token* token, OSObject* key);
	CK_RV getSLHDSAPublicKey(SLHDSAPublicKey* publicKey, Token* token, OSObject* key);
	CK_RV generateMLKEM
	(
		CK_SESSION_HANDLE hSession,
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
	);
	CK_RV getMLKEMPrivateKey(MLKEMPrivateKey* privateKey, Token* token, OSObject* key);
	CK_RV getMLKEMPublicKey(MLKEMPublicKey* publicKey, Token* token, OSObject* key);
	CK_RV getECDHPublicKey(ECPublicKey* publicKey, ECPrivateKey* privateKey, ByteString& pubData);
	CK_RV getEDDHPublicKey(EDPublicKey* publicKey, EDPrivateKey* privateKey, ByteString& pubData);
	CK_RV getSymmetricKey(SymmetricKey* skey, Token* token, OSObject* key);

	ByteString getECDHPubData(ByteString& pubData);

	bool setRSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const;
	bool setECPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const;
	bool setEDPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const;
	CK_RV WrapKeyAsym
	(
		CK_MECHANISM_PTR pMechanism,
		Token *token,
		OSObject *wrapKey,
		ByteString &keydata,
		ByteString &wrapped
	);

	size_t RFC5652Pad(ByteString &keydata, size_t blocksize);
	size_t RFC3394Pad(ByteString &keydata);
	bool RFC5652Unpad(ByteString &keydata, size_t blocksize);
	bool RFC3394Unpad(ByteString &keydata);
	
	CK_RV WrapKeySym
	(
		CK_MECHANISM_PTR pMechanism,
		Token *token,
		OSObject *wrapKey,
		ByteString &keydata,
		ByteString &wrapped
	);

	CK_RV UnwrapKeyAsym
	(
		CK_MECHANISM_PTR pMechanism,
		ByteString &wrapped,
		Token* token,
		OSObject *unwrapKey,
		ByteString &keydata
	);

	CK_RV UnwrapKeySym
	(
		CK_MECHANISM_PTR pMechanism,
		ByteString &wrapped,
		Token* token,
		OSObject *unwrapKey,
		ByteString &keydata
	);

	CK_RV WrapMechRsaAesKw
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		Token *token,
		OSObject *wrapKey,
		ByteString &keydata,
		ByteString &wrapped
	);

	CK_RV UnwrapMechRsaAesKw
	(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		Token *token,
		OSObject *unwrapKey,
		ByteString &wrapped,
		ByteString &keydata
	);

	CK_RV MechParamCheckRSAPKCSOAEP(CK_MECHANISM_PTR pMechanism);
	CK_RV MechParamCheckRSAAESKEYWRAP(CK_MECHANISM_PTR pMechanism);

	bool isMechanismPermitted(OSObject* key, CK_MECHANISM_TYPE mechanism);
	void prepareSupportedMechanisms(std::map<std::string, CK_MECHANISM_TYPE> &t);
	bool detectFork(void);

	// -------------------------------------------------------------------------
	// Session acquisition helpers — eliminate the 5-step boilerplate repeated
	// across ~76 C_* functions.  outGuard must outlive the raw pointer it guards;
	// always declare it before outSession/outToken/outKey at each call site.
	// -------------------------------------------------------------------------
	CK_RV acquireSession(
		CK_SESSION_HANDLE           hSession,
		std::shared_ptr<Session>&   outGuard,
		Session*&                   outSession);

	CK_RV acquireSessionToken(
		CK_SESSION_HANDLE           hSession,
		std::shared_ptr<Session>&   outGuard,
		Session*&                   outSession,
		Token*&                     outToken);

	CK_RV acquireSessionTokenKey(
		CK_SESSION_HANDLE           hSession,
		CK_OBJECT_HANDLE            hKey,
		CK_ATTRIBUTE_TYPE           usageAttr,
		CK_MECHANISM_PTR            pMechanism,
		std::shared_ptr<Session>&   outGuard,
		Session*&                   outSession,
		Token*&                     outToken,
		OSObject*&                  outKey);

	/// Recycles algorithm/key-pair objects and destroys both key handles if rv != CKR_OK.
	void cleanupKeyPair(
		AsymmetricAlgorithm*        algo,
		AsymmetricKeyPair*          kp,
		Token*                      token,
		CK_OBJECT_HANDLE_PTR        phPublicKey,
		CK_OBJECT_HANDLE_PTR        phPrivateKey,
		CK_RV                       rv);
};

