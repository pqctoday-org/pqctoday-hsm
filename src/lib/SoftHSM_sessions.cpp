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
 SoftHSM_sessions.cpp

 PKCS#11 session management: C_OpenSession, C_CloseSession,
 C_CloseAllSessions, C_GetSessionInfo, C_GetOperationState,
 C_SetOperationState, C_Login, C_Logout.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "HandleManager.h"
#include "SessionManager.h"
#include "cryptoki.h"
#include "SlotManager.h"

CK_RV SoftHSM::C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	Slot* slot = slotManager->getSlot(slotID);

	CK_RV rv = sessionManager->openSession(slot, flags, pApplication, notify, phSession);
	if (rv != CKR_OK)
		return rv;

	// Get a pointer to the session object and store it in the handle manager.
	auto sessionGuard = sessionManager->getSession(*phSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	*phSession = handleManager->addSession(slotID, sessionGuard);

	return CKR_OK;
}

// Close the given session
CK_RV SoftHSM::C_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Tell the handle manager the session has been closed.
	handleManager->sessionClosed(hSession);


	// Tell the session object store that the session has closed.
	sessionObjectStore->sessionClosed(hSession);

	// Tell the session manager the session has been closed.
	return sessionManager->closeSession(session->getHandle());
}

// Close all open sessions
CK_RV SoftHSM::C_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the slot
	Slot* slot = slotManager->getSlot(slotID);
	if (slot == NULL) return CKR_SLOT_ID_INVALID;

	// Get the token
	Token* token = slot->getToken();
	if (token == NULL) return CKR_TOKEN_NOT_PRESENT;

	// Tell the handle manager all sessions were closed for the given slotID.
	// The handle manager should then remove all session and object handles for this slot.
	handleManager->allSessionsClosed(slotID);

	// Tell the session object store that all sessions were closed for the given slotID.
	// The session object store should then remove all session objects for this slot.
	sessionObjectStore->allSessionsClosed(slotID);

	// Finally tell the session manager tho close all sessions for the given slot.
	// This will also trigger a logout on the associated token to occur.
	return sessionManager->closeAllSessions(slot);
}

// Retrieve information about the specified session
CK_RV SoftHSM::C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	return session->getInfo(pInfo);
}

// Determine the state of a running operation in a session
CK_RV SoftHSM::C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pOperationState*/, CK_ULONG_PTR /*pulOperationStateLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Session-state serialization is not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Set the operation sate in a session
CK_RV SoftHSM::C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pOperationState*/, CK_ULONG /*ulOperationStateLen*/, CK_OBJECT_HANDLE /*hEncryptionKey*/, CK_OBJECT_HANDLE /*hAuthenticationKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Session-state serialization is not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Login on the token in the specified session
CK_RV SoftHSM::C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;

	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the PIN
	if (pPin == NULL_PTR) return CKR_ARGUMENTS_BAD;
	ByteString pin(pPin, ulPinLen);

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	switch (userType)
	{
		case CKU_SO:
			// There cannot exist a R/O session on this slot
			if (sessionManager->haveROSession(session->getSlot()->getSlotID())) return CKR_SESSION_READ_ONLY_EXISTS;

			// Login
			rv = token->loginSO(pin);
			break;
		case CKU_USER:
			// Login
			rv = token->loginUser(pin);
			break;
		case CKU_CONTEXT_SPECIFIC:
			// Check if re-authentication is required
			if (!session->getReAuthentication()) return CKR_OPERATION_NOT_INITIALIZED;

			// Re-authenticate
			rv = token->reAuthenticate(pin);
			if (rv == CKR_OK) session->setReAuthentication(false);
			break;
		default:
			return CKR_USER_TYPE_INVALID;
	}

	return rv;
}

// Log out of the token in the specified session
CK_RV SoftHSM::C_Logout(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Logout
	token->logout();

	// [PKCS#11 v2.40, C_Logout] When logout is successful...
	// a. Any of the application's handles to private objects become invalid.
	// b. Even if a user is later logged back into the token those handles remain invalid.
	// c. All private session objects from sessions belonging to the application are destroyed.

	// Have the handle manager remove all handles pointing to private objects for this slot.
	CK_SLOT_ID slotID = session->getSlot()->getSlotID();
	handleManager->tokenLoggedOut(slotID);
	sessionObjectStore->tokenLoggedOut(slotID);

	return CKR_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// G6: PKCS#11 v3.0 session management extensions
// ─────────────────────────────────────────────────────────────────────────────

// C_LoginUser — Like C_Login but adds an optional username (PKCS#11 v3.0 §5.6.8).
// softhsmv3 uses single-user per-role tokens; pUsername is accepted but ignored.
CK_RV SoftHSM::C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
	CK_UTF8CHAR_PTR /*pUsername*/, CK_ULONG /*ulUsernameLen*/)
{
	// Delegate to C_Login; username is not used in single-user token model.
	return C_Login(hSession, userType, pPin, ulPinLen);
}

// C_SessionCancel — Cancel one or more active cryptographic operations in the
// session (PKCS#11 v3.2 §5.6.5).  flags is a bitmask naming the operation
// type(s) to cancel.
//
// V-16 semantics:
//   - flags == 0          → no-op, return CKR_OK (nothing requested).
//   - a flag whose op is   → ignore the flag (the spec says only the requested
//     not active             operations that are active get cancelled; an
//                            unmatched flag is not an error).
//   - matched flag         → cancel the active op.
//
// softhsmv3 supports exactly one active operation per session, so cancelling
// any matching flag cancels that single operation.  We honour both the legacy
// CKF_ENCRYPT/DECRYPT/SIGN/VERIFY/DIGEST flags and the v3.0/3.2 message flags
// (CKF_MESSAGE_*) and CKF_FIND_OBJECTS so message-session ops and Find can be
// cancelled.
CK_RV SoftHSM::C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// flags == 0: nothing was requested → no-op success.
	if (flags == 0)
		return CKR_OK;

	int opType = session->getOpType();

	// Determine whether any set flag names the operation currently active. If
	// the named op is not active we silently ignore that flag (spec: only the
	// active requested operations are cancelled; an unmatched flag is not an
	// error).
	bool match = false;

	// Encrypt family (single-part, message, and dual ops).
	if ((flags & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT)) &&
	    (opType == SESSION_OP_ENCRYPT || opType == SESSION_OP_MESSAGE_ENCRYPT ||
	     opType == SESSION_OP_MESSAGE_ENCRYPT_BEGIN ||
	     opType == SESSION_OP_DIGEST_ENCRYPT || opType == SESSION_OP_SIGN_ENCRYPT))
		match = true;

	// Decrypt family.
	if ((flags & (CKF_DECRYPT | CKF_MESSAGE_DECRYPT)) &&
	    (opType == SESSION_OP_DECRYPT || opType == SESSION_OP_MESSAGE_DECRYPT ||
	     opType == SESSION_OP_MESSAGE_DECRYPT_BEGIN ||
	     opType == SESSION_OP_DECRYPT_DIGEST || opType == SESSION_OP_DECRYPT_VERIFY))
		match = true;

	// Sign family.
	if ((flags & (CKF_SIGN | CKF_MESSAGE_SIGN)) &&
	    (opType == SESSION_OP_SIGN || opType == SESSION_OP_MESSAGE_SIGN ||
	     opType == SESSION_OP_MESSAGE_SIGN_BEGIN || opType == SESSION_OP_SIGN_RECOVER ||
	     opType == SESSION_OP_SIGN_ENCRYPT))
		match = true;

	// Verify family.
	if ((flags & (CKF_VERIFY | CKF_MESSAGE_VERIFY)) &&
	    (opType == SESSION_OP_VERIFY || opType == SESSION_OP_MESSAGE_VERIFY ||
	     opType == SESSION_OP_MESSAGE_VERIFY_BEGIN || opType == SESSION_OP_VERIFY_RECOVER ||
	     opType == SESSION_OP_VERIFY_SIGNATURE || opType == SESSION_OP_DECRYPT_VERIFY))
		match = true;

	// Digest family.
	if ((flags & CKF_DIGEST) &&
	    (opType == SESSION_OP_DIGEST || opType == SESSION_OP_DIGEST_ENCRYPT ||
	     opType == SESSION_OP_DECRYPT_DIGEST))
		match = true;

	// Find objects.
	if ((flags & CKF_FIND_OBJECTS) && (opType == SESSION_OP_FIND))
		match = true;

	// No requested operation is active → ignore (success, nothing to cancel).
	if (!match)
		return CKR_OK;

	session->resetOp();

	return CKR_OK;
}

// C_GetSessionValidationFlags — Report the session's validation state flags
// (PKCS#11 v3.2 §5.6.11).  V-19: must honour the init gate and validate the
// session handle and the requested validation-flags type.  This software token
// performs no FIPS/CC validation of operations, so *pFlags = 0 ("no validation
// performed / no validation state recorded") is the honest answer once the
// arguments are accepted.
CK_RV SoftHSM::C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession,
	CK_SESSION_VALIDATION_FLAGS_TYPE type, CK_FLAGS_PTR pFlags)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pFlags == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Validate the requested flags type. The only defined query state is
	// CKS_LAST_VALIDATION_OK; anything else is a bad argument.
	if (type != CKS_LAST_VALIDATION_OK) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// No validation constraints recorded for a software token.
	*pFlags = 0;
	return CKR_OK;
}


