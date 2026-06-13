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
 SessionTests.cpp

 Contains test cases to C_OpenSession, C_CloseSession, C_CloseAllSessions, and
 C_GetSessionInfo
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "SessionTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SessionTests);

void SessionTests::testOpenSession()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

    // Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_invalidSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_notInitializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_TOKEN_NOT_RECOGNIZED);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, 0, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_PARALLEL_NOT_SUPPORTED);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void SessionTests::testCloseSession()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseSession(CK_INVALID_HANDLE) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession + 1) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
}

void SessionTests::testCloseAllSessions()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_SESSION_INFO info;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_CloseAllSessions(m_initializedTokenSlotID) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseAllSessions(m_invalidSlotID) );
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

	rv = CRYPTOKI_F_PTR( C_CloseAllSessions(m_notInitializedTokenSlotID) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, &info) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseAllSessions(m_initializedTokenSlotID) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
}

void SessionTests::testGetSessionInfo()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_SESSION_INFO info;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, &info) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(CK_INVALID_HANDLE, &info) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession + 1, &info) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);

	rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, &info) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    CPPUNIT_ASSERT(info.state == CKS_RO_PUBLIC_SESSION);
	CPPUNIT_ASSERT(info.flags == CKF_SERIAL_SESSION);

    rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR( C_GetSessionInfo(hSession, &info) );
	CPPUNIT_ASSERT(rv == CKR_SESSION_HANDLE_INVALID);
}

void SessionTests::testSessionCancel()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_BYTE data[] = "test";
	CK_BYTE digest[32];
	CK_ULONG digestLen = sizeof(digest);

	// 1. flags==0 with no active operation: spec §5.6.5 says nothing was
	//    requested, so this is a no-op that returns CKR_OK (V-16).
	rv = CRYPTOKI_F_PTR( C_SessionCancel(hSession, 0) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Initialize a Digest operation
	CK_MECHANISM mechanism = { CKM_SHA256, NULL_PTR, 0 };
	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// 2. Unmatched flag: cancelling ENCRYPT while only DIGEST is running must
	//    be ignored (CKR_OK) and the DIGEST op must remain active (V-16).
	rv = CRYPTOKI_F_PTR( C_SessionCancel(hSession, CKF_ENCRYPT) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// The digest op survived the unmatched cancel — it can still complete.
	digestLen = sizeof(digest);
	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data) - 1, digest, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// 3. Matched cancel: start a new DIGEST and cancel it with CKF_DIGEST.
	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_SessionCancel(hSession, CKF_DIGEST) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Digest should now fail because it was cancelled.
	digestLen = sizeof(digest);
	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data) - 1, digest, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OPERATION_NOT_INITIALIZED);

	// 4. flags==0 is always a no-op: an active op must NOT be cancelled by it.
	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_SessionCancel(hSession, 0) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// The op survives flags==0; complete it to prove it is still active.
	digestLen = sizeof(digest);
	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data) - 1, digest, &digestLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}
