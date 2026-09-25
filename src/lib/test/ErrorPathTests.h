/*
 * Copyright (c) 2026 PQC Today
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
 ErrorPathTests.h

 PKCS#11 v3.2 error-path return values found wrong by the Hub's G-8
 error-path probes (2026-09-25). Every expected value is the one the
 specification names; each test cites its section.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ERRORPATHTESTS_H
#define _SOFTHSM_V2_ERRORPATHTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <string>

class ErrorPathTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(ErrorPathTests);
	CPPUNIT_TEST(testKeyTypeInconsistentAtInit);
	CPPUNIT_TEST(testUnwrapKeyTypeCode);
	CPPUNIT_TEST_SUITE_END();

public:
	void testKeyTypeInconsistentAtInit();
	void testUnwrapKeyTypeCode();

protected:
	CK_RV openUserSession(CK_SESSION_HANDLE& hSession);
	bool advertised(CK_MECHANISM_TYPE mech);
	CK_RV aesKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE& hKey);
	CK_RV rsaKeyPair(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE& hPuk, CK_OBJECT_HANDLE& hPrk);
	CK_RV ecKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL sign, CK_BBOOL derive,
	                CK_OBJECT_HANDLE& hPuk, CK_OBJECT_HANDLE& hPrk);
	CK_RV pqcKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE gen, CK_KEY_TYPE kt, CK_ULONG ps,
	                 CK_OBJECT_HANDLE& hPuk, CK_OBJECT_HANDLE& hPrk);
	static void expect(std::string& fails, const std::string& what, CK_RV got, CK_RV want);
};

#endif // !_SOFTHSM_V2_ERRORPATHTESTS_H
