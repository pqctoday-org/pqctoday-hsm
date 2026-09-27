/*****************************************************************************
 Pbkdf2PolicyTests.h

 CKM_PKCS5_PBKD2: NIST ACVP PBKDF 1.0 known answers above the token's
 iteration floor, and the floor itself. See Pbkdf2PolicyTests.cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_PBKDF2POLICYTESTS_H
#define _SOFTHSM_V2_PBKDF2POLICYTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <vector>

class Pbkdf2PolicyTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(Pbkdf2PolicyTests);
	CPPUNIT_TEST(testNistPbkdfAndIterationFloor);
	CPPUNIT_TEST_SUITE_END();

public:
	void testNistPbkdfAndIterationFloor();

protected:
	CK_RV derive(CK_SESSION_HANDLE hSession, const std::string& password, const std::vector<unsigned char>& salt,
	             CK_ULONG iterations, CK_ULONG prf, CK_ULONG keyLen, std::vector<unsigned char>& out);
};

#endif // !_SOFTHSM_V2_PBKDF2POLICYTESTS_H
