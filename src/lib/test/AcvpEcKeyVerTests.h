/*****************************************************************************
 AcvpEcKeyVerTests.h

 EC public-key validation at C_CreateObject (CKR_PUBLIC_KEY_INVALID, PKCS#11
 v3.2 §5.1.6): NIST ACVP KeyVer verdicts for P-224/256/384/521, Ed25519 and
 Ed448, plus the Edwards cases NIST does not publish. See the .cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ACVPECKEYVERTESTS_H
#define _SOFTHSM_V2_ACVPECKEYVERTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <vector>

class AcvpEcKeyVerTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(AcvpEcKeyVerTests);
	CPPUNIT_TEST(testNistKeyVer);
	CPPUNIT_TEST(testEdwardsOutsideSubgroup);
	CPPUNIT_TEST_SUITE_END();

public:
	void testNistKeyVer();
	void testEdwardsOutsideSubgroup();

protected:
	void openSession(CK_SESSION_HANDLE& hSession);
	CK_RV createPublic(CK_SESSION_HANDLE hSession, CK_KEY_TYPE kt, const std::vector<unsigned char>& oid,
	                   const std::vector<unsigned char>& point);
};

#endif // !_SOFTHSM_V2_ACVPECKEYVERTESTS_H
