/*****************************************************************************
 KmacParamsTests.h

 CKM_KMAC_128 with CK_PQCTODAY_KMAC_PARAMS (output length L + customization
 S) against NIST ACVP KMAC-128 1.0 MVT cases. See KmacParamsTests.cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_KMACPARAMSTESTS_H
#define _SOFTHSM_V2_KMACPARAMSTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <vector>

class KmacParamsTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(KmacParamsTests);
	CPPUNIT_TEST(testNistMvt);
	CPPUNIT_TEST(testParameterValidation);
	CPPUNIT_TEST_SUITE_END();

public:
	void testNistMvt();
	void testParameterValidation();

protected:
	void openSession(CK_SESSION_HANDLE& hSession);
	CK_RV importKey(CK_SESSION_HANDLE hSession, const std::vector<unsigned char>& value, CK_OBJECT_HANDLE& hKey);
};

#endif // !_SOFTHSM_V2_KMACPARAMSTESTS_H
