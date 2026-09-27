/*****************************************************************************
 EcParamsErrorTests.h

 CKA_EC_PARAMS that the C++ engine cannot use must be refused with the codes
 PKCS#11 v3.2 §6.3 names (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID),
 never CKR_GENERAL_ERROR, and a malformed curveName must never crash it.
 See EcParamsErrorTests.cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ECPARAMSERRORTESTS_H
#define _SOFTHSM_V2_ECPARAMSERRORTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class EcParamsErrorTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(EcParamsErrorTests);
	CPPUNIT_TEST(testEcKeyGenRefusesUnusableParams);
	CPPUNIT_TEST(testEdKeyGenRefusesUnusableParams);
	CPPUNIT_TEST(testEdImportMalformedCurveNameDoesNotCrash);
	CPPUNIT_TEST_SUITE_END();

public:
	void testEcKeyGenRefusesUnusableParams();
	void testEdKeyGenRefusesUnusableParams();
	void testEdImportMalformedCurveNameDoesNotCrash();
};

#endif // !_SOFTHSM_V2_ECPARAMSERRORTESTS_H
