/*****************************************************************************
 HmacMinKeySizeTests.h

 C_GetMechanismInfo's HMAC ulMinKeySize against the keys the engine actually
 accepts (NIST ACVP HMAC 2.0 samples). See HmacMinKeySizeTests.cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_HMACMINKEYSIZETESTS_H
#define _SOFTHSM_V2_HMACMINKEYSIZETESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class HmacMinKeySizeTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(HmacMinKeySizeTests);
	CPPUNIT_TEST(testAdvertisedMinimumMatchesAcceptedKeys);
	CPPUNIT_TEST_SUITE_END();

public:
	void testAdvertisedMinimumMatchesAcceptedKeys();
};

#endif // !_SOFTHSM_V2_HMACMINKEYSIZETESTS_H
