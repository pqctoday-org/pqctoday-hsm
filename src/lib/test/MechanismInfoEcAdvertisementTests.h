/*****************************************************************************
 MechanismInfoEcAdvertisementTests.h

 C_GetMechanismInfo's EC-family capability flags and Montgomery/BIP32 key-size
 ranges against what C_DeriveKey actually accepts (finding E20).
 See MechanismInfoEcAdvertisementTests.cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MECHANISMINFOECADVERTISEMENTTESTS_H
#define _SOFTHSM_V2_MECHANISMINFOECADVERTISEMENTTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class MechanismInfoEcAdvertisementTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(MechanismInfoEcAdvertisementTests);
	CPPUNIT_TEST(testEcdh1AdvertisesEcCapabilityFlags);
	CPPUNIT_TEST(testMontgomeryMechanismsAdvertiseTheirCurveSize);
	CPPUNIT_TEST(testBip32ChildDeriveAdvertisesItsParentKeySize);
	CPPUNIT_TEST_SUITE_END();

public:
	void testEcdh1AdvertisesEcCapabilityFlags();
	void testMontgomeryMechanismsAdvertiseTheirCurveSize();
	void testBip32ChildDeriveAdvertisesItsParentKeySize();
};

#endif // !_SOFTHSM_V2_MECHANISMINFOECADVERTISEMENTTESTS_H
