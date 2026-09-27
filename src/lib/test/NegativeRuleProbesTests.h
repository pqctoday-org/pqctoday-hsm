/*****************************************************************************
 NegativeRuleProbesTests.h

 2.D negative-rule probes, C++ engine: the same twelve PKCS#11 v3.2 rules the
 Rust engine's ffi::negative_rule_probes_2d drives (rust/src/ffi.rs), each
 asserting the SPEC-correct outcome. See NegativeRuleProbesTests.cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_NEGATIVERULEPROBESTESTS_H
#define _SOFTHSM_V2_NEGATIVERULEPROBESTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class NegativeRuleProbesTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(NegativeRuleProbesTests);
	CPPUNIT_TEST(testP01UniqueIdGeneratedUniqueAndReadOnly);
	CPPUNIT_TEST(testP02TrustedTrueRefusedInUserSession);
	CPPUNIT_TEST(testP03CounterModeRejectsCounterDataParam);
	CPPUNIT_TEST(testP04DkmLengthAtMostOneInstance);
	CPPUNIT_TEST(testP05UnwrapLengthConflictsWithKeyType);
	CPPUNIT_TEST(testP06SessionInfoSerialFlagAlwaysSet);
	CPPUNIT_TEST(testP07EveryListedSlotAnswersGetSlotInfo);
	CPPUNIT_TEST(testP08SizeQueryIgnoresInputValueLen);
	CPPUNIT_TEST(testP09GetAttributeValueContinuesAfterInvalidType);
	CPPUNIT_TEST(testP10MessageSignVerifyInitRequireUsageFlag);
	CPPUNIT_TEST(testP11ObserveMissingIterationVariable);
	CPPUNIT_TEST(testP12ObserveTwoCounterParams);
	CPPUNIT_TEST(testDkmLengthMatchesReference);
	CPPUNIT_TEST_SUITE_END();

public:
	void testP01UniqueIdGeneratedUniqueAndReadOnly();
	void testP02TrustedTrueRefusedInUserSession();
	void testP03CounterModeRejectsCounterDataParam();
	void testP04DkmLengthAtMostOneInstance();
	void testP05UnwrapLengthConflictsWithKeyType();
	void testP06SessionInfoSerialFlagAlwaysSet();
	void testP07EveryListedSlotAnswersGetSlotInfo();
	void testP08SizeQueryIgnoresInputValueLen();
	void testP09GetAttributeValueContinuesAfterInvalidType();
	void testP10MessageSignVerifyInitRequireUsageFlag();
	void testP11ObserveMissingIterationVariable();
	void testP12ObserveTwoCounterParams();
	void testDkmLengthMatchesReference();
};

#endif // !_SOFTHSM_V2_NEGATIVERULEPROBESTESTS_H
