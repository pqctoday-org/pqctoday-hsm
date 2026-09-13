/*
 * Copyright (c) 2026 pqctoday
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BehaviourRingTests.h

 Contains test cases for the behaviour event ring writer
 (src/lib/common/BehaviourRing.{h,cpp}) -- record encoding against the golden
 vectors shared with the Rust engine, and the ring file's header and slot
 semantics.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BEHAVIOURRINGTESTS_H
#define _SOFTHSM_V2_BEHAVIOURRINGTESTS_H

#include <cppunit/extensions/HelperMacros.h>

class BehaviourRingTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(BehaviourRingTests);
	CPPUNIT_TEST(testBuckets);
	CPPUNIT_TEST(testGoldenVectors);
	CPPUNIT_TEST(testIdTables);
	CPPUNIT_TEST(testRingWriteAndReadBack);
	CPPUNIT_TEST(testRingWrapAndGeometryRefusal);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp();
	void tearDown();

	void testBuckets();
	void testGoldenVectors();
	void testIdTables();
	void testRingWriteAndReadBack();
	void testRingWrapAndGeometryRefusal();
};

#endif // !_SOFTHSM_V2_BEHAVIOURRINGTESTS_H
