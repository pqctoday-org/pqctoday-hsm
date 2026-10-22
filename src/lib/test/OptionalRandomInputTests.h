/*****************************************************************************
 OptionalRandomInputTests.h

 The optional caller-supplied randomness model (vendor_mechanisms.h,
 "Optional caller-supplied randomness"; acvp-explicit-randomness-model plan,
 P2/P4) through the real PKCS#11 ABI, C++ engine:

   shape 1  CKM_ML_KEM C_EncapsulateKey with m (CKM_ECDSA + k lives in
            AcvpEcdsaExplicitKTests);
   shape 2  the extended CK_[HASH_]SIGN_ADDITIONAL_CONTEXT with rnd / addrnd
            and messageEncoding for ML-DSA and SLH-DSA.

 NIST ACVP vectors byte-exact for every in-scope group, absent input
 unchanged, sabotage, refusals, no sensitivity guard (D0 a), interoperability
 of the output under the standard mechanisms, and the operation log.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OPTIONALRANDOMINPUTTESTS_H
#define _SOFTHSM_V2_OPTIONALRANDOMINPUTTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <vector>

class OptionalRandomInputTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(OptionalRandomInputTests);
	CPPUNIT_TEST(testMlKemEncapsulateMatchesNist);
	CPPUNIT_TEST(testMlKemRefusalsAndAbsentInput);
	CPPUNIT_TEST(testMlDsaSigGenMatchesNist);
	CPPUNIT_TEST(testMlDsaSigVerInternalMatchesNist);
	CPPUNIT_TEST(testSlhDsaSigGenMatchesNist);
	CPPUNIT_TEST(testSlhDsaSigVerInternalMatchesNist);
	CPPUNIT_TEST(testFullNistSetWhenProvided);
	CPPUNIT_TEST(testSignContextRefusals);
	CPPUNIT_TEST(testAbsentInputUnchanged);
	CPPUNIT_TEST(testSabotageAndInteroperability);
	CPPUNIT_TEST(testNoSensitivityGuard);
	CPPUNIT_TEST(testOperationLogNotesSuppliedInput);
	CPPUNIT_TEST(testGenericPreHashSha512t);
	CPPUNIT_TEST(testVerifySignatureLengthRange);
	CPPUNIT_TEST(testGenericPreHashSinglePartOnly);
	CPPUNIT_TEST_SUITE_END();

public:
	void testMlKemEncapsulateMatchesNist();
	void testMlKemRefusalsAndAbsentInput();
	void testMlDsaSigGenMatchesNist();
	void testMlDsaSigVerInternalMatchesNist();
	void testSlhDsaSigGenMatchesNist();
	void testSlhDsaSigVerInternalMatchesNist();
	void testFullNistSetWhenProvided();
	void testSignContextRefusals();
	void testAbsentInputUnchanged();
	void testSabotageAndInteroperability();
	void testNoSensitivityGuard();
	void testOperationLogNotesSuppliedInput();
	void testGenericPreHashSha512t();
	void testVerifySignatureLengthRange();
	void testGenericPreHashSinglePartOnly();

protected:
	void openSession(CK_SESSION_HANDLE& hSession);
};

#endif // !_SOFTHSM_V2_OPTIONALRANDOMINPUTTESTS_H
