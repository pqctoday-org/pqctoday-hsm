/*****************************************************************************
 AcvpEcdsaExplicitKTests.h

 CKM_PQCTODAY_ECDSA_EXPLICIT_K (vendor; a deliberate key-recovery teaching
 primitive — SECURITY.md) through the real PKCS#11 ABI: NIST ACVP ECDSA
 SigGen byte-matches, parameter and key refusals, sabotage controls, and the
 mechanism's advertisement. See AcvpEcdsaExplicitKTests.cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ACVPECDSAEXPLICITKTESTS_H
#define _SOFTHSM_V2_ACVPECDSAEXPLICITKTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <vector>

class AcvpEcdsaExplicitKTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(AcvpEcdsaExplicitKTests);
	CPPUNIT_TEST(testSigGenMatchesNist);
	CPPUNIT_TEST(testSabotageIsDetected);
	CPPUNIT_TEST(testRefusals);
	CPPUNIT_TEST(testAdvertisedSignOnly);
	CPPUNIT_TEST_SUITE_END();

public:
	void testSigGenMatchesNist();
	void testSabotageIsDetected();
	void testRefusals();
	void testAdvertisedSignOnly();

protected:
	void openSession(CK_SESSION_HANDLE& hSession);
	CK_OBJECT_HANDLE importPrivate(CK_SESSION_HANDLE hSession, const std::vector<unsigned char>& oid,
	                               const std::vector<unsigned char>& d);
	CK_OBJECT_HANDLE importPublic(CK_SESSION_HANDLE hSession, const std::vector<unsigned char>& oid,
	                              const std::vector<unsigned char>& qx, const std::vector<unsigned char>& qy);
	CK_RV signInit(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, const std::vector<unsigned char>* k);
	CK_RV sign(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, const std::vector<unsigned char>& k,
	           std::vector<unsigned char>& digest, std::vector<unsigned char>& sig);
};

#endif // !_SOFTHSM_V2_ACVPECDSAEXPLICITKTESTS_H
