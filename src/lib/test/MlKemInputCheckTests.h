/*****************************************************************************
 MlKemInputCheckTests.h

 ML-KEM (FIPS 203) input checks through the real PKCS#11 ABI: the NIST ACVP
 encapDecap VAL key-check and decapsulation cases, plus key/ciphertext
 length boundaries. See MlKemInputCheckTests.cpp.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMINPUTCHECKTESTS_H
#define _SOFTHSM_V2_MLKEMINPUTCHECKTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <vector>

class MlKemInputCheckTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(MlKemInputCheckTests);
	CPPUNIT_TEST(testNistKeyChecks);
	CPPUNIT_TEST(testNistDecapsulation);
	CPPUNIT_TEST(testLengthBoundaries);
	CPPUNIT_TEST_SUITE_END();

public:
	void testNistKeyChecks();
	void testNistDecapsulation();
	void testLengthBoundaries();

protected:
	void openSession(CK_SESSION_HANDLE& hSession);
	CK_RV importKey(CK_SESSION_HANDLE hSession, bool isPrivate, CK_ULONG paramSet,
	                const std::vector<unsigned char>& value, CK_OBJECT_HANDLE& hKey);
	CK_RV decapsulate(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPrk,
	                  const std::vector<unsigned char>& ct, CK_OBJECT_HANDLE& hSecret);
};

#endif // !_SOFTHSM_V2_MLKEMINPUTCHECKTESTS_H
