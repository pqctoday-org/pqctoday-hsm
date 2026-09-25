/*****************************************************************************
 AcvpSlhDsaTests.h

 NIST ACVP SLH-DSA (FIPS 205) SigVer + deterministic SigGen known-answer
 tests, pure and pre-hash (HashSLH-DSA), through the real PKCS#11 ABI.
 See AcvpSlhDsaTests.cpp for vector provenance and expected-verdict rules.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ACVPSLHDSATESTS_H
#define _SOFTHSM_V2_ACVPSLHDSATESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <vector>

namespace acvpkat { struct Failures; }

class AcvpSlhDsaTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(AcvpSlhDsaTests);
	CPPUNIT_TEST(testSigVer);
	CPPUNIT_TEST(testDeterministicSigGen);
	CPPUNIT_TEST_SUITE_END();

public:
	void testSigVer();
	void testDeterministicSigGen();

protected:
	void openSession(CK_SESSION_HANDLE& hSession);
	CK_RV importKey(CK_SESSION_HANDLE hSession, bool isPrivate, CK_ULONG paramSet,
	                const std::vector<unsigned char>& value, CK_OBJECT_HANDLE& hKey);
	void runSigVerFile(const char* file, CK_SESSION_HANDLE hSession, acvpkat::Failures& f,
	                   size_t& positives, size_t& preHashCases);
};

#endif // !_SOFTHSM_V2_ACVPSLHDSATESTS_H
