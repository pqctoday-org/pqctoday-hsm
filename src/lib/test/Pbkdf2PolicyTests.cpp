/*****************************************************************************
 Pbkdf2PolicyTests.cpp

 Gap-closure plan 2026-09-25, finding E15 / decision D7 (C++ engine).

 Vectors: tests/acvp/pbkdf2_acvp_test.json — the NIST ACVP-Server@975de31e
 PBKDF-1.0 sample subset (PRF HMAC-SHA2-224; copied from pqctoday-hub
 src/data/acvp/ @ c9c75a624).

 D7: keep the < 1000-iteration floor (NIST SP 800-132 §5.2's recommended
 minimum) on BOTH engines. The Rust engine already refused c < 1000
 (rust/src/ffi.rs, CKM_PKCS5_PBKD2 arm); the C++ engine accepted c = 1.
 Every NIST case at or above the floor must derive byte-exact; the c = 1
 case (tc20) must be refused "by policy" with CKR_MECHANISM_PARAM_INVALID
 (decision D6: the count is a mechanism-parameter field, PKCS#11 v3.2
 §5.1.6), and the boundary sits exactly at 1000 (c = 0 refused too).
 *****************************************************************************/

#include <config.h>
#include "Pbkdf2PolicyTests.h"
#include "AcvpKatUtil.h"

CPPUNIT_TEST_SUITE_REGISTRATION(Pbkdf2PolicyTests);

static const CK_ULONG kPolicyFloor = 1000;  // SP 800-132 §5.2; = PBKDF2_MIN_ITERATIONS

CK_RV Pbkdf2PolicyTests::derive(CK_SESSION_HANDLE hSession, const std::string& password,
                                const std::vector<unsigned char>& salt, CK_ULONG iterations,
                                CK_ULONG prf, CK_ULONG keyLen, std::vector<unsigned char>& out)
{
	std::vector<unsigned char> pw(password.begin(), password.end());
	std::vector<unsigned char> s(salt);
	CK_ULONG pwLen = (CK_ULONG)pw.size();
	CK_PKCS5_PBKD2_PARAMS2 params = {
		CKZ_SALT_SPECIFIED, s.data(), (CK_ULONG)s.size(), iterations,
		prf, NULL_PTR, 0, pw.data(), pwLen
	};
	CK_MECHANISM mech = { CKM_PKCS5_PBKD2, &params, sizeof(params) };
	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) }, { CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) }, { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }, { CKA_VALUE_LEN, &keyLen, sizeof(keyLen) },
	};
	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
	CK_RV rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, &mech, CK_INVALID_HANDLE, tmpl,
	                                       sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &h) );
	out.clear();
	if (rv != CKR_OK) return rv;
	out.resize(keyLen);
	CK_ATTRIBUTE a[] = { { CKA_VALUE, out.data(), keyLen } };
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, h, a, 1) );
	out.resize(rv == CKR_OK ? a[0].ulValueLen : 0);
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, h) );
	return rv;
}

void Pbkdf2PolicyTests::testNistPbkdfAndIterationFloor()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_SESSION_HANDLE hSession;
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	nlohmann::json doc = acvpkat::load("pbkdf2_acvp_test.json");
	acvpkat::Failures f;
	size_t belowFloor = 0, derived = 0;
	for (const auto& g : doc["testGroups"])
	{
		CPPUNIT_ASSERT(g["hmacAlg"] == "SHA2-224");
		for (const auto& t : g["tests"])
		{
			const std::string id = "tc" + std::to_string(t["tcId"].get<int>());
			const CK_ULONG iters = (CK_ULONG)t["iterationCount"].get<long>();
			const CK_ULONG keyLen = (CK_ULONG)(t["keyLen"].get<int>() / 8);
			std::vector<unsigned char> out;
			rv = derive(hSession, t["password"].get<std::string>(), acvpkat::hexField(t, "salt"),
			            iters, CKP_PKCS5_PBKD2_HMAC_SHA224, keyLen, out);
			if (iters < kPolicyFloor)
			{
				belowFloor++;
				f.check(rv == CKR_MECHANISM_PARAM_INVALID, id + " (c=" + std::to_string(iters) +
				        "): expected refusal by policy (CKR_MECHANISM_PARAM_INVALID), got " + acvpkat::rvHex(rv));
			}
			else
			{
				derived++;
				f.check(rv == CKR_OK && out == acvpkat::hexField(t, "derivedKey"),
				        id + " (c=" + std::to_string(iters) + "): derive rv=" + acvpkat::rvHex(rv) +
				        (rv == CKR_OK ? ", DK differs from NIST" : ""));
			}
		}
	}

	// The floor is exactly 1000: 999 refused, 1000 derives.
	std::vector<unsigned char> out, salt(16, 0xa5);
	rv = derive(hSession, "policy-floor", salt, kPolicyFloor - 1, CKP_PKCS5_PBKD2_HMAC_SHA256, 32, out);
	f.check(rv == CKR_MECHANISM_PARAM_INVALID, "c=999: expected CKR_MECHANISM_PARAM_INVALID, got " + acvpkat::rvHex(rv));
	rv = derive(hSession, "policy-floor", salt, 0, CKP_PKCS5_PBKD2_HMAC_SHA256, 32, out);
	f.check(rv == CKR_MECHANISM_PARAM_INVALID, "c=0: expected CKR_MECHANISM_PARAM_INVALID, got " + acvpkat::rvHex(rv));
	rv = derive(hSession, "policy-floor", salt, kPolicyFloor, CKP_PKCS5_PBKD2_HMAC_SHA256, 32, out);
	f.check(rv == CKR_OK && out.size() == 32, "c=1000: expected CKR_OK, got " + acvpkat::rvHex(rv));

	f.assertNone("PBKDF2 NIST cases + iteration floor");
	CPPUNIT_ASSERT_EQUAL((size_t)1, belowFloor);
	CPPUNIT_ASSERT_EQUAL((size_t)4, derived);
}
