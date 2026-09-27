/*****************************************************************************
 MlKemInputCheckTests.cpp

 Gap-closure plan 2026-09-25, finding E3 (C++ engine).

 Vectors: tests/acvp/mlkem_encapdecap_val_test.json — a byte-copied subset of
 NIST ACVP-Server@975de31e ML-KEM-encapDecap-FIPS203 (provenance in the
 file; copied from pqctoday-hub src/data/acvp/ @ 7656391c7).

 * Key checks (FIPS 203 §7.2 encapsulation-key modulus check, §7.3
   decapsulation-key hash check): C_CreateObject of every key-check case —
   testPassed=true -> CKR_OK, testPassed=false -> CKR_ATTRIBUTE_VALUE_INVALID
   (PKCS#11 v3.2 §4.1.1 rule 2; §6.68.2/§6.68.3 define CKA_VALUE as the FIPS
   203 ek/dk). Before the fix C_CreateObject stored all of them.
 * Decapsulation: every case (valid and modified ciphertext — implicit
   rejection) decapsulates byte-exact to the upstream k.
 * Boundaries: ek/dk one byte short or long -> CKR_ATTRIBUTE_VALUE_INVALID
   (FIPS 203 §7.2/§7.3 type check); a ciphertext of another parameter set's
   length (or off by one) -> CKR_WRAPPED_KEY_LEN_RANGE (PKCS#11 v3.2 §5.1.6
   "invalid solely on the basis of its length", listed for C_DecapsulateKey
   in §5.18.9), with no key object created. Before the fix a 768- or
   1568-byte ciphertext against an ML-KEM-768 key returned
   CKR_WRAPPED_KEY_INVALID and a 1-byte-short dk was accepted.
 *****************************************************************************/

#include <config.h>
#include "MlKemInputCheckTests.h"
#include "AcvpKatUtil.h"
#include <cstring>

CPPUNIT_TEST_SUITE_REGISTRATION(MlKemInputCheckTests);

namespace {

CK_ULONG mlkemParamSet(const std::string& name)
{
	if (name == "ML-KEM-512")  return CKP_ML_KEM_512;
	if (name == "ML-KEM-768")  return CKP_ML_KEM_768;
	if (name == "ML-KEM-1024") return CKP_ML_KEM_1024;
	return (CK_ULONG)-1;
}

const nlohmann::json* findCase(const nlohmann::json& doc, const char* function,
                               const char* paramSet, bool wantPassed)
{
	for (const auto& g : doc["testGroups"])
	{
		if (g["function"] != function || g["parameterSet"] != paramSet) continue;
		for (const auto& t : g["tests"])
			if (!t.contains("testPassed") || t["testPassed"].get<bool>() == wantPassed)
				return &t;
	}
	return NULL;
}

} // namespace

void MlKemInputCheckTests::openSession(CK_SESSION_HANDLE& hSession)
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

CK_RV MlKemInputCheckTests::importKey(CK_SESSION_HANDLE hSession, bool isPrivate, CK_ULONG paramSet,
                                      const std::vector<unsigned char>& value, CK_OBJECT_HANDLE& hKey)
{
	CK_OBJECT_CLASS cls = isPrivate ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
	CK_KEY_TYPE kt = CKK_ML_KEM;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	std::vector<unsigned char> v(value);
	std::vector<CK_ATTRIBUTE> tmpl = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ (CK_ATTRIBUTE_TYPE)(isPrivate ? CKA_DECAPSULATE : CKA_ENCAPSULATE), &bTrue, sizeof(bTrue) },
		{ CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
		{ CKA_VALUE, v.empty() ? NULL_PTR : v.data(), (CK_ULONG)v.size() },
	};
	if (isPrivate)
	{
		tmpl.push_back({ CKA_SENSITIVE, &bFalse, sizeof(bFalse) });
		tmpl.push_back({ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) });
	}
	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl.data(), (CK_ULONG)tmpl.size(), &hKey) );
}

CK_RV MlKemInputCheckTests::decapsulate(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPrk,
                                        const std::vector<unsigned char>& ct, CK_OBJECT_HANDLE& hSecret)
{
	CK_MECHANISM mech = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
	};
	std::vector<unsigned char> c(ct);
	hSecret = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mech, hPrk, tmpl, sizeof(tmpl) / sizeof(CK_ATTRIBUTE),
	                                        c.data(), (CK_ULONG)c.size(), &hSecret) );
}

void MlKemInputCheckTests::testNistKeyChecks()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	nlohmann::json doc = acvpkat::load("mlkem_encapdecap_val_test.json");
	acvpkat::Failures f;
	size_t negatives = 0;
	for (const auto& g : doc["testGroups"])
	{
		const std::string fn = g["function"].get<std::string>();
		if (fn != "encapsulationKeyCheck" && fn != "decapsulationKeyCheck") continue;
		const bool isPrivate = (fn == "decapsulationKeyCheck");
		const std::string ps = g["parameterSet"].get<std::string>();
		for (const auto& t : g["tests"])
		{
			const bool passed = t["testPassed"].get<bool>();
			if (!passed) negatives++;
			const std::string id = "tc" + std::to_string(t["tcId"].get<int>()) + " " + ps + " " + fn +
				" (" + t["reason"].get<std::string>() + ")";
			CK_OBJECT_HANDLE h;
			CK_RV rv = importKey(hSession, isPrivate, mlkemParamSet(ps),
			                     acvpkat::hexField(t, isPrivate ? "dk" : "ek"), h);
			const CK_RV expected = passed ? CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID;
			f.check(rv == expected, id + ": C_CreateObject expected " + acvpkat::rvHex(expected) +
			        ", got " + acvpkat::rvHex(rv));
			if (!passed)
				f.check(h == CK_INVALID_HANDLE, id + ": a refused key must not yield a handle");
			if (rv == CKR_OK && passed && !isPrivate)
			{
				// A key that passed the check stays usable.
				CK_MECHANISM mech = { CKM_ML_KEM, NULL_PTR, 0 };
				CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
				CK_ATTRIBUTE st[] = { { CKA_CLASS, &secretClass, sizeof(secretClass) } };
				CK_ULONG ctLen = 0;
				CK_OBJECT_HANDLE hs = CK_INVALID_HANDLE;
				CK_RV erv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mech, h, st, 1, NULL_PTR, &ctLen, &hs) );
				f.check(erv == CKR_OK && ctLen > 0, id + ": C_EncapsulateKey size query rv=" + acvpkat::rvHex(erv));
			}
			if (h != CK_INVALID_HANDLE) CRYPTOKI_F_PTR( C_DestroyObject(hSession, h) );
		}
	}
	f.assertNone("mlkem_encapdecap_val_test.json key checks");
	CPPUNIT_ASSERT_EQUAL((size_t)6, negatives);
}

void MlKemInputCheckTests::testNistDecapsulation()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	nlohmann::json doc = acvpkat::load("mlkem_encapdecap_val_test.json");
	acvpkat::Failures f;
	for (const auto& g : doc["testGroups"])
	{
		if (g["function"] != "decapsulation") continue;
		const std::string ps = g["parameterSet"].get<std::string>();
		for (const auto& t : g["tests"])
		{
			const std::string id = "tc" + std::to_string(t["tcId"].get<int>()) + " " + ps +
				" (" + t["reason"].get<std::string>() + ")";
			CK_OBJECT_HANDLE hPrk;
			CK_RV rv = importKey(hSession, true, mlkemParamSet(ps), acvpkat::hexField(t, "dk"), hPrk);
			if (rv != CKR_OK) { f.check(false, id + ": import dk rv=" + acvpkat::rvHex(rv)); continue; }
			CK_OBJECT_HANDLE hSecret;
			rv = decapsulate(hSession, hPrk, acvpkat::hexField(t, "c"), hSecret);
			if (rv != CKR_OK) { f.check(false, id + ": decapsulate rv=" + acvpkat::rvHex(rv)); }
			else
			{
				CK_BYTE k[64];
				CK_ATTRIBUTE a[] = { { CKA_VALUE, k, sizeof(k) } };
				rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSecret, a, 1) );
				const std::vector<unsigned char> expected = acvpkat::hexField(t, "k");
				f.check(rv == CKR_OK && a[0].ulValueLen == expected.size() &&
				        memcmp(k, expected.data(), expected.size()) == 0, id + ": shared secret differs from NIST k");
				CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSecret) );
			}
			CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
		}
	}
	f.assertNone("mlkem_encapdecap_val_test.json decapsulation");
}

void MlKemInputCheckTests::testLengthBoundaries()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	nlohmann::json doc = acvpkat::load("mlkem_encapdecap_val_test.json");
	const nlohmann::json* validDk = findCase(doc, "decapsulationKeyCheck", "ML-KEM-768", true);
	const nlohmann::json* validEk = findCase(doc, "encapsulationKeyCheck", "ML-KEM-768", true);
	const nlohmann::json* decap   = findCase(doc, "decapsulation", "ML-KEM-768", true);
	CPPUNIT_ASSERT(validDk != NULL && validEk != NULL && decap != NULL);
	const std::vector<unsigned char> dk = acvpkat::hexField(*validDk, "dk");
	const std::vector<unsigned char> ek = acvpkat::hexField(*validEk, "ek");
	CPPUNIT_ASSERT_EQUAL((size_t)2400, dk.size());
	CPPUNIT_ASSERT_EQUAL((size_t)1184, ek.size());

	acvpkat::Failures f;
	struct KeyCase { const char* what; bool isPrivate; std::vector<unsigned char> v; CK_ULONG ps; };
	std::vector<unsigned char> dkShort(dk.begin(), dk.end() - 1), dkLong(dk); dkLong.push_back(0);
	std::vector<unsigned char> ekShort(ek.begin(), ek.end() - 1), ekLong(ek); ekLong.push_back(0);
	const KeyCase keyCases[] = {
		{ "dk 1 byte short", true,  dkShort, CKP_ML_KEM_768 },
		{ "dk 1 byte long",  true,  dkLong,  CKP_ML_KEM_768 },
		{ "ek 1 byte short", false, ekShort, CKP_ML_KEM_768 },
		{ "ek 1 byte long",  false, ekLong,  CKP_ML_KEM_768 },
		{ "ML-KEM-768 dk labelled ML-KEM-1024", true,  dk, CKP_ML_KEM_1024 },
		{ "ML-KEM-768 ek labelled ML-KEM-512",  false, ek, CKP_ML_KEM_512 },
		{ "unknown parameter set",              false, ek, (CK_ULONG)0x7F },
	};
	for (const KeyCase& kc : keyCases)
	{
		CK_OBJECT_HANDLE h;
		CK_RV rv = importKey(hSession, kc.isPrivate, kc.ps, kc.v, h);
		f.check(rv == CKR_ATTRIBUTE_VALUE_INVALID && h == CK_INVALID_HANDLE,
		        std::string(kc.what) + ": expected CKR_ATTRIBUTE_VALUE_INVALID, got " + acvpkat::rvHex(rv));
		if (h != CK_INVALID_HANDLE) CRYPTOKI_F_PTR( C_DestroyObject(hSession, h) );
	}

	// Ciphertext lengths against an ML-KEM-768 key (valid c is 1088 bytes).
	CK_OBJECT_HANDLE hPrk;
	CK_RV rv = importKey(hSession, true, CKP_ML_KEM_768, acvpkat::hexField(*decap, "dk"), hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	const size_t ctLens[] = { 768 /* ML-KEM-512 */, 1568 /* ML-KEM-1024 */, 1087, 1089, 1 };
	for (size_t len : ctLens)
	{
		CK_OBJECT_HANDLE hSecret;
		rv = decapsulate(hSession, hPrk, std::vector<unsigned char>(len, 0x5a), hSecret);
		f.check(rv == CKR_WRAPPED_KEY_LEN_RANGE && hSecret == CK_INVALID_HANDLE,
		        std::to_string(len) + "-byte ciphertext vs ML-KEM-768 key: expected CKR_WRAPPED_KEY_LEN_RANGE, got " +
		        acvpkat::rvHex(rv));
		if (hSecret != CK_INVALID_HANDLE) CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSecret) );
	}
	// ...and the right length still decapsulates.
	CK_OBJECT_HANDLE hSecret;
	rv = decapsulate(hSession, hPrk, acvpkat::hexField(*decap, "c"), hSecret);
	f.check(rv == CKR_OK, "1088-byte NIST ciphertext: rv=" + acvpkat::rvHex(rv));
	f.assertNone("ML-KEM length boundaries");
}
