/*****************************************************************************
 KmacParamsTests.cpp

 Gap-closure plan 2026-09-25, finding E16 (C++ engine).

 Vectors: tests/acvp/kmac_acvp_test.json — every byte-aligned non-XOF case
 of NIST ACVP-Server@975de31e KMAC-128-1.0 (two MVT cases with a hex
 customization string; copied from pqctoday-hub src/data/acvp/ @ c9c75a624).

 NIST SP 800-185 §4.3 KMAC128(K, X, L, S): the output length L and the
 customization S are inputs to the computation. The vendor mechanism takes
 them in CK_PQCTODAY_KMAC_PARAMS (src/lib/vendor_mechanisms.h — the layout
 the Rust engine and the Hub already use). Before the fix the C++ engine
 ignored the parameter entirely: every MAC was KMAC128(K, X, 256, ""), so the
 valid 478-byte tc799 MAC returned CKR_SIGNATURE_LEN_RANGE, and tc771 was
 "rejected" only because S was dropped.
 *****************************************************************************/

#include <config.h>
#include "KmacParamsTests.h"
#include "AcvpKatUtil.h"
#include "vendor_mechanisms.h"
#include <cstring>

CPPUNIT_TEST_SUITE_REGISTRATION(KmacParamsTests);

void KmacParamsTests::openSession(CK_SESSION_HANDLE& hSession)
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

CK_RV KmacParamsTests::importKey(CK_SESSION_HANDLE hSession, const std::vector<unsigned char>& value,
                                 CK_OBJECT_HANDLE& hKey)
{
	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	std::vector<unsigned char> v(value);
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE, v.data(), (CK_ULONG)v.size() },
	};
	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl, sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &hKey) );
}

void KmacParamsTests::testNistMvt()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	nlohmann::json doc = acvpkat::load("kmac_acvp_test.json");
	CPPUNIT_ASSERT(doc["algorithm"] == "KMAC-128");
	acvpkat::Failures f;
	size_t positives = 0;
	for (const auto& g : doc["testGroups"])
	{
		CPPUNIT_ASSERT(g["xof"] == false);
		for (const auto& t : g["tests"])
		{
			const std::string id = "tc" + std::to_string(t["tcId"].get<int>());
			CPPUNIT_ASSERT(t["keyLen"].get<int>() % 8 == 0 && t["msgLen"].get<int>() % 8 == 0 &&
			               t["macLen"].get<int>() % 8 == 0);
			const bool passed = t["testPassed"].get<bool>();
			if (passed) positives++;
			std::vector<unsigned char> custom = g["hexCustomization"].get<bool>()
				? acvpkat::hexField(t, "customizationHex")
				: std::vector<unsigned char>(t["customization"].get<std::string>().begin(),
				                             t["customization"].get<std::string>().end());
			std::vector<unsigned char> msg = acvpkat::hexField(t, "msg");
			std::vector<unsigned char> mac = acvpkat::hexField(t, "mac");
			const CK_ULONG outLen = (CK_ULONG)(t["macLen"].get<int>() / 8);

			CK_OBJECT_HANDLE hKey;
			CK_RV rv = importKey(hSession, acvpkat::hexField(t, "key"), hKey);
			if (rv != CKR_OK) { f.check(false, id + ": import key rv=" + acvpkat::rvHex(rv)); continue; }

			CK_PQCTODAY_KMAC_PARAMS kp = { custom.empty() ? NULL_PTR : custom.data(), (CK_ULONG)custom.size(), outLen };
			CK_MECHANISM mech = { CKM_KMAC_128, &kp, sizeof(kp) };

			// MVT: the upstream verdict, exactly.
			const CK_RV expected = passed ? CKR_OK : CKR_SIGNATURE_INVALID;
			rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mech, hKey) );
			if (rv == CKR_OK)
				rv = CRYPTOKI_F_PTR( C_Verify(hSession, msg.data(), (CK_ULONG)msg.size(), mac.data(), (CK_ULONG)mac.size()) );
			f.check(rv == expected, id + " (macLen " + std::to_string(outLen) + " B): C_Verify expected " +
			        acvpkat::rvHex(expected) + ", got " + acvpkat::rvHex(rv));

			// The valid MAC is also a sign-side answer: C_Sign must reproduce it.
			if (passed)
			{
				CK_ULONG sigLen = 0;
				rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mech, hKey) );
				if (rv == CKR_OK)
					rv = CRYPTOKI_F_PTR( C_Sign(hSession, msg.data(), (CK_ULONG)msg.size(), NULL_PTR, &sigLen) );
				f.check(rv == CKR_OK && sigLen == outLen, id + ": C_Sign size query rv=" + acvpkat::rvHex(rv) +
				        " len=" + std::to_string(sigLen));
				std::vector<unsigned char> out(sigLen > 0 ? sigLen : 1);
				if (rv == CKR_OK)
					rv = CRYPTOKI_F_PTR( C_Sign(hSession, msg.data(), (CK_ULONG)msg.size(), out.data(), &sigLen) );
				out.resize(rv == CKR_OK ? sigLen : 0);
				f.check(rv == CKR_OK && out == mac, id + ": C_Sign output differs from NIST mac (rv=" +
				        acvpkat::rvHex(rv) + ")");
			}
			CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
		}
	}
	f.assertNone("kmac_acvp_test.json");
	CPPUNIT_ASSERT_EQUAL((size_t)1, positives);
}

void KmacParamsTests::testParameterValidation()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	CK_OBJECT_HANDLE hKey;
	CK_RV rv = importKey(hSession, std::vector<unsigned char>(32, 0x42), hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	unsigned char msg[] = { 0x00, 0x01, 0x02, 0x03 };
	unsigned char custom[] = { 'a', 'b', 'c' };
	acvpkat::Failures f;

	// No parameter: the documented defaults (32 / 64 bytes), unchanged.
	const CK_MECHANISM_TYPE mechs[] = { CKM_KMAC_128, CKM_KMAC_256 };
	const CK_ULONG defaults[] = { 32, 64 };
	for (int i = 0; i < 2; i++)
	{
		CK_MECHANISM m = { mechs[i], NULL_PTR, 0 };
		CK_ULONG len = 0;
		unsigned char out[128];
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hKey) );
		if (rv == CKR_OK) rv = CRYPTOKI_F_PTR( C_Sign(hSession, msg, sizeof(msg), NULL_PTR, &len) );
		f.check(rv == CKR_OK && len == defaults[i], "no parameter: default output length (rv=" + acvpkat::rvHex(rv) +
		        " len=" + std::to_string(len) + ")");
		len = sizeof(out);
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_Sign(hSession, msg, sizeof(msg), out, &len) );  // completes the op
	}

	// ulOutputLen honoured on both sides of a round trip, and S matters.
	CK_PQCTODAY_KMAC_PARAMS kp = { custom, sizeof(custom), 100 };
	CK_MECHANISM m = { CKM_KMAC_256, &kp, sizeof(kp) };
	std::vector<unsigned char> mac(100);
	CK_ULONG len = (CK_ULONG)mac.size();
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hKey) );
	if (rv == CKR_OK) rv = CRYPTOKI_F_PTR( C_Sign(hSession, msg, sizeof(msg), mac.data(), &len) );
	f.check(rv == CKR_OK && len == 100, "KMAC-256 L=100: sign rv=" + acvpkat::rvHex(rv) + " len=" + std::to_string(len));
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &m, hKey) );
	if (rv == CKR_OK) rv = CRYPTOKI_F_PTR( C_Verify(hSession, msg, sizeof(msg), mac.data(), 100) );
	f.check(rv == CKR_OK, "KMAC-256 L=100: verify rv=" + acvpkat::rvHex(rv));
	CK_PQCTODAY_KMAC_PARAMS kpNoS = { NULL_PTR, 0, 100 };
	CK_MECHANISM mNoS = { CKM_KMAC_256, &kpNoS, sizeof(kpNoS) };
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mNoS, hKey) );
	if (rv == CKR_OK) rv = CRYPTOKI_F_PTR( C_Verify(hSession, msg, sizeof(msg), mac.data(), 100) );
	f.check(rv == CKR_SIGNATURE_INVALID, "customization dropped: verify must fail, rv=" + acvpkat::rvHex(rv));

	// Malformed parameters -> CKR_MECHANISM_PARAM_INVALID (v3.2 §5.1.6).
	CK_PQCTODAY_KMAC_PARAMS tooLong = { NULL_PTR, 0, 1025 };
	CK_PQCTODAY_KMAC_PARAMS nullS = { NULL_PTR, 3, 32 };
	CK_MECHANISM bad[] = {
		{ CKM_KMAC_128, &tooLong, sizeof(tooLong) },
		{ CKM_KMAC_128, &nullS, sizeof(nullS) },
		{ CKM_KMAC_128, &kp, sizeof(kp) - 1 },
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
	{
		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &bad[i], hKey) );
		f.check(rv == CKR_MECHANISM_PARAM_INVALID, "malformed parameter #" + std::to_string(i) +
		        ": expected CKR_MECHANISM_PARAM_INVALID, got " + acvpkat::rvHex(rv));
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_Verify(hSession, msg, sizeof(msg), msg, sizeof(msg)) );  // ends the op
	}
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	f.assertNone("KMAC parameter handling");
}
