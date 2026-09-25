/*****************************************************************************
 AcvpSlhDsaTests.cpp

 NIST ACVP-Server@975de31e SLH-DSA (FIPS 205) known-answer tests through the
 real PKCS#11 ABI — gap-closure plan 2026-09-25, finding E1.

 Vectors (byte-copied subsets, provenance in each file's _provenance block,
 re-verified against the upstream sha256 by scripts/check_acvp_provenance.py):
   tests/acvp/slhdsa_sigver_sha2_test.json   SLH-DSA-sigVer-FIPS205
   tests/acvp/slhdsa_sigver_shake_test.json  SLH-DSA-sigVer-FIPS205
   tests/acvp/slhdsa_siggen_det_test.json    SLH-DSA-sigGen-FIPS205
 (copied from pqctoday-hub src/data/acvp/ @ 7656391c7 — see copied_from.)

 SigVer: every case, verdict-exact — CKR_OK for testPassed=true,
 CKR_SIGNATURE_LEN_RANGE for a too-small/too-large signature (PKCS#11 v3.2
 §5.1.6, "invalid solely on the basis of its length"), CKR_SIGNATURE_INVALID
 for every other negative. SigGen: deterministic (CKH_DETERMINISTIC_REQUIRED),
 signature byte-compared to the upstream one.

 Pure groups use CKM_SLH_DSA; preHash groups CKM_HASH_SLH_DSA_<hash>; both
 carry the upstream context in CK_SIGN_ADDITIONAL_CONTEXT. Before the E1 fix
 (OSSLSLHDSA.cpp) every preHash positive failed: the engine built
 M' = 0x01 || len(ctx) || ctx || OID || PH(M) itself and then let OpenSSL's
 pure SLH-DSA wrap it again as 0x00 || len(ctx) || ctx || M'.
 *****************************************************************************/

#include <config.h>
#include "AcvpSlhDsaTests.h"
#include "AcvpKatUtil.h"
#include <cstring>
#include <map>

CPPUNIT_TEST_SUITE_REGISTRATION(AcvpSlhDsaTests);

namespace {

CK_ULONG slhParamSet(const std::string& name)
{
	static const std::map<std::string, CK_ULONG> m = {
		{ "SLH-DSA-SHA2-128s",  CKP_SLH_DSA_SHA2_128S  }, { "SLH-DSA-SHAKE-128s", CKP_SLH_DSA_SHAKE_128S },
		{ "SLH-DSA-SHA2-128f",  CKP_SLH_DSA_SHA2_128F  }, { "SLH-DSA-SHAKE-128f", CKP_SLH_DSA_SHAKE_128F },
		{ "SLH-DSA-SHA2-192s",  CKP_SLH_DSA_SHA2_192S  }, { "SLH-DSA-SHAKE-192s", CKP_SLH_DSA_SHAKE_192S },
		{ "SLH-DSA-SHA2-192f",  CKP_SLH_DSA_SHA2_192F  }, { "SLH-DSA-SHAKE-192f", CKP_SLH_DSA_SHAKE_192F },
		{ "SLH-DSA-SHA2-256s",  CKP_SLH_DSA_SHA2_256S  }, { "SLH-DSA-SHAKE-256s", CKP_SLH_DSA_SHAKE_256S },
		{ "SLH-DSA-SHA2-256f",  CKP_SLH_DSA_SHA2_256F  }, { "SLH-DSA-SHAKE-256f", CKP_SLH_DSA_SHAKE_256F },
	};
	auto it = m.find(name);
	return it == m.end() ? (CK_ULONG)-1 : it->second;
}

// ACVP hashAlg -> PKCS#11 v3.2 §6.69 hash-specific HashSLH-DSA mechanism.
// "none" (pure groups) -> CKM_SLH_DSA.
CK_MECHANISM_TYPE slhMechanism(const std::string& preHash, const std::string& hashAlg)
{
	if (preHash != "preHash") return CKM_SLH_DSA;
	static const std::map<std::string, CK_MECHANISM_TYPE> m = {
		{ "SHA2-224", CKM_HASH_SLH_DSA_SHA224 },   { "SHA2-256", CKM_HASH_SLH_DSA_SHA256 },
		{ "SHA2-384", CKM_HASH_SLH_DSA_SHA384 },   { "SHA2-512", CKM_HASH_SLH_DSA_SHA512 },
		{ "SHA3-224", CKM_HASH_SLH_DSA_SHA3_224 }, { "SHA3-256", CKM_HASH_SLH_DSA_SHA3_256 },
		{ "SHA3-384", CKM_HASH_SLH_DSA_SHA3_384 }, { "SHA3-512", CKM_HASH_SLH_DSA_SHA3_512 },
		{ "SHAKE-128", CKM_HASH_SLH_DSA_SHAKE128 }, { "SHAKE-256", CKM_HASH_SLH_DSA_SHAKE256 },
	};
	auto it = m.find(hashAlg);
	return it == m.end() ? (CK_MECHANISM_TYPE)-1 : it->second;
}

} // namespace

void AcvpSlhDsaTests::openSession(CK_SESSION_HANDLE& hSession)
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

CK_RV AcvpSlhDsaTests::importKey(CK_SESSION_HANDLE hSession, bool isPrivate, CK_ULONG paramSet,
                                 const std::vector<unsigned char>& value, CK_OBJECT_HANDLE& hKey)
{
	CK_OBJECT_CLASS cls = isPrivate ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
	CK_KEY_TYPE kt = CKK_SLH_DSA;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	std::vector<unsigned char> v(value);
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ (CK_ATTRIBUTE_TYPE)(isPrivate ? CKA_SIGN : CKA_VERIFY), &bTrue, sizeof(bTrue) },
		{ CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
		{ CKA_VALUE, v.data(), (CK_ULONG)v.size() },
	};
	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl, sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &hKey) );
}

void AcvpSlhDsaTests::runSigVerFile(const char* file, CK_SESSION_HANDLE hSession, acvpkat::Failures& f,
                                    size_t& positives, size_t& preHashCases)
{
	nlohmann::json doc = acvpkat::load(file);
	for (const auto& g : doc["testGroups"])
	{
		const std::string ps = g["parameterSet"].get<std::string>();
		const std::string preHash = g["preHash"].get<std::string>();
		const CK_ULONG ckp = slhParamSet(ps);
		for (const auto& t : g["tests"])
		{
			const std::string id = std::string(file) + " tc" + std::to_string(t["tcId"].get<int>()) +
				" " + ps + "/" + preHash + "/" + t["hashAlg"].get<std::string>();
			const CK_MECHANISM_TYPE mech = slhMechanism(preHash, t["hashAlg"].get<std::string>());
			if (ckp == (CK_ULONG)-1 || mech == (CK_MECHANISM_TYPE)-1)
			{
				f.check(false, id + ": unmapped parameter set / hashAlg");
				continue;
			}
			const bool passed = t["testPassed"].get<bool>();
			const std::string reason = t["reason"].get<std::string>();
			CK_RV expected = CKR_OK;
			if (!passed)
				expected = (reason.find("too small") != std::string::npos ||
				            reason.find("too large") != std::string::npos)
				           ? CKR_SIGNATURE_LEN_RANGE : CKR_SIGNATURE_INVALID;
			if (passed) positives++;
			if (preHash == "preHash") preHashCases++;

			CK_OBJECT_HANDLE hPub;
			CK_RV rv = importKey(hSession, false, ckp, acvpkat::hexField(t, "pk"), hPub);
			if (rv != CKR_OK) { f.check(false, id + ": import pk rv=" + acvpkat::rvHex(rv)); continue; }

			std::vector<unsigned char> ctx = acvpkat::hexField(t, "context");
			std::vector<unsigned char> msg = acvpkat::hexField(t, "message");
			std::vector<unsigned char> sig = acvpkat::hexField(t, "signature");
			CK_SIGN_ADDITIONAL_CONTEXT param = { CKH_HEDGE_PREFERRED, ctx.empty() ? NULL_PTR : ctx.data(), (CK_ULONG)ctx.size() };
			CK_MECHANISM m = { mech, &param, sizeof(param) };
			rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &m, hPub) );
			if (rv == CKR_OK)
				rv = CRYPTOKI_F_PTR( C_Verify(hSession, acvpkat::dataPtr(msg), (CK_ULONG)msg.size(),
				                              sig.data(), (CK_ULONG)sig.size()) );
			f.check(rv == expected, id + " (" + reason + "): expected " + acvpkat::rvHex(expected) +
			        ", got " + acvpkat::rvHex(rv));
			CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPub) );
		}
	}
}

void AcvpSlhDsaTests::testSigVer()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	size_t positives = 0, preHashCases = 0;
	acvpkat::Failures f;
	runSigVerFile("slhdsa_sigver_sha2_test.json", hSession, f, positives, preHashCases);
	runSigVerFile("slhdsa_sigver_shake_test.json", hSession, f, positives, preHashCases);
	f.assertNone("SLH-DSA sigVer (sha2 + shake files)");
	// Guard against a silently shrunken vector set: the two files carry 16
	// cases, 6 of them preHash (5 valid + 1 too-small signature).
	CPPUNIT_ASSERT_EQUAL((size_t)6, preHashCases);
	CPPUNIT_ASSERT(positives >= 7);
}

void AcvpSlhDsaTests::testDeterministicSigGen()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	const char* file = "slhdsa_siggen_det_test.json";
	nlohmann::json doc = acvpkat::load(file);
	acvpkat::Failures f;
	size_t preHashCases = 0;
	for (const auto& g : doc["testGroups"])
	{
		CPPUNIT_ASSERT(g["deterministic"].get<bool>());
		const std::string ps = g["parameterSet"].get<std::string>();
		const std::string preHash = g["preHash"].get<std::string>();
		const CK_ULONG ckp = slhParamSet(ps);
		for (const auto& t : g["tests"])
		{
			const std::string id = std::string(file) + " tc" + std::to_string(t["tcId"].get<int>()) +
				" " + ps + "/" + preHash + "/" + t["hashAlg"].get<std::string>();
			const CK_MECHANISM_TYPE mech = slhMechanism(preHash, t["hashAlg"].get<std::string>());
			if (ckp == (CK_ULONG)-1 || mech == (CK_MECHANISM_TYPE)-1)
			{
				f.check(false, id + ": unmapped parameter set / hashAlg");
				continue;
			}
			if (preHash == "preHash") preHashCases++;

			CK_OBJECT_HANDLE hPrk;
			CK_RV rv = importKey(hSession, true, ckp, acvpkat::hexField(t, "sk"), hPrk);
			if (rv != CKR_OK) { f.check(false, id + ": import sk rv=" + acvpkat::rvHex(rv)); continue; }

			std::vector<unsigned char> ctx = acvpkat::hexField(t, "context");
			std::vector<unsigned char> msg = acvpkat::hexField(t, "message");
			const std::vector<unsigned char> expected = acvpkat::hexField(t, "signature");
			CK_SIGN_ADDITIONAL_CONTEXT param = { CKH_DETERMINISTIC_REQUIRED, ctx.empty() ? NULL_PTR : ctx.data(), (CK_ULONG)ctx.size() };
			CK_MECHANISM m = { mech, &param, sizeof(param) };
			std::vector<unsigned char> sig(expected.size() + 64);
			CK_ULONG sigLen = (CK_ULONG)sig.size();
			rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hPrk) );
			if (rv == CKR_OK)
				rv = CRYPTOKI_F_PTR( C_Sign(hSession, acvpkat::dataPtr(msg), (CK_ULONG)msg.size(),
				                            sig.data(), &sigLen) );
			if (rv != CKR_OK)
			{
				f.check(false, id + ": sign rv=" + acvpkat::rvHex(rv));
			}
			else
			{
				sig.resize(sigLen);
				size_t firstDiff = 0;
				while (firstDiff < sig.size() && firstDiff < expected.size() && sig[firstDiff] == expected[firstDiff])
					firstDiff++;
				f.check(sig == expected, id + ": signature differs from NIST (len " + std::to_string(sig.size()) +
				        " vs " + std::to_string(expected.size()) + ", first differing byte " + std::to_string(firstDiff) + ")");
			}
			CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
		}
	}
	f.assertNone(file);
	CPPUNIT_ASSERT_EQUAL((size_t)2, preHashCases);
}
