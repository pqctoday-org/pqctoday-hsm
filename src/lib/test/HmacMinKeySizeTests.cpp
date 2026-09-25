/*****************************************************************************
 HmacMinKeySizeTests.cpp

 Gap-closure plan 2026-09-25, finding E17 (C++ engine).

 Vectors: tests/acvp/hmac_acvp_matrix_test.json — subsets of NIST
 ACVP-Server@975de31e HMAC-<hash>-2.0 (every upstream file in its
 _provenance.source_files; copied from pqctoday-hub src/data/acvp/ @
 c9c75a624), including a 1-byte (keyLen 8) key for every hash.

 ulMinKeySize is "the minimum size of the key for the mechanism" (PKCS#11
 v3.2 §3.x CK_MECHANISM_INFO). The engine deliberately enforces no HMAC key
 floor (RFC 2104 §3 / FIPS 198-1 allow any length; kMacMechTable in
 SoftHSM_sign.cpp), yet advertised the digest length (20..64 bytes). For
 every case: CKM_<hash>_HMAC_GENERAL (CK_MAC_GENERAL_PARAMS = macLen/8)
 must sign byte-exact and verify back, AND the advertised ulMinKeySize of
 both the plain and the _GENERAL mechanism must not exceed that key's
 length. Before the fix the 1-byte keys computed correctly while the
 advertisement claimed they were out of range. Since the engine enforces no
 floor at all, the advertised minimum must be exactly 0 and an empty key
 must be accepted — advertisement and enforcement agree at the boundary.
 *****************************************************************************/

#include <config.h>
#include "HmacMinKeySizeTests.h"
#include "AcvpKatUtil.h"
#include <map>

CPPUNIT_TEST_SUITE_REGISTRATION(HmacMinKeySizeTests);

namespace {

struct HmacMechs { CK_MECHANISM_TYPE plain, general; };

bool hmacMechs(const std::string& hashAlg, HmacMechs& out)
{
	static const std::map<std::string, HmacMechs> m = {
		{ "SHA-1",        { CKM_SHA_1_HMAC,      CKM_SHA_1_HMAC_GENERAL } },
		{ "SHA2-224",     { CKM_SHA224_HMAC,     CKM_SHA224_HMAC_GENERAL } },
		{ "SHA2-256",     { CKM_SHA256_HMAC,     CKM_SHA256_HMAC_GENERAL } },
		{ "SHA2-384",     { CKM_SHA384_HMAC,     CKM_SHA384_HMAC_GENERAL } },
		{ "SHA2-512",     { CKM_SHA512_HMAC,     CKM_SHA512_HMAC_GENERAL } },
		{ "SHA2-512/224", { CKM_SHA512_224_HMAC, CKM_SHA512_224_HMAC_GENERAL } },
		{ "SHA2-512/256", { CKM_SHA512_256_HMAC, CKM_SHA512_256_HMAC_GENERAL } },
		{ "SHA3-224",     { CKM_SHA3_224_HMAC,   CKM_SHA3_224_HMAC_GENERAL } },
		{ "SHA3-256",     { CKM_SHA3_256_HMAC,   CKM_SHA3_256_HMAC_GENERAL } },
		{ "SHA3-384",     { CKM_SHA3_384_HMAC,   CKM_SHA3_384_HMAC_GENERAL } },
		{ "SHA3-512",     { CKM_SHA3_512_HMAC,   CKM_SHA3_512_HMAC_GENERAL } },
	};
	auto it = m.find(hashAlg);
	if (it == m.end()) return false;
	out = it->second;
	return true;
}

} // namespace

void HmacMinKeySizeTests::testAdvertisedMinimumMatchesAcceptedKeys()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CK_SESSION_HANDLE hSession;
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	nlohmann::json doc = acvpkat::load("hmac_acvp_matrix_test.json");
	acvpkat::Failures f;
	size_t oneByteKeys = 0;
	for (const auto& g : doc["testGroups"])
	{
		const std::string hashAlg = g["hashAlg"].get<std::string>();
		HmacMechs hm;
		if (!hmacMechs(hashAlg, hm)) { f.check(false, hashAlg + ": unmapped hashAlg"); continue; }

		CK_MECHANISM_INFO infoPlain, infoGeneral;
		CK_RV r1 = CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, hm.plain, &infoPlain) );
		CK_RV r2 = CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, hm.general, &infoGeneral) );
		f.check(r1 == CKR_OK && r2 == CKR_OK, hashAlg + ": C_GetMechanismInfo");
		if (r1 != CKR_OK || r2 != CKR_OK) continue;
		f.check(infoPlain.ulMinKeySize == 0 && infoGeneral.ulMinKeySize == 0,
		        hashAlg + ": advertised ulMinKeySize " + std::to_string(infoPlain.ulMinKeySize) + "/" +
		        std::to_string(infoGeneral.ulMinKeySize) + ", but the engine enforces no minimum (0)");

		// Boundary: the empty key the advertisement admits is accepted.
		{
			CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
			CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
			CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
			unsigned char none[1] = { 0 };
			CK_ATTRIBUTE tmpl[] = {
				{ CKA_CLASS, &cls, sizeof(cls) }, { CKA_KEY_TYPE, &kt, sizeof(kt) },
				{ CKA_TOKEN, &bFalse, sizeof(bFalse) }, { CKA_SIGN, &bTrue, sizeof(bTrue) },
				{ CKA_VALUE, none, 0 },
			};
			CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
			rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl, sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &hKey) );
			CK_MECHANISM m = { hm.plain, NULL_PTR, 0 };
			unsigned char msg[3] = { 'a', 'b', 'c' }, out[64];
			CK_ULONG outLen = sizeof(out);
			if (rv == CKR_OK) rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hKey) );
			if (rv == CKR_OK) rv = CRYPTOKI_F_PTR( C_Sign(hSession, msg, sizeof(msg), out, &outLen) );
			f.check(rv == CKR_OK, hashAlg + ": 0-byte key (the advertised minimum) rv=" + acvpkat::rvHex(rv));
			if (hKey != CK_INVALID_HANDLE) CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
		}

		for (const auto& t : g["tests"])
		{
			const std::string id = hashAlg + " tc" + std::to_string(t["tcId"].get<int>());
			std::vector<unsigned char> key = acvpkat::hexField(t, "key");
			std::vector<unsigned char> msg = acvpkat::hexField(t, "msg");
			const std::vector<unsigned char> mac = acvpkat::hexField(t, "mac");
			if (key.size() == 1) oneByteKeys++;

			CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
			CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
			CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
			CK_ATTRIBUTE tmpl[] = {
				{ CKA_CLASS, &cls, sizeof(cls) }, { CKA_KEY_TYPE, &kt, sizeof(kt) },
				{ CKA_TOKEN, &bFalse, sizeof(bFalse) }, { CKA_SIGN, &bTrue, sizeof(bTrue) },
				{ CKA_VERIFY, &bTrue, sizeof(bTrue) }, { CKA_VALUE, key.data(), (CK_ULONG)key.size() },
			};
			CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
			rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl, sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &hKey) );
			if (rv != CKR_OK) { f.check(false, id + ": import key rv=" + acvpkat::rvHex(rv)); continue; }

			CK_MAC_GENERAL_PARAMS macLen = (CK_MAC_GENERAL_PARAMS)mac.size();
			CK_MECHANISM m = { hm.general, &macLen, sizeof(macLen) };
			std::vector<unsigned char> out(64);
			CK_ULONG outLen = (CK_ULONG)out.size();
			rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hKey) );
			if (rv == CKR_OK)
				rv = CRYPTOKI_F_PTR( C_Sign(hSession, acvpkat::dataPtr(msg), (CK_ULONG)msg.size(), out.data(), &outLen) );
			out.resize(rv == CKR_OK ? outLen : 0);
			const bool computed = (rv == CKR_OK && out == mac);
			f.check(computed, id + " (" + std::to_string(key.size()) + "-byte key): sign rv=" + acvpkat::rvHex(rv) +
			        (rv == CKR_OK ? ", MAC differs from NIST" : ""));
			if (computed)
			{
				rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &m, hKey) );
				if (rv == CKR_OK)
					rv = CRYPTOKI_F_PTR( C_Verify(hSession, acvpkat::dataPtr(msg), (CK_ULONG)msg.size(),
					                              out.data(), (CK_ULONG)out.size()) );
				f.check(rv == CKR_OK, id + ": verify rv=" + acvpkat::rvHex(rv));
				// The engine accepted and computed this key correctly, so the
				// advertised minimum must admit it.
				f.check(infoPlain.ulMinKeySize <= key.size() && infoGeneral.ulMinKeySize <= key.size(),
				        id + ": accepted a " + std::to_string(key.size()) + "-byte key but advertises ulMinKeySize " +
				        std::to_string(infoPlain.ulMinKeySize) + "/" + std::to_string(infoGeneral.ulMinKeySize));
			}
			CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
		}
	}
	f.assertNone("hmac_acvp_matrix_test.json");
	CPPUNIT_ASSERT(oneByteKeys >= 11);  // one keyLen=8 case per hash in the subset
}
