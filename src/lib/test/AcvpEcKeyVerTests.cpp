/*****************************************************************************
 AcvpEcKeyVerTests.cpp

 C_CreateObject public-key validation for EC-family keys, through the real
 PKCS#11 ABI. #274 added the NIST-curve check (EVP_PKEY_public_check) but
 committed no test; this pins it, and the Edwards check added alongside it.

 Vectors: tests/acvp/ec_keyver_test.json — NIST ACVP-Server@975de31e
 ECDSA-KeyVer-FIPS186-5 (P-224/256/384/521) and EDDSA-KeyVer-1.0 (Ed25519,
 Ed448); every verdict is NIST's own. Edwards keys go in both bare and
 DER-wrapped.

 NIST publishes no identity, small-order, mixed-order or non-canonical Edwards
 case, and those are the dangerous ones: OpenSSL builds an Edwards key from any
 correct-length bytes. The byte strings below were computed with independent
 Python affine arithmetic and are the same constants the Rust engine's
 ec_public_key_validation_tests assert on:
   T   order-8 point (a published small-order point)
   M   7*B + T      mixed order: not small-order, yet L*M != identity
   V   7*B          valid control
   V4  17*B         valid, and its encoding starts with 0x04 (a DER tag)
 *****************************************************************************/

#include <config.h>
#include "AcvpEcKeyVerTests.h"
#include "AcvpKatUtil.h"
#include <set>
#include <string>

CPPUNIT_TEST_SUITE_REGISTRATION(AcvpEcKeyVerTests);

namespace {

const std::vector<unsigned char> OID_P224 = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21 };
const std::vector<unsigned char> OID_P256 = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const std::vector<unsigned char> OID_P384 = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
const std::vector<unsigned char> OID_P521 = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
const std::vector<unsigned char> OID_ED25519 = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
const std::vector<unsigned char> OID_ED448 = { 0x06, 0x03, 0x2b, 0x65, 0x71 };

std::vector<unsigned char> derOctet(const std::vector<unsigned char>& bare)
{
	std::vector<unsigned char> v = { 0x04 };
	if (bare.size() >= 0x80) v.push_back(0x81);
	v.push_back((unsigned char)bare.size());
	v.insert(v.end(), bare.begin(), bare.end());
	return v;
}

} // namespace

void AcvpEcKeyVerTests::openSession(CK_SESSION_HANDLE& hSession)
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

CK_RV AcvpEcKeyVerTests::createPublic(CK_SESSION_HANDLE hSession, CK_KEY_TYPE kt,
                                      const std::vector<unsigned char>& oid,
                                      const std::vector<unsigned char>& point)
{
	CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	std::vector<unsigned char> o(oid), pt(point);
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_EC_PARAMS, o.data(), (CK_ULONG)o.size() },
		{ CKA_EC_POINT, pt.data(), (CK_ULONG)pt.size() },
	};
	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl, sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &h) );
}

void AcvpEcKeyVerTests::testNistKeyVer()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	nlohmann::json doc = acvpkat::load("ec_keyver_test.json");
	acvpkat::Failures f;
	std::set<std::string> curves;
	size_t accepted = 0, refused = 0;
	for (const auto& g : doc["testGroups"])
	{
		const std::string curve = g["curve"].get<std::string>();
		curves.insert(curve);
		for (const auto& t : g["tests"])
		{
			const bool passed = t["testPassed"].get<bool>();
			const std::string id = curve + " tc" + std::to_string(t["tcId"].get<int>()) + " (" +
			                       t["reason"].get<std::string>() + ")";
			std::vector<std::pair<CK_KEY_TYPE, std::pair<std::vector<unsigned char>, std::vector<unsigned char>>>> cases;
			if (curve == "ED-25519" || curve == "ED-448")
			{
				const std::vector<unsigned char>& oid = curve == "ED-25519" ? OID_ED25519 : OID_ED448;
				std::vector<unsigned char> q = acvpkat::hexField(t, "q");
				cases.push_back({ CKK_EC_EDWARDS, { oid, q } });
				cases.push_back({ CKK_EC_EDWARDS, { oid, derOctet(q) } });
			}
			else
			{
				const std::vector<unsigned char>& oid =
					curve == "P-224" ? OID_P224 : curve == "P-256" ? OID_P256 : curve == "P-384" ? OID_P384 : OID_P521;
				std::vector<unsigned char> sec1 = { 0x04 };
				std::vector<unsigned char> qx = acvpkat::hexField(t, "qx"), qy = acvpkat::hexField(t, "qy");
				sec1.insert(sec1.end(), qx.begin(), qx.end());
				sec1.insert(sec1.end(), qy.begin(), qy.end());
				cases.push_back({ CKK_EC, { oid, derOctet(sec1) } });
			}
			for (const auto& c : cases)
			{
				CK_RV rv = createPublic(hSession, c.first, c.second.first, c.second.second);
				if (passed)
				{
					f.check(rv == CKR_OK, id + ": NIST-valid key refused, rv=" + acvpkat::rvHex(rv));
					accepted++;
				}
				else
				{
					f.check(rv == CKR_PUBLIC_KEY_INVALID, id + ": NIST-invalid key gave rv=" + acvpkat::rvHex(rv));
					refused++;
				}
			}
		}
	}
	f.assertNone("EC KeyVer");
	CPPUNIT_ASSERT_EQUAL((size_t)6, curves.size());
	CPPUNIT_ASSERT_EQUAL((size_t)(4 + 8), accepted);
	CPPUNIT_ASSERT_EQUAL((size_t)(8 + 8), refused);
}

void AcvpEcKeyVerTests::testEdwardsOutsideSubgroup()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	struct Case { const char* name; const char* hex; const std::vector<unsigned char>* oid; CK_RV want; };
	const Case cases[] = {
		{ "valid 7*B", "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1", &OID_ED25519, CKR_OK },
		{ "valid 17*B, starts 0x04", "04be97ec9bfe6ccd01f9343b7288b117b79f91cc45c24af2f93e0060ca2b6d6f", &OID_ED25519, CKR_OK },
		{ "identity", "0100000000000000000000000000000000000000000000000000000000000000", &OID_ED25519, CKR_PUBLIC_KEY_INVALID },
		{ "order-8 point T", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", &OID_ED25519, CKR_PUBLIC_KEY_INVALID },
		{ "mixed order 7*B+T", "e9b2fe981587efae6478f48ba1fa60cec6126d0e26dde72a0a24f640dcd783e5", &OID_ED25519, CKR_PUBLIC_KEY_INVALID },
		{ "non-canonical y = p+1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", &OID_ED25519, CKR_PUBLIC_KEY_INVALID },
		{ "Ed448 identity", "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", &OID_ED448, CKR_PUBLIC_KEY_INVALID },
	};
	acvpkat::Failures f;
	for (const Case& c : cases)
	{
		std::vector<unsigned char> q = acvpkat::hex(c.hex);
		for (int der = 0; der < 2; der++)
		{
			CK_RV rv = createPublic(hSession, CKK_EC_EDWARDS, *c.oid, der ? derOctet(q) : q);
			f.check(rv == c.want, std::string(c.name) + (der ? " (DER)" : " (bare)") +
			        ": rv=" + acvpkat::rvHex(rv) + " want " + acvpkat::rvHex(c.want));
		}
	}
	f.assertNone("Edwards subgroup");
}
