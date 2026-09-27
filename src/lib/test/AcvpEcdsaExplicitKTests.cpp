/*****************************************************************************
 AcvpEcdsaExplicitKTests.cpp

 CKM_PQCTODAY_ECDSA_EXPLICIT_K — ECDSA with a caller-supplied nonce k, a
 deliberate key-recovery teaching primitive (SECURITY.md). Same checks as the
 Rust engine's ffi::ecdsa_explicit_k_ffi_tests.

 Vectors: tests/acvp/ecdsa_siggen_explicit_k_test.json — NIST ACVP-Server
 @975de31e ECDSA-SigGen-FIPS186-5, 40 cases over (P-256, SHA2-256),
 (P-384, SHA2-384), (P-521, SHA2-512) and (P-256, SHA2-512), the last one a
 digest longer than the order (bits2int truncation). ACVP SigGen is
 random-k, so (r, s) is reproducible only when k is an input; every expected
 value is the upstream one, byte-compared.
 *****************************************************************************/

#include <config.h>
#include "AcvpEcdsaExplicitKTests.h"
#include "AcvpKatUtil.h"
#include "vendor_mechanisms.h"
#include <algorithm>
#include <set>
#include <string>

CPPUNIT_TEST_SUITE_REGISTRATION(AcvpEcdsaExplicitKTests);

namespace {

const std::vector<unsigned char> OID_P256 = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const std::vector<unsigned char> OID_P384 = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
const std::vector<unsigned char> OID_P521 = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
const std::vector<unsigned char> OID_P224 = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21 };
const std::vector<unsigned char> OID_K256 = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a };

// P-256 group order n (SP 800-186 §3.2.1.3).
const char* N_P256 = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
// A valid P-256 private key and nonce (RFC 6979 A.2.5's key and its SHA-256
// "sample" k) for the refusal cases; any in-range values would do.
const char* D_P256 = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const char* K_P256 = "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60";

const std::vector<unsigned char>& oidFor(const std::string& curve)
{
	if (curve == "P-384") return OID_P384;
	if (curve == "P-521") return OID_P521;
	return OID_P256;
}

} // namespace

void AcvpEcdsaExplicitKTests::openSession(CK_SESSION_HANDLE& hSession)
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

CK_OBJECT_HANDLE AcvpEcdsaExplicitKTests::importPrivate(CK_SESSION_HANDLE hSession,
                                                        const std::vector<unsigned char>& oid,
                                                        const std::vector<unsigned char>& d)
{
	CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
	CK_KEY_TYPE kt = CKK_EC;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	std::vector<unsigned char> o(oid), v(d);
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_EC_PARAMS, o.data(), (CK_ULONG)o.size() },
		{ CKA_VALUE, v.data(), (CK_ULONG)v.size() },
	};
	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
	CK_RV rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl, sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &h) );
	CPPUNIT_ASSERT_MESSAGE("import EC private key rv=" + acvpkat::rvHex(rv), rv == CKR_OK);
	return h;
}

CK_OBJECT_HANDLE AcvpEcdsaExplicitKTests::importPublic(CK_SESSION_HANDLE hSession,
                                                       const std::vector<unsigned char>& oid,
                                                       const std::vector<unsigned char>& qx,
                                                       const std::vector<unsigned char>& qy)
{
	// CKA_EC_POINT: DER OCTET STRING around 04 || x || y.
	std::vector<unsigned char> sec1 = { 0x04 };
	sec1.insert(sec1.end(), qx.begin(), qx.end());
	sec1.insert(sec1.end(), qy.begin(), qy.end());
	std::vector<unsigned char> point = { 0x04 };
	if (sec1.size() > 127) point.push_back(0x81);
	point.push_back((unsigned char)sec1.size());
	point.insert(point.end(), sec1.begin(), sec1.end());

	CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
	CK_KEY_TYPE kt = CKK_EC;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	std::vector<unsigned char> o(oid);
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_EC_PARAMS, o.data(), (CK_ULONG)o.size() },
		{ CKA_EC_POINT, point.data(), (CK_ULONG)point.size() },
	};
	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
	CK_RV rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl, sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &h) );
	CPPUNIT_ASSERT_MESSAGE("import EC public key rv=" + acvpkat::rvHex(rv), rv == CKR_OK);
	return h;
}

CK_RV AcvpEcdsaExplicitKTests::signInit(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey,
                                        const std::vector<unsigned char>* k)
{
	std::vector<unsigned char> kv = k ? *k : std::vector<unsigned char>();
	CK_MECHANISM m = { CKM_PQCTODAY_ECDSA_EXPLICIT_K,
	                   k ? kv.data() : NULL_PTR, (CK_ULONG)(k ? kv.size() : 0) };
	return CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hKey) );
}

CK_RV AcvpEcdsaExplicitKTests::sign(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey,
                                    const std::vector<unsigned char>& k,
                                    std::vector<unsigned char>& digest, std::vector<unsigned char>& sig)
{
	CK_RV rv = signInit(hSession, hKey, &k);
	if (rv != CKR_OK) return rv;
	sig.assign(132, 0);
	CK_ULONG len = (CK_ULONG)sig.size();
	rv = CRYPTOKI_F_PTR( C_Sign(hSession, acvpkat::dataPtr(digest), (CK_ULONG)digest.size(), sig.data(), &len) );
	sig.resize(rv == CKR_OK ? len : 0);
	return rv;
}

void AcvpEcdsaExplicitKTests::testSigGenMatchesNist()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	nlohmann::json doc = acvpkat::load("ecdsa_siggen_explicit_k_test.json");
	acvpkat::Failures f;
	std::set<std::string> groups;
	size_t ran = 0;

	for (const auto& g : doc["testGroups"])
	{
		const std::string curve = g["curve"].get<std::string>();
		const std::string hashAlg = g["hashAlg"].get<std::string>();
		const std::vector<unsigned char>& oid = oidFor(curve);
		CK_OBJECT_HANDLE hPriv = importPrivate(hSession, oid, acvpkat::hexField(g, "d"));
		CK_OBJECT_HANDLE hPub = importPublic(hSession, oid, acvpkat::hexField(g, "qx"), acvpkat::hexField(g, "qy"));
		groups.insert(curve + "/" + hashAlg);
		for (const auto& t : g["tests"])
		{
			const std::string id = curve + "/" + hashAlg + " tc" + std::to_string(t["tcId"].get<int>());
			std::vector<unsigned char> digest = acvpkat::hexField(t, "digest");
			std::vector<unsigned char> want = acvpkat::hexField(t, "r");
			std::vector<unsigned char> s = acvpkat::hexField(t, "s");
			want.insert(want.end(), s.begin(), s.end());
			std::vector<unsigned char> sig;
			CK_RV rv = sign(hSession, hPriv, acvpkat::hexField(t, "k"), digest, sig);
			ran++;
			if (rv != CKR_OK) { f.check(false, id + ": sign rv=" + acvpkat::rvHex(rv)); continue; }
			f.check(sig == want, id + ": (r, s) differs from NIST");

			// Ordinary ECDSA: CKM_ECDSA verifies it.
			CK_MECHANISM m = { CKM_ECDSA, NULL_PTR, 0 };
			rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &m, hPub) );
			if (rv == CKR_OK)
				rv = CRYPTOKI_F_PTR( C_Verify(hSession, acvpkat::dataPtr(digest), (CK_ULONG)digest.size(),
				                              sig.data(), (CK_ULONG)sig.size()) );
			f.check(rv == CKR_OK, id + ": CKM_ECDSA verify rv=" + acvpkat::rvHex(rv));
		}
	}
	f.assertNone("ECDSA explicit-k SigGen");
	// Reachability: every case ran, including the truncation group.
	CPPUNIT_ASSERT_EQUAL((size_t)40, ran);
	CPPUNIT_ASSERT_EQUAL((size_t)4, groups.size());
	CPPUNIT_ASSERT(groups.count("P-256/SHA2-512") == 1);
}

void AcvpEcdsaExplicitKTests::testSabotageIsDetected()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	nlohmann::json doc = acvpkat::load("ecdsa_siggen_explicit_k_test.json");
	const auto& g = doc["testGroups"][0];
	const auto& t = g["tests"][0];
	CK_OBJECT_HANDLE hPriv = importPrivate(hSession, oidFor(g["curve"].get<std::string>()), acvpkat::hexField(g, "d"));
	std::vector<unsigned char> digest = acvpkat::hexField(t, "digest");
	std::vector<unsigned char> k = acvpkat::hexField(t, "k");
	std::vector<unsigned char> want = acvpkat::hexField(t, "r");
	std::vector<unsigned char> s = acvpkat::hexField(t, "s");
	want.insert(want.end(), s.begin(), s.end());

	std::vector<unsigned char> sig;
	CPPUNIT_ASSERT(sign(hSession, hPriv, k, digest, sig) == CKR_OK);
	CPPUNIT_ASSERT_MESSAGE("positive control", sig == want);

	// A flipped expected byte is a mismatch — the comparison has teeth.
	std::vector<unsigned char> flipped(want);
	flipped[40] ^= 0x01;
	CPPUNIT_ASSERT(sig != flipped);
	// A different k gives a different signature — k is really used.
	std::vector<unsigned char> k2(k);
	k2.back() ^= 0x01;
	std::vector<unsigned char> sig2;
	CPPUNIT_ASSERT(sign(hSession, hPriv, k2, digest, sig2) == CKR_OK);
	CPPUNIT_ASSERT(sig2 != want);
	// A different digest changes s but not r (r = x(kG) mod n).
	std::vector<unsigned char> d2(digest);
	d2[0] ^= 0x80;
	std::vector<unsigned char> sig3;
	CPPUNIT_ASSERT(sign(hSession, hPriv, k, d2, sig3) == CKR_OK);
	CPPUNIT_ASSERT(std::equal(sig3.begin(), sig3.begin() + 32, want.begin()));
	CPPUNIT_ASSERT(!std::equal(sig3.begin() + 32, sig3.end(), want.begin() + 32));
}

void AcvpEcdsaExplicitKTests::testRefusals()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	CK_OBJECT_HANDLE hPriv = importPrivate(hSession, OID_P256, acvpkat::hex(D_P256));
	std::vector<unsigned char> good = acvpkat::hex(K_P256);

	// No parameter, k = 0, k = n, k > n, and wrong lengths.
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, signInit(hSession, hPriv, NULL));
	std::vector<unsigned char> zero(32, 0), n = acvpkat::hex(N_P256), ff(32, 0xff);
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, signInit(hSession, hPriv, &zero));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, signInit(hSession, hPriv, &n));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, signInit(hSession, hPriv, &ff));
	std::vector<unsigned char> shortK(good.begin(), good.end() - 1), longK(good);
	longK.insert(longK.begin(), 0x00);
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, signInit(hSession, hPriv, &shortK));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, signInit(hSession, hPriv, &longK));
	// n - 1 is the largest legal k.
	std::vector<unsigned char> nMinus1(n);
	nMinus1.back() -= 1;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signInit(hSession, hPriv, &nMinus1));
	CRYPTOKI_F_PTR( C_SignInit(hSession, NULL_PTR, CK_INVALID_HANDLE) );  // cancel (§5.13.1)

	// Curves outside P-256/384/521: the two key codes §5.13.1 allows.
	CK_OBJECT_HANDLE hP224 = importPrivate(hSession, OID_P224,
		acvpkat::hex("3f0c488e987c80be0fee521f8d90be6034ec69ae11ca72aa777481e8"));
	std::vector<unsigned char> k28(good.begin(), good.begin() + 28);
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_KEY_SIZE_RANGE, signInit(hSession, hP224, &k28));
	CK_OBJECT_HANDLE hK256 = importPrivate(hSession, OID_K256, acvpkat::hex(D_P256));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_KEY_TYPE_INCONSISTENT, signInit(hSession, hK256, &good));

	// Sign only, single-part. The verify refusal uses a real P-256 verify key
	// (vector group 0's Q), so the mechanism is the only thing wrong.
	nlohmann::json doc = acvpkat::load("ecdsa_siggen_explicit_k_test.json");
	CK_OBJECT_HANDLE hPub = importPublic(hSession, OID_P256, acvpkat::hexField(doc["testGroups"][0], "qx"),
	                                     acvpkat::hexField(doc["testGroups"][0], "qy"));
	CK_MECHANISM m = { CKM_PQCTODAY_ECDSA_EXPLICIT_K, good.data(), (CK_ULONG)good.size() };
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_INVALID, CRYPTOKI_F_PTR( C_VerifyInit(hSession, &m, hPub) ));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_INVALID, CRYPTOKI_F_PTR( C_MessageSignInit(hSession, &m, hPriv) ));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signInit(hSession, hPriv, &good));
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_SignUpdate(hSession, good.data(), (CK_ULONG)good.size()) ) != CKR_OK);
}

void AcvpEcdsaExplicitKTests::testAdvertisedSignOnly()
{
	CK_SESSION_HANDLE hSession;
	openSession(hSession);
	CK_MECHANISM_INFO info;
	CK_RV rv = CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, CKM_PQCTODAY_ECDSA_EXPLICIT_K, &info) );
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, rv);
	CPPUNIT_ASSERT_EQUAL((CK_ULONG)256, info.ulMinKeySize);
	CPPUNIT_ASSERT_EQUAL((CK_ULONG)521, info.ulMaxKeySize);
	CPPUNIT_ASSERT(info.flags & CKF_SIGN);
	CPPUNIT_ASSERT(!(info.flags & CKF_VERIFY));
	CPPUNIT_ASSERT(!(info.flags & CKF_MESSAGE_SIGN));
}
