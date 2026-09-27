/*****************************************************************************
 EcParamsErrorTests.cpp

 PKCS#11 v3.2 §6.3 gives two return codes for CKA_EC_PARAMS a token cannot use:
 CKR_CURVE_NOT_SUPPORTED ("Curve is not supported by the token") and
 CKR_DOMAIN_PARAMS_INVALID ("Invalid or unsupported domain parameters"), and
 scopes them to creating, generating, deriving or unwrapping a key. The C++
 engine used neither: every unusable value became CKR_GENERAL_ERROR at
 C_GenerateKeyPair, which tells a caller nothing about what to change. The
 Rust engine already draws the line (decode_ec_params, rust/src/crypto/
 handlers.rs); this matches it:

   - a well-formed OBJECT IDENTIFIER naming a curve the engine does not
     implement, or an explicit ECParameters SEQUENCE (a legal CHOICE arm this
     engine does not decode for generation), is CKR_CURVE_NOT_SUPPORTED;
   - for the Edwards/Montgomery generator, which accepts §6.3.10's curveName
     form, a well-formed PrintableString naming an unknown curve is also
     CKR_CURVE_NOT_SUPPORTED;
   - anything that is not one complete, well-formed DER value of those kinds
     (truncated, implicitCA NULL, other tags) is CKR_DOMAIN_PARAMS_INVALID.
 The classification applies only once the engine has failed to use the value:
 a curve OpenSSL decodes is generated as before.

 The C++ Weierstrass generator does not accept the curveName form at all (the
 Rust engine does; tests/differential/exceptions.json records that split as
 legal), so a curveName there is an unsupported REPRESENTATION —
 CKR_DOMAIN_PARAMS_INVALID — not an unsupported curve.

 The third test is a crash: OSSL::byteString2oid passed the result of
 d2i_ASN1_PRINTABLESTRING to strcmp without a NULL check, so a malformed
 curveName (tag 0x13 with a length longer than the bytes supplied) in
 CKA_EC_PARAMS dereferenced NULL — reachable from C_GenerateKeyPair and from
 C_CreateObject of an Edwards/Montgomery key.
 *****************************************************************************/

#include <config.h>
#include "EcParamsErrorTests.h"
#include <cstring>
#include <string>
#include <vector>

CPPUNIT_TEST_SUITE_REGISTRATION(EcParamsErrorTests);

namespace {

// TestsBase::setUp leaves the SO logged in on the token, so a USER login in
// the same library instance answers CKR_USER_ANOTHER_ALREADY_LOGGED_IN.
// Re-initialise first (the pattern AcvpEcKeyVerTests uses).
CK_RV login(CK_SESSION_HANDLE& hSession, CK_SLOT_ID slot,
            CK_UTF8CHAR_PTR pin, CK_ULONG pinLen)
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	if (rv != CKR_OK) return rv;
	rv = CRYPTOKI_F_PTR( C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
	                                        NULL_PTR, NULL_PTR, &hSession) );
	if (rv != CKR_OK) return rv;
	return CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, pin, pinLen) );
}

std::vector<CK_BYTE> bytes(std::initializer_list<int> v)
{
	std::vector<CK_BYTE> out;
	for (int b : v) out.push_back((CK_BYTE)b);
	return out;
}

std::vector<CK_BYTE> printable(const char* s)
{
	std::vector<CK_BYTE> out = { 0x13, (CK_BYTE)strlen(s) };
	out.insert(out.end(), s, s + strlen(s));
	return out;
}

CK_RV generate(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechType,
               CK_KEY_TYPE keyType, std::vector<CK_BYTE> params)
{
	CK_MECHANISM mech = { mechType, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
	CK_ATTRIBUTE pub[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_EC_PARAMS, params.data(), (CK_ULONG)params.size() },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
	};
	CK_ATTRIBUTE priv[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
	};
	CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mech, pub, 4, priv, 2, &hPub, &hPriv) );
}

std::string hexOf(const std::vector<CK_BYTE>& v)
{
	static const char* d = "0123456789abcdef";
	std::string s;
	for (CK_BYTE b : v) { s += d[b >> 4]; s += d[b & 15]; }
	return s;
}

} // namespace

void EcParamsErrorTests::testEcKeyGenRefusesUnusableParams()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	struct Case { const char* what; std::vector<CK_BYTE> params; CK_RV want; };
	const Case cases[] = {
		// Control: P-256 by OID generates.
		{ "P-256 OID (control)", bytes({0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07}), CKR_OK },
		// 1.3.132.0.200 — a well-formed OID under the SECG arc that names no
		// curve OpenSSL (or anyone) implements.
		{ "unimplemented curve OID", bytes({0x06,0x06,0x2b,0x81,0x04,0x00,0x81,0x48}), CKR_CURVE_NOT_SUPPORTED },
		// Ed25519's OID is a curve, just not a Weierstrass one this generator makes.
		{ "Ed25519 OID to the EC generator", bytes({0x06,0x03,0x2b,0x65,0x70}), CKR_CURVE_NOT_SUPPORTED },
		// A complete SEQUENCE: the explicit-parameters arm, not implemented here.
		{ "explicit ECParameters SEQUENCE", bytes({0x30,0x03,0x02,0x01,0x01}), CKR_CURVE_NOT_SUPPORTED },
		// implicitCA (NULL) — forbidden by §6.3.
		{ "implicitCA NULL", bytes({0x05,0x00}), CKR_DOMAIN_PARAMS_INVALID },
		// P-256's OID with its last byte missing.
		{ "truncated OID", bytes({0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01}), CKR_DOMAIN_PARAMS_INVALID },
		// Not tested here: a valid OID followed by stray bytes. OpenSSL's
		// d2i_ECPKParameters decodes the prefix and generates, and the Rust
		// engine's decode_ec_params also ignores trailing bytes, so both
		// engines accept it today. Tightening that is a separate, two-engine
		// change (gap-closure plan item 3.B′), not part of this fix.
		// curveName is not a representation this generator accepts.
		{ "curveName P-256", printable("P-256"), CKR_DOMAIN_PARAMS_INVALID },
	};
	for (const Case& c : cases)
	{
		CK_RV rv = generate(hSession, CKM_EC_KEY_PAIR_GEN, CKK_EC, c.params);
		std::string msg = std::string("CKM_EC_KEY_PAIR_GEN, ") + c.what + " (" + hexOf(c.params) + ")";
		CPPUNIT_ASSERT_EQUAL_MESSAGE(msg, c.want, rv);
	}
}

void EcParamsErrorTests::testEdKeyGenRefusesUnusableParams()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	struct Case { const char* what; std::vector<CK_BYTE> params; CK_RV want; };
	const Case cases[] = {
		// Controls: both §6.3.10 forms generate.
		{ "Ed25519 OID (control)", bytes({0x06,0x03,0x2b,0x65,0x70}), CKR_OK },
		{ "edwards25519 curveName (control)", printable("edwards25519"), CKR_OK },
		// secp256k1 is a curve, but not an Edwards one.
		{ "secp256k1 OID to the Edwards generator", bytes({0x06,0x05,0x2b,0x81,0x04,0x00,0x0a}), CKR_CURVE_NOT_SUPPORTED },
		{ "unimplemented curve OID", bytes({0x06,0x06,0x2b,0x81,0x04,0x00,0x81,0x48}), CKR_CURVE_NOT_SUPPORTED },
		{ "unknown curveName", printable("edwards99"), CKR_CURVE_NOT_SUPPORTED },
		// PrintableString whose length (5) runs past the 1 byte supplied: this
		// is the value that crashed OSSL::byteString2oid.
		{ "malformed curveName", bytes({0x13,0x05,0x41}), CKR_DOMAIN_PARAMS_INVALID },
		{ "implicitCA NULL", bytes({0x05,0x00}), CKR_DOMAIN_PARAMS_INVALID },
		{ "truncated OID", bytes({0x06,0x03,0x2b,0x65}), CKR_DOMAIN_PARAMS_INVALID },
	};
	for (const Case& c : cases)
	{
		CK_RV rv = generate(hSession, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK_EC_EDWARDS, c.params);
		std::string msg = std::string("CKM_EC_EDWARDS_KEY_PAIR_GEN, ") + c.what + " (" + hexOf(c.params) + ")";
		CPPUNIT_ASSERT_EQUAL_MESSAGE(msg, c.want, rv);
	}
}

void EcParamsErrorTests::testEdImportMalformedCurveNameDoesNotCrash()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	// RFC 8032 §7.1 TEST 1 public key — a genuine Ed25519 point, so the only
	// thing wrong with this template is CKA_EC_PARAMS.
	const CK_BYTE point[32] = {
		0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
		0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a };
	CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
	CK_KEY_TYPE kt = CKK_EC_EDWARDS;
	CK_BBOOL bFalse = CK_FALSE;

	const std::vector<CK_BYTE> good = bytes({0x06,0x03,0x2b,0x65,0x70});
	const std::vector<CK_BYTE> bad = bytes({0x13,0x05,0x41});
	for (const std::vector<CK_BYTE>* params : { &good, &bad })
	{
		CK_ATTRIBUTE tmpl[] = {
			{ CKA_CLASS, &cls, sizeof(cls) },
			{ CKA_KEY_TYPE, &kt, sizeof(kt) },
			{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
			{ CKA_EC_PARAMS, (CK_VOID_PTR)params->data(), (CK_ULONG)params->size() },
			{ CKA_EC_POINT, (CK_VOID_PTR)point, sizeof(point) },
		};
		CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
		CK_RV rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, tmpl, 5, &h) );
		if (params == &good)
			CPPUNIT_ASSERT_EQUAL_MESSAGE("control: a genuine Ed25519 public key imports", (CK_RV)CKR_OK, rv);
		else
			// Reaching this line at all is the fix; the import must still fail.
			CPPUNIT_ASSERT_MESSAGE("a malformed curveName must be refused", rv != CKR_OK);
	}
}
