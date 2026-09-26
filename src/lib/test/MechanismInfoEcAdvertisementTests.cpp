/*****************************************************************************
 MechanismInfoEcAdvertisementTests.cpp

 Finding E20 (2026-09-25) — C++ engine's C_GetMechanismInfo advertisement for
 three groups of EC-family derive mechanisms, each checked against what
 C_DeriveKey actually accepts rather than against the other engine.

 A CK_MECHANISM_INFO field is a claim about the token (PKCS#11 v3.2 §5.4.4:
 each CKF_* flag is "TRUE if the mechanism can be used with" that function;
 ulMinKeySize/ulMaxKeySize are "the minimum/maximum size of the key"). So
 every assertion below pairs the advertised value with a real operation that
 demonstrates it:

   1. CKM_ECDH1_DERIVE / CKM_ECDH1_COFACTOR_DERIVE advertised CKF_DERIVE
      (plus the KEM pair) but none of the EC-family capability flags, while
      the CKM_ECDSA and CKM_EC_KEY_PAIR_GEN arms of the same switch already
      advertised all three for the same key objects. The derive below uses a
      prime-field curve (CKF_EC_F_P), names it by OID in CKA_EC_PARAMS
      (CKF_EC_NAMEDCURVE, == CKF_EC_OID in pkcs11t.h), and hands the peer an
      uncompressed CKA_EC_POINT (CKF_EC_UNCOMPRESS). All three flags are
      exercised by the one call that has to succeed.

   2. CKM_X25519 and CKM_X448 reported 0/0 for a mechanism whose curve — and
      therefore key size — is fixed by its own name (RFC 7748; v3.2 §6.7).
      255 and 448 bits, the same values OSSLEDDSA::getMin/MaxKeySize already
      supplies to the Montgomery keygen/derive arms.

   3. CKM_BIP32_CHILD_DERIVE reported 0/0 though HDWalletDerivation::
      deriveChildNode consumes the parent private scalar as a 32-byte value
      on every curve it supports.

 CKM_BIP32_MASTER_DERIVE is deliberately NOT asserted to 32/32: its base key
 is the BIP-32 binary seed and deriveMasterNode HMAC-SHA512s a seed of any
 length, so it keeps 0/0. The test pins that too, so a future change to 32/32
 has to argue with this file.
 *****************************************************************************/

#include <config.h>
#include "MechanismInfoEcAdvertisementTests.h"
#include <cstring>
#include <string>

CPPUNIT_TEST_SUITE_REGISTRATION(MechanismInfoEcAdvertisementTests);

namespace {

// PKCS#11 v3.2 §5.4.4 / pkcs11t.h: CKF_EC_NAMEDCURVE is defined as CKF_EC_OID.
const CK_FLAGS EC_COMMON_FLAGS = CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;

CK_RV login(CK_SESSION_HANDLE& hSession, CK_SLOT_ID slot,
            CK_UTF8CHAR_PTR pin, CK_ULONG pinLen)
{
	CK_RV rv = CRYPTOKI_F_PTR( C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
	                                        NULL_PTR, NULL_PTR, &hSession) );
	if (rv != CKR_OK) return rv;
	return CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, pin, pinLen) );
}

// Raw (point-only) form of a CKA_EC_POINT, the uncompressed encoding a peer
// hands CK_ECDH1_DERIVE_PARAMS. Mirrors DeriveTests::ecdhDerive's useRaw path.
bool rawPublicPoint(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey,
                    std::string& out)
{
	CK_ATTRIBUTE a = { CKA_EC_POINT, NULL_PTR, 0 };
	if (CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPublicKey, &a, 1) ) != CKR_OK) return false;
	std::string buf(a.ulValueLen, '\0');
	a.pValue = &buf[0];
	if (CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPublicKey, &a, 1) ) != CKR_OK) return false;
	buf.resize(a.ulValueLen);

	size_t offset = 0;
	const unsigned char* p = (const unsigned char*)buf.data();
	if (buf.size() > 2 && p[0] == 0x04)
	{
		if (p[1] < 0x80) offset = 2;
		else if (buf.size() > (size_t)((p[1] & 0x7F) + 2)) offset = 2 + (p[1] & 0x7F);
	}
	out = buf.substr(offset);
	return !out.empty();
}

// Derive a shared secret from hPrk against hPuk's uncompressed point, under
// the given mechanism. Returns the C_DeriveKey rv.
CK_RV deriveWith(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechType,
                 CK_OBJECT_HANDLE hPuk, CK_OBJECT_HANDLE hPrk)
{
	std::string point;
	if (!rawPublicPoint(hSession, hPuk, point)) return CKR_FUNCTION_FAILED;

	CK_ECDH1_DERIVE_PARAMS parms = { CKD_NULL, 0, NULL_PTR, 0, NULL_PTR };
	parms.pPublicData = (CK_BYTE_PTR)point.data();
	parms.ulPublicDataLen = (CK_ULONG)point.size();
	CK_MECHANISM mech = { mechType, &parms, sizeof(parms) };

	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	CK_ULONG secLen = 32;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &secLen, sizeof(secLen) }
	};
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_DeriveKey(hSession, &mech, hPrk, keyAttribs,
	                                   sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE), &hKey) );
}

} // namespace

#if defined(WITH_ECC) || defined(WITH_EDDSA)
void MechanismInfoEcAdvertisementTests::testEcdh1AdvertisesEcCapabilityFlags()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) ) == CKR_OK);
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT(login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length) == CKR_OK);

	// P-256 by OID — a named prime-field curve, the only form this engine's
	// ECDH takes. Proves CKF_EC_F_P and CKF_EC_NAMEDCURVE at the same time.
	CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE ecType = CKK_EC;
	CK_BYTE oidP256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_EC_PARAMS, oidP256, sizeof(oidP256) },
		{ CKA_KEY_TYPE, &ecType, sizeof(ecType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_KEY_TYPE, &ecType, sizeof(ecType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
	};
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE, hPrk = CK_INVALID_HANDLE;
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &genMech,
		pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
		prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE), &hPuk, &hPrk) ) == CKR_OK);

	const CK_MECHANISM_TYPE mechs[] = { CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE };
	const char* names[] = { "CKM_ECDH1_DERIVE", "CKM_ECDH1_COFACTOR_DERIVE" };
	for (int i = 0; i < 2; i++)
	{
		// The operation first: a flag claim is only owed if the thing works.
		CK_RV rv = deriveWith(hSession, mechs[i], hPuk, hPrk);
		CPPUNIT_ASSERT_MESSAGE(std::string(names[i]) + ": derive over a named prime curve with "
		                       "an uncompressed peer point failed", rv == CKR_OK);

		CK_MECHANISM_INFO info;
		memset(&info, 0, sizeof info);
		CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, mechs[i], &info) ) == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(std::string(names[i]) + ": derives over named prime curves with "
		                       "uncompressed points but does not advertise CKF_EC_F_P|"
		                       "CKF_EC_NAMEDCURVE|CKF_EC_UNCOMPRESS",
		                       (info.flags & EC_COMMON_FLAGS) == EC_COMMON_FLAGS);
		CPPUNIT_ASSERT_MESSAGE(std::string(names[i]) + ": lost CKF_DERIVE",
		                       (info.flags & CKF_DERIVE) != 0);
	}
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}
#else
void MechanismInfoEcAdvertisementTests::testEcdh1AdvertisesEcCapabilityFlags() {}
#endif

#ifdef WITH_EDDSA
void MechanismInfoEcAdvertisementTests::testMontgomeryMechanismsAdvertiseTheirCurveSize()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) ) == CKR_OK);
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT(login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length) == CKR_OK);

	// PrintableString curve names, as CKA_EC_PARAMS takes them for Montgomery
	// keys (OSSLUtil.cpp maps "curve25519"/"curve448").
	CK_BYTE nameX25519[] = { 0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39 };
	CK_BYTE nameX448[]   = { 0x13, 0x08, 0x63, 0x75, 0x72, 0x76, 0x65, 0x34, 0x34, 0x38 };

	struct Case {
		CK_MECHANISM_TYPE mech; const char* name;
		CK_BYTE* params; CK_ULONG paramsLen; CK_ULONG expectedSize;
	} cases[] = {
		{ CKM_X25519, "CKM_X25519", nameX25519, sizeof(nameX25519), 255 },
		{ CKM_X448,   "CKM_X448",   nameX448,   sizeof(nameX448),   448 },
	};

	for (const Case& c : cases)
	{
		CK_MECHANISM genMech = { CKM_EC_MONTGOMERY_KEY_PAIR_GEN, NULL_PTR, 0 };
		CK_KEY_TYPE mType = CKK_EC_MONTGOMERY;
		CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
		CK_ATTRIBUTE pukAttribs[] = {
			{ CKA_EC_PARAMS, c.params, c.paramsLen },
			{ CKA_KEY_TYPE, &mType, sizeof(mType) },
			{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
			{ CKA_PRIVATE, &bFalse, sizeof(bFalse) }
		};
		CK_ATTRIBUTE prkAttribs[] = {
			{ CKA_KEY_TYPE, &mType, sizeof(mType) },
			{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
			{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
			{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
		};
		CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE, hPrk = CK_INVALID_HANDLE;
		CK_RV rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &genMech,
			pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
			prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE), &hPuk, &hPrk) );
		CPPUNIT_ASSERT_MESSAGE(std::string(c.name) + ": Montgomery key pair generation failed",
		                       rv == CKR_OK);

		// The operation this mechanism exists for, under the mechanism itself
		// (not CKM_ECDH1_DERIVE, which DeriveTests already covers).
		rv = deriveWith(hSession, c.mech, hPuk, hPrk);
		CPPUNIT_ASSERT_MESSAGE(std::string(c.name) + ": C_DeriveKey under this mechanism failed",
		                       rv == CKR_OK);

		CK_MECHANISM_INFO info;
		memset(&info, 0, sizeof info);
		CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, c.mech, &info) ) == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(std::string(c.name) + ": derives over its own fixed curve but "
		                       "advertises ulMinKeySize " + std::to_string(info.ulMinKeySize) +
		                       " instead of " + std::to_string(c.expectedSize),
		                       info.ulMinKeySize == c.expectedSize);
		CPPUNIT_ASSERT_MESSAGE(std::string(c.name) + ": advertises ulMaxKeySize " +
		                       std::to_string(info.ulMaxKeySize) + " instead of " +
		                       std::to_string(c.expectedSize),
		                       info.ulMaxKeySize == c.expectedSize);
		CPPUNIT_ASSERT_MESSAGE(std::string(c.name) + ": lost CKF_DERIVE",
		                       (info.flags & CKF_DERIVE) != 0);
	}
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}
#else
void MechanismInfoEcAdvertisementTests::testMontgomeryMechanismsAdvertiseTheirCurveSize() {}
#endif

void MechanismInfoEcAdvertisementTests::testBip32ChildDeriveAdvertisesItsParentKeySize()
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) ) == CKR_OK);
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT(login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length) == CKR_OK);

	// A BIP-32 seed. 32 bytes here, but nothing in the master-derive path
	// constrains that — see the assertion on CKM_BIP32_MASTER_DERIVE below.
	CK_MECHANISM genMech = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
	CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
	CK_KEY_TYPE genType = CKK_GENERIC_SECRET;
	CK_ULONG seedLen = 32;
	CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
	CK_ATTRIBUTE seedTmpl[] = {
		{ CKA_CLASS, &secClass, sizeof(secClass) },
		{ CKA_KEY_TYPE, &genType, sizeof(genType) },
		{ CKA_VALUE_LEN, &seedLen, sizeof(seedLen) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
	};
	CK_OBJECT_HANDLE hSeed = CK_INVALID_HANDLE;
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_GenerateKey(hSession, &genMech, seedTmpl,
		sizeof(seedTmpl)/sizeof(CK_ATTRIBUTE), &hSeed) ) == CKR_OK);

	CK_BYTE oidSecp256k1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a };
	CK_OBJECT_CLASS prkClass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE nodeTmpl[] = {
		{ CKA_CLASS, &prkClass, sizeof(prkClass) },
		{ CKA_EC_PARAMS, oidSecp256k1, sizeof(oidSecp256k1) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) }
	};
	const CK_ULONG nodeCount = sizeof(nodeTmpl)/sizeof(CK_ATTRIBUTE);

	CK_MECHANISM masterMech = { CKM_BIP32_MASTER_DERIVE, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hMaster = CK_INVALID_HANDLE;
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_DeriveKey(hSession, &masterMech, hSeed,
		nodeTmpl, nodeCount, &hMaster) ) == CKR_OK);

	// The child derive consumes hMaster's 32-byte private scalar. That is the
	// key size CKM_BIP32_CHILD_DERIVE has to advertise.
	CK_BIP32_CHILD_DERIVE_PARAMS childParams = { 0, 1 };
	CK_MECHANISM childMech = { CKM_BIP32_CHILD_DERIVE, &childParams, sizeof(childParams) };
	CK_OBJECT_HANDLE hChild = CK_INVALID_HANDLE;
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_DeriveKey(hSession, &childMech, hMaster,
		nodeTmpl, nodeCount, &hChild) ) == CKR_OK);

	CK_MECHANISM_INFO info;
	memset(&info, 0, sizeof info);
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID,
		CKM_BIP32_CHILD_DERIVE, &info) ) == CKR_OK);
	CPPUNIT_ASSERT_MESSAGE("CKM_BIP32_CHILD_DERIVE: derived from a 32-byte parent scalar but "
	                       "advertises ulMinKeySize " + std::to_string(info.ulMinKeySize),
	                       info.ulMinKeySize == 32);
	CPPUNIT_ASSERT_MESSAGE("CKM_BIP32_CHILD_DERIVE: advertises ulMaxKeySize " +
	                       std::to_string(info.ulMaxKeySize),
	                       info.ulMaxKeySize == 32);

	// CKM_BIP32_MASTER_DERIVE keeps 0/0 on purpose: deriveMasterNode accepts a
	// seed of any length, so there is no range to claim. Pinned so that
	// "make it match the Rust engine's 32/32" cannot land without a decision.
	memset(&info, 0, sizeof info);
	CPPUNIT_ASSERT(CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID,
		CKM_BIP32_MASTER_DERIVE, &info) ) == CKR_OK);
	CPPUNIT_ASSERT_MESSAGE("CKM_BIP32_MASTER_DERIVE: should advertise no key-size range (0/0) — "
	                       "its seed length is unconstrained",
	                       info.ulMinKeySize == 0 && info.ulMaxKeySize == 0);

	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}
