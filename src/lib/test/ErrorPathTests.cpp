/*
 * Copyright (c) 2026 PQC Today
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 ErrorPathTests.cpp

 PKCS#11 v3.2 (pkcs11-spec-v3.2-os) error-path return values, reproducing the
 C++-engine findings of the Hub's G-8 error-path probes (2026-09-25; plan
 acvp-gap-closure-plan-09252026 §1.3, findings E5-E9 and E19). Each check
 asserts the exact CK_RV the specification names — never a set of
 "acceptable" codes — and every mismatch is collected before the assertion,
 so one run lists all of them.
 *****************************************************************************/

#include "ErrorPathTests.h"
#include "vendor_mechanisms.h"
#include <cppunit/extensions/HelperMacros.h>
#include <cstdio>
#include <cstring>
#include <vector>

CPPUNIT_TEST_SUITE_REGISTRATION(ErrorPathTests);

void ErrorPathTests::expect(std::string& fails, const std::string& what, CK_RV got, CK_RV want)
{
	if (got == want) return;
	char buf[96];
	snprintf(buf, sizeof(buf), ": got 0x%08lx, want 0x%08lx\n", (unsigned long)got, (unsigned long)want);
	fails += what + buf;
}

// TestsBase::setUp leaves an SO-logged-in session open; restart the library
// (as DeriveTests does) so the user can log in on a fresh R/W session.
CK_RV ErrorPathTests::openUserSession(CK_SESSION_HANDLE& hSession)
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	if (rv != CKR_OK) return rv;
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	if (rv != CKR_OK) return rv;
	return CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
}

bool ErrorPathTests::advertised(CK_MECHANISM_TYPE mech)
{
	CK_MECHANISM_INFO info;
	return CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, mech, &info) ) == CKR_OK;
}

// AES-256 secret key with every usage attribute set, so a rejection can only
// come from the key TYPE, never from a usage attribute.
CK_RV ErrorPathTests::aesKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE& hKey)
{
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG len = 32;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_VALUE_LEN, &len, sizeof(len) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_DERIVE, &bTrue, sizeof(bTrue) },
	};
	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hKey) );
}

CK_RV ErrorPathTests::rsaKeyPair(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE& hPuk, CK_OBJECT_HANDLE& hPrk)
{
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 2048;
	CK_BYTE pubExp[] = { 0x01, 0x00, 0x01 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY_RECOVER, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN_RECOVER, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
	};
	hPuk = hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
		pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
		prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE), &hPuk, &hPrk) );
}

// P-256 key pair; `sign` / `derive` set the private key's CKA_SIGN / CKA_DERIVE.
CK_RV ErrorPathTests::ecKeyPair(CK_SESSION_HANDLE hSession, CK_BBOOL sign, CK_BBOOL derive,
                                CK_OBJECT_HANDLE& hPuk, CK_OBJECT_HANDLE& hPrk)
{
	CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BYTE oidP256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_EC_PARAMS, oidP256, sizeof(oidP256) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &sign, sizeof(sign) },
		{ CKA_DERIVE, &derive, sizeof(derive) },
	};
	hPuk = hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
		pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
		prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE), &hPuk, &hPrk) );
}

CK_RV ErrorPathTests::pqcKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE gen, CK_KEY_TYPE kt, CK_ULONG ps,
                                 CK_OBJECT_HANDLE& hPuk, CK_OBJECT_HANDLE& hPrk)
{
	CK_MECHANISM mechanism = { gen, NULL_PTR, 0 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_PARAMETER_SET, &ps, sizeof(ps) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
	};
	hPuk = hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
		pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
		prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE), &hPuk, &hPrk) );
}

// The CK_RSA_PKCS_PSS_PARAMS a PSS mechanism accepts (hash and MGF must match
// the mechanism, §6.1.14), so a rejection cannot come from the parameter.
static CK_RSA_PKCS_PSS_PARAMS pssParamsFor(CK_MECHANISM_TYPE mech)
{
	switch (mech)
	{
		case CKM_SHA1_RSA_PKCS_PSS:     return { CKM_SHA_1,    CKG_MGF1_SHA1,     20 };
		case CKM_SHA224_RSA_PKCS_PSS:   return { CKM_SHA224,   CKG_MGF1_SHA224,   28 };
		case CKM_SHA384_RSA_PKCS_PSS:   return { CKM_SHA384,   CKG_MGF1_SHA384,   48 };
		case CKM_SHA512_RSA_PKCS_PSS:   return { CKM_SHA512,   CKG_MGF1_SHA512,   64 };
		case CKM_SHA3_224_RSA_PKCS_PSS: return { CKM_SHA3_224, CKG_MGF1_SHA3_224, 28 };
		case CKM_SHA3_256_RSA_PKCS_PSS: return { CKM_SHA3_256, CKG_MGF1_SHA3_256, 32 };
		case CKM_SHA3_384_RSA_PKCS_PSS: return { CKM_SHA3_384, CKG_MGF1_SHA3_384, 48 };
		case CKM_SHA3_512_RSA_PKCS_PSS: return { CKM_SHA3_512, CKG_MGF1_SHA3_512, 64 };
		default:                        return { CKM_SHA256,   CKG_MGF1_SHA256,   32 };
	}
}

static bool isPss(CK_MECHANISM_TYPE mech)
{
	switch (mech)
	{
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA224_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_SHA3_224_RSA_PKCS_PSS:
		case CKM_SHA3_256_RSA_PKCS_PSS:
		case CKM_SHA3_384_RSA_PKCS_PSS:
		case CKM_SHA3_512_RSA_PKCS_PSS:
			return true;
		default:
			return false;
	}
}

// E5 / E6 — §5.13.1 C_SignInit, §5.13.5 C_SignRecoverInit, §5.14.1
// C_MessageSignInit, §5.15.1 C_VerifyInit, §5.15.5 C_VerifyRecoverInit,
// §5.16.1 C_MessageVerifyInit, §5.18.5 C_DeriveKey and §5.18.8
// C_EncapsulateKey all list CKR_KEY_TYPE_INCONSISTENT; §5.1.6 defines it ("The
// specified key is not the correct type of key to use with the specified
// mechanism") and ranks it above CKR_KEY_FUNCTION_NOT_PERMITTED.
void ErrorPathTests::testKeyTypeInconsistentAtInit()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT(openUserSession(hSession) == CKR_OK);

	CK_OBJECT_HANDLE hAes, hEcPuk, hEcPrk, hEcPukNoUse, hEcPrkNoUse;
	CPPUNIT_ASSERT(aesKey(hSession, hAes) == CKR_OK);
	CPPUNIT_ASSERT(ecKeyPair(hSession, CK_TRUE, CK_TRUE, hEcPuk, hEcPrk) == CKR_OK);
	CPPUNIT_ASSERT(ecKeyPair(hSession, CK_FALSE, CK_FALSE, hEcPukNoUse, hEcPrkNoUse) == CKR_OK);

	std::string fails;

	// The 33 ECDSA / EdDSA / RSA mechanisms the G-8 probes found accepting an
	// AES key, plus ML-DSA / SLH-DSA, which already rejected it (regression).
	const CK_MECHANISM_TYPE sigMechs[] = {
		CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384,
		CKM_ECDSA_SHA512, CKM_ECDSA_SHA3_224, CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384,
		CKM_ECDSA_SHA3_512,
		CKM_EDDSA,
		CKM_RSA_PKCS, CKM_RSA_X_509, CKM_MD5_RSA_PKCS,
		CKM_SHA1_RSA_PKCS, CKM_SHA224_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS,
		CKM_SHA512_RSA_PKCS, CKM_SHA3_224_RSA_PKCS, CKM_SHA3_256_RSA_PKCS,
		CKM_SHA3_384_RSA_PKCS, CKM_SHA3_512_RSA_PKCS,
		CKM_RSA_PKCS_PSS,
		CKM_SHA1_RSA_PKCS_PSS, CKM_SHA224_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS,
		CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS, CKM_SHA3_224_RSA_PKCS_PSS,
		CKM_SHA3_256_RSA_PKCS_PSS, CKM_SHA3_384_RSA_PKCS_PSS, CKM_SHA3_512_RSA_PKCS_PSS,
		CKM_ML_DSA, CKM_SLH_DSA,
	};
	size_t probed = 0;
	for (CK_MECHANISM_TYPE mech : sigMechs)
	{
		CK_MECHANISM_INFO info;
		if (CRYPTOKI_F_PTR( C_GetMechanismInfo(m_initializedTokenSlotID, mech, &info) ) != CKR_OK)
			continue;
		probed++;
		CK_RSA_PKCS_PSS_PARAMS pss = pssParamsFor(mech);
		CK_MECHANISM m = { mech, NULL_PTR, 0 };
		if (isPss(mech)) { m.pParameter = &pss; m.ulParameterLen = sizeof(pss); }
		char name[64];
		snprintf(name, sizeof(name), "mech 0x%08lx", (unsigned long)mech);

		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hAes) );
		expect(fails, std::string("C_SignInit(AES key) ") + name, rv, CKR_KEY_TYPE_INCONSISTENT);
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_SignInit(hSession, NULL_PTR, CK_INVALID_HANDLE) );

		rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &m, hAes) );
		expect(fails, std::string("C_VerifyInit(AES key) ") + name, rv, CKR_KEY_TYPE_INCONSISTENT);
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_VerifyInit(hSession, NULL_PTR, CK_INVALID_HANDLE) );

		if (info.flags & CKF_MESSAGE_SIGN)
		{
			rv = CRYPTOKI_F_PTR( C_MessageSignInit(hSession, &m, hAes) );
			expect(fails, std::string("C_MessageSignInit(AES key) ") + name, rv, CKR_KEY_TYPE_INCONSISTENT);
			if (rv == CKR_OK) CRYPTOKI_F_PTR( C_MessageSignFinal(hSession) );
		}
		if (info.flags & CKF_MESSAGE_VERIFY)
		{
			rv = CRYPTOKI_F_PTR( C_MessageVerifyInit(hSession, &m, hAes) );
			expect(fails, std::string("C_MessageVerifyInit(AES key) ") + name, rv, CKR_KEY_TYPE_INCONSISTENT);
			if (rv == CKR_OK) CRYPTOKI_F_PTR( C_MessageVerifyFinal(hSession) );
		}
	}
	CPPUNIT_ASSERT_MESSAGE("no signature mechanism advertised", probed > 0);

	// §5.1.6 priority: the AES key has no CKA_SIGN_RECOVER / CKA_VERIFY_RECOVER,
	// so a usage-first implementation answers CKR_KEY_FUNCTION_NOT_PERMITTED.
	const CK_MECHANISM_TYPE recoverMechs[] = { CKM_RSA_PKCS, CKM_RSA_X_509 };
	for (CK_MECHANISM_TYPE mech : recoverMechs)
	{
		CK_MECHANISM m = { mech, NULL_PTR, 0 };
		char name[64];
		snprintf(name, sizeof(name), "mech 0x%08lx", (unsigned long)mech);
		rv = CRYPTOKI_F_PTR( C_SignRecoverInit(hSession, &m, hAes) );
		expect(fails, std::string("C_SignRecoverInit(AES key) ") + name, rv, CKR_KEY_TYPE_INCONSISTENT);
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_SignRecoverInit(hSession, NULL_PTR, CK_INVALID_HANDLE) );
		rv = CRYPTOKI_F_PTR( C_VerifyRecoverInit(hSession, &m, hAes) );
		expect(fails, std::string("C_VerifyRecoverInit(AES key) ") + name, rv, CKR_KEY_TYPE_INCONSISTENT);
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_VerifyRecoverInit(hSession, NULL_PTR, CK_INVALID_HANDLE) );
	}

	// The usage check itself still applies to a key of the RIGHT type.
	{
		CK_MECHANISM m = { CKM_ECDSA_SHA256, NULL_PTR, 0 };
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hEcPrkNoUse) );
		expect(fails, "C_SignInit(EC key, CKA_SIGN=FALSE)", rv, CKR_KEY_FUNCTION_NOT_PERMITTED);
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_SignInit(hSession, NULL_PTR, CK_INVALID_HANDLE) );
		rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &m, hEcPrk) );
		expect(fails, "C_SignInit(EC key, CKA_SIGN=TRUE)", rv, CKR_OK);
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_SignInit(hSession, NULL_PTR, CK_INVALID_HANDLE) );
	}

	// §5.18.8 C_EncapsulateKey lists CKR_KEY_TYPE_INCONSISTENT and not
	// CKR_KEY_FUNCTION_NOT_PERMITTED; the AES key has no CKA_ENCAPSULATE.
	{
		CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
		CK_KEY_TYPE genKeyType = CKK_GENERIC_SECRET;
		CK_BBOOL bFalse = CK_FALSE;
		CK_ATTRIBUTE tmpl[] = {
			{ CKA_CLASS, &secretClass, sizeof(secretClass) },
			{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
			{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		};
		const CK_MECHANISM_TYPE kemMechs[] = { CKM_ML_KEM, CKM_ECDH1_DERIVE };
		for (CK_MECHANISM_TYPE mech : kemMechs)
		{
			if (!advertised(mech)) continue;
			CK_MECHANISM m = { mech, NULL_PTR, 0 };
			CK_ULONG ctLen = 0;
			CK_OBJECT_HANDLE hSecret = CK_INVALID_HANDLE;
			char name[64];
			snprintf(name, sizeof(name), "mech 0x%08lx", (unsigned long)mech);
			rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &m, hAes, tmpl, sizeof(tmpl)/sizeof(CK_ATTRIBUTE),
			                                      NULL_PTR, &ctLen, &hSecret) );
			expect(fails, std::string("C_EncapsulateKey(AES key) ") + name, rv, CKR_KEY_TYPE_INCONSISTENT);
		}
	}

	// §6.62.3: the HKDF base key is a CKK_HKDF / CKK_GENERIC_SECRET key or a
	// data object — never an EC private key, with or without CKA_DERIVE.
	if (advertised(CKM_HKDF_DERIVE))
	{
		CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
		CK_KEY_TYPE genKeyType = CKK_GENERIC_SECRET;
		CK_ULONG outLen = 32;
		CK_ATTRIBUTE outAttribs[] = {
			{ CKA_CLASS, &secretClass, sizeof(secretClass) },
			{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
			{ CKA_VALUE_LEN, &outLen, sizeof(outLen) },
		};
		CK_HKDF_PARAMS params = { CK_TRUE, CK_TRUE, CKM_SHA256,
			CKF_HKDF_SALT_NULL, NULL_PTR, 0, CK_INVALID_HANDLE, NULL_PTR, 0 };
		CK_MECHANISM m = { CKM_HKDF_DERIVE, &params, sizeof(params) };
		CK_OBJECT_HANDLE hOut = CK_INVALID_HANDLE;
		rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, &m, hEcPrk, outAttribs, sizeof(outAttribs)/sizeof(CK_ATTRIBUTE), &hOut) );
		expect(fails, "C_DeriveKey(CKM_HKDF_DERIVE, EC private key, CKA_DERIVE=TRUE)", rv, CKR_KEY_TYPE_INCONSISTENT);
		rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, &m, hEcPrkNoUse, outAttribs, sizeof(outAttribs)/sizeof(CK_ATTRIBUTE), &hOut) );
		expect(fails, "C_DeriveKey(CKM_HKDF_DERIVE, EC private key, CKA_DERIVE=FALSE)", rv, CKR_KEY_TYPE_INCONSISTENT);
	}

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT_MESSAGE(fails, fails.empty());
}

// E7 — §5.18.4 C_UnwrapKey lists CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT; §5.1.6
// says CKR_WRAPPING_KEY_TYPE_INCONSISTENT "can only be returned by C_WrapKey".
void ErrorPathTests::testUnwrapKeyTypeCode()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT(openUserSession(hSession) == CKR_OK);

	CK_OBJECT_HANDLE hEcPuk, hEcPrk;
	CPPUNIT_ASSERT(ecKeyPair(hSession, CK_TRUE, CK_TRUE, hEcPuk, hEcPrk) == CKR_OK);

	std::string fails;
	CK_BYTE iv[16] = { 0 };
	CK_BYTE wrapped[32] = { 0 };
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_KEY_TYPE aesType = CKK_AES;
	CK_BBOOL bFalse = CK_FALSE;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &aesType, sizeof(aesType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
	};
	const CK_MECHANISM_TYPE mechs[] = { CKM_AES_CBC, CKM_AES_CBC_PAD };
	for (CK_MECHANISM_TYPE mech : mechs)
	{
		CK_MECHANISM m = { mech, iv, sizeof(iv) };
		CK_OBJECT_HANDLE hNew = CK_INVALID_HANDLE;
		char name[64];
		snprintf(name, sizeof(name), "mech 0x%08lx", (unsigned long)mech);
		rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &m, hEcPrk, wrapped, sizeof(wrapped),
		                                 tmpl, sizeof(tmpl)/sizeof(CK_ATTRIBUTE), &hNew) );
		expect(fails, std::string("C_UnwrapKey(EC private key) ") + name, rv, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
	}

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT_MESSAGE(fails, fails.empty());
}
