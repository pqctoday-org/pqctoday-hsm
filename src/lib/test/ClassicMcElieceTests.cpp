/*
 * Copyright (c) 2010 SURFnet bv
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
 ClassicMcElieceTests.cpp

 Contains test cases for Classic McEliece (BSI TR-02102-1 §2.4.2)
 C_GenerateKeyPair / C_EncapsulateKey / C_DecapsulateKey, across all 10
 CKP_CLASSIC_MCELIECE_* parameter sets, through the real PKCS#11 ABI —
 implementation plan §5.5 cross-validation (the C++-engine half; the
 official-KAT half lives in the Rust crate's own tests/kat_verification.rs).
 *****************************************************************************/

#include "ClassicMcElieceTests.h"
#include "vendor_mechanisms.h"
#include <cppunit/extensions/HelperMacros.h>
#include <vector>
#include <string>
#include <cstring>

CPPUNIT_TEST_SUITE_REGISTRATION(ClassicMcElieceTests);

CK_RV ClassicMcElieceTests::generateKeyPair(CK_SESSION_HANDLE hSession, CK_ULONG parameterSet, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	// CKA_ENCAPSULATE/CKA_DECAPSULATE are set by the engine itself
	// (SoftHSM::generateClassicMcEliece, PKCS#11 v3.2's own rule for
	// C_GenerateKeyPair) — not supplied here, matching the RSA/EC test
	// helpers' own minimal templates.
	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
					 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
					 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
					 &hPuk, &hPrk) );
}

void ClassicMcElieceTests::testKemRoundTrip()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER so we can create private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// (pkBytes, skBytes, ctBytes) mirrored from
	// ClassicMcEliecePublicKey::paramSetToSizes — itself verified against
	// the official Round-4 KAT vectors by the Rust crate's own tests.
	struct Variant { CK_ULONG ps; CK_ULONG pkBytes; CK_ULONG skBytes; CK_ULONG ctBytes; const char* name; };
	const Variant variants[] = {
		{ CKP_CLASSIC_MCELIECE_348864,    261120,  6492,  96, "348864"   },
		{ CKP_CLASSIC_MCELIECE_348864F,   261120,  6492,  96, "348864f"  },
		{ CKP_CLASSIC_MCELIECE_460896,    524160, 13608, 156, "460896"   },
		{ CKP_CLASSIC_MCELIECE_460896F,   524160, 13608, 156, "460896f"  },
		{ CKP_CLASSIC_MCELIECE_6688128,  1044992, 13932, 208, "6688128"  },
		{ CKP_CLASSIC_MCELIECE_6688128F, 1044992, 13932, 208, "6688128f" },
		{ CKP_CLASSIC_MCELIECE_6960119,  1047319, 13948, 194, "6960119"  },
		{ CKP_CLASSIC_MCELIECE_6960119F, 1047319, 13948, 194, "6960119f" },
		{ CKP_CLASSIC_MCELIECE_8192128,  1357824, 14120, 208, "8192128"  },
		{ CKP_CLASSIC_MCELIECE_8192128F, 1357824, 14120, 208, "8192128f" },
	};

	for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); ++v)
	{
		const Variant& variant = variants[v];
		const std::string msg = std::string("Classic McEliece variant ") + variant.name;

		CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE, hPrk = CK_INVALID_HANDLE;
		rv = generateKeyPair(hSessionRW, variant.ps, hPuk, hPrk);
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(msg, hPuk != CK_INVALID_HANDLE);
		CPPUNIT_ASSERT_MESSAGE(msg, hPrk != CK_INVALID_HANDLE);

		// Sanity: CKA_VALUE lengths match the plan's size table
		CK_ATTRIBUTE pukVal[] = { { CKA_VALUE, NULL_PTR, 0 } };
		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSessionRW, hPuk, pukVal, 1) );
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(msg, pukVal[0].ulValueLen == variant.pkBytes);

		CK_ATTRIBUTE prkVal[] = { { CKA_VALUE, NULL_PTR, 0 } };
		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSessionRW, hPrk, prkVal, 1) );
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(msg, prkVal[0].ulValueLen == variant.skBytes);

		// Encapsulate: size query, then the real call
		CK_MECHANISM mechanism = { CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE, NULL_PTR, 0 };
		CK_BBOOL bTrue = CK_TRUE;
		CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
		CK_ATTRIBUTE secretTemplate[] = {
			{ CKA_CLASS, &secretClass, sizeof(secretClass) },
			{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		};
		const CK_ULONG secretTemplateCount = sizeof(secretTemplate) / sizeof(CK_ATTRIBUTE);

		CK_ULONG ctLen = 0;
		CK_OBJECT_HANDLE hSecretSizeQuery = CK_INVALID_HANDLE;
		rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSessionRW, &mechanism, hPuk,
				secretTemplate, secretTemplateCount, NULL_PTR, &ctLen, &hSecretSizeQuery) );
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(msg, ctLen == variant.ctBytes);

		std::vector<CK_BYTE> ciphertext(ctLen);
		CK_OBJECT_HANDLE hSecret1 = CK_INVALID_HANDLE;
		rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSessionRW, &mechanism, hPuk,
				secretTemplate, secretTemplateCount, ciphertext.data(), &ctLen, &hSecret1) );
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(msg, hSecret1 != CK_INVALID_HANDLE);

		// Decapsulate the real ciphertext with the matching private key
		CK_OBJECT_HANDLE hSecret2 = CK_INVALID_HANDLE;
		rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSessionRW, &mechanism, hPrk,
				secretTemplate, secretTemplateCount, ciphertext.data(), ctLen, &hSecret2) );
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(msg, hSecret2 != CK_INVALID_HANDLE);

		// Both sides of the round trip must agree on the shared secret
		// (32 bytes, all 10 variants — ClassicMcEliecePrivateKey::getOutputLength).
		CK_BYTE secret1[64];
		CK_BYTE secret2[64];
		CK_ATTRIBUTE getSecret1[] = { { CKA_VALUE, secret1, sizeof(secret1) } };
		CK_ATTRIBUTE getSecret2[] = { { CKA_VALUE, secret2, sizeof(secret2) } };
		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSessionRW, hSecret1, getSecret1, 1) );
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_OK);
		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSessionRW, hSecret2, getSecret2, 1) );
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_OK);
		CPPUNIT_ASSERT_MESSAGE(msg, getSecret1[0].ulValueLen == 32);
		CPPUNIT_ASSERT_MESSAGE(msg, getSecret2[0].ulValueLen == 32);
		CPPUNIT_ASSERT_MESSAGE(msg, memcmp(secret1, secret2, 32) == 0);

		// Negative case: a ciphertext of the wrong length must be rejected,
		// not silently truncated/padded (implementation plan §3.2 — the
		// f/non-f interop consequence generalises to any length mismatch).
		std::vector<CK_BYTE> shortCiphertext(ctLen > 1 ? ctLen - 1 : 1, 0);
		CK_OBJECT_HANDLE hSecretBad = CK_INVALID_HANDLE;
		rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSessionRW, &mechanism, hPrk,
				secretTemplate, secretTemplateCount,
				shortCiphertext.data(), (CK_ULONG)shortCiphertext.size(), &hSecretBad) );
		CPPUNIT_ASSERT_MESSAGE(msg, rv == CKR_WRAPPED_KEY_LEN_RANGE);
	}
}
