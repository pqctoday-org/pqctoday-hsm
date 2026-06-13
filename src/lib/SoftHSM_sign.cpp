/*
 * Copyright (c) 2022 NLnet Labs
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
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
 SoftHSM_sign.cpp

 PKCS#11 sign/verify/MAC operations: MacSignInit, AsymSignInit,
 StatefulSignInit, C_SignInit, C_Sign, C_SignUpdate, C_SignFinal,
 C_SignRecoverInit, C_SignRecover, MacVerifyInit, AsymVerifyInit,
 StatefulVerifyInit, StatefulVerify, C_VerifyInit, C_Verify, C_VerifyUpdate,
 C_VerifyFinal, multi-message stubs, C_VerifyRecoverInit, C_VerifyRecover,
 combined-operation stubs.  Static helpers: isMacMechanism, kMacMechTable,
 resolveMacMech, parseMLDSASignContext, parseSLHDSASignContext.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "CryptoFactory.h"
#include "cryptoki.h"
#include "MacAlgorithm.h"
#include "MutexFactory.h"
#include "AsymmetricAlgorithm.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"
#include "MLDSAPublicKey.h"
#include "MLDSAPrivateKey.h"
#include "MLDSAParameters.h"
#include "OSSLMLDSAPublicKey.h"
#include "OSSLMLDSAPrivateKey.h"
#include "SLHDSAPublicKey.h"
#include "SLHDSAPrivateKey.h"
#include "OSSLSLHDSAPublicKey.h"
#include "OSSLSLHDSAPrivateKey.h"
extern "C" {
#include "stateful/hash-sigs/hss.h"
#include "stateful/xmss-reference/xmss_core.h"
#include "stateful/xmss-reference/xmss.h"
}
#include "vendor_mechanisms.h"

// Sign*/Verify*() is for MACs too
static bool isMacMechanism(CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL_PTR) return false;

	switch(pMechanism->mechanism) {
		case CKM_MD5_HMAC:
#ifdef WITH_RIPEMD160
		case CKM_RIPEMD160_HMAC:
#endif
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
		case CKM_SHA3_224_HMAC:
		case CKM_SHA3_256_HMAC:
		case CKM_SHA3_384_HMAC:
		case CKM_SHA3_512_HMAC:
		case CKM_AES_CMAC:
		case CKM_KMAC_128:
		case CKM_KMAC_256:
			return true;
		default:
			return false;
	}
}

// ---------------------------------------------------------------------------
// MAC mechanism lookup table (H3 refactor)
//
// Maps each supported MAC mechanism to its required key type, whether
// CKK_GENERIC_SECRET is an acceptable alternative (HMAC), the PKCS#11
// minimum output length in bytes, and the internal MacAlgo identifier.
// Adding a new MAC mechanism requires one table row and no switch edits.
// ---------------------------------------------------------------------------
namespace {

struct MacMechInfo {
	CK_MECHANISM_TYPE mech;
	CK_KEY_TYPE       specificKeyType; ///< e.g. CKK_SHA256_HMAC; CKK_AES for CMAC
	bool              allowGenericSecret; ///< HMAC: true; CMAC: false
	size_t            minKeyBytes;     ///< minimum key length (0 = no PKCS#11 minimum)
	MacAlgo::Type     algo;
};

static const MacMechInfo kMacMechTable[] = {
#ifdef WITH_RIPEMD160
	// HMAC-RIPEMD-160 (native-only; legacy provider). Mirrors SHA-1-HMAC sizing.
	{ CKM_RIPEMD160_HMAC,CKK_RIPEMD160_HMAC,true,  20, MacAlgo::HMAC_RIPEMD160},
#endif
	{ CKM_SHA_1_HMAC,    CKK_SHA_1_HMAC,    true,  20, MacAlgo::HMAC_SHA1     },
	{ CKM_SHA224_HMAC,   CKK_SHA224_HMAC,   true,  28, MacAlgo::HMAC_SHA224   },
	{ CKM_SHA256_HMAC,   CKK_SHA256_HMAC,   true,  32, MacAlgo::HMAC_SHA256   },
	{ CKM_SHA384_HMAC,   CKK_SHA384_HMAC,   true,  48, MacAlgo::HMAC_SHA384   },
	{ CKM_SHA512_HMAC,   CKK_SHA512_HMAC,   true,  64, MacAlgo::HMAC_SHA512   },
	{ CKM_SHA3_224_HMAC, CKK_SHA3_224_HMAC, true,  28, MacAlgo::HMAC_SHA3_224 },
	{ CKM_SHA3_256_HMAC, CKK_SHA3_256_HMAC, true,  32, MacAlgo::HMAC_SHA3_256 },
	{ CKM_SHA3_384_HMAC, CKK_SHA3_384_HMAC, true,  48, MacAlgo::HMAC_SHA3_384 },
	{ CKM_SHA3_512_HMAC, CKK_SHA3_512_HMAC, true,  64, MacAlgo::HMAC_SHA3_512 },
	{ CKM_AES_CMAC,      CKK_AES,           false,  0, MacAlgo::CMAC_AES      },
	{ CKM_KMAC_128,      CKK_GENERIC_SECRET,true,  16, MacAlgo::KMAC_128      },
	{ CKM_KMAC_256,      CKK_GENERIC_SECRET,true,  32, MacAlgo::KMAC_256      },
};

/**
 * @brief Resolve a MAC mechanism to its algorithm and key-type requirements.
 *
 * Handles the WITH_FIPS compile-time exclusion of CKM_MD5_HMAC and validates
 * that @p keyType is consistent with the chosen mechanism.
 *
 * @param mech     Mechanism identifier from the caller's CK_MECHANISM.
 * @param keyType  CKA_KEY_TYPE of the supplied key object.
 * @param algo     [out] Resolved MacAlgo identifier.
 * @param minKeyBytes [out] Minimum acceptable key byte length.
 * @return CKR_OK, CKR_MECHANISM_INVALID, or CKR_KEY_TYPE_INCONSISTENT.
 */
static CK_RV resolveMacMech(CK_MECHANISM_TYPE mech, CK_KEY_TYPE keyType,
                             MacAlgo::Type& algo, size_t& minKeyBytes)
{
#ifndef WITH_FIPS
	if (mech == CKM_MD5_HMAC) {
		if (keyType != CKK_GENERIC_SECRET && keyType != CKK_MD5_HMAC)
			return CKR_KEY_TYPE_INCONSISTENT;
		algo        = MacAlgo::HMAC_MD5;
		minKeyBytes = 16;
		return CKR_OK;
	}
#endif
	for (const MacMechInfo& e : kMacMechTable) {
		if (e.mech != mech) continue;
		if (e.allowGenericSecret) {
			if (keyType != CKK_GENERIC_SECRET && keyType != e.specificKeyType)
				return CKR_KEY_TYPE_INCONSISTENT;
		} else {
			if (keyType != e.specificKeyType)
				return CKR_KEY_TYPE_INCONSISTENT;
		}
		algo        = e.algo;
		minKeyBytes = e.minKeyBytes;
		return CKR_OK;
	}
	return CKR_MECHANISM_INVALID;
}

} // anonymous namespace

// MacAlgorithm version of C_SignInit
CK_RV SoftHSM::MacSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_SIGN lets a Sign init pair with an already-active Encrypt op
	// for C_SignEncryptUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_SIGN, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_SIGN);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Resolve mechanism → algorithm + key-type check via lookup table (H3).
	MacAlgo::Type algo = MacAlgo::Unknown;
	size_t minSize = 0;
	CK_RV mechRv = resolveMacMech(pMechanism->mechanism, keyType, algo, minSize);
	if (mechRv != CKR_OK) return mechRv;

	MacAlgorithm* mac = CryptoFactory::i()->getMacAlgorithm(algo);
	if (mac == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* privkey = new SymmetricKey();

	if (getSymmetricKey(privkey, token, key) != CKR_OK)
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_GENERAL_ERROR;
	}

	// Key must have at least 1 byte; RFC 2104 permits any positive key size for HMAC
	privkey->setBitLen(privkey->getKeyBits().size() * 8);

	if (privkey->getBitLen() == 0)
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_KEY_SIZE_RANGE;
	}

	// Initialize signing
	if (!mac->signInit(privkey))
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_SIGN);
	session->setMacOp(mac);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(privkey);

	return CKR_OK;
}

// Parse CK_SIGN_ADDITIONAL_CONTEXT or CK_HASH_SIGN_ADDITIONAL_CONTEXT → MLDSA_SIGN_PARAMS
// Deep-copies context bytes into inline buffer to avoid dangling pointers in session storage.
static CK_RV parseMLDSASignContext(CK_MECHANISM_PTR pMechanism, MLDSA_SIGN_PARAMS& out)
{
	memset(&out, 0, sizeof(out));
	out.hashAlg = HashAlgo::Unknown;

	if (pMechanism->pParameter == NULL_PTR || pMechanism->ulParameterLen == 0)
	{
		// No params → defaults: hedged, no context, pure mode
		return CKR_OK;
	}

	// Only CKM_HASH_ML_DSA (generic) uses CK_HASH_SIGN_ADDITIONAL_CONTEXT (16 bytes).
	// The specific CKM_HASH_ML_DSA_SHA256 etc. use CK_SIGN_ADDITIONAL_CONTEXT (12 bytes)
	// — the hash algorithm is implicit in the mechanism constant.
	bool isHashMech = (pMechanism->mechanism == CKM_HASH_ML_DSA);

	if (!isHashMech)
	{
		// CK_SIGN_ADDITIONAL_CONTEXT (12 bytes on 32-bit, may vary)
		if (pMechanism->ulParameterLen != sizeof(CK_SIGN_ADDITIONAL_CONTEXT))
		{
			ERROR_MSG("Invalid ML-DSA parameter size (%lu, expected %lu)",
				pMechanism->ulParameterLen, (unsigned long)sizeof(CK_SIGN_ADDITIONAL_CONTEXT));
			return CKR_ARGUMENTS_BAD;
		}
		CK_SIGN_ADDITIONAL_CONTEXT* ctx =
			(CK_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;

		switch (ctx->hedgeVariant)
		{
			case CKH_HEDGE_PREFERRED:
				out.deterministic = false;
				out.hedgeRequired = false;
				break;
			case CKH_HEDGE_REQUIRED:
				out.deterministic = false;
				out.hedgeRequired = true;
				break;
			case CKH_DETERMINISTIC_REQUIRED:
				out.deterministic = true;
				out.hedgeRequired = false;
				break;
			default:
				ERROR_MSG("Invalid hedge variant %lu", ctx->hedgeVariant);
				return CKR_ARGUMENTS_BAD;
		}

		if (ctx->ulContextLen > 255)
		{
			ERROR_MSG("ML-DSA context string too long (%lu, max 255)", ctx->ulContextLen);
			return CKR_ARGUMENTS_BAD;
		}
		out.contextLen = ctx->ulContextLen;
		if (ctx->ulContextLen > 0)
		{
			if (ctx->pContext == NULL_PTR)
			{
				ERROR_MSG("ML-DSA context pointer is NULL with non-zero length");
				return CKR_ARGUMENTS_BAD;
			}
			memcpy(out.context, ctx->pContext, ctx->ulContextLen);
		}
		out.preHash = false;
	}
	else
	{
		// CK_HASH_SIGN_ADDITIONAL_CONTEXT (16 bytes on 32-bit, may vary)
		if (pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
		{
			ERROR_MSG("Invalid HashML-DSA parameter size (%lu, expected %lu)",
				pMechanism->ulParameterLen,
				(unsigned long)sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT));
			return CKR_ARGUMENTS_BAD;
		}
		CK_HASH_SIGN_ADDITIONAL_CONTEXT* ctx =
			(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;

		switch (ctx->hedgeVariant)
		{
			case CKH_HEDGE_PREFERRED:
				out.deterministic = false;
				out.hedgeRequired = false;
				break;
			case CKH_HEDGE_REQUIRED:
				out.deterministic = false;
				out.hedgeRequired = true;
				break;
			case CKH_DETERMINISTIC_REQUIRED:
				out.deterministic = true;
				out.hedgeRequired = false;
				break;
			default:
				ERROR_MSG("Invalid hedge variant %lu", ctx->hedgeVariant);
				return CKR_ARGUMENTS_BAD;
		}

		if (ctx->ulContextLen > 255)
		{
			ERROR_MSG("ML-DSA context string too long (%lu)", ctx->ulContextLen);
			return CKR_ARGUMENTS_BAD;
		}
		out.contextLen = ctx->ulContextLen;
		if (ctx->ulContextLen > 0)
		{
			if (ctx->pContext == NULL_PTR) return CKR_ARGUMENTS_BAD;
			memcpy(out.context, ctx->pContext, ctx->ulContextLen);
		}
		out.preHash = true;
	}
	return CKR_OK;
}

// Parse CK_SIGN_ADDITIONAL_CONTEXT or CK_HASH_SIGN_ADDITIONAL_CONTEXT → SLHDSA_SIGN_PARAMS
// SLH-DSA is always probabilistic; hedgeVariant is accepted but ignored.
//
// Parameter struct selection (PKCS#11 v3.2):
//   CKM_HASH_SLH_DSA (generic)  → CK_HASH_SIGN_ADDITIONAL_CONTEXT (includes hash field)
//   CKM_HASH_SLH_DSA_SHA256 etc → CK_SIGN_ADDITIONAL_CONTEXT (hash is implied by mechanism)
//
// When isHashMech is false (all 10 typed CKM_HASH_SLH_DSA_* variants), callers MUST supply
// CK_SIGN_ADDITIONAL_CONTEXT, NOT CK_HASH_SIGN_ADDITIONAL_CONTEXT.  Passing the larger
// struct to a typed variant returns CKR_ARGUMENTS_BAD with an "Invalid SLH-DSA parameter
// size" error.
static CK_RV parseSLHDSASignContext(CK_MECHANISM_PTR pMechanism, SLHDSA_SIGN_PARAMS& out)
{
	memset(&out, 0, sizeof(out));
	out.hashAlg = HashAlgo::Unknown;

	if (pMechanism->pParameter == NULL_PTR || pMechanism->ulParameterLen == 0)
	{
		// No params → defaults: no context, pure mode
		return CKR_OK;
	}

	bool isHashMech = (pMechanism->mechanism == CKM_HASH_SLH_DSA);

	if (!isHashMech)
	{
		// CK_SIGN_ADDITIONAL_CONTEXT: hedgeVariant (ignored for SLH-DSA) + context
		if (pMechanism->ulParameterLen != sizeof(CK_SIGN_ADDITIONAL_CONTEXT))
		{
			ERROR_MSG("Invalid SLH-DSA parameter size (%lu, expected %lu)",
				pMechanism->ulParameterLen,
				(unsigned long)sizeof(CK_SIGN_ADDITIONAL_CONTEXT));
			return CKR_ARGUMENTS_BAD;
		}
		CK_SIGN_ADDITIONAL_CONTEXT* ctx =
			(CK_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;

		// Honor deterministic mode (FIPS 205 §10); other hedgeVariants accepted but ignored
		out.deterministic = (ctx->hedgeVariant == CKH_DETERMINISTIC_REQUIRED);

		if (ctx->ulContextLen > 255)
		{
			ERROR_MSG("SLH-DSA context string too long (%lu, max 255)",
				ctx->ulContextLen);
			return CKR_ARGUMENTS_BAD;
		}
		out.contextLen = ctx->ulContextLen;
		if (ctx->ulContextLen > 0)
		{
			if (ctx->pContext == NULL_PTR)
			{
				ERROR_MSG("SLH-DSA context pointer is NULL with non-zero length");
				return CKR_ARGUMENTS_BAD;
			}
			memcpy(out.context, ctx->pContext, ctx->ulContextLen);
		}
		out.preHash = false;
	}
	else
	{
		// CK_HASH_SIGN_ADDITIONAL_CONTEXT: hedgeVariant + context + hash
		if (pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
		{
			ERROR_MSG("Invalid HashSLH-DSA parameter size (%lu, expected %lu)",
				pMechanism->ulParameterLen,
				(unsigned long)sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT));
			return CKR_ARGUMENTS_BAD;
		}
		CK_HASH_SIGN_ADDITIONAL_CONTEXT* ctx =
			(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;

		// Honor deterministic mode (FIPS 205 §10)
		out.deterministic = (ctx->hedgeVariant == CKH_DETERMINISTIC_REQUIRED);

		if (ctx->ulContextLen > 255)
		{
			ERROR_MSG("SLH-DSA context string too long (%lu)", ctx->ulContextLen);
			return CKR_ARGUMENTS_BAD;
		}
		out.contextLen = ctx->ulContextLen;
		if (ctx->ulContextLen > 0)
		{
			if (ctx->pContext == NULL_PTR) return CKR_ARGUMENTS_BAD;
			memcpy(out.context, ctx->pContext, ctx->ulContextLen);
		}
		out.preHash = true;
		// hash algorithm is set by the caller after this function returns
	}
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignInit
CK_RV SoftHSM::AsymSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_SIGN lets a Sign init pair with an already-active Encrypt op
	// for C_SignEncryptUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_SIGN, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_SIGN);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	void* param = NULL;
	size_t paramLen = 0;
	RSA_PKCS_PSS_PARAMS pssParam;
	MLDSA_SIGN_PARAMS mldsaSignParam;
	memset(&mldsaSignParam, 0, sizeof(mldsaSignParam));
	SLHDSA_SIGN_PARAMS slhdsaSignParam;
	memset(&slhdsaSignParam, 0, sizeof(slhdsaSignParam));
	bool bAllowMultiPartOp;
	bool isRSA = false;
#ifdef WITH_ECC
	bool isECDSA = false;
#endif
#ifdef WITH_EDDSA
	bool isEDDSA = false;
#endif
	bool isMLDSA = false;
	bool isSLHDSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = AsymMech::RSA_PKCS;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = AsymMech::RSA;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#ifndef WITH_FIPS
		case CKM_MD5_RSA_PKCS:
			mechanism = AsymMech::RSA_MD5_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA1_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA224_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA256_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA384_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA512_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_224_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA3_224_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_256_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA3_256_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_384_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA3_384_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_512_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA3_512_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
			{
				ERROR_MSG("Invalid RSA-PSS parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_PKCS_PSS;
			unsigned long allowedMgf;

			switch(CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg) {
				case CKM_SHA_1:
					pssParam.hashAlg = HashAlgo::SHA1;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
					allowedMgf = CKG_MGF1_SHA1;
					break;
				case CKM_SHA224:
					pssParam.hashAlg = HashAlgo::SHA224;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
					allowedMgf = CKG_MGF1_SHA224;
					break;
				case CKM_SHA256:
					pssParam.hashAlg = HashAlgo::SHA256;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
					allowedMgf = CKG_MGF1_SHA256;
					break;
				case CKM_SHA384:
					pssParam.hashAlg = HashAlgo::SHA384;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
					allowedMgf = CKG_MGF1_SHA384;
					break;
				case CKM_SHA512:
					pssParam.hashAlg = HashAlgo::SHA512;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
					allowedMgf = CKG_MGF1_SHA512;
					break;
				default:
					ERROR_MSG("Invalid RSA-PSS hash");
					return CKR_ARGUMENTS_BAD;
			}

			if (CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != allowedMgf) {
				ERROR_MSG("Hash and MGF don't match");
				return CKR_ARGUMENTS_BAD;
			}

			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA_1 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA1_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA1;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA224 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA224_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA224;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA256 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA256_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA256;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA384 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA384_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA384;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA512 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA512_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA512;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_224_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA3_224 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA3_224)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA3_224_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA3_224;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA3_224;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_256_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA3_256 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA3_256)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA3_256_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA3_256;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA3_256;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_384_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA3_384 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA3_384)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA3_384_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA3_384;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA3_384;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_512_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA3_512 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA3_512)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA3_512_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA3_512;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA3_512;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_ECC
		case CKM_ECDSA:
			mechanism = AsymMech::ECDSA;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA1:
			mechanism = AsymMech::ECDSA_SHA1;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA224:
			mechanism = AsymMech::ECDSA_SHA224;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA256:
			mechanism = AsymMech::ECDSA_SHA256;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA384:
			mechanism = AsymMech::ECDSA_SHA384;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA512:
			mechanism = AsymMech::ECDSA_SHA512;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA3_224:
			mechanism = AsymMech::ECDSA_SHA3_224;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA3_256:
			mechanism = AsymMech::ECDSA_SHA3_256;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA3_384:
			mechanism = AsymMech::ECDSA_SHA3_384;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA3_512:
			mechanism = AsymMech::ECDSA_SHA3_512;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
#endif
#ifdef WITH_EDDSA
		case CKM_EDDSA:
			mechanism = AsymMech::EDDSA;
			bAllowMultiPartOp = true;
			isEDDSA = true;
			break;
		case CKM_EDDSA_PH:
			mechanism = AsymMech::EDDSA_PH;
			bAllowMultiPartOp = true;
			isEDDSA = true;
			break;
#endif
		case CKM_ML_DSA:
		{
			mechanism = AsymMech::MLDSA;
			bAllowMultiPartOp = true;
			isMLDSA = true;
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			param = &mldsaSignParam;
			paramLen = sizeof(mldsaSignParam);
			break;
		}
		case CKM_HASH_ML_DSA:
		{
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
			{
				ERROR_MSG("CKM_HASH_ML_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::HASH_MLDSA;
			bAllowMultiPartOp = true;
			isMLDSA = true;
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			// For generic CKM_HASH_ML_DSA, hash comes from param struct
			CK_HASH_SIGN_ADDITIONAL_CONTEXT* hctx =
				(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;
			switch (hctx->hash)
			{
				case CKM_SHA224:   mldsaSignParam.hashAlg = HashAlgo::SHA224;   break;
				case CKM_SHA256:   mldsaSignParam.hashAlg = HashAlgo::SHA256;   break;
				case CKM_SHA384:   mldsaSignParam.hashAlg = HashAlgo::SHA384;   break;
				case CKM_SHA512:   mldsaSignParam.hashAlg = HashAlgo::SHA512;   break;
				case CKM_SHA3_224: mldsaSignParam.hashAlg = HashAlgo::SHA3_224; break;
				case CKM_SHA3_256: mldsaSignParam.hashAlg = HashAlgo::SHA3_256; break;
				case CKM_SHA3_384: mldsaSignParam.hashAlg = HashAlgo::SHA3_384; break;
				case CKM_SHA3_512: mldsaSignParam.hashAlg = HashAlgo::SHA3_512; break;
				default:
					ERROR_MSG("Unsupported hash 0x%08lx for CKM_HASH_ML_DSA", hctx->hash);
					return CKR_ARGUMENTS_BAD;
			}
			param = &mldsaSignParam;
			paramLen = sizeof(mldsaSignParam);
			break;
		}
#define HASH_MLDSA_CASE(CKM_CONST, MECH_ENUM, HASH_ALGO) \
		case CKM_CONST: \
		{ \
			mechanism = AsymMech::MECH_ENUM; \
			bAllowMultiPartOp = true; \
			isMLDSA = true; \
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam); \
			if (rv2 != CKR_OK) return rv2; \
			mldsaSignParam.preHash = true; \
			mldsaSignParam.hashAlg = HashAlgo::HASH_ALGO; \
			param = &mldsaSignParam; \
			paramLen = sizeof(mldsaSignParam); \
			break; \
		}
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA224,  HASH_MLDSA_SHA224,  SHA224)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA256,  HASH_MLDSA_SHA256,  SHA256)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA384,  HASH_MLDSA_SHA384,  SHA384)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA512,  HASH_MLDSA_SHA512,  SHA512)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_224, HASH_MLDSA_SHA3_224, SHA3_224)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_256, HASH_MLDSA_SHA3_256, SHA3_256)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_384, HASH_MLDSA_SHA3_384, SHA3_384)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_512, HASH_MLDSA_SHA3_512, SHA3_512)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHAKE128, HASH_MLDSA_SHAKE128, SHAKE128)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHAKE256, HASH_MLDSA_SHAKE256, SHAKE256)
#undef HASH_MLDSA_CASE
		case CKM_SLH_DSA:
			// PKCS#11 v3.2: CKM_SLH_DSA accepts optional CK_SIGN_ADDITIONAL_CONTEXT
			// for context string (FIPS 205 §9.2) and deterministic mode (FIPS 205 §10).
			if (pMechanism->pParameter != NULL_PTR)
			{
				CK_RV rv2 = parseSLHDSASignContext(pMechanism, slhdsaSignParam);
				if (rv2 != CKR_OK) return rv2;
				param = &slhdsaSignParam;
				paramLen = sizeof(slhdsaSignParam);
			}
			mechanism = AsymMech::SLHDSA;
			bAllowMultiPartOp = true;
			isSLHDSA = true;
			break;
		case CKM_HASH_SLH_DSA:
		{
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
			{
				ERROR_MSG("CKM_HASH_SLH_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::HASH_SLHDSA;
			bAllowMultiPartOp = true;
			isSLHDSA = true;
			CK_RV rv2 = parseSLHDSASignContext(pMechanism, slhdsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			CK_HASH_SIGN_ADDITIONAL_CONTEXT* hctx =
				(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;
			switch (hctx->hash)
			{
				case CKM_SHA224:   slhdsaSignParam.hashAlg = HashAlgo::SHA224;   break;
				case CKM_SHA256:   slhdsaSignParam.hashAlg = HashAlgo::SHA256;   break;
				case CKM_SHA384:   slhdsaSignParam.hashAlg = HashAlgo::SHA384;   break;
				case CKM_SHA512:   slhdsaSignParam.hashAlg = HashAlgo::SHA512;   break;
				case CKM_SHA3_224: slhdsaSignParam.hashAlg = HashAlgo::SHA3_224; break;
				case CKM_SHA3_256: slhdsaSignParam.hashAlg = HashAlgo::SHA3_256; break;
				case CKM_SHA3_384: slhdsaSignParam.hashAlg = HashAlgo::SHA3_384; break;
				case CKM_SHA3_512: slhdsaSignParam.hashAlg = HashAlgo::SHA3_512; break;
				default:
					ERROR_MSG("Unsupported hash 0x%08lx for CKM_HASH_SLH_DSA",
					          hctx->hash);
					return CKR_ARGUMENTS_BAD;
			}
			param = &slhdsaSignParam;
			paramLen = sizeof(slhdsaSignParam);
			break;
		}
#define HASH_SLHDSA_CASE(CKM_CONST, MECH_ENUM, HASH_ALGO) \
		case CKM_CONST: \
		{ \
			mechanism = AsymMech::MECH_ENUM; \
			bAllowMultiPartOp = true; \
			isSLHDSA = true; \
			CK_RV rv2 = parseSLHDSASignContext(pMechanism, slhdsaSignParam); \
			if (rv2 != CKR_OK) return rv2; \
			slhdsaSignParam.preHash = true; \
			slhdsaSignParam.hashAlg = HashAlgo::HASH_ALGO; \
			param = &slhdsaSignParam; \
			paramLen = sizeof(slhdsaSignParam); \
			break; \
		}
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA224,   HASH_SLHDSA_SHA224,   SHA224)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA256,   HASH_SLHDSA_SHA256,   SHA256)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA384,   HASH_SLHDSA_SHA384,   SHA384)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA512,   HASH_SLHDSA_SHA512,   SHA512)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA3_224, HASH_SLHDSA_SHA3_224, SHA3_224)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA3_256, HASH_SLHDSA_SHA3_256, SHA3_256)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA3_384, HASH_SLHDSA_SHA3_384, SHA3_384)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA3_512, HASH_SLHDSA_SHA3_512, SHA3_512)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHAKE128, HASH_SLHDSA_SHAKE128, SHAKE128)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHAKE256, HASH_SLHDSA_SHAKE256, SHAKE256)
#undef HASH_SLHDSA_CASE
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Reject unexpected parameters for parameterless mechanisms
	if (param == NULL && pMechanism->pParameter != NULL_PTR)
	{
		ERROR_MSG("Mechanism does not accept parameters");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PrivateKey* privateKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#ifdef WITH_ECC
	else if (isECDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getECPrivateKey((ECPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
#ifdef WITH_EDDSA
	else if (isEDDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getEDPrivateKey((EDPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	else if (isMLDSA)
	{
		if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_ML_DSA)
			return CKR_KEY_TYPE_INCONSISTENT;

		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getMLDSAPrivateKey((MLDSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else if (isSLHDSA)
	{
		if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_SLH_DSA)
			return CKR_KEY_TYPE_INCONSISTENT;

		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getSLHDSAPrivateKey((SLHDSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		// No recognized mechanism flag was set — the mechanism switch above
		// must return CKR_MECHANISM_INVALID before reaching here; this branch
		// is unreachable today, but assert defensively to prevent a NULL
		// dereference if a future mechanism case forgets to set a flag.
		return CKR_MECHANISM_INVALID;
	}

	// Initialize signing
	if (bAllowMultiPartOp && !asymCrypto->signInit(privateKey,mechanism,param,paramLen))
	{
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	// Check if re-authentication is required
	if (key->getBooleanValue(CKA_ALWAYS_AUTHENTICATE, false))
	{
		session->setReAuthentication(true);
	}

	if (param != NULL && paramLen > 0 && !session->setParameters(param, paramLen))
	{
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_HOST_MEMORY;
	}

	session->setOpType(SESSION_OP_SIGN);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(bAllowMultiPartOp);
	session->setAllowSinglePartOp(true);
	session->setPrivateKey(privateKey);

	return CKR_OK;
}

// Stateful version of C_SignInit
CK_RV SoftHSM::StatefulSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_SIGN lets a Sign init pair with an already-active Encrypt op
	// for C_SignEncryptUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_SIGN, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_SIGN);
	if (rv != CKR_OK) return rv;

	session->setOpType(SESSION_OP_SIGN);
	
	// Stateful signatures do NOT use AsymmetricAlgorithm base.
	// Instead, we just track the exact mechanism and the raw hKey in the session.
	AsymMech::Type mechanism = AsymMech::Unknown;
	if (pMechanism->mechanism == CKM_HSS) {
		mechanism = (AsymMech::Type)1000; // Custom flag for HSS
	} else if (pMechanism->mechanism == CKM_XMSS) {
		mechanism = (AsymMech::Type)1001; // Custom flag for XMSS
	} else if (pMechanism->mechanism == CKM_XMSSMT) {
		mechanism = (AsymMech::Type)1002; // Custom flag for XMSS^MT
	} else {
		return CKR_MECHANISM_INVALID;
	}

	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false); // Stateful signatures are 100% single-part (C_Sign only)
	session->setAllowSinglePartOp(true);
	session->setSignKeyHandle(hKey);

	return CKR_OK;
}

// Initialise a signing operation using the specified key and mechanism
CK_RV SoftHSM::C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	
	if (isMacMechanism(pMechanism))
		return MacSignInit(hSession, pMechanism, hKey);
	else if (pMechanism->mechanism == CKM_HSS ||
	         pMechanism->mechanism == CKM_XMSS || pMechanism->mechanism == CKM_XMSSMT)
		return StatefulSignInit(hSession, pMechanism, hKey);
	else
		return AsymSignInit(hSession, pMechanism, hKey);
}

// MacAlgorithm version of C_Sign
static CK_RV MacSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	// V-17: a one-shot C_Sign after C_SignUpdate must report CKR_OPERATION_ACTIVE
	// without destroying the multi-part op (the caller can still C_SignFinal).
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Size of the signature
	CK_ULONG size = mac->getMacSize();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Sign the data
	if (!mac->signUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the signature
	ByteString signature;
	if (!mac->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_Sign
static CK_RV AsymSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PrivateKey* privateKey = session->getPrivateKey();
	size_t paramLen;
	void* param = session->getParameters(paramLen);
	if (asymCrypto == NULL || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	// V-17: a one-shot C_Sign after C_SignUpdate must report CKR_OPERATION_ACTIVE
	// without destroying the multi-part op (the caller can still C_SignFinal).
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data;

	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (mechanism == AsymMech::RSA) {
		if (ulDataLen > size)
		{
			session->resetOp();
			return CKR_DATA_LEN_RANGE;
		}
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);
	ByteString signature;

	// Sign the data
	if (session->getAllowMultiPartOp())
	{
		if (!asymCrypto->signUpdate(data) ||
		    !asymCrypto->signFinal(signature))
		{
			session->resetOp();
			return CKR_GENERAL_ERROR;
		}
	}
	else if (!asymCrypto->sign(privateKey,data,signature,mechanism,param,paramLen))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

CK_RV SoftHSM::StatefulSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!session->getAllowSinglePartOp()) {
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	CK_OBJECT_HANDLE hKey = session->getSignKeyHandle();
	OSObject* osObj = (OSObject*)handleManager->getObject(hKey, session->getSlot()->getSlotID());
	if (!osObj) {
		session->resetOp();
		return CKR_KEY_HANDLE_INVALID;
	}

	AsymMech::Type mechanism = session->getMechanism();

	// Leaf-reuse race (audit API-dimension V5): two sessions signing the same
	// stateful key both read CKA_VALUE before either commits, releasing two
	// signatures from the same one-time leaf. Serialize the whole
	// read → sign → commit critical section for all stateful keys. The state
	// is persisted BEFORE the signature is released to the caller; if the
	// commit fails the signature is never handed out.
	static Mutex* statefulSignMutex = MutexFactory::i()->getMutex();
	MutexLocker statefulSignLock(statefulSignMutex);

	// V-13: private CKA_VALUE is stored token-encrypted (matching every other
	// private key type). Decrypt before use; re-encrypt the mutated state on
	// write-back. Public keys (CKA_PRIVATE=FALSE) store the value in clear.
	Token* token = session->getToken();
	bool isPrivate = osObj->getBooleanValue(CKA_PRIVATE, true);
	ByteString storedValue = osObj->getByteStringValue(CKA_VALUE);
	ByteString privKeyBytes;
	if (isPrivate) {
		if (token == NULL || !token->decrypt(storedValue, privKeyBytes)) {
			session->resetOp();
			return CKR_GENERAL_ERROR;
		}
	} else {
		privKeyBytes = storedValue;
	}

	// Heap-size the output buffer to sig_bytes + ulDataLen. xmss_sign() /
	// xmssmt_sign() write [signature || message]; the old fixed 8000-byte
	// stack array overflowed on large messages (audit C++C-3).
	ByteString sigBuf;
	unsigned char* sig = NULL;
	unsigned long long sig_len = 0;

	if (mechanism == (AsymMech::Type)1000) { // HSS
		struct hss_working_key* working_key = hss_load_private_key(
			NULL,
			(void*)privKeyBytes.byte_str(),
			0, // minimal memory target
			NULL, 0, NULL
		);
		if (!working_key) {
			session->resetOp();
			return CKR_FUNCTION_FAILED;
		}

		size_t exact_sig_len = hss_get_signature_len_from_working_key(working_key);

		// HSS does not append the message; buffer = exact signature length.
		sigBuf.resize(exact_sig_len);
		sig = &sigBuf[0];

		struct hss_extra_info hssInfo;
		hss_init_extra_info(&hssInfo);
		bool ok = hss_generate_signature(
			working_key,
			NULL, // update_private_key callback
			(void*)privKeyBytes.byte_str(), // context (memory to mutate)
			pData, ulDataLen,
			sig, sigBuf.size(), &hssInfo
		);
		sig_len = exact_sig_len;

		enum hss_error_code hssErr = hss_extra_info_test_error_code(&hssInfo);

		hss_free_working_key(working_key);

		if (!ok) {
			session->resetOp();
			// GAP 4.5: only report CKR_KEY_EXHAUSTED when the leaves are
			// genuinely used up; map all other backend failures (bad params,
			// RNG, NVRAM write, internal) to CKR_DEVICE_ERROR.
			if (hssErr == hss_error_private_key_expired ||
			    hssErr == hss_error_not_that_many_sigs_left)
				return CKR_KEY_EXHAUSTED;
			return CKR_DEVICE_ERROR;
		}
	} else if (mechanism == (AsymMech::Type)1001 || mechanism == (AsymMech::Type)1002) { // XMSS / XMSSMT
		// xmss_sign()/xmssmt_sign() return sm = [signature || message],
		// smlen = sig_bytes + msg_len. Derive sig_bytes from the OID embedded
		// in the (decrypted) private key so the buffer is exactly sized.
		if (privKeyBytes.size() < XMSS_OID_LEN) {
			session->resetOp();
			return CKR_GENERAL_ERROR;
		}
		uint32_t oid = 0;
		for (unsigned int i = 0; i < XMSS_OID_LEN; i++) {
			oid |= ((uint32_t)privKeyBytes.const_byte_str()[XMSS_OID_LEN - i - 1]) << (i * 8);
		}
		xmss_params params;
		int prv = (mechanism == (AsymMech::Type)1001)
		          ? xmss_parse_oid(&params, oid)
		          : xmssmt_parse_oid(&params, oid);
		if (prv != 0) {
			session->resetOp();
			return CKR_GENERAL_ERROR;
		}

		sigBuf.resize((size_t)params.sig_bytes + ulDataLen);
		sig = &sigBuf[0];

		int ret = (mechanism == (AsymMech::Type)1001)
		          ? xmss_sign(privKeyBytes.byte_str(), sig, &sig_len, pData, ulDataLen)
		          : xmssmt_sign(privKeyBytes.byte_str(), sig, &sig_len, pData, ulDataLen);
		if (ret != 0) {
			session->resetOp();
			// GAP 4.5: the xmss-reference core returns -2 specifically when all
			// one-time keys are used up; any other nonzero return is a genuine
			// processing/parameter error, not exhaustion.
			if (ret == -2)
				return CKR_KEY_EXHAUSTED;
			return CKR_DEVICE_ERROR;
		}
		// Per PKCS#11 v3.2, C_Sign returns only the signature portion.
		// Strip the appended message: sig_len = sig_bytes + ulDataLen.
		sig_len -= ulDataLen;
	} else {
		session->resetOp();
		return CKR_MECHANISM_INVALID;
	}

	if (pSignature == NULL_PTR) {
		*pulSignatureLen = sig_len;
		return CKR_OK;
	}

	if (*pulSignatureLen < sig_len) {
		// Buffer too small: do NOT commit the mutated state, so the leaf is
		// not burned (audit-confirmed burn-after-validation behaviour).
		*pulSignatureLen = sig_len;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Persist the updated private key state (CKA_VALUE with mutated leaf idx)
	// BEFORE releasing the signature. The stateful signers mutated
	// privKeyBytes in place; re-encrypt it for private keys.
	ByteString writeBack;
	if (isPrivate) {
		if (token == NULL || !token->encrypt(privKeyBytes, writeBack)) {
			session->resetOp();
			return CKR_DEVICE_ERROR;
		}
	} else {
		writeBack = privKeyBytes;
	}

	if (osObj->startTransaction()) {
		bool bOK = osObj->setAttribute(CKA_VALUE, writeBack);

		// Decrement the keys remaining counter
		const CK_ATTRIBUTE_TYPE ATTR_CKA_HSS_KEYS_REMAINING = 0x0000061cUL;
		if (osObj->attributeExists(ATTR_CKA_HSS_KEYS_REMAINING)) {
			CK_ULONG remainingSigs = osObj->getUnsignedLongValue(ATTR_CKA_HSS_KEYS_REMAINING, 0);
			if (remainingSigs > 0) {
				remainingSigs--;
				bOK = bOK && osObj->setAttribute(ATTR_CKA_HSS_KEYS_REMAINING, remainingSigs);
			}
		}

		if (!bOK || !osObj->commitTransaction()) {
			osObj->abortTransaction();
			session->resetOp();
			return CKR_DEVICE_ERROR;
		}
	} else {
		session->resetOp();
		return CKR_DEVICE_ERROR;
	}

	// State committed — now it is safe to release the signature to the caller.
	memcpy(pSignature, sig, sig_len);
	*pulSignatureLen = sig_len;

	session->resetOp();
	return CKR_OK;
}

// Sign the data in a single pass operation
CK_RV SoftHSM::C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	AsymMech::Type mechanism = session->getMechanism();
	if (mechanism == (AsymMech::Type)1000 || mechanism == (AsymMech::Type)1001 || mechanism == (AsymMech::Type)1002) {
		return StatefulSign(session, pData, ulDataLen, pSignature, pulSignatureLen);
	}

	if (session->getMacOp() != NULL)
		return MacSign(session, pData, ulDataLen,
			       pSignature, pulSignatureLen);
	else
		return AsymSign(session, pData, ulDataLen,
				pSignature, pulSignatureLen);
}

// MacAlgorithm version of C_SignUpdate
static CK_RV MacSignUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Sign the data
	if (!mac->signUpdate(part))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignUpdate
static CK_RV AsymSignUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	if (asymCrypto == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Sign the data
	if (!asymCrypto->signUpdate(part))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running signing operation with additional data
CK_RV SoftHSM::C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSignUpdate(session, pPart, ulPartLen);
	else
		return AsymSignUpdate(session, pPart, ulPartLen);
}

// MacAlgorithm version of C_SignFinal
static CK_RV MacSignFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString signature;
	if (!mac->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignFinal
static CK_RV AsymSignFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString signature;
	if (!asymCrypto->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	// Release only the sign half; a dual cipher partner (if any) survives.
	session->endOpFamily(SESSION_OP_SIGN);
	return CKR_OK;
}

// Finalise a running signing operation and return the signature
CK_RV SoftHSM::C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Accept a standalone sign op, or the (asymmetric) sign half of a §5.13
	// C_SignEncryptUpdate dual op whose cipher partner was finalised first
	// (op then lingers at SESSION_OP_ENCRYPT while asymmetricCryptoOp is live).
	bool dualSignSurvivor = (session->getOpType() == SESSION_OP_ENCRYPT && session->getAsymmetricCryptoOp() != NULL);
	if ((session->getOpType() != SESSION_OP_SIGN && !dualSignSurvivor) || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSignFinal(session, pSignature, pulSignatureLen);
	else
		return AsymSignFinal(session, pSignature, pulSignatureLen);
}

// Initialise a signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_SIGN_RECOVER, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Check if this mechanism is supported for SignRecover (only RSA and RSA_PKCS)
	if (pMechanism->mechanism != CKM_RSA_PKCS && pMechanism->mechanism != CKM_RSA_X_509)
	{
		return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

	PrivateKey* privateKey = asymCrypto->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_HOST_MEMORY;
	}

	if (getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key) != CKR_OK)
	{
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_GENERAL_ERROR;
	}

	AsymMech::Type mechanism = (pMechanism->mechanism == CKM_RSA_PKCS) ? AsymMech::RSA_PKCS : AsymMech::RSA;

	if (!asymCrypto->signInit(privateKey, mechanism, NULL, 0))
	{
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_SIGN_RECOVER);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setPrivateKey(privateKey);
	session->setMechanism(mechanism);
	session->setAllowSinglePartOp(true);
	session->setAllowMultiPartOp(false); // SignRecover is single-part only

	return CKR_OK;
}

// Perform a single part signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR || pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN_RECOVER || !session->getAllowSinglePartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString data(pData, ulDataLen);
	ByteString signature;
	if (!asymCrypto->sign(privateKey, data, signature, session->getMechanism(), NULL, 0))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// MacAlgorithm version of C_VerifyInit
CK_RV SoftHSM::MacVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_VERIFY lets a Verify init pair with an already-active Decrypt
	// op for C_DecryptVerifyUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_VERIFY, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_VERIFY);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Resolve mechanism → algorithm + key-type check via lookup table (H3).
	MacAlgo::Type algo = MacAlgo::Unknown;
	size_t minSize = 0;
	CK_RV mechRv = resolveMacMech(pMechanism->mechanism, keyType, algo, minSize);
	if (mechRv != CKR_OK) return mechRv;

	MacAlgorithm* mac = CryptoFactory::i()->getMacAlgorithm(algo);
	if (mac == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* pubkey = new SymmetricKey();

	if (getSymmetricKey(pubkey, token, key) != CKR_OK)
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_GENERAL_ERROR;
	}

	// Check key size
	pubkey->setBitLen(pubkey->getKeyBits().size() * 8);

	if (pubkey->getBitLen() < (minSize * 8))
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_KEY_SIZE_RANGE;
	}

	// Initialize verifying
	if (!mac->verifyInit(pubkey))
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_VERIFY);
	session->setMacOp(mac);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(pubkey);

	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyInit
CK_RV SoftHSM::AsymVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_VERIFY lets a Verify init pair with an already-active Decrypt
	// op for C_DecryptVerifyUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_VERIFY, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_VERIFY);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	void* param = NULL;
	size_t paramLen = 0;
	RSA_PKCS_PSS_PARAMS pssParam;
	MLDSA_SIGN_PARAMS mldsaSignParam;
	memset(&mldsaSignParam, 0, sizeof(mldsaSignParam));
	SLHDSA_SIGN_PARAMS slhdsaSignParam;
	memset(&slhdsaSignParam, 0, sizeof(slhdsaSignParam));
	bool bAllowMultiPartOp;
	bool isRSA = false;
#ifdef WITH_ECC
	bool isECDSA = false;
#endif
#ifdef WITH_EDDSA
	bool isEDDSA = false;
#endif
	bool isMLDSA = false;
	bool isSLHDSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = AsymMech::RSA_PKCS;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = AsymMech::RSA;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#ifndef WITH_FIPS
		case CKM_MD5_RSA_PKCS:
			mechanism = AsymMech::RSA_MD5_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA1_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA224_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA256_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA384_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA512_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_224_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA3_224_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_256_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA3_256_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_384_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA3_384_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_512_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA3_512_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_PKCS_PSS;

			unsigned long expectedMgf;
			switch(CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg) {
				case CKM_SHA_1:
					pssParam.hashAlg = HashAlgo::SHA1;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
					expectedMgf = CKG_MGF1_SHA1;
					break;
				case CKM_SHA224:
					pssParam.hashAlg = HashAlgo::SHA224;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
					expectedMgf = CKG_MGF1_SHA224;
					break;
				case CKM_SHA256:
					pssParam.hashAlg = HashAlgo::SHA256;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
					expectedMgf = CKG_MGF1_SHA256;
					break;
				case CKM_SHA384:
					pssParam.hashAlg = HashAlgo::SHA384;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
					expectedMgf = CKG_MGF1_SHA384;
					break;
				case CKM_SHA512:
					pssParam.hashAlg = HashAlgo::SHA512;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
					expectedMgf = CKG_MGF1_SHA512;
					break;
				default:
					return CKR_ARGUMENTS_BAD;
			}

			if (CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != expectedMgf) {
				return CKR_ARGUMENTS_BAD;
			}

			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA_1 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA1_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA1;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA224 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA224_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA224;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA256 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA256_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA256;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA384 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA384_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA384;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA512 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA512_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA512;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_224_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA3_224 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA3_224)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA3_224_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA3_224;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA3_224;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_256_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA3_256 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA3_256)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA3_256_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA3_256;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA3_256;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_384_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA3_384 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA3_384)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA3_384_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA3_384;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA3_384;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA3_512_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA3_512 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA3_512)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA3_512_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA3_512;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA3_512;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			if (pssParam.sLen > 512)
			{
				ERROR_MSG("RSA-PSS salt length exceeds maximum (512)");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_ECC
		case CKM_ECDSA:
			mechanism = AsymMech::ECDSA;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA1:
			mechanism = AsymMech::ECDSA_SHA1;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA224:
			mechanism = AsymMech::ECDSA_SHA224;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA256:
			mechanism = AsymMech::ECDSA_SHA256;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA384:
			mechanism = AsymMech::ECDSA_SHA384;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA512:
			mechanism = AsymMech::ECDSA_SHA512;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA3_224:
			mechanism = AsymMech::ECDSA_SHA3_224;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA3_256:
			mechanism = AsymMech::ECDSA_SHA3_256;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA3_384:
			mechanism = AsymMech::ECDSA_SHA3_384;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA3_512:
			mechanism = AsymMech::ECDSA_SHA3_512;
			bAllowMultiPartOp = true;
			isECDSA = true;
			break;
#endif
#ifdef WITH_EDDSA
		case CKM_EDDSA:
			mechanism = AsymMech::EDDSA;
			bAllowMultiPartOp = true;
			isEDDSA = true;
			break;
		case CKM_EDDSA_PH:
			mechanism = AsymMech::EDDSA_PH;
			bAllowMultiPartOp = true;
			isEDDSA = true;
			break;
#endif
		case CKM_ML_DSA:
		{
			mechanism = AsymMech::MLDSA;
			bAllowMultiPartOp = true;
			isMLDSA = true;
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			param = &mldsaSignParam;
			paramLen = sizeof(mldsaSignParam);
			break;
		}
		case CKM_HASH_ML_DSA:
		{
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
			{
				ERROR_MSG("CKM_HASH_ML_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::HASH_MLDSA;
			bAllowMultiPartOp = true;
			isMLDSA = true;
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			CK_HASH_SIGN_ADDITIONAL_CONTEXT* hctx =
				(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;
			switch (hctx->hash)
			{
				case CKM_SHA224:   mldsaSignParam.hashAlg = HashAlgo::SHA224;   break;
				case CKM_SHA256:   mldsaSignParam.hashAlg = HashAlgo::SHA256;   break;
				case CKM_SHA384:   mldsaSignParam.hashAlg = HashAlgo::SHA384;   break;
				case CKM_SHA512:   mldsaSignParam.hashAlg = HashAlgo::SHA512;   break;
				case CKM_SHA3_224: mldsaSignParam.hashAlg = HashAlgo::SHA3_224; break;
				case CKM_SHA3_256: mldsaSignParam.hashAlg = HashAlgo::SHA3_256; break;
				case CKM_SHA3_384: mldsaSignParam.hashAlg = HashAlgo::SHA3_384; break;
				case CKM_SHA3_512: mldsaSignParam.hashAlg = HashAlgo::SHA3_512; break;
				default:
					ERROR_MSG("Unsupported hash 0x%08lx for CKM_HASH_ML_DSA", hctx->hash);
					return CKR_ARGUMENTS_BAD;
			}
			param = &mldsaSignParam;
			paramLen = sizeof(mldsaSignParam);
			break;
		}
#define HASH_MLDSA_CASE(CKM_CONST, MECH_ENUM, HASH_ALGO) \
		case CKM_CONST: \
		{ \
			mechanism = AsymMech::MECH_ENUM; \
			bAllowMultiPartOp = true; \
			isMLDSA = true; \
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam); \
			if (rv2 != CKR_OK) return rv2; \
			mldsaSignParam.preHash = true; \
			mldsaSignParam.hashAlg = HashAlgo::HASH_ALGO; \
			param = &mldsaSignParam; \
			paramLen = sizeof(mldsaSignParam); \
			break; \
		}
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA224,  HASH_MLDSA_SHA224,  SHA224)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA256,  HASH_MLDSA_SHA256,  SHA256)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA384,  HASH_MLDSA_SHA384,  SHA384)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA512,  HASH_MLDSA_SHA512,  SHA512)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_224, HASH_MLDSA_SHA3_224, SHA3_224)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_256, HASH_MLDSA_SHA3_256, SHA3_256)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_384, HASH_MLDSA_SHA3_384, SHA3_384)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_512, HASH_MLDSA_SHA3_512, SHA3_512)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHAKE128, HASH_MLDSA_SHAKE128, SHAKE128)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHAKE256, HASH_MLDSA_SHAKE256, SHAKE256)
#undef HASH_MLDSA_CASE
		case CKM_SLH_DSA:
			// PKCS#11 v3.2: CKM_SLH_DSA accepts optional CK_SIGN_ADDITIONAL_CONTEXT
			// for context string (FIPS 205 §9.2) and deterministic mode (FIPS 205 §10).
			if (pMechanism->pParameter != NULL_PTR)
			{
				CK_RV rv2 = parseSLHDSASignContext(pMechanism, slhdsaSignParam);
				if (rv2 != CKR_OK) return rv2;
				param = &slhdsaSignParam;
				paramLen = sizeof(slhdsaSignParam);
			}
			mechanism = AsymMech::SLHDSA;
			bAllowMultiPartOp = true;
			isSLHDSA = true;
			break;
		case CKM_HASH_SLH_DSA:
		{
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
			{
				ERROR_MSG("CKM_HASH_SLH_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::HASH_SLHDSA;
			bAllowMultiPartOp = true;
			isSLHDSA = true;
			CK_RV rv2 = parseSLHDSASignContext(pMechanism, slhdsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			CK_HASH_SIGN_ADDITIONAL_CONTEXT* hctx =
				(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;
			switch (hctx->hash)
			{
				case CKM_SHA224:   slhdsaSignParam.hashAlg = HashAlgo::SHA224;   break;
				case CKM_SHA256:   slhdsaSignParam.hashAlg = HashAlgo::SHA256;   break;
				case CKM_SHA384:   slhdsaSignParam.hashAlg = HashAlgo::SHA384;   break;
				case CKM_SHA512:   slhdsaSignParam.hashAlg = HashAlgo::SHA512;   break;
				case CKM_SHA3_224: slhdsaSignParam.hashAlg = HashAlgo::SHA3_224; break;
				case CKM_SHA3_256: slhdsaSignParam.hashAlg = HashAlgo::SHA3_256; break;
				case CKM_SHA3_384: slhdsaSignParam.hashAlg = HashAlgo::SHA3_384; break;
				case CKM_SHA3_512: slhdsaSignParam.hashAlg = HashAlgo::SHA3_512; break;
				default:
					ERROR_MSG("Unsupported hash 0x%08lx for CKM_HASH_SLH_DSA",
					          hctx->hash);
					return CKR_ARGUMENTS_BAD;
			}
			param = &slhdsaSignParam;
			paramLen = sizeof(slhdsaSignParam);
			break;
		}
#define HASH_SLHDSA_CASE(CKM_CONST, MECH_ENUM, HASH_ALGO) \
		case CKM_CONST: \
		{ \
			mechanism = AsymMech::MECH_ENUM; \
			bAllowMultiPartOp = true; \
			isSLHDSA = true; \
			CK_RV rv2 = parseSLHDSASignContext(pMechanism, slhdsaSignParam); \
			if (rv2 != CKR_OK) return rv2; \
			slhdsaSignParam.preHash = true; \
			slhdsaSignParam.hashAlg = HashAlgo::HASH_ALGO; \
			param = &slhdsaSignParam; \
			paramLen = sizeof(slhdsaSignParam); \
			break; \
		}
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA224,   HASH_SLHDSA_SHA224,   SHA224)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA256,   HASH_SLHDSA_SHA256,   SHA256)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA384,   HASH_SLHDSA_SHA384,   SHA384)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA512,   HASH_SLHDSA_SHA512,   SHA512)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA3_224, HASH_SLHDSA_SHA3_224, SHA3_224)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA3_256, HASH_SLHDSA_SHA3_256, SHA3_256)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA3_384, HASH_SLHDSA_SHA3_384, SHA3_384)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHA3_512, HASH_SLHDSA_SHA3_512, SHA3_512)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHAKE128, HASH_SLHDSA_SHAKE128, SHAKE128)
		HASH_SLHDSA_CASE(CKM_HASH_SLH_DSA_SHAKE256, HASH_SLHDSA_SHAKE256, SHAKE256)
#undef HASH_SLHDSA_CASE
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Reject unexpected parameters for parameterless mechanisms
	if (param == NULL && pMechanism->pParameter != NULL_PTR)
	{
		ERROR_MSG("Mechanism does not accept parameters");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PublicKey* publicKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#ifdef WITH_ECC
	else if (isECDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getECPublicKey((ECPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
#ifdef WITH_EDDSA
	else if (isEDDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getEDPublicKey((EDPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	else if (isMLDSA)
	{
		if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_ML_DSA)
			return CKR_KEY_TYPE_INCONSISTENT;

		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getMLDSAPublicKey((MLDSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else if (isSLHDSA)
	{
		if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_SLH_DSA)
			return CKR_KEY_TYPE_INCONSISTENT;

		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getSLHDSAPublicKey((SLHDSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		// No recognized mechanism flag was set — the mechanism switch above
		// must return CKR_MECHANISM_INVALID before reaching here; this branch
		// is unreachable today, but assert defensively to prevent a NULL
		// dereference if a future mechanism case forgets to set a flag.
		return CKR_MECHANISM_INVALID;
	}

	// Initialize verifying
	if (bAllowMultiPartOp && !asymCrypto->verifyInit(publicKey,mechanism,param,paramLen))
	{
		asymCrypto->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	if (param != NULL && paramLen > 0 && !session->setParameters(param, paramLen))
	{
		asymCrypto->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_HOST_MEMORY;
	}

	session->setOpType(SESSION_OP_VERIFY);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(bAllowMultiPartOp);
	session->setAllowSinglePartOp(true);
	session->setPublicKey(publicKey);

	return CKR_OK;
}

// Stateful hash-based signature verification init (HSS/LMS/XMSS/XMSSMT)
// PKCS#11 v3.2 §6.14: CKM_HSS, CKM_XMSS, CKM_XMSSMT — C_VerifyInit + C_Verify
CK_RV SoftHSM::StatefulVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	// SESSION_OP_VERIFY lets a Verify init pair with an already-active Decrypt
	// op for C_DecryptVerifyUpdate (§5.13).
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_VERIFY, pMechanism,
	                                   sessionGuard, session, token, key, SESSION_OP_VERIFY);
	if (rv != CKR_OK) return rv;

	session->setOpType(SESSION_OP_VERIFY);

	AsymMech::Type mechanism = AsymMech::Unknown;
	if (pMechanism->mechanism == CKM_HSS) {
		mechanism = (AsymMech::Type)1000;
	} else if (pMechanism->mechanism == CKM_XMSS) {
		mechanism = (AsymMech::Type)1001;
	} else if (pMechanism->mechanism == CKM_XMSSMT) {
		mechanism = (AsymMech::Type)1002;
	} else {
		return CKR_MECHANISM_INVALID;
	}

	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setVerifyKeyHandle(hKey);

	return CKR_OK;
}

// Stateful hash-based signature verification (HSS/LMS/XMSS/XMSSMT)
// PKCS#11 v3.2 §6.14: verification is stateless — only needs public key + message + signature
CK_RV SoftHSM::StatefulVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!session->getAllowSinglePartOp()) {
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	CK_OBJECT_HANDLE hKey = session->getVerifyKeyHandle();
	OSObject* osObj = (OSObject*)handleManager->getObject(hKey, session->getSlot()->getSlotID());
	if (!osObj) {
		session->resetOp();
		return CKR_KEY_HANDLE_INVALID;
	}

	AsymMech::Type mechanism = session->getMechanism();
	ByteString pubKeyBytes = osObj->getByteStringValue(CKA_VALUE);

	// GAP 4.6: pre-check the signature length so a malformed length reports
	// CKR_SIGNATURE_LEN_RANGE (matching MacVerify / AsymVerify), not the
	// catch-all CKR_SIGNATURE_INVALID. An empty signature is always malformed.
	if (pSignature == NULL_PTR || ulSignatureLen == 0) {
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}
	if (mechanism == (AsymMech::Type)1001 || mechanism == (AsymMech::Type)1002) {
		// XMSS/XMSSMT signatures are fixed-length for the param set encoded in
		// the public key OID; any other length is out of range.
		if (pubKeyBytes.size() >= XMSS_OID_LEN) {
			uint32_t oid = 0;
			for (unsigned int i = 0; i < XMSS_OID_LEN; i++) {
				oid |= ((uint32_t)pubKeyBytes.const_byte_str()[XMSS_OID_LEN - i - 1]) << (i * 8);
			}
			xmss_params params;
			int prv = (mechanism == (AsymMech::Type)1001)
			          ? xmss_parse_oid(&params, oid)
			          : xmssmt_parse_oid(&params, oid);
			if (prv == 0 && ulSignatureLen != (CK_ULONG)params.sig_bytes) {
				session->resetOp();
				return CKR_SIGNATURE_LEN_RANGE;
			}
		}
	}

	bool verified = false;

	if (mechanism == (AsymMech::Type)1000) { // HSS / LMS
		verified = hss_validate_signature(
			pubKeyBytes.const_byte_str(),
			pData, ulDataLen,
			pSignature, ulSignatureLen,
			NULL
		);
	} else if (mechanism == (AsymMech::Type)1001) { // XMSS
		// xmss_sign_open expects sm = [signature || message] format
		// Reconstruct from separate sig + msg per PKCS#11 C_Verify interface
		unsigned long long smlen = ulSignatureLen + ulDataLen;
		std::vector<unsigned char> sm(smlen);
		memcpy(sm.data(), pSignature, ulSignatureLen);
		memcpy(sm.data() + ulSignatureLen, pData, ulDataLen);

		std::vector<unsigned char> m(smlen);
		unsigned long long mlen = 0;
		int ret = xmss_sign_open(m.data(), &mlen, sm.data(), smlen,
		                         pubKeyBytes.const_byte_str());
		verified = (ret == 0);
	} else if (mechanism == (AsymMech::Type)1002) { // XMSSMT
		unsigned long long smlen = ulSignatureLen + ulDataLen;
		std::vector<unsigned char> sm(smlen);
		memcpy(sm.data(), pSignature, ulSignatureLen);
		memcpy(sm.data() + ulSignatureLen, pData, ulDataLen);

		std::vector<unsigned char> m(smlen);
		unsigned long long mlen = 0;
		int ret = xmssmt_sign_open(m.data(), &mlen, sm.data(), smlen,
		                           pubKeyBytes.const_byte_str());
		verified = (ret == 0);
	} else {
		session->resetOp();
		return CKR_MECHANISM_INVALID;
	}

	session->resetOp();
	return verified ? CKR_OK : CKR_SIGNATURE_INVALID;
}

// Initialise a verification operation using the specified key and mechanism
CK_RV SoftHSM::C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	if (isMacMechanism(pMechanism))
		return MacVerifyInit(hSession, pMechanism, hKey);
	else if (pMechanism->mechanism == CKM_HSS ||
	         pMechanism->mechanism == CKM_XMSS || pMechanism->mechanism == CKM_XMSSMT)
		return StatefulVerifyInit(hSession, pMechanism, hKey);
	else
		return AsymVerifyInit(hSession, pMechanism, hKey);
}

// MacAlgorithm version of C_Verify
static CK_RV MacVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	// V-17: a one-shot C_Verify after C_VerifyUpdate must report CKR_OPERATION_ACTIVE
	// without destroying the multi-part op (the caller can still C_VerifyFinal).
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Size of the signature
	CK_ULONG size = mac->getMacSize();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Verify the data
	if (!mac->verifyUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the signature
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the signature
	if (!mac->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_Verify
static CK_RV AsymVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PublicKey* publicKey = session->getPublicKey();
	size_t paramLen;
	void* param = session->getParameters(paramLen);
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	// V-17: a one-shot C_Verify after C_VerifyUpdate must report CKR_OPERATION_ACTIVE
	// without destroying the multi-part op (the caller can still C_VerifyFinal).
	if (!session->getAllowSinglePartOp())
		return CKR_OPERATION_ACTIVE;

	// Size of the signature
	CK_ULONG size = publicKey->getOutputLength();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString data;

	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (mechanism == AsymMech::RSA) {
		if (ulDataLen > size)
		{
			session->resetOp();
			return CKR_DATA_LEN_RANGE;
		}
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (session->getAllowMultiPartOp())
	{
		if (!asymCrypto->verifyUpdate(data) ||
		    !asymCrypto->verifyFinal(signature))
		{
			session->resetOp();
			return CKR_SIGNATURE_INVALID;
		}
	}
	else if (!asymCrypto->verify(publicKey,data,signature,mechanism,param,paramLen))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// Perform a single pass verification operation
CK_RV SoftHSM::C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	AsymMech::Type mechanism = session->getMechanism();
	if (mechanism == (AsymMech::Type)1000 || mechanism == (AsymMech::Type)1001 || mechanism == (AsymMech::Type)1002) {
		return StatefulVerify(session, pData, ulDataLen, pSignature, ulSignatureLen);
	}

	if (session->getMacOp() != NULL)
		return MacVerify(session, pData, ulDataLen,
				 pSignature, ulSignatureLen);
	else
		return AsymVerify(session, pData, ulDataLen,
				  pSignature, ulSignatureLen);
}

// MacAlgorithm version of C_VerifyUpdate
static CK_RV MacVerifyUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Verify the data
	if (!mac->verifyUpdate(part))
	{
		// verifyUpdate can't fail for a logical reason, so we assume total breakdown.
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyUpdate
static CK_RV AsymVerifyUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	if (asymCrypto == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Verify the data
	if (!asymCrypto->verifyUpdate(part))
	{
		// verifyUpdate can't fail for a logical reason, so we assume total breakdown.
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running verification operation with additional data
CK_RV SoftHSM::C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerifyUpdate(session, pPart, ulPartLen);
	else
		return AsymVerifyUpdate(session, pPart, ulPartLen);
}

// MacAlgorithm version of C_SignFinal
static CK_RV MacVerifyFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the signature
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (!mac->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyFinal
static CK_RV AsymVerifyFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = publicKey->getOutputLength();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (!asymCrypto->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	// Release only the verify half; a dual decrypt partner (if any) survives.
	session->endOpFamily(SESSION_OP_VERIFY);
	return CKR_OK;
}

// Finalise the verification operation and check the signature
CK_RV SoftHSM::C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Accept a standalone verify op, or the (asymmetric) verify half of a §5.13
	// C_DecryptVerifyUpdate dual op whose decrypt partner was finalised first
	// (op then lingers at SESSION_OP_DECRYPT while asymmetricCryptoOp is live).
	bool dualVerifySurvivor = (session->getOpType() == SESSION_OP_DECRYPT && session->getAsymmetricCryptoOp() != NULL);
	if ((session->getOpType() != SESSION_OP_VERIFY && !dualVerifySurvivor) || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerifyFinal(session, pSignature, ulSignatureLen);
	else
		return AsymVerifyFinal(session, pSignature, ulSignatureLen);
}

// ── PKCS#11 v3.0/v3.2: message signing ───────────────────────────────────────────────────────

// applyPerMessageParam — shared helper for C_SignMessage / C_SignMessageBegin /
// C_SignMessageNext / C_VerifyMessage / C_VerifyMessageBegin / C_VerifyMessageNext.
// Merges a per-message CK_SIGN_ADDITIONAL_CONTEXT or CK_HASH_SIGN_ADDITIONAL_CONTEXT
// into the session's existing ML-DSA or SLH-DSA parameters while preserving the
// preHash / hashAlg values baked in at C_MessageSignInit / C_MessageVerifyInit time.
// Returns CKR_OK immediately if pParameter is NULL or ulParameterLen is 0.
static CK_RV applyPerMessageParam(Session* session,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	if (pParameter == NULL_PTR || ulParameterLen == 0)
		return CKR_OK;

	AsymMech::Type mech = session->getMechanism();

	if (mech >= AsymMech::MLDSA && mech <= AsymMech::HASH_MLDSA_SHAKE256)
	{
		size_t existingLen;
		void* existing = session->getParameters(existingLen);

		MLDSA_SIGN_PARAMS mldsaParam;
		CK_MECHANISM fakeMech;
		fakeMech.mechanism = CKM_ML_DSA;
		fakeMech.pParameter = pParameter;
		fakeMech.ulParameterLen = ulParameterLen;
		CK_RV rv2 = parseMLDSASignContext(&fakeMech, mldsaParam);
		if (rv2 != CKR_OK) return rv2;

		// Preserve preHash / hashAlg set by the init mechanism
		if (existing && existingLen == sizeof(MLDSA_SIGN_PARAMS))
		{
			MLDSA_SIGN_PARAMS* initParams = (MLDSA_SIGN_PARAMS*)existing;
			mldsaParam.preHash = initParams->preHash;
			mldsaParam.hashAlg = initParams->hashAlg;
		}
		if (!session->setParameters(&mldsaParam, sizeof(mldsaParam)))
			return CKR_HOST_MEMORY;
	}
	else if (mech >= AsymMech::SLHDSA && mech <= AsymMech::HASH_SLHDSA_SHAKE256)
	{
		size_t existingLen;
		void* existing = session->getParameters(existingLen);

		SLHDSA_SIGN_PARAMS slhdsaParam;
		CK_MECHANISM fakeMech;
		fakeMech.mechanism = CKM_SLH_DSA;
		fakeMech.pParameter = pParameter;
		fakeMech.ulParameterLen = ulParameterLen;
		CK_RV rv2 = parseSLHDSASignContext(&fakeMech, slhdsaParam);
		if (rv2 != CKR_OK) return rv2;

		// Preserve preHash / hashAlg set by the init mechanism
		if (existing && existingLen == sizeof(SLHDSA_SIGN_PARAMS))
		{
			SLHDSA_SIGN_PARAMS* initParams = (SLHDSA_SIGN_PARAMS*)existing;
			slhdsaParam.preHash = initParams->preHash;
			slhdsaParam.hashAlg = initParams->hashAlg;
		}
		if (!session->setParameters(&slhdsaParam, sizeof(slhdsaParam)))
			return CKR_HOST_MEMORY;
	}
	return CKR_OK;
}

// C_MessageSignInit — initialise a multi-message sign context (PKCS#11 v3.0 §5.8.1)
CK_RV SoftHSM::C_MessageSignInit(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	// Reuse existing asymmetric-sign init; it validates the key, mechanism, and session
	CK_RV rv = AsymSignInit(hSession, pMechanism, hKey);
	if (rv != CKR_OK) return rv;

	// Upgrade op type so C_Sign cannot be called against this context
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	session->setOpType(SESSION_OP_MESSAGE_SIGN);
	return CKR_OK;
}

// C_SignMessage — one-shot message sign (PKCS#11 v3.0 §5.8.2)
// pParameter / ulParameterLen are mechanism-specific; NULL/0 for ML-DSA and SLH-DSA.
CK_RV SoftHSM::C_SignMessage(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	// Per-message parameter override (PKCS#11 v3.2 §5.8.5) — ML-DSA and SLH-DSA context / hedging
	{ CK_RV rv2 = applyPerMessageParam(session, pParameter, ulParameterLen); if (rv2 != CKR_OK) return rv2; }

	// Snapshot mechanism params — AsymSign calls resetOp() which frees them.
	// C_SignMessage is invoked twice per message in the two-pass (size-query then
	// real-sign) pattern; params (context string, deterministic flag) must survive
	// both calls so each message is signed with the same context as the init call.
	size_t snapLen = 0;
	void* snapBase = session->getParameters(snapLen);
	void* snap = NULL;
	if (snapBase && snapLen > 0)
	{
		snap = malloc(snapLen);
		if (!snap) return CKR_HOST_MEMORY;
		memcpy(snap, snapBase, snapLen);
	}

	// AsymSign expects SESSION_OP_SIGN; temporarily satisfy that check.
	// AsymSign calls resetOp() before returning (both size-query and real sign),
	// so we must unconditionally restore MESSAGE_SIGN on success to keep the
	// multi-message contract (caller may send further messages under this session).
	session->setOpType(SESSION_OP_SIGN);
	CK_RV rv = AsymSign(session, pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK)
	{
		session->setOpType(SESSION_OP_MESSAGE_SIGN);
		if (snap) session->setParameters(snap, snapLen);
	}
	if (snap) free(snap);
	return rv;
}

// C_MessageSignFinal — end a multi-message sign context (PKCS#11 v3.0 §5.8.6)
CK_RV SoftHSM::C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;
	session->resetOp();
	return CKR_OK;
}

// C_MessageVerifyInit — initialise a multi-message verify context (PKCS#11 v3.0 §5.8.7)
CK_RV SoftHSM::C_MessageVerifyInit(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = AsymVerifyInit(hSession, pMechanism, hKey);
	if (rv != CKR_OK) return rv;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	session->setOpType(SESSION_OP_MESSAGE_VERIFY);
	return CKR_OK;
}

// C_VerifyMessage — one-shot message verify (PKCS#11 v3.2 §5.8.8)
// pParameter / ulParameterLen allow per-message ML-DSA parameter override.
CK_RV SoftHSM::C_VerifyMessage(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	// Per-message parameter override (PKCS#11 v3.2 §5.8.8) — ML-DSA and SLH-DSA context / hedging
	{ CK_RV rv2 = applyPerMessageParam(session, pParameter, ulParameterLen); if (rv2 != CKR_OK) return rv2; }

	// Snapshot mechanism params — AsymVerify calls resetOp() which frees them.
	// Restore after each call so subsequent messages verify with the same context.
	size_t snapLen = 0;
	void* snapBase = session->getParameters(snapLen);
	void* snap = NULL;
	if (snapBase && snapLen > 0)
	{
		snap = malloc(snapLen);
		if (!snap) return CKR_HOST_MEMORY;
		memcpy(snap, snapBase, snapLen);
	}

	// AsymVerify expects SESSION_OP_VERIFY; temporarily satisfy that check.
	// AsymVerify calls resetOp() before returning, so restore MESSAGE_VERIFY on
	// success to maintain the multi-message contract.
	session->setOpType(SESSION_OP_VERIFY);
	CK_RV rv = AsymVerify(session, pData, ulDataLen, pSignature, ulSignatureLen);
	if (rv == CKR_OK)
	{
		session->setOpType(SESSION_OP_MESSAGE_VERIFY);
		if (snap) session->setParameters(snap, snapLen);
	}
	if (snap) free(snap);
	return rv;
}

// C_MessageVerifyFinal — end a multi-message verify context (PKCS#11 v3.0 §5.8.12)
CK_RV SoftHSM::C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;
	session->resetOp();
	return CKR_OK;
}

// ── PKCS#11 v3.2: streaming message signing (commit-then-sign) ───────────────────────────────
//
// State machine for C_SignMessageBegin / C_SignMessageNext:
//
//   C_MessageSignInit()       → SESSION_OP_MESSAGE_SIGN (0x11)
//     C_SignMessageBegin()    → stores per-message param → SESSION_OP_MESSAGE_SIGN_BEGIN (0x13)
//       C_SignMessageNext(NULL)   → size query, stays in MESSAGE_SIGN_BEGIN
//       C_SignMessageNext(buf)    → sign, → back to MESSAGE_SIGN (0x11)
//     C_SignMessage() / repeat
//   C_MessageSignFinal()      → SESSION_OP_NONE
//
// The verify side is symmetric (0x12 / 0x14).

// C_SignMessageBegin — commit per-message parameters before streaming sign (PKCS#11 v3.2 §5.8.3)
CK_RV SoftHSM::C_SignMessageBegin(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	// Merge per-message pParameter (context string, hedging) into session params.
	// preHash / hashAlg from init time are always preserved by applyPerMessageParam.
	CK_RV rv = applyPerMessageParam(session, pParameter, ulParameterLen);
	if (rv != CKR_OK) return rv;

	session->setOpType(SESSION_OP_MESSAGE_SIGN_BEGIN);
	return CKR_OK;
}

// C_SignMessageNext — perform (or size-query) one message sign (PKCS#11 v3.2 §5.8.4)
// pSignature == NULL_PTR → size query; session stays in MESSAGE_SIGN_BEGIN.
// pSignature != NULL_PTR → actual sign; session returns to MESSAGE_SIGN on success.
CK_RV SoftHSM::C_SignMessageNext(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pData == NULL_PTR || pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_SIGN_BEGIN)
		return CKR_OPERATION_NOT_INITIALIZED;

	// pParameter in Next overrides Begin's committed params (spec §5.8.4: may be NULL)
	CK_RV rv = applyPerMessageParam(session, pParameter, ulParameterLen);
	if (rv != CKR_OK) return rv;

	// AsymSign requires SESSION_OP_SIGN; satisfy temporarily then restore.
	// Size-query path (pSignature==NULL): AsymSign does not call resetOp, so session
	// crypto objects survive — stay in BEGIN to allow a subsequent real-sign call.
	// Real sign path (pSignature!=NULL): AsymSign calls resetOp, restore MESSAGE_SIGN
	// so the caller may begin another message under the same session.
	// CKR_BUFFER_TOO_SMALL path: AsymSign does NOT call resetOp (crypto context
	// survives for retry); restore MESSAGE_SIGN_BEGIN so caller can retry with a
	// correctly-sized buffer.  All other errors: AsymSign called resetOp, leaving
	// SESSION_OP_NONE — the multi-message context is terminated per spec.
	session->setOpType(SESSION_OP_SIGN);
	rv = AsymSign(session, pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK)
	{
		if (pSignature != NULL_PTR)
			session->setOpType(SESSION_OP_MESSAGE_SIGN);        // message complete
		else
			session->setOpType(SESSION_OP_MESSAGE_SIGN_BEGIN);  // size query, stay
	}
	else if (rv == CKR_BUFFER_TOO_SMALL)
	{
		session->setOpType(SESSION_OP_MESSAGE_SIGN_BEGIN);      // restore for retry
	}
	return rv;
}

// C_VerifyMessageBegin — commit per-message parameters before streaming verify (PKCS#11 v3.2 §5.8.9)
CK_RV SoftHSM::C_VerifyMessageBegin(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	CK_RV rv = applyPerMessageParam(session, pParameter, ulParameterLen);
	if (rv != CKR_OK) return rv;

	session->setOpType(SESSION_OP_MESSAGE_VERIFY_BEGIN);
	return CKR_OK;
}

// C_VerifyMessageNext — perform one message verify (PKCS#11 v3.2 §5.8.10)
// Verification always requires a signature buffer; no size-query path.
// On success the session returns to MESSAGE_VERIFY.
CK_RV SoftHSM::C_VerifyMessageNext(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pData == NULL_PTR || pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_VERIFY_BEGIN)
		return CKR_OPERATION_NOT_INITIALIZED;

	CK_RV rv = applyPerMessageParam(session, pParameter, ulParameterLen);
	if (rv != CKR_OK) return rv;

	// AsymVerify requires SESSION_OP_VERIFY; satisfy temporarily then restore.
	session->setOpType(SESSION_OP_VERIFY);
	rv = AsymVerify(session, pData, ulDataLen, pSignature, ulSignatureLen);
	if (rv == CKR_OK)
		session->setOpType(SESSION_OP_MESSAGE_VERIFY);
	return rv;
}

// ─────────────────────────────────────────────────────────────────────────────
// G4: PKCS#11 v3.2 pre-bound signature verification
//
// The signature is bound at init time so that subsequent data calls carry no
// signature argument.  This is useful for streaming protocols where the
// signature is received before the data (e.g. signed HTTP responses).
//
// Session state machine:
//   C_VerifySignatureInit(sig) → SESSION_OP_VERIFY_SIGNATURE (0x19)
//     C_VerifySignature(data)  → 0x0  (one-shot; single-part only)
//     C_VerifySignatureUpdate(part) + C_VerifySignatureFinal() → 0x0  (multi-part)
// ─────────────────────────────────────────────────────────────────────────────

// Combined heap blob layout stored in session->param by C_VerifySignatureInit:
//   [ PreBoundVerifySig header | signature bytes | algo-param bytes ]
struct PreBoundVerifySig {
	CK_ULONG sigLen;       // length of signature bytes that follow the header
	CK_ULONG algoParamLen; // length of algo-specific params (may be 0)
};

// C_VerifySignatureInit — bind a signature to the session before receiving data
CK_RV SoftHSM::C_VerifySignatureInit(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pSignature == NULL_PTR || ulSignatureLen == 0) return CKR_ARGUMENTS_BAD;

	// Reuse AsymVerifyInit to validate the mechanism, load the public key, and
	// start any multi-part verifier (for mechanisms where bAllowMultiPartOp is
	// true).  It also stores algo-specific params (ML-DSA / SLH-DSA context)
	// in session->param.
	CK_RV rv = AsymVerifyInit(hSession, pMechanism, hKey);
	if (rv != CKR_OK) return rv;

	// Re-acquire the session to read the algo params left by AsymVerifyInit and
	// to overwrite session->param with the combined pre-bound blob.
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	size_t algoParamLen = 0;
	void* algoParam = session->getParameters(algoParamLen);

	// Build the combined blob: header + signature + algo params.
	// Guard against wrap-around on 32-bit targets (e.g. Emscripten WASM where
	// CK_ULONG and size_t are both 32-bit).
	if (ulSignatureLen > SIZE_MAX - sizeof(PreBoundVerifySig) - algoParamLen)
	{
		session->resetOp();
		return CKR_ARGUMENTS_BAD;
	}
	size_t totalLen = sizeof(PreBoundVerifySig) + ulSignatureLen + algoParamLen;
	std::vector<uint8_t> blob(totalLen);
	PreBoundVerifySig* hdr = reinterpret_cast<PreBoundVerifySig*>(blob.data());
	hdr->sigLen      = ulSignatureLen;
	hdr->algoParamLen = static_cast<CK_ULONG>(algoParamLen);
	memcpy(blob.data() + sizeof(PreBoundVerifySig), pSignature, ulSignatureLen);
	if (algoParamLen > 0)
		memcpy(blob.data() + sizeof(PreBoundVerifySig) + ulSignatureLen, algoParam, algoParamLen);

	if (!session->setParameters(blob.data(), totalLen))
	{
		session->resetOp();
		return CKR_HOST_MEMORY;
	}

	// Enable both single-part (C_VerifySignature) and multi-part
	// (C_VerifySignatureUpdate + C_VerifySignatureFinal) paths.
	// AsymVerifyInit leaves allowMultiPartOp=false for ML-DSA/SLH-DSA (they are
	// single-part-only in the standard verifyUpdate/verifyFinal sense), but G4
	// multi-part accumulates data in session->msgBuffer and calls the one-shot
	// verify at Final time, so both flags must be true here.
	session->clearMsgBuffer();
	session->setAllowMultiPartOp(true);
	session->setOpType(SESSION_OP_VERIFY_SIGNATURE);
	return CKR_OK;
}

// C_VerifySignature — single-part verify against the pre-bound signature
CK_RV SoftHSM::C_VerifySignature(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_VERIFY_SIGNATURE || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Extract pre-bound signature and algo params from the combined blob.
	size_t blobLen = 0;
	void* blobPtr  = session->getParameters(blobLen);
	if (blobPtr == NULL || blobLen < sizeof(PreBoundVerifySig))
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	PreBoundVerifySig* hdr = reinterpret_cast<PreBoundVerifySig*>(blobPtr);
	// Overflow-safe secondary bounds check (guards 32-bit/WASM targets where
	// CK_ULONG addition can wrap to a value smaller than the individual operands).
	if (hdr->sigLen > blobLen - sizeof(PreBoundVerifySig) ||
	    hdr->algoParamLen > blobLen - sizeof(PreBoundVerifySig) - hdr->sigLen)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	CK_BYTE_PTR sigBytes = reinterpret_cast<CK_BYTE_PTR>(
		reinterpret_cast<uint8_t*>(blobPtr) + sizeof(PreBoundVerifySig));
	void* algoParam = (hdr->algoParamLen > 0) ?
		reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(blobPtr) + sizeof(PreBoundVerifySig) + hdr->sigLen) :
		NULL;

	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism        = session->getMechanism();
	PublicKey* publicKey            = session->getPublicKey();
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	ByteString data(pData, ulDataLen);
	ByteString signature(sigBytes, hdr->sigLen);
	bool ok = asymCrypto->verify(publicKey, data, signature, mechanism,
	                              algoParam, hdr->algoParamLen);
	session->resetOp();
	return ok ? CKR_OK : CKR_SIGNATURE_INVALID;
}

// C_VerifySignatureUpdate — accumulate data for multi-part pre-bound verify
CK_RV SoftHSM::C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pPart == NULL_PTR && ulPartLen != 0) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_VERIFY_SIGNATURE || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Accumulate data — the actual verify happens at C_VerifySignatureFinal using
	// the one-shot AsymmetricAlgorithm::verify() call, which works for all PQC
	// mechanisms (ML-DSA, SLH-DSA) without requiring a functional verifyFinal().
	session->appendToMsgBuffer(pPart, ulPartLen);
	return CKR_OK;
}

// C_VerifySignatureFinal — finalise multi-part pre-bound verify
CK_RV SoftHSM::C_VerifySignatureFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_VERIFY_SIGNATURE || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	size_t blobLen = 0;
	void* blobPtr  = session->getParameters(blobLen);
	if (blobPtr == NULL || blobLen < sizeof(PreBoundVerifySig))
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	PreBoundVerifySig* hdr = reinterpret_cast<PreBoundVerifySig*>(blobPtr);
	// Overflow-safe bounds check (mirrors C_VerifySignature).
	if (hdr->sigLen > blobLen - sizeof(PreBoundVerifySig) ||
	    hdr->algoParamLen > blobLen - sizeof(PreBoundVerifySig) - hdr->sigLen)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	CK_BYTE_PTR sigBytes = reinterpret_cast<CK_BYTE_PTR>(
		reinterpret_cast<uint8_t*>(blobPtr) + sizeof(PreBoundVerifySig));
	void* algoParam = (hdr->algoParamLen > 0) ?
		reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(blobPtr) + sizeof(PreBoundVerifySig) + hdr->sigLen) :
		NULL;

	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism        = session->getMechanism();
	PublicKey* publicKey            = session->getPublicKey();
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Use the one-shot verify with the accumulated message — this works for all
	// PQC mechanisms (ML-DSA, SLH-DSA) without requiring verifyFinal() to be
	// implemented.  The accumulated message was built by C_VerifySignatureUpdate.
	ByteString msg(session->getMsgBuffer());
	ByteString signature(sigBytes, hdr->sigLen);
	bool ok = asymCrypto->verify(publicKey, msg, signature, mechanism,
	                             algoParam, hdr->algoParamLen);
	session->resetOp();  // also clears msgBuffer
	return ok ? CKR_OK : CKR_SIGNATURE_INVALID;
}

// ─────────────────────────────────────────────────────────────────────────────

// Initialise a verification operation the allows recovery of the signed data from the signature
CK_RV SoftHSM::C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_VERIFY_RECOVER, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Check if this mechanism is supported
	if (pMechanism->mechanism != CKM_RSA_PKCS && pMechanism->mechanism != CKM_RSA_X_509)
	{
		return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

	PublicKey* publicKey = asymCrypto->newPublicKey();
	if (publicKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_HOST_MEMORY;
	}

	if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
	{
		asymCrypto->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_GENERAL_ERROR;
	}

	AsymMech::Type mechanism = (pMechanism->mechanism == CKM_RSA_PKCS) ? AsymMech::RSA_PKCS : AsymMech::RSA;

	if (!asymCrypto->verifyInit(publicKey, mechanism, NULL, 0))
	{
		asymCrypto->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_VERIFY_RECOVER);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setPublicKey(publicKey);
	session->setMechanism(mechanism);
	session->setAllowSinglePartOp(true);
	session->setAllowMultiPartOp(false); // VerifyRecover is single-part only

	return CKR_OK;
}

// Perform a single part verification operation and recover the signed data
CK_RV SoftHSM::C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pSignature == NULL_PTR || pulDataLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY_RECOVER || !session->getAllowSinglePartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the data output
	CK_ULONG size = publicKey->getOutputLength();
	if (pData == NULL_PTR)
	{
		*pulDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < size)
	{
		*pulDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Verify and recover the data
	ByteString signature(pSignature, ulSignatureLen);
	ByteString data;
	if (!asymCrypto->verifyRecover(publicKey, signature, data, session->getMechanism(), NULL, 0))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	// Copy to buffer
	memcpy(pData, data.const_byte_str(), data.size());
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;
}

/*

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// CKM_RSA_X_509 recovery is not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}
*/

// ───────────────────────────────────────────────────────────────────────────
// §5.13 dual-function cryptographic operations.
//
// Each runs two independent session contexts in lockstep on the same buffer:
// the symmetric-cipher context (symmetricCryptoOp) plus a digest, sign or
// verify context. The two were set up by two successive C_*Init calls, which
// coexist because acquireSession()/isComplementaryDualOp() relaxes the
// single-op CKR_OPERATION_ACTIVE guard for these pairings, and resetOp() now
// releases every live context independently.
//
// The cipher output honours the standard two-call convention (NULL out → size;
// short buffer → CKR_BUFFER_TOO_SMALL with the op left intact). The companion
// digest/sign/verify state is advanced ONLY on the data-producing call, so a
// preceding size query does not double-feed it.
// ───────────────────────────────────────────────────────────────────────────

// Update a running multi-part encryption and digesting operation.
// Requires an active C_DigestInit AND C_EncryptInit (symmetric cipher).
CK_RV SoftHSM::C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR || pulEncryptedPartLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Both halves must be initialised: a digest op and a symmetric encrypt op.
	HashAlgorithm* digest = session->getDigestOp();
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (digest == NULL || cipher == NULL) return CKR_OPERATION_NOT_INITIALIZED;

	// Encrypt half (handles the two-call convention; leaves the op intact on a
	// size query or short buffer).
	CK_RV rv = symEncryptUpdateRaw(session, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv != CKR_OK) return rv;
	if (pEncryptedPart == NULL_PTR) return CKR_OK;  // size query — digest untouched

	// Digest half: feed the plaintext exactly once, now that ciphertext is produced.
	ByteString data(pPart, ulPartLen);
	if (!digest->hashUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running multi-part decryption and digesting operation.
// Requires an active C_DecryptInit (symmetric cipher) AND C_DigestInit.
CK_RV SoftHSM::C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pEncryptedPart == NULL_PTR || pulDecryptedPartLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	HashAlgorithm* digest = session->getDigestOp();
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (digest == NULL || cipher == NULL) return CKR_OPERATION_NOT_INITIALIZED;

	// Decrypt half (two-call convention preserved).
	CK_RV rv = symDecryptUpdateRaw(session, pEncryptedPart, ulEncryptedPartLen, pDecryptedPart, pulDecryptedPartLen);
	if (rv != CKR_OK) return rv;
	if (pDecryptedPart == NULL_PTR) return CKR_OK;  // size query — digest untouched

	// Digest half: feed the recovered plaintext exactly once.
	ByteString plain(pDecryptedPart, *pulDecryptedPartLen);
	if (!digest->hashUpdate(plain))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running multi-part signing and encryption operation.
// Requires an active C_SignInit AND C_EncryptInit (symmetric cipher).
// The sign half must be an asymmetric signer; an HMAC signer and a symmetric
// cipher both claim the session's single symmetric-key slot, so that
// combination is rejected as uninitialised.
CK_RV SoftHSM::C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR || pulEncryptedPartLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	AsymmetricAlgorithm* asymSign = session->getAsymmetricCryptoOp();
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (asymSign == NULL || cipher == NULL || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	// Re-authentication (CKA_ALWAYS_AUTHENTICATE) must be honoured before
	// feeding more data to the signer, mirroring AsymSignUpdate.
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Encrypt half (two-call convention preserved).
	CK_RV rv = symEncryptUpdateRaw(session, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv != CKR_OK) return rv;
	if (pEncryptedPart == NULL_PTR) return CKR_OK;  // size query - signer untouched

	// Sign half: feed the plaintext exactly once.
	ByteString data(pPart, ulPartLen);
	if (!asymSign->signUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running multi-part decryption and verification operation.
// Requires an active C_DecryptInit (symmetric cipher) AND C_VerifyInit.
// The verify half must be an asymmetric verifier (see C_SignEncryptUpdate for
// the HMAC key-slot collision rationale).
CK_RV SoftHSM::C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pEncryptedPart == NULL_PTR || pulPartLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	AsymmetricAlgorithm* asymVerify = session->getAsymmetricCryptoOp();
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (asymVerify == NULL || cipher == NULL || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	// Decrypt half (two-call convention preserved).
	CK_RV rv = symDecryptUpdateRaw(session, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	if (rv != CKR_OK) return rv;
	if (pPart == NULL_PTR) return CKR_OK;  // size query - verifier untouched

	// Verify half: feed the recovered plaintext exactly once.
	ByteString plain(pPart, *pulPartLen);
	if (!asymVerify->verifyUpdate(plain))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	session->setAllowSinglePartOp(false);
	return CKR_OK;
}


