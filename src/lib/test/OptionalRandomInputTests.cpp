/*****************************************************************************
 OptionalRandomInputTests.cpp

 Optional caller-supplied randomness (vendor_mechanisms.h; acvp-explicit-
 randomness-model plan, P2 + P4, owner decisions S1/S3/D0-D4), C++ engine.

 Vectors (tests/acvp/, byte-copied subsets of NIST ACVP-Server @975de31e,
 provenance in each file's _provenance block):
   mlkem_encap_aft_test.json              ML-KEM encapsulation AFT, m given
   mldsa_siggen_optional_input_test.json  ML-DSA sigGen: hedged (rnd) and
                                          internal-interface groups
   mldsa_sigver_internal_test.json        ML-DSA sigVer, internal interface
   slhdsa_siggen_optional_input_test.json SLH-DSA sigGen: hedged (addrnd)
                                          and internal-interface groups
   slhdsa_sigver_internal_test.json       SLH-DSA sigVer, internal interface
 Together they hold every in-scope NIST group (81 groups; plan revision 9).
 With ACVP_OPTIONAL_INPUT_FULL_DIR pointing at the five upstream
 internalProjection files (named <ACVP-Server dir>.json, e.g.
 ML-DSA-sigGen-FIPS204.json), testFullNistSetWhenProvided runs all 909
 in-scope cases; cases whose hashAlg has no PKCS#11 mechanism (SHA2-512/224,
 SHA2-512/256: a separate, out-of-scope gap) are counted and reported.

 Routes (owner decision 22 Oct 2026, "Use the standard route"):
   ML-DSA internal deterministic sigGen and internal sigVer run through the
   standard CKM_ML_DSA_EXTERNAL_MU, µ = SHAKE256(SHAKE256(pk, 64) || M', 64);
   hedged internal through CKM_ML_DSA + messageEncoding internal + rnd;
   hedged external-µ through CKM_ML_DSA_EXTERNAL_MU + rnd;
   SLH-DSA internal through messageEncoding internal.
 *****************************************************************************/

#include <config.h>
#include "OptionalRandomInputTests.h"
#include "AcvpKatUtil.h"
#include "vendor_mechanisms.h"
#include <openssl/evp.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <unistd.h>

CPPUNIT_TEST_SUITE_REGISTRATION(OptionalRandomInputTests);

namespace {

typedef std::vector<unsigned char> Bytes;
const CK_MECHANISM_TYPE UNMAPPED = (CK_MECHANISM_TYPE)-1;

CK_ULONG mldsaSet(const std::string& n)
{
	if (n == "ML-DSA-44") return CKP_ML_DSA_44;
	if (n == "ML-DSA-65") return CKP_ML_DSA_65;
	if (n == "ML-DSA-87") return CKP_ML_DSA_87;
	return (CK_ULONG)-1;
}

CK_ULONG mlkemSet(const std::string& n)
{
	if (n == "ML-KEM-512") return CKP_ML_KEM_512;
	if (n == "ML-KEM-768") return CKP_ML_KEM_768;
	if (n == "ML-KEM-1024") return CKP_ML_KEM_1024;
	return (CK_ULONG)-1;
}

CK_ULONG slhSet(const std::string& n)
{
	static const std::map<std::string, CK_ULONG> m = {
		{ "SLH-DSA-SHA2-128s",  CKP_SLH_DSA_SHA2_128S  }, { "SLH-DSA-SHAKE-128s", CKP_SLH_DSA_SHAKE_128S },
		{ "SLH-DSA-SHA2-128f",  CKP_SLH_DSA_SHA2_128F  }, { "SLH-DSA-SHAKE-128f", CKP_SLH_DSA_SHAKE_128F },
		{ "SLH-DSA-SHA2-192s",  CKP_SLH_DSA_SHA2_192S  }, { "SLH-DSA-SHAKE-192s", CKP_SLH_DSA_SHAKE_192S },
		{ "SLH-DSA-SHA2-192f",  CKP_SLH_DSA_SHA2_192F  }, { "SLH-DSA-SHAKE-192f", CKP_SLH_DSA_SHAKE_192F },
		{ "SLH-DSA-SHA2-256s",  CKP_SLH_DSA_SHA2_256S  }, { "SLH-DSA-SHAKE-256s", CKP_SLH_DSA_SHAKE_256S },
		{ "SLH-DSA-SHA2-256f",  CKP_SLH_DSA_SHA2_256F  }, { "SLH-DSA-SHAKE-256f", CKP_SLH_DSA_SHAKE_256F },
	};
	auto it = m.find(n);
	return it == m.end() ? (CK_ULONG)-1 : it->second;
}

// ACVP hashAlg -> PKCS#11 v3.2 hash-specific pre-hash mechanism, or UNMAPPED
// (SHA2-512/224 and SHA2-512/256 have none).
CK_MECHANISM_TYPE preHashMech(bool mldsa, const std::string& h)
{
	static const std::map<std::string, std::pair<CK_MECHANISM_TYPE, CK_MECHANISM_TYPE> > m = {
		{ "SHA2-224",  { CKM_HASH_ML_DSA_SHA224,   CKM_HASH_SLH_DSA_SHA224 } },
		{ "SHA2-256",  { CKM_HASH_ML_DSA_SHA256,   CKM_HASH_SLH_DSA_SHA256 } },
		{ "SHA2-384",  { CKM_HASH_ML_DSA_SHA384,   CKM_HASH_SLH_DSA_SHA384 } },
		{ "SHA2-512",  { CKM_HASH_ML_DSA_SHA512,   CKM_HASH_SLH_DSA_SHA512 } },
		{ "SHA3-224",  { CKM_HASH_ML_DSA_SHA3_224, CKM_HASH_SLH_DSA_SHA3_224 } },
		{ "SHA3-256",  { CKM_HASH_ML_DSA_SHA3_256, CKM_HASH_SLH_DSA_SHA3_256 } },
		{ "SHA3-384",  { CKM_HASH_ML_DSA_SHA3_384, CKM_HASH_SLH_DSA_SHA3_384 } },
		{ "SHA3-512",  { CKM_HASH_ML_DSA_SHA3_512, CKM_HASH_SLH_DSA_SHA3_512 } },
		{ "SHAKE-128", { CKM_HASH_ML_DSA_SHAKE128, CKM_HASH_SLH_DSA_SHAKE128 } },
		{ "SHAKE-256", { CKM_HASH_ML_DSA_SHAKE256, CKM_HASH_SLH_DSA_SHAKE256 } },
	};
	auto it = m.find(h);
	if (it == m.end()) return UNMAPPED;
	return mldsa ? it->second.first : it->second.second;
}

Bytes shake256(const Bytes& a, const Bytes& b, size_t outLen)
{
	Bytes out(outLen);
	EVP_MD_CTX* c = EVP_MD_CTX_new();
	CPPUNIT_ASSERT(c != NULL);
	bool ok = EVP_DigestInit_ex(c, EVP_shake256(), NULL) == 1 &&
	          EVP_DigestUpdate(c, a.data(), a.size()) == 1 &&
	          (b.empty() || EVP_DigestUpdate(c, b.data(), b.size()) == 1) &&
	          EVP_DigestFinalXOF(c, out.data(), outLen) == 1;
	EVP_MD_CTX_free(c);
	CPPUNIT_ASSERT_MESSAGE("SHAKE256", ok);
	return out;
}

// µ = SHAKE256(tr || M', 64), tr = SHAKE256(pk, 64) (FIPS 204 Alg 7 l.6, Alg 8 l.7).
Bytes mlDsaMu(const Bytes& pk, const Bytes& mPrime)
{
	return shake256(shake256(pk, Bytes(), 64), mPrime, 64);
}

CK_RV importKey(CK_SESSION_HANDLE h, CK_KEY_TYPE kt, bool isPrivate, CK_ULONG ps,
                const Bytes& value, CK_OBJECT_HANDLE& hKey, bool sensitive = false)
{
	CK_OBJECT_CLASS cls = isPrivate ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
	CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
	CK_ATTRIBUTE_TYPE use = (kt == CKK_ML_KEM) ? (isPrivate ? CKA_DECAPSULATE : CKA_ENCAPSULATE)
	                                           : (isPrivate ? CKA_SIGN : CKA_VERIFY);
	Bytes v(value);
	std::vector<CK_ATTRIBUTE> t = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ use, &bTrue, sizeof(bTrue) },
		{ CKA_PARAMETER_SET, &ps, sizeof(ps) },
		{ CKA_VALUE, v.data(), (CK_ULONG)v.size() },
	};
	if (isPrivate) t.push_back({ CKA_SENSITIVE, sensitive ? &bTrue : &bFalse, sizeof(bTrue) });
	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(h, t.data(), (CK_ULONG)t.size(), &hKey) );
}

// A CK_MECHANISM whose parameter is the standard or extended sign context,
// owning its storage.
struct SignMech
{
	CK_PQCTODAY_SIGN_ADDITIONAL_CONTEXT_EXT ext;
	CK_PQCTODAY_HASH_SIGN_ADDITIONAL_CONTEXT_EXT hext;
	Bytes ctx, rnd;
	CK_MECHANISM m;

	// extended=false: standard CK_SIGN_ADDITIONAL_CONTEXT (prefix of ext).
	SignMech(CK_MECHANISM_TYPE mech, CK_HEDGE_TYPE hedge, const Bytes& context,
	         const Bytes& random, CK_ULONG encoding, bool extended = true, bool hashForm = false,
	         CK_MECHANISM_TYPE hash = CKM_SHA256)
	    : ctx(context), rnd(random)
	{
		memset(&ext, 0, sizeof(ext));
		memset(&hext, 0, sizeof(hext));
		ext.hedgeVariant = hext.hedgeVariant = hedge;
		ext.pContext = hext.pContext = ctx.empty() ? NULL_PTR : ctx.data();
		ext.ulContextLen = hext.ulContextLen = (CK_ULONG)ctx.size();
		ext.pRandom = hext.pRandom = rnd.empty() ? NULL_PTR : rnd.data();
		ext.ulRandomLen = hext.ulRandomLen = (CK_ULONG)rnd.size();
		ext.messageEncoding = hext.messageEncoding = encoding;
		hext.hash = hash;
		m.mechanism = mech;
		if (hashForm)
		{
			m.pParameter = &hext;
			m.ulParameterLen = extended ? sizeof(hext) : sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT);
		}
		else
		{
			m.pParameter = &ext;
			m.ulParameterLen = extended ? sizeof(ext) : sizeof(CK_SIGN_ADDITIONAL_CONTEXT);
		}
	}
	SignMech(const SignMech&) = delete;
	CK_MECHANISM* get() { return &m; }
};

CK_RV signOnce(CK_SESSION_HANDLE h, CK_MECHANISM* m, CK_OBJECT_HANDLE hKey, Bytes data, Bytes& sig)
{
	CK_RV rv = CRYPTOKI_F_PTR( C_SignInit(h, m, hKey) );
	if (rv != CKR_OK) return rv;
	CK_ULONG len = 0;
	rv = CRYPTOKI_F_PTR( C_Sign(h, acvpkat::dataPtr(data), (CK_ULONG)data.size(), NULL_PTR, &len) );
	if (rv != CKR_OK) return rv;
	sig.assign(len, 0);
	rv = CRYPTOKI_F_PTR( C_Sign(h, acvpkat::dataPtr(data), (CK_ULONG)data.size(), sig.data(), &len) );
	sig.resize(rv == CKR_OK ? len : 0);
	return rv;
}

CK_RV verifyOnce(CK_SESSION_HANDLE h, CK_MECHANISM* m, CK_OBJECT_HANDLE hKey, Bytes data, Bytes sig)
{
	CK_RV rv = CRYPTOKI_F_PTR( C_VerifyInit(h, m, hKey) );
	if (rv != CKR_OK) return rv;
	return CRYPTOKI_F_PTR( C_Verify(h, acvpkat::dataPtr(data), (CK_ULONG)data.size(),
	                                sig.empty() ? acvpkat::dataPtr(sig) : sig.data(), (CK_ULONG)sig.size()) );
}

CK_RV verifySignatureOnce(CK_SESSION_HANDLE h, CK_MECHANISM* m, CK_OBJECT_HANDLE hKey, Bytes data, Bytes sig)
{
	CK_RV rv = CRYPTOKI_F_PTR( C_VerifySignatureInit(h, m, hKey, sig.data(), (CK_ULONG)sig.size()) );
	if (rv != CKR_OK) return rv;
	return CRYPTOKI_F_PTR( C_VerifySignature(h, acvpkat::dataPtr(data), (CK_ULONG)data.size()) );
}

// One NIST sigGen case through PKCS#11. Returns the CK_RV and the signature.
// `skipped` is set (and nothing run) when the case's hashAlg has no PKCS#11
// pre-hash mechanism.
CK_RV runSigGenCase(CK_SESSION_HANDLE h, bool mldsa, const nlohmann::json& g, const nlohmann::json& t,
                    Bytes& sig, bool& skipped, bool sensitive = false)
{
	skipped = false;
	const std::string ps = g["parameterSet"].get<std::string>();
	const bool internal = g["signatureInterface"].get<std::string>() == "internal";
	const bool preHash = g["preHash"].get<std::string>() == "preHash";
	const bool det = g["deterministic"].get<bool>();
	const bool extMu = mldsa && g.contains("externalMu") && g["externalMu"].get<bool>();
	const Bytes rnd = det ? Bytes() : acvpkat::hexField(t, mldsa ? "rnd" : "additionalRandomness");
	const Bytes ctx = acvpkat::hexField(t, "context");
	const CK_HEDGE_TYPE hedge = det ? CKH_DETERMINISTIC_REQUIRED : CKH_HEDGE_PREFERRED;

	CK_MECHANISM_TYPE mech = mldsa ? CKM_ML_DSA : CKM_SLH_DSA;
	if (preHash)
	{
		mech = preHashMech(mldsa, t["hashAlg"].get<std::string>());
		if (mech == UNMAPPED) { skipped = true; return CKR_OK; }
	}
	Bytes data = acvpkat::hexField(t, "message");
	CK_ULONG enc = PQCTODAY_MESSAGE_ENCODING_STANDARD;
	if (mldsa && extMu)
	{
		mech = CKM_ML_DSA_EXTERNAL_MU;
		data = acvpkat::hexField(t, "mu");
	}
	else if (mldsa && internal && det)
	{
		// Standard route (owner decision): CKM_ML_DSA_EXTERNAL_MU over µ of M'.
		mech = CKM_ML_DSA_EXTERNAL_MU;
		data = mlDsaMu(acvpkat::hexField(t, "pk"), data);
	}
	else if (internal)
	{
		enc = PQCTODAY_MESSAGE_ENCODING_INTERNAL;
	}

	CK_OBJECT_HANDLE hKey;
	CK_RV rv = importKey(h, mldsa ? CKK_ML_DSA : CKK_SLH_DSA, true,
	                     mldsa ? mldsaSet(ps) : slhSet(ps), acvpkat::hexField(t, "sk"), hKey, sensitive);
	if (rv != CKR_OK) return rv;
	// The extended form only when something in it is used: absent input stays
	// the standard structure.
	const bool needExt = !rnd.empty() || enc != PQCTODAY_MESSAGE_ENCODING_STANDARD;
	SignMech sm(mech, hedge, ctx, rnd, enc, needExt);
	rv = signOnce(h, sm.get(), hKey, data, sig);
	CRYPTOKI_F_PTR( C_DestroyObject(h, hKey) );
	return rv;
}

void runSigGenDoc(CK_SESSION_HANDLE h, bool mldsa, const nlohmann::json& doc, const std::set<int>* tgIds,
                  acvpkat::Failures& f, std::set<int>& groups, size_t& cases, size_t& skipped)
{
	for (const auto& g : doc["testGroups"])
	{
		const int tg = g["tgId"].get<int>();
		if (tgIds && !tgIds->count(tg)) continue;
		for (const auto& t : g["tests"])
		{
			const std::string id = std::string(mldsa ? "ML-DSA" : "SLH-DSA") + " tg" + std::to_string(tg) +
				" tc" + std::to_string(t["tcId"].get<int>()) + " " + g["parameterSet"].get<std::string>() +
				" " + g["signatureInterface"].get<std::string>() + "/" + g["preHash"].get<std::string>() +
				(g["deterministic"].get<bool>() ? "/det" : "/hedged");
			Bytes sig;
			bool skip = false;
			CK_RV rv = runSigGenCase(h, mldsa, g, t, sig, skip);
			if (skip) { skipped++; continue; }
			groups.insert(tg);
			cases++;
			if (rv != CKR_OK) { f.check(false, id + ": rv=" + acvpkat::rvHex(rv)); continue; }
			f.check(sig == acvpkat::hexField(t, "signature"), id + ": signature differs from NIST");
		}
	}
}

// Expected verdict code for a NIST sigVer case.
CK_RV expectedVerdict(const nlohmann::json& t)
{
	if (t["testPassed"].get<bool>()) return CKR_OK;
	const std::string r = t["reason"].get<std::string>();
	return (r.find("too small") != std::string::npos || r.find("too large") != std::string::npos)
	       ? CKR_SIGNATURE_LEN_RANGE : CKR_SIGNATURE_INVALID;
}

void runSigVerDoc(CK_SESSION_HANDLE h, bool mldsa, const nlohmann::json& doc, const std::set<int>* tgIds,
                  acvpkat::Failures& f, std::set<int>& groups, size_t& cases, size_t& negatives)
{
	for (const auto& g : doc["testGroups"])
	{
		const int tg = g["tgId"].get<int>();
		if (tgIds && !tgIds->count(tg)) continue;
		groups.insert(tg);
		const std::string ps = g["parameterSet"].get<std::string>();
		for (const auto& t : g["tests"])
		{
			const std::string id = std::string(mldsa ? "ML-DSA" : "SLH-DSA") + " sigVer tg" + std::to_string(tg) +
				" tc" + std::to_string(t["tcId"].get<int>()) + " " + ps + " (" + t["reason"].get<std::string>() + ")";
			const CK_RV want = expectedVerdict(t);
			if (want != CKR_OK) negatives++;
			cases++;
			CK_OBJECT_HANDLE hPub;
			CK_RV rv = importKey(h, mldsa ? CKK_ML_DSA : CKK_SLH_DSA, false,
			                     mldsa ? mldsaSet(ps) : slhSet(ps), acvpkat::hexField(t, "pk"), hPub);
			if (rv != CKR_OK) { f.check(false, id + ": import pk rv=" + acvpkat::rvHex(rv)); continue; }
			const Bytes msg = acvpkat::hexField(t, "message");
			const Bytes sig = acvpkat::hexField(t, "signature");
			// messageEncoding internal, through C_VerifyInit and C_VerifySignatureInit.
			{
				SignMech sm(mldsa ? CKM_ML_DSA : CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(),
				            PQCTODAY_MESSAGE_ENCODING_INTERNAL);
				rv = verifyOnce(h, sm.get(), hPub, msg, sig);
				f.check(rv == want, id + ": internal C_Verify expected " + acvpkat::rvHex(want) +
				        ", got " + acvpkat::rvHex(rv));
				// C_VerifySignature has no length precheck in this engine (it
				// answers CKR_SIGNATURE_INVALID for a wrong-length signature on
				// the standard path too) -- a pre-existing, separate gap, so the
				// length cases are checked through C_Verify only.
				if (want != CKR_SIGNATURE_LEN_RANGE)
				{
					rv = verifySignatureOnce(h, sm.get(), hPub, msg, sig);
					f.check(rv == want, id + ": internal C_VerifySignature expected " + acvpkat::rvHex(want) +
					        ", got " + acvpkat::rvHex(rv));
				}
			}
			// ML-DSA: the standard route too (owner decision), CKM_ML_DSA_EXTERNAL_MU.
			if (mldsa)
			{
				CK_MECHANISM mu = { CKM_ML_DSA_EXTERNAL_MU, NULL_PTR, 0 };
				rv = verifyOnce(h, &mu, hPub, mlDsaMu(acvpkat::hexField(t, "pk"), msg), sig);
				f.check(rv == want, id + ": EXTERNAL_MU C_Verify expected " + acvpkat::rvHex(want) +
				        ", got " + acvpkat::rvHex(rv));
			}
			CRYPTOKI_F_PTR( C_DestroyObject(h, hPub) );
		}
	}
}

// Encapsulate with a supplied m; returns c and the extracted shared secret.
CK_RV encapsulate(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE hPub, const Bytes* m, Bytes& ct, Bytes& ss,
                  CK_ULONG paramLen = (CK_ULONG)-1, bool nullParam = false)
{
	Bytes mv = m ? *m : Bytes();
	CK_MECHANISM mech = { CKM_ML_KEM, (m && !nullParam) ? mv.data() : NULL_PTR,
	                      paramLen != (CK_ULONG)-1 ? paramLen : (CK_ULONG)mv.size() };
	CK_OBJECT_CLASS sc = CKO_SECRET_KEY;
	CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &sc, sizeof(sc) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
	};
	CK_ULONG ctLen = 0;
	CK_OBJECT_HANDLE hs = CK_INVALID_HANDLE;
	CK_RV rv = CRYPTOKI_F_PTR( C_EncapsulateKey(h, &mech, hPub, tmpl, 4, NULL_PTR, &ctLen, &hs) );
	if (rv != CKR_OK) return rv;
	ct.assign(ctLen, 0);
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(h, &mech, hPub, tmpl, 4, ct.data(), &ctLen, &hs) );
	if (rv != CKR_OK) return rv;
	ct.resize(ctLen);
	CK_ATTRIBUTE val = { CKA_VALUE, NULL_PTR, 0 };
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(h, hs, &val, 1) );
	if (rv != CKR_OK) return rv;
	ss.assign(val.ulValueLen, 0);
	val.pValue = ss.data();
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(h, hs, &val, 1) );
	CRYPTOKI_F_PTR( C_DestroyObject(h, hs) );
	return rv;
}

CK_RV decapsulate(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE hPrk, Bytes ct, Bytes& ss,
                  void* param = NULL_PTR, CK_ULONG paramLen = 0)
{
	CK_MECHANISM mech = { CKM_ML_KEM, param, paramLen };
	CK_OBJECT_CLASS sc = CKO_SECRET_KEY;
	CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &sc, sizeof(sc) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
	};
	CK_OBJECT_HANDLE hs = CK_INVALID_HANDLE;
	CK_RV rv = CRYPTOKI_F_PTR( C_DecapsulateKey(h, &mech, hPrk, tmpl, 4, ct.data(), (CK_ULONG)ct.size(), &hs) );
	if (rv != CKR_OK) return rv;
	CK_ATTRIBUTE val = { CKA_VALUE, NULL_PTR, 0 };
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(h, hs, &val, 1) );
	if (rv != CKR_OK) return rv;
	ss.assign(val.ulValueLen, 0);
	val.pValue = ss.data();
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(h, hs, &val, 1) );
	CRYPTOKI_F_PTR( C_DestroyObject(h, hs) );
	return rv;
}

void runMlKemDoc(CK_SESSION_HANDLE h, const nlohmann::json& doc, const std::set<int>* tgIds,
                 acvpkat::Failures& f, std::set<int>& groups, size_t& cases)
{
	for (const auto& g : doc["testGroups"])
	{
		const int tg = g["tgId"].get<int>();
		if (tgIds && !tgIds->count(tg)) continue;
		if (g["function"].get<std::string>() != "encapsulation") continue;
		groups.insert(tg);
		const std::string ps = g["parameterSet"].get<std::string>();
		for (const auto& t : g["tests"])
		{
			const std::string id = "ML-KEM tg" + std::to_string(tg) + " tc" + std::to_string(t["tcId"].get<int>()) + " " + ps;
			cases++;
			CK_OBJECT_HANDLE hPub, hPrk;
			CK_RV rv = importKey(h, CKK_ML_KEM, false, mlkemSet(ps), acvpkat::hexField(t, "ek"), hPub);
			if (rv != CKR_OK) { f.check(false, id + ": import ek rv=" + acvpkat::rvHex(rv)); continue; }
			Bytes m = acvpkat::hexField(t, "m"), ct, ss;
			rv = encapsulate(h, hPub, &m, ct, ss);
			if (rv != CKR_OK) { f.check(false, id + ": encapsulate rv=" + acvpkat::rvHex(rv)); }
			else
			{
				f.check(ct == acvpkat::hexField(t, "c"), id + ": c differs from NIST");
				f.check(ss == acvpkat::hexField(t, "k"), id + ": k differs from NIST");
				// Ordinary output: the standard decapsulation recovers k.
				rv = importKey(h, CKK_ML_KEM, true, mlkemSet(ps), acvpkat::hexField(t, "dk"), hPrk);
				Bytes ss2;
				if (rv == CKR_OK) rv = decapsulate(h, hPrk, ct, ss2);
				f.check(rv == CKR_OK && ss2 == ss, id + ": decapsulation does not recover k, rv=" + acvpkat::rvHex(rv));
				if (hPrk != CK_INVALID_HANDLE) CRYPTOKI_F_PTR( C_DestroyObject(h, hPrk) );
			}
			CRYPTOKI_F_PTR( C_DestroyObject(h, hPub) );
		}
	}
}

// The first case of the first group in `file` matching `pred`.
template <class P>
bool findCase(const nlohmann::json& doc, P pred, nlohmann::json& g, nlohmann::json& t)
{
	for (const auto& gg : doc["testGroups"])
		if (pred(gg)) { g = gg; t = gg["tests"][0]; return true; }
	return false;
}

} // namespace

void OptionalRandomInputTests::openSession(CK_SESSION_HANDLE& hSession)
{
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CK_RV rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void OptionalRandomInputTests::testMlKemEncapsulateMatchesNist()
{
	CK_SESSION_HANDLE h;
	openSession(h);
	acvpkat::Failures f;
	std::set<int> groups;
	size_t cases = 0;
	runMlKemDoc(h, acvpkat::load("mlkem_encap_aft_test.json"), NULL, f, groups, cases);
	f.assertNone("ML-KEM encapsulation AFT with supplied m");
	CPPUNIT_ASSERT_EQUAL((size_t)3, groups.size());
	CPPUNIT_ASSERT_EQUAL((size_t)75, cases);
}

void OptionalRandomInputTests::testMlKemRefusalsAndAbsentInput()
{
	CK_SESSION_HANDLE h;
	openSession(h);
	nlohmann::json doc = acvpkat::load("mlkem_encap_aft_test.json");
	const auto& g = doc["testGroups"][0];
	const auto& t = g["tests"][0];
	const CK_ULONG ps = mlkemSet(g["parameterSet"].get<std::string>());
	CK_OBJECT_HANDLE hPub, hPrk;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_ML_KEM, false, ps, acvpkat::hexField(t, "ek"), hPub));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_ML_KEM, true, ps, acvpkat::hexField(t, "dk"), hPrk));
	Bytes m = acvpkat::hexField(t, "m"), ct, ss;

	// Wrong lengths and a NULL pointer with a length: refused before any work.
	Bytes m31(m.begin(), m.end() - 1), m33(m);
	m33.push_back(0);
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, encapsulate(h, hPub, &m31, ct, ss));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, encapsulate(h, hPub, &m33, ct, ss));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, encapsulate(h, hPub, &m, ct, ss, 32, true));

	// Absent (NULL/0): standard randomised encapsulation, unchanged — two
	// ciphertexts differ and each decapsulates to its own secret.
	Bytes ct1, ss1, ct2, ss2, d1, d2;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, encapsulate(h, hPub, NULL, ct1, ss1));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, encapsulate(h, hPub, NULL, ct2, ss2));
	CPPUNIT_ASSERT(ct1 != ct2);
	CPPUNIT_ASSERT(ct1 != acvpkat::hexField(t, "c"));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, decapsulate(h, hPrk, ct1, d1));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, decapsulate(h, hPrk, ct2, d2));
	CPPUNIT_ASSERT(d1 == ss1 && d2 == ss2);

	// Same m twice: same output (the value is really used).
	Bytes ctA, ssA, ctB, ssB;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, encapsulate(h, hPub, &m, ctA, ssA));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, encapsulate(h, hPub, &m, ctB, ssB));
	CPPUNIT_ASSERT(ctA == ctB && ssA == ssB);
	// Sabotage: a one-bit change of m changes c and k.
	Bytes mx(m);
	mx[0] ^= 0x01;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, encapsulate(h, hPub, &mx, ctB, ssB));
	CPPUNIT_ASSERT(ctB != ctA && ssB != ssA);
	Bytes flipped = acvpkat::hexField(t, "c");
	flipped[5] ^= 0x01;
	CPPUNIT_ASSERT(ctA != flipped);

	// Decapsulation draws no randomness: any parameter is refused (new).
	Bytes ssX;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, decapsulate(h, hPrk, ctA, ssX, m.data(), (CK_ULONG)m.size()));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, decapsulate(h, hPrk, ctA, ssX, NULL_PTR, 32));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_MECHANISM_PARAM_INVALID, decapsulate(h, hPrk, ctA, ssX, m.data(), 0));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, decapsulate(h, hPrk, ctA, ssX));
	CPPUNIT_ASSERT(ssX == ssA);
}

void OptionalRandomInputTests::testMlDsaSigGenMatchesNist()
{
	CK_SESSION_HANDLE h;
	openSession(h);
	acvpkat::Failures f;
	std::set<int> groups;
	size_t cases = 0, skipped = 0;
	runSigGenDoc(h, true, acvpkat::load("mldsa_siggen_optional_input_test.json"), NULL, f, groups, cases, skipped);
	f.assertNone("ML-DSA sigGen with supplied rnd / internal interface");
	CPPUNIT_ASSERT_EQUAL((size_t)15, groups.size());
	CPPUNIT_ASSERT_EQUAL((size_t)30, cases);
	CPPUNIT_ASSERT_EQUAL((size_t)0, skipped);
}

void OptionalRandomInputTests::testMlDsaSigVerInternalMatchesNist()
{
	CK_SESSION_HANDLE h;
	openSession(h);
	acvpkat::Failures f;
	std::set<int> groups;
	size_t cases = 0, negatives = 0;
	runSigVerDoc(h, true, acvpkat::load("mldsa_sigver_internal_test.json"), NULL, f, groups, cases, negatives);
	f.assertNone("ML-DSA sigVer, internal interface");
	CPPUNIT_ASSERT_EQUAL((size_t)3, groups.size());
	CPPUNIT_ASSERT_EQUAL((size_t)15, cases);
	CPPUNIT_ASSERT_EQUAL((size_t)12, negatives);
}

void OptionalRandomInputTests::testSlhDsaSigGenMatchesNist()
{
	CK_SESSION_HANDLE h;
	openSession(h);
	acvpkat::Failures f;
	std::set<int> groups;
	size_t cases = 0, skipped = 0;
	runSigGenDoc(h, false, acvpkat::load("slhdsa_siggen_optional_input_test.json"), NULL, f, groups, cases, skipped);
	f.assertNone("SLH-DSA sigGen with supplied addrnd / internal interface");
	CPPUNIT_ASSERT_EQUAL((size_t)48, groups.size());
	CPPUNIT_ASSERT_EQUAL((size_t)48, cases);
	CPPUNIT_ASSERT_EQUAL((size_t)0, skipped);
}

void OptionalRandomInputTests::testSlhDsaSigVerInternalMatchesNist()
{
	CK_SESSION_HANDLE h;
	openSession(h);
	acvpkat::Failures f;
	std::set<int> groups;
	size_t cases = 0, negatives = 0;
	runSigVerDoc(h, false, acvpkat::load("slhdsa_sigver_internal_test.json"), NULL, f, groups, cases, negatives);
	f.assertNone("SLH-DSA sigVer, internal interface");
	CPPUNIT_ASSERT_EQUAL((size_t)12, groups.size());
	CPPUNIT_ASSERT_EQUAL((size_t)25, cases);
	CPPUNIT_ASSERT_EQUAL((size_t)13, negatives);
}

void OptionalRandomInputTests::testFullNistSetWhenProvided()
{
	const char* dir = getenv("ACVP_OPTIONAL_INPUT_FULL_DIR");
	if (dir == NULL || dir[0] == '\0') return;  // the committed subsets above always run
	CK_SESSION_HANDLE h;
	openSession(h);
	auto loadFull = [&](const char* name) {
		const std::string path = std::string(dir) + "/" + name + ".json";
		std::ifstream in(path);
		CPPUNIT_ASSERT_MESSAGE("cannot open " + path, in.good());
		nlohmann::json j;
		in >> j;
		return j;
	};
	const std::set<int> kem = { 1, 2, 3 };
	const std::set<int> mlGen = { 8, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24 };
	const std::set<int> mlVer = { 8, 10, 12 };
	std::set<int> slhGen = { 13, 14, 15, 16, 17, 18 };
	for (int i = 31; i <= 72; i++) slhGen.insert(i);
	const std::set<int> slhVer = { 13, 14, 15, 16, 17, 18, 31, 32, 33, 34, 35, 36 };

	acvpkat::Failures f;
	std::set<int> gK, gMG, gMV, gSG, gSV;
	size_t cK = 0, cMG = 0, cMV = 0, cSG = 0, cSV = 0, skMG = 0, skSG = 0, neg = 0;
	runMlKemDoc(h, loadFull("ML-KEM-encapDecap-FIPS203"), &kem, f, gK, cK);
	runSigGenDoc(h, true, loadFull("ML-DSA-sigGen-FIPS204"), &mlGen, f, gMG, cMG, skMG);
	runSigVerDoc(h, true, loadFull("ML-DSA-sigVer-FIPS204"), &mlVer, f, gMV, cMV, neg);
	runSigGenDoc(h, false, loadFull("SLH-DSA-sigGen-FIPS205"), &slhGen, f, gSG, cSG, skSG);
	runSigVerDoc(h, false, loadFull("SLH-DSA-sigVer-FIPS205"), &slhVer, f, gSV, cSV, neg);
	const size_t total = cK + cMG + cMV + cSG + cSV;
	fprintf(stderr, "\n[full NIST optional-input set] groups=%zu cases run=%zu (ML-KEM %zu, ML-DSA gen %zu ver %zu, "
	        "SLH-DSA gen %zu ver %zu); no-PKCS#11-hash skipped: ML-DSA %zu, SLH-DSA %zu\n",
	        gK.size() + gMG.size() + gMV.size() + gSG.size() + gSV.size(), total, cK, cMG, cMV, cSG, cSV, skMG, skSG);
	f.assertNone("full in-scope NIST set");
	CPPUNIT_ASSERT_EQUAL((size_t)81, gK.size() + gMG.size() + gMV.size() + gSG.size() + gSV.size());
	CPPUNIT_ASSERT_EQUAL((size_t)909, total + skMG + skSG);
}

void OptionalRandomInputTests::testSignContextRefusals()
{
	CK_SESSION_HANDLE h;
	openSession(h);
	nlohmann::json ml = acvpkat::load("mldsa_siggen_optional_input_test.json");
	nlohmann::json g, t;
	CPPUNIT_ASSERT(findCase(ml, [](const nlohmann::json& x) {
		return x["preHash"] == "pure" && x["signatureInterface"] == "external" && !x["deterministic"].get<bool>(); }, g, t));
	CK_OBJECT_HANDLE hMl, hMlPub;
	const CK_ULONG mlps = mldsaSet(g["parameterSet"].get<std::string>());
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_ML_DSA, true, mlps, acvpkat::hexField(t, "sk"), hMl));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_ML_DSA, false, mlps, acvpkat::hexField(t, "pk"), hMlPub));
	const Bytes rnd = acvpkat::hexField(t, "rnd"), ctx = acvpkat::hexField(t, "context");
	const Bytes rnd31(rnd.begin(), rnd.end() - 1);
	Bytes rnd33(rnd);
	rnd33.push_back(0);
	const CK_RV PI = CKR_MECHANISM_PARAM_INVALID;
	auto si = [&](SignMech& sm, CK_OBJECT_HANDLE k) {
		CK_RV rv = CRYPTOKI_F_PTR( C_SignInit(h, sm.get(), k) );
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_SignInit(h, NULL_PTR, CK_INVALID_HANDLE) );
		return rv;
	};
	auto vi = [&](SignMech& sm, CK_OBJECT_HANDLE k) {
		CK_RV rv = CRYPTOKI_F_PTR( C_VerifyInit(h, sm.get(), k) );
		if (rv == CKR_OK) CRYPTOKI_F_PTR( C_VerifyInit(h, NULL_PTR, CK_INVALID_HANDLE) );
		return rv;
	};
	const CK_ULONG STD = PQCTODAY_MESSAGE_ENCODING_STANDARD, INT = PQCTODAY_MESSAGE_ENCODING_INTERNAL;

	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx, rnd, STD); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, si(s, hMl)); }
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_REQUIRED, ctx, rnd, STD); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, si(s, hMl)); }
	// Wrong rnd lengths.
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx, rnd31, STD); CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx, rnd33, STD); CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	// pRandom NULL with a length.
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx, rnd, STD); s.ext.pRandom = NULL_PTR; CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	// Supplied random + CKH_DETERMINISTIC_REQUIRED: a contradiction.
	{ SignMech s(CKM_ML_DSA, CKH_DETERMINISTIC_REQUIRED, ctx, rnd, STD); CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	// Unknown messageEncoding.
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(), 2); CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	// Internal encoding: non-empty context, pre-hash and external-µ refused.
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx.empty() ? Bytes(1, 0x5a) : ctx, rnd, INT); CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	{ SignMech s(CKM_HASH_ML_DSA_SHA256, CKH_HEDGE_PREFERRED, Bytes(), rnd, INT); CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	{ SignMech s(CKM_HASH_ML_DSA, CKH_HEDGE_PREFERRED, Bytes(), rnd, INT, true, true); CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	{ SignMech s(CKM_ML_DSA_EXTERNAL_MU, CKH_HEDGE_PREFERRED, Bytes(), rnd, INT); CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	{ SignMech s(CKM_HASH_ML_DSA_SHA256, CKH_HEDGE_PREFERRED, Bytes(), Bytes(), INT); CPPUNIT_ASSERT_EQUAL(PI, vi(s, hMlPub)); }
	// Pre-hash (typed and generic) and external-µ accept rnd.
	{ SignMech s(CKM_HASH_ML_DSA_SHA256, CKH_HEDGE_PREFERRED, ctx, rnd, STD); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, si(s, hMl)); }
	{ SignMech s(CKM_HASH_ML_DSA, CKH_HEDGE_PREFERRED, ctx, rnd, STD, true, true); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, si(s, hMl)); }
	{ SignMech s(CKM_ML_DSA_EXTERNAL_MU, CKH_HEDGE_PREFERRED, Bytes(), rnd, STD); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, si(s, hMl)); }
	// A random value on verification is refused (VerifyInit and VerifySignatureInit).
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx, rnd, STD); CPPUNIT_ASSERT_EQUAL(PI, vi(s, hMlPub));
	  Bytes sig(2420, 0);
	  CPPUNIT_ASSERT_EQUAL(PI, CRYPTOKI_F_PTR( C_VerifySignatureInit(h, s.get(), hMlPub, sig.data(), (CK_ULONG)sig.size()) )); }
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(), INT); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, vi(s, hMlPub)); }
	// Sizes other than standard or extended (per ABI) are refused.
	for (CK_ULONG bad : { (CK_ULONG)(sizeof(CK_SIGN_ADDITIONAL_CONTEXT) + 1),
	                      (CK_ULONG)(sizeof(CK_PQCTODAY_SIGN_ADDITIONAL_CONTEXT_EXT) - sizeof(CK_ULONG)),
	                      (CK_ULONG)(sizeof(CK_PQCTODAY_SIGN_ADDITIONAL_CONTEXT_EXT) + sizeof(CK_ULONG)),
	                      (CK_ULONG)sizeof(CK_PQCTODAY_HASH_SIGN_ADDITIONAL_CONTEXT_EXT) })
	{
		SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx, Bytes(), STD);
		s.m.ulParameterLen = bad;
		CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl));
		CPPUNIT_ASSERT_EQUAL(PI, vi(s, hMlPub));
	}
	{ SignMech s(CKM_HASH_ML_DSA, CKH_HEDGE_PREFERRED, ctx, Bytes(), STD, true, true);
	  s.m.ulParameterLen = sizeof(CK_PQCTODAY_HASH_SIGN_ADDITIONAL_CONTEXT_EXT) + sizeof(CK_ULONG);
	  CPPUNIT_ASSERT_EQUAL(PI, si(s, hMl)); }
	// Message-based signing refuses the extended form (init and per message).
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx, rnd, STD);
	  CPPUNIT_ASSERT_EQUAL(PI, CRYPTOKI_F_PTR( C_MessageSignInit(h, s.get(), hMl) ));
	  CPPUNIT_ASSERT_EQUAL(PI, CRYPTOKI_F_PTR( C_MessageVerifyInit(h, s.get(), hMlPub) )); }
	{ SignMech std0(CKM_ML_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(), STD, false);
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_MessageSignInit(h, std0.get(), hMl) ));
	  SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, Bytes(), rnd, STD);
	  Bytes msg(4, 0x11), sig(4627, 0);
	  CK_ULONG sl = (CK_ULONG)sig.size();
	  CPPUNIT_ASSERT_EQUAL(PI, CRYPTOKI_F_PTR( C_SignMessage(h, &s.ext, sizeof(s.ext), msg.data(), (CK_ULONG)msg.size(), sig.data(), &sl) ));
	  CRYPTOKI_F_PTR( C_MessageSignFinal(h) ); }

	// SLH-DSA: addrnd must be exactly n for the key's set.
	nlohmann::json sl = acvpkat::load("slhdsa_siggen_optional_input_test.json");
	CPPUNIT_ASSERT(findCase(sl, [](const nlohmann::json& x) {
		return x["preHash"] == "pure" && x["signatureInterface"] == "external" && !x["deterministic"].get<bool>() &&
		       x["parameterSet"] == "SLH-DSA-SHA2-192f"; }, g, t));
	CK_OBJECT_HANDLE hSl, hSlPub;
	const CK_ULONG slps = slhSet(g["parameterSet"].get<std::string>());
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_SLH_DSA, true, slps, acvpkat::hexField(t, "sk"), hSl));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_SLH_DSA, false, slps, acvpkat::hexField(t, "pk"), hSlPub));
	const Bytes add = acvpkat::hexField(t, "additionalRandomness");
	CPPUNIT_ASSERT_EQUAL((size_t)24, add.size());
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), add, STD); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, si(s, hSl)); }
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(add.begin(), add.begin() + 16), STD); CPPUNIT_ASSERT_EQUAL(PI, si(s, hSl)); }
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(32, 7), STD); CPPUNIT_ASSERT_EQUAL(PI, si(s, hSl)); }
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(33, 7), STD); CPPUNIT_ASSERT_EQUAL(PI, si(s, hSl)); }
	{ SignMech s(CKM_SLH_DSA, CKH_DETERMINISTIC_REQUIRED, Bytes(), add, STD); CPPUNIT_ASSERT_EQUAL(PI, si(s, hSl)); }
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(1, 1), add, INT); CPPUNIT_ASSERT_EQUAL(PI, si(s, hSl)); }
	{ SignMech s(CKM_HASH_SLH_DSA_SHA256, CKH_HEDGE_PREFERRED, Bytes(), add, INT); CPPUNIT_ASSERT_EQUAL(PI, si(s, hSl)); }
	{ SignMech s(CKM_HASH_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), add, STD, true, true); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, si(s, hSl)); }
	{ SignMech s(CKM_HASH_SLH_DSA_SHA256, CKH_HEDGE_PREFERRED, Bytes(), add, STD); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, si(s, hSl)); }
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), add, STD); CPPUNIT_ASSERT_EQUAL(PI, vi(s, hSlPub)); }
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(), INT); CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, vi(s, hSlPub)); }
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, Bytes(), Bytes(), STD); s.m.ulParameterLen += 1; CPPUNIT_ASSERT_EQUAL(PI, si(s, hSl)); }
}

void OptionalRandomInputTests::testAbsentInputUnchanged()
{
	// Absent input means standard behaviour, byte for byte: the extended form
	// with no random value and standard encoding signs exactly like the
	// standard form (deterministic), and hedged signing stays randomised.
	CK_SESSION_HANDLE h;
	openSession(h);
	nlohmann::json ml = acvpkat::load("mldsa_siggen_optional_input_test.json");
	nlohmann::json g, t;
	CPPUNIT_ASSERT(findCase(ml, [](const nlohmann::json& x) {
		return x["preHash"] == "pure" && x["signatureInterface"] == "external"; }, g, t));
	CK_OBJECT_HANDLE hMl;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_ML_DSA, true, mldsaSet(g["parameterSet"].get<std::string>()),
	                                              acvpkat::hexField(t, "sk"), hMl));
	const Bytes msg = acvpkat::hexField(t, "message"), ctx = acvpkat::hexField(t, "context");
	Bytes a, b, c, d;
	{ SignMech s(CKM_ML_DSA, CKH_DETERMINISTIC_REQUIRED, ctx, Bytes(), PQCTODAY_MESSAGE_ENCODING_STANDARD, false);
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hMl, msg, a)); }
	{ SignMech s(CKM_ML_DSA, CKH_DETERMINISTIC_REQUIRED, ctx, Bytes(), PQCTODAY_MESSAGE_ENCODING_STANDARD, true);
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hMl, msg, b)); }
	CPPUNIT_ASSERT(a == b);
	{ SignMech s(CKM_ML_DSA, CKH_HEDGE_PREFERRED, ctx, Bytes(), PQCTODAY_MESSAGE_ENCODING_STANDARD, true);
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hMl, msg, c));
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hMl, msg, d)); }
	CPPUNIT_ASSERT(c != d);
	CPPUNIT_ASSERT(c != a);

	// SLH-DSA deterministic: standard vs extended-without-input identical.
	nlohmann::json sl = acvpkat::load("slhdsa_siggen_optional_input_test.json");
	CPPUNIT_ASSERT(findCase(sl, [](const nlohmann::json& x) {
		return x["preHash"] == "pure" && x["parameterSet"] == "SLH-DSA-SHAKE-128f" && !x["deterministic"].get<bool>(); }, g, t));
	CK_OBJECT_HANDLE hSl;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_SLH_DSA, true, slhSet(g["parameterSet"].get<std::string>()),
	                                              acvpkat::hexField(t, "sk"), hSl));
	const Bytes smsg = acvpkat::hexField(t, "message"), sctx = acvpkat::hexField(t, "context");
	{ SignMech s(CKM_SLH_DSA, CKH_DETERMINISTIC_REQUIRED, sctx, Bytes(), PQCTODAY_MESSAGE_ENCODING_STANDARD, false);
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hSl, smsg, a)); }
	{ SignMech s(CKM_SLH_DSA, CKH_DETERMINISTIC_REQUIRED, sctx, Bytes(), PQCTODAY_MESSAGE_ENCODING_STANDARD, true);
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hSl, smsg, b)); }
	CPPUNIT_ASSERT(a == b);
	{ SignMech s(CKM_SLH_DSA, CKH_HEDGE_PREFERRED, sctx, Bytes(), PQCTODAY_MESSAGE_ENCODING_STANDARD, true);
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hSl, smsg, c));
	  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hSl, smsg, d)); }
	CPPUNIT_ASSERT(c != d);
}

void OptionalRandomInputTests::testSabotageAndInteroperability()
{
	CK_SESSION_HANDLE h;
	openSession(h);
	for (int alg = 0; alg < 2; alg++)
	{
		const bool mldsa = (alg == 0);
		nlohmann::json doc = acvpkat::load(mldsa ? "mldsa_siggen_optional_input_test.json"
		                                         : "slhdsa_siggen_optional_input_test.json");
		nlohmann::json g, t;
		CPPUNIT_ASSERT(findCase(doc, [](const nlohmann::json& x) {
			return x["preHash"] == "pure" && x["signatureInterface"] == "external" && !x["deterministic"].get<bool>(); }, g, t));
		const CK_ULONG ps = mldsa ? mldsaSet(g["parameterSet"].get<std::string>()) : slhSet(g["parameterSet"].get<std::string>());
		const CK_KEY_TYPE kt = mldsa ? CKK_ML_DSA : CKK_SLH_DSA;
		CK_OBJECT_HANDLE hPrk, hPub;
		CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, kt, true, ps, acvpkat::hexField(t, "sk"), hPrk));
		CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, kt, false, ps, acvpkat::hexField(t, "pk"), hPub));
		const Bytes msg = acvpkat::hexField(t, "message"), ctx = acvpkat::hexField(t, "context");
		const Bytes want = acvpkat::hexField(t, "signature");
		Bytes rnd = acvpkat::hexField(t, mldsa ? "rnd" : "additionalRandomness"), sig, sig2;
		const CK_MECHANISM_TYPE mech = mldsa ? CKM_ML_DSA : CKM_SLH_DSA;
		{ SignMech s(mech, CKH_HEDGE_PREFERRED, ctx, rnd, PQCTODAY_MESSAGE_ENCODING_STANDARD);
		  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hPrk, msg, sig)); }
		CPPUNIT_ASSERT_MESSAGE("positive control", sig == want);
		Bytes flipped(want);
		flipped[flipped.size() / 2] ^= 0x01;
		CPPUNIT_ASSERT(sig != flipped);
		rnd[0] ^= 0x01;
		{ SignMech s(mech, CKH_HEDGE_PREFERRED, ctx, rnd, PQCTODAY_MESSAGE_ENCODING_STANDARD);
		  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hPrk, msg, sig2)); }
		CPPUNIT_ASSERT_MESSAGE("a changed random value changes the signature", sig2 != want);
		// Ordinary output: both verify under the standard mechanism and
		// standard parameter structure.
		SignMech std0(mech, CKH_HEDGE_PREFERRED, ctx, Bytes(), PQCTODAY_MESSAGE_ENCODING_STANDARD, false);
		CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, verifyOnce(h, std0.get(), hPub, msg, sig));
		CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, verifyOnce(h, std0.get(), hPub, msg, sig2));
		Bytes bad(sig);
		bad[bad.size() / 2] ^= 0x01;
		CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_SIGNATURE_INVALID, verifyOnce(h, std0.get(), hPub, msg, bad));
		// An internal-encoding signature of M' = 0 || |ctx| || ctx || M IS the
		// standard signature of M (FIPS 204 Alg 2 / FIPS 205 Alg 22).
		Bytes mPrime = { 0x00, (unsigned char)ctx.size() };
		mPrime.insert(mPrime.end(), ctx.begin(), ctx.end());
		mPrime.insert(mPrime.end(), msg.begin(), msg.end());
		Bytes sig3;
		{ SignMech s(mech, CKH_HEDGE_PREFERRED, Bytes(), acvpkat::hexField(t, mldsa ? "rnd" : "additionalRandomness"),
		             PQCTODAY_MESSAGE_ENCODING_INTERNAL);
		  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, signOnce(h, s.get(), hPrk, mPrime, sig3)); }
		CPPUNIT_ASSERT(sig3 == want);
		// Multi-part signing carries the supplied value too.
		{ SignMech s(mech, CKH_HEDGE_PREFERRED, ctx, acvpkat::hexField(t, mldsa ? "rnd" : "additionalRandomness"),
		             PQCTODAY_MESSAGE_ENCODING_STANDARD);
		  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_SignInit(h, s.get(), hPrk) ));
		  Bytes m1(msg.begin(), msg.begin() + msg.size() / 2), m2(msg.begin() + msg.size() / 2, msg.end());
		  if (!m1.empty()) CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_SignUpdate(h, m1.data(), (CK_ULONG)m1.size()) ));
		  if (!m2.empty()) CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_SignUpdate(h, m2.data(), (CK_ULONG)m2.size()) ));
		  Bytes mp(want.size() + 16);
		  CK_ULONG l = (CK_ULONG)mp.size();
		  CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_SignFinal(h, mp.data(), &l) ));
		  mp.resize(l);
		  CPPUNIT_ASSERT(mp == want); }
	}
}

void OptionalRandomInputTests::testNoSensitivityGuard()
{
	// Owner decision D0 (a): no guard. A supplied value works on CKA_SENSITIVE
	// keys exactly as on non-sensitive ones; pinned so a guard cannot be added
	// by accident.
	CK_SESSION_HANDLE h;
	openSession(h);
	for (int alg = 0; alg < 2; alg++)
	{
		const bool mldsa = (alg == 0);
		nlohmann::json doc = acvpkat::load(mldsa ? "mldsa_siggen_optional_input_test.json"
		                                         : "slhdsa_siggen_optional_input_test.json");
		for (const auto& g : doc["testGroups"])
		{
			if (g["deterministic"].get<bool>() || g["signatureInterface"] != "internal") continue;
			if (mldsa && g["externalMu"].get<bool>()) continue;
			const auto& t = g["tests"][0];
			for (int sens = 0; sens < 2; sens++)
			{
				Bytes sig;
				bool skipped = false;
				CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, runSigGenCase(h, mldsa, g, t, sig, skipped, sens != 0));
				CPPUNIT_ASSERT(sig == acvpkat::hexField(t, "signature"));
			}
			break;
		}
	}
}

void OptionalRandomInputTests::testOperationLogNotesSuppliedInput()
{
	// Plan M4 "Visible use": the operation log marks a supplied value.
	char path[] = "/tmp/softhsm-oplog-optional-input-XXXXXX";
	int fd = mkstemp(path);
	CPPUNIT_ASSERT(fd >= 0);
	close(fd);
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	setenv("SOFTHSM3_OP_LOG", path, 1);
	CK_SESSION_HANDLE h;
	openSession(h);

	nlohmann::json kem = acvpkat::load("mlkem_encap_aft_test.json");
	const auto& kg = kem["testGroups"][0];
	CK_OBJECT_HANDLE hPub;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, importKey(h, CKK_ML_KEM, false, mlkemSet(kg["parameterSet"].get<std::string>()),
	                                              acvpkat::hexField(kg["tests"][0], "ek"), hPub));
	Bytes m = acvpkat::hexField(kg["tests"][0], "m"), ct, ss;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, encapsulate(h, hPub, &m, ct, ss));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, encapsulate(h, hPub, NULL, ct, ss));

	nlohmann::json ml = acvpkat::load("mldsa_siggen_optional_input_test.json");
	nlohmann::json g, t;
	CPPUNIT_ASSERT(findCase(ml, [](const nlohmann::json& x) {
		return x["signatureInterface"] == "internal" && !x["deterministic"].get<bool>() && !x["externalMu"].get<bool>(); }, g, t));
	Bytes sig;
	bool skipped = false;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, runSigGenCase(h, true, g, t, sig, skipped));
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	unsetenv("SOFTHSM3_OP_LOG");

	std::ifstream in(path);
	std::stringstream ss2;
	ss2 << in.rdbuf();
	unlink(path);
	const std::string log = ss2.str();
	size_t encWith = 0, encWithout = 0, signInternal = 0;
	std::istringstream lines(log);
	for (std::string line; std::getline(lines, line);)
	{
		if (line.find("op=C_EncapsulateKey") != std::string::npos && line.find("probe=0") != std::string::npos)
			(line.find(" test_input=random ") != std::string::npos ? encWith : encWithout)++;
		if (line.find("op=C_SignInit") != std::string::npos &&
		    line.find(" test_input=random+internal ") != std::string::npos)
			signInternal++;
	}
	CPPUNIT_ASSERT_EQUAL_MESSAGE(log, (size_t)1, encWith);
	CPPUNIT_ASSERT_EQUAL_MESSAGE(log, (size_t)1, encWithout);
	CPPUNIT_ASSERT_EQUAL_MESSAGE(log, (size_t)1, signInternal);
}
