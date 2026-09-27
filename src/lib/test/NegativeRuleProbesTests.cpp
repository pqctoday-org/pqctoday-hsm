/*****************************************************************************
 NegativeRuleProbesTests.cpp

 2.D negative-rule probes for the C++ engine: the same twelve PKCS#11 v3.2
 rules as the Rust engine's ffi::negative_rule_probes_2d (rust/src/ffi.rs),
 driven through the real C_* entry points, with the same spec citations.

 Each asserted test states the SPEC-CORRECT outcome, so a failure is an engine
 gap. Probes whose failure on the current engine was predicted by reading the
 implementation carry an "EXPECTED GAP:" comment with the file:line that
 causes it. Probes 11 and 12 only RECORD the engine's answer (on stderr) and
 never fail: rule 11 is "probe first, then decide" on both engines; rule 12
 is asserted on the Rust side but recorded here until the C++ engine's
 behaviour has been measured.

 Written without a C++ build in reach (no container): every struct and
 constant used below was checked against src/lib/pkcs11/pkcs11t.h, and the
 calling patterns mirror existing tests (EcParamsErrorTests.cpp login helper,
 SymmetricAlgorithmTests.cpp C_WrapKey, MechanismInfoEcAdvertisementTests.cpp
 key-pair generation, ErrorPathTests.cpp C_MessageSignInit).
 *****************************************************************************/

#include <config.h>
#include "NegativeRuleProbesTests.h"
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

CPPUNIT_TEST_SUITE_REGISTRATION(NegativeRuleProbesTests);

namespace {

// TestsBase::setUp leaves the SO logged in on the token, so a USER login in
// the same library instance answers CKR_USER_ANOTHER_ALREADY_LOGGED_IN.
// Re-initialise first (the pattern EcParamsErrorTests / AcvpEcKeyVerTests use).
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

std::string hexRv(CK_RV rv)
{
	std::ostringstream s;
	s << "0x" << std::hex << (unsigned long)rv;
	return s.str();
}

// Session secret key (CKA_TOKEN=FALSE, CKA_PRIVATE=FALSE) of keyType with
// CKA_VALUE = value and each attribute in trueFlags set CK_TRUE. Optional
// extra attribute appended as-is. Returns the C_CreateObject rv.
CK_RV tryCreateSecret(CK_SESSION_HANDLE hSession, CK_KEY_TYPE keyType,
                      const std::vector<CK_BYTE>& value,
                      const std::vector<CK_ATTRIBUTE_TYPE>& trueFlags,
                      CK_OBJECT_HANDLE& hKey,
                      const CK_ATTRIBUTE* extra = NULL_PTR)
{
	static CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	static CK_BBOOL bTrue = CK_TRUE;
	static CK_BBOOL bFalse = CK_FALSE;
	CK_KEY_TYPE kt = keyType;
	std::vector<CK_ATTRIBUTE> t;
	t.push_back({ CKA_CLASS, &cls, sizeof(cls) });
	t.push_back({ CKA_KEY_TYPE, &kt, sizeof(kt) });
	t.push_back({ CKA_TOKEN, &bFalse, sizeof(bFalse) });
	t.push_back({ CKA_PRIVATE, &bFalse, sizeof(bFalse) });
	t.push_back({ CKA_VALUE, (CK_VOID_PTR)value.data(), (CK_ULONG)value.size() });
	for (CK_ATTRIBUTE_TYPE f : trueFlags)
		t.push_back({ f, &bTrue, sizeof(bTrue) });
	if (extra != NULL_PTR)
		t.push_back(*extra);
	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_CreateObject(hSession, t.data(), (CK_ULONG)t.size(), &hKey) );
}

CK_OBJECT_HANDLE createSecret(CK_SESSION_HANDLE hSession, CK_KEY_TYPE keyType,
                              const std::vector<CK_BYTE>& value,
                              const std::vector<CK_ATTRIBUTE_TYPE>& trueFlags)
{
	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
	CK_RV rv = tryCreateSecret(hSession, keyType, value, trueFlags, h);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("setup: C_CreateObject", (CK_RV)CKR_OK, rv);
	return h;
}

// Two-call C_GetAttributeValue (size query, then fetch).
CK_RV getAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE h,
              CK_ATTRIBUTE_TYPE type, std::vector<CK_BYTE>& out)
{
	out.clear();
	CK_ATTRIBUTE a = { type, NULL_PTR, 0 };
	CK_RV rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, h, &a, 1) );
	if (rv != CKR_OK) return rv;
	out.resize(a.ulValueLen);
	a.pValue = out.empty() ? NULL_PTR : out.data();
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, h, &a, 1) );
	if (rv == CKR_OK) out.resize(a.ulValueLen);
	return rv;
}

// ── SP 800-108 plumbing ─────────────────────────────────────────────────────

enum Mode { MODE_COUNTER, MODE_FEEDBACK, MODE_DOUBLE_PIPELINE };

const char* modeName(Mode m)
{
	switch (m)
	{
		case MODE_COUNTER:  return "Counter";
		case MODE_FEEDBACK: return "Feedback";
		default:            return "DoublePipeline";
	}
}

// One CK_PRF_DATA_PARAM.
enum SegKind
{
	SEG_ITER_COUNTER, // counter-mode ITERATION_VARIABLE: pValue -> CK_SP800_108_COUNTER_FORMAT
	SEG_ITER_NULL,    // feedback / double-pipeline ITERATION_VARIABLE: NULL, 0
	SEG_COUNTER,      // CK_SP800_108_COUNTER: pValue -> CK_SP800_108_COUNTER_FORMAT
	SEG_DKM,          // CK_SP800_108_DKM_LENGTH (SUM_OF_KEYS, big-endian, 32 bits)
	SEG_BYTES         // CK_SP800_108_BYTE_ARRAY
};

struct Seg
{
	SegKind kind;
	const char* bytes; // SEG_BYTES only
};

const Seg ITER_COUNTER = { SEG_ITER_COUNTER, NULL };
const Seg ITER_NULL = { SEG_ITER_NULL, NULL };
const Seg COUNTER = { SEG_COUNTER, NULL };
const Seg DKM = { SEG_DKM, NULL };
Seg bytesSeg(const char* s) { Seg r = { SEG_BYTES, s }; return r; }

// C_DeriveKey for `mode` over `segs`, against a fresh 32-byte generic secret
// base key (CKA_DERIVE=TRUE), deriving a 32-byte generic secret. Returns the
// rv; hOut receives the new handle (CK_INVALID_HANDLE when none).
CK_RV derive(CK_SESSION_HANDLE hSession, Mode mode, const std::vector<Seg>& segs,
             CK_OBJECT_HANDLE& hOut)
{
	hOut = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hBase = createSecret(hSession, CKK_GENERIC_SECRET,
	                                      std::vector<CK_BYTE>(32, 0x42), { CKA_DERIVE });

	CK_SP800_108_COUNTER_FORMAT counterFmt;
	memset(&counterFmt, 0, sizeof(counterFmt));
	counterFmt.bLittleEndian = CK_FALSE;
	counterFmt.ulWidthInBits = 32;
	CK_SP800_108_DKM_LENGTH_FORMAT dkmFmt;
	memset(&dkmFmt, 0, sizeof(dkmFmt));
	dkmFmt.dkmLengthMethod = CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS;
	dkmFmt.bLittleEndian = CK_FALSE;
	dkmFmt.ulWidthInBits = 32;

	std::vector<CK_PRF_DATA_PARAM> arr;
	for (const Seg& s : segs)
	{
		CK_PRF_DATA_PARAM p;
		memset(&p, 0, sizeof(p));
		switch (s.kind)
		{
			case SEG_ITER_COUNTER:
				p.type = CK_SP800_108_ITERATION_VARIABLE;
				p.pValue = &counterFmt;
				p.ulValueLen = sizeof(counterFmt);
				break;
			case SEG_ITER_NULL:
				p.type = CK_SP800_108_ITERATION_VARIABLE;
				p.pValue = NULL_PTR;
				p.ulValueLen = 0;
				break;
			case SEG_COUNTER:
				p.type = CK_SP800_108_COUNTER;
				p.pValue = &counterFmt;
				p.ulValueLen = sizeof(counterFmt);
				break;
			case SEG_DKM:
				p.type = CK_SP800_108_DKM_LENGTH;
				p.pValue = &dkmFmt;
				p.ulValueLen = sizeof(dkmFmt);
				break;
			case SEG_BYTES:
				p.type = CK_SP800_108_BYTE_ARRAY;
				p.pValue = (CK_VOID_PTR)s.bytes;
				p.ulValueLen = (CK_ULONG)strlen(s.bytes);
				break;
		}
		arr.push_back(p);
	}

	CK_BYTE iv[16];
	memset(iv, 0x11, sizeof(iv));

	// Counter and double pipeline: CK_SP800_108_KDF_PARAMS. Feedback:
	// CK_SP800_108_FEEDBACK_KDF_PARAMS. No additional derived keys.
	CK_SP800_108_KDF_PARAMS kp;
	memset(&kp, 0, sizeof(kp));
	kp.prfType = CKM_SHA256_HMAC;
	kp.ulNumberOfDataParams = (CK_ULONG)arr.size();
	kp.pDataParams = arr.empty() ? NULL_PTR : arr.data();
	kp.ulAdditionalDerivedKeys = 0;
	kp.pAdditionalDerivedKeys = NULL_PTR;

	CK_SP800_108_FEEDBACK_KDF_PARAMS fp;
	memset(&fp, 0, sizeof(fp));
	fp.prfType = CKM_SHA256_HMAC;
	fp.ulNumberOfDataParams = (CK_ULONG)arr.size();
	fp.pDataParams = arr.empty() ? NULL_PTR : arr.data();
	fp.ulIVLen = sizeof(iv);
	fp.pIV = iv;
	fp.ulAdditionalDerivedKeys = 0;
	fp.pAdditionalDerivedKeys = NULL_PTR;

	CK_MECHANISM mech;
	switch (mode)
	{
		case MODE_COUNTER:
			mech.mechanism = CKM_SP800_108_COUNTER_KDF;
			mech.pParameter = &kp;
			mech.ulParameterLen = sizeof(kp);
			break;
		case MODE_FEEDBACK:
			mech.mechanism = CKM_SP800_108_FEEDBACK_KDF;
			mech.pParameter = &fp;
			mech.ulParameterLen = sizeof(fp);
			break;
		default:
			mech.mechanism = CKM_SP800_108_DOUBLE_PIPELINE_KDF;
			mech.pParameter = &kp;
			mech.ulParameterLen = sizeof(kp);
			break;
	}

	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
	CK_ULONG valueLen = 32;
	CK_BBOOL bFalse = CK_FALSE;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_VALUE_LEN, &valueLen, sizeof(valueLen) }
	};
	return CRYPTOKI_F_PTR( C_DeriveKey(hSession, &mech, hBase, tmpl,
	                                   sizeof(tmpl)/sizeof(CK_ATTRIBUTE), &hOut) );
}

} // namespace

// ── 1. CKA_UNIQUE_ID ────────────────────────────────────────────────────────

// v3.2 §4.4.1: "Any time a new object is created, a value for CKA_UNIQUE_ID
// MUST be generated by the token ... values generated MUST be unique across
// all objects visible to any particular session ... Any attempt to modify the
// CKA_UNIQUE_ID attribute of an existing object or to specify the value of the
// CKA_UNIQUE_ID attribute in the template for an operation that creates one or
// more objects MUST fail. Operations failing for this reason return the error
// code CKR_ATTRIBUTE_READ_ONLY."
// Predicted to pass: P11AttrUniqueId::setDefault mints a UUID
// (P11Attributes.cpp:871) and updateAttr always answers CKR_ATTRIBUTE_READ_ONLY
// (P11Attributes.cpp:912-915).
void NegativeRuleProbesTests::testP01UniqueIdGeneratedUniqueAndReadOnly()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	const std::vector<CK_BYTE> v(32, 0x01);
	CK_OBJECT_HANDLE h1 = createSecret(hSession, CKK_GENERIC_SECRET, v, {});
	CK_OBJECT_HANDLE h2 = createSecret(hSession, CKK_GENERIC_SECRET, v, {});
	std::vector<CK_BYTE> id1, id2;
	CPPUNIT_ASSERT_EQUAL_MESSAGE("CKA_UNIQUE_ID readable (1)", (CK_RV)CKR_OK, getAttr(hSession, h1, CKA_UNIQUE_ID, id1));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("CKA_UNIQUE_ID readable (2)", (CK_RV)CKR_OK, getAttr(hSession, h2, CKA_UNIQUE_ID, id2));
	CPPUNIT_ASSERT_MESSAGE("CKA_UNIQUE_ID must be generated", !id1.empty() && !id2.empty());
	CPPUNIT_ASSERT_MESSAGE("two identical objects must get different CKA_UNIQUE_IDs", id1 != id2);

	// Supplied in a creation template -> CKR_ATTRIBUTE_READ_ONLY, no object.
	static const char forged[] = "forged-unique-id";
	CK_ATTRIBUTE forgedAttr = { CKA_UNIQUE_ID, (CK_VOID_PTR)forged, (CK_ULONG)strlen(forged) };
	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
	CK_RV rv = tryCreateSecret(hSession, CKK_GENERIC_SECRET, std::vector<CK_BYTE>(32, 0x02), {}, h, &forgedAttr);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("template-supplied CKA_UNIQUE_ID", (CK_RV)CKR_ATTRIBUTE_READ_ONLY, rv);
	CPPUNIT_ASSERT_MESSAGE("no object handle may be returned on failure", h == CK_INVALID_HANDLE);

	// Modifying it on an existing object -> CKR_ATTRIBUTE_READ_ONLY.
	CK_ATTRIBUTE set[] = { forgedAttr };
	CPPUNIT_ASSERT_EQUAL_MESSAGE("C_SetAttributeValue on CKA_UNIQUE_ID", (CK_RV)CKR_ATTRIBUTE_READ_ONLY,
	                             CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, h1, set, 1) ));
	std::vector<CK_BYTE> after;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, getAttr(hSession, h1, CKA_UNIQUE_ID, after));
	CPPUNIT_ASSERT_MESSAGE("CKA_UNIQUE_ID must be unchanged", after == id1);
}

// ── 2. CKA_TRUSTED is SO-only ───────────────────────────────────────────────

// v3.2 §4.2 Table 13 footnote 10 ("Can only be set to CK_TRUE by the SO
// user"), applied to CKA_TRUSTED in the certificate (§4.6.2 Table 21),
// public-key and secret-key attribute tables; §4.6.2 also says "The
// CKA_TRUSTED attribute cannot be set to CK_TRUE by an application." Neither
// names a return code; §4.1.1 rule 3 gives CKR_ATTRIBUTE_READ_ONLY for a value
// on an attribute that is read-only "under certain circumstances".
// Predicted to pass: P11AttrTrusted::updateAttr refuses TRUE without an SO
// login (P11Attributes.cpp:1313-1316); secret keys register it
// (P11Objects.cpp:1657).
void NegativeRuleProbesTests::testP02TrustedTrueRefusedInUserSession()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	const std::vector<CK_BYTE> v(16, 0x03);
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE trustedTrue = { CKA_TRUSTED, &bTrue, sizeof(bTrue) };
	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
	CK_RV rv = tryCreateSecret(hSession, CKK_AES, v, {}, h, &trustedTrue);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("C_CreateObject CKA_TRUSTED=TRUE as USER", (CK_RV)CKR_ATTRIBUTE_READ_ONLY, rv);
	CPPUNIT_ASSERT(h == CK_INVALID_HANDLE);

	CK_OBJECT_HANDLE hKey = createSecret(hSession, CKK_AES, v, {});
	CK_ATTRIBUTE set[] = { trustedTrue };
	CPPUNIT_ASSERT_EQUAL_MESSAGE("C_SetAttributeValue CKA_TRUSTED=TRUE as USER", (CK_RV)CKR_ATTRIBUTE_READ_ONLY,
	                             CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, hKey, set, 1) ));
	std::vector<CK_BYTE> trusted;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, getAttr(hSession, hKey, CKA_TRUSTED, trusted));
	CPPUNIT_ASSERT_MESSAGE("CKA_TRUSTED must stay FALSE", trusted.size() == 1 && trusted[0] == CK_FALSE);
}

// ── 3. CK_SP800_108_COUNTER invalid in counter mode ─────────────────────────

// v3.2 §6.42.3 Table 199: CK_SP800_108_COUNTER "This data field type is
// invalid for this KDF type." No specific CKR is named; §5.1.6's
// CKR_MECHANISM_PARAM_INVALID is the applicable generic code.
void NegativeRuleProbesTests::testP03CounterModeRejectsCounterDataParam()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
	CPPUNIT_ASSERT_EQUAL_MESSAGE("positive control: well-formed counter-mode derive", (CK_RV)CKR_OK,
	                             derive(hSession, MODE_COUNTER, { ITER_COUNTER, bytesSeg("label") }, h));

	// EXPECTED GAP: the counter-mode segment loop sends CK_SP800_108_COUNTER to
	// `default: break; // COUNTER, DKM_LENGTH, KEY_HANDLE not supported — skip`
	// (src/lib/SoftHSM_keygen.cpp:3697-3698), so the derive succeeds (CKR_OK).
	CK_RV rv = derive(hSession, MODE_COUNTER, { ITER_COUNTER, COUNTER, bytesSeg("label") }, h);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("CK_SP800_108_COUNTER in counter mode", (CK_RV)CKR_MECHANISM_PARAM_INVALID, rv);
	CPPUNIT_ASSERT(h == CK_INVALID_HANDLE);
}

// ── 4. At most one CK_SP800_108_DKM_LENGTH ──────────────────────────────────

// v3.2 §6.42.3 Table 199, §6.42.4 Table 200, §6.42.5 Table 201, each for
// CK_SP800_108_DKM_LENGTH: "If specified, only one instance of this type may be
// specified." Expected CKR_MECHANISM_PARAM_INVALID (generic, §5.1.6; the tables
// name no code).
void NegativeRuleProbesTests::testP04DkmLengthAtMostOneInstance()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	// EXPECTED GAP: all three C++ handlers skip CK_SP800_108_DKM_LENGTH
	// entirely — counter src/lib/SoftHSM_keygen.cpp:3697-3698, feedback
	// :4091-4092, double pipeline :4476-4477 ("DKM_LENGTH ... not supported —
	// skip") — so two instances (and even one) are silently ignored: CKR_OK.
	const Mode modes[] = { MODE_COUNTER, MODE_FEEDBACK, MODE_DOUBLE_PIPELINE };
	std::vector<std::pair<Mode, CK_RV> > results;
	for (Mode mode : modes)
	{
		const Seg iter = (mode == MODE_COUNTER) ? ITER_COUNTER : ITER_NULL;
		CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
		CK_RV one = derive(hSession, mode, { iter, bytesSeg("ctx"), DKM }, h);
		CPPUNIT_ASSERT_EQUAL_MESSAGE(std::string(modeName(mode)) + ": positive control with one DKM_LENGTH",
		                             (CK_RV)CKR_OK, one);
		CK_RV two = derive(hSession, mode, { iter, DKM, bytesSeg("ctx"), DKM }, h);
		std::cerr << "2.D p04 C++ " << modeName(mode) << ": two DKM_LENGTH -> " << hexRv(two) << std::endl;
		results.push_back(std::make_pair(mode, two));
	}
	for (size_t i = 0; i < results.size(); i++)
		CPPUNIT_ASSERT_EQUAL_MESSAGE(std::string(modeName(results[i].first)) + ": two DKM_LENGTH instances",
		                             (CK_RV)CKR_MECHANISM_PARAM_INVALID, results[i].second);
}

// ── 5. C_UnwrapKey length vs key type ───────────────────────────────────────

// v3.2 §5.18.4: "If any length conflict occurs between the key type of the
// unwrapped key, the output from the unwrapping mechanism, or the specified
// CKA_VALUE_LEN, then the function SHALL return CKR_WRAPPED_KEY_LEN_RANGE."
// §6.58.2 Table 254: ChaCha20 "Key length is fixed at 256 bits."
void NegativeRuleProbesTests::testP05UnwrapLengthConflictsWithKeyType()
{
#ifdef HAVE_AES_KEY_WRAP
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	CK_OBJECT_HANDLE hKek = createSecret(hSession, CKK_AES, std::vector<CK_BYTE>(16, 0x5a), { CKA_WRAP, CKA_UNWRAP });
	CK_OBJECT_HANDLE hTarget = createSecret(hSession, CKK_AES, std::vector<CK_BYTE>(16, 0xa5), { CKA_EXTRACTABLE });
	CK_MECHANISM mech = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
	CK_BYTE wrapped[64];
	CK_ULONG wrappedLen = sizeof(wrapped);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("setup: wrap a 16-byte key", (CK_RV)CKR_OK,
	                             CRYPTOKI_F_PTR( C_WrapKey(hSession, &mech, hKek, hTarget, wrapped, &wrappedLen) ));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("AES-KW of 16 bytes is 24 bytes", (CK_ULONG)24, wrappedLen);

	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_BBOOL bFalse = CK_FALSE;
	struct { CK_KEY_TYPE kt; CK_RV want; const char* what; } cases[] = {
		{ CKK_AES, CKR_OK, "control: 16 bytes unwrapped into CKK_AES" },
		// EXPECTED GAP: C_UnwrapKey stores the unwrapped bytes as CKA_VALUE and
		// sets CKA_VALUE_LEN from them with no check against the template's key
		// type (src/lib/SoftHSM_keygen.cpp:2529-2548; the only length checks,
		// :2236-2275, are on the wrapped input), so this returns CKR_OK and
		// makes a 128-bit ChaCha20 key.
		{ CKK_CHACHA20, CKR_WRAPPED_KEY_LEN_RANGE, "16 bytes unwrapped into CKK_CHACHA20" },
	};
	for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++)
	{
		CK_KEY_TYPE kt = cases[i].kt;
		CK_ATTRIBUTE tmpl[] = {
			{ CKA_CLASS, &cls, sizeof(cls) },
			{ CKA_KEY_TYPE, &kt, sizeof(kt) },
			{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
			{ CKA_PRIVATE, &bFalse, sizeof(bFalse) }
		};
		CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
		CK_RV rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mech, hKek, wrapped, wrappedLen,
		                                       tmpl, sizeof(tmpl)/sizeof(CK_ATTRIBUTE), &h) );
		CPPUNIT_ASSERT_EQUAL_MESSAGE(cases[i].what, cases[i].want, rv);
		if (cases[i].want != CKR_OK)
			CPPUNIT_ASSERT_MESSAGE("no handle on failure", h == CK_INVALID_HANDLE);
	}
#endif
}

// ── 6. CKF_SERIAL_SESSION always set ────────────────────────────────────────

// v3.2 §3.3 Table 7: CKF_SERIAL_SESSION "should always be set to true";
// §5.6.1: "the CKF_SERIAL_SESSION bit MUST always be set" (for C_OpenSession).
// C_GetSessionInfo is §5.6.4.
// Predicted to pass: Session::getInfo sets it unconditionally
// (src/lib/session_mgr/Session.cpp:128).
void NegativeRuleProbesTests::testP06SessionInfoSerialFlagAlwaysSet()
{
	CK_SESSION_HANDLE hRw;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hRw, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));
	CK_SESSION_HANDLE hRo;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION,
	                                                                   NULL_PTR, NULL_PTR, &hRo) ));
	struct { const char* name; CK_SESSION_HANDLE h; bool rw; } cases[] = {
		{ "RW", hRw, true },
		{ "RO", hRo, false },
	};
	for (size_t i = 0; i < 2; i++)
	{
		CK_SESSION_INFO info;
		memset(&info, 0, sizeof(info));
		CPPUNIT_ASSERT_EQUAL_MESSAGE(cases[i].name, (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_GetSessionInfo(cases[i].h, &info) ));
		CPPUNIT_ASSERT_MESSAGE(std::string(cases[i].name) + ": CKF_SERIAL_SESSION must be set",
		                       (info.flags & CKF_SERIAL_SESSION) != 0);
		CPPUNIT_ASSERT_MESSAGE(std::string(cases[i].name) + ": CKF_RW_SESSION",
		                       ((info.flags & CKF_RW_SESSION) != 0) == cases[i].rw);
	}
}

// ── 7. Every listed slot answers C_GetSlotInfo ──────────────────────────────

// v3.2 §5.5.1: "All slots which C_GetSlotList reports MUST be able to be
// queried as valid slots by C_GetSlotInfo."
// Predicted to pass: SlotManager::getSlotList lists only slots in its own map
// (src/lib/slot_mgr/SlotManager.cpp:102-165), and C_GetSlotInfo resolves any
// of them (src/lib/SoftHSM_slots.cpp:379-401).
void NegativeRuleProbesTests::testP07EveryListedSlotAnswersGetSlotInfo()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));
	const CK_BBOOL presence[] = { CK_FALSE, CK_TRUE };
	for (CK_BBOOL tokenPresent : presence)
	{
		CK_ULONG count = 0;
		CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_GetSlotList(tokenPresent, NULL_PTR, &count) ));
		CPPUNIT_ASSERT_MESSAGE("at least one slot", count >= 1);
		std::vector<CK_SLOT_ID> slots(count);
		CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_GetSlotList(tokenPresent, slots.data(), &count) ));
		slots.resize(count);
		for (CK_SLOT_ID slot : slots)
		{
			CK_SLOT_INFO info;
			std::ostringstream msg;
			msg << "tokenPresent=" << (int)tokenPresent << ": C_GetSlotInfo(" << (unsigned long)slot << ")";
			CPPUNIT_ASSERT_EQUAL_MESSAGE(msg.str(), (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_GetSlotInfo(slot, &info) ));
		}
	}
}

// ── 8. ulValueLen ignored on input for a size query ─────────────────────────

// v3.2 §5.7.5 step 3: "if the pValue field has the value NULL_PTR, then the
// ulValueLen field is modified to hold the exact length of the specified
// attribute for the object." The input ulValueLen plays no part in that case.
// Predicted to pass: P11Attribute::retrieve answers a NULL pValue before it
// reads *pulValueLen (src/lib/P11Attributes.cpp:312-316).
void NegativeRuleProbesTests::testP08SizeQueryIgnoresInputValueLen()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));
	CK_OBJECT_HANDLE h = createSecret(hSession, CKK_GENERIC_SECRET, std::vector<CK_BYTE>(32, 0x07), {});
	static const char label[] = "probe-label";
	CK_ATTRIBUTE set[] = { { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) } };
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, h, set, 1) ));

	const CK_ULONG garbage[] = { 0UL, 1UL, 0xdeadbeefUL, CK_UNAVAILABLE_INFORMATION };
	for (CK_ULONG g : garbage)
	{
		CK_ATTRIBUTE q = { CKA_LABEL, NULL_PTR, g };
		std::ostringstream msg;
		msg << "size query with input ulValueLen=0x" << std::hex << (unsigned long)g;
		CPPUNIT_ASSERT_EQUAL_MESSAGE(msg.str(), (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, h, &q, 1) ));
		CPPUNIT_ASSERT_EQUAL_MESSAGE(msg.str() + ": exact length out", (CK_ULONG)strlen(label), q.ulValueLen);
	}
}

// ── 9. C_GetAttributeValue continues past an invalid type ───────────────────

// v3.2 §5.7.5 step 2 (invalid attribute -> ulValueLen =
// CK_UNAVAILABLE_INFORMATION, call returns CKR_ATTRIBUTE_TYPE_INVALID) and
// "the call MUST nonetheless have processed every attribute in the template
// ... Each attribute in the template whose value can be returned ... will be
// returned".
// Predicted to pass: P11Object::loadTemplate marks the unknown type and
// `continue`s (src/lib/P11Objects.cpp:173-179).
void NegativeRuleProbesTests::testP09GetAttributeValueContinuesAfterInvalidType()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));
	CK_OBJECT_HANDLE h = createSecret(hSession, CKK_GENERIC_SECRET, std::vector<CK_BYTE>(32, 0x08), {});
	static const char label[] = "L9";
	CK_ATTRIBUTE set[] = { { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) } };
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_SetAttributeValue(hSession, h, set, 1) ));

	const CK_ATTRIBUTE_TYPE BOGUS = 0x7fff0f0fUL; // not a v3.2 attribute, below CKA_VENDOR_DEFINED
	CK_BYTE labelBuf[16];
	CK_BYTE bogusBuf[16];
	CK_OBJECT_CLASS classBuf = CKO_VENDOR_DEFINED;
	memset(labelBuf, 0, sizeof(labelBuf));
	memset(bogusBuf, 0xee, sizeof(bogusBuf));
	CK_ATTRIBUTE q[] = {
		{ CKA_LABEL, labelBuf, sizeof(labelBuf) },
		{ BOGUS, bogusBuf, sizeof(bogusBuf) },
		{ CKA_CLASS, &classBuf, sizeof(classBuf) }
	};
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_ATTRIBUTE_TYPE_INVALID, CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, h, q, 3) ));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("valid attribute before the bad one: length", (CK_ULONG)strlen(label), q[0].ulValueLen);
	CPPUNIT_ASSERT_MESSAGE("valid attribute before the bad one: value", memcmp(labelBuf, label, strlen(label)) == 0);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("invalid attribute: CK_UNAVAILABLE_INFORMATION",
	                             (CK_ULONG)CK_UNAVAILABLE_INFORMATION, q[1].ulValueLen);
	CK_BYTE untouched[16];
	memset(untouched, 0xee, sizeof(untouched));
	CPPUNIT_ASSERT_MESSAGE("invalid attribute's buffer untouched", memcmp(bogusBuf, untouched, sizeof(bogusBuf)) == 0);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("valid attribute after the bad one: length", (CK_ULONG)sizeof(classBuf), q[2].ulValueLen);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("valid attribute after the bad one: value", (CK_OBJECT_CLASS)CKO_SECRET_KEY, classBuf);
}

// ── 10. CKA_SIGN / CKA_VERIFY at message-based init ─────────────────────────

// v3.2 §5.14.1: "The CKA_SIGN attribute of the signature key ... MUST be
// CK_TRUE." §5.16.1: "The CKA_VERIFY attribute of the verification key ...
// MUST be CK_TRUE." Code: CKR_KEY_FUNCTION_NOT_PERMITTED (§5.1.6).
// Predicted to pass: C_MessageSignInit / C_MessageVerifyInit delegate to
// AsymSignInit / AsymVerifyInit (src/lib/SoftHSM_sign.cpp:3888-3890,
// 4044-4046), whose acquireSessionTokenKey refuses a FALSE usage attribute
// (src/lib/SoftHSM.cpp:313).
void NegativeRuleProbesTests::testP10MessageSignVerifyInitRequireUsageFlag()
{
#ifdef WITH_ECC
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	// P-256 by OID.
	CK_BYTE oidP256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };

	// usage = CK_TRUE -> (hPub with CKA_VERIFY, hPriv with CKA_SIGN) both TRUE; CK_FALSE -> both FALSE.
	auto genPair = [&](CK_BBOOL usage, CK_OBJECT_HANDLE& hPub, CK_OBJECT_HANDLE& hPriv) {
		CK_ATTRIBUTE pukAttribs[] = {
			{ CKA_EC_PARAMS, oidP256, sizeof(oidP256) },
			{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
			{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
			{ CKA_VERIFY, &usage, sizeof(usage) }
		};
		CK_ATTRIBUTE prkAttribs[] = {
			{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
			{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
			{ CKA_SIGN, &usage, sizeof(usage) }
		};
		hPub = hPriv = CK_INVALID_HANDLE;
		CPPUNIT_ASSERT_EQUAL_MESSAGE("setup: C_GenerateKeyPair P-256", (CK_RV)CKR_OK,
			CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &genMech,
			                                  pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
			                                  prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
			                                  &hPub, &hPriv) ));
	};

	CK_OBJECT_HANDLE hPubOk, hPrivOk, hPubNo, hPrivNo;
	genPair(CK_TRUE, hPubOk, hPrivOk);
	genPair(CK_FALSE, hPubNo, hPrivNo);

	// Positive controls: flag TRUE -> CKR_OK.
	CK_MECHANISM mech = { CKM_ECDSA, NULL_PTR, 0 };
	CPPUNIT_ASSERT_EQUAL_MESSAGE("control: C_MessageSignInit with CKA_SIGN=TRUE", (CK_RV)CKR_OK,
	                             CRYPTOKI_F_PTR( C_MessageSignInit(hSession, &mech, hPrivOk) ));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_MessageSignFinal(hSession) ));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("control: C_MessageVerifyInit with CKA_VERIFY=TRUE", (CK_RV)CKR_OK,
	                             CRYPTOKI_F_PTR( C_MessageVerifyInit(hSession, &mech, hPubOk) ));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_MessageVerifyFinal(hSession) ));

	// Flag FALSE -> CKR_KEY_FUNCTION_NOT_PERMITTED.
	CPPUNIT_ASSERT_EQUAL_MESSAGE("C_MessageSignInit with CKA_SIGN=FALSE", (CK_RV)CKR_KEY_FUNCTION_NOT_PERMITTED,
	                             CRYPTOKI_F_PTR( C_MessageSignInit(hSession, &mech, hPrivNo) ));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("C_MessageVerifyInit with CKA_VERIFY=FALSE", (CK_RV)CKR_KEY_FUNCTION_NOT_PERMITTED,
	                             CRYPTOKI_F_PTR( C_MessageVerifyInit(hSession, &mech, hPubNo) ));
#endif
}

// ── 11. ITERATION_VARIABLE absent (OBSERVED) ────────────────────────────────

// v3.2 §6.42.3 Table 199, §6.42.4 Table 200, §6.42.5 Table 201:
// CK_SP800_108_ITERATION_VARIABLE "This data field type is mandatory."
// Probe-first: record the engine's answer when it is absent. Not asserted.
// Read-predicted: CKR_OK in all three modes — each handler synthesises the
// missing variable (src/lib/SoftHSM_keygen.cpp:3706-3713 counter,
// :4097-4104 feedback, :4481-4488 double pipeline).
void NegativeRuleProbesTests::testP11ObserveMissingIterationVariable()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));
	const Mode modes[] = { MODE_COUNTER, MODE_FEEDBACK, MODE_DOUBLE_PIPELINE };
	for (Mode mode : modes)
	{
		CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
		CK_RV rv = derive(hSession, mode, { bytesSeg("label-and-context") }, h);
		std::string obs = std::string("2.D p11 OBSERVED C++ ") + modeName(mode) +
		                  ": no ITERATION_VARIABLE -> rv=" + hexRv(rv);
		std::cerr << obs << std::endl;
		CPPUNIT_ASSERT_MESSAGE(obs, true); // recorded, never fails
	}
}

// ── 12. Two CK_SP800_108_COUNTER (OBSERVED) ─────────────────────────────────

// v3.2 §6.42.4 Table 200 and §6.42.5 Table 201, CK_SP800_108_COUNTER: "If
// specified, only one instance of this type may be specified." The Rust engine
// now refuses a second instance with CKR_MECHANISM_PARAM_INVALID (its p12
// asserts it). Here the answer is recorded, not asserted.
// Read-predicted: CKR_OK in both modes — each COUNTER entry just appends
// another counter segment (src/lib/SoftHSM_keygen.cpp:4061-4075 feedback,
// :4449-4463 double pipeline) with no instance count.
void NegativeRuleProbesTests::testP12ObserveTwoCounterParams()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));
	const Mode modes[] = { MODE_FEEDBACK, MODE_DOUBLE_PIPELINE };
	for (Mode mode : modes)
	{
		CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
		CK_RV one = derive(hSession, mode, { ITER_NULL, COUNTER, bytesSeg("ctx") }, h);
		CK_RV two = derive(hSession, mode, { ITER_NULL, COUNTER, bytesSeg("ctx"), COUNTER }, h);
		std::string obs = std::string("2.D p12 OBSERVED C++ ") + modeName(mode) +
		                  ": one COUNTER -> " + hexRv(one) + "; two COUNTER -> rv=" + hexRv(two) +
		                  " (spec: CKR_MECHANISM_PARAM_INVALID)";
		std::cerr << obs << std::endl;
		CPPUNIT_ASSERT_MESSAGE(obs, true); // recorded, never fails
	}
}

// CK_SP800_108_DKM_LENGTH in all three SP 800-108 modes, both methods, widths
// 8/16/32/64 and both byte orders (plan 2.D, p04). Until 2026-09-27 this engine
// skipped the field entirely, deriving different bytes from the spec and from
// the Rust engine under CKR_OK. Oracle: an independent Python reference written
// from PKCS#11 v3.2 §6.42 / NIST SP 800-108 (HMAC-SHA256, key 0x0b*32, fixed
// input "dkm-label", 42-byte output, feedback IV empty). NIST ACVP has no
// DKM-length vectors. The Rust engine's dkm_length_reference_tests pins the
// same 24 values — the cross-engine byte match.
void NegativeRuleProbesTests::testDkmLengthMatchesReference()
{
	CK_SESSION_HANDLE hSession;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, login(hSession, m_initializedTokenSlotID, m_userPin1, m_userPin1Length));

	struct V { CK_MECHANISM_TYPE mech; CK_ULONG method; CK_ULONG width; CK_BBOOL le; const char* hex; };
	static const V vecs[] = {
		{ CKM_SP800_108_COUNTER_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 8, CK_FALSE, "116609ac4d2d7960af94e3fe089959ec66b9b4550226ded1877029f8d622e7cc5e96e0a0ef230c292967" },
		{ CKM_SP800_108_COUNTER_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 16, CK_TRUE, "c0e3cb82ea48581546a89154bbecf9d9c1162e8e1bd77268467173c610122a219f433cb1d2af792134bd" },
		{ CKM_SP800_108_COUNTER_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 32, CK_FALSE, "2968a086903a5bdc5c4fe4b1aab292d86fb42303542990ad82544fec1c97c299cd435803ebd267ac2314" },
		{ CKM_SP800_108_COUNTER_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 64, CK_TRUE, "bdb77c3565707b931551ef04aab39e57208949afabe28ebde72b1e2033c221141211ea6f1b62d231719d" },
		{ CKM_SP800_108_COUNTER_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 8, CK_FALSE, "58c5400989d378291880cad48d368974ae19941158846ffe3e6cafe9d2806660c888569115dc3bbd3f5d" },
		{ CKM_SP800_108_COUNTER_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 16, CK_TRUE, "1d7bbfc7be8d4ab4ac23c0d1c6c2a6cd9ec5bef507994cb0a4d25f3fad1c2e17374caa747e54a73a9ec0" },
		{ CKM_SP800_108_COUNTER_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 32, CK_FALSE, "235c202255b58966676d649fd8e18f540c6512fc3a86e939129ff2226ab94931408392067140cb6b74f4" },
		{ CKM_SP800_108_COUNTER_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 64, CK_TRUE, "2f76a30ff2be8f42c52f79926f2c87053838422cc7193092ba4aee95af52b64ab00e0731c55f4e545b6e" },
		{ CKM_SP800_108_FEEDBACK_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 8, CK_FALSE, "30b1292a96cb61e9609ba4c565f87e206d52690102c4da13aa739b2212cd89d914b13e163385e27f2b6c" },
		{ CKM_SP800_108_FEEDBACK_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 16, CK_TRUE, "dd4d4cffb9d40b7a56a66110633daef6a05c8edac473c63900a799801e90d8a41524707d4c8e22607117" },
		{ CKM_SP800_108_FEEDBACK_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 32, CK_FALSE, "e3561de9888a3b3302c84ba1a4a7103a207514116619192534c97616730a93226d4b8aad8fc513a8b485" },
		{ CKM_SP800_108_FEEDBACK_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 64, CK_TRUE, "34d61a57e703883764bc954338c102970632b1eb262051ae05f2ac03efddb415da0f1519cebff976f2ac" },
		{ CKM_SP800_108_FEEDBACK_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 8, CK_FALSE, "1b51da43f48f6a43d90dd7e79af474bf016eb9b5595c81096ba7635e1cc500ed036f94445dc368f5308a" },
		{ CKM_SP800_108_FEEDBACK_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 16, CK_TRUE, "d82dc7cb5e4a4da0152a9bcf30bb5abd36fc90bff1356ad5dc7d5a4add7199a81b718720e3e6b87d944e" },
		{ CKM_SP800_108_FEEDBACK_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 32, CK_FALSE, "a43be4ebc17a4459856d50d2e84678814a39ff0919bd2260a61317bde6f2b4643c7fcd84af7877cd6f0c" },
		{ CKM_SP800_108_FEEDBACK_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 64, CK_TRUE, "c8fc228568bffd6904b8bedf2e09bf316fc312fbe6ae02ae80a09e71336633df28c0b66a1a7f09847f75" },
		{ CKM_SP800_108_DOUBLE_PIPELINE_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 8, CK_FALSE, "14b13e163385e27f2b6c8df28d123e505249f270baf93b1c81db2de76b9601dde7013b4999da4356de1d" },
		{ CKM_SP800_108_DOUBLE_PIPELINE_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 16, CK_TRUE, "1524707d4c8e22607117e5c2e13e86b5a15e8272cb686e0b0026fd6fc5abdc2fbc9ab8f358feb0ed7005" },
		{ CKM_SP800_108_DOUBLE_PIPELINE_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 32, CK_FALSE, "6d4b8aad8fc513a8b4855a5e8c741442b732d86ed37737b9bb5bfb0bd9f010b5b9d6218679518f350da7" },
		{ CKM_SP800_108_DOUBLE_PIPELINE_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, 64, CK_TRUE, "da0f1519cebff976f2ac910c984113d737321969402fa1990630fb7f1897556027e84b1a9a87cc7b4318" },
		{ CKM_SP800_108_DOUBLE_PIPELINE_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 8, CK_FALSE, "036f94445dc368f5308a37a93f86b7971a344f84bce7a1ea74e2c43ee70c885f682c9958e8e87a4389b3" },
		{ CKM_SP800_108_DOUBLE_PIPELINE_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 16, CK_TRUE, "1b718720e3e6b87d944e41086637032802d99c7dee85532c3ea446f85ac8bbb301213a383b3544974fe5" },
		{ CKM_SP800_108_DOUBLE_PIPELINE_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 32, CK_FALSE, "3c7fcd84af7877cd6f0ccb9813add7516b3de37a40976bbacb7f6a824f624db2fa7e5e4971debea58b45" },
		{ CKM_SP800_108_DOUBLE_PIPELINE_KDF, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, 64, CK_TRUE, "28c0b66a1a7f09847f75edea6492a25d7623dfd105b8e181ec48f7f1225b0e7368bf71a9fae902cc0835" },
	};
	CK_BYTE key[32];
	memset(key, 0x0b, sizeof(key));
	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
	CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
	CK_ATTRIBUTE baseT[] = {
		{ CKA_CLASS, &cls, sizeof(cls) }, { CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) }, { CKA_DERIVE, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE, key, sizeof(key) },
	};
	CK_OBJECT_HANDLE hBase = CK_INVALID_HANDLE;
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_CreateObject(hSession, baseT, 5, &hBase) ));

	static CK_BYTE label[] = { 'd','k','m','-','l','a','b','e','l' };
	for (const V& v : vecs)
	{
		CK_SP800_108_COUNTER_FORMAT cf = { CK_FALSE, 32 };
		CK_SP800_108_DKM_LENGTH_FORMAT df = { v.method, v.le, v.width };
		CK_PRF_DATA_PARAM segs[3];
		if (v.mech == CKM_SP800_108_COUNTER_KDF)
			segs[0] = { CK_SP800_108_ITERATION_VARIABLE, &cf, sizeof(cf) };
		else
			segs[0] = { CK_SP800_108_ITERATION_VARIABLE, NULL_PTR, 0 };
		segs[1] = { CK_SP800_108_BYTE_ARRAY, label, sizeof(label) };
		segs[2] = { CK_SP800_108_DKM_LENGTH, &df, sizeof(df) };
		CK_SP800_108_KDF_PARAMS kp = { CKM_SHA256_HMAC, 3, segs, 0, NULL_PTR };
		CK_SP800_108_FEEDBACK_KDF_PARAMS fp = { CKM_SHA256_HMAC, 3, segs, 0, NULL_PTR, 0, NULL_PTR };
		CK_MECHANISM m = { v.mech, NULL_PTR, 0 };
		if (v.mech == CKM_SP800_108_FEEDBACK_KDF) { m.pParameter = &fp; m.ulParameterLen = sizeof(fp); }
		else { m.pParameter = &kp; m.ulParameterLen = sizeof(kp); }
		CK_ULONG outLen = 42;
		CK_ATTRIBUTE dt[] = {
			{ CKA_CLASS, &cls, sizeof(cls) }, { CKA_KEY_TYPE, &kt, sizeof(kt) },
			{ CKA_VALUE_LEN, &outLen, sizeof(outLen) }, { CKA_TOKEN, &bFalse, sizeof(bFalse) },
			{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }, { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		};
		CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
		std::string what = std::string("mech=") + std::to_string(v.mech) + " method=" + std::to_string(v.method) +
		                   " width=" + std::to_string(v.width) + " le=" + std::to_string((int)v.le);
		CK_RV rv = CRYPTOKI_F_PTR( C_DeriveKey(hSession, &m, hBase, dt, 6, &h) );
		CPPUNIT_ASSERT_EQUAL_MESSAGE(what, (CK_RV)CKR_OK, rv);
		CK_BYTE val[64];
		CK_ATTRIBUTE va = { CKA_VALUE, val, sizeof(val) };
		CPPUNIT_ASSERT_EQUAL_MESSAGE(what, (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, h, &va, 1) ));
		std::string got;
		static const char* d = "0123456789abcdef";
		for (CK_ULONG i = 0; i < va.ulValueLen; i++) { got += d[val[i] >> 4]; got += d[val[i] & 15]; }
		CPPUNIT_ASSERT_EQUAL_MESSAGE(what + ": DKM bytes differ from the reference", std::string(v.hex), got);
	}
}
