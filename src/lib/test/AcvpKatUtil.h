/*****************************************************************************
 AcvpKatUtil.h

 Shared helpers for the NIST ACVP known-answer suites in this directory
 (AcvpSlhDsaTests, MlKemInputCheckTests, KmacParamsTests,
 MacKdfPolicyTests): load a vector file from tests/acvp/ (the directory
 whose provenance scripts/check_acvp_provenance.py re-verifies on every
 gate run) and decode its hex fields. Every verdict these suites assert is
 the upstream vector's own — nothing here derives an expected value.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ACVPKATUTIL_H
#define _SOFTHSM_V2_ACVPKATUTIL_H

#include <cppunit/extensions/HelperMacros.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "json.hpp"  // tests/json.hpp (nlohmann/json 3.11.3)

#ifndef ACVP_VECTOR_DIR
#error "ACVP_VECTOR_DIR must point at tests/acvp (set by src/lib/test/CMakeLists.txt)"
#endif

namespace acvpkat {

inline nlohmann::json load(const char* file)
{
	const std::string path = std::string(ACVP_VECTOR_DIR) + "/" + file;
	std::ifstream in(path);
	CPPUNIT_ASSERT_MESSAGE("cannot open ACVP vector file " + path, in.good());
	nlohmann::json j;
	in >> j;
	return j;
}

inline std::vector<unsigned char> hex(const std::string& h)
{
	CPPUNIT_ASSERT_MESSAGE("odd-length hex string", h.size() % 2 == 0);
	std::vector<unsigned char> out(h.size() / 2);
	for (size_t i = 0; i < out.size(); i++)
		out[i] = (unsigned char)std::stoul(h.substr(2 * i, 2), NULL, 16);
	return out;
}

// Upstream JSON hex fields are strings; an absent/empty one is an empty
// byte string (e.g. SLH-DSA "context": "").
inline std::vector<unsigned char> hexField(const nlohmann::json& t, const char* name)
{
	if (!t.contains(name) || t[name].is_null()) return std::vector<unsigned char>();
	return hex(t[name].get<std::string>());
}

// Accumulates per-case failures so one run reports EVERY failing case (the
// fail-before evidence), then fails the test once at the end.
struct Failures
{
	std::vector<std::string> items;
	size_t checked = 0;
	void check(bool ok, const std::string& what)
	{
		checked++;
		if (!ok) items.push_back(what);
	}
	void assertNone(const std::string& suite) const
	{
		std::ostringstream os;
		os << suite << ": " << items.size() << " of " << checked << " case check(s) failed";
		for (const std::string& s : items) os << "\n  - " << s;
		CPPUNIT_ASSERT_MESSAGE(os.str(), items.empty());
		CPPUNIT_ASSERT_MESSAGE(suite + ": no case was checked", checked > 0);
	}
};

// A zero-length message still needs a non-NULL pData: PKCS#11 treats a NULL
// pData as CKR_ARGUMENTS_BAD, which does not end the active operation.
inline unsigned char* dataPtr(std::vector<unsigned char>& v)
{
	static unsigned char empty[1] = { 0 };
	return v.empty() ? empty : v.data();
}

inline std::string rvHex(unsigned long rv)
{
	std::ostringstream os;
	os << "0x" << std::hex << rv;
	return os.str();
}

} // namespace acvpkat

#endif // !_SOFTHSM_V2_ACVPKATUTIL_H
