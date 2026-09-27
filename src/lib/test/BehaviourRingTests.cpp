/*
 * Copyright (c) 2026 pqctoday
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BehaviourRingTests.cpp

 Contains test cases for the behaviour event ring writer. The golden vectors
 asserted here are the same ones rust/src/behaviour/mod.rs asserts: both
 engines encoding the same inputs to the same bytes is what makes one ring
 file readable regardless of which engine wrote a slot.
 *****************************************************************************/

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "BehaviourRingTests.h"
#include "BehaviourRing.h"
#include "BehaviourIds.h"

#ifndef _WIN32
#include <unistd.h>
#endif

CPPUNIT_TEST_SUITE_REGISTRATION(BehaviourRingTests);

namespace
{
	std::string tempRing(const char* tag)
	{
		char buf[256];
		snprintf(buf, sizeof(buf), "behaviour-%s-%ld.ring", tag, (long)getpid());
		unlink(buf);
		return std::string(buf);
	}

	// Minimal reader mirroring rust behaviour::read_all: header fields plus
	// every slot whose seq matches its index.
	struct Snapshot
	{
		uint32_t magic, version, slots, slotBytes, tableVersion;
		uint64_t head, lost;
		std::vector<uint64_t> records;
	};

	bool readAll(const std::string& path, Snapshot& out)
	{
		FILE* f = fopen(path.c_str(), "rb");
		if (f == NULL) return false;
		std::vector<unsigned char> bytes;
		unsigned char chunk[4096];
		size_t n;
		while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) bytes.insert(bytes.end(), chunk, chunk + n);
		fclose(f);
		if (bytes.size() < BehaviourRing::HEADER_BYTES) return false;
		memcpy(&out.magic,        &bytes[0],  4);
		memcpy(&out.version,      &bytes[4],  4);
		memcpy(&out.slots,        &bytes[8],  4);
		memcpy(&out.slotBytes,    &bytes[12], 4);
		memcpy(&out.head,         &bytes[16], 8);
		memcpy(&out.tableVersion, &bytes[32], 4);
		out.records.clear();
		const uint64_t start = out.head > out.slots ? out.head - out.slots : 0;
		out.lost = start;
		for (uint64_t i = start; i < out.head; ++i)
		{
			const size_t off = BehaviourRing::HEADER_BYTES + (size_t)(i & (out.slots - 1)) * BehaviourRing::SLOT_BYTES;
			uint64_t rec, seq;
			memcpy(&rec, &bytes[off], 8);
			memcpy(&seq, &bytes[off + 8], 8);
			if (seq == i + 1) out.records.push_back(rec);
		}
		return true;
	}
}

void BehaviourRingTests::setUp()
{
	BehaviourRing::shutdown();
}

void BehaviourRingTests::tearDown()
{
	BehaviourRing::shutdown();
}

void BehaviourRingTests::testBuckets()
{
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::log2Bucket(0), 0);
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::log2Bucket(1), 0);
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::log2Bucket(2), 1);
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::log2Bucket(3), 1);
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::log2Bucket(1024), 10);
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::log2Bucket(1500), 10);
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::log2Bucket(~(uint64_t)0), 63);

	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::clientBucket(NULL), 0);
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::clientBucket(""), 0);
	CPPUNIT_ASSERT(BehaviourRing::clientBucket("cn=learner-1") >= 1);
	CPPUNIT_ASSERT_EQUAL((int)BehaviourRing::clientBucket("10.0.0.7:51234"),
	                     (int)BehaviourRing::clientBucket("10.0.0.7:51234"));
}

void BehaviourRingTests::testGoldenVectors()
{
	for (size_t i = 0; i < BehaviourIds::VECTOR_COUNT; ++i)
	{
		const BehaviourIds::Vector& v = BehaviourIds::VECTORS[i];
		BehaviourRing::Record r;
		r.src     = v.src;
		r.op      = v.op;
		r.alg     = v.alg;
		r.result  = v.result;
		r.client  = v.client;
		r.size    = BehaviourRing::log2Bucket(v.sizeBytes);
		r.latency = BehaviourRing::log2Bucket(v.latencyUs);
		r.dt      = (v.dtUs < 0) ? 255 : BehaviourRing::log2Bucket((uint64_t)v.dtUs);
		char msg[96];
		snprintf(msg, sizeof(msg), "vector %zu (src %u op %u)", i, (unsigned)v.src, (unsigned)v.op);
		CPPUNIT_ASSERT_EQUAL_MESSAGE(msg, (unsigned long long)v.expected, (unsigned long long)BehaviourRing::encode(r));
	}
}

void BehaviourRingTests::testIdTables()
{
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::ALG_ML_DSA_65, (int)BehaviourIds::algFromCkm(CKM_ML_DSA, 2));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::ALG_ML_DSA_87, (int)BehaviourIds::algFromCkm(CKM_ML_DSA_KEY_PAIR_GEN, 3));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::ALG_ML_KEM_768, (int)BehaviourIds::algFromCkm(CKM_ML_KEM, 2));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::ALG_EDDSA, (int)BehaviourIds::algFromCkm(CKM_EDDSA, 0));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::ALG_RSA, (int)BehaviourIds::algFromCkm(CKM_RSA_PKCS_PSS, 7));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::ALG_OTHER, (int)BehaviourIds::algFromCkm(0xdeadbeefUL, 0));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::ALG_OTHER, (int)BehaviourIds::algFromCkm(CKM_ML_DSA, 9));

	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::RESULT_OK, (int)BehaviourIds::resultFromCkr(CKR_OK));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::RESULT_AUTH_FAIL, (int)BehaviourIds::resultFromCkr(CKR_USER_NOT_LOGGED_IN));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::RESULT_AUTH_FAIL, (int)BehaviourIds::resultFromCkr(CKR_PIN_INCORRECT));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::RESULT_INTERNAL_ERROR, (int)BehaviourIds::resultFromCkr(CKR_FUNCTION_FAILED));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::RESULT_CALLER_ERROR, (int)BehaviourIds::resultFromCkr(CKR_MECHANISM_INVALID));
	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::RESULT_CALLER_ERROR, (int)BehaviourIds::resultFromCkr(CKR_SIGNATURE_INVALID));

	CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::SRC_P11_REMOTING_REST, (int)BehaviourIds::srcFromName("p11-remoting-rest"));
	CPPUNIT_ASSERT_EQUAL(0, (int)BehaviourIds::srcFromName("nope"));
	CPPUNIT_ASSERT_EQUAL(0, (int)BehaviourIds::srcFromName(NULL));
}

void BehaviourRingTests::testRingWriteAndReadBack()
{
	const std::string path = tempRing("basic");
	CPPUNIT_ASSERT(!BehaviourRing::enabled());
	CPPUNIT_ASSERT(BehaviourRing::openAt(path.c_str(), 16));
	CPPUNIT_ASSERT(BehaviourRing::enabled());
	CPPUNIT_ASSERT_EQUAL(0ULL, (unsigned long long)BehaviourRing::head());

	for (uint8_t i = 0; i < 5; ++i)
		BehaviourRing::emit(BehaviourRing::p11(i, BehaviourIds::ALG_NONE, CKR_OK, 0, 0));

	Snapshot s;
	CPPUNIT_ASSERT(readAll(path, s));
	CPPUNIT_ASSERT_EQUAL((unsigned long)BehaviourRing::MAGIC, (unsigned long)s.magic);
	CPPUNIT_ASSERT_EQUAL((unsigned long)BehaviourRing::FORMAT_VERSION, (unsigned long)s.version);
	CPPUNIT_ASSERT_EQUAL(16UL, (unsigned long)s.slots);
	CPPUNIT_ASSERT_EQUAL((unsigned long)BehaviourRing::SLOT_BYTES, (unsigned long)s.slotBytes);
	CPPUNIT_ASSERT_EQUAL((unsigned long)BehaviourIds::TABLE_VERSION, (unsigned long)s.tableVersion);
	CPPUNIT_ASSERT_EQUAL(5ULL, (unsigned long long)s.head);
	CPPUNIT_ASSERT_EQUAL(0ULL, (unsigned long long)s.lost);
	CPPUNIT_ASSERT_EQUAL((size_t)5, s.records.size());
	for (size_t i = 0; i < 5; ++i)
	{
		CPPUNIT_ASSERT_EQUAL((int)BehaviourIds::SRC_P11_LOCAL, (int)(s.records[i] & 0xff));
		CPPUNIT_ASSERT_EQUAL((int)i, (int)((s.records[i] >> 8) & 0xff));
	}
	CPPUNIT_ASSERT_EQUAL(255, (int)(s.records[0] >> 56));      // first record: no predecessor
	CPPUNIT_ASSERT((int)(s.records[1] >> 56) < 255);             // second: a real gap

	BehaviourRing::shutdown();
	CPPUNIT_ASSERT(!BehaviourRing::enabled());
	unlink(path.c_str());
}

void BehaviourRingTests::testRingWrapAndGeometryRefusal()
{
	const std::string path = tempRing("wrap");
	CPPUNIT_ASSERT(BehaviourRing::openAt(path.c_str(), 8));
	for (uint8_t i = 0; i < 20; ++i)
		BehaviourRing::emit(BehaviourRing::p11(i, BehaviourIds::ALG_NONE, CKR_OK, 0, 0));

	Snapshot s;
	CPPUNIT_ASSERT(readAll(path, s));
	CPPUNIT_ASSERT_EQUAL(20ULL, (unsigned long long)s.head);
	CPPUNIT_ASSERT_EQUAL(12ULL, (unsigned long long)s.lost);
	CPPUNIT_ASSERT_EQUAL((size_t)8, s.records.size());
	for (size_t i = 0; i < 8; ++i)
		CPPUNIT_ASSERT_EQUAL((int)(12 + i), (int)((s.records[i] >> 8) & 0xff));

	// Re-opening the same file with a different slot count is refused and the
	// file is left alone.
	BehaviourRing::shutdown();
	CPPUNIT_ASSERT(!BehaviourRing::openAt(path.c_str(), 32));
	CPPUNIT_ASSERT(!BehaviourRing::enabled());
	Snapshot again;
	CPPUNIT_ASSERT(readAll(path, again));
	CPPUNIT_ASSERT_EQUAL(8UL, (unsigned long)again.slots);
	CPPUNIT_ASSERT_EQUAL(20ULL, (unsigned long long)again.head);

	// A non-ring file is refused and untouched.
	const std::string bogus = tempRing("bogus");
	FILE* f = fopen(bogus.c_str(), "wb");
	CPPUNIT_ASSERT(f != NULL);
	fputs("not a ring", f);
	fclose(f);
	CPPUNIT_ASSERT(!BehaviourRing::openAt(bogus.c_str(), 16));
	f = fopen(bogus.c_str(), "rb");
	char buf[32] = {0};
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	CPPUNIT_ASSERT_EQUAL(std::string("not a ring"), std::string(buf, n));

	unlink(path.c_str());
	unlink(bogus.c_str());
}
