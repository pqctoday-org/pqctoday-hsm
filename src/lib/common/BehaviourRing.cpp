/*
 * Copyright (c) 2026 pqctoday
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BehaviourRing.cpp

 Implements the behaviour event ring writer. See BehaviourRing.h for the
 record and file layout, and rust/src/behaviour/mod.rs for the Rust twin this
 must stay byte-compatible with.
 *****************************************************************************/

#include "config.h"
#include "BehaviourRing.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace BehaviourRing
{
	bool gEnabled = false;
}

namespace
{
	const size_t OFF_MAGIC      = 0;
	const size_t OFF_VERSION    = 4;
	const size_t OFF_SLOTS      = 8;
	const size_t OFF_SLOT_BYTES = 12;
	const size_t OFF_HEAD       = 16;
	const size_t OFF_CREATED    = 24;
	const size_t OFF_TABLE      = 32;

	unsigned char* gBase   = NULL;
	size_t         gLen    = 0;
	uint64_t       gMask   = 0;
	uint64_t       gLastNs = 0;   // 0 = no record yet from this process
	uint8_t        gSrc    = 0;   // resolved once from PQC_BEHAVIOUR_SRC

	inline uint32_t* u32At(size_t off) { return reinterpret_cast<uint32_t*>(gBase + off); }
	inline uint64_t* u64At(size_t off) { return reinterpret_cast<uint64_t*>(gBase + off); }

	uint64_t nowNanos()
	{
#if !defined(_WIN32) && defined(CLOCK_MONOTONIC)
		struct timespec ts;
		if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
			return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
		return (uint64_t)time(NULL) * 1000000000ULL;
	}

	uint64_t epochMillis()
	{
#if defined(CLOCK_REALTIME)
		struct timespec ts;
		if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
			return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
#endif
		return (uint64_t)time(NULL) * 1000ULL;
	}
}

uint64_t BehaviourRing::nowMicros()
{
	return nowNanos() / 1000ULL;
}

uint8_t BehaviourRing::log2Bucket(uint64_t v)
{
	if (v == 0) return 0;
	uint8_t b = 0;
	while (v >>= 1) ++b;
	return b;
}

uint8_t BehaviourRing::clientBucket(const char* identity)
{
	if (identity == NULL || identity[0] == '\0') return 0;
	uint32_t h = 0x811c9dc5UL;
	for (const unsigned char* p = (const unsigned char*)identity; *p; ++p)
	{
		h ^= (uint32_t)*p;
		h *= 0x01000193UL;
	}
	return (uint8_t)(1 + (h % 255));
}

uint64_t BehaviourRing::encode(const Record& r)
{
	return (uint64_t)r.src
	     | ((uint64_t)r.op      << 8)
	     | ((uint64_t)r.alg     << 16)
	     | ((uint64_t)r.result  << 24)
	     | ((uint64_t)r.client  << 32)
	     | ((uint64_t)r.size    << 40)
	     | ((uint64_t)r.latency << 48)
	     | ((uint64_t)r.dt      << 56);
}

uint8_t BehaviourRing::p11Src()
{
	if (gSrc == 0)
	{
		const uint8_t fromEnv = BehaviourIds::srcFromName(getenv("PQC_BEHAVIOUR_SRC"));
		gSrc = (fromEnv != 0) ? fromEnv : BehaviourIds::SRC_P11_LOCAL;
	}
	return gSrc;
}

BehaviourRing::Record BehaviourRing::p11(uint8_t op, uint8_t alg, CK_RV rv, uint64_t sizeBytes, uint64_t latencyUs)
{
	Record r;
	r.src     = p11Src();
	r.op      = op;
	r.alg     = alg;
	r.result  = BehaviourIds::resultFromCkr((unsigned long)rv);
	r.client  = 0;
	r.size    = log2Bucket(sizeBytes);
	r.latency = log2Bucket(latencyUs);
	r.dt      = 0;
	return r;
}

#ifndef _WIN32

bool BehaviourRing::openAt(const char* path, uint32_t slots)
{
	if (gBase != NULL) return true;   // already mapped
	if (path == NULL || path[0] == '\0') return false;
	if (slots == 0 || (slots & (slots - 1)) != 0) return false;

	const size_t len = HEADER_BYTES + (size_t)slots * SLOT_BYTES;

	// Elect an initialiser with O_EXCL: whoever creates the file sizes it and
	// writes the header, publishing the magic last; everyone else waits for
	// the magic and then checks the geometry.
	bool initialiser = true;
	int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0660);
	if (fd < 0)
	{
		initialiser = false;
		fd = open(path, O_RDWR);
		if (fd < 0)
		{
			fprintf(stderr, "pqc-behaviour: cannot open ring %s: %s; behaviour ring disabled\n", path, strerror(errno));
			return false;
		}
		struct stat st;
		if (fstat(fd, &st) != 0 || (size_t)st.st_size != len)
		{
			fprintf(stderr, "pqc-behaviour: ring %s is %lld bytes, expected %zu; behaviour ring disabled\n",
			        path, (long long)st.st_size, len);
			close(fd);
			return false;
		}
	}
	else if (ftruncate(fd, (off_t)len) != 0)
	{
		fprintf(stderr, "pqc-behaviour: cannot size ring %s: %s; behaviour ring disabled\n", path, strerror(errno));
		close(fd);
		unlink(path);
		return false;
	}

	void* base = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (base == MAP_FAILED)
	{
		fprintf(stderr, "pqc-behaviour: cannot map ring %s: %s; behaviour ring disabled\n", path, strerror(errno));
		return false;
	}
	gBase = (unsigned char*)base;
	gLen  = len;
	gMask = (uint64_t)slots - 1;

	if (initialiser)
	{
		__atomic_store_n(u32At(OFF_VERSION),    FORMAT_VERSION,            __ATOMIC_RELAXED);
		__atomic_store_n(u32At(OFF_SLOTS),      slots,                     __ATOMIC_RELAXED);
		__atomic_store_n(u32At(OFF_SLOT_BYTES), (uint32_t)SLOT_BYTES,      __ATOMIC_RELAXED);
		__atomic_store_n(u32At(OFF_TABLE),      BehaviourIds::TABLE_VERSION, __ATOMIC_RELAXED);
		__atomic_store_n(u64At(OFF_HEAD),       (uint64_t)0,               __ATOMIC_RELAXED);
		__atomic_store_n(u64At(OFF_CREATED),    epochMillis(),             __ATOMIC_RELAXED);
		__atomic_store_n(u32At(OFF_MAGIC),      MAGIC,                     __ATOMIC_RELEASE);
	}
	else
	{
		// Bounded wait (100 ms) for the initialiser to publish the header.
		int waited = 0;
		while (__atomic_load_n(u32At(OFF_MAGIC), __ATOMIC_ACQUIRE) != MAGIC)
		{
			if (++waited > 1000)
			{
				fprintf(stderr, "pqc-behaviour: ring %s header never became valid; behaviour ring disabled\n", path);
				munmap(gBase, gLen);
				gBase = NULL;
				gLen  = 0;
				return false;
			}
			usleep(100);
		}
		const uint32_t version = __atomic_load_n(u32At(OFF_VERSION), __ATOMIC_RELAXED);
		const uint32_t count   = __atomic_load_n(u32At(OFF_SLOTS), __ATOMIC_RELAXED);
		const uint32_t sb      = __atomic_load_n(u32At(OFF_SLOT_BYTES), __ATOMIC_RELAXED);
		if (version != FORMAT_VERSION || count != slots || sb != SLOT_BYTES)
		{
			fprintf(stderr, "pqc-behaviour: ring %s header mismatch (version %u, %u slots of %u bytes); behaviour ring disabled\n",
			        path, (unsigned)version, (unsigned)count, (unsigned)sb);
			munmap(gBase, gLen);
			gBase = NULL;
			gLen  = 0;
			return false;
		}
	}

	gLastNs  = 0;
	gEnabled = true;
	return true;
}

void BehaviourRing::init()
{
	if (gBase != NULL) return;   // C_Initialize may run more than once
	const char* spec = getenv("PQC_BEHAVIOUR_RING");
	if (spec == NULL || spec[0] == '\0')
	{
		gEnabled = false;
		return;
	}
	openAt(spec, DEFAULT_SLOTS);
}

void BehaviourRing::shutdown()
{
	if (gBase == NULL) return;
	munmap(gBase, gLen);
	gBase    = NULL;
	gLen     = 0;
	gMask    = 0;
	gEnabled = false;
}

void BehaviourRing::emit(Record r)
{
	if (!gEnabled || gBase == NULL) return;

	const uint64_t now  = nowNanos() + 1;   // 0 = never
	const uint64_t prev = __atomic_exchange_n(&gLastNs, now, __ATOMIC_RELAXED);
	r.dt = (prev == 0) ? 255 : log2Bucket((now > prev ? now - prev : 0) / 1000ULL);

	const uint64_t idx  = __atomic_fetch_add(u64At(OFF_HEAD), (uint64_t)1, __ATOMIC_RELAXED);
	const size_t   slot = HEADER_BYTES + (size_t)(idx & gMask) * SLOT_BYTES;
	__atomic_store_n(u64At(slot),     encode(r), __ATOMIC_RELAXED);
	__atomic_store_n(u64At(slot + 8), idx + 1,   __ATOMIC_RELEASE);
}

uint64_t BehaviourRing::head()
{
	if (!gEnabled || gBase == NULL) return 0;
	return __atomic_load_n(u64At(OFF_HEAD), __ATOMIC_ACQUIRE);
}

#else /* _WIN32: no POSIX shared mappings; every entry point is a no-op. */

bool BehaviourRing::openAt(const char*, uint32_t) { return false; }
void BehaviourRing::init() { gEnabled = false; }
void BehaviourRing::shutdown() {}
void BehaviourRing::emit(Record) {}
uint64_t BehaviourRing::head() { return 0; }

#endif
