/*
 * Copyright (c) 2026 pqctoday
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BehaviourRing.h

 Behaviour event ring -- one 8-byte record per cryptographic operation,
 written into a shared-memory ring for an out-of-process consumer.

 This is the C++ engine's half of the third runtime-gated evidence sink; the
 Rust engine's half is rust/src/behaviour/mod.rs and the two write the SAME
 record into the SAME ring file, byte for byte (the generated id tables in
 BehaviourIds.h / rust/src/behaviour/ids.rs come from one behaviour/ids.json,
 and both engines' test suites encode the same golden vectors). OpLog.h emits
 text for humans and scripts; this emits a fixed-width binary record for a
 daemon that wants every operation at a cost the crypto process cannot feel.

 Record (8 bytes, little-endian uint64, byte 0 first):

   0 src      which surface produced it            (BehaviourIds::SRC_*)
   1 op       operation id in that surface's space  (BehaviourIds::OP_*)
   2 alg      algorithm + parameter set             (BehaviourIds::ALG_*), 0 = n/a
   3 result   outcome class                         (BehaviourIds::RESULT_*)
   4 client   8-bit bucket of the caller identity, 0 = local / none
   5 size     floor(log2(input bytes)), 0 when 0 or unknown
   6 latency  floor(log2(microseconds)), 0 when unknown
   7 dt       floor(log2(microseconds since this process's previous record)), 255 = first

 Ring file (PQC_BEHAVIOUR_RING, format v1): a 4096-byte header (magic "PQBR",
 format version, slot count, slot bytes = 16, a 64-bit head claimed with one
 atomic add, creation time, id-table version) followed by slots of
 [uint64 record][uint64 seq]. A producer claims an index, stores the record,
 then stores seq = index + 1 with release ordering; the reader accepts a slot
 only when seq == index + 1. Nothing is dropped at the producer -- the ring
 overwrites, and loss is the reader's to measure.

 Same properties as OpLog: gated at RUNTIME by PQC_BEHAVIOUR_RING (unset means
 enabled() is one load and a branch), never by a build flag; and off when a
 benchmark measures. PQC_BEHAVIOUR_SRC names which PKCS#11 surface this
 process is (p11-local when unset).

 Not available on Windows (no POSIX mmap): every entry point compiles to a
 no-op there, mirroring the Rust engine's wasm gate.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BEHAVIOURRING_H
#define _SOFTHSM_V2_BEHAVIOURRING_H

#include "config.h"
#include "cryptoki.h"
#include "BehaviourIds.h"

#include <stdint.h>
#include <stddef.h>

namespace BehaviourRing
{
	static const uint32_t MAGIC          = 0x52425150UL; /* "PQBR" little-endian */
	static const uint32_t FORMAT_VERSION = 1;
	static const size_t   HEADER_BYTES   = 4096;
	static const size_t   SLOT_BYTES     = 16;
	static const uint32_t DEFAULT_SLOTS  = 65536;

	struct Record
	{
		uint8_t src, op, alg, result, client, size, latency, dt;
	};

	// Set once by init(). Read directly by enabled() so the disabled path costs
	// a load and a branch, not a function call into another translation unit.
	extern bool gEnabled;

	inline bool enabled() { return gEnabled; }

	// Map the ring named by PQC_BEHAVIOUR_RING. Idempotent; safe to call from
	// C_Initialize on every re-initialisation.
	void init();

	// Unmap. Safe to call when never initialised.
	void shutdown();

	// Map the ring at `path` with `slots` slots (a power of two), creating and
	// initialising it if absent. The public init() calls this with the
	// environment's path; tests call it directly. Returns false (and leaves
	// the sink disabled) on any failure -- a file of the wrong size or version
	// is refused, never rewritten.
	bool openAt(const char* path, uint32_t slots);

	// Monotonic microseconds, for timing an operation around its dispatch.
	uint64_t nowMicros();

	// floor(log2(v)) for v >= 1; 0 for v == 0.
	uint8_t log2Bucket(uint64_t v);

	// 1 + (fnv1a32(identity) mod 255), or 0 for NULL / empty.
	uint8_t clientBucket(const char* identity);

	// The record as the little-endian uint64 that lands in the ring.
	uint64_t encode(const Record& r);

	// Append one record; fills r.dt from this process's clock. Best-effort,
	// never blocks, never throws; a no-op when the ring is absent.
	void emit(Record r);

	// The src byte for this process's PKCS#11 records (PQC_BEHAVIOUR_SRC).
	uint8_t p11Src();

	// Build the record for one PKCS#11 entry point in this process.
	Record p11(uint8_t op, uint8_t alg, CK_RV rv, uint64_t sizeBytes, uint64_t latencyUs);

	// Records written so far (the ring's head), or 0 when disabled.
	uint64_t head();
}

#endif /* !_SOFTHSM_V2_BEHAVIOURRING_H */
