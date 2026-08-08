/*
 * Copyright (c) 2026 pqctoday
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OpLog.h

 PKCS#11 operation-evidence log.

 This is deliberately NOT the same thing as log.h. log.h is a diagnostic
 facility: it writes to syslog, it is dominated by error paths, and its output
 is prose meant to be read by a human debugging the library.

 This is an *evidence* facility. It emits one machine-parseable line per
 completed cryptographic operation so that a consumer -- a test harness, a
 scenario runner, an auditor -- can prove after the fact which mechanism ran
 inside the token, on which key, with what result. It exists because a claim
 such as "this signature was produced by ML-DSA-65 inside the HSM" was
 previously only assertable by reading the source.

 Two properties are load-bearing:

   1. It is gated at RUNTIME, by the SOFTHSM3_OP_LOG environment variable, and
      never by a compile-time feature. The artifact you collect evidence from
      must be byte-identical to the artifact you ship; a build flag would mean
      evidence about a binary nobody runs. With the variable unset, emit() is
      one predictable-branch load and returns.

   2. Its output grammar is stable, because things parse it. Every record is a
      single line:

        PQCEV v=1 ts=<ms since epoch> pid=<pid> op=<C_ function> <key=value>...

      Values containing anything other than [A-Za-z0-9._:/+-] are double-quoted
      with backslash escaping. Unknown keys may be added over time; a parser
      must ignore keys it does not recognise rather than reject the line.

 SOFTHSM3_OP_LOG accepts:

   (unset) or ""   logging disabled -- the shipped default
   "stderr" or "-" write to stderr (the only retrieval path for a distroless
                   container, where `docker logs` is all there is)
   <path>          append to that file (one file per scenario run)

 Throughput note: the Rust engine's benchmark reaches ~62,000 signs/sec. A
 logging-on run at that rate is measuring the logger, not the HSM. Any
 published ops/sec figure must come from a run with this variable unset.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OPLOG_H
#define _SOFTHSM_V2_OPLOG_H

#include "config.h"
#include "cryptoki.h"

#include <string>

namespace OpLog
{
	// Set once by init(). Read directly by enabled() so the disabled path costs
	// a load and a branch, not a function call into another translation unit.
	extern bool gEnabled;

	inline bool enabled() { return gEnabled; }

	// Open the sink from SOFTHSM3_OP_LOG. Idempotent; safe to call from
	// C_Initialize on every re-initialisation.
	void init();

	// Flush and close. Safe to call when never initialised.
	void shutdown();

	// Emit one record. `tail` is a printf-style key=value list appended after
	// the fixed prefix. Callers MUST guard with enabled() when building the
	// tail costs anything (e.g. reading an attribute off an object).
	void emit(const char* op, const char* fmt, ...)
#ifdef __GNUC__
		__attribute__((format(printf, 2, 3)))
#endif
		;

	// Spelled-out PKCS#11 names, or "CKM_UNKNOWN"/"CKR_UNKNOWN" when the value
	// is outside the set this file knows. The numeric id is always logged
	// alongside, so an unknown name is a readability loss and never a data loss.
	const char* mechName(CK_MECHANISM_TYPE mech);
	const char* rvName(CK_RV rv);
	const char* keyTypeName(CK_KEY_TYPE keyType);

	// CKA_PARAMETER_SET is mechanism-relative: 0x02 means ML-DSA-65 under
	// CKM_ML_DSA and ML-KEM-768 under CKM_ML_KEM. Resolving it needs both.
	const char* paramSetName(CK_MECHANISM_TYPE mech, unsigned long paramSet);

	// Render an arbitrary byte range (a CKA_LABEL, typically) as a safe log
	// value: bare when it matches [A-Za-z0-9._:/+-]+, otherwise double-quoted
	// with \" \\ and \xNN escapes. Truncated to 128 source bytes. An empty or
	// absent label renders as the bare token `-`.
	std::string value(const unsigned char* data, size_t len);
	std::string value(const std::string& s);
}

#endif /* !_SOFTHSM_V2_OPLOG_H */
