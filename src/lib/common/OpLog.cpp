/*
 * Copyright (c) 2026 pqctoday
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OpLog.cpp

 Implements the PKCS#11 operation-evidence log. See OpLog.h for why this is
 separate from log.h and why the gating is at runtime.
 *****************************************************************************/

#include "config.h"
#include "OpLog.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
#define OPLOG_GETPID() ((long)_getpid())
#else
#include <unistd.h>
#define OPLOG_GETPID() ((long)getpid())
#endif

namespace OpLog
{
	bool gEnabled = false;
}

namespace
{
	FILE* gSink        = NULL;
	bool  gSinkIsOwned = false;   // true when we opened a file and must fclose it

	// Milliseconds since the epoch. A record's ordering matters more than its
	// absolute accuracy -- consumers correlate HSM records against daemon logs.
	long long nowMillis()
	{
#if defined(CLOCK_REALTIME)
		struct timespec ts;
		if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
			return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000L);
#endif
		return (long long)time(NULL) * 1000LL;
	}
}

void OpLog::init()
{
	if (gSink != NULL) return;   // already open; C_Initialize may run more than once

	const char* spec = getenv("SOFTHSM3_OP_LOG");
	if (spec == NULL || spec[0] == '\0')
	{
		gEnabled = false;
		return;
	}

	if (strcmp(spec, "stderr") == 0 || strcmp(spec, "-") == 0)
	{
		gSink        = stderr;
		gSinkIsOwned = false;
	}
	else
	{
		// Append, never truncate: several processes in one scenario (sshd, the
		// client, an agent) legitimately share one evidence file.
		gSink = fopen(spec, "a");
		if (gSink == NULL)
		{
			// Falling back to stderr rather than silently disabling: a run that
			// was asked for evidence and produced none must be visibly wrong,
			// not quietly empty.
			fprintf(stderr, "PQCEV v=1 op=oplog_init error=\"cannot open %s\" fallback=stderr\n", spec);
			gSink        = stderr;
			gSinkIsOwned = false;
		}
		else
		{
			gSinkIsOwned = true;
		}
	}

	gEnabled = true;
	emit("oplog_init", "sink=%s", value(spec).c_str());
}

void OpLog::shutdown()
{
	if (gSink == NULL) return;

	emit("oplog_shutdown", "-");
	fflush(gSink);
	if (gSinkIsOwned) fclose(gSink);

	gSink        = NULL;
	gSinkIsOwned = false;
	gEnabled     = false;
}

void OpLog::emit(const char* op, const char* fmt, ...)
{
	if (!gEnabled || gSink == NULL) return;

	char tail[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(tail, sizeof(tail), fmt, args);
	va_end(args);

	// One fprintf of a complete line. stdio streams are implicitly locked under
	// POSIX, so concurrent sessions interleave records but never split one.
	fprintf(gSink, "PQCEV v=1 ts=%lld pid=%ld op=%s %s\n",
	        nowMillis(), OPLOG_GETPID(), op, tail);
	fflush(gSink);
}

const char* OpLog::mechName(CK_MECHANISM_TYPE mech)
{
	switch (mech)
	{
		/* PQC signature -- pure */
		case CKM_ML_DSA:                  return "CKM_ML_DSA";
		case CKM_ML_DSA_KEY_PAIR_GEN:     return "CKM_ML_DSA_KEY_PAIR_GEN";
		case CKM_SLH_DSA:                 return "CKM_SLH_DSA";
		case CKM_SLH_DSA_KEY_PAIR_GEN:    return "CKM_SLH_DSA_KEY_PAIR_GEN";

		/* PQC signature -- pre-hash (FIPS 204 §5.4 / FIPS 205 §10.2). These are
		   still ML-DSA and SLH-DSA signatures: leaving them as CKM_UNKNOWN would
		   make a consumer conclude no PQC signing happened when it did. */
		case CKM_HASH_ML_DSA:             return "CKM_HASH_ML_DSA";
		case CKM_HASH_ML_DSA_SHA224:      return "CKM_HASH_ML_DSA_SHA224";
		case CKM_HASH_ML_DSA_SHA256:      return "CKM_HASH_ML_DSA_SHA256";
		case CKM_HASH_ML_DSA_SHA384:      return "CKM_HASH_ML_DSA_SHA384";
		case CKM_HASH_ML_DSA_SHA512:      return "CKM_HASH_ML_DSA_SHA512";
		case CKM_HASH_ML_DSA_SHA3_224:    return "CKM_HASH_ML_DSA_SHA3_224";
		case CKM_HASH_ML_DSA_SHA3_256:    return "CKM_HASH_ML_DSA_SHA3_256";
		case CKM_HASH_ML_DSA_SHA3_384:    return "CKM_HASH_ML_DSA_SHA3_384";
		case CKM_HASH_ML_DSA_SHA3_512:    return "CKM_HASH_ML_DSA_SHA3_512";
		case CKM_HASH_ML_DSA_SHAKE128:    return "CKM_HASH_ML_DSA_SHAKE128";
		case CKM_HASH_ML_DSA_SHAKE256:    return "CKM_HASH_ML_DSA_SHAKE256";
		case CKM_HASH_SLH_DSA:            return "CKM_HASH_SLH_DSA";
		case CKM_HASH_SLH_DSA_SHA224:     return "CKM_HASH_SLH_DSA_SHA224";
		case CKM_HASH_SLH_DSA_SHA256:     return "CKM_HASH_SLH_DSA_SHA256";
		case CKM_HASH_SLH_DSA_SHA384:     return "CKM_HASH_SLH_DSA_SHA384";
		case CKM_HASH_SLH_DSA_SHA512:     return "CKM_HASH_SLH_DSA_SHA512";
		case CKM_HASH_SLH_DSA_SHA3_224:   return "CKM_HASH_SLH_DSA_SHA3_224";
		case CKM_HASH_SLH_DSA_SHA3_256:   return "CKM_HASH_SLH_DSA_SHA3_256";
		case CKM_HASH_SLH_DSA_SHA3_384:   return "CKM_HASH_SLH_DSA_SHA3_384";
		case CKM_HASH_SLH_DSA_SHA3_512:   return "CKM_HASH_SLH_DSA_SHA3_512";
		case CKM_HASH_SLH_DSA_SHAKE128:   return "CKM_HASH_SLH_DSA_SHAKE128";
		case CKM_HASH_SLH_DSA_SHAKE256:   return "CKM_HASH_SLH_DSA_SHAKE256";
		case CKM_HSS:                     return "CKM_HSS";
		case CKM_HSS_KEY_PAIR_GEN:        return "CKM_HSS_KEY_PAIR_GEN";
		case CKM_XMSS:                    return "CKM_XMSS";
		case CKM_XMSS_KEY_PAIR_GEN:       return "CKM_XMSS_KEY_PAIR_GEN";
		case CKM_XMSSMT:                  return "CKM_XMSSMT";
		case CKM_XMSSMT_KEY_PAIR_GEN:     return "CKM_XMSSMT_KEY_PAIR_GEN";

		/* PQC KEM */
		case CKM_ML_KEM:                  return "CKM_ML_KEM";
		case CKM_ML_KEM_KEY_PAIR_GEN:     return "CKM_ML_KEM_KEY_PAIR_GEN";

		/* Classical -- logged so that E5 negative evidence ("no classical
		   fallback where PQC is claimed") is assertable, not just PQC. */
		case CKM_RSA_PKCS:                return "CKM_RSA_PKCS";
		case CKM_RSA_X_509:               return "CKM_RSA_X_509";
		case CKM_RSA_PKCS_PSS:            return "CKM_RSA_PKCS_PSS";
		case CKM_RSA_PKCS_KEY_PAIR_GEN:   return "CKM_RSA_PKCS_KEY_PAIR_GEN";
		case CKM_SHA1_RSA_PKCS:           return "CKM_SHA1_RSA_PKCS";
		case CKM_SHA224_RSA_PKCS:         return "CKM_SHA224_RSA_PKCS";
		case CKM_SHA256_RSA_PKCS:         return "CKM_SHA256_RSA_PKCS";
		case CKM_SHA384_RSA_PKCS:         return "CKM_SHA384_RSA_PKCS";
		case CKM_SHA512_RSA_PKCS:         return "CKM_SHA512_RSA_PKCS";
		case CKM_SHA1_RSA_PKCS_PSS:       return "CKM_SHA1_RSA_PKCS_PSS";
		case CKM_SHA224_RSA_PKCS_PSS:     return "CKM_SHA224_RSA_PKCS_PSS";
		case CKM_SHA256_RSA_PKCS_PSS:     return "CKM_SHA256_RSA_PKCS_PSS";
		case CKM_SHA384_RSA_PKCS_PSS:     return "CKM_SHA384_RSA_PKCS_PSS";
		case CKM_SHA512_RSA_PKCS_PSS:     return "CKM_SHA512_RSA_PKCS_PSS";
		case CKM_SHA3_224_RSA_PKCS:       return "CKM_SHA3_224_RSA_PKCS";
		case CKM_SHA3_256_RSA_PKCS:       return "CKM_SHA3_256_RSA_PKCS";
		case CKM_SHA3_384_RSA_PKCS:       return "CKM_SHA3_384_RSA_PKCS";
		case CKM_SHA3_512_RSA_PKCS:       return "CKM_SHA3_512_RSA_PKCS";
		case CKM_SHA3_224_RSA_PKCS_PSS:   return "CKM_SHA3_224_RSA_PKCS_PSS";
		case CKM_SHA3_256_RSA_PKCS_PSS:   return "CKM_SHA3_256_RSA_PKCS_PSS";
		case CKM_SHA3_384_RSA_PKCS_PSS:   return "CKM_SHA3_384_RSA_PKCS_PSS";
		case CKM_SHA3_512_RSA_PKCS_PSS:   return "CKM_SHA3_512_RSA_PKCS_PSS";
		case CKM_ECDSA:                   return "CKM_ECDSA";
		case CKM_ECDSA_SHA1:              return "CKM_ECDSA_SHA1";
		case CKM_ECDSA_SHA224:            return "CKM_ECDSA_SHA224";
		case CKM_ECDSA_SHA256:            return "CKM_ECDSA_SHA256";
		case CKM_ECDSA_SHA384:            return "CKM_ECDSA_SHA384";
		case CKM_ECDSA_SHA512:            return "CKM_ECDSA_SHA512";
		case CKM_ECDSA_SHA3_224:          return "CKM_ECDSA_SHA3_224";
		case CKM_ECDSA_SHA3_256:          return "CKM_ECDSA_SHA3_256";
		case CKM_ECDSA_SHA3_384:          return "CKM_ECDSA_SHA3_384";
		case CKM_ECDSA_SHA3_512:          return "CKM_ECDSA_SHA3_512";
		case CKM_EC_KEY_PAIR_GEN:         return "CKM_EC_KEY_PAIR_GEN";
		case CKM_ECDH1_DERIVE:            return "CKM_ECDH1_DERIVE";
		case CKM_EDDSA:                   return "CKM_EDDSA";
		case CKM_EC_EDWARDS_KEY_PAIR_GEN: return "CKM_EC_EDWARDS_KEY_PAIR_GEN";
		case CKM_EC_MONTGOMERY_KEY_PAIR_GEN: return "CKM_EC_MONTGOMERY_KEY_PAIR_GEN";
		case CKM_AES_KEY_GEN:             return "CKM_AES_KEY_GEN";
		case CKM_SHA_1_HMAC:              return "CKM_SHA_1_HMAC";
		case CKM_SHA224_HMAC:             return "CKM_SHA224_HMAC";
		case CKM_SHA256_HMAC:             return "CKM_SHA256_HMAC";
		case CKM_SHA384_HMAC:             return "CKM_SHA384_HMAC";
		case CKM_SHA512_HMAC:             return "CKM_SHA512_HMAC";
		case CKM_SHA3_224_HMAC:           return "CKM_SHA3_224_HMAC";
		case CKM_SHA3_256_HMAC:           return "CKM_SHA3_256_HMAC";
		case CKM_SHA3_384_HMAC:           return "CKM_SHA3_384_HMAC";
		case CKM_SHA3_512_HMAC:           return "CKM_SHA3_512_HMAC";
		case CKM_RIPEMD160_HMAC:          return "CKM_RIPEMD160_HMAC";

		default:                          return "CKM_UNKNOWN";
	}
}

const char* OpLog::rvName(CK_RV rv)
{
	switch (rv)
	{
		case CKR_OK:                          return "CKR_OK";
		case CKR_ARGUMENTS_BAD:               return "CKR_ARGUMENTS_BAD";
		case CKR_BUFFER_TOO_SMALL:            return "CKR_BUFFER_TOO_SMALL";
		case CKR_CRYPTOKI_NOT_INITIALIZED:    return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_DEVICE_ERROR:                return "CKR_DEVICE_ERROR";
		case CKR_FUNCTION_FAILED:             return "CKR_FUNCTION_FAILED";
		case CKR_GENERAL_ERROR:               return "CKR_GENERAL_ERROR";
		case CKR_KEY_FUNCTION_NOT_PERMITTED:  return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		case CKR_KEY_HANDLE_INVALID:          return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE:              return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT:       return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_MECHANISM_INVALID:           return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID:     return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID:       return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE:            return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED:   return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_SESSION_HANDLE_INVALID:      return "CKR_SESSION_HANDLE_INVALID";
		case CKR_TEMPLATE_INCOMPLETE:         return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT:       return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_USER_NOT_LOGGED_IN:          return "CKR_USER_NOT_LOGGED_IN";
		default:                              return "CKR_UNKNOWN";
	}
}

const char* OpLog::keyTypeName(CK_KEY_TYPE keyType)
{
	switch (keyType)
	{
		case CKK_RSA:            return "CKK_RSA";
		case CKK_EC:             return "CKK_EC";
		case CKK_EC_EDWARDS:     return "CKK_EC_EDWARDS";
		case CKK_EC_MONTGOMERY:  return "CKK_EC_MONTGOMERY";
		case CKK_AES:            return "CKK_AES";
		case CKK_GENERIC_SECRET: return "CKK_GENERIC_SECRET";
		case CKK_HSS:            return "CKK_HSS";
		case CKK_XMSS:           return "CKK_XMSS";
		case CKK_XMSSMT:         return "CKK_XMSSMT";
		case CKK_ML_KEM:         return "CKK_ML_KEM";
		case CKK_ML_DSA:         return "CKK_ML_DSA";
		case CKK_SLH_DSA:        return "CKK_SLH_DSA";
		default:                 return "CKK_UNKNOWN";
	}
}

const char* OpLog::paramSetName(CK_MECHANISM_TYPE mech, unsigned long paramSet)
{
	switch (mech)
	{
		case CKM_ML_DSA:
		case CKM_ML_DSA_KEY_PAIR_GEN:
		case CKM_HASH_ML_DSA:
		case CKM_HASH_ML_DSA_SHA224:
		case CKM_HASH_ML_DSA_SHA256:
		case CKM_HASH_ML_DSA_SHA384:
		case CKM_HASH_ML_DSA_SHA512:
		case CKM_HASH_ML_DSA_SHA3_224:
		case CKM_HASH_ML_DSA_SHA3_256:
		case CKM_HASH_ML_DSA_SHA3_384:
		case CKM_HASH_ML_DSA_SHA3_512:
		case CKM_HASH_ML_DSA_SHAKE128:
		case CKM_HASH_ML_DSA_SHAKE256:
			switch (paramSet)
			{
				case CKP_ML_DSA_44: return "ML-DSA-44";
				case CKP_ML_DSA_65: return "ML-DSA-65";
				case CKP_ML_DSA_87: return "ML-DSA-87";
				default:            return "unknown";
			}

		case CKM_ML_KEM:
		case CKM_ML_KEM_KEY_PAIR_GEN:
			switch (paramSet)
			{
				case CKP_ML_KEM_512:  return "ML-KEM-512";
				case CKP_ML_KEM_768:  return "ML-KEM-768";
				case CKP_ML_KEM_1024: return "ML-KEM-1024";
				default:              return "unknown";
			}

		case CKM_SLH_DSA:
		case CKM_SLH_DSA_KEY_PAIR_GEN:
		case CKM_HASH_SLH_DSA:
		case CKM_HASH_SLH_DSA_SHA224:
		case CKM_HASH_SLH_DSA_SHA256:
		case CKM_HASH_SLH_DSA_SHA384:
		case CKM_HASH_SLH_DSA_SHA512:
		case CKM_HASH_SLH_DSA_SHA3_224:
		case CKM_HASH_SLH_DSA_SHA3_256:
		case CKM_HASH_SLH_DSA_SHA3_384:
		case CKM_HASH_SLH_DSA_SHA3_512:
		case CKM_HASH_SLH_DSA_SHAKE128:
		case CKM_HASH_SLH_DSA_SHAKE256:
			switch (paramSet)
			{
				case CKP_SLH_DSA_SHA2_128S:  return "SLH-DSA-SHA2-128s";
				case CKP_SLH_DSA_SHAKE_128S: return "SLH-DSA-SHAKE-128s";
				case CKP_SLH_DSA_SHA2_128F:  return "SLH-DSA-SHA2-128f";
				case CKP_SLH_DSA_SHAKE_128F: return "SLH-DSA-SHAKE-128f";
				case CKP_SLH_DSA_SHA2_192S:  return "SLH-DSA-SHA2-192s";
				case CKP_SLH_DSA_SHAKE_192S: return "SLH-DSA-SHAKE-192s";
				case CKP_SLH_DSA_SHA2_192F:  return "SLH-DSA-SHA2-192f";
				case CKP_SLH_DSA_SHAKE_192F: return "SLH-DSA-SHAKE-192f";
				case CKP_SLH_DSA_SHA2_256S:  return "SLH-DSA-SHA2-256s";
				case CKP_SLH_DSA_SHAKE_256S: return "SLH-DSA-SHAKE-256s";
				case CKP_SLH_DSA_SHA2_256F:  return "SLH-DSA-SHA2-256f";
				case CKP_SLH_DSA_SHAKE_256F: return "SLH-DSA-SHAKE-256f";
				default:                     return "unknown";
			}

		default:
			return "n/a";
	}
}

std::string OpLog::value(const unsigned char* data, size_t len)
{
	if (data == NULL || len == 0) return "-";
	if (len > 128) len = 128;

	bool bare = true;
	for (size_t i = 0; i < len; i++)
	{
		const unsigned char c = data[i];
		const bool safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		                  (c >= '0' && c <= '9') ||
		                  c == '.' || c == '_' || c == ':' || c == '/' ||
		                  c == '+' || c == '-';
		if (!safe) { bare = false; break; }
	}

	if (bare) return std::string((const char*)data, len);

	std::string out;
	out.reserve(len + 8);
	out += '"';
	for (size_t i = 0; i < len; i++)
	{
		const unsigned char c = data[i];
		if (c == '"' || c == '\\')
		{
			out += '\\';
			out += (char)c;
		}
		else if (c >= 0x20 && c < 0x7f)
		{
			out += (char)c;
		}
		else
		{
			char esc[5];
			snprintf(esc, sizeof(esc), "\\x%02x", c);
			out += esc;
		}
	}
	out += '"';
	return out;
}

std::string OpLog::value(const std::string& s)
{
	return value((const unsigned char*)s.data(), s.size());
}
