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
 OSSLCryptoFactory.cpp

 OpenSSL 3.x EVP-only cryptographic algorithm factory.
 OpenSSL 3.x EVP-only. Legacy algorithms (DES, DSA, DH, GOST) removed from
 this fork. MD5 (digest, HMAC, RSA-PKCS#1v1.5 sign) is intentionally RETAINED
 for non-FIPS interop -- see the "audit G5" comments in SoftHSM_slots.cpp /
 SoftHSM_sign.cpp -- this header comment was stale until the 2026-08-24 gap
 remediation wired the last missing piece (OSSLMD5, the raw-digest class)
 in below; do not re-remove it without also updating those advertise-side
 gates.
 Retained: RSA, ECDSA, ECDH, EdDSA, AES, SHA-2, SHA-3, HMAC, CMAC,
 ML-DSA, SLH-DSA, ML-KEM.
 *****************************************************************************/

#include "config.h"
#include "MutexFactory.h"
#include "OSSLCryptoFactory.h"
#include "OSSLRNG.h"
#include "OSSLAES.h"
#include "OSSLChaCha20.h"
#include "OSSLMD5.h"
#include "OSSLSHA1.h"
#include "OSSLSHA224.h"
#include "OSSLSHA256.h"
#include "OSSLSHA384.h"
#include "OSSLSHA512.h"
#include "OSSLSHA3.h"
#include "OSSLCMAC.h"
#include "OSSLKMAC.h"
#include "OSSLHMAC.h"
#include "OSSLRSA.h"
#include "OSSLECDH.h"
#include "OSSLECDSA.h"
#include "OSSLEDDSA.h"
#include "OSSLMLDSA.h"
#include "OSSLSLHDSA.h"
#include "OSSLMLKEM.h"
#ifdef WITH_RIPEMD160
#include "OSSLRIPEMD160.h"
#endif

#include <mutex>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifdef WITH_RIPEMD160
#include <openssl/provider.h>
#endif

// Constructor
OSSLCryptoFactory::OSSLCryptoFactory()
{
#ifdef WITH_RIPEMD160
	// RIPEMD-160 (and HMAC-RIPEMD-160) live in the OpenSSL LEGACY provider,
	// which is not loaded into the default library context by default. Native
	// builds load it here so EVP_ripemd160() resolves. Both default and legacy
	// must be loaded explicitly once any explicit OSSL_PROVIDER_load() is done,
	// otherwise the implicit default provider is dropped. The WASM build omits
	// the legacy provider entirely (WITH_RIPEMD160 unset) — no size bloat. A
	// failed load is non-fatal: G1 already returns CKR_MECHANISM_INVALID, so
	// the worst case degrades to the no-legacy behavior rather than crashing.
	legacyProvider  = OSSL_PROVIDER_load(NULL, "legacy");
	defaultProvider = OSSL_PROVIDER_load(NULL, "default");
#endif

	// Initialise the one-and-only RNG
	rng = new OSSLRNG();
}

// Destructor
OSSLCryptoFactory::~OSSLCryptoFactory()
{
	// Destroy the one-and-only RNG
	delete rng;

#ifdef WITH_RIPEMD160
	// Release the explicitly-loaded providers (native only).
	if (legacyProvider != NULL)  OSSL_PROVIDER_unload(legacyProvider);
	if (defaultProvider != NULL) OSSL_PROVIDER_unload(defaultProvider);
#endif
}

// Return the one-and-only instance
OSSLCryptoFactory* OSSLCryptoFactory::i()
{
	static std::mutex s_initMutex;
	std::lock_guard<std::mutex> lock(s_initMutex);
	if (!instance) {
		instance.reset(new OSSLCryptoFactory());
	}
	return instance.get();
}

// This will destroy the one-and-only instance.
void OSSLCryptoFactory::reset()
{
	instance.reset();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* OSSLCryptoFactory::getSymmetricAlgorithm(SymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case SymAlgo::AES:
			return new OSSLAES();
		case SymAlgo::CHACHA:
			return new OSSLChaCha20();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unknown algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* OSSLCryptoFactory::getAsymmetricAlgorithm(AsymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case AsymAlgo::RSA:
			return new OSSLRSA();
		case AsymAlgo::ECDH:
			return new OSSLECDH();
		case AsymAlgo::ECDSA:
			return new OSSLECDSA();
		case AsymAlgo::EDDSA:
			return new OSSLEDDSA();
		case AsymAlgo::MLDSA:
			return new OSSLMLDSA();
		case AsymAlgo::SLHDSA:
			return new OSSLSLHDSA();
		case AsymAlgo::MLKEM:
			return new OSSLMLKEM();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unknown algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* OSSLCryptoFactory::getHashAlgorithm(HashAlgo::Type algorithm)
{
	switch (algorithm)
	{
		// gap remediation (2026-08-24): CKM_MD5 is advertised in every
		// non-FIPS build and SoftHSM_digest.cpp's C_DigestInit switch
		// already maps it to HashAlgo::MD5 (audit G5) -- but this factory
		// had no case for it, so the lookup fell through to `default` below
		// and C_DigestInit turned the resulting NULL into
		// CKR_MECHANISM_INVALID for an advertised mechanism. This also
		// silently broke CKM_MD5_RSA_PKCS, whose sign path (OSSLRSA::
		// signInit) calls this same factory method for its MD5 pre-hash.
		case HashAlgo::MD5:
			return new OSSLMD5();
#ifdef WITH_RIPEMD160
		case HashAlgo::RIPEMD160:
			return new OSSLRIPEMD160();
#endif
		case HashAlgo::SHA1:
			return new OSSLSHA1();
		case HashAlgo::SHA224:
			return new OSSLSHA224();
		case HashAlgo::SHA256:
			return new OSSLSHA256();
		case HashAlgo::SHA384:
			return new OSSLSHA384();
		case HashAlgo::SHA512:
			return new OSSLSHA512();
		case HashAlgo::SHA3_224:
			return new OSSLSHA3_224();
		case HashAlgo::SHA3_256:
			return new OSSLSHA3_256();
		case HashAlgo::SHA3_384:
			return new OSSLSHA3_384();
		case HashAlgo::SHA3_512:
			return new OSSLSHA3_512();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unknown algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of a MAC algorithm
MacAlgorithm* OSSLCryptoFactory::getMacAlgorithm(MacAlgo::Type algorithm)
{
	switch (algorithm)
	{
		// gap remediation (2026-08-24): OSSLHMACMD5 (OSSLHMAC.h) was fully
		// implemented but never wired into this switch, so CKM_MD5_HMAC --
		// advertised in every non-FIPS build (SoftHSM_slots.cpp) and
		// correctly recognized by resolveMacMech's own CKM_MD5_HMAC special
		// case (SoftHSM_sign.cpp) -- fell through to the `default` below and
		// answered CKR_MECHANISM_INVALID for a mechanism the token claims to
		// support. Found while adding real HMAC-MD5 round-trip coverage.
		case MacAlgo::HMAC_MD5:
			return new OSSLHMACMD5();
#ifdef WITH_RIPEMD160
		case MacAlgo::HMAC_RIPEMD160:
			return new OSSLHMACRIPEMD160();
#endif
		case MacAlgo::HMAC_SHA1:
			return new OSSLHMACSHA1();
		case MacAlgo::HMAC_SHA224:
			return new OSSLHMACSHA224();
		case MacAlgo::HMAC_SHA256:
			return new OSSLHMACSHA256();
		case MacAlgo::HMAC_SHA384:
			return new OSSLHMACSHA384();
		case MacAlgo::HMAC_SHA512:
			return new OSSLHMACSHA512();
		case MacAlgo::HMAC_SHA3_224:
			return new OSSLHMACSHA3_224();
		case MacAlgo::HMAC_SHA3_256:
			return new OSSLHMACSHA3_256();
		case MacAlgo::HMAC_SHA3_384:
			return new OSSLHMACSHA3_384();
		case MacAlgo::HMAC_SHA3_512:
			return new OSSLHMACSHA3_512();
		case MacAlgo::CMAC_AES:
			return new OSSLCMACAES();
		case MacAlgo::KMAC_128:
			return new OSSLKMAC128();
		case MacAlgo::KMAC_256:
			return new OSSLKMAC256();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unknown algorithm '%i'", algorithm);
	return NULL;
}

// Get the global RNG (may be a unique RNG per thread)
RNG* OSSLCryptoFactory::getRNG(RNGImpl::Type name /* = RNGImpl::Default */)
{
	if (name == RNGImpl::Default)
	{
		return rng;
	}
	else
	{
		// No RNG implementation is available
		ERROR_MSG("Unknown RNG '%i'", name);

		return NULL;
	}
}
