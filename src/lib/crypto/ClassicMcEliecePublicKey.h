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
 ClassicMcEliecePublicKey.h

 Abstract base class for Classic McEliece (BSI TR-02102-1 §2.4.2) public
 keys. Stores the raw public key bytes and the CKP_CLASSIC_MCELIECE_*
 parameter set. Unlike MLKEMPublicKey, there is no OpenSSL EVP_PKEY
 representation anywhere in this family (D-2 — no EVP route exists for
 Classic McEliece at all); the OSSL-prefixed subclass holds a liboqs
 `OQS_KEM*` handle instead.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CLASSICMCELIECEPUBLICKEY_H
#define _SOFTHSM_V2_CLASSICMCELIECEPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"
#include "cryptoki.h"

class ClassicMcEliecePublicKey : public PublicKey
{
public:
	// Run-time type identifier
	static const char* type;
	virtual bool isOfType(const char* inType);

	// Returns NIST claimed security category * 32, as a stand-in "bit
	// length" consistent with how MLKEMPublicKey reports strength (128 for
	// Category 1, 192 for Category 3, 256 for Category 5) — Classic
	// McEliece's own security claims are stated in NIST categories, not a
	// single bit-length number, so this maps category -> the same
	// 128/192/256 scale ML-KEM already uses on this same virtual.
	virtual unsigned long getBitLength() const;

	// PublicKey pure virtual: not meaningful for KEM public keys (returns 0)
	virtual unsigned long getOutputLength() const;

	// Returns the ciphertext length produced by encapsulation (96-208
	// bytes depending on parameter set — see paramSetToSizes)
	virtual unsigned long getCiphertextLength() const;

	// Parameter set (one of the 10 CKP_CLASSIC_MCELIECE_* values)
	void setParameterSet(CK_ULONG ps);
	CK_ULONG getParameterSet() const;

	// Raw public key bytes
	void setValue(const ByteString& inValue);
	const ByteString& getValue() const;

	// Serialisation (4-byte LE parameterSet || raw key bytes)
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// (publicKeyBytes, secretKeyBytes, ciphertextBytes) for a
	// CKP_CLASSIC_MCELIECE_* value, or (0,0,0) if unrecognised. The single
	// source of truth for every size this family needs — mirrored exactly
	// from classic-mceliece-multi's own per-module CRYPTO_*BYTES constants
	// (independently verified there against the official Round-4 KAT
	// vectors), so C++ and Rust cannot silently drift.
	static void paramSetToSizes(CK_ULONG ps, unsigned long& pkBytes,
	                             unsigned long& skBytes, unsigned long& ctBytes);

protected:
	CK_ULONG parameterSet;  // CKP_CLASSIC_MCELIECE_*
	ByteString value;       // raw public key bytes
};

#endif // !_SOFTHSM_V2_CLASSICMCELIECEPUBLICKEY_H
