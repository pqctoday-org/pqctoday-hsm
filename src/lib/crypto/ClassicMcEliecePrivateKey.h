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
 ClassicMcEliecePrivateKey.h

 Abstract base class for Classic McEliece (BSI TR-02102-1 §2.4.2) private
 keys. CKA_VALUE stores the RAW secret key bytes — there is no
 AlgorithmIdentifier OID registered for Classic McEliece anywhere (the IETF
 draft defines none), so unlike MLKEMPrivateKey there is no PKCS#8
 encode/decode path here at all: raw is the only wire format that exists.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CLASSICMCELIECEPRIVATEKEY_H
#define _SOFTHSM_V2_CLASSICMCELIECEPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"
#include "cryptoki.h"

class ClassicMcEliecePrivateKey : public PrivateKey
{
public:
	// Run-time type identifier
	static const char* type;
	virtual bool isOfType(const char* inType);

	// See ClassicMcEliecePublicKey::getBitLength for the category->bits mapping.
	virtual unsigned long getBitLength() const;

	// Returns the shared secret length (always 32 bytes, all 10 variants)
	virtual unsigned long getOutputLength() const;

	// Returns the ciphertext length (96-208 bytes depending on parameter set)
	virtual unsigned long getCiphertextLength() const;

	// Parameter set (one of the 10 CKP_CLASSIC_MCELIECE_* values)
	void setParameterSet(CK_ULONG ps);
	CK_ULONG getParameterSet() const;

	// Raw secret key bytes
	void setValue(const ByteString& inValue);
	const ByteString& getValue() const;

	// Serialisation (4-byte LE parameterSet || raw key bytes)
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// PrivateKey pure virtuals — Classic McEliece has no registered
	// AlgorithmIdentifier OID (the IETF draft defines none), so there is no
	// well-formed PKCS#8 form to produce on ANY build; both are safety-net
	// stubs, never reached in practice because CKK_PQCTODAY_CLASSIC_MCELIECE
	// is routed onto the raw-CKA_VALUE path in every caller that would
	// otherwise invoke these (C_WrapKey's PQC branch in SoftHSM_keygen.cpp;
	// there is no McEliece-specific PKCS8Decode call site at all, matching
	// ML-KEM/ML-DSA/SLH-DSA's own precedent).
	virtual ByteString PKCS8Encode();
	virtual bool PKCS8Decode(const ByteString& ber);

protected:
	CK_ULONG parameterSet;  // CKP_CLASSIC_MCELIECE_*
	ByteString value;       // raw secret key bytes
};

#endif // !_SOFTHSM_V2_CLASSICMCELIECEPRIVATEKEY_H
