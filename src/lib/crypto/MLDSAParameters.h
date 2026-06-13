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
 MLDSAParameters.h

 ML-DSA (FIPS 204) key-generation parameter class.
 Carries the CKP_ML_DSA_* parameter set value to generateKeyPair().
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSAPARAMETERS_H
#define _SOFTHSM_V2_MLDSAPARAMETERS_H

#include "config.h"
#include "AsymmetricParameters.h"
#include "../pkcs11/pkcs11t.h"

class MLDSAParameters : public AsymmetricParameters
{
public:
	// The type
	static const char* type;

	// Constructor — default to ML-DSA-44
	MLDSAParameters() : parameterSet(CKP_ML_DSA_44) { }

	// Set/get the parameter set (CKP_ML_DSA_44/65/87)
	void setParameterSet(CK_ULONG inParamSet);
	CK_ULONG getParameterSet() const;

	// Set/get the optional deterministic-keygen seed (xi, 32 bytes).
	// When non-empty, generateKeyPair() derives the key deterministically.
	void setSeed(const ByteString& inSeed);
	const ByteString& getSeed() const;

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	CK_ULONG parameterSet;
	ByteString seed;
};

#endif // !_SOFTHSM_V2_MLDSAPARAMETERS_H
