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
 ClassicMcElieceParameters.h

 Key generation parameters for Classic McEliece (BSI TR-02102-1 §2.4.2).
 Selects one of the 10 CKP_CLASSIC_MCELIECE_* parameter sets — required,
 no default (unlike MLKEMParameters, which defaults to CKP_ML_KEM_768;
 Classic McEliece's 10 values are not a small contiguous "obvious middle"
 range the way ML-KEM's 3 are, so the engine's keygen path requires the
 caller to state one explicitly — see SoftHSM_keygen.cpp).

 No deterministic-keygen seed field (unlike MLKEMParameters): liboqs's
 Classic McEliece `_keypair_derand` entry points exist in the header but
 report a zero-length seed, so no genuine seeded-keygen capability exists
 here to expose.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CLASSICMCELIECEPARAMETERS_H
#define _SOFTHSM_V2_CLASSICMCELIECEPARAMETERS_H

#include "config.h"
#include "AsymmetricParameters.h"
#include "cryptoki.h"

class ClassicMcElieceParameters : public AsymmetricParameters
{
public:
	// Run-time type identifier
	static const char* type;

	// No default parameter set — 0 is not a valid CKP_CLASSIC_MCELIECE_*
	// value, so an un-set instance fails validation rather than silently
	// picking a variant.
	ClassicMcElieceParameters() : parameterSet(0) { }

	virtual bool areOfType(const char* inType);

	void setParameterSet(CK_ULONG ps);
	CK_ULONG getParameterSet() const;

	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	CK_ULONG parameterSet;
};

#endif // !_SOFTHSM_V2_CLASSICMCELIECEPARAMETERS_H
