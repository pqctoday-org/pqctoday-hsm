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
 ECParameters.h

 Elliptic Curve parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ECPARAMETERS_H
#define _SOFTHSM_V2_ECPARAMETERS_H

#include "config.h"
#include "ByteString.h"
#include "AsymmetricParameters.h"

class ECParameters : public AsymmetricParameters
{
public:
	// The type
	static const char* type;

	// Set the curve OID ec
	void setEC(const ByteString& inEC);

	// Get the curve OID ec
	const ByteString& getEC() const;

	// Select the private-key generation method.
	//
	// false (the default) is the "testing candidates" method, i.e. whatever
	// the provider does for a plain keygen; true is FIPS 186-5 A.2.2
	// "Extra Random Bits", which PKCS#11 v3.2 exposes as the separate
	// mechanism CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS. Only the generation of
	// the private scalar differs; the resulting key is an ordinary EC key.
	//
	// This is deliberately NOT part of serialise()/deserialise(): the flag
	// is an input to one key generation call, not a property of the curve,
	// and ECParameters objects are persisted by callers that only ever
	// carry the curve.
	void setUseExtraBits(bool inUseExtraBits);
	bool getUseExtraBits() const;

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	ByteString ec;
	bool useExtraBits = false;
};

#endif // !_SOFTHSM_V2_ECPARAMETERS_H

