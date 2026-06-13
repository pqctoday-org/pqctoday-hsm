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

#include "config.h"
#include "SLHDSAParameters.h"
#include <string.h>

const char* SLHDSAParameters::type = "SLH-DSA Parameters";

void SLHDSAParameters::setParameterSet(CK_ULONG inParamSet)
{
	parameterSet = inParamSet;
}

CK_ULONG SLHDSAParameters::getParameterSet() const
{
	return parameterSet;
}

void SLHDSAParameters::setSeed(const ByteString& inSeed)
{
	seed = inSeed;
}

const ByteString& SLHDSAParameters::getSeed() const
{
	return seed;
}

bool SLHDSAParameters::areOfType(const char* inType)
{
	return !strcmp(type, inType);
}

ByteString SLHDSAParameters::serialise() const
{
	ByteString s;
	CK_ULONG ps = parameterSet;
	s += ByteString((unsigned char*)&ps, sizeof(ps));
	return s;
}

bool SLHDSAParameters::deserialise(ByteString& serialised)
{
	if (serialised.size() < sizeof(CK_ULONG)) return false;
	memcpy(&parameterSet, serialised.byte_str(), sizeof(CK_ULONG));
	serialised = serialised.substr(sizeof(CK_ULONG));
	return true;
}
