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
#include "ClassicMcEliecePublicKey.h"
#include "../vendor_mechanisms.h"
#include <string.h>

const char* ClassicMcEliecePublicKey::type = "Classic McEliece Public Key";

bool ClassicMcEliecePublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// pkBytes/skBytes/ctBytes verified against the official Round-4 KAT vectors
// (kmip/kat/classic-mceliece/README.md) and classic-mceliece-multi's own
// per-module CRYPTO_*BYTES constants — the same table the implementation
// plan §1.1/§3.1 records.
/*static*/ void ClassicMcEliecePublicKey::paramSetToSizes(CK_ULONG ps,
	unsigned long& pkBytes, unsigned long& skBytes, unsigned long& ctBytes)
{
	switch (ps)
	{
		case CKP_CLASSIC_MCELIECE_348864:
		case CKP_CLASSIC_MCELIECE_348864F:
			pkBytes = 261120; skBytes = 6492; ctBytes = 96; return;
		case CKP_CLASSIC_MCELIECE_460896:
		case CKP_CLASSIC_MCELIECE_460896F:
			pkBytes = 524160; skBytes = 13608; ctBytes = 156; return;
		case CKP_CLASSIC_MCELIECE_6688128:
		case CKP_CLASSIC_MCELIECE_6688128F:
			pkBytes = 1044992; skBytes = 13932; ctBytes = 208; return;
		case CKP_CLASSIC_MCELIECE_6960119:
		case CKP_CLASSIC_MCELIECE_6960119F:
			pkBytes = 1047319; skBytes = 13948; ctBytes = 194; return;
		case CKP_CLASSIC_MCELIECE_8192128:
		case CKP_CLASSIC_MCELIECE_8192128F:
			pkBytes = 1357824; skBytes = 14120; ctBytes = 208; return;
		default:
			pkBytes = 0; skBytes = 0; ctBytes = 0; return;
	}
}

unsigned long ClassicMcEliecePublicKey::getBitLength() const
{
	switch (parameterSet)
	{
		case CKP_CLASSIC_MCELIECE_348864:
		case CKP_CLASSIC_MCELIECE_348864F:
			return 128;  // NIST Category 1
		case CKP_CLASSIC_MCELIECE_460896:
		case CKP_CLASSIC_MCELIECE_460896F:
			return 192;  // NIST Category 3
		case CKP_CLASSIC_MCELIECE_6688128:
		case CKP_CLASSIC_MCELIECE_6688128F:
		case CKP_CLASSIC_MCELIECE_6960119:
		case CKP_CLASSIC_MCELIECE_6960119F:
		case CKP_CLASSIC_MCELIECE_8192128:
		case CKP_CLASSIC_MCELIECE_8192128F:
			return 256;  // NIST Category 5
		default:
			return 0;
	}
}

unsigned long ClassicMcEliecePublicKey::getOutputLength() const
{
	return 0;
}

unsigned long ClassicMcEliecePublicKey::getCiphertextLength() const
{
	unsigned long pk, sk, ct;
	paramSetToSizes(parameterSet, pk, sk, ct);
	return ct;
}

void ClassicMcEliecePublicKey::setParameterSet(CK_ULONG inParamSet)
{
	parameterSet = inParamSet;
}

CK_ULONG ClassicMcEliecePublicKey::getParameterSet() const
{
	return parameterSet;
}

void ClassicMcEliecePublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& ClassicMcEliecePublicKey::getValue() const
{
	return value;
}

ByteString ClassicMcEliecePublicKey::serialise() const
{
	ByteString s;
	CK_ULONG ps = parameterSet;
	s += ByteString((unsigned char*)&ps, sizeof(ps));
	s += value.serialise();
	return s;
}

bool ClassicMcEliecePublicKey::deserialise(ByteString& serialised)
{
	if (serialised.size() < sizeof(CK_ULONG)) return false;
	memcpy(&parameterSet, serialised.byte_str(), sizeof(CK_ULONG));
	serialised = serialised.substr(sizeof(CK_ULONG));

	ByteString val = ByteString::chainDeserialise(serialised);
	setValue(val);
	return true;
}
