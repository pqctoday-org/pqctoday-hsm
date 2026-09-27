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
#include "log.h"
#include "ClassicMcEliecePrivateKey.h"
#include "ClassicMcEliecePublicKey.h"
#include "../vendor_mechanisms.h"
#include <string.h>

const char* ClassicMcEliecePrivateKey::type = "Classic McEliece Private Key";

bool ClassicMcEliecePrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long ClassicMcEliecePrivateKey::getBitLength() const
{
	switch (parameterSet)
	{
		case CKP_CLASSIC_MCELIECE_348864:
		case CKP_CLASSIC_MCELIECE_348864F:
			return 128;
		case CKP_CLASSIC_MCELIECE_460896:
		case CKP_CLASSIC_MCELIECE_460896F:
			return 192;
		case CKP_CLASSIC_MCELIECE_6688128:
		case CKP_CLASSIC_MCELIECE_6688128F:
		case CKP_CLASSIC_MCELIECE_6960119:
		case CKP_CLASSIC_MCELIECE_6960119F:
		case CKP_CLASSIC_MCELIECE_8192128:
		case CKP_CLASSIC_MCELIECE_8192128F:
			return 256;
		default:
			return 0;
	}
}

unsigned long ClassicMcEliecePrivateKey::getOutputLength() const
{
	// Shared secret is always 32 bytes for all 10 Classic McEliece variants.
	return 32;
}

unsigned long ClassicMcEliecePrivateKey::getCiphertextLength() const
{
	unsigned long pk, sk, ct;
	ClassicMcEliecePublicKey::paramSetToSizes(parameterSet, pk, sk, ct);
	return ct;
}

void ClassicMcEliecePrivateKey::setParameterSet(CK_ULONG inParamSet)
{
	parameterSet = inParamSet;
}

CK_ULONG ClassicMcEliecePrivateKey::getParameterSet() const
{
	return parameterSet;
}

void ClassicMcEliecePrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& ClassicMcEliecePrivateKey::getValue() const
{
	return value;
}

ByteString ClassicMcEliecePrivateKey::serialise() const
{
	ByteString s;
	CK_ULONG ps = parameterSet;
	s += ByteString((unsigned char*)&ps, sizeof(ps));
	s += value.serialise();
	return s;
}

bool ClassicMcEliecePrivateKey::deserialise(ByteString& serialised)
{
	if (serialised.size() < sizeof(CK_ULONG)) return false;
	memcpy(&parameterSet, serialised.byte_str(), sizeof(CK_ULONG));
	serialised = serialised.substr(sizeof(CK_ULONG));

	ByteString val = ByteString::chainDeserialise(serialised);
	setValue(val);
	return true;
}

// See the header's doc comment: no AlgorithmIdentifier OID exists for
// Classic McEliece, so there is no well-formed PKCS#8 form to encode.
// Never reached via C_WrapKey (routed to the raw-CKA_VALUE path instead,
// SoftHSM_keygen.cpp) — logged loudly if it ever is, rather than silently
// returning a misleadingly-empty-but-"successful" result.
ByteString ClassicMcEliecePrivateKey::PKCS8Encode()
{
	ERROR_MSG("Classic McEliece has no PKCS#8 form (no registered AlgorithmIdentifier OID)");
	return ByteString();
}

bool ClassicMcEliecePrivateKey::PKCS8Decode(const ByteString& /*ber*/)
{
	ERROR_MSG("Classic McEliece has no PKCS#8 form (no registered AlgorithmIdentifier OID)");
	return false;
}
