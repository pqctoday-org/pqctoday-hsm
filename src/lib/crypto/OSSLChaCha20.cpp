/*
 * Copyright (c) 2024 PQC Today
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
 OSSLChaCha20.cpp

 OpenSSL ChaCha20-Poly1305 implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLChaCha20.h"
#include "log.h"
#include <algorithm>
#include <openssl/evp.h>

bool OSSLChaCha20::wrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("ChaCha20-Poly1305 does not support key wrapping");
	return false;
}

bool OSSLChaCha20::unwrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("ChaCha20-Poly1305 does not support key unwrapping");
	return false;
}

const EVP_CIPHER* OSSLChaCha20::getCipher() const
{
	if (currentKey == NULL) return NULL;

	// Check currentKey bit length; ChaCha20-Poly1305 only supports 256-bit keys
	if (currentKey->getBitLen() != 256)
	{
		ERROR_MSG("Invalid ChaCha20 key length (%d bits)", currentKey->getBitLen());
		return NULL;
	}

	// Determine the cipher mode
	if (currentCipherMode == SymMode::CHACHA_POLY1305)
	{
		return EVP_chacha20_poly1305();
	}
	if (currentCipherMode == SymMode::CHACHA)
	{
		// Bare ChaCha20 stream cipher (CKM_CHACHA20). OpenSSL's EVP_chacha20
		// takes a 16-byte IV laid out as counter[4] || nonce[12]; the PKCS#11
		// layer assembles that from CK_CHACHA20_PARAMS before calling us.
		return EVP_chacha20();
	}

	ERROR_MSG("Invalid ChaCha20 cipher mode %i", currentCipherMode);

	return NULL;
}

size_t OSSLChaCha20::getBlockSize() const
{
	// ChaCha20 is a stream cipher, so block size is nominally 1 byte
	return 1;
}
