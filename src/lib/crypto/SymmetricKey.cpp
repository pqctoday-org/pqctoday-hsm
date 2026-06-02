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
 SymmetricKey.cpp

 Base class for symmetric key classes
 *****************************************************************************/

#include "config.h"
#include "ByteString.h"
#include "Serialisable.h"
#include "SymmetricKey.h"
#include "CryptoFactory.h"

// Base constructors
SymmetricKey::SymmetricKey(size_t inBitLen /* = 0 */)
{
	bitLen = inBitLen;
}

// Set the key
bool SymmetricKey::setKeyBits(const ByteString& keybits)
{
	if ((bitLen > 0) && ((keybits.size() * 8) != bitLen))
	{
		return false;
	}

	keyData = keybits;

	return true;
}

// Get the key
const ByteString& SymmetricKey::getKeyBits() const
{
	return keyData;
}

// Get the key check value
//
// PKCS#11 v3.2 mandates per-key-type KCV algorithms. This base method is used
// for secret-key types whose §6.x.2 object definition specifies SHA-1, namely:
//   • CKK_GENERIC_SECRET — §6.8.2 (line 39752): SHA-1(CKA_VALUE)[0:3]
//   • CKK_CHACHA20       — §6.58.2 (line 70198): SHA-1(CKA_VALUE)[0:3]
//   • CKK_SALSA20        — §6.59.2 (line 70724): SHA-1(CKA_VALUE)[0:3]
// Cipher-bearing types (AES, DES2, DES3) override this via their own subclass
// to follow the §4.11 "default-cipher ECB(zero block)[0:3]" form.
//
// SHA-1 deprecation note: NIST SP 800-131A R2 deprecates SHA-1 for cryptographic
// uses (signatures, MACs). KCV is explicitly defined (PKCS#11 v3.2 §4.11 line
// 15879-15885) as a non-cryptographic 24-bit fingerprint with expected
// collisions and "should not be usable to obtain any part of the key value".
// The collision-finding work factor that motivates SHA-1 deprecation (~2^60)
// is orders of magnitude beyond what a 24-bit truncated fingerprint exposes,
// so the spec authors knowingly kept SHA-1 in v3.2 (published 2024–2025).
// No PKCS#11 v3.x version permits SHA-256 for KCV — verified against v3.0,
// v3.1, and v3.2 cs01 (grep "SHA-256" + CKA_CHECK_VALUE returns 0 hits).
ByteString SymmetricKey::getKeyCheckValue() const
{
	ByteString digest;

	HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA1);
	if (hash == NULL) return digest;

	if (!hash->hashInit() ||
	    !hash->hashUpdate(keyData) ||
	    !hash->hashFinal(digest))
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return digest;
	}
	CryptoFactory::i()->recycleHashAlgorithm(hash);

	digest.resize(3);

	return digest;
}

// Serialisation
ByteString SymmetricKey::serialise() const
{
	return keyData;
}

// Set the bit length
void SymmetricKey::setBitLen(const size_t inBitLen)
{
	bitLen = inBitLen;
}

// Retrieve the bit length
size_t SymmetricKey::getBitLen() const
{
	return bitLen;
}

