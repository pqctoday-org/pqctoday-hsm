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
 OSSLSHA512.h

 OpenSSL SHA512 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSHA512_H
#define _SOFTHSM_V2_OSSLSHA512_H

#include "config.h"
#include "OSSLEVPHashAlgorithm.h"
#include <openssl/evp.h>

class OSSLSHA512 : public OSSLEVPHashAlgorithm
{
	virtual int getHashSize();
protected:
	virtual const EVP_MD* getEVPHash() const;
};

// FIPS 180-4 truncated variants (WS-6.3, 2026-08-30): distinct initial hash
// values, not SHA-512 output truncated post-hoc — OpenSSL's EVP_sha512_224/
// _256 already compute the correct FIPS-defined IV, so this is the same
// thin wrapper pattern as OSSLSHA512 above, just a different EVP_MD.
class OSSLSHA512_224 : public OSSLEVPHashAlgorithm
{
	virtual int getHashSize();
protected:
	virtual const EVP_MD* getEVPHash() const;
};

class OSSLSHA512_256 : public OSSLEVPHashAlgorithm
{
	virtual int getHashSize();
protected:
	virtual const EVP_MD* getEVPHash() const;
};

#endif // !_SOFTHSM_V2_OSSLSHA512_H

