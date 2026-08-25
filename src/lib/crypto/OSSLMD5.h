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
 OSSLMD5.h

 OpenSSL MD5 implementation

 gap remediation (2026-08-24): CKM_MD5 is advertised in every non-FIPS build
 (SoftHSM_slots.cpp) and SoftHSM_digest.cpp's C_DigestInit switch already has
 a `case CKM_MD5:` mapping it to HashAlgo::MD5 -- but OSSLCryptoFactory::
 getHashAlgorithm() had no case for HashAlgo::MD5 at all, so the lookup fell
 through to its `default: return NULL`, and C_DigestInit turned that NULL
 into CKR_MECHANISM_INVALID for an advertised mechanism. This mirrors
 OSSLSHA1 exactly (MD5, unlike RIPEMD-160, lives in OpenSSL's default
 provider, not the legacy one, so no WITH_* gate is needed here).
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMD5_H
#define _SOFTHSM_V2_OSSLMD5_H

#include "config.h"
#include "OSSLEVPHashAlgorithm.h"
#include <openssl/evp.h>

class OSSLMD5 : public OSSLEVPHashAlgorithm
{
	virtual int getHashSize();
protected:
	virtual const EVP_MD* getEVPHash() const;
};

#endif // !_SOFTHSM_V2_OSSLMD5_H
