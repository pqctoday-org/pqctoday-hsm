/*
 * Copyright (c) 2026 PQC Today
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
 OSSLMuGenDigest.h

 Remediation R39 (phase 8, PQCTODAY-VENDOR-EXT-MU): incremental SHAKE256
 XOF with a fixed 64-byte output, backing CKM_ML_DSA_EXTERNAL_MU_GEN's
 C_DigestInit/C_DigestUpdate/C_DigestFinal dispatch (SoftHSM_digest.cpp).
 FIPS 204 Eq. 2 computes mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || M,
 64) -- the caller streams M through C_DigestUpdate, this class squeezes
 the fixed 64-byte mu at C_DigestFinal without ever buffering the whole
 message. The tr||0x00||len(ctx)||ctx prefix is fed via hashUpdate() once
 at construction time (SoftHSM_digest.cpp's own case block), before any
 caller data arrives -- this class itself has no FIPS 204 awareness, it
 is a plain incremental XOF.

 Deliberately NOT registered with CryptoFactory::getHashAlgorithm /
 HashAlgo::Type -- narrowly scoped to this one mechanism (constructed
 directly), not a general-purpose SHAKE256 digest (getHashSize() is a
 hardcoded 64, not a real XOF length parameter; OSSLEVPHashAlgorithm's
 own hashFinal() uses EVP_DigestFinal_ex, which is wrong for a XOF --
 see OSSLMLDSA.cpp's own buildPreHashEncoding, which uses
 EVP_DigestFinalXOF for exactly this reason).
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMUGENDIGEST_H
#define _SOFTHSM_V2_OSSLMUGENDIGEST_H

#include "config.h"
#include "HashAlgorithm.h"
#include <openssl/evp.h>

class OSSLMuGenDigest : public HashAlgorithm
{
public:
	OSSLMuGenDigest() : HashAlgorithm(), curCTX(NULL) { }
	virtual ~OSSLMuGenDigest();

	virtual bool hashInit();
	virtual bool hashUpdate(const ByteString& data);
	virtual bool hashFinal(ByteString& hashedData);

	virtual int getHashSize() { return 64; }

private:
	EVP_MD_CTX* curCTX;
};

#endif // !_SOFTHSM_V2_OSSLMUGENDIGEST_H
