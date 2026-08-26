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
 OSSLMuGenDigest.cpp

 See OSSLMuGenDigest.h for the full rationale (remediation R39, phase 8).
 *****************************************************************************/

#include "config.h"
#include "OSSLMuGenDigest.h"
#include "log.h"

OSSLMuGenDigest::~OSSLMuGenDigest()
{
	EVP_MD_CTX_free(curCTX);
}

bool OSSLMuGenDigest::hashInit()
{
	if (!HashAlgorithm::hashInit())
	{
		return false;
	}

	curCTX = EVP_MD_CTX_new();
	if (curCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_MD_CTX");
		return false;
	}

	EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
	if (md == NULL)
	{
		ERROR_MSG("EVP_MD_fetch(SHAKE256) failed");
		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}
	bool ok = EVP_DigestInit_ex(curCTX, md, NULL);
	EVP_MD_free(md);
	if (!ok)
	{
		ERROR_MSG("EVP_DigestInit failed (SHAKE256)");
		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}

	return true;
}

bool OSSLMuGenDigest::hashUpdate(const ByteString& data)
{
	if (!HashAlgorithm::hashUpdate(data))
	{
		return false;
	}

	if (data.size() == 0)
	{
		return true;
	}

	if (!EVP_DigestUpdate(curCTX, data.const_byte_str(), data.size()))
	{
		ERROR_MSG("EVP_DigestUpdate failed (SHAKE256)");
		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}

	return true;
}

bool OSSLMuGenDigest::hashFinal(ByteString& hashedData)
{
	if (!HashAlgorithm::hashFinal(hashedData))
	{
		return false;
	}

	hashedData.resize(64);
	if (!EVP_DigestFinalXOF(curCTX, &hashedData[0], 64))
	{
		ERROR_MSG("EVP_DigestFinalXOF failed (SHAKE256)");
		EVP_MD_CTX_free(curCTX);
		curCTX = NULL;
		return false;
	}

	EVP_MD_CTX_free(curCTX);
	curCTX = NULL;

	return true;
}
