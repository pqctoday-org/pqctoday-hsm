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
 OSSLECPublicKey.cpp

 OpenSSL Elliptic Curve public key class — EVP_PKEY throughout (OpenSSL 3.x)
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "DerUtil.h"
#include "OSSLECPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <string.h>

// Constructors
OSSLECPublicKey::OSSLECPublicKey()
{
	pkey = NULL;
}

OSSLECPublicKey::OSSLECPublicKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLECPublicKey::~OSSLECPublicKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLECPublicKey::type = "OpenSSL EC Public Key";

// Check if the key is of the given type
bool OSSLECPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the base point order length
unsigned long OSSLECPublicKey::getOrderLength() const
{
	if (ec.size() == 0)
		return 0;

	EC_GROUP* grp = OSSL::byteString2grp(ec);
	if (grp == NULL)
		return 0;

	BIGNUM* order = BN_new();
	if (order == NULL)
	{
		EC_GROUP_free(grp);
		return 0;
	}
	if (!EC_GROUP_get_order(grp, order, NULL))
	{
		BN_clear_free(order);
		EC_GROUP_free(grp);
		return 0;
	}
	unsigned long len = BN_num_bytes(order);
	BN_clear_free(order);
	EC_GROUP_free(grp);
	return len;
}

// Set from OpenSSL EVP_PKEY representation
void OSSLECPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	// Extract group name and build DER-encoded ECParameters
	char curve_name[80] = {};
	if (EVP_PKEY_get_utf8_string_param(inPKEY, OSSL_PKEY_PARAM_GROUP_NAME,
	                                   curve_name, sizeof(curve_name), NULL))
	{
		int nid = OBJ_sn2nid(curve_name);
		if (nid == NID_undef) nid = OBJ_ln2nid(curve_name);
		if (nid != NID_undef)
		{
			EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
			if (grp)
			{
				ByteString inEC = OSSL::grp2ByteString(grp);
				setEC(inEC);
				EC_GROUP_free(grp);
			}
		}
	}

	// Extract public key — OpenSSL 3.x returns the raw uncompressed point (04 || x || y)
	unsigned char pub_buf[256] = {};
	size_t pub_len = 0;
	if (EVP_PKEY_get_octet_string_param(inPKEY, OSSL_PKEY_PARAM_PUB_KEY,
	                                    pub_buf, sizeof(pub_buf), &pub_len) && pub_len > 0)
	{
		// Wrap in DER OCTET STRING as expected by the base class (PKCS#11 EC_POINT encoding)
		ByteString raw(pub_buf, pub_len);
		ByteString inQ = DERUTIL::raw2Octet(raw);
		setQ(inQ);
	}
}

// Setters for the EC public key components
void OSSLECPublicKey::setEC(const ByteString& inEC)
{
	ECPublicKey::setEC(inEC);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLECPublicKey::setQ(const ByteString& inQ)
{
	ECPublicKey::setQ(inQ);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

// Retrieve the OpenSSL EVP_PKEY representation of the key (built lazily)
EVP_PKEY* OSSLECPublicKey::getOSSLKey()
{
	if (pkey != NULL)
		return pkey;

	if (ec.size() == 0 || q.size() == 0)
		return NULL;

	// Decode DER-encoded ECParameters → EC_GROUP → curve short name
	EC_GROUP* grp = OSSL::byteString2grp(ec);
	if (grp == NULL)
		return NULL;

	int nid = EC_GROUP_get_curve_name(grp);
	const char* curve_name = OBJ_nid2sn(nid);
	EC_GROUP_free(grp);

	if (curve_name == NULL)
		return NULL;

	// Unwrap DER OCTET STRING → raw uncompressed point bytes
	ByteString raw = DERUTIL::octet2Raw(q);
	if (raw.size() == 0)
		return NULL;

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
		return NULL;

	if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
	                                      curve_name, strlen(curve_name)) ||
	    !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
	                                       raw.const_byte_str(), raw.size()))
	{
		OSSL_PARAM_BLD_free(bld);
		return NULL;
	}

	OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);

	if (params == NULL)
		return NULL;

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL)
	{
		OSSL_PARAM_free(params);
		return NULL;
	}

	if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	{
		ERROR_MSG("Could not build EVP_PKEY for EC public key (0x%08X)", ERR_get_error());
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);

	// Public key validation (added 2026-09-25). EVP_PKEY_fromdata IMPORTS a
	// point; it does not check it. Without this, an EC public key whose point is
	// off the curve, or has a coordinate outside [0,p), or lies outside the
	// prime-order subgroup, was accepted and usable.
	//
	// Note on the standard, because it is easy to overstate: PKCS#11 v3.2 does
	// NOT require this. CKR_PUBLIC_KEY_INVALID occurs exactly once in the whole
	// specification and only permissively — "This error code may be returned by
	// C_CreateObject, when the public key is created, or by C_VerifyInit..." —
	// and chapter 6 carries no validation mandate (all 22 X9.62 references are
	// about point and parameter ENCODING). The requirement being met here is
	// NIST SP 800-56A §5.6.2.3.3, which the ACVP KeyVer test groups exercise.
	// So this is a security and ACVP fix, not a conformance one.
	//
	// EVP_PKEY_public_check is used rather than a hand-rolled test because for
	// EC it checks all three conditions INCLUDING the prime-order subgroup. That
	// distinction is load-bearing: every invalid KeyVer vector available is
	// either off-curve or coordinate-out-of-range and none is small-order, so an
	// on-curve-plus-range check would drive the vector failures to zero while
	// still admitting a small-order point — passing the tests and leaving the
	// small-subgroup attack open. A range check must also compare against the
	// field prime, not the byte length, for the same reason: a length test
	// accepts an out-of-range value that happens to be the right width.
	if (pkey != NULL)
	{
		EVP_PKEY_CTX* cctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
		if (cctx == NULL || EVP_PKEY_public_check(cctx) <= 0)
		{
			ERROR_MSG("EC public key failed public-key validation (0x%08X)", ERR_get_error());
			EVP_PKEY_free(pkey);
			pkey = NULL;
		}
		if (cctx != NULL) EVP_PKEY_CTX_free(cctx);
	}

	return pkey;
}
#endif
