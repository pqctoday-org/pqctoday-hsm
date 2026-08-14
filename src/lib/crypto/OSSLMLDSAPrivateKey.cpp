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
 OSSLMLDSAPrivateKey.cpp

 OpenSSL ML-DSA private key class (FIPS 204).
 CKA_VALUE stores PKCS#8 DER-encoded private key.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLMLDSAPrivateKey.h"
#include "OSSLMLDSAPublicKey.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <string.h>

/*static*/ const char* OSSLMLDSAPrivateKey::type = "OpenSSL ML-DSA Private Key";

OSSLMLDSAPrivateKey::OSSLMLDSAPrivateKey() : pkey(NULL)
{
	parameterSet = CKP_ML_DSA_44;
}

OSSLMLDSAPrivateKey::OSSLMLDSAPrivateKey(const EVP_PKEY* inPKEY) : pkey(NULL)
{
	parameterSet = CKP_ML_DSA_44;
	setFromOSSL(inPKEY);
}

OSSLMLDSAPrivateKey::~OSSLMLDSAPrivateKey()
{
	EVP_PKEY_free(pkey);
}

bool OSSLMLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLMLDSAPrivateKey::setParameterSet(CK_ULONG inParamSet)
{
	MLDSAPrivateKey::setParameterSet(inParamSet);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLMLDSAPrivateKey::setValue(const ByteString& inValue)
{
	MLDSAPrivateKey::setValue(inValue);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLMLDSAPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	if (inPKEY == NULL) return;

	// Detect parameter set
	CK_ULONG ps;
	if      (EVP_PKEY_is_a(inPKEY, "ml-dsa-44")) ps = CKP_ML_DSA_44;
	else if (EVP_PKEY_is_a(inPKEY, "ml-dsa-65")) ps = CKP_ML_DSA_65;
	else if (EVP_PKEY_is_a(inPKEY, "ml-dsa-87")) ps = CKP_ML_DSA_87;
	else
	{
		ERROR_MSG("Unknown ML-DSA parameter set in setFromOSSL");
		return;
	}
	MLDSAPrivateKey::setParameterSet(ps);

	// E3 (2026-08-13). PKCS#11 v3.2 defines CKA_VALUE on this key as the RAW
	// FIPS artefact — "Private key (sk) as defined in ML-DSA.Keygen-internal in [FIPS 204]" — and PKCS#8 appears in the whole
	// specification exactly once, as the TRANSPORT format for wrapping (§6.7),
	// never as an attribute format. Storing the PKCS#8 DER wrapper here meant an
	// application reading CKA_VALUE got a DER SEQUENCE instead of the key.
	// PKCS8Encode() below still produces PKCS#8 for the C_WrapKey path.
	EVP_PKEY* key = const_cast<EVP_PKEY*>(inPKEY);
	size_t rawLen = 0;
	if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
	                                    NULL, 0, &rawLen) <= 0 || rawLen == 0)
	{
		ERROR_MSG("Could not size the raw private key (0x%08X)", ERR_get_error());
		return;
	}
	ByteString raw;
	raw.resize(rawLen);
	if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
	                                    &raw[0], rawLen, &rawLen) <= 0)
	{
		ERROR_MSG("Could not read the raw private key (0x%08X)", ERR_get_error());
		return;
	}
	raw.resize(rawLen);
	MLDSAPrivateKey::setValue(raw);

	// Cache the key
	if (pkey) EVP_PKEY_free(pkey);
	pkey = EVP_PKEY_dup(key);
}

// §6.7: "For wrapping, a private key is BER-encoded according to [PKCS #8]
// PrivateKeyInfo ASN.1 type." Since the E3 fix CKA_VALUE holds the raw FIPS
// bytes, so the transport encoding is rebuilt from the OpenSSL key here.
ByteString OSSLMLDSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(key);
	if (p8 == NULL)
	{
		ERROR_MSG("EVP_PKEY2PKCS8 failed (0x%08X)", ERR_get_error());
		return der;
	}
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
	if (len <= 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8);
		ERROR_MSG("i2d_PKCS8_PRIV_KEY_INFO failed");
		return der;
	}
	der.resize(len);
	unsigned char* p = &der[0];
	i2d_PKCS8_PRIV_KEY_INFO(p8, &p);
	PKCS8_PRIV_KEY_INFO_free(p8);
	return der;
}

// Decode from PKCS#8 DER: validate and store
bool OSSLMLDSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = (int)ber.size();
	if (len <= 0) return false;
	const unsigned char* p = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
	if (p8 == NULL)
	{
		ERROR_MSG("PKCS8Decode: d2i_PKCS8_PRIV_KEY_INFO failed (0x%08X)", ERR_get_error());
		return false;
	}
	EVP_PKEY* key = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (key == NULL)
	{
		ERROR_MSG("PKCS8Decode: EVP_PKCS82PKEY failed (0x%08X)", ERR_get_error());
		return false;
	}
	setFromOSSL(key);
	EVP_PKEY_free(key);
	return true;
}

EVP_PKEY* OSSLMLDSAPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();
	return pkey;
}

void OSSLMLDSAPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;
	if (value.size() == 0) return;

	// Path 1: raw FIPS 204 sk bytes — what CKA_VALUE holds since the E3 fix,
	// and what an application importing a key per the ML-DSA private-key table
	// supplies. Mirrors OSSLMLKEMPrivateKey::createOSSLKey.
	const char* keyName = OSSLMLDSAPublicKey::paramSetToName(parameterSet);
	if (keyName != NULL)
	{
		OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
		if (bld != NULL)
		{
			if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
			                                     value.const_byte_str(), value.size()))
			{
				OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
				if (params != NULL)
				{
					EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, keyName, NULL);
					if (ctx != NULL)
					{
						if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
						    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
						{
							pkey = NULL;
						}
						EVP_PKEY_CTX_free(ctx);
					}
					OSSL_PARAM_free(params);
				}
			}
			OSSL_PARAM_BLD_free(bld);
		}
		if (pkey != NULL) return;
	}

	// Path 2: PKCS#8 DER — the encoding this engine wrote before 2026-08-13, so
	// keys already on a token keep loading.
	int len = (int)value.size();
	const unsigned char* p = value.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
	if (p8 == NULL)
	{
		ERROR_MSG("createOSSLKey: d2i_PKCS8_PRIV_KEY_INFO failed (0x%08X)", ERR_get_error());
		return;
	}
	pkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (pkey == NULL)
	{
		ERROR_MSG("createOSSLKey: EVP_PKCS82PKEY failed (0x%08X)", ERR_get_error());
	}
}
