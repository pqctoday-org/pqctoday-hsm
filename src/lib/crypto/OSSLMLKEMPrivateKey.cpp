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
 OSSLMLKEMPrivateKey.cpp

 OpenSSL ML-KEM private (decapsulation) key class (FIPS 203).
 CKA_VALUE stores PKCS#8 DER-encoded decapsulation key.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLMLKEMPrivateKey.h"
#include "OSSLMLKEMPublicKey.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <string.h>

/*static*/ const char* OSSLMLKEMPrivateKey::type = "OpenSSL ML-KEM Private Key";

OSSLMLKEMPrivateKey::OSSLMLKEMPrivateKey() : pkey(NULL)
{
	parameterSet = CKP_ML_KEM_768;
}

OSSLMLKEMPrivateKey::OSSLMLKEMPrivateKey(const EVP_PKEY* inPKEY) : pkey(NULL)
{
	parameterSet = CKP_ML_KEM_768;
	setFromOSSL(inPKEY);
}

OSSLMLKEMPrivateKey::~OSSLMLKEMPrivateKey()
{
	EVP_PKEY_free(pkey);
}

bool OSSLMLKEMPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLMLKEMPrivateKey::setParameterSet(CK_ULONG inParamSet)
{
	MLKEMPrivateKey::setParameterSet(inParamSet);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLMLKEMPrivateKey::setValue(const ByteString& inValue)
{
	MLKEMPrivateKey::setValue(inValue);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLMLKEMPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	if (inPKEY == NULL) return;

	// Detect parameter set from key name
	CK_ULONG ps;
	if      (EVP_PKEY_is_a(inPKEY, "mlkem512"))  ps = CKP_ML_KEM_512;
	else if (EVP_PKEY_is_a(inPKEY, "mlkem768"))  ps = CKP_ML_KEM_768;
	else if (EVP_PKEY_is_a(inPKEY, "mlkem1024")) ps = CKP_ML_KEM_1024;
	else
	{
		ERROR_MSG("Unknown ML-KEM parameter set in setFromOSSL");
		return;
	}
	MLKEMPrivateKey::setParameterSet(ps);

	// E3 (2026-08-13). PKCS#11 v3.2 defines CKA_VALUE on this key as the RAW
	// FIPS artefact — the "decapsulation key dk as defined in [FIPS 203]" — and PKCS#8 appears in the whole
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
	MLKEMPrivateKey::setValue(raw);

	// Cache the key
	if (pkey) EVP_PKEY_free(pkey);
	pkey = EVP_PKEY_dup(key);
}

// §6.7: "For wrapping, a private key is BER-encoded according to [PKCS #8]
// PrivateKeyInfo ASN.1 type." Since the E3 fix CKA_VALUE holds the raw FIPS
// bytes, so the transport encoding is rebuilt from the OpenSSL key here.
ByteString OSSLMLKEMPrivateKey::PKCS8Encode()
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

bool OSSLMLKEMPrivateKey::PKCS8Decode(const ByteString& ber)
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

EVP_PKEY* OSSLMLKEMPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();
	return pkey;
}

void OSSLMLKEMPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;
	if (value.size() == 0) return;

	// Path 1: Try PKCS#8 DER (keys generated via C_GenerateKeyPair)
	int len = (int)value.size();
	const unsigned char* p = value.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
	if (p8 != NULL)
	{
		pkey = EVP_PKCS82PKEY(p8);
		PKCS8_PRIV_KEY_INFO_free(p8);
		if (pkey != NULL) return;
		ERROR_MSG("createOSSLKey: EVP_PKCS82PKEY failed (0x%08X)", ERR_get_error());
	}

	// Path 2: Raw FIPS 203 key bytes via EVP_PKEY_fromdata (imported keys)
	const char* keyName = OSSLMLKEMPublicKey::paramSetToName(parameterSet);
	if (keyName == NULL)
	{
		ERROR_MSG("createOSSLKey: unknown ML-KEM parameter set %lu", parameterSet);
		return;
	}
	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) { ERROR_MSG("OSSL_PARAM_BLD_new failed"); return; }
	if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
	                                       value.const_byte_str(), value.size()))
	{
		OSSL_PARAM_BLD_free(bld);
		ERROR_MSG("createOSSLKey: push OSSL_PKEY_PARAM_PRIV_KEY failed");
		return;
	}
	OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);
	if (params == NULL) { ERROR_MSG("createOSSLKey: to_param failed"); return; }

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, keyName, NULL);
	if (ctx == NULL)
	{
		OSSL_PARAM_free(params);
		ERROR_MSG("createOSSLKey: CTX_new(%s) failed (0x%08X)", keyName, ERR_get_error());
		return;
	}
	if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
	{
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(ctx);
		ERROR_MSG("createOSSLKey: fromdata(priv) failed (0x%08X)", ERR_get_error());
		return;
	}
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(ctx);
}
