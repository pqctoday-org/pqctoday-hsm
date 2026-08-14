/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation)
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
 P11Objects.h

 This class respresent a PKCS#11 object
 *****************************************************************************/

#ifndef _SOFTHSM_V2_P11OBJECTS_H
#define _SOFTHSM_V2_P11OBJECTS_H

#include "OSObject.h"
#include "P11Attributes.h"
#include "Token.h"
#include "cryptoki.h"
#include <map>

class P11Object
{
public:
	// Destructor
	virtual ~P11Object();

protected:
	// Constructor
	P11Object();

	// The object
	OSObject* osobject;

	// The attributes
	std::map<CK_ATTRIBUTE_TYPE, P11Attribute*> attributes;

public:
	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;

public:
	CK_RV loadTemplate(Token *token, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount);

	// Save template
	CK_RV saveTemplate(Token *token, bool isPrivate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, int op);

protected:
	bool isPrivate();
	bool isCopyable();
	bool isModifiable();
};

// PKCS#11 v3.2 §4.9 / Profiles v3.2 §5.1 condition 4 — the CKO_PROFILE object a
// conforming Provider must publish. CKA_PROFILE_ID lives here and ONLY here: it
// used to be attached by P11Object::init to every object in the store, where its
// default value 0 is Profiles v3.2's reserved CKP_INVALID_ID.
class P11ProfileObj : public P11Object
{
public:
	// Constructor
	P11ProfileObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11DataObj : public P11Object
{
public:
	// Constructor
	P11DataObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11CertificateObj : public P11Object
{
protected:
	// Constructor
	P11CertificateObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
	bool initialized;
};

class P11X509CertificateObj : public P11CertificateObj
{
public:
	// Constructor
	P11X509CertificateObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
	virtual CK_RV saveTemplate(Token *token, bool isPrivate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, int op);
protected:
	bool initialized;
};

class P11OpenPGPPublicKeyObj : public P11CertificateObj
{
public:
	// Constructor
	P11OpenPGPPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11KeyObj : public P11Object
{
protected:
	// Constructor
	P11KeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
	bool initialized;
};

class P11PublicKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11PublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
	bool initialized;
};

class P11RSAPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11RSAPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11DSAPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11DSAPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11ECPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11ECPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11EDPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11EDPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11DHPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11DHPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11PrivateKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11PrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
	bool initialized;
};

class P11RSAPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11RSAPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11DSAPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11DSAPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11ECPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11ECPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11EDPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11EDPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11DHPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11DHPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11SecretKeyObj : public P11KeyObj
{
protected:
	// Constructor
	P11SecretKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
	bool initialized;
};

class P11GenericSecretKeyObj : public P11SecretKeyObj
{
public:
	// Constructor
	P11GenericSecretKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

	// Better than multiply subclasses
	virtual bool setKeyType(CK_KEY_TYPE inKeytype);
	virtual CK_KEY_TYPE getKeyType();

protected:
	bool initialized;
	CK_KEY_TYPE keytype;
};

class P11AESSecretKeyObj : public P11SecretKeyObj
{
public:
	// Constructor
	P11AESSecretKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11ChaCha20SecretKeyObj : public P11SecretKeyObj
{
public:
	// Constructor
	P11ChaCha20SecretKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11DESSecretKeyObj : public P11SecretKeyObj
{
public:
	// Constructor
	P11DESSecretKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

	// Better than multiply subclasses
	virtual bool setKeyType(CK_KEY_TYPE inKeytype);
	virtual CK_KEY_TYPE getKeyType();

protected:
	bool initialized;
	CK_KEY_TYPE keytype;
};

class P11DomainObj : public P11Object
{
protected:
	// Constructor
	P11DomainObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
	bool initialized;
};

class P11DSADomainObj : public P11DomainObj
{
public:
	// Constructor
	P11DSADomainObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
protected:
	bool initialized;
};

class P11DHDomainObj : public P11DomainObj
{
public:
	// Constructor
	P11DHDomainObj();

	// Add attributes
	virtual bool init(OSObject *inobject);
protected:
	bool initialized;
};

// ─── ML-DSA (FIPS 204, PKCS#11 v3.2) ────────────────────────────────────────

class P11MLDSAPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11MLDSAPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11MLDSAPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11MLDSAPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

// ─── ML-KEM (FIPS 203, PKCS#11 v3.2) ────────────────────────────────────────

class P11MLKEMPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11MLKEMPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11MLKEMPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11MLKEMPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

// ─── SLH-DSA (FIPS 205, PKCS#11 v3.2) ───────────────────────────────────────

class P11SLHDSAPublicKeyObj : public P11PublicKeyObj
{
public:
	// Constructor
	P11SLHDSAPublicKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

class P11SLHDSAPrivateKeyObj : public P11PrivateKeyObj
{
public:
	// Constructor
	P11SLHDSAPrivateKeyObj();

	// Add attributes
	virtual bool init(OSObject *inobject);

protected:
	bool initialized;
};

// ─── HSS/LMS (PKCS#11 v3.2, CKK_HSS = 0x46) ─────────────────────────────────

class P11HSSPublicKeyObj : public P11PublicKeyObj
{
public:
	P11HSSPublicKeyObj();
	virtual bool init(OSObject *inobject);
protected:
	bool initialized;
};

class P11HSSPrivateKeyObj : public P11PrivateKeyObj
{
public:
	P11HSSPrivateKeyObj();
	virtual bool init(OSObject *inobject);
protected:
	bool initialized;
};

// ─── XMSS (PKCS#11 v3.2, CKK_XMSS = 0x47) ───────────────────────────────────

class P11XMSSPublicKeyObj : public P11PublicKeyObj
{
public:
	P11XMSSPublicKeyObj();
	virtual bool init(OSObject *inobject);
protected:
	bool initialized;
};

class P11XMSSPrivateKeyObj : public P11PrivateKeyObj
{
public:
	P11XMSSPrivateKeyObj();
	virtual bool init(OSObject *inobject);
protected:
	bool initialized;
};

// ─── XMSS-MT (PKCS#11 v3.2, CKK_XMSSMT = 0x48) ─────────────────────────────

class P11XMSSMTPublicKeyObj : public P11PublicKeyObj
{
public:
	P11XMSSMTPublicKeyObj();
	virtual bool init(OSObject *inobject);
protected:
	bool initialized;
};

class P11XMSSMTPrivateKeyObj : public P11PrivateKeyObj
{
public:
	P11XMSSMTPrivateKeyObj();
	virtual bool init(OSObject *inobject);
protected:
	bool initialized;
};

#endif // !_SOFTHSM_V2_P11OBJECTS_H
