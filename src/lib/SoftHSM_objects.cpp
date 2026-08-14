/*
 * Copyright (c) 2022 NLnet Labs
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
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
 SoftHSM_objects.cpp

 PKCS#11 object management: C_CreateObject, C_CopyObject, C_DestroyObject,
 C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit,
 C_FindObjects, C_FindObjectsFinal.  Also contains CreateObject() and the
 shared object-construction helpers (newP11Object, extractObjectInformation,
 checkKeyLength).
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "SessionManager.h"
#include "CryptoFactory.h"
#include "cryptoki.h"
#include "P11Attributes.h"
#include "P11Objects.h"
#include "SlotManager.h"
#include "SymmetricKey.h"
#include "AESKey.h"

// CKC_OPENPGP was in PKCS#11 2.x but removed from v3.2 headers.
#ifndef CKC_OPENPGP
#define CKC_OPENPGP 0x00000003UL
#endif



static CK_RV newP11Object(CK_OBJECT_CLASS objClass, CK_KEY_TYPE keyType, CK_CERTIFICATE_TYPE certType, P11Object **p11object)
{
	switch(objClass) {
		case CKO_DATA:
			*p11object = new P11DataObj();
			break;
		case CKO_CERTIFICATE:
			if (certType == CKC_X_509)
				*p11object = new P11X509CertificateObj();
			else if (certType == CKC_OPENPGP)
				*p11object = new P11OpenPGPPublicKeyObj();
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_PUBLIC_KEY:
			if (keyType == CKK_RSA)
				*p11object = new P11RSAPublicKeyObj();
			else if (keyType == CKK_EC)
				*p11object = new P11ECPublicKeyObj();
			else if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY)
				*p11object = new P11EDPublicKeyObj();
			else if (keyType == CKK_ML_DSA)
				*p11object = new P11MLDSAPublicKeyObj();
			else if (keyType == CKK_ML_KEM)
				*p11object = new P11MLKEMPublicKeyObj();
			else if (keyType == CKK_SLH_DSA)
				*p11object = new P11SLHDSAPublicKeyObj();
			else if (keyType == CKK_HSS)
				*p11object = new P11HSSPublicKeyObj();
			else if (keyType == CKK_XMSS)
				*p11object = new P11XMSSPublicKeyObj();
			else if (keyType == CKK_XMSSMT)
				*p11object = new P11XMSSMTPublicKeyObj();
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_PRIVATE_KEY:
			// we need to know the type too
			if (keyType == CKK_RSA)
				*p11object = new P11RSAPrivateKeyObj();
			else if (keyType == CKK_EC)
				*p11object = new P11ECPrivateKeyObj();
			else if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY)
				*p11object = new P11EDPrivateKeyObj();
			else if (keyType == CKK_ML_DSA)
				*p11object = new P11MLDSAPrivateKeyObj();
			else if (keyType == CKK_ML_KEM)
				*p11object = new P11MLKEMPrivateKeyObj();
			else if (keyType == CKK_SLH_DSA)
				*p11object = new P11SLHDSAPrivateKeyObj();
			else if (keyType == CKK_HSS)
				*p11object = new P11HSSPrivateKeyObj();
			else if (keyType == CKK_XMSS)
				*p11object = new P11XMSSPrivateKeyObj();
			else if (keyType == CKK_XMSSMT)
				*p11object = new P11XMSSMTPrivateKeyObj();
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_SECRET_KEY:
			if ((keyType == CKK_GENERIC_SECRET) ||
			    (keyType == CKK_MD5_HMAC) ||
			    (keyType == CKK_SHA_1_HMAC) ||
			    (keyType == CKK_SHA224_HMAC) ||
			    (keyType == CKK_SHA256_HMAC) ||
			    (keyType == CKK_SHA384_HMAC) ||
			    (keyType == CKK_SHA512_HMAC))
			{
				P11GenericSecretKeyObj* key = new P11GenericSecretKeyObj();
				*p11object = key;
				key->setKeyType(keyType);
			}
			else if (keyType == CKK_AES)
			{
				*p11object = new P11AESSecretKeyObj();
			}
			else if (keyType == CKK_CHACHA20)
			{
				*p11object = new P11ChaCha20SecretKeyObj();
			}
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKO_DOMAIN_PARAMETERS:
			return CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID; // invalid value for a valid argument
	}
	return CKR_OK;
}

CK_RV extractObjectInformation(CK_ATTRIBUTE_PTR pTemplate,
				      CK_ULONG ulCount,
				      CK_OBJECT_CLASS &objClass,
				      CK_KEY_TYPE &keyType,
				      CK_CERTIFICATE_TYPE &certType,
				      CK_BBOOL &isOnToken,
				      CK_BBOOL &isPrivate,
				      bool bImplicit)
{
	bool bHasClass = false;
	bool bHasKeyType = false;
	bool bHasCertType = false;
	bool bHasPrivate = false;

	// Extract object information
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
				if (pTemplate[i].pValue == NULL_PTR)
					return CKR_ATTRIBUTE_VALUE_INVALID;
				if (pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS))
				{
					objClass = *(CK_OBJECT_CLASS_PTR)pTemplate[i].pValue;
					bHasClass = true;
				}
				break;
			case CKA_KEY_TYPE:
				if (pTemplate[i].pValue == NULL_PTR)
					return CKR_ATTRIBUTE_VALUE_INVALID;
				if (pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE))
				{
					keyType = *(CK_KEY_TYPE*)pTemplate[i].pValue;
					bHasKeyType = true;
				}
				break;
			case CKA_CERTIFICATE_TYPE:
				if (pTemplate[i].pValue == NULL_PTR)
					return CKR_ATTRIBUTE_VALUE_INVALID;
				if (pTemplate[i].ulValueLen == sizeof(CK_CERTIFICATE_TYPE))
				{
					certType = *(CK_CERTIFICATE_TYPE*)pTemplate[i].pValue;
					bHasCertType = true;
				}
				break;
			case CKA_TOKEN:
				if (pTemplate[i].pValue == NULL_PTR)
					return CKR_ATTRIBUTE_VALUE_INVALID;
				if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
				}
				break;
			case CKA_PRIVATE:
				if (pTemplate[i].pValue == NULL_PTR)
					return CKR_ATTRIBUTE_VALUE_INVALID;
				if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
					bHasPrivate = true;
				}
				break;
			default:
				break;
		}
	}

	if (bImplicit)
	{
		return CKR_OK;
	}

	if (!bHasClass)
	{
		return CKR_TEMPLATE_INCOMPLETE;
	}

	bool bKeyTypeRequired = (objClass == CKO_PUBLIC_KEY || objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY);
	if (bKeyTypeRequired && !bHasKeyType)
	{
		 return CKR_TEMPLATE_INCOMPLETE;
	}

	if (objClass == CKO_CERTIFICATE)
	{
		if (!bHasCertType)
		{
			return CKR_TEMPLATE_INCOMPLETE;
		}
		if (!bHasPrivate)
		{
			// Change default value for certificates
			isPrivate = CK_FALSE;
		}
	}

	if (objClass == CKO_PUBLIC_KEY && !bHasPrivate)
	{
		// Change default value for public keys
		isPrivate = CK_FALSE;
	}

	return CKR_OK;
}

// PKCS#11 v3.2 §4.11 — CKA_CHECK_VALUE in an object-creation template.
//
//   "If a value is supplied in the application template (allowed but never
//    necessary) then, if supported, it MUST match what the library calculates
//    it to be or the library returns a CKR_ATTRIBUTE_VALUE_INVALID."
//   "The generation of the KCV may be prevented by the application supplying
//    the attribute in the template as a no-value (0 length) entry."
//
// The C++ engine used to reject EVERY non-empty entry, including a correct one,
// which the first sentence forbids. This helper only classifies the entry; the
// comparison itself has to happen where the key bits are known.
CK_RV checkValueFromTemplate(const CK_ATTRIBUTE& attr, bool& generate,
                             bool& supplied, ByteString& suppliedValue)
{
	if (attr.ulValueLen == 0)
	{
		// No-value entry: suppression channel.
		generate = false;
		supplied = false;
		suppliedValue.wipe(0);
		return CKR_OK;
	}
	if (attr.pValue == NULL_PTR)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	generate = true;
	supplied = true;
	suppliedValue = ByteString((unsigned char*)attr.pValue, attr.ulValueLen);
	return CKR_OK;
}

CK_RV checkKeyLength(CK_KEY_TYPE keyType, size_t byteLen)
{
	switch (keyType) {
		case CKK_GENERIC_SECRET:
			break;
		case CKK_AES:
			if (byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				INFO_MSG("CKA_VALUE_LEN must be 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	return CKR_OK;
}

static CK_RV newP11Object(OSObject *object, P11Object **p11object)
{
	CK_OBJECT_CLASS objClass = object->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	if (object->attributeExists(CKA_KEY_TYPE))
		keyType = object->getUnsignedLongValue(CKA_KEY_TYPE, CKK_RSA);
	if (object->attributeExists(CKA_CERTIFICATE_TYPE))
		certType = object->getUnsignedLongValue(CKA_CERTIFICATE_TYPE, CKC_X_509);
	CK_RV rv = newP11Object(objClass,keyType,certType,p11object);
	if (rv != CKR_OK)
		return rv;
	if (!(*p11object)->init(object))
		return CKR_GENERAL_ERROR; // something went wrong that shouldn't have.
	return CKR_OK;
}

#ifdef notyet
static CK_ATTRIBUTE bsAttribute(CK_ATTRIBUTE_TYPE type, const ByteString &value)
{
	CK_ATTRIBUTE attr = {type, (CK_VOID_PTR)value.const_byte_str(), value.size() };
	return attr;
}
#endif

CK_RV SoftHSM::C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	return this->CreateObject(hSession,pTemplate,ulCount,phObject,OBJECT_OP_CREATE);
}

// Create a copy of the object with the specified handle
CK_RV SoftHSM::C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phNewObject == NULL_PTR) return CKR_ARGUMENTS_BAD;
	*phNewObject = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the slot
	Slot* slot = session->getSlot();
	if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle (§2.4: scoped to this session's slot — a handle minted
	// on another token is not reachable here).
	OSObject *object = (OSObject *)handleManager->getObject(hObject, slot->getSlotID());
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL wasOnToken = object->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL wasPrivate = object->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), wasOnToken, wasPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check if the object is copyable
	CK_BBOOL isCopyable = object->getBooleanValue(CKA_COPYABLE, true);
	if (!isCopyable) return CKR_ACTION_PROHIBITED;

	// Extract critical information from the template
	CK_BBOOL isOnToken = wasOnToken;
	CK_BBOOL isPrivate = wasPrivate;

	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		if ((pTemplate[i].type == CKA_TOKEN) && (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)))
		{
			isOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
			continue;
		}
		if ((pTemplate[i].type == CKA_PRIVATE) && (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)))
		{
			isPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
			continue;
		}
	}

	// Check privacy does not downgrade
	if (wasPrivate && !isPrivate) return CKR_TEMPLATE_INCONSISTENT;

	// Check write user credentials
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Create the object in session or on the token
	OSObject *newobject = NULL_PTR;
	if (isOnToken)
	{
		newobject = (OSObject*) token->createObject();
	}
	else
	{
		newobject = sessionObjectStore->createObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE);
	}
	if (newobject == NULL) return CKR_GENERAL_ERROR;

	// Copy attributes from object class (CKA_CLASS=0 so the first)
	if (!newobject->startTransaction())
	{
		newobject->destroyObject();
		return CKR_FUNCTION_FAILED;
	}

	CK_ATTRIBUTE_TYPE attrType = CKA_CLASS;
	do
	{
		if (!object->attributeExists(attrType))
		{
			rv = CKR_FUNCTION_FAILED;
			break;
		}

		// CKA_UNIQUE_ID is strictly token-assigned and immutable. Do NOT clone
		// it from the source — the new object's P11Object::init()/setDefault()
		// mints a fresh UUID so the copy gets its own distinct identity
		// (audit V-14). Cloning it would make init() see it already present and
		// skip regeneration, leaving source and copy sharing one id.
		if (attrType == CKA_UNIQUE_ID)
		{
			attrType = object->nextAttributeType(attrType);
			continue;
		}

		OSAttribute attr = object->getAttribute(attrType);

		// Upgrade privacy has to encrypt byte strings
		if (!wasPrivate && isPrivate &&
		    attr.isByteStringAttribute() &&
		    attr.getByteStringValue().size() != 0)
		{
			ByteString value;
			if (!token->encrypt(attr.getByteStringValue(), value) ||
			    !newobject->setAttribute(attrType, value))
			{
				rv = CKR_FUNCTION_FAILED;
				break;
			}
		}
		else
		{
			if (!newobject->setAttribute(attrType, attr))
			{
				rv = CKR_FUNCTION_FAILED;
				break;
			}
		}
		attrType = object->nextAttributeType(attrType);
	}
	while (attrType != CKA_CLASS);

	if (rv != CKR_OK)
	{
		newobject->abortTransaction();
	}
	else if (!newobject->commitTransaction())
	{
		rv = CKR_FUNCTION_FAILED;
	}

	if (rv != CKR_OK)
	{
		newobject->destroyObject();
		return rv;
	}

	// Get the new P11 object
	P11Object* newp11object = NULL;
	rv = newP11Object(newobject,&newp11object);
	if (rv != CKR_OK)
	{
		newobject->destroyObject();
		return rv;
	}

	// Apply the template
	rv = newp11object->saveTemplate(token, isPrivate != CK_FALSE, pTemplate, ulCount, OBJECT_OP_COPY);
	delete newp11object;

	if (rv != CKR_OK)
	{
		newobject->destroyObject();
		return rv;
	}

	// Set handle
	if (isOnToken)
	{
		*phNewObject = handleManager->addTokenObject(slot->getSlotID(), isPrivate != CK_FALSE, newobject);
	}
	else
	{
		*phNewObject = handleManager->addSessionObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE, newobject);
	}

	return CKR_OK;
}

// Destroy the specified object
CK_RV SoftHSM::C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle (§2.4: scoped to this session's slot).
	OSObject *object = (OSObject *)handleManager->getObject(hObject, session->getSlot()->getSlotID());
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = object->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = object->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Check if the object is destroyable
	CK_BBOOL isDestroyable = object->getBooleanValue(CKA_DESTROYABLE, true);
	if (!isDestroyable) return CKR_ACTION_PROHIBITED;

	// Tell the handleManager to forget about the object.
	handleManager->destroyObject(hObject);

	// Destroy the object
	if (!object->destroyObject())
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

// Determine the size of the specified object
CK_RV SoftHSM::C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulSize == NULL) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check the object handle (§2.4: scoped to this session's slot).
	OSObject *object = (OSObject *)handleManager->getObject(hObject, session->getSlot()->getSlotID());
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	*pulSize = CK_UNAVAILABLE_INFORMATION;

	return CKR_OK;
}

// Retrieve the specified attributes for the given object
CK_RV SoftHSM::C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the object handle (§2.4: scoped to this session's slot).
	OSObject *object = (OSObject *)handleManager->getObject(hObject, session->getSlot()->getSlotID());
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = object->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = object->getBooleanValue(CKA_PRIVATE, true);

	// Check read user credentials
	CK_RV rv = haveRead(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		// CKR_USER_NOT_LOGGED_IN is not a valid return code for this function,
		// so we use CKR_GENERAL_ERROR.
		return CKR_GENERAL_ERROR;
	}

	// Wrap a P11Object around the OSObject so we can access the attributes in the
	// context of the object in which it is defined.
	P11Object* p11object = NULL;
	rv = newP11Object(object,&p11object);
	if (rv != CKR_OK)
		return rv;

	// Ask the P11Object to fill the template with attribute values.
	rv = p11object->loadTemplate(token, pTemplate,ulCount);
	delete p11object;
	return rv;
}

// Change or set the value of the specified attributes on the specified object
CK_RV SoftHSM::C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the object handle (§2.4: scoped to this session's slot).
	OSObject *object = (OSObject *)handleManager->getObject(hObject, session->getSlot()->getSlotID());
	if (object == NULL_PTR || !object->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isOnToken = object->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isPrivate = object->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Check if the object is modifiable
	CK_BBOOL isModifiable = object->getBooleanValue(CKA_MODIFIABLE, true);
	if (!isModifiable) return CKR_ACTION_PROHIBITED;

	// Wrap a P11Object around the OSObject so we can access the attributes in the
	// context of the object in which it is defined.
	P11Object* p11object = NULL;
	rv = newP11Object(object,&p11object);
	if (rv != CKR_OK)
		return rv;

	// Ask the P11Object to save the template with attribute values.
	rv = p11object->saveTemplate(token, isPrivate != CK_FALSE, pTemplate,ulCount,OBJECT_OP_SET);
	delete p11object;
	return rv;
}

// Initialise object search in the specified session using the specified attribute template as search parameters
CK_RV SoftHSM::C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pTemplate == NULL_PTR && ulCount != 0) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the slot
	Slot* slot = session->getSlot();
	if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

	// Determine whether we have a public session or not.
	bool isPublicSession;
	switch (session->getState()) {
		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:
			isPublicSession = false;
			break;
		default:
			isPublicSession = true;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Check if we have another operation
	if (session->getOpType() != SESSION_OP_NONE) return CKR_OPERATION_ACTIVE;

	session->setOpType(SESSION_OP_FIND);
	FindOperation *findOp = FindOperation::create();

	// Check if we are out of memory
	if (findOp == NULL_PTR)
	{
		session->resetOp();
		return CKR_HOST_MEMORY;
	}

	std::set<OSObject*> allObjects;
	token->getObjects(allObjects);
	sessionObjectStore->getObjects(slot->getSlotID(),allObjects);

	std::set<CK_OBJECT_HANDLE> handles;
	std::set<OSObject*>::iterator it;
	for (it=allObjects.begin(); it != allObjects.end(); ++it)
	{
		// Refresh object and check if it is valid
		if (!(*it)->isValid()) {
			DEBUG_MSG("Object is not valid, skipping");
			continue;
		}

		// Determine if the object has CKA_PRIVATE set to CK_TRUE
		bool isPrivateObject = (*it)->getBooleanValue(CKA_PRIVATE, true);

		// If the object is private, and we are in a public session then skip it !
		if (isPublicSession && isPrivateObject)
			continue; // skip object

		// Perform the actual attribute matching.
		bool bAttrMatch = true; // We let an empty template match everything.
		for (CK_ULONG i=0; i<ulCount; ++i)
		{
			bAttrMatch = false;

			if (!(*it)->attributeExists(pTemplate[i].type))
				break;

			OSAttribute attr = (*it)->getAttribute(pTemplate[i].type);

			if (attr.isBooleanAttribute())
			{
				if (sizeof(CK_BBOOL) != pTemplate[i].ulValueLen)
					break;
				bool bTemplateValue = (*(CK_BBOOL*)pTemplate[i].pValue == CK_TRUE);
				if (attr.getBooleanValue() != bTemplateValue)
					break;
			}
			else
			{
				if (attr.isUnsignedLongAttribute())
				{
					if (sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
						break;
					CK_ULONG ulTemplateValue = *(CK_ULONG_PTR)pTemplate[i].pValue;
					if (attr.getUnsignedLongValue() != ulTemplateValue)
						break;
				}
				else
				{
					if (attr.isByteStringAttribute())
					{
						ByteString bsAttrValue;
						if (isPrivateObject && attr.getByteStringValue().size() != 0)
						{
							if (!token->decrypt(attr.getByteStringValue(), bsAttrValue))
							{
								delete findOp;
								session->resetOp();
								return CKR_GENERAL_ERROR;
							}
						}
						else
							bsAttrValue = attr.getByteStringValue();

						if (bsAttrValue.size() != pTemplate[i].ulValueLen)
							break;
						if (pTemplate[i].ulValueLen != 0)
						{
							ByteString bsTemplateValue((const unsigned char*)pTemplate[i].pValue, pTemplate[i].ulValueLen);
							if (bsAttrValue != bsTemplateValue)
								break;
						}
					}
					else
						break;
				}
			}
			// The attribute matched !
			bAttrMatch = true;
		}

		if (bAttrMatch)
		{
			CK_SLOT_ID slotID = slot->getSlotID();
			bool isOnToken = (*it)->getBooleanValue(CKA_TOKEN, false);
			bool isPrivate = (*it)->getBooleanValue(CKA_PRIVATE, true);
			// Create an object handle for every returned object.
			CK_OBJECT_HANDLE hObject;
			if (isOnToken)
				hObject = handleManager->addTokenObject(slotID,isPrivate,*it);
			else
				hObject = handleManager->addSessionObject(slotID,hSession,isPrivate,*it);
			if (hObject == CK_INVALID_HANDLE)
			{
				delete findOp;
				session->resetOp();
				return CKR_GENERAL_ERROR;
			}
			handles.insert(hObject);
		}
	}

	// Storing the object handles for the find will protect the library
	// whenever a stale object handle is used to access the library.
	findOp->setHandles(handles);

	session->setFindOp(findOp);

	return CKR_OK;
}

// Continue the search for objects in the specified session
CK_RV SoftHSM::C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (phObject == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulObjectCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_FIND) return CKR_OPERATION_NOT_INITIALIZED;

	// return the object handles that have been added to the find operation.
	FindOperation *findOp = session->getFindOp();
	if (findOp == NULL) return CKR_GENERAL_ERROR;

	// Ask the find operation to retrieve the object handles
	*pulObjectCount = findOp->retrieveHandles(phObject,ulMaxObjectCount);

	// Erase the object handles from the find operation.
	findOp->eraseHandles(0,*pulObjectCount);

	return CKR_OK;
}

// Finish searching for objects
CK_RV SoftHSM::C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_FIND) return CKR_OPERATION_NOT_INITIALIZED;

	session->resetOp();
	return CKR_OK;
}

CK_RV SoftHSM::CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject, int op)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phObject == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Get the slot
	Slot* slot = session->getSlot();
	if (slot == NULL_PTR) return CKR_GENERAL_ERROR;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass = CKO_DATA;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	bool isImplicit = false;
	CK_RV rv = extractObjectInformation(pTemplate,ulCount,objClass,keyType,certType, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
	{
		ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Check user credentials
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// ── S5 (2026-08-13) — hash-based-signature private keys ──────────────────
	// PKCS#11 v3.2 §6.65.3 (HSS): "CKA_SENSITIVE MUST be true, CKA_EXTRACTABLE
	// MUST be false, and CKA_COPYABLE MUST be false for this key."
	// §6.66.4 (XMSS) / §6.66.5 (XMSS-MT): "CKA_SENSITIVE MUST be true and
	// CKA_EXTRACTABLE MUST be false for this key."
	//
	// These keys hold the one-time-signature STATE in CKA_VALUE — the same
	// tables warn that "exporting this value is dangerous as it would allow key
	// reuse", and reuse of an LMS/XMSS one-time key permits forgery. Until this
	// pass neither generation nor C_CreateObject set any of the three, so the
	// class defaults applied (sensitive false) and the state was one
	// C_GetAttributeValue from extraction.
	//
	// Enforced here rather than in the keygen mechanism block because both
	// C_CreateObject and C_GenerateKeyPair reach the object through this
	// function, so one gate covers "at generation AND at object creation".
	const bool hbsPrivateKey =
		(objClass == CKO_PRIVATE_KEY) &&
		(keyType == CKK_HSS || keyType == CKK_XMSS || keyType == CKK_XMSSMT);
	if (hbsPrivateKey)
	{
		for (CK_ULONG i = 0; i < ulCount; i++)
		{
			const CK_ATTRIBUTE_TYPE t = pTemplate[i].type;
			if (t != CKA_SENSITIVE && t != CKA_EXTRACTABLE &&
			    !(keyType == CKK_HSS && t == CKA_COPYABLE))
				continue;
			if (pTemplate[i].pValue == NULL_PTR ||
			    pTemplate[i].ulValueLen != sizeof(CK_BBOOL))
				return CKR_ATTRIBUTE_VALUE_INVALID;
			const CK_BBOOL v = *(CK_BBOOL*)pTemplate[i].pValue;
			const CK_BBOOL required = (t == CKA_SENSITIVE) ? CK_TRUE : CK_FALSE;
			// §4.1.1 rule 6 lets a template restate the mandated value; rule 5
			// makes a contradicting one an error.
			if ((v != CK_FALSE) != (required != CK_FALSE))
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	// Change order of attributes
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE attribs[maxAttribs];
	CK_ATTRIBUTE saveAttribs[maxAttribs];
	CK_ULONG attribsCount = 0;
	CK_ULONG saveAttribsCount = 0;
	// Three forced entries may be appended below for HBS private keys.
	if (ulCount > (hbsPrivateKey ? maxAttribs - 3 : maxAttribs))
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}
	for (CK_ULONG i=0; i < ulCount; i++)
	{
		if (hbsPrivateKey &&
		    (pTemplate[i].type == CKA_SENSITIVE ||
		     pTemplate[i].type == CKA_EXTRACTABLE ||
		     (keyType == CKK_HSS && pTemplate[i].type == CKA_COPYABLE)))
		{
			// Validated above; the engine writes the mandated value itself.
			continue;
		}
		switch (pTemplate[i].type)
		{
			case CKA_CHECK_VALUE:
				saveAttribs[saveAttribsCount++] = pTemplate[i];
				break;
			default:
				attribs[attribsCount++] = pTemplate[i];
		}
	}
	CK_BBOOL hbsSensitive = CK_TRUE;
	CK_BBOOL hbsExtractable = CK_FALSE;
	CK_BBOOL hbsCopyable = CK_FALSE;
	if (hbsPrivateKey)
	{
		attribs[attribsCount].type = CKA_SENSITIVE;
		attribs[attribsCount].pValue = &hbsSensitive;
		attribs[attribsCount].ulValueLen = sizeof(hbsSensitive);
		attribsCount++;
		attribs[attribsCount].type = CKA_EXTRACTABLE;
		attribs[attribsCount].pValue = &hbsExtractable;
		attribs[attribsCount].ulValueLen = sizeof(hbsExtractable);
		attribsCount++;
		if (keyType == CKK_HSS)
		{
			attribs[attribsCount].type = CKA_COPYABLE;
			attribs[attribsCount].pValue = &hbsCopyable;
			attribs[attribsCount].ulValueLen = sizeof(hbsCopyable);
			attribsCount++;
		}
	}
	for (CK_ULONG i=0; i < saveAttribsCount; i++)
	{
		attribs[attribsCount++] = saveAttribs[i];
	}

	P11Object* p11object = NULL;
	rv = newP11Object(objClass,keyType,certType,&p11object);
	if (rv != CKR_OK)
		return rv;

	// Create the object in session or on the token
	OSObject *object = NULL_PTR;
	if (isOnToken)
	{
		object = (OSObject*) token->createObject();
	}
	else
	{
		object = sessionObjectStore->createObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE);
	}

	if (object == NULL)
	{
		delete p11object;
		return CKR_GENERAL_ERROR;
	}

	// Pre-set key type on the object so init() sees the correct value
	// (needed when a single P11 object class serves multiple CKK types, e.g. Edwards+Montgomery)
	if (objClass == CKO_PUBLIC_KEY || objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY)
	{
		OSAttribute attrKT((unsigned long)keyType);
		object->setAttribute(CKA_KEY_TYPE, attrKT);
	}

	if (!p11object->init(object))
	{
		delete p11object;
		return CKR_GENERAL_ERROR;
	}

	rv = p11object->saveTemplate(token, isPrivate != CK_FALSE, attribs,attribsCount,op);
	delete p11object;
	if (rv != CKR_OK)
		return rv;

	if (op == OBJECT_OP_CREATE)
	{
		if (objClass == CKO_PUBLIC_KEY &&
		    (!object->startTransaction() ||
		    !object->setAttribute(CKA_LOCAL, false) ||
		    !object->commitTransaction()))
		{
			return CKR_GENERAL_ERROR;
		}

		if ((objClass == CKO_SECRET_KEY || objClass == CKO_PRIVATE_KEY) &&
		    (!object->startTransaction() ||
		    !object->setAttribute(CKA_LOCAL, false) ||
		    !object->setAttribute(CKA_ALWAYS_SENSITIVE, false) ||
		    !object->setAttribute(CKA_NEVER_EXTRACTABLE, false) ||
		    !object->commitTransaction()))
		{
			return CKR_GENERAL_ERROR;
		}

		// Compute CKA_CHECK_VALUE for imported keys.
		// Generated keys get KCV in SoftHSM_keygen.cpp; C_CreateObject skips
		// that path so we compute it here for all key classes.
		{
			ByteString kcv;

			// Helper: read a stored attribute, decrypting if the object is private.
			// saveTemplate() may have encrypted ByteString attributes when isPrivate=true.
			auto getRawBytes = [&](CK_ATTRIBUTE_TYPE t) -> ByteString {
				if (!object->attributeExists(t)) return ByteString();
				ByteString stored = object->getAttribute(t).getByteStringValue();
				if (!stored.size()) return stored;
				if (isPrivate != CK_FALSE) {
					ByteString plain;
					if (!token->decrypt(stored, plain)) return ByteString();
					return plain;
				}
				return stored;
			};

			if (objClass == CKO_PUBLIC_KEY || objClass == CKO_PRIVATE_KEY)
			{
				// Asymmetric keys: SHA-256(key material) → first 3 bytes.
				// ML-DSA/ML-KEM/SLH-DSA store raw bytes in CKA_VALUE.
				// RSA stores modulus in CKA_MODULUS; EC stores point in CKA_EC_POINT.
				ByteString keyMaterial;
				if (object->attributeExists(CKA_VALUE))
					keyMaterial = getRawBytes(CKA_VALUE);
				else if (object->attributeExists(CKA_MODULUS))
					keyMaterial = getRawBytes(CKA_MODULUS);
				else if (object->attributeExists(CKA_EC_POINT))
					keyMaterial = getRawBytes(CKA_EC_POINT);

				if (keyMaterial.size() > 0)
				{
					HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA256);
					if (hash != NULL)
					{
						ByteString digest;
						bool ok = hash->hashInit() &&
						          hash->hashUpdate(keyMaterial) &&
						          hash->hashFinal(digest);
						CryptoFactory::i()->recycleHashAlgorithm(hash);
						if (ok && digest.size() >= 3)
							kcv = digest.substr(0, 3);
					}
				}
			}
			else if (objClass == CKO_SECRET_KEY)
			{
				// Secret keys: AES uses ECB-zero-block; others use SHA-256.
				ByteString keyBits;
				if (object->attributeExists(CKA_VALUE))
					keyBits = getRawBytes(CKA_VALUE);

				if (keyBits.size() > 0)
				{
					if (keyType == CKK_AES)
					{
						AESKey aesKey;
						aesKey.setKeyBits(keyBits);
						aesKey.setBitLen(keyBits.size() * 8);
						kcv = aesKey.getKeyCheckValue();
					}
					else
					{
						SymmetricKey symKey;
						symKey.setKeyBits(keyBits);
						symKey.setBitLen(keyBits.size() * 8);
						kcv = symKey.getKeyCheckValue();
					}
				}
			}

			if (kcv.size() > 0)
			{
				if (!object->startTransaction() ||
				    !object->setAttribute(CKA_CHECK_VALUE, kcv) ||
				    !object->commitTransaction())
				{
					// Non-fatal: KCV computation failed, leave default empty value
				}
			}
		}
	}

	if (isOnToken)
	{
		*phObject = handleManager->addTokenObject(slot->getSlotID(), isPrivate != CK_FALSE, object);
	} else {
		*phObject = handleManager->addSessionObject(slot->getSlotID(), hSession, isPrivate != CK_FALSE, object);
	}

	return CKR_OK;
}

