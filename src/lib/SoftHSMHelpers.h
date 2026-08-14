/*
 * Copyright (c) 2022 NLnet Labs
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
 SoftHSMHelpers.h

 Private implementation constants shared across SoftHSM split translation
 units.  This file is NOT installed and is not part of the public API.
 *****************************************************************************/

#ifndef _SOFTHSM_V3_SOFTSHM_HELPERS_H
#define _SOFTHSM_V3_SOFTSHM_HELPERS_H

#include "cryptoki.h"
#include "ByteString.h"
#include <cstddef>

// ---------------------------------------------------------------------------
// Named key-size constants — replaces raw magic numbers (Md1).
// Defined as static constexpr so each TU gets its own copy without ODR issues.
// ---------------------------------------------------------------------------

/// Maximum ulMaxKeySize for mechanisms with no practical key-size limit (2^31).
static constexpr CK_ULONG UNLIMITED_KEY_SIZE       = 0x80000000UL;

/// Hard cap on generic secret key byte length in C_GenerateKey (128 MiB).
static constexpr CK_ULONG MAX_GENERIC_KEY_LEN_BYTES = 0x8000000UL;

/// Maximum HMAC key length in bytes (512 bytes / 4096 bits, matches upstream).
static constexpr CK_ULONG MAX_HMAC_KEY_BYTES        = 512UL;

/// Valid AES key lengths in bytes.
static constexpr CK_ULONG AES_KEY_BYTES_128         = 16UL;  ///< AES-128
static constexpr CK_ULONG AES_KEY_BYTES_192         = 24UL;  ///< AES-192
static constexpr CK_ULONG AES_KEY_BYTES_256         = 32UL;  ///< AES-256

// ---------------------------------------------------------------------------
// Cross-file free-function declarations.
// ---------------------------------------------------------------------------

/// Reset MutexFactory callbacks to the OS-native implementations.
/// Defined in SoftHSM.cpp; called by constructor, destructor, and C_Initialize.
void resetMutexFactoryCallbacks();

/// Check that a secret-key byte length is valid for the given CKK_* type.
/// Defined in SoftHSM_objects.cpp; used by objects and keygen files.
CK_RV checkKeyLength(CK_KEY_TYPE keyType, size_t byteLen);

/// Extract CKA_CLASS / CKA_KEY_TYPE / CKA_TOKEN / CKA_PRIVATE from a
/// template.  bImplicit=true skips the "class required" check (for unwrap).
/// Defined in SoftHSM_objects.cpp; used by objects, keygen, and kem files.
CK_RV extractObjectInformation(CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulCount,
                               CK_OBJECT_CLASS& objClass,
                               CK_KEY_TYPE& keyType,
                               CK_CERTIFICATE_TYPE& certType,
                               CK_BBOOL& isOnToken,
                               CK_BBOOL& isPrivate,
                               bool bImplicit);

/// Compute the PKCS#11 v3.2 §4.11 / §4.10.2 key check value of a secret key:
/// CKK_AES → AES-ECB(zero block)[0:3]; every other symmetric type →
/// SHA-1(keyBits)[0:3].  Returns an empty ByteString when it cannot be
/// computed.  Defined in SoftHSM_keygen.cpp; used by keygen and kem files.
ByteString computeSecretKeyKCV(CK_KEY_TYPE keyType, const ByteString& keyBits);

/// PKCS#11 v3.2 §4.11 CKA_CHECK_VALUE template handling, shared by every
/// object-creation function that contributes a secret key.
///   • a no-value (0 length) entry suppresses generation  → generate=false
///   • a non-empty entry is the caller's claim, to be compared against what
///     the library computes                              → supplied=true
/// Returns CKR_ATTRIBUTE_VALUE_INVALID for a malformed entry.
/// Defined in SoftHSM_objects.cpp.
CK_RV checkValueFromTemplate(const CK_ATTRIBUTE& attr, bool& generate,
                             bool& supplied, ByteString& suppliedValue);

#endif // !_SOFTHSM_V3_SOFTSHM_HELPERS_H
