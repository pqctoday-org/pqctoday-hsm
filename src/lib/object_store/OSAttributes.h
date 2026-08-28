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
 OSAttributes.h

 Specifies vendor defined attributes for use in internal object store files
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSATTRIBUTES_H
#define _SOFTHSM_V2_OSATTRIBUTES_H

#include "config.h"
#include "cryptoki.h"

// Define vendor tag; presumably the one below is reasonably unique
#define CKA_VENDOR_SOFTHSM	(CKA_VENDOR_DEFINED + 0x5348) // 'SH'

// Vendor defined attribute types for the token file
#define CKA_OS_TOKENLABEL	(CKA_VENDOR_SOFTHSM + 1)
#define CKA_OS_TOKENSERIAL	(CKA_VENDOR_SOFTHSM + 2)
#define CKA_OS_TOKENFLAGS	(CKA_VENDOR_SOFTHSM + 3)
#define CKA_OS_SOPIN		(CKA_VENDOR_SOFTHSM + 4)
#define CKA_OS_USERPIN		(CKA_VENDOR_SOFTHSM + 5)

// WS-11 (2026-08-28) — a per-object creation-order marker, stored as an
// 8-byte big-endian std::chrono::steady_clock nanosecond timestamp
// (OSToken::createObject / SessionObjectStore::createObject). Object
// *handles* only reflect discovery order within one C_Initialize/
// C_Finalize lifetime — the HandleManager (and its handle counter) is
// destroyed on every C_Finalize and rebuilt from scratch on the next
// C_Initialize, so a rediscovered token object gets a brand-new handle in
// whatever order the object store's std::set<OSObject*> (pointer-address
// order) happens to iterate, which is unrelated to when the object was
// actually created. This attribute survives C_Finalize (it is real,
// persisted object-file data, not HandleManager bookkeeping), so
// C_FindObjectsInit's ordering sort (SoftHSM_objects.cpp) uses it instead
// of the handle whenever it is present. Internal only — never registered
// with P11Attributes, so it is invisible to C_GetAttributeValue.
#define CKA_OS_CREATIONSEQ	(CKA_VENDOR_SOFTHSM + 6)

#endif // !_SOFTHSM_V2_OSATTRIBUTES_H

