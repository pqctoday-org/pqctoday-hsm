/* Copyright (C) 2026 SoftHSMv3 Contributors
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _MAC_H
#define _MAC_H

/* R8 (OSSL_OP_MAC): bytes-in mode only, no SKEYMGMT dependency (per the
 * phase-4 plan's own C5 scoping). One generic "HMAC" algorithm — not
 * one name per digest — matching the default provider's own
 * convention (confirmed live: `openssl list -mac-algorithms -provider
 * default` shows a single bare "HMAC" name); the underlying digest is
 * chosen at runtime via OSSL_MAC_PARAM_DIGEST, same as
 * `openssl mac -digest SHA256 HMAC` sets it for the default provider.
 * OSSL_MAC_PARAM_KEY arrives as raw bytes, becomes an ephemeral session
 * secret key object via p11prov_create_mac_key (objects.c), then
 * C_SignInit/C_SignUpdate/C_SignFinal with the CKM_SHA*_HMAC mechanism
 * matching the chosen digest compute the MAC on-token. */

extern const OSSL_DISPATCH p11prov_hmac_mac_functions[];

#define P11PROV_NAMES_HMAC "HMAC"
#define P11PROV_DESCS_HMAC "PKCS11 HMAC Implementation"

#endif /* _MAC_H */
