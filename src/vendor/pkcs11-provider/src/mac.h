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

/* CKM_KMAC_128/256 are vendor-defined (OASIS-assigned CKM_VENDOR_DEFINED
 * range, not the standard v3.2 header this provider vendors) — this
 * project's own engine defines them the same way
 * (src/lib/pkcs11/pkcs11t.h: `CKM_VENDOR_DEFINED | 0x100`/`0x101`); no
 * equivalent exists in the provider's own vendored pkcs11.h, so defined
 * locally here rather than in that upstream-tracked file. */
#ifndef CKM_KMAC_128
#define CKM_KMAC_128 (CKM_VENDOR_DEFINED | 0x00000100UL)
#endif
#ifndef CKM_KMAC_256
#define CKM_KMAC_256 (CKM_VENDOR_DEFINED | 0x00000101UL)
#endif

/* Phase 5 R23: CMAC and KMAC-128/256 join HMAC as real OSSL_OP_MAC
 * implementations (the OP-1/ALG-8 remainder R8 left open), plus
 * OSSL_FUNC_MAC_INIT_SKEY for all three — see mac.c's own struct
 * comment for the R24 finding that motivated it. Names confirmed live
 * via `openssl list -mac-algorithms -provider default`: bare "CMAC" (no
 * OID shown there, unlike HMAC/KMAC), "KMAC-128"/"KMAC128" and
 * "KMAC-256"/"KMAC256" with their FIPS 202/SP 800-185 OIDs. */
extern const OSSL_DISPATCH p11prov_cmac_mac_functions[];
extern const OSSL_DISPATCH p11prov_kmac128_mac_functions[];
extern const OSSL_DISPATCH p11prov_kmac256_mac_functions[];

#define P11PROV_NAMES_CMAC "CMAC"
#define P11PROV_DESCS_CMAC "PKCS11 CMAC Implementation"
#define P11PROV_NAMES_KMAC128 "KMAC-128:KMAC128:2.16.840.1.101.3.4.2.19"
#define P11PROV_DESCS_KMAC128 "PKCS11 KMAC-128 Implementation"
#define P11PROV_NAMES_KMAC256 "KMAC-256:KMAC256:2.16.840.1.101.3.4.2.20"
#define P11PROV_DESCS_KMAC256 "PKCS11 KMAC-256 Implementation"

#endif /* _MAC_H */
