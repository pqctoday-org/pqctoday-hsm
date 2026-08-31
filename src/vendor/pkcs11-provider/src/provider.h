/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _PROVIDER_H
#define _PROVIDER_H

/* We need at least -D_XOPEN_SOURCE=700 for strnlen. */
#define _XOPEN_SOURCE 700
#include "config.h"

#include <stdbool.h>
#include <sys/types.h>

#include "pkcs11.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <openssl/macros.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/ui.h>

#ifdef OSSL_OP_SKEYMGMT
#define SKEY_SUPPORT 1
#else
#define SKEY_SUPPORT 0
#endif

#define UNUSED __attribute__((unused))
#define RET_OSSL_OK 1
#define RET_OSSL_ERR 0
#define RET_OSSL_BAD -1

#define P11PROV_DEFAULT_PROPERTIES "provider=pkcs11"
#define P11PROV_FIPS_PROPERTIES "provider=pkcs11,fips=yes"

#define P11PROV_NAME_RSA "RSA"
#define P11PROV_NAMES_RSA "RSA:rsaEncryption:1.2.840.113549.1.1.1"
#define P11PROV_DESCS_RSA "PKCS11 RSA Implementation"
#define P11PROV_NAME_RSAPSS "RSA-PSS"
#define P11PROV_NAMES_RSAPSS "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10"
#define P11PROV_DESCS_RSAPSS "PKCS11 RSA PSS Implementation"
#define P11PROV_NAMES_RSA_SHA1 \
    "RSA-SHA1:RSA-SHA-1:sha1WithRSAEncryption:1.2.840.113549.1.1.5"
#define P11PROV_DESCS_RSA_SHA1 "PKCS11 RSA-SHA1 Implementation"
#define P11PROV_NAMES_RSA_SHA256 \
    "RSA-SHA2-256:RSA-SHA256:sha256WithRSAEncryption:1.2.840.113549.1.1.11"
#define P11PROV_DESCS_RSA_SHA256 "PKCS11 RSA-SHA256 Implementation"
#define P11PROV_NAMES_RSA_SHA384 \
    "RSA-SHA2-384:RSA-SHA384:sha384WithRSAEncryption:1.2.840.113549.1.1.12"
#define P11PROV_DESCS_RSA_SHA384 "PKCS11 RSA-SHA384 Implementation"
#define P11PROV_NAMES_RSA_SHA512 \
    "RSA-SHA2-512:RSA-SHA512:sha512WithRSAEncryption:1.2.840.113549.1.1.13"
#define P11PROV_DESCS_RSA_SHA512 "PKCS11 RSA-SHA512 Implementation"
#define P11PROV_NAMES_RSA_SHA224 \
    "RSA-SHA2-224:RSA-SHA224:sha224WithRSAEncryption:1.2.840.113549.1.1.14"
#define P11PROV_DESCS_RSA_SHA224 "PKCS11 RSA-SHA224 Implementation"
#define P11PROV_NAMES_RSA_SHA3_224 \
    "RSA-SHA3-224:id-rsassa-pkcs1-v1_5-with-sha3-224:2.16.840.1.101.3.4.3.13"
#define P11PROV_DESCS_RSA_SHA3_224 "PKCS11 RSA-SHA3_224 Implementation"
#define P11PROV_NAMES_RSA_SHA3_256 \
    "RSA-SHA3-256:id-rsassa-pkcs1-v1_5-with-sha3-256:2.16.840.1.101.3.4.3.14"
#define P11PROV_DESCS_RSA_SHA3_256 "PKCS11 RSA-SHA3_256 Implementation"
#define P11PROV_NAMES_RSA_SHA3_384 \
    "RSA-SHA3-384:id-rsassa-pkcs1-v1_5-with-sha3-384:2.16.840.1.101.3.4.3.15"
#define P11PROV_DESCS_RSA_SHA3_384 "PKCS11 RSA-SHA3_384 Implementation"
#define P11PROV_NAMES_RSA_SHA3_512 \
    "RSA-SHA3-512:id-rsassa-pkcs1-v1_5-with-sha3-512:2.16.840.1.101.3.4.3.16"
#define P11PROV_DESCS_RSA_SHA3_512 "PKCS11 RSA-SHA3_512 Implementation"
#define P11PROV_NAME_EC "EC"
#define P11PROV_NAMES_EC "EC:id-ecPublicKey:1.2.840.10045.2.1"
#define P11PROV_DESCS_EC "PKCS11 EC Implementation"
#define P11PROV_NAME_ECDSA "ECDSA"
#define P11PROV_NAMES_ECDSA P11PROV_NAME_ECDSA
#define P11PROV_DESCS_ECDSA "PKCS11 ECDSA Implementation"
#define P11PROV_NAMES_ECDSA_SHA1 \
    "ECDSA-SHA1:ECDSA-SHA-1:ecdsa-with-SHA1:1.2.840.10045.4.1"
#define P11PROV_DESCS_ECDSA_SHA1 "PKCS11 ECDSA-SHA1 Implementation"
#define P11PROV_NAMES_ECDSA_SHA224 \
    "ECDSA-SHA2-224:ECDSA-SHA224:ecdsa-with-SHA224:1.2.840.10045.4.3.1"
#define P11PROV_DESCS_ECDSA_SHA224 "PKCS11 ECDSA-SHA224 Implementation"
#define P11PROV_NAMES_ECDSA_SHA256 \
    "ECDSA-SHA2-256:ECDSA-SHA256:ecdsa-with-SHA256:1.2.840.10045.4.3.2"
#define P11PROV_DESCS_ECDSA_SHA256 "PKCS11 ECDSA-SHA256 Implementation"
#define P11PROV_NAMES_ECDSA_SHA384 \
    "ECDSA-SHA2-384:ECDSA-SHA384:ecdsa-with-SHA384:1.2.840.10045.4.3.3"
#define P11PROV_DESCS_ECDSA_SHA384 "PKCS11 ECDSA-SHA384 Implementation"
#define P11PROV_NAMES_ECDSA_SHA512 \
    "ECDSA-SHA2-512:ECDSA-SHA512:ecdsa-with-SHA512:1.2.840.10045.4.3.4"
#define P11PROV_DESCS_ECDSA_SHA512 "PKCS11 ECDSA-SHA512 Implementation"
#define P11PROV_NAMES_ECDSA_SHA3_224 \
    "ECDSA-SHA3-224:ecdsa_with_SHA3-224:id-ecdsa-with-sha3-224:2.16.840.1." \
    "101.3.4.3.9"
#define P11PROV_DESCS_ECDSA_SHA3_224 "PKCS11 ECDSA-SHA3_224 Implementation"
#define P11PROV_NAMES_ECDSA_SHA3_256 \
    "ECDSA-SHA3-256:ecdsa_with_SHA3-256:id-ecdsa-with-sha3-256:2.16.840.1." \
    "101.3.4.3.10"
#define P11PROV_DESCS_ECDSA_SHA3_256 "PKCS11 ECDSA-SHA3_256 Implementation"
#define P11PROV_NAMES_ECDSA_SHA3_384 \
    "ECDSA-SHA3-384:ecdsa_with_SHA3-384:id-ecdsa-with-sha3-384:2.16.840.1." \
    "101.3.4.3.11"
#define P11PROV_DESCS_ECDSA_SHA3_384 "PKCS11 ECDSA-SHA3_384 Implementation"
#define P11PROV_NAMES_ECDSA_SHA3_512 \
    "ECDSA-SHA3-512:ecdsa_with_SHA3-512:id-ecdsa-with-sha3-512:2.16.840.1." \
    "101.3.4.3.12"
#define P11PROV_DESCS_ECDSA_SHA3_512 "PKCS11 ECDSA-SHA3_512 Implementation"
#define P11PROV_NAME_ECDH "ECDH"
#define P11PROV_NAMES_ECDH P11PROV_NAME_ECDH
#define P11PROV_DESCS_ECDH "PKCS11 ECDH Implementation"
#define P11PROV_NAME_HKDF "HKDF"
#define P11PROV_NAMES_HKDF P11PROV_NAME_HKDF
#define P11PROV_DESCS_HKDF "PKCS11 HKDF Implementation"
/* Phase 4 R10: matches the default provider's own "PBKDF2" name +
 * id-PBKDF2 OID — confirmed live via `openssl list -kdf-algorithms
 * -provider default` (`{ 1.2.840.113549.1.5.12, PBKDF2 } @ default`),
 * the same check R8 (MAC) made before assuming a name convention. */
#define P11PROV_NAME_PBKDF2 "PBKDF2"
#define P11PROV_NAMES_PBKDF2 "PBKDF2:1.2.840.113549.1.5.12"
#define P11PROV_DESCS_PBKDF2 "PKCS11 PBKDF2 Implementation"
/* Phase 5 R22: no OID alias — confirmed live via `openssl list
 * -kdf-algorithms -provider default` (plain "KBKDF @ default", unlike
 * PBKDF2's OID-qualified entry above), the same check made before
 * assuming a name convention. */
#define P11PROV_NAME_KBKDF "KBKDF"
#define P11PROV_NAMES_KBKDF "KBKDF"
#define P11PROV_DESCS_KBKDF "PKCS11 SP800-108 KBKDF Implementation"
#define P11PROV_NAMES_ED25519 "ED25519:1.3.101.112"
#define P11PROV_NAME_ED25519 "ED25519"
#define P11PROV_DESCS_ED25519 "PKCS11 ED25519 Implementation"
#define P11PROV_NAMES_ED25519ph "ED25519ph"
#define P11PROV_DESCS_ED25519ph "PKCS11 ED25519ph implementation"
#define P11PROV_NAMES_ED25519ctx "ED25519ctx"
#define P11PROV_DESCS_ED25519ctx "PKCS11 ED25519ctx implementation"
#define P11PROV_NAMES_ED448 "ED448:1.3.101.113"
#define P11PROV_NAME_ED448 "ED448"
#define P11PROV_DESCS_ED448 "PKCS11 ED448 Implementation"
#define P11PROV_NAMES_ED448ph "ED448ph"
#define P11PROV_DESCS_ED448ph "PKCS11 ED448ph implementation"

/* Remediation item 4 (2026-08-30 OpenSSL-provider gap audit): CKM_EDDSA_PH
 * is a SoftHSMv3 vendor-range mechanism (src/lib/pkcs11/pkcs11t.h:
 * `CKM_VENDOR_DEFINED | 0x1057`, "Our internal alias for Pre-hash EdDSA
 * (phFlag=1)") -- not part of the standard PKCS#11 v3.2 header this
 * provider vendors (src/vendor/pkcs11-provider/src/pkcs11.h), so it has
 * no equivalent there. Defined locally here rather than in that
 * upstream-tracked file, same pattern mac.h already uses for
 * CKM_KMAC_128/256. */
#ifndef CKM_EDDSA_PH
#define CKM_EDDSA_PH (CKM_VENDOR_DEFINED | 0x00001057UL)
#endif
#define P11PROV_NAMES_ML_DSA_44 \
    "ML-DSA-44:MLDSA44:2.16.840.1.101.3.4.3.17:id-ml-dsa-44"
#define P11PROV_DESCS_ML_DSA_44 "PKCS11 ML-DSA-44 implementation"
#define P11PROV_NAMES_ML_DSA_65 \
    "ML-DSA-65:MLDSA65:2.16.840.1.101.3.4.3.18:id-ml-dsa-65"
#define P11PROV_DESCS_ML_DSA_65 "PKCS11 ML-DSA-65 implementation"
#define P11PROV_NAMES_ML_DSA_87 \
    "ML-DSA-87:MLDSA87:2.16.840.1.101.3.4.3.19:id-ml-dsa-87"
#define P11PROV_DESCS_ML_DSA_87 "PKCS11 ML-DSA-87 implementation"

/* Remediation item 5 (2026-08-30, risk-accepted): bespoke vendor names --
 * unlike ML_DSA_44/65/87 above, OpenSSL itself has no native "Pre Hash
 * ML-DSA"/"Pre Hash SLH-DSA" algorithm identity or OID to alias (real
 * OpenSSL 4.0 docs, EVP_SIGNATURE-ML-DSA(7) / EVP_SIGNATURE-SLH-DSA(7) --
 * confirmed byte-identical in the vendored OpenSSL 3.6.3 tree this
 * provider actually builds against, doc/man7/EVP_SIGNATURE-ML-DSA.pod /
 * EVP_SIGNATURE-SLH-DSA.pod: "OpenSSL does not support Pre Hash ML-DSA
 * [/SLH-DSA] Signature Generation, but this may be done by the user by
 * doing Pre hash encoding externally and then choosing the option to not
 * encode the message" -- message-encoding=0 is documented as "used for
 * testing", not a stable production contract). One generic name per
 * family, paramset-agnostic (see sig/mldsa.c's p11prov_hash_mldsa_* /
 * sig/slhdsa.c's p11prov_hash_slhdsa_* — paramset is resolved from the
 * bound key at runtime, mirroring sig/xmss.c's own generic-name pattern),
 * following this file's own COMPOSITE_*-style convention for names this
 * provider invents rather than a real external standard/OID. */
#define P11PROV_NAMES_HASH_ML_DSA "HASH-ML-DSA"
#define P11PROV_DESCS_HASH_ML_DSA \
    "PKCS11 HashML-DSA pre-hash implementation (CKM_HASH_ML_DSA* family; " \
    "rests on OpenSSL's own testing-only message-encoding=0 escape hatch)"
#define P11PROV_NAMES_HASH_SLH_DSA "HASH-SLH-DSA"
#define P11PROV_DESCS_HASH_SLH_DSA \
    "PKCS11 HashSLH-DSA pre-hash implementation (CKM_HASH_SLH_DSA* family; " \
    "rests on OpenSSL's own testing-only message-encoding=0 escape hatch)"

/* Composite-ML-DSA signature profiles per draft-ietf-lamps-pq-composite-sigs-19.
 * OIDs are stable in draft-19 §6; PKIX alg arc 1.3.6.1.5.5.7.6.{37,45,49}. */
#define P11PROV_NAMES_COMPOSITE_MLDSA44_RSA2048_PSS \
    "MLDSA44-RSA2048-PSS-SHA256:id-MLDSA44-RSA2048-PSS-SHA256:1.3.6.1.5.5.7.6.37"
#define P11PROV_DESCS_COMPOSITE_MLDSA44_RSA2048_PSS \
    "PKCS11 Composite ML-DSA-44 + RSA-2048-PSS-SHA256 (draft-lamps-19)"

#define P11PROV_NAMES_COMPOSITE_MLDSA65_ECDSA_P256 \
    "MLDSA65-ECDSA-P256-SHA512:id-MLDSA65-ECDSA-P256-SHA512:1.3.6.1.5.5.7.6.45"
#define P11PROV_DESCS_COMPOSITE_MLDSA65_ECDSA_P256 \
    "PKCS11 Composite ML-DSA-65 + ECDSA-P256-SHA512 (draft-lamps-19)"

#define P11PROV_NAMES_COMPOSITE_MLDSA87_ECDSA_P384 \
    "MLDSA87-ECDSA-P384-SHA512:id-MLDSA87-ECDSA-P384-SHA512:1.3.6.1.5.5.7.6.49"
#define P11PROV_DESCS_COMPOSITE_MLDSA87_ECDSA_P384 \
    "PKCS11 Composite ML-DSA-87 + ECDSA-P384-SHA512 (draft-lamps-19)"

/* Phase 4 R7: profiles 4-8. OIDs verified against kmip/src/kmip30/algos.rs
 * and draft-lamps-pq-composite-sigs-19 §6. */
#define P11PROV_NAMES_COMPOSITE_MLDSA44_ED25519 \
    "MLDSA44-Ed25519-SHA512:id-MLDSA44-Ed25519-SHA512:1.3.6.1.5.5.7.6.39"
#define P11PROV_DESCS_COMPOSITE_MLDSA44_ED25519 \
    "PKCS11 Composite ML-DSA-44 + Ed25519-SHA512 (draft-lamps-19)"

#define P11PROV_NAMES_COMPOSITE_MLDSA44_ECDSA_P256_SHA256 \
    "MLDSA44-ECDSA-P256-SHA256:id-MLDSA44-ECDSA-P256-SHA256:1.3.6.1.5.5.7.6.40"
#define P11PROV_DESCS_COMPOSITE_MLDSA44_ECDSA_P256_SHA256 \
    "PKCS11 Composite ML-DSA-44 + ECDSA-P256-SHA256 (draft-lamps-19)"

#define P11PROV_NAMES_COMPOSITE_MLDSA65_RSA3072_PSS \
    "MLDSA65-RSA3072-PSS-SHA512:id-MLDSA65-RSA3072-PSS-SHA512:1.3.6.1.5.5.7.6.41"
#define P11PROV_DESCS_COMPOSITE_MLDSA65_RSA3072_PSS \
    "PKCS11 Composite ML-DSA-65 + RSA-3072-PSS-SHA512 (draft-lamps-19)"

#define P11PROV_NAMES_COMPOSITE_MLDSA65_ED25519 \
    "MLDSA65-Ed25519-SHA512:id-MLDSA65-Ed25519-SHA512:1.3.6.1.5.5.7.6.48"
#define P11PROV_DESCS_COMPOSITE_MLDSA65_ED25519 \
    "PKCS11 Composite ML-DSA-65 + Ed25519-SHA512 (draft-lamps-19)"

#define P11PROV_NAMES_COMPOSITE_MLDSA65_ECDSA_P384 \
    "MLDSA65-ECDSA-P384-SHA512:id-MLDSA65-ECDSA-P384-SHA512:1.3.6.1.5.5.7.6.46"
#define P11PROV_DESCS_COMPOSITE_MLDSA65_ECDSA_P384 \
    "PKCS11 Composite ML-DSA-65 + ECDSA-P384-SHA512 (draft-lamps-19)"

/* Composite keymgmt / signature / encoder dispatch tables (composite.c) */
extern const OSSL_DISPATCH p11prov_composite_mldsa44_rsa2048_pss_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa65_ecdsa_p256_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa87_ecdsa_p384_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa44_ed25519_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa44_ecdsa_p256_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa65_rsa3072_pss_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa65_ed25519_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa65_ecdsa_p384_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa44_rsa2048_pss_sig_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa65_ecdsa_p256_sig_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa87_ecdsa_p384_sig_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa44_ed25519_sig_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa44_ecdsa_p256_sig_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa65_rsa3072_pss_sig_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa65_ed25519_sig_functions[];
extern const OSSL_DISPATCH p11prov_composite_mldsa65_ecdsa_p384_sig_functions[];
/* Single SPKI encoder per output format — keyed by the composite profile
 * embedded in the keydata, so one table serves all eight composite OIDs. */
extern const OSSL_DISPATCH p11prov_composite_encoder_spki_der_functions[];
extern const OSSL_DISPATCH p11prov_composite_encoder_spki_pem_functions[];
/* Per-profile SPKI DER decoders — used by X509_get0_pubkey to round-trip
 * cert SPKI bytes into a (software-mode) composite EVP_PKEY, so
 * X509_check_private_key inside CMS_sign can match cert against signing
 * key via the keymgmt MATCH function. */
extern const OSSL_DISPATCH
    p11prov_composite_mldsa44_rsa2048_pss_decoder_der_functions[];
extern const OSSL_DISPATCH
    p11prov_composite_mldsa65_ecdsa_p256_decoder_der_functions[];
extern const OSSL_DISPATCH
    p11prov_composite_mldsa87_ecdsa_p384_decoder_der_functions[];

#define P11PROV_NAME_X25519 "X25519"
#define P11PROV_NAMES_X25519 "X25519:1.3.101.110"
#define P11PROV_DESCS_X25519 "PKCS11 X25519 Implementation"

#define P11PROV_NAME_X448 "X448"
#define P11PROV_NAMES_X448 "X448:1.3.101.111"
#define P11PROV_DESCS_X448 "PKCS11 X448 Implementation"

/* SLH-DSA (FIPS 205), all 12 parameter sets — per-variant like ML-DSA's
 * 44/65/87 (not the single generic name the earlier scaffolding used),
 * so each variant gets its own OpenSSL namemap identity and
 * `-algorithm SLH-DSA-SHA2-128s` etc. via `?provider=pkcs11` resolves
 * straight to this provider's implementation instead of a name that
 * doesn't match OpenSSL's own 12 native algorithm names. */
#define P11PROV_NAMES_SLH_DSA_SHA2_128S "SLH-DSA-SHA2-128s"
#define P11PROV_DESCS_SLH_DSA_SHA2_128S "PKCS11 SLH-DSA-SHA2-128s Implementation"
#define P11PROV_NAMES_SLH_DSA_SHAKE_128S "SLH-DSA-SHAKE-128s"
#define P11PROV_DESCS_SLH_DSA_SHAKE_128S "PKCS11 SLH-DSA-SHAKE-128s Implementation"
#define P11PROV_NAMES_SLH_DSA_SHA2_128F "SLH-DSA-SHA2-128f"
#define P11PROV_DESCS_SLH_DSA_SHA2_128F "PKCS11 SLH-DSA-SHA2-128f Implementation"
#define P11PROV_NAMES_SLH_DSA_SHAKE_128F "SLH-DSA-SHAKE-128f"
#define P11PROV_DESCS_SLH_DSA_SHAKE_128F "PKCS11 SLH-DSA-SHAKE-128f Implementation"
#define P11PROV_NAMES_SLH_DSA_SHA2_192S "SLH-DSA-SHA2-192s"
#define P11PROV_DESCS_SLH_DSA_SHA2_192S "PKCS11 SLH-DSA-SHA2-192s Implementation"
#define P11PROV_NAMES_SLH_DSA_SHAKE_192S "SLH-DSA-SHAKE-192s"
#define P11PROV_DESCS_SLH_DSA_SHAKE_192S "PKCS11 SLH-DSA-SHAKE-192s Implementation"
#define P11PROV_NAMES_SLH_DSA_SHA2_192F "SLH-DSA-SHA2-192f"
#define P11PROV_DESCS_SLH_DSA_SHA2_192F "PKCS11 SLH-DSA-SHA2-192f Implementation"
#define P11PROV_NAMES_SLH_DSA_SHAKE_192F "SLH-DSA-SHAKE-192f"
#define P11PROV_DESCS_SLH_DSA_SHAKE_192F "PKCS11 SLH-DSA-SHAKE-192f Implementation"
#define P11PROV_NAMES_SLH_DSA_SHA2_256S "SLH-DSA-SHA2-256s"
#define P11PROV_DESCS_SLH_DSA_SHA2_256S "PKCS11 SLH-DSA-SHA2-256s Implementation"
#define P11PROV_NAMES_SLH_DSA_SHAKE_256S "SLH-DSA-SHAKE-256s"
#define P11PROV_DESCS_SLH_DSA_SHAKE_256S "PKCS11 SLH-DSA-SHAKE-256s Implementation"
#define P11PROV_NAMES_SLH_DSA_SHA2_256F "SLH-DSA-SHA2-256f"
#define P11PROV_DESCS_SLH_DSA_SHA2_256F "PKCS11 SLH-DSA-SHA2-256f Implementation"
#define P11PROV_NAMES_SLH_DSA_SHAKE_256F "SLH-DSA-SHAKE-256f"
#define P11PROV_DESCS_SLH_DSA_SHAKE_256F "PKCS11 SLH-DSA-SHAKE-256f Implementation"
/* Phase 4 R9: HSS/LMS. This provider generates/signs via CKK_HSS (the
 * project's own key type — see CLAUDE.md), a genuinely different
 * EVP_PKEY identity from OpenSSL's own software "LMS", so it gets its
 * own name rather than aliasing into that one. */
#define P11PROV_NAMES_HSS "HSS"
#define P11PROV_DESCS_HSS "PKCS11 HSS/LMS Implementation"
/* keymgmt tables: keymgmt.h. Encoder tables: encoder.h. Signature tables:
 * sig/signature.h. Matches ML-DSA's own per-header convention. */

#define P11PROV_NAMES_ML_KEM "ML-KEM:ML-KEM-512:ML-KEM-768:ML-KEM-1024"
#define P11PROV_NAME_ML_KEM P11PROV_NAMES_ML_KEM
#define P11PROV_DESCS_ML_KEM "PKCS11 ML-KEM Implementation"
#define P11PROV_NAMES_ML_KEM_512 "ML-KEM-512:MLKEM512"
#define P11PROV_DESCS_ML_KEM_512 "PKCS11 ML-KEM-512 Implementation"
#define P11PROV_NAMES_ML_KEM_768 "ML-KEM-768:MLKEM768"
#define P11PROV_DESCS_ML_KEM_768 "PKCS11 ML-KEM-768 Implementation"
#define P11PROV_NAMES_ML_KEM_1024 "ML-KEM-1024:MLKEM1024"
#define P11PROV_DESCS_ML_KEM_1024 "PKCS11 ML-KEM-1024 Implementation"

#define P11PROV_NAMES_XMSS "XMSS"
#define P11PROV_NAME_XMSS P11PROV_NAMES_XMSS
#define P11PROV_DESCS_XMSS "PKCS11 XMSS Implementation"
/* Remediation R41 (phase 8) */
#define P11PROV_NAMES_XMSSMT "XMSSMT:XMSS-MT"
#define P11PROV_NAME_XMSSMT P11PROV_NAMES_XMSSMT
#define P11PROV_DESCS_XMSSMT "PKCS11 XMSS^MT Implementation"

#define P11PROV_NAMES_RAND "PKCS11-RAND"
#define P11PROV_DESCS_RAND "PKCS11 Random Generator"
#define P11PROV_NAME_CERTIFICATE "CERTIFICATE"
#define P11PROV_NAME_TLS13_KDF "TLS13-KDF"
#define P11PROV_NAMES_TLS13_KDF P11PROV_NAME_TLS13_KDF
#define P11PROV_DESCS_TLS13_KDF "PKCS11 TLS 1.3 HKDF Implementation"
#define P11PROV_NAMES_DER "DER"
#define P11PROV_DESCS_DER "DER decoder implementation in PKCS11 provider"
#define P11PROV_NAMES_URI "pkcs11"
#define P11PROV_DESCS_URI "PKCS11 URI Store"

#define P11PROV_PARAM_URI "pkcs11_uri"
#define P11PROV_PARAM_EPHEMERAL "pkcs11_ephemeral"
#define P11PROV_PARAM_KEY_USAGE "pkcs11_key_usage"
#define P11PROV_PARAM_SLOT_ID "pkcs11_slot_id"

#if SKEY_SUPPORT == 1

#define P11PROV_NAME_GENERIC_SECRET "GENERIC-SECRET"

#define P11PROV_NAME_AES "AES"
#define P11PROV_NAMES_AES "AES:2.16.840.1.101.3.4.1"
#define P11PROV_DESCS_AES "PKCS11 AES Implementation"
#define P11PROV_NAMES_AES_256_ECB "AES-256-ECB:2.16.840.1.101.3.4.1.41"
#define P11PROV_DESCS_AES_256_ECB "AES-256 ECB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_ECB "AES-192-ECB:2.16.840.1.101.3.4.1.21"
#define P11PROV_DESCS_AES_192_ECB "AES-192 ECB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_ECB "AES-128-ECB:2.16.840.1.101.3.4.1.1"
#define P11PROV_DESCS_AES_128_ECB "AES-128 ECB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CBC \
    "AES-256-CBC:AES256:aes256:2.16.840.1.101.3.4.1.42"
#define P11PROV_DESCS_AES_256_CBC "AES-256 CBC PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CBC \
    "AES-192-CBC:AES192:aes192:2.16.840.1.101.3.4.1.22"
#define P11PROV_DESCS_AES_192_CBC "AES-192 CBC PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CBC \
    "AES-128-CBC:AES128:aes128:2.16.840.1.101.3.4.1.2"
#define P11PROV_DESCS_AES_128_CBC "AES-128 CBC PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_OFB "AES-256-OFB:2.16.840.1.101.3.4.1.43"
#define P11PROV_DESCS_AES_256_OFB "AES-256 OFB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_OFB "AES-192-OFB:2.16.840.1.101.3.4.1.23"
#define P11PROV_DESCS_AES_192_OFB "AES-192 OFB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_OFB "AES-128-OFB:2.16.840.1.101.3.4.1.3"
#define P11PROV_DESCS_AES_128_OFB "AES-128 OFB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CFB "AES-256-CFB:2.16.840.1.101.3.4.1.44"
#define P11PROV_DESCS_AES_256_CFB \
    "AES-256 CFB128 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CFB "AES-192-CFB:2.16.840.1.101.3.4.1.24"
#define P11PROV_DESCS_AES_192_CFB \
    "AES-192 CFB128 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CFB "AES-128-CFB:2.16.840.1.101.3.4.1.4"
#define P11PROV_DESCS_AES_128_CFB \
    "AES-128 CFB128 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CFB1 "AES-256-CFB1"
#define P11PROV_DESCS_AES_256_CFB1 "AES-256 CFB1 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CFB1 "AES-192-CFB1"
#define P11PROV_DESCS_AES_192_CFB1 "AES-192 CFB1 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CFB1 "AES-128-CFB1"
#define P11PROV_DESCS_AES_128_CFB1 "AES-128 CFB1 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CFB8 "AES-256-CFB8"
#define P11PROV_DESCS_AES_256_CFB8 "AES-256 CFB8 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CFB8 "AES-192-CFB8"
#define P11PROV_DESCS_AES_192_CFB8 "AES-192 CFB8 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CFB8 "AES-128-CFB8"
#define P11PROV_DESCS_AES_128_CFB8 "AES-128 CFB8 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CTR "AES-256-CTR"
#define P11PROV_DESCS_AES_256_CTR "AES-256 CTR PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CTR "AES-192-CTR"
#define P11PROV_DESCS_AES_192_CTR "AES-192 CTR PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CTR "AES-128-CTR"
#define P11PROV_DESCS_AES_128_CTR "AES-128 CTR PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CTS "AES-256-CBC-CTS"
#define P11PROV_DESCS_AES_256_CTS "AES-256 CTS PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CTS "AES-192-CBC-CTS"
#define P11PROV_DESCS_AES_192_CTS "AES-192 CTS PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CTS "AES-128-CBC-CTS"
#define P11PROV_DESCS_AES_128_CTS "AES-128 CTS PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_GCM "AES-256-GCM:id-aes256-GCM"
#define P11PROV_DESCS_AES_256_GCM "AES-256 GCM PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_GCM "AES-192-GCM:id-aes192-GCM"
#define P11PROV_DESCS_AES_192_GCM "AES-192 GCM PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_GCM "AES-128-GCM:id-aes128-GCM"
#define P11PROV_DESCS_AES_128_GCM "AES-128 GCM PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CCM "AES-256-CCM:id-aes256-CCM"
#define P11PROV_DESCS_AES_256_CCM "AES-256 CCM PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CCM "AES-192-CCM:id-aes192-CCM"
#define P11PROV_DESCS_AES_192_CCM "AES-192 CCM PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CCM "AES-128-CCM:id-aes128-CCM"
#define P11PROV_DESCS_AES_128_CCM "AES-128 CCM PKCS11 Provider Implementation"
/* AES-XTS remediation item (2026-08-30). Names confirmed against
 * `docs.openssl.org/3.6/man7/EVP_CIPHER-AES/`: only 128/256-bit variants
 * exist (XTS combines two AES keys, so there is no 192-bit XTS). */
#define P11PROV_NAMES_AES_256_XTS "AES-256-XTS"
#define P11PROV_DESCS_AES_256_XTS "AES-256 XTS PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_XTS "AES-128-XTS"
#define P11PROV_DESCS_AES_128_XTS "AES-128 XTS PKCS11 Provider Implementation"
/* AES Key Wrap remediation item (2026-08-30). Names confirmed against
 * `docs.openssl.org/3.6/man7/EVP_CIPHER-AES/`. "AES-*-WRAP-PAD" (RFC
 * 5649) is registered once, backed by CKM_AES_KEY_WRAP_KWP -- see
 * cipher.c's own DISPATCH_TABLE_CIPHER_WRAP_FN(..., wrappad, ...) call
 * sites for why CKM_AES_KEY_WRAP_PAD needs no separate registration. */
#define P11PROV_NAMES_AES_256_WRAP "AES-256-WRAP:id-aes256-wrap"
#define P11PROV_DESCS_AES_256_WRAP "AES-256 WRAP PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_WRAP "AES-192-WRAP:id-aes192-wrap"
#define P11PROV_DESCS_AES_192_WRAP "AES-192 WRAP PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_WRAP "AES-128-WRAP:id-aes128-wrap"
#define P11PROV_DESCS_AES_128_WRAP "AES-128 WRAP PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_WRAP_PAD "AES-256-WRAP-PAD:id-aes256-wrap-pad"
#define P11PROV_DESCS_AES_256_WRAP_PAD \
    "AES-256 WRAP-PAD PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_WRAP_PAD "AES-192-WRAP-PAD:id-aes192-wrap-pad"
#define P11PROV_DESCS_AES_192_WRAP_PAD \
    "AES-192 WRAP-PAD PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_WRAP_PAD "AES-128-WRAP-PAD:id-aes128-wrap-pad"
#define P11PROV_DESCS_AES_128_WRAP_PAD \
    "AES-128 WRAP-PAD PKCS11 Provider Implementation"
/* Phase 5 R26. Names confirmed live against `openssl list -cipher-
 * algorithms -provider default` -- no OID alias for either, unlike most
 * AES variants above. */
#define P11PROV_NAMES_CHACHA20 "ChaCha20"
#define P11PROV_DESCS_CHACHA20 "ChaCha20 PKCS11 Provider Implementation"
#define P11PROV_NAMES_CHACHA20_POLY1305 "ChaCha20-Poly1305"
#define P11PROV_DESCS_CHACHA20_POLY1305 \
    "ChaCha20-Poly1305 PKCS11 Provider Implementation"
#define P11PROV_NAME_GENERIC_SECRET "GENERIC-SECRET"
#define P11PROV_NAMES_GENERIC_SECRET P11PROV_NAME_GENERIC_SECRET
#define P11PROV_DESCS_GENERIC_SECRET "PKCS11 Generic Secret Implementation"

#endif

typedef struct p11prov_ctx P11PROV_CTX;
typedef struct p11prov_module_ctx P11PROV_MODULE;
typedef struct p11prov_interface P11PROV_INTERFACE;
typedef struct p11prov_uri P11PROV_URI;
typedef struct p11prov_obj P11PROV_OBJ;
typedef struct p11prov_slot P11PROV_SLOT;
typedef struct p11prov_slots_ctx P11PROV_SLOTS_CTX;
typedef struct p11prov_session P11PROV_SESSION;
typedef struct p11prov_session_pool P11PROV_SESSION_POOL;
typedef struct p11prov_obj_pool P11PROV_OBJ_POOL;

#if __SANITIZE_ADDRESS__
#define P11PROV_ADDRESS_SANITIZER 1
#endif
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define P11PROV_ADDRESS_SANITIZER 1
#endif
#endif

/* Provider ctx */
P11PROV_INTERFACE *p11prov_ctx_get_interface(P11PROV_CTX *ctx);
CK_UTF8CHAR_PTR p11prov_ctx_pin(P11PROV_CTX *ctx);
OSSL_LIB_CTX *p11prov_ctx_get_libctx(P11PROV_CTX *ctx);
CK_RV p11prov_ctx_status(P11PROV_CTX *ctx);
P11PROV_SLOTS_CTX *p11prov_ctx_get_slots(P11PROV_CTX *ctx);
void p11prov_ctx_set_slots(P11PROV_CTX *ctx, P11PROV_SLOTS_CTX *slots);
CK_RV p11prov_ctx_get_quirk(P11PROV_CTX *ctx, CK_SLOT_ID id, const char *name,
                            void **data, CK_ULONG *size);
CK_RV p11prov_ctx_set_quirk(P11PROV_CTX *ctx, CK_SLOT_ID id, const char *name,
                            void *data, CK_ULONG size);
#define GET_ATTR 0
#define SET_ATTR 1
CK_RV p11prov_token_sup_attr(P11PROV_CTX *ctx, CK_SLOT_ID id, int action,
                             CK_ATTRIBUTE_TYPE attr, CK_BBOOL *data);

#define ALLOW_EXPORT_PUBLIC 0
#define DISALLOW_EXPORT_PUBLIC 1
int p11prov_ctx_allow_export(P11PROV_CTX *ctx);

#define PUBKEY_LOGIN_AUTO 0
#define PUBKEY_LOGIN_ALWAYS 1
#define PUBKEY_LOGIN_NEVER 2
int p11prov_ctx_login_behavior(P11PROV_CTX *ctx);
bool p11prov_ctx_cache_pins(P11PROV_CTX *ctx);

enum p11prov_cache_keys {
    P11PROV_CACHE_KEYS_NEVER = 0,
    P11PROV_CACHE_KEYS_IN_SESSION,
};
int p11prov_ctx_cache_keys(P11PROV_CTX *ctx);
int p11prov_ctx_cache_sessions(P11PROV_CTX *ctx);

bool p11prov_ctx_is_call_blocked(P11PROV_CTX *ctx, uint64_t mask);
bool p11prov_ctx_no_session_callbacks(P11PROV_CTX *ctx);

CK_INFO p11prov_ctx_get_ck_info(P11PROV_CTX *ctx);

#include "debug.h"

/* Errors */
void p11prov_raise(P11PROV_CTX *ctx, const char *file, int line,
                   const char *func, int errnum, const char *fmt, ...);

#define P11PROV_raise(ctx, errnum, format, ...) \
    do { \
        p11prov_raise((ctx), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, \
                      (errnum), format, ##__VA_ARGS__); \
        P11PROV_debug("Error: 0x%08lX; " format, (unsigned long)(errnum), \
                      ##__VA_ARGS__); \
    } while (0)

int p11prov_set_error_mark(P11PROV_CTX *ctx);
int p11prov_clear_last_error_mark(P11PROV_CTX *ctx);
int p11prov_pop_error_to_mark(P11PROV_CTX *ctx);

/* dispatching */
#define DECL_DISPATCH_FUNC(type, prefix, name) \
    static OSSL_FUNC_##type##_##name##_fn prefix##_##name

extern const OSSL_DISPATCH p11prov_slhdsa_signature_functions[];
extern const OSSL_DISPATCH p11prov_mlkem_kem_functions[];
extern const OSSL_DISPATCH p11prov_mlkem512_kem_functions[];
extern const OSSL_DISPATCH p11prov_mlkem768_kem_functions[];
extern const OSSL_DISPATCH p11prov_mlkem1024_kem_functions[];
extern const OSSL_DISPATCH p11prov_mlkem_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mlkem512_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mlkem1024_keymgmt_functions[];

#include "interface.h"
#include "objects.h"
#include "keymgmt.h"
#include "store.h"
#include "sig/signature.h"
#include "asymmetric_cipher.h"
#include "exchange.h"
#include "kdf.h"
#include "encoder.h"
#include "digests.h"
#include "mac.h"
#include "util.h"
#include "session.h"
#include "slot.h"
#include "random.h"
#include "pk11_uri.h"

#if SKEY_SUPPORT == 1
#include "cipher.h"
#include "skeymgmt.h"
#endif

/* TLS */
int tls_group_capabilities(OSSL_CALLBACK *cb, void *arg);
int tls_sigalg_capabilities(OSSL_CALLBACK *cb, void *arg);

/* Phase 5 R25: real RFC 8554 HSS signature size for a given key (sig/hss.c),
 * shared with keymgmt.c's own OSSL_PKEY_PARAM_MAX_SIZE so the two never
 * drift apart. */
size_t hss_sig_size_for_key(P11PROV_OBJ *key);

/* Remediation R41 (phase 8): real RFC 8391/SP 800-208 XMSS/XMSS^MT
 * signature size for a given key (sig/xmss.c), shared with keymgmt.c's
 * own OSSL_PKEY_PARAM_MAX_SIZE -- same reason as hss_sig_size_for_key
 * above. Reads CKA_PARAMETER_SET off the key; `is_mt` selects the
 * XMSS vs XMSS^MT formula (the two have different parameter-set value
 * spaces and different signature layouts, RFC 8391 SS4.2 vs SS4.2.3). */
size_t xmss_sig_size_for_key(P11PROV_OBJ *key, bool is_mt);

#endif /* _PROVIDER_H */
