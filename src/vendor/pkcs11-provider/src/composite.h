/* Copyright (C) 2026 pqctoday-org
   SPDX-License-Identifier: Apache-2.0 */

/* Public declarations for LAMPS composite-sig support
 * (draft-ietf-lamps-pq-composite-sigs-19).
 *
 * Most of composite.c is invoked indirectly through OSSL_DISPATCH tables
 * registered in provider.c. This header exposes the small number of
 * symbols that callers outside the provider need to drive composite key
 * construction and message-representative computation directly:
 *
 *   - p11prov_composite_profile_by_oid     — registry lookup
 *   - p11prov_composite_obj_new_from_subkeys — build a composite key from
 *     two pre-loaded softhsm PKCS#11 objects (the application owns the
 *     subkey refs; this function takes its own references).
 *   - p11prov_composite_build_mprime       — M' per draft-19 §2.2, exposed
 *     so an out-of-process verifier can compute the same bytes without
 *     re-implementing the spec.
 *
 * The structs are intentionally opaque to callers — only pointers cross
 * this boundary. */

#ifndef P11PROV_COMPOSITE_H
#define P11PROV_COMPOSITE_H

#include "provider.h"
#include "objects.h"
#include <stddef.h>
#include <openssl/evp.h>

struct p11prov_composite_profile;
struct p11prov_composite_obj;
typedef struct p11prov_composite_obj P11PROV_COMPOSITE_OBJ;

/* Composite OID for the IMPORT param holding a pre-built composite obj
 * pointer (see composite.c — kept as a string to avoid macro leakage). */
#define P11PROV_COMPOSITE_PARAM_REFERENCE_STR "pqctoday-composite-ref"

/* Lookup a registered composite profile by OID string
 * (e.g. "1.3.6.1.5.5.7.6.45"). Returns NULL when no match. */
const struct p11prov_composite_profile *
p11prov_composite_profile_by_oid(const char *oid);

/* Build a composite key from two pre-loaded softhsm objects.
 * Caller retains references on inputs (this function refs them
 * internally). Returns NULL on alloc failure or bad arguments. */
P11PROV_COMPOSITE_OBJ *
p11prov_composite_obj_new_from_subkeys(
    P11PROV_CTX *provctx,
    const struct p11prov_composite_profile *profile,
    P11PROV_OBJ *pq_obj,
    P11PROV_OBJ *classical_obj);

/* Compute M' per draft-19 §2.2:
 *   M' = Prefix || Label || len(ctx) || ctx || PH(M)
 *
 * `out` must be caller-allocated with capacity >= 32 + strlen(label) + 1
 * + ctx_len + EVP_MD_size(profile->pre_hash). On success `*out_sz` is set
 * to the actual M' length. Returns 1 on success, 0 on failure. */
int p11prov_composite_build_mprime(
    const struct p11prov_composite_profile *profile,
    const unsigned char *msg, size_t msg_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char *out, size_t *out_sz);

/* Accessors for profile fields needed by external verify shims.
 * These return zero / NULL when `profile == NULL`. */
size_t p11prov_composite_profile_mldsa_pk_bytes(
    const struct p11prov_composite_profile *profile);
size_t p11prov_composite_profile_mldsa_sig_bytes(
    const struct p11prov_composite_profile *profile);
int p11prov_composite_profile_pre_hash_nid(
    const struct p11prov_composite_profile *profile);
const char *p11prov_composite_profile_label(
    const struct p11prov_composite_profile *profile);
const char *p11prov_composite_profile_signature_label(
    const struct p11prov_composite_profile *profile);
const char *p11prov_composite_profile_classical_alg_oid(
    const struct p11prov_composite_profile *profile);
/* Returns 44, 65, or 87 (the ML-DSA strength) — useful for selecting the
 * software-side EVP_PKEY type during external verify. */
int p11prov_composite_profile_mldsa_strength(
    const struct p11prov_composite_profile *profile);

/* One-shot bridge: load two softhsm-resident subkeys via their pkcs11: URIs
 * and return a composite EVP_PKEY whose signature dispatch routes through
 * composite.c (draft-19 §4 wire format).
 *
 * Caller owns the returned EVP_PKEY (free with EVP_PKEY_free). Returns
 * NULL on any failure; the OpenSSL error stack is populated. */
EVP_PKEY *p11prov_composite_evp_pkey_from_uris(
    P11PROV_CTX *provctx,
    const struct p11prov_composite_profile *profile,
    const char *pq_uri,
    const char *classical_uri);

#endif /* P11PROV_COMPOSITE_H */
