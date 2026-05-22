/*
 * Copyright (c) 2026 SoftHSMv3 Contributors
 * 
 * This file is an extension of the original openssl-projects/pkcs11-provider.
 * Modified to implement XMSS/LMS PQC extensions connecting to SoftHSMv3.
 * NOTE: As per design constraints, XMSS and LMS are restricted to VALIDATION 
 * (Signature Verification) operations only. Key generation and signing are not exposed.
 */

#include "provider.h"
#include "keymgmt.h"

// TODO: Implement parsing for CKK_XMSS parameter sets and wrap PKCS#11 verify primitives
const OSSL_DISPATCH p11prov_xmss_signature_functions[] = {
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_xmss_keymgmt_functions[] = {
    { 0, NULL },
};
