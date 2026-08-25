package com.pqctoday.hsm.jce;

/**
 * PKCS#11 v3.2 constants used by W2+ SPIs. Values taken directly from
 * src/lib/pkcs11/pkcs11t.h — this repo's CLAUDE.md designates that header
 * (and the OASIS v3.2 spec) as the ONLY source of truth for CK_* values;
 * do not add or edit an entry here without checking it against that file.
 */
final class P11Constants {
    private P11Constants() {}

    // ── Mechanisms ───────────────────────────────────────────────────────
    static final long CKM_ML_DSA_KEY_PAIR_GEN  = 0x0000001cL;
    static final long CKM_ML_DSA               = 0x0000001dL;
    static final long CKM_SLH_DSA_KEY_PAIR_GEN = 0x0000002dL;
    static final long CKM_SLH_DSA              = 0x0000002eL;

    // ── Object classes ──────────────────────────────────────────────────
    static final long CKO_PUBLIC_KEY  = 0x00000002L;
    static final long CKO_PRIVATE_KEY = 0x00000003L;

    // ── Key types ────────────────────────────────────────────────────────
    static final long CKK_ML_DSA  = 0x0000004aL;
    static final long CKK_SLH_DSA = 0x0000004bL;

    // ── Attributes ───────────────────────────────────────────────────────
    static final long CKA_CLASS            = 0x00000000L;
    static final long CKA_TOKEN            = 0x00000001L;
    static final long CKA_PRIVATE          = 0x00000002L;
    static final long CKA_VALUE            = 0x00000011L;
    static final long CKA_KEY_TYPE         = 0x00000100L;
    static final long CKA_SENSITIVE        = 0x00000103L;
    static final long CKA_SIGN             = 0x00000108L;
    static final long CKA_VERIFY           = 0x0000010aL;
    static final long CKA_EXTRACTABLE      = 0x00000162L;
    static final long CKA_PUBLIC_KEY_INFO  = 0x00000129L; // v3.2 §4.14: SubjectPublicKeyInfo DER
    static final long CKA_PARAMETER_SET    = 0x0000061dL;

    // ── ML-DSA parameter sets (CKA_PARAMETER_SET values) ────────────────
    static final long CKP_ML_DSA_44 = 0x00000001L;
    static final long CKP_ML_DSA_65 = 0x00000002L;
    static final long CKP_ML_DSA_87 = 0x00000003L;

    // ── SLH-DSA parameter sets (CKA_PARAMETER_SET values, all 12) ───────
    static final long CKP_SLH_DSA_SHA2_128S  = 0x00000001L;
    static final long CKP_SLH_DSA_SHAKE_128S = 0x00000002L;
    static final long CKP_SLH_DSA_SHA2_128F  = 0x00000003L;
    static final long CKP_SLH_DSA_SHAKE_128F = 0x00000004L;
    static final long CKP_SLH_DSA_SHA2_192S  = 0x00000005L;
    static final long CKP_SLH_DSA_SHAKE_192S = 0x00000006L;
    static final long CKP_SLH_DSA_SHA2_192F  = 0x00000007L;
    static final long CKP_SLH_DSA_SHAKE_192F = 0x00000008L;
    static final long CKP_SLH_DSA_SHA2_256S  = 0x00000009L;
    static final long CKP_SLH_DSA_SHAKE_256S = 0x0000000aL;
    static final long CKP_SLH_DSA_SHA2_256F  = 0x0000000bL;
    static final long CKP_SLH_DSA_SHAKE_256F = 0x0000000cL;
}
