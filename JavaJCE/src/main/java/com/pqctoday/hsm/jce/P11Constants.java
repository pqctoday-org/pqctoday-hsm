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
    static final long CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055L;
    static final long CKM_EDDSA                = 0x00001057L;
    static final long CKM_EC_KEY_PAIR_GEN      = 0x00001040L;
    static final long CKM_ECDH1_DERIVE         = 0x00001050L;
    static final long CKM_ECDSA_SHA256         = 0x00001044L;
    static final long CKM_ECDSA_SHA384         = 0x00001045L;
    static final long CKM_ECDSA_SHA512         = 0x00001046L;
    static final long CKM_ECDSA_SHA3_256       = 0x00001048L;
    static final long CKM_ECDSA_SHA3_384       = 0x00001049L;
    static final long CKM_ECDSA_SHA3_512       = 0x0000104aL;
    static final long CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000L;
    static final long CKM_SHA256_RSA_PKCS      = 0x00000040L;
    static final long CKM_SHA384_RSA_PKCS      = 0x00000041L;
    static final long CKM_SHA512_RSA_PKCS      = 0x00000042L;
    static final long CKM_SHA256_RSA_PKCS_PSS  = 0x00000043L;
    static final long CKM_SHA384_RSA_PKCS_PSS  = 0x00000044L;
    static final long CKM_SHA512_RSA_PKCS_PSS  = 0x00000045L;
    static final long CKM_SHA256               = 0x00000250L;
    static final long CKM_SHA384               = 0x00000260L;
    static final long CKM_SHA512               = 0x00000270L;
    static final long CKM_ML_KEM_KEY_PAIR_GEN  = 0x0000000fL;
    static final long CKM_ML_KEM                = 0x00000017L;

    // ── AES (W4) ─────────────────────────────────────────────────────────
    static final long CKM_AES_KEY_GEN      = 0x00001080L;
    static final long CKM_AES_CBC          = 0x00001082L;
    static final long CKM_AES_CBC_PAD      = 0x00001085L;
    static final long CKM_AES_CTR          = 0x00001086L;
    static final long CKM_AES_GCM          = 0x00001087L;
    static final long CKM_AES_KEY_WRAP     = 0x00002109L;
    static final long CKM_AES_KEY_WRAP_PAD = 0x0000210aL;

    // ── MAC (W4) ─────────────────────────────────────────────────────────
    static final long CKM_GENERIC_SECRET_KEY_GEN = 0x00000350L;
    static final long CKM_SHA224_HMAC   = 0x00000256L;
    static final long CKM_SHA256_HMAC   = 0x00000251L;
    static final long CKM_SHA384_HMAC   = 0x00000261L;
    static final long CKM_SHA512_HMAC   = 0x00000271L;
    static final long CKM_SHA3_224_HMAC = 0x000002b6L;
    static final long CKM_SHA3_256_HMAC = 0x000002b1L;
    static final long CKM_SHA3_384_HMAC = 0x000002c1L;
    static final long CKM_SHA3_512_HMAC = 0x000002d1L;
    static final long CKM_AES_CMAC      = 0x0000108aL;
    static final long CKM_KMAC_128      = 0x80000100L; // CKM_VENDOR_DEFINED | 0x100
    static final long CKM_KMAC_256      = 0x80000101L; // CKM_VENDOR_DEFINED | 0x101

    // ── KDF (W4) ─────────────────────────────────────────────────────────
    static final long CKM_HKDF_DERIVE = 0x0000402aL;
    static final long CKM_PKCS5_PBKD2 = 0x000003b0L;
    static final long CKZ_SALT_SPECIFIED = 0x00000001L;
    static final long CKP_PKCS5_PBKD2_HMAC_SHA256 = 0x00000004L;
    static final long CKP_PKCS5_PBKD2_HMAC_SHA384 = 0x00000005L;
    static final long CKP_PKCS5_PBKD2_HMAC_SHA512 = 0x00000006L;
    static final long CKM_SP800_108_COUNTER_KDF  = 0x000003acL;
    static final long CKM_SP800_108_FEEDBACK_KDF = 0x000003adL;
    static final long CK_SP800_108_BYTE_ARRAY    = 0x00000004L;

    // ── Object classes ──────────────────────────────────────────────────
    static final long CKO_CERTIFICATE = 0x00000001L;
    static final long CKO_PUBLIC_KEY  = 0x00000002L;
    static final long CKO_PRIVATE_KEY = 0x00000003L;
    static final long CKO_SECRET_KEY  = 0x00000004L;

    // ── Certificate types ────────────────────────────────────────────────
    static final long CKC_X_509 = 0x00000000L;

    // ── Key types ────────────────────────────────────────────────────────
    static final long CKK_ML_DSA         = 0x0000004aL;
    static final long CKK_SLH_DSA        = 0x0000004bL;
    static final long CKK_EC_EDWARDS     = 0x00000040L;
    static final long CKK_EC             = 0x00000003L;
    static final long CKK_RSA            = 0x00000000L;
    static final long CKK_ML_KEM         = 0x00000049L;
    static final long CKK_GENERIC_SECRET = 0x00000010L;
    static final long CKK_AES            = 0x0000001fL;

    // ── Attributes ───────────────────────────────────────────────────────
    static final long CKA_CLASS            = 0x00000000L;
    static final long CKA_TOKEN            = 0x00000001L;
    static final long CKA_PRIVATE          = 0x00000002L;
    static final long CKA_LABEL            = 0x00000003L;
    static final long CKA_ID               = 0x00000102L;
    static final long CKA_VALUE            = 0x00000011L;
    static final long CKA_KEY_TYPE         = 0x00000100L;
    static final long CKA_SENSITIVE        = 0x00000103L;
    static final long CKA_ENCRYPT          = 0x00000104L;
    static final long CKA_DECRYPT          = 0x00000105L;
    static final long CKA_WRAP             = 0x00000106L;
    static final long CKA_UNWRAP           = 0x00000107L;
    static final long CKA_SIGN             = 0x00000108L;
    static final long CKA_VERIFY           = 0x0000010aL;
    static final long CKA_DERIVE           = 0x0000010cL;
    static final long CKA_MODULUS          = 0x00000120L;
    static final long CKA_MODULUS_BITS     = 0x00000121L;
    static final long CKA_PUBLIC_EXPONENT  = 0x00000122L;
    static final long CKA_EXTRACTABLE      = 0x00000162L;
    static final long CKA_PUBLIC_KEY_INFO  = 0x00000129L; // v3.2 §4.14: SubjectPublicKeyInfo DER
    static final long CKA_PARAMETER_SET    = 0x0000061dL;
    static final long CKA_EC_PARAMS        = 0x00000180L;
    static final long CKA_EC_POINT         = 0x00000181L;
    static final long CKA_VALUE_LEN        = 0x00000161L;
    static final long CKA_ENCAPSULATE      = 0x00000633L;
    static final long CKA_DECAPSULATE      = 0x00000634L;

    // ── Certificate attributes (v3.2 §4.9) ────────────────────────────────
    static final long CKA_CERTIFICATE_TYPE = 0x00000080L;
    static final long CKA_ISSUER           = 0x00000081L;
    static final long CKA_SERIAL_NUMBER    = 0x00000082L;
    static final long CKA_SUBJECT          = 0x00000101L;

    // ── RSA-PSS/OAEP mechanism parameters ────────────────────────────────
    static final long CKG_MGF1_SHA256   = 0x00000002L;
    static final long CKG_MGF1_SHA384   = 0x00000003L;
    static final long CKG_MGF1_SHA512   = 0x00000004L;
    static final long CKG_MGF1_SHA3_256 = 0x00000007L;
    static final long CKG_MGF1_SHA3_384 = 0x00000008L;
    static final long CKG_MGF1_SHA3_512 = 0x00000009L;
    static final long CKM_RSA_PKCS_OAEP = 0x00000009L;
    static final long CKM_SHA3_256      = 0x000002b0L;
    static final long CKM_SHA3_384      = 0x000002c0L;
    static final long CKM_SHA3_512      = 0x000002d0L;

    // ── EdDSA curve OIDs (DER-encoded, RFC 8410) — the exact byte arrays
    // already proven live in pqctoday-sandbox's C/Rust Ed25519 samples
    // (samples/c/12_ed25519.c, samples/rust/src/12_ed25519.rs); Ed448's
    // OID (1.3.101.113) differs from Ed25519's (1.3.101.112) only in the
    // final arc byte, same DER TLV shape. ────────────────────────────────
    static final byte[] ED25519_OID = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
    static final byte[] ED448_OID   = { 0x06, 0x03, 0x2B, 0x65, 0x71 };

    // ── ML-DSA parameter sets (CKA_PARAMETER_SET values) ────────────────
    static final long CKP_ML_DSA_44 = 0x00000001L;
    static final long CKP_ML_DSA_65 = 0x00000002L;
    static final long CKP_ML_DSA_87 = 0x00000003L;

    // ── ML-KEM parameter sets (CKA_PARAMETER_SET values) ─────────────────
    static final long CKP_ML_KEM_512  = 0x00000001L;
    static final long CKP_ML_KEM_768  = 0x00000002L;
    static final long CKP_ML_KEM_1024 = 0x00000003L;

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
