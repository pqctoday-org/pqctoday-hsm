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
    // Real PKCS#11 v3.3 working-draft codepoint (OASIS status "proposed",
    // not yet through final ballot — see src/lib/vendor_mechanisms.h in the
    // engine repo, NOT pkcs11t.h). Renamed 2026-08-30 from the prior
    // vendor-range stopgap CKM_PQCTODAY_ML_DSA_MU.
    static final long CKM_ML_DSA_EXTERNAL_MU   = 0x0000403cL;
    static final int  ML_DSA_EXTERNAL_MU_LEN   = 64; // FIPS 204 Eq.(2): SHAKE256 output, fixed
    static final long CKM_SLH_DSA_KEY_PAIR_GEN = 0x0000002dL;
    static final long CKM_SLH_DSA              = 0x0000002eL;
    static final long CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055L;
    static final long CKM_EDDSA                = 0x00001057L;
    // Vendor-range-flagged per PKCS#11 v3.2 (CKM_VENDOR_DEFINED | 0x1057) —
    // a real, distinct mechanism (grepped in pkcs11t.h), not an alias.
    static final long CKM_EDDSA_PH             = 0x80001057L;
    static final long CKM_EC_KEY_PAIR_GEN      = 0x00001040L;
    static final long CKM_ECDH1_DERIVE         = 0x00001050L;
    static final long CKM_ECDH1_COFACTOR_DERIVE = 0x00001051L;
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
    // WS-D: real, engine-dispatched (confirmed reading SoftHSM_slots.cpp's
    // prepareSupportedMechanisms AND SoftHSM_sign.cpp's C_SignInit/
    // C_VerifyInit dispatch before adding these — not assumed from the
    // SHA-2 PSS precedent, per this item's own plan text).
    static final long CKM_SHA3_224_RSA_PKCS_PSS = 0x00000067L;
    static final long CKM_SHA3_256_RSA_PKCS_PSS = 0x00000063L;
    static final long CKM_SHA3_384_RSA_PKCS_PSS = 0x00000064L;
    static final long CKM_SHA3_512_RSA_PKCS_PSS = 0x00000065L;
    static final long CKM_SHA224               = 0x00000255L;
    static final long CKM_SHA256               = 0x00000250L;
    static final long CKM_SHA384               = 0x00000260L;
    static final long CKM_SHA512               = 0x00000270L;
    static final long CKM_ML_KEM_KEY_PAIR_GEN  = 0x0000000fL;
    static final long CKM_ML_KEM                = 0x00000017L;

    // ── Items 3/4 (2026-08-30 follow-on) — scattered digest/signature gaps
    // vs the merged PKCS#11 surface, grepped from pkcs11t.h. ──────────────
    static final long CKM_SHA512_224            = 0x00000048L;
    static final long CKM_SHA512_256            = 0x0000004cL;
    // *_KEY_DERIVATION variants of these two (0x4b/0x4f) are deliberately
    // NOT declared here — engine-dispatched (SoftHSM_slots.cpp) but out of
    // scope this pass, matching the prior "digest-based KEY_DERIVATION
    // family deferred" decision.
    static final long CKM_ECDSA_SHA224          = 0x00001043L;
    static final long CKM_ECDSA_SHA3_224        = 0x00001047L;
    static final long CKM_SHA224_RSA_PKCS       = 0x00000046L;
    static final long CKM_SHA224_RSA_PKCS_PSS   = 0x00000047L;
    static final long CKM_SHA3_224_RSA_PKCS     = 0x00000066L;
    static final long CKM_SHA3_256_RSA_PKCS     = 0x00000060L;
    static final long CKM_SHA3_384_RSA_PKCS     = 0x00000061L;
    static final long CKM_SHA3_512_RSA_PKCS     = 0x00000062L;

    // ── AES (W4) ─────────────────────────────────────────────────────────
    static final long CKM_AES_KEY_GEN      = 0x00001080L;
    static final long CKM_AES_CBC          = 0x00001082L;
    static final long CKM_AES_CBC_PAD      = 0x00001085L;
    static final long CKM_AES_CTR          = 0x00001086L;
    static final long CKM_AES_GCM          = 0x00001087L;
    static final long CKM_AES_KEY_WRAP     = 0x00002109L;
    static final long CKM_AES_KEY_WRAP_PAD = 0x0000210aL;
    static final long CKM_AES_KEY_WRAP_KWP = 0x0000210bL;
    static final long CKM_AES_CCM          = 0x00001088L;
    static final long CKM_AES_GMAC         = 0x0000108eL;
    // Item 1 (2026-08-30 follow-on): CKM_AES_XTS (IEEE 1619-2007 / PKCS#11
    // v3.2 §6.15.4) — double-length key, CKK_AES_XTS-typed only (never
    // plain CKK_AES). CKM_AES_XTS_KEY_GEN is its own dedicated keygen
    // mechanism (§6.15.3), not CKM_AES_KEY_GEN.
    static final long CKM_AES_XTS          = 0x00001071L;
    static final long CKM_AES_XTS_KEY_GEN  = 0x00001072L;
    // Item 2 (2026-08-30 follow-on): real standard JCA cipher modes
    // ("OFB"/"CFBx" per the Java Security Standard Algorithm Names spec).
    // CKM_AES_CFB64 (0x2105) exists in pkcs11t.h but is NOT declared here —
    // the engine's own SymmetricAlgorithm.h marks the width-less legacy
    // CFB constant "kept as an alias, unused" and SoftHSM_cipher.cpp only
    // ever dispatches CFB1/CFB8/CFB128, never a bare/64-bit variant.
    static final long CKM_AES_OFB          = 0x00002104L;
    static final long CKM_AES_CFB8         = 0x00002106L;
    static final long CKM_AES_CFB128       = 0x00002107L;
    static final long CKM_AES_CFB1         = 0x00002108L;

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
    // Plain (non-truncated) SHA-512/224 and SHA-512/256 HMAC — not
    // registered as their own Mac services here (out of this item's
    // scope), only needed as PRF entries in
    // P11SP800108SecretKeyFactorySpi's PRF_NAMES table.
    static final long CKM_SHA512_224_HMAC = 0x00000049L;
    static final long CKM_SHA512_256_HMAC = 0x0000004dL;
    static final long CKM_AES_CMAC      = 0x0000108aL;
    static final long CKM_KMAC_128      = 0x80000100L; // CKM_VENDOR_DEFINED | 0x100
    static final long CKM_KMAC_256      = 0x80000101L; // CKM_VENDOR_DEFINED | 0x101

    // ── HMAC general-length ("_HMAC_GENERAL") variants (item 1) ──────────
    // CKM_SHA_1_HMAC_GENERAL is deliberately NOT declared: SHA-1-based HMAC
    // is excluded everywhere else in this provider under the FIPS 140-3 L3
    // policy (see SoftHSMv3Provider's class javadoc and
    // ExcludedMechanismsTest) — a truncated-output variant of the same
    // excluded primitive would undermine that policy, not extend it.
    static final long CKM_SHA224_HMAC_GENERAL   = 0x00000257L;
    static final long CKM_SHA256_HMAC_GENERAL   = 0x00000252L;
    static final long CKM_SHA384_HMAC_GENERAL   = 0x00000262L;
    static final long CKM_SHA512_HMAC_GENERAL   = 0x00000272L;
    static final long CKM_SHA3_224_HMAC_GENERAL = 0x000002b7L;
    static final long CKM_SHA3_256_HMAC_GENERAL = 0x000002b2L;
    static final long CKM_SHA3_384_HMAC_GENERAL = 0x000002c2L;
    static final long CKM_SHA3_512_HMAC_GENERAL = 0x000002d2L;

    // ── KDF (W4) ─────────────────────────────────────────────────────────
    static final long CKM_HKDF_DERIVE = 0x0000402aL;
    static final long CKM_PKCS5_PBKD2 = 0x000003b0L;
    static final long CKZ_SALT_SPECIFIED = 0x00000001L;
    static final long CKP_PKCS5_PBKD2_HMAC_SHA256 = 0x00000004L;
    static final long CKP_PKCS5_PBKD2_HMAC_SHA384 = 0x00000005L;
    static final long CKP_PKCS5_PBKD2_HMAC_SHA512 = 0x00000006L;
    static final long CKM_SP800_108_COUNTER_KDF  = 0x000003acL;
    static final long CKM_SP800_108_FEEDBACK_KDF = 0x000003adL;
    static final long CKM_SP800_108_DOUBLE_PIPELINE_KDF = 0x000003aeL;
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
    // Item 1 (2026-08-30 follow-on): CKK_AES_XTS — a genuinely distinct
    // key type from CKK_AES (double-length raw value, 32 or 64 bytes;
    // PKCS#11 v3.2 §6.15.2 Table 124), not an AES-family alias.
    static final long CKK_AES_XTS        = 0x00000035L;

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
    // Item 4 (2026-08-30 follow-on): needed for P11RSAPSSSignatureSpi's
    // missing "SHA-224" DIGEST_TO_MECH_AND_MGF entry.
    static final long CKG_MGF1_SHA224   = 0x00000005L;
    static final long CKG_MGF1_SHA256   = 0x00000002L;
    static final long CKG_MGF1_SHA384   = 0x00000003L;
    static final long CKG_MGF1_SHA512   = 0x00000004L;
    static final long CKG_MGF1_SHA3_224 = 0x00000006L;
    static final long CKG_MGF1_SHA3_256 = 0x00000007L;
    static final long CKG_MGF1_SHA3_384 = 0x00000008L;
    static final long CKG_MGF1_SHA3_512 = 0x00000009L;
    static final long CKM_RSA_PKCS_OAEP = 0x00000009L;
    static final long CKM_SHA3_224      = 0x000002b5L;
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
