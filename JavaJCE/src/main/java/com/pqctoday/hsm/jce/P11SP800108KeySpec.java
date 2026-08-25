package com.pqctoday.hsm.jce;

import javax.crypto.SecretKey;
import java.security.spec.KeySpec;

/**
 * Provider-specific KeySpec for SP 800-108 counter/feedback KDF
 * (CKM_SP800_108_COUNTER_KDF / CKM_SP800_108_FEEDBACK_KDF) — no standard
 * JCA KeySpec exists for this family (unlike PBKDF2's PBEKeySpec), so
 * this carries everything C_DeriveKey needs: the base key Ki (must be a
 * SecretKey from this provider, or a foreign key with real encoded
 * bytes — same on-the-fly-import pattern as everywhere else in this
 * module), the PRF ("HmacSHA256"/.../"HmacSHA3-512" or "AESCMAC" —
 * translated internally, matching the exact set ckmHmacPrfToDigestName
 * accepts in SoftHSM_keygen.cpp), the fixed input (label/context,
 * concatenated — the caller is responsible for SP 800-108's own
 * Label‖0x00‖Context‖[L] framing per §4.1, this class does not impose
 * one), an optional feedback IV (ignored by the counter-mode factory
 * instance), and the output length in bits.
 *
 * Deliberately does not expose counter-width customization or
 * additional-derived-keys — the engine itself only implements
 * CK_SP800_108_BYTE_ARRAY and (for counter mode) a default 32-bit
 * counter among the several CK_PRF_DATA_TYPE values the spec defines
 * (CK_SP800_108_DKM_LENGTH and key-handle data params are parsed but
 * silently skipped by the engine — "not supported"), so exposing those
 * here would promise behavior the native layer doesn't actually have.
 */
record P11SP800108KeySpec(SecretKey baseKey, String prf, byte[] fixedInput, byte[] iv, int outputLengthBits)
        implements KeySpec {

    P11SP800108KeySpec(SecretKey baseKey, String prf, byte[] fixedInput, int outputLengthBits) {
        this(baseKey, prf, fixedInput, new byte[0], outputLengthBits);
    }
}
