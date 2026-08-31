package com.pqctoday.hsm.jce;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Requests a truncated/general-length MAC output — the JCA-side carrier for
 * PKCS#11's {@code CK_MAC_GENERAL_PARAMS} (a bare {@code CK_ULONG} output
 * length in bytes; PKCS#11 v3.2 §6.20.3 and its per-hash
 * {@code *_HMAC_GENERAL} siblings, item 1 of the JCE-provider gap
 * remediation).
 *
 * Verified against the real {@code javax.crypto.spec} javadoc (JDK 21+)
 * before writing this: that package has {@code GCMParameterSpec} (AEAD tag
 * length, a completely different mechanism shape) and nothing else
 * resembling a truncated-MAC-length spec — no standard class exists for
 * this shape of parameter. Same reasoning {@link P11SP800108KeySpec}
 * already used for its own "no standard shape exists" gap: a small,
 * minimal, one-field custom spec rather than inventing something larger.
 */
record P11MacOutputLengthParameterSpec(int outputLengthBytes) implements AlgorithmParameterSpec {
    P11MacOutputLengthParameterSpec {
        if (outputLengthBytes <= 0) {
            throw new IllegalArgumentException("outputLengthBytes must be positive, got " + outputLengthBytes);
        }
    }
}
