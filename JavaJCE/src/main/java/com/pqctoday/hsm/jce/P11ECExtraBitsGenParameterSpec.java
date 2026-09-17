package com.pqctoday.hsm.jce;

import java.security.spec.ECGenParameterSpec;

/**
 * Requests FIPS 186-5 A.2.2 ("Key Pair Generation Using Extra Random Bits")
 * from the "EC" {@code KeyPairGenerator} — PKCS#11 v3.2's
 * {@code CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS} rather than the default
 * {@code CKM_EC_KEY_PAIR_GEN}. Plan item X1; closes Q-6 of
 * {@code docs/remediation-plan-provider-layer-gaps-2026-08-30.md}.
 *
 * <p>JCA has no standard way to ask for an EC key-generation <em>method</em>
 * — {@link ECGenParameterSpec} names a curve and nothing else — so this is a
 * provider-specific spec, and the only public API this module adds for it.
 * It deliberately <strong>extends</strong> {@code ECGenParameterSpec} rather
 * than sitting beside it: the generator's existing
 * {@code instanceof ECGenParameterSpec} guard and curve lookup then continue
 * to work unchanged, and any code that already accepts an
 * {@code ECGenParameterSpec} keeps accepting this. The subclass carries the
 * generation method and nothing else.
 *
 * <pre>{@code
 * KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SoftHSMv3");
 * g.initialize(new P11ECExtraBitsGenParameterSpec("secp384r1"));
 * KeyPair kp = g.generateKeyPair();
 * }</pre>
 *
 * <p>Both generation methods produce an ordinary EC key: only the way the
 * private scalar is drawn differs. The resulting key's
 * {@code CKA_KEY_GEN_MECHANISM} records which method was used.
 *
 * <p>The token must support the mechanism. Both engines in this repository
 * do — the Rust engine since 2026-08-30, the C++ engine as of plan item X1 —
 * but a third-party token that does not will fail generation with
 * {@code CKR_MECHANISM_INVALID}, surfaced the same way as any other
 * unsupported mechanism.
 */
public final class P11ECExtraBitsGenParameterSpec extends ECGenParameterSpec {

    /**
     * @param stdName the standard curve name, exactly as
     *                {@link ECGenParameterSpec} takes it — {@code "secp256r1"},
     *                {@code "secp384r1"} or {@code "secp521r1"}.
     */
    public P11ECExtraBitsGenParameterSpec(String stdName) {
        super(stdName);
    }
}
