package com.pqctoday.hsm.jce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * Generic KeyPairGeneratorSpi for "pure" PKCS#11 signature algorithms whose
 * keygen mechanism derives the key type internally (confirmed for both
 * ML-DSA and SLH-DSA by reading SoftHSM_keygen.cpp's dispatch — e.g.
 * `case CKM_ML_DSA_KEY_PAIR_GEN: keyType = CKK_ML_DSA;` — so this class
 * does not set CKA_KEY_TYPE itself) and whose parameter set lives on the
 * key (CKA_PARAMETER_SET), not the mechanism. One instance per registered
 * parameter-set service name (e.g. "ML-DSA-65", "SLH-DSA-SHA2-128S").
 *
 * Extracted from what was P11MLDSAKeyPairGeneratorSpi after confirming
 * SLH-DSA needs an identically-shaped class — see the W2 SLH-DSA commit
 * for the regression check that ran before/after this extraction.
 */
final class P11PureSigKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final P11Library lib;
    private final String algorithm;
    private final long keygenMechanism;
    private final long parameterSet;

    P11PureSigKeyPairGeneratorSpi(P11Library lib, String algorithm, long keygenMechanism, long parameterSet) {
        this.lib = lib;
        this.algorithm = algorithm;
        this.keygenMechanism = keygenMechanism;
        this.parameterSet = parameterSet;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        throw new UnsupportedOperationException(
            algorithm + " has no keysize-int initializer; use the no-arg or spec-based initialize");
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        // See P11MLDSAKeyPairGeneratorSpi's original javadoc (now here):
        // W0.1's live JSSE probe showed this overload can be called
        // redundantly even when the algorithm identity is already fixed by
        // the service name, and that the JDK's default (unoverridden)
        // implementation throwing can be silently absorbed by a caller.
        // Overriding it here, tolerantly, avoids reproducing that footgun.
        if (params instanceof NamedParameterSpec nps && !nps.getName().equals(algorithm)) {
            throw new InvalidAlgorithmParameterException(
                "this KeyPairGenerator is bound to " + algorithm + ", got " + nps.getName());
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        // Randomness comes from the token's own DRBG — see
        // P11MLDSAKeyPairGeneratorSpi's original note (same reasoning).
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_PARAMETER_SET, parameterSet),
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        P11Library.Attr[] prvTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PRIVATE_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_PRIVATE, true),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_SIGN, true),
        };
        long[] handles = lib.generateKeyPair(keygenMechanism, pubTmpl, prvTmpl);
        byte[] spki = lib.getAttributeBytes(handles[0], CKA_PUBLIC_KEY_INFO);
        P11Key.Pub pub = new P11Key.Pub(handles[0], algorithm, spki);
        P11Key.Priv priv = new P11Key.Priv(handles[1], algorithm);
        return new KeyPair(pub, priv);
    }
}
