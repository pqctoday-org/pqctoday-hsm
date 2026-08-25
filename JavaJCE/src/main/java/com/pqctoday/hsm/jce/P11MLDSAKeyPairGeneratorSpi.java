package com.pqctoday.hsm.jce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * One instance per registered parameter set (ML-DSA-44/65/87 are separate
 * JCA service names, each bound to a fixed CKA_PARAMETER_SET at
 * construction — see SoftHSMv3Provider's registration).
 *
 * Overrides initialize(AlgorithmParameterSpec, SecureRandom) even though
 * this SPI's algorithm identity is already fixed at construction — W0.1's
 * live JSSE probe found that a caller MAY call this overload redundantly
 * (passing a NamedParameterSpec that just repeats the algorithm name it
 * already asked for by name), and that the JDK's default implementation
 * of this overload THROWS if not overridden, with no exception surfaced
 * to the caller in at least one real code path (JSSE silently moved on to
 * a different provider). Silently degrading here would be the exact same
 * footgun for any caller that does this — so this is a real fix informed
 * by that finding, not a defensive guess.
 */
final class P11MLDSAKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final P11Library lib;
    private final String algorithm;
    private final long parameterSet;
    private SecureRandom random;

    P11MLDSAKeyPairGeneratorSpi(P11Library lib, String algorithm, long parameterSet) {
        this.lib = lib;
        this.algorithm = algorithm;
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
        if (params instanceof NamedParameterSpec nps && !nps.getName().equals(algorithm)) {
            throw new InvalidAlgorithmParameterException(
                "this KeyPairGenerator is bound to " + algorithm + ", got " + nps.getName());
        }
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        // random is intentionally unused: randomness for key generation
        // comes from the token's own DRBG (C_GenerateRandom path inside
        // the engine), same posture as SecureRandom in this provider —
        // never mix JVM-side randomness into token-side key material.
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
        long[] handles = lib.generateKeyPair(CKM_ML_DSA_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        byte[] spki = lib.getAttributeBytes(handles[0], CKA_PUBLIC_KEY_INFO);
        P11Key.Pub pub = new P11Key.Pub(handles[0], algorithm, spki);
        P11Key.Priv priv = new P11Key.Priv(handles[1], algorithm);
        return new KeyPair(pub, priv);
    }
}
