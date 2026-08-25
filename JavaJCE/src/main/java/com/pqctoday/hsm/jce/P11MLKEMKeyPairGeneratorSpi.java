package com.pqctoday.hsm.jce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * ML-KEM-512/768/1024 KeyPairGenerator — same single-mechanism,
 * parameter-set-on-the-key shape as P11PureSigKeyPairGeneratorSpi
 * (CKM_ML_KEM_KEY_PAIR_GEN is parameter-set-agnostic; CKA_PARAMETER_SET
 * on the key selects 512/768/1024), but NOT built on that class: ML-KEM
 * keys carry CKA_ENCAPSULATE/CKA_DECAPSULATE, not CKA_SIGN/CKA_VERIFY —
 * confirmed against pkcs11t.h (0x633/0x634) before writing the template,
 * same as the earlier CKA_MODULUS_BITS/CKA_PUBLIC_EXPONENT check for RSA.
 */
final class P11MLKEMKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final P11Library lib;
    private final String algorithm;
    private final long parameterSet;

    P11MLKEMKeyPairGeneratorSpi(P11Library lib, String algorithm, long parameterSet) {
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
        // Same reasoning as every other KeyPairGeneratorSpi in this
        // module — W0.1's live JSSE probe (this exact provider,
        // real handshake against pqc-rest) showed this overload gets
        // called for the ML-KEM family too, and that a missing override
        // fails open (silent fallback to a different provider) rather
        // than surfacing an error.
        if (params instanceof NamedParameterSpec nps && !nps.getName().equals(algorithm)) {
            throw new InvalidAlgorithmParameterException(
                "this KeyPairGenerator is bound to " + algorithm + ", got " + nps.getName());
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_PARAMETER_SET, parameterSet),
            P11Library.attrBool(CKA_ENCAPSULATE, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        P11Library.Attr[] prvTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PRIVATE_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_PRIVATE, true),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_DECAPSULATE, true),
        };
        long[] handles = lib.generateKeyPair(CKM_ML_KEM_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        byte[] spki = lib.getAttributeBytes(handles[0], CKA_PUBLIC_KEY_INFO);
        P11Key.Pub pub = new P11Key.Pub(handles[0], algorithm, spki);
        P11Key.Priv priv = new P11Key.Priv(handles[1], algorithm);
        return new KeyPair(pub, priv);
    }
}
