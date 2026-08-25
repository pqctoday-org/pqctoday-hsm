package com.pqctoday.hsm.jce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * Ed25519/Ed448 KeyPairGenerator. Not built on the generic
 * P11PureSigKeyPairGeneratorSpi: EdDSA keygen identifies its curve via
 * CKA_EC_PARAMS (a DER-encoded curve OID), not CKA_PARAMETER_SET — traced
 * directly in SoftHSM_keygen.cpp's generateED (reads CKA_EC_PARAMS out of
 * the public key template, CKR_TEMPLATE_INCOMPLETE if absent) before
 * assuming this class needed a different shape than ML-DSA/SLH-DSA's.
 * The OID bytes themselves are the exact values already proven live in
 * the sandbox's C/Rust Ed25519 samples (see P11Constants).
 *
 * The Signature side, in contrast, DOES reuse the generic
 * P11PureSigSignatureSpi unchanged: CKM_EDDSA is curve-agnostic (the
 * curve lives on the key), the exact same shape ML-DSA/SLH-DSA already
 * proved — see SoftHSMv3Provider's registration.
 */
final class P11EdDSAKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final P11Library lib;
    private final String algorithm;
    private final byte[] curveOid;

    P11EdDSAKeyPairGeneratorSpi(P11Library lib, String algorithm, byte[] curveOid) {
        this.lib = lib;
        this.algorithm = algorithm;
        this.curveOid = curveOid;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        throw new UnsupportedOperationException(
            algorithm + " has no keysize-int initializer; use the no-arg or spec-based initialize");
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        // Same reasoning as P11PureSigKeyPairGeneratorSpi — see its javadoc
        // (W0.1's JSSE finding: this overload can be called redundantly and
        // must not silently no-op/throw unhandled).
        if (params instanceof NamedParameterSpec nps && !nps.getName().equals(algorithm)) {
            throw new InvalidAlgorithmParameterException(
                "this KeyPairGenerator is bound to " + algorithm + ", got " + nps.getName());
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_EC_EDWARDS),
            P11Library.attr(CKA_EC_PARAMS, curveOid),
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
        long[] handles = lib.generateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        byte[] spki = lib.getAttributeBytes(handles[0], CKA_PUBLIC_KEY_INFO);
        P11Key.Pub pub = new P11Key.Pub(lib, handles[0], algorithm, spki);
        P11Key.Priv priv = new P11Key.Priv(lib, handles[1], algorithm);
        return new KeyPair(pub, priv);
    }
}
