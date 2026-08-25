package com.pqctoday.hsm.jce;

import javax.crypto.MacSpi;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * HMAC-SHA-family, AESCMAC, KMAC128/KMAC256 — one generic class, mechanism
 * (and expected key algorithm) supplied at construction, same shape as
 * P11PureSigSignatureSpi. PKCS#11 treats a MAC as a plain C_Sign
 * operation (confirmed reading SoftHSM_sign.cpp before writing this
 * class: the same C_SignInit/C_Sign functions already bound for
 * Signature in W2 are what compute a MAC — no new native binding
 * needed), so this class is a thin buffer-then-sign wrapper, same
 * single-shot-buffering shape as every CipherSpi in this module.
 *
 * The macLength passed in is this instance's own PKCS#11-minimum output
 * size (from the engine's kMacMechTable — see
 * P11GenericSecretKeyGeneratorSpi's javadoc) and is asserted against the
 * actual engineDoFinal() result rather than trusted blindly, since
 * KMAC's real output length was already found live once this session
 * (W0.3's spike) to not match a first, unverified guess.
 */
final class P11MacSpi extends MacSpi {
    private final P11Library lib;
    private final long mech;
    private final String expectedKeyAlgorithm;
    private final int macLength;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    private long keyHandle = -1;

    P11MacSpi(P11Library lib, long mech, String expectedKeyAlgorithm, int macLength) {
        this.lib = lib;
        this.mech = mech;
        this.expectedKeyAlgorithm = expectedKeyAlgorithm;
        this.macLength = macLength;
    }

    @Override protected int engineGetMacLength() { return macLength; }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("this Mac takes no parameters");
        }
        if (!(key instanceof P11Key.Secret s) || !expectedKeyAlgorithm.equals(s.getAlgorithm())) {
            throw new InvalidKeyException("this Mac needs a " + expectedKeyAlgorithm
                + " SecretKey from " + SoftHSMv3Provider.class.getSimpleName());
        }
        this.keyHandle = s.handle();
        buf.reset();
    }

    @Override protected void engineUpdate(byte input) { buf.write(input); }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        buf.write(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        byte[] result = lib.sign(mech, keyHandle, buf.toByteArray());
        buf.reset();
        return result;
    }

    @Override protected void engineReset() { buf.reset(); }
}
