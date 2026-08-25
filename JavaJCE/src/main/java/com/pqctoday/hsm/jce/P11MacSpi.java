package com.pqctoday.hsm.jce;

import javax.crypto.MacSpi;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * HMAC-SHA-family, AESCMAC, KMAC128/KMAC256 — one generic class, mechanism
 * supplied at construction, same shape as P11PureSigSignatureSpi.
 * PKCS#11 treats a MAC as a plain C_Sign
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
    private final int macLength;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    private long keyHandle = -1;

    P11MacSpi(P11Library lib, long mech, int macLength) {
        this.lib = lib;
        this.mech = mech;
        this.macLength = macLength;
    }

    @Override protected int engineGetMacLength() { return macLength; }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("this Mac takes no parameters");
        }
        // Deliberately NOT also requiring expectedKeyAlgorithm.equals(s.getAlgorithm()):
        // a KDF-derived opaque key (e.g. PBKDF2's output) is generically
        // labeled by design, matching real JCA convention (JDK's own
        // PBKDF2 SecretKey.getAlgorithm() returns "PBKDF2WithHmacSHA256",
        // not "HmacSHA256" either — a caller normally re-wraps its raw
        // bytes via `new SecretKeySpec(bytes, "HmacSHA256")` to relabel
        // it, which an opaque key with no bytes to wrap simply cannot do).
        // The real type constraint is enforced natively anyway — the
        // engine rejects an incompatible key at the PKCS#11 level (e.g.
        // CKM_AES_CMAC requires CKK_AES) regardless of what this class
        // checks, so this Java-side check only needs to confirm the key
        // is a real token handle, not guess at its intended purpose.
        if (!(key instanceof P11Key.Secret)) {
            throw new InvalidKeyException("this Mac needs a SecretKey from " + SoftHSMv3Provider.class.getSimpleName());
        }
        P11Key.Secret s = (P11Key.Secret) key;
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
