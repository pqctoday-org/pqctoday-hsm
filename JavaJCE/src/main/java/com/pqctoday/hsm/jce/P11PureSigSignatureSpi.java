package com.pqctoday.hsm.jce;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Generic SignatureSpi for "pure" (no pre-hash) PKCS#11 signature
 * mechanisms — single-part signing over the whole buffered message, one
 * mechanism value serving every parameter set of the algorithm (the
 * parameter set lives on the key, not the mechanism — confirmed for
 * ML-DSA and SLH-DSA by reading the engine's dispatch code before
 * assuming it). Pre-hash variants (CKM_HASH_ML_DSA_*, CKM_HASH_SLH_DSA_*)
 * are a separate, not-yet-built W2 item — they need a different
 * SignatureSpi shape (digest algorithm selection), not this class.
 *
 * Extracted from what was P11MLDSASignatureSpi.
 */
final class P11PureSigSignatureSpi extends SignatureSpi {
    private final P11Library lib;
    private final long mechanism;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private long signKey = -1;
    private long verifyKey = -1;

    P11PureSigSignatureSpi(P11Library lib, long mechanism) {
        this.lib = lib;
        this.mechanism = mechanism;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof P11Key.Priv p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3Provider.class.getSimpleName());
        }
        signKey = p.handle();
        verifyKey = -1;
        buf.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof P11Key.Pub p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3Provider.class.getSimpleName());
        }
        verifyKey = p.handle();
        signKey = -1;
        buf.reset();
    }

    @Override protected void engineUpdate(byte b) { buf.write(b); }
    @Override protected void engineUpdate(byte[] b, int off, int len) { buf.write(b, off, len); }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signKey < 0) throw new SignatureException("engineInitSign was not called");
        try {
            byte[] sig = lib.sign(mechanism, signKey, buf.toByteArray());
            buf.reset();
            return sig;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (verifyKey < 0) throw new SignatureException("engineInitVerify was not called");
        try {
            boolean ok = lib.verify(mechanism, verifyKey, buf.toByteArray(), sigBytes);
            buf.reset();
            return ok;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("use engineSetParameter(AlgorithmParameterSpec)");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("use engineGetParameters()");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("this pure signature mechanism takes no parameters");
        }
    }
}
