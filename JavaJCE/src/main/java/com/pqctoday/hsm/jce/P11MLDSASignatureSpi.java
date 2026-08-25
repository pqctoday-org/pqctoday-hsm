package com.pqctoday.hsm.jce;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.CKM_ML_DSA;

/**
 * Pure ML-DSA (CKM_ML_DSA, no pre-hash) — single-part signing, so this
 * buffers the whole message and calls C_Sign/C_Verify once, matching the
 * mechanism's own semantics (there is no C_SignUpdate-style streaming for
 * the pure variant; pre-hash CKM_HASH_ML_DSA_* variants are a separate,
 * not-yet-built W2 item). One mechanism serves ML-DSA-44/65/87 alike — the
 * parameter set lives on the KEY (CKA_PARAMETER_SET), not the mechanism.
 */
final class P11MLDSASignatureSpi extends SignatureSpi {
    private final P11Library lib;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private long signKey = -1;
    private long verifyKey = -1;

    P11MLDSASignatureSpi(P11Library lib) {
        this.lib = lib;
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
            byte[] sig = lib.sign(CKM_ML_DSA, signKey, buf.toByteArray());
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
            boolean ok = lib.verify(CKM_ML_DSA, verifyKey, buf.toByteArray(), sigBytes);
            buf.reset();
            return ok;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    // Deprecated legacy parameter API — not needed by ML-DSA; default
    // SignatureSpi behavior (UnsupportedOperationException) is correct.
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
            throw new InvalidAlgorithmParameterException("ML-DSA (pure) takes no signature parameters");
        }
    }
}
