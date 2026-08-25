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
 * are a separate, deliberately deferred item — they need a different
 * SignatureSpi shape (digest algorithm selection) than this class, not
 * this class extended.
 *
 * Investigated, not left implicit (plan §WS-D, 2026-08-25): the engine
 * genuinely implements every one of these mechanisms — confirmed in both
 * SoftHSM_slots.cpp's mechanism-info table and SoftHSM_sign.cpp's real
 * C_SignInit/C_VerifyInit dispatch (the CK_HASH_SIGN_ADDITIONAL_CONTEXT/
 * CK_SIGN_ADDITIONAL_CONTEXT parameter shapes, not stubs), so this is not
 * an engine gap. What's actually missing is a corresponding JCA hook to
 * build this class's shape against: this same JDK 27's own ML-DSA
 * implementation (sun.security.provider.ML_DSA/ML_DSA_Impls, read in
 * full) implements only the pure (no external pre-hash) mode — no
 * "HashML-DSA" standard algorithm name, no pre-hash Signature API
 * surface exists anywhere in this JDK to interoperate against or model
 * a naming convention on. Building this now would mean inventing a
 * non-standard algorithm-naming and digest-selection scheme with no
 * external precedent to verify it against — exactly the kind of
 * unforced design decision this module's own discipline avoids making
 * speculatively. Deferred with this disclosed reasoning rather than
 * left as a bare "not yet built"; revisit if/when a JDK release (or
 * FIPS 204/205's own pre-hash mode) gains real standard-library
 * traction worth building against.
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
