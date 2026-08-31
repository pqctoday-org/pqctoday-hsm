package com.pqctoday.hsm.jce;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EdDSAParameterSpec;

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
 *
 * Item 7 (2026-08-30, EdDSA context/prehash): {@code java.security.spec.
 * EdDSAParameterSpec} (JDK 15+) is a REAL standard class covering RFC
 * 8032's full Ed25519/Ed25519ctx/Ed25519ph/Ed448/Ed448ph mode selection
 * in one shape (isPrehash()/getContext()) — confirmed against the real
 * JDK 21+ javadoc before writing this, correcting an earlier audit that
 * wrongly claimed no such precedent existed. Only meaningful when
 * {@code mechanism == CKM_EDDSA}; every other mechanism this class
 * serves (RSA-PKCS1, SLH-DSA, plain ML-DSA, ML-DSA-EXTERNAL-MU) keeps
 * rejecting any non-null parameter exactly as before.
 *
 * Mechanism dispatch always stays CKM_EDDSA (never CKM_EDDSA_PH) even in
 * prehash mode, with CK_EDDSA_PARAMS.phFlag carrying the mode — this
 * mirrors the parallel OpenSSL-provider fix for this exact concern
 * (src/vendor/pkcs11-provider/src/sig/eddsa.c's
 * p11prov_eddsa_instance_to_params, read before writing this): that fix
 * also always constructs its context with CKM_EDDSA
 * (p11prov_sig_newctx(ctx, CKM_EDDSA, ...)) and only ever *attaches*
 * CK_EDDSA_PARAMS with phFlag=CK_TRUE for the ph variants — never
 * switches the mechanism type itself to CKM_EDDSA_PH. The engine's own
 * SoftHSM_sign.cpp explains why: CKM_EDDSA_PH is kept "deliberately
 * still parameterless" as a legacy/vendor shorthand for prehash-with-no-
 * context, since "everything CK_EDDSA_PARAMS can express is now
 * reachable through the standard CKM_EDDSA" — widening the vendor
 * mechanism to also accept params "would add a second way to say the
 * same thing." Gating: CKM_EDDSA_PH is still checked for advertisement
 * (via {@link P11Library#mechanismSupported}) whenever prehash is
 * requested, even though it is never the mechanism actually dispatched —
 * used purely as the capability SIGNAL "this token really supports
 * pre-hash EdDSA," exactly the same non-obvious design choice the
 * OpenSSL-provider fix makes (its own p11prov_check_mechanism call
 * checks CKM_EDDSA_PH for the identical reason, in the identical place).
 */
final class P11PureSigSignatureSpi extends SignatureSpi {
    private final P11Library lib;
    private final long mechanism;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private long signKey = -1;
    private long verifyKey = -1;

    // Only ever non-null when mechanism == CKM_EDDSA and the caller has
    // called engineSetParameter(EdDSAParameterSpec) — see engineSign()/
    // engineVerify()/engineSetParameter() below. Deliberately NOT reset by
    // engineInitSign/engineInitVerify — same precedent as
    // P11RSAPSSSignatureSpi's digestName/saltLen fields elsewhere in this
    // module, which also survive re-init, matching the real JDK
    // SignatureSpi contract that setParameter() may legally be called
    // either before or after initSign()/initVerify().
    private EdDSAParameterSpec eddsaParams;

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
            byte[] sig = eddsaParams != null
                ? signWithEdDSAParams(signKey, buf.toByteArray())
                : lib.sign(mechanism, signKey, buf.toByteArray());
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
            boolean ok = eddsaParams != null
                ? verifyWithEdDSAParams(verifyKey, buf.toByteArray(), sigBytes)
                : lib.verify(mechanism, verifyKey, buf.toByteArray(), sigBytes);
            buf.reset();
            return ok;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    private byte[] signWithEdDSAParams(long key, byte[] data) {
        try (var op = java.lang.foreign.Arena.ofConfined()) {
            return lib.sign(op, eddsaMechanism(op), key, data);
        }
    }

    private boolean verifyWithEdDSAParams(long key, byte[] data, byte[] sig) {
        try (var op = java.lang.foreign.Arena.ofConfined()) {
            return lib.verify(op, eddsaMechanism(op), key, data, sig);
        }
    }

    private java.lang.foreign.MemorySegment eddsaMechanism(java.lang.foreign.Arena op) {
        boolean prehash = eddsaParams.isPrehash();
        byte[] context = eddsaParams.getContext().orElse(new byte[0]);
        return lib.mechEddsaWithParams(op, prehash, context);
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
        if (params == null) {
            eddsaParams = null;
            return;
        }
        if (mechanism == P11Constants.CKM_EDDSA && params instanceof EdDSAParameterSpec spec) {
            // Prehash -> Ed25519ph/Ed448ph: gated on the token advertising
            // CKM_EDDSA_PH, purely as a capability signal — see this
            // class's javadoc for why CKM_EDDSA (not CKM_EDDSA_PH) is
            // still what actually gets dispatched. Not gated for the
            // plain/ctx cases: those are always reachable the moment
            // plain CKM_EDDSA itself is (a token could in principle
            // advertise CKM_EDDSA without CKM_EDDSA_PH, but the reverse —
            // CKM_EDDSA_PH without CKM_EDDSA — is not a real PKCS#11
            // configuration this engine or spec produces).
            if (spec.isPrehash() && !lib.mechanismSupported(P11Constants.CKM_EDDSA_PH)) {
                throw new InvalidAlgorithmParameterException(
                    "this token does not advertise CKM_EDDSA_PH -- Ed25519ph/Ed448ph (prehash) is not available");
            }
            eddsaParams = spec;
            return;
        }
        throw new InvalidAlgorithmParameterException("this pure signature mechanism takes no parameters"
            + (mechanism == P11Constants.CKM_EDDSA ? " other than EdDSAParameterSpec" : ""));
    }
}
