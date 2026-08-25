package com.pqctoday.hsm.jce;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Map;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * "RSASSA-PSS" Signature — a genuinely different shape than every prior
 * SignatureSpi in this module: PSS's exact mechanism and mechanism
 * parameters (CK_RSA_PKCS_PSS_PARAMS { hashAlg; mgf; sLen; }) are chosen
 * by the CALLER after construction, via engineSetParameter(PSSParameterSpec)
 * — not fixed at Service registration time like every algorithm above.
 * Matches how SunRsaSign itself registers "RSASSA-PSS" as one configurable
 * service rather than one service per digest.
 *
 * Approved digests only (SHA-256/384/512 — SHA-1 explicitly rejected,
 * same FIPS 140-3 L3 exclusion policy enforced everywhere else in this
 * provider, W1's digest registration first). SHA-3 PSS variants
 * (CKG_MGF1_SHA3_*) are a real, not-yet-built gap — this class covers
 * the SHA-2 family only; scoped down deliberately rather than left
 * silently incomplete.
 *
 * Default (before any engineSetParameter call): SHA-256/MGF1-SHA256/
 * 32-byte salt — NOT SunRsaSign's own SHA-1-based default, which this
 * provider's FIPS policy excludes outright.
 */
final class P11RSAPSSSignatureSpi extends SignatureSpi {
    private final P11Library lib;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private long signKey = -1;
    private long verifyKey = -1;

    private static final Map<String, long[]> DIGEST_TO_MECH_AND_MGF = Map.of(
        // digestName -> { CKM_SHA*_RSA_PKCS_PSS, CK_RSA_PKCS_PSS_PARAMS.hashAlg, CKG_MGF1_SHA* }
        "SHA-256", new long[]{ CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, CKG_MGF1_SHA256 },
        "SHA-384", new long[]{ CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384, CKG_MGF1_SHA384 },
        "SHA-512", new long[]{ CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512, CKG_MGF1_SHA512 }
    );

    private String digestName = "SHA-256";
    private int saltLen = 32;

    P11RSAPSSSignatureSpi(P11Library lib) {
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
            byte[] sig = lib.sign(pssMech(), signKey, buf.toByteArray());
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
            boolean ok = lib.verify(pssMech(), verifyKey, buf.toByteArray(), sigBytes);
            buf.reset();
            return ok;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    private java.lang.foreign.MemorySegment pssMech() {
        long[] m = DIGEST_TO_MECH_AND_MGF.get(digestName);
        return lib.mechWithParams(m[0], m[1], m[2], saltLen);
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (!(params instanceof PSSParameterSpec pss)) {
            throw new InvalidAlgorithmParameterException(
                "expected PSSParameterSpec, got " + (params == null ? "null" : params.getClass()));
        }
        String digest = pss.getDigestAlgorithm();
        if (!DIGEST_TO_MECH_AND_MGF.containsKey(digest)) {
            throw new InvalidAlgorithmParameterException(
                "unsupported PSS digest " + digest + " — supported: " + DIGEST_TO_MECH_AND_MGF.keySet()
                + " (SHA-1 excluded by this provider's FIPS 140-3 L3 policy; SHA-3 PSS not yet built)");
        }
        if (!(pss.getMGFAlgorithm().equals("MGF1")
                && pss.getMGFParameters() instanceof MGF1ParameterSpec mgf
                && mgf.getDigestAlgorithm().equals(digest))) {
            throw new InvalidAlgorithmParameterException(
                "MGF must be MGF1 with the same digest as the PSS digest (" + digest + ")");
        }
        if (pss.getTrailerField() != PSSParameterSpec.TRAILER_FIELD_BC) {
            throw new InvalidAlgorithmParameterException("only the standard trailer field (0xBC) is supported");
        }
        this.digestName = digest;
        this.saltLen = pss.getSaltLength();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // No AlgorithmParameters factory registered for PSS in this
        // provider (would need its own AlgorithmParametersSpi) — real,
        // small, not-yet-built gap, same honesty standard as the SHA-3
        // scope note above.
        throw new UnsupportedOperationException(
            "engineGetParameters not yet implemented — use engineSetParameter(PSSParameterSpec) to configure");
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
}
