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
 * Approved digests only (SHA-256/384/512 and the full SHA-3 family —
 * SHA-1 explicitly rejected, same FIPS 140-3 L3 exclusion policy
 * enforced everywhere else in this provider, W1's digest registration
 * first). SHA-3 PSS support (plan §WS-D) was added once confirmed real
 * rather than assumed from the SHA-2 precedent: the engine genuinely
 * dispatches all four `CKM_SHA3_*_RSA_PKCS_PSS` mechanisms — checked in
 * both `SoftHSM_slots.cpp`'s mechanism-info table (same
 * `CKF_SIGN|CKF_VERIFY` capability flags as the SHA-2 variants) and
 * `SoftHSM_sign.cpp`'s actual `C_SignInit`/`C_VerifyInit` dispatch
 * (real `AsymMech::RSA_SHA3_*_PKCS_PSS` cases, not stubs), each
 * expecting exactly the same `{hashAlg=CKM_SHA3_*; mgf=CKG_MGF1_SHA3_*}`
 * parameter shape this class already builds for SHA-2.
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
        // Item 4 (2026-08-30 follow-on): "SHA-224" was the one digest
        // missing from this map — CKM_SHA224_RSA_PKCS_PSS is a real,
        // engine-dispatched mechanism (SoftHSM_slots.cpp/SoftHSM_sign.cpp)
        // and the constant simply hadn't been declared yet.
        "SHA-224", new long[]{ CKM_SHA224_RSA_PKCS_PSS, CKM_SHA224, CKG_MGF1_SHA224 },
        "SHA-256", new long[]{ CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, CKG_MGF1_SHA256 },
        "SHA-384", new long[]{ CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384, CKG_MGF1_SHA384 },
        "SHA-512", new long[]{ CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512, CKG_MGF1_SHA512 },
        "SHA3-224", new long[]{ CKM_SHA3_224_RSA_PKCS_PSS, CKM_SHA3_224, CKG_MGF1_SHA3_224 },
        "SHA3-256", new long[]{ CKM_SHA3_256_RSA_PKCS_PSS, CKM_SHA3_256, CKG_MGF1_SHA3_256 },
        "SHA3-384", new long[]{ CKM_SHA3_384_RSA_PKCS_PSS, CKM_SHA3_384, CKG_MGF1_SHA3_384 },
        "SHA3-512", new long[]{ CKM_SHA3_512_RSA_PKCS_PSS, CKM_SHA3_512, CKG_MGF1_SHA3_512 }
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
        try (var op = java.lang.foreign.Arena.ofConfined()) {
            byte[] sig = lib.sign(op, pssMech(op), signKey, buf.toByteArray());
            buf.reset();
            return sig;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (verifyKey < 0) throw new SignatureException("engineInitVerify was not called");
        try (var op = java.lang.foreign.Arena.ofConfined()) {
            boolean ok = lib.verify(op, pssMech(op), verifyKey, buf.toByteArray(), sigBytes);
            buf.reset();
            return ok;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    private java.lang.foreign.MemorySegment pssMech(java.lang.foreign.Arena op) {
        long[] m = DIGEST_TO_MECH_AND_MGF.get(digestName);
        return lib.mechWithParams(op, m[0], m[1], m[2], saltLen);
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
                + " (SHA-1 excluded by this provider's FIPS 140-3 L3 policy)");
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
