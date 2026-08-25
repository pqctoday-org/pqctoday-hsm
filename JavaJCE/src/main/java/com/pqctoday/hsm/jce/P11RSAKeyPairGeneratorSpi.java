package com.pqctoday.hsm.jce;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Set;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * Standard JCA "RSA" KeyPairGenerator — same one-service-covers-every-size
 * shape as "EC" (P11ECKeyPairGeneratorSpi), size/exponent chosen via
 * initialize(). Bounds confirmed against the engine directly:
 * SoftHSM_keygen.cpp's generateRSA reads CKA_MODULUS_BITS (required,
 * CKR_TEMPLATE_INCOMPLETE if 0/absent) and CKA_PUBLIC_EXPONENT (defaults
 * to 0x010001 = 65537 if absent, per its own ByteString("010001")
 * default), so this class always sends both explicitly rather than
 * relying on the engine's default. Accepted sizes: 2048/3072/4096
 * (decided with the user — 2048 stays FIPS-approved through 2030, but
 * anything smaller is rejected outright rather than silently generated).
 */
final class P11RSAKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final P11Library lib;
    private static final Set<Integer> ALLOWED_SIZES = Set.of(2048, 3072, 4096);
    private static final BigInteger DEFAULT_EXPONENT = BigInteger.valueOf(65537);

    private int modulusBits = -1;
    private BigInteger publicExponent = DEFAULT_EXPONENT;

    P11RSAKeyPairGeneratorSpi(P11Library lib) {
        this.lib = lib;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (!ALLOWED_SIZES.contains(keysize)) {
            throw new InvalidParameterException(
                "unsupported RSA modulus size " + keysize + " (use 2048, 3072, or 4096)");
        }
        modulusBits = keysize;
        publicExponent = DEFAULT_EXPONENT;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof RSAKeyGenParameterSpec spec)) {
            throw new InvalidAlgorithmParameterException(
                "expected RSAKeyGenParameterSpec, got " + (params == null ? "null" : params.getClass()));
        }
        if (!ALLOWED_SIZES.contains(spec.getKeysize())) {
            throw new InvalidAlgorithmParameterException(
                "unsupported RSA modulus size " + spec.getKeysize() + " (use 2048, 3072, or 4096)");
        }
        modulusBits = spec.getKeysize();
        publicExponent = spec.getPublicExponent() != null ? spec.getPublicExponent() : DEFAULT_EXPONENT;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (modulusBits < 0) {
            throw new java.security.ProviderException("RSA KeyPairGenerator was not initialized "
                + "(call initialize(2048|3072|4096, ...) or initialize(new RSAKeyGenParameterSpec(...)) first)");
        }
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_MODULUS_BITS, modulusBits),
            P11Library.attr(CKA_PUBLIC_EXPONENT, unsignedBigEndian(publicExponent)),
            P11Library.attrBool(CKA_VERIFY, true),
            // Same lesson as P11ECKeyPairGeneratorSpi's CKA_DERIVE fix:
            // a real RSA keypair is algorithm-agnostic at generation
            // time — the single "RSA" KeyPairGenerator serves both
            // signing (CKA_VERIFY/CKA_SIGN) and OAEP encrypt/decrypt
            // (CKA_ENCRYPT/CKA_DECRYPT), so both must be granted.
            // Added proactively here (not after a live failure) once
            // the EC precedent made the pattern obvious.
            P11Library.attrBool(CKA_ENCRYPT, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        P11Library.Attr[] prvTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PRIVATE_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_PRIVATE, true),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_SIGN, true),
            P11Library.attrBool(CKA_DECRYPT, true),
        };
        long[] handles = lib.generateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        byte[] spki = lib.getAttributeBytes(handles[0], CKA_PUBLIC_KEY_INFO);
        P11Key.Pub pub = new P11Key.Pub(lib, handles[0], "RSA", spki);
        P11Key.Priv priv = new P11Key.Priv(lib, handles[1], "RSA");
        return new KeyPair(pub, priv);
    }

    /** BigInteger.toByteArray() may carry a leading 0x00 sign byte for values with the high bit set; strip it. */
    private static byte[] unsignedBigEndian(BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? java.util.Arrays.copyOfRange(b, 1, b.length) : b;
    }
}
