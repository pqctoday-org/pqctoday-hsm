package com.pqctoday.hsm.jce;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Map;

/**
 * The three P-curves this module supports (secp256r1/384r1/521r1),
 * shared between {@link P11ECKeyPairGeneratorSpi} (generation) and
 * {@link P11PublicKeyFactorySpi} (import) — extracted so the curve
 * OID/coordinate-size/{@link ECParameterSpec} mapping lives in exactly
 * one place instead of being duplicated wherever an EC point needs to
 * round-trip between this module's opaque handles and a real
 * {@code java.security.interfaces.ECKey}. The DER OID byte values
 * themselves are unchanged from where they already lived (this class's
 * javadoc note on the byte derivation is preserved on
 * {@link P11ECKeyPairGeneratorSpi} where it was first written).
 */
final class P11EcCurves {
    private P11EcCurves() {}

    record Curve(String name, String oid, byte[] oidDer, int coordBytes) {}

    private static final Curve SECP256R1 = new Curve("secp256r1", "1.2.840.10045.3.1.7",
        new byte[]{ 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07 }, 32);
    private static final Curve SECP384R1 = new Curve("secp384r1", "1.3.132.0.34",
        new byte[]{ 0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x22 }, 48);
    private static final Curve SECP521R1 = new Curve("secp521r1", "1.3.132.0.35",
        new byte[]{ 0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x23 }, 66);

    static final Map<String, Curve> BY_NAME = Map.of(
        "secp256r1", SECP256R1, "secp384r1", SECP384R1, "secp521r1", SECP521R1);

    /** Curve OID string (dotted decimal) -> Curve, for import paths that only have the OID. */
    static final Map<String, Curve> BY_OID = Map.of(
        "1.2.840.10045.3.1.7", SECP256R1,
        "1.3.132.0.34", SECP384R1,
        "1.3.132.0.35", SECP521R1);

    /**
     * Identifies one of the three supported curves purely from an
     * incoming {@link ECParameterSpec}'s field size — used when a
     * caller (e.g. JDK 27's own {@code DHasKEM}, deserializing a peer's
     * TLS key_share) hands us params with no curve name attached, only
     * the field/curve/generator/order/cofactor values themselves. Since
     * this module supports exactly three NIST P-curves and each has a
     * distinct, well-known field bit length (256/384/521), matching on
     * that is unambiguous — no need to compare full curve equations.
     */
    static Curve byFieldSize(ECParameterSpec params) {
        int bits = params.getCurve().getField().getFieldSize();
        return switch (bits) {
            case 256 -> SECP256R1;
            case 384 -> SECP384R1;
            case 521 -> SECP521R1;
            default -> throw new IllegalArgumentException("unsupported EC field size " + bits + " bits");
        };
    }

    /** The real, JDK-recognized ECParameterSpec for a curve — via AlgorithmParameters, not hand-built. */
    static ECParameterSpec jdkParams(Curve curve) {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec(curve.name()));
            return ap.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new AssertionError("JDK's own \"" + curve.name() + "\" AlgorithmParameters lookup failed", e);
        }
    }

    /** Decodes an uncompressed EC point (0x04 || X || Y) into a java.security.spec.ECPoint. */
    static java.security.spec.ECPoint decodePoint(byte[] uncompressed, int coordBytes) {
        if (uncompressed.length != 1 + 2 * coordBytes || uncompressed[0] != 0x04) {
            throw new IllegalArgumentException("expected an uncompressed EC point (0x04 || X || Y), got "
                + uncompressed.length + " bytes starting with 0x" + Integer.toHexString(uncompressed[0] & 0xff));
        }
        byte[] x = java.util.Arrays.copyOfRange(uncompressed, 1, 1 + coordBytes);
        byte[] y = java.util.Arrays.copyOfRange(uncompressed, 1 + coordBytes, 1 + 2 * coordBytes);
        return new java.security.spec.ECPoint(new java.math.BigInteger(1, x), new java.math.BigInteger(1, y));
    }

    /** Encodes an ECPoint back into uncompressed wire form (0x04 || X || Y), zero-padded to coordBytes each. */
    static byte[] encodePoint(java.security.spec.ECPoint w, int coordBytes) {
        byte[] out = new byte[1 + 2 * coordBytes];
        out[0] = 0x04;
        copyFixedWidth(w.getAffineX(), out, 1, coordBytes);
        copyFixedWidth(w.getAffineY(), out, 1 + coordBytes, coordBytes);
        return out;
    }

    private static void copyFixedWidth(java.math.BigInteger v, byte[] dest, int destOffset, int width) {
        byte[] b = v.toByteArray();
        int srcOffset = Math.max(0, b.length - width);
        int len = b.length - srcOffset;
        System.arraycopy(b, srcOffset, dest, destOffset + (width - len), len);
    }
}
