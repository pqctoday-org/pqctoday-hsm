package com.pqctoday.hsm.jce;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Map;

/**
 * ECDSA SignatureSpi — NOT built on P11PureSigSignatureSpi despite
 * CKM_ECDSA_SHA* being the same "hash internally, raw message in" shape
 * as ML-DSA/SLH-DSA/EdDSA (confirmed in SoftHSMv3Provider's registration
 * comment). The reason is a format mismatch discovered live, not assumed:
 * PKCS#11's C_Sign/C_Verify for ECDSA use RAW r‖s bytes (each exactly the
 * curve's field size, per PKCS#11 v3.2 §2.3.1), but JCA's "SHA256withECDSA"
 * convention (inherited from DSA) is ASN.1 DER SEQUENCE{INTEGER r,
 * INTEGER s} (RFC 3279 §2.2.3, "ECDSA-Sig-Value"). A first pass reusing
 * P11PureSigSignatureSpi unchanged passed our own round-trip (our sign,
 * our verify — both raw, so symmetric and silently "worked") but FAILED
 * cross-verification against JDK's own SunEC with a real
 * java.security.SignatureException ("Invalid encoding for signature" /
 * "Not the correct tag") — exactly the kind of self-consistent-but-wrong
 * result the cross-verification step in this plan's testing convention
 * exists to catch (see the W2 EC commit for the full trace).
 *
 * The DER<->raw conversion uses Bouncy Castle's org.bouncycastle.asn1
 * classes (ASN1Integer/DERSequence/ASN1Sequence) — pure syntax, not
 * crypto (see pom.xml's dependency comment for the exact boundary) —
 * rather than a hand-rolled parser: this repo's own precedent, from
 * peculiar/asn1-schema in pqctoday-hub to nlohmann::json in the sandbox's
 * C++ samples, is consistently "use a small established library for a
 * wire format, don't reinvent the codec." A hand-rolled DER-integer
 * codec was written first and then replaced with this one specifically
 * because of that precedent (checked directly, not assumed).
 */
final class P11ECDSASignatureSpi extends SignatureSpi {
    private final P11Library lib;
    private final long mechanism;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private long signKey = -1;
    private long verifyKey = -1;
    private int fieldSize = -1;

    // CKA_EC_PARAMS bytes (hex) -> field size in bytes, for the curves
    // P11ECKeyPairGeneratorSpi supports.
    private static final Map<String, Integer> FIELD_SIZE_BY_OID_HEX = Map.of(
        "06082a8648ce3d030107", 32, // secp256r1
        "06052b8104" + "0022", 48, // secp384r1
        "06052b8104" + "0023", 66  // secp521r1
    );

    P11ECDSASignatureSpi(P11Library lib, long mechanism) {
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
        fieldSize = fieldSizeOf(signKey);
        buf.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof P11Key.Pub p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3Provider.class.getSimpleName());
        }
        verifyKey = p.handle();
        signKey = -1;
        fieldSize = fieldSizeOf(verifyKey);
        buf.reset();
    }

    private int fieldSizeOf(long handle) throws InvalidKeyException {
        byte[] ecParams = lib.getAttributeBytes(handle, P11Constants.CKA_EC_PARAMS);
        StringBuilder hex = new StringBuilder();
        for (byte b : ecParams) hex.append(String.format("%02x", b));
        Integer fs = FIELD_SIZE_BY_OID_HEX.get(hex.toString());
        if (fs == null) {
            throw new InvalidKeyException("unrecognized EC curve (CKA_EC_PARAMS=" + hex + ")");
        }
        return fs;
    }

    @Override protected void engineUpdate(byte b) { buf.write(b); }
    @Override protected void engineUpdate(byte[] b, int off, int len) { buf.write(b, off, len); }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signKey < 0) throw new SignatureException("engineInitSign was not called");
        try {
            byte[] raw = lib.sign(mechanism, signKey, buf.toByteArray());
            buf.reset();
            if (raw.length != 2 * fieldSize) {
                throw new SignatureException("unexpected raw ECDSA signature length "
                    + raw.length + ", expected " + (2 * fieldSize));
            }
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(raw, 0, fieldSize));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(raw, fieldSize, raw.length));
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            return new DERSequence(v).getEncoded("DER");
        } catch (IOException e) {
            throw new SignatureException("DER encoding failed", e);
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (verifyKey < 0) throw new SignatureException("engineInitVerify was not called");
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(sigBytes);
            if (seq.size() != 2) {
                throw new SignatureException("ECDSA-Sig-Value must have exactly 2 elements, got " + seq.size());
            }
            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            byte[] raw = new byte[2 * fieldSize];
            copyUnsigned(r, raw, 0, fieldSize);
            copyUnsigned(s, raw, fieldSize, fieldSize);
            boolean ok = lib.verify(mechanism, verifyKey, buf.toByteArray(), raw);
            buf.reset();
            return ok;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    /** Writes a BigInteger's unsigned big-endian value into dst[off..off+len), zero-padded on the left. */
    private static void copyUnsigned(BigInteger value, byte[] dst, int off, int len) throws SignatureException {
        byte[] mag = value.toByteArray(); // two's-complement; may have a leading 0x00 sign byte
        int magStart = (mag.length > 1 && mag[0] == 0) ? 1 : 0;
        int magLen = mag.length - magStart;
        if (magLen > len) {
            throw new SignatureException("signature integer too large for field size " + len + " (got " + magLen + " bytes)");
        }
        System.arraycopy(mag, magStart, dst, off + (len - magLen), magLen);
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
            throw new InvalidAlgorithmParameterException("ECDSA takes no signature parameters");
        }
    }
}
