package com.pqctoday.hsm.jce;

import javax.crypto.MacSpi;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * HMAC-SHA-family, AESCMAC, KMAC128/256 — one generic class, mechanism
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
 *
 * Item 1 (2026-08-30): general-length ("_HMAC_GENERAL") support. Verified
 * against the real javax.crypto.spec javadoc (JDK 21+) before writing
 * this — {@link P11MacOutputLengthParameterSpec}'s own javadoc records
 * the finding: no standard AlgorithmParameterSpec for MAC-output
 * truncation exists anywhere in the JDK. {@code generalMech} (0 = "no
 * general-length twin", the exact same sentinel convention as the
 * engine's own kMacMechTable.generalMech in SoftHSM_sign.cpp) is supplied
 * only by the new "*General"-suffixed registrations
 * (SoftHSMv3Provider#registerHmacGeneral); every pre-existing
 * registration (plain HmacSHA*, AESCMAC, KMAC128/256) still constructs
 * this class via the original 2-arg constructor, which fixes
 * generalMech=0 and therefore keeps engineInit's "this Mac takes no
 * parameters" rejection of any non-null AlgorithmParameterSpec
 * byte-for-byte unchanged — the plain HMAC path is completely untouched.
 */
final class P11MacSpi extends MacSpi {
    private final P11Library lib;
    private final long mech;
    private final long generalMech; // 0 = no general-length twin (see class javadoc)
    private final int macLength;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    private long keyHandle = -1;
    private long effectiveMech = -1;
    private int effectiveMacLength = -1;

    P11MacSpi(P11Library lib, long mech, int macLength) {
        this(lib, mech, 0L, macLength);
    }

    /** @param generalMech the mechanism's "_HMAC_GENERAL" twin, or 0 if this Mac has none — see class javadoc. */
    P11MacSpi(P11Library lib, long mech, long generalMech, int macLength) {
        this.lib = lib;
        this.mech = mech;
        this.generalMech = generalMech;
        this.macLength = macLength;
    }

    @Override
    protected int engineGetMacLength() {
        return effectiveMacLength > 0 ? effectiveMacLength : macLength;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params == null) {
            if (generalMech != 0) {
                throw new InvalidAlgorithmParameterException(
                    "this Mac is the general-length (\"_HMAC_GENERAL\") variant and requires a "
                    + "P11MacOutputLengthParameterSpec — PKCS#11's general-length MAC mechanism has no "
                    + "default output length (the engine's own applyGeneralMacLength() unconditionally "
                    + "requires a CK_MAC_GENERAL_PARAMS)");
            }
            effectiveMech = mech;
            effectiveMacLength = macLength;
        } else if (params instanceof P11MacOutputLengthParameterSpec lenSpec) {
            if (generalMech == 0) {
                throw new InvalidAlgorithmParameterException(
                    "this Mac has no general-length (truncatable) variant — use the plain algorithm name");
            }
            effectiveMech = generalMech;
            effectiveMacLength = lenSpec.outputLengthBytes();
        } else {
            throw new InvalidAlgorithmParameterException(
                "this Mac takes no parameters" + (generalMech != 0 ? " other than P11MacOutputLengthParameterSpec" : "")
                + " — got " + params.getClass());
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
        byte[] result;
        if (generalMech != 0 && effectiveMech == generalMech) {
            try (var op = java.lang.foreign.Arena.ofConfined()) {
                var m = lib.mechWithParams(op, generalMech, effectiveMacLength);
                result = lib.sign(op, m, keyHandle, buf.toByteArray());
            }
        } else {
            result = lib.sign(effectiveMech, keyHandle, buf.toByteArray());
        }
        buf.reset();
        return result;
    }

    @Override protected void engineReset() { buf.reset(); }
}
