package com.pqctoday.hsm.jce;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * ML-KEM KEMSpi — registered under the bare family name "ML-KEM" (no
 * parameter-set suffix), matching what W0.1's live JSSE probe proved
 * JDK 27's Hybrid.getKEM() actually requests
 * (KEM.getInstance("ML-KEM"), verbatim, regardless of which parameter
 * set the hybrid group needs) — confirmed against the real RC binary in
 * a live TLS handshake against pqc-rest, not assumed from the API shape
 * alone. The parameter set is determined per-call from the key handed
 * to engineNewEncapsulator/engineNewDecapsulator (its own
 * CKA_PARAMETER_SET), the same "family name, parameter set on the key"
 * pattern as P11PureSigSignatureSpi.
 *
 * Shared-secret handling — user decision (2026-08-24), matching what
 * W0.1 already proved is required for real JSSE integration: the
 * decapsulated secret is extracted from the token as a plain
 * SecretKeySpec, NOT kept as an opaque handle. This is a deliberate,
 * singular exception to every other secret/private key in this module
 * (which never sets CKA_EXTRACTABLE=true) — the KEM secret's entire
 * purpose is to be consumed by code outside the token (JSSE's own HKDF
 * key schedule and AES-GCM record cipher), so keeping it opaque would
 * make the KEM unusable for its actual job. See the class comment on
 * P11MLKEMKeyPairGeneratorSpi and the implementation plan's W3 entry for
 * the full reasoning (including why a fully token-resident alternative
 * doesn't exist within a standard-JSSE architecture).
 */
final class P11MLKEMSpi implements KEMSpi {
    private final P11Library lib;

    // Ciphertext ("encapsulation") sizes in bytes — filled in and
    // verified live per parameter set the first time each is needed
    // (see the W3 ML-KEM commit for the confirmed FIPS 203 values);
    // avoids hardcoding a table from memory before observing the real
    // engine output at least once.
    private static final Map<Long, Integer> CIPHERTEXT_SIZE = Map.of(
        CKP_ML_KEM_512, 768,
        CKP_ML_KEM_768, 1088,
        CKP_ML_KEM_1024, 1568
    );
    private static final int SECRET_SIZE = 32; // FIPS 203: K is always 32 bytes, all parameter sets

    P11MLKEMSpi(P11Library lib) {
        this.lib = lib;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("ML-KEM takes no encapsulation parameters");
        }
        if (!(publicKey instanceof P11Key.Pub p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3Provider.class.getSimpleName());
        }
        long parameterSet = parameterSetOf(p.handle());
        return new Encapsulator(p.handle(), parameterSet);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("ML-KEM takes no decapsulation parameters");
        }
        if (!(privateKey instanceof P11Key.Priv p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3Provider.class.getSimpleName());
        }
        long parameterSet = parameterSetOf(p.handle());
        return new Decapsulator(p.handle(), parameterSet);
    }

    private long parameterSetOf(long handle) throws InvalidKeyException {
        byte[] psBytes = lib.getAttributeBytes(handle, CKA_PARAMETER_SET);
        long ps = 0;
        for (int i = 0; i < Math.min(psBytes.length, 8); i++) ps |= (psBytes[i] & 0xffL) << (8 * i);
        if (!CIPHERTEXT_SIZE.containsKey(ps)) {
            throw new InvalidKeyException("unrecognized ML-KEM parameter set value " + ps);
        }
        return ps;
    }

    private final class Encapsulator implements EncapsulatorSpi {
        private final long publicKeyHandle;
        private final long parameterSet;

        Encapsulator(long publicKeyHandle, long parameterSet) {
            this.publicKeyHandle = publicKeyHandle;
            this.parameterSet = parameterSet;
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            P11Library.Attr[] ssTmpl = {
                P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
                P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                P11Library.attrBool(CKA_TOKEN, false),
                P11Library.attrBool(CKA_SENSITIVE, false),
                // Deliberate exception to this module's "never
                // extractable" pattern — see class javadoc.
                P11Library.attrBool(CKA_EXTRACTABLE, true),
            };
            P11Library.Encapsulated enc = lib.encapsulate(CKM_ML_KEM, publicKeyHandle, ssTmpl);
            byte[] fullSecret = lib.getAttributeBytes(enc.sharedSecretHandle(), CKA_VALUE);
            byte[] sliced = java.util.Arrays.copyOfRange(fullSecret, from, to);
            // SecretKeySpec's constructor defensively clones its input
            // (verified against real JDK 27 source: `this.key =
            // key.clone()`), so both intermediate arrays are safe to
            // zero immediately afterward — neither is referenced by
            // anything else (§6.5 zeroization posture).
            SecretKey key = new SecretKeySpec(sliced, algorithm);
            java.util.Arrays.fill(fullSecret, (byte) 0);
            java.util.Arrays.fill(sliced, (byte) 0);
            return new KEM.Encapsulated(key, enc.ciphertext(), null);
        }

        @Override public int engineSecretSize() { return SECRET_SIZE; }
        @Override public int engineEncapsulationSize() { return CIPHERTEXT_SIZE.get(parameterSet); }
    }

    private final class Decapsulator implements DecapsulatorSpi {
        private final long privateKeyHandle;
        private final long parameterSet;

        Decapsulator(long privateKeyHandle, long parameterSet) {
            this.privateKeyHandle = privateKeyHandle;
            this.parameterSet = parameterSet;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm) throws DecapsulateException {
            P11Library.Attr[] ssTmpl = {
                P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
                P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                P11Library.attrBool(CKA_TOKEN, false),
                P11Library.attrBool(CKA_SENSITIVE, false),
                P11Library.attrBool(CKA_EXTRACTABLE, true), // see class javadoc
            };
            long ssHandle;
            try {
                ssHandle = lib.decapsulate(CKM_ML_KEM, privateKeyHandle, ssTmpl, encapsulation);
            } catch (RuntimeException e) {
                throw new DecapsulateException("decapsulation failed", e);
            }
            byte[] fullSecret = lib.getAttributeBytes(ssHandle, CKA_VALUE);
            byte[] sliced = java.util.Arrays.copyOfRange(fullSecret, from, to);
            // See Encapsulator#engineEncapsulate's comment: SecretKeySpec
            // clones defensively, so both intermediates are safe to zero
            // right after (§6.5).
            SecretKey key = new SecretKeySpec(sliced, algorithm);
            java.util.Arrays.fill(fullSecret, (byte) 0);
            java.util.Arrays.fill(sliced, (byte) 0);
            return key;
        }

        @Override public int engineSecretSize() { return SECRET_SIZE; }
        @Override public int engineEncapsulationSize() { return CIPHERTEXT_SIZE.get(parameterSet); }
    }
}
