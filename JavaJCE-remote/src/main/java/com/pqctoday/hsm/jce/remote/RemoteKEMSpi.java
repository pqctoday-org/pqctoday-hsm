package com.pqctoday.hsm.jce.remote;

import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.Algorithm;

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

/**
 * ML-KEM {@code KEMSpi} — registered under the bare family name
 * {@code "ML-KEM"} (no parameter-set suffix), same convention as the
 * local {@code ../../JavaJCE/}'s own {@code P11MLKEMSpi} (matching what
 * JDK 27's own {@code Hybrid.getKEM()} requests, confirmed live in that
 * module's own W0.1 probe). The parameter set is carried on the key
 * itself — {@link RemoteKey.Pub#getAlgorithm()}/{@link RemoteKey.Priv#getAlgorithm()}
 * hold the specific JCA name ({@code "ML-KEM-768"} etc, set at
 * {@link RemoteKeyPairGeneratorSpi#generateKeyPair()} time) — looked up
 * back to the proto {@link Algorithm} enum value here, since the wire
 * calls need the specific size, not just the family.
 *
 * <p>Shared-secret handling mirrors the local provider's own deliberate,
 * disclosed exception to its opaque-key design (the KEM secret's whole
 * purpose is to be consumed off-token) — except here it's not even a
 * choice: {@code Encapsulate}/{@code Decapsulate} already return the raw
 * shared-secret bytes directly over the wire (confirmed reading the
 * proto: {@code EncapsulateResponse}/{@code DecapsulateResponse} both
 * carry {@code bytes shared_secret}, never a handle) — there is no
 * opaque alternative available for this remote surface at all.
 */
final class RemoteKEMSpi implements KEMSpi {
    private final GrpcTransport transport;

    private static final Map<String, Algorithm> NAME_TO_ALGO = Map.of(
        "ML-KEM-512", Algorithm.ML_KEM_512,
        "ML-KEM-768", Algorithm.ML_KEM_768,
        "ML-KEM-1024", Algorithm.ML_KEM_1024
    );
    // Ciphertext ("encapsulation") sizes in bytes — same FIPS 203 values
    // the local provider's own P11MLKEMSpi already confirmed live per
    // parameter set (see that class's own commit for the confirmed
    // engine output this table was built from).
    private static final Map<String, Integer> CIPHERTEXT_SIZE =
        Map.of("ML-KEM-512", 768, "ML-KEM-768", 1088, "ML-KEM-1024", 1568);
    private static final int SECRET_SIZE = 32; // FIPS 203: K is always 32 bytes, all parameter sets

    RemoteKEMSpi(GrpcTransport transport) {
        this.transport = transport;
    }

    private static Algorithm algorithmOf(String jcaName) throws InvalidKeyException {
        Algorithm a = NAME_TO_ALGO.get(jcaName);
        if (a == null) {
            throw new InvalidKeyException("unrecognized ML-KEM parameter set: " + jcaName);
        }
        return a;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("ML-KEM takes no encapsulation parameters");
        }
        if (!(publicKey instanceof RemoteKey.Pub p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3RemoteProvider.class.getSimpleName());
        }
        return new Encapsulator(p.handle(), algorithmOf(p.getAlgorithm()), p.getAlgorithm());
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("ML-KEM takes no decapsulation parameters");
        }
        if (!(privateKey instanceof RemoteKey.Priv p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3RemoteProvider.class.getSimpleName());
        }
        return new Decapsulator(p.handle(), algorithmOf(p.getAlgorithm()), p.getAlgorithm());
    }

    private final class Encapsulator implements EncapsulatorSpi {
        private final long publicKeyHandle;
        private final Algorithm protoAlgorithm;
        private final String jcaName;

        Encapsulator(long publicKeyHandle, Algorithm protoAlgorithm, String jcaName) {
            this.publicKeyHandle = publicKeyHandle;
            this.protoAlgorithm = protoAlgorithm;
            this.jcaName = jcaName;
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            GrpcTransport.Encapsulated enc = transport.encapsulate(publicKeyHandle, protoAlgorithm);
            byte[] sliced = java.util.Arrays.copyOfRange(enc.sharedSecret(), from, to);
            // SecretKeySpec's constructor defensively clones its input
            // (same fact the local provider's own P11MLKEMSpi already
            // verified against real JDK 27 source), so the intermediate
            // is safe to zero right after.
            SecretKey key = new SecretKeySpec(sliced, algorithm);
            java.util.Arrays.fill(enc.sharedSecret(), (byte) 0);
            java.util.Arrays.fill(sliced, (byte) 0);
            return new KEM.Encapsulated(key, enc.ciphertext(), null);
        }

        @Override public int engineSecretSize() { return SECRET_SIZE; }
        @Override public int engineEncapsulationSize() { return CIPHERTEXT_SIZE.get(jcaName); }
    }

    private final class Decapsulator implements DecapsulatorSpi {
        private final long privateKeyHandle;
        private final Algorithm protoAlgorithm;
        private final String jcaName;

        Decapsulator(long privateKeyHandle, Algorithm protoAlgorithm, String jcaName) {
            this.privateKeyHandle = privateKeyHandle;
            this.protoAlgorithm = protoAlgorithm;
            this.jcaName = jcaName;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm) throws DecapsulateException {
            byte[] fullSecret;
            try {
                fullSecret = transport.decapsulate(privateKeyHandle, protoAlgorithm, encapsulation);
            } catch (RuntimeException e) {
                throw new DecapsulateException("decapsulation failed", e);
            }
            byte[] sliced = java.util.Arrays.copyOfRange(fullSecret, from, to);
            SecretKey key = new SecretKeySpec(sliced, algorithm);
            java.util.Arrays.fill(fullSecret, (byte) 0);
            java.util.Arrays.fill(sliced, (byte) 0);
            return key;
        }

        @Override public int engineSecretSize() { return SECRET_SIZE; }
        @Override public int engineEncapsulationSize() { return CIPHERTEXT_SIZE.get(jcaName); }
    }
}
