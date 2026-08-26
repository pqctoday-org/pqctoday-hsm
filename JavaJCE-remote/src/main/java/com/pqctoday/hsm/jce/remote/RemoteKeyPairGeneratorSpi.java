package com.pqctoday.hsm.jce.remote;

import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.Algorithm;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

/**
 * Generic {@code KeyPairGeneratorSpi} for the whole remote surface — one
 * shape for all 7 algorithms (Ed25519, ML-DSA-44/65/87, ML-KEM-512/768/1024),
 * unlike the local {@code ../../JavaJCE/} provider's split between
 * {@code P11PureSigKeyPairGeneratorSpi} and
 * {@code P11MLKEMKeyPairGeneratorSpi}: those exist only because the LOCAL
 * engine's own {@code C_GenerateKeyPair} templates genuinely differ per
 * key type ({@code CKA_SIGN}/{@code CKA_VERIFY} vs
 * {@code CKA_ENCAPSULATE}/{@code CKA_DECAPSULATE}). This remote surface's
 * {@code GenerateKeyPair} verb abstracts all of that server-side —
 * {@code remoting/core/src/verbs.rs::generate_key_pair} takes exactly
 * {@code (session, algorithm, cka_id, label)} regardless of algorithm
 * family — so one class genuinely suffices here.
 */
final class RemoteKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final GrpcTransport transport;
    private final String jcaAlgorithm;
    private final Algorithm protoAlgorithm;

    RemoteKeyPairGeneratorSpi(GrpcTransport transport, String jcaAlgorithm, Algorithm protoAlgorithm) {
        this.transport = transport;
        this.jcaAlgorithm = jcaAlgorithm;
        this.protoAlgorithm = protoAlgorithm;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        throw new UnsupportedOperationException(
            jcaAlgorithm + " has no keysize-int initializer; use the no-arg or spec-based initialize");
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        // Same tolerant-validation pattern as the local provider's own
        // KeyPairGeneratorSpi classes (P11PureSigKeyPairGeneratorSpi /
        // P11MLKEMKeyPairGeneratorSpi) — a real caller (JDK's own JSSE
        // among them, per plan §W0.1's live probe) can call this overload
        // even when the algorithm identity is already fixed by the
        // service name; a missing override fails OPEN (silent fallback
        // to a different provider) rather than surfacing an error.
        if (params instanceof NamedParameterSpec nps && !nps.getName().equals(jcaAlgorithm)) {
            throw new InvalidAlgorithmParameterException(
                "this KeyPairGenerator is bound to " + jcaAlgorithm + ", got " + nps.getName());
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] ckaId = new byte[8];
        new SecureRandom().nextBytes(ckaId);
        long[] handles = transport.generateKeyPair(protoAlgorithm, ckaId, "jca-remote-" + jcaAlgorithm);
        RemoteKey.Pub pub = new RemoteKey.Pub(handles[0], jcaAlgorithm);
        RemoteKey.Priv priv = new RemoteKey.Priv(handles[1], jcaAlgorithm);
        return new KeyPair(pub, priv);
    }
}
