package com.pqctoday.hsm.jce;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Opaque handle-backed key objects (FIPS 140-3 L3 posture, plan §6.2): key
 * MATERIAL never crosses into the JVM. Only the PKCS#11 object handle is
 * held; every crypto operation routes back through the token via that
 * handle. Private keys are unconditionally opaque (getFormat()/getEncoded()
 * return null — there is no encoding to give out). Public keys are NOT
 * secret, so they export their real X.509 SubjectPublicKeyInfo DER,
 * read directly from the engine's own CKA_PUBLIC_KEY_INFO attribute
 * (PKCS#11 v3.2 §4.14) rather than hand-assembled here — the engine
 * already builds this correctly (see SoftHSM_keygen.cpp's spkiFromPkey
 * call for ML-DSA), so this class does not reinvent ASN.1 encoding.
 */
final class P11Key {
    private P11Key() {}

    static final class Priv implements PrivateKey {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient long handle;
        private final String algorithm;

        Priv(long handle, String algorithm) {
            this.handle = handle;
            this.algorithm = algorithm;
        }

        long handle() { return handle; }
        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }
    }

    static final class Pub implements PublicKey {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient long handle;
        private final String algorithm;
        private final byte[] spkiDer;

        Pub(long handle, String algorithm, byte[] spkiDer) {
            this.handle = handle;
            this.algorithm = algorithm;
            this.spkiDer = spkiDer;
        }

        long handle() { return handle; }
        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return "X.509"; }
        @Override public byte[] getEncoded() { return spkiDer.clone(); }
    }

    /**
     * Opaque, handle-backed secret key (AES, HMAC generic-secret, etc.) —
     * same non-exportable design as Priv above (CKA_SENSITIVE=TRUE,
     * CKA_EXTRACTABLE=FALSE on the token side; getEncoded()==null here).
     * The one deliberate exception to this pattern in the whole module
     * remains the KEM/ECDH shared secret (see P11MLKEMSpi/P11ECDHKeyAgreementSpi),
     * which is a plain javax.crypto.spec.SecretKeySpec, not this class.
     */
    static final class Secret implements SecretKey {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient long handle;
        private final String algorithm;

        Secret(long handle, String algorithm) {
            this.handle = handle;
            this.algorithm = algorithm;
        }

        long handle() { return handle; }
        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }
    }
}
