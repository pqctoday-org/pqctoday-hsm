package com.pqctoday.hsm.jce;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
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
 *
 * All three inner classes implement {@link Destroyable} (§6.5's
 * zeroization posture): since these objects hold no plaintext key
 * material in the JVM at all — the whole point of the opaque-handle
 * design — the only meaningful "destroy" is destroying the underlying
 * PKCS#11 object itself via {@code C_DestroyObject}, not scrubbing a
 * Java-heap byte[] that was never there. destroy() is idempotent (a
 * second call is a silent no-op, matching real-world Destroyable
 * implementations rather than the interface's bare minimum contract);
 * handle() throws IllegalStateException after destroy(), per
 * Destroyable's own javadoc ("subsequent calls to certain methods...
 * will result in an IllegalStateException"), since using a destroyed
 * object's handle in a native call would otherwise fail with an opaque
 * PKCS#11 error instead of a clear Java exception. getAlgorithm()/
 * getFormat()/getEncoded() stay usable post-destroy — harmless metadata
 * accessors, not operations that touch the token.
 */
final class P11Key {
    private P11Key() {}

    static final class Priv implements PrivateKey, Destroyable {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient P11Library lib;
        private final transient long handle;
        private final String algorithm;
        private transient volatile boolean destroyed;

        Priv(P11Library lib, long handle, String algorithm) {
            this.lib = lib;
            this.handle = handle;
            this.algorithm = algorithm;
        }

        long handle() {
            if (destroyed) throw new IllegalStateException("this key has been destroyed");
            return handle;
        }
        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }

        @Override
        public void destroy() throws DestroyFailedException {
            if (destroyed) return;
            try {
                lib.destroyObject(handle);
            } catch (RuntimeException e) {
                throw (DestroyFailedException) new DestroyFailedException(e.getMessage()).initCause(e);
            } finally {
                destroyed = true;
            }
        }
        @Override public boolean isDestroyed() { return destroyed; }
    }

    static final class Pub implements PublicKey, Destroyable {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient P11Library lib;
        private final transient long handle;
        private final String algorithm;
        private final byte[] spkiDer;
        private transient volatile boolean destroyed;

        Pub(P11Library lib, long handle, String algorithm, byte[] spkiDer) {
            this.lib = lib;
            this.handle = handle;
            this.algorithm = algorithm;
            this.spkiDer = spkiDer;
        }

        long handle() {
            if (destroyed) throw new IllegalStateException("this key has been destroyed");
            return handle;
        }
        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return "X.509"; }
        @Override public byte[] getEncoded() { return spkiDer.clone(); }

        @Override
        public void destroy() throws DestroyFailedException {
            if (destroyed) return;
            try {
                lib.destroyObject(handle);
            } catch (RuntimeException e) {
                throw (DestroyFailedException) new DestroyFailedException(e.getMessage()).initCause(e);
            } finally {
                destroyed = true;
            }
        }
        @Override public boolean isDestroyed() { return destroyed; }
    }

    /**
     * Opaque, handle-backed secret key (AES, HMAC generic-secret, etc.) —
     * same non-exportable design as Priv above (CKA_SENSITIVE=TRUE,
     * CKA_EXTRACTABLE=FALSE on the token side; getEncoded()==null here).
     * The one deliberate exception to this pattern in the whole module
     * remains the KEM/ECDH shared secret (see P11MLKEMSpi/P11ECDHKeyAgreementSpi),
     * which is a plain javax.crypto.spec.SecretKeySpec, not this class.
     */
    static final class Secret implements SecretKey, Destroyable {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient P11Library lib;
        private final transient long handle;
        private final String algorithm;
        private transient volatile boolean destroyed;

        Secret(P11Library lib, long handle, String algorithm) {
            this.lib = lib;
            this.handle = handle;
            this.algorithm = algorithm;
        }

        long handle() {
            if (destroyed) throw new IllegalStateException("this key has been destroyed");
            return handle;
        }
        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }

        @Override
        public void destroy() throws DestroyFailedException {
            if (destroyed) return;
            try {
                lib.destroyObject(handle);
            } catch (RuntimeException e) {
                throw (DestroyFailedException) new DestroyFailedException(e.getMessage()).initCause(e);
            } finally {
                destroyed = true;
            }
        }
        @Override public boolean isDestroyed() { return destroyed; }
    }
}
