package com.pqctoday.hsm.jce;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

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

    static class Priv implements PrivateKey, Destroyable {
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

    /**
     * EC-specific private key — adds {@link ECKey#getParams()} (curve
     * domain parameters only — field, curve equation, generator, order,
     * cofactor; all PUBLIC values, not secret) so JDK 27's own internal
     * {@code sun.security.ssl.DHasKEM} (the classical half of JEP 527's
     * hybrid TLS KEM groups) accepts this key at all: its
     * {@code paramsFromKey} does {@code k instanceof ECKey eckey; eckey.getParams()}
     * to identify which named curve it's dealing with — found live
     * (`Unsupported key` / `InvalidKeyException` deep inside JSSE's own
     * handshake code, plan §W6) when this class did not implement
     * {@code ECKey}, not assumed in advance. Deliberately implements only
     * {@code ECKey}, NOT the full {@code ECPrivateKey} — that would
     * additionally require {@code getS()}, the actual private scalar,
     * which this opaque-key design will never expose. Extracted from JDK
     * 27's real {@code DHasKEM.java} source (not guessed) that
     * {@code paramsFromKey}'s check is exactly {@code instanceof ECKey},
     * not {@code instanceof ECPrivateKey} — confirming this narrower
     * interface is sufficient.
     */
    static final class EcPriv extends Priv implements ECKey {
        private final ECParameterSpec ecParams;

        EcPriv(P11Library lib, long handle, ECParameterSpec ecParams) {
            super(lib, handle, "EC");
            this.ecParams = ecParams;
        }

        @Override public ECParameterSpec getParams() { return ecParams; }
    }

    static class Pub implements PublicKey, Destroyable {
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
     * EC-specific public key — adds full {@link ECPublicKey} (curve
     * params plus {@link ECPublicKey#getW()}, the point coordinates).
     * Unlike {@link EcPriv}, this can and does implement the complete
     * interface: a PUBLIC key's coordinates are not confidential, so
     * there is no opaque-key design tension here. Needed because JDK
     * 27's {@code DHasKEM.SerializePublicKey} does a hard
     * {@code ((ECPublicKey) k).getW()} cast on the client's own ephemeral
     * public key when building the TLS key_share extension — found live
     * alongside the {@link EcPriv} gap (plan §W6), same root cause.
     */
    static final class EcPub extends Pub implements ECPublicKey {
        private final ECParameterSpec ecParams;
        private final ECPoint w;

        EcPub(P11Library lib, long handle, byte[] spkiDer, ECParameterSpec ecParams, ECPoint w) {
            super(lib, handle, "EC", spkiDer);
            this.ecParams = ecParams;
            this.w = w;
        }

        @Override public ECParameterSpec getParams() { return ecParams; }
        @Override public ECPoint getW() { return w; }
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
