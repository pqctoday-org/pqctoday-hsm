package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.*;

/**
 * P11Key.Priv/Pub/Secret implementing javax.security.auth.Destroyable
 * (§6.5) — real destruction (C_DestroyObject on the underlying PKCS#11
 * object, not just a Java-side flag), idempotency, and the
 * IllegalStateException Destroyable's own javadoc calls for on later use.
 */
class DestroyableTest {

    @Test
    void destroyRemovesTheUnderlyingTokenObjectAndIsIdempotent() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
        KeyPair kp = kpg.generateKeyPair();
        P11Key.Priv priv = (P11Key.Priv) kp.getPrivate();
        long handle = priv.handle();

        assertFalse(priv.isDestroyed());
        assertDoesNotThrow(priv::destroy);
        assertTrue(priv.isDestroyed());

        // Real destruction, not just a flag: the same handle is genuinely
        // gone from the token now — a second, independent destroyObject
        // call against it must fail natively (CKR_OBJECT_HANDLE_INVALID),
        // proving C_DestroyObject actually ran the first time rather than
        // this test just trusting the isDestroyed() flag.
        assertThrows(RuntimeException.class, () -> p.lib.destroyObject(handle),
            "the handle must already be gone from the token after destroy()");

        // Idempotent: a second destroy() call is a silent no-op, not an
        // attempt to destroy an already-gone handle again.
        assertDoesNotThrow(priv::destroy);
        assertTrue(priv.isDestroyed());
    }

    @Test
    void usingAHandleAfterDestroyThrowsIllegalStateException() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
        KeyPair kp = kpg.generateKeyPair();
        P11Key.Priv priv = (P11Key.Priv) kp.getPrivate();

        assertDoesNotThrow(priv::destroy);
        assertThrows(IllegalStateException.class, priv::handle,
            "Destroyable's own contract: subsequent use of a destroyed object's sensitive accessor must throw");
    }

    @Test
    void metadataAccessorsStayUsableAfterDestroy() throws Exception {
        // getAlgorithm()/getFormat()/getEncoded() are harmless metadata,
        // not operations that touch the token — Destroyable's javadoc
        // says "certain methods" throw post-destroy, not all of them.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
        KeyPair kp = kpg.generateKeyPair();
        P11Key.Pub pub = (P11Key.Pub) kp.getPublic();

        assertDoesNotThrow(pub::destroy);
        assertEquals("Ed25519", pub.getAlgorithm());
        assertEquals("X.509", pub.getFormat());
        assertNotNull(pub.getEncoded());
    }

    @Test
    void signingWithADestroyedPrivateKeyFails() throws Exception {
        // engineInitSign reads the handle immediately (signKey = p.handle()),
        // so the failure surfaces at initSign() itself, not at a later
        // sign() call — handle()'s post-destroy guard doing its job as
        // early as possible rather than deferring to a native round trip.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
        KeyPair kp = kpg.generateKeyPair();
        P11Key.Priv priv = (P11Key.Priv) kp.getPrivate();
        priv.destroy();

        Signature sig = Signature.getInstance("Ed25519", p);
        assertThrows(IllegalStateException.class, () -> sig.initSign(priv),
            "signing must fail once the underlying key handle has been destroyed");
    }
}
