package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import java.security.*;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Fixes the classic SunPKCS11 "0 keys" gap for this token (noted against
 * this exact engine in the sandbox's OpenSession.java/ListKeys.java
 * samples this session) — real enumeration via C_FindObjects, not an
 * empty result.
 */
class KeyStoreTest {

    @Test
    void enumeratesGeneratedKeysAndReturnsUsableKeyObjects() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();

        // Generate one key we can recognize among whatever else this
        // process/token already has (tests may run in any order and
        // share the token — don't assume an empty starting state).
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", p).generateKeyPair();
        long ourHandle = ((P11Key.Pub) kp.getPublic()).handle();

        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);

        List<String> aliases = Collections.list(ks.aliases());
        assertFalse(aliases.isEmpty(), "KeyStore must not report 0 keys against a token with real objects on it");
        assertTrue(ks.size() > 0);

        // Our just-generated public key's handle must appear somewhere
        // in the enumeration, wrapped in a usable P11Key.Pub.
        boolean found = false;
        for (String alias : aliases) {
            Key k = ks.getKey(alias, null);
            if (k instanceof P11Key.Pub pub && pub.handle() == ourHandle) {
                found = true;
                assertEquals("ML-DSA-65", pub.getAlgorithm());
                assertTrue(ks.isKeyEntry(alias));
                assertTrue(ks.containsAlias(alias));
            }
        }
        assertTrue(found, "the key just generated must be discoverable through the KeyStore");
    }

    @Test
    void writePathIsNotYetSupported() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", p).generateKeyPair();
        assertThrows(Exception.class, () -> ks.setKeyEntry("x", kp.getPrivate(), null, null),
            "write path is explicitly out of scope for W2 — must fail loudly, not silently no-op");
    }
}
