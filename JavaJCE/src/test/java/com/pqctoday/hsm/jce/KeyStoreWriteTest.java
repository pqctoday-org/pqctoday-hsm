package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KeyStore write path (setEntry/deleteEntry, completing W4). The
 * meaningful test here is TRUE cross-session persistence — a session
 * object (CKA_TOKEN=false, what every generate/derive call in this
 * module produces) is destroyed when its session closes, but a token
 * object (CKA_TOKEN=true, what setKeyEntry promotes to via
 * C_CopyObject) survives. Proven by actually closing the first
 * provider's session and opening a completely fresh one, not just
 * re-reading within the same session (which would pass even for a
 * session object still alive from earlier in the same test).
 */
class KeyStoreWriteTest {

    @Test
    void setEntryPersistsAcrossASessionCloseAndReopen() throws Exception {
        String alias = "test-persist-" + System.nanoTime();

        SoftHSMv3Provider p1 = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p1).generateKey();
        KeyStore ks1 = KeyStore.getInstance("PKCS11-SoftHSMv3", p1);
        ks1.load(null, null);
        assertFalse(ks1.containsAlias(alias));
        ks1.setKeyEntry(alias, key, null, null);
        assertTrue(ks1.containsAlias(alias), "alias must be visible immediately after setKeyEntry");

        // Encrypt with the ORIGINAL key while p1's session is still open —
        // this must happen before closing it below.
        var enc = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", p1);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        byte[] iv = enc.getIV();
        byte[] ct = enc.doFinal("cross-session check".getBytes());

        p1.lib.close(); // ends THIS session — a session-scoped object would vanish here

        SoftHSMv3Provider p2 = new SoftHSMv3Provider(); // a completely fresh session
        KeyStore ks2 = KeyStore.getInstance("PKCS11-SoftHSMv3", p2);
        ks2.load(null, null);
        assertTrue(ks2.containsAlias(alias),
            "the entry must survive into a brand-new session — proving it was truly promoted to a token object, "
            + "not left as a session object that merely hadn't been cleaned up yet");

        SecretKey recovered = (SecretKey) ks2.getKey(alias, null);
        assertEquals("AES", recovered.getAlgorithm());
        assertNull(recovered.getEncoded(), "recovered key must still be opaque");

        // Prove it's actually usable, not just present — decrypt (in the
        // brand-new session) what the original key encrypted (in the old one).
        var dec = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", p2);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, recovered, new javax.crypto.spec.GCMParameterSpec(128, iv));
        assertArrayEquals("cross-session check".getBytes(), dec.doFinal(ct));

        ks2.deleteEntry(alias);
        assertFalse(ks2.containsAlias(alias));
    }

    @Test
    void deleteEntryRemovesTheKey() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        String alias = "delete-me-" + System.nanoTime();
        ks.setKeyEntry(alias, key, null, null);
        assertTrue(ks.containsAlias(alias));

        ks.deleteEntry(alias);
        assertFalse(ks.containsAlias(alias));
        assertNull(ks.getKey(alias, null));
    }

    @Test
    void deleteEntryOnAnUnknownAliasThrows() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        assertThrows(KeyStoreException.class, () -> ks.deleteEntry("no-such-alias"));
    }

    @Test
    void setEntryRejectsANonEmptyCertificateChain() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        Certificate fakeCert = new Certificate("X.509") {
            @Override public byte[] getEncoded() { return new byte[0]; }
            @Override public void verify(java.security.PublicKey key) {}
            @Override public void verify(java.security.PublicKey key, String sigProvider) {}
            @Override public String toString() { return "fake"; }
            @Override public java.security.PublicKey getPublicKey() { return null; }
        };
        assertThrows(KeyStoreException.class,
            () -> ks.setKeyEntry("alias", key, null, new Certificate[]{ fakeCert }));
    }

    @Test
    void setEntryRejectsAForeignKey() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        SecretKey foreign = new SecretKeySpec(raw, "AES");
        assertThrows(KeyStoreException.class, () -> ks.setKeyEntry("alias", foreign, null, null),
            "this KeyStore must refuse to import foreign key material, same policy as private-key import");
    }

    @Test
    void byteArrayFormOfSetKeyEntryIsRejected() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        assertThrows(KeyStoreException.class,
            () -> ks.setKeyEntry("alias", new byte[]{1, 2, 3}, null));
    }

    @Test
    void setEntryWorksForAPublicKeyToo() throws Exception {
        // A PublicKey, not a PrivateKey: java.security.KeyStore's own
        // public setKeyEntry(String, Key, char[], Certificate[]) has a
        // JDK-level precondition ("Private key must be accompanied by
        // certificate chain") that runs BEFORE engineSetKeyEntry is ever
        // reached — confirmed live, not assumed. That JDK requirement
        // directly conflicts with this KeyStore's own honest "never
        // stores or returns certificates" design (see the class
        // javadoc), so storing a PrivateKey via the STANDARD public API
        // is genuinely unsupported here, by design — see
        // privateKeyEntryViaStandardApiIsUnsupportedWithoutAChain below
        // for that boundary as an explicit, tested limitation rather
        // than a silently-avoided gap. A PublicKey has no such JDK-level
        // chain requirement, so it still exercises the same
        // P11Key.Pub-handling branch in engineSetKeyEntry.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        var kpg = java.security.KeyPairGenerator.getInstance("Ed25519", p);
        var kp = kpg.generateKeyPair();
        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        String alias = "ed25519-pub-" + System.nanoTime();
        ks.setKeyEntry(alias, kp.getPublic(), null, null);
        assertTrue(ks.containsAlias(alias));
        assertEquals("Ed25519", ks.getKey(alias, null).getAlgorithm());
        ks.deleteEntry(alias);
    }

    @Test
    void privateKeyEntryViaStandardApiIsUnsupportedWithoutAChain() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        var kpg = java.security.KeyPairGenerator.getInstance("Ed25519", p);
        var kp = kpg.generateKeyPair();
        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        assertThrows(IllegalArgumentException.class,
            () -> ks.setKeyEntry("alias", kp.getPrivate(), null, null),
            "java.security.KeyStore itself refuses a PrivateKey with no chain, before this SPI is even reached — "
            + "this provider cannot satisfy that requirement since it never stores certificates");
    }
}
