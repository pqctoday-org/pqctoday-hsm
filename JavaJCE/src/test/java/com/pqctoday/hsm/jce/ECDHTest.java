package com.pqctoday.hsm.jce;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class ECDHTest {

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
    void twoOfOurOwnKeysAgreeOnTheSameSecret(String curve) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", p);
        kpg.initialize(new ECGenParameterSpec(curve));
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        KeyAgreement aliceKa = KeyAgreement.getInstance("ECDH", p);
        aliceKa.init(alice.getPrivate());
        aliceKa.doPhase(bob.getPublic(), true);
        byte[] aliceSecret = aliceKa.generateSecret();

        KeyAgreement bobKa = KeyAgreement.getInstance("ECDH", p);
        bobKa.init(bob.getPrivate());
        bobKa.doPhase(alice.getPublic(), true);
        byte[] bobSecret = bobKa.generateSecret();

        assertArrayEquals(aliceSecret, bobSecret, "both parties must derive the same ECDH secret for " + curve);
        assertTrue(aliceSecret.length > 0);
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
    void crossVerifyAgainstJdkSunEC_oursInitiatesJdkResponds(String curve) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator ourKpg = KeyPairGenerator.getInstance("EC", p);
        ourKpg.initialize(new ECGenParameterSpec(curve));
        KeyPair ourKp = ourKpg.generateKeyPair();

        KeyPairGenerator jdkKpg = KeyPairGenerator.getInstance("EC");
        jdkKpg.initialize(new ECGenParameterSpec(curve));
        KeyPair jdkKp = jdkKpg.generateKeyPair();

        // We derive using OUR private key + JDK's public key.
        KeyAgreement ourKa = KeyAgreement.getInstance("ECDH", p);
        ourKa.init(ourKp.getPrivate());
        ourKa.doPhase(jdkKp.getPublic(), true);
        byte[] ourSecret = ourKa.generateSecret();

        // JDK derives using ITS private key + OUR public key (imported
        // via JDK's own EC KeyFactory — standard X.509 SPKI, no special
        // handling needed on JDK's side).
        KeyFactory jdkKf = KeyFactory.getInstance("EC");
        PublicKey ourPubViaJdk = jdkKf.generatePublic(new X509EncodedKeySpec(ourKp.getPublic().getEncoded()));
        KeyAgreement jdkKa = KeyAgreement.getInstance("ECDH");
        jdkKa.init(jdkKp.getPrivate());
        jdkKa.doPhase(ourPubViaJdk, true);
        byte[] jdkSecret = jdkKa.generateSecret();

        assertArrayEquals(ourSecret, jdkSecret,
            "our ECDH and JDK's SunEC ECDH must agree on the same secret for " + curve);
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
    void acceptsForeignPeerKeyDirectlyWithoutExplicitImport(String curve) throws Exception {
        // engineDoPhase given a raw java.security.PublicKey (not a
        // P11Key.Pub) must import it on the fly — exercises
        // P11ECDHKeyAgreementSpi's rawPointOf() foreign-key branch
        // directly, not just via an explicit KeyFactory.generatePublic call.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator ourKpg = KeyPairGenerator.getInstance("EC", p);
        ourKpg.initialize(new ECGenParameterSpec(curve));
        KeyPair ourKp = ourKpg.generateKeyPair();

        KeyPairGenerator jdkKpg = KeyPairGenerator.getInstance("EC");
        jdkKpg.initialize(new ECGenParameterSpec(curve));
        KeyPair jdkKp = jdkKpg.generateKeyPair();

        KeyAgreement ourKa = KeyAgreement.getInstance("ECDH", p);
        ourKa.init(ourKp.getPrivate());
        ourKa.doPhase(jdkKp.getPublic(), true); // raw JDK PublicKey, no pre-import
        SecretKey secret = ourKa.generateSecret("AES");
        assertNotNull(secret);
        assertTrue(secret.getEncoded().length > 0);
    }
}
