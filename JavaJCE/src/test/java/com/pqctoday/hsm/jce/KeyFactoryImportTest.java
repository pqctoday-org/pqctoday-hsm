package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The reverse cross-check flagged as a real gap in the ML-DSA commit: a
 * foreign-provider-generated key, imported and verified by OUR provider —
 * the direction that did NOT work before this KeyFactory existed.
 */
class KeyFactoryImportTest {

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    void importsJdkGeneratedMLDSAKeyAndVerifiesJdkSignature(String alg) throws Exception {
        // JDK's OWN software ML-DSA — no provider argument.
        KeyPair jdkKp = KeyPairGenerator.getInstance(alg).generateKeyPair();
        Signature jdkSigner = Signature.getInstance(alg);
        jdkSigner.initSign(jdkKp.getPrivate());
        byte[] msg = ("reverse cross-check " + alg).getBytes();
        jdkSigner.update(msg);
        byte[] jdkSig = jdkSigner.sign();

        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyFactory kf = KeyFactory.getInstance(alg, p);
        PublicKey imported = kf.generatePublic(new X509EncodedKeySpec(jdkKp.getPublic().getEncoded()));
        assertInstanceOf(P11Key.Pub.class, imported);

        Signature ourVerifier = Signature.getInstance(alg, p);
        ourVerifier.initVerify(imported);
        ourVerifier.update(msg);
        assertTrue(ourVerifier.verify(jdkSig), "our provider must verify a JDK-generated-and-signed " + alg + " signature");
    }

    @Test
    void importsBcGeneratedEd25519KeyAndVerifiesBcSignature() throws Exception {
        KeyPair jdkKp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Signature jdkSigner = Signature.getInstance("Ed25519");
        jdkSigner.initSign(jdkKp.getPrivate());
        byte[] msg = "reverse cross-check Ed25519".getBytes();
        jdkSigner.update(msg);
        byte[] jdkSig = jdkSigner.sign();

        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyFactory kf = KeyFactory.getInstance("Ed25519", p);
        PublicKey imported = kf.generatePublic(new X509EncodedKeySpec(jdkKp.getPublic().getEncoded()));

        Signature ourVerifier = Signature.getInstance("Ed25519", p);
        ourVerifier.initVerify(imported);
        ourVerifier.update(msg);
        assertTrue(ourVerifier.verify(jdkSig));
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
    void importsJdkGeneratedECKeyAndVerifiesJdkSignature(String curve) throws Exception {
        KeyPairGenerator jdkKpg = KeyPairGenerator.getInstance("EC");
        jdkKpg.initialize(new ECGenParameterSpec(curve));
        KeyPair jdkKp = jdkKpg.generateKeyPair();
        Signature jdkSigner = Signature.getInstance("SHA256withECDSA");
        jdkSigner.initSign(jdkKp.getPrivate());
        byte[] msg = ("reverse cross-check EC " + curve).getBytes();
        jdkSigner.update(msg);
        byte[] jdkSig = jdkSigner.sign();

        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyFactory kf = KeyFactory.getInstance("EC", p);
        PublicKey imported = kf.generatePublic(new X509EncodedKeySpec(jdkKp.getPublic().getEncoded()));

        Signature ourVerifier = Signature.getInstance("SHA256withECDSA", p);
        ourVerifier.initVerify(imported);
        ourVerifier.update(msg);
        assertTrue(ourVerifier.verify(jdkSig), "our provider must verify a JDK-generated-and-signed EC/" + curve + " signature");
    }

    @Test
    void importsJdkGeneratedRsaKeyAndVerifiesJdkSignature() throws Exception {
        KeyPairGenerator jdkKpg = KeyPairGenerator.getInstance("RSA");
        jdkKpg.initialize(2048);
        KeyPair jdkKp = jdkKpg.generateKeyPair();
        Signature jdkSigner = Signature.getInstance("SHA256withRSA");
        jdkSigner.initSign(jdkKp.getPrivate());
        byte[] msg = "reverse cross-check RSA".getBytes();
        jdkSigner.update(msg);
        byte[] jdkSig = jdkSigner.sign();

        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyFactory kf = KeyFactory.getInstance("RSA", p);
        PublicKey imported = kf.generatePublic(new X509EncodedKeySpec(jdkKp.getPublic().getEncoded()));

        Signature ourVerifier = Signature.getInstance("SHA256withRSA", p);
        ourVerifier.initVerify(imported);
        ourVerifier.update(msg);
        assertTrue(ourVerifier.verify(jdkSig));
    }

    @Test
    void privateKeyImportIsRefused() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertThrows(InvalidKeySpecException.class, () -> {
            KeyPair jdkKp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance("Ed25519", p);
            kf.generatePrivate(new PKCS8EncodedKeySpec(jdkKp.getPrivate().getEncoded()));
        }, "private key import must be refused unconditionally (FIPS 140-3 L3 posture)");
    }
}
