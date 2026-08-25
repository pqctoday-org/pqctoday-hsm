package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class RSATest {

    @ParameterizedTest
    @ValueSource(ints = {2048, 3072, 4096})
    void keygenAndPkcs1v15InteropsWithJdkSunRsaSign(int bits) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(bits);
        KeyPair kp = kpg.generateKeyPair();
        assertEquals("X.509", kp.getPublic().getFormat());
        assertNull(kp.getPrivate().getEncoded());

        Signature signer = Signature.getInstance("SHA256withRSA", p);
        signer.initSign(kp.getPrivate());
        byte[] msg = ("RSA-" + bits + " PKCS#1 v1.5").getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();
        assertEquals(bits / 8, sig.length, "PKCS#1 v1.5 signature must be exactly one modulus-size block");

        Signature verifier = Signature.getInstance("SHA256withRSA", p);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig));

        Signature verifier2 = Signature.getInstance("SHA256withRSA", p);
        verifier2.initVerify(kp.getPublic());
        verifier2.update("tampered".getBytes());
        assertFalse(verifier2.verify(sig));

        // JDK's own SunRsaSign must accept our SPKI export and verify our
        // token-produced signature — the same class of check that caught
        // the ECDSA raw-vs-DER format mismatch; here it confirms PKCS#1
        // v1.5's raw-modulus-block format needed no conversion.
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey jdkPub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        Signature jdkVerifier = Signature.getInstance("SHA256withRSA");
        jdkVerifier.initVerify(jdkPub);
        jdkVerifier.update(msg);
        assertTrue(jdkVerifier.verify(sig), "JDK SunRsaSign must verify our token-produced PKCS#1 v1.5 signature");
    }

    @ParameterizedTest
    @CsvSource({ "SHA256withRSA", "SHA384withRSA", "SHA512withRSA" })
    void allApprovedDigestsRoundTrip(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        signer.update("digest coverage".getBytes());
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(alg, p);
        verifier.initVerify(kp.getPublic());
        verifier.update("digest coverage".getBytes());
        assertTrue(verifier.verify(sig));
    }

    @Test
    void pssInteropsWithJdkSunRsaSign() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        PSSParameterSpec pssSpec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC);

        Signature signer = Signature.getInstance("RSASSA-PSS", p);
        signer.setParameter(pssSpec);
        signer.initSign(kp.getPrivate());
        byte[] msg = "RSASSA-PSS interop".getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("RSASSA-PSS", p);
        verifier.setParameter(pssSpec);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig));

        Signature verifier2 = Signature.getInstance("RSASSA-PSS", p);
        verifier2.setParameter(pssSpec);
        verifier2.initVerify(kp.getPublic());
        verifier2.update("tampered".getBytes());
        assertFalse(verifier2.verify(sig));

        // Cross-verify against JDK's own SunRsaSign RSASSA-PSS.
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey jdkPub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        Signature jdkVerifier = Signature.getInstance("RSASSA-PSS");
        jdkVerifier.setParameter(pssSpec);
        jdkVerifier.initVerify(jdkPub);
        jdkVerifier.update(msg);
        assertTrue(jdkVerifier.verify(sig), "JDK SunRsaSign must verify our token-produced PSS signature");
    }

    @Test
    void pssRejectsSha1() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertThrows(InvalidAlgorithmParameterException.class, () -> {
            Signature signer = Signature.getInstance("RSASSA-PSS", p);
            signer.setParameter(new PSSParameterSpec(
                "SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1));
        }, "SHA-1 PSS must be rejected by this provider's FIPS 140-3 L3 policy");
    }

    @Test
    void smallModulusRejected() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertThrows(InvalidParameterException.class, () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
            kpg.initialize(1024);
        });
    }
}
