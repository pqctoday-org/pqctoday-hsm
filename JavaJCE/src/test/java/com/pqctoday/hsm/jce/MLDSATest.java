package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class MLDSATest {

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    void signVerifyRoundTripsAndTamperIsRejected(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();

        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        byte[] msg = ("round trip " + alg).getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(alg, p);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig));

        Signature verifier2 = Signature.getInstance(alg, p);
        verifier2.initVerify(kp.getPublic());
        verifier2.update("tampered".getBytes());
        assertFalse(verifier2.verify(sig));
    }

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    void signatureSizeMatchesFips204(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();
        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        signer.update("size check".getBytes());
        byte[] sig = signer.sign();
        int expected = switch (alg) {
            case "ML-DSA-44" -> 2420;
            case "ML-DSA-65" -> 3309;
            case "ML-DSA-87" -> 4627;
            default -> throw new IllegalStateException();
        };
        assertEquals(expected, sig.length, alg + " signature size must match FIPS 204");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    void publicKeyExportInteropsWithJdkSoftwareImplementation(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();
        assertEquals("X.509", kp.getPublic().getFormat());

        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        byte[] msg = "interop".getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();

        // JDK's OWN software ML-DSA (no provider argument) must accept our
        // SPKI export and verify our signature — proves the export is
        // standards-correct, not just self-consistent with our own KeyFactory.
        KeyFactory kf = KeyFactory.getInstance(alg);
        PublicKey jdkPub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        Signature jdkVerifier = Signature.getInstance(alg);
        jdkVerifier.initVerify(jdkPub);
        jdkVerifier.update(msg);
        assertTrue(jdkVerifier.verify(sig), "JDK software ML-DSA must verify our token-produced signature");
    }

    @Test
    void privateKeyNeverExportsMaterial() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        PrivateKey priv = assertDoesNotThrow(() ->
            KeyPairGenerator.getInstance("ML-DSA-65", p).generateKeyPair().getPrivate());
        assertNull(priv.getFormat());
        assertNull(priv.getEncoded());
    }
}
