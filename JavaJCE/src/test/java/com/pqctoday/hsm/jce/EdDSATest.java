package com.pqctoday.hsm.jce;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class EdDSATest {

    // alg, expected SPKI length (RFC 8410), expected signature length (RFC 8032)
    @ParameterizedTest
    @CsvSource({
        "Ed25519, 44, 64",
        "Ed448,   69, 114",
    })
    void signVerifyInteropsWithJdkSunEC(String alg, int spkiLen, int sigLen) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();
        assertEquals("X.509", kp.getPublic().getFormat());
        assertEquals(spkiLen, kp.getPublic().getEncoded().length);
        assertNull(kp.getPrivate().getEncoded());

        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        byte[] msg = ("interop " + alg).getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();
        assertEquals(sigLen, sig.length);

        Signature verifier = Signature.getInstance(alg, p);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig));

        Signature verifier2 = Signature.getInstance(alg, p);
        verifier2.initVerify(kp.getPublic());
        verifier2.update("tampered".getBytes());
        assertFalse(verifier2.verify(sig));

        // JDK's own SunEC Ed25519/Ed448 (native since JEP 339) must accept
        // our SPKI export and verify our signature.
        KeyFactory kf = KeyFactory.getInstance(alg);
        PublicKey jdkPub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        Signature jdkVerifier = Signature.getInstance(alg);
        jdkVerifier.initVerify(jdkPub);
        jdkVerifier.update(msg);
        assertTrue(jdkVerifier.verify(sig), "JDK SunEC must verify our token-produced " + alg + " signature");
    }
}
