package com.pqctoday.hsm.jce;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

class SLHDSATest {

    @ParameterizedTest
    @ValueSource(strings = {
        "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F",
        "SLH-DSA-SHA2-192S", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHA2-192F", "SLH-DSA-SHAKE-192F",
        "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-256F",
    })
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

    // Expected sizes observed live during W2 development (see the
    // implementation plan's W2 SLH-DSA entry) and cross-checked against
    // the published FIPS 205 signature-size table — not guessed.
    @ParameterizedTest
    @ValueSource(strings = {
        "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F",
        "SLH-DSA-SHA2-192S", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHA2-192F", "SLH-DSA-SHAKE-192F",
        "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-256F",
    })
    void signatureSizeMatchesFips205(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();
        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        signer.update("size check".getBytes());
        byte[] sig = signer.sign();
        int expected = switch (alg) {
            case "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S" -> 7856;
            case "SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F" -> 17088;
            case "SLH-DSA-SHA2-192S", "SLH-DSA-SHAKE-192S" -> 16224;
            case "SLH-DSA-SHA2-192F", "SLH-DSA-SHAKE-192F" -> 35664;
            case "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-256S" -> 29792;
            case "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-256F" -> 49856;
            default -> throw new IllegalStateException(alg);
        };
        assertEquals(expected, sig.length, alg + " signature size must match FIPS 205");
    }
}
