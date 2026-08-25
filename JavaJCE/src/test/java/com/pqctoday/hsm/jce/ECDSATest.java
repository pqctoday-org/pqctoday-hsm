package com.pqctoday.hsm.jce;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class ECDSATest {

    // curve, expected field size in bytes (coordinate size)
    @ParameterizedTest
    @CsvSource({
        "secp256r1, 32",
        "secp384r1, 48",
        "secp521r1, 66",
    })
    void curveOidProducesTheRequestedCurve(String curve, int fieldBytes) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", p);
        kpg.initialize(new ECGenParameterSpec(curve));
        KeyPair kp = kpg.generateKeyPair();

        // Empirical curve-identity check — critical for secp384r1, whose
        // CKA_EC_PARAMS bytes were derived by analogy to secp521r1's
        // proven encoding, not reused from already-proven code (see
        // P11ECKeyPairGeneratorSpi's javadoc). A wrong OID would produce
        // a key for the WRONG curve; decoding via JDK's own EC KeyFactory
        // and checking the field size catches that.
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPublicKey jdkPub = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        int actualFieldBytes = (jdkPub.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        assertEquals(fieldBytes, actualFieldBytes, curve + " must decode to the requested field size");
    }

    @ParameterizedTest
    @CsvSource({
        "secp256r1, SHA256withECDSA",
        "secp256r1, SHA384withECDSA",
        "secp256r1, SHA512withECDSA",
        "secp384r1, SHA256withECDSA",
        "secp384r1, SHA384withECDSA",
        "secp521r1, SHA512withECDSA",
    })
    void signVerifyRoundTripsAndInteropsWithJdkSunEC(String curve, String sigAlg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", p);
        kpg.initialize(new ECGenParameterSpec(curve));
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(sigAlg, p);
        signer.initSign(kp.getPrivate());
        byte[] msg = (curve + " " + sigAlg).getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(sigAlg, p);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig), "our own verify must accept our own signature");

        Signature verifier2 = Signature.getInstance(sigAlg, p);
        verifier2.initVerify(kp.getPublic());
        verifier2.update("tampered".getBytes());
        assertFalse(verifier2.verify(sig), "tampered message must be rejected");

        // The DER-format check this whole class exists for: JDK's own
        // SunEC must accept our exported SPKI and DER-encoded signature.
        // This is exactly the check that first caught the raw-r‖s-vs-DER
        // format mismatch during development (see P11ECDSASignatureSpi's
        // javadoc) — a self-consistency-only test would NOT catch it.
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey jdkPub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        Signature jdkVerifier = Signature.getInstance(sigAlg);
        jdkVerifier.initVerify(jdkPub);
        jdkVerifier.update(msg);
        assertTrue(jdkVerifier.verify(sig), "JDK SunEC must verify our DER-encoded, token-produced signature");
    }
}
