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

    // ── Item 6: CKM_ML_DSA_EXTERNAL_MU ─────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    void externalMuSignVerifyRoundTripsAndTamperIsRejected(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();
        byte[] mu = new byte[64]; // FIPS 204 Eq.(2): a fixed 64-byte SHAKE256 output
        new SecureRandom().nextBytes(mu);

        Signature signer = Signature.getInstance(alg + "-ExternalMu", p);
        signer.initSign(kp.getPrivate());
        signer.update(mu);
        byte[] sig = signer.sign();
        assertEquals(alg.equals("ML-DSA-44") ? 2420 : alg.equals("ML-DSA-65") ? 3309 : 4627, sig.length,
            alg + "-ExternalMu signature size must match plain " + alg + "'s FIPS 204 size");

        Signature verifier = Signature.getInstance(alg + "-ExternalMu", p);
        verifier.initVerify(kp.getPublic());
        verifier.update(mu);
        assertTrue(verifier.verify(sig));

        Signature verifier2 = Signature.getInstance(alg + "-ExternalMu", p);
        verifier2.initVerify(kp.getPublic());
        byte[] tamperedMu = mu.clone();
        tamperedMu[0] ^= 0x01;
        verifier2.update(tamperedMu);
        assertFalse(verifier2.verify(sig));
    }

    @Test
    void externalMuRejectsAMuBufferThatIsNotExactly64Bytes() throws Exception {
        // OSSLMLDSA.cpp's own real length check ("CKM_ML_DSA_EXTERNAL_MU
        // requires exactly %u bytes of mu") — a genuine end-to-end
        // exercise of the live engine's validation, not a Java-side guess.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", p).generateKeyPair();

        Signature signer = Signature.getInstance("ML-DSA-65-ExternalMu", p);
        signer.initSign(kp.getPrivate());
        signer.update(new byte[63]);
        assertThrows(SignatureException.class, signer::sign,
            "the engine must reject a 63-byte buffer under CKM_ML_DSA_EXTERNAL_MU (exactly 64 bytes required)");
    }

    @Test
    void externalMuIsGatedOnRealMechanismAdvertisement() throws Exception {
        // Real (non-mocked) verification of the exact gating primitive
        // SoftHSMv3Provider#registerMLDSAExternalMu's Service#newInstance
        // relies on: this engine build genuinely advertises
        // CKM_ML_DSA_EXTERNAL_MU (so "ML-DSA-65-ExternalMu" resolves), and
        // the SAME check correctly reports "unsupported" for a fabricated
        // mechanism id nothing implements — proving the gate would
        // correctly refuse (NoSuchAlgorithmException, via
        // registerMLDSAExternalMu's own check) if this build's engine
        // ever did NOT advertise this still-only-draft PKCS#11 v3.3
        // mechanism, which cannot be simulated on this live token/build
        // (see P11ECDHKeyAgreementSpi's own disclosed-limitation pattern
        // for the same class of practical constraint).
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertNotNull(Signature.getInstance("ML-DSA-65-ExternalMu", p),
            "precondition: this engine build genuinely advertises CKM_ML_DSA_EXTERNAL_MU");
        assertTrue(p.lib.mechanismSupported(P11Constants.CKM_ML_DSA_EXTERNAL_MU));
        assertFalse(p.lib.mechanismSupported(0x8000fffdL),
            "a fabricated, never-implemented vendor mechanism id must report unsupported — "
            + "proves mechanismSupported() reflects real C_GetMechanismInfo data, not a hardcoded true");
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
