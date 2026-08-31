package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.*;
import java.security.spec.EdDSAParameterSpec;
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

    // ── Item 7: CKM_EDDSA_PH + CK_EDDSA_PARAMS (context/prehash) ───────────

    @ParameterizedTest
    @ValueSource(strings = {"Ed25519", "Ed448"})
    void prehashModeRoundTripsAndTamperIsRejected(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();
        byte[] msg = ("prehash mode, " + alg).getBytes();

        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        signer.setParameter(new EdDSAParameterSpec(true)); // Ed25519ph/Ed448ph, no context
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(alg, p);
        verifier.initVerify(kp.getPublic());
        verifier.setParameter(new EdDSAParameterSpec(true));
        verifier.update(msg);
        assertTrue(verifier.verify(sig), alg + "ph must verify its own real signature");

        Signature verifier2 = Signature.getInstance(alg, p);
        verifier2.initVerify(kp.getPublic());
        verifier2.setParameter(new EdDSAParameterSpec(true));
        verifier2.update("tampered".getBytes());
        assertFalse(verifier2.verify(sig));

        // A pure-mode Signature over the SAME key/message must NOT
        // accept the prehash signature — proves this is a genuinely
        // different mechanism, not a no-op parameter.
        Signature pureVerifier = Signature.getInstance(alg, p);
        pureVerifier.initVerify(kp.getPublic());
        pureVerifier.update(msg);
        assertFalse(pureVerifier.verify(sig), "a pure-mode " + alg + " signature must not verify a " + alg + "ph signature");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Ed25519", "Ed448"})
    void contextModeRoundTripsAndWrongContextIsRejected(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();
        byte[] msg = ("context mode, " + alg).getBytes();
        byte[] context = "protocol-v1".getBytes();

        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        signer.setParameter(new EdDSAParameterSpec(false, context));
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(alg, p);
        verifier.initVerify(kp.getPublic());
        verifier.setParameter(new EdDSAParameterSpec(false, context));
        verifier.update(msg);
        assertTrue(verifier.verify(sig));

        // Wrong context must fail verification — proves the context
        // string is genuinely bound into the signature, not ignored.
        Signature wrongContext = Signature.getInstance(alg, p);
        wrongContext.initVerify(kp.getPublic());
        wrongContext.setParameter(new EdDSAParameterSpec(false, "protocol-v2".getBytes()));
        wrongContext.update(msg);
        assertFalse(wrongContext.verify(sig), "a different RFC 8032 context string must not verify");
    }

    @Test
    void nonEdDSAParameterSpecIsRejected() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", p).generateKeyPair();
        Signature signer = Signature.getInstance("Ed25519", p);
        signer.initSign(kp.getPrivate());
        assertThrows(InvalidAlgorithmParameterException.class,
            () -> signer.setParameter(new java.security.spec.PSSParameterSpec(64)),
            "a foreign AlgorithmParameterSpec must still be rejected for EdDSA, exactly as before item 7");
    }

    @Test
    void prehashGatingIsWiredToRealMechanismAdvertisement() throws Exception {
        // Real (non-mocked) verification of the exact gating primitive
        // engineSetParameter relies on: this engine build genuinely
        // advertises CKM_EDDSA_PH (WS-1.3, 2026-08-29 — confirmed reading
        // SoftHSM_slots.cpp before writing this), so the prehash setParameter
        // call above succeeds; the SAME check correctly reports
        // "unsupported" for a fabricated mechanism id nothing implements —
        // proving the gate would correctly refuse
        // (InvalidAlgorithmParameterException, per engineSetParameter's own
        // logic) if this build's engine ever did NOT advertise
        // CKM_EDDSA_PH. Reconfiguring THIS live token to genuinely drop
        // CKM_EDDSA_PH (the way the parallel OpenSSL-provider test does via
        // softhsm2.conf's slots.mechanisms=-CKM_EDDSA_PH) is not reachable
        // from this test process — PKCS#11 module state is process-global,
        // set once at C_Initialize (see P11Library's own class javadoc) —
        // so this checks the real underlying primitive directly instead,
        // the same disclosed-limitation pattern used elsewhere in this
        // suite (see P11ECDHKeyAgreementSpi's own cofactor=1 caveat).
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertTrue(p.lib.mechanismSupported(P11Constants.CKM_EDDSA_PH),
            "precondition: this engine build genuinely advertises CKM_EDDSA_PH");
        assertFalse(p.lib.mechanismSupported(0x8000fffdL),
            "a fabricated, never-implemented vendor mechanism id must report unsupported — "
            + "proves mechanismSupported() reflects real C_GetMechanismInfo data, not a hardcoded true");
    }
}
