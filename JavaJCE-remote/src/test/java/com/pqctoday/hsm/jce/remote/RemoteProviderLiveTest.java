package com.pqctoday.hsm.jce.remote;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Live, run-it-for-real regression suite against the actual {@code pqc-grpc}
 * container (E4, "full coverage" — plan §7 WS-E) — same discipline as
 * {@code remoting/acceptance/tests/three_way_parity.rs} on the Rust side:
 * every case exercises a genuine network round trip, never a mock. Requires
 * the sandbox environment ({@code pqc-grpc} reachable, real mTLS material at
 * {@code /admin-certs}) — same precondition {@code LiveSmokeMain} already
 * confirmed live (2026-08-25) before this class was written from its
 * observed, not guessed, output.
 */
final class RemoteProviderLiveTest {
    private static SoftHSMv3RemoteProvider provider;

    @BeforeAll
    static void openProvider() {
        provider = new SoftHSMv3RemoteProvider();
        Security.addProvider(provider);
    }

    @AfterAll
    static void closeProvider() {
        if (provider != null) {
            Security.removeProvider(provider.getName());
            provider.close();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    void signVerifyDetectsTamper(String algo) throws Exception {
        KeyPair kp = generateKeyPair(algo);
        byte[] msg = ("live regression message for " + algo).getBytes();

        Signature signer = Signature.getInstance(algo, provider);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(algo, provider);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig), "genuine signature must verify");

        Signature tamperVerifier = Signature.getInstance(algo, provider);
        tamperVerifier.initVerify(kp.getPublic());
        tamperVerifier.update("a different message entirely".getBytes());
        assertFalse(tamperVerifier.verify(sig), "tampered message must not verify");
    }

    // ── FIPS 204 external-µ mode (added 2026-08-31: SignRequest/
    // VerifyRequest.external_mu on the wire, "ML-DSA-{44,65,87}-ExternalMu"
    // Signature service names on this provider) ────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    void externalMuSignVerifyRoundTripsAndTamperIsRejected(String alg) throws Exception {
        KeyPair kp = generateKeyPair(alg);
        byte[] mu = new byte[64]; // FIPS 204 Eq.(2): a fixed 64-byte SHAKE256 output
        new SecureRandom().nextBytes(mu);

        Signature signer = Signature.getInstance(alg + "-ExternalMu", provider);
        signer.initSign(kp.getPrivate());
        signer.update(mu);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(alg + "-ExternalMu", provider);
        verifier.initVerify(kp.getPublic());
        verifier.update(mu);
        assertTrue(verifier.verify(sig), "genuine external-mu signature must verify");

        Signature tamperVerifier = Signature.getInstance(alg + "-ExternalMu", provider);
        tamperVerifier.initVerify(kp.getPublic());
        byte[] tamperedMu = mu.clone();
        tamperedMu[0] ^= 0x01;
        tamperVerifier.update(tamperedMu);
        assertFalse(tamperVerifier.verify(sig), "tampered mu must not verify");
    }

    /**
     * The load-bearing case for this feature: proves the server genuinely
     * routes {@code external_mu=true} through a different signing/
     * verification path rather than silently accepting and ignoring the
     * flag. A server that dropped the field on the floor (e.g. an old
     * binary predating this proto field, or a regression that stopped
     * reading it) would still pass
     * {@link #externalMuSignVerifyRoundTripsAndTamperIsRejected} — plain
     * ML-DSA over 64 arbitrary bytes also signs and verifies fine — so
     * that case alone is not proof. This one is: the SAME 64-byte buffer
     * signed under {@code "ML-DSA-65"} (plain) and under
     * {@code "ML-DSA-65-ExternalMu"} must produce different signature
     * bytes, and a signature from one mode must be REJECTED when checked
     * under the other.
     */
    @Test
    void externalMuIsGenuinelyDifferentFromPlainModeNotSilentlyIgnored() throws Exception {
        KeyPair kp = generateKeyPair("ML-DSA-65");
        byte[] mu = new byte[64];
        new SecureRandom().nextBytes(mu);

        Signature muSigner = Signature.getInstance("ML-DSA-65-ExternalMu", provider);
        muSigner.initSign(kp.getPrivate());
        muSigner.update(mu);
        byte[] sigMu = muSigner.sign();

        Signature plainSigner = Signature.getInstance("ML-DSA-65", provider);
        plainSigner.initSign(kp.getPrivate());
        plainSigner.update(mu);
        byte[] sigPlain = plainSigner.sign();

        assertFalse(Arrays.equals(sigMu, sigPlain),
            "the same 64 bytes signed in the two modes must not produce the same signature");

        // external-mu signature checked under the PLAIN verifier must fail
        Signature plainVerifier = Signature.getInstance("ML-DSA-65", provider);
        plainVerifier.initVerify(kp.getPublic());
        plainVerifier.update(mu);
        assertFalse(plainVerifier.verify(sigMu), "an external-mu signature must NOT verify under plain mode");

        // plain-mode signature checked under the EXTERNAL-MU verifier must fail
        Signature muVerifier = Signature.getInstance("ML-DSA-65-ExternalMu", provider);
        muVerifier.initVerify(kp.getPublic());
        muVerifier.update(mu);
        assertFalse(muVerifier.verify(sigPlain), "a plain-mode signature must NOT verify under external-mu mode");
    }

    @Test
    void externalMuRejectsAMuBufferThatIsNotExactly64Bytes() throws Exception {
        // Real end-to-end exercise of the live engine's own length check
        // (rust/src/crypto/handlers.rs::sign_ml_dsa_external_mu returns
        // CKR_ARGUMENTS_BAD for anything but exactly 64 bytes) reached
        // through the full wire path: Java -> gRPC -> Rust verb layer ->
        // native::sign_pqc -> the engine.
        KeyPair kp = generateKeyPair("ML-DSA-65");

        Signature signer = Signature.getInstance("ML-DSA-65-ExternalMu", provider);
        signer.initSign(kp.getPrivate());
        signer.update(new byte[63]);
        assertThrows(SignatureException.class, signer::sign,
            "the server must reject a 63-byte buffer under external-mu mode (CKR_ARGUMENTS_BAD)");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    void selfSignedCertificateIsPkixValidAndSelfSigned(String algo) throws Exception {
        KeyPair kp = generateKeyPair(algo);

        X509Certificate cert = provider.getSelfSignedCertificate(kp, "regress-" + algo, 30);
        cert.checkValidity();
        cert.verify(kp.getPublic());

        assertEquals(cert.getSubjectX500Principal(), cert.getIssuerX500Principal(), "issuer must equal subject");
        assertTrue(cert.getSubjectX500Principal().getName().contains("regress-" + algo));

        TrustAnchor anchor = new TrustAnchor(cert, null);
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        validator.validate(cf.generateCertPath(List.of(cert)), params);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    void encapsulateDecapsulateAgreeOnSharedSecret(String algo) throws Exception {
        KeyPair kp = generateKeyPair(algo);

        KEM kem = KEM.getInstance("ML-KEM", provider);
        KEM.Encapsulator encapsulator = kem.newEncapsulator(kp.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();

        KEM.Decapsulator decapsulator = kem.newDecapsulator(kp.getPrivate());
        SecretKey decapsulated = decapsulator.decapsulate(encapsulated.encapsulation());

        assertArrayEquals(encapsulated.key().getEncoded(), decapsulated.getEncoded());
        assertEquals(32, decapsulated.getEncoded().length, "FIPS 203: K is always 32 bytes");
    }

    @Test
    void certificateRejectsMlKemKey() throws Exception {
        KeyPair kp = generateKeyPair("ML-KEM-768");
        ProviderException e = assertThrows(ProviderException.class,
            () -> provider.getSelfSignedCertificate(kp, "should-fail", 30));
        assertTrue(e.getMessage().contains("ML-KEM-768"), "message should name the rejected algorithm: " + e.getMessage());
    }

    @Test
    void missingMtlsMaterialFailsClosedBeforeAnyNetworkCall() {
        // E3: no plaintext/no-mTLS fallback — construction must refuse
        // before ever touching the network when client.crt/client.key/
        // ca.crt aren't present at certDir, not silently degrade.
        ProviderException e = assertThrows(ProviderException.class,
            () -> new SoftHSMv3RemoteProvider("pqc-grpc", 5710, "1234", "/tmp"));
        assertTrue(e.getMessage().contains("requires real mTLS identity material"),
            "must name the real fail-closed reason, not a generic connection error: " + e.getMessage());
    }

    @Test
    void wrongPinRejectedAtSessionOpen() {
        String host = System.getenv().getOrDefault("PKCS11_GRPC_HOST", "pqc-grpc");
        int port = Integer.parseInt(System.getenv().getOrDefault("PKCS11_GRPC_PORT", "5710"));
        String certDir = System.getenv().getOrDefault("AGILE_KMIP_CERTS", "/admin-certs");

        ProviderException e = assertThrows(ProviderException.class,
            () -> new SoftHSMv3RemoteProvider(host, port, "0000-definitely-wrong", certDir));
        assertTrue(e.getMessage().contains("CKR_PIN_INCORRECT"),
            "must name the real CKR_* code, not just fail generically: " + e.getMessage());
    }

    private static KeyPair generateKeyPair(String algo) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo, provider);
        kpg.initialize(new NamedParameterSpec(algo));
        return kpg.generateKeyPair();
    }
}
