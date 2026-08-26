package com.pqctoday.hsm.jce.remote;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.NamedParameterSpec;
import java.util.Collections;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

/**
 * Live, unguessed, run-it-for-real driver against the actual pqc-grpc
 * container — not a JUnit test yet, deliberately: the point of this class
 * is to OBSERVE real behavior (exact CKR_* names, exact exception shapes)
 * before writing permanent assertions from a guess. Once run once and its
 * output inspected, its confirmed outcomes get promoted into
 * {@code RemoteProviderLiveTest} as real JUnit assertions.
 */
public final class LiveSmokeMain {
    private static int pass = 0, fail = 0;

    public static void main(String[] args) throws Exception {
        try (SoftHSMv3RemoteProvider provider = new SoftHSMv3RemoteProvider()) {
            java.security.Security.addProvider(provider);

            for (String sigAlgo : new String[]{"Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}) {
                signVerifyTamperRoundTrip(provider, sigAlgo);
                certificateRoundTrip(provider, sigAlgo);
            }
            for (String kemAlgo : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
                kemRoundTrip(provider, kemAlgo);
            }
            certificateRejectsKemKey(provider);
            badPinRejected();
        }

        System.out.println();
        System.out.println("==== " + pass + " passed, " + fail + " failed ====");
        if (fail > 0) System.exit(1);
    }

    private static void signVerifyTamperRoundTrip(SoftHSMv3RemoteProvider provider, String algo) {
        String label = "sign/verify/tamper[" + algo + "]";
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo, provider);
            kpg.initialize(new NamedParameterSpec(algo));
            KeyPair kp = kpg.generateKeyPair();

            byte[] msg = ("hello from LiveSmokeMain " + algo).getBytes();
            Signature signer = Signature.getInstance(algo, provider);
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(algo, provider);
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);
            boolean ok = verifier.verify(sig);

            Signature verifierTampered = Signature.getInstance(algo, provider);
            verifierTampered.initVerify(kp.getPublic());
            verifierTampered.update("tampered message!!".getBytes());
            boolean tamperedOk = verifierTampered.verify(sig);

            check(label, ok && !tamperedOk, "verify(real)=" + ok + " verify(tampered)=" + tamperedOk);
        } catch (Exception e) {
            fail(label, e);
        }
    }

    private static void certificateRoundTrip(SoftHSMv3RemoteProvider provider, String algo) {
        String label = "certificate[" + algo + "]";
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo, provider);
            kpg.initialize(new NamedParameterSpec(algo));
            KeyPair kp = kpg.generateKeyPair();

            // subjectCn is the bare RDN VALUE, not "CN=..." — the server
            // builds Name::from_str("CN={subject_cn}") itself
            // (remoting/core/src/cert.rs); passing an already-prefixed
            // string here produces a literal "CN=CN=..." subject.
            X509Certificate cert = provider.getSelfSignedCertificate(kp, "live-smoke-" + algo, 30);
            cert.checkValidity();
            cert.verify(kp.getPublic()); // JDK-side signature re-verification, independent of the server

            TrustAnchor anchor = new TrustAnchor(cert, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            var path = cf.generateCertPath(java.util.List.of(cert));
            validator.validate(path, params);

            boolean subjectOk = cert.getSubjectX500Principal().getName().contains("live-smoke-" + algo);
            boolean selfSignedOk = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
            check(label, subjectOk && selfSignedOk, "subject=" + cert.getSubjectX500Principal() + " selfSigned=" + selfSignedOk);
        } catch (Exception e) {
            fail(label, e);
        }
    }

    private static void kemRoundTrip(SoftHSMv3RemoteProvider provider, String algo) {
        String label = "kem[" + algo + "]";
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo, provider);
            kpg.initialize(new NamedParameterSpec(algo));
            KeyPair kp = kpg.generateKeyPair();

            KEM kem = KEM.getInstance("ML-KEM", provider);
            KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated encapsulated = enc.encapsulate();

            KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate());
            SecretKey decapsulated = dec.decapsulate(encapsulated.encapsulation());

            boolean secretsEqual = java.util.Arrays.equals(
                encapsulated.key().getEncoded(), decapsulated.getEncoded());
            check(label, secretsEqual, "secretsEqual=" + secretsEqual
                + " ctSize=" + encapsulated.encapsulation().length + " secretSize=" + decapsulated.getEncoded().length);
        } catch (Exception e) {
            fail(label, e);
        }
    }

    private static void certificateRejectsKemKey(SoftHSMv3RemoteProvider provider) {
        String label = "certificate-rejects-kem-key";
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", provider);
            kpg.initialize(new NamedParameterSpec("ML-KEM-768"));
            KeyPair kp = kpg.generateKeyPair();
            X509Certificate cert = provider.getSelfSignedCertificate(kp, "CN=should-fail", 30);
            fail(label, new AssertionError("expected rejection, got a certificate: " + cert));
        } catch (java.security.ProviderException e) {
            check(label, true, "rejected as expected: " + e.getMessage());
        } catch (Exception e) {
            fail(label, e);
        }
    }

    private static void badPinRejected() {
        String label = "bad-pin-rejected-at-open-session";
        String host = System.getenv().getOrDefault("PKCS11_GRPC_HOST", "pqc-grpc");
        int port = Integer.parseInt(System.getenv().getOrDefault("PKCS11_GRPC_PORT", "5710"));
        String certDir = System.getenv().getOrDefault("AGILE_KMIP_CERTS", "/admin-certs");
        try (SoftHSMv3RemoteProvider bad = new SoftHSMv3RemoteProvider(host, port, "0000-definitely-wrong", certDir)) {
            fail(label, new AssertionError("expected construction to throw, but it succeeded: " + bad));
        } catch (java.security.ProviderException e) {
            check(label, true, "rejected as expected: " + e.getMessage());
        } catch (Exception e) {
            fail(label, e);
        }
    }

    private static void check(String label, boolean ok, String detail) {
        if (ok) {
            pass++;
            System.out.println("PASS  " + label + "  (" + detail + ")");
        } else {
            fail++;
            System.out.println("FAIL  " + label + "  (" + detail + ")");
        }
    }

    private static void fail(String label, Throwable e) {
        fail++;
        System.out.println("FAIL  " + label + "  threw " + e);
        e.printStackTrace(System.out);
    }
}
