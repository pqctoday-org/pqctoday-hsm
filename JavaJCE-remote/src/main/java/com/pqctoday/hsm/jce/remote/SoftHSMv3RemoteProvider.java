package com.pqctoday.hsm.jce.remote;

import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.Algorithm;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * JCA/JCE provider bridging {@code javax.crypto}/{@code java.security} to
 * the {@code softhsmrustv3} engine via gRPC ({@code remoting/grpc}) —
 * NOT the local PKCS#11 FFM path {@code ../../JavaJCE/}'s
 * {@code SoftHSMv3Provider} uses. See plan
 * {@code docs/implementation-plan-jca-remaining-gaps-2026-08-25.md} §7
 * (WS-E) for the full design record: why this is a separate module/jar
 * (E1 — the core provider keeps zero network dependencies), the real
 * narrower remote surface (Ed25519 + ML-DSA-44/65/87 + ML-KEM-512/768/1024
 * only — no SLH-DSA/EC/RSA/symmetric, confirmed against the real proto,
 * not the main plan's own original "kebab-case" assumption), and the
 * real public-key-export gap this provider's own
 * {@link #getSelfSignedCertificate} closes (found live mid-workstream:
 * none of the original 7 verbs return a public key's bytes at all).
 *
 * <p>Every generated key is opaque — {@code getEncoded()} is {@code null}
 * for BOTH {@link RemoteKey.Priv} and {@link RemoteKey.Pub} (see that
 * class's own javadoc for why {@code Pub} differs from the local
 * provider's own key type here). {@link #getSelfSignedCertificate} is
 * the one way to get real key bytes out of this provider — a genuine,
 * signed X.509 certificate, not a bare key export.
 */
public final class SoftHSMv3RemoteProvider extends Provider implements AutoCloseable {
    @java.io.Serial private static final long serialVersionUID = 1L;

    private static final String NAME = "SoftHSMv3-Remote";
    private static final String INFO =
        "PKCS#11 gRPC-remote JCA/JCE provider for softhsmrustv3 (Ed25519, ML-DSA-44/65/87, ML-KEM-512/768/1024)";

    // Package-private (not private) so same-package test code can reach
    // the transport directly, same discipline as the local provider's
    // own package-visible `lib` field.
    final GrpcTransport transport;

    public SoftHSMv3RemoteProvider() {
        this(
            System.getenv().getOrDefault("PKCS11_GRPC_HOST", "pqc-grpc"),
            Integer.parseInt(System.getenv().getOrDefault("PKCS11_GRPC_PORT", "5710")),
            System.getenv().getOrDefault("PKCS11_PIN", "1234"),
            // Same env var name RestPkcs11Demo.java (pqctoday-sandbox
            // samples/java-jca/) already established for this same
            // /admin-certs material, kept consistent rather than
            // inventing a second name for the same directory.
            System.getenv().getOrDefault("AGILE_KMIP_CERTS", "/admin-certs"));
    }

    public SoftHSMv3RemoteProvider(String host, int port, String pin, String certDir) {
        super(NAME, "0.1.0", INFO);
        this.transport = new GrpcTransport(host, port, pin, certDir);
        registerServices();
        // Best-effort cleanup even if the caller never explicitly closes
        // this provider — same §6.5-equivalent posture the local
        // provider's own SoftHSMv3Provider already established, and the
        // same CLOSE_LOCK-motivated lesson from that module's own
        // WS-B finding applies here in spirit: GrpcTransport.close() is
        // idempotent, so registering this unconditionally is safe.
        Runtime.getRuntime().addShutdownHook(new Thread(transport::close, "SoftHSMv3RemoteProvider-shutdown"));
    }

    /** Best-effort session/channel teardown — see {@link GrpcTransport#close()}. Idempotent. */
    public void close() {
        transport.close();
    }

    /**
     * The one way to get real bytes for a remote public key out of this
     * provider at all (see this class's own javadoc and
     * {@link RemoteKey}'s) — a genuine, self-signed X.509 certificate
     * wrapping {@code kp}'s public key, signed by {@code kp}'s own
     * private key through the token (never a software signature).
     * {@code kp} must be a {@link KeyPair} this same provider instance
     * generated for a signature-capable algorithm (Ed25519 or
     * ML-DSA-44/65/87) — ML-KEM keys are rejected by the server with
     * {@code CKR_ARGUMENTS_BAD} (a KEM key cannot sign its own
     * certificate; see {@code remoting/core/src/cert.rs}'s own doc).
     *
     * @param kp a keypair from this provider's own {@code KeyPairGenerator}
     * @param subjectCn the bare {@code CN} RDN VALUE (e.g. {@code "my-key"},
     *     not {@code "CN=my-key"}) — the server itself builds
     *     {@code CN={subjectCn}} (see {@code remoting/core/src/cert.rs});
     *     passing an already-prefixed string produces a literal
     *     {@code CN=CN=...} subject
     * @param validityDays how many days from now the certificate remains valid
     */
    public X509Certificate getSelfSignedCertificate(KeyPair kp, String subjectCn, long validityDays) {
        if (!(kp.getPublic() instanceof RemoteKey.Pub pub) || !(kp.getPrivate() instanceof RemoteKey.Priv priv)) {
            throw new ProviderException("getSelfSignedCertificate needs a KeyPair from " + NAME + "'s own KeyPairGenerator");
        }
        Algorithm algo = algorithmOf(pub.getAlgorithm());
        byte[] der = transport.getSelfSignedCertificate(pub.handle(), priv.handle(), algo, subjectCn, validityDays);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new ProviderException("server returned a certificate this JDK's own X.509 CertificateFactory could not parse", e);
        }
    }

    private static Algorithm algorithmOf(String jcaName) {
        return switch (jcaName) {
            case "Ed25519" -> Algorithm.ED25519;
            case "ML-DSA-44" -> Algorithm.ML_DSA_44;
            case "ML-DSA-65" -> Algorithm.ML_DSA_65;
            case "ML-DSA-87" -> Algorithm.ML_DSA_87;
            default -> throw new ProviderException(
                jcaName + " is not a signature-capable algorithm this provider can certify (ML-KEM keys cannot sign)");
        };
    }

    private void registerServices() {
        // ── KeyPairGenerator: all 7 algorithms, one generic SPI shape ──
        registerKeyPairGenerator("Ed25519", Algorithm.ED25519);
        registerKeyPairGenerator("ML-DSA-44", Algorithm.ML_DSA_44);
        registerKeyPairGenerator("ML-DSA-65", Algorithm.ML_DSA_65);
        registerKeyPairGenerator("ML-DSA-87", Algorithm.ML_DSA_87);
        registerKeyPairGenerator("ML-KEM-512", Algorithm.ML_KEM_512);
        registerKeyPairGenerator("ML-KEM-768", Algorithm.ML_KEM_768);
        registerKeyPairGenerator("ML-KEM-1024", Algorithm.ML_KEM_1024);

        // ── Signature: the 4 signature-capable algorithms ──────────────
        registerSignature("Ed25519", Algorithm.ED25519);
        registerSignature("ML-DSA-44", Algorithm.ML_DSA_44);
        registerSignature("ML-DSA-65", Algorithm.ML_DSA_65);
        registerSignature("ML-DSA-87", Algorithm.ML_DSA_87);

        // ── KEM: bare family name (what JDK's own JEP 527 hybrid-TLS
        // path requests, matching the local provider's own precedent)
        // plus the 3 parameter-set-specific names for direct use.
        for (String name : new String[]{ "ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" }) {
            putService(new Service(this, "KEM", name, RemoteKEMSpi.class.getName(), List.of(), Map.of()) {
                @Override
                public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                    return new RemoteKEMSpi(transport);
                }
            });
        }
    }

    private void registerKeyPairGenerator(String name, Algorithm algo) {
        putService(new Service(this, "KeyPairGenerator", name, RemoteKeyPairGeneratorSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new RemoteKeyPairGeneratorSpi(transport, name, algo);
            }
        });
    }

    private void registerSignature(String name, Algorithm algo) {
        putService(new Service(this, "Signature", name, RemoteSignatureSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new RemoteSignatureSpi(transport, algo);
            }
        });
    }
}
