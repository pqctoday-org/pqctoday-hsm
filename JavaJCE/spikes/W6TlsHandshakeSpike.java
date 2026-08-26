import com.pqctoday.hsm.jce.SoftHSMv3Provider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.security.Security;

/**
 * W6 live verification spike (not part of the regular `mvn test` suite —
 * requires the pqc-rest container reachable at pqc-rest:5720, same
 * precedent as W0.1's own JSSE probe spike). Installs the real
 * SoftHSMv3Provider at top priority, pins ONE FIPS-friendly hybrid group
 * per plan §7 (passed as argv[0], default SecP256r1MLKEM768 — run once
 * per group to confirm both), and performs a real TLS 1.3 handshake
 * against pqc-rest's quantum-safe endpoint (TLS 1.3 only,
 * X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 — confirmed
 * live from its own startup log). Run with -Dsofthsmv3.jce.debug=true to
 * see this provider's own native-call log lines (P11Debug) proving its
 * code path ran, not a silent fallback to SunJCE's own built-in ML-KEM
 * (confirmed present in this same JDK 27 RC — SunJCE registers
 * KeyPairGenerator/KeyFactory/KEM for ML-KEM-512/768/1024 and the bare
 * "ML-KEM" name, so success alone does not prove which provider serviced
 * the request). Also needs -Dsofthsmv3.jce.callerGcmIv=true (plan
 * §WS-B): TLS 1.3's record cipher supplies its own RFC 8446-mandated
 * deterministic nonce, which this provider's GCM Cipher refuses by
 * default (SP 800-38D §8.2 policy) unless this flag opts in.
 *
 * A real, live handshake success (protocol + cipher suite reported) IS
 * the proof this workstream needs — the deliberately-omitted HTTP
 * exchange afterward would need a client certificate this spike doesn't
 * have (pqc-rest's quantum-safe endpoint requires mTLS at the
 * application layer, orthogonal to what this spike verifies), so this
 * closes the socket right after a successful handshake rather than
 * chasing an unrelated certificate_required alert.
 */
public class W6TlsHandshakeSpike {
    public static void main(String[] args) throws Exception {
        String group = args.length > 0 ? args[0] : "SecP256r1MLKEM768";
        System.setProperty("jdk.tls.namedGroups", group);

        SoftHSMv3Provider p = new SoftHSMv3Provider();
        Security.insertProviderAt(p, 1);
        System.err.println("Installed " + p.getName() + " at priority 1, pinned group: " + group);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, new javax.net.ssl.TrustManager[]{ new javax.net.ssl.X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        }}, null);

        try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket("pqc-rest", 5720)) {
            SSLParameters params = socket.getSSLParameters();
            params.setNamedGroups(new String[]{ group });
            socket.setSSLParameters(params);
            System.err.println("Starting handshake...");
            socket.startHandshake();
            System.err.println("HANDSHAKE SUCCEEDED (group=" + group + ")");
            System.err.println("Protocol: " + socket.getSession().getProtocol());
            System.err.println("CipherSuite: " + socket.getSession().getCipherSuite());
        }
    }
}
