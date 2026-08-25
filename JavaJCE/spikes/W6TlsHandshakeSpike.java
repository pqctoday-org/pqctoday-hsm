import com.pqctoday.hsm.jce.SoftHSMv3Provider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;

/**
 * W6 live verification spike (not part of the regular `mvn test` suite —
 * requires the pqc-rest container reachable at pqc-rest:5720, same
 * precedent as W0.1's own JSSE probe spike). Installs the real
 * SoftHSMv3Provider at top priority, pins the FIPS-friendly hybrid
 * groups per plan §7, and performs a real TLS 1.3 handshake against
 * pqc-rest's quantum-safe endpoint (TLS 1.3 only, X25519MLKEM768 /
 * SecP256r1MLKEM768 / SecP384r1MLKEM1024 — confirmed live from its own
 * startup log). Run with -Dsofthsmv3.jce.debug=true to see this
 * provider's own native-call log lines (P11Debug) proving its code path
 * ran, not a silent fallback to SunJCE's own built-in ML-KEM (confirmed
 * present in this same JDK 27 RC — SunJCE registers KeyPairGenerator/
 * KeyFactory/KEM for ML-KEM-512/768/1024 and the bare "ML-KEM" name,
 * so success alone does not prove which provider serviced the request).
 */
public class W6TlsHandshakeSpike {
    public static void main(String[] args) throws Exception {
        System.setProperty("jdk.tls.namedGroups", "SecP256r1MLKEM768,SecP384r1MLKEM1024");

        SoftHSMv3Provider p = new SoftHSMv3Provider();
        Security.insertProviderAt(p, 1);
        System.err.println("Installed " + p.getName() + " at priority 1. Provider order:");
        for (var prov : Security.getProviders()) {
            System.err.println("  " + prov.getName());
        }

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, new javax.net.ssl.TrustManager[]{ new javax.net.ssl.X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        }}, null);

        try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket("pqc-rest", 5720)) {
            SSLParameters params = socket.getSSLParameters();
            params.setNamedGroups(new String[]{ "SecP256r1MLKEM768", "SecP384r1MLKEM1024" });
            socket.setSSLParameters(params);
            System.err.println("Starting handshake...");
            socket.startHandshake();
            System.err.println("HANDSHAKE SUCCEEDED");
            System.err.println("Protocol: " + socket.getSession().getProtocol());
            System.err.println("CipherSuite: " + socket.getSession().getCipherSuite());

            OutputStream out = socket.getOutputStream();
            out.write("GET / HTTP/1.1\r\nHost: pqc-rest\r\nConnection: close\r\n\r\n".getBytes());
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] buf = new byte[4096];
            int n = in.read(buf);
            System.err.println("Response (" + n + " bytes): " + new String(buf, 0, Math.max(n, 0)));
        }
    }
}
