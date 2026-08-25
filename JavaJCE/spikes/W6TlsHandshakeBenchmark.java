import com.pqctoday.hsm.jce.SoftHSMv3Provider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.security.Security;
import java.util.Arrays;

/**
 * W6 required deliverable (plan §WS-B decision Q4): N-handshake latency
 * comparison, this provider (token-backed KEM/keygen/record cipher) vs
 * stock JDK (SunJCE's own software ML-KEM — confirmed present in this
 * JDK 27 RC, plan §W6's own finding). Same methodology shape as the
 * repo's transport-arms benchmark precedent: sequential real handshakes
 * against the same live endpoint, min/mean/p50/p95 reported from raw
 * numbers, not summarized adjectives.
 *
 * Not part of `mvn test` (needs the live pqc-rest container, same
 * precedent as the other W6 spikes). Requires
 * -Dsofthsmv3.jce.callerGcmIv=true when running the token-backed arm
 * (record cipher needs it); the stock-JDK arm never touches this
 * provider at all, so the flag is irrelevant there.
 */
public class W6TlsHandshakeBenchmark {
    private static final String HOST = "pqc-rest";
    private static final int PORT = 5720;
    private static final String GROUP = "SecP256r1MLKEM768";
    private static final int N = 50;

    public static void main(String[] args) throws Exception {
        System.setProperty("jdk.tls.namedGroups", GROUP);

        System.err.println("=== Arm 1: stock JDK (SunJCE software ML-KEM, no custom provider) ===");
        long[] stockMillis = run(N);
        report("stock JDK", stockMillis);

        System.err.println();
        System.err.println("=== Arm 2: SoftHSMv3Provider at priority 1 (token-backed) ===");
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        Security.insertProviderAt(p, 1);
        long[] tokenMillis = run(N);
        report("token-backed (SoftHSMv3)", tokenMillis);

        System.err.println();
        System.err.printf("Ratio (token-backed mean / stock JDK mean): %.2fx%n",
            mean(tokenMillis) / mean(stockMillis));
    }

    private static long[] run(int n) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, new javax.net.ssl.TrustManager[]{ new javax.net.ssl.X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        }}, null);

        long[] millis = new long[n];
        for (int i = 0; i < n; i++) {
            long start = System.nanoTime();
            try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(HOST, PORT)) {
                SSLParameters params = socket.getSSLParameters();
                params.setNamedGroups(new String[]{ GROUP });
                socket.setSSLParameters(params);
                socket.startHandshake();
            }
            millis[i] = (System.nanoTime() - start) / 1_000_000;
        }
        return millis;
    }

    private static double mean(long[] v) {
        double sum = 0;
        for (long x : v) sum += x;
        return sum / v.length;
    }

    private static void report(String label, long[] millis) {
        long[] sorted = millis.clone();
        Arrays.sort(sorted);
        long min = sorted[0];
        long max = sorted[sorted.length - 1];
        double mean = mean(millis);
        long p50 = sorted[sorted.length / 2];
        long p95 = sorted[(int) (sorted.length * 0.95)];
        System.err.printf("%s: n=%d min=%dms mean=%.1fms p50=%dms p95=%dms max=%dms%n",
            label, millis.length, min, mean, p50, p95, max);
    }
}
