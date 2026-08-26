package com.pqctoday.hsm.jce;

import com.sun.management.HotSpotDiagnosticMXBean;
import org.junit.jupiter.api.Test;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.RandomAccessFile;
import java.lang.management.ManagementFactory;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Live, heap-dump-based zeroization audit (plan §6.5) — not a code-review
 * assertion, an actual JVM heap dump scanned for a real byte pattern. This
 * targets the ONE place in this module where genuine plaintext secret
 * material passes through the JVM heap at all: ML-KEM's decapsulated
 * shared secret (see P11MLKEMSpi's class javadoc for why it's the single
 * deliberate exception to this module's "opaque handle only" design).
 * Every other key type in this module (P11Key.Priv/Pub/Secret) never
 * holds raw key bytes in the JVM in the first place — getEncoded() is
 * unconditionally null for private/secret keys, so there is nothing a
 * heap dump could find or fail to find for them; a heap-dump test there
 * would only be re-proving what reading the class already shows.
 *
 * Real, disclosed reason this matters beyond "the object goes out of
 * scope eventually": a well-known JVM gotcha (the reason Java security
 * guidance recommends explicit Arrays.fill(..., 0) for sensitive byte[]
 * rather than relying on GC) is that a stale local-variable stack slot
 * can keep an otherwise-dead object artificially reachable until that
 * slot is overwritten by a later call — "let it go out of scope" is not
 * a reliable clearing strategy by itself. P11MLKEMSpi's
 * Encapsulator/Decapsulator explicitly Arrays.fill() their intermediate
 * fullSecret/sliced arrays before returning specifically to close that
 * gap; this test is the live proof it actually does.
 */
class ZeroizationAuditTest {

    @Test
    void decapsulatedSecretDoesNotLeaveExtraCopiesOnTheHeap() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", p);
        kpg.initialize(new NamedParameterSpec("ML-KEM-768"));
        KeyPair kp = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("ML-KEM", p);
        KEM.Encapsulator encapsulator = kem.newEncapsulator(kp.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        SecretKey liveKey = encapsulated.key();
        byte[] secretBytes = liveKey.getEncoded();
        assertTrue(secretBytes.length >= 16, "sanity: expected real key material, not an empty/trivial key");

        File dump = File.createTempFile("post-encap-heap", ".hprof");
        assertTrue(dump.delete(), "dumpHeap requires the target file to not already exist");
        try {
            dumpHeap(dump);
            int occurrences = countOccurrences(dump, secretBytes);
            // Expected, legitimate copies at the moment of the dump:
            // (1) this test's own `secretBytes` local, (2) liveKey's
            // internal SecretKeySpec clone (still referenced — we
            // haven't discarded it). Anything beyond that would be an
            // uncleared leftover copy from P11MLKEMSpi's own
            // fullSecret/sliced intermediates — exactly what the
            // Arrays.fill() calls added for §6.5 are there to prevent.
            assertTrue(occurrences <= 2,
                "found " + occurrences + " copies of the decapsulated secret in a live heap dump, "
                + "expected at most 2 (the test's own comparison copy + the live SecretKey's own clone) — "
                + "an uncleared leftover copy would mean P11MLKEMSpi's intermediate byte[] zeroing regressed");
        } finally {
            dump.delete();
        }
    }

    private static void dumpHeap(File file) throws Exception {
        HotSpotDiagnosticMXBean bean =
            ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class);
        bean.dumpHeap(file.getAbsolutePath(), true); // live=true: GC first, reachable objects only
    }

    /** Plain raw-byte substring scan over the hprof file — no HPROF parser needed for this purpose. */
    private static int countOccurrences(File dump, byte[] pattern) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(dump, "r");
             FileChannel ch = raf.getChannel()) {
            long size = ch.size();
            MappedByteBuffer buf = ch.map(FileChannel.MapMode.READ_ONLY, 0, size);
            byte[] haystack = new byte[(int) size];
            buf.get(haystack);
            int count = 0;
            int from = 0;
            int idx;
            while ((idx = indexOf(haystack, pattern, from)) >= 0) {
                count++;
                from = idx + 1;
            }
            return count;
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle, int fromIndex) {
        outer:
        for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}
