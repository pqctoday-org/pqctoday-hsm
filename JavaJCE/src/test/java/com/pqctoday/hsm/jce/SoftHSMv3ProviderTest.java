package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Runs against the live PKCS#11 module (PKCS11_MODULE env var, default
 * /usr/local/lib/softhsm/libsofthsmv3.so) — same standard as every other
 * live-verified test in this repo; no mocking of the token (mocked-vs-real
 * divergence is exactly what this repo's testing conventions guard
 * against). Requires --enable-native-access=ALL-UNNAMED (wired into
 * pom.xml's surefire argLine).
 */
class SoftHSMv3ProviderTest {

    @Test
    void digestMatchesFips1804Kat() throws NoSuchAlgorithmException {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        MessageDigest md = MessageDigest.getInstance("SHA-256", p);
        byte[] got = md.digest("abc".getBytes());
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            HexFormat.of().formatHex(got));
    }

    @Test
    void allApprovedDigestsProduceCorrectLength() throws NoSuchAlgorithmException {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        var lengths = java.util.Map.of(
            "SHA-224", 28, "SHA-256", 32, "SHA-384", 48, "SHA-512", 64,
            "SHA3-224", 28, "SHA3-256", 32, "SHA3-384", 48, "SHA3-512", 64);
        for (var e : lengths.entrySet()) {
            MessageDigest md = MessageDigest.getInstance(e.getKey(), p);
            assertEquals(e.getValue(), md.digest("test".getBytes()).length, e.getKey());
        }
    }

    @Test
    void deprecatedDigestsAreNotRegistered() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        for (String excluded : new String[]{"SHA-1", "MD5"}) {
            assertThrows(NoSuchAlgorithmException.class,
                () -> MessageDigest.getInstance(excluded, p),
                excluded + " must not be registered by the FIPS 140-3 L3 policy");
        }
    }

    @Test
    void secureRandomProducesDistinctOutputAndSupportsSeed() throws NoSuchAlgorithmException {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecureRandom sr = SecureRandom.getInstance("SoftHSMv3-DRBG", p);
        byte[] a = new byte[16];
        byte[] b = new byte[16];
        sr.nextBytes(a);
        sr.nextBytes(b);
        assertFalse(java.util.Arrays.equals(a, b), "two draws must not collide");
        assertEquals(8, sr.generateSeed(8).length);
        assertDoesNotThrow(() -> sr.setSeed(new byte[]{1, 2, 3, 4}));
    }
}

// POST fail-closed behavior (construction throws ProviderException and no
// service is ever registered when the KAT doesn't match) was verified via
// a sabotaged throwaway copy of this class during W1 development — see
// docs/implementation-plan-jdk27-jca-provider-2026-08-24.md's W1 entry.
// Not re-verified here: the real POST constant lives in production code,
// and corrupting it from a test would mean testing a modified copy of the
// class under test, not the class itself.
