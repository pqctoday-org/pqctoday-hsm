package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

import static com.pqctoday.hsm.jce.P11Constants.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Item 3 (2026-08-30 follow-on): SHA-512/224 and SHA-512/256 (FIPS 180-4
 * §5) — MessageDigest and plain (non-general) HMAC coverage. These are
 * genuinely different digests from plain SHA-512 (a distinct FIPS 180-4
 * initial hash value, truncated output — not a display alias or a
 * simple truncation of SHA-512's own output), so they get their own
 * dedicated test file rather than folding into an existing one: no
 * digest-only test file existed before this (digests were previously
 * only exercised indirectly, via SoftHSMv3Provider's own POST self-test).
 *
 * "SHA-512/224"/"SHA-512/256" (MessageDigest) and "HmacSHA512/224"/
 * "HmacSHA512/256" (Mac) are all confirmed live, real JDK 27 standard
 * algorithm names — the SUN and SunJCE providers both register them
 * (confirmed via a container probe before writing this test) — so JDK
 * itself is the cross-verification oracle, the same "JDK is the oracle"
 * pattern MacTest.java already established for the other SHA-2/SHA3 HMAC
 * variants.
 *
 * The CKM_SHA512_224_KEY_DERIVATION / CKM_SHA512_256_KEY_DERIVATION
 * mechanism family is deliberately OUT of scope here — see
 * P11Constants' own comment on why those two constants are not declared.
 */
class Sha512SubVariantsTest {

    // NIST FIPS 180-4 Appendix (published SHA-512/224 and SHA-512/256
    // "abc" test vectors) — an independent, standards-body-published KAT
    // in addition to the live JDK cross-check below.
    private static final byte[] ABC = "abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final String SHA512_224_ABC_KAT =
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa";
    private static final String SHA512_256_ABC_KAT =
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23";

    @ParameterizedTest
    @CsvSource({
        "SHA-512/224, 28",
        "SHA-512/256, 32",
    })
    void digestKatMatchesFips1804(String name, int digestLen) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        MessageDigest md = MessageDigest.getInstance(name, p);
        assertEquals(digestLen, md.getDigestLength());
        byte[] got = md.digest(ABC);
        assertEquals(digestLen, got.length);
        String expected = name.equals("SHA-512/224") ? SHA512_224_ABC_KAT : SHA512_256_ABC_KAT;
        assertEquals(expected, java.util.HexFormat.of().formatHex(got),
            name + "(\"abc\") must match the published FIPS 180-4 KAT");
    }

    @ParameterizedTest
    @CsvSource({
        "SHA-512/224, 28",
        "SHA-512/256, 32",
    })
    void digestInteropsWithJdkSun(String name, int digestLen) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        MessageDigest ours = MessageDigest.getInstance(name, p);
        MessageDigest jdk = MessageDigest.getInstance(name); // default SUN
        byte[] data = "SHA-512 sub-variant JDK interop check".getBytes();
        assertArrayEquals(jdk.digest(data), ours.digest(data),
            "our " + name + " must match JDK's own SUN digest for the same input");
    }

    @ParameterizedTest
    @CsvSource({
        "HmacSHA512/224, 28",
        "HmacSHA512/256, 32",
    })
    void hmacKeyGeneratorAndSelfConsistency(String name, int macLength) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance(name, p).generateKey();
        assertNull(key.getEncoded(), "generated MAC keys must be opaque");

        Mac mac = Mac.getInstance(name, p);
        assertEquals(macLength, mac.getMacLength());
        mac.init(key);
        byte[] a = mac.doFinal("same input".getBytes());
        assertEquals(macLength, a.length);

        mac.init(key);
        byte[] b = mac.doFinal("same input".getBytes());
        assertArrayEquals(a, b, "HMAC must be deterministic for the same key+input");

        mac.init(key);
        byte[] c = mac.doFinal("different input".getBytes());
        assertFalse(java.util.Arrays.equals(a, c), "different input must produce a different MAC");
    }

    @ParameterizedTest
    @CsvSource({
        "HmacSHA512/224, 28",
        "HmacSHA512/256, 32",
    })
    void hmacInteropsWithJdkSunJCE(String name, int macLength) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] raw = new byte[macLength];
        new java.security.SecureRandom().nextBytes(raw);
        long handle = importRawSecret(p.lib, raw, CKK_GENERIC_SECRET);
        SecretKey ourKey = new P11Key.Secret(p.lib, handle, name);
        SecretKey jdkKey = new SecretKeySpec(raw, name);

        Mac ours = Mac.getInstance(name, p);
        ours.init(ourKey);
        byte[] ourMac = ours.doFinal("interop check".getBytes());

        Mac jdk = Mac.getInstance(name); // default SunJCE
        jdk.init(jdkKey);
        byte[] jdkMac = jdk.doFinal("interop check".getBytes());

        assertArrayEquals(jdkMac, ourMac, "our HMAC must match JDK SunJCE's own HMAC for the same key+input");
    }

    @Test
    void plainHmacRejectsGeneralLengthParameter() throws Exception {
        // Same regression guard as MacTest's own plainHmacStillRejectsAnyNonNullParameter
        // — the plain (non-"_HMAC_GENERAL") mechanism must never accept a
        // truncation parameter, for either of these two variants either.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("HmacSHA512/224", p).generateKey();
        Mac mac = Mac.getInstance("HmacSHA512/224", p);
        assertThrows(java.security.InvalidAlgorithmParameterException.class,
            () -> mac.init(key, new P11MacOutputLengthParameterSpec(16)));
    }

    private static long importRawSecret(P11Library lib, byte[] raw, long keyType) {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, keyType),
            P11Library.attr(CKA_VALUE, raw),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_SIGN, true),
        };
        return lib.createObject(tmpl);
    }
}
