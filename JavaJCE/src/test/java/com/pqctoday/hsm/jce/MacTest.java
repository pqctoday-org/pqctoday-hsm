package com.pqctoday.hsm.jce;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.Security;

import static com.pqctoday.hsm.jce.P11Constants.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * HMAC-SHA*, AESCMAC, KMAC128/256 — MacSpi over the engine's existing
 * C_SignInit/C_Sign path.
 *
 * Same structural cross-verification constraint as AESCipherTest: a
 * token-generated MAC key is non-extractable, so cross-verification
 * needs a known raw key imported into both this provider and the
 * external oracle. HMAC-SHA224/256/384/512 and HmacSHA3-224/256/384/512
 * are all registered in the JDK's own SunJCE (confirmed live via
 * Security.getAlgorithms("Mac") before writing this test), so those use
 * the JDK as the oracle. AESCMAC and KMAC128/256 are NOT in SunJCE
 * (confirmed the same way — absent from that same live enumeration), so
 * those cross-verify against Bouncy Castle instead, which does register
 * all three (confirmed live too) — same "JDK lacks it, use BC" pattern
 * already established for SLH-DSA (W2) and SHA-3 OAEP (W3).
 */
class MacTest {

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

    @ParameterizedTest
    @CsvSource({
        "HmacSHA224, 28",
        "HmacSHA256, 32",
        "HmacSHA384, 48",
        "HmacSHA512, 64",
        "HmacSHA3-224, 28",
        "HmacSHA3-256, 32",
        "HmacSHA3-384, 48",
        "HmacSHA3-512, 64",
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
        "HmacSHA224, 28",
        "HmacSHA256, 32",
        "HmacSHA384, 48",
        "HmacSHA512, 64",
        "HmacSHA3-224, 28",
        "HmacSHA3-256, 32",
        "HmacSHA3-384, 48",
        "HmacSHA3-512, 64",
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
    void aesCmacInteropsWithBouncyCastle() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKey = new byte[16];
        new java.security.SecureRandom().nextBytes(rawKey);
        long handle = importRawSecret(p.lib, rawKey, CKK_AES);
        SecretKey ourKey = new P11Key.Secret(p.lib, handle, "AES");
        SecretKey bcKey = new SecretKeySpec(rawKey, "AES");

        Mac ours = Mac.getInstance("AESCMAC", p);
        assertEquals(16, ours.getMacLength());
        ours.init(ourKey);
        byte[] ourMac = ours.doFinal("CMAC interop".getBytes());

        Mac bc = Mac.getInstance("AESCMAC", "BC");
        bc.init(bcKey);
        byte[] bcMac = bc.doFinal("CMAC interop".getBytes());

        assertArrayEquals(bcMac, ourMac, "our AESCMAC must match Bouncy Castle's own AES-CMAC for the same key+input");
    }

    @ParameterizedTest
    @CsvSource({
        "KMAC128, 16, 32",
        "KMAC256, 32, 64",
    })
    void kmacInteropsWithBouncyCastle(String name, int keyBytes, int macLength) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKey = new byte[keyBytes];
        new java.security.SecureRandom().nextBytes(rawKey);
        long handle = importRawSecret(p.lib, rawKey, CKK_GENERIC_SECRET);
        SecretKey ourKey = new P11Key.Secret(p.lib, handle, name);
        SecretKey bcKey = new SecretKeySpec(rawKey, name);

        Mac ours = Mac.getInstance(name, p);
        assertEquals(macLength, ours.getMacLength());
        ours.init(ourKey);
        byte[] ourMac = ours.doFinal("KMAC interop".getBytes());
        assertEquals(macLength, ourMac.length);

        Mac bc = Mac.getInstance(name, "BC");
        bc.init(bcKey);
        byte[] bcMac = bc.doFinal("KMAC interop".getBytes());

        assertArrayEquals(bcMac, ourMac,
            "our " + name + " must match Bouncy Castle's own KMAC for the same key+input "
            + "(this is also the empirical check on macLength itself — W0.3's spike already found "
            + "KMAC-256's real output is 64 bytes, not a naively-guessed 32, so this value is never assumed)");
    }

    // ── Item 1: CKM_*_HMAC_GENERAL (truncated/general-length HMAC) ────────

    @Test
    void plainHmacStillRejectsAnyNonNullParameter() throws Exception {
        // Regression guard: item 1's whole point is that the PLAIN
        // (non-general) HMAC path stays completely untouched.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("HmacSHA256", p).generateKey();
        Mac mac = Mac.getInstance("HmacSHA256", p);
        assertThrows(InvalidAlgorithmParameterException.class,
            () -> mac.init(key, new P11MacOutputLengthParameterSpec(16)),
            "the plain \"HmacSHA256\" Mac must still reject any AlgorithmParameterSpec, general-length or not");
    }

    @ParameterizedTest
    @CsvSource({
        "HmacSHA224General, HmacSHA224, 28, 14",
        "HmacSHA256General, HmacSHA256, 32, 16",
        "HmacSHA384General, HmacSHA384, 48, 24",
        "HmacSHA512General, HmacSHA512, 64, 32",
        "HmacSHA3-224General, HmacSHA3-224, 28, 14",
        "HmacSHA3-256General, HmacSHA3-256, 32, 16",
        "HmacSHA3-384General, HmacSHA3-384, 48, 24",
        "HmacSHA3-512General, HmacSHA3-512, 64, 32",
    })
    void generalLengthHmacTruncatesTheRealFullMac(String generalName, String plainName, int fullLen, int truncLen)
            throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        // Same key works under both names — P11MacSpi doesn't enforce
        // key.getAlgorithm() equality (see its own javadoc).
        SecretKey key = KeyGenerator.getInstance(plainName, p).generateKey();
        byte[] data = "general-length HMAC round trip".getBytes();

        Mac full = Mac.getInstance(plainName, p);
        full.init(key);
        byte[] fullMac = full.doFinal(data);
        assertEquals(fullLen, fullMac.length);

        Mac truncated = Mac.getInstance(generalName, p);
        assertThrows(InvalidAlgorithmParameterException.class, () -> truncated.init(key, null),
            "the general-length mechanism has no default output length — PKCS#11's own "
            + "applyGeneralMacLength() unconditionally requires a CK_MAC_GENERAL_PARAMS");
        truncated.init(key, new P11MacOutputLengthParameterSpec(truncLen));
        assertEquals(truncLen, truncated.getMacLength());
        byte[] truncMac = truncated.doFinal(data);
        assertEquals(truncLen, truncMac.length,
            "the general-length MAC must be exactly the requested truncated length, not the full length");

        // PKCS#11 v3.2 §6.20.3: "the MAC is taken from the start of the
        // full ... HMAC output" — a real, checkable property, not just a
        // length check.
        assertArrayEquals(java.util.Arrays.copyOf(fullMac, truncLen), truncMac,
            generalName + " must be exactly the first " + truncLen + " bytes of the full " + plainName + " MAC");

        // Requesting the FULL length via the general mechanism must match
        // the plain mechanism's own output exactly (a real, live
        // cross-check that the general variant is genuinely the same
        // construction, not just "any truncation").
        Mac fullViaGeneral = Mac.getInstance(generalName, p);
        fullViaGeneral.init(key, new P11MacOutputLengthParameterSpec(fullLen));
        assertArrayEquals(fullMac, fullViaGeneral.doFinal(data));
    }

    // ── Item 3: CKM_AES_GMAC (GMAC-as-a-MAC) ───────────────────────────────

    @Test
    void gmacRoundTripsAndDetectsTampering() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKey = new byte[16];
        new java.security.SecureRandom().nextBytes(rawKey);
        long handle = importRawSecret(p.lib, rawKey, CKK_AES);
        SecretKey key = new P11Key.Secret(p.lib, handle, "AES");
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        byte[] data = "AES-GMAC round trip".getBytes();

        Mac mac = Mac.getInstance("AES-GMAC", p);
        mac.init(key, new IvParameterSpec(iv));
        byte[] tag = mac.doFinal(data);
        assertEquals(16, tag.length, "default AES-GMAC tag length must be 128 bits");
        assertEquals(16, mac.getMacLength());

        Mac mac2 = Mac.getInstance("AES-GMAC", p);
        mac2.init(key, new IvParameterSpec(iv));
        assertArrayEquals(tag, mac2.doFinal(data), "AES-GMAC must be deterministic for the same key+iv+input");

        Mac mac3 = Mac.getInstance("AES-GMAC", p);
        mac3.init(key, new IvParameterSpec(iv));
        assertFalse(java.util.Arrays.equals(tag, mac3.doFinal("tampered".getBytes())),
            "a different input must produce a different GMAC tag");
    }

    @Test
    void gmacInteropsWithBouncyCastle() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKey = new byte[16];
        new java.security.SecureRandom().nextBytes(rawKey);
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        byte[] data = "AES-GMAC BC interop".getBytes();

        long handle = importRawSecret(p.lib, rawKey, CKK_AES);
        SecretKey ourKey = new P11Key.Secret(p.lib, handle, "AES");
        SecretKey bcKey = new SecretKeySpec(rawKey, "AES");

        Mac ours = Mac.getInstance("AES-GMAC", p);
        ours.init(ourKey, new IvParameterSpec(iv));
        byte[] ourTag = ours.doFinal(data);

        // Explicit 128-bit tag length on both sides — Bouncy Castle's own
        // "AES-GMAC" default under a bare IvParameterSpec was confirmed
        // live (container probe, before writing this test) to ALSO be
        // 128 bits, but this pins it explicitly rather than relying on
        // that default matching ours by coincidence.
        Mac bc = Mac.getInstance("AES-GMAC", "BC");
        bc.init(bcKey, new GCMParameterSpec(128, iv));
        byte[] bcTag = bc.doFinal(data);

        assertArrayEquals(bcTag, ourTag, "our AES-GMAC must match Bouncy Castle's own AES-GMAC for the same key+iv+input");
    }
}
