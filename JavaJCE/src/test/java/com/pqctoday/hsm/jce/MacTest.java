package com.pqctoday.hsm.jce;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
}
