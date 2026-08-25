package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PBKDF2WithHmacSHA256/384/512. Derived keys are deliberately opaque
 * (same non-export design as every other generated/derived key in this
 * module), so neither a hardcoded KAT nor a direct byte-for-byte JDK
 * cross-verify is possible the way RSA-OAEP/HKDF's were. Correctness is
 * instead verified indirectly but just as conclusively: derive via both
 * this provider and JDK's own SunJCE for the identical
 * password/salt/iterations/length, then HMAC identical data with each
 * derived key (ours via this provider's own already-proven Mac SPI,
 * JDK's via a plain SecretKeySpec of its own exported bytes) and compare
 * the MAC outputs — if the two derivations produced different key
 * material, the MACs would differ with overwhelming probability, so a
 * match proves the derived keys are identical without ever exporting
 * this provider's own key bytes.
 */
class PBKDF2Test {

    // HmacSHA384/512 need at least a 48/64-byte key (the engine's own
    // kMacMechTable minimums, same as MacTest's macLength values) — a
    // fixed 256-bit derived key is too short for those and fails live
    // with CKR_KEY_SIZE_RANGE, so every test below sizes the derived key
    // to match the HMAC variant it will actually be used with.
    private static int keyLengthBitsFor(String pbkdf2Name) {
        return switch (pbkdf2Name) {
            case "PBKDF2WithHmacSHA256" -> 256;
            case "PBKDF2WithHmacSHA384" -> 384;
            case "PBKDF2WithHmacSHA512" -> 512;
            default -> throw new IllegalArgumentException(pbkdf2Name);
        };
    }

    @ParameterizedTest
    @ValueSource(strings = {"PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    void derivesAnOpaqueDeterministicKey(String name) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKeyFactory skf = SecretKeyFactory.getInstance(name, p);
        char[] password = "correct horse battery staple".toCharArray();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int keyLengthBits = keyLengthBitsFor(name);

        SecretKey a = skf.generateSecret(new PBEKeySpec(password, salt, 10_000, keyLengthBits));
        assertNull(a.getEncoded(), "derived PBKDF2 keys must be opaque, matching every other derived key in this module");

        SecretKey b = skf.generateSecret(new PBEKeySpec(password, salt, 10_000, keyLengthBits));

        String hmacName = "HmacSHA" + name.substring("PBKDF2WithHmacSHA".length());
        Mac macA = Mac.getInstance(hmacName, p);
        macA.init(a);
        byte[] outA = macA.doFinal("determinism check".getBytes());

        Mac macB = Mac.getInstance(hmacName, p);
        macB.init(b);
        byte[] outB = macB.doFinal("determinism check".getBytes());

        assertArrayEquals(outA, outB, "PBKDF2 must be deterministic — same inputs must derive the same key twice");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    void interopsWithJdkSunJCE(String name) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        char[] password = "hunter2 but longer for entropy".toCharArray();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 4096;
        int keyLengthBits = keyLengthBitsFor(name);
        String hmacName = "HmacSHA" + name.substring("PBKDF2WithHmacSHA".length());
        byte[] data = "cross-provider PBKDF2 check".getBytes();

        SecretKey ourKey = SecretKeyFactory.getInstance(name, p)
            .generateSecret(new PBEKeySpec(password, salt, iterations, keyLengthBits));
        Mac ourMac = Mac.getInstance(hmacName, p);
        ourMac.init(ourKey);
        byte[] ourOut = ourMac.doFinal(data);

        SecretKey jdkKey = SecretKeyFactory.getInstance(name) // default SunJCE
            .generateSecret(new PBEKeySpec(password, salt, iterations, keyLengthBits));
        assertNotNull(jdkKey.getEncoded(), "sanity check: JDK's own PBKDF2 key must be a real exportable key");
        assertEquals(keyLengthBits / 8, jdkKey.getEncoded().length);
        Mac jdkMac = Mac.getInstance(hmacName); // default SunJCE
        jdkMac.init(new SecretKeySpec(jdkKey.getEncoded(), hmacName));
        byte[] jdkOut = jdkMac.doFinal(data);

        assertArrayEquals(jdkOut, ourOut,
            name + ": HMAC over identical data with each side's derived key must match, proving identical key material");
    }

    @Test
    void rejectsAKeyLengthThatIsNotAWholeNumberOfBytes() throws Exception {
        // PBEKeySpec's own constructor does not validate this (confirmed
        // live: new PBEKeySpec(pw, salt, iter, 10) constructs fine with
        // getKeyLength()==10) — this genuinely reaches this provider's
        // own validation, unlike an empty salt, which PBEKeySpec's
        // constructor already rejects with IllegalArgumentException
        // before this provider ever sees it.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", p);
        assertThrows(InvalidKeySpecException.class,
            () -> skf.generateSecret(new PBEKeySpec("pw".toCharArray(), new byte[]{1, 2, 3, 4}, 1000, 10)));
    }

    @Test
    void engineGetKeySpecIsRefused() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", p);
        SecretKey key = skf.generateSecret(new PBEKeySpec("pw".toCharArray(), new byte[16], 1000, 256));
        assertThrows(InvalidKeySpecException.class, () -> skf.getKeySpec(key, PBEKeySpec.class),
            "an opaque, token-resident key must never yield a recoverable KeySpec");
    }
}
