package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;

import static com.pqctoday.hsm.jce.P11Constants.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * HKDF-SHA256/384/512 via javax.crypto.KDF. RFC 5869 Test Case 1 gives a
 * real published KAT (not just a JDK cross-verify) — confirmed first,
 * live, that JDK 27's own SunJCE computes exactly that published value
 * before trusting it as this test's oracle for the other digest sizes.
 */
class HKDFTest {

    // RFC 5869 §A.1, Test Case 1 (SHA-256).
    private static final byte[] RFC5869_IKM = HexFormat.of().parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    private static final byte[] RFC5869_SALT = HexFormat.of().parseHex("000102030405060708090a0b0c");
    private static final byte[] RFC5869_INFO = HexFormat.of().parseHex("f0f1f2f3f4f5f6f7f8f9");
    private static final byte[] RFC5869_OKM = HexFormat.of().parseHex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    private static long importRaw(P11Library lib, byte[] raw) {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attr(CKA_VALUE, raw),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_DERIVE, true),
        };
        return lib.createObject(tmpl);
    }

    @Test
    void extractThenExpandMatchesTheRfc5869KnownAnswer() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KDF kdf = KDF.getInstance("HKDF-SHA256", p);

        SecretKey ikm = new P11Key.Secret(p.lib, importRaw(p.lib, RFC5869_IKM), "Generic");
        SecretKey salt = new SecretKeySpec(RFC5869_SALT, "Generic"); // foreign key — has real getEncoded()
        var spec = HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(salt).thenExpand(RFC5869_INFO, 42);

        byte[] okm = kdf.deriveData(spec);
        assertArrayEquals(RFC5869_OKM, okm, "must match RFC 5869 §A.1 Test Case 1 exactly");
    }

    @Test
    void extractThenExpandInTwoStepsMatchesOneShot() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KDF kdf = KDF.getInstance("HKDF-SHA256", p);

        SecretKey ikm = new P11Key.Secret(p.lib, importRaw(p.lib, RFC5869_IKM), "Generic");
        SecretKey salt = new SecretKeySpec(RFC5869_SALT, "Generic");

        var extractSpec = HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(salt).extractOnly();
        SecretKey prk = kdf.deriveKey("Generic", extractSpec);
        assertNull(prk.getEncoded(), "the derived PRK must stay opaque — extract-then-expand across two calls "
            + "must never require the PRK to leave the token");

        var expandSpec = HKDFParameterSpec.expandOnly(prk, RFC5869_INFO, 42);
        byte[] okm = kdf.deriveData(expandSpec);
        assertArrayEquals(RFC5869_OKM, okm, "two-step extract-then-expand must match the one-shot result");
    }

    @Test
    void extractOnlyProducesAHashSizedPrk() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KDF kdf = KDF.getInstance("HKDF-SHA384", p);
        SecretKey ikm = new P11Key.Secret(p.lib, importRaw(p.lib, RFC5869_IKM), "Generic");
        var spec = HKDFParameterSpec.ofExtract().addIKM(ikm).extractOnly();
        byte[] prk = kdf.deriveData(spec);
        assertEquals(48, prk.length, "SHA-384's PRK must be exactly the hash's 48-byte output size");
    }

    @Test
    void rejectsMultipleIkms() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KDF kdf = KDF.getInstance("HKDF-SHA256", p);
        SecretKey a = new SecretKeySpec(new byte[16], "Generic");
        SecretKey b = new SecretKeySpec(new byte[16], "Generic");
        var spec = HKDFParameterSpec.ofExtract().addIKM(a).addIKM(b).extractOnly();
        assertThrows(InvalidAlgorithmParameterException.class, () -> kdf.deriveData(spec));
    }

    @Test
    void rejectsMultipleSalts() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KDF kdf = KDF.getInstance("HKDF-SHA256", p);
        SecretKey ikm = new SecretKeySpec(new byte[16], "Generic");
        SecretKey s1 = new SecretKeySpec(new byte[8], "Generic");
        SecretKey s2 = new SecretKeySpec(new byte[8], "Generic");
        var spec = HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(s1).addSalt(s2).extractOnly();
        assertThrows(InvalidAlgorithmParameterException.class, () -> kdf.deriveData(spec));
    }

    @Test
    void rejectsAnOpaqueKeyAsSalt() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KDF kdf = KDF.getInstance("HKDF-SHA256", p);
        SecretKey ikm = new SecretKeySpec(new byte[16], "Generic");
        SecretKey opaqueSalt = new P11Key.Secret(p.lib, importRaw(p.lib, new byte[16]), "Generic");
        var spec = HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(opaqueSalt).extractOnly();
        assertThrows(InvalidAlgorithmParameterException.class, () -> kdf.deriveData(spec),
            "this provider's own opaque keys can never be used as an HKDF salt (engine rejects CKF_HKDF_SALT_KEY)");
    }

    @Test
    void interopsWithJdkSunJCEForSha384AndSha512() throws Exception {
        for (String name : List.of("HKDF-SHA384", "HKDF-SHA512")) {
            SoftHSMv3Provider p = new SoftHSMv3Provider();
            byte[] ikmBytes = new byte[32];
            byte[] saltBytes = new byte[16];
            byte[] info = "context info".getBytes();
            new SecureRandom().nextBytes(ikmBytes);
            new SecureRandom().nextBytes(saltBytes);

            SecretKey ourIkm = new P11Key.Secret(p.lib, importRaw(p.lib, ikmBytes), "Generic");
            SecretKey ourSalt = new SecretKeySpec(saltBytes, "Generic");
            KDF ours = KDF.getInstance(name, p);
            byte[] ourOkm = ours.deriveData(
                HKDFParameterSpec.ofExtract().addIKM(ourIkm).addSalt(ourSalt).thenExpand(info, 64));

            KDF jdk = KDF.getInstance(name); // default SunJCE
            SecretKey jdkIkm = new SecretKeySpec(ikmBytes, "Generic");
            SecretKey jdkSalt = new SecretKeySpec(saltBytes, "Generic");
            byte[] jdkOkm = jdk.deriveData(
                HKDFParameterSpec.ofExtract().addIKM(jdkIkm).addSalt(jdkSalt).thenExpand(info, 64));

            assertArrayEquals(jdkOkm, ourOkm, name + " must match JDK SunJCE's own HKDF for the same inputs");
        }
    }
}
