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
    void multipleIkmsAreConcatenatedMatchingJdksOwnReferenceHkdf() throws Exception {
        // Real, live need (plan §W6): JEP 527 hybrid TLS 1.3's key
        // schedule hands this KDF a two-element ikms() list (the
        // classical ECDH-as-KEM secret, then the PQ KEM secret) and
        // expects "concatenate, then HKDF-Extract" — confirmed from
        // JDK 27's own com.sun.crypto.provider.HKDFKeyDerivation source
        // (consolidateKeyMaterial is a plain concatenation loop, nothing
        // more), not assumed. Proven here against SunJCE's own actual
        // reference implementation with the SAME two IKMs, not just
        // internal self-consistency.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey a = new SecretKeySpec("first-ikm-secret".getBytes(), "Generic");
        SecretKey b = new SecretKeySpec("second-ikm-secret".getBytes(), "Generic");
        var spec = HKDFParameterSpec.ofExtract().addIKM(a).addIKM(b).extractOnly();

        byte[] ours = KDF.getInstance("HKDF-SHA256", p).deriveData(spec);
        byte[] jdks = KDF.getInstance("HKDF-SHA256").deriveData(spec); // default SunJCE
        assertEquals(32, ours.length);
        assertArrayEquals(jdks, ours,
            "multi-IKM HKDF must match JDK's own reference implementation byte-for-byte");
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
    void opaqueSaltIsAcceptedViaSaltKeyHandle() throws Exception {
        // Was rejectsAnOpaqueKeyAsSalt until the engine gained real
        // CKF_HKDF_SALT_KEY support (plan §WS-A, 2026-08-25) — the exact
        // gap plan §W6's live TLS spike hit: JEP 527 hybrid TLS 1.3's key
        // schedule needs to chain a previous (opaque) derived secret back
        // in as the next Extract step's salt, which this provider's own
        // "no plaintext key export" opaque keys could not previously
        // satisfy at all. Proven correct, not just "doesn't throw
        // anymore": derive with the opaque salt-by-handle, then derive
        // again with the SAME salt bytes as a plain SecretKeySpec on
        // JDK's own reference HKDF ("HKDF-SHA256" with no explicit
        // provider) — byte-for-byte match is the real proof.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] ikmBytes = "opaque-salt-test-ikm".getBytes();
        byte[] saltBytes = "opaque-salt-test-salt16".getBytes();
        SecretKey ikm = new SecretKeySpec(ikmBytes, "Generic");
        SecretKey opaqueSalt = new P11Key.Secret(p.lib, importRaw(p.lib, saltBytes), "Generic");
        var spec = HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(opaqueSalt).extractOnly();

        byte[] ours = KDF.getInstance("HKDF-SHA256", p).deriveData(spec);

        SecretKey plainSalt = new SecretKeySpec(saltBytes, "Generic");
        var jdkSpec = HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(plainSalt).extractOnly();
        byte[] jdks = KDF.getInstance("HKDF-SHA256").deriveData(jdkSpec); // default SunJCE

        assertEquals(32, ours.length);
        assertArrayEquals(jdks, ours,
            "salt-by-handle must key HKDF-Extract on the salt key's real CKA_VALUE, matching JDK's own reference HKDF given the same salt bytes");
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

    @Test
    void extractableHkdfFallbackFlagYieldsANonOpaqueKey() throws Exception {
        // -Dsofthsmv3.jce.extractableHkdf=true (plan §WS-A's decided
        // fallback for an engine build predating CKF_HKDF_SALT_KEY) — a
        // real, disclosed narrowing of engineDeriveKey's opacity, off by
        // default. System property is global JVM state (Surefire runs
        // every test class in one JVM by default), so this restores it
        // unconditionally in a finally block regardless of outcome —
        // same discipline as AuthProviderTest's own token-wide-state care.
        String prior = System.getProperty("softhsmv3.jce.extractableHkdf");
        try {
            System.setProperty("softhsmv3.jce.extractableHkdf", "true");
            SoftHSMv3Provider p = new SoftHSMv3Provider();
            SecretKey ikm = new SecretKeySpec("fallback-flag-test-ikm".getBytes(), "Generic");
            var spec = HKDFParameterSpec.ofExtract().addIKM(ikm).extractOnly();
            SecretKey derived = KDF.getInstance("HKDF-SHA256", p).deriveKey("Generic", spec);
            assertFalse(derived instanceof P11Key.Secret,
                "with the flag set, engineDeriveKey must NOT return this provider's opaque key type");
            assertNotNull(derived.getEncoded(), "with the flag set, the derived key must be extractable");
            assertEquals(32, derived.getEncoded().length);
        } finally {
            if (prior == null) {
                System.clearProperty("softhsmv3.jce.extractableHkdf");
            } else {
                System.setProperty("softhsmv3.jce.extractableHkdf", prior);
            }
        }
    }

    @Test
    void withoutTheFallbackFlagEngineDeriveKeyStaysOpaque() throws Exception {
        // The default (flag unset) behavior — regression guard so the
        // opt-in fallback above can never become the silent default.
        assertNull(System.getProperty("softhsmv3.jce.extractableHkdf"),
            "this test assumes no other test left the fallback flag set — a leaked property would invalidate it");
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey ikm = new SecretKeySpec("default-opaque-test-ikm".getBytes(), "Generic");
        var spec = HKDFParameterSpec.ofExtract().addIKM(ikm).extractOnly();
        SecretKey derived = KDF.getInstance("HKDF-SHA256", p).deriveKey("Generic", spec);
        assertTrue(derived instanceof P11Key.Secret, "by default engineDeriveKey must return this provider's opaque key type");
        assertNull(derived.getEncoded(), "by default the derived key must stay opaque");
    }

    @Test
    void deriveKeyWithAesAlgorithmProducesAGenuineAesKeyUsableByThisProvidersOwnCipher() throws Exception {
        // Real, live need (plan §WS-B): the engine's CKM_HKDF_DERIVE
        // always produces a CKK_GENERIC_SECRET object regardless of the
        // requested algorithm label — this provider's own AES/GCM Cipher
        // then rejects it with CKR_KEY_TYPE_INCONSISTENT. JDK 27's own
        // SSLTrafficKeyDerivation requests exactly "AES" for the TLS
        // record cipher's traffic key, so deriveKey("AES", spec) must
        // produce a key this provider's own Cipher can actually use.
        //
        // Correctness proven two ways: (1) the key round-trips through
        // this provider's own AES/GCM Cipher; (2) the SAME derivation,
        // done independently via JDK's own reference HKDF with an
        // extractable IKM, produces byte-identical raw key material —
        // confirming the re-import preserves the derived value exactly,
        // not just that *some* usable AES key came out.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] ikmBytes = "aes-traffic-key-test-ikm".getBytes();
        byte[] saltBytes = "aes-traffic-key-salt".getBytes();
        byte[] info = "tls13 key".getBytes();
        SecretKey ikm = new SecretKeySpec(ikmBytes, "Generic");
        SecretKey salt = new SecretKeySpec(saltBytes, "Generic");
        var spec = HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(salt)
            .thenExpand(info, 16); // AES-128

        SecretKey aesKey = KDF.getInstance("HKDF-SHA256", p).deriveKey("AES", spec);
        assertEquals("AES", aesKey.getAlgorithm());
        assertNull(aesKey.getEncoded(), "the re-imported AES key must still be opaque, like every other AES key this provider produces");

        byte[] plaintext = "TLS record plaintext".getBytes();
        var enc = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", p);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = enc.getIV();
        byte[] ct = enc.doFinal(plaintext);
        var dec = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", p);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, aesKey, new javax.crypto.spec.GCMParameterSpec(128, iv));
        assertArrayEquals(plaintext, dec.doFinal(ct));

        // Independent re-derivation via JDK's own reference HKDF (no
        // provider), same inputs, to get the actual raw key bytes for comparison.
        byte[] jdkOkm = KDF.getInstance("HKDF-SHA256").deriveData(
            HKDFParameterSpec.ofExtract().addIKM(new SecretKeySpec(ikmBytes, "Generic"))
                .addSalt(new SecretKeySpec(saltBytes, "Generic")).thenExpand(info, 16));
        SecretKey jdkAesKey = new SecretKeySpec(jdkOkm, "AES");
        var jdkDec = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding"); // default SunJCE
        jdkDec.init(javax.crypto.Cipher.DECRYPT_MODE, jdkAesKey, new javax.crypto.spec.GCMParameterSpec(128, iv));
        assertArrayEquals(plaintext, jdkDec.doFinal(ct),
            "the re-imported AES key's raw value must exactly match JDK's own reference HKDF derivation");
    }
}
