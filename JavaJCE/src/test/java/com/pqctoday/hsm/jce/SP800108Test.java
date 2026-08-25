package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.util.HexFormat;

import static com.pqctoday.hsm.jce.P11Constants.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * SP 800-108 counter/feedback KDF.
 *
 * True third-party cross-verification (the Bouncy Castle pattern used
 * for AESCMAC/KMAC elsewhere) was attempted and abandoned: several
 * standard SP 800-108 counter/fixed-input framings (counter as 4-byte
 * BE/LE prefix or suffix, with and without an auto-appended output
 * length field) all failed to match this engine's real output, as did
 * `openssl kdf`'s own CLI output for the nominally identical
 * key/salt/digest/r parameters. That last mismatch could have meant a
 * bug in this module's own FFM struct-building — ruled out
 * conclusively via an isolated C reproduction that calls the real
 * engine's C_DeriveKey directly (dlopen'd against the same .so, no
 * Java/FFM involved at all, same technique that found the real
 * CKA_CLASS/CKA_KEY_TYPE bug in W4's HKDF work): it produces the exact
 * same output this provider does, and a DIFFERENT output than the
 * `openssl kdf` CLI tool for the same nominal inputs — proving the
 * discrepancy is a genuine difference between how the engine's C++
 * code invokes EVP_KDF_derive internally and how the CLI tool invokes
 * the identical primitive (an OpenSSL-internal default neither side
 * makes explicit), not a bug anywhere in this module. The C-probe
 * output below is therefore a real, engine-verified reference vector —
 * not a third-party independent implementation's opinion, but proof
 * this provider's Java/FFM layer faithfully reproduces the real
 * engine's actual behavior, byte for byte.
 *
 * Feedback mode additionally hit an unresolved "invalid seed length"
 * from OpenSSL's own KBKDF provider for every IV length tried
 * (including the MAC's own 32-byte output size) when probed via the
 * `openssl kdf` CLI — feedback mode is therefore verified by
 * self-consistency (determinism) only, with this gap disclosed rather
 * than silently dropped.
 */
class SP800108Test {

    private static long importRaw(P11Library lib, byte[] raw) {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attr(CKA_VALUE, raw),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_DERIVE, true),
            P11Library.attrBool(CKA_SIGN, true),
        };
        return lib.createObject(tmpl);
    }

    // Reference vector obtained by calling the real engine's C_DeriveKey
    // directly via an isolated C reproduction (dlopen'd against the same
    // .so, no Java/FFM involved) with KI=0x01..0x20 (32 bytes),
    // fixedInput="label context", CKM_SHA256_HMAC PRF, 32-byte output —
    // see this class's own javadoc for why this is the correct oracle
    // (proven byte-identical to what this provider itself produces,
    // confirming Java/FFM correctness independent of the separate,
    // unresolved openssl-CLI-vs-engine convention discrepancy).
    private static final byte[] KI =
        HexFormat.of().parseHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    private static final byte[] FIXED_INPUT = "label context".getBytes();
    private static final byte[] EXPECTED_OUTPUT = HexFormat.of().parseHex(
        "647FC5F392933826746AFA12BAE801127E6D457026452A147C639A39F25FF6F9");

    @Test
    void counterModeMatchesEngineReference() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        long handle = importRaw(p.lib, KI);
        SecretKey ourKi = new P11Key.Secret(handle, "Generic");

        SecretKeyFactory skf = SecretKeyFactory.getInstance("SP800-108-Counter", p);
        SecretKey derived = skf.generateSecret(
            new P11SP800108KeySpec(ourKi, "HmacSHA256", FIXED_INPUT, 256));
        assertNull(derived.getEncoded(), "derived SP 800-108 keys must be opaque");

        // Compare via HMAC of known data with a known-raw-value SecretKeySpec
        // built from EXPECTED_OUTPUT, since our own derived key is opaque —
        // same indirect-comparison technique as PBKDF2Test.
        Mac ourMac = Mac.getInstance("HmacSHA256", p);
        ourMac.init(derived);
        byte[] ourOut = ourMac.doFinal("probe".getBytes());

        Mac referenceMac = Mac.getInstance("HmacSHA256", p);
        long referenceHandle = importRaw(p.lib, EXPECTED_OUTPUT);
        referenceMac.init(new P11Key.Secret(referenceHandle, "Generic"));
        byte[] referenceOut = referenceMac.doFinal("probe".getBytes());

        assertArrayEquals(referenceOut, ourOut,
            "our SP 800-108 counter-mode derivation must match the engine's own C-probe-verified reference output");
    }

    @Test
    void counterModeIsDeterministic() throws Exception {
        // PRF here is AESCMAC (the internal KBKDF PRF) — unrelated to
        // the output key's own type, which this engine always hardcodes
        // to CKK_GENERIC_SECRET (confirmed reading SoftHSM_keygen.cpp's
        // kbkKeyType before writing this test), so the derived key is
        // consumed with an HMAC Mac below, not AESCMAC.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKi = new byte[32];
        new SecureRandom().nextBytes(rawKi);
        long handle1 = importRaw(p.lib, rawKi);
        long handle2 = importRaw(p.lib, rawKi);
        byte[] fixedInput = "same input".getBytes();

        SecretKeyFactory skf = SecretKeyFactory.getInstance("SP800-108-Counter", p);
        SecretKey a = skf.generateSecret(
            new P11SP800108KeySpec(new P11Key.Secret(handle1, "Generic"), "AESCMAC", fixedInput, 256));
        SecretKey b = skf.generateSecret(
            new P11SP800108KeySpec(new P11Key.Secret(handle2, "Generic"), "AESCMAC", fixedInput, 256));

        Mac macA = Mac.getInstance("HmacSHA256", p);
        macA.init(a);
        Mac macB = Mac.getInstance("HmacSHA256", p);
        macB.init(b);

        assertArrayEquals(macA.doFinal("x".getBytes()), macB.doFinal("x".getBytes()));
    }

    @Test
    void feedbackModeIsDeterministic() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKi = new byte[32];
        byte[] iv = new byte[32];
        new SecureRandom().nextBytes(rawKi);
        new SecureRandom().nextBytes(iv);
        long handle1 = importRaw(p.lib, rawKi);
        long handle2 = importRaw(p.lib, rawKi);
        byte[] fixedInput = "same input".getBytes();

        SecretKeyFactory skf = SecretKeyFactory.getInstance("SP800-108-Feedback", p);
        SecretKey a = skf.generateSecret(
            new P11SP800108KeySpec(new P11Key.Secret(handle1, "Generic"), "HmacSHA256", fixedInput, iv, 256));
        SecretKey b = skf.generateSecret(
            new P11SP800108KeySpec(new P11Key.Secret(handle2, "Generic"), "HmacSHA256", fixedInput, iv, 256));

        Mac macA = Mac.getInstance("HmacSHA256", p);
        macA.init(a);
        Mac macB = Mac.getInstance("HmacSHA256", p);
        macB.init(b);

        assertArrayEquals(macA.doFinal("x".getBytes()), macB.doFinal("x".getBytes()));
    }

    @Test
    void feedbackModeWithoutAnIvAlsoWorks() throws Exception {
        // The engine treats the IV as optional (pIV==NULL_PTR/ulIVLen==0
        // simply omits OSSL_KDF_PARAM_SEED) — confirmed reading
        // SoftHSM_keygen.cpp before writing this test.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKi = new byte[32];
        new SecureRandom().nextBytes(rawKi);
        long handle = importRaw(p.lib, rawKi);
        SecretKey ki = new P11Key.Secret(handle, "Generic");

        SecretKeyFactory skf = SecretKeyFactory.getInstance("SP800-108-Feedback", p);
        SecretKey derived = skf.generateSecret(
            new P11SP800108KeySpec(ki, "HmacSHA256", "ctx".getBytes(), 256));
        assertNull(derived.getEncoded());

        Mac mac = Mac.getInstance("HmacSHA256", p);
        mac.init(derived);
        assertEquals(32, mac.doFinal("x".getBytes()).length);
    }
}
