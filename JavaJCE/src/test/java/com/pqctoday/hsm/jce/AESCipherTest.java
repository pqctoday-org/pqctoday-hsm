package com.pqctoday.hsm.jce;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.Security;

import static com.pqctoday.hsm.jce.P11Constants.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * AES KeyGenerator + Cipher (GCM/CBC/CTR). Unlike every asymmetric
 * algorithm tested elsewhere in this module, a true cross-verification
 * against an independent codebase (JDK SunJCE or Bouncy Castle) is
 * structurally impossible for a token-*generated* AES key: this
 * provider's whole design point is CKA_EXTRACTABLE=false (plan §6.2 —
 * key material never crosses into the JVM), so there is no raw key
 * value an external library could ever be given to check against. The
 * tests below therefore cross-verify against Bouncy Castle using a
 * KNOWN raw key imported into both this provider (via
 * P11Library.createObject — the same production import path
 * P11AESWrapCipherSpi already needs for foreign keys) and a plain
 * SecretKeySpec for BC — not a hack, just the only way to get
 * independent-codebase verification for a symmetric algorithm whose
 * whole point is that its key never normally exists outside the token.
 */
class AESCipherTest {

    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    void keyGeneratorProducesOpaqueKeysOfTheRequestedSize(int bits) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyGenerator kg = KeyGenerator.getInstance("AES", p);
        kg.init(bits);
        SecretKey key = kg.generateKey();
        assertEquals("AES", key.getAlgorithm());
        assertNull(key.getEncoded(), "generated AES keys must be opaque — no raw key material in the JVM");
    }

    @Test
    void keyGeneratorRejectsNonAesSizes() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyGenerator kg = KeyGenerator.getInstance("AES", p);
        assertThrows(InvalidParameterException.class, () -> kg.init(127));
    }

    @Test
    void gcmSelfRoundTripsWithAndWithoutAad() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        byte[] plaintext = "GCM round trip, plan section 4.3".getBytes();
        byte[] aad = "associated-data".getBytes();

        for (byte[] a : new byte[][]{ new byte[0], aad }) {
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", p);
            enc.init(Cipher.ENCRYPT_MODE, key);
            if (a.length > 0) enc.updateAAD(a);
            byte[] iv = enc.getIV();
            assertNotNull(iv, "module must generate and expose the GCM IV before doFinal");
            assertEquals(12, iv.length);
            byte[] ct = enc.doFinal(plaintext);

            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", p);
            dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            if (a.length > 0) dec.updateAAD(a);
            assertArrayEquals(plaintext, dec.doFinal(ct));
        }
    }

    @Test
    void gcmEncryptRejectsCallerSuppliedIv() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", p);
        byte[] callerIv = new byte[12];
        assertThrows(InvalidAlgorithmParameterException.class,
            () -> enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, callerIv)),
            "plan §4.3: AES-GCM encryption IVs must be module-generated, not caller-supplied");
    }

    @Test
    void gcmIvsAreDistinctAcrossSessionsNotJustWithinOne() throws Exception {
        // Plan §WS-D: the main plan's own W4 verify list marked this
        // "not yet attempted" — module-generated GCM IVs come from
        // C_GenerateRandom (the token's own SP 800-90A DRBG, per
        // generateIv()'s own javadoc), a real cryptographic RNG rather
        // than a per-process counter, so uniqueness across independent
        // sessions is exactly the property worth checking directly
        // rather than assuming from "it's an RNG." Two SEPARATE provider
        // instances (independent P11Library sessions) are used
        // deliberately, not one provider called twice — this is the
        // "across sessions" case the plan item names, not merely
        // "within one session."
        SoftHSMv3Provider p1 = new SoftHSMv3Provider();
        SoftHSMv3Provider p2 = new SoftHSMv3Provider();
        SecretKey key1 = KeyGenerator.getInstance("AES", p1).generateKey();
        SecretKey key2 = KeyGenerator.getInstance("AES", p2).generateKey();

        int n = 64;
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < n; i++) {
            SoftHSMv3Provider p = (i % 2 == 0) ? p1 : p2;
            SecretKey key = (i % 2 == 0) ? key1 : key2;
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", p);
            enc.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = enc.getIV();
            assertTrue(seen.add(java.util.HexFormat.of().formatHex(iv)),
                "module-generated GCM IV repeated across " + n + " encrypts spanning two independent sessions "
                + "— iteration " + i);
        }
        assertEquals(n, seen.size());
    }

    @Test
    void callerGcmIvFlagAllowsAndUsesTheExactSuppliedIv() throws Exception {
        // -Dsofthsmv3.jce.callerGcmIv=true (plan §WS-B's decided fallback
        // for JEP 527 TLS 1.3, whose record cipher MUST supply its own
        // RFC 8446-mandated deterministic nonce). Default off; a real,
        // disclosed narrowing of the module-generated-IV policy while
        // set, not a silent default — restored unconditionally, same
        // discipline as this module's other two runtime flags.
        String prior = System.getProperty("softhsmv3.jce.callerGcmIv");
        try {
            System.setProperty("softhsmv3.jce.callerGcmIv", "true");
            Security.addProvider(new BouncyCastleProvider());
            SoftHSMv3Provider p = new SoftHSMv3Provider();
            byte[] rawKey = new byte[16];
            new java.security.SecureRandom().nextBytes(rawKey);
            long handle = importRawAesKeyReal(p.lib, rawKey, false);
            SecretKey ourKey = new P11Key.Secret(p.lib, handle, "AES");

            byte[] callerIv = new byte[12];
            new java.security.SecureRandom().nextBytes(callerIv);
            byte[] plaintext = "caller-supplied IV via the flag".getBytes();

            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", p);
            enc.init(Cipher.ENCRYPT_MODE, ourKey, new GCMParameterSpec(128, callerIv));
            assertArrayEquals(callerIv, enc.getIV(), "the Cipher must use the EXACT IV supplied, not a different one");
            byte[] ct = enc.doFinal(plaintext);

            // Prove it's genuinely the same construction an independent
            // implementation would produce with the same key/IV/plaintext
            // — decrypt with Bouncy Castle, not just round-trip with
            // ourselves.
            SecretKey bcKey = new SecretKeySpec(rawKey, "AES");
            Cipher bcDec = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            bcDec.init(Cipher.DECRYPT_MODE, bcKey, new GCMParameterSpec(128, callerIv));
            assertArrayEquals(plaintext, bcDec.doFinal(ct));
        } finally {
            if (prior == null) {
                System.clearProperty("softhsmv3.jce.callerGcmIv");
            } else {
                System.setProperty("softhsmv3.jce.callerGcmIv", prior);
            }
        }
    }

    @Test
    void gcmDecryptRequiresAnIv() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", p);
        assertThrows(java.security.InvalidKeyException.class, () -> dec.init(Cipher.DECRYPT_MODE, key),
            "decrypting without the IV the data was encrypted with must fail at init(), not silently");
    }

    @ParameterizedTest
    @ValueSource(strings = {"AES/CBC/NoPadding", "AES/CBC/PKCS5Padding", "AES/CTR/NoPadding"})
    void cbcAndCtrSelfRoundTrip(String transform) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        // CBC/NoPadding requires an exact 16-byte block multiple; CTR and
        // CBC+PKCS5 are both fine with arbitrary-length plaintext.
        byte[] plaintext = transform.equals("AES/CBC/NoPadding")
            ? "0123456789ABCDEF0123456789ABCDEF".getBytes() // 32 bytes = 2 blocks
            : "arbitrary length plaintext for a stream-shaped or padded mode".getBytes();

        Cipher enc = Cipher.getInstance(transform, p);
        enc.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = enc.getIV();
        assertNotNull(iv);
        byte[] ct = enc.doFinal(plaintext);

        Cipher dec = Cipher.getInstance(transform, p);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        assertArrayEquals(plaintext, dec.doFinal(ct));
    }

    @Test
    void gcmInteropsWithBouncyCastleUsingAKnownImportedKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKey = new byte[32];
        new java.security.SecureRandom().nextBytes(rawKey);
        SecretKey bcKey = new SecretKeySpec(rawKey, "AES");
        long handle = importRawAesKeyReal(p.lib, rawKey, false);
        SecretKey ourKey = new P11Key.Secret(p.lib, handle, "AES");

        byte[] plaintext = "BC AES-GCM cross-verify".getBytes();
        byte[] aad = "aad".getBytes();

        // BC encrypts (caller-supplied IV, fine for BC — our own IV policy
        // only restricts THIS provider's own encrypt path), we decrypt.
        byte[] bcIv = new byte[12];
        new java.security.SecureRandom().nextBytes(bcIv);
        Cipher bcEnc = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        bcEnc.init(Cipher.ENCRYPT_MODE, bcKey, new GCMParameterSpec(128, bcIv));
        bcEnc.updateAAD(aad);
        byte[] bcCt = bcEnc.doFinal(plaintext);

        Cipher ourDec = Cipher.getInstance("AES/GCM/NoPadding", p);
        ourDec.init(Cipher.DECRYPT_MODE, ourKey, new GCMParameterSpec(128, bcIv));
        ourDec.updateAAD(aad);
        assertArrayEquals(plaintext, ourDec.doFinal(bcCt),
            "our provider must decrypt Bouncy Castle's own AES-GCM ciphertext given the same raw key");

        // We encrypt (our own module-generated IV), BC decrypts using the
        // IV we report via getIV().
        Cipher ourEnc = Cipher.getInstance("AES/GCM/NoPadding", p);
        ourEnc.init(Cipher.ENCRYPT_MODE, ourKey);
        ourEnc.updateAAD(aad);
        byte[] ourIv = ourEnc.getIV();
        byte[] ourCt = ourEnc.doFinal(plaintext);

        Cipher bcDec = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        bcDec.init(Cipher.DECRYPT_MODE, bcKey, new GCMParameterSpec(128, ourIv));
        bcDec.updateAAD(aad);
        assertArrayEquals(plaintext, bcDec.doFinal(ourCt),
            "Bouncy Castle must decrypt our provider's own AES-GCM ciphertext given the same raw key");
    }

    @Test
    void aesWrapRoundTripsAndInteropsWithBouncyCastle() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawWrapKey = new byte[32];
        new java.security.SecureRandom().nextBytes(rawWrapKey);
        long wrapHandle = importRawAesKeyReal(p.lib, rawWrapKey, false);
        SecretKey ourWrapKey = new P11Key.Secret(p.lib, wrapHandle, "AES");
        SecretKey bcWrapKey = new SecretKeySpec(rawWrapKey, "AES");

        // The target key being wrapped must itself be CKA_EXTRACTABLE=true —
        // confirmed live: a plain KeyGenerator-produced key (deliberately
        // non-extractable, per P11AESKeyGeneratorSpi's L3 template) is
        // correctly REJECTED by the token with CKR_KEY_UNEXTRACTABLE when
        // wrapping is attempted. That is the L3 non-export policy working
        // as intended, not a bug: this provider's own "vault" keys can
        // never be wrapped back out, only externally-sourced/ephemeral
        // keys explicitly imported as extractable (the realistic AES-KW
        // use case — wrapping a short-lived transport key) can be.
        byte[] rawTargetKey = new byte[32];
        new java.security.SecureRandom().nextBytes(rawTargetKey);
        long targetHandle = importRawAesKeyReal(p.lib, rawTargetKey, true);
        SecretKey targetKey = new P11Key.Secret(p.lib, targetHandle, "AES");

        Cipher ourWrapper = Cipher.getInstance("AESWrap", p);
        ourWrapper.init(Cipher.WRAP_MODE, ourWrapKey);
        byte[] wrapped = ourWrapper.wrap(targetKey);

        // BC must be able to unwrap what we wrapped (independent RFC 3394 implementation).
        Cipher bcUnwrapper = Cipher.getInstance("AESWrap", "BC");
        bcUnwrapper.init(Cipher.UNWRAP_MODE, bcWrapKey);
        SecretKey bcUnwrapped = (SecretKey) bcUnwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        assertEquals(32, bcUnwrapped.getEncoded().length);

        // And our own unwrap must recover a usable key (round trip through GCM).
        Cipher ourUnwrapper = Cipher.getInstance("AESWrap", p);
        ourUnwrapper.init(Cipher.UNWRAP_MODE, ourWrapKey);
        SecretKey recovered = (SecretKey) ourUnwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        byte[] plaintext = "wrap/unwrap round trip".getBytes();
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", p);
        enc.init(Cipher.ENCRYPT_MODE, targetKey);
        byte[] iv = enc.getIV();
        byte[] ct = enc.doFinal(plaintext);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", p);
        dec.init(Cipher.DECRYPT_MODE, recovered, new GCMParameterSpec(128, iv));
        assertArrayEquals(plaintext, dec.doFinal(ct),
            "the unwrapped key must decrypt what the original (wrapped) key encrypted");
    }

    @Test
    void gcmOutputSizeIsExactNotAConservativeUpperBound() throws Exception {
        // A real bug found live via plan §WS-B's TLS spike: JDK 27's own
        // SSLCipher (the TLS 1.3 record cipher) uses the ByteBuffer-based
        // Cipher.doFinal(ByteBuffer, ByteBuffer) overload, whose default
        // CipherSpi bridging pre-sizes the output buffer from
        // engineGetOutputSize()'s return value and then STRICTLY requires
        // the real written length to equal it — "Cipher buffering error"
        // otherwise. This provider's engineGetOutputSize used to return a
        // padded inputLen+32 "conservative upper bound", which the
        // ordinary byte[]-based doFinal() every other test here uses
        // never noticed was wrong, since that path doesn't care.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        byte[] plaintext = "exact output size check, GCM tag is 16 bytes".getBytes();

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", p);
        enc.init(Cipher.ENCRYPT_MODE, key);
        assertEquals(plaintext.length + 16, enc.getOutputSize(plaintext.length),
            "GCM encrypt output size must be exactly plaintext + 16-byte tag, not a padded estimate");

        // Exercise the actual ByteBuffer path JSSE uses, not just
        // getOutputSize() in isolation — this is what a wrong estimate
        // above would have broken in practice.
        ByteBuffer inBuf = ByteBuffer.wrap(plaintext);
        ByteBuffer outBuf = ByteBuffer.allocate(enc.getOutputSize(plaintext.length));
        int written = enc.doFinal(inBuf, outBuf);
        assertEquals(outBuf.capacity(), written,
            "doFinal(ByteBuffer, ByteBuffer) must write exactly the pre-computed output size — this is JSSE's own strict check");
        byte[] iv = enc.getIV();

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", p);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        assertEquals(plaintext.length, dec.getOutputSize(written),
            "GCM decrypt output size must be exactly ciphertext-and-tag minus the 16-byte tag");
        outBuf.flip();
        ByteBuffer decOut = ByteBuffer.allocate(dec.getOutputSize(written));
        int decWritten = dec.doFinal(outBuf, decOut);
        assertEquals(plaintext.length, decWritten);
        decOut.flip();
        byte[] recoveredPlaintext = new byte[decWritten];
        decOut.get(recoveredPlaintext);
        assertArrayEquals(plaintext, recoveredPlaintext);
    }

    // ── Item 2: CKM_AES_CCM ─────────────────────────────────────────────

    @Test
    void ccmSelfRoundTripsWithAndWithoutAad() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        byte[] plaintext = "CCM round trip, item 2".getBytes();
        byte[] aad = "associated-data".getBytes();

        for (byte[] a : new byte[][]{ new byte[0], aad }) {
            Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", p);
            enc.init(Cipher.ENCRYPT_MODE, key);
            if (a.length > 0) enc.updateAAD(a);
            byte[] iv = enc.getIV();
            assertNotNull(iv, "module must generate and expose the CCM nonce before doFinal");
            assertEquals(12, iv.length);
            byte[] ct = enc.doFinal(plaintext);
            assertEquals(plaintext.length + 16, ct.length, "default CCM tag is 128 bits (16 bytes)");

            Cipher dec = Cipher.getInstance("AES/CCM/NoPadding", p);
            dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            if (a.length > 0) dec.updateAAD(a);
            assertArrayEquals(plaintext, dec.doFinal(ct));
        }
    }

    @Test
    void ccmEncryptRejectsCallerSuppliedIv() throws Exception {
        // Same SP 800-38D §8.2-derived AEAD-nonce-uniqueness policy as
        // GCM's own rejection above, applied to CCM's nonce too.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", p);
        byte[] callerIv = new byte[12];
        assertThrows(InvalidAlgorithmParameterException.class,
            () -> enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, callerIv)));
    }

    @Test
    void ccmOutputSizeIsExact() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        SecretKey key = KeyGenerator.getInstance("AES", p).generateKey();
        byte[] plaintext = "exact CCM output size check".getBytes();

        Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", p);
        enc.init(Cipher.ENCRYPT_MODE, key);
        assertEquals(plaintext.length + 16, enc.getOutputSize(plaintext.length));
        byte[] ct = enc.doFinal(plaintext);
        byte[] iv = enc.getIV();

        Cipher dec = Cipher.getInstance("AES/CCM/NoPadding", p);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        assertEquals(plaintext.length, dec.getOutputSize(ct.length));
        assertArrayEquals(plaintext, dec.doFinal(ct));
    }

    @Test
    void ccmInteropsWithBouncyCastleUsingAKnownImportedKey() throws Exception {
        // No standard javax.crypto.spec.CCMParameterSpec exists anywhere
        // in the JDK (confirmed against the real javax.crypto.spec javadoc
        // before writing this class — see P11AESCipherSpi's Mode.CCM
        // handling for the same finding) — this Cipher reuses the
        // standard GCMParameterSpec (nonce + tag length in bits, exactly
        // the pair CCM needs) rather than inventing a new class, following
        // this file's own GCM precedent. Bouncy Castle's own "CCM"/"AES/CCM/
        // NoPadding" Cipher does NOT accept GCMParameterSpec (confirmed
        // live via bytecode/runtime probes before writing this test — it
        // only accepts IvParameterSpec or its own
        // org.bouncycastle.jcajce.spec.AEADParameterSpec), and its default
        // tag length under a bare IvParameterSpec is 64 bits, NOT this
        // class's own 128-bit default (also confirmed live) — so this
        // test always passes an explicit, matching 128-bit tag length on
        // both sides rather than relying on either library's default.
        Security.addProvider(new BouncyCastleProvider());
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        byte[] rawKey = new byte[16];
        new java.security.SecureRandom().nextBytes(rawKey);
        SecretKey bcKey = new SecretKeySpec(rawKey, "AES");
        long handle = importRawAesKeyReal(p.lib, rawKey, false);
        SecretKey ourKey = new P11Key.Secret(p.lib, handle, "AES");

        byte[] plaintext = "BC AES-CCM cross-verify".getBytes();
        byte[] aad = "aad".getBytes();
        byte[] nonce = new byte[12];
        new java.security.SecureRandom().nextBytes(nonce);

        // BC encrypts, we decrypt.
        Cipher bcEnc = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        bcEnc.init(Cipher.ENCRYPT_MODE, bcKey, new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, 128, aad));
        byte[] bcCt = bcEnc.doFinal(plaintext);

        Cipher ourDec = Cipher.getInstance("AES/CCM/NoPadding", p);
        ourDec.init(Cipher.DECRYPT_MODE, ourKey, new GCMParameterSpec(128, nonce));
        ourDec.updateAAD(aad);
        assertArrayEquals(plaintext, ourDec.doFinal(bcCt),
            "our provider must decrypt Bouncy Castle's own AES-CCM ciphertext given the same raw key");

        // We encrypt (caller-supplied nonce, via the same opt-in flag
        // GCM's own interop test above uses, so both sides use the
        // identical nonce for this comparison), BC decrypts.
        String prior = System.getProperty("softhsmv3.jce.callerGcmIv");
        try {
            System.setProperty("softhsmv3.jce.callerGcmIv", "true");
            Cipher ourEnc = Cipher.getInstance("AES/CCM/NoPadding", p);
            ourEnc.init(Cipher.ENCRYPT_MODE, ourKey, new GCMParameterSpec(128, nonce));
            ourEnc.updateAAD(aad);
            byte[] ourCt = ourEnc.doFinal(plaintext);

            Cipher bcDec = Cipher.getInstance("AES/CCM/NoPadding", "BC");
            bcDec.init(Cipher.DECRYPT_MODE, bcKey, new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, 128, aad));
            assertArrayEquals(plaintext, bcDec.doFinal(ourCt),
                "Bouncy Castle must decrypt our provider's own AES-CCM ciphertext given the same raw key");
        } finally {
            if (prior == null) {
                System.clearProperty("softhsmv3.jce.callerGcmIv");
            } else {
                System.setProperty("softhsmv3.jce.callerGcmIv", prior);
            }
        }
    }

    private static long importRawAesKeyReal(P11Library lib, byte[] raw, boolean extractable) {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_AES),
            P11Library.attr(CKA_VALUE, raw),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, extractable),
            P11Library.attrBool(CKA_ENCRYPT, true),
            P11Library.attrBool(CKA_DECRYPT, true),
            P11Library.attrBool(CKA_WRAP, true),
            P11Library.attrBool(CKA_UNWRAP, true),
        };
        return lib.createObject(tmpl);
    }
}
