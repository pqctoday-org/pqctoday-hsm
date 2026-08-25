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
