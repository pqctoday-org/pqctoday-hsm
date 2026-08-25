package com.pqctoday.hsm.jce;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class RSAOAEPTest {

    // digestName (JCA transform suffix), MGF1ParameterSpec digest name —
    // used to build an explicit OAEPParameterSpec for the JDK side.
    // Necessary because of a real, confirmed JDK/SunJCE quirk (see the
    // W3 OAEP commit): given only the plain transformation string
    // "OAEPWithSHA-384AndMGF1Padding" (no explicit OAEPParameterSpec),
    // SunJCE does NOT default its MGF digest to match the main hash for
    // SHA-384/512 — it does for SHA-256, but not consistently for the
    // others. Root-caused live (isolated probe, then confirmed by
    // forcing a matching MGF1ParameterSpec, which fixed it) before
    // concluding this was a test-side gap, not a provider bug: our
    // provider always uses MGF1 matching the main hash, which is what
    // the algorithm name means and the only sane, secure choice.
    @ParameterizedTest
    @CsvSource({
        "SHA-256, SHA-256",
        "SHA-384, SHA-384",
        "SHA-512, SHA-512",
    })
    void encryptDecryptRoundTripsAndInteropsWithJdkSunJCE(String digest, String mgfDigest) throws Exception {
        String transform = "RSA/ECB/OAEPWith" + digest + "AndMGF1Padding";
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] plaintext = ("OAEP round trip " + transform).getBytes();

        Cipher ourEnc = Cipher.getInstance(transform, p);
        ourEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] ciphertext = ourEnc.doFinal(plaintext);
        assertEquals(2048 / 8, ciphertext.length, "RSA-OAEP ciphertext must be exactly one modulus-size block");

        Cipher ourDec = Cipher.getInstance(transform, p);
        ourDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decrypted = ourDec.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted, "our own encrypt/decrypt round trip must recover the plaintext");

        // Cross-verify against JDK's own SunJCE RSA-OAEP: JDK encrypts
        // against our exported public key (explicit OAEPParameterSpec —
        // see the class javadoc above for why), we decrypt with our
        // token-resident private key.
        KeyFactory jdkKf = KeyFactory.getInstance("RSA");
        PublicKey jdkImportedPub = jdkKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        OAEPParameterSpec spec = new OAEPParameterSpec(
            digest, "MGF1", new MGF1ParameterSpec(mgfDigest), PSource.PSpecified.DEFAULT);
        Cipher jdkEnc = Cipher.getInstance(transform);
        jdkEnc.init(Cipher.ENCRYPT_MODE, jdkImportedPub, spec);
        byte[] jdkCiphertext = jdkEnc.doFinal(plaintext);

        Cipher ourDec2 = Cipher.getInstance(transform, p);
        ourDec2.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decryptedFromJdk = ourDec2.doFinal(jdkCiphertext);
        assertArrayEquals(plaintext, decryptedFromJdk,
            "our token must decrypt JDK SunJCE's own RSA-OAEP ciphertext for " + transform);
    }

    @Test
    void wrapUnwrapRoundTripsAnAesKey() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] aesKeyBytes = new byte[32];
        new SecureRandom().nextBytes(aesKeyBytes);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", p);
        wrapper.init(Cipher.WRAP_MODE, kp.getPublic());
        byte[] wrapped = wrapper.wrap(aesKey);
        assertEquals(2048 / 8, wrapped.length);

        Cipher unwrapper = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", p);
        unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        Key unwrapped = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        assertArrayEquals(aesKeyBytes, unwrapped.getEncoded(),
            "unwrapped AES key must match the original key bytes");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
    })
    void unsupportedDigestsAreNotRegistered(String transform) {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertThrows(NoSuchAlgorithmException.class,
            () -> Cipher.getInstance(transform, p),
            transform + " must not be registered — SHA-1 is excluded by this provider's FIPS 140-3 L3 policy");
    }

    // Self round trip only for SHA-3 OAEP — see sha3OaepInteropsWithBouncyCastle
    // below for why the JDK-cross-verify pattern used for SHA-2 above can't
    // extend to SHA-3: it's not a matter of missing OAEPParameterSpec, it's
    // that SunJCE's own transformation-string parser doesn't recognize a
    // "SHA3-*" digest name inside "OAEPWith...AndMGF1Padding" at all
    // (confirmed live: Cipher.getInstance("RSA/ECB/OAEPWithSHA3-256AndMGF1Padding", "SunJCE")
    // throws NoSuchPaddingException, independent of any provider or params).
    @ParameterizedTest
    @ValueSource(strings = {"SHA3-256", "SHA3-384", "SHA3-512"})
    void sha3OaepSelfRoundTrips(String digest) throws Exception {
        String transform = "RSA/ECB/OAEPWith" + digest + "AndMGF1Padding";
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] plaintext = ("OAEP round trip " + transform).getBytes();

        Cipher enc = Cipher.getInstance(transform, p);
        enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] ciphertext = enc.doFinal(plaintext);
        assertEquals(2048 / 8, ciphertext.length, "RSA-OAEP ciphertext must be exactly one modulus-size block");

        Cipher dec = Cipher.getInstance(transform, p);
        dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        assertArrayEquals(plaintext, dec.doFinal(ciphertext),
            "our own encrypt/decrypt round trip must recover the plaintext for " + transform);
    }

    // Independent third-party cross-verification of the SHA-3 OAEP engine
    // fix (see the W3 OAEP commit): the C++ engine originally rejected all
    // SHA-3 hashAlg/mgf combinations with CKR_ARGUMENTS_BAD due to a
    // hardcoded allow-list in SoftHSM_keygen.cpp's
    // MechParamCheckRSAPKCSOAEP, even though the PKCS#11 v3.2 spec
    // (verified against the actual OASIS standard PDF, §6.1.8) defines
    // hashAlg generically with no restriction, and CKG_MGF1_SHA3_* MGFs
    // in the same normative table as the SHA-2 ones. After fixing the
    // engine (OSSLRSA.cpp, SoftHSM_cipher.cpp, SoftHSM_keygen.cpp), this
    // test proves the fix against Bouncy Castle's independent RSA-OAEP
    // implementation — a completely separate codebase from both our
    // engine and the JDK's own SunJCE (which, per the note above, can't
    // even construct an OAEP+SHA-3 Cipher instance) — in both directions.
    @ParameterizedTest
    @CsvSource({
        "SHA3-256, SHA3-256",
        "SHA3-384, SHA3-384",
        "SHA3-512, SHA3-512",
    })
    void sha3OaepInteropsWithBouncyCastle(String digest, String mgfDigest) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String transform = "RSA/ECB/OAEPWith" + digest + "AndMGF1Padding";
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] plaintext = ("BC SHA-3 OAEP cross-verify " + transform).getBytes();
        OAEPParameterSpec spec = new OAEPParameterSpec(
            digest, "MGF1", new MGF1ParameterSpec(mgfDigest), PSource.PSpecified.DEFAULT);

        KeyFactory bcKf = KeyFactory.getInstance("RSA", "BC");
        PublicKey bcImportedPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        // BC encrypts against our exported public key, we decrypt with our
        // token-resident private key.
        Cipher bcEnc = Cipher.getInstance(transform, "BC");
        bcEnc.init(Cipher.ENCRYPT_MODE, bcImportedPub, spec);
        byte[] bcCiphertext = bcEnc.doFinal(plaintext);

        Cipher ourDec = Cipher.getInstance(transform, p);
        ourDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decryptedFromBc = ourDec.doFinal(bcCiphertext);
        assertArrayEquals(plaintext, decryptedFromBc,
            "our token must decrypt Bouncy Castle's own RSA-OAEP ciphertext for " + transform);

        // And the reverse direction: we encrypt, BC decrypts — requires a
        // BC-native key pair since BC's own private-key operations need a
        // real BC PrivateKey (our private keys are opaque/non-exportable
        // by design).
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", "BC");
        bcKpg.initialize(2048);
        KeyPair bcKp = bcKpg.generateKeyPair();

        Cipher ourEnc = Cipher.getInstance(transform, p);
        PublicKey ourImportedBcPub = KeyFactory.getInstance("RSA", p)
            .generatePublic(new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));
        ourEnc.init(Cipher.ENCRYPT_MODE, ourImportedBcPub);
        byte[] ourCiphertext = ourEnc.doFinal(plaintext);

        Cipher bcDec = Cipher.getInstance(transform, "BC");
        bcDec.init(Cipher.DECRYPT_MODE, bcKp.getPrivate(), spec);
        byte[] decryptedByBc = bcDec.doFinal(ourCiphertext);
        assertArrayEquals(plaintext, decryptedByBc,
            "Bouncy Castle must decrypt our provider's own RSA-OAEP ciphertext for " + transform);
    }
}
