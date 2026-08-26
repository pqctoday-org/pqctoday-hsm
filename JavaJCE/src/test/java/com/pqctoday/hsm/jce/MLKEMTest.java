package com.pqctoday.hsm.jce;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class MLKEMTest {

    // alg, expected ciphertext length (FIPS 203)
    @ParameterizedTest
    @CsvSource({
        "ML-KEM-512, 768",
        "ML-KEM-768, 1088",
        "ML-KEM-1024, 1568",
    })
    void selfRoundTripAndFipsSizes(String alg, int expectedCtLen) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();

        KEM kem = KEM.getInstance("ML-KEM", p); // bare family name — matches what JSSE requests
        KEM.Encapsulator encer = kem.newEncapsulator(kp.getPublic());
        assertEquals(expectedCtLen, encer.encapsulationSize());
        assertEquals(32, encer.secretSize());

        KEM.Encapsulated enc = encer.encapsulate();
        assertEquals(expectedCtLen, enc.encapsulation().length);
        assertEquals(32, enc.key().getEncoded().length);

        KEM.Decapsulator decer = kem.newDecapsulator(kp.getPrivate());
        SecretKey decapsulated = decer.decapsulate(enc.encapsulation());
        assertArrayEquals(enc.key().getEncoded(), decapsulated.getEncoded(),
            "our own encapsulate/decapsulate round trip must produce the same secret");
    }

    // Note on the direction NOT tested here: "our provider encapsulates,
    // JDK decapsulates with OUR private key" is not achievable at all —
    // decapsulation needs the private key, and ours never leaves the
    // token by design. The two genuinely achievable cross-directions are
    // both covered below: JDK generates + encapsulates, we decapsulate
    // (needs no import); and JDK generates, we import + encapsulate, JDK
    // decapsulates (exercises this workstream's KeyFactory import path).

    @ParameterizedTest
    @CsvSource({ "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" })
    void crossVerifyAgainstJdkSoftwareMLKEM_theirsEncapsulateOursDecapsulate(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();

        // Our provider generates the keypair (private key never leaves the token).
        KeyPair ourKp = KeyPairGenerator.getInstance(alg, p).generateKeyPair();

        // JDK's OWN software ML-KEM imports our exported public key and
        // encapsulates against it — zero involvement of our provider for
        // this step.
        KeyFactory jdkKf = KeyFactory.getInstance(alg);
        PublicKey jdkImportedPub = jdkKf.generatePublic(new X509EncodedKeySpec(ourKp.getPublic().getEncoded()));
        KEM jdkKem = KEM.getInstance("ML-KEM");
        KEM.Encapsulated jdkEnc = jdkKem.newEncapsulator(jdkImportedPub).encapsulate();

        // WE decapsulate JDK's ciphertext using our own token-resident
        // private key — the real reverse cross-check: two independent
        // implementations must agree on the derived secret.
        KEM ourKem = KEM.getInstance("ML-KEM", p);
        SecretKey ourSecret = ourKem.newDecapsulator(ourKp.getPrivate()).decapsulate(jdkEnc.encapsulation());

        assertArrayEquals(jdkEnc.key().getEncoded(), ourSecret.getEncoded(),
            "our token-produced decapsulation must match JDK software ML-KEM's own encapsulated secret for " + alg);
    }

    @ParameterizedTest
    @CsvSource({ "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" })
    void importedForeignKeyEncapsulatesAndOursDecapsulatesCorrectly(String alg) throws Exception {
        // The other reverse direction: a JDK-generated KEYPAIR, its
        // public key imported into OUR provider via KeyFactory, WE
        // encapsulate against it, JDK decapsulates with its own private
        // key. Exercises this workstream's KeyFactory import path
        // specifically (not just Signature import, proven in W2).
        KeyPair jdkKp = KeyPairGenerator.getInstance(alg).generateKeyPair();

        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyFactory ourKf = KeyFactory.getInstance(alg, p);
        PublicKey imported = ourKf.generatePublic(new X509EncodedKeySpec(jdkKp.getPublic().getEncoded()));
        assertInstanceOf(P11Key.Pub.class, imported);

        KEM ourKem = KEM.getInstance("ML-KEM", p);
        KEM.Encapsulated ourEnc = ourKem.newEncapsulator(imported).encapsulate();

        KEM jdkKem = KEM.getInstance("ML-KEM");
        SecretKey jdkSecret = jdkKem.newDecapsulator(jdkKp.getPrivate()).decapsulate(ourEnc.encapsulation());

        assertArrayEquals(ourEnc.key().getEncoded(), jdkSecret.getEncoded(),
            "JDK must decapsulate our token-produced ciphertext (against an imported JDK public key) to the same secret");
    }
}
