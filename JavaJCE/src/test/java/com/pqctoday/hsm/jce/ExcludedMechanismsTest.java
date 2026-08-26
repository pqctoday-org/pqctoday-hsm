package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Regression coverage for plan §5 ("Excluded surface — deprecated /
 * non-approved"). SoftHSMv3ProviderTest already covers SHA-1/MD5 digest
 * exclusion; this class covers the rest of the §5 table.
 *
 * A genuine, disclosed finding from writing these tests: §5's own text
 * says "the policy layer additionally refuses them if requested by
 * alias, so exclusion is enforced, not just omitted" — but a full read
 * of SoftHSMv3Provider#registerServices() (every putService/registerX
 * call, no addAlias anywhere, no generic passthrough service that
 * accepts an arbitrary caller-supplied CKM_* value) shows there is no
 * separate runtime-checked policy layer distinct from simply never
 * registering a JCA Service for these algorithm names. That is a
 * completely adequate enforcement mechanism here — there is no
 * registered alias or generic entry point through which any of these
 * mechanisms could be reached, verified by reading the whole method,
 * not assumed — but it is "enforced by omission", not by a separate
 * allow/deny check, so this class's real job is to be the regression
 * safety net that keeps that true: if a future change ever registers
 * one of these under its standard JCA name, these tests fail.
 *
 * CKM_BIP32_MASTER/CHILD_DERIVE, the CKM_CONCATENATE family, and
 * CKM_SHAKE_256_KEY_DERIVATION (standalone) are deliberately not
 * covered here: §5 already notes these were never exposed as JCA
 * services with a standard name at all (no conventional
 * getInstance(String) string a caller could plausibly reach for), so
 * there is no realistic "accidentally re-registered under its usual
 * name" regression to guard against, unlike SHA-1/AES-ECB/X25519/etc.,
 * which collide with real, commonly-used JCA algorithm name strings.
 */
class ExcludedMechanismsTest {

    @Test
    void ripemd160AndKeccakDigestsAreNotRegistered() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        for (String excluded : new String[]{"RIPEMD160", "KECCAK-256"}) {
            assertThrows(NoSuchAlgorithmException.class,
                () -> MessageDigest.getInstance(excluded, p),
                excluded + " must not be registered by the FIPS 140-3 L3 policy (§5)");
        }
    }

    @Test
    void sha1AndMd5BasedHmacsAreNotRegistered() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        for (String excluded : new String[]{"HmacSHA1", "HmacMD5", "HmacRIPEMD160"}) {
            assertThrows(NoSuchAlgorithmException.class,
                () -> Mac.getInstance(excluded, p),
                excluded + " must not be registered by the FIPS 140-3 L3 policy (§5)");
        }
    }

    @Test
    void sha1AndMd5CompositeSignaturesAreNotRegistered() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        for (String excluded : new String[]{"SHA1withECDSA", "SHA1withRSA", "MD5withRSA"}) {
            assertThrows(NoSuchAlgorithmException.class,
                () -> Signature.getInstance(excluded, p),
                excluded + " must not be registered by the FIPS 140-3 L3 policy (§5)");
        }
    }

    @Test
    void rawUnpaddedAndPkcs1RsaCipherAreNotRegistered() {
        // CKM_RSA_X_509 (raw RSA) and CKM_RSA_PKCS as a Cipher (v1.5
        // encryption/key transport) — §5 keeps CKM_RSA_PKCS as a
        // SIGNATURE mechanism only (registerRSAPKCS1 above), never as a
        // Cipher; only the OAEP transformation strings are registered as
        // Ciphers under "RSA".
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        for (String excluded : new String[]{"RSA/ECB/NoPadding", "RSA/ECB/PKCS1Padding", "RSA"}) {
            assertThrows(Exception.class, // NoSuchAlgorithmException or NoSuchPaddingException, both prove absence
                () -> Cipher.getInstance(excluded, p),
                excluded + " must not be registered as a Cipher by the FIPS 140-3 L3 policy (§5)");
        }
    }

    @Test
    void chaCha20FamilyIsNotRegistered() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertThrows(NoSuchAlgorithmException.class, () -> Cipher.getInstance("ChaCha20", p));
        assertThrows(NoSuchAlgorithmException.class, () -> Cipher.getInstance("ChaCha20-Poly1305", p));
        assertThrows(NoSuchAlgorithmException.class, () -> KeyGenerator.getInstance("ChaCha20", p));
    }

    @Test
    void aesEcbModeIsNotRegistered() {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        for (String excluded : new String[]{"AES/ECB/NoPadding", "AES/ECB/PKCS5Padding"}) {
            assertThrows(Exception.class, // NoSuchAlgorithmException or NoSuchPaddingException, both prove absence
                () -> Cipher.getInstance(excluded, p),
                excluded + " must not be registered — ECB is excluded as a confidentiality mode (§5)");
        }
    }

    @Test
    void montgomeryKeyAgreementIsNotRegistered() {
        // CKM_X25519/CKM_X448/CKM_EC_MONTGOMERY_KEY_PAIR_GEN — this
        // provider only registers "EC" (Weierstrass, secp256r1/384r1/521r1)
        // and "ECDH" over that same family; no X25519/X448/XDH service
        // exists under any name.
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        for (String excluded : new String[]{"X25519", "X448", "XDH"}) {
            assertThrows(NoSuchAlgorithmException.class,
                () -> KeyPairGenerator.getInstance(excluded, p),
                excluded + " KeyPairGenerator must not be registered (§5)");
            assertThrows(NoSuchAlgorithmException.class,
                () -> KeyAgreement.getInstance(excluded, p),
                excluded + " KeyAgreement must not be registered (§5)");
        }
    }

    @Test
    void statefulHashBasedSignaturesAreNotRegistered() {
        // CKM_HSS/CKM_XMSS/CKM_XMSSMT — engine-supported but deliberately
        // deferred by scope decision (plan §10: a JCA mapping needs its
        // own state-management design first, not a naive port).
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        for (String excluded : new String[]{"HSS", "XMSS", "XMSSMT"}) {
            assertThrows(NoSuchAlgorithmException.class,
                () -> KeyPairGenerator.getInstance(excluded, p),
                excluded + " KeyPairGenerator must not be registered — deferred per plan §10");
        }
    }
}
