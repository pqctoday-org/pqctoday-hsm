package com.pqctoday.hsm.jce;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Real CKO_CERTIFICATE storage — both PrivateKeyEntry chains and
 * TrustedCertificateEntry — plus an actual end-to-end trust-path
 * validation via the JDK's own PKIXParameters/CertPathValidator("PKIX"),
 * which is the entire point of storing certificates correctly (verified
 * against the real JDK 27 source before any of this was built: see
 * P11KeyStoreSpi's own javadoc for the exact citations).
 *
 * Certificates are built with real signatures using Bouncy Castle's
 * bcpkix module (test-only dependency — see pom.xml) since this
 * provider's own keys need to sign something to make a meaningful test;
 * signing routes through THIS provider (JcaContentSignerBuilder's
 * setProvider), proving an HSM-backed key can produce a certificate a
 * standard JDK validator accepts.
 */
class KeyStoreCertificateTest {

    private static X509Certificate selfSignedCert(SoftHSMv3Provider p, String cn, KeyPair kp) throws Exception {
        X500Name name = new X500Name("CN=" + cn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(System.identityHashCode(kp) & 0x7fffffffL),
            new Date(0), new Date(System.currentTimeMillis() + 10L * 365 * 24 * 3600 * 1000), name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider(p).build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private static X509Certificate signedBy(SoftHSMv3Provider p, String cn, java.security.PublicKey subjectPub,
            X500Name issuer, java.security.PrivateKey issuerPriv) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer, BigInteger.valueOf(System.identityHashCode(subjectPub) & 0x7fffffffL),
            new Date(0), new Date(System.currentTimeMillis() + 10L * 365 * 24 * 3600 * 1000), new X500Name("CN=" + cn), subjectPub);
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider(p).build(issuerPriv);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    @Test
    void setKeyEntryWithChainPersistsAndRetrievesInLeafFirstOrder() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.Security.addProvider(bc);
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
        KeyPair rootKp = kpg.generateKeyPair();
        KeyPair leafKp = kpg.generateKeyPair();

        X509Certificate rootCert = selfSignedCert(p, "Test Root CA " + System.nanoTime(), rootKp);
        X509Certificate leafCert = signedBy(p, "Test Leaf " + System.nanoTime(), leafKp.getPublic(),
            new X500Name(rootCert.getSubjectX500Principal().getName()), rootKp.getPrivate());

        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        String alias = "leaf-" + System.nanoTime();
        ks.setKeyEntry(alias, leafKp.getPrivate(), null, new java.security.cert.Certificate[]{ leafCert, rootCert });

        assertTrue(ks.isKeyEntry(alias));
        assertFalse(ks.isCertificateEntry(alias), "a key entry's own chain certs are not a TrustedCertificateEntry");

        java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
        assertNotNull(chain);
        assertEquals(2, chain.length);
        assertArrayEquals(leafCert.getEncoded(), chain[0].getEncoded(), "chain[0] must be the leaf");
        assertArrayEquals(rootCert.getEncoded(), chain[1].getEncoded(), "chain[1] must be the root");
        assertArrayEquals(leafCert.getEncoded(), ks.getCertificate(alias).getEncoded(),
            "getCertificate on a PrivateKeyEntry must return the leaf (chain[0])");
    }

    @Test
    void setCertificateEntryStoresATrustedCertificate() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.Security.addProvider(bc);
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair rootKp = KeyPairGenerator.getInstance("Ed25519", p).generateKeyPair();
        X509Certificate rootCert = selfSignedCert(p, "Trusted Root " + System.nanoTime(), rootKp);

        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        String alias = "trust-anchor-" + System.nanoTime();
        ks.setCertificateEntry(alias, rootCert);

        assertTrue(ks.isCertificateEntry(alias));
        assertFalse(ks.isKeyEntry(alias));
        assertArrayEquals(rootCert.getEncoded(), ks.getCertificate(alias).getEncoded());
        assertNull(ks.getCertificateChain(alias), "a TrustedCertificateEntry has no chain");
        assertEquals(alias, ks.getCertificateAlias(rootCert));
    }

    @Test
    void setCertificateEntryRejectsAnAliasThatIsAlreadyAKeyEntry() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.Security.addProvider(bc);
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", p).generateKeyPair();
        X509Certificate cert = selfSignedCert(p, "collide " + System.nanoTime(), kp);

        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        String alias = "keyentry-" + System.nanoTime();
        ks.setKeyEntry(alias, kp.getPrivate(), null, new java.security.cert.Certificate[]{ cert });

        assertThrows(KeyStoreException.class, () -> ks.setCertificateEntry(alias, cert));
    }

    @Test
    void reSettingAnAliasReplacesRatherThanOrphaningOldObjects() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.Security.addProvider(bc);
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();
        X509Certificate cert1 = selfSignedCert(p, "first " + System.nanoTime(), kp1);

        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        String alias = "replace-" + System.nanoTime();
        ks.setKeyEntry(alias, kp1.getPrivate(), null, new java.security.cert.Certificate[]{ cert1 });
        assertNotNull(ks.getCertificateChain(alias));

        // Re-set the SAME alias with a DIFFERENT key and NO chain. Uses
        // kp2's PUBLIC key specifically — java.security.KeyStore's own
        // "PrivateKey must be accompanied by a chain" precondition (the
        // same one KeyStoreWriteTest's own test already documents) would
        // otherwise block this before engineSetKeyEntry is ever reached;
        // a PublicKey has no such requirement.
        ks.setKeyEntry(alias, kp2.getPublic(), null, null);
        assertNull(ks.getCertificateChain(alias),
            "the old chain cert must be gone, not left dangling under the same alias after a replace");
        assertTrue(ks.isKeyEntry(alias));
    }

    @Test
    void deleteEntryRemovesTheKeyAndAllItsChainCertificates() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.Security.addProvider(bc);
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPair rootKp = KeyPairGenerator.getInstance("Ed25519", p).generateKeyPair();
        KeyPair leafKp = KeyPairGenerator.getInstance("Ed25519", p).generateKeyPair();
        X509Certificate rootCert = selfSignedCert(p, "del-root " + System.nanoTime(), rootKp);
        X509Certificate leafCert = signedBy(p, "del-leaf " + System.nanoTime(), leafKp.getPublic(),
            new X500Name(rootCert.getSubjectX500Principal().getName()), rootKp.getPrivate());

        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        String alias = "del-" + System.nanoTime();
        ks.setKeyEntry(alias, leafKp.getPrivate(), null, new java.security.cert.Certificate[]{ leafCert, rootCert });
        assertTrue(ks.containsAlias(alias));

        ks.deleteEntry(alias);
        assertFalse(ks.containsAlias(alias));
        assertNull(ks.getKey(alias, null));
        assertNull(ks.getCertificateChain(alias));
        assertNull(ks.getCertificate(alias));
    }

    @Test
    void endToEndTrustPathValidationSucceedsForAKeystoreTrustedRoot() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.Security.addProvider(bc);
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
        KeyPair rootKp = kpg.generateKeyPair();
        KeyPair leafKp = kpg.generateKeyPair();
        X509Certificate rootCert = selfSignedCert(p, "PKIX Root " + System.nanoTime(), rootKp);
        X509Certificate leafCert = signedBy(p, "PKIX Leaf " + System.nanoTime(), leafKp.getPublic(),
            new X500Name(rootCert.getSubjectX500Principal().getName()), rootKp.getPrivate());

        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        ks.setCertificateEntry("pkix-root-" + System.nanoTime(), rootCert);

        PKIXParameters params = new PKIXParameters(ks);
        params.setRevocationEnabled(false); // no CRL/OCSP infrastructure in this test
        // NOT an exact-count assertion: CKA_TOKEN=true certificate
        // entries genuinely persist across test methods within this
        // suite's shared token (that is the whole point of this
        // KeyStore's write path) — other tests' own trusted certs may
        // legitimately still be present. Assert presence, not isolation.
        boolean rootIsATrustAnchor = params.getTrustAnchors().stream()
            .anyMatch(a -> a.getTrustedCert().equals(rootCert));
        assertTrue(rootIsATrustAnchor, "the root cert just stored must be among the KeyStore-fed trust anchors");

        CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(leafCert));
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

        assertDoesNotThrow(() -> validator.validate(path, params),
            "a leaf cert signed by the KeyStore's own trusted root must validate successfully via the JDK's own PKIX validator");
    }

    @Test
    void endToEndTrustPathValidationFailsForAnUntrustedRoot() throws Exception {
        org.bouncycastle.jce.provider.BouncyCastleProvider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.Security.addProvider(bc);
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
        KeyPair trustedRootKp = kpg.generateKeyPair();
        KeyPair rogueRootKp = kpg.generateKeyPair(); // never stored in the KeyStore
        KeyPair leafKp = kpg.generateKeyPair();
        X509Certificate trustedRootCert = selfSignedCert(p, "Trusted " + System.nanoTime(), trustedRootKp);
        X509Certificate rogueRootCert = selfSignedCert(p, "Rogue " + System.nanoTime(), rogueRootKp);
        // Leaf signed by the ROGUE root, not the one the KeyStore trusts.
        X509Certificate rogueLeafCert = signedBy(p, "Rogue Leaf " + System.nanoTime(), leafKp.getPublic(),
            new X500Name(rogueRootCert.getSubjectX500Principal().getName()), rogueRootKp.getPrivate());

        KeyStore ks = KeyStore.getInstance("PKCS11-SoftHSMv3", p);
        ks.load(null, null);
        ks.setCertificateEntry("only-trusted-" + System.nanoTime(), trustedRootCert);

        PKIXParameters params = new PKIXParameters(ks);
        params.setRevocationEnabled(false);

        CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(rogueLeafCert));
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

        assertThrows(CertPathValidatorException.class, () -> validator.validate(path, params),
            "a leaf signed by a root the KeyStore does NOT trust must be rejected — proves this is a real "
            + "trust check, not something that would pass unconditionally");
    }
}
