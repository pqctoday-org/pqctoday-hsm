package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Plan item X1 / Q-6: {@link P11ECExtraBitsGenParameterSpec} must actually
 * select {@code CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS} (FIPS 186-5 A.2.2) on the
 * token, and a plain {@code ECGenParameterSpec} must not.
 *
 * <p>The assertion is deliberately made against {@code CKA_KEY_GEN_MECHANISM}
 * read back off the generated key rather than against anything the provider
 * reports about itself. Both mechanisms produce an ordinary, working EC key —
 * only the way the private scalar is drawn differs — so a sign/verify test, or
 * any check of the key's shape, passes identically whichever mechanism ran and
 * would prove nothing. The attribute is the only externally visible evidence
 * of which one the token actually used.
 *
 * <p>Every positive case is paired with its negative. Asserting only that the
 * extra-bits spec yields the extra-bits mechanism would still pass if the flag
 * were stuck on and every key were generated that way; asserting the plain
 * spec's mechanism too is what pins the distinction.
 *
 * <p><b>Requires an engine that implements the mechanism.</b> The C++ engine
 * gained it on 2026-09-07; the Rust engine has had it since 2026-08-30. A
 * token without it fails these tests with {@code CKR_MECHANISM_INVALID}, which
 * is the correct and informative outcome — do not soften it into a skip.
 */
class ECExtraBitsTest {

    /** CK_ULONG is a native 8-byte little-endian word on every platform this builds for. */
    private static long keyGenMechanism(P11Library lib, long handle) {
        byte[] b = lib.getAttributeBytes(handle, CKA_KEY_GEN_MECHANISM);
        assertNotNull(b, "CKA_KEY_GEN_MECHANISM must be readable on a generated key");
        assertEquals(8, b.length, "CKA_KEY_GEN_MECHANISM must be a native CK_ULONG");
        long v = 0;
        for (int i = b.length - 1; i >= 0; i--) {
            v = (v << 8) | (b[i] & 0xffL);
        }
        return v;
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
    void extraBitsSpecSelectsTheExtraBitsMechanism(String curve) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", p);
        kpg.initialize(new P11ECExtraBitsGenParameterSpec(curve));
        KeyPair kp = kpg.generateKeyPair();

        long pubMech = keyGenMechanism(p.lib, ((P11Key.EcPub) kp.getPublic()).handle());
        long privMech = keyGenMechanism(p.lib, ((P11Key.EcPriv) kp.getPrivate()).handle());

        assertEquals(CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS, pubMech,
            curve + ": public key must record the extra-bits mechanism");
        assertEquals(CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS, privMech,
            curve + ": private key must record the extra-bits mechanism");

        // The key must still be a usable EC key — an A.2.2 scalar that did not
        // match its public point would sign but never verify.
        Signature s = Signature.getInstance("SHA256withECDSA", p);
        s.initSign(kp.getPrivate());
        s.update("extra random bits".getBytes());
        byte[] sig = s.sign();
        s.initVerify(kp.getPublic());
        s.update("extra random bits".getBytes());
        assertTrue(s.verify(sig), curve + ": extra-bits key pair must be self-consistent");
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
    void plainSpecStillSelectsThePlainMechanism(String curve) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", p);
        kpg.initialize(new ECGenParameterSpec(curve));
        KeyPair kp = kpg.generateKeyPair();

        assertEquals(CKM_EC_KEY_PAIR_GEN,
            keyGenMechanism(p.lib, ((P11Key.EcPriv) kp.getPrivate()).handle()),
            curve + ": a plain ECGenParameterSpec must not select extra-bits");
    }

    /**
     * The generator is reusable, and a bare key size cannot express a
     * generation method. Re-initialising with {@code initialize(int)} after an
     * extra-bits {@code initialize(spec)} must go back to the plain mechanism —
     * the one line in the SPI whose only purpose is to prevent a silent carry
     * over, and which nothing else would catch.
     */
    @Test
    void reinitialisingWithAKeySizeClearsTheExtraBitsSelection() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", p);

        kpg.initialize(new P11ECExtraBitsGenParameterSpec("secp256r1"));
        KeyPair first = kpg.generateKeyPair();
        assertEquals(CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS,
            keyGenMechanism(p.lib, ((P11Key.EcPriv) first.getPrivate()).handle()),
            "precondition: the first key must be an extra-bits key");

        kpg.initialize(384, null);
        KeyPair second = kpg.generateKeyPair();
        assertEquals(CKM_EC_KEY_PAIR_GEN,
            keyGenMechanism(p.lib, ((P11Key.EcPriv) second.getPrivate()).handle()),
            "initialize(int) must reset the generation method, not inherit it");
    }

    /**
     * The spec is a real {@link ECGenParameterSpec}, which is what lets the
     * generator's existing instanceof guard and curve lookup keep working
     * unchanged. Cheap to assert, and it is the design decision the whole
     * approach rests on.
     */
    @Test
    void specIsAnEcGenParameterSpecCarryingTheCurveName() {
        P11ECExtraBitsGenParameterSpec spec = new P11ECExtraBitsGenParameterSpec("secp384r1");
        assertInstanceOf(ECGenParameterSpec.class, spec);
        assertEquals("secp384r1", spec.getName());
    }
}
