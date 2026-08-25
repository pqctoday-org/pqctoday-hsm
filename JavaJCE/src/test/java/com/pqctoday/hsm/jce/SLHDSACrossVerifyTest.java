package com.pqctoday.hsm.jce;

import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Independent cross-verification of our token-produced SLH-DSA signatures
 * against Bouncy Castle's own SLH-DSA implementation — closing the gap
 * flagged in the SLH-DSA commit ("no JDK software SLH-DSA exists to
 * cross-verify against"). BC 1.79+ added real ML-KEM/ML-DSA/SLH-DSA
 * support (confirmed live against bcprov-jdk18on 1.85.2, already a
 * dependency for the ECDSA DER codec — see pom.xml).
 *
 * Uses BC's low-level org.bouncycastle.crypto API (SLHDSASigner +
 * SLHDSAPublicKeyParameters), not its JCA Signature.getInstance(String)
 * wrapper: BC's own issue tracker (bcgit/bc-java#1841) documents real,
 * unresolved inconsistency in the JCA algorithm-name strings it registers
 * for SLH-DSA. The low-level API sidesteps that entirely — typed
 * SLHDSAParameters constants instead of string lookup. Every class/field
 * name used here was confirmed via `javap` against the real
 * bcprov-jdk18on-1.85.2.jar before writing this file, not guessed from
 * documentation.
 *
 * This is NOT the provider using BC for crypto — it is test code using
 * BC as an independent second implementation to verify a signature our
 * token already produced. The provider itself never touches BC's PQC
 * classes (see pom.xml's dependency comment for that boundary).
 */
class SLHDSACrossVerifyTest {

    // JCA name -> BC's SLHDSAParameters constant for the PURE variant
    // (no "_with_sha256"/"_with_shake128" suffix — those are the
    // pre-hash variants, matching CKM_HASH_SLH_DSA_*, not the pure
    // CKM_SLH_DSA this provider's Signature currently implements).
    private static final Map<String, SLHDSAParameters> BC_PARAMS = Map.ofEntries(
        Map.entry("SLH-DSA-SHA2-128S", SLHDSAParameters.sha2_128s),
        Map.entry("SLH-DSA-SHAKE-128S", SLHDSAParameters.shake_128s),
        Map.entry("SLH-DSA-SHA2-128F", SLHDSAParameters.sha2_128f),
        Map.entry("SLH-DSA-SHAKE-128F", SLHDSAParameters.shake_128f),
        Map.entry("SLH-DSA-SHA2-192S", SLHDSAParameters.sha2_192s),
        Map.entry("SLH-DSA-SHAKE-192S", SLHDSAParameters.shake_192s),
        Map.entry("SLH-DSA-SHA2-192F", SLHDSAParameters.sha2_192f),
        Map.entry("SLH-DSA-SHAKE-192F", SLHDSAParameters.shake_192f),
        Map.entry("SLH-DSA-SHA2-256S", SLHDSAParameters.sha2_256s),
        Map.entry("SLH-DSA-SHAKE-256S", SLHDSAParameters.shake_256s),
        Map.entry("SLH-DSA-SHA2-256F", SLHDSAParameters.sha2_256f),
        Map.entry("SLH-DSA-SHAKE-256F", SLHDSAParameters.shake_256f)
    );

    @ParameterizedTest
    @ValueSource(strings = {
        "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F",
        "SLH-DSA-SHA2-192S", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHA2-192F", "SLH-DSA-SHAKE-192F",
        "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-256F",
    })
    void tokenSignatureVerifiesUnderIndependentBouncyCastleImplementation(String alg) throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, p);
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(alg, p);
        signer.initSign(kp.getPrivate());
        byte[] msg = ("BC cross-verify " + alg).getBytes();
        signer.update(msg);
        byte[] sig = signer.sign();

        // Raw public key bytes (CKA_VALUE) — NOT our own SPKI export, so
        // this check has zero dependency on our own P11Key/KeyFactory
        // code being correct. Confirmed live in SoftHSM_keygen.cpp
        // ("SLH-DSA Public Key Attributes: CKA_PARAMETER_SET + CKA_VALUE
        // (raw pub key bytes)") before relying on it here.
        long pubHandle = ((P11Key.Pub) kp.getPublic()).handle();
        byte[] rawPub = p.lib.getAttributeBytes(pubHandle, P11Constants.CKA_VALUE);

        SLHDSAParameters bcParams = BC_PARAMS.get(alg);
        SLHDSAPublicKeyParameters bcPub = new SLHDSAPublicKeyParameters(bcParams, rawPub);
        SLHDSASigner bcVerifier = new SLHDSASigner();
        bcVerifier.init(false, bcPub);
        boolean bcOk = bcVerifier.verifySignature(msg, sig);

        assertTrue(bcOk, "Bouncy Castle's independent SLH-DSA implementation must verify "
            + "our token-produced " + alg + " signature");
    }
}
