package com.pqctoday.hsm.jce;

import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandomSpi;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * JCA/JCE Provider bridging javax.crypto/java.security to this repo's
 * PKCS#11 v3.2 engine over FFM (see docs/implementation-plan-jdk27-jca-provider-2026-08-24.md).
 *
 * W1 slice: SecureRandom + the approved-only MessageDigest set (FIPS
 * 140-3 L3 exclusion policy from the plan's §5 — SHA-1/MD5/RIPEMD-160 are
 * NOT registered even though the live engine advertises and dispatches
 * them; verified during W0.2's mechanism sweep that the engine is
 * permissive and the FIPS narrowing is this provider's job, not the
 * engine's). Every service construction runs the POST battery first
 * (§6.3) — failure here means every getService() call in this JVM fails
 * closed, matching the CACP fail-open remediation lesson elsewhere in
 * this repo (never fail open on a crypto boundary).
 */
public final class SoftHSMv3Provider extends Provider {

    private static final String NAME = "SoftHSMv3";
    private static final String INFO = "PKCS#11 v3.2 bridge (FIPS 140-3 L3 approved subset)";

    // CKM_* — only the mechanisms this class dispatches to.
    static final long CKM_SHA224 = 0x0255L;
    static final long CKM_SHA256 = 0x0250L;
    static final long CKM_SHA384 = 0x0260L;
    static final long CKM_SHA512 = 0x0270L;
    static final long CKM_SHA3_224 = 0x02b5L;
    static final long CKM_SHA3_256 = 0x02b0L;
    static final long CKM_SHA3_384 = 0x02c0L;
    static final long CKM_SHA3_512 = 0x02d0L;

    // NIST FIPS 180-4 KAT: SHA-256("abc") — used as the POST vector.
    private static final byte[] SHA256_ABC_KAT = HexFormat.of().parseHex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Package-private (not private) so same-package test code can reach
    // the native layer directly for cross-verification checks that need
    // raw token attributes our own KeyFactory/SPKI code doesn't expose
    // (e.g. SLHDSACrossVerifyTest reading CKA_VALUE) — deliberately not
    // reflection, since that would be needless indirection for something
    // already in the same package.
    final P11Library lib;

    public SoftHSMv3Provider() {
        this(System.getenv().getOrDefault("PKCS11_MODULE", "/usr/local/lib/softhsm/libsofthsmv3.so"),
             System.getenv().getOrDefault("PKCS11_PIN", "1234"));
    }

    public SoftHSMv3Provider(String modulePath, String pin) {
        super(NAME, "0.1.0", INFO);
        this.lib = new P11Library(modulePath, pin);
        runPowerOnSelfTest();
        registerServices();
    }

    /**
     * Power-on self-test: one digest KAT against a real published FIPS
     * vector, run through this exact instance's native path before any
     * service is exposed. A real implementation (W5) extends this per
     * §6.3 to cover one KAT per algorithm family; this W1 slice proves the
     * fail-closed mechanism with the one algorithm family this slice has.
     */
    private void runPowerOnSelfTest() {
        byte[] got;
        try {
            got = lib.digest(CKM_SHA256, "abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        } catch (RuntimeException e) {
            lib.close();
            throw new ProviderException("POST failed: SHA-256 KAT threw", e);
        }
        if (!java.util.Arrays.equals(got, SHA256_ABC_KAT)) {
            lib.close();
            throw new ProviderException("POST failed: SHA-256(\"abc\") KAT mismatch — "
                + "expected " + HexFormat.of().formatHex(SHA256_ABC_KAT)
                + " got " + HexFormat.of().formatHex(got));
        }
    }

    private void registerServices() {
        putService(new Service(this, "SecureRandom", NAME + "-DRBG",
            P11SecureRandomSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11SecureRandomSpi(lib);
            }
        });

        registerDigest("SHA-224", CKM_SHA224);
        registerDigest("SHA-256", CKM_SHA256);
        registerDigest("SHA-384", CKM_SHA384);
        registerDigest("SHA-512", CKM_SHA512);
        registerDigest("SHA3-224", CKM_SHA3_224);
        registerDigest("SHA3-256", CKM_SHA3_256);
        registerDigest("SHA3-384", CKM_SHA3_384);
        registerDigest("SHA3-512", CKM_SHA3_512);
        // Deliberately NOT registered: SHA-1, MD5, RIPEMD-160 — see class javadoc.

        // W2: ML-DSA (FIPS 204) + SLH-DSA (FIPS 205) — KeyPairGenerator +
        // Signature, one service pair per parameter set, both built on the
        // generic P11PureSig* classes (see their javadoc for why one
        // Signature class per algorithm serves every parameter set: the
        // mechanism is parameter-set-agnostic, the parameter set lives on
        // the key).
        registerPureSig("ML-DSA-44", CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA, CKP_ML_DSA_44);
        registerPureSig("ML-DSA-65", CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA, CKP_ML_DSA_65);
        registerPureSig("ML-DSA-87", CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA, CKP_ML_DSA_87);

        registerPureSig("SLH-DSA-SHA2-128S", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHA2_128S);
        registerPureSig("SLH-DSA-SHAKE-128S", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHAKE_128S);
        registerPureSig("SLH-DSA-SHA2-128F", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHA2_128F);
        registerPureSig("SLH-DSA-SHAKE-128F", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHAKE_128F);
        registerPureSig("SLH-DSA-SHA2-192S", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHA2_192S);
        registerPureSig("SLH-DSA-SHAKE-192S", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHAKE_192S);
        registerPureSig("SLH-DSA-SHA2-192F", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHA2_192F);
        registerPureSig("SLH-DSA-SHAKE-192F", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHAKE_192F);
        registerPureSig("SLH-DSA-SHA2-256S", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHA2_256S);
        registerPureSig("SLH-DSA-SHAKE-256S", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHAKE_256S);
        registerPureSig("SLH-DSA-SHA2-256F", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHA2_256F);
        registerPureSig("SLH-DSA-SHAKE-256F", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHAKE_256F);

        // W2: EdDSA — KeyPairGenerator needs CKA_EC_PARAMS (curve OID), a
        // different shape than the pure-sig algorithms above, so it gets
        // its own class (P11EdDSAKeyPairGeneratorSpi). Signature reuses
        // the generic P11PureSigSignatureSpi unchanged: CKM_EDDSA is
        // curve-agnostic, same shape ML-DSA/SLH-DSA already proved.
        registerEdDSA("Ed25519", ED25519_OID);
        registerEdDSA("Ed448", ED448_OID);

        // W2: EC/ECDSA. Registration shape genuinely differs from the
        // above: standard JCA "EC" is ONE KeyPairGenerator service
        // covering every curve (curve chosen via
        // initialize(ECGenParameterSpec), matching how SunEC itself
        // works) rather than one service per curve — see
        // P11ECKeyPairGeneratorSpi's javadoc. Signature needs its own
        // class too, for a DIFFERENT reason than KeyPairGenerator: found
        // live (not assumed) that PKCS#11's raw r‖s ECDSA signature
        // format fails to cross-verify against JDK's own SunEC, which
        // expects ASN.1 DER SEQUENCE{r,s} — see P11ECDSASignatureSpi's
        // javadoc for the exact exception and the fix.
        putService(new Service(this, "KeyPairGenerator", "EC",
            P11ECKeyPairGeneratorSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11ECKeyPairGeneratorSpi(lib);
            }
        });
        registerECDSASignature("SHA256withECDSA", CKM_ECDSA_SHA256);
        registerECDSASignature("SHA384withECDSA", CKM_ECDSA_SHA384);
        registerECDSASignature("SHA512withECDSA", CKM_ECDSA_SHA512);
        registerECDSASignature("SHA3-256withECDSA", CKM_ECDSA_SHA3_256);
        registerECDSASignature("SHA3-384withECDSA", CKM_ECDSA_SHA3_384);
        registerECDSASignature("SHA3-512withECDSA", CKM_ECDSA_SHA3_512);
    }

    private void registerECDSASignature(String name, long mech) {
        putService(new Service(this, "Signature", name,
            P11ECDSASignatureSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11ECDSASignatureSpi(lib, mech);
            }
        });
    }

    private void registerEdDSA(String name, byte[] curveOid) {
        putService(new Service(this, "KeyPairGenerator", name,
            P11EdDSAKeyPairGeneratorSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11EdDSAKeyPairGeneratorSpi(lib, name, curveOid);
            }
        });
        putService(new Service(this, "Signature", name,
            P11PureSigSignatureSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11PureSigSignatureSpi(lib, CKM_EDDSA);
            }
        });
    }

    private void registerDigest(String name, long mech) {
        putService(new Service(this, "MessageDigest", name,
            P11MessageDigestSpi.class.getName(), List.of(), Map.of("mechanism", Long.toString(mech))) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11MessageDigestSpi(lib, mech);
            }
        });
    }

    private void registerPureSig(String name, long keygenMech, long signMech, long parameterSet) {
        putService(new Service(this, "KeyPairGenerator", name,
            P11PureSigKeyPairGeneratorSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11PureSigKeyPairGeneratorSpi(lib, name, keygenMech, parameterSet);
            }
        });
        putService(new Service(this, "Signature", name,
            P11PureSigSignatureSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11PureSigSignatureSpi(lib, signMech);
            }
        });
    }

    // ── SPIs ─────────────────────────────────────────────────────────────

    static final class P11MessageDigestSpi extends MessageDigestSpi {
        private final P11Library lib;
        private final long mech;
        private final java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();

        P11MessageDigestSpi(P11Library lib, long mech) {
            this.lib = lib;
            this.mech = mech;
        }

        @Override protected void engineUpdate(byte input) { buf.write(input); }
        @Override protected void engineUpdate(byte[] input, int offset, int len) { buf.write(input, offset, len); }
        @Override protected byte[] engineDigest() {
            byte[] out = lib.digest(mech, buf.toByteArray());
            buf.reset();
            return out;
        }
        @Override protected void engineReset() { buf.reset(); }
    }

    /**
     * SecureRandom backed by C_GenerateRandom (SP 800-90A DRBG inside the
     * token) — never JVM software randomness. engineSetSeed feeds
     * C_SeedRandom rather than mixing locally, since the DRBG state lives
     * in the token.
     */
    static final class P11SecureRandomSpi extends SecureRandomSpi {
        private final P11Library lib;

        P11SecureRandomSpi(P11Library lib) {
            this.lib = lib;
        }

        @Override protected void engineSetSeed(byte[] seed) { lib.seedRandom(seed); }
        @Override protected void engineNextBytes(byte[] bytes) {
            byte[] r = lib.generateRandom(bytes.length);
            System.arraycopy(r, 0, bytes, 0, bytes.length);
        }
        @Override protected byte[] engineGenerateSeed(int numBytes) { return lib.generateRandom(numBytes); }
    }
}
