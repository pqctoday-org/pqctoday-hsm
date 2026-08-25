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

    // RFC 4231 §4.7 Test Case 6 — HMAC-SHA-256 under a 131-byte
    // (larger-than-block-size) all-0xaa key. Extracted verbatim from the
    // RFC's own raw text (fetched and read directly, not from a
    // paraphrased summary — an earlier AI-summarized fetch of this same
    // RFC in this session returned an internally inconsistent value and
    // was discarded). Deliberately NOT Test Case 1 (a 20-byte key):
    // this engine enforces its own PKCS#11-level minimum HMAC key length
    // equal to the digest's output size (kMacMechTable.minKeyBytes = 32
    // for CKM_SHA256_HMAC, confirmed live and in SoftHSM_sign.cpp — a
    // 20-byte key hits CKR_KEY_SIZE_RANGE, found live when this POST
    // check first ran against the real engine, not a hypothetical).
    private static final byte[] HMAC_KAT_KEY = HexFormat.of().parseHex("aa".repeat(131));
    private static final byte[] HMAC_KAT_DATA =
        "Test Using Larger Than Block-Size Key - Hash Key First"
            .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] HMAC_KAT_EXPECTED = HexFormat.of().parseHex(
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    // "Test Case 2" from the original GCM specification (McGrew & Viega,
    // "The Galois/Counter Mode of Operation (GCM)", 2005, Appendix B —
    // the paper NIST adopted as SP 800-38D's normative source; SP 800-38D
    // itself does not carry worked vectors inline). AES-128, all-zero
    // 16-byte key/plaintext, all-zero 96-bit IV, no AAD. Read directly
    // from the primary-source PDF (not a third-party transcription) via
    // this session's PDF page-extraction tooling, and cross-checked
    // against the byte lengths PKCS#11's AES-GCM contract requires.
    private static final byte[] GCM_KAT_KEY = new byte[16];
    private static final byte[] GCM_KAT_PLAINTEXT = new byte[16];
    private static final byte[] GCM_KAT_IV = new byte[12];
    private static final byte[] GCM_KAT_EXPECTED_CT_TAG = HexFormat.of().parseHex(
        "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");

    // Fixed message for the asymmetric pairwise-consistency checks below
    // (§6.3). These five algorithm families (ML-DSA-65, SLH-DSA-SHA2-128S,
    // ECDSA-P256, Ed25519, RSA-PSS) and ML-KEM-768 have no fixed-vector
    // KAT this provider can run without importing a specific fixed
    // private key onto the token — which this provider deliberately
    // refuses as a matter of policy (see P11KeyStoreSpi.engineSetKeyEntry's
    // foreign-key-material refusal: "same FIPS 140-3 L3 policy as
    // private-key import"). Per FIPS 140-3 IG 10.3.A, the accepted
    // alternative is a pairwise consistency test: generate a fresh
    // keypair on the token, sign/encapsulate, then verify/decapsulate,
    // and require it to succeed — genuinely different from a fixed-answer
    // KAT and documented as such here rather than mislabeled.
    private static final byte[] POST_SELF_TEST_MESSAGE =
        "SoftHSMv3Provider POST pairwise-consistency message".getBytes(java.nio.charset.StandardCharsets.UTF_8);

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
     * Power-on self-test (§6.3): every service construction runs this
     * full battery first — one digest KAT, one HMAC-SHA-256 KAT, one
     * AES-GCM KAT, one DRBG sanity check, one sign/verify pairwise
     * consistency check per signature family (ML-DSA-65,
     * SLH-DSA-SHA2-128S, ECDSA-P256, Ed25519, RSA-PSS), and one
     * encapsulate/decapsulate consistency check (ML-KEM-768). Any
     * failure closes the native session and throws out of the
     * constructor — no caller can ever obtain a live reference to a
     * provider whose POST failed, so every getService() call fails
     * closed by construction, not by a checked flag (mirrors the CACP
     * fail-open remediation lesson elsewhere in this repo).
     *
     * Every native object this battery creates (throwaway HMAC/AES keys,
     * generated keypairs, ML-KEM shared-secret objects) is explicitly
     * destroyed after use, success or failure — these are CKA_TOKEN=false
     * session objects that would otherwise linger for the life of this
     * provider's one long-lived session and pollute
     * P11KeyStoreSpi#discoverAll()'s enumeration.
     */
    private void runPowerOnSelfTest() {
        try {
            checkSha256Kat();
            checkDrbgHealth();
            checkHmacSha256Kat();
            checkAesGcmKat();
            checkPureSigRoundTrip("ML-DSA-65", CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA, CKP_ML_DSA_65);
            checkPureSigRoundTrip("SLH-DSA-SHA2-128S", CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKP_SLH_DSA_SHA2_128S);
            checkEcdsaP256RoundTrip();
            checkEd25519RoundTrip();
            checkRsaPssRoundTrip();
            checkMlKem768RoundTrip();
        } catch (RuntimeException e) {
            lib.close();
            throw new ProviderException("POST failed: " + e.getMessage(), e);
        }
    }

    private void checkSha256Kat() {
        byte[] got = lib.digest(CKM_SHA256, "abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        if (!java.util.Arrays.equals(got, SHA256_ABC_KAT)) {
            throw new IllegalStateException("SHA-256(\"abc\") KAT mismatch — expected "
                + HexFormat.of().formatHex(SHA256_ABC_KAT) + " got " + HexFormat.of().formatHex(got));
        }
    }

    /**
     * Not a NIST SP 800-90B statistical health test suite — that battery
     * runs inside OpenSSL's own DRBG implementation (this engine's actual
     * randomness source, see the repo's CLAUDE.md: "OpenSSL-only
     * backend"), out of this JCA layer's reach and not this provider's to
     * duplicate. This is a minimal, honestly-scoped sanity check: two
     * consecutive draws of the requested length that are not identical
     * (catches a stuck/degenerate generator, nothing subtler).
     */
    private void checkDrbgHealth() {
        byte[] a = lib.generateRandom(32);
        byte[] b = lib.generateRandom(32);
        if (a.length != 32 || b.length != 32) {
            throw new IllegalStateException("DRBG health check failed: expected 32 random bytes, got "
                + a.length + " and " + b.length);
        }
        if (java.util.Arrays.equals(a, b)) {
            throw new IllegalStateException("DRBG health check failed: two consecutive 32-byte draws "
                + "were identical (signature of a stuck/degenerate generator)");
        }
    }

    private void checkHmacSha256Kat() {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attr(CKA_VALUE, HMAC_KAT_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SIGN, true),
        };
        long handle = lib.createObject(tmpl);
        try {
            byte[] got = lib.sign(CKM_SHA256_HMAC, handle, HMAC_KAT_DATA);
            if (!java.util.Arrays.equals(got, HMAC_KAT_EXPECTED)) {
                throw new IllegalStateException("HMAC-SHA-256 KAT (RFC 4231 Test Case 1) mismatch — expected "
                    + HexFormat.of().formatHex(HMAC_KAT_EXPECTED) + " got " + HexFormat.of().formatHex(got));
            }
        } finally {
            lib.destroyObject(handle);
        }
    }

    private void checkAesGcmKat() {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_AES),
            P11Library.attr(CKA_VALUE, GCM_KAT_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_ENCRYPT, true),
        };
        long handle = lib.createObject(tmpl);
        try {
            var mech = lib.mechGcm(GCM_KAT_IV, new byte[0], 128);
            byte[] got = lib.encrypt(mech, handle, GCM_KAT_PLAINTEXT);
            if (!java.util.Arrays.equals(got, GCM_KAT_EXPECTED_CT_TAG)) {
                throw new IllegalStateException("AES-GCM KAT (GCM spec Appendix B Test Case 2) mismatch — expected "
                    + HexFormat.of().formatHex(GCM_KAT_EXPECTED_CT_TAG) + " got " + HexFormat.of().formatHex(got));
            }
        } finally {
            lib.destroyObject(handle);
        }
    }

    /** ML-DSA/SLH-DSA share this shape: keygen mechanism is parameter-set-agnostic, sign mechanism is too. */
    private void checkPureSigRoundTrip(String label, long keygenMech, long signMech, long parameterSet) {
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_PARAMETER_SET, parameterSet),
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        P11Library.Attr[] prvTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PRIVATE_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_PRIVATE, true),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_SIGN, true),
        };
        long[] handles = lib.generateKeyPair(keygenMech, pubTmpl, prvTmpl);
        try {
            byte[] sig = lib.sign(signMech, handles[1], POST_SELF_TEST_MESSAGE);
            if (!lib.verify(signMech, handles[0], POST_SELF_TEST_MESSAGE, sig)) {
                throw new IllegalStateException(label + " pairwise consistency check failed: "
                    + "a freshly generated keypair's own signature did not verify");
            }
        } finally {
            lib.destroyObject(handles[0]);
            lib.destroyObject(handles[1]);
        }
    }

    private void checkEcdsaP256RoundTrip() {
        byte[] secp256r1Oid = { 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07 };
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_EC),
            P11Library.attr(CKA_EC_PARAMS, secp256r1Oid),
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        P11Library.Attr[] prvTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PRIVATE_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_PRIVATE, true),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_SIGN, true),
        };
        long[] handles = lib.generateKeyPair(CKM_EC_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        try {
            byte[] sig = lib.sign(CKM_ECDSA_SHA256, handles[1], POST_SELF_TEST_MESSAGE);
            if (!lib.verify(CKM_ECDSA_SHA256, handles[0], POST_SELF_TEST_MESSAGE, sig)) {
                throw new IllegalStateException("ECDSA-P256 pairwise consistency check failed: "
                    + "a freshly generated keypair's own signature did not verify");
            }
        } finally {
            lib.destroyObject(handles[0]);
            lib.destroyObject(handles[1]);
        }
    }

    private void checkEd25519RoundTrip() {
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_EC_EDWARDS),
            P11Library.attr(CKA_EC_PARAMS, ED25519_OID),
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        P11Library.Attr[] prvTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PRIVATE_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_PRIVATE, true),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_SIGN, true),
        };
        long[] handles = lib.generateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        try {
            byte[] sig = lib.sign(CKM_EDDSA, handles[1], POST_SELF_TEST_MESSAGE);
            if (!lib.verify(CKM_EDDSA, handles[0], POST_SELF_TEST_MESSAGE, sig)) {
                throw new IllegalStateException("Ed25519 pairwise consistency check failed: "
                    + "a freshly generated keypair's own signature did not verify");
            }
        } finally {
            lib.destroyObject(handles[0]);
            lib.destroyObject(handles[1]);
        }
    }

    private void checkRsaPssRoundTrip() {
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_MODULUS_BITS, 2048),
            P11Library.attr(CKA_PUBLIC_EXPONENT, new byte[]{ 0x01, 0x00, 0x01 }),
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        P11Library.Attr[] prvTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PRIVATE_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_PRIVATE, true),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_SIGN, true),
        };
        long[] handles = lib.generateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        try {
            var pssMech = lib.mechWithParams(CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, CKG_MGF1_SHA256, 32);
            byte[] sig = lib.sign(pssMech, handles[1], POST_SELF_TEST_MESSAGE);
            if (!lib.verify(pssMech, handles[0], POST_SELF_TEST_MESSAGE, sig)) {
                throw new IllegalStateException("RSA-PSS pairwise consistency check failed: "
                    + "a freshly generated keypair's own signature did not verify");
            }
        } finally {
            lib.destroyObject(handles[0]);
            lib.destroyObject(handles[1]);
        }
    }

    private void checkMlKem768RoundTrip() {
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
            P11Library.attrBool(CKA_ENCAPSULATE, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        P11Library.Attr[] prvTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PRIVATE_KEY),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_PRIVATE, true),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_DECAPSULATE, true),
        };
        long[] handles = lib.generateKeyPair(CKM_ML_KEM_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        long ssEncHandle = -1;
        long ssDecHandle = -1;
        try {
            P11Library.Attr[] ssTmpl = {
                P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
                P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                P11Library.attrBool(CKA_TOKEN, false),
                P11Library.attrBool(CKA_SENSITIVE, false),
                P11Library.attrBool(CKA_EXTRACTABLE, true),
            };
            P11Library.Encapsulated enc = lib.encapsulate(CKM_ML_KEM, handles[0], ssTmpl);
            ssEncHandle = enc.sharedSecretHandle();
            ssDecHandle = lib.decapsulate(CKM_ML_KEM, handles[1], ssTmpl, enc.ciphertext());
            byte[] secretFromEncap = lib.getAttributeBytes(ssEncHandle, CKA_VALUE);
            byte[] secretFromDecap = lib.getAttributeBytes(ssDecHandle, CKA_VALUE);
            if (!java.util.Arrays.equals(secretFromEncap, secretFromDecap)) {
                throw new IllegalStateException("ML-KEM-768 pairwise consistency check failed: "
                    + "decapsulating a freshly encapsulated ciphertext with the matching private key "
                    + "did not recover the same shared secret");
            }
        } finally {
            lib.destroyObject(handles[0]);
            lib.destroyObject(handles[1]);
            if (ssEncHandle >= 0) lib.destroyObject(ssEncHandle);
            if (ssDecHandle >= 0) lib.destroyObject(ssDecHandle);
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

        // W2: RSA. KeyPairGenerator: same single-service,
        // initialize()-configured shape as "EC" — sizes 2048/3072/4096,
        // exponent 65537 by default (decided with the user). Signature:
        // PKCS#1 v1.5 (SHA256/384/512withRSA) reuses P11PureSigSignatureSpi
        // unchanged — RSA's PKCS#1 v1.5 signature format is already a raw
        // modulus-size big-endian byte string in BOTH PKCS#11 and JCA (no
        // ASN.1 wrapping, unlike ECDSA's r,s pair), confirmed live via
        // cross-verification against SunRsaSign in the W2 RSA commit, not
        // assumed from the (correct, as it turned out) general convention.
        // RSASSA-PSS needed its own class (P11RSAPSSSignatureSpi): its
        // mechanism/parameters are chosen by the caller via
        // engineSetParameter(PSSParameterSpec) after construction, not
        // fixed at registration time like every algorithm above.
        putService(new Service(this, "KeyPairGenerator", "RSA",
            P11RSAKeyPairGeneratorSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11RSAKeyPairGeneratorSpi(lib);
            }
        });
        registerRSAPKCS1(("SHA256withRSA"), CKM_SHA256_RSA_PKCS);
        registerRSAPKCS1(("SHA384withRSA"), CKM_SHA384_RSA_PKCS);
        registerRSAPKCS1(("SHA512withRSA"), CKM_SHA512_RSA_PKCS);
        putService(new Service(this, "Signature", "RSASSA-PSS",
            P11RSAPSSSignatureSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11RSAPSSSignatureSpi(lib);
            }
        });

        // KeyFactory (public-key import — see P11PublicKeyFactorySpi for
        // why private import is refused). One generic class, registered
        // under every algorithm name above: import dispatches on the
        // imported SPKI's own OID, not on which name looked the factory
        // up, matching the Signature classes' precedent.
        for (String name : new String[]{
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F",
                "SLH-DSA-SHA2-192S", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHA2-192F", "SLH-DSA-SHAKE-192F",
                "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-256F",
                "Ed25519", "Ed448", "EC", "RSA",
                "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
            putService(new Service(this, "KeyFactory", name,
                P11PublicKeyFactorySpi.class.getName(), List.of(), Map.of()) {
                @Override
                public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                    return new P11PublicKeyFactorySpi(lib);
                }
            });
        }

        // W3: ML-KEM (FIPS 203). KeyPairGenerator: one service per
        // parameter set, same shape as ML-DSA/SLH-DSA. KEM: registered
        // under the bare family name "ML-KEM" (no suffix) because W0.1's
        // live JSSE probe proved JDK 27's own Hybrid.getKEM() requests
        // exactly that string, verbatim, regardless of parameter set —
        // plus the parameter-set-specific names for direct non-JSSE use.
        // See P11MLKEMSpi's javadoc for the shared-secret handling
        // decision.
        registerMLKEMKeyPairGenerator("ML-KEM-512", CKP_ML_KEM_512);
        registerMLKEMKeyPairGenerator("ML-KEM-768", CKP_ML_KEM_768);
        registerMLKEMKeyPairGenerator("ML-KEM-1024", CKP_ML_KEM_1024);
        for (String name : new String[]{"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
            putService(new Service(this, "KEM", name,
                P11MLKEMSpi.class.getName(), List.of(), Map.of()) {
                @Override
                public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                    return new P11MLKEMSpi(lib);
                }
            });
        }

        // W3: RSA-OAEP — one Cipher service per (digest, MGF) pair, SHA-2
        // + SHA-3 (user decision, "fuller matrix"). SHA-3 registration
        // was briefly dropped after discovering the C++ engine's
        // MechParamCheckRSAPKCSOAEP hardcoded a SHA-1/SHA-2-only
        // allow-list — confirmed against the actual PKCS#11 v3.2 OASIS
        // Standard text (docs/refs/pkcs11-spec-v3.2-os.pdf §6.1.8) that
        // this was a genuine engine completeness gap, not a spec-mandated
        // restriction (hashAlg is spec-defined as an open "mechanism ID
        // of the message digest algorithm", and CKG_MGF1_SHA3_* is
        // defined in the same normative table as the SHA-2 MGF1
        // variants). Fixed directly in the engine (pqctoday-hsm's
        // OSSLRSA.cpp + SoftHSM_cipher.cpp + SoftHSM_keygen.cpp — SHA-3
        // support added to the same 4 locations the SHA-2 family already
        // used, reusing the exact pattern already proven for
        // ECDSA/HMAC's own SHA-3 support elsewhere in that codebase) per
        // the user's explicit "fix the gap" request, rather than left as
        // a permanently scoped-down Java-side workaround. See
        // P11RSAOAEPCipherSpi's javadoc for why this registration shape
        // differs from RSASSA-PSS's single configurable service.
        registerRSAOAEP("SHA-256", CKM_SHA256, CKG_MGF1_SHA256);
        registerRSAOAEP("SHA-384", CKM_SHA384, CKG_MGF1_SHA384);
        registerRSAOAEP("SHA-512", CKM_SHA512, CKG_MGF1_SHA512);
        registerRSAOAEP("SHA3-256", CKM_SHA3_256, CKG_MGF1_SHA3_256);
        registerRSAOAEP("SHA3-384", CKM_SHA3_384, CKG_MGF1_SHA3_384);
        registerRSAOAEP("SHA3-512", CKM_SHA3_512, CKG_MGF1_SHA3_512);

        // W3: ECDH — CKM_ECDH1_DERIVE, CKD_NULL (plain ECDH, no KDF).
        // See P11ECDHKeyAgreementSpi's javadoc for the raw-vs-DER-wrapped
        // EC point distinction this needed.
        putService(new Service(this, "KeyAgreement", "ECDH",
            P11ECDHKeyAgreementSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11ECDHKeyAgreementSpi(lib);
            }
        });

        // W4: AES (FIPS 197) — KeyGenerator, Cipher (GCM/CBC/CBC+PKCS5/CTR),
        // and AESWrap/AESWrapPad (SP 800-38F, via native C_WrapKey/
        // C_UnwrapKey — a different native shape than every other Cipher
        // in this module; see P11AESWrapCipherSpi's javadoc). GCM's IV
        // policy (module-generated only on encrypt, plan §4.3) lives in
        // P11AESCipherSpi, not here.
        putService(new Service(this, "KeyGenerator", "AES",
            P11AESKeyGeneratorSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11AESKeyGeneratorSpi(lib);
            }
        });
        registerAESCipher("AES/GCM/NoPadding", P11AESCipherSpi.Mode.GCM);
        registerAESCipher("AES/CBC/NoPadding", P11AESCipherSpi.Mode.CBC);
        registerAESCipher("AES/CBC/PKCS5Padding", P11AESCipherSpi.Mode.CBC_PAD);
        registerAESCipher("AES/CTR/NoPadding", P11AESCipherSpi.Mode.CTR);
        registerAESWrap("AESWrap", CKM_AES_KEY_WRAP);
        registerAESWrap("AESWrapPad", CKM_AES_KEY_WRAP_PAD);

        // W4: MAC (HMAC-SHA*/AESCMAC/KMAC128/256) — MAC is a plain
        // C_Sign operation in PKCS#11 (confirmed reading SoftHSM_sign.cpp
        // before writing P11MacSpi), so no new native binding was needed
        // beyond what W2's Signature classes already proved. Key
        // generators: HMAC/KMAC use CKK_GENERIC_SECRET (engine's own
        // kMacMechTable marks allowGenericSecret=true for both); AESCMAC
        // reuses the existing "AES" KeyGenerator unchanged (the table
        // requires CKK_AES specifically, no generic-secret fallback).
        // macLength values are the engine's own PKCS#11-minimum per
        // mechanism (same table) — KMAC's in particular were NOT assumed:
        // KMAC-256's 64-byte (not 32) output was already found live once
        // this session, in the W0.3 spike.
        registerHmac("HmacSHA224", CKM_SHA224_HMAC, 28);
        registerHmac("HmacSHA256", CKM_SHA256_HMAC, 32);
        registerHmac("HmacSHA384", CKM_SHA384_HMAC, 48);
        registerHmac("HmacSHA512", CKM_SHA512_HMAC, 64);
        registerHmac("HmacSHA3-224", CKM_SHA3_224_HMAC, 28);
        registerHmac("HmacSHA3-256", CKM_SHA3_256_HMAC, 32);
        registerHmac("HmacSHA3-384", CKM_SHA3_384_HMAC, 48);
        registerHmac("HmacSHA3-512", CKM_SHA3_512_HMAC, 64);
        registerGenericSecretKeyGenerator("KMAC128", 16);
        registerGenericSecretKeyGenerator("KMAC256", 32);
        putService(new Service(this, "Mac", "KMAC128",
            P11MacSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11MacSpi(lib, CKM_KMAC_128, 32);
            }
        });
        putService(new Service(this, "Mac", "KMAC256",
            P11MacSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11MacSpi(lib, CKM_KMAC_256, 64);
            }
        });
        putService(new Service(this, "Mac", "AESCMAC",
            P11MacSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11MacSpi(lib, CKM_AES_CMAC, 16);
            }
        });

        // W4: HKDF via the new javax.crypto.KDF/KDFSpi API (JEP 478,
        // finalized on JDK 27 — see pom.xml). Registered under
        // "HKDF-SHA256/384/512" — the exact JDK 27 EA-documented KDF
        // names (confirmed W0's Java Security Standard Algorithm Names
        // check), distinct from the "HmacSHA256" Mac names above even
        // though both key off the same underlying hash. See
        // P11HKDFKDFSpi's javadoc for the single-IKM/single-salt
        // restriction this engine's CK_HKDF_PARAMS genuinely requires.
        registerHKDF("HKDF-SHA256", CKM_SHA256, 32);
        registerHKDF("HKDF-SHA384", CKM_SHA384, 48);
        registerHKDF("HKDF-SHA512", CKM_SHA512, 64);

        // W4: PBKDF2 (SP 800-132) via SecretKeyFactory — see
        // P11PBKDF2SecretKeyFactorySpi's javadoc for why no base key is
        // needed. Registered for all three SHA-2 sizes, matching this
        // module's own established pattern for every other digest-family
        // service (Mac, MessageDigest, OAEP all cover 256/384/512
        // uniformly), even though the plan text only named 256/512
        // explicitly.
        registerPBKDF2("PBKDF2WithHmacSHA256", CKP_PKCS5_PBKD2_HMAC_SHA256);
        registerPBKDF2("PBKDF2WithHmacSHA384", CKP_PKCS5_PBKD2_HMAC_SHA384);
        registerPBKDF2("PBKDF2WithHmacSHA512", CKP_PKCS5_PBKD2_HMAC_SHA512);

        // W4: SP 800-108 counter/feedback KDF — no standard JCA name
        // exists for this family (unlike PBKDF2's PBEKeySpec), so these
        // are provider-named services taking a P11SP800108KeySpec (see
        // its javadoc for why the PRF choice lives in the spec rather
        // than the registered name, unlike this module's usual
        // one-service-per-digest pattern).
        putService(new Service(this, "SecretKeyFactory", "SP800-108-Counter",
            P11SP800108SecretKeyFactorySpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11SP800108SecretKeyFactorySpi(lib, false);
            }
        });
        putService(new Service(this, "SecretKeyFactory", "SP800-108-Feedback",
            P11SP800108SecretKeyFactorySpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11SP800108SecretKeyFactorySpi(lib, true);
            }
        });

        // W2: KeyStore (read path — see P11KeyStoreSpi's javadoc for why
        // write/delete throw for now). Fixes the classic SunPKCS11 "0
        // keys" gap for this token by actually enumerating objects via
        // C_FindObjects.
        putService(new Service(this, "KeyStore", "PKCS11-SoftHSMv3",
            P11KeyStoreSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11KeyStoreSpi(lib);
            }
        });
    }

    private void registerRSAOAEP(String digestName, long hashMech, long mgf) {
        // digestName is already exactly right for this: "SHA-256" ->
        // ".../OAEPWithSHA-256AndMGF1Padding", "SHA3-256" -> "...SHA3-256...".
        putService(new Service(this, "Cipher", "RSA/ECB/OAEPWith" + digestName + "AndMGF1Padding",
            P11RSAOAEPCipherSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11RSAOAEPCipherSpi(lib, hashMech, mgf);
            }
        });
    }

    private void registerAESCipher(String name, P11AESCipherSpi.Mode mode) {
        putService(new Service(this, "Cipher", name,
            P11AESCipherSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11AESCipherSpi(lib, mode);
            }
        });
    }

    private void registerHKDF(String name, long prfHashMech, int hashOutputBytes) {
        putService(new Service(this, "KDF", name,
            P11HKDFKDFSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                try {
                    return new P11HKDFKDFSpi(lib, prfHashMech, hashOutputBytes,
                        (javax.crypto.KDFParameters) ctrParamObj);
                } catch (java.security.InvalidAlgorithmParameterException e) {
                    throw new NoSuchAlgorithmException(e.getMessage(), e);
                }
            }
        });
    }

    private void registerPBKDF2(String name, long prf) {
        putService(new Service(this, "SecretKeyFactory", name,
            P11PBKDF2SecretKeyFactorySpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11PBKDF2SecretKeyFactorySpi(lib, prf);
            }
        });
    }

    private void registerHmac(String name, long mech, int macLength) {
        registerGenericSecretKeyGenerator(name, macLength);
        putService(new Service(this, "Mac", name,
            P11MacSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11MacSpi(lib, mech, macLength);
            }
        });
    }

    private void registerGenericSecretKeyGenerator(String name, int defaultKeySizeBytes) {
        putService(new Service(this, "KeyGenerator", name,
            P11GenericSecretKeyGeneratorSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11GenericSecretKeyGeneratorSpi(lib, name, defaultKeySizeBytes);
            }
        });
    }

    private void registerAESWrap(String name, long mechType) {
        putService(new Service(this, "Cipher", name,
            P11AESWrapCipherSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11AESWrapCipherSpi(lib, mechType);
            }
        });
    }

    private void registerMLKEMKeyPairGenerator(String name, long parameterSet) {
        putService(new Service(this, "KeyPairGenerator", name,
            P11MLKEMKeyPairGeneratorSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11MLKEMKeyPairGeneratorSpi(lib, name, parameterSet);
            }
        });
    }

    private void registerRSAPKCS1(String name, long mech) {
        putService(new Service(this, "Signature", name,
            P11PureSigSignatureSpi.class.getName(), List.of(), Map.of()) {
            @Override
            public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
                return new P11PureSigSignatureSpi(lib, mech);
            }
        });
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
