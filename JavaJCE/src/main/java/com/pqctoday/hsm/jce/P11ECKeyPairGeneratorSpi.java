package com.pqctoday.hsm.jce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * "EC" KeyPairGenerator — a genuinely different registration shape than
 * ML-DSA/SLH-DSA/EdDSA: those register one service per parameter set
 * (e.g. "ML-DSA-65"), matching how PKCS#11 ties the parameter set to the
 * key. Standard JCA "EC" is ONE service covering every curve, with the
 * curve selected at initialize() time via ECGenParameterSpec — matching
 * how SunEC itself works, so ordinary EC-using code (new
 * ECGenParameterSpec("secp256r1")) needs no changes to target this
 * provider. generateKeyPair() before a successful initialize() throws
 * (no implicit default curve — same as requiring an explicit choice).
 *
 * CKA_EC_PARAMS encoding: same DER-OID-bytes approach as EdDSA (traced to
 * SoftHSM_keygen.cpp's generateEC, which reads CKA_EC_PARAMS out of the
 * template exactly like generateED does). secp256r1's bytes are already
 * proven live in the sandbox's C samples; secp521r1's are taken from this
 * repo's own p11_v32_compliance_test.cpp (already live-verified,
 * 779/0 PASS this session). secp384r1's bytes were NOT found reused
 * anywhere in this repo — derived by direct analogy to secp521r1's proven
 * encoding (same OID arc prefix 1.3.132.0.x, SECG namedCurve arc, only
 * the final arc number differs: 34 vs 35) and confirmed empirically live
 * (see the W2 EC commit) by generating a real key and checking the
 * resulting EC point size matches P-384's known 48-byte coordinate size
 * — not assumed correct from the derivation alone.
 */
final class P11ECKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final P11Library lib;

    private P11EcCurves.Curve curve;

    P11ECKeyPairGeneratorSpi(P11Library lib) {
        this.lib = lib;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        // Matches the keysize -> curve mapping SunEC itself documents.
        String name = switch (keysize) {
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> throw new InvalidParameterException(
                "unsupported EC key size " + keysize + " (use 256, 384, or 521)");
        };
        curve = P11EcCurves.BY_NAME.get(name);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof ECGenParameterSpec ecSpec)) {
            throw new InvalidAlgorithmParameterException(
                "expected ECGenParameterSpec, got " + (params == null ? "null" : params.getClass()));
        }
        P11EcCurves.Curve c = P11EcCurves.BY_NAME.get(ecSpec.getName());
        if (c == null) {
            throw new InvalidAlgorithmParameterException(
                "unsupported curve " + ecSpec.getName() + " — supported: " + P11EcCurves.BY_NAME.keySet());
        }
        curve = c;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (curve == null) {
            throw new ProviderException("EC KeyPairGenerator was not initialized with a curve "
                + "(call initialize(new ECGenParameterSpec(\"secp256r1\"|\"secp384r1\"|\"secp521r1\")) first)");
        }
        P11Debug.log("EC KeyPairGenerator.generateKeyPair() — token C_GenerateKeyPair, curve=" + curve.name());
        P11Library.Attr[] pubTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_EC),
            P11Library.attr(CKA_EC_PARAMS, curve.oidDer()),
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
            // A real EC keypair is algorithm-agnostic at generation time
            // — the single JCA "EC" KeyPairGenerator serves both ECDSA
            // (CKA_SIGN) and ECDH (CKA_DERIVE), so both must be granted
            // here, unlike every other keygen class in this module whose
            // single-purpose key only ever needs one. Missing this
            // caused a real, live CKR_KEY_FUNCTION_NOT_PERMITTED from
            // C_DeriveKey during W3's ECDH work — the token correctly
            // refusing a key that was never authorized for derive.
            P11Library.attrBool(CKA_DERIVE, true),
        };
        long[] handles = lib.generateKeyPair(CKM_EC_KEY_PAIR_GEN, pubTmpl, prvTmpl);
        byte[] spki = lib.getAttributeBytes(handles[0], CKA_PUBLIC_KEY_INFO);
        // CKA_EC_POINT is a DER OCTET STRING wrapping the raw uncompressed
        // point (same convention already proven in P11ECDHKeyAgreementSpi/
        // P11PublicKeyFactorySpi's importEC) — unwrap it to build the real
        // java.security.spec.ECPoint EcPub needs for JEP 527 TLS (plan §W6).
        byte[] wrappedPoint = lib.getAttributeBytes(handles[0], CKA_EC_POINT);
        byte[] rawPoint = org.bouncycastle.asn1.ASN1OctetString.getInstance(wrappedPoint).getOctets();
        java.security.spec.ECPoint w = P11EcCurves.decodePoint(rawPoint, curve.coordBytes());
        java.security.spec.ECParameterSpec ecParams = P11EcCurves.jdkParams(curve);
        P11Key.EcPub pub = new P11Key.EcPub(lib, handles[0], spki, ecParams, w);
        P11Key.EcPriv priv = new P11Key.EcPriv(lib, handles[1], ecParams);
        return new KeyPair(pub, priv);
    }
}
