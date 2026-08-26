package com.pqctoday.hsm.jce;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * PUBLIC-key-only KeyFactory — imports a foreign X.509-encoded public key
 * onto the token (via C_CreateObject) so it can be used with this
 * provider's Signature classes, closing the gap noted in the ML-DSA
 * commit: a JDK/BC-generated key could not previously be verified by our
 * provider (only the reverse direction worked). Private-key import is
 * refused unconditionally — decided in the original implementation plan
 * (§4, "private import refused — L3"): an imported private key's material
 * would have crossed through JVM memory to get here, which is exactly
 * what the opaque-key/L3 design (P11Key's own javadoc) exists to prevent.
 *
 * One generic class serves every registered algorithm name (matching
 * P11PureSigSignatureSpi's precedent): import dispatches on the SPKI's
 * own embedded AlgorithmIdentifier OID, which is self-describing — not on
 * which service name was used to look up this KeyFactory.
 *
 * ASN.1 parsing uses Bouncy Castle's org.bouncycastle.asn1 classes
 * (SubjectPublicKeyInfo/RSAPublicKey/DEROctetString), already a
 * dependency for the ECDSA codec — pure syntax, not crypto, same
 * boundary as everywhere else BC appears in this module. Every OID and
 * every per-algorithm CKA_EC_POINT/CKA_VALUE wire-format decision below
 * was confirmed empirically against the live engine (see the KeyFactory
 * import commit) before being hardcoded — including one asymmetry that
 * would have silently broken import if assumed: EdDSA's CKA_EC_POINT is
 * RAW (unwrapped), while ordinary EC's CKA_EC_POINT is a DER OCTET
 * STRING wrapping the same raw point bytes, despite sharing the same
 * attribute name.
 */
final class P11PublicKeyFactorySpi extends KeyFactorySpi {
    private final P11Library lib;

    // OID -> { JCA algorithm name, CKK_* key type, CKA_PARAMETER_SET value or -1 }
    // Values confirmed live by generating one key per algorithm through
    // this provider and reading back its real SPKI OID via BC — not
    // taken from any external reference.
    private record PureSigAlgo(String jcaName, long parameterSet) {}
    private static final Map<String, PureSigAlgo> ML_DSA_OIDS = Map.of(
        "2.16.840.1.101.3.4.3.17", new PureSigAlgo("ML-DSA-44", CKP_ML_DSA_44),
        "2.16.840.1.101.3.4.3.18", new PureSigAlgo("ML-DSA-65", CKP_ML_DSA_65),
        "2.16.840.1.101.3.4.3.19", new PureSigAlgo("ML-DSA-87", CKP_ML_DSA_87)
    );
    private static final Map<String, PureSigAlgo> SLH_DSA_OIDS = Map.ofEntries(
        Map.entry("2.16.840.1.101.3.4.3.20", new PureSigAlgo("SLH-DSA-SHA2-128S", CKP_SLH_DSA_SHA2_128S)),
        Map.entry("2.16.840.1.101.3.4.3.21", new PureSigAlgo("SLH-DSA-SHA2-128F", CKP_SLH_DSA_SHA2_128F)),
        Map.entry("2.16.840.1.101.3.4.3.22", new PureSigAlgo("SLH-DSA-SHA2-192S", CKP_SLH_DSA_SHA2_192S)),
        Map.entry("2.16.840.1.101.3.4.3.23", new PureSigAlgo("SLH-DSA-SHA2-192F", CKP_SLH_DSA_SHA2_192F)),
        Map.entry("2.16.840.1.101.3.4.3.24", new PureSigAlgo("SLH-DSA-SHA2-256S", CKP_SLH_DSA_SHA2_256S)),
        Map.entry("2.16.840.1.101.3.4.3.25", new PureSigAlgo("SLH-DSA-SHA2-256F", CKP_SLH_DSA_SHA2_256F)),
        Map.entry("2.16.840.1.101.3.4.3.26", new PureSigAlgo("SLH-DSA-SHAKE-128S", CKP_SLH_DSA_SHAKE_128S)),
        Map.entry("2.16.840.1.101.3.4.3.27", new PureSigAlgo("SLH-DSA-SHAKE-128F", CKP_SLH_DSA_SHAKE_128F)),
        Map.entry("2.16.840.1.101.3.4.3.28", new PureSigAlgo("SLH-DSA-SHAKE-192S", CKP_SLH_DSA_SHAKE_192S)),
        Map.entry("2.16.840.1.101.3.4.3.29", new PureSigAlgo("SLH-DSA-SHAKE-192F", CKP_SLH_DSA_SHAKE_192F)),
        Map.entry("2.16.840.1.101.3.4.3.30", new PureSigAlgo("SLH-DSA-SHAKE-256S", CKP_SLH_DSA_SHAKE_256S)),
        Map.entry("2.16.840.1.101.3.4.3.31", new PureSigAlgo("SLH-DSA-SHAKE-256F", CKP_SLH_DSA_SHAKE_256F))
    );
    private static final Map<String, PureSigAlgo> ML_KEM_OIDS = Map.of(
        "2.16.840.1.101.3.4.4.1", new PureSigAlgo("ML-KEM-512", CKP_ML_KEM_512),
        "2.16.840.1.101.3.4.4.2", new PureSigAlgo("ML-KEM-768", CKP_ML_KEM_768),
        "2.16.840.1.101.3.4.4.3", new PureSigAlgo("ML-KEM-1024", CKP_ML_KEM_1024)
    );
    private static final String OID_ED25519 = "1.3.101.112";
    private static final String OID_ED448 = "1.3.101.113";
    private static final String OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    private static final String OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

    P11PublicKeyFactorySpi(P11Library lib) {
        this.lib = lib;
    }

    @Override
    protected java.security.PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof ECPublicKeySpec ecSpec) {
            // Curve name/OID unknown here (ECParameterSpec carries only
            // the raw field/curve/generator/order/cofactor values, not a
            // name) — identified by field size, since this module
            // supports exactly the three curves P11EcCurves knows about.
            // Needed for JDK 27's own DHasKEM (the classical half of JEP
            // 527 hybrid TLS groups) to deserialize a peer's key_share —
            // its DeserializePublicKey builds exactly this KeySpec shape
            // and calls KeyFactory.getInstance("EC").generatePublic(...)
            // with no explicit provider, landing here once this provider
            // is installed at top priority (plan §W6). Found live: this
            // method previously rejected anything but X509EncodedKeySpec.
            P11EcCurves.Curve curve;
            try {
                curve = P11EcCurves.byFieldSize(ecSpec.getParams());
            } catch (IllegalArgumentException e) {
                throw new InvalidKeySpecException(e.getMessage());
            }
            byte[] rawPoint = P11EcCurves.encodePoint(ecSpec.getW(), curve.coordBytes());
            return importEC(curve, rawPoint, null);
        }
        if (!(keySpec instanceof X509EncodedKeySpec x509Spec)) {
            throw new InvalidKeySpecException("only X509EncodedKeySpec or ECPublicKeySpec is supported for import");
        }
        SubjectPublicKeyInfo info;
        try {
            info = SubjectPublicKeyInfo.getInstance(x509Spec.getEncoded());
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException("malformed X.509 SubjectPublicKeyInfo", e);
        }
        String oid = info.getAlgorithm().getAlgorithm().getId();
        byte[] rawKeyMaterial = info.getPublicKeyData().getBytes();

        PureSigAlgo mldsa = ML_DSA_OIDS.get(oid);
        if (mldsa != null) return importPureSig(mldsa, CKK_ML_DSA, rawKeyMaterial, x509Spec.getEncoded());

        PureSigAlgo slhdsa = SLH_DSA_OIDS.get(oid);
        if (slhdsa != null) return importPureSig(slhdsa, CKK_SLH_DSA, rawKeyMaterial, x509Spec.getEncoded());

        PureSigAlgo mlkem = ML_KEM_OIDS.get(oid);
        if (mlkem != null) return importMLKEM(mlkem, rawKeyMaterial, x509Spec.getEncoded());

        if (oid.equals(OID_ED25519)) return importEdDSA("Ed25519", ED25519_OID, rawKeyMaterial, x509Spec.getEncoded());
        if (oid.equals(OID_ED448)) return importEdDSA("Ed448", ED448_OID, rawKeyMaterial, x509Spec.getEncoded());

        if (oid.equals(OID_EC_PUBLIC_KEY)) {
            String curveOid = ASN1ObjectIdentifier.getInstance(info.getAlgorithm().getParameters()).getId();
            P11EcCurves.Curve curve = P11EcCurves.BY_OID.get(curveOid);
            if (curve == null) {
                throw new InvalidKeySpecException("unsupported EC curve OID " + curveOid);
            }
            return importEC(curve, rawKeyMaterial, x509Spec.getEncoded());
        }

        if (oid.equals(OID_RSA_ENCRYPTION)) {
            RSAPublicKey rsaKey = RSAPublicKey.getInstance(rawKeyMaterial);
            return importRSA(rsaKey.getModulus(), rsaKey.getPublicExponent(), x509Spec.getEncoded());
        }

        throw new InvalidKeySpecException("unsupported public key algorithm OID " + oid);
    }

    private P11Key.Pub importPureSig(PureSigAlgo algo, long keyType, byte[] rawValue, byte[] spki) {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, keyType),
            P11Library.attrLong(CKA_PARAMETER_SET, algo.parameterSet()),
            P11Library.attr(CKA_VALUE, rawValue),
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        long handle = lib.createObject(tmpl);
        return new P11Key.Pub(lib, handle, algo.jcaName(), spki);
    }

    private P11Key.Pub importMLKEM(PureSigAlgo algo, byte[] rawValue, byte[] spki) {
        // Same shape as importPureSig, but CKA_ENCAPSULATE instead of
        // CKA_VERIFY (an ML-KEM public key's operation is encapsulation,
        // not verification) — see P11MLKEMKeyPairGeneratorSpi's javadoc
        // for the same distinction on the generation side.
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_ML_KEM),
            P11Library.attrLong(CKA_PARAMETER_SET, algo.parameterSet()),
            P11Library.attr(CKA_VALUE, rawValue),
            P11Library.attrBool(CKA_ENCAPSULATE, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        long handle = lib.createObject(tmpl);
        return new P11Key.Pub(lib, handle, algo.jcaName(), spki);
    }

    private P11Key.Pub importEdDSA(String jcaName, byte[] curveOidDer, byte[] rawPoint, byte[] spki) {
        // EdDSA's CKA_EC_POINT is RAW (unwrapped) — see class javadoc.
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_EC_EDWARDS),
            P11Library.attr(CKA_EC_PARAMS, curveOidDer),
            P11Library.attr(CKA_EC_POINT, rawPoint), // RAW for EdDSA — see class javadoc
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        long handle = lib.createObject(tmpl);
        return new P11Key.Pub(lib, handle, jcaName, spki);
    }

    /**
     * @param spki the real X.509 SubjectPublicKeyInfo DER when the caller
     *     has one (the X509EncodedKeySpec import path); {@code null} when
     *     importing from a bare {@link ECPublicKeySpec} (no encoded form
     *     was ever handed to us — DHasKEM's peer-key deserialization,
     *     plan §W6) — in which case one is built here via Bouncy Castle
     *     rather than left absent, so {@code getEncoded()} on the
     *     resulting key stays honest instead of NPEing the first time
     *     something calls it.
     */
    private P11Key.EcPub importEC(P11EcCurves.Curve curve, byte[] rawPoint, byte[] spki) throws InvalidKeySpecException {
        // Ordinary EC's CKA_EC_POINT IS a DER OCTET STRING wrapping the
        // raw point — confirmed empirically (see class javadoc), so wrap
        // it here with Bouncy Castle rather than hand-rolling the 1-2
        // byte tag+length prefix.
        byte[] wrapped;
        byte[] effectiveSpki = spki;
        try {
            wrapped = new DEROctetString(rawPoint).getEncoded("DER");
            if (effectiveSpki == null) {
                var algId = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                    new ASN1ObjectIdentifier(OID_EC_PUBLIC_KEY), new ASN1ObjectIdentifier(curve.oid()));
                effectiveSpki = new SubjectPublicKeyInfo(algId, rawPoint).getEncoded("DER");
            }
        } catch (IOException e) {
            throw new InvalidKeySpecException("failed to DER-encode EC point/SubjectPublicKeyInfo", e);
        }
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_EC),
            P11Library.attr(CKA_EC_PARAMS, curve.oidDer()),
            P11Library.attr(CKA_EC_POINT, wrapped), // DER-OCTET-STRING-wrapped — see class javadoc
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        long handle = lib.createObject(tmpl);
        java.security.spec.ECPoint w = P11EcCurves.decodePoint(rawPoint, curve.coordBytes());
        java.security.spec.ECParameterSpec ecParams = P11EcCurves.jdkParams(curve);
        return new P11Key.EcPub(lib, handle, effectiveSpki, ecParams, w);
    }

    private P11Key.Pub importRSA(BigInteger modulus, BigInteger exponent, byte[] spki) {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_PUBLIC_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_RSA),
            P11Library.attr(CKA_MODULUS, unsignedBigEndian(modulus)),
            P11Library.attr(CKA_PUBLIC_EXPONENT, unsignedBigEndian(exponent)),
            P11Library.attrBool(CKA_VERIFY, true),
            P11Library.attrBool(CKA_ENCRYPT, true),
            P11Library.attrBool(CKA_TOKEN, false),
        };
        long handle = lib.createObject(tmpl);
        return new P11Key.Pub(lib, handle, "RSA", spki);
    }

    private static byte[] unsignedBigEndian(BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? java.util.Arrays.copyOfRange(b, 1, b.length) : b;
    }

    @Override
    protected java.security.PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        throw new InvalidKeySpecException("private key import is refused by this provider's FIPS 140-3 L3 "
            + "posture — an imported private key's material would have already crossed through JVM memory, "
            + "which the opaque-key design exists to prevent (see the implementation plan §6.2 and P11Key's javadoc)");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key instanceof P11Key.Pub pub && keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
            return keySpec.cast(new X509EncodedKeySpec(pub.getEncoded()));
        }
        throw new InvalidKeySpecException("unsupported key/spec combination");
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof P11Key.Pub || key instanceof P11Key.Priv) return key;
        if (key instanceof java.security.PublicKey pub && "X.509".equals(pub.getFormat()) && pub.getEncoded() != null) {
            try {
                return engineGeneratePublic(new X509EncodedKeySpec(pub.getEncoded()));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        }
        throw new InvalidKeyException("cannot translate key of type " + key.getClass());
    }
}
