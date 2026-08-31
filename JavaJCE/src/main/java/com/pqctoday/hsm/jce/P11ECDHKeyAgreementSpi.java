package com.pqctoday.hsm.jce;

import org.bouncycastle.asn1.ASN1OctetString;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * "ECDH" KeyAgreement (CKM_ECDH1_DERIVE, CKD_NULL — plain ECDH, no KDF).
 * Standard two-phase JCA KeyAgreement shape: engineInit(ourPrivateKey),
 * engineDoPhase(theirPublicKey, lastPhase=true), engineGenerateSecret().
 *
 * peerPublicKey may be either a P11Key.Pub (our own generated/imported EC
 * key) or any foreign PublicKey exposing "X.509" getEncoded() — the
 * latter is imported on the fly via P11PublicKeyFactorySpi rather than
 * duplicating that OID-dispatch/attribute-template logic here.
 *
 * CK_ECDH1_DERIVE_PARAMS.pPublicData needs the RAW uncompressed EC point,
 * not the DER-OCTET-STRING-wrapped form CKA_EC_POINT stores — confirmed
 * against the sandbox's own proven C sample (08_ecdh_p256.c) before
 * writing P11Library.ecdh1Derive. Unwrapped here via Bouncy Castle's
 * ASN1OctetString rather than hand-parsing the tag+length bytes (the C
 * sample had to hand-roll this only because it has no ASN.1 library
 * available — we do, and reuse it, same "don't hand-roll a codec"
 * discipline as the ECDSA signature format and the EC point wrapping in
 * KeyFactory import).
 *
 * Shared-secret extraction follows the same deliberate, documented
 * exception as ML-KEM's (see P11MLKEMSpi's javadoc): engineGenerateSecret()
 * must return raw bytes to the JCA caller by contract, so the derived
 * secret-key object is created CKA_EXTRACTABLE=true and read back.
 *
 * Item 5 (2026-08-30): cofactor mode (CKM_ECDH1_COFACTOR_DERIVE),
 * registered as a SECOND KeyAgreement service, "ECDHC" — this class
 * unchanged in shape, just a {@code cofactor} flag selecting which
 * mechanism {@link P11Library#ecdh1Derive} dispatches. Confirmed real
 * before building this: SoftHSM_keygen.cpp genuinely implements cofactor
 * multiplication for this mechanism (not an alias for plain ECDH — see
 * OSSLECDH.cpp's "Enable cofactor Diffie-Hellman" comment), restricted to
 * CKK_EC keys only (PKCS#11 v3.2 Table 79 forbids it for
 * CKK_EC_MONTGOMERY/CKK_EC_EDWARDS — irrelevant here since this class's
 * own "EC" KeyPairGenerator only ever produces CKK_EC/Weierstrass keys).
 *
 * "ECDHC" naming — verified live, not guessed (a prior audit's claim that
 * this is "SunEC's own convention" turned out to be WRONG): a full grep
 * of JDK 27's own java.base source (src.zip, sun/security/ec and every
 * other package) has no "ECDHC" algorithm name at all — SunEC only
 * registers "ECDH". Bouncy Castle 1.85.2, however, DOES register
 * "ECDHC" as a real KeyAgreement service (confirmed live via
 * Security.getServices() inside the pqc-dev-sandbox container), which is
 * also the traditional, widely-recognized name for cofactor
 * Diffie-Hellman across the broader JCA ecosystem — used here on that
 * basis, not SunEC's (which doesn't have it).
 *
 * Genuine limitation, disclosed rather than hidden: every curve this
 * provider's "EC" KeyPairGenerator produces (secp256r1/384r1/521r1) has
 * cofactor h=1, so CKM_ECDH1_COFACTOR_DERIVE's output is numerically
 * IDENTICAL to plain CKM_ECDH1_DERIVE's on all of them — this module has
 * no curve with h&gt;1 to demonstrate a byte-different result. The
 * verification test therefore proves the real, distinct mechanism value
 * round-trips correctly end-to-end (two parties agree on the same
 * secret through it), not that its arithmetic differs from plain ECDH on
 * any curve this provider currently exposes.
 */
final class P11ECDHKeyAgreementSpi extends KeyAgreementSpi {
    private final P11Library lib;
    private final boolean cofactor;
    private long ourPrivateKeyHandle = -1;
    private byte[] derivedSecret;

    P11ECDHKeyAgreementSpi(P11Library lib) {
        this(lib, false);
    }

    P11ECDHKeyAgreementSpi(P11Library lib, boolean cofactor) {
        this.lib = lib;
        this.cofactor = cofactor;
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof P11Key.Priv p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3Provider.class.getSimpleName());
        }
        ourPrivateKeyHandle = p.handle();
        // Real KeyAgreementSpi contract (verified against JDK 27 source):
        // "After a call to generateSecret, the object can be reused... by
        // calling one of the init methods" — so a caller starting a new
        // agreement here has, by contract, already finished with any
        // prior derivedSecret. Zero it before discarding the reference
        // (§6.5) rather than just dropping it for the GC to reclaim
        // whenever it gets around to it.
        if (derivedSecret != null) java.util.Arrays.fill(derivedSecret, (byte) 0);
        derivedSecret = null;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("plain ECDH takes no parameters");
        }
        engineInit(key, random);
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException {
        if (ourPrivateKeyHandle < 0) {
            throw new IllegalStateException("engineInit was not called");
        }
        if (!lastPhase) {
            throw new IllegalStateException("plain two-party ECDH has exactly one phase (lastPhase must be true)");
        }
        byte[] rawPeerPoint = rawPointOf(key);

        P11Library.Attr[] ssTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, false),
            P11Library.attrBool(CKA_EXTRACTABLE, true), // see class javadoc
        };
        long ssHandle = lib.ecdh1Derive(
            cofactor ? CKM_ECDH1_COFACTOR_DERIVE : CKM_ECDH1_DERIVE,
            ourPrivateKeyHandle, rawPeerPoint, ssTmpl);
        derivedSecret = lib.getAttributeBytes(ssHandle, CKA_VALUE);
        return null; // no intermediate key for a 2-party exchange
    }

    private byte[] rawPointOf(Key peerKey) throws InvalidKeyException {
        long handle;
        if (peerKey instanceof P11Key.Pub p) {
            handle = p.handle();
        } else if (peerKey instanceof java.security.PublicKey pub
                && "X.509".equals(pub.getFormat()) && pub.getEncoded() != null) {
            // Foreign EC public key — import via the same KeyFactory path
            // proven in W2, rather than re-parsing the SPKI here.
            // engineTranslateKey already declares throws InvalidKeyException,
            // matching this method's own signature — let it propagate.
            P11PublicKeyFactorySpi kf = new P11PublicKeyFactorySpi(lib);
            Key imported = kf.engineTranslateKey(pub);
            if (!(imported instanceof P11Key.Pub p2)) {
                throw new InvalidKeyException("imported key is not an EC public key");
            }
            handle = p2.handle();
        } else {
            throw new InvalidKeyException("unsupported peer key type " + peerKey.getClass());
        }
        byte[] wrapped = lib.getAttributeBytes(handle, CKA_EC_POINT);
        return ASN1OctetString.getInstance(wrapped).getOctets();
    }

    @Override
    protected byte[] engineGenerateSecret() {
        requireDerived();
        return derivedSecret.clone();
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws ShortBufferException {
        requireDerived();
        if (sharedSecret.length - offset < derivedSecret.length) {
            throw new ShortBufferException("need " + derivedSecret.length + " bytes");
        }
        System.arraycopy(derivedSecret, 0, sharedSecret, offset, derivedSecret.length);
        return derivedSecret.length;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) {
        requireDerived();
        return new SecretKeySpec(derivedSecret, algorithm);
    }

    private void requireDerived() {
        if (derivedSecret == null) {
            throw new IllegalStateException("engineDoPhase(peerKey, true) was not called");
        }
    }
}
