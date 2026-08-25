package com.pqctoday.hsm.jce;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Map;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * SP 800-108 counter/feedback KDF — "SP800-108-Counter" and
 * "SP800-108-Feedback", one factory instance per mode (not per PRF —
 * unlike OAEP/HMAC/PBKDF2's one-service-per-digest pattern elsewhere in
 * this module, the PRF choice lives in {@link P11SP800108KeySpec}
 * instead, since a per-(mode,PRF) registration would be 18 services for
 * a low-usage feature with no standard JCA name to hang them off of
 * anyway).
 *
 * Derived keys are opaque, same as every other derived/generated key in
 * this module.
 */
final class P11SP800108SecretKeyFactorySpi extends SecretKeyFactorySpi {

    private static final Map<String, Long> PRF_NAMES = Map.ofEntries(
        Map.entry("HmacSHA224", CKM_SHA224_HMAC),
        Map.entry("HmacSHA256", CKM_SHA256_HMAC),
        Map.entry("HmacSHA384", CKM_SHA384_HMAC),
        Map.entry("HmacSHA512", CKM_SHA512_HMAC),
        Map.entry("HmacSHA3-224", CKM_SHA3_224_HMAC),
        Map.entry("HmacSHA3-256", CKM_SHA3_256_HMAC),
        Map.entry("HmacSHA3-384", CKM_SHA3_384_HMAC),
        Map.entry("HmacSHA3-512", CKM_SHA3_512_HMAC),
        Map.entry("AESCMAC", CKM_AES_CMAC)
    );

    private final P11Library lib;
    private final boolean feedback;

    P11SP800108SecretKeyFactorySpi(P11Library lib, boolean feedback) {
        this.lib = lib;
        this.feedback = feedback;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof P11SP800108KeySpec spec)) {
            throw new InvalidKeySpecException("expected a P11SP800108KeySpec, got " + keySpec.getClass());
        }
        Long prfMech = PRF_NAMES.get(spec.prf());
        if (prfMech == null) {
            throw new InvalidKeySpecException("unknown PRF \"" + spec.prf() + "\" — expected one of " + PRF_NAMES.keySet());
        }
        if (spec.outputLengthBits() <= 0 || spec.outputLengthBits() % 8 != 0 || spec.outputLengthBits() / 8 > 512) {
            throw new InvalidKeySpecException(
                "output length must be a positive multiple of 8 bits, at most 4096 (got " + spec.outputLengthBits() + ")");
        }

        long baseHandle;
        try {
            baseHandle = handleOf(spec.baseKey());
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }

        var mech = feedback
            ? lib.mechSp800108Feedback(prfMech, spec.fixedInput(), spec.iv())
            : lib.mechSp800108Counter(prfMech, spec.fixedInput());

        P11Library.Attr[] outputTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attrLong(CKA_VALUE_LEN, spec.outputLengthBits() / 8),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_DERIVE, true),
            P11Library.attrBool(CKA_ENCRYPT, true),
            P11Library.attrBool(CKA_DECRYPT, true),
            P11Library.attrBool(CKA_SIGN, true),
        };
        long handle = lib.deriveKey(mech, baseHandle, outputTmpl);
        return new P11Key.Secret(handle, feedback ? "SP800-108-Feedback" : "SP800-108-Counter");
    }

    /** Resolves the base key (Ki) to a token handle — directly for our own keys, or by importing a foreign key's raw bytes. */
    private long handleOf(SecretKey key) throws InvalidKeyException {
        if (key instanceof P11Key.Secret s) return s.handle();
        byte[] raw = key.getEncoded();
        if (raw == null) {
            throw new InvalidKeyException("base key has no encoded form and no token handle");
        }
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attr(CKA_VALUE, raw),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_DERIVE, true),
        };
        return lib.createObject(tmpl);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        throw new InvalidKeySpecException(
            "cannot recover a KeySpec from an opaque, token-resident key — this provider never exports derived key material");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof P11Key.Secret) {
            return key;
        }
        throw new InvalidKeyException(
            "cannot translate a foreign key into this provider's opaque representation — regenerate it via engineGenerateSecret instead");
    }
}
