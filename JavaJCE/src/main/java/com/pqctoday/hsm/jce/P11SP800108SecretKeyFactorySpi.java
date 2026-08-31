package com.pqctoday.hsm.jce;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Map;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * SP 800-108 counter/feedback/double-pipeline KDF — "SP800-108-Counter",
 * "SP800-108-Feedback", and "SP800-108-DoublePipeline" (item 4), one
 * factory instance per mode (not per PRF — unlike OAEP/HMAC/PBKDF2's
 * one-service-per-digest pattern elsewhere in this module, the PRF choice
 * lives in {@link P11SP800108KeySpec} instead, since a per-(mode,PRF)
 * registration would be dozens of services for a low-usage feature with
 * no standard JCA name to hang them off of anyway).
 *
 * Double-pipeline mode (SP 800-108 §5.3) is the SAME KBKDF backend as
 * counter/feedback — confirmed reading SoftHSM_keygen.cpp's
 * double-pipeline branch before adding it here: it parses the identical
 * CK_SP800_108_KDF_PARAMS struct counter mode already uses, just a third
 * {@code CKM_SP800_108_DOUBLE_PIPELINE_KDF} mechanism value, not new
 * native machinery — so {@link Mode#DOUBLE_PIPELINE} reuses
 * {@link P11Library#mechSp800108DoublePipeline} exactly the way
 * {@link Mode#COUNTER} reuses {@link P11Library#mechSp800108Counter}.
 *
 * PRF_NAMES also gained {@code HmacSHA512/224}/{@code HmacSHA512/256}
 * (item 4's second finding): a prior audit flagged these as missing;
 * verified still genuinely absent by reading this table directly before
 * adding them (not assumed from the audit note alone).
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
        Map.entry("HmacSHA512/224", CKM_SHA512_224_HMAC),
        Map.entry("HmacSHA512/256", CKM_SHA512_256_HMAC),
        Map.entry("HmacSHA3-224", CKM_SHA3_224_HMAC),
        Map.entry("HmacSHA3-256", CKM_SHA3_256_HMAC),
        Map.entry("HmacSHA3-384", CKM_SHA3_384_HMAC),
        Map.entry("HmacSHA3-512", CKM_SHA3_512_HMAC),
        Map.entry("AESCMAC", CKM_AES_CMAC)
    );

    /** SP 800-108 mode selector — see class javadoc. */
    enum Mode { COUNTER, FEEDBACK, DOUBLE_PIPELINE }

    private final P11Library lib;
    private final Mode mode;

    P11SP800108SecretKeyFactorySpi(P11Library lib, Mode mode) {
        this.lib = lib;
        this.mode = mode;
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
        try (var op = java.lang.foreign.Arena.ofConfined()) {
            var mech = switch (mode) {
                case COUNTER -> lib.mechSp800108Counter(op, prfMech, spec.fixedInput());
                case FEEDBACK -> lib.mechSp800108Feedback(op, prfMech, spec.fixedInput(), spec.iv());
                case DOUBLE_PIPELINE -> lib.mechSp800108DoublePipeline(op, prfMech, spec.fixedInput());
            };
            long handle = lib.deriveKey(op, mech, baseHandle, outputTmpl);
            String label = switch (mode) {
                case COUNTER -> "SP800-108-Counter";
                case FEEDBACK -> "SP800-108-Feedback";
                case DOUBLE_PIPELINE -> "SP800-108-DoublePipeline";
            };
            return new P11Key.Secret(lib, handle, label);
        }
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
