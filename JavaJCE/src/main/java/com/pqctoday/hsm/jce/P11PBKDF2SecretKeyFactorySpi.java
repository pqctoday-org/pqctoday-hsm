package com.pqctoday.hsm.jce;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.nio.charset.StandardCharsets;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * PBKDF2WithHmacSHA256/384/512 (SP 800-132) via CKM_PKCS5_PBKD2 — no base
 * key needed, confirmed by reading SoftHSM_keygen.cpp before writing this
 * class: the password lives entirely in the mechanism parameters, and
 * the engine's C_DeriveKey handles this mechanism in an early branch
 * that never resolves a base-key handle at all (see
 * P11Library.deriveKeyNoBase's javadoc).
 *
 * Only CKZ_SALT_SPECIFIED (a raw byte salt) is supported by this engine
 * — the only source type PBEKeySpec's own shape (plain byte[] salt)
 * needs anyway, so no gap here.
 *
 * Derived keys are opaque (CKA_EXTRACTABLE=false), same as every
 * generated/derived key elsewhere in this module (plan §6.2) — a
 * deliberate consistency choice, not a JCA requirement (SecretKey does
 * not require a real getEncoded()). engineGetKeySpec/engineTranslateKey
 * both refuse for the same reason P11PublicKeyFactorySpi refuses
 * private-key import: there is no way to recover a spec, or usefully
 * "translate", an opaque handle-backed key.
 */
final class P11PBKDF2SecretKeyFactorySpi extends SecretKeyFactorySpi {
    private final P11Library lib;
    private final long prf;

    P11PBKDF2SecretKeyFactorySpi(P11Library lib, long prf) {
        this.lib = lib;
        this.prf = prf;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec spec)) {
            throw new InvalidKeySpecException("expected a PBEKeySpec, got " + keySpec.getClass());
        }
        char[] password = spec.getPassword();
        byte[] salt = spec.getSalt();
        int iterations = spec.getIterationCount();
        int keyLengthBits = spec.getKeyLength();
        if (salt == null || salt.length == 0) {
            throw new InvalidKeySpecException("PBKDF2 requires a non-empty salt");
        }
        if (iterations <= 0) {
            throw new InvalidKeySpecException("PBKDF2 requires a positive iteration count");
        }
        if (keyLengthBits <= 0 || keyLengthBits % 8 != 0 || keyLengthBits / 8 > 512) {
            throw new InvalidKeySpecException(
                "PBKDF2 key length must be a positive multiple of 8 bits, at most 4096 (got " + keyLengthBits + ")");
        }

        byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
        try {
            var mech = lib.mechPbkdf2(prf, salt, iterations, passwordBytes);
            P11Library.Attr[] outputTmpl = {
                P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
                P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                P11Library.attrLong(CKA_VALUE_LEN, keyLengthBits / 8),
                P11Library.attrBool(CKA_TOKEN, false),
                P11Library.attrBool(CKA_SENSITIVE, true),
                P11Library.attrBool(CKA_EXTRACTABLE, false),
                P11Library.attrBool(CKA_DERIVE, true),
                P11Library.attrBool(CKA_ENCRYPT, true),
                P11Library.attrBool(CKA_DECRYPT, true),
                P11Library.attrBool(CKA_SIGN, true),
            };
            long handle = lib.deriveKeyNoBase(mech, outputTmpl);
            return new P11Key.Secret(lib, handle, "PBKDF2");
        } finally {
            java.util.Arrays.fill(passwordBytes, (byte) 0);
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        throw new InvalidKeySpecException(
            "cannot recover a KeySpec from an opaque, token-resident key — this provider never exports derived key material");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof P11Key.Secret) {
            return key; // already one of ours — pass through, matching every other translateKey precedent in this module
        }
        throw new InvalidKeyException(
            "cannot translate a foreign key into this provider's opaque representation — regenerate it via engineGenerateSecret instead");
    }
}
