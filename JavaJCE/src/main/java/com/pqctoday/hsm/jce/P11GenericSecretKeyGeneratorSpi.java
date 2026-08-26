package com.pqctoday.hsm.jce;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * CKK_GENERIC_SECRET key generator for HMAC-* and KMAC128/256 — the
 * engine's MAC mechanism table (SoftHSM_sign.cpp's kMacMechTable) marks
 * `allowGenericSecret=true` for every HMAC variant and both KMAC
 * mechanisms (only CKM_AES_CMAC requires the more specific CKK_AES,
 * already covered by P11AESKeyGeneratorSpi — no new class needed there).
 *
 * One instance per registered JCA name, each with a fixed default key
 * length matching the engine's own PKCS#11 minimum for that mechanism
 * (kMacMechTable's minKeyBytes) — SP 800-185's documented KMAC128/256
 * defaults (32/64 bytes) happen to match this same pattern. A caller MAY
 * override via engineInit(int, SecureRandom), same shape as
 * P11AESKeyGeneratorSpi.
 */
final class P11GenericSecretKeyGeneratorSpi extends KeyGeneratorSpi {
    private final P11Library lib;
    private final String algorithm;
    private int keySizeBytes;

    P11GenericSecretKeyGeneratorSpi(P11Library lib, String algorithm, int defaultKeySizeBytes) {
        this.lib = lib;
        this.algorithm = algorithm;
        this.keySizeBytes = defaultKeySizeBytes;
    }

    @Override
    protected void engineInit(SecureRandom random) {
        // Token DRBG generates the key itself (C_GenerateKey) — nothing to seed here.
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
            algorithm + " KeyGenerator takes a byte length via engineInit(int, SecureRandom), not an AlgorithmParameterSpec");
    }

    @Override
    protected void engineInit(int keysizeBits, SecureRandom random) {
        if (keysizeBits <= 0 || keysizeBits % 8 != 0) {
            throw new java.security.InvalidParameterException(
                algorithm + " key size must be a positive multiple of 8 bits (got " + keysizeBits + ")");
        }
        this.keySizeBytes = keysizeBits / 8;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attrLong(CKA_VALUE_LEN, keySizeBytes),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_SIGN, true),
        };
        long handle = lib.generateKey(CKM_GENERIC_SECRET_KEY_GEN, tmpl);
        return new P11Key.Secret(lib, handle, algorithm);
    }
}
