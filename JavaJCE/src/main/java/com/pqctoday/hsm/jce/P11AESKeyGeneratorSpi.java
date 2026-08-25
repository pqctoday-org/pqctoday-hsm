package com.pqctoday.hsm.jce;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * KeyGeneratorSpi for "AES" (FIPS 197) — CKM_AES_KEY_GEN, 128/192/256-bit.
 * The generated key is a session object (CKA_TOKEN=false, matching every
 * other generated key in this provider), non-extractable
 * (CKA_SENSITIVE=true/CKA_EXTRACTABLE=false, plan §6.2), and carries
 * CKA_ENCRYPT/CKA_DECRYPT (for P11AESCipherSpi) and CKA_WRAP/CKA_UNWRAP
 * (for P11AESWrapCipherSpi) — proactively, not discovered live, applying
 * the exact lesson learned twice already in W3 (ECDH's missing
 * CKA_DERIVE, RSA's missing CKA_ENCRYPT/CKA_DECRYPT): grant every
 * operation attribute a key of this type could plausibly need at
 * generation time, not just the one the first caller happens to use.
 *
 * javax.crypto.KeyGenerator never REQUIRES an init() call before
 * generateKey() (unlike KeyPairGenerator's initialize()); this provider's
 * default, applied when engineInit(SecureRandom) is called instead of
 * engineInit(int, SecureRandom), is 256 bits — the FIPS-preferred
 * strength, same reasoning as RSA's "prefer 3072" default elsewhere in
 * this module.
 */
final class P11AESKeyGeneratorSpi extends KeyGeneratorSpi {
    private final P11Library lib;
    private int keySizeBits = 256;

    P11AESKeyGeneratorSpi(P11Library lib) {
        this.lib = lib;
    }

    @Override
    protected void engineInit(SecureRandom random) {
        // Token DRBG is always used for the key itself (C_GenerateKey);
        // this SecureRandom parameter has nothing to seed — same non-use
        // as every other keygen SPI in this module.
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
            "AES KeyGenerator takes a bit-length via engineInit(int, SecureRandom), not an AlgorithmParameterSpec");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != 128 && keysize != 192 && keysize != 256) {
            throw new InvalidParameterException(
                "AES key size must be 128, 192, or 256 bits (got " + keysize + ")");
        }
        this.keySizeBits = keysize;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_AES),
            P11Library.attrLong(CKA_VALUE_LEN, keySizeBits / 8),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_ENCRYPT, true),
            P11Library.attrBool(CKA_DECRYPT, true),
            P11Library.attrBool(CKA_WRAP, true),
            P11Library.attrBool(CKA_UNWRAP, true),
        };
        long handle = lib.generateKey(CKM_AES_KEY_GEN, tmpl);
        return new P11Key.Secret(lib, handle, "AES");
    }
}
