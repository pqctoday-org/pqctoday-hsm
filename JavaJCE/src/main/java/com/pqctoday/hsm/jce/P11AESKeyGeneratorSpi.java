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
 *
 * Item 1 (2026-08-30 follow-on) also routes AES-XTS keygen through this
 * SAME class via the {@code xts} constructor flag, registered under the
 * separate JCA name "AES_XTS" (see SoftHSMv3Provider's registration site
 * for why a distinct name is unavoidable here, unlike every other AES
 * mode which shares the plain "AES" KeyGenerator): CKM_AES_XTS_KEY_GEN
 * produces a genuinely different, double-length CKK_AES_XTS key (32 or 64
 * raw bytes — two concatenated AES-128 or AES-256 sub-keys, PKCS#11 v3.2
 * §6.15.2 Table 124), which the engine's own C_GenerateKey validation
 * (SoftHSM_keygen.cpp's generateAESXTS) rejects at any other length, and
 * which P11AESCipherSpi's XTS mode requires be CKK_AES_XTS-typed
 * specifically (never plain CKK_AES) — so a single "AES" name producing
 * either key shape by accident was never an option. engineInit(int)'s
 * `keysize` here means the TOTAL raw key size in bits (256 or 512),
 * matching both CKA_VALUE_LEN*8 and the real-world dm-crypt/LUKS
 * "aes-xts-plain64 --key-size 512" convention (not the per-sub-key AES
 * strength) — no live JCA precedent for this convention was found (see
 * P11AESCipherSpi's own javadoc for the live BC/JDK probe results this
 * item's whole naming/sizing scheme is grounded in), so this is disclosed
 * as this provider's own reasoned choice, not a borrowed one.
 */
final class P11AESKeyGeneratorSpi extends KeyGeneratorSpi {
    private final P11Library lib;
    private final boolean xts;
    private int keySizeBits;

    P11AESKeyGeneratorSpi(P11Library lib) {
        this(lib, false);
    }

    P11AESKeyGeneratorSpi(P11Library lib, boolean xts) {
        this.lib = lib;
        this.xts = xts;
        this.keySizeBits = xts ? 512 : 256; // prefer the strongest allowed default, same reasoning either way
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
        if (xts) {
            if (keysize != 256 && keysize != 512) {
                throw new InvalidParameterException(
                    "AES-XTS key size must be 256 or 512 bits TOTAL — two concatenated AES-128 or "
                    + "AES-256 sub-keys (PKCS#11 v3.2 §6.15.2 Table 124: CKA_VALUE is 32 or 64 raw bytes), "
                    + "got " + keysize);
            }
        } else if (keysize != 128 && keysize != 192 && keysize != 256) {
            throw new InvalidParameterException(
                "AES key size must be 128, 192, or 256 bits (got " + keysize + ")");
        }
        this.keySizeBits = keysize;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        P11Library.Attr[] tmpl = xts
            ? new P11Library.Attr[] {
                P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
                P11Library.attrLong(CKA_KEY_TYPE, CKK_AES_XTS),
                P11Library.attrLong(CKA_VALUE_LEN, keySizeBits / 8),
                P11Library.attrBool(CKA_TOKEN, false),
                P11Library.attrBool(CKA_SENSITIVE, true),
                P11Library.attrBool(CKA_EXTRACTABLE, false),
                P11Library.attrBool(CKA_ENCRYPT, true),
                P11Library.attrBool(CKA_DECRYPT, true),
                // Deliberately no CKA_WRAP/CKA_UNWRAP: AES-XTS is a
                // data-at-rest/sector cipher (IEEE 1619-2007), never a key-
                // wrapping KEK — P11AESWrapCipherSpi requires a plain "AES"
                // (CKK_AES) key regardless, so these would be meaningless here.
            }
            : new P11Library.Attr[] {
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
        long handle = lib.generateKey(xts ? CKM_AES_XTS_KEY_GEN : CKM_AES_KEY_GEN, tmpl);
        return new P11Key.Secret(lib, handle, xts ? "AES_XTS" : "AES");
    }
}
