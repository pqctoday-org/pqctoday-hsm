package com.pqctoday.hsm.jce;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * RSA-OAEP Cipher — one instance per registered (digest, MGF) pair,
 * matching the plan's decision to register one JCA name per digest
 * (e.g. "RSA/ECB/OAEPWithSHA-256AndMGF1Padding") rather than a single
 * configurable service the way RSASSA-PSS needed (OAEP's JCA convention
 * fixes the digest in the algorithm name, not via a settable
 * AlgorithmParameterSpec after construction — no
 * engineSetParameter(OAEPParameterSpec) support needed here). SHA-2 and
 * SHA-3 variants both registered (user decision, 2026-08-24, "fuller
 * matrix") — SHA-1 excluded, same FIPS 140-3 L3 policy as everywhere
 * else in this provider.
 *
 * Single-block cipher (no streaming/chunking) — RSA-OAEP always operates
 * on one block up to the modulus-minus-padding-overhead size, matching
 * how P11PureSigSignatureSpi/P11RSAPSSSignatureSpi buffer-then-operate,
 * except here the buffer is the plaintext/ciphertext itself, not a
 * to-be-signed message.
 */
final class P11RSAOAEPCipherSpi extends CipherSpi {
    private final P11Library lib;
    private final long hashAlg;
    private final long mgf;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    private int opmode = -1;
    private long keyHandle = -1;

    P11RSAOAEPCipherSpi(P11Library lib, long hashAlg, long mgf) {
        this.lib = lib;
        this.hashAlg = hashAlg;
        this.mgf = mgf;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"ECB".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("only ECB (single-block) is supported for RSA-OAEP");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.toUpperCase().contains("OAEP")) {
            throw new NoSuchPaddingException("only OAEP padding is supported");
        }
    }

    @Override protected int engineGetBlockSize() { return 0; }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // Conservative upper bound — the real size depends on the key's
        // modulus, only known once initialized with a key.
        return keyHandle < 0 ? inputLen : Integer.MAX_VALUE;
    }

    @Override protected byte[] engineGetIV() { return null; }
    @Override protected AlgorithmParameters engineGetParameters() { return null; }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        initKey(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                "this Cipher's digest/MGF are fixed by its registered name; use the matching "
                + "RSA/ECB/OAEPWithSHA-*AndMGF1Padding name rather than passing OAEPParameterSpec");
        }
        initKey(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported — see the other engineInit overload");
        }
        initKey(opmode, key);
    }

    private void initKey(int opmode, Key key) throws InvalidKeyException {
        // WRAP_MODE/UNWRAP_MODE are ENCRYPT/DECRYPT-shaped at the native
        // layer for RSA-OAEP — the spec says so directly ("C_DecapsulateKey
        // is exactly equivalent to C_UnwrapKey for RSA OAEP", §6.1.8):
        // wrap uses the public key + C_Encrypt, unwrap uses the private
        // key + C_Decrypt, identically to plain encrypt/decrypt. A first
        // version of this method only recognized ENCRYPT_MODE/DECRYPT_MODE
        // and rejected WRAP_MODE/UNWRAP_MODE outright — caught live via
        // the wrap/unwrap test, which JCA's Cipher.init(WRAP_MODE, ...)
        // genuinely uses (not just ENCRYPT_MODE with a different name).
        boolean encryptDirection = (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE);
        boolean decryptDirection = (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE);
        if (encryptDirection) {
            if (!(key instanceof P11Key.Pub p)) {
                throw new InvalidKeyException("OAEP encrypt/wrap needs a public key from " + SoftHSMv3Provider.class.getSimpleName());
            }
            keyHandle = p.handle();
        } else if (decryptDirection) {
            if (!(key instanceof P11Key.Priv p)) {
                throw new InvalidKeyException("OAEP decrypt/unwrap needs a private key from " + SoftHSMv3Provider.class.getSimpleName());
            }
            keyHandle = p.handle();
        } else {
            throw new InvalidKeyException("unsupported Cipher opmode " + opmode
                + " (only ENCRYPT_MODE/DECRYPT_MODE/WRAP_MODE/UNWRAP_MODE)");
        }
        // Normalize to ENCRYPT_MODE/DECRYPT_MODE for engineDoFinal's own
        // direction check, so it doesn't need to know about WRAP/UNWRAP too.
        this.opmode = encryptDirection ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        buf.reset();
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buf.write(input, inputOffset, inputLen);
        return null; // single-block cipher — nothing to emit until engineDoFinal
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        buf.write(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input != null && inputLen > 0) buf.write(input, inputOffset, inputLen);
        byte[] data = buf.toByteArray();
        buf.reset();
        try (java.lang.foreign.Arena op = java.lang.foreign.Arena.ofConfined()) {
            var mech = lib.mechOaep(op, hashAlg, mgf);
            return opmode == Cipher.ENCRYPT_MODE ? lib.encrypt(op, mech, keyHandle, data) : lib.decrypt(op, mech, keyHandle, data);
        } catch (RuntimeException e) {
            if (opmode == Cipher.DECRYPT_MODE) throw new BadPaddingException(e.getMessage());
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws javax.crypto.ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new javax.crypto.ShortBufferException("need " + result.length + " bytes");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (key.getEncoded() == null) {
            throw new InvalidKeyException("cannot wrap a key with no encoded form (opaque keys must stay in-token)");
        }
        try {
            return engineDoFinal(key.getEncoded(), 0, key.getEncoded().length);
        } catch (BadPaddingException e) {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException {
        try {
            byte[] raw = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return new javax.crypto.spec.SecretKeySpec(raw, wrappedKeyAlgorithm);
        } catch (Exception e) {
            throw new InvalidKeyException("unwrap failed", e);
        }
    }
}
