package com.pqctoday.hsm.jce;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * AESWrap / AESWrapPad (SP 800-38F) — CKM_AES_KEY_WRAP /
 * CKM_AES_KEY_WRAP_PAD, via the engine's native C_WrapKey/C_UnwrapKey
 * rather than C_EncryptInit/C_Encrypt. This is a genuinely different
 * shape than P11RSAOAEPCipherSpi's WRAP_MODE/UNWRAP_MODE handling: OAEP
 * wraps arbitrary bytes (key.getEncoded()) through an encrypt operation,
 * but PKCS#11's C_WrapKey/C_UnwrapKey operate on a KEY OBJECT HANDLE, not
 * bytes — confirmed by reading SoftHSM_keygen.cpp before writing this
 * class: CKM_AES_KEY_WRAP has no C_EncryptInit/C_Encrypt handling in
 * SoftHSM_cipher.cpp at all, only C_WrapKey/C_UnwrapKey in
 * SoftHSM_keygen.cpp, and both require the wrapping key AND the
 * to-be-wrapped key to already be CKO_SECRET_KEY/CKK_AES token objects.
 *
 * A key being wrapped may be one of this provider's own opaque
 * P11Key.Secret/Priv objects (wrapped directly by handle — fully
 * in-token, no key material ever touches the JVM) or a foreign key with
 * a real encoding (e.g. a plain SecretKeySpec built from raw bytes) —
 * the latter is imported as a temporary (CKA_TOKEN=false) session object
 * first, the same on-the-fly-import pattern already proven for foreign
 * EC public keys in P11ECDHKeyAgreementSpi.
 *
 * Only SECRET_KEY unwrap targets are supported (the standard AES-KW use
 * case); PRIVATE_KEY/PUBLIC_KEY unwrap is not attempted — no live-verified
 * need for it in this scope, and guessing at the PKCS#11 template for an
 * arbitrary asymmetric key type without testing it would be exactly the
 * kind of unverified claim this module's discipline avoids.
 */
final class P11AESWrapCipherSpi extends CipherSpi {
    private final P11Library lib;
    private final long mechType;

    private int opmode = -1;
    private long keyHandle = -1;

    P11AESWrapCipherSpi(P11Library lib, long mechType) {
        this.lib = lib;
        this.mechType = mechType;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"ECB".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("only ECB (single-block) is supported for AES key wrap");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException("only NoPadding is supported (this Cipher's own padding is fixed by its registered name)");
        }
    }

    @Override protected int engineGetBlockSize() { return 8; }
    @Override protected int engineGetOutputSize(int inputLen) { return inputLen + 16; }
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
            throw new InvalidAlgorithmParameterException("AES key wrap takes no parameters");
        }
        initKey(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("AES key wrap takes no parameters");
        }
        initKey(opmode, key);
    }

    private void initKey(int opmode, Key key) throws InvalidKeyException {
        if (!(key instanceof P11Key.Secret s) || !"AES".equals(s.getAlgorithm())) {
            throw new InvalidKeyException("AES key wrap needs an AES SecretKey from " + SoftHSMv3Provider.class.getSimpleName());
        }
        if (opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE) {
            throw new InvalidKeyException("this Cipher only supports WRAP_MODE/UNWRAP_MODE, not opmode " + opmode);
        }
        this.opmode = opmode;
        this.keyHandle = s.handle();
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new UnsupportedOperationException("AES key wrap only supports wrap()/unwrap(), not update()/doFinal()");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        throw new UnsupportedOperationException("AES key wrap only supports wrap()/unwrap(), not update()/doFinal()");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        throw new UnsupportedOperationException("AES key wrap only supports wrap()/unwrap(), not update()/doFinal()");
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        throw new UnsupportedOperationException("AES key wrap only supports wrap()/unwrap(), not update()/doFinal()");
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (opmode != Cipher.WRAP_MODE) {
            throw new IllegalStateException("Cipher not initialized for WRAP_MODE");
        }
        long targetHandle = handleOf(key, true);
        try {
            return lib.wrapKey(mechType, keyHandle, targetHandle);
        } catch (RuntimeException e) {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException {
        if (opmode != Cipher.UNWRAP_MODE) {
            throw new InvalidKeyException("Cipher not initialized for UNWRAP_MODE");
        }
        if (wrappedKeyType != Cipher.SECRET_KEY) {
            throw new InvalidKeyException(
                "this Cipher only supports unwrapping SECRET_KEY targets, not type " + wrappedKeyType);
        }
        long keyType = "AES".equalsIgnoreCase(wrappedKeyAlgorithm) ? CKK_AES : CKK_GENERIC_SECRET;
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, keyType),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_ENCRYPT, true),
            P11Library.attrBool(CKA_DECRYPT, true),
        };
        try {
            long handle = lib.unwrapKey(mechType, keyHandle, wrappedKey, tmpl);
            return new P11Key.Secret(handle, wrappedKeyAlgorithm);
        } catch (RuntimeException e) {
            throw new InvalidKeyException("unwrap failed", e);
        }
    }

    /**
     * Resolves the handle of the key to be wrapped: directly for our own
     * opaque keys, or by importing a foreign key's raw encoding as a
     * temporary extractable session object first (C_WrapKey requires
     * CKA_EXTRACTABLE=TRUE on the target regardless of origin).
     */
    private long handleOf(Key key, boolean mustBeExtractable) throws InvalidKeyException {
        if (key instanceof P11Key.Secret s) return s.handle();
        if (key instanceof P11Key.Priv p) return p.handle();
        byte[] raw = key.getEncoded();
        if (raw == null) {
            throw new InvalidKeyException("cannot wrap a key with no encoded form and no token handle");
        }
        long keyType = "AES".equalsIgnoreCase(key.getAlgorithm()) ? CKK_AES : CKK_GENERIC_SECRET;
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, keyType),
            P11Library.attr(CKA_VALUE, raw),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_EXTRACTABLE, mustBeExtractable),
        };
        return lib.createObject(tmpl);
    }
}
