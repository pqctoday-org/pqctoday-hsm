package com.pqctoday.hsm.jce;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * AES Cipher — one instance per registered mode (GCM/CBC/CBC+PKCS5/CTR),
 * same per-name-registration shape as P11RSAOAEPCipherSpi. Single-shot
 * (buffer-until-engineDoFinal), same documented simplification as OAEP —
 * this is an HSM bridge, not a bulk-throughput streaming cipher; true
 * multi-part C_EncryptUpdate/C_DecryptUpdate chunking is a possible
 * future enhancement, not attempted here.
 *
 * GCM IV policy (plan §4.3, L3-relevant, SP 800-38D §8.2): on
 * ENCRYPT_MODE, this class REJECTS a caller-supplied IV — it always
 * generates one itself via lib.generateRandom() (the token's own SP
 * 800-90A DRBG, C_GenerateRandom — the same RNG the engine would use
 * internally either way), retrievable via engineGetIV() before
 * engineDoFinal is even called, matching Cipher's documented contract.
 * On DECRYPT_MODE the caller must supply the IV that was used (received
 * out-of-band, e.g. via getIV() after encryption) through
 * GCMParameterSpec (preferred — carries the tag length too) or
 * IvParameterSpec (tag length then defaults to 128 bits). CBC/CTR carry
 * no such restriction in the plan — standard JCE IvParameterSpec
 * behavior (caller-supplied or provider-generated) applies to both.
 *
 * Mechanism choice: uses the traditional C_EncryptInit/C_Encrypt path
 * (CK_GCM_PARAMS) rather than the newer message-based
 * C_MessageEncryptInit/C_EncryptMessage family (CK_GCM_MESSAGE_PARAMS).
 * Both are spec-legal ways to satisfy the in-module-IV-generation policy
 * above (confirmed by reading both code paths in SoftHSM_cipher.cpp
 * before choosing) — the traditional path was chosen because (a) it
 * needs no new native function family beyond what W3 already bound, and
 * (b) it was confirmed live in the engine's own decrypt path
 * (`aeadBuf = pCipher || pTag`) to already produce/expect
 * ciphertext-with-appended-tag, which is exactly JCE's own
 * Cipher.doFinal() GCM convention — zero extra reassembly needed.
 */
final class P11AESCipherSpi extends CipherSpi {

    enum Mode { GCM, CBC, CBC_PAD, CTR }

    private final P11Library lib;
    private final Mode mode;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private final ByteArrayOutputStream aad = new ByteArrayOutputStream();

    private int opmode = -1;
    private long keyHandle = -1;
    private byte[] iv;
    private int tagBits = 128;

    P11AESCipherSpi(P11Library lib, Mode mode) {
        this.lib = lib;
        this.mode = mode;
    }

    @Override
    protected void engineSetMode(String modeStr) throws NoSuchAlgorithmException {
        String want = switch (mode) {
            case GCM -> "GCM";
            case CBC, CBC_PAD -> "CBC";
            case CTR -> "CTR";
        };
        if (!want.equalsIgnoreCase(modeStr)) {
            throw new NoSuchAlgorithmException("this Cipher instance is registered for " + want + ", not " + modeStr);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        boolean wantsPad = mode == Mode.CBC_PAD;
        boolean isPad = padding.toUpperCase().contains("PKCS5") || padding.toUpperCase().contains("PKCS7");
        boolean isNone = padding.equalsIgnoreCase("NoPadding");
        if ((wantsPad && !isPad) || (!wantsPad && !isNone)) {
            throw new NoSuchPaddingException(
                "this Cipher instance is registered for " + (wantsPad ? "PKCS5Padding" : "NoPadding")
                + ", not " + padding);
        }
    }

    @Override protected int engineGetBlockSize() { return 16; }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // Conservative upper bound (GCM tag, CBC pad block) — exact size
        // depends on native results only known at engineDoFinal time.
        return inputLen + 32;
    }

    @Override protected byte[] engineGetIV() { return iv == null ? null : iv.clone(); }
    @Override protected AlgorithmParameters engineGetParameters() { return null; }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        initKey(opmode, key);
        if (opmode == Cipher.ENCRYPT_MODE) {
            generateIv();
        } else {
            throw new InvalidKeyException(
                "decryption requires the IV the data was encrypted with — "
                + "use init(DECRYPT_MODE, key, GCMParameterSpec/IvParameterSpec)");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        initKey(opmode, key);
        byte[] callerIv;
        Integer callerTagBits = null;
        if (params instanceof GCMParameterSpec g) {
            callerIv = g.getIV();
            callerTagBits = g.getTLen();
        } else if (params instanceof IvParameterSpec p) {
            callerIv = p.getIV();
        } else if (params == null) {
            callerIv = null;
        } else {
            throw new InvalidAlgorithmParameterException(
                "unsupported AlgorithmParameterSpec " + params.getClass() + " — use GCMParameterSpec or IvParameterSpec");
        }

        if (mode == Mode.GCM && this.opmode == Cipher.ENCRYPT_MODE && callerIv != null) {
            throw new InvalidAlgorithmParameterException(
                "AES-GCM encryption IVs must be generated inside this module (SP 800-38D §8.2) — "
                + "do not pass an IV via GCMParameterSpec/IvParameterSpec on ENCRYPT_MODE; "
                + "call engineGetIV()/Cipher.getIV() after init() to retrieve the token-generated IV");
        }
        if (mode == Mode.GCM && callerTagBits != null) {
            this.tagBits = callerTagBits;
        }
        if (callerIv != null) {
            this.iv = callerIv.clone();
        } else if (this.opmode == Cipher.ENCRYPT_MODE) {
            generateIv();
        } else {
            throw new InvalidAlgorithmParameterException(
                "decryption requires the IV the data was encrypted with, via GCMParameterSpec or IvParameterSpec");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
            "AlgorithmParameters not supported — pass GCMParameterSpec/IvParameterSpec directly");
    }

    private void initKey(int opmode, Key key) throws InvalidKeyException {
        if (!(key instanceof P11Key.Secret s) || !"AES".equals(s.getAlgorithm())) {
            throw new InvalidKeyException("AES Cipher needs an AES SecretKey from " + SoftHSMv3Provider.class.getSimpleName());
        }
        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new InvalidKeyException("unsupported Cipher opmode " + opmode + " (only ENCRYPT_MODE/DECRYPT_MODE)");
        }
        this.opmode = opmode;
        this.keyHandle = s.handle();
        this.iv = null;
        this.tagBits = 128;
        buf.reset();
        aad.reset();
    }

    private void generateIv() {
        // GCM: 96-bit IV, the SP 800-38D-recommended/universal size.
        // CBC/CTR: full 16-byte block, matching AES's block size.
        this.iv = lib.generateRandom(mode == Mode.GCM ? 12 : 16);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (mode != Mode.GCM) {
            throw new UnsupportedOperationException("AAD is only meaningful for AES-GCM");
        }
        aad.write(src, offset, len);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buf.write(input, inputOffset, inputLen);
        return null; // single-shot — nothing to emit until engineDoFinal
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
        if (iv == null) {
            throw new IllegalStateException("Cipher not initialized with an IV");
        }
        try {
            var mech = switch (mode) {
                case GCM -> lib.mechGcm(iv, aad.toByteArray(), tagBits);
                case CBC -> lib.mechCbc(CKM_AES_CBC, iv);
                case CBC_PAD -> lib.mechCbc(CKM_AES_CBC_PAD, iv);
                case CTR -> lib.mechCtr(iv);
            };
            return opmode == Cipher.ENCRYPT_MODE ? lib.encrypt(mech, keyHandle, data) : lib.decrypt(mech, keyHandle, data);
        } catch (RuntimeException e) {
            if (opmode == Cipher.DECRYPT_MODE) throw new BadPaddingException(e.getMessage());
            throw new IllegalBlockSizeException(e.getMessage());
        } finally {
            aad.reset();
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
}
