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
 * ENCRYPT_MODE, this class REJECTS a caller-supplied IV by default — it
 * always generates one itself via lib.generateRandom() (the token's own
 * SP 800-90A DRBG, C_GenerateRandom — the same RNG the engine would use
 * internally either way), retrievable via engineGetIV() before
 * engineDoFinal is even called, matching Cipher's documented contract.
 * On DECRYPT_MODE the caller must supply the IV that was used (received
 * out-of-band, e.g. via getIV() after encryption) through
 * GCMParameterSpec (preferred — carries the tag length too) or
 * IvParameterSpec (tag length then defaults to 128 bits). CBC/CTR carry
 * no such restriction in the plan — standard JCE IvParameterSpec
 * behavior (caller-supplied or provider-generated) applies to both.
 *
 * {@code -Dsofthsmv3.jce.callerGcmIv=true} (default off, NON-FIPS):
 * lifts the ENCRYPT_MODE caller-IV rejection above. Added for plan
 * §WS-B's real, live need: JDK 27's own {@code sun.security.ssl.SSLCipher}
 * (the TLS 1.3 record cipher) calls {@code Cipher.getInstance("AES/GCM/NoPadding")}
 * with no explicit provider — landing on this one once it's installed at
 * top priority — and for every record computes the RFC 8446-mandated
 * deterministic nonce (a fixed IV XOR'd with the monotonic record
 * sequence number) and passes it in explicitly via
 * {@code GCMParameterSpec}. Confirmed from JDK 27's real
 * {@code SSLCipher.java} source (not guessed): this is not caller
 * laziness, it is the TLS 1.3 protocol's own required nonce
 * construction — no module-generated-IV policy can ever satisfy TLS 1.3
 * record encryption, since the peer independently computes the same
 * deterministic nonce and requires the sender to have used exactly it.
 * That construction is itself cryptographically sound by design
 * (monotonic, non-repeating within a connection), which is why this is
 * an explicit opt-in flag rather than a blanket policy change — this
 * provider has no way to verify a given caller's IVs actually follow a
 * safe construction, so the responsibility for that shifts to whoever
 * sets the flag.
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

    enum Mode { GCM, CCM, CBC, CBC_PAD, CTR }

    private final P11Library lib;
    private final Mode mode;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private final ByteArrayOutputStream aad = new ByteArrayOutputStream();

    private int opmode = -1;
    private long keyHandle = -1;
    private byte[] iv;
    private int tagBits = 128; // GCM only — CK_GCM_PARAMS.ulTagBits is in BITS
    // CCM only — CK_CCM_PARAMS.ulMACLen is in BYTES (a different unit than
    // GCM's own ulTagBits, confirmed grepping pkcs11t.h before writing
    // this — not assumed to match). Default 16 (128 bits) matches this
    // class's own GCM default for internal consistency; DISCLOSED
    // cross-library caveat: Bouncy Castle's own AES/CCM defaults to a
    // 64-bit tag under a bare IvParameterSpec (confirmed live via a
    // container probe before writing the interop test), so an interop
    // test must always pass an explicit tag length on both sides rather
    // than rely on this default matching BC's.
    private int ccmTagLenBytes = 16;

    P11AESCipherSpi(P11Library lib, Mode mode) {
        this.lib = lib;
        this.mode = mode;
    }

    // Deliberately NOT a cached `static final boolean` — see
    // P11HKDFKDFSpi#extractableHkdfFallback's javadoc for why a
    // one-time class-load-time read of this property would silently
    // stop honoring later changes (the same reasoning applies here).
    private static boolean callerGcmIvAllowed() {
        return Boolean.getBoolean("softhsmv3.jce.callerGcmIv");
    }

    @Override
    protected void engineSetMode(String modeStr) throws NoSuchAlgorithmException {
        String want = switch (mode) {
            case GCM -> "GCM";
            case CCM -> "CCM";
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
        // GCM's real, EXACT size (not a conservative upper bound) — a
        // genuine bug found live via plan §WS-B's TLS spike: JDK 27's
        // own SSLCipher (the TLS 1.3 record cipher) calls the
        // ByteBuffer-based Cipher.doFinal(ByteBuffer, ByteBuffer)
        // overload, whose CipherSpi default bridging pre-sizes the
        // output buffer from THIS method's return value and then
        // STRICTLY checks the real written length equals it afterward
        // ("Cipher buffering error" otherwise) — a padded/conservative
        // answer that ordinary byte[]-based doFinal() callers never
        // noticed silently breaks the ByteBuffer path outright. GCM's
        // real output is exactly plaintext+tag (encrypt) or
        // ciphertext-tag (decrypt), both fully knowable ahead of time
        // from tagBits alone — no reason to pad.
        if (mode == Mode.GCM) {
            int tagBytes = tagBits / 8;
            return opmode == Cipher.DECRYPT_MODE
                ? Math.max(0, inputLen - tagBytes)
                : inputLen + tagBytes;
        }
        // CCM: same exact-size reasoning as GCM above, just with the tag
        // length already tracked in bytes (ccmTagLenBytes) rather than bits.
        if (mode == Mode.CCM) {
            return opmode == Cipher.DECRYPT_MODE
                ? Math.max(0, inputLen - ccmTagLenBytes)
                : inputLen + ccmTagLenBytes;
        }
        // CBC/CTR (NoPadding): output length equals input length exactly.
        if (mode == Mode.CBC || mode == Mode.CTR) {
            return inputLen;
        }
        // CBC_PAD encrypt: PKCS5 always adds 1..16 bytes, deterministic
        // from inputLen alone. Decrypt: the real (post-unpad) length
        // isn't knowable without decrypting — inputLen itself is a safe
        // upper bound (padding removal only ever shrinks), not exercised
        // by the ByteBuffer-strict-equality path above (TLS 1.3 is
        // GCM-only), so a conservative answer here is fine.
        return opmode == Cipher.ENCRYPT_MODE ? inputLen + (16 - (inputLen % 16)) : inputLen;
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

        if ((mode == Mode.GCM || mode == Mode.CCM) && this.opmode == Cipher.ENCRYPT_MODE
                && callerIv != null && !callerGcmIvAllowed()) {
            throw new InvalidAlgorithmParameterException(
                "AES-" + mode + " encryption IVs must be generated inside this module (SP 800-38D §8.2 / "
                + "the same AEAD-nonce-uniqueness policy applied to CCM's nonce) — "
                + "do not pass an IV via GCMParameterSpec/IvParameterSpec on ENCRYPT_MODE; "
                + "call engineGetIV()/Cipher.getIV() after init() to retrieve the token-generated IV "
                + "(or set -Dsofthsmv3.jce.callerGcmIv=true — see this class's javadoc for when that's appropriate)");
        }
        if (mode == Mode.GCM && callerTagBits != null) {
            this.tagBits = callerTagBits;
        }
        if (mode == Mode.CCM && callerTagBits != null) {
            this.ccmTagLenBytes = callerTagBits / 8;
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
        // CCM: 12-byte nonce, well within RFC 3610/SP 800-38C's valid
        // 7..13-byte range (confirmed reading SoftHSM_cipher.cpp before
        // choosing this) and the same size as GCM's, for consistency.
        // CBC/CTR: full 16-byte block, matching AES's block size.
        this.iv = lib.generateRandom(mode == Mode.GCM || mode == Mode.CCM ? 12 : 16);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (mode != Mode.GCM && mode != Mode.CCM) {
            throw new UnsupportedOperationException("AAD is only meaningful for AES-GCM/AES-CCM");
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
        try (java.lang.foreign.Arena op = java.lang.foreign.Arena.ofConfined()) {
            var mech = switch (mode) {
                case GCM -> lib.mechGcm(op, iv, aad.toByteArray(), tagBits);
                // CK_CCM_PARAMS.ulDataLen is CCM's own upfront total-length
                // declaration — plaintext length on encrypt, or
                // ciphertext-minus-tag length on decrypt (see
                // P11Library#mechCcm's javadoc for why the engine needs
                // this up front, unlike GCM).
                case CCM -> lib.mechCcm(op,
                    opmode == Cipher.ENCRYPT_MODE ? data.length : data.length - ccmTagLenBytes,
                    iv, aad.toByteArray(), ccmTagLenBytes);
                case CBC -> lib.mechCbc(op, CKM_AES_CBC, iv);
                case CBC_PAD -> lib.mechCbc(op, CKM_AES_CBC_PAD, iv);
                case CTR -> lib.mechCtr(op, iv);
            };
            return opmode == Cipher.ENCRYPT_MODE ? lib.encrypt(op, mech, keyHandle, data) : lib.decrypt(op, mech, keyHandle, data);
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
