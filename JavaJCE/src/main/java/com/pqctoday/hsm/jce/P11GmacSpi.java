package com.pqctoday.hsm.jce;

import javax.crypto.MacSpi;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * "AES-GMAC" (item 3) — GMAC-as-a-MAC (CKM_AES_GMAC, PKCS#11 v3.2 §6.13.6),
 * a real, distinct engine mechanism from the CKM_AES_GCM AEAD cipher
 * (P11AESCipherSpi) even though it reuses the identical CK_GCM_PARAMS
 * mechanism-parameter shape for its IV — confirmed reading
 * SoftHSM_sign.cpp's applyGmacParams (added WS-8, 2026-08-30) before
 * writing this class.
 *
 * Doesn't fit P11MacSpi's shape: every other Mac in this module needs no
 * per-call parameters at all, while GMAC genuinely needs a caller-supplied
 * IV every time. So this gets its own small SPI — same buffer-then-sign
 * shape as P11MacSpi, plus the IV/tag-length handling convention
 * P11AESCipherSpi's own GCM Cipher path already established
 * (GCMParameterSpec preferred — carries the tag length; IvParameterSpec
 * defaults the tag to 128 bits, the same default Bouncy Castle's own
 * "AES-GMAC" Mac uses under a bare IvParameterSpec — confirmed live via a
 * container probe before choosing this default, not assumed).
 *
 * Unlike P11AESCipherSpi's AEAD-cipher GCM path, this Mac has NO
 * module-generated-IV policy: GMAC is a MAC (integrity only), not an
 * AEAD confidentiality mode, and PKCS#11 v3.2 places no equivalent
 * restriction on it — a caller-supplied IV is always accepted here,
 * matching how a MAC's nonce is ordinarily just caller-managed protocol
 * state.
 *
 * Registered under "AES-GMAC" (SoftHSMv3Provider#registerServices) —
 * the exact same algorithm name Bouncy Castle's own AES$AESGMAC service
 * uses (confirmed live via Security.getServices() before choosing this
 * name, not guessed), so a cross-verification test against BC can use the
 * identical getInstance() string on both providers.
 */
final class P11GmacSpi extends MacSpi {
    private final P11Library lib;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    private long keyHandle = -1;
    private byte[] iv;
    private int tagLenBytes = 16; // 128 bits — see class javadoc

    P11GmacSpi(P11Library lib) {
        this.lib = lib;
    }

    @Override protected int engineGetMacLength() { return tagLenBytes; }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] callerIv;
        Integer callerTagBits = null;
        if (params instanceof GCMParameterSpec g) {
            callerIv = g.getIV();
            callerTagBits = g.getTLen();
        } else if (params instanceof IvParameterSpec p) {
            callerIv = p.getIV();
        } else {
            throw new InvalidAlgorithmParameterException(
                "AES-GMAC requires a GCMParameterSpec or IvParameterSpec (the IV) — got "
                + (params == null ? "null" : params.getClass()));
        }
        if (callerIv == null || callerIv.length == 0) {
            throw new InvalidAlgorithmParameterException("AES-GMAC requires a non-empty IV");
        }
        if (!(key instanceof P11Key.Secret s) || !"AES".equals(s.getAlgorithm())) {
            throw new InvalidKeyException("AES-GMAC needs an AES SecretKey from " + SoftHSMv3Provider.class.getSimpleName());
        }
        this.iv = callerIv.clone();
        this.tagLenBytes = callerTagBits != null ? callerTagBits / 8 : 16;
        this.keyHandle = s.handle();
        buf.reset();
    }

    @Override protected void engineUpdate(byte input) { buf.write(input); }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        buf.write(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        if (keyHandle < 0) {
            throw new IllegalStateException("engineInit was not called");
        }
        try (var op = java.lang.foreign.Arena.ofConfined()) {
            var mech = lib.mechGmac(op, iv, tagLenBytes * 8);
            byte[] result = lib.sign(op, mech, keyHandle, buf.toByteArray());
            buf.reset();
            return result;
        }
    }

    @Override protected void engineReset() { buf.reset(); }
}
