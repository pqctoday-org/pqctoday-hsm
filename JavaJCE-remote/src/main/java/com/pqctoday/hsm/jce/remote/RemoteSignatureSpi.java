package com.pqctoday.hsm.jce.remote;

import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.Algorithm;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Generic {@code SignatureSpi} for the remote surface's signature-capable
 * algorithms (Ed25519, ML-DSA-44/65/87) — single-part, no digest, the
 * same "pure" shape as the local {@code ../../JavaJCE/}'s own
 * {@code P11PureSigSignatureSpi} (one instance per registered service
 * name, buffer the whole message, sign/verify in one shot at the end —
 * matches this proto's own unary-RPC-only phase-1 scope, so there is no
 * multi-part streaming shape to build here either).
 */
final class RemoteSignatureSpi extends SignatureSpi {
    private final GrpcTransport transport;
    private final Algorithm protoAlgorithm;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private long signKey = -1;
    private long verifyKey = -1;

    RemoteSignatureSpi(GrpcTransport transport, Algorithm protoAlgorithm) {
        this.transport = transport;
        this.protoAlgorithm = protoAlgorithm;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof RemoteKey.Priv p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3RemoteProvider.class.getSimpleName());
        }
        signKey = p.handle();
        verifyKey = -1;
        buf.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof RemoteKey.Pub p)) {
            throw new InvalidKeyException("not a key from " + SoftHSMv3RemoteProvider.class.getSimpleName());
        }
        verifyKey = p.handle();
        signKey = -1;
        buf.reset();
    }

    @Override protected void engineUpdate(byte b) { buf.write(b); }
    @Override protected void engineUpdate(byte[] b, int off, int len) { buf.write(b, off, len); }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signKey < 0) throw new SignatureException("engineInitSign was not called");
        try {
            byte[] sig = transport.sign(signKey, protoAlgorithm, buf.toByteArray());
            buf.reset();
            return sig;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (verifyKey < 0) throw new SignatureException("engineInitVerify was not called");
        try {
            boolean ok = transport.verify(verifyKey, protoAlgorithm, buf.toByteArray(), sigBytes);
            buf.reset();
            return ok;
        } catch (RuntimeException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("use engineSetParameter(AlgorithmParameterSpec)");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("use engineGetParameters()");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("this signature mechanism takes no parameters");
        }
    }
}
