package com.pqctoday.hsm.jce.remote;

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteGrpc;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.Algorithm;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.CloseSessionRequest;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.DecapsulateRequest;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.DecapsulateResponse;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.EncapsulateRequest;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.EncapsulateResponse;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.GenerateKeyPairRequest;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.GenerateKeyPairResponse;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.GetSelfSignedCertificateRequest;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.GetSelfSignedCertificateResponse;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.OpenSessionRequest;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.OpenSessionResponse;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.SignRequest;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.SignResponse;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.VerifyRequest;
import pqctoday.pkcs11remote.v1.Pkcs11RemoteOuterClass.VerifyResponse;

import java.io.File;
import java.security.ProviderException;
import java.util.concurrent.TimeUnit;

/**
 * Thin gRPC client for the {@code Pkcs11Remote} service
 * ({@code remoting/grpc}, backed by the Rust {@code softhsmrustv3}
 * engine) — the network counterpart to {@code ../../JavaJCE/}'s FFM
 * {@code P11Library}. One instance owns one server-side session, opened
 * eagerly at construction and closed at {@link #close()} — the exact
 * same lifecycle shape {@code P11Library} already uses for the local
 * PKCS#11 session, deliberately kept consistent rather than inventing a
 * different model for this transport (plan
 * {@code docs/implementation-plan-jca-remaining-gaps-2026-08-25.md} §7,
 * WS-E, E1).
 *
 * <p>mTLS is mandatory, not optional (E3): a real client cert/key/CA
 * bundle at {@code certDir} is required to construct this class at all —
 * no plaintext fallback exists. This matches the actual running
 * {@code pqc-grpc} server's own configuration (confirmed live, E0:
 * {@code PKCS11_REMOTE_TLS_PROFILE=quantum-safe}, which itself refuses
 * to start without {@code --tls-client-ca}) and the same
 * {@code /admin-certs} volume every other admin-facing client in this
 * whole engagement already uses.
 *
 * <p>Every RPC is unary and blocking ({@link Pkcs11RemoteGrpc.Pkcs11RemoteBlockingStub}) —
 * the proto's own phase-1 scope (see its header comment), and a natural
 * fit for the synchronous {@code Signature}/{@code KeyPairGenerator}/
 * {@code KEMSpi} JCA contracts this class backs.
 */
final class GrpcTransport implements AutoCloseable {

    private final ManagedChannel channel;
    private final Pkcs11RemoteGrpc.Pkcs11RemoteBlockingStub stub;
    // uint32 on the wire (proto: OpenSessionResponse.session_handle) — kept
    // as int, not long, so it round-trips straight back into every
    // .setSessionHandle(int) call below without a narrowing cast.
    private final int sessionHandle;
    private volatile boolean closed;

    GrpcTransport(String host, int port, String pin, String certDir) {
        File clientCert = new File(certDir, "client.crt");
        File clientKey = new File(certDir, "client.key");
        File caCert = new File(certDir, "ca.crt");
        // Fail-closed (E3) — no plaintext/no-mTLS fallback, matching this
        // whole repo's own KMIP/gRPC server-side convention (§3.3.4) from
        // the other direction.
        if (!clientCert.isFile() || !clientKey.isFile() || !caCert.isFile()) {
            throw new ProviderException(
                "SoftHSMv3RemoteProvider requires real mTLS identity material at " + certDir
                + " (client.crt/client.key/ca.crt) — refusing to start without it (plan §7 E3, "
                + "no plaintext fallback)");
        }

        SslContext sslContext;
        try {
            sslContext = GrpcSslContexts.forClient()
                .keyManager(clientCert, clientKey)
                .trustManager(caCert)
                .build();
        } catch (Exception e) {
            throw new ProviderException("failed to build mTLS context from " + certDir, e);
        }

        this.channel = NettyChannelBuilder.forAddress(host, port)
            .sslContext(sslContext)
            .build();
        this.stub = Pkcs11RemoteGrpc.newBlockingStub(channel);

        try {
            OpenSessionResponse resp =
                stub.openSession(OpenSessionRequest.newBuilder().setUserPin(pin).build());
            this.sessionHandle = resp.getSessionHandle();
        } catch (StatusRuntimeException e) {
            channel.shutdownNow();
            throw RemoteError.wrap(e);
        } catch (RuntimeException e) {
            channel.shutdownNow();
            throw e;
        }
    }

    /** {@code (publicHandle, privateHandle)}. */
    long[] generateKeyPair(Algorithm algorithm, byte[] ckaId, String label) {
        try {
            GenerateKeyPairResponse resp = stub.generateKeyPair(GenerateKeyPairRequest.newBuilder()
                .setSessionHandle(sessionHandle)
                .setAlgorithm(algorithm)
                .setCkaId(com.google.protobuf.ByteString.copyFrom(ckaId))
                .setLabel(label)
                .build());
            return new long[]{ resp.getPublicHandle(), resp.getPrivateHandle() };
        } catch (StatusRuntimeException e) {
            throw RemoteError.wrap(e);
        }
    }

    byte[] sign(long privateHandle, Algorithm algorithm, byte[] data) {
        try {
            SignResponse resp = stub.sign(SignRequest.newBuilder()
                .setSessionHandle(sessionHandle)
                .setPrivateHandle((int) privateHandle)
                .setAlgorithm(algorithm)
                .setData(com.google.protobuf.ByteString.copyFrom(data))
                .build());
            return resp.getSignature().toByteArray();
        } catch (StatusRuntimeException e) {
            throw RemoteError.wrap(e);
        }
    }

    boolean verify(long publicHandle, Algorithm algorithm, byte[] data, byte[] signature) {
        try {
            VerifyResponse resp = stub.verify(VerifyRequest.newBuilder()
                .setSessionHandle(sessionHandle)
                .setPublicHandle((int) publicHandle)
                .setAlgorithm(algorithm)
                .setData(com.google.protobuf.ByteString.copyFrom(data))
                .setSignature(com.google.protobuf.ByteString.copyFrom(signature))
                .build());
            return resp.getValid();
        } catch (StatusRuntimeException e) {
            throw RemoteError.wrap(e);
        }
    }

    /** {@code (ciphertext, sharedSecret)}. */
    record Encapsulated(byte[] ciphertext, byte[] sharedSecret) {}

    Encapsulated encapsulate(long publicHandle, Algorithm algorithm) {
        try {
            EncapsulateResponse resp = stub.encapsulate(EncapsulateRequest.newBuilder()
                .setSessionHandle(sessionHandle)
                .setPublicHandle((int) publicHandle)
                .setAlgorithm(algorithm)
                .build());
            return new Encapsulated(resp.getCiphertext().toByteArray(), resp.getSharedSecret().toByteArray());
        } catch (StatusRuntimeException e) {
            throw RemoteError.wrap(e);
        }
    }

    byte[] decapsulate(long privateHandle, Algorithm algorithm, byte[] ciphertext) {
        try {
            DecapsulateResponse resp = stub.decapsulate(DecapsulateRequest.newBuilder()
                .setSessionHandle(sessionHandle)
                .setPrivateHandle((int) privateHandle)
                .setAlgorithm(algorithm)
                .setCiphertext(com.google.protobuf.ByteString.copyFrom(ciphertext))
                .build());
            return resp.getSharedSecret().toByteArray();
        } catch (StatusRuntimeException e) {
            throw RemoteError.wrap(e);
        }
    }

    /**
     * The 8th verb (plan §7, added mid-workstream — see
     * {@code remoting/core/src/cert.rs}'s own doc for the full design):
     * a real, self-signed (issuer == subject) X.509 certificate, DER
     * encoded, for a signature-capable keypair already generated on this
     * session. This is the ONLY way any bytes for a remote public key
     * ever leave the server at all — {@code generateKeyPair} itself
     * returns only opaque handles.
     */
    byte[] getSelfSignedCertificate(long publicHandle, long privateHandle, Algorithm algorithm,
            String subjectCn, long validityDays) {
        try {
            GetSelfSignedCertificateResponse resp =
                stub.getSelfSignedCertificate(GetSelfSignedCertificateRequest.newBuilder()
                    .setSessionHandle(sessionHandle)
                    .setPublicHandle((int) publicHandle)
                    .setPrivateHandle((int) privateHandle)
                    .setAlgorithm(algorithm)
                    .setSubjectCn(subjectCn)
                    .setValidityDays(validityDays)
                    .build());
            return resp.getCertificateDer().toByteArray();
        } catch (StatusRuntimeException e) {
            throw RemoteError.wrap(e);
        }
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        try {
            stub.closeSession(CloseSessionRequest.newBuilder().setSessionHandle(sessionHandle).build());
        } catch (RuntimeException ignored) {
            // best-effort teardown, matching P11Library.close()'s own convention
        } finally {
            channel.shutdown();
            try {
                channel.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                channel.shutdownNow();
            }
        }
    }
}
