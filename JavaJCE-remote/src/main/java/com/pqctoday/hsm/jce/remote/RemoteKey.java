package com.pqctoday.hsm.jce.remote;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Opaque handle-backed key objects for the gRPC remote surface — the
 * remote counterpart to {@code ../../JavaJCE/}'s own {@code P11Key}.
 * Only the server-side {@code uint32} object handle is held; every
 * crypto operation routes back through {@link GrpcTransport} via that
 * handle.
 *
 * <p><b>Both {@code Priv} AND {@code Pub} report {@code getEncoded() ==
 * null}</b> — a real, disclosed difference from the local provider's own
 * {@code P11Key.Pub} (which exports real SPKI bytes via
 * {@code CKA_PUBLIC_KEY_INFO}). This is not a security-opacity design
 * choice here; it's a wire-protocol capability gap (plan
 * {@code docs/implementation-plan-jca-remaining-gaps-2026-08-25.md} §7
 * E1's own second correction, found live): none of this remote surface's
 * verbs return a public key's raw bytes at all.
 * {@link SoftHSMv3RemoteProvider#getSelfSignedCertificate} is the one way
 * to get real key bytes out of this provider — wrapped in a full,
 * genuinely-signed X.509 certificate, not as a bare {@code getEncoded()}
 * call on either key object.
 *
 * <p>Neither class implements {@link javax.security.auth.Destroyable} —
 * unlike the local provider's own key types, which back it with a real
 * {@code C_DestroyObject} call. This remote surface has no destroy verb
 * at all (the 8-verb proto is
 * {@code Health/OpenSession/CloseSession/GenerateKeyPair/Sign/Verify/
 * Encapsulate/Decapsulate/GetSelfSignedCertificate} — confirmed by
 * re-reading the proto's own {@code service} block, no ninth verb
 * exists), so implementing {@code Destroyable} here would claim a
 * capability this provider cannot actually deliver — a real, disclosed
 * gap rather than a silent no-op {@code destroy()}.
 */
final class RemoteKey {
    private RemoteKey() {}

    static final class Priv implements PrivateKey {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient long handle;
        private final String algorithm;

        Priv(long handle, String algorithm) {
            this.handle = handle;
            this.algorithm = algorithm;
        }

        long handle() { return handle; }
        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }
    }

    static final class Pub implements PublicKey {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient long handle;
        private final String algorithm;

        Pub(long handle, String algorithm) {
            this.handle = handle;
            this.algorithm = algorithm;
        }

        long handle() { return handle; }
        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }
    }
}
