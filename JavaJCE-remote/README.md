# `JavaJCE-remote` — gRPC-remote JCA/JCE provider

`com.pqctoday.hsm.jce.remote.SoftHSMv3RemoteProvider` (JCA name
`SoftHSMv3-Remote`) bridges `javax.crypto`/`java.security` to the
`softhsmrustv3` engine over the network (`remoting/grpc`), not the local
PKCS#11 FFM path [`../JavaJCE/`](../JavaJCE/README.md) uses. Use this
module when the JVM and the engine don't run on the same host; use
`JavaJCE/` when they do — it has broader algorithm coverage and no
network dependency.

See `docs/implementation-plan-jca-remaining-gaps-2026-08-25.md` §7
(WS-E) for the full design record.

## Coverage

Narrower than `JavaJCE/` by real proto contract, not omission — exactly
what `remoting/proto/proto/pkcs11_remote.proto`'s `Algorithm` enum
covers:

- `KeyPairGenerator`/`KeyFactory`: Ed25519, ML-DSA-44/65/87,
  ML-KEM-512/768/1024
- `Signature`: Ed25519, ML-DSA-44/65/87 (pure, single-part)
- `KEM`: ML-KEM-512/768/1024, registered under the bare `"ML-KEM"` name
  too (what JDK's own hybrid-TLS path requests)
- `SoftHSMv3RemoteProvider.getSelfSignedCertificate(KeyPair, String subjectCn, long validityDays)`
  — a real, self-signed X.509 certificate for a signature-capable
  keypair this provider generated. The **only** way to get real bytes
  for a remote public key out of this provider: `RemoteKey.Priv` and
  `RemoteKey.Pub` both report `getEncoded() == null` — a wire-protocol
  capability gap (no verb returns raw public-key bytes), not the local
  provider's deliberate opacity design. `subjectCn` is the bare RDN
  value (e.g. `"my-key"`), not a `"CN=..."`-prefixed string — the server
  builds `CN={subjectCn}` itself.

No SLH-DSA, EC/ECDSA, RSA, or symmetric algorithms — widening this is
an explicit follow-on with its own gate (plan §7 E5), not silent scope
creep.

## mTLS (mandatory)

Construction fails closed if `client.crt`/`client.key`/`ca.crt` aren't
present at `certDir` (default `/admin-certs`, env var
`AGILE_KMIP_CERTS`) — there is no plaintext fallback, matching the
`pqc-grpc` server's own `PKCS11_REMOTE_TLS_PROFILE=quantum-safe`
posture from the other direction.

```java
// env-var defaults: PKCS11_GRPC_HOST=pqc-grpc, PKCS11_GRPC_PORT=5710,
// PKCS11_PIN=1234, AGILE_KMIP_CERTS=/admin-certs
try (SoftHSMv3RemoteProvider provider = new SoftHSMv3RemoteProvider()) {
    Security.addProvider(provider);

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", provider);
    kpg.initialize(new NamedParameterSpec("ML-DSA-65"));
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("ML-DSA-65", provider);
    sig.initSign(kp.getPrivate());
    sig.update(message);
    byte[] signature = sig.sign();

    X509Certificate cert = provider.getSelfSignedCertificate(kp, "my-key", 30);
}
```

## Build

Depends on the core `JavaJCE/` jar (`com.pqctoday:softhsmv3-jce`) as a
normal (repository-resolved) Maven dependency — install it first:

```bash
cd ../JavaJCE && mvn install -DskipTests
cd ../JavaJCE-remote && mvn install
```

No reactor parent aggregates the two modules, deliberately —
`JavaJCE/pom.xml` stays a standalone, independently-buildable project.

The proto is consumed **verbatim** from
`../remoting/proto/proto/pkcs11_remote.proto` (a relative
`protoSourceRoot`, not a copy that can drift from the Rust server's own
schema). `protoc` and `protobuf-java` are pinned to the **same**
version explicitly (`${protobuf.version}`) — `grpc-protobuf`'s own
transitive `protobuf-java` does not automatically match whatever
`protoc` version is pinned via `protocArtifact`, and a mismatch fails
to compile the generated stub with confusing errors (missing
`RuntimeVersion`, wrong `parseUnknownField` arity, etc.) rather than a
clear version-conflict message.

## Test

`RemoteProviderLiveTest` is a live integration suite — it needs a real,
reachable `pqc-grpc` server and real mTLS material at `/admin-certs`
(the `pqc-dev-sandbox` container has both). No mocks: every case is a
genuine network round trip.

```bash
mvn test
```

Or via the repo's gate: `bash scripts/local-gate.sh --javajce-remote`
(separate from `--javajce`, which only covers the local FFM module —
this step additionally requires the `pqc-grpc` stack from
`pqctoday-sandbox`'s `docker-compose.yml` to be up).
