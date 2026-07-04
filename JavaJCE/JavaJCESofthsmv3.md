# SoftHSMv3 Java Cryptography Extension (JCE) Translation Layer

## Overview
Java applications like Hyperledger Besu utilize the abstract Java Cryptography Architecture (JCA) for all digital operations. When they execute `Signature.getInstance("ML-DSA-65")`, the JVM must locate a registered JCE Security Provider that understands how to physically generate that signature.

While we successfully patched the JVM core (`SunPKCS11` JNI) to not reject the `0x0000001D` PKCS11 v3.2 constants returned from the hardware, standard Java classes lack the frontend translation logic to convert the String `"ML-DSA-65"` into `CKM_ML_DSA` integer representations autonomously.

To resolve this, we have constructed this `JavaJCE` native plugin matrix.

## The Strategy

This module acts as a lightweight interceptor wrapper residing physically adjacent to `strongswan-pkcs11`.
1.  **Register the Provider**: A custom `SoftHSMJCEProvider` is loaded dynamically alongside `SunPKCS11`.
2.  **Intercept the JCA Request**: When Besu requests `ML-DSA-65`, our Provider catches it.
3.  **Translate to Hardware**: Our `SignatureSpi` implementation translates the abstract parameters into `java.security.spec.ECParameterSpec` or native structures mathematically identical to standard calls, retrieves the `SoftHSMv3` slot handler, and requests a `C_SignInit` passing the injected `0x0000001DL` macro natively available in the bespoke JRE.

## Directory Structure

```text
JavaJCE/
├── JavaJCESofthsmv3.md                              (This Architecture Document)
├── src/main/java/org/softhsmv3/jce/
│   ├── SoftHSMJCEProvider.java   (JCA Provider "SoftHSMv3-PQC" — service registry)
│   ├── MLDSASignatureSpi.java    (SignatureSpi: ML-DSA-44/65/87, SLH-DSA)
│   ├── MLKEMKeyAgreementSpi.java (KeyAgreementSpi: ML-KEM-512/768/1024)
│   └── ClassicalSignatureSpi.java (SignatureSpi: SHA256withRSA etc.)
└── src/test/java/org/softhsmv3/jce/
    └── PKCS11IntegrationTest.java (has a `main()` — runs the SPIs vs a token)
```

There is **no** `build.gradle`; the package is `org.softhsmv3.jce` (not
`com.pqctoday.jce`). Registered services (see `SoftHSMJCEProvider`):
`Signature.ML-DSA-{44,65,87}`, `KeyAgreement.ML-KEM-{512,768,1024}`,
`Signature.SLH-DSA-*`, and classical `Signature.SHA256withRSA`.

## Building and testing

Compiled with `javac` inside the patched-JRE Docker container (no standalone
build system in-tree). To build and run the integration test against a
softhsmv3 token:

```bash
# inside the patched-JRE container, from JavaJCE/
javac -d out $(find src/main/java -name '*.java')
javac -d out -cp out $(find src/test/java -name '*.java')

# PKCS11IntegrationTest.main() registers SoftHSMJCEProvider and drives the SPIs
java -cp out org.softhsmv3.jce.PKCS11IntegrationTest
```

## Integration with Docker Context

Because the patched JVM environment uniquely holding the `CKM_ML_DSA` capabilities only exists inside the `playground-physics` container generated from `Dockerfile.physics`, this library must also be compiled *inside* that container.

In the Docker infrastructure, the compilation sequences will physically pull this `/JavaJCE` directory internally, compile it using the freshly patched `javac` environment, bundle it into a `/opt/besu/lib/javajce-softhsm.jar` injection file, and mount it to the Java Classpath!
