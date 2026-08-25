package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.security.InvalidParameterException;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Provider.configure(String) (§6.1) — a plain key=value config file, not
 * a port of SunPKCS11's own much larger grammar (see the class javadoc on
 * configure() for why). PKCS11_MODULE/PKCS11_PIN come from the real
 * environment this suite already runs under (same convention every other
 * test file in this module uses for its own SoftHSMv3Provider() calls).
 */
class ConfigureTest {

    private static final String MODULE =
        System.getenv().getOrDefault("PKCS11_MODULE", "/usr/local/lib/softhsm/libsofthsmv3.so");
    private static final String PIN = System.getenv().getOrDefault("PKCS11_PIN", "1234");

    private static File writeConfig(String content) throws Exception {
        File f = File.createTempFile("softhsmv3-jce-test", ".properties");
        try (FileWriter w = new FileWriter(f, java.nio.charset.StandardCharsets.UTF_8)) {
            w.write(content);
        }
        f.deleteOnExit();
        return f;
    }

    @Test
    void configureWithLiteralPinProducesAWorkingProvider() throws Exception {
        File cfg = writeConfig("library = " + MODULE + "\npin = " + PIN + "\n");
        SoftHSMv3Provider base = new SoftHSMv3Provider();
        SoftHSMv3Provider configured = base.configure(cfg.getAbsolutePath());
        assertNotNull(configured);
        byte[] got = MessageDigest.getInstance("SHA-256", configured).digest("abc".getBytes());
        assertEquals(32, got.length);
    }

    @Test
    void configureWithPinEnvProducesAWorkingProvider() throws Exception {
        // Reuse whatever env var already holds the real PIN in this test
        // environment rather than inventing a new one — PKCS11_PIN is
        // already set for the whole suite to work at all.
        File cfg = writeConfig("library = " + MODULE + "\npinEnv = PKCS11_PIN\n");
        SoftHSMv3Provider base = new SoftHSMv3Provider();
        SoftHSMv3Provider configured = base.configure(cfg.getAbsolutePath());
        byte[] got = MessageDigest.getInstance("SHA-256", configured).digest("abc".getBytes());
        assertEquals(32, got.length);
    }

    @Test
    void configureAppliesANameSuffix() throws Exception {
        File cfg = writeConfig("library = " + MODULE + "\npin = " + PIN + "\nname = second-token\n");
        SoftHSMv3Provider base = new SoftHSMv3Provider();
        SoftHSMv3Provider configured = base.configure(cfg.getAbsolutePath());
        assertEquals("SoftHSMv3-second-token", configured.getName());
    }

    @Test
    void configureRejectsAMissingLibraryKey() throws Exception {
        File cfg = writeConfig("pin = " + PIN + "\n");
        SoftHSMv3Provider base = new SoftHSMv3Provider();
        assertThrows(InvalidParameterException.class, () -> base.configure(cfg.getAbsolutePath()));
    }

    @Test
    void configureRejectsMissingBothPinAndPinEnv() throws Exception {
        File cfg = writeConfig("library = " + MODULE + "\n");
        SoftHSMv3Provider base = new SoftHSMv3Provider();
        assertThrows(InvalidParameterException.class, () -> base.configure(cfg.getAbsolutePath()));
    }

    @Test
    void configureRejectsAPinEnvThatIsNotSet() throws Exception {
        File cfg = writeConfig("library = " + MODULE + "\npinEnv = SOFTHSMV3_JCE_TEST_UNSET_VAR_XYZ\n");
        SoftHSMv3Provider base = new SoftHSMv3Provider();
        assertThrows(InvalidParameterException.class, () -> base.configure(cfg.getAbsolutePath()));
    }

    @Test
    void configureRejectsANonexistentFile() {
        SoftHSMv3Provider base = new SoftHSMv3Provider();
        assertThrows(InvalidParameterException.class,
            () -> base.configure("/no/such/path/softhsmv3-jce-does-not-exist.properties"));
    }
}
