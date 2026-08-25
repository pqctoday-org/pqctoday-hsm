package com.pqctoday.hsm.jce;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AuthProvider login/logout (§6.1). PKCS#11 login state is per-TOKEN, not
 * per-session (spec §5.6.1, already documented in P11Library) — every
 * live SoftHSMv3Provider/P11Library instance in this JVM shares ONE
 * physical SoftHSM token, so a logout() here genuinely deauthenticates
 * every other test's session too, for as long as this test leaves it
 * that way. This is why the whole risky portion below is one method
 * wrapped in a single try/finally that unconditionally logs back in
 * with the correct PIN before returning — leaving the token logged out
 * would break every OTHER test class that runs afterward in the same
 * Surefire JVM, not just this one.
 */
class AuthProviderTest {

    private static final String CORRECT_PIN =
        System.getenv().getOrDefault("PKCS11_PIN", "1234");

    private static CallbackHandler pinHandler(String pin) {
        return callbacks -> {
            for (Callback c : callbacks) {
                if (c instanceof PasswordCallback pc) {
                    pc.setPassword(pin.toCharArray());
                } else {
                    throw new UnsupportedCallbackException(c);
                }
            }
        };
    }

    @Test
    void loginIsANoOpImmediatelyAfterConstruction() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertTrue(p.lib.isLoggedIn(), "construction already logs in eagerly");
        assertDoesNotThrow(() -> p.login(null, null),
            "login() on an already-logged-in provider must be a no-op, not an error");
    }

    @Test
    void logoutAndLoginCycleAffectsRealOperationsAndFailedPinIsDistinguished() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        assertTrue(p.lib.isLoggedIn());

        try {
            // 1. Real logout: a privileged operation (creating a key
            //    object requires the session to be authenticated) must
            //    now fail — proof this is real C_Logout, not a flag.
            p.logout();
            assertFalse(p.lib.isLoggedIn());
            assertThrows(RuntimeException.class,
                () -> javax.crypto.KeyGenerator.getInstance("AES", p).generateKey(),
                "key generation must fail while logged out");

            // 2. Wrong PIN via a real CallbackHandler -> FailedLoginException
            //    specifically, not a generic LoginException.
            p.setCallbackHandler(pinHandler("wrong-pin-0000"));
            assertThrows(FailedLoginException.class, () -> p.login(null, null));
            assertFalse(p.lib.isLoggedIn(), "a failed login attempt must not leave the token authenticated");

            // 3. Correct PIN via the same CallbackHandler mechanism ->
            //    real operations work again.
            p.setCallbackHandler(pinHandler(CORRECT_PIN));
            assertDoesNotThrow(() -> p.login(null, null));
            assertTrue(p.lib.isLoggedIn());
            SecretKey key = javax.crypto.KeyGenerator.getInstance("AES", p).generateKey();
            assertNotNull(key);
        } finally {
            // Restore token-wide login state unconditionally — every
            // other test class in this Surefire JVM depends on it.
            if (!p.lib.isLoggedIn()) {
                p.lib.login(CORRECT_PIN.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            assertTrue(p.lib.isLoggedIn(), "token must be left logged in for every other test");
        }
    }

    @Test
    void loginWithNoCallbackHandlerAfterLogoutThrowsInsteadOfHangingOrCrashing() throws Exception {
        SoftHSMv3Provider p = new SoftHSMv3Provider();
        try {
            p.logout();
            assertThrows(javax.security.auth.login.LoginException.class, () -> p.login(null, null),
                "no CallbackHandler available (none passed, none set via setCallbackHandler) must fail cleanly");
        } finally {
            p.lib.login(CORRECT_PIN.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertTrue(p.lib.isLoggedIn(), "token must be left logged in for every other test");
        }
    }
}
