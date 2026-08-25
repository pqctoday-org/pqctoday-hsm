package com.pqctoday.hsm.jce;

/**
 * Opt-in, zero-cost-by-default operational logging — plan §W6's own
 * verification requirement ("confirm via provider-side logging that
 * encap/decap ran in the token"), not a throwaway test hack stripped out
 * afterward. Off unless {@code -Dsofthsmv3.jce.debug=true} is set, so
 * normal production/test usage never pays for it or gets its stderr
 * cluttered — exists specifically so a caller (or this plan's own W6
 * TLS spike) can positively confirm this provider's native code path
 * actually ran for a given operation, rather than JSSE/JCA having
 * silently fallen back to a different, higher- or equal-priority
 * provider (a real, previously-observed failure mode — see W0.1's
 * "silent partial-bypass" finding in the plan doc: a provider missing
 * the right method override can degrade to a different provider with no
 * exception and no other visible signal).
 */
final class P11Debug {
    private P11Debug() {}

    private static final boolean ENABLED = Boolean.getBoolean("softhsmv3.jce.debug");

    static void log(String message) {
        if (ENABLED) {
            System.err.println("[softhsmv3-jce] " + message);
        }
    }
}
