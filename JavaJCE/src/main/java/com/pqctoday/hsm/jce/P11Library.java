package com.pqctoday.hsm.jce;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.security.ProviderException;

import static java.lang.foreign.ValueLayout.*;

/**
 * FFM bridge to the softhsmv3 PKCS#11 v3.2 C ABI (java.lang.foreign, no
 * JDK-internal APIs — this is the deliberate replacement for the removed
 * JavaJCE/ placeholder, which reflected into sun.security.pkcs11.wrapper).
 *
 * Generalizes the pattern already proven live, repeatedly, in
 * pqctoday-sandbox's samples/java/.../P11Ffm.java: every PKCS#11 function
 * is resolved by symbol name via dlsym (Linker.downcallHandle +
 * SymbolLookup.find), not by walking the CK_FUNCTION_LIST_3_2 struct that
 * C_GetInterface returns. P11Ffm's own header comment explains why: the
 * v3.2 entry points (C_EncapsulateKey/C_DecapsulateKey) must be resolved
 * this way because C_GetFunctionList returns a v2-sized struct without the
 * new slots — so by-name resolution is required for at least those
 * functions regardless, and using it uniformly avoids maintaining two
 * different binding mechanisms for what is otherwise identical work.
 * C_GetInterface is still probed once at construction (matching P11Ffm's
 * probeGetInterface) to confirm the library negotiates v3.2 — this is a
 * verification step, not the resolution mechanism.
 *
 * W1 scope (this class): the smallest end-to-end slice per the
 * implementation plan — session lifecycle, digest, and random. One
 * instance owns one logged-in session, matching P11Ffm's model; a
 * multi-session pool (P11SessionPool, for concurrent per-operation state
 * once Signature/Cipher/KEM need independent handles) is real W2+ work,
 * not built here.
 *
 * C_Initialize/C_Finalize lifecycle: PKCS#11 defines these as PROCESS-GLOBAL,
 * not per-caller (confirmed by reading the engine's own C_Initialize —
 * src/lib/SoftHSM_slots.cpp:84-101 — which tracks a single isInitialised
 * flag and returns CKR_CRYPTOKI_ALREADY_INITIALIZED on a second call; it
 * even registers its own atexit handler, signaling the engine expects
 * process-exit teardown rather than a per-object one). A first version of
 * this class called C_Initialize/C_Finalize per instance, matching
 * P11Ffm's single-session sample pattern — that works for a one-shot CLI
 * sample but breaks the moment a real JVM process constructs more than
 * one instance (every test in this module's own test class, and any real
 * multi-Provider or repeated-getInstance JCA usage). Caught live via
 * `mvn test` (CKR_CRYPTOKI_ALREADY_INITIALIZED on the second instance)
 * before this ever reached production code. Fixed here: C_Initialize is
 * called at most once per JVM process (idempotent guard below); C_Finalize
 * is intentionally never called from Java — global engine state lives for
 * the process lifetime, matching the engine's own atexit-handler design
 * intent, and matching how JCA providers conventionally treat expensive
 * process-wide native state (not torn down per-Provider-instance/GC).
 * close() only releases this instance's own session (C_CloseSession) —
 * see the close() method itself for why C_Logout is deliberately excluded
 * too (same token-wide-state reasoning as C_Initialize/C_Finalize above).
 *
 * Memory-lifetime architecture (plan §WS-C, 2026-08-25 — replaces an
 * earlier, disclosed design gap): a first version of this class allocated
 * every native buffer — mechanism/attribute structs, key material,
 * plaintext, the PIN — from ONE {@code Arena.ofShared()} that lived for
 * the whole session, freed only when {@link #close()} ran. That arena's
 * own javadoc still names the reason it must stay shared and long-lived
 * for one specific purpose: {@code SymbolLookup.libraryLookup(modulePath,
 * arena)} ties the loaded native library's lifetime to it, and
 * {@link #close()} can run on a JVM shutdown-hook thread different from
 * the one that constructed this instance (see {@code close()}'s own
 * comment on {@code CLOSE_LOCK}) — a {@code Arena.ofConfined()} could not
 * be closed from that other thread. But every OTHER allocation in this
 * class never needed that lifetime: closing a confined arena deallocates
 * without scrubbing, so real secret material (PIN bytes, HKDF salts,
 * raw key bytes re-imported as AES, decrypted plaintext) sat mapped and
 * readable in this process for as long as the session stayed open —
 * potentially hours — rather than for the single native call that
 * actually needed it. Every operation method below now opens its own
 * {@code Arena.ofConfined()} (named {@code op} throughout) spanning
 * exactly that one operation, and the mechanism/attribute builder methods
 * (the {@code mechXxx}/{@code attrs}/{@code bytes} family) take that
 * arena as an explicit parameter instead of reaching for an instance
 * field — necessary because a caller building a mechanism via
 * {@code mechGcm}/{@code mechHkdf}/etc. and a subsequent
 * {@code encrypt}/{@code deriveKey}/etc. call are two separate method
 * calls sharing one memory segment, so both must run inside the same
 * still-open arena (a per-call self-closing arena inside the builder
 * itself would free the segment before the native call that reads it
 * ever ran). Every segment built from real byte[] content — anything
 * that came from {@link #bytes} directly, or from {@link #attrs}'s
 * per-attribute value segments (which can carry a real {@code CKA_VALUE})
 * — is explicitly zeroed ({@code MemorySegment.fill((byte) 0)}) in a
 * {@code finally} block before its confined arena closes; this is
 * intentionally broader than only the values the plan itself named as
 * clearly secret (the PIN, {@code getAttributeBytes}'s {@code CKA_VALUE}
 * output, wrap/unwrap buffers, sign/encrypt/decrypt data) — applying one
 * uniform rule ("real byte-content segments get scrubbed; pure protocol
 * scaffolding like mechanism/attribute struct headers and length/handle
 * cells does not") is both simpler to verify by inspection than a
 * method-by-method secret/non-secret judgment call and strictly more
 * thorough, at negligible cost (these are all sub-KB buffers on an
 * already token-bound, non-hot-path operation). Public key material,
 * KEM ciphertext, GCM IVs/AAD, and similar values that are public by
 * protocol design are the deliberate exceptions left unscrubbed, matching
 * the plan's own (c) classification. Verified by code review and by this
 * refactor's own structure (every secret-carrying buffer's arena now
 * closes within the single native call that used it, not at session end)
 * — not by a native-heap-dump probe, which the plan explicitly judged
 * disproportionate for this class of change (the existing JVM-heap-dump
 * audit in {@code ZeroizationAuditTest} covers the one place real secret
 * bytes ever reach the JVM heap at all, an orthogonal and already-solved
 * problem this refactor does not touch).
 */
final class P11Library implements AutoCloseable {

    // CK_MECHANISM { CK_MECHANISM_TYPE; CK_VOID_PTR; CK_ULONG; }
    private static final MemoryLayout MECHANISM =
        MemoryLayout.structLayout(JAVA_LONG, ADDRESS, JAVA_LONG);
    // CK_ATTRIBUTE { CK_ATTRIBUTE_TYPE; CK_VOID_PTR; CK_ULONG; }
    private static final MemoryLayout ATTRIBUTE =
        MemoryLayout.structLayout(JAVA_LONG, ADDRESS, JAVA_LONG);
    private static final long ATTR_SIZE = ATTRIBUTE.byteSize();

    static final long CKU_USER = 1L;
    static final long CKF_SERIAL_SESSION = 0x4L;
    static final long CKF_RW_SESSION = 0x2L;

    /** Attribute value pair; use attr()/attrBool()/attrLong() to build one. */
    record Attr(long type, byte[] value) {}

    static Attr attr(long type, byte[] value)  { return new Attr(type, value); }
    static Attr attrBool(long type, boolean v) { return new Attr(type, new byte[]{ (byte) (v ? 1 : 0) }); }
    static Attr attrLong(long type, long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) b[i] = (byte) (v >>> (8 * i));
        return new Attr(type, b);
    }

    /**
     * attrs() build result: the CK_ATTRIBUTE struct array plus each
     * attribute's individually-allocated value segment, so the caller can
     * scrub them (see {@link #zero(BuiltAttrs)}) after the native call
     * that consumes them — a value segment can carry a real
     * {@code CKA_VALUE} (raw key material being imported), and this class
     * scrubs indiscriminately across all of them rather than special-casing
     * which attribute type happens to be secret at a given call site (see
     * the class javadoc's "Memory-lifetime architecture" note).
     */
    private record BuiltAttrs(MemorySegment segment, MemorySegment[] values) {}

    /**
     * mechXxx() build result for the two builders (HKDF, PBKDF2) whose
     * mechanism parameters embed real secret byte content (a salt that may
     * be a foreign key's raw bytes, or a PBKDF2 password) — see the class
     * javadoc. Builders whose embedded byte content is public by protocol
     * design (GCM IV/AAD, CBC/CTR IV, SP 800-108 fixed-input/IV, RSA-PSS's
     * all-CK_ULONG params) return a plain {@link MemorySegment} instead;
     * there is nothing in them worth tracking for zeroing.
     */
    record BuiltMech(MemorySegment segment, MemorySegment[] secrets) {}

    private static void zero(MemorySegment... segs) {
        for (MemorySegment s : segs) {
            if (s != null && s != MemorySegment.NULL && s.byteSize() > 0) s.fill((byte) 0);
        }
    }

    private static void zero(BuiltAttrs a) { zero(a.values()); }
    private static void zero(BuiltMech m) { zero(m.secrets()); }

    // Process-global C_Initialize guard — see class javadoc. Synchronized
    // on the class object; construction only happens on the (rare, non-hot)
    // provider/session-setup path, so contention is not a concern.
    private static volatile boolean globalInitDone = false;

    // Kept ONLY to hold the loaded native library alive for this instance's
    // lifetime (SymbolLookup.libraryLookup(modulePath, arena) below) and to
    // be closeable from a shutdown-hook thread different from the
    // constructing one (see close()'s CLOSE_LOCK comment) — Arena.ofShared()
    // is required for that cross-thread close, Arena.ofConfined() is not.
    // NEVER allocate application data from this field after construction —
    // see the class javadoc's "Memory-lifetime architecture" note; every
    // operation method below opens its own short-lived confined arena
    // instead.
    private final Arena arena;
    private final MethodHandle cGetSlotList, cOpenSession, cLogin,
        // cLogout: bound but deliberately unused in this class — see
        // close()'s comment. Reserved for W2's P11SessionPool, which will
        // own a real reference-counted "logout only when the last session
        // on this token closes" policy instead of an individual
        // P11Library instance guessing at other instances' state.
        cLogout, cCloseSession, cDigestInit, cDigestUpdate, cDigestFinal,
        cGenerateRandom, cSeedRandom, cGenerateKeyPair, cSignInit, cSign,
        cVerifyInit, cVerify, cGetAttributeValue, cCreateObject,
        cFindObjectsInit, cFindObjects, cFindObjectsFinal,
        cEncapsulateKey, cDecapsulateKey, cDeriveKey,
        cEncryptInit, cEncrypt, cDecryptInit, cDecrypt,
        cGenerateKey, cWrapKey, cUnwrapKey,
        cCopyObject, cDestroyObject;
    private final long session;
    private volatile boolean closed;
    private volatile boolean loggedIn;

    P11Library(String modulePath, String pin) {
        arena = Arena.ofShared();
        try {
            Linker linker = Linker.nativeLinker();
            SymbolLookup lib = SymbolLookup.libraryLookup(modulePath, arena);

            int negotiated = probeGetInterface(linker, lib);
            if (negotiated < 32) {
                throw new ProviderException("PKCS#11 module at " + modulePath
                    + " did not negotiate v3.2 (probe returned " + negotiated + ")");
            }

            cGetSlotList   = h(linker, lib, "C_GetSlotList", fd(JAVA_BYTE, ADDRESS, ADDRESS));
            cOpenSession   = h(linker, lib, "C_OpenSession", fd(JAVA_LONG, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS));
            cLogin         = h(linker, lib, "C_Login", fd(JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG));
            cLogout        = h(linker, lib, "C_Logout", fd(JAVA_LONG));
            cCloseSession  = h(linker, lib, "C_CloseSession", fd(JAVA_LONG));
            cDigestInit    = h(linker, lib, "C_DigestInit", fd(JAVA_LONG, ADDRESS));
            cDigestUpdate  = h(linker, lib, "C_DigestUpdate", fd(JAVA_LONG, ADDRESS, JAVA_LONG));
            cDigestFinal   = h(linker, lib, "C_DigestFinal", fd(JAVA_LONG, ADDRESS, ADDRESS));
            cGenerateRandom = h(linker, lib, "C_GenerateRandom", fd(JAVA_LONG, ADDRESS, JAVA_LONG));
            cSeedRandom    = h(linker, lib, "C_SeedRandom", fd(JAVA_LONG, ADDRESS, JAVA_LONG));
            // Signatures below cross-checked against P11Ffm's already-live-verified
            // bindings (samples/java/.../P11Ffm.java in pqctoday-sandbox), not
            // re-derived from the spec by hand — avoids repeating the transcription
            // slip caught earlier on C_Login.
            cGenerateKeyPair = h(linker, lib, "C_GenerateKeyPair",
                fd(JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
            cSignInit      = h(linker, lib, "C_SignInit", fd(JAVA_LONG, ADDRESS, JAVA_LONG));
            cSign          = h(linker, lib, "C_Sign", fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
            cVerifyInit    = h(linker, lib, "C_VerifyInit", fd(JAVA_LONG, ADDRESS, JAVA_LONG));
            cVerify        = h(linker, lib, "C_Verify", fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
            cGetAttributeValue = h(linker, lib, "C_GetAttributeValue", fd(JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG));
            cCreateObject  = h(linker, lib, "C_CreateObject", fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS));
            cFindObjectsInit = h(linker, lib, "C_FindObjectsInit", fd(JAVA_LONG, ADDRESS, JAVA_LONG));
            cFindObjects   = h(linker, lib, "C_FindObjects", fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS));
            cFindObjectsFinal = h(linker, lib, "C_FindObjectsFinal", fd(JAVA_LONG));
            // v3.2 KEM functions — signatures cross-checked against P11Ffm's
            // already-live-verified bindings, same discipline as above.
            cEncapsulateKey = h(linker, lib, "C_EncapsulateKey",
                fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS));
            cDecapsulateKey = h(linker, lib, "C_DecapsulateKey",
                fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS));
            cDeriveKey     = h(linker, lib, "C_DeriveKey",
                fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS));
            // Cross-checked against P11Ffm's already-live-verified bindings.
            cEncryptInit   = h(linker, lib, "C_EncryptInit", fd(JAVA_LONG, ADDRESS, JAVA_LONG));
            cEncrypt       = h(linker, lib, "C_Encrypt", fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
            cDecryptInit   = h(linker, lib, "C_DecryptInit", fd(JAVA_LONG, ADDRESS, JAVA_LONG));
            cDecrypt       = h(linker, lib, "C_Decrypt", fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
            // W4 — AES key generation and wrap/unwrap.
            cGenerateKey   = h(linker, lib, "C_GenerateKey", fd(JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
            cWrapKey       = h(linker, lib, "C_WrapKey",
                fd(JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG, ADDRESS, ADDRESS));
            cUnwrapKey     = h(linker, lib, "C_UnwrapKey",
                fd(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS));
            // W4 — KeyStore write path.
            cCopyObject    = h(linker, lib, "C_CopyObject", fd(JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS));
            cDestroyObject = h(linker, lib, "C_DestroyObject", fd(JAVA_LONG, JAVA_LONG));

            ensureGlobalInit(linker, lib);

            // Slot lookup, session open, and login all use a LOCAL confined
            // arena scoped to just this constructor — none of these
            // segments need to outlive it, and the PIN copy in particular
            // must not (plan §WS-C item 4): a prior version of this class
            // allocated all of this from the long-lived shared `arena`
            // field above, leaving the PIN's raw bytes mapped and readable
            // for the whole session instead of for this one login call.
            try (Arena init = Arena.ofConfined()) {
                MemorySegment count = init.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cGetSlotList, (byte) 1, MemorySegment.NULL, count), "C_GetSlotList(size)");
                long n = count.get(JAVA_LONG, 0);
                if (n == 0) throw new ProviderException("no PKCS#11 slots with a token present");
                MemorySegment slots = init.allocate(JAVA_LONG, n);
                P11Error.check(invokeRv(cGetSlotList, (byte) 1, slots, count), "C_GetSlotList");
                long slot = slots.get(JAVA_LONG, 0);

                MemorySegment hSession = init.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cOpenSession, slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    MemorySegment.NULL, MemorySegment.NULL, hSession), "C_OpenSession");
                session = hSession.get(JAVA_LONG, 0);

                byte[] pinBytes = pin.getBytes(StandardCharsets.UTF_8);
                MemorySegment pinSeg = init.allocate(Math.max(pinBytes.length, 1));
                MemorySegment.copy(pinBytes, 0, pinSeg, JAVA_BYTE, 0, pinBytes.length);
                try {
                    long loginRv = invokeRv(cLogin, session, CKU_USER, pinSeg, (long) pinBytes.length);
                    // CKR_USER_ALREADY_LOGGED_IN is not an error here: PKCS#11 login
                    // state is per-TOKEN, not per-session (spec §5.6.1) — a prior
                    // session on this same slot (e.g. an earlier P11Library
                    // instance in this process) already authenticated, and that
                    // covers every session on the token, including this new one.
                    // Same class of bug as C_Initialize above, caught the same way
                    // (live `mvn test` with 2+ instances) — every OTHER CK_RV still
                    // fails hard via P11Error.check.
                    if (loginRv != P11Error.CKR_OK && loginRv != CKR_USER_ALREADY_LOGGED_IN) {
                        P11Error.check(loginRv, "C_Login");
                    }
                } finally {
                    zero(pinSeg);
                    java.util.Arrays.fill(pinBytes, (byte) 0);
                }
            }
            loggedIn = true;
        } catch (ProviderException e) {
            arena.close();
            throw e;
        } catch (Throwable t) {
            arena.close();
            throw new ProviderException("PKCS#11 module init failed for " + modulePath, t);
        }
    }

    // §6.1 AuthProvider support. Real C_RV values from pkcs11t.h (grepped
    // before use, this repo's usual discipline): CKR_USER_ALREADY_LOGGED_IN
    // = 0x100, CKR_USER_NOT_LOGGED_IN = 0x101, CKR_PIN_INCORRECT = 0xA0.
    static final long CKR_USER_ALREADY_LOGGED_IN = 0x00000100L;
    static final long CKR_USER_NOT_LOGGED_IN     = 0x00000101L;
    static final long CKR_PIN_INCORRECT          = 0x000000A0L;

    boolean isLoggedIn() { return loggedIn; }

    /**
     * Explicit C_Login, for AuthProvider.login() called after an earlier
     * logout() (construction already logs in eagerly — see the class
     * javadoc — so this is not needed for the default "just works"
     * lifecycle, only for a caller doing real login/logout cycling).
     * The native call's own return code is authoritative, not the local
     * `loggedIn` flag: PKCS#11 login state is per-TOKEN (spec §5.6.1), so
     * another P11Library instance sharing this token in the same process
     * could have changed it without this instance knowing.
     */
    void login(byte[] pinBytes) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment pinSeg = op.allocate(Math.max(pinBytes.length, 1));
            MemorySegment.copy(pinBytes, 0, pinSeg, JAVA_BYTE, 0, pinBytes.length);
            try {
                long rv = invokeRv(cLogin, session, CKU_USER, pinSeg, (long) pinBytes.length);
                if (rv == P11Error.CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) {
                    loggedIn = true;
                    return;
                }
                loggedIn = false;
                if (rv == CKR_PIN_INCORRECT) {
                    // Distinct unchecked type so SoftHSMv3Provider.login() can
                    // translate this into javax.security.auth.login.FailedLoginException
                    // without string-matching a generic ProviderException message.
                    throw new SecurityException("CKR_PIN_INCORRECT");
                }
                P11Error.check(rv, "C_Login");
            } finally {
                zero(pinSeg);
            }
        } catch (ProviderException | SecurityException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("login failed", t);
        }
    }

    /**
     * Explicit C_Logout — deauthenticates the WHOLE TOKEN (spec §5.6.1,
     * same reasoning as login() above), not just this instance's own
     * session: every other live P11Library/SoftHSMv3Provider instance
     * sharing this token in the same process is logged out too, and
     * their next privileged operation will fail until someone logs back
     * in. This is real PKCS#11 semantics, not a bug in this method — the
     * class javadoc's own C_Logout-exclusion note for close() documents
     * the same fact from the other direction (why close() never calls it
     * implicitly).
     */
    void logout() {
        ensureOpen();
        try {
            long rv = invokeRv(cLogout, session);
            if (rv == P11Error.CKR_OK || rv == CKR_USER_NOT_LOGGED_IN) {
                loggedIn = false;
                return;
            }
            P11Error.check(rv, "C_Logout");
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("logout failed", t);
        }
    }

    /** C_DigestInit/Update/Final, single call. */
    byte[] digest(long mechType, byte[] data) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment mech = mech(op, mechType);
            MemorySegment in = bytes(op, data);
            try {
                P11Error.check(invokeRv(cDigestInit, session, mech), "C_DigestInit");
                P11Error.check(invokeRv(cDigestUpdate, session, in, (long) data.length), "C_DigestUpdate");
                MemorySegment len = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cDigestFinal, session, MemorySegment.NULL, len), "C_DigestFinal(size)");
                MemorySegment out = op.allocate(len.get(JAVA_LONG, 0));
                P11Error.check(invokeRv(cDigestFinal, session, out, len), "C_DigestFinal");
                return toBytes(out, len.get(JAVA_LONG, 0));
            } finally {
                zero(in);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("digest failed", t);
        }
    }

    /** C_GenerateRandom — SP 800-90A DRBG inside the token, never JVM software randomness. */
    byte[] generateRandom(int len) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment out = op.allocate(Math.max(len, 1));
            try {
                P11Error.check(invokeRv(cGenerateRandom, session, out, (long) len), "C_GenerateRandom");
                return toBytes(out, len);
            } finally {
                zero(out);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("generateRandom failed", t);
        }
    }

    /** C_SeedRandom. */
    void seedRandom(byte[] seed) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment s = bytes(op, seed);
            try {
                P11Error.check(invokeRv(cSeedRandom, session, s, (long) seed.length), "C_SeedRandom");
            } finally {
                zero(s);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("seedRandom failed", t);
        }
    }

    /** C_GenerateKeyPair; returns { publicHandle, privateHandle }. */
    long[] generateKeyPair(long mechType, Attr[] pubTmpl, Attr[] prvTmpl) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment mech = mech(op, mechType);
            BuiltAttrs builtPub = attrs(op, pubTmpl);
            BuiltAttrs builtPrv = attrs(op, prvTmpl);
            try {
                MemorySegment hPub = op.allocate(JAVA_LONG);
                MemorySegment hPrv = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cGenerateKeyPair, session, mech, builtPub.segment(), (long) pubTmpl.length,
                    builtPrv.segment(), (long) prvTmpl.length, hPub, hPrv), "C_GenerateKeyPair");
                return new long[]{ hPub.get(JAVA_LONG, 0), hPrv.get(JAVA_LONG, 0) };
            } finally {
                zero(builtPub);
                zero(builtPrv);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("generateKeyPair failed", t);
        }
    }

    /** C_SignInit + C_Sign (single-part), two-call sizing. Opens its own confined arena — see the Arena-taking overload for callers that already built their own mechanism. */
    byte[] sign(long mechType, long key, byte[] data) {
        try (Arena op = Arena.ofConfined()) {
            return sign(op, mech(op, mechType), key, data);
        }
    }

    /** Same as sign(long, long, byte[]) but with a caller-built CK_MECHANISM (e.g. RSA-PSS's parameter block) and the arena it was built in — see the class javadoc's "Memory-lifetime architecture" note for why the arena must be shared across both calls. */
    byte[] sign(Arena op, MemorySegment mech, long key, byte[] data) {
        ensureOpen();
        try {
            P11Error.check(invokeRv(cSignInit, session, mech, key), "C_SignInit");
            MemorySegment msg = bytes(op, data);
            try {
                MemorySegment len = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cSign, session, msg, (long) data.length, MemorySegment.NULL, len), "C_Sign(size)");
                MemorySegment sig = op.allocate(len.get(JAVA_LONG, 0));
                P11Error.check(invokeRv(cSign, session, msg, (long) data.length, sig, len), "C_Sign");
                return toBytes(sig, len.get(JAVA_LONG, 0));
            } finally {
                zero(msg);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("sign failed", t);
        }
    }

    /** C_VerifyInit + C_Verify (single-part). Returns false (not an exception) on CKR_SIGNATURE_INVALID. Opens its own confined arena — see the Arena-taking overload. */
    boolean verify(long mechType, long key, byte[] data, byte[] signature) {
        try (Arena op = Arena.ofConfined()) {
            return verify(op, mech(op, mechType), key, data, signature);
        }
    }

    /** Same as verify(long, long, byte[], byte[]) but with a caller-built CK_MECHANISM and the arena it was built in. */
    boolean verify(Arena op, MemorySegment mech, long key, byte[] data, byte[] signature) {
        ensureOpen();
        try {
            P11Error.check(invokeRv(cVerifyInit, session, mech, key), "C_VerifyInit");
            MemorySegment msg = bytes(op, data);
            try {
                long rv = invokeRv(cVerify, session, msg, (long) data.length,
                    bytes(op, signature), (long) signature.length);
                if (rv == P11Error.CKR_OK) return true;
                if (rv == 0x000000c0L /* CKR_SIGNATURE_INVALID */) return false;
                P11Error.check(rv, "C_Verify");
                return false; // unreachable — check() throws for any other non-OK rv
            } finally {
                zero(msg);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("verify failed", t);
        }
    }

    /** C_GetAttributeValue, two-call sizing — for public-key export (SubjectPublicKeyInfo assembly) and the module's few deliberate opaque-key exceptions (raw CKA_VALUE reads). */
    byte[] getAttributeBytes(long object, long attrType) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment a = op.allocate(ATTRIBUTE);
            a.set(JAVA_LONG, 0, attrType);
            a.set(ADDRESS, 8, MemorySegment.NULL);
            a.set(JAVA_LONG, 16, 0L);
            P11Error.check(invokeRv(cGetAttributeValue, session, object, a, 1L), "C_GetAttributeValue(size)");
            long len = a.get(JAVA_LONG, 16);
            MemorySegment buf = op.allocate(Math.max(len, 1));
            a.set(ADDRESS, 8, buf);
            try {
                P11Error.check(invokeRv(cGetAttributeValue, session, object, a, 1L), "C_GetAttributeValue");
                return toBytes(buf, len);
            } finally {
                zero(buf);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("getAttributeBytes failed", t);
        }
    }

    /**
     * C_FindObjectsInit + repeated C_FindObjects + C_FindObjectsFinal.
     * PKCS#11 §5.6 defines C_FindObjects as a batched call that must be
     * called repeatedly (each time asking for up to `batch` more) until
     * it returns fewer objects than requested — a single call is only
     * guaranteed complete if the true match count is below the batch
     * size. A first version of this method called C_FindObjects exactly
     * once with a fixed cap and returned whatever came back, silently
     * truncating once the token held more matching objects than that cap
     * — caught live via `mvn test`'s full suite (not a single isolated
     * test, which stayed under the cap and passed): a just-generated key
     * went missing from KeyStore enumeration once accumulated session
     * objects from ~80 other key-generating tests pushed the real count
     * past the old hardcoded batch size. Fixed by looping.
     */
    long[] findObjects(Attr[] template) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            BuiltAttrs builtTmpl = attrs(op, template);
            try {
                P11Error.check(invokeRv(cFindObjectsInit, session, builtTmpl.segment(), (long) template.length), "C_FindObjectsInit");
                try {
                    int batch = 256;
                    java.util.List<Long> out = new java.util.ArrayList<>();
                    MemorySegment handles = op.allocate(JAVA_LONG, batch);
                    MemorySegment count = op.allocate(JAVA_LONG);
                    while (true) {
                        P11Error.check(invokeRv(cFindObjects, session, handles, (long) batch, count), "C_FindObjects");
                        long n = count.get(JAVA_LONG, 0);
                        for (int i = 0; i < n; i++) out.add(handles.get(JAVA_LONG, i * 8L));
                        if (n < batch) break; // fewer than requested => this was the last batch
                    }
                    long[] result = new long[out.size()];
                    for (int i = 0; i < result.length; i++) result[i] = out.get(i);
                    return result;
                } finally {
                    invokeRv(cFindObjectsFinal, session);
                }
            } finally {
                zero(builtTmpl);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("findObjects failed", t);
        }
    }

    /** Result of C_EncapsulateKey: the wire ciphertext plus a handle to the (opaque) derived shared-secret object. */
    record Encapsulated(byte[] ciphertext, long sharedSecretHandle) {}

    /** C_EncapsulateKey with two-call ciphertext sizing (v3.2 §5.27) — matches P11Ffm's proven pattern. */
    Encapsulated encapsulate(long mechType, long publicKey, Attr[] ssTmpl) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment mech = mech(op, mechType);
            BuiltAttrs builtTmpl = attrs(op, ssTmpl);
            try {
                MemorySegment ctLen = op.allocate(JAVA_LONG);
                MemorySegment hSs = op.allocate(JAVA_LONG);
                long rv = invokeRv(cEncapsulateKey, session, mech, publicKey,
                    builtTmpl.segment(), (long) ssTmpl.length, MemorySegment.NULL, ctLen, hSs);
                if (rv != P11Error.CKR_OK && rv != 0x00000150L /* CKR_BUFFER_TOO_SMALL */) {
                    P11Error.check(rv, "C_EncapsulateKey(size)");
                }
                MemorySegment ct = op.allocate(ctLen.get(JAVA_LONG, 0));
                P11Error.check(invokeRv(cEncapsulateKey, session, mech, publicKey,
                    builtTmpl.segment(), (long) ssTmpl.length, ct, ctLen, hSs), "C_EncapsulateKey");
                return new Encapsulated(toBytes(ct, ctLen.get(JAVA_LONG, 0)), hSs.get(JAVA_LONG, 0));
            } finally {
                zero(builtTmpl);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("encapsulate failed", t);
        }
    }

    /** C_DecapsulateKey; returns a handle to the (opaque) derived shared-secret object. */
    long decapsulate(long mechType, long privateKey, Attr[] ssTmpl, byte[] ciphertext) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment mech = mech(op, mechType);
            BuiltAttrs builtTmpl = attrs(op, ssTmpl);
            MemorySegment ct = bytes(op, ciphertext);
            try {
                MemorySegment hSs = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cDecapsulateKey, session, mech, privateKey,
                    builtTmpl.segment(), (long) ssTmpl.length, ct, (long) ciphertext.length, hSs),
                    "C_DecapsulateKey");
                return hSs.get(JAVA_LONG, 0);
            } finally {
                zero(builtTmpl);
                zero(ct);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("decapsulate failed", t);
        }
    }

    // CK_ECDH1_DERIVE_PARAMS { CK_EC_KDF_TYPE kdf; CK_ULONG ulSharedDataLen;
    // CK_BYTE_PTR pSharedData; CK_ULONG ulPublicDataLen; CK_BYTE_PTR pPublicData; }
    private static final MemoryLayout ECDH1_DERIVE_PARAMS =
        MemoryLayout.structLayout(JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS);

    /**
     * C_DeriveKey for CKM_ECDH1_DERIVE (CKD_NULL, no shared data — the
     * plain-ECDH case). `peerPublicPointRaw` must be the RAW uncompressed
     * point (04||X||Y), NOT the DER-OCTET-STRING-wrapped form CKA_EC_POINT
     * itself stores — confirmed against the sandbox's own proven C sample
     * (samples/c/08_ecdh_p256.c's get_ec_point() helper, which explicitly
     * strips that wrapper before passing the bytes to this struct) before
     * writing this method, not assumed. Returns the derived secret-key
     * object's handle.
     */
    long ecdh1Derive(long basePrivateKey, byte[] peerPublicPointRaw, Attr[] ssTmpl) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment pubData = bytes(op, peerPublicPointRaw);
            MemorySegment params = op.allocate(ECDH1_DERIVE_PARAMS);
            params.set(JAVA_LONG, 0, 1L); // CKD_NULL (pkcs11t.h: 0x00000001)
            params.set(JAVA_LONG, 8, 0L); // ulSharedDataLen
            params.set(ADDRESS, 16, MemorySegment.NULL); // pSharedData
            params.set(JAVA_LONG, 24, (long) peerPublicPointRaw.length);
            params.set(ADDRESS, 32, pubData);

            MemorySegment mech = op.allocate(MECHANISM);
            mech.set(JAVA_LONG, 0, P11Constants.CKM_ECDH1_DERIVE);
            mech.set(ADDRESS, 8, params);
            mech.set(JAVA_LONG, 16, ECDH1_DERIVE_PARAMS.byteSize());

            BuiltAttrs builtTmpl = attrs(op, ssTmpl);
            try {
                MemorySegment hKey = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cDeriveKey, session, mech, basePrivateKey,
                    builtTmpl.segment(), (long) ssTmpl.length, hKey), "C_DeriveKey");
                return hKey.get(JAVA_LONG, 0);
            } finally {
                zero(builtTmpl);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("ecdh1Derive failed", t);
        }
    }

    // CK_RSA_PKCS_OAEP_PARAMS { CK_MECHANISM_TYPE hashAlg; CK_RSA_PKCS_MGF_TYPE mgf;
    // CK_RSA_PKCS_OAEP_SOURCE_TYPE source; CK_VOID_PTR pSourceData; CK_ULONG ulSourceDataLen; }
    // Pointer field is NOT last (unlike ECDH1_DERIVE_PARAMS) — its own struct, not reusable.
    private static final MemoryLayout OAEP_PARAMS =
        MemoryLayout.structLayout(JAVA_LONG, JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG);

    /** CKM_RSA_PKCS_OAEP with no label (CKZ_DATA_SPECIFIED, empty source — the common case). No embedded secret content — plain MemorySegment. */
    MemorySegment mechOaep(Arena op, long hashAlg, long mgf) {
        MemorySegment params = op.allocate(OAEP_PARAMS);
        params.set(JAVA_LONG, 0, hashAlg);
        params.set(JAVA_LONG, 8, mgf);
        params.set(JAVA_LONG, 16, 1L); // CKZ_DATA_SPECIFIED
        params.set(ADDRESS, 24, MemorySegment.NULL);
        params.set(JAVA_LONG, 32, 0L);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_RSA_PKCS_OAEP);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, OAEP_PARAMS.byteSize());
        return m;
    }

    /** C_EncryptInit + C_Encrypt (single-part), two-call sizing. Caller supplies the arena the mechanism was built in — see the class javadoc. */
    byte[] encrypt(Arena op, MemorySegment mech, long key, byte[] plaintext) {
        ensureOpen();
        try {
            MemorySegment in = bytes(op, plaintext);
            try {
                P11Error.check(invokeRv(cEncryptInit, session, mech, key), "C_EncryptInit");
                MemorySegment len = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cEncrypt, session, in, (long) plaintext.length, MemorySegment.NULL, len), "C_Encrypt(size)");
                MemorySegment out = op.allocate(len.get(JAVA_LONG, 0));
                try {
                    P11Error.check(invokeRv(cEncrypt, session, in, (long) plaintext.length, out, len), "C_Encrypt");
                    return toBytes(out, len.get(JAVA_LONG, 0));
                } finally {
                    zero(out);
                }
            } finally {
                zero(in);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("encrypt failed", t);
        }
    }

    /** C_DecryptInit + C_Decrypt (single-part), two-call sizing. Caller supplies the arena the mechanism was built in. */
    byte[] decrypt(Arena op, MemorySegment mech, long key, byte[] ciphertext) {
        ensureOpen();
        try {
            MemorySegment in = bytes(op, ciphertext);
            try {
                P11Error.check(invokeRv(cDecryptInit, session, mech, key), "C_DecryptInit");
                MemorySegment len = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cDecrypt, session, in, (long) ciphertext.length, MemorySegment.NULL, len), "C_Decrypt(size)");
                MemorySegment out = op.allocate(len.get(JAVA_LONG, 0));
                try {
                    P11Error.check(invokeRv(cDecrypt, session, in, (long) ciphertext.length, out, len), "C_Decrypt");
                    return toBytes(out, len.get(JAVA_LONG, 0));
                } finally {
                    zero(out); // the decrypted PLAINTEXT — the single most sensitive buffer in this class
                }
            } finally {
                zero(in);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("decrypt failed", t);
        }
    }

    // CK_HKDF_PARAMS { CK_BBOOL bExtract; CK_BBOOL bExpand; [6 bytes padding];
    // CK_MECHANISM_TYPE prfHashMechanism; CK_ULONG ulSaltType; CK_BYTE_PTR pSalt;
    // CK_ULONG ulSaltLen; CK_OBJECT_HANDLE hSaltKey; CK_BYTE_PTR pInfo; CK_ULONG ulInfoLen; }
    // Layout NOT assumed from ABI convention alone — this is the first struct
    // in this class with 1-byte fields immediately preceding an 8-byte field,
    // an ambiguous case none of the earlier all-CK_ULONG/pointer structs
    // exercised (they happened to need no padding either way). Confirmed via
    // a standalone C probe (sizeof/offsetof against this repo's own
    // pkcs11.h, no #pragma pack override present) before writing this
    // layout: total size 64 bytes, 6 bytes of padding after the two
    // CK_BBOOL fields to reach prfHashMechanism's 8-byte alignment.
    private static final MemoryLayout HKDF_PARAMS = MemoryLayout.structLayout(
        JAVA_BYTE, JAVA_BYTE, MemoryLayout.paddingLayout(6),
        JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG);

    static final long CKF_HKDF_SALT_NULL = 0x00000001L;
    static final long CKF_HKDF_SALT_DATA = 0x00000002L;
    static final long CKF_HKDF_SALT_KEY  = 0x00000004L;

    /**
     * CKM_HKDF_DERIVE mechanism, salt passed as raw bytes
     * (CKF_HKDF_SALT_DATA) or omitted (CKF_HKDF_SALT_NULL). CKA_VALUE_LEN
     * is REQUIRED in the derive template regardless of mode, including
     * extract-only (where RFC 5869 fixes the PRK length at the hash's
     * output size) — confirmed live that the engine will not infer it,
     * the caller must compute and supply it explicitly.
     *
     * Returns a {@link BuiltMech}, not a plain MemorySegment: the salt can
     * be a foreign key's real raw bytes, genuine secret material — tracked
     * so the caller can zero it after the derive call completes (see the
     * class javadoc).
     *
     * See {@link #mechHkdf(Arena, long, boolean, boolean, long, byte[])} for the
     * salt-by-handle (CKF_HKDF_SALT_KEY) overload, added for plan §W6/WS-A
     * once the engine gained real support for it (2026-08-25) — this
     * class's own javadoc used to say the engine "explicitly rejects
     * CKF_HKDF_SALT_KEY", true when first written, no longer true.
     */
    BuiltMech mechHkdf(Arena op, long prfHashMech, boolean extract, boolean expand, byte[] salt, byte[] info) {
        MemorySegment params = op.allocate(HKDF_PARAMS);
        params.set(JAVA_BYTE, 0, (byte) (extract ? 1 : 0));
        params.set(JAVA_BYTE, 1, (byte) (expand ? 1 : 0));
        params.set(JAVA_LONG, 8, prfHashMech);
        params.set(JAVA_LONG, 16, salt.length > 0 ? CKF_HKDF_SALT_DATA : CKF_HKDF_SALT_NULL);
        MemorySegment saltSeg = salt.length > 0 ? bytes(op, salt) : MemorySegment.NULL;
        params.set(ADDRESS, 24, saltSeg);
        params.set(JAVA_LONG, 32, (long) salt.length);
        params.set(JAVA_LONG, 40, 0L); // hSaltKey — unused on this path, see the salt-by-handle overload
        MemorySegment infoSeg = info.length > 0 ? bytes(op, info) : MemorySegment.NULL;
        params.set(ADDRESS, 48, infoSeg);
        params.set(JAVA_LONG, 56, (long) info.length);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_HKDF_DERIVE);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, HKDF_PARAMS.byteSize());
        return new BuiltMech(m, new MemorySegment[]{ saltSeg, infoSeg });
    }

    /**
     * CKM_HKDF_DERIVE with the salt supplied as a token object handle
     * (CKF_HKDF_SALT_KEY) rather than raw bytes — lets an opaque key (one
     * whose CKA_VALUE never crosses into the JVM) serve as the HKDF salt
     * without extracting it. This is the salt-by-handle path plan §W6's
     * live TLS spike needed: TLS 1.3's key schedule chains a previous
     * (opaque) derived secret back in as the next Extract step's salt.
     * The engine change (2026-08-25) is what makes this method possible —
     * before it, hSaltKey was accepted structurally but the engine
     * rejected CKF_HKDF_SALT_KEY outright.
     */
    BuiltMech mechHkdf(Arena op, long prfHashMech, boolean extract, boolean expand, long saltKeyHandle, byte[] info) {
        MemorySegment params = op.allocate(HKDF_PARAMS);
        params.set(JAVA_BYTE, 0, (byte) (extract ? 1 : 0));
        params.set(JAVA_BYTE, 1, (byte) (expand ? 1 : 0));
        params.set(JAVA_LONG, 8, prfHashMech);
        params.set(JAVA_LONG, 16, CKF_HKDF_SALT_KEY);
        params.set(ADDRESS, 24, MemorySegment.NULL); // pSalt — unused on this path
        params.set(JAVA_LONG, 32, 0L); // ulSaltLen — unused on this path
        params.set(JAVA_LONG, 40, saltKeyHandle);
        MemorySegment infoSeg = info.length > 0 ? bytes(op, info) : MemorySegment.NULL;
        params.set(ADDRESS, 48, infoSeg);
        params.set(JAVA_LONG, 56, (long) info.length);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_HKDF_DERIVE);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, HKDF_PARAMS.byteSize());
        return new BuiltMech(m, new MemorySegment[]{ infoSeg });
    }

    // CK_PKCS5_PBKD2_PARAMS2 { CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE saltSource;
    // CK_VOID_PTR pSaltSourceData; CK_ULONG ulSaltSourceDataLen; CK_ULONG iterations;
    // CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf; CK_VOID_PTR pPrfData;
    // CK_ULONG ulPrfDataLen; CK_UTF8CHAR_PTR pPassword; CK_ULONG ulPasswordLen; }
    // All 9 fields are CK_ULONG-or-pointer (8 bytes each, naturally aligned) —
    // unlike CK_HKDF_PARAMS, no CK_BBOOL fields exist here, so there is no
    // padding ambiguity to verify against a C probe first.
    private static final MemoryLayout PBKDF2_PARAMS = MemoryLayout.structLayout(
        JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG);

    /** CKM_PKCS5_PBKD2 (SP 800-132). Salt is always CKZ_SALT_SPECIFIED (raw bytes) — the only source type this engine supports. Returns a BuiltMech: the password is genuine secret material. */
    BuiltMech mechPbkdf2(Arena op, long prf, byte[] salt, long iterations, byte[] password) {
        MemorySegment params = op.allocate(PBKDF2_PARAMS);
        params.set(JAVA_LONG, 0, P11Constants.CKZ_SALT_SPECIFIED);
        MemorySegment saltSeg = bytes(op, salt);
        params.set(ADDRESS, 8, saltSeg);
        params.set(JAVA_LONG, 16, (long) salt.length);
        params.set(JAVA_LONG, 24, iterations);
        params.set(JAVA_LONG, 32, prf);
        params.set(ADDRESS, 40, MemorySegment.NULL); // pPrfData — unused for the HMAC PRF family
        params.set(JAVA_LONG, 48, 0L);
        MemorySegment pwSeg = bytes(op, password);
        params.set(ADDRESS, 56, pwSeg);
        params.set(JAVA_LONG, 64, (long) password.length);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_PKCS5_PBKD2);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, PBKDF2_PARAMS.byteSize());
        return new BuiltMech(m, new MemorySegment[]{ saltSeg, pwSeg });
    }

    /**
     * C_DeriveKey for mechanisms that need no base key (CKM_PKCS5_PBKD2:
     * the password IS the key material, carried entirely in the
     * mechanism parameters) — confirmed by reading SoftHSM_keygen.cpp's
     * C_DeriveKey before writing this that PBKDF2 is handled in its own
     * early branch that returns before hBaseKey is ever resolved or
     * validated, so any handle value is accepted. Passes 0 explicitly
     * (not reusing deriveKey(...) with a real handle) so a future reader
     * doesn't mistake this for a real base-key dependency.
     */
    long deriveKeyNoBase(Arena op, BuiltMech mech, Attr[] outputTmpl) {
        return deriveKey(op, mech, 0L, outputTmpl);
    }

    // CK_PRF_DATA_PARAM { CK_PRF_DATA_TYPE type; CK_VOID_PTR pValue; CK_ULONG ulValueLen; }
    // — same 3-field ULONG/pointer/ULONG shape as CK_ATTRIBUTE/CK_MECHANISM,
    // reused deliberately rather than declaring a byte-identical duplicate layout.
    private static final MemoryLayout PRF_DATA_PARAM = MECHANISM; // structurally identical
    private static final long PRF_DATA_PARAM_SIZE = PRF_DATA_PARAM.byteSize();

    // CK_SP800_108_KDF_PARAMS { CK_SP800_108_PRF_TYPE prfType; CK_ULONG
    // ulNumberOfDataParams; CK_PRF_DATA_PARAM_PTR pDataParams; CK_ULONG
    // ulAdditionalDerivedKeys; CK_DERIVED_KEY_PTR pAdditionalDerivedKeys; }
    private static final MemoryLayout SP800_108_COUNTER_PARAMS =
        MemoryLayout.structLayout(JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS);

    // CK_SP800_108_FEEDBACK_KDF_PARAMS — same as above with ulIVLen/pIV
    // inserted before the additional-derived-keys tail.
    private static final MemoryLayout SP800_108_FEEDBACK_PARAMS =
        MemoryLayout.structLayout(JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS);

    /**
     * One-element CK_PRF_DATA_PARAM array holding CK_SP800_108_BYTE_ARRAY
     * fixed input (label/context) — the only CK_PRF_DATA_TYPE this engine
     * actually implements besides CK_SP800_108_ITERATION_VARIABLE
     * (confirmed reading SoftHSM_keygen.cpp: CK_SP800_108_DKM_LENGTH and
     * key-handle data params are parsed but silently skipped, "not
     * supported"). Neither counter-width customization nor additional
     * derived keys are exposed here — the engine's own default 32-bit
     * counter applies, matching the scope this class's callers actually
     * need. Returns {addressOrNull, count} — count is 0 (address unused)
     * when fixedInput is empty, matching how an absent CK_PRF_DATA_PARAM
     * array is expressed.
     */
    private static MemorySegment prfDataParams(Arena op, byte[] fixedInput) {
        if (fixedInput.length == 0) return MemorySegment.NULL;
        MemorySegment seg = op.allocate(PRF_DATA_PARAM_SIZE);
        seg.set(JAVA_LONG, 0, P11Constants.CK_SP800_108_BYTE_ARRAY);
        seg.set(ADDRESS, 8, bytes(op, fixedInput));
        seg.set(JAVA_LONG, 16, (long) fixedInput.length);
        return seg;
    }

    /** CKM_SP800_108_COUNTER_KDF (SP 800-108 §5.1). prfType must be a CKM_SHA*_HMAC constant or CKM_AES_CMAC. fixedInput is a public label/context, not secret — plain MemorySegment. */
    MemorySegment mechSp800108Counter(Arena op, long prfType, byte[] fixedInput) {
        MemorySegment params = op.allocate(SP800_108_COUNTER_PARAMS);
        params.set(JAVA_LONG, 0, prfType);
        params.set(JAVA_LONG, 8, fixedInput.length == 0 ? 0L : 1L);
        params.set(ADDRESS, 16, prfDataParams(op, fixedInput));
        params.set(JAVA_LONG, 24, 0L); // ulAdditionalDerivedKeys — not supported here
        params.set(ADDRESS, 32, MemorySegment.NULL);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_SP800_108_COUNTER_KDF);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, SP800_108_COUNTER_PARAMS.byteSize());
        return m;
    }

    /** CKM_SP800_108_FEEDBACK_KDF (SP 800-108 §5.2). iv may be empty (no seed supplied — engine default applies). Neither fixedInput nor iv is secret — plain MemorySegment. */
    MemorySegment mechSp800108Feedback(Arena op, long prfType, byte[] fixedInput, byte[] iv) {
        MemorySegment params = op.allocate(SP800_108_FEEDBACK_PARAMS);
        params.set(JAVA_LONG, 0, prfType);
        params.set(JAVA_LONG, 8, fixedInput.length == 0 ? 0L : 1L);
        params.set(ADDRESS, 16, prfDataParams(op, fixedInput));
        params.set(JAVA_LONG, 24, (long) iv.length);
        params.set(ADDRESS, 32, iv.length == 0 ? MemorySegment.NULL : bytes(op, iv));
        params.set(JAVA_LONG, 40, 0L); // ulAdditionalDerivedKeys — not supported here
        params.set(ADDRESS, 48, MemorySegment.NULL);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_SP800_108_FEEDBACK_KDF);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, SP800_108_FEEDBACK_PARAMS.byteSize());
        return m;
    }

    /** C_DeriveKey with a caller-built CK_MECHANISM whose embedded content is public (HKDF/ECDH have their own dedicated entry points above). */
    long deriveKey(Arena op, MemorySegment mech, long baseKey, Attr[] outputTmpl) {
        ensureOpen();
        try {
            BuiltAttrs builtTmpl = attrs(op, outputTmpl);
            try {
                MemorySegment hKey = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cDeriveKey, session, mech, baseKey,
                    builtTmpl.segment(), (long) outputTmpl.length, hKey), "C_DeriveKey");
                return hKey.get(JAVA_LONG, 0);
            } finally {
                zero(builtTmpl);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("deriveKey failed", t);
        }
    }

    /** Same as deriveKey(Arena, MemorySegment, long, Attr[]) but for a BuiltMech (HKDF/PBKDF2) — scrubs the mechanism's own embedded secret bytes after the derive call completes. */
    long deriveKey(Arena op, BuiltMech mech, long baseKey, Attr[] outputTmpl) {
        try {
            return deriveKey(op, mech.segment(), baseKey, outputTmpl);
        } finally {
            zero(mech);
        }
    }

    /** C_CreateObject — imports a caller-supplied key onto the token (public keys only; see KeyFactory import). */
    long createObject(Attr[] template) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            BuiltAttrs builtTmpl = attrs(op, template);
            try {
                MemorySegment hObj = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cCreateObject, session, builtTmpl.segment(), (long) template.length, hObj), "C_CreateObject");
                return hObj.get(JAVA_LONG, 0);
            } finally {
                zero(builtTmpl);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("createObject failed", t);
        }
    }

    /** C_GenerateKey (single secret key, not a keypair — e.g. CKM_AES_KEY_GEN). */
    long generateKey(long mechType, Attr[] tmpl) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment mech = mech(op, mechType);
            BuiltAttrs builtTmpl = attrs(op, tmpl);
            try {
                MemorySegment hKey = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cGenerateKey, session, mech, builtTmpl.segment(), (long) tmpl.length, hKey), "C_GenerateKey");
                return hKey.get(JAVA_LONG, 0);
            } finally {
                zero(builtTmpl);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("generateKey failed", t);
        }
    }

    // CK_GCM_PARAMS { CK_BYTE_PTR pIv; CK_ULONG ulIvLen; CK_ULONG ulIvBits;
    // CK_BYTE_PTR pAAD; CK_ULONG ulAADLen; CK_ULONG ulTagBits; }
    private static final MemoryLayout GCM_PARAMS =
        MemoryLayout.structLayout(ADDRESS, JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG);

    /**
     * CKM_AES_GCM mechanism. The IV is always supplied here as a plain
     * byte array — this class has no opinion on where it came from; the
     * caller (P11AESCipherSpi) is responsible for the L3 policy of
     * generating it via this same instance's generateRandom() (the
     * token's own SP 800-90A DRBG, C_GenerateRandom) rather than
     * java.security.SecureRandom, and for rejecting a caller-supplied
     * encryption IV per the plan's §4.3 GCM note. Using the traditional
     * C_EncryptInit/C_Encrypt path with a pre-generated IV is spec-equivalent
     * to the newer C_MessageEncryptInit/C_EncryptMessage in-module-IV-generation
     * API for SP 800-38D §8.2 purposes (same DRBG either way) and needs no
     * new native function family — confirmed by reading both code paths in
     * SoftHSM_cipher.cpp before choosing this design. Neither the IV nor
     * AAD is secret (both are public by GCM's own protocol design) — plain
     * MemorySegment, nothing tracked for zeroing.
     */
    MemorySegment mechGcm(Arena op, byte[] iv, byte[] aad, int tagBits) {
        MemorySegment params = op.allocate(GCM_PARAMS);
        params.set(ADDRESS, 0, bytes(op, iv));
        params.set(JAVA_LONG, 8, (long) iv.length);
        params.set(JAVA_LONG, 16, (long) iv.length * 8);
        params.set(ADDRESS, 24, aad.length > 0 ? bytes(op, aad) : MemorySegment.NULL);
        params.set(JAVA_LONG, 32, (long) aad.length);
        params.set(JAVA_LONG, 40, (long) tagBits);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_AES_GCM);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, GCM_PARAMS.byteSize());
        return m;
    }

    /** CKM_AES_CBC / CKM_AES_CBC_PAD — mechanism parameter is the raw 16-byte IV, no struct. IV is not secret. */
    MemorySegment mechCbc(Arena op, long mechType, byte[] iv) {
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, mechType);
        m.set(ADDRESS, 8, bytes(op, iv));
        m.set(JAVA_LONG, 16, (long) iv.length);
        return m;
    }

    // CK_AES_CTR_PARAMS { CK_ULONG ulCounterBits; CK_BYTE cb[16]; } — cb is
    // inline bytes within the struct, not a separate pointer target.
    private static final MemoryLayout CTR_PARAMS =
        MemoryLayout.structLayout(JAVA_LONG, MemoryLayout.sequenceLayout(16, JAVA_BYTE));

    /** CKM_AES_CTR with the full 128-bit counter block treated as the counter (ulCounterBits=128). Not secret. */
    MemorySegment mechCtr(Arena op, byte[] counterBlock) {
        MemorySegment params = op.allocate(CTR_PARAMS);
        params.set(JAVA_LONG, 0, 128L);
        MemorySegment.copy(counterBlock, 0, params, JAVA_BYTE, 8, 16);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_AES_CTR);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, CTR_PARAMS.byteSize());
        return m;
    }

    /** C_WrapKey — wraps a token key object (by handle) with another token key, two-call sizing. */
    byte[] wrapKey(long mechType, long wrappingKey, long keyToWrap) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment mech = mech(op, mechType);
            MemorySegment len = op.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cWrapKey, session, mech, wrappingKey, keyToWrap, MemorySegment.NULL, len),
                "C_WrapKey(size)");
            MemorySegment out = op.allocate(len.get(JAVA_LONG, 0));
            try {
                P11Error.check(invokeRv(cWrapKey, session, mech, wrappingKey, keyToWrap, out, len), "C_WrapKey");
                return toBytes(out, len.get(JAVA_LONG, 0));
            } finally {
                zero(out);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("wrapKey failed", t);
        }
    }

    /** C_UnwrapKey — returns a handle to the newly-imported (unwrapped) key object. */
    long unwrapKey(long mechType, long unwrappingKey, byte[] wrapped, Attr[] tmpl) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            MemorySegment mech = mech(op, mechType);
            MemorySegment w = bytes(op, wrapped);
            BuiltAttrs builtTmpl = attrs(op, tmpl);
            try {
                MemorySegment hKey = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cUnwrapKey, session, mech, unwrappingKey, w, (long) wrapped.length,
                    builtTmpl.segment(), (long) tmpl.length, hKey), "C_UnwrapKey");
                return hKey.get(JAVA_LONG, 0);
            } finally {
                zero(w);
                zero(builtTmpl);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("unwrapKey failed", t);
        }
    }

    /**
     * C_CopyObject — used by the KeyStore write path to promote a
     * session-scoped key object to a persistent token object (a
     * template entry of {@code CKA_TOKEN=true}) while simultaneously
     * setting its {@code CKA_LABEL} (the alias), confirmed by reading
     * SoftHSM_objects.cpp before writing this method: CKA_TOKEN is
     * exactly the one attribute C_CopyObject's own template loop
     * recognizes and overrides (session→token promotion is what this
     * call exists for — CKA_TOKEN is otherwise immutable post-creation,
     * unlike ordinary attributes C_SetAttributeValue can change).
     */
    long copyObject(long handle, Attr[] overrideTmpl) {
        ensureOpen();
        try (Arena op = Arena.ofConfined()) {
            BuiltAttrs builtTmpl = attrs(op, overrideTmpl);
            try {
                MemorySegment hNew = op.allocate(JAVA_LONG);
                P11Error.check(invokeRv(cCopyObject, session, handle, builtTmpl.segment(), (long) overrideTmpl.length, hNew), "C_CopyObject");
                return hNew.get(JAVA_LONG, 0);
            } finally {
                zero(builtTmpl);
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("copyObject failed", t);
        }
    }

    /** C_DestroyObject. */
    void destroyObject(long handle) {
        ensureOpen();
        try {
            P11Error.check(invokeRv(cDestroyObject, session, handle), "C_DestroyObject");
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("destroyObject failed", t);
        }
    }

    // ── Struct builders (shared with future W2+ SPIs via package access) ──

    private static BuiltAttrs attrs(Arena op, Attr[] template) {
        MemorySegment seg = op.allocate(ATTR_SIZE * Math.max(template.length, 1));
        MemorySegment[] values = new MemorySegment[template.length];
        for (int i = 0; i < template.length; i++) {
            MemorySegment val = bytes(op, template[i].value());
            values[i] = val;
            seg.set(JAVA_LONG, i * ATTR_SIZE, template[i].type());
            seg.set(ADDRESS, i * ATTR_SIZE + 8, val);
            seg.set(JAVA_LONG, i * ATTR_SIZE + 16, template[i].value().length);
        }
        return new BuiltAttrs(seg, values);
    }

    private static MemorySegment mech(Arena op, long type) {
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, type);
        m.set(ADDRESS, 8, MemorySegment.NULL);
        m.set(JAVA_LONG, 16, 0L);
        return m;
    }

    /**
     * CK_MECHANISM with a parameter block of N consecutive CK_ULONG
     * fields — covers CK_RSA_PKCS_PSS_PARAMS { hashAlg; mgf; sLen; }
     * (RSA-PSS, 3 fields) and any future PKCS#11 struct with the same
     * "all-ULONG" shape. A struct mixing ULONG and pointer/byte fields
     * (like CK_SP800_108_KDF_PARAMS's variable-length PRF-data array)
     * needs its own dedicated builder — deliberately not attempted here.
     * All-ULONG parameters carry no raw byte content — plain MemorySegment.
     */
    MemorySegment mechWithParams(Arena op, long type, long... params) {
        MemorySegment p = op.allocate(JAVA_LONG, params.length);
        for (int i = 0; i < params.length; i++) p.set(JAVA_LONG, i * 8L, params[i]);
        MemorySegment m = op.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, type);
        m.set(ADDRESS, 8, p);
        m.set(JAVA_LONG, 16, params.length * 8L);
        return m;
    }

    private static MemorySegment bytes(Arena op, byte[] b) {
        MemorySegment seg = op.allocate(Math.max(b.length, 1));
        MemorySegment.copy(b, 0, seg, JAVA_BYTE, 0, b.length);
        return seg;
    }

    static byte[] toBytes(MemorySegment seg, long len) {
        byte[] out = new byte[(int) len];
        MemorySegment.copy(seg, JAVA_BYTE, 0, out, 0, (int) len);
        return out;
    }

    private void ensureOpen() {
        if (closed) throw new ProviderException("P11Library is closed");
    }

    /**
     * Calls C_Initialize at most once per JVM process — see class javadoc.
     * The double-checked flag avoids the native call entirely on the
     * common path (second+ instance); CKR_CRYPTOKI_ALREADY_INITIALIZED is
     * additionally tolerated as a defense-in-depth fallback (e.g. a racing
     * thread that got past the flag check before it was set), since it
     * means exactly the state this method is trying to reach, not a
     * failure — every OTHER CK_RV still fails hard via P11Error.check.
     */
    private static synchronized void ensureGlobalInit(Linker linker, SymbolLookup lib) throws Throwable {
        if (globalInitDone) return;
        MethodHandle cInitialize = h(linker, lib, "C_Initialize", fd(ADDRESS));
        long rv = invokeRv(cInitialize, MemorySegment.NULL);
        if (rv != P11Error.CKR_OK && rv != 0x00000191L /* CKR_CRYPTOKI_ALREADY_INITIALIZED */) {
            P11Error.check(rv, "C_Initialize");
        }
        globalInitDone = true;
    }

    /**
     * C_GetInterface probe — verification only (see class javadoc): confirms
     * the loaded module negotiates PKCS#11 v3.2 before any function is
     * resolved by name. Returns major*10+minor (e.g. 32 for v3.2), or -1 if
     * the module doesn't export C_GetInterface at all.
     */
    private static int probeGetInterface(Linker linker, SymbolLookup lib) {
        var sym = lib.find("C_GetInterface");
        if (sym.isEmpty()) return -1;
        try {
            MethodHandle getIface = linker.downcallHandle(sym.get(), fd(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG));
            try (Arena probeArena = Arena.ofConfined()) {
                MemorySegment name = probeArena.allocateFrom("PKCS 11");
                MemorySegment version = probeArena.allocate(2);
                version.set(JAVA_BYTE, 0, (byte) 3);
                version.set(JAVA_BYTE, 1, (byte) 2);
                MemorySegment ppInterface = probeArena.allocate(ADDRESS);
                long rv = (long) getIface.invoke(name, version, ppInterface, 0L);
                if (rv != P11Error.CKR_OK) return -1;
                MemorySegment iface = ppInterface.get(ADDRESS, 0).reinterpret(24);
                MemorySegment functionList = iface.get(ADDRESS, 8).reinterpret(2);
                int major = functionList.get(JAVA_BYTE, 0) & 0xff;
                int minor = functionList.get(JAVA_BYTE, 1) & 0xff;
                return major * 10 + minor;
            }
        } catch (Throwable t) {
            return -1;
        }
    }

    private static MethodHandle h(Linker l, SymbolLookup lib, String name, FunctionDescriptor d) {
        return l.downcallHandle(lib.find(name)
            .orElseThrow(() -> new ProviderException(name + " not exported by PKCS#11 module")), d);
    }

    private static FunctionDescriptor fd(MemoryLayout... args) {
        return FunctionDescriptor.of(JAVA_LONG, args);
    }

    private static long invokeRv(MethodHandle h, Object... args) throws Throwable {
        return (long) h.invokeWithArguments(args);
    }

    // Serializes every native C_CloseSession call across EVERY P11Library
    // instance in this JVM process — found necessary live, not added
    // speculatively: the JVM shutdown hook SoftHSMv3Provider registers
    // (§6.5) is one independent Thread per constructed provider instance,
    // and the JVM runs all registered shutdown hooks concurrently. A test
    // suite that constructs 100+ providers (this one does) therefore fires
    // that many threads all calling C_CloseSession on their own distinct
    // session at once on exit — and that concurrent pattern crashed the
    // JVM outright with a native SIGSEGV inside libsofthsmv3.so's session
    // teardown (std::_Rb_tree_increment, i.e. an internal std::map
    // iteration corrupted by concurrent access), reproduced live during
    // plan §WS-B. HandleManager/SessionManager/SessionObjectStore all have
    // their own per-instance mutexes already (checked before concluding
    // this was the right fix, not assumed) — whether the deeper cause is
    // some other unprotected shared state or a genuine engine gap wasn't
    // chased further, since eliminating the concurrent-call pattern from
    // the Java side is squarely this class's own responsibility (it chose
    // to spawn N independent threads) and is sufficient regardless of the
    // engine-side root cause. A single JVM-wide lock is fine here: close()
    // is a rare, teardown-only operation, never a hot path.
    private static final Object CLOSE_LOCK = new Object();

    @Override
    public void close() {
        if (closed) return;
        synchronized (CLOSE_LOCK) {
            if (closed) return;
            closed = true;
            try {
                invokeRv(cCloseSession, session);
                // C_Logout and C_Finalize are deliberately NOT called here:
                // both are token-/process-wide state (spec §5.6.1 — login
                // applies to every session on the token, not just this one),
                // and this instance cannot know whether another live
                // P11Library instance on the same token still needs to be
                // logged in. Only C_CloseSession is genuinely scoped to this
                // instance's own session and safe to call unilaterally.
            } catch (Throwable ignored) {
                // best-effort teardown
            } finally {
                arena.close();
            }
        }
    }
}
