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

    // Process-global C_Initialize guard — see class javadoc. Synchronized
    // on the class object; construction only happens on the (rare, non-hot)
    // provider/session-setup path, so contention is not a concern.
    private static volatile boolean globalInitDone = false;

    private final Arena arena;
    private final MethodHandle cGetSlotList, cOpenSession, cLogin,
        // cLogout: bound but deliberately unused in this class — see
        // close()'s comment. Reserved for W2's P11SessionPool, which will
        // own a real reference-counted "logout only when the last session
        // on this token closes" policy instead of an individual
        // P11Library instance guessing at other instances' state.
        cLogout, cCloseSession, cDigestInit, cDigestUpdate, cDigestFinal,
        cGenerateRandom, cSeedRandom, cGenerateKeyPair, cSignInit, cSign,
        cVerifyInit, cVerify, cGetAttributeValue;
    private final long session;
    private volatile boolean closed;

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

            ensureGlobalInit(linker, lib);

            MemorySegment count = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cGetSlotList, (byte) 1, MemorySegment.NULL, count), "C_GetSlotList(size)");
            long n = count.get(JAVA_LONG, 0);
            if (n == 0) throw new ProviderException("no PKCS#11 slots with a token present");
            MemorySegment slots = arena.allocate(JAVA_LONG, n);
            P11Error.check(invokeRv(cGetSlotList, (byte) 1, slots, count), "C_GetSlotList");
            long slot = slots.get(JAVA_LONG, 0);

            MemorySegment hSession = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cOpenSession, slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                MemorySegment.NULL, MemorySegment.NULL, hSession), "C_OpenSession");
            session = hSession.get(JAVA_LONG, 0);

            byte[] pinBytes = pin.getBytes(StandardCharsets.UTF_8);
            MemorySegment pinSeg = arena.allocate(Math.max(pinBytes.length, 1));
            MemorySegment.copy(pinBytes, 0, pinSeg, JAVA_BYTE, 0, pinBytes.length);
            long loginRv = invokeRv(cLogin, session, CKU_USER, pinSeg, (long) pinBytes.length);
            // CKR_USER_ALREADY_LOGGED_IN is not an error here: PKCS#11 login
            // state is per-TOKEN, not per-session (spec §5.6.1) — a prior
            // session on this same slot (e.g. an earlier P11Library
            // instance in this process) already authenticated, and that
            // covers every session on the token, including this new one.
            // Same class of bug as C_Initialize above, caught the same way
            // (live `mvn test` with 2+ instances) — every OTHER CK_RV still
            // fails hard via P11Error.check.
            if (loginRv != P11Error.CKR_OK && loginRv != 0x00000100L /* CKR_USER_ALREADY_LOGGED_IN */) {
                P11Error.check(loginRv, "C_Login");
            }
        } catch (ProviderException e) {
            arena.close();
            throw e;
        } catch (Throwable t) {
            arena.close();
            throw new ProviderException("PKCS#11 module init failed for " + modulePath, t);
        }
    }

    /** C_DigestInit/Update/Final, single call. */
    byte[] digest(long mechType, byte[] data) {
        ensureOpen();
        try {
            MemorySegment mech = mech(mechType);
            P11Error.check(invokeRv(cDigestInit, session, mech), "C_DigestInit");
            MemorySegment in = bytes(data);
            P11Error.check(invokeRv(cDigestUpdate, session, in, (long) data.length), "C_DigestUpdate");
            MemorySegment len = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cDigestFinal, session, MemorySegment.NULL, len), "C_DigestFinal(size)");
            MemorySegment out = arena.allocate(len.get(JAVA_LONG, 0));
            P11Error.check(invokeRv(cDigestFinal, session, out, len), "C_DigestFinal");
            return toBytes(out, len.get(JAVA_LONG, 0));
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("digest failed", t);
        }
    }

    /** C_GenerateRandom — SP 800-90A DRBG inside the token, never JVM software randomness. */
    byte[] generateRandom(int len) {
        ensureOpen();
        try {
            MemorySegment out = arena.allocate(Math.max(len, 1));
            P11Error.check(invokeRv(cGenerateRandom, session, out, (long) len), "C_GenerateRandom");
            return toBytes(out, len);
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("generateRandom failed", t);
        }
    }

    /** C_SeedRandom. */
    void seedRandom(byte[] seed) {
        ensureOpen();
        try {
            P11Error.check(invokeRv(cSeedRandom, session, bytes(seed), (long) seed.length), "C_SeedRandom");
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("seedRandom failed", t);
        }
    }

    /** C_GenerateKeyPair; returns { publicHandle, privateHandle }. */
    long[] generateKeyPair(long mechType, Attr[] pubTmpl, Attr[] prvTmpl) {
        ensureOpen();
        try {
            MemorySegment mech = mech(mechType);
            MemorySegment pub = attrs(pubTmpl);
            MemorySegment prv = attrs(prvTmpl);
            MemorySegment hPub = arena.allocate(JAVA_LONG);
            MemorySegment hPrv = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cGenerateKeyPair, session, mech, pub, (long) pubTmpl.length,
                prv, (long) prvTmpl.length, hPub, hPrv), "C_GenerateKeyPair");
            return new long[]{ hPub.get(JAVA_LONG, 0), hPrv.get(JAVA_LONG, 0) };
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("generateKeyPair failed", t);
        }
    }

    /** C_SignInit + C_Sign (single-part), two-call sizing. */
    byte[] sign(long mechType, long key, byte[] data) {
        ensureOpen();
        try {
            MemorySegment mech = mech(mechType);
            P11Error.check(invokeRv(cSignInit, session, mech, key), "C_SignInit");
            MemorySegment msg = bytes(data);
            MemorySegment len = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cSign, session, msg, (long) data.length, MemorySegment.NULL, len), "C_Sign(size)");
            MemorySegment sig = arena.allocate(len.get(JAVA_LONG, 0));
            P11Error.check(invokeRv(cSign, session, msg, (long) data.length, sig, len), "C_Sign");
            return toBytes(sig, len.get(JAVA_LONG, 0));
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("sign failed", t);
        }
    }

    /** C_VerifyInit + C_Verify (single-part). Returns false (not an exception) on CKR_SIGNATURE_INVALID. */
    boolean verify(long mechType, long key, byte[] data, byte[] signature) {
        ensureOpen();
        try {
            MemorySegment mech = mech(mechType);
            P11Error.check(invokeRv(cVerifyInit, session, mech, key), "C_VerifyInit");
            long rv = invokeRv(cVerify, session, bytes(data), (long) data.length,
                bytes(signature), (long) signature.length);
            if (rv == P11Error.CKR_OK) return true;
            if (rv == 0x000000c0L /* CKR_SIGNATURE_INVALID */) return false;
            P11Error.check(rv, "C_Verify");
            return false; // unreachable — check() throws for any other non-OK rv
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("verify failed", t);
        }
    }

    /** C_GetAttributeValue, two-call sizing — for public-key export (SubjectPublicKeyInfo assembly). */
    byte[] getAttributeBytes(long object, long attrType) {
        ensureOpen();
        try {
            MemorySegment a = arena.allocate(ATTRIBUTE);
            a.set(JAVA_LONG, 0, attrType);
            a.set(ADDRESS, 8, MemorySegment.NULL);
            a.set(JAVA_LONG, 16, 0L);
            P11Error.check(invokeRv(cGetAttributeValue, session, object, a, 1L), "C_GetAttributeValue(size)");
            long len = a.get(JAVA_LONG, 16);
            MemorySegment buf = arena.allocate(Math.max(len, 1));
            a.set(ADDRESS, 8, buf);
            P11Error.check(invokeRv(cGetAttributeValue, session, object, a, 1L), "C_GetAttributeValue");
            return toBytes(buf, len);
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("getAttributeBytes failed", t);
        }
    }

    // ── Struct builders (shared with future W2+ SPIs via package access) ──

    private MemorySegment attrs(Attr[] template) {
        MemorySegment seg = arena.allocate(ATTR_SIZE * Math.max(template.length, 1));
        for (int i = 0; i < template.length; i++) {
            MemorySegment val = bytes(template[i].value());
            seg.set(JAVA_LONG, i * ATTR_SIZE, template[i].type());
            seg.set(ADDRESS, i * ATTR_SIZE + 8, val);
            seg.set(JAVA_LONG, i * ATTR_SIZE + 16, template[i].value().length);
        }
        return seg;
    }

    MemorySegment mech(long type) {
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, type);
        m.set(ADDRESS, 8, MemorySegment.NULL);
        m.set(JAVA_LONG, 16, 0L);
        return m;
    }

    MemorySegment bytes(byte[] b) {
        MemorySegment seg = arena.allocate(Math.max(b.length, 1));
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

    @Override
    public void close() {
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
