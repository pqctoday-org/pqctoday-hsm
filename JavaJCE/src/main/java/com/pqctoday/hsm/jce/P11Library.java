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
        cVerifyInit, cVerify, cGetAttributeValue, cCreateObject,
        cFindObjectsInit, cFindObjects, cFindObjectsFinal,
        cEncapsulateKey, cDecapsulateKey, cDeriveKey,
        cEncryptInit, cEncrypt, cDecryptInit, cDecrypt,
        cGenerateKey, cWrapKey, cUnwrapKey;
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
        return sign(mech(mechType), key, data);
    }

    /** Same as sign(long, long, byte[]) but with a caller-built CK_MECHANISM (e.g. RSA-PSS's parameter block). */
    byte[] sign(MemorySegment mech, long key, byte[] data) {
        ensureOpen();
        try {
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
        return verify(mech(mechType), key, data, signature);
    }

    /** Same as verify(long, long, byte[], byte[]) but with a caller-built CK_MECHANISM. */
    boolean verify(MemorySegment mech, long key, byte[] data, byte[] signature) {
        ensureOpen();
        try {
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
        try {
            MemorySegment tmpl = attrs(template);
            P11Error.check(invokeRv(cFindObjectsInit, session, tmpl, (long) template.length), "C_FindObjectsInit");
            try {
                int batch = 256;
                java.util.List<Long> out = new java.util.ArrayList<>();
                MemorySegment handles = arena.allocate(JAVA_LONG, batch);
                MemorySegment count = arena.allocate(JAVA_LONG);
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
        try {
            MemorySegment mech = mech(mechType);
            MemorySegment tmpl = attrs(ssTmpl);
            MemorySegment ctLen = arena.allocate(JAVA_LONG);
            MemorySegment hSs = arena.allocate(JAVA_LONG);
            long rv = invokeRv(cEncapsulateKey, session, mech, publicKey,
                tmpl, (long) ssTmpl.length, MemorySegment.NULL, ctLen, hSs);
            if (rv != P11Error.CKR_OK && rv != 0x00000150L /* CKR_BUFFER_TOO_SMALL */) {
                P11Error.check(rv, "C_EncapsulateKey(size)");
            }
            MemorySegment ct = arena.allocate(ctLen.get(JAVA_LONG, 0));
            P11Error.check(invokeRv(cEncapsulateKey, session, mech, publicKey,
                tmpl, (long) ssTmpl.length, ct, ctLen, hSs), "C_EncapsulateKey");
            return new Encapsulated(toBytes(ct, ctLen.get(JAVA_LONG, 0)), hSs.get(JAVA_LONG, 0));
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("encapsulate failed", t);
        }
    }

    /** C_DecapsulateKey; returns a handle to the (opaque) derived shared-secret object. */
    long decapsulate(long mechType, long privateKey, Attr[] ssTmpl, byte[] ciphertext) {
        ensureOpen();
        try {
            MemorySegment mech = mech(mechType);
            MemorySegment hSs = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cDecapsulateKey, session, mech, privateKey,
                attrs(ssTmpl), (long) ssTmpl.length, bytes(ciphertext), (long) ciphertext.length, hSs),
                "C_DecapsulateKey");
            return hSs.get(JAVA_LONG, 0);
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
        try {
            MemorySegment pubData = bytes(peerPublicPointRaw);
            MemorySegment params = arena.allocate(ECDH1_DERIVE_PARAMS);
            params.set(JAVA_LONG, 0, 1L); // CKD_NULL (pkcs11t.h: 0x00000001)
            params.set(JAVA_LONG, 8, 0L); // ulSharedDataLen
            params.set(ADDRESS, 16, MemorySegment.NULL); // pSharedData
            params.set(JAVA_LONG, 24, (long) peerPublicPointRaw.length);
            params.set(ADDRESS, 32, pubData);

            MemorySegment mech = arena.allocate(MECHANISM);
            mech.set(JAVA_LONG, 0, P11Constants.CKM_ECDH1_DERIVE);
            mech.set(ADDRESS, 8, params);
            mech.set(JAVA_LONG, 16, ECDH1_DERIVE_PARAMS.byteSize());

            MemorySegment tmpl = attrs(ssTmpl);
            MemorySegment hKey = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cDeriveKey, session, mech, basePrivateKey,
                tmpl, (long) ssTmpl.length, hKey), "C_DeriveKey");
            return hKey.get(JAVA_LONG, 0);
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

    /** CKM_RSA_PKCS_OAEP with no label (CKZ_DATA_SPECIFIED, empty source — the common case). */
    MemorySegment mechOaep(long hashAlg, long mgf) {
        MemorySegment params = arena.allocate(OAEP_PARAMS);
        params.set(JAVA_LONG, 0, hashAlg);
        params.set(JAVA_LONG, 8, mgf);
        params.set(JAVA_LONG, 16, 1L); // CKZ_DATA_SPECIFIED
        params.set(ADDRESS, 24, MemorySegment.NULL);
        params.set(JAVA_LONG, 32, 0L);
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_RSA_PKCS_OAEP);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, OAEP_PARAMS.byteSize());
        return m;
    }

    /** C_EncryptInit + C_Encrypt (single-part), two-call sizing. */
    byte[] encrypt(MemorySegment mech, long key, byte[] plaintext) {
        ensureOpen();
        try {
            P11Error.check(invokeRv(cEncryptInit, session, mech, key), "C_EncryptInit");
            MemorySegment in = bytes(plaintext);
            MemorySegment len = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cEncrypt, session, in, (long) plaintext.length, MemorySegment.NULL, len), "C_Encrypt(size)");
            MemorySegment out = arena.allocate(len.get(JAVA_LONG, 0));
            P11Error.check(invokeRv(cEncrypt, session, in, (long) plaintext.length, out, len), "C_Encrypt");
            return toBytes(out, len.get(JAVA_LONG, 0));
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("encrypt failed", t);
        }
    }

    /** C_DecryptInit + C_Decrypt (single-part), two-call sizing. */
    byte[] decrypt(MemorySegment mech, long key, byte[] ciphertext) {
        ensureOpen();
        try {
            P11Error.check(invokeRv(cDecryptInit, session, mech, key), "C_DecryptInit");
            MemorySegment in = bytes(ciphertext);
            MemorySegment len = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cDecrypt, session, in, (long) ciphertext.length, MemorySegment.NULL, len), "C_Decrypt(size)");
            MemorySegment out = arena.allocate(len.get(JAVA_LONG, 0));
            P11Error.check(invokeRv(cDecrypt, session, in, (long) ciphertext.length, out, len), "C_Decrypt");
            return toBytes(out, len.get(JAVA_LONG, 0));
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

    /**
     * CKM_HKDF_DERIVE mechanism. Salt is always passed as raw bytes
     * (CKF_HKDF_SALT_DATA) or omitted (CKF_HKDF_SALT_NULL) — confirmed by
     * reading SoftHSM_keygen.cpp before writing this method that the
     * engine explicitly rejects CKF_HKDF_SALT_KEY
     * ("CKM_HKDF_DERIVE: CKF_HKDF_SALT_KEY not supported"), so a salt
     * that is one of this provider's own opaque (non-extractable) keys
     * can never be used here — P11HKDFKDFSpi rejects that case with a
     * clear error rather than silently degrading. Also confirmed live in
     * that same code path that CKA_VALUE_LEN is REQUIRED in the derive
     * template regardless of mode, including extract-only (where RFC
     * 5869 fixes the PRK length at the hash's output size) — the caller
     * must compute and supply that length explicitly, the engine will
     * not infer it.
     */
    MemorySegment mechHkdf(long prfHashMech, boolean extract, boolean expand, byte[] salt, byte[] info) {
        MemorySegment params = arena.allocate(HKDF_PARAMS);
        params.set(JAVA_BYTE, 0, (byte) (extract ? 1 : 0));
        params.set(JAVA_BYTE, 1, (byte) (expand ? 1 : 0));
        params.set(JAVA_LONG, 8, prfHashMech);
        params.set(JAVA_LONG, 16, salt.length > 0 ? CKF_HKDF_SALT_DATA : CKF_HKDF_SALT_NULL);
        params.set(ADDRESS, 24, salt.length > 0 ? bytes(salt) : MemorySegment.NULL);
        params.set(JAVA_LONG, 32, (long) salt.length);
        params.set(JAVA_LONG, 40, 0L); // hSaltKey — always unused, see javadoc above
        params.set(ADDRESS, 48, info.length > 0 ? bytes(info) : MemorySegment.NULL);
        params.set(JAVA_LONG, 56, (long) info.length);
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_HKDF_DERIVE);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, HKDF_PARAMS.byteSize());
        return m;
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

    /** CKM_PKCS5_PBKD2 (SP 800-132). Salt is always CKZ_SALT_SPECIFIED (raw bytes) — the only source type this engine supports. */
    MemorySegment mechPbkdf2(long prf, byte[] salt, long iterations, byte[] password) {
        MemorySegment params = arena.allocate(PBKDF2_PARAMS);
        params.set(JAVA_LONG, 0, P11Constants.CKZ_SALT_SPECIFIED);
        params.set(ADDRESS, 8, bytes(salt));
        params.set(JAVA_LONG, 16, (long) salt.length);
        params.set(JAVA_LONG, 24, iterations);
        params.set(JAVA_LONG, 32, prf);
        params.set(ADDRESS, 40, MemorySegment.NULL); // pPrfData — unused for the HMAC PRF family
        params.set(JAVA_LONG, 48, 0L);
        params.set(ADDRESS, 56, bytes(password));
        params.set(JAVA_LONG, 64, (long) password.length);
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_PKCS5_PBKD2);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, PBKDF2_PARAMS.byteSize());
        return m;
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
    long deriveKeyNoBase(MemorySegment mech, Attr[] outputTmpl) {
        return deriveKey(mech, 0L, outputTmpl);
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
    private MemorySegment prfDataParams(byte[] fixedInput) {
        if (fixedInput.length == 0) return MemorySegment.NULL;
        MemorySegment seg = arena.allocate(PRF_DATA_PARAM_SIZE);
        seg.set(JAVA_LONG, 0, P11Constants.CK_SP800_108_BYTE_ARRAY);
        seg.set(ADDRESS, 8, bytes(fixedInput));
        seg.set(JAVA_LONG, 16, (long) fixedInput.length);
        return seg;
    }

    /** CKM_SP800_108_COUNTER_KDF (SP 800-108 §5.1). prfType must be a CKM_SHA*_HMAC constant or CKM_AES_CMAC. */
    MemorySegment mechSp800108Counter(long prfType, byte[] fixedInput) {
        MemorySegment params = arena.allocate(SP800_108_COUNTER_PARAMS);
        params.set(JAVA_LONG, 0, prfType);
        params.set(JAVA_LONG, 8, fixedInput.length == 0 ? 0L : 1L);
        params.set(ADDRESS, 16, prfDataParams(fixedInput));
        params.set(JAVA_LONG, 24, 0L); // ulAdditionalDerivedKeys — not supported here
        params.set(ADDRESS, 32, MemorySegment.NULL);
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_SP800_108_COUNTER_KDF);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, SP800_108_COUNTER_PARAMS.byteSize());
        return m;
    }

    /** CKM_SP800_108_FEEDBACK_KDF (SP 800-108 §5.2). iv may be empty (no seed supplied — engine default applies). */
    MemorySegment mechSp800108Feedback(long prfType, byte[] fixedInput, byte[] iv) {
        MemorySegment params = arena.allocate(SP800_108_FEEDBACK_PARAMS);
        params.set(JAVA_LONG, 0, prfType);
        params.set(JAVA_LONG, 8, fixedInput.length == 0 ? 0L : 1L);
        params.set(ADDRESS, 16, prfDataParams(fixedInput));
        params.set(JAVA_LONG, 24, (long) iv.length);
        params.set(ADDRESS, 32, iv.length == 0 ? MemorySegment.NULL : bytes(iv));
        params.set(JAVA_LONG, 40, 0L); // ulAdditionalDerivedKeys — not supported here
        params.set(ADDRESS, 48, MemorySegment.NULL);
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_SP800_108_FEEDBACK_KDF);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, SP800_108_FEEDBACK_PARAMS.byteSize());
        return m;
    }

    /** C_DeriveKey with a caller-built CK_MECHANISM (HKDF; ECDH has its own ecdh1Derive convenience above). */
    long deriveKey(MemorySegment mech, long baseKey, Attr[] outputTmpl) {
        ensureOpen();
        try {
            MemorySegment tmpl = attrs(outputTmpl);
            MemorySegment hKey = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cDeriveKey, session, mech, baseKey,
                tmpl, (long) outputTmpl.length, hKey), "C_DeriveKey");
            return hKey.get(JAVA_LONG, 0);
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("deriveKey failed", t);
        }
    }

    /** C_CreateObject — imports a caller-supplied key onto the token (public keys only; see KeyFactory import). */
    long createObject(Attr[] template) {
        ensureOpen();
        try {
            MemorySegment tmpl = attrs(template);
            MemorySegment hObj = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cCreateObject, session, tmpl, (long) template.length, hObj), "C_CreateObject");
            return hObj.get(JAVA_LONG, 0);
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("createObject failed", t);
        }
    }

    /** C_GenerateKey (single secret key, not a keypair — e.g. CKM_AES_KEY_GEN). */
    long generateKey(long mechType, Attr[] tmpl) {
        ensureOpen();
        try {
            MemorySegment mech = mech(mechType);
            MemorySegment t = attrs(tmpl);
            MemorySegment hKey = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cGenerateKey, session, mech, t, (long) tmpl.length, hKey), "C_GenerateKey");
            return hKey.get(JAVA_LONG, 0);
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
     * SoftHSM_cipher.cpp before choosing this design.
     */
    MemorySegment mechGcm(byte[] iv, byte[] aad, int tagBits) {
        MemorySegment params = arena.allocate(GCM_PARAMS);
        params.set(ADDRESS, 0, bytes(iv));
        params.set(JAVA_LONG, 8, (long) iv.length);
        params.set(JAVA_LONG, 16, (long) iv.length * 8);
        params.set(ADDRESS, 24, aad.length > 0 ? bytes(aad) : MemorySegment.NULL);
        params.set(JAVA_LONG, 32, (long) aad.length);
        params.set(JAVA_LONG, 40, (long) tagBits);
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_AES_GCM);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, GCM_PARAMS.byteSize());
        return m;
    }

    /** CKM_AES_CBC / CKM_AES_CBC_PAD — mechanism parameter is the raw 16-byte IV, no struct. */
    MemorySegment mechCbc(long mechType, byte[] iv) {
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, mechType);
        m.set(ADDRESS, 8, bytes(iv));
        m.set(JAVA_LONG, 16, (long) iv.length);
        return m;
    }

    // CK_AES_CTR_PARAMS { CK_ULONG ulCounterBits; CK_BYTE cb[16]; } — cb is
    // inline bytes within the struct, not a separate pointer target.
    private static final MemoryLayout CTR_PARAMS =
        MemoryLayout.structLayout(JAVA_LONG, MemoryLayout.sequenceLayout(16, JAVA_BYTE));

    /** CKM_AES_CTR with the full 128-bit counter block treated as the counter (ulCounterBits=128). */
    MemorySegment mechCtr(byte[] counterBlock) {
        MemorySegment params = arena.allocate(CTR_PARAMS);
        params.set(JAVA_LONG, 0, 128L);
        MemorySegment.copy(counterBlock, 0, params, JAVA_BYTE, 8, 16);
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, P11Constants.CKM_AES_CTR);
        m.set(ADDRESS, 8, params);
        m.set(JAVA_LONG, 16, CTR_PARAMS.byteSize());
        return m;
    }

    /** C_WrapKey — wraps a token key object (by handle) with another token key, two-call sizing. */
    byte[] wrapKey(long mechType, long wrappingKey, long keyToWrap) {
        ensureOpen();
        try {
            MemorySegment mech = mech(mechType);
            MemorySegment len = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cWrapKey, session, mech, wrappingKey, keyToWrap, MemorySegment.NULL, len),
                "C_WrapKey(size)");
            MemorySegment out = arena.allocate(len.get(JAVA_LONG, 0));
            P11Error.check(invokeRv(cWrapKey, session, mech, wrappingKey, keyToWrap, out, len), "C_WrapKey");
            return toBytes(out, len.get(JAVA_LONG, 0));
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("wrapKey failed", t);
        }
    }

    /** C_UnwrapKey — returns a handle to the newly-imported (unwrapped) key object. */
    long unwrapKey(long mechType, long unwrappingKey, byte[] wrapped, Attr[] tmpl) {
        ensureOpen();
        try {
            MemorySegment mech = mech(mechType);
            MemorySegment w = bytes(wrapped);
            MemorySegment t = attrs(tmpl);
            MemorySegment hKey = arena.allocate(JAVA_LONG);
            P11Error.check(invokeRv(cUnwrapKey, session, mech, unwrappingKey, w, (long) wrapped.length,
                t, (long) tmpl.length, hKey), "C_UnwrapKey");
            return hKey.get(JAVA_LONG, 0);
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException("unwrapKey failed", t);
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

    /**
     * CK_MECHANISM with a parameter block of N consecutive CK_ULONG
     * fields — covers CK_RSA_PKCS_PSS_PARAMS { hashAlg; mgf; sLen; }
     * (RSA-PSS, 3 fields) and any future PKCS#11 struct with the same
     * "all-ULONG" shape. A struct mixing ULONG and pointer/byte fields
     * (like CK_SP800_108_KDF_PARAMS's variable-length PRF-data array)
     * needs its own dedicated builder — deliberately not attempted here.
     */
    MemorySegment mechWithParams(long type, long... params) {
        MemorySegment p = arena.allocate(JAVA_LONG, params.length);
        for (int i = 0; i < params.length; i++) p.set(JAVA_LONG, i * 8L, params[i]);
        MemorySegment m = arena.allocate(MECHANISM);
        m.set(JAVA_LONG, 0, type);
        m.set(ADDRESS, 8, p);
        m.set(JAVA_LONG, 16, params.length * 8L);
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
