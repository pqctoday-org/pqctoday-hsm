package com.pqctoday.hsm.jce;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * HKDF-SHA256/384/512 via the new javax.crypto.KDF/KDFSpi API (JEP 478,
 * finalized on JDK 27 — see the pom.xml comment for why this module's
 * compiler baseline moved from 24 to 27 for exactly this class).
 * Interface shape (KDFSpi/KDFParameters/HKDFParameterSpec.Extract/Expand/
 * ExtractThenExpand) confirmed via javap against the real JDK before
 * writing this, same discipline as every other JDK interface this
 * module implements.
 *
 * Single-salt only — a real constraint of the underlying engine,
 * confirmed by reading SoftHSM_keygen.cpp before writing any code:
 * PKCS#11's CK_HKDF_DERIVE operates on exactly one base key handle
 * (C_DeriveKey's hBaseKey) and one salt. salts() with more than one
 * element is rejected with a clear InvalidAlgorithmParameterException,
 * rather than guessing at a concatenation policy with no normative
 * reference for salts specifically.
 *
 * Multiple IKMs ARE supported, added for plan §W6's real, live need
 * (JEP 527 hybrid TLS 1.3's key schedule hands this class exactly two:
 * the classical ECDH-as-KEM secret and the PQ KEM secret) — see
 * {@link #handleOfConsolidated}'s javadoc for how, and for the real JDK
 * source confirming that simple concatenation (not some engine-specific
 * multi-key primitive) is the actual, correct semantics JDK's own
 * reference HKDF gives a multi-element ikms() list. This was NOT
 * originally supported — an earlier version of this class rejected
 * anything but exactly one IKM outright — and was extended only once
 * §W6's live spike proved it was genuinely needed, not spent on
 * speculatively ahead of any real caller.
 *
 * A salt key is either one of this provider's own token-resident keys
 * (opaque or not — used by handle via CKF_HKDF_SALT_KEY, engine support
 * added 2026-08-25, plan §WS-A) or a foreign key with real encoded bytes
 * (used via CKF_HKDF_SALT_DATA) — see {@link #saltMechFor}. Before the
 * engine change, an opaque salt was rejected outright; that limitation
 * is what plan §W6's live TLS spike hit directly (JEP 527 hybrid TLS
 * 1.3's key schedule needs to chain a previous opaque derived secret
 * back in as the next Extract step's salt).
 *
 * {@code -Dsofthsmv3.jce.extractableHkdf=true} (default off, NON-FIPS):
 * makes {@link #engineDeriveKey}'s output a plain extractable
 * {@code SecretKeySpec} instead of an opaque {@link P11Key.Secret} —
 * the fallback plan §WS-A decided on for a deployment running an engine
 * build that predates the CKF_HKDF_SALT_KEY addition above: with an
 * extractable output, {@link #saltMechFor}'s own logic naturally falls
 * through to the plain-bytes CKF_HKDF_SALT_DATA path (already worked
 * against every engine build, old or new) when that key is later used
 * as a salt, rather than needing the new handle-based path at all. This
 * is a real, disclosed narrowing of this provider's opaque-key
 * guarantee for every {@code engineDeriveKey} caller while the flag is
 * set, not a scoped-down exception the way the KEM/ECDH secrets are —
 * flagged loudly via {@link P11Debug} every time it actually changes
 * behavior, not silently.
 */
final class P11HKDFKDFSpi extends KDFSpi {
    // Deliberately NOT a cached `static final boolean` read once at class
    // init: a caller (including this module's own tests) may reasonably
    // toggle this property at runtime, and a one-time-cached read would
    // silently stop honoring later changes the instant this class first
    // loads — read fresh on every call instead.
    private static boolean extractableHkdfFallback() {
        return Boolean.getBoolean("softhsmv3.jce.extractableHkdf");
    }

    private final P11Library lib;
    private final long prfHashMech;
    private final int hashOutputBytes;

    P11HKDFKDFSpi(P11Library lib, long prfHashMech, int hashOutputBytes, KDFParameters params)
            throws InvalidAlgorithmParameterException {
        super(params);
        if (params != null) {
            throw new InvalidAlgorithmParameterException("this KDF takes no KDFParameters");
        }
        this.lib = lib;
        this.prfHashMech = prfHashMech;
        this.hashOutputBytes = hashOutputBytes;
    }

    @Override
    protected KDFParameters engineGetParameters() {
        return null;
    }

    @Override
    protected SecretKey engineDeriveKey(String alg, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        if (extractableHkdfFallback()) {
            P11Debug.log("HKDF engineDeriveKey(" + alg + ") — softhsmv3.jce.extractableHkdf=true, "
                + "returning a NON-OPAQUE SecretKeySpec (non-FIPS fallback, see P11HKDFKDFSpi's javadoc)");
            long handle = derive(spec, true);
            byte[] raw = lib.getAttributeBytes(handle, CKA_VALUE);
            return new javax.crypto.spec.SecretKeySpec(raw, alg);
        }
        if ("AES".equalsIgnoreCase(alg)) {
            return deriveAndReimportAsAes(spec);
        }
        long handle = derive(spec, false);
        return new P11Key.Secret(lib, handle, alg);
    }

    /**
     * The engine's {@code CKM_HKDF_DERIVE} unconditionally produces a
     * {@code CKK_GENERIC_SECRET} object — confirmed reading
     * {@code SoftHSM_keygen.cpp}'s HKDF output-template code, which
     * explicitly discards any caller-supplied {@code CKA_CLASS}/
     * {@code CKA_KEY_TYPE} from the template (a {@code switch} case
     * whose only action is {@code continue}) and hardcodes
     * {@code CKK_GENERIC_SECRET} instead — which this provider's own
     * {@code AES/GCM} Cipher then correctly refuses with
     * {@code CKR_KEY_TYPE_INCONSISTENT} at {@code C_EncryptInit}. Found
     * live via plan §WS-B's TLS spike: JDK 27's own
     * {@code SSLTrafficKeyDerivation} requests exactly {@code "AES"} for
     * the record cipher's traffic key
     * ({@code cs.bulkCipher.algorithm}, confirmed from real JDK source),
     * so this case is a genuine, real caller, not a hypothetical.
     *
     * Bridged the same way this module already imports foreign raw AES
     * keys ({@code P11AESWrapCipherSpi}'s unwrap path,
     * {@code importRawAesKeyReal} in the test suite): derive
     * EXTRACTABLE, read the raw bytes back, re-import as a genuine
     * {@code CKK_AES} object, then destroy the throwaway generic-secret
     * and zero the Java-side intermediate copy (§6.5). A real, disclosed,
     * narrow exception to this KDF's opaque-by-default output — the same
     * class of exception already accepted for the KEM/ECDH secrets: the
     * whole point of a TLS traffic key is to be consumed by this
     * provider's own Cipher, which cannot do that with a
     * {@code CKK_GENERIC_SECRET} object no matter what Java-level
     * algorithm label is attached to it.
     */
    private SecretKey deriveAndReimportAsAes(AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        long genericHandle = derive(spec, true);
        byte[] raw = lib.getAttributeBytes(genericHandle, CKA_VALUE);
        lib.destroyObject(genericHandle);
        try {
            P11Library.Attr[] tmpl = {
                P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
                P11Library.attrLong(CKA_KEY_TYPE, CKK_AES),
                P11Library.attr(CKA_VALUE, raw),
                P11Library.attrBool(CKA_TOKEN, false),
                P11Library.attrBool(CKA_SENSITIVE, true),
                P11Library.attrBool(CKA_EXTRACTABLE, false),
                P11Library.attrBool(CKA_ENCRYPT, true),
                P11Library.attrBool(CKA_DECRYPT, true),
            };
            long aesHandle = lib.createObject(tmpl);
            return new P11Key.Secret(lib, aesHandle, "AES");
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
    }

    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
        long handle;
        try {
            handle = derive(spec, true);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }
        return lib.getAttributeBytes(handle, CKA_VALUE);
    }

    private long derive(AlgorithmParameterSpec spec, boolean extractable)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        boolean extract;
        boolean expand;
        List<SecretKey> ikms;
        List<SecretKey> salts;
        byte[] info;
        int length;

        if (spec instanceof HKDFParameterSpec.Extract e) {
            extract = true;
            expand = false;
            ikms = e.ikms();
            salts = e.salts();
            info = new byte[0];
            length = hashOutputBytes; // RFC 5869: PRK length is always the hash's output size.
        } else if (spec instanceof HKDFParameterSpec.Expand e) {
            extract = false;
            expand = true;
            ikms = List.of(e.prk());
            salts = List.of();
            info = e.info() == null ? new byte[0] : e.info();
            length = e.length();
        } else if (spec instanceof HKDFParameterSpec.ExtractThenExpand e) {
            extract = true;
            expand = true;
            ikms = e.ikms();
            salts = e.salts();
            info = e.info() == null ? new byte[0] : e.info();
            length = e.length();
        } else {
            throw new InvalidAlgorithmParameterException(
                "expected HKDFParameterSpec.Extract/Expand/ExtractThenExpand, got " + spec);
        }

        if (salts.size() > 1) {
            throw new InvalidAlgorithmParameterException(
                "this provider's native HKDF supports at most one salt, got " + salts.size()
                + " — see P11HKDFKDFSpi's javadoc for why");
        }
        if (length <= 0 || length > 512) {
            throw new InvalidAlgorithmParameterException("output length must be 1..512 bytes, got " + length);
        }

        long ikmHandle = ikms.size() == 1 ? handleOf(ikms.get(0), "IKM") : handleOfConsolidated(ikms);

        // CKA_CLASS/CKA_KEY_TYPE must be present here even though the
        // engine's own HKDF code later forces both to exactly these same
        // values regardless of what's supplied — a SEPARATE, generic
        // template pre-check (SoftHSM_keygen.cpp's shared
        // extractObjectInformation call, reached before the HKDF-specific
        // block since CKM_HKDF_DERIVE's isImplicit=false) validates the
        // caller's raw template first and rejects it as incomplete
        // without them. Found by reading the source AND confirmed live
        // via an isolated C bisection against the real engine (a 4-attr
        // template without these two fails CKR_TEMPLATE_INCOMPLETE; the
        // identical template plus these two succeeds) — not assumed from
        // the HKDF-specific code block alone, which reads misleadingly
        // self-sufficient in isolation.
        P11Library.Attr[] outputTmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attrLong(CKA_VALUE_LEN, length),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, !extractable),
            P11Library.attrBool(CKA_EXTRACTABLE, extractable),
            // The canonical two-step HKDF pattern (Extract, then a
            // separate later Expand call) chains the Extract step's PRK
            // in as the Expand step's own base key — so every derived
            // key needs CKA_DERIVE too, proactively, not just discovered
            // after that exact live failure (same lesson as ECDH's
            // missing CKA_DERIVE and the IKM-import gap above, applied
            // before a third live failure rather than after it).
            P11Library.attrBool(CKA_DERIVE, true),
        };
        // One confined arena spans both the mechanism build (which may
        // embed real secret bytes — a foreign salt key's raw value) and
        // the derive call that consumes it — see P11Library's own class
        // javadoc ("Memory-lifetime architecture") for why a per-call
        // arena inside the mech builder itself would free that memory
        // before the native call ever read it.
        try (var op = java.lang.foreign.Arena.ofConfined()) {
            // Salt: prefer the handle path (CKF_HKDF_SALT_KEY, engine
            // support added 2026-08-25 — plan §WS-A) whenever the salt is
            // already one of this provider's own token-resident keys,
            // opaque or not — no reason to round-trip through raw bytes
            // when a handle already exists, and this is what actually
            // unblocks the real caller that needed it: JEP 527 hybrid TLS
            // 1.3 chaining a previous (opaque) derived secret back in as
            // the next Extract step's salt (plan §W6). A foreign,
            // non-opaque salt key still goes through the plain-bytes path
            // (CKF_HKDF_SALT_DATA) — no need to import it onto the token
            // first when the engine will happily take the bytes directly.
            var mech = salts.isEmpty()
                ? lib.mechHkdf(op, prfHashMech, extract, expand, new byte[0], info)
                : saltMechFor(op, salts.get(0), extract, expand, info);
            return lib.deriveKey(op, mech, ikmHandle, outputTmpl);
        }
    }

    private P11Library.BuiltMech saltMechFor(java.lang.foreign.Arena op, SecretKey salt, boolean extract, boolean expand, byte[] info)
            throws InvalidAlgorithmParameterException {
        if (salt instanceof P11Key.Secret s) {
            return lib.mechHkdf(op, prfHashMech, extract, expand, s.handle(), info);
        }
        byte[] raw = salt.getEncoded();
        if (raw == null) {
            throw new InvalidAlgorithmParameterException(
                "HKDF salt must be either one of this provider's own keys (used by handle) or a key "
                + "with real encoded bytes (e.g. SecretKeySpec) — got " + salt.getClass()
                + " with no encoded form");
        }
        return lib.mechHkdf(op, prfHashMech, extract, expand, raw, info);
    }

    /** Resolves a key to a token handle: directly for our own opaque keys, or by importing a foreign key's raw bytes. */
    private long handleOf(SecretKey key, String role) throws InvalidAlgorithmParameterException {
        if (key instanceof P11Key.Secret s) return s.handle();
        byte[] raw = key.getEncoded();
        if (raw == null) {
            throw new InvalidAlgorithmParameterException(
                role + " key has no encoded form and no token handle (from neither this provider nor a plain SecretKeySpec)");
        }
        P11Library.Attr[] tmpl = {
            P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
            P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            P11Library.attr(CKA_VALUE, raw),
            P11Library.attrBool(CKA_TOKEN, false),
            P11Library.attrBool(CKA_SENSITIVE, true),
            P11Library.attrBool(CKA_EXTRACTABLE, false),
            P11Library.attrBool(CKA_DERIVE, true),
        };
        return lib.createObject(tmpl);
    }

    /**
     * Multi-IKM support (plan §W6): the engine's own CK_HKDF_PARAMS still
     * takes exactly one base key — this does not add real multi-IKM
     * support to CKM_HKDF_DERIVE, it reproduces, in Java, exactly what
     * JDK's own reference HKDF implementation does for more than one IKM
     * before this method is ever reached: simple concatenation.
     * Confirmed from real JDK 27 source
     * ({@code com.sun.crypto.provider.HKDFKeyDerivation#consolidateKeyMaterial}
     * — a loop appending each key's raw bytes to one
     * {@code ByteArrayOutputStream}, nothing more), not assumed from
     * HKDF's general shape or guessed to make JEP 527's hybrid TLS 1.3
     * key schedule happen to work. TLS 1.3 hybrid groups need exactly
     * this: JSSE's {@code KAKeyDerivation} hands this KDF a two-element
     * {@code ikms()} list (the classical ECDH-as-KEM secret, then the
     * PQ KEM secret) and expects the standard "concatenate, then
     * HKDF-Extract" combiner — found live as a real
     * {@code InvalidAlgorithmParameterException} against pqc-rest's
     * quantum-safe endpoint before this method existed, not anticipated
     * in advance.
     *
     * Every one of these IKMs must itself be extractable (a real
     * {@code byte[]} via {@code getEncoded()}) — this provider's own
     * opaque {@link P11Key.Secret} keys can never appear here, same
     * restriction {@code handleOf} already enforces for the single-IKM
     * case, and matching SunJCE's own "throws InvalidKeyException if any
     * key is unextractable" behavior for the same operation. The
     * concatenated intermediate array is explicitly zeroed after import
     * (§6.5) — it's a throwaway copy, not returned to any caller.
     */
    private long handleOfConsolidated(List<SecretKey> ikms) throws InvalidAlgorithmParameterException {
        var buf = new java.io.ByteArrayOutputStream();
        for (SecretKey k : ikms) {
            byte[] raw = k.getEncoded();
            if (raw == null) {
                throw new InvalidAlgorithmParameterException(
                    "every IKM in a multi-element ikms() list must be extractable (this provider's own "
                    + "opaque keys can never appear in a multi-IKM HKDF call — see handleOfConsolidated's javadoc)");
            }
            buf.writeBytes(raw);
        }
        byte[] concatenated = buf.toByteArray();
        try {
            P11Library.Attr[] tmpl = {
                P11Library.attrLong(CKA_CLASS, CKO_SECRET_KEY),
                P11Library.attrLong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                P11Library.attr(CKA_VALUE, concatenated),
                P11Library.attrBool(CKA_TOKEN, false),
                P11Library.attrBool(CKA_SENSITIVE, true),
                P11Library.attrBool(CKA_EXTRACTABLE, false),
                P11Library.attrBool(CKA_DERIVE, true),
            };
            return lib.createObject(tmpl);
        } finally {
            java.util.Arrays.fill(concatenated, (byte) 0);
        }
    }
}
