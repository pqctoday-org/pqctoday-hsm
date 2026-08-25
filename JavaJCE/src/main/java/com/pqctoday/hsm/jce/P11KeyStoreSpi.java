package com.pqctoday.hsm.jce;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * "PKCS11-SoftHSMv3" KeyStore — read AND write path (W4 completes what
 * W2 deferred). Fixes the classic SunPKCS11 "0 keys" gap for this token
 * properly, by actually enumerating token objects via C_FindObjects
 * rather than the empty KeyStore SunPKCS11 often reports against this
 * engine (a limitation noted since the sandbox's
 * OpenSession.java/ListKeys.java samples this session).
 *
 * Write path scope: engineSetKeyEntry promotes one of this provider's
 * OWN opaque keys (P11Key.Priv/Pub/Secret — already token-resident by
 * construction) to persistent storage via C_CopyObject with
 * CKA_TOKEN=true and CKA_LABEL=alias — confirmed reading
 * SoftHSM_objects.cpp before writing this that CKA_TOKEN is exactly the
 * one attribute C_CopyObject's own template loop recognizes for
 * session→token promotion (it's otherwise immutable post-creation). A
 * FOREIGN key (not one of this provider's own opaque types) is refused,
 * same FIPS 140-3 L3 policy as P11PublicKeyFactorySpi's private-key
 * import refusal — this KeyStore persists keys the token itself
 * generated or derived, it does not import external key material.
 * Certificate chains are refused too if non-empty (this KeyStore never
 * stores or returns certificates, so accepting one silently would be
 * dishonest — engineGetCertificateChain always returns null).
 *
 * Alias scheme, per user decision: an object's own CKA_LABEL when set
 * (respects a label an operator already gave the key), falling back to a
 * synthesized "algorithm-CKA_ID_hex" alias when CKA_LABEL is empty, so
 * every object still gets a stable, unique alias either way.
 *
 * Algorithm identity for an arbitrary discovered object (not one this
 * session just generated) is resolved from its own attributes:
 * CKA_KEY_TYPE first, then CKA_PARAMETER_SET for ML-DSA/SLH-DSA
 * (parameter set is part of the algorithm name, e.g. "ML-DSA-65"), or
 * CKA_EC_PARAMS for EdDSA specifically (Ed25519 vs Ed448, reverse-matched
 * against the ED25519_OID/ED448_OID constants already used for
 * generation — not a second, independently-typed table). Ordinary
 * CKK_EC resolves to the single name "EC" regardless of curve: unlike
 * ML-DSA/SLH-DSA, JCA's "EC" algorithm name does not vary by curve — the
 * curve is a property of the key, not the registered service name (same
 * as P11ECKeyPairGeneratorSpi's single "EC" service covering all three
 * curves) — so no curve-OID reverse-lookup is needed here. Public keys
 * additionally carry CKA_PUBLIC_KEY_INFO for full SPKI-backed
 * P11Key.Pub construction; private keys need only algorithm identity
 * (P11Key.Priv never encodes).
 */
final class P11KeyStoreSpi extends KeyStoreSpi {
    private final P11Library lib;

    P11KeyStoreSpi(P11Library lib) {
        this.lib = lib;
    }

    // ── Discovery ────────────────────────────────────────────────────────

    private record Entry(String alias, long handle, long objectClass) {}

    private List<Entry> discoverAll() {
        List<Entry> out = new ArrayList<>();
        for (long cko : new long[]{ CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY }) {
            P11Library.Attr[] tmpl = { P11Library.attrLong(CKA_CLASS, cko) };
            for (long handle : lib.findObjects(tmpl)) {
                out.add(new Entry(aliasFor(handle), handle, cko));
            }
        }
        return out;
    }

    private String aliasFor(long handle) {
        byte[] label = safeAttr(handle, CKA_LABEL);
        if (label != null && label.length > 0) {
            return new String(label, java.nio.charset.StandardCharsets.UTF_8);
        }
        // CKA_ID is not a reliable uniqueness source even when present:
        // keys generated without an explicit CKA_ID come back with a
        // present-but-ZERO-LENGTH byte array (not null) — confirmed live,
        // not assumed (see the KeyStore commit): two distinct freshly
        // generated ML-DSA-65 keys both read back CKA_ID="" (len=0),
        // which collapsed to the identical synthesized alias
        // "ML-DSA-65-" for both, silently shadowing the second key
        // behind the first in engineGetKey's lookup. The PKCS#11 object
        // HANDLE is the one value guaranteed unique within a session —
        // always fold it in, using CKA_ID only when it actually carries
        // content.
        byte[] id = safeAttr(handle, CKA_ID);
        String idPart = (id != null && id.length > 0) ? HexFormat.of().formatHex(id) : Long.toHexString(handle);
        String alg = algorithmNameOf(handle);
        return (alg != null ? alg : "unknown") + "-" + idPart + "-" + Long.toHexString(handle);
    }

    private byte[] safeAttr(long handle, long attrType) {
        try {
            return lib.getAttributeBytes(handle, attrType);
        } catch (RuntimeException e) {
            return null; // attribute not present on this object type — not an error
        }
    }

    private static long toLong(byte[] b) {
        long v = 0;
        for (int i = 0; i < Math.min(b.length, 8); i++) v |= (b[i] & 0xffL) << (8 * i);
        return v;
    }

    /** Resolves the JCA algorithm name from an object's own attributes. Returns null if unrecognized. */
    private String algorithmNameOf(long handle) {
        byte[] keyTypeBytes = safeAttr(handle, CKA_KEY_TYPE);
        if (keyTypeBytes == null) return null;
        long keyType = toLong(keyTypeBytes);

        if (keyType == CKK_ML_DSA) {
            long ps = toLong(safeAttr(handle, CKA_PARAMETER_SET));
            if (ps == CKP_ML_DSA_44) return "ML-DSA-44";
            if (ps == CKP_ML_DSA_65) return "ML-DSA-65";
            if (ps == CKP_ML_DSA_87) return "ML-DSA-87";
            return "ML-DSA";
        }
        if (keyType == CKK_SLH_DSA) {
            long ps = toLong(safeAttr(handle, CKA_PARAMETER_SET));
            return slhDsaName(ps);
        }
        if (keyType == CKK_EC_EDWARDS) {
            byte[] params = safeAttr(handle, CKA_EC_PARAMS);
            if (params != null && Arrays.equals(params, ED25519_OID)) return "Ed25519";
            if (params != null && Arrays.equals(params, ED448_OID)) return "Ed448";
            return "EdDSA";
        }
        if (keyType == CKK_EC) return "EC";
        if (keyType == CKK_RSA) return "RSA";
        if (keyType == CKK_AES) return "AES";
        // CKK_GENERIC_SECRET covers HMAC/KMAC/HKDF/PBKDF2/SP800-108
        // output alike — the engine doesn't preserve which of those
        // Java-level algorithm names a given generic-secret object was
        // really for (see P11GenericSecretKeyGeneratorSpi/HKDF/PBKDF2/
        // SP800-108's own SPIs — all use this same CKK_ value), so
        // "Generic" is the honest answer here, not a guess at which one.
        if (keyType == CKK_GENERIC_SECRET) return "Generic";
        return null;
    }

    private static String slhDsaName(long ps) {
        return switch ((int) ps) {
            case 1 -> "SLH-DSA-SHA2-128S";
            case 2 -> "SLH-DSA-SHAKE-128S";
            case 3 -> "SLH-DSA-SHA2-128F";
            case 4 -> "SLH-DSA-SHAKE-128F";
            case 5 -> "SLH-DSA-SHA2-192S";
            case 6 -> "SLH-DSA-SHAKE-192S";
            case 7 -> "SLH-DSA-SHA2-192F";
            case 8 -> "SLH-DSA-SHAKE-192F";
            case 9 -> "SLH-DSA-SHA2-256S";
            case 10 -> "SLH-DSA-SHAKE-256S";
            case 11 -> "SLH-DSA-SHA2-256F";
            case 12 -> "SLH-DSA-SHAKE-256F";
            default -> "SLH-DSA";
        };
    }

    private Key keyFor(Entry e) {
        String alg = algorithmNameOf(e.handle());
        String algOrUnknown = alg != null ? alg : "unknown";
        if (e.objectClass() == CKO_PRIVATE_KEY) {
            return new P11Key.Priv(e.handle(), algOrUnknown);
        }
        if (e.objectClass() == CKO_SECRET_KEY) {
            return new P11Key.Secret(e.handle(), algOrUnknown);
        }
        byte[] spki = safeAttr(e.handle(), CKA_PUBLIC_KEY_INFO);
        return new P11Key.Pub(e.handle(), algOrUnknown, spki != null ? spki : new byte[0]);
    }

    // ── KeyStoreSpi ──────────────────────────────────────────────────────

    @Override
    public void engineLoad(InputStream stream, char[] password) {
        // No-op: this provider's session is already logged in by the time
        // SoftHSMv3Provider construction completes (see P11Library's
        // class javadoc) — the token IS the keystore, there is no file to
        // load. A future P11SessionPool (W2+/W4) could move login to this
        // method instead, matching SunPKCS11's own convention more
        // closely; not attempted here since that would touch every SPI
        // in this module, not just this one.
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(discoverAll().stream().map(Entry::alias).toList());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return discoverAll().stream().anyMatch(e -> e.alias().equals(alias));
    }

    @Override
    public int engineSize() {
        return discoverAll().size();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) {
        return discoverAll().stream().filter(e -> e.alias().equals(alias))
            .findFirst().map(this::keyFor).orElse(null);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) { return null; }

    @Override
    public Certificate engineGetCertificate(String alias) { return null; }

    @Override
    public Date engineGetCreationDate(String alias) {
        return engineContainsAlias(alias) ? new Date(0) : null; // token doesn't record creation time
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return discoverAll().stream().anyMatch(e -> e.alias().equals(alias));
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) { return false; }

    @Override
    public String engineGetCertificateAlias(Certificate cert) { return null; }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
        // No-op: nothing to serialize — the token itself is the store.
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        if (chain != null && chain.length > 0) {
            throw new KeyStoreException(
                "this KeyStore never stores or returns certificates (engineGetCertificateChain always returns null) — "
                + "pass a null or empty chain");
        }
        long handle = switch (key) {
            case P11Key.Priv p -> p.handle();
            case P11Key.Pub p -> p.handle();
            case P11Key.Secret s -> s.handle();
            default -> throw new KeyStoreException(
                "this KeyStore only persists keys already resident on this provider's token "
                + "(generated or derived via " + SoftHSMv3Provider.class.getSimpleName()
                + ") — it does not import foreign key material, same FIPS 140-3 L3 policy as private-key import");
        };
        P11Library.Attr[] overrideTmpl = {
            P11Library.attrBool(CKA_TOKEN, true),
            P11Library.attr(CKA_LABEL, alias.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
        };
        try {
            lib.copyObject(handle, overrideTmpl);
        } catch (RuntimeException e) {
            throw new KeyStoreException("failed to persist key under alias \"" + alias + "\"", e);
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException(
            "pre-protected key bytes are not supported by this KeyStore — it wraps a live PKCS#11 token, "
            + "not a file-based store; use engineSetKeyEntry(alias, Key, password, chain) with one of this "
            + "provider's own keys instead");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("certificate entries are not supported by this KeyStore");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        long handle = discoverAll().stream().filter(e -> e.alias().equals(alias))
            .findFirst().map(Entry::handle)
            .orElseThrow(() -> new KeyStoreException("no entry with alias \"" + alias + "\""));
        try {
            lib.destroyObject(handle);
        } catch (RuntimeException e) {
            throw new KeyStoreException("failed to delete alias \"" + alias + "\"", e);
        }
    }
}
