package com.pqctoday.hsm.jce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static com.pqctoday.hsm.jce.P11Constants.*;

/**
 * "PKCS11-SoftHSMv3" KeyStore — read AND write path, including real
 * certificate storage (W4/W5 completes what W2 deferred). Fixes the
 * classic SunPKCS11 "0 keys" gap for this token properly, by actually
 * enumerating token objects via C_FindObjects rather than the empty
 * KeyStore SunPKCS11 often reports against this engine (a limitation
 * noted since the sandbox's OpenSession.java/ListKeys.java samples this
 * session).
 *
 * Certificate design — verified against the real engine source and the
 * real JDK 27 source before writing any of this, not assumed:
 *
 * - CKO_CERTIFICATE/CKC_X_509 is a genuinely implemented engine object
 *   class (confirmed reading P11Objects.cpp/P11Objects.h), requiring
 *   CKA_VALUE and CKA_SUBJECT at creation (both flagged mandatory —
 *   "ck1" — in that same source). CKA_PUBLIC_KEY_INFO is auto-extracted
 *   by the engine from the cert DER via OpenSSL at creation time.
 * - CKA_TRUSTED can only be set to true by the SO (verified verbatim in
 *   P11Attributes.cpp's CKA_TRUSTED updateAttr — "CKA_TRUSTED can only
 *   be set to true by the SO"), and this provider's own P11Library only
 *   ever logs in as CKU_USER (confirmed — no CKU_SO constant or login
 *   call exists anywhere in this module). So the native trusted flag is
 *   never usable here; TrustedCertificateEntry vs. a PrivateKeyEntry's
 *   own chain certs is distinguished at the JAVA level instead: if a
 *   private/secret key shares an alias, its certs are that entry's
 *   chain; otherwise a certificate under that alias is a standalone
 *   trusted entry.
 * - Chain ordering: real java.security.KeyStore.getCertificateChain
 *   javadoc says "ordered with the user's certificate first" (leaf
 *   first). PKCS#11 has no standard "chain position" attribute, so this
 *   class uses CKA_ID as its own internal ordinal ("0" = leaf, "1" =
 *   next, ...) — a deliberate, simple, self-consistent convention (not
 *   a real-world PKCS#11 interop convention like CKA_ID-as-pubkey-hash,
 *   since no external PKCS#11 tooling reads these specific objects).
 * - setKeyEntry re-setting an existing alias REPLACES it (confirmed
 *   verbatim in KeyStore.java's javadoc: "If the given alias already
 *   exists, the keystore information associated with it is overridden")
 *   — this class deletes every existing object under that alias first,
 *   rather than leaving the old ones orphaned as session/token garbage.
 * - setCertificateEntry throws if the alias already identifies a
 *   non-trusted-cert entry (confirmed verbatim in the same javadoc).
 */
final class P11KeyStoreSpi extends KeyStoreSpi {
    private final P11Library lib;
    private final CertificateFactory x509Factory;

    P11KeyStoreSpi(P11Library lib) {
        this.lib = lib;
        try {
            this.x509Factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new ProviderException("X.509 CertificateFactory unavailable", e);
        }
    }

    // ── Low-level discovery helpers ─────────────────────────────────────

    private record ObjRef(long handle, long objectClass) {}

    /**
     * One full scan across every object class, grouped by alias.
     * Deliberately NOT an exact-CKA_LABEL lookup keyed by the target
     * alias string: a key generated directly by KeyPairGenerator/
     * KeyGenerator (i.e. never persisted via engineSetKeyEntry) has no
     * CKA_LABEL at all, and is only discoverable via aliasFor()'s
     * synthesized fallback — an exact-label filter would silently miss
     * every such key. Caught live via a regression in this exact
     * module's own pre-existing KeyStoreTest before this was fixed:
     * "the key just generated must be discoverable through the
     * KeyStore" started failing the moment discovery was rewritten to
     * filter by CKA_LABEL directly instead of enumerating everything
     * and computing each object's alias the way the original W2 read
     * path always did.
     */
    private Map<String, List<ObjRef>> discoverAll() {
        Map<String, List<ObjRef>> byAlias = new LinkedHashMap<>();
        for (long cko : new long[]{ CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKO_CERTIFICATE }) {
            P11Library.Attr[] tmpl = { P11Library.attrLong(CKA_CLASS, cko) };
            for (long handle : lib.findObjects(tmpl)) {
                byAlias.computeIfAbsent(aliasFor(handle), k -> new ArrayList<>()).add(new ObjRef(handle, cko));
            }
        }
        return byAlias;
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

    private String aliasFor(long handle) {
        byte[] label = safeAttr(handle, CKA_LABEL);
        if (label != null && label.length > 0) {
            return new String(label, StandardCharsets.UTF_8);
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

    /** Resolves the JCA algorithm name from a key object's own attributes. Returns null if unrecognized. */
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
        // really for, so "Generic" is the honest answer, not a guess.
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

    private Key keyFor(long handle, long objectClass) {
        String alg = algorithmNameOf(handle);
        String algOrUnknown = alg != null ? alg : "unknown";
        if (objectClass == CKO_PRIVATE_KEY) {
            return new P11Key.Priv(handle, algOrUnknown);
        }
        if (objectClass == CKO_SECRET_KEY) {
            return new P11Key.Secret(handle, algOrUnknown);
        }
        byte[] spki = safeAttr(handle, CKA_PUBLIC_KEY_INFO);
        return new P11Key.Pub(handle, algOrUnknown, spki != null ? spki : new byte[0]);
    }

    // ── Per-alias entry classification (all derived from one discoverAll() scan) ──

    /** The one key object (if any) among this alias's objects — CKO_PRIVATE_KEY preferred, then CKO_SECRET_KEY, then CKO_PUBLIC_KEY. */
    private Optional<ObjRef> keyRefFor(Map<String, List<ObjRef>> all, String alias) {
        List<ObjRef> refs = all.getOrDefault(alias, List.of());
        for (long cko : new long[]{ CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKO_PUBLIC_KEY }) {
            for (ObjRef r : refs) {
                if (r.objectClass() == cko) return Optional.of(r);
            }
        }
        return Optional.empty();
    }

    /** Certificate handles among this alias's objects, ordered by CKA_ID ("0"=leaf) when present. */
    private List<Long> certChainHandlesFor(Map<String, List<ObjRef>> all, String alias) {
        List<Long> certs = all.getOrDefault(alias, List.of()).stream()
            .filter(r -> r.objectClass() == CKO_CERTIFICATE)
            .map(ObjRef::handle)
            .collect(java.util.stream.Collectors.toCollection(ArrayList::new));
        certs.sort(Comparator.comparingInt(h -> {
            byte[] id = safeAttr(h, CKA_ID);
            if (id == null || id.length == 0) return 0;
            try {
                return Integer.parseInt(new String(id, StandardCharsets.UTF_8));
            } catch (NumberFormatException e) {
                return 0;
            }
        }));
        return certs;
    }

    private X509Certificate certAt(long handle) {
        byte[] der = safeAttr(handle, CKA_VALUE);
        if (der == null) return null;
        try {
            return (X509Certificate) x509Factory.generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new ProviderException("stored certificate DER failed to parse", e);
        }
    }

    /** Deletes every object (key or certificate) stored under this alias. */
    private void deleteAllForAlias(String alias) {
        for (ObjRef r : discoverAll().getOrDefault(alias, List.of())) {
            lib.destroyObject(r.handle());
        }
    }

    // ── KeyStoreSpi ──────────────────────────────────────────────────────

    @Override
    public void engineLoad(InputStream stream, char[] password) {
        // No-op: this provider's session is already logged in by the time
        // SoftHSMv3Provider construction completes (see P11Library's
        // class javadoc) — the token IS the keystore, there is no file to
        // load.
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(new ArrayList<>(discoverAll().keySet()));
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        Map<String, List<ObjRef>> all = discoverAll();
        return keyRefFor(all, alias).isPresent() || !certChainHandlesFor(all, alias).isEmpty();
    }

    @Override
    public int engineSize() {
        return discoverAll().size();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) {
        return keyRefFor(discoverAll(), alias).map(r -> keyFor(r.handle(), r.objectClass())).orElse(null);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        // Per java.security.KeyStore.getCertificateChain's real javadoc:
        // only applies to a PrivateKeyEntry-shaped alias (a key entry
        // with an associated chain) — not a TrustedCertificateEntry.
        Map<String, List<ObjRef>> all = discoverAll();
        if (keyRefFor(all, alias).isEmpty()) return null;
        List<Long> certs = certChainHandlesFor(all, alias);
        if (certs.isEmpty()) return null;
        Certificate[] chain = new Certificate[certs.size()];
        for (int i = 0; i < certs.size(); i++) chain[i] = certAt(certs.get(i));
        return chain;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        // Real javadoc: TrustedCertificateEntry -> that cert;
        // PrivateKeyEntry -> chain[0] (the leaf).
        List<Long> certs = certChainHandlesFor(discoverAll(), alias);
        if (certs.isEmpty()) return null;
        return certAt(certs.get(0));
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return engineContainsAlias(alias) ? new Date(0) : null; // token doesn't record creation time
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return keyRefFor(discoverAll(), alias).isPresent();
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        // A TrustedCertificateEntry specifically: a certificate exists
        // under this alias AND no key does (a key's own chain certs are
        // NOT "certificate entries" in the JCA sense — confirmed via
        // KeyStore.getCertificate's javadoc distinguishing the two cases).
        Map<String, List<ObjRef>> all = discoverAll();
        return keyRefFor(all, alias).isEmpty() && !certChainHandlesFor(all, alias).isEmpty();
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        if (!(cert instanceof X509Certificate x509)) return null;
        byte[] target;
        try {
            target = x509.getEncoded();
        } catch (CertificateEncodingException e) {
            return null;
        }
        Map<String, List<ObjRef>> all = discoverAll();
        for (String alias : all.keySet()) {
            List<Long> certs = certChainHandlesFor(all, alias);
            if (certs.isEmpty()) continue;
            Certificate c = certAt(certs.get(0));
            try {
                if (Arrays.equals(target, c.getEncoded())) return alias;
            } catch (CertificateEncodingException ignored) {
                // skip — can't compare
            }
        }
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
        // No-op: nothing to serialize — the token itself is the store.
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        long handle = switch (key) {
            case P11Key.Priv p -> p.handle();
            case P11Key.Pub p -> p.handle();
            case P11Key.Secret s -> s.handle();
            default -> throw new KeyStoreException(
                "this KeyStore only persists keys already resident on this provider's token "
                + "(generated or derived via " + SoftHSMv3Provider.class.getSimpleName()
                + ") — it does not import foreign key material, same FIPS 140-3 L3 policy as private-key import");
        };
        List<X509Certificate> x509Chain = new ArrayList<>();
        if (chain != null) {
            for (Certificate c : chain) {
                if (!(c instanceof X509Certificate x509)) {
                    throw new KeyStoreException("only X.509 certificates are supported, got " + c.getType());
                }
                x509Chain.add(x509);
            }
        }

        // setKeyEntry on an existing alias REPLACES it (KeyStore.java's
        // own javadoc) — delete every prior object under this alias
        // first rather than orphaning it.
        deleteAllForAlias(alias);

        P11Library.Attr[] overrideTmpl = {
            P11Library.attrBool(CKA_TOKEN, true),
            P11Library.attr(CKA_LABEL, alias.getBytes(StandardCharsets.UTF_8)),
        };
        try {
            lib.copyObject(handle, overrideTmpl);
        } catch (RuntimeException e) {
            throw new KeyStoreException("failed to persist key under alias \"" + alias + "\"", e);
        }

        for (int i = 0; i < x509Chain.size(); i++) {
            createCertificateObject(alias, x509Chain.get(i), i);
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
        if (!(cert instanceof X509Certificate x509)) {
            throw new KeyStoreException("only X.509 certificates are supported, got " + cert.getType());
        }
        if (keyRefFor(discoverAll(), alias).isPresent()) {
            throw new KeyStoreException(
                "alias \"" + alias + "\" already identifies a key entry, not a trusted certificate entry");
        }
        // Re-setting an existing TrustedCertificateEntry overrides it
        // (KeyStore.java's own javadoc) — delete any prior standalone
        // cert(s) under this alias first.
        deleteAllForAlias(alias);
        createCertificateObject(alias, x509, -1); // -1 = standalone trusted entry, no chain ordinal
    }

    private void createCertificateObject(String alias, X509Certificate cert, int chainIndex) throws KeyStoreException {
        byte[] der;
        byte[] subject;
        byte[] issuer;
        try {
            der = cert.getEncoded();
            subject = cert.getSubjectX500Principal().getEncoded();
            issuer = cert.getIssuerX500Principal().getEncoded();
        } catch (CertificateEncodingException e) {
            throw new KeyStoreException("failed to encode certificate", e);
        }
        List<P11Library.Attr> tmpl = new ArrayList<>(List.of(
            P11Library.attrLong(CKA_CLASS, CKO_CERTIFICATE),
            P11Library.attrLong(CKA_CERTIFICATE_TYPE, CKC_X_509),
            P11Library.attrBool(CKA_TOKEN, true),
            P11Library.attr(CKA_LABEL, alias.getBytes(StandardCharsets.UTF_8)),
            P11Library.attr(CKA_VALUE, der),
            P11Library.attr(CKA_SUBJECT, subject),
            P11Library.attr(CKA_ISSUER, issuer)
        ));
        if (chainIndex >= 0) {
            tmpl.add(P11Library.attr(CKA_ID, Integer.toString(chainIndex).getBytes(StandardCharsets.UTF_8)));
        }
        try {
            lib.createObject(tmpl.toArray(new P11Library.Attr[0]));
        } catch (RuntimeException e) {
            throw new KeyStoreException("failed to store certificate under alias \"" + alias + "\"", e);
        }
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        if (!engineContainsAlias(alias)) {
            throw new KeyStoreException("no entry with alias \"" + alias + "\"");
        }
        try {
            deleteAllForAlias(alias);
        } catch (RuntimeException e) {
            throw new KeyStoreException("failed to delete alias \"" + alias + "\"", e);
        }
    }
}
