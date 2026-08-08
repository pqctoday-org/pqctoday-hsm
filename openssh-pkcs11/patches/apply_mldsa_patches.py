#!/usr/bin/env python3
"""
apply_mldsa_patches.py
Applies ML-DSA-65 + SLH-DSA-SHA2-128s support to an openssh-portable source tree.
Implements draft-sfluhrer-ssh-mldsa-06 and draft-josefsson-ssh-sphincs-02.
Run from within the openssh-portable directory.

--dry-run / --check : report whether every anchor would apply, WITHOUT
    touching this checkout. Copies the 7 files this script patches into a
    temp directory, re-invokes this same script (without the flag) against
    the copy, reports the result, and discards the copy. This replays the
    real sequential patch order rather than checking each anchor against the
    pristine tree in isolation, which matters: several later anchors (e.g.
    the SLH-DSA sshkey.h edit) only match text an EARLIER patch in this same
    run inserted, so checking them independently would report false failures.

Added 2026-08-08 (upgrade plan A6) after a 10.3->10.4 bump broke 2 of the then
24 anchors mid-run, leaving a partially-patched tree — this exists so that
kind of break is caught before anything is touched, and so CI can check an
upstream bump without a full image build.
"""
import os, sys, re, shutil, subprocess, tempfile

DRY_RUN = any(a in ('--dry-run', '--check') for a in sys.argv[1:])

# Self-counted, not hand-maintained: every patch below is a top-level
# `replace_once(` call, so this can never silently drift from the real count.
_SELF_SOURCE = open(__file__).read()
ANCHOR_COUNT = len(re.findall(r'^replace_once\(', _SELF_SOURCE, re.M))

PATCHED_FILES = ["Makefile.in", "myproposal.h", "sshkey.h", "sshkey.c",
                  "ssh-pkcs11.c", "sshd-auth.c", "sshd.c"]


def _detect_version():
    """Best-effort — informational only, never blocks a run."""
    try:
        out = subprocess.run(["git", "describe", "--tags", "--always"],
                              capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return f"commit {out.stdout.strip()} (untagged or shallow clone)"
    except Exception:
        pass
    return "unknown (not a git checkout, or git unavailable)"


print(f"apply_mldsa_patches.py — preflight")
print(f"  target tree     : {os.getcwd()}")
print(f"  detected version: {_detect_version()}")
print(f"  anchors declared: {ANCHOR_COUNT} across {len(PATCHED_FILES)} files")
print(f"  mode            : {'DRY RUN (no files will be modified)' if DRY_RUN else 'apply'}")

if DRY_RUN:
    missing = [f for f in PATCHED_FILES if not os.path.isfile(f)]
    if missing:
        print(f"DRY RUN FAILED: source file(s) not found in {os.getcwd()}: {missing}",
              file=sys.stderr)
        sys.exit(1)
    with tempfile.TemporaryDirectory(prefix="mldsa-patch-dryrun-") as tmp:
        for f in PATCHED_FILES:
            shutil.copy(f, os.path.join(tmp, f))
        # Re-invoke this same script with no flag, so the real replace_once
        # logic below runs unchanged against the throwaway copy.
        result = subprocess.run([sys.executable, os.path.abspath(__file__)],
                                 cwd=tmp, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"DRY RUN OK: all {ANCHOR_COUNT} anchors would apply cleanly.")
            sys.exit(0)
        else:
            print("DRY RUN FAILED — this tree would NOT patch cleanly:", file=sys.stderr)
            print(result.stderr.strip(), file=sys.stderr)
            sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────
# Real application from here down. Also what the --dry-run subprocess above
# runs against its temp copy (invoked with no flags, so DRY_RUN is False
# there) — the sequential patch logic itself is untouched by A6.
# ─────────────────────────────────────────────────────────────────────────

def read(path):
    with open(path) as f:
        return f.read()

def write(path, content):
    with open(path, 'w') as f:
        f.write(content)
    print(f"  patched: {path}")

def replace_once(path, old_pattern, new):
    content = read(path)
    if not re.search(old_pattern, content):
        print(f"ERROR: marker not found in {path}:\n  {old_pattern!r}", file=sys.stderr)
        sys.exit(1)
    write(path, re.sub(old_pattern, new, content, count=1))

# ── 1. Makefile.in ───────────────────────────────────────────────────────────
replace_once(
    "Makefile.in",
    r"\tmsg\.o dns\.o entropy\.o gss-genr\.o umac\.o umac128\.o \\",
    r"	ssh-mldsa.o msg.o dns.o entropy.o gss-genr.o umac.o umac128.o \\"
)

# ── 2. myproposal.h ──────────────────────────────────────────────────────────
replace_once(
    "myproposal.h",
    r'#define\s+KEX_DEFAULT_PK_ALG\s+\\\n\s+"ssh-ed25519-cert-v01@openssh\.com,"',
    '#define\tKEX_DEFAULT_PK_ALG\t\\\n\t"ssh-mldsa-65," \\\n\t"ssh-ed25519-cert-v01@openssh.com,"'
)

# ── 3. sshkey.h ──────────────────────────────────────────────────────────────
# Anchor tolerates key types upstream inserts between KEY_ED25519_SK_CERT and
# KEY_UNSPEC, and PRESERVES them via the capture group. OpenSSH 10.4 added
# KEY_MLDSA44_ED25519 + KEY_MLDSA44_ED25519_CERT in exactly this slot, which
# broke the previous fixed-adjacency anchor. Keeping KEY_ED25519_SK_CERT in the
# pattern (rather than anchoring on KEY_UNSPEC alone) means a future upstream
# reorganisation still fails loudly instead of inserting in the wrong place.
replace_once(
    "sshkey.h",
    r"(\s+KEY_ED25519_SK_CERT,\n(?:\s+KEY_\w+,\n)*)(\s+KEY_UNSPEC)",
    r"\g<1>\tKEY_MLDSA_65,\n\g<2>"
)

# ── 4. sshkey.c ──────────────────────────────────────────────────────────────
# 4a: extern declaration
replace_once(
    "sshkey.c",
    r"extern const struct sshkey_impl sshkey_ed25519_sk_cert_impl;\n",
    "extern const struct sshkey_impl sshkey_ed25519_sk_cert_impl;\nextern const struct sshkey_impl sshkey_mldsa65_impl;\n"
)
# 4b: register in keyimpls[]
replace_once(
    "sshkey.c",
    r"&sshkey_ed25519_cert_impl,\n\s*#\s*ifdef ENABLE_SK",
    "&sshkey_ed25519_cert_impl,\n\n\t&sshkey_mldsa65_impl,\n# ifdef ENABLE_SK"
)

# ── 5. ssh-pkcs11.c ──────────────────────────────────────────────────────────
PKCS11_CONSTANTS = r"""
/* ML-DSA PKCS#11 v3.2 -- draft-sfluhrer-ssh-mldsa-06
 * Constants from SoftHSMv3 src/lib/pkcs11/pkcs11t.h */
#ifndef CKK_ML_DSA
#define CKK_ML_DSA              0x0000004aUL
#endif
#ifndef CKM_ML_DSA_KEY_PAIR_GEN
#define CKM_ML_DSA_KEY_PAIR_GEN 0x0000001cUL
#endif
#ifndef CKM_ML_DSA
#define CKM_ML_DSA              0x0000001dUL
#endif
/* PKCS#11 v3.2 §4.9 common CKO_PUBLIC_KEY attribute: DER SubjectPublicKeyInfo.
 * softhsmv3 populates this on every ML-DSA pubkey (SoftHSM_keygen.cpp). */
#ifndef CKA_PUBLIC_KEY_INFO
#define CKA_PUBLIC_KEY_INFO     0x00000129UL
#endif
/* FIPS 204 Table 2 + draft s3 */
#define SSH_MLDSA65_PK_SZ  1952
#define SSH_MLDSA65_SIG_SZ 3309

"""

FETCH_MLDSA = r"""
/*
 * pkcs11_fetch_mldsa_pubkey -- draft-sfluhrer-ssh-mldsa-06 s4
 *
 * Two-path pubkey extraction (softhsmv3 populates both):
 *   1. CKA_PUBLIC_KEY_INFO -- DER SubjectPublicKeyInfo (PKCS#11 v3.2 §4.9).
 *      Parsed via d2i_PUBKEY(); OpenSSL 3.3+ handles ML-DSA-65 SPKI natively.
 *      This is the robust path and is tried first.
 *   2. CKA_VALUE -- raw 1952-byte pk (PKCS#11 v3.2 §6.67.2 Table 280).
 *      Fallback for tokens that populate only raw pk. Imported via
 *      EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-65", ...).
 */
static struct sshkey *
pkcs11_fetch_mldsa_pubkey(struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 key_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = NULL;
	CK_RV			 rv;
	struct sshkey		*key = NULL;
	EVP_PKEY		*pkey = NULL;
	int			 success = -1, i;
	const unsigned char	*spki_p;

	memset(&key_attr, 0, sizeof(key_attr));
	key_attr[0].type = CKA_ID;
	key_attr[1].type = CKA_PUBLIC_KEY_INFO; /* DER SPKI -- preferred */
	key_attr[2].type = CKA_VALUE;           /* raw 1952 bytes -- fallback */

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* Size-probe: missing optional attrs return CKR_ATTRIBUTE_TYPE_INVALID
	 * with ulValueLen=CK_UNAVAILABLE_INFORMATION; we accept either as long as
	 * at least one usable pubkey path (SPKI or raw) was returned. */
	rv = f->C_GetAttributeValue(session, *obj, key_attr, 3);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (probe) failed: %lu", rv);
		return NULL;
	}
	if (key_attr[1].ulValueLen == (CK_ULONG)-1)
		key_attr[1].ulValueLen = 0;
	if (key_attr[2].ulValueLen == (CK_ULONG)-1)
		key_attr[2].ulValueLen = 0;
	if (key_attr[1].ulValueLen == 0 && key_attr[2].ulValueLen == 0) {
		error_f("no ML-DSA pubkey material on token object");
		return NULL;
	}
	if (key_attr[2].ulValueLen != 0 &&
	    key_attr[2].ulValueLen != SSH_MLDSA65_PK_SZ) {
		debug_f("CKA_VALUE length %lu != %d (non-fatal; "
		    "will prefer CKA_PUBLIC_KEY_INFO if present)",
		    (u_long)key_attr[2].ulValueLen, SSH_MLDSA65_PK_SZ);
	}
	for (i = 0; i < 3; i++)
		if (key_attr[i].ulValueLen > 0)
			key_attr[i].pValue = xcalloc(1, key_attr[i].ulValueLen);
	rv = f->C_GetAttributeValue(session, *obj, key_attr, 3);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (fetch) failed: %lu", rv);
		goto fail;
	}

	/* Path 1: DER SPKI -- d2i_PUBKEY handles ML-DSA-65 natively (OpenSSL 3.3+). */
	if (key_attr[1].ulValueLen > 0) {
		spki_p = (const unsigned char *)key_attr[1].pValue;
		pkey = d2i_PUBKEY(NULL, &spki_p,
		    (long)key_attr[1].ulValueLen);
		if (pkey == NULL)
			debug_f("d2i_PUBKEY failed on CKA_PUBLIC_KEY_INFO; "
			    "will try CKA_VALUE fallback");
	}
	/* Path 2: raw 1952-byte pk fallback. */
	if (pkey == NULL && key_attr[2].ulValueLen == SSH_MLDSA65_PK_SZ) {
		pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-65",
		    NULL, key_attr[2].pValue, key_attr[2].ulValueLen);
	}
	if (pkey == NULL) {
		error_f("could not materialise ML-DSA-65 pubkey "
		    "(spki=%lu bytes, raw=%lu bytes)",
		    (u_long)key_attr[1].ulValueLen,
		    (u_long)key_attr[2].ulValueLen);
		goto fail;
	}
	if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
		fatal_f("sshkey_new failed");
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = NULL;
	key->type = KEY_MLDSA_65;
	key->flags |= SSHKEY_FLAG_EXT;
	if (pkcs11_record_key(p, slotidx, &key_attr[0], key))
		goto fail;
	success = 0;
fail:
	if (success != 0) {
		EVP_PKEY_free(pkey);
		sshkey_free(key);
		key = NULL;
	}
	for (i = 0; i < 3; i++)
		free(key_attr[i].pValue);
	return key;
}

"""

SIGN_MLDSA = r"""
/*
 * pkcs11_sign_mldsa -- draft-sfluhrer-ssh-mldsa-06
 *
 * s5. Signature Algorithm
 *   Pure ML-DSA (FIPS 204 s5.2), empty context string.
 *   CKM_ML_DSA (0x1d) NULL_PTR param: full message passed, C_Sign hashes
 *   internally per FIPS 204.
 *
 * s6. Signature Format
 *   string  "ssh-mldsa-65"
 *   string  signature  (3309 raw bytes)
 */
static int
pkcs11_sign_mldsa(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider,
    const char *sk_pin, u_int compat)
{
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_MECHANISM		 mech = { CKM_ML_DSA, NULL_PTR, 0 }; /* s5 */
	CK_ULONG		 slen = SSH_MLDSA65_SIG_SZ;
	CK_RV			 rv;
	u_char			*sig = NULL;
	struct sshbuf		*b = NULL;
	int			 ret = SSH_ERR_INTERNAL_ERROR;

	if (sigp != NULL) *sigp = NULL;
	if (lenp != NULL) *lenp = 0;
	if ((k11 = pkcs11_lookup_key(key)) == NULL) {
		error_f("no key found");
		return SSH_ERR_KEY_NOT_FOUND;
	}
	if (pkcs11_get_key(k11, CKM_ML_DSA) == -1)
		return SSH_ERR_AGENT_FAILURE;
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];
	sig = xmalloc(slen);
	/* s5: full message to C_Sign -- pure ML-DSA, no pre-hash */
	rv = f->C_Sign(si->session, (CK_BYTE_PTR)data, (CK_ULONG)datalen,
	    sig, &slen);
	if (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		goto done;
	}
	if (slen != SSH_MLDSA65_SIG_SZ) {
		error_f("bad signature length: %lu (expected %d)",
		    (u_long)slen, SSH_MLDSA65_SIG_SZ);
		goto done;
	}
	/* s6: wire format */
	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (sshbuf_put_cstring(b, "ssh-mldsa-65") != 0 ||
	    sshbuf_put_string(b, sig, slen) != 0)
		fatal_f("sshbuf_put failed");
	if (sigp != NULL) {
		*sigp = xmalloc(sshbuf_len(b));
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	if (lenp != NULL)
		*lenp = sshbuf_len(b);
	ret = 0;
done:
	sshbuf_free(b);
	freezero(sig, slen);
	return ret;
}

"""

# 5a: insert constants after crypto_api.h include
replace_once(
    "ssh-pkcs11.c",
    r'#\s*include "crypto_api\.h"\n',
    '# include "crypto_api.h"\n' + PKCS11_CONSTANTS
)

# 5b: insert pkcs11_fetch_mldsa_pubkey before "# ifdef WITH_OPENSSL /* libcrypto"
replace_once(
    "ssh-pkcs11.c",
    r"\n#\s*ifdef WITH_OPENSSL /\* libcrypto needed for certificate parsing \*/",
    "\n" + FETCH_MLDSA + "# ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */"
)

# 5c: add CKK_ML_DSA case in pkcs11_fetch_keys() switch
replace_once(
    "ssh-pkcs11.c",
    r"\t\tcase CKK_EC_EDWARDS:\n\t\t\tkey = pkcs11_fetch_ed25519_pubkey\(p, slotidx, &obj\);\n\t\t\tbreak;\n\t\tdefault:",
    "\t\tcase CKK_EC_EDWARDS:\n\t\t\tkey = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\t/* draft-sfluhrer-ssh-mldsa-06 */\n\t\tcase CKK_ML_DSA:\n\t\t\tkey = pkcs11_fetch_mldsa_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\tdefault:"
)

# 5d: insert pkcs11_sign_mldsa before pkcs11_sign()
replace_once(
    "ssh-pkcs11.c",
    r"\nint\npkcs11_sign\(struct sshkey \*key,",
    "\n" + SIGN_MLDSA + "int\npkcs11_sign(struct sshkey *key,"
)

# 5e: add KEY_MLDSA_65 case in pkcs11_sign() switch
replace_once(
    "ssh-pkcs11.c",
    r"\treturn pkcs11_sign_ed25519\(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat\);\n\s*default:",
    "\treturn pkcs11_sign_ed25519(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat);\n\t/* draft-sfluhrer-ssh-mldsa-06 */\n\tcase KEY_MLDSA_65:\n\t\treturn pkcs11_sign_mldsa(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat);\n\tdefault:"
)

# ── 6. sshd-auth.c — list_hostkey_types() ───────────────────────────────────
# list_hostkey_types() has a switch that only covers RSA/ECDSA/ED25519/SK types.
# Without KEY_MLDSA_65, the server never advertises ssh-mldsa-65 as a host key
# algorithm even when the key is loaded from the agent via HostKeyAgent.
replace_once(
    "sshd-auth.c",
    r"\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t\tappend_hostkey_type\(b, sshkey_ssh_name\(key\)\);\n\t\t\tbreak;",
    "\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t/* draft-sfluhrer-ssh-mldsa-06: agent-backed ML-DSA-65 host key */\n\t\tcase KEY_MLDSA_65:\n\t\t\tappend_hostkey_type(b, sshkey_ssh_name(key));\n\t\t\tbreak;"
)

# ── 7. sshd.c — have_ssh2_key switch ─────────────────────────────────────────
# When sshd loads a HostKey that is only backed by the agent (pubkey-only,
# no private key file), it checks the keytype in a switch to set have_ssh2_key=1.
# Without KEY_MLDSA_65 here, sshd exits with "no hostkeys available" when the
# only configured HostKey is ML-DSA-65 (agent-only, no file-based classical keys).
replace_once(
    "sshd.c",
    r"\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t\tif \(have_agent \|\| key != NULL\)\n\t\t\t\tsensitive_data\.have_ssh2_key = 1;\n\t\t\tbreak;",
    "\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t/* draft-sfluhrer-ssh-mldsa-06 */\n\t\tcase KEY_MLDSA_65:\n\t\t\tif (have_agent || key != NULL)\n\t\t\t\tsensitive_data.have_ssh2_key = 1;\n\t\t\tbreak;"
)

# ══════════════════════════════════════════════════════════════════════════════
# SLH-DSA-SHA2-128s patches (draft-josefsson-ssh-sphincs-02)
# These target the ML-DSA-patched file state produced above.
# ══════════════════════════════════════════════════════════════════════════════

# ── S1. Makefile.in — add ssh-slhdsa.o ───────────────────────────────────────
replace_once(
    "Makefile.in",
    r"\tssh-mldsa\.o msg\.o",
    r"	ssh-mldsa.o ssh-slhdsa.o msg.o"
)

# ── S2. myproposal.h — add ssh-slh-dsa-sha2-128s to default PK alg list ──────
replace_once(
    "myproposal.h",
    r'"ssh-mldsa-65," \\\n\t"ssh-ed25519-cert-v01@openssh\.com,"',
    '"ssh-mldsa-65," \\\n\t"ssh-slh-dsa-sha2-128s," \\\n\t"ssh-ed25519-cert-v01@openssh.com,"'
)

# ── S3. sshkey.h — add KEY_SLH_DSA_SHA2_128S after KEY_MLDSA_65 ──────────────
replace_once(
    "sshkey.h",
    r"\tKEY_MLDSA_65,\n\s+KEY_UNSPEC",
    "\tKEY_MLDSA_65,\n\tKEY_SLH_DSA_SHA2_128S,\n\tKEY_UNSPEC"
)

# ── S4. sshkey.c — extern + register sshkey_slhdsa_sha2_128s_impl ────────────
# 4a: extern declaration after ML-DSA extern
replace_once(
    "sshkey.c",
    r"extern const struct sshkey_impl sshkey_mldsa65_impl;\n",
    "extern const struct sshkey_impl sshkey_mldsa65_impl;\nextern const struct sshkey_impl sshkey_slhdsa_sha2_128s_impl;\n"
)
# 4b: register after ML-DSA entry in keyimpls[]
replace_once(
    "sshkey.c",
    r"&sshkey_mldsa65_impl,\n# ifdef ENABLE_SK",
    "&sshkey_mldsa65_impl,\n\n\t&sshkey_slhdsa_sha2_128s_impl,\n# ifdef ENABLE_SK"
)

# ── S5. ssh-pkcs11.c — SLH-DSA constants + fetch + sign + dispatch ───────────
PKCS11_SLH_CONSTANTS = r"""
/* SLH-DSA PKCS#11 v3.2 -- draft-josefsson-ssh-sphincs-02
 * Constants from SoftHSMv3 src/lib/pkcs11/pkcs11t.h */
#ifndef CKK_SLH_DSA
#define CKK_SLH_DSA              0x0000004bUL
#endif
#ifndef CKM_SLH_DSA_KEY_PAIR_GEN
#define CKM_SLH_DSA_KEY_PAIR_GEN 0x0000002dUL
#endif
#ifndef CKM_SLH_DSA
#define CKM_SLH_DSA              0x0000002eUL
#endif
/* FIPS 205 §11 Table 2 + draft s3 */
#define SSH_SLHDSA128S_PK_SZ  32
#define SSH_SLHDSA128S_SIG_SZ 7856

"""

FETCH_SLHDSA = r"""
/*
 * pkcs11_fetch_slhdsa_pubkey -- draft-josefsson-ssh-sphincs-02 s4
 *
 * Two-path pubkey extraction (softhsmv3 populates both):
 *   1. CKA_PUBLIC_KEY_INFO -- DER SubjectPublicKeyInfo (PKCS#11 v3.2 §4.9).
 *      Parsed via d2i_PUBKEY(); OpenSSL 3.5+ handles SLH-DSA-SHA2-128s SPKI.
 *   2. CKA_VALUE -- raw 32-byte pk (PKCS#11 v3.2 §6.X SLH-DSA).
 *      Fallback: imported via EVP_PKEY_new_raw_public_key_ex(..., "SLH-DSA-SHA2-128s").
 */
static struct sshkey *
pkcs11_fetch_slhdsa_pubkey(struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 key_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = NULL;
	CK_RV			 rv;
	struct sshkey		*key = NULL;
	EVP_PKEY		*pkey = NULL;
	int			 success = -1, i;
	const unsigned char	*spki_p;

	memset(&key_attr, 0, sizeof(key_attr));
	key_attr[0].type = CKA_ID;
	key_attr[1].type = CKA_PUBLIC_KEY_INFO;
	key_attr[2].type = CKA_VALUE;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_GetAttributeValue(session, *obj, key_attr, 3);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (probe) failed: %lu", rv);
		return NULL;
	}
	if (key_attr[1].ulValueLen == (CK_ULONG)-1)
		key_attr[1].ulValueLen = 0;
	if (key_attr[2].ulValueLen == (CK_ULONG)-1)
		key_attr[2].ulValueLen = 0;
	if (key_attr[1].ulValueLen == 0 && key_attr[2].ulValueLen == 0) {
		error_f("no SLH-DSA pubkey material on token object");
		return NULL;
	}
	for (i = 0; i < 3; i++)
		if (key_attr[i].ulValueLen > 0)
			key_attr[i].pValue = xcalloc(1, key_attr[i].ulValueLen);
	rv = f->C_GetAttributeValue(session, *obj, key_attr, 3);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (fetch) failed: %lu", rv);
		goto fail;
	}

	/* Path 1: DER SPKI */
	if (key_attr[1].ulValueLen > 0) {
		spki_p = (const unsigned char *)key_attr[1].pValue;
		pkey = d2i_PUBKEY(NULL, &spki_p,
		    (long)key_attr[1].ulValueLen);
		if (pkey == NULL)
			debug_f("d2i_PUBKEY failed; trying CKA_VALUE fallback");
	}
	/* Path 2: raw 32-byte pk fallback */
	if (pkey == NULL && key_attr[2].ulValueLen == SSH_SLHDSA128S_PK_SZ) {
		pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "SLH-DSA-SHA2-128s",
		    NULL, key_attr[2].pValue, key_attr[2].ulValueLen);
	}
	if (pkey == NULL) {
		error_f("could not materialise SLH-DSA-SHA2-128s pubkey "
		    "(spki=%lu bytes, raw=%lu bytes)",
		    (u_long)key_attr[1].ulValueLen,
		    (u_long)key_attr[2].ulValueLen);
		goto fail;
	}
	if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
		fatal_f("sshkey_new failed");
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = NULL;
	key->type = KEY_SLH_DSA_SHA2_128S;
	key->flags |= SSHKEY_FLAG_EXT;
	if (pkcs11_record_key(p, slotidx, &key_attr[0], key))
		goto fail;
	success = 0;
fail:
	if (success != 0) {
		EVP_PKEY_free(pkey);
		sshkey_free(key);
		key = NULL;
	}
	for (i = 0; i < 3; i++)
		free(key_attr[i].pValue);
	return key;
}

"""

SIGN_SLHDSA = r"""
/*
 * pkcs11_sign_slhdsa -- draft-josefsson-ssh-sphincs-02
 *
 * s5. Signature Algorithm
 *   Pure SLH-DSA (FIPS 205 §9.2), empty context string.
 *   CKM_SLH_DSA (0x2e) NULL_PTR param: full message to C_Sign.
 *
 * s6. Signature Format
 *   string  "ssh-slh-dsa-sha2-128s"
 *   string  signature  (7856 raw bytes)
 */
static int
pkcs11_sign_slhdsa(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider,
    const char *sk_pin, u_int compat)
{
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_MECHANISM		 mech = { CKM_SLH_DSA, NULL_PTR, 0 };
	CK_ULONG		 slen = SSH_SLHDSA128S_SIG_SZ;
	CK_RV			 rv;
	u_char			*sig = NULL;
	struct sshbuf		*b = NULL;
	int			 ret = SSH_ERR_INTERNAL_ERROR;

	if (sigp != NULL) *sigp = NULL;
	if (lenp != NULL) *lenp = 0;
	if ((k11 = pkcs11_lookup_key(key)) == NULL) {
		error_f("no key found");
		return SSH_ERR_KEY_NOT_FOUND;
	}
	if (pkcs11_get_key(k11, CKM_SLH_DSA) == -1)
		return SSH_ERR_AGENT_FAILURE;
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];
	sig = xmalloc(slen);
	rv = f->C_Sign(si->session, (CK_BYTE_PTR)data, (CK_ULONG)datalen,
	    sig, &slen);
	if (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		goto done;
	}
	if (slen != SSH_SLHDSA128S_SIG_SZ) {
		error_f("bad signature length: %lu (expected %d)",
		    (u_long)slen, SSH_SLHDSA128S_SIG_SZ);
		goto done;
	}
	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (sshbuf_put_cstring(b, "ssh-slh-dsa-sha2-128s") != 0 ||
	    sshbuf_put_string(b, sig, slen) != 0)
		fatal_f("sshbuf_put failed");
	if (sigp != NULL) {
		*sigp = xmalloc(sshbuf_len(b));
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	if (lenp != NULL)
		*lenp = sshbuf_len(b);
	ret = 0;
done:
	sshbuf_free(b);
	freezero(sig, slen);
	return ret;
}

"""

# S5a: insert SLH-DSA constants after ML-DSA constants block
replace_once(
    "ssh-pkcs11.c",
    r"#define SSH_MLDSA65_SIG_SZ 3309\n\n",
    "#define SSH_MLDSA65_SIG_SZ 3309\n\n" + PKCS11_SLH_CONSTANTS
)

# S5b: insert pkcs11_fetch_slhdsa_pubkey after pkcs11_fetch_mldsa_pubkey
replace_once(
    "ssh-pkcs11.c",
    r"\n#\s*ifdef WITH_OPENSSL /\* libcrypto needed for certificate parsing \*/",
    "\n" + FETCH_SLHDSA + "# ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */"
)

# S5c: add CKK_SLH_DSA case in pkcs11_fetch_keys() after CKK_ML_DSA case
replace_once(
    "ssh-pkcs11.c",
    r"\t\t/\* draft-sfluhrer-ssh-mldsa-06 \*/\n\t\tcase CKK_ML_DSA:\n\t\t\tkey = pkcs11_fetch_mldsa_pubkey\(p, slotidx, &obj\);\n\t\t\tbreak;\n\t\tdefault:",
    "\t\t/* draft-sfluhrer-ssh-mldsa-06 */\n\t\tcase CKK_ML_DSA:\n\t\t\tkey = pkcs11_fetch_mldsa_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\t/* draft-josefsson-ssh-sphincs-02 */\n\t\tcase CKK_SLH_DSA:\n\t\t\tkey = pkcs11_fetch_slhdsa_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\tdefault:"
)

# S5d: insert pkcs11_sign_slhdsa before pkcs11_sign()
replace_once(
    "ssh-pkcs11.c",
    r"\nint\npkcs11_sign\(struct sshkey \*key,",
    "\n" + SIGN_SLHDSA + "int\npkcs11_sign(struct sshkey *key,"
)

# S5e: add KEY_SLH_DSA_SHA2_128S case in pkcs11_sign() after ML-DSA case
replace_once(
    "ssh-pkcs11.c",
    r"\t/\* draft-sfluhrer-ssh-mldsa-06 \*/\n\tcase KEY_MLDSA_65:\n\t\treturn pkcs11_sign_mldsa\(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat\);\n\tdefault:",
    "\t/* draft-sfluhrer-ssh-mldsa-06 */\n\tcase KEY_MLDSA_65:\n\t\treturn pkcs11_sign_mldsa(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat);\n\t/* draft-josefsson-ssh-sphincs-02 */\n\tcase KEY_SLH_DSA_SHA2_128S:\n\t\treturn pkcs11_sign_slhdsa(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat);\n\tdefault:"
)

# ── S6. sshd-auth.c — add KEY_SLH_DSA_SHA2_128S to list_hostkey_types() ──────
replace_once(
    "sshd-auth.c",
    r"\t\t/\* draft-sfluhrer-ssh-mldsa-06: agent-backed ML-DSA-65 host key \*/\n\t\tcase KEY_MLDSA_65:\n\t\t\tappend_hostkey_type\(b, sshkey_ssh_name\(key\)\);\n\t\t\tbreak;",
    "\t\t/* draft-sfluhrer-ssh-mldsa-06: agent-backed ML-DSA-65 host key */\n\t\tcase KEY_MLDSA_65:\n\t\t/* draft-josefsson-ssh-sphincs-02: agent-backed SLH-DSA-SHA2-128s host key */\n\t\tcase KEY_SLH_DSA_SHA2_128S:\n\t\t\tappend_hostkey_type(b, sshkey_ssh_name(key));\n\t\t\tbreak;"
)

# ── S7. sshd.c — add KEY_SLH_DSA_SHA2_128S to have_ssh2_key switch ───────────
replace_once(
    "sshd.c",
    r"\t\t/\* draft-sfluhrer-ssh-mldsa-06 \*/\n\t\tcase KEY_MLDSA_65:\n\t\t\tif \(have_agent \|\| key != NULL\)\n\t\t\t\tsensitive_data\.have_ssh2_key = 1;\n\t\t\tbreak;",
    "\t\t/* draft-sfluhrer-ssh-mldsa-06 */\n\t\tcase KEY_MLDSA_65:\n\t\t/* draft-josefsson-ssh-sphincs-02 */\n\t\tcase KEY_SLH_DSA_SHA2_128S:\n\t\t\tif (have_agent || key != NULL)\n\t\t\t\tsensitive_data.have_ssh2_key = 1;\n\t\t\tbreak;"
)

print("All patches applied successfully (ML-DSA-65 + SLH-DSA-SHA2-128s).")
print("Next: ensure ssh-mldsa.c AND ssh-slhdsa.c are in the source tree "
      "(Makefile.in now references both objects), then "
      "autoreconf -i && ./configure ... && make")
