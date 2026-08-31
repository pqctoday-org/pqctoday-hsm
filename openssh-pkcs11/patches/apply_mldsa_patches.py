#!/usr/bin/env python3
"""
apply_mldsa_patches.py
Applies ML-DSA (44/65/87) + SLH-DSA (8 of 12 FIPS 205 parameter sets) support
to an openssh-portable source tree.
Implements draft-sfluhrer-ssh-mldsa-08 and draft-josefsson-ssh-sphincs-02.
Run from within the openssh-portable directory.

SLH-DSA coverage note: draft-josefsson-ssh-sphincs-02 does not define
standalone SSH wire names for the standard FIPS 205 192-category parameter
sets (SHA2/SHAKE-192s/192f). Its own 192-bit table entries
(ssh-slh-dsa-{sha2,shake}-192-24) are a DIFFERENT, non-FIPS-205 parameter
family from NIST SP 800-230 IDP that this engine does not implement. See
patches/ssh-slhdsa.c's file header for the full citation trail.

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

2026-08-31: generalized from single-parameter-set (ssh-mldsa-65 /
ssh-slh-dsa-sha2-128s only) to full ML-DSA coverage (44/65/87) and 8-of-12
SLH-DSA coverage. See the remediation plan's section 3 and this repo's
CHANGELOG.md for the byte-size verification trail (engine + vendored
OpenSSL 3.6.3 source + live draft fetches).
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
# All 3 ML-DSA parameter sets (draft-sfluhrer-ssh-mldsa-08 s3).
replace_once(
    "myproposal.h",
    r'#define\s+KEX_DEFAULT_PK_ALG\s+\\\n\s+"ssh-ed25519-cert-v01@openssh\.com,"',
    '#define\tKEX_DEFAULT_PK_ALG\t\\\n'
    '\t"ssh-mldsa-44," \\\n'
    '\t"ssh-mldsa-65," \\\n'
    '\t"ssh-mldsa-87," \\\n'
    '\t"ssh-ed25519-cert-v01@openssh.com,"'
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
    r"\g<1>\tKEY_MLDSA_44,\n\tKEY_MLDSA_65,\n\tKEY_MLDSA_87,\n\g<2>"
)

# ── 4. sshkey.c ──────────────────────────────────────────────────────────────
# 4a: extern declarations (all 3 ML-DSA impls)
replace_once(
    "sshkey.c",
    r"extern const struct sshkey_impl sshkey_ed25519_sk_cert_impl;\n",
    "extern const struct sshkey_impl sshkey_ed25519_sk_cert_impl;\n"
    "extern const struct sshkey_impl sshkey_mldsa44_impl;\n"
    "extern const struct sshkey_impl sshkey_mldsa65_impl;\n"
    "extern const struct sshkey_impl sshkey_mldsa87_impl;\n"
)
# 4b: register in keyimpls[] (all 3 ML-DSA impls)
replace_once(
    "sshkey.c",
    r"&sshkey_ed25519_cert_impl,\n\s*#\s*ifdef ENABLE_SK",
    "&sshkey_ed25519_cert_impl,\n\n"
    "\t&sshkey_mldsa44_impl,\n"
    "\t&sshkey_mldsa65_impl,\n"
    "\t&sshkey_mldsa87_impl,\n"
    "# ifdef ENABLE_SK"
)

# ── 5. ssh-pkcs11.c ──────────────────────────────────────────────────────────
# Combined ML-DSA (3 sets) + SLH-DSA (8 sets) PKCS#11 constants and
# parameter-set dispatch tables. A single object of shared PKCS#11 key TYPE
# (CKK_ML_DSA / CKK_SLH_DSA) covers every parameter set in its family — the
# variant is selected by CKA_PARAMETER_SET (softhsmv3 populates this on every
# ML-DSA/SLH-DSA pubkey object; SoftHSM_keygen.cpp) or, failing that, by the
# self-describing DER SPKI the token also returns.
PKCS11_CONSTANTS = r"""
/* ML-DSA PKCS#11 v3.2 -- draft-sfluhrer-ssh-mldsa-08
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
 * softhsmv3 populates this on every ML-DSA/SLH-DSA pubkey (SoftHSM_keygen.cpp). */
#ifndef CKA_PUBLIC_KEY_INFO
#define CKA_PUBLIC_KEY_INFO     0x00000129UL
#endif
#ifndef CKA_PARAMETER_SET
#define CKA_PARAMETER_SET       0x0000061dUL
#endif
#ifndef CKP_ML_DSA_44
#define CKP_ML_DSA_44           0x00000001UL
#endif
#ifndef CKP_ML_DSA_65
#define CKP_ML_DSA_65           0x00000002UL
#endif
#ifndef CKP_ML_DSA_87
#define CKP_ML_DSA_87           0x00000003UL
#endif

/* FIPS 204 Table 2 + draft-sfluhrer-ssh-mldsa-08 s4/s6 -- verified against
 * deps/openssl-src/openssl-3.6.3/include/crypto/ml_dsa.h. */
struct mldsa_variant {
	CK_ULONG	paramset;	/* CKP_ML_DSA_44/65/87 */
	int		keytype;	/* KEY_MLDSA_44/65/87 */
	const char     *ssh_name;	/* "ssh-mldsa-44" etc */
	const char     *ossl_name;	/* "ML-DSA-44" etc */
	size_t		pk_sz;
	size_t		sig_sz;
};

static const struct mldsa_variant mldsa_variants[] = {
	{ CKP_ML_DSA_44, KEY_MLDSA_44, "ssh-mldsa-44", "ML-DSA-44", 1312, 2420 },
	{ CKP_ML_DSA_65, KEY_MLDSA_65, "ssh-mldsa-65", "ML-DSA-65", 1952, 3309 },
	{ CKP_ML_DSA_87, KEY_MLDSA_87, "ssh-mldsa-87", "ML-DSA-87", 2592, 4627 },
};
#define N_MLDSA_VARIANTS (sizeof(mldsa_variants) / sizeof(mldsa_variants[0]))

static const struct mldsa_variant *
mldsa_variant_by_paramset(CK_ULONG paramset)
{
	size_t i;
	for (i = 0; i < N_MLDSA_VARIANTS; i++)
		if (mldsa_variants[i].paramset == paramset)
			return &mldsa_variants[i];
	return NULL;
}

/* ML-DSA's three public-key sizes (1312/1952/2592) are pairwise distinct, so
 * a length-based fallback is unambiguous when CKA_PARAMETER_SET or a decoded
 * SPKI aren't available. */
static const struct mldsa_variant *
mldsa_variant_by_pklen(CK_ULONG len)
{
	size_t i;
	for (i = 0; i < N_MLDSA_VARIANTS; i++)
		if (mldsa_variants[i].pk_sz == len)
			return &mldsa_variants[i];
	return NULL;
}

static const struct mldsa_variant *
mldsa_variant_by_pkey(EVP_PKEY *pkey)
{
	size_t i;
	for (i = 0; i < N_MLDSA_VARIANTS; i++)
		if (EVP_PKEY_is_a(pkey, mldsa_variants[i].ossl_name))
			return &mldsa_variants[i];
	return NULL;
}

static const struct mldsa_variant *
mldsa_variant_by_keytype(int keytype)
{
	size_t i;
	for (i = 0; i < N_MLDSA_VARIANTS; i++)
		if (mldsa_variants[i].keytype == keytype)
			return &mldsa_variants[i];
	return NULL;
}

/* SLH-DSA PKCS#11 v3.2 -- draft-josefsson-ssh-sphincs-02. Only the 8
 * parameter sets the draft defines standalone SSH names for (see
 * ssh-slhdsa.c's file header for why 192s/192f are excluded).
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
#ifndef CKP_SLH_DSA_SHA2_128S
#define CKP_SLH_DSA_SHA2_128S    0x00000001UL
#endif
#ifndef CKP_SLH_DSA_SHAKE_128S
#define CKP_SLH_DSA_SHAKE_128S   0x00000002UL
#endif
#ifndef CKP_SLH_DSA_SHA2_128F
#define CKP_SLH_DSA_SHA2_128F    0x00000003UL
#endif
#ifndef CKP_SLH_DSA_SHAKE_128F
#define CKP_SLH_DSA_SHAKE_128F   0x00000004UL
#endif
#ifndef CKP_SLH_DSA_SHA2_256S
#define CKP_SLH_DSA_SHA2_256S    0x00000009UL
#endif
#ifndef CKP_SLH_DSA_SHAKE_256S
#define CKP_SLH_DSA_SHAKE_256S   0x0000000aUL
#endif
#ifndef CKP_SLH_DSA_SHA2_256F
#define CKP_SLH_DSA_SHA2_256F    0x0000000bUL
#endif
#ifndef CKP_SLH_DSA_SHAKE_256F
#define CKP_SLH_DSA_SHAKE_256F   0x0000000cUL
#endif

/* FIPS 205 §11 Table 2 + draft-josefsson-ssh-sphincs-02 s4/s6 -- verified
 * against deps/openssl-src/openssl-3.6.3/crypto/slh_dsa/slh_params.c. */
struct slhdsa_variant {
	CK_ULONG	paramset;
	int		keytype;
	const char     *ssh_name;
	const char     *ossl_name;
	size_t		pk_sz;
	size_t		sig_sz;
};

static const struct slhdsa_variant slhdsa_variants[] = {
	{ CKP_SLH_DSA_SHA2_128S,  KEY_SLH_DSA_SHA2_128S,  "ssh-slh-dsa-sha2-128s",  "SLH-DSA-SHA2-128s",  32, 7856 },
	{ CKP_SLH_DSA_SHA2_128F,  KEY_SLH_DSA_SHA2_128F,  "ssh-slh-dsa-sha2-128f",  "SLH-DSA-SHA2-128f",  32, 17088 },
	{ CKP_SLH_DSA_SHAKE_128S, KEY_SLH_DSA_SHAKE_128S, "ssh-slh-dsa-shake-128s", "SLH-DSA-SHAKE-128s", 32, 7856 },
	{ CKP_SLH_DSA_SHAKE_128F, KEY_SLH_DSA_SHAKE_128F, "ssh-slh-dsa-shake-128f", "SLH-DSA-SHAKE-128f", 32, 17088 },
	{ CKP_SLH_DSA_SHA2_256S,  KEY_SLH_DSA_SHA2_256S,  "ssh-slh-dsa-sha2-256s",  "SLH-DSA-SHA2-256s",  64, 29792 },
	{ CKP_SLH_DSA_SHA2_256F,  KEY_SLH_DSA_SHA2_256F,  "ssh-slh-dsa-sha2-256f",  "SLH-DSA-SHA2-256f",  64, 49856 },
	{ CKP_SLH_DSA_SHAKE_256S, KEY_SLH_DSA_SHAKE_256S, "ssh-slh-dsa-shake-256s", "SLH-DSA-SHAKE-256s", 64, 29792 },
	{ CKP_SLH_DSA_SHAKE_256F, KEY_SLH_DSA_SHAKE_256F, "ssh-slh-dsa-shake-256f", "SLH-DSA-SHAKE-256f", 64, 49856 },
};
#define N_SLHDSA_VARIANTS (sizeof(slhdsa_variants) / sizeof(slhdsa_variants[0]))

static const struct slhdsa_variant *
slhdsa_variant_by_paramset(CK_ULONG paramset)
{
	size_t i;
	for (i = 0; i < N_SLHDSA_VARIANTS; i++)
		if (slhdsa_variants[i].paramset == paramset)
			return &slhdsa_variants[i];
	return NULL;
}

/* NOTE: unlike ML-DSA, SLH-DSA parameter sets do NOT have pairwise-distinct
 * public-key sizes (128s/128f share 32 bytes; 256s/256f share 64 bytes; SHA2
 * and SHAKE variants of the same class also share sizes) -- so there is
 * deliberately no by-pklen fallback here. A raw CKA_VALUE without a usable
 * CKA_PARAMETER_SET is genuinely ambiguous for this family. */
static const struct slhdsa_variant *
slhdsa_variant_by_pkey(EVP_PKEY *pkey)
{
	size_t i;
	for (i = 0; i < N_SLHDSA_VARIANTS; i++)
		if (EVP_PKEY_is_a(pkey, slhdsa_variants[i].ossl_name))
			return &slhdsa_variants[i];
	return NULL;
}

static const struct slhdsa_variant *
slhdsa_variant_by_keytype(int keytype)
{
	size_t i;
	for (i = 0; i < N_SLHDSA_VARIANTS; i++)
		if (slhdsa_variants[i].keytype == keytype)
			return &slhdsa_variants[i];
	return NULL;
}

"""

FETCH_MLDSA = r"""
/*
 * pkcs11_fetch_mldsa_pubkey -- draft-sfluhrer-ssh-mldsa-08 s4
 *
 * Covers all 3 ML-DSA parameter sets (CKK_ML_DSA is shared across them; the
 * variant is resolved from the decoded SPKI's own algorithm, or from
 * CKA_PARAMETER_SET / raw-length as fallbacks -- see mldsa_variant_by_*
 * above).
 *
 * Two-path pubkey extraction (softhsmv3 populates both):
 *   1. CKA_PUBLIC_KEY_INFO -- DER SubjectPublicKeyInfo (PKCS#11 v3.2 §4.9).
 *      Parsed via d2i_PUBKEY(); OpenSSL 3.3+ handles ML-DSA SPKI natively.
 *      This is the robust path (self-describing) and is tried first.
 *   2. CKA_VALUE -- raw pk (PKCS#11 v3.2 §6.67.2 Table 280).
 *      Fallback for tokens that populate only raw pk, sized/typed via
 *      CKA_PARAMETER_SET or (ML-DSA only) the raw length itself.
 */
static struct sshkey *
pkcs11_fetch_mldsa_pubkey(struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 key_attr[4];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = NULL;
	CK_RV			 rv;
	struct sshkey		*key = NULL;
	EVP_PKEY		*pkey = NULL;
	int			 success = -1, i;
	const unsigned char	*spki_p;
	CK_ULONG		 paramset = (CK_ULONG)-1;
	const struct mldsa_variant *variant = NULL;

	memset(&key_attr, 0, sizeof(key_attr));
	key_attr[0].type = CKA_ID;
	key_attr[1].type = CKA_PUBLIC_KEY_INFO; /* DER SPKI -- preferred */
	key_attr[2].type = CKA_VALUE;           /* raw pk -- fallback */
	key_attr[3].type = CKA_PARAMETER_SET;   /* selects the variant */

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* Size-probe: missing optional attrs return CKR_ATTRIBUTE_TYPE_INVALID
	 * with ulValueLen=CK_UNAVAILABLE_INFORMATION; we accept either as long as
	 * at least one usable pubkey path (SPKI or raw) was returned. */
	rv = f->C_GetAttributeValue(session, *obj, key_attr, 4);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (probe) failed: %lu", rv);
		return NULL;
	}
	for (i = 1; i < 4; i++)
		if (key_attr[i].ulValueLen == (CK_ULONG)-1)
			key_attr[i].ulValueLen = 0;
	if (key_attr[1].ulValueLen == 0 && key_attr[2].ulValueLen == 0) {
		error_f("no ML-DSA pubkey material on token object");
		return NULL;
	}
	for (i = 0; i < 4; i++)
		if (key_attr[i].ulValueLen > 0)
			key_attr[i].pValue = xcalloc(1, key_attr[i].ulValueLen);
	rv = f->C_GetAttributeValue(session, *obj, key_attr, 4);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (fetch) failed: %lu", rv);
		goto fail;
	}
	if (key_attr[3].ulValueLen == sizeof(CK_ULONG))
		memcpy(&paramset, key_attr[3].pValue, sizeof(CK_ULONG));

	/* Path 1: DER SPKI -- d2i_PUBKEY handles ML-DSA SPKI natively (OpenSSL
	 * 3.3+); self-describing, so the variant comes from the decoded key
	 * itself rather than trusting CKA_PARAMETER_SET blindly. */
	if (key_attr[1].ulValueLen > 0) {
		spki_p = (const unsigned char *)key_attr[1].pValue;
		pkey = d2i_PUBKEY(NULL, &spki_p,
		    (long)key_attr[1].ulValueLen);
		if (pkey == NULL)
			debug_f("d2i_PUBKEY failed on CKA_PUBLIC_KEY_INFO; "
			    "will try CKA_VALUE fallback");
		else
			variant = mldsa_variant_by_pkey(pkey);
	}
	/* Path 2: raw pk fallback -- CKA_PARAMETER_SET first, then raw length
	 * (ML-DSA's 3 sizes are pairwise distinct so this is unambiguous). */
	if (pkey == NULL) {
		if (variant == NULL && paramset != (CK_ULONG)-1)
			variant = mldsa_variant_by_paramset(paramset);
		if (variant == NULL && key_attr[2].ulValueLen > 0)
			variant = mldsa_variant_by_pklen(key_attr[2].ulValueLen);
		if (variant != NULL && key_attr[2].ulValueLen == variant->pk_sz)
			pkey = EVP_PKEY_new_raw_public_key_ex(NULL,
			    variant->ossl_name, NULL, key_attr[2].pValue,
			    key_attr[2].ulValueLen);
	}
	if (pkey == NULL || variant == NULL) {
		error_f("could not materialise ML-DSA pubkey "
		    "(spki=%lu bytes, raw=%lu bytes, paramset=%lu)",
		    (u_long)key_attr[1].ulValueLen,
		    (u_long)key_attr[2].ulValueLen, (u_long)paramset);
		goto fail;
	}
	if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
		fatal_f("sshkey_new failed");
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = NULL;
	key->type = variant->keytype;
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
	for (i = 0; i < 4; i++)
		free(key_attr[i].pValue);
	return key;
}

"""

SIGN_MLDSA = r"""
/*
 * pkcs11_sign_mldsa -- draft-sfluhrer-ssh-mldsa-08
 *
 * Covers all 3 ML-DSA parameter sets; the variant (and hence the wire-format
 * algorithm name + expected signature length) is resolved from key->type,
 * which pkcs11_fetch_mldsa_pubkey set at key-load time.
 *
 * s5. Signature Algorithm
 *   Pure ML-DSA (FIPS 204 s5.2), empty context string.
 *   CKM_ML_DSA (0x1d) NULL_PTR param: full message passed, C_Sign hashes
 *   internally per FIPS 204. The mechanism is the same across all 3
 *   parameter sets -- the token infers the parameter set from the private
 *   key object itself.
 *
 * s6. Signature Format
 *   string  <algorithm name>
 *   string  signature  (raw bytes, sized per parameter set)
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
	const struct mldsa_variant *variant;
	CK_ULONG		 slen;
	CK_RV			 rv;
	u_char			*sig = NULL;
	struct sshbuf		*b = NULL;
	int			 ret = SSH_ERR_INTERNAL_ERROR;

	(void)alg; (void)sk_provider; (void)sk_pin; (void)compat;
	if (sigp != NULL) *sigp = NULL;
	if (lenp != NULL) *lenp = 0;
	if ((variant = mldsa_variant_by_keytype(key->type)) == NULL) {
		error_f("unknown ML-DSA key type %d", key->type);
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if ((k11 = pkcs11_lookup_key(key)) == NULL) {
		error_f("no key found");
		return SSH_ERR_KEY_NOT_FOUND;
	}
	if (pkcs11_get_key(k11, CKM_ML_DSA) == -1)
		return SSH_ERR_AGENT_FAILURE;
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];
	slen = (CK_ULONG)variant->sig_sz;
	sig = xmalloc(slen);
	/* s5: full message to C_Sign -- pure ML-DSA, no pre-hash */
	rv = f->C_Sign(si->session, (CK_BYTE_PTR)data, (CK_ULONG)datalen,
	    sig, &slen);
	if (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		goto done;
	}
	if (slen != variant->sig_sz) {
		error_f("bad signature length: %lu (expected %zu) for %s",
		    (u_long)slen, variant->sig_sz, variant->ssh_name);
		goto done;
	}
	/* s6: wire format */
	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (sshbuf_put_cstring(b, variant->ssh_name) != 0 ||
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

# 5a: insert combined ML-DSA + SLH-DSA constants/tables after crypto_api.h include
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
    "\t\tcase CKK_EC_EDWARDS:\n\t\t\tkey = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\t/* draft-sfluhrer-ssh-mldsa-08 */\n\t\tcase CKK_ML_DSA:\n\t\t\tkey = pkcs11_fetch_mldsa_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\tdefault:"
)

# 5d: insert pkcs11_sign_mldsa before pkcs11_sign()
replace_once(
    "ssh-pkcs11.c",
    r"\nint\npkcs11_sign\(struct sshkey \*key,",
    "\n" + SIGN_MLDSA + "int\npkcs11_sign(struct sshkey *key,"
)

# 5e: add KEY_MLDSA_44/65/87 cases (fallthrough to one call) in pkcs11_sign() switch
replace_once(
    "ssh-pkcs11.c",
    r"\treturn pkcs11_sign_ed25519\(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat\);\n\s*default:",
    "\treturn pkcs11_sign_ed25519(key, sigp, lenp, data, datalen,\n"
    "\t\t    alg, sk_provider, sk_pin, compat);\n"
    "\t/* draft-sfluhrer-ssh-mldsa-08 */\n"
    "\tcase KEY_MLDSA_44:\n\tcase KEY_MLDSA_65:\n\tcase KEY_MLDSA_87:\n"
    "\t\treturn pkcs11_sign_mldsa(key, sigp, lenp, data, datalen,\n"
    "\t\t    alg, sk_provider, sk_pin, compat);\n\tdefault:"
)

# ══════════════════════════════════════════════════════════════════════════════
# SLH-DSA patches (draft-josefsson-ssh-sphincs-02) -- 8 parameter sets.
# These target the ML-DSA-patched file state produced above.
# ══════════════════════════════════════════════════════════════════════════════

FETCH_SLHDSA = r"""
/*
 * pkcs11_fetch_slhdsa_pubkey -- draft-josefsson-ssh-sphincs-02 s4
 *
 * Covers all 8 SLH-DSA parameter sets this connector implements (CKK_SLH_DSA
 * is shared across them). Unlike ML-DSA, SLH-DSA parameter sets do NOT have
 * pairwise-distinct public-key sizes, so the raw CKA_VALUE fallback path
 * requires a usable CKA_PARAMETER_SET -- there is no length-based guess.
 */
static struct sshkey *
pkcs11_fetch_slhdsa_pubkey(struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 key_attr[4];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = NULL;
	CK_RV			 rv;
	struct sshkey		*key = NULL;
	EVP_PKEY		*pkey = NULL;
	int			 success = -1, i;
	const unsigned char	*spki_p;
	CK_ULONG		 paramset = (CK_ULONG)-1;
	const struct slhdsa_variant *variant = NULL;

	memset(&key_attr, 0, sizeof(key_attr));
	key_attr[0].type = CKA_ID;
	key_attr[1].type = CKA_PUBLIC_KEY_INFO;
	key_attr[2].type = CKA_VALUE;
	key_attr[3].type = CKA_PARAMETER_SET;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_GetAttributeValue(session, *obj, key_attr, 4);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (probe) failed: %lu", rv);
		return NULL;
	}
	for (i = 1; i < 4; i++)
		if (key_attr[i].ulValueLen == (CK_ULONG)-1)
			key_attr[i].ulValueLen = 0;
	if (key_attr[1].ulValueLen == 0 && key_attr[2].ulValueLen == 0) {
		error_f("no SLH-DSA pubkey material on token object");
		return NULL;
	}
	for (i = 0; i < 4; i++)
		if (key_attr[i].ulValueLen > 0)
			key_attr[i].pValue = xcalloc(1, key_attr[i].ulValueLen);
	rv = f->C_GetAttributeValue(session, *obj, key_attr, 4);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (fetch) failed: %lu", rv);
		goto fail;
	}
	if (key_attr[3].ulValueLen == sizeof(CK_ULONG))
		memcpy(&paramset, key_attr[3].pValue, sizeof(CK_ULONG));

	/* Path 1: DER SPKI -- self-describing, so prefer it for variant ID. */
	if (key_attr[1].ulValueLen > 0) {
		spki_p = (const unsigned char *)key_attr[1].pValue;
		pkey = d2i_PUBKEY(NULL, &spki_p,
		    (long)key_attr[1].ulValueLen);
		if (pkey == NULL)
			debug_f("d2i_PUBKEY failed; trying CKA_VALUE fallback");
		else
			variant = slhdsa_variant_by_pkey(pkey);
	}
	/* Path 2: raw pk fallback -- REQUIRES CKA_PARAMETER_SET (sizes are
	 * ambiguous across this family's parameter sets; see the comment on
	 * slhdsa_variant_by_pkey above). */
	if (pkey == NULL) {
		if (variant == NULL && paramset != (CK_ULONG)-1)
			variant = slhdsa_variant_by_paramset(paramset);
		if (variant != NULL && key_attr[2].ulValueLen == variant->pk_sz)
			pkey = EVP_PKEY_new_raw_public_key_ex(NULL,
			    variant->ossl_name, NULL, key_attr[2].pValue,
			    key_attr[2].ulValueLen);
	}
	if (pkey == NULL || variant == NULL) {
		error_f("could not materialise SLH-DSA pubkey "
		    "(spki=%lu bytes, raw=%lu bytes, paramset=%lu)",
		    (u_long)key_attr[1].ulValueLen,
		    (u_long)key_attr[2].ulValueLen, (u_long)paramset);
		goto fail;
	}
	if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
		fatal_f("sshkey_new failed");
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = NULL;
	key->type = variant->keytype;
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
	for (i = 0; i < 4; i++)
		free(key_attr[i].pValue);
	return key;
}

"""

SIGN_SLHDSA = r"""
/*
 * pkcs11_sign_slhdsa -- draft-josefsson-ssh-sphincs-02
 *
 * Covers all 8 SLH-DSA parameter sets; the variant is resolved from
 * key->type exactly as pkcs11_sign_mldsa does.
 *
 * s5. Signature Algorithm
 *   Pure SLH-DSA (FIPS 205 §9.2), empty context string.
 *   CKM_SLH_DSA (0x2e) NULL_PTR param: full message to C_Sign.
 *
 * s6. Signature Format
 *   string  <algorithm name>
 *   string  signature  (raw bytes, sized per parameter set)
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
	const struct slhdsa_variant *variant;
	CK_ULONG		 slen;
	CK_RV			 rv;
	u_char			*sig = NULL;
	struct sshbuf		*b = NULL;
	int			 ret = SSH_ERR_INTERNAL_ERROR;

	(void)alg; (void)sk_provider; (void)sk_pin; (void)compat;
	if (sigp != NULL) *sigp = NULL;
	if (lenp != NULL) *lenp = 0;
	if ((variant = slhdsa_variant_by_keytype(key->type)) == NULL) {
		error_f("unknown SLH-DSA key type %d", key->type);
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if ((k11 = pkcs11_lookup_key(key)) == NULL) {
		error_f("no key found");
		return SSH_ERR_KEY_NOT_FOUND;
	}
	if (pkcs11_get_key(k11, CKM_SLH_DSA) == -1)
		return SSH_ERR_AGENT_FAILURE;
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];
	slen = (CK_ULONG)variant->sig_sz;
	sig = xmalloc(slen);
	rv = f->C_Sign(si->session, (CK_BYTE_PTR)data, (CK_ULONG)datalen,
	    sig, &slen);
	if (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		goto done;
	}
	if (slen != variant->sig_sz) {
		error_f("bad signature length: %lu (expected %zu) for %s",
		    (u_long)slen, variant->sig_sz, variant->ssh_name);
		goto done;
	}
	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (sshbuf_put_cstring(b, variant->ssh_name) != 0 ||
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

# S5b: insert pkcs11_fetch_slhdsa_pubkey after pkcs11_fetch_mldsa_pubkey (same
# anchor as 5b -- still present, now shifted past the ML-DSA fetch function).
replace_once(
    "ssh-pkcs11.c",
    r"\n#\s*ifdef WITH_OPENSSL /\* libcrypto needed for certificate parsing \*/",
    "\n" + FETCH_SLHDSA + "# ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */"
)

# S5c: add CKK_SLH_DSA case in pkcs11_fetch_keys() after CKK_ML_DSA case
replace_once(
    "ssh-pkcs11.c",
    r"\t\t/\* draft-sfluhrer-ssh-mldsa-08 \*/\n\t\tcase CKK_ML_DSA:\n\t\t\tkey = pkcs11_fetch_mldsa_pubkey\(p, slotidx, &obj\);\n\t\t\tbreak;\n\t\tdefault:",
    "\t\t/* draft-sfluhrer-ssh-mldsa-08 */\n\t\tcase CKK_ML_DSA:\n\t\t\tkey = pkcs11_fetch_mldsa_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\t/* draft-josefsson-ssh-sphincs-02 */\n\t\tcase CKK_SLH_DSA:\n\t\t\tkey = pkcs11_fetch_slhdsa_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\tdefault:"
)

# S5d: insert pkcs11_sign_slhdsa before pkcs11_sign() (same anchor as 5d --
# still present, now shifted past pkcs11_sign_mldsa).
replace_once(
    "ssh-pkcs11.c",
    r"\nint\npkcs11_sign\(struct sshkey \*key,",
    "\n" + SIGN_SLHDSA + "int\npkcs11_sign(struct sshkey *key,"
)

# S5e: add the 8 SLH-DSA cases (fallthrough to one call) after the ML-DSA cases
replace_once(
    "ssh-pkcs11.c",
    r"\t/\* draft-sfluhrer-ssh-mldsa-08 \*/\n\tcase KEY_MLDSA_44:\n\tcase KEY_MLDSA_65:\n\tcase KEY_MLDSA_87:\n\t\treturn pkcs11_sign_mldsa\(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat\);\n\tdefault:",
    "\t/* draft-sfluhrer-ssh-mldsa-08 */\n"
    "\tcase KEY_MLDSA_44:\n\tcase KEY_MLDSA_65:\n\tcase KEY_MLDSA_87:\n"
    "\t\treturn pkcs11_sign_mldsa(key, sigp, lenp, data, datalen,\n"
    "\t\t    alg, sk_provider, sk_pin, compat);\n"
    "\t/* draft-josefsson-ssh-sphincs-02 */\n"
    "\tcase KEY_SLH_DSA_SHA2_128S:\n\tcase KEY_SLH_DSA_SHA2_128F:\n"
    "\tcase KEY_SLH_DSA_SHAKE_128S:\n\tcase KEY_SLH_DSA_SHAKE_128F:\n"
    "\tcase KEY_SLH_DSA_SHA2_256S:\n\tcase KEY_SLH_DSA_SHA2_256F:\n"
    "\tcase KEY_SLH_DSA_SHAKE_256S:\n\tcase KEY_SLH_DSA_SHAKE_256F:\n"
    "\t\treturn pkcs11_sign_slhdsa(key, sigp, lenp, data, datalen,\n"
    "\t\t    alg, sk_provider, sk_pin, compat);\n\tdefault:"
)

# ── S3. sshkey.h — 8 SLH-DSA key types after the 3 ML-DSA ones ───────────────
replace_once(
    "sshkey.h",
    r"\tKEY_MLDSA_87,\n\s+KEY_UNSPEC",
    "\tKEY_MLDSA_87,\n"
    "\tKEY_SLH_DSA_SHA2_128S,\n\tKEY_SLH_DSA_SHA2_128F,\n"
    "\tKEY_SLH_DSA_SHAKE_128S,\n\tKEY_SLH_DSA_SHAKE_128F,\n"
    "\tKEY_SLH_DSA_SHA2_256S,\n\tKEY_SLH_DSA_SHA2_256F,\n"
    "\tKEY_SLH_DSA_SHAKE_256S,\n\tKEY_SLH_DSA_SHAKE_256F,\n"
    "\tKEY_UNSPEC"
)

# ── S4. sshkey.c — extern + register the 8 SLH-DSA impls ─────────────────────
replace_once(
    "sshkey.c",
    r"extern const struct sshkey_impl sshkey_mldsa87_impl;\n",
    "extern const struct sshkey_impl sshkey_mldsa87_impl;\n"
    "extern const struct sshkey_impl sshkey_slhdsa_sha2_128s_impl;\n"
    "extern const struct sshkey_impl sshkey_slhdsa_sha2_128f_impl;\n"
    "extern const struct sshkey_impl sshkey_slhdsa_shake_128s_impl;\n"
    "extern const struct sshkey_impl sshkey_slhdsa_shake_128f_impl;\n"
    "extern const struct sshkey_impl sshkey_slhdsa_sha2_256s_impl;\n"
    "extern const struct sshkey_impl sshkey_slhdsa_sha2_256f_impl;\n"
    "extern const struct sshkey_impl sshkey_slhdsa_shake_256s_impl;\n"
    "extern const struct sshkey_impl sshkey_slhdsa_shake_256f_impl;\n"
)
replace_once(
    "sshkey.c",
    r"&sshkey_mldsa87_impl,\n# ifdef ENABLE_SK",
    "&sshkey_mldsa87_impl,\n\n"
    "\t&sshkey_slhdsa_sha2_128s_impl,\n"
    "\t&sshkey_slhdsa_sha2_128f_impl,\n"
    "\t&sshkey_slhdsa_shake_128s_impl,\n"
    "\t&sshkey_slhdsa_shake_128f_impl,\n"
    "\t&sshkey_slhdsa_sha2_256s_impl,\n"
    "\t&sshkey_slhdsa_sha2_256f_impl,\n"
    "\t&sshkey_slhdsa_shake_256s_impl,\n"
    "\t&sshkey_slhdsa_shake_256f_impl,\n"
    "# ifdef ENABLE_SK"
)

# ── S2. myproposal.h — 8 SLH-DSA names after the 3 ML-DSA ones ───────────────
replace_once(
    "myproposal.h",
    r'"ssh-mldsa-87," \\\n\t"ssh-ed25519-cert-v01@openssh\.com,"',
    '"ssh-mldsa-87," \\\n'
    '\t"ssh-slh-dsa-sha2-128s," \\\n'
    '\t"ssh-slh-dsa-sha2-128f," \\\n'
    '\t"ssh-slh-dsa-shake-128s," \\\n'
    '\t"ssh-slh-dsa-shake-128f," \\\n'
    '\t"ssh-slh-dsa-sha2-256s," \\\n'
    '\t"ssh-slh-dsa-sha2-256f," \\\n'
    '\t"ssh-slh-dsa-shake-256s," \\\n'
    '\t"ssh-slh-dsa-shake-256f," \\\n'
    '\t"ssh-ed25519-cert-v01@openssh.com,"'
)

# ── S1. Makefile.in — add ssh-slhdsa.o ───────────────────────────────────────
replace_once(
    "Makefile.in",
    r"\tssh-mldsa\.o msg\.o",
    r"	ssh-mldsa.o ssh-slhdsa.o msg.o"
)

# ── S6. sshd-auth.c — list_hostkey_types() covers all 11 new key types ───────
# list_hostkey_types() has a switch that only covers RSA/ECDSA/ED25519/SK types.
# Without these cases, the server never advertises the new algorithms as host
# key algorithms even when the key is loaded from the agent via HostKeyAgent.
replace_once(
    "sshd-auth.c",
    r"\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t\tappend_hostkey_type\(b, sshkey_ssh_name\(key\)\);\n\t\t\tbreak;",
    "\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n"
    "\t\t/* draft-sfluhrer-ssh-mldsa-08: agent-backed ML-DSA host keys */\n"
    "\t\tcase KEY_MLDSA_44:\n\t\tcase KEY_MLDSA_65:\n\t\tcase KEY_MLDSA_87:\n"
    "\t\t/* draft-josefsson-ssh-sphincs-02: agent-backed SLH-DSA host keys */\n"
    "\t\tcase KEY_SLH_DSA_SHA2_128S:\n\t\tcase KEY_SLH_DSA_SHA2_128F:\n"
    "\t\tcase KEY_SLH_DSA_SHAKE_128S:\n\t\tcase KEY_SLH_DSA_SHAKE_128F:\n"
    "\t\tcase KEY_SLH_DSA_SHA2_256S:\n\t\tcase KEY_SLH_DSA_SHA2_256F:\n"
    "\t\tcase KEY_SLH_DSA_SHAKE_256S:\n\t\tcase KEY_SLH_DSA_SHAKE_256F:\n"
    "\t\t\tappend_hostkey_type(b, sshkey_ssh_name(key));\n\t\t\tbreak;"
)

# ── S7. sshd.c — have_ssh2_key switch covers all 11 new key types ────────────
# When sshd loads a HostKey that is only backed by the agent (pubkey-only,
# no private key file), it checks the keytype in a switch to set have_ssh2_key=1.
# Without these cases, sshd exits with "no hostkeys available" when the only
# configured HostKey is one of the new agent-only PQC types.
replace_once(
    "sshd.c",
    r"\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t\tif \(have_agent \|\| key != NULL\)\n\t\t\t\tsensitive_data\.have_ssh2_key = 1;\n\t\t\tbreak;",
    "\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n"
    "\t\t/* draft-sfluhrer-ssh-mldsa-08 */\n"
    "\t\tcase KEY_MLDSA_44:\n\t\tcase KEY_MLDSA_65:\n\t\tcase KEY_MLDSA_87:\n"
    "\t\t/* draft-josefsson-ssh-sphincs-02 */\n"
    "\t\tcase KEY_SLH_DSA_SHA2_128S:\n\t\tcase KEY_SLH_DSA_SHA2_128F:\n"
    "\t\tcase KEY_SLH_DSA_SHAKE_128S:\n\t\tcase KEY_SLH_DSA_SHAKE_128F:\n"
    "\t\tcase KEY_SLH_DSA_SHA2_256S:\n\t\tcase KEY_SLH_DSA_SHA2_256F:\n"
    "\t\tcase KEY_SLH_DSA_SHAKE_256S:\n\t\tcase KEY_SLH_DSA_SHAKE_256F:\n"
    "\t\t\tif (have_agent || key != NULL)\n\t\t\t\tsensitive_data.have_ssh2_key = 1;\n\t\t\tbreak;"
)

print("All patches applied successfully (ML-DSA-44/65/87 + 8 SLH-DSA parameter sets).")
print("Next: ensure ssh-mldsa.c AND ssh-slhdsa.c are in the source tree "
      "(Makefile.in now references both objects), then "
      "autoreconf -i && ./configure ... && make")
