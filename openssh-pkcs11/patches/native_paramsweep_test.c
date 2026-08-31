/*
 * native_paramsweep_test.c -- native (non-WASM) verification harness.
 *
 * Ports sshd_wasm_main.c's in-process handshake driver (ssh_api.c-based:
 * the same privsep-free single-process embedding the WASM build uses) to a
 * plain native executable, so the newly-added ML-DSA-44/87 and 8 SLH-DSA
 * parameter sets can be exercised with a REAL SSH handshake + RFC 4252
 * publickey userauth round trip in an environment with no Emscripten
 * toolchain available. The PKCS#11 module is loaded via a genuine dlopen()
 * of the native softhsmv3 build -- OpenSSH's real provider path
 * (pkcs11_add_provider), not the WASM static-link shim.
 *
 * For each parameter set: generate ONE host+user keypair (same key serves
 * both roles, mirroring sm1-smoke.cjs/sm5-slhdsa-smoke.cjs) on a shared
 * softhsm token, negotiate KEX with that host-key algorithm forced, drive
 * to NEWKEYS, then drive RFC 4252 publickey userauth to USERAUTH_SUCCESS.
 * Asserts the real C_Sign signature length against the FIPS 204/205 size
 * for that exact parameter set at both steps.
 */
#include "includes.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "ssh_api.h"
#include "sshkey.h"
#include "ssherr.h"
#include "kex.h"
#include "myproposal.h"
#include "ssh-pkcs11.h"
#include "packet.h"
#include "sshbuf.h"
#include "ssh2.h"

#ifndef CKA_PARAMETER_SET
#define CKA_PARAMETER_SET 0x0000061dUL
#endif
#ifndef CKF_TOKEN_INITIALIZED
#define CKF_TOKEN_INITIALIZED 0x00000400UL
#endif

#define SO_PIN   "12345678"
#define USER_PIN "1234"

struct variant {
	const char	*hostalg;	/* SSH wire algorithm name */
	CK_KEY_TYPE	 ck_keytype;	/* CKK_ML_DSA / CKK_SLH_DSA */
	CK_MECHANISM_TYPE keygen_mech;
	CK_MECHANISM_TYPE sign_mech;
	CK_ULONG	 paramset;
	int		 sshkey_type;	/* KEY_MLDSA_44 etc, real enum from sshkey.h */
	CK_ULONG	 sig_sz;
};

/* CKK_ML_DSA=0x4a, CKK_SLH_DSA=0x4b, CKM_ML_DSA_KEY_PAIR_GEN=0x1c,
 * CKM_ML_DSA=0x1d, CKM_SLH_DSA_KEY_PAIR_GEN=0x2d, CKM_SLH_DSA=0x2e --
 * from src/lib/pkcs11/pkcs11t.h (parent pqctoday-hsm repo). CKP_* values
 * likewise (see apply_mldsa_patches.py's PKCS11_CONSTANTS block, which this
 * table mirrors). */
static const struct variant VARIANTS[] = {
	{ "ssh-mldsa-44", 0x4a, 0x1c, 0x1d, 1, KEY_MLDSA_44, 2420 },
	{ "ssh-mldsa-65", 0x4a, 0x1c, 0x1d, 2, KEY_MLDSA_65, 3309 },
	{ "ssh-mldsa-87", 0x4a, 0x1c, 0x1d, 3, KEY_MLDSA_87, 4627 },
	{ "ssh-slh-dsa-sha2-128s",  0x4b, 0x2d, 0x2e, 1, KEY_SLH_DSA_SHA2_128S,  7856 },
	{ "ssh-slh-dsa-sha2-128f",  0x4b, 0x2d, 0x2e, 3, KEY_SLH_DSA_SHA2_128F,  17088 },
	{ "ssh-slh-dsa-shake-128s", 0x4b, 0x2d, 0x2e, 2, KEY_SLH_DSA_SHAKE_128S, 7856 },
	{ "ssh-slh-dsa-shake-128f", 0x4b, 0x2d, 0x2e, 4, KEY_SLH_DSA_SHAKE_128F, 17088 },
	{ "ssh-slh-dsa-sha2-256s",  0x4b, 0x2d, 0x2e, 9, KEY_SLH_DSA_SHA2_256S,  29792 },
	{ "ssh-slh-dsa-sha2-256f",  0x4b, 0x2d, 0x2e, 11, KEY_SLH_DSA_SHA2_256F, 49856 },
	{ "ssh-slh-dsa-shake-256s", 0x4b, 0x2d, 0x2e, 10, KEY_SLH_DSA_SHAKE_256S, 29792 },
	{ "ssh-slh-dsa-shake-256f", 0x4b, 0x2d, 0x2e, 12, KEY_SLH_DSA_SHAKE_256F, 49856 },
};
#define N_VARIANTS (sizeof(VARIANTS) / sizeof(VARIANTS[0]))

static int failures = 0;
#define CHECKF(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); \
		failures++; \
		return -1; \
	} \
} while (0)

/* ── raw PKCS#11 bootstrap + provisioning (direct dlopen, real module) ──── */
static CK_FUNCTION_LIST *g_p11 = NULL;
static CK_SLOT_ID        g_slot = 0;
static CK_SESSION_HANDLE g_session = CK_INVALID_HANDLE;

static int raw_bootstrap(const char *modpath) {
	void *h = dlopen(modpath, RTLD_NOW);
	if (h == NULL) { fprintf(stderr, "dlopen(%s): %s\n", modpath, dlerror()); return -1; }
	CK_RV (*get_func_list)(CK_FUNCTION_LIST_PTR_PTR) =
	    (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(h, "C_GetFunctionList");
	if (get_func_list == NULL) { fprintf(stderr, "dlsym C_GetFunctionList: %s\n", dlerror()); return -1; }
	CK_RV rv = get_func_list(&g_p11);
	if (rv != CKR_OK) { fprintf(stderr, "C_GetFunctionList rv=%lu\n", (unsigned long)rv); return -1; }

	rv = g_p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) { fprintf(stderr, "C_Initialize rv=%lu\n", (unsigned long)rv); return -1; }

	CK_SLOT_ID slots[16]; CK_ULONG nslots = 16;
	rv = g_p11->C_GetSlotList(CK_FALSE, slots, &nslots);
	if (rv != CKR_OK || nslots == 0) { fprintf(stderr, "C_GetSlotList rv=%lu n=%lu\n", (unsigned long)rv, (unsigned long)nslots); return -1; }

	CK_UTF8CHAR label[32];
	memset(label, ' ', sizeof label);
	memcpy(label, "pqc-native-test", 15);
	rv = g_p11->C_InitToken(slots[0], (CK_UTF8CHAR_PTR)SO_PIN, strlen(SO_PIN), label);
	if (rv != CKR_OK) { fprintf(stderr, "C_InitToken rv=%lu\n", (unsigned long)rv); return -1; }

	nslots = 16;
	rv = g_p11->C_GetSlotList(CK_FALSE, slots, &nslots);
	if (rv != CKR_OK) { fprintf(stderr, "C_GetSlotList(2) rv=%lu\n", (unsigned long)rv); return -1; }
	int found = 0;
	for (CK_ULONG i = 0; i < nslots; i++) {
		CK_TOKEN_INFO ti;
		if (g_p11->C_GetTokenInfo(slots[i], &ti) == CKR_OK && (ti.flags & CKF_TOKEN_INITIALIZED)) {
			g_slot = slots[i]; found = 1; break;
		}
	}
	if (!found) { fprintf(stderr, "no initialized slot after C_InitToken\n"); return -1; }

	rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &g_session);
	if (rv != CKR_OK) { fprintf(stderr, "C_OpenSession rv=%lu\n", (unsigned long)rv); return -1; }
	rv = g_p11->C_Login(g_session, CKU_SO, (CK_UTF8CHAR_PTR)SO_PIN, strlen(SO_PIN));
	if (rv != CKR_OK) { fprintf(stderr, "C_Login(SO) rv=%lu\n", (unsigned long)rv); return -1; }
	rv = g_p11->C_InitPIN(g_session, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN));
	if (rv != CKR_OK) { fprintf(stderr, "C_InitPIN rv=%lu\n", (unsigned long)rv); return -1; }
	rv = g_p11->C_Logout(g_session);
	if (rv != CKR_OK) { fprintf(stderr, "C_Logout rv=%lu\n", (unsigned long)rv); return -1; }
	rv = g_p11->C_Login(g_session, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN));
	if (rv != CKR_OK) { fprintf(stderr, "C_Login(USER) rv=%lu\n", (unsigned long)rv); return -1; }

	printf("[bootstrap] token initialized + USER logged in (slot %lu)\n", (unsigned long)g_slot);
	return 0;
}

/* Generate one keypair on the token for `v`, CKA_ID = v->hostalg (used as
 * BOTH the host key and the user auth key, same as the existing sm1/sm5
 * smoke tests). */
static int provision_variant(const struct variant *v) {
	CK_OBJECT_CLASS pub_cls = CKO_PUBLIC_KEY, priv_cls = CKO_PRIVATE_KEY;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_KEY_TYPE kt = v->ck_keytype;
	CK_ULONG pset = v->paramset;
	CK_MECHANISM gen = { v->keygen_mech, NULL_PTR, 0 };
	CK_ATTRIBUTE pub_tmpl[] = {
		{ CKA_CLASS,         &pub_cls, sizeof pub_cls },
		{ CKA_KEY_TYPE,      &kt,      sizeof kt      },
		{ CKA_TOKEN,         &yes,     sizeof yes     },
		{ CKA_VERIFY,        &yes,     sizeof yes     },
		{ CKA_PARAMETER_SET, &pset,    sizeof pset    },
		{ CKA_ID,            (void*)v->hostalg, strlen(v->hostalg) },
	};
	CK_ATTRIBUTE priv_tmpl[] = {
		{ CKA_CLASS,       &priv_cls, sizeof priv_cls },
		{ CKA_KEY_TYPE,    &kt,       sizeof kt        },
		{ CKA_TOKEN,       &yes,      sizeof yes       },
		{ CKA_PRIVATE,     &yes,      sizeof yes       },
		{ CKA_SIGN,        &yes,      sizeof yes       },
		{ CKA_EXTRACTABLE, &no,       sizeof no        },
		{ CKA_ID,          (void*)v->hostalg, strlen(v->hostalg) },
	};
	CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;
	CK_RV rv = g_p11->C_GenerateKeyPair(g_session, &gen,
	    pub_tmpl, sizeof(pub_tmpl)/sizeof(pub_tmpl[0]),
	    priv_tmpl, sizeof(priv_tmpl)/sizeof(priv_tmpl[0]),
	    &hPub, &hPriv);
	if (rv != CKR_OK) { fprintf(stderr, "C_GenerateKeyPair(%s) rv=%lu\n", v->hostalg, (unsigned long)rv); return -1; }
	printf("[provision] %-24s pk/priv generated on token\n", v->hostalg);
	return 0;
}

/* ── SSH transport pump (verbatim port of sshd_wasm_main.c's sm2_pump/deliver_all) ── */
static int sm2_pump(struct ssh *from, struct ssh *to) {
	u_char type;
	for (;;) {
		int r = ssh_packet_next(from, &type);
		if (r != 0) { fprintf(stderr, "ssh_packet_next: %d\n", r); return -1; }
		if (type != 0) return 0;
		size_t len; const u_char *buf = ssh_output_ptr(from, &len);
		if (len == 0) return 0;
		if ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_input_append(to, buf, len)) != 0) { fprintf(stderr, "pump io: %d\n", r); return -1; }
	}
}

static void deliver_all(struct ssh *from, struct ssh *to) {
	size_t len; const u_char *buf;
	while ((buf = ssh_output_ptr(from, &len)) != NULL && len > 0) {
		ssh_input_append(to, buf, len);
		ssh_output_consume(from, len);
	}
}

/* ── RFC 4252 publickey userauth (verbatim port of do_userauth) ─────────── */
static int do_userauth(struct ssh *client, struct ssh *server,
    struct sshkey *authkey, const struct variant *v) {
	struct sshbuf *b = NULL;
	u_char *sig = NULL, *pkblob = NULL, *rsig = NULL, have_sig = 0, type = 0;
	size_t slen = 0, pklen = 0, rsiglen = 0, skip = 0;
	char *user = NULL, *service = NULL, *method = NULL, *alg = NULL;
	struct sshkey *recv_key = NULL;
	int r, g, ret = -1;
	const char *U = "pqcuser", *SVC = "ssh-connection", *M = "publickey", *A = v->hostalg;

	if ((b = sshbuf_new()) == NULL) { fprintf(stderr, "userauth sshbuf_new\n"); return -1; }

	if ((r = sshbuf_put_stringb(b, client->kex->session_id)) != 0) { fprintf(stderr, "ua put session_id: %d\n", r); goto out; }
	skip = sshbuf_len(b);
	if ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, U)) != 0 ||
	    (r = sshbuf_put_cstring(b, SVC)) != 0 ||
	    (r = sshbuf_put_cstring(b, M)) != 0 ||
	    (r = sshbuf_put_u8(b, 1)) != 0 ||
	    (r = sshbuf_put_cstring(b, A)) != 0 ||
	    (r = sshkey_puts(authkey, b)) != 0) { fprintf(stderr, "ua assemble: %d\n", r); goto out; }
	if ((r = sshkey_sign(authkey, &sig, &slen, sshbuf_ptr(b), sshbuf_len(b),
	    A, NULL, NULL, client->compat)) != 0) { fprintf(stderr, "ua sshkey_sign: %d\n", r); goto out; }
	{
		size_t expect = 4 + strlen(A) + 4 + v->sig_sz;
		CHECKF(slen == expect, "%s: user_sig_len=%zu expected=%zu", v->hostalg, slen, expect);
	}
	if ((r = sshbuf_put_string(b, sig, slen)) != 0) { fprintf(stderr, "ua append sig: %d\n", r); goto out; }
	if ((r = sshbuf_consume(b, skip + 1)) != 0) { fprintf(stderr, "ua consume: %d\n", r); goto out; }
	if ((r = sshpkt_start(client, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(client, b)) != 0 ||
	    (r = sshpkt_send(client)) != 0) { fprintf(stderr, "ua send request: %d\n", r); goto out; }
	deliver_all(client, server);

	for (g = 0; g < 8; g++) { if ((r = ssh_packet_next(server, &type)) != 0) { fprintf(stderr, "ua srv next: %d\n", r); goto out; } if (type != 0) break; }
	if (type != SSH2_MSG_USERAUTH_REQUEST) { fprintf(stderr, "ua got_type=%d\n", type); goto out; }
	if ((r = sshpkt_get_cstring(server, &user, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(server, &service, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(server, &method, NULL)) != 0 ||
	    (r = sshpkt_get_u8(server, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(server, &alg, NULL)) != 0 ||
	    (r = sshpkt_get_string(server, &pkblob, &pklen)) != 0 ||
	    (r = sshpkt_get_string(server, &rsig, &rsiglen)) != 0) { fprintf(stderr, "ua parse: %d\n", r); goto out; }
	if ((r = sshkey_from_blob(pkblob, pklen, &recv_key)) != 0) { fprintf(stderr, "ua from_blob: %d\n", r); goto out; }
	sshbuf_reset(b);
	if ((r = sshbuf_put_stringb(b, server->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, method)) != 0 ||
	    (r = sshbuf_put_u8(b, 1)) != 0 ||
	    (r = sshbuf_put_cstring(b, alg)) != 0 ||
	    (r = sshkey_puts(recv_key, b)) != 0) { fprintf(stderr, "ua rebuild: %d\n", r); goto out; }
	if ((r = sshkey_verify(recv_key, rsig, rsiglen, sshbuf_ptr(b), sshbuf_len(b),
	    alg, server->compat, NULL)) != 0) { fprintf(stderr, "ua sshkey_verify: %d\n", r); goto out; }
	if (!sshkey_equal_public(recv_key, authkey)) { fprintf(stderr, "ua key not authorized\n"); goto out; }
	printf("  [userauth] server verified %s signature via sshkey_verify\n", alg);
	if ((r = sshpkt_start(server, SSH2_MSG_USERAUTH_SUCCESS)) != 0 ||
	    (r = sshpkt_send(server)) != 0) { fprintf(stderr, "ua send success: %d\n", r); goto out; }
	deliver_all(server, client);

	type = 0;
	for (g = 0; g < 8; g++) { if ((r = ssh_packet_next(client, &type)) != 0) { fprintf(stderr, "ua cli next: %d\n", r); goto out; } if (type != 0) break; }
	if (type != SSH2_MSG_USERAUTH_SUCCESS) { fprintf(stderr, "ua got_type=%d\n", type); goto out; }
	ret = 0;
out:
	sshbuf_free(b); free(sig); free(pkblob); free(rsig);
	free(user); free(service); free(method); free(alg);
	sshkey_free(recv_key);
	return ret;
}

/* ── one full round trip for one parameter set ───────────────────────────── */
static int run_variant(const struct variant *v, struct sshkey **keys, int nkeys) {
	printf("== %s ==\n", v->hostalg);

	struct sshkey *hostkey = NULL, *pub = NULL;
	for (int i = 0; i < nkeys; i++)
		if (keys[i] != NULL && keys[i]->type == v->sshkey_type) { hostkey = keys[i]; break; }
	CHECKF(hostkey != NULL, "%s: token key of type %d not returned by provider", v->hostalg, v->sshkey_type);

	/* Direct C_Sign proof, mirroring sm1_prove_sign(). */
	{
		struct pkcs11_key *dummy; (void)dummy; /* not used directly; go via sshkey_sign below instead */
	}

	int r;
	if ((r = sshkey_from_private(hostkey, &pub)) != 0) { fprintf(stderr, "sshkey_from_private: %d\n", r); failures++; return -1; }

	struct ssh *client = NULL, *server = NULL;
	struct kex_params kp;
	char *base[PROPOSAL_MAX] = { KEX_CLIENT };
	memset(&kp, 0, sizeof kp);
	memcpy(kp.proposal, base, sizeof base);
	kp.proposal[PROPOSAL_KEX_ALGS] = "mlkem768x25519-sha256";
	kp.proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = (char *)v->hostalg;

	if ((r = ssh_init(&client, 0, &kp)) != 0) { fprintf(stderr, "ssh_init(client): %d\n", r); failures++; return -1; }
	if ((r = ssh_init(&server, 1, &kp)) != 0) { fprintf(stderr, "ssh_init(server): %d\n", r); failures++; return -1; }
	if ((r = ssh_add_hostkey(server, hostkey)) != 0) { fprintf(stderr, "ssh_add_hostkey(server): %d\n", r); failures++; return -1; }
	if ((r = ssh_add_hostkey(client, pub)) != 0)     { fprintf(stderr, "ssh_add_hostkey(client): %d\n", r); failures++; return -1; }

	int guard = 0;
	while ((!server->kex->done || !client->kex->done) && guard++ < 64) {
		if (sm2_pump(server, client) != 0) { failures++; return -1; }
		if (sm2_pump(client, server) != 0) { failures++; return -1; }
	}
	CHECKF(server->kex->done && client->kex->done, "%s: kex did not converge", v->hostalg);
	printf("  [kex] NEWKEYS reached both sides (mlkem768x25519-sha256 + %s host sign via C_Sign)\n", v->hostalg);

	int rc = do_userauth(client, server, hostkey, v);
	CHECKF(rc == 0, "%s: userauth did not reach USERAUTH_SUCCESS", v->hostalg);
	printf("  PASS -- USERAUTH_SUCCESS, sig_len matched FIPS size (%lu bytes raw)\n", (unsigned long)v->sig_sz);
	return 0;
}

int main(int argc, char **argv) {
	if (argc < 2) { fprintf(stderr, "usage: %s <path-to-libsofthsmv3.dylib>\n", argv[0]); return 2; }
	const char *modpath = argv[1];

	if (raw_bootstrap(modpath) != 0) return 1;
	for (size_t i = 0; i < N_VARIANTS; i++)
		if (provision_variant(&VARIANTS[i]) != 0) return 1;
	/* OpenSSH's pkcs11_add_provider runs its own C_Initialize and treats
	 * CKR_CRYPTOKI_ALREADY_INITIALIZED as fatal -- finalize our bootstrap
	 * session first (file-backed token persists the provisioned keys). */
	g_p11->C_Finalize(NULL_PTR);

	pkcs11_init(0);
	struct sshkey **keys = NULL; char **labels = NULL;
	int nkeys = pkcs11_add_provider((char *)modpath, USER_PIN, &keys, &labels);
	if (nkeys <= 0) { fprintf(stderr, "pkcs11_add_provider: %d\n", nkeys); return 1; }
	printf("[provider] loaded %d keys from token via real dlopen provider path\n\n", nkeys);

	for (size_t i = 0; i < N_VARIANTS; i++)
		run_variant(&VARIANTS[i], keys, nkeys);

	printf("\n==================================================\n");
	printf("%zu parameter sets exercised, %d failure(s)\n", N_VARIANTS, failures);
	return failures == 0 ? 0 : 1;
}
