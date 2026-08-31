/*
 * Copyright (C) 2026 PQC Timeline Project
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#include "pkcs11_kem.h"

#include <utils/debug.h>
#include <library.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>

#include "pkcs11_manager.h"

typedef struct private_pkcs11_kem_t private_pkcs11_kem_t;

/**
 * Private data of a pkcs11_kem_t object.
 */
struct private_pkcs11_kem_t {
	/** Public interface */
	pkcs11_kem_t public;

	/** PKCS#11 library */
	pkcs11_library_t *lib;

	/** Session handle */
	CK_SESSION_HANDLE session;

	/** KEM Group / Algorithm */
	key_exchange_method_t group;

	/** Handle for own private key */
	CK_OBJECT_HANDLE pri_key;

	/** Public key */
	chunk_t pub_key;

	/** Ciphertext to send/receive */
	chunk_t ciphertext;

	/** Shared secret */
	chunk_t secret;

	/** Mechanism to use to generate a key pair */
	CK_MECHANISM_TYPE mech_key;

	/** Mechanism to use for encapsulation/decapsulation */
	CK_MECHANISM_TYPE mech_encap;
};

/**
 * Finds a token supporting the requested mechanism.
 */
static pkcs11_library_t *find_token(private_pkcs11_kem_t *this, CK_SESSION_HANDLE *session)
{
	enumerator_t *tokens, *mechs;
	pkcs11_manager_t *manager;
	pkcs11_library_t *current, *found = NULL;
	CK_MECHANISM_TYPE type;
	CK_SLOT_ID slot;

	manager = lib->get(lib, "pkcs11-manager");
	if (!manager) {
		return NULL;
	}
	tokens = manager->create_token_enumerator(manager);
	while (tokens->enumerate(tokens, &current, &slot)) {
		mechs = current->create_mechanism_enumerator(current, slot);
		while (mechs->enumerate(mechs, &type, NULL)) {
			/* Look for proper KEM mechanism support */
			if (type == this->mech_encap) {
				if (current->f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, session) == CKR_OK) {
#ifdef __EMSCRIPTEN__
					/* WASM static-link path: ML-KEM private keys default to
					 * CKA_PRIVATE=TRUE per PKCS#11 v3.2 §6.68.3 + §4.7, so
					 * C_GenerateKeyPair without C_Login returns
					 * CKR_USER_NOT_LOGGED_IN (§5.18.2). The slot was
					 * provisioned by wasm_hsm_init with USER_PIN="1234";
					 * uninitialized append-on-probe slots will fail login
					 * and be skipped (we try the next slot). */
					static const CK_UTF8CHAR wasm_pin[] = {'1','2','3','4'};
					CK_RV login_rv = current->f->C_Login(*session, CKU_USER,
						(CK_UTF8CHAR_PTR)wasm_pin, sizeof(wasm_pin));
					if (login_rv != CKR_OK &&
						login_rv != CKR_USER_ALREADY_LOGGED_IN)
					{
						DBG2(DBG_CFG, "pkcs11_kem WASM C_Login slot=%lu: %N — skipping",
							 (unsigned long)slot, ck_rv_names, login_rv);
						current->f->C_CloseSession(*session);
						break;
					}
#endif
					found = current;
					break;
				}
			}
		}
		mechs->destroy(mechs);
		if (found) break;
	}
	tokens->destroy(tokens);
	return found;
}

/* PKCS#11 v3.2 CKA_PARAMETER_SET values (pkcs11.h) for each FIPS 203
 * ML-KEM size strongSwan can negotiate. pkcs11_kem_create() only ever
 * constructs this object for ML_KEM_512/768/1024 (see its group switch),
 * so the default arm below is unreachable in practice; it exists only to
 * give the compiler a defined value for every key_exchange_method_t. */
static CK_ULONG kem_parameter_set(key_exchange_method_t group)
{
	switch (group) {
		case ML_KEM_512:  return CKP_ML_KEM_512;
		case ML_KEM_768:  return CKP_ML_KEM_768;
		case ML_KEM_1024: return CKP_ML_KEM_1024;
		default:          return CKP_ML_KEM_768;
	}
}

/**
 * Initiator: Generates an ML-KEM key pair and returns the public key
 * Responder: Encapsulates against initiator's public key, returning the ciphertext
 */
METHOD(key_exchange_t, get_public_key, bool,
	private_pkcs11_kem_t *this, chunk_t *value)
{
	/* If we already have a ciphertext, we are the responder and should return the ciphertext! */
	if (this->ciphertext.ptr) {
		*value = chunk_clone(this->ciphertext);
		return TRUE;
	}

	/* Otherwise, we are the initiator. Let's generate a key pair */
	CK_MECHANISM mech = { this->mech_key, NULL, 0 };
	CK_OBJECT_HANDLE pub_key;
	CK_BBOOL ck_true = CK_TRUE;
	/* softhsmv3 requires CKA_PARAMETER_SET on the ML-KEM keygen template
	 * to select the variant (512/768/1024). Without it C_GenerateKeyPair
	 * returns CKR_TEMPLATE_INCOMPLETE. Derive it from this->group so all
	 * three ML-KEM sizes work, not just 768. */
	CK_ULONG parameter_set = kem_parameter_set(this->group);

	/* PKCS#11 v3.2 KEM flags. softhsmv3 also sets these internally during
	 * keygen (SoftHSM_keygen.cpp 6651/6732) but being explicit is safer
	 * and documents intent. */
	CK_ATTRIBUTE pub_attr[] = {
		{ CKA_DERIVE,        &ck_true,       sizeof(ck_true)       },
		{ CKA_ENCAPSULATE,   &ck_true,       sizeof(ck_true)       },
		{ CKA_PARAMETER_SET, &parameter_set, sizeof(parameter_set) },
	};
	CK_ATTRIBUTE pri_attr[] = {
		{ CKA_DERIVE,        &ck_true,       sizeof(ck_true)       },
		{ CKA_DECAPSULATE,   &ck_true,       sizeof(ck_true)       },
		{ CKA_PARAMETER_SET, &parameter_set, sizeof(parameter_set) },
	};

	CK_RV rv = this->lib->f->C_GenerateKeyPair(this->session, &mech,
												pub_attr, countof(pub_attr),
												pri_attr, countof(pri_attr),
												&pub_key, &this->pri_key);
	if (rv != CKR_OK) {
		DBG1(DBG_CFG, "PKCS#11 C_GenerateKeyPair() KEM error: %N", ck_rv_names, rv);
		return FALSE;
	}
	DBG1(DBG_CFG, "PKCS#11 KEM keygen OK: session=%lu pub=%lu pri=%lu",
	     (unsigned long)this->session, (unsigned long)pub_key,
	     (unsigned long)this->pri_key);

	/* Grab the public key value */
	if (!this->lib->get_ck_attribute(this->lib, this->session, pub_key, CKA_VALUE, &this->pub_key)) {
		chunk_free(&this->pub_key);
		return FALSE;
	}

	*value = chunk_clone(this->pub_key);
	return TRUE;
}

/**
 * Initiator: Receives the ciphertext
 * Responder: Receives the initiator's public key
 */
/* FIPS 203 ML-KEM pubkey sizes — strongSwan's upstream
 * key_exchange_verify_pubkey() codes all ML_KEM_* cases as
 * `valid = FALSE` with comment "verification currently not supported, do
 * in plugin". So if we delegate to that helper, it fails. Do the check
 * ourselves. */
static bool pkcs11_kem_verify_pubkey(key_exchange_method_t group, chunk_t value)
{
	switch (group) {
		case ML_KEM_512:  return value.len == 800;
		case ML_KEM_768:  return value.len == 1184;
		case ML_KEM_1024: return value.len == 1568;
		default:          return key_exchange_verify_pubkey(group, value);
	}
}

/* Resolve the v3.2 KEM entry points directly from the underlying softhsmv3
 * module.  pkcs11-spy < 0.26 doesn't forward C_EncapsulateKey/C_DecapsulateKey
 * in its exposed CK_FUNCTION_LIST, so the cast of `this->lib->f` to
 * CK_FUNCTION_LIST_3_0* reads garbage at the v3 slot offsets. We dlopen the
 * real module named in $PKCS11SPY (or fall back to the common install path)
 * and dlsym the two symbols. They are set as the DSO's top-level C_* symbols
 * by softhsmv3, so no session/handle sharing concern — the call still targets
 * the same in-process instance via the same handleManager state. */
#include <dlfcn.h>
typedef CK_RV (*encap_fn_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                            CK_ATTRIBUTE_PTR, CK_ULONG,
                            CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*decap_fn_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                            CK_ATTRIBUTE_PTR, CK_ULONG,
                            CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

static bool get_v3_kem_funcs(encap_fn_t *enc, decap_fn_t *dec)
{
#ifdef __EMSCRIPTEN__
	/* WASM static-link: softhsmv3 is linked directly into charon.wasm and
	 * the browser has no dynamic linker, so dlopen always fails. The PKCS#11
	 * v3.2 entry points are in scope as ordinary C symbols — bind them once
	 * via extern declarations matching encap_fn_t / decap_fn_t. Same in-
	 * process instance as everything else (handleManager state shared). */
	extern CK_RV C_EncapsulateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
	                              CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
	                              CK_BYTE_PTR, CK_ULONG_PTR,
	                              CK_OBJECT_HANDLE_PTR);
	extern CK_RV C_DecapsulateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
	                              CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
	                              CK_BYTE_PTR, CK_ULONG,
	                              CK_OBJECT_HANDLE_PTR);
	*enc = C_EncapsulateKey;
	*dec = C_DecapsulateKey;
	return TRUE;
#else
	static encap_fn_t cached_enc = NULL;
	static decap_fn_t cached_dec = NULL;
	if (cached_enc && cached_dec) {
		*enc = cached_enc;
		*dec = cached_dec;
		return TRUE;
	}
	const char *real = getenv("PKCS11SPY");
	if (!real || !*real) {
		real = "/usr/local/lib/softhsm/libsofthsmv3.so";
	}
	void *h = dlopen(real, RTLD_NOW | RTLD_NOLOAD);
	if (!h) h = dlopen(real, RTLD_NOW);
	if (!h) {
		DBG1(DBG_CFG, "PKCS#11 KEM: dlopen(%s) failed: %s", real, dlerror());
		return FALSE;
	}
	cached_enc = (encap_fn_t)dlsym(h, "C_EncapsulateKey");
	cached_dec = (decap_fn_t)dlsym(h, "C_DecapsulateKey");
	if (!cached_enc || !cached_dec) {
		DBG1(DBG_CFG, "PKCS#11 KEM: dlsym C_Encap/Decap missing on %s", real);
		return FALSE;
	}
	*enc = cached_enc;
	*dec = cached_dec;
	return TRUE;
#endif
}

/* Responder encapsulation — produces ciphertext + shared secret from
 * the initiator's public key. Called eagerly at set_public_key() time so
 * get_public_key() can immediately return the ciphertext (IKE flow calls
 * get_public_key BEFORE get_shared_secret on the responder). */
static bool encapsulate_on_responder(private_pkcs11_kem_t *this)
{
	encap_fn_t encap_fn = NULL;
	decap_fn_t decap_fn = NULL;
	if (!get_v3_kem_funcs(&encap_fn, &decap_fn)) {
		DBG1(DBG_CFG, "PKCS#11 KEM: v3 function resolution failed");
		return FALSE;
	}

	CK_OBJECT_CLASS klass_key = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type_key = CKK_ML_KEM;
	CK_ULONG parameter_set = kem_parameter_set(this->group);
	CK_BBOOL ck_true_encap = CK_TRUE;
	/* softhsmv3 enforces CKA_ENCAPSULATE=TRUE on the pub key for
	 * C_EncapsulateKey (SoftHSM_kem.cpp returns
	 * CKR_KEY_FUNCTION_NOT_PERMITTED otherwise). */
	CK_ATTRIBUTE key_template[] = {
		{ CKA_CLASS,         &klass_key,         sizeof(klass_key)     },
		{ CKA_KEY_TYPE,      &type_key,          sizeof(type_key)      },
		{ CKA_PARAMETER_SET, &parameter_set,     sizeof(parameter_set) },
		{ CKA_ENCAPSULATE,   &ck_true_encap,     sizeof(ck_true_encap) },
		{ CKA_VALUE,         this->pub_key.ptr,  this->pub_key.len     },
	};

	CK_OBJECT_HANDLE hPublicKey, hSecretKey;
	CK_RV rv = this->lib->f->C_CreateObject(this->session, key_template,
	                                        countof(key_template), &hPublicKey);
	if (rv != CKR_OK) {
		DBG1(DBG_CFG, "PKCS#11 KEM C_CreateObject(peer pubkey) failed: %N",
		     ck_rv_names, rv);
		return FALSE;
	}

	/* Output secret-key template per PKCS#11 v3.2 §5.20 and
	 * pqctoday-hsm/p11_v32_compliance_test.cpp. Without this the call
	 * mis-parses its argument list, reading garbage as ciphertext-buffer
	 * and returning OBJECT_HANDLE_INVALID / ATTRIBUTE_VALUE_INVALID. */
	CK_OBJECT_CLASS sec_class = CKO_SECRET_KEY;
	CK_KEY_TYPE     sec_type  = CKK_GENERIC_SECRET;
	CK_ULONG        sec_len   = 32;  /* ML-KEM shared secret is 32 bytes */
	CK_BBOOL        ck_true2  = CK_TRUE;
	CK_BBOOL        ck_false  = CK_FALSE;
	CK_ATTRIBUTE secret_tmpl[] = {
		{ CKA_CLASS,       &sec_class, sizeof(sec_class) },
		{ CKA_KEY_TYPE,    &sec_type,  sizeof(sec_type)  },
		{ CKA_VALUE_LEN,   &sec_len,   sizeof(sec_len)   },
		{ CKA_TOKEN,       &ck_false,  sizeof(ck_false)  },
		{ CKA_EXTRACTABLE, &ck_true2,  sizeof(ck_true2)  },
	};

	CK_MECHANISM encap_mech = { this->mech_encap, NULL, 0 };
	unsigned long ct_len = 0;
	rv = encap_fn(this->session, &encap_mech, hPublicKey,
	              secret_tmpl, countof(secret_tmpl),
	              NULL, &ct_len, &hSecretKey);
#ifdef __EMSCRIPTEN__
	{
		extern void wasm_pkcs11_trace_kem(const char *op, uint32_t sess,
		                                  uint32_t mech, int in_a, int in_b,
		                                  int rv_, int out_a, int out_b);
		wasm_pkcs11_trace_kem("C_EncapsulateKey(size)",
		                      (uint32_t)this->session,
		                      (uint32_t)this->mech_encap,
		                      (int)hPublicKey, 0, (int)rv,
		                      (int)ct_len, 0);
	}
#endif
	if (rv != CKR_OK) {
		DBG1(DBG_CFG, "PKCS#11 KEM C_EncapsulateKey(size query) failed: %N",
		     ck_rv_names, rv);
		return FALSE;
	}

	this->ciphertext = chunk_alloc(ct_len);
	rv = encap_fn(this->session, &encap_mech, hPublicKey,
	              secret_tmpl, countof(secret_tmpl),
	              this->ciphertext.ptr, &ct_len, &hSecretKey);
#ifdef __EMSCRIPTEN__
	{
		extern void wasm_pkcs11_trace_kem(const char *op, uint32_t sess,
		                                  uint32_t mech, int in_a, int in_b,
		                                  int rv_, int out_a, int out_b);
		wasm_pkcs11_trace_kem("C_EncapsulateKey",
		                      (uint32_t)this->session,
		                      (uint32_t)this->mech_encap,
		                      (int)hPublicKey, 0, (int)rv,
		                      (int)ct_len, (int)hSecretKey);
	}
#endif
	if (rv != CKR_OK) {
		DBG1(DBG_CFG, "PKCS#11 KEM C_EncapsulateKey failed: %N",
		     ck_rv_names, rv);
		return FALSE;
	}

	if (!this->lib->get_ck_attribute(this->lib, this->session, hSecretKey,
	                                  CKA_VALUE, &this->secret)) {
		DBG1(DBG_CFG, "PKCS#11 KEM get CKA_VALUE on secret failed");
		return FALSE;
	}

	DBG1(DBG_CFG, "PKCS#11 KEM encap OK: session=%lu ct_len=%lu secret_len=%zu",
	     (unsigned long)this->session, (unsigned long)ct_len, this->secret.len);
	return TRUE;
}

/* Expected ciphertext sizes (FIPS 203). */
static size_t kem_ciphertext_size(key_exchange_method_t group)
{
	switch (group) {
		case ML_KEM_512:  return 768;
		case ML_KEM_768:  return 1088;
		case ML_KEM_1024: return 1568;
		default:          return 0;
	}
}

METHOD(key_exchange_t, set_public_key, bool,
	private_pkcs11_kem_t *this, chunk_t value)
{
	/* Strongswan's KEM flow denotes whether we have generated our own key first.
       If we have pri_key, we are the initiator, so this value is literally CIPHERTEXT.
       If we do not have pri_key, we are the responder, so this value is the PUBLIC KEY.
       The length check therefore depends on role: ciphertext size (1088 for
       ML-KEM-768) on the initiator, public key size (1184) on the responder.
       Previous code always required pubkey-size and rejected initiator input. */

	if (this->pri_key != CK_INVALID_HANDLE) {
		size_t expected = kem_ciphertext_size(this->group);
		if (!expected || value.len != expected) {
			DBG1(DBG_CFG, "PKCS#11 KEM initiator: bad ciphertext size %zu (expected %zu)",
			     value.len, expected);
			return FALSE;
		}
		this->ciphertext = chunk_clone(value);
		return TRUE;
	}

	if (!pkcs11_kem_verify_pubkey(this->group, value)) {
		return FALSE;
	}
	this->pub_key = chunk_clone(value);
	return encapsulate_on_responder(this);
}

/**
 * Encap/Decap Execution
 */
METHOD(key_exchange_t, get_shared_secret, bool,
	private_pkcs11_kem_t *this, chunk_t *secret)
{
	/* Resolve v3.2 KEM entry points from the real softhsmv3 module
	 * (bypassing pkcs11-spy's v2-only function table). */
	encap_fn_t encap_fn = NULL;
	decap_fn_t decap_fn = NULL;
	if (!get_v3_kem_funcs(&encap_fn, &decap_fn)) {
		return FALSE;
	}

	if (this->pri_key == CK_INVALID_HANDLE) {
		/* We are RESPONDER — encapsulation already done in set_public_key.
		 * Just verify we have the secret computed. */
		if (!this->secret.ptr) {
			DBG1(DBG_CFG, "PKCS#11 KEM responder: no secret (encap skipped?)");
			return FALSE;
		}
	} else {
		/* We are INITIATOR. We must DECAPSULATE using this->pri_key and this->ciphertext */
		CK_MECHANISM decap_mech = { this->mech_encap, NULL, 0 };
		CK_OBJECT_HANDLE hSecretKey;

		DBG1(DBG_CFG, "PKCS#11 KEM decap attempt: session=%lu pri=%lu ct_len=%zu",
		     (unsigned long)this->session, (unsigned long)this->pri_key,
		     this->ciphertext.len);

		/* Output secret-key template — PKCS#11 v3.2 §5.20 (same shape as
		 * encap side). Omitting it shifts args and softhsmv3 returns
		 * spurious OBJECT_HANDLE_INVALID. */
		CK_OBJECT_CLASS sec_class = CKO_SECRET_KEY;
		CK_KEY_TYPE     sec_type  = CKK_GENERIC_SECRET;
		CK_ULONG        sec_len   = 32;
		CK_BBOOL        ck_true3  = CK_TRUE;
		CK_BBOOL        ck_false2 = CK_FALSE;
		CK_ATTRIBUTE decap_tmpl[] = {
			{ CKA_CLASS,       &sec_class, sizeof(sec_class) },
			{ CKA_KEY_TYPE,    &sec_type,  sizeof(sec_type)  },
			{ CKA_VALUE_LEN,   &sec_len,   sizeof(sec_len)   },
			{ CKA_TOKEN,       &ck_false2, sizeof(ck_false2) },
			{ CKA_EXTRACTABLE, &ck_true3,  sizeof(ck_true3)  },
		};

		CK_RV rv = decap_fn(this->session, &decap_mech,
		                    this->pri_key,
		                    decap_tmpl, countof(decap_tmpl),
		                    this->ciphertext.ptr,
		                    this->ciphertext.len,
		                    &hSecretKey);
#ifdef __EMSCRIPTEN__
		{
			extern void wasm_pkcs11_trace_kem(const char *op, uint32_t sess,
			                                  uint32_t mech, int in_a, int in_b,
			                                  int rv_, int out_a, int out_b);
			wasm_pkcs11_trace_kem("C_DecapsulateKey",
			                      (uint32_t)this->session,
			                      (uint32_t)this->mech_encap,
			                      (int)this->pri_key,
			                      (int)this->ciphertext.len,
			                      (int)rv,
			                      (int)hSecretKey, 0);
		}
#endif
		if (rv != CKR_OK) {
			DBG1(DBG_CFG, "PKCS#11 C_DecapsulateKey() failed: %N", ck_rv_names, rv);
			return FALSE;
		}

		if (!this->lib->get_ck_attribute(this->lib, this->session, hSecretKey, CKA_VALUE, &this->secret)) return FALSE;
	}

	*secret = chunk_clone(this->secret);
	return TRUE;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_pkcs11_kem_t *this)
{
	return this->group;
}

METHOD(key_exchange_t, destroy, void,
	private_pkcs11_kem_t *this)
{
	if (this->session != CK_INVALID_HANDLE) {
		this->lib->f->C_CloseSession(this->session);
	}
	chunk_clear(&this->pub_key);
	chunk_clear(&this->ciphertext);
	chunk_clear(&this->secret);
	free(this);
}

/**
 * See header
 *
 * The variadic args are required by ke_constructor_t (crypto_factory.h) for
 * MODP_CUSTOM-style runtime parameters; ML-KEM ignores them but the signature
 * MUST match the typedef or wasm-ld emits a function-pointer-cast trap when
 * the plugin loader calls this through the (*)(method, ...) dispatcher.
 */
pkcs11_kem_t *pkcs11_kem_create(key_exchange_method_t group, ...)
{
	private_pkcs11_kem_t *this;
	CK_MECHANISM_TYPE key_gen_mech = 0;
	CK_MECHANISM_TYPE encap_mech = 0;

	switch (group) {
		case ML_KEM_512:
		case ML_KEM_768:
		case ML_KEM_1024:
			/* softhsmv3 uses SEPARATE OIDs: CKM_ML_KEM_KEY_PAIR_GEN (0x0F)
			 * for generating the Alice keypair, CKM_ML_KEM (0x17) for the
			 * Bob encapsulate + Alice decapsulate call.  Prior code used
			 * CKM_ML_KEM for both, which made C_GenerateKeyPair return
			 * CKR_MECHANISM_INVALID and strongSwan silently fall through
			 * to the openssl plugin — see pkcs11.h note above. These two
			 * mechanisms are the same across all three ML-KEM sizes; the
			 * variant is selected via CKA_PARAMETER_SET on the key
			 * templates (see kem_parameter_set() above), not the
			 * mechanism itself. */
			key_gen_mech = CKM_ML_KEM_KEY_PAIR_GEN;
			encap_mech = CKM_ML_KEM;
			break;
		default:
			return NULL;
	}

	INIT(this,
		.public = {
			.ke = {
				.get_shared_secret = _get_shared_secret,
				.set_public_key = _set_public_key,
				.get_public_key = _get_public_key,
				.get_method = _get_method,
				.destroy = _destroy,
			},
		},
		.group = group,
		.mech_key = key_gen_mech,
		.mech_encap = encap_mech,
		.pri_key = CK_INVALID_HANDLE,
		.session = CK_INVALID_HANDLE,
	);

	this->lib = find_token(this, &this->session);
	if (!this->lib) {
		free(this);
		return NULL;
	}
	return &this->public;
}
