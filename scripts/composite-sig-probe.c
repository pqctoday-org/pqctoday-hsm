/* composite-sig-probe — drives composite.c's external bridge
 * (p11prov_composite_evp_pkey_from_uris, composite.h) directly to sign
 * and verify with a real composite key built from two token-resident
 * PKCS#11 subkeys.
 *
 * Exists because the standard openssl CLI cannot reach this path: a
 * composite EVP_PKEY can only be constructed by combining two pre-loaded
 * subkey objects (there is no OSSL_FUNC_KEYMGMT_GEN for the composite
 * keymgmt — see composite.h's own comment on the bridge), which needs a
 * C pointer to cross the IMPORT param boundary. Used by
 * test-openssl-provider.sh's T21 (COMPSIG) cases.
 *
 * Two operations, both against a real composite EVP_PKEY:
 *   sign   oid pq_priv_uri classical_priv_uri msg           -> hex sig on stdout
 *   verify oid pq_pub_uri  classical_pub_uri  msg sig_hex   -> "VERIFY OK" or exit 1
 *
 * URIs must be pkcs11: strings (not the base64 "PKCS#11 Provider URI
 * v1.0"-wrapped PEM this provider's own -out files produce for
 * `openssl genpkey`) — decode that wrapper first. sign needs the
 * PRIVATE key URIs (CKA_SIGN); verify needs the PUBLIC key URIs
 * (CKA_VERIFY) — feeding sign's private URIs to verify fails at
 * EVP_PKEY_verify_init with an empty OpenSSL error queue (PKCS#11
 * C_VerifyInit against a class=PRIVATE_KEY object fails below the level
 * this provider raises an OSSL error for), which looks like a silent
 * crash if you don't already know to check the key class.
 *
 * p11prov_composite_profile_by_oid() and p11prov_composite_evp_pkey_from_uris()
 * are real exported C symbols in pkcs11-provider.so (composite.h's own
 * comment on the bridge), but this probe does not build-time-link against
 * that library: pkcs11-provider is a CMake MODULE target, which on macOS
 * builds as a Mach-O bundle (MH_BUNDLE) — Apple's linker refuses those as
 * direct link inputs ("unsupported mach-o filetype", only MH_OBJECT/
 * MH_DYLIB are linkable), unlike GNU ld/lld on Linux, which links an
 * ordinary ELF .so regardless of its intended loadable-module role (see
 * CMakeLists.txt's comment on this target for the platform history).
 * dlopen()/dlsym() load MH_BUNDLE and ELF .so identically on both
 * platforms, so the two symbols below are resolved at runtime instead —
 * same idiom scripts/dp-kdf-counter-probe.cpp and
 * scripts/hss-pubkey-dump.c already use for comparable cross-module
 * boundaries. This sidesteps the link-time portability problem entirely
 * rather than fighting linker flag syntax per platform. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "composite.h"

/* Must match composite.h's extern declarations exactly — that header stays
 * the source of truth for the signatures; only the *linking* is indirect. */
typedef const struct p11prov_composite_profile *(*profile_by_oid_fn)(
    const char *oid);
typedef EVP_PKEY *(*evp_pkey_from_uris_fn)(
    P11PROV_CTX *provctx, const struct p11prov_composite_profile *profile,
    const char *pq_uri, const char *classical_uri);

#ifndef PKCS11_PROVIDER_SO_PATH
#define PKCS11_PROVIDER_SO_PATH "pkcs11-provider.so"
#endif

/* Resolves both composite-bridge symbols from pkcs11-provider.so via a
 * dedicated dlopen() (independent of OSSL_PROVIDER_load()'s own internal
 * dlopen below, which may use RTLD_LOCAL and so need not expose its
 * symbols process-wide). PKCS11_PROVIDER_SO env var overrides the
 * CMake-baked build path, matching the other env overrides this probe's
 * caller (scripts/test-openssl-provider.sh) already uses. */
static int resolve_composite_bridge(profile_by_oid_fn *profile_by_oid_out,
                                     evp_pkey_from_uris_fn *evp_pkey_from_uris_out)
{
    const char *so_path = getenv("PKCS11_PROVIDER_SO");
    if (!so_path || !*so_path) {
        so_path = PKCS11_PROVIDER_SO_PATH;
    }
    void *dl = dlopen(so_path, RTLD_NOW | RTLD_LOCAL);
    if (!dl) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", so_path, dlerror());
        return 0;
    }
    dlerror(); /* clear any pre-existing error before dlsym per POSIX idiom */
    void *sym1 = dlsym(dl, "p11prov_composite_profile_by_oid");
    const char *err = dlerror();
    if (err) {
        fprintf(stderr, "dlsym(p11prov_composite_profile_by_oid): %s\n", err);
        return 0;
    }
    void *sym2 = dlsym(dl, "p11prov_composite_evp_pkey_from_uris");
    err = dlerror();
    if (err) {
        fprintf(stderr, "dlsym(p11prov_composite_evp_pkey_from_uris): %s\n",
                err);
        return 0;
    }
    /* Object-pointer -> function-pointer conversion via dlsym is undefined
     * in strict ISO C but is a POSIX-blessed, universally supported
     * extension on every platform this project targets (macOS, Linux). */
    *profile_by_oid_out = (profile_by_oid_fn)sym1;
    *evp_pkey_from_uris_out = (evp_pkey_from_uris_fn)sym2;
    return 1;
}

static void hexdump(const unsigned char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 6) {
        fprintf(stderr,
               "usage: %s sign|verify oid pq_uri classical_uri msg [sig_hex]\n",
               argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *oid = argv[2];
    const char *pq_uri = argv[3];
    const char *classical_uri = argv[4];
    const char *msg = argv[5];

    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) {
        ERR_print_errors_fp(stderr);
        return 2;
    }
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (!prov) {
        ERR_print_errors_fp(stderr);
        return 2;
    }
    P11PROV_CTX *provctx = (P11PROV_CTX *)OSSL_PROVIDER_get0_provider_ctx(prov);
    if (!provctx) {
        fprintf(stderr, "no provctx\n");
        return 2;
    }

    profile_by_oid_fn profile_by_oid = NULL;
    evp_pkey_from_uris_fn evp_pkey_from_uris = NULL;
    if (!resolve_composite_bridge(&profile_by_oid, &evp_pkey_from_uris)) {
        return 2;
    }

    const struct p11prov_composite_profile *profile = profile_by_oid(oid);
    if (!profile) {
        fprintf(stderr, "unknown oid %s\n", oid);
        return 2;
    }

    EVP_PKEY *pkey =
        evp_pkey_from_uris(provctx, profile, pq_uri, classical_uri);
    if (!pkey) {
        fprintf(stderr, "bridge failed\n");
        ERR_print_errors_fp(stderr);
        return 2;
    }

    EVP_PKEY_CTX *pctx = NULL;
    int rc = 0;

    if (strcmp(mode, "sign") == 0) {
        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!pctx || EVP_PKEY_sign_init(pctx) != 1) {
            ERR_print_errors_fp(stderr);
            rc = 2;
            goto out;
        }
        size_t siglen = 0;
        if (EVP_PKEY_sign(pctx, NULL, &siglen, (const unsigned char *)msg,
                          strlen(msg)) != 1) {
            ERR_print_errors_fp(stderr);
            rc = 2;
            goto out;
        }
        unsigned char *sig = malloc(siglen);
        if (sig == NULL
            || EVP_PKEY_sign(pctx, sig, &siglen, (const unsigned char *)msg,
                             strlen(msg)) != 1) {
            ERR_print_errors_fp(stderr);
            free(sig);
            rc = 2;
            goto out;
        }
        hexdump(sig, siglen);
        free(sig);
    } else if (strcmp(mode, "verify") == 0) {
        if (argc < 7) {
            fprintf(stderr, "verify needs sig_hex\n");
            rc = 2;
            goto out;
        }
        const char *hex = argv[6];
        size_t siglen = strlen(hex) / 2;
        unsigned char *sig = malloc(siglen);
        if (sig == NULL) {
            rc = 2;
            goto out;
        }
        for (size_t i = 0; i < siglen; i++) {
            unsigned int b;
            sscanf(hex + 2 * i, "%2x", &b);
            sig[i] = (unsigned char)b;
        }
        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!pctx || EVP_PKEY_verify_init(pctx) != 1) {
            ERR_print_errors_fp(stderr);
            free(sig);
            rc = 2;
            goto out;
        }
        int r = EVP_PKEY_verify(pctx, sig, siglen, (const unsigned char *)msg,
                                strlen(msg));
        free(sig);
        if (r != 1) {
            fprintf(stderr, "VERIFY FAILED r=%d\n", r);
            ERR_print_errors_fp(stderr);
            rc = 1;
            goto out;
        }
        printf("VERIFY OK\n");
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        rc = 2;
    }

out:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return rc;
}
