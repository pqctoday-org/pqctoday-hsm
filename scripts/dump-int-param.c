/* dump-int-param — reads one integer EVP_PKEY param by name from a
 * PEM-encoded (or URI-PEM-wrapped) key file and prints it to stdout.
 *
 * Generic, reusable probe: exists because there is no openssl CLI
 * subcommand that dumps an arbitrary EVP_PKEY int param (pkey -text is
 * algorithm-specific and only prints what that algorithm's own print
 * function was written to show). Used by test-openssl-provider.sh's T23
 * (phase-4 R20 / F36-5, OSSL_PKEY_PARAM_SECURITY_CATEGORY). */
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/pem.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s pemfile paramname\n", argv[0]);
        return 2;
    }
    OSSL_PROVIDER_load(NULL, "pkcs11");
    EVP_PKEY *pk = NULL;
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "open failed\n");
        return 2;
    }
    PEM_read_PrivateKey(f, &pk, NULL, NULL);
    fclose(f);
    if (!pk) {
        printf("LOAD FAILED\n");
        return 1;
    }
    int val = -999;
    if (!EVP_PKEY_get_int_param(pk, argv[2], &val)) {
        printf("GET FAILED\n");
        return 1;
    }
    printf("%d\n", val);
    return 0;
}
