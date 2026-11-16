/* SPDX-License-Identifier: AGPL-3.0-only */
#include <openssl/rand.h>
static int reject_serial_rng = 0;
static int serial_random_bytes(unsigned char *bytes, int length) {
    return reject_serial_rng ? 0 : RAND_bytes(bytes, length);
}
#define RAND_bytes serial_random_bytes
#include "cmp_simulation.c"
#undef RAND_bytes

static int ok_result(char *result) {
    int ok = result && strstr(result, "\"ok\":true");
    free(result); return ok;
}
static int exists(const char *path) { FILE *f=fopen(path,"r"); if(!f)return 0; fclose(f);return 1; }
static char *enroll(const char *key, const char *output) {
    return execute_cmp_simulation(key,"/CN=fictional-initial","sample","sample-secret","ca.pem","ca.key",output);
}
int main(void) {
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    X509 *cert = NULL;
    if(!ok_result(generate_mock_ca_root("ML-DSA-65","/CN=fictional-ca","ca.key","ca.pem",1)))return 2;
    key=EVP_PKEY_Q_keygen(NULL,NULL,"ED25519");bio=BIO_new_file("ee.key","w");
    if(!key||!bio||!PEM_write_bio_PrivateKey(bio,key,NULL,NULL,0,NULL,NULL))return 3;
    BIO_free(bio);EVP_PKEY_free(key);
    if(!ok_result(enroll("ee.key","issued.pem")))return 4;
    cert=load_x509_pem("issued.pem");if(!cert)return 5;
    if(ASN1_STRING_length(X509_get0_serialNumber(cert))!=16 || ASN1_INTEGER_get(X509_get0_serialNumber(cert))==0)return 6;
    X509_free(cert);
    if(ok_result(enroll("missing.key","issued.pem"))||exists("issued.pem"))return 7;
    if(ok_result(enroll("ee.key","ca.pem"))||!exists("ca.pem"))return 8;
    reject_serial_rng=1;
    char *result=enroll("ee.key","issued.pem");
    int rejected=result && strstr(result,"\"ok\":false") && strstr(result,"randomness unavailable");
    free(result);
    if(!rejected||exists("issued.pem"))return 9;
    reject_serial_rng=0;
    if(!ok_result(enroll("ee.key","issued.pem")))return 10;
    puts("{\"case\":\"initial-enrollment-rng-stale-output-recovery\",\"passed\":true}");
    return 0;
}
