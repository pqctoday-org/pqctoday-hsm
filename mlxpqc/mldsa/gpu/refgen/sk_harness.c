#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sign.h"
#include "params.h"
void rb_set(const uint8_t* p);
int main(int argc, char** argv){
  int nk = argc>1?atoi(argv[1]):65536;
  uint8_t* stream = malloc((size_t)nk*32);
  uint64_t s=0xDEADBEEF12345678ull;
  for(int i=0;i<nk*32;i++){ s^=s<<13; s^=s>>7; s^=s<<17; stream[i]=(uint8_t)s; }
  rb_set(stream);
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES], msg[32]; uint8_t* zsig=calloc(1,CRYPTO_BYTES);
  FILE* f=fopen("/tmp/mldsa_sksig.bin","wb");
  for(int i=0;i<nk;i++){ crypto_sign_keypair(pk,sk); for(int j=0;j<32;j++) msg[j]=(uint8_t)(i*31+j*7);
    fwrite(sk,1,CRYPTO_SECRETKEYBYTES,f); fwrite(msg,1,32,f); fwrite(zsig,1,CRYPTO_BYTES,f); }
  fclose(f); printf("sk-only: nk=%d (dummy sig; throughput-only)\n", nk); return 0;
}
