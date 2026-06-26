#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sign.h"
#include "params.h"
void rb_set(const uint8_t* p);
int main(int argc, char** argv){
  int nk = argc > 1 ? atoi(argv[1]) : 256;
  uint8_t* seeds = malloc((size_t)nk*32);
  uint64_t s = 0x123456789ABCDEF0ull;            // deterministic seeds (shared with GPU)
  for(int i = 0; i < nk*32; i++){ s ^= s<<13; s ^= s>>7; s ^= s<<17; seeds[i] = (uint8_t)s; }
  FILE* fs = fopen("/tmp/mldsa_seeds.bin","wb"); fwrite(seeds,1,(size_t)nk*32,fs); fclose(fs);
  rb_set(seeds);
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  FILE* fk = fopen("/tmp/mldsa_refkeys.bin","wb");
  for(int i = 0; i < nk; i++){ crypto_sign_keypair(pk,sk); fwrite(pk,1,CRYPTO_PUBLICKEYBYTES,fk); fwrite(sk,1,CRYPTO_SECRETKEYBYTES,fk); }
  fclose(fk);
  printf("ref: nk=%d  pk=%d sk=%d  -> /tmp/mldsa_refkeys.bin\n", nk, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES);
  return 0;
}
