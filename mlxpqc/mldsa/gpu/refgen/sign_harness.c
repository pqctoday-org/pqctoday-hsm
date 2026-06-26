#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sign.h"
#include "params.h"
void rb_set(const uint8_t* p);
int crypto_sign_signature_internal(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t[32], const uint8_t*);
int main(int argc, char** argv){
  int nk = argc>1?atoi(argv[1]):256;
  uint8_t* stream = malloc((size_t)nk*64);
  uint64_t s=0xDEADBEEF12345678ull;
  for(int i=0;i<nk*64;i++){ s^=s<<13; s^=s>>7; s^=s<<17; stream[i]=(uint8_t)s; }
  rb_set(stream);
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES], sig[CRYPTO_BYTES], msg[32];
  size_t siglen;
  // dump sk|msg|sig per entry (deterministic signing, rnd=0)
  FILE* f=fopen("/tmp/mldsa_sksig.bin","wb");
  uint8_t pre[2]={0,0}, rnd[32]={0};
  for(int i=0;i<nk;i++){
    crypto_sign_keypair(pk,sk);
    for(int j=0;j<32;j++) msg[j]=(uint8_t)(i*31+j*7);
    crypto_sign_signature_internal(sig,&siglen,msg,32,pre,2,rnd,sk);   // deterministic rnd=0
    fwrite(sk,1,CRYPTO_SECRETKEYBYTES,f); fwrite(msg,1,32,f); fwrite(sig,1,CRYPTO_BYTES,f);
  }
  fclose(f);
  printf("sign: nk=%d sk=%d msg=32 sig=%zu -> /tmp/mldsa_sksig.bin\n", nk, CRYPTO_SECRETKEYBYTES, siglen);
  return 0;
}
