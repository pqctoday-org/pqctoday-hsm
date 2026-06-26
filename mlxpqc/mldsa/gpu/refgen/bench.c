#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include "sign.h"
#include "params.h"
__thread uint64_t rng_state = 0;
void randombytes(uint8_t* out, size_t n){ if(!rng_state) rng_state=((uint64_t)pthread_self()<<1)|1; for(size_t i=0;i<n;i++){ rng_state^=rng_state<<13; rng_state^=rng_state>>7; rng_state^=rng_state<<17; out[i]=(uint8_t)rng_state; } }
static int per_thread;
void* worker(void* arg){ (void)arg; uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES]; for(int i=0;i<per_thread;i++) crypto_sign_keypair(pk,sk); return 0; }
double now(){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec*1e-9; }
int main(int argc, char** argv){
  int nk = argc>1?atoi(argv[1]):4096; int P = argc>2?atoi(argv[2]):1;
  per_thread = nk/P;
  pthread_t th[64]; double s=now();
  for(int i=0;i<P;i++) pthread_create(&th[i],0,worker,0);
  for(int i=0;i<P;i++) pthread_join(th[i],0);
  double t=now()-s; int total=per_thread*P;
  printf("CPU keyGen P=%d: %.3f ms for %d keys = %.4f M keys/sec\n", P, t*1e3, total, total/t/1e6);
  return 0;
}
