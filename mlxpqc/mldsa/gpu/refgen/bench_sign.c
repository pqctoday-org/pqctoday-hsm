#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include "sign.h"
#include "params.h"
int crypto_sign_signature_internal(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t[32], const uint8_t*);
#define ENTRY (CRYPTO_SECRETKEYBYTES + 32 + CRYPTO_BYTES)
static uint8_t* g; static int g_n, g_per;
void* w(void* a){ long id=(long)a; uint8_t sig[CRYPTO_BYTES]; size_t sl; uint8_t pre[2]={0,0}, rnd[32]={0};
  for(int i=0;i<g_per;i++){ int idx=(id*g_per+i)%g_n; uint8_t* e=g+(size_t)idx*ENTRY; crypto_sign_signature_internal(sig,&sl,e+CRYPTO_SECRETKEYBYTES,32,pre,2,rnd,e); } return 0; }
double now(){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec*1e-9; }
int main(int argc,char**argv){ int P=argc>1?atoi(argv[1]):1, reps=argc>2?atoi(argv[2]):1;
  FILE* f=fopen("/tmp/mldsa_sksig.bin","rb"); fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET); g=malloc(sz); fread(g,1,sz,f); fclose(f); g_n=sz/ENTRY; g_per=g_n*reps/P;
  pthread_t th[64]; double s=now(); for(long i=0;i<P;i++) pthread_create(&th[i],0,w,(void*)i); for(int i=0;i<P;i++) pthread_join(th[i],0);
  double t=now()-s; long tot=(long)g_per*P; printf("CPU sign P=%d: %.4f M sign/sec\n", P, tot/t/1e6); return 0; }
