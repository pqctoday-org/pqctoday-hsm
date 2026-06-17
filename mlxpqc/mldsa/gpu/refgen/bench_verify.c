#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include "sign.h"
#include "params.h"
#define ENTRY (CRYPTO_PUBLICKEYBYTES + 32 + CRYPTO_BYTES)
static uint8_t* g_data; static int g_n, g_per;
void* worker(void* arg){ long id=(long)arg; for(int i=0;i<g_per;i++){ int idx=(id*g_per+i)%g_n; uint8_t* e=g_data+(size_t)idx*ENTRY; crypto_sign_verify(e+CRYPTO_PUBLICKEYBYTES+32, CRYPTO_BYTES, e+CRYPTO_PUBLICKEYBYTES, 32, NULL, 0, e); } return 0; }
double now(){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec*1e-9; }
int main(int argc, char** argv){
  int P = argc>1?atoi(argv[1]):1; int reps = argc>2?atoi(argv[2]):1;
  FILE* f=fopen("/tmp/mldsa_sigs.bin","rb"); fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
  g_data=malloc(sz); fread(g_data,1,sz,f); fclose(f); g_n=sz/ENTRY;
  g_per = g_n*reps/P;
  pthread_t th[64]; double s=now();
  for(long i=0;i<P;i++) pthread_create(&th[i],0,worker,(void*)i);
  for(int i=0;i<P;i++) pthread_join(th[i],0);
  double t=now()-s; long total=(long)g_per*P;
  printf("CPU verify P=%d: %.4f M verify/sec\n", P, total/t/1e6);
  return 0;
}
