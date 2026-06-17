// MLDSASIGN — full ML-DSA-65 Sign (deterministic, rnd=0) on Metal: setup kernels +
// host-driven rejection loop. Validated bit-exact vs pq-crystals reference
// (/tmp/mldsa_sksig.bin = sk(4032)|msg(32)|sig(3309) per entry).
// Build: swiftc -O MLDSASIGN.swift -o mldsa_sign -framework Metal -framework Foundation

import Foundation
import Metal

let kSrc = """
#include <metal_stdlib>
using namespace metal;
constant int DQ=8380417, DQINV=58728449, G1=(1<<19), G2=(8380417-1)/32, BETA=196;
constant int BNDZ=(1<<19)-196, BNDW=(8380417-1)/32 - 196;
constant uint KK=6, LL=5, DD=13, TAU=49, OMEGA=55;
constant uint ENTRY=7373, SKO=0, MSGO=4032, SIGREF=4064;
constant uint SK_RHO=0, SK_KEY=32, SK_TR=64, SK_S1=128, SK_S2=768, SK_T0=1536;
constant int ZETAS[256] = {
0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
-2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
-3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
-1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
-3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
-1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
-671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
-3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
-3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
-655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
-3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
-1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
-1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
-542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
-2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
-3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
-3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
-426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
-2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
-554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782
};
constant ulong RC[24]={0x1ul,0x8082ul,0x800000000000808aul,0x8000000080008000ul,0x808bul,0x80000001ul,0x8000000080008081ul,0x8000000000008009ul,0x8aul,0x88ul,0x80008009ul,0x8000000aul,0x8000808bul,0x800000000000008bul,0x8000000000008089ul,0x8000000000008003ul,0x8000000000008002ul,0x8000000000000080ul,0x800aul,0x800000008000000aul,0x8000000080008081ul,0x8000000000008080ul,0x80000001ul,0x8000000080008008ul};
constant uint RHt[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
constant uint PIL[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
inline ulong rotl64(ulong x,uint n){return (x<<n)|(x>>(64-n));}
inline void kf(thread ulong* a){for(int r=0;r<24;++r){ulong b[5];for(int i=0;i<5;i++)b[i]=a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20];for(int i=0;i<5;i++){ulong t=b[(i+4)%5]^rotl64(b[(i+1)%5],1);for(int j=0;j<25;j+=5)a[j+i]^=t;}ulong t=a[1];for(int i=0;i<24;i++){uint j=PIL[i];ulong tm=a[j];a[j]=rotl64(t,RHt[i]);t=tm;}for(int j=0;j<25;j+=5){ulong c[5];for(int i=0;i<5;i++)c[i]=a[j+i];for(int i=0;i<5;i++)a[j+i]=c[i]^((~c[(i+1)%5])&c[(i+2)%5]);}a[0]^=RC[r];}}
inline int mont(long a){int t=(int)a*DQINV;long r=(a-(long)t*(long)DQ)>>32;return (int)r;}
inline int reduce32(int a){int t=(a+(1<<22))>>23;return a-t*DQ;}
inline int caddq(int a){return a+((a>>31)&DQ);}
inline int decompose(int a, thread int* a0){int a1=(a+127)>>7;a1=(a1*1025+(1<<21))>>22;a1&=15;int r=a-a1*2*G2;r-=(((DQ-1)/2 - r)>>31)&DQ;*a0=r;return a1;}
inline int absI(int a){ return a-((a>>31)&(2*a)); }
inline void absorbN(thread ulong* s, thread const uchar* in, uint inlen, uint rate){ for(uint i=0;i<25u;i++)s[i]=0; uint off=0,rem=inlen; while(rem>=rate){for(uint i=0;i<rate/8u;i++){ulong v=0;for(uint b=0;b<8u;b++)v|=(ulong)in[off+8u*i+b]<<(8u*b);s[i]^=v;}off+=rate;rem-=rate;kf(s);} for(uint i=0;i<rem;i++)s[i/8u]^=(ulong)in[off+i]<<(8u*(i%8u)); s[rem/8u]^=(ulong)0x1F<<(8u*(rem%8u)); s[(rate-1u)/8u]^=(ulong)1<<63; }

// ---- SETUP ----
kernel void s_unpack(device const uchar* ent [[buffer(0)]], device uchar* rho [[buffer(1)]], device int* s1 [[buffer(2)]], device int* s2 [[buffer(3)]], device int* t0 [[buffer(4)]], uint g [[thread_position_in_grid]]){
    uint e=g*ENTRY;
    for(uint i=0;i<32u;i++) rho[g*32u+i]=ent[e+SKO+SK_RHO+i];
    for(uint v=0;v<LL;v++){ uint sb=e+SKO+SK_S1+v*128u, ob=(g*LL+v)*256u; for(uint i=0;i<128u;i++){ int b=ent[sb+i]; s1[ob+2*i]=4-(b&0xF); s1[ob+2*i+1]=4-(b>>4); } }
    for(uint v=0;v<KK;v++){ uint sb=e+SKO+SK_S2+v*128u, ob=(g*KK+v)*256u; for(uint i=0;i<128u;i++){ int b=ent[sb+i]; s2[ob+2*i]=4-(b&0xF); s2[ob+2*i+1]=4-(b>>4); } }
    for(uint v=0;v<KK;v++){ uint sb=e+SKO+SK_T0+v*416u, ob=(g*KK+v)*256u;
        for(uint i=0;i<32u;i++){ uint o=sb+13*i; uint t[8];
            t[0]=((uint)ent[o]|((uint)ent[o+1]<<8))&0x1FFF;
            t[1]=(((uint)ent[o+1]>>5)|((uint)ent[o+2]<<3)|((uint)ent[o+3]<<11))&0x1FFF;
            t[2]=(((uint)ent[o+3]>>2)|((uint)ent[o+4]<<6))&0x1FFF;
            t[3]=(((uint)ent[o+4]>>7)|((uint)ent[o+5]<<1)|((uint)ent[o+6]<<9))&0x1FFF;
            t[4]=(((uint)ent[o+6]>>4)|((uint)ent[o+7]<<4)|((uint)ent[o+8]<<12))&0x1FFF;
            t[5]=(((uint)ent[o+8]>>1)|((uint)ent[o+9]<<7))&0x1FFF;
            t[6]=(((uint)ent[o+9]>>6)|((uint)ent[o+10]<<2)|((uint)ent[o+11]<<10))&0x1FFF;
            t[7]=(((uint)ent[o+11]>>3)|((uint)ent[o+12]<<5))&0x1FFF;
            for(uint q=0;q<8u;q++) t0[ob+8*i+q]=(1<<(DD-1))-(int)t[q]; }
    }
}
kernel void s_mu(device const uchar* ent [[buffer(0)]], device uchar* mu [[buffer(1)]], uint g [[thread_position_in_grid]]){
    uint e=g*ENTRY; uchar buf[98]; for(uint i=0;i<64u;i++) buf[i]=ent[e+SKO+SK_TR+i]; buf[64]=0; buf[65]=0; for(uint i=0;i<32u;i++) buf[66+i]=ent[e+MSGO+i];
    ulong s[25]; absorbN(s, buf, 98u, 136u); kf(s); for(uint i=0;i<8u;i++){ulong v=s[i];for(uint b=0;b<8u;b++) mu[g*64u+8u*i+b]=(uchar)(v>>(8u*b));}
}
kernel void s_rhop(device const uchar* ent [[buffer(0)]], device const uchar* mu [[buffer(1)]], device uchar* rhop [[buffer(2)]], uint g [[thread_position_in_grid]]){
    uint e=g*ENTRY; uchar buf[128]; for(uint i=0;i<32u;i++) buf[i]=ent[e+SKO+SK_KEY+i]; for(uint i=0;i<32u;i++) buf[32+i]=0; for(uint i=0;i<64u;i++) buf[64+i]=mu[g*64u+i];
    ulong s[25]; absorbN(s, buf, 128u, 136u); kf(s); for(uint i=0;i<8u;i++){ulong v=s[i];for(uint b=0;b<8u;b++) rhop[g*64u+8u*i+b]=(uchar)(v>>(8u*b));}
}
kernel void s_expandA(device const uchar* rho [[buffer(0)]], device int* A [[buffer(1)]], uint g [[thread_position_in_grid]]){
    uint key=g/(KK*LL), rem=g%(KK*LL), i=rem/LL, j=rem%LL, nonce=(i<<8)|j;
    uchar buf[34]; for(uint k=0;k<32u;k++) buf[k]=rho[key*32u+k]; buf[32]=(uchar)(nonce&0xff); buf[33]=(uchar)(nonce>>8);
    ulong s[25]; absorbN(s, buf, 34u, 168u); uint ctr=0, ob=g*256u; uchar bb[168];
    while(ctr<256u){ kf(s); for(uint k=0;k<21u;k++){ulong v=s[k];for(uint b=0;b<8u;b++)bb[8u*k+b]=(uchar)(v>>(8u*b));} for(uint p=0;p+3u<=168u&&ctr<256u;p+=3u){uint t=(uint)bb[p]|((uint)bb[p+1]<<8)|(((uint)bb[p+2]&0x7f)<<16); if(t<(uint)DQ) A[ob+ctr++]=(int)t;} }
}
kernel void ntt_fwd(device const int* inp [[buffer(0)]], device int* outp [[buffer(1)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    uint pb=tg*256u; a[tid]=inp[pb+tid]; a[tid+128u]=inp[pb+tid+128u]; threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint len=128u;len>0u;len>>=1u){uint gg=tid/len;int z=ZETAS[(128u/len)+gg];uint j=gg*(2u*len)+(tid%len),jp=j+len;int t=mont((long)z*(long)a[jp]);int aj=a[j];a[jp]=aj-t;a[j]=aj+t;threadgroup_barrier(mem_flags::mem_threadgroup);}
    outp[pb+tid]=a[tid]; outp[pb+tid+128u]=a[tid+128u];
}
// invntt helper applied to threadgroup a[256] with tid (128 threads)
#define INVNTT(a,tid) { for(uint len=1u;len<256u;len<<=1u){uint gg=tid/len;int z=-ZETAS[(256u/len)-1u-gg];uint j=gg*(2u*len)+(tid%len),jp=j+len;int t=a[j],u=a[jp];a[j]=t+u;a[jp]=mont((long)z*(long)(t-u));threadgroup_barrier(mem_flags::mem_threadgroup);} const int f=41978; a[tid]=mont((long)f*(long)a[tid]); a[tid+128u]=mont((long)f*(long)a[tid+128u]); }
// done-aware NTT for the rejection loop (skip finished sigs)
kernel void ntt_sign(device const int* inp [[buffer(0)]], device int* outp [[buffer(1)]], device const int* done [[buffer(2)]], constant uint& perSig [[buffer(3)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    if(done[tg/perSig]!=0) return;
    uint pb=tg*256u; a[tid]=inp[pb+tid]; a[tid+128u]=inp[pb+tid+128u]; threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint len=128u;len>0u;len>>=1u){uint gg=tid/len;int z=ZETAS[(128u/len)+gg];uint j=gg*(2u*len)+(tid%len),jp=j+len;int t=mont((long)z*(long)a[jp]);int aj=a[j];a[jp]=aj-t;a[j]=aj+t;threadgroup_barrier(mem_flags::mem_threadgroup);}
    outp[pb+tid]=a[tid]; outp[pb+tid+128u]=a[tid+128u];
}

// ---- PER ROUND ----
kernel void r_expandmask(device const uchar* rhop [[buffer(0)]], device int* y [[buffer(1)]], device const int* done [[buffer(2)]], constant uint& round [[buffer(3)]], uint g [[thread_position_in_grid]]){
    uint sig=g/LL; if(done[sig]!=0) return; uint l=g%LL, nonce=LL*round + l;
    uchar buf[66]; for(uint k=0;k<64u;k++) buf[k]=rhop[sig*64u+k]; buf[64]=(uchar)(nonce&0xff); buf[65]=(uchar)(nonce>>8);
    ulong s[25]; absorbN(s, buf, 66u, 136u); uchar bb[680]; for(uint blk=0;blk<5u;blk++){ kf(s); for(uint k=0;k<17u;k++){ulong v=s[k];for(uint q=0;q<8u;q++)bb[blk*136u+8u*k+q]=(uchar)(v>>(8u*q));} }
    uint ob=g*256u;
    for(uint i=0;i<128u;i++){ int c0=(int)bb[5*i]|((int)bb[5*i+1]<<8)|((int)bb[5*i+2]<<16); c0&=0xFFFFF; int c1=((int)bb[5*i+2]>>4)|((int)bb[5*i+3]<<4)|((int)bb[5*i+4]<<12); c1&=0xFFFFF; y[ob+2*i]=G1-c0; y[ob+2*i+1]=G1-c1; }
}
kernel void r_matvec(device const int* A [[buffer(0)]], device const int* yntt [[buffer(1)]], device int* w1o [[buffer(2)]], device int* w0o [[buffer(3)]], device const int* done [[buffer(4)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    uint sig=tg/KK; if(done[sig]!=0) return; uint row=tg%KK, c0=tid, c1=tid+128u; int ac0=0,ac1=0;
    for(uint j=0;j<LL;j++){uint aB=((sig*KK+row)*LL+j)*256u,zB=(sig*LL+j)*256u; ac0+=mont((long)A[aB+c0]*(long)yntt[zB+c0]); ac1+=mont((long)A[aB+c1]*(long)yntt[zB+c1]);}
    a[c0]=reduce32(ac0); a[c1]=reduce32(ac1); threadgroup_barrier(mem_flags::mem_threadgroup);
    INVNTT(a,tid);
    int v0=caddq(a[c0]), v1=caddq(a[c1]); int o0,o1; int h0=decompose(v0,&o0), h1=decompose(v1,&o1);
    uint ob=(sig*KK+row)*256u; w1o[ob+c0]=h0; w0o[ob+c0]=o0; w1o[ob+c1]=h1; w0o[ob+c1]=o1;
}
kernel void r_chal(device const uchar* mu [[buffer(0)]], device const int* w1 [[buffer(1)]], device uchar* ctil [[buffer(2)]], device int* cp [[buffer(3)]], device const int* done [[buffer(4)]], uint g [[thread_position_in_grid]]){
    if(done[g]!=0) return;
    uchar buf[832]; for(uint i=0;i<64u;i++) buf[i]=mu[g*64u+i];
    for(uint v=0;v<KK;v++){ uint tb=(g*KK+v)*256u, rb=64u+v*128u; for(uint i=0;i<128u;i++) buf[rb+i]=(uchar)(w1[tb+2*i]|(w1[tb+2*i+1]<<4)); }
    ulong s[25]; absorbN(s, buf, 832u, 136u); kf(s); uchar c2[136]; for(uint i=0;i<17u;i++){ulong v=s[i];for(uint b=0;b<8u;b++)c2[8u*i+b]=(uchar)(v>>(8u*b));}
    for(uint i=0;i<48u;i++) ctil[g*48u+i]=c2[i];
    // SampleInBall = FRESH SHAKE256(c~) (not a continuation of the mu||w1 hash)
    uchar cc[48]; for(uint i=0;i<48u;i++) cc[i]=c2[i];
    ulong s2[25]; absorbN(s2, cc, 48u, 136u); kf(s2);
    uchar cb[136]; for(uint i=0;i<17u;i++){ulong v=s2[i];for(uint q=0;q<8u;q++)cb[8u*i+q]=(uchar)(v>>(8u*q));}
    ulong signs=0; for(uint i=0;i<8u;i++)signs|=(ulong)cb[i]<<(8u*i); uint pos=8u; uint ob=g*256u; for(uint i=0;i<256u;i++)cp[ob+i]=0;
    for(uint i=256u-TAU;i<256u;i++){uint b; do{ if(pos>=136u){ kf(s2); for(uint k=0;k<17u;k++){ulong v=s2[k];for(uint q=0;q<8u;q++)cb[8u*k+q]=(uchar)(v>>(8u*q));} pos=0; } b=cb[pos++]; }while(b>i); cp[ob+i]=cp[ob+b]; cp[ob+b]=1-2*(int)(signs&1); signs>>=1;}
}
kernel void r_z(device const int* cpntt [[buffer(0)]], device const int* s1ntt [[buffer(1)]], device const int* y [[buffer(2)]], device int* zo [[buffer(3)]], device atomic_uint* rej [[buffer(4)]], device const int* done [[buffer(5)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    uint sig=tg/LL; if(done[sig]!=0) return; uint l=tg%LL, c0=tid, c1=tid+128u; uint cB=sig*256u, sB=(sig*LL+l)*256u;
    a[c0]=mont((long)cpntt[cB+c0]*(long)s1ntt[sB+c0]); a[c1]=mont((long)cpntt[cB+c1]*(long)s1ntt[sB+c1]); threadgroup_barrier(mem_flags::mem_threadgroup);
    INVNTT(a,tid);
    int z0=reduce32(a[c0]+y[sB+c0]), z1=reduce32(a[c1]+y[sB+c1]); zo[sB+c0]=z0; zo[sB+c1]=z1;
    if(absI(z0)>=BNDZ || absI(z1)>=BNDZ) atomic_fetch_or_explicit(&rej[sig],1u,memory_order_relaxed);
}
kernel void r_w0(device const int* cpntt [[buffer(0)]], device const int* s2ntt [[buffer(1)]], device int* w0 [[buffer(2)]], device atomic_uint* rej [[buffer(3)]], device const int* done [[buffer(4)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    uint sig=tg/KK; if(done[sig]!=0) return; uint k=tg%KK, c0=tid, c1=tid+128u; uint cB=sig*256u, wB=(sig*KK+k)*256u;
    a[c0]=mont((long)cpntt[cB+c0]*(long)s2ntt[wB+c0]); a[c1]=mont((long)cpntt[cB+c1]*(long)s2ntt[wB+c1]); threadgroup_barrier(mem_flags::mem_threadgroup);
    INVNTT(a,tid);
    int n0=reduce32(w0[wB+c0]-a[c0]), n1=reduce32(w0[wB+c1]-a[c1]); w0[wB+c0]=n0; w0[wB+c1]=n1;
    if(absI(n0)>=BNDW || absI(n1)>=BNDW) atomic_fetch_or_explicit(&rej[sig],1u,memory_order_relaxed);
}
kernel void r_hint(device const int* cpntt [[buffer(0)]], device const int* t0ntt [[buffer(1)]], device int* w0 [[buffer(2)]], device const int* w1 [[buffer(3)]], device int* hbits [[buffer(4)]], device atomic_uint* rej [[buffer(5)]], device atomic_uint* hcnt [[buffer(6)]], device const int* done [[buffer(7)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]], threadgroup int* red [[threadgroup(1)]]){
    uint sig=tg/KK; if(done[sig]!=0) return; uint k=tg%KK, c0=tid, c1=tid+128u; uint cB=sig*256u, wB=(sig*KK+k)*256u;
    a[c0]=mont((long)cpntt[cB+c0]*(long)t0ntt[wB+c0]); a[c1]=mont((long)cpntt[cB+c1]*(long)t0ntt[wB+c1]); threadgroup_barrier(mem_flags::mem_threadgroup);
    INVNTT(a,tid);
    int ct0=reduce32(a[c0]), ct1=reduce32(a[c1]);
    if(absI(ct0)>=G2 || absI(ct1)>=G2) atomic_fetch_or_explicit(&rej[sig],1u,memory_order_relaxed);
    int nw0=w0[wB+c0]+ct0, nw1=w0[wB+c1]+ct1;
    // make_hint(a0=nw0, a1=w1)
    int hb0=(nw0>G2||nw0<-G2||(nw0==-G2&&w1[wB+c0]!=0))?1:0;
    int hb1=(nw1>G2||nw1<-G2||(nw1==-G2&&w1[wB+c1]!=0))?1:0;
    hbits[wB+c0]=hb0; hbits[wB+c1]=hb1;
    red[tid]=hb0+hb1; threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint s=64u;s>0u;s>>=1u){ if(tid<s) red[tid]+=red[tid+s]; threadgroup_barrier(mem_flags::mem_threadgroup); }
    if(tid==0) atomic_fetch_add_explicit(&hcnt[sig], (uint)red[0], memory_order_relaxed);
}
kernel void r_final(device const uchar* ctil [[buffer(0)]], device const int* z [[buffer(1)]], device const int* hbits [[buffer(2)]], device const uint* rej [[buffer(3)]], device const uint* hcnt [[buffer(4)]], device int* done [[buffer(5)]], device uchar* sig [[buffer(6)]], uint g [[thread_position_in_grid]]){
    if(done[g]!=0) return;
    if(rej[g]!=0 || hcnt[g]>OMEGA) return;
    uint sb=g*3309u;
    for(uint i=0;i<48u;i++) sig[sb+i]=ctil[g*48u+i];
    uint o=sb+48u;
    for(uint v=0;v<LL;v++){ uint zb=(g*LL+v)*256u, rb=o+v*640u; for(uint i=0;i<128u;i++){ int t0=G1-z[zb+2*i], t1=G1-z[zb+2*i+1];
        sig[rb+5*i+0]=(uchar)t0; sig[rb+5*i+1]=(uchar)(t0>>8); sig[rb+5*i+2]=(uchar)((t0>>16)|(t1<<4)); sig[rb+5*i+3]=(uchar)(t1>>4); sig[rb+5*i+4]=(uchar)(t1>>12); } }
    o += LL*640u;
    for(uint i=0;i<OMEGA+KK;i++) sig[o+i]=0;
    uint cnt=0;
    for(uint v=0;v<KK;v++){ uint hb=(g*KK+v)*256u; for(uint j=0;j<256u;j++) if(hbits[hb+j]!=0){ sig[o+cnt]=(uchar)j; cnt++; } sig[o+OMEGA+v]=(uchar)cnt; }
    done[g]=1;
}
"""

let dev = MTLCreateSystemDefaultDevice()!
let queue = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: kSrc, options: nil)
func pso(_ n:String)->MTLComputePipelineState{ try! dev.makeComputePipelineState(function: lib.makeFunction(name:n)!) }
let K=6,L=5,ENTRY=7373,SIGLEN=3309

let data = try! Data(contentsOf: URL(fileURLWithPath: "/tmp/mldsa_sksig.bin"))
let nk = data.count / ENTRY
print("=== MLDSASIGN — ML-DSA-65 Sign on Metal vs reference (\(nk) sigs) ===\n")
func mk(_ b:Int)->MTLBuffer{ dev.makeBuffer(length:max(1,b), options:.storageModeShared)! }
let ent = dev.makeBuffer(bytes:[UInt8](data), length:data.count, options:.storageModeShared)!
let rho=mk(nk*32), s1=mk(nk*L*256*4), s2=mk(nk*K*256*4), t0=mk(nk*K*256*4)
let mu=mk(nk*64), rhop=mk(nk*64), A=mk(nk*K*L*256*4)
let s1n=mk(nk*L*256*4), s2n=mk(nk*K*256*4), t0n=mk(nk*K*256*4)
let y=mk(nk*L*256*4), yn=mk(nk*L*256*4), w1=mk(nk*K*256*4), w0=mk(nk*K*256*4)
let ctil=mk(nk*48), cp=mk(nk*256*4), cpn=mk(nk*256*4), z=mk(nk*L*256*4), hbits=mk(nk*K*256*4)
let rej=mk(nk*4), hcnt=mk(nk*4), done=mk(nk*4), sigout=mk(nk*SIGLEN)

func disp(_ p:MTLComputePipelineState,_ th:Int,_ bufs:[MTLBuffer], tg:Bool=false, tgw:Int=256, tgmem:[Int]=[], bytes:[(UInt32,Int)]=[]){
    let cb=queue.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!; e.setComputePipelineState(p); for (i,b) in bufs.enumerated(){e.setBuffer(b,offset:0,index:i)}; for (v,idx) in bytes{var vv=v;e.setBytes(&vv,length:4,index:idx)}; for (i,m) in tgmem.enumerated(){e.setThreadgroupMemoryLength(m,index:i)}
    if tg { e.dispatchThreadgroups(MTLSize(width:th,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:tgw,height:1,depth:1)) } else { e.dispatchThreads(MTLSize(width:th,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(256,th),height:1,depth:1)) }
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
let pUn=pso("s_unpack"),pMu=pso("s_mu"),pRp=pso("s_rhop"),pEA=pso("s_expandA"),pNtt=pso("ntt_fwd")
let pEM=pso("r_expandmask"),pMv=pso("r_matvec"),pCh=pso("r_chal"),pZ=pso("r_z"),pW0=pso("r_w0"),pHi=pso("r_hint"),pFi=pso("r_final"),pNtS=pso("ntt_sign")

// setup
disp(pUn,nk,[ent,rho,s1,s2,t0]); disp(pMu,nk,[ent,mu]); disp(pRp,nk,[ent,mu,rhop]); disp(pEA,nk*K*L,[rho,A])
disp(pNtt,nk*L,[s1,s1n],tg:true,tgw:128,tgmem:[256*4]); disp(pNtt,nk*K,[s2,s2n],tg:true,tgw:128,tgmem:[256*4]); disp(pNtt,nk*K,[t0,t0n],tg:true,tgw:128,tgmem:[256*4])

func zero(_ b:MTLBuffer,_ n:Int){ memset(b.contents(), 0, n) }
var rounds=0
@discardableResult func runSign()->Int {
    disp(pUn,nk,[ent,rho,s1,s2,t0]); disp(pMu,nk,[ent,mu]); disp(pRp,nk,[ent,mu,rhop]); disp(pEA,nk*K*L,[rho,A])
    disp(pNtt,nk*L,[s1,s1n],tg:true,tgw:128,tgmem:[256*4]); disp(pNtt,nk*K,[s2,s2n],tg:true,tgw:128,tgmem:[256*4]); disp(pNtt,nk*K,[t0,t0n],tg:true,tgw:128,tgmem:[256*4])
    zero(done,nk*4); var rr=0
    for r in 0..<80 {
        zero(rej,nk*4); zero(hcnt,nk*4)
        disp(pEM, nk*L, [rhop,y,done], bytes:[(UInt32(r),3)])
        disp(pNtS, nk*L, [y,yn,done], tg:true,tgw:128,tgmem:[256*4], bytes:[(UInt32(L),3)])
        disp(pMv, nk*K, [A,yn,w1,w0,done], tg:true,tgw:128,tgmem:[256*4])
        disp(pCh, nk, [mu,w1,ctil,cp,done])
        disp(pNtS, nk, [cp,cpn,done], tg:true,tgw:128,tgmem:[256*4], bytes:[(UInt32(1),3)])
        disp(pZ, nk*L, [cpn,s1n,y,z,rej,done], tg:true,tgw:128,tgmem:[256*4])
        disp(pW0, nk*K, [cpn,s2n,w0,rej,done], tg:true,tgw:128,tgmem:[256*4])
        disp(pHi, nk*K, [cpn,t0n,w0,w1,hbits,rej,hcnt,done], tg:true,tgw:128,tgmem:[256*4, 128*4])
        disp(pFi, nk, [ctil,z,hbits,rej,hcnt,done,sigout])
        rr=r+1
        let d=Array(UnsafeBufferPointer(start:done.contents().bindMemory(to:Int32.self,capacity:nk),count:nk))
        if d.allSatisfy({$0==1}) { break }
    }
    return rr
}
rounds = runSign()
let nDone = Array(UnsafeBufferPointer(start:done.contents().bindMemory(to:Int32.self,capacity:nk),count:nk)).filter{$0==1}.count
let sg = [UInt8](UnsafeBufferPointer(start: sigout.contents().bindMemory(to:UInt8.self,capacity:nk*SIGLEN), count:nk*SIGLEN))
let ref = [UInt8](data)
var ok=0
for i in 0..<nk { let rs=Array(ref[i*ENTRY+4064 ..< i*ENTRY+4064+SIGLEN]); if Array(sg[i*SIGLEN..<(i+1)*SIGLEN])==rs { ok+=1 } }
print("signatures completed: \(nDone)/\(nk) in \(rounds) rounds")
print("signatures bit-exact vs reference: \(ok)/\(nk)  -> \(ok==nk ? "PASS":"FAIL")")
func hx(_ a:ArraySlice<UInt8>)->String{ a.map{String(format:"%02x",$0)}.joined() }
let g0=Array(sg[0..<SIGLEN]); let r0=Array(ref[4064..<4064+SIGLEN])
print("c~  gpu: \(hx(g0[0..<16]))")
print("c~  ref: \(hx(r0[0..<16]))")
print("z   gpu: \(hx(g0[48..<64]))")
print("z   ref: \(hx(r0[48..<64]))")
var firstDiff = -1; for i in 0..<SIGLEN where g0[i] != r0[i] { firstDiff=i; break }
print("first differing byte index (key0): \(firstDiff)")

// throughput (full sign incl. rejection loop)
for _ in 0..<2 { runSign() }
var ts=[Double](); for _ in 0..<5 { let s=Date(); rounds=runSign(); ts.append(-s.timeIntervalSinceNow) }
ts.sort(); let t=ts[ts.count/2]
print(String(format: "\nGPU Sign: %.3f ms for %d sigs = %.4f M sign/sec (%d rounds to clear batch)", t*1e3, nk, Double(nk)/t/1e6, rounds))
