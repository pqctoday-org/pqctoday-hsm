// MLDSAVERIFY — full ML-DSA-65 Verify on Metal, validated vs pq-crystals reference
// (/tmp/mldsa_sigs.bin = pk(1952)|msg(32)|sig(3309) per entry, from refgen/sign_harness).
// Build: swiftc -O MLDSAVERIFY.swift -o mldsa_verify -framework Metal -framework Foundation

import Foundation
import Metal

let kSrc = """
#include <metal_stdlib>
using namespace metal;
constant int DQ=8380417, DQINV=58728449, G1=(1<<19), G2=(8380417-1)/32, BETA=196, BND=(1<<19)-196;
constant uint KK=6, LL=5, DD=13, TAU=49;
constant uint ENTRY=5293, PKO=0, MSGO=1952, SIGO=1984, ZO=1984+48, HO=1984+48+3200;
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
inline int usehint(int a,int h){int a0;int a1=decompose(a,&a0);if(h==0)return a1;return a0>0?((a1+1)&15):((a1-1)&15);}
inline void absorb1(thread ulong* s, thread const uchar* in, uint inlen, uint rate){for(uint i=0;i<25u;i++)s[i]=0;for(uint i=0;i<inlen;i++)s[i/8u]^=(ulong)in[i]<<(8u*(i%8u));s[inlen/8u]^=(ulong)0x1F<<(8u*(inlen%8u));s[(rate-1u)/8u]^=(ulong)1<<63;}

// 1) unpack t1, z, hints; chknorm(z); copy c~
kernel void k_unpack(device const uchar* ent [[buffer(0)]], device int* t1 [[buffer(1)]], device int* z [[buffer(2)]], device int* h [[buffer(3)]], device int* nflag [[buffer(4)]], uint gid [[thread_position_in_grid]]){
    uint e=gid*ENTRY;
    // t1 (K polys, polyt1_unpack from pk+32)
    for(uint v=0;v<KK;v++){ uint pb=e+PKO+32u+v*320u, ob=(gid*KK+v)*256u;
        for(uint i=0;i<64u;i++){ uint a0=ent[pb+5*i],a1=ent[pb+5*i+1],a2=ent[pb+5*i+2],a3=ent[pb+5*i+3],a4=ent[pb+5*i+4];
            t1[ob+4*i+0]=(int)(((a0)|(a1<<8))&0x3FF); t1[ob+4*i+1]=(int)(((a1>>2)|(a2<<6))&0x3FF); t1[ob+4*i+2]=(int)(((a2>>4)|(a3<<4))&0x3FF); t1[ob+4*i+3]=(int)(((a3>>6)|(a4<<2))&0x3FF); } }
    // z (L polys, polyz_unpack G1=2^19) + chknorm
    int bad=0;
    for(uint v=0;v<LL;v++){ uint zb=e+ZO+v*640u, ob=(gid*LL+v)*256u;
        for(uint i=0;i<128u;i++){ uint b0=ent[zb+5*i],b1=ent[zb+5*i+1],b2=ent[zb+5*i+2],b3=ent[zb+5*i+3],b4=ent[zb+5*i+4];
            int c0=(int)(((b0)|(b1<<8)|(b2<<16))&0xFFFFF); int c1=(int)(((b2>>4)|(b3<<4)|(b4<<12))&0xFFFFF);
            c0=G1-c0; c1=G1-c1; z[ob+2*i]=c0; z[ob+2*i+1]=c1;
            int t=c0-((c0>>31)&(2*c0)); if(t>=BND) bad=1; t=c1-((c1>>31)&(2*c1)); if(t>=BND) bad=1; } }
    nflag[gid]=bad;
    // hints decode
    for(uint i=0;i<KK*256u;i++) h[gid*KK*256u+i]=0;
    uint k=0;
    for(uint i=0;i<KK;i++){ uint cnt=ent[e+HO+55u+i];
        for(uint j=k;j<cnt;j++){ uint pos=ent[e+HO+j]; h[(gid*KK+i)*256u+pos]=1; }
        k=cnt; }
}
// 2) mu = SHAKE256(SHAKE256(pk) || 0 || 0 || msg)
kernel void k_mu(device const uchar* ent [[buffer(0)]], device uchar* mu [[buffer(1)]], uint gid [[thread_position_in_grid]]){
    uint e=gid*ENTRY; ulong s[25]; for(uint i=0;i<25u;i++)s[i]=0;
    uint off=0,rem=1952u,rate=136u;                          // tr=SHAKE256(pk,64)
    while(rem>=rate){ for(uint i=0;i<rate/8u;i++){ulong v=0;for(uint b=0;b<8u;b++)v|=(ulong)ent[e+PKO+off+8u*i+b]<<(8u*b);s[i]^=v;} off+=rate; rem-=rate; kf(s);}
    for(uint i=0;i<rem;i++)s[i/8u]^=(ulong)ent[e+PKO+off+i]<<(8u*(i%8u)); s[rem/8u]^=(ulong)0x1F<<(8u*(rem%8u)); s[(rate-1u)/8u]^=(ulong)1<<63; kf(s);
    uchar tr[64]; for(uint i=0;i<8u;i++){ulong v=s[i];for(uint b=0;b<8u;b++)tr[8u*i+b]=(uchar)(v>>(8u*b));}
    uchar buf[98]; for(uint i=0;i<64u;i++) buf[i]=tr[i]; buf[64]=0; buf[65]=0; for(uint i=0;i<32u;i++) buf[66+i]=ent[e+MSGO+i];
    ulong s2[25]; absorb1(s2, buf, 98u, 136u); kf(s2);
    for(uint i=0;i<8u;i++){ulong v=s2[i];for(uint b=0;b<8u;b++) mu[gid*64u+8u*i+b]=(uchar)(v>>(8u*b));}
}
// 3) challenge cp from c~
kernel void k_challenge(device const uchar* ent [[buffer(0)]], device int* cp [[buffer(1)]], uint gid [[thread_position_in_grid]]){
    uint e=gid*ENTRY; uchar sd[48]; for(uint i=0;i<48u;i++) sd[i]=ent[e+SIGO+i];
    ulong s[25]; absorb1(s, sd, 48u, 136u); kf(s); uchar buf[136]; for(uint i=0;i<17u;i++){ulong v=s[i];for(uint b=0;b<8u;b++)buf[8u*i+b]=(uchar)(v>>(8u*b));}
    ulong signs=0; for(uint i=0;i<8u;i++)signs|=(ulong)buf[i]<<(8u*i); uint pos=8u; uint ob=gid*256u;
    for(uint i=0;i<256u;i++)cp[ob+i]=0;
    for(uint i=256u-TAU;i<256u;i++){uint b; do{if(pos>=136u){kf(s);for(uint k=0;k<17u;k++){ulong v=s[k];for(uint q=0;q<8u;q++)buf[8u*k+q]=(uchar)(v>>(8u*q));}pos=0;}b=buf[pos++];}while(b>i); cp[ob+i]=cp[ob+b]; cp[ob+b]=1-2*(int)(signs&1); signs>>=1;}
}
// 4) ExpandA (key,i,j)
kernel void expandA(device const uchar* ent [[buffer(0)]], device int* A [[buffer(1)]], uint gid [[thread_position_in_grid]]){
    uint key=gid/(KK*LL), rem=gid%(KK*LL), i=rem/LL, j=rem%LL, nonce=(i<<8)|j;
    uchar buf[34]; for(uint k=0;k<32u;k++) buf[k]=ent[key*ENTRY+PKO+k]; buf[32]=(uchar)(nonce&0xff); buf[33]=(uchar)(nonce>>8);
    ulong s[25]; absorb1(s, buf, 34u, 168u); uint ctr=0, ob=gid*256u; uchar bb[168];
    while(ctr<256u){ kf(s); for(uint k=0;k<21u;k++){ulong v=s[k];for(uint b=0;b<8u;b++)bb[8u*k+b]=(uchar)(v>>(8u*b));}
        for(uint p=0;p+3u<=168u&&ctr<256u;p+=3u){uint t=(uint)bb[p]|((uint)bb[p+1]<<8)|(((uint)bb[p+2]&0x7f)<<16); if(t<(uint)DQ) A[ob+ctr++]=(int)t;} }
}
// 5) forward NTT (one threadgroup per poly)
kernel void ntt_fwd(device const int* inp [[buffer(0)]], device int* outp [[buffer(1)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    uint pb=tg*256u; a[tid]=inp[pb+tid]; a[tid+128u]=inp[pb+tid+128u]; threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint len=128u;len>0u;len>>=1u){uint g=tid/len;int z=ZETAS[(128u/len)+g];uint j=g*(2u*len)+(tid%len),jp=j+len;int t=mont((long)z*(long)a[jp]);int aj=a[j];a[jp]=aj-t;a[j]=aj+t;threadgroup_barrier(mem_flags::mem_threadgroup);}
    outp[pb+tid]=a[tid]; outp[pb+tid+128u]=a[tid+128u];
}
// 6) shiftl t1 by D
kernel void k_shiftl(device const int* in [[buffer(0)]], device int* out [[buffer(1)]], uint gid [[thread_position_in_grid]]){ out[gid]=in[gid]<<DD; }
// 7) combine: w = A.z - cp.(t1<<D); reduce; invntt; caddq; usehint -> w1
kernel void k_combine(device const int* A [[buffer(0)]], device const int* zntt [[buffer(1)]], device const int* cpntt [[buffer(2)]], device const int* t1ntt [[buffer(3)]], device const int* h [[buffer(4)]], device int* w1 [[buffer(5)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    uint key=tg/KK, row=tg%KK, c0=tid, c1=tid+128u;
    int ac0=0,ac1=0;
    for(uint j=0;j<LL;j++){uint aB=((key*KK+row)*LL+j)*256u,zB=(key*LL+j)*256u; ac0+=mont((long)A[aB+c0]*(long)zntt[zB+c0]); ac1+=mont((long)A[aB+c1]*(long)zntt[zB+c1]);}
    uint cB=key*256u, tB=(key*KK+row)*256u;
    int ct0=mont((long)cpntt[cB+c0]*(long)t1ntt[tB+c0]), ct1=mont((long)cpntt[cB+c1]*(long)t1ntt[tB+c1]);
    a[c0]=reduce32(ac0-ct0); a[c1]=reduce32(ac1-ct1); threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint len=1u;len<256u;len<<=1u){uint g=tid/len;int z=-ZETAS[(256u/len)-1u-g];uint j=g*(2u*len)+(tid%len),jp=j+len;int t=a[j],u=a[jp];a[j]=t+u;a[jp]=mont((long)z*(long)(t-u));threadgroup_barrier(mem_flags::mem_threadgroup);}
    const int f=41978; int v0=caddq(mont((long)f*(long)a[c0])), v1=caddq(mont((long)f*(long)a[c1]));
    w1[tB+c0]=usehint(v0, h[tB+c0]); w1[tB+c1]=usehint(v1, h[tB+c1]);
}
// 8) pack w1, c~' = SHAKE256(mu || w1pack), compare
kernel void k_final(device const uchar* ent [[buffer(0)]], device const uchar* mu [[buffer(1)]], device const int* w1 [[buffer(2)]], device const int* nflag [[buffer(3)]], device int* accept [[buffer(4)]], uint gid [[thread_position_in_grid]]){
    uchar buf[832]; for(uint i=0;i<64u;i++) buf[i]=mu[gid*64u+i];            // 64 + K*128 = 64+768=832
    for(uint v=0;v<KK;v++){ uint tb=(gid*KK+v)*256u, rb=64u+v*128u; for(uint i=0;i<128u;i++) buf[rb+i]=(uchar)(w1[tb+2*i]|(w1[tb+2*i+1]<<4)); }
    ulong s[25]; for(uint i=0;i<25u;i++) s[i]=0; uint off=0,rem=832u,rate=136u;   // multi-block absorb
    while(rem>=rate){ for(uint i=0;i<rate/8u;i++){ulong v=0;for(uint b=0;b<8u;b++)v|=(ulong)buf[off+8u*i+b]<<(8u*b);s[i]^=v;} off+=rate; rem-=rate; kf(s);}
    for(uint i=0;i<rem;i++)s[i/8u]^=(ulong)buf[off+i]<<(8u*(i%8u)); s[rem/8u]^=(ulong)0x1F<<(8u*(rem%8u)); s[(rate-1u)/8u]^=(ulong)1<<63; kf(s);
    uchar c2[48]; for(uint i=0;i<6u;i++){ulong v=s[i];for(uint b=0;b<8u;b++)c2[8u*i+b]=(uchar)(v>>(8u*b));}
    int ok = (nflag[gid]==0)?1:0;
    for(uint i=0;i<48u;i++) if(c2[i]!=ent[gid*ENTRY+SIGO+i]) ok=0;
    accept[gid]=ok;
}
"""

let dev = MTLCreateSystemDefaultDevice()!
let queue = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: kSrc, options: nil)
func pso(_ n:String)->MTLComputePipelineState{ try! dev.makeComputePipelineState(function: lib.makeFunction(name:n)!) }
let K=6, L=5, ENTRY=5293

let data = try! Data(contentsOf: URL(fileURLWithPath: "/tmp/mldsa_sigs.bin"))
let nk = data.count / ENTRY
print("=== MLDSAVERIFY — ML-DSA-65 Verify on Metal vs reference (\(nk) sigs) ===\n")
func mk(_ b:Int)->MTLBuffer{ dev.makeBuffer(length:max(1,b), options:.storageModeShared)! }
let ent = dev.makeBuffer(bytes:[UInt8](data), length:data.count, options:.storageModeShared)!
let t1=mk(nk*K*256*4), z=mk(nk*L*256*4), h=mk(nk*K*256*4), nflag=mk(nk*4), mu=mk(nk*64), cp=mk(nk*256*4)
let A=mk(nk*K*L*256*4), zntt=mk(nk*L*256*4), cpntt=mk(nk*256*4), t1sh=mk(nk*K*256*4), t1ntt=mk(nk*K*256*4), w1=mk(nk*K*256*4), accept=mk(nk*4)

func disp(_ p:MTLComputePipelineState,_ threads:Int,_ bufs:[MTLBuffer], tg:Bool=false, tgw:Int=256, tgmem:Int=0){
    let cb=queue.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!; e.setComputePipelineState(p); for (i,b) in bufs.enumerated(){e.setBuffer(b,offset:0,index:i)}
    if tgmem>0 { e.setThreadgroupMemoryLength(tgmem,index:0) }
    if tg { e.dispatchThreadgroups(MTLSize(width:threads,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:tgw,height:1,depth:1)) }
    else { e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(256,threads),height:1,depth:1)) }
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
let pUn=pso("k_unpack"), pMu=pso("k_mu"), pCh=pso("k_challenge"), pEA=pso("expandA"), pNtt=pso("ntt_fwd"), pSh=pso("k_shiftl"), pCo=pso("k_combine"), pFi=pso("k_final")
func runAll(){
    disp(pUn, nk, [ent,t1,z,h,nflag]); disp(pMu, nk, [ent,mu]); disp(pCh, nk, [ent,cp])
    disp(pEA, nk*K*L, [ent,A])
    disp(pNtt, nk*L, [z,zntt], tg:true, tgw:128, tgmem:256*4)
    disp(pNtt, nk, [cp,cpntt], tg:true, tgw:128, tgmem:256*4)
    disp(pSh, nk*K*256, [t1,t1sh]); disp(pNtt, nk*K, [t1sh,t1ntt], tg:true, tgw:128, tgmem:256*4)
    disp(pCo, nk*K, [A,zntt,cpntt,t1ntt,h,w1], tg:true, tgw:128, tgmem:256*4)
    disp(pFi, nk, [ent,mu,w1,nflag,accept])
}
runAll()
let acc = Array(UnsafeBufferPointer(start: accept.contents().bindMemory(to:Int32.self,capacity:nk), count:nk))
let nAccept = acc.filter{ $0==1 }.count
print("valid signatures accepted by GPU: \(nAccept)/\(nk)  -> \(nAccept==nk ? "PASS":"FAIL")")

// negative test: tamper msg byte of entry 0 -> must reject
let p = ent.contents().bindMemory(to: UInt8.self, capacity: data.count)
let saved = p[1952]; p[1952] = saved &+ 1
runAll()
let a0 = accept.contents().bindMemory(to: Int32.self, capacity: nk)[0]
print("tampered signature rejected: \(a0 == 0 ? "PASS" : "FAIL")")
p[1952] = saved; runAll()

// throughput
for _ in 0..<3 { runAll() }
var ts=[Double](); for _ in 0..<9 { let s=Date(); runAll(); ts.append(-s.timeIntervalSinceNow) }
ts.sort(); let t=ts[ts.count/2]
print(String(format: "\nGPU Verify: %.3f ms for %d sigs = %.3f M verify/sec", t*1e3, nk, Double(nk)/t/1e6))
