// MLDSAKEYGEN — full ML-DSA-65 keyGen on Metal (8 kernels), validated bit-exact
// against the pq-crystals reference (/tmp/mldsa_refkeys.bin from refgen/ref_harness).
// Build: swiftc -O MLDSAKEYGEN.swift -o mldsa_keygen -framework Metal -framework Foundation
// Run:   ./refgen/ref_harness <N>   then   ./mldsa_keygen <N>

import Foundation
import Metal

let kSrc = """
#include <metal_stdlib>
using namespace metal;
constant int  DQ = 8380417;
constant int  DQINV = 58728449;
constant uint KK = 6, LL = 5, NN = 256, DD = 13;
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
constant ulong RC[24] = {0x1ul,0x8082ul,0x800000000000808aul,0x8000000080008000ul,0x808bul,0x80000001ul,0x8000000080008081ul,0x8000000000008009ul,0x8aul,0x88ul,0x80008009ul,0x8000000aul,0x8000808bul,0x800000000000008bul,0x8000000000008089ul,0x8000000000008003ul,0x8000000000008002ul,0x8000000000000080ul,0x800aul,0x800000008000000aul,0x8000000080008081ul,0x8000000000008080ul,0x80000001ul,0x8000000080008008ul};
constant uint RHOt[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
constant uint PIL[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
inline ulong rotl64(ulong x, uint n){ return (x<<n)|(x>>(64-n)); }
inline void keccakf(thread ulong* a){
    for(int r=0;r<24;++r){ ulong b[5];
        for(int i=0;i<5;i++) b[i]=a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20];
        for(int i=0;i<5;i++){ ulong t=b[(i+4)%5]^rotl64(b[(i+1)%5],1); for(int j=0;j<25;j+=5) a[j+i]^=t; }
        ulong t=a[1];
        for(int i=0;i<24;i++){ uint j=PIL[i]; ulong tmp=a[j]; a[j]=rotl64(t,RHOt[i]); t=tmp; }
        for(int j=0;j<25;j+=5){ ulong c[5]; for(int i=0;i<5;i++)c[i]=a[j+i]; for(int i=0;i<5;i++)a[j+i]=c[i]^((~c[(i+1)%5])&c[(i+2)%5]); }
        a[0]^=RC[r];
    }
}
inline int mont_reduce(long a){ int t=(int)a*DQINV; long r=(a-(long)t*(long)DQ)>>32; return (int)r; }
inline int reduce32(int a){ int t=(a+(1<<22))>>23; return a-t*DQ; }
inline int caddq(int a){ return a+((a>>31)&DQ); }
inline void absorb1(thread ulong* s, thread const uchar* in, uint inlen, uint rate, uchar dom){
    for(uint i=0;i<25u;i++) s[i]=0;
    for(uint i=0;i<inlen;i++) s[i/8u]^=(ulong)in[i]<<(8u*(i%8u));
    s[inlen/8u]^=(ulong)dom<<(8u*(inlen%8u));
    s[(rate-1u)/8u]^=(ulong)1<<63;
}

// 1) seed expand: SHAKE256(seed||K||L) -> 128 bytes (rho|rhoprime|key)
kernel void seed_expand(device const uchar* seeds [[buffer(0)]], device uchar* expand [[buffer(1)]], uint gid [[thread_position_in_grid]]){
    uchar buf[34]; for(uint i=0;i<32u;i++) buf[i]=seeds[gid*32u+i]; buf[32]=(uchar)KK; buf[33]=(uchar)LL;
    ulong s[25]; absorb1(s, buf, 34u, 136u, 0x1F);
    keccakf(s);
    uchar blk[136]; for(uint i=0;i<17u;i++){ ulong v=s[i]; for(uint b=0;b<8u;b++) blk[8u*i+b]=(uchar)(v>>(8u*b)); }
    for(uint i=0;i<128u;i++) expand[gid*128u+i]=blk[i];
}
// 2) ExpandA: one thread per (key,i,j) -> A in NTT domain
kernel void expandA(device const uchar* expand [[buffer(0)]], device int* A [[buffer(1)]], uint gid [[thread_position_in_grid]]){
    uint key=gid/(KK*LL), rem=gid%(KK*LL), i=rem/LL, j=rem%LL; uint nonce=(i<<8)|j;
    uchar buf[34]; for(uint k=0;k<32u;k++) buf[k]=expand[key*128u+k]; buf[32]=(uchar)(nonce&0xff); buf[33]=(uchar)(nonce>>8);
    ulong s[25]; absorb1(s, buf, 34u, 168u, 0x1F);
    uint ctr=0, ob=gid*256u; uchar bb[168];
    while(ctr<256u){
        keccakf(s);
        for(uint k=0;k<21u;k++){ ulong v=s[k]; for(uint b=0;b<8u;b++) bb[8u*k+b]=(uchar)(v>>(8u*b)); }
        for(uint pos=0; pos+3u<=168u && ctr<256u; pos+=3u){ uint t=(uint)bb[pos]|((uint)bb[pos+1]<<8)|(((uint)bb[pos+2]&0x7f)<<16); if(t<(uint)DQ) A[ob+ctr++]=(int)t; }
    }
}
// 3) ExpandS: one thread per (key,idx) idx in [0,L+K) -> s1 (idx<L) or s2
kernel void expandS(device const uchar* expand [[buffer(0)]], device int* s1 [[buffer(1)]], device int* s2 [[buffer(2)]], uint gid [[thread_position_in_grid]]){
    uint key=gid/(LL+KK), idx=gid%(LL+KK); uint nonce=idx;
    uchar buf[66]; for(uint k=0;k<64u;k++) buf[k]=expand[key*128u+32u+k]; buf[64]=(uchar)(nonce&0xff); buf[65]=(uchar)(nonce>>8);
    ulong s[25]; absorb1(s, buf, 66u, 136u, 0x1F);
    uint ctr=0; uchar bb[136];
    int tmp[256];
    while(ctr<256u){
        keccakf(s);
        for(uint k=0;k<17u;k++){ ulong v=s[k]; for(uint b=0;b<8u;b++) bb[8u*k+b]=(uchar)(v>>(8u*b)); }
        for(uint pos=0; pos<136u && ctr<256u; pos+=1u){ uint t0=(uint)bb[pos]&0xF, t1=(uint)bb[pos]>>4;
            if(t0<9u) tmp[ctr++]=4-(int)t0; if(t1<9u && ctr<256u) tmp[ctr++]=4-(int)t1; }
    }
    uint ob = (idx<LL) ? (key*LL+idx)*256u : (key*KK+(idx-LL))*256u;
    device int* dst = (idx<LL) ? s1 : s2;
    for(uint c=0;c<256u;c++) dst[ob+c]=tmp[c];
}
// 4) forward NTT (one threadgroup per poly)
kernel void ntt_fwd(device const int* inp [[buffer(0)]], device int* outp [[buffer(1)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    uint pb=tg*256u; a[tid]=inp[pb+tid]; a[tid+128u]=inp[pb+tid+128u]; threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint len=128u; len>0u; len>>=1u){ uint g=tid/len; int z=ZETAS[(128u/len)+g]; uint j=g*(2u*len)+(tid%len),jp=j+len; int t=mont_reduce((long)z*(long)a[jp]); int aj=a[j]; a[jp]=aj-t; a[j]=aj+t; threadgroup_barrier(mem_flags::mem_threadgroup); }
    outp[pb+tid]=a[tid]; outp[pb+tid+128u]=a[tid+128u];
}
// 5) matvec + power2round (one threadgroup per (key,row))
kernel void matvec(device const int* A [[buffer(0)]], device const int* s1hat [[buffer(1)]], device const int* s2 [[buffer(2)]], device int* t1o [[buffer(3)]], device int* t0o [[buffer(4)]], uint tid [[thread_position_in_threadgroup]], uint tg [[threadgroup_position_in_grid]], threadgroup int* a [[threadgroup(0)]]){
    uint key=tg/KK, row=tg%KK, c0=tid, c1=tid+128u; int acc0=0,acc1=0;
    for(uint j=0;j<LL;j++){ uint aB=((key*KK+row)*LL+j)*256u, sB=(key*LL+j)*256u; acc0+=mont_reduce((long)A[aB+c0]*(long)s1hat[sB+c0]); acc1+=mont_reduce((long)A[aB+c1]*(long)s1hat[sB+c1]); }
    a[c0]=reduce32(acc0); a[c1]=reduce32(acc1); threadgroup_barrier(mem_flags::mem_threadgroup);
    for(uint len=1u; len<256u; len<<=1u){ uint g=tid/len; int z=-ZETAS[(256u/len)-1u-g]; uint j=g*(2u*len)+(tid%len),jp=j+len; int t=a[j],u=a[jp]; a[j]=t+u; a[jp]=mont_reduce((long)z*(long)(t-u)); threadgroup_barrier(mem_flags::mem_threadgroup); }
    const int f=41978; a[c0]=mont_reduce((long)f*(long)a[c0]); a[c1]=mont_reduce((long)f*(long)a[c1]);
    uint s2B=(key*KK+row)*256u, ob=tg*256u;
    int v0=caddq(a[c0]+s2[s2B+c0]); int u0=(v0+4095)>>13; t1o[ob+c0]=u0; t0o[ob+c0]=v0-(u0<<13);
    int v1=caddq(a[c1]+s2[s2B+c1]); int u1=(v1+4095)>>13; t1o[ob+c1]=u1; t0o[ob+c1]=v1-(u1<<13);
}
// 6) pack_pk (one thread per key): rho(32) || polyt1_pack(t1) per K
kernel void pack_pk(device const uchar* expand [[buffer(0)]], device const int* t1 [[buffer(1)]], device uchar* pk [[buffer(2)]], uint gid [[thread_position_in_grid]]){
    uint pkb=gid*1952u; for(uint i=0;i<32u;i++) pk[pkb+i]=expand[gid*128u+i];
    for(uint v=0;v<KK;v++){ uint tb=(gid*KK+v)*256u, rb=pkb+32u+v*320u;
        for(uint i=0;i<64u;i++){ int a0=t1[tb+4*i],a1=t1[tb+4*i+1],a2=t1[tb+4*i+2],a3=t1[tb+4*i+3];
            pk[rb+5*i+0]=(uchar)(a0); pk[rb+5*i+1]=(uchar)((a0>>8)|(a1<<2)); pk[rb+5*i+2]=(uchar)((a1>>6)|(a2<<4)); pk[rb+5*i+3]=(uchar)((a2>>4)|(a3<<6)); pk[rb+5*i+4]=(uchar)(a3>>2); }
    }
}
// 7) tr = SHAKE256(pk, 64) (one thread per key, multi-block absorb)
kernel void tr_hash(device const uchar* pk [[buffer(0)]], device uchar* tr [[buffer(1)]], uint gid [[thread_position_in_grid]]){
    ulong s[25]; for(uint i=0;i<25u;i++) s[i]=0; uint base=gid*1952u, off=0, rem=1952u, rate=136u;
    while(rem>=rate){ for(uint i=0;i<rate/8u;i++){ ulong v=0; for(uint b=0;b<8u;b++) v|=(ulong)pk[base+off+8u*i+b]<<(8u*b); s[i]^=v; } off+=rate; rem-=rate; keccakf(s); }
    for(uint i=0;i<rem;i++) s[i/8u]^=(ulong)pk[base+off+i]<<(8u*(i%8u));
    s[rem/8u]^=(ulong)0x1F<<(8u*(rem%8u)); s[(rate-1u)/8u]^=(ulong)1<<63;
    keccakf(s); uchar blk[136]; for(uint i=0;i<17u;i++){ ulong v=s[i]; for(uint b=0;b<8u;b++) blk[8u*i+b]=(uchar)(v>>(8u*b)); }
    for(uint i=0;i<64u;i++) tr[gid*64u+i]=blk[i];
}
// 8) pack_sk (one thread per key)
kernel void pack_sk(device const uchar* expand [[buffer(0)]], device const uchar* tr [[buffer(1)]], device const int* s1 [[buffer(2)]], device const int* s2 [[buffer(3)]], device const int* t0 [[buffer(4)]], device uchar* sk [[buffer(5)]], uint gid [[thread_position_in_grid]]){
    uint b=gid*4032u;
    for(uint i=0;i<32u;i++) sk[b+i]=expand[gid*128u+i];            // rho
    for(uint i=0;i<32u;i++) sk[b+32u+i]=expand[gid*128u+96u+i];    // key
    for(uint i=0;i<64u;i++) sk[b+64u+i]=tr[gid*64u+i];             // tr
    uint o=b+128u;
    // s1: L polys, polyeta_pack ETA=4 (2 coeffs/byte)
    for(uint v=0;v<LL;v++){ uint tb=(gid*LL+v)*256u, rb=o+v*128u;
        for(uint i=0;i<128u;i++){ int t0c=4-s1[tb+2*i], t1c=4-s1[tb+2*i+1]; sk[rb+i]=(uchar)(t0c|(t1c<<4)); } }
    o+=LL*128u;
    for(uint v=0;v<KK;v++){ uint tb=(gid*KK+v)*256u, rb=o+v*128u;
        for(uint i=0;i<128u;i++){ int t0c=4-s2[tb+2*i], t1c=4-s2[tb+2*i+1]; sk[rb+i]=(uchar)(t0c|(t1c<<4)); } }
    o+=KK*128u;
    // t0: K polys, polyt0_pack (13-bit, 8 coeffs -> 13 bytes)
    for(uint v=0;v<KK;v++){ uint tb=(gid*KK+v)*256u, rb=o+v*416u;
        for(uint i=0;i<32u;i++){ uint t[8];
            for(uint q=0;q<8u;q++) t[q]=(uint)((1<<(DD-1)) - t0[tb+8*i+q]);
            uint r=rb+13*i;
            sk[r+0]=(uchar)t[0]; sk[r+1]=(uchar)((t[0]>>8)|(t[1]<<5)); sk[r+2]=(uchar)(t[1]>>3); sk[r+3]=(uchar)((t[1]>>11)|(t[2]<<2));
            sk[r+4]=(uchar)((t[2]>>6)|(t[3]<<7)); sk[r+5]=(uchar)(t[3]>>1); sk[r+6]=(uchar)((t[3]>>9)|(t[4]<<4)); sk[r+7]=(uchar)((t[4]>>4));
            sk[r+8]=(uchar)((t[4]>>12)|(t[5]<<1)); sk[r+9]=(uchar)((t[5]>>7)|(t[6]<<6)); sk[r+10]=(uchar)(t[6]>>2); sk[r+11]=(uchar)((t[6]>>10)|(t[7]<<3)); sk[r+12]=(uchar)(t[7]>>5);
        }
    }
}
"""

let dev = MTLCreateSystemDefaultDevice()!
let queue = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: kSrc, options: nil)
func pso(_ n: String) -> MTLComputePipelineState { try! dev.makeComputePipelineState(function: lib.makeFunction(name: n)!) }
let K = 6, L = 5
let PK = 1952, SK = 4032

let nk = CommandLine.arguments.count > 1 ? Int(CommandLine.arguments[1])! : 256
let seedData = try! Data(contentsOf: URL(fileURLWithPath: "/tmp/mldsa_seeds.bin"))
let refData = try! Data(contentsOf: URL(fileURLWithPath: "/tmp/mldsa_refkeys.bin"))
print("=== MLDSAKEYGEN — ML-DSA-65 keyGen on Metal vs pq-crystals reference (\(nk) keys) ===\n")

func mkU(_ bytes: Int) -> MTLBuffer { dev.makeBuffer(length: max(1,bytes), options: .storageModeShared)! }
let seeds = dev.makeBuffer(bytes: [UInt8](seedData), length: seedData.count, options: .storageModeShared)!
let expand = mkU(nk*128)
let A = mkU(nk*K*L*256*4), s1 = mkU(nk*L*256*4), s2 = mkU(nk*K*256*4), s1hat = mkU(nk*L*256*4)
let t1 = mkU(nk*K*256*4), t0 = mkU(nk*K*256*4)
let pk = mkU(nk*PK), tr = mkU(nk*64), sk = mkU(nk*SK)

func disp(_ p: MTLComputePipelineState, _ threads: Int, _ bufs: [MTLBuffer], tg: Bool = false, tgw: Int = 256, tgmem: Int = 0) {
    let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p); for (i,b) in bufs.enumerated() { e.setBuffer(b, offset: 0, index: i) }
    if tgmem > 0 { e.setThreadgroupMemoryLength(tgmem, index: 0) }
    if tg { e.dispatchThreadgroups(MTLSize(width: threads, height:1, depth:1), threadsPerThreadgroup: MTLSize(width: tgw, height:1, depth:1)) }
    else { e.dispatchThreads(MTLSize(width: threads, height:1, depth:1), threadsPerThreadgroup: MTLSize(width: min(256,threads), height:1, depth:1)) }
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}

let pSeed = pso("seed_expand"), pEA = pso("expandA"), pES = pso("expandS")
let pNtt = pso("ntt_fwd"), pMv = pso("matvec"), pPk = pso("pack_pk"), pTr = pso("tr_hash"), pSk = pso("pack_sk")
func runAll() {
    disp(pSeed, nk, [seeds, expand])
    disp(pEA, nk*K*L, [expand, A])
    disp(pES, nk*(L+K), [expand, s1, s2])
    disp(pNtt, nk*L, [s1, s1hat], tg: true, tgw: 128, tgmem: 256*4)
    disp(pMv, nk*K, [A, s1hat, s2, t1, t0], tg: true, tgw: 128, tgmem: 256*4)
    disp(pPk, nk, [expand, t1, pk])
    disp(pTr, nk, [pk, tr])
    disp(pSk, nk, [expand, tr, s1, s2, t0, sk])
}
runAll()

// compare pk||sk per key to reference (refData interleaves pk then sk per key)
let pkArr = [UInt8](UnsafeBufferPointer(start: pk.contents().bindMemory(to: UInt8.self, capacity: nk*PK), count: nk*PK))
let skArr = [UInt8](UnsafeBufferPointer(start: sk.contents().bindMemory(to: UInt8.self, capacity: nk*SK), count: nk*SK))
let ref = [UInt8](refData)
var pkOK = true, skOK = true, firstBad = -1
for i in 0..<nk {
    let rpk = Array(ref[i*(PK+SK) ..< i*(PK+SK)+PK])
    let rsk = Array(ref[i*(PK+SK)+PK ..< (i+1)*(PK+SK)])
    if Array(pkArr[i*PK..<(i+1)*PK]) != rpk { pkOK = false; if firstBad < 0 { firstBad = i } }
    if Array(skArr[i*SK..<(i+1)*SK]) != rsk { skOK = false; if firstBad < 0 { firstBad = i } }
}
print("pk bit-exact vs reference: \(pkOK ? "PASS" : "FAIL")")
print("sk bit-exact vs reference: \(skOK ? "PASS" : "FAIL")")
if !pkOK || !skOK { print("first mismatching key: \(firstBad)") }

// throughput (end-to-end GPU pipeline; unified memory => no host copy)
for _ in 0..<3 { runAll() }
var ts = [Double]()
for _ in 0..<9 { let s = Date(); runAll(); ts.append(-s.timeIntervalSinceNow) }
ts.sort(); let t = ts[ts.count/2]
print(String(format: "\nGPU keyGen: %.3f ms for %d keys = %.3f M keys/sec", t*1e3, nk, Double(nk)/t/1e6))
